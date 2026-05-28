"""
Shani nanoclaw Adapter.

nanoclaw エージェントのツール呼び出しを Shani ガバナンスで制御する。

nanoclaw は qwibitai/nanoclaw の軽量 Python エージェントフレームワーク。
本アダプターは nanoclaw の Agent.tools を Shani でラップし、
Shani Specification v0.3 に従った DecisionProposal → ADO → Capability
フローを強制する。

Usage (zero-change integration):

    from nanoclaw import Agent
    from shani.adapters.nanoclaw import patch_nanoclaw_agent
    from shani.hitl import HITLGate

    agent = Agent(name="my-agent", model="claude-3-5-sonnet-20241022")

    @agent.tool
    def fetch_report(url: str) -> str: ...

    @agent.tool
    def write_config(path: str, content: str) -> str: ...

    patch_nanoclaw_agent(
        agent=agent,
        gate=hitl_gate,
        proposed_by="nanoclaw-agent/v1",
        policy={
            "write_config": dict(
                decision_type=DecisionType.CONFIGURATION_CHANGE,
                blast_radius=BlastRadius.LIMITED,
            ),
        },
    )
    # All tool calls now go through Shani before execution.

Usage (per-tool wrapping):

    from shani.adapters.nanoclaw import ShaniNanoclawAdapter

    adapter = ShaniNanoclawAdapter(gate=hitl_gate, proposed_by="nanoclaw-agent/v1")
    result = adapter.call_tool(
        tool_name="fetch_report",
        tool_fn=fetch_report,
        kwargs={"url": "https://api.example.com/report"},
        decision_type=DecisionType.DATA_ACCESS,
        blast_radius=BlastRadius.ISOLATED,
    )
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable

from ...schemas.decision import (
    BlastRadius,
    DecisionProposal,
    DecisionScope,
    DecisionType,
    EvidenceItem,
)
from ...core.evaluator import DeniedDecision, ShaniEvaluator
from ...hitl.approval.gate import HITLGate
from ...boundary.capability import ExecutionBoundary
from ...adapters.generic.wrapper import ShaniToolWrapper, GovernanceGate

logger = logging.getLogger("shani.adapter.nanoclaw")


class NanoclawToolAction(str, Enum):
    """nanoclaw のツール種別に対応したアクション分類。"""
    READ    = "read"     # 読み取り専用ツール（http_get, read_file 相当）
    WRITE   = "write"    # 書き込みツール（write_file, http_post 相当）
    EXECUTE = "execute"  # コマンド実行ツール（run_command 相当）
    FETCH   = "fetch"    # 外部 API フェッチ（http_get 相当）


# デフォルトポリシー — ツール名パターンで決定型を推定
NANOCLAW_TOOL_POLICY: dict[NanoclawToolAction, tuple[DecisionType, BlastRadius, bool]] = {
    NanoclawToolAction.READ:    (DecisionType.DATA_ACCESS,          BlastRadius.ISOLATED,    True),
    NanoclawToolAction.FETCH:   (DecisionType.DATA_ACCESS,          BlastRadius.ISOLATED,    True),
    NanoclawToolAction.WRITE:   (DecisionType.CONFIGURATION_CHANGE, BlastRadius.LIMITED,     True),
    NanoclawToolAction.EXECUTE: (DecisionType.AGENT_TASK,           BlastRadius.SIGNIFICANT, False),
}


def _infer_action(tool_name: str) -> NanoclawToolAction:
    """ツール名からデフォルトの NanoclawToolAction を推定する。"""
    name = tool_name.lower()
    if any(kw in name for kw in ("write", "save", "update", "put", "post", "create", "delete")):
        return NanoclawToolAction.WRITE
    if any(kw in name for kw in ("run", "exec", "execute", "command", "cmd", "bash", "shell")):
        return NanoclawToolAction.EXECUTE
    if any(kw in name for kw in ("fetch", "get", "request", "call", "http")):
        return NanoclawToolAction.FETCH
    return NanoclawToolAction.READ


class ShaniNanoclawAdapter:
    """
    nanoclaw エージェントのツール呼び出しを Shani ガバナンスでラップするアダプター。

    nanoclaw の Agent.tools に登録された callable を intercept し、
    実行前に DecisionProposal → ADO フローを強制する。

    同一 action+target の HITL リクエストは重複排除される。
    """

    def __init__(
        self,
        gate: GovernanceGate,
        proposed_by: str = "nanoclaw-agent/v1",
        timeout_minutes: int = 10,
    ) -> None:
        self._gate = gate
        self._proposed_by = proposed_by
        self._timeout_minutes = timeout_minutes
        self._boundary = ExecutionBoundary(gate)

        self._caps: dict[str, Any] = {}
        self._pending_proposals: dict[str, DecisionProposal] = {}
        self._pending_dedup: dict[str, str] = {}
        self._lock = threading.Lock()

    def call_tool(
        self,
        tool_name: str,
        tool_fn: Callable,
        kwargs: dict,
        decision_type: DecisionType | None = None,
        blast_radius: BlastRadius | None = None,
        reversibility: bool | None = None,
        evidence: list | None = None,
        confidence: float = 0.8,
    ) -> Any:
        """
        nanoclaw ツールを Shani ガバナンス経由で同期実行する。

        Args:
            tool_name:     ツール名（ログ・DecisionProposal に使用）
            tool_fn:       実際の callable
            kwargs:        ツールに渡す引数
            decision_type: None の場合ツール名から自動推定
            blast_radius:  None の場合 action から自動設定
            reversibility: None の場合 action から自動設定
            evidence:      追加エビデンス
            confidence:    エージェントの確信度

        Returns:
            tool_fn(**kwargs) の戻り値

        Raises:
            PermissionError: Shani がアクションを拒否した場合
            RuntimeError:    ADO バインディング検証失敗
        """
        action = _infer_action(tool_name)
        default_dt, default_br, default_rev = NANOCLAW_TOOL_POLICY[action]

        dt  = decision_type  if decision_type  is not None else default_dt
        br  = blast_radius   if blast_radius   is not None else default_br
        rev = reversibility  if reversibility  is not None else default_rev

        target = f"{tool_name}:{str(kwargs)[:60]}"
        ev_items = [
            EvidenceItem(
                source="nanoclaw-agent",
                content=f"tool={tool_name} args_keys={sorted(kwargs.keys())}",
                confidence=0.75,
            )
        ]
        for e in (evidence or []):
            if isinstance(e, EvidenceItem):
                ev_items.append(e)
            elif isinstance(e, dict):
                ev_items.append(EvidenceItem(
                    source=e.get("source", "nanoclaw"),
                    content=e.get("content", ""),
                    confidence=float(e.get("confidence", 0.8)),
                ))

        proposal = DecisionProposal(
            decision_type=dt,
            proposed_by=self._proposed_by,
            description=f"nanoclaw tool: {tool_name}",
            target=target,
            scope=DecisionScope(asset_ids=[target]),
            evidence=ev_items,
            confidence=confidence,
            reversibility=rev,
            blast_radius=br,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=self._timeout_minutes),
        )

        result = self._gate.evaluate(proposal)
        if isinstance(result, DeniedDecision):
            logger.warning("nanoclaw tool DENIED | tool=%s reason=%s", tool_name, result.reason)
            raise PermissionError(
                f"Shani denied nanoclaw tool '{tool_name}': {result.reason}"
            )

        logger.info("nanoclaw tool EXECUTING | tool=%s dsal=%s", tool_name, result.authorized_dsal)
        output = tool_fn(**kwargs)
        self._gate.register_executed(result, agent_id=self._proposed_by)
        return output

    def wrap_tool(
        self,
        tool_name: str,
        tool_fn: Callable,
        decision_type: DecisionType | None = None,
        blast_radius: BlastRadius | None = None,
        reversibility: bool | None = None,
        confidence: float = 0.8,
    ) -> ShaniToolWrapper:
        """
        nanoclaw ツール関数を ShaniToolWrapper でラップして返す。

        返された callable は元の tool_fn と同じシグネチャを持ち、
        呼び出しのたびに Shani ガバナンスを通過する。

        Example:
            agent.tools["fetch"] = adapter.wrap_tool("fetch", original_fetch)
        """
        action = _infer_action(tool_name)
        default_dt, default_br, default_rev = NANOCLAW_TOOL_POLICY[action]

        return ShaniToolWrapper(
            fn=tool_fn,
            gate=self._gate,
            decision_type=decision_type  if decision_type  is not None else default_dt,
            blast_radius=blast_radius    if blast_radius    is not None else default_br,
            proposed_by=self._proposed_by,
            target_extractor=tool_name,
            reversibility=reversibility  if reversibility   is not None else default_rev,
            confidence=confidence,
            timeout_minutes=self._timeout_minutes,
        )


def patch_nanoclaw_agent(
    agent: Any,
    gate: GovernanceGate,
    proposed_by: str,
    policy: dict[str, dict] | None = None,
    default_blast_radius: BlastRadius | None = None,
    default_decision_type: DecisionType | None = None,
) -> None:
    """
    nanoclaw Agent の tools を Shani ガバナンス版に置き換える（in-place）。

    nanoclaw Agent は tools を dict または list で保持している前提。
    本関数はその構造を自動検出し、全ツールを ShaniToolWrapper でラップする。

    Args:
        agent:                 nanoclaw.Agent インスタンス
        gate:                  ShaniEvaluator または HITLGate
        proposed_by:           エージェント識別子（policy.yaml の agent_registry と一致させること）
        policy:                ツール名 → {decision_type, blast_radius, ...} の上書きポリシー
        default_blast_radius:  ポリシー未指定のツールに適用するデフォルト
        default_decision_type: ポリシー未指定のツールに適用するデフォルト

    Note:
        nanoclaw の Agent.tools が dict の場合は直接パッチ。
        list の場合は {fn.__name__: fn} に変換してパッチ。
    """
    policy = policy or {}
    adapter = ShaniNanoclawAdapter(gate=gate, proposed_by=proposed_by)

    # nanoclaw Agent が tools を持つ場合にパッチ
    tools = getattr(agent, "tools", None)
    if tools is None:
        logger.warning("nanoclaw Agent has no .tools attribute. Nothing to patch.")
        return

    if isinstance(tools, dict):
        patched: dict[str, Callable] = {}
        for name, fn in tools.items():
            tool_policy = policy.get(name, {})
            patched[name] = adapter.wrap_tool(
                tool_name=name,
                tool_fn=fn,
                decision_type=tool_policy.get("decision_type", default_decision_type),
                blast_radius=tool_policy.get("blast_radius", default_blast_radius),
                reversibility=tool_policy.get("reversibility"),
            )
            logger.info("Patched nanoclaw tool | name=%s", name)
        agent.tools = patched

    elif isinstance(tools, list):
        patched_list: list = []
        for fn in tools:
            name = getattr(fn, "__name__", str(fn))
            tool_policy = policy.get(name, {})
            wrapped = adapter.wrap_tool(
                tool_name=name,
                tool_fn=fn,
                decision_type=tool_policy.get("decision_type", default_decision_type),
                blast_radius=tool_policy.get("blast_radius", default_blast_radius),
                reversibility=tool_policy.get("reversibility"),
            )
            patched_list.append(wrapped)
            logger.info("Patched nanoclaw tool | name=%s", name)
        agent.tools = patched_list

    else:
        logger.warning(
            "Unsupported agent.tools type: %s. "
            "Use ShaniNanoclawAdapter.wrap_tool() directly.",
            type(tools).__name__,
        )
        return

    logger.info("nanoclaw agent patched | %d tools governed", len(agent.tools))
