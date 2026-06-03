"""
Shani cowork Adapter — Claude API (Anthropic) tool_use ガバナンス。

cowork は Claude API の tool_use 機能を用いたマルチエージェント協調フレームワーク。
本アダプターは Claude API が返す tool_use ブロックを実行する前に Shani ガバナンスを
通過させ、DecisionProposal → ADO → Capability フローを強制する。

依存関係: anthropic パッケージ（オプション）。インポートせずとも使用可能。

Flow:
    Claude API
        ↓ response.content[i].type == "tool_use"
    ShaniCoworkAdapter.execute_tool_use()
        ├─ DecisionProposal を構築
        ├─ gate.evaluate()
        │     ├─ D-SAL チェック
        │     └─ HITL（D-SAL >= threshold の場合）
        └─ 承認後 tool_fn(**tool_input) を実行

Usage (Claude API ループの中で):

    import anthropic
    from shani.adapters.cowork import ShaniCoworkAdapter
    from shani.hitl import HITLGate

    adapter = ShaniCoworkAdapter(
        gate=hitl_gate,
        proposed_by="cowork-agent/v1",
        policy={
            "bash":       dict(decision_type=DecisionType.AGENT_TASK,          blast_radius=BlastRadius.SIGNIFICANT),
            "write_file": dict(decision_type=DecisionType.CONFIGURATION_CHANGE, blast_radius=BlastRadius.LIMITED),
            "read_file":  dict(decision_type=DecisionType.DATA_ACCESS,          blast_radius=BlastRadius.ISOLATED),
        },
    )

    client = anthropic.Anthropic()
    tools = [...]  # anthropic ToolParam リスト

    response = client.messages.create(
        model="claude-opus-4-7-20261001",
        tools=tools,
        messages=messages,
    )

    # tool_use ブロックを Shani 経由で処理
    tool_results = adapter.process_response(response, tool_registry)

    # tool_results を次の messages に追加して継続
    messages.append({"role": "assistant", "content": response.content})
    messages.append({"role": "user", "content": tool_results})

ツールレジストリ形式:
    tool_registry = {
        "bash":       lambda input: subprocess.check_output(input["command"], shell=True),
        "read_file":  lambda input: open(input["path"]).read(),
        "write_file": lambda input: open(input["path"], "w").write(input["content"]),
    }
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Any, Callable

from ...schemas.decision import (
    BlastRadius,
    DecisionProposal,
    DecisionScope,
    DecisionType,
    EvidenceItem,
)
from ...core.evaluator import DeniedDecision
from ...adapters.generic.wrapper import GovernanceGate

logger = logging.getLogger("shani.adapter.cowork")


@dataclass
class CoworkToolPolicy:
    """
    個別ツールの Shani ガバナンスポリシー。

    tool_registry に登録された各ツール名に対して設定する。
    未設定のツールはデフォルトポリシー（TOOL_CALL / LIMITED）が適用される。
    """
    decision_type: DecisionType = DecisionType.TOOL_CALL
    blast_radius: BlastRadius = BlastRadius.LIMITED
    reversibility: bool = True
    confidence_override: float | None = None


# ツール名パターンからデフォルトポリシーを推定
_TOOL_PATTERNS: list[tuple[list[str], CoworkToolPolicy]] = [
    (
        ["bash", "shell", "exec", "run", "command", "cmd"],
        CoworkToolPolicy(DecisionType.AGENT_TASK, BlastRadius.SIGNIFICANT, False),
    ),
    (
        ["write", "save", "create", "update", "delete", "remove", "put", "post"],
        CoworkToolPolicy(DecisionType.CONFIGURATION_CHANGE, BlastRadius.LIMITED, True),
    ),
    (
        ["http", "request", "call", "api"],
        CoworkToolPolicy(DecisionType.NETWORK_ACTION, BlastRadius.LIMITED, True),
    ),
    (
        ["read", "get", "fetch", "list", "search", "find", "query"],
        CoworkToolPolicy(DecisionType.DATA_ACCESS, BlastRadius.ISOLATED, True),
    ),
]


def _infer_policy(tool_name: str) -> CoworkToolPolicy:
    """ツール名からデフォルト CoworkToolPolicy を推定する。"""
    name = tool_name.lower()
    for keywords, policy in _TOOL_PATTERNS:
        if any(kw in name for kw in keywords):
            return policy
    return CoworkToolPolicy()  # デフォルト: TOOL_CALL / LIMITED


class ShaniCoworkAdapter:
    """
    Claude API (Anthropic) の tool_use ブロックを Shani ガバナンスでラップするアダプター。

    cowork マルチエージェントフレームワークや Claude API を直接使用するコードで
    tool_use の実行を Shani DecisionProposal フローに通す。

    anthropic パッケージへの依存は実行時のみ（型ヒントには使わない）。
    anthropic がインストールされていない環境でも import できる。
    """

    def __init__(
        self,
        gate: GovernanceGate,
        proposed_by: str = "cowork-agent/v1",
        policy: dict[str, dict | CoworkToolPolicy] | None = None,
        timeout_minutes: int = 10,
        deny_on_unknown_tool: bool = False,
    ) -> None:
        """
        Args:
            gate:                 ShaniEvaluator または HITLGate
            proposed_by:          エージェント識別子
            policy:               ツール名 → CoworkToolPolicy または dict
            timeout_minutes:      ADO 有効期限（分）
            deny_on_unknown_tool: レジストリ未登録のツールを拒否するか（デフォルト: False = 警告して実行）
        """
        self._gate = gate
        self._proposed_by = proposed_by
        self._timeout_minutes = timeout_minutes
        self._deny_on_unknown = deny_on_unknown_tool

        self._policy: dict[str, CoworkToolPolicy] = {}
        for name, p in (policy or {}).items():
            if isinstance(p, CoworkToolPolicy):
                self._policy[name] = p
            elif isinstance(p, dict):
                self._policy[name] = CoworkToolPolicy(
                    decision_type=p.get("decision_type", DecisionType.TOOL_CALL),
                    blast_radius=p.get("blast_radius", BlastRadius.LIMITED),
                    reversibility=bool(p.get("reversibility", True)),
                    confidence_override=p.get("confidence_override"),
                )

    def _get_policy(self, tool_name: str) -> CoworkToolPolicy:
        return self._policy.get(tool_name) or _infer_policy(tool_name)

    def execute_tool_use(
        self,
        tool_use_block: Any,
        tool_fn: Callable,
        context: str | None = None,
        confidence: float = 0.85,
    ) -> Any:
        """
        単一の tool_use ブロックを Shani 経由で実行する。

        Args:
            tool_use_block: anthropic ToolUseBlock（.name, .input, .id を持つオブジェクト）
                            または dict {"name": ..., "input": ..., "id": ...}
            tool_fn:        実際のツール実装 callable（input dict を受け取る）
            context:        Claude の思考テキスト（エビデンスとして使用）
            confidence:     実行の確信度

        Returns:
            tool_fn(tool_use_block.input) の戻り値

        Raises:
            PermissionError: Shani がアクションを拒否した場合
        """
        if isinstance(tool_use_block, dict):
            tool_name  = tool_use_block["name"]
            tool_input = tool_use_block.get("input", {})
            tool_id    = tool_use_block.get("id", "unknown")
        else:
            tool_name  = tool_use_block.name
            tool_input = tool_use_block.input
            tool_id    = getattr(tool_use_block, "id", "unknown")

        pol = self._get_policy(tool_name)
        target = f"{tool_name}:{str(tool_input)[:80]}"

        evidence: list[EvidenceItem] = [
            EvidenceItem(
                source="claude-api-tool-use",
                content=f"tool_use_id={tool_id} name={tool_name}",
                confidence=0.9,
            )
        ]
        if context:
            evidence.append(EvidenceItem(
                source="claude-thinking",
                content=context[:200],
                confidence=0.7,
            ))

        proposal = DecisionProposal(
            decision_type=pol.decision_type,
            proposed_by=self._proposed_by,
            description=f"cowork tool_use: {tool_name}",
            target=target,
            scope=DecisionScope(asset_ids=[target]),
            evidence=evidence,
            confidence=pol.confidence_override if pol.confidence_override is not None else confidence,
            reversibility=pol.reversibility,
            blast_radius=pol.blast_radius,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=self._timeout_minutes),
        )

        result = self._gate.evaluate(proposal)
        if isinstance(result, DeniedDecision):
            logger.warning(
                "cowork tool_use DENIED | tool=%s reason=%s", tool_name, result.reason
            )
            raise PermissionError(
                f"Shani denied cowork tool '{tool_name}': {result.reason}"
            )

        logger.info(
            "cowork tool_use EXECUTING | tool=%s dsal=%s", tool_name, result.authorized_dsal
        )
        output = tool_fn(tool_input)
        self._gate.register_executed(result, agent_id=self._proposed_by)
        return output

    def process_response(
        self,
        response: Any,
        tool_registry: dict[str, Callable],
        context: str | None = None,
    ) -> list[dict]:
        """
        Claude API レスポンス内の全 tool_use ブロックを Shani 経由で処理する。

        Args:
            response:       anthropic Messages レスポンスオブジェクト
                            （.content がブロックのリスト）
            tool_registry:  {"tool_name": callable} の dict
            context:        Claude の思考テキスト（エビデンス）

        Returns:
            tool_result コンテンツブロックのリスト（次の user メッセージに追加する）

        Example:
            messages.append({"role": "assistant", "content": response.content})
            tool_results = adapter.process_response(response, tool_registry)
            messages.append({"role": "user", "content": tool_results})
        """
        tool_results: list[dict] = []

        content = getattr(response, "content", response) if not isinstance(response, list) else response

        for block in content:
            block_type = block.get("type") if isinstance(block, dict) else getattr(block, "type", None)
            if block_type != "tool_use":
                continue

            if isinstance(block, dict):
                tool_name = block["name"]
                tool_id   = block.get("id", "unknown")
            else:
                tool_name = block.name
                tool_id   = getattr(block, "id", "unknown")

            tool_fn = tool_registry.get(tool_name)
            if tool_fn is None:
                if self._deny_on_unknown:
                    logger.error("Unknown tool '%s' — denied (deny_on_unknown_tool=True)", tool_name)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "is_error": True,
                        "content": f"Unknown tool: {tool_name}",
                    })
                    continue
                else:
                    logger.warning("Unknown tool '%s' — not in registry, skipping", tool_name)
                    continue

            try:
                output = self.execute_tool_use(
                    tool_use_block=block,
                    tool_fn=tool_fn,
                    context=context,
                )
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": str(output),
                })
            except PermissionError as exc:
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "is_error": True,
                    "content": str(exc),
                })

        return tool_results

    def wrap_tool_registry(
        self,
        tool_registry: dict[str, Callable],
    ) -> dict[str, Callable]:
        """
        ツールレジストリ全体を Shani ガバナンス版に変換して返す。

        元の callable の代わりに governed_fn を返す。
        governed_fn は (tool_input: dict) を引数にとり Shani を通過する。

        Example:
            governed_registry = adapter.wrap_tool_registry(tool_registry)
            # governed_registry の callable はすべて Shani 承認済みのみ実行される
        """
        governed: dict[str, Callable] = {}
        for name, fn in tool_registry.items():
            # クロージャでバインド
            def make_governed(tool_name: str, tool_func: Callable) -> Callable:
                def governed_fn(tool_input: dict, _context: str | None = None) -> Any:
                    return self.execute_tool_use(
                        tool_use_block={"name": tool_name, "input": tool_input, "id": "wrapped"},
                        tool_fn=tool_func,
                        context=_context,
                    )
                governed_fn.__name__ = f"shani_governed_{tool_name}"
                return governed_fn
            governed[name] = make_governed(name, fn)
            logger.info("Wrapped cowork tool | name=%s", name)
        return governed
