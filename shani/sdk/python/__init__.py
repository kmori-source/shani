"""
shani.sdk.python — Python SDK for Shani governance.

Re-exports from shani.adapters and shani.schemas (Phase 3 logical split).

Adapters provide framework-specific integration:
    langchain    patch_langchain_tools()
    langgraph    ShaniLangGraphCheckpointer
    autogen      patch_autogen_agent()
    nanoclaw     NanoclawAdapter, NanoclawSidecarClient
    chrome       ChromeAdapter
    cowork       CoworkAdapter
    generic      governed_tool, ShaniToolWrapper

Schemas provide the core data model:
    decision     DecisionProposal, AuthorizedDecisionObject, DecisionType…
    posture      UserPosture, PostureConstraints…
    state        DIS, DSAL, DISStateMachine

Usage:
    from shani.sdk.python.schemas.decision import DecisionProposal
    from shani.sdk.python.adapters.generic import governed_tool
"""
from shani import schemas  # noqa: F401

__all__ = ["schemas"]


def __getattr__(name: str) -> object:
    if name == "adapters":
        from shani import adapters
        return adapters
    raise AttributeError(f"module 'shani.sdk.python' has no attribute {name!r}")
