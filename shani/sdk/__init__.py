"""
shani.sdk — Shani SDK for integrating governance into agent frameworks.

Sub-packages:
    python   Python SDK: adapters and schemas for LangChain, LangGraph,
             AutoGen, Nanoclaw, Chrome extension, and generic wrappers.

Usage:
    from shani.sdk.python import adapters, schemas
    from shani.sdk.python.adapters.langchain import patch_langchain_tools
"""

from . import python

__all__ = ["python"]
