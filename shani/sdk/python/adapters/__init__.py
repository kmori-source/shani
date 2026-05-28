"""
shani.sdk.python.adapters — Framework adapters (re-exports from shani.adapters).

Available adapters (imported on demand to avoid optional dependency errors):
    generic      governed_tool, ShaniToolWrapper
    langchain    patch_langchain_tools  (requires langchain-core)
    langgraph    ShaniLangGraphCheckpointer (requires langgraph)
    autogen      patch_autogen_agent    (requires autogen)
    nanoclaw     NanoclawAdapter        (requires httpx or requests)
    chrome       ChromeAdapter
    cowork       CoworkAdapter

Usage:
    from shani.sdk.python.adapters.langchain import patch_langchain_tools
    from shani.sdk.python.adapters.generic import governed_tool
"""
