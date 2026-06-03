"""
shani/_bootstrap.py

Inject pydantic shim when the real package is not installed.
Import this module FIRST, before any other shani import.

    import shani._bootstrap
    from shani import ShaniEvaluator, ...

Safe to import even when pydantic IS installed — it does nothing in that case.
"""
import sys

try:
    import pydantic  # noqa: F401
except ImportError:
    # Inject shim as `pydantic` into sys.modules
    import types
    from shani._compat import BaseModel, Field, field_validator, model_validator

    pydantic_mod = types.ModuleType("pydantic")
    pydantic_mod.BaseModel = BaseModel
    pydantic_mod.Field = Field
    pydantic_mod.field_validator = field_validator
    pydantic_mod.model_validator = model_validator
    sys.modules["pydantic"] = pydantic_mod
