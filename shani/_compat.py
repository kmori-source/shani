"""
shani/_compat.py — pydantic shim for environments without pydantic.

Drop-in replacement for pydantic.BaseModel sufficient to run Shani.
Provides: field validation, frozen models, model_copy, model_validator.

Install pydantic for production use:
    pip install "pydantic>=2.5"

This shim is intentionally minimal — it skips type coercion and
ge/le range validation. Use only for development/testing.
"""
from __future__ import annotations

import copy
import json
from typing import Any, Callable, ClassVar


class _FieldInfo:
    def __init__(self, default=..., default_factory=None, **kwargs):
        self.default = default
        self.default_factory = default_factory
        self.metadata = kwargs

    def has_default(self):
        return self.default is not ... or self.default_factory is not None

    def get_default(self):
        if self.default_factory is not None:
            return self.default_factory()
        return copy.deepcopy(self.default)


def Field(default=..., *, default_factory=None, **kwargs):
    return _FieldInfo(default=default, default_factory=default_factory, **kwargs)


def field_validator(*fields, **kwargs):
    def decorator(fn):
        fn._is_field_validator = True
        fn._validator_fields = fields
        return classmethod(fn)
    return decorator


def model_validator(*, mode="after"):
    def decorator(fn):
        fn._is_model_validator = True
        fn._validator_mode = mode
        return fn
    return decorator


class ModelMetaclass(type):
    def __new__(mcs, name, bases, namespace):
        annotations = {}
        for base in reversed(bases):
            annotations.update(getattr(base, "__annotations__", {}))
        annotations.update(namespace.get("__annotations__", {}))
        namespace["__annotations__"] = annotations

        # Collect field defaults
        fields = {}
        for base in reversed(bases):
            fields.update(getattr(base, "_fields", {}))
        for fname, _ in annotations.items():
            if fname.startswith("_"):
                continue
            if fname in namespace:
                val = namespace[fname]
                if isinstance(val, _FieldInfo):
                    fields[fname] = val
                elif not callable(val) and not isinstance(val, (classmethod, staticmethod, property)):
                    fields[fname] = _FieldInfo(default=val)
            elif fname not in fields:
                fields[fname] = _FieldInfo()  # required

        namespace["_fields"] = fields

        # Collect validators
        validators = {}
        model_validators = []
        for base in reversed(bases):
            validators.update(getattr(base, "_validators", {}))
            model_validators.extend(getattr(base, "_model_validators", []))
        for attr_name, val in namespace.items():
            if callable(val) and getattr(val, "_is_field_validator", False):
                for f in val._validator_fields:
                    validators[f] = val
            if callable(val) and getattr(val, "_is_model_validator", False):
                model_validators.append(val)
        namespace["_validators"] = validators
        namespace["_model_validators"] = model_validators

        cls = super().__new__(mcs, name, bases, namespace)
        return cls


class BaseModel(metaclass=ModelMetaclass):
    model_config: ClassVar[dict] = {}
    _fields: ClassVar[dict]
    _validators: ClassVar[dict]
    _model_validators: ClassVar[list]

    def __init__(self, **data: Any):
        for fname, finfo in self._fields.items():
            if fname in data:
                val = data[fname]
                # Run field validators
                if fname in self._validators:
                    v = self._validators[fname]
                    fn = v.__func__ if isinstance(v, classmethod) else v
                    val = fn(type(self), val)
                object.__setattr__(self, fname, val)
            elif finfo.has_default():
                object.__setattr__(self, fname, finfo.get_default())
            else:
                raise ValueError(f"{type(self).__name__}: missing required field '{fname}'")

        # Run model validators (mode="after")
        for mv in self._model_validators:
            result = mv(self)
            if result is not None:
                pass  # validator may mutate self via object.__setattr__

    def __setattr__(self, name, value):
        if self.model_config.get("frozen", False):
            raise TypeError(f"{type(self).__name__} is frozen")
        object.__setattr__(self, name, value)

    @classmethod
    def model_validate(cls, obj: dict) -> "BaseModel":
        return cls(**_coerce_model_data(cls, obj))

    @classmethod
    def model_construct(cls, **data: Any) -> "BaseModel":
        inst = cls.__new__(cls)
        for fname, finfo in cls._fields.items():
            if fname in data:
                object.__setattr__(inst, fname, data[fname])
            elif finfo.has_default():
                object.__setattr__(inst, fname, finfo.get_default())
            else:
                object.__setattr__(inst, fname, None)
        return inst

    def model_copy(self, *, update: dict | None = None) -> "BaseModel":
        data = {f: getattr(self, f) for f in self._fields}
        if update:
            data.update(update)
        return type(self)(**data)

    def model_dump(self, *, mode: str = "python") -> dict:
        result = {}
        for fname in self._fields:
            val = getattr(self, fname)
            result[fname] = _serialize_value(val, mode)
        return result

    def __repr__(self):
        fields = ", ".join(f"{k}={getattr(self, k)!r}" for k in self._fields)
        return f"{type(self).__name__}({fields})"

    def __eq__(self, other):
        if type(self) is not type(other):
            return False
        return all(getattr(self, f) == getattr(other, f) for f in self._fields)

    def __hash__(self):
        if not self.model_config.get("frozen", False):
            raise TypeError("unhashable type")
        return hash(tuple((f, _hashable(getattr(self, f))) for f in self._fields))


def _coerce_model_data(cls: type, data: dict) -> dict:
    """Pre-process data dict: coerce nested dicts/lists to appropriate types."""
    try:
        import typing
        hints = typing.get_type_hints(cls)
    except Exception:
        # get_type_hints fails when the shim module (_compat) is not in sys.modules,
        # because Python cannot find the namespace to evaluate string annotations on
        # BaseModel. Fall back: walk the MRO and evaluate each class's own annotations
        # in the context of *its own module* (which is in sys.modules for all real
        # shani modules). Private/ClassVar fields are skipped — they're never in `data`.
        import sys as _sys
        import builtins as _builtins
        hints = {}
        for klass in cls.__mro__:
            ann = getattr(klass, '__annotations__', {})
            if not ann:
                continue
            mod_name = getattr(klass, '__module__', None)
            mod = _sys.modules.get(mod_name) if mod_name else None
            globalns = mod.__dict__ if mod is not None else {}
            _local = {**globalns, '__builtins__': vars(_builtins)}
            for k, v in ann.items():
                if k.startswith('_') or k in hints:
                    continue
                if isinstance(v, str):
                    try:
                        hints[k] = eval(v, _local)  # noqa: S307
                    except Exception:
                        pass
                else:
                    hints[k] = v
        if not hints:
            return data
    out = {}
    for k, v in data.items():
        hint = hints.get(k)
        out[k] = _coerce_field_value(hint, v) if (hint is not None and v is not None) else v
    return out


def _coerce_field_value(hint: Any, v: Any) -> Any:
    """Coerce value v to match hint type when deserializing (shim only)."""
    import enum as _enum
    origin = getattr(hint, '__origin__', None)
    args = getattr(hint, '__args__', None) or ()

    # list[T] — coerce each element
    if origin is list and args and isinstance(v, list):
        inner = args[0]
        if isinstance(inner, type):
            if issubclass(inner, BaseModel):
                return [inner.model_validate(i) if isinstance(i, dict) else i for i in v]
            if issubclass(inner, _enum.Enum):
                return [inner(i) if isinstance(i, str) else i for i in v]
        return v

    # Union / Optional — unwrap single non-None arg and retry
    if args and v is not None:
        non_none = [a for a in args if a is not type(None)]
        is_union = False
        try:
            import typing
            if origin is typing.Union:
                is_union = True
        except Exception:
            pass
        if not is_union:
            try:
                import types as _types
                if isinstance(hint, _types.UnionType):
                    is_union = True
            except AttributeError:
                pass
        if is_union and len(non_none) == 1:
            return _coerce_field_value(non_none[0], v)

    # Enum subclass — coerce string to enum
    if isinstance(hint, type) and issubclass(hint, _enum.Enum) and isinstance(v, str):
        try:
            return hint(v)
        except (ValueError, KeyError):
            return v

    # BaseModel subclass — coerce dict to model
    if isinstance(hint, type) and issubclass(hint, BaseModel) and isinstance(v, dict):
        return hint.model_validate(v)

    # datetime — coerce ISO string to datetime (needed when model_validate is called
    # on JSON-serialized data where datetimes have been converted to ISO strings)
    import datetime as _dt
    if isinstance(hint, type) and issubclass(hint, _dt.datetime) and isinstance(v, str):
        try:
            return _dt.datetime.fromisoformat(v)
        except (ValueError, TypeError):
            return v

    return v


def _serialize_value(val: Any, mode: str) -> Any:
    import datetime
    import enum
    if isinstance(val, BaseModel):
        return val.model_dump(mode=mode)
    if isinstance(val, list):
        return [_serialize_value(v, mode) for v in val]
    if isinstance(val, dict):
        return {k: _serialize_value(v, mode) for k, v in val.items()}
    if mode == "json":
        if isinstance(val, datetime.datetime):
            return val.isoformat()
        if isinstance(val, datetime.date):
            return val.isoformat()
        if isinstance(val, enum.Enum):
            return val.value
    return val


def _hashable(v):
    if isinstance(v, dict):
        return tuple(sorted((k, _hashable(val)) for k, val in v.items()))
    if isinstance(v, list):
        return tuple(_hashable(i) for i in v)
    return v
