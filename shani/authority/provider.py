"""
Shani Authority Module.

Human authority mapping: D-SAL → named human role.

Humans do not make decisions at runtime.
Humans define the boundaries. Shani enforces them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


# Default authority map (used when no config file is present)
DEFAULT_AUTHORITY_MAP: dict[int, str] = {
    0: "any-operator",
    1: "SOC-Analyst",
    2: "SecOps-Lead",
    3: "Org-Policy",
    4: "Board-Level",
}


class YAMLAuthorityProvider:
    """
    Loads authority configuration from a YAML file.

    Expected YAML format:

        authority:
          D-SAL-0: any-operator
          D-SAL-1: SOC-Analyst
          D-SAL-2: SecOps-Lead
          D-SAL-3: Org-Policy
          D-SAL-4: Board-Level
        max_authorized_dsal: 2
    """

    def __init__(self, config_path: Path | str | None = None) -> None:
        self._map: dict[int, str] = {}
        self._max: int = 0

        if config_path is not None:
            self._load(Path(config_path))
        else:
            self._map = DEFAULT_AUTHORITY_MAP.copy()
            self._max = max(self._map.keys())

    def _load(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Authority config not found: {path}")

        with path.open() as f:
            import yaml

            data: dict[str, Any] = yaml.safe_load(f)

        authority_block = data.get("authority", {})
        for key, value in authority_block.items():
            level = int(key.replace("D-SAL-", ""))
            self._map[level] = str(value)

        self._max = int(data.get("max_authorized_dsal", max(self._map.keys())))

    def resolve_authority(self, effective_dsal: int) -> str:
        return self._map.get(effective_dsal, f"undefined-authority-for-dsal-{effective_dsal}")

    def max_authorized_dsal(self) -> int:
        return self._max


class StaticAuthorityProvider:
    """
    In-memory authority provider for testing and embedded use.
    """

    def __init__(
        self,
        authority_map: dict[int, str] | None = None,
        max_dsal: int = 2,
    ) -> None:
        self._map = authority_map or DEFAULT_AUTHORITY_MAP.copy()
        self._max = max_dsal

    def resolve_authority(self, effective_dsal: int) -> str:
        return self._map.get(effective_dsal, f"undefined-dsal-{effective_dsal}")

    def max_authorized_dsal(self) -> int:
        return self._max
