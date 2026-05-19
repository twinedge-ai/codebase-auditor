from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def resolve_external_tool(config: dict[str, Any], name: str) -> str | None:
    tools = config.get("externalTools", {})
    if not isinstance(tools, dict):
        return None
    configured = tools.get(name)
    if not configured:
        return None
    path = Path(str(configured)).expanduser()
    if not path.is_absolute():
        return None
    try:
        normalized = Path(os.path.normpath(str(path)))
        realpath = Path(os.path.realpath(str(path)))
        if realpath != normalized:
            return None
        if normalized.is_file() and os.access(normalized, os.X_OK):
            return str(normalized)
    except OSError:
        return None
    return None
