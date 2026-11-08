"""Small helpers: JSON path lookup, template rendering, markers."""

from __future__ import annotations

import json
import secrets
from typing import Any


def get_path(obj: Any, path: str | None) -> Any:
    """Resolve a dotted path such as ``choices.0.message.content`` or ``data[0].reply``."""
    if not path:
        return obj
    cur = obj
    for part in path.replace("[", ".").replace("]", "").split("."):
        if part == "":
            continue
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


def render(obj: Any, variables: dict[str, str]) -> Any:
    """Replace ``{{name}}`` placeholders inside any nested JSON-like structure.

    Substitution happens on Python objects, so values are JSON-escaped correctly
    when the body is serialised later.
    """
    if isinstance(obj, str):
        for key, value in variables.items():
            obj = obj.replace("{{" + key + "}}", value)
        return obj
    if isinstance(obj, dict):
        return {k: render(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render(v, variables) for v in obj]
    return obj


def new_marker() -> str:
    """Unique token an attack asks the model to output. Its presence proves control."""
    return "LLMP-" + secrets.token_hex(3).upper()


def normalize_tool_calls(calls: Any) -> list[dict[str, Any]]:
    """Accept plain ``{name, arguments}`` dicts or OpenAI-style ``{function: {...}}``."""
    if not isinstance(calls, list):
        return []
    out = []
    for call in calls:
        if not isinstance(call, dict):
            continue
        fn = call.get("function", call)
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"_raw": args}
        out.append({"name": fn.get("name", ""), "arguments": args})
    return out


def snippet(text: str, start: int, length: int, context: int = 80) -> str:
    lo = max(0, start - context)
    hi = min(len(text), start + length + context)
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(text) else ""
    return prefix + text[lo:hi] + suffix
