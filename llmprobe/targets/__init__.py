from __future__ import annotations

from typing import Any

from llmprobe.targets.base import Target
from llmprobe.targets.http import HTTPTarget
from llmprobe.targets.openai_compat import OpenAICompatTarget

TARGET_TYPES: dict[str, type[Target]] = {
    "http": HTTPTarget,
    "openai": OpenAICompatTarget,
}


def build_target(cfg: dict[str, Any], transport=None) -> Target:
    kind = cfg.get("type", "http")
    if kind not in TARGET_TYPES:
        raise ValueError(f"Unknown target type '{kind}'. Available: {', '.join(TARGET_TYPES)}")
    return TARGET_TYPES[kind](cfg, transport=transport)


__all__ = ["Target", "HTTPTarget", "OpenAICompatTarget", "build_target"]
