from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from llmprobe.models import TargetResponse


class Target(ABC):
    """Something that receives a prompt (and optionally a document) and answers."""

    kind = "base"

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        # Secrets planted in the system prompt / context. Seeing one in a reply = leak.
        self.canaries: list[str] = list(cfg.get("canaries", []))

    @property
    def label(self) -> str:
        return self.cfg.get("name") or self.cfg.get("url") or self.cfg.get("base_url") or self.kind

    @abstractmethod
    async def send(self, prompt: str, document: str | None = None) -> TargetResponse: ...

    async def close(self) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()
