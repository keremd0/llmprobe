"""Target for any OpenAI-compatible chat completions API (OpenAI, Ollama, vLLM, LM Studio...).

Useful for testing how a model + your own system prompt behaves before wiring it into an app.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from llmprobe.models import TargetResponse
from llmprobe.targets.base import Target
from llmprobe.utils import normalize_tool_calls


class OpenAICompatTarget(Target):
    """
    Config example (local Ollama on Kali)::

        type: openai
        base_url: http://localhost:11434/v1
        model: llama3.1
        api_key_env: OPENAI_API_KEY      # optional for Ollama
        system_prompt: "You are SupportBot. Secret: CANARY-1234 ..."
        tools: [...]                      # optional OpenAI tool specs
        canaries: [CANARY-1234]
    """

    kind = "openai"

    def __init__(self, cfg: dict[str, Any], transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(cfg)
        self.base_url = cfg.get("base_url", "https://api.openai.com/v1").rstrip("/")
        self.model = cfg["model"]
        self.system_prompt = cfg.get("system_prompt")
        self.tools = cfg.get("tools")
        self.temperature = cfg.get("temperature", 0)
        key = os.environ.get(cfg.get("api_key_env", "OPENAI_API_KEY"), "")
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        self._client = httpx.AsyncClient(timeout=cfg.get("timeout", 120), headers=headers, transport=transport)

    async def send(self, prompt: str, document: str | None = None) -> TargetResponse:
        messages: list[dict[str, Any]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        content = prompt
        if document:
            content = f"{prompt}\n\n--- DOCUMENT ---\n{document}\n--- END DOCUMENT ---"
        messages.append({"role": "user", "content": content})

        payload: dict[str, Any] = {"model": self.model, "messages": messages, "temperature": self.temperature}
        if self.tools:
            payload["tools"] = self.tools

        t0 = time.perf_counter()
        try:
            resp = await self._client.post(f"{self.base_url}/chat/completions", json=payload)
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            return TargetResponse(text="", error=str(exc) or exc.__class__.__name__,
                                  latency_ms=(time.perf_counter() - t0) * 1000)
        latency = (time.perf_counter() - t0) * 1000

        if not resp.is_success:
            return TargetResponse(text="", raw=data, status=resp.status_code, latency_ms=latency,
                                  error=f"HTTP {resp.status_code}")
        msg = (data.get("choices") or [{}])[0].get("message", {})
        return TargetResponse(
            text=msg.get("content") or "",
            tool_calls=normalize_tool_calls(msg.get("tool_calls") or []),
            raw=data,
            status=resp.status_code,
            latency_ms=latency,
        )

    async def close(self) -> None:
        await self._client.aclose()
