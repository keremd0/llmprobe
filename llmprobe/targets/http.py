"""Generic HTTP target: works with almost any chatbot API via a request template."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from llmprobe.models import TargetResponse
from llmprobe.targets.base import Target
from llmprobe.utils import get_path, normalize_tool_calls, render


class HTTPTarget(Target):
    """
    Config example::

        type: http
        url: http://127.0.0.1:8765/chat
        method: POST
        headers: {Authorization: "Bearer ${API_TOKEN}"}
        body: {message: "{{prompt}}", document: "{{document}}"}
        response_path: reply
        tool_calls_path: tool_calls
    """

    kind = "http"

    def __init__(self, cfg: dict[str, Any], transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(cfg)
        self.url = cfg["url"]
        self.method = cfg.get("method", "POST").upper()
        self.headers = {k: os.path.expandvars(str(v)) for k, v in cfg.get("headers", {}).items()}
        self.body = cfg.get("body", {"message": "{{prompt}}"})
        self.response_path = cfg.get("response_path", "")
        self.tool_calls_path = cfg.get("tool_calls_path")
        self._client = httpx.AsyncClient(
            timeout=cfg.get("timeout", 60),
            transport=transport,
            verify=cfg.get("verify_tls", True),
            follow_redirects=True,
        )

    async def send(self, prompt: str, document: str | None = None) -> TargetResponse:
        body = render(self.body, {"prompt": prompt, "document": document or ""})
        t0 = time.perf_counter()
        try:
            if self.method == "GET":
                resp = await self._client.get(self.url, params=body, headers=self.headers)
            else:
                resp = await self._client.request(self.method, self.url, json=body, headers=self.headers)
        except httpx.HTTPError as exc:
            return TargetResponse(
                text="", error=str(exc) or exc.__class__.__name__,
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
        latency = (time.perf_counter() - t0) * 1000

        try:
            data: Any = resp.json()
        except ValueError:
            data = resp.text

        structured = isinstance(data, (dict, list))
        text = get_path(data, self.response_path) if structured else data
        tool_calls = get_path(data, self.tool_calls_path) if (structured and self.tool_calls_path) else []

        return TargetResponse(
            text="" if text is None else str(text),
            tool_calls=normalize_tool_calls(tool_calls),
            raw=data,
            status=resp.status_code,
            latency_ms=latency,
            error=None if resp.is_success else f"HTTP {resp.status_code}",
        )

    async def close(self) -> None:
        await self._client.aclose()
