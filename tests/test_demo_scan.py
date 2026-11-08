"""End-to-end: scan the vulnerable demo app in-process (no network, no server)."""

import httpx
import pytest

pytest.importorskip("fastapi")

from demo.vulnerable_app.app import app  # noqa: E402
from llmprobe.attacks import load_attacks  # noqa: E402
from llmprobe.engine import Engine  # noqa: E402
from llmprobe.reporting import write_html, write_json, write_sarif  # noqa: E402
from llmprobe.targets import build_target  # noqa: E402

CFG = {
    "type": "http",
    "url": "http://vulnbot/chat",
    "body": {"message": "{{prompt}}", "document": "{{document}}"},
    "response_path": "reply",
    "tool_calls_path": "tool_calls",
    "canaries": ["CANARY-7f3a91"],
}


async def test_demo_app_is_found_vulnerable(tmp_path):
    target = build_target(CFG, transport=httpx.ASGITransport(app=app))
    async with target:
        report = await Engine(target, load_attacks(),
                              ["identity", "base64", "payload_split", "roleplay"]).run()

    by_id = {f.attack.id: f for f in report.findings}
    for attack_id in ("system-prompt-leak", "direct-prompt-injection", "indirect-prompt-injection",
                      "excessive-agency-tool-abuse", "sensitive-data-disclosure"):
        assert by_id[attack_id].vulnerable, attack_id

    # The naive blocklist stops the plain "system prompt" payload, but encodings bypass it.
    leak = by_id["system-prompt-leak"]
    assert "base64" in leak.successful_mutators
    assert leak.success_rate < 1.0

    assert all(r.response.error is None for r in report.results)
    for writer, name in ((write_html, "r.html"), (write_json, "r.json"), (write_sarif, "r.sarif")):
        assert writer(report, tmp_path / name).stat().st_size > 0
