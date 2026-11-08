from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from llmprobe import __version__
from llmprobe.models import Finding, Result, ScanReport


def _result(r: Result) -> dict[str, Any]:
    return {
        "attack": r.probe.attack.id,
        "mutator": r.probe.mutator,
        "success": r.success,
        "detector": r.detector,
        "evidence": r.evidence,
        "prompt": r.probe.prompt,
        "document": r.probe.document,
        "response": r.response.text,
        "tool_calls": r.response.tool_calls,
        "status": r.response.status,
        "latency_ms": round(r.response.latency_ms, 1),
        "error": r.response.error,
    }


def _finding(f: Finding) -> dict[str, Any]:
    a = f.attack
    return {
        "id": a.id,
        "name": a.name,
        "owasp": a.owasp,
        "owasp_name": a.owasp_name,
        "severity": a.severity.value,
        "vulnerable": f.vulnerable,
        "probes": f.total,
        "successes": f.successes,
        "errors": f.errors,
        "success_rate": round(f.success_rate, 3),
        "successful_mutators": f.successful_mutators,
        "description": a.description,
        "remediation": a.remediation,
        "references": a.references,
        "examples": [_result(r) for r in f.examples],
    }


def report_to_dict(report: ScanReport, include_all_results: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {
        "tool": "llmprobe",
        "version": __version__,
        "target": report.target,
        "started": report.started,
        "finished": report.finished,
        "summary": {
            "probes": len(report.results),
            "successful_probes": sum(r.success for r in report.results),
            "errors": sum(1 for r in report.results if r.response.error),
            "vulnerable_attacks": len(report.vulnerable_findings),
        },
        "findings": [_finding(f) for f in sorted(report.findings, key=lambda f: -f.attack.severity.rank)],
    }
    if include_all_results:
        data["results"] = [_result(r) for r in report.results]
    return data


def write_json(report: ScanReport, path: Path) -> Path:
    path.write_text(json.dumps(report_to_dict(report), indent=2, ensure_ascii=False), encoding="utf-8")
    return path
