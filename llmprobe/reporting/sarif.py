"""SARIF 2.1.0 output so findings show up in GitHub code scanning / CI dashboards."""

from __future__ import annotations

import json
from pathlib import Path

from llmprobe import __version__
from llmprobe.models import ScanReport, Severity

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def write_sarif(report: ScanReport, path: Path) -> Path:
    rules, results = [], []
    for f in report.findings:
        a = f.attack
        rules.append({
            "id": a.id,
            "name": a.name,
            "shortDescription": {"text": a.name},
            "fullDescription": {"text": a.description or a.name},
            "help": {"text": a.remediation or "See references."},
            "helpUri": a.references[0] if a.references else "https://genai.owasp.org/",
            "properties": {
                "tags": ["security", "llm", a.owasp],
                "security-severity": SECURITY_SEVERITY[a.severity],
            },
        })
        if not f.vulnerable:
            continue
        evidence = f.examples[0].evidence if f.examples else ""
        results.append({
            "ruleId": a.id,
            "level": LEVEL[a.severity],
            "message": {
                "text": (
                    f"{a.name} ({a.owasp} {a.owasp_name}): {f.successes}/{f.total} probes succeeded "
                    f"(mutators: {', '.join(f.successful_mutators)}). Evidence: {evidence}"
                )
            },
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": report.target}}}],
            "properties": {"success_rate": round(f.success_rate, 3)},
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "llmprobe",
                "version": __version__,
                "informationUri": "https://github.com/",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
