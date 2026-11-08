"""Self-contained single-file HTML report."""

from __future__ import annotations

import json
from collections import Counter
from html import escape
from pathlib import Path

from llmprobe import __version__
from llmprobe.models import Finding, Result, ScanReport, Severity

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1b1f24;--muted:#5b6470;--line:#e3e6ea;--code:#f0f2f5;
--crit:#b3132b;--high:#d9480f;--med:#b08800;--low:#1971c2;--ok:#2b8a3e}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8eb;--muted:#9aa3ad;
--line:#262b35;--code:#1e232c;--crit:#ff6b6b;--high:#ff922b;--med:#fcc419;--low:#4dabf7;--ok:#51cf66}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}
.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:20px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.stat b{display:block;font-size:26px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:18px 20px;margin-bottom:14px}.head{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.head h3{margin:0;font-size:17px;flex:1 1 auto}.badge{font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;
border:1px solid currentColor;white-space:nowrap}.critical{color:var(--crit)}.high{color:var(--high)}
.medium{color:var(--med)}.low,.info{color:var(--low)}.ok{color:var(--ok)}
.bar{height:6px;background:var(--line);border-radius:3px;overflow:hidden;margin:10px 0}
.bar span{display:block;height:100%;background:currentColor}
pre{background:var(--code);padding:10px 12px;border-radius:8px;overflow-x:auto;white-space:pre-wrap;
word-break:break-word;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;margin:6px 0}
details{margin-top:10px}summary{cursor:pointer;color:var(--muted);font-size:14px}
.ex{border-top:1px dashed var(--line);padding-top:10px;margin-top:10px}.lbl{font-size:12px;
text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-top:8px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line)}
mark{background:transparent;color:var(--crit);font-weight:600}a{color:var(--low)}
.legal{margin-top:40px;font-size:13px}
"""


def _sev(s: Severity) -> str:
    return f'<span class="badge {s.value}">{s.value.upper()}</span>'


def _example(r: Result) -> str:
    parts = [f'<div class="ex"><div class="lbl">Mutator: {escape(r.probe.mutator)} · '
             f'Detector: {escape(r.detector or "-")}</div>']
    parts.append(f'<div class="lbl">Prompt</div><pre>{escape(r.probe.prompt)}</pre>')
    if r.probe.document:
        parts.append(f'<div class="lbl">Injected document</div><pre>{escape(r.probe.document)}</pre>')
    parts.append(f'<div class="lbl">Evidence</div><pre><mark>{escape(r.evidence or "")}</mark></pre>')
    if r.response.tool_calls:
        parts.append(f'<div class="lbl">Tool calls</div><pre>'
                     f'{escape(json.dumps(r.response.tool_calls, indent=2, ensure_ascii=False))}</pre>')
    parts.append("</div>")
    return "".join(parts)


def _finding(f: Finding) -> str:
    a = f.attack
    state = (f'<span class="badge critical">VULNERABLE</span>' if f.vulnerable
             else '<span class="badge ok">PASSED</span>')
    color = a.severity.value if f.vulnerable else "ok"
    refs = "".join(f'<li><a href="{escape(u)}">{escape(u)}</a></li>' for u in a.references)
    examples = "".join(_example(r) for r in f.examples)
    return f"""
<div class="card">
  <div class="head"><h3>{escape(a.name)}</h3>{_sev(a.severity)}
    <span class="badge low">{escape(a.owasp)} · {escape(a.owasp_name)}</span>{state}</div>
  <div class="bar {color}"><span style="width:{f.success_rate * 100:.1f}%"></span></div>
  <div class="muted">{f.successes}/{f.total} probes succeeded ({f.success_rate:.0%})
    {"· bypassing mutators: <b>" + escape(", ".join(f.successful_mutators)) + "</b>" if f.successful_mutators else ""}
    {f"· {f.errors} errors" if f.errors else ""}</div>
  <p>{escape(a.description)}</p>
  {f"<details open><summary>Evidence ({len(f.examples)} example(s))</summary>{examples}</details>" if examples else ""}
  <details><summary>Remediation</summary><p>{escape(a.remediation)}</p><ul>{refs}</ul></details>
</div>"""


def _matrix(report: ScanReport) -> str:
    mutators = sorted({r.probe.mutator for r in report.results})
    rows = []
    for f in sorted(report.findings, key=lambda f: -f.attack.severity.rank):
        cells = []
        for m in mutators:
            rs = [r for r in report.results if r.probe.attack.id == f.attack.id and r.probe.mutator == m]
            if not rs:
                cells.append('<td class="muted">-</td>')
                continue
            hits = sum(r.success for r in rs)
            cls = "critical" if hits else "ok"
            cells.append(f'<td class="{cls}">{hits}/{len(rs)}</td>')
        rows.append(f"<tr><td>{escape(f.attack.name)}</td>{''.join(cells)}</tr>")
    head = "".join(f"<th>{escape(m)}</th>" for m in mutators)
    return f"<table><tr><th>Attack</th>{head}</tr>{''.join(rows)}</table>"


def write_html(report: ScanReport, path: Path) -> Path:
    vuln = report.vulnerable_findings
    sev_count = Counter(f.attack.severity for f in vuln)
    successes = sum(r.success for r in report.results)
    stats = [
        ("Probes sent", len(report.results), ""),
        ("Successful probes", successes, "critical" if successes else "ok"),
        ("Vulnerable attacks", f"{len(vuln)}/{len(report.findings)}", "critical" if vuln else "ok"),
        ("Critical / High", f"{sev_count[Severity.CRITICAL]} / {sev_count[Severity.HIGH]}", "high" if vuln else "ok"),
    ]
    stat_html = "".join(f'<div class="stat"><span class="muted">{escape(k)}</span><b class="{c}">{v}</b></div>'
                        for k, v, c in stats)
    ordered = sorted(report.findings, key=lambda f: (not f.vulnerable, -f.attack.severity.rank, -f.success_rate))

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>llmprobe report</title>
<style>{CSS}</style></head><body><div class="wrap">
<h1>llmprobe security report</h1>
<div class="muted">Target: <b>{escape(report.target)}</b> · {escape(report.started)} → {escape(report.finished)}
 · llmprobe v{__version__}</div>
<div class="grid">{stat_html}</div>
<h2>Findings</h2>{"".join(_finding(f) for f in ordered)}
<h2>Attack × mutator matrix</h2>
<div class="card"><p class="muted">Which obfuscation techniques got past the target's defences.</p>{_matrix(report)}</div>
<p class="legal muted">Generated by llmprobe. Only test systems you own or are explicitly authorised to assess.</p>
</div></body></html>"""
    path.write_text(page, encoding="utf-8")
    return path
