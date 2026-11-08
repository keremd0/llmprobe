"""Loads attack definitions from YAML files (built-in library + user directories)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import yaml

from llmprobe.models import OWASP_LLM_TOP10, Attack, Detector, Severity

BUILTIN_DIR = Path(__file__).parent / "payloads"
DETECTOR_TYPES = {"canary", "marker", "regex", "contains", "tool_call"}


class AttackDefinitionError(ValueError):
    pass


def parse_attack(data: dict[str, Any], source: str = "") -> Attack:
    missing = [k for k in ("id", "name", "owasp", "payloads", "detectors") if k not in data]
    if missing:
        raise AttackDefinitionError(f"{source}: missing field(s): {', '.join(missing)}")
    if data["owasp"] not in OWASP_LLM_TOP10:
        raise AttackDefinitionError(f"{source}: unknown OWASP id '{data['owasp']}'")

    detectors = []
    for d in data["detectors"]:
        if d.get("type") not in DETECTOR_TYPES:
            raise AttackDefinitionError(f"{source}: unknown detector type '{d.get('type')}'")
        detectors.append(Detector(type=d["type"], value=d.get("value"), arg=d.get("arg")))

    return Attack(
        id=data["id"],
        name=data["name"],
        category=data.get("category", data["owasp"]),
        owasp=data["owasp"],
        severity=Severity(data.get("severity", "medium")),
        description=(data.get("description") or "").strip(),
        payloads=[str(p).strip() for p in data["payloads"]],
        detectors=detectors,
        documents=[str(d).strip() for d in data.get("documents", [])],
        mutate=bool(data.get("mutate", True)),
        remediation=(data.get("remediation") or "").strip(),
        references=list(data.get("references", [])),
        source=source,
    )


def load_attacks(
    extra_dirs: Iterable[str | Path] = (),
    only: Iterable[str] | None = None,
    include_builtin: bool = True,
) -> list[Attack]:
    dirs = ([BUILTIN_DIR] if include_builtin else []) + [Path(d) for d in extra_dirs]
    attacks: dict[str, Attack] = {}
    for directory in dirs:
        for path in sorted(directory.glob("*.y*ml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            items = data if isinstance(data, list) else [data]
            for item in items:
                attack = parse_attack(item, source=str(path))
                attacks[attack.id] = attack  # user files can override built-ins by id

    wanted = set(only or [])
    if wanted:
        unknown = wanted - attacks.keys()
        if unknown:
            raise AttackDefinitionError(f"Unknown attack id(s): {', '.join(sorted(unknown))}")
        return [a for a in attacks.values() if a.id in wanted]
    return list(attacks.values())
