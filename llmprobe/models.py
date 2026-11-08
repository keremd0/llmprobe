"""Core data structures shared across the framework."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


OWASP_LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


@dataclass
class Detector:
    """How success of an attack is decided. See judges.py for the types."""

    type: str  # canary | marker | regex | contains | tool_call
    value: str | None = None
    arg: str | None = None  # tool_call only: substring required in the arguments


@dataclass
class Attack:
    id: str
    name: str
    category: str
    owasp: str
    severity: Severity
    description: str
    payloads: list[str]
    detectors: list[Detector]
    documents: list[str] = field(default_factory=list)
    mutate: bool = True
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    source: str = ""

    @property
    def owasp_name(self) -> str:
        return OWASP_LLM_TOP10.get(self.owasp, "")


@dataclass
class Probe:
    """One concrete request sent to the target."""

    attack: Attack
    payload: str  # payload before mutation
    prompt: str  # what is actually sent as the user message
    mutator: str
    marker: str
    document: str | None = None


@dataclass
class TargetResponse:
    text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw: Any = None
    status: int | None = None
    latency_ms: float = 0.0
    error: str | None = None


@dataclass
class Result:
    probe: Probe
    response: TargetResponse
    success: bool
    detector: str | None = None
    evidence: str | None = None


@dataclass
class Finding:
    """Aggregated outcome of one attack across all its probes."""

    attack: Attack
    total: int
    successes: int
    errors: int
    successful_mutators: list[str]
    examples: list[Result]

    @property
    def success_rate(self) -> float:
        return self.successes / self.total if self.total else 0.0

    @property
    def vulnerable(self) -> bool:
        return self.successes > 0


@dataclass
class ScanReport:
    target: str
    started: str
    finished: str
    results: list[Result]
    findings: list[Finding]

    @property
    def vulnerable_findings(self) -> list[Finding]:
        return sorted(
            (f for f in self.findings if f.vulnerable),
            key=lambda f: (-f.attack.severity.rank, -f.success_rate),
        )
