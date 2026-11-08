"""Scan engine: expands attacks into probes, sends them concurrently, judges and aggregates."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable

from llmprobe.judges import judge
from llmprobe.models import Attack, Finding, Probe, Result, ScanReport
from llmprobe.mutators import get_mutators
from llmprobe.targets.base import Target
from llmprobe.utils import new_marker


def build_probes(attacks: list[Attack], mutator_names: list[str] | None = None) -> list[Probe]:
    mutators = get_mutators(mutator_names)
    probes: list[Probe] = []
    for attack in attacks:
        active = mutators if attack.mutate else {"identity": mutators.get("identity") or (lambda p: p)}
        documents = attack.documents or [None]
        for payload in attack.payloads:
            for document in documents:
                for name, fn in active.items():
                    marker = new_marker()
                    filled = payload.replace("{marker}", marker)
                    probes.append(Probe(
                        attack=attack,
                        payload=filled,
                        prompt=fn(filled),
                        mutator=name,
                        marker=marker,
                        document=document.replace("{marker}", marker) if document else None,
                    ))
    return probes


def aggregate(results: list[Result], max_examples: int = 3) -> list[Finding]:
    by_attack: dict[str, list[Result]] = defaultdict(list)
    attacks: dict[str, Attack] = {}
    for r in results:
        by_attack[r.probe.attack.id].append(r)
        attacks[r.probe.attack.id] = r.probe.attack

    findings = []
    for attack_id, rs in by_attack.items():
        wins = [r for r in rs if r.success]
        findings.append(Finding(
            attack=attacks[attack_id],
            total=len(rs),
            successes=len(wins),
            errors=sum(1 for r in rs if r.response.error),
            successful_mutators=sorted({r.probe.mutator for r in wins}),
            examples=wins[:max_examples],
        ))
    return findings


class Engine:
    def __init__(
        self,
        target: Target,
        attacks: list[Attack],
        mutators: list[str] | None = None,
        concurrency: int = 4,
        delay: float = 0.0,
        on_result: Callable[[Result], None] | None = None,
    ):
        self.target = target
        self.probes = build_probes(attacks, mutators)
        self.concurrency = max(1, concurrency)
        self.delay = delay
        self.on_result = on_result

    async def _run_probe(self, probe: Probe, sem: asyncio.Semaphore) -> Result:
        async with sem:
            response = await self.target.send(probe.prompt, probe.document)
            if self.delay:
                await asyncio.sleep(self.delay)
        verdict = judge(probe, response, self.target.canaries)
        result = Result(probe, response, verdict.success, verdict.detector, verdict.evidence)
        if self.on_result:
            self.on_result(result)
        return result

    async def run(self) -> ScanReport:
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        sem = asyncio.Semaphore(self.concurrency)
        results = await asyncio.gather(*(self._run_probe(p, sem) for p in self.probes))
        finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return ScanReport(
            target=self.target.label,
            started=started,
            finished=finished,
            results=list(results),
            findings=aggregate(list(results)),
        )
