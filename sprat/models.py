from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 0


@dataclass
class Finding:
    stage: str
    severity: str
    title: str
    endpoint: str = ""
    detail: str = ""
    operation: str = ""  # "GET /path" from the spec, when the finding maps to one


@dataclass
class StageResult:
    name: str
    status: str = "ok"  # ok | skipped | error | cancelled
    note: str = ""
    findings: list[Finding] = field(default_factory=list)
    duration: float = 0.0
