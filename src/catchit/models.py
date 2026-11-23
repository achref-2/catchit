from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class RepoFile:
    path: str
    content: str


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: Severity
    path: str
    line: int | None
    message: str


@dataclass
class Report:
    repo: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        weights = {Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 35}
        return min(100, sum(weights[f.severity] for f in self.findings))