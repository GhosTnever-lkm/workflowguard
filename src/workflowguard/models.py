from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    path: str
    line: int
    title: str
    message: str
    remediation: str


@dataclass(frozen=True, slots=True)
class WorkflowDoc:
    data: object
    line_map: dict[tuple[object, ...], int]
    text: str
    path: str

    def line_of(self, *parts: object) -> int:
        """Return the nearest recorded YAML key line, defaulting to line one."""
        for size in range(len(parts), 0, -1):
            line = self.line_map.get(tuple(parts[:size]))
            if line is not None:
                return line
        return 1


@dataclass(frozen=True, slots=True)
class ScanResult:
    root: str
    files_scanned: int
    findings: tuple[Finding, ...]
