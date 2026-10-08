from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .models import Finding, ScanResult, Severity
from .rules import RULES


def _counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = Counter(item.severity.value for item in findings)
    return {name: counts.get(name, 0) for name in ("error", "warning")}


def render_json(result: ScanResult) -> str:
    payload = {
        "tool": "WorkflowGuard",
        "version": __version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
        "counts": _counts(result.findings),
        "findings": [
            {
                "rule_id": item.rule_id,
                "severity": item.severity.value,
                "path": item.path,
                "line": item.line,
                "title": item.title,
                "message": item.message,
                "remediation": item.remediation,
            }
            for item in result.findings
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def render_text(result: ScanResult) -> str:
    counts = _counts(result.findings)
    lines = [
        f"WorkflowGuard {__version__}: scanned {result.files_scanned} workflow file(s)",
        f"Findings: {counts['error']} error(s), {counts['warning']} warning(s)",
    ]
    for item in result.findings:
        lines.extend([
            f"{item.path}:{item.line}: {item.severity.value.upper()} {item.rule_id} — {item.title}",
            f"  {item.message}",
            f"  Fix: {item.remediation}",
        ])
    if not result.findings:
        lines.append("No findings.")
    return "\n".join(lines) + "\n"


def render_sarif(result: ScanResult) -> str:
    rule_metadata = [
        {
            "id": rule,
            "shortDescription": {"text": next((f.title for f in result.findings if f.rule_id == rule), rule)},
            "defaultConfiguration": {"level": "error" if rule in {"WFG002", "WFG003", "WFG007"} else "warning"},
        }
        for rule in RULES
    ]
    results = [
        {
            "ruleId": item.rule_id,
            "level": "error" if item.severity is Severity.ERROR else "warning",
            "message": {"text": f"{item.message} Remediation: {item.remediation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": item.path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": item.line},
                }
            }],
        }
        for item in result.findings
    ]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "WorkflowGuard", "version": __version__, "rules": rule_metadata}},
            "results": results,
            "originalUriBaseIds": {"%SRCROOT%": {"uri": Path(result.root).as_uri().rstrip("/") + "/"}},
        }],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
