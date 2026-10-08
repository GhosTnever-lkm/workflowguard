from __future__ import annotations

import re
from collections.abc import Iterator

from .models import Finding, ScanResult, Severity, WorkflowDoc

_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.event\.(?:"
    r"pull_request\.(?:title|body|head\.(?:ref|label|repo\.(?:full_name|description|homepage|name)))|"
    r"issue\.(?:title|body)|comment\.(?:body|title)|review\.(?:body|title)|"
    r"review_comment\.(?:body|path)|discussion\.(?:title|body)|"
    r"discussion_comment\.(?:body|title)|"
    r"workflow_run\.(?:head_commit\.message|head_repository\.(?:description|homepage|name))|"
    r"commits\[\d+\]\.message|head_commit\.message"
    r")[^}]*\}\}"
)
_PR_HEAD = re.compile(
    r"\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|github\.head_ref)\s*\}\}"
)
_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_SECRET = re.compile(r"(?<![A-Za-z0-9_])secrets\.[A-Za-z_][A-Za-z0-9_]*")
RULES = ("WFG001", "WFG002", "WFG003", "WFG004", "WFG005", "WFG006", "WFG007", "WFG008")


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _jobs(doc: WorkflowDoc) -> Iterator[tuple[str, dict, tuple[object, ...]]]:
    for name, job in _mapping(_mapping(doc.data).get("jobs")).items():
        if isinstance(job, dict):
            yield str(name), job, ("jobs", name)


def _steps(doc: WorkflowDoc) -> Iterator[tuple[str, dict, tuple[object, ...]]]:
    for job_name, job, job_path in _jobs(doc):
        steps = job.get("steps")
        if isinstance(steps, list):
            for index, step in enumerate(steps):
                if isinstance(step, dict):
                    yield job_name, step, job_path + ("steps", index)


def _checkout(step: dict) -> bool:
    uses = step.get("uses")
    return isinstance(uses, str) and uses.lower().startswith("actions/checkout@")


def _events(data: dict) -> set[str]:
    value = data.get("on", {})
    if isinstance(value, dict):
        return {str(event) for event in value}
    if isinstance(value, list):
        return {str(event) for event in value}
    if isinstance(value, str):
        return {value}
    return set()


def _finding(doc: WorkflowDoc, rule: str, severity: Severity, path: tuple[object, ...], title: str, message: str, remediation: str) -> Finding:
    return Finding(rule, severity, doc.path, doc.line_of(*path), title, message, remediation)


def scan_workflow(doc: WorkflowDoc) -> list[Finding]:
    data = _mapping(doc.data)
    found: list[Finding] = []

    if "permissions" not in data:
        found.append(_finding(
            doc, "WFG001", Severity.WARNING, ("permissions",),
            "Missing top-level permissions",
            "The workflow inherits the repository default GITHUB_TOKEN permissions.",
            "Set top-level permissions to read-all or an explicit minimal map, then grant additional scopes only where needed.",
        ))

    if data.get("permissions") == "write-all":
        found.append(_finding(
            doc, "WFG002", Severity.ERROR, ("permissions",),
            "permissions: write-all", "The workflow grants write access to every GITHUB_TOKEN scope.",
            "Replace write-all with read-all or the smallest explicit set of permissions.",
        ))
    for job_name, job, job_path in _jobs(doc):
        if job.get("permissions") == "write-all":
            found.append(_finding(
                doc, "WFG002", Severity.ERROR, job_path + ("permissions",),
                "permissions: write-all", f"Job {job_name!r} grants write access to every GITHUB_TOKEN scope.",
                "Grant only the token scopes this job needs.",
            ))

    if "pull_request_target" in _events(data):
        for _job_name, step, step_path in _steps(doc):
            if _checkout(step):
                with_values = _mapping(step.get("with"))
                for key in ("ref", "repository"):
                    value = with_values.get(key)
                    if isinstance(value, str) and _PR_HEAD.search(value):
                        found.append(_finding(
                            doc, "WFG003", Severity.ERROR, step_path + ("with", key),
                            "pull_request_target checks out untrusted PR data",
                            f"Checkout input {key!r} evaluates to pull request-controlled branch or repository data.",
                            "Do not check out an untrusted PR head in pull_request_target. Use pull_request, or split privileged work into a separately secured workflow.",
                        ))
            run = step.get("run")
            if isinstance(run, str) and any(
                _UNTRUSTED.search("${{ " + expr.group(1) + " }}") for expr in _EXPRESSION.finditer(run)
            ):
                found.append(_finding(
                    doc, "WFG003", Severity.ERROR, step_path + ("run",),
                    "pull_request_target executes untrusted event text",
                    "The shell command interpolates attacker-controlled event data while the workflow has the target event's elevated context.",
                    "Do not interpolate PR-controlled data into shell source in pull_request_target. Move untrusted processing to an unprivileged pull_request workflow and keep privileged work separate.",
                ))

    for _job_name, step, step_path in _steps(doc):
        uses = step.get("uses")
        if isinstance(uses, str) and not uses.startswith("./"):
            if uses.startswith("docker://"):
                if not re.search(r"@sha256:[0-9a-fA-F]{64}$", uses):
                    found.append(_finding(
                        doc, "WFG004", Severity.WARNING, step_path + ("uses",),
                        "Container action is not pinned to an image digest",
                        f"The container reference {uses!r} can resolve to a different image later.",
                        "Pin the container image to a verified sha256 digest.",
                    ))
            elif "@" in uses:
                ref = uses.rsplit("@", 1)[1]
                if not _SHA.fullmatch(ref):
                    found.append(_finding(
                        doc, "WFG004", Severity.WARNING, step_path + ("uses",),
                        "Action reference is not pinned to a commit",
                        f"The action reference {uses!r} can move without a workflow change.",
                        "Pin the action to a verified full 40-character commit SHA and keep the original version in a comment.",
                    ))

            if _checkout(step):
                with_values = _mapping(step.get("with"))
                persist = with_values.get("persist-credentials")
                if persist is not False and not (isinstance(persist, str) and persist.lower() == "false"):
                    found.append(_finding(
                        doc, "WFG005", Severity.WARNING, step_path + ("uses",),
                        "Checkout keeps credentials in local Git config",
                        "actions/checkout persists the token in the checkout's Git config unless disabled.",
                        "Set with.persist-credentials to false unless later steps specifically require the token.",
                    ))

        run = step.get("run")
        if isinstance(run, str) and any(_SECRET.search(expr.group(1)) for expr in _EXPRESSION.finditer(run)):
            found.append(_finding(
                doc, "WFG006", Severity.WARNING, step_path + ("run",),
                "Secret is interpolated directly into a shell command",
                "A secrets.* expression is expanded before the shell runs and may affect logs or command parsing.",
                "Pass the secret through the step's env block and quote the environment variable in the script.",
            ))
        if isinstance(run, str):
            match = _UNTRUSTED.search(run)
            if match:
                found.append(_finding(
                    doc, "WFG007", Severity.ERROR, step_path + ("run",),
                    "Untrusted event value is interpolated in a shell command",
                    f"The expression {match.group(0)!r} can contain attacker-controlled pull request or issue text.",
                    "Pass the value through an environment variable and use it as quoted data; do not splice it into shell source.",
                ))

    for job_name, job, job_path in _jobs(doc):
        uses = job.get("uses")
        if not isinstance(uses, str) or ".github/workflows/" not in uses or "@" not in uses:
            continue
        ref = uses.rsplit("@", 1)[1]
        if not _SHA.fullmatch(ref):
            found.append(_finding(
                doc, "WFG008", Severity.WARNING, job_path + ("uses",),
                "Reusable workflow reference is not pinned to a commit",
                f"Reusable workflow {uses!r} follows a mutable branch or tag.",
                "Pin the reusable workflow to a verified full 40-character commit SHA.",
            ))

    return sorted(found, key=lambda item: (item.path, item.line, item.rule_id, item.message))
