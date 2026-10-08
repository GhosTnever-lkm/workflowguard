from __future__ import annotations

import os
from pathlib import Path

from .loader import WorkflowLoadError, load_workflow
from .models import ScanResult
from .rules import scan_workflow


class InputError(ValueError):
    """The requested scan root or one of its workflows is invalid."""


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _layout(selected: Path) -> tuple[Path, Path, Path | None]:
    if selected.is_file():
        raw_root = selected.parent
        if raw_root.name == "workflows" and raw_root.parent.name == ".github":
            root = raw_root.parent.parent.resolve()
            return root, raw_root.resolve(), selected
        root = raw_root.resolve()
        return root, raw_root.resolve(), selected
    if not selected.is_dir():
        raise InputError(f"scan path does not exist: {selected}")
    resolved = selected.resolve()
    if resolved.name == "workflows" and resolved.parent.name == ".github":
        return resolved.parent.parent.resolve(), resolved, None
    return resolved, resolved / ".github" / "workflows", None


def _workflow_files(root: Path, workflow_dir: Path, explicit_file: Path | None) -> list[Path]:
    if explicit_file is not None:
        resolved = explicit_file.resolve()
        if not _within(resolved, root):
            raise InputError(f"workflow symlink escapes scan root: {explicit_file}")
        if explicit_file.suffix.lower() not in {".yml", ".yaml"}:
            raise InputError("a directly selected file must end in .yml or .yaml")
        if not explicit_file.is_file():
            raise InputError(f"workflow file does not exist: {explicit_file}")
        return [explicit_file]
    if not workflow_dir.is_dir():
        raise InputError(f"workflow directory not found: {workflow_dir}")
    resolved_workflow_dir = workflow_dir.resolve()
    if not _within(resolved_workflow_dir, root):
        raise InputError(f"workflow directory symlink escapes scan root: {workflow_dir}")

    candidates: list[Path] = []
    for current, directories, filenames in os.walk(workflow_dir, followlinks=False):
        current_path = Path(current)
        safe_directories: list[str] = []
        for name in directories:
            entry = current_path / name
            resolved = entry.resolve()
            if not _within(resolved, root):
                raise InputError(f"workflow directory symlink escapes scan root: {entry}")
            if not entry.is_symlink():
                safe_directories.append(name)
        directories[:] = safe_directories
        for name in filenames:
            entry = current_path / name
            if entry.suffix.lower() not in {".yml", ".yaml"}:
                continue
            resolved = entry.resolve()
            if not _within(resolved, root):
                raise InputError(f"workflow symlink escapes scan root: {entry}")
            if not entry.is_file():
                raise InputError(f"workflow file is not a regular file: {entry}")
            candidates.append(entry)
    return sorted(candidates, key=lambda path: path.as_posix().casefold())


def scan(path: str | Path = ".") -> ScanResult:
    selected = Path(path).expanduser()
    if not selected.exists():
        raise InputError(f"scan path does not exist: {selected}")
    root, workflow_dir, explicit = _layout(selected)
    files = _workflow_files(root, workflow_dir, explicit)
    findings = []
    for file_path in files:
        relative = file_path.resolve().relative_to(root).as_posix()
        try:
            doc = load_workflow(file_path, relative)
        except WorkflowLoadError as exc:
            raise InputError(str(exc)) from exc
        findings.extend(scan_workflow(doc))
    findings.sort(key=lambda item: (item.path.casefold(), item.line, item.rule_id, item.message))
    return ScanResult(str(root), len(files), tuple(findings))
