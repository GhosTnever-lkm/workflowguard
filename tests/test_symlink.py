from pathlib import Path

import pytest

from workflowguard.scanner import InputError, scan


def test_workflow_file_symlink_outside_root_is_rejected(tmp_path: Path):
    repo = tmp_path / "repo"
    workflow_dir = repo / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    outside = tmp_path / "outside.yml"
    outside.write_text("on: push\n", encoding="utf-8")
    link = workflow_dir / "external.yml"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(InputError, match="escapes scan root"):
        scan(repo)


def test_workflow_dir_symlink_outside_root_is_rejected(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / ".github").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (repo / ".github" / "workflows").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(InputError, match="workflow directory not found|escapes"):
        scan(repo)
