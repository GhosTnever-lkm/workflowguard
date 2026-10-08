from pathlib import Path

import pytest

from workflowguard.scanner import InputError, scan


def test_scan_stops_with_clear_error_for_malformed_workflow(tmp_path: Path):
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    (directory / "broken.yml").write_text("jobs: [\n", encoding="utf-8")
    with pytest.raises(InputError, match="broken.yml"):
        scan(tmp_path)


def test_empty_workflow_directory_is_valid(tmp_path: Path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    result = scan(tmp_path)
    assert result.files_scanned == 0
    assert result.findings == ()
