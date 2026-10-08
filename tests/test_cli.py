import json
from pathlib import Path

from workflowguard.cli import main


def make_repo(tmp_path: Path, workflow: str) -> Path:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    (directory / "ci.yml").write_text(workflow, encoding="utf-8")
    return tmp_path


def test_error_gate_exits_one_only_for_error(tmp_path: Path, capsys):
    repo = make_repo(tmp_path, "on: push\njobs: {}\n")
    assert main(["scan", str(repo), "--fail-on", "error"]) == 0
    assert "WFG001" in capsys.readouterr().out


def test_warning_gate_exits_one_for_warning(tmp_path: Path, capsys):
    repo = make_repo(tmp_path, "on: push\njobs: {}\n")
    assert main(["scan", str(repo), "--fail-on", "warning"]) == 1
    capsys.readouterr()


def test_never_gate_exits_zero_with_error_finding(tmp_path: Path, capsys):
    repo = make_repo(tmp_path, "on: push\npermissions: write-all\njobs: {}\n")
    assert main(["scan", str(repo), "--fail-on", "never"]) == 0
    capsys.readouterr()


def test_json_file_output(tmp_path: Path, capsys):
    repo = make_repo(tmp_path, "on: push\njobs: {}\n")
    output = tmp_path / "report.json"
    assert main(["scan", str(repo), "--format", "json", "--output", str(output)]) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["files_scanned"] == 1
    assert payload["findings"][0]["rule_id"] == "WFG001"
    assert capsys.readouterr().out == ""


def test_missing_path_returns_two(tmp_path: Path, capsys):
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_unicode_and_spaces_in_scan_path(tmp_path: Path, capsys):
    repo = tmp_path / "мод с пробелами"
    repo.mkdir()
    make_repo(repo, "on: push\npermissions: read-all\njobs: {}\n")
    assert main(["scan", str(repo)]) == 0
    assert "scanned 1" in capsys.readouterr().out
