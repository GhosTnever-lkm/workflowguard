from pathlib import Path

import pytest

from workflowguard.loader import WorkflowLoadError, load_workflow


def test_github_on_key_stays_a_string(tmp_path: Path):
    file = tmp_path / "ci.yml"
    file.write_text("on:\n  pull_request:\njobs: {}\n", encoding="utf-8")
    doc = load_workflow(file, "ci.yml")
    assert "on" in doc.data
    assert doc.data["on"] == {"pull_request": None}


def test_unknown_github_tag_is_safe_and_accepted(tmp_path: Path):
    file = tmp_path / "ci.yml"
    file.write_text("on: push\njobs: {}\nconcurrency: !cancelled()\n", encoding="utf-8")
    doc = load_workflow(file, "ci.yml")
    assert doc.data["concurrency"] == ""


def test_duplicate_mapping_key_is_rejected(tmp_path: Path):
    file = tmp_path / "ci.yml"
    file.write_text("on: push\non: pull_request\n", encoding="utf-8")
    with pytest.raises(WorkflowLoadError, match="duplicate YAML key"):
        load_workflow(file, "ci.yml")


def test_malformed_yaml_is_rejected(tmp_path: Path):
    file = tmp_path / "ci.yml"
    file.write_text("jobs: [\n", encoding="utf-8")
    with pytest.raises(WorkflowLoadError, match="ci.yml"):
        load_workflow(file, "ci.yml")


def test_unsafe_python_constructor_is_not_executed(tmp_path: Path):
    file = tmp_path / "ci.yml"
    file.write_text("value: !!python/object/apply:os.system ['echo unsafe']\n", encoding="utf-8")
    with pytest.raises(WorkflowLoadError):
        load_workflow(file, "ci.yml")
