import json
from pathlib import Path

from workflowguard.loader import load_workflow
from workflowguard.models import ScanResult
from workflowguard.renderers import render_json, render_sarif, render_text
from workflowguard.rules import scan_workflow


def sample_result(tmp_path: Path):
    path = tmp_path / "ci.yml"
    path.write_text("on: push\npermissions: write-all\njobs: {}\n", encoding="utf-8")
    findings = scan_workflow(load_workflow(path, ".github/workflows/ci.yml"))
    return ScanResult(str(tmp_path.resolve()), 1, tuple(findings))


def test_json_contains_stable_findings_shape(tmp_path: Path):
    value = json.loads(render_json(sample_result(tmp_path)))
    assert value["tool"] == "WorkflowGuard"
    assert value["findings"][0]["rule_id"] == "WFG002"
    assert value["findings"][0]["path"] == ".github/workflows/ci.yml"


def test_sarif_has_version_rule_and_relative_location(tmp_path: Path):
    value = json.loads(render_sarif(sample_result(tmp_path)))
    run = value["runs"][0]
    assert value["version"] == "2.1.0"
    assert run["results"][0]["ruleId"] == "WFG002"
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == ".github/workflows/ci.yml"
    assert location["region"]["startLine"] == 2
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].endswith("/")


def test_text_output_includes_fix(tmp_path: Path):
    text = render_text(sample_result(tmp_path))
    assert "ERROR WFG002" in text
    assert "Fix:" in text
