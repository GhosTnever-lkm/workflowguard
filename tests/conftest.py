from pathlib import Path

import pytest

from workflowguard.loader import load_workflow
from workflowguard.rules import scan_workflow


@pytest.fixture
def findings_for(tmp_path: Path):
    def scan_text(text: str, path: str = ".github/workflows/test.yml"):
        file = tmp_path / "workflow.yml"
        file.write_text(text, encoding="utf-8")
        doc = load_workflow(file, path)
        return scan_workflow(doc)
    return scan_text
