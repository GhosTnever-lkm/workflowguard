def test_nested_finding_line_number_is_exact(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - name: Pin checkout
        uses: actions/checkout@v4
        with:
          persist-credentials: true
"""
    finding = next(item for item in findings_for(text) if item.rule_id == "WFG005")
    assert finding.line == 7


def test_multiline_run_reports_run_key_line(findings_for):
    text = """on: issues
permissions: read-all
jobs:
  build:
    steps:
      - run: |
          echo ${{ github.event.issue.body }}
"""
    finding = next(item for item in findings_for(text) if item.rule_id == "WFG007")
    assert finding.line == 6


def test_complex_yaml_key_does_not_crash_scanner(tmp_path):
    import pytest
    from workflowguard.scanner import scan
    from workflowguard.scanner import InputError

    file = tmp_path / '.github' / 'workflows' / 'complex.yml'
    file.parent.mkdir(parents=True)
    file.write_text('on: push\npermissions: read-all\n? [a, b]\n: value\njobs: {}\n', encoding='utf-8')
    with pytest.raises(InputError, match="found unhashable key"):
        scan(tmp_path)
