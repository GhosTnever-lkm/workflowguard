def ids(findings):
    return [finding.rule_id for finding in findings]


def test_wfg001_missing_top_level_permissions(findings_for):
    assert "WFG001" in ids(findings_for("on: push\njobs: {}\n"))


def test_wfg001_accepts_explicit_permissions(findings_for):
    assert "WFG001" not in ids(findings_for("on: push\npermissions:\n  contents: read\njobs: {}\n"))


def test_wfg002_detects_top_level_and_job_write_all(findings_for):
    text = "on: push\npermissions: write-all\njobs:\n  build:\n    permissions: write-all\n"
    assert ids(findings_for(text)).count("WFG002") == 2


def test_wfg002_ignores_minimal_permissions(findings_for):
    text = "on: push\npermissions:\n  contents: read\njobs: {}\n"
    assert "WFG002" not in ids(findings_for(text))


def test_wfg003_detects_pull_request_head_checkout(findings_for):
    text = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    assert "WFG003" in ids(findings_for(text))


def test_wfg003_ignores_regular_checkout(findings_for):
    text = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
"""
    assert "WFG003" not in ids(findings_for(text))


def test_wfg003_flags_untrusted_shell_input_under_pull_request_target(findings_for):
    text = """on: pull_request_target
permissions: read-all
jobs:
  build:
    steps:
      - run: echo ${{ github.event.pull_request.title }}
"""
    assert "WFG003" in ids(findings_for(text))


def test_wfg004_flags_mutable_action_tag_and_ignores_local(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - uses: owner/action@v2.1.0
      - uses: ./local-action
"""
    assert ids(findings_for(text)).count("WFG004") == 1


def test_wfg004_accepts_full_commit_sha(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - uses: owner/action@0123456789abcdef0123456789abcdef01234567
"""
    assert "WFG004" not in ids(findings_for(text))


def test_wfg004_requires_digest_for_container_action(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - uses: docker://ghcr.io/owner/action:latest
"""
    assert "WFG004" in ids(findings_for(text))


def test_wfg004_accepts_container_digest(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - uses: docker://ghcr.io/owner/action@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
"""
    assert "WFG004" not in ids(findings_for(text))


def test_wfg005_requires_explicit_false(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
"""
    assert "WFG005" not in ids(findings_for(text))


def test_wfg005_flags_checkout_default(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
"""
    assert "WFG005" in ids(findings_for(text))


def test_wfg006_direct_secret_run_only(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - run: deploy --token ${{ secrets.DEPLOY_TOKEN }}
"""
    assert "WFG006" in ids(findings_for(text))


def test_wfg006_secret_in_env_is_not_reported(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - run: deploy --token "$TOKEN"
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
"""
    assert "WFG006" not in ids(findings_for(text))


def test_wfg006_detects_secret_inside_compound_expression(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - run: deploy --token ${{ secrets.DEPLOY_TOKEN || '' }}
"""
    assert "WFG006" in ids(findings_for(text))


def test_wfg007_flags_known_untrusted_issue_text(findings_for):
    text = """on: issues
permissions: read-all
jobs:
  build:
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""
    assert "WFG007" in ids(findings_for(text))


def test_wfg007_does_not_flag_other_event_values(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - run: echo "${{ github.event_name }}"
"""
    assert "WFG007" not in ids(findings_for(text))


def test_wfg007_detects_pr_repo_description(findings_for):
    text = """on: pull_request
permissions: read-all
jobs:
  build:
    steps:
      - run: echo "${{ github.event.pull_request.head.repo.description }}"
"""
    assert "WFG007" in ids(findings_for(text))


def test_wfg007_ignores_expression_that_only_mentions_untrusted_field_as_text(findings_for):
    text = """on: push
permissions: read-all
jobs:
  build:
    steps:
      - run: echo '${{ github.event_name }}'
"""
    assert "WFG007" not in ids(findings_for(text))


def test_wfg008_flags_reusable_workflow_ref(findings_for):
    text = """on: push
permissions: read-all
jobs:
  call:
    uses: owner/repo/.github/workflows/build.yml@main
"""
    assert "WFG008" in ids(findings_for(text))


def test_wfg008_accepts_reusable_workflow_sha(findings_for):
    text = """on: push
permissions: read-all
jobs:
  call:
    uses: owner/repo/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567
"""
    assert "WFG008" not in ids(findings_for(text))
