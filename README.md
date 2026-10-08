# WorkflowGuard

**Offline security checks for GitHub Actions workflows.** WorkflowGuard reads workflow YAML, reports risky permissions and common injection patterns, and exports text, JSON, or SARIF. It never runs workflow commands or contacts the network.

WorkflowGuard checks every workflow in a repository. [DiffShield](https://github.com/GhosTnever-lkm/diffshield-action) focuses on changes in a pull request; the two tools cover different review stages.

## Install

Python 3.11 or newer is required.

Download the current wheel from the repository and install the downloaded file:

```console
python -m pip install workflowguard-1.0.0-py3-none-any.whl
```

Or download [the source bundle](https://github.com/GhosTnever-lkm/workflowguard/blob/main/WorkflowGuard-Source-v1.0.0.zip), extract it, and run the checkout instructions below.

When a release is tagged, use its release assets for stable, versioned downloads.

To install from PyPI after the package is published there:

```console
python -m pip install workflowguard
```

To install from a checkout:

```console
python -m pip install .
```

## Quick start

Run from a repository root containing `.github/workflows/`:

```console
workflowguard scan .
workflowguard scan . --format json --output workflowguard.json
workflowguard scan . --format sarif --output workflowguard.sarif --fail-on warning
```

You can also pass the workflow directory or a single `.yml`/`.yaml` file:

```console
workflowguard scan .github/workflows
workflowguard scan ".github/workflows/build and release.yml"
```

`--fail-on error` (default) exits 1 for error findings. `warning` exits 1 for any finding. `never` always exits 0 after a successful scan. Input, parse, or output errors exit 2. Reports are still written when findings block the command.

## Checks

| Rule | Default level | What it flags |
|:--|:--|:--|
| WFG001 | warning | No explicit workflow-level `permissions` block |
| WFG002 | error | `permissions: write-all` at workflow or job level |
| WFG003 | error | `pull_request_target` checks out PR-controlled data or interpolates known untrusted event text into a shell command |
| WFG004 | warning | A step action or container image is not pinned to a full commit SHA or image digest |
| WFG005 | warning | `actions/checkout` keeps credentials in local Git config |
| WFG006 | warning | A `secrets.*` expression inside any `${{ ... }}` block is interpolated directly inside `run` |
| WFG007 | error | Known attacker-controlled event text is interpolated inside `run` |
| WFG008 | warning | A reusable workflow is referenced through a mutable ref |

Action tags such as `@v4` are convenient but can move. WorkflowGuard recommends a verified full commit SHA; keep a version comment beside it for readability. The scanner is intentionally conservative and does not claim to prove a workflow safe.

## GitHub Actions example

```yaml
name: Workflow security
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<verified-40-character-commit-sha> # v4
        with:
          persist-credentials: false
      - uses: GhosTnever-lkm/workflowguard-action@<verified-40-character-commit-sha>
        with:
          path: .
          fail-on: error
```

WorkflowGuard currently ships as a local CLI. The snippet shows the intended setup shape; the hosted Action reference is not published yet.

## Output and privacy

Findings include a rule ID, level, relative POSIX path, line, explanation, and a suggested fix. JSON and SARIF reports contain findings only. Workflow source, environment values, and secret values are never copied into a report. SARIF uses the scan root as its source base so the paths remain relative.

The tool reads files under the chosen scan root. It rejects symlinks that point outside that root and does not follow symlinked directories. The only write performed by the program is the file explicitly named with `--output`.

## Limits

- This is static analysis, not a GitHub workflow interpreter. It can miss dynamically generated commands and project-specific trust boundaries.
- YAML is parsed with a `SafeLoader`-derived loader. GitHub's `on` key stays a string (rather than YAML 1.1's boolean), and unknown GitHub tags such as `!cancelled()` are retained as their underlying value without custom object constructors.
- WFG007 checks a focused list of well-known attacker-controlled event fields. It does not treat every `github.event.*` value as untrusted text.
- WFG003 catches recognizable expressions that check out PR-controlled refs/repositories or interpolate known untrusted event fields into shell commands in `pull_request_target`; it does not reason about all indirect checkout or artifact flows.
- YAML aliases resolve to their anchor node, so a finding that comes from an aliased value may point to the anchor's line rather than the alias use.
- WFG004 treats every non-SHA action tag as mutable and requires a digest for Docker actions. Review the upstream source and pin the exact revision you intend to trust.
- The scanner does not inspect composite action internals, remote reusable workflow contents, runner images, or dependencies downloaded by workflow steps.

## Development

```console
python -m pip install -e ".[dev]"
pytest -q
```

## License

MIT. See [LICENSE](LICENSE).
