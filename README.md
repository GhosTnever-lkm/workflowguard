# WorkflowGuard

**Offline security checks for GitHub Actions workflows.** WorkflowGuard reads workflow YAML, reports risky permissions and common injection patterns, and exports text, JSON, or SARIF. It never runs workflow commands or contacts the network.

WorkflowGuard checks every workflow in a repository. [DiffShield](https://github.com/GhosTnever-lkm/diffshield-action) focuses on changes in a pull request; the two tools cover different review stages.

## Install

Python 3.11 or newer is required.

Download the wheel from the [latest GitHub release](https://github.com/GhosTnever-lkm/workflowguard/releases/latest) and install the downloaded file:

```console
python -m pip install workflowguard-1.0.1-py3-none-any.whl
```

The release also includes a source bundle. Extract it and follow the checkout instructions below to install from source.

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

## GitHub Actions example (CLI)

WorkflowGuard is a CLI, not a published GitHub Action. Install the CLI in a job and run it against the checked-out repository:

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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: '3.12'
      - run: python -m pip install https://github.com/GhosTnever-lkm/workflowguard/releases/download/v1.0.1/workflowguard-1.0.1-py3-none-any.whl
      - run: workflowguard scan . --format sarif --output workflowguard.sarif --fail-on error
```

The example installs the versioned wheel from GitHub Releases. The command writes a SARIF report; add an artifact upload step if you need to download that report from the run.

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

<details>
<summary>Public wallet addresses</summary>

Send only assets on the matching network.

| Network | Address |
|:--|:--|
| Bitcoin | `bc1qn75pj4n7gyl2k5kf2f97elvyenz52q6nn2g30u` |
| TRON | `TCBSy38X57hA6w2onJcxom24x1febc1mP1` |
| BNB Smart Chain | `0xD431a917961E0b086B96D9F72b5C8fF19b19068a` |

</details>

## Support / Pro Version

WorkflowGuard CLI is free and MIT-licensed. The optional [WorkflowGuard Pro Kit on Boosty](https://boosty.to/azizazimov/posts/5c87f36c-8306-462e-85a8-a4facd470adb) is a separate 50 ₽ pack of starter workflow templates and release checklists; it does not unlock hidden CLI features.

You can also support development through [Buy Me a Coffee](https://buymeacoffee.com/azizazimov8) or [Boosty](https://boosty.to/azizazimov).
