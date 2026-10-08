from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .renderers import render_json, render_sarif, render_text
from .scanner import InputError, scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="workflowguard", description="Offline GitHub Actions workflow security checks.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("scan", help="scan workflow YAML files")
    command.add_argument("path", nargs="?", default=".", help="repository root, workflow directory, or one workflow file")
    command.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    command.add_argument("--output", help="write output to this file instead of stdout")
    command.add_argument("--fail-on", choices=("error", "warning", "never"), default="error")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = scan(args.path)
        rendered = {"text": render_text, "json": render_json, "sarif": render_sarif}[args.format](result)
        if args.output:
            Path(args.output).expanduser().write_text(rendered, encoding="utf-8", newline="\n")
        else:
            sys.stdout.write(rendered)
    except (InputError, OSError) as exc:
        print(f"workflowguard: {exc}", file=sys.stderr)
        return 2

    if args.fail_on == "warning" and result.findings:
        return 1
    if args.fail_on == "error" and any(item.severity.value == "error" for item in result.findings):
        return 1
    return 0
