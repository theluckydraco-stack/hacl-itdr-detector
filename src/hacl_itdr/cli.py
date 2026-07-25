"""Command-line interface for the hACL ITDR detector."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .alerts import alerts_to_jsonl, write_alerts
from .parsers import ParseError, load_auth_events, load_config, load_employees
from .password_spray import detect_password_sprays


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hacl-itdr",
        description="Detect password-spray activity in synthetic authentication data.",
    )
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--employees", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the detector and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        events = load_auth_events(args.events)
        employees = load_employees(args.employees)
        config = load_config(args.config)
        alerts = detect_password_sprays(events, employees, config)
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        write_alerts(args.output, alerts)
    else:
        sys.stdout.write(alerts_to_jsonl(alerts))
    return 0
