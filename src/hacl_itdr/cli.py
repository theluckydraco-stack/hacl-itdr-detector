"""Command-line interface for the hACL ITDR detector."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .alerts import alerts_to_jsonl, write_alerts
from .inactive_account import detect_inactive_account_logons
from .integrity import IntegrityError, inspect_allow_list, load_baseline
from .models import FileAccessEvent, SecurityAlert
from .parsers import (
    ParseError,
    load_auth_events,
    load_config,
    load_employees,
    load_integrity_config,
)
from .password_spray import detect_password_sprays
from .report import (
    ReportError,
    collect_evidence_artifacts,
    write_investigation_report,
)
from .timeline import build_investigation_timeline, write_timeline
from .windows_schema import load_windows_security_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hacl-itdr",
        description=(
            "Detect identity threats and protected allow-list changes in "
            "synthetic evidence."
        ),
    )
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument(
        "--events-format",
        choices=("normalised", "windows-security"),
        default="normalised",
    )
    parser.add_argument("--employees", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-list", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--timeline-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the detector and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.allow_list is None) != (args.baseline is None):
        print(
            "error: --allow-list and --baseline must be supplied together",
            file=sys.stderr,
        )
        return 2

    try:
        file_access_events: tuple[FileAccessEvent, ...] = ()
        if args.events_format == "windows-security":
            evidence = load_windows_security_events(args.events)
            events = list(evidence.authentication_events)
            file_access_events = evidence.file_access_events
        else:
            events = load_auth_events(args.events)

        employees = load_employees(args.employees)
        password_config = load_config(args.config)
        integrity_config = load_integrity_config(args.config)
        alerts: list[SecurityAlert] = []
        alerts.extend(detect_password_sprays(events, employees, password_config))
        alerts.extend(detect_inactive_account_logons(events, employees))
        if args.allow_list is not None and args.baseline is not None:
            baseline = load_baseline(args.baseline)
            integrity_alert = inspect_allow_list(args.allow_list, baseline)
            if integrity_alert is not None:
                alerts.append(integrity_alert)
    except (ParseError, IntegrityError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        write_alerts(args.output, alerts)
    else:
        sys.stdout.write(alerts_to_jsonl(alerts))

    timeline = build_investigation_timeline(
        events,
        alerts,
        integrity_config,
        file_access_events,
    )
    if args.timeline_output:
        write_timeline(args.timeline_output, timeline)

    if args.report_output:
        evidence_paths = {
            "authentication_events": args.events,
            "employee_directory": args.employees,
            "detector_configuration": args.config,
        }
        if args.allow_list is not None and args.baseline is not None:
            evidence_paths["observed_allow_list"] = args.allow_list
            evidence_paths["trusted_baseline"] = args.baseline
        try:
            artifacts = collect_evidence_artifacts(evidence_paths)
            write_investigation_report(
                args.report_output,
                alerts,
                timeline,
                artifacts,
            )
        except ReportError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    return 0
