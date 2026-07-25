from __future__ import annotations

import json
from pathlib import Path

import pytest

from hacl_itdr import cli
from hacl_itdr.report import ReportError

ROOT = Path(__file__).resolve().parents[1]


def test_cli_processes_windows_evidence_and_writes_report(tmp_path: Path) -> None:
    alerts_output = tmp_path / "alerts.jsonl"
    timeline_output = tmp_path / "timeline.jsonl"
    report_output = tmp_path / "report.md"

    exit_code = cli.main(
        [
            "--events",
            str(ROOT / "data" / "windows_security_events.jsonl"),
            "--events-format",
            "windows-security",
            "--employees",
            str(ROOT / "data" / "employees.csv"),
            "--config",
            str(ROOT / "config" / "detector.toml"),
            "--allow-list",
            str(ROOT / "data" / "tampered_allow_list.txt"),
            "--baseline",
            str(ROOT / "data" / "allow_list_baseline.json"),
            "--output",
            str(alerts_output),
            "--timeline-output",
            str(timeline_output),
            "--report-output",
            str(report_output),
        ]
    )

    assert exit_code == 0
    alert_payloads = [
        json.loads(line)
        for line in alerts_output.read_text(encoding="utf-8").splitlines()
    ]
    alert_types = {payload["alert_type"] for payload in alert_payloads}
    assert alert_types == {
        "password_spray",
        "inactive_account_logon",
        "allow_list_integrity",
    }
    timeline_text = timeline_output.read_text(encoding="utf-8")
    assert "windows_file_access_observed" in timeline_text
    assert "inactive_account_successful_logon" in timeline_text
    report_text = report_output.read_text(encoding="utf-8")
    assert "# hACL ITDR Investigation Report" in report_text
    assert "Evidence integrity" in report_text
    assert "f.balogun" in report_text


def test_cli_reports_evidence_hashing_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_collect(paths: object) -> tuple[()]:
        raise ReportError("forced report failure")

    monkeypatch.setattr(cli, "collect_evidence_artifacts", fail_collect)

    exit_code = cli.main(
        [
            "--events",
            str(ROOT / "data" / "synthetic_auth_events.jsonl"),
            "--employees",
            str(ROOT / "data" / "employees.csv"),
            "--config",
            str(ROOT / "config" / "detector.toml"),
            "--report-output",
            str(tmp_path / "report.md"),
        ]
    )

    assert exit_code == 2
    assert "forced report failure" in capsys.readouterr().err
