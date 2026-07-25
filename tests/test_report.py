from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from hacl_itdr.models import (
    InactiveAccountAlert,
    IntegrityAlert,
    PasswordSprayAlert,
    TimelineEvent,
)
from hacl_itdr.report import (
    ReportError,
    build_investigation_report,
    collect_evidence_artifacts,
    write_investigation_report,
)

NOW = datetime(2026, 7, 25, 18, 0, tzinfo=UTC)


def alerts() -> list[PasswordSprayAlert | InactiveAccountAlert | IntegrityAlert]:
    return [
        PasswordSprayAlert(
            alert_id="spray-1",
            generated_at_utc=NOW,
            detection_start_utc=NOW,
            detection_end_utc=NOW,
            source_ip="203.0.113.25",
            failed_attempts=5,
            distinct_accounts=5,
            targeted_accounts=("alice", "bob"),
            known_employee_accounts=("alice", "bob"),
            unknown_accounts=(),
            privileged_accounts=(),
            successful_logon_accounts=("alice",),
            locked_out_accounts=("bob",),
            severity="high",
            confidence="high",
        ),
        InactiveAccountAlert(
            alert_id="inactive-1",
            generated_at_utc=NOW,
            detected_at_utc=NOW,
            account="former.user",
            employee_id="EMP-9",
            department="Finance",
            directory_status="disabled",
            source_ip="198.51.100.42",
            host="APP01",
            workstation="WKSTN-42",
            logon_type=10,
            privileged=False,
            severity="high",
        ),
        IntegrityAlert(
            alert_id="integrity-1",
            generated_at_utc=NOW,
            detected_at_utc=NOW,
            asset_id="allow-list",
            protected_path="data/allow_list.txt",
            change_type="entries_added",
            baseline_sha256="a" * 64,
            observed_sha256="b" * 64,
            baseline_entry_count=2,
            observed_entry_count=3,
            added_entries=("203.0.113.20",),
            removed_entries=(),
            replacement_suspected=False,
            severity="high",
        ),
    ]


def timeline() -> list[TimelineEvent]:
    return [
        TimelineEvent(
            event_id="event-1",
            timestamp_utc=NOW,
            category="correlation",
            event_type="combined_finding",
            severity="critical",
            summary="Identity and integrity evidence correlated",
            source="test",
            related_alert_ids=("spray-1", "integrity-1"),
            details={"source_ip": "203.0.113.25"},
        )
    ]


def test_collect_evidence_artifacts_hashes_and_sorts(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("alpha", encoding="utf-8")
    second.write_text("beta", encoding="utf-8")

    artifacts = collect_evidence_artifacts({"zeta": second, "alpha": first})

    assert [artifact.label for artifact in artifacts] == ["alpha", "zeta"]
    assert artifacts[0].byte_length == 5
    assert len(artifacts[0].sha256) == 64


def test_collect_evidence_artifacts_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="unable to hash"):
        collect_evidence_artifacts({"missing": tmp_path / "missing.txt"})


def test_build_report_contains_findings_evidence_and_limitations(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "events.jsonl"
    evidence.write_text("{}\n", encoding="utf-8")
    artifacts = collect_evidence_artifacts({"events": evidence})

    report = build_investigation_report(
        alerts(), timeline(), artifacts, generated_at=NOW
    )

    assert "Alerts generated: 3" in report
    assert "Password-spray alerts: 1" in report
    assert "Inactive-account alerts: 1" in report
    assert "Integrity alerts: 1" in report
    assert "former.user" in report
    assert "T1110.003" in report
    assert "T1078" in report
    assert "T1685" in report
    assert artifacts[0].sha256 in report
    assert "Identity and integrity evidence correlated" in report
    assert "Alerts are investigative leads" in report


def test_build_report_handles_empty_inputs() -> None:
    report = build_investigation_report([], [], [], generated_at=NOW)

    assert "Alerts generated: 0" in report
    assert "No detector findings were generated" in report
    assert "No identities were identified" in report
    assert "No mapped findings" in report
    assert "No investigation events were generated" in report


def test_write_investigation_report_creates_parent(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "report.md"

    write_investigation_report(output, alerts(), timeline(), [])

    assert output.exists()
    assert output.read_text(encoding="utf-8").startswith(
        "# hACL ITDR Investigation Report"
    )
