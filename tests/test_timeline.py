from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from hacl_itdr.models import (
    AuthEvent,
    IntegrityAlert,
    IntegrityConfig,
    PasswordSprayAlert,
)
from hacl_itdr.timeline import (
    build_investigation_timeline,
    timeline_to_jsonl,
    timeline_to_markdown,
    write_timeline,
)

BASE = datetime(2026, 7, 25, 17, 0, tzinfo=UTC)


def spray_alert(*, success: bool = True) -> PasswordSprayAlert:
    return PasswordSprayAlert(
        alert_id="spray-1",
        generated_at_utc=BASE,
        detection_start_utc=BASE,
        detection_end_utc=BASE + timedelta(minutes=4),
        source_ip="203.0.113.25",
        failed_attempts=5,
        distinct_accounts=5,
        targeted_accounts=("alice", "bob", "carol", "dave", "erin"),
        known_employee_accounts=("alice", "bob", "carol", "dave", "erin"),
        unknown_accounts=(),
        privileged_accounts=("carol",),
        successful_logon_accounts=("carol",) if success else (),
        locked_out_accounts=("bob",),
        severity="critical" if success else "high",
        confidence="high",
    )


def integrity_alert(*, minute: int = 6) -> IntegrityAlert:
    return IntegrityAlert(
        alert_id="integrity-1",
        generated_at_utc=BASE + timedelta(minutes=minute),
        detected_at_utc=BASE + timedelta(minutes=minute),
        asset_id="hacl-primary",
        protected_path="data/allow_list.txt",
        change_type="entries_added",
        baseline_sha256="a" * 64,
        observed_sha256="b" * 64,
        baseline_entry_count=3,
        observed_entry_count=4,
        added_entries=("198.51.100.10",),
        removed_entries=(),
        replacement_suspected=False,
        severity="high",
    )


def auth_events() -> list[AuthEvent]:
    return [
        AuthEvent(
            timestamp_utc=BASE + timedelta(minutes=7),
            event_id=4624,
            source_ip="203.0.113.25",
            account="carol",
            host="DC01",
        ),
        AuthEvent(
            timestamp_utc=BASE + timedelta(minutes=8),
            event_id=4740,
            source_ip=None,
            account="bob",
            host="DC01",
        ),
    ]


def test_build_timeline_combines_detector_and_source_evidence() -> None:
    timeline = build_investigation_timeline(
        auth_events(),
        [spray_alert(), integrity_alert()],
        IntegrityConfig(correlation_window_minutes=60),
    )

    assert [event.event_type for event in timeline] == [
        "password_spray_threshold_crossed",
        "allow_list_entries_added",
        "integrity_change_near_password_spray",
        "successful_logon_after_spray",
        "account_lockout_after_spray",
    ]
    correlation = timeline[2]
    assert correlation.severity == "critical"
    assert correlation.related_alert_ids == ("integrity-1", "spray-1")


def test_timeline_does_not_correlate_outside_window() -> None:
    timeline = build_investigation_timeline(
        [],
        [spray_alert(success=False), integrity_alert(minute=120)],
        IntegrityConfig(correlation_window_minutes=30),
    )

    assert "integrity_change_near_password_spray" not in {
        event.event_type for event in timeline
    }


def test_timeline_is_deterministic_for_same_inputs() -> None:
    first = build_investigation_timeline(
        auth_events(), [spray_alert(), integrity_alert()], IntegrityConfig()
    )
    second = build_investigation_timeline(
        auth_events(), [spray_alert(), integrity_alert()], IntegrityConfig()
    )

    assert [event.event_id for event in first] == [
        event.event_id for event in second
    ]


def test_timeline_serialisers(tmp_path: Path) -> None:
    timeline = build_investigation_timeline(
        [], [spray_alert(success=False)], IntegrityConfig()
    )
    jsonl = timeline_to_jsonl(timeline)
    markdown = timeline_to_markdown(timeline)

    assert '"event_type": "password_spray_threshold_crossed"' in jsonl
    assert "| high | authentication |" in markdown

    json_path = tmp_path / "timeline.jsonl"
    markdown_path = tmp_path / "timeline.md"
    write_timeline(json_path, timeline)
    write_timeline(markdown_path, timeline)

    assert json_path.read_text(encoding="utf-8") == jsonl
    assert markdown_path.read_text(encoding="utf-8") == markdown


def test_empty_timeline_markdown_is_explicit() -> None:
    assert "No investigation events were generated" in timeline_to_markdown([])
