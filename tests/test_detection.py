from __future__ import annotations

from datetime import UTC, datetime, timedelta

from hacl_itdr.identity import correlate_identities
from hacl_itdr.models import AuthEvent, Employee, PasswordSprayConfig
from hacl_itdr.password_spray import detect_password_sprays

BASE = datetime(2026, 7, 25, 15, 0, tzinfo=UTC)


def event(
    minute: int,
    event_id: int,
    account: str,
    source_ip: str | None = "203.0.113.25",
) -> AuthEvent:
    return AuthEvent(
        timestamp_utc=BASE + timedelta(minutes=minute),
        event_id=event_id,
        source_ip=source_ip,
        account=account.casefold(),
        host="DC01",
        logon_type=3 if event_id in {4624, 4625} else None,
    )


def employees() -> dict[str, Employee]:
    return {
        "alice": Employee("alice", "EMP-1", "Security", "active", False),
        "bob": Employee("bob", "EMP-2", "Finance", "active", False),
        "carol": Employee("carol", "EMP-3", "IT", "active", True),
        "dave": Employee("dave", "EMP-4", "HR", "active", False),
        "erin": Employee("erin", "EMP-5", "Ops", "active", False),
    }


def threshold_events() -> list[AuthEvent]:
    return [
        event(0, 4625, "alice"),
        event(1, 4625, "bob"),
        event(2, 4625, "carol"),
        event(3, 4625, "dave"),
        event(4, 4625, "erin"),
    ]


def test_correlate_identities_splits_known_unknown_and_privileged() -> None:
    known, unknown, privileged = correlate_identities(
        ["ALICE", "carol", "missing", "alice"], employees()
    )

    assert known == ("alice", "carol")
    assert unknown == ("missing",)
    assert privileged == ("carol",)


def test_detects_threshold_crossing() -> None:
    alerts = detect_password_sprays(
        threshold_events(),
        employees(),
        PasswordSprayConfig(),
        generated_at=BASE,
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.source_ip == "203.0.113.25"
    assert alert.failed_attempts == 5
    assert alert.distinct_accounts == 5
    assert alert.targeted_accounts == ("alice", "bob", "carol", "dave", "erin")
    assert alert.privileged_accounts == ("carol",)
    assert alert.severity == "high"
    assert alert.confidence == "high"


def test_does_not_alert_below_failure_threshold() -> None:
    alerts = detect_password_sprays(
        threshold_events()[:4], employees(), PasswordSprayConfig()
    )

    assert alerts == []


def test_does_not_alert_without_distinct_accounts() -> None:
    repeated = [event(index, 4625, "alice") for index in range(5)]

    alerts = detect_password_sprays(repeated, employees(), PasswordSprayConfig())

    assert alerts == []


def test_sliding_window_excludes_old_events() -> None:
    spread = [
        event(0, 4625, "alice"),
        event(1, 4625, "bob"),
        event(2, 4625, "carol"),
        event(20, 4625, "dave"),
        event(21, 4625, "erin"),
    ]

    alerts = detect_password_sprays(spread, employees(), PasswordSprayConfig())

    assert alerts == []


def test_groups_failures_by_source_ip() -> None:
    mixed = [
        event(0, 4625, "alice", "203.0.113.1"),
        event(1, 4625, "bob", "203.0.113.1"),
        event(2, 4625, "carol", "203.0.113.1"),
        event(3, 4625, "dave", "203.0.113.2"),
        event(4, 4625, "erin", "203.0.113.2"),
    ]

    alerts = detect_password_sprays(mixed, employees(), PasswordSprayConfig())

    assert alerts == []


def test_success_after_spray_raises_critical_for_privileged_account() -> None:
    events = threshold_events() + [event(7, 4624, "carol")]

    alert = detect_password_sprays(
        events, employees(), PasswordSprayConfig(), generated_at=BASE
    )[0]

    assert alert.successful_logon_accounts == ("carol",)
    assert alert.severity == "critical"
    assert alert.confidence == "high"


def test_success_from_different_source_is_not_correlated() -> None:
    events = threshold_events() + [
        event(7, 4624, "carol", source_ip="198.51.100.10")
    ]

    alert = detect_password_sprays(events, employees(), PasswordSprayConfig())[0]

    assert alert.successful_logon_accounts == ()
    assert alert.severity == "high"


def test_lockout_is_correlated_by_targeted_account() -> None:
    events = threshold_events() + [event(6, 4740, "bob", source_ip=None)]

    alert = detect_password_sprays(events, employees(), PasswordSprayConfig())[0]

    assert alert.locked_out_accounts == ("bob",)
    assert alert.severity == "high"


def test_unknown_accounts_reduce_confidence() -> None:
    unknown_events = [
        event(0, 4625, "unknown1"),
        event(1, 4625, "unknown2"),
        event(2, 4625, "unknown3"),
        event(3, 4625, "unknown4"),
        event(4, 4625, "unknown5"),
    ]

    alert = detect_password_sprays(
        unknown_events, employees(), PasswordSprayConfig()
    )[0]

    assert alert.known_employee_accounts == ()
    assert len(alert.unknown_accounts) == 5
    assert alert.confidence == "low"
    assert alert.severity == "medium"


def test_duplicate_suppression_avoids_overlapping_alerts() -> None:
    events = threshold_events() + [
        event(5, 4625, "frank"),
        event(6, 4625, "grace"),
    ]

    alerts = detect_password_sprays(events, employees(), PasswordSprayConfig())

    assert len(alerts) == 1


def test_new_campaign_after_suppression_generates_second_alert() -> None:
    first = threshold_events()
    second = [
        event(30, 4625, "alice"),
        event(31, 4625, "bob"),
        event(32, 4625, "carol"),
        event(33, 4625, "dave"),
        event(34, 4625, "erin"),
    ]

    alerts = detect_password_sprays(
        first + second, employees(), PasswordSprayConfig()
    )

    assert len(alerts) == 2
    assert alerts[1].detection_start_utc == BASE + timedelta(minutes=30)


def test_alert_to_dict_nests_mitre_and_formats_timestamps() -> None:
    alert = detect_password_sprays(
        threshold_events(),
        employees(),
        PasswordSprayConfig(),
        generated_at=BASE,
    )[0]

    payload = alert.to_dict()

    assert payload["generated_at_utc"] == "2026-07-25T15:00:00Z"
    assert payload["mitre_attack"] == {
        "technique_id": "T1110.003",
        "technique": "Password Spraying",
        "tactic": "Credential Access",
    }
    assert "technique_id" not in payload
