from __future__ import annotations

from datetime import UTC, datetime

from hacl_itdr.inactive_account import detect_inactive_account_logons
from hacl_itdr.models import AuthEvent, Employee

NOW = datetime(2026, 7, 25, 18, 0, tzinfo=UTC)


def auth_event(
    *,
    event_id: int = 4624,
    account: str = "former.user",
    source_ip: str | None = "198.51.100.42",
) -> AuthEvent:
    return AuthEvent(
        timestamp_utc=NOW,
        event_id=event_id,
        source_ip=source_ip,
        account=account,
        host="APP01",
        logon_type=10,
        workstation="WKSTN-42",
    )


def directory(*, privileged: bool = False) -> dict[str, Employee]:
    return {
        "former.user": Employee(
            "former.user", "EMP-9", "Finance", "disabled", privileged
        ),
        "active.user": Employee(
            "active.user", "EMP-10", "Security", "active", False
        ),
    }


def test_detects_successful_logon_by_disabled_identity() -> None:
    alerts = detect_inactive_account_logons(
        [auth_event()], directory(), generated_at=NOW
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.account == "former.user"
    assert alert.directory_status == "disabled"
    assert alert.source_ip == "198.51.100.42"
    assert alert.workstation == "WKSTN-42"
    assert alert.severity == "high"


def test_privileged_inactive_identity_is_critical() -> None:
    alert = detect_inactive_account_logons(
        [auth_event()], directory(privileged=True), generated_at=NOW
    )[0]

    assert alert.privileged is True
    assert alert.severity == "critical"


def test_ignores_failures_active_and_unknown_accounts() -> None:
    events = [
        auth_event(event_id=4625),
        auth_event(account="active.user"),
        auth_event(account="unknown.user"),
    ]

    assert detect_inactive_account_logons(events, directory()) == []


def test_duplicate_source_record_is_suppressed() -> None:
    event = auth_event()

    alerts = detect_inactive_account_logons([event, event], directory())

    assert len(alerts) == 1


def test_alert_serialisation_contains_contextual_attack_mapping() -> None:
    alert = detect_inactive_account_logons(
        [auth_event(source_ip=None)], directory(), generated_at=NOW
    )[0]

    payload = alert.to_dict()

    assert payload["alert_type"] == "inactive_account_logon"
    assert payload["schema_version"] == "1.0"
    assert payload["detected_at_utc"] == "2026-07-25T18:00:00Z"
    assert payload["mitre_attack"]["technique_id"] == "T1078"
    assert "Contextual mapping" in payload["mitre_attack"]["mapping_basis"]
