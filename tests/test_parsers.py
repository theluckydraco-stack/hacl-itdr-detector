from __future__ import annotations

from pathlib import Path

import pytest

from hacl_itdr.models import PasswordSprayConfig
from hacl_itdr.parsers import (
    ParseError,
    load_auth_events,
    load_config,
    load_employees,
    parse_auth_event,
)


def test_parse_auth_event_normalises_timezone_account_and_ip() -> None:
    event = parse_auth_event(
        {
            "timestamp_utc": "2026-07-25T16:00:00+01:00",
            "event_id": "4625",
            "source_ip": "203.0.113.25",
            "account": " Alice ",
            "host": " DC01 ",
            "logon_type": "3",
        },
        context="test",
    )

    assert event.timestamp_utc.isoformat() == "2026-07-25T15:00:00+00:00"
    assert event.account == "alice"
    assert event.source_ip == "203.0.113.25"
    assert event.host == "DC01"
    assert event.logon_type == 3


def test_parse_lockout_allows_missing_source_ip() -> None:
    event = parse_auth_event(
        {
            "timestamp_utc": "2026-07-25T15:00:00Z",
            "event_id": 4740,
            "source_ip": None,
            "account": "alice",
            "host": "DC01",
        },
        context="test",
    )

    assert event.source_ip is None
    assert event.is_lockout


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("timestamp_utc", "2026-07-25T15:00:00", "include a timezone"),
        ("event_id", 9999, "unsupported event_id"),
        ("source_ip", "999.0.0.1", "invalid source_ip"),
        ("account", "", "account must be"),
        ("host", "", "host must be"),
        ("logon_type", True, "expected an integer"),
    ],
)
def test_parse_auth_event_rejects_invalid_values(
    field: str, value: object, message: str
) -> None:
    payload: dict[str, object] = {
        "timestamp_utc": "2026-07-25T15:00:00Z",
        "event_id": 4625,
        "source_ip": "203.0.113.25",
        "account": "alice",
        "host": "DC01",
        "logon_type": 3,
    }
    payload[field] = value

    with pytest.raises(ParseError, match=message):
        parse_auth_event(payload, context="test")


def test_load_auth_events_sorts_and_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        '\n{"timestamp_utc":"2026-07-25T15:02:00Z","event_id":4625,'
        '"source_ip":"203.0.113.2","account":"b","host":"DC01"}\n'
        '{"timestamp_utc":"2026-07-25T15:01:00Z","event_id":4625,'
        '"source_ip":"203.0.113.1","account":"a","host":"DC01"}\n',
        encoding="utf-8",
    )

    events = load_auth_events(path)

    assert [event.account for event in events] == ["a", "b"]


def test_load_auth_events_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("{bad json}\n", encoding="utf-8")

    with pytest.raises(ParseError, match="invalid JSON"):
        load_auth_events(path)


def test_load_auth_events_rejects_non_object_json(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("[]\n", encoding="utf-8")

    with pytest.raises(ParseError, match="JSON object"):
        load_auth_events(path)


def test_load_employees_parses_records(tmp_path: Path) -> None:
    path = tmp_path / "employees.csv"
    path.write_text(
        "username,employee_id,department,status,privileged\n"
        "Alice,EMP-1,Security,active,true\n",
        encoding="utf-8",
    )

    employees = load_employees(path)

    assert employees["alice"].privileged is True
    assert employees["alice"].department == "Security"


def test_load_employees_rejects_duplicate_username(tmp_path: Path) -> None:
    path = tmp_path / "employees.csv"
    path.write_text(
        "username,employee_id,department,status,privileged\n"
        "alice,EMP-1,Security,active,false\n"
        "ALICE,EMP-2,Finance,active,false\n",
        encoding="utf-8",
    )

    with pytest.raises(ParseError, match="duplicate username"):
        load_employees(path)


def test_load_employees_rejects_invalid_privileged_value(tmp_path: Path) -> None:
    path = tmp_path / "employees.csv"
    path.write_text(
        "username,employee_id,department,status,privileged\n"
        "alice,EMP-1,Security,active,yes\n",
        encoding="utf-8",
    )

    with pytest.raises(ParseError, match="true or false"):
        load_employees(path)


def test_load_config_uses_values(tmp_path: Path) -> None:
    path = tmp_path / "detector.toml"
    path.write_text(
        "[password_spray]\n"
        "window_minutes = 20\n"
        "minimum_failed_attempts = 8\n"
        "minimum_distinct_accounts = 6\n"
        "success_correlation_minutes = 45\n"
        "duplicate_suppression_minutes = 25\n",
        encoding="utf-8",
    )

    config = load_config(path)

    assert config == PasswordSprayConfig(20, 8, 6, 45, 25)


def test_load_config_rejects_missing_section(tmp_path: Path) -> None:
    path = tmp_path / "detector.toml"
    path.write_text("[other]\nvalue = 1\n", encoding="utf-8")

    with pytest.raises(ParseError, match=r"missing \[password_spray\]"):
        load_config(path)


def test_password_spray_config_rejects_invalid_thresholds() -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        PasswordSprayConfig(window_minutes=0)

    with pytest.raises(ValueError, match="cannot exceed"):
        PasswordSprayConfig(
            minimum_failed_attempts=4,
            minimum_distinct_accounts=5,
        )
