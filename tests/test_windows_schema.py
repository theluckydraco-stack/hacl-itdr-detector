from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hacl_itdr.models import AuthEvent, FileAccessEvent
from hacl_itdr.parsers import ParseError
from hacl_itdr.windows_schema import (
    load_windows_security_events,
    parse_windows_security_record,
)


def record(event_id: int = 4625) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "System": {
            "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
            "EventID": event_id,
            "TimeCreated": {"SystemTime": "2026-07-25T15:00:00Z"},
            "Computer": "DC01.contoso.local",
        },
        "EventData": {},
    }
    if event_id in {4624, 4625}:
        payload["EventData"] = {
            "TargetUserName": " Alice ",
            "TargetDomainName": "CONTOSO",
            "LogonType": "3",
            "WorkstationName": "WKSTN-17",
            "IpAddress": "203.0.113.25",
            "Status": "0xC000006D" if event_id == 4625 else None,
            "SubStatus": "0xC000006A" if event_id == 4625 else None,
        }
    elif event_id == 4740:
        payload["EventData"] = {
            "TargetUserName": "Alice",
            "TargetDomainName": "CONTOSO",
            "CallerComputerName": "WKSTN-17",
            "SubjectUserName": "DC01$",
            "SubjectDomainName": "CONTOSO",
        }
    else:
        payload["EventData"] = {
            "SubjectUserName": "svc.deploy",
            "SubjectDomainName": "CONTOSO",
            "ObjectName": r"C:\hacl\data\allow_list.txt",
            "ProcessName": r"C:\Windows\System32\powershell.exe",
            "AccessMask": "0x2",
            "HandleId": "0x93c",
        }
    return payload


def test_parses_failed_logon_fields() -> None:
    parsed = parse_windows_security_record(record(), context="test")

    assert isinstance(parsed, AuthEvent)
    assert parsed.account == "alice"
    assert parsed.source_ip == "203.0.113.25"
    assert parsed.logon_type == 3
    assert parsed.workstation == "WKSTN-17"
    assert parsed.status == "0xC000006D"


def test_parses_lockout_without_source_ip() -> None:
    parsed = parse_windows_security_record(record(4740), context="test")

    assert isinstance(parsed, AuthEvent)
    assert parsed.is_lockout
    assert parsed.source_ip is None
    assert parsed.workstation == "WKSTN-17"


def test_parses_file_access_evidence() -> None:
    parsed = parse_windows_security_record(record(4663), context="test")

    assert isinstance(parsed, FileAccessEvent)
    assert parsed.subject_account == r"contoso\svc.deploy"
    assert parsed.object_name.endswith("allow_list.txt")
    assert parsed.access_mask == "0x2"
    assert parsed.handle_id == "0x93c"


def test_loader_separates_and_sorts_event_types(tmp_path: Path) -> None:
    earlier = record(4663)
    later = record(4624)
    later["System"]["TimeCreated"]["SystemTime"] = "2026-07-25T16:00:00Z"
    path = tmp_path / "windows.jsonl"
    path.write_text(
        "\n" + json.dumps(later) + "\n" + json.dumps(earlier) + "\n",
        encoding="utf-8",
    )

    evidence = load_windows_security_events(path)

    assert len(evidence.authentication_events) == 1
    assert len(evidence.file_access_events) == 1
    assert evidence.authentication_events[0].timestamp_utc.hour == 16
    assert evidence.file_access_events[0].timestamp_utc.hour == 15


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda payload: payload["System"].update(
                {"Provider": {"Name": "Other-Provider"}}
            ),
            "unsupported provider",
        ),
        (
            lambda payload: payload["System"].update({"EventID": 9999}),
            "unsupported EventID",
        ),
        (
            lambda payload: payload["System"].update(
                {"TimeCreated": {"SystemTime": "2026-07-25T15:00:00"}}
            ),
            "include a timezone",
        ),
        (
            lambda payload: payload["EventData"].update(
                {"IpAddress": "999.0.0.1"}
            ),
            "invalid IpAddress",
        ),
        (
            lambda payload: payload["EventData"].pop("LogonType"),
            "LogonType",
        ),
    ],
)
def test_rejects_invalid_representative_records(
    mutator: Any, message: str
) -> None:
    payload = record()
    mutator(payload)

    with pytest.raises(ParseError, match=message):
        parse_windows_security_record(payload, context="test")


def test_allows_missing_remote_ip_for_successful_logon() -> None:
    payload = record(4624)
    payload["EventData"]["IpAddress"] = "-"

    parsed = parse_windows_security_record(payload, context="test")

    assert isinstance(parsed, AuthEvent)
    assert parsed.source_ip is None


def test_rejects_non_object_sections() -> None:
    payload = record()
    payload["System"] = []

    with pytest.raises(ParseError, match="System: expected an object"):
        parse_windows_security_record(payload, context="test")


def test_loader_rejects_invalid_json_and_non_object(tmp_path: Path) -> None:
    path = tmp_path / "windows.jsonl"
    path.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ParseError, match="invalid JSON"):
        load_windows_security_events(path)

    path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ParseError, match="JSON object"):
        load_windows_security_events(path)


def test_loader_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ParseError, match="unable to read Windows Security"):
        load_windows_security_events(tmp_path / "missing.jsonl")
