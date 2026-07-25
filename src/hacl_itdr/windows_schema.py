"""Strict adapters for representative Windows Security event exports."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import AuthEvent, FileAccessEvent
from .parsers import ParseError

SUPPORTED_WINDOWS_EVENT_IDS = {4624, 4625, 4663, 4740}
WINDOWS_SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"


@dataclass(frozen=True, slots=True)
class WindowsSecurityEvidence:
    """Normalised authentication and file-access evidence."""

    authentication_events: tuple[AuthEvent, ...]
    file_access_events: tuple[FileAccessEvent, ...]


def _mapping(value: object, *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ParseError(f"{context}: expected an object")
    return value


def _required_text(value: object, *, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ParseError(f"{context}: expected a non-empty string")
    return value.strip()


def _optional_text(value: object) -> str | None:
    if value in (None, "", "-"):
        return None
    if not isinstance(value, str):
        return str(value)
    return value.strip() or None


def _integer(value: object, *, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ParseError(f"{context}: expected an integer")
    try:
        return int(value)
    except ValueError as exc:
        raise ParseError(f"{context}: expected an integer") from exc


def _timestamp(system: dict[str, Any], *, context: str) -> datetime:
    raw = system.get("TimeCreated")
    if isinstance(raw, dict):
        raw = raw.get("SystemTime")
    text = _required_text(raw, context=f"{context}: TimeCreated.SystemTime")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError(f"{context}: invalid SystemTime") from exc
    if parsed.tzinfo is None:
        raise ParseError(f"{context}: SystemTime must include a timezone")
    return parsed.astimezone(UTC)


def _provider_name(system: dict[str, Any], *, context: str) -> str:
    provider = system.get("Provider")
    if isinstance(provider, dict):
        provider = provider.get("Name")
    return _required_text(provider, context=f"{context}: Provider.Name")


def _source_ip(value: object, *, context: str) -> str | None:
    text = _optional_text(value)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise ParseError(f"{context}: invalid IpAddress") from exc


def _subject_account(event_data: dict[str, Any], *, context: str) -> str:
    username = _required_text(
        event_data.get("SubjectUserName"),
        context=f"{context}: SubjectUserName",
    )
    domain = _optional_text(event_data.get("SubjectDomainName"))
    return f"{domain}\\{username}".casefold() if domain else username.casefold()


def parse_windows_security_record(
    payload: dict[str, Any], *, context: str
) -> AuthEvent | FileAccessEvent:
    """Parse one representative Windows Security record."""

    system = _mapping(payload.get("System"), context=f"{context}: System")
    event_data = _mapping(payload.get("EventData"), context=f"{context}: EventData")

    provider = _provider_name(system, context=context)
    if provider != WINDOWS_SECURITY_PROVIDER:
        raise ParseError(f"{context}: unsupported provider {provider}")

    event_id = _integer(system.get("EventID"), context=f"{context}: EventID")
    if event_id not in SUPPORTED_WINDOWS_EVENT_IDS:
        raise ParseError(f"{context}: unsupported EventID {event_id}")

    timestamp = _timestamp(system, context=context)
    host = _required_text(system.get("Computer"), context=f"{context}: Computer")

    if event_id == 4663:
        return FileAccessEvent(
            timestamp_utc=timestamp,
            event_id=event_id,
            host=host,
            subject_account=_subject_account(event_data, context=context),
            object_name=_required_text(
                event_data.get("ObjectName"), context=f"{context}: ObjectName"
            ),
            process_name=_required_text(
                event_data.get("ProcessName"), context=f"{context}: ProcessName"
            ),
            access_mask=_required_text(
                event_data.get("AccessMask"), context=f"{context}: AccessMask"
            ).casefold(),
            handle_id=_optional_text(event_data.get("HandleId")),
        )

    account = _required_text(
        event_data.get("TargetUserName"), context=f"{context}: TargetUserName"
    ).casefold()
    workstation = _optional_text(
        event_data.get("WorkstationName")
        or event_data.get("CallerComputerName")
    )
    logon_type = None
    if event_id in {4624, 4625}:
        logon_type = _integer(
            event_data.get("LogonType"), context=f"{context}: LogonType"
        )

    return AuthEvent(
        timestamp_utc=timestamp,
        event_id=event_id,
        source_ip=_source_ip(event_data.get("IpAddress"), context=context),
        account=account,
        host=host,
        logon_type=logon_type,
        status=_optional_text(event_data.get("Status")),
        sub_status=_optional_text(event_data.get("SubStatus")),
        workstation=workstation,
    )


def load_windows_security_events(path: Path) -> WindowsSecurityEvidence:
    """Load newline-delimited representative Windows Security records."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ParseError(f"unable to read Windows Security events: {path}") from exc

    authentication_events: list[AuthEvent] = []
    file_access_events: list[FileAccessEvent] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        context = f"{path}: line {line_number}"
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ParseError(f"{context}: invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ParseError(f"{context}: event must be a JSON object")
        record = parse_windows_security_record(payload, context=context)
        if isinstance(record, AuthEvent):
            authentication_events.append(record)
        else:
            file_access_events.append(record)

    return WindowsSecurityEvidence(
        authentication_events=tuple(
            sorted(authentication_events, key=lambda event: event.timestamp_utc)
        ),
        file_access_events=tuple(
            sorted(file_access_events, key=lambda event: event.timestamp_utc)
        ),
    )
