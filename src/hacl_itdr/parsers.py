"""Strict parsers for synthetic authentication and identity data."""

from __future__ import annotations

import csv
import ipaddress
import json
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import AuthEvent, Employee, PasswordSprayConfig

SUPPORTED_EVENT_IDS = {4624, 4625, 4740}


class ParseError(ValueError):
    """Raised when detector input cannot be parsed safely."""


def _normalise_account(value: object, *, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ParseError(f"{context}: account must be a non-empty string")
    return value.strip().casefold()


def _parse_timestamp(value: object, *, context: str) -> datetime:
    if not isinstance(value, str):
        raise ParseError(f"{context}: timestamp_utc must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError(f"{context}: invalid timestamp_utc") from exc
    if parsed.tzinfo is None:
        raise ParseError(f"{context}: timestamp_utc must include a timezone")
    return parsed.astimezone(UTC)


def _parse_source_ip(value: object, *, event_id: int, context: str) -> str | None:
    if value in (None, "", "-"):
        if event_id == 4740:
            return None
        raise ParseError(f"{context}: source_ip is required for event {event_id}")
    if not isinstance(value, str):
        raise ParseError(f"{context}: source_ip must be a string")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ParseError(f"{context}: invalid source_ip") from exc


def _parse_optional_int(value: object, *, context: str) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ParseError(f"{context}: expected an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ParseError(f"{context}: expected an integer") from exc


def parse_auth_event(payload: dict[str, Any], *, context: str) -> AuthEvent:
    """Parse one authentication event from a JSON object."""

    raw_event_id = payload.get("event_id")
    if isinstance(raw_event_id, bool):
        raise ParseError(f"{context}: event_id must be an integer")
    try:
        event_id = int(raw_event_id)
    except (TypeError, ValueError) as exc:
        raise ParseError(f"{context}: event_id must be an integer") from exc
    if event_id not in SUPPORTED_EVENT_IDS:
        raise ParseError(f"{context}: unsupported event_id {event_id}")

    host = payload.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ParseError(f"{context}: host must be a non-empty string")

    return AuthEvent(
        timestamp_utc=_parse_timestamp(payload.get("timestamp_utc"), context=context),
        event_id=event_id,
        source_ip=_parse_source_ip(
            payload.get("source_ip"), event_id=event_id, context=context
        ),
        account=_normalise_account(payload.get("account"), context=context),
        host=host.strip(),
        logon_type=_parse_optional_int(
            payload.get("logon_type"), context=f"{context}: logon_type"
        ),
        status=(str(payload["status"]).strip() if payload.get("status") else None),
        sub_status=(
            str(payload["sub_status"]).strip() if payload.get("sub_status") else None
        ),
    )


def load_auth_events(path: Path) -> list[AuthEvent]:
    """Load and validate newline-delimited JSON authentication events."""

    events: list[AuthEvent] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ParseError(f"unable to read authentication events: {path}") from exc

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
        events.append(parse_auth_event(payload, context=context))

    return sorted(events, key=lambda event: event.timestamp_utc)


def load_employees(path: Path) -> dict[str, Employee]:
    """Load a synthetic employee directory keyed by normalised username."""

    employees: dict[str, Employee] = {}
    try:
        file_handle = path.open(encoding="utf-8", newline="")
    except OSError as exc:
        raise ParseError(f"unable to read employee directory: {path}") from exc

    with file_handle:
        reader = csv.DictReader(file_handle)
        required = {"username", "employee_id", "department", "status", "privileged"}
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ParseError(f"{path}: employee CSV is missing required columns")

        for row_number, row in enumerate(reader, start=2):
            context = f"{path}: row {row_number}"
            username = _normalise_account(row.get("username"), context=context)
            if username in employees:
                raise ParseError(f"{context}: duplicate username {username}")
            privileged_raw = (row.get("privileged") or "").strip().casefold()
            if privileged_raw not in {"true", "false"}:
                raise ParseError(f"{context}: privileged must be true or false")
            employee_id = (row.get("employee_id") or "").strip()
            department = (row.get("department") or "").strip()
            status = (row.get("status") or "").strip().casefold()
            if not all((employee_id, department, status)):
                raise ParseError(f"{context}: employee fields cannot be empty")
            employees[username] = Employee(
                username=username,
                employee_id=employee_id,
                department=department,
                status=status,
                privileged=privileged_raw == "true",
            )

    return employees


def load_config(path: Path) -> PasswordSprayConfig:
    """Load detector thresholds from a TOML configuration file."""

    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ParseError(f"unable to parse detector configuration: {path}") from exc

    section = payload.get("password_spray")
    if not isinstance(section, dict):
        raise ParseError(f"{path}: missing [password_spray] configuration")
    try:
        return PasswordSprayConfig(
            window_minutes=int(section.get("window_minutes", 10)),
            minimum_failed_attempts=int(section.get("minimum_failed_attempts", 5)),
            minimum_distinct_accounts=int(
                section.get("minimum_distinct_accounts", 5)
            ),
            success_correlation_minutes=int(
                section.get("success_correlation_minutes", 30)
            ),
            duplicate_suppression_minutes=int(
                section.get("duplicate_suppression_minutes", 15)
            ),
        )
    except (TypeError, ValueError) as exc:
        raise ParseError(f"{path}: invalid password_spray configuration") from exc
