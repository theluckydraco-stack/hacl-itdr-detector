"""Identity detection for successful logons by non-active accounts."""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime

from .models import AuthEvent, Employee, InactiveAccountAlert


def detect_inactive_account_logons(
    events: Iterable[AuthEvent],
    employees: Mapping[str, Employee],
    *,
    generated_at: datetime | None = None,
) -> list[InactiveAccountAlert]:
    """Detect successful logons for identities not marked active."""

    generated_at_utc = (generated_at or datetime.now(UTC)).astimezone(UTC)
    alerts: list[InactiveAccountAlert] = []
    seen: set[tuple[datetime, str, str | None, str]] = set()

    for event in sorted(events, key=lambda item: item.timestamp_utc):
        if not event.is_success:
            continue
        employee = employees.get(event.account)
        if employee is None or employee.status == "active":
            continue

        deduplication_key = (
            event.timestamp_utc,
            event.account,
            event.source_ip,
            event.host,
        )
        if deduplication_key in seen:
            continue
        seen.add(deduplication_key)

        alerts.append(
            InactiveAccountAlert(
                alert_id=str(uuid.uuid4()),
                generated_at_utc=generated_at_utc,
                detected_at_utc=event.timestamp_utc,
                account=event.account,
                employee_id=employee.employee_id,
                department=employee.department,
                directory_status=employee.status,
                source_ip=event.source_ip,
                host=event.host,
                workstation=event.workstation,
                logon_type=event.logon_type,
                privileged=employee.privileged,
                severity="critical" if employee.privileged else "high",
            )
        )

    return alerts
