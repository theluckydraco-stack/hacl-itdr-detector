"""Password-spray detection and authentication correlation."""

from __future__ import annotations

import uuid
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta

from .identity import correlate_identities
from .models import (
    AuthEvent,
    Confidence,
    Employee,
    PasswordSprayAlert,
    PasswordSprayConfig,
    Severity,
)


def _severity_and_confidence(
    *,
    success_accounts: tuple[str, ...],
    lockout_accounts: tuple[str, ...],
    privileged_accounts: tuple[str, ...],
    known_accounts: tuple[str, ...],
    distinct_accounts: int,
) -> tuple[Severity, Confidence]:
    if success_accounts and privileged_accounts:
        severity: Severity = "critical"
    elif success_accounts:
        severity = "high"
    elif lockout_accounts or privileged_accounts:
        severity = "high"
    else:
        severity = "medium"

    known_ratio = len(known_accounts) / distinct_accounts if distinct_accounts else 0.0
    if success_accounts or known_ratio >= 0.8:
        confidence: Confidence = "high"
    elif known_ratio >= 0.4:
        confidence = "medium"
    else:
        confidence = "low"
    return severity, confidence


def _correlate_follow_on_events(
    *,
    all_events: Iterable[AuthEvent],
    source_ip: str,
    accounts: set[str],
    start: datetime,
    end: datetime,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    successes: set[str] = set()
    lockouts: set[str] = set()
    for event in all_events:
        if event.timestamp_utc < start or event.timestamp_utc > end:
            continue
        if event.account not in accounts:
            continue
        if event.is_success and event.source_ip == source_ip:
            successes.add(event.account)
        elif event.is_lockout:
            lockouts.add(event.account)
    return tuple(sorted(successes)), tuple(sorted(lockouts))


def detect_password_sprays(
    events: Iterable[AuthEvent],
    employees: Mapping[str, Employee],
    config: PasswordSprayConfig,
    *,
    generated_at: datetime | None = None,
) -> list[PasswordSprayAlert]:
    """Detect threshold crossings in sliding windows grouped by source IP."""

    ordered_events = sorted(events, key=lambda event: event.timestamp_utc)
    failures_by_source: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in ordered_events:
        if event.is_failure and event.source_ip is not None:
            failures_by_source[event.source_ip].append(event)

    generated_at_utc = (generated_at or datetime.now(UTC)).astimezone(UTC)
    window = timedelta(minutes=config.window_minutes)
    follow_on = timedelta(minutes=config.success_correlation_minutes)
    suppression = timedelta(minutes=config.duplicate_suppression_minutes)
    alerts: list[PasswordSprayAlert] = []

    for source_ip, source_failures in sorted(failures_by_source.items()):
        active_window: deque[AuthEvent] = deque()
        suppressed_until: datetime | None = None

        for failure in source_failures:
            while (
                active_window
                and failure.timestamp_utc - active_window[0].timestamp_utc > window
            ):
                active_window.popleft()
            active_window.append(failure)

            if suppressed_until is not None and failure.timestamp_utc <= suppressed_until:
                continue

            targeted_accounts = {event.account for event in active_window}
            if len(active_window) < config.minimum_failed_attempts:
                continue
            if len(targeted_accounts) < config.minimum_distinct_accounts:
                continue

            detection_start = active_window[0].timestamp_utc
            detection_end = active_window[-1].timestamp_utc
            success_accounts, lockout_accounts = _correlate_follow_on_events(
                all_events=ordered_events,
                source_ip=source_ip,
                accounts=targeted_accounts,
                start=detection_start,
                end=detection_end + follow_on,
            )
            known, unknown, privileged = correlate_identities(
                targeted_accounts, employees
            )
            severity, confidence = _severity_and_confidence(
                success_accounts=success_accounts,
                lockout_accounts=lockout_accounts,
                privileged_accounts=privileged,
                known_accounts=known,
                distinct_accounts=len(targeted_accounts),
            )

            alerts.append(
                PasswordSprayAlert(
                    alert_id=str(uuid.uuid4()),
                    generated_at_utc=generated_at_utc,
                    detection_start_utc=detection_start,
                    detection_end_utc=detection_end,
                    source_ip=source_ip,
                    failed_attempts=len(active_window),
                    distinct_accounts=len(targeted_accounts),
                    targeted_accounts=tuple(sorted(targeted_accounts)),
                    known_employee_accounts=known,
                    unknown_accounts=unknown,
                    privileged_accounts=privileged,
                    successful_logon_accounts=success_accounts,
                    locked_out_accounts=lockout_accounts,
                    severity=severity,
                    confidence=confidence,
                )
            )
            suppressed_until = detection_end + suppression

    return sorted(
        alerts,
        key=lambda alert: (alert.detection_start_utc, alert.source_ip),
    )
