"""Investigation timeline generation across authentication and integrity evidence."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from datetime import timedelta
from pathlib import Path

from .models import (
    AuthEvent,
    IntegrityAlert,
    IntegrityConfig,
    PasswordSprayAlert,
    SecurityAlert,
    Severity,
    TimelineEvent,
)

_TIMELINE_NAMESPACE = uuid.UUID("d69fb0d9-1b7a-5d6c-bc30-902c5cd11d43")


def _event_id(*parts: object) -> str:
    return str(uuid.uuid5(_TIMELINE_NAMESPACE, "|".join(str(part) for part in parts)))


def _password_spray_event(alert: PasswordSprayAlert) -> TimelineEvent:
    return TimelineEvent(
        event_id=_event_id("spray", alert.alert_id),
        timestamp_utc=alert.detection_end_utc,
        category="authentication",
        event_type="password_spray_threshold_crossed",
        severity=alert.severity,
        summary=(
            f"Password-spray threshold crossed from {alert.source_ip}: "
            f"{alert.failed_attempts} failures across "
            f"{alert.distinct_accounts} accounts"
        ),
        source="password_spray_detector",
        related_alert_ids=(alert.alert_id,),
        details={
            "source_ip": alert.source_ip,
            "detection_start_utc": alert.detection_start_utc.isoformat(),
            "targeted_accounts": list(alert.targeted_accounts),
            "privileged_accounts": list(alert.privileged_accounts),
        },
    )


def _integrity_event(alert: IntegrityAlert) -> TimelineEvent:
    return TimelineEvent(
        event_id=_event_id("integrity", alert.alert_id),
        timestamp_utc=alert.detected_at_utc,
        category="integrity",
        event_type=f"allow_list_{alert.change_type}",
        severity=alert.severity,
        summary=(
            f"Allow-list integrity changed for {alert.asset_id}: "
            f"{alert.change_type}"
        ),
        source="allow_list_integrity_detector",
        related_alert_ids=(alert.alert_id,),
        details={
            "protected_path": alert.protected_path,
            "added_entries": list(alert.added_entries),
            "removed_entries": list(alert.removed_entries),
            "replacement_suspected": alert.replacement_suspected,
            "baseline_sha256": alert.baseline_sha256,
            "observed_sha256": alert.observed_sha256,
        },
    )


def _follow_on_events(
    auth_events: Iterable[AuthEvent],
    spray_alerts: Iterable[PasswordSprayAlert],
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for alert in spray_alerts:
        success_accounts = set(alert.successful_logon_accounts)
        lockout_accounts = set(alert.locked_out_accounts)
        for auth_event in auth_events:
            if (
                auth_event.is_success
                and auth_event.account in success_accounts
                and auth_event.source_ip == alert.source_ip
            ):
                events.append(
                    TimelineEvent(
                        event_id=_event_id(
                            "success",
                            alert.alert_id,
                            auth_event.timestamp_utc,
                            auth_event.account,
                        ),
                        timestamp_utc=auth_event.timestamp_utc,
                        category="authentication",
                        event_type="successful_logon_after_spray",
                        severity="critical"
                        if auth_event.account in alert.privileged_accounts
                        else "high",
                        summary=(
                            f"Successful logon for {auth_event.account} from "
                            f"{alert.source_ip} after spray activity"
                        ),
                        source=f"windows_event_{auth_event.event_id}",
                        related_alert_ids=(alert.alert_id,),
                        details={
                            "account": auth_event.account,
                            "source_ip": auth_event.source_ip,
                            "host": auth_event.host,
                        },
                    )
                )
            elif auth_event.is_lockout and auth_event.account in lockout_accounts:
                events.append(
                    TimelineEvent(
                        event_id=_event_id(
                            "lockout",
                            alert.alert_id,
                            auth_event.timestamp_utc,
                            auth_event.account,
                        ),
                        timestamp_utc=auth_event.timestamp_utc,
                        category="authentication",
                        event_type="account_lockout_after_spray",
                        severity="high",
                        summary=(
                            f"Account lockout for {auth_event.account} after "
                            "password-spray activity"
                        ),
                        source=f"windows_event_{auth_event.event_id}",
                        related_alert_ids=(alert.alert_id,),
                        details={
                            "account": auth_event.account,
                            "host": auth_event.host,
                        },
                    )
                )
    return events


def _correlation_events(
    spray_alerts: Iterable[PasswordSprayAlert],
    integrity_alerts: Iterable[IntegrityAlert],
    config: IntegrityConfig,
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    correlation_window = timedelta(minutes=config.correlation_window_minutes)
    for integrity_alert in integrity_alerts:
        for spray_alert in spray_alerts:
            delta = abs(
                integrity_alert.detected_at_utc - spray_alert.detection_end_utc
            )
            if delta > correlation_window:
                continue
            severity: Severity = (
                "critical"
                if spray_alert.successful_logon_accounts
                or integrity_alert.severity == "critical"
                else "high"
            )
            events.append(
                TimelineEvent(
                    event_id=_event_id(
                        "correlation", integrity_alert.alert_id, spray_alert.alert_id
                    ),
                    timestamp_utc=max(
                        integrity_alert.detected_at_utc,
                        spray_alert.detection_end_utc,
                    ),
                    category="correlation",
                    event_type="integrity_change_near_password_spray",
                    severity=severity,
                    summary=(
                        "Protected allow-list change occurred within "
                        f"{config.correlation_window_minutes} minutes of "
                        "password-spray activity"
                    ),
                    source="investigation_correlator",
                    related_alert_ids=(
                        integrity_alert.alert_id,
                        spray_alert.alert_id,
                    ),
                    details={
                        "time_delta_seconds": int(delta.total_seconds()),
                        "integrity_change_type": integrity_alert.change_type,
                        "source_ip": spray_alert.source_ip,
                        "successful_logon_accounts": list(
                            spray_alert.successful_logon_accounts
                        ),
                    },
                )
            )
    return events


def build_investigation_timeline(
    auth_events: Iterable[AuthEvent],
    alerts: Iterable[SecurityAlert],
    config: IntegrityConfig,
) -> list[TimelineEvent]:
    """Build a chronological timeline from detector alerts and source events."""

    alert_list = list(alerts)
    spray_alerts = [
        alert for alert in alert_list if isinstance(alert, PasswordSprayAlert)
    ]
    integrity_alerts = [
        alert for alert in alert_list if isinstance(alert, IntegrityAlert)
    ]
    timeline = [
        *(_password_spray_event(alert) for alert in spray_alerts),
        *(_integrity_event(alert) for alert in integrity_alerts),
        *_follow_on_events(auth_events, spray_alerts),
        *_correlation_events(spray_alerts, integrity_alerts, config),
    ]
    category_order = {"integrity": 0, "authentication": 1, "correlation": 2}
    return sorted(
        timeline,
        key=lambda event: (
            event.timestamp_utc,
            category_order[event.category],
            event.event_id,
        ),
    )


def timeline_to_jsonl(events: Iterable[TimelineEvent]) -> str:
    lines = [json.dumps(event.to_dict(), sort_keys=True) for event in events]
    return "\n".join(lines) + ("\n" if lines else "")


def timeline_to_markdown(events: Iterable[TimelineEvent]) -> str:
    event_list = list(events)
    lines = [
        "# Investigation Timeline",
        "",
        "| Time (UTC) | Severity | Category | Event | Summary |",
        "|---|---|---|---|---|",
    ]
    for event in event_list:
        timestamp = event.timestamp_utc.isoformat().replace("+00:00", "Z")
        summary = event.summary.replace("|", "\\|")
        lines.append(
            f"| {timestamp} | {event.severity} | {event.category} | "
            f"{event.event_type} | {summary} |"
        )
    if not event_list:
        lines.extend(["", "No investigation events were generated."])
    return "\n".join(lines) + "\n"


def write_timeline(path: Path, events: Iterable[TimelineEvent]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.casefold() == ".md":
        content = timeline_to_markdown(events)
    else:
        content = timeline_to_jsonl(events)
    path.write_text(content, encoding="utf-8")
