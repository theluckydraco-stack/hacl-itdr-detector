"""Automated Markdown investigation reporting."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .models import (
    InactiveAccountAlert,
    PasswordSprayAlert,
    SecurityAlert,
    TimelineEvent,
)
from .timeline import timeline_to_markdown


class ReportError(ValueError):
    """Raised when report evidence cannot be collected."""


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    """Hash and size metadata for one investigation input."""

    label: str
    path: str
    sha256: str
    byte_length: int


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def collect_evidence_artifacts(
    paths: Mapping[str, Path],
) -> tuple[EvidenceArtifact, ...]:
    """Collect deterministic SHA-256 evidence metadata."""

    artifacts: list[EvidenceArtifact] = []
    for label, path in sorted(paths.items()):
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise ReportError(f"unable to hash report evidence: {path}") from exc
        artifacts.append(
            EvidenceArtifact(
                label=label,
                path=str(path),
                sha256=hashlib.sha256(content).hexdigest(),
                byte_length=len(content),
            )
        )
    return tuple(artifacts)


def _finding_row(alert: SecurityAlert) -> tuple[str, str, str, str]:
    if isinstance(alert, PasswordSprayAlert):
        summary = (
            f"{alert.failed_attempts} failures across {alert.distinct_accounts} "
            f"accounts from {alert.source_ip}"
        )
        return alert.alert_id, "Password spray", alert.severity, summary
    if isinstance(alert, InactiveAccountAlert):
        summary = (
            f"Successful logon by {alert.account}, directory status "
            f"{alert.directory_status}, on {alert.host}"
        )
        return alert.alert_id, "Inactive account logon", alert.severity, summary
    summary = (
        f"{alert.change_type} for {alert.asset_id}; "
        f"added={len(alert.added_entries)}, removed={len(alert.removed_entries)}"
    )
    return alert.alert_id, "Allow-list integrity", alert.severity, summary


def _affected_identities(alerts: Iterable[SecurityAlert]) -> tuple[str, ...]:
    identities: set[str] = set()
    for alert in alerts:
        if isinstance(alert, PasswordSprayAlert):
            identities.update(alert.targeted_accounts)
            identities.update(alert.successful_logon_accounts)
            identities.update(alert.locked_out_accounts)
        elif isinstance(alert, InactiveAccountAlert):
            identities.add(alert.account)
    return tuple(sorted(identities))


def _attack_rows(alerts: Iterable[SecurityAlert]) -> tuple[tuple[str, str, str], ...]:
    rows: set[tuple[str, str, str]] = set()
    for alert in alerts:
        payload = alert.to_dict()["mitre_attack"]
        rows.add(
            (
                str(payload["technique_id"]),
                str(payload["technique"]),
                str(payload["tactic"]),
            )
        )
    return tuple(sorted(rows))


def build_investigation_report(
    alerts: Iterable[SecurityAlert],
    timeline: Iterable[TimelineEvent],
    artifacts: Iterable[EvidenceArtifact],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Build a complete Markdown report from detector evidence."""

    alert_list = list(alerts)
    timeline_list = list(timeline)
    artifact_list = list(artifacts)
    generated = (generated_at or datetime.now(UTC)).astimezone(UTC)
    severity_counts = Counter(alert.severity for alert in alert_list)
    type_counts = Counter(type(alert).__name__ for alert in alert_list)

    lines = [
        "# hACL ITDR Investigation Report",
        "",
        f"Generated: {_utc_text(generated)}",
        "",
        "## Executive summary",
        "",
        f"- Alerts generated: {len(alert_list)}",
        f"- Timeline events: {len(timeline_list)}",
        f"- Critical alerts: {severity_counts['critical']}",
        f"- High alerts: {severity_counts['high']}",
        f"- Password-spray alerts: {type_counts['PasswordSprayAlert']}",
        f"- Inactive-account alerts: {type_counts['InactiveAccountAlert']}",
        f"- Integrity alerts: {type_counts['IntegrityAlert']}",
        "",
        (
            "This report records deterministic detector output from synthetic "
            "evidence. Alerts are investigative leads and require analyst validation."
        ),
        "",
        "## Findings",
        "",
        "| Alert ID | Type | Severity | Summary |",
        "|---|---|---|---|",
    ]
    for alert in alert_list:
        alert_id, alert_type, severity, summary = _finding_row(alert)
        lines.append(
            f"| {_escape(alert_id)} | {_escape(alert_type)} | "
            f"{_escape(severity)} | {_escape(summary)} |"
        )
    if not alert_list:
        lines.append("| - | No alerts | - | No detector findings were generated |")

    lines.extend(["", "## Affected identities", ""])
    identities = _affected_identities(alert_list)
    if identities:
        lines.extend(f"- `{identity}`" for identity in identities)
    else:
        lines.append("No identities were identified by the detector.")

    lines.extend(
        [
            "",
            "## ATT&CK context",
            "",
            "| Technique | Name | Tactic |",
            "|---|---|---|",
        ]
    )
    attack_rows = _attack_rows(alert_list)
    for technique_id, technique, tactic in attack_rows:
        lines.append(
            f"| {_escape(technique_id)} | {_escape(technique)} | "
            f"{_escape(tactic)} |"
        )
    if not attack_rows:
        lines.append("| - | No mapped findings | - |")

    lines.extend(
        [
            "",
            "## Evidence integrity",
            "",
            "| Artifact | Path | SHA-256 | Bytes |",
            "|---|---|---|---:|",
        ]
    )
    for artifact in artifact_list:
        lines.append(
            f"| {_escape(artifact.label)} | `{_escape(artifact.path)}` | "
            f"`{artifact.sha256}` | {artifact.byte_length} |"
        )
    if not artifact_list:
        lines.append("| - | - | - | 0 |")

    lines.extend(["", "## Recommended actions", ""])
    actions = sorted(
        {
            action
            for alert in alert_list
            for action in alert.recommended_actions
        }
    )
    if actions:
        lines.extend(f"- {action}" for action in actions)
    else:
        lines.append("No detector-specific actions were generated.")

    lines.extend(
        [
            "",
            "## Investigation timeline",
            "",
            timeline_to_markdown(timeline_list).removeprefix(
                "# Investigation Timeline\n\n"
            ).rstrip(),
            "",
            "## Limitations",
            "",
            "- The included data is synthetic and does not establish production readiness.",
            "- Directory status, Windows telemetry, and the baseline manifest are trust inputs.",
            "- ATT&CK mappings provide investigation context, not adversary attribution.",
            "- Sigma and KQL content requires field mapping and tuning for the target SIEM.",
            "",
        ]
    )
    return "\n".join(lines)


def write_investigation_report(
    path: Path,
    alerts: Iterable[SecurityAlert],
    timeline: Iterable[TimelineEvent],
    artifacts: Iterable[EvidenceArtifact],
) -> None:
    """Write a Markdown investigation report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        build_investigation_report(alerts, timeline, artifacts),
        encoding="utf-8",
    )
