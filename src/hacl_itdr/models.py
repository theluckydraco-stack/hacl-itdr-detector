"""Typed models for authentication, integrity, and investigation output."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Literal

Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
IntegrityChangeType = Literal[
    "content_modified",
    "entries_added",
    "entries_removed",
    "entries_changed",
    "missing",
    "invalid",
]
TimelineCategory = Literal["authentication", "integrity", "correlation"]


def _utc_text(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """Normalised Windows authentication event used by the detector."""

    timestamp_utc: datetime
    event_id: int
    source_ip: str | None
    account: str
    host: str
    logon_type: int | None = None
    status: str | None = None
    sub_status: str | None = None

    @property
    def is_failure(self) -> bool:
        return self.event_id == 4625

    @property
    def is_success(self) -> bool:
        return self.event_id == 4624

    @property
    def is_lockout(self) -> bool:
        return self.event_id == 4740


@dataclass(frozen=True, slots=True)
class Employee:
    """Synthetic identity-directory record used for correlation."""

    username: str
    employee_id: str
    department: str
    status: str
    privileged: bool = False


@dataclass(frozen=True, slots=True)
class PasswordSprayConfig:
    """Configurable thresholds for password-spray detection."""

    window_minutes: int = 10
    minimum_failed_attempts: int = 5
    minimum_distinct_accounts: int = 5
    success_correlation_minutes: int = 30
    duplicate_suppression_minutes: int = 15

    def __post_init__(self) -> None:
        numeric_values = {
            "window_minutes": self.window_minutes,
            "minimum_failed_attempts": self.minimum_failed_attempts,
            "minimum_distinct_accounts": self.minimum_distinct_accounts,
            "success_correlation_minutes": self.success_correlation_minutes,
            "duplicate_suppression_minutes": self.duplicate_suppression_minutes,
        }
        for name, value in numeric_values.items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")

        if self.minimum_distinct_accounts > self.minimum_failed_attempts:
            raise ValueError(
                "minimum_distinct_accounts cannot exceed minimum_failed_attempts"
            )


@dataclass(frozen=True, slots=True)
class IntegrityConfig:
    """Configuration for alert correlation around integrity changes."""

    correlation_window_minutes: int = 60

    def __post_init__(self) -> None:
        if self.correlation_window_minutes <= 0:
            raise ValueError("correlation_window_minutes must be greater than zero")


@dataclass(frozen=True, slots=True)
class PasswordSprayAlert:
    """Structured password-spray alert emitted by the detector."""

    alert_id: str
    generated_at_utc: datetime
    detection_start_utc: datetime
    detection_end_utc: datetime
    source_ip: str
    failed_attempts: int
    distinct_accounts: int
    targeted_accounts: tuple[str, ...]
    known_employee_accounts: tuple[str, ...]
    unknown_accounts: tuple[str, ...]
    privileged_accounts: tuple[str, ...]
    successful_logon_accounts: tuple[str, ...]
    locked_out_accounts: tuple[str, ...]
    severity: Severity
    confidence: Confidence
    title: str = "Possible password spray detected"
    technique_id: str = "T1110.003"
    technique_name: str = "Password Spraying"
    tactic: str = "Credential Access"
    recommended_actions: tuple[str, ...] = (
        "Investigate the source IP and affected identities",
        "Review successful authentication activity from the source IP",
        "Confirm MFA and conditional-access outcomes",
        "Reset credentials only where compromise is confirmed",
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable alert dictionary."""

        payload = asdict(self)
        payload["alert_type"] = "password_spray"
        payload["schema_version"] = "1.0"
        for field_name in (
            "generated_at_utc",
            "detection_start_utc",
            "detection_end_utc",
        ):
            payload[field_name] = _utc_text(getattr(self, field_name))
        payload["mitre_attack"] = {
            "technique_id": payload.pop("technique_id"),
            "technique": payload.pop("technique_name"),
            "tactic": payload.pop("tactic"),
        }
        return payload


@dataclass(frozen=True, slots=True)
class IntegrityBaseline:
    """Trusted manifest describing the expected allow-list state."""

    schema_version: str
    asset_id: str
    protected_path: str
    generated_at_utc: datetime
    sha256: str
    byte_length: int
    entries: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "asset_id": self.asset_id,
            "protected_path": self.protected_path,
            "generated_at_utc": _utc_text(self.generated_at_utc),
            "sha256": self.sha256,
            "byte_length": self.byte_length,
            "entry_count": len(self.entries),
            "entries": list(self.entries),
        }


@dataclass(frozen=True, slots=True)
class IntegrityAlert:
    """Structured alert describing a protected allow-list integrity failure."""

    alert_id: str
    generated_at_utc: datetime
    detected_at_utc: datetime
    asset_id: str
    protected_path: str
    change_type: IntegrityChangeType
    baseline_sha256: str
    observed_sha256: str | None
    baseline_entry_count: int
    observed_entry_count: int | None
    added_entries: tuple[str, ...]
    removed_entries: tuple[str, ...]
    replacement_suspected: bool
    severity: Severity
    confidence: Confidence = "high"
    title: str = "Protected allow list integrity changed"
    technique_id: str = "T1685"
    technique_name: str = "Disable or Modify Tools"
    tactic: str = "Defense Impairment"
    nist_control: str = "SI-7"
    recommended_actions: tuple[str, ...] = (
        "Preserve the current file and trusted baseline as evidence",
        "Confirm whether the change was authorised",
        "Review file-access telemetry and administrator activity",
        "Investigate authentication alerts near the change time",
        "Restore through an approved change process when required",
    )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["alert_type"] = "allow_list_integrity"
        payload["schema_version"] = "1.0"
        payload["generated_at_utc"] = _utc_text(self.generated_at_utc)
        payload["detected_at_utc"] = _utc_text(self.detected_at_utc)
        payload["mitre_attack"] = {
            "technique_id": payload.pop("technique_id"),
            "technique": payload.pop("technique_name"),
            "tactic": payload.pop("tactic"),
            "mapping_basis": (
                "Contextual mapping for unauthorised modification of a "
                "security-control configuration file"
            ),
        }
        payload["nist"] = {
            "control": payload.pop("nist_control"),
            "name": "Software, Firmware, and Information Integrity",
        }
        return payload


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    """One normalised investigation event."""

    event_id: str
    timestamp_utc: datetime
    category: TimelineCategory
    event_type: str
    severity: Severity
    summary: str
    source: str
    related_alert_ids: tuple[str, ...]
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["schema_version"] = "1.0"
        payload["timestamp_utc"] = _utc_text(self.timestamp_utc)
        return payload


SecurityAlert = PasswordSprayAlert | IntegrityAlert
