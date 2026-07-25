"""Typed models for authentication events and detector output."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Literal

Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


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
        for field_name in (
            "generated_at_utc",
            "detection_start_utc",
            "detection_end_utc",
        ):
            payload[field_name] = getattr(self, field_name).isoformat().replace(
                "+00:00", "Z"
            )
        payload["mitre_attack"] = {
            "technique_id": payload.pop("technique_id"),
            "technique": payload.pop("technique_name"),
            "tactic": payload.pop("tactic"),
        }
        return payload
