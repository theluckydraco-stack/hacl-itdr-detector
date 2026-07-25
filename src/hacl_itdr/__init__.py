"""hACL ITDR detector package."""

from .inactive_account import detect_inactive_account_logons
from .integrity import create_baseline, inspect_allow_list, load_baseline
from .models import (
    AuthEvent,
    Employee,
    FileAccessEvent,
    InactiveAccountAlert,
    IntegrityAlert,
    IntegrityBaseline,
    IntegrityConfig,
    PasswordSprayAlert,
    PasswordSprayConfig,
    TimelineEvent,
)
from .password_spray import detect_password_sprays
from .report import build_investigation_report, collect_evidence_artifacts
from .timeline import build_investigation_timeline
from .windows_schema import load_windows_security_events

__all__ = [
    "AuthEvent",
    "Employee",
    "FileAccessEvent",
    "InactiveAccountAlert",
    "IntegrityAlert",
    "IntegrityBaseline",
    "IntegrityConfig",
    "PasswordSprayAlert",
    "PasswordSprayConfig",
    "TimelineEvent",
    "build_investigation_report",
    "build_investigation_timeline",
    "collect_evidence_artifacts",
    "create_baseline",
    "detect_inactive_account_logons",
    "detect_password_sprays",
    "inspect_allow_list",
    "load_baseline",
    "load_windows_security_events",
]
