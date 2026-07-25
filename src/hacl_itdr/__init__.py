"""hACL ITDR detector package."""

from .integrity import create_baseline, inspect_allow_list, load_baseline
from .models import (
    AuthEvent,
    Employee,
    IntegrityAlert,
    IntegrityBaseline,
    IntegrityConfig,
    PasswordSprayAlert,
    PasswordSprayConfig,
    TimelineEvent,
)
from .password_spray import detect_password_sprays
from .timeline import build_investigation_timeline

__all__ = [
    "AuthEvent",
    "Employee",
    "IntegrityAlert",
    "IntegrityBaseline",
    "IntegrityConfig",
    "PasswordSprayAlert",
    "PasswordSprayConfig",
    "TimelineEvent",
    "build_investigation_timeline",
    "create_baseline",
    "detect_password_sprays",
    "inspect_allow_list",
    "load_baseline",
]
