"""Structured alert output helpers."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from .models import PasswordSprayAlert


def alerts_to_jsonl(alerts: Iterable[PasswordSprayAlert]) -> str:
    """Serialise alerts as deterministic JSON Lines output."""

    lines = [json.dumps(alert.to_dict(), sort_keys=True) for alert in alerts]
    return "\n".join(lines) + ("\n" if lines else "")


def write_alerts(path: Path, alerts: Iterable[PasswordSprayAlert]) -> None:
    """Write JSON Lines alerts, creating parent directories when required."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(alerts_to_jsonl(alerts), encoding="utf-8")
