"""Trusted-baseline creation and allow-list integrity monitoring."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import IntegrityAlert, IntegrityBaseline, IntegrityChangeType, Severity

BASELINE_SCHEMA_VERSION = "1.0"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(ValueError):
    """Raised when integrity input or baseline data cannot be trusted."""


def _utc(value: datetime | None) -> datetime:
    return (value or datetime.now(UTC)).astimezone(UTC)


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest for raw file bytes."""

    return hashlib.sha256(data).hexdigest()


def parse_allow_list_bytes(data: bytes, *, context: str) -> tuple[str, ...]:
    """Parse a strict, duplicate-free IPv4 allow list."""

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrityError(f"{context}: allow list must be UTF-8") from exc

    entries: list[str] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        value = raw_line.strip()
        if not value:
            continue
        try:
            canonical = str(ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError as exc:
            raise IntegrityError(
                f"{context}: line {line_number}: invalid IPv4 address"
            ) from exc
        if canonical in seen:
            raise IntegrityError(
                f"{context}: line {line_number}: duplicate IPv4 address {canonical}"
            )
        seen.add(canonical)
        entries.append(canonical)

    return tuple(sorted(entries))


def _read_bytes(path: Path, *, purpose: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise IntegrityError(f"unable to read {purpose}: {path}") from exc


def create_baseline(
    allow_list_path: Path,
    *,
    asset_id: str,
    generated_at: datetime | None = None,
) -> IntegrityBaseline:
    """Create an in-memory trusted baseline from the current allow list."""

    if not asset_id.strip():
        raise IntegrityError("asset_id must be a non-empty string")

    data = _read_bytes(allow_list_path, purpose="allow list")
    entries = parse_allow_list_bytes(data, context=str(allow_list_path))
    return IntegrityBaseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        asset_id=asset_id.strip(),
        protected_path=str(allow_list_path),
        generated_at_utc=_utc(generated_at),
        sha256=sha256_bytes(data),
        byte_length=len(data),
        entries=entries,
    )


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise IntegrityError(f"unable to write baseline manifest: {path}") from exc


def write_baseline(path: Path, baseline: IntegrityBaseline) -> None:
    """Write a baseline manifest using atomic replacement."""

    content = json.dumps(baseline.to_dict(), indent=2, sort_keys=True) + "\n"
    _atomic_write(path, content)


def _parse_manifest_timestamp(value: object, *, path: Path) -> datetime:
    if not isinstance(value, str):
        raise IntegrityError(f"{path}: generated_at_utc must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntegrityError(f"{path}: invalid generated_at_utc") from exc
    if parsed.tzinfo is None:
        raise IntegrityError(f"{path}: generated_at_utc must include a timezone")
    return parsed.astimezone(UTC)


def _require_manifest_string(
    payload: dict[str, Any], field_name: str, *, path: Path
) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise IntegrityError(f"{path}: {field_name} must be a non-empty string")
    return value.strip()


def load_baseline(path: Path) -> IntegrityBaseline:
    """Load and strictly validate a trusted baseline manifest."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"unable to parse baseline manifest: {path}") from exc
    if not isinstance(payload, dict):
        raise IntegrityError(f"{path}: baseline manifest must be a JSON object")

    schema_version = _require_manifest_string(payload, "schema_version", path=path)
    if schema_version != BASELINE_SCHEMA_VERSION:
        raise IntegrityError(
            f"{path}: unsupported baseline schema_version {schema_version}"
        )

    digest = _require_manifest_string(payload, "sha256", path=path).casefold()
    if _SHA256_PATTERN.fullmatch(digest) is None:
        raise IntegrityError(f"{path}: sha256 must be a 64-character hex digest")

    byte_length = payload.get("byte_length")
    if isinstance(byte_length, bool) or not isinstance(byte_length, int):
        raise IntegrityError(f"{path}: byte_length must be an integer")
    if byte_length < 0:
        raise IntegrityError(f"{path}: byte_length cannot be negative")

    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list) or not all(
        isinstance(entry, str) for entry in raw_entries
    ):
        raise IntegrityError(f"{path}: entries must be a list of strings")
    entries_text = ("\n".join(raw_entries) + ("\n" if raw_entries else "")).encode()
    entries = parse_allow_list_bytes(entries_text, context=f"{path}: entries")

    entry_count = payload.get("entry_count")
    if isinstance(entry_count, bool) or not isinstance(entry_count, int):
        raise IntegrityError(f"{path}: entry_count must be an integer")
    if entry_count != len(entries):
        raise IntegrityError(f"{path}: entry_count does not match entries")

    return IntegrityBaseline(
        schema_version=schema_version,
        asset_id=_require_manifest_string(payload, "asset_id", path=path),
        protected_path=_require_manifest_string(payload, "protected_path", path=path),
        generated_at_utc=_parse_manifest_timestamp(
            payload.get("generated_at_utc"), path=path
        ),
        sha256=digest,
        byte_length=byte_length,
        entries=entries,
    )


def _classify_change(
    *,
    added: tuple[str, ...],
    removed: tuple[str, ...],
) -> IntegrityChangeType:
    if added and removed:
        return "entries_changed"
    if added:
        return "entries_added"
    if removed:
        return "entries_removed"
    return "content_modified"


def _severity_for_change(
    change_type: IntegrityChangeType,
    *,
    replacement_suspected: bool,
) -> Severity:
    if change_type in {"missing", "invalid"} or replacement_suspected:
        return "critical"
    if change_type in {"entries_added", "entries_removed", "entries_changed"}:
        return "high"
    return "medium"


def inspect_allow_list(
    allow_list_path: Path,
    baseline: IntegrityBaseline,
    *,
    detected_at: datetime | None = None,
) -> IntegrityAlert | None:
    """Compare an observed allow list with a trusted baseline."""

    now = _utc(detected_at)
    try:
        data = allow_list_path.read_bytes()
    except FileNotFoundError:
        return IntegrityAlert(
            alert_id=str(uuid.uuid4()),
            generated_at_utc=now,
            detected_at_utc=now,
            asset_id=baseline.asset_id,
            protected_path=str(allow_list_path),
            change_type="missing",
            baseline_sha256=baseline.sha256,
            observed_sha256=None,
            baseline_entry_count=len(baseline.entries),
            observed_entry_count=None,
            added_entries=(),
            removed_entries=baseline.entries,
            replacement_suspected=False,
            severity="critical",
        )
    except OSError as exc:
        raise IntegrityError(f"unable to read allow list: {allow_list_path}") from exc

    observed_sha256 = sha256_bytes(data)
    if observed_sha256 == baseline.sha256:
        return None

    try:
        observed_entries = parse_allow_list_bytes(data, context=str(allow_list_path))
    except IntegrityError:
        return IntegrityAlert(
            alert_id=str(uuid.uuid4()),
            generated_at_utc=now,
            detected_at_utc=now,
            asset_id=baseline.asset_id,
            protected_path=str(allow_list_path),
            change_type="invalid",
            baseline_sha256=baseline.sha256,
            observed_sha256=observed_sha256,
            baseline_entry_count=len(baseline.entries),
            observed_entry_count=None,
            added_entries=(),
            removed_entries=(),
            replacement_suspected=False,
            severity="critical",
        )

    baseline_set = set(baseline.entries)
    observed_set = set(observed_entries)
    added = tuple(sorted(observed_set - baseline_set))
    removed = tuple(sorted(baseline_set - observed_set))
    replacement_suspected = bool(
        baseline_set and observed_set and baseline_set.isdisjoint(observed_set)
    )
    change_type = _classify_change(added=added, removed=removed)
    return IntegrityAlert(
        alert_id=str(uuid.uuid4()),
        generated_at_utc=now,
        detected_at_utc=now,
        asset_id=baseline.asset_id,
        protected_path=str(allow_list_path),
        change_type=change_type,
        baseline_sha256=baseline.sha256,
        observed_sha256=observed_sha256,
        baseline_entry_count=len(baseline.entries),
        observed_entry_count=len(observed_entries),
        added_entries=added,
        removed_entries=removed,
        replacement_suspected=replacement_suspected,
        severity=_severity_for_change(
            change_type, replacement_suspected=replacement_suspected
        ),
    )
