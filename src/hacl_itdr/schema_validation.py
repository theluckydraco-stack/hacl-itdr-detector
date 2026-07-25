"""Static validation for detection content against representative schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class DetectionValidationError(ValueError):
    """Raised when schema or contract files cannot be parsed."""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DetectionValidationError(f"unable to parse validation input: {path}") from exc


def _object(value: Any, *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DetectionValidationError(f"{context} must be a JSON object")
    return value


def _string_list(value: Any, *, context: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise DetectionValidationError(f"{context} must be a list of strings")
    return list(value)


def validate_detection_content(root: Path) -> list[str]:
    """Return contract violations for Sigma and KQL detection files."""

    schemas = root / "schemas"
    contracts = _object(
        _load_json(schemas / "detection_contracts.json"),
        context="detection contracts",
    )
    windows_raw = _object(
        _load_json(schemas / "windows_security_event_fields.json"),
        context="Windows event fields",
    )
    sentinel_columns = set(
        _string_list(
            _load_json(schemas / "sentinel_securityevent_columns.json"),
            context="Sentinel columns",
        )
    )
    windows_fields = {
        event_id: set(_string_list(fields, context=f"Windows event {event_id}"))
        for event_id, fields in windows_raw.items()
    }

    errors: list[str] = []
    for relative_path, raw_contract in sorted(contracts.items()):
        contract = _object(raw_contract, context=f"contract {relative_path}")
        path = root / relative_path
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            errors.append(f"{relative_path}: file is missing or unreadable")
            continue

        kind = contract.get("kind")
        required_tokens = _string_list(
            contract.get("required_tokens", []),
            context=f"{relative_path}: required_tokens",
        )
        for token in required_tokens:
            if token not in content:
                errors.append(f"{relative_path}: required token missing: {token}")

        if kind == "sigma":
            if "title:" not in content or "logsource:" not in content:
                errors.append(f"{relative_path}: incomplete Sigma metadata")
            raw_event_ids = contract.get("event_ids", [])
            if not isinstance(raw_event_ids, list) or not all(
                isinstance(event_id, int) for event_id in raw_event_ids
            ):
                raise DetectionValidationError(
                    f"{relative_path}: event_ids must be a list of integers"
                )
            available_fields: set[str] = set()
            for event_id in raw_event_ids:
                fields = windows_fields.get(str(event_id))
                if fields is None:
                    errors.append(
                        f"{relative_path}: event {event_id} has no schema contract"
                    )
                    continue
                available_fields.update(fields)
            for field in _string_list(
                contract.get("event_fields", []),
                context=f"{relative_path}: event_fields",
            ):
                if field not in available_fields:
                    errors.append(
                        f"{relative_path}: field {field} is absent from event schema"
                    )
                if field not in content:
                    errors.append(
                        f"{relative_path}: field {field} is not referenced by the rule"
                    )
        elif kind == "kql":
            table = contract.get("table")
            if not isinstance(table, str) or not table:
                raise DetectionValidationError(
                    f"{relative_path}: table must be a non-empty string"
                )
            if table not in content:
                errors.append(f"{relative_path}: table {table} is not referenced")
            for column in _string_list(
                contract.get("columns", []),
                context=f"{relative_path}: columns",
            ):
                if column not in sentinel_columns:
                    errors.append(
                        f"{relative_path}: column {column} is absent from SecurityEvent"
                    )
                if column not in content:
                    errors.append(
                        f"{relative_path}: column {column} is not referenced"
                    )
        else:
            raise DetectionValidationError(
                f"{relative_path}: unsupported contract kind {kind}"
            )

    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hacl-itdr-validate-detections",
        description="Validate Sigma and KQL content against repository schemas.",
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        errors = validate_detection_content(args.root)
    except DetectionValidationError as exc:
        print(f"error: {exc}")
        return 2
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1
    print("Detection content validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
