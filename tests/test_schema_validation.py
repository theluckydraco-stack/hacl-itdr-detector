from __future__ import annotations

import json
from pathlib import Path

import pytest

from hacl_itdr.schema_validation import (
    DetectionValidationError,
    main,
    validate_detection_content,
)

ROOT = Path(__file__).resolve().parents[1]


def write_validation_root(
    root: Path,
    *,
    contract: dict[str, object],
    detection_content: str = "SecurityEvent\n| where EventID == 4625\n",
) -> None:
    schemas = root / "schemas"
    detection = root / "detections" / "sample.kql"
    schemas.mkdir(parents=True)
    detection.parent.mkdir(parents=True)
    (schemas / "detection_contracts.json").write_text(
        json.dumps({"detections/sample.kql": contract}), encoding="utf-8"
    )
    (schemas / "windows_security_event_fields.json").write_text(
        json.dumps({"4625": ["EventID", "IpAddress", "TargetUserName"]}),
        encoding="utf-8",
    )
    (schemas / "sentinel_securityevent_columns.json").write_text(
        json.dumps(["EventID", "TimeGenerated"]), encoding="utf-8"
    )
    detection.write_text(detection_content, encoding="utf-8")


def test_repository_detection_contracts_pass() -> None:
    assert validate_detection_content(ROOT) == []


def test_reports_missing_tokens_and_unknown_columns(tmp_path: Path) -> None:
    write_validation_root(
        tmp_path,
        contract={
            "kind": "kql",
            "table": "SecurityEvent",
            "columns": ["EventID", "UnknownColumn"],
            "required_tokens": ["summarize"],
        },
    )

    errors = validate_detection_content(tmp_path)

    assert any("required token missing" in error for error in errors)
    assert any("absent from SecurityEvent" in error for error in errors)
    assert any("not referenced" in error for error in errors)


def test_reports_missing_detection_file(tmp_path: Path) -> None:
    write_validation_root(
        tmp_path,
        contract={
            "kind": "kql",
            "table": "SecurityEvent",
            "columns": ["EventID"],
            "required_tokens": [],
        },
    )
    (tmp_path / "detections" / "sample.kql").unlink()

    assert validate_detection_content(tmp_path) == [
        "detections/sample.kql: file is missing or unreadable"
    ]


def test_sigma_contract_checks_event_schema(tmp_path: Path) -> None:
    write_validation_root(
        tmp_path,
        contract={
            "kind": "sigma",
            "event_ids": [4625],
            "event_fields": ["TargetUserName", "MissingField"],
            "required_tokens": ["logsource:"],
        },
        detection_content=(
            "title: Sample\nlogsource:\n  product: windows\n"
            "detection:\n  selection:\n    TargetUserName: alice\n"
            "  condition: selection\n"
        ),
    )

    errors = validate_detection_content(tmp_path)

    assert any("MissingField is absent" in error for error in errors)
    assert any("MissingField is not referenced" in error for error in errors)


def test_rejects_malformed_or_unsupported_contracts(tmp_path: Path) -> None:
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    (schemas / "detection_contracts.json").write_text("[]", encoding="utf-8")
    (schemas / "windows_security_event_fields.json").write_text(
        "{}", encoding="utf-8"
    )
    (schemas / "sentinel_securityevent_columns.json").write_text(
        "[]", encoding="utf-8"
    )

    with pytest.raises(DetectionValidationError, match="JSON object"):
        validate_detection_content(tmp_path)

    write_validation_root(
        tmp_path / "unsupported",
        contract={"kind": "other", "required_tokens": []},
    )
    with pytest.raises(DetectionValidationError, match="unsupported contract kind"):
        validate_detection_content(tmp_path / "unsupported")


def test_validation_cli_success_and_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--root", str(ROOT)]) == 0
    assert "validation passed" in capsys.readouterr().out

    write_validation_root(
        tmp_path,
        contract={
            "kind": "kql",
            "table": "SecurityEvent",
            "columns": ["EventID"],
            "required_tokens": ["summarize"],
        },
    )
    assert main(["--root", str(tmp_path)]) == 1
    assert "required token missing" in capsys.readouterr().out
