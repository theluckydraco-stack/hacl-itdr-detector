from __future__ import annotations

import json
from pathlib import Path

import pytest

from hacl_itdr.alerts import alerts_to_jsonl, write_alerts
from hacl_itdr.cli import main


def write_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    events = tmp_path / "events.jsonl"
    employees = tmp_path / "employees.csv"
    config = tmp_path / "detector.toml"

    events.write_text(
        "\n".join(
            [
                '{"timestamp_utc":"2026-07-25T15:00:00Z","event_id":4625,'
                '"source_ip":"203.0.113.25","account":"alice","host":"DC01"}',
                '{"timestamp_utc":"2026-07-25T15:01:00Z","event_id":4625,'
                '"source_ip":"203.0.113.25","account":"bob","host":"DC01"}',
                '{"timestamp_utc":"2026-07-25T15:02:00Z","event_id":4625,'
                '"source_ip":"203.0.113.25","account":"carol","host":"DC01"}',
                '{"timestamp_utc":"2026-07-25T15:03:00Z","event_id":4625,'
                '"source_ip":"203.0.113.25","account":"dave","host":"DC01"}',
                '{"timestamp_utc":"2026-07-25T15:04:00Z","event_id":4625,'
                '"source_ip":"203.0.113.25","account":"erin","host":"DC01"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    employees.write_text(
        "username,employee_id,department,status,privileged\n"
        "alice,EMP-1,Security,active,false\n"
        "bob,EMP-2,Finance,active,false\n"
        "carol,EMP-3,IT,active,true\n"
        "dave,EMP-4,HR,active,false\n"
        "erin,EMP-5,Ops,active,false\n",
        encoding="utf-8",
    )
    config.write_text(
        "[password_spray]\n"
        "window_minutes = 10\n"
        "minimum_failed_attempts = 5\n"
        "minimum_distinct_accounts = 5\n"
        "success_correlation_minutes = 30\n"
        "duplicate_suppression_minutes = 15\n",
        encoding="utf-8",
    )
    return events, employees, config


def test_alerts_to_jsonl_empty() -> None:
    assert alerts_to_jsonl([]) == ""


def test_write_alerts_creates_parent_directory(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "alerts.jsonl"

    write_alerts(output, [])

    assert output.read_text(encoding="utf-8") == ""


def test_cli_writes_alert_file(tmp_path: Path) -> None:
    events, employees, config = write_inputs(tmp_path)
    output = tmp_path / "output" / "alerts.jsonl"

    exit_code = main(
        [
            "--events",
            str(events),
            "--employees",
            str(employees),
            "--config",
            str(config),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["source_ip"] == "203.0.113.25"
    assert payload["mitre_attack"]["technique_id"] == "T1110.003"


def test_cli_prints_alert_to_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events, employees, config = write_inputs(tmp_path)

    exit_code = main(
        [
            "--events",
            str(events),
            "--employees",
            str(employees),
            "--config",
            str(config),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"source_ip": "203.0.113.25"' in captured.out


def test_cli_returns_two_for_parse_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events, employees, config = write_inputs(tmp_path)
    events.write_text("not-json\n", encoding="utf-8")

    exit_code = main(
        [
            "--events",
            str(events),
            "--employees",
            str(employees),
            "--config",
            str(config),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "invalid JSON" in captured.err
