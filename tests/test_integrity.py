from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hacl_itdr.baseline_cli import main as baseline_main
from hacl_itdr.integrity import (
    IntegrityError,
    create_baseline,
    inspect_allow_list,
    load_baseline,
    parse_allow_list_bytes,
    sha256_bytes,
    write_baseline,
)
from hacl_itdr.models import IntegrityBaseline

NOW = datetime(2026, 7, 25, 17, 30, tzinfo=UTC)


def write_allow_list(path: Path, *entries: str) -> None:
    path.write_text("\n".join(entries) + "\n", encoding="utf-8")


def baseline_for(tmp_path: Path) -> tuple[Path, IntegrityBaseline]:
    allow_list = tmp_path / "allow_list.txt"
    write_allow_list(allow_list, "10.0.0.1", "10.0.0.2", "192.0.2.10")
    baseline = create_baseline(
        allow_list, asset_id="hacl-primary-allow-list", generated_at=NOW
    )
    return allow_list, baseline


def test_sha256_bytes_is_deterministic() -> None:
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_parse_allow_list_normalises_and_sorts() -> None:
    assert parse_allow_list_bytes(
        b"192.0.2.10\n10.0.0.1\n", context="test"
    ) == ("10.0.0.1", "192.0.2.10")


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"999.0.0.1\n", "invalid IPv4"),
        (b"2001:db8::1\n", "invalid IPv4"),
        (b"10.0.0.1\n10.0.0.1\n", "duplicate IPv4"),
        (b"\xff", "must be UTF-8"),
    ],
)
def test_parse_allow_list_rejects_untrusted_content(
    payload: bytes, message: str
) -> None:
    with pytest.raises(IntegrityError, match=message):
        parse_allow_list_bytes(payload, context="test")


def test_create_and_load_baseline_round_trip(tmp_path: Path) -> None:
    allow_list, baseline = baseline_for(tmp_path)
    manifest = tmp_path / "baseline.json"

    write_baseline(manifest, baseline)
    loaded = load_baseline(manifest)

    assert loaded == baseline
    assert loaded.sha256 == sha256_bytes(allow_list.read_bytes())
    assert json.loads(manifest.read_text())["entry_count"] == 3


def test_create_baseline_rejects_empty_asset_id(tmp_path: Path) -> None:
    allow_list = tmp_path / "allow.txt"
    write_allow_list(allow_list, "10.0.0.1")

    with pytest.raises(IntegrityError, match="asset_id"):
        create_baseline(allow_list, asset_id=" ")


def test_load_baseline_rejects_invalid_schema(tmp_path: Path) -> None:
    manifest = tmp_path / "baseline.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "9.0",
                "asset_id": "x",
                "protected_path": "allow.txt",
                "generated_at_utc": "2026-07-25T17:30:00Z",
                "sha256": "a" * 64,
                "byte_length": 1,
                "entry_count": 1,
                "entries": ["10.0.0.1"],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(IntegrityError, match="unsupported baseline"):
        load_baseline(manifest)


def test_load_baseline_rejects_entry_count_mismatch(tmp_path: Path) -> None:
    _, baseline = baseline_for(tmp_path)
    manifest = tmp_path / "baseline.json"
    payload = baseline.to_dict()
    payload["entry_count"] = 99
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(IntegrityError, match="entry_count"):
        load_baseline(manifest)


def test_unchanged_allow_list_produces_no_alert(tmp_path: Path) -> None:
    allow_list, baseline = baseline_for(tmp_path)

    assert inspect_allow_list(allow_list, baseline, detected_at=NOW) is None


def test_added_entry_produces_high_alert(tmp_path: Path) -> None:
    allow_list, baseline = baseline_for(tmp_path)
    write_allow_list(
        allow_list, "10.0.0.1", "10.0.0.2", "192.0.2.10", "203.0.113.20"
    )

    alert = inspect_allow_list(allow_list, baseline, detected_at=NOW)

    assert alert is not None
    assert alert.change_type == "entries_added"
    assert alert.added_entries == ("203.0.113.20",)
    assert alert.removed_entries == ()
    assert alert.severity == "high"


def test_removed_entry_produces_high_alert(tmp_path: Path) -> None:
    allow_list, baseline = baseline_for(tmp_path)
    write_allow_list(allow_list, "10.0.0.1", "192.0.2.10")

    alert = inspect_allow_list(allow_list, baseline, detected_at=NOW)

    assert alert is not None
    assert alert.change_type == "entries_removed"
    assert alert.removed_entries == ("10.0.0.2",)


def test_changed_entries_explain_before_and_after_diff(tmp_path: Path) -> None:
    allow_list, baseline = baseline_for(tmp_path)
    write_allow_list(allow_list, "10.0.0.1", "198.51.100.8")

    alert = inspect_allow_list(allow_list, baseline, detected_at=NOW)

    assert alert is not None
    assert alert.change_type == "entries_changed"
    assert alert.added_entries == ("198.51.100.8",)
    assert alert.removed_entries == ("10.0.0.2", "192.0.2.10")


def test_reordered_content_detects_raw_byte_change(tmp_path: Path) -> None:
    allow_list, baseline = baseline_for(tmp_path)
    write_allow_list(allow_list, "192.0.2.10", "10.0.0.2", "10.0.0.1")

    alert = inspect_allow_list(allow_list, baseline, detected_at=NOW)

    assert alert is not None
    assert alert.change_type == "content_modified"
    assert alert.added_entries == ()
    assert alert.removed_entries == ()
    assert alert.severity == "medium"


def test_disjoint_file_is_flagged_as_suspected_replacement(tmp_path: Path) -> None:
    allow_list, baseline = baseline_for(tmp_path)
    write_allow_list(allow_list, "198.51.100.1", "203.0.113.2")

    alert = inspect_allow_list(allow_list, baseline, detected_at=NOW)

    assert alert is not None
    assert alert.replacement_suspected is True
    assert alert.severity == "critical"


def test_missing_file_produces_critical_alert(tmp_path: Path) -> None:
    allow_list, baseline = baseline_for(tmp_path)
    allow_list.unlink()

    alert = inspect_allow_list(allow_list, baseline, detected_at=NOW)

    assert alert is not None
    assert alert.change_type == "missing"
    assert alert.observed_sha256 is None
    assert alert.removed_entries == baseline.entries
    assert alert.severity == "critical"


def test_invalid_observed_file_produces_critical_alert(tmp_path: Path) -> None:
    allow_list, baseline = baseline_for(tmp_path)
    allow_list.write_text("not-an-ip\n", encoding="utf-8")

    alert = inspect_allow_list(allow_list, baseline, detected_at=NOW)

    assert alert is not None
    assert alert.change_type == "invalid"
    assert alert.observed_entry_count is None
    assert alert.severity == "critical"


def test_integrity_alert_serialisation_has_mappings(tmp_path: Path) -> None:
    allow_list, baseline = baseline_for(tmp_path)
    write_allow_list(allow_list, "10.0.0.1")
    alert = inspect_allow_list(allow_list, baseline, detected_at=NOW)

    assert alert is not None
    payload = alert.to_dict()
    assert payload["alert_type"] == "allow_list_integrity"
    assert payload["mitre_attack"]["technique_id"] == "T1685"
    assert payload["nist"]["control"] == "SI-7"


def test_baseline_cli_writes_manifest(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    allow_list = tmp_path / "allow.txt"
    manifest = tmp_path / "nested" / "baseline.json"
    write_allow_list(allow_list, "10.0.0.1")

    exit_code = baseline_main(
        [
            "--allow-list",
            str(allow_list),
            "--manifest",
            str(manifest),
            "--asset-id",
            "primary",
        ]
    )

    assert exit_code == 0
    assert load_baseline(manifest).asset_id == "primary"
    assert '"asset_id": "primary"' in capsys.readouterr().out


def test_baseline_cli_returns_two_for_invalid_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    allow_list = tmp_path / "allow.txt"
    allow_list.write_text("bad\n", encoding="utf-8")

    exit_code = baseline_main(
        [
            "--allow-list",
            str(allow_list),
            "--manifest",
            str(tmp_path / "baseline.json"),
            "--asset-id",
            "primary",
        ]
    )

    assert exit_code == 2
    assert "invalid IPv4" in capsys.readouterr().err
