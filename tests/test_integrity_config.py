from __future__ import annotations

from pathlib import Path

import pytest

from hacl_itdr.models import IntegrityConfig
from hacl_itdr.parsers import ParseError, load_integrity_config


def test_load_integrity_config_uses_configured_window(tmp_path: Path) -> None:
    path = tmp_path / "detector.toml"
    path.write_text(
        "[password_spray]\n"
        "window_minutes = 10\n"
        "minimum_failed_attempts = 5\n"
        "minimum_distinct_accounts = 5\n"
        "success_correlation_minutes = 30\n"
        "duplicate_suppression_minutes = 15\n"
        "[integrity]\n"
        "correlation_window_minutes = 90\n",
        encoding="utf-8",
    )

    assert load_integrity_config(path) == IntegrityConfig(90)


def test_load_integrity_config_defaults_when_section_is_absent(tmp_path: Path) -> None:
    path = tmp_path / "detector.toml"
    path.write_text("[password_spray]\nwindow_minutes = 10\n", encoding="utf-8")

    assert load_integrity_config(path) == IntegrityConfig()


def test_load_integrity_config_rejects_non_table(tmp_path: Path) -> None:
    path = tmp_path / "detector.toml"
    path.write_text('integrity = "invalid"\n', encoding="utf-8")

    with pytest.raises(ParseError, match=r"\[integrity\] must be a table"):
        load_integrity_config(path)


def test_load_integrity_config_rejects_invalid_window(tmp_path: Path) -> None:
    path = tmp_path / "detector.toml"
    path.write_text(
        "[integrity]\ncorrelation_window_minutes = 0\n", encoding="utf-8"
    )

    with pytest.raises(ParseError, match="invalid integrity configuration"):
        load_integrity_config(path)
