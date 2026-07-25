"""CLI for creating a trusted allow-list baseline manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .integrity import IntegrityError, create_baseline, write_baseline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hacl-itdr-baseline",
        description="Create a trusted SHA-256 baseline for an IPv4 allow list.",
    )
    parser.add_argument("--allow-list", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--asset-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        baseline = create_baseline(args.allow_list, asset_id=args.asset_id)
        write_baseline(args.manifest, baseline)
    except IntegrityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    sys.stdout.write(json.dumps(baseline.to_dict(), sort_keys=True) + "\n")
    return 0
