# Architecture

The detector is a local, deterministic pipeline using only synthetic data.

## Authentication pipeline

Authentication JSONL is parsed into normalised events, enriched with the synthetic employee directory, evaluated by the sliding-window password-spray detector, and correlated with successful logons and account lockouts.

## Integrity pipeline

An approved IPv4 allow list is converted into a trusted baseline manifest containing a raw-file SHA-256 digest and canonical entries. The observed allow list is compared with that manifest to produce an integrity alert when bytes or access-control entries change.

The baseline records both raw bytes and canonical IPv4 entries. This separates two questions:

1. Did any byte change? SHA-256 detects reordering, whitespace, encoding, or content changes.
2. What access decision changed? Canonical set comparison explains added and removed addresses.

Baseline manifests are written by atomic replacement. The observed allow list is never modified or repaired by the detector.

## Investigation pipeline

Authentication events, password-spray alerts, and integrity alerts are converted into a UTC-ordered timeline. Timeline events use deterministic UUIDv5 identifiers derived from source evidence. Correlation is controlled by `correlation_window_minutes`.

## Boundaries

- The detector does not authenticate users or modify accounts.
- The detector does not change or restore the original hACL allow list.
- The baseline manifest is trusted input and must be protected externally.
- Alerts are investigative leads, not proof of compromise.
- Thresholds and correlation windows are demonstration defaults.
- No runtime network access is required.
