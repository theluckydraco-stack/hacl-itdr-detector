# hACL ITDR Detector

[![CI](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/ci.yml)
[![CodeQL](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/codeql.yml/badge.svg)](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/codeql.yml)

A Python identity-threat detection engineering project built as a separate extension of the access-governance ideas demonstrated by hACL.

The first milestone detects possible password spraying, correlates targeted accounts with a synthetic employee directory, checks for successful logons and account lockouts, and emits structured ATT&CK-mapped JSONL alerts.

## Project boundary

This repository is not the original hACL access-list manager. It does not modify hACL history, silently repair access lists, authenticate users, or claim to be a production SIEM. It is a local detection lab using synthetic data.

## Detection implemented

**MITRE ATT&CK T1110.003 — Password Spraying**

The detector identifies failed Windows logons (`4625`) from one source IP against multiple distinct accounts inside a configurable sliding time window. It then correlates:

- successful logons (`4624`) from the same source to targeted accounts;
- account lockouts (`4740`) affecting targeted accounts;
- known, unknown, and privileged identities from a synthetic directory.

## Engineering evidence

| Area | Evidence |
|---|---|
| Detection | Sliding-window source-IP and distinct-account correlation |
| Identity | Employee and privileged-account enrichment |
| Investigation | Success-after-spray and lockout correlation |
| Output | Structured JSON Lines alerts with ATT&CK metadata |
| Quality | Python 3.12/3.13, Ruff, mypy, pytest, branch coverage |
| Security | Strict parsers, synthetic-data policy, CodeQL, Dependabot |
| Portability | Sigma correlation rule and Microsoft Sentinel KQL draft |

## Repository layout

```text
config/                 Detector thresholds
data/                   Synthetic events and employee records
detections/kql/         Microsoft Sentinel KQL draft
detections/sigma/       Sigma base and correlation rules
docs/                   Architecture, logic, and threat model
reports/                Sample incident report
src/hacl_itdr/           Python detector package
tests/                   Positive, negative, boundary, and CLI tests
```

## Run the demonstration

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

hacl-itdr \
  --events data/synthetic_auth_events.jsonl \
  --employees data/employees.csv \
  --config config/detector.toml \
  --output output/alerts.jsonl

cat output/alerts.jsonl
```

## Configuration

```toml
[password_spray]
window_minutes = 10
minimum_failed_attempts = 5
minimum_distinct_accounts = 5
success_correlation_minutes = 30
duplicate_suppression_minutes = 15
```

These are demonstration defaults, not universal detection standards. Production thresholds depend on identity architecture, authentication volume, shared infrastructure, lockout policies, and acceptable false-positive rates.

## Alert content

Alerts include the source IP and detection window; failure and distinct-account counts; targeted, known, unknown, and privileged identities; correlated successful logons and account lockouts; severity, confidence, ATT&CK metadata, and recommended actions.

## Quality checks

```bash
ruff check src tests
mypy src tests
python -m pytest
```

The test configuration enforces at least 90% statement and branch coverage.

## Detection-as-code notes

The included Sigma file uses a base Windows failed-logon rule plus a value-count correlation grouped by source IP. The KQL draft uses `summarize`, `count()`, and `dcount()` to aggregate failures and distinct accounts. Field names and backend support must be adapted to the target SIEM schema.

## Roadmap

1. Password-spray detection and identity correlation — current milestone
2. hACL allow-list integrity monitoring
3. Alert-schema versioning and incident timeline generation
4. Sigma and KQL validation against representative schemas
5. Investigation report automation and additional ITDR detections

## References

- MITRE ATT&CK T1110.003: https://attack.mitre.org/techniques/T1110/003/
- Microsoft Windows event 4625: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
- Microsoft Windows audit logon events: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon
- Microsoft Windows event 4740: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740
- Sigma correlations: https://sigmahq.io/docs/meta/correlations.html
- KQL summarize: https://learn.microsoft.com/en-us/kusto/query/summarize-operator
