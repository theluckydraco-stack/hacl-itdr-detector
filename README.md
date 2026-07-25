# hACL ITDR Detector

[![CI](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/ci.yml)
[![CodeQL](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/codeql.yml/badge.svg)](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/codeql.yml)

A Python identity-threat detection engineering project built as a separate extension of the access-governance ideas demonstrated by hACL.

The project now combines password-spray detection, identity correlation, trusted-baseline allow-list monitoring, and investigation-timeline generation. All included evidence is synthetic.

## Project boundary

This repository is not the original hACL access-list manager. It does not modify hACL history, silently repair access lists, authenticate users, or claim to be a production SIEM. Integrity alerts identify a state change; they do not by themselves prove malicious intent.

## Detections implemented

### MITRE ATT&CK T1110.003 — Password Spraying

The detector identifies failed Windows logons (`4625`) from one source IP against multiple distinct accounts inside a configurable sliding time window. It correlates:

- successful logons (`4624`) from the same source to targeted accounts;
- account lockouts (`4740`) affecting targeted accounts;
- known, unknown, and privileged identities from a synthetic directory.

### Allow-list integrity monitoring

The detector creates and loads a trusted baseline manifest containing:

- a raw-file SHA-256 digest;
- canonical IPv4 entries;
- byte length, asset ID, protected path, schema version, and generation time.

It then detects:

- added or removed allow-list entries;
- combined entry changes;
- raw-byte changes with no semantic entry change;
- invalid or unreadable content;
- missing files;
- suspected full replacement when baseline and observed entries are disjoint.

The contextual ATT&CK mapping is **T1685 — Disable or Modify Tools**, because unauthorised changes to a security-control configuration can impair a defensive mechanism. The alert also references NIST SP 800-53 **SI-7 — Software, Firmware, and Information Integrity**. This mapping provides investigation context rather than attributing an adversary.

## Investigation timeline

The timeline generator combines:

- password-spray threshold crossings;
- successful logons and account lockouts associated with a spray;
- allow-list integrity changes;
- cross-correlation when integrity and authentication alerts occur inside the configured time window.

Output can be JSON Lines or Markdown.

## Engineering evidence

| Area | Evidence |
|---|---|
| Detection | Sliding-window password-spray and SHA-256 allow-list integrity monitoring |
| Identity | Employee, unknown-account, and privileged-account enrichment |
| Investigation | Success, lockout, integrity, and cross-alert timeline correlation |
| Output | Versioned JSONL alerts and Markdown/JSONL timelines |
| Quality | Python 3.12/3.13, Ruff, strict mypy, pytest, branch coverage |
| Security | Strict parsers, atomic baseline writes, CodeQL, Dependabot |
| Portability | Sigma and Microsoft Sentinel KQL drafts |

## Repository layout

```text
config/                 Detector thresholds
data/                   Synthetic events, identities, allow lists, and baseline
detections/kql/         Microsoft Sentinel KQL drafts
detections/sigma/       Sigma detection and correlation drafts
docs/                   Architecture, logic, integrity, timeline, and threat model
reports/                Sample incident and timeline reports
src/hacl_itdr/           Python detector package
tests/                   Positive, negative, boundary, tampering, and CLI tests
```

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Create a trusted baseline

Run this only against a reviewed, approved allow-list state:

```bash
hacl-itdr-baseline \
  --allow-list data/allow_list.txt \
  --manifest data/allow_list_baseline.json \
  --asset-id hacl-primary-allow-list
```

The manifest is a trust anchor. Protect it with restrictive permissions, change control, and an independent backup or signature in any real deployment.

## Run the combined demonstration

```bash
hacl-itdr \
  --events data/synthetic_auth_events.jsonl \
  --employees data/employees.csv \
  --config config/detector.toml \
  --allow-list data/tampered_allow_list.txt \
  --baseline data/allow_list_baseline.json \
  --output output/alerts.jsonl \
  --timeline-output output/investigation-timeline.md
```

## Configuration

```toml
[password_spray]
window_minutes = 10
minimum_failed_attempts = 5
minimum_distinct_accounts = 5
success_correlation_minutes = 30
duplicate_suppression_minutes = 15

[integrity]
correlation_window_minutes = 60
```

These are demonstration defaults, not universal detection standards.

## Quality checks

```bash
ruff check src tests
mypy src tests
python -m pytest
```

The test configuration enforces at least 90% statement and branch coverage.

## Detection-as-code notes

The Sigma and KQL file-tampering drafts use Windows Security event `4663`. Windows file-system auditing must be enabled and the protected object must have an appropriate SACL before this event can provide useful evidence. Field names and access-mask representations must be adapted to the target SIEM schema.

## Roadmap

1. Password-spray detection and identity correlation — complete
2. hACL allow-list integrity monitoring — complete
3. Versioned investigation timeline generation — complete
4. Validate Sigma and KQL drafts against representative Windows schemas
5. Automate a full investigation report and add further identity detections

## References

- MITRE ATT&CK T1110.003: https://attack.mitre.org/techniques/T1110/003/
- MITRE ATT&CK T1685: https://attack.mitre.org/techniques/T1685/
- NIST SP 800-53 SI-7: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- Microsoft advanced audit policy: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration
- Microsoft Windows event 4663: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663
- Sigma correlations: https://sigmahq.io/docs/meta/correlations.html
- KQL summarize: https://learn.microsoft.com/en-us/kusto/query/summarize-operator
