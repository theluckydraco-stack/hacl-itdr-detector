# hACL ITDR Detector

[![CI](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/ci.yml)
[![CodeQL](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/codeql.yml/badge.svg)](https://github.com/theluckydraco-stack/hacl-itdr-detector/actions/workflows/codeql.yml)

A Python identity-threat detection engineering project built as a separate extension of the access-governance ideas demonstrated by hACL.

The project combines password-spray detection, identity correlation, successful logon detection for non-active accounts, trusted-baseline allow-list monitoring, Windows Security schema adapters, deterministic timelines, and automated investigation reports. All included evidence is synthetic.

## Project boundary

This repository is not the original hACL access-list manager. It does not modify hACL history, repair access lists, authenticate users, or claim production SIEM readiness. Alerts identify evidence that requires analyst validation; they do not prove malicious intent or adversary attribution.

## Detections implemented

### Password spraying — ATT&CK T1110.003

The detector identifies failed Windows logons (`4625`) from one source IP against multiple distinct accounts inside a configurable sliding time window. It correlates:

- successful logons (`4624`) from the same source to targeted accounts;
- account lockouts (`4740`) affecting targeted accounts;
- known, unknown, and privileged identities from a synthetic directory.

### Successful logon by a non-active account — ATT&CK T1078 context

A successful event `4624` generates an identity alert when the synthetic directory contains the account but its status is not `active`. Privileged non-active identities receive critical severity. The T1078 mapping is contextual and does not claim the credentials were compromised.

### Allow-list integrity monitoring

The detector creates and loads a trusted baseline manifest containing:

- a raw-file SHA-256 digest;
- canonical IPv4 entries;
- byte length, asset ID, protected path, schema version, and generation time.

It detects:

- added or removed allow-list entries;
- combined entry changes;
- raw-byte changes with no semantic entry change;
- invalid or unreadable content;
- missing files;
- suspected full replacement when baseline and observed entries are disjoint.

The contextual ATT&CK mapping is **T1685 — Disable or Modify Tools**. The alert also references NIST SP 800-53 **SI-7 — Software, Firmware, and Information Integrity**.

## Representative Windows Security schemas

The repository includes a strict adapter for newline-delimited records shaped from the documented Windows Security event fields:

- `4624` — successful logon;
- `4625` — failed logon;
- `4740` — account lockout;
- `4663` — file access performed.

The adapter validates the provider, event ID, timestamp, computer, event-specific fields, IP addresses, logon types, file paths, access masks, process names, and subject accounts. It normalises authentication evidence into `AuthEvent` records and event `4663` evidence into `FileAccessEvent` records.

The sample file is `data/windows_security_events.jsonl`.

## Detection-content validation

`hacl-itdr-validate-detections` checks the Sigma and KQL drafts against repository contracts derived from representative Windows event fields and the Microsoft Sentinel `SecurityEvent` table.

The validator checks:

- required Sigma metadata and log source declarations;
- event-specific field availability;
- correlation fields and tokens;
- Microsoft Sentinel table and column references;
- required aggregation and time-binning expressions.

This is a static repository contract, not a substitute for deploying and tuning rules in a live SIEM.

## Investigation timeline and report

The timeline combines:

- password-spray threshold crossings;
- successful logons and lockouts associated with a spray;
- successful logons by non-active accounts;
- allow-list integrity changes;
- Windows event `4663` file-access evidence;
- cross-correlation when integrity and authentication alerts occur inside the configured window.

Output can be JSON Lines or Markdown. The report generator adds:

- executive counts by severity and alert type;
- finding summaries;
- affected identities;
- ATT&CK context;
- SHA-256 hashes and sizes for evidence inputs;
- recommended actions;
- the chronological timeline;
- explicit trust assumptions and limitations.

## Engineering evidence

| Area | Evidence |
|---|---|
| Detection | Password spraying, inactive-account logons, and SHA-256 allow-list integrity monitoring |
| Schema | Strict representative adapters for events 4624, 4625, 4663, and 4740 |
| Identity | Employee, unknown-account, privileged-account, and directory-status enrichment |
| Investigation | Success, lockout, file-access, integrity, and cross-alert timeline correlation |
| Reporting | Evidence hashes, findings, ATT&CK context, actions, and Markdown report automation |
| Quality | Python 3.12/3.13, Ruff, strict mypy, pytest, branch coverage |
| Security | Strict parsers, atomic baseline writes, CodeQL, Dependabot |
| Portability | Sigma and Microsoft Sentinel KQL drafts with field-contract validation |

## Repository layout

```text
config/                 Detector thresholds
data/                   Synthetic normalised and Windows-shaped evidence
detections/kql/         Microsoft Sentinel KQL drafts
detections/sigma/       Sigma detection and correlation drafts
docs/                   Architecture, schemas, integrity, timeline, and reporting
reports/                Sample incident and investigation reports
schemas/                Windows, Sentinel, and detection-content contracts
src/hacl_itdr/           Python detector package
tests/                   Positive, negative, boundary, schema, report, and CLI tests
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

## Run the full Windows-schema demonstration

```bash
hacl-itdr \
  --events data/windows_security_events.jsonl \
  --events-format windows-security \
  --employees data/employees.csv \
  --config config/detector.toml \
  --allow-list data/tampered_allow_list.txt \
  --baseline data/allow_list_baseline.json \
  --output output/alerts.jsonl \
  --timeline-output output/investigation-timeline.jsonl \
  --report-output output/investigation-report.md
```

The original normalised JSONL format remains available with the default `--events-format normalised`.

## Validate detection content

```bash
hacl-itdr-validate-detections --root .
```

This command is also enforced in CI on Python 3.12 and 3.13.

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
hacl-itdr-validate-detections --root .
python -m pytest
```

The test configuration enforces at least 90% statement and branch coverage.

## Detection-as-code notes

The password-spray Sigma correlation uses a `value_count` rule grouped by source IP and counting distinct target accounts. The KQL draft uses `summarize`, `count()`, `dcount()`, and explicit `bin()` time grouping.

The file-access Sigma and KQL drafts use event `4663`, `ObjectName`, `AccessMask`, `ProcessName`, and subject fields. Windows Audit File System and a matching object SACL must be enabled before event `4663` can provide useful evidence.

## Roadmap

1. Password-spray detection and identity correlation — complete
2. hACL allow-list integrity monitoring — complete
3. Versioned investigation timeline generation — complete
4. Representative Windows schema adapters and detection-content validation — complete
5. Automated evidence-backed investigation reporting — complete
6. Additional identity detections and environment-specific SIEM validation

## References

- MITRE ATT&CK T1110.003: https://attack.mitre.org/techniques/T1110/003/
- MITRE ATT&CK T1078: https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK T1685: https://attack.mitre.org/techniques/T1685/
- NIST SP 800-53 SI-7: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- Microsoft Windows event 4624: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- Microsoft Windows event 4625: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
- Microsoft Windows event 4740: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740
- Microsoft Windows event 4663: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663
- Microsoft Sentinel SecurityEvent: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent
- Sigma rules: https://sigmahq.io/docs/basics/rules.html
- Sigma correlations: https://sigmahq.io/docs/meta/correlations.html
- KQL summarize: https://learn.microsoft.com/en-us/kusto/query/summarize-operator
