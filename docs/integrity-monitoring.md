# Allow-list integrity monitoring

## Detection objective

Detect any divergence between an approved IPv4 allow-list state and an observed file, then explain the semantic access-control difference.

## Baseline fields

- schema version;
- asset ID;
- protected path;
- UTC generation time;
- raw-file SHA-256 digest;
- byte length;
- canonical, duplicate-free IPv4 entries.

## Change classifications

| Change type | Meaning | Default severity |
|---|---|---|
| `content_modified` | Raw bytes changed but canonical entries are unchanged | Medium |
| `entries_added` | One or more new addresses appeared | High |
| `entries_removed` | One or more approved addresses disappeared | High |
| `entries_changed` | Additions and removals occurred | High |
| `missing` | The protected file no longer exists | Critical |
| `invalid` | The file cannot be parsed as strict UTF-8 IPv4 data | Critical |

A disjoint observed set is marked `replacement_suspected` and raised to critical severity.

## ATT&CK and NIST context

The contextual ATT&CK mapping is T1685, Disable or Modify Tools. MITRE describes tampering with defensive tools and their configuration as defense impairment. The detector does not claim that every hash mismatch is adversary activity.

NIST SP 800-53 SI-7 addresses software, firmware, and information integrity. The raw digest and trusted-state comparison are aligned with that integrity-checking objective.

## Operational requirements

- Create the baseline only after independent review.
- Store the manifest separately from the observed file where possible.
- Restrict who can update either file.
- Preserve both files before remediation.
- Record an authorised change ticket and regenerate the baseline only after approval.
- Do not silently restore a file from this detector.

## Windows telemetry companion

The included Sigma and KQL drafts use Security event 4663 to identify access to the protected path. Microsoft notes that Audit File System must be configured and a matching SACL must exist on the object. The local hash detector remains useful when such telemetry is missing, but it cannot identify the actor by itself.
