# Threat model

## Protected assets

- employee and privileged identities;
- authentication telemetry;
- the hACL-style allow list;
- the trusted baseline manifest;
- alert and timeline integrity;
- detector configuration.

## Threats considered

- one source trying a common password against many accounts;
- successful authentication after suspicious failures;
- account lockouts affecting targeted identities;
- unauthorised allow-list additions or removals;
- file replacement, deletion, invalid encoding, or malformed entries;
- raw-byte changes that preserve the same logical entries;
- malformed or misleading authentication records;
- duplicate or out-of-order telemetry;
- thresholds that create avoidable false positives or false negatives.

## Trust assumptions

- event files and observed allow lists are untrusted input;
- the baseline manifest represents a reviewed and approved state;
- the baseline is protected by permissions, change control, and independent backup or signing outside this lab;
- employee data is synthetic and may be incomplete;
- timestamps include a timezone;
- source IP addresses may represent shared infrastructure;
- an integrity change can be authorised, accidental, or malicious;
- ATT&CK mappings add behavioural context and do not establish attribution.

## Security controls

- strict event schemas and supported event IDs;
- strict IPv4-only allow-list parsing;
- duplicate rejection and canonical entry comparison;
- raw-byte SHA-256 verification;
- atomic baseline-manifest replacement;
- manifest schema and digest validation;
- timezone normalisation;
- deterministic investigation timeline IDs;
- no automatic restoration or mutation of protected files;
- structured, versioned output;
- automated tests, static analysis, and code scanning.

## Important limitation

A local manifest cannot prove its own trustworthiness. A real deployment should store or sign the baseline through an independently protected mechanism and collect file-access telemetry from the operating system.
