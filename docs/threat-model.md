# Threat model

## Protected assets

- employee identities;
- privileged accounts;
- authentication telemetry;
- alert integrity;
- detector configuration.

## Threats considered

- one source trying a common password against many accounts;
- successful authentication after suspicious failures;
- account lockouts affecting targeted identities;
- malformed or misleading input records;
- duplicate or out-of-order telemetry;
- thresholds that create avoidable false positives or false negatives.

## Trust assumptions

- event files are untrusted input and must be parsed strictly;
- employee data is synthetic and may be incomplete;
- timestamps include a timezone;
- source IP addresses may represent shared infrastructure;
- alerts are investigative leads rather than proof of compromise.

## Security controls in this milestone

- strict event schemas and supported event IDs;
- IP-address validation;
- timezone normalisation;
- deterministic account normalisation;
- no runtime network access;
- structured output;
- automated tests, static analysis, and code scanning.
