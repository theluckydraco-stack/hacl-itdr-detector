# Password-spray detection logic

The detector searches for failed Windows authentication events (`4625`) from one source IP against several distinct accounts inside a configurable sliding window.

A candidate becomes an alert when both conditions are met:

1. Failed attempts meet or exceed `minimum_failed_attempts`.
2. Distinct targeted accounts meet or exceed `minimum_distinct_accounts`.

The detector then searches the configured follow-on period for successful logons (`4624`) from the same source IP, account lockouts (`4740`), and employee-directory matches.

## Severity

- `critical`: a successful logon follows the spray and a privileged account was targeted;
- `high`: a successful logon, lockout, or privileged account is present;
- `medium`: threshold conditions are met without stronger follow-on evidence.

## Confidence

Confidence increases when targeted identities match the synthetic employee directory or when a successful logon follows the spray.

## Expected false positives

- stale passwords in services, scripts, mapped drives, or scheduled tasks;
- approved security tests and vulnerability scanners;
- shared gateways, VPN concentrators, or proxies that aggregate many users;
- identity-provider retry behaviour;
- incorrectly normalised source addresses or account names.

Analysts must validate source context, authentication method, MFA outcomes, device evidence, account status, and change records before containment.
