# Sample incident report: suspected password spray

## Executive summary

Synthetic authentication data triggered an alert for source `203.0.113.25`. Five failed logons targeted five accounts within four minutes. A successful logon to a privileged account followed three minutes later, and a separate targeted account was locked out.

## Detection evidence

- MITRE ATT&CK: T1110.003 Password Spraying
- Failed attempts: 5
- Distinct accounts: 5
- Privileged account targeted: `c.owolabi`
- Successful follow-on logon: `c.owolabi`
- Account lockout: `b.okafor`
- Unknown identity: `unknown.contractor`

## Assessment

The follow-on success to a privileged identity increases severity. This is not proof of compromise because the source could be shared infrastructure and the successful event could be unrelated. Device, MFA, conditional-access, VPN, and change-management evidence must be reviewed.

## Recommended investigation

1. Identify the owner, network segment, and reputation of the source IP.
2. Review all successful logons from the source during the correlation window.
3. Validate MFA and conditional-access results for the successful account.
4. Check endpoint and identity telemetry for the targeted privileged account.
5. Confirm whether scheduled tasks or services explain the failed attempts.
6. Reset credentials and revoke sessions only when compromise is substantiated.
