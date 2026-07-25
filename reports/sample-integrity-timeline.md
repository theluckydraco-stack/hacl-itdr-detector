# Sample integrity investigation timeline

All data in this report is synthetic.

| Time (UTC) | Severity | Category | Event | Summary |
|---|---|---|---|---|
| 2026-07-25T15:04:00Z | high | authentication | password_spray_threshold_crossed | Five failed logons from 203.0.113.25 targeted five distinct accounts |
| 2026-07-25T15:06:00Z | high | integrity | allow_list_entries_changed | 203.0.113.77 was added and 192.0.2.50 was removed |
| 2026-07-25T15:06:00Z | high | correlation | integrity_change_near_password_spray | Allow-list change occurred two minutes after password-spray threshold crossing |
| 2026-07-25T15:07:00Z | critical | authentication | successful_logon_after_spray | Privileged account carol authenticated successfully from 203.0.113.25 |
| 2026-07-25T15:08:00Z | high | authentication | account_lockout_after_spray | Targeted account bob was locked out |

## Analyst interpretation

The correlation raises priority because a protected access-control file changed near suspicious identity activity. The evidence does not establish a common actor. Preserve the baseline, observed file, authentication records, Windows file-access events, and change-management records before remediation.
