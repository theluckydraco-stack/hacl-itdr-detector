# Investigation timeline

The timeline converts detector output and selected source events into one ordered evidence stream.

## Event types

- `password_spray_threshold_crossed`
- `successful_logon_after_spray`
- `account_lockout_after_spray`
- `allow_list_<change_type>`
- `integrity_change_near_password_spray`

## Correlation rule

An integrity alert and password-spray alert are linked when the absolute difference between the integrity detection time and password-spray threshold time is no greater than `correlation_window_minutes`.

Correlation increases investigative priority. It does not prove that the same actor caused both events.

## Determinism

Timeline event IDs are UUIDv5 values derived from the relevant alert IDs, timestamp, account, and event type. Replaying the same evidence produces the same timeline identifiers.

## Output

- `.jsonl` produces machine-readable event records.
- `.md` produces an analyst-readable chronological table.
