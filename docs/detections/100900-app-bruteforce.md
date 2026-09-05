# billing-api Brute Force (rules 100900-100902)

| | |
|---|---|
| **Rule/decoder files** | `decoders/100900-custom-app-auth.xml`, `rules/100900-app-bruteforce.xml` |
| **MITRE ATT&CK** | T1110 - Brute Force |
| **Data source** | Synthetic internal application log (key=value format, no out-of-the-box Wazuh decoder) |
| **Tests** | `tests/samples/100900_app_bruteforce_attack.log`, `100900_app_login_benign.log` |

This detection exists primarily to demonstrate the decoder-writing half
of the stack (PCRE field extraction from an unstructured, non-syslog,
non-JSON log) end to end, paired with a frequency/timeframe correlation -
not because `billing-api` is a real system. Swap the `<prematch>`/`<regex>`
in the decoder and the log path in the doc comment for any real internal
app's auth log and the rest of the pattern holds.

## Logic

1. **100900** (level 5): a `login_failed` event is decoded.
2. **100901** (level 0): the failing `user` is on
   `lists/app-auth-service-accounts` (health checks, sync jobs that are
   expected to occasionally fail auth, e.g. during a credential
   rotation window) - suppressed.
3. **100902** (level 10, `frequency` unused - see below): 5+ failures
   from the same source IP within 120 seconds, excluding allow-listed
   accounts, via `<if_matched_sid>100900</if_matched_sid>` +
   `<same_source_ip/>`. Matching on source IP rather than a fixed
   username also catches password-spraying (many usernames, one
   source), not just classic single-account brute force.

## Caught by CI, not by review

The decoder's `<order>` originally named the fourth captured group `user`.
`wazuh-logtest`'s Phase 2 field dump showed it decoded as `dstuser`
instead - Wazuh silently maps `user` to the static `dstuser` field rather
than creating a distinct dynamic field with that name. The rules'
`<list field="user">` lookups and `$(user)` description placeholders were
therefore referencing a field that didn't exist: the CDB allow-list check
silently never matched anything, and every alert description rendered
`for user  from ...` with the name missing. Nothing in this failed loudly
- it just quietly did the wrong thing, which is worse. `tests/run_tests.py`
caught it because the test manifest asserts *which rule IDs* fire, and a
non-functioning allow-list would eventually have shown up as a failed
suppression test - but it was actually spotted directly in the raw
`wazuh-logtest` field dump while debugging an unrelated harness bug. Fixed
by using `dstuser` explicitly throughout instead of relying on an
undocumented alias.

## Known false positives

- **NAT / shared egress IP**: if `billing-api` is reachable from behind
  a corporate NAT or a VPN concentrator, multiple real users' failed
  logins can appear to come from one `srcip` and trip 100902 without
  any single account being attacked. `<same_source_ip/>` is the wrong
  correlation key in that topology - use `<same_field name="user">` (or
  drop IP correlation and go per-user) if the deployment sits behind
  shared egress.
- **Password rotation windows**: a bulk credential rotation can produce
  a burst of legitimate `login_failed` events from old cached
  credentials. `lists/app-auth-service-accounts` covers known
  automation accounts, not this case - if it becomes a recurring
  source of noise, add a maintenance-window suppression instead of
  permanently loosening the frequency threshold.
