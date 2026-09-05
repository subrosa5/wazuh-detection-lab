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

## Caught by CI, not by review (two rounds)

**Round 1:** the decoder's `<order>` originally named the fourth captured
group `user`. `wazuh-logtest`'s Phase 2 field dump showed it decoded as
`dstuser` instead of a plain dynamic field called `user`. The rules'
`<list field="user">` lookups and `$(user)` description placeholders were
therefore referencing a field that didn't exist under that name: the CDB
allow-list check silently never matched anything, and every alert
description rendered `for user  from ...` with the name missing. Nothing
failed loudly - it just quietly did the wrong thing, which is worse.

**Round 2:** switching every reference to `dstuser` (matching what the
field dump actually showed) fixed the `$(dstuser)` description
substitution, but `<list field="dstuser" lookup="match_key">` *still*
never matched a value that was, byte-for-byte, sitting in the CDB list.
`user`/`srcuser`/`dstuser` turn out to be Wazuh **static fields** with
documented, long-standing limitations around generic `<field name=>`/
`<list field=>` matching - see
[wazuh/wazuh#15146](https://github.com/wazuh/wazuh/issues/15146),
[wazuh/wazuh-ruleset#868](https://github.com/wazuh/wazuh-ruleset/issues/868),
and [wazuh/wazuh#31648](https://github.com/wazuh/wazuh/issues/31648) for
other people hitting variations of the same thing. The fix that actually
worked: stop using a reserved static-field name at all. The decoder's
`<order>` now calls the field `account` - a plain, unreserved dynamic
field name - and every rule reference (`<list field="account">`,
`$(account)`) uses that instead. Sidestepping the special-cased field
entirely turned out to be more reliable than fighting to use it
correctly.

## A same-level sibling nuance (not worth over-fixing)

On the 5th (threshold-tipping) benign-account log line, both 100901
(`if_sid=100900` + allow-list) and 100902 (`if_sid=100900` +
`if_matched_sid=100900` + frequency) structurally match as siblings under
100900. Empirically, 100901 - not 100902/100903 - ends up as the reported
alert; sibling-evaluation order isn't `level`-descending in this case
(100901 is level 0, 100902 is level 10) but appears to follow declaration
order instead. This is left as-is rather than reordered or forced,
because it doesn't matter: 100901 and 100903 are both level 0 suppression
outcomes, so which one "wins" changes only which rule ID appears in a
debug trace, not whether anything actually alerts. `tests/test_manifest.json`
asserts that behavior explicitly (`expect_any_of`) instead of pinning an
undocumented engine detail.

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
