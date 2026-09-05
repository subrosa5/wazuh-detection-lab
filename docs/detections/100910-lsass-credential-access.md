# LSASS Credential Access (rules 100910-100913)

| | |
|---|---|
| **Rule file** | `rules/100910-lsass-credential-access.xml` |
| **MITRE ATT&CK** | T1003.001 - OS Credential Dumping: LSASS Memory |
| **Data source** | Sysmon Event ID 10 (ProcessAccess), `TargetImage` = lsass.exe |
| **Tests** | `tests/samples/100910_lsass_mimikatz_attack.json`, `100910_lsass_defender_benign.json` |

## Hypothesis

An attacker with local admin (or a token impersonating one) reads LSASS
process memory to extract cached credentials, Kerberos tickets, or NTLM
hashes - via Mimikatz's `sekurlsa` module, `procdump -ma lsass.exe`,
`rundll32 comsvcs.dll MiniDump`, Task Manager's "Create dump file", or a
custom loader doing the same `OpenProcess`/`ReadProcessMemory` sequence
Mimikatz does.

## Logic

1. **100910** (level 3, silent parent): any process opens a handle to
   `lsass.exe`. Wide net, `no_full_log` to avoid indexing every hit.
2. **100912** (level 12): the `GrantedAccess` mask matches a
   documented Mimikatz/ProcDump-style read (`0x1010`, `0x1400-0x1410`,
   `0x1438`/`0x143a`, `0x1fffff`).
3. **100913** (level 6): any other access whose mask does NOT match that
   set (`negate="yes"` on the same regex, making 100912/100913
   structurally mutually exclusive) - lower confidence, still worth a
   human look.
4. **100914** / **100915** (level 0, children of 100912 / 100913
   respectively): source process is on `lists/lsass-access-allowlist` -
   suppressed. Allow-listing is applied as a *child rule* of each
   detection, not as a negated list condition on it - see the comment
   header in the rule file for why (a `<list negate="yes">` version of
   this shipped first and failed CI, caught by a real `wazuh-manager`
   refusing to start).

## Known false positives

- **Windows Defender (`MsMpEng.exe`)** routinely opens LSASS with
  `PROCESS_QUERY_LIMITED_INFORMATION`-class access as part of normal
  scanning. Allow-listed by path.
- **WerFault.exe** when LSASS itself crashes and Windows Error Reporting
  captures a dump - legitimate, but note this is *also* exactly what an
  attacker abusing the WER dump path would try to blend in with; if this
  fires outside of an actual LSASS crash event, escalate rather than
  dismiss.
- **EDR/AV agents in general** - every serious endpoint agent reads LSASS
  memory for credential-theft detection of its own. Add your specific
  vendor's binary path before deploying this, or you will page someone
  every few minutes.
- **`0x1410` specifically** is also what a legitimate admin manually
  running ProcDump or Task Manager's dump feature produces. This mask
  alone is not proof of malice - it's proof someone read LSASS memory.
  Correlate with `sourceImage` reputation and whether it was expected
  (change ticket, EDR-initiated) before treating 100912 as confirmed
  malicious.

## Future work (explicitly out of scope for this repo)

- Move the allow-list from path-based to Authenticode
  signature-thumbprint or SHA-256 based (Sysmon Event ID 10 does not
  carry a hash by default - would need to correlate against a prior
  Sysmon Event ID 1 for the same `sourceProcessGUID`). Path-based
  allow-listing is convenience, not a security boundary - see the
  comment header in `lists/lsass-access-allowlist`.
- Correlate with Event ID 7 (ImageLoad) for `dbghelp.dll`/`dbgcore.dll`
  loaded by the source process shortly before access - a strong
  MiniDump-API signal independent of the GrantedAccess mask.
