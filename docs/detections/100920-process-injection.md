# Process Injection via Remote Thread (rules 100920-100922)

| | |
|---|---|
| **Rule file** | `rules/100920-process-injection.xml` |
| **MITRE ATT&CK** | T1055 - Process Injection, T1055.001 - DLL/shellcode injection |
| **Data source** | Sysmon Event ID 8 (CreateRemoteThread) |
| **Tests** | `tests/samples/100920_process_injection_attack.json` (no paired benign sample - see below) |

## Hypothesis

A malicious loader injects shellcode or a reflectively-loaded DLL into a
legitimate process (a common defense-evasion + execution step ahead of
credential access or C2 staging - see `100940-credential-access-chain.xml`
for how this feeds the flagship correlation rule).

## Logic

1. **100920** (level 3, silent parent): any `CreateRemoteThread` event.
2. **100921** (level 11): `StartModule` is empty - the thread's start
   address has no backing module on disk. This is the classic
   fingerprint of manually-mapped/reflective shellcode, since a normal
   `LoadLibrary`-based DLL injection resolves to a real module path.
3. **100922** (level 9): target process is one of
   `lsass|winlogon|csrss|services|svchost` regardless of module
   presence - injecting into these is rarely legitimate.

## Known false positives

**This rule set has no benign test sample on purpose.** `CreateRemoteThread`
into another process is inherently rare in legitimate software (compared
to, say, LSASS access, which AV does constantly) - but it is not zero:
debuggers, some game anti-cheat/DRM systems, and a handful of legacy
enterprise agents inject remote threads as part of normal operation. This
repo does not have telemetry from a real fleet to build that allow-list
honestly, so it ships without one rather than invent plausible-sounding
entries that would give false confidence. **Before deploying 100921/100922
to production**, run a baseline period with alerting-only (or route to a
lower channel) and build `lists/process-injection-allowlist` from what
actually fires - do not skip this step. Documenting an honest gap here
is deliberate, not an oversight.

## Future work

- Add an allow-list once real baseline data exists (see above).
- Correlate `TargetImage` against the source process's own child-process
  tree - injection into a *freshly-spawned, suspended* process
  (a common process-hollowing pattern) is a stronger signal than
  injection into a long-running one, but needs Event ID 1 correlation
  with `CREATE_SUSPENDED` timing this repo doesn't currently model.
