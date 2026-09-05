# Credential Access Chain - Flagship Correlation (rules 100941-100942)

| | |
|---|---|
| **Rule file** | `rules/100940-credential-access-chain.xml` |
| **MITRE ATT&CK** | T1055 -> T1003.001 -> T1059.001 |
| **Depends on** | `100920-process-injection.xml` (rule 100921), `100910-lsass-credential-access.xml` (rule 100912), `100930-powershell-suspicious.xml` (rule 100931) |
| **Test** | `tests/samples/100940_chain_sequence.json` (3-stage sequence, fed as one `wazuh-logtest` session) |

## Why this rule exists

Every rule above it alerts on one atomic technique in isolation. A single
`100912` (LSASS access with a dumping mask) is a real signal, but on its
own it's exactly the kind of thing that gets a "known FP, tuned it out"
shrug three weeks into a role (see the FP discussion in
`100910-lsass-credential-access.md`). Stacking three independent,
individually-plausible-to-dismiss detections into one host-scoped,
time-boxed chain is what turns "here's a pile of medium alerts" into
"here's one alert an analyst should actually act on at 2am". This is the
difference between writing rules and doing detection *engineering*.

## Logic

- **100941** (level 13, `timeframe="300"`): the *current* event
  independently matches **100912** (`<if_sid>`) - i.e. it's a real,
  non-allow-listed, dumping-mask LSASS access - **and** **100921**
  (shellcode injection) already fired on *some* prior event within the
  last 5 minutes (`<if_matched_sid>`).
- **100942** (level 15, `timeframe="300"`): the *current* event
  independently matches **100931** (suspicious PowerShell) **and**
  **100941** (the stage-2 chain alert) already fired within the last 5
  minutes.

`<if_sid>` and `<if_matched_sid>` do different things and this rule set
depends on combining them correctly: `<if_sid>` requires the log
*triggering this evaluation* to itself belong to that rule's match chain;
`<if_matched_sid>` requires the referenced rule to have fired on *any*
prior log within `timeframe`. Neither `100941` nor `100942` sets
`frequency` - omitting it means "at least once in the window", not "N
times"; `frequency` is reserved for volumetric rules like `100902`.

## How the test proves it, without a 5-minute sleep in CI

Wazuh evaluates `timeframe` against each event's own embedded
`systemTime`/timestamp, not wall-clock arrival time. `tests/samples/100940_chain_sequence.json`
sets its three stages 30-90 seconds apart and `tests/run_tests.py` feeds
them to one `wazuh-logtest` session back-to-back - so the correlation
window is satisfied by the data, and CI runs in seconds, not minutes.

## Known limitations

- All three stages are keyed to `win.system.computer` implicitly, via
  Wazuh's default per-agent correlation scope - this chain does **not**
  currently constrain on `sourceProcessGUID` matching across stages 1
  and 2 (i.e. it would also fire if two *different* processes on the
  same host independently did injection and LSASS access within the
  window). For a first alarm that pages someone, that's an acceptable
  trade-off toward recall; a v2 could tighten precision by carrying
  `sourceProcessGUID` through as a correlated field once real traffic
  volume justifies the extra complexity.
- Depends on all three prerequisite rules being enabled and their
  upstream data sources (Sysmon, PowerShell Script Block Logging)
  actually configured - see each rule's own doc for prerequisites.
