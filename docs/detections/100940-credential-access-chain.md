# Credential Access Chain - Flagship Correlation (rules 100941-100942)

| | |
|---|---|
| **Rule file** | `rules/100940-credential-access-chain.xml` |
| **MITRE ATT&CK** | T1055 -> T1003.001 -> T1059.001 |
| **Depends on** | `100920-process-injection.xml` (rule 100921), `100910-lsass-credential-access.xml` (rule 100912), `100930-powershell-suspicious.xml` (rule 100931) |
| **Tests** | `tests/samples/100940_chain_sequence.json` (3-stage escalation), `tests/samples/100940_chain_sequence_timeout.json` (embedded `systemTime` 10 minutes apart - see below for why that gap is narrative, not something the rule or the test actually waits on) |

## Why this rule exists

Every rule above it alerts on one atomic technique in isolation. A single
`100912` (LSASS access with a dumping mask) is a real signal, but on its
own it's exactly the kind of thing that gets a "known FP, tuned it out"
shrug three weeks into a role (see the FP discussion in
`100910-lsass-credential-access.md`). Stacking three independent,
individually-plausible-to-dismiss detections into one host-scoped chain
is what turns "here's a pile of medium alerts" into
"here's one alert an analyst should actually act on at 2am". This is the
difference between writing rules and doing detection *engineering*.

## Logic

- **100941** (level 13): the *current* event independently matches
  **100912** (`<if_sid>`) - i.e. it's a real, non-allow-listed,
  dumping-mask LSASS access - **and** **100921** (shellcode injection)
  already fired on *some* prior event, at any point in this analysisd
  session (`<if_matched_sid>`).
- **100942** (level 15): the *current* event independently matches
  **100931** (suspicious PowerShell) **and** **100941** (the stage-2
  chain alert) already fired at some earlier point.

`<if_sid>` and `<if_matched_sid>` do different things and this rule set
depends on combining them correctly: `<if_sid>` requires the log
*triggering this evaluation* to itself belong to that rule's match chain;
`<if_matched_sid>` requires the referenced rule to have fired on *any*
prior log, full stop.

## No time bound - a real engine limitation, not a design choice

The original version of this rule set `timeframe="300"` (5 minutes) on
both rules, intending "B happened within 5 minutes of A". It doesn't
work, and there's no clean way to make it work for a chain like this
one. Two rounds of CI proved it, in order:

1. **`timeframe` alone does nothing.** A negative test (injection, then
   an LSASS dump 10 minutes later) escalated anyway. `timeframe` on an
   `if_matched_sid` rule is silently ignored unless `frequency` is *also*
   set - the docs describe them as used together, but the engine doesn't
   enforce that pairing, so a rule shipping `timeframe` alone quietly
   does nothing with it. Confirmed independently upstream:
   [wazuh/wazuh#7929](https://github.com/wazuh/wazuh/issues/7929).
2. **`frequency` can't express "once".** Adding `frequency="1"` to make
   the pairing valid made `wazuh-manager` refuse to load the rule file at
   all: `frequency` must be `>= 2`. It counts occurrences of the
   referenced rule, so it's built for volumetric correlation ("brute
   force: 5 failures in 2 minutes" - see `100902`), not "this exact
   thing happened once, recently".

**What this rule actually guarantees, as shipped:** injection happened at
some point in this manager's uptime, then this specific LSASS access
happened, in that order, on this host. That's a real, useful ordering
signal - just weaker than a 5-minute window would be, and worth knowing
about before you page someone with "within 5 minutes" language that
isn't true. `tests/samples/100940_chain_sequence_timeout.json` (a
10-minute gap) is kept as a regression test asserting exactly this
current, honest behavior, not a decorative timeframe that never worked.

## Future work: a real bounded window

Getting an actual "within N minutes" guarantee for a single-occurrence
chain means moving that specific correlation out of the real-time rule
engine entirely - e.g. a scheduled query against `wazuh-alerts-*` in
OpenSearch/Kibana (or an external correlation engine) that looks for
`rule.id: 100921` and `rule.id: 100912` on the same `agent.id` within a
bounded time range, which is exactly the kind of query Lucene/DSL is
good at (see the "Where this kind of work applies" section of the main
README) and the rule engine, per the above, is not.

## Known limitations

- All three stages are keyed to `win.system.computer` implicitly, via
  Wazuh's default per-agent correlation scope - this chain does **not**
  currently constrain on `sourceProcessGUID` matching across stages 1
  and 2 (i.e. it would also fire if two *different* processes on the
  same host independently did injection and LSASS access, at any point
  in the session - see "No time bound" above). For a first alarm that
  pages someone, that's an acceptable trade-off toward recall; a v2
  could tighten precision by carrying `sourceProcessGUID` through as a
  correlated field once real traffic volume justifies the extra
  complexity - and would matter more here specifically, since there's no
  time window narrowing the pool of candidate precursor events either.
- Depends on all three prerequisite rules being enabled and their
  upstream data sources (Sysmon, PowerShell Script Block Logging)
  actually configured - see each rule's own doc for prerequisites.
