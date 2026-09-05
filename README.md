# Wazuh Detection Lab

A Detection-as-Code repository for Wazuh: custom rules, decoders and CDB
lists that are proven against a real `wazuh-manager` via `wazuh-logtest`
on every pull request, not just eyeballed once and shipped.

The centerpiece is a 3-stage correlation rule that turns three
individually-noisy detections (process injection -> LSASS memory access
-> suspicious PowerShell) into one high-confidence, host-scoped incident
alert - see [`docs/detections/100940-credential-access-chain.md`](docs/detections/100940-credential-access-chain.md).

## Why this repo exists

Most "custom Wazuh rules" examples online are a single `<rule>` matching
a regex, screenshotted once against a log that was hand-typed to match
it. This repo is built the other way round: every rule ships with an
attack sample **and** a paired benign sample, a written false-positive
analysis, and a CI pipeline that fails the PR if the rule doesn't fire on
the attack sample or fires on the benign one. See
[`docs/architecture.md`](docs/architecture.md) for how the pieces fit
together and why specific tooling choices (manager-only Docker, CLI
`wazuh-logtest` over the REST API) were made.

## What's covered

| Rules | Technique | MITRE | Data source |
|---|---|---|---|
| [`100900-app-bruteforce.xml`](rules/100900-app-bruteforce.xml) | Brute force / password spraying | T1110 | Custom app log (PCRE decoder) |
| [`100910-lsass-credential-access.xml`](rules/100910-lsass-credential-access.xml) | LSASS memory dumping | T1003.001 | Sysmon Event ID 10 |
| [`100920-process-injection.xml`](rules/100920-process-injection.xml) | Remote thread / shellcode injection | T1055, T1055.001 | Sysmon Event ID 8 |
| [`100930-powershell-suspicious.xml`](rules/100930-powershell-suspicious.xml) | Obfuscated/encoded PowerShell | T1059.001, T1027 | PowerShell Event ID 4104 |
| [`100940-credential-access-chain.xml`](rules/100940-credential-access-chain.xml) | **Full attack chain** (injection -> dump -> staging) | T1055 -> T1003.001 -> T1059.001 | correlation across the three above |

Full MITRE ATT&CK coverage table (auto-generated, do not hand-edit):
[`docs/mitre-coverage.md`](docs/mitre-coverage.md) - import
[`docs/mitre-coverage.json`](docs/mitre-coverage.json) into the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to
see it on the matrix.

Every rule set has a write-up under [`docs/detections/`](docs/detections/)
covering the detection hypothesis, the exact logic, and - the part most
portfolios skip - **known false positives and honest limitations**. The
process-injection rules in particular ship *without* an allow-list on
purpose, with the reasoning written down rather than faked:
[`docs/detections/100920-process-injection.md`](docs/detections/100920-process-injection.md).

## Quickstart

Requires Docker and Python 3.9+.

```bash
git clone <this-repo>
cd wazuh-detection-lab

docker compose up -d                       # starts wazuh-manager:4.14.7
bash scripts/bootstrap_manager.sh           # registers CDB lists, restarts analysisd
python3 tests/run_tests.py                  # runs the full detection regression suite
```

Expected output: `PASSED: all 8 test case(s).` (verified green in CI:
[the run](https://github.com/subrosa5/wazuh-detection-lab/actions/runs/33969042374)
after 8 iterations of the actual bug-hunting sequence below - left in the
commit history on purpose).

To poke at a rule interactively:

```bash
docker exec -it wazuh-manager /var/ossec/bin/wazuh-logtest
# paste any line from tests/samples/*.log, or a compacted single-line JSON
# from tests/samples/*.json, and hit Enter twice
```

## Repository layout

```
rules/            custom <rule> definitions, one file per detection area
decoders/         custom <decoder> definitions (PCRE field extraction)
lists/            CDB allow-lists referenced by rules, with documented limitations
tests/samples/    one attack + one benign sample per rule set (raw logs / JSON)
tests/            test_manifest.json (declarative expectations) + run_tests.py (harness)
docs/detections/  one write-up per rule set: hypothesis, logic, known FPs, future work
docs/             architecture.md, auto-generated mitre-coverage.{md,json}
scripts/          validate_xml.py, check_rule_ids.py, generate_mitre_navigator_layer.py, bootstrap_manager.sh
.github/workflows/ci.yml   the quality gate: XML validation -> ID collision check ->
                            live wazuh-logtest regression -> MITRE coverage regen
```

## CI pipeline

Every PR touching `rules/`, `decoders/`, `lists/`, or `tests/` runs:

1. **XML well-formedness** (`scripts/validate_xml.py`)
2. **Rule ID collision / range check** (`scripts/check_rule_ids.py`) - custom
   rules must live in Wazuh's reserved local range, 100000-119999
3. **A real `wazuh-manager:4.14.7` container**, with this repo's
   rules/decoders/lists mounted in
4. **The full regression suite** (`tests/run_tests.py`) against that
   live manager via `wazuh-logtest` - including the 3-stage correlation
   chain, fed through one session with synthetic timestamps so CI
   doesn't need to sleep for 10 real minutes
5. **MITRE coverage regeneration**, failing the build if the committed
   `docs/mitre-coverage.*` is stale relative to the rules

This goes one step further than Wazuh's own official
[Ruleset-as-Code pipeline](https://wazuh.com/blog/wazuh-ruleset-as-code-rac/),
which validates rule ID uniqueness on merge but - per their own public
write-up - does not run `wazuh-logtest` in CI.

## Honest gaps (read this before trusting any of it blindly)

- **This repo's CI turned up three real bugs before anything else saw the
  code**, in order: (1) `<list negate="yes">` isn't valid syntax and
  crashed analysisd outright; (2) `100910`/`100920` chained off Wazuh's
  default Sysmon ruleset groups (`sysmon_event_10`, `sysmon_event8`) via
  `<if_group>`, which never populated when `wazuh-logtest` decoded the
  test JSON through its generic built-in `json` decoder instead of
  whatever path feeds those groups for live agent telemetry - fixed by
  matching directly on `win.system.channel`/`eventID` instead, the same
  pattern `100930` already used; (3) a decoder `<order>` field literally
  named `user` silently decoded as the static field `dstuser` instead,
  so the CDB allow-list lookups referencing `field="user"` never matched
  anything. None of these were visible from reading the XML - all three
  came from `tests/run_tests.py` actually running against a live
  `wazuh-manager`. See the full sequence of pushes in this repo's commit
  history and [Actions runs](https://github.com/subrosa5/wazuh-detection-lab/actions)
  if you want the blow-by-blow.
- **The first pushed version of this repo failed its own CI**:
  `<list field="..." negate="yes">` (used to exclude allow-listed
  sources) is not valid Wazuh syntax - a real `wazuh-manager:4.14.7`
  refused to start (`ERROR: List field="yes" is not valid`), and the
  health-check step caught it before anything else ran. Fixed by
  restructuring the allow-list check as a child rule instead of a
  negated condition - see the comment headers in
  `rules/100910-lsass-credential-access.xml` and
  `rules/100900-app-bruteforce.xml`, and
  [the run that caught it](https://github.com/subrosa5/wazuh-detection-lab/actions/runs/33967376239).
  Left in the history deliberately instead of squashed away.
- `rules/100920-process-injection.xml` has no benign test sample or
  allow-list - explained in its own doc, not hidden.
- The LSASS allow-list (`lists/lsass-access-allowlist`) is path-based,
  which is convenience against noise, not a security boundary against a
  renamed/side-loaded binary - documented in the list file itself.
- Sysmon default-ruleset group names (`sysmon_event_10`, `sysmon_event8`)
  were verified against `wazuh-ruleset` source at the time of writing;
  Wazuh has changed these before across releases. The PowerShell rule
  set (`100930`) deliberately avoids asserting an unverified group name
  and matches on raw channel/event ID fields instead - see the comment
  header in that file.
- None of the attack samples came from a live Windows host running
  Atomic Red Team - they're hand-built against the documented
  `wazuh-logtest` eventchannel JSON schema. The CI pipeline validates
  rule logic against that schema faithfully; it does not validate that
  Sysmon/the Wazuh agent actually emit exactly this shape in the wild.
  Closing that gap for real is the natural next step: run
  [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
  T1003.001/T1055 procedures on a real Windows VM with this ruleset
  deployed, and replace the synthetic samples with captured agent
  output.

---

🤖 Bootstrapped with [Claude Code](https://claude.com/claude-code)
