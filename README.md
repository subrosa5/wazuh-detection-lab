# Wazuh Detection Lab

*[Читать на русском](README.ru.md)*

A working example of **Detection Engineering** on [Wazuh](https://wazuh.com/) -
the discipline of turning raw endpoint/network telemetry (Sysmon,
PowerShell logging, application logs, syslog) into alerts a human should
actually act on, instead of noise a human learns to ignore.

Wazuh is a free, open-source SIEM/XDR platform: agents on endpoints ship
logs to a manager, the manager's rule engine (`analysisd`) matches those
logs against decoders and rules, and anything that matches becomes an
alert. Writing a *good* rule - one with an acceptable false-positive
rate, tied to a real attack technique, that survives contact with a real
environment - is most of the actual job of a detection engineer, and it's
also the part almost no public example demonstrates honestly. This repo
tries to.

Concretely: custom rules, decoders and CDB (allow/deny) lists for Wazuh,
each one **proven against a real `wazuh-manager` via `wazuh-logtest` on
every push** - not just written once and eyeballed. The centerpiece is a
3-stage correlation rule that turns three individually-noisy detections
(process injection -> LSASS memory access -> suspicious PowerShell) into
one high-confidence, host-scoped incident alert - the kind of thing that
separates "wrote a regex" from "designed a detection" - see
[`docs/detections/100940-credential-access-chain.md`](docs/detections/100940-credential-access-chain.md).

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

## Where this kind of work applies

Detection engineering isn't tied to one industry - anywhere that runs
endpoints, servers, or applications and cares about being breached needs
someone doing this job, in-house or through a vendor:

- **SOC / MSSP / MDR providers** - this is literally the day job: writing
  and tuning the detections a 24/7 analyst team triages against. The
  false-positive discipline in `docs/detections/` (documented FP sources,
  allow-lists, honest gaps) is what keeps an analyst team from drowning
  and quitting.
- **In-house enterprise security teams** (finance, healthcare, retail/
  e-commerce, SaaS, government) building or tuning their own SIEM instead
  of buying a fully-managed one - Wazuh specifically is popular here
  because it's free at the core, unlike Splunk/Elastic's paid tiers.
- **Regulated industries** (banking, healthcare, insurance) where
  detective controls are an explicit requirement of PCI-DSS, HIPAA,
  SOC 2, or ISO 27001 audits - a documented, tested ruleset like this is
  literally the evidence an auditor asks for.
- **Critical infrastructure and government** - credential-access and
  process-injection detection (this repo's flagship chain) is exactly
  the kind of pattern used against these targets by nation-state actors;
  ATT&CK-mapped detections are the common language threat-intel-driven
  defense is built on.
- **Red/purple team and adversary-emulation work** - the
  [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
  references throughout `docs/detections/` are exactly what a purple
  team uses to validate a detection actually fires, not just that it
  looks plausible on paper.
- **DevSecOps / platform engineering** - the CI pipeline here
  (`.github/workflows/ci.yml`) is a template for "detection-as-code":
  treating SIEM content like application code, with tests and a merge
  gate, rather than hand-editing rules on a production manager over SSH.
- **Training and education** - SOC-analyst onboarding, CTF/range
  building, or just learning Wazuh internals hands-on via
  `wazuh-logtest` (see the Quickstart below).

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

- **This repo's CI turned up five real bugs before anything else saw the
  code** - none visible just from reading the XML, all found by
  `tests/run_tests.py` actually running against a live `wazuh-manager`:
  1. `<list field="..." negate="yes">` (meant to exclude allow-listed
     sources) isn't valid Wazuh syntax - a real `wazuh-manager:4.14.7`
     refused to start (`ERROR: List field="yes" is not valid`), caught
     by the health-check before anything else ran. Fixed by
     restructuring the allow-list check as a child rule instead of a
     negated condition ([the run that caught it](https://github.com/subrosa5/wazuh-detection-lab/actions/runs/33967376239)).
  2. `100910`/`100920` chained off Wazuh's default Sysmon ruleset groups
     (`sysmon_event_10`, `sysmon_event8`) via `<if_group>`, which never
     populated because `wazuh-logtest` decodes fed JSON through its
     generic built-in `json` decoder, not whatever path feeds those
     groups for live agent telemetry - fixed by matching directly on
     `win.system.channel`/`eventID`, the pattern `100930` already used.
  3. A sibling-rule ambiguity: two child rules under `100920` both
     matched the same test event, making the "most specific rule wins"
     assumption untestable - fixed by adjusting the test sample, not the
     rule logic.
  4. CDB list keys that were Windows paths (`C:\...`) silently broke on
     the drive-letter colon, which the CDB format's own docs say must be
     quote-escaped - `lookup="match_key"` was comparing against the
     wrong substring the whole time.
  5. A decoder field named `user` turned out to collide with a reserved
     Wazuh **static field** (`user`/`srcuser`/`dstuser`) with documented
     upstream matching bugs ([wazuh/wazuh#15146](https://github.com/wazuh/wazuh/issues/15146),
     [wazuh/wazuh-ruleset#868](https://github.com/wazuh/wazuh-ruleset/issues/868)) -
     fixed by renaming it to a plain, unreserved field (`account`).

  See the full sequence of pushes in this repo's commit history and
  [Actions runs](https://github.com/subrosa5/wazuh-detection-lab/actions)
  for the blow-by-blow - left in deliberately, not squashed away.
- `rules/100920-process-injection.xml` has no benign test sample or
  allow-list - explained in its own doc, not hidden.
- The LSASS allow-list (`lists/lsass-access-allowlist`) is path-based,
  which is convenience against noise, not a security boundary against a
  renamed/side-loaded binary - documented in the list file itself.
- None of the Sysmon/PowerShell rules depend on Wazuh's default-ruleset
  group names anymore (bug #2 above is why) - all four match directly on
  `win.system.channel`/`win.system.eventID`. More verbose than
  `<if_group>`, but it doesn't break when Wazuh reshuffles its internal
  ruleset, and it's what actually worked against the real engine.
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
