# Suspicious PowerShell ScriptBlock (rules 100930-100931)

| | |
|---|---|
| **Rule file** | `rules/100930-powershell-suspicious.xml` |
| **MITRE ATT&CK** | T1059.001 - Command and Scripting Interpreter: PowerShell, T1027 - Obfuscated Files or Information |
| **Data source** | Windows PowerShell Event ID 4104 (Script Block Logging) |
| **Tests** | `tests/samples/100930_powershell_encoded_attack.json`, `100930_powershell_benign.json` |

## Prerequisite

Script Block Logging must be enabled via GPO
(`Administrative Templates > Windows Components > Windows PowerShell >
Turn on PowerShell Script Block Logging`) and the
`Microsoft-Windows-PowerShell/Operational` channel forwarded to the
Wazuh agent. Without it, Event ID 4104 is never generated and this whole
rule set is silent - verify the GPO first if 100930 never fires on a
host you know runs PowerShell.

## Why no `<if_group>` parent

Every other Windows rule set in this repo (`100910`, `100920`) chains off
a Sysmon default-ruleset group name that was verified directly against
`wazuh-ruleset`'s source on GitHub. No equivalent PowerShell group name
could be confirmed the same way during this repo's research pass, so
`100930` matches directly on `win.system.channel` + `win.system.eventID`
instead of asserting a group name nobody checked. More verbose, but
honest - see the comment header in the rule file itself.

## Logic

1. **100930** (level 3, silent parent): any ScriptBlock logged.
2. **100931** (level 10): the script block text contains an
   obfuscation/download-cradle indicator - `-EncodedCommand`,
   `FromBase64String`, `-nop`/`-noni`, `-WindowStyle Hidden`,
   `IEX`/`Invoke-Expression`, `.DownloadString(`, or
   `Reflection.Assembly` (in-memory .NET loading).

## Known false positives

- Legitimate deployment tooling (Chocolatey, DSC, some CI runners)
  routinely uses `-nop -w hidden` for unattended runs - this is the
  single noisiest indicator in the pattern. Expect to tune per
  environment; consider splitting `-nop`/`-w hidden` alone (weak
  signal) from `EncodedCommand` + `DownloadString` together (strong
  signal) into separate severities if FP volume is high.
- Any admin script using `Invoke-Expression` for legitimate
  metaprogramming will match - `IEX` alone is a very common, very weak
  signal in isolation. Real reason this fires at level 10 and not
  higher: it's meant to be triaged, not auto-actioned.

## Future work

- PowerShell 4104 events longer than ~8KB get split across multiple
  `MessageNumber`/`MessageTotal` records - this rule set does not
  currently reassemble multi-part script blocks before matching, so a
  payload deliberately padded to straddle a chunk boundary could evade
  the regex. Reassembly requires accumulating by `ScriptBlockId` across
  events, which needs a stateful correlation this rule set doesn't do
  yet.
