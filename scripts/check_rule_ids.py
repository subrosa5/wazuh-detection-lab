#!/usr/bin/env python3
"""CI gate: fail if any two rules in rules/*.xml share an ID, or if an ID
falls outside the range Wazuh reserves for local/custom rules
(100000-119999 - ids below 100000 belong to the shipped default ruleset
and colliding with one will silently shadow or corrupt it).

Mirrors (independently of) the intent of Wazuh's own official
`check_rule_ids.py` used in their Ruleset-as-Code pipeline
(https://wazuh.com/blog/wazuh-ruleset-as-code-rac/), which diffs new IDs
in a dev branch against main. This version is self-contained: it only
needs the checked-out repo, no second branch to diff against, so it also
catches an in-PR collision between two new files.
"""
import re
import sys
from pathlib import Path

ID_RE = re.compile(r'<rule\s+id="(\d+)"')
RULES_DIR = Path(__file__).parent.parent / "rules"
RESERVED_LOW, RESERVED_HIGH = 100000, 119999


def main() -> int:
    seen: dict[str, str] = {}
    out_of_range: list[tuple[str, str]] = []

    for path in sorted(RULES_DIR.glob("*.xml")):
        for rid in ID_RE.findall(path.read_text()):
            if rid in seen:
                print(f"::error::duplicate rule id {rid} in {path.name} (first seen in {seen[rid]})")
                return 1
            seen[rid] = path.name
            if not (RESERVED_LOW <= int(rid) <= RESERVED_HIGH):
                out_of_range.append((rid, path.name))

    if out_of_range:
        for rid, fname in out_of_range:
            print(f"::error file={fname}::rule id {rid} is outside the reserved local range {RESERVED_LOW}-{RESERVED_HIGH}")
        return 1

    print(f"OK: {len(seen)} rule id(s) checked across {len(list(RULES_DIR.glob('*.xml')))} file(s) - all unique and in range.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
