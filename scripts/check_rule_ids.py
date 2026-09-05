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

Parses the XML properly (ElementTree, wrapped in a synthetic root the
same way scripts/validate_xml.py does) rather than regex-matching
`<rule id="...">` - a regex anchored on attribute order would silently
miss a perfectly valid `<rule level="10" id="100900">`.
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RULES_DIR = Path(__file__).parent.parent / "rules"
RESERVED_LOW, RESERVED_HIGH = 100000, 119999


def rule_ids(path: Path) -> list:
    root = ET.fromstring(f"<_root>\n{path.read_text()}\n</_root>")
    return [rule.get("id") for rule in root.iter("rule") if rule.get("id") is not None]


def main() -> int:
    seen: dict = {}
    out_of_range: list = []

    for path in sorted(RULES_DIR.glob("*.xml")):
        for rid in rule_ids(path):
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
