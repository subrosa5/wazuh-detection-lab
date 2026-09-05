#!/usr/bin/env python3
"""
Detection regression harness for the Wazuh Detection Lab.

Feeds tests/samples/* through a live `wazuh-logtest` session inside the
wazuh-manager container (see docker-compose.yml) and asserts which rule
IDs fired. This is the CI quality gate referenced throughout the rule
files: no rule change merges without proving it (a) fires on its intended
attack sample and (b) stays silent, or hits the right suppression rule,
on its paired benign sample.

Usage:
    python3 tests/run_tests.py [--container wazuh-manager]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# Calibrated against real wazuh-logtest 4.14.7 output (Phase 3 prints
# `\tid: '100900'` on its own line inside each fired rule's block, not
# the "Rule: NNNN (level N)" format this repo's first draft assumed and
# CI immediately proved wrong - see git history / README "Honest gaps".
RULE_ID_RE = re.compile(r"^\s*id:\s*'(\d+)'\s*$", re.MULTILINE)
TESTS_DIR = Path(__file__).parent
MANIFEST = TESTS_DIR / "test_manifest.json"


def run_logtest(container: str, lines: list[str]) -> str:
    """Feed one or more raw log lines to a SINGLE wazuh-logtest session
    inside the container and return combined stdout+stderr. Lines fed in
    one invocation share one session/token, which is what lets
    frequency/if_matched_sid correlation rules see prior matches -
    exactly like a real manager sees a real event stream."""
    payload = "\n".join(lines) + "\n"
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "/var/ossec/bin/wazuh-logtest"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.stdout + "\n" + proc.stderr


def matched_rules(output: str) -> set[int]:
    return {int(m.group(1)) for m in RULE_ID_RE.finditer(output)}


def load_lines(case: dict) -> list[str]:
    sample_path = TESTS_DIR / case["sample"]
    kind = case["type"]

    if kind == "lines":
        return [line for line in sample_path.read_text().splitlines() if line.strip()]

    if kind == "single":
        obj = json.loads(sample_path.read_text())
        return [json.dumps(obj, separators=(",", ":"))]

    if kind == "sequence":
        events = json.loads(sample_path.read_text())
        out = []
        for ev in events:
            ev = {k: v for k, v in ev.items() if not k.startswith("_")}
            out.append(json.dumps(ev, separators=(",", ":")))
        return out

    raise ValueError(f"unknown test type: {kind!r} in case {case.get('name')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="wazuh-manager")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text())
    failures: list[str] = []

    for case in manifest["tests"]:
        lines = load_lines(case)
        output = run_logtest(args.container, lines)
        got = matched_rules(output)

        expect = set(case.get("expect_rules", []))
        forbid = set(case.get("forbid_rules", []))

        missing = expect - got
        unexpected = forbid & got
        ok = not missing and not unexpected

        print(f"[{'PASS' if ok else 'FAIL'}] {case['name']} - {case['description']}")
        if missing:
            print(f"         missing expected rule(s): {sorted(missing)}")
        if unexpected:
            print(f"         unexpectedly fired forbidden rule(s): {sorted(unexpected)}")
        print(f"         rules observed: {sorted(got)}")

        if not ok:
            failures.append(case["name"])
            print("         --- raw wazuh-logtest output (debug) ---")
            for line in output.splitlines():
                print(f"         | {line}")
            print("         --- end raw output ---")

    print()
    total = len(manifest["tests"])
    if failures:
        print(f"FAILED: {len(failures)}/{total} test case(s): {failures}")
        return 1

    print(f"PASSED: all {total} test case(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
