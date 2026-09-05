#!/usr/bin/env python3
"""Well-formedness check for Wazuh rule/decoder XML files.

Wazuh's own loader accepts files with multiple top-level <decoder>
elements and no enclosing root - that's the convention used throughout
the default ruleset (see decoders/100900-custom-app-auth.xml here for an
example: two sibling <decoder> blocks, no wrapper). That means a naive
`xml.dom.minidom.parse()` on the raw file rejects perfectly valid Wazuh
decoder files, since it requires a single document root. We wrap the
content in a synthetic root before parsing, purely for this
well-formedness check - nothing is written back to disk.
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional


def check(path: Path) -> Optional[str]:
    content = path.read_text()
    try:
        ET.fromstring(f"<_root>\n{content}\n</_root>")
    except ET.ParseError as e:
        return str(e)
    return None


def main() -> int:
    paths = [Path(p) for p in sys.argv[1:]]
    if not paths:
        paths = sorted(Path("rules").glob("*.xml")) + sorted(Path("decoders").glob("*.xml"))

    failed = False
    for path in paths:
        err = check(path)
        if err:
            print(f"::error file={path}::not well-formed XML: {err}")
            failed = True
        else:
            print(f"OK {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
