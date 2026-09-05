#!/usr/bin/env python3
"""Copy tools/tools.json (the single source of truth) into both packages.

    python3 tools/sync_tools.py          # write the copies
    python3 tools/sync_tools.py --check  # exit 1 if a copy has drifted (CI)

The copies are committed so `pip install -e python/` and `npm install` work
without a build step; this script (and the test suites) keep them honest.
"""
import filecmp
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "tools" / "tools.json"
COPIES = [
    ROOT / "python" / "src" / "threatcluster_mcp" / "tools.json",
    ROOT / "node" / "tools.json",
]


def main() -> int:
    check = "--check" in sys.argv[1:]
    drift = 0
    for dest in COPIES:
        same = dest.exists() and filecmp.cmp(SOURCE, dest, shallow=False)
        if check:
            print(f"{'ok   ' if same else 'DRIFT'} {dest.relative_to(ROOT)}")
            drift += 0 if same else 1
        elif not same:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE, dest)
            print(f"wrote {dest.relative_to(ROOT)}")
        else:
            print(f"up to date {dest.relative_to(ROOT)}")
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
