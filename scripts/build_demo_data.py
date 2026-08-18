#!/usr/bin/env python3
"""Build a static UI snapshot for local file-based visual review."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel import DefenseEngine


def main() -> None:
    engine = DefenseEngine()
    payload = {"overview": engine.overview(), "attacks": engine.attacks()}
    output = ROOT / "web" / "demo-data.js"
    output.write_text(
        "window.MASTERSHIELD_DEMO = " + json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + ";\n",
        encoding="utf-8",
    )
    print(f"Wrote {output} ({output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
