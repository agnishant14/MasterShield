#!/usr/bin/env python3
"""Export a reproducible JSONL dataset for offline inspection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.generator import SyntheticGenerator


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=10000)
    parser.add_argument("--attack-rate", type=float, default=0.22)
    parser.add_argument("--intensity", type=float, default=1.0)
    parser.add_argument("--output", type=Path, default=Path("data/synthetic_payments.jsonl"))
    args = parser.parse_args()
    generator = SyntheticGenerator(seed=2026)
    rows = generator.generate_mixed(args.rows, args.attack_rate, args.intensity)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")
    print(json.dumps({"output": str(args.output), "rows": len(rows), "attacks": sum(row["label"] for row in rows)}))


if __name__ == "__main__":
    main()
