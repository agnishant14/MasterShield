#!/usr/bin/env python3
"""Run the same closed-loop bootstrap used by the web application."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel import DefenseEngine


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=Path("work/model-report.json"))
    args = parser.parse_args()
    engine = DefenseEngine()
    report = {
        "cycle": engine.cycle,
        "metrics": engine.metrics,
        "history": engine.history,
        "feature_importance": engine.detector.feature_importance(),
        "training_rows": len(engine.training_rows),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
