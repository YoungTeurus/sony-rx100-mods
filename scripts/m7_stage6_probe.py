#!/usr/bin/env python3
"""User CLI wrapper for Stage 6 WIP v1 read-only untethered RAM daemon probe."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prototype-stage6-autonomy"))
import stage6_runner

if __name__ == "__main__":
    raise SystemExit(stage6_runner.main())
