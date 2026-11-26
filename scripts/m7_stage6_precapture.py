#!/usr/bin/env python3
"""User CLI entrypoint for Stage 6 WIP v2 autonomous untethered RAM Pre-Capture daemon."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "prototype-stage6-autonomy"))

import stage6_v2_runner

if __name__ == "__main__":
    raise SystemExit(stage6_v2_runner.main())
