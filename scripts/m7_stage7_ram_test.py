#!/usr/bin/env python3
"""User CLI entrypoint for Stage 7.2 volatile RAM-only live camera test (DSC-RX100M7 1.00)."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "prototype-stage7-persist"))

import stage7_ram_runner

if __name__ == "__main__":
    raise SystemExit(stage7_ram_runner.main())
