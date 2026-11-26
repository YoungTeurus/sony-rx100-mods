"""Cross-check a published file receipt against its capture log, optionally with JPEGs."""

import argparse
import json
from pathlib import Path
import re

from capture_analysis import parse_daemon_log, verify_card_saved_files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", choices=("2", "4b"))
    parser.add_argument("--jpeg-dir", type=Path, help="Directory containing the original PC*.JPG files")
    args = parser.parse_args()
    evidence = Path(__file__).resolve().parents[1] / "evidence"
    receipt = json.loads((evidence / f"run-{args.run}-card.json").read_text())
    log = parse_daemon_log((evidence / f"run-{args.run}-events.log").read_text())
    files = receipt["files"]
    rows = {f["file"]: f for f in files}
    logged = log["ring_files"]
    expected_count = {"2": 3, "4b": 20}[args.run]
    if not (len(rows) == len(files) == receipt["checked"] == len(logged) == expected_count):
        parser.exit(1, "FAIL: file counts disagree\n")
    if {r["file"] for r in logged} != set(rows) or not receipt["all_ok"] or receipt["empty_file_list"]:
        parser.exit(1, "FAIL: file lists or recorded card result disagree\n")
    for event in logged:
        name = event["file"]
        row = rows[name]
        matched = (row["ok"] and row["valid"] and row["status"] == event["status"] == "13"
                   and row["size"] == row["expected_bytes"] == int(event["bytes"]) > 0
                   and (row["width"], row["height"]) == (5472, 3648)
                   and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]))
        if not matched:
            parser.exit(1, f"FAIL: file receipt mismatch for {name}\n")
    if args.jpeg_dir:
        observed = verify_card_saved_files(args.jpeg_dir, logged, expect_nonempty=True)
        if not observed["all_ok"] or any(f["sha256"] != rows[f["file"]]["sha256"] for f in observed["files"]):
            parser.exit(1, "FAIL: JPEG readback mismatch\n")
    total = sum(f["size"] for f in files)
    scope = "receipts and JPEGs" if args.jpeg_dir else "receipts"
    print(f"PASS ({scope}): {len(files)} files, {total:,} bytes")


if __name__ == "__main__":
    main()
