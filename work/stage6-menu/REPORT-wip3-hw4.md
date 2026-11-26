# Stage 6 hardware Run #4 — 2026-11-26

**Run #4a tethered diagnostic — PASS.** See the [tethered report](REPORT-wip3-hw4a.md).

**Run #4b startup — PASS.** Start receipt `20261126T145647Z-0193e507ebdb-start.json` (operator archive) records `cli_ok=true`, PID 3500 and the reviewed r3 template digests. The receipt SHA-256 is `da4f5f418374d56657d93d22f0914169438bf15d2715faddb7900abd439e4274`.

**Run #4b — HARDWARE PASS for RAM-only JPEG pre-capture, including SD readback.** The operator completed the four actions in JPEG mode and reconnected USB in Mass Storage mode. The published event excerpt [evidence/run-4b-events.log](../../evidence/run-4b-events.log) comes from `20261126T150548Z-b6d997048cfa-daemon.log`, which matches the log embedded in collection receipt `20261126T150548Z-b6d997048cfa-collect.json`.

| Scenario | Hardware observation |
|---|---|
| OFF, Continuous | At 20.319 s, full press with toggle off, gate closed and ring inactive. No ring session started. |
| ON, Single | At 33.516 s, full press with Single selected, gate closed and ring inactive. No ring session started. |
| ON, Continuous SAVE | Sequence 1 logged five pre and 15 post frames, reaching the configured post limit. Twenty distinct file records total 197,827,393 bytes. After full release at 58.731 s the last file was logged at 91.552 s (+32.821 s), followed by ring exit at 105.288 s (+46.557 s). The operator saw no save progress indicator. |
| ON, Continuous CANCEL | Sequence 2 logged a half press from 110.116 to 122.251 s with no full press. It entered drain at 122.311 s, finished drain at 133.420 s and exited at 134.406 s. Release to exit took 12.155 s, including 11.109 s in drain. The window was empty and no files were reported by this session. The log times helper exit; the first moment another shot was possible was not measured. |

Both ring exits had rc=0, unres=0 and fault=0. STOP reported two successful runs, 20 files, zero faults and no truncation. Collection stopped the daemon cleanly, persisted the log, removed the RAM directory (GONE) and cleared the active state.

| Receipt | SHA-256 |
|---|---|
| [Card readback JSON](../../evidence/run-4b-card.json) (excerpt; full receipt SHA-256) | `d10afab1c3b5a744818f6ebe644f372194595c2d0c8a8dd03b6307353de10f5a` |
| Collect JSON | `3be9fdce0c5a221477034408c5b726c3dab0d1c56d7e4e40f823fe98ed1c75e5` |
| Daemon log | `2902f6e0e8f9f03daded5c2966be4c8c2e1211b29a1a09058bd3ed376718016d` |

The operator ran this read-only SD check from the repository root.

```sh
clear
.venv-analysis/bin/python3 -B scripts/m7_stage6_precapture.py --check-card-only --card /Volumes/RX100M7 --log work/stage6-menu/wip2/20261126T150548Z-b6d997048cfa-daemon.log | tee work/stage6-menu/wip2/20261126T150548Z-b6d997048cfa-card-check.json
```

Observed `checked=20` and `all_ok=true`. Each of the 20 distinct filenames matched sequence 1 in the daemon log. Each JPEG passed the card checker at 5472 × 3648 pixels, with its exact logged byte count. The card receipt records SHA-256 for each file.

Open usability items are save-progress feedback and cancel latency. RAW support and cold-boot operation were outside this JPEG qualification.
