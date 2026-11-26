# Stage 6 WIP v3 Build & Verification Report

Date: 2026-11-22  
Target: Sony DSC-RX100M7 (firmware 1.00, unmodified)  
Baseline commit: `92b08cb827ceba39709018b520841a8f628d39ea`  
Independent Review Verdict: **GO for Live Hardware Run #3** (`REVIEW-wip3-astra-r5.md`, internal archive)

---

## 1. Summary of WIP v3 Capabilities

1. **Variant A Two-Phase Hybrid Fast Cadence (`stage6_ring.c`):**
   - **Phase 1 (Burst):** Holds software S2 continuously at full stock Continuous Hi parity (`~15–20 fps`) until the upstream queue reaches `--burst-cap` (`C_burst`, default `24`, range `8..60`).
   - **Phase 2 (Sustained Rolling):** Hysteresis controller `[low_water, burst_cap]` (`low_water = max(before + 1, burst_cap - 3)`) sustaining `~3.3–3.8 fps` rolling with zero blind gaps for 60+ s holds.
   - **Async S2 Command Control (`s6_s2_spawn` / `s6_s2_poll_once`):** Strict child-reaping state machine checking `wait4 == pid`; never declares teardown complete while an S2 child is unreaped (fails closed `218/11` on kill failure or `-ECHILD`), and unifies reaped nonzero/killed S2-down/S2-up recovery via compensating synchronous `sender(o, 2, 0)` (including when overlapping a prior cancel `reason=4`).
2. **Hold-Driven Unbounded Post Window (`--after 0` default) & Configurable Pre (`--before 1..15`, default `5`):**
   - Continues capturing post frames while physical `full == 1` stays held, up to `--post-max` (default `48`, range `1..96`) and upstream queue limit `backlog_cap - 12` (`--backlog-cap`, default `96`, range `24..128`).
   - Frozen pre+post selections are preserved in `PRECAP_POST` and `PRECAP_DRAIN` even if the user continues holding physical `full == 1` past the cutoff (late unselected frames fast-drop without triggering `reason=12`).
   - Fixed `after > 0` windows cut short by safety limits (H-2 single-slot guard, queue cap, disarm, or 30 s POST timer) preserve and save all captured frames cleanly and explicitly report partial completion (`savedFlag=0, reason=13`, plus `post_cutoff_cause` and requested `after` in `SUMMARY`/`CADENCE`/`WINDOW`). Truly empty selections report `reason=8`.
3. **Fast Unselected Drop (`~1–3 ms` dwell) & Fast Save (`~0.6 s/photo`):**
   - Unselected frames bypass `ram_candidate`, `hold_acquire`, and Trap #3 (`0xa126d8`), jumping directly `Trap #1 (0xa14c98) -> 0xa153d2 -> Trap #2 (0xa146f6, r1=frame+0x2938) -> re-arm Trap #1`.
   - Selected frames preserve H-2 single-slot ownership (`held_owned <= 1`), pool-length-safe backward-chain validation (`s6_retained_state` up to `4096` nodes; `precap_pool_closed` up to `512` inert nodes), and fast 8 KiB stack `memcpy` (`0x10d8dc`).
   - Redundant SHA-256 readback eliminated; replaced with strict ISO/IEC 10918-1 `SOF0/SOF1/SOF2` + `SOS` + `EOI` structural validation (`s6_fast_jpeg_inspect`) with exact host parity (`stage6_v2_runner.py:inspect_jpeg_file`), strict `5472x3648` JPEG L 20M 3:2 enforcement, MPF trailing screennail exclusion, and 24-bit non-colliding `PCxxxxxx.JPG` naming (`255` unique files/run).
   - Unconditional `hold_unlock` + clean SD route restoration (`reason=7`, zero leaked locks/refs/traced threads) on all known pre-write save refusals (transient busy pool lock, malformed/wrong-resolution/truncated JPEG, pre-existing destination file `status=5`, `OpenFile(7)` error). Indeterminate `CloseFile` (`51`/`52`) and permanently wedged `s6_hold_release` (`41/1`) remain fail-closed.
4. **Coordinated 3-Tier Shutdown Supervision (`stage6_ring.c`, `stage6_daemon.c`, `stage6_v2_runner.py`):**
   - `S6_SAVE_BUDGET_MS = 60,000 ms` (checked only when an actual selected frame awaits saving, avoiding spurious `reason=14` on late unselected frames after window completion).
   - `S6_SINGLE_SAVE_TIMEOUT_MS = 30,000 ms` (`< RING_STOP_WAIT_MS = 35,000 ms`, fail-closed `218/22` on hung single-file I/O).
   - `PRECAP_DRAIN_ABSOLUTE_MS = 180,000 ms` + worst-case `30.900 s` bounded post-SUMMARY SD restoration retries + latency margin `< RING_STOP_HARD_MAX_MS = 240,000 ms` `< collector max_polls = 250`.
   - Daemon isolation preserved: 1 RX `PT_LOAD`, 0 writable globals, 158/158 resolved `svc 0` sites with 0 `ptrace` (26), full native config validation parity with `build_stage6_v2.py`.

---

## 2. Independent Review History (Codex Astra, `serviceTier=default`)

| Round | Verdict | Outcome | Report |
|---|---|---|---|
| r1 | NO-GO | Found 6 blockers (unreaped S2 child, held-full `reason=12` erasing frozen selection, short fixed post reporting `savedFlag=1`, `hold_lock` leak & `218/19` park on recoverable refusals, weak SOF/SOS checks, 180 s timeout mid-save) + 4 secondary items. All fixed. | `REVIEW-wip3-astra-r1.md` |
| r2 | NO-GO | Found 5 edge cases (cancel overlapping failed S2 child, fixed-window 30 s timer discarding pre-frame, mixed-latency save crossing 90 s daemon cap, SOF2+baseline SOS & host RST parity, 85 s hold spurious `reason=14` on unselected frame). All fixed. | `REVIEW-wip3-astra-r2.md` |
| r3 | NO-GO | All 5 r2 findings PASS; found 140 s daemon cap < 180 s ring drain envelope on slow-develop 158.6 s drain & 152.2 s held drain. Raised daemon cap to 210 s / collector 220 polls. | `REVIEW-wip3-astra-r3.md` |
| r4 | NO-GO | All 3 r3 counterexamples PASS; found worst-case 179.8 s drain + 30.900 s bounded SD-restore retries = 210.841 s crossing 210 s cap by 832 ms. Raised daemon cap to 240 s / collector 250 polls (`stage6_ring.elf` byte-identical to r3/r4). | `REVIEW-wip3-astra-r4.md` |
| **r5** | **GO** | **ALL checks PASS** (`bounded` 210.841 s reaped at 210.859 s with `29.150 s` margin, `78,074/78,074` packets, `r_reap=1, r_sav=2`; `stuck` caught at 180.009 s with `r_unres=1, r_flt=1`; 30/30 tests; 6/6 byte-for-byte reproducibility; 158/158 `svc 0`, 0 `ptrace`). | `REVIEW-wip3-astra-r5.md` |

---

## 3. Sealed Release Artifacts (`prototype-stage6-autonomy/out-v2/`)

All 6 artifacts verified via `build_stage6_v2.verify_seal()` and byte-for-byte independent `-Os` temporary rebuild:

| File | SHA-256 |
|---|---|
| `build.json` | `1dcb42c0237100786a6e1bd29a002ee7a7e3d311521557ab4df2d78e2ccc41ef` |
| `sony_pins.h` | `05d5403c404849b2291b08bb842bec1ed8e5c252ec24208cea599ed3278559de` |
| `stage6_daemon.elf` | `cdb29883c5b9ed40920b9cfca09502aadd430a5a373abcf5528d735c3280be20` |
| `stage6_daemon.o` | `0138bf7b112c38b16183cf123bc3f2b1a43eddb2ba8e99f46d905a0ab920981d` |
| `stage6_ring.elf` | `2b0e4344c5453b294145b659ae7087d2a3828495cee4e91fedb622ba9b003718` |
| `stage6_ring.o` | `9015d781968386c07ccb2a60f53345866eb1fdb1a1aed05545023ba9cac0b4d1` |

---

## 4. Verification Status & Exact Commands

| Check | Status | Proof |
|---|---|---|
| Sealed build & 6-file byte-for-byte reproducibility | **PASS** | `build_stage6_v2.verify_seal()` + temp-dir rebuild matched 6/6 files identically |
| Daemon isolation & zero `ptrace` | **PASS** | 1 RX `PT_LOAD` (`36,631 B`), 0 writable sections, 158/158 `svc 0` resolved, 0 syscall 26 |
| Public test suites (`test_stage6_v2.py` + `test_stage6_probe.py`) | **PASS** | **22/22** v2 tests + **8/8** v1 tests = **30/30 PASS** |
| Independent Astra r5 offline replays | **PASS** | `bounded`, `bounded-short`, `near`, `stuck`, `latency`, r3 supervision replays, watchdog, collector |
| Real Sony RX100M7 primary JPEG preservation & header rejection | **PASS** | `9,385,509 B` primary saved byte-exact; single-byte SOF2/P=12/RST corruptions rejected by both |
| Cross-writer `Fsys_Open(flags=7)` exclusivity on Sony firmware | **INCONCLUSIVE** | Imported PLT stub in `libmpr.so` (`0x19e828`); relies on single-writer assumption while `0x4100` active |
| Live camera Run #3 (actual fps, save speed, SD restore, unplug) | **INCONCLUSIVE** | Offline ARM emulation only; awaiting user-operated Live Hardware Run #3 |

Commands executed:
```sh
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=prototype-stage6-autonomy
.venv-analysis/bin/python3 -B prototype-stage6-autonomy/build_stage6_v2.py
.venv-analysis/bin/python3 -B prototype-stage6-autonomy/test_stage6_v2.py
.venv-analysis/bin/python3 -B prototype-stage6-autonomy/test_stage6_probe.py
```
