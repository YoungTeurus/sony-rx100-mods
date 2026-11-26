# Sony DSC-RX100M7 RAM Pre-Capture (Stage 6)

Untethered, RAM-only JPEG pre-capture implementation, build tooling, offline ARM verification suites, and hardware qualification results for the original **Sony DSC-RX100M7** running stock firmware **1.00** (build `29110_03.2021050601`, Linux `3.0.27` ARM).

With the Stage 6 daemon running in camera RAM and the USB cable disconnected:
- **Half-press** in Continuous Shooting tracks focus and rolls full-resolution `5472 × 3648` JPEGs inside camera RAM (evicting the oldest frames) with **zero card writes during the hold**.
- **Full-press** commits the last `N` pre-shutter frames plus hold-driven post-shutter frames directly to the SD card as standard `PC*.JPG` files.
- **Releasing half-press without full-press** discards the ring cleanly and writes **zero files**.
- **OFF or Single Shooting** stays 100% passive (`0` `ptrace`, `0` traps, stock camera behavior).

> [!WARNING]
> **Experimental RAM-only camera software — use at your own risk.**
> - Targets **ONLY** original **DSC-RX100M7** firmware `1.00` (`29110_03.2021050601`). Both host preflight and on-camera code-pin checks abort immediately on any mismatch.
> - **Zero flash writes:** everything runs from `/tmp_network` (1 MiB `tmpfs` RAM) and disappears on `--collect` or a power cycle / battery pull.
> - **Current qualification scope:** JPEG L 20M 3:2 with SD card inserted. RAW capture, dedicated custom menu items, and cold-boot persistence without per-boot USB startup are outside Stage 6 (see [Stage 7 status](results/stage-7-status.md)).

---

## Current Project Progress (2026-11-26)

| Stage | Scope | Hardware Verdict | Details |
|---|---|---|---|
| **Stages 1–4** | Physical shutter trigger, cancel, AF lock, 14.98 fps burst window | **PASS** | [results/stages-1-5.md](results/stages-1-5.md) |
| **Stage 5** | Rolling RAM-only JPEG buffer, zero hold-time card writes, return to stock shooting | **PASS (7/7)** | [results/stages-1-5.md](results/stages-1-5.md) |
| **Stage 6 · WIP v1** | Self-discovering read-only untethered RAM daemon + `/dev/uipc` BackupID toggle proof | **PASS** | [REPORT-wip1-hw.md](work/stage6-menu/REPORT-wip1-hw.md) |
| **Stage 6 · WIP v2.1** | First full untethered RAM pre-capture (`N=2, M=1`, Run #2: 3 verified JPEGs) | **PASS** | [REPORT-wip2-hw2.md](work/stage6-menu/REPORT-wip2-hw2.md) · [Run #2 evidence](evidence/run-2-events.log) |
| **Stage 6 · WIP v3 (HW3 r3)** | Fast two-phase cadence, hold-driven post, fast verified JPEG save, full `ptrace` `-ESRCH` hardening (**Run #4a tethered + Run #4b untethered: 5 pre + 15 post = 20 verified `5472×3648` JPEGs, `197,827,393 B`, clean cancel, clean teardown**) | **HARDWARE PASS** | [results/stage-6.md](results/stage-6.md) · [REPORT-wip3-hw4.md](work/stage6-menu/REPORT-wip3-hw4.md) · [Run #4b evidence](evidence/run-4b-events.log) |
| **Stage 7** | Cold-boot firmware persistence + native menu items (`Pre-Capture ON/OFF`, `Pre-Capture Count N`) | **IN PROGRESS (offline only)** | [results/stage-7-status.md](results/stage-7-status.md) · [Stage 7 Report](work/stage7-persist/REPORT.md) |

---

## Stage 6 Architecture

Stage 6 uses a **two-ELF freestanding ARM architecture** under [prototype-stage6-autonomy/](prototype-stage6-autonomy/) with zero external libc dependencies:

1. **`stage6_daemon.elf`** ([stage6_daemon.c](prototype-stage6-autonomy/stage6_daemon.c), `36,631 B`, single RX `PT_LOAD`, zero writable globals, **0 `ptrace` syscalls**):
   - Double-forks and `setsid()`s into camera RAM (`/tmp_network/.m7-s6-<nonce>/`) so it survives USB service-mode exit and physical USB cable disconnect.
   - Self-discovers `im.elf` PID, all 5 shared library load biases, private VMAs, `mwf_monitor_inp` TID, `CamSetParams` drive/format state, `InfraInput` physical shutter rows, and `Spinal` subscription state directly via `/proc`.
   - Reads the stock **Release w/o Card** setting (`BackupID = 0x01071472`, `0 = Enable / Pre-Capture ON`, `1 = Disable / OFF`) via an isolated `/dev/uipc` worker process (`Backup_read`).
   - Stays completely passive (`0` `ptrace`, `0` traps) whenever the toggle is OFF, Drive Mode is not Continuous (`0x5f`), format is not JPEG L 20M 3:2, or live view is inactive.
   - Spawns `stage6_ring.elf` lazily only on a debounced physical half-press (`--debounce-ms`, default `100 ms`) while the gate is open, and supervises it with a coordinated watchdog and clean nonce-file stop (`/tmp_network/.m7-s6-<nonce>/stop`).

2. **`stage6_ring.elf`** ([stage6_ring.c](prototype-stage6-autonomy/stage6_ring.c), `122,980 B`, RX + RELRO config segment):
   - Verifies **291 firmware 1.00 code pins** against live `im.elf` memory before touching any state.
   - Routes captures into Sony's stock RAM media (`0x4100`) during half-press hold and manages the pre-capture ring via [prototype-ring/src/pre_capture.c](prototype-ring/src/pre_capture.c).
   - **Two-phase cadence (Variant A):** Phase 1 continuous burst up to `--burst-cap` (default `24`), followed by smooth sustained rolling (`~3–4 fps`, zero blind gaps) for long holds.
   - **Hold-driven post-capture (`--after 0`):** continues capturing post frames for as long as full-press remains held, up to `--post-max` (default `48`, qualified at `15` in Run #4b).
   - **Fast verified JPEG commit:** 8 KiB stack-buffered copy with strict ISO `SOI`/`SOF0–2`/`SOS`/`EOI` validation (matching host [inspect_jpeg_file](prototype-stage6-autonomy/stage6_v2_runner.py#L625)) writing non-colliding `PCxxxxxx.JPG` files to SD drive `A:`.
   - **HW3 Hotfix r3 `ptrace` hardening:** exactly 3 `ptrace` `svc #0` instructions in the entire image, bounded `-ESRCH` retries with revocation re-checks before `Insert4100` and pre-S1 continue, and unambiguous `(stage, errno)` diagnostics (see [HANDOFF.md](work/stage6-menu/HANDOFF.md) and [REVIEW-wip3-hw3fix-astra-r3.md](work/stage6-menu/REVIEW-wip3-hw3fix-astra-r3.md)).

### Sealed Run #4b Binaries (`prototype-stage6-autonomy/out-v2/`)

| File | Size | SHA-256 |
|---|---:|---|
| `stage6_daemon.elf` | 36,631 B | `cdb29883c5b9ed40920b9cfca09502aadd430a5a373abcf5528d735c3280be20` |
| `stage6_ring.elf` | 122,980 B | `ee931ac970d299e4c77306db12102fe65bcc2e5ec453bd05a3586aa8e00a6820` |
| `build.json` | 23,670 B | `f33c2649730fd385d125455e2758f6b9ae84bf1ca9687031941b84920581b982` |

Both binaries and `build.json` are preserved **byte-for-byte verbatim** from Hardware Run #4b (`ddaaac4`).

---

## Running Stage 6 on a Real Sony DSC-RX100M7 (Firmware 1.00)

### 1. Host Prerequisites

- Python **3.9+** (tested on macOS with `sudo` for libusb access; Linux requires appropriate udev rules or `sudo`).
- Install Python dependencies:
  ```sh
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  ```
- Clone [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) at the exact audited commit required by [scripts/m7_probe.py](scripts/m7_probe.py):
  ```sh
  mkdir -p sources
  git clone https://github.com/ma1co/Sony-PMCA-RE.git sources/sony-pmca-re
  git -C sources/sony-pmca-re checkout a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0
  ```
- Verify the sealed build manifest before touching hardware:
  ```sh
  python3 -B -c "import sys; sys.path.insert(0, 'prototype-stage6-autonomy'); import build_stage6_v2 as b; b.verify_seal(); print('SEAL_V2_OK')"
  ```

### 2. Camera Setup

1. Insert a formatted SD card with free space.
2. Set **File Format** = `JPEG`, **JPEG Image Size** = `L:20M`, **Aspect Ratio** = `3:2` (`5472 × 3648`).
3. Set **Drive Mode** = `Continuous Shooting` (Hi / Mid / Lo).
4. Set **USB Connection** = `Mass Storage`.
5. Use **Menu → Release w/o Card** as the Stage 6 toggle (**Enable** = Pre-Capture ON, **Disable** = Pre-Capture OFF). Consider adding it to **My Menu** for quick toggling.
6. Power on the camera and connect it via USB in normal Mass Storage mode (not updater/service mode).

### 3. Untethered Pre-Capture Workflow (Run #4b Configuration)

1. **Upload and start the autonomous RAM daemon** (takes ~3 minutes over Sony's serial USB console; verifies `md5sum`, daemonizes, exits USB service mode):
   ```sh
   sudo .venv/bin/python3 -B scripts/m7_stage6_precapture.py --start \
     --before 5 --after 0 --burst-cap 24 --post-max 15 --backlog-cap 96 --duration-sec 600
   ```
   Wait until `DAEMON_STARTED` and `RESULT=...` print with exit code `0`.

2. **Disconnect the USB cable and shoot untethered:**
   - **Pre-Capture SAVE:** With `Release w/o Card = Enable` and `Continuous Shooting`, hold the shutter halfway (~2–10 s to fill and roll the RAM ring), then press fully and hold for post-shutter frames. Release and wait for the card write activity to finish (~30–45 s for 20 JPEGs; note there is no on-screen save progress bar yet).
   - **Pre-Capture CANCEL:** Hold halfway, then release without pressing fully (wait ~12 s for drain/teardown; writes 0 files).
   - **Stock shooting:** Switch `Release w/o Card = Disable` or switch Drive Mode to `Single Shooting` — the daemon stays passive with zero interference.

3. **Reconnect USB (Mass Storage) to stop cleanly, retrieve logs, and clean camera RAM:**
   ```sh
   sudo .venv/bin/python3 -B scripts/m7_stage6_precapture.py --collect
   ```
   Wait for `COLLECT_SUMMARY: ok=True ... cleanup=GONE`. (Powering off the camera also clears RAM immediately; `--collect` will detect a stale state and clean the local marker.)

4. **Verify saved `PC*.JPG` files against the daemon log (read-only, no USB service mode):**
   Mount the SD card (e.g. `/Volumes/RX100M7`) and run:
   ```sh
   .venv/bin/python3 -B scripts/m7_stage6_precapture.py --check-card-only \
     --card /Volumes/RX100M7 \
     --log work/stage6-menu/wip2/<timestamp>-<nonce>-daemon.log
   ```

### Optional Diagnostics

- **Tethered live-streaming diagnostic** (streams every `STATE`, `RING_EVT`, `RING_FILE`, and `UNRESOLVED` line in real time over USB while shooting):
  ```sh
  sudo .venv/bin/python3 -B work/stage6-menu/diag_tethered_v3.py
  ```
- **Read-only observation probe (WIP v1, zero `ptrace`, zero shutter interception):**
  ```sh
  sudo .venv/bin/python3 -B scripts/m7_stage6_probe.py --start --duration-sec 180
  # Unplug USB, toggle modes/shutter, reconnect USB:
  sudo .venv/bin/python3 -B scripts/m7_stage6_probe.py --collect
  ```

### Known Stage 6 Operational Limits

- **No on-screen save progress indicator yet:** after releasing a 20-frame burst, saving finishes in ~33 s and ring exit in ~47 s without a stock UI busy bar.
- **Cancel drain latency:** releasing a half-press without full-press takes ~12 s for Sony's virtual-media teardown (`Pullout4100` + drain).
- **Per-boot USB start & JPEG-only lock:** requires `--start` after each reboot and intentionally refuses RAW / non-20M 3:2 modes.

---

## Offline Verification & Rebuilding from Source

### Checks Runnable Immediately (No Camera or Firmware Required)

1. **Hardware receipt cross-checks** (stdlib only):
   ```sh
   python3 tools/check_run.py 2
   python3 tools/check_run.py 4b
   ```
   Add `--jpeg-dir /path/to/PC_JPEGs` if you have the original saved JPEGs locally.

2. **Pure C ring-buffer unit tests** (`prototype-ring/`):
   ```sh
   cc -Wall -Wextra -Werror -std=c99 -I prototype-ring/src \
     prototype-ring/src/pre_capture.c \
     prototype-ring/tests/test_pre_capture.c \
     -o /tmp/test_pre_capture && /tmp/test_pre_capture
   ```

3. **Sealed build manifest verification (WIP v1 + WIP v3):**
   ```sh
   .venv/bin/python3 -B -c "
   import sys; sys.path.insert(0, 'prototype-stage6-autonomy')
   import build_stage6 as b1, build_stage6_v2 as b2
   b1.verify_seal(); print('SEAL_V1_OK')
   b2.verify_seal(); print('SEAL_V2_OK')
   "
   ```

4. **WIP v1 ARM Unicorn emulation suite (8/8 tests) & from-scratch rebuild** (requires `unicorn`, `capstone`, and `clang` with `armv7-none-eabi` target):
   ```sh
   .venv/bin/python3 -B prototype-stage6-autonomy/build_stage6.py
   .venv/bin/python3 -B prototype-stage6-autonomy/test_stage6_probe.py
   ```

### Full From-Scratch Rebuild of `stage6_daemon.elf` & `stage6_ring.elf` + Full 23-Test Suite

Rebuilding `stage6_ring.elf` from scratch and running `test_stage6_v2.py` (23/23 tests) regenerates `out-v2/sony_pins.h` by slicing the 291 firmware-verification signatures directly from **your own camera's** extracted firmware 1.00 shared libraries (`libObj.so`, `libmpr.so`, `libmprctrl.so`, `libMWF.so`, `libosal_uipc.so`, `libpthread-2.11.2.so`). Sony's proprietary binaries are **not redistributed** in this repository.

Place the 6 extracted libraries matching the SHA-256 constants in [prototype-producer-probe/build.py](prototype-producer-probe/build.py#L18-L29) under `extracted/`, then run:
```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python3 -B prototype-stage6-autonomy/build_stage6_v2.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python3 -B prototype-stage6-autonomy/test_stage6_v2.py
```

---

## Repository Layout

- `prototype-stage6-autonomy/` — Stage 6 freestanding ARM C sources (`stage6_daemon.c`, `stage6_ring.c`, `stage6_probe.c`, `stage6_v2_common.h`), custom ARM ELF relocator/builders (`build_stage6_v2.py`, `build_stage6.py`), host runners (`stage6_v2_runner.py`, `stage6_runner.py`), Unicorn ARM test suites (`test_stage6_v2.py`, `test_stage6_probe.py`), and sealed ELFs (`out-v2/`, `out/`).
- `prototype-ring/` — Pure C99 pre-capture ring state machine (`src/pre_capture.{c,h}`) and host unit tests (`tests/test_pre_capture.c`).
- `prototype-producer-probe/` — Stage 5 native ARM camera-control modules included by `stage6_ring.c` plus the pin-range definitions (`build.py`).
- `scripts/` — User CLI entrypoints (`m7_stage6_precapture.py`, `m7_stage6_probe.py`) and audited USB/terminal/identity modules (`m7_probe.py`, `m7_burst_identity.py`, `m7_terminal_*.py`, etc.).
- `tools/` — Standalone offline receipt & JPEG structure checkers (`check_run.py`, `capture_analysis.py`).
- `evidence/` — Published Run #2 and Run #4b event log excerpts and SD card readback receipts (metadata and hashes only; no personal photographs).
- `results/` — Concise milestone summaries: [stages-1-5.md](results/stages-1-5.md), [stage-6.md](results/stage-6.md), [stage-7-status.md](results/stage-7-status.md).
- `plans/` — Stage specifications: [06-autonomy.md](plans/06-autonomy.md), [07-persistence.md](plans/07-persistence.md).
- `work/stage6-menu/` — Stage 6 technical reports, cadence analysis, independent r3 review, operator handoff/telemetry decoder, tethered diagnostic script, and ARM reverse-engineering notes.
- `work/stage7-persist/` — Stage 7 offline feasibility report, recovery assessment, menu symbol inspector (`inspect_stock_menu.py`), and reference file SHA-256 manifest (`m7-1.00-files.sha256`).

## Intentionally Excluded Files

- **Sony proprietary firmware binaries** (`extracted/`, `downloads/`) — not redistributed for copyright reasons.
- **Third-party `Sony-PMCA-RE`** (`sources/sony-pmca-re/`) — clone directly from upstream at commit `a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0`.
- **Personal photographs & raw USB service-session JSONs** (`work/stage6-menu/wip*/`) — omitted for privacy; sanitized logs and per-file SHA-256 readback receipts are published under `evidence/`.
