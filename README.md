# Sony DSC-RX100M7 Persistent Pre-Capture Mod (Stage 7.3 Phase B)

Untethered, **battery-pull persistent** JPEG **Pre-Capture** with a **native 7th `Mods` menu tab** for the original **Sony DSC-RX100M7** running stock firmware **1.00** (build `29110_03.2021050601`, Linux `3.0.27` ARM).

Once installed (one-time 5-file setup — zero modifications to factory WBI, kernel, `initrd.img`, `/usr`, or `Backup.bin`):
- **Survives both Power Switch (S2R) and Battery Removal (WBI):** turns on automatically with your signed SD card (`MLV2.TAR`), no phone or laptop needed.
- **Native 7th `Mods` Menu Tab:** configure **Pre-Capture ON / OFF** and **Pre-Frames (`1 / 2 / 3 / 5 / 8 / 10`)** directly inside the camera's own menu. Settings are remembered across power cycles and battery swaps (`/setting/mlv2_precap.cfg`), and stock **Release w/o Card** stays untouched.
- **True Zero-Card-Write Ring Buffer:** half-press in Continuous Shooting tracks focus and rolls full-resolution `5472 × 3648` JPEGs inside camera RAM (evicting the oldest frames) with **zero SD card writes during the hold**. Full-press saves the last `N` pre-shutter frames plus hold-driven post-shutter frames as `PC*.JPG` files in the SD card root; releasing half-press cancels cleanly with zero files written.
- **Instant Return to Stock:** remove the SD card (or place an empty `MLV2.OFF` file at SD root) and the camera boots 100% stock (6 tabs). Re-inserting the SD card automatically re-enables the `Mods` tab with your saved settings.
- **Safe & Reversible:** includes a mandatory live `LD_PRELOAD` smoke test before writing `/etc/ld.so.preload`, a one-command `--mode uninstall`, and a shell-free `--mode emergency-filecontrol-uninstall`.

> [!WARNING]
> **Experimental camera firmware modification — use at your own risk.**
> - Targets **ONLY** original **Sony DSC-RX100M7** firmware **1.00** (build `29110_03.2021050601`). Does **NOT** support DSC-RX100M7A (`1.01`) or other camera models; both host preflight and on-camera version/code-pin checks abort immediately on any mismatch.
> - **Stage 7.3 Phase B writes 5 small files to internal flash** (`/setting/mlv2_*` + `/etc/ld.so.preload`). Factory WBI, kernel, `initrd.img`, `/usr`, and `Backup.bin` are never modified. If you prefer **zero flash writes**, use the RAM-only [Stage 6](#ram-only-alternative-stage-6-zero-flash-writes) workflow below.
> - **Current qualification scope:** JPEG L 20M 3:2 (`5472 × 3648`) in Continuous Shooting with SD card inserted. RAW capture and non-20M formats are intentionally passed through passively as stock shooting.

---

## Project Progress (2026-11-28)

| Stage | Scope | Hardware Verdict | Details |
|---|---|---|---|
| **Stages 1–4** | Physical shutter trigger, cancel, AF lock, 14.98 fps burst window | **PASS** | [results/stages-1-5.md](results/stages-1-5.md) |
| **Stage 5** | Rolling RAM-only JPEG buffer, zero hold-time card writes, stock shooting parity | **PASS (7/7)** | [results/stages-1-5.md](results/stages-1-5.md) |
| **Stage 6 (WIP v3 HW3 r3)** | Untethered RAM-only daemon, fast two-phase cadence, hold-driven post, 20 verified JPEGs in Run #4b (zero flash writes) | **HARDWARE PASS** | [results/stage-6.md](results/stage-6.md) · [REPORT-wip3-hw4.md](work/stage6-menu/REPORT-wip3-hw4.md) |
| **Stage 7.2 (r7)** | Native 7th `Mods` tab + `Pre-Capture` submenu (`ON/OFF`, `Pre-Frames`), 29 verified JPEGs (RAM-only) | **HARDWARE PASS** | [REPORT-stage7-2-hw.md](work/stage7-persist/REPORT-stage7-2-hw.md) |
| **Stage 7.3 Phase A (r7+r9)** | Owner-authenticated SD `MLV2.TAR` (`HMAC-SHA256`) + remembered settings restoration before first `MENU` open (RAM-only) | **HARDWARE PASS** | [REPORT-stage7-3a-hw.md](work/stage7-persist/REPORT-stage7-3a-hw.md) |
| **Stage 7.3 Phase B** | **Battery-pull (WBI) + Power-switch (S2R) persistent SD auto-boot via `/tmp_bt` + `mlv2_sd_boot_hook.so` + live smoke-gated installer + rollback** | **HARDWARE PASS** | [results/stage-7-status.md](results/stage-7-status.md) · [REPORT-stage7-3b-persist.md](work/stage7-persist/REPORT-stage7-3b-persist.md) · [Install Receipt](evidence/stage7-phaseb-install-receipt.json) |

---

## Install Pre-Capture on a Clean Sony DSC-RX100M7 (Firmware 1.00)

You do **not** need Sony firmware dumps, `clang`, `ld.lld`, or `capstone` to install the sealed pre-built Phase B release (`prototype-stage7-persist/out-phaseb-persist/`).

### 1. Host Setup (macOS / Linux)

1. Clone this repository and create a Python **3.9+** virtual environment:
   ```sh
   git clone https://github.com/YoungTeurus/sony-rx100-mods.git
   cd sony-rx100-mods
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```
2. Clone [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) at the exact audited commit required by [scripts/m7_probe.py](scripts/m7_probe.py):
   ```sh
   mkdir -p sources
   git clone https://github.com/ma1co/Sony-PMCA-RE.git sources/sony-pmca-re
   git -C sources/sony-pmca-re checkout a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0
   ```
3. Verify the sealed Phase B artifacts offline (zero USB access):
   ```sh
   python3 -B scripts/m7_stage7_phaseb_install.py --mode dry-run
   ```
   Confirm `"status": "DRY_RUN_OK"`.

### 2. Prepare Your SD Card (Generates Your Personal Owner Key)

Insert your camera's formatted SD card into your computer (e.g. `/Volumes/RX100M7` on macOS or `/media/$USER/RX100M7` on Linux) and run:
```sh
python3 -B scripts/m7_stage7_phaseb_install.py --mode prep-sd \
  --sd-root /Volumes/RX100M7 \
  --owner-key ~/.m7-phaseb-owner.key \
  --create-owner-key \
  --clear-disable-markers
```
- Creates your private 32-byte HMAC-SHA256 signing key at `~/.m7-phaseb-owner.key` (`0600`, outside the repo). **Keep a backup of this key** so you can sign additional SD cards later (omit `--create-owner-key` for extra cards).
- Writes the signed `MLV2.TAR` (`204,928 B`) atomically to the SD card root and verifies its SHA-256 readback without touching `DCIM/`.
- Safely eject the SD card and insert it back into the camera.

### 3. Configure the Camera

On the RX100M7:
1. Verify firmware is **1.00**: `Menu → Setup (toolbox) → Version → Ver. 1.00`.
2. Enable Bluetooth (**required for automatic post-WBI startup after battery removal**):
   `Menu → Network → Bluetooth Settings → Bluetooth Function → On`.
3. Set USB mode to Mass Storage:
   `Menu → Setup → USB Connection → Mass Storage`.
4. For Pre-Capture shooting:
   - **File Format:** `JPEG`, **JPEG Image Size:** `L:20M`, **Aspect Ratio:** `3:2`.
   - **Drive Mode:** `Continuous Shooting` (`Hi` / `Mid` / `Lo`).

### 4. One-Time Flash Install Over USB

Power on the camera (with the prepared SD card inserted), connect it to your computer via USB (screen shows USB Mass Storage mode), and run (`"$HOME"` expands to your home directory in your shell before `sudo` executes):
```sh
sudo .venv/bin/python3 -B scripts/m7_stage7_phaseb_install.py --mode install \
  --owner-authorized-flash \
  --owner-key "$HOME/.m7-phaseb-owner.key"
```
What this command does automatically:
1. Confirms live camera identity is **DSC-RX100M7** build `29110_03.2021050601`.
2. Uploads the 4 `/setting/mlv2_*` files to `.new` staging paths via Sony `FileControl`, verifies every byte via readback, sets permissions (`755` / `600`), and moves them atomically into place.
3. Runs a **mandatory live smoke test** (`LD_PRELOAD=/setting/mlv2_sd_boot_hook.so /bin/busybox sh -c 'echo PRELOAD_SMOKE_OK'`). If this fails for any reason, it aborts **before** touching `/etc/ld.so.preload`.
4. Only after the smoke test passes, writes `/etc/ld.so.preload`, runs a post-preload sanity check (`POST_PRELOAD_OK`), verifies via `FileControl` readback, and writes a JSON receipt under `work/stage7-persist/phaseb-install/`.

Confirm the output ends with:
```text
INSTALL_OK=True
LIVE_PRELOAD_SMOKE_PASSED=True
```
*(Note: `SERVICE_STOP_TRANSPORT_OK=False` on `StopSenser` is normal on RX100M7 1.00 because the USB gadget disconnects immediately on stop.)*

### 5. First Autonomous Boot & Daily Usage

1. **Unplug USB**, turn the camera **OFF**, **remove the battery for ~10 seconds**, reinsert the battery (with your prepared SD card inside), and turn the camera **ON**.
2. Wait **~25–30 seconds** on the first boot after a battery pull (Bluetooth's `bsa_server` launches ~21 s after WBI resume and triggers our loader).
3. Press **MENU** and scroll right past My Menu to the new **7th tab (`Mods`) → `Pre-Capture`**:
   - Set **Mod Status** = `ON`.
   - Set **Pre-Frames** = `1`, `2`, `3`, `5`, `8`, or `10`.
4. **Shoot untethered:**
   - **Pre-Capture SAVE:** In `Continuous Shooting`, hold the shutter halfway (~1–10 s to fill and roll the RAM ring), then press fully and hold for post-shutter frames. Release and wait for card save to finish — both the `N` pre-shutter frames and all hold-driven post-shutter frames from that burst are saved together as `PC*.JPG` files in the **SD card root** (outside `DCIM/`, so view them on a computer/phone rather than stock in-camera Playback).
   - **Pre-Capture CANCEL:** Hold halfway, then release without full-press (~12 s drain; writes 0 files).
   - **Power Switch (S2R):** Turning the camera off/on with the normal power switch keeps `/tmp_bt`, the `Mods` tab, and your daemon running immediately with zero 25 s wait.
   - **Battery Pull (WBI):** Changing batteries automatically reloads `Mods` (~25–30 s after power-on) and restores your last saved `ON/OFF` and `Pre-Frames` state.
   - **Instant Stock Mode:** Boot without the SD card (or put an empty `MLV2.OFF` file at SD root) for 100% stock 6-tab behavior. Re-inserting the SD card brings `Mods` back automatically.

---

## Uninstall & Emergency Recovery

### Clean Normal Uninstall (Return Camera to 100% Stock)

Connect the camera via USB in **Mass Storage** mode and run:
```sh
sudo .venv/bin/python3 -B scripts/m7_stage7_phaseb_install.py --mode uninstall \
  --owner-authorized-flash
```
This removes our entry from `/etc/ld.so.preload` first (preserving any unrelated entries), deletes all `/setting/mlv2_*` files (including `/setting/mlv2_precap.cfg`), runs `sync`, and verifies every file is absent. Power-cycle / pull battery for 10 s afterward.

### Emergency Shell-Free Recovery (`FileControl` Only)

Because factory WBI is untouched, `im.elf` resumes from WBI without re-parsing `/etc/ld.so.preload`, and Sony's `SONY_PFUNC_FileControl` runs in-process inside `im.elf` without spawning a shell. If shell access is ever unavailable, connect via USB Mass Storage and run:
```sh
sudo .venv/bin/python3 -B scripts/m7_stage7_phaseb_install.py --mode emergency-filecontrol-uninstall \
  --owner-authorized-flash
```
This writes and verifies `/setting/disable_sd_boot` (disarming the hook immediately) and deletes `/etc/ld.so.preload` plus the 4 `/setting/mlv2_*` files without enabling the serial terminal.

---

## Sealed Stage 7.3 Phase B Release (`prototype-stage7-persist/out-phaseb-persist/`)

| File | Destination | Size | SHA-256 |
|---|---|---:|---|
| `mlv2_sd_boot_hook.so` | `/setting/mlv2_sd_boot_hook.so` | 2,436 B | `0cae4d4a0264952ad4ce0ef3a6f5764f8ad743d9c1e2ce6c6d034c0820281c32` |
| `mlv2_card_read.elf` | `/setting/mlv2_card_read.elf` | 13,760 B | `1f8bbd8fe627a24a4c115d8fdd7d6033eb8bfd40964b8de26c7082a5d4752b0f` |
| `mlv2_sd_boot.sh` | `/setting/mlv2_sd_boot.sh` | 19,213 B | `87cf24059f352d110e6624d9d41f75a1fd30e128eef0d61c5dc7631502e0f93f` |
| `card.ustar` | Signed into SD `/MLV2.TAR` (`204,928 B`) | 204,800 B | `ccd01c1f175351fc8e85bef3fea536917d48e8e969395df97db0874522ac1697` |

---

## RAM-Only Alternative: Stage 6 (Zero Flash Writes)

If you want to try Pre-Capture with **zero flash modifications** (everything runs in `/tmp_network` RAM and vanishes on power-off, using **Menu → Release w/o Card** as the ON/OFF switch):
```sh
sudo .venv/bin/python3 -B scripts/m7_stage6_precapture.py --start \
  --before 5 --after 0 --burst-cap 24 --post-max 15 --backlog-cap 96 --duration-sec 600
```
Disconnect USB, shoot untethered, then reconnect USB to retrieve logs and clean RAM:
```sh
sudo .venv/bin/python3 -B scripts/m7_stage6_precapture.py --collect
```
See [results/stage-6.md](results/stage-6.md) and [work/stage6-menu/HANDOFF.md](work/stage6-menu/HANDOFF.md) for full Stage 6 details.

---

## Offline Verification & Rebuilding from Source

### Immediate Checks (No Camera or Extracted Sony Firmware Needed)

1. **Verify sealed Phase B pre-built artifacts** (Python stdlib only):
   ```sh
   python3 -B scripts/m7_stage7_phaseb_install.py --mode dry-run
   ```
2. **Stage 6 hardware receipt cross-checks** (stdlib only):
   ```sh
   python3 tools/check_run.py 2
   python3 tools/check_run.py 4b
   ```
3. **Pure C ring-buffer unit tests** (`prototype-ring/`):
   ```sh
   cc -Wall -Wextra -Werror -std=c99 -I prototype-ring/src \
     prototype-ring/src/pre_capture.c \
     prototype-ring/tests/test_pre_capture.c \
     -o /tmp/test_pre_capture && /tmp/test_pre_capture
   ```
4. **Stage 6 sealed manifest checks:**
   ```sh
   .venv/bin/python3 -B -c "
   import sys; sys.path.insert(0, 'prototype-stage6-autonomy')
   import build_stage6 as b1, build_stage6_v2 as b2
   b1.verify_seal(); print('SEAL_V1_OK')
   b2.verify_seal(); print('SEAL_V2_OK')
   "
   ```

### Full From-Scratch Rebuild of Stage 7 Phase B (Developers)

Rebuilding all ARM binaries from source and running the full 125-test offline verification suite (`unicorn`, `capstone`, `clang` with `armv7-none-eabi`, `ld.lld`) requires your own camera's extracted M7 1.00 firmware libraries and kernel map under `extracted/` and `evidence/m7-kernel-analysis/` (Sony proprietary binaries are never redistributed here). Once placed locally:
```sh
.venv/bin/python3 -B prototype-stage7-persist/build_stage7_phaseb_persist.py
.venv/bin/python3 -B scripts/m7_stage7_phaseb_install.py --self-test
.venv/bin/python3 -B -m unittest discover -s prototype-stage7-persist -p 'test_stage7*.py'
```

---

## Repository Layout

- `prototype-stage7-persist/` — Stage 7 freestanding ARM C sources (`mlv2_sd_boot_hook.c`, `mlv2_card_read.c`, `mlv2_phaseb_sd_boot.sh`, `shim.c`, `core.c`, `precap_mod.c`, `mlv2_guard.c`, `stage7_daemon.c`, `stage7_ring.c`), reproducible builders (`build_stage7_phaseb_persist.py`, `build_stage7_sd.py`, `build_stage7.py`), offline Unicorn/shell/CLI test suites (`test_stage7*.py`), and sealed releases (`out-phaseb-persist/`, `out-sd/`, `out/`, `out-phaseb/`).
- `scripts/m7_stage7_phaseb_install.py` — Standalone Phase B CLI (`--mode dry-run`, `prep-sd`, `install`, `uninstall`, `emergency-filecontrol-uninstall`).
- `prototype-stage6-autonomy/`, `prototype-ring/`, `prototype-producer-probe/` — Stage 5–6 RAM-only pre-capture sources, ring state machine, and sealed ELFs.
- `scripts/` — Audited USB service transport, terminal framing, identity gates, and Stage 6/7 CLIs.
- `evidence/` — Sanitized Run #2, Run #4b, and Stage 7.3 Phase B install receipts (no personal photos or private keys).
- `results/` — Milestone summaries: [stages-1-5.md](results/stages-1-5.md), [stage-6.md](results/stage-6.md), [stage-7-status.md](results/stage-7-status.md).
- `plans/` & `work/` — Stage specifications, ARM/WBI/S2R research reports, and hardware verification records.

## Intentionally Excluded Files

- **Sony proprietary firmware binaries** (`extracted/`, `downloads/`) — not redistributed for copyright reasons.
- **Third-party `Sony-PMCA-RE`** (`sources/sony-pmca-re/`) — clone directly from upstream at commit `a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0`.
- **Owner HMAC signing keys** (`*.key`) and **personal photos / raw USB probe logs** — never committed.
