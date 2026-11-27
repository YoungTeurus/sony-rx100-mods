# Stage 7 — Persistent Native-Menu Pre-Capture (LIVE HARDWARE PASS)

Status: **LIVE HARDWARE PASS (Stage 7.2, Stage 7.3 Phase A, and Stage 7.3 Phase B)** on original **Sony DSC-RX100M7** firmware **1.00** (`29110_03.2021050601`) as of 2026-11-28.

Stage 7 completes the full product goal on RX100M7 1.00:
1. **Native 7th `Mods` Menu Tab** (`Pre-Capture` submenu with dedicated **Mod Status: ON / OFF** and **Pre-Frames: 1 / 2 / 3 / 5 / 8 / 10**, leaving **Release w/o Card** 100% stock).
2. **Remembered User Settings** persisted atomically in `/setting/mlv2_precap.cfg` (`S7PC1 <0|1> <N>\n`) across power switches and battery removals.
3. **Owner-Authenticated SD Package (`MLV2.TAR`)** verified via freestanding ARM32 `HMAC-SHA256` + `SHA-256` directly from `/dev/mmca1` (FAT32 / exFAT).
4. **Untethered Persistence Across Both S2R (Power Switch) and WBI (Battery Pull)** with zero modifications to factory WBI snapshots, kernel (`vmlinux.bin`), `initrd.img`, `/usr`, or `Backup.bin`.

---

## Milestone Summary

| Sub-stage | Scope | Hardware Verdict | Details |
|---|---|---|---|
| **Stage 7.1** | Freestanding `mlv2` shim + PIC core + `PreCapture.mod` + zero-`ptrace` `stage7_daemon.elf` + `stage7_ring.elf` | **OFFLINE PASS** | [REPORT-stage7-1-impl.md](../work/stage7-persist/REPORT-stage7-1-impl.md) |
| **Stage 7.2 (r7)** | Live native 7th `Mods` tab, live menu editing, 29 verified 20MP JPEGs across 2 bursts, clean `mlv2_guard.elf uninstall` (RAM-only) | **LIVE HARDWARE PASS** | [REPORT-stage7-2-hw.md](../work/stage7-persist/REPORT-stage7-2-hw.md) |
| **Stage 7.3 Phase A (r7+r9)** | Owner-authenticated SD `MLV2.TAR` (`204,928 B`) + remembered state restoration before first `MENU` open + hot-removal retirement (RAM-only) | **LIVE HARDWARE PASS** | [REPORT-stage7-3a-hw.md](../work/stage7-persist/REPORT-stage7-3a-hw.md) |
| **Stage 7.3 Phase B** | Persistent `/tmp_bt` runtime + zero-dependency `mlv2_sd_boot_hook.so` (`/usr/bin/bsa_server` post-WBI/S2R trigger) + live `LD_PRELOAD` smoke-gated installer + normal & shell-free `FileControl` uninstall | **LIVE HARDWARE PASS** | [REPORT-stage7-3b-persist.md](../work/stage7-persist/REPORT-stage7-3b-persist.md) · [Sanitized Install Receipt](../evidence/stage7-phaseb-install-receipt.json) |

---

## How Phase B Works on RX100M7 1.00

Empirical power-transition probes (Steps B1–B5) established two decisive RX100M7 1.00 behaviors:
- **Ordinary Power Switch = Suspend-to-RAM (S2R):** `im.elf` stays resident in RAM; `/tmp_network` is wiped and remounted on every suspend/resume, whereas **`/tmp_bt` stays mounted completely untouched** (`mount_id` and inodes preserved across S2R).
- **10 s Battery Pull = Warm Boot Image (WBI) Snapshot Resume:** `im.elf` (PID 161, `starttime=105`) is restored from the factory WBI snapshot without re-running `/lib/ld-2.11.2.so`. When standard **Bluetooth Function = On** is enabled in the camera menu, Sony's `startBTCore.sh` automatically mounts `/tmp_bt` and runs `execve("/usr/bin/bsa_server")` after both WBI battery-pull resume (~21 s after boot) and S2R resume.

Phase B uses this stock lifecycle with minimal flash footprint (5 small files total):
- `/setting/mlv2_sd_boot_hook.so` (`2,436 B`, `-nostdlib -shared -fPIC`, zero `DT_NEEDED`, zero undefined symbols, 11 verified M7 kernel syscalls): returns after a single `readlink("/proc/self/exe")` for every process except `/usr/bin/bsa_server`, then double-forks `/bin/busybox sh /setting/mlv2_sd_boot.sh` without delaying `bsa_server`.
- `/setting/mlv2_card_read.elf` (`13,760 B`): freestanding FAT32/exFAT + `HMAC-SHA256` verifier reading `/setting/mlv2_owner.key` (`32 B`, `0600`) and extracting authenticated `MLV2.TAR` into `/tmp_bt/mlv2/`.
- `/setting/mlv2_sd_boot.sh` (`19,213 B`): BusyBox 1.13.4-strict worker expanding `/tmp_bt` to 4 MiB, maintaining an S2R-safe live `.boot.lock` + 2-strike MMC debounce monitor loop, restoring `/setting/mlv2_precap.cfg`, and leaving the camera 100% stock (6 tabs) whenever SD is absent or `MLV2.OFF` is present.
- `/etc/ld.so.preload` (single line `/setting/mlv2_sd_boot_hook.so`): written LAST by `scripts/m7_stage7_phaseb_install.py --mode install` **only after** a live on-camera `LD_PRELOAD=/setting/mlv2_sd_boot_hook.so /bin/busybox sh -c 'echo PRELOAD_SMOKE_OK'` check succeeds.

### Live Hardware Checks Passed (2026-11-28)
1. **Supervised install:** `INSTALL_OK=True`, `LIVE_PRELOAD_SMOKE_PASSED=True` (`0.084 s`), `post_preload_sanity_ok=True` (`0.058 s`), `terminal_disable_verified=True`.
2. **Battery pull (10 s, WBI) with SD card:** 7th `Mods` tab (`Pre-Capture`) appeared untethered with no USB.
3. **Ordinary power switch (S2R) + live capture:** `/tmp_bt` workspace, `Mods` tab, and `Pre-Capture = ON` survived S2R; live burst pre-capture frames saved cleanly.
4. **Second battery pull (10 s, WBI):** `Mods` tab returned automatically and remembered saved `ON` and `Pre-Frames` state.
5. **Boot without SD card:** 100% stock 6-tab Sony menu.
6. **Hot SD re-insertion after no-SD boot:** `Mods` menu appeared automatically and restored saved Pre-Capture state.
