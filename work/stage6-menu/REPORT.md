# Stage 6 Research Synthesis — Autonomy, Continuous-Only Gate & Menu Surface

- **Date:** 2026-11-21
- **Researchers:** Gemini 4 Neon (three parallel read-only tracks: A, B, C)
- **Inputs:** `STATE.md`, `AGENTS.md`, `plans/06-autonomy.md`, `plans/07-persistence.md`, M7 1.00 dumps (`libObj.so`, `libMWF.so`, `libmpr.so`, `libmprctrl.so`, `libsencore.so`, `av-cam.bin`, `vmlinux.bin`, `runtime.txt`), Stage 5 Hardware PASS receipts (`51302f4b3857`, `2ce4db80793d`, `8db652a0245b`), sibling M7A 1.01 static references (`sbin/init`, `bootin.elf`, `launch_shell.elf`, `usbg_sen.ko`, `viewUnified*.so`).
- **Detailed track reports:**
  - Track A (Drive Mode & Format Gate): `work/stage6-menu/research-drivemode-neon.md`
  - Track B (Boot, Menu Surface & Toggle): `work/stage6-menu/research-boot-menu-neon.md`
  - Track C (Self-Discovery, Off-State Silence & Watchdog): `work/stage6-menu/research-autonomy-safety-neon.md`

---

## Summary Verdicts by Stage 6 Research Question (`plans/06-autonomy.md`)

| # | Question | Verdict | Key Evidence |
|---|---|---|---|
| **Q1** | Drive Mode storage & Continuous enum (≥2 confirmations) | **PROVEN** (exact slots & enums) / **GAP** (live `0x005f` vs `0x05bc`) | `CamSetParams` `.bss` singleton at `libObj.so bias + 0x145f3f0` (guard `bias + 0x145f3ec`, `CamStateMgr+0x1a88`). Linear slots `bias + 0x145f3f0 + (paramId - 0x9500)*4` pointing to 8-byte `MWF::ParamStd_Template<int, 7>` updated atomically in-place (`str r1, [r0]`). `PARAMID_DRIVE_MODE_ACT` (`0x9541`, `bias + 0x145f4f4`): `0x005e` Single, `0x005f` Burst (Continuous), `0x05bc` BOL Burst (Blackout-Less Continuous), `0x0c89` Spot/Single Burst (7-shot, refuse). Also contiguous Image Format/Size/Aspect/Quality at `bias + 0x145f5f0..0x145f5fc` (`0x00bd` JPEG, `0x00b3` L/20M, `0x00b9` 3:2). **100% read-only via `pread64` on `/proc/<pid>/mem`, zero `ptrace`.** |
| **Q2** | Cold-boot from SD card & non-flashing menu surface | **PROVEN ABSENT — STOP CRITERIA TRIGGERED** | No PlayMemories/Android/Dalvik (`apps=false`); compiled C `/sbin/init` & `bootin.elf` have no `/etc/init.d`, no hotplug, and zero SD-card reads; `av-cam.bin`, `upm.ko`, and RSA-signed `sauu` updater have no unauthenticated SD auto-exec. Menu UI lives in compiled `.uxc`/`.uxb` + `viewUnified*.so` on `ext2 ro` `/usr`; M7 1.00 `vmlinux.bin` has **zero** `/dev/fb0` framebuffer (`register_framebuffer`/`fbmem`) or `evdev` drivers. Per `plans/06-autonomy.md:45-48`, cold-boot auto-start (`/etc/ld.so.preload` on `nflasha10` or `/setting/mode/preload` on `nflasha2`) and custom menu entries strictly move to **Stage 7**. |
| **Q2 (interim)** | Untethered RAM daemon surviving USB unplug | **HYPOTHESIS (high confidence, 1 HW test needed)** | `setsid()` PID-1 reparenting is proven on M7 (`5e34e221096f`); M7 `libsencore.so` has no `kill`/`killpg` imports and M7A `usbg_sen.ko` only tears down `tty-ldisc-17`. Double-fork + `setsid()` + closing tty fds `0/1/2` should survive `auth.stop()` + USB unplug until power-off with zero flash writes. |
| **Q3** | Persistent toggle before Stage 7 & SD visibility | **PROVEN (mechanism)** / **GAP** (exact Backup/Param ID of chosen item) | Linux VFS does **not** mount the SD card and M7 1.00 `vmlinux.bin` lacks `exfat`; Sony Fsys (`A:\` via `libmpr.so`) is already HW-proven on the user's 128 GB exFAT card. Best on-camera toggle with native Sony UI + power-cycle persistence + zero flash writes: repurpose a capture-benign stock menu setting in NVRAM (`ModelBeepToInstance` / Audio Signals, `ModelGridLineToInstance` / Grid Line, or `ModelRedEyeToInstance` / Red Eye Reduction). Self-timer is **disqualified** (mutually exclusive with Continuous); Smile Shutter is **rejected** (pipeline interference). Physical button combo (`sd_input.c`, 627 keys) or Continuous-always-on are clean zero-side-effect alternatives. |
| **Q4** | Readable "off" state & zero-interference silence | **PROVEN** | All 16 `m7_config` fields are 100% self-discoverable on-camera via `/proc` (`im.elf` PID, `maps`, `monitor_tid` via `comm` or `libMWF+0x4547c`). Deferring `Insert4100` + `mode_set(0x4100)` + `capture_trap_set` behind `(enabled == 1 && drive_mode ∈ {0x005f, 0x05bc} && format == JPEG L 20M 3:2 && half_press)` guarantees **zero `ptrace`, zero traps, zero route changes, zero `sndcmd`** while OFF or in Single Shooting. Measured arming latency with pre-attached `0x4100`: `731–750 ms` (`600 ms` hardcoded `focus_ms` + `131–150 ms` setup); deferred `Insert4100` adds `~1.6–1.75 s` at current poll intervals (tunable). |
| **Q5** | Watchdog & manual recovery without laptop | **PROVEN (design) / GAP (soft power-off under wedge)** | Untethered `retain_unresolved()` must be split into recoverable self-abort (always `capture_trap_restore` + `trace_restore` + release refs + restore `0x1000` before exiting — **never** exit with `0xde01` poked or `im.elf` crashes with `SIGILL`) vs safe-park hard fault. Hard bounds on hold/post/drain/wait + `SIGTERM`/`im.elf` exit/route-drop monitors. Because `/tmp_network` and `im.elf` state are 100% volatile RAM, **battery pull unconditionally restores stock**. |

---

## Toggle Selection Proof — Release w/o Card (`0x01071472`) via `/dev/uipc`

Selected by the user (2026-11-21) for **zero photographic side effects** while an SD card is inserted (no flash pre-flash, no beep, no grid overlay, no EXIF changes, never greyed out in Continuous Shooting, NVRAM-persistent across reboots, addable to My Menu):

- **Backup ID (`0x01071472`):** Verified in sibling M7A `viewUnified2.so` (`CmnViewProcessDataElementCustomReleaseWOCard` vtable `0x9ca34c` → getter `0x5a5bbc` / setter `0x5a5c10` calling `CmnViewModelIfWrapper::backupRead(0x01071472, &byte)` with 1-byte boolean, plus 15 total refs in `viewUnified2.so`, and `CautionConfig.so` `cmnViewSettingNodeRootCustomReleaseWOCard` Enable/Disable property lists at `0xd34138`/`0xd60e58`). *(GAP: exact M7 1.00 live `datasize == 1` and `0` vs `1` mapping for Enable/Disable will be confirmed directly on hardware in WIP v1.)*
- **Zero-ptrace, zero-fork kernel read via `/dev/uipc`:**
  - Verified directly in **M7 1.00 `libosal_uipc.so`** (`17c84895...`, `do_init` `0x210c`, `u_osal_valloc_msg_wait` `0x2870`, `u_osal_snd_sync_msg` `0x2604`, `u_osal_free_msg` `0x28c8`) and corroborated against M7A `libbackup.so` (`backup_sync_msg` `0xf64`, queue `0x3e014d`), `osal_uipc.ko` (`__k_uipc_cdev_ioctl` `0x5a8`, `__k_4u_valloc_msg_wait` `0x10e4`, `__k_4u_snd_sync_msg` `0x137c`, `__k_4u_free_msg` `0x12f4`), and `backup.ko` (`backup_osal_call_func` `0x51fc`: op `0` = `Backup_get_datasize`, op `3` = `Backup_read` using `__copy_to_user`).
  - **Critical ABI detail verified in `osal_uipc.ko` (`0x640..0x650`):** `/dev/uipc` pins `file_priv->tgid` at `open()` and rejects ioctls from another PID/tgid; the daemon MUST open & mmap `/dev/uipc` **after** double-fork.
  - **Critical ABI detail verified in `backup.ko` (`0x1074`):** `Backup_read_4Byte` (op `4`) returns `0` whenever `size != 4`; we MUST check `Backup_get_datasize` (op `0`) `== 1` and use `Backup_read` (op `3`) for 1-byte ID `0x01071472`.
- *(Note: Red Eye Reduction `PARAMID_RED_EYE_REDUCTION_MODE_SET = 0x9606` / `ACT = 0x9607` at `bias + 0x145f808`/`0x145f80c`, `ON = 0x152`, `OFF = 0x153` remains verified in M7 1.00 `libObj.so` as a fallback if ever needed.)*

## Stage 6 Execution Plan (User Decisions Confirmed 2026-11-21)

1. **Confirmed product decisions:**
   - Build the **Stage 6 standalone RAM daemon** (launched via USB, self-discovers `/proc`, survives USB cable unplug until power-off, zero flash writes).
   - Use stock **Release w/o Card** (`BackupID = 0x01071472`) as the Stage 6 ON/OFF toggle.
   - Defer UI rework (dedicated new menu item / custom label) and cold-boot persistence to **Stage 7** once the RAM daemon is stable.
   - Keep `s->committed` cadence optimization (~3 s/frame) queued for later.
2. **WIP v1 (Read-Only Self-Discovering Untethered Daemon Probe — zero `ptrace`, zero traps, zero SD/flash writes):**
   - Built in standalone `prototype-stage6-autonomy/` (zero edits to sealed Stage 5 files).
   - Proves on live M7 1.00 in one ~60-second untethered run: (a) full `/proc` self-discovery, (b) double-fork + `setsid()` daemon survival across `auth.stop()` + physical USB unplug, (c) live `/dev/uipc` `Backup_read(0x01071472)` Enable/Disable values for Release w/o Card, (d) live `CamSetParams` values for Single / Continuous Hi-Mid-Lo (`0x005f` vs `0x05bc`) / JPEG vs RAW+JPEG, and (e) live untethered `sd_input` shutter (`0x1f1`/`0xa7`) & `subscription` (`route[7]`) reads.
3. **WIP v2 (Full Untethered Stage 6 Pre-Capture RAM Daemon):**
   - Combines proven Stage 5 RAM ring + self-discovery + passive OFF/Single loop (0 `ptrace`, 0 traps, 0 `Insert4100`) + Continuous + JPEG L 20M 3:2 + Release w/o Card toggle gate + tiered untethered watchdog/safe-abort.
