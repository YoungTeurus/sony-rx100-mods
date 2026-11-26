# Stage 6 Research (Track B): Card-Boot / Auto-Start, Non-Flashing Menu Surface, and Persistent Toggle

- **Date:** 2026-11-21
- **Role:** Read-only Researcher (Gemini 4 Neon)
- **Scope:** Stage 6 (`plans/06-autonomy.md`) Research Questions 2a, 2b, 3, and Stop Criteria, with boundary mapping to Stage 7 (`plans/07-persistence.md`).
- **Constraints honored:** Strictly offline, read-only inspection of M7 1.00 dumps/receipts, M7A 1.01 unpacked firmware, and reference repos under `sources/`. Zero production edits, zero USB/camera access, zero edits to `evidence/**`.

---

## Executive Verdicts

| Question | Verdict | Summary |
|---|---|---|
| **Q2a: PlayMemories / Android / Dalvik on RX100M7** | **PROVEN ABSENT** | No Android/Dalvik runtime, no PMCA app layer, no mounted `/android/*` partitions, `apps=false` on CXD90045. |
| **Q2a: Stock SD-card cold-boot / autoexec without flashing** | **PROVEN ABSENT** | `sbin/init` and `bootin.elf` are compiled C binaries with no `/etc/init.d`, no hotplug/mdev/udev, and zero SD-card reads/execs. `av-cam.bin`, `upm.ko`, and `0400_updater` have no unauthenticated SD auto-run trigger. Cold boot requires internal flash writes (**Stage 7**). |
| **Q2b: Non-flashing native menu or `/dev/fb0` OSD surface** | **PROVEN ABSENT** (for native menu & `/dev/fb0`); **STOP CRITERIA TRIGGERED** | Stock UI is compiled `.uxc`/`.uxb` + `viewUnified*.so` on read-only `/usr` (`ext2 ro`). M7 1.00 kernel (`vmlinux.bin`) has **no framebuffer driver** (`register_framebuffer` / `fbmem` absent) and **no evdev** (`evdev_connect` absent). Ship USB-launched RAM daemon as Stage 6 interim product; move native menu & cold-boot persistence to Stage 7. |
| **Q2b (Interim Stage 6): Detached RAM daemon surviving USB unplug** | **HYPOTHESIS (untested on hardware)** | Helper runs from volatile tmpfs (`/tmp_network`) with zero flash writes; a daemonized (`setsid`, ignore `SIGHUP`, close tty fds) process should survive `service_stop` + USB disconnect until power-off, but hardware survival across USB unplug has not yet been tested. |
| **Q3: SD card visibility in Linux VFS vs Sony Fsys** | **PROVEN** | Linux VFS **does NOT mount the SD card** (absent from `/proc/mounts`). Live 128 GB card is **exFAT** (`mmca10p1`), and M7 1.00 `vmlinux.bin` has **zero exFAT support**. Sony Fsys (`A:\` via `libmpr.so` `Fsys_Open`/`Fsys_Read`/`Fsys_Close`) is **already proven on hardware** on this exact exFAT card. |
| **Q3: Best persistent toggle before Stage 7** | **PROVEN (mechanism) / GAP (exact Backup IDs)** | Repurposing a capture-benign stock menu setting in NVRAM/Backup (`BKID_APP_MENU_BEEP_SETTING`, `AutoReview`, or `GridLine` via `Backup_read`) gives **native UI + power-cycle persistence + zero flash writes**. SD config file (`A:\PRECAP.CFG` via Sony Fsys) persists across power cycles but cannot be edited on-camera. Self-timer is **disqualified** (mutually exclusive with Continuous Drive Mode); Smile Shutter is **high-risk** (interferes with shooting pipeline). |

---

## Inspected Artifacts and Hashes

| Artifact | SHA-256 | Provenance |
|---|---|---|
| `extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/bin/im.elf` | `ad08a5b12fa344ba595f56c8c9ce12263be4673d15deede1b67f4434309e105a` | Original M7 1.00 |
| `extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/lib/libObj.so` | `38cba88dab492ed8529ae1ec80636bce64d649229ed790023f3579144860a092` | Original M7 1.00 |
| `extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/lib/libmpr.so` | `2b1057ab5069127398fb077fd4bd332cc21e47601b4d19f95d92987e599fbbe0` | Original M7 1.00 |
| `extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/system/av-cam.bin` | `ba62fd6c5654856470b1e327984408857cc1583c9e31cf24ec59b9d2e30f3a3e` | Original M7 1.00 |
| `extracted/m7-kernel-file-20261105T210321Z-78319ef81a60/system/vmlinux.bin` | `fbc91e66ce27ea917041c33c53e038bfc92e0cf8aea6f254f9dae01acefdfaeb` | Original M7 1.00 |
| `extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha7_unpacked/sbin/init` | `d0f099683723acd3c16cfef01f74d6f693f4dacb02e5cc33d2d955331cc0bb60` | Sibling M7A 1.01 (identical to `nflasha3/initrd.img/sbin/init`) |
| `extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked/bin/bootin.elf` | `1f6961bdd69ceba78d660e7f42249ee054431849fb7dfe62c20e57f69fd413c2` | Sibling M7A 1.01 |
| `extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked/bin/launch_shell.elf` | `5561b8f2fe92620e48ba1e4bca8049b24d84392345ac3f888145f6859fe3c526` | Sibling M7A 1.01 |
| `extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked/lib/viewUnified2.so` | `dab4e2a80214e3762676711b586d31a8947186b72c471837a4674e26a480534f` | Sibling M7A 1.01 |
| `extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked/lib/viewUnified4.so` | `d10e926cd4ed50be92937f26ae9413575888af5efc0779e46c4bb559710f9448` | Sibling M7A 1.01 |
| `evidence/m7-probe-20261104T212038Z.json` | `e751bd72500224f77a0711cdf3a6eccc103b11d940cb6052e0c7607af02be490` | Live M7 1.00 hardware receipt |
| `evidence/m7-kernel-inventory-20261105T171038Z-1b3501b7e14f.json` | `24ceceb1e8ca8ca9b538f22e73e1202dc147eee5f06e4b499de4ce7a8aaec488` | Live M7 1.00 hardware receipt |
| `evidence/m7-capture-probe/20261121T082654Z-51302f4b3857.json` | `24afa4d9414e4dd5ef3456a8db63d8e78fe80d7e0496a72b1dda8c4c1c5a1fd3` | Live M7 1.00 Stage 5 PASS receipt |

---

## 1. Q2a — Launching from the SD Card without USB / without Flashing

### 1.1 PlayMemories Camera Apps (PMCA) / OpenMemories / Android / Dalvik — **PROVEN ABSENT**

1. **Live M7 1.00 mounts (`extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/runtime.txt:3-17`, `evidence/m7-probe-20261104T212038Z.json`):**
   Only internal eMMC partitions `nflasha7` (`/`), `nflasha15` (`/usr`), `nflasha10` (`/tmp`, `/etc`), `nflasha3` (`/system`), `nflasha2` (`/setting`), `nflasha18` (`/lens`), `nflasha12` (`/cert`), `nflasha11` (`/log`) and pseudo-filesystems (`proc`, `sysfs`, `devpts`, `tmpfs` `/tmp_ipsec` & `/tmp_network`) are mounted. Neither `/android/system` nor `/android/data` is mounted.
2. **Legacy empty partition slots do not mean Android exists:**
   `extracted/m7a-1.01-fw/firmware.tar_unpacked/0100_config/mount.conf:25-26` (template header `Macro Version: 2011/06/14`) lists `/dev/nflasha16 /android/system` and `/dev/nflasha17 /android/data`, and live M7 1.00 `/proc/partitions` (`evidence/m7-kernel-inventory-20261105T171038Z-1b3501b7e14f.json`) preserves partition table entries `252:16 nflasha16` (143,360 blocks) and `252:17 nflasha17` (102,400 blocks). However:
   - `extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/` contains ONLY `nflasha3`, `nflasha5`, `nflasha7`, and `nflasha15` — zero Android filesystem images.
   - `0800_appli/` contains only `lens/fixed_lensfile.bin`, `setting/{DmmConfig.bin,facedmy.bin,kemco.txt,ulogio.bin,appfw_infra/}`, and `tmp/{config.spec,nsswitch.conf,protocols,services,toprc,images/*.ltt,Sony_DI_Icons.ttf}`.
   - Live M7 1.00 `ps` (`evidence/m7-probe-20261104T212038Z.json`) contains **zero** Android/Dalvik processes (`zygote`, `app_process`, `dalvikvm`, `servicemanager`, `adbd` all absent; kernel `binder` thread PID 62 is a compiled-in kernel remnant with no Android userspace).
   - M7 1.00 `libObj.so` has **0 hits** for `dalvik` or `android`.
   - `sources/pmca-re-reloaded/crates/pmca-app/src/devices.rs:495` confirms `("DSC-RX100M7", Some("CXD90045"), Some(false), Some(CommunityReport::Works))` (`apps=false`).

### 1.2 Stock Linux Boot Chain (`sbin/init` -> `bootin.elf` -> `im.elf` / `launch_shell.elf`) — **PROVEN NO SD-CARD HOOK**

Live M7 1.00 `/proc/cmdline` (`evidence/m7-kernel-inventory-20261105T171038Z-1b3501b7e14f.json`) specifies `rootfstype=ext2 root=/dev/ram0 init=/sbin/init initrd=0x700000,8M`, and live M7 1.00 `ps` (`evidence/m7-probe-20261104T212038Z.json`) shows:
- PID `1`: `launch_shell.el` (`/usr/bin/launch_shell.elf`)
- PID `154`: `bootin.elf`
- PID `160`: `ash`
- PID `161`: `im.elf` (PPID `1`, `runtime.txt:894-898`)

Full static disassembly of the **unstripped** M7A 1.01 `/sbin/init` (`d0f09968...`, byte-identical between `nflasha3/initrd.img` and `nflasha7`) and `bootin.elf` (`1f6961bd...`) proves the exact cold-boot execution path:

1. **No SysV init, no `/etc/init.d/`, no `/etc/rc*`, no `mdev`/`udevd`/`/sbin/hotplug`:**
   - `/sbin/init` is a compiled 32-bit Thumb-2 ELF (`main` @ VA `0x9a10`, 1624 B), NOT a shell-script runner.
   - `nflasha7_unpacked/etc/` is an empty mountpoint (at runtime `/dev/nflasha10` is mounted onto both `/tmp` and `/etc`).
   - Raw `nflasha7` ext2 scan shows only one `init.d`/`rcS` string at file offset `0xb2e4c` (`b'n/sh\x00USER=root\x00RUNLEVEL\x00-s\x00/etc/init.d/rcS\x00'`), which is inside the unused BusyBox `init` applet binary (`/bin/busybox`), never invoked because `/sbin/init` is Sony's native ELF.
   - M7 1.00 `vmlinux.bin` has **0 hits** for `/sbin/hotplug`, `udev`, `mdev`, or `autoexec`.
2. **Exact actions of `sbin/init::main` (`0x9a10..0xa068`):**
   - Sets static env (`HOME=/`, `PATH=/sbin:/bin:/usr/sbin:/usr/bin:/devel/usr/bin`, `TOPRC=/etc/toprc`, `MALLOC_*`).
   - Calls `check_oreore1` (`0x973c`: `check_qemu` + `check_nfs` + `parse_cmdline`).
   - Loads initial storage kmods via `insmod_drivers` (`devno`, `dmac`, `ldec`, `emmc`).
   - Mounts `/rootfs` (`nflasha7`), executes `pivot_root(".", "initrd")` + `chroot(".")`, moves mounts, then mounts `/usr` (`nflasha15`), `/tmp` (`nflasha10`), `/etc` (`nflasha10`), `/system` (`nflasha3`), `/setting` (`nflasha2`), `/log` (`nflasha11`), `/lens` (`nflasha18`), `/cert` (`nflasha12`).
   - **Checked dead table entry:** The `.data` mount table contains a struct at VA `0x137d8` (`"/dev/ms1"`, `"/log"`, `"vfat"`, `"posix_attr"`), alongside unused `/dev/nflasha9 -> /usr/upgrade` (`0x13788`). Direct literal-pool scan of `.text` confirms **0 references** to `0x137d8`, `0x137ec`, or `0x13788`. `sbin/init` never mounts removable media.
   - Calls `check_oreore2` (`0x9750` -> `check_mode_file` @ `0x93b0`, reads **internal flash** `/setting/mode/dmode`).
   - Calls `set_oreore_env` (`0x98b0`, mmaps **internal flash** `/setting/env.txt` and calls `putenv` on key=value lines).
   - Loads remaining Sony kmods via `insmod_drivers` (`osal_utm`, `osal_uipc`, `utimer`, `backup`, `osal_ulogio`, `input`, `udate`, `indctr`, `i2c`, `sircs`, `stream`, `stream2`, `usb_portMonitor`, `usbg_sen`, `usb_extcmd`, `kikilog`, `dmm`, `upm`, `nfc`, `grm_ma`, `grm_gles`, `accel`, `mag`, `compass`, etc.).
   - Calls `check_oreore3` (`0x975c`: `check_bootmode` @ `0x95d8` reading `/proc/udm/upm_bootmode` for `USB_CHARGE`/`ADJUST`/`BIS`, and `check_forced_senser` @ `0x90fc` reading **internal flash** `/setting/sen/smode` for `"UU"`).
   - Optionally sets debug `LD_PRELOAD` (hardcoded `/usr/tool/{libkmcsup.so.2.0.0,libsonyefence.so,libduma.so}`) if enabled by `dmode`.
   - Spawns ONLY `/usr/bin/bootin.elf` (`0x9f6c`/`0x9f74`), `/usr/bin/sen.elf` (`0x9f80`, conditional on forced senser), and `/usr/bin/net_cmdd.elf` (`0x9f86`).
   - Clears `LD_PRELOAD=` (`0x9f9e`) and `execl`s `/usr/bin/launch_shell.elf` (`0x99e0`..`0x99ea`), which unmounts `/initrd`, frees `/dev/ram0`, and loops on `/bin/ash --login` on `/dev/ttycons`.
3. **Exact actions of `bootin.elf` (`1f6961bd...`):**
   - Reads **internal flash** `/setting/mode/dmode` (string VA `0xa24d`, xref `0x9690`) and, if debug preload flag bit is set, reads **internal flash** `/setting/mode/preload` (string VA `0xa6bc`, xref `0x9b74`; matches `/usr/bin/change_mode.sh` `PRELOAD_FILE=/setting/mode/preload`).
   - Builds command line for `/usr/bin/im.elf` (`0x9a46..0x9af8`), runs it via internal `system()` wrapper, then clears `LD_PRELOAD` and `MALLOC_OPTIONS` (`0x9b2a..0x9b3a`).
   - Never accesses `/dev/mmca*`, `/dev/ms1`, or any SD card path.

**Gap noted honestly:** M7 1.00's own `/sbin/init` and `/usr/bin/bootin.elf` are not in `extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/` (which contains 16 selected runtime binaries). However, live M7 1.00 receipts (`runtime.txt`, `m7-probe-20261104T212038Z.json`, `m7-kernel-inventory-20261105T171038Z-1b3501b7e14f.json`) confirm identical PID 1 (`launch_shell.elf`), PID 154 (`bootin.elf`), PID 161 (`im.elf`), identical mount layout, identical kernel cmdline `init=/sbin/init`, and identical kmod loading order.

### 1.3 Other Potential Cold-Boot / Non-Flashing Triggers Checked — **PROVEN ABSENT**

- **RTOS (`extracted/m7-1.00-.../system/av-cam.bin`, 17,293,972 B):** String scan shows **0 hits** for `A:\`, `A:/`, `B:\`, `TWEAK`, `SEN_MODE`, `.SH`, `.ELF`, `AUTOEXEC.BIN`, `BODYDATA`, `SONY_UPD`. The 14 `autoexec` hits are internal C++ class names (`ScalarSequenceJpegStageAutoexec_*`). No SD-card script or binary execution hook exists.
- **`upm.ko` / BootFactor (`reports/m7-upm-boot-factor.md`):** Proven statically from M7 1.00 `upm.ko` (`ab7762e8...`) that BootFactor getter `0x00920111` only reads a 36 B RAM cache (`.data+0x44..0x67`) and returns; `upm.ko` has no SD-card boot trigger or dynamic script hook.
- **Updater partition (`0400_updater/dev/nflasha1_unpacked/boot/initrd.img_unpacked/usr/bin/{UdtrMain.sh,execute_ufp.sh,execute_prod.sh}`):**
  - Updater only boots when internal flash flag `/setting/updater/mode*` exists (or serial boot `/root/IAMLDUDWRT`).
  - Standard modes run `sauu` (`d79af0e6...`), which verifies RSA signatures against `/etc/VerificationKey.pem` (`reports/pmca-access.md:70-77`).
  - `MODE_MSCRYPT` (`sdfileinput.elf`) loads `mcmn_drv.ko`/`mmc_drv.ko`/`ms_drv.ko` to read an update package from media, **ONLY** if `/setting/updater/mode5` was already written to internal flash (`/usr/bin/up.sh` `func_mscrypt`).
  - No Bionz XR-style unprompted `BODYDATA.DAT` SD-card trigger exists in M7/M7A (`0 hits` in `av-cam.bin` and `sdfileinput.elf`).
- **Sibling camera autoexec techniques (`sources/a6400/hook/`, `sources/zv-e10-re/docs/07-modification.md`):**
  - `a6400/hook/autoexec.sh` + `README.md` uses `/etc/ld.so.preload` (supported by glibc `/lib/ld-2.11.2.so`, string verified at `0x412c79` in `nflasha7`).
  - `zv-e10-re/docs/07-modification.md:447-458` documents `/setting/mode/dmode` + `/setting/mode/preload` (`change_mode.sh`).
  - **CRITICAL DISTINCTION:** Both `/etc` (`/dev/nflasha10`, vfat rw) and `/setting` (`/dev/nflasha2`, vfat rw) are **persistent internal eMMC flash partitions**, NOT the SD card and NOT volatile RAM. Using either of them violates Stage 1–6's RAM-only constraint (`STATE.md:58-59`) and therefore belongs to **Stage 7** (where it is actually a very attractive *non-signed-updater* persistence mechanism to evaluate alongside firmware patching!).

### 1.4 Q2a Conclusion
**No non-flashing, zero-flash-write cold-boot from SD card exists on RX100M7 1.00.** Cold boot without USB requires at least one persistent write to internal flash (e.g., `/etc/ld.so.preload` on `nflasha10` or `/setting/mode/preload` on `nflasha2`) — strictly **Stage 7** work.

---

## 2. Q2b — Non-Flashing Menu Surface & Stop Criteria Evaluation

### 2.1 Stock Menu & UI Architecture

1. **Menu code & assets live on read-only `/usr` (`/dev/nflasha15`, ext2 ro):**
   - UI resources in `nflasha15_unpacked/share/app/` are Sony binary `.uxc`/`.uxb` containers (`LayoutMaster_Menu.uxc`, `viewGlobalMenu.uxc`, `viewBaseMenu.uxc`, `viewFnMenu.uxc`, `viewSettingMenu.uxc`, `viewRecDriveMode.uxc`, `viewSmileShutter.uxc`, `string_*.uxc`, `image_*_43.uxc`, `color_cmn.uxc`).
   - UI logic is split across `viewUnified2.so` .. `viewUnified8.so`:
     - `viewUnified2.so` (11.8 MB on M7A; mapped live at `153f1000-15d64000` in M7 1.00 `runtime.txt:663`): owns `viewGlobalMenu`, `viewBaseMenu`, `viewSettingMenu`, `PAS_Menu*`, `CmnZakoMenuUtil`, `CmnMenuTableUtil`, and the input conversion table (`reports/m7-physical-shutter-route.md:5,73`).
     - `viewUnified4.so` (2.9 MB on M7A): exports `ViewFnMenuToInstance`, `ViewRecDriveModeToInstance`, `ViewCustomWBToInstance`, `ViewCustomZebraToInstance`. It is **on-demand / lazy-loaded** — confirmed by live Stage 5 receipts (`evidence/m7-capture-probe/20261121T082654Z-51302f4b3857.json`: `ui_libs: {'viewUnified4_loaded': False}` from `prototype-producer-probe/runner.py:1357`).
     - `viewUnified6.so` (568 KB; mapped live at `199c9000-19a43000` in `runtime.txt:679`).
   - Note also: M7 1.00's own `viewUnified2.so` and `viewUnified4.so` are **not** in `extracted/m7-1.00-.../`.
   - Modifying `.uxc` or `viewUnified*.so` on disk requires `mount -o remount,rw /usr` (internal flash write) and, per `sources/zv-e10-re/docs/07-modification.md:37-46,177-255`, has no safe `.uxc` menu-addition packer (only same-length string/palette patches were demonstrated, and `/usr/share/app` was reported wiped on boot on ZV-E10).
2. **In-RAM menu injection into `viewUnified2.so`:**
   - Not viable without flashing AND high crash risk: would require dumping M7 1.00 `viewUnified2.so` (11.8 MB), reverse-engineering dynamic menu-table structs + `.uxc` string IDs + widget callbacks, and live-patching `im.elf` UI state in RAM. Not minimal and violates Stage 6 scope discipline.
3. **Sidecar `/dev/fb0` OSD overlay (e.g., `sources/a6400/gui/` or `sources/zv-e10-re/docs/SIDECAR_GUI_PROPOSAL.md`) — PROVEN UNSUPPORTED ON M7 1.00 KERNEL:**
   - Although `/dev/fb0` exists as a static ext2 node in M7A `nflasha7` (`0xe1648`) and as a string next to `AV_DDS`/`DdsUserIf` in M7 1.00 `libObj.so` (`0xfddecc`), direct inspection of the actual **M7 1.00 kernel (`extracted/m7-kernel-file-20261105T210321Z-78319ef81a60/system/vmlinux.bin`, SHA-256 `fbc91e66...`)** proves:
     - `register_framebuffer`: **0 hits**
     - `fbmem`: **0 hits**, `fb_open`: **0 hits**, `fb_ioctl`: **0 hits**, `fb_init`: **0 hits**, `fbcon`: **0 hits**
     - `evdev_connect`: **0 hits** (buttons go through Sony `input.ko` + OSAL IPC, not Linux evdev `/dev/input/event*`; matches `sources/a6400/PROJECT_MEMORY.md:62,79`).
   - Live display rendering in `im.elf` goes through the DMP SUGILITE GPU (`/dev/dmpgles2`, `grm_gles.ko`, mapped at `0d586000-0d5a6000` in `runtime.txt:455`), not a Linux framebuffer. `a6400_gui.elf` was never confirmed working on hardware (`sources/a6400/PROJECT_MEMORY.md:62,84,87`).

### 2.2 Explicit Evaluation of Stage 6 Stop Criteria (`plans/06-autonomy.md:45-48`)

> *"If no non-flashing menu surface exists, ship the laptop command as the interim product, note it plainly, and move the menu into stage 7 with the firmware work."*

**VERDICT: STOP CRITERIA EXPLICITLY TRIGGERED.**
1. **No non-flashing custom menu surface exists** on RX100M7 1.00 (no PMCA/Android, no `/dev/fb0` kernel driver, `.uxc` and `viewUnified*.so` live on read-only `/usr`).
2. **No non-flashing cold-boot from SD card exists either** (`sbin/init`, `bootin.elf`, `av-cam.bin`, `upm.ko`, and `0400_updater` never execute user code from the SD card without prior internal-flash modification).

### 2.3 Clean Split: What CAN Ship in Stage 6 (Zero Flash Writes) vs What Strictly Moves to Stage 7

| Capability | Stage 6 (RAM-only, zero flash writes) | Stage 7 (Persistent internal flash / firmware) |
|---|---|---|
| **Start mechanism** | **Laptop USB launch command** (uploads ELF to `/tmp_network` tmpfs, launches helper). **Hypothesis:** daemonizing helper (`setsid()`, ignore `SIGHUP`, close tty fds) lets it **survive `service_stop` + USB cable unplug** until power-off/battery pull (needs 1 hardware test to verify `usbgtertx`/`ash` exit does not kill detached children and normal USB/shooting resumes cleanly). | **Cold boot without USB** via internal flash hook (`/etc/ld.so.preload` on `nflasha10` or `/setting/mode/preload` on `nflasha2`, or patched partition), with SD-card killswitch (`A:\DISABLE.TXT` via Fsys) and documented rollback. |
| **Drive-mode gate** | **Full Continuous-only gate** (Track A) — silent/no-op in Single Shooting; fixes `s->committed` cadence leak and clean RAW+JPEG/size refusal. | Carried forward identically. |
| **On/off toggle** | **Stock camera menu toggle** (repurposing a benign NVRAM setting read via `Backup_read`, e.g., Audio Signals / Auto Review / Grid Line — already has a native Sony menu UI and survives power cycles!) **and/or** physical button combo via `sd_input.c` (already proven on M7 1.00!). | Optional dedicated custom menu label/entry (e.g., patched string/menu resource on `/usr` or UI hook) if a repurposed stock setting is not sufficient. |

---

## 3. Q3 — Persistent Toggle before Stage 7 & Exact SD Card Mount Verification

### 3.1 SD Card Visibility in Linux Userland on RX100M7 1.00 — **PROVEN**

1. **Linux VFS does NOT mount the SD card:**
   Live M7 1.00 `/proc/mounts` (`extracted/m7-1.00-.../runtime.txt:3-17`, `evidence/m7-probe-20261104T212038Z.json`, `evidence/m7-kernel-inventory-20261105T171038Z-1b3501b7e14f.json`) lists ONLY internal eMMC mounts (`nflasha7`, `nflasha15`, `nflasha10`, `nflasha3`, `nflasha2`, `nflasha18`, `nflasha12`, `nflasha11`) plus `proc`, `sysfs`, `devpts`, `/tmp_ipsec`, `/tmp_network`. There is **no** `/mnt`, `/media`, `/sdcard`, or `/dev/mmca*` mount anywhere in Linux VFS.
2. **Block device exists, but Linux kernel CANNOT mount the user's 128 GB exFAT SDXC card:**
   - Live M7 1.00 `/proc/partitions` (`evidence/m7-kernel-inventory-20261105T171038Z-1b3501b7e14f.json`) exposes `250:10 mmca10` (125,173,760 blocks) and `250:11 mmca10p1` (125,157,376 blocks) via `mmc_drv.ko` + `mcmn_drv.ko` (`bdev_mmca`, PID 726).
   - The user's live SD card is **128 GB exFAT** (`evidence/m7-capture-probe/20261121T082654Z-51302f4b3857.json`: `card_before.identity.filesystem = "exfat"`, `size = 128144506880`).
   - Direct inspection of M7 1.00 `vmlinux.bin` (`fbc91e66...`) and M7A `nflasha15/kmod/` proves:
     - `exfat`: **0 hits** in `vmlinux.bin`, no `exfat.ko` in `/usr/kmod/`.
     - Compiled-in filesystems are `vfat` (`fat_fill_super`), `ext2`, `cramfs`, `tmpfs`, `devpts`, `proc`, `sysfs`.
   - Therefore, the `a6400`/`zv-e10` trick (`mount -t vfat /dev/mmca1 /mnt`) **fails on exFAT SDXC cards** (confirmed in `sources/a6400/PROJECT_MEMORY.md:68`), and mounting a live SD block device in Linux VFS while Sony's Fsys/RTOS owns it creates dual-writer filesystem corruption risk.
3. **Sony Fsys (`A:\`) ALREADY works on exFAT and is hardware-proven for BOTH write AND read:**
   - `prototype-producer-probe/README.md:325-366` and `prototype-producer-probe/commit.c:38-199` already implement and have hardware-proven (Stage 5 PASS) full Sony Fsys discovery and file I/O via M7 1.00 `libmpr.so` (`2b1057ab...`):
     - `GetDevicePath` (`libmpr+0x7c54d5` Thumb) -> `/dev/mmca`
     - `Fsys_GetDriveLetter` (`libmpr+0x19e95c` PLT) -> `'A'`
     - `Fsys_GetDriveInfo` (`libmpr+0x19ec4c` PLT) -> type `0x8402`, flags `0`
     - `Fsys_Open` (`libmpr+0x19e828` PLT) -> `flags=1` (read-only), returns `0x80000051` (`FSYS_E_NOTFOUND`) if absent
     - `Fsys_Read` (`libmpr+0x19f614` PLT) -> reads up to 3968 B chunks
     - `Fsys_Close` (`libmpr+0x19dd5c` PLT)
   - Thus, the native helper can read a config file like `A:\PRECAP.CFG` or `A:\PRIVATE\PRECAP.TXT` directly on exFAT or FAT32 with **zero Linux mounts** and **zero filesystem race**.

### 3.2 Comparison of Persistent Toggle Options before Stage 7

| Option | Survives power cycle? | Toggleable on-camera (no laptop)? | Native Sony UI? | Zero flash writes by helper? | Pipeline / UX Risks | Verdict |
|---|---|---|---|---|---|---|
| **A. Stock menu setting in Backup NVRAM** (e.g., **Audio Signals** `BKID_APP_MENU_BEEP_SETTING`, **Grid Line** `ModelGridLineToInstance`, or **Auto Review** `PARAMID_AC_AUTOREVIEW_MODE_*`) | **Yes** (stock camera saves to NVRAM) | **Yes** (Menu / Fn / My Menu) | **Yes** (100% stock UI) | **Yes** (helper only calls `Backup_read` or reads `libObj` RAM) | Minor benign side effect (e.g., beep on/off, grid on/off, or auto-review on/off). Zero capture-pipeline interference. | **RECOMMENDED PRIMARY** (requires small follow-up to confirm exact numeric Backup ID + values on M7 1.00). |
| **B. SD Card config file via Sony Fsys** (`A:\PRECAP.CFG` or `A:\PRIVATE\PRECAP.TXT`) | **Yes** | **No** (needs computer/phone to edit/rename) | No | **Yes** (read-only `Fsys_Open(..., 1)`) | Cannot flip on/off in the field; Stage 5 card verifier refuses unknown non-DCIM files unless allowlisted. | **Good for config/killswitch** (`A:\DISABLE.TXT` in Stage 7), weak as interactive toggle. |
| **C. Physical button combo / long-press via `sd_input.c`** (`libObj.so` `0x145d230`, 627 live keys sampled every 20 ms) | **No** (RAM-only state resets on power cycle) | **Yes** (instant in the field) | No (no OSD feedback unless paired with LED/setting) | **Yes** | Must pick a non-conflicting key combo (e.g., long-press `Delete/C` or `Down` while idle) so stock UI action does not fire unexpectedly. | **RECOMMENDED SECONDARY** (instant RAM toggle if user wants zero side effects on any stock setting, or combined with Option A/B). |
| **D. Self-timer** | Yes | Yes | Yes | Yes | **DISQUALIFIED:** Self-timer is a Drive Mode inside `viewRecDriveMode.uxc` — mutually exclusive with Continuous Shooting. | **REJECTED** |
| **E. Smile Shutter** (`PARAMID_AGENT_SMILE_SHUTTER_MODE*`) | Yes | Yes | Yes | Yes | **HIGH RISK:** Actively arms face/smile auto-shutter and interacts with Drive Mode / RAW restrictions on Sony bodies. | **REJECTED** |
| **F. Memory Recall (`MR` dial slot `1`/`2`/`3`)** | Yes | Yes (mode dial) | Yes | Yes | Consumes an entire MR preset slot (locks exposure/AF/drive settings together), though clean for users who dedicate MR3 to "Pre-Capture". | **Optional power-user alternative**, not general on/off toggle. |

### 3.3 Evidence for `Backup_read` Accessibility on M7 1.00
- `Backup_read` is directly imported in M7 1.00 `im.elf` (`PLT 0x8ea8`) and M7 1.00 `libObj.so` (alongside `Backup_read_4Byte`, `Backup_read_multi`, `Backup_read_setting_attr`), backed by `/usr/lib/libbackup.so` (mapped at `040d5000-040d7000` in `runtime.txt:160`), and invoked by standalone `/usr/bin/bk.elf` (which links `libbackup.so`, `libosal_uipc.so`, `libosal_utm.so`).
- Therefore, the helper can read a stock Backup setting **either** directly from its own standalone process via `libbackup.so` / OSAL IPC (without even ptrace-stopping `im.elf`!) **or** by reading the live cached setting in `libObj.so` RAM (just like Track A's drive-mode read).

---

## 4. Open Gaps (Honest Inventory)

1. **M7 1.00 `/sbin/init` and `/usr/bin/bootin.elf` binaries were not dumped:** Init disassembly (`0x9a10..0xa068`, `0x9a20..0x9b80`) is from sibling **M7A 1.01**. Live M7 1.00 `ps`, `/proc/cmdline`, and `/proc/mounts` confirm the same process topology (`launch_shell.elf` PID 1, `bootin.elf` PID 154, `im.elf` PID 161), but exact M7 1.00 offsets in `bootin.elf` are not independently verified. (Does not affect the Q2a negative conclusion because live M7 1.00 mounts and `vmlinux.bin` independently rule out SD-card mounts/autoexec.)
2. **USB disconnect / daemon survival on M7 1.00 is untested on hardware:** We have proven `im.elf` shoots normally while a tmpfs native process runs during a service shell (`reports/M7_LIVE_ACCESS.md`, Stage 5 PASS), and `service_stop` exits service mode cleanly. We have **not** yet proven on hardware that a double-forked / `setsid()` RAM daemon in `/tmp_network` stays alive after `terminal_disable` + `service_stop` + physical USB cable unplug, and that `im.elf` remains fully responsive afterward.
3. **Exact numeric Backup IDs / RAM offsets for Audio Signals (`BKID_APP_MENU_BEEP_SETTING`), Auto Review, and Grid Line on M7 1.00:** Confirmed present by symbol/string in M7 1.00 `libObj.so`, but their exact numeric IDs / RAM getters (and whether `Backup_read` works out-of-process from our static helper or should be read from `libObj.so` RAM) require a brief targeted lookup once the user/orchestrator picks the preferred toggle setting.
4. **Physical button keycodes for RX100M7 custom/menu keys (`C`, `Delete/?`, `Fn`) in `sd_input.c`:** `sd_input.c` already maps all 627 keys in `libObj.so` `0x145d230`, but Stage 5 only filtered/logged shutter/remote keys (`0xa7`, `0x1f1`, `0x1f4`, `0x1a00000d`, `0x1a00000e`). If Option C (button combo) is chosen, one quick key-table dump from M7 1.00 `libObj.so` or a live press log is needed to pin the exact keycode.

---

## 5. Reproduction Commands Used

```sh
# 1. Verify M7A init ELF identity & disassemble main/boot checks
.venv-analysis/bin/python -c "
import hashlib
for p in [
  'extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha7_unpacked/sbin/init',
  'extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha3_unpacked/initrd.img_unpacked/sbin/init',
]:
  print(p, hashlib.sha256(open(p,'rb').read()).hexdigest())
"

# 2. Verify M7 1.00 kernel lacks exfat, fbmem/register_framebuffer, evdev_connect, hotplug/mdev/udev
.venv-analysis/bin/python -c "
import re
data = open('extracted/m7-kernel-file-20261105T210321Z-78319ef81a60/system/vmlinux.bin', 'rb').read()
for kw in [b'exfat', b'vfat', b'fbmem', b'register_framebuffer', b'fb_open', b'evdev_connect', b'/sbin/hotplug', b'mdev', b'udev']:
    print(kw.decode(), len(re.findall(re.escape(kw), data, re.I)))
"

# 3. Verify M7 1.00 live mounts, partitions, and exFAT SD card
sed -n '1,18p' extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/runtime.txt
.venv-analysis/bin/python -c "
import json
inv = json.load(open('evidence/m7-kernel-inventory-20261105T171038Z-1b3501b7e14f.json'))['inventory']
print(inv['partitions'])
s5 = json.load(open('evidence/m7-capture-probe/20261121T082654Z-51302f4b3857.json'))
print('card fs:', s5['card_before']['identity'], 'ui_libs:', s5['ui_libs'])
"
```
