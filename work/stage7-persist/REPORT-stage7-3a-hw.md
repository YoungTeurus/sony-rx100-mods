# Stage 7.3 Phase A Live Hardware Report — SD-Card Auto-Boot & Remembered State (RAM-Only, Zero Flash Writes)

Date: 2026-11-27  
Camera: **DSC-RX100M7** firmware **1.00** (`29110_03.2021050601`)  
Status: **LIVE HARDWARE PASS (100% RAM-only, zero camera flash writes, zero camera SD writes)**

## 1. Sealed Release Tested (r7 Part A + r9 Part B — Both Independent Sol GO)

- Part A (menu persistence, v2 shim, `core.bin`, daemon, guard): Sol r7 **GO** ([REVIEW-stage7-3a-sol-menu-r7.md](REVIEW-stage7-3a-sol-menu-r7.md))
  - `prototype-stage7-persist/out/build.json`: `7a3ab88cf59c8551a2f64a7243aea7070d09222c272fe5ed08d442fbb85772f7`
  - `PreCapture.mod` (`564 B`): `208b5aa074017f078816a2a173471f38d1af55bfa90672c1eb757a91fa6d4356`
  - `shim.bin` (`1,864 B`): `2d7e470d94819f29c460bbcc9a8a2022f09f2f66db314a02fa2950879fad031b`
  - `core.bin` (`18,484 B`): `83ed0915faf5ba8715720867ec05395dbd8e3aa4be505624672ecc1377baa018`
  - `mlv2.req` (`1,992 B`): `379a359ec218b97caa9d37ab6fed7b25164312fb412d444d61787ddb7f571e12`
  - `mlv2_guard.elf` (`16,800 B`): `f1c634067075345d2386127c77cbfebca5bc53fdf6dcd623feaa43fff41cf61b`
  - `stage7_daemon.elf` (`30,340 B`): `ae990a999a864758ef9d6221aa890b6d1f14e3a7bf59e117fd508e4e0657e6dd`
  - `stage7_ring.elf` (`122,980 B`): `ee931ac970d299e4c77306db12102fe65bcc2e5ec453bd05a3586aa8e00a6820`
- Part B (bare ARM exFAT/FAT32 reader, BusyBox SD boot worker, Phase A CLI): Sol r5 + r9 **GO** ([REVIEW-stage7-3a-sol-sd-r5.md](REVIEW-stage7-3a-sol-sd-r5.md), [REVIEW-stage7-3a-sol-sd-r9.md](REVIEW-stage7-3a-sol-sd-r9.md))
  - `prototype-stage7-persist/out-sd/mlv2_card_read.elf` (`13,768 B`): `4aed6c1c511123d4d3abc30d3808ef681923507dea2c326412de739502082757`
  - `prototype-stage7-persist/out-sd/mlv2_sd_boot.sh` (`17,139 B`): `7e580aad8da187034ca07d5ae724360cadd7374669a4e9c4390634b064e9bffa`
  - `prototype-stage7-persist/out-sd/card.ustar` (`204,800 B`): `7c110dd396398045458ce7e9c411d3abc5ead319089334ecfb32bdc3ee0e881f`
  - `prototype-stage7-persist/out-sd/build-sd.json`: `be4cb3a6952826de8e42b7094689541ffc7e5090751d16c598543016982f28c1`
  - `scripts/m7_stage7_sd_probe.py`: `007c993c4f108ac5263208bafb3c2e88a3c8153b66308a24cb76893cf93574db`

## 2. Live Hardware Evidence & Receipts

### Step A1 — Owner-Authenticated SD Package (`--prep-card`) — PASS
- Target: `/Volumes/RX100M7/MLV2.TAR` (`204,928 B`, `release_seq=1`, `key_sha256_prefix=f45e46d9e1289390`).
- Signed package SHA-256: `e5db7d251154c458f424382aeffd364e6ee3eb27c4b2ab169defc8f9fb6c562d`.
- Readback verification passed; `DCIM/` untouched; owner key stored locally at `work/stage7-persist/.sd-phase-a.key` (`0600`, gitignored).

### Step A2 — Read-Only SD & Boot Telemetry Probes (`--boot-probe`) — PASS
1. **Run 1** ([20261127T150047Z-a5657d9d6703-boot-probe.json](sd-phase-a/20261127T150047Z-a5657d9d6703-boot-probe.json)):
   - Live 128 GB SDXC exFAT partition (`/dev/mmca1`, major `250`, minor `11`): `DEV_OK=1`, `FS_TYPE=exFAT`, `BPS=512`, `SPC=256` (128 KiB clusters), `TOTAL_SECTORS=250314752`, `DATA_LBA=32768`, `ROOT_CLUSTER=4`, `MLV2_FOUND=1`, `MLV2_BYTES=204928`, `MLV2_DATA_LEN=204928`, `DISABLE_MARKERS=0`.
   - Live bare ARM `mlv2_card_read.elf` HMAC-SHA256 verification: `present_rc=0`, `verify_rc=0`, `verified_ok=true`.
   - `/tmp_network` tmpfs idle `statfs64`: `bsize=4096`, `blocks=256`, `bfree=252`, **`free_bytes=1,032,192`** (`1,008 KiB` free of `1,024 KiB`).
   - Stock flash state: `/etc/ld.so.preload` absent, `/setting/mode` empty, `/tmp_network` contains only `dhcpd` and `run`.
   - Boot diagnostics: `boot_id=28321e77-82dc-4178-9baa-9099c7f86bbf`, `uptime=66.84 205.83`, `cmdline` has `warm.mode=2`, `cmpr.path=/system/sabin/ssboot.bin`, `pm.ddr_ctrl=sref`; `dmesg` recorded **`[LIRO]: liro resume (WBI)`**, `entry_resume:635c6078(1)`, `PM: resume of devices complete after 0.638 msecs`, SD detected at `1.448–1.665 s` (`mmca10: p1`).
   - Userspace processes (outside USB ash): only PID `1` `/usr/bin/launch_shell.elf` (`st=0`), PID `154` `/usr/bin/bootin.elf` (`st=99`), PID `160` `/bin/busybox` (`st=103`), PID `161` `/usr/bin/im.elf` (`st=105`).
   - Cleanup: `probe_dir_cleanup="GONE"`, `flash_writes_performed=false`, `sd_writes_performed=false`.
2. **Run 2 after power cycle & suspend/resume** ([20261127T152506Z-ae390576af24-boot-probe.json](sd-phase-a/20261127T152506Z-ae390576af24-boot-probe.json)):
   - Confirmed `/tmp_network` returned to stock (`dhcpd`, `run` only, `free_bytes=1,032,192`) and `card_auth_check.verified_ok=true`.
   - Key Phase B observation: `boot_id=291d2369-ae2e-44eb-b484-e74ab8a89eff` (changed from Run 1), `uptime=591.06 2070.29`, `dmesg` recorded **`[LIRO]: liro resume` (without `(WBI)`)**, `entry_resume:635c6078(0)`, while `im.elf` remained PID `161` with `starttime=105`.

### Step A3 — End-to-End SD Boot Worker (`--ram-start` on r9) — PASS
- Earlier Run 1 on r5 ([20261127T150328Z-f3774a6bb2c0-ram-start.json](sd-phase-a/20261127T150328Z-f3774a6bb2c0-ram-start.json)) exposed a real-kernel `/proc/mounts -> self/mounts` symlink mismatch in `mount_ok()`; fixed in r8/r9 and independently approved by Sol r9 ([REVIEW-stage7-3a-sol-sd-r9.md](REVIEW-stage7-3a-sol-sd-r9.md)).
- Live r9 run ([20261127T152635Z-a900597b36e4-ram-start.json](sd-phase-a/20261127T152635Z-a900597b36e4-ram-start.json)):
  - Seeded simulated persistent preference `/tmp_network/mlv2/sim-setting-precap.cfg = "S7PC1 1 8\n"`.
  - `mlv2_sd_boot.sh` exited `0` with complete boot log:
    `MLV2_SD_START build=29110_03.2021050601` -> `MLV2_IM_PID=161 im_st=105` -> `MLV2_PRECAP_RESTORED=S7PC1 1 8` -> `MLV2_GUARD_INSTALL_BEGIN` -> `MLV2_SD_INSTALLED` -> `MLV2_SD_READY daemon_pid=2991`.
  - `/tmp_network` `statfs64` after full deployment: `bfree=187`, **`free_bytes=765,952`** (`748 KiB` remaining free; deployed footprint ~`232 KiB`).
  - `precap.cfg` exact MD5 verified: `262f27a70fa26918c7900229479f9bc8  /tmp_network/mlv2/precap.cfg` (`S7PC1 1 8\n`).
  - Initial `daemon.log` proved **pre-MENU armed startup**: `BOOT self_pid=2991 ... pre_f=8 post=0 bcap=24 pmax=48 deb=100`, `STATE t=76 ... drive=0x5f ... pre_f=8 ... elig=1 tog=1`.
  - Note (host CLI polish item): host check `scripts/m7_stage7_sd_probe.py:651` flagged the trailing `\n` in `precap_cfg_after_boot` (`'S7PC1 1 8\n'` vs `'S7PC1 1 8'`) even though exact-byte MD5 matched; camera-side boot and daemon startup completed cleanly.

### Step A4 — Untethered Camera Qualification & Collect (`--ram-collect`) — PASS
- **Collect #1** ([20261127T153125Z-a900597b36e4-ram-collect.json](sd-phase-a/20261127T153125Z-a900597b36e4-ram-collect.json), [daemon.log](sd-phase-a/20261127T153125Z-a900597b36e4-daemon.log), [mod_loader-before.log](sd-phase-a/20261127T153125Z-a900597b36e4-mod_loader-before.log)):
  1. **Armed BEFORE first MENU open:** User confirmed active pre-capture immediately after unplugging USB; `daemon.log` proved `RING_START t=100805 seq=1 pid=3051 pre_f=8`, `READY b=8 c=8`, `WINDOW a=8 b=8`, **16** full-res `PC*.JPG` files (`~9.85–9.91 MB`, `status=13`), `RING_EXIT rc=0 sig=0 unres=0 fault=0`.
  2. **First MENU open hydration:** User confirmed 7th `Mods` tab immediately showed `Pre-Capture ON >`, submenu `Mod Status: ON`, `Pre-Frames: 8`; `mod_loader.log` recorded `tab_icon_tab6 00000000`, `core_init 00000005`, `core_load c3400daa`, `mod_on 04026000`, `auto_on 04026000`.
  3. **Live count edit while ON (`8 -> 10`):** `mod_loader.log` recorded `persist_ok 0000010a`, `mod_cfg 00000005`; `daemon.log` proved `STATE t=142660 pre_f=10`, `RING_START t=145298 seq=2 pid=3059 pre_f=10`, `READY b=10 c=10`, `WINDOW a=10 b=1`, **11** full-res `PC*.JPG` files (`~9.99–10.08 MB`, `status=13`), `RING_EXIT rc=0 sig=0 unres=0 fault=0` (total `r_runs=2, r_ok=2, r_sav=27, r_flt=0, r_unres=0, rerr=0, ferr=0`).
  4. **OFF + OFF-state count edits (`10 -> 1 -> 2 -> 3`) + re-enable ON (`3`):** `mod_loader.log` recorded `mod_off`, `persist_ok 0000000a`, `persist_ok 00000001` (`mod_cfg_off 00000000`), `persist_ok 00000002` (`mod_cfg_off 00000001`), `persist_ok 00000003` (`mod_cfg_off 00000002`), `persist_ok 00000103`, `mod_on`; `daemon.log` showed `STATE t=188870 pre_f=0 tog=0` -> `STATE t=195830 pre_f=3 tog=1`. Both `precap_cfg_before_disable` and `sim_persist_before_disable` read exact `"S7PC1 1 3\n"`.
  5. **Clean daemon stop + `sd-disabled` preservation:** `daemon.elf` stopped cleanly via `stop` file (`STOP reason=stop_file`), `guard_check_before` verified `STATE hooks=v2 rects=patched shim=shim`, `sd-disabled` written (`sd_disabled_written=true`), `sim_persist_preserved_across_disable=true`, atomic `.boot.lock` `ACQ -> REL`.
- **Post-`sd-disabled` MENU retirement (confirmed by user: "Вариант А"):** After USB unplug, pressing MENU opened stock MENU cleanly with 6 stock tabs (the 7th `Mods` tab vanished cleanly without crash).
- **Collect #2** ([20261127T153523Z-a900597b36e4-ram-collect.json](sd-phase-a/20261127T153523Z-a900597b36e4-ram-collect.json)): Following a power cycle before USB reconnect, confirmed `/tmp_network/mlv2` was absent, `ram_cleanup="GONE"`, `active_state_cleared=true`, `flash_writes_performed=false`, `sd_writes_performed=false`.

## 3. Carry-Forward Items for Stage 7.3 Phase B

1. **WBI (`warm.mode=2` / `ssboot.bin`) & S2R (`pm.ddr_ctrl=sref`) persistent entry architecture + independent recovery proof:** Required before ANY camera flash write (`plans/07-persistence.md:48-51`).
2. **Minor Phase A host CLI fixes:** Strip trailing `\r\n` on `precap_cfg_after_boot` comparison (`scripts/m7_stage7_sd_probe.py:651`, keeping exact-byte MD5 check) and record `/proc/sys/kernel/random/boot_id` in `.active` state so WBI reboots with constant `im_pid=161, im_starttime=105` are detected unambiguously.
