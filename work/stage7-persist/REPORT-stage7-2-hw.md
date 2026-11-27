# Stage 7.2 Live Hardware Report — Volatile RAM-Only Verification (DSC-RX100M7 1.00)

Date: 2026-11-27  
Camera: **DSC-RX100M7** firmware **1.00** (`29110_03.2021050601`)  
Status: **LIVE HARDWARE PASS (100% RAM-only, zero flash writes)**

## Receipts & Saved Artifacts

1. **First `--start` attempt (discovered kernel console printk on freeze, proved native `install` + `sd-disabled` safety path):**
   - Receipt: `work/stage7-persist/ram-runs/20261127T083517Z-7c9eb51c0142-start.json`
   - `mlv2_guard.elf install` succeeded on all 186 threads of `/proc/161` (`INSTALLED shim=15d63800..15d63e98 hooks=15d63d8d,15d63dc1,15d63ddd`, `RESUME count=186 result=0`, `MLV2_RESULT=0 changed=1`), followed by `STATE hooks=v2 rects=patched shim=shim`.
   - Kernel console (`usbgcon-1`) interleaved `[  333.144999] fops_se_ioctl_receive(1000) fops_se_ioctl_receive(916) fops_se_ioctl_receive(986) ` onto `FREEZE threads=186`; runner failed closed, wrote `sd-disabled`, and preserved custody.
   - Fixed in Stage 7.2 r7 via fresh per-invocation `/tmp_network/mlv2/.g<6hex>` stdout capture (Sol r7 **GO**: `work/stage7-persist/REVIEW-stage7-2-sol-r7.md`).

2. **First `--collect` (proved native `core.bin` load, `sd-disabled` -> `sd-stopped`, and live `mlv2_guard.elf uninstall`):**
   - Receipt: `work/stage7-persist/ram-runs/20261127T090859Z-d1b37a469e6e-collect.json`
   - `mod_loader.log`: `work/stage7-persist/ram-runs/20261127T090859Z-d1b37a469e6e-mod_loader.log` (`tab_icon_tab6 00000000`, `core_init 00000005`, `core_load 5c8af766`).
   - `sd-stopped` verified (`FILE_OK`), `mlv2_guard.elf uninstall` restored stock (`UNINSTALLED restored=stock`, `RESUME count=186 result=0`, `MLV2_RESULT=0 changed=1`), console printk cleanly isolated via `.g9537d3`.
   - Post-uninstall check confirmed `STATE hooks=stock rects=stock shim=zero`; `/tmp_network/mods` and `/tmp_network/mlv2` -> `GONE`; custody cleared.

3. **Full end-to-end Stage 7.2 r7 `--start`:**
   - Receipt: `work/stage7-persist/ram-runs/20261127T091103Z-799a2f60f946-start.json`
   - `start_ready=True`, `daemon_pid=2160`, `view_bias=0x00000000`, `BOOT self_pid=2160 im_pid=161 im_st=105 ... mon_proc=170 mon_mwf=170 in_ok=1 ring_ok=1 pre_f=0 post=0 bcap=24 pmax=48 deb=100`.
   - Untethered user verification on live camera:
     - 7th **`Mods`** tab and **`Pre-Capture`** submenu (`Mod Status`, `Pre-Frames`) appeared cleanly and operated without crashes.
     - Stock `Release w/o Card` remained completely decoupled.
     - Master switch ON/OFF and live `Pre-Frames` changes worked immediately.

4. **End-to-end `--collect` #1 (daemon stop, logs, `precap.cfg`, `sd-disabled`):**
   - Receipt: `work/stage7-persist/ram-runs/20261127T092124Z-ce7b58c49934-collect.json` (`cli_ok=true`, `terminal_disable_requested=true`, `service_stop_requested=true`).
   - `daemon.log`: `work/stage7-persist/ram-runs/20261127T092124Z-ce7b58c49934-daemon.log`
   - `mod_loader.log`: `work/stage7-persist/ram-runs/20261127T092124Z-ce7b58c49934-mod_loader.log` (`mod_on`, `mod_cfg 4/5/0/1`, `mod_off`)
   - `precap.cfg`: `work/stage7-persist/ram-runs/20261127T092124Z-ce7b58c49934-precap.cfg` (`S7PC1 0 2\n`, byte-exact `wc -c` + `md5sum`)
   - Verified runtime diagnostics (`runtime_clean=true`, `rerr=0`, `ferr=0`, `r_flt=0`, `r_unres=0`, `trunc=0`, `r_reap=1`):
     - Cycle 1 (`seq=1`, `pre_f=5`): `WINDOW a=5 b=15`, **20** full-res 20MP JPEGs (`8.13–8.20 MB`, `status=13`), `rc=0`, `fault=0`.
     - Live menu reconfiguration verified in `daemon.log`: `pre_f=5 -> 8 -> 10 -> 1 -> 2`.
     - Cycle 2 (`seq=2`, `pre_f=2`): `WINDOW a=2 b=7`, **9** full-res 20MP JPEGs (`8.16–8.29 MB`, `status=13`), `rc=0`, `fault=0`.
     - Total saved: **29** `PC*.JPG` files across 2 cycles (`r_runs=2, r_ok=2, r_sav=29`).
     - Passive OFF verification (`t=140539..142492`): half-press + full-press while `Mod Status = OFF` (`pre_f=0, tog=0, gate=0`) remained 100% passive stock (`r_act=0`).
     - Clean daemon stop: `STOP t=337445 reason=stop_file r_reap=1 r_runs=2 r_ok=2 r_sav=29 r_flt=0 r_unres=0 trunc=0`.

5. **Final `--collect` #2 (live uninstall after user opened MENU):**
   - Receipt: `work/stage7-persist/ram-runs/20261127T092451Z-f33ada4e54de-collect.json`
   - `sd_stopped_state=FILE_OK`, `UNINSTALLED restored=stock` (`RESUME count=186 result=0`, `MLV2_RESULT=0 changed=1`), post-uninstall check `STATE hooks=stock rects=stock shim=zero`, `mods_cleanup=GONE`, `mlv2_cleanup=GONE`, `active_state_cleared=True`, `collect_outcome=uninstalled_clean`.

## Observed Live Camera Notes (For Later Polish)

- **Save duration & UX indicator:** Each 8.2 MB 20MP JPEG wrote in ~1.18 s (~7 MB/s sequential), so 20 frames took ~28.5 s and 9 frames took ~16.3 s without an on-screen progress HUD. Deferred to post-Stage-7.3 polish.
- **USB `setTerminalEnable(False)` after `PTRACE_ATTACH`:** On runs that invoked `mlv2_guard.elf install`/`uninstall`, `setTerminalEnable(False)` threw `GenericUsbException` on the first try while `service_stop_requested` succeeded immediately after; on the collect run without `PTRACE_ATTACH` (`ce7b58c49934`), `terminal_disable_requested` succeeded cleanly (`cli_ok=true`).
