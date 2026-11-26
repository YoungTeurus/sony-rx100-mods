# Stage 6 WIP v1 (r4) Hardware Qualification Report

Date: 2026-11-21
Device: Sony DSC-RX100M7 (firmware `29110_03.2021050601`, unmodified)
Sealed build: commit `f446406`, `prototype-stage6-autonomy/out/stage6_probe.elf` SHA-256 `b77694a07390ff43a79722cb39b21e754f21aa03c137054824ebfa61fa09a645` (independent review: Sol GO, `work/stage6-menu/REVIEW-sol-wip1-r4.md`).

## Receipts

- Early handshake retry (safe abort before upload): `work/stage6-menu/wip1/20261121T171422Z-c8dd11861dc1-start.json` (`read_ready` timeout before any remote write; clean service exit).
- Launch (`--start`, PASS): `work/stage6-menu/wip1/20261121T172044Z-540344602722-start.json` (`cli_ok: true`, `daemon_pid: 1261`, `daemon_starttime: 61132`, `w_pid: 1263`).
- Collection (`--collect`, PASS): `work/stage6-menu/wip1/20261121T172355Z-5770b5bad484-collect.json` (`cli_ok: true`, `collect_outcome: "collected"`, `alive_at_collect: true`, `stopped_cleanly: true`, `cleanup: "GONE"`, `active_state_cleared: true`).
- Durable native log (81 lines): `work/stage6-menu/wip1/20261121T172355Z-5770b5bad484-probe.log`.

## Live Hardware Findings — ALL 5 PROVEN (PASS)

1. **Zero-host-config on-camera self-discovery — PASS:**
   - `BOOT` emitted in 81 ms (`t=81`): `self_pid=1261` (`PPid=1`, `TracerPid=0`, `VmRSS=4 kB`), `w_pid=1263`, `im_pid=161` (`im_st=105`), `libobj=0x5ecd000`, `mwf=0x4460000`, `mpr=0x7400000`, `mprctrl=0x44a8000`, `uipc=0x4053000`, `ranges=235`.
   - `mon_proc=170 == mon_mwf=170` (exact match between `/proc/161/task/*/comm` and `libMWF.so` `ObjThread` handle).
   - `in_ok=1 ih=27 if=14` (`InfraInput` shutter indices discovered zero-ptrace).
   - Stage 7 bonus witness: `str_uxc=0x173a4000..0x1744d000 str_uxc_path=/usr/share/app/string_russian.uxc`.

2. **Untethered RAM daemon survival across `auth.stop()` + physical USB unplug — PASS:**
   - Ran continuously for **112.1 s (`1852` ticks)** across service-mode exit (`t=2.3 s`), physical USB cable disconnect → live-view shooting (`t=9.7..13.6 s`), menu navigation & shutter press (`t=17..32 s`), USB cable reconnect (`t=36.4..37.2 s`), and second service-mode entry (`t=99.0 s`).
   - Zero read errors (`rerr=0`, `ferr=0`), zero IPC errors/timeouts (`uipc_dis=0`, `uipc_ferr=0`, `uipc_to=0`), dynamic `/proc/161/maps` refresh triggered cleanly once (`mref=1` at `t=99 s`).
   - Both processes (`1261`, `1263`) were alive at `--collect` (`live_pids_at_collect: [1261, 1263]`). Writing `/tmp_network/.m7-s6-540344602722/stop` (zero host `kill`) triggered stop at `trig_t=112038 ms`, cleanly reaped worker `1263` in **61 ms** (`w_reap=1`), wrote `STOP t=112099 reason=stop_file`, and cleared `live_pids_after_stop: []` and RAM dir (`cleanup: "GONE"`).

3. **Live `Release w/o Card` (`BackupID = 0x01071472`) polarity via isolated `/dev/uipc` worker — PASS:**
   - Verified `uipc_ok=1`, `bk_sz=1`, `bk_rc=0`, `bk_ok=1` across the entire 112 s run (~460 polls, zero errors).
   - **Exact live polarity on M7 1.00:**
     - **Release w/o Card = Enable:** `bk=0x0` (`t=81..22390 ms` and `t=28058..112099 ms`).
     - **Release w/o Card = Disable:** `bk=0x1` (`t=24198..26498 ms`).
   - Transition reflected immediately in live view without reboot or ptrace.

4. **Live `CamSetParams` Drive Mode & format reads (zero ptrace) — PASS:**
   - `csp_ptr_ok=1`, `cam=1`, `size=0xb3` (20M L), `asp=0xb9` (3:2), `qual=0xbc` (Extra Fine), `fmt=0xbd` (JPEG), `bspd=0x69` (Hi), `bol=0x5bf` (Hi).
   - Single: `drive=0x5e`, `elig=0` (`t=13569 ms`, `t=20311 ms`).
   - Continuous: `drive=0x5f`, `elig=1` (`t=17171 ms`).
   - **Mode-transition finding for WIP v2:** During USB/shooting transitions (`t=2.3 s`, `t=9.7 s`, `t=37.1 s`, `t=99.0 s`), `im.elf` transiently clears `CamSetParams` (`cam=0`) and `Spinal` (`sub_ok=0`) for ~120 ms before repopulating user settings and later enabling `sub_en=1`. At `t=12038..12107 ms` (while `sub_en=0`), `half` pulsed `1` for 69 ms during wake-up. Therefore WIP v2 MUST gate arming strictly on `sub_ok==1 && sub_en==1 && cam==1` and invalidate cached shooting-mode object pointers whenever `sub_en` or `cam` drops to `0`.

5. **Live untethered shutter & subscription reads — PASS:**
   - Live view ready: `sub_ok=1 sub_en=1 sub_raw=0x1` (`t=13569..36370 ms`); drops cleanly to `sub_en=0` on USB reconnect (`t=36370 ms`).
   - Physical half-press in live view (`t=30878..31969 ms`, 1091 ms hold): `half_ok=1 half=0x1 full_ok=1 full=0x0` → clean release `half=0x0`.

## Notes for Stage 6 WIP v2

- **Toggle polarity (product choice):** Stock default for Release w/o Card is Enable (`bk=0x0`), Disable is `bk=0x1`. Confirm whether Pre-Capture ON maps to Enable (`bk=0x0`, intuitive label) or Disable (`bk=0x1`, off-by-default on stock settings).
- **Upload speed optimization:** M7 BusyBox lacks `--list` (rc 127) and `base64`, but DOES have `gunzip` in `/bin/busybox` help text (step 4 of `collect.json`). Falling back to parsing `/bin/busybox` help text (as Stage 5 `runner.py:1239` does) enables gzip+octal, cutting upload size ~54% (~2× faster upload).
- **WIP v2 architecture:** Combine proven Stage 5 RAM ring (`ram_precapture_ring.c` + `ram_native.c`) with WIP v1 self-discovery, passive zero-ptrace idle loop (`0` ptrace / `0` traps / `0` `Insert4100` until `toggle_on && sub_en==1 && elig==1 && half==1` debounced), per-run stop file, and bounded untethered safe-abort watchdog.
