# Stage 6 WIP v2 Live Hardware Run #1 Report

Date: 2026-11-21
Commit tested: `e451fdb` (`Stage 6 WIP v2 (r5)`)
Camera: Sony DSC-RX100M7, firmware `1.00`, JPEG L 20M 3:2, SD card inserted.

## Receipts (Local Operator Archive)

- Start receipt: `20261121T191608Z-ca85694e6bf5-start.json`
- Collect receipt: `20261121T192319Z-958c73cbd0fa-collect.json`
- Saved daemon log: `20261121T192319Z-958c73cbd0fa-daemon.log`

## Verdict

- **Start / Upload / Daemonization / USB Unplug Survival:** **PASS** (`cli_ok=True`, `start_ready=True`, `daemon_pid=3174`, `w_pid=3176`, `im_pid=161`, `mon_proc=170 == mon_mwf=170`, `csp_ptr_ok=1`, `uipc_ok=1`, `in_ok=1`, `ring_ok=1`, `rerr=0`, survived 182.5 s untethered).
- **Passive Zero-Interference Gating (OFF + Continuous, ON + Single):** **PASS** (`t=25670..27242` OFF + Continuous full press: `r_runs=0`; ON + Single: `elig=0, gate=0, r_runs=0`).
- **Pre-Capture Ring Arming & Save:** **FAIL (Safe Abort, Camera 100% Healthy)** — `ring.elf` spawned cleanly on debounced half-press (`t=35705`, `pid=3232`), verified all 291 Sony pins live (`SESSION a=1 b=1`), executed `Insert4100` (`SESSION a=2 b=1`), then aborted cleanly before `mode_set(0x4100)` (`ABORT a=90 b=7 c=2`), ran `Pullout4100` cleanly (`SESSION a=4 b=1 c=1`), exited `rc=7`, latched `r_flt=1` (`unres=0`), and camera resumed normal stock shooting and clean `--collect` teardown (`stopped_cleanly=True`, `cleanup=GONE`).

## Root Causes Proven by Live Telemetry

1. **Premature `topology == 2` return in `stage6_route_wait` (`stage6_ring.c:824-835`):**
   - Stage 5's real M7 receipt (`work/stage5-no-card-writes/hostfix-astra-r7/nohold/20261110T051710Z-5718385fdc4f-replay.json`) proves `Insert4100` transitions through `topology=1 (SD) -> topology=2 (DETACHED, ~250 ms) -> topology=3 (STOCK RAM 0x4100)`.
   - Stage 5 polled every `250 ms` (`streak=2` at `topology=3`). `stage6_route_wait` shortened polling to `100 ms` while still returning on `streak == 2` for any nonzero topology when `after_stop == 0`, so two `100 ms` polls landed inside the transient ~250 ms `topology == 2` window and returned `2` before Sony attached `0x4100`.
   - **Fix:** Wait explicitly for `want = after_stop ? 1u : 3u` (`streak >= 2`).

2. **Transient ~928 ms `sub_en=0` dip during Sony's `Insert4100` (`daemon.log` lines 42-48):**
   - `t=36013`: `Insert4100` started (`SESSION a=1 b=1`).
   - `t=36118`: `sub_en` dropped `1 -> 0` while `cam=1 drive=0x5f bk=0x0 half=0x1 full=0x0 elig=1 tog=1`.
   - `t=36200`: Daemon fired false `DISARM_GATE` after 50 ms of `sub_en == 0`.
   - `t=37046`: `sub_en` returned `0 -> 1` automatically (928 ms later) without the user leaving shooting mode.
   - **Fix:**
     - In `stage6_daemon.c`: track `ring_phase` from `M7CAP1` `PHASE` events; do not disarm on transient `sub_en == 0` during `ring_phase == 0` (`Insert4100`/`mode_set`, up to 4 s ceiling) or `ring_phase >= 2` (`POST`/`DRAIN`/`RESTORE`/`Pullout4100`), while preserving instant 50 ms disarm on `elig`/`cam`/`tog`/`shutter` drops in any phase and on `sub_en == 0` during `PRECAP_ARMED` once `sub_en == 1` has been observed.
     - In `stage6_ring.c`: after `stage6_route_wait == 3` and before `connect_pair(3)` / `mode_set(0x4100)`, wait up to 2,000 ms (checking physical hold & disarm every 25 ms) for `subscription(o, 0, 0)` (`sub_en == 1`) to settle before arming.

3. **Upload UX & Speed Observation:**
   - Upload took `267.4 s` (`1,203` pure-octal chunks × `0.212 s/chunk`) with no live progress indicator.
   - Add live progress reporting (`UPLOAD[label]: done/total (%) elapsed eta`) and safe literal-ASCII + octal chunk encoding with per-file shell path variable (`M7D`) while keeping audited 32 B / 10 ms USB pacing and `< 512 B` frames.
   - Hardware commands on macOS require `sudo`.
