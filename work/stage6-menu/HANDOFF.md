# Stage 6 WIP v3 HW3 Hotfix (r3) — Agent Handoff Guide

Updated 2026-11-26
Target hardware: Sony DSC-RX100M7 (firmware `1.00`, unmodified, Linux `3.0.27` ARM SMP)

---

## 1. Exact Status Right Now

- **Sealed code & offline verification: PASS / GO for Live Hardware Run #4** (code commit `1420937e174904e0c368b42abe728f68d688a4af`, independent review **Codex Astra r3 GO**: [REVIEW-wip3-hw3fix-astra-r3.md](REVIEW-wip3-hw3fix-astra-r3.md), build report: [REPORT-wip3-hw3fix.md](REPORT-wip3-hw3fix.md)).
- **Run #4a tethered PASS. Run #4b HARDWARE PASS. All 20 JPEGs passed SD readback. See the [Run #4 report](REPORT-wip3-hw4.md) for timings and remaining usability items.** See the [hardware report](REPORT-wip3-hw4a.md) for the six logged saves, ring exit and cleanup.
- **Prior live receipts (Run #3 / #3b / #3c on WIP v3 r5 `04b0a1e`):**
  - Run #3c tethered diag (`work/stage6-menu/wip2/20261122T183042Z-3a8e789ea44f-tethered-diag.{log,json}`) proved live fast rolling (`READY` 5 pre-frames in `695 ms` / `7.2 fps`, `36` frames in `5.39 s` / `6.7 fps`, `+11` post-frames in `1.68 s` / `6.55 fps`, `0` read/UIPC errors) and caught the freeze at `t=23781 ms` (`5.8 s` into `PRECAP_DRAIN`): `RING_EVT ev=UNRESOLVED a=7 b=1407 c=170 d=14871` (`stage=7`, `detail=0x057f`, `tid=170 = mwf_monitor_inp`), leaving TIDs `170` and `446` traced under `ring.elf`.
  - Because r5 collapsed `status != 0x057f || PTRACE_GETREGS != 0` into `7 / 1407`, the live failing call site and errno remain **INCONCLUSIVE**. The fault did not recur in Run #4a.
- **Camera custody state:** Both Run #4a and #4b recorded clean RAM removal. The next planned stage is [Stage 7](../../plans/07-persistence.md).

---

## 2. Sealed Release Digests (`prototype-stage6-autonomy/out-v2/`)

All 6 files rebuild byte-for-byte via `build_stage6_v2.py` and pass `build_stage6_v2.verify_seal()`:

| File | Size | SHA-256 | Notes |
|---|---:|---|---|
| `stage6_daemon.elf` | 36,631 B | `cdb29883c5b9ed40920b9cfca09502aadd430a5a373abcf5528d735c3280be20` | Unchanged from r5; 1 RX `PT_LOAD`, 158 `svc #0`, 0 `ptrace` |
| `stage6_ring.elf` | 122,980 B | `ee931ac970d299e4c77306db12102fe65bcc2e5ec453bd05a3586aa8e00a6820` | RX `117,756 B` + RW `8,192 B` RELRO; `841–842` upload chunks `< 850`; 3 `ptrace` `svc #0` total |
| `build.json` | 23,670 B | `f33c2649730fd385d125455e2758f6b9ae84bf1ca9687031941b84920581b982` | Seals 31 native + 19 host sources |
| `sony_pins.h` | 96,172 B | `05d5403c404849b2291b08bb842bec1ed8e5c252ec24208cea599ed3278559de` | Generated from pinned Stage 5 extracted libraries |

---

## 3. Hardware Run #4 Plan (Hand User ONE Command at a Time, `clear` on First Line)

### Step 4a — Tethered live-streaming verification (recommended first)

Runs the exact sealed `out-v2/*.elf` (`ee931ac9...` + `cdb29883...`) with `daemonize=False` so every `STATE`, `RING_EVT`, `RING_FILE`, and `UNRESOLVED` streams live and flushes to `work/stage6-menu/wip2/<ts>-<nonce>-tethered-diag.{log,json}` (and automatically cleans up `/tmp_network/.m7-s6-<nonce>` on clean exit):

```sh
clear
sudo python3 -B work/stage6-menu/diag_tethered_v3.py
```

User action once `READY_STREAMING` and `gate=1` appear (keeping USB connected):
1. Hold half-press ~5 s, then full-press ~1–2 s and release.
2. Wait ~65 s for `STOP` and send back the output or `LOG=` / `RESULT=` paths.

### Step 4b — Official untethered qualification (after Step 4a passes)

1. Start & unplug USB:
   ```sh
   clear
   sudo python3 -B scripts/m7_stage6_precapture.py --start --before 5 --after 0 --burst-cap 24 --post-max 15 --backlog-cap 96 --duration-sec 600
   ```
2. Untethered camera tests (with USB cable physically disconnected):
   - Passive OFF (`Release w/o Card` = Disable) + Continuous shot (verify `r_runs=0`).
   - Passive ON + Single Shooting shot (verify `r_runs=0`).
   - Continuous + ON: **SAVE** (~5–10 s half-press + ~1–2 s full-press; wait for card write LED to stop).
   - Continuous + ON: **CANCEL** (~5–10 s half-press, release without full-press; verify 0 new files).
3. Reconnect USB (Mass Storage) and collect log + remove RAM dir:
   ```sh
   clear
   sudo python3 -B scripts/m7_stage6_precapture.py --collect
   ```
4. Read-only SD card readback verification (replace `<LOG_PATH>` with `saved_log` printed by `--collect`, and verify `/Volumes/RX100M7` is mounted):
   ```sh
   clear
   python3 -B scripts/m7_stage6_precapture.py --check-card-only --card /Volumes/RX100M7 --log <LOG_PATH>
   ```

---

## 4. Decoding Run #4 Outcomes & `UNRESOLVED` Telemetry

In `stage6_daemon.c:1507`, ring unresolved events print as:
`RING_EVT t=<ms> seq=<n> ev=UNRESOLVED a=<stage> b=<detail> c=<trace_tid> d=<ring_ms>`

Note: `detail` (`b=...`) is printed as an unsigned 32-bit decimal integer. Convert `> 2^31` to signed errno via `b - 2**32` (e.g., `4294967293` = `0xfffffffd` = `-3` = `-ESRCH`; `4294967282` = `0xfffffff2` = `-14` = `-EFAULT`; `4294967295` = `-1` = `-EPERM`; `4294967291` = `-5` = `-EIO`).

| `stage` (`a=`) | Exact Meaning (`stage6_ring.c`) | `detail` (`b=`) |
|---|---|---|
| `7` | `wait4` stop status `!= 0x057f` (cannot be `1407` anymore!) | Actual `wait4` status word (e.g., unexpected signal stop or exit) |
| `8` / `9` | Post-Sony-call trap PC/CPSR/SP mismatch (`8`) or callee-saved `r4..r11` clobber (`9`) | PC (`8`) or register index (`9`) |
| `221..256` (`220 + op`) | Post-`wait_trace_stop` `PTRACE_GETREGS` failed after 33 attempts (`-3`) or 1 attempt (non-`-3`) in `s6_sony_call4`, `s6_copy_pixels_fast`, or `stage6_insert4100_call` | Signed 32-bit errno |
| — `221` / `224` | Pool mutex `trylock` (`op=1`) / `unlock` (`op=4`) on `tid=170` | Signed errno |
| — `222` / `223` | `GetImage` (`op=2`) / `ReleaseImage` (`op=3`) on `tid=170` | Signed errno |
| — `225` / `226` | Root mutex `trylock` (`op=5`) / `unlock` (`op=6`) on `tid=170` | Signed errno |
| — `227` | `s6_copy_pixels_fast` `memcpy` (`op=7`) on `tid=170` | Signed errno |
| — `228..234` | `libmpr` SD commit calls: `228`=`GetDrive`(8), `229`=`OpenFile`(9), `230`=`WriteFile`(10), `231`=`CloseFile`(11), `233`=`GetMediaPath`(13), `234`=`GetMediaInfo`(14) | Signed errno |
| — `244` | `pthread_setcancelstate` (`op=24`) on `tid=446` | Signed errno |
| — `249..254` | `s6_mode_set` (`op=29..34`) on `tid=446` | Signed errno |
| — `255` | `Insert4100` (`stage6_insert4100_call`) or `Pullout4100` (`op=35`) on `tid=446` | Signed errno |
| `257..261` | `s6_trace_restore` ptrace failures: `257`=`SETVFPREGS`(28), `258`=`SETREGS`(13, also insert abort restore), `259`=`GETREGS`(12), `260`=`GETVFPREGS`(27), `261`=`DETACH`(17) | Signed errno |
| `262..263` | `s6_rec_wait_trap_fast` post-stop `GETREGS`(12) / `GETVFPREGS`(27) on `tid=446` | Signed errno |
| `264..267` | `s6_rec_continue_fast` `SETREGS`(13) / `GETREGS`(12) / `GETVFPREGS`(27) / `CONT`(7) on `tid=446` | Signed errno |
| `268..274` | `s6_burst_*` / `s6_burst_boundary` `GETREGS`/`GETVFPREGS`/`GETSIGINFO`/`CONT` on `tid=446` | Signed errno |
| `161` | `ram_candidate` failed 8× (`b=1`), duplicate candidate (`b=2`), or `s6_hold_acquire` failed 16× (`b=3`) | Subcode `1..3` |

### Decision tree after Run #4a

1. **If Step 4a PASSES** (`RING_FILE` count matches pre+post, `SUMMARY` `ok=1`, `RING_EXIT` `rc=0 unres=0 fault=0`, `cleanup=GONE`):
   - Immediately proceed to **Step 4b** (untethered `--start` → SAVE + CANCEL → `--collect` → `--check-card-only`).
   - Once Step 4b passes, write `work/stage6-menu/REPORT-wip3-hw4.md`, update `STATE.md`, commit, and move to **Stage 7** (`plans/07-persistence.md`: cold-boot firmware persistence + custom menu items `Pre-Capture ON/OFF` and `Pre-Capture Count N`).
2. **If Step 4a hits `UNRESOLVED`:**
   - Read exact `a=<stage>`, `b=<detail>`, `c=<tid>`, and `TRACED_IM_THREADS` + `RING_PROC` from the saved `.log` / `.json`.
   - If `a` is `221..274` with `-3` (`-ESRCH`): the 32 × 1 ms budget was still too short or a specific kernel state needs deeper analysis (e.g., check `/proc/<pid>/task/<tid>/status` & `wchan` in the receipt).
   - If `a` is `221..274` with another errno (e.g., `-14` `-EFAULT`, `-5` `-EIO`, `-1` `-EPERM`), or `a == 7` with a non-`0x057f` status (e.g., `SIGSEGV=0x0b7f`, `SIGILL=0x047f`, `SIGSTOP=0x137f`), inspect that exact Sony call / signal against the ARM disassembly in `extracted/`.

---

## 5. Rules, Scope Boundaries & Toolchain for the Next Agent

- **Read first:** `AGENTS.md`, `STATE.md`, `plans/06-autonomy.md`, `plans/07-persistence.md`, and this file.
- **Python environment:** Always use `.venv-analysis/bin/python3` (`PYTHONDONTWRITEBYTECODE=1`; has `pyusb`, `pyelftools`, `unicorn`, `capstone`).
- **Stage 6 build & full offline test suite (31/31 tests):**
  ```sh
  PYTHONDONTWRITEBYTECODE=1 .venv-analysis/bin/python3 -B prototype-stage6-autonomy/build_stage6_v2.py
  PYTHONDONTWRITEBYTECODE=1 .venv-analysis/bin/python3 -B prototype-stage6-autonomy/test_stage6_probe.py
  PYTHONDONTWRITEBYTECODE=1 .venv-analysis/bin/python3 -B prototype-stage6-autonomy/test_stage6_v2.py
  ```
- **Hard protected paths (NEVER edit during Stage 6):**
  - `evidence/**` and `evidence/m7-capture-probe/.active.json`
  - `prototype-producer-probe/**`, `scripts/m7_stock_precapture.py`, `work/stock-sd-v1/**`
  - Sealed WIP v1 files (`prototype-stage6-autonomy/{stage6_probe.c, build_stage6.py, stage6_runner.py, test_stage6_probe.py, out/}`, `scripts/m7_stage6_probe.py`)
  - Untracked legacy Stage 5 scratch artifacts under `work/stage5-no-card-writes/` exist in the working tree — do **not** delete them and do **not** `git add -A` them.
- **Hardware & review rules (`AGENTS.md`):**
  - Never access `/dev` USB or `/Volumes` from agent commands; always hand the user ONE shell command with `clear` on its own first line (`sudo` for macOS USB).
  - Keep strict `5472x3648` JPEG L 20M 3:2 lock, `0` `ptrace` / single RX segment in `stage6_daemon.elf`, RELRO + `< 850` upload chunks in `stage6_ring.elf`.
  - Independent review of any code change must come from a different model than the implementer; for Codex Astra use `providerInstanceId: "codex"`, `driverKind: "codex"`, `model: "gpt-6.2-astra"`, `options: {"reasoningEffort": "high", "serviceTier": "default"}` (never `ultrafast`/`priority`).
