# Stage 6 WIP v3 HW3 Hotfix Report (r1 -> r3)

- Date: 2026-11-22
- Target: Sony DSC-RX100M7 (firmware 1.00, unmodified)
- Baseline commit: `04b0a1e43dc39706b0845ff01e68ff22b8222225`
- Independent Review Verdict: **GO for Live Hardware Run #4** ([REVIEW-wip3-hw3fix-astra-r3.md](REVIEW-wip3-hw3fix-astra-r3.md))

---

## 1. Live Hardware Run #3 / #3b / #3c Evidence

1. **Run #3 (untethered, WIP v3 r5 `04b0a1e`):**
   - Receipts: `work/stage6-menu/wip2/20261122T175347Z-dc9d440ba6c9-start.json`, `20261122T180656Z-f54cfe946e59-collect.json` (stale recovery after battery pull).
   - User reported ~10 s hold, fast shooting, followed by a freeze (`NO CARD` blinking) after ~1 minute. Read-only card check showed 10 valid `5472x3648` JPEGs (`PCA97EEC.JPG`..`PCA97EE7.JPG`, EXIF `20:56:40`–`20:56:41`, mtimes `20:56:50`–`20:57:03`, ~1.4 s/file).
2. **Run #3b (untethered, `--before 5 --post-max 15 --burst-cap 24 --backlog-cap 96`):**
   - Receipts: `work/stage6-menu/wip2/20261122T181049Z-96330b2b2909-start.json`, `20261122T181635Z-79f856a5efdc-collect.json`.
   - ~5 s half-press + ~2 s full-press froze with blinking `NO CARD`. Read-only card check showed 1 new valid `5472x3648` JPEG (`PC19BF29.JPG`, `10,906,582 B`).
3. **Run #3c (tethered live streaming diagnostic over `usbgcon-1`, same sealed r5 `2b0e4344...` ELFs):**
   - Receipts: `work/stage6-menu/wip2/20261122T183042Z-3a8e789ea44f-tethered-diag.log` (`SHA-256 a597df7ce20574281201f4a36f8b02ffb34339a42228626434e052b79849fa95`) and `.json` (`SHA-256 bf7169db48641ab63c07ec06921cc47047784d779cebb2c18d3b8082ded3ce74`).
   - Live rolling performance confirmed: `READY` (5 pre-frames) in `695 ms` (`7.2 fps`), `36` frames in `5.39 s` half-press (`6.7 fps`), `+11` post-frames in `1.68 s` (`6.55 fps`), `rerr=0`, `uipc_dis=0`, `uipc_to=0`.
   - Exact failure at `t=23781 ms` (`5.8 s` into `PRECAP_DRAIN`, `0` files saved):
     - `RING_EVT t=23781 seq=1 ev=UNRESOLVED a=7 b=1407 c=170 d=14871` (`stage=7`, `detail=0x057f`, `trace_tid=170 = mwf_monitor_inp`).
     - Kernel `/proc` snapshot at `t=65 s`: `ring.elf` PID `2353` in `hrtimer_nanosleep`; `/proc/161/task/170` (`mwf_monitor_inp`) and `/proc/161/task/446` (`ObjStillRecorde`) both in `State: t (tracing stop), TracerPid: 2353`.
   - **Hardware root-cause status: INCONCLUSIVE.** In r5, both `s6_copy_pixels_fast` and Stage 5's `sony_call4()` (`retain.c:263`) collapsed `status != 0x057f || PTRACE_GETREGS != 0` into `retain_unresolved(o, 7, status)`, discarding the failing call site and errno.

---

## 2. Hotfix r3 Design (`prototype-stage6-autonomy/stage6_ring.c`)

Zero edits to `prototype-producer-probe/**` or `stage6_daemon.c`.

1. **Unified bounded `ptrace` retry helper (`s6_ptrace_retry_n` / `s6_ptrace_retry`):**
   - Retries ONLY `-ESRCH` (`-3`), requesting at most `max_retries` × 1 ms sleeps (`max_retries + 1` total ptrace calls; `s6_ptrace_retry` uses `max_retries = 32`).
   - Explicitly NEVER retries `PTRACE_ATTACH` (`16`).
   - Permanent or non-`-ESRCH` errors propagate exact signed 32-bit errno; post-`PTRACE_CONT` callers remain fail-closed via `retain_unresolved` without blindly detaching an unknown mid-call thread state.
2. **Complete replacement of all 27 reachable Stage 5 `ptrace`/Sony-call helpers:**
   - Added hardened `s6_*` implementations in `stage6_ring.c` (`s6_trace_begin`, `s6_trace_restore`, `s6_sony_call4`, `s6_sony_call`, `s6_commit_scratch`, `s6_create_cancel_state`, `s6_create_restore_cancel`, `s6_connect_release`, `s6_connect_pair`, `s6_mode_set`, `s6_mode_drain`, `s6_try_lock`, `s6_unlock_owned`, `s6_hold_lock`, `s6_hold_unlock`, `s6_commit_sd_drive`, `s6_commit_open`, `s6_commit_close`, `s6_capture_trap_set`, `s6_capture_trap_restore`, `s6_ram_restore_trap`, `s6_ram_next_trap`, `s6_ram_capture_complete`, `s6_burst_registers`, `s6_burst_unchanged`, `s6_burst_own_stop`) and routed `probe_main()`'s Pullout4100 through `stage6_start_command(..., 2, ..., 0)`.
   - Clang dead-code-eliminated all 27 superseded Stage 5 helpers. Whole-image RX census (`[0, 117756)`) confirmed **exactly 3** `ptrace` (`r7=26`) `svc #0` sites in `stage6_ring.elf`: `s6_trace_begin` (`PTRACE_ATTACH=16`) and the two sites inside `s6_ptrace_retry_n`.
3. **Unambiguous `(stage, errno)` diagnostics (`7 / 1407` unreachable):**
   - In `s6_sony_call4`, `s6_copy_pixels_fast`, and `stage6_insert4100_call`, `status != 0x057f` -> `retain_unresolved(o, 7, status)` (only non-`0x057f` status), while post-stop `PTRACE_GETREGS` failure -> `retain_unresolved(o, 220 + op, (u32)grc)` (`221..256`, exact Sony operation + exact signed errno).
   - Other ptrace failure sites (`s6_trace_restore`, `s6_rec_wait_trap_fast`, `s6_rec_continue_fast`, `s6_burst_*`) report unique non-overlapping stages `257..274` with exact signed errno.
4. **Gated pre-dispatch retry loops (closing Astra r2 blocker):**
   - `stage6_insert4100_call()` and the pre-S1 `rec_tid` `PTRACE_CONT` in `stage6_session_stock_capture()` run explicit `0..32` loops calling `s6_ptrace_retry_n(o, 7u, 0u, 0u, 0u)` and re-checking `precap_check_still_holding(o, ps) && subscription(o, 0, 0)` before every retry attempt. On revocation or permanent error, original registers/cancel state (and Trap #1 / SD mode on pre-S1) are restored cleanly with zero dispatch.
5. **Concurrent pool-list and lock-contention retries:**
   - Added 8 × 5 ms retry around `ram_candidate()` in `s6_handle_frame()`, and `s6_hold_lock_retry` (16 × 20 ms with unconditional `s6_hold_unlock` + zeroing) around `s6_hold_acquire()` and `s6_hold_release()`.

---

## 3. Independent Review History (Codex Astra, `serviceTier=default`)

| Round | Verdict | Outcome | Report |
|---|---|---|---|
| r1 | NO-GO | Found unmodified Stage 5 `sony_call4()` still linked and producing `7 / 1407 / 170` on single `GETREGS` failure (`-3`/`-14`). Fixed in r2 by replacing all 27 reachable Stage 5 ptrace/Sony-call helpers. | `REVIEW-wip3-hw3fix-astra-r1.md` |
| r2 | NO-GO | Confirmed r1 shared-call counterexample PASS, whole-image 3-site ptrace audit PASS, Stage 5 parity PASS, `7 / 1407` unreachable PASS. Found pre-arm regression: `Insert4100` `PTRACE_CONT` retry sleep outlived hold/subscription/disarm revocation. Fixed in r3 via gated `s6_ptrace_retry_n(..., 0u)` loops for both Insert4100 and pre-S1 resume. | `REVIEW-wip3-hw3fix-astra-r2.md` |
| **r3** | **GO** | **ALL offline checks PASS** (Insert4100 & pre-S1 revocations on sleep 1 and sleep 32, held positive controls, persistent `-3` / immediate `-14` register restore, r1/r2 shared-call counterexample, 97/97 RX `svc #0` census = exact 3 `ptrace` sites, `7 / 1407` unreachable, 6/6 byte-for-byte rebuild, 31/31 tests). Live camera behavior remains **INCONCLUSIVE** pending Run #4. | [REVIEW-wip3-hw3fix-astra-r3.md](REVIEW-wip3-hw3fix-astra-r3.md) |

---

## 4. Sealed Release Artifacts (`prototype-stage6-autonomy/out-v2/`)

| File | Size | SHA-256 |
|---|---:|---|
| `build.json` | 23,670 B | `f33c2649730fd385d125455e2758f6b9ae84bf1ca9687031941b84920581b982` |
| `sony_pins.h` | 96,172 B | `05d5403c404849b2291b08bb842bec1ed8e5c252ec24208cea599ed3278559de` |
| `stage6_daemon.elf` | 36,631 B | `cdb29883c5b9ed40920b9cfca09502aadd430a5a373abcf5528d735c3280be20` |
| `stage6_daemon.o` | 45,688 B | `0138bf7b112c38b16183cf123bc3f2b1a43eddb2ba8e99f46d905a0ab920981d` |
| `stage6_ring.elf` | 122,980 B | `ee931ac970d299e4c77306db12102fe65bcc2e5ec453bd05a3586aa8e00a6820` |
| `stage6_ring.o` | 177,260 B | `19e29c2d7291a3be3a08b1fbde94b316b8f7fbbe7b11a3fe61c8ae2e89af9a4e` |

Source digests:
- `prototype-stage6-autonomy/stage6_ring.c`: `21baa71907100d6e0120b151e9b7a0d6e05d83e75452aaa54243f921cdefda7b`
- `prototype-stage6-autonomy/test_stage6_v2.py`: `69b0826cf386776bd32cefef8f2bdea04f4abe4dd7789d8096bb941297c6a352`

---

## 5. Verification Status & Exact Commands

| Check | Status | Proof |
|---|---|---|
| Sealed build & 6-file byte-for-byte reproducibility | **PASS** | `build_stage6_v2.verify_seal()` + temp-dir `build_all()` matched 6/6 files identically |
| Whole-image RX `svc #0` & stage-7 audit | **PASS** | 97/97 RX `svc #0` classified; exact 3 `ptrace` sites; 0/27 superseded helpers; `7 / 1407` unreachable |
| Ring layout, RELRO & upload chunks | **PASS** | `122,980 B`, RX `117,756 B`, RW `8,192 B` RELRO, `841–842` upload chunks `< 850` |
| Daemon isolation | **PASS** | Unchanged `36,631 B` (`cdb29883...`), 1 RX `PT_LOAD`, 158 `svc #0`, 0 `ptrace` |
| Public offline test suites | **PASS** | `test_stage6_probe.py` **8/8** (`1.542 s`), `test_stage6_v2.py` **23/23** (`831.935 s`) |
| Independent Astra r3 replays | **PASS** | All Insert4100/pre-S1 revocations (sleep 1 & sleep 32), shared-call counterexample, retry bounds |
| Live camera Run #4 | **INCONCLUSIVE** | Offline ARM emulation only; awaiting user-operated Live Hardware Run #4 |

```sh
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=prototype-stage6-autonomy
.venv-analysis/bin/python3 -B prototype-stage6-autonomy/build_stage6_v2.py
.venv-analysis/bin/python3 -B prototype-stage6-autonomy/test_stage6_probe.py
.venv-analysis/bin/python3 -B prototype-stage6-autonomy/test_stage6_v2.py
```
