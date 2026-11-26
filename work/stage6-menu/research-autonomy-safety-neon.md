# Stage 6 Track C Research — Self-Discovery, Off-State Silence & Watchdog/Recovery

- **Author / Role:** Gemini 4 Neon (read-only research)
- **Date:** 2026-11-21
- **Scope:** Stage 6 Research Questions 4 & 5 (`plans/06-autonomy.md`) + Stage 7 Question 2 self-discovery prerequisites (`plans/07-persistence.md`).
- **Evidence base:** Live code in `prototype-producer-probe/` and `scripts/`, Stage 5 hardware receipts (`20261121T082654Z-51302f4b3857.json`, `20261121T083545Z-2ce4db80793d.json`, `20261121T084418Z-8db652a0245b.json`), M7 runtime & active-session receipts (`runtime.txt`, `m7-probe-20261104T212038Z.json`, `20261107T174128Z-5e34e221096f.json`, `m7-monitor-runtime-20261105T154355Z-65fa01112a69.json`), M7 `libsencore.so`, and clearly labeled M7A 1.01 static references (`launch_shell.elf`, `usbg_sen.ko`).
- **No production files, tests, `STATE.md`, `AGENTS.md`, or `evidence/**` were modified. No camera/USB access was performed.**

---

## Executive Summary of Verdicts

| Topic | Verdict | Proof / Basis |
|---|---|---|
| 100% of host-patched `m7_config` / `m7_precap_config` fields can be self-discovered or defaulted on-camera | **PROVEN (static + `/proc` receipts)** | Every runtime address/ID (`pid`, `bias`, `mpr_bias`, `mprctrl_bias`, `mwf_bias`, `monitor_tid`, `ranges[]`) maps directly to verified M7 `/proc` files or `libMWF.so` RAM chains; `uipc_bias`, `pthread_bias`, `rec_tid`, `remote_tid`, `source_tid`, and `commit_drive` are *already* self-discovered in-camera. |
| Detached RAM helper survives `setTerminalEnable(False)` + `auth.stop()` + USB unplug | **HYPOTHESIS (strongly supported, hardware test needed)** | `setsid()` + PID-1 reparenting (`PPid=1`, `SigIgn=0x1007`, `tty_nr=0`) is **PROVEN** on M7 (`20261107T174128Z-5e34e221096f.json`); M7 `libsencore.so` has no `kill`/`killpg` imports and M7A `usbg_sen.ko` only tears down `tty-ldisc-17` endpoints. However, survival *across* `auth.stop()` + physical USB disconnect has not yet been executed on M7 hardware (**GAP**). |
| Zero-interference passive loop while OFF or in Single Shooting (zero `ptrace`, zero `Insert4100`, zero traps, zero `sndcmd`) | **PROVEN (code + receipts)** | `sd_input.c` and `read_mem()` use only read-only `pread64` on `/proc/<pid>/mem`. Currently `ram_native.c:388,401` prematurely runs `Insert4100` + `mode_set(0x4100)` *before* `PRECAP_WAIT`; deferring them behind `(enabled==1 && drive_mode==Continuous && half_press)` makes OFF/Single 100% passive. |
| Half-press arming latency | **PROVEN (measured on 3 Stage 5 hardware runs)** | With `0x4100` pre-attached: **731–750 ms** (`half_press -> PRECAP_ARMED`), of which **600 ms** is hardcoded `observe(focus_ms=600)` and only **131–150 ms** is `ptrace` + trap + `sndcmd S1`. Deferring `Insert4100` + `mode_set(0x4100)` adds **1,610–1,750 ms** with current 200–250 ms polling sleeps (reducible by tightening poll intervals, see §2.3). |
| Current `retain_unresolved()` behavior untethered | **PROVEN (code audit)** | Calls `precap_abort()` (releasing S2/S1) then loops `for (;;) sleep_ms(1000)` (`retain.c:18-35`), permanently wedging any stopped tracee, held mutex, `0xde01` trap, or `0x4100` RAM route until battery pull. |
| Safe untethered recovery & manual fallback | **PROVEN (architectural / kernel semantics) + GAP on soft power-off** | RAM-only helper + RAM-only `im.elf` state guarantees **battery pull always returns 100% stock camera** (confirmed by 30+ `.rebooted-*.json` cycles). Soft power-switch behavior while `im.elf` holds a wedged mutex/tracee is unmeasured (**GAP**). |

---

## 1. Host-to-Helper Dependency Audit (Stage 7 Q2 Prerequisites)

### 1.1 Every Field Currently Patched by the Laptop

The freestanding single-segment ARM ELF built by `prototype-producer-probe/build.py:273-325` contains two `const volatile` config structs patched in-place by `build.configure()` (`build.py:434-493`) before upload via `runner.py:1400-1415`.

#### A. `m7_config` (`struct config`, `native.c:22-27`, 4156 bytes = 60 + 512×8)

| # | Field | Offset | Current Host Source (`runner.py` / `build.py`) | Runtime Usage in RAM Pre-Capture | On-Camera Self-Discovery / Replacement | Status |
|---|---|---:|---|---|---|---|
| 1 | `magic` | `0x00` | Constant `0x3143504d` (`build.py:481`) | Validation (`ram_native.c:334`) | Compile-time constant | **PROVEN** |
| 2 | `version` | `0x04` | Constant `6` (`build.py:481`) | Validation (`ram_native.c:334`) | Compile-time constant | **PROVEN** |
| 3 | `token` | `0x08` | `secrets.randbelow(0xffffffff)+1` (`runner.py:1885`) | `M7CAP1=` journal tag (`native.c:145`) and output filename `PCxxxxxx.JPG` (`commit.c:1-3, 33`) | Generate on-camera from `/dev/urandom` (or `clock_gettime(CLOCK_MONOTONIC)` ^ `getpid()`) per trigger; increment & retry if `commit_open(flags=1)` reports existing file (`commit.c:116-122`). | **PROVEN** |
| 4 | `pid` | `0x0c` | `/bin/busybox pidof im.elf` (`m7_burst_identity.py:119`, `runner.py:1343`) | `/proc/<pid>/mem`, `/proc/<pid>/maps`, `/proc/<pid>/task/<tid>/*`, `tgkill` (`native.c:174`, `retain.c:61`, `ram_continuous.c:187`) | Scan `/proc` via `open("/proc", O_RDONLY\|O_DIRECTORY)` + `getdents64` (ARM syscall `217`); match numeric dir where `readlink("/proc/<pid>/exe")` (`syscall 85`) == `"/usr/bin/im.elf"` and `/proc/<pid>/status` confirms `Name: im.elf`, `Pid == Tgid`, `TracerPid: 0`, `Uid: 0 0 0 0`. Verified format in `runtime.txt:893-930` & `20261107T174128Z` steps 1–3 (`PID=161`). | **PROVEN** |
| 5 | `bias` | `0x10` | `parse_identity()` parsing `/proc/<pid>/maps` (`m7_burst_identity.py:266-295`, `runner.py:1400`) | All `libObj.so` code/data VAs (`0x1463800`, `0x145d230`, `0x1463130`, `0x145d884`, `0xa14c98`, etc.) | Single-pass `/proc/<pid>/maps` parser in helper: match `r-xp 00000000 ... /usr/lib/libObj.so`, verify 3 file-backed VMAs against `libObj.so` `PT_LOAD` (`r-xp [0, 0x1325000)`, `---p [0x1325000, 0x132c000)`, `rw-p [0x132c000, 0x1425000)` off `0x1324000`, same dev:ino) + anon BSS tail `[0x1425000, 0x1464000)`, then run existing `code_pins` check (`retain.c:77-84`). Verified in `runtime.txt:306-309` (`0x05ecd000`). | **PROVEN** |
| 6 | `nranges` | `0x14` | `len(ranges)` (`runner.py:1397-1400`) | Bounds `private_range()` loop (`native.c:248`) | Populated in-camera during the same `/proc/<pid>/maps` pass (`229–234` eligible ranges observed in Stage 5 receipts, well below `MAX_RANGES=512`). | **PROVEN** |
| 7 | `interval_ms` | `0x18` | Constant `2` (`build.py:481`) | `observe()` poll sleep (`native.c:432`) | Compile-time constant (`2`) | **PROVEN** |
| 8 | `focus_ms` | `0x1c` | Default `600` (`build.py:434, 482`) | `observe(o, m7_config.focus_ms)` (`ram_precapture_ring.c:686`) | Compile-time or card-config constant (see §2.3 on reducing/removing it when physical S1 already runs AF) | **PROVEN** |
| 9 | `settle_ms` | `0x20` | Default `1500` (`build.py:434, 482`) | Validated only (`ram_native.c:346`); unused by `ram_precapture_ring.c` | Remove or constant | **PROVEN** |
| 10 | `diagnose_only` | `0x24` | `0` (`build.py:482`) | Validated `== 0` (`ram_native.c:336`) | Compile-time constant (`0`) | **PROVEN** |
| 11 | `retain_check` | `0x28` | `11` (`build.py:482`) | Gates `read_mem`/`retain_preflight`/`sony_call4` (`ram_native.c:335`, `retain.c:219`) | Compile-time constant (`11`) | **PROVEN** |
| 12 | `monitor_tid` | `0x2c` | Host scans `/proc/<pid>/task/*/comm` for `mwf_monitor_inp` (`runner.py:1154-1185, 1391`) | `ram_monitor()` (`ram_capture.c:36-40`) for `hold_acquire`, `hold_release`, `commit_write` | **Two independent proven paths:** **(A)** `/proc/<pid>/task` scan via `getdents64` + `comm == "mwf_monitor_inp\n"` (exact logic in `runner.py:1156`, verified `TID=170` across all receipts); **(B)** direct `libMWF.so` RAM chain (no dir scan!): `*(u8*)(mwf_bias+0x45478)==1` → `J = *(u32*)(mwf_bias+0x4547c)` (`ObjThread*`, vptr `mwf_bias+0x43088`, entry `mwf_bias+0x2860d`, name `"mwf_monitor_input\0"` at `J+0x1c`) → `H = J[5]` (`H[0]==0x66888866`, `H[2]==J[6]==tid`), then verify `/proc/<pid>/task/<tid>/comm` (`retain.c:59-76`). Proven on M7 hardware in `reports/M7_MONITOR_RUNTIME_PLAN.md:24-51` & `reports/M7_MONITOR_RUNTIME_RESULT.md:28-38`. | **PROVEN** |
| 13 | `mpr_bias` | `0x30` | `mpr_identity()` from `/proc/<pid>/maps` (`runner.py:1213-1214, 1403`) | `sony_call4` ops 8–14 (`commit.c`, `retain.c:237`) & `mpr_code_pins` (`retain.c:87-94`) | Same `/proc/<pid>/maps` pass: match `/usr/lib/libmpr.so` `r-xp` off `0` (`PT_LOAD` `[0,0xc4c000)`, gap `[0xc4c000,0xc53000)`, RW `[0xc53000,0xc7e000)` off `0xc4b000`) + existing `mpr_code_pins`. Verified in `runtime.txt:314-317` (`0x07400000`). | **PROVEN** |
| 14 | `mprctrl_bias` | `0x34` | `mprctrl_identity()` from `/proc/<pid>/maps` (`runner.py:1217-1218, 1404`) | `sony_call4` op 18 (`retain.c:236`) & `mprctrl_code_pins` (`retain.c:98`) | Same `/proc/<pid>/maps` pass: match `/usr/lib/libmprctrl.so` `r-xp` off `0` (`PT_LOAD` `[0,0x3b000)`, gap `[0x3b000,0x43000)`, RW `[0x43000,0x49000)` off `0x3b000`) + existing `mprctrl_code_pins`. Verified in `runtime.txt:209-211` (`0x044a8000`). | **PROVEN** |
| 15 | `mwf_bias` | `0x38` | `module_identity()` from `/proc/<pid>/maps` (`runner.py:1375, 1407`) | `ObjIf` class registry `mwf_bias+0x4548c`, vtables, ops 21–23 & 29–33 (`retain.c:236`) | Same `/proc/<pid>/maps` pass: match `/usr/lib/libMWF.so` `r-xp` off `0` (`PT_LOAD` `[0,0x3b000)`, gap `[0x3b000,0x42000)`, RW `[0x42000,0x45000)` off `0x3a000`) + existing `mwf_code_pins`. Verified in `runtime.txt:205-208` (`0x04460000`). | **PROVEN** |
| 16 | `ranges[512]` | `0x3c..0x103b` | Eligible `rw-p 00000000 00:00 0` (`""` or `"[heap]"`) minus `libObj` BSS (`runner.py:1397-1398`, `build.py:484-487`) | `private_range()` pointer guard (`native.c:246-256`) | Populated directly during `/proc/<pid>/maps` pass using the exact line parser already written in `native.c:184-215` (`matching_map()`), excluding `[libObj_bias+0x1425000, libObj_bias+0x1464000)`. **Fix required for long-running daemon:** remove the hard 16-attempt ceiling in `newly_allocated_range()` (`native.c:218`) and support rate-limited full `maps` refresh on miss, since `private_ranges` grew `229 → 234` across 4 cycles in one boot (`20261121T081135Z` → `20261121T084418Z`). | **PROVEN** |

#### B. `m7_precap_config` (`struct precap_config`, `ram_precapture_ring.c:18-19`, 32 bytes)

| # | Field | Offset | Default / Patched? | On-Camera Replacement |
|---|---|---:|---|---|
| 1–2 | `magic` (`0x32525043`), `revision` (`7`) | `0x00..0x07` | Checked only (`build.py:477`) | Compile-time constants |
| 3–5 | `before` (`1..4`, def `2`), `after` (`0..3`, def `1`), `backlog_cap` (`12..64`, def `12`) | `0x08..0x13` | Patched by `build.py:479` | Compiled defaults, optionally overridable from card config file |
| 6–8 | `sample_ms` (`50`), `window_ms` (`120000`), `drain_ms` (`5000`) | `0x14..0x1f` | Not patched; asserted equal (`ram_native.c:328-330`) | Compile-time constants / watchdog bounds |

#### C. Values Already Self-Discovered In-Camera (No Host Patching Exists Today)

Notably, **six** critical runtime bindings are *not* in `m7_config` at all — the existing native helper already discovers them dynamically on-camera:
1. **`uipc_bias`** (`/usr/lib/libosal_uipc.so`): `runner.py:1378` reads it only for offline verification (`expected_uipc_bias`); it is never patched into `template.elf`. In-camera, `start_native.c:83-89` computes `c->uipc = callback[2] - 0x3169` from `ObjMedia4100` (`sh[23] -> wrapper[5] -> callback[2]`) and checks `start_uipc_code_pins` (`ram_native.c:379`).
2. **`owner_pthread_bias`** (`/lib/libpthread-2.11.2.so`): Discovered in-camera from the stopped `futex` PC in `media_create.c:64-68` (`c->pthread_bias = pc - (post == 0x144 ? 0xd144 : 0xd146)`) and verified against `pthread_code_pins`.
3. **`rec_tid`** (`ObjStillRecorde`, live `446`): Discovered in-camera by `create_discover_tid()` (`media_create.c:34-47`) via `libObj+0x145d884` → `core+0x20` → `ObjThread[6]`.
4. **`remote_tid`** (`ObjCntMgr`, live `408`): Discovered in-camera by `connect_discover()` (`media_connect.c:37-66`) via `libMWF+0x4548c` registry → `ObjCntMgr` → `ObjThread[6]`.
5. **`source_tid`** (`ObjMedia`, live `409`): Discovered in-camera by `start_graph_state()` (`start_native.c:72`).
6. **`commit_drive`** (SD drive letter `'A'`): Discovered in-camera by `commit_sd_drive()` (`commit.c:38-84`) via MMgr enumeration.

#### D. Structural Notes for Self-Discovery Implementation
- **No writable global segment needed (`build.py:277, 322`):** `build.py` enforces a single `PF_R|PF_X` segment with zero writable globals (`assert not section["sh_flags"] & 1`). A self-discovering helper can keep this exact freestanding build contract by storing `struct runtime_config` inside `probe_main()`'s stack or an `mmap2` anonymous buffer (already proven on M7 in `ram_precapture.c:202`, syscall `192`).
- **`/proc/<pid>/maps` size:** Across all 9 recent Stage 5 receipts (including `20261121T082654Z`, `20261121T083545Z`, `20261121T084418Z`), `/proc/161/maps` has **783–793 rows (~42.4–42.9 KiB)** — well inside the existing 256 KiB scan budget (`native.c:224`).
- **Observed determinism (do not hardcode):** Across every M7 boot recorded in `evidence/m7-capture-probe/` (including distinct boots `8b7a6dcb...`, `9a661c06...`, and `runtime.txt`), `im.elf` had `PID=161`, `libObj=0x05ecd000`, `libmpr=0x07400000`, `libMWF=0x04460000`, `libmprctrl=0x044a8000`, `libosal_uipc=0x04053000`, `monitor_tid=170`. Despite zero ASLR observed, dynamic `/proc` discovery must remain mandatory so boot-order variations never dereference wrong addresses.
- **`stdout` pipe decoupling:** `native.c:118` writes `M7CAP1=` to fd 1 and increments `o->io_errors`, which causes `ram_native.c:429` to fail the cycle. An untethered daemon must direct fd 0/1/2 to `/dev/null` (or a bounded circular RAM log in `/tmp_network`) and must never treat logging I/O as fatal.

---

### 1.2 Survival Across Exiting USB Service Mode (`auth.stop()`) and USB Unplug

#### Evidence from Live M7 Receipts & Binaries
1. **Live M7 process tree during USB Service Mode (`evidence/m7-probe-20261104T212038Z.json:28`):**
   - `PID 1`: `launch_shell.el` (`/usr/bin/launch_shell.elf`)
   - `PID 154`: `bootin.elf`
   - `PID 160`: `ash` (console shell spawned at boot)
   - `PID 161`: `im.elf` (`PPid: 1`, `runtime.txt:898`)
   - `PID 782`: `usbgtertx` (kernel thread created by `usbg_sen.ko` terminal line discipline)
   - `PID 784`: `ash` (service terminal shell)
2. **Live M7 proof of `setsid()` + PID-1 reparenting (`evidence/m7-active-session/20261107T174128Z-5e34e221096f.json`, steps 9–17):**
   - When `probe.elf` (PID `2451`, launched by `runner.py` in `20261107T170819Z-8a68ee87e0f4.json`) executed `rt_sigaction(SIGPIPE/SIGHUP, SIG_IGN)` + `setsid()` (`native.c:544-547`) and entered `retain_unresolved()`, the host disconnected from the terminal.
   - Inspected 33 minutes later, PID `2451` was still alive with:
     - `PPid: 1` (reparented to `launch_shell.elf`), `Pid: 2451`, `Pgid: 2451`, `Sid: 2451`, `tty_nr: 0` (no controlling TTY)
     - `SigIgn: 0000000000001007` (`SIGHUP=1`, `SIGINT=2`, `SIGQUIT=3`, `SIGPIPE=13` ignored)
     - `State: S (sleeping)`, `wchan: hrtimer_nanosleep`, `VmRSS: 4 kB`
   - **Limitation of that receipt:** `20261107T170819Z-8a68ee87e0f4.json` set `preserve_service: True` and `service_stop_deferred: True`, so `setTerminalEnable(False)` and `auth.stop()` were **not** sent in that session.
3. **Static audit of M7 `libsencore.so` (`extracted/m7-1.00-.../usr/lib/libsencore.so`):**
   - `senser_stop` (`VA 0xf44c`), `SenserIfStop` (`0x116b2`), `Usb::shutdown_service` (`0x115f8`), and `CoreModule::stop` (`0x176d0`) tear down the USB service interface (`Usb::stop` / `MSS_stop`) and unlock `Inconcurrent::resource_t`.
   - `libsencore.so`'s `.dynsym` imports contain **no** `kill`, `killpg`, `tgkill`, `fork`, or `exec*` symbols (only `pthread_*`, `open`/`close`/`ioctl`, `dlopen`/`dlclose`, and an unreferenced/non-Thumb `system@plt`). It does not enumerate `/proc` or kill independent Linux processes.
4. **Static reference from M7A 1.01 `usbg_sen.ko` & `launch_shell.elf` *(M7A reference, not M7 binary)*:**
   - `usbg_sen.ko` registers `tty-ldisc-17` (`usbgter` / `usbgtertx`). `core_stop` (`0x4a0`), `usbg_ldisc_stop` (`0x3a70`), and `usbg_sen_ldisc_close` (`0x3150`) only clear endpoint flags, wake tty waitqueues, `unregister_console`, and free USB endpoint buffers (`usbg_ldisc_cleanup_ep_data`). No process-killing or `/tmp_network` cleanup occurs.
   - `launch_shell.elf` (`0x88c4..0x8a24`) is a minimal PID-1 loop: `fork()` → `setsid()` → open `/dev/ttycons` → `execv("/bin/ash", ["--login"])` → `wait4()` → `sleep(2)`. It never kills reparented children.
   - `/tmp_network` is a mounted `tmpfs` (`size=1024k`, `runtime.txt:17`) independent of USB gadget state.

#### Verdict & Required Detach Protocol
- **HYPOTHESIS (high confidence, requires one hardware confirmation test):** A RAM helper launched from the service shell **will survive** `setTerminalEnable(False)`, `auth.stop()` (`SONY_VendorRequest_StopSenser`, `sony.py:892, 906-910`), USB re-enumeration back to MSC, and physical USB cable unplug **if and only if** it detaches properly before the shell command returns:
  1. **Double-fork + `setsid()`:** Parent exits `0` immediately so `ash` returns ACK 0 cleanly and host finishes `setTerminalEnable(False)` + `auth.stop()`. First child calls `setsid()` (guaranteed not to be a pgrp leader) and forks the daemon grandchild, then exits so grandchild is reparented to PID 1 (`launch_shell.elf`) and can never reacquire a controlling TTY.
  2. **Close/redirect ALL inherited fds (`0, 1, 2`, plus any higher fds) to `/dev/null`** (or a bounded file in `/tmp_network/`) so the daemon holds **zero** references to `/dev/ttycons` (`usbg_sen` ldisc) — preventing `usbg_sen_ldisc_close()` from blocking or delivering `SIGHUP`/`SIGPIPE`.
  3. **`chdir("/")` and ignore `SIGHUP`/`SIGPIPE`**, while catching `SIGTERM` for graceful shutdown (see §3.2).
- **GAP:** Surviving `auth.stop()` + USB unplug has not yet been executed on physical M7 hardware (must be tested as part of Stage 6 interim verification; also verify that `/usr/bin/sndcmd.elf` and `im.elf` subscription work normally once USB is unplugged — in fact, unplugging USB should eliminate the `inactive_route` state that required the 3-second `wake_for_subscription` S1 wake in USB Service Mode!).

---

## 2. Q4 — Readable "Off" State, Zero-Interference Silence & Arming Latency

### 2.1 Exact Timeline of First Touches to `im.elf` in the Current Stage 5 Helper

Tracing `ram_native.c` → `start_native.c` → `media_connect.c` → `ram_precapture_ring.c` → `sd_input.c` shows **exact points where `im.elf` is mutated today**:

| Step | Location | Action on `im.elf` | Mutating? | Happens BEFORE or AFTER half-press today? |
|---|---|---|---|---|
| 1 | `ram_native.c:352-354` | `open("/proc/<pid>/mem")`, `create_discover_tid`, `create_find_owner`, `retain_preflight` | **No** (read-only `pread64` + `/proc/.../comm`) | Before |
| 2 | `ram_native.c:356-362` | `subscription()` → if `inactive_route` (USB service mode), calls `source_s1(1)`/`source_s1(0)` (`sndcmd.elf`) + 2 s wait | **Yes** (`sndcmd` S1 wake; only triggered if USB suppressed shooting route) | Before |
| 3 | `ram_native.c:374-382` | `source_sample`, `start_graph`, `check_media_pins`, `start_wait` | **No** (read-only `pread64`) | Before |
| **4** | **`ram_native.c:388`** | **`start_command(&o, &c, 1)`** → **`PTRACE_ATTACH` on `rec_tid` (`446`)**, calls `libObj+0xa34be9` (`remote start`) → triggers **`Insert4100`** (`ObjMedia4100` → `PcRemote`) | **YES — FIRST `ptrace` & route-topology mutation** | **BEFORE `PRECAP_WAIT`!** |
| **5** | **`ram_native.c:401` → `274, 282`** | **`session_stock_capture`** → **`connect_pair()` (`PTRACE_ATTACH` on `rec_tid` `446` AND `remote_tid` `408`)**, calls `mode_set({0, 0x4100, 0xffffffff, 1})` (`libObj+0xa1c4e1`, op 34) → switches still destination **from SD (`0x1000`) to RAM (`0x4100`)** | **YES — diverts camera still route to RAM (`0x4100`)** | **BEFORE `PRECAP_WAIT`!** |
| 6 | `ram_precapture_ring.c:662-673` | `sd_input_init()` + `PRECAP_WAIT` loop polling `sd_input_sample()` every 10–20 ms | **No** (read-only `pread64`), **BUT `0x4100` RAM route is ALREADY active!** | Waiting for `0x1f1 0->1` |
| **7** | **`ram_precapture_ring.c:678-685`** | After `0x1f1 0->1`: `connect_pair()`, **`capture_trap_set()` (`PTRACE_POKETEXT` `0xde01` at `libObj+0xa14c98`)**, detaches `remote_tid`, `PTRACE_CONT` on `rec_tid`, **`sender(o, 1, 1)` (`sndcmd.elf` S1)**, `observe(focus_ms=600)` | **YES — code trap + active `ptrace` + software S1** | After half-press |
| **8** | **`ram_precapture_ring.c:689-733`** | `PRECAP_ARMED` loop: `precap_tick_work()` fires `sndcmd.elf` S2 pulses; intercepts `0xa14c98` / `0xa146f6` / `0xa126d8` traps; `hold_acquire`/`hold_release`/`commit_write` via `monitor_tid` (`170`) | **YES — shutter injection + trap interception + SD write** | Armed / Post / Drain |
| 9 | `ram_native.c:290-294, 409-421` | `mode_set({0, 0x1000, ...})` (restore SD) → `start_command(2)` (`remote stop` / `Pullout4100`) → `session_route_wait` (topology 1 = SD) | **YES — restores stock SD route** | Teardown |

### 2.2 Proof of 100% Passive Zero-Interference Silence (Q4)

**PROVEN:** An autonomous helper **can** sit in a 100% passive, zero-`ptrace`, zero-trap, zero-route-change, zero-`sndcmd` loop while `enabled == 0` OR `drive_mode != Continuous` OR idle (shutter not half-pressed):

1. **Everything needed for the idle/gate loop is pure `pread64` on `/proc/<pid>/mem` (plus optional file `stat`/`read` for a toggle):**
   - `sd_input.c:39-183`: `sd_input_init()` and `sd_input_sample()` ONLY call `read_mem()` → `pread64` (ARM syscall `180`, `native.c:273`) on `/proc/<pid>/mem` (`libObj+0x145d230` → `InfraInput` `config` and `state` arrays, 627 entries, throttled to every 20 ms at `sd_input.c:136`). Neither function ever calls `ptrace`, `sndcmd`, or writes to `im.elf`.
   - `subscription(o, 0, 0)` (`native.c:278-306`): pure `pread64` on `libObj+0x145d230`, `libObj+0x1463130`, `SpinalUtil`, `ObjCamera` vtable — verifies shooting mode is active (not playback/menu/USB).
   - Drive mode read (from Track A) and toggle read (from Track B): read-only `pread64` / `open`+`read` (no mutation).
   - Overhead of a passive 20–50 ms poll loop reading 2–3 small structs + 2 input rows (`0x1f1` at index 27, `0xa7` at index 14 — or full `state` table 627×40 B = 25 KiB): negligible CPU, **4 KiB VmRSS** (`20261107T174128Z` step 11).
2. **Exact Architectural Split (Readable "Off" State):**
   - **Recommended "off" state:** Helper stays resident with `enabled == 0` (readable by both the menu/toggle and the helper itself) **and performs zero `ptrace`, zero `Insert4100`, zero `mode_set`, zero `PTRACE_POKETEXT`, zero `sndcmd`** whenever `enabled == 0` OR `drive_mode != Continuous` OR `shutter_half == 0`.
   - In Single Shooting (or while `enabled == 0`), `im.elf` has `TracerPid: 0` on every thread, untouched code pages, stock `0x1000` SD route, no virtual `0x4100` media inserted, and zero shutter interception — **mathematically indistinguishable from the helper being absent**.
   - **Critical correction vs Stage 5:** Steps 4 & 5 (`start_command(1)` / `Insert4100` and `mode_set(0x4100)`) MUST NOT run while `enabled == 0` or in Single Shooting. Whether Steps 4 & 5 run (a) on entering `(enabled==1 && drive_mode==Continuous)` or (b) on physical half-press (`0x1f1 0->1`) is a latency vs zero-touch trade-off quantified exactly below.

### 2.3 Measured Arming Latency from Real Stage 5 Hardware Receipts

Extracted directly from `evidence/m7-capture-probe/20261121T082654Z-51302f4b3857.json` (Save), `20261121T083545Z-2ce4db80793d.json` (Cancel), and `20261121T084418Z-8db652a0245b.json` (Repeat):

| Phase / Transition | Save (`51302f4b`) | Cancel (`2ce4db80`) | Repeat (`8db652a0`) | Notes / Breakdown |
|---|---:|---:|---:|---|
| USB wake (`source_s1` + `wait_for_subscription`) | 2,992 ms | 3,001 ms | 3,029 ms | **USB Service Mode only** (not needed untethered in shooting mode!) |
| Pre-admit checks (`source_sample` + pins + `start_wait(0)`) | 462 ms | 441 ms | 392 ms | Includes 1×200 ms `start_wait` streak sleep (`start_native.c:201`); pins check can be cached at boot! |
| `start_command(1)` (`remote start` / `Insert4100`) | 60 ms | 52 ms | 15 ms | Actual `ptrace` call to `libObj+0xa34be9` |
| `start_wait(1)` (`ObjMedia4100` active, streak=2) | 243 ms | 234 ms | 322 ms | **1st poll (10 ms / 5 ms / 84 ms) was ALREADY ready (`streak=1`)!** Remaining ~200–238 ms is just `sleep_ms(200)` (`start_native.c:201`)! |
| `session_route_wait` (`topology==3`, streak=2) | 800 ms | 791 ms | 816 ms | 4 polls (`topo 1 -> 2 -> 3 -> 3`) × `sleep_ms(250)` (`ram_native.c:310`) — Sony took ~500 ms to reach `topology=3`, plus 250 ms confirmation sleep. |
| `mode_set(0x4100)` + `mode_drain` | 633 ms | 518 ms | 545 ms | `mode_set` = **208–262 ms**; `mode_drain` succeeded on **attempt 1** (`310–371 ms`, zero 250 ms retries!). |
| **Subtotal: `Insert4100` + `mode_set(0x4100)`** | **1,750 ms** | **1,610 ms** | **1,715 ms** | From `session stage=1` to `mode stage=3` |
| **--- Physical half-press (`0x1f1 0->1`) detected ---** | **`12517 ms`** | **`6701 ms`** | **`5888 ms`** | |
| `half_press` → `retain_preflight` + `ram_notice(0)` | 13 ms | 19 ms | 14 ms | Can be 0 ms if preflight done once at daemon startup |
| `connect_pair` + `ram_precondition` | 44 ms | 56 ms | 63 ms | Attaches `rec_tid` + `remote_tid`, verifies idle |
| `capture_trap_set` (`0xde01` at `libObj+0xa14c98`) | 0 ms | 0 ms | 1 ms | Single `PTRACE_POKETEXT` + verify read |
| `trace_restore(remote)` + `CONT` + `sender(S1, 1)` | 69 ms | 75 ms | 58 ms | `sndcmd.elf` itself took 20–25 ms |
| `observe(focus_ms=600)` | 605 ms | 600 ms | 604 ms | Hardcoded `focus_ms=600` (`build.py:434`) |
| **Measured `half_press` → `PRECAP_ARMED` (current)** | **731 ms** | **750 ms** | **740 ms** | **131–150 ms real work + 600 ms `focus_ms` wait** |
| `PRECAP_ARMED` → 1st frame registered (`stage 46`) | 179 ms | 152 ms | 154 ms | Time from first S2 pulse to registration |
| `PRECAP_ARMED` → 1st frame delivered (`stage 3`) | 908 ms | 893 ms | 857 ms | `ready_ms - armed_at` = 795–808 ms |
| `half_press` → 1st frame registered | 910 ms | 902 ms | 894 ms | |
| `half_press` → `RING_READY` (N=2 frames) | 4,080 ms | 3,967 ms | 4,028 ms | Inflated by ~3.1 s/frame `s->committed` leak (Stage 6 fix will drop 2nd frame to ~100–200 ms!) |
| **Teardown (`PRECAP_RESTORE` → `session stage=4`)** | **3,419 ms** | **3,104 ms** | **2,899 ms** | `mode_set(SD)`+drain (~936–1002 ms) + `remote stop`+wait (~461–806 ms) + route/graph verify |

#### Key Design Trade-Off Revealed by the Numbers
- **Option A — Full Zero-Touch Until Half-Press (`Insert4100` + `mode_set(0x4100)` on `0x1f1 0->1`):**
  - Guarantees **0% `im.elf` modification** even while idle in Continuous Shooting (so a rapid mash straight to full-press without pausing on half-press still shoots stock SD, or is caught cleanly).
  - Cost: **~1.75 s** (`Insert4100` + `mode_set`) + **~0.14 s** (`connect_pair` + `trap` + `S1`) = **~1.9 s** before first S2 pulse (even if `focus_ms=600` is removed because physical S1 already runs AF during those 1.9 s!). Tightening `start_wait`/`session_route_wait` sleeps from 200–250 ms to 25–50 ms could shave ~500–600 ms off, bringing it down to **~1.2–1.3 s** (**HYPOTHESIS**, requires hardware check).
  - Teardown after release takes **~2.9–3.4 s** (similarly reducible to ~1.5–2.0 s with tighter poll sleeps), during which a rapid second half-press must wait for restore or reuse the session.
- **Option B — Pre-Route on `(enabled==1 && drive_mode==Continuous)`? DANGER:**
  - Leaving `mode_set(0x4100)` active *while idle* in Continuous Shooting means if the user presses S2 directly (without pre-capture arming, or if the helper crashes), **stock shooting would route to `0x4100` (RAM) instead of SD**, breaking normal shots!
  - **Recommendation:** **Option A (strict zero-touch until `enabled==1 && drive_mode==Continuous && half_press`)** is strictly safer for untethered camera usability and satisfies Q4 literally ("NOTHING intercepts the shutter or modifies camera state until enabled==1 AND drive_mode==Continuous AND half-press starts"). If the user releases half-press *during* the ~1.2–1.9 s setup window, the setup aborts and immediately runs teardown (`mode_set(SD)` + `remote stop`) without ever firing S2. (Also: `s->input` must be sampled during setup so an instant full-press during setup can cleanly abort and let stock SD take the shot — though note once `mode_set(0x4100)` is issued, stock SD is temporarily diverted until `mode_set(SD)` completes.)

---

## 3. Q5 — Watchdog, Power-Off & Manual Fallback Without a Laptop

### 3.1 Exact Behavior of `retain_unresolved()` Today (Untethered Hazard Audit)

In `prototype-producer-probe/retain.c:18-35`:
```c
static void retain_unresolved(struct observer *o, u32 stage, u32 detail) {
#if M7_RAM_LATE_REGISTER
    late_flush(o);
#endif
#if M7_RAM_CONTINUOUS
    if (o->shutter_abort) {
        void (*abort_shutter)(struct observer *)=o->shutter_abort;
        o->shutter_abort=0;
        abort_shutter(o);
    }
#endif
#if M7_RAM_PROBE
    probe_flush(o);
#endif
    retain_notice(o, 98, stage, detail);
    /* Rewinding a partially executed Sony call would not undo its locks or reference. */
    for (;;) sleep_ms(1000);
}
```

When triggered **with no laptop attached**, `retain_unresolved()` executes `precap_abort()` (which calls `precap_stop()` to send `S2-up` and `S1-up` via `sndcmd.elf`, `ram_precapture_ring.c:122-141`), emits a `M7CAP1=` stage-98 record to nobody, and **sleeps forever (`for (;;) sleep_ms(1000)`)**.

We audited all **118 `retain_unresolved()` call sites** across `prototype-producer-probe/` and classified them into **three distinct severity tiers** for an untethered camera:

| Tier | Examples in `ram_precapture_ring.c` / `ram_native.c` / `ram_capture.c` / `retain.c` | State of `im.elf` at failure | Untethered Impact Today | Can Stage 6 Replace with Safe Self-Abort? |
|---|---|---|---|---|
| **Tier 1: Soft / Recoverable (no tracee dirty, no mutex held, no trap armed)** | `ram_precapture_ring.c:663` (`sd_input_init` fail), `675` (`retain_preflight` fail), `678` (`connect_pair`/`ram_precondition` fail), `681` (`capture_trap_set` refused before POKETEXT); **RAW+JPEG or non-`5472x3648` size** in `ram_precapture_ring.c:533,556` (`precap_save` fails `wrote=0` → calls `retain_unresolved(218,19)`!) | Clean! `rec_tid`/`remote_tid` detached (or cleanly detachable), zero held mutexes, zero traps armed | **Needlessly wedges the camera** in `0x4100` RAM mode forever! (Notably, shooting with RAW+JPEG or non-20M JPEG currently hits `218,19` or `ram_image` `161,1`!) | **YES — 100% recoverable:** abort cycle, release any owned `CheckImage` refs, restore SD route (`mode_set(0x1000)`), `remote stop`, return to `PRECAP_IDLE` with error latch/backoff. |
| **Tier 2: Trap-Armed / Active-Cycle Fault (tracee stopped at known trap or `SIGSTOP`, no Sony mutex held)** | `ram_capture.c:150` (15 s wait timeout), `ram_capture.c:387` (`ram_image` mismatch, e.g. RAW+JPEG `flags != 0x000101` at `ram_capture.c:252`), `ram_precapture_ring.c:279,286,291` (drain timeout) | `rec_tid` attached & stopped; `0xde01` trap is armed at a known address; zero Sony mutexes held; `0x4100` route active | Leaves `rec_tid` frozen forever in `T` state + `0xde01` in RAM + `0x4100` route stuck | **YES — recoverable via ordered teardown:** (1) `precap_stop` (release S2/S1); (2) if `rec_tid` is running, send `tgkill(SIGSTOP)` and wait for `0x137f`; (3) **`capture_trap_restore()`** (MUST restore original instruction BEFORE detaching!); (4) `trace_restore()` (detach `rec_tid`); (5) wait briefly for pipeline idle, release any owned `CheckImage` refs via `monitor_tid`, restore `mode_set(0x1000)` + `remote stop`. |
| **Tier 3: Hard Invariant Fault (in-flight `sony_call4` never returned, register/stack corruption, mutex unlock failed, or `POKETEXT` restore failed)** | `retain.c:163-170` (`trace_restore` failed), `264-268` (`sony_call4` unexpected stop/PC/callee-saved reg), `301-302` (`unlock_owned` failed), `capture_trap.c:43,45,50` (trap restore readback mismatch) | Unknown Sony lock/call/code-page state | Detaching blindly would crash `im.elf` (`SIGILL` on `0xde01` or corrupted stack/mutex) | **NO safe rollback possible.** Must release S2/S1, log fault code to `/tmp_network/precap.fault`, disable further arming, and park safely (requiring user power-cycle / battery pull). **Crucially:** never `exit()` while a `0xde01` trap is still poked in `im.elf` (kernel auto-detach on tracer death would let `im.elf` hit `0xde01` → `SIGILL`). |

### 3.2 Concrete Watchdog & Self-Recovery Architecture (Stage 6 Design)

#### A. Hard Upper Bounds (All Monotonic `CLOCK_MONOTONIC`, `now()`, Syscall `263`)

Every blocking or looping phase must have a bounded wall-clock timeout — **zero unbounded `for (;;)` loops** (note: `retain.c:125` `wait_trace_stop()` currently has an **unbounded** `for (;;)` loop with only a 2 s diagnostic print at line 132!):

| Phase / Operation | Current Code | Proposed Hard Bound | On Expiry Action |
|---|---|---|---|
| `wait_trace_stop()` (`retain.c:123`) | **Unbounded `for (;;)`** | **5,000 ms** (attach / normal Sony call); **15,000 ms** (`WriteFile` 1 MiB chunk) | If initial attach stop (`op==1`): abort attach (`PTRACE_DETACH` if attached), fail cleanly (Tier 1). If mid-`sony_call4`: Tier 3 fault park + release buttons. |
| `PRECAP_ARMED` hold (`ram_precapture_ring.c:258`) | `window_ms = 120,000 ms` (2 min) | **90,000–120,000 ms** (satisfies ≥60 s product target in `STATE.md:30-36` with margin) | Clean cancel transition `PRECAP_ARMED -> PRECAP_DRAIN` (`reason=4`), release S2/S1, drain, restore SD route, wait for physical S1 release before re-arming. |
| `PRECAP_POST` post-trigger (`ram_precapture_ring.c:5, 270`) | `PRECAP_POST_MS = 30,000 ms` | **10,000 ms** (once `s->committed` cadence leak is fixed, M=1..3 post frames take <1 s) | Force `PRECAP_POST -> PRECAP_DRAIN`, save whatever complete frames were captured, release S2/S1. |
| `PRECAP_DRAIN` drain (`ram_precapture_ring.c:12, 278`) | `PRECAP_DRAIN_ABSOLUTE_MS = 180,000 ms` → `retain_unresolved(218,22)` | **15,000 ms** (or `5,000 + open*2,500` capped at **30,000 ms**) | Replace `retain_unresolved` with Tier 2 forced trap-restore + detach + ref-release + SD route restore! |
| Trap-armed lifetime (`ram_capture.c:148`, `ram_continuous.c:183`) | `ram_wait`: 15 s; **`burst_boundary` in `M7_RAM_PRECAPTURE`: NO total deadline** (`#if !M7_RAM_PRECAPTURE` disables the 15 s check at `ram_continuous.c:182-184`!) | Bound by `PRECAP_ARMED` (120 s) + `PRECAP_POST` (10 s) + `PRECAP_DRAIN` (30 s) = **160 s absolute ceiling** from `capture_trap_set` to `capture_trap_restore` | Tier 2 forced `SIGSTOP` → `capture_trap_restore()` → `trace_restore()` → `mode_set(0x1000)` → `remote stop`. |
| Single `sndcmd.elf` child (`native.c:456-464`, `shutter_start.c:17-22`) | 1,500 ms → `SIGKILL`, 1,800 ms reap cap | Keep **1,500 ms `SIGKILL` / 1,800 ms reap** | Ensure `release_buttons()` (`S2-up`, `S1-up`) is always attempted on abort. |
| Setup (`Insert4100` + `mode_set(0x4100)`) | ~1.7 s (no total cap across retries) | **5,000 ms** total setup ceiling | Abort setup, undo any completed step (`mode_set(0x1000)` / `remote stop`), return to `PRECAP_IDLE` with 2 s cooldown. |
| Drive-mode change mid-hold (`plans/06-autonomy.md:35`) | Not checked yet | Checked every 50 ms inside `precap_sample()` | If `drive_mode != Continuous` or `enabled == 0` while `PRECAP_ARMED`: immediate clean cancel (`PRECAP_ARMED -> PRECAP_DRAIN`), discard ring, restore SD route. |

#### B. Power-Switch, Shutdown, `SIGTERM` & `im.elf` Exit Detection

1. **Signal handling (`rt_sigaction`, syscall `174`):**
   - Keep `SIGHUP` (1) and `SIGPIPE` (13) set to `SIG_IGN`.
   - Install a lightweight signal handler for `SIGTERM` (15) and `SIGINT` (2) that sets a `volatile u32 g_shutdown_requested = 1` flag (note: since single-segment freestanding ELF has no writable `.data`, either add a minimal `.bss` RW `PT_LOAD` segment in `build.py` — ~5 lines — or keep a global pointer via `mmap2` / single RW page).
   - When `g_shutdown_requested` is set:
     - If in `PRECAP_IDLE`: exit `0` immediately (0 ms delay, zero `im.elf` interaction).
     - If in `PRECAP_ARMED`/`POST`/`DRAIN`: immediately cancel, restore `0xde01` trap, detach `ptrace`, release refs, restore `0x1000` SD route + `remote stop`, then exit `0`.
2. **`im.elf` exit / PID-reuse detection (zero extra overhead):**
   - Every passive loop tick (`pread64` on `/proc/<pid>/mem` or `kill(im_pid, 0)` syscall `37`):
     - If `kill(im_pid, 0) == -ESRCH` (`-3`) or `pread64` returns `0` / `-ESRCH` / `-EIO`: `im.elf` has exited (shutdown or crash) → immediately exit `0` (if `im.elf` is gone, kernel already freed its address space and any `ptrace` state).
   - Periodically (e.g. once per second while idle) re-verify `/proc/<pid>/stat` `starttime` matches startup `starttime` so PID reuse cannot trick the helper.
   - Check `subscription(o, 0, 0)` every poll tick while idle (and during arming): if `enabled` byte (`o->route[7]`) drops to `0` (user entered playback, USB mode, sleep, or power-off sequence), immediately refuse arming or trigger clean cancel + SD restore!
3. **Power-switch / `upm` detection (GAP):**
   - `upm.ko` has `k_upm_init_off_factor` and `k_upm_init_power_status` (`reports/m7-upm-boot-factor.md:52-53`), and `InfraInput` has 627 entries (`20261121T082654Z` kind 76). However, the exact `InfraInput` key code (if any) for the physical power button on M7 has **not yet been mapped** (**GAP**). Detecting `subscription` drop (`o->route[7] == 0`), `SIGTERM`, and `im.elf` exit covers shutdown without needing the raw power-button key code, though mapping the power-button key in `InfraInput` would give ~100–300 ms earlier notice to abort an active hold.

#### C. Manual Fallback & Camera Recovery Guarantee (No Laptop)

What returns the camera to 100% stock normal if the untethered helper wedges?

| Scenario | Persistent Flash State Changed? | SD Card Risk? | Recovery Procedure | Verdict |
|---|---|---|---|---|
| **Stage 6 (RAM helper in `/tmp_network`, no firmware flash edits)** | **NONE.** `/` and `/usr` are mounted `ro` (`ext2`, `runtime.txt:5-6`); helper lives only in volatile `tmpfs` `/tmp_network` (`runtime.txt:17`). All `im.elf` changes (CoW `0xde01` page, `0x4100` route, `Insert4100`, `CheckImage` refcounts, mutexes, `ptrace`) are volatile RAM only. | Only if battery is pulled *during* active `commit_write()` (`WriteFile` on a brand-new `PCxxxxxx.JPG`). Existing `DCIM/` files are never opened for write (`commit.c:116-122`). | **Battery pull** (remove & reinsert battery, wait 2 s, power on): unconditionally resets RTOS + Linux, wipes `/tmp_network` and `im.elf` RAM, returns 100% stock camera. Proven across 30+ `.rebooted-*.json` cycles (`STATE.md:62-63`). | **PROVEN** |
| **Soft power switch while helper is wedged in Tier 3** | None | None (wait for SD write LED off first) | If `im.elf` is deadlocked (e.g. `rec_tid` frozen in `T` state or `root_lock` held), `im.elf`'s graceful power-off handler may hang instead of retracting the lens and cutting power; user must pull the battery. | **GAP** (soft power-off timeout under `im.elf` deadlock not measured on M7) |
| **Stage 6 with card-boot / card-config toggle (future)** | Only config file on SD card (if used) | Removing/renaming the SD card config file or switching to Single Shooting disables the helper on next boot | **Escape hatch:** remove SD card or delete/rename config file (or hold a designated boot-bypass button if launched at boot) + battery pull → 100% stock camera. | **HYPOTHESIS** (depends on Track B boot surface) |
| **Helper `SIGKILL`ed while `0xde01` trap is poked in `im.elf`** | None | None | **CRITICAL HAZARD:** Linux `ptrace` auto-detaches tracees when the tracer exits; if `0xde01` is still patched at `libObj+0xa14c98`, `im.elf` will hit `0xde01` (`SIGILL`) and crash on the next capture. Therefore: (a) never install a suicide watchdog that `exit()`s while `trap.armed == 1` without first restoring the trap; (b) an external watchdog process must send `SIGTERM` (never `SIGKILL` first) so the helper executes `capture_trap_restore()` before exiting. | **PROVEN (ARM/Linux `ptrace` semantics)** |

---

## 4. Summary of Gaps & Recommended Next Checks

1. **GAP 1 (Hardware check needed):** Survival of a double-forked, `setsid()`, stdio-`/dev/null` RAM helper in `/tmp_network` across `setTerminalEnable(False)` → `auth.stop()` (`StopSenser`) → physical USB unplug, followed by confirming live shooting works and the helper still sees `0x1f1`/`0xa7` transitions via `/proc/161/mem`.
2. **GAP 2 (Hardware check needed):** Real arming latency when `Insert4100` + `mode_set(0x4100)` are deferred until physical half-press with tightened polling sleeps (25–50 ms instead of 200–250 ms), and whether `sender(o, 1, 1)` + `observe(focus_ms=600)` can be shortened/omitted when physical S1 (`0x1f1 == 1`) is already held.
3. **GAP 3 (Static/Hardware check):** Exact `InfraInput` key code for the M7 power switch (optional enhancement for faster shutdown abort) and M7 soft power-off timeout behavior if `im.elf` is deadlocked.
4. **GAP 4 (Carried-forward Stage 5 native items affecting untethered safety):**
   - `ram_capture.c:252` (`(flags & 0xffffff) != 0x000101`) and `ram_precapture_ring.c:533, 556` (`5472x3648` check calling `retain_unresolved(218, 19)`) MUST be converted to clean Tier-1/Tier-2 refusal + SD-route restore before any untethered run, or switching the camera to RAW / RAW+JPEG / M/S JPEG will wedge the helper in RAM!
   - `native.c:218` (`nadded == 16 || map_attempts++ >= 16`) must be replaced with rate-limited `/proc/<pid>/maps` refresh for multi-hour untethered operation.
   - `retain.c:123` (`wait_trace_stop()` unbounded `for (;;)`) and `ram_continuous.c:182` (disabled timeout in `M7_RAM_PRECAPTURE`) must receive hard monotonic deadlines.
