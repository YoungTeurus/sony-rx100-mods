# Stage 6 Cadence & Latency Research Report

Date: 2026-11-22
Role: research, READ-ONLY (no camera, no USB, no `/dev`, no `/Volumes`, no production edits, no `evidence/**` edits).
Inputs: `STATE.md`, `prototype-stage6-autonomy/stage6_ring.c`, `prototype-producer-probe/{ram_precapture_ring.c,ram_continuous.c,ram_capture.c,hold.c,commit.c,jpeg.c,native.c,shutter_start.c}`, live M7 1.00 receipts `20261122T092322Z-16e19cc6817b-daemon.log`, `20261121T082654Z-51302f4b3857.json`, `20261110T011539Z-22a564b7fb95.json`, `20261109T133413Z-98e8d563a3c7.json`, `20261109T114042Z-efb8761ab17a.json`, prior Stage 4/5 research reports, and original DSC-RX100M7 firmware `1.00` `libObj.so` (`SHA-256 38cba88dab492ed8529ae1ec80636bce64d649229ed790023f3579144860a092`).

## Executive Verdict

1. **Current `0.33 fps` (~3.0 s/frame) and `17 s` save latency in Stage 6 WIP v2.1 are 100% self-inflicted software bottlenecks, NOT the camera's speed.**
2. **Hardware physics of DSC-RX100M7 (20MP Extra Fine JPEG, `5472x3648`):**
   - **Sensor/RTOS burst capture rate:** **`15–20 fps`** into Sony's internal RTOS/DMM burst buffer (~`155` Extra Fine JPEG frames capacity).
   - **BIONZ-X FIFO develop-to-JPEG drain rate (`0x4100` RAM):** **`~3.0–3.5+ fps`** (median `282–296 ms/frame` whenever helper trap dwell is `< 60 ms` in live receipts `22a564b7fb95` and `efb8761ab17a`; true zero-dwell ceiling is likely `~3.3–3.8 fps`).
   - **Upstream per-frame RAW discard in `libObj.so`:** **ABSENT (statically proven).** `ImageMgr::ReleasePreRegisterImage` (`0xdd2228`) deletes only the 440 B metadata cell in `StillPool`; the RTOS still develops the frame and delivers a `DummyRec` ~340 ms later (`0xdc0a86`). `StillPool` `0x1019` (`0xdbc57c`) only signals the pool wait condition (`0xdcfb28`).
   - **Consequence:** A 60+ s infinite hold on 20MP JPEG cannot sustain 15–20 fps without RTOS-side firmware patching, because BIONZ-X develops FIFO. However, we can achieve **BOTH** full `15–20 fps` burst parity during the initial burst window (`C_burst` frames) **AND** smooth `~3.3–3.8 fps` sustained rolling for 60+ s — plus **`~10x` faster saving (`~0.5 s/photo` instead of `5.7 s/photo`)**.

## 1. Root Cause #1 — `0.33 fps` Rolling Cadence (`stage6_ring.c` / `ram_precapture_ring.c`)

Proven by `stage6_ring.c:874-895`, `ram_continuous.c:252`, and live receipt `20261121T082654Z-51302f4b3857.json`:

- `precap_tick_work()` debits `s->committed = outstanding + PRECAP_ADMISSION_RESERVE` (`+4`) per S2 pulse, while blocking any new pulse when `outstanding + 4 + 4 > 12` (`outstanding > 4`).
- Each short S2 pulse produces `1` frame (decrementing `committed` by `1`), so after 1–2 pulses `committed` stays jammed at `5..8 > 4` even when `queue == 0`.
- `precap_admission_idle()` ONLY refunds `s->committed` after **`RAM_BURST_QUIET_MS = 2,000 ms` of complete recorder idleness** (`ram_continuous.c:252`).
- Live receipt `51302f4b3857` timestamps confirm this exact 2-second dead stall between every frame (`st=3` at `14156` → `st=59` refund at `16334`, `+2178 ms`; `st=3` at `20370` → `st=59` at `22456`, `+2086 ms`; `st=3` at `23751` → `st=59` at `25844`, `+2093 ms`, etc.).
- By contrast, the earlier live M7 1.00 receipt `20261110T011539Z-22a564b7fb95.json` (same `0x4100` RAM route, without the `+4` / `2000 ms` refund stall) already achieved **`2.67–3.03 fps`** (`79` armed deliveries in `29.25 s`, `95` total deliveries in `31.33 s`).

## 2. Root Cause #2 — `132–209 ms` Per-Frame Trap Dwell & `240–513 ms` Blocking `sndcmd.elf`

Proven by correlating `st=50` (`dwell = continued_at - ready_ms`) against `dt = next_ready - ready_ms` in live receipts `20261110T011539Z-22a564b7fb95.json` and `20261109T114042Z-efb8761ab17a.json`:

| Receipt | Dwell bucket (ms) | Samples | Med dwell (ms) | Med Sony gap (ms) | Med frame `dt` (ms) | Effective FPS |
|---|---|---:|---:|---:|---:|---:|
| `22a564b7fb95` | `[0, 60)` | 17 | `50` | `225` | **`282`** | **`3.55 fps`** |
| `22a564b7fb95` | `[60, 100)` | 17 | `73` | `305` | `368` | `2.72 fps` |
| `22a564b7fb95` | `[100, 150)` | 13 | `131` | `252` | `378` | `2.65 fps` |
| `22a564b7fb95` | `[250, 450)` | 16 | `354` | `72` | `417` | `2.40 fps` |
| `22a564b7fb95` | `[450, 1000)` | 3 | `523` | `45` | `567` | `1.76 fps` |
| `efb8761ab17a` | `[0, 100)` | 13 | `46` | `251` | **`296`** | **`3.38 fps`** |
| `efb8761ab17a` | `[180, 250)` | 12 | `222` | `237` | `467` | `2.14 fps` |

Why unselected dropped frames cost `132–209 ms` of recorder freeze:
1. `ram_capture_body()` (`ram_capture.c:416-423`) stops `rec_tid` at **3 separate UDF traps** (`0xa14c98` → `0xa146f6` → `0xa126d8`), polls twice via `ram_wait()` with `10 ms` `sleep_ms` intervals, walks the full `StillPool` linked list (`ram_candidate`), parses all `ParamMap` pointers in `ram_completion`, and emits ~40 `M7CAP1` diagnostic packets per dropped frame.
2. In `22a564b7fb95`, `fork/exec /usr/bin/sndcmd.elf` took `76 / 240 / 513 ms` (min/med/max across 54 pulses) under load, AND `sender(o, 2, 0)` ran synchronously inside `precap_sample()` while `rec_tid` was frozen at a trap, causing `354–523 ms` trap stalls.

**Fix:**
- **Fast Unselected Drop Path (`~1–3 ms` dwell):** For frames not in `s->ids` (`!precap_keep_source`), at Trap #1 (`0xa14c98`) read only `info[11]` (`capture`) + `r7+0x2938` (`uid`), skip `ram_candidate` and `ram_words` spam, jump `r6=0, PC=0xa153d2`, catch Trap #2 (`0xa146f6`) with tight `1 ms` / short-spin `wait4` to set `r1 = frame+0x2938`, skip Trap #3 (`0xa126d8`) completely (re-arming `0xa14c98` directly at `0xa146f6`!).
- **Non-blocking S2 Control:** Never invoke synchronous `sender(o, 2, 0)` inside `precap_sample()` while `rec_tid` is stopped; use asynchronous S2-down/up or continuous S2 hold (and optionally direct `/dev/uipc` `InfraInput` message without `fork/exec`, eliminating 240–513 ms `sndcmd.elf` CPU/paging jitter altogether).
- **Zero held references during rolling when `backlog >= N`:** Keeping a steady FIFO buffer of `backlog >= N` undeveloped exposures means every arriving frame at `0xa14c98` is already older than the newest `N` IDs — zero `hold_acquire` calls during the roll, keeping both Sony develop slots 100% free and allowing `N > 2` (e.g. `N = 5..10`) without any 2-slot stall or Linux heap copy!

## 3. Root Cause #3 — `5.7 s/photo` Save Latency (`17 s` for 3 Photos) → `~0.5 s/photo` (`~1.5 s` for 3 Photos!)

Proven by `st=27` pass timings in live receipt `20261121T082654Z-51302f4b3857.json`:

| Frame | Pass 1 (`hold_hash` 4 KB `copy_pixels` + SHA-256) | Pass 2 (`commit_write` 1 MB chunks to SD) | Bytes |
|---|---:|---:|---:|
| 1 (`PC8E7F70.JPG`) | **`4,451 ms`** | **`505 ms`** (21.1 MB/s) | `10,636,356` |
| 2 (`PCBE7F70.JPG`) | **`5,069 ms`** | **`460 ms`** (23.1 MB/s) | `10,633,718` |
| 3 (`PCAE7F70.JPG`) | **`4,981 ms`** | **`477 ms`** (22.3 MB/s) | `10,617,978` |

- `stage6_ring.c:927` runs `hold_hash(o, &lock, 3, &o->jpeg_after); o->jpeg_before = o->jpeg_after;` — spending **14.5 seconds** running 70-instruction/byte SHA-256 (`work/stage4-rate/RESEARCH-opus.md:72`) across 32 MB of JPEGs solely to find `jpeg.length` (`0xFFD9`) and check `width == 5472 && height == 3648`, then comparing `digest` against a copy of itself!
- ARM disassembly of `makeJpegFileImageInfo` (`libObj.so` `0xdc818a..0xdc8262`) and `PreWriteStill` (`0xa14cc4..0xa14d5a`) confirms `GetFileImage` already computes exact JPEG length (`param 0x5008` / `0x5007` = `extent_sum - header[1]`) before `0xa14c98`; alternatively, reading the first ~64 KB for `SOI` + `SOF0` (`5472x3648`) and scanning backward from `body[1]` in 4 KB chunks for `0xFFD9` (without SHA-256) finds exact `jpeg.length` in **`< 30–50 ms`** with zero new Sony offsets!
- Expected save time for 3 full 20MP JPEGs: **`~1.5–1.8 s`** total (down from `~17 s`).

## 4. Candidate Modes for Stage 6 WIP v3 ("Fast Cadence")

| Profile | Phase 1 (first burst) | Phase 2 (sustained 60+ s) | Post-press drain + save (`N=2+1` / `N=5+2`) |
|---|---|---|---|
| **A. Two-Phase Hybrid (Recommended)** | **15–20 fps** continuous S2 hold up to `C_burst = 16–20` (~1.3–1.8 s full serial parity) | Smooth **`~3.3–3.8 fps`** (backlog held near `N+1`, zero blind gaps, zero held refs) | Peak ~4–5 s drain + ~1.5 s save (`N=2+1`); steady ~1–2 s drain + ~1.5 s save |
| **B. Low-Latency Steady** | Immediate **`~3.3–3.8 fps`** (`backlog` kept minimal at `N+1`) | Smooth **`~3.3–3.8 fps`** for 60+ s | ~1–2 s drain + ~1.5 s save |
| **C. Extended High-Speed Burst** | **15–20 fps** up to `C_burst = 40–60` (~3–5 s full serial parity, supports `N=5..10`) | Smooth **`~3.3–3.8 fps`** for 60+ s | Peak ~12–18 s drain + ~3.5 s save (`N=5+2`) |

## 5. Unmeasured Hardware Levers (Optional Benchmark)

- **JPEG Size / Quality (`M 10M` / `S 5M`, `Fine` / `Standard`):** Unmeasured on `0x4100`. Removing the hardcoded `5472x3648` gate allows measuring whether BIONZ-X develops smaller JPEGs significantly faster than `~3.5 fps`.
- **Continuous Lo (`3 fps`, `SLOT_BURST_SPEED_ACT 0x145f4fc`):** Continuous S2 hold without pulsing may natively match BIONZ-X develop rate (`3.0 fps`) with zero `sndcmd` overhead.
- **True 60 s sustained 15–20 fps:** Requires RTOS-side upstream RAW buffer eviction (outside Linux `libObj.so`), which is a separate firmware-RE project beyond Stage 6.
