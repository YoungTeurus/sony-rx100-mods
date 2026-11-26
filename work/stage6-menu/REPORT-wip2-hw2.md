# Stage 6 WIP v2.1 (r13) Live Hardware Run #2 Report

Date: 2026-11-22
Commit tested: `f689a63` (`Stage 6 WIP v2.1 (r13)`)
Camera: Sony DSC-RX100M7, firmware `1.00` (unmodified), `29110_03.2021050601`, JPEG L 20M 3:2 (`fmt=0xbd, size=0xb3, asp=0xb9, qual=0xbc`), SD card inserted.

## Sealed Release & Receipts

| Artifact | Path / Published Excerpt | SHA-256 |
|---|---|---|
| Sealed manifest (r13) | `prototype-stage6-autonomy/out-v2/build.json` (at `f689a63`) | `6f23b62c1eef708f072d7adf44bcc7ae629fe3681afa7545e2e0b29ebabf3204` |
| Sealed daemon template (`35,986 B`) | `prototype-stage6-autonomy/out-v2/stage6_daemon.elf` (at `f689a63`) | `68f3d22537f2282bd182beab3b353fb844f910fc48e4c07b5b29793c59201dce` |
| Sealed ring template (`122,972 B`) | `prototype-stage6-autonomy/out-v2/stage6_ring.elf` (at `f689a63`) | `811054b37e0c683681f554ef52437eb3afa9a390d29682e28ea55853e80f1eac` |
| Start receipt (`nonce=cd9aba309d54`) | `20261122T091619Z-cd9aba309d54-start.json` (operator archive) | `0392c3db0623a7d1ffb58b2d1de054a9efa6f94f4e4e9457df7c683fcb0b9863` |
| Collect receipt (`nonce=16e19cc6817b`) | `20261122T092322Z-16e19cc6817b-collect.json` (operator archive) | `906e22ad7411802701fb7e646c7208ba03b40733670c12767d65605ca14c814f` |
| Saved daemon log (`188` lines) | [evidence/run-2-events.log](../../evidence/run-2-events.log) (excerpt of `20261122T092322Z-16e19cc6817b-daemon.log`) | `834f9caab08f1f2875f7efaf2dc38700305746545b61011fcc52eeb76e10e623` |
| SD card readback receipt | [evidence/run-2-card.json](../../evidence/run-2-card.json) | User-run `--check-card-only` on `/Volumes/RX100M7` (`all_ok: true`, `checked: 3`) |

Configured per-run ELF hashes (`nonce=cd9aba309d54`, `pre=2`, `post=1`, `duration_ms=600000`, `toggle_bkid=0x01071472`, `toggle_on_val=0`, `debounce_ms=100`, `focus_ms=300`):
- `daemon.elf`: `7dc66261efff99b3b305d9f8cc136ae896e8778cf22e82d4853dd2fa8bfd0d74`
- `ring.elf`: `c66a33406b4d9a514ac7075d0e541879cb923d2dc40352b24c491865f45226f4`

## Verdict Summary

| Check | Status | Proof |
|---|---|---|
| Preflight, mixed-octal gzip upload & daemon start | **PASS** | `cli_ok=True`, `start_ready=True`, `teardown_requested_clean=True`; `1,026` mixed-octal chunks (`824` ring + `202` daemon) verified by BusyBox v1.13.4 `md5sum` in `211.39 s` (`223.07 s` total `--start`, down from `267.4 s` in Run #1); `daemon_pid=1835`, `PPid=1`, `TracerPid=0`, `w_pid=1837`, `mon_proc=170 == mon_mwf=170`, `uipc_ok=1`, `in_ok=1`, `ring_ok=1`. |
| USB unplug survival & untethered runtime | **PASS** | Survived `216.981 s` (`5,750` ticks) across USB disconnect, shooting, menu toggles, drive switches, 2 full ring cycles, and USB reconnect with `rerr=0`, `ferr=0`, `uipc_dis=0`, `uipc_ferr=0`, `uipc_to=0`, `mref=2`, `VmRSS=4 kB`. |
| Step 1 — Passive OFF (`Release w/o Card` = Disable) + Continuous | **PASS** | `daemon.log` lines 20–32 (`t=14.768..24.328 s`): `bk=0x1, tog=0, gate=0`; full shot at `t=18.400..19.186 s` produced `r_runs=0`, zero `ptrace`, stock camera behavior. |
| Step 2 — Passive ON (`Release w/o Card` = Enable) + Single | **PASS** | `daemon.log` lines 33–48 (`t=26.328..36.478 s`): brief 64 ms tap at `t=27.468..27.532 s` filtered by `deb=100`; in Single (`drive=0x5e, elig=0, gate=0`), 2.24 s half-press + full-press at `t=30.862..33.289 s` produced `r_runs=0`, zero `ptrace`, stock camera behavior. |
| Step 3 — Untethered Pre-Capture SAVE (`N=2, M=1`) | **PASS** | `seq=1`, `pid=1893`, `tok=0x1a2b886d` (`daemon.log` lines 51–98): survived `538 ms` `Insert4100` `sub_en=0` dip (`t=41.141..41.679 s`), armed at `t=42.648 s`, `READY` at `t=42.901 s` (`2,290 ms`), rolled `18.61 s` continuously in RAM (`7` frames, `5` evicted), triggered on physical full-press at `t=61.261 s` (`+17 ms` to `TRIGGER`), committed 3 valid `5472x3648` JPEGs (`status=13`) to drive `'A'`, survived `468 ms` `Pullout4100` `sub_en=0` dip (`t=83.010..83.478 s`), restored SD, exited `rc=0 sig=0 unres=0 fault=0`. |
| Step 4 — Untethered Pre-Capture CANCEL + Repeatability | **PASS** | `seq=2`, `pid=1917`, `tok=0x8e65b8f5` (`daemon.log` lines 99–131): re-armed `2.48 s` after `seq=1`, survived `488 ms` `Insert4100` `sub_en=0` dip (`t=86.760..87.248 s`), armed at `t=87.863 s`, `READY` at `t=88.139 s` (`1,930 ms`), rolled `20.48 s` continuously in RAM (`8` frames, `6` evicted), cancelled on half-press release at `t=108.338 s` (`+60 ms` to `PHASE 1->3`), `SUMMARY a=0 b=8 c=6 d=4` (`0` files committed; zero `PC*B8F5.JPG` or other new `PC*.JPG` on `/Volumes/RX100M7`), survived `93 ms` `Pullout4100` dip (`t=110.377..110.470 s`), restored SD, exited `rc=0 sig=0 unres=0 fault=0`. |
| Clean `--collect` stop, log persistence & RAM cleanup | **PASS** | `cli_ok=True`, `collect_outcome='collected'`, `stopped_cleanly=True`, `w_reap=1`, `r_reap=1`, `r_runs=2`, `r_ok=2`, `r_sav=3`, `r_flt=0`, `r_unres=0`, `trunc=0`, `unknown_lines=[]`, `log_retrieved=True`, `log_persisted=True`, `cleanup='GONE'`, `active_state_cleared=True`, `teardown_requested_clean=True`. |
| SD card JPEG readback integrity (`--check-card-only`) | **PASS** | User-run read-only `--check-card-only --card /Volumes/RX100M7`: `all_ok=true`, `checked=3`, all 3 JPEGs valid (`SOI`/`SOF0 5472x3648`/`EOI`), exact byte-size matches, and `/Volumes/RX100M7/PC*.JPG` listing confirms zero extra `PC*.JPG` from Step 4 cancel (only the 3 Run #2 files from Nov 22 `12:19:43–12:19:54` plus the 3 prior Stage 5 files from Nov 21). |

## Verified Committed Files on SD Card (`/Volumes/RX100M7`)

| Commit time (`t`) | Local mtime | Card filename (`drive=65` / `A:`) | Size (reported == card) | Geometry | SHA-256 | Result |
|---|---|---|---|---|---|---|
| `67,188 ms` | `2026-11-22 12:19:43` | `PC3B886D.JPG` | `10,643,492 B` | `5472x3648` | `abb75a84db7b33cb390c18ed8302bdbff6fc2c9745c8f18fd9d1214e28584474` | **PASS** (`status=13`, valid JPEG) |
| `72,929 ms` | `2026-11-22 12:19:49` | `PC0B886D.JPG` | `10,658,299 B` | `5472x3648` | `63e0443de68f33f1ef010180b9be44e5b386c0d5be7d52a15b12b16468c88be9` | **PASS** (`status=13`, valid JPEG) |
| `78,681 ms` | `2026-11-22 12:19:54` | `PC1B886D.JPG` | `10,682,692 B` | `5472x3648` | `08b16c86733b6c82feb388ade13cd812b7b3c368588ab6c7ad57c62dd0b8dc30` | **PASS** (`status=13`, valid JPEG) |

## Proof That Both Run #1 Live-Hardware Fixes Worked on Camera

1. **`stage6_route_wait` `topology == 2 -> 3` fix:** Both `seq=1` (`t=40.969 -> 41.751 s`) and `seq=2` (`t=86.578 -> 87.314 s`) waited cleanly past Sony's intermediate detached `topology == 2` window and confirmed `topology == 3` (`0x4100` stock RAM) with zero early aborts.
2. **Phase-aware `sub_en` dip tolerance (`stage6_daemon.c` + `stage6_ring.c`):** All four real Sony `Insert4100` / `Pullout4100` `sub_en=0` dips (`538 ms`, `468 ms`, `488 ms`, `93 ms`) occurred cleanly without triggering a single false `DISARM_GATE` or leaving any unresolved trace state (`unres=0`, `fault=0`).
3. **Mixed-octal gzip upload on real Sony BusyBox v1.13.4:** `1,026` chunks (`824` for `67,150 B` gzipped `ring.elf` + `202` for `16,352 B` gzipped `daemon.elf`) passed remote `md5sum` verification on the first try and reduced total `--start` time from `267.4 s` (Run #1) to `223.07 s` (`-44.3 s`).

## Observed Live Performance Notes (Informational, Non-Blocking)

- **Arming latency:** Half-press to `PHASE 0->1` (`PRECAP_ARMED`): `2.25 s` (`seq=1`), `1.86 s` (`seq=2`); to `READY` (2 pre-frames buffered): `2.50 s` (`seq=1`), `2.13 s` (`seq=2`).
- **Rolling cadence during hold:** ~`2.6–3.0 s/frame` (`7` frames in `18.61 s` in `seq=1`; `8` frames in `20.48 s` in `seq=2`) — matches the known carried-forward `s->committed` reservation leak already queued for optimization after Stage 6.
- **Commit time per saved 20MP JPEG:** ~`5.7 s/file` (`t=67.188 s`, `72.929 s`, `78.681 s`, ~`21.4 s` total from full-press to `PRECAP_RESTORE`), matching Stage 5's `hold_hash` + `commit_write` timing.

## Final Hardware Verdict

**STAGE 6 WIP v2.1 (r13) LIVE HARDWARE PASS.** End-to-end untethered RAM Pre-Capture (USB unplug survival, stock `Release w/o Card` toggle, Continuous-only + format gating, zero-`ptrace` passive OFF/Single mode, RAM rolling ring with zero card writes during hold, physical full-press 2-pre + 1-post valid `5472x3648` JPEG save, back-to-back zero-file cancel, and clean `--collect` teardown) is proven on live Sony DSC-RX100M7 firmware `1.00`.
