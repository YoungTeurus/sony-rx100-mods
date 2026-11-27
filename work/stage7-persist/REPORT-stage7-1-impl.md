# Stage 7.1 Implementation Report — DSC-RX100M7 1.00 (r6)

Date: 2026-11-26  
Target: DSC-RX100M7 firmware 1.00 (`29110_03.2021050601`)  
Scope: Complete sealed, offline-verified Stage 7.1 build under `prototype-stage7-persist/` (building on Astra's sealed `PreCapture.mod` + `stage7_common.h` from `work/stage7-persist/REPORT-stage7-1-astra.md`, resolving the sole remaining finding from `work/stage7-persist/REVIEW-stage7-1-sol-r5.md`).

## Verdict (Offline)

**PASS offline (ready for independent Sol r6 review; live hardware behavior remains INCONCLUSIVE until Stage 7.2 RAM test).**

| Area | Verdict | Proof |
|---|---|---|
| M7 1.00 binary layout & ARM disassembly verification | PASS | `m7_100_layout.py` verifies all 4 original binary SHA-256 digests, unique hook sites (`0x696408`, `0x696834`, `0x696df8`), `menu_refresh` (`0x696ec4`), PLT veneers (`0x1617c0`, `0x1680c8`), tab-bar backdrop widget (`menu + 0x97c`), both 7th-tab rect tables (`0x88c814`, `0x88c894`), `viewUnified2.so` RX zero padding tail (`0x9727f0..0x973000`, 2,064 zero bytes, 2,048 B shim slot at `+0x972800..+0x973000`), and `libObj.so` event symbols. |
| Reproducible sealed build (7 artifacts) | PASS | `build_stage7.py` built all 7 artifacts twice in isolated temp directories with identical bytes and sealed `out/build.json` (`187,648` bytes total; `shim.bin` = `1,688` B <= `2,048` B). Six of seven artifacts (`shim.bin`, `core.bin`, `mlv2.req`, `PreCapture.mod`, `stage7_daemon.elf`, `stage7_ring.elf`) are byte-identical to r5; only `mlv2_guard.elf` and `build.json` updated. |
| `stage7_daemon.elf` static syscall census | PASS | Both `build_stage7.py` and Sol's full-CFG census resolved all `113/113` ARM `svc #0` sites (`missing []`, `dynamic {}`, `indirect []`): **zero `ptrace` (26)**, **zero `ioctl` (54)**, **zero `/dev/uipc`**. |
| `mlv2_guard.elf` strict `/proc/<pid>/maps` EOF & column validation | PASS | `scan_maps()` requires `eof && total > 0 && used == 0 && !overlong` and rejects embedded NUL bytes (`\0`), unterminated EOF records, overlong lines `>= 512` B, empty streams, read errors, and 512 KiB truncation; `handle_map_line()` validates all 5 mandatory `/proc/<pid>/maps` columns (`lo-hi rwxp off dev:dev inode`) with 32-bit hex overflow rejection (`parse_hex_req`). Verified by `test_stage7_integration.py::test_5` for global and 4th-open `unterminated_eof`, `malformed_cols`, `embedded_nul`, `addr_overflow`, and `view_off_overflow` (zero pokes, all threads detached, shim untouched). |
| End-to-end menu + `PreCapture.mod` + daemon + ring suites | PASS | `test_stage7_unicorn.py` (5/5), `test_stage7_integration.py` (5/5), and both Stage 6 v1/v2 `verify_seal()` passed. |
| Live camera behavior | INCONCLUSIVE | No camera/USB hardware was accessed in Stage 7.1. Requires Stage 7.2 RAM-only live run after independent Sol r6 review GO. |

## Changes Applied Since r5 (Resolving the Sole Sol r5 Finding)

- **`prototype-stage7-persist/mlv2_guard.c` (`parse_hex_req`, `handle_map_line`, `scan_maps`):**
  - Removed leftover trailing-buffer parsing at EOF in `scan_maps()`, widened line buffer to 512 B, rejected embedded `\0` bytes and overlong lines immediately, and required `eof && total > 0u && used == 0u && !overlong`.
  - Validated all 5 mandatory `/proc/<pid>/maps` fields (`lo-hi`, 4-char perms, `off`, `dev_maj:dev_min`, numeric `inode`) with 32-bit hex overflow checking (`parse_hex_req`) in `handle_map_line()` before recording any VMA bound.
- **`prototype-stage7-persist/test_stage7_integration.py` (`test_5`):**
  - Added regression checks for `unterminated_eof`, `malformed_cols`, `embedded_nul`, `addr_overflow`, and `view_off_overflow`, both globally and on the 4th `/proc/149/maps` open (TID 150 stack VMA lookup).

## Sealed Artifact SHA-256 Digests (`prototype-stage7-persist/out/`)

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `shim.bin` | 1,688 | `28c93d2b7a86196aaadaa7390d8615522ccbb9d9a35dfb35d4cde9f3dd7f62f7` |
| `core.bin` | 13,696 | `064db7fbaf061abf36b5a8983091a879f95a9561e409709d47c49fe52fa1c11a` |
| `mlv2.req` | 1,816 | `4379058a46f55a4664ac4d14306c1bd7c13f1026827b0de1235f7626c3af170c` |
| `mlv2_guard.elf` | 16,800 | `f0851076c6538fce130b1eaf85f8475a4b79ab4479f0c719505523768ec11328` |
| `PreCapture.mod` | 536 | `f2aa3b3d2447593b2e6a156b239d563e783ba7df38fb2c5942f729a0ed1a6963` |
| `stage7_daemon.elf` | 30,132 | `c432dc764fbd207ad22592cc6f5fd3607c35128b1675e65bcf8ea58e9e3aa155` |
| `stage7_ring.elf` | 122,980 | `8b07b26f43a82bb36afba14cfa991e0e90c7819ce150a72244286b8e99acc0e9` |
| `build.json` | — | `2a6059cff31a7d24a03b98cbabfef212e714ec671eee004f81fc6b83d9f70dd3` |
| `precap-build.json` | — | `a2c912ac2ef747e0da6952797d5b560eadada0de6143e045565bd64d60ddc7bc` |

## Reproduction Commands

```sh
.venv-analysis/bin/python3 -B prototype-stage7-persist/m7_100_layout.py
.venv-analysis/bin/python3 -B prototype-stage7-persist/build_stage7.py
.venv-analysis/bin/python3 -B prototype-stage7-persist/test_stage7_unicorn.py -v
.venv-analysis/bin/python3 -B prototype-stage7-persist/test_stage7_integration.py -v
```
