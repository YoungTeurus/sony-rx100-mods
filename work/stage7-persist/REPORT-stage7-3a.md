# Stage 7.3 Phase A Implementation Report (r2 — Post-Sol Review Fixes)

**Target:** Sony DSC-RX100M7 firmware `1.00` (build `29110_03.2021050601`).
**Scope:** Stage 7.3 Phase A — 100% RAM-only SD-boot package, remembered-state menu persistence, bounded menu/boot logging, and zero-flash-write Phase A telemetry/trial CLI (`--prep-card`, `--boot-probe`, `--ram-start`, `--ram-collect`).

## Verdicts

- **Offline build & seals:** **PASS** — Stage 7.1 (`out/build.json`, `193,648 B`, `shim.bin` `1,776 B` / `2,048 B` cave, `stage7_ring.elf` untouched `8b07b26f...`) and Stage 7.3 Phase A (`out-sd/build-sd.json`, `mlv2_card_read.elf` `13,448 B`, `mlv2_sd_boot.sh` `11,826 B`, `card.ustar` `204,800 B`) build reproducibly and pass `verify_seal()`.
- **Offline test suites:** **PASS (41/41)** — `test_stage7_unicorn.py` (`5/5`), `test_stage7_integration.py` (`6/6`), `test_stage7_sd.py` (`20/20`), `test_stage7_ram_runner.py` (`10/10`).
- **Live camera / physical 128 GB SD card / warm-boot behavior:** **INCONCLUSIVE** — No camera, USB interface, or mounted SD card was touched. Submitted for independent Codex Sol r2 review (Part A & Part B).

## Disposition of All 13 Sol r1 Findings

### Part A ([REVIEW-stage7-3a-sol-menu.md](REVIEW-stage7-3a-sol-menu.md))
1. **BLOCKER (malformed gate with embedded NUL):** Fixed in `core.c:persist_precap_if_authorized()` — reads full 64-byte buffer and enforces exact byte length (`25`/`41`) + `ml_memcmp` (zero `ml_strcmp`).
2. **MAJOR (FIFO read acceptance & blocking open on OFF count edit):** Added `s7_fd_is_regular()` (`SYS_FSTAT64=197`, `S_IFREG`) in `stage7_common.h:s7_parse_precap_record()` and `core.c:persist_precap_if_authorized()`, switched `mlv2_sys.h:ml_path_absent()` to `O_RDONLY|O_NONBLOCK|O_NOFOLLOW`, added `197` to `build_stage7.py`'s daemon syscall allowlist, and passed `gated` out-param from `persist_precap_if_authorized()` instead of re-opening `persist-cfg`.
3. **MAJOR (same-core OFF reactivation stale count):** Added `need_rehydrate` at end of `Ctx` (set in `sd_disabled()`, consumed and cleared in `rescan()`), refreshing both `ON/N` and `OFF/N` on reactivation while preserving ordinary in-menu OFF edits.
4. **MAJOR (transient uncommitted runtime exposure & dual-failure OFF):** `core_before_enter()` now persists durable state **before** updating daemon-visible `/tmp_network/mlv2/precap.cfg` on both ON enable and ON count edits; on ON→OFF, verifies `s7_pre_frames() == 0u` after `toggle(m)` and restores `m->enabled=1, m->off_called=0` showing `"ON!"` if both runtime rename and unlink failed.
5. **MAJOR (16 KiB log cap interleaving):** Added `volatile uint32_t log_lock` at end of `ShimState` (`mlv2.h`), moved `core_load` log before `ml_atomic_store_rel(&s->core_base, base)` (`shim.c`), and serialized `lseek(SEEK_END)+write` in `ml_log_to_locked()` via non-deadlocking bounded `ldrex`/`strex` CAS shared between `shim.bin` and `core.bin`.
6. **MINOR (`OFF!` disappearing on refresh):** Added `persist_off_dirty` at end of `Ctx`, reflected in `state_text()` (`"OFF!"`) and `state_text_top()` (`"OFF! >"`) until cleared by a successful edit or reactivation.

### Part B ([REVIEW-stage7-3a-sol-sd.md](REVIEW-stage7-3a-sol-sd.md))
1. **BLOCKER (volatile `tmpfs` confinement & symlink safety):**
   - `mlv2_card_read.c`: `--extract` now verifies `stage_path_safe()` (strict `/tmp_network/...`, no `..`, `O_DIRECTORY|O_NOFOLLOW` + `fstat64` `S_IFDIR`), `space_at()` `f_type == 0x01021994` (`TMPFS_MAGIC`), and `exact_file()` `S_IFREG`.
   - `mlv2_sd_boot.sh`: confines `stage`/`mods`/`daemon_dir` strictly inside `$ram_root/`, requires unique `tmpfs rw` mount with zero nested mounts under `$ram_root/`, and checks `safe_leaf_ok()` (non-symlink, non-dir) before every shell redirection.
   - `scripts/m7_stage7_sd_probe.py`: `--boot-probe` now runs full shared `identity.preflight_commands()` + `checked_preflight()` (incl. `HISTFILE=/dev/null`, `ulimit -c 0`, `umask 077`, zero nested mounts) and checks leaf non-existence; `--ram-collect` uses `_safe_touch_ram_marker()` checking both parent dir and leaf before `: >`.
2. **BLOCKER (HMAC key retained in receipts):** Added `_send_secret_command()` scrubbing `receipt["commands"]`, `receipt["steps"]`, and `camera.dev.packet_log` in `finally:` for every `sd.key` upload step (including on error/timeout), verified by synthetic-key non-leakage tests in `test_stage7_sd.py`.
3. **BLOCKER (`--ram-collect` uninstall while daemon alive):** Hard-gated `mlv2_guard.elf uninstall` on `daemon_stopped == True` (`observe_live_s7_processes()["certain_clear"]`), returning `collect_outcome="daemon_still_running"` and preserving custody if daemon/ring is still alive.
4. **MAJOR (lost USB ACK recovery & timeout alignment):** Persists durable `status="stock_verified_pending_cleanup"` checkpoint to `active_path` before `rm -rf`; recovers `pending_boot`/`boot_failed_pending_collect` with retained pre-install refusal `sd-boot.log` once `sd-managed` and `.boot.lock` are confirmed absent; passes `MLV2_WAIT_IM=5 MLV2_CARD_TRIES=3` (`<= 26 s < 40 s` host timeout).
5. **MAJOR (`--prep-card` symlink safety):** Rejects symlink `sd_root` and symlink/dir `MLV2.TAR`; writes to random exclusive temp `.MLV2.TAR.<hex>.tmp` with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` (`0600`), `fsync`, re-checks destination before `os.replace()`, and verifies regular-file readback via `O_RDONLY|O_NOFOLLOW` + `S_ISREG`.
6. **MAJOR (daemon readiness validation):** `mlv2_sd_boot.sh` validates positive numeric PID, `readlink /proc/$dpid/exe == $daemon_dir/daemon.elf`, and non-zombie `stat` (`) [RSDT] `); `m7_stage7_sd_probe.py` independently verifies `readlink`, `parse_any_proc_stat`, and `parse_daemon_log` `BOOT` matching `self_pid`, `im_pid`, `im_st`.
7. **MINOR (`.boot.lock` lifetime & card `closefd` ordering):** `mlv2_sd_boot.sh` holds `.boot.lock` until the end of `cleanup()`; `mlv2_card_read.c` closes card `fd` before `rename(card.tar.tmp, card.tar)` so `card.tar` is never published on non-zero exit.

## Verification Commands & Results

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-analysis/bin/python3 -B prototype-stage7-persist/build_precap_mod.py
PYTHONDONTWRITEBYTECODE=1 .venv-analysis/bin/python3 -B prototype-stage7-persist/build_stage7.py
PYTHONDONTWRITEBYTECODE=1 .venv-analysis/bin/python3 -B prototype-stage7-persist/build_stage7_sd.py
PYTHONDONTWRITEBYTECODE=1 .venv-analysis/bin/python3 -B prototype-stage7-persist/test_stage7_unicorn.py -v
PYTHONDONTWRITEBYTECODE=1 .venv-analysis/bin/python3 -B prototype-stage7-persist/test_stage7_integration.py -v
PYTHONDONTWRITEBYTECODE=1 .venv-analysis/bin/python3 -B prototype-stage7-persist/test_stage7_sd.py -v
PYTHONDONTWRITEBYTECODE=1 .venv-analysis/bin/python3 -B prototype-stage7-persist/test_stage7_ram_runner.py -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=prototype-stage7-persist .venv-analysis/bin/python3 -B -c \
  'import build_stage7, build_stage7_sd; m1 = build_stage7.verify_seal(); m2 = build_stage7_sd.verify_seal(); print("SEALS PASS:", m1["total_artifact_bytes"], m2["artifacts"]["card_ustar"]["bytes"])'
```

| Suite / Check | Result | Time / Proof |
|---|---|---|
| `build_stage7.verify_seal()` | **PASS** | `193,648 B` (`shim.bin` `1,776 B`, `core.bin` `19,296 B`, `stage7_ring.elf` untouched `122,980 B`) |
| `build_stage7_sd.verify_seal()` | **PASS** | `reader=13,448 B`, `boot_sh=11,826 B`, `card.ustar=204,800 B` |
| `test_stage7_unicorn.py` | **PASS (5/5)** | `0.111s` (incl. `fstat64` `S_IFIFO` refusal) |
| `test_stage7_integration.py` | **PASS (6/6)** | `10.337s` (incl. all 6 Sol Part A regressions) |
| `test_stage7_sd.py` | **PASS (20/20)** | `32.330s` (incl. all 7 Sol Part B regressions) |
| `test_stage7_ram_runner.py` | **PASS (10/10)** | `97.594s` |
| Live hardware (`--prep-card`, `--boot-probe`, `--ram-start`, `--ram-collect`) | **INCONCLUSIVE** | Untested on physical camera/SD; awaiting Sol r2 **GO** |

## File SHA-256 Manifest (r2)

| File | SHA-256 |
|---|---|
| `prototype-stage7-persist/mlv2.h` | `7127cf4fc5481d26de98c45dfb4cf6bf334f1bc145a05f71cf1f12d990ae789d` |
| `prototype-stage7-persist/mlv2_sys.h` | `f9085b0c5ec67dcf041964bee50df83632680bb9171a599fa97b262529001a28` |
| `prototype-stage7-persist/stage7_common.h` | `ca6562c9713ea4a65ec889d2adc9705184dda4f19720463f3dcb01672062f816` |
| `prototype-stage7-persist/precap_mod.c` | `0f68774cd9824d62d75395e9d2f9642e65aa50de6b942826118289f4c2b53472` |
| `prototype-stage7-persist/shim.c` | `51fe261b2105a2d21fdc3c25aca1ed69a1979a7543a095eb805fb000f39a09e5` |
| `prototype-stage7-persist/core.c` | `bcacdbcd6b6dd0e0cbbb533c05d9d4b37c1185071fdb0313c76ec38276fec498` |
| `prototype-stage7-persist/build_stage7.py` | `10079bd5fc627788ca662501b84e55accc7c12308d379a61a44903266c5ce8e6` |
| `prototype-stage7-persist/test_stage7_unicorn.py` | `d8318979d5db7d6b76f7d959091d936b607871b8c62f927f564385e85d5ebcde` |
| `prototype-stage7-persist/test_stage7_integration.py` | `4b127cbb1f0ec0439736c5252c05b914729e165fa2684e1cc70c457fa1f938e2` |
| `prototype-stage7-persist/test_stage7_ram_runner.py` | `50def14923da7179ea53ca20caa62d1b2e92c6db2bae3c31ab29c239486c091e` |
| `prototype-stage7-persist/out/build.json` | `ba739ebb791f3ddb7d291e6ecbf9e12ac26efa66075d2ea940a38889f30a77b8` |
| `prototype-stage7-persist/out/precap-build.json` | `ade89192759aa0db367a8e656e6462d28267b83dae6c5c45302f34babda8e1df` |
| `prototype-stage7-persist/out/shim.bin` | `b3977fc6e09468c7a44ae2cce18b74b31f5142e64843ab34c0adfba864ee74fa` |
| `prototype-stage7-persist/out/core.bin` | `57f1edbe43395b8ba455a01a28a6a5e1127f8343ba0f4067e42edc72f0199cee` |
| `prototype-stage7-persist/out/stage7_ring.elf` | `8b07b26f43a82bb36afba14cfa991e0e90c7819ce150a72244286b8e99acc0e9` |
| `prototype-stage7-persist/mlv2_card_read.c` | `516df0585769ffd965a5aaa57b8e0c0091c11a9bcaac58f9ce17e43d71a79006` |
| `prototype-stage7-persist/mlv2_sd_boot.sh` | `b79c8cc8af9658c26ea3e3cfb2bcaa0db26b34b2cc33c7a01e84eb29ab8327fb` |
| `prototype-stage7-persist/build_stage7_sd.py` | `c1e1f2a86b041e7c666e9bc0e7a2a052d890689c385e6d7d080082edab3ae970` |
| `prototype-stage7-persist/test_stage7_sd.py` | `4838bb055d460f159e4cdf771e040778d0caccf01a17bcec803090479bf49ac6` |
| `prototype-stage7-persist/out-sd/mlv2_card_read.elf` | `3876cbafe3762f11d40b637f59b4936dae8e21dd48fd8ae6bc65803c7ceded50` |
| `prototype-stage7-persist/out-sd/card.ustar` | `e315961843ea0ea1f596332ffda0a881a76b6cdacc8fca3374c6302d7468e553` |
| `prototype-stage7-persist/out-sd/build-sd.json` | `dbfe3a62acb0f59919d6657d3f70b07698f83302121c4057dac8305696b990a9` |
| `scripts/m7_stage7_sd_probe.py` | `ffe354b7539d43d9b43c1683fa3962ffe1e52291b56d058b624ce7fa4bdec66d` |
| `.gitignore` | `6f7a44b8f3dcbd37dcaf89e61e40205516d8ebf41a7a52fb27fe2bbfcba263fb` |

---

## Stage 7.3 Phase A — r3 Update (Post-Sol r2 Fixes)

### Verdicts (r3)

- **Offline build & seals:** **PASS** — Stage 7.1 (`out/build.json`, `192,068 B`, `shim.bin` `1,864 B` / `2,048 B` cave, `core.bin` `17,528 B`, `PreCapture.mod` `564 B`, `stage7_ring.elf` untouched `122,980 B` `8b07b26f...`) and Stage 7.3 Phase A (`out-sd/build-sd.json`, `mlv2_card_read.elf` `13,768 B`, `mlv2_sd_boot.sh` `15,656 B`, `card.ustar` `204,800 B`) build reproducibly and pass `verify_seal()`.
- **Offline test suites:** **PASS (43/43)** — `test_stage7_unicorn.py` (`6/6`), `test_stage7_integration.py` (`6/6`), `test_stage7_ram_runner.py` (`10/10`), `test_stage7_sd.py` (`21/21`).
- **Live hardware:** **INCONCLUSIVE** — No camera, USB interface, or mounted SD card was touched. Submitted for independent Codex Sol r3 review (Part A & Part B).

### Disposition of All Sol r2 Findings

#### Part A ([REVIEW-stage7-3a-sol-menu-r2.md](REVIEW-stage7-3a-sol-menu-r2.md))
1. **Finding 4 residual (false `OFF!` on readback `fstat64 -EIO`):** Added `s7_parse_precap_record_status()` (tri-state: `1` valid regular record, `0` `-ENOENT`, `-1` error/non-regular/malformed) and `s7_confirm_runtime_disarmed()` in `stage7_common.h`. `core.c` now requires `s7_confirm_runtime_disarmed() == 1` before publishing OFF or attempting durable OFF; on failed disarm or readback error, keeps `m->enabled = 1, m->off_called = 0, c->persist_dirty = 1` (`"ON!"` / `"ON! >"` both immediately and on refresh) with zero durable I/O. Generalized `persist_off_dirty` to `persist_dirty`.
2. **Additional Finding #1 (MAJOR — ON count edit runtime write failure):**
   - `precap_mod.c`: only falls back to `unlink(PRECAP_CFG)` when `!enabled`; preserves prior `ON/<prev>` runtime record on `reason == 1`/`2` write failures.
   - `core.c`: after `sub_cfg_off` on ON count edit, verifies exact `(1, fr)` via `s7_parse_precap_record_status()`. If runtime preserved `(1, prev_fr)`, reverts UI/BSS and durable back to `(1, prev_fr)` (or flags `persist_dirty = 1` → `"ON!"` if durable revert fails); if runtime disarmed, syncs UI/durable to OFF; if readback failed, reverts count and flags `"ON!"` immediately and on refresh.
3. **Additional Finding #2 (MAJOR — FIFO `mod_loader.log` blocking under `log_lock`):** Added `ml_fd_is_regular(fd)` (`SYS_FSTAT64=197` `S_IFREG`) in `mlv2_sys.h`; `ml_log_to_locked()` now opens with `flags | ML_O_NONBLOCK | ML_O_NOFOLLOW` and requires `ml_fd_is_regular(fd)` before seek/write while always releasing `log_lock`. Hardened `sd_acknowledge_stop`, `shim_try_core`, `parse_mod`, `load_code`, `process_reload`, and `scan_mods_in` with `ML_O_NOFOLLOW` (+ `ML_O_NONBLOCK` and `ml_fd_is_regular` where reading regular files).

#### Part B ([REVIEW-stage7-3a-sol-sd-r2.md](REVIEW-stage7-3a-sol-sd-r2.md))
1. **Finding 1 (BLOCKER — Full-path volatile tmpfs confinement):**
   - `mlv2_card_read.c`: replaced pathname-based staging with component-by-component `openat(..., O_RDONLY|O_DIRECTORY|O_NOFOLLOW)` anchored from `"/"`, `fstatfs64` (slot `267`, `sys_fstatfs64_wrapper` verified against M7 `vmlinux.bin`) directly on pinned `stage_fd`, and `*at` operations (`openat=322`, `unlinkat=328`, `renameat=329`) relative to `stage_fd` (eliminating pathname-based `unlink=10` and `rename=38`).
   - `mlv2_sd_boot.sh`: `check_ram_child()` now walks and rejects symlinks at EVERY component under `$ram_root`; `mount_ok()` parses `/proc/mounts` field-by-field in pure POSIX `sh`, requiring unique `tmpfs rw` (non-`noexec`) row (`m_tot == 1 && m_ok == 1 && m_nested == 0`); `safe_leaf_ok()` rejects symlinks, dirs, FIFOs, devices, and sockets; TAR extraction requires `fresh_leaf_ok()` before `tar -xf` and `reg_file_ok()` on all 6 members before `chmod`.
   - `scripts/m7_stage7_sd_probe.py`: `_safe_touch_ram_marker()` and `upload_phase_a_file()` check `/tmp_network` non-symlink dir, parent non-symlink dir, and non-symlink absent/regular leaf.
2. **Finding 4 & N2 (MAJOR — `MLV2_GUARD_NOT_STOCK` custody & launch deadline):** Removed `MLV2_GUARD_NOT_STOCK` and `MLV2_GUARD_CHECK_FAIL` from `PRE_INSTALL_REFUSAL_LINES` so failed stock checks never clear recovery custody without fresh stock verification or power-cycle. Bounded `--ram-start` worker waits to `MLV2_WAIT_MOUNT=1 MLV2_WAIT_IM=2 MLV2_CARD_TRIES=0 MLV2_WAIT_DAEMON=5` (`<= 28 s` worst-case) under a `60 s` host timeout.
3. **Finding 6 (MAJOR — Matching `BOOT` record in `mlv2_sd_boot.sh`):** Worker captures `im_st` (field 22 of `/proc/$im_pid/stat`) and requires exact unique `BOOT self_pid=$dpid im_pid=$im_pid im_st=$im_st ` in regular non-symlink `$daemon_dir/daemon.log` before emitting `MLV2_SD_READY`.
4. **Finding 7 (MINOR — `.boot.lock` lifetime):** When `owns_stage=1`, `mlv2_sd_boot.sh` deletes shared `$log_file` BEFORE releasing `.boot.lock`, then calls `rmdir "$stage"` after lock release. (`mlv2_card_read.elf` retains hard `SIG_DFL` `SIGALRM` termination; worker `cleanup()` and next extraction clear any interrupted `card.tar.tmp`.)
5. **Finding N1 (BLOCKER — Boot/collect race ownership):** `do_ram_collect()` now gates stop, stock verification, `sd-disabled`, uninstall, and deletion on (a) `observe_boot_worker_clear()` confirming zero live reader/guard/stage-anchored workers and (b) atomic exclusive acquisition of `/tmp_network/mlv2/.boot.lock` (refusing immediately with zero writes if held by the boot worker, and releasing in `finally:` on incomplete collect).

### File SHA-256 Manifest (r3)

| File | SHA-256 |
|---|---|
| `prototype-stage7-persist/mlv2.h` | `7127cf4fc5481d26de98c45dfb4cf6bf334f1bc145a05f71cf1f12d990ae789d` |
| `prototype-stage7-persist/mlv2_sys.h` | `979cdbbcd0c7d14017a41bcc6534a3db057a8e8305f436cacdc038f776251ddf` |
| `prototype-stage7-persist/stage7_common.h` | `935aae3f8972e64d2a188cc66c4497db4c0779d0cfe57580b08de616875afdba` |
| `prototype-stage7-persist/precap_mod.c` | `8b8270e200f4ef2270fc9e6f1fd2cd002a936f042f0f9c5b9bae3b807024525e` |
| `prototype-stage7-persist/shim.c` | `ec9ac34f5447c6389f1c0839f9b43b081914e8d0fcacbcd46a58aecc0bb45fef` |
| `prototype-stage7-persist/core.c` | `0d618d961dc76f70e5bc136174a27a3f277b03b1fbb59ee097950f74e52942b7` |
| `prototype-stage7-persist/build_stage7.py` | `10079bd5fc627788ca662501b84e55accc7c12308d379a61a44903266c5ce8e6` |
| `prototype-stage7-persist/test_stage7_unicorn.py` | `a8a15755b5a7312bf816b5660448b93aafc9a07b278baa29e556ac6fb928f7d7` |
| `prototype-stage7-persist/test_stage7_integration.py` | `3176584df4f0f10fe01540015561a740c3186f28b61fbc53c09b93f65aca3a8c` |
| `prototype-stage7-persist/test_stage7_ram_runner.py` | `50def14923da7179ea53ca20caa62d1b2e92c6db2bae3c31ab29c239486c091e` |
| `prototype-stage7-persist/out/PreCapture.mod` | `208b5aa074017f078816a2a173471f38d1af55bfa90672c1eb757a91fa6d4356` |
| `prototype-stage7-persist/out/shim.bin` | `2d7e470d94819f29c460bbcc9a8a2022f09f2f66db314a02fa2950879fad031b` |
| `prototype-stage7-persist/out/core.bin` | `13900c0454bc84682aa1986b167add06434e76d2bb622e29b56d1d5e8146b360` |
| `prototype-stage7-persist/out/mlv2.req` | `379a359ec218b97caa9d37ab6fed7b25164312fb412d444d61787ddb7f571e12` |
| `prototype-stage7-persist/out/mlv2_guard.elf` | `f1c634067075345d2386127c77cbfebca5bc53fdf6dcd623feaa43fff41cf61b` |
| `prototype-stage7-persist/out/stage7_daemon.elf` | `95d707c3fdfae5075bf4eb77ec7b1bb5355b3ff9f377ded4c06bfb8abf695201` |
| `prototype-stage7-persist/out/stage7_ring.elf` | `8b07b26f43a82bb36afba14cfa991e0e90c7819ce150a72244286b8e99acc0e9` |
| `prototype-stage7-persist/out/precap-build.json` | `a48e836057f4c18d975ff187a6a9f95744cdecf93f8b8677b8982fb8eccf9901` |
| `prototype-stage7-persist/out/build.json` | `73005c9b2579d9065e99d544b7f2a96574d56997d99e008d40fd32425fa04ed9` |
| `prototype-stage7-persist/mlv2_card_read.c` | `e77a7ecce12a317a2f58102bf424dfd6d7f3c477344aa020ed43fe224c2c2b12` |
| `prototype-stage7-persist/mlv2_sd_boot.sh` | `552181b6f376c47477cd0afbd3a13179f43d243f149101df6acce92f629cbfb7` |
| `prototype-stage7-persist/build_stage7_sd.py` | `53890c371a96551705d486eb3097fe9a360e5d534c5122348fc1a1ca0caa09d1` |
| `prototype-stage7-persist/test_stage7_sd.py` | `84faa296f0efa87befe37b040cb03b6b4b65d8fb892b053eb2f1c2ae81c13742` |
| `prototype-stage7-persist/out-sd/mlv2_card_read.elf` | `4aed6c1c511123d4d3abc30d3808ef681923507dea2c326412de739502082757` |
| `prototype-stage7-persist/out-sd/mlv2_sd_boot.sh` | `552181b6f376c47477cd0afbd3a13179f43d243f149101df6acce92f629cbfb7` |
| `prototype-stage7-persist/out-sd/card.ustar` | `37916f44656adf147c4b5a049d63c042268bf342fc02be490054182664ab4546` |
| `prototype-stage7-persist/out-sd/build-sd.json` | `b3509631355e1e3c149162c540f08fa69e2d6ef5bf598016f081904b0e845bca` |
| `scripts/m7_stage7_sd_probe.py` | `a951294f230b6ade359b7cea1bd6e690ba5bd06d89806b9a9fa67808372a1dde` |
| `.gitignore` | `6f7a44b8f3dcbd37dcaf89e61e40205516d8ebf41a7a52fb27fe2bbfcba263fb` |

---

## Stage 7.3 Phase A — r4 Update (Post-Sol r3 Final Fixes)

### Verdicts (r4)

- **Offline build & seals:** **PASS** — Stage 7.1 (`out/build.json`, `192,264 B`, `core.bin` `17,724 B`; `shim.bin` `1,864 B`, `PreCapture.mod` `564 B`, `mlv2_guard.elf` `16,800 B`, `stage7_daemon.elf` `30,340 B`, `stage7_ring.elf` `122,980 B` all byte-identical to r3) and Stage 7.3 Phase A (`out-sd/build-sd.json`, `mlv2_card_read.elf` `13,768 B` byte-identical to r3, `mlv2_sd_boot.sh` `16,641 B`, `card.ustar` `204,800 B`) pass `verify_seal()`.
- **Offline test suites:** **PASS (43/43)** — `test_stage7_unicorn.py` (`6/6`), `test_stage7_integration.py` (`6/6`), `test_stage7_ram_runner.py` (`10/10`), `test_stage7_sd.py` (`21/21`).
- **Live hardware:** **INCONCLUSIVE** — Zero camera/USB/SD access; submitted for independent Codex Sol r4 review (Part A & Part B).

### Disposition of All Sol r3 Findings

#### Part A ([REVIEW-stage7-3a-sol-menu-r3.md](REVIEW-stage7-3a-sol-menu-r3.md))
1. **BLOCKING (compensation with vanished or retargeted gate + unexpected disarm warning):**
   - `core.c:persist_precap_if_authorized()` now accepts `required_dest` (`0`=forward/optional, `1`=`/setting/mlv2_precap.cfg`, `2`=`/tmp_network/mlv2/sim-setting-precap.cfg`) and returns exact `out_dest`. On compensation (`required_dest != 0`), `-ENOENT` or a switched gate destination returns `0` with zero writes to any alternate destination, keeping `c->persist_dirty = 1u` (`"ON!"` / `"OFF!"` immediately and across refreshes).
   - On unexpected runtime disarm during an ON count edit, `core.c` always sets `c->persist_dirty = 1u` (`"OFF!"` / `"OFF! >"`) even when durable reconciliation succeeds.

#### Part B ([REVIEW-stage7-3a-sol-sd-r3.md](REVIEW-stage7-3a-sol-sd-r3.md))
1. **N1 (BLOCKER — Absent-stage transition ownership & lock held through final mutation):**
   - `scripts/m7_stage7_sd_probe.py:do_ram_collect()` now uses a pure read-only fast path for `stock_verified_pending_cleanup` when all 4 RAM paths are already `GONE` and processes are clear (zero camera writes).
   - For every mutating path (including `pending_boot` or dirty `stock_verified_pending_cleanup` when `/tmp_network/mlv2` starts `ABSENT`), collector atomically ensures `/tmp_network/mlv2` exists and acquires `/tmp_network/mlv2/.boot.lock` (`owner=collect`) **before** any stop/disable/guard/cleanup command (refusing immediately with zero writes if `HELD`).
   - During final cleanup, `.boot.lock` remains held across deleting `stage_dir`, `daemon_dir`, `/tmp_network/mods`, and all sibling entries inside `/tmp_network/mlv2`, and is removed ONLY as the final operation (`rm -f .boot.lock/owner && rmdir .boot.lock && rmdir /tmp_network/mlv2`).
2. **N2 (MAJOR — Unreadable / empty boot log distinction):**
   - Added `_inspect_ram_leaf()` + `grab_with_rc()` in `scripts/m7_stage7_sd_probe.py`. `pre_boot_upload_aborted_clean` now requires `status == "pending_boot"`, confirmed `sd_boot_log_state == "FILE_ABSENT"`, absent `sd-managed`, and absent `daemon_dir`/`/tmp_network/mods`. `pre_boot_refusal_recovered` requires `sd_boot_log_state == "FILE_OK"`, `sd_boot_log_rc == 0`, non-empty lines, no install marker, and a recognized pre-install refusal line. Unreadable, missing (`boot_failed_pending_collect`), or empty logs fail closed as `pre_boot_stock_unverified` preserving custody.
3. **Finding 6 (MAJOR — Unambiguous `BOOT` validation & unterminated final line):**
   - `mlv2_sd_boot.sh` now checks `line_nl` (`while :; do ... if ! IFS= read -r bline; then line_nl=0; [ -n "$bline" ] || break; fi`) so any unterminated `BOOT` line (1st or 2nd) is counted and rejected, and counts exact token occurrences so `self_pid=`, `im_pid=`, and `im_st=` must each appear **exactly once** with matching values.
   - `scripts/m7_stage7_sd_probe.py:do_ram_start()` additionally requires zero `BOOT` entries in `dlog_parsed["duplicate_keys"]`.

### File SHA-256 Manifest (r4)

| File | SHA-256 |
|---|---|
| `prototype-stage7-persist/mlv2.h` | `7127cf4fc5481d26de98c45dfb4cf6bf334f1bc145a05f71cf1f12d990ae789d` |
| `prototype-stage7-persist/mlv2_sys.h` | `979cdbbcd0c7d14017a41bcc6534a3db057a8e8305f436cacdc038f776251ddf` |
| `prototype-stage7-persist/stage7_common.h` | `935aae3f8972e64d2a188cc66c4497db4c0779d0cfe57580b08de616875afdba` |
| `prototype-stage7-persist/precap_mod.c` | `8b8270e200f4ef2270fc9e6f1fd2cd002a936f042f0f9c5b9bae3b807024525e` |
| `prototype-stage7-persist/shim.c` | `ec9ac34f5447c6389f1c0839f9b43b081914e8d0fcacbcd46a58aecc0bb45fef` |
| `prototype-stage7-persist/core.c` | `e1dc940c8627d2b224c6dd51489bb20c844ccffdf2b5ce785bc5cb71553103b6` |
| `prototype-stage7-persist/build_stage7.py` | `10079bd5fc627788ca662501b84e55accc7c12308d379a61a44903266c5ce8e6` |
| `prototype-stage7-persist/test_stage7_unicorn.py` | `a8a15755b5a7312bf816b5660448b93aafc9a07b278baa29e556ac6fb928f7d7` |
| `prototype-stage7-persist/test_stage7_integration.py` | `1f2f8cb46692f6b0013e57c7645425252f35a93e1dfeb7d0338bfb8626f63c34` |
| `prototype-stage7-persist/test_stage7_ram_runner.py` | `50def14923da7179ea53ca20caa62d1b2e92c6db2bae3c31ab29c239486c091e` |
| `prototype-stage7-persist/out/PreCapture.mod` | `208b5aa074017f078816a2a173471f38d1af55bfa90672c1eb757a91fa6d4356` |
| `prototype-stage7-persist/out/shim.bin` | `2d7e470d94819f29c460bbcc9a8a2022f09f2f66db314a02fa2950879fad031b` |
| `prototype-stage7-persist/out/core.bin` | `7734bb136791c37a933219a6cc434b70246f789b301e5fc5b465c2dc9e092080` |
| `prototype-stage7-persist/out/mlv2.req` | `379a359ec218b97caa9d37ab6fed7b25164312fb412d444d61787ddb7f571e12` |
| `prototype-stage7-persist/out/mlv2_guard.elf` | `f1c634067075345d2386127c77cbfebca5bc53fdf6dcd623feaa43fff41cf61b` |
| `prototype-stage7-persist/out/stage7_daemon.elf` | `95d707c3fdfae5075bf4eb77ec7b1bb5355b3ff9f377ded4c06bfb8abf695201` |
| `prototype-stage7-persist/out/stage7_ring.elf` | `8b07b26f43a82bb36afba14cfa991e0e90c7819ce150a72244286b8e99acc0e9` |
| `prototype-stage7-persist/out/precap-build.json` | `a48e836057f4c18d975ff187a6a9f95744cdecf93f8b8677b8982fb8eccf9901` |
| `prototype-stage7-persist/out/build.json` | `cc995d771cc3192418c8923173db3211489d5f16fc9cf803a16092e6fe2f4f97` |
| `prototype-stage7-persist/mlv2_card_read.c` | `e77a7ecce12a317a2f58102bf424dfd6d7f3c477344aa020ed43fe224c2c2b12` |
| `prototype-stage7-persist/mlv2_sd_boot.sh` | `f4dc853cefd62694f7ef6336c7133c0450b6d6cba4694d0566e170c9112d7d70` |
| `prototype-stage7-persist/build_stage7_sd.py` | `53890c371a96551705d486eb3097fe9a360e5d534c5122348fc1a1ca0caa09d1` |
| `prototype-stage7-persist/test_stage7_sd.py` | `793521e911de49e0767e4da2c44836ca4f7f3093f3ceb39ab63f14bb0895160c` |
| `prototype-stage7-persist/out-sd/mlv2_card_read.elf` | `4aed6c1c511123d4d3abc30d3808ef681923507dea2c326412de739502082757` |
| `prototype-stage7-persist/out-sd/mlv2_sd_boot.sh` | `f4dc853cefd62694f7ef6336c7133c0450b6d6cba4694d0566e170c9112d7d70` |
| `prototype-stage7-persist/out-sd/card.ustar` | `4e2c4edcc150e4348b1b4d8ea11ba96686828fbfb6a56a9966a1dcfff75aee06` |
| `prototype-stage7-persist/out-sd/build-sd.json` | `c1e183849e26cd959575ff88aa57534f37fa0acdfa4a16b3798e16c9a28c27f0` |
| `scripts/m7_stage7_sd_probe.py` | `9d92dae7486698d472ab3372e019338fa24823c44feab5a4e7265267e7026502` |
| `.gitignore` | `6f7a44b8f3dcbd37dcaf89e61e40205516d8ebf41a7a52fb27fe2bbfcba263fb` |


---

## Stage 7.3 Phase A — r5 Update (Post-Sol r4 Final Fixes)

### Verdicts (r5)

- **Offline build & seals:** **PASS** — Stage 7.1 (`out/build.json`, `192,724 B`, `core.bin` `18,184 B`; `shim.bin` `1,864 B`, `PreCapture.mod` `564 B`, `mlv2.req` `1,992 B`, `mlv2_guard.elf` `16,800 B`, `stage7_daemon.elf` `30,340 B`, `stage7_ring.elf` `122,980 B` all byte-identical to r4) and Stage 7.3 Phase A (`out-sd/build-sd.json`, `mlv2_card_read.elf` `13,768 B` and `mlv2_sd_boot.sh` `16,641 B` byte-identical to r4, `card.ustar` `204,800 B`) pass `verify_seal()`.
- **Offline test suites:** **PASS (49/49)** — `test_stage7_unicorn.py` (`6/6`), `test_stage7_integration.py` (`6/6`), `test_stage7_ram_runner.py` (`10/10`), `test_stage7_sd.py` (`27/27`).
- **Live hardware:** **INCONCLUSIVE** — Zero camera/USB/SD access; submitted for independent Codex Sol r5 review (Part A & Part B).

### Disposition of All Sol r4 Findings

#### Part A ([REVIEW-stage7-3a-sol-menu-r4.md](REVIEW-stage7-3a-sol-menu-r4.md))
1. **BLOCKING (subsequent explicit OFF or OFF count edit clearing dirty warning while original durable destination still holds ON):**
   - Repurposed `Ctx.persist_dirty` in `prototype-stage7-persist/core.c` into a per-destination bitmask (`PERSIST_DIRTY_SETTING=1`, `PERSIST_DIRTY_SIM=2`, `PERSIST_DIRTY_RUNTIME=4`, `PERSIST_DIRTY_GATE_ERR=8`) with `persist_dest_bit()` and `clear_persist_dirty_for()`.
   - `clear_persist_dirty_for(c, dest_id)` clears `PERSIST_DIRTY_RUNTIME`, and clears `persist_dest_bit(dest_id) | PERSIST_DIRTY_GATE_ERR` only when `dest_id != 0`, preserving unreconciled bits for other durable destinations across subsequent ungated or alternate-destination OFF toggles and count edits until the original destination itself is reconciled.
   - `persist_precap_if_authorized()` sets `*out_dest = dest_id` before both the idempotent check and `s7_write_precap_record()`. Added sealed-ARM regression tests in `test_stage7_integration.py` covering follow-up OFF and OFF count edits with absent/retargeted/restored gates, dual-dirty destinations, and malformed-gate recovery.

#### Part B ([REVIEW-stage7-3a-sol-sd-r4.md](REVIEW-stage7-3a-sol-sd-r4.md))
1. **N1 (BLOCKER — finalizer deleting successor worker's live `.boot.lock` & ownerless lock on interrupted 2-step release):**
   - Added `_acquire_collect_lock()` and `_release_collect_lock(session, *, try_rmdir_parent)` in `scripts/m7_stage7_sd_probe.py`.
   - `_release_collect_lock()` verifies `/tmp_network`, `/tmp_network/mlv2`, `.boot.lock` (non-symlink dirs), `.boot.lock/owner` (regular non-symlink file), and exact owner `collect`; if not owned by `collect`, prints `NOT_OWNED` with zero mutations. When owned, cleans stale `.boot.rel`, atomically renames `.boot.lock` (with `owner` still inside) to `.boot.rel`, removes `.boot.rel`, optionally attempts `rmdir /tmp_network/mlv2`, and prints `REL`.
   - Final cleanup sets `lock_owned = False` immediately on `("REL", "NOT_OWNED")`; `finally:` uses the exact same owner-checked `_release_collect_lock()`, eliminating both successor deletion and the ownerless-lock interruption window.
2. **N2 (MAJOR — unsafe boot-log leaf still read by unconditional `cat`):**
   - Tightened `REMOTE_RAM_DIR_RE`/`REMOTE_RAM_LEAF_RE` and `_inspect_ram_leaf()` to verify non-symlink `/tmp_network` and parent dir; added `_safe_cat_ram_file()` guarding every RAM read in `do_ram_start()` and `do_ram_collect()` with non-symlink dir + regular non-symlink leaf checks.
   - When `boot_log_state != "FILE_OK"`, `do_ram_collect()` sends zero `cat` commands for `sd-boot.log`. Added 6 new real-`/bin/sh` and wire-framing tests in `test_stage7_sd.py` (`CollectorShellTests` + `test_cli_wire_budget_with_fixture_uploads`).

### File SHA-256 Manifest (r5)

| File | SHA-256 |
|---|---|
| `prototype-stage7-persist/mlv2.h` | `7127cf4fc5481d26de98c45dfb4cf6bf334f1bc145a05f71cf1f12d990ae789d` |
| `prototype-stage7-persist/mlv2_sys.h` | `979cdbbcd0c7d14017a41bcc6534a3db057a8e8305f436cacdc038f776251ddf` |
| `prototype-stage7-persist/stage7_common.h` | `935aae3f8972e64d2a188cc66c4497db4c0779d0cfe57580b08de616875afdba` |
| `prototype-stage7-persist/precap_mod.c` | `8b8270e200f4ef2270fc9e6f1fd2cd002a936f042f0f9c5b9bae3b807024525e` |
| `prototype-stage7-persist/shim.c` | `ec9ac34f5447c6389f1c0839f9b43b081914e8d0fcacbcd46a58aecc0bb45fef` |
| `prototype-stage7-persist/core.c` | `7e932565eda9be636f2ee245e5594592455060e3950f168c660d9095a0957986` |
| `prototype-stage7-persist/build_stage7.py` | `10079bd5fc627788ca662501b84e55accc7c12308d379a61a44903266c5ce8e6` |
| `prototype-stage7-persist/test_stage7_unicorn.py` | `a8a15755b5a7312bf816b5660448b93aafc9a07b278baa29e556ac6fb928f7d7` |
| `prototype-stage7-persist/test_stage7_integration.py` | `a1e6d5fb55bb9b417f3f4037a2d2bd828c8d257d588725e141f2266d31b6351f` |
| `prototype-stage7-persist/test_stage7_ram_runner.py` | `50def14923da7179ea53ca20caa62d1b2e92c6db2bae3c31ab29c239486c091e` |
| `prototype-stage7-persist/out/PreCapture.mod` | `208b5aa074017f078816a2a173471f38d1af55bfa90672c1eb757a91fa6d4356` |
| `prototype-stage7-persist/out/shim.bin` | `2d7e470d94819f29c460bbcc9a8a2022f09f2f66db314a02fa2950879fad031b` |
| `prototype-stage7-persist/out/core.bin` | `9f846a8858c1d38d470728c80cbfef1b7ff2a14428704b7d4b0e5996f026de18` |
| `prototype-stage7-persist/out/mlv2.req` | `379a359ec218b97caa9d37ab6fed7b25164312fb412d444d61787ddb7f571e12` |
| `prototype-stage7-persist/out/mlv2_guard.elf` | `f1c634067075345d2386127c77cbfebca5bc53fdf6dcd623feaa43fff41cf61b` |
| `prototype-stage7-persist/out/stage7_daemon.elf` | `95d707c3fdfae5075bf4eb77ec7b1bb5355b3ff9f377ded4c06bfb8abf695201` |
| `prototype-stage7-persist/out/stage7_ring.elf` | `8b07b26f43a82bb36afba14cfa991e0e90c7819ce150a72244286b8e99acc0e9` |
| `prototype-stage7-persist/out/precap-build.json` | `a48e836057f4c18d975ff187a6a9f95744cdecf93f8b8677b8982fb8eccf9901` |
| `prototype-stage7-persist/out/build.json` | `6f0761e0a12b17c97987c57726a72fe5c23765b9710879d4763d862c5d22b8c4` |
| `prototype-stage7-persist/mlv2_card_read.c` | `e77a7ecce12a317a2f58102bf424dfd6d7f3c477344aa020ed43fe224c2c2b12` |
| `prototype-stage7-persist/mlv2_sd_boot.sh` | `f4dc853cefd62694f7ef6336c7133c0450b6d6cba4694d0566e170c9112d7d70` |
| `prototype-stage7-persist/build_stage7_sd.py` | `53890c371a96551705d486eb3097fe9a360e5d534c5122348fc1a1ca0caa09d1` |
| `prototype-stage7-persist/test_stage7_sd.py` | `ebf8b1f791d0b681589689ebd6ee6726ba0f4baa290b8f506c6adfcb45f0dfac` |
| `prototype-stage7-persist/out-sd/mlv2_card_read.elf` | `4aed6c1c511123d4d3abc30d3808ef681923507dea2c326412de739502082757` |
| `prototype-stage7-persist/out-sd/mlv2_sd_boot.sh` | `f4dc853cefd62694f7ef6336c7133c0450b6d6cba4694d0566e170c9112d7d70` |
| `prototype-stage7-persist/out-sd/card.ustar` | `bf05d60e38a9c903bb2a194d515be7d85da66629e6944469cd161c7eaac05490` |
| `prototype-stage7-persist/out-sd/build-sd.json` | `3726d73b7407ccdecbce1937ec8cd3106689505f052f3e6042490d56dcc0339c` |
| `scripts/m7_stage7_sd_probe.py` | `007c993c4f108ac5263208bafb3c2e88a3c8153b66308a24cb76893cf93574db` |
| `.gitignore` | `6f7a44b8f3dcbd37dcaf89e61e40205516d8ebf41a7a52fb27fe2bbfcba263fb` |


---

## Stage 7.3 Phase A — r6 Update (Post-Sol r5 Part A Final Fix; Part B Already GO at r5)

### Verdicts (r6)

- **Offline build & seals:** **PASS** — Stage 7.1 (`out/build.json`, `192,820 B`, `core.bin` `18,280 B`; `shim.bin` `1,864 B`, `PreCapture.mod` `564 B`, `mlv2.req` `1,992 B`, `mlv2_guard.elf` `16,800 B`, `stage7_daemon.elf` `30,340 B`, `stage7_ring.elf` `122,980 B` all byte-identical to r4/r5) and Stage 7.3 Phase A (`out-sd/build-sd.json`, `mlv2_card_read.elf` `13,768 B`, `mlv2_sd_boot.sh` `16,641 B`, `scripts/m7_stage7_sd_probe.py`, `test_stage7_sd.py` all byte-identical to Sol's Part B r5 **GO**; `card.ustar` `204,800 B` re-packaged with r6 `core.bin`) pass `verify_seal()`.
- **Offline test suites:** **PASS (50/50)** — `test_stage7_unicorn.py` (`6/6`), `test_stage7_integration.py` (`7/7`), `test_stage7_ram_runner.py` (`10/10`), `test_stage7_sd.py` (`27/27`).
- **Part B review status:** **GO** at r5 ([REVIEW-stage7-3a-sol-sd-r5.md](REVIEW-stage7-3a-sol-sd-r5.md)); zero Part B source/script/ELF/CLI changes in r6 (only `card.ustar` + `build-sd.json` re-sealed for r6 `core.bin` and verified by `build_stage7_sd.verify_seal()` + 27/27 `test_stage7_sd.py`).
- **Live hardware:** **INCONCLUSIVE** — Zero camera/USB/SD access; submitted for independent Codex Sol Part A r6 review.

### Disposition of Sol Part A r5 Finding ([REVIEW-stage7-3a-sol-menu-r5.md](REVIEW-stage7-3a-sol-menu-r5.md))

1. **BLOCKING (`mod_cfg_unverified` losing original durable destination bit on successful compensation + adjacent `disarm_fail` hardening):**
   - `core.c:1322-1329`: `mod_cfg_unverified` now unconditionally sets `PERSIST_DIRTY_RUNTIME | persist_dest_bit(dest_id)` even when compensating `persist_precap_if_authorized(1, prev_fr, dest_id, 0)` succeeds, because runtime agreement is unverified until a subsequent verified edit reconciles `dest_id`.
   - `core.c:503-540, 1244-1250`: Extracted read-only `read_persist_gate_dest()` (nonblocking, `O_NOFOLLOW`, `S_IFREG`, zero durable file/temp I/O) and used it on `disarm_fail` so a failed runtime disarm records `persist_dest_bit(gdest)` (or `PERSIST_DIRTY_GATE_ERR` on invalid/unreadable gate), preventing a subsequent absent/retargeted-gate `OFF` from hiding an armed durable record while preserving clean RAM-only (`gdest == 0`) behavior.
   - Added full sealed-ARM regression test in `test_stage7_integration.py` covering all 12 verification-`-EIO` follow-up cases across both destinations, both `disarm_fail` follow-ups, and standalone RAM-only operation.

### File SHA-256 Manifest (r6)

| File | SHA-256 |
|---|---|
| `prototype-stage7-persist/mlv2.h` | `7127cf4fc5481d26de98c45dfb4cf6bf334f1bc145a05f71cf1f12d990ae789d` |
| `prototype-stage7-persist/mlv2_sys.h` | `979cdbbcd0c7d14017a41bcc6534a3db057a8e8305f436cacdc038f776251ddf` |
| `prototype-stage7-persist/stage7_common.h` | `935aae3f8972e64d2a188cc66c4497db4c0779d0cfe57580b08de616875afdba` |
| `prototype-stage7-persist/precap_mod.c` | `8b8270e200f4ef2270fc9e6f1fd2cd002a936f042f0f9c5b9bae3b807024525e` |
| `prototype-stage7-persist/shim.c` | `ec9ac34f5447c6389f1c0839f9b43b081914e8d0fcacbcd46a58aecc0bb45fef` |
| `prototype-stage7-persist/core.c` | `43c84ca032ef117ec8d8a613dfb465e0c5b63b06b172a763e8ed0beaf06a2dd9` |
| `prototype-stage7-persist/build_stage7.py` | `10079bd5fc627788ca662501b84e55accc7c12308d379a61a44903266c5ce8e6` |
| `prototype-stage7-persist/test_stage7_unicorn.py` | `a8a15755b5a7312bf816b5660448b93aafc9a07b278baa29e556ac6fb928f7d7` |
| `prototype-stage7-persist/test_stage7_integration.py` | `681c1a8189f3f3cba677270550c5b8857839ec5abef4004db4695f2494e7c577` |
| `prototype-stage7-persist/test_stage7_ram_runner.py` | `50def14923da7179ea53ca20caa62d1b2e92c6db2bae3c31ab29c239486c091e` |
| `prototype-stage7-persist/out/PreCapture.mod` | `208b5aa074017f078816a2a173471f38d1af55bfa90672c1eb757a91fa6d4356` |
| `prototype-stage7-persist/out/shim.bin` | `2d7e470d94819f29c460bbcc9a8a2022f09f2f66db314a02fa2950879fad031b` |
| `prototype-stage7-persist/out/core.bin` | `1c5a1f239dc75c3f612f18ff6936641e8354d96f7af3d754eb4e09061302aa2b` |
| `prototype-stage7-persist/out/mlv2.req` | `379a359ec218b97caa9d37ab6fed7b25164312fb412d444d61787ddb7f571e12` |
| `prototype-stage7-persist/out/mlv2_guard.elf` | `f1c634067075345d2386127c77cbfebca5bc53fdf6dcd623feaa43fff41cf61b` |
| `prototype-stage7-persist/out/stage7_daemon.elf` | `95d707c3fdfae5075bf4eb77ec7b1bb5355b3ff9f377ded4c06bfb8abf695201` |
| `prototype-stage7-persist/out/stage7_ring.elf` | `8b07b26f43a82bb36afba14cfa991e0e90c7819ce150a72244286b8e99acc0e9` |
| `prototype-stage7-persist/out/precap-build.json` | `a48e836057f4c18d975ff187a6a9f95744cdecf93f8b8677b8982fb8eccf9901` |
| `prototype-stage7-persist/out/build.json` | `eeb4e3196febfa7e42c8347b291583f496ab5574aab6df70a97607b9f1602e1a` |
| `prototype-stage7-persist/mlv2_card_read.c` | `e77a7ecce12a317a2f58102bf424dfd6d7f3c477344aa020ed43fe224c2c2b12` |
| `prototype-stage7-persist/mlv2_sd_boot.sh` | `f4dc853cefd62694f7ef6336c7133c0450b6d6cba4694d0566e170c9112d7d70` |
| `prototype-stage7-persist/build_stage7_sd.py` | `53890c371a96551705d486eb3097fe9a360e5d534c5122348fc1a1ca0caa09d1` |
| `prototype-stage7-persist/test_stage7_sd.py` | `ebf8b1f791d0b681589689ebd6ee6726ba0f4baa290b8f506c6adfcb45f0dfac` |
| `prototype-stage7-persist/out-sd/mlv2_card_read.elf` | `4aed6c1c511123d4d3abc30d3808ef681923507dea2c326412de739502082757` |
| `prototype-stage7-persist/out-sd/mlv2_sd_boot.sh` | `f4dc853cefd62694f7ef6336c7133c0450b6d6cba4694d0566e170c9112d7d70` |
| `prototype-stage7-persist/out-sd/card.ustar` | `a353b661e6658cd5ca1235a9f225e6e07d5a6429e8c2a1d46ffacccb9fb54acf` |
| `prototype-stage7-persist/out-sd/build-sd.json` | `7e80c41d777a891ecf8aa6db809c523be7e6c379de519d0d75ec7ec9da36e952` |
| `scripts/m7_stage7_sd_probe.py` | `007c993c4f108ac5263208bafb3c2e88a3c8153b66308a24cb76893cf93574db` |
| `.gitignore` | `6f7a44b8f3dcbd37dcaf89e61e40205516d8ebf41a7a52fb27fe2bbfcba263fb` |


---

## Stage 7.3 Phase A — r7 Update (Post-Sol r6 Part A `persist_armed_dest` Fix; Part B Already GO at r5)

### Verdicts (r7)

- **Offline build & seals:** **PASS** — Stage 7.1 (`out/build.json`, `193,024 B`, `core.bin` `18,484 B`; `shim.bin` `1,864 B`, `PreCapture.mod` `564 B`, `mlv2.req` `1,992 B`, `mlv2_guard.elf` `16,800 B`, `stage7_daemon.elf` `30,340 B`, `stage7_ring.elf` `122,980 B` all byte-identical to r4/r5/r6) and Stage 7.3 Phase A (`out-sd/build-sd.json`, `mlv2_card_read.elf` `13,768 B`, `mlv2_sd_boot.sh` `16,641 B`, `scripts/m7_stage7_sd_probe.py`, `test_stage7_sd.py` all byte-identical to Sol's Part B r5 **GO**; `card.ustar` `204,800 B` re-packaged with r7 `core.bin`) pass `verify_seal()`.
- **Offline test suites:** **PASS (50/50)** — `test_stage7_unicorn.py` (`6/6`), `test_stage7_integration.py` (`7/7`, including all 152 disarm-matrix scenarios), `test_stage7_ram_runner.py` (`10/10`), `test_stage7_sd.py` (`27/27`).
- **Part B review status:** **GO** at r5 ([REVIEW-stage7-3a-sol-sd-r5.md](REVIEW-stage7-3a-sol-sd-r5.md)); zero Part B source/script/ELF/CLI changes in r7 (`card.ustar` + `build-sd.json` re-sealed for r7 `core.bin` and verified by `build_stage7_sd.verify_seal()` + 27/27 `test_stage7_sd.py`).
- **Live hardware:** **INCONCLUSIVE** — Zero camera/USB/SD access; submitted for independent Codex Sol Part A r7 review.

### Disposition of Sol Part A r6 Finding ([REVIEW-stage7-3a-sol-menu-r6.md](REVIEW-stage7-3a-sol-menu-r6.md))

1. **BLOCKING (failed disarm forgetting previously armed durable destination when gate disappears, is withdrawn, becomes FIFO/malformed, or retargets):**
   - Added 1-byte bitmask `Ctx.persist_armed_dest` (`core.c:105`) tracking every durable destination (`1u` = `/setting`, `2u` = `sim`) confirmed to hold `ON` via `persist_precap_if_authorized()` (`core.c:570-573`) or boot-hydrated `ON` in `rescan()` (`core.c:629-633`), reset in `sd_disabled()` (`core.c:742`).
   - On `disarm_fail` (`core.c:1258-1263`), uses `c->persist_armed_dest` when known (never polluted by a retargeted gate, never lost by gate withdrawal/FIFO/malformed, zero durable file/temp I/O), falling back to `read_persist_gate_dest()` only when `c->persist_armed_dest == 0u` (preserving clean standalone RAM-only behavior).
   - On every confirmed `OFF` transition (`ON -> OFF`, `OFF` count edit, rollback disarm, unexpected disarm), `c->persist_dirty |= c->persist_armed_dest` retains `OFF!` / `OFF! >` until each armed durable destination is explicitly reconciled to `OFF` under a valid gate.
   - Added 152-scenario disarm-matrix coverage in `test_stage7_integration.py` spanning all 7 rows of Sol's r6 matrix across both destinations plus clean-OFF-after-gate-withdrawal and boot-hydrated disarm-fail cases.

### File SHA-256 Manifest (r7)

| File | SHA-256 |
|---|---|
| `prototype-stage7-persist/mlv2.h` | `7127cf4fc5481d26de98c45dfb4cf6bf334f1bc145a05f71cf1f12d990ae789d` |
| `prototype-stage7-persist/mlv2_sys.h` | `979cdbbcd0c7d14017a41bcc6534a3db057a8e8305f436cacdc038f776251ddf` |
| `prototype-stage7-persist/stage7_common.h` | `935aae3f8972e64d2a188cc66c4497db4c0779d0cfe57580b08de616875afdba` |
| `prototype-stage7-persist/precap_mod.c` | `8b8270e200f4ef2270fc9e6f1fd2cd002a936f042f0f9c5b9bae3b807024525e` |
| `prototype-stage7-persist/shim.c` | `ec9ac34f5447c6389f1c0839f9b43b081914e8d0fcacbcd46a58aecc0bb45fef` |
| `prototype-stage7-persist/core.c` | `c8630f00ff96597d0435a7effc1bc79e08629d7b2191f30b1bdff6d08728afbe` |
| `prototype-stage7-persist/build_stage7.py` | `10079bd5fc627788ca662501b84e55accc7c12308d379a61a44903266c5ce8e6` |
| `prototype-stage7-persist/test_stage7_unicorn.py` | `a8a15755b5a7312bf816b5660448b93aafc9a07b278baa29e556ac6fb928f7d7` |
| `prototype-stage7-persist/test_stage7_integration.py` | `0048ea598d1e17d1cbf080283b84c2c8fca75734980d3521fcfdf081ae0ff74d` |
| `prototype-stage7-persist/test_stage7_ram_runner.py` | `50def14923da7179ea53ca20caa62d1b2e92c6db2bae3c31ab29c239486c091e` |
| `prototype-stage7-persist/out/PreCapture.mod` | `208b5aa074017f078816a2a173471f38d1af55bfa90672c1eb757a91fa6d4356` |
| `prototype-stage7-persist/out/shim.bin` | `2d7e470d94819f29c460bbcc9a8a2022f09f2f66db314a02fa2950879fad031b` |
| `prototype-stage7-persist/out/core.bin` | `83ed0915faf5ba8715720867ec05395dbd8e3aa4be505624672ecc1377baa018` |
| `prototype-stage7-persist/out/mlv2.req` | `379a359ec218b97caa9d37ab6fed7b25164312fb412d444d61787ddb7f571e12` |
| `prototype-stage7-persist/out/mlv2_guard.elf` | `f1c634067075345d2386127c77cbfebca5bc53fdf6dcd623feaa43fff41cf61b` |
| `prototype-stage7-persist/out/stage7_daemon.elf` | `95d707c3fdfae5075bf4eb77ec7b1bb5355b3ff9f377ded4c06bfb8abf695201` |
| `prototype-stage7-persist/out/stage7_ring.elf` | `8b07b26f43a82bb36afba14cfa991e0e90c7819ce150a72244286b8e99acc0e9` |
| `prototype-stage7-persist/out/precap-build.json` | `a48e836057f4c18d975ff187a6a9f95744cdecf93f8b8677b8982fb8eccf9901` |
| `prototype-stage7-persist/out/build.json` | `7a3ab88cf59c8551a2f64a7243aea7070d09222c272fe5ed08d442fbb85772f7` |
| `prototype-stage7-persist/mlv2_card_read.c` | `e77a7ecce12a317a2f58102bf424dfd6d7f3c477344aa020ed43fe224c2c2b12` |
| `prototype-stage7-persist/mlv2_sd_boot.sh` | `f4dc853cefd62694f7ef6336c7133c0450b6d6cba4694d0566e170c9112d7d70` |
| `prototype-stage7-persist/build_stage7_sd.py` | `53890c371a96551705d486eb3097fe9a360e5d534c5122348fc1a1ca0caa09d1` |
| `prototype-stage7-persist/test_stage7_sd.py` | `ebf8b1f791d0b681589689ebd6ee6726ba0f4baa290b8f506c6adfcb45f0dfac` |
| `prototype-stage7-persist/out-sd/mlv2_card_read.elf` | `4aed6c1c511123d4d3abc30d3808ef681923507dea2c326412de739502082757` |
| `prototype-stage7-persist/out-sd/mlv2_sd_boot.sh` | `f4dc853cefd62694f7ef6336c7133c0450b6d6cba4694d0566e170c9112d7d70` |
| `prototype-stage7-persist/out-sd/card.ustar` | `7c110dd396398045458ce7e9c411d3abc5ead319089334ecfb32bdc3ee0e881f` |
| `prototype-stage7-persist/out-sd/build-sd.json` | `cfe1d205df92329a0cff22c811f9c07145b9a1c2c94cefbd9bba31d8bca9f8e0` |
| `scripts/m7_stage7_sd_probe.py` | `007c993c4f108ac5263208bafb3c2e88a3c8153b66308a24cb76893cf93574db` |
| `.gitignore` | `6f7a44b8f3dcbd37dcaf89e61e40205516d8ebf41a7a52fb27fe2bbfcba263fb` |


---

## Stage 7.3 Phase A — r8 Update (Live M7 Hardware Finding: `/proc/mounts` Symlink in `mlv2_sd_boot.sh`)

### Live Hardware Evidence (`20261127T150047Z-a5657d9d6703-boot-probe.json` & `20261127T150328Z-f3774a6bb2c0-ram-start.json`)

- **Step A1 (`--prep-card`):** **PASS** — `MLV2.TAR` (`204,928 B`, SHA-256 `e5db7d251154c458f424382aeffd364e6ee3eb27c4b2ab169defc8f9fb6c562d`) written and readback-verified on `/Volumes/RX100M7`.
- **Step A2 (`--boot-probe`):** **PASS** — Real 128 GB exFAT SD card (`BPS=512`, `SPC=256`, `TOTAL_SECTORS=250314752`, `DATA_LBA=32768`, `ROOT_CLUSTER=4`, `MLV2_FOUND=1`, `DISABLE_MARKERS=0`) authenticated cleanly by sealed ARM `mlv2_card_read.elf` (`present_rc=0`, `verify_rc=0`, `verified_ok=true`, `/tmp_network` `1,032,192 B` free, `probe_dir_cleanup="GONE"`). Confirmed WBI resume (`warm.mode=2`, `/system/sabin/ssboot.bin`, `im.elf` PID `161` `starttime=105`).
- **Step A3 first run (`--ram-start`):** Found a real Linux kernel difference in `mlv2_sd_boot.sh:103` (`mount_ok()`): on the live M7 kernel (`vmlinux.bin`: `self/mounts` + `proc_mounts_operations` in `tgid_base_stuff`), `/proc/mounts` is a kernel symlink `mounts -> self/mounts`, so `[ ! -L "$proc_root/mounts" ]` failed closed and exited `0` before writing `sd-boot.log` or modifying `im.elf` (`probe_before == probe_after == 1,003,520 B` free, zero flash writes).

### r8 Fix & Offline Verification

- `prototype-stage7-persist/mlv2_sd_boot.sh`:
  - `mount_ok()` now verifies `[ ! -L "$proc_root" ] && [ -d "$proc_root" ]`, explicitly rejects any symlink at `$proc_root/$$` or `$proc_root/$$/mounts`, prefers the symlink-free per-PID procfs file `$proc_root/$$/mounts`, and falls back to regular non-symlink `$proc_root/mounts` for host fixtures.
  - Rewrote the three `BOOT` token checks (`self_pid`, `im_pid`, `im_st`) to explicit `if [ ... ]; then ...; fi` under BusyBox 1.13.4 `set -e`.
- `prototype-stage7-persist/test_stage7_sd.py`:
  - Added `test_symlinked_mount_sources_leave_stage_untouched` (rejecting symlinked `proc_root`, global `mounts`, and per-PID `$$/mounts`) and `test_real_linux_proc_pid_mounts_with_symlinked_proc_mounts` (accepting real-Linux `/proc/mounts -> self/mounts` + regular `/proc/$$/mounts`).
- **Offline verification:** **PASS (52/52)** — `test_stage7_sd.py` (`29/29`), `sh -n`, `build_stage7.verify_seal()`, `build_stage7_sd.verify_seal()`; `mlv2_card_read.elf` (`4aed6c1c...`), `card.ustar` (`7c110dd3...`), and `scripts/m7_stage7_sd_probe.py` (`007c993c...`) are byte-identical to r7 (SD card `MLV2.TAR` unchanged).

| Changed file (r8) | SHA-256 |
|---|---|
| `prototype-stage7-persist/mlv2_sd_boot.sh` | `3f89eb5b6e8eea130b63214a4fd203ec9d996af77338b7b4d9c9da2098375bd5` |
| `prototype-stage7-persist/out-sd/mlv2_sd_boot.sh` | `3f89eb5b6e8eea130b63214a4fd203ec9d996af77338b7b4d9c9da2098375bd5` |
| `prototype-stage7-persist/out-sd/build-sd.json` | `49150b8afe7e85832d3ff2b96e6fff3d8c4481a6f952ed1be1c3c872ecb62406` |
| `prototype-stage7-persist/test_stage7_sd.py` | `2a472f3fb95ed0ec2e4791b7a5985529df272b28feb40888d5d8edc60c4fee80` |
| `prototype-stage7-persist/out-sd/mlv2_card_read.elf` (unchanged) | `4aed6c1c511123d4d3abc30d3808ef681923507dea2c326412de739502082757` |
| `prototype-stage7-persist/out-sd/card.ustar` (unchanged) | `7c110dd396398045458ce7e9c411d3abc5ead319089334ecfb32bdc3ee0e881f` |


---

## Stage 7.3 Phase A — r9 Update (Disallow `mount_ok()` Fallthrough on Non-Regular `$proc_root/$$/mounts`)

- Fixed Sol r8 finding ([REVIEW-stage7-3a-sol-sd-r8.md](REVIEW-stage7-3a-sol-sd-r8.md)): in `mlv2_sd_boot.sh:mount_ok()`, whenever `$proc_root/$$` exists or is a symlink, require it to be a non-symlink directory and `$proc_root/$$/mounts` to be a readable non-symlink regular file (failing closed with zero fallthrough to `$proc_root/mounts` if `$proc_root/$$/mounts` is a FIFO, directory, symlink, missing, or unreadable).
- Added `pid-mounts-fifo` and `pid-mounts-dir` (with valid `$proc_root/mounts` present) to `test_symlinked_mount_sources_leave_stage_untouched` in `test_stage7_sd.py`.
- **Offline verification:** **PASS (52/52)** — `test_stage7_sd.py` (`29/29`), `sh -n`, `build_stage7.verify_seal()`, `build_stage7_sd.verify_seal()`; `mlv2_card_read.elf` (`4aed6c1c...`), `card.ustar` (`7c110dd3...`), and `scripts/m7_stage7_sd_probe.py` (`007c993c...`) remain byte-identical.

| Changed file (r9) | SHA-256 |
|---|---|
| `prototype-stage7-persist/mlv2_sd_boot.sh` & `out-sd/mlv2_sd_boot.sh` (`17,139 B`) | `7e580aad8da187034ca07d5ae724360cadd7374669a4e9c4390634b064e9bffa` |
| `prototype-stage7-persist/out-sd/build-sd.json` | `be4cb3a6952826de8e42b7094689541ffc7e5090751d16c598543016982f28c1` |
| `prototype-stage7-persist/test_stage7_sd.py` | `7ccf4090f4958e9b780619b4835baf36f3a4ceb5a620de9ac55766f794e10df9` |
