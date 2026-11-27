# Stage 7.3 Phase B — Sealed Persistent SD Loader Release (DSC-RX100M7 1.00)

2026-11-28 · DSC-RX100M7 firmware `1.00` (`29110_03.2021050601`) · **LIVE HARDWARE PASS (install, WBI battery pull, S2R power switch + Pre-Capture capture, WBI settings persistence, no-SD stock boot, and no-SD -> SD reinsertion).**

## 5. Live Hardware Verification (2026-11-28, Physical DSC-RX100M7 1.00)

- **SD card prep (`--mode prep-sd`):** **PASS** — `/Volumes/RX100M7/MLV2.TAR` (`204,928 B`, SHA-256 `416b9ccedc6783c9b56f5aea468ace36dda2b22fe308814ca04a940bdfbffffa`), owner key `~/.m7-phaseb-owner.key` (`0600`, prefix `b4ec763efb9c`).
- **Flash installation (`--mode install --owner-authorized-flash`):** **PASS** — receipt [`20261127T213907Z-b98a5eb0d59f-install.json`](phaseb-install/20261127T213907Z-b98a5eb0d59f-install.json): `INSTALL_OK=True`, `LIVE_PRELOAD_SMOKE_PASSED=True` (`PRELOAD_SMOKE_OK` in `0.084 s`), `post_preload_sanity_ok=True` (`0.058 s`), `terminal_disable_verified=True`.
- **Untethered live camera checks (owner-confirmed):**
  1. **PASS — Battery pull (10 s, WBI) with SD card:** 7th `Mods` tab (`Pre-Capture`) appeared automatically with no USB.
  2. **PASS — Ordinary power switch (S2R) + live Pre-Capture shot:** `Mods` tab and `Pre-Capture = ON` survived S2R intact; burst Pre-Capture frames recorded cleanly.
  3. **PASS — Second battery pull (10 s, WBI):** `Mods` tab returned automatically with remembered `Pre-Capture` state intact.
  4. **PASS — Boot without SD card:** 100% stock 6-tab menu.
  5. **PASS — Hot SD insertion after no-SD boot:** `Mods` tab appeared automatically and restored saved Pre-Capture state.
- **Note:** `--mode uninstall` and `--mode emergency-filecontrol-uninstall` remain offline-verified (28/28 tests PASS); live hardware uninstall has not been executed because the owner is keeping Phase B installed.

### Rollback / Uninstall Commands (USB Mass Storage mode)

```sh
# Normal uninstall (cleanly restores stock /etc and /setting)
sudo python3 -B scripts/m7_stage7_phaseb_install.py --mode uninstall --owner-authorized-flash

# Emergency shell-free FileControl uninstall (if shell is unavailable)
sudo python3 -B scripts/m7_stage7_phaseb_install.py --mode emergency-filecontrol-uninstall --owner-authorized-flash
```

## 1. Live Hardware Basis (Step B5 Receipts)

| Sample | Receipt | Boot ID | `/tmp_bt` mount ID / root inode | `bsa_server` PID (`starttime`) | Verdict |
|---|---|---|---:|---:|---|
| B5.1 baseline (`BT=On`) | `work/stage7-persist/phaseb-probes/20261127T205311Z-16e2c7af0c9f-bt-bt-s0-plant.json` | `ff7115aa...` | `23` / `4555` | `2324` (`315076`) | `/tmp_bt` tmpfs + `bsa_server` confirmed live |
| B5.2 after Power Switch (S2R) | `work/stage7-persist/phaseb-probes/20261127T205733Z-a10782d8b762-bt-bt-s1-after-switch.json` | `ff7115aa...` | `23` / `4555` (`ble_local_keys` inode `77` intact) | `3921` (`335206`) | **PASS** — `/tmp_bt` survives S2R untouched; `bsa_server` re-execs |
| B5.3 after 10 s Battery Pull (WBI) | `work/stage7-persist/phaseb-probes/20261127T205917Z-2db616a924fe-bt-bt-s2-after-battery.json` | `4d4e46b1...` | `23` / `2059` | `731` (`2101`) | **PASS** — WBI resume (`WARMBOOT`, `entry_resume(1)`) automatically mounts `/tmp_bt` and launches `/usr/bin/bsa_server` |

## 2. Sealed Phase B Flash & SD Manifest (`prototype-stage7-persist/out-phaseb-persist/`)

Zero WBI, kernel (`vmlinux.bin`), or `initrd.img` modifications. Runtime RAM workspace migrated via `-DS7_RAM_ROOT='"/tmp_bt"'` (verified zero `/tmp_network` references across all Phase B artifacts).

| Target Path | Role | Size (B) | SHA-256 |
|---|---|---:|---|
| `/setting/mlv2_sd_boot_hook.so` | Zero-dep ARM32 EABI `-nostdlib -shared -fPIC` constructor (`DT_NEEDED=0`, `SHN_UNDEF=0`, `R_ARM_RELATIVE` only, 11 verified M7 kernel syscalls); triggers ONLY on `/usr/bin/bsa_server`, returns after 1 `readlink` for all other processes | 2,436 | `0cae4d4a0264952ad4ce0ef3a6f5764f8ad743d9c1e2ce6c6d034c0820281c32` |
| `/setting/mlv2_card_read.elf` | Freestanding ARM32 FAT32/exFAT + HMAC-SHA256 reader (`/tmp_bt`, `/setting/mlv2_owner.key`) | 13,760 | `1f8bbd8fe627a24a4c115d8fdd7d6033eb8bfd40964b8de26c7082a5d4752b0f` |
| `/setting/mlv2_sd_boot.sh` | BusyBox 1.13.4-strict SD boot & monitor script (`/tmp_bt` remounted to 4 MiB, S2R live `.boot.lock` idempotency, 2-strike S2R MMC debounce, kill-switch `/setting/disable_sd_boot`, restores `/setting/mlv2_precap.cfg`) | 19,213 | `87cf24059f352d110e6624d9d41f75a1fd30e128eef0d61c5dc7631502e0f93f` |
| `/setting/mlv2_owner.key` | Owner-generated 32-byte HMAC-SHA256 key (`chmod 600`, stored outside git, redacted from all receipts) | 32 | owner-local |
| `/etc/ld.so.preload` | Single line `/setting/mlv2_sd_boot_hook.so`, written LAST only after live `LD_PRELOAD=/setting/mlv2_sd_boot_hook.so /bin/busybox sh -c 'echo PRELOAD_SMOKE_OK'` succeeds | 30 | generated on install |
| SD `/MLV2.TAR` (from `card.ustar`) | Owner HMAC-SHA256-authenticated 6-member archive (`guard`, `mlv2.req`, `core.bin`, `PreCapture.mod`, `daemon`, `ring.elf` compiled for `/tmp_bt`) | 204,800 (+128 B M7SD1 hdr = 204,928) | `ccd01c1f175351fc8e85bef3fea536917d48e8e969395df97db0874522ac1697` (`card.ustar`) |

## 3. Safety & Recovery Controls

1. **Pre-preload live smoke gate (`scripts/m7_stage7_phaseb_install.py --mode install`):** uploads and verifies all 4 `/setting/*` files via `FileControl` + readback, moves them atomically, and runs `LD_PRELOAD=/setting/mlv2_sd_boot_hook.so /bin/busybox sh -c 'echo PRELOAD_SMOKE_OK'` BEFORE touching `/etc/ld.so.preload`. Any non-exact output aborts with zero changes to `/etc/ld.so.preload`.
2. **Stock mode when SD absent or `MLV2.OFF` present:** `mlv2_sd_boot.sh` cleans `/tmp_bt/mlv2` and exits 0 leaving the camera 100% stock (6 tabs).
3. **Normal uninstall (`--mode uninstall --owner-authorized-flash`):** removes our entry from `/etc/ld.so.preload` first (preserving any unrelated lines), removes all `/setting/mlv2_*` and `/setting/disable_sd_boot`, syncs, and verifies absence via shell checks.
4. **Shell-free emergency recovery (`--mode emergency-filecontrol-uninstall --owner-authorized-flash`):** connects via Sony Senser `SONY_PFUNC_FileControl` inside WBI-restored `im.elf` with zero terminal calls, writes+verifies `/setting/disable_sd_boot`, deletes all 5 target files, and honestly records delete/read status (`0x82` ambiguity disclosed).

## 4. Offline Verification Summary

```sh
.venv-analysis/bin/python3 -B prototype-stage7-persist/build_stage7_phaseb_persist.py --verify
.venv-analysis/bin/python3 -B scripts/m7_stage7_phaseb_install.py --mode dry-run
.venv-analysis/bin/python3 -B scripts/m7_stage7_phaseb_install.py --self-test
.venv-analysis/bin/python3 -B -m unittest discover -s prototype-stage7-persist -p 'test_stage7*.py'
.venv-analysis/bin/python3 -B -c 'import sys; sys.path.insert(0, "prototype-stage7-persist"); import build_stage7, build_stage7_sd, build_stage7_phaseb, build_stage7_phaseb_persist; [(m.verify_seal(), print("PASS SEAL:", m.__name__)) for m in (build_stage7, build_stage7_sd, build_stage7_phaseb, build_stage7_phaseb_persist)]'
```

- **PASS:** `build_stage7`, `build_stage7_sd`, `build_stage7_phaseb`, `build_stage7_phaseb_persist` — all 4 seals verified green.
- **PASS:** `test_stage7_phaseb_persist.py` — **28/28 tests OK** (14 Astra FileControl/ARM recovery tests + 6 Phase B seal & Unicorn ARM emulation tests of the compiled `mlv2_sd_boot_hook.so` + 1 BusyBox shell kill-switch/S2R lock test + 7 CLI `dry-run`/`prep-sd`/`install`/`smoke-abort`/`uninstall`/`InstallGate` tests).
- **PASS:** Full `test_stage7*.py` discovery — **124/124 tests OK** prior to adding the 1-test `InstallGate` check (125 total across all suites).
- **INCONCLUSIVE (hardware):** Live `prep-sd`, `install`, WBI battery-pull boot, S2R power-switch survival, and `uninstall` have not yet been run on physical camera hardware.
