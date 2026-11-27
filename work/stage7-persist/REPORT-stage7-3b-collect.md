# Stage 7.3 Phase B Read-Only Collector & Filesystem Inspector Report (r6)

2026-11-27 · DSC-RX100M7 1.00 · build `29110_03.2021050601` · offline implementation & Sol r5 timestamp remediation

Status: **OFFLINE PASS (pending independent Codex Sol r6 review; hardware INCONCLUSIVE until live owner collection).**

## 1. r6 Delta Over Sol r5 (`--extract-boot` GO, `--transition-probe` timestamp fix)

Sol r5 issued **GO** for `--extract-boot` and flagged one remaining blocker on `--transition-probe`: the permissive `[A-Z][a-z]{2}\s+\d+\s+[0-9:]{4,5}` timestamp pattern in `LS_MTIME_RE` / `LS_FILE_INODE_RE` accepted malformed strings such as `Nov 27 :::::`, `Xyz  0 99:99`, and tab-separated `Jan\t1\t00000`.

r6 fixes this cleanly against exact BusyBox 1.13.4 `coreutils/ls.c:652-658` (`printf("%6.6s ", filetime + 4); printf("%5.5s ", filetime + 11)` or `printf(" %4.4s ", filetime + 20)`) and live M7 1.00 `ls` outputs (`Jan  1 00:00`, `Jan  1  1980`, `May  6  2021`):
- `_LS_MTIME_PAT` matches only exact 12-character `ctime()` slices with literal ASCII spaces (no `\t`), valid English month names (`Jan`–`Dec`), calendar-bounded days per month (`1..31`, `1..30`, `Feb 1..29`), and either `HH:MM` (`00:00`–`23:59`) or ` YYYY` (`[12][0-9]{3}`).
- `_is_valid_ls_mtime()` additionally rejects `Feb 29  YYYY` on non-leap years (e.g. `Feb 29  2021`).
- Enforced uniformly across all four `ls` parsers and receipt validators: `LS_DOT_RE` (`parse_tmp_network_ls`), `LS_FILE_INODE_RE` (`_parse_marker_ls_meta`), `LS_DIR_INODE_RE` (`statfs_dir_check`), `_validate_marker_observation` (`marker.*.mtime`), and `validate_receipt` (`tmp_network.mtime`).
- Added negative tests in `test_stage7_phaseb_collect.py` covering `Nov 27 :::::`, `Xyz  0 99:99`, `Jan\t1\t00000`, `Feb 30 12:00`, `Feb 29  2021`, `Nov 27 24:00` on both live `_inspect_ram_marker()` and offline `compare()` / `validate_receipt()`.

All prior r5 guarantees and documented observational boundaries remain intact:
- Sealed `phaseb_statfs.elf` (`2,816 B`, SHA-256 `1310666d...`, MD5 `34657c84de91710ba6282a47539849bd`) is unchanged.
- `cwd`-pinned staging cleanup (`_make_statfs_cleanup_cmd`), 4-state ownership, and lost-ACK `POISONED_SESSION_UNVERIFIED` reporting are unchanged (single-operator stock-camera assumption for final pathname `rmdir`).
- `--transition-probe` emits zero `FileControl` calls, zero ELF uploads, and zero `rm`/`rmdir` commands (`--ram-marker` choices: `none`, `plant`, `check`).
- Exact 41-field M7 `do_task_stat` (`0x6045d4f7`) grammar, `comm <= 15 B` (`0x601c3fb4`), `cmdline <= 4096 B` (`0x602001b4`), exact `raced_pids` schema, host destination guard (`os.path.samefile` + case-fold), and extraction completion checks are unchanged (with disclosed inline-framing/unescaped-`comm` observational limits).

## 2. Exact Verification Commands & Results

```sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
py=.venv-analysis/bin/python3
dir=prototype-stage7-persist
prior=$(shasum -a 256 "$dir"/out/* "$dir"/out-sd/*)
"$py" -B "$dir/build_stage7_phaseb.py"
first=$(shasum -a 256 "$dir"/out-phaseb/*)
"$py" -B "$dir/build_stage7_phaseb.py"
second=$(shasum -a 256 "$dir"/out-phaseb/*)
test "$first" = "$second"
"$py" -B "$dir/build_stage7_phaseb.py" --verify
"$py" -B "$dir/test_stage7_phaseb_collect.py"
TMPDIR=/var/tmp "$py" -B "$dir/test_stage7_phaseb_collect.py"
"$py" -B scripts/m7_stage7_collect.py --self-test
(cd "$dir" && ../.venv-analysis/bin/python3 -B -c 'import build_precap_mod as m, build_stage7 as s, build_stage7_sd as a; m.verify_seal(); print("PASS build_precap_mod.verify_seal()"); s.verify_seal(); print("PASS build_stage7.verify_seal()"); a.verify_seal(); print("PASS build_stage7_sd.verify_seal()")')
test "$prior" = "$(shasum -a 256 "$dir"/out/* "$dir"/out-sd/*)"
```

- Reproducibility: **PASS** (`first == second`)
- `build_stage7_phaseb.py --verify`: **PASS**
- `test_stage7_phaseb_collect.py` (default `TMPDIR` and `TMPDIR=/var/tmp`): **13/13 PASS**
- `m7_stage7_collect.py --self-test`: **PASS**
- Legacy seals (`build_precap_mod`, `build_stage7`, `build_stage7_sd`): **3/3 PASS**, `out/*` and `out-sd/*` byte-identical.

## 3. Delivered File Digests (SHA-256)

| File | SHA-256 |
| --- | --- |
| `prototype-stage7-persist/phaseb_statfs.c` | `e44486e70eb0288cecd6a043d2a39df6becac1012c5d123b248d1418e879c274` |
| `prototype-stage7-persist/build_stage7_phaseb.py` | `443699067a30abc8d88c0a0dc5ce7fbb654d329c1782ffb79b106f9c603d53d7` |
| `prototype-stage7-persist/out-phaseb/phaseb_statfs.elf` | `1310666d79e0301da773e966d611c4522ac88c3dacbe7cf00b2da69830ebb337` |
| `prototype-stage7-persist/out-phaseb/build-phaseb.json` | `0196830e60df5301a4a66d7ec927356b1c40f5a09107cee653364602c1196ec5` |
| `scripts/m7_stage7_phaseb_collect.py` | `c009b341a67b0975cce862c6dbbd4a2be58e4f951da28f0dc4dff43bd8fd405c` |
| `prototype-stage7-persist/test_stage7_phaseb_collect.py` | `2e0f9dd60b890c9f75e3c3d33949dfb83db24a7fdd76301c6de7293c0f243733` |

`phaseb_statfs.elf`: `2,816 B`, MD5 `34657c84de91710ba6282a47539849bd`.
