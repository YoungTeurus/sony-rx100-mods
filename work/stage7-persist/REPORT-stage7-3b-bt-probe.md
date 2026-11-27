# Stage 7.3 Phase B Step B5 transition probe, Sol r4 correction

2026-11-27 · Host receipt publication · Implementation verification

**PASS offline for the r4 temporary-name exchange.** During a successful framed capture in a mode-0777 scratch directory, a second same-UID Python process moved the open staging file to `displaced` and placed the review’s 11-byte truncated JSON at its old name. The CLI returned exit 1, printed no `RESULT`, and created no final JSON. The displaced inode held the complete capture, and the substitute retained its 11 bytes.

The publisher keeps the exclusively opened staging descriptor through file fsync, publication and readback. Preflight verifies the host can address the pinned inode. Publication checks the temporary name’s current identity and links from the inode address. The no-clobber link preserves an occupied final name. Before reporting success, the publisher opens the final name without following symlinks and verifies its device, inode, length, exact serialized bytes and visible name. Cleanup checks identity before removing a name. Host-side marker intent and inode checkpoints use this same publisher.

| Regression | Observed result |
|---|---|
| Second process swaps the staging name during capture, reproducing r4 | Exit 1, no final JSON, no success line |
| Swap immediately inside the link call, after the staging-name check | Exit 0, byte-complete final JSON on the original inode, foreign temporary file preserved |
| Modify one byte of the just-published inode without changing its size | Exact readback detects the change, exit 1, no final or staging name left |

This run exercised the macOS volume inode path on the local filesystem. Linux uses `/proc/self/fd` with a directory-relative `linkat` destination. Linux execution was not tested here. A host that cannot resolve the inode address fails preflight. Readback establishes the result at verification time. Another writer with directory or file access can subsequently change it. **Physical camera behavior remains INCONCLUSIVE.**

## Offline verification

All commands exited 0. The self-test and both unittest runs each passed 32 tests, including all three r4 regressions. All three seal checks ran in verify-only mode.

```sh
env -u TMPDIR .venv-analysis/bin/python3 -B scripts/m7_stage7_phaseb_bt_probe.py --self-test
env -u TMPDIR .venv-analysis/bin/python3 -B -m unittest prototype-stage7-persist/test_stage7_phaseb_bt_probe.py
TMPDIR=/var/tmp .venv-analysis/bin/python3 -B -m unittest prototype-stage7-persist/test_stage7_phaseb_bt_probe.py
PYTHONPATH=prototype-stage7-persist .venv-analysis/bin/python3 -B -c 'import build_stage7, build_stage7_sd; build_stage7.verify_seal(); print("PASS Stage 7"); build_stage7_sd.verify_seal(); print("PASS Stage 7 SD")'
.venv-analysis/bin/python3 -B prototype-stage7-persist/build_stage7_phaseb.py --verify
```

## Current SHA-256

| File | SHA-256 |
|---|---|
| scripts/m7_stage7_phaseb_bt_probe.py | `d4e5e06fd509ff583d6162bad7a52f184981210c68f3d754a14040ad55bebaee` |
| prototype-stage7-persist/test_stage7_phaseb_bt_probe.py | `3fd544658de3405c9c59243c6ef46791c713a414195e11a009ef79c97a41ca3b` |
| work/stage7-persist/REVIEW-stage7-3b-bt-probe-sol-r4.md | `4ed3dd696e14ba9b1f7a1774873daabea1be7c2a92a98e4cff95b806b2774908` |
| extracted/m7-stage7-phaseb-1.00-20261127T184903Z/bin/busybox | `e6ebb87e6de8814f994c18ed194a22bfb463fe55cb8f66aef94b22fb6103905f` |
| prototype-stage7-persist/out/build.json | `7a3ab88cf59c8551a2f64a7243aea7070d09222c272fe5ed08d442fbb85772f7` |
| prototype-stage7-persist/out-sd/build-sd.json | `be4cb3a6952826de8e42b7094689541ffc7e5090751d16c598543016982f28c1` |
| prototype-stage7-persist/out-phaseb/build-phaseb.json | `0196830e60df5301a4a66d7ec927356b1c40f5a09107cee653364602c1196ec5` |
| prototype-stage7-persist/out-phaseb/phaseb_statfs.elf | `1310666d79e0301da773e966d611c4522ac88c3dacbe7cf00b2da69830ebb337` |

---

# Stage 7.3 Phase B Step B5 transition probe, Sol r3 corrections

2026-11-27 · DSC-RX100M7 firmware 1.00 · Implementation verification

**PASS offline for the three assigned r3 findings.** All three suite invocations passed 29 tests. The three verify-only seal entry points passed. **INCONCLUSIVE on the physical camera.** The complete producer-to-shell procfd handoff and timing have not been exercised on the M7 kernel. Independent review of this revision is pending.

## Mapping to Sol r3

| Finding | Change and regression |
|---|---|
| 1. Empty regular replacement accepted after exclusive create | The host chooses the basename before creation. The shell reopens the creator’s /proc/PID/fd/3 as descriptor 7, pinning the exclusively created inode. It checks the creator executable, the creator's private input pipe, the resolved pathname and device/inode equality. The host records the inode from descriptor 7 and the shell keeps the descriptor through write and final identity verification. Payload bytes go to descriptor 7 even if another writer swaps the name at the last moment. The framed regressions substitute an empty inode at the creation ACK and an identical-content inode after the write. Both refuse `planted`. The host filesystem test exercises an empty file, FIFO and symlink, then swaps the name at echo after the same-file predicate. Only the saved original receives bytes. [Plant](scripts/m7_stage7_phaseb_bt_probe.py:285) · [Framed regressions](prototype-stage7-persist/test_stage7_phaseb_bt_probe.py:419) |
| 2. A complete final receipt can be overwritten after preflight | The publisher flushes and fsyncs the temporary sibling, closes it, and hard-links it at the final name through the pinned directory descriptor. An occupied final name makes the link fail atomically. Both success and failure unlink the temporary sibling. Successful publication fsyncs its directory. A competing writer in the mocked connection published 25 bytes at the reserved basename. Publication raised `FileExistsError`, retained those exact bytes and left only the competing receipt. [Publisher](scripts/m7_stage7_phaseb_bt_probe.py:441) · [Collision test](prototype-stage7-persist/test_stage7_phaseb_bt_probe.py:620) |
| 3. Inherited shell variables can redirect the scratch race fixture | The scratch shell receives an explicit environment containing PATH and LC_ALL. All fixture paths live under its temporary root. The test exports hostile `d` and `f` values pointing at an unrelated sentinel and verifies its bytes after the write. A separate invocation with both variables already exported also passed. [Scratch test](prototype-stage7-persist/test_stage7_phaseb_bt_probe.py:350) |

The r3 review also discussed the cleanup result and a gap in the skipped-mount assertion. The earlier assignment expressly requires `DATA_CAPTURE_OK=False` and exit 1 for an unverified requested cleanup. A receipt now separately records `telemetry_capture_ok`. The read-only replay has successful telemetry, failed cleanup and exit 1. The skipped-mount test checks the whole marker prefix and guard commands.

## Creation descriptor on the exact M7 build

The original `mktemp` applet at Thumb entry `0x25b4d` prints a pathname and exits. The replacement uses the stock `cpio -i` extractor as a short-lived exclusive creator. The anonymous pipe supplies a single, host-generated 180-byte newc header containing a mode-0600 regular member with a one-byte archive size. A bounded stock `sleep 10` holds the pipe writer on descriptor 0 and emits no archive data. The terminal closes its writer before the extractor starts. This gives the shell a bounded opportunity to pin the exclusive descriptor. Once pinned, host checkpointing and readback no longer depend on the extractor's lifetime. A timeout during transfer refuses the plant. On pipe EOF the extractor stops in its short-copy error path.

| Original M7 BusyBox evidence | Property checked |
|---|---|
| ash `eval` entry `0x174f1`, heredoc path `0x1697c–0x16a30`, bracket applet `0x255f1` | The fixed, quoted empty heredoc creates a pipe. The probe checks `-p` and refuses occupied descriptors 7, 8 or 9 before setup. |
| Echo at `0x2278c–0x22834`, cpio main at `0x1de74–0x1df24`, newc reader at `0x211fc–0x212c0` | The compiled echo supports combined `-ne`, escaped NUL padding and `-e` for the fixed heredoc. The extractor supports `-i`. The newc reader consumes a 110-byte header, the name and its alignment. An independent host archive reader recognized the generated member when supplied with a completed fixture archive. |
| `0x1de90`, `0x1fb7a–0x1fc06`, `0x1fc70–0x1fc86`, `0xc980–0xc994` | Default `cpio -i` uses flags 0x10. The signed existing-mtime comparison at `0x1fbca–0x1fbcc` cannot take the unlink branch with the member's INT32_MAX mtime. The missing-name regular branch passes 0xc1 (O_WRONLY, O_CREAT, O_EXCL) to `open64`. An entry installed after lstat yields an exclusive-open collision. |
| `0xcd40–0xcd68`, `0x1fd0a` | Short copy terminates before post-copy pathname ownership or mode updates. A Unicorn test executes the original extraction callback with controlled libc boundaries. It exercises minimum, zero and maximum signed existing mtimes, a post-lstat collision and short EOF. It checks the actual open flags and copy fd and detects entry to unlink or post-copy metadata code. [ARM regression](prototype-stage7-persist/test_stage7_phaseb_bt_probe.py:125) |
| `sleep` at `0x24078`, `usleep` at `0x2eacc`, `readlink` at `0x23f30`, `ls -Li` at `0x23744`, `-ef` at `0x2527c–0x252dc` | The bounded holder calls `sleep(10)`. The short readiness loop accepts the member only on the expected executable and private pipe. This also excludes a library briefly occupying fd 3 during process startup. The readback uses the held descriptor, and the final visible name must denote it. |

The host scratch test uses a real O_EXCL descriptor and POSIX redirection. On macOS it adapts fdescfs inode comparison. The ARM callback test intercepts libc calls. Neither exercises complete target-kernel process scheduling or procfs descriptor transfer. A concurrent directory change after the final sample, or after the final identity check and before the separate cleanup unlink, remains outside the sampled guarantee. The owner procedure below still applies when an interruption leaves no creation-inode checkpoint.

## Offline verification

Run from the project root. The self-test and both unittest commands each ran 29 tests and exited 0. The exported-environment regression passed, and each released seal passed read-only verification.

```sh
env -u TMPDIR .venv-analysis/bin/python3 -B scripts/m7_stage7_phaseb_bt_probe.py --self-test
env -u TMPDIR .venv-analysis/bin/python3 -B -m unittest prototype-stage7-persist/test_stage7_phaseb_bt_probe.py
TMPDIR=/var/tmp .venv-analysis/bin/python3 -B -m unittest prototype-stage7-persist/test_stage7_phaseb_bt_probe.py
env d=external-sentinel f=external-sentinel TMPDIR=/var/tmp .venv-analysis/bin/python3 -B -m unittest prototype-stage7-persist.test_stage7_phaseb_bt_probe.ProbeTests.test_mutation_commands_in_host_scratch_directory
PYTHONPATH=prototype-stage7-persist .venv-analysis/bin/python3 -B -c 'import build_stage7, build_stage7_sd; build_stage7.verify_seal(); print("PASS Stage 7"); build_stage7_sd.verify_seal(); print("PASS Stage 7 SD")'
.venv-analysis/bin/python3 -B prototype-stage7-persist/build_stage7_phaseb.py --verify
```

All 30 distinct frames from plant, check and check-and-remove passed host `/bin/sh -n`. At index 99 with a 20-digit inode the longest wire line was 499 bytes against the exclusive 512-byte limit. The frame check is reproducible with the Python verification block in the r2 section below, setting `case.camera.inode = 18446744073709551615`.

## SHA-256 at the r3 remediation

| File | SHA-256 |
|---|---|
| scripts/m7_stage7_phaseb_bt_probe.py | `829f03fcf10db6d0350c8056a7530d3d068e57184720986bc80a1b138da36558` |
| prototype-stage7-persist/test_stage7_phaseb_bt_probe.py | `2bf84c45bd2dc4d1cd51cd5b4a0d57be420e9aa1c5c5f1027e97ad22b696f332` |
| work/stage7-persist/REVIEW-stage7-3b-bt-probe-sol-r3.md | `c4dc952f8688e9e63a52e3e5dcebba28c8d246672e31140e693b51d0c79450a8` |
| extracted/m7-stage7-phaseb-1.00-20261127T184903Z/bin/busybox | `e6ebb87e6de8814f994c18ed194a22bfb463fe55cb8f66aef94b22fb6103905f` |
| prototype-stage7-persist/out/build.json | `7a3ab88cf59c8551a2f64a7243aea7070d09222c272fe5ed08d442fbb85772f7` |
| prototype-stage7-persist/out-sd/build-sd.json | `be4cb3a6952826de8e42b7094689541ffc7e5090751d16c598543016982f28c1` |
| prototype-stage7-persist/out-phaseb/build-phaseb.json | `0196830e60df5301a4a66d7ec927356b1c40f5a09107cee653364602c1196ec5` |
| prototype-stage7-persist/out-phaseb/phaseb_statfs.elf | `1310666d79e0301da773e966d611c4522ac88c3dacbe7cf00b2da69830ebb337` |

---

# Stage 7.3 Phase B Step B5 transition probe, Sol r2 corrections

2026-11-27 · RX100M7 firmware 1.00 · Implementation verification

**PASS offline** for the six findings below, 26 regression tests, the exact-image command audit, and the three release seals. **INCONCLUSIVE on hardware** for transition retention, actual flash activity, and physical UI recovery. The B5 collector continues to report `full_b5_complete=false`. Independent review of these hashes is pending.

## R2 findings and evidence

| Sol r2 finding | Implemented behavior and offline evidence |
|---|---|
| 1. Noclobber can open a non-regular destination | Plant calls the original BusyBox `mktemp` with a relative, nonce- and seed-qualified template in the guarded tmpfs cwd. The applet exclusively creates a mode-0600 regular file. After checkpointing its inode, the content writer pins a read descriptor and checks its type, inode, resolved pathname, mount guard, and equality to the visible entry. The write goes through the checked kernel descriptor link. The scratch-shell regression exercises a regular file, FIFO, symlink, and a name replacement at the second guard. The unrelated target remains byte-identical. |
| 2. An interrupted plant can leave a short file | A durable intent precedes creation and an immutable basename/inode checkpoint precedes the first payload byte. On the same boot and tmpfs mount, a matching inode and prefix of the expected 43-byte token yields `incomplete` on check. Cleanup revalidates the observed inode and digest and confirms absence. Injected interruptions at 0, 9 and 42 bytes all recovered. A changed inode or wrong prefix was refused. Complete r1 and r2 records remain readable. A regression also recovered 0- and 9-byte fixed-name r2 files using the earlier verified plant observation and intent. See the owner procedure below for missing inode evidence. |
| 3. Read-only mount gives a false cleanup success | `check-and-remove` requires verified absence or verified removal. With a known marker retained on a read-only mount the fixture returned exit 1, `data_capture_ok=false`, `bt_probe_ok=false`, and `marker_cleanup_verified=false`. It kept the telemetry with `capture_complete=true` and issued no remove. |
| 4. A final JSON can be empty or truncated | Writable preflight exclusively opens a hidden, mode-0600 sibling through the pinned directory fd. After serialization the writer flushes, fsyncs, closes, replaces the final name and fsyncs the directory. Exceptions before publication unlink the temporary file. Fault injection covered a partial serialization, file fsync and replace. Each left the final path absent and no temp file. A pre-existing final receipt retained its bytes. An uncatchable process death can leave a hidden temporary sibling. |
| 5. Invalid CLI receipt path raises a traceback | Invalid basename and symlink invocations now return exit 1 with a receipt diagnostic. Neither test reaches connection. Permission refusal retains its writable-directory guidance. |
| 6. Final disable masks the primary capture error | An unexpected build together with a failing final disable records the build failure in `error` and the teardown failure in `terminal_disable_error`. The regression verifies both and exit 1. |

### Owner recovery when no creation inode was acknowledged

Use the same host receipt directory throughout a transition series. If the host lost the connection immediately after exclusive creation, a volatile empty file can exist before the host has an inode checkpoint. An old fixed-name plant can likewise leave a short file without a verified plant receipt. The probe refuses to unlink either based only on its name. It reports the recovery instructions in the receipt and on stderr. End the current series, power the camera off, and let volatile RAM lose power. Start Bluetooth again and use the probe to verify absence on a fresh writable tmpfs before planting another marker. A warm transition alone does not establish that the tmpfs was recreated. The fixture verified that cleanup and replant succeed after verified absence. Physical power-cycle behavior remains unmeasured.

### Exact M7 shell audit

The firmware audit reads the named ARM ELF, checks its SHA-256 and maps the applets, ash builtins, test operators and option literals used by the wire commands. The new applet entry is `mktemp` at Thumb VA `0x25b4d`. For a supplied template without flags the branch at `0x25b78` skips temporary-directory prefixing. The file branch calls `mkstemp64@plt` at `0x25bb0` and prints the resulting pathname at `0x25bba`. The new write frame uses the existing bracket predicates, `ls -Li`, single-path `readlink`, ash substitution and output redirection. Directory discovery checks `-r` and `-x`, then uses an ash glob and loop. The tests check those operators against the original table. The retained applets and their original option evidence are itemized in the historical audit below.

All 20 distinct frames captured from the three-mode fixture passed host `/bin/sh -n`. With a 10-digit inode and index 99 the longest wire line was 494 bytes against the exclusive limit of 512. The ARM interpreter was inspected statically. On macOS the shell fixture adapts procfd resolution, same-file comparison, and descriptor access mode for fdescfs. Linux procfd execution on the physical M7 remains unverified. The mount/name observations are sampled. A different privileged writer can still change a name between the final identity check and unlink.

## Offline verification commands

Run from the project root. Each command in the first block exited 0. Each suite ran 26 tests. The Stage 7 and SD entry points verified their published seals, and Phase B verified the inspector hash shown below.

```sh
.venv-analysis/bin/python3 -B scripts/m7_stage7_phaseb_bt_probe.py --self-test
.venv-analysis/bin/python3 -B -m unittest prototype-stage7-persist/test_stage7_phaseb_bt_probe.py
TMPDIR=/var/tmp .venv-analysis/bin/python3 -B -m unittest prototype-stage7-persist/test_stage7_phaseb_bt_probe.py
PYTHONPATH=prototype-stage7-persist .venv-analysis/bin/python3 -B -c 'import build_stage7; build_stage7.verify_seal(); print("PASS Stage 7")'
PYTHONPATH=prototype-stage7-persist .venv-analysis/bin/python3 -B -c 'import build_stage7_sd; build_stage7_sd.verify_seal(); print("PASS Stage 7 SD")'
.venv-analysis/bin/python3 -B prototype-stage7-persist/build_stage7_phaseb.py --verify
```

The scratch race fixture failed once during an intermediate concurrent verification when the expected moved file was absent. Added an assertion at the injected race boundary, then observed 50 consecutive passes of that case under `TMPDIR=/var/tmp` and green final suites under both settings. The cause of that single host-fixture failure was not established.

```sh
B=extracted/m7-stage7-phaseb-1.00-20261127T184903Z/bin/busybox
objdump -d --triple=thumbv7a-linux-gnueabi --start-address=0x25b4c --stop-address=0x25bc0 "$B"
.venv-analysis/bin/python3 -B - <<'PYVERIFY'
import sys, subprocess
sys.path.insert(0, "prototype-stage7-persist")
from test_stage7_phaseb_bt_probe import ProbeTests, pb
case = ProbeTests()
case.setUp()
try:
    case.camera.inode = 4294967295
    frames = set()
    for mode in ("plant", "check", "check-and-remove"):
        rc, receipt, commands, _ = case.invoke(mode)
        assert rc == 0, receipt
        frames.update(pb.frame(cmd, 99, "0123456789ab")[0] for cmd in commands)
    for frame in frames:
        subprocess.run(["/bin/sh", "-n"], input=frame, check=True)
    print(len(frames), max(len(f.splitlines()[0]) for f in frames))
finally:
    case.doCleanups()
PYVERIFY
```

## SHA-256 at the r2 remediation

| File | SHA-256 |
|---|---|
| scripts/m7_stage7_phaseb_bt_probe.py | `be0cef0be7b973a23ee494ef9dc0e7024b5d8e3b1044cd2e0ba3dd3746ae6ff6` |
| prototype-stage7-persist/test_stage7_phaseb_bt_probe.py | `4c22f296e625574964dcbb241af5bbecb7b5bf118b3e006d62bbd125b4d29cff` |
| work/stage7-persist/REVIEW-stage7-3b-bt-probe-sol-r2.md | `827855c172653b92537241133a8a7b78eb6517c524dbc7cbf752e2133d967217` |
| extracted/m7-stage7-phaseb-1.00-20261127T184903Z/bin/busybox | `e6ebb87e6de8814f994c18ed194a22bfb463fe55cb8f66aef94b22fb6103905f` |
| prototype-stage7-persist/out/build.json | `7a3ab88cf59c8551a2f64a7243aea7070d09222c272fe5ed08d442fbb85772f7` |
| prototype-stage7-persist/out-sd/build-sd.json | `be4cb3a6952826de8e42b7094689541ffc7e5090751d16c598543016982f28c1` |
| prototype-stage7-persist/out-phaseb/build-phaseb.json | `0196830e60df5301a4a66d7ec927356b1c40f5a09107cee653364602c1196ec5` |
| prototype-stage7-persist/out-phaseb/phaseb_statfs.elf | `1310666d79e0301da773e966d611c4522ac88c3dacbe7cf00b2da69830ebb337` |

---

# Stage 7.3 B5 transition probe after Sol r1

**PASS for the offline transition-probe regression suite and all three existing seals. INCONCLUSIVE for the physical camera.** The review correctly identified three commands that the stock shell cannot run and a working-directory change that breaks terminal framing. The previous ten passing tests missed them. This revision checks the command set against the extracted RX100M7 BusyBox and exercises the terminal protocol with an in-memory device.

The implemented CLI covers boot, mount, process and volatile-marker observations. The complete B5 extractor and targeted server/loader inspection remain outside this implementation. Receipts carry `full_b5_complete=false`. No hardware or USB command ran. This is the implementer’s verification. Sol’s r1 NO-GO applies to the earlier hashes and no new independent verdict is claimed.

## Findings and corrections

| Sol r1 finding | Implementation and verification |
|---|---|
| Default receipt directory is unwritable | The existing default is root:staff, mode 0755, under host UID 501. Exclusive receipt creation still precedes connection. Permission failure gives a specific diagnostic. `--receipt-dir work/stage7-persist/phaseb-probes-local` selects a writable sibling. Reuse that same directory for a transition series so the matching ownership record remains available. No permission or ownership changes were made to the original directory. Tests exercise a real permission denial as UID 501, the alternative, protected paths and symlink rejection. |
| Firmware lacks command and df | No shell capability discovery or free-space query runs. The receipt records `df_unavailable` for each requested path and preserves the kernel mount evidence. Free block counts are unavailable. The strict mock rejects the old command and unaudited command forms. |
| Interactive cd invalidates the prompt | Each marker operation enters /tmp_bt inside a subshell. The parent shell retains its working directory. The test device emits the changed prompt for an unscoped cd and the actual frame matcher rejects it. A separate host shell test observes the caller’s cwd after the scoped command. |
| No stat applet, cpio cannot write newc | Both dependencies were removed. Initial checks require one rw tmpfs row in /proc/mounts and a matching root-mounted rw tmpfs in mountinfo. A mount over the marker is refused. Each scoped command rechecks digests of both complete tables, including the sampled mount ID, and compares its cwd to the current /tmp_bt with test -ef. Plant and remove repeat the guard before mutation. A host shell regression changes the mount ID while retaining the same filesystem type, then changes just the mount table. Both changes deny the command. Active tmpfs without usable mountinfo fails closed. |
| Firmware-side writes and version-read order | The mount stack and /version.txt overmount check precede the version read. The regression verifies an overmounted version file is never read. Receipts disclose possible Sony /setting/.etools writes during authentication, the separate FileControl side effect and best-effort ash history suppression. The gate permits no FileControl requests. There are no VFAT free-space queries. The receipt lists the project's permitted mutation destination and records stock flash writes as unobserved (null). |
| Completed marker stranded after teardown or receipt failure | Before issuing the plant frame, the host durably publishes a mode-0600 ownership record using exclusive creation, file fsync, hard-link publication and directory fsync. The camera writes a 43-byte marker through its open file descriptor. Its tag depends on a fresh host seed and the inode read through that same descriptor. A subsequent check validates the nonce, exact tag, byte count and inode independently of the earlier data/transport verdict. Tests cover failed final disable, an unreadable-as-JSON final receipt, a completed creation with no successful readback, a different inode carrying identical bytes, and recovery from an r1 plant receipt with verified readback and failed teardown. |
| Unqualified success on skipped plant | Missing, read-only, flash and stacked mounts skip the marker without a marker command. For a requested plant, a clean skip can complete telemetry, while `marker_baseline_established=false`, `bt_probe_ok=false` and exit 1 identify the missing baseline. |
| Final path identity and transition races | Removal checks the inode and MD5 via an open fd, repeats the mount guard, rejects a symlink and compares the visible file to the fd immediately before unlink. The receipt requires verified absence afterward. These are sampled namespace checks. A separate privileged writer replacing the name between the last test and unlink is outside the guarantee of shell-level checks. Abrupt interruption before a valid 43-byte record has actually been written can leave an incomplete file. Recovery refuses to delete an entry whose ownership cannot be established. |
| Terminal and StopSenser outcomes | A complete capture with a failed StopSenser transport retains DATA_CAPTURE_OK=True, SERVICE_STOP_TRANSPORT_OK=False, the recorded GenericUsbException and exit 1. A failed terminal-disable proof sets DATA_CAPTURE_OK=False. Physical UI return and actual Sony flash activity remain unmeasured. |

## Exact-build command audit

The test reads `extracted/m7-stage7-phaseb-1.00-20261127T184903Z/bin/busybox` and verifies its SHA-256, the 90 applet names and entrypoint mapping used by the probe, the required ash builtins, test operators and compiled option strings. The 18 normalized command templates in the mock admit only the audited shell text with validated shapes for variable fields. The inherited process sweep is included. The longest framed line at index 99 is 456 bytes. The terminal limit is 512.

| Command or shell construct | Evidence in the extracted ARM EABI5 image |
|---|---|
| ash framing and setup | Builtin table VA 0x2fb48, **file offset 0x27b48**. The table includes echo 0x2278d, export 0x13ce9, ulimit 0x146f5, umask 0x145d5, set 0x14331, exec 0x14ca9, exit 0x13da9, continue 0x14581 and cd 0x149bd (Thumb pointers). Resource selector HSatfdscmlpnvw includes -c. The shell option string at 0x382f9 includes Cnoclobber for set -C. The cd option literal LP is at 0x37ed1. The PS1 literal at 0x38262 includes the current working directory. The exec implementation at 0x14ca8 branches on an absent command operand. The marker uses redirection-only exec in a subshell. |
| Shell grammar | Assignment, functions, positional parameters, substitution, suffix-pattern removal, subshells, loops, redirection and pipelines are shell syntax. Scratch shell execution exercises marker creation, fd inheritance, tag formation, duplicate or symlink refusal, removal and cwd restoration. On macOS the test uses /dev/fd/7 for the actual inode/checksum reads and adapts the final same-file predicate because fdescfs reports a synthetic device number. This is host shell execution. The ARM ash interpreter was inspected statically. |
| Test expressions | The bracket applet enters 0x255f0. Six-byte operator records beginning at 0x3c579 contain -L, -e, -d, -f, -ef, -eq, ! and =. |
| File, directory and process reads | cat at 0x21a70 takes a single file. ls at 0x23744 uses Cadil1gnsxAkcetuSXrvFpLRhT:w:, covering -lai, -li and -Li (follow the open-fd link). wc at 0x258f8 includes -c. readlink at 0x23f30 uses the one-path form. dd at 0x2242c has the bs, count and if operand table at 0x3bc9d. |
| Integrity, removal and log | md5sum at 0x23a94 uses the digest/filename output format at 0x3bfc1. The probe uses stdin, one-file and two-file forms. rm at 0x23f5c receives the fixed relative marker pathname. dmesg at 0x18cb4 uses its no-option, non-clearing form. |
| Excluded forms | command is absent from the builtin and applet tables. df and stat are absent from the applet table. cpio_main loads ituvF:dm, which excludes -o and -H. |

## Verification

Commands ran from the repository root using the existing analysis environment. No release builder ran in write mode.

```sh
export PATH="$PWD/.venv-analysis/bin:$PATH" PYTHONDONTWRITEBYTECODE=1
python3 scripts/m7_stage7_phaseb_bt_probe.py --self-test
python3 -m unittest prototype-stage7-persist/test_stage7_phaseb_bt_probe.py
TMPDIR=/var/tmp python3 scripts/m7_stage7_phaseb_bt_probe.py --self-test
TMPDIR=/var/tmp python3 -m unittest prototype-stage7-persist/test_stage7_phaseb_bt_probe.py
PYTHONPATH=prototype-stage7-persist python3 -B -c 'import build_stage7; build_stage7.verify_seal(); print("PASS Stage 7")'
PYTHONPATH=prototype-stage7-persist python3 -B -c 'import build_stage7_sd; build_stage7_sd.verify_seal(); print("PASS Stage 7 SD")'
python3 -B prototype-stage7-persist/build_stage7_phaseb.py --verify
```

| Check | Actual output | Exit |
|---|---|---|
| Self-test, default TMPDIR | Ran 18 tests in 0.540s, OK | 0 |
| unittest, default TMPDIR | Ran 18 tests in 0.535s, OK | 0 |
| Self-test, /var/tmp | Ran 18 tests in 0.532s, OK | 0 |
| unittest, /var/tmp | Ran 18 tests in 0.541s, OK | 0 |
| Stage 7 seal | PASS Stage 7 | 0 |
| SD seal | PASS Stage 7 SD | 0 |
| Phase B seal | PASS Phase B offline inspector 1310666d79e0301da773e966d611c4522ac88c3dacbe7cf00b2da69830ebb337 | 0 |

## SHA-256

| Path | SHA-256 |
|---|---|
| scripts/m7_stage7_phaseb_bt_probe.py | d063ed2f7e177ae3c00055823f5a9261bdc6d5cd01e8afbb1f9b61c971d44f57 |
| prototype-stage7-persist/test_stage7_phaseb_bt_probe.py | 0ea83843110c7f3dad9e452c09366e2c5df030efe423e74632747ab554bd05b8 |
| work/stage7-persist/REVIEW-stage7-3b-bt-probe-sol-r1.md | 0fe010d132dce38eb9dd9693ba841144ebda1fa0a86636653524ebf9e85865ec |
| extracted/m7-stage7-phaseb-1.00-20261127T184903Z/bin/busybox | e6ebb87e6de8814f994c18ed194a22bfb463fe55cb8f66aef94b22fb6103905f |
| prototype-stage7-persist/out/build.json | 7a3ab88cf59c8551a2f64a7243aea7070d09222c272fe5ed08d442fbb85772f7 |
| prototype-stage7-persist/out-sd/build-sd.json | be4cb3a6952826de8e42b7094689541ffc7e5090751d16c598543016982f28c1 |
| prototype-stage7-persist/out-phaseb/build-phaseb.json | 0196830e60df5301a4a66d7ec927356b1c40f5a09107cee653364602c1196ec5 |
| prototype-stage7-persist/out-phaseb/phaseb_statfs.elf | 1310666d79e0301da773e966d611c4522ac88c3dacbe7cf00b2da69830ebb337 |

This revision edited the probe, its test and this report. The digest of `git status --short -uall` before and after the revision was `307eafc0937e4d2a7a220eb7d30b838b3afa1352d7798bd61c7914595f9484fc`. The checkout already contained unrelated changes. No live receipt was created.
