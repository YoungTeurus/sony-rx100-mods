# Stage 7.3 research — DSC-RX100M7 1.00, build 29110_03.2021050601

2026-11-27 · Offline analysis of original M7 files, the Stage 7.2 camera receipts and the upstream card reader.

**Decision: NO-GO for a persistent install.** The prior hardware PASS covers a working, already-booted camera and a reversible RAM session. Neither candidate has demonstrated recovery from an early boot failure. The upstream no-card result actually observed the custom library mapped into the imaging process. It supports a stock-looking menu, but fails the literal requirement that no custom hook run. Removing the card cannot undo a flash-resident preload decision made before reading the card. See upstream E0681:6–10,26–32 and `REPORT-stage7-2-hw.md:15–27,42–49`.

| Question | Verdict | Decisive evidence |
|---|---|---|
| Is the Stage 7.1 starting payload identified? | PASS, offline | All seven files match the sizes and SHA-256 digests in `out/build.json`. Total 187,648 B. |
| Can the upstream parser copy a file beyond the 4 GiB offset on a 128 GB-class volume? | PASS for two host fixtures | Byte-identical output with 128 KiB clusters, both contiguous and fragmented. Physical card and bare ARM I/O remain unqualified. |
| Can the upstream worker run as supplied? | FAIL | Its mandatory timeout and archive verification utilities are absent from the camera's full BusyBox applet list. |
| Can current settings survive reboot and first MENU? | FAIL, source | Only RAM is written. A fresh menu uses OFF/5, and an OFF-state count edit never reaches the module writer. |
| Does the proposed package fit? | PASS for the modeled file set; actual peak INCONCLUSIVE | Plain USTAR plus the full seven-file set needs 405,504 B at extraction with assumed 4 KiB allocation. Other writers, temporary files and uncapped logs determine actual peak. |
| Can the camera recover independently of either candidate after a failed boot? | INCONCLUSIVE | No failed-boot recovery receipt. Stage 7.2 used the USB service after a successful stock boot. |

Source shorthand below: `I` = `extracted/m7-stage7-1.00-20261126T172306Z/inventory.txt`; stock binary names are relative to that extraction. Stage sources and `out/` are under `prototype-stage7-persist/`. Stage receipts and `ram-runs/` are under `work/stage7-persist/`. `card_read.c` and `sd_boot_ilce6400a.sh` are under `sources/bionz-x-research/tools/native_camera/mlv2/`; the packager is under its sibling `tools/research/`; E0681 is under `sources/bionz-x-research/docs/evidence/`. Binary addresses below are image VAs unless identified as kernel addresses. Additional reads beyond the plan's original whitelist were for the explicitly requested Stage 7.2 receipts, upstream implementation, M7 kernel ABI, and the headers defining runtime file lengths/logging. All camera observations below are from existing receipts.

## 1. Stock boot, flash alias and recovery

**Verified mount calls.** In `sbin/init` Thumb `main`, the call at 0x97d6 passes the mount descriptor at 0x1334c for `/tmp`. The call at 0x97dc passes 0x1348c for `/etc`. Both identify the root of the same volume, `/dev/nflasha10`. The subsequent calls at 0x97e2/0x97f4 try the system volume and the call at 0x97fa passes 0x13310 for `/setting` on `/dev/nflasha2`. The first two calls fall through without testing their return values. This is the order on the path through 0x97d4; the binary has other boot paths. The observed mounts match, as do the file sizes and names in both directory listings. Writing a temp file under `/tmp` would write flash. `/usr` was ext2 read-only. `/tmp_network` was a separate 1,024 KiB tmpfs. Its creation time relative to the imaging process is unproven. Sources: `I:5–19,224–261`.

**Verified launch requests.** On the normal background path, `init` requests `bootin.elf`, conditionally requests `sen.elf`, then requests the network command daemon. Thumb VAs 0x9afa, 0x9b06, 0x9b0c call `run_bg_process`. In that function 0x8df4 calls `fork`, and 0x8e0a calls `execv` in the child. Literal pointers at 0x9ba4, 0x9bac and 0x9bb0 identify the three targets. There is also a foreground `system` branch at 0x9af2. A fork order does not establish which child finished initialization first. `bootin.elf` contains the imaging application launch strings; `im.elf` was already running in the Stage 7.2 BOOT record, PID 161. `launch_shell.elf` has a separate console path (Thumb 0x89ba fork, 0x89d8 setsid, 0x8a08 execv; strings name ttycons, console and ash). `sen.elf` is dynamically linked and also calls dlopen (Thumb 0xb4ec). Neither proves an independent USB rescue console. Sources: `I:303–308,727–741`; `ram-runs/20261127T092124Z-ce7b58c49934-daemon.log:1`.

**Global preload.** The original loader contains `/etc/ld.so.preload` at 0x14c64. Thumb 0x2164 sets mode 4 (read access), 0x2168 passes the path and 0x216a calls ARM 0x10d90 (`mov r7,#33; svc #0`). Only zero branches into the file-processing path at 0x2a1e. Thus absence or denied read access at this check skips the file. A failure sentinel from the subsequent file helper at 0x2a26 also rejoins normal startup at 0x2174. The worker loops over nonempty entries at 0x2b5a–0x2b76. Its caught object-load error branch at 0x9c6–0x9d6 emits the “cannot be preloaded: ignored” diagnostic at 0x13ad8 to fd 2. A library which passes loading and then faults or blocks during initialization is a different failure. This diagnostic gives no recovery guarantee for that case. Stock init, bootin, sen and launch_shell all name the same dynamic interpreter. A global setting can affect dynamically launched services once that file is visible, even if the desired imaging application never starts.

**Sony debug mode.** The original `usr/bin/change_mode.sh:11–32` labels mode 3 the default full application boot and documents the debug variants. Lines 35–48 perform filesystem changes even before argument validation. Lines 105–116 select a debug preload variant. This script records a requested mode. It does not establish isolation of the USB path, a watchdog guarantee, normal startup latency, or identical behavior under warm resume. The inventory shows an empty mode directory at acquisition (`I:213–216`). Replacing an absent original file with a text default on uninstall would leave a different configuration.

| Candidate or failure | Recovery implication |
|---|---|
| Global setting, object absent or rejected by loader | The identified skip/error paths allow further initialization in those cases. No M7 receipt shows USB recovery with the setting installed. |
| Global setting, object valid or corrupt after mapping | Early code can execute in services that recovery needs. Removing the SD package cannot remove a broken object on flash. |
| Sony debug setting, object present, absent or corrupt | A narrower scope is plausible. No evidence here proves that the full USB dependency chain is independent of the imaging app, or that a fault there leaves a usable service. All three recovery outcomes remain unqualified. |

**Warm restart.** `I:35–38,275–281` records `warm.mode=2`, watchdog parameters, both snapshot paths, and actual 11,280 B and 9,648 B files. `evidence/m7-kernel-analysis/m7.kallsyms:808–812,2563–2573` identifies resume and snapshot-status functions. The files have the recorded firmware date. They do not establish that the user's last power-off captured running processes, or that the next power-on restarted the imaging process. Searching the extracted init and bootin for literal “ssboot” or “warm” yielded no matching strings; this cannot exclude a kernel or indirect path. To distinguish behaviors, compare boot ID, process start ticks, uptime and stock snapshot status across ordinary off/on and a genuinely cold start. A repeated PID alone is ambiguous. Include cold and warm starts with the card removed after the previous session was ON.

**Verdict.** Neither mechanism qualifies as the safest install on this evidence. Global preload has demonstrably broader failure exposure. The mandatory stock-without-hook condition also conflicts with either design if custom code must run to discover package absence. A native preexisting stock card decision, or an explicit change to the product criterion, would be materially different evidence.

## 2. Filesystem, ARM ABI and card reader

**Card identity.** `I:63–74` identifies partition 250:11, 125,157,376 KiB = 128,161,153,024 B. The whole disk is 250:10. Capacity is consistent with SDXC. No VBR or filesystem type for that partition appears in the mount inventory. `card_read.c:162–198,418–443` reads sector zero of the partition as a VBR. Reinterpreting it as sector zero of a whole-disk MBR would change the offsets.

**Flash permissions.** `I:12,179–203,217–221` shows vfat, sync, dirsync, fmask/dmask 0022, posix_attr and errors=remount-ro. Existing regular files include unusual execute/write modes. The kernel has FAT get/set POSIX attribute functions and a file fsync function (`m7.kallsyms:6127–6131,6185–6186`). The mount record contains no noexec option. Those observations establish neither execute permission on a newly created file nor a successful executable mapping. Executing an ELF and mapping a shared object exercise different permission checks. RAM-only Stage 7.2 did not qualify either on the settings volume.

**ARM stat64.** The original libc Thumb `__fxstat64` at 0x95c3c moves fd and buffer to r0/r1 and sets r12 to 197. The trampoline at 0x15792 moves r12 to r7 and executes `svc #0` at 0x15794. The wrapper passes the buffer through. Independent layout evidence is the original kernel's `cp_new_stat64` at 0x601c2d88. For a result based at fp−0x7c, stores at 0x601c2df8/0x601c2de8 place rdev at +32/+36, and the mode store at 0x601c2e10 lands at +16. Libc's conversion at 0x9a1a0–0x9a1b8 likewise copies the +16 word and +32 doubleword. Getter and structure layout are independently supported. Expected rdev for this device is 0xfa0b. An actual fd/result capture on this M7 remains outstanding.

**A flag mismatch matters.** `card_read.c:19–24,431–443` defines its bare-ARM O_NOFOLLOW as octal 00400000 (0x20000). M7 libc `open64` Thumb 0x961b0 explicitly adds 0x20000 before ordinary open. The Stage 7 ARM header uses 0100000 (0x8000) for O_NOFOLLOW (`stage7_common.h:7–10`). The bare reader cannot claim its input open enforces the named no-follow check. Its post-open block type and rdev checks still apply. Host builds import host flags and cannot qualify this detail.

**Syscall slots, offline PASS.** Read the little-endian words at raw image file offset 0x6084 + 4 × slot. The image hash and base are in `evidence/m7-kernel-analysis/analysis.json:2–26`, the table symbol in `m7.kallsyms:150`. Each resulting address resolves to the following symbol. This verifies the ABI entries, not runtime permissions, timeout delivery or bounded driver latency.

| Slot | Resolved symbol | Slot | Resolved symbol | Slot | Resolved symbol |
|---:|---|---:|---|---:|---|
| 1 | sys_exit | 2 | sys_fork_wrapper | 3 | sys_read |
| 4 | sys_write | 5 | sys_open | 6 | sys_close |
| 10 | sys_unlink | 11 | sys_execve_wrapper | 33 | sys_access |
| 63 | sys_dup2 | 66 | sys_setsid | 85 | sys_readlink |
| 104 | sys_setitimer | 114 | sys_wait4 | 140 | sys_llseek |
| 197 | sys_fstat64 | 199 | sys_getuid (32-bit UID entry) | 248 | sys_exit_group |

**Parser audit.**

- Only 512-byte sectors are accepted. On exFAT, cluster shift 8 gives 256 sectors/128 KiB, well inside the allowed shifts. File data moves in 4 KiB chunks and uses a 64-bit byte offset. FAT32 separately caps clusters at 128 sectors. `card_read.c:53–69,132–159,166–195,369–385`.
- Both root scans stop at 256 sectors. On 128 KiB clusters that is one full root cluster, including unused or deleted directory slots. Reaching the cap with more clusters returns an error. A perfectly valid file can be unavailable in a busy root. All disable-name searches must complete successfully as well. Payload copying has a different limit of 2,048 cluster visits and 4 MiB. At 128 KiB, even 4 MiB consumes only 32 clusters. At 512 B per cluster the visit cap allows only 1 MiB. The loop has no distinct-cluster check. `card_read.c:216–272,275–334,355–395,406–415`.
- FAT32 checks LFN sequence and alias checksum, with up to five LFN slots and 8.3 fallback. exFAT assembles up to 64 UTF-16 code units; only ASCII characters survive verbatim, with ASCII case folding. This suffices for the requested ASCII names. The exFAT path accepts two FATs yet always uses the first FAT, and does not validate the directory set checksum, allocation bitmap, or uniqueness of a matched name. `card_read.c:108–117,152–185,232–266,291–325`.
- For exFAT the reader rejects ValidDataLength > DataLength but sets output length to ValidDataLength, allowing a shorter initialized prefix. The exFAT metadata and `--present` result do not authenticate a complete TAR. Require equal lengths for a release archive and agreement with the authenticated package length. The reader supports contiguous extents and FAT chains, and writes only the requested remaining bytes. It may read beyond logical EOF within an allocated cluster. `card_read.c:299–322,369–399,455–459`.
- Positive short reads on bare ARM and positive short writes loop. A negative EINTR aborts. Native close errors trigger removal of the output; abrupt termination can leave a partial file and prevent an O_EXCL retry. A stale output must never count as verified. A timer limits ordinary user-space work; it cannot promise interruption of uninterruptible block I/O. `card_read.c:53–64,341–367,395–403`.

**Host fixture result.** The unmodified host branch copied a harmless one-member, 163,840 B TAR from sparse synthetic partition images of 250,314,752 sectors. A lowercase exFAT name, 128 KiB clusters, first byte offset 5,246,943,232, and cluster sequences 40000→40001 (contiguous) and 40000→40007 (FAT chain) both produced SHA-256 `8c26d537486d3ae7ae12a93a06b3315428376f5dc15647cb6ca303624f5d8faa`, identical to the input. These were minimal parser fixtures, without a complete mountable exFAT volume. Darwin's first compile failed because the Linux-only sys/sysmacros.h is missing. The rerun used a temporary include shim containing just sys/types.h for the host major/minor definitions. It exercised host pread on a regular file. The camera kernel, device flags and SD controller were outside the test.

## 3. BusyBox and the 1 MiB RAM filesystem

**Applet evidence.** The inventory lists some links. The authoritative full list is the actual BusyBox v1.13.4 banner in `ram-runs/20261127T092451Z-f33ada4e54de-collect.json:102`:

~~~text
[, [[, ash, basename, bunzip2, bzcat, cat, chgrp, chmod, chown,
chroot, cmp, cp, cpio, cut, date, dd, dirname, dmesg, echo, egrep,
env, expr, false, fgrep, freeramdisk, ftpget, ftpput, fuser, getty,
grep, gunzip, gzip, halt, ifconfig, insmod, kill, killall, klogd,
ln, logger, login, ls, lsmod, md5sum, mkdir, mkfifo, mknod, mktemp,
modprobe, mount, mv, pidof, ping, ping6, pivot_root, poweroff,
pwd, readlink, reboot, rm, rmdir, rmmod, route, sed, sfdisk, sh,
sha1sum, sleep, sort, stty, swapoff, swapon, switch_root, sync,
syslogd, tail, tar, taskset, test, touch, true, umount, uname,
uniq, usleep, vconfig, wc, xargs, zcat
~~~

No timeout, sha256sum, printf or df applet appears. `sd_boot_ilce6400a.sh:10–14,85–89,113–117` requires the first two; its fallback is a different syntax for the same missing timeout command. The live receipt shows ash accepted `umask 077` and includes successful tests using `[ -e ... ]` and executable symlink reads (`…f33ada4e54de-collect.json:7,19–26,82,142–152`). The octal upload encoder actually uses BusyBox echo (`stage7_ram_runner.py:693`). Neither a successful standalone printf nor an ash printf builtin nor a direct `test -b` invocation is established by those receipts. `-b` conventionally tests block-special type and does not check major/minor. The captured listing directly corroborates block-special type. For process identity the live flow used /proc/PID/exe and start ticks. The daemon used /proc/PID/task/TID/comm for a thread name (`stage7_daemon.c:650–668`, BOOT record line 1). A short task name and an executable path answer different questions. The upstream process-level /comm loop is not the one demonstrated in 7.2. BusyBox tar, gunzip and zcat exist; tar's integrated -z support and ash pipeline error behavior on this build were not qualified.

**Budget inputs.** The limit is 1,048,576 B (`I:19`; `…799a2f60f946-start.json:8272–8279`). No free-block measurement or exhaustive listing of that mount at idle was found in those records. Treat Sony's concurrent use as an unknown. Count file allocation, not just payload or RSS.

| Item | Logical bytes | File allocation assuming 4 KiB pages |
|---|---:|---:|
| Seven sealed artifacts, individual files | 187,648 | 208,896 |
| Six files actually uploaded in 7.2, omitting standalone shim | 185,960 | 204,800 |
| Model TAR of seven flat regular members, default Python USTAR record padding | 194,560 | 196,608 |
| Same model TAR, gzip level 9, mtime 0 | 102,650 | 106,496 |
| daemon.log, configured maximum for a fresh session | 131,072 | 131,072 |
| run.cfg and its replacement during rename | 4,224 each | 8,192 each |
| precap.cfg and its replacement during rename | 10 or 11 each | 4,096 each |
| mod_loader.log in the successful collect | 162 | 4,096 |
| sd-boot.log | Unknown | No actual M7 Stage 7.3 file or cap |

The six uploaded paths are in `…799a2f60f946-start.json:8437–8487`. Seven is a conservative accounting choice. `stage7_v2_common.h:16–46` gives run.cfg as 16 + 12 + 60 + 512×8 + 40 = 4,224 B. The daemon's 131,072 B cap includes its stop reserve (`stage7_daemon.c:112–126,310–326`). The 337 s live run produced 31,518 B of daemon.log, 162 B of mod_loader.log and 10 B of precap.cfg (`ram-runs/20261127T092124Z-ce7b58c49934-*`, daemon.log:275). Menu logging appends, with bounded line length but no file length cap (`mlv2_sys.h:113–130`). The upstream shell redirects to a receipt at line 59. Its repeated status messages can accumulate. The bare reader allows a 4 MiB archive even though this entire mount is 1 MiB.

**Explicit scenario.** Assign 4 KiB each to menu and boot logs, retain all seven artifacts, assume the daemon log is full and one copy each of run.cfg and precap.cfg exists. File data totals **360,448 B steady**, **557,056 B with the plain archive** and **466,944 B with the compressed archive**. The respective nominal headrooms are 688,128, 491,520 and 581,632 B. Concurrent config replacements add up to 12,288 B. At plain extraction alone (artifacts + TAR only), the total is 405,504 B. Actual phases can overlap differently, particularly if the card is reread after insertion. These totals exclude other writers, reader executable if staged in RAM, verification metadata, daemon.pid, markers, guard output and any retained staging generation. The present code gives no finite application-level peak for uncapped logs. The filesystem capacity is a hard ceiling, not guaranteed available space.

**Decision.** Start the storage estimate with plain USTAR and keep the existing daemon diagnostic cap. Compression saves 90,112 allocated bytes in this example only if a full decompressed TAR is never staged alongside it. A 64 KiB daemon cap would recover 65,536 B but abbreviate evidence during long sessions. Bound both other logs and archive input/unpacked sizes, decide from measured free space, and reserve room for atomic replacements and cleanup. Streaming gzip requires independently checking decompressor completion and complete authenticated output. A successful last pipeline command alone is inadequate.

## 4. Update integrity

The upstream packager defaults to ILCE targets, emits USTAR, and writes the archive SHA-256 into a separate generated shell script (`package_mlv2_sd.py:13–19,85–109`). The M7 version file is exactly the 19 bytes `29110_03.2021050601`, without a newline (`I:705–708` and extracted version.txt). A version match is a target check, not an archive integrity check.

| Choice | Detects | Update cost and limitation |
|---|---|---|
| Digest pinned in the installed script | Any archive byte change assuming a trusted verifier | Every different release needs a new installed pin. Fails the SD-only update requirement. |
| Plain SHA-256 sidecar or embedded unkeyed manifest | Accidental corruption when the expected digest is independently intact | SD-only update. Anyone replacing the archive can also replace a plain digest. A manifest checked by code taken from the same unverified package cannot authenticate that code. |
| Owner-keyed HMAC-SHA256 over the release metadata and bytes | Unauthorized changes from parties without the key, plus corruption | Owner can prepare SD-only updates. Camera and owner must both safeguard the same secret. Readable key storage permits forgery; backup/recovery and verified access controls matter. |

**Recommendation among these three: authenticated owner releases.** Provision trust once and keep it independent of the removable package. If a reviewed public-key verifier fits the trusted component, a signature has the further advantage that the camera stores only a public verification key. Model/build, exact archive length, release format and member hashes belong in authenticated metadata. An authenticated release number identifies versions; preventing deliberate rollback requires a separate policy and trusted state. The requested zero-flash-write updates do not by themselves provide monotonic anti-rollback.

Verify the complete bounded staged bytes, bind model and exact build, and accept only an explicit set of regular files, exact sizes and hashes. Reject duplicate or unexpected members, directory traversal, links, device files, trailing payload, missing end markers and excessive expansion. Verify the bytes that will actually be consumed to avoid swapping between validation and use. Wrong model, truncated transport, absent verifier, disk full or media loss leaves the session passive. Stock-byte comparison is an independent compatibility check; running an unverified package-supplied checker to establish package trust would reverse the dependency. For a one-file SD update, authentication metadata can be part of the signed distribution rather than requiring two separately replaced names. Interrupted replacement must leave either a fully valid release or a passive boot.

## 5. Last user-selected status and frame count

**Current behavior.** `build_precap_mod.py:18,61–69` defines choices 1/2/3/5/8/10 and default index 3 (5). `core.c:299–321,325–333` initializes fresh module state and options. `core.c:463–505` retains some values across rescans of an already-known module in the same session. `core.c:763–772` renders the status and count from those in-memory fields. Initial MENU can therefore display OFF/5 even if someone separately seeds the daemon's runtime file with ON/8. Initial scanning does not itself unconditionally rewrite the file; the UI and runtime can disagree until an action writes it.

The menu status handler calls toggle (`core.c:1074–1082`); successful lifecycle callbacks use 1 for enable, 0 for disable (`core.c:904–930,934–960`). Count changes always change the displayed index but call reason 2 only while enabled (`core.c:1084–1097`). `precap_mod.c:6–40` treats reasons 1 and 2 as ON, handles partial writes and EINTR, closes, and renames a RAM temp file. On failure it attempts to remove the runtime preference. Calling reason 2 to save an OFF count would **turn it ON**. Likewise, `core.c:611–624` uses the same toggle during teardown as the user OFF action. Simply mirroring every lifecycle write to flash would **erase remembered ON during teardown**. The current helper returns void; success of the displayed toggle does not establish a durable write.

`stage7_common.h:22–45` only recognizes the exact ON grammar when producing an armed count. Its result 0 conflates valid OFF/N, missing, malformed and read failure. It cannot reconstruct a retained OFF count. The host has a strict two-field parser already (`stage7_ram_runner.py:175–178`). The reference daemon reads the RAM record unless disable/stop is present or marker checks fail (`stage7_daemon.c:730–740`). Eligibility still requires valid camera, continuous drive, supported image settings, subscription, input and no ring fault (`stage7_daemon.c:820–828`). “ON before MENU” means the requested count is available at the first sample, with normal safety gates active. The first sample of the verified 7.2 run was OFF. The sealed daemon's default duration is 600,000 ms; its duration contract also supports zero/indefinite. Copying the sealed default is not proof of all-day behavior (`stage7_daemon.c:95–126,1531–1541,1675–1680`).

| Event | Required state transition and evidence for future acceptance |
|---|---|
| Valid SD session, durable ON/8 | Validate and publish the whole runtime pair before the first daemon sample. In continuous eligible operation verify 8 before first MENU, then ON/8 on first MENU and after reopening it. Verify unchanged durable bytes during both menu opens. |
| Valid OFF/8 | First sample passive. First MENU OFF/8. Re-enabling selects 8. |
| Explicit user edit | Commit status and actual count together for every supported N and both status values. An OFF count edit keeps the runtime and durable pair OFF/N; successful saved UI state equals readback. Skip same-value durable writes. |
| Physical removal, teardown or reload | Immediately gate runtime activity on disable. Disarm runtime even if MENU never opens; retirement/acknowledgment can finish later. Preserve the durable pair and do not treat automatic disable/reload as a user edit. 7.2 demonstrated a software marker and MENU-assisted teardown, not physical hot removal. |
| RAM-only 7.2 or an unverified session | Absence of explicit, current-session permission to save preferences means RAM-only operation. Test with a pre-existing saved ON/8 and compare file bytes and metadata before and after. A leftover marker or mere existence of the preference must not grant write authority. |
| Card/package absent or disabled at cold boot | Saved settings remain inert. Verify no daemon, no guard activity, no imaging changes and stock UI independently. Literal absence of even an early custom library requires separate architectural proof (§1). |
| Missing or malformed preference | Publish OFF/5 to RAM. Ignore abandoned temporary records. Avoid writing defaults to flash on every boot. Test both truncated and trailing bytes, invalid status/count, duplicate record, EIO and empty file. |

**Smallest settings changes by responsibility.** In `stage7_common.h`, add exact parsing of a complete pair and keep the existing daemon-facing “armed count or zero” adapter. In `core.c`, initialize this specific settings module from the validated session pair at first discovery, retain the selected **index 4** for 8, and reconcile lifecycle state before rendering. An enabled flag alone is insufficient if the corresponding module has not entered its lifecycle. Keep other mods' default/rescan behavior. Capture explicit user edits at the UI boundary, including OFF count edits; automatic disable, restore and reload are separate causes. In `precap_mod.c` and the shared record writer, distinguish applying effective RAM state from saving a user preference; use exactly one writer for each published record. The existing SMNU ABI can remain if explicit edit persistence belongs to the UI and the module callback remains runtime-only. Changes to generic module format or the ring data path are unnecessary for the settings requirement. Scope the permission enabling durable writes to the authenticated SD session; RAM tests use a volatile destination. A shared path constant may belong in a header. `stage7_daemon.c` can retain the gate as written if initialization publishes the runtime pair first.

For `/setting/mlv2_precap.cfg`, use a temp on the same filesystem, full write, file sync, checked close, rename, and parent directory sync if supported. Establish what the vendor FAT returns for directory fsync; distinguish visibility after rename from surviving sudden power loss. Sync/dirsync are useful evidence of policy, not journaling. Never delete the prior durable record on a failed update. Track durable and effective state separately: OFF must disarm immediately even if flash is unavailable; an unsuccessful save must be visible to the user because the previous ON could otherwise return after reboot. A failed ON save should leave the session passive. Two separate mount points cannot be updated by one atomic rename. Ensure first MENU and boot cannot race in publishing competing defaults. The plain example grammar detects malformed data, but a bit error changing valid OFF/8 to valid ON/8 is undetectable from syntax alone. If that corruption must fail closed too, give the durable record independent integrity protection and specify compatibility with the plain example.

**Re-seal.** `build_stage7.py:84–104,699–702,996–1027` covers native sources and host sources and cross-checks the standalone module seal. `build_precap_mod.py:72–96` binds module bytes to the module and shared header. Any change to covered sources invalidates the relevant seal even if one artifact's bytes stay identical. Rebuild the standalone module seal where affected, rebuild/rederive the unified manifest, rerun the existing suites and verify the new release before calling it qualified. The old hardware PASS applies to its tested artifacts. No rebuild or release modification was performed in this research.

## 6. Verification and recovery gate

**Phase A — data and RAM evidence; no camera flash writes.** Separate the acceptance records so a card/parser failure can be diagnosed without involving the imaging process.

1. Record stock target/build, RAM mount identity/free blocks, card block identity, VBR type, sector size, cluster shift, volume length and the known host digest of a harmless test TAR on the user's SD. Read the partition as a partition. All camera-side staging and diagnostics must stay within the verified RAM mount. Even temporary shell output under /tmp would violate this phase.
2. Perform read-only card-to-RAM verification of exact size and digest on the actual controller. Exercise missing package, all card disable names, truncated data, wrong target, wrong authentication tag and insufficient RAM. Require zero accepted members and no service activity on every rejection. Observe driver latency on removal and record whether a stuck reader prevents a stock UI response. A timer slot existing is insufficient proof of recovery.
3. Exercise restored ON/8, OFF/8, malformed→OFF/5, all six counts while OFF/ON, repeated MENU opens, software teardown and physical removal using a RAM substitute for the durable preference. Capture first daemon sample before MENU, effective settings, UI observation, safe release of any in-flight capture and exact before/after preference bytes. Prove the existing RAM qualification remains isolated. Repeat an update with a distinct authorized release and unchanged trust anchor.
4. Record RAM free blocks before, during extraction, after archive removal and during a capture. Measure stock occupancy, temp files, all logs and peak, with a nonce/session identity in the receipt. Existing Stage 7.2 data already covers USB-launched operation and clean RAM removal. It cannot serve as evidence that a new card-sourced package was verified or survived a cold boot.

**Phase B — persistent-install readiness: FAIL pending independent recovery.** Before any install decision, establish an independently accessible vendor recovery route for this exact model and build, its behavior when the imaging app fails, an original-file inventory covering contents, permissions and originally absent files, and evidence that the rollback restores that baseline. A successful USB session while the stock firmware is running does not qualify rescue after a boot failure. The plan's own stop criterion is `plans/07-persistence.md:48–51`.

A future boot-verification receipt would need the detached cold-start and normal power-cycle results, valid/absent/disabled/wrong-card cases, user-visible stock shooting, service availability, update without changes to installed trust/configuration, and ON/OFF settings across power cycles. Treat the card-side disable names and a settings-volume disable marker as software controls whose effectiveness depends on reaching the code that checks them. Treat physical card removal as a test of stock behavior, not a rollback of changes on flash. Uninstall acceptance is byte/mode restoration or verified original absence for every touched file, plus stock cold boot and an accessible service after uninstall. Maintain separate evidence that the mod did not write /usr or Backup.bin; Sony's ordinary background writes need attribution.

No independently verified M7 persistent installation, pre-OS recovery procedure or complete stock-behavior receipt was identified. This report does not provide a target-specific persistent code-injection installation sequence. The safe next hardware evidence is the owner's RAM-only data test with the real card.

## Reproduction and fingerprints

Offline inspection commands from the project root (macOS, Xcode LLVM). Temporary host fixtures were discarded. No candidate archive was installed or delivered as a release.

~~~sh
p=extracted/m7-stage7-1.00-20261126T172306Z
nl -ba "$p/inventory.txt"
file "$p/sbin/init" "$p"/usr/bin/{bootin,sen,launch_shell}.elf "$p/lib/ld-2.11.2.so"
xcrun llvm-objdump -t "$p/sbin/init"
xcrun llvm-objdump -d --start-address=0x97d4 --stop-address=0x981e "$p/sbin/init"
xcrun llvm-objdump -d --triple=thumbv7-linux-gnueabi --start-address=0x215e --stop-address=0x217e "$p/lib/ld-2.11.2.so"
xcrun llvm-objdump -d --triple=armv7-linux-gnueabi --start-address=0x10d90 --stop-address=0x10da8 "$p/lib/ld-2.11.2.so"
xcrun llvm-objdump -d --triple=thumbv7-linux-gnueabi --start-address=0x95c3c --stop-address=0x95c54 "$p/lib/libc-2.11.2.so"
wc -c work/stage7-persist/ram-runs/*.{log,cfg}
shasum -a 256 "$p"/{inventory.txt,sbin/init,usr/bin/{bootin.elf,sen.elf,launch_shell.elf,change_mode.sh},lib/{ld-2.11.2.so,libc-2.11.2.so}}
~~~

For the archive model, use Python tarfile.open on BytesIO with mode w, USTAR_FORMAT, default TarInfo metadata, and members in this order: PreCapture.mod, core.bin, mlv2.req, mlv2_guard.elf, shim.bin, stage7_daemon.elf, stage7_ring.elf. Set each size from its sealed contents. The resulting 194,560 B stream has SHA-256 `7005b525e94f38ce290baa51b8af083be309a50b23395bfb6cf6f6910bb0b7af`. Gzip length above is from the local Python gzip.compress at level 9, mtime=0. For the card-reader experiment the compiler invocation was `cc -DMLV2_HOST_TEST=1 -Wall -Wextra -I "$fixture_dir" sources/bionz-x-research/tools/native_camera/mlv2/card_read.c -o "$fixture_dir/reader"`. The fixture used 512 B sectors, FAT at sector 24, 8,192 FAT sectors, heap at 8,448, root cluster 2. The sample TAR contained sample.txt with ASCII “card-reader-data” plus newline repeated 9,200 times. The host reader used MLV2_CARD_READ_IMAGE and MLV2_CARD_READ_OUT pointing exclusively to temporary host files.

| Evidence | SHA-256 |
|---|---|
| inventory.txt | 8b1752329e1f080a09432f1368eb42607d35a7ef7c74b3dd7674ef2eee3cefa6 |
| sbin/init | 0267d7b05a9250b525b95ebfd2edc04d6aef2dbd4bcabc32e15a197d41e52912 |
| usr/bin/bootin.elf | 23802d6c9ba3c41c1c0c3096ec6d1ba884ed27374e854416283547755faf4e48 |
| usr/bin/sen.elf | 524abb301d5b134e577ccac6b62e9d6a36c0c5a735ac121a8b4ef79a77c053d2 |
| usr/bin/launch_shell.elf | 21ea1ebbd488c8ce342d87290396152b1bc0ca8619708375d8ab5788ae0d4db1 |
| usr/bin/change_mode.sh | 44a2c60b43b172e988b02b94a67429e03fb22b58f2b67f477c17b9f4876a1797 |
| lib/ld-2.11.2.so | 289253ca75a446036ac947fa93ff7d2c2224ffd10293e5c6b599af490b1a348d |
| lib/libc-2.11.2.so | 246a8458ae6cfa16b4791606f9bfbae0b0339faba199cf7eeaa56a53154b4a72 |
| Original M7 kernel image | fbc91e66ce27ea917041c33c53e038bfc92e0cf8aea6f254f9dae01acefdfaeb |
| Stage 7.1 out/build.json | 2a6059cff31a7d24a03b98cbabfef212e714ec671eee004f81fc6b83d9f70dd3 |
| Upstream card_read.c | 9246011fcc481090026c2894f14564f67595a12537ad69f9a1e5e8da7f38deed |
| Stage 7.2 successful collect daemon.log | 21cd08ab002405ce9cff994a65cb6b37d453f6064e9fb8b342c40d980e609725 |
