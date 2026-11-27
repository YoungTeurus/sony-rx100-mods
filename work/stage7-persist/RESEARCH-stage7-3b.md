# Stage 7.3 Phase B — RX100M7 startup and recovery

2026-11-27 · DSC-RX100M7 1.00 · build `29110_03.2021050601` · offline research

**NO-GO for persistent Phase B implementation.** The camera receipts establish two distinct LIRO resume paths. Neither receipt observes a fresh imaging-process launch at resume. Both successful service connections had a running imaging process. There is no demonstrated route to restore a bad startup configuration if it prevents both imaging and service entry. The plan requires a documented rollback and proof on paper and in a model. A repeatable failure in an on-flash component is sufficient to withhold a GO. This is a qualification decision, not a claim that the stock camera was bricked. [Stage plan](../../plans/07-persistence.md#L39-L51) · [Phase A hardware report](REPORT-stage7-3a-hw.md#L32-L53)

## Evidence and notation

- **I** is [the M7 inventory](../../extracted/m7-stage7-1.00-20261126T172306Z/inventory.txt). **R** is [the earlier M7 runtime capture](../../extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/runtime.txt).
- **A** is [the 15:00:47 boot probe](sd-phase-a/20261127T150047Z-a5657d9d6703-boot-probe.json). **B** is [the 15:25:06 boot probe](sd-phase-a/20261127T152506Z-ae390576af24-boot-probe.json). Times are host receipt timestamps in UTC.
- **K** denotes the original M7 kernel at base `0x60108000`. Kernel addresses are ARM, little-endian. Functions take arguments in r0–r3 and return their scalar result in r0 unless specified. User ELF addresses below are linked Thumb instruction addresses unless marked ARM. Module addresses are **section-relative** offsets in relocatable objects. The camera runtime module base can vary. See [kernel identification and base validation](../../evidence/m7-kernel-analysis/analysis.json#L2-L27) and [its live-byte limitation](../../evidence/m7-kernel-analysis/analysis.json#L63).
- The additional local reads were the two already extracted M7 kernel modules to identify the resume predicates, the intervening failed probes to check chronology, and the two Phase A collect receipts to check whether a RAM marker had actually survived. The extraction filename search distinguishes the original M7 from the separate M7A 1.01 corpus. Only the report was written. No camera, USB or mounted card was accessed.

## Q1. What happened at each power transition?

| Evidence from the original receipts | A | B |
|---|---|---|
| Boot ID and uptime in seconds | `28321e77-82dc-4178-9baa-9099c7f86bbf`, 66.84 | `291d2369-ae2e-44eb-b484-e74ab8a89eff`, 591.06 |
| LIRO log | Plain resume **and** WBI message, then `635c6078(1)` | Plain resume, then `635c6078(0)` |
| Observed non-kernel processes | PID 1 launch_shell, 154 bootin, 160 BusyBox ash, 161 im, 783 BusyBox | Same first four, 1034 BusyBox |
| Start ticks for the first four | 0, 99, 103, 105 | 0, 99, 103, 105 |
| `/tmp_network` at listing | `dhcpd` and `run`, both 00:00 | Same names, both 00:09 |
| Probe cleanup | `GONE` | `GONE` |

Sources are A:970–985,1011–1013,1222,1293–1296,1345 and B:970–988,1011–1013,1291–1293,1343. Both receipts use a keyword filter and keep only the final 80 matching kernel lines (A/B:27). Neither records an execution trace. The directory listings precede the temporary probe upload in each run (A/B:20–28).

**PASS — the LIRO distinction has a precise meaning.** In `liro.ko .text+0x0e8`, the ordinary resume message is unconditional at +0x104. The driver initializes the printed flag to zero (+0xfc,+0x110). It reaches the WBI branch only when `pm_get_state() == 4` **and** `pm_is_mem_alive() == 0` (+0x114–0x128). It sets the flag to one and prints the WBI message at +0x130–0x140. At +0x24c–0x258 the callback address goes in r1 and the flag in r2 for printk. At +0x2cc it wakes a task. In `thread_resume`, +0x940–0x94c performs an indirect call through the callback slot; +0x95c signals completion. The three format strings are in `.rodata.str1.1` at +0x3, +0x2a and +0xca. Thus B rules out that specific WBI branch for the logged event. A zero by itself does not uniquely establish a particular physical switch sequence or DDR state.

**True cold boot, without snapshot restore.** K `kernel_init` at 0x60494994 reaches `prepare_namespace` on one path and `init_post` at 0x60494acc. In `init_post`, 0x60108738–0x601087b8 tries configured init paths and fallbacks. The four fallback strings are `/sbin/init`, `/etc/init`, `/bin/init`, `/bin/sh` at K 0x6044c5ad–0x6044c5cc. `run_init_process(path)` calls `kernel_execve(path, argv, envp)` at 0x601086d4; success replaces the task image. I:38 specifies an 8 MiB initrd, ram0 root and `init=/sbin/init`. The captured installed init performs module setup (0x970a), mount and root transition work (0x9724–0x977c), and the qualified launch requests below. **Gap:** the first init actually contained in the M7 initrd has not been compared with the captured installed init. The identical pair reported for another image in E0014:14,48 has a different hash from this installed M7 init.

**Kernel suspend/resume.** K `enter_state` calls `sys_sync` at 0x60167024, disables usermode helpers at 0x60167084, freezes processes at 0x60167090, enters device suspend at 0x601670cc, thaws processes at 0x601670d8 and re-enables helpers at 0x601670dc on the success path. K 0x60166e60, 0x60166ec0 and 0x60166ee8 resume the core and devices. K 0x601249e8–0x60124a2c checks the same state and memory-alive predicates as LIRO, conditionally clears a kernel log buffer and sets snapshot mode on one branch, then enters platform early resume. UPM also performs stock power-on accounting and restores power-management state (`upm.ko .text+0xfe54–0xfe98`). **PASS** for task thaw and driver resume in the binary. The core path has no required fresh exec of init, bootin or im. Re-enabled helpers, driver callbacks and thawed application threads leave later conditional execs possible. The captured kernel path is also a reason to distinguish “no research flash writes” from a guarantee that Sony's OS performs no bookkeeping during a physical transition.

**WBI and battery removal.** I:38 contains both configured snapshot paths, and I:275–281 lists their sizes as 11,280 and 9,648 bytes. The LIRO flag identifies the driver's WBI path. It does not identify the bytes that restored Linux process memory, the age of a snapshot, or whether one of these small files contains a complete Linux image. K 0x601671d0–0x601671f4 implements `ssboot_is_resumed()` as a test for one of two internal states. **Hypothesis:** restoration from a fixed baseline explains why several early tasks have identical start ticks and stack addresses at both samples while later task counters differ. A deterministic fresh startup also merits consideration. There is no direct observation of a battery removal bracketed by these two successful probes. A battery removal cuts RAM retention if all power is lost; the subsequent boot can still load a stock snapshot. No arbitrary state created after that snapshot is guaranteed to return.

**Boot ID and uptime.** The M7 kernel's `boot_id` sysctl entry at K 0x604ea0c4 has a backing pointer of 0x605165a4, mode 0444 and handler 0x60299d7c. The adjacent `uuid` entry at 0x604ea0e8 has a null data pointer. The former handler locks and tests byte 8 of its backing data, generating an ID only when that byte is zero (K 0x60299db4–0x60299ddc). Generation sets the variant bits in byte 8 (0x60299d64–0x60299d74). The latter entry generates temporary bytes for each read (0x60299d9c–0x60299db0). The probes read `boot_id` (A/B:20). The uptime handler reads the monotonic clock and converts it to boot-based time (K 0x60206bf4–0x60206bfc). The second number is cumulative CPU idle time, derived separately (K 0x60206ba8–0x60206be8).

The receipt timestamps are **1,459 s** apart. First-field uptime increased **524.22 s**. The early process identities match, but the minor-fault count of PID 154 decreased from 360 to 359, and the accumulated child user ticks of PID 161 decreased from 3 to 1 (A/B:1011–1013). These samples are poor evidence of one continuously accumulating task history. The intervening probes at [15:15:48](sd-phase-a/20261127T151548Z-c21669867329-boot-probe.json#L8-L11) and [15:17:36](sd-phase-a/20261127T151736Z-d7a9883c4277-boot-probe.json#L8-L11) failed before collecting telemetry. **INCONCLUSIVE** which transition changed the UUID. A retained, already initialized backing store should preserve it through an ordinary thaw. Restoring a snapshot with an uninitialized backing store would allow a fresh value on the next read; restoring initialized bytes could repeat an old value. Neither an unconditional UUID change on WBI nor an unconditional uptime increment of the wall-clock off interval is established.

**RAM contents, daemons and patches.** A tmpfs mount is confirmed in I:19. Pure retention and thaw are compatible with surviving files, process memory and daemons. A service can still clean or re-create its directory or stop a process. In B the parent and both child directories show 00:09 (B:973–977). Directory timestamps do not distinguish recreation, changed contents, or other timestamp updates. A removed its own probe directory (A:1345), and the intervening r5 startup failed (Phase A hardware report:45–47). In the later, separately reported power cycle, the collector saw the project directory absent. Its actual attempted config read returned status 1 with empty output, even though the receipt carries a previous value in its summary ([later collect, lines 198–201](sd-phase-a/20261127T153523Z-a900597b36e4-ram-collect.json#L198-L201), lines 450–477). The daemon had already been stopped before that cycle (Phase A hardware report:62–64). **INCONCLUSIVE** for generic tmpfs clearing, live daemon survival and preservation of patched pages across either class. A stopped daemon is not a survival test.

## Q2. Stock execution and the proposed startup surfaces

| Stock path | What the local evidence establishes |
|---|---|
| Cold init launching children | On the background branch, captured init requests bootin, conditionally sen, then net_cmdd (0x9afa, 0x9b02–0x9b06, 0x9b0c; target literals at 0x9ba4, 0x9bac, 0x9bb0). Its helper forks and calls `execv` in the child (0x8df4, 0x8e0a). A foreground branch calls `system` at 0x9af2. These are reachable launch requests, not a record of successful execs on every boot. |
| Init finishing startup | Init calls its own `launch_shell` (0x9b2e), which calls `execl` at 0x9676. If it returns, an error path includes a login-shell command (0x9b3e–0x9b44; string 0xa841). In the separate launch_shell ELF there are fork, setsid, and child execv calls at 0x89ba, 0x89d8 and 0x8a08. The observed PID 1 executable is launch_shell, and PID 160 is ash with PPID 1 (A/B:985,1012). |
| Stock ancillary commands | Conditional init paths include dosfsck via `system` at 0x8f18 and a checker probe via `popen` at 0x98b6. mkdosfs and swap_prepare.sh are reachable at 0x9a7e and 0x9a90 (literal pointers 0x9b5c, 0x9b6c). A compiled format fallback is not measured geometry. Bootin contains multiple imaging launch variants (strings 0xa32a–0xa36c) and a shell-mediated launch at 0x9830. No corresponding trace shows which helpers ran on A, on B, or during creation of the stock snapshot. |
| WBI and ordinary resume | There is no required userspace exec in the verified LIRO callback or kernel thaw sequence. There is also no event-level evidence that **any particular** userspace executable ran afresh as part of either recorded resume. The probes themselves subsequently invoked BusyBox utilities and their reader (A/B:8–28,144–150). Their observation changes the process list and cannot establish autonomous stock startup. |

**A — Sony's debug-mode setting.** The stock script documents full application boot and several debug variants, and prepares mode files even before checking arguments (`change_mode.sh:11–48,105–116`). Bootin constructs an application-specific command and submits it through a shell. Its read-only configuration reader takes an error exit on open/read failure (Thumb 0x9036–0x9054). The caller issues the application launch request and later performs conditional environment cleanup (0x9830–0x9866). The observed target is im. A command-scoped assignment supplies that invoked program and can propagate to its subsequent children. It cannot retroactively change the environment of the parent init or its separately forked service siblings. No isolated process-environment capture identifies every effective recipient. In particular, after the `system` call it conditionally passes the *bare name* `LD_PRELOAD` to libc. M7 libc `putenv` searches for '=' and calls `unsetenv` for a bare name (0x26642–0x2664e, 0x26686–0x26688). Init separately installs an **empty assignment** before handing off to its shell, *after* requesting background children (init 0x9b24–0x9b2e, literal 0xa80d). These are different operations in different processes. Clearing a parent's environment after launch cannot revoke an environment or library mapping already received by a child. **INCONCLUSIVE** for end-to-end isolation to im and for which descendants inherit the value in a real debug-mode boot. Neither receipt contains such a boot or an environment trace. No evidence that this debug mode suppresses WBI selection. Reaching an application-launch routine while booting and reaching it on each thaw are separate requirements.

**B — global dynamic-loader configuration.** Init, bootin, sen, launch_shell and im are ARM EABI dynamic executables. The M7 loader tests readability at 0x2164–0x2174, with a separate object-load error path at 0x9c6–0x9d6. I:9–10 and init 0x97d6–0x97dc establish when the flash-backed normal `/etc` is mounted on the captured init path. A newly started dynamic program sees the loader and filesystem namespace applicable to *that exec*. Init's own interpreter runs before its main can mount that volume. A restored, already mapped im image has no need to consult the loader again merely because a device resumed. Global configuration therefore has both a larger failure impact on later services and uncertain coverage of actual power-on events. The updater root and its interpreter view are unresolved. A/B:979–983 show stock mode state and absent global configuration.

**C — stock events and card handling.** K exports a uevent helper interface and event dispatcher (`m7.kallsyms:2133–2136,7428`). That interface neither names a configured helper in the receipts nor proves that an SD event executes a stock program. Sen calls a dynamic loader and symbol resolver (0xb4ec, 0xb4c8). The named network, USB and compatibility scripts are listed under read-only `/usr` (I:8,304,317,333). The initrd, snapshot and updater components have boot-wide effects (I:38,217–221,268–281). No extracted evidence identifies a stock policy that authenticates and executes the Phase A card package on a cold boot or resume. Phase A used a host-launched worker (hardware report:45–54). **INCONCLUSIVE** that no such stock mechanism exists anywhere in the firmware. Every evaluated design that relies on custom resident code retains a flash dependency when the SD is absent. Removing the card can stop optional work only after the deciding code runs; it cannot restore the original flash contents or repair a fault before that decision.

**Cross-model evidence.** E0681:7,23–32 identifies the target as ILCE-6400A 1.01, describes two QEMU boots and explicitly leaves physical installation pending. The no-card guest still mapped the custom library while displaying a stock six-tab menu. The upstream worker expects its own tmpfs (`sd_boot_ilce6400a.sh:7–25`). E0411:3–6,22–32,68–81 examined one cold-boot Wi-Fi condition with a second resident component still active. Neither source demonstrates hardware WBI coverage or rescue from a loader hang on the M7. E0014:14–17 and E0025:3–8 document startup on other inputs; E0342:3–10 is a mode-dependent peripheral experiment; E0306:11–34 concerns another storage capture; E0043:5–12 recovers a packaged WBI image; E0073:3–11 identifies an ILCE-6400 2.00. None supplies the missing M7 event trace.

## Q3. Recovery under a failed startup

**USB — working-camera PASS, independent recovery INCONCLUSIVE.** Conditional sen startup and shell creation are separate branches of init. The proposed linear dependency “sen starts launch_shell” is therefore incorrect for the branch above. R:79–84 shows the gadget and UPM modules loaded. R:109–111,243–245 places `libsencore.so` inside the imaging process's address space; it exports separate normal-mode and USB-mode entry functions (Thumb 0xf428 and 0xf3f8). A/B:900–904 show successful service authentication and shells, with im alive at A/B:1013. B:1308–1311 shows console enablement on opening the line discipline. A resident PID 1 or an ash with PPID 1 establishes neither host enumeration nor service authentication. Missing proof concerns a **new connection from a disconnected host** after im fails, including USB mode selection, handshake and access to the affected filesystem. An already open shell cannot establish that result.

**Updater — stock artifacts PASS, independent entry and rollback INCONCLUSIVE.** M7 init's `check_bootmode` opens and reads `/proc/udm/upm_bootmode` and compares the prefixes USB_CHARGE, ADJUST and BIS (0x927e, 0x92a6, 0x92b2–0x92d6, literal pointers 0x92f8–0x9318). I:67–68 recorded NORM. M7 `up.sh:14–31,231–253,294–299` changes and syncs persistent mode files and conditionally invokes an LSI utility. It presupposes running userland. Its version and region operations can also change data, as the actual script shows at lines 128–145,187–215. The local updater libraries expose user-space routines (`libupdaterufp.so` 0x19fc, `libupdatertalk.so` 0x624,0x64c). Finding these routines proves neither a bootloader button chord nor an independent recovery environment. There was no literal `/setting/updater` match in the raw K image. Indirection, constructed paths and other boot components remain possible. The `/system/initrd.img` listed in I:270 is not itself proof of a separately selectable updater image.

E0138:15–34 depends on pre-existing custom startup and describes restoring another unit's Backup.bin. Its verification covers the prepared card and host suite. It fails both the independence test and this project's zero-Backup.bin-write requirement. E0666:3–8 describes an ILCE-6400 2.00 experiment, and E0668:199–207,243–247 documents limitations on the ILCE-6400A. Neither establishes a working M7 recovery transport, a signed compatible repair image, or the ability to selectively restore these files without changing other state. The existing M7 stock-recovery assessment also identifies a gap in per-unit recovery coverage (recovery-codex.md:9–24).

**Watchdog and WBI fallback.** I:38 records `wdt.timeout=500`, `wdt.mode=1`, `exception.reboot=1`, `warm.mode=2`, `warm.tmo=100000`, `warm.resume_drop=0`, `warm.ignore_drop=1`. K `watchdog_tick` conditionally calls `cpu_wdt_restart` at 0x60120514. The interrupt handler logs status, conditionally calls a function pointer and can take a BUG path (0x6012044c–0x60120498). The ordinary `wbi_drop` reads the variable registered as `warm.ignore_drop` and returns zero without doing the drop when it is nonzero (0x6011c0f8–0x6011c114, parameter descriptor 0x60491a38). The stock UPM routine named `upm_senser_wbi_drop` itself calls `wbi_drop` (UPM .text+0x10200). Its name alone cannot establish that a USB session discarded the snapshot. The separate `wbi_resume_drop` checks mode and the `warm.resume_drop` variable before calling the internal drop function (0x6011c128–0x6011c144, descriptor 0x60491a58). `wbi_is_timeout` checks a platform cycle counter against stored state (0x6011c41c–0x6011c430); the warm timeout parameter is registered at 0x60491a78. These values give no proven wall-clock deadline for a hung application. **FAIL as a rollback mechanism:** even a successful reset leaves a bad persistent input in place. No captured watchdog path restores a verified original or guarantees progress past that input.

| Failure | Can a marker, attempt counter or immediate fork protect the next boot? |
|---|---|
| Absent or rejected library | The loader can skip unreadable configuration and report certain rejected objects. Recovery depends on the precise failure path. No custom marker code executes in a library that never loads. Loader 0x2164–0x2174, 0x9c6–0x9d6. |
| Malformed object that faults during loading, relocation or early initialization | A check embedded in that object may never execute. The stock loader's handled-error branch is insufficient evidence for arbitrary corruption. Same loader sites and Phase 7.3 research:24,28–32. |
| Constructor faults or loops before it returns | A check or fork later in the constructor cannot protect its caller from an earlier fault. A child can isolate later work only after the parent successfully returns. The upstream library also starts as a constructor (`sd_boot_hook.c:39`). |
| Repeated attempt, card absent or failed card read | A durable counter can influence a later attempt only if its reader runs and its update survives. Incrementing it on flash introduces writes; mounting the state incorrectly or losing power introduces additional failure cases (Q4). A removable disable marker likewise depends on reaching a working reader. |
| im crashes or hangs after the launcher returns | Child isolation does not restore imaging service, undo previously executed changes, or establish cold USB access. Healthy-im receipts are the only service evidence (A/B:900–904,1013). |

**Decision.** Raw syscalls reduce dependencies after control reaches valid code. A hook's own code cannot provide independent recovery from its earliest failure. No independently bootable recovery model was available or exercised for this report.

## Q4. What writable VFAT actually supports

| Property | Finding from original M7 kernel code |
|---|---|
| Mounts and aliases | I:7–19 records ext2 read-only for `/` and `/usr`, VFAT `rw,sync,dirsync,...,posix_attr` on both `/setting` and `/etc`, and no listed `noexec`. `/tmp` is another mount of the same device as `/etc`; `/tmp_network` is tmpfs. I:224–259 shows matching /etc and /tmp filenames and sizes. |
| Creation and chmod | **Static PASS under normal VFS permissions.** K `fat_show_options` ties private byte 0x66 bit 0x40 to the printed `posix_attr` option (0x60222ae4–0x60222b00). `vfat_create(dir,dentry,mode,...)` preserves r2, then on this option clears 0xe00 from the requested mode, stores the resulting halfword into the new inode and marks it dirty (0x602274e0, 0x602275a4–0x602275cc). Both file and directory inode operation tables select `fat_setattr` at +0x3c. For `ATTR_MODE` it rejects special mode bits on the POSIX branch, takes the POSIX branch around the generic FAT mode restrictions, and calls `setattr_copy` and `__mark_inode_dirty` (0x60221d5c–0x60221dbc, 0x60221ea0–0x60221eb0, 0x60221f60–0x60221f74). Mode 0755 passes these bit tests. The vendor symbols are **get_vfat_posix_attr** and **set_vfat_posix_attr**. Table 0x603da420 points at the setter and getter at +4/+8. The setter reads inode permission bits and encodes directory-entry fields (0x60225acc–0x60225be4), and the getter restores inode mode on its decode paths (0x60225844–0x60225a68). No new on-camera file was created or chmodded. |
| Executable files and executable mappings | **Static support, hardware INCONCLUSIVE.** `open_exec` opens the path, checks for a regular inode, checks mount bit 4 and rejects a disallowed case with -EACCES (0x601c4168–0x601c419c, 0x601c41e0). Both regular FAT operation tables point at `generic_file_mmap` at +0x28 (0x603d9e5c and 0x603d9df4). The mmap path checks readability, the mount noexec bit and executable VM flag, then checks the file callback (0x6019f420–0x6019f45c) and reaches a policy check at 0x6019f494. The generic mapping installs VM ops on success (0x6017bd20–0x6017bd38). These mounts and file operations support executing an otherwise eligible ELF and mapping eligible file data executable. File type, mode where applicable, mapping permissions, interpreter availability and other VFS checks still matter. There is no M7 receipt for either operation on a newly created internal file. |
| File **and directory** fsync | **Static PASS for both callbacks.** File table word 0x603d9e6c, alternate file table word 0x603d9e04, and directory table word 0x603d9d58 all contain **0x602217ec**. In `vfs_fsync_range`, +0x38 is the callback slot. A null slot would give -EINVAL; these slots are populated (0x601e3cb0–0x601e3ccc, 0x601e3cf0–0x601e3d24). The VFS returns a prior writeback error first, otherwise the callback result. `fat_file_fsync(file,datasync)` tests private byte 0x68 bit 0x20 (the printed `batch_sync` option, K 0x60222a08–0x60222a24). I:10,12 lack that option. On the ordinary branch it calls `generic_file_fsync` then `sync_mapping_buffers`, returning the first error if nonzero, otherwise the second result (0x60221830–0x60221854). Thus **0 on success or a negative error**, including for a valid directory fd. No unconditional “directories return EINVAL,” and no measured on-camera return code. |
| Rename and power loss | `vfat_dir_inode_operations+0x34` = `vfat_rename`. Its code locks the superblock and performs separate entry/inode/buffer operations with error exits (K 0x60226e28, 0x60226f00, 0x60226f50, 0x60227098, 0x60227140, 0x60227224, 0x6022735c). Namespace serialization and success from file/directory fsync establish useful semantics. They do not demonstrate old-or-new contents after power is lost between physical metadata writes. A disposable filesystem image is needed to test that property for the proposed config replacement. |
| Capacity and allocation | I:42–52 gives partition capacity of **20,480 KiB** (20 MiB) for setting and **12,288 KiB** (12 MiB) for etc. R:106 reports the stock `df` command failed. The 16,384-byte directories (I:213–219,225–229) suggest 16 KiB allocation units, **hypothesis only**. The 128 KiB exFAT clusters and 4 KiB tmpfs blocks in B:1313–1333 concern different filesystems. K `fat_statfs(dentry,buf)` checks its cached count or calls `fat_count_free_clusters` and propagates errors at 0x60222c58–0x60222c78. It reports allocation size and free/available units at 0x60222c90–0x60222cc0. **Exact free bytes and cluster sizes for these two internal mounts remain unmeasured.** A tiny nonempty preference and its temporary replacement can each occupy an entire allocation unit while both exist. |

## Q5. Options, rollback and the next read-only evidence

Ranks reflect ability to meet the product and recovery requirements, not recommendations to install. No option below has a measured Phase B startup latency.

| Rank and option | Cold boot / WBI / retained S2R | Internal files and SD-absent behavior | Independent recovery and uninstall |
|---|---|---|---|
| 1. Stock decision on removable content, if one exists | Needs a qualifying stock decision on each required lifecycle. Card detection alone is insufficient (A:1309; B:1307). | No new flash files in the purely card-based variant. With the card absent there is no custom code source. A separate internal saved preference would change this footprint. | Best fit for stock behavior, **INCONCLUSIVE existence**. No internal changes to undo in the purely removable variant. |
| 2. Sony application debug startup | Adds work when the application launch path actually runs. No proven trigger on either resume. | Requested mode/preload configuration under `/setting/mode`, a resident object and any on-flash preference. A/B:979–983 show the initial directory state. Startup configuration remains active with SD absent. | **NO-GO.** Usable USB after imaging failure remains unproved. File-level reversal requires restoring absence for newly created entries and original bytes and attributes for any pre-existing entries. |
| 3. Global loader startup | Adds per-exec work to dynamic programs while the file is visible. An already restored process can bypass it. | Global configuration under `/etc`, resident object, and any on-flash preference. It affects services even without the card available for a later decision. | **NO-GO.** The normal recovery userspace can share the failing loader. Restore captured original content/metadata or original absence. A/B:983 recorded absence. |
| 4. Stock service/event or updater configuration | No demonstrated stock post-resume package dispatch. Latency and ownership unknown. | No qualified file set. The named scripts are on read-only `/usr`; updater flags touch persistent mode state (`up.sh:14–31,231–245`). | **NO-GO.** An exact uninstall cannot be specified without identifying the active stock consumer and all its writes. |
| 5. Change snapshot, initrd or system image | Changes early boot components shared by potential recovery paths. | Would alter existing `/system` content (I:268–281). Removing SD would leave the change installed. | **NO-GO.** Highest consequence of corruption. No matching complete independently restorable preimage or verified early recovery route in this evidence. |
| Reference only. Phase A RAM worker | Demonstrated after explicit launch on a running M7. No untethered cold-start qualification. | No research changes to internal flash in the Phase A receipts (A/B:5–6). Card and RAM behavior are documented in the hardware report:45–64. | **PASS for the tested RAM workflow only.** Its clean removal is a different test from recovering an unbootable camera. |

**Byte-for-byte uninstall is currently unqualified for every flash design.** A file manifest can verify file bytes, modes, paths and original absence. Deleting a VFAT entry can also leave changes to directory slots, timestamps, FAT allocation and free-space bookkeeping. A file hash does not cover those bytes. The plan calls for a changed-byte-range manifest (lines 39–46). A partition image of one unit also includes unrelated mutable data, including `Backup.bin` on the setting volume (I:179–187). Replaying an old entire setting partition could overwrite later stock/user state and violates the stated prohibition on writing Backup.bin. A valid model needs to distinguish changed project bytes from concurrent stock state before it can claim exact restoration. Exact installer filenames, byte ranges and preimages for a never-built candidate are undefined.

### Smallest next observations

1. **First establish which physical transition retains RAM.** Bracket one ordinary switch-off/on while the battery stays installed, then separately bracket an owner-observed complete power loss and the next startup. Record host timestamps, power and USB sequence, full unfiltered kernel log, boot ID, uptime, mount identity, process start ticks and cumulative counters immediately on both sides. Use an already existing, distinctive stock RAM object if one is available; distinguish inode identity, contents and mtime. Take two same-session control samples first. Reconnecting USB itself starts service activity (B:1308–1311). Strictly observational data can falsify continuity, but cannot positively demonstrate survival of an *arbitrary* daemon or patched page if no such object was present before. Do not repurpose the cleanup-enabled Phase A probe as a retention marker (A:1345). A battery restart must still be classified from the log; it is not automatically a snapshot-free cold boot.
2. **Read the missing exact-build inputs.** Priority is the M7 normal initrd (I:270), the independently selected updater boot files **if identifiable**, and matching original service gadget code (I:431–435). Preserve normal and updater roots as distinct evidence. The two small sabin files (I:275–281) and a read-only boot-selection/snapshot descriptor or header would establish what is loaded from where. Inspect early stock selectors and their dependency on both writable volumes. **Already local:** the matching-size 65,276-byte liro and 144,476-byte upm modules (I:372,421), both analyzed above. No second camera extraction of them is needed. A related M7A image does not qualify as M7 1.00 evidence.
3. **Measure the two filesystems directly.** A read-only statfs of each mounted path with its device ID, block size, free units and available units gives the missing capacity data. A read-only FAT boot-sector geometry cross-check can confirm allocation size. A single volume exposed at two mountpoints must be counted once. Geometry and free space do not demonstrate rollback.
4. **Close the recovery gate in a disposable offline model.** Start from an identified early M7 boot root and stock selection path. Model missing, loader-rejected, post-load faulting and indefinitely blocked startup, plus a nonfunctional imaging process. Require independently reachable recovery with the card absent, a verified restore, a normal boot, preservation of per-unit state, and before/after byte and metadata comparisons. The model also needs filesystem power-loss cases. Observing a healthy live camera, reading files, or unplugging USB cannot on its own prove recovery from those failures. No live fault induction is needed to collect the missing inputs.

## Reproduction and input integrity

Run from the project root in zsh. These commands read host files. The receipt query restricts output to telemetry and omits the transport/upload command bodies.

~~~sh
p=extracted/m7-stage7-1.00-20261126T172306Z
r=extracted/m7-1.00-29110_03.2021050601-20261104T212913Z
k=extracted/m7-kernel-file-20261105T210321Z-78319ef81a60/system/vmlinux.bin
lr=extracted/m7-kernel-20261104T223751Z/usr/kmod/liro.ko
up=extracted/m7-upm-20261106T003324Z-c92febc9b830/usr/kmod/upm.ko
for f in work/stage7-persist/sd-phase-a/{20261127T150047Z,20261127T152506Z}-*boot-probe.json; do
  jq '{utc,boot_id,uptime,tmp_network_ls,probe_dir_cleanup,users:[.processes_raw[]|select(test("[|]/(usr/)?bin/"))],resume:[.dmesg_boot_lines[]|select(test("LIRO|resume of devices|console \\[usbgcon"))]}' "$f"
done
nl -ba "$p/inventory.txt" | sed -n '4,68p;179,281p;284,333p;370,373p;419,435p'
nl -ba "$p/usr/bin/up.sh" | sed -n '14,31p;128,145p;187,215p;231,253p;294,299p'
file "$p/sbin/init" "$p"/usr/bin/*.elf "$r/usr/bin/im.elf"
xcrun llvm-objdump -d "$p/sbin/init"
xcrun llvm-objdump -dr -j .text --start-address=0xe8 --stop-address=0x360 "$lr"
xcrun llvm-objdump -dr -j .text --start-address=0x924 --stop-address=0x974 "$lr"
xcrun llvm-objdump -s -j .rodata.str1.1 "$lr"
xcrun llvm-objdump -dr -j .text --start-address=0xfe48 --stop-address=0xfea4 "$up"
xcrun llvm-objdump -d --triple=thumbv7-linux-gnueabi --start-address=0x9830 --stop-address=0x9874 "$p/usr/bin/bootin.elf"
xcrun llvm-objdump -d --triple=thumbv7-linux-gnueabi --start-address=0x26640 --stop-address=0x26690 "$p/lib/libc-2.11.2.so"
xcrun llvm-objdump -d --triple=thumbv7-linux-gnueabi --start-address=0x89ba --stop-address=0x8a10 "$p/usr/bin/launch_shell.elf"
xcrun llvm-objdump -d --triple=thumbv7-linux-gnueabi --start-address=0x215e --stop-address=0x2176 "$p/lib/ld-2.11.2.so"
rg --files --hidden --no-ignore extracted | rg '/(initrd.img|liro.ko|upm.ko|usbg_sen.ko|ssboot(_any)?.bin)$'
~~~

The following local decoder prints kernel instructions, resolves direct branch targets using the supplied symbol map, and reads the original table words. The end of a symbol may contain a literal pool; interpret PC-relative constants as data. Module instruction references require the relocation-aware objdump commands above.

~~~python
# Run with ./.venv-analysis/bin/python -B - and supply this block on stdin.
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
import json

meta = json.loads(Path("evidence/m7-kernel-analysis/analysis.json").read_text())
raw = Path(meta["kernel"]["path"]).read_bytes()
base = meta["base_address"]
symbols = {}
for line in Path(meta["kallsyms"]["path"]).read_text().splitlines():
    addr, kind, name = line.split(maxsplit=2)
    symbols[name] = int(addr, 16)
names = {addr: name for name, addr in symbols.items()}
boundaries = sorted(names)
decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
for name in ("run_init_process", "init_post", "kernel_init", "enter_state",
             "suspend_devices_and_enter", "cxd900x0_pm_enter", "ssboot_is_resumed",
             "proc_do_uuid", "generate_random_uuid", "uptime_proc_show",
             "watchdog_tick", "wdt_intr", "wbi_drop", "wbi_resume_drop", "wbi_is_timeout",
             "fat_show_options", "vfat_create", "fat_setattr", "get_vfat_posix_attr",
             "set_vfat_posix_attr", "fat_file_fsync", "vfs_fsync_range", "fat_statfs",
             "open_exec", "do_mmap_pgoff", "generic_file_mmap", "vfat_rename"):
    start = symbols[name]
    end = next(a for a in boundaries if a > start)
    for ins in decoder.disasm(raw[start-base:end-base], start):
        op = ins.op_str
        target = int(op[1:], 16) if op.startswith("#0x") else 0
        print(name, hex(ins.address), ins.mnemonic, op, names.get(target, ""))
for addr in (0x603d9d58, 0x603d9e04, 0x603d9e6c, 0x603d9df4, 0x603d9e5c,
             0x603d9edc, 0x603da37c, 0x603da374, 0x603da424, 0x603da428,
             0x604ea0c4, 0x604ea0c8, 0x604ea0dc, 0x604ea0e8, 0x604ea0ec):
    word, = struct.unpack_from("<I", raw, addr-base)
    print(hex(addr), hex(word), names.get(word, ""))
~~~

SHA-256 below covers the local input bytes, including reference-only binaries. A hash verifies identity of a copy; behavioral findings above distinguish executed camera observations from static paths. Recompute with `shasum -a 256` on each path. Prefixes p, r, k, lr and up expand as in the shell block.

| Local input | SHA-256 |
|---|---|
| `p/inventory.txt` | `8b1752329e1f080a09432f1368eb42607d35a7ef7c74b3dd7674ef2eee3cefa6` |
| `p/sbin/init` | `0267d7b05a9250b525b95ebfd2edc04d6aef2dbd4bcabc32e15a197d41e52912` |
| `p/usr/bin/bootin.elf` | `23802d6c9ba3c41c1c0c3096ec6d1ba884ed27374e854416283547755faf4e48` |
| `p/usr/bin/sen.elf` | `524abb301d5b134e577ccac6b62e9d6a36c0c5a735ac121a8b4ef79a77c053d2` |
| `p/usr/bin/launch_shell.elf` | `21ea1ebbd488c8ce342d87290396152b1bc0ca8619708375d8ab5788ae0d4db1` |
| `p/usr/bin/bk.elf` | `f97ef56e064d3d21a69f1f5ce95b3d7d1f0b22ef19aa0fc86878465a6fae867f` |
| `p/usr/bin/up.sh` | `03a70fd0d0ef269c0de9530398d1e4d7cd8fcb089286cff682ee32d097ad16bd` |
| `p/usr/bin/change_mode.sh` | `44a2c60b43b172e988b02b94a67429e03fb22b58f2b67f477c17b9f4876a1797` |
| `p/lib/ld-2.11.2.so` | `289253ca75a446036ac947fa93ff7d2c2224ffd10293e5c6b599af490b1a348d` |
| `p/lib/libc-2.11.2.so` | `246a8458ae6cfa16b4791606f9bfbae0b0339faba199cf7eeaa56a53154b4a72` |
| `p/usr/lib/libupdatertalk.so` | `1e36b989214aafb0a426a45ee06a578d17814926226e3d39307a0124fdf90587` |
| `p/usr/lib/libupdaterufp.so` | `fbb87b03409e180c7aceebdc6d2a22511932e9305201e4e6da99585b8a6fc60b` |
| `p/usr/lib/libInfraFsys.so` | `04b0e2a37e9c70802352a4ed4103808d17033ed00dd485c3d1fe298f23310131` |
| `r/runtime.txt` | `7f1c82e5d91e3b292e0e8dd0901c17946efe43e698338febd1789058f9499016` |
| `r/usr/bin/im.elf` | `ad08a5b12fa344ba595f56c8c9ce12263be4673d15deede1b67f4434309e105a` |
| `r/usr/lib/libsencore.so` | `d79365e3a168bffcad68bf8cce24bfa62be1de2e0d7ed062470632a0af9f1279` |
| `k` | `fbc91e66ce27ea917041c33c53e038bfc92e0cf8aea6f254f9dae01acefdfaeb` |
| `lr` | `6b276cd909d4d3ad35dc99303148bdc4591d1e885c1f767e301b007646bbe005` |
| `up` | `ab7762e8e5340accde9c28e5e8b997ddd68b404f541dc1a72d356bd0362a0e77` |
| `evidence/m7-kernel-analysis/m7.kallsyms` | `d4c990382c1071631863944ee8f09612e78542746d35b0ebe894d7d2bfcb546b` |
| `evidence/m7-kernel-analysis/analysis.json` | `9a93127c8e4e4e8c76e4e63d5edd9ecace561a9ddb4958ef381941bf27405ece` |
| `20261127T150047Z-a5657d9d6703-boot-probe.json` | `620cd5392bc0973a708ded5a5b9ee7f88eec5c99aa198b79608523e16c6807b0` |
| `20261127T152506Z-ae390576af24-boot-probe.json` | `8c40811f54fb811e6a74dcb686b646678790c520ddf173ca3d5d39a3f2b2550a` |
