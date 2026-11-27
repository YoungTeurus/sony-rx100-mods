# Stage 7.3 Phase B — recovery and power-transition evidence

2026-11-27 · DSC-RX100M7 1.00, build 29110_03.2021050601 · offline research

**NO-GO for a Phase B flash write.** The exact M7 implements the FileControl filesystem operations in the service process. A responding service can operate without launching ash for the operation. The missing link is between an intact WBI image and a responding, authenticated service under the proposed failure. There is also a concrete conflict with the proposed B5 test. Sony's service can rewrite an existing file on internal flash during authentication and during FileControl **read**. Selecting a RAM destination does not remove that side effect.

## Evidence and scope

M denotes extracted/m7-1.00-29110_03.2021050601-20261104T212913Z, P denotes extracted/m7-stage7-1.00-20261126T172306Z, D denotes extracted/m7-stage7-phaseb-1.00-20261127T184903Z. C denotes the **M7A 1.01** comparator directory extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked. VAs below are ELF-relative except for the executable. Thumb entry addresses omit the low state bit. r0–r3 are the first four ARM EABI argument registers. Local names for stripped loader functions describe their observed roles.

I read the assigned stage documents, the named captures, PMCA host implementation, Phase A source and its included path definitions. I also checked P/usr/bin/up.sh for ownership of /tmp_updater and the Phase A path consumers outside the four named files to assess completeness. Binary findings below come from the host copies. The earlier hardware observations are attributed to the archived captures. No camera or target executable was run for this report.

## 1. M7 1.00 USB FileControl and the recovery boundary

**PASS for the ordinary filesystem operation once dispatched.** M/runtime.txt:109–118,243–245,893–931 identifies PID 161 as im.elf, shows the loader and libsencore.so mapped, and records effective UID 0. im.elf's DT_NEEDED includes libdl and libIMDB, with no direct dependency entry for libsencore. A live mapping establishes residency in that sample. It does not identify how a new session after restore reaches the library.

| Operation | M/usr/lib/libsencore.so, exact call chain |
|---|---|
| Dispatch | FileControl at 0x14d08 decodes its header, tests the operation at 0x14d30–0x14d42. For read/delete, 0x14e28–0x14e44 constructs a DispatchCommand. PC-relative callback words at 0x14e78 and 0x14e7c resolve to Thumb pointers 0x136d5 and 0x13049. DispatchCommand::DoExecute calls its stored callback at 0x1234e. Disassembler labels on the unnamed callbacks can inherit the preceding exported symbol. |
| Read | Callback 0x136d4 obtains the path and calls access at 0x136ec. At 0x13754 it constructs ReadDeviceData. Its constructor calls DeviceIo at 0x126f0, then DeviceIo::read at 0x12724. Advance calls read again at 0x12286. DeviceIo's pathname constructor calls open at 0xf610. DeviceIo::open calls libc open at 0x18782 and DeviceIo::read calls libc read at 0x1854c. |
| Write | At 0x14d46–0x14d82 the handler obtains and terminates the pathname. At 0x14dfe–0x14e0a it passes the pathname, flags 0x1241 and chunk capacity 0x8000 to WriteDeviceData. Its constructor calls DeviceIo at 0x127fa. Advance calls DeviceIo::write at 0x121fa, which calls libc write at 0x18574. The flags include truncation. Replacing an existing file this way provides no atomic replacement guarantee if USB drops or storage fills. |
| Delete | Callback 0x13048 obtains the path through the packet object, checks access(path, F_OK) at 0x1305e, then calls unlink(path) at 0x1306a. An access result of −1 jumps to the same return value 1 used after successful deletion, bypassing unlink. Unlink failure takes the 0x82 return at 0x13086. After successful unlink the path calls sync at 0x130c8. A success response alone cannot certify that the named file existed, was accessible, or was removed. |

The host corroborates the distinction. sources/sony-pmca-re/pmca/usb/sony.py:944–956,976–978,997–1023 sends file requests directly. pmca/platform/backend/senser.py:9–23 enables a terminal only on the interactive-shell path. On the camera, normal execution of the filesystem leaves above has no intervening shell or interpreter startup. libc PLT resolution in a running process can involve the already-mapped dynamic linker. That is distinct from starting an ELF interpreter and reparsing its system preload list.

**PASS for an authentication thread; INCONCLUSIVE for every dependency from fresh USB connection to reply.** The host sends a vendor request and performs a separate authentication exchange. Its start method catches a transport exception, so returning from start alone establishes little (sony.py:900–940). At the camera application layer, senser_usb_mode_start and senser_normal_mode_start enter the service start path (0xf3f8, 0xf428). SenserIfStart obtains the USB singleton at 0x116a0. Usb::start_service opens its channel and registers its dispatcher at 0x113b2 and 0x113c0. Usb::start performs indirect calls at 0x10ef0 and 0x10f0e. WorkerThreadManager::start_authentication at 0x10c8c retrieves NinThread via the relocation at 0x5d6b4, selecting worker slot zero. run_worker calls Thread::create at 0x10c0a, which invokes pthread_create at 0x18862. NinThread (0x105b4) has indirect transport/service calls, including 0x1061a, 0x10674 and 0x1082e. The worker code even has an abort branch at 0x10bee when its worker slot is already created. These binaries establish an in-process architecture for that portion. They do not prove every gadget event, callback recipient and prerequisite is responsive on the specific WBI path. The earlier M7 analysis distinguishes normal imaging service from the conditional startup of a separate sen.elf (RESEARCH-stage7-3b-boot-recovery.md, “Recovery with imaging unavailable”).

**PASS for a conditional internal flash-write path.** The static proof covers the following three links.

1. NinThread calls tlog_file_exist at 0x10830 and can call tlog_update_file at 0x10846. FileControl has the same pattern for a read (0x13704, 0x1373e), write (0x14d84, 0x14de8) and successful delete (0x1308a, 0x130c4).
2. tlog_file_exist at 0x16a18 opens the literal /setting/.etools in mode r at 0x16a24. If the existing log can be read and processed, tlog_update_file calls its writer at 0x16ee6. The update also calls helpers that send synchronous OSAL messages (0x16b74, 0x16aba and 0x16b22). The complete request can therefore depend on other responsive components even after dispatch.
3. tlog_write_file opens /setting/.etools in mode wb at 0x16cae. It passes the buffer, item size 0x1000, count one and FILE pointer to fwrite at 0x16cc0. P/inventory.txt:183 and D/inventory.txt:102 both list a 4,096-byte .etools. D/inventory.txt:12 puts /setting on internal VFAT. This proves a possible stock write in precisely the proposed test conditions. Neither inventory is an I/O trace of a particular request.

**Recovery verdict.** Under the narrower assumption “authentication has completed, dispatcher and logging dependencies progress, and the filesystem remains writable,” the M7 code supports shell-free file repair. Changing a preload list on disk does not retroactively start an interpreter in the restored imaging process. Under the actual assumption “the WBI bytes are intact and im.elf resumes,” service readiness, filesystem health and completion of repair remain open. A hung imaging event loop, synchronous service call, unavailable mount or unhealthy storage defeats this argument. A missing preload *target* is also a substantially weaker fault than an object that maps and hangs during initialization. No exact-build failed-state recovery receipt was found in the assigned evidence.

## 2. Stock Bluetooth and other post-wake activity

**M7A comparator.** C/lib/libInfraBluetoothCore.so's startBcmBsaServerCommon constructs the temporary-directory object at 0xd134, and calls BTUtils_::CProcess::startProcessViaIM at 0xd20c. The utility's CTmpDir constructor calls mountPartition at 0x2a74. Its mount and UnMountPartition routines call libc at 0x29ec and 0x2aa2 in **C/lib/libBTUtils.so**. The normal start request seen here goes through an OSAL message in startProcessViaIM, whose return and message result are checked at 0x2b44–0x2b70. The utility also contains a shell-launch string, and C/lib/libIMDB.so contains the script pathname. Those strings alone do not identify the recipient's actual exec call. The script itself starts the server in the background on each of its four branches (C/bin/startBTCore.sh:3–24).

The comparator suspend handler contains conditional start, stop and wake-on-Bluetooth paths, including a timed message receive and suspend-complete call. The resume handler also conditionally requests a start (C/lib/libInfraBluetooth.so, jobSuspend 0xf4e8–0xf7bf, jobResume 0xf7c0–0xf8ef). There is no unconditional shell restart established by those two handlers. Neither a menu flag nor the existence of an unmount method establishes which path a particular M7 took. On the comparator stock stop path, stopBcmBsaServer calls the CTmpDir destructor at 0xd4f6. The destructor at 0x294a–0x296e in libBTUtils.so disposes its logger and string without calling UnMountPartition. A search for the exported UnMountPartition name across C/bin and C/lib returned only the defining library. The stop call therefore supplies no evidence of an S2R unmount; other paths and mount-namespace changes remain possible. Stock BT ownership makes /tmp_bt unsuitable as a private workspace regardless.

**Server exit and delay.** The comparator script loops at lines 26–47 with no explicit timeout or sleep. It breaks on a nonempty PID file passing its grep filter. A server that exits before satisfying the test can leave the script polling indefinitely. An exit after that check is a different case. A PID file is no evidence that the radio handshake or socket is ready. The imaging-side comparator client independently calls waitPidFile at 0xd224 and waitDaemonFile at 0xd27a. Each calls the stat wrapper at 0x1e7f8, then usleep, then repeats on a nonzero saved stat result. The sleeps are 30,000 µs (0xcd54–0xcd64) and 100,000 µs (0xce28–0xce36, literal at 0xce44), including a sleep after a successful stat. Neither loop has a retry limit. A PID file can exist while empty because the shell redirects pidof output before validating it. If the socket never appears the calling thread can wait indefinitely. A 5 ms delay can be hidden within one polling interval or can cross its sampling boundary and add another interval. The binary supplies no end-to-end timing bound for im.elf and no proof that all imaging threads block or terminate. There is no M7 measurement of exit handling, standby completion, shutter readiness or the effect of a 5 ms delay.

**M7 1.00 cross-check.** M/runtime.txt maps libIMDB.so (122–124), libBTUtils.so (329–331), libInfraBluetooth.so (368–370), libInfraBluetoothCore.so (389–391), libInfraBluetoothLowEnergy.so (586–588), libInfraNetInitializer.so (371–373) and libInfraIPsec.so (459–461). P/inventory.txt:292,298,323 lists WS_SubProcess.elf, bsa_server and startBTCore.sh. The script length matches the comparator's 1,283 bytes. The M7 bsa_server is 4,802,499 bytes, the M7A copy **5,390,567**. They cannot be byte-identical. A standalone server's executable would normally appear in its own maps. Its absence from imaging maps would say nothing about whether it ran.

**Comparator import census.** I checked all 185 regular, non-symlink files below C/bin and C/lib recursively. All 167 ELF files had .dynsym. In 29 files there was at least one undefined dynamic symbol named exactly system (8 files), popen (0), execve (2), fork (10) or dlopen (15). Counts overlap. Comparing all 29 against an executable mapping with the same /usr-relative pathname in the M7 PID 161 sample yielded **14 matches**. Eight of the 29 had a basename in the P filesystem listing, one of those also had a matching map. That listing is partial. An exact-name import scan misses aliases, raw syscalls, static code, callbacks and dynamically resolved names. It establishes neither temporal reachability nor the absence of such calls elsewhere.

**INCONCLUSIVE for universal activation, with BT on or off.** No stock M7 trace in the assigned evidence spans the detached interval with process creation, library loads and radio state. Driver resume, card enumeration, a mapped library and endpoint process snapshots each measure something different. The earlier transition evidence establishes an S2R thaw and a separate WBI restore (RESEARCH-stage7-3b-wbi-hooks.md:36–48). Neither proves the stock shell script ran, that /tmp_bt remained mounted, or that another program executed on every wake. The census is a stock dependency check. No target-specific persistence entry point is qualified here.

## 3. Exact M7 loader failure behavior

| Input | Verified behavior in P/lib/ld-2.11.2.so |
|---|---|
| Missing or inaccessible preload **list** | At 0x2160–0x2174 the loader forms the address of the string at 0x14c64, passes mode 4 to its access wrapper at 0x10d90 (ARM syscall 33 at 0x10d98), and enters list processing only on success. A failed access takes the normal continuation at 0x2174. This case does not produce the per-object warning. |
| Accessible list naming a missing **object** | The token loop calls the stripped preload helper at 0x2b70 and resumes iteration at 0x2b76. There is also a final-token call at 0x2bd4. The helper at 0x97c calls its error catcher at 0x9b0, passing mapping callback 0x9e5 (Thumb). That callback calls the mapper at 0x9fa. The open-failure path at 0x6690–0x669c passes the saved error and “cannot open shared object file” to the loader error routine. A caught error takes 0x9c6–0x9d6, prints the ignored-object diagnostic to fd 2, returns zero, and the caller continues. ENOENT for the named object alone is therefore not fatal to this startup path. |
| Permission denied, short file or bad magic | A target open failure reported by the mapper uses the same catch. Short-file and invalid-header branches load messages at 0x4736–0x473a and 0x4718–0x471e respectively and join error processing at 0x4672. A recognized, caught map rejection is skipped. File mode bits alone do not establish EACCES for a privileged process. A closed stderr can make a diagnostic unobservable. |
| Object maps successfully | At 0x9b8–0x9c2 the helper returns whether the loaded-object count changed. That completes the guarded *mapping* step. Later dependency loading, relocation, initialization and the program's use of symbols are separate operations. A missing transitive dependency, unusable relocation or initializer that waits forever cannot be treated like ENOENT of the originally requested file. No bounded recovery from arbitrary malformed input follows from these selected error branches. |

**FAIL for the proposed zero-risk ELF guarantee.** A dependency-free object can still carry executable initialization that never returns. The loader must read, map and interpret the object before a /proc/self/exe check could run. Section names, choice of ARM syscall interface, absence of PLT imports and a DT_INIT or DT_INIT_ARRAY entry cannot guarantee progress, correct relocation, sufficient resources or application compatibility. This is a logical counterexample to the requested guarantee. It applies even when the list is syntactically correct. No preload construction or installation is part of this finding.

## 4. Workspace and Phase A continuity

**No mountpoint passes the proposed qualification.** Both inventories, lines 7–19, show the active root and /usr read-only. /tmp and /etc use the same internal device; /tmp/mlv2 would require a flash directory if it did not exist. D/inventory.txt:57–84 lists existing root directories. A directory entry, ownership or link count cannot identify an exclusive or unused mountpoint. The stock M7 updater explicitly mounts and unmounts /tmp_updater (P/usr/bin/up.sh:124,151,184,217). /tmp_bt belongs to BT on the comparator. /tmp_cert and /mnt have no documented exclusivity or witnessed private mount. /tmp_ipsec is 128 KiB, below the 167,088 bytes for the three Phase A executables alone. /tmp_network had 1,040,384 bytes free at D/inventory.txt:344. The recorded S2R replaced its visible marker and directory inodes (RESEARCH-stage7-3b-persist-mechanism.md, “Runtime workspace and daemon continuity”). A 4 MiB tmpfs limit is a ceiling, not available-RAM evidence. No candidate has before/after mount identity, stock ownership and capture-headroom evidence together.

### Phase A source audit

| Component | Paths, resources and failure boundaries |
|---|---|
| stage7_daemon.c and its headers | stage7_common.h:5–11 binds live config, temporary config, persistence gate and simulation files. stage7_v2_common.h:18 supplies the run prefix. stage7_daemon.c:370–389 derives log, PID, stop, disarm, published and temporary run config, and child executable. Lines 732–733 hardcode the two SD stop markers. In daemon mode cwd becomes / at 1518. Its log is an open fd, /proc/<im>/mem is opened once, and a running child has a nonblocking output pipe (1391–1400,1574–1612,1815–1820). Short-lived fds include proc directory, maps, stat and comm reads, urandom, disarm, PID and run-config writes. The launch path sets up the child pipe and stdio and closes inherited descriptors 3–63 (1338–1399). PID/start tick, memory ranges, object pointers, monitor thread, half-press/debounce, child PID/reap status, ring sequence and time budgets are session state. A reopened pathname may now designate a different inode from a still-open log; the marker looked up by name may have vanished. |
| stage7_ring.c | Line 11 is a stale Stage 6 comment. Actual code uses S7_RUN_PREFIX at 164–174 to derive run.cfg, stop and disarm (2893,3042–3043). Config fd is closed at 2908; observer fd is opened at 3048 and closed at 3202. Its output is the inherited pipe. Retained state includes validated config and addresses, observer arena, trace ownership, held frames, storage handles, active capture and outstanding child waits (881–965,1950–1988,2119–2127,2893–2929,3012–3069). Retaining a daemon or pipe does not validate a frame, an outstanding save or the medium. The worker textually includes common capture/SD code (lines 49–103). This is an audit of the named translation-unit source, not a complete static descriptor analysis of all linked Sony code. |
| mlv2_card_read.c (Stage 7's card reader) | Literal prefix at 228 and default RAM/stage paths at 919. The directory walker pins and closes intermediate fds under O_NOFOLLOW (221–271). Verification opens the card, key and version; FAT geometry/catalog and stream position live in memory. Extraction holds a stage dirfd, an exclusive temporary output and the card fd; it closes card and output before publishing and releases the dirfd (826–887,916–961). The diagnostic's configurable RAM path and available-byte output are distinct from the extraction check of tmpfs on the open directory (855–866,891–909). A successful probe against a directory cannot certify that a later extraction uses the same mount. After media replacement, the previous scan and card identity no longer qualify a read. |
| scripts/m7_stage7_sd_probe.py | Lines 42–60 bind daemon root, simulation, upload and cleanup allowlists. Lines 240–353 bind parent checks, locks and marker operations. Lines 416–469 and 553–702 bind telemetry, staging, recovery markers, logs and expected checksums. Lines 826–917 and 959–1159 bind cleanup, stop markers and custody. The host-local fds at 80–85 and 159–196 are receipt/custody I/O. The USB session and its command channel, active host receipt, lock owner, expected nonce, binary hashes, PID and start tick are different kinds of state. Line 439 samples boot_id; the same_im predicate at 804–810 compares preflight result, PID and start tick. The WBI sample retained both numerical identifiers while the boot UUID changed. Those two identifiers alone cannot distinguish generations. Cleanup decisions must account for that ambiguity and for path reuse. |

The literal index in the appendix covers every literal occurrence in discoverable text files in the supplied Phase A directory and the named probe, including tests, generated outputs and comments. Generated outputs describe the sealed release. Changing a source invalidates its source-hash contract until a rebuild and successful suites. Additional important consumers include mlv2.h, core.c, shim.c, mlv2_sd_boot.sh, both builders and stage7_ram_runner.py. A change limited to daemon, ring and reader would leave conflicting allowlists and cleanup behavior. S2R continuity of the existing release, and a fresh authenticated session after WBI, remain separate unverified outcomes.

## 5. B5 decision and minimum evidence

| Question | Smallest meaningful evidence and what it would establish |
|---|---|
| Can the remaining exact-build BT questions be resolved offline? | Obtain M7 1.00 /usr/bin/startBTCore.sh, /usr/lib/libBTUtils.so, /usr/lib/libInfraBluetoothCore.so, /usr/lib/libInfraBluetooth.so and /usr/lib/libIMDB.so to cover the script, mount utility, server client, policy and IM request handling. Add /usr/bin/bsa_server for server-side exit/readiness behavior and /usr/lib/libInfraNetInitializer.so for attribution of the separate network-mount replacement. Record byte counts and SHA-256. Prefer a stock offline image or existing archive. M7 libsencore.so, im.elf and the loader are already present. A live FileControl extraction itself can trigger Sony logging. |
| What does stock BT actually do on wake? | With BT in its already-selected stock state, obtain matched before/after boot UUID, uptime, LIRO event, /proc mountinfo for /tmp_bt, server PID/start tick and readiness observations. Distinguish a USB reconnect control, switch S2R and battery WBI. Cover both BT states in separately identified captures. Menu toggling can itself persist a preference. Continuous stock telemetry across USB-detached wake is needed to exclude short-lived processes; a pair of snapshots cannot settle that question. Startup jitter needs matched timing measurements. Do not infer behavior under injected process failure from these observations. |
| Are private RAM and a retained application usable after S2R? | A passive read of mountinfo can identify stock mounts. Qualifying a new private mount necessarily changes volatile state. Once exclusive ownership and a RAM-only parent are evidenced, an isolated retention trial would need a mount ID, filesystem type, st_dev, fresh witness contents, inode and free space before/after the same transition. Distinguish survival of a pinned fd from re-opening by path. A later run would have to follow daemon, pipe/child, input, actual media identity and a successful post-wake capture. A witness disappearing across WBI can be consistent with correct snapshot rollback. |
| Does shell-free FileControl work on a healthy camera? | An already archived trace showing enumeration, authentication, a recognizable read result and stop/re-enumeration with no terminal-enable request can support the healthy read claim. For write/delete, a volatile unique canary would need a known-content readback, successful deletion and an independent absence check. The returned status is insufficient. A RAM canary would still leave the stock .etools write path and global sync. Under a literal zero-internal-flash-write constraint there is **no qualifying live FileControl transaction sequence established here**. /tmp is specifically disqualified as a RAM test target. |
| Can a damaged camera recover? | A healthy FileControl trace cannot satisfy this gate. Evidence must cover entry into responsive stock recovery under the specified failure, repair of only intended files, durable readback and successful return to stock. An offline exact-build model can test failure classes but cannot certify real USB timing, mount recovery, or physical recovery entry. Absent an independently evidenced recovery route, the stage stop condition remains in force (plans/07-persistence.md:48–51). |

B5 therefore cannot close *all* items through read-only live checks. Several proposed observations change volatile state, some may write internal flash through stock behavior, and the universal zero-risk claim is false. No hardware command is warranted by this research assignment.

## Host-only reproduction

Run from the repository root under zsh. All outputs go to stdout.

```sh
M=extracted/m7-1.00-29110_03.2021050601-20261104T212913Z
P=extracted/m7-stage7-1.00-20261126T172306Z
C=extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked
xcrun llvm-objdump -p "$M/usr/bin/im.elf"
xcrun llvm-objdump -TC "$M/usr/lib/libsencore.so"
for f in "$M/usr/lib/libsencore.so" "$P/lib/ld-2.11.2.so" "$C/lib/libBTUtils.so" "$C/lib/libInfraBluetoothCore.so" "$C/lib/libInfraBluetooth.so"; do
  xcrun llvm-objdump -dC --triple=thumbv7-linux-gnueabi "$f"
done
xcrun llvm-objdump -d --triple=armv7-linux-gnueabi --start-address=0x10d90 --stop-address=0x10dac "$P/lib/ld-2.11.2.so"
rg -nF /tmp_network prototype-stage7-persist scripts/m7_stage7_sd_probe.py
rg -n '/tmp_updater' "$P/usr/bin/up.sh"
rg -n 'FileControl|SONY_FILE_CONTROL|def authenticate' sources/sony-pmca-re/pmca/usb/sony.py
shasum -a 256 "$M/usr/bin/im.elf" "$M/usr/lib/libsencore.so" "$P/lib/ld-2.11.2.so" "$C"/bin/{startBTCore.sh,bsa_server} "$C"/lib/{libBTUtils,libInfraBluetoothCore,libInfraBluetooth}.so
```

The following reproduces the comparator census and the M7 mapping counts.

```sh
.venv-analysis/bin/python -B - <<'PY'
from collections import Counter
from pathlib import Path
from elftools.elf.elffile import ELFFile

root = Path('extracted')
comp = root / 'm7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked'
snapshot = next(root.glob('m7-1.00-*/runtime.txt')).read_text()
maps = snapshot.split('__M7_MAPS_PID_161__')[1].split('__M7_')[0]
mapped = {line.split()[-1] for line in maps.splitlines() if ' r-xp ' in line}
listing = next(root.glob('m7-stage7-1.00-*/inventory.txt')).read_text().splitlines()
symbols = {'system', 'popen', 'fork', 'execve', 'dlopen'}
counts, imports, coverage = Counter(), Counter(), Counter()
for group in ('bin', 'lib'):
    for path in sorted((comp / group).rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        counts['regular'] += 1
        with path.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
            stream.seek(0)
            counts['elf'] += 1
            dyn = ELFFile(stream).get_section_by_name('.dynsym')
            if dyn is None:
                counts['no dynsym'] += 1
                continue
            hits = {s.name for s in dyn.iter_symbols() if s['st_shndx'] == 'SHN_UNDEF'} & symbols
        if hits:
            counts['matched'] += 1
            imports.update(hits)
            coverage[('/usr/' + str(path.relative_to(comp)) in mapped,
                      any(line.endswith(' ' + path.name) for line in listing))] += 1
print(counts, imports, coverage)
PY
```

### Binary SHA-256

| Build | File | SHA-256 |
|---|---|---|
| M7 1.00 | im.elf | ad08a5b12fa344ba595f56c8c9ce12263be4673d15deede1b67f4434309e105a |
| M7 1.00 | libsencore.so | d79365e3a168bffcad68bf8cce24bfa62be1de2e0d7ed062470632a0af9f1279 |
| M7 1.00 | ld-2.11.2.so | 289253ca75a446036ac947fa93ff7d2c2224ffd10293e5c6b599af490b1a348d |
| M7A 1.01 | startBTCore.sh | 33c82447cdbcdbd27e476ddf15f39f19a96d826d775e241d14ee0691d97beb27 |
| M7A 1.01 | bsa_server | cfad2e351a3f82a40cb4d30421402e12396593c4c2f34f50033b505f151b63fe |
| M7A 1.01 | libBTUtils.so | 0b7c7706f517a8cdeaa61282a386693dde65949d9b7e0f27da6dec84f3b0ee39 |
| M7A 1.01 | libInfraBluetoothCore.so | 1b0a4a3ab12b68dc470fa5df4cb9bb21b646f44b6c5f8b8851f5945a33e12f63 |
| M7A 1.01 | libInfraBluetooth.so | 938e47ba5f9ac0b7659db1754503faf74d84222a941529e7594916b6c3ad992e |

### Phase A literal index

Line numbers below come from the read-only rg command above. Counts include comments and tests. Indirectly derived paths and descriptor lifetimes are discussed in section 4.

| File | Lines containing /tmp_network |
|---|---|
| prototype-stage7-persist/build_stage7.py | 745, 1007 |
| prototype-stage7-persist/build_stage7_sd.py | 255 |
| prototype-stage7-persist/core.c | 5, 10, 577 |
| prototype-stage7-persist/mlv2.h | 4, 46, 47, 48, 49, 50, 51, 52, 53, 54 |
| prototype-stage7-persist/mlv2_card_read.c | 228, 919 |
| prototype-stage7-persist/mlv2_sd_boot.sh | 7, 8, 9, 10 |
| prototype-stage7-persist/out-sd/mlv2_sd_boot.sh | 7, 8, 9, 10 |
| prototype-stage7-persist/out/build.json | 176 |
| prototype-stage7-persist/phaseb_statfs.c | 129 |
| prototype-stage7-persist/shim.c | 3 |
| prototype-stage7-persist/stage7_common.h | 5, 7, 10, 11 |
| prototype-stage7-persist/stage7_daemon.c | 8, 732, 733 |
| prototype-stage7-persist/stage7_ram_runner.py | 4, 48, 49, 59, 60, 61, 62, 63, 65, 66, 67, 175, 1069, 1482, 1578, 1650, 2042, 3089, 3157 |
| prototype-stage7-persist/stage7_ring.c | 11 |
| prototype-stage7-persist/stage7_v2_common.h | 18 |
| prototype-stage7-persist/test_stage7_integration.py | 297, 298, 458, 518, 519, 631, 945, 958, 959, 963, 968, 976, 991, 1002, 1021, 1027, 1030, 1031, 1036, 1038, 1044, 1059, 1062, 1100, 1106, 1113, 1119, 1132, 1134, 1138, 1141, 1155, 1162, 1169, 1176, 1338, 1341, 1357, 1360, 1361, 1362, 1366, 1377, 1378, 1403, 1412, 1419, 1432, 1438, 1449, 1450, 1453, 1465, 1484, 1511, 1512, 1533, 1534, 1535, 1536, 1559, 1576, 1577, 1578, 1579, 1582, 1612, 1634, 1635, 1669, 1688, 1699, 1700, 1703, 1716, 1717, 1721, 1732, 1739, 1755, 1773, 1780, 1823, 1826, 1828, 1829, 1830, 1872, 1877, 1880, 1881, 2147, 2149, 2150, 2260, 2279, 2280, 2281, 2282 |
| prototype-stage7-persist/test_stage7_phaseb_collect.py | 42, 67, 565, 596, 839, 851, 1003, 1064, 1204, 1214 |
| prototype-stage7-persist/test_stage7_ram_runner.py | 199, 208, 249, 302, 375, 378, 379, 399, 403, 440, 447, 460, 469, 478, 483, 489, 507, 535, 550, 556, 565, 605, 609, 775, 778, 779, 874, 932, 1039, 1135, 1278, 1402 |
| prototype-stage7-persist/test_stage7_sd.py | 257, 365, 498, 502, 505, 506, 518, 528, 529, 542, 543, 544, 545, 546, 588, 603, 616, 623, 768, 774, 902, 1027, 1066, 1322, 1327, 1354, 1356, 1358, 1360, 1372, 1381, 1383, 1473, 1480, 1507, 1509, 1511, 1515, 1521, 1523, 1525, 1534, 1542, 1550, 1559, 1561, 1562, 1563, 1565, 1580, 1587, 1590, 1594, 1607, 1621, 1622, 1624, 1701, 1736, 1743, 1768, 1815, 1852, 1866, 1873, 1900, 1902, 1908, 1914, 1916, 1922, 1926, 1928, 1934, 1973, 1990, 2099, 2124, 2132, 2207, 2231, 2250 |
| prototype-stage7-persist/test_stage7_unicorn.py | 14 |
| scripts/m7_stage7_sd_probe.py | 6, 8, 42, 43, 47, 50, 51, 52, 59, 60, 240, 263, 296, 304, 316, 353, 416, 421, 442, 469, 553, 566, 599, 610, 617, 620, 638, 642, 649, 652, 674, 675, 688, 692, 702, 826, 856, 857, 858, 867, 880, 881, 897, 901, 905, 906, 917, 959, 963, 969, 970, 1022, 1025, 1091, 1102, 1130, 1142, 1143, 1146, 1158, 1159 |
