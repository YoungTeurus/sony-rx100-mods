# RX100M7 1.00 power transitions and independent recovery

**Decision, 2026-11-27 — NO-GO for a persistent Phase B installation.** The owner’s switch cycle retained the running imaging process and replaced the directory tree visible at `/tmp_network`. The subsequent battery-pull start took the WBI branch and returned to an earlier process state. Neither observation establishes an untethered stock launch of the owner-authenticated card package or a way to repair a failed internal startup component. Keep the tested Phase A workflow as the baseline. The single most informative missing M7 binary for the filesystem question is **`/usr/lib/libInfraNetInitializer.so`**. Its M7 mapping, the sibling firmware’s mount code, and the measured directory changes agree. [S0:427–453,1095–1101; S1:357–377,1019–1025,2586; S2:357–377,1046–1052,2604; M:371–373; N VAs below; STATE.md:84–89; plans/07-persistence.md:39–51.]

## Evidence key and custody

All paths are relative to the project root. S0, S1 and S2 denote the following exact files under `work/stage7-persist/phaseb-probes/`. The physical switch/battery actions and ten-second pull are the owner's sequence as supplied in the assignment. Timing inside the receipts is the probe timing. S0.d[n] below means decoded line n of the single JSON string at S0:2662. S1.d and S2.d refer to S1:2586 and S2:2604. Hashes and full diff commands are below.

| Key | File |
|---|---|
| S0 | `20261127T185303Z-7906834d545f-s0-plant.json` |
| S1 | `20261127T185558Z-3f60cb41a0cd-s1-after-switch.json` |
| S2 | `20261127T185735Z-c15565b7df8f-s2-after-battery.json` |
| B1 | `20261127T184903Z-57c117b5d78d-extract-boot.json` in the same directory |
| D, I | `extracted/m7-stage7-phaseb-1.00-20261127T184903Z`; I is its `inventory.txt` |
| P | `extracted/m7-stage7-1.00-20261126T172306Z`, including `sbin/init` |
| M | `extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/runtime.txt` |
| K, L | M7 raw `vmlinux.bin` and M7 `liro.ko` in the manifest. K VAs use base `0x60108000`. L addresses are offsets in .text. |
| A, B | `work/stage7-persist/RESEARCH-stage7-3b.md` and `work/stage7-persist/RESEARCH-stage7-3b-boot-recovery.md` |
| N, J | Comparative **RX100M7A 1.01 only**, `libInfraNetInitializer.so` and `libInfraIPsec.so` in the manifest. Addresses are link-time Thumb VAs unless marked file offsets. |

Read scope beyond the primary M7 inputs: the two related-model DSOs and a string census of their sibling lib/bin directories distinguish a path consumer from the actual mount lifecycle. The read-only M7 kernel analysis metadata and symbol map cited by A identify original K instructions. The bionz-x reference documentation identifies which model its card startup actually covers. Only this report was written. No live commands, device accesses or hardware experiments were performed in this investigation.

**Receipt integrity and qualification have separate verdicts.** All three report the same build, completed diagnostic data, terminal disable verification and an unsuccessful StopSenser transport with camera exit unconfirmed. Each has `transition_probe_ok=false`. The dmesg bytes can be independently checked against both text and the embedded hash, and no process read races are recorded. Use the observations below. The end-to-end collection/teardown gate is **FAIL** for all three. The collector discloses possible stock side effects, including shell history. [S0:5–25,380–388,424–432,2661–2671; S1:5–25,310–318,354–362,2585–2595; S2:5–25,310–318,354–362,2603–2613; B:75–85.]

## What happened on this camera

| Observation | S0, before switch | S1, after switch | S2, after battery pull |
|---|---:|---:|---:|
| Boot UUID (prefix) / uptime, seconds | 291d2369 / 13052.39 | 291d2369 / 13224.38 | ff7115aa / 33.47 |
| LIRO argument / tasks restarted at kernel log time | 0 / 0.121128 | 0 / 0.123259 | 1 / 0.783176 |
| Process rows / rows with a nonempty exe | 245 / 5 | 245 / 5 | 247 / 5 |
| Minor faults, PID 1 / 154 / 160 / 161 | 770 / 365 / 230 / 117557 | 770 / 365 / 230 / 132361 | 769 / 359 / 229 / 36014 |
| Start ticks, same four PIDs | 0 / 99 / 103 / 105 | 0 / 99 / 103 / 105 | 0 / 99 / 103 / 105 |
| Inodes of network root / run / dhcpd | 7523 / 7524 / 7525 | 11749 / 11750 / 11751 | 2053 / 2054 / 2055 |
| Marker, before → after probe | absent → 43-byte regular file | absent → absent | absent → absent |

Sources for every row: S0:427–453,454–2662; S1:357–377,378–2586; S2:357–377,378–2604. The S0 directory listing precedes the plant. Its readback records inode 10280 and MD5 `d6bd8ed45e235dba0138fc109693886d`. S1 did **not** replant it. S2 therefore cannot independently test the survival of a file known to exist immediately before the battery pull.

**PASS, retained S2R across the switch.** Uptime advanced 171.99 seconds and PID 161 accumulated 14,804 minor faults with the same start ticks, command line and exe. The log contains a fresh secondary-CPU offline/online sequence, the zero LIRO flag, then task thaw. Zero means the driver's combined predicate was false. The switch classification draws on all these observations. **FAIL, pathname retention on this cycle.** Even the root inode changed. Removing only the marker from an otherwise untouched mounted tree cannot explain the three new inode identities. A newly mounted tmpfs fits all observations. Endpoint listings alone cannot discriminate an unmount followed by mount from an overmount or a change of mount namespace. They cannot date the change relative to USB reconnect. [S0:388,427–453,1095–1101; S1:318,357–377,1019–1025; S1.d[72–88,158,173,178–181]; L .text+0x110–0x140.]

**PASS, WBI resume after the battery pull.** S2.d[1–3] starts with WARMBOOT and low-level resume complete. At [92–99] LIRO logs WBI, two backup regions and argument 1. L calls `pm_get_state()` and `pm_is_mem_alive()` and selects that branch for state 4 and memory-alive zero. The restored early task identities, lower cumulative counters, new boot UUID and uptime agree with a return to snapshot state. This supports restore of the baseline process population. Its capture time, header identity and page-by-page membership remain unknown. K freezes tasks at 0x60167090, enters device suspend at 0x601670cc, thaws tasks at 0x601670d8 and re-enables usermode helpers at 0x601670dc. There is no obligatory fresh userspace exec in that sequence. The same printed callback address in S1/S2 is an address supplied to printk, not an observed Linux process exec. [S1:357–360,378–2585; S2:357–360,378–2603; S2.d[97–110]; L .text+0x114–0x140,+0x24c–0x258; A:27–31.]

### Accounting for the complete captures

* **Processes.** Comparing keyed PID, comm, start ticks, exe and the entire command-line byte sequence gives 81 matching identities S0→S1, with 164 old-only and 164 new-only PIDs. Of the 81, 54 whole JSON rows are identical. S1→S2 gives 80 matching tuples, 165 old-only and 167 new-only, with 47 identical whole rows. Equal tuples across WBI can be restored. In both pairs each side's nonshared PIDs include 140 `liro-kliro_*` tasks. The only comm multiplicity differences across the switch are three CPU 1/2/3 kworkers with suffix :2 replaced by :1. Across battery, S2 adds one `kworker/0:0` and one `flush-1:0`. The four recurring userspace exes belong to launch_shell, bootin, BusyBox login ash and im. The fifth is a service-session BusyBox shell (PID 1256, 2868, 767). No sampled exe is sen.elf. A short-lived process may finish between enumerations. [S0:454–2661; S1:378–2585; S2:378–2603.]
* **Mounts and directories.** All 15 mount lines, including options and order, are byte-identical in all three. Mount instance IDs are absent. All 46 flash-listing lines were compared. Only four change across the switch, exclusively printed mtimes of `/etc/kikilog.dat`, `/setting/.etools`, `.hasp` and `Backup.bin`. Across battery 25 listing lines change, involving inode numbers and/or mtimes. All names and printed sizes remain. An unchanged listing says nothing about file bytes. S2.d[28–33] explicitly logs invalidation of internal partitions 2, 3, 10, 11, 12 and 18. That message does not establish a file deletion or a flash rollback. The empty `/setting/mode` and the two listed updater entries `comp`, `dat4` occur in each sample. [S0:388,433–434; S1/S2:318,363–364; I:124–132.]
* **Kernel logs.** The windows contain 178/181/118 lines and 7661/7652/5244 bytes. No *complete timestamped line* matches across adjacent captures. Stripping just the leading timestamp gives 165 shared line occurrences (13/16 unmatched) across switch and 95 (86/23 unmatched) across battery, counting duplicates. The first two windows begin mid-message; S2 begins at low-level restore. All three show MMC detection after task restart, then service-console activity. In S2 the order is task restart at 0.783176 s, card detection at 1.530439 s, partition report at 1.742272 s and service line discipline open at 14.084335 s. These are kernel log times. They measure neither switch-to-shutter latency nor module insertion time. None of the windows records a named mount caller for the network tree or a userspace open/exec trace. [S0.d[1,148–178]; S1.d[1,158–181]; S2.d[1–3,92–118]; S0:2662–2666; S1:2586–2590; S2:2604–2608.]

## Who owns the network tmpfs?

**INCONCLUSIVE on M7 1.00, with a specific, testable attribution.** M:371–373 maps the M7 network initializer into the imaging process (executable mapping 0x093e6000–0x093eb000 in that historical sample). The supplied M7 extracts contain neither that DSO nor the M7 IPsec DSO. A plaintext byte search finds no `/tmp_network` literal in the collected M7 executables, libraries, modules or raw K. This bounds the search only for contiguous ASCII. Literal absence cannot exclude constructed paths, compressed content, IPC requests or an indirect caller. P/usr/bin/up.sh:123–125,148–152 concerns `/tmp_updater`. D/usr/bin/network.sh:1–3 names a separate WS_SubProcess executable and has no mount instruction. No evidence assigns the network mount to PID 1 or to either script.

**PASS on the comparator only.** In N the following lifecycle uses libc directly. The order and names account for the three consecutive inode numbers on each M7 sample. This is a hypothesis about the M7 actor, not a transfer of M7A VAs into M7.

| Comparative M7A operation | Checked Thumb call and ABI |
|---|---|
| Network suspend | `suspend(unsigned)` takes this in r0 and the argument in r1; 0x3248 calls finalizePartition. At 0x3b2c this calls executePartitionUmount; 0x3a58 calls libc umount(path in r0). On failure the loop increments its counter, sends a synchronous message, compares against 50 and branches back (0x3a7c–0x3ab0). A long-lived reference that keeps the filesystem busy could therefore affect the stock transition. That failure was not exercised on M7. |
| Network resume | Same method ABI; 0x3034 calls initializePartition, which calls executePartitionMount at 0x3b98. At 0x39ea the libc mount arguments are r0 = “none”, r1 = “/tmp_network”, r2 = “tmpfs”, r3 = 0xc0ed0490, [sp] = “size=1M”. Strings at file offsets 0x440c–0x442c and literal pool 0x3a20–0x3a30. The wrapper logs a mount failure and returns zero at 0x3a18–0x3a1c. Function return alone would make a poor success witness. |
| Populate directory tree | 0x3bb0 and 0x3bce request mkdir for run then dhcpd with requested mode 0777; the wrapper calls libc mkdir(path in r0, mode in r1) at 0x3b5c. Strings at 0x442d and 0x443e. M7 S0:433 and S1/S2:363 show exactly that order by inode. |

**Other writable locations.** Of the visible general-purpose tmpfs mounts, only `/tmp_ipsec` remains a retention candidate (128 KiB total). No B2–B4 marker, mount ID, before/after inode or open-file witness was recorded for it. Its **capacity alone cannot hold the 204,928-byte Phase A archive**. The corresponding M7 library appears in M:459–461. In comparator J, `InfraIPsec_init` calls mount at 0x28de, `InfraIPsec_exit` calls umount at 0x29fa, and `IPsecSuspend` returns zero at 0x404e–0x4054. That is a useful distinction from N. Whether another layer invokes exit/init during M7 suspend remains open. `/tmp` and `/etc` both expose internal VFAT partition 10. `/dev` and `/tmp_bt` have no separate writable RAM mount in these listings; /dev/pts is devpts. The rootfs line coexists with the visible read-only ext2 root. Proc, sysfs and devpts do not establish a regular-file workspace. **INCONCLUSIVE** for any stock RAM directory retaining binaries, sockets and files across S2R. A running mapped image and a pathname that a later child must reopen are different dependencies. No project daemon, open descriptor, socket or reconnect test was included in these captures. [S0:388,433–454; S1/S2:318,363–378; I:4–19,62,78–81; STATE.md:86–88; J file offsets 0x54b1–0x54fa.]

## Boot families and rollback

Rank is research priority for the stated product. Only the RAM baseline is qualified for its existing, explicitly launched use. No row meets the Phase B acceptance and recovery requirements in plans/07-persistence.md:39–51.

| Rank / architecture | Ordinary switch | WBI / battery | Boot-time effect | Minimum internal change and failure with card absent or bad | Independent rollback verdict |
|---|---|---|---|---|---|
| 1. Existing stock, removable-media decision after resume | Stock tasks thaw. A repeated package decision is unobserved. | Card detection follows thaw; no stock package dispatch identified. | No measured overhead or ready-to-shoot time. | Zero internal files **by definition** for a wholly card-based design; persistent internal preferences would enlarge that set. Absence then removes the package source. An invalid package, parser hang or partial activation still needs a measured clean stock outcome. | **INCONCLUSIVE existence.** Card removal could recover a subsequent clean load only if no prior activation or saved state survives. S1 demonstrates stock process continuity. [S1.d[158–181]; S2.d[93–118]; STATE.md:86–88; A:93–95.] |
| 2. Explicit Phase A RAM start and retained daemon | Plausible for private process memory; established pathname dependency fails. Worker continuity, child launch, socket reconnect and image/UI health are untested across switch. | S2 resumes earlier state; no evidence a later-launched worker belongs to that snapshot. | No firmware-start latency change established. Explicit start required for the demonstrated workflow. | Zero project flash files in tested Phase A. Missing or bad card during an unattended resume was not exercised here. | **PASS for Phase A only; FAIL as a demonstrated standalone Phase B design.** Clean removal was demonstrated from a functioning camera. [STATE.md:84–89; S0/S1/S2 process tables and marker above.] |
| 3. Internal post-resume event consumer, preserving stock WBI | Resident network code is a credible filesystem owner. No documented M7 extension reader established. | No observed package consumer after WBI, SD enumeration or service readiness. | Unknown event timing and timeout behavior. | No qualified file list. Any added resident component remains present with SD absent. A child crash may be isolated; a synchronous hang can stall its caller even with a valid signature. | **INCONCLUSIVE trigger and independent recovery.** All service samples are from a functioning im. [M:371–373; D/usr/bin/compat_firmware.sh:10,17–31; S2.d[92–118]; B:63–71.] |
| 4. Stock cold application start or global startup configuration, preserving WBI | Existing running processes need not replay startup. | Snapshot baseline may bypass a later cold-start change. | No true-cold baseline or per-exec overhead measurement. | Candidate surfaces are application configuration on /setting and wider startup configuration on /etc. Exact file/byte manifest undefined. Absent SD leaves the internal configuration active. A global fault can affect service userspace too. | **FAIL as guaranteed coverage of both observed transitions.** No independent restore demonstrated. [A:89–102; B:41–48,65–70; S1/S2 observations above.] |
| 5. Bypass WBI, regenerate it, or modify the boot image | Suppressing WBI alone does not convert a battery-retained S2R into cold userspace startup. | Bypass would require a verified cold chain. Regeneration would require identifying the image actually selected and what it contains. | Cold boot would perform init/module/mount/application work. Net latency and camera behavior are unmeasured. Regeneration cost and state freshness also unknown. | No defensible minimal file set. Normal initrd, compressor inputs and sector image are distinct. Bad boot data or an unhealthy snapshot can remain effective with the card removed. | **NO-GO.** Recovery must be independently selected before the failed component and preserve per-unit data. No such M7 restore is established. [B:24–45,53–71; S2.d[1–13,92–110]; A:99–102.] |
| Reference family. Another BIONZ X model’s SD-autostart companion | No RX100M7 S2R qualification. | No RX100M7 WBI qualification. | No transferable camera timing. | ILCE-6400A's documented standalone procedure includes a one-time companion setup. That example cannot establish a zero-file stock M7 path. | **INCONCLUSIVE applicability.** The reference’s supported-camera table and target guide identify where work was verified. [sources/bionz-x-research/README.md:40–50; sources/bionz-x-research/mods/ilce_6400a/README.md:1–7,68–74.] |

### What the stock WBI controls establish

* **PASS for configuration and primitives.** Every command line names warm.mode=2, warm.boot_drop=0, warm.resume_drop=0, warm.ignore_drop=1 and pm.ddr_ctrl=sref. M7 K registers the drop parameters at 0x60491a38/48/58. The ordinary wbi_drop returns zero without the internal drop call when the ignore flag is set (0x6011c0f8–0x6011c114). The resume variant tests mode and the resume-drop variable before the call (0x6011c128–0x6011c144). The boot-drop descriptor points to 0x604de6c8. A descriptor and its configured zero give no proof of reset-time media selection. No recorded `/setting/mode` entry demonstrates a stock WBI toggle; the stock updater-mode script manages a different directory. [S0:430,434; S1/S2:360,364; I:45,124–132; P/usr/bin/up.sh:3–6,231–253; A:66.]
* **PASS for snapshot creation code; INCONCLUSIVE for the selected instance.** K has separate prepare/snapshot/write steps and a sector-backed writer. `cxd_create_warmbootimage` submits page sections and rewrites the header, and the normal initrd eMMC module provides sector callbacks. The two small sabin files are compressor inputs. `swap_prepare.sh` prepares partition 8 as compswap backing on its success branch. None of this identifies a snapshot file to replace, who authorized a regeneration, the selected header or the state included at capture. The normal initrd's PID 1 matches the installed init. No matched, independently selected updater root and reset-time selector were established in B1. [K 0x6011c50c–0x6011c65c,0x60126f3c–0x60127130,0x60167920–0x60167960; B:5,53–61,70; D/usr/bin/swap_prepare.sh:3–22.]
* **INCONCLUSIVE for a universally executed process or script.** The kernel can resume drivers and thaw an existing task without starting a new process. Each healthy sample shows an empty hotplug setting. D/usr/bin/compat_firmware.sh consumes firmware from read-only /usr/wlan/ath on a qualifying device-add event; D/usr/bin/network.sh calls a fixed /usr executable. Neither demonstrates a package reader on writable flash or SD, on every S2R or WBI, or after service has become independently usable. M7 init asks for the service module in a cold module group after accessing /setting. A loaded gadget and a later healthy console open answer different questions from whether an im crash or hang permits repair. [S0:430–432; S1/S2:360–362; S2.d[110–118]; B:30–51,65–71; P/sbin/init Thumb 0x981c,0x9872,0x9ae4–0x9b0c.]
* **FAIL for a guaranteed stock recovery with a failed flash component.** The observed cold path can block before the service-module load. A separately forked sen child is conditional. A shared userland failure can block subsequent service activity, and a watchdog restart can reach the same fault. There is no failed-im USB-enumeration plus selective stock restoration receipt. Signed or absent card handling cannot undo a failure that precedes card access. S0/S1/S2 do not measure an invalid package, malformed card filesystem, crashing resident component or hung callback. [P/sbin/init Thumb 0x905e,0x981c,0x9872,0x9ae4–0x9b0c; B:63–75; A:66,102; plans/07-persistence.md:39–51.]

**Remaining evidence, in priority order.** (1) The exact M7 network initializer DSO and its stock lifecycle caller would test the attribution. M7 IPsec DSO and lifecycle caller would distinguish a plausible alternative mount from a retained one. The M7 media-mount library and WS_SubProcess are secondary if a documented file consumer is in question. Their identifiers come from M:143–144,371–373,459–461 and D/usr/bin/network.sh:3. (2) Mount IDs plus scoped file-identity and process-liveness observations spanning each transition, with a USB-only control, would separate filesystem replacement, pathname reachability and process survival. A separately planted pre-battery witness is missing. [S0:388,439–453; S1/S2:318,369–377.] (3) For failed-boot recovery, the decisive missing materials are the exact-build reset-time selector, selected WBI header/backend identity, independently selected recovery root, and evidence that route restores project-owned changes with imaging unavailable. The normal initrd, LIRO, kernel and service gadget have already been collected. More copies of those binaries would not close the dependency gap. [B:9–12,53–71,112; plans/07-persistence.md:39–51.]

## Offline reproduction

Run at the project root. This first command checks integrity and prints a full unified diff for every process field, mount row, both directory listings and every dmesg line. The compact identity comparison ignores volatile counters; the complete process diff retains them. Empty output for a mount diff means all 15 rows, including options and order, agree.

```sh
python3 -B - <<'PY'
from pathlib import Path
from collections import Counter
from difflib import unified_diff
from hashlib import sha256
import base64, json, re

directory = Path('work/stage7-persist/phaseb-probes')
def read(nonce):
    path, = directory.glob('*' + nonce + '*')
    return json.loads(path.read_bytes())
b1 = read('57c117b5d78d')
for f in b1['files'].values():
    data = Path(f['host_path']).read_bytes()
    assert len(data) == f['bytes'] and sha256(data).hexdigest() == f['sha256']
print('B1 verified files', len(b1['files']))
samples = [read(n) for n in ('7906834d545f','3f60cb41a0cd','c15565b7df8f')]
def identity(p):
    head, tail = p['stat'].rsplit(')', 1)
    return head.split('(', 1)[1], tail.split()[19], p['exe'], p['cmdline_b64']
for s in samples:
    data = base64.b64decode(s['dmesg_b64'], validate=True)
    assert data == s['dmesg'].encode() and len(data) == s['dmesg_bytes']
    assert sha256(data).hexdigest() == s['dmesg_sha256']
    for p in s['processes']:
        assert base64.b64decode(p['cmdline_b64']) == p['cmdline'].encode()
    print(s['label'], len(s['processes']), s['marker'], s['service_stop_transport'])
for a,b in zip(samples,samples[1:]):
    p,q = ({x['pid']:x for x in s['processes']} for s in (a,b))
    common = p.keys() & q.keys()
    print('shared PIDs / shared identities / identical rows / old-only / new-only',
          len(common), sum(identity(p[i]) == identity(q[i]) for i in common),
          sum(p[i] == q[i] for i in common), len(p)-len(common),len(q)-len(common))
    for norm in (lambda s:s, lambda s:re.sub(r'^\[\s*[0-9.]+\] ','',s)):
        x,y = (Counter(map(norm,s['dmesg'].splitlines())) for s in (a,b))
        print('log overlap/old-only/new-only',sum((x&y).values()),
              sum((x-y).values()),sum((y-x).values()))
    for key in ('processes','mounts_raw','ls_tmp_network','ls_flash_dirs','dmesg'):
        def lines(s):
            if key == 'processes':
                return [json.dumps(p,sort_keys=True) for p in sorted(s[key],key=lambda p:p['pid'])]
            return s[key].splitlines()
        print(key, *unified_diff(lines(a),lines(b),a['label'],b['label'],lineterm=''),sep='\n')
PY
```

The second command reproduces the file census and the comparator disassembly. Addresses printed under N and J belong only to the comparator files. For the kernel-side snapshot writer and normal-initrd contents, B:116–122,305–430 documents the extraction and decoder, and B:53–61 gives the ABI and call sites.

```sh
rg -a -l --hidden --no-ignore -F /tmp_network extracted/m7-*
rg --files --hidden --no-ignore extracted | rg '/(libInfraNetInitializer.so|libInfraIPsec.so|WS_SubProcess.elf)$'
rg -n 'libInfra(NetInitializer|IPsec|MediaMount)' extracted/m7-1.00-*/runtime.txt
cmpdir=extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked/lib
for f in "$cmpdir/libInfraNetInitializer.so" "$cmpdir/libInfraIPsec.so"; do
    xcrun llvm-objdump -T -C "$f"
    xcrun llvm-objdump -d -C --triple=thumbv7-linux-gnueabi "$f"
    strings -t x "$f" | rg '/tmp_(network|ipsec)|tmpfs|size=1M'
done
xcrun llvm-objdump -dr -j .text --start-address=0xe8 --stop-address=0x2d0 extracted/m7-kernel-20261104T223751Z/usr/kmod/liro.ko
./.venv-analysis/bin/python -B - <<'PY'
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
import json,struct
m=json.loads(Path('evidence/m7-kernel-analysis/analysis.json').read_text())
k=Path(m['kernel']['path']).read_bytes()
base=m['base_address']
for va,end in ((0x6011c0ec,0x6011c14c),(0x60167084,0x601670e0)):
    for i in Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(k[va-base:end-base],va):
        print(hex(i.address),i.mnemonic,i.op_str)
for va in (0x60491a38,0x60491a48,0x60491a58):
    print(hex(va),[hex(v) for v in struct.unpack_from('<4I',k,va-base)])
PY
```

## SHA-256 of inputs

The manifest below names original file bytes. B1 itself contains the individual extracted-file checksums at its `files` entries. The integrity command above checks those against the host copies. The two prior reports are identified separately so that inherited static findings can be distinguished from observations in S0–S2. Recompute the manifest from the project root with the command after the table.

```text
b2b68f77d351478c06223bb036d21348e23f43611789084936e6fff6080f0a27  AGENTS.md
444c7b092f85880367ff51cae84aaf7f05a8492a8d3b8866dda3f758beb6d7f7  STATE.md
f09c892ce41a62c552cece871faeb19a619673159b7f336fb9d80e7c244008d6  plans/07-persistence.md
5f30fd9ba9ca30e77d5f529cf9714f082280b6e3162015214f1eb403a13b9108  work/stage7-persist/RESEARCH-stage7-3b.md
c94a0c47347191e358e9c57780ef2f2dbbfb390da95d1142fcf996a3e5a7750d  work/stage7-persist/RESEARCH-stage7-3b-boot-recovery.md
5708508e34d5332a965bf89eb86ccdc0a1ab19b346e8ccdeed7ad1b74770a758  work/stage7-persist/phaseb-probes/20261127T184903Z-57c117b5d78d-extract-boot.json
e355781961cdc8d35c3e7d615471974192cb5a27d4a214b9e22f6b44298e3f35  work/stage7-persist/phaseb-probes/20261127T185303Z-7906834d545f-s0-plant.json
65b5224470eb36d97a3044248f85a3ff9ccd9a7965c956739fbc62e4946ecd10  work/stage7-persist/phaseb-probes/20261127T185558Z-3f60cb41a0cd-s1-after-switch.json
06d7165ebbbb2136fe15a0dd9536c734cf5a6bd16983341e683f46376a5b726b  work/stage7-persist/phaseb-probes/20261127T185735Z-c15565b7df8f-s2-after-battery.json
8d055ace281516993127d17f07e510533af55eb8cb4252d33dd3c925b6f02bf7  extracted/m7-stage7-phaseb-1.00-20261127T184903Z/inventory.txt
f038a727293abf956eba2098425accb419d9c10426763fc5ca6da9c4f06834bc  extracted/m7-stage7-phaseb-1.00-20261127T184903Z/system/initrd.img
a707c285f8f1768481d0602e367c791efc850ab5a770ee59286c752b7ec38b8e  extracted/m7-stage7-phaseb-1.00-20261127T184903Z/system/sabin/ssboot.bin
a018e8879afafce75e9881b0bf3f14199fe01028354562bc4567af9fcba310d4  extracted/m7-stage7-phaseb-1.00-20261127T184903Z/system/sabin/ssboot_any.bin
1c4f6e5efa247020e18aac30c373b22e6c43b702ffd35819cb59740e0ede0899  extracted/m7-stage7-phaseb-1.00-20261127T184903Z/usr/bin/network.sh
a6340c07f69b64976035d1c3a90a9efe37f22d07cde01493d60b7bf71c8f68a3  extracted/m7-stage7-phaseb-1.00-20261127T184903Z/usr/bin/compat_firmware.sh
5fd89ebf168a0860e900b4df00e402679fc71f0c8e617ae7f1a8f29c723d52b1  extracted/m7-stage7-phaseb-1.00-20261127T184903Z/usr/bin/swap_prepare.sh
bf6484bd060244634f3de5a1c99ca2663e4c5688aedeb7d7874d7ae53a7d3302  extracted/m7-stage7-phaseb-1.00-20261127T184903Z/usr/kmod/usbg_sen.ko
0267d7b05a9250b525b95ebfd2edc04d6aef2dbd4bcabc32e15a197d41e52912  extracted/m7-stage7-1.00-20261126T172306Z/sbin/init
23802d6c9ba3c41c1c0c3096ec6d1ba884ed27374e854416283547755faf4e48  extracted/m7-stage7-1.00-20261126T172306Z/usr/bin/bootin.elf
03a70fd0d0ef269c0de9530398d1e4d7cd8fcb089286cff682ee32d097ad16bd  extracted/m7-stage7-1.00-20261126T172306Z/usr/bin/up.sh
524abb301d5b134e577ccac6b62e9d6a36c0c5a735ac121a8b4ef79a77c053d2  extracted/m7-stage7-1.00-20261126T172306Z/usr/bin/sen.elf
7f1c82e5d91e3b292e0e8dd0901c17946efe43e698338febd1789058f9499016  extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/runtime.txt
ad08a5b12fa344ba595f56c8c9ce12263be4673d15deede1b67f4434309e105a  extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/bin/im.elf
38cba88dab492ed8529ae1ec80636bce64d649229ed790023f3579144860a092  extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/lib/libObj.so
fbc91e66ce27ea917041c33c53e038bfc92e0cf8aea6f254f9dae01acefdfaeb  extracted/m7-kernel-file-20261105T210321Z-78319ef81a60/system/vmlinux.bin
6b276cd909d4d3ad35dc99303148bdc4591d1e885c1f767e301b007646bbe005  extracted/m7-kernel-20261104T223751Z/usr/kmod/liro.ko
9a93127c8e4e4e8c76e4e63d5edd9ecace561a9ddb4958ef381941bf27405ece  evidence/m7-kernel-analysis/analysis.json
d4c990382c1071631863944ee8f09612e78542746d35b0ebe894d7d2bfcb546b  evidence/m7-kernel-analysis/m7.kallsyms
db9b707fc3657c108964c9c2a36be78d5d14909f83d7fe5f125eff1b89eb63fe  extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked/lib/libInfraNetInitializer.so
320750867cd0f1c4d1e72c7baf61d79ad661be8c0aeea69eff0bb1d7d06f186f  extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked/lib/libInfraIPsec.so
6353ae1b674a30bdd6ed6c3c2fc3e55037d8c0faa1c1a98c08b0367e675f2703  sources/bionz-x-research/README.md
ca6ae10b03ed826949d314341361fed3d9a82b7f418b2e9572738b1a21f1b1bb  sources/bionz-x-research/mods/ilce_6400a/README.md
```

```sh
awk '/^[[:xdigit:]]{64}  /' work/stage7-persist/RESEARCH-stage7-3b-wbi-hooks.md | shasum -a 256 -c
```
