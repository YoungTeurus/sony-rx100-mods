# RX100M7 1.00 · Phase B power-cycle evidence and installation decision

2026-11-27 · Offline research · **NO-GO for a flash installer.** The switch retained the imaging process on the observed cycle, but lost the network workspace. The battery cycle restored an earlier process population. No capture followed a running Phase A daemon through either transition. The physical a6400 report does not identify which executable originally caused its debugger to start. No architecture in these records meets all four requirements of untethered operation, owner authentication, stock behavior with the card absent or disabled, and independent USB rollback.

## Inputs and scope

B1–B4 below are the four explicitly assigned JSON receipts in `work/stage7-persist/phaseb-probes/`. B1 is the boot-file extraction. B2/S0, B3/S1 and B4/S2 are the plant, post-switch and post-battery snapshots. I is B1's original text inventory at `extracted/m7-stage7-phaseb-1.00-20261127T184903Z/inventory.txt`. R and W denote the adjacent `RESEARCH-stage7-3b-boot-recovery.md` and `RESEARCH-stage7-3b-wbi-hooks.md`. E numbers denote `sources/bionz-x-research/docs/evidence/` and the matching number/title. For dmesg, d[n] denotes the one-based line *within the decoded log*. Input hashes and an executable comparison are below.

The assigned reference sources establish comparator provenance. The Phase A hardware report establishes whether the daemon was active at the time of a transition. The historical M7 runtime map and kernel symbol list identify the actual loader and the filesystem implementation. Those are the reasons for reading beyond the stage plan's original whitelist. The M7 process and log comparisons below were recomputed from the receipts. The prior ARM findings are attributed expressly to their reports. This is a lifecycle and recovery assessment, not an exhaustive disassembly or a design for persistent code injection. No hardware was accessed.

## 1. What the reference cameras establish

**ILCE-6400, physical.** E0411:68–85 specifies the owner's sequence: USB disconnected, battery removed for about 30 seconds, no SD, screen ready, one stock Wi-Fi attempt, an unexpected warm reboot, then USB reconnected. PID 700 was a live debugger at the post-reboot check. The maps check searched for the *disabled touch library*. It did not identify the first process that mapped the launcher, or even test the launcher mapping with that query. The ring identifies the crashing WLAN task and entry to WARMBOOT (E0411:85–103). There is no timestamped parent/exec record tying PID 700 to the first screen-ready interval. “Cold boot” is the author's name for the physical procedure. It does not establish a fresh Linux userspace start. The raw E0411 receipt directory named on lines 3–6 is absent from this checkout.

E0084:43–53 reports that a **secondary Bluetooth process** loaded a diagnostic library on the physical a6400 while imaging had resumed. This explains how a preload could have an effect without the imaging process restarting. **Attribution of E0411 to that Bluetooth process remains INCONCLUSIVE.** It was a different investigation, different diagnostic library and different PID. The available launcher's child-launch code also cannot identify its own first parent. The checkout's `tools/native_camera/hook/usb_debug_launcher.c:29–42` and E0411:13–19 describe different child-launch sequences. E0411:60–66 identifies its preserved binary by hash; source equivalence is unestablished. E0418b:22–41 distinguishes stock images, process environment and project-installed runtime configuration. None dates a first load on a specific boot.

**ILCE-6400A 1.01, QEMU.** E0681:6–10,22–32 records no-card and card-present guest starts, menu rendering and media removal. Physical installation was pending in that report. Its SD companion and installer are implementation artifacts for that target. Neither those files nor a passing round-trip in a guest observes a physical M7 WBI or S2R. E0138:13–34 verifies the *contents of a prepared recovery card* and host tests. It does not report restoration on an M7 with imaging unavailable. E0410:10–35 documents a WLAN fault and warm reboot on the a6400. A fault-induced reboot is an unsuitable proxy for an ordinary M7 power-switch cycle.

## 2. What ran on the M7

Build `29110_03.2021050601` (I:33–49). B1 has no process array. The other three captures have zero reported PID read races. The table accounts for **every process with a nonempty executable or command line**. Start times are raw kernel ticks. Sources: B2:454–2661, B3:378–2585, B4:378–2603.

| Sample | PID / PPID | Start | Executable | Argument vector |
|---|---|---:|---|---|
| B2, B3, B4 | 1 / 0 | 0 | /usr/bin/launch_shell.elf | /usr/bin/launch_shell.elf · 0 · 1 |
| B2, B3, B4 | 154 / 1 | 99 | /usr/bin/bootin.elf | /usr/bin/bootin.elf |
| B2, B3, B4 | 160 / 1 | 103 | /bin/busybox | /bin/ash · --login |
| B2, B3, B4 | 161 / 1 | 105 | /usr/bin/im.elf | im.elf · debug · s · g · r · u · l · i · a · lazy-global |
| B2 | 1256 / 161 | 1305172 | /bin/busybox | ash · --login |
| B3 | 2868 / 161 | 1322371 | /bin/busybox | ash · --login |
| B4 | 767 / 161 | 3271 | /bin/busybox | ash · --login |

Middle dots above separate arguments. The original byte vectors, with trailing NUL, are preserved in `cmdline_b64`. Of the rows with start tick **strictly greater than 105**, all others have PPID 2 and an empty exe and argv: 172 in B2, 172 in B3 and 171 in B4. The only late userspace process visible in each sample was the service-session shell. The reproduction below emits every late PID, PPID, start tick, exe and argv, including the empty fields. The samples were taken through USB. There is no detached process trace.

| Pair | Rows, old → new | Common PID + PPID + comm + start + exe + argv | Entire rows identical | Old-only / new-only PID |
|---|---:|---:|---:|---:|
| B2 → B3 | 245 → 245 | 81 | 54 | 164 / 164 |
| B3 → B4 | 245 → 247 | 80 | 47 | 165 / 167 |

**Kernel logs.** In chronological order the windows have 178, 178, 181 and 118 lines. Matching full lines with multiplicity across adjacent windows gives **2, 0, 0** shared lines. Removing only the leading kernel timestamp gives **169, 165, 95** shared occurrences, with old-only/new-only counts **9/9, 13/16, 86/23**. These are bounded windows with different starting points. B1 and B2 are distinct captures even where their sizes and line counts agree. No line-count comparison is an exec trace. I:159–337; B2:2662–2666; B3:2586–2590; B4:2604–2608.

* **Switch, PASS for retained S2R.** B2 and B3 share boot UUID `291d2369-ae2e-44eb-b484-e74ab8a89eff`; uptime advances from 13052.39 to 13224.38 s. Imaging PID 161 keeps start tick 105 and gains 14,804 minor faults. The B3 log reports ordinary LIRO resume and task restart at kernel time 0.123259 s. B2:427–453; B3:357–377; W:30–47; B3.d[157–173].
* **Battery, PASS for WBI.** B4 has a new UUID `ff7115aa-eb66-44d3-8731-5f0dfc6673be`, uptime 33.47 s, restored early task identities and reduced counters. The kernel explicitly logs WARMBOOT, low-level resume, LIRO WBI and task restart at 0.783176 s. Detection of the card at 1.530439 s and its partition at 1.742272 s precede the service-console open at 14.084335 s. Neither MMC enumeration nor a process being thawed implies a new userspace program ran. B4:357–377,378–2608; B4.d[1–3,92–118].
* **Automatic exec or dlopen, INCONCLUSIVE.** An endpoint table cannot see a helper that already exited. An old PID does not exclude an intervening exec under that PID. A retained process can load a library without starting a child. None of B1–B4 records time-resolved library mappings or library-load calls. The hotplug setting is empty at sampling (I:52–55; W:79–82). The network and firmware scripts establish conditional behavior; no receipt witnesses WS_SubProcess, a Wi-Fi/BT script, filesystem checker, mount helper or ash starting on *every* USB-detached wake or card mount. Conditional imports or strings cannot establish that proposition, including in im.elf and libObj.so.
* **Stock boot selection, INCONCLUSIVE at reset.** I:44–49,124–132 shows the warm-mode parameters, normal boot mode and an empty mode directory. The M7 kernel reads the two small sabin files as compressor inputs and separately writes snapshot sections and a header to a sector backend. The normal initrd contains the same init binary as the root filesystem. No available observation identifies the selected header, an independent reset-time button path, or a normal Linux cold start forced by a setting. The comparison camera's description of ssboot.bin as the snapshot should not be transferred to M7. Original M7 kernel/ARM and initrd references: R:16–18,53–61,65–71.
* **Latency.** The B3 and B4 timestamps measure kernel events on their respective log clocks. There is no common physical power-on timestamp, first-ready frame or shutter-ready witness, or matched true-cold sample. A post-resume feature could preserve the stock wake path but add contention after thaw. Suppressing WBI would add cold-initialization dependencies on the battery path and would still leave retained S2R to handle. Quantitative differences in user-visible latency and power consumption are unknown.

## 3. Runtime workspace and daemon continuity

| Candidate | M7 evidence | Decision for the existing Phase A release |
|---|---|---|
| /tmp_network | B1:965–1027 measured 1 MiB total, 1,040,384 B free. The 43-byte B2 marker was read back at inode 10280. It was absent in B3, and the directory, run and dhcpd all had new inode numbers. B2:433–453; B3:363–377. | **FAIL** for retained paths. Mount text stayed identical. Replacement of the visible tree is observed; its exact unmount time and actor remain unresolved. Do not keep executable files, working directories or open logs there across S2R. |
| /tmp_ipsec | 128 KiB total (I:18); daemon, ring and card reader are 30,340 + 122,980 + 13,768 = **167,088 B**, before filesystem rounding or logs (`REPORT-stage7-3a-hw.md:15–21`). | **FAIL for capacity** even without keeping the 204,928-byte package. Retention was not measured. |
| /dev and /tmp | Root is read-only ext2. The only distinct mount under /dev is devpts. /tmp and /etc are backed by the same internal VFAT partition. I:4–19,57–84. | Neither is an evidenced writable RAM workspace. Device nodes and devpts serve other purposes. |
| /setting/mlv2/ | /setting has 17,039,360 B free at B1 and is internal VFAT (B1:965–980; I:11–12). | Has space but would make ordinary runtime data persistent, including logs and stale locks. It fails the RAM-only workspace criterion. |
| Dedicated, bounded tmpfs independent of stock subsystems | M7 already mounts two tmpfs instances. The matching kernel map lists shmem_file_setup, shmem_fill_super and init_tmpfs (`evidence/m7-kernel-analysis/m7.kallsyms:3407,3430,23925`). | **Preferred candidate for a RAM-only continuity test.** No private mount instance or dedicated unused mountpoint was qualified. B1–B4 do not establish retention, executable access, free RAM under capture load or safe teardown. No concrete path is qualified as safest. |
| memfd | The M7 identifies as 3.0.27_nl-rt106+ (historical M7 runtime.txt:2). No memfd-named kernel symbol was found. | No demonstrated callable ABI. Anonymous storage alone would not provide the named config, log and child executable paths that Phase A uses. |

**M7A 1.01 comparator only.** W:54–62 traces the network initializer's suspend-time umount retry loop and the separate IPsec lifecycle. The 50-attempt bound belongs to the comparator. It does not establish 50 attempts, delays or failed suspends on M7. Keeping the stock network mount busy would confound the very retention test it is intended to perform.

**Phase A at the power boundary.** The hardware report records armed capture in one live session, clean daemon stop, six-tab menu retirement, then a later check after a power cycle (`REPORT-stage7-3a-hw.md:50–64`). In B2–B4 there was no running Phase A daemon to follow. S2R retention of im.elf supports a hypothesis of retained in-memory state, but cannot certify that its menu still points to valid state, the daemon and subscriptions resume, or old media/file descriptors still designate the current card. Distinguish surviving bytes, a runnable daemon, a fresh ring child and a correct saved capture. No receipt establishes all four. On B4, snapshot rollback makes loss of post-snapshot changes the expected outcome. No separately planted Phase A witness was present before the pull; even the B2 marker was already gone by B3. A fresh boot UUID alone cannot demonstrate a clean, exactly-once authenticated load.

## 4. Decision, rollback and missing inputs

**Keep the RAM-only release as the qualified baseline. No Phase B flash write set or working independent uninstall is established.** Removing the SD card or presenting MLV2.OFF can govern payload activation only after a functioning component inspects the card. It cannot repair an earlier failed startup. Authentication establishes who supplied a package. It does not establish correct handling of absent media, recovery from a hung startup, bounded USB latency, or permission to reuse stale state across a media change.

| Architecture family | S2R / WBI coverage | Recovery and impact |
|---|---|---|
| Explicitly launched Phase A in RAM | S2R continuity open; battery restore can discard it | Demonstrated clean stop and retirement while healthy. Zero internal project files. Does not supply untethered start after battery loss. |
| Stock-supported removable-media extension after wake | No documented qualified M7 interface in this evidence | Best fit for preserving stock wake and normal service **if** such an interface exists. No supported installer or uninstall path can be specified from this record. |
| Global userspace startup change | Neither wake implies fresh startup of the relevant app | Shared service dependencies make recovery and timing uncertain even with no SD. |
| Change the boot image or WBI policy | May replace the battery path; retained S2R remains separate | Highest recovery dependency. No matched cold-boot baseline, validated image-selection evidence, or independently observed selective restore. |

Independent recovery is the decisive missing input. The cold-init analysis shows an early settings check before service gadget loading. A healthy service shell in these measurements is parented by imaging. Neither fact proves that USB repair works with imaging hung. Nor does it prove every independent service route is impossible. No receipt times an unaffected stock service start under that failure or demonstrates rollback of project-owned state while preserving unrelated settings. R:65–71,112; `plans/07-persistence.md:39–51`. The existing Phase A rollback while healthy is documented in `REPORT-stage7-3a-hw.md:62–64`; it is not a flash uninstall.

**Minimum further evidence, by question.**

1. **Runtime retention:** zero further binaries are needed to identify the network-path failure or IPsec capacity failure. The missing observation is a before/after record on a dedicated RAM workspace, with mount identity, process identity, child launch, media identity, stock suspend completion and a successful post-wake capture. Include a USB reconnect without a power transition as a control, and a fresh pre-battery witness. Stock USB-free wake timing needs its own independent observation.
2. **Exact-build attribution of the stock mounts:** the M7 copies of `/usr/lib/libInfraNetInitializer.so` and `/usr/lib/libInfraIPsec.so` would allow comparison against the already-analyzed M7A files. Static analysis can establish what their lifecycle functions do; attribution to a particular transition also needs an observation of that path. W:51–62,84. These DSOs are optional for the capacity and retention verdicts above.
3. **Loader identity:** the historical M7 runtime map at `extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/runtime.txt:114–118,199–202` names glibc 2.11.2. The M7 loader already exists at `extracted/m7-stage7-1.00-20261126T172306Z/lib/ld-2.11.2.so`, SHA-256 `289253ca75a446036ac947fa93ff7d2c2224ffd10293e5c6b599af490b1a348d`. There is no evidence-based need to extract ld-uClibc.so.0. Extracting WS_SubProcess alone would not establish that it runs during a detached transition.
4. **Persistent installation:** no list of extra userland files is sufficient. Missing are exact-build evidence for an independently selected stock recovery environment, its ability to restore only project-owned state when imaging is unavailable, successful return to stock, and an observed supported detached activation event. Until then the defensible change count for /etc and /setting is **zero**. No absent-card, MLV2.OFF or USB performance claim is made for an unbuilt persistent configuration.

## Offline reproduction and custody

Run in the project root. These commands operate on host files only. The Python block checks B1's extracted files and all four log byte digests, accounts for every late task, and computes full adjacent diffs including counters and raw command bytes. To display the full patch text, replace the last two `print` calls that report diff lengths with `print(*patch, sep="\n")`.

```sh
python3 -B - <<'PY'
from base64 import b64decode
from collections import Counter
from difflib import unified_diff
from hashlib import sha256
from pathlib import Path
import json
import re

directory = Path('work/stage7-persist/phaseb-probes')
nonces = ('57c117b5d78d', '7906834d545f', '3f60cb41a0cd', 'c15565b7df8f')
samples = []
for nonce in nonces:
    path, = directory.glob('*' + nonce + '*')
    data = path.read_bytes()
    print(path.name, sha256(data).hexdigest())
    samples.append(json.loads(data))
b1 = samples[0]
for entry in b1['files'].values():
    data = Path(entry['host_path']).read_bytes()
    assert len(data) == entry['bytes'] and sha256(data).hexdigest() == entry['sha256']
inventory = Path(b1['inventory_path']).read_bytes()
assert sha256(inventory).hexdigest() == b1['inventory_sha256']
first_log = inventory.split(b'=== dmesg ===\n', 1)[1].split(b'\n=== statfs', 1)[0]
logs = [first_log.rstrip(b'\n') + b'\n']
logs.extend(b64decode(s['dmesg_b64'], validate=True) for s in samples[1:])
for log, sample in zip(logs, samples):
    assert sha256(log).hexdigest() == sample['dmesg_sha256']
    assert len(log) == sample['dmesg_bytes']
    if 'dmesg' in sample:
        assert log == sample['dmesg'].encode()
for sample in samples[1:]:
    assert not sample['raced_pids']
    rows = sample['processes']
    print(sample['label'], len(rows))
    for row in rows:
        tail = row['stat'].rsplit(')', 1)[1].split()
        argv = b64decode(row['cmdline_b64'], validate=True)
        assert argv == row['cmdline'].encode()
        if int(tail[19]) > 105:
            print(row['pid'], tail[1], tail[19], row['exe'], repr(argv))
for left, right in zip(logs, logs[1:]):
    a, b = (x.decode().splitlines() for x in (left, right))
    for normalize in (lambda x: x, lambda x: re.sub(r'^\[\s*[0-9.]+\] ', '', x)):
        u, v = (Counter(map(normalize, x)) for x in (a, b))
        print('shared / left-only / right-only', sum((u & v).values()),
              sum((u - v).values()), sum((v - u).values()))
    patch = list(unified_diff(a, b, lineterm=''))
    print('log diff lines', len(patch))
for left, right in zip(samples[1:], samples[2:]):
    a, b = ([json.dumps(p, sort_keys=True) for p in sorted(s['processes'],
             key=lambda p: p['pid'])] for s in (left, right))
    patch = list(unified_diff(a, b, lineterm=''))
    print('process diff lines', len(patch))
PY
```

| Receipt filename | SHA-256 |
|---|---|
| 20261127T184903Z-57c117b5d78d-extract-boot.json | 5708508e34d5332a965bf89eb86ccdc0a1ab19b346e8ccdeed7ad1b74770a758 |
| 20261127T185303Z-7906834d545f-s0-plant.json | e355781961cdc8d35c3e7d615471974192cb5a27d4a214b9e22f6b44298e3f35 |
| 20261127T185558Z-3f60cb41a0cd-s1-after-switch.json | 65b5224470eb36d97a3044248f85a3ff9ccd9a7965c956739fbc62e4946ecd10 |
| 20261127T185735Z-c15565b7df8f-s2-after-battery.json | 06d7165ebbbb2136fe15a0dd9536c734cf5a6bd16983341e683f46376a5b726b |

**Collection qualification.** B1 reports all files verified, but its overall extraction flag is false. B2–B4 likewise have a false transition-probe flag. In each receipt StopSenser transport failed and camera exit was unconfirmed. The checked bytes support the scoped observations above; the overall collection/teardown gates are **FAIL**. B1:18–25,891–893,1294; B2:18–25,2667–2671; B3:18–25,2591–2595; B4:18–25,2609–2613.
