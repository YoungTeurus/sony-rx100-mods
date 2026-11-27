# RX100M7 1.00 boot and independent recovery after Step B1

2026-11-27 · build `29110_03.2021050601` · offline examination of the 18:49:03 UTC extraction

**Phase B persistent installation — NO-GO.** The strongest new evidence is the normal boot root itself. Its PID 1 binary is identical to the installed init. On the stock cold-start branch, init mounts the writable volumes and checks setting state **before** asking the kernel to load the service gadget. It can request a service process separately from the imaging launcher. Neither that ordering nor the captured healthy service session establishes an owner-accessible repair path if startup hangs earlier. The extraction also identifies the two small `ssboot*.bin` files as inputs to the kernel's WBI compressor. Treating either file as a restorable copy of camera RAM would be a recovery error. [Boot evidence below; init `0x97d6–0x9876`, kernel `0x601270cc–0x60127130`; stage plan `plans/07-persistence.md:39–51`.]

## Provenance and interpretation

- **R** = `work/stage7-persist/phaseb-probes/20261127T184903Z-57c117b5d78d-extract-boot.json`. **D** = `extracted/m7-stage7-phaseb-1.00-20261127T184903Z`. **I** = D/inventory.txt. **L** = D/dmesg.bin. **P** = `extracted/m7-stage7-1.00-20261126T172306Z`. **A** = `work/stage7-persist/RESEARCH-stage7-3b.md`.
- **PASS, file integrity.** All 25 local file lengths and SHA-256 hashes match R, totaling 3,187,562 bytes. Inventory and dmesg hashes match independently. **FAIL, collection completion as recorded.** R reports terminal disable sent, files verified, stop transport failed, and `extract_boot_ok=false`. These are distinct outcomes. The complete byte list is below. [R:18–25,892–894,954–964,1027–1029,1114–1295.]
- In addition to the assigned inputs I read the original Stage 7.1 stop receipt to compare transport results, the earlier kernel symbol map and metadata to name calls in the matching flat image, and P/usr/bin/up.sh to identify actual updater callers. The normal M7 root is the sole initrd examined. Only ordinary files were materialized in host temporary storage. No target program ran. No device node was created or accessed. Hardware observations below are attributed to the owner's receipts.
- **K** addresses denote little-endian ARM instructions in the M7 flat kernel, file offset = VA minus `0x60108000`. **Init**, BusyBox and user-program VAs denote Thumb code unless identified as data. ELF module offsets are relative to the named section, normally `.text`. Arguments use r0–r3, remaining arguments on the stack, scalar result in r0. An ext2 inode citation gives an offset **in the image**, independent of the mounted path. [Kernel identity and base: `evidence/m7-kernel-analysis/analysis.json:2–26`.]

## Cold start from the normal initrd

**PASS, stock initrd identity and contents.** The image contains an ext2 superblock at 0x400, magic at 0x438, 1,024-byte blocks and 128-byte inodes. There are 408 reachable entries including the root, with 15 directories, 12 regular files, 16 symbolic links, 183 character devices, 180 block devices and two FIFOs. The full inode inventory below includes the special files. The only regular files in /sbin are dosfsck and init. The directory walk finds no /linuxrc, /init, /etc directory, rc scripts, shell, or sen/im executable. A Linux device node name in this image establishes neither a responding device nor successful repair. [Image superblock 0x400–0x46f, root inode at 0x3480, /sbin inode at 0x10280; complete inventory below.]

**PASS, first userspace image.** The command line selects ext2, ram0, an 8 MiB initrd region and /sbin/init. The image file itself is 2,192,384 bytes. Inode 416 (0x10380) is a 27,062-byte dynamically linked ARM EABI5 executable. Both this inode and P/sbin/init hash to `0267d7b05a9250b525b95ebfd2edc04d6aef2dbd4bcabc32e15a197d41e52912`. The image carries its interpreter and libc. On the normal pivot branch the original init continues after changing root. There is no second exec of /sbin/init at that pivot. [I:44–45; R:1129–1134; image inodes 407–411,416; init `main` 0x9736–0x9796; kernel init path A:29.]

| Order on the ordinary local-root branch | Evidence in the exact init |
|---|---|
| Mount /proc, perform boot checks, request first four modules. | 0x96a4–0x96b2, 0x9702–0x970a. First table at 0x131c4, count 4 in r1. |
| Try /rootfs on dnflasha7, then nflasha7 on failure. On success chdir /rootfs, pivot, chroot and move proc into the new root. | 0x9720–0x9734, 0x9736–0x975a, 0x975e–0x977c. Root records 0x13450 and 0x13464. ARM syscall 218 at 0x973c–0x9742, r1 and r2 point to “.” and “initrd”. |
| Try /usr as ext2 (compressed device), ext2 (plain device), cramfs, then vfat as needed. Request /tmp then /etc on nflasha10. | 0x9798–0x97dc; descriptors 0x13374, 0x13428, 0x13360, 0x13388, 0x1334c, 0x1348c. I:7–12 gives the final observed mounts. |
| Try /system on dnflasha3 then nflasha3; request /setting, /log, /lens, /cert. Check setting state, then request second module group if the branch continues. | 0x97e0–0x981c, 0x9820–0x9830, 0x986e–0x9876. A mount record is five words. At 0x8e5e–0x8e66 the helper supplies source, target, type and flags in r0–r3 and data on stack. |
| Check boot mode and service state. One branch prepares swap and mounts sysfs early, another requests sysfs later. Request bootin; a separate condition requests sen; request net_cmdd. Finally hand off PID 1 to launch_shell. | 0x9876–0x987e, 0x9a82–0x9a94, 0x9ae4–0x9b0c, 0x9b1a–0x9b2e, 0x9676. bootin can be called in the foreground at 0x9af2 or via fork/exec at 0x9afa (helper 0x8df4, 0x8e0a). sen is conditional at 0x9b02–0x9b06. |

Table entries are program order for **requests**. Failure checks and alternate roots can skip work. Sibling forks do not order userspace readiness. The imaging launch is in bootin, which has im command strings at 0xa32a–0xa36c and calls libc system at 0x9830. The previously recorded normal process sample shows launch_shell, bootin, ash and im, and its listed early start ticks were identical across two probes. It does not timestamp initialization of im relative to service readiness. [Init 0x970e–0x9720, 0x982a–0x9830, 0x9ae4–0x9b0c; P/usr/bin/bootin.elf 0x982e–0x9834; A:18–31,45–48.]

**Compiled module order.** The first table requests `devno, dmac, ldec, emmc`, in /kmod. nand and lld exist in the image, outside this four-entry table. The second table in /usr/kmod requests, in order:

```text
osal_utm, osal_uipc, utimer, backup, osal_ulogio, input, udate, indctr,
i2c, sircs, stream, stream2, usb_portMonitor, usbg_sen, usb_extcmd,
kikilog, dmm, upm, nfc, grm_ma, grm_gles, accel, mag, compass,
mcmn_drv, ms_drv, mmc_drv, sata_drv, msen_drv, dma330, codec_drv, iris_dial
```

Each name has suffix .ko. Init passes the pointer and count (4 or 32) in r0 and r1 to insmod_drivers. The loop maps each file, calls syscall 128 with image, size and parameters, and advances eight bytes per entry. A completed iteration can follow an earlier load error. usb_insmod.sh contains a separate eight-command list under /kmod; its presence does not establish it as the normal loader. The normal initrd's /kmod directory lacks those USB modules. [Init 0x9706–0x970a, 0x986e–0x9872, 0x8d24–0x8d7c, 0x8dae–0x8dbc, tables 0x131c4–0x131e3 and 0x131e8–0x132e7; image inodes 399–405; D/usr/bin/usb_insmod.sh:3–10.]

### What can be said about writable-volume reads

| Transition | Answer supported by the artifacts |
|---|---|
| Cold start from the supplied root | **PASS for a /setting open attempt before service-module loading.** Init calls check_mode_file via 0x981c and 0x93e4. The file is opened read-only at 0x905e and read at 0x906e only on success. A later service-state check attempts a separate read-only open at 0x8fea after the second module group (0x9876, 0x93ec–0x93f4). The second module table supplies `/setting/ulogio.bin` and `/setting/DmmConfig.bin` as data-file arguments at entries 0x13208 and 0x13268. They exist in I:106,121. Passing a path does not establish that a module successfully opened or consumed it. |
| /etc on cold boot | **PASS for mount order, INCONCLUSIVE for the complete read set.** The /etc volume is mounted before the second group (init 0x97da–0x97dc). The initrd interpreter starts in a root with no /etc. Executables launched after the pivot encounter a different filesystem. Stock ash can attempt /etc/profile on its login branch (BusyBox 0x183c8–0x183e4, file offset 0x3028d). B1's directory listing shows no profile (I:87–97). It supplies no open/exec trace. |
| WBI restore | **INCONCLUSIVE for either /setting or /etc on this transition.** The early files above describe cold-start code. A resume callback or a restored userspace thread can run without replaying those opens. The B1 sample shows the LIRO zero-flag event, while the previously reported positive WBI branch belongs to a different sample. [L:145–162; A:18–31.] |
| Ordinary thaw | **PASS for device resume and task thaw; INCONCLUSIVE for subsequent file reads.** A kernel callback can perform I/O while tasks are frozen, and a thawed task can perform I/O without exec. Neither a driver name nor an absence of file names in dmesg establishes an empty read set. [L:91–103,119–120,141–165; K 0x60167090, 0x601670cc–0x601670dc.] |
| /system | Two named files are actual conditional compressor inputs, as traced below. The inventory also lists the kernel, initrd and other binaries (I:134–150). Only a matching pre-Linux consumer or timed trace can identify which media reads actually occurred on a specific power transition. |

An exhaustive run-specific file map is **INCONCLUSIVE**. B1 contains one mount listing and a bounded kernel log, without per-open events, per-process filenames or early-loader storage telemetry. The stock network wrapper starts WS_SubProcess; compat_firmware.sh handles a WLAN add event and gets its payload from /usr/wlan/ath. Neither script demonstrates an autonomous boot or restore from the SD card. [I:4–19; L:1–2,175–178; D/usr/bin/network.sh:1–3; D/usr/bin/compat_firmware.sh:10,17–31.]

## WBI inputs, snapshot writing and restore boundary

**PASS, the sabin pair belongs to the compressor.** I:45 binds cmpr.path and cmpr.path2 to the two sabin files. The K parameter descriptors at 0x60492108 and 0x604920f8 point through 0x603d04b0 and 0x603d049c to two 64-byte path buffers at 0x604feaec and 0x604feb2c. K 0x6049c4d0–0x6049c4d4 registers the compressor operations at 0x604e1b08. That table includes cmpr_init (0x60127068) and cmpr_deflate (0x60126b64). cmpr_init loads the first file at 0x601270ec and, if configured and the first succeeds, the second at 0x60127130, on a 128-byte-aligned boundary. cmpr_load_file takes (path, destination, remaining space) in r0–r2. It stats, bounds-checks, opens, reads, compares the count to the stated length, performs DMA cache maintenance and closes. [K 0x60126f3c, 0x60126f5c–0x60126f94, 0x60126fcc–0x60127034; K 0x60127188 contains the path-structure base 0x604feaa0.] The files are 11,280 and 9,648 bytes. Each contains its own file length at offsets 0x0c, 0x14 and 0x18 (little-endian). This establishes a consumer and direction of transfer. The internal instruction/data format remains unidentified. [R:1150–1163; both files offsets 0x00–0x1b.]

**PASS, there is a separate sector-backed image writer.** On a creation branch, K cxd_create_warmbootimage counts pages (0x6011c50c), sends initial data (0x6011c570), flushes (0x6011c57c), sends sections (0x6011c598), flushes again (0x6011c5e4) and rewrites the header (0x6011c65c). wbi_rewrite_header calls the selected backend at offset +0x24; wbi_read_header uses +0x28 (K 0x6011ea04–0x6011ea10 and 0x6011ead0–0x6011eadc). The normal initrd actually contains an eMMC provider. Its register call is at emmc.ko .text+0x834c, with relocations to emmc_wbi_open/read_sector/write_sector/close at .text+0x8430–0x843c. Code stores the write pointer four bytes before the read pointer (.text+0x8334–0x8348). These are calls into a device backend. The compressor input filenames do not identify a snapshot output filename. [Image inode 403, offset 0xfd00; kernel and module sites above.]

**PASS for stock swap preparation and snapshot primitives.** When the expected partition directory exists, the stock script configures compswap for ssboot with nflasha8 backing and sets disksize_kb to 60000. Its alternative returns 1. A branch in init calls this script through system; the branch can be skipped. K ssboot_prepare can allocate a bitmap, enable swap, shrink memory and wait for I/O; ssboot_snapshot creates the bitmap and copies critical pages; ssboot_write builds a section list and calls a registered writer (r0 = image descriptor, r1 = writer-specific argument at K 0x60167954–0x60167960). K warm_boot_pm_begin also has conditional swap setup. Preparing swap does not prove that partition 8 holds the selected WBI image, or that a snapshot was saved during B1. [D/usr/bin/swap_prepare.sh:3–22; init 0x987a–0x987e, 0x9a8e–0x9a94; K 0x60167808–0x60167850, 0x601678d0–0x601678e8, 0x60167920–0x60167960, 0x6011c9ec–0x6011ca10.]

**INCONCLUSIVE, full restore lifecycle.** The pack includes normal Linux initrd, kernel-side functions and sector callbacks. It supplies no trace of reset-time media selection, selected WBI partition/header, validated physical image, restored task set, or capture timestamp. The observed B1 flags and driver messages describe Linux *after* low-level resume. The storage source and age of a particular restored task image remain open. [R:1114–1290; I:44–49; L:68–78,145–162; A:27–35.] ldr_drv.bin decodes as ARM at file offset zero: it tests r0, returns −1 for null, otherwise reads fields at 0, 4 and 8 and branches to file offset 0x194 (0x00–0x18, load base unspecified). bonobo.bin begins with bytes `b7 72 00 00 06 31 31 00` and contains patterned records at 0x18–0x6f. B1 supplies neither a matching caller ABI for these two files nor evidence that either selected recovery. Their startup order, execution processor for bonobo, and recovery roles are unqualified. [I:134–142; R:1136–1148.]

## Recovery with imaging unavailable

| Proposed stock route | Verdict and evidence |
|---|---|
| Normal USB service after an early /setting failure | **FAIL as a guaranteed fallback.** A hang at the first setting check would block the same init thread before the second insmod call. A hang solely inside a separately forked imaging child need not block init, but a separate sen fork is conditional. Neither scenario establishes a working repair service. [Init 0x981c, 0x93e4, 0x905e, 0x9872, 0x9ae4–0x9b0c.] |
| Normal USB after an /etc failure | **INCONCLUSIVE.** /etc is visible to subsequently launched dynamic programs, including service components. Loading a kernel driver precedes knowing whether its userspace dependencies start, USB enumerates, and a repair operation can complete. B1 recorded NORM and an active ash console. The prior two successful probes both had im running. [Init 0x97dc, 0x9872, 0x9b02; R:893–894,954–958; A:18–25,52,60.] |
| Port monitor, gadget, mass storage, still image, external command | **PASS for stock functions; INCONCLUSIVE for recovery.** usb_portMonitor.ko has usb_portMonitor_resume (.text+0x2070), usbg_cmn.ko constructs endpoint lists (.text+0x2bc), usbg_storage.ko probes mass storage (.text+0x37dc), usbg_stillimage.ko has init_module and usbg_cmn_copy_probe_info (.text+0x30cc), and usb_extcmd.ko has extcmd_ioctl (.text+0xc00). Neither mass storage nor still image is an entry in the 32-module cold-init table. None of these symbols proves a stock service exposing a failed internal volume for selective repair. [Init table 0x131e8–0x132e7; I:4–19; module symbols above.] |
| Updater | **INCONCLUSIVE for independent entry.** The stock update script needs running userland and persistent mode bookkeeping. ud_datcnv.elf is a userspace converter (getopt 0x87ee, fread/fwrite 0x8874/0x88d0); ud_send_lsi.elf calls Backup_read, allocates a message, sends it and waits for a response (0x8746, 0x876c, 0x8794, 0x87b0). P/usr/lib/libupdaterufp.so exports udtr_ufp_init at 0x19fc and libupdatertalk.so exports Dec_ScrambleInit at 0x624. B1 contains no independently selected updater root and no receipt for restoring specific files with im dead. [P/usr/bin/up.sh:3–6,124–145,184–215,231–253,294–299; R:1114–1290.] |
| Button, SD, backup and watchdog | **INCONCLUSIVE.** L shows input resume and card detection; mmc_drv.ko has mmc_resume at .text+0x11e4, backup.ko has backup_resume at .text+0xcc. Those are driver callbacks. The normal root has no card recovery script, and B1 records neither a reset-time button selector nor a signed SD restore followed by a stock boot. A watchdog reset can encounter the same persistent fault on the next start. [L:101–106,141–142,162–165; initrd inventory below; I:45; A:64–74.] |

### What the two StopSenser errors establish

**FAIL, host transport success in both runs. INCONCLUSIVE, immediate disconnect or re-enumeration.** Both stop records identify GenericUsbDriver, GenericUsbException, transport_ok=false and no confirmed camera exit. Neither records a controller error code, endpoint-zero status transaction, disconnect timestamp, new address, or subsequent device identity. [`work/stage7-persist/collect-stage7-20261126T172306Z-39dc7f327b95.json:11–19`; R:18–25,1292–1294.]

In usbg_sen.ko, core_vendor compares the eight incoming bytes (r1) with two records obtained through driver state. A match can issue usb_gadgetcore_stop_other_driver and then queue an event; it returns 2 even on the unmatched path. That call's target is the *other* driver. A separate core_stop callback stops the line discipline, cleans endpoint state and queues an event. sen.elf separately resolves a userspace stop operation and invokes it indirectly (its stop name at file offset 0x395b, dispatch at Thumb 0xa25e–0xa270, dlsym at 0xb4c8). libsencore.so's exported senser_stop calls SenserIfStop, which obtains the Usb singleton. The code supplies no on-wire timing for either receipt. The exact live contents of the compared records and the handling of the failed transfer by the gadget core are absent from the B1 trace. [usbg_sen.ko .text+0x248–0x294, +0x2ac–0x318, +0x4cc, +0x528, +0x54c, +0x570; libsencore.so 0xf44c–0xf45e, 0x116b2–0x116c2.]

**Hypothesis.** A gadget transition could race host completion. A transport or endpoint failure without a completed stop is also compatible with the receipts. The close visible at 46.895842 belongs to an **earlier** console session. The B1 shell banner matches the later open at 11632.977081, and the captured log ends at that open. Assigning the earlier close to the B1 stop would reverse the recorded order. [L:167–178; R:79–82,892–894,1292–1294.] A passive, correlated bus trace covering setup through status and subsequent enumeration would distinguish the cases.

## Stock BusyBox ash history

**PASS for compiled behavior; INCONCLUSIVE for an actual flash write during B1.** The 228,444-byte binary and shell banner agree on BusyBox 1.13.4. On the interactive branch ash looks up HISTFILE. If unset and HOME is available, it joins HOME and .ash_history and installs that value. The default therefore depends on the process's HOME. The program latches the history path into the line editor before the top-level command loop. The HISTFILE variable-table entry has a null callback. B1's assignment is itself a command sent to an already started shell. It cannot establish the destination used when reading that command or certify that subsequent history was redirected. [R:29–32,894,1122–1128; BusyBox file offsets 0x2e4c3, 0x30272–0x3028c; Thumb 0x18388–0x183b4, 0x1842e–0x18444; table words at VAs 0x2fa70–0x2fa78.]

The line editor reads its file when enabled (0x29804–0x29818) and keeps up to 15 nonempty entries (0x29844–0x2987c). On completion of an eligible input line it checks for empty input and an immediately repeated command, shifts out the oldest entry when full, then opens the latched path in **w** mode, prints each retained entry as “%s\n” and closes it before returning the input to the caller. This can rewrite history **per accepted line, before the command executes**. The write does not depend on normal shell exit. [BusyBox 0x11618–0x11636, 0x29be4–0x29c1a, 0x29c28–0x29c92, 0x29cd0–0x29cd8. fopen64 veneers 0x2b11c and 0x2b134 with mode pointers at 0x2b124 and 0x2b13c; write-mode string 0x3bf0d; format string 0x3bfc5.] A tcgetattr failure or clear echo flag takes a plain fgets route that returns without the history writer (0x297b4–0x297ee). The shell's job-control warning does not record that termios result. The actual HOME, cached destination, open result and before/after history file were not sampled in R. An unconditional zero-write claim would exceed R:7–13,894.

## Capacity and the captured transition

**PASS, B1 filesystem measurements.** Every lstat and statfs64 returned 0. For all four rows fragment size equals block size and free blocks equal available blocks. The last mount is volatile tmpfs. /tmp aliases /etc on the same VFAT device. Its space must only be counted once. Free space is specific to the sample with the collector staged. [R:962–1027; I:7–19.]

| Mount | Device | Type | Bytes/unit | Total units | Free/available units | Total bytes | Free/available bytes |
|---|---|---|---:|---:|---:|---:|---:|
| /setting | 252:2 | VFAT | 16,384 | 1,278 | 1,040 | 20,938,752 | 17,039,360 |
| /etc | 252:10 | VFAT | 16,384 | 766 | 413 | 12,550,144 | 6,766,592 |
| /system | 252:3 | VFAT | 16,384 | 1,814 | 337 | 29,720,576 | 5,521,408 |
| /tmp_network | 0:10 | tmpfs | 4,096 | 256 | 254 | 1,048,576 | 1,040,384 |

**PASS, one resume sequence in the retained log.** The 7,661-byte, 178-line log starts mid-message. Kernel times below belong to the clock shown in that log. Treating their differences across low-level resume as wall-clock time would be invalid. [L:1–2,60–77,98–100; R:954–961.]

| Kernel time (s) | Event and source |
|---:|---|
| 611.873312–611.994103 | Tail of suspend, late device suspend then secondary CPU shutdown. L:2–67. |
| 0.033327–0.046554 | Low-level resume completes, CPUs return, early device resume completes. L:68–77. |
| 0.048118–0.073598 | eMMC, backup, USB port monitor and MMC resume callbacks. L:91–103,119–120,141–142. |
| 0.073724 | LIRO prints entry_resume:635c6078(0). Zero means the combined WBI predicate was false for *this* callback. It does not identify the physical switch action. L:145–149; liro.ko .text+0xfc–0x140, +0x24c–0x258; A:27. |
| 0.097614–0.367867 | Device resume completes, tasks restart at 0.123179, MMC card detection follows. L:161–165. |
| 11.839357–47.059371 | Receive error, line discipline starts and opens, console enables, later closes/stops; another receive error. L:166–174. |
| 11632.359879–11632.986317 | Line discipline starts again. Console enables at 11632.977081. The final message records completion of opening the line discipline. L:175–178; R:894. |

## Decision and remaining evidence

**FAIL for Phase B recovery qualification.** No architecture in the assigned evidence satisfies both untethered cold-start persistence and independent rollback under failed startup. In particular, a separate service child helps only if the stock parent reaches it, its dependencies initialize, and a repair endpoint actually works. A design wholly on removable media would avoid leaving a broken internal component with the card removed, but B1 has no demonstrated stock trigger for it across the required transitions. The plan calls for an offline byte-range manifest and reproducible build, a hardware stock restore, and recovery proven on paper and in the model if power cycling cannot clear a boot failure. No failed-boot restore was modelled or observed here. The B1 receipt describes a responding camera. [`plans/07-persistence.md:39–51`; A:89–109; init 0x981c–0x9876, 0x9ae4–0x9b0c.]

**B2–B4 have a narrower question to answer.** A bracketed baseline, battery-retained switch cycle, and separately owner-observed loss of power can establish whether a particular RAM marker survived each transition. Interpret it alongside boot ID, uptime, LIRO flag, kernel-clock discontinuities, task start ticks and counters. A pre-existing UUID can be restored with snapshot memory; identical early PIDs alone do not establish continuity. Battery removal alone does not establish a snapshot-free boot. Neither a surviving marker nor a successfully reconnected healthy service validates recovery with a failed imaging process. The decision requires an independently identified stock startup/restore path, plus offline fault cases for a missing, rejected, crashing or hanging startup component and a verified selective restoration that preserves per-unit state. [A:18–39,99–109; I:34–49,99–122; R:18–25; `plans/07-persistence.md:39–51`.] This report adjudicates only the named B1 receipt. Later transition receipts are outside this assignment.

## Complete normal-initrd inventory

Each number is the ext2 inode. Its on-image byte offset is 0x3400 + (inode − 1) × 0x80 for every entry listed. Types follow the inode mode. Directory rows omit the self and parent entries. Ordinary-file lengths and digests refer to the data obtained through the inode block map. The 408 entries include the root.

**Directories**

```text
2 /   11 /dev   85 /dev/net   176 /dev/usb
280 /dev/snd   293 /dev/bus   294 /dev/bus/usb   328 /dev/pts
330 /dev/jet   352 /dev/input   399 /kmod   406 /lib
412 /proc   413 /rootfs   414 /sbin
```

**Regular files (bytes, SHA-256)**

```text
400 /kmod/nand.ko 152284 c131eb3341c6e2af324688a84f9a78449c91ac5aa4a7b87b8d3d6025b8579e5d
401 /kmod/lld.ko 82724 37c2da9d399edf7fd56957a9c338ee398c2f2bbdc7093ebeda33c2f9aa2e9816
402 /kmod/dmac.ko 17384 76b82e01ce0af637871c17cb2db25046e7897bd6e9aed3d385a7d7e8ed4007bf
403 /kmod/emmc.ko 217660 a1b75d0ca670283c65f19405b036c8f5f4d6d903a0c335ce00e9639751a63ce2
404 /kmod/ldec.ko 16104 3d73995e8d1c287cf4624989c2a040cb4f00c91c37c8427da4deb00eb2c4c97b
405 /kmod/devno.ko 4308 4ea5027c413d8efdc514958a7efedad7948c444b6e18bcec8e72cef5ccf47379
408 /lib/libc-2.11.2.so 984276 246a8458ae6cfa16b4791606f9bfbae0b0339faba199cf7eeaa56a53154b4a72
410 /lib/ld-2.11.2.so 101720 289253ca75a446036ac947fa93ff7d2c2224ffd10293e5c6b599af490b1a348d
411 /lib/libgcc_s.so.1 252717 d2b341668d65bc054fc21f6a739a5b198c8caa9a9044f693bfaae842f16375c4
415 /sbin/dosfsck 64822 7c36c8d21d050bd8eb06c4ff849ac0be947a9cc8b351f7d37b30a1601f617922
416 /sbin/init 27062 0267d7b05a9250b525b95ebfd2edc04d6aef2dbd4bcabc32e15a197d41e52912
417 /version.txt 19 f0289d325aff2df6fd421e63c70c7936419604709c740c3b1fae4e0222c5abc4
```

**Symbolic links (target)**

```text
14 /dev/satauhs -> sata
28 /dev/core -> /proc/kcore
35 /dev/stderr -> fd/2
109 /dev/ttycons -> ttyAM0
138 /dev/satauhsb -> satab
139 /dev/vcsa -> vcsa0
143 /dev/ttyBT -> ttyAM1
212 /dev/stdin -> fd/0
221 /dev/fd -> /proc/self/fd
228 /dev/stdout -> fd/1
306 /dev/satassd -> sata
323 /dev/vcs -> vcs0
326 /dev/ram -> ram1
365 /dev/satauhsa -> sataa
407 /lib/ld-linux.so.3 -> ld-2.11.2.so
409 /lib/libc.so.6 -> libc-2.11.2.so
```

**FIFOs**

```text
338 /dev/jet/TransferJet_APM2PCLCD   340 /dev/jet/TransferJet_PCLCD2APM
```

**Character device names**

```text
16 /dev/port   17 /dev/satab   19 /dev/tty12   20 /dev/vcs14
24 /dev/ttyUSB5   30 /dev/vcsa8   31 /dev/tty13   33 /dev/ttyUSB3
34 /dev/sio4   37 /dev/vcsa5   38 /dev/vcsa13   40 /dev/vcs7
41 /dev/tty17   44 /dev/vcsa14   50 /dev/vcs16   51 /dev/boss-t3
54 /dev/backup   57 /dev/urandom   60 /dev/vcsa0   65 /dev/console
66 /dev/crash   67 /dev/tty6   76 /dev/fuse   75 /dev/hdmi_input
79 /dev/ttyAM0   82 /dev/ttyUSB6   83 /dev/mem   84 /dev/tty15
86 /dev/net/tun   88 /dev/satac   89 /dev/ttyACM2   102 /dev/vcsa16
103 /dev/ttyUSB4   104 /dev/vcs2   107 /dev/vcs4   108 /dev/vcs9
111 /dev/qcqmi0   114 /dev/vcs15   116 /dev/tty16   120 /dev/satad
124 /dev/dmpgles2   127 /dev/ppp   128 /dev/vcs19   130 /dev/tty19
131 /dev/mmca-char   134 /dev/vcs18   135 /dev/ttyUSB10   140 /dev/vcs12
142 /dev/ttyS3   145 /dev/mmcd-char   149 /dev/full   150 /dev/tty7
151 /dev/vcs17   154 /dev/tty0   157 /dev/hdmi   158 /dev/vcsa12
163 /dev/ttyUSB8   166 /dev/vcs8   168 /dev/vcs0   170 /dev/uipc
172 /dev/tty14   173 /dev/vcsa2   174 /dev/ptmx   177 /dev/usb/cur
178 /dev/usb/usbcore   179 /dev/usb/sicd_core   180 /dev/usb/buspwric   181 /dev/usb/otgcore
182 /dev/usb/std   183 /dev/usb/usb_extcmd   184 /dev/usb/scsi   185 /dev/usb/massstorage
186 /dev/usb/kikilog   187 /dev/usb/buspwr   188 /dev/usb/event   189 /dev/usb/sen
190 /dev/usb/swic   191 /dev/usb/sicd_event   192 /dev/usb/adb   193 /dev/usb/vspe
194 /dev/usb/usbg_bspwr   195 /dev/usb/portmon   196 /dev/usb/sicd_data   197 /dev/usb/ter
198 /dev/usb/gadgetcore   199 /dev/tty4   200 /dev/vcsa4   204 /dev/uio0
205 /dev/kmem   206 /dev/rtc   207 /dev/ttyAM3   209 /dev/ms-char
213 /dev/ttyACM1   214 /dev/ttyUSB0   216 /dev/fb1   219 /dev/emif
220 /dev/tty11   222 /dev/vcsa1   223 /dev/hdmi_external_tx   225 /dev/ttyS1
231 /dev/vcsa9   232 /dev/mmce-char   234 /dev/stream   236 /dev/vcsa18
237 /dev/ttyUSB1   240 /dev/vcsa6   241 /dev/boss-t1   242 /dev/random
243 /dev/ttyACM0   244 /dev/ttyUSB11   246 /dev/dma330   247 /dev/rmon
252 /dev/tty9   254 /dev/vcsa11   255 /dev/sio2   256 /dev/tty10
259 /dev/tty8   262 /dev/vcs11   263 /dev/zero   264 /dev/sataa
266 /dev/sio3   269 /dev/qcqmi2   271 /dev/sata   273 /dev/boss-t2
275 /dev/ttyAM2   277 /dev/vcsa15   279 /dev/mmcb-char   281 /dev/snd/timer
282 /dev/snd/pcmC0D0p   283 /dev/snd/controlC0   284 /dev/snd/pcmC0D0c   286 /dev/qcqmi1
288 /dev/vcsa17   290 /dev/vcs6   296 /dev/mcmn   297 /dev/ca
309 /dev/null   299 /dev/ttyUSB9   301 /dev/ttyS2   303 /dev/vcsa10
305 /dev/vcs13   307 /dev/ttyUSB2   310 /dev/ioexp   311 /dev/ttyUSB7
313 /dev/gpio   317 /dev/vcsa7   318 /dev/ldec   319 /dev/bootimg
321 /dev/tty3   322 /dev/tty   325 /dev/sxs_blk0   329 /dev/vcs1
331 /dev/jet/adj_drv   332 /dev/jet/pcl_obex   333 /dev/jet/wrapper   334 /dev/jet/event
335 /dev/jet/obex   336 /dev/jet/scsi_tgt   337 /dev/jet/pclc_ctr   339 /dev/jet/pclc_msg
345 /dev/cec   347 /dev/vcsa19   348 /dev/fb0   353 /dev/input/event2
354 /dev/input/event1   355 /dev/input/event0   356 /dev/vcs3   358 /dev/vcs5
359 /dev/tty2   360 /dev/ttyAM1   361 /dev/uinput   367 /dev/vcs10
370 /dev/dmac   374 /dev/sxs_blk1   378 /dev/sio0   379 /dev/tty5
380 /dev/sio1   381 /dev/stream2   383 /dev/mmcc-char   385 /dev/tty18
388 /dev/tty1   392 /dev/ttyS0   397 /dev/vcsa3
```

**Block device names**

```text
12 /dev/nflashaB0   13 /dev/dnflasha24   15 /dev/ram7   18 /dev/dnflasha14
21 /dev/mmcab1   22 /dev/ram13   23 /dev/mmcda   25 /dev/mmccd
26 /dev/nflasha23   27 /dev/nflasha20   29 /dev/nflasha16   32 /dev/nflasha21
36 /dev/sda   39 /dev/ram3   42 /dev/nflasha4   43 /dev/ram4
45 /dev/ram16   46 /dev/nflasha2   47 /dev/mmcbc   48 /dev/ms6
49 /dev/mmcba1   52 /dev/ram9   53 /dev/dnflasha3   55 /dev/mmce
56 /dev/nflasha22   58 /dev/mmcad   59 /dev/mmcaa1   61 /dev/dnflasha27
62 /dev/mmcb4   63 /dev/ms1   64 /dev/mmcd   68 /dev/mmcdb
69 /dev/sda4   70 /dev/mmcdc1   71 /dev/sdb   72 /dev/ram12
73 /dev/dnflasha17   74 /dev/ram6   77 /dev/nflasha9   78 /dev/mmcbc1
80 /dev/nflasha28   81 /dev/sdc   87 /dev/ms8   90 /dev/mmcac
91 /dev/dnflasha7   92 /dev/mmcbd1   93 /dev/mmcc   94 /dev/ram2
95 /dev/mmcc1   96 /dev/nflasha19   97 /dev/compswap   98 /dev/mmcdd1
99 /dev/mmccd1   100 /dev/loop6   101 /dev/mmce2   105 /dev/dnflasha6
106 /dev/dnflasha15   110 /dev/ram1   112 /dev/mmcb1   113 /dev/mmca3
115 /dev/mmcd4   117 /dev/sdb1   118 /dev/loop4   119 /dev/dnflasha19
121 /dev/mmcea   122 /dev/ram10   123 /dev/mmcbd   125 /dev/mmcd3
126 /dev/loop2   129 /dev/dnflasha29   132 /dev/ram0   133 /dev/nflasha12
136 /dev/loop3   137 /dev/mmce4   141 /dev/mmcb3   144 /dev/ram11
146 /dev/dnflasha22   147 /dev/ms2   148 /dev/mmcc3   152 /dev/mmccb1
153 /dev/nflasha17   155 /dev/nflasha   156 /dev/sda2   159 /dev/mmcac1
160 /dev/nflasha15   161 /dev/nflasha3   162 /dev/nflasha11   164 /dev/mmca4
165 /dev/mmcec1   167 /dev/mmca2   169 /dev/ram8   171 /dev/mmcca1
175 /dev/loop1   201 /dev/nflasha8   202 /dev/dnflasha30   203 /dev/loop5
208 /dev/loop0   210 /dev/nflasha30   211 /dev/nflasha7   215 /dev/ram14
217 /dev/nflasha18   218 /dev/ms4   224 /dev/mmccc   226 /dev/nflasha14
227 /dev/sr1   229 /dev/nflasha24   230 /dev/ram15   233 /dev/mmcdb1
235 /dev/nflasha26   238 /dev/nflasha29   239 /dev/mmcaa   245 /dev/sdd
248 /dev/mmca1   249 /dev/nflasha5   250 /dev/mmcbb1   251 /dev/ms5
253 /dev/dnflasha4   257 /dev/mmcd1   258 /dev/nflasha10   260 /dev/mmcb
261 /dev/nflasha27   265 /dev/dnflasha23   267 /dev/mmcc4   268 /dev/mmccc1
270 /dev/nflasha25   272 /dev/mmcb2   274 /dev/mmccb   276 /dev/mmcdd
278 /dev/mmcc2   285 /dev/dnflasha9   287 /dev/mmce3   289 /dev/dnflasha20
291 /dev/ms7   292 /dev/dnflasha5   295 /dev/dnflasha11   298 /dev/mmcad1
300 /dev/nflasha13   302 /dev/dnflasha   304 /dev/dnflasha8   308 /dev/dnflasha18
312 /dev/mmcab   314 /dev/dnflasha31   315 /dev/mmcdc   316 /dev/mmced1
320 /dev/mmca   324 /dev/mmcda1   327 /dev/loop7   341 /dev/mmcca
342 /dev/mmcbb   343 /dev/mmcea1   344 /dev/ms9   346 /dev/mmced
349 /dev/mmcec   350 /dev/dnflasha25   351 /dev/mmceb   357 /dev/dnflasha1
362 /dev/sda3   363 /dev/dnflasha26   364 /dev/ms3   366 /dev/nflasha1
368 /dev/sr0   369 /dev/mmce1   371 /dev/dnflasha16   372 /dev/nflasha31
373 /dev/sdc1   375 /dev/dnflasha13   376 /dev/mmcba   377 /dev/dnflasha12
382 /dev/nflashaB1   384 /dev/sda1   386 /dev/ms   387 /dev/nflasha6
389 /dev/sdd1   390 /dev/dnflasha2   391 /dev/ram5   393 /dev/mmceb1
394 /dev/dnflasha21   395 /dev/dnflasha28   396 /dev/dnflasha10   398 /dev/mmcd2
```

## Input SHA-256 manifest

B1 device-relative names below are under D. Original expected digests and byte counts appear in R:959–961,1028–1029,1114–1290.

```text
SHA-256                                                           bytes  path
f0289d325aff2df6fd421e63c70c7936419604709c740c3b1fae4e0222c5abc4        19  /version.txt
e6ebb87e6de8814f994c18ed194a22bfb463fe55cb8f66aef94b22fb6103905f    228444  /bin/busybox
f038a727293abf956eba2098425accb419d9c10426763fc5ca6da9c4f06834bc   2192384  /system/initrd.img
63b615f9e312ace24df10c839baee05f76c90b4935257fc6c429b070c30a6b7a      7012  /system/ldr_drv.bin
08483ff1742589c5dd6ba8ebdbb2d4a52d9909f8addf1d99ec655d34d2616c8e    172144  /system/bonobo.bin
a707c285f8f1768481d0602e367c791efc850ab5a770ee59286c752b7ec38b8e     11280  /system/sabin/ssboot.bin
a018e8879afafce75e9881b0bf3f14199fe01028354562bc4567af9fcba310d4      9648  /system/sabin/ssboot_any.bin
bf6484bd060244634f3de5a1c99ca2663e4c5688aedeb7d7874d7ae53a7d3302     31204  /usr/kmod/usbg_sen.ko
8200c93a825eb107a4d9db0196743920556eeb60660f7310df5c269977978add      4140  /usr/kmod/usbg_cmn.ko
c60dec80155719a4afc1de5dde7663fc3a29e9e1dfdedd636aacf6dae749c8c4     67212  /usr/kmod/usbg_storage.ko
595828c171135637f93f40bc9e692b78972e390492a0a02aadeddee40033cd55     29212  /usr/kmod/usbg_stillimage.ko
544f0c53fbf971f1db6f18767c9ecac0cbbb7ba04cddaa4fc067c4051942d6b7     14068  /usr/kmod/usbg_buspower.ko
0c4042638929c72a4aa9db10428b35dcbc674137d30a7cbc782094c3233a675e     13600  /usr/kmod/usb_buspwr.ko
bab7b4858c5c3b5695f89aa0de96350c7bf7a684e83bbf6408d5617dd6711764     14808  /usr/kmod/usb_extcmd.ko
fd522668bc6b000130432f973fbff8a02b2a8120fb1caa4708e32e3749f52844     18864  /usr/kmod/usb_portMonitor.ko
a9933dabb87a11bb85367b7858a63ad39a7f02566ea13e9fe161861864e233fb     39996  /usr/kmod/usb_max14648.ko
c05890a71b80d1d76982bfa9a6bc66272d5e267be77fd82ebc442b4a0ee4d9eb     73828  /usr/kmod/backup.ko
295ff8bcc11556a25a7444cd5af6c193e43581cfbd764ff6341c88a4abceddf4    240852  /usr/kmod/mmc_drv.ko
f796923b4db3277c90105df3d8801cc21f7828f443df58dd761a80b5b4706f2a      6780  /usr/kmod/mmcioWrapper.ko
d4711014b6d64982131570496f120ae8378db8b00082d6d8cceb4cf1b5f80160      5940  /usr/bin/ud_datcnv.elf
d01a4749b1f55c40cc8064289900d546bdf500f3ddc1f8abf8de997fa298c214      4324  /usr/bin/ud_send_lsi.elf
1c4f6e5efa247020e18aac30c373b22e6c43b702ffd35819cb59740e0ede0899        39  /usr/bin/network.sh
5e885d964a9ab9c9e18c23453af42f7ff7da57d0aa446c1812b385206f3d8f7a       225  /usr/bin/usb_insmod.sh
a6340c07f69b64976035d1c3a90a9efe37f22d07cde01493d60b7bf71c8f68a3      1043  /usr/bin/compat_firmware.sh
5fd89ebf168a0860e900b4df00e402679fc71f0c8e617ae7f1a8f29c723d52b1       496  /usr/bin/swap_prepare.sh
b6c465b158bdc16d3c65e6d101d2d7ac78c23b3616078165862a3ab15656ee73      7661  dmesg.bin
8d055ace281516993127d17f07e510533af55eb8cb4252d33dd3c925b6f02bf7     20897  inventory.txt
```
Additional inputs, paths relative to the project root:

```text
b2b68f77d351478c06223bb036d21348e23f43611789084936e6fff6080f0a27  AGENTS.md
444c7b092f85880367ff51cae84aaf7f05a8492a8d3b8866dda3f758beb6d7f7  STATE.md
f09c892ce41a62c552cece871faeb19a619673159b7f336fb9d80e7c244008d6  plans/07-persistence.md
5f30fd9ba9ca30e77d5f529cf9714f082280b6e3162015214f1eb403a13b9108  work/stage7-persist/RESEARCH-stage7-3b.md
5708508e34d5332a965bf89eb86ccdc0a1ab19b346e8ccdeed7ad1b74770a758  work/stage7-persist/phaseb-probes/20261127T184903Z-57c117b5d78d-extract-boot.json
75ae67c5fb8f807027fa78cfb37951e69699741aa12e2ed621b828e1655ff38e  work/stage7-persist/collect-stage7-20261126T172306Z-39dc7f327b95.json
8b1752329e1f080a09432f1368eb42607d35a7ef7c74b3dd7674ef2eee3cefa6  extracted/m7-stage7-1.00-20261126T172306Z/inventory.txt
0267d7b05a9250b525b95ebfd2edc04d6aef2dbd4bcabc32e15a197d41e52912  extracted/m7-stage7-1.00-20261126T172306Z/sbin/init
23802d6c9ba3c41c1c0c3096ec6d1ba884ed27374e854416283547755faf4e48  extracted/m7-stage7-1.00-20261126T172306Z/usr/bin/bootin.elf
21ea1ebbd488c8ce342d87290396152b1bc0ca8619708375d8ab5788ae0d4db1  extracted/m7-stage7-1.00-20261126T172306Z/usr/bin/launch_shell.elf
524abb301d5b134e577ccac6b62e9d6a36c0c5a735ac121a8b4ef79a77c053d2  extracted/m7-stage7-1.00-20261126T172306Z/usr/bin/sen.elf
03a70fd0d0ef269c0de9530398d1e4d7cd8fcb089286cff682ee32d097ad16bd  extracted/m7-stage7-1.00-20261126T172306Z/usr/bin/up.sh
fbb87b03409e180c7aceebdc6d2a22511932e9305201e4e6da99585b8a6fc60b  extracted/m7-stage7-1.00-20261126T172306Z/usr/lib/libupdaterufp.so
1e36b989214aafb0a426a45ee06a578d17814926226e3d39307a0124fdf90587  extracted/m7-stage7-1.00-20261126T172306Z/usr/lib/libupdatertalk.so
d79365e3a168bffcad68bf8cce24bfa62be1de2e0d7ed062470632a0af9f1279  extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/lib/libsencore.so
fbc91e66ce27ea917041c33c53e038bfc92e0cf8aea6f254f9dae01acefdfaeb  extracted/m7-kernel-file-20261105T210321Z-78319ef81a60/system/vmlinux.bin
6b276cd909d4d3ad35dc99303148bdc4591d1e885c1f767e301b007646bbe005  extracted/m7-kernel-20261104T223751Z/usr/kmod/liro.ko
d4c990382c1071631863944ee8f09612e78542746d35b0ebe894d7d2bfcb546b  evidence/m7-kernel-analysis/m7.kallsyms
9a93127c8e4e4e8c76e4e63d5edd9ecace561a9ddb4958ef381941bf27405ece  evidence/m7-kernel-analysis/analysis.json
```
## Reproduction on the host

Run the shell blocks in the same zsh from the project root. All outputs below go to standard output or a private temporary directory. The parser emits only regular files in scratch. Binary-internal strings and module relocations can be checked without executing the target.

```sh
repo=$PWD
d="$repo/extracted/m7-stage7-phaseb-1.00-20261127T184903Z"
p="$repo/extracted/m7-stage7-1.00-20261126T172306Z"
r="$repo/work/stage7-persist/phaseb-probes/20261127T184903Z-57c117b5d78d-extract-boot.json"
t=$(mktemp -d "${TMPDIR:-/tmp}/m7b1.XXXXXXXX")
jq '{build,all_files_verified,extract_boot_ok,service_stop_transport,statfs}' "$r"
python3 - "$r" "$d" <<'PYHASH'
from pathlib import Path
import hashlib, json, sys
rec = json.loads(Path(sys.argv[1]).read_bytes())
root = Path(sys.argv[2])
digest = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
for key, row in rec['files'].items():
    f = root / key[1:]
    assert row['verified'] and f.stat().st_size == row['bytes'] and digest(f) == row['sha256']
for name, field in [('inventory.txt', 'inventory_sha256'), ('dmesg.bin', 'dmesg_sha256')]:
    assert digest(root / name) == rec[field]
print(len(rec['files']), sum(row['bytes'] for row in rec['files'].values()))
PYHASH
nl -ba "$d/dmesg.bin"
(cd "$t" && python3 -B - "$d/system/initrd.img" > inventory.host <<'PYEXT'
import struct, sys, hashlib, stat
from pathlib import Path
b=Path(sys.argv[1]).read_bytes()
u16=lambda p:struct.unpack_from('<H',b,p)[0]
u32=lambda p:struct.unpack_from('<I',b,p)[0]
bs=1024<<u32(1048)
ipg=u32(1064)
isz=u16(1112)
print('geometry',bs,ipg,isz,hex(u16(1080)))
def walk(n,path,entry):
    g,i=divmod(n-1,ipg)
    a=u32((2 if bs==1024 else 1)*bs+g*32+8)*bs+i*isz
    m,z=u16(a),u32(a+4)
    p=list(struct.unpack_from('<15I',b,a+40))
    def blocks(block,depth):
        if not depth: yield b[block*bs:(block+1)*bs] if block else bytes(bs)
        elif block:
            for child in struct.unpack_from('<%dI'%(bs//4),b,block*bs):
                yield from blocks(child,depth-1)
        else:
            raise ValueError('missing indirect block')
    data=b''
    if stat.S_ISLNK(m) and z<=60: data=b[a+40:a+40+z]
    elif stat.S_ISREG(m) or stat.S_ISDIR(m) or stat.S_ISLNK(m):
        for j,blk in enumerate(p):
            if len(data)>=z: break
            for piece in blocks(blk,max(0,j-11)):
                data+=piece
                if len(data)>=z: break
        data=data[:z]
        assert len(data)==z
    print(n,hex(a),oct(m),z,path, data.decode() if stat.S_ISLNK(m) else hashlib.sha256(data).hexdigest() if stat.S_ISREG(m) else '-')
    if stat.S_ISREG(m):
        out=Path('tree')/path[1:];out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
    if stat.S_ISDIR(m):
        o=0
        while o<len(data):
            ino,size,nlen=struct.unpack_from('<IHB',data,o)
            assert size>=8 and o+size<=len(data)
            name=data[o+8:o+8+nlen].decode()
            if ino and name not in ('.','..'):walk(ino,path.rstrip('/')+'/'+name,o)
            o+=size
walk(2,'/',0)
PYEXT
)
cat "$t/inventory.host"
cmp "$t/tree/sbin/init" "$p/sbin/init" && shasum -a 256 "$p/sbin/init"
xcrun llvm-objdump -d --triple=thumbv7-linux-gnueabi "$t/tree/sbin/init"
xcrun llvm-objdump -s -j .data -j .rodata "$t/tree/sbin/init"
for f in "$d"/usr/kmod/*.ko "$t/tree/kmod/emmc.ko"; do xcrun llvm-nm -n "$f"; done
xcrun llvm-objdump -dr -j .text "$d/usr/kmod/usbg_sen.ko"
xcrun llvm-objdump -dr -j .text "$t/tree/kmod/emmc.ko"
for f in "$d/bin/busybox" "$p/usr/bin/sen.elf" "$p/usr/bin/bootin.elf" "$d"/usr/bin/ud_*.elf; do
  xcrun llvm-objdump -d --triple=thumbv7-linux-gnueabi "$f"
done
for f in "$d"/system/{*.bin,sabin/*.bin}; do xxd -l 128 "$f"; done
```

For the raw kernel, resolve direct ARM call targets against the matching map. Stop interpreting trailing literal pools as code at the function return.

```sh
cat > "$t/kernel.py" <<'PYK'
from pathlib import Path
from struct import unpack_from
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
import sys
rows=[x.split(maxsplit=2) for x in Path('evidence/m7-kernel-analysis/m7.kallsyms').read_text().splitlines()]; names={int(a,16):n for a,t,n in rows}; va={n:int(a,16) for a,t,n in rows}; base=0x60108000; raw=next(Path('extracted').glob('m7-kernel-file-*/system/vmlinux.bin')).read_bytes(); cs=Cs(CS_ARCH_ARM,CS_MODE_ARM)
for n in sys.argv[1:]:
 a=va[n]; end=min(x for x in names if x>a); print(n,hex(a),hex(end));
 for i in cs.disasm(raw[a-base:end-base],a):
  ops=i.op_str; value=int(ops[1:],16) if ops.startswith('#0x') else 0; label=names.get(value,''); print(hex(i.address),i.mnemonic,ops,label)
PYK
.venv-analysis/bin/python -B "$t/kernel.py" cmpr_init cmpr_load_file __boottime_cmpr_register_compressor ssboot_prepare ssboot_snapshot ssboot_write warm_boot_pm_begin cxd_create_warmbootimage wbi_rewrite_header wbi_read_header
```
