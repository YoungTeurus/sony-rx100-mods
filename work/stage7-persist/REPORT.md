# Stage 7 — DSC-RX100M7 cold boot and menu settings

2026-11-26. First offline feasibility pass, starting at commit `ddaaac49b541cddb245527bfd2bd4653c998c4e3`. Hardware qualification for Stage 7 is **INCONCLUSIVE**. The user-operated [Stage 6 Run #4](../stage6-menu/REPORT-wip3-hw4.md) qualifies the capture engine after USB startup.

## Stock baseline and recovery

| Question | Finding | Evidence |
|---|---|---|
| Which camera and build were captured? | **PASS** for identification. The target is DSC-RX100M7 1.00, build `29110_03.2021050601`. | [Captured version](../../extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/version.txt), [Run #4 collection receipt](../stage6-menu/wip2/20261126T150548Z-b6d997048cfa-collect.json) |
| Which bytes can a future stock image be compared against? | **PASS** for the main local snapshot. All 17 files matched the SHA-256 inventory. It covers 15 camera binaries and libraries plus two capture records. Use the binary rows for image comparison. | [File manifest](m7-1.00-files.sha256) |
| Can the local Windows installer serve as the M7 rollback package? | **FAIL** for model applicability. The filename and 326,950,456-byte size match the package Sony publishes exclusively for DSC-RX100M7A 1.01. | [Sony applicable model and file details](https://www.sony.co.uk/electronics/support/software/00409507) |
| Is there a public M7 system restore package? | **INCONCLUSIVE.** The M7 download pages reviewed list camera software and host applications. The separate M7 open-source catalogue distributes components including the kernel and BusyBox. None of these sources identifies a stock reinstall image or failed-boot recovery procedure. | [Sony US downloads](https://www.sony.com/electronics/support/compact-cameras-dsc-rx-series/dsc-rx100m7/downloads), [Sony UK downloads](https://www.sony.co.uk/electronics/support/compact-cameras-dsc-rx-series/dsc-rx100m7/downloads), [M7 source packages](https://oss.sony.net/Products/Linux/DI/DSC-RX100M7.html) |

Sony documents Initialize as restoring camera settings. Its troubleshooting guide refers unresolved failures to an authorized service facility. Neither establishes how to restore firmware after a failed boot. A stock-before/stock-after comparison and recovery test remain open. [Setting Reset](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001117097.html), [Sony troubleshooting](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001117155.html).

Codex completed the local inventory on 2026-11-26. The nine original-model capture directories contain 25 files. The eight files beyond the main snapshot comprise one kernel binary, four kernel modules and three shared libraries. This inventory contains individual components. A complete restorable M7 image was not identified in these captures or in `downloads/`.

## Startup and menu controls

The previous run separates two requirements. Once started, the daemon handled the toggle, drive mode, physical shutter and card saves with the cable detached. It exited cleanly and the host removed the RAM directory. Cold boot still needs a way to start the feature before the first half-press. Sony's published PlayMemories Camera Apps compatibility list omits this model and the download service ended in 2025. A supported application or card startup route remains unverified. [Run #4, scenarios and cleanup](../stage6-menu/REPORT-wip3-hw4.md), [Sony Camera Apps compatibility](https://www.sony-asia.com/electronics/support/e-mount-body-ilce-5000-series/ilce-5100y/articles/00288923).

Sony's My Menu can register existing entries. Its documented interface does not establish a way to define either new setting. Stage 7 needs an independent master switch and a pre-frame count. The original Release w/o Card setting must keep its stock function. Run #4 verified five **pre** frames and 15 **post** frames. The upper bound for a user-selectable pre count needs separate evidence. [My Menu](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001310617.html), [Release w/o Card](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001140477.html), [verified capture window](../stage6-menu/REPORT-wip3-hw4.md).

**PASS for identifying native menu code in the exact build.** The captured `usr/lib/libObj.so` defines `CmnViewMenuData` functions for reading option counts and child items. ELF dynamic symbol entries 2272 and 2660 are the two `getOptionNum` overloads, and 2906 is `getSubItem`. All three are defined functions in section 10. Their names and argument types give offline research a way to recognize existing menu structures. They do not identify the shooting-menu entries, their display strings or how choices are stored. The next UI question is which exact-model resources represent one existing boolean and one bounded numeric choice. The library digest is recorded in the [manifest](m7-1.00-files.sha256).

The M7 capture also identifies concrete resource filenames. Its [runtime mapping list](../../extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/runtime.txt) records `/usr/share/app/lang.uxb` on line 115, `global.xdb` on line 186 and `string_russian.uxc` on line 672. The snapshot contains the mapping records only. As a comparison, the M7A Russian resource contains the exact UTF-8 label `Спуск без карты`, and its English resource contains `Release w/o Card`. This gives a concrete text check for a future **original M7** menu-resource copy. Display text alone does not identify which setting is changed when the user selects it.

## Decision and next evidence

**Menu comparison, 2026-11-26.** Two stock controls have independently documented behavior on the original M7. Release w/o Card offers Enable and Disable. Auto Review offers three display durations (10, 5 and 2 seconds) and Off. These make a boolean and a finite-choice reference for the planned settings. Auto Review establishes an example of option selection, not a safe pre-frame count. [Sony Release w/o Card](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001140477.html), [Sony Auto Review](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001117037.html).

| Evidence | Release w/o Card | Auto Review |
|---|---|---|
| M7A 1.01 `CautionConfig.so` | Defines the named root object and a default count of 2 | Defines the named root object and a default count of 4 |
| M7A 1.01 `viewUnified2.so` | Imports the root object | Imports the root object |
| Original M7 1.00 | The runtime records both library names. The two files are missing from its snapshot. | Same limitation |

**PASS for the M7A comparison. INCONCLUSIVE for the M7 definitions.** On the original M7, lines 663 and 667 of the [runtime capture](../../extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/runtime.txt) record `/usr/lib/viewUnified2.so` and `/usr/lib/CautionConfig.so`. These are the first two files to check in an original-model backup or export. The Russian text resource is useful for caption verification later. The [offline inspector](inspect_stock_menu.py) reads the libraries from a local directory, checks how the symbols are defined, decodes both option counts and records each file's SHA-256. Matching counts establish only these two observations. They cannot authenticate the camera model or prove a new setting works.

The old project collector stops before USB access at [m7_collect.py, line 234](../../scripts/m7_collect.py#L234). Its earlier investigation found that a firmware file-read request can update an internal service log and confirmed that the log exists on this camera. Sony documents Mass Storage for transferring images. Neither route provided a verified zero-write export of these libraries. Scope was extended to the collector and its cited report to check this property. [Service-log findings, lines 7–17 and 38–40](../../reports/M7_SERVICE_LOG.md), [Sony image transfer instructions](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001140511.html).

The owner reports having no separate M7 archive. **PASS for earlier direct transfers from this unit.** The [original collection receipt](../../evidence/m7-collect-20261104T212913Z.json) records 21,089,716 bytes for `libObj.so` on build `29110_03.2021050601`. A separate [RAM reader run](../../reports/M7_MPRCTRL_RESULT.md) verified the 263,812-byte `libmprctrl.so` against the camera checksum. These two historical receipts were consulted to assess feasibility. **INCONCLUSIVE for direct collection of the two Stage 7 files.** Neither receipt covers them. On the M7A comparison build they total 27,368,048 bytes. The original M7 sizes and transfer time are unknown. A separate archive is one possible source, not a prerequisite for a direct transfer.

On 2026-11-26 the owner accepted a possible service-log update while reading these two libraries. The existing collector has a fixed list of other inputs and stops before opening USB. Sony documents the normal USB connection for media transfer. The two requested files would need an export from the camera's internal filesystem. No Stage 7 hardware retrieval took place.

The [stock recovery assessment](recovery-codex.md) lists what the capture covers and what remains unverified, including factory calibration and how recovery is reached after a failed boot. Sony's documented settings presets and card backups do not furnish a stock firmware restore.

Keep the M7A package out of the installation and rollback paths. The two inputs that would advance firmware work are an original M7 image or a verifiably restorable backup from this camera, and model-specific documentation of how recovery is reached if normal startup fails. For a candidate, record its origin, model and version, compare the available unchanged files, and establish what device-specific data recovery preserves. A matching file hash alone verifies only that file.

Stage 7 has no candidate firmware image, changed-byte manifest or hardware test at this point. The Stage 6 observations on save progress and cancel delay remain in the hardware report.

## Reproduce the local checks

From the repository root:

```sh
cat extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/version.txt
shasum -a 256 -c work/stage7-persist/m7-1.00-files.sha256
wc -c downloads/Update_DSCRX100M7AV101.exe
shasum -a 256 downloads/Update_DSCRX100M7AV101.exe work/stage7-persist/m7-1.00-files.sha256
/usr/bin/strings -a extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/lib/libObj.so | rg 'CmnViewMenuData.*(getOptionNum|getSubItem)'
rg -n '/usr/share/app/(lang\.uxb|global\.xdb|string_russian\.uxc)' extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/runtime.txt
rg -alF 'Спуск без карты' extracted/m7a-1.01-fw -g string_russian.uxc --no-ignore
.venv-analysis/bin/python3 -B work/stage7-persist/inspect_stock_menu.py extracted/m7a-1.01-fw/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked
.venv-analysis/bin/python3 -B work/stage7-persist/inspect_stock_menu.py extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr
```

The menu inspector returned 0 on the M7A comparison (`CautionConfig.so` SHA-256 `de5e9713a09f63e3e4d4a365f4b543804608c808dd6be22d95d62b00907e98c2`, `viewUnified2.so` SHA-256 `dab4e2a80214e3762676711b586d31a8947186b72c471837a4674e26a480534f`). On the supplied original M7 snapshot it returned 2 for missing input.

**Independent review, 2026-11-26 — Codex Sol, GO for the offline findings.** Sol independently read the ARM32 ELF definitions, imports and stored option counts in the M7A files, reproduced both inspector exit codes, and verified all 17 original M7 manifest entries. Original M7 menu definitions, zero-write export and failed-boot recovery remain **INCONCLUSIVE**.

The local M7A installer SHA-256 is `43312b5ee26449f065ea2c9b08907b237ab426052e00754481f1b46c369ded42`. The main M7 snapshot manifest SHA-256 is `f4a83ef95ab7b972f3ca1d308b0c5a43afdc4bb0adc7d2f78ea5713016ca1cce`. Source scope also included Sony's public support and source-code catalogues to verify model applicability, the M7 help guide to check the documented menu and recovery functions, and a filename-only search of nearby project records for previous firmware backups.
