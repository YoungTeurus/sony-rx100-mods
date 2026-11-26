# DSC-RX100M7 stock recovery evidence

2026-11-26 · Original DSC-RX100M7, firmware 1.00.

**INCONCLUSIVE for return to stock after a failed boot.** The captures identify the running build, several mounted filesystems and individual stock files. They leave two questions open: which data must survive to restore this particular camera, and how recovery would be reached if normal startup failed. Sony documents user settings and memory-card backups for this model. The cited features offer no documented export or restore of firmware or factory calibration.

## What a stock backup would have to cover

For each layer affected by a failure, recovery needs either a restorable original or evidence that the layer survives intact. These are coverage requirements inferred from the Stage 7 rollback criterion. They do not imply that every mount needs a separate image. [Stage 7 plan, lines 39–51](../../plans/07-persistence.md#L39-L51)

| Layer | What the original M7 files establish | What is missing |
|---|---|---|
| Startup, storage layout and kernel | The version record contains build ID `29110_03.2021050601`. The runtime identifies Linux `3.0.27_nl-rt106+`. The earlier inventory also records one kernel binary and four kernel modules. (`version.txt` line 1, `runtime.txt` line 2, [inventory, lines 9–16](REPORT.md#L9-L16)) | Full storage layout, early boot components, and a documented recovery route usable before the normal camera menu. |
| Operating system, camera application and resources | Read-only ext2 mounts use `nflasha7` for `/` and `nflasha15` for `/usr`. The main manifest contains 15 payload files, including `im.elf` and `/system/av-cam.bin`. A runtime mapping also identifies `/usr/share/app/lang.uxb`. (`runtime.txt` lines 5–6 and 109–115, [manifest, lines 2–16](m7-1.00-files.sha256#L2-L16)) | Complete stock filesystem contents and metadata. A mapped pathname establishes that a file was in use. Only a manifest entry with a matching local file establishes captured bytes. |
| Writable internal volumes and per-unit state | The capture lists writable VFAT mounts on `nflasha10` (both `/tmp` and `/etc`), `3` (`/system`), `2` (`/setting`), `18` (`/lens`), `12` (`/cert`) and `11` (`/log`). It separately lists two RAM-backed tmpfs mounts. The kernel module list includes `backup`. (`runtime.txt` lines 7–17 and 70) | Location, contents and preservation of this unit’s factory adjustments and identity data. The names `/lens`, `/cert` and `backup` establish neither where calibration resides nor which values are unique to the unit. The mount list gives no partition sizes or coverage of unmounted storage. |
| Owner data on removable media | Sony treats photographs, movies and card-based shooting presets as memory-card data. [Precautions, “Backing up memory cards”](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0002053558.html), [Format, Note](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001117088.html) | A separate card copy covers owner data if required. Internal firmware and per-unit data require their own evidence. |

## What Sony's user features cover

- **Memory / Recall** stores up to three shooting presets in the camera and four on the card. Examples include aperture, shutter speed and zoom. Sony permits recalling a card preset on another camera of the same model. [Memory, “Items that can be registered”](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001117013.html), [Recall, Hint](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001116942.html)
- **Camera Settings Reset / Initialize** returns shooting settings or the broader set of camera settings to defaults. Both retain recorded images and leave Picture Profile settings intact. Sony's troubleshooting sequence refers persistent problems to the dealer or an authorized service facility. [Setting Reset, menu details and Note](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001117097.html), [Troubleshooting, steps 3–4](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001117155.html)
- **Recover Image DB** repairs the card's image database for playback. The M7-specific Imaging Edge Mobile list covers shooting controls and image transfer. Neither document describes a camera-system backup. [Recover Image DB](https://helpguide.sony.net/dsc/1920/v1/en/contents/TP0001117093.html), [Imaging Edge Mobile functions for DSC-RX100M7](https://support.d-imaging.sony.co.jp/www/cscs/pmm/page1.php?area=ap&lang=en&mdl=DSC-RX100M7)

**FAIL as evidence of a firmware or calibration backup.** None of these documented functions supplies the missing layers. How a reset treats individual factory calibration records remains undocumented in these sources.

## Local verification

**PASS for file identification and local integrity.** From the repository root, `shasum -a 256 -c work/stage7-persist/m7-1.00-files.sha256` matched all 17 entries. SHA-256 for `runtime.txt` was `7f1c82e5d91e3b292e0e8dd0901c17946efe43e698338febd1789058f9499016` and for `version.txt` was `f0289d325aff2df6fd421e63c70c7936419604709c740c3b1fae4e0222c5abc4`. These hashes verify the local copies against the project manifest. The original capture's file-checksum section contains shell errors throughout (`runtime.txt` lines 931–963).

Scope beyond the stage whitelist was limited to the assigned Stage 7 report, its existing hash manifest and the cited official Sony pages, to distinguish stock files, settings and service guidance. All camera observations come from the existing capture.
