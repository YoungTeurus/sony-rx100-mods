# Stage 7 — Cold-Boot Persistence & Native Menu Research (Status)

Status: **IN PROGRESS (offline feasibility only — zero flash writes)** as of 2026-11-26.

Stage 6 qualified the untethered RAM-only JPEG pre-capture daemon ([Run #4 report](../work/stage6-menu/REPORT-wip3-hw4.md)), which still requires a per-boot USB startup command and temporarily reuses the stock **Release w/o Card** setting (`BackupID = 0x01071472`) as its ON/OFF switch. Stage 7 investigates turning this into a cold-boot persistent feature with two dedicated menu items:

1. **Pre-Capture ON / OFF** (leaving Release w/o Card stock)
2. **Pre-Capture Count (`N` pre-frames)** (user-selectable pre-shutter buffer depth)

## Summary of Offline Findings

| Area | Status | Findings |
|---|---|---|
| Target build baseline | **PASS** | Original Sony DSC-RX100M7 firmware `1.00`, build `29110_03.2021050601`, Linux `3.0.27_nl-rt106+`. Seventeen extracted reference files verified via SHA-256 ([m7-1.00-files.sha256](../work/stage7-persist/m7-1.00-files.sha256)). |
| Stock firmware rollback package | **INCONCLUSIVE / BLOCKED** | Sony's public `Update_DSCRX100M7AV101.exe` applies exclusively to the newer **DSC-RX100M7A** (1.01) hardware revision, not the original M7 1.00. No public full-system reinstall or failed-boot recovery image for original M7 1.00 has been identified. |
| Built-in Sony reset / backup features | **FAIL as firmware recovery** | Camera Settings Reset, Initialize, Memory/Recall, and Recover Image DB do not export or restore flash partitions or per-unit factory calibration (`/lens`, `/cert`, `backup`). See [recovery-codex.md](../work/stage7-persist/recovery-codex.md). |
| Native menu structures | **PARTIAL / INCONCLUSIVE on M7** | Original M7 `libObj.so` exports `CmnViewMenuData::getOptionNum` and `getSubItem`. Runtime maps show `/usr/lib/CautionConfig.so` and `/usr/lib/viewUnified2.so` on M7 1.00, and the [offline inspector](../work/stage7-persist/inspect_stock_menu.py) verified the `ReleaseWOCard` (2 options) and `AutoReview` (4 options) symbol structures on the M7A reference image. Original M7 copies of those two libraries have not yet been exported. |
| Cold-boot auto-start route | **INCONCLUSIVE** | RX100M7 does not support PlayMemories Camera Apps; a safe, recoverable cold-boot startup mechanism remains open. |

## Stop Criteria & Next Inputs Needed

Per [plans/07-persistence.md](../plans/07-persistence.md), no flash modification will be attempted until:
1. A verified, restorable original M7 1.00 firmware backup/image and documented failed-boot recovery path exist, and
2. Original M7 1.00 `CautionConfig.so` and `viewUnified2.so` are inspected offline to map exact menu-node symbols without relying on M7A offsets.

Full Stage 7 feasibility report: [work/stage7-persist/REPORT.md](../work/stage7-persist/REPORT.md) · Recovery assessment: [work/stage7-persist/recovery-codex.md](../work/stage7-persist/recovery-codex.md).
