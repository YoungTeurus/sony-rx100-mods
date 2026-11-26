# Sony DSC-RX100M7 pre-capture qualification, stages 1–5

On one camera running stock firmware 1.00, a physical full shutter press saved frames from both sides of the press. Releasing the half-press without pressing fully discarded the selection. Two builds demonstrated different capabilities. Stage 4 reached 14.98 frames/s while the camera wrote its burst to the card. Stage 5 kept a rolling two-frame JPEG window in RAM at about 0.3 frames/s and passed the project's sampled check for card writes during the hold.

The results below come from the hardware reports at commit `ddaaac4`. Receipt IDs identify individual runs. A stage pass applies to the conditions exercised in that run.

| Stage | Hardware result | Verification and limits |
|---|---|---|
| 1 · Trigger | **PASS** · `978632244e35`. A new pre-frame displaced the oldest frame. The physical full press latched once, and the post-frame arrived 688 ms later. | Both saved JPEGs opened at 5472 × 3648 and matched their stock originals byte for byte through the JPEG end marker. The originals had additional zero padding. The test used manual focus, single drive and one retained pre-frame. |
| 2 · Cancel | **PASS** · `77622359fe6b`. Releasing without a full press selected neither of the two observed frames. After cleanup, the card inventory matched its baseline. | An earlier save left two late stock files. Follow-up save `f4fa1f68afbe` retained one pre- and one post-frame from four and left zero new stock files after cleanup. Its queue was quiet for 4.017 s. These checks concern the final card contents. |
| 3 · Autofocus | **PASS** · `9d26d3879c3e`. Focus changed from non-ready to confirmed lock after 569 ms. One pre- and one post-frame passed card readback and hash verification. | A third stock frame appeared during hashing. The finalizer backed it up, verified it and removed it. This run exercised fresh lock. The documented 1.5 s fallback for manual focus or hunting was outside this run. |
| 4 · Burst rate | **PASS** · `037d1c6f0707`. The camera registered the physical full press during the burst. All 20 selected pre-frames were still awaiting image processing at that instant. Their window spanned 1.277 s, and the five post-frames spanned 332 ms. | The camera wrote 40 stock frames. At release, 36 were pending and all finished within 13.574 s. All 25 selected JPEGs matched their sources by size and SHA-256 on card readback. Cleanup removed the 40 stock files after backup verification. |

## Stage 5 · RAM capture and return to normal shooting

**PASS, 7 of 7 requirements.** On 21 November 2026 the operator ran a save, a cancel, an ordinary camera shot and a repeat cancel on the same boot and card. The operator ran the final verifier with the card mounted. The qualification used Continuous Hi and 5472 × 3648 JPEGs.

| Operator action | Receipt | Hold | Observed result |
|---|---|---:|---|
| Full press to save | `51302f4b3857` | 26.30 s | Seven older frames evicted. Two pre-frames and one post-frame saved. All three JPEGs matched their source SHA-256 on card readback. |
| Release to cancel | `2ce4db80793d` | 32.95 s | Nine evictions. Card count stayed at 3,732 with no new files. |
| Take an ordinary shot | `normal-shot-20261121` | — | The card contained a new ordinary camera JPEG of 10,493,096 bytes. |
| Release to cancel again | `8db652a0245b` | 30.95 s | Eight evictions. Card count stayed at 3,733 with no new files. |

The verifier passed hold sampling, frame selection, saved-file integrity, the hold-time write check, empty cancellation, repeat usability and safe shutdown. The write check combined 500 ms sampling of the capture route with before-and-after card file sizes and modification times, excluding host-created metadata. It could miss transient writes between inventories or writes from other camera components.

All three holds exceeded the 10 s qualification minimum. The longest was 32.95 s, leaving the one-minute product target unverified. The qualification covered one JPEG size and a host-assisted workflow. RAW capture, other image sizes and autonomous operation remained outside its scope.

## Source reports at ddaaac4

- Stage 1 — `work/stage1-trigger/HW-978632.md`
- Stage 2 — `work/stage2-cancel/HW-776223.md` and `work/stage2-cancel/HW-f4fa1f68.md`
- Stage 3 — `work/stage3-af/HW-9d26d387.md`
- Stage 4 — `work/stage4-rate/HW-037d1c6f.md`
- Stage 5 — `work/stage5-no-card-writes/HW-STAGE5-PASS-20261121.md` and `work/stage5-no-card-writes/qualification/normal-shot-20261121.json`
