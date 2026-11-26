# Stage 7 — persistence in firmware

Status: IN PROGRESS — offline research, 2026-11-26. Stage 6 JPEG hardware qualification passed in [Run #4](../work/stage6-menu/REPORT-wip3-hw4.md). See the [Stage 7 evidence and open questions](../work/stage7-persist/REPORT.md).

## Goal

The pre-capture change survives a power cycle and needs no laptop: it is a real,
persistent modification of the camera, with a documented way back to stock.

## Product UI requirements (from user, 2026-11-22)

Add two camera menu settings (replacing the temporary `Release w/o Card` toggle used in
Stage 6):
1. **Pre-Capture ON / OFF** (master enable; OFF must remain 100% passive stock).
2. **Pre-Capture Count (`N` pre-frames):** user-configurable number of pre-shutter frames
   (`1..max`, up to the validated safe buffer limit).

Post-capture (`post`) is **not** fixed to a small `M`: once full-press is engaged, post
frames keep recording for as long as the user holds full-press (`full == 1`), up to the
camera's buffer safety ceiling.

## Why now

The user's final product requires it. It is last because it depends on a stable
mechanism, a stable menu gate, and a known-good RAM version to port.

## Research questions

1. Which firmware surface can carry the change: a card-loaded overlay at boot, a
   patched binary in a partition, or a startup hook — and what does the RX100M7
   firmware update path verify?
2. How is the RAM helper currently injected (ranges, `libObj` bias, monitor tid,
   token) and which of those can be discovered in-camera instead of by a host?
3. What are the exact persistence mechanics (partition, filesystem, checksums,
   update wrapper) and what does recovery look like if a write is bad?
4. Can the change be installed and removed by the stock firmware update procedure,
   so no extra tool is needed at the end?

## Acceptance

Offline: an image diff, a manifest of every changed byte range, checksums and a
reproducible build. The build must be reproducible from source by the helper
tooling, not by hand-editing a binary.
Hardware: cold boot with USB detached has pre-capture active in Continuous, the
menu toggle works, a saved window verifies, and the documented rollback restores
stock.

## Stop criteria

Any boot failure that a normal power cycle cannot clear parks the stage until the
recovery path is proven on paper and in the model.

## Context whitelist

`STATE.md`, this file, stage-6 report, `prototype-producer-probe/build.py`,
`stock_sd_precapture.py`, the firmware extraction artifacts under `extracted/` and
`downloads/` that the research note cites.

## Output

`work/stage7-persist/REPORT.md`.
