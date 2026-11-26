# Stage 6 — menu on/off, continuous-only gate, no laptop

Status: HARDWARE PASS for the RAM-only JPEG scope — WIP v2.1 (r13) **HARDWARE PASS** (`work/stage6-menu/REPORT-wip2-hw2.md`); WIP v3 HW3 Hotfix (r3, fast cadence + hold-driven post + fast save + full `ptrace` `-ESRCH` hardening) **OFFLINE GO** (`work/stage6-menu/REVIEW-wip3-hw3fix-astra-r3.md`), **Live Hardware Run #4a tethered PASS** ([report](../work/stage6-menu/REPORT-wip3-hw4a.md)), **Run #4b HARDWARE PASS**, including [20/20 JPEGs verified from SD](../work/stage6-menu/REPORT-wip3-hw4.md). See `work/stage6-menu/HANDOFF.md` for exact Run #4 commands, sealed digests, whitelist, and `UNRESOLVED` decoding. Per stop criteria below, RAM-only Stage 6 uses stock `Release w/o Card` (`BackupID=0x01071472`, `0x0=ON`, `0x1=OFF`) as the menu toggle and defers custom menu items + cold-boot auto-start to `plans/07-persistence.md`.

## Goal

The feature is switched on and off from the camera menu and starts itself with the
camera, without a USB host. It arms **only in Continuous Shooting**; in Single
Shooting pre-capture does nothing and the camera behaves stock.

## Why now

Everything before this assumes a laptop, root USB upload and an interactive
prompt. This is the product shape the user wants. It needs a stable mechanism and a
stable drive-mode source, so it comes after rate and window correctness.

## Research questions

1. Where is the drive mode stored (look for the shooting-mode/drive enum that the
   stock UI writes), and what value means Continuous (single, continuous low, Hi)?
   Two independent confirmations per claim.
2. How does the camera start the helper from the card, and which surface lets a
   menu entry exist without flashing yet?
3. Where can a toggle live so it survives a power cycle before stage 7: a card
   config file, or a stock setting the helper reads?
4. What is the readable "off" state: helper absent, or `enabled=0`? Nothing may
   intercept the shutter while off.
5. Manual fallback and watchdog: what returns the camera to normal if the helper
   wedges?

## Gate behaviour

- Off, or drive mode not continuous: no arm, no retain, no interference.
- Continuous + on: the stage-5 window behaviour applies.
- A drive-mode change mid-hold: define it once (cancel and re-arm is acceptable).

## Acceptance

Offline: the gate refuses to arm in every non-continuous model variant and stays
silent in off mode.
Hardware: cold start from the card with USB detached, menu toggle visible and
persistent enough for the test, one saved window in Continuous, nothing in Single,
power cycle returns a normal camera.

## Stop criteria

If no non-flashing menu surface exists, ship the laptop command as the interim
product, note it plainly, and move the menu into stage 7 with the firmware work.

## Context whitelist

`STATE.md`, this file, `REVIEW-BRIEF.md`, `prototype-producer-probe/build.py`,
`stock_sd_precapture.py` (connect/configure), the reports the research note cites.

## Output

`work/stage6-menu/REPORT.md`.
