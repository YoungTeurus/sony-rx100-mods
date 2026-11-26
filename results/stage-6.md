# Stage 6 — untethered JPEG capture

Target: Sony DSC-RX100M7, firmware 1.00, JPEG L 20M, 3:2, SD card inserted. The operator used the physical shutter. The release ran in RAM for the current boot.

| Milestone | Hardware outcome |
|---|---|
| Observation build | The camera remained usable through USB disconnect and reconnect. The observer monitored menu and shutter state for 112.1 seconds. |
| Run 1 | Startup, gating and teardown were exercised. Capture timing problems remained. |
| Run 2 | The RAM capture survived a 217-second untethered session. Three JPEGs passed SD readback. The two passive shooting cases and clean collection were verified. |
| Runs 3–3c | Faster capture and saving worked, but the camera froze while finishing a capture. These runs exposed a hardware failure. |
| Run 4a, tethered | Five pre frames and one post frame were logged. The ring exited cleanly and the temporary directory was removed. |
| Run 4b, untethered | All four scenarios below passed. The user reconnected USB for log collection and verified the saved files on the card. |

## Run 4b

| Action | Observation |
|---|---|
| Disable the feature, select Continuous, press the shutter | Gate stayed closed. No pre-capture session started. |
| Enable the feature, select Single, press the shutter | Gate stayed closed. No pre-capture session started. |
| Enable the feature, select Continuous, hold halfway, then press fully | The camera logged five pre frames and fifteen post frames, reaching this run's configured post limit. All 20 distinct JPEGs passed readback. Total size was 197,827,393 bytes. |
| In the same mode, hold halfway and release without pressing fully | The capture window was empty and the session logged zero saved files. |

The last save was reported 32.821 seconds after full release. The save session exited after 46.557 seconds. The operator saw no save-progress indicator. On cancel, the session exited 12.155 seconds after half-release, including 11.109 seconds in drain. The log measures process exit. The earliest moment the camera could take another shot was not measured.

Both sessions exited with zero faults and no unresolved event. The final stop reported two successful capture sessions, twenty saves and no log truncation. The temporary session files were removed.

[Run 2 events](../evidence/run-2-events.log) · [Run 2 card readback](../evidence/run-2-card.json) · [Run 4b events](../evidence/run-4b-events.log) · [Run 4b card readback](../evidence/run-4b-card.json)

Source receipts are identified by their UTC timestamp and run identifier: Run 2 collection `20261122T092322Z-16e19cc6817b`, Run 4a diagnostic `20261126T145000Z-943224617a21`, Run 4b collection `20261126T150548Z-b6d997048cfa`. The SHA-256 of the original Run 4b card-check receipt before field selection is `d10afab1c3b5a744818f6ebe644f372194595c2d0c8a8dd03b6307353de10f5a`.
