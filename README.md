# Sony RX100 VII JPEG pre-capture research

Hardware results for Stages 1–6 on an original Sony DSC-RX100M7 running firmware 1.00. In the final untethered test, holding the shutter halfway maintained a rolling pre-capture window in RAM. A full press in Continuous Shooting kept five earlier frames and fifteen later frames. All twenty JPEGs were read back from the card at 5472 × 3648 pixels, with their recorded byte counts.

The Stage 6 prototype required a USB startup step on each boot. The operator disconnected the cable before shooting. The camera's stock **Release w/o Card** setting acted as the temporary enable switch. The project qualified JPEG capture with the card inserted. RAW and cold-boot startup remained outside that qualification.

## Hardware results

- [Stages 1–5](results/stages-1-5.md) cover trigger detection, cancellation, autofocus, burst rate and the RAM-only capture window.
- [Stage 6](results/stage-6.md) covers the passive modes, untethered save, cancel latency and SD readback.

## Reproduce the offline checks

Run from this checkout with Python 3.9 or later. The checker reads local files and uses only the standard library.

```sh
python3 tools/check_run.py 2
python3 tools/check_run.py 4b
```

The commands compare the capture log's file list and byte counts with the recorded SD readback. With the original JPEGs available locally, add `--jpeg-dir /path/to/files` to check JPEG structure, dimensions, size and SHA-256 against the receipt. The repository contains metadata and per-file hashes. The photographs remain with the camera owner.

## Provenance

Source project milestone `ddaaac49b541cddb245527bfd2bd4653c998c4e3`, 26 November 2026. The files under `evidence/` preserve the selected verification fields from operator-run sessions. The event logs are excerpts. The local parser and JPEG inspection functions in [capture_analysis.py](tools/capture_analysis.py) originate in the Stage 6 runner at that revision. This repository publishes research results and offline analysis.
