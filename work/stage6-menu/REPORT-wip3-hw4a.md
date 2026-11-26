# Live Hardware Run #4a — 2026-11-26

**PASS** for the tethered diagnostic on HW3 hotfix r3. The user operated the camera. Evidence comes from the local operator archive receipts `20261126T145000Z-943224617a21-tethered-diag.log` and `20261126T145000Z-943224617a21-tethered-diag.json`. Both template digests match the sealed r3 release listed in [HANDOFF.md](HANDOFF.md).

| Check | Observed result |
|---|---|
| Capture window | READY reached five frames. TRIGGER retained five. WINDOW reported five pre and one post. Six distinct RING_FILE entries agree with the final saved count. |
| Drain and ring exit | SUMMARY reported success. RING_EXIT at 38.314 s recorded rc=0, sig=0, unres=0 and fault=0. The Run #3c freeze did not recur in this session. |
| Watchdog and cleanup | STOP at 65.081 s reported the configured timeout, one successful run, six saves, both children reaped and zero faults or truncation. The host found no live daemon or ring afterwards and recorded cleanup=GONE. |

**INCONCLUSIVE** for untethered qualification and SD readback, pending Run #4b. The logged full press lasted 3.091 s and yielded one post frame. This run gives no sustained post-capture rate or explanation for the previous freeze.

Offline receipt checks from the repository root:

```sh
rg -n 'ev=(WINDOW|SUMMARY)|^RING_FILE|^RING_EXIT|^STOP' work/stage6-menu/wip2/20261126T145000Z-943224617a21-tethered-diag.log
shasum -a 256 work/stage6-menu/wip2/20261126T145000Z-943224617a21-tethered-diag.{log,json}
```

| Receipt | SHA-256 |
|---|---|
| Log | `fe72f3755e8379273ad23ce5eb369999acbad0b8ffa6ce4b3255292e7f985f68` |
| JSON | `8116fcb1712f0bf2d7b915232ef7dc9094336d9509b60084d0d812777c9e5eeb` |
