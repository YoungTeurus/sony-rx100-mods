# Stage 6 WIP v3 HW3 hotfix r3 independent verification

**GO for Live Hardware Run #4 on ring SHA-256 `ee931ac970d299e4c77306db12102fe65bcc2e5ec453bd05a3586aa8e00a6820`.** The sealed ARM program suppressed Insert4100 and pre-S1 recorder resume in all requested revocation cases. The held control dispatched once on its second attempt. Both offline suites passed. Live camera behavior remains **INCONCLUSIVE**.

Reviewed on 2026-11-22 the working tree against `04b0a1e43dc39706b0845ff01e68ff22b8222225`. All execution below used host fixtures or ARM emulation.

## Dispatch and restoration

**PASS.** I ran the original r2 `gate.py` unmodified. It passed its held control and exited 1 at line 31 on half-release. That line requires the r2 defect to recur. I then repeated all four cases with the identical stimulus and the acceptance assertions for r3. No repository test expectations changed. The first refusal occurred at fixture time 10,200 ms in all four cases.

| Insert4100 input | Continue requests | 1 ms sleeps | Actual dispatches | End state |
|---|---:|---:|---:|---|
| Gates held, first request returns −3 | 2 | 1 | 1 at 10,201 ms | init, detached, exit 0 |
| Half released during sleep | 1 | 1 | 0 | init, detached, exit 0 |
| Subscription lost during sleep | 1 | 1 | 0 | init, detached, exit 0 |
| Disarm present during sleep | 1 | 1 | 0 | init, detached, exit 0 |
| Persistent −3 | 33 | 32 | 0 | init, detached, exit 0 |
| Immediate −14 | 1 | 0 | 0 | init, detached, exit 0 |

An independent observer checked the restore sequence through the ring entry point. In each of the five no-dispatch cases, the **first** SETREGS after refusal wrote all 18 original core words. The recorder cancellation calls were `[1, 0]`, the three TLS words matched their initial values, and all core and VFP words matched the attachment snapshot at detach. The modeled recorder made zero trap writes and zero shutter commands. In the held control, the subsequent explicit cancellation also restored SD and produced an empty traced-task set.

**PASS for pre-S1.** With Trap #1 installed, I refused the first resume of the idle recorder and changed one input during the 1 ms sleep. Half-release, subscription loss and disarm each produced one refused request, **zero successful idle resumes**, and **zero shutter commands**. The fixture saw exactly two writes to the trap address. Final readback was `0x531ef240`, media mode progressed from RAM through SD restoration to init, both recorder and remote registers matched at detach, and each run exited 0 with `traced == {}`.

I also applied each revocation on **sleep 32** in both paths. All six runs suppressed attempt 33 and unwound. With the gates held, Insert4100 succeeded on attempt 33 at 10,232 ms. These witnesses distinguish rechecking after every retry from handling only the first sleep.

The linked instructions corroborate the input observations. Insert4100 checks hold and subscription at `0x14a84` and `0x14a98`. Its failed continue restores the subscription-check flag at `0x14ad8`, then the sleep loops back at `0x14b50`. The command-1 caller supplies a hold context. The pre-S1 path rechecks hold at `0x171c8` and then subscription at `0x1715c` before the next resume. Source locations are `prototype-stage6-autonomy/stage6_ring.c:663`, `:2784` and `:3130`.

## Shared-call counterexample

**PASS.** I replayed the r1/r2 stimulus with the physical inputs released at 1,100 ms. The fixture hit operation 5 on TID 170 at 2,989 ms after arming, following a successful wait. I relocated the observer to the r3 post-wait GETREGS call at `0x1ec70`. The new wrapper adds a stack frame, so the observer matched its saved caller return address. The injected errors and original result assertions were unchanged.

| Post-wait read | Requests / sleeps | Ring and daemon outcome |
|---|---:|---|
| One −3, then success | 2 / 1 | Exit 0, init, empty traced set and no held frames or open handles. Eight 12,455-byte files matched the fixture JPEG byte for byte and passed the host card check against the sealed daemon’s records. |
| Persistent −3 | 33 / 32 | UNRESOLVED 225 / 0xfffffffd / 170. No files. The ring retained TIDs 170 and 446 in RAM mode. Daemon recorded the same tuple, `r_unres=1`, `r_reap=0`. |
| Immediate −14 | 1 / 0 | UNRESOLVED 225 / 0xfffffff2 / 170. Same retained state and daemon counts. |

The persistent −3 and immediate −14 after continue both left the ring waiting with two tasks traced. Either may require operator recovery on hardware. The pre-S1 error branch also distinguishes gate loss from a permanent resume error with gates held. The latter short-circuits the sender and reaches 218 / 10 at `stage6_ring.c:2805` on source inspection. The clean pre-S1 exits above concern gate loss.

## Linked ARM and release checks

| Check | Result and proof |
|---|---|
| Ring syscall census | **PASS.** Scanned every aligned word in RX offsets `[0, 117756)`. All 97 `svc #0` words lay in ARM code and had classified reaching definitions for r7. Exactly three selected syscall 26. They were the attach at `0x1e074` and the two sites in `s6_ptrace_retry_n` at `0x1e5e0` and `0x1e660`. All 27 superseded functions were absent. |
| Stage 7 / 1407 | **PASS under the linked call ABI.** All 114 direct calls to the nonreturning unresolved handler matched the 114 object relocations. No aligned RX word held its absolute address. Exactly three calls passed literal stage 7. Each received the same status compared against 1407, and its only reachable incoming edge was the unequal branch. The branch/call pairs were `0x14bb8 / 0x14ce4`, `0x1ec5c / 0x1ed80` and `0x20830 / 0x20910`. The two computed stage sources were the wait operation (1, 45, or 10 plus an admitted operation) and 220 plus an admitted operation. Neither yields 7. The Stage 5 combined-error predicate is at `prototype-producer-probe/retain.c:263`. |
| ARM parity | **PASS for compared bytes.** The 148-byte operation table matched Stage 5 and HEAD. All 20 pin descriptor groups, 291 entries and 21,809 pointed-to bytes matched HEAD. |
| Retry bounds | **PASS.** Direct calls of the sealed helper used the fifth ARM argument on the stack. Attach with budget 32 and persistent −3 returned after 1 request / 0 sleeps. Budget 0 produced 1 / 0 for success, −3 and −14. With budget 32, 0, 3 and 32 transient errors succeeded in 1, 4 and 33 requests. Persistent −3 returned after 33 / 32. Immediate −14 returned after 1 / 0. Every requested retry sleep was exactly (0 s, 1,000,000 ns). |
| Static stack | **PASS.** The stack-usage build reproduced the sealed ring object byte for byte. All 144 reported frames were static. Largest single frame was 12,176 B for the capture session. Ring entry used 4,528 B, burst boundary 1,288 B, trace restore 400 B, burst comparison 376 B, shared call 184 B, wrapper 16 B and retry helper 44 B. The wrapper calls the helper, adding its frame on that path. Hardware stack high-water remains **INCONCLUSIVE**. |
| Scope, seal and rebuild | **PASS.** HEAD matched the assignment and whitespace validation exited 0. The tracked diff listed exactly the ring C source, v2 tests, manifest, ring object and ring ELF. `verify_seal()` accepted the working release. A fresh empty directory produced exactly the same six filenames and all six matched byte for byte. |
| Ring layout and transport size | **PASS.** ELF size 122,980 B. RX file and memory size 117,756 B. RW load at file offset 118,784, VA 184,320, file size 4,196 B and memory size 8,192 B. The boot descriptor covered those same two pages and test 05 observed a single read-only protection request for that range. With the Run #3c framing fixture, gzip was 68,633 B and required **841 chunks**, below 850. |
| Daemon | **PASS.** ELF and HEAD hashed identically. One RX load, 36,631 B. All 158 aligned syscall sites classified, zero ptrace. |
| Full offline suites | **PASS.** `test_stage6_probe.py` passed 8/8 in 1.695 s. `test_stage6_v2.py` passed 23/23 in 833.772 s. Both processes exited 0. The separate six-file comparison establishes the identity of the locally rebuilt image used by the suites. |

Test 23 now covers both revocation paths and scans the full RX extent. Its 80-byte backward window can omit a syscall whose r7 definition falls outside the window. The independent census above classified all 97 sites in this release. See `prototype-stage6-autonomy/test_stage6_v2.py:4903`, `:5083` and `:5121`.

## SHA-256

| File | Digest |
|---|---|
| stage6_ring.c | `21baa71907100d6e0120b151e9b7a0d6e05d83e75452aaa54243f921cdefda7b` |
| test_stage6_v2.py | `69b0826cf386776bd32cefef8f2bdea04f4abe4dd7789d8096bb941297c6a352` |
| build.json | `f33c2649730fd385d125455e2758f6b9ae84bf1ca9687031941b84920581b982` |
| sony_pins.h | `05d5403c404849b2291b08bb842bec1ed8e5c252ec24208cea599ed3278559de` |
| stage6_daemon.elf | `cdb29883c5b9ed40920b9cfca09502aadd430a5a373abcf5528d735c3280be20` |
| stage6_daemon.o | `0138bf7b112c38b16183cf123bc3f2b1a43eddb2ba8e99f46d905a0ab920981d` |
| stage6_ring.elf | `ee931ac970d299e4c77306db12102fe65bcc2e5ec453bd05a3586aa8e00a6820` |
| stage6_ring.o | `19e29c2d7291a3be3a08b1fbde94b316b8f7fbbe7b11a3fe61c8ae2e89af9a4e` |

## Reproduction and custody

I read the assignment, project state, persistence plan and r2 review. The explicit replay and rebuild requirements also used the previously named external harnesses, the builder's declared host inputs and extracted-library pins, and the prior upload framing receipt under `work/stage6-menu/wip2/`. All new review scripts, logs and comparative objects were created in the OS temporary directory. The report is the sole repository output. The working tree and HEAD were rechecked before the verdict.

```sh
cd <repo-root>
export PYTHONDONTWRITEBYTECODE=1
py=.venv-analysis/bin/python3
r1="$TMPDIR"s6-audit.HZ0DLDk0ag
r2="$TMPDIR"s6-audit-r2.A6O6RDs0Ry
r3="$TMPDIR"s6-astra-r3.miaE4SEQ24
export PYTHONPATH="prototype-stage6-autonomy:$r2"

git rev-parse HEAD
git diff --name-status HEAD
git diff --check HEAD
git show HEAD:prototype-stage6-autonomy/out-v2/stage6_daemon.elf | shasum -a 256
"$py" -Bu "$r2/gate.py"  # r2 reproduction assertion exits 1 on fixed half-release
"$py" -Bu "$r1/release.py"
"$py" -Bu "$r2/audit.py"
"$py" -Bu "$r2/daemon.py"
for script in gate restore last_retry observation bound edges callers
do
    "$py" -Bu "$r3/$script.py" "$r2" || break
done
clang --target=armv7-none-eabi -marm -mfloat-abi=soft -mno-movt -Os \
    -ffreestanding -fno-builtin -fno-stack-protector -fno-unwind-tables \
    -fno-asynchronous-unwind-tables -fno-pic -fno-pie -fdata-sections \
    -Wall -Wextra -Werror -Iprototype-stage6-autonomy/out-v2 \
    -Iprototype-stage6-autonomy -Iprototype-producer-probe -fstack-usage \
    -c prototype-stage6-autonomy/stage6_ring.c -o "$r3/ring.o"
cmp "$r3/ring.o" prototype-stage6-autonomy/out-v2/stage6_ring.o
"$py" -Bu prototype-stage6-autonomy/test_stage6_probe.py
"$py" -Bu prototype-stage6-autonomy/test_stage6_v2.py
shasum -a 256 prototype-stage6-autonomy/out-v2/* "$r3"/*.py
```

Witness SHA-256 digests are `04c1202d0afbfa223d64a4f9896cd8453f510b12ccb652a3336616fc8d71f305` for the unmodified r2 gate, `0dccc69d64ea81391f87ca8e4b75a8ab96bf9b8b04a36d8bb7ff1aada8baec0b` for its r3 result assertions, `b214da462d979ecee871d953b051073c701b24133a9d0eadd54005b19a20bfca` for restoration, `843ffe158e9156b4eadd177df1a118afefeceb970ebf2cb12775d5b23da7db15` for last-sleep revocation, and `201da0b72cdf2dab144199bfc35eb4f1a96f0161af0bc368d66edd5a144ca62e` for the relocated shared-call witness.

**Final verdict — GO for Live Hardware Run #4.**
