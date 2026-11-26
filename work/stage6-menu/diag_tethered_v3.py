#!/usr/bin/env python3
"""One-shot tethered live-streaming diagnostic for already-sealed Stage 6 WIP v3 ELFs.

Uses prototype-stage6-autonomy/out-v2/stage6_daemon.elf with daemonize=False
(stdout -> usbgcon-1) and out-v2/stage6_ring.elf so every STATE / RING_EVT /
RING_FILE / UNRESOLVED line streams live to the Mac terminal and is flushed to
work/stage6-menu/wip2/ immediately.
"""
import json
import os
from pathlib import Path
import secrets
import sys
import time

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "prototype-stage6-autonomy"))
sys.path.insert(0, str(REPO / "scripts"))

import m7_probe as usb
import m7_terminal_repaint as terminal
from m7_terminal_steps import frame, read_ready
import build_stage6_v2 as builder
import stage6_v2_runner as r


class StreamingSession(r.Stage6Session):
    def command_stream(self, command, on_line, allowed=(0,), timeout=130):
        index = len(self.receipt["commands"])
        wire, begin, end = frame(command, index, self.receipt["nonce"])
        spec = (wire[:-1], begin, end)
        self.receipt["commands"].append(command)
        self.camera.dev.next_frame = spec[0]
        raw, lines = bytearray(), []
        normalizer = terminal.ResponseLines(spec)
        started = time.monotonic()
        in_body = False
        try:
            with usb.deadline(timeout + 10):
                self.camera.dev.writeTerminal(spec[0])
                while time.monotonic() - started < timeout:
                    chunk = self.camera.dev.readTerminal()
                    if not chunk:
                        time.sleep(0.01)
                        continue
                    raw.extend(chunk)
                    r.require(len(raw) < 2 * 1024 * 1024, "Terminal response exceeded 2 MiB")
                    new_lines = normalizer.feed(chunk)
                    lines.extend(new_lines)
                    for ln in new_lines:
                        if ln == begin:
                            in_body = True
                            continue
                        if ln.startswith(end):
                            in_body = False
                            continue
                        if in_body:
                            on_line(ln.decode("utf8", "replace"))
                    ends = [i for i, line in enumerate(lines) if line.startswith(end)]
                    if not ends:
                        continue
                    record = dict(step=index, response=raw.decode("utf8", "replace"))
                    status = terminal.ack_status(record, spec, index)
                    r.require(status is not None, "Missing ordered ACK")
                    pending = bytes(normalizer.pending)
                    r.require(
                        not lines[ends[0] + 1:] and not normalizer.soft_parts and
                        terminal.SHELL_PROMPT.startswith(pending),
                        "Unexpected trailing bytes after ACK",
                    )
                    if pending == terminal.SHELL_PROMPT:
                        r.require(status in allowed, f"Camera shell exited with {status}")
                        return b"\n".join(lines[lines.index(begin) + 1:ends[0]]), status
                raise usb.ProbeError("Missing complete ACK/prompt")
        except BaseException:
            self.camera.dev.poisoned = True
            raise
        finally:
            self.receipt["steps"].append(dict(
                step=index,
                response=raw.decode("utf8", "replace"),
                elapsed_seconds=time.monotonic() - started,
            ))


def main():
    r.OUT_DIR.mkdir(parents=True, exist_ok=True)
    utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    nonce = secrets.token_hex(6)
    out_json = r.OUT_DIR / f"{utc}-{nonce}-tethered-diag.json"
    out_log = r.OUT_DIR / f"{utc}-{nonce}-tethered-diag.log"

    daemon_tmpl, ring_tmpl, manifest = builder.verify_seal()
    configured_daemon = builder.configure_daemon(
        daemon_tmpl,
        manifest,
        duration_ms=65000,
        poll_ms=50,
        heartbeat_ms=2000,
        max_log_bytes=131072,
        daemonize=False,
        toggle_bkid=0x01071472,
        toggle_on_val=0,
        before=5,
        after=0,
        backlog_cap=96,
        debounce_ms=100,
        focus_ms=300,
        burst_cap=24,
        post_max=15,
        nonce=nonce,
    )
    configured_ring = builder.configure_ring(ring_tmpl, manifest, nonce=nonce)

    receipt = dict(
        utc=utc,
        nonce=nonce,
        action="tethered_diag",
        probe_kind="stage6-v2-tethered-diagnostic",
        daemon_template_sha256=manifest["daemon"]["sha256"],
        ring_template_sha256=manifest["ring"]["sha256"],
        daemon_sha256=builder.sha(configured_daemon),
        ring_sha256=builder.sha(configured_ring),
        log_path=str(out_log),
        commands=[],
        steps=[],
    )

    def diag(camera, rec):
        session = StreamingSession(camera, rec)
        directory = "/tmp_network/.m7-s6-" + nonce
        remote_daemon = directory + "/daemon.elf"
        remote_ring = directory + "/ring.elf"
        enable_attempted = False
        dir_created = False
        try:
            with usb.deadline(10):
                camera.setTerminalEnable(False)
                enable_attempted = True
                camera.setTerminalEnable(True)
                rec["shell_banner"] = read_ready(camera).decode("utf8", "replace")

            preflight = r.run_start_preflight(session, rec)

            # Clear stale .active-stage6-v2.json from prior battery pull if its dir is already gone.
            if r.ACTIVE_STATE.exists():
                old = r.load_active_state(r.ACTIVE_STATE)
                old_dir = old["directory"]
                st = r.inspect_dir_state(session, old_dir)
                ld, lr = r.find_all_live_s6_pids(session, old["daemon_exe"], old["ring_exe"])
                rec["stale_check"] = dict(old_dir=old_dir, state=st, live_d=ld, live_r=lr)
                r.require(st == "DIR_GONE" and not ld and not lr, f"Existing live session at {old_dir}: {st} {ld} {lr}")
                r.ACTIVE_STATE.unlink()
                rec["stale_active_cleared"] = True
                print(f"STALE_ACTIVE_CLEARED: {old_dir}", flush=True)

            r.check_no_existing_s6_dirs(session, rec)
            applets, applet_src = r.detect_busybox_applets(session)
            rec["busybox_applets_source"] = applet_src

            session.command(f"/bin/busybox mkdir {directory}")
            dir_created = True
            session.command(f"/bin/busybox chmod 700 {directory}")
            r.verify_nonsymlink_dir(session, directory)

            r.upload_elf(session, configured_ring, remote_ring, applets, "ring")
            session.command(f"/bin/busybox chmod 500 {remote_ring}")
            r.upload_elf(session, configured_daemon, remote_daemon, applets, "daemon")
            session.command(f"/bin/busybox chmod 500 {remote_daemon}")

            print("READY_STREAMING: keep USB connected. Once gate=1 appears, hold half-press ~5 s, then full-press ~1-2 s and release.", flush=True)
            log_lines = []
            with out_log.open("w", encoding="utf-8") as lf:
                def on_line(text):
                    log_lines.append(text)
                    lf.write(text + "\n")
                    lf.flush()
                    print(text, flush=True)
                    if "ev=UNRESOLVED" in text:
                        print(">>> UNRESOLVED CAPTURED LIVE (wait for daemon STOP) <<<", flush=True)

                body, rc = session.command_stream(
                    remote_daemon,
                    on_line=on_line,
                    allowed=tuple(range(256)),
                    timeout=140,
                )
            rec["daemon_rc"] = rc
            rec["log_line_count"] = len(log_lines)
            rec["summary"] = r.parse_daemon_log("\n".join(log_lines) + "\n")

            live_d, live_r = r.find_all_live_s6_pids(session, remote_daemon, remote_ring)
            rec["live_daemon_after"] = live_d
            rec["live_ring_after"] = live_r
            if live_r:
                rec["preserve_service"] = True
                im_pid = preflight["pid"]
                for rpid in live_r:
                    wc, _ = session.command(
                        f'echo "WCHAN=$(/bin/busybox cat /proc/{rpid}/wchan 2>/dev/null) '
                        f'SYSCALL=$(/bin/busybox cat /proc/{rpid}/syscall 2>/dev/null)"',
                        allowed=(0, 1),
                    )
                    rec.setdefault("ring_proc_diag", {})[str(rpid)] = wc.decode("utf8", "replace")
                    print(f"RING_PROC[{rpid}]: {wc.decode('utf8', 'replace').strip()}", flush=True)
                tr, _ = session.command(
                    f'for f in $(/bin/busybox grep -l "TracerPid:.*[1-9]" /proc/{im_pid}/task/*/status 2>/dev/null); do '
                    'echo "=== $f ==="; /bin/busybox grep -E "^(Name|State|TracerPid):" "$f"; done; true',
                    allowed=(0, 1),
                    timeout=20,
                )
                tr_txt = tr.decode("utf8", "replace")
                rec["traced_im_threads"] = tr_txt
                print("TRACED_IM_THREADS:\n" + tr_txt, flush=True)
            elif not live_d and dir_created:
                session.command(f"/bin/busybox rm -rf {directory}", allowed=(0, 1))
                chk, _ = session.command(f"if [ -e {directory} ]; then echo PRESENT; else echo GONE; fi", allowed=(0, 1))
                rec["cleanup"] = chk.decode("ascii", "replace").strip()
        finally:
            if enable_attempted and not rec.get("preserve_service") and not camera.dev.poisoned:
                try:
                    with usb.deadline(8):
                        camera.setTerminalEnable(False)
                    rec["terminal_disable_requested"] = True
                except Exception as err:
                    rec["terminal_disable_error"] = str(err)

    try:
        usb.connect(
            receipt,
            diagnostic=diag,
            gate_factory=r.Stage6Gate,
            should_stop_service=lambda: not receipt.get("preserve_service"),
        )
    except (Exception, KeyboardInterrupt) as err:
        receipt["error"] = f"{type(err).__name__}: {err}"
        print(f"ERROR={receipt['error']}", file=sys.stderr, flush=True)

    r.write_text_atomic(out_json, json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(f"LOG={out_log}", flush=True)
    print(f"RESULT={out_json}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
