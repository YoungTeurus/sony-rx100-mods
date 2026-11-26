"""Host launcher/collector for Stage 6 WIP v1 read-only untethered RAM daemon probe."""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(HERE))

import m7_probe as usb
import m7_burst_identity as identity
import m7_terminal_repaint as terminal
from m7_terminal_steps import frame, read_ready
from m7_terminal_check import PACKETS
import build_stage6 as builder

OUT_DIR = ROOT / "work/stage6-menu/wip1"
ACTIVE_STATE = OUT_DIR / ".active-stage6.json"
REMOTE_DIR_RE = re.compile(r"^/tmp_network/\.m7-s6-[0-9a-f]{12}$")
REMOTE_ELF_RE = re.compile(r"^/tmp_network/\.m7-s6-[0-9a-f]{12}/probe\.elf$")


def require(cond, msg):
    if not cond:
        raise usb.ProbeError(msg)


def validate_pid(text: str) -> int:
    s = text.strip()
    require(re.fullmatch(r"[1-9][0-9]{0,9}", s), f"Invalid PID token: {text!r}")
    val = int(s)
    require(1 < val < 0x80000000, f"PID out of range: {val}")
    return val


def parse_proc_stat(text: str, expected_pid: int, expected_comm: str):
    s = text.strip()
    prefix = f"{expected_pid} ({expected_comm}) "
    if not s.startswith(prefix):
        return None
    fields = s[len(prefix):].split()
    if len(fields) < 20 or not fields[19].isdigit():
        return None
    return dict(state=fields[0], starttime=int(fields[19]))


def parse_proc_status(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


class Stage6Gate:
    """Allow only audited terminal selection packets and exact framed commands."""
    def __init__(self, device):
        self.device = device
        self.next_frame = None
        self.poisoned = False
        self.pending = bytearray()
        self.packet_log = []

    def sendSenserPacket(self, function, payload, output=None):
        require((function, payload) in PACKETS, "Disallowed Senser service packet requested")
        self.packet_log.append(dict(function=function, payload=payload.hex()))
        return self.device.sendSenserPacket(function, payload, output)

    def readTerminal(self):
        if self.pending:
            data = bytes(self.pending)
            self.pending.clear()
            return data
        return self.device.readTerminal()

    def writeTerminal(self, data):
        require(not self.poisoned and data == self.next_frame, "Unapproved or duplicate terminal frame")
        self.next_frame = None
        try:
            driver = self.device.driver
            for start in range(0, len(data), 32):
                chunk = data[start:start + 32]
                written = driver.backend.dev.write(driver.epOut[1], chunk)
                require(type(written) is int and written == len(chunk), "Short USB OUT write")
                self.pending.extend(self.device.readTerminal())
                require(len(self.pending) <= 256 * 1024, "Terminal receive overflow")
                time.sleep(0.01)
        except BaseException:
            self.poisoned = True
            raise


class Stage6Session:
    def __init__(self, camera, receipt):
        self.camera = camera
        self.receipt = receipt

    def command(self, command, allowed=(0,), timeout=12):
        index = len(self.receipt["commands"])
        wire, begin, end = frame(command, index, self.receipt["nonce"])
        spec = (wire[:-1], begin, end)
        self.receipt["commands"].append(command)
        self.camera.dev.next_frame = spec[0]
        raw, lines = bytearray(), []
        normalizer = terminal.ResponseLines(spec)
        started = time.monotonic()
        try:
            with usb.deadline(timeout + 5):
                self.camera.dev.writeTerminal(spec[0])
                while time.monotonic() - started < timeout:
                    chunk = self.camera.dev.readTerminal()
                    raw.extend(chunk)
                    require(len(raw) < 512 * 1024, "Terminal response exceeded 512 KiB")
                    lines.extend(normalizer.feed(chunk))
                    ends = [i for i, line in enumerate(lines) if line.startswith(end)]
                    if not ends:
                        continue
                    record = dict(step=index, response=raw.decode("utf8", "replace"))
                    status = terminal.ack_status(record, spec, index)
                    require(status is not None, "Missing ordered ACK")
                    pending = bytes(normalizer.pending)
                    require(not lines[ends[0] + 1:] and not normalizer.soft_parts and
                            terminal.SHELL_PROMPT.startswith(pending), "Unexpected trailing bytes after ACK")
                    if pending == terminal.SHELL_PROMPT:
                        require(status in allowed, f"Camera shell exited with {status}")
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


def run_start_preflight(session, receipt):
    """Pin M7 1.00 firmware, ro /usr, 1 MiB rw exec tmpfs /tmp_network, and live im.elf."""
    commands = identity.preflight_commands()
    bodies = [
        session.command(c, allowed=(0, 1) if i == 4 else (0,))[0].decode("utf8", "replace")
        for i, c in enumerate(commands)
    ]
    preflight = identity.checked_preflight(bodies, receipt["model"])
    receipt["preflight"] = preflight
    return preflight


def run_collect_preflight(session, receipt):
    """Pin M7 1.00 firmware and mounts for collection, allowing im.elf to be absent (im_exit)."""
    commands = identity.preflight_commands()
    bodies = []
    im_pid_rc = 0
    for i, c in enumerate(commands):
        allowed = (0, 1) if i in (4, 6) else (0,)
        body, rc = session.command(c, allowed=allowed)
        if i == 6:
            im_pid_rc = rc
        bodies.append(body.decode("utf8", "replace"))
    im_present = (im_pid_rc == 0 and bool(bodies[6].strip()))
    # Reuse audited checked_preflight verbatim, passing a placeholder PID only when im.elf exited.
    check_bodies = list(bodies)
    if not im_present:
        check_bodies[6] = "2"
    preflight = identity.checked_preflight(check_bodies, receipt["model"])
    if not im_present:
        preflight["pid"] = None
        preflight["im_present_at_collect"] = False
    else:
        preflight["im_present_at_collect"] = True
    receipt["preflight"] = preflight
    return preflight


def upload_elf(session, image: bytes, remote_elf: str):
    require(re.fullmatch(r"/tmp_network/\.m7-s6-[0-9a-f]{12}/probe\.elf", remote_elf),
            f"Invalid remote ELF path: {remote_elf!r}")
    applets_raw, st = session.command("/bin/busybox --list", allowed=(0, 1, 127))
    applets = set(applets_raw.decode("ascii", "replace").splitlines()) if st == 0 else set()
    compressed = gzip.compress(image, mtime=0)
    packed = "gunzip" in applets and len(compressed) < len(image)
    payload = compressed if packed else image
    encoded = "base64" in applets
    dest = remote_elf + ".gz" if packed else remote_elf
    chunk_size = 192 if encoded else 64
    session.receipt["upload"] = dict(
        elf_bytes=len(image),
        transfer_bytes=len(payload),
        compression="gzip" if packed else "none",
        encoding="base64" if encoded else "octal",
    )
    print(f"UPLOAD_PLAN: ELF={len(image)} B, transfer={len(payload)} B", flush=True)
    for off in range(0, len(payload), chunk_size):
        chunk = payload[off:off + chunk_size]
        redir = "> " if off == 0 else ">> "
        if encoded:
            cmd = "/bin/busybox echo -n '" + base64.b64encode(chunk).decode("ascii") + "' | /bin/busybox base64 -d " + redir + dest
        else:
            cmd = "/bin/busybox echo -ne '" + "".join("\\0%03o" % b for b in chunk) + "' " + redir + dest
        session.command(cmd)
    if packed:
        session.command(f"/bin/busybox gunzip -c {dest} > {remote_elf}")
        session.command(f"/bin/busybox rm -f {dest}")
    expected = hashlib.md5(image).hexdigest() + "  " + remote_elf
    actual = session.command(f"/bin/busybox md5sum {remote_elf}")[0].decode("ascii", "replace").strip()
    require(actual == expected, f"MD5 mismatch after upload: {actual!r} != {expected!r}")


def parse_probe_log(text: str) -> dict:
    boot = None
    states = []
    heartbeats = []
    stops = []
    unknown = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        kind = parts[0]
        kv = {}
        extra = []
        for token in parts[1:]:
            if "=" in token:
                k, v = token.split("=", 1)
                kv[k] = v
            else:
                extra.append(token)
        if extra:
            kv["_extra"] = " ".join(extra)
        if kind == "BOOT":
            boot = kv
        elif kind == "STATE":
            states.append(kv)
        elif kind == "HB":
            heartbeats.append(kv)
        elif kind == "STOP":
            stops.append(kv)
        else:
            unknown.append(line)

    # Filter invalid rows (cam!=1, bk_ok!=1, sub_ok!=1, half_ok!=1) out of enum summaries.
    drives = sorted({s.get("drive") for s in states if s.get("cam") == "1" and s.get("drive")})
    formats = sorted({(s.get("fmt"), s.get("size"), s.get("asp"), s.get("qual"))
                      for s in states if s.get("cam") == "1"})
    bk_vals = sorted({s.get("bk") for s in states if s.get("bk_ok") == "1"})
    sub_ens = sorted({s.get("sub_en") for s in states if s.get("sub_ok") == "1"})
    halves = sorted({s.get("half") for s in states if s.get("half_ok") == "1"})
    fulls = sorted({s.get("full") for s in states if s.get("full_ok") == "1"})
    hb_times = [int(h["t"]) for h in heartbeats if h.get("t", "").isdigit()]
    return dict(
        boot=boot,
        state_count=len(states),
        heartbeat_count=len(heartbeats),
        heartbeat_span_ms=(max(hb_times) - min(hb_times)) if len(hb_times) >= 2 else (hb_times[0] if hb_times else 0),
        stop=stops[-1] if stops else None,
        drives_seen=drives,
        formats_seen=[list(x) for x in formats],
        bk_values_seen=bk_vals,
        sub_enabled_seen=sub_ens,
        half_values_seen=halves,
        full_values_seen=fulls,
        states=states,
        heartbeats=heartbeats,
        unknown_lines=unknown,
    )


def verify_live_daemon_identity(session, pid: int, expected_exe: str, expected_starttime=None):
    """Verify live process owns exact exe path, Name=probe.elf, and optional starttime."""
    exe_raw, exe_rc = session.command(f"/bin/busybox readlink /proc/{pid}/exe 2>/dev/null", allowed=(0, 1))
    exe = exe_raw.decode("utf8", "replace").strip() if exe_rc == 0 else ""
    stat_raw, stat_rc = session.command(f"/bin/busybox cat /proc/{pid}/stat 2>/dev/null", allowed=(0, 1))
    stat_txt = stat_raw.decode("utf8", "replace") if stat_rc == 0 else ""
    status_raw, status_rc = session.command(f"/bin/busybox cat /proc/{pid}/status 2>/dev/null", allowed=(0, 1))
    status_txt = status_raw.decode("utf8", "replace") if status_rc == 0 else ""

    parsed_stat = parse_proc_stat(stat_txt, pid, "probe.elf") if stat_rc == 0 else None
    parsed_status = parse_proc_status(status_txt) if status_rc == 0 else {}

    matches = (
        exe_rc == 0 and exe == expected_exe and
        parsed_stat is not None and
        parsed_status.get("Name") == "probe.elf" and
        parsed_status.get("Pid") == str(pid) and
        parsed_status.get("Tgid") == str(pid) and
        (expected_starttime is None or parsed_stat["starttime"] == expected_starttime)
    )
    return dict(
        matches=matches,
        exe=exe,
        stat=parsed_stat,
        status=parsed_status,
        status_raw=status_txt,
    )


def inspect_dir_state(session, directory: str) -> str:
    require(REMOTE_DIR_RE.fullmatch(directory), f"Invalid Stage 6 RAM directory: {directory!r}")
    out, _ = session.command(
        f'if [ -d {directory} ] && [ ! -L {directory} ]; then echo DIR_OK; '
        f'elif [ ! -e {directory} ] && [ ! -L {directory} ]; then echo DIR_GONE; '
        f'else echo BAD; fi'
    )
    return out.decode("ascii", "replace").strip()


def verify_nonsymlink_dir(session, directory: str):
    state = inspect_dir_state(session, directory)
    require(state == "DIR_OK", f"Unexpected path state {state!r} at {directory}")


def check_no_existing_s6_dirs(session, receipt):
    cmd = 'for d in /tmp_network/.m7-s6-*; do if [ -e "$d" ] || [ -L "$d" ]; then echo "$d"; fi; done'
    body, _ = session.command(cmd)
    paths = [line.strip() for line in body.decode("ascii", "replace").splitlines() if line.strip()]
    receipt["ram_s6_dir_check"] = dict(clear=not paths, paths=paths)
    require(not paths, f"Leftover Stage 6 RAM path(s) present: {paths}; run --collect or power-cycle camera first.")


def find_live_pids_for_exe(session, expected_exe: str) -> list:
    """Read-only scan of /proc/[1-9]*/exe for any live process executing expected_exe."""
    require(REMOTE_ELF_RE.fullmatch(expected_exe), f"Invalid Stage 6 ELF path: {expected_exe!r}")
    out, _ = session.command(
        f'for p in /proc/[1-9]*; do case "$(/bin/busybox readlink "$p/exe" 2>/dev/null)" '
        f'in "{expected_exe}"|"{expected_exe} "*) echo "$p";; esac; done'
    )
    pids = []
    for line in out.decode("ascii", "replace").splitlines():
        s = line.strip()
        if s.startswith("/proc/"):
            pids.append(validate_pid(s[len("/proc/"):]))
    return sorted(set(pids))


def request_stop_via_file(session, directory: str, expected_exe: str, expected_pid=None, expected_starttime=None):
    """Stop ONLY this daemon instance via its private nonce stop file (zero kill/PID race!)."""
    verify_nonsymlink_dir(session, directory)
    require(expected_exe == directory + "/probe.elf", f"Mismatched exe path {expected_exe!r} for {directory!r}")
    stop_file = directory + "/stop"
    session.command(
        f'if [ ! -L {stop_file} ]; then /bin/busybox echo stop > {stop_file}; else exit 1; fi'
    )
    last_live = []
    for _ in range(6):
        session.command("/bin/busybox sleep 1")
        last_live = find_live_pids_for_exe(session, expected_exe)
        id_alive = False
        if expected_pid is not None:
            recheck = verify_live_daemon_identity(session, expected_pid, expected_exe, expected_starttime)
            id_alive = bool(recheck["matches"])
        if not id_alive and not last_live:
            return True, []
    return False, last_live


def fsync_dir(directory: Path):
    dfd = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def write_text_atomic(path: Path, text: str):
    """Write text atomically via temp file + fsync + replace + parent dir fsync."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        fsync_dir(path.parent)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def persist_collected_log_atomic(log_text: str, out_dir: Path, utc: str, nonce: str) -> Path:
    """Persist collected probe.log durably on host BEFORE deleting camera RAM directory."""
    log_path = out_dir / f"{utc}-{nonce}-probe.log"
    write_text_atomic(log_path, log_text)
    return log_path


def write_active_state_exclusive(state: dict, path: Path = ACTIVE_STATE):
    """Atomically create active custody file exclusively (never leaves a partial file)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with tmp.open("x") as stream:
            json.dump(state, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(tmp, path)
        fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def replace_active_state_atomic(state: dict, path: Path = ACTIVE_STATE):
    """Atomically replace existing active custody file (never leaves a leftover .tmp)."""
    write_text_atomic(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def load_active_state(path: Path = ACTIVE_STATE) -> dict:
    require(path.is_file(), f"No active Stage 6 session file at {path}; run --start first.")
    state = json.loads(path.read_text())
    nonce = state.get("nonce", "")
    directory = state.get("directory", "")
    status = state.get("status", "")
    require(status in ("pending_upload", "pending_launch", "running"), f"Corrupt active state status: {status!r}")
    require(re.fullmatch(r"[0-9a-f]{12}", nonce), "Corrupt active state nonce")
    require(directory == "/tmp_network/.m7-s6-" + nonce, "Corrupt active state directory")
    require(state.get("daemon_exe") == directory + "/probe.elf", "Corrupt active state exe")
    if status == "running":
        require(type(state.get("daemon_pid")) is int and 1 < state["daemon_pid"] < 0x80000000, "Corrupt active state pid")
        require(type(state.get("daemon_starttime")) is int and state["daemon_starttime"] >= 0, "Corrupt active state starttime")
    else:
        require(state.get("daemon_pid") is None and state.get("daemon_starttime") is None, "Corrupt pending active state")
    return state


def inspect_log_file_state(session, remote_log: str) -> str:
    require(re.fullmatch(r"/tmp_network/\.m7-s6-[0-9a-f]{12}/probe\.log", remote_log),
            f"Invalid Stage 6 log path: {remote_log!r}")
    out, _ = session.command(
        f'if [ -f {remote_log} ] && [ ! -L {remote_log} ]; then echo LOG_OK; '
        f'elif [ ! -e {remote_log} ] && [ ! -L {remote_log} ]; then echo LOG_ABSENT; '
        f'else echo LOG_BAD; fi'
    )
    return out.decode("ascii", "replace").strip()


def verify_usable_initial_witnesses(summary: dict, daemon_pid: int, im_pid: int):
    boot = summary.get("boot")
    require(boot is not None, "Missing BOOT record in initial log")
    require(boot.get("self_pid") == str(daemon_pid), f"BOOT self_pid mismatch: {boot.get('self_pid')} != {daemon_pid}")
    require(boot.get("im_pid") == str(im_pid), f"BOOT im_pid mismatch: {boot.get('im_pid')} != {im_pid}")
    require(boot.get("uipc_ok") == "1", f"/dev/uipc init failed: uipc_err={boot.get('uipc_err')}")
    require(boot.get("bk_sz") == "1", f"BackupID datasize != 1: bk_sz={boot.get('bk_sz')} bk_rc={boot.get('bk_rc')}")
    require(boot.get("in_ok") == "1", "InfraInput watch init failed (in_ok!=1)")
    mon_proc = boot.get("mon_proc", "")
    mon_mwf = boot.get("mon_mwf", "")
    require(re.fullmatch(r"[1-9][0-9]*", mon_proc) and mon_proc == mon_mwf,
            f"Monitor TID mismatch/missing: proc={mon_proc!r} mwf={mon_mwf!r}")
    require(summary.get("state_count", 0) >= 1, "Missing initial STATE record")
    require(summary.get("stop") is None, f"Daemon already emitted STOP: {summary.get('stop')}")
    first = summary["states"][0]
    require(first.get("cam") == "1", f"Initial CamSetParams read invalid: {first}")
    require(first.get("bk_ok") == "1" and first.get("bk_rc") == "0", f"Initial Backup_read failed: {first}")
    require(first.get("sub_ok") == "1", f"Initial subscription read invalid: {first}")
    require(first.get("half_ok") == "1" and first.get("full_ok") == "1", f"Initial shutter rows invalid: {first}")


def do_start(camera, receipt, image, active_path: Path = ACTIVE_STATE):
    require(not active_path.exists(), f"Active Stage 6 session already exists at {active_path}; run --collect first.")
    session = Stage6Session(camera, receipt)
    directory = "/tmp_network/.m7-s6-" + receipt["nonce"]
    remote_elf = directory + "/probe.elf"
    remote_pid = directory + "/probe.pid"
    remote_log = directory + "/probe.log"
    enable_attempted = False
    dir_created = False
    custody_created = False
    launched = False
    stopped_after_fail = False
    daemon_pid = None
    daemon_starttime = None
    try:
        with usb.deadline(10):
            camera.setTerminalEnable(False)
            enable_attempted = True
            camera.setTerminalEnable(True)
            receipt["shell_banner"] = read_ready(camera).decode("utf8", "replace")

        preflight = run_start_preflight(session, receipt)
        check_no_existing_s6_dirs(session, receipt)

        # Persist custody BEFORE the very first remote mutation so an interrupted upload is always recoverable.
        pending_upload = dict(
            status="pending_upload",
            nonce=receipt["nonce"],
            directory=directory,
            daemon_pid=None,
            daemon_starttime=None,
            daemon_exe=remote_elf,
            probe_sha256=receipt["probe_sha256"],
            utc=receipt["utc"],
        )
        write_active_state_exclusive(pending_upload, active_path)
        custody_created = True

        session.command(f"/bin/busybox mkdir {directory}")
        dir_created = True
        session.command(f"/bin/busybox chmod 700 {directory}")
        verify_nonsymlink_dir(session, directory)

        upload_elf(session, image, remote_elf)
        session.command(f"/bin/busybox chmod 500 {remote_elf}")

        # Upgrade custody to pending_launch BEFORE executing probe.elf.
        pending_launch = dict(pending_upload, status="pending_launch")
        replace_active_state_atomic(pending_launch, active_path)

        launched = True
        out, rc = session.command(remote_elf, allowed=tuple(range(256)), timeout=10)
        receipt["launch_output"] = out.decode("utf8", "replace")
        receipt["launch_rc"] = rc
        require(rc == 0, f"probe.elf launcher exited with {rc}")

        # Wait up to 4 s for probe.pid (published only after discovery + initial Backup + BOOT + STATE).
        pid_txt = ""
        for _ in range(4):
            session.command("/bin/busybox sleep 1")
            pid_raw, pid_rc = session.command(
                f"if [ -f {remote_pid} ] && [ ! -L {remote_pid} ]; then /bin/busybox cat {remote_pid}; fi",
                allowed=(0, 1),
            )
            pid_txt = pid_raw.decode("ascii", "replace").strip() if pid_rc == 0 else ""
            if pid_txt:
                break

        log_raw, _ = session.command(
            f"if [ -f {remote_log} ] && [ ! -L {remote_log} ]; then /bin/busybox cat {remote_log}; fi",
            allowed=(0, 1),
        )
        initial_log = log_raw.decode("utf8", "replace")
        receipt["initial_log"] = initial_log
        summary = parse_probe_log(initial_log)
        receipt["initial_summary"] = summary

        require(bool(pid_txt), f"Daemon did not publish probe.pid; log={initial_log.strip()!r}")
        daemon_pid = validate_pid(pid_txt)
        ident = verify_live_daemon_identity(session, daemon_pid, remote_elf)
        receipt["daemon_identity_at_start"] = ident
        require(ident["matches"], f"Live PID {daemon_pid} does not match {remote_elf}")
        daemon_starttime = ident["stat"]["starttime"]
        require(ident["status"].get("PPid") == "1", f"Daemon not reparented to PID 1: PPid={ident['status'].get('PPid')!r}")
        require(ident["status"].get("TracerPid") == "0", f"Unexpected TracerPid={ident['status'].get('TracerPid')!r}")

        verify_usable_initial_witnesses(summary, daemon_pid, preflight["pid"])

        # Atomically upgrade active custody to "running" BEFORE setting start_ready=True.
        running_record = dict(
            status="running",
            nonce=receipt["nonce"],
            directory=directory,
            daemon_pid=daemon_pid,
            daemon_starttime=daemon_starttime,
            daemon_exe=remote_elf,
            probe_sha256=receipt["probe_sha256"],
            utc=receipt["utc"],
        )
        replace_active_state_atomic(running_record, active_path)

        receipt["daemon_pid"] = daemon_pid
        receipt["daemon_starttime"] = daemon_starttime
        receipt["directory"] = directory
        receipt["start_ready"] = True

        print(f"DAEMON_STARTED: PID={daemon_pid} starttime={daemon_starttime} dir={directory}", flush=True)
        for line in initial_log.splitlines()[:6]:
            print("  " + line, flush=True)
    except BaseException:
        # Stop via per-nonce stop file (zero kill/PID race!) if launched, else clean dir directly.
        if launched and dir_created and not camera.dev.poisoned:
            try:
                stopped_after_fail, live_after = request_stop_via_file(
                    session, directory, remote_elf,
                    expected_pid=daemon_pid,
                    expected_starttime=daemon_starttime,
                )
                receipt["failed_start_stopped"] = stopped_after_fail
                receipt["failed_start_live_pids_after_stop"] = live_after
            except Exception as err:
                receipt["failed_start_stop_error"] = str(err)
        raise
    finally:
        if not receipt.get("start_ready"):
            if not dir_created and custody_created and not camera.dev.poisoned and active_path.exists():
                active_path.unlink()
                receipt["failed_start_custody_cleared"] = True
            elif dir_created and (not launched or stopped_after_fail) and not camera.dev.poisoned:
                try:
                    session.command(f"/bin/busybox rm -rf {directory}", allowed=(0, 1))
                    chk, _ = session.command(f'if [ -e {directory} ] || [ -L {directory} ]; then echo PRESENT; else echo GONE; fi', allowed=(0, 1))
                    if chk.decode("ascii", "replace").strip() == "GONE":
                        receipt["failed_start_cleanup"] = True
                        if custody_created and active_path.exists():
                            active_path.unlink()
                            receipt["failed_start_custody_cleared"] = True
                except Exception as err:
                    receipt["failed_start_cleanup_error"] = str(err)
        if enable_attempted:
            try:
                with usb.deadline(8):
                    camera.setTerminalEnable(False)
                receipt["terminal_disable_requested"] = True
            except Exception as err:
                receipt["terminal_disable_error"] = str(err)


def do_collect(camera, receipt, active_path: Path = ACTIVE_STATE, log_out_dir: Path = OUT_DIR):
    active = load_active_state(active_path)
    directory = active["directory"]
    remote_elf = active["daemon_exe"]
    remote_pid = directory + "/probe.pid"
    remote_log = directory + "/probe.log"
    expected_pid = active["daemon_pid"]
    expected_starttime = active["daemon_starttime"]
    receipt["active_session"] = active

    session = Stage6Session(camera, receipt)
    enable_attempted = False
    try:
        with usb.deadline(10):
            camera.setTerminalEnable(False)
            enable_attempted = True
            camera.setTerminalEnable(True)
            receipt["shell_banner"] = read_ready(camera).decode("utf8", "replace")

        run_collect_preflight(session, receipt)
        dir_state = inspect_dir_state(session, directory)
        receipt["remote_dir_state"] = dir_state
        if dir_state == "DIR_GONE":
            # Verify no process still executes remote_elf (e.g. unlinked binary) before stale recovery.
            live_after_gone = find_live_pids_for_exe(session, remote_elf)
            receipt["live_pids_at_collect"] = live_after_gone
            if live_after_gone:
                receipt["alive_at_collect"] = True
                receipt["stopped_cleanly"] = False
                receipt["cleanup"] = "DEFERRED_DAEMON_STILL_ALIVE"
                receipt["collect_outcome"] = "incomplete"
                return
            receipt["stale_active_recovered"] = True
            receipt["alive_at_collect"] = False
            receipt["stopped_cleanly"] = True
            receipt["cleanup"] = "DIR_ALREADY_ABSENT"
            receipt["collect_outcome"] = "stale_recovered"
            active_path.unlink()
            receipt["active_state_cleared"] = True
            return
        require(dir_state == "DIR_OK", f"Unexpected path state {dir_state!r} at {directory}")

        live_pids = find_live_pids_for_exe(session, remote_elf)
        receipt["live_pids_at_collect"] = live_pids

        pid_raw, pid_rc = session.command(
            f"if [ -f {remote_pid} ] && [ ! -L {remote_pid} ]; then /bin/busybox cat {remote_pid}; fi",
            allowed=(0, 1),
        )
        pid_txt = pid_raw.decode("ascii", "replace").strip() if pid_rc == 0 else ""
        receipt["pid_file_value"] = pid_txt

        # Determine whether the exact launched daemon is currently alive.
        alive = False
        if expected_pid is not None:
            ident = verify_live_daemon_identity(session, expected_pid, remote_elf, expected_starttime)
            receipt["daemon_identity_at_collect"] = ident
            alive = bool(ident["matches"])
            if not alive and ident["status"]:
                receipt["pid_reused_detected"] = True
        elif pid_txt:
            # Pending-launch recovery: validate pid_txt defensively without crashing before stop.
            try:
                cand_pid = validate_pid(pid_txt)
            except usb.ProbeError:
                receipt["pid_file_invalid"] = True
                cand_pid = None
            if cand_pid is not None:
                ident = verify_live_daemon_identity(session, cand_pid, remote_elf, None)
                receipt["daemon_identity_at_collect"] = ident
                alive = bool(ident["matches"])
                if alive:
                    expected_pid = cand_pid
                    expected_starttime = ident["stat"]["starttime"]
        receipt["alive_at_collect"] = bool(alive or live_pids)

        if alive or live_pids or active["status"] == "pending_launch":
            # Stop ONLY via private per-nonce stop file (zero kill/PID race!).
            stopped, live_after = request_stop_via_file(
                session, directory, remote_elf,
                expected_pid=expected_pid,
                expected_starttime=expected_starttime,
            )
            receipt["stopped_cleanly"] = stopped
            receipt["live_pids_after_stop"] = live_after
        else:
            receipt["stopped_cleanly"] = True
            receipt["live_pids_after_stop"] = []

        # Explicitly verify probe.log presence and read with strict exit status check.
        log_state = inspect_log_file_state(session, remote_log)
        receipt["remote_log_state"] = log_state
        log_text = ""
        log_read_ok = False
        if log_state == "LOG_OK":
            log_raw, log_rc = session.command(
                f"/bin/busybox cat {remote_log}",
                allowed=(0, 1),
                timeout=20,
            )
            receipt["log_read_rc"] = log_rc
            if log_rc == 0:
                log_text = log_raw.decode("utf8", "replace")
                if log_text and not log_text.endswith("\n"):
                    log_text += "\n"
                log_read_ok = True
        receipt["log_text"] = log_text
        summary = parse_probe_log(log_text)
        receipt["summary"] = summary

        # Decide whether log retrieval succeeded or whether this is a confirmed prelaunch recovery.
        is_prelaunch = active["status"] in ("pending_upload", "pending_launch")
        has_valid_log = log_read_ok and bool(log_text.strip()) and summary.get("boot") is not None
        can_cleanup_prelaunch = is_prelaunch and (log_state == "LOG_ABSENT" or (log_read_ok and bool(log_text.strip())))
        receipt["log_retrieved"] = has_valid_log

        if not receipt.get("stopped_cleanly"):
            receipt["cleanup"] = "DEFERRED_DAEMON_STILL_ALIVE"
            receipt["collect_outcome"] = "incomplete"
            return

        if not has_valid_log and not can_cleanup_prelaunch:
            receipt["cleanup"] = "DEFERRED_LOG_READ_FAILED"
            receipt["collect_outcome"] = "incomplete"
            return

        # Persist any retrieved log durably on host BEFORE removing the camera RAM directory!
        if log_read_ok and log_text:
            saved_log = persist_collected_log_atomic(log_text, log_out_dir, receipt["utc"], receipt["nonce"])
            receipt["saved_log_path"] = str(saved_log)
            receipt["log_persisted"] = True
        else:
            receipt["log_persisted"] = False

        if not has_valid_log and is_prelaunch:
            receipt["prelaunch_recovered"] = True

        verify_nonsymlink_dir(session, directory)
        session.command(f"/bin/busybox rm -rf {directory}")
        chk, _ = session.command(f'if [ -e {directory} ] || [ -L {directory} ]; then echo PRESENT; else echo GONE; fi')
        receipt["cleanup"] = chk.decode("ascii", "replace").strip()
        if receipt["cleanup"] == "GONE":
            active_path.unlink()
            receipt["active_state_cleared"] = True
            receipt["collect_outcome"] = "collected" if has_valid_log else "prelaunch_recovered"
        else:
            receipt["collect_outcome"] = "incomplete"
    finally:
        if enable_attempted:
            try:
                with usb.deadline(8):
                    camera.setTerminalEnable(False)
                receipt["terminal_disable_requested"] = True
            except Exception as err:
                receipt["terminal_disable_error"] = str(err)


def teardown_clean(receipt: dict) -> bool:
    return (
        bool(receipt.get("terminal_disable_requested")) and
        not receipt.get("terminal_disable_error") and
        bool(receipt.get("service_stop_requested")) and
        not receipt.get("service_stop_error")
    )


def evaluate_cli_success(action: str, receipt: dict) -> bool:
    if "error" in receipt or not receipt.get("teardown_requested_clean"):
        return False
    if action == "start":
        return bool(receipt.get("start_ready"))
    if not (bool(receipt.get("stopped_cleanly")) and bool(receipt.get("active_state_cleared"))):
        return False
    outcome = receipt.get("collect_outcome")
    if outcome == "stale_recovered":
        return bool(receipt.get("stale_active_recovered")) and receipt.get("cleanup") == "DIR_ALREADY_ABSENT"
    if outcome == "prelaunch_recovered":
        return bool(receipt.get("prelaunch_recovered")) and receipt.get("cleanup") == "GONE"
    if outcome == "collected":
        return (
            receipt.get("cleanup") == "GONE" and
            bool(receipt.get("log_retrieved")) and
            bool(receipt.get("log_persisted"))
        )
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--start", action="store_true", help="Upload and start sealed read-only Stage 6 RAM daemon, then exit service mode")
    mode.add_argument("--collect", action="store_true", help="Stop daemon via nonce stop file, collect log, clean RAM dir")
    parser.add_argument("--duration-sec", type=int, default=240, help="Daemon watchdog lifetime in seconds (default 240)")
    args = parser.parse_args(argv)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    nonce = secrets.token_hex(6)
    utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    kind = "start" if args.start else "collect"
    out_path = OUT_DIR / f"{utc}-{nonce}-{kind}.json"

    receipt = dict(
        stage="stage6-wip1-probe",
        action=kind,
        utc=utc,
        nonce=nonce,
        commands=[],
        steps=[],
    )

    image = None
    try:
        template, manifest = builder.verify_seal()
        receipt["sealed_template_sha256"] = manifest["sha256"]
        if args.start:
            image = builder.configure_probe(
                template, manifest,
                duration_ms=args.duration_sec * 1000,
                nonce=nonce,
            )
            receipt["probe_sha256"] = builder.sha(image)
            receipt["probe_bytes"] = len(image)
            receipt["duration_ms"] = args.duration_sec * 1000

        usb.connect(
            receipt,
            diagnostic=(lambda cam, rec: do_start(cam, rec, image)) if args.start else do_collect,
            gate_factory=Stage6Gate,
        )
    except (Exception, KeyboardInterrupt) as error:
        receipt["error"] = f"{type(error).__name__}: {error}"
        print(receipt["error"], flush=True)

    receipt["teardown_requested_clean"] = teardown_clean(receipt)
    ok = evaluate_cli_success(kind, receipt)
    receipt["cli_ok"] = ok
    try:
        write_text_atomic(out_path, json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
        print(f"RESULT={out_path}", flush=True)
    except OSError as err:
        ok = False
        print(f"RECEIPT_WRITE_ERROR: {err}", flush=True)
        if receipt.get("saved_log_path"):
            print(f"SAVED_LOG_PRESERVED={receipt['saved_log_path']}", flush=True)

    if args.start:
        if ok:
            print("NEXT: Отключите USB-кабель от камеры, пощёлкайте режимы (Покадровая/Серийная, Спуск без карты Вкл/Выкл, полунажатие), затем снова подключите USB и запустите --collect.", flush=True)
        else:
            print("START_NOT_READY: Запуск или выход из service mode не подтверждены; проверьте квитанцию перед отключением USB.", flush=True)
    else:
        if receipt.get("stale_active_recovered"):
            print("STALE_RECOVERY: Камера перезагружалась, каталог в RAM уже отсутствует; локальный маркер очищен.", flush=True)
        elif receipt.get("prelaunch_recovered"):
            print("PRELAUNCH_RECOVERY: Прерванный запуск/загрузка очищены без перезагрузки камеры.", flush=True)
        s = receipt.get("summary", {})
        print(
            f"COLLECT_SUMMARY: ok={ok} outcome={receipt.get('collect_outcome')} "
            f"alive_at_collect={receipt.get('alive_at_collect')} "
            f"stopped_cleanly={receipt.get('stopped_cleanly')} cleanup={receipt.get('cleanup')} "
            f"saved_log={receipt.get('saved_log_path')} "
            f"states={s.get('state_count')} heartbeats={s.get('heartbeat_count')} "
            f"hb_span_ms={s.get('heartbeat_span_ms')} drives={s.get('drives_seen')} "
            f"bk_vals={s.get('bk_values_seen')} sub_en={s.get('sub_enabled_seen')} "
            f"half={s.get('half_values_seen')}",
            flush=True,
        )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
