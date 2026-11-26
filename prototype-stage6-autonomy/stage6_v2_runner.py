"""Host launcher/collector for Stage 6 WIP v2 autonomous untethered RAM Pre-Capture daemon."""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
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
import build_stage6_v2 as builder

OUT_DIR = ROOT / "work/stage6-menu/wip2"
ACTIVE_STATE = OUT_DIR / ".active-stage6-v2.json"
REMOTE_DIR_RE = re.compile(r"^/tmp_network/\.m7-s6-[0-9a-f]{12}$")
REMOTE_DAEMON_RE = re.compile(r"^/tmp_network/\.m7-s6-[0-9a-f]{12}/daemon\.elf$")
REMOTE_RING_RE = re.compile(r"^/tmp_network/\.m7-s6-[0-9a-f]{12}/ring\.elf$")
REMOTE_ELF_RE = re.compile(r"^/tmp_network/\.m7-s6-[0-9a-f]{12}/(daemon|ring)\.elf$")


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
    commands = identity.preflight_commands()
    bodies = [
        session.command(c, allowed=(0, 1) if i == 4 else (0,))[0].decode("utf8", "replace")
        for i, c in enumerate(commands)
    ]
    preflight = identity.checked_preflight(bodies, receipt["model"])
    receipt["preflight"] = preflight
    return preflight


def run_collect_preflight(session, receipt):
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


def detect_busybox_applets(session):
    """Detect available BusyBox applets, falling back to /bin/busybox help text (M7 1.00)."""
    listed, status = session.command("/bin/busybox --list", allowed=(0, 1, 127))
    source = "busybox-list"
    names = listed.decode("ascii", "replace").splitlines() if status == 0 else []
    if not names or not all(re.fullmatch(r"[A-Za-z0-9_.+\[\]-]+", n) for n in names):
        banner, help_status = session.command("/bin/busybox", allowed=(0, 1, 127))
        text = banner.decode("ascii", "replace").replace("\r", "")
        parts = text.split("Currently defined functions:\n")
        names = (
            re.split(r"[,\s]+", parts[1].strip())
            if help_status in (0, 1) and text.startswith("BusyBox v") and len(parts) == 2
            else []
        )
        source = "busybox-help"
    if not names or not all(re.fullmatch(r"[A-Za-z0-9_.+\[\]-]+", n) for n in names):
        names = []
        source = "unavailable"
    return set(names), source


SAFE_ASCII_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,_:/+@="
)


def encode_echo_mixed(chunk: bytes) -> str:
    """Encode bytes for BusyBox `echo -ne '...'` using inert ASCII (no '-', '\\', or quotes) + unambiguous 3-digit octal."""
    out = []
    prev_esc = False
    for b in chunk:
        if b in SAFE_ASCII_BYTES and not (prev_esc and 0x30 <= b <= 0x37):
            out.append(chr(b))
            prev_esc = False
        else:
            out.append("\\0%03o" % b)
            prev_esc = True
    return "".join(out)


def upload_chunk_command(chunk: bytes, destination: str, encoded: bool, first: bool) -> str:
    redir = "> " if first else ">> "
    if encoded:
        return "/bin/busybox echo -n '" + base64.b64encode(chunk).decode("ascii") + "' | /bin/busybox base64 -d " + redir + destination
    return "/bin/busybox echo -ne '" + encode_echo_mixed(chunk) + "' " + redir + destination


def plan_upload_chunks(payload: bytes, dest: str, encoded: bool, base_cmd_idx: int, nonce: str) -> list:
    """Pack variable-size chunks so every framed command stays strictly < 512 wire bytes."""
    require(len(payload) > 0, f"Empty upload payload for {dest}")
    if encoded:
        for cand in range(240, 0, -1):
            last_idx = base_cmd_idx + (len(payload) + cand - 1) // cand - 1
            cmd = upload_chunk_command(bytes(cand), dest, True, first=False)
            try:
                wire, _, _ = frame(cmd, last_idx, nonce)
                if len(wire) < 512:
                    return [payload[off:off + cand] for off in range(0, len(payload), cand)]
            except ValueError:
                continue
        raise usb.ProbeError(f"No valid base64 chunk size for {dest}")

    # Compute exact max encoded string length allowed for the worst-case command index.
    worst_idx = base_cmd_idx + len(payload)
    empty_wire, _, _ = frame(f"/bin/busybox echo -ne '' >> {dest}", worst_idx, nonce)
    max_enc_len = 511 - len(empty_wire)
    require(max_enc_len >= 16, f"No valid mixed-octal budget for {dest}")

    chunks = []
    pos = 0
    n = len(payload)
    while pos < n:
        cur = bytearray()
        enc_len = 0
        prev_esc = False
        while pos < n:
            b = payload[pos]
            if b in SAFE_ASCII_BYTES and not (prev_esc and 0x30 <= b <= 0x37):
                add = 1
                next_esc = False
            else:
                add = 5
                next_esc = True
            if enc_len + add > max_enc_len:
                break
            cur.append(b)
            enc_len += add
            prev_esc = next_esc
            pos += 1
        require(len(cur) > 0, f"Failed to pack byte at offset {pos} for {dest}")
        chunk_bytes = bytes(cur)
        idx = len(chunks)
        wire, _, _ = frame(upload_chunk_command(chunk_bytes, dest, False, first=(idx == 0)), base_cmd_idx + idx, nonce)
        require(len(wire) < 512, f"Mixed-octal chunk {idx} exceeded 511 wire bytes: {len(wire)}")
        chunks.append(chunk_bytes)
    return chunks


def upload_elf(session, image: bytes, remote_elf: str, applets: set, label: str):
    require(REMOTE_ELF_RE.fullmatch(remote_elf), f"Invalid remote ELF path: {remote_elf!r}")
    compressed = gzip.compress(image, mtime=0)
    packed = "gunzip" in applets and len(compressed) < len(image)
    payload = compressed if packed else image
    encoded = "base64" in applets
    dest = remote_elf + ".gz" if packed else remote_elf

    chunk_list = plan_upload_chunks(payload, dest, encoded, len(session.receipt["commands"]), session.receipt["nonce"])
    chunks = len(chunk_list)
    info = dict(
        label=label,
        remote=remote_elf,
        elf_bytes=len(image),
        transfer_bytes=len(payload),
        compression="gzip" if packed else "none",
        encoding="base64" if encoded else "mixed-octal",
        chunks=chunks,
    )
    session.receipt.setdefault("uploads", []).append(info)
    print(
        f"UPLOAD_PLAN[{label}]: ELF={len(image)} B, transfer={len(payload)} B "
        f"({info['compression']}+{info['encoding']}, {chunks} chunks)",
        flush=True,
    )
    started = time.monotonic()
    for idx, chunk in enumerate(chunk_list, 1):
        cmd = upload_chunk_command(chunk, dest, encoded, first=(idx == 1))
        session.command(cmd)
        if idx == chunks or (idx % 25 == 0):
            elapsed = time.monotonic() - started
            pct = int(idx * 100 // chunks) if chunks else 100
            eta = (elapsed * (chunks - idx) / idx) if idx else 0.0
            print(
                f"UPLOAD[{label}]: {idx}/{chunks} ({pct}%) elapsed={elapsed:.1f}s eta={eta:.1f}s",
                flush=True,
            )
    if packed:
        session.command(f"/bin/busybox gunzip -c {dest} > {remote_elf}", timeout=20)
        session.command(f"/bin/busybox rm -f {dest}")
    expected = hashlib.md5(image).hexdigest() + "  " + remote_elf
    actual = session.command(f"/bin/busybox md5sum {remote_elf}")[0].decode("ascii", "replace").strip()
    require(actual == expected, f"MD5 mismatch after upload of {label}: {actual!r} != {expected!r}")


def parse_daemon_log(text: str) -> dict:
    boot = None
    states = []
    heartbeats = []
    ring_starts = []
    ring_events = []
    ring_files = []
    ring_exits = []
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
        elif kind == "RING_START":
            ring_starts.append(kv)
        elif kind == "RING_EVT":
            ring_events.append(kv)
        elif kind == "RING_FILE":
            ring_files.append(kv)
        elif kind == "RING_EXIT":
            ring_exits.append(kv)
        elif kind == "STOP":
            stops.append(kv)
        else:
            unknown.append(line)

    drives = sorted({s.get("drive") for s in states if s.get("cam") == "1" and s.get("drive")})
    formats = sorted({(s.get("fmt"), s.get("size"), s.get("asp"), s.get("qual"))
                      for s in states if s.get("cam") == "1"})
    bk_vals = sorted({s.get("bk") for s in states if s.get("bk_ok") == "1"})
    sub_ens = sorted({s.get("sub_en") for s in states if s.get("sub_ok") == "1"})
    gates = sorted({s.get("gate") for s in states if s.get("gate") is not None})
    hb_times = [int(h["t"]) for h in heartbeats if h.get("t", "").isdigit()]
    unresolved = [e for e in ring_events if e.get("ev") == "UNRESOLVED"]
    return dict(
        boot=boot,
        state_count=len(states),
        heartbeat_count=len(heartbeats),
        heartbeat_span_ms=(max(hb_times) - min(hb_times)) if len(hb_times) >= 2 else (hb_times[0] if hb_times else 0),
        ring_start_count=len(ring_starts),
        ring_exit_count=len(ring_exits),
        ring_file_count=len(ring_files),
        ring_unresolved_count=len(unresolved),
        stop=stops[-1] if stops else None,
        drives_seen=drives,
        formats_seen=[list(x) for x in formats],
        bk_values_seen=bk_vals,
        sub_enabled_seen=sub_ens,
        gates_seen=gates,
        states=states,
        heartbeats=heartbeats,
        ring_starts=ring_starts,
        ring_events=ring_events,
        ring_files=ring_files,
        ring_exits=ring_exits,
        unknown_lines=unknown,
    )


def verify_live_daemon_identity(session, pid: int, expected_exe: str, expected_starttime=None):
    exe_raw, exe_rc = session.command(f"/bin/busybox readlink /proc/{pid}/exe 2>/dev/null", allowed=(0, 1))
    exe = exe_raw.decode("utf8", "replace").strip() if exe_rc == 0 else ""
    stat_raw, stat_rc = session.command(f"/bin/busybox cat /proc/{pid}/stat 2>/dev/null", allowed=(0, 1))
    stat_txt = stat_raw.decode("utf8", "replace") if stat_rc == 0 else ""
    status_raw, status_rc = session.command(f"/bin/busybox cat /proc/{pid}/status 2>/dev/null", allowed=(0, 1))
    status_txt = status_raw.decode("utf8", "replace") if status_rc == 0 else ""

    parsed_stat = parse_proc_stat(stat_txt, pid, "daemon.elf") if stat_rc == 0 else None
    parsed_status = parse_proc_status(status_txt) if status_rc == 0 else {}

    matches = (
        exe_rc == 0 and exe == expected_exe and
        parsed_stat is not None and
        parsed_status.get("Name") == "daemon.elf" and
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


def find_all_live_s6_pids(session, daemon_exe: str, ring_exe: str) -> tuple:
    d_pids = find_live_pids_for_exe(session, daemon_exe)
    r_pids = find_live_pids_for_exe(session, ring_exe)
    return d_pids, r_pids


def request_stop_via_file(
    session,
    directory: str,
    daemon_exe: str,
    ring_exe: str,
    expected_pid=None,
    expected_starttime=None,
    max_polls: int = 250,
):
    """Stop ONLY this daemon + ring instance via private nonce stop file (zero kill/PID race!)."""
    verify_nonsymlink_dir(session, directory)
    require(daemon_exe == directory + "/daemon.elf", f"Mismatched daemon exe {daemon_exe!r}")
    require(ring_exe == directory + "/ring.elf", f"Mismatched ring exe {ring_exe!r}")
    stop_file = directory + "/stop"
    session.command(
        f'if [ ! -L {stop_file} ]; then /bin/busybox echo stop > {stop_file}; else exit 1; fi'
    )
    last_d, last_r = [], []
    for _ in range(max_polls):
        session.command("/bin/busybox sleep 1")
        last_d, last_r = find_all_live_s6_pids(session, daemon_exe, ring_exe)
        id_alive = False
        if expected_pid is not None:
            recheck = verify_live_daemon_identity(session, expected_pid, daemon_exe, expected_starttime)
            id_alive = bool(recheck["matches"])
        if not id_alive and not last_d and not last_r:
            return True, [], []
    return False, last_d, last_r


def fsync_dir(directory: Path):
    dfd = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def write_text_atomic(path: Path, text: str):
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
    log_path = out_dir / f"{utc}-{nonce}-daemon.log"
    write_text_atomic(log_path, log_text)
    return log_path


def write_active_state_exclusive(state: dict, path: Path = ACTIVE_STATE):
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
    write_text_atomic(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def load_active_state(path: Path = ACTIVE_STATE) -> dict:
    require(path.is_file(), f"No active Stage 6 WIP v2 session file at {path}; run --start first.")
    state = json.loads(path.read_text())
    nonce = state.get("nonce", "")
    directory = state.get("directory", "")
    status = state.get("status", "")
    require(status in ("pending_upload", "pending_launch", "running"), f"Corrupt active state status: {status!r}")
    require(re.fullmatch(r"[0-9a-f]{12}", nonce), "Corrupt active state nonce")
    require(directory == "/tmp_network/.m7-s6-" + nonce, "Corrupt active state directory")
    require(state.get("daemon_exe") == directory + "/daemon.elf", "Corrupt active state daemon_exe")
    require(state.get("ring_exe") == directory + "/ring.elf", "Corrupt active state ring_exe")
    if status == "running":
        require(type(state.get("daemon_pid")) is int and 1 < state["daemon_pid"] < 0x80000000, "Corrupt active state pid")
        require(type(state.get("daemon_starttime")) is int and state["daemon_starttime"] >= 0, "Corrupt active state starttime")
    else:
        require(state.get("daemon_pid") is None and state.get("daemon_starttime") is None, "Corrupt pending active state")
    return state


def inspect_log_file_state(session, remote_log: str) -> str:
    require(re.fullmatch(r"/tmp_network/\.m7-s6-[0-9a-f]{12}/daemon\.log", remote_log),
            f"Invalid Stage 6 log path: {remote_log!r}")
    out, _ = session.command(
        f'if [ -f {remote_log} ] && [ ! -L {remote_log} ]; then echo LOG_OK; '
        f'elif [ ! -e {remote_log} ] && [ ! -L {remote_log} ]; then echo LOG_ABSENT; '
        f'else echo LOG_BAD; fi'
    )
    return out.decode("ascii", "replace").strip()


def verify_usable_initial_witnesses(
    summary: dict,
    daemon_pid: int,
    im_pid: int,
    before: int,
    after: int,
    toggle_on_val: int,
    burst_cap=None,
    post_max=None,
):
    boot = summary.get("boot")
    require(boot is not None, "Missing BOOT record in initial log")
    require(boot.get("self_pid") == str(daemon_pid), f"BOOT self_pid mismatch: {boot.get('self_pid')} != {daemon_pid}")
    require(boot.get("im_pid") == str(im_pid), f"BOOT im_pid mismatch: {boot.get('im_pid')} != {im_pid}")
    require(boot.get("uipc_ok") == "1", f"/dev/uipc init failed: uipc_err={boot.get('uipc_err')}")
    require(boot.get("bk_sz") == "1", f"BackupID datasize != 1: bk_sz={boot.get('bk_sz')} bk_rc={boot.get('bk_rc')}")
    require(boot.get("bk_on") == str(toggle_on_val), f"Toggle polarity mismatch: {boot.get('bk_on')} != {toggle_on_val}")
    require(boot.get("in_ok") == "1", "InfraInput watch init failed (in_ok!=1)")
    require(boot.get("ring_ok") == "1", "ring.elf missing or unreadable at daemon boot (ring_ok!=1)")
    require(boot.get("pre") == str(before) and boot.get("post") == str(after),
            f"Window mismatch: pre={boot.get('pre')} post={boot.get('post')}")
    if burst_cap is not None:
        require(boot.get("bcap") == str(burst_cap), f"burst_cap mismatch: bcap={boot.get('bcap')} != {burst_cap}")
    if post_max is not None:
        require(boot.get("pmax") == str(post_max), f"post_max mismatch: pmax={boot.get('pmax')} != {post_max}")
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


def inspect_jpeg_file(path: Path) -> dict:
    """Read-only strict JPEG SOI/SOF0-2/SOS/EOI structural verification (exact parity with stage6_ring.c)."""
    data = path.read_bytes()
    n = len(data)
    digest = hashlib.sha256(data).hexdigest()
    bad = dict(valid=False, size=n, width=0, height=0, sha256=digest)
    if n < 4 or data[:2] != b"\xff\xd8" or data[-2:] != b"\xff\xd9":
        return bad
    all_sof = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    supported_sof = {0xC0, 0xC1, 0xC2}
    pos = 2
    width = height = 0
    sof_marker = None
    sof_cids = None
    sos_seen = False
    eoi_seen = False
    while pos < n:
        if data[pos] != 0xFF:
            return bad
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            return bad
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            eoi_seen = True
            break
        if marker == 0x01:
            continue
        if marker == 0x00 or 0xD0 <= marker <= 0xD8:
            return bad
        if marker in all_sof and marker not in supported_sof:
            return bad
        if pos + 2 > n:
            return bad
        seg_len = struct.unpack_from(">H", data, pos)[0]
        if seg_len < 2 or pos + seg_len > n:
            return bad
        payload = data[pos + 2:pos + seg_len]
        pos += seg_len
        if marker in supported_sof:
            if sof_cids is not None or seg_len < 11:
                return bad
            prec = payload[0]
            height, width = struct.unpack_from(">HH", payload, 1)
            nf = payload[5]
            prec_ok = (prec == 8) if marker == 0xC0 else (prec in (8, 12))
            if not prec_ok or width == 0 or height == 0 or not (1 <= nf <= 4) or seg_len != 8 + 3 * nf:
                return bad
            cids = []
            for k in range(nf):
                cid, hv, tq = payload[6 + 3 * k:9 + 3 * k]
                hi, vi = hv >> 4, hv & 0x0F
                if cid in cids or not (1 <= hi <= 4) or not (1 <= vi <= 4) or tq > 3:
                    return bad
                cids.append(cid)
            sof_cids = cids
            sof_marker = marker
        elif marker == 0xDA:
            if sof_cids is None or seg_len < 8:
                return bad
            ns = payload[0]
            if not (1 <= ns <= len(sof_cids)) or seg_len != 6 + 2 * ns:
                return bad
            max_ht = 1 if sof_marker == 0xC0 else 3
            seen_cs = set()
            for k in range(ns):
                cs, tdta = payload[1 + 2 * k], payload[2 + 2 * k]
                if cs not in sof_cids or cs in seen_cs or (tdta >> 4) > max_ht or (tdta & 0x0F) > max_ht:
                    return bad
                seen_cs.add(cs)
            ss, se, ahal = payload[1 + 2 * ns:4 + 2 * ns]
            ah, al = ahal >> 4, ahal & 0x0F
            if sof_marker in (0xC0, 0xC1):
                if ss != 0 or se != 63 or ahal != 0:
                    return bad
            else:
                if ss == 0:
                    if se != 0:
                        return bad
                else:
                    if ns != 1 or not (1 <= ss <= se <= 63):
                        return bad
                if ah > 13 or al > 13 or (ah != 0 and ah != al + 1):
                    return bad
            sos_seen = True
            # Scan entropy-coded scan segment until next non-stuffed, non-RST marker.
            while pos < n:
                ff = data.find(b"\xff", pos)
                if ff < 0 or ff + 1 >= n:
                    return bad
                nxt = ff + 1
                while nxt < n and data[nxt] == 0xFF:
                    nxt += 1
                if nxt >= n:
                    return bad
                b = data[nxt]
                if b == 0x00 or (0xD0 <= b <= 0xD7):
                    pos = nxt + 1
                    continue
                pos = ff
                break
    valid = bool(eoi_seen and pos == n and sof_cids is not None and sos_seen and width > 0 and height > 0)
    return dict(valid=valid, size=n, width=width if valid else 0, height=height if valid else 0, sha256=digest)


def verify_card_saved_files(card_root: Path, ring_files: list, *, expect_nonempty: bool = False) -> dict:
    """Optional read-only verification of PC*.JPG files reported by daemon.log."""
    require(card_root.is_dir(), f"Card mount directory not found: {card_root}")
    results = []
    empty_file_list = len(ring_files) == 0
    all_ok = not (expect_nonempty and empty_file_list)
    for entry in ring_files:
        name = entry.get("file", "")
        expected_bytes = int(entry["bytes"]) if entry.get("bytes", "").isdigit() else -1
        status = entry.get("status", "")
        if not re.fullmatch(r"PC[0-9A-F]{6}\.JPG", name):
            results.append(dict(file=name, ok=False, reason="invalid_name"))
            all_ok = False
            continue
        fpath = card_root / name
        if not fpath.is_file():
            results.append(dict(file=name, ok=False, reason="missing_on_card", expected_bytes=expected_bytes))
            all_ok = False
            continue
        info = inspect_jpeg_file(fpath)
        ok = (
            status == "13" and
            info["valid"] and
            info["size"] == expected_bytes and
            info["width"] == 5472 and
            info["height"] == 3648
        )
        if not ok:
            all_ok = False
        results.append(dict(file=name, ok=ok, expected_bytes=expected_bytes, status=status, **info))
    return dict(
        card_root=str(card_root),
        checked=len(results),
        empty_file_list=empty_file_list,
        all_ok=all_ok,
        files=results,
    )


def do_start(
    camera,
    receipt,
    daemon_image: bytes,
    ring_image: bytes,
    *,
    before: int,
    after: int,
    toggle_on_val: int,
    burst_cap=None,
    post_max=None,
    active_path: Path = ACTIVE_STATE,
    log_out_dir: Path = OUT_DIR,
):
    require(not active_path.exists(), f"Active Stage 6 WIP v2 session already exists at {active_path}; run --collect first.")
    require(receipt.get("model") == "DSC-RX100M7", f"Unsupported model: {receipt.get('model')!r}")
    session = Stage6Session(camera, receipt)
    directory = "/tmp_network/.m7-s6-" + receipt["nonce"]
    remote_daemon = directory + "/daemon.elf"
    remote_ring = directory + "/ring.elf"
    remote_pid = directory + "/daemon.pid"
    remote_log = directory + "/daemon.log"
    enable_attempted = False
    dir_created = False
    custody_created = False
    launched = False
    stopped_after_fail = False
    failed_start_log_safe = False
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
        applets, applet_src = detect_busybox_applets(session)
        receipt["busybox_applets_source"] = applet_src
        receipt["busybox_has_gunzip"] = "gunzip" in applets

        pending_upload = dict(
            status="pending_upload",
            nonce=receipt["nonce"],
            directory=directory,
            daemon_pid=None,
            daemon_starttime=None,
            daemon_exe=remote_daemon,
            ring_exe=remote_ring,
            daemon_sha256=receipt["daemon_sha256"],
            ring_sha256=receipt["ring_sha256"],
            before=before,
            after=after,
            toggle_on_val=toggle_on_val,
            utc=receipt["utc"],
        )
        write_active_state_exclusive(pending_upload, active_path)
        custody_created = True

        session.command(f"/bin/busybox mkdir {directory}")
        dir_created = True
        session.command(f"/bin/busybox chmod 700 {directory}")
        verify_nonsymlink_dir(session, directory)

        upload_elf(session, ring_image, remote_ring, applets, "ring")
        session.command(f"/bin/busybox chmod 500 {remote_ring}")

        upload_elf(session, daemon_image, remote_daemon, applets, "daemon")
        session.command(f"/bin/busybox chmod 500 {remote_daemon}")

        pending_launch = dict(pending_upload, status="pending_launch")
        replace_active_state_atomic(pending_launch, active_path)

        launched = True
        out, rc = session.command(remote_daemon, allowed=tuple(range(256)), timeout=10)
        receipt["launch_output"] = out.decode("utf8", "replace")
        receipt["launch_rc"] = rc
        require(rc == 0, f"daemon.elf launcher exited with {rc}")

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
        summary = parse_daemon_log(initial_log)
        receipt["initial_summary"] = summary

        require(bool(pid_txt), f"Daemon did not publish daemon.pid; log={initial_log.strip()!r}")
        daemon_pid = validate_pid(pid_txt)
        ident = verify_live_daemon_identity(session, daemon_pid, remote_daemon)
        receipt["daemon_identity_at_start"] = ident
        require(ident["matches"], f"Live PID {daemon_pid} does not match {remote_daemon}")
        daemon_starttime = ident["stat"]["starttime"]
        require(ident["status"].get("PPid") == "1", f"Daemon not reparented to PID 1: PPid={ident['status'].get('PPid')!r}")
        require(ident["status"].get("TracerPid") == "0", f"Unexpected TracerPid={ident['status'].get('TracerPid')!r}")

        verify_usable_initial_witnesses(
            summary, daemon_pid, preflight["pid"], before, after, toggle_on_val,
            burst_cap=burst_cap, post_max=post_max,
        )

        running_record = dict(
            pending_upload,
            status="running",
            daemon_pid=daemon_pid,
            daemon_starttime=daemon_starttime,
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
        if launched and dir_created and not camera.dev.poisoned:
            try:
                stopped_after_fail, live_d, live_r = request_stop_via_file(
                    session, directory, remote_daemon, remote_ring,
                    expected_pid=daemon_pid,
                    expected_starttime=daemon_starttime,
                )
                receipt["failed_start_stopped"] = stopped_after_fail
                receipt["failed_start_live_daemon_pids"] = live_d
                receipt["failed_start_live_ring_pids"] = live_r
                # Durably persist final daemon.log BEFORE failed-start cleanup deletes the RAM directory;
                # if a log exists and reading or local fsync fails, preserve RAM dir + custody for --collect!
                if stopped_after_fail:
                    log_state = inspect_log_file_state(session, remote_log)
                    receipt["failed_start_log_state"] = log_state
                    if log_state == "LOG_ABSENT":
                        failed_start_log_safe = True
                    elif log_state == "LOG_OK":
                        final_raw, final_rc = session.command(
                            f"/bin/busybox cat {remote_log}",
                            allowed=(0, 1),
                            timeout=20,
                        )
                        receipt["failed_start_log_read_rc"] = final_rc
                        if final_rc == 0:
                            final_log = final_raw.decode("utf8", "replace")
                            if final_log and not final_log.endswith("\n"):
                                final_log += "\n"
                            receipt["failed_start_final_log"] = final_log
                            # Durably persist even a present 0-byte log (file + dir fsync) to preserve distinction from LOG_ABSENT.
                            saved = persist_collected_log_atomic(final_log, log_out_dir, receipt["utc"], receipt["nonce"])
                            receipt["saved_log_path"] = str(saved)
                            receipt["log_persisted"] = True
                            if not final_log:
                                receipt["failed_start_empty_log"] = True
                            failed_start_log_safe = True
                        else:
                            receipt["failed_start_cleanup"] = "DEFERRED_LOG_READ_FAILED"
                    else:
                        receipt["failed_start_cleanup"] = "DEFERRED_LOG_BAD_STATE"
            except Exception as err:
                receipt["failed_start_stop_error"] = str(err)
                failed_start_log_safe = False
        raise
    finally:
        if not receipt.get("start_ready"):
            if not dir_created and custody_created and not camera.dev.poisoned and active_path.exists():
                active_path.unlink()
                receipt["failed_start_custody_cleared"] = True
            elif dir_created and (not launched or (stopped_after_fail and failed_start_log_safe)) and not camera.dev.poisoned:
                try:
                    session.command(f"/bin/busybox rm -rf {directory}", allowed=(0, 1))
                    chk, _ = session.command(
                        f'if [ -e {directory} ] || [ -L {directory} ]; then echo PRESENT; else echo GONE; fi',
                        allowed=(0, 1),
                    )
                    if chk.decode("ascii", "replace").strip() == "GONE":
                        receipt["failed_start_cleanup"] = True
                        if custody_created and active_path.exists():
                            active_path.unlink()
                            receipt["failed_start_custody_cleared"] = True
                except Exception as err:
                    receipt["failed_start_cleanup_error"] = str(err)
            elif dir_created and launched and stopped_after_fail and not failed_start_log_safe:
                receipt.setdefault("failed_start_cleanup", "DEFERRED_LOG_CUSTODY_PRESERVED")
        if enable_attempted:
            try:
                with usb.deadline(8):
                    camera.setTerminalEnable(False)
                receipt["terminal_disable_requested"] = True
            except Exception as err:
                receipt["terminal_disable_error"] = str(err)


def do_collect(camera, receipt, active_path: Path = ACTIVE_STATE, log_out_dir: Path = OUT_DIR, card_root=None):
    require(receipt.get("model") == "DSC-RX100M7", f"Unsupported model: {receipt.get('model')!r}")
    active = load_active_state(active_path)
    directory = active["directory"]
    remote_daemon = active["daemon_exe"]
    remote_ring = active["ring_exe"]
    remote_pid = directory + "/daemon.pid"
    remote_log = directory + "/daemon.log"
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
            live_d, live_r = find_all_live_s6_pids(session, remote_daemon, remote_ring)
            receipt["live_daemon_pids_at_collect"] = live_d
            receipt["live_ring_pids_at_collect"] = live_r
            if live_d or live_r:
                receipt["alive_at_collect"] = True
                receipt["stopped_cleanly"] = False
                receipt["cleanup"] = "DEFERRED_PROCESS_STILL_ALIVE"
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

        live_d, live_r = find_all_live_s6_pids(session, remote_daemon, remote_ring)
        receipt["live_daemon_pids_at_collect"] = live_d
        receipt["live_ring_pids_at_collect"] = live_r

        pid_raw, pid_rc = session.command(
            f"if [ -f {remote_pid} ] && [ ! -L {remote_pid} ]; then /bin/busybox cat {remote_pid}; fi",
            allowed=(0, 1),
        )
        pid_txt = pid_raw.decode("ascii", "replace").strip() if pid_rc == 0 else ""
        receipt["pid_file_value"] = pid_txt

        alive = False
        if expected_pid is not None:
            ident = verify_live_daemon_identity(session, expected_pid, remote_daemon, expected_starttime)
            receipt["daemon_identity_at_collect"] = ident
            alive = bool(ident["matches"])
            if not alive and ident["status"]:
                receipt["pid_reused_detected"] = True
        elif pid_txt:
            try:
                cand_pid = validate_pid(pid_txt)
            except usb.ProbeError:
                receipt["pid_file_invalid"] = True
                cand_pid = None
            if cand_pid is not None:
                ident = verify_live_daemon_identity(session, cand_pid, remote_daemon, None)
                receipt["daemon_identity_at_collect"] = ident
                alive = bool(ident["matches"])
                if alive:
                    expected_pid = cand_pid
                    expected_starttime = ident["stat"]["starttime"]
        receipt["alive_at_collect"] = bool(alive or live_d or live_r)

        if alive or live_d or live_r or active["status"] == "pending_launch":
            stopped, rem_d, rem_r = request_stop_via_file(
                session, directory, remote_daemon, remote_ring,
                expected_pid=expected_pid,
                expected_starttime=expected_starttime,
            )
            receipt["stopped_cleanly"] = stopped
            receipt["live_daemon_pids_after_stop"] = rem_d
            receipt["live_ring_pids_after_stop"] = rem_r
        else:
            receipt["stopped_cleanly"] = True
            receipt["live_daemon_pids_after_stop"] = []
            receipt["live_ring_pids_after_stop"] = []

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
        summary = parse_daemon_log(log_text)
        receipt["summary"] = summary
        stop_rec = summary.get("stop") or {}
        receipt["diagnostics"] = dict(
            daemon_clean_stop=(
                bool(stop_rec) and
                stop_rec.get("reason") in ("stop_file", "timeout", "signal") and
                stop_rec.get("r_reap") == "1"
            ),
            ring_fault_seen=(stop_rec.get("r_flt") == "1" or any(e.get("fault") == "1" for e in summary.get("ring_exits", []))),
            ring_unresolved_seen=(summary.get("ring_unresolved_count", 0) > 0 or stop_rec.get("r_unres") == "1"),
            log_truncated=(stop_rec.get("trunc") == "1"),
            unmatched_ring_cycles=(summary.get("ring_start_count", 0) != summary.get("ring_exit_count", 0)),
            ring_start_count=summary.get("ring_start_count", 0),
            ring_exit_count=summary.get("ring_exit_count", 0),
            ring_file_count=summary.get("ring_file_count", 0),
        )

        is_prelaunch = active["status"] in ("pending_upload", "pending_launch")
        has_valid_log = log_read_ok and bool(log_text.strip()) and summary.get("boot") is not None
        can_cleanup_prelaunch = is_prelaunch and (log_state == "LOG_ABSENT" or (log_read_ok and bool(log_text.strip())))
        receipt["log_retrieved"] = has_valid_log

        if not receipt.get("stopped_cleanly"):
            # Even if a process remained alive, persist any retrieved log durably for postmortem.
            if log_read_ok and log_text:
                saved_log = persist_collected_log_atomic(log_text, log_out_dir, receipt["utc"], receipt["nonce"])
                receipt["saved_log_path"] = str(saved_log)
                receipt["log_persisted"] = True
            receipt["cleanup"] = "DEFERRED_PROCESS_STILL_ALIVE"
            receipt["collect_outcome"] = "incomplete"
            return

        if not has_valid_log and not can_cleanup_prelaunch:
            receipt["cleanup"] = "DEFERRED_LOG_READ_FAILED"
            receipt["collect_outcome"] = "incomplete"
            return

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

        if card_root is not None and has_valid_log:
            receipt["card_check"] = verify_card_saved_files(Path(card_root), summary.get("ring_files", []))
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
        card_ok = True
        if "card_check" in receipt:
            card_ok = bool(receipt["card_check"].get("all_ok"))
        return (
            receipt.get("cleanup") == "GONE" and
            bool(receipt.get("log_retrieved")) and
            bool(receipt.get("log_persisted")) and
            card_ok
        )
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description="Stage 6 WIP v2 autonomous untethered RAM Pre-Capture daemon.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--start", action="store_true", help="Upload & start autonomous daemon+ring in camera RAM")
    group.add_argument("--collect", action="store_true", help="Stop daemon+ring cleanly, persist log, remove RAM dir")
    group.add_argument("--check-card-only", action="store_true", help="Verify PC*.JPG against a saved daemon.log without USB")
    parser.add_argument("--duration-sec", type=int, default=600, help="Auto-exit watchdog timeout in seconds (default 600)")
    parser.add_argument("--before", type=int, default=5, help="Pre-capture frames N (1..15, default 5)")
    parser.add_argument("--after", type=int, default=0, help="Post-capture frames M (0=hold-driven unlimited up to --post-max, or 1..64; default 0)")
    parser.add_argument("--burst-cap", type=int, default=24, help="Phase-1 continuous S2 burst cap C_burst (8..60, default 24)")
    parser.add_argument("--post-max", type=int, default=48, help="Safety ceiling for hold-driven post frames (1..96, default 48)")
    parser.add_argument("--backlog-cap", type=int, default=96, help="Hard upstream backlog safety ceiling (24..128, default 96)")
    parser.add_argument("--debounce-ms", type=int, default=100, help="Half-press debounce in ms (0..2000, default 100)")
    parser.add_argument("--focus-ms", type=int, default=300, help="AF observe wait in ms (100..1500, default 300)")
    parser.add_argument("--toggle-bkid", default="0x01071472", help="BackupID for menu toggle (default Release w/o Card)")
    parser.add_argument("--toggle-on", type=int, default=0, choices=(0, 1), help="Backup byte meaning ON (default 0=Enable)")
    parser.add_argument("--card", default=None, help="Optional read-only SD card mount path to verify PC*.JPG on --collect")
    parser.add_argument("--log", default=None, help="Saved daemon.log path for --check-card-only")
    parser.add_argument("--allow-empty", action="store_true", help="Allow zero RING_FILE entries in --check-card-only")
    args = parser.parse_args(argv)

    if args.check_card_only:
        require(args.card and args.log, "--check-card-only requires --card and --log")
        summary = parse_daemon_log(Path(args.log).read_text(encoding="utf-8"))
        res = verify_card_saved_files(
            Path(args.card),
            summary.get("ring_files", []),
            expect_nonempty=not args.allow_empty,
        )
        print(json.dumps(res, indent=2))
        return 0 if res["all_ok"] else 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    nonce = secrets.token_hex(6)
    action = "start" if args.start else "collect"
    out_path = OUT_DIR / f"{utc}-{nonce}-{action}.json"

    receipt = dict(
        utc=utc,
        nonce=nonce,
        action=action,
        probe_kind="stage6-v2-autonomous-precapture",
        commands=[],
        steps=[],
    )

    try:
        daemon_tmpl, ring_tmpl, manifest = builder.verify_seal()
        receipt["daemon_template_sha256"] = manifest["daemon"]["sha256"]
        receipt["ring_template_sha256"] = manifest["ring"]["sha256"]

        configured_daemon = None
        configured_ring = None
        if args.start:
            require(30 <= args.duration_sec <= 3600, "--duration-sec must be 30..3600")
            bkid = int(args.toggle_bkid, 0)
            configured_daemon = builder.configure_daemon(
                daemon_tmpl,
                manifest,
                duration_ms=args.duration_sec * 1000,
                poll_ms=50,
                heartbeat_ms=2000,
                max_log_bytes=131072,
                daemonize=True,
                toggle_bkid=bkid,
                toggle_on_val=args.toggle_on,
                before=args.before,
                after=args.after,
                backlog_cap=args.backlog_cap,
                debounce_ms=args.debounce_ms,
                focus_ms=args.focus_ms,
                burst_cap=args.burst_cap,
                post_max=args.post_max,
                nonce=nonce,
            )
            configured_ring = builder.configure_ring(ring_tmpl, manifest, nonce=nonce)
            receipt["daemon_sha256"] = builder.sha(configured_daemon)
            receipt["ring_sha256"] = builder.sha(configured_ring)
            receipt["duration_ms"] = args.duration_sec * 1000
            receipt["toggle_bkid"] = hex(bkid)
            receipt["toggle_on_val"] = args.toggle_on
            receipt["before"] = args.before
            receipt["after"] = args.after
            receipt["burst_cap"] = args.burst_cap
            receipt["post_max"] = args.post_max
            receipt["backlog_cap"] = args.backlog_cap
        else:
            load_active_state(ACTIVE_STATE)
            if args.card is not None:
                require(Path(args.card).is_dir(), f"Card mount directory not found: {args.card}")

        usb.connect(
            receipt,
            diagnostic=(
                (lambda cam, rec: do_start(
                    cam, rec, configured_daemon, configured_ring,
                    before=args.before, after=args.after, toggle_on_val=args.toggle_on,
                    burst_cap=args.burst_cap, post_max=args.post_max,
                    active_path=ACTIVE_STATE, log_out_dir=OUT_DIR,
                ))
                if args.start
                else (lambda cam, rec: do_collect(
                    cam, rec, active_path=ACTIVE_STATE, log_out_dir=OUT_DIR, card_root=args.card,
                ))
            ),
            gate_factory=Stage6Gate,
        )
    except (Exception, KeyboardInterrupt) as err:
        receipt["error"] = f"{type(err).__name__}: {err}"
        print(f"ERROR={receipt['error']}", file=sys.stderr, flush=True)

    receipt["teardown_requested_clean"] = teardown_clean(receipt)
    ok = evaluate_cli_success(action, receipt)
    receipt["cli_ok"] = ok
    try:
        write_text_atomic(out_path, json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
        print(f"RESULT={out_path}", flush=True)
    except OSError as err:
        ok = False
        print(f"RECEIPT_WRITE_ERROR: {err}", file=sys.stderr, flush=True)
        if receipt.get("saved_log_path"):
            print(f"SAVED_LOG_PRESERVED={receipt['saved_log_path']}", flush=True)

    if args.collect:
        s = receipt.get("summary", {})
        d = receipt.get("diagnostics", {})
        print(
            f"COLLECT_SUMMARY: ok={ok} outcome={receipt.get('collect_outcome')} "
            f"stopped_cleanly={receipt.get('stopped_cleanly')} cleanup={receipt.get('cleanup')} "
            f"saved_log={receipt.get('saved_log_path')} "
            f"r_runs={d.get('ring_start_count')} r_exits={d.get('ring_exit_count')} "
            f"r_files={d.get('ring_file_count')} fault={d.get('ring_fault_seen')} "
            f"unres={d.get('ring_unresolved_seen')} trunc={d.get('log_truncated')} "
            f"states={s.get('state_count')}",
            flush=True,
        )

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
