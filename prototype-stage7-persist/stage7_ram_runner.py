"""Host launcher/collector for Stage 7.2 volatile RAM-only live camera test (DSC-RX100M7 1.00).

Zero persistent flash writes: stages all Stage 7.1 sealed artifacts exclusively under
/tmp_network (volatile 1 MiB tmpfs), verifies both /usr/lib/libObj.so and
/usr/lib/viewUnified2.so pins on-camera before modifying RAM, installs mlv2 via
mlv2_guard.elf, launches stage7_daemon.elf, and supports crash-resumable collection,
durable byte-faithful log/settings persistence, runtime-stop qualification across
retries, sd-disabled teardown, per-call pinned mlv2_guard.elf execution (uninstall
only when core.bin has written sd-stopped; never fabricated by host), and strict
process-replacement / verified-absence recovery.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
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
import build_stage7 as builder

OUT_DIR = ROOT / "work/stage7-persist/ram-runs"
ACTIVE_STATE = OUT_DIR / ".active-stage7-ram.json"

CAMERA_VIEW_LIBRARY = "/usr/lib/viewUnified2.so"
VIEWUNIFIED2_BYTES = 11773672
VIEWUNIFIED2_MD5 = "5d8afdc78a48b686ebf25abf268c3a2e"

REMOTE_MLV2_DIR = "/tmp_network/mlv2"
REMOTE_MODS_DIR = "/tmp_network/mods"
REMOTE_CORE = REMOTE_MLV2_DIR + "/core.bin"
REMOTE_REQ = REMOTE_MLV2_DIR + "/mlv2.req"
REMOTE_GUARD = REMOTE_MLV2_DIR + "/mlv2_guard.elf"
REMOTE_PRECAP_MOD = REMOTE_MODS_DIR + "/PreCapture.mod"
REMOTE_PRECAP_CFG = REMOTE_MLV2_DIR + "/precap.cfg"
REMOTE_SD_DISABLED = REMOTE_MLV2_DIR + "/sd-disabled"
REMOTE_SD_STOPPED = REMOTE_MLV2_DIR + "/sd-stopped"
REMOTE_MOD_LOG = REMOTE_MODS_DIR + "/mod_loader.log"

REMOTE_DAEMON_DIR_RE = re.compile(r"^/tmp_network/\.m7-s7-[0-9a-f]{12}$")
REMOTE_S7_ELF_RE = re.compile(r"^/tmp_network/\.m7-s7-[0-9a-f]{12}/(daemon|ring)\.elf$")
REMOTE_DAEMON_LOG_RE = re.compile(r"^/tmp_network/\.m7-s7-[0-9a-f]{12}/daemon\.log$")
REMOTE_DAEMON_PID_RE = re.compile(r"^/tmp_network/\.m7-s7-[0-9a-f]{12}/daemon\.pid$")
REMOTE_GUARD_OUT_RE = re.compile(r"^/tmp_network/mlv2/\.g[0-9a-f]{6}$")
REMOTE_UPLOAD_RE = re.compile(
    r"^(/tmp_network/mlv2/(core\.bin|mlv2\.req|mlv2_guard\.elf)"
    r"|/tmp_network/mods/PreCapture\.mod"
    r"|/tmp_network/\.m7-s7-[0-9a-f]{12}/(daemon|ring)\.elf)$"
)

ALLOWED_DIR_PATHS = frozenset({REMOTE_MLV2_DIR, REMOTE_MODS_DIR})
ALLOWED_STATIC_FILES = frozenset({
    REMOTE_CORE,
    REMOTE_REQ,
    REMOTE_GUARD,
    REMOTE_PRECAP_MOD,
    REMOTE_PRECAP_CFG,
    REMOTE_SD_DISABLED,
    REMOTE_SD_STOPPED,
    REMOTE_MOD_LOG,
})
VALID_CUSTODY_STATUSES = frozenset({
    "pending_upload",
    "pending_install",
    "pending_launch",
    "running",
    "daemon_log_persisted",
    "mlv2_disabled_pending_reboot_or_uninstall",
    "mlv2_stock_verified",
})
VALID_PRE_FRAMES = frozenset({1, 2, 3, 5, 8, 10})
SAFE_ASCII_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,_:/+@="
)

_HELD_LOCK_PATHS: set[Path] = set()


def require(cond, msg):
    if not cond:
        raise usb.ProbeError(msg)


@contextlib.contextmanager
def custody_lock(active_path: Path):
    """Serialize --start and --collect operations via exclusive non-blocking flock."""
    resolved = active_path.resolve()
    if resolved in _HELD_LOCK_PATHS:
        yield
        return
    resolved.parent.mkdir(parents=True, exist_ok=True)
    lock_path = resolved.with_name(resolved.name + ".lock")
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as err:
            raise usb.ProbeError(
                f"Another Stage 7.2 runner instance already holds custody lock {lock_path}"
            ) from err
        _HELD_LOCK_PATHS.add(resolved)
        try:
            yield
        finally:
            _HELD_LOCK_PATHS.discard(resolved)
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        os.close(fd)


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


def parse_any_proc_stat(text: str, expected_pid: int):
    """Parse /proc/<pid>/stat for any process name (matching Linux proc(5) last ')')."""
    s = text.strip()
    m = re.match(rf"^{expected_pid} \((.+)\) (.+)$", s)
    if not m:
        return None
    comm = m.group(1)
    fields = m.group(2).split()
    if len(fields) < 20 or not fields[19].isdigit():
        return None
    return dict(comm=comm, state=fields[0], starttime=int(fields[19]))


def parse_proc_status(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def parse_precap_cfg(text: str) -> dict:
    """Parse exact ASCII text of /tmp_network/mlv2/precap.cfg (strict parity with stage7_common.h)."""
    m = re.fullmatch(r"S7PC1 ([01]) (1|2|3|5|8|10)\n", text)
    if not m:
        return dict(valid=False, enabled=False, pre_frames=0, raw=text)
    enabled = m.group(1) == "1"
    frames = int(m.group(2))
    return dict(
        valid=True,
        enabled=enabled,
        pre_frames=frames if enabled else 0,
        configured_frames=frames,
        raw=text,
    )


def load_and_verify_sealed_artifacts(out_dir: Path = builder.OUT) -> tuple[dict[str, bytes], dict]:
    """Verify the Stage 7.1 build seal and load all six live RAM artifacts."""
    manifest = builder.verify_seal(out_dir)
    keys = {
        "core": "core.bin",
        "request": "mlv2.req",
        "guard": "mlv2_guard.elf",
        "precap_mod": "PreCapture.mod",
        "daemon": "stage7_daemon.elf",
        "ring": "stage7_ring.elf",
    }
    artifacts: dict[str, bytes] = {}
    for key, fname in keys.items():
        info = manifest["artifacts"][key]
        data = (out_dir / fname).read_bytes()
        if len(data) != info["bytes"] or builder.sha(data) != info["sha256"]:
            raise ValueError(f"Sealed artifact {fname} changed after verify_seal()")
        artifacts[key] = data
    return artifacts, manifest


def configure_daemon(
    image: bytes,
    manifest: dict,
    *,
    duration_ms: int = 600000,
    poll_ms: int = 50,
    heartbeat_ms: int = 2000,
    max_log_bytes: int = 131072,
    daemonize: bool = True,
    after: int = 0,
    backlog_cap: int = 96,
    debounce_ms: int = 100,
    focus_ms: int = 300,
    burst_cap: int = 24,
    post_max: int = 48,
    nonce: str = "000000000000",
) -> bytes:
    """Patch m7_s7_daemon_config in memory for a bounded Stage 7.2 RAM run."""
    d = manifest["artifacts"]["daemon"]
    if len(image) != d["bytes"] or builder.sha(image) != d["sha256"]:
        raise ValueError("stage7_daemon.elf template hash/size mismatch")
    if not (
        type(duration_ms) is int and 30000 <= duration_ms <= 3600000 and
        type(poll_ms) is int and 10 <= poll_ms <= 1000 and
        type(heartbeat_ms) is int and 100 <= heartbeat_ms <= 60000 and
        type(max_log_bytes) is int and 2048 <= max_log_bytes <= 262144 and
        type(daemonize) is bool and
        type(after) is int and 0 <= after <= 64 and
        type(burst_cap) is int and 14 <= burst_cap <= 60 and
        type(backlog_cap) is int and 24 <= backlog_cap <= 128 and backlog_cap >= burst_cap + 16 and
        type(post_max) is int and 1 <= post_max <= 96 and 10 + post_max <= 112 and
        type(debounce_ms) is int and 0 <= debounce_ms <= 2000 and
        type(focus_ms) is int and 100 <= focus_ms <= 1500 and
        type(nonce) is str and bool(re.fullmatch(r"[0-9a-f]{12}", nonce))
    ):
        raise ValueError("Invalid stage7_daemon RAM configuration")
    off = d["config_offset"]
    if d["config_bytes"] != builder.DAEMON_CONFIG_BYTES or d["config_version"] != builder.DAEMON_VERSION:
        raise ValueError("stage7_daemon manifest config metadata mismatch")
    if struct.unpack_from("<2I", image, off) != (builder.DAEMON_MAGIC, builder.DAEMON_VERSION):
        raise ValueError("stage7_daemon config header mismatch")
    if image[off + 52:off + 64] != b"0" * 12:
        raise ValueError("stage7_daemon template nonce placeholder mismatch")
    result = bytearray(image)
    struct.pack_into(
        "<13I12s", result, off,
        builder.DAEMON_MAGIC, builder.DAEMON_VERSION,
        duration_ms, poll_ms, heartbeat_ms, max_log_bytes,
        int(daemonize), after, backlog_cap, debounce_ms, focus_ms,
        burst_cap, post_max,
        nonce.encode("ascii"),
    )
    checked = bytearray(result)
    checked[off:off + builder.DAEMON_CONFIG_BYTES] = image[off:off + builder.DAEMON_CONFIG_BYTES]
    if bytes(checked) != image:
        raise ValueError("stage7_daemon config patch escaped config bounds")
    return bytes(result)


def configure_ring(image: bytes, manifest: dict, *, nonce: str) -> bytes:
    """Patch m7_s7_ring_boot.nonce in memory for a Stage 7.2 RAM run."""
    r = manifest["artifacts"]["ring"]
    if len(image) != r["bytes"] or builder.sha(image) != r["sha256"]:
        raise ValueError("stage7_ring.elf template hash/size mismatch")
    if not (type(nonce) is str and bool(re.fullmatch(r"[0-9a-f]{12}", nonce))):
        raise ValueError("Invalid stage7_ring nonce")
    boot_off = r["boot_offset"]
    nonce_off = r["nonce_offset"]
    if nonce_off != boot_off + 16 or r["boot_bytes"] != builder.RING_BOOT_BYTES:
        raise ValueError("stage7_ring manifest boot metadata mismatch")
    if struct.unpack_from("<4I", image, boot_off) != (
        builder.RING_BOOT_MAGIC, builder.RING_BOOT_VERSION, r["rw_vaddr"], r["rw_memsz"]
    ):
        raise ValueError("stage7_ring boot header mismatch")
    if image[nonce_off:nonce_off + 12] != b"0" * 12:
        raise ValueError("stage7_ring template nonce placeholder mismatch")
    result = bytearray(image)
    result[nonce_off:nonce_off + 12] = nonce.encode("ascii")
    checked = bytearray(result)
    checked[nonce_off:nonce_off + 12] = image[nonce_off:nonce_off + 12]
    if bytes(checked) != image:
        raise ValueError("stage7_ring nonce patch escaped boot bounds")
    return bytes(result)


class Stage7Gate:
    """Allow only audited terminal selection packets and exact framed commands (no FileControl/HASP)."""

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


class Stage7Session:
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
                    require(
                        not lines[ends[0] + 1:] and not normalizer.soft_parts and
                        terminal.SHELL_PROMPT.startswith(pending),
                        "Unexpected trailing bytes after ACK",
                    )
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


def verify_view_library_preflight(session) -> dict:
    """Pin /usr/lib/viewUnified2.so (non-symlink regular file, exact byte size and MD5)."""
    ls_raw, _ = session.command("ls -ld " + CAMERA_VIEW_LIBRARY)
    ls_lines = [line for line in ls_raw.decode("utf8", "replace").splitlines() if line.strip()]
    require(len(ls_lines) == 1, f"Unexpected ls -ld output for {CAMERA_VIEW_LIBRARY}: {ls_lines!r}")
    fields = ls_lines[0].split()
    require(
        len(fields) >= 9 and fields[-1] == CAMERA_VIEW_LIBRARY and
        bool(re.fullmatch(r"-[rwxstST-]{9}", fields[0])),
        f"Expected regular non-symlink {CAMERA_VIEW_LIBRARY}: {ls_lines[0]!r}",
    )
    size_raw, _ = session.command("/bin/busybox wc -c " + CAMERA_VIEW_LIBRARY)
    size_m = re.fullmatch(
        r"\s*([1-9][0-9]*)\s+" + re.escape(CAMERA_VIEW_LIBRARY) + r"\s*",
        size_raw.decode("utf8", "replace"),
    )
    require(
        bool(size_m) and int(size_m.group(1)) == VIEWUNIFIED2_BYTES,
        f"On-camera {CAMERA_VIEW_LIBRARY} size mismatch: {size_raw!r}",
    )
    md5_raw, _ = session.command("/bin/busybox md5sum " + CAMERA_VIEW_LIBRARY, timeout=20)
    md5_m = re.fullmatch(
        r"([0-9a-f]{32})\s+\*?" + re.escape(CAMERA_VIEW_LIBRARY) + r"\s*",
        md5_raw.decode("utf8", "replace").strip(),
    )
    require(
        bool(md5_m) and md5_m.group(1) == VIEWUNIFIED2_MD5,
        f"On-camera {CAMERA_VIEW_LIBRARY} MD5 mismatch: {md5_raw!r}",
    )
    return dict(
        path=CAMERA_VIEW_LIBRARY,
        bytes=VIEWUNIFIED2_BYTES,
        md5=VIEWUNIFIED2_MD5,
        non_symlink=True,
    )


def inspect_im_identity(session, im_pid: int) -> dict:
    """Inspect /proc/<im_pid> preserving observed fields even if traced or stopped."""
    exe_raw, exe_rc = session.command(f"/bin/busybox readlink /proc/{im_pid}/exe 2>/dev/null", allowed=(0, 1))
    exe = exe_raw.decode("utf8", "replace").strip() if exe_rc == 0 else ""
    stat_raw, stat_rc = session.command(f"/bin/busybox cat /proc/{im_pid}/stat 2>/dev/null", allowed=(0, 1))
    stat_txt = stat_raw.decode("utf8", "replace") if stat_rc == 0 else ""
    status_raw, status_rc = session.command(f"/bin/busybox cat /proc/{im_pid}/status 2>/dev/null", allowed=(0, 1))
    status_txt = status_raw.decode("utf8", "replace") if status_rc == 0 else ""

    parsed_stat = parse_proc_stat(stat_txt, im_pid, "im.elf") if stat_rc == 0 else None
    parsed_status = parse_proc_status(status_txt) if status_rc == 0 else {}
    exe_ok = (exe_rc == 0 and exe == "/usr/bin/im.elf")
    stat_ok = parsed_stat is not None
    status_ok = (
        status_rc == 0 and
        parsed_status.get("Name") == "im.elf" and
        parsed_status.get("Pid") == str(im_pid) and
        parsed_status.get("Tgid") == str(im_pid)
    )
    untraced = (parsed_status.get("TracerPid") == "0")
    runnable = bool(parsed_stat is not None and parsed_stat["state"] in ("R", "S", "D"))
    matches = exe_ok and stat_ok and status_ok and untraced and runnable
    return dict(
        matches=matches,
        exe_ok=exe_ok,
        stat_ok=stat_ok,
        status_ok=status_ok,
        untraced=untraced,
        runnable=runnable,
        pid=im_pid,
        exe=exe,
        stat=parsed_stat,
        status=parsed_status,
        starttime=parsed_stat["starttime"] if parsed_stat is not None else None,
    )


def observe_live_im(
    session,
    pidof_body: str,
    pidof_rc: int,
    *,
    expected_prev_pid: int | None = None,
    expected_prev_starttime: int | None = None,
) -> dict:
    """Discover /usr/bin/im.elf via /proc/*/exe (parity with mlv2_guard) and cross-check pidof.

    Returns state in {"verified_live", "verified_absent", "uncertain"}. Any unreadable userspace
    executable link, ambiguous/broken /proc scan, traced/stopped im.elf, or unverified surviving
    expected_prev_pid is reported as "uncertain" so callers fail closed.
    """
    pidof_pids: list[int] = []
    pidof_malformed = False
    if pidof_rc == 0:
        toks = pidof_body.split()
        if not toks:
            pidof_malformed = True
        else:
            for tok in toks:
                if re.fullmatch(r"[1-9][0-9]{0,9}", tok):
                    val = int(tok)
                    if 1 < val < 0x80000000:
                        pidof_pids.append(val)
                    else:
                        pidof_malformed = True
                else:
                    pidof_malformed = True
            pidof_pids = sorted(set(pidof_pids))
    elif pidof_rc == 1 and not pidof_body.strip():
        pidof_pids = []
    else:
        pidof_malformed = True

    scan_cmd = (
        'n=; for p in /proc/[1-9]*; do [ -e "$p/stat" ] || continue; n=1; '
        'e=$(/bin/busybox readlink "$p/exe" 2>/dev/null); '
        'if [ -n "$e" ]; then case "$e" in "/usr/bin/im.elf"|"/usr/bin/im.elf "*) echo "IM:$p";; esac; '
        'elif ! c=$(/bin/busybox cat "$p/cmdline" 2>/dev/null) || [ -n "$c" ]; then echo "UNREAD:$p"; fi; '
        'done; [ -n "$n" ] && echo PROC_OK'
    )
    scan_raw, scan_rc = session.command(scan_cmd, allowed=(0, 1), timeout=15)
    scan_lines = [line.strip() for line in scan_raw.decode("utf8", "replace").splitlines() if line.strip()]
    proc_ok = ("PROC_OK" in scan_lines) and (scan_rc == 0)
    exe_pids: list[int] = []
    unread_pids: list[int] = []
    scan_malformed = False
    for line in scan_lines:
        if line == "PROC_OK":
            continue
        if line.startswith("IM:/proc/"):
            tok = line[len("IM:/proc/"):]
            if re.fullmatch(r"[1-9][0-9]{0,9}", tok):
                val = int(tok)
                if 1 < val < 0x80000000:
                    exe_pids.append(val)
                    continue
        elif line.startswith("UNREAD:/proc/"):
            tok = line[len("UNREAD:/proc/"):]
            if re.fullmatch(r"[1-9][0-9]{0,9}", tok):
                val = int(tok)
                if 1 < val < 0x80000000:
                    unread_pids.append(val)
                    continue
        scan_malformed = True
    exe_pids = sorted(set(exe_pids))
    unread_pids = sorted(set(unread_pids))

    base = dict(
        proc_ok=proc_ok,
        exe_pids=exe_pids,
        unread_pids=unread_pids,
        pidof_pids=pidof_pids,
        pidof_rc=pidof_rc,
        pidof_malformed=pidof_malformed,
        pid=None,
        starttime=None,
        identity=None,
    )

    if not proc_ok or scan_malformed:
        return dict(base, state="uncertain", reason="proc_scan_unverified")

    if len(exe_pids) > 1:
        return dict(base, state="uncertain", reason="multiple_im_exe_pids")

    if len(exe_pids) == 0:
        if pidof_malformed or pidof_pids:
            return dict(base, state="uncertain", reason="pidof_proc_disagree")
        if unread_pids:
            return dict(base, state="uncertain", reason="unreadable_userspace_exe")
        if expected_prev_pid is not None:
            # Must affirmatively prove expected_prev_pid either disappeared OR is a distinct non-im.elf process!
            exists_raw, _ = session.command(
                f"if [ ! -e /proc/{expected_prev_pid} ]; then echo PID_GONE; else echo PID_EXISTS; fi"
            )
            if exists_raw.decode("ascii", "replace").strip() != "PID_GONE":
                prev_exe_raw, prev_exe_rc = session.command(
                    f"/bin/busybox readlink /proc/{expected_prev_pid}/exe 2>/dev/null",
                    allowed=(0, 1),
                )
                prev_stat_raw, prev_stat_rc = session.command(
                    f"/bin/busybox cat /proc/{expected_prev_pid}/stat 2>/dev/null",
                    allowed=(0, 1),
                )
                prev_exe = prev_exe_raw.decode("utf8", "replace").strip() if prev_exe_rc == 0 else ""
                prev_stat = parse_any_proc_stat(prev_stat_raw.decode("utf8", "replace"), expected_prev_pid) if prev_stat_rc == 0 else None
                proven_different = (
                    prev_exe_rc == 0 and bool(prev_exe) and not prev_exe.startswith("/usr/bin/im.elf") and
                    prev_stat is not None and
                    (
                        prev_stat["comm"] != "im.elf" or
                        (expected_prev_starttime is not None and prev_stat["starttime"] != expected_prev_starttime)
                    )
                )
                if not proven_different:
                    return dict(base, state="uncertain", reason="prev_pid_exists_unverified")
        return dict(base, state="verified_absent", reason="no_im_exe_and_prev_pid_cleared")

    # Exactly one live /usr/bin/im.elf PID discovered via /proc/*/exe.
    pid = exe_pids[0]
    ident = inspect_im_identity(session, pid)
    base["pid"] = pid
    base["starttime"] = ident["starttime"]
    base["identity"] = ident
    if unread_pids and (expected_prev_pid is None or expected_prev_pid in unread_pids or pid != expected_prev_pid):
        return dict(base, state="uncertain", reason="unreadable_other_userspace_exe")
    if pidof_malformed or (pidof_pids and pidof_pids != [pid]):
        return dict(base, state="uncertain", reason="pidof_exe_pid_mismatch")
    if not ident["matches"]:
        reason = "im_traced" if (ident["exe_ok"] and ident["stat_ok"] and not ident["untraced"]) else "im_identity_incomplete"
        return dict(base, state="uncertain", reason=reason)
    return dict(base, state="verified_live", reason="ok")


def run_start_preflight(session, receipt) -> dict:
    commands = identity.preflight_commands()
    bodies = [
        session.command(c, allowed=(0, 1) if i == 4 else (0,), timeout=20 if i == 8 else 12)[0].decode("utf8", "replace")
        for i, c in enumerate(commands)
    ]
    preflight = identity.checked_preflight(bodies, receipt["model"])
    preflight["viewUnified2"] = verify_view_library_preflight(session)
    im_obs = observe_live_im(session, bodies[6], 0)
    preflight["im_observation"] = im_obs
    require(
        im_obs["state"] == "verified_live" and
        im_obs["pid"] == preflight["pid"] and
        im_obs["pidof_pids"] == [preflight["pid"]] and
        im_obs["starttime"] is not None,
        f"Live im.elf identity/tracer verification failed: {im_obs}",
    )
    preflight["im_starttime"] = im_obs["starttime"]
    preflight["im_identity"] = im_obs["identity"]
    receipt["preflight"] = preflight
    return preflight


def run_collect_preflight(
    session,
    receipt,
    *,
    expected_prev_pid: int | None = None,
    expected_prev_starttime: int | None = None,
) -> dict:
    commands = identity.preflight_commands()
    bodies = []
    im_pid_rc = 0
    for i, c in enumerate(commands):
        allowed = (0, 1) if i in (4, 6) else (0,)
        body, rc = session.command(c, allowed=allowed, timeout=20 if i == 8 else 12)
        if i == 6:
            im_pid_rc = rc
        bodies.append(body.decode("utf8", "replace"))
    pidof_body = bodies[6]
    single_pid_ok = (im_pid_rc == 0 and bool(re.fullmatch(r"[1-9][0-9]{0,9}", pidof_body.strip())))
    check_bodies = list(bodies)
    if not single_pid_ok:
        check_bodies[6] = "2"
    preflight = identity.checked_preflight(check_bodies, receipt["model"])
    preflight["viewUnified2"] = verify_view_library_preflight(session)
    im_obs = observe_live_im(
        session, pidof_body, im_pid_rc,
        expected_prev_pid=expected_prev_pid,
        expected_prev_starttime=expected_prev_starttime,
    )
    preflight["im_observation"] = im_obs
    preflight["im_state"] = im_obs["state"]
    preflight["pid"] = im_obs["pid"]
    preflight["im_starttime"] = im_obs["starttime"]
    preflight["im_identity"] = im_obs["identity"]
    preflight["im_present_at_collect"] = (im_obs["state"] != "verified_absent")
    receipt["preflight"] = preflight
    return preflight


def detect_busybox_applets(session):
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


def encode_echo_mixed(chunk: bytes) -> str:
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


def upload_ram_file(session, image: bytes, remote_path: str, applets: set, label: str, mode: str):
    require(REMOTE_UPLOAD_RE.fullmatch(remote_path), f"Disallowed remote upload path: {remote_path!r}")
    require(mode in ("444", "500"), f"Disallowed chmod mode: {mode!r}")
    compressed = gzip.compress(image, mtime=0)
    packed = "gunzip" in applets and len(compressed) < len(image)
    payload = compressed if packed else image
    encoded = "base64" in applets
    dest = remote_path + ".gz" if packed else remote_path

    chunk_list = plan_upload_chunks(payload, dest, encoded, len(session.receipt["commands"]), session.receipt["nonce"])
    chunks = len(chunk_list)
    info = dict(
        label=label,
        remote=remote_path,
        file_bytes=len(image),
        transfer_bytes=len(payload),
        compression="gzip" if packed else "none",
        encoding="base64" if encoded else "mixed-octal",
        chunks=chunks,
        mode=mode,
    )
    session.receipt.setdefault("uploads", []).append(info)
    print(
        f"UPLOAD_PLAN[{label}]: size={len(image)} B, transfer={len(payload)} B "
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
        session.command(f"/bin/busybox gunzip -c {dest} > {remote_path}", timeout=20)
        session.command(f"/bin/busybox rm -f {dest}")
    expected = hashlib.md5(image).hexdigest() + "  " + remote_path
    actual = session.command(f"/bin/busybox md5sum {remote_path}")[0].decode("ascii", "replace").strip()
    require(actual == expected, f"MD5 mismatch after upload of {label}: {actual!r} != {expected!r}")
    session.command(f"/bin/busybox chmod {mode} {remote_path}")


def verify_remote_file_pinned(session, path: str, expected_bytes: int, expected_md5: str) -> dict:
    """Verify an existing remote RAM file is a regular non-symlink matching exact size and MD5."""
    state = inspect_file_state(session, path)
    if state != "FILE_OK":
        return dict(ok=False, state=state, reason="not_regular_file")
    size_raw, size_rc = session.command(f"/bin/busybox wc -c {path}", allowed=(0, 1))
    size_m = re.fullmatch(
        r"\s*([1-9][0-9]*)\s+" + re.escape(path) + r"\s*",
        size_raw.decode("utf8", "replace"),
    ) if size_rc == 0 else None
    actual_bytes = int(size_m.group(1)) if size_m else None
    if actual_bytes != expected_bytes:
        return dict(ok=False, state=state, actual_bytes=actual_bytes, expected_bytes=expected_bytes, reason="size_mismatch")
    md5_raw, md5_rc = session.command(f"/bin/busybox md5sum {path}", allowed=(0, 1))
    md5_m = re.fullmatch(
        r"([0-9a-f]{32})\s+\*?" + re.escape(path) + r"\s*",
        md5_raw.decode("utf8", "replace").strip(),
    ) if md5_rc == 0 else None
    actual_md5 = md5_m.group(1) if md5_m else None
    if actual_md5 != expected_md5:
        return dict(ok=False, state=state, actual_bytes=actual_bytes, actual_md5=actual_md5, expected_md5=expected_md5, reason="md5_mismatch")
    return dict(ok=True, state=state, bytes=actual_bytes, md5=actual_md5)


def parse_guard_output(text: str) -> dict:
    """Strict parser for stdout lines emitted by mlv2_guard.elf with exact record-kind tracking."""
    out = dict(
        fnv_size=None,
        fnv_hex=None,
        target_pid=None,
        view_bias=None,
        freeze_threads=None,
        hooks=None,
        rects=None,
        shim=None,
        installed=False,
        installed_line=None,
        installed_shim_start=None,
        installed_shim_end=None,
        installed_hooks=None,
        already_installed=False,
        uninstalled=False,
        already_stock=False,
        busy_lines=[],
        rollback_lines=[],
        resume_count=None,
        resume_result=None,
        result_code=None,
        changed=None,
        result_detail=None,
        record_kinds=[],
        duplicate_lines=[],
        unknown_lines=[],
    )
    seen_singletons: set[str] = set()

    def mark_singleton(kind: str, line: str) -> bool:
        out["record_kinds"].append(kind)
        if kind in seen_singletons:
            out["duplicate_lines"].append(line)
            return False
        seen_singletons.add(kind)
        return True

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.fullmatch(r"FNV size=([0-9]+) fnv=([0-9a-f]{8})", line)
        if m:
            if mark_singleton("FNV", line):
                out["fnv_size"] = int(m.group(1))
                out["fnv_hex"] = m.group(2)
            continue
        m = re.fullmatch(r"TARGET /proc/([1-9][0-9]*) view_bias=([0-9a-f]{8})", line)
        if m:
            if mark_singleton("TARGET", line):
                out["target_pid"] = int(m.group(1))
                out["view_bias"] = m.group(2)
            continue
        m = re.fullmatch(r"FREEZE threads=([0-9]+)", line)
        if m:
            if mark_singleton("FREEZE", line):
                out["freeze_threads"] = int(m.group(1))
            continue
        m = re.fullmatch(r"STATE hooks=([A-Za-z0-9_]+) rects=([A-Za-z0-9_]+) shim=([A-Za-z0-9_]+)", line)
        if m:
            if mark_singleton("STATE", line):
                out["hooks"], out["rects"], out["shim"] = m.group(1), m.group(2), m.group(3)
            continue
        m = re.fullmatch(
            r"INSTALLED shim=([0-9a-f]{8})\.\.([0-9a-f]{8}) hooks=([0-9a-f]{8}),([0-9a-f]{8}),([0-9a-f]{8})",
            line,
        )
        if m:
            if mark_singleton("INSTALLED", line):
                out["installed"] = True
                out["installed_line"] = line
                out["installed_shim_start"] = int(m.group(1), 16)
                out["installed_shim_end"] = int(m.group(2), 16)
                out["installed_hooks"] = [int(m.group(3), 16), int(m.group(4), 16), int(m.group(5), 16)]
            continue
        if line == "ALREADY_INSTALLED":
            if mark_singleton("ALREADY_INSTALLED", line):
                out["already_installed"] = True
            continue
        if line == "UNINSTALLED restored=stock":
            if mark_singleton("UNINSTALLED", line):
                out["uninstalled"] = True
            continue
        if line == "ALREADY_STOCK":
            if mark_singleton("ALREADY_STOCK", line):
                out["already_stock"] = True
            continue
        if line.startswith("BUSY "):
            out["record_kinds"].append("BUSY")
            out["busy_lines"].append(line)
            continue
        if line.startswith("ROLLBACK "):
            out["record_kinds"].append("ROLLBACK")
            out["rollback_lines"].append(line)
            continue
        m = re.fullmatch(r"RESUME count=([0-9]+) result=(-?[0-9]+)", line)
        if m:
            if mark_singleton("RESUME", line):
                out["resume_count"] = int(m.group(1))
                out["resume_result"] = int(m.group(2))
            continue
        m = re.fullmatch(r"MLV2_RESULT=(-?[0-9]+)(?:\s+(.*))?", line)
        if m:
            if mark_singleton("MLV2_RESULT", line):
                out["result_code"] = int(m.group(1))
                detail = (m.group(2) or "").strip()
                out["result_detail"] = detail
                cm = re.fullmatch(r"changed=([01])", detail)
                if cm:
                    out["changed"] = int(cm.group(1))
            continue
        out["unknown_lines"].append(line)
    return out


def guard_fnv_matches(parsed: dict, rc: int, *, expected_size: int, expected_fnv_hex: str) -> bool:
    return (
        rc == 0 and
        parsed["record_kinds"] == ["FNV"] and
        parsed["fnv_size"] == expected_size and
        parsed["fnv_hex"] == expected_fnv_hex and
        not parsed["duplicate_lines"] and
        not parsed["unknown_lines"]
    )


def guard_check_matches(
    parsed: dict,
    rc: int,
    *,
    expected_pid: int,
    expected_hooks: str,
    expected_rects: str,
    expected_shim: str,
    expected_view_bias: str | None = None,
) -> bool:
    return (
        rc == 0 and
        parsed["record_kinds"] == ["TARGET", "STATE", "MLV2_RESULT"] and
        parsed["target_pid"] == expected_pid and
        parsed["view_bias"] is not None and
        (expected_view_bias is None or parsed["view_bias"] == expected_view_bias) and
        parsed["hooks"] == expected_hooks and
        parsed["rects"] == expected_rects and
        parsed["shim"] == expected_shim and
        parsed["result_code"] == 0 and
        parsed["changed"] == 0 and
        not parsed["duplicate_lines"] and
        not parsed["unknown_lines"]
    )


def guard_install_matches(
    parsed: dict,
    rc: int,
    *,
    expected_pid: int,
    expected_view_bias: str,
    manifest: dict,
) -> bool:
    shim_meta = manifest["artifacts"]["shim"]
    vb = int(expected_view_bias, 16)
    want_start = (shim_meta["addr"] + vb) & 0xFFFFFFFF
    want_end = (want_start + shim_meta["bytes"]) & 0xFFFFFFFF
    want_hooks = [
        (int(shim_meta["entries"][k], 16) + vb) & 0xFFFFFFFF
        for k in ("ml_hook_set_root", "ml_hook_refresh", "ml_hook_open_item")
    ]
    return (
        rc == 0 and
        parsed["record_kinds"] == ["TARGET", "FREEZE", "STATE", "INSTALLED", "RESUME", "MLV2_RESULT"] and
        parsed["target_pid"] == expected_pid and
        parsed["view_bias"] == expected_view_bias and
        parsed["hooks"] == "stock" and
        parsed["rects"] == "stock" and
        parsed["shim"] == "zero" and
        parsed["installed"] and
        parsed["installed_shim_start"] == want_start and
        parsed["installed_shim_end"] == want_end and
        parsed["installed_hooks"] == want_hooks and
        parsed["freeze_threads"] is not None and parsed["freeze_threads"] >= 1 and
        parsed["resume_count"] == parsed["freeze_threads"] and
        parsed["resume_result"] == 0 and
        parsed["result_code"] == 0 and
        parsed["changed"] == 1 and
        not parsed["duplicate_lines"] and
        not parsed["unknown_lines"]
    )


def guard_uninstall_matches(
    parsed: dict,
    rc: int,
    *,
    expected_pid: int,
    expected_view_bias: str,
) -> bool:
    if not (
        rc == 0 and
        parsed["target_pid"] == expected_pid and
        parsed["view_bias"] == expected_view_bias and
        parsed["freeze_threads"] is not None and parsed["freeze_threads"] >= 1 and
        parsed["resume_count"] == parsed["freeze_threads"] and
        parsed["resume_result"] == 0 and
        parsed["result_code"] == 0 and
        not parsed["duplicate_lines"] and
        not parsed["unknown_lines"]
    ):
        return False
    if parsed["record_kinds"] == ["TARGET", "FREEZE", "STATE", "UNINSTALLED", "RESUME", "MLV2_RESULT"]:
        return (
            parsed["uninstalled"] and
            parsed["changed"] == 1 and
            parsed["hooks"] == "v2" and
            parsed["rects"] == "patched" and
            parsed["shim"] == "shim"
        )
    if parsed["record_kinds"] == ["TARGET", "FREEZE", "STATE", "ALREADY_STOCK", "RESUME", "MLV2_RESULT"]:
        return (
            parsed["already_stock"] and
            parsed["changed"] == 0 and
            parsed["hooks"] == "stock" and
            parsed["rects"] == "stock" and
            parsed["shim"] == "zero"
        )
    return False


def run_pinned_guard_command(
    session,
    subcmd: str,
    arg_path: str,
    *,
    guard_bytes: int,
    guard_md5: str,
    arg_bytes: int,
    arg_md5: str,
    timeout: int = 20,
) -> tuple[bool, dict, dict, int | None, str]:
    """Verify both remote mlv2_guard.elf and its input file pins and re-check MD5 inside the exec command."""
    require(subcmd in ("fnv", "check", "install", "uninstall"), f"Disallowed guard subcmd: {subcmd!r}")
    require(arg_path in (REMOTE_CORE, REMOTE_REQ), f"Disallowed guard arg path: {arg_path!r}")
    require(bool(re.fullmatch(r"[0-9a-f]{32}", guard_md5)), f"Invalid guard_md5: {guard_md5!r}")
    require(bool(re.fullmatch(r"[0-9a-f]{32}", arg_md5)), f"Invalid arg_md5: {arg_md5!r}")
    g_pin = verify_remote_file_pinned(session, REMOTE_GUARD, guard_bytes, guard_md5)
    a_pin = verify_remote_file_pinned(session, arg_path, arg_bytes, arg_md5)
    pins = dict(guard=g_pin, arg=a_pin)
    if not (g_pin["ok"] and a_pin["ok"]):
        return False, pins, parse_guard_output(""), None, ""
    # Fresh unique per-invocation output file (/tmp_network/mlv2/.g<6hex>) verified absent before exec
    # and inside the single pre-exec gate ([ ! -e "$o" ]&&[ ! -L "$o" ]) so FIFOs, symlinks, dirs,
    # and stale files can never block redirection or leak old output.
    # Framed length stays <= 496 bytes even at command index 99,999,999 (< 512 B hard limit).
    out_tag = secrets.token_hex(3)
    out_name = f".g{out_tag}"
    out_path = f"{REMOTE_MLV2_DIR}/{out_name}"
    pins["output_path"] = out_path
    pre_out_state = inspect_file_state(session, out_path)
    if pre_out_state != "FILE_ABSENT":
        pins["output_precheck_state"] = pre_out_state
        pins["preexec_pin_failed"] = True
        return False, pins, parse_guard_output(""), None, ""

    arg_name = arg_path.rsplit("/", 1)[1]
    exec_cmd = (
        f'd={REMOTE_MLV2_DIR};g=$d/mlv2_guard.elf;a=$d/{arg_name};o=$d/{out_name};x=/bin/busybox;'
        f'if [ -f "$g" ]&&[ ! -L "$g" ]&&[ -f "$a" ]&&[ ! -L "$a" ]&&[ ! -e "$o" ]&&[ ! -L "$o" ]'
        f'&&[ "$($x md5sum "$g")" = "{guard_md5}  $g" ]'
        f'&&[ "$($x md5sum "$a")" = "{arg_md5}  $a" ];'
        f'then "$g" {subcmd} "$a">"$o";else echo M7_PIN_FAIL;(exit 125);fi'
    )
    console_raw, rc = session.command(
        exec_cmd,
        allowed=tuple(range(256)),
        timeout=timeout,
    )
    console_text = console_raw.decode("utf8", "replace")
    if console_text.strip():
        pins["console_output"] = console_text
    # Distinct subshell exit code 125 (mlv2_guard.c exits 0..18) OR refusal token catches pre-exec failure
    # even when kernel console printk appends directly onto the refusal line.
    if rc == 125 or "M7_PIN_FAIL" in console_text:
        pins["preexec_pin_failed"] = True
        return False, pins, parse_guard_output(""), None, console_text

    # Single-command guarded readback refuses symlinks/FIFOs/missing files at open time (exit 126 via subshell).
    read_cmd = (
        f'if [ -f {out_path} ]&&[ ! -L {out_path} ];'
        f'then /bin/busybox cat {out_path};else echo M7_OUT_BAD;(exit 126);fi'
    )
    out_raw, out_rc = session.command(
        read_cmd,
        allowed=tuple(range(256)),
        timeout=10,
    )
    if out_rc == 126:
        pins["output_file_state"] = "BAD_OR_ABSENT"
        return True, pins, parse_guard_output(""), rc, ""

    # Checked removal of our fresh regular file: failure to remove rejects the guard result (fail-closed).
    _, rm_rc = session.command(f"/bin/busybox rm -f {out_path}", allowed=(0, 1))
    rm_state = inspect_file_state(session, out_path)
    pins["output_cleanup_rc"] = rm_rc
    pins["output_cleanup_state"] = rm_state
    cleanup_ok = (rm_rc == 0 and rm_state == "FILE_ABSENT")
    pins["output_cleanup_ok"] = cleanup_ok
    if out_rc != 0:
        pins["output_read_rc"] = out_rc
        return True, pins, parse_guard_output(""), rc, ""
    if not cleanup_ok:
        return True, pins, parse_guard_output(""), rc, ""
    text = out_raw.decode("utf8", "replace")
    return True, pins, parse_guard_output(text), rc, text


def parse_daemon_log(text: str) -> dict:
    boots = []
    states = []
    heartbeats = []
    ring_starts = []
    ring_events = []
    ring_files = []
    ring_exits = []
    stops = []
    unknown = []
    records = []
    duplicate_keys = []
    for line_no, raw in enumerate(text.splitlines(), 1):
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
                if k in kv:
                    duplicate_keys.append(dict(line_no=line_no, kind=kind, key=k))
                else:
                    kv[k] = v
            else:
                extra.append(token)
        if extra:
            kv["_extra"] = " ".join(extra)
        records.append((kind, kv))
        if kind == "BOOT":
            boots.append(kv)
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

    drives = sorted({s["drive"] for s in states if s.get("cam") == "1" and s.get("drive") is not None})
    formats = sorted(
        {
            (s.get("fmt"), s.get("size"), s.get("asp"), s.get("qual"))
            for s in states if s.get("cam") == "1"
        },
        key=lambda row: tuple("" if v is None else v for v in row),
    )
    pre_frames_seen = sorted({int(s["pre_f"]) for s in states if s.get("pre_f", "").isdigit()})
    toggles_seen = sorted({s["tog"] for s in states if s.get("tog") is not None})
    sub_ens = sorted({s["sub_en"] for s in states if s.get("sub_ok") == "1" and s.get("sub_en") is not None})
    gates = sorted({s["gate"] for s in states if s.get("gate") is not None})
    hb_times = [int(h["t"]) for h in heartbeats if h.get("t", "").isdigit()]
    unresolved = [e for e in ring_events if e.get("ev") == "UNRESOLVED"]
    return dict(
        boot=boots[0] if boots else None,
        boot_count=len(boots),
        state_count=len(states),
        heartbeat_count=len(heartbeats),
        heartbeat_span_ms=(max(hb_times) - min(hb_times)) if len(hb_times) >= 2 else (hb_times[0] if hb_times else 0),
        ring_start_count=len(ring_starts),
        ring_exit_count=len(ring_exits),
        ring_file_count=len(ring_files),
        ring_unresolved_count=len(unresolved),
        stop_count=len(stops),
        stop=stops[-1] if stops else None,
        duplicate_keys=duplicate_keys,
        records=records,
        drives_seen=drives,
        formats_seen=[list(x) for x in formats],
        pre_frames_seen=pre_frames_seen,
        toggles_seen=toggles_seen,
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


def compute_log_diagnostics(summary: dict) -> dict:
    """Strictly qualify daemon BOOT/STOP uniqueness & order, no duplicate keys, and exact chronological ring pairing."""
    boot_count = summary.get("boot_count", 1 if summary.get("boot") is not None else 0)
    stop_count = summary.get("stop_count", 1 if summary.get("stop") is not None else 0)
    stop_rec = summary.get("stop")
    duplicate_keys = summary.get("duplicate_keys", [])
    has_duplicate_keys = bool(duplicate_keys)
    records = summary.get("records")

    boot_ok = (
        boot_count == 1 and
        summary.get("boot") is not None and
        (not records or records[0][0] == "BOOT")
    )
    stop_is_terminal = (
        stop_count == 1 and
        stop_rec is not None and
        (not records or records[-1][0] == "STOP")
    )
    required_stop_keys = ("reason", "r_reap", "r_runs", "r_ok", "r_flt", "r_unres", "trunc")
    stop_fields_complete = (
        stop_count == 1 and
        stop_rec is not None and
        all(k in stop_rec and stop_rec[k] != "" for k in required_stop_keys)
    )
    daemon_clean_stop = (
        stop_fields_complete and
        stop_is_terminal and
        stop_rec["reason"] in ("stop_file", "timeout", "signal") and
        stop_rec["r_reap"] == "1"
    )
    ring_fault_seen = (
        (stop_rec is not None and stop_rec.get("r_flt") != "0") or
        any(
            e.get("fault") != "0" or e.get("rc") != "0" or e.get("sig") != "0"
            for e in summary.get("ring_exits", [])
        )
    )
    ring_unresolved_seen = (
        summary.get("ring_unresolved_count", 0) > 0 or
        (stop_rec is not None and stop_rec.get("r_unres") != "0") or
        any(e.get("unres") != "0" for e in summary.get("ring_exits", []))
    )
    log_truncated = (stop_rec is not None and stop_rec.get("trunc") != "0")

    starts = summary.get("ring_starts", [])
    exits = summary.get("ring_exits", [])
    start_pairs = []
    exit_pairs = []
    valid_ids = True
    for e in starts:
        s_tok, p_tok = e.get("seq", ""), e.get("pid", "")
        if not (re.fullmatch(r"[1-9][0-9]*", s_tok) and re.fullmatch(r"[1-9][0-9]*", p_tok)):
            valid_ids = False
        start_pairs.append((s_tok, p_tok))
    for e in exits:
        s_tok, p_tok = e.get("seq", ""), e.get("pid", "")
        if not (re.fullmatch(r"[1-9][0-9]*", s_tok) and re.fullmatch(r"[1-9][0-9]*", p_tok)):
            valid_ids = False
        exit_pairs.append((s_tok, p_tok))

    # Strict chronological ordering: RING_START must precede matching RING_FILE/RING_EXIT, all before terminal STOP.
    ring_order_valid = True
    if records is not None:
        active_ring: tuple[str, str] | None = None
        seen_seqs: set[str] = set()
        stop_seen = False
        for kind, kv in records:
            if stop_seen:
                ring_order_valid = False
                break
            if kind == "RING_START":
                s_tok, p_tok = kv.get("seq", ""), kv.get("pid", "")
                if (
                    active_ring is not None or
                    not (re.fullmatch(r"[1-9][0-9]*", s_tok) and re.fullmatch(r"[1-9][0-9]*", p_tok)) or
                    s_tok in seen_seqs
                ):
                    ring_order_valid = False
                    break
                seen_seqs.add(s_tok)
                active_ring = (s_tok, p_tok)
            elif kind == "RING_FILE":
                if active_ring is None or kv.get("seq", "") != active_ring[0]:
                    ring_order_valid = False
                    break
            elif kind == "RING_EXIT":
                s_tok, p_tok = kv.get("seq", ""), kv.get("pid", "")
                if active_ring is None or (s_tok, p_tok) != active_ring:
                    ring_order_valid = False
                    break
                active_ring = None
            elif kind == "STOP":
                if active_ring is not None:
                    ring_order_valid = False
                    break
                stop_seen = True
        if active_ring is not None:
            ring_order_valid = False

    unique_seqs = len({s for s, _ in start_pairs}) == len(start_pairs)
    stop_counts_match = (
        stop_fields_complete and
        stop_rec["r_runs"] == str(len(start_pairs)) and
        stop_rec["r_ok"] == str(len(exit_pairs))
    )
    ring_cycles_paired = (
        valid_ids and
        unique_seqs and
        ring_order_valid and
        start_pairs == exit_pairs and
        stop_counts_match
    )
    unmatched_ring_cycles = not ring_cycles_paired
    runtime_clean = (
        boot_ok and
        not has_duplicate_keys and
        stop_fields_complete and
        stop_is_terminal and
        daemon_clean_stop and
        not ring_fault_seen and
        not ring_unresolved_seen and
        not log_truncated and
        ring_cycles_paired
    )
    return dict(
        boot_ok=boot_ok,
        has_duplicate_keys=has_duplicate_keys,
        stop_fields_complete=stop_fields_complete,
        stop_is_terminal=stop_is_terminal,
        daemon_clean_stop=daemon_clean_stop,
        ring_fault_seen=ring_fault_seen,
        ring_unresolved_seen=ring_unresolved_seen,
        log_truncated=log_truncated,
        ring_order_valid=ring_order_valid,
        ring_cycles_paired=ring_cycles_paired,
        unmatched_ring_cycles=unmatched_ring_cycles,
        runtime_clean=runtime_clean,
        ring_start_count=len(starts),
        ring_exit_count=len(exits),
        ring_file_count=summary.get("ring_file_count", 0),
    )


def verify_live_daemon_identity(session, pid: int, expected_exe: str, expected_starttime=None):
    """Inspect /proc/<pid> with explicit 4-way state: matched | proven_gone | proven_different | uncertain."""
    exists_raw, _ = session.command(
        f"if [ ! -e /proc/{pid} ]; then echo PID_GONE; else echo PID_EXISTS; fi"
    )
    if exists_raw.decode("ascii", "replace").strip() == "PID_GONE":
        return dict(
            matches=False,
            state="proven_gone",
            pid_gone=True,
            exe="",
            stat=None,
            any_stat=None,
            status={},
            status_raw="",
        )

    exe_raw, exe_rc = session.command(f"/bin/busybox readlink /proc/{pid}/exe 2>/dev/null", allowed=(0, 1))
    exe = exe_raw.decode("utf8", "replace").strip() if exe_rc == 0 else ""
    stat_raw, stat_rc = session.command(f"/bin/busybox cat /proc/{pid}/stat 2>/dev/null", allowed=(0, 1))
    stat_txt = stat_raw.decode("utf8", "replace") if stat_rc == 0 else ""
    status_raw, status_rc = session.command(f"/bin/busybox cat /proc/{pid}/status 2>/dev/null", allowed=(0, 1))
    status_txt = status_raw.decode("utf8", "replace") if status_rc == 0 else ""

    parsed_stat = parse_proc_stat(stat_txt, pid, "daemon.elf") if stat_rc == 0 else None
    any_stat = parse_any_proc_stat(stat_txt, pid) if stat_rc == 0 else None
    parsed_status = parse_proc_status(status_txt) if status_rc == 0 else {}

    matches = (
        exe_rc == 0 and exe == expected_exe and
        parsed_stat is not None and
        parsed_status.get("Name") == "daemon.elf" and
        parsed_status.get("Pid") == str(pid) and
        parsed_status.get("Tgid") == str(pid) and
        (expected_starttime is None or parsed_stat["starttime"] == expected_starttime)
    )
    if matches:
        state = "matched"
    else:
        exe_points_elsewhere = (
            exe_rc == 0 and bool(exe) and not (exe == expected_exe or exe.startswith(expected_exe + " "))
        )
        stat_proves_different = (
            any_stat is not None and (
                any_stat["comm"] != "daemon.elf" or
                (expected_starttime is not None and any_stat["starttime"] != expected_starttime)
            )
        )
        exe_conflicts_with_different = (
            exe_rc == 0 and bool(exe) and (exe == expected_exe or exe.startswith(expected_exe + " "))
        )
        if stat_proves_different and not exe_conflicts_with_different and (exe_rc != 0 or exe_points_elsewhere):
            state = "proven_different"
        else:
            state = "uncertain"

    return dict(
        matches=matches,
        state=state,
        pid_gone=False,
        exe=exe,
        stat=parsed_stat,
        any_stat=any_stat,
        status=parsed_status,
        status_raw=status_txt,
    )


def _valid_dir_path(path: str) -> bool:
    return path in ALLOWED_DIR_PATHS or bool(REMOTE_DAEMON_DIR_RE.fullmatch(path))


def _valid_file_path(path: str) -> bool:
    return (
        path in ALLOWED_STATIC_FILES or
        bool(REMOTE_DAEMON_LOG_RE.fullmatch(path)) or
        bool(REMOTE_DAEMON_PID_RE.fullmatch(path)) or
        bool(REMOTE_GUARD_OUT_RE.fullmatch(path))
    )


def inspect_dir_state(session, directory: str) -> str:
    require(_valid_dir_path(directory), f"Invalid Stage 7 RAM directory: {directory!r}")
    out, _ = session.command(
        f'if [ -d {directory} ] && [ ! -L {directory} ]; then echo DIR_OK; '
        f'elif [ ! -e {directory} ] && [ ! -L {directory} ]; then echo DIR_GONE; '
        f'else echo BAD; fi'
    )
    return out.decode("ascii", "replace").strip()


def verify_nonsymlink_dir(session, directory: str):
    state = inspect_dir_state(session, directory)
    require(state == "DIR_OK", f"Unexpected path state {state!r} at {directory}")


def inspect_file_state(session, path: str) -> str:
    require(_valid_file_path(path), f"Invalid Stage 7 RAM file path: {path!r}")
    out, _ = session.command(
        f'if [ -f {path} ] && [ ! -L {path} ]; then echo FILE_OK; '
        f'elif [ ! -e {path} ] && [ ! -L {path} ]; then echo FILE_ABSENT; '
        f'else echo FILE_BAD; fi'
    )
    return out.decode("ascii", "replace").strip()


def check_no_existing_ram_state(session, receipt):
    cmd = (
        'for d in /tmp_network/.m7-s6-* /tmp_network/.m7-s7-* /tmp_network/mlv2 /tmp_network/mods; '
        'do if [ -e "$d" ] || [ -L "$d" ]; then echo "$d"; fi; done'
    )
    body, _ = session.command(cmd)
    paths = [line.strip() for line in body.decode("ascii", "replace").splitlines() if line.strip()]
    receipt["ram_clean_check"] = dict(clear=not paths, paths=paths)
    require(not paths, f"Leftover RAM path(s) present: {paths}; run --collect or power-cycle camera first.")


def observe_live_s7_processes(session, daemon_exe: str, ring_exe: str) -> dict:
    """Scan /proc/[1-9]* for live daemon/ring EXEs and any unreadable userspace EXEs (fail-closed, < 495 framed bytes)."""
    require(REMOTE_S7_ELF_RE.fullmatch(daemon_exe), f"Invalid Stage 7 daemon path: {daemon_exe!r}")
    require(REMOTE_S7_ELF_RE.fullmatch(ring_exe), f"Invalid Stage 7 ring path: {ring_exe!r}")
    base_dir = daemon_exe[:-len("/daemon.elf")]
    require(
        daemon_exe == base_dir + "/daemon.elf" and ring_exe == base_dir + "/ring.elf",
        f"Mismatched Stage 7 daemon/ring paths: {daemon_exe!r}, {ring_exe!r}",
    )
    scan_cmd = (
        f'b={base_dir};x=/bin/busybox;n=;'
        'for p in /proc/[1-9]*;do [ -e "$p/stat" ]||continue;n=1;'
        'e=$($x readlink "$p/exe" 2>/dev/null);'
        'if [ -n "$e" ];then case "$e" in "$b/daemon.elf"|"$b/daemon.elf "*)echo D:$p;;"$b/ring.elf"|"$b/ring.elf "*)echo R:$p;;esac;'
        'elif ! c=$($x cat "$p/cmdline" 2>/dev/null)||[ -n "$c" ];then echo U:$p;fi;'
        'done;[ -n "$n" ]&&echo PROC_OK'
    )
    raw, rc = session.command(scan_cmd, allowed=(0, 1), timeout=15)
    lines = [line.strip() for line in raw.decode("utf8", "replace").splitlines() if line.strip()]
    proc_ok = (rc == 0) and ("PROC_OK" in lines)
    live_d: list[int] = []
    live_r: list[int] = []
    unread_pids: list[int] = []
    scan_malformed = False
    for line in lines:
        if line == "PROC_OK":
            continue
        if len(line) > 8 and line[1:8] == ":/proc/" and line[0] in ("D", "R", "U"):
            tok = line[8:]
            if re.fullmatch(r"[1-9][0-9]{0,9}", tok):
                val = int(tok)
                if 1 < val < 0x80000000:
                    if line[0] == "D":
                        live_d.append(val)
                    elif line[0] == "R":
                        live_r.append(val)
                    else:
                        unread_pids.append(val)
                    continue
        scan_malformed = True
    live_d = sorted(set(live_d))
    live_r = sorted(set(live_r))
    unread_pids = sorted(set(unread_pids))
    certain_clear = proc_ok and (not scan_malformed) and (not live_d) and (not live_r) and (not unread_pids)
    return dict(
        proc_ok=proc_ok,
        scan_malformed=scan_malformed,
        live_d=live_d,
        live_r=live_r,
        unread_pids=unread_pids,
        certain_clear=certain_clear,
    )


def request_stop_via_file(
    session,
    directory: str,
    daemon_exe: str,
    ring_exe: str,
    expected_pid=None,
    expected_starttime=None,
    max_polls: int = 250,
):
    """Stop ONLY this daemon + ring instance via private nonce stop file; verify certain exit (fail-closed)."""
    verify_nonsymlink_dir(session, directory)
    require(daemon_exe == directory + "/daemon.elf", f"Mismatched daemon exe {daemon_exe!r}")
    require(ring_exe == directory + "/ring.elf", f"Mismatched ring exe {ring_exe!r}")
    stop_file = directory + "/stop"
    _, rc = session.command(
        f"/bin/busybox test ! -L {stop_file} && /bin/busybox echo stop > {stop_file}",
        allowed=(0, 1),
    )
    require(rc == 0, f"Refused symlink or failed write at {stop_file}")
    last_obs = dict(proc_ok=False, scan_malformed=False, live_d=[], live_r=[], unread_pids=[], certain_clear=False)
    for _ in range(max_polls):
        session.command("/bin/busybox sleep 1")
        last_obs = observe_live_s7_processes(session, daemon_exe, ring_exe)
        id_clear = True
        if expected_pid is not None:
            recheck = verify_live_daemon_identity(session, expected_pid, daemon_exe, expected_starttime)
            id_clear = recheck["state"] in ("proven_gone", "proven_different")
        if id_clear and last_obs["certain_clear"]:
            return True, [], [], last_obs
    return False, last_obs["live_d"], last_obs["live_r"], last_obs


def write_sd_disabled_marker(session) -> bool:
    """Write /tmp_network/mlv2/sd-disabled safely (non-symlink verified, never calls shell exit). Never writes sd-stopped."""
    verify_nonsymlink_dir(session, REMOTE_MLV2_DIR)
    _, rc = session.command(
        f"/bin/busybox test ! -L {REMOTE_SD_DISABLED} && /bin/busybox echo disabled > {REMOTE_SD_DISABLED}",
        allowed=(0, 1),
    )
    if rc != 0:
        return False
    return inspect_file_state(session, REMOTE_SD_DISABLED) == "FILE_OK"


def remove_ram_dir_verified(session, directory: str) -> str:
    state = inspect_dir_state(session, directory)
    if state == "DIR_GONE":
        return "GONE"
    require(state == "DIR_OK", f"Refusing rm -rf on unexpected path state {state!r} at {directory}")
    session.command(f"/bin/busybox rm -rf {directory}", allowed=(0, 1))
    chk, _ = session.command(
        f'if [ -e {directory} ] || [ -L {directory} ]; then echo PRESENT; else echo GONE; fi',
        allowed=(0, 1),
    )
    return chk.decode("ascii", "replace").strip()


def fsync_dir(directory: Path):
    dfd = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def write_bytes_atomic(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with tmp.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        fsync_dir(path.parent)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def write_text_atomic(path: Path, text: str):
    write_bytes_atomic(path, text.encode("utf-8"))


def persist_named_artifact_atomic(text: str, out_dir: Path, utc: str, nonce: str, suffix: str) -> Path:
    path = out_dir / f"{utc}-{nonce}-{suffix}"
    write_text_atomic(path, text)
    return path


def persist_named_bytes_atomic(data: bytes, out_dir: Path, utc: str, nonce: str, suffix: str) -> Path:
    path = out_dir / f"{utc}-{nonce}-{suffix}"
    write_bytes_atomic(path, data)
    return path


def validate_active_state_dict(state: dict) -> dict:
    """Validate all custody invariants; enforced on EVERY write and read so corrupt intermediate states cannot be saved."""
    require(isinstance(state, dict), "Corrupt active state JSON")
    require(state.get("schema_version") == 1, f"Unsupported active state schema: {state.get('schema_version')!r}")
    status = state.get("status", "")
    nonce = state.get("nonce", "")
    directory = state.get("directory", "")
    require(status in VALID_CUSTODY_STATUSES, f"Corrupt active state status: {status!r}")
    require(type(nonce) is str and bool(re.fullmatch(r"[0-9a-f]{12}", nonce)), "Corrupt active state nonce")
    require(directory == "/tmp_network/.m7-s7-" + nonce, "Corrupt active state directory")
    require(state.get("mlv2_dir") == REMOTE_MLV2_DIR, "Corrupt active state mlv2_dir")
    require(state.get("mods_dir") == REMOTE_MODS_DIR, "Corrupt active state mods_dir")
    require(state.get("daemon_exe") == directory + "/daemon.elf", "Corrupt active state daemon_exe")
    require(state.get("ring_exe") == directory + "/ring.elf", "Corrupt active state ring_exe")
    require(type(state.get("install_attempted")) is bool, "Corrupt active state install_attempted")
    require(type(state.get("launch_attempted")) is bool, "Corrupt active state launch_attempted")
    require(type(state.get("daemon_started")) is bool, "Corrupt active state daemon_started")
    require(type(state.get("mlv2_installed")) is bool, "Corrupt active state mlv2_installed")
    require(type(state.get("mlv2_stock_verified")) is bool, "Corrupt active state mlv2_stock_verified")
    require(type(state.get("sd_disabled_confirmed")) is bool, "Corrupt active state sd_disabled_confirmed")
    require(type(state.get("daemon_collected")) is bool, "Corrupt active state daemon_collected")
    require(type(state.get("daemon_log_lost")) is bool, "Corrupt active state daemon_log_lost")
    require(type(state.get("im_pid")) is int and 1 < state["im_pid"] < 0x80000000, "Corrupt active state im_pid")
    require(type(state.get("im_starttime")) is int and state["im_starttime"] >= 0, "Corrupt active state im_starttime")
    require(type(state.get("guard_bytes")) is int and state["guard_bytes"] > 0, "Corrupt active state guard_bytes")
    require(type(state.get("guard_md5")) is str and bool(re.fullmatch(r"[0-9a-f]{32}", state["guard_md5"])), "Corrupt active state guard_md5")
    require(type(state.get("req_bytes")) is int and state["req_bytes"] > 0, "Corrupt active state req_bytes")
    require(type(state.get("req_md5")) is str and bool(re.fullmatch(r"[0-9a-f]{32}", state["req_md5"])), "Corrupt active state req_md5")
    if state.get("view_bias") is not None:
        require(type(state["view_bias"]) is str and bool(re.fullmatch(r"[0-9a-f]{8}", state["view_bias"])), "Corrupt active state view_bias")
    if state["mlv2_installed"]:
        require(state["install_attempted"] is True, "Corrupt active state: mlv2_installed without install_attempted")
    if state["launch_attempted"]:
        require(state["install_attempted"] is True, "Corrupt active state: launch_attempted without install_attempted")
    if state["daemon_started"]:
        require(state["launch_attempted"] is True, "Corrupt active state: daemon_started without launch_attempted")
    if state["daemon_log_lost"]:
        require(state.get("daemon_runtime_clean") is False, "Corrupt active state: daemon_log_lost without daemon_runtime_clean=False")
    if status == "running":
        require(type(state.get("daemon_pid")) is int and 1 < state["daemon_pid"] < 0x80000000, "Corrupt active state pid")
        require(type(state.get("daemon_starttime")) is int and state["daemon_starttime"] >= 0, "Corrupt active state starttime")
        require(state["mlv2_installed"] is True and state["daemon_started"] is True, "Running state must have mlv2_installed and daemon_started")
    else:
        require(state.get("daemon_pid") is None and state.get("daemon_starttime") is None, "Corrupt non-running active state")
    if state.get("saved_log_path") is not None:
        require(type(state["saved_log_path"]) is str, "Corrupt active state saved_log_path")
    if state.get("daemon_runtime_clean") is not None:
        require(type(state["daemon_runtime_clean"]) is bool, "Corrupt active state daemon_runtime_clean")
    return state


def write_active_state_exclusive(state: dict, path: Path = ACTIVE_STATE):
    validate_active_state_dict(state)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with tmp.open("x", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(tmp, path)
        fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def replace_active_state_atomic(state: dict, path: Path = ACTIVE_STATE):
    validate_active_state_dict(state)
    write_text_atomic(path, json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def load_active_state(path: Path = ACTIVE_STATE) -> dict:
    require(path.is_file(), f"No active Stage 7.2 RAM session file at {path}; run --start first.")
    state = json.loads(path.read_text(encoding="utf-8"))
    return validate_active_state_dict(state)


def verify_usable_initial_witnesses(
    summary: dict,
    daemon_pid: int,
    im_pid: int,
    im_starttime: int,
    *,
    after: int,
    burst_cap: int,
    post_max: int,
    debounce_ms: int,
):
    boot = summary.get("boot")
    require(boot is not None, "Missing BOOT record in initial Stage 7 daemon.log")
    require(boot.get("self_pid") == str(daemon_pid), f"BOOT self_pid mismatch: {boot.get('self_pid')} != {daemon_pid}")
    require(boot.get("im_pid") == str(im_pid), f"BOOT im_pid mismatch: {boot.get('im_pid')} != {im_pid}")
    require(boot.get("im_st") == str(im_starttime), f"BOOT im_st mismatch: {boot.get('im_st')} != {im_starttime}")
    require(boot.get("in_ok") == "1", "InfraInput watch init failed (in_ok!=1)")
    require(boot.get("ring_ok") == "1", "ring.elf missing or unreadable at daemon boot (ring_ok!=1)")
    require(boot.get("pre_f") == "0", f"Daemon must start passive OFF (pre_f=0), got {boot.get('pre_f')!r}")
    require(boot.get("post") == str(after), f"BOOT post mismatch: {boot.get('post')} != {after}")
    require(boot.get("bcap") == str(burst_cap), f"BOOT bcap mismatch: {boot.get('bcap')} != {burst_cap}")
    require(boot.get("pmax") == str(post_max), f"BOOT pmax mismatch: {boot.get('pmax')} != {post_max}")
    require(boot.get("deb") == str(debounce_ms), f"BOOT deb mismatch: {boot.get('deb')} != {debounce_ms}")
    mon_proc = boot.get("mon_proc", "")
    mon_mwf = boot.get("mon_mwf", "")
    require(
        bool(re.fullmatch(r"[1-9][0-9]*", mon_proc)) and mon_proc == mon_mwf,
        f"Monitor TID mismatch/missing: proc={mon_proc!r} mwf={mon_mwf!r}",
    )
    require(summary.get("state_count", 0) >= 1, "Missing initial STATE record")
    require(summary.get("stop") is None, f"Daemon already emitted STOP: {summary.get('stop')}")
    first = summary["states"][0]
    require(first.get("cam") == "1", f"Initial CamSetParams read invalid: {first}")
    require(first.get("pre_f") == "0", f"Initial STATE pre_f must be 0: {first}")
    require(first.get("tog") == "0", f"Initial STATE tog must be 0: {first}")
    require(first.get("gate") == "0", f"Initial STATE gate must be 0: {first}")
    require(first.get("sub_ok") == "1", f"Initial subscription read invalid: {first}")
    require(first.get("half_ok") == "1" and first.get("full_ok") == "1", f"Initial shutter rows invalid: {first}")


def inspect_jpeg_file(path: Path) -> dict:
    """Read-only strict JPEG SOI/SOF0-2/SOS/EOI structural verification."""
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
    require(card_root.is_dir() and not card_root.is_symlink(), f"Card mount directory not found or symlink: {card_root}")
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
        if fpath.is_symlink():
            results.append(dict(file=name, ok=False, reason="symlink_rejected", expected_bytes=expected_bytes))
            all_ok = False
            continue
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


def _snapshot_optional_mlv2_artifacts(session, receipt, log_out_dir: Path):
    """Best-effort byte-faithful read & durable persistence of mod_loader.log and precap.cfg."""
    if inspect_dir_state(session, REMOTE_MODS_DIR) == "DIR_OK":
        ml_state = inspect_file_state(session, REMOTE_MOD_LOG)
        receipt["mod_loader_log_state"] = ml_state
        if ml_state == "FILE_OK":
            raw, rc = session.command(f"/bin/busybox cat {REMOTE_MOD_LOG}", allowed=(0, 1), timeout=15)
            if rc == 0:
                text = raw.decode("utf8", "replace")
                if text and not text.endswith("\n"):
                    text += "\n"
                receipt["mod_loader_log"] = text
                saved = persist_named_artifact_atomic(
                    text, log_out_dir, receipt["utc"], receipt["nonce"], "mod_loader.log"
                )
                receipt["saved_mod_loader_log_path"] = str(saved)
    if inspect_dir_state(session, REMOTE_MLV2_DIR) == "DIR_OK":
        cfg_state = inspect_file_state(session, REMOTE_PRECAP_CFG)
        receipt["precap_cfg_state"] = cfg_state
        if cfg_state == "FILE_OK":
            sz_raw, sz_rc = session.command(f"/bin/busybox wc -c {REMOTE_PRECAP_CFG}", allowed=(0, 1))
            sz_m = re.fullmatch(
                r"\s*([0-9]+)\s+" + re.escape(REMOTE_PRECAP_CFG) + r"\s*",
                sz_raw.decode("utf8", "replace"),
            ) if sz_rc == 0 else None
            exact_bytes = int(sz_m.group(1)) if sz_m else None
            md5_raw, md5_rc = session.command(f"/bin/busybox md5sum {REMOTE_PRECAP_CFG}", allowed=(0, 1))
            md5_m = re.fullmatch(
                r"([0-9a-f]{32})\s+\*?" + re.escape(REMOTE_PRECAP_CFG) + r"\s*",
                md5_raw.decode("utf8", "replace").strip(),
            ) if md5_rc == 0 else None
            remote_md5 = md5_m.group(1) if md5_m else None
            # Sentinel preserves exact raw bytes and trailing LF without matching __M7_ ACK markers.
            raw, rc = session.command(
                f"/bin/busybox cat {REMOTE_PRECAP_CFG} && /bin/busybox echo CFG_END_SENTINEL",
                allowed=(0, 1),
                timeout=10,
            )
            if rc == 0:
                sentinel_b = b"CFG_END_SENTINEL\n"
                if raw.endswith(sentinel_b):
                    exact_raw = raw[:-len(sentinel_b)]
                    observed_md5 = hashlib.md5(exact_raw).hexdigest()
                    # Verify BOTH exact byte length and exact MD5 BEFORE saving named precap.cfg (reject CRLF alteration!).
                    if (
                        exact_bytes is None or
                        remote_md5 is None or
                        len(exact_raw) != exact_bytes or
                        observed_md5 != remote_md5
                    ):
                        receipt["precap_cfg"] = dict(
                            valid=False,
                            enabled=False,
                            pre_frames=0,
                            byte_fidelity_error=True,
                            size_mismatch=(exact_bytes is None or len(exact_raw) != exact_bytes),
                            md5_mismatch=(remote_md5 is None or observed_md5 != remote_md5),
                            reported_bytes=exact_bytes,
                            observed_bytes=len(exact_raw),
                            reported_md5=remote_md5,
                            observed_md5=observed_md5,
                            observed_raw_hex=exact_raw.hex(),
                        )
                    else:
                        saved_cfg = persist_named_bytes_atomic(
                            exact_raw, log_out_dir, receipt["utc"], receipt["nonce"], "precap.cfg"
                        )
                        receipt["saved_precap_cfg_path"] = str(saved_cfg)
                        try:
                            exact_ascii = exact_raw.decode("ascii")
                        except UnicodeDecodeError:
                            receipt["precap_cfg"] = dict(
                                valid=False,
                                enabled=False,
                                pre_frames=0,
                                raw_hex=exact_raw.hex(),
                                non_ascii=True,
                            )
                        else:
                            receipt["precap_cfg"] = parse_precap_cfg(exact_ascii)
                else:
                    receipt["precap_cfg"] = dict(valid=False, enabled=False, pre_frames=0, reason="sentinel_missing")


def _run_card_check_nonfatal(receipt: dict, card_root, summary_or_path, *, allow_empty_card: bool):
    """Run card verification without aborting camera teardown; record failure cleanly in receipt."""
    if card_root is None:
        return
    try:
        if isinstance(summary_or_path, dict):
            ring_files = summary_or_path.get("ring_files", [])
        elif isinstance(summary_or_path, (str, Path)) and Path(summary_or_path).is_file():
            ring_files = parse_daemon_log(Path(summary_or_path).read_text(encoding="utf-8")).get("ring_files", [])
        else:
            receipt["card_check"] = dict(
                card_root=str(card_root),
                all_ok=False,
                error="No collected daemon.log available for requested --card verification",
            )
            return
        receipt["card_check"] = verify_card_saved_files(
            Path(card_root),
            ring_files,
            expect_nonempty=not allow_empty_card,
        )
    except Exception as err:
        receipt["card_check"] = dict(
            card_root=str(card_root),
            all_ok=False,
            error=f"{type(err).__name__}: {err}",
        )


def do_start(
    camera,
    receipt,
    artifacts: dict[str, bytes],
    manifest: dict,
    daemon_image: bytes,
    ring_image: bytes,
    *,
    duration_ms: int,
    after: int,
    burst_cap: int,
    post_max: int,
    backlog_cap: int,
    debounce_ms: int,
    focus_ms: int,
    active_path: Path = ACTIVE_STATE,
    log_out_dir: Path = OUT_DIR,
):
    with custody_lock(active_path):
        require(not active_path.exists(), f"Active Stage 7.2 RAM session already exists at {active_path}; run --collect first.")
        require(receipt.get("model") == "DSC-RX100M7", f"Unsupported model: {receipt.get('model')!r}")
        session = Stage7Session(camera, receipt)
        directory = "/tmp_network/.m7-s7-" + receipt["nonce"]
        remote_daemon = directory + "/daemon.elf"
        remote_ring = directory + "/ring.elf"
        remote_pid = directory + "/daemon.pid"
        remote_log = directory + "/daemon.log"

        core_bytes = len(artifacts["core"])
        core_md5 = hashlib.md5(artifacts["core"]).hexdigest()
        guard_bytes = len(artifacts["guard"])
        guard_md5 = hashlib.md5(artifacts["guard"]).hexdigest()
        req_bytes = len(artifacts["request"])
        req_md5 = hashlib.md5(artifacts["request"]).hexdigest()

        enable_attempted = False
        custody_created = False
        created_dirs: list[str] = []
        mlv2_install_attempted = False
        mlv2_confirmed_stock_after_fail = False
        sd_disabled_written = False
        launched = False
        stopped_after_fail = False
        failed_start_log_safe = False
        daemon_pid = None
        daemon_starttime = None
        base_state: dict = {}
        preflight: dict = {}
        observed_view_bias: str | None = None

        try:
            with usb.deadline(10):
                camera.setTerminalEnable(False)
                enable_attempted = True
                camera.setTerminalEnable(True)
                receipt["shell_banner"] = read_ready(camera).decode("utf8", "replace")

            preflight = run_start_preflight(session, receipt)
            check_no_existing_ram_state(session, receipt)
            applets, applet_src = detect_busybox_applets(session)
            receipt["busybox_applets_source"] = applet_src
            receipt["busybox_has_gunzip"] = "gunzip" in applets

            base_state = dict(
                schema_version=1,
                status="pending_upload",
                nonce=receipt["nonce"],
                directory=directory,
                mlv2_dir=REMOTE_MLV2_DIR,
                mods_dir=REMOTE_MODS_DIR,
                daemon_exe=remote_daemon,
                ring_exe=remote_ring,
                install_attempted=False,
                launch_attempted=False,
                daemon_started=False,
                mlv2_installed=False,
                mlv2_stock_verified=False,
                sd_disabled_confirmed=False,
                daemon_collected=False,
                daemon_log_lost=False,
                daemon_pid=None,
                daemon_starttime=None,
                im_pid=preflight["pid"],
                im_starttime=preflight["im_starttime"],
                view_bias=None,
                guard_bytes=guard_bytes,
                guard_md5=guard_md5,
                req_bytes=req_bytes,
                req_md5=req_md5,
                daemon_sha256=receipt["daemon_sha256"],
                ring_sha256=receipt["ring_sha256"],
                core_sha256=receipt["core_sha256"],
                guard_sha256=receipt["guard_sha256"],
                req_sha256=receipt["req_sha256"],
                precap_mod_sha256=receipt["precap_mod_sha256"],
                saved_log_path=None,
                saved_mod_loader_log_path=None,
                saved_precap_cfg_path=None,
                daemon_runtime_clean=None,
                duration_ms=duration_ms,
                after=after,
                burst_cap=burst_cap,
                post_max=post_max,
                backlog_cap=backlog_cap,
                debounce_ms=debounce_ms,
                focus_ms=focus_ms,
                utc=receipt["utc"],
            )
            write_active_state_exclusive(base_state, active_path)
            custody_created = True

            for dpath, perm in ((REMOTE_MLV2_DIR, "755"), (REMOTE_MODS_DIR, "755"), (directory, "700")):
                session.command(f"/bin/busybox mkdir {dpath}")
                created_dirs.append(dpath)
                session.command(f"/bin/busybox chmod {perm} {dpath}")
                verify_nonsymlink_dir(session, dpath)

            # Upload ALL six RAM artifacts BEFORE touching im.elf hooks.
            upload_ram_file(session, artifacts["core"], REMOTE_CORE, applets, "core.bin", "444")
            upload_ram_file(session, artifacts["request"], REMOTE_REQ, applets, "mlv2.req", "444")
            upload_ram_file(session, artifacts["guard"], REMOTE_GUARD, applets, "mlv2_guard.elf", "500")
            upload_ram_file(session, artifacts["precap_mod"], REMOTE_PRECAP_MOD, applets, "PreCapture.mod", "444")
            upload_ram_file(session, ring_image, remote_ring, applets, "stage7_ring.elf", "500")
            upload_ram_file(session, daemon_image, remote_daemon, applets, "stage7_daemon.elf", "500")

            # Read-only pinned guard self-checks: verify FNV of core.bin and stock state of im.elf.
            pin_ok, fnv_pins, fnv_parsed, fnv_rc, fnv_txt = run_pinned_guard_command(
                session, "fnv", REMOTE_CORE,
                guard_bytes=guard_bytes, guard_md5=guard_md5,
                arg_bytes=core_bytes, arg_md5=core_md5,
            )
            receipt["guard_fnv"] = dict(pins_ok=pin_ok, pins=fnv_pins, rc=fnv_rc, output=fnv_txt, parsed=fnv_parsed)
            expected_core_fnv = f"{builder.fnv1a_32(artifacts['core']):08x}"
            require(
                pin_ok and guard_fnv_matches(fnv_parsed, fnv_rc, expected_size=core_bytes, expected_fnv_hex=expected_core_fnv),
                f"mlv2_guard fnv mismatch: pin_ok={pin_ok} rc={fnv_rc} out={fnv_txt!r}",
            )

            pin_ok, pre_pins, pre_chk, pre_rc, pre_txt = run_pinned_guard_command(
                session, "check", REMOTE_REQ,
                guard_bytes=guard_bytes, guard_md5=guard_md5,
                arg_bytes=req_bytes, arg_md5=req_md5,
            )
            receipt["guard_check_before"] = dict(pins_ok=pin_ok, pins=pre_pins, rc=pre_rc, output=pre_txt, parsed=pre_chk)
            require(
                pin_ok and guard_check_matches(
                    pre_chk, pre_rc,
                    expected_pid=preflight["pid"],
                    expected_hooks="stock",
                    expected_rects="stock",
                    expected_shim="zero",
                ),
                f"im.elf not in clean stock state before install: pin_ok={pin_ok} rc={pre_rc} out={pre_txt!r}",
            )
            observed_view_bias = pre_chk["view_bias"]
            base_state["view_bias"] = observed_view_bias

            # Advance custody to pending_install (install_attempted=True) BEFORE invoking mlv2_guard install.
            base_state["install_attempted"] = True
            replace_active_state_atomic(dict(base_state, status="pending_install"), active_path)

            mlv2_install_attempted = True
            pin_ok, inst_pins, inst, inst_rc, inst_txt = run_pinned_guard_command(
                session, "install", REMOTE_REQ,
                guard_bytes=guard_bytes, guard_md5=guard_md5,
                arg_bytes=req_bytes, arg_md5=req_md5,
                timeout=20,
            )
            receipt["guard_install"] = dict(pins_ok=pin_ok, pins=inst_pins, rc=inst_rc, output=inst_txt, parsed=inst)
            require(
                pin_ok and guard_install_matches(
                    inst, inst_rc,
                    expected_pid=preflight["pid"],
                    expected_view_bias=observed_view_bias,
                    manifest=manifest,
                ),
                f"mlv2_guard install failed: pin_ok={pin_ok} rc={inst_rc} out={inst_txt!r}",
            )

            pin_ok, post_pins, post_chk, post_rc, post_txt = run_pinned_guard_command(
                session, "check", REMOTE_REQ,
                guard_bytes=guard_bytes, guard_md5=guard_md5,
                arg_bytes=req_bytes, arg_md5=req_md5,
            )
            receipt["guard_check_after"] = dict(pins_ok=pin_ok, pins=post_pins, rc=post_rc, output=post_txt, parsed=post_chk)
            require(
                pin_ok and guard_check_matches(
                    post_chk, post_rc,
                    expected_pid=preflight["pid"],
                    expected_hooks="v2",
                    expected_rects="patched",
                    expected_shim="shim",
                    expected_view_bias=observed_view_bias,
                ),
                f"Post-install mlv2_guard check failed: pin_ok={pin_ok} rc={post_rc} out={post_txt!r}",
            )

            base_state["launch_attempted"] = True
            pending_launch = dict(base_state, status="pending_launch", mlv2_installed=True)
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
                summary,
                daemon_pid,
                preflight["pid"],
                preflight["im_starttime"],
                after=after,
                burst_cap=burst_cap,
                post_max=post_max,
                debounce_ms=debounce_ms,
            )

            base_state["daemon_started"] = True
            running_record = dict(
                base_state,
                status="running",
                mlv2_installed=True,
                daemon_pid=daemon_pid,
                daemon_starttime=daemon_starttime,
            )
            replace_active_state_atomic(running_record, active_path)

            receipt["daemon_pid"] = daemon_pid
            receipt["daemon_starttime"] = daemon_starttime
            receipt["directory"] = directory
            receipt["view_bias"] = observed_view_bias
            receipt["start_ready"] = True

            print(
                f"STAGE7_RAM_STARTED: im_pid={preflight['pid']} view_bias=0x{observed_view_bias} "
                f"daemon_pid={daemon_pid} dir={directory}",
                flush=True,
            )
            for line in initial_log.splitlines()[:6]:
                print("  " + line, flush=True)
        except BaseException:
            if launched and directory in created_dirs and not camera.dev.poisoned:
                try:
                    stopped_after_fail, live_d, live_r, stop_obs = request_stop_via_file(
                        session, directory, remote_daemon, remote_ring,
                        expected_pid=daemon_pid,
                        expected_starttime=daemon_starttime,
                    )
                    receipt["failed_start_stopped"] = stopped_after_fail
                    receipt["failed_start_live_daemon_pids"] = live_d
                    receipt["failed_start_live_ring_pids"] = live_r
                    receipt["failed_start_stop_observation"] = stop_obs
                    if stopped_after_fail:
                        log_state = inspect_file_state(session, remote_log)
                        receipt["failed_start_log_state"] = log_state
                        if log_state == "FILE_ABSENT":
                            failed_start_log_safe = True
                        elif log_state == "FILE_OK":
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
                                fs_summary = parse_daemon_log(final_log)
                                fs_diag = compute_log_diagnostics(fs_summary)
                                receipt["failed_start_diagnostics"] = fs_diag
                                fs_clean = bool(fs_diag["runtime_clean"]) if final_log.strip() else False
                                receipt["failed_start_runtime_clean"] = fs_clean
                                saved = persist_named_artifact_atomic(
                                    final_log, log_out_dir, receipt["utc"], receipt["nonce"], "daemon.log"
                                )
                                receipt["saved_log_path"] = str(saved)
                                receipt["log_persisted"] = True
                                # Checkpoint 1 BEFORE removing nonce dir so failed-start fault/log can NEVER vanish on ACK loss!
                                if custody_created and base_state:
                                    cp1 = dict(
                                        base_state,
                                        status="daemon_log_persisted",
                                        install_attempted=mlv2_install_attempted,
                                        launch_attempted=launched,
                                        daemon_started=False,
                                        mlv2_installed=bool(mlv2_install_attempted),
                                        daemon_pid=None,
                                        daemon_starttime=None,
                                        saved_log_path=str(saved),
                                        daemon_runtime_clean=fs_clean,
                                    )
                                    replace_active_state_atomic(cp1, active_path)
                                    base_state = cp1
                                failed_start_log_safe = True
                            else:
                                receipt["failed_start_cleanup"] = "DEFERRED_LOG_READ_FAILED"
                        else:
                            receipt["failed_start_cleanup"] = "DEFERRED_LOG_BAD_STATE"
                except Exception as err:
                    receipt["failed_start_stop_error"] = str(err)
                    failed_start_log_safe = False

            if mlv2_install_attempted and not camera.dev.poisoned:
                try:
                    pin_ok, fpins, fchk, frc, ftxt = run_pinned_guard_command(
                        session, "check", REMOTE_REQ,
                        guard_bytes=guard_bytes, guard_md5=guard_md5,
                        arg_bytes=req_bytes, arg_md5=req_md5,
                    )
                    receipt["failed_start_guard_pins"] = fpins
                    if pin_ok:
                        receipt["failed_start_guard_check"] = dict(rc=frc, output=ftxt, parsed=fchk)
                        if guard_check_matches(
                            fchk, frc,
                            expected_pid=preflight["pid"],
                            expected_hooks="stock",
                            expected_rects="stock",
                            expected_shim="zero",
                            expected_view_bias=observed_view_bias,
                        ):
                            mlv2_confirmed_stock_after_fail = True
                        else:
                            sd_disabled_written = write_sd_disabled_marker(session)
                            receipt["failed_start_sd_disabled_written"] = sd_disabled_written
                    else:
                        sd_disabled_written = write_sd_disabled_marker(session)
                        receipt["failed_start_sd_disabled_written"] = sd_disabled_written
                except Exception as err:
                    receipt["failed_start_guard_error"] = str(err)
                    mlv2_confirmed_stock_after_fail = False
                    if not camera.dev.poisoned and REMOTE_MLV2_DIR in created_dirs:
                        try:
                            sd_disabled_written = write_sd_disabled_marker(session)
                            receipt["failed_start_sd_disabled_written"] = sd_disabled_written
                        except Exception as derr:
                            receipt["failed_start_sd_disabled_error"] = str(derr)
            raise
        finally:
            if not receipt.get("start_ready") and not camera.dev.poisoned:
                daemon_dir_gone = directory not in created_dirs
                if directory in created_dirs and (not launched or (stopped_after_fail and failed_start_log_safe)):
                    try:
                        daemon_dir_gone = remove_ram_dir_verified(session, directory) == "GONE"
                        receipt["failed_start_daemon_dir_removed"] = daemon_dir_gone
                    except Exception as err:
                        receipt["failed_start_daemon_cleanup_error"] = str(err)

                can_remove_mlv2 = (not mlv2_install_attempted) or mlv2_confirmed_stock_after_fail
                if can_remove_mlv2:
                    # NEVER swallow Checkpoint 3 failure: preserve mlv2/mods if stock checkpoint cannot be written!
                    stock_checkpoint_ok = (not custody_created) or (not mlv2_install_attempted)
                    if custody_created and mlv2_confirmed_stock_after_fail and base_state:
                        try:
                            cp3 = dict(
                                base_state,
                                status="mlv2_stock_verified",
                                install_attempted=mlv2_install_attempted,
                                mlv2_installed=False,
                                mlv2_stock_verified=True,
                                daemon_collected=bool(daemon_dir_gone and receipt.get("saved_log_path")),
                                daemon_pid=None,
                                daemon_starttime=None,
                                saved_log_path=receipt.get("saved_log_path"),
                                daemon_runtime_clean=receipt.get("failed_start_runtime_clean"),
                            )
                            replace_active_state_atomic(cp3, active_path)
                            base_state = cp3
                            stock_checkpoint_ok = True
                        except Exception as err:
                            receipt["failed_start_stock_checkpoint_error"] = str(err)
                            stock_checkpoint_ok = False
                    if stock_checkpoint_ok:
                        mods_gone = REMOTE_MODS_DIR not in created_dirs
                        mlv2_gone = REMOTE_MLV2_DIR not in created_dirs
                        try:
                            if REMOTE_MODS_DIR in created_dirs:
                                mods_gone = remove_ram_dir_verified(session, REMOTE_MODS_DIR) == "GONE"
                            if REMOTE_MLV2_DIR in created_dirs:
                                mlv2_gone = remove_ram_dir_verified(session, REMOTE_MLV2_DIR) == "GONE"
                        except Exception as err:
                            receipt["failed_start_mlv2_cleanup_error"] = str(err)
                        if daemon_dir_gone and mlv2_gone and mods_gone:
                            receipt["failed_start_cleanup"] = True
                            if custody_created and active_path.exists():
                                active_path.unlink()
                                receipt["failed_start_custody_cleared"] = True
                    else:
                        receipt["failed_start_cleanup"] = "DEFERRED_STOCK_CHECKPOINT_FAILED"
                else:
                    receipt["failed_start_cleanup"] = "MLV2_PRESERVED_SD_DISABLED"
                    if custody_created and sd_disabled_written and daemon_dir_gone and base_state:
                        try:
                            replace_active_state_atomic(
                                dict(
                                    base_state,
                                    status="mlv2_disabled_pending_reboot_or_uninstall",
                                    install_attempted=True,
                                    mlv2_installed=True,
                                    sd_disabled_confirmed=True,
                                    daemon_collected=bool(receipt.get("saved_log_path")),
                                    daemon_pid=None,
                                    daemon_starttime=None,
                                    saved_log_path=receipt.get("saved_log_path"),
                                    daemon_runtime_clean=receipt.get("failed_start_runtime_clean"),
                                ),
                                active_path,
                            )
                            receipt["failed_start_custody_updated"] = "mlv2_disabled_pending_reboot_or_uninstall"
                        except Exception as err:
                            receipt["failed_start_custody_update_error"] = str(err)
            if enable_attempted:
                try:
                    with usb.deadline(8):
                        camera.setTerminalEnable(False)
                    receipt["terminal_disable_requested"] = True
                except Exception as err:
                    receipt["terminal_disable_error"] = f"{type(err).__name__}: {err}"
            if hasattr(camera, "dev") and hasattr(camera.dev, "packet_log"):
                receipt["packets"] = list(camera.dev.packet_log)


def _latch_runtime_clean(prior: bool | None, current: bool | None) -> bool | None:
    """Monotonic latch: once a runtime fault (False) is recorded, never revert to True or None."""
    if prior is False or current is False:
        return False
    if current is True:
        return True
    return prior


def do_collect(
    camera,
    receipt,
    artifacts: dict[str, bytes] | None = None,
    manifest: dict | None = None,
    *,
    active_path: Path = ACTIVE_STATE,
    log_out_dir: Path = OUT_DIR,
    card_root=None,
    allow_empty_card: bool = False,
):
    with custody_lock(active_path):
        require(receipt.get("model") == "DSC-RX100M7", f"Unsupported model: {receipt.get('model')!r}")
        if artifacts is None or manifest is None:
            artifacts, manifest = load_and_verify_sealed_artifacts()

        active = load_active_state(active_path)
        sealed_guard_bytes = len(artifacts["guard"])
        sealed_guard_md5 = hashlib.md5(artifacts["guard"]).hexdigest()
        sealed_req_bytes = len(artifacts["request"])
        sealed_req_md5 = hashlib.md5(artifacts["request"]).hexdigest()
        require(
            active["guard_bytes"] == sealed_guard_bytes and active["guard_md5"] == sealed_guard_md5 and
            active["req_bytes"] == sealed_req_bytes and active["req_md5"] == sealed_req_md5,
            "Active custody guard/request pins disagree with current sealed Stage 7.1 build",
        )

        directory = active["directory"]
        remote_daemon = active["daemon_exe"]
        remote_ring = active["ring_exe"]
        remote_pid = directory + "/daemon.pid"
        remote_log = directory + "/daemon.log"
        expected_pid = active["daemon_pid"]
        expected_starttime = active["daemon_starttime"]
        receipt["active_session"] = dict(active)
        receipt["card_requested"] = (card_root is not None)
        if active.get("daemon_runtime_clean") is not None:
            receipt["prior_daemon_runtime_clean"] = active["daemon_runtime_clean"]
        if active.get("daemon_log_lost"):
            receipt["prior_daemon_log_lost"] = True

        session = Stage7Session(camera, receipt)
        enable_attempted = False
        card_source: dict | str | None = active.get("saved_log_path")

        try:
            with usb.deadline(10):
                camera.setTerminalEnable(False)
                enable_attempted = True
                camera.setTerminalEnable(True)
                receipt["shell_banner"] = read_ready(camera).decode("utf8", "replace")

            preflight = run_collect_preflight(
                session, receipt,
                expected_prev_pid=active["im_pid"],
                expected_prev_starttime=active["im_starttime"],
            )
            im_obs = preflight["im_observation"]
            im_state = im_obs["state"]
            daemon_dir_state = inspect_dir_state(session, directory)
            mlv2_dir_state = inspect_dir_state(session, REMOTE_MLV2_DIR)
            mods_dir_state = inspect_dir_state(session, REMOTE_MODS_DIR)
            receipt["remote_dir_states"] = dict(
                daemon=daemon_dir_state,
                mlv2=mlv2_dir_state,
                mods=mods_dir_state,
            )
            require(
                daemon_dir_state != "BAD" and mlv2_dir_state != "BAD" and mods_dir_state != "BAD",
                f"Unexpected symlink/non-dir state in RAM: {receipt['remote_dir_states']}",
            )

            # Case 1: All three RAM directories are absent.
            if daemon_dir_state == "DIR_GONE" and mlv2_dir_state == "DIR_GONE" and mods_dir_state == "DIR_GONE":
                s7_obs = observe_live_s7_processes(session, remote_daemon, remote_ring)
                receipt["s7_process_observation"] = s7_obs
                receipt["live_daemon_pids_at_collect"] = s7_obs["live_d"]
                receipt["live_ring_pids_at_collect"] = s7_obs["live_r"]
                id_clear = True
                if expected_pid is not None:
                    ident = verify_live_daemon_identity(session, expected_pid, remote_daemon, expected_starttime)
                    receipt["daemon_identity_at_collect"] = ident
                    id_clear = ident["state"] in ("proven_gone", "proven_different")
                if not s7_obs["certain_clear"] or not id_clear:
                    receipt["alive_at_collect"] = True
                    receipt["stopped_cleanly"] = False
                    receipt["cleanup"] = (
                        "DEFERRED_PROCESS_STILL_ALIVE"
                        if (s7_obs["live_d"] or s7_obs["live_r"] or (expected_pid is not None and receipt.get("daemon_identity_at_collect", {}).get("state") == "matched"))
                        else "DEFERRED_PROCESS_IDENTITY_UNCERTAIN"
                    )
                    receipt["collect_outcome"] = "incomplete"
                    return
                receipt["alive_at_collect"] = False
                receipt["stopped_cleanly"] = True
                prior_fault = (active.get("daemon_runtime_clean") is False) or bool(active.get("daemon_log_lost"))
                receipt["effective_runtime_clean"] = not prior_fault

                # Already proven stock OR never attempted install -> safe to clear custody regardless of im state!
                if active["mlv2_stock_verified"]:
                    active_path.unlink()
                    receipt["active_state_cleared"] = True
                    receipt["cleanup"] = "GONE"
                    if (not active["daemon_started"]) and (not active["daemon_collected"]) and (not prior_fault):
                        receipt["prelaunch_recovered"] = True
                        receipt["collect_outcome"] = "prelaunch_recovered"
                    else:
                        receipt["collect_outcome"] = (
                            "uninstalled_with_prior_runtime_fault" if prior_fault else "uninstalled_clean"
                        )
                    _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                    return

                mlv2_possibly_installed = active["install_attempted"] or active["mlv2_installed"]
                if not mlv2_possibly_installed:
                    active_path.unlink()
                    receipt["active_state_cleared"] = True
                    receipt["stale_active_recovered"] = True
                    receipt["cleanup"] = "DIR_ALREADY_ABSENT"
                    receipt["collect_outcome"] = (
                        "recovered_with_prior_runtime_fault" if prior_fault else "stale_recovered"
                    )
                    _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                    return

                if im_state == "uncertain":
                    receipt["cleanup"] = "DEFERRED_IM_IDENTITY_UNCERTAIN"
                    receipt["collect_outcome"] = "incomplete"
                    return
                if im_state == "verified_absent":
                    active_path.unlink()
                    receipt["active_state_cleared"] = True
                    receipt["im_verified_absent"] = True
                    receipt["cleanup"] = "DIR_ALREADY_ABSENT"
                    receipt["collect_outcome"] = (
                        "recovered_with_prior_runtime_fault" if prior_fault else "im_absent_recovered"
                    )
                    _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                    return
                # im_state == "verified_live"
                im_replaced = (
                    im_obs["pid"] != active["im_pid"] or
                    im_obs["starttime"] != active["im_starttime"]
                )
                receipt["im_process_replaced"] = im_replaced
                if not im_replaced:
                    receipt["cleanup"] = "MLV2_DIR_MISSING_WHILE_SAME_IM_LIVE"
                    receipt["collect_outcome"] = "incomplete"
                    return
                active_path.unlink()
                receipt["active_state_cleared"] = True
                receipt["process_replaced_recovered"] = True
                receipt["cleanup"] = "DIR_ALREADY_ABSENT"
                receipt["collect_outcome"] = (
                    "recovered_with_prior_runtime_fault" if prior_fault else "process_replaced_recovered"
                )
                _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                return

            # Step A: Stop daemon+ring (if nonce dir still present), durably persist logs, checkpoint BEFORE rm -rf.
            daemon_collected_now = False
            daemon_dir_gone = (daemon_dir_state == "DIR_GONE")
            summary: dict = {}
            orig_status = active["status"]
            is_prelaunch = not active["daemon_started"]
            prior_sd_disabled = bool(active["sd_disabled_confirmed"])
            mlv2_possibly_installed = active["install_attempted"] or active["mlv2_installed"]
            prior_log_durable = (
                bool(active.get("saved_log_path")) and
                Path(active["saved_log_path"]).is_file()
            )
            daemon_runtime_clean_now: bool | None = None

            def _hydrate_prior_saved_log() -> bool | None:
                saved_p = Path(active["saved_log_path"])
                saved_txt = saved_p.read_text(encoding="utf-8")
                saved_sum = parse_daemon_log(saved_txt)
                saved_diag = compute_log_diagnostics(saved_sum)
                receipt["saved_log_path"] = str(saved_p)
                receipt["log_retrieved"] = bool(saved_txt.strip() and saved_sum.get("boot") is not None)
                receipt["log_persisted"] = True
                receipt["summary"] = saved_sum
                receipt["diagnostics"] = saved_diag
                return bool(saved_diag["runtime_clean"])

            if daemon_dir_state == "DIR_OK":
                s7_obs = observe_live_s7_processes(session, remote_daemon, remote_ring)
                receipt["s7_process_observation"] = s7_obs
                live_d, live_r = s7_obs["live_d"], s7_obs["live_r"]
                receipt["live_daemon_pids_at_collect"] = live_d
                receipt["live_ring_pids_at_collect"] = live_r

                pid_raw, pid_rc = session.command(
                    f"if [ -f {remote_pid} ] && [ ! -L {remote_pid} ]; then /bin/busybox cat {remote_pid}; fi",
                    allowed=(0, 1),
                )
                pid_txt = pid_raw.decode("ascii", "replace").strip() if pid_rc == 0 else ""
                receipt["pid_file_value"] = pid_txt

                alive = False
                ident = None
                if expected_pid is not None:
                    ident = verify_live_daemon_identity(session, expected_pid, remote_daemon, expected_starttime)
                    receipt["daemon_identity_at_collect"] = ident
                    alive = (ident["state"] == "matched")
                    if ident["state"] == "proven_different":
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
                        alive = (ident["state"] == "matched")
                        if ident["state"] in ("matched", "uncertain"):
                            expected_pid = cand_pid
                            if ident["stat"] is not None:
                                expected_starttime = ident["stat"]["starttime"]

                daemon_uncertain = (
                    (not s7_obs["proc_ok"]) or
                    s7_obs["scan_malformed"] or
                    bool(s7_obs["unread_pids"]) or
                    (ident is not None and ident["state"] == "uncertain")
                )
                receipt["daemon_identity_uncertain"] = daemon_uncertain
                receipt["alive_at_collect"] = bool(alive or live_d or live_r or daemon_uncertain)

                if (
                    alive or live_d or live_r or daemon_uncertain or
                    (active["launch_attempted"] and not active["daemon_started"])
                ):
                    stopped, rem_d, rem_r, stop_obs = request_stop_via_file(
                        session, directory, remote_daemon, remote_ring,
                        expected_pid=expected_pid,
                        expected_starttime=expected_starttime,
                    )
                    receipt["stopped_cleanly"] = stopped
                    receipt["live_daemon_pids_after_stop"] = rem_d
                    receipt["live_ring_pids_after_stop"] = rem_r
                    receipt["stop_observation"] = stop_obs
                else:
                    receipt["stopped_cleanly"] = True
                    receipt["live_daemon_pids_after_stop"] = []
                    receipt["live_ring_pids_after_stop"] = []

                log_state = inspect_file_state(session, remote_log)
                receipt["remote_log_state"] = log_state
                log_text = ""
                log_read_ok = False
                if log_state == "FILE_OK":
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
                diag = compute_log_diagnostics(summary)
                receipt["diagnostics"] = diag

                _snapshot_optional_mlv2_artifacts(session, receipt, log_out_dir)

                has_valid_log = log_read_ok and bool(log_text.strip()) and summary.get("boot") is not None
                readable_non_boot_log = (log_state == "FILE_OK") and log_read_ok and (not has_valid_log)
                read_error = (log_state == "FILE_BAD") or (log_state == "FILE_OK" and not log_read_ok)
                missing_log_after_start = (log_state == "FILE_ABSENT") and active["daemon_started"] and (not prior_log_durable)
                receipt["log_retrieved"] = has_valid_log

                if not receipt.get("stopped_cleanly"):
                    if log_read_ok and log_text:
                        saved = persist_named_artifact_atomic(
                            log_text, log_out_dir, receipt["utc"], receipt["nonce"], "daemon.log"
                        )
                        receipt["saved_log_path"] = str(saved)
                        receipt["log_persisted"] = True
                    receipt["cleanup"] = (
                        "DEFERRED_PROCESS_STILL_ALIVE"
                        if (receipt.get("live_daemon_pids_after_stop") or receipt.get("live_ring_pids_after_stop") or alive)
                        else "DEFERRED_PROCESS_IDENTITY_UNCERTAIN"
                    )
                    receipt["collect_outcome"] = "incomplete"
                    return

                # Only defer on genuine I/O or bad-file read failure; readable BOOT-less or absent logs proceed to Step B as faults!
                if read_error and not prior_log_durable:
                    receipt["cleanup"] = "DEFERRED_LOG_READ_FAILED"
                    receipt["collect_outcome"] = "incomplete"
                    return

                saved_log_path_str = active.get("saved_log_path")
                if log_read_ok and (log_text or is_prelaunch or readable_non_boot_log):
                    saved = persist_named_artifact_atomic(
                        log_text, log_out_dir, receipt["utc"], receipt["nonce"], "daemon.log"
                    )
                    saved_log_path_str = str(saved)
                    receipt["saved_log_path"] = saved_log_path_str
                    receipt["log_persisted"] = True
                elif prior_log_durable:
                    receipt["saved_log_path"] = saved_log_path_str
                    receipt["log_persisted"] = True
                else:
                    receipt["log_persisted"] = False

                if has_valid_log:
                    daemon_runtime_clean_now = bool(diag["runtime_clean"])
                    card_source = summary
                elif readable_non_boot_log:
                    receipt["log_missing_boot"] = True
                    if active["daemon_started"] or bool(log_text.strip()):
                        daemon_runtime_clean_now = False
                    card_source = saved_log_path_str
                elif prior_log_durable:
                    saved_clean = _hydrate_prior_saved_log()
                    daemon_runtime_clean_now = _latch_runtime_clean(active.get("daemon_runtime_clean"), saved_clean)
                    card_source = saved_log_path_str
                elif missing_log_after_start:
                    receipt["daemon_log_missing_in_dir"] = True
                    daemon_runtime_clean_now = False

                # Checkpoint 1 (BEFORE rm -rf of nonce dir): preserve monotonic lifecycle + fault flags and valid status.
                cp1_has_log = bool(has_valid_log or prior_log_durable or readable_non_boot_log)
                if cp1_has_log:
                    cp1_status = "daemon_log_persisted"
                elif missing_log_after_start:
                    cp1_status = (
                        "mlv2_disabled_pending_reboot_or_uninstall"
                        if (mlv2_possibly_installed and not active["mlv2_stock_verified"])
                        else ("mlv2_stock_verified" if active["mlv2_stock_verified"] else "daemon_log_persisted")
                    )
                else:
                    cp1_status = orig_status
                active = dict(
                    active,
                    status=cp1_status,
                    install_attempted=mlv2_possibly_installed,
                    mlv2_installed=active["mlv2_installed"],
                    daemon_log_lost=bool(active["daemon_log_lost"] or missing_log_after_start),
                    daemon_pid=None,
                    daemon_starttime=None,
                    saved_log_path=saved_log_path_str,
                    saved_mod_loader_log_path=receipt.get("saved_mod_loader_log_path", active.get("saved_mod_loader_log_path")),
                    saved_precap_cfg_path=receipt.get("saved_precap_cfg_path", active.get("saved_precap_cfg_path")),
                    daemon_runtime_clean=_latch_runtime_clean(active.get("daemon_runtime_clean"), daemon_runtime_clean_now),
                )
                replace_active_state_atomic(active, active_path)

                daemon_cleanup = remove_ram_dir_verified(session, directory)
                receipt["daemon_cleanup"] = daemon_cleanup
                if daemon_cleanup != "GONE":
                    receipt["cleanup"] = "DEFERRED_DAEMON_DIR_REMOVE_FAILED"
                    receipt["collect_outcome"] = "incomplete"
                    return
                daemon_dir_gone = True
                daemon_collected_now = bool(cp1_has_log or missing_log_after_start)

                # Checkpoint 2 (IMMEDIATELY AFTER nonce dir is GONE, BEFORE guard calls or card check):
                next_status = active["status"]
                if mlv2_possibly_installed and not active["mlv2_stock_verified"]:
                    next_status = "mlv2_disabled_pending_reboot_or_uninstall"
                active = dict(
                    active,
                    status=next_status,
                    daemon_collected=bool(active["daemon_collected"] or cp1_has_log),
                )
                replace_active_state_atomic(active, active_path)
            else:
                # daemon_dir_state == "DIR_GONE" while mlv2 or mods still exist (non-reboot!).
                s7_obs = observe_live_s7_processes(session, remote_daemon, remote_ring)
                receipt["s7_process_observation"] = s7_obs
                receipt["live_daemon_pids_at_collect"] = s7_obs["live_d"]
                receipt["live_ring_pids_at_collect"] = s7_obs["live_r"]
                id_clear = True
                if expected_pid is not None:
                    ident = verify_live_daemon_identity(session, expected_pid, remote_daemon, expected_starttime)
                    receipt["daemon_identity_at_collect"] = ident
                    id_clear = ident["state"] in ("proven_gone", "proven_different")
                if not s7_obs["certain_clear"] or not id_clear:
                    receipt["alive_at_collect"] = True
                    receipt["stopped_cleanly"] = False
                    receipt["cleanup"] = (
                        "DEFERRED_PROCESS_STILL_ALIVE"
                        if (s7_obs["live_d"] or s7_obs["live_r"] or (expected_pid is not None and receipt.get("daemon_identity_at_collect", {}).get("state") == "matched"))
                        else "DEFERRED_PROCESS_IDENTITY_UNCERTAIN"
                    )
                    receipt["collect_outcome"] = "incomplete"
                    return
                receipt["alive_at_collect"] = False
                receipt["stopped_cleanly"] = True
                receipt["daemon_cleanup"] = "ALREADY_GONE"
                _snapshot_optional_mlv2_artifacts(session, receipt, log_out_dir)

                if prior_log_durable and (not active["daemon_collected"] or not prior_sd_disabled):
                    saved_clean = _hydrate_prior_saved_log()
                    daemon_runtime_clean_now = _latch_runtime_clean(active.get("daemon_runtime_clean"), saved_clean)
                    active = dict(
                        active,
                        status=(
                            "mlv2_disabled_pending_reboot_or_uninstall"
                            if (mlv2_possibly_installed and not active["mlv2_stock_verified"])
                            else active["status"]
                        ),
                        daemon_collected=True,
                        daemon_runtime_clean=_latch_runtime_clean(active.get("daemon_runtime_clean"), daemon_runtime_clean_now),
                    )
                    replace_active_state_atomic(active, active_path)
                elif active["daemon_started"] and not active["daemon_collected"] and not prior_log_durable:
                    # Non-reboot unexpected disappearance of a running session's nonce dir:
                    # latch fault durably AND transition status away from "running" so custody remains valid on crash!
                    receipt["daemon_dir_missing_unexpectedly"] = True
                    daemon_runtime_clean_now = False
                    lost_status = (
                        "mlv2_disabled_pending_reboot_or_uninstall"
                        if (mlv2_possibly_installed and not active["mlv2_stock_verified"])
                        else ("mlv2_stock_verified" if active["mlv2_stock_verified"] else "daemon_log_persisted")
                    )
                    active = dict(
                        active,
                        status=lost_status,
                        daemon_log_lost=True,
                        daemon_runtime_clean=False,
                        daemon_pid=None,
                        daemon_starttime=None,
                    )
                    replace_active_state_atomic(active, active_path)

            # Effective runtime cleanliness spans BOTH current collection AND all prior latched faults!
            effective_runtime_clean = (
                (daemon_runtime_clean_now is not False) and
                (active.get("daemon_runtime_clean") is not False) and
                (not active.get("daemon_log_lost")) and
                (not receipt.get("daemon_dir_missing_unexpectedly"))
            )
            receipt["effective_runtime_clean"] = effective_runtime_clean

            def _pick_outcome(clean_now: str, fault_now: str, clean_retry: str, fault_retry: str) -> str:
                if daemon_collected_now:
                    return clean_now if effective_runtime_clean else fault_now
                return clean_retry if effective_runtime_clean else fault_retry

            # Helper for crash-resumable final removal AFTER stock proof (Checkpoint 3 -> rm mods -> rm mlv2 -> unlink).
            def _finish_stock_cleanup(clean_now: str, fault_now: str, clean_retry: str, fault_retry: str, *, mark_prelaunch: bool = False):
                nonlocal active
                active = dict(
                    active,
                    status="mlv2_stock_verified",
                    mlv2_installed=False,
                    mlv2_stock_verified=True,
                    daemon_pid=None,
                    daemon_starttime=None,
                    daemon_runtime_clean=_latch_runtime_clean(active.get("daemon_runtime_clean"), daemon_runtime_clean_now),
                )
                replace_active_state_atomic(active, active_path)
                # Remove mods FIRST, mlv2 SECOND so mlv2_guard.elf remains until last possible moment!
                mods_rm = remove_ram_dir_verified(session, REMOTE_MODS_DIR)
                mlv2_rm = remove_ram_dir_verified(session, REMOTE_MLV2_DIR)
                receipt["mods_cleanup"] = mods_rm
                receipt["mlv2_cleanup"] = mlv2_rm
                if mlv2_rm == "GONE" and mods_rm == "GONE" and daemon_dir_gone:
                    active_path.unlink()
                    receipt["active_state_cleared"] = True
                    receipt["cleanup"] = "GONE"
                    if mark_prelaunch and is_prelaunch and effective_runtime_clean:
                        receipt["prelaunch_recovered"] = True
                        receipt["collect_outcome"] = "prelaunch_recovered"
                    else:
                        receipt["collect_outcome"] = _pick_outcome(clean_now, fault_now, clean_retry, fault_retry)
                else:
                    receipt["cleanup"] = "DEFERRED_POST_STOCK_DIR_REMOVE_FAILED"
                    receipt["collect_outcome"] = "incomplete"
                _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)

            # Step B0: If Checkpoint 3 (mlv2_stock_verified) was already persisted on an earlier interrupted collect,
            # finish removing any surviving mods/mlv2 directories without needing mlv2_guard.elf again!
            if active["mlv2_stock_verified"]:
                _finish_stock_cleanup(
                    "collected_uninstalled", "collected_runtime_fault_uninstalled",
                    "uninstalled_clean", "uninstalled_with_prior_runtime_fault",
                    mark_prelaunch=(is_prelaunch and not active["daemon_collected"] and not daemon_collected_now and effective_runtime_clean),
                )
                return

            # Step B1: Handle uncertain or verified_absent im.elf.
            if im_state == "uncertain":
                if mlv2_dir_state == "DIR_OK":
                    receipt["sd_disabled_written"] = write_sd_disabled_marker(session)
                receipt["cleanup"] = "DEFERRED_IM_IDENTITY_UNCERTAIN"
                receipt["collect_outcome"] = "incomplete"
                _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                return

            if im_state == "verified_absent":
                mods_rm = remove_ram_dir_verified(session, REMOTE_MODS_DIR)
                mlv2_rm = remove_ram_dir_verified(session, REMOTE_MLV2_DIR)
                receipt["mods_cleanup"] = mods_rm
                receipt["mlv2_cleanup"] = mlv2_rm
                if mlv2_rm == "GONE" and mods_rm == "GONE" and daemon_dir_gone:
                    active_path.unlink()
                    receipt["active_state_cleared"] = True
                    receipt["cleanup"] = "GONE"
                    if daemon_collected_now:
                        receipt["collect_outcome"] = _pick_outcome(
                            "collected_stock", "collected_runtime_fault_stock",
                            "im_absent_recovered", "recovered_with_prior_runtime_fault",
                        )
                    elif is_prelaunch and not active["daemon_collected"] and effective_runtime_clean:
                        receipt["prelaunch_recovered"] = True
                        receipt["collect_outcome"] = "prelaunch_recovered"
                    else:
                        receipt["im_verified_absent"] = True
                        receipt["collect_outcome"] = (
                            "im_absent_recovered" if effective_runtime_clean else "recovered_with_prior_runtime_fault"
                        )
                else:
                    receipt["cleanup"] = "INCOMPLETE_IM_ABSENT"
                    receipt["collect_outcome"] = "incomplete"
                _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                return

            # Step B2: im_state == "verified_live"
            live_im_pid = im_obs["pid"]
            live_im_replaced = (
                live_im_pid != active["im_pid"] or
                im_obs["starttime"] != active["im_starttime"]
            )
            receipt["im_process_replaced"] = live_im_replaced
            expected_vb = None if live_im_replaced else active.get("view_bias")

            # Re-verify pinned remote guard & request immediately before check.
            pin_ok, chk_pins, chk, chk_rc, chk_txt = run_pinned_guard_command(
                session, "check", REMOTE_REQ,
                guard_bytes=sealed_guard_bytes, guard_md5=sealed_guard_md5,
                arg_bytes=sealed_req_bytes, arg_md5=sealed_req_md5,
            )
            receipt["guard_pins_at_collect"] = chk_pins
            if not pin_ok:
                # Re-read custody under lock: if install was NEVER attempted (pending_upload), safe to clean partial dirs!
                fresh_active = load_active_state(active_path)
                if (
                    not fresh_active["install_attempted"] and
                    not fresh_active["mlv2_installed"] and
                    chk_pins["guard"].get("state") != "FILE_BAD" and
                    chk_pins["arg"].get("state") != "FILE_BAD"
                ):
                    mods_rm = remove_ram_dir_verified(session, REMOTE_MODS_DIR)
                    mlv2_rm = remove_ram_dir_verified(session, REMOTE_MLV2_DIR)
                    receipt["mods_cleanup"] = mods_rm
                    receipt["mlv2_cleanup"] = mlv2_rm
                    if mlv2_rm == "GONE" and mods_rm == "GONE" and daemon_dir_gone:
                        active_path.unlink()
                        receipt["active_state_cleared"] = True
                        receipt["prelaunch_recovered"] = effective_runtime_clean
                        receipt["cleanup"] = "GONE"
                        receipt["collect_outcome"] = (
                            "prelaunch_recovered" if effective_runtime_clean else "recovered_with_prior_runtime_fault"
                        )
                    else:
                        receipt["cleanup"] = "INCOMPLETE_CLEANUP"
                        receipt["collect_outcome"] = "incomplete"
                    _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                    return
                if mlv2_dir_state == "DIR_OK":
                    receipt["sd_disabled_written"] = write_sd_disabled_marker(session)
                receipt["cleanup"] = "DEFERRED_GUARD_PIN_MISMATCH"
                receipt["collect_outcome"] = "incomplete"
                _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                return

            receipt["guard_check_at_collect"] = dict(rc=chk_rc, output=chk_txt, parsed=chk)

            # Subcase B2a: Verified stock state -> Checkpoint 3 + clean mods then mlv2.
            if guard_check_matches(
                chk, chk_rc,
                expected_pid=live_im_pid,
                expected_hooks="stock",
                expected_rects="stock",
                expected_shim="zero",
                expected_view_bias=expected_vb,
            ):
                _finish_stock_cleanup(
                    "collected_stock", "collected_runtime_fault_stock",
                    "uninstalled_clean", "uninstalled_with_prior_runtime_fault",
                    mark_prelaunch=(is_prelaunch and not daemon_collected_now and not active["daemon_collected"] and effective_runtime_clean),
                )
                return

            # Subcase B2b: Verified active mlv2 v2 hooks/rects/shim.
            if guard_check_matches(
                chk, chk_rc,
                expected_pid=live_im_pid,
                expected_hooks="v2",
                expected_rects="patched",
                expected_shim="shim",
                expected_view_bias=expected_vb,
            ):
                sd_dis_ok = write_sd_disabled_marker(session)
                receipt["sd_disabled_written"] = sd_dis_ok
                require(sd_dis_ok, "Failed to verify /tmp_network/mlv2/sd-disabled after write")

                sd_stop_state = inspect_file_state(session, REMOTE_SD_STOPPED)
                receipt["sd_stopped_state"] = sd_stop_state
                if sd_stop_state == "FILE_OK":
                    # Re-verify remote guard & request pins immediately before uninstall!
                    un_pin_ok, un_pins, un, un_rc, un_txt = run_pinned_guard_command(
                        session, "uninstall", REMOTE_REQ,
                        guard_bytes=sealed_guard_bytes, guard_md5=sealed_guard_md5,
                        arg_bytes=sealed_req_bytes, arg_md5=sealed_req_md5,
                        timeout=20,
                    )
                    receipt["guard_uninstall"] = dict(pins_ok=un_pin_ok, pins=un_pins, rc=un_rc, output=un_txt, parsed=un)
                    if not un_pin_ok:
                        receipt["cleanup"] = "DEFERRED_GUARD_PIN_MISMATCH"
                        receipt["collect_outcome"] = "incomplete"
                        _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                        return
                    if guard_uninstall_matches(
                        un, un_rc,
                        expected_pid=live_im_pid,
                        expected_view_bias=chk["view_bias"],
                    ):
                        # Re-verify remote guard & request pins immediately before post-uninstall check!
                        pu_pin_ok, pu_pins, post_un, post_un_rc, post_un_txt = run_pinned_guard_command(
                            session, "check", REMOTE_REQ,
                            guard_bytes=sealed_guard_bytes, guard_md5=sealed_guard_md5,
                            arg_bytes=sealed_req_bytes, arg_md5=sealed_req_md5,
                        )
                        receipt["guard_check_after_uninstall"] = dict(
                            pins_ok=pu_pin_ok, pins=pu_pins, rc=post_un_rc, output=post_un_txt, parsed=post_un
                        )
                        if not pu_pin_ok:
                            receipt["cleanup"] = "DEFERRED_GUARD_PIN_MISMATCH"
                            receipt["collect_outcome"] = "incomplete"
                            _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                            return
                        if guard_check_matches(
                            post_un, post_un_rc,
                            expected_pid=live_im_pid,
                            expected_hooks="stock",
                            expected_rects="stock",
                            expected_shim="zero",
                            expected_view_bias=chk["view_bias"],
                        ):
                            _finish_stock_cleanup(
                                "collected_uninstalled", "collected_runtime_fault_uninstalled",
                                "uninstalled_clean", "uninstalled_with_prior_runtime_fault",
                            )
                            return
                    updated = dict(
                        active,
                        status="mlv2_disabled_pending_reboot_or_uninstall",
                        install_attempted=True,
                        mlv2_installed=True,
                        sd_disabled_confirmed=True,
                        view_bias=chk["view_bias"],
                        daemon_collected=bool(active["daemon_collected"] or daemon_collected_now),
                        daemon_pid=None,
                        daemon_starttime=None,
                        daemon_runtime_clean=_latch_runtime_clean(active.get("daemon_runtime_clean"), daemon_runtime_clean_now),
                    )
                    replace_active_state_atomic(updated, active_path)
                    receipt["cleanup"] = "MLV2_UNINSTALL_DEFERRED_BUSY"
                    receipt["collect_outcome"] = "mlv2_uninstall_busy"
                    _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                    return

                # sd-stopped is absent (or bad): NEVER fabricate sd-stopped and NEVER delete /tmp_network/mlv2!
                updated = dict(
                    active,
                    status="mlv2_disabled_pending_reboot_or_uninstall",
                    install_attempted=True,
                    mlv2_installed=True,
                    sd_disabled_confirmed=True,
                    view_bias=chk["view_bias"],
                    daemon_collected=bool(active["daemon_collected"] or daemon_collected_now),
                    daemon_pid=None,
                    daemon_starttime=None,
                    daemon_runtime_clean=_latch_runtime_clean(active.get("daemon_runtime_clean"), daemon_runtime_clean_now),
                )
                replace_active_state_atomic(updated, active_path)
                receipt["cleanup"] = "MLV2_DISABLED_AWAITING_REBOOT_OR_MENU"
                if (
                    receipt.get("daemon_dir_missing_unexpectedly") or
                    active.get("daemon_log_lost") or
                    sd_stop_state != "FILE_ABSENT"
                ):
                    receipt["collect_outcome"] = "incomplete"
                elif daemon_collected_now or (not prior_sd_disabled and daemon_dir_gone and (active["daemon_collected"] or is_prelaunch)):
                    receipt["collect_outcome"] = (
                        "collected_mlv2_disabled" if effective_runtime_clean else "collected_runtime_fault_mlv2_disabled"
                    )
                else:
                    receipt["collect_outcome"] = "mlv2_waiting_sd_stopped"
                _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
                return

            # Subcase B2c: Unexpected hook/rect/shim state or invalid guard output -> fail closed.
            receipt["sd_disabled_written"] = write_sd_disabled_marker(session)
            receipt["cleanup"] = "DEFERRED_UNEXPECTED_MLV2_STATE"
            receipt["collect_outcome"] = "incomplete"
            _run_card_check_nonfatal(receipt, card_root, card_source, allow_empty_card=allow_empty_card)
        finally:
            if enable_attempted:
                try:
                    with usb.deadline(8):
                        camera.setTerminalEnable(False)
                    receipt["terminal_disable_requested"] = True
                except Exception as err:
                    receipt["terminal_disable_error"] = f"{type(err).__name__}: {err}"
            if hasattr(camera, "dev") and hasattr(camera.dev, "packet_log"):
                receipt["packets"] = list(camera.dev.packet_log)


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
    if not bool(receipt.get("stopped_cleanly")):
        return False
    if (
        receipt.get("effective_runtime_clean") is False or
        receipt.get("prior_daemon_runtime_clean") is False or
        receipt.get("prior_daemon_log_lost") is True or
        receipt.get("daemon_dir_missing_unexpectedly") is True
    ):
        return False
    if receipt.get("card_requested"):
        if "card_check" not in receipt or not bool(receipt["card_check"].get("all_ok")):
            return False
    outcome = receipt.get("collect_outcome")
    if outcome in ("process_replaced_recovered", "im_absent_recovered", "stale_recovered"):
        if receipt.get("cleanup") == "DIR_ALREADY_ABSENT":
            return bool(receipt.get("active_state_cleared"))
        if outcome == "im_absent_recovered" and receipt.get("cleanup") == "GONE":
            return bool(receipt.get("active_state_cleared"))
        return False
    if outcome == "prelaunch_recovered":
        return (
            bool(receipt.get("active_state_cleared")) and
            bool(receipt.get("prelaunch_recovered")) and
            receipt.get("cleanup") == "GONE"
        )
    if outcome == "uninstalled_clean":
        return bool(receipt.get("active_state_cleared")) and receipt.get("cleanup") == "GONE"
    if outcome in ("collected_uninstalled", "collected_stock"):
        return (
            bool(receipt.get("active_state_cleared")) and
            receipt.get("cleanup") == "GONE" and
            bool(receipt.get("log_retrieved")) and
            bool(receipt.get("log_persisted")) and
            bool(receipt.get("diagnostics", {}).get("runtime_clean"))
        )
    if outcome == "collected_mlv2_disabled":
        daemon_ok = receipt.get("daemon_cleanup") in ("GONE", "ALREADY_GONE")
        prelaunch_ok = (not receipt.get("active_session", {}).get("daemon_started", True)) and daemon_ok
        log_ok = (
            bool(receipt.get("log_retrieved")) and
            bool(receipt.get("log_persisted")) and
            bool(receipt.get("diagnostics", {}).get("runtime_clean"))
        )
        return (
            daemon_ok and
            bool(receipt.get("sd_disabled_written")) and
            receipt.get("cleanup") == "MLV2_DISABLED_AWAITING_REBOOT_OR_MENU" and
            (log_ok or prelaunch_ok)
        )
    return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Stage 7.2 volatile RAM-only live camera test runner (mlv2 + PreCapture.mod + daemon + ring)."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--start", action="store_true", help="Upload sealed Stage 7.1 artifacts to RAM, install mlv2, and start daemon")
    group.add_argument("--collect", action="store_true", help="Stop daemon, persist logs, disable mlv2, and uninstall if sd-stopped is present")
    group.add_argument("--check-card-only", action="store_true", help="Verify PC*.JPG against a saved daemon.log without USB")
    parser.add_argument("--duration-sec", type=int, default=600, help="Auto-exit watchdog timeout in seconds (30..3600, default 600)")
    parser.add_argument("--after", type=int, default=0, help="Post-capture frames M (0=hold-driven up to --post-max, or 1..64; default 0)")
    parser.add_argument("--burst-cap", type=int, default=24, help="Phase-1 continuous S2 burst cap C_burst (14..60, default 24)")
    parser.add_argument("--post-max", type=int, default=48, help="Safety ceiling for hold-driven post frames (1..96, default 48)")
    parser.add_argument("--backlog-cap", type=int, default=96, help="Hard upstream backlog safety ceiling (24..128, default 96)")
    parser.add_argument("--debounce-ms", type=int, default=100, help="Half-press debounce in ms (0..2000, default 100)")
    parser.add_argument("--focus-ms", type=int, default=300, help="AF observe wait in ms (100..1500, default 300)")
    parser.add_argument("--card", default=None, help="Optional read-only SD card mount path to verify PC*.JPG")
    parser.add_argument("--log", default=None, help="Saved daemon.log path for --check-card-only")
    parser.add_argument("--allow-empty", action="store_true", help="Allow zero RING_FILE entries in card verification")
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
        probe_kind="stage7-2-ram-only-test",
        commands=[],
        steps=[],
    )

    try:
        with custody_lock(ACTIVE_STATE):
            artifacts, manifest = load_and_verify_sealed_artifacts()
            receipt["stage7_1_manifest_stage"] = manifest["stage"]
            receipt["stage7_1_total_artifact_bytes"] = manifest["total_artifact_bytes"]
            receipt["core_sha256"] = manifest["artifacts"]["core"]["sha256"]
            receipt["req_sha256"] = manifest["artifacts"]["request"]["sha256"]
            receipt["guard_sha256"] = manifest["artifacts"]["guard"]["sha256"]
            receipt["precap_mod_sha256"] = manifest["artifacts"]["precap_mod"]["sha256"]
            receipt["daemon_template_sha256"] = manifest["artifacts"]["daemon"]["sha256"]
            receipt["ring_template_sha256"] = manifest["artifacts"]["ring"]["sha256"]

            configured_daemon = None
            configured_ring = None
            if args.start:
                require(30 <= args.duration_sec <= 3600, "--duration-sec must be 30..3600")
                configured_daemon = configure_daemon(
                    artifacts["daemon"],
                    manifest,
                    duration_ms=args.duration_sec * 1000,
                    poll_ms=50,
                    heartbeat_ms=2000,
                    max_log_bytes=131072,
                    daemonize=True,
                    after=args.after,
                    backlog_cap=args.backlog_cap,
                    debounce_ms=args.debounce_ms,
                    focus_ms=args.focus_ms,
                    burst_cap=args.burst_cap,
                    post_max=args.post_max,
                    nonce=nonce,
                )
                configured_ring = configure_ring(artifacts["ring"], manifest, nonce=nonce)
                receipt["daemon_sha256"] = builder.sha(configured_daemon)
                receipt["ring_sha256"] = builder.sha(configured_ring)
                receipt["duration_ms"] = args.duration_sec * 1000
                receipt["after"] = args.after
                receipt["burst_cap"] = args.burst_cap
                receipt["post_max"] = args.post_max
                receipt["backlog_cap"] = args.backlog_cap
                receipt["debounce_ms"] = args.debounce_ms
                receipt["focus_ms"] = args.focus_ms
            else:
                # Fail fast only when no active session exists; --card runs non-fatally AFTER Step B teardown.
                load_active_state(ACTIVE_STATE)

            usb.connect(
                receipt,
                diagnostic=(
                    (lambda cam, rec: do_start(
                        cam, rec, artifacts, manifest, configured_daemon, configured_ring,
                        duration_ms=args.duration_sec * 1000,
                        after=args.after,
                        burst_cap=args.burst_cap,
                        post_max=args.post_max,
                        backlog_cap=args.backlog_cap,
                        debounce_ms=args.debounce_ms,
                        focus_ms=args.focus_ms,
                        active_path=ACTIVE_STATE,
                        log_out_dir=OUT_DIR,
                    ))
                    if args.start
                    else (lambda cam, rec: do_collect(
                        cam, rec, artifacts, manifest,
                        active_path=ACTIVE_STATE,
                        log_out_dir=OUT_DIR,
                        card_root=args.card,
                        allow_empty_card=args.allow_empty,
                    ))
                ),
                gate_factory=Stage7Gate,
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
            f"runtime_clean={receipt.get('effective_runtime_clean')} "
            f"stopped_cleanly={receipt.get('stopped_cleanly')} cleanup={receipt.get('cleanup')} "
            f"saved_log={receipt.get('saved_log_path')} "
            f"saved_mod_log={receipt.get('saved_mod_loader_log_path')} "
            f"saved_cfg={receipt.get('saved_precap_cfg_path')} "
            f"r_runs={d.get('ring_start_count')} r_exits={d.get('ring_exit_count')} "
            f"r_files={d.get('ring_file_count')} fault={d.get('ring_fault_seen')} "
            f"unres={d.get('ring_unresolved_seen')} trunc={d.get('log_truncated')} "
            f"states={s.get('state_count')}",
            flush=True,
        )
        if receipt.get("collect_outcome") in (
            "collected_mlv2_disabled",
            "collected_runtime_fault_mlv2_disabled",
            "mlv2_waiting_sd_stopped",
        ):
            print(
                "NEXT_STEP: sd-disabled is active. Power-cycle the camera to clear 100% RAM, "
                "OR disconnect USB, open camera MENU once (restores 6 stock tabs and writes sd-stopped), "
                "reconnect USB and re-run --collect to complete live mlv2_guard uninstall.",
                flush=True,
            )

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
