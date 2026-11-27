#!/usr/bin/env python3
"""Stage 7.0 read-only collector for missing original DSC-RX100M7 (1.00) boot, recovery, and menu files.

Safety contract:
- Strictly model-locked to DSC-RX100M7 and build 29110_03.2021050601.
- Strictly read-only on the host protocol: blocks FileControl WRITE/DELETE, MemoryDump,
  HASP, Backup WRITE, and all non-allowlisted paths.
- Uses audited 32-byte chunked framed terminal commands (< 512 wire bytes).
- Validates BEFORE any shell content read (including /version.txt) that every ancestor
  directory of the 32-path allowlist is a non-symlink directory and /version.txt is a
  non-symlink regular file, verifies from live /proc/mounts that / and /usr are mounted
  read-only, and skips leaf symlinks (failing closed on readlink errors) so neither shell
  reads nor FileControl READ traverse symlinks into /setting or /cert.
- Validates every allowlisted path witness (exact 1 state per path, zero duplicates or
  contradictions, positive size <= 64 MiB, all 8 required Stage 7 paths present) and
  verifies BOTH terminal-disable packets (0x10 status 1 and 0x40 status 0) BEFORE
  sending any FileControl READ packet.
- Observes USB transport errors on both terminal toggle (0x40) and service stop
  (StopSenser vendorRequestOut across normal-driver, pre-gate service-driver, and
  post-gate service-driver cleanup paths) without letting PMCA suppress them.
- Verifies every downloaded file against on-camera byte size and MD5 (plus ELF magic for
  ELF binaries) before renaming from .partial, and removes .partial on any error or
  KeyboardInterrupt.
- Side-effect transparency and explicit CLI consent:
  `--connect` requires `--confirm-32-file-etools-and-history` before opening USB because:
  1) Sony libsencore.so FileControl READ may update /setting/.etools (4096 B) if present;
     up to 32 allowlisted paths may be read.
  2) BusyBox ash shell-history saving on this unit is unverified; HISTFILE=/dev/null
     is best-effort and does not prove absence of shell-history writes.
  3) StopSenser transport success does not confirm physical camera return to normal UI;
     the operator must confirm camera state physically.
- Never modifies evidence/** or any sealed Stage 5/6 files.
"""
import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import m7_probe as probe
import m7_terminal_repaint as terminal
from m7_terminal_check import PACKETS
from m7_terminal_steps import frame, read_ready

MODEL = "DSC-RX100M7"
BUILD = "29110_03.2021050601"
MAX_FILE_BYTES = 64 * 1024 * 1024
OUT_RECEIPT_DIR = ROOT / "work/stage7-persist"

TERM_DISABLE_P1 = (0x10, b"\x00\x00\xf1\x00\x00")
TERM_ENABLE_P1 = (0x10, b"\x00\x00\xf1\x00\x01")
TERM_DISABLE_P2 = (0x40, b"\x01\x06\x1f\x00\x00")
TERM_ENABLE_P2 = (0x40, b"\x01\x06\x1f\x00\x02")
STOP_SENSER_VENDOR_REQ = (1, 0xC800, 0x2855)

# Fixed read-only allowlist of 32 original M7 1.00 boot, recovery, libc, and menu/UI files.
# Zero user-private or /setting or /cert files are included.
PATHS = (
    "/version.txt",
    # Boot, init, recovery, filesystem, and glibc/loader chain
    "/sbin/init",
    "/lib/ld-2.11.2.so",
    "/lib/libc-2.11.2.so",
    "/lib/libdl-2.11.2.so",
    "/lib/libpthread-2.11.2.so",
    "/usr/bin/bootin.elf",
    "/usr/bin/change_mode.sh",
    "/usr/bin/sen.elf",
    "/usr/bin/launch_shell.elf",
    "/usr/bin/bk.elf",
    "/usr/bin/up.sh",
    "/usr/kmod/input.ko",
    "/usr/lib/libbackup.so",
    "/usr/lib/libBackupManager.so",
    "/usr/lib/libAK8975.so",
    "/usr/lib/libInfraFsys.so",
    "/usr/lib/libupdatertalk.so",
    "/usr/lib/libupdaterufp.so",
    # Native menu, caution, and UI resources
    "/usr/lib/CautionConfig.so",
    "/usr/lib/CautionRsrcConfig.so",
    "/usr/lib/ModelCautionConfig.so",
    "/usr/lib/viewUnified2.so",
    "/usr/lib/viewUnified4.so",
    "/usr/lib/viewUnified6.so",
    "/usr/share/app/viewGlobalMenu.uxc",
    "/usr/share/app/viewSettingMenu.uxc",
    "/usr/share/app/viewFnMenu.uxc",
    "/usr/share/app/string_english.uxc",
    "/usr/share/app/string_russian.uxc",
    "/usr/share/app/lang.uxb",
    "/usr/share/app/global.xdb",
)

# Every ancestor directory of PATHS in top-down order so intermediate symlinks are caught
# before any content read or witness command.
ANCESTOR_DIRS = tuple(
    sorted(
        {str(parent) for path in PATHS for parent in Path(path).parents if str(parent) != "/"},
        key=lambda s: (s.count("/"), s),
    )
)

# Minimum Stage 7 required files (build identity, core boot/loader/service chain,
# and both Stage 7 native menu inputs cited in STATE.md).
REQUIRED_PATHS = frozenset((
    "/version.txt",
    "/sbin/init",
    "/lib/ld-2.11.2.so",
    "/lib/libc-2.11.2.so",
    "/usr/bin/bootin.elf",
    "/usr/bin/sen.elf",
    "/usr/lib/CautionConfig.so",
    "/usr/lib/viewUnified2.so",
))

ELF_PATHS = frozenset(
    p for p in PATHS
    if p.endswith((".elf", ".so", ".ko")) or ".so." in p or p == "/sbin/init"
)

ANCESTOR_CHECK_CMD = (
    f"rc=0; for d in {' '.join(ANCESTOR_DIRS)}; do "
    'if [ -L "$d" ] || [ ! -d "$d" ]; then echo "ANC BAD $d"; rc=1; '
    'else echo "ANC OK $d"; fi; done; '
    'if [ -L /version.txt ] || [ ! -f /version.txt ]; then echo "ANC BAD /version.txt"; rc=1; '
    'else echo "ANC OK /version.txt"; fi; [ "$rc" -eq 0 ]'
)

INVENTORY_COMMANDS = (
    ("setup", "HISTFILE=/dev/null; export HISTFILE; ulimit -c 0 && umask 077", (0,)),
    ("mounts", "/bin/busybox cat /proc/mounts", (0,)),
    ("check_ancestors", ANCESTOR_CHECK_CMD, (0,)),
    ("version", "/bin/busybox cat /version.txt", (0,)),
    ("cmdline", "/bin/busybox cat /proc/cmdline", (0,)),
    ("partitions", "/bin/busybox cat /proc/partitions", (0,)),
    ("upm_bootmode", "/bin/busybox cat /proc/udm/upm_bootmode 2>/dev/null; true", (0,)),
    ("devs_and_input", "/bin/busybox ls -la /dev/nflasha* /dev/mmca* /proc/input 2>/dev/null; true", (0,)),
    ("ls_sbin_lib", "/bin/busybox ls -la /sbin /lib 2>/dev/null; true", (0,)),
    ("ls_setting", "/bin/busybox ls -laR /setting 2>/dev/null; true", (0,)),
    ("ls_etc_tmp", "/bin/busybox ls -laR /etc /tmp 2>/dev/null; true", (0,)),
    ("ls_system", "/bin/busybox ls -laR /system 2>/dev/null; true", (0,)),
    ("ls_usr_bin_kmod", "/bin/busybox ls -la /usr/bin /usr/kmod 2>/dev/null; true", (0,)),
    ("ls_usr_share_app", "/bin/busybox ls -la /usr/share/app 2>/dev/null; true", (0,)),
)


def encode_file_read_payload(path: str) -> bytes:
    if path not in PATHS:
        raise probe.ProbeError(f"Path not in Stage 7 read allowlist: {path!r}")
    raw = path.encode("ascii")
    padded = raw + b"\x00" * (4 - len(raw) % 4)
    return b"\x02\x00" + len(padded).to_bytes(2, "little") + padded


ALLOWED_FILE_READ_PAYLOADS = frozenset(encode_file_read_payload(p) for p in PATHS)


def build_checksum_commands(paths=PATHS, nonce="000000000000", start_index=len(INVENTORY_COMMANDS)):
    """Pack tagged per-file classification + wc -c + md5sum commands so every wire line stays < 512 bytes.

    Uses `rc=0; ... || rc=1; done; [ "$rc" -eq 0 ]` instead of `exit` so a failing command
    sets the step status nonzero without terminating the interactive camera ash session.
    Leaf symlinks are reported as `ST LINK <path> <target>` (propagating readlink errors via
    rc=1) and never followed. Ancestor directories are verified non-symlinks earlier.
    """
    cmds = []
    batch = []
    idx = start_index

    def make_cmd(items):
        joined = " ".join(items)
        return (
            f"rc=0; for p in {joined}; do "
            'if [ -L "$p" ]; then t=$(/bin/busybox readlink "$p") || rc=1; echo "ST LINK $p $t"; '
            'elif [ ! -e "$p" ]; then echo "ST MISS $p"; '
            'elif [ ! -f "$p" ]; then echo "ST NONREG $p"; '
            'else echo "ST REG $p"; '
            's=$(/bin/busybox wc -c "$p") || rc=1; echo "SZ $s"; '
            'm=$(/bin/busybox md5sum "$p") || rc=1; echo "MD $m"; '
            'fi; done; [ "$rc" -eq 0 ]'
        )

    for p in paths:
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", p) or ".." in p:
            raise ValueError(f"Unsafe path in allowlist: {p!r}")
        cand = batch + [p]
        cmd_str = make_cmd(cand)
        fits = False
        try:
            wire, _, _ = frame(cmd_str, idx, nonce)
            fits = len(wire) < 512
        except ValueError:
            fits = False
        if fits:
            batch = cand
        else:
            if not batch:
                raise ValueError(f"Single path exceeds terminal line limit: {p!r}")
            cmds.append((f"checksums_{len(cmds)}", make_cmd(batch), (0,)))
            idx += 1
            batch = [p]
            wire, _, _ = frame(make_cmd(batch), idx, nonce)
            if len(wire) >= 512:
                raise ValueError(f"Single path exceeds terminal line limit: {p!r}")
    if batch:
        cmds.append((f"checksums_{len(cmds)}", make_cmd(batch), (0,)))
    return cmds


def make_stop_transport_record():
    return dict(
        attempted=False,
        observed=False,
        transport_ok=False,
        camera_exit_confirmed=False,
        driver_class=None,
        error=None,
    )


def _record_stop_call(info: dict, driver, fn, args, kwargs):
    is_stop = len(args) >= 3 and tuple(args[:3]) == STOP_SENSER_VENDOR_REQ
    if is_stop:
        info["attempted"] = True
        info["observed"] = True
        info["transport_ok"] = False
        info["camera_exit_confirmed"] = False
        info["driver_class"] = type(driver).__name__
        info["error"] = None
    try:
        res = fn(*args, **kwargs)
    except BaseException as err:
        if is_stop:
            info["error"] = f"{type(err).__name__}: {err}"
        raise
    if is_stop:
        info["transport_ok"] = True
    return res


@contextlib.contextmanager
def observe_stop_senser(receipt: dict):
    """Observe SonySenserAuthDevice.stop() across ALL driver lifetimes (normal, pre-gate
    service, and post-gate service) without letting PMCA swallow GenericUsbException."""
    sys.path.insert(0, str(probe.PMCA))
    from pmca.usb.sony import SonySenserAuthDevice

    orig_stop = SonySenserAuthDevice.stop
    info = receipt.setdefault("service_stop_transport", make_stop_transport_record())

    def observed_stop(self):
        driver = getattr(self, "driver", None)
        orig_vro = getattr(driver, "vendorRequestOut", None)
        info["attempted"] = True
        info["driver_class"] = type(driver).__name__ if driver is not None else None
        if driver is None or not callable(orig_vro):
            info["observed"] = False
            info["transport_ok"] = False
            info["error"] = "driver has no callable vendorRequestOut"
            return orig_stop(self)

        # If Stage7CollectGate already wrapped this driver's vendorRequestOut for the same
        # receipt dict, call orig_stop directly so we don't double-wrap.
        if getattr(orig_vro, "_stage7_stop_info", None) is info:
            return orig_stop(self)

        def wrapped_vro(*args, **kwargs):
            return _record_stop_call(info, driver, orig_vro, args, kwargs)

        wrapped_vro._stage7_stop_info = info
        driver.vendorRequestOut = wrapped_vro
        try:
            return orig_stop(self)
        finally:
            if getattr(driver, "vendorRequestOut", None) is wrapped_vro:
                driver.vendorRequestOut = orig_vro

    SonySenserAuthDevice.stop = observed_stop
    try:
        yield
    finally:
        SonySenserAuthDevice.stop = orig_stop


class Stage7CollectGate:
    """Allow ONLY audited terminal selection packets, exact framed read-only shell commands,
    and FileControl READ strictly for the fixed 32-path allowlist when terminal mode is
    verified disabled.

    Also records exact packet responses/errors (preventing PMCA from hiding 0x40 AdjustControl
    failures) and observes StopSenser vendorRequestOut on the service driver (preventing PMCA
    from hiding service-stop USB transport errors).
    """

    def __init__(self, device, receipt=None):
        self.device = device
        self.receipt = receipt
        self.next_frame = None
        self.poisoned = False
        self.pending = bytearray()
        self.packet_log = []
        self.terminal_disable_verified = False
        self._disable_step1_ok = False
        if receipt is not None:
            self.stop_transport = receipt.setdefault("service_stop_transport", make_stop_transport_record())
        else:
            self.stop_transport = make_stop_transport_record()
        self._install_stop_observer()

    def _install_stop_observer(self):
        driver = getattr(self.device, "driver", None)
        orig = getattr(driver, "vendorRequestOut", None)
        if driver is None or not callable(orig) or getattr(orig, "_stage7_stop_info", None) is self.stop_transport:
            return

        def observed_vendor_request_out(*args, **kwargs):
            return _record_stop_call(self.stop_transport, driver, orig, args, kwargs)

        observed_vendor_request_out._stage7_stop_info = self.stop_transport
        driver.vendorRequestOut = observed_vendor_request_out

    def sendSenserPacket(self, function, payload, output=None):
        pair = (function, payload)
        if pair in PACKETS:
            entry = dict(kind="terminal", function=hex(function), payload=payload.hex(), ok=False, response=None, error=None)
            self.packet_log.append(entry)
            if pair in (TERM_ENABLE_P1, TERM_ENABLE_P2, TERM_DISABLE_P1):
                self.terminal_disable_verified = False
                self._disable_step1_ok = False
            try:
                res, data = self.device.sendSenserPacket(function, payload, output)
            except BaseException as err:
                entry["error"] = f"{type(err).__name__}: {err}"
                if pair in (TERM_DISABLE_P1, TERM_DISABLE_P2):
                    self.terminal_disable_verified = False
                    self._disable_step1_ok = False
                raise
            expected = 0 if function == 0x40 else 1
            entry["response"] = res
            entry["ok"] = (res == expected)
            if pair == TERM_DISABLE_P1:
                self._disable_step1_ok = (res == 1)
            elif pair == TERM_DISABLE_P2:
                self.terminal_disable_verified = bool(self._disable_step1_ok and res == 0)
                self._disable_step1_ok = False
            return res, data

        if function == 0xFF01 and payload in ALLOWED_FILE_READ_PAYLOADS:
            if not self.terminal_disable_verified:
                raise probe.ProbeError("FileControl blocked: terminal disable not verified")
            entry = dict(kind="file_read", function=hex(function), payload_len=len(payload), ok=False, response=None, error=None)
            self.packet_log.append(entry)
            try:
                res, data = self.device.sendSenserPacket(function, payload, output)
            except BaseException as err:
                entry["error"] = f"{type(err).__name__}: {err}"
                raise
            entry["response"] = res
            entry["ok"] = (res == 1)
            return res, data

        raise probe.ProbeError(f"Disallowed Senser packet blocked: function={function:#x} len={len(payload)}")

    def readTerminal(self):
        if self.pending:
            data = bytes(self.pending)
            self.pending.clear()
            return data
        return self.device.readTerminal()

    def writeTerminal(self, data):
        if self.poisoned or data != self.next_frame:
            raise probe.ProbeError("Unapproved or duplicate terminal frame")
        self.next_frame = None
        try:
            driver = self.device.driver
            for start in range(0, len(data), 32):
                chunk = data[start:start + 32]
                written = driver.backend.dev.write(driver.epOut[1], chunk)
                if type(written) is not int or written != len(chunk):
                    raise probe.ProbeError("Short USB OUT write")
                self.pending.extend(self.device.readTerminal())
                if len(self.pending) > 512 * 1024:
                    raise probe.ProbeError("Terminal receive overflow")
                time.sleep(0.01)
        except BaseException:
            self.poisoned = True
            raise


def toggle_terminal(camera, enable: bool, toggle_log: list, phase: str):
    """Run setTerminalEnable(enable) and verify BOTH 0x10 and 0x40 packets succeeded without suppression."""
    gate = getattr(camera, "dev", None)
    is_gate = isinstance(gate, Stage7CollectGate)
    start_idx = len(gate.packet_log) if is_gate else 0
    rec = dict(phase=phase, enable=bool(enable), ok=False)
    toggle_log.append(rec)
    try:
        with probe.deadline(8):
            camera.setTerminalEnable(enable)
    except BaseException as err:
        rec["error"] = f"{type(err).__name__}: {err}"
        if is_gate:
            rec["packets"] = gate.packet_log[start_idx:]
        raise

    if is_gate:
        events = gate.packet_log[start_idx:]
        rec["packets"] = events
        exp_p1 = TERM_ENABLE_P1 if enable else TERM_DISABLE_P1
        exp_p2 = TERM_ENABLE_P2 if enable else TERM_DISABLE_P2
        if len(events) != 2:
            rec["error"] = f"Expected 2 terminal toggle packets, saw {len(events)}"
            raise probe.ProbeError(f"{phase}: {rec['error']}")
        p1, p2 = events[0], events[1]
        if (
            p1.get("function") != hex(exp_p1[0])
            or p1.get("payload") != exp_p1[1].hex()
            or not p1.get("ok")
        ):
            rec["error"] = f"ProductInfo terminal packet failed: {p1}"
            raise probe.ProbeError(f"{phase}: {rec['error']}")
        if (
            p2.get("function") != hex(exp_p2[0])
            or p2.get("payload") != exp_p2[1].hex()
            or not p2.get("ok")
        ):
            rec["error"] = f"AdjustControl 0x601/0x1f terminal packet failed or suppressed: {p2}"
            raise probe.ProbeError(f"{phase}: {rec['error']}")
    rec["ok"] = True


class TerminalSession:
    def __init__(self, camera, receipt):
        self.camera = camera
        self.receipt = receipt

    def command(self, label, command, allowed=(0,), timeout=20):
        index = len(self.receipt["commands"])
        wire, begin, end = frame(command, index, self.receipt["nonce"])
        spec = (wire[:-1], begin, end)
        self.receipt["commands"].append(dict(step=index, label=label, command=command))
        self.camera.dev.next_frame = spec[0]
        raw, lines = bytearray(), []
        normalizer = terminal.ResponseLines(spec)
        started = time.monotonic()
        deadline_exceeded = False
        ack_committed_at = None

        def check_deadline():
            nonlocal deadline_exceeded
            elapsed = time.monotonic() - started
            if elapsed >= timeout:
                deadline_exceeded = True
                raise probe.ProbeError(f"{label}: host terminal deadline exceeded; ACK not committed")
            return elapsed

        try:
            with probe.deadline(timeout + 5):
                self.camera.dev.writeTerminal(spec[0])
                while time.monotonic() - started < timeout:
                    chunk = self.camera.dev.readTerminal()
                    raw.extend(chunk)
                    check_deadline()
                    if len(raw) >= 512 * 1024:
                        raise probe.ProbeError(f"{label}: terminal response exceeded 512 KiB")
                    lines.extend(normalizer.feed(chunk))
                    ends = [i for i, line in enumerate(lines) if line.startswith(end)]
                    if not ends:
                        continue
                    record = dict(step=index, response=raw.decode("utf8", "replace"))
                    status = terminal.ack_status(record, spec, index)
                    if status is None:
                        raise probe.ProbeError(f"{label}: missing ordered ACK")
                    pending = bytes(normalizer.pending)
                    if lines[ends[0] + 1:] or normalizer.soft_parts or not terminal.SHELL_PROMPT.startswith(pending):
                        raise probe.ProbeError(f"{label}: unexpected trailing bytes after ACK")
                    if pending == terminal.SHELL_PROMPT:
                        ack_committed_at = check_deadline()
                        if status not in allowed:
                            raise probe.ProbeError(f"{label}: camera shell exited with {status}")
                        phys = bytes(raw).split(b"\n")
                        b_pos = [i for i, pl in enumerate(phys) if pl in (begin, begin + b"\r")]
                        e_pos = [
                            i for i, pl in enumerate(phys)
                            if re.fullmatch(re.escape(end) + rb"[0-9]+__\r?", pl)
                        ]
                        if len(b_pos) != 1 or len(e_pos) != 1 or b_pos[0] >= e_pos[0]:
                            raise probe.ProbeError(f"{label}: malformed physical marker framing")
                        body_bytes = b"\n".join(pl.removesuffix(b"\r") for pl in phys[b_pos[0] + 1:e_pos[0]])
                        body = body_bytes.decode("utf8", "replace")
                        return body, status
                deadline_exceeded = True
                raise probe.ProbeError(f"{label}: missing complete ACK/prompt")
        except BaseException:
            self.camera.dev.poisoned = True
            raise
        finally:
            elapsed = time.monotonic() - started
            deadline_exceeded = deadline_exceeded or (ack_committed_at is None and elapsed >= timeout)
            self.receipt["steps"].append(dict(
                step=index,
                label=label,
                bytes=len(raw),
                elapsed_seconds=round(elapsed, 3),
                deadline_seconds=timeout,
                deadline_exceeded=deadline_exceeded,
                ack_committed_at_seconds=round(ack_committed_at, 3) if ack_committed_at is not None else None,
            ))


class BoundedSink:
    def __init__(self, stream, limit=MAX_FILE_BYTES):
        self.stream = stream
        self.limit = limit
        self.bytes = 0
        self.sha256 = hashlib.sha256()
        self.md5 = hashlib.md5()

    def write(self, data):
        if self.bytes + len(data) > self.limit:
            raise probe.ProbeError("Transferred file exceeds host size cap")
        written = self.stream.write(data)
        if written != len(data):
            raise OSError("Incomplete host file write")
        self.bytes += written
        self.sha256.update(data)
        self.md5.update(data)
        return written


def _split_ascii_lf_lines(text: str, label: str):
    """Split terminal witness text strictly on LF and reject non-ASCII or control characters."""
    if not text.isascii():
        raise probe.ProbeError(f"Non-ASCII character in {label}")
    for ch in text:
        code = ord(ch)
        if (code < 0x20 and ch != "\n") or code == 0x7F:
            raise probe.ProbeError(f"Control character {ch!r} in {label}")
    return text.split("\n")


def verify_ancestor_check(text: str, ancestor_dirs=ANCESTOR_DIRS):
    """Require every allowlisted ancestor dir and /version.txt to report ANC OK with zero BAD/unknown lines."""
    expected = list(ancestor_dirs) + ["/version.txt"]
    expected_set = set(expected)
    seen = {}
    for raw in _split_ascii_lf_lines(text, "ancestor witness"):
        if not raw:
            continue
        m = re.fullmatch(r"ANC (OK|BAD) ([\x21-\x7e]+)", raw, re.ASCII)
        if not m:
            raise probe.ProbeError(f"Unrecognized ancestor witness line: {raw!r}")
        status, target = m[1], m[2]
        if target not in expected_set:
            raise probe.ProbeError(f"Unexpected ancestor witness path: {target!r}")
        if target in seen:
            raise probe.ProbeError(f"Duplicate ancestor witness for {target}")
        if status != "OK":
            raise probe.ProbeError(f"Ancestor or /version.txt failed non-symlink check: {target}")
        seen[target] = status
    missing = [p for p in expected if p not in seen]
    if missing:
        raise probe.ProbeError(f"Missing ancestor witness for: {missing}")
    return expected


def verify_readonly_mounts(mounts_text: str):
    """Verify from live /proc/mounts (LF-delimited, ASCII single-space 6-field Linux format)
    that / and /usr are backed solely by the stock read-only ext2 partitions (/dev/nflasha7
    and /dev/nflasha15, preserving the boot rootfs row at /), and refuse malformed rows,
    non-ASCII or noncanonical targets, contradictory ro/rw flags, or any mount (rw or ro)
    over any allowlisted ancestor directory or file path."""
    entries_by_target = {}
    for raw in _split_ascii_lf_lines(mounts_text, "/proc/mounts"):
        if not raw:
            continue
        parts = raw.split(" ")
        if len(parts) != 6 or any(not p for p in parts):
            raise probe.ProbeError(f"Malformed /proc/mounts line (expected 6 single-space ASCII fields): {raw!r}")
        dev, target, fstype, opts_str, dump, passno = parts
        if not re.fullmatch(r"[0-9]+", dump, re.ASCII) or not re.fullmatch(r"[0-9]+", passno, re.ASCII):
            raise probe.ProbeError(f"Malformed /proc/mounts numeric tail fields: {raw!r}")
        if not target.startswith("/") or "\\" in target or "//" in target or (target != "/" and target.endswith("/")):
            raise probe.ProbeError(f"Noncanonical /proc/mounts target: {target!r}")
        if target != "/" and any(seg in ("", ".", "..") for seg in target[1:].split("/")):
            raise probe.ProbeError(f"Noncanonical /proc/mounts target segment: {target!r}")
        opts = opts_str.split(",")
        if not opts or "" in opts:
            raise probe.ProbeError(f"Malformed /proc/mounts options: {raw!r}")
        if "ro" in opts and "rw" in opts:
            raise probe.ProbeError(f"Contradictory ro/rw /proc/mounts options: {raw!r}")
        entries_by_target.setdefault(target, []).append(dict(dev=dev, fstype=fstype, opts=opts))

    root_entries = entries_by_target.get("/", [])
    if (
        len(root_entries) != 2
        or root_entries[0]["dev"] != "rootfs"
        or root_entries[0]["fstype"] != "rootfs"
        or root_entries[1]["dev"] != "/dev/nflasha7"
        or root_entries[1]["fstype"] != "ext2"
        or "ro" not in root_entries[1]["opts"]
        or "rw" in root_entries[1]["opts"]
    ):
        raise probe.ProbeError(f"Unexpected root mount stack at /: {root_entries!r}")

    usr_entries = entries_by_target.get("/usr", [])
    if (
        len(usr_entries) != 1
        or usr_entries[0]["dev"] != "/dev/nflasha15"
        or usr_entries[0]["fstype"] != "ext2"
        or "ro" not in usr_entries[0]["opts"]
        or "rw" in usr_entries[0]["opts"]
    ):
        raise probe.ProbeError(f"Unexpected /usr mount stack: {usr_entries!r}")

    forbidden_mount_targets = [d for d in ANCESTOR_DIRS if d != "/usr"] + list(PATHS)
    for target in forbidden_mount_targets:
        if target in entries_by_target:
            raise probe.ProbeError(
                f"Unexpected mount over allowlisted path {target}: {entries_by_target[target]!r}"
            )

    return {"/": root_entries[1], "/usr": usr_entries[0]}


def parse_camera_checksums(text: str, paths=PATHS, required_paths=REQUIRED_PATHS, max_file_bytes=MAX_FILE_BYTES):
    """Parse and strictly validate tagged camera witnesses BEFORE any FileControl transfer.

    Every path in `paths` must appear with exactly one state (`REG`, `MISS`, `LINK`, or `NONREG`).
    Every `REG` path must have exactly one `SZ` (1..max_file_bytes) and one `MD` (32 hex chars).
    Every `LINK` path must carry a non-empty readlink target. Non-`REG` paths must have neither
    `SZ` nor `MD`. Every path in `required_paths` must be `REG`.
    """
    allowed_set = set(paths)
    states = {}
    link_targets = {}
    sizes = {}
    md5s = {}

    for raw in _split_ascii_lf_lines(text, "checksum witness"):
        if not raw:
            continue
        m = re.fullmatch(r"ST (REG|MISS|NONREG) ([\x21-\x7e]+)", raw, re.ASCII)
        if m:
            st, path = m[1], m[2]
            if path not in allowed_set:
                raise probe.ProbeError(f"Unexpected path in witness state: {path!r}")
            if path in states:
                raise probe.ProbeError(f"Duplicate or contradictory state witness for {path}")
            states[path] = st
            continue
        m = re.fullmatch(r"ST LINK ([\x21-\x7e]+) ([\x21-\x7e][\x20-\x7e]*)", raw, re.ASCII)
        if m:
            path, target = m[1], m[2].rstrip(" ")
            if path not in allowed_set:
                raise probe.ProbeError(f"Unexpected path in symlink witness: {path!r}")
            if path in states:
                raise probe.ProbeError(f"Duplicate or contradictory state witness for {path}")
            states[path] = "LINK"
            link_targets[path] = target
            continue
        m = re.fullmatch(r"SZ ( *[1-9][0-9]*|        0) ([\x21-\x7e]+)", raw, re.ASCII)
        if m:
            field, path = m[1], m[2]
            digits = field.lstrip(" ")
            if len(field) != max(9, len(digits)):
                raise probe.ProbeError(f"Noncanonical BusyBox wc -c size width: {raw!r}")
            size = int(digits)
            if path not in allowed_set:
                raise probe.ProbeError(f"Unexpected path in size witness: {path!r}")
            if path in sizes:
                raise probe.ProbeError(f"Duplicate size witness for {path}")
            sizes[path] = size
            continue
        m = re.fullmatch(r"MD ([0-9a-f]{32})  ([\x21-\x7e]+)", raw, re.ASCII)
        if m:
            digest, path = m[1], m[2]
            if path not in allowed_set:
                raise probe.ProbeError(f"Unexpected path in MD5 witness: {path!r}")
            if path in md5s:
                raise probe.ProbeError(f"Duplicate MD5 witness for {path}")
            md5s[path] = digest
            continue
        raise probe.ProbeError(f"Unrecognized checksum witness line: {raw!r}")

    unclassified = [p for p in paths if p not in states]
    if unclassified:
        raise probe.ProbeError(f"Missing state witness for allowlisted paths: {unclassified[:5]}")

    reg_paths = []
    missing = []
    symlinks = {}
    nonreg = []
    for p in paths:
        st = states[p]
        if st == "REG":
            if p not in sizes or p not in md5s:
                raise probe.ProbeError(f"{p}: REG path missing SZ or MD witness")
            sz = sizes[p]
            if sz <= 0 or sz > max_file_bytes:
                raise probe.ProbeError(f"{p}: camera size {sz} outside allowed 1..{max_file_bytes} B range")
            reg_paths.append(p)
        else:
            if p in sizes or p in md5s:
                raise probe.ProbeError(f"{p}: non-REG ({st}) path unexpectedly has SZ or MD witness")
            if st == "MISS":
                missing.append(p)
            elif st == "LINK":
                symlinks[p] = link_targets[p]
            else:
                nonreg.append(p)

    missing_required = sorted(p for p in required_paths if states.get(p) != "REG")
    if missing_required:
        raise probe.ProbeError(
            f"Required Stage 7 paths not present as regular files on camera: {missing_required}"
        )
    if not reg_paths:
        raise probe.ProbeError("Zero transferable regular files found on camera")

    return dict(
        reg_paths=reg_paths,
        sizes=sizes,
        md5s=md5s,
        missing=missing,
        symlinks=symlinks,
        nonreg=nonreg,
        states=states,
    )


def verify_transfer(path: str, sink: BoundedSink, sizes: dict, md5s: dict, first4: bytes):
    if path not in sizes or path not in md5s:
        raise probe.ProbeError(f"{path}: missing camera wc -c or md5sum witness")
    if sink.bytes <= 0 or sink.bytes != sizes[path]:
        raise probe.ProbeError(f"{path}: size mismatch host={sink.bytes} camera={sizes[path]}")
    if sink.md5.hexdigest() != md5s[path]:
        raise probe.ProbeError(f"{path}: MD5 mismatch host={sink.md5.hexdigest()} camera={md5s[path]}")
    if path in ELF_PATHS and first4 != b"\x7fELF":
        raise probe.ProbeError(f"{path}: expected ELF magic, got {first4!r}")


def collect(camera, receipt):
    if receipt.get("model") != MODEL:
        raise probe.ProbeError(f"Unsupported model: {receipt.get('model')!r}")

    receipt.setdefault("terminal_toggles", [])
    receipt["ancestors_verified"] = False
    receipt["readonly_mounts_verified"] = False
    receipt["terminal_disable_verified"] = False
    receipt["terminal_disable_sent"] = False
    receipt["all_files_verified"] = False

    destination = ROOT / receipt["collection_directory"]
    destination.mkdir(parents=True, exist_ok=False)

    session = TerminalSession(camera, receipt)
    enable_attempted = False
    terminal_disabled = False
    terminal_disable_error = None
    inventory_sections = []
    witness = None

    try:
        toggle_terminal(camera, False, receipt["terminal_toggles"], phase="pre_disable")
        enable_attempted = True
        toggle_terminal(camera, True, receipt["terminal_toggles"], phase="enable")
        with probe.deadline(10):
            receipt["shell_banner"] = read_ready(camera).decode("utf8", "replace")

        checksum_cmds = build_checksum_commands(PATHS, receipt["nonce"], len(INVENTORY_COMMANDS))
        all_cmds = list(INVENTORY_COMMANDS) + checksum_cmds

        checksum_text = []
        for label, cmd, allowed in all_cmds:
            if label == "check_ancestors" and not receipt["readonly_mounts_verified"]:
                raise probe.ProbeError("Refusing ancestor check before mount verification")
            if label == "version" and (not receipt["readonly_mounts_verified"] or not receipt["ancestors_verified"]):
                raise probe.ProbeError("Refusing version read before mount and ancestor verification")
            if label.startswith("checksums_") and (
                not receipt["readonly_mounts_verified"]
                or not receipt["ancestors_verified"]
                or receipt.get("build") != BUILD
            ):
                raise probe.ProbeError("Refusing checksum command before mount, ancestor, and build verification")
            body, _ = session.command(label, cmd, allowed=allowed, timeout=25)
            inventory_sections.append(f"=== {label} ===\n{body}\n")
            if label == "mounts":
                receipt["verified_ro_mounts"] = verify_readonly_mounts(body)
                receipt["readonly_mounts_verified"] = True
            elif label == "check_ancestors":
                receipt["verified_ancestors"] = verify_ancestor_check(body)
                receipt["ancestors_verified"] = True
            elif label == "version":
                actual_build = body.strip()
                receipt["build"] = actual_build
                if actual_build != BUILD:
                    raise probe.ProbeError(f"Expected original M7 build {BUILD!r}, got {actual_build!r}")
                print(f"BUILD_VERIFIED: {actual_build}", flush=True)
            elif label.startswith("checksums_"):
                checksum_text.append(body)

        if not receipt["ancestors_verified"] or not receipt["readonly_mounts_verified"]:
            raise probe.ProbeError("Missing ancestor or read-only mount verification before FileControl")

        inv_path = destination / "inventory.txt"
        inv_text = "\n".join(inventory_sections)
        inv_path.write_text(inv_text, encoding="utf-8")
        receipt["inventory_path"] = str(inv_path.relative_to(ROOT))
        receipt["inventory_sha256"] = hashlib.sha256(inv_text.encode("utf-8")).hexdigest()

        witness = parse_camera_checksums("\n".join(checksum_text))
        receipt["camera_path_states"] = witness["states"]
        receipt["camera_expected_sizes"] = witness["sizes"]
        receipt["camera_expected_md5"] = witness["md5s"]
        receipt["camera_missing_paths"] = witness["missing"]
        receipt["camera_symlink_paths"] = witness["symlinks"]
        receipt["camera_nonreg_paths"] = witness["nonreg"]
        print(
            f"INVENTORY_OK: {len(witness['reg_paths'])} regular files, "
            f"{len(witness['missing'])} absent, {len(witness['symlinks'])} symlinks, "
            f"{len(witness['nonreg'])} non-regular; saved {receipt['inventory_path']}",
            flush=True,
        )
    finally:
        if enable_attempted:
            try:
                toggle_terminal(camera, False, receipt["terminal_toggles"], phase="final_disable")
                terminal_disabled = True
                receipt["terminal_disable_verified"] = True
                receipt["terminal_disable_sent"] = True
            except Exception as err:
                terminal_disable_error = f"{type(err).__name__}: {err}"
                receipt["terminal_disable_verified"] = False
                receipt["terminal_disable_sent"] = False
                receipt["terminal_disable_error"] = terminal_disable_error

    if not terminal_disabled:
        raise probe.ProbeError(
            f"Aborting before FileControl: final terminal disable failed ({terminal_disable_error})"
        )

    present_paths = witness["reg_paths"]
    sizes = witness["sizes"]
    md5s = witness["md5s"]
    receipt["files"] = {}
    total_bytes = sum(sizes[p] for p in present_paths)
    print(f"FILE_PULL_START: {len(present_paths)} files, {total_bytes:,} bytes total", flush=True)

    done_bytes = 0
    for idx, path in enumerate(present_paths, 1):
        exp = sizes[path]
        print(f"[{idx}/{len(present_paths)}] READ {path} ({exp:,} B)...", flush=True)
        out_path = destination / path.lstrip("/")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        partial = out_path.with_name(out_path.name + ".partial")
        renamed = False
        try:
            with partial.open("xb") as stream:
                sink = BoundedSink(stream)
                with probe.deadline(max(30, min(180, exp // 200000 + 30))):
                    camera.readFile(path, sink)
            with partial.open("rb") as stream:
                first4 = stream.read(4)
            verify_transfer(path, sink, sizes, md5s, first4)
            partial.rename(out_path)
            renamed = True
            done_bytes += sink.bytes
            receipt["files"][path] = dict(
                host_path=str(out_path.relative_to(ROOT)),
                bytes=sink.bytes,
                sha256=sink.sha256.hexdigest(),
                md5=sink.md5.hexdigest(),
                verified=True,
            )
            print(f"  OK {sink.bytes:,} B sha256={sink.sha256.hexdigest()[:16]}...", flush=True)
        except BaseException as err:
            if not renamed:
                partial.unlink(missing_ok=True)
            receipt["files"][path] = dict(error=f"{type(err).__name__}: {err}", verified=False)
            print(f"  ERROR {path}: {err}", flush=True)
            raise

    receipt["total_transferred_bytes"] = done_bytes
    receipt["all_files_verified"] = (
        bool(present_paths)
        and REQUIRED_PATHS.issubset(receipt["files"].keys())
        and set(receipt["files"].keys()) == set(present_paths)
        and all(receipt["files"][p].get("verified") is True for p in present_paths)
    )


def _assert_raises(exc_type, fn, contains=None):
    try:
        fn()
    except exc_type as err:
        if contains is not None and contains not in str(err):
            raise AssertionError(f"Expected {contains!r} in error {err!r}")
        return
    raise AssertionError(f"Expected {exc_type.__name__} to be raised")


def self_test():
    # 1. Verify all terminal inventory & checksum commands are valid /bin/sh syntax and < 512 wire bytes
    nonce = "0123456789ab"
    checksum_cmds = build_checksum_commands(PATHS, nonce, len(INVENTORY_COMMANDS))
    assert len(checksum_cmds) >= 1
    assert INVENTORY_COMMANDS[1][0] == "mounts" and INVENTORY_COMMANDS[2][0] == "check_ancestors" and INVENTORY_COMMANDS[3][0] == "version"
    for i, (label, cmd, _) in enumerate(list(INVENTORY_COMMANDS) + checksum_cmds):
        wire, _, _ = frame(cmd, i, nonce)
        assert len(wire) < 512, f"{label} wire length {len(wire)} >= 512"
        subprocess.run(["/bin/sh", "-n", "-c", cmd], check=True)

    # 2. Verify PacketGate allowlist, terminal state-machine gate, and stop transport observer
    sys.path.insert(0, str(probe.PMCA))
    from pmca.usb.driver.generic import GenericUsbException
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserCamera

    class FakeDriver:
        def __init__(self, fail_stop=False):
            self.fail_stop = fail_stop
            self.vendor_calls = []

        def reset(self):
            pass

        def vendorRequestOut(self, *args):
            self.vendor_calls.append(args)
            if self.fail_stop:
                raise GenericUsbException()

    class FakeDev:
        def __init__(self, fail_0x40=False, bad_0x40_status=None, fail_stop=False):
            self.calls = []
            self.fail_0x40 = fail_0x40
            self.bad_0x40_status = bad_0x40_status
            self.driver = FakeDriver(fail_stop=fail_stop)

        def sendSenserPacket(self, function, payload, output=None):
            self.calls.append((function, payload))
            if function == 0x40 and self.fail_0x40:
                raise GenericUsbException()
            if function == 0x40 and self.bad_0x40_status is not None:
                return self.bad_0x40_status, b""
            if output is not None:
                output.write(b"\x7fELFfixture")
            return (0 if function == 0x40 else 1), b"\x7fELFfixture"

        def readTerminal(self):
            return b""

    fake = FakeDev()
    gate_receipt = {}
    gate = Stage7CollectGate(fake, receipt=gate_receipt)
    cam = SonySenserCamera(gate)
    toggles = []

    _assert_raises(probe.ProbeError, lambda: cam.readFile("/version.txt"), "terminal disable not verified")
    toggle_terminal(cam, False, toggles, "pre_disable")
    toggle_terminal(cam, True, toggles, "enable")
    _assert_raises(probe.ProbeError, lambda: cam.readFile("/version.txt"), "terminal disable not verified")
    toggle_terminal(cam, False, toggles, "final_disable")

    for p in PATHS:
        buf = io.BytesIO()
        cam.readFile(p, BoundedSink(buf))
        assert buf.getvalue() == b"\x7fELFfixture"

    before = len(fake.calls)
    forbidden = [
        lambda: cam.writeFile("/version.txt", b"x"),
        lambda: cam.writeFile("/setting/env.txt", b"LD_PRELOAD=/tmp/x.so\n"),
        lambda: cam.deleteFile("/version.txt"),
        lambda: cam.readFile("/setting/Backup.bin"),
        lambda: cam.readFile("/setting/.etools"),
        lambda: cam.readFile("/cert/private.pem"),
        lambda: cam.readFile("/usr/lib/../lib/CautionConfig.so"),
        lambda: cam.readHasp(),
        lambda: cam.readMemory(0, 4),
        lambda: cam.writeMemory(0, b"1234"),
        lambda: cam.writeBackup(0x01071472, b"\x00"),
        lambda: gate.writeTerminal(b"reboot\n"),
    ]
    for op in forbidden:
        _assert_raises(probe.ProbeError, op)
    assert len(fake.calls) == before

    # 3. Verify PMCA-swallowed 0x40 AdjustControl failures are detected AND block FileControl
    for dev_bad in (FakeDev(fail_0x40=True), FakeDev(bad_0x40_status=2)):
        bad_gate = Stage7CollectGate(dev_bad)
        bad_cam = SonySenserCamera(bad_gate)
        _assert_raises(probe.ProbeError, lambda: toggle_terminal(bad_cam, False, [], "bad_disable"), "0x601/0x1f")
        _assert_raises(probe.ProbeError, lambda: bad_cam.readFile("/version.txt"), "terminal disable not verified")

    # 4. Verify observe_stop_senser detects PMCA-swallowed GenericUsbException even WITHOUT Stage7CollectGate
    for fail_flag in (False, True):
        stop_rec = {"service_stop_transport": make_stop_transport_record()}
        drv = FakeDriver(fail_stop=fail_flag)
        with observe_stop_senser(stop_rec):
            probe.finish_service(SonySenserAuthDevice(drv), stop_rec)
        assert stop_rec["service_stop_requested"] is True
        st = stop_rec["service_stop_transport"]
        assert st["attempted"] is True and st["observed"] is True and st["camera_exit_confirmed"] is False
        assert st["transport_ok"] is (not fail_flag)
        if fail_flag:
            assert "GenericUsbException" in (st["error"] or "")

    # 5. Verify ancestor check, read-only mount check, tagged checksum parser, and blank readlink rejection
    good_anc = "\n".join(f"ANC OK {p}" for p in list(ANCESTOR_DIRS) + ["/version.txt"])
    assert verify_ancestor_check(good_anc) == list(ANCESTOR_DIRS) + ["/version.txt"]
    _assert_raises(probe.ProbeError, lambda: verify_ancestor_check(good_anc.replace("ANC OK /lib", "ANC BAD /lib")), "non-symlink")
    _assert_raises(probe.ProbeError, lambda: verify_ancestor_check(good_anc.replace("ANC OK /version.txt", "ANC BAD /version.txt")), "non-symlink")

    good_mounts = (
        "rootfs / rootfs rw 0 0\n"
        "/dev/nflasha7 / ext2 ro,relatime 0 0\n"
        "/dev/nflasha15 /usr ext2 ro,relatime 0 0\n"
        "/dev/nflasha2 /setting vfat rw,sync 0 0\n"
    )
    verify_readonly_mounts(good_mounts)
    for bad_m in (
        good_mounts.replace("/usr ext2 ro", "/usr ext2 rw"),
        good_mounts.replace("/ ext2 ro", "/ ext2 ro,rw"),
        good_mounts.replace("/usr ext2 ro", "/usr ext2 rw,ro"),
        good_mounts.replace("/dev/nflasha7 / ext2", "/dev/nflasha7 // ext2"),
        good_mounts.replace("/dev/nflasha15 /usr ext2", "/dev/nflasha15 /usr/ ext2"),
        good_mounts.replace("/dev/nflasha15 /usr ext2", "/dev/nflasha15 //usr ext2"),
        good_mounts + "fixture /other tmpfs ro\n",
        good_mounts + "fixture /other tmpfs ro 0\n",
        good_mounts + "fixture /other tmpfs ro 0 0 extra\n",
        good_mounts + "fixture /other tmpfs ro x y\n",
        good_mounts + "fixture other tmpfs ro 0 0\n",
        good_mounts + "/dev/x /usr/lib tmpfs rw 0 0\n",
        good_mounts + "/dev/x /usr/lib ext2 ro 0 0\n",
        good_mounts + "/dev/x /version.txt ext2 ro 0 0\n",
        good_mounts + "/dev/x /usr/lib/CautionConfig.so ext2 rw 0 0\n",
        good_mounts + "/dev/x /usr ext2 ro 0 0\n",
        good_mounts.replace("/usr ext2 ro,relatime 0 0", "/usr ext2 ro,relatime \u0660 \uff10"),
        good_mounts.replace("/dev/nflasha15 /usr", "/dev/nflasha15\u00a0/usr"),
        good_mounts.replace("/dev/nflasha7 / ext2 ro,relatime 0 0\n", "/dev/nflasha7 / ext2 ro,relatime 0 0\u2028"),
        good_mounts.replace("/dev/nflasha15 /usr", "/dev/nflasha15  /usr"),
        good_mounts.replace("/dev/nflasha15 /usr", "/dev/nflasha15\t/usr"),
    ):
        _assert_raises(probe.ProbeError, lambda: verify_readonly_mounts(bad_m))

    def make_full_witness(overrides=None, md5_override=None, size_override=None):
        overrides = overrides or {}
        md5_override = md5_override or {}
        size_override = size_override or {}
        lines = []
        for p in PATHS:
            st = overrides.get(p, "REG")
            if st == "REG":
                sz = size_override.get(p, 11)
                dig = md5_override.get(p, hashlib.md5(b"\x7fELFfixture").hexdigest())
                lines.append(f"ST REG {p}")
                lines.append(f"SZ {sz:9d} {p}")
                lines.append(f"MD {dig}  {p}")
            elif st == "LINK":
                lines.append(f"ST LINK {p} /usr/lib/target.so")
            else:
                lines.append(f"ST {st} {p}")
        return "\n".join(lines)

    all_dec_md5 = "1" * 32
    w_dec = parse_camera_checksums(make_full_witness(
        overrides={"/usr/lib/viewUnified4.so": "MISS", "/usr/share/app/viewFnMenu.uxc": "LINK"},
        md5_override={"/version.txt": all_dec_md5},
        size_override={"/version.txt": 19},
    ))
    assert w_dec["sizes"]["/version.txt"] == 19 and w_dec["md5s"]["/version.txt"] == all_dec_md5
    assert w_dec["symlinks"] == {"/usr/share/app/viewFnMenu.uxc": "/usr/lib/target.so"}

    # Blank readlink target MUST be rejected
    blank_link = make_full_witness(overrides={"/usr/lib/viewUnified4.so": "LINK"}).replace(
        "ST LINK /usr/lib/viewUnified4.so /usr/lib/target.so", "ST LINK /usr/lib/viewUnified4.so "
    )
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums(blank_link), "Unrecognized")
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums("\n".join(f"ST MISS {p}" for p in PATHS)), "Required Stage 7")
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums(make_full_witness(overrides={p: "MISS" for p in PATHS if p != "/version.txt"})), "Required Stage 7")
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums(make_full_witness(overrides={"/usr/lib/CautionConfig.so": "MISS"})), "Required Stage 7")
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums(make_full_witness(overrides={"/usr/lib/viewUnified2.so": "LINK"})), "Required Stage 7")
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums(make_full_witness() + "\nST MISS /version.txt"), "Duplicate")
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums(make_full_witness(size_override={"/version.txt": 0})), "outside allowed")
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums(make_full_witness(size_override={"/version.txt": MAX_FILE_BYTES + 1})), "outside allowed")
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums(make_full_witness().replace("SZ        11 /version.txt", "SZ 11 /version.txt")), "Noncanonical")
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums(make_full_witness().replace("SZ        11 /version.txt", "SZ 0000000011 /version.txt")), "Unrecognized")
    _assert_raises(probe.ProbeError, lambda: parse_camera_checksums(make_full_witness().replace("  /version.txt", " */version.txt")), "Unrecognized")

    # 6. Verify transfer verifier
    buf = io.BytesIO()
    sink = BoundedSink(buf)
    sink.write(b"\x7fELFfixture")
    w_ok = parse_camera_checksums(make_full_witness())
    verify_transfer("/usr/lib/CautionConfig.so", sink, w_ok["sizes"], w_ok["md5s"], b"\x7fELF")
    for bad_call in (
        lambda: verify_transfer("/usr/lib/CautionConfig.so", sink, w_ok["sizes"], w_ok["md5s"], b"NOPE"),
        lambda: verify_transfer("/usr/lib/CautionConfig.so", sink, {"/usr/lib/CautionConfig.so": 10}, w_ok["md5s"], b"\x7fELF"),
        lambda: verify_transfer("/usr/lib/CautionConfig.so", sink, w_ok["sizes"], {"/usr/lib/CautionConfig.so": "0" * 32}, b"\x7fELF"),
        lambda: verify_transfer("/usr/lib/viewUnified2.so", sink, {}, {}, b"\x7fELF"),
    ):
        _assert_raises(probe.ProbeError, bad_call)

    # 7. Verify TerminalSession rejects late ACK at/past timeout
    _, begin, end = frame(":", 0, nonce)
    ack = begin + b"\r\n" + end + b"0__\r\n" + terminal.SHELL_PROMPT

    class ClockRaw:
        def __init__(self, data):
            self.data = data
            self.driver = SimpleNamespace(epOut=[0x02, 0x04], backend=SimpleNamespace(dev=self))

        def readTerminal(self):
            chunk, self.data = self.data[:64], self.data[64:]
            return chunk

        def write(self, ep, chunk):
            return len(chunk)

    late_cam = SimpleNamespace(dev=Stage7CollectGate(ClockRaw(ack)))
    late_session = TerminalSession(late_cam, dict(nonce=nonce, commands=[], steps=[]))
    with patch.object(time, "sleep", lambda _: None), patch.object(time, "monotonic", side_effect=[0.0, 19.99, 20.00, 20.02]):
        _assert_raises(probe.ProbeError, lambda: late_session.command("late", ":", timeout=20), "deadline exceeded")
    assert late_session.receipt["steps"][0]["deadline_exceeded"] is True

    # 7b. Verify CR-CR-LF inside a terminal body survives into witness text so parsers reject it
    cr2_reply = begin + b"\r\nANC OK /lib\r\r\n" + end + b"0__\r\n" + terminal.SHELL_PROMPT
    cr2_cam = SimpleNamespace(dev=Stage7CollectGate(ClockRaw(cr2_reply)))
    cr2_sess = TerminalSession(cr2_cam, dict(nonce=nonce, commands=[], steps=[]))
    with patch.object(time, "sleep", lambda _: None):
        cr2_body, _ = cr2_sess.command("cr2", ":", timeout=20)
    assert "\r" in cr2_body
    _assert_raises(probe.ProbeError, lambda: verify_ancestor_check(cr2_body), "Control character")

    # 8. Verify collect() gates: ancestor failure, writable /usr mount, terminal-disable failure, KeyboardInterrupt
    valid_witness = make_full_witness(overrides={p: "MISS" for p in PATHS if p not in REQUIRED_PATHS})

    def run_collect_fixture(fail_0x40_on_final=False, read_exc=None, anc_out=good_anc, mounts_out=good_mounts):
        pulls = []

        class FixtureDev:
            def __init__(self):
                self.disable_count = 0
                self.driver = FakeDriver()

            def sendSenserPacket(self, function, payload, output=None):
                if (function, payload) == TERM_DISABLE_P2:
                    self.disable_count += 1
                    if fail_0x40_on_final and self.disable_count == 2:
                        raise GenericUsbException()
                if function == 0xFF01:
                    pulls.append(payload)
                    if output is not None:
                        output.write(b"\x7fELF")
                        if read_exc is not None:
                            raise read_exc
                        output.write(b"fixture")
                    return 1, b""
                return (0 if function == 0x40 else 1), b""

            def readTerminal(self):
                return b""

        seen_labels = []

        def fake_cmd(self_sess, label, *args, **kwargs):
            seen_labels.append(label)
            if label == "check_ancestors":
                return anc_out, 0
            if label == "version":
                return BUILD, 0
            if label == "mounts":
                return mounts_out, 0
            if label == "checksums_0":
                return valid_witness, 0
            return "", 0

        fdev = FixtureDev()
        rec = dict(model=MODEL, nonce=nonce, collection_directory="collection", commands=[], steps=[])
        fgate = Stage7CollectGate(fdev, receipt=rec)
        fcam = SonySenserCamera(fgate)
        with tempfile.TemporaryDirectory() as tmp, patch.object(sys.modules[__name__], "ROOT", Path(tmp)), \
                patch.object(sys.modules[__name__], "read_ready", lambda _: b"/ # "), \
                patch.object(TerminalSession, "command", fake_cmd), patch("builtins.print"):
            try:
                collect(fcam, rec)
            except BaseException as err:
                rec["observed_error"] = type(err).__name__
            partials = list(Path(tmp).rglob("*.partial"))
        return rec, pulls, partials, seen_labels

    r_ok, p_ok, part_ok, _ = run_collect_fixture()
    assert "observed_error" not in r_ok and r_ok["all_files_verified"] is True
    assert r_ok["ancestors_verified"] is True and r_ok["readonly_mounts_verified"] is True
    assert r_ok["terminal_disable_verified"] is True and len(p_ok) == len(REQUIRED_PATHS) and not part_ok

    # Ancestor symlink MUST abort BEFORE version cat and with ZERO FileControl reads
    r_anc, p_anc, _, labels_anc = run_collect_fixture(anc_out=good_anc.replace("ANC OK /lib", "ANC BAD /lib"))
    assert r_anc["observed_error"] == "ProbeError" and "version" not in labels_anc and p_anc == []

    # Writable /usr mount or file mount at /version.txt MUST abort BEFORE version cat and with ZERO FileControl reads
    for bad_mnt in (
        good_mounts.replace("/usr ext2 ro", "/usr ext2 rw"),
        good_mounts + "fixture /version.txt ext2 ro 0 0\n",
        good_mounts + "fixture /usr/lib ext2 ro 0 0\n",
    ):
        r_mnt, p_mnt, _, labels_mnt = run_collect_fixture(mounts_out=bad_mnt)
        assert r_mnt["observed_error"] == "ProbeError" and "version" not in labels_mnt and p_mnt == []

    # PMCA-swallowed 0x40 failure on final disable MUST abort with ZERO FileControl reads
    r_dis, p_dis, part_dis, _ = run_collect_fixture(fail_0x40_on_final=True)
    assert r_dis["observed_error"] == "ProbeError" and r_dis["terminal_disable_verified"] is False
    assert p_dis == [] and not part_dis

    # KeyboardInterrupt during FileControl MUST remove .partial and fail cleanly
    r_int, _, part_int, _ = run_collect_fixture(read_exc=KeyboardInterrupt())
    assert r_int["observed_error"] == "KeyboardInterrupt" and r_int["all_files_verified"] is False and not part_int

    # 9. Verify --connect without exact full consent flag (including abbreviated --confirm) refuses before touching USB
    for bad_argv in (["--connect"], ["--connect", "--confirm"]):
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                main(bad_argv)
            except SystemExit as ex:
                assert ex.code != 0
            else:
                raise AssertionError(f"{bad_argv!r} succeeded without exact side-effect consent flag")

    print(
        f"SELF_TEST_OK: {len(PATHS)} allowlisted read paths ({len(REQUIRED_PATHS)} required, "
        f"{len(ANCESTOR_DIRS)} verified ancestors), {len(INVENTORY_COMMANDS) + len(checksum_cmds)} "
        f"framed commands (<512 B), teardown/stop/ancestor/mount/interrupt/consent gates passed; no USB opened."
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--connect", action="store_true", help="Collect Stage 7 M7 1.00 files over USB (read-only)")
    mode.add_argument("--self-test", action="store_true", help="Run offline safety/framing/gate self-tests (no USB)")
    parser.add_argument(
        "--confirm-32-file-etools-and-history",
        action="store_true",
        help=(
            "Explicit owner confirmation required for --connect: accepts up to 32 FileControl READ "
            "requests (possible /setting/.etools 4096 B update) and unverified BusyBox .ash_history behavior."
        ),
    )
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if not args.confirm_32_file_etools_and_history:
        parser.error(
            "--connect requires --confirm-32-file-etools-and-history: this run sends up to 32 FileControl READ "
            "requests (Sony libsencore.so may update /setting/.etools) and opens a BusyBox ash session "
            "(shell-history saving behavior is unverified)."
        )

    OUT_RECEIPT_DIR.mkdir(parents=True, exist_ok=True)
    utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    nonce = secrets.token_hex(6)
    receipt = dict(
        collector_version=9,
        stage="stage7-readonly-collect",
        utc=utc,
        nonce=nonce,
        pmca_commit=probe.PMCA_COMMIT,
        camera_writes_requested=False,
        owner_confirmed_32_file_etools_and_history=True,
        note_etools=(
            "FileControl READ requests up to 32 allowlisted paths; Sony libsencore.so may "
            "update /setting/.etools (4096 B) if present. Confirmed by operator CLI flag."
        ),
        note_shell_history=(
            "BusyBox ash shell-history saving on this unit is unverified; HISTFILE=/dev/null "
            "is best-effort and does not prove absence of .ash_history writes. Confirmed by operator CLI flag."
        ),
        service_stop_camera_exit_confirmed=False,
        service_stop_transport=make_stop_transport_record(),
        collection_directory=f"extracted/m7-stage7-1.00-{utc}",
        commands=[],
        steps=[],
        terminal_toggles=[],
    )

    try:
        with observe_stop_senser(receipt):
            probe.connect(
                receipt,
                diagnostic=collect,
                gate_factory=lambda device: Stage7CollectGate(device, receipt=receipt),
            )
    except (Exception, KeyboardInterrupt) as err:
        receipt["error"] = f"{type(err).__name__}: {err}"
        print(f"ERROR={receipt['error']}", file=sys.stderr, flush=True)

    stop_info = receipt.get("service_stop_transport", {})
    if stop_info.get("attempted") and not stop_info.get("transport_ok"):
        print(
            f"SERVICE_STOP_TRANSPORT_WARNING: {stop_info.get('error')}; "
            "verify physical camera return to normal UI / power cycle if needed.",
            file=sys.stderr,
            flush=True,
        )

    receipt_path = OUT_RECEIPT_DIR / f"collect-stage7-{utc}-{nonce}.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"RESULT={receipt_path}", flush=True)
    ok = (
        "error" not in receipt
        and receipt.get("ancestors_verified") is True
        and receipt.get("readonly_mounts_verified") is True
        and receipt.get("all_files_verified") is True
        and receipt.get("terminal_disable_verified") is True
        and receipt.get("service_stop_requested") is True
        and receipt.get("service_stop_error") is None
        and stop_info.get("observed") is True
        and stop_info.get("transport_ok") is True
    )
    print(f"STAGE7_COLLECT_OK={ok}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
