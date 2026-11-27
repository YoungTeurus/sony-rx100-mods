#!/usr/bin/env python3
"""Stage 7.3 Phase B persistent SD loader installer, SD prep tool, uninstaller,
and shell-free emergency FileControl removal for Sony DSC-RX100M7 1.00.

Works out-of-the-box on a clean repository clone using only the Python standard
library (for dry-run and prep-sd) plus pyusb/libusb-package/Sony-PMCA-RE (for
live USB install, uninstall, and emergency recovery), without requiring local
extracted Sony firmware, clang/ld.lld, capstone, or pyelftools.
"""

import argparse
import contextlib
import errno
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "prototype-stage7-persist"
OUT_PERSIST = PROTO / "out-phaseb-persist"
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import m7_probe as probe  # noqa: E402
from m7_terminal_check import PACKETS  # noqa: E402
from m7_terminal_steps import frame, read_ready  # noqa: E402


BUILD = "29110_03.2021050601"
TARGET_BUILD_BYTES = BUILD.encode("ascii")
SHELL_PROMPT = b"/usr/share/app # "
PROMPT_SUFFIXES = tuple(SHELL_PROMPT[i:] for i in range(len(SHELL_PROMPT) + 1))
TERM_ENABLE_P1 = (0x10, b"\x00\x00\xf1\x00\x01")
TERM_ENABLE_P2 = (0x40, b"\x01\x06\x1f\x00\x02")
TERM_DISABLE_P1 = (0x10, b"\x00\x00\xf1\x00\x00")
TERM_DISABLE_P2 = (0x40, b"\x01\x06\x1f\x00\x00")
STOP_SENSER_VENDOR_REQ = (0x41, 0x05, 0)
MODE = "emergency-filecontrol-uninstall"
ALL_MODES = (
    "dry-run",
    "prep-sd",
    "install",
    "uninstall",
    MODE,
)
RECEIPTS = probe.ROOT / "work/stage7-persist/phaseb-install"
MARKER = "/setting/disable_sd_boot"
MARKER_BYTES = b"1\n"
PRELOAD = "/etc/ld.so.preload"
PRELOAD_BAK = "/etc/ld.so.preload.stock_bak"
HOOK = "/setting/mlv2_sd_boot_hook.so"
BOOT_SH = "/setting/mlv2_sd_boot.sh"
READER = "/setting/mlv2_card_read.elf"
OWNER_KEY = "/setting/mlv2_owner.key"
PRECAP_CFG = "/setting/mlv2_precap.cfg"
PRECAP_CFG_TMP = "/setting/mlv2_precap.cfg.tmp"
FILES = (PRELOAD, HOOK, BOOT_SH, READER, OWNER_KEY)
DISABLE_SD_MARKERS = ("MLV2.OFF", "DISABLE.TXT", "DISABLE_HOOK")
DISCLOSURE = (
    "M7 FileControl read status 0x82 covers ENOENT, EACCES and EIO. It shows "
    "a failed lookup. Confirm file absence and stock behavior separately after restart."
)
INSTALL_DISCLOSURE = (
    "Owner-authorized Phase B flash install writes only the 4 /setting/mlv2_* files "
    "and /etc/ld.so.preload (after passing a live LD_PRELOAD=/setting/mlv2_sd_boot_hook.so "
    "smoke check). Stock Sony Senser auth/FileControl may also update /setting/.etools."
)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sign_mlv2_tar(ustar_bytes, key_32b, release_seq=1):
    """Wrap a plain USTAR archive in the authenticated 128-byte M7SD1 HMAC-SHA256 envelope."""
    if len(key_32b) != 32:
        raise ValueError("Owner HMAC key must be exactly 32 bytes")
    if not (isinstance(release_seq, int) and not isinstance(release_seq, bool) and 1 <= release_seq <= 0xFFFFFFFF):
        raise ValueError(f"Invalid release_seq: {release_seq!r}")
    if len(ustar_bytes) < 512 or len(ustar_bytes) > 384 * 1024 or len(ustar_bytes) % 512 != 0:
        raise ValueError(f"Invalid USTAR payload length: {len(ustar_bytes)}")
    prefix = struct.pack(
        "<8s24sII24x32s",
        b"M7SD1",
        TARGET_BUILD_BYTES,
        release_seq,
        len(ustar_bytes),
        hashlib.sha256(ustar_bytes).digest(),
    )
    tag = hmac.digest(key_32b, prefix, "sha256")
    return prefix + tag + ustar_bytes


def verify_prebuilt_release(directory=OUT_PERSIST, *, strict_rebuild=False):
    """Verify sealed pre-built Phase B artifacts against build-phaseb-persist.json using stdlib only.

    Pass strict_rebuild=True (developer machines with extracted firmware + clang/lld) to also
    run full source-to-binary reproducibility verification via build_stage7_phaseb_persist.verify_seal().
    """
    if strict_rebuild:
        if str(PROTO) not in sys.path:
            sys.path.insert(0, str(PROTO))
        import build_stage7_phaseb_persist as phaseb_build  # noqa: E402
        return phaseb_build.verify_seal(directory)

    manifest_path = Path(directory) / "build-phaseb-persist.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Missing Phase B release manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("target") != f"DSC-RX100M7 1.00 ({BUILD})" or manifest.get("ram_root") != "/tmp_bt":
        raise ValueError("Phase B release manifest target/ram_root mismatch")
    artifacts = manifest.get("artifacts", {})
    for key in ("hook", "reader", "boot_script", "card_ustar"):
        entry = artifacts.get(key)
        if not isinstance(entry, dict):
            raise ValueError(f"Missing artifact metadata {key!r} in build-phaseb-persist.json")
        fpath = Path(directory) / entry["file"]
        if not fpath.is_file():
            raise FileNotFoundError(f"Missing sealed Phase B artifact: {fpath}")
        blob = fpath.read_bytes()
        if len(blob) != entry["bytes"] or sha256_bytes(blob) != entry["sha256"]:
            raise ValueError(f"Sealed Phase B artifact hash/size mismatch: {fpath.name}")
        if b"/tmp_network" in blob:
            raise ValueError(f"Unexpected /tmp_network reference in {fpath.name}")
    if not (Path(directory) / "mlv2_sd_boot_hook.so").read_bytes().startswith(b"\x7fELF"):
        raise ValueError("mlv2_sd_boot_hook.so is not an ELF file")
    if not (Path(directory) / "mlv2_card_read.elf").read_bytes().startswith(b"\x7fELF"):
        raise ValueError("mlv2_card_read.elf is not an ELF file")
    return manifest


def _open_dir_nofollow(path, dir_fd=None):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    return os.open(path, flags, dir_fd=dir_fd)


@contextlib.contextmanager
def custody(path):
    """Pin a non-symlink directory by fd (creating the leaf dir if missing)."""
    target = Path(path).absolute()
    parts = target.parts
    if not parts or parts[0] != os.sep:
        raise ValueError(f"Expected absolute directory path: {path}")
    fd = _open_dir_nofollow(os.sep)
    try:
        for idx, comp in enumerate(parts[1:], start=1):
            try:
                nxt = _open_dir_nofollow(comp, dir_fd=fd)
            except FileNotFoundError:
                if idx != len(parts) - 1:
                    raise
                os.mkdir(comp, 0o755, dir_fd=fd)
                nxt = _open_dir_nofollow(comp, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd
    finally:
        os.close(fd)


def names_inode(directory_fd, filename, expected_stat):
    try:
        st = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as err:
        if err.errno == errno.ENOENT:
            return False
        raise
    return os.path.samestat(st, expected_stat)


def packet(op, path, data=b""):
    name = path.encode("ascii")
    name += b"\0" * (4 - len(name) % 4)
    return struct.pack("<HH", op, len(name)) + name + data


ALLOWED = frozenset([packet(1, MARKER, MARKER_BYTES)]
                    + [packet(2, path) for path in ("/version.txt", MARKER, *FILES)]
                    + [packet(3, path) for path in FILES])

INSTALL_FC_READ_ALLOW = frozenset((
    "/version.txt",
    PRELOAD,
    PRELOAD_BAK,
    MARKER,
    HOOK,
    HOOK + ".new",
    BOOT_SH,
    BOOT_SH + ".new",
    READER,
    READER + ".new",
    OWNER_KEY,
    OWNER_KEY + ".new",
))

INSTALL_FC_WRITE_ALLOW = frozenset((
    HOOK + ".new",
    BOOT_SH + ".new",
    READER + ".new",
    OWNER_KEY + ".new",
))


class FileControlError(Exception):
    def __init__(self, status):
        self.status = status
        super().__init__(f"FileControl status {status:#x}")


class RecoveryGate:
    """Only forward the reviewed FileControl requests, including the exact marker bytes."""

    def __init__(self, device):
        self.device = device

    def sendSenserPacket(self, function, payload, output=None):
        if function != 0xFF01 or payload not in ALLOWED:
            raise probe.ProbeError("Request outside the emergency recovery manifest")
        with probe.deadline(15):
            status, reply = self.device.sendSenserPacket(function, payload, output)
        if status != 1:
            raise FileControlError(status)
        return status, reply


def make_stop_transport_record():
    return dict(
        attempted=False,
        observed=False,
        transport_ok=False,
        camera_exit_confirmed=False,
        driver_class=None,
        error=None,
    )


def _record_stop_call(info, driver, fn, args, kwargs):
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
def observe_stop_senser(receipt):
    """Observe SonySenserAuthDevice.stop() without letting PMCA swallow GenericUsbException."""
    info = receipt.setdefault("service_stop_transport", make_stop_transport_record())
    if not probe.PMCA.is_dir():
        yield
        return
    if str(probe.PMCA) not in sys.path:
        sys.path.insert(0, str(probe.PMCA))
    try:
        from pmca.usb.sony import SonySenserAuthDevice
    except ImportError:
        yield
        return

    orig_stop = SonySenserAuthDevice.stop

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


def toggle_terminal(camera, enable, toggles, *, phase):
    start_idx = len(camera.dev.packet_log)
    ok = False
    try:
        with probe.deadline(10):
            camera.setTerminalEnable(enable)
        packets = camera.dev.packet_log[start_idx:]
        expected = [TERM_ENABLE_P1, TERM_ENABLE_P2] if enable else [TERM_DISABLE_P1, TERM_DISABLE_P2]
        ok = (
            len(packets) == 2
            and [p["ok"] for p in packets] == [True, True]
            and [(int(p["function"], 16), bytes.fromhex(p["payload"])) for p in packets] == expected
        )
        toggles.append({"phase": phase, "enable": enable, "ok": ok, "packets": list(packets)})
        if not ok:
            raise probe.ProbeError(f"Terminal toggle {phase} did not complete cleanly")
    except BaseException:
        if not toggles or toggles[-1].get("phase") != phase:
            toggles.append({
                "phase": phase,
                "enable": enable,
                "ok": False,
                "packets": list(camera.dev.packet_log[start_idx:]),
            })
        raise


def marker_like(line):
    return bool(line) and (b"__M7_".startswith(line) or line.startswith(b"__M7_"))


class ResponseLines:
    def __init__(self, spec):
        self.command = spec[0].rstrip(b"\n")
        self.marker_seen = False
        self.echo_repaints_removed = 0
        self.pending = bytearray()
        self.soft_parts = []
        self.echo_soft_wraps_removed = 0

    def feed(self, chunk):
        parts = chunk.split(b"\n")
        if len(parts) == 1:
            self.pending.extend(chunk)
            return []
        physical_lines = [bytes(self.pending) + parts[0]] + parts[1:-1]
        self.pending = bytearray(parts[-1])
        lines = []
        for physical in physical_lines:
            if physical.endswith(b"\r\r"):
                self.soft_parts.append(bytes(physical))
                continue
            line = bytes(physical).removesuffix(b"\r")
            if self.soft_parts:
                candidate = b"".join(p[:-2] for p in self.soft_parts) + line
                prefix = candidate[:-len(self.command)] if candidate.endswith(self.command) else None
                repeated = prefix[:-len(SHELL_PROMPT)] if prefix and prefix.endswith(SHELL_PROMPT) else b""
                if (0 < len(repeated) < len(self.command) < 512
                        and b"\r" not in self.command and b"\n" not in self.command
                        and self.command.startswith(repeated)):
                    if self.marker_seen or self.echo_repaints_removed:
                        raise probe.ProbeError("Repeated or late command echo repaint")
                    candidate = candidate[len(repeated):]
                    prefix = SHELL_PROMPT
                    self.echo_repaints_removed += 1
                if prefix in PROMPT_SUFFIXES:
                    lines.append(candidate)
                    self.echo_soft_wraps_removed += len(self.soft_parts)
                else:
                    if any(marker_like(p.rstrip(b"\r")) for p in self.soft_parts):
                        raise probe.ProbeError("Soft-wrapped ACK is not an exact command echo")
                    lines.extend(p.rstrip(b"\r") for p in self.soft_parts)
                    lines.append(line)
                self.soft_parts.clear()
            else:
                lines.append(line)
            self.marker_seen |= any(marker_like(value) for value in lines)
        return lines

    def partial_marker(self):
        return any(marker_like(p.rstrip(b"\r")) for p in (*self.soft_parts, bytes(self.pending)))


class InstallGate:
    """Bounded Senser gate for supervised Phase B install/uninstall (zero external binary deps)."""

    def __init__(self, device, *, allow_writes=False, receipt=None):
        self.device = device
        self.allow_writes = allow_writes
        self.receipt = receipt
        self.next_frame = None
        self.poisoned = False
        self.packet_log = []
        self.terminal_disable_verified = False
        self._disable_step1_ok = False
        self._terminal_open = False
        self.stop_transport = (
            receipt.setdefault("service_stop_transport", make_stop_transport_record())
            if receipt is not None else make_stop_transport_record()
        )
        driver = getattr(self.device, "driver", None)
        orig = getattr(driver, "vendorRequestOut", None)
        if driver is not None and callable(orig) and getattr(orig, "_stage7_stop_info", None) is not self.stop_transport:
            def observed_vro(*args, **kwargs):
                return _record_stop_call(self.stop_transport, driver, orig, args, kwargs)
            observed_vro._stage7_stop_info = self.stop_transport
            driver.vendorRequestOut = observed_vro

    def sendSenserPacket(self, function, payload, output=None):
        pair = (function, payload)
        if pair in PACKETS:
            entry = dict(kind="terminal", function=hex(function), payload=payload.hex(), ok=False, response=None, error=None)
            self.packet_log.append(entry)
            if pair == TERM_ENABLE_P1:
                self._terminal_open = True
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
                self._terminal_open = False
            elif pair == TERM_DISABLE_P2:
                self.terminal_disable_verified = bool(self._disable_step1_ok and res == 0)
                self._disable_step1_ok = False
            return res, data
        if function == 0xFF01:
            if self._terminal_open:
                raise probe.ProbeError("FileControl blocked while terminal is enabled")
            if len(payload) < 4:
                raise probe.ProbeError("Truncated FileControl packet")
            op, size = struct.unpack_from("<HH", payload, 0)
            if size == 0 or 4 + size > len(payload):
                raise probe.ProbeError("Malformed FileControl path length")
            path = payload[4:4 + size].rstrip(b"\0").decode("ascii", errors="strict")
            if op == 2:
                if path not in INSTALL_FC_READ_ALLOW:
                    raise probe.ProbeError(f"FileControl read outside allowlist: {path}")
            elif op == 1:
                if not self.allow_writes or path not in INSTALL_FC_WRITE_ALLOW:
                    raise probe.ProbeError(f"FileControl write outside allowlist: {path}")
            else:
                raise probe.ProbeError(f"FileControl op {op} disallowed in terminal install/uninstall gate")
            with probe.deadline(30):
                status, reply = self.device.sendSenserPacket(function, payload, output)
            if status != 1:
                raise FileControlError(status)
            return status, reply
        raise probe.ProbeError(f"Senser function {function:#x} outside Phase B install allowlist")

    def readTerminal(self):
        return self.device.readTerminal()

    def writeTerminal(self, data):
        if self.poisoned:
            raise probe.ProbeError("Terminal gate poisoned after incomplete ACK")
        if self.next_frame is None or data != self.next_frame:
            raise probe.ProbeError("Unexpected terminal write outside active framed command")
        self.next_frame = None
        return self.device.writeTerminal(data)


class FramedTerminalSession:
    """Byte-preserving framed terminal session matching PhaseBTerminalSession without heavy deps."""

    def __init__(self, camera, receipt):
        self.camera = camera
        self.receipt = receipt

    def command(self, label, command, allowed=(0,), timeout=20):
        index = len(self.receipt["commands"])
        wire, begin, end = frame(command, index, self.receipt["nonce"])
        spec = (wire[:-1], begin, end)
        self.receipt["commands"].append({"step": index, "label": label, "command": command})
        self.camera.dev.next_frame = spec[0]
        raw, lines = bytearray(), []
        normalizer = ResponseLines(spec)
        started = time.monotonic()
        deadline_exceeded = False
        ack_committed_at = None
        clean_ack = False

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
                    end_matches = [
                        (i, re.fullmatch(re.escape(end) + rb"([0-9]+)__", ln))
                        for i, ln in enumerate(lines)
                    ]
                    end_matches = [(i, m) for i, m in end_matches if m]
                    markers = [ln for ln in lines if marker_like(ln)]
                    if (
                        lines.count(begin) != 1
                        or len(end_matches) != 1
                        or lines.index(begin) >= end_matches[0][0]
                        or len(markers) != 2
                        or normalizer.partial_marker()
                    ):
                        raise probe.ProbeError(f"{label}: missing ordered ACK")
                    status = int(end_matches[0][1][1])
                    pending = bytes(normalizer.pending)
                    if lines[ends[0] + 1:] or normalizer.soft_parts or not SHELL_PROMPT.startswith(pending):
                        raise probe.ProbeError(f"{label}: unexpected trailing bytes after ACK")
                    if pending == SHELL_PROMPT:
                        ack_committed_at = check_deadline()
                        phys = bytes(raw).split(b"\n")
                        b_pos = [i for i, pl in enumerate(phys) if pl in (begin, begin + b"\r")]
                        e_pos = [
                            i for i, pl in enumerate(phys)
                            if re.fullmatch(re.escape(end) + rb"[0-9]+__\r?", pl)
                        ]
                        if len(b_pos) != 1 or len(e_pos) != 1 or b_pos[0] >= e_pos[0]:
                            raise probe.ProbeError(f"{label}: malformed physical marker framing")
                        body_bytes = b"\n".join(pl.removesuffix(b"\r") for pl in phys[b_pos[0] + 1:e_pos[0]])
                        clean_ack = True
                        if status not in allowed:
                            raise probe.ProbeError(f"{label}: command exited {status}: {body_bytes!r}")
                        return body_bytes.decode("ascii"), status
                deadline_exceeded = True
                raise probe.ProbeError(f"{label}: missing complete ACK/prompt")
        except BaseException:
            if not clean_ack:
                self.camera.dev.poisoned = True
            raise
        finally:
            elapsed = time.monotonic() - started
            deadline_exceeded = deadline_exceeded or (ack_committed_at is None and elapsed >= timeout)
            self.receipt["steps"].append({
                "step": index,
                "label": label,
                "bytes": len(raw),
                "elapsed_seconds": round(elapsed, 3),
                "deadline_seconds": timeout,
                "deadline_exceeded": deadline_exceeded,
                "ack_committed_at_seconds": round(ack_committed_at, 3) if ack_committed_at is not None else None,
            })


def response(operation, *args):
    try:
        operation(*args)
    except FileControlError as err:
        return err.status
    return 1


def readback(camera, path):
    with probe.BoundedBytes() as sink:
        status = response(camera.readFile, path, sink)
        return status, sink.getvalue()


class DiscardReply:
    def write(self, data):
        return len(data)


def recover(camera, receipt):
    status, version = readback(camera, "/version.txt")
    if (receipt.get("model") != probe.MODEL or receipt.get("service_authenticated") is not True
            or status != 1 or version.rstrip(b"\r\n") != TARGET_BUILD_BYTES):
        raise probe.ProbeError("Recovery requires authenticated M7 firmware 1.00")
    receipt["build"] = BUILD
    receipt["disable_write_status"] = response(camera.writeFile, MARKER, MARKER_BYTES)
    if receipt["disable_write_status"] != 1:
        raise probe.ProbeError("Disable marker write failed")
    status, data = readback(camera, MARKER)
    receipt["disable_read_status"] = status
    if status != 1 or data != MARKER_BYTES:
        raise probe.ProbeError("Disable marker readback failed")
    receipt["disable_marker_written_and_readback"] = True

    status, existing = readback(camera, PRELOAD)
    receipt["preload_pre_delete_read_status"] = status
    if status == 1 and existing.split() != [HOOK.encode("ascii")]:
        raise probe.ProbeError("Preload list differs from the single Phase B entry")
    if status not in (1, 0x82):
        raise probe.ProbeError("Unexpected preload lookup status")

    for path in FILES:
        row = {"path": path, "delete_status": None, "post_delete_read_status": None}
        receipt["files"].append(row)
        row["delete_status"] = response(camera.deleteFile, path)
        row["post_delete_read_status"] = response(camera.readFile, path, DiscardReply())
        if path == PRELOAD and (row["delete_status"], row["post_delete_read_status"]) != (1, 0x82):
            raise probe.ProbeError("Preload removal did not produce the expected responses")


@contextlib.contextmanager
def public_receipt(directory, filename):
    temp = "." + filename + ".partial"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(temp, flags, 0o600, dir_fd=directory), "w", encoding="utf-8") as out:
        inode = os.fstat(out.fileno())
        source = (f"/.vol/{inode.st_dev & 0xffffffff}/{inode.st_ino}" if sys.platform == "darwin"
                  else f"/proc/self/fd/{out.fileno()}")
        try:
            if not os.path.samestat(inode, os.stat(source)):
                raise OSError("Cannot identify receipt staging file")
            try:
                os.stat(filename, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(filename)
            yield out
            out.flush()
            os.fchmod(out.fileno(), 0o644)
            os.fsync(out.fileno())
            os.link(source, filename, dst_dir_fd=directory, follow_symlinks=True)
        finally:
            if names_inode(directory, temp, inode):
                os.unlink(temp, dir_fd=directory)
        os.fsync(directory)


def ensure_receipt_dir():
    RECEIPTS.parent.mkdir(parents=True, exist_ok=True)
    with custody(RECEIPTS.parent) as parent:
        try:
            os.mkdir(RECEIPTS.name, 0o755, dir_fd=parent)
        except FileExistsError:
            pass
        else:
            fd = os.open(RECEIPTS.name, os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fchmod(fd, 0o755)
            finally:
                os.close(fd)


def load_or_create_owner_key(key_path, *, create_if_missing=False):
    p = Path(key_path).expanduser().resolve()
    if p.exists():
        if p.is_symlink() or not p.is_file():
            raise ValueError(f"Owner key must be a regular non-symlink file: {p}")
        key = p.read_bytes()
        if len(key) != 32:
            raise ValueError(f"Owner key must be exactly 32 bytes, got {len(key)}")
        return p, key, False
    if not create_if_missing:
        raise FileNotFoundError(f"Owner key does not exist: {p} (pass --create-owner-key to generate one)")
    for forbidden in (ROOT / "prototype-stage7-persist", ROOT / "scripts", ROOT / "evidence", ROOT / "plans"):
        if p == forbidden.resolve() or p.is_relative_to(forbidden.resolve()):
            raise ValueError(f"Refusing to create owner key inside tracked source tree: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    return p, key, True


def run_dry_run(*, strict_rebuild=False):
    manifest = verify_prebuilt_release(strict_rebuild=strict_rebuild)
    out = {
        "mode": "dry-run",
        "usb_contacted": False,
        "target": manifest["target"],
        "ram_root": manifest["ram_root"],
        "flash_manifest": {
            HOOK: {
                "bytes": manifest["artifacts"]["hook"]["bytes"],
                "sha256": manifest["artifacts"]["hook"]["sha256"],
                "syscalls": manifest["artifacts"]["hook"]["syscalls"],
            },
            READER: {
                "bytes": manifest["artifacts"]["reader"]["bytes"],
                "sha256": manifest["artifacts"]["reader"]["sha256"],
            },
            BOOT_SH: {
                "bytes": manifest["artifacts"]["boot_script"]["bytes"],
                "sha256": manifest["artifacts"]["boot_script"]["sha256"],
            },
            OWNER_KEY: {"bytes": 32, "mode": "0600"},
            PRELOAD: {"line": HOOK, "written_after_live_smoke_test": True},
        },
        "sd_card_ustar": {
            "bytes": manifest["artifacts"]["card_ustar"]["bytes"],
            "sha256": manifest["artifacts"]["card_ustar"]["sha256"],
        },
        "status": "DRY_RUN_OK",
    }
    print(json.dumps(out, indent=2))
    return 0


def run_prep_sd(sd_root, owner_key_path, *, create_owner_key=False, release_seq=1,
                clear_disable_markers=False, strict_rebuild=False):
    root = Path(sd_root).resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"SD card root directory does not exist: {root}")
    repo_root = ROOT.resolve()
    if root == repo_root or repo_root.is_relative_to(root) or root.is_relative_to(repo_root):
        raise ValueError(f"Refusing to treat repository/system path as SD root: {root}")
    if str(root) in ("/", "/Users", "/System", "/Applications", "/tmp", "/var", "/private", "/Volumes"):
        raise ValueError(f"Refusing to write to system root: {root}")

    manifest = verify_prebuilt_release(strict_rebuild=strict_rebuild)
    key_p, key_bytes, created_key = load_or_create_owner_key(owner_key_path, create_if_missing=create_owner_key)
    ustar = (OUT_PERSIST / "card.ustar").read_bytes()
    signed = sign_mlv2_tar(ustar, key_bytes, release_seq=release_seq)
    expected_sha = sha256_bytes(signed)

    removed_markers = []
    remaining_markers = []
    for name in DISABLE_SD_MARKERS:
        mp = root / name
        if mp.exists():
            if clear_disable_markers and mp.is_file() and not mp.is_symlink():
                mp.unlink()
                removed_markers.append(name)
            else:
                remaining_markers.append(name)

    dst = root / "MLV2.TAR"
    tmp = root / "MLV2.TAR.tmp"
    with tmp.open("wb") as f:
        f.write(signed)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, dst)

    readback_bytes = dst.read_bytes()
    if sha256_bytes(readback_bytes) != expected_sha:
        raise RuntimeError("SD MLV2.TAR readback SHA-256 mismatch")

    result = {
        "mode": "prep-sd",
        "status": "SD_PREPARED_OK",
        "sd_root": str(root),
        "owner_key_path": str(key_p),
        "owner_key_created": created_key,
        "owner_key_sha256_prefix": sha256_bytes(key_bytes)[:12],
        "mlv2_tar_path": str(dst),
        "mlv2_tar_bytes": len(readback_bytes),
        "mlv2_tar_sha256": expected_sha,
        "card_ustar_sha256": manifest["artifacts"]["card_ustar"]["sha256"],
        "removed_disable_markers": removed_markers,
        "remaining_disable_markers": remaining_markers,
    }
    print(json.dumps(result, indent=2))
    return 0


@contextlib.contextmanager
def open_terminal(camera, receipt):
    """Open and cleanly close a framed Phase B terminal session with verified disable."""
    session = FramedTerminalSession(camera, receipt)
    enable_attempted = False
    try:
        toggle_terminal(camera, False, receipt["terminal_toggles"], phase="pre_disable")
        enable_attempted = True
        toggle_terminal(camera, True, receipt["terminal_toggles"], phase="enable")
        with probe.deadline(10):
            receipt["shell_banner"] = read_ready(camera).decode("utf8", "replace")
        session.command("disable_histfile", "HISTFILE=/dev/null", allowed=(0,), timeout=10)
        yield session
    finally:
        if enable_attempted:
            receipt["terminal_disable_requested"] = True
            try:
                toggle_terminal(camera, False, receipt["terminal_toggles"], phase="disable")
                receipt["terminal_disable_verified"] = True
            except BaseException as err:
                receipt["terminal_disable_error"] = f"{type(err).__name__}: {err}"
                raise


def _verify_camera_mounts(session, receipt):
    mounts, _ = session.command("read_mounts", "/bin/busybox cat /proc/mounts", allowed=(0,), timeout=12)
    receipt["mounts_raw"] = mounts
    setting_ok = False
    etc_ok = False
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            if parts[1] == "/setting" and parts[2] == "vfat" and "rw" in parts[3].split(","):
                setting_ok = True
            if parts[1] == "/etc" and parts[2] == "vfat" and "rw" in parts[3].split(","):
                etc_ok = True
    if not (setting_ok and etc_ok):
        raise probe.ProbeError("Expected /setting and /etc mounted rw vfat")
    receipt["mounts_verified"] = True


def _install_session(camera, receipt, payloads):
    status, version = readback(camera, "/version.txt")
    if (receipt.get("model") != probe.MODEL or receipt.get("service_authenticated") is not True
            or status != 1 or version.rstrip(b"\r\n") != TARGET_BUILD_BYTES):
        raise probe.ProbeError("Install requires authenticated M7 firmware 1.00")
    receipt["build"] = BUILD

    pre_status, pre_data = readback(camera, PRELOAD)
    receipt["preload_before_status"] = pre_status
    if pre_status == 1:
        receipt["preload_before_lines"] = [
            ln.decode("ascii", errors="replace") for ln in pre_data.splitlines() if ln.strip()
        ]
    elif pre_status == 0x82:
        receipt["preload_before_lines"] = []
    else:
        raise probe.ProbeError(f"Unexpected pre-install preload read status: {pre_status:#x}")

    receipt["staged_files"] = {}
    for dst, blob in payloads:
        tmp_dst = dst + ".new"
        w_status = response(camera.writeFile, tmp_dst, blob)
        if w_status != 1:
            raise probe.ProbeError(f"FileControl write failed for {tmp_dst}: {w_status:#x}")
        r_status, rb = readback(camera, tmp_dst)
        if r_status != 1 or rb != blob:
            raise probe.ProbeError(f"FileControl readback mismatch for {tmp_dst}")
        receipt["staged_files"][dst] = {
            "bytes": len(blob),
            "sha256": sha256_bytes(blob) if dst != OWNER_KEY else "redacted_owner_key",
        }

    with open_terminal(camera, receipt) as session:
        _verify_camera_mounts(session, receipt)
        session.command(
            "chmod_staged",
            f"/bin/busybox chmod 755 {HOOK}.new {BOOT_SH}.new {READER}.new && /bin/busybox chmod 600 {OWNER_KEY}.new",
            allowed=(0,),
            timeout=15,
        )
        session.command(
            "move_staged",
            (
                f"/bin/busybox mv -f {HOOK}.new {HOOK} && /bin/busybox mv -f {BOOT_SH}.new {BOOT_SH} && "
                f"/bin/busybox mv -f {READER}.new {READER} && /bin/busybox mv -f {OWNER_KEY}.new {OWNER_KEY}"
            ),
            allowed=(0,),
            timeout=15,
        )
        moved, _ = session.command(
            "clear_disable",
            f"/bin/busybox rm -f {MARKER} && /bin/busybox sync && echo STAGE_MOVED_OK",
            allowed=(0,),
            timeout=15,
        )
        if moved.strip() != "STAGE_MOVED_OK":
            raise probe.ProbeError(f"Failed moving staged /setting files: {moved!r}")
        receipt["setting_files_installed"] = True

        # MANDATORY LIVE PRE-PRELOAD SMOKE TEST BEFORE WRITING /etc/ld.so.preload!
        smoke, _ = session.command(
            "live_ld_preload_smoke_test",
            f"LD_PRELOAD={HOOK} /bin/busybox sh -c 'echo PRELOAD_SMOKE_OK'",
            allowed=(0,),
            timeout=15,
        )
        receipt["live_preload_smoke_output"] = smoke.strip()
        if smoke.strip() != "PRELOAD_SMOKE_OK":
            raise probe.ProbeError(
                f"Live LD_PRELOAD smoke test failed ({smoke!r}); aborting BEFORE writing {PRELOAD}"
            )
        receipt["live_preload_smoke_passed"] = True

        session.command(
            "backup_preload",
            f"if [ -f {PRELOAD} ] && [ ! -f {PRELOAD_BAK} ]; then /bin/busybox cp -f {PRELOAD} {PRELOAD_BAK}; fi",
            allowed=(0,),
            timeout=15,
        )
        session.command(
            "write_preload_new",
            (
                f": > {PRELOAD}.new && "
                f"if [ -f {PRELOAD} ]; then /bin/busybox grep -vx '{HOOK}' {PRELOAD} >> {PRELOAD}.new || true; fi && "
                f"echo '{HOOK}' >> {PRELOAD}.new"
            ),
            allowed=(0,),
            timeout=15,
        )
        preload_after, _ = session.command(
            "activate_preload",
            f"/bin/busybox chmod 644 {PRELOAD}.new && /bin/busybox mv -f {PRELOAD}.new {PRELOAD} && /bin/busybox sync && /bin/busybox cat {PRELOAD}",
            allowed=(0,),
            timeout=15,
        )
        after_lines = [ln.strip() for ln in preload_after.splitlines() if ln.strip()]
        if HOOK not in after_lines:
            raise probe.ProbeError(f"{PRELOAD} verification missing {HOOK}: {after_lines!r}")
        receipt["preload_after_lines"] = after_lines

        post_smoke, _ = session.command(
            "post_preload_sanity",
            "/bin/busybox echo POST_PRELOAD_OK",
            allowed=(0,),
            timeout=15,
        )
        if post_smoke.strip() != "POST_PRELOAD_OK":
            raise probe.ProbeError(f"Post-preload sanity check failed: {post_smoke!r}")
        receipt["post_preload_sanity_ok"] = True

    fc_status, fc_preload = readback(camera, PRELOAD)
    if fc_status != 1 or HOOK.encode("ascii") not in fc_preload.splitlines():
        raise probe.ProbeError("Final FileControl readback of /etc/ld.so.preload failed")
    receipt["install_verified"] = True


def _uninstall_session(camera, receipt):
    status, version = readback(camera, "/version.txt")
    if (receipt.get("model") != probe.MODEL or receipt.get("service_authenticated") is not True
            or status != 1 or version.rstrip(b"\r\n") != TARGET_BUILD_BYTES):
        raise probe.ProbeError("Uninstall requires authenticated M7 firmware 1.00")
    receipt["build"] = BUILD

    with open_terminal(camera, receipt) as session:
        _verify_camera_mounts(session, receipt)
        session.command(
            "clean_preload",
            (
                f"if [ -f {PRELOAD} ]; then "
                f"/bin/busybox grep -vx '{HOOK}' {PRELOAD} > {PRELOAD}.new || true; "
                f"if [ -s {PRELOAD}.new ]; then /bin/busybox mv -f {PRELOAD}.new {PRELOAD}; "
                f"else /bin/busybox rm -f {PRELOAD}.new {PRELOAD} {PRELOAD_BAK}; fi; fi"
            ),
            allowed=(0,),
            timeout=15,
        )
        session.command(
            "rm_phaseb_files",
            (
                f"/bin/busybox rm -f {HOOK} {HOOK}.new {BOOT_SH} {BOOT_SH}.new "
                f"{READER} {READER}.new {OWNER_KEY} {OWNER_KEY}.new {MARKER} "
                f"{PRECAP_CFG} {PRECAP_CFG_TMP} && /bin/busybox sync"
            ),
            allowed=(0,),
            timeout=15,
        )
        v_out, _ = session.command(
            "verify_uninstall_absence",
            f'ok=1; for f in {HOOK} {BOOT_SH} {READER} {OWNER_KEY} {MARKER} {PRECAP_CFG}; do [ ! -e "$f" ] || ok=0; done; echo ABSENCE_OK=$ok',
            allowed=(0,),
            timeout=15,
        )
        if v_out.strip() != "ABSENCE_OK=1":
            raise probe.ProbeError(f"Post-uninstall absence verification failed: {v_out!r}")
        p_out, _ = session.command(
            "verify_preload_absent",
            f"if [ -f {PRELOAD} ] && /bin/busybox grep -qx '{HOOK}' {PRELOAD}; then echo PRELOAD_STILL_SET; else echo PRELOAD_CLEAN; fi",
            allowed=(0,),
            timeout=15,
        )
        if p_out.strip() != "PRELOAD_CLEAN":
            raise probe.ProbeError(f"Post-uninstall preload check failed: {p_out!r}")
        receipt["uninstall_absence_verified"] = True


def run_install(owner_key_path, *, strict_rebuild=False):
    manifest = verify_prebuilt_release(strict_rebuild=strict_rebuild)
    key_p, key_bytes, _ = load_or_create_owner_key(owner_key_path, create_if_missing=False)
    hook_bytes = (OUT_PERSIST / "mlv2_sd_boot_hook.so").read_bytes()
    boot_sh_bytes = (OUT_PERSIST / "mlv2_sd_boot.sh").read_bytes()
    reader_bytes = (OUT_PERSIST / "mlv2_card_read.elf").read_bytes()
    payloads = [
        (HOOK, hook_bytes),
        (BOOT_SH, boot_sh_bytes),
        (READER, reader_bytes),
        (OWNER_KEY, key_bytes),
    ]

    utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    nonce = secrets.token_hex(6)
    filename = f"{utc}-{nonce}-install.json"
    receipt = dict(
        mode="install",
        utc=utc,
        nonce=nonce,
        owner_key_path=str(key_p),
        owner_key_sha256_prefix=sha256_bytes(key_bytes)[:12],
        card_ustar_sha256=manifest["artifacts"]["card_ustar"]["sha256"],
        commands=[],
        steps=[],
        terminal_toggles=[],
        terminal_disable_verified=False,
        live_preload_smoke_passed=False,
        install_verified=False,
        note=INSTALL_DISCLOSURE,
        service_stop_transport=make_stop_transport_record(),
    )
    ensure_receipt_dir()
    with custody(RECEIPTS) as directory:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with public_receipt(directory, filename) as output:
            try:
                with observe_stop_senser(receipt):
                    probe.connect(
                        receipt,
                        diagnostic=lambda cam, rec: _install_session(cam, rec, payloads),
                        gate_factory=lambda dev: InstallGate(dev, allow_writes=True, receipt=receipt),
                    )
            except (Exception, KeyboardInterrupt) as err:
                receipt["error_type"] = type(err).__name__
                if isinstance(err, probe.ProbeError):
                    receipt["error"] = str(err)
            stop = receipt["service_stop_transport"]
            receipt["service_stop_transport_ok"] = bool(
                receipt.get("service_stop_requested") and not receipt.get("service_stop_error")
                and stop["attempted"] and stop["observed"] and stop["transport_ok"] and not stop["error"]
            )
            receipt["install_ok"] = bool(
                receipt["install_verified"] and receipt["live_preload_smoke_passed"]
                and receipt["terminal_disable_verified"] and "error_type" not in receipt
            )
            json.dump(receipt, output, indent=2, allow_nan=False)
            output.write("\n")
    print(f"RESULT={RECEIPTS / filename}")
    print(f"INSTALL_OK={receipt['install_ok']}")
    print(f"LIVE_PRELOAD_SMOKE_PASSED={receipt['live_preload_smoke_passed']}")
    print(f"SERVICE_STOP_TRANSPORT_OK={receipt['service_stop_transport_ok']}")
    return 0 if receipt["install_ok"] and receipt["service_stop_transport_ok"] else 1


def run_uninstall():
    utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    nonce = secrets.token_hex(6)
    filename = f"{utc}-{nonce}-uninstall.json"
    receipt = dict(
        mode="uninstall",
        utc=utc,
        nonce=nonce,
        commands=[],
        steps=[],
        terminal_toggles=[],
        terminal_disable_verified=False,
        uninstall_absence_verified=False,
        service_stop_transport=make_stop_transport_record(),
    )
    ensure_receipt_dir()
    with custody(RECEIPTS) as directory:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with public_receipt(directory, filename) as output:
            try:
                with observe_stop_senser(receipt):
                    probe.connect(
                        receipt,
                        diagnostic=_uninstall_session,
                        gate_factory=lambda dev: InstallGate(dev, allow_writes=False, receipt=receipt),
                    )
            except (Exception, KeyboardInterrupt) as err:
                receipt["error_type"] = type(err).__name__
                if isinstance(err, probe.ProbeError):
                    receipt["error"] = str(err)
            stop = receipt["service_stop_transport"]
            receipt["service_stop_transport_ok"] = bool(
                receipt.get("service_stop_requested") and not receipt.get("service_stop_error")
                and stop["attempted"] and stop["observed"] and stop["transport_ok"] and not stop["error"]
            )
            receipt["uninstall_ok"] = bool(
                receipt["uninstall_absence_verified"] and receipt["terminal_disable_verified"]
                and "error_type" not in receipt
            )
            json.dump(receipt, output, indent=2, allow_nan=False)
            output.write("\n")
    print(f"RESULT={RECEIPTS / filename}")
    print(f"UNINSTALL_OK={receipt['uninstall_ok']}")
    print(f"SERVICE_STOP_TRANSPORT_OK={receipt['service_stop_transport_ok']}")
    return 0 if receipt["uninstall_ok"] and receipt["service_stop_transport_ok"] else 1


def run_recovery():
    utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    filename = f"{utc}-{secrets.token_hex(8)}-recovery.json"
    receipt = dict(mode=MODE, utc=utc, files=[], disable_marker_written_and_readback=False,
                   filecontrol_unreadable_after_delete=False, absence_certified=False,
                   stock_state="INCONCLUSIVE", note=DISCLOSURE,
                   service_stop_transport=make_stop_transport_record())
    ensure_receipt_dir()
    with custody(RECEIPTS) as directory:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with public_receipt(directory, filename) as output:
            try:
                with observe_stop_senser(receipt):
                    probe.connect(receipt, diagnostic=recover, gate_factory=RecoveryGate)
            except (Exception, KeyboardInterrupt) as err:
                receipt["error_type"] = type(err).__name__
                if isinstance(err, probe.ProbeError):
                    receipt["error"] = str(err)
            rows = receipt["files"]
            complete = (len(rows) == len(FILES) and
                        all(r["post_delete_read_status"] is not None for r in rows))
            unreadable = complete and all(r["post_delete_read_status"] == 0x82 for r in rows)
            receipt["filecontrol_unreadable_after_delete"] = unreadable
            receipt["data_capture_ok"] = complete and receipt["disable_marker_written_and_readback"]
            receipt["recovery_requests_ok"] = (unreadable and "error_type" not in receipt
                                               and all(r["delete_status"] == 1 for r in rows))
            stop = receipt["service_stop_transport"]
            receipt["service_stop_transport_ok"] = bool(
                receipt.get("service_stop_requested") and not receipt.get("service_stop_error")
                and stop["attempted"] and stop["observed"] and stop["transport_ok"] and not stop["error"]
            )
            json.dump(receipt, output, indent=2, allow_nan=False)
            output.write("\n")
    print(f"RESULT={RECEIPTS / filename}")
    for key in ("data_capture_ok", "recovery_requests_ok", "service_stop_transport_ok", "stock_state"):
        print(f"{key.upper()}={receipt[key]}")
    return 0 if receipt["recovery_requests_ok"] and receipt["service_stop_transport_ok"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--mode", choices=ALL_MODES)
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--owner-authorized-flash", action="store_true")
    parser.add_argument("--owner-key", type=Path, help="Path to 32-byte owner HMAC-SHA256 key file")
    parser.add_argument("--create-owner-key", action="store_true", help="Create 32-byte owner key if missing (prep-sd only)")
    parser.add_argument("--sd-root", type=Path, help="Mounted SD card root (e.g. /Volumes/UNTITLED) for prep-sd")
    parser.add_argument("--release-seq", type=int, default=1)
    parser.add_argument("--clear-disable-markers", action="store_true")
    parser.add_argument("--strict-rebuild-verify", action="store_true",
                        help="Also recompile and verify against local extracted M7 firmware (developer mode)")
    args = parser.parse_args(argv)

    if args.self_test:
        return subprocess.run([
            sys.executable, "-B", "-m", "unittest", "discover", "-s",
            str(probe.ROOT / "prototype-stage7-persist"), "-p", "test_stage7_phaseb_persist.py",
        ], cwd=probe.ROOT).returncode

    if args.mode == "dry-run":
        return run_dry_run(strict_rebuild=args.strict_rebuild_verify)

    if args.mode == "prep-sd":
        if args.sd_root is None or args.owner_key is None:
            parser.error("--mode prep-sd requires --sd-root and --owner-key")
        return run_prep_sd(
            args.sd_root,
            args.owner_key,
            create_owner_key=args.create_owner_key,
            release_seq=args.release_seq,
            clear_disable_markers=args.clear_disable_markers,
            strict_rebuild=args.strict_rebuild_verify,
        )

    if not args.owner_authorized_flash:
        parser.error(f"--owner-authorized-flash is required for --mode {args.mode}")

    if args.mode == "install":
        if args.owner_key is None:
            parser.error("--mode install requires --owner-key")
        return run_install(args.owner_key, strict_rebuild=args.strict_rebuild_verify)

    if args.mode == "uninstall":
        return run_uninstall()

    return run_recovery()


if __name__ == "__main__":
    raise SystemExit(main())
