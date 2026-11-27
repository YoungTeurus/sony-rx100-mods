#!/usr/bin/env python3
"""Stage 7.3 Phase B read-only stock boot/gadget collector, power-transition probe, and receipt comparator.

Safety & side-effect transparency contract (DSC-RX100M7 1.00, build 29110_03.2021050601):
- Zero tool-issued flash or SD writes: never issues FileControl WRITE/DELETE, MemoryDump,
  HASP, Backup WRITE, or shell writes outside verified tmpfs /tmp_network.
- Explicit operator consent flags document Sony stock firmware-side bookkeeping:
  1) --extract-boot requires --confirm-phaseb-boot-extract-etools-statfs-and-history:
     - Sony libsencore.so FileControl READ (0x13704 -> 0x16cae) may update /setting/.etools
       (4096 B) if present; up to 25 allowlisted stock paths (zero /setting or /cert files)
       may be read.
     - Running the sealed phaseb_statfs.elf calls statfs64 on /setting, /etc, /system,
       /tmp_network; M7 fat_statfs (0x60222c58 -> 0x602215fc) can mark FAT32 FSInfo dirty
       if free-cluster counts are uncached.
     - BusyBox ash HISTFILE=/dev/null is best-effort on this build.
     - StopSenser transport success does not confirm physical return to normal camera UI.
  2) --transition-probe requires --confirm-phaseb-transition-history:
     - Performs ZERO FileControl operations, ZERO ELF uploads, and ZERO file deletions.
     - BusyBox ash HISTFILE=/dev/null is best-effort on this build.
     - --ram-marker plant creates only one 43-byte token file at /tmp_network/.m7-pb-ret.txt
       via exclusive noclobber creation (set -C) inside verified tmpfs /tmp_network; none and
       check perform zero writes even to /tmp_network. Full battery removal clears volatile tmpfs.
     - StopSenser transport success does not confirm physical return to normal camera UI.
  3) --compare BEFORE.json AFTER.json is 100% offline.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "prototype-stage7-persist"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(PROTO))

import m7_probe as probe  # noqa: E402
import m7_stage7_collect as collect_base  # noqa: E402
import m7_terminal_repaint as terminal  # noqa: E402
from m7_terminal_steps import frame, read_ready  # noqa: E402
import stage7_ram_runner as ram  # noqa: E402

MODEL = "DSC-RX100M7"
BUILD = "29110_03.2021050601"
MAX_FILE_BYTES = 64 * 1024 * 1024
LABEL = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}", re.ASCII)
TRACKED = (1, 154, 160, 161)

EXTRACT_CONSENT = "--confirm-phaseb-boot-extract-etools-statfs-and-history"
TRANSITION_CONSENT = "--confirm-phaseb-transition-history"
INSPECTOR_DIR = PROTO / "out-phaseb"
INSPECTOR_FILENAME = "phaseb_statfs.elf"
INSPECTOR_SHA256 = "1310666d79e0301da773e966d611c4522ac88c3dacbe7cf00b2da69830ebb337"
OUT_RECEIPT_DIR = ROOT / "work/stage7-persist/phaseb-probes"
RAM_MARKER_PATH = "/tmp_network/.m7-pb-ret.txt"
RAM_MARKER_BYTES = 43  # len("M7_PB_MARKER 0123456789ab 20261127T160000Z\n")
RAM_MARKER_TOKEN_RE = re.compile(r"^M7_PB_MARKER ([0-9a-f]{12}) ([0-9]{8}T[0-9]{6}Z)\n$", re.ASCII)

# Fixed read-only allowlist of 25 stock M7 1.00 boot, WBI, USB-gadget, BusyBox, and helper files.
# Zero /setting, /cert, /lens, /log, /etc, or /tmp files are included.
EXTRACT_PATHS = (
    "/version.txt",
    "/bin/busybox",
    "/system/initrd.img",
    "/system/ldr_drv.bin",
    "/system/bonobo.bin",
    "/system/sabin/ssboot.bin",
    "/system/sabin/ssboot_any.bin",
    "/usr/kmod/usbg_sen.ko",
    "/usr/kmod/usbg_cmn.ko",
    "/usr/kmod/usbg_storage.ko",
    "/usr/kmod/usbg_stillimage.ko",
    "/usr/kmod/usbg_buspower.ko",
    "/usr/kmod/usb_buspwr.ko",
    "/usr/kmod/usb_extcmd.ko",
    "/usr/kmod/usb_portMonitor.ko",
    "/usr/kmod/usb_max14648.ko",
    "/usr/kmod/backup.ko",
    "/usr/kmod/mmc_drv.ko",
    "/usr/kmod/mmcioWrapper.ko",
    "/usr/bin/ud_datcnv.elf",
    "/usr/bin/ud_send_lsi.elf",
    "/usr/bin/network.sh",
    "/usr/bin/usb_insmod.sh",
    "/usr/bin/compat_firmware.sh",
    "/usr/bin/swap_prepare.sh",
)

EXTRACT_REQUIRED_PATHS = frozenset((
    "/version.txt",
    "/bin/busybox",
    "/system/initrd.img",
    "/system/sabin/ssboot.bin",
    "/system/sabin/ssboot_any.bin",
    "/usr/kmod/usbg_sen.ko",
    "/usr/kmod/usbg_cmn.ko",
    "/usr/kmod/usbg_storage.ko",
    "/usr/kmod/usbg_stillimage.ko",
    "/usr/kmod/usb_portMonitor.ko",
))

EXTRACT_ELF_PATHS = frozenset(
    p for p in EXTRACT_PATHS
    if p == "/bin/busybox" or p.endswith((".elf", ".ko"))
)

EXTRACT_ANCESTOR_DIRS = tuple(
    sorted(
        {str(parent) for path in EXTRACT_PATHS for parent in Path(path).parents if str(parent) != "/"},
        key=lambda s: (s.count("/"), s),
    )
)

EXTRACT_ANCESTOR_CHECK_CMD = (
    f"rc=0; for d in {' '.join(EXTRACT_ANCESTOR_DIRS)} /tmp_network; do "
    'if [ -L "$d" ] || [ ! -d "$d" ]; then echo "ANC BAD $d"; rc=1; '
    'else echo "ANC OK $d"; fi; done; '
    'if [ -L /version.txt ] || [ ! -f /version.txt ]; then echo "ANC BAD /version.txt"; rc=1; '
    'else echo "ANC OK /version.txt"; fi; [ "$rc" -eq 0 ]'
)

TRANSITION_ANCESTOR_CHECK_CMD = (
    'rc=0; for d in /tmp_network; do '
    'if [ -L "$d" ] || [ ! -d "$d" ]; then echo "ANC BAD $d"; rc=1; '
    'else echo "ANC OK $d"; fi; done; '
    'if [ -L /version.txt ] || [ ! -f /version.txt ]; then echo "ANC BAD /version.txt"; rc=1; '
    'else echo "ANC OK /version.txt"; fi; [ "$rc" -eq 0 ]'
)

SETUP_CMD = "HISTFILE=/dev/null; export HISTFILE; ulimit -c 0 && umask 077"
MOUNTS_CMD = "/bin/busybox cat /proc/mounts"
VERSION_CMD = "/bin/busybox cat /version.txt"
BOOT_ID_CMD = "/bin/busybox cat /proc/sys/kernel/random/boot_id"
UPTIME_CMD = "/bin/busybox cat /proc/uptime"
DATE_CMD = "/bin/busybox date"
CMDLINE_CMD = "/bin/busybox cat /proc/cmdline"
UPM_BOOTMODE_CMD = "/bin/busybox cat /proc/udm/upm_bootmode 2>/dev/null; true"
HOTPLUG_CMD = "/bin/busybox cat /proc/sys/kernel/hotplug 2>/dev/null; true"
DMESG_CMD = "/bin/busybox dmesg"

EXTRACT_LS_CMD = (
    "/bin/busybox ls -la / /system /system/sabin /setting /setting/mode "
    "/setting/updater /etc /tmp_network 2>/dev/null; true"
)
TRANSITION_LS_TMP_CMD = "/bin/busybox ls -lai /tmp_network /tmp_network/dhcpd /tmp_network/run 2>/dev/null; true"
TRANSITION_LS_FLASH_CMD = "/bin/busybox ls -lai /setting /setting/mode /setting/updater /etc 2>/dev/null; true"

# Single-sweep length-prefixed /proc snapshot: captures both wc and cat exit codes (w, c),
# delimits multi-line stat before cmdline with C|, always reads cmdline, and brackets with
# a second stat read (T|c|stat) + E|/proc/<pid> so read failures, PID exit/reuse, 0->nonzero
# growth, and embedded NUL/LF bytes are detected and preserved without silent truncation.
PROC_SNAPSHOT_CMD = (
    'b=/bin/busybox;for p in /proc/[1-9]*;do [ -e "$p/stat" ]||continue;'
    's=$($b cat "$p/stat" 2>/dev/null)||continue;'
    'e=$($b readlink "$p/exe" 2>/dev/null);'
    'o=$($b wc -c "$p/cmdline" 2>/dev/null);w=$?;set -- $o;n=${1:-0};'
    'echo "R|$p|$w|$n|$e";echo "S|$s";echo "C|";'
    '$b cat "$p/cmdline" 2>/dev/null;c=$?;'
    'echo;t=$($b cat "$p/stat" 2>/dev/null);echo "T|$c|$t";echo "E|$p";done'
)

MARKER_STATE_CMD = (
    f"t=/tmp_network;f={RAM_MARKER_PATH};"
    'if [ ! -d "$t" ]||[ -L "$t" ];then echo UNSAFE;'
    'elif [ -L "$f" ];then echo UNSAFE;'
    'elif [ -f "$f" ];then echo REGULAR;'
    'elif [ -e "$f" ];then echo UNSAFE;'
    'else echo ABSENT;fi'
)
# Metadata-only lstat check (zero file data read on camera before host size validation).
MARKER_META_CMD = (
    f"t=/tmp_network;f={RAM_MARKER_PATH};"
    'if [ -d "$t" ]&&[ ! -L "$t" ]&&[ -f "$f" ]&&[ ! -L "$f" ];then '
    '/bin/busybox ls -li "$f";else echo UNSAFE;(exit 1);fi'
)
# Camera-side hard 44-byte read cap (one byte beyond 43-byte token to detect growth).
MARKER_READ_CMD = (
    f"t=/tmp_network;f={RAM_MARKER_PATH};"
    'if [ -d "$t" ]&&[ ! -L "$t" ]&&[ -f "$f" ]&&[ ! -L "$f" ];then '
    '/bin/busybox dd if="$f" bs=1 count=44 2>/dev/null;else echo UNSAFE;(exit 1);fi'
)

STATFS_LINE_RE = re.compile(
    r"^STATFS path=(/[A-Za-z0-9_/-]+) lstat_rc=(-?[0-9]+) dev=([0-9]+):([0-9]+) "
    r"mode=([0-7]+) statfs_rc=(-?[0-9]+) type=0x([0-9a-f]+) "
    r"bsize=([0-9]+) frsize=([0-9]+) blocks=([0-9]+) bfree=([0-9]+) "
    r"bavail=([0-9]+) free_bytes=([0-9]+) total_bytes=([0-9]+)$",
    re.ASCII,
)
STATFS_EXPECTED_PATHS = ("/setting", "/etc", "/system", "/tmp_network")
# Exact BusyBox 1.13.4 coreutils/ls.c:652-658 ctime() slice:
# "%6.6s " (Mmm + space + %2d) followed by "%5.5s" (HH:MM) or " %4.4s" (space + YYYY).
_LS_MTIME_PAT = (
    r"(?:(?:Jan|Mar|May|Jul|Aug|Oct|Dec) (?: [1-9]|[12][0-9]|3[01])"
    r"|(?:Apr|Jun|Sep|Nov) (?: [1-9]|[12][0-9]|30)"
    r"|Feb (?: [1-9]|1[0-9]|2[0-9]))"
    r" (?:(?:[01][0-9]|2[0-3]):[0-5][0-9]| [12][0-9]{3})"
)
LS_MTIME_RE = re.compile(_LS_MTIME_PAT, re.ASCII)


def _is_valid_ls_mtime(text: str) -> bool:
    """Validate exact BusyBox 1.13.4 ls.c:652-658 ctime() 12-char timestamp slice (including leap years)."""
    if not isinstance(text, str) or not LS_MTIME_RE.fullmatch(text):
        return False
    if text.startswith("Feb 29  "):
        year = int(text[8:])
        return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
    return True


LS_DOT_RE = re.compile(
    rf"^\s*([1-9][0-9]*)\s+d\S+\s+\d+\s+\S+\s+\S+\s+\d+\s+({_LS_MTIME_PAT}) \.$",
    re.ASCII,
)
LS_FILE_INODE_RE = re.compile(
    rf"^\s*([1-9][0-9]*)\s+-\S+\s+\d+\s+\S+\s+\S+\s+(\d+)\s+({_LS_MTIME_PAT}) (.+)$",
    re.ASCII,
)
LS_DIR_INODE_RE = re.compile(
    rf"^\s*([1-9][0-9]*)\s+d\S+\s+\d+\s+\S+\s+\S+\s+\d+\s+({_LS_MTIME_PAT}) (.+)$",
    re.ASCII,
)
_S = r"-?[0-9]+"
_U = r"[0-9]+"
# Exact 41-field numeric tail emitted by original M7 do_task_stat (vmlinux.bin VA 0x6045d4f7):
# 5x %d, 7x %u/%lu, 4x %ld, %d, literal 0, 2x %llu/%lu, %ld, 13x %lu, 2x %d, 4x %u/%llu/%lu, %ld.
STAT_TAIL_RE = re.compile(
    " ".join([_S] * 5 + [_U] * 7 + [_S] * 4 + [_S, "0"] + [_U] * 2 + [_S] + [_U] * 13 + [_S] * 2 + [_U] * 4 + [_S]),
    re.ASCII,
)
RACED_REASON_RE = re.compile(
    r"^(?:exited_during_snapshot|cmdline_length_changed|pid_reused:[0-9]+->[0-9]+|"
    r"cmdline_read_error:wc=[0-9]+,cat=[0-9]+|cmdline_length_and_read_error:wc=[0-9]+,cat=[0-9]+)$",
    re.ASCII,
)


class CameraExitError(probe.ProbeError):
    """Cleanly acknowledged shell command returned a disallowed exit status (framing intact)."""

    def __init__(self, label: str, status: int, body: bytes):
        super().__init__(f"{label}: camera shell exited with {status}")
        self.label = label
        self.status = status
        self.body = body


def encode_extract_read_payload(path: str) -> bytes:
    if path not in EXTRACT_PATHS:
        raise probe.ProbeError(f"Path not in Phase B extract allowlist: {path!r}")
    raw = path.encode("ascii")
    padded = raw + b"\x00" * (4 - len(raw) % 4)
    return b"\x02\x00" + len(padded).to_bytes(2, "little") + padded


PHASEB_ALLOWED_FILE_READ_PAYLOADS = frozenset(encode_extract_read_payload(p) for p in EXTRACT_PATHS)


def verify_local_inspector(directory: Path = INSPECTOR_DIR) -> dict:
    manifest = json.loads((directory / "build-phaseb.json").read_text(encoding="utf-8"))
    data = (directory / INSPECTOR_FILENAME).read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    if (
        not isinstance(manifest, dict)
        or manifest.get("target") != f"{MODEL} {BUILD}"
        or manifest.get("file") != INSPECTOR_FILENAME
        or type(manifest.get("bytes")) is not int
        or manifest["bytes"] != len(data)
        or manifest.get("sha256") != INSPECTOR_SHA256
        or sha != INSPECTOR_SHA256
        or manifest.get("md5") != md5
    ):
        raise ValueError("Local filesystem inspector differs from the approved Phase B release")
    return {"bytes": len(data), "sha256": sha, "md5": md5, "data": data}


def validate_host_out_dir(out_dir: Path) -> Path:
    """Refuse symlinks, protected repo/volume ancestors (including case aliases), or existing dirs."""
    candidate = out_dir if out_dir.is_absolute() else (ROOT / out_dir)
    for part in (candidate, *candidate.parents):
        if part.is_symlink():
            raise ValueError(f"Refusing symlink in output directory path: {part}")
    resolved = candidate.resolve(strict=False)
    forbidden_roots = (ROOT / "evidence", ROOT / "sources", Path("/Volumes"))
    ancestors = list(dict.fromkeys((candidate, *candidate.parents, resolved, *resolved.parents)))
    for forbidden in forbidden_roots:
        f_res = forbidden.resolve(strict=False)
        if forbidden.exists():
            for anc in ancestors:
                if anc.exists() and os.path.samefile(anc, forbidden):
                    raise ValueError(f"Refusing protected destination path: {resolved}")
        res_fold = os.path.normcase(str(resolved)).casefold()
        f_fold = os.path.normcase(str(f_res)).casefold()
        if resolved == f_res or resolved.is_relative_to(f_res) or res_fold == f_fold or res_fold.startswith(f_fold + os.sep):
            raise ValueError(f"Refusing protected destination path: {resolved}")
    if candidate.exists() or resolved.exists():
        raise ValueError(f"Output directory already exists: {resolved}")
    return resolved


def _parse_mounts_strict(mounts_text: str) -> dict[str, list[dict]]:
    entries_by_target: dict[str, list[dict]] = {}
    for raw in collect_base._split_ascii_lf_lines(mounts_text, "/proc/mounts"):
        if not raw:
            continue
        parts = raw.split(" ")
        if len(parts) != 6 or any(not p for p in parts):
            raise probe.ProbeError(f"Malformed /proc/mounts line: {raw!r}")
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
        entries_by_target.setdefault(target, []).append({"dev": dev, "fstype": fstype, "opts": opts})
    return entries_by_target


def _verify_common_mounts(entries_by_target: dict[str, list[dict]]) -> dict[str, dict]:
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

    tmp_entries = entries_by_target.get("/tmp_network", [])
    if (
        len(tmp_entries) != 1
        or tmp_entries[0]["fstype"] != "tmpfs"
        or "rw" not in tmp_entries[0]["opts"]
        or "ro" in tmp_entries[0]["opts"]
        or "noexec" in tmp_entries[0]["opts"]
    ):
        raise probe.ProbeError(f"Unexpected /tmp_network mount stack: {tmp_entries!r}")

    return {"/": root_entries[1], "/usr": usr_entries[0], "/tmp_network": tmp_entries[0]}


def verify_extract_mounts(mounts_text: str) -> dict[str, dict]:
    entries = _parse_mounts_strict(mounts_text)
    verified = _verify_common_mounts(entries)

    sys_entries = entries.get("/system", [])
    if (
        len(sys_entries) != 1
        or sys_entries[0]["dev"] != "/dev/nflasha3"
        or sys_entries[0]["fstype"] != "vfat"
    ):
        raise probe.ProbeError(f"Unexpected /system mount stack: {sys_entries!r}")
    verified["/system"] = sys_entries[0]

    forbidden_targets = [d for d in EXTRACT_ANCESTOR_DIRS if d not in ("/usr", "/system")] + list(EXTRACT_PATHS)
    for target in forbidden_targets:
        if target in entries:
            raise probe.ProbeError(f"Unexpected mount over allowlisted path {target}: {entries[target]!r}")
    return verified


def verify_transition_mounts(mounts_text: str) -> dict[str, dict]:
    entries = _parse_mounts_strict(mounts_text)
    verified = _verify_common_mounts(entries)
    for target in ("/version.txt", RAM_MARKER_PATH):
        if target in entries:
            raise probe.ProbeError(f"Unexpected mount over {target}: {entries[target]!r}")
    return verified


def verify_extract_transfer(path: str, sink: collect_base.BoundedSink, sizes: dict, md5s: dict, first4: bytes) -> None:
    if path not in sizes or path not in md5s:
        raise probe.ProbeError(f"{path}: missing camera wc -c or md5sum witness")
    if sink.bytes <= 0 or sink.bytes != sizes[path]:
        raise probe.ProbeError(f"{path}: size mismatch host={sink.bytes} camera={sizes[path]}")
    if sink.md5.hexdigest() != md5s[path]:
        raise probe.ProbeError(f"{path}: MD5 mismatch host={sink.md5.hexdigest()} camera={md5s[path]}")
    if path in EXTRACT_ELF_PATHS and first4 != b"\x7fELF":
        raise probe.ProbeError(f"{path}: expected ELF magic, got {first4!r}")


def parse_statfs_output(text: str, *, expect_ok: bool = True) -> dict[str, dict]:
    parsed: dict[str, dict] = {}
    for raw in collect_base._split_ascii_lf_lines(text, "phaseb_statfs output"):
        if not raw:
            continue
        m = STATFS_LINE_RE.fullmatch(raw)
        if not m:
            raise probe.ProbeError(f"Malformed phaseb_statfs line: {raw!r}")
        path = m[1]
        if path not in STATFS_EXPECTED_PATHS or path in parsed:
            raise probe.ProbeError(f"Unexpected or duplicate phaseb_statfs path: {path!r}")
        row = {
            "lstat_rc": int(m[2]),
            "dev_major": int(m[3]),
            "dev_minor": int(m[4]),
            "mode_octal": m[5],
            "statfs_rc": int(m[6]),
            "type_hex": f"0x{m[7]}",
            "bsize": int(m[8]),
            "frsize": int(m[9]),
            "blocks": int(m[10]),
            "bfree": int(m[11]),
            "bavail": int(m[12]),
            "free_bytes": int(m[13]),
            "total_bytes": int(m[14]),
        }
        if expect_ok:
            if row["lstat_rc"] != 0 or row["statfs_rc"] != 0:
                raise probe.ProbeError(f"Nonzero statfs row status for {path}: {row!r}")
            if row["free_bytes"] != row["bfree"] * row["bsize"] or row["total_bytes"] != row["blocks"] * row["bsize"]:
                raise probe.ProbeError(f"Inconsistent byte capacity product for {path}: {row!r}")
        parsed[path] = row
    missing = [p for p in STATFS_EXPECTED_PATHS if p not in parsed]
    if missing:
        raise probe.ProbeError(f"Missing phaseb_statfs rows for: {missing}")
    return parsed


def parse_tmp_network_ls(text: str) -> dict:
    in_tmp_section = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.endswith(":") and stripped.startswith("/"):
            in_tmp_section = stripped[:-1]
            continue
        if in_tmp_section in (None, "/tmp_network"):
            m = LS_DOT_RE.fullmatch(line)
            if m and _is_valid_ls_mtime(m[2]):
                return {"inode": int(m[1]), "mtime": m[2]}
    raise probe.ProbeError("Could not parse /tmp_network '.' inode and mtime from ls -lai")


def _parse_stat_fields(stat_text: str, expected_pid: int | None = None) -> tuple[int, list[int]]:
    """Strictly parse M7 /proc/<pid>/stat: <=15-byte comm (get_task_comm 0x601c3fb4), single-line integer tail."""
    match = re.fullmatch(r"([1-9][0-9]*) \((.*)\) ([A-Za-z]) ([^\r\n]+)", stat_text, re.S)
    if not match:
        raise ValueError(f"Malformed /proc/PID/stat: {stat_text!r}")
    pid = int(match[1])
    if expected_pid is not None and pid != expected_pid:
        raise ValueError(f"Mismatched PID in /proc/{expected_pid}/stat: {stat_text!r}")
    if len(match[2].encode("latin-1")) > 15:
        raise ValueError(f"Overlong comm (>15 B) in /proc/{pid}/stat: {stat_text!r}")
    tail = match[4]
    if not STAT_TAIL_RE.fullmatch(tail):
        raise ValueError(f"Malformed numeric tail in /proc/{pid}/stat: {stat_text!r}")
    return pid, [int(tok) for tok in tail.split(" ")]


def _parse_stat_starttime(stat_text: str, expected_pid: int) -> int:
    try:
        _, values = _parse_stat_fields(stat_text, expected_pid=expected_pid)
    except ValueError as err:
        raise probe.ProbeError(str(err)) from err
    return values[22 - 4]


def parse_proc_snapshot_bytes(raw: bytes) -> tuple[list[dict], list[dict]]:
    """Parse exact byte-level single-sweep /proc snapshot without truncating NUL or LF.

    Returns (rows, raced_pids). Fails closed on any malformed record, any cmdline read error
    on a tracked PID, or if any tracked PID (1, 154, 160, 161) is missing or raced.
    """
    rows: list[dict] = []
    raced: list[dict] = []
    seen: set[int] = set()
    pos = 0
    total = len(raw)

    def read_line(at: int) -> tuple[bytes, int]:
        nl = raw.find(b"\n", at)
        if nl == -1:
            return raw[at:], total
        return raw[at:nl], nl + 1

    def parse_t_block(t_block: bytes, pid: int) -> tuple[int, str]:
        if not t_block.startswith(b"T|"):
            raise probe.ProbeError(f"Malformed T| trailer for PID {pid}: {t_block!r}")
        t_parts = t_block.split(b"|", 2)
        if len(t_parts) != 3 or not re.fullmatch(rb"[0-9]+", t_parts[1]):
            raise probe.ProbeError(f"Malformed T| status for PID {pid}: {t_block!r}")
        cat_rc = int(t_parts[1])
        stat_after = t_parts[2].decode("latin-1")
        if stat_after:
            _parse_stat_starttime(stat_after, pid)
        return cat_rc, stat_after

    while pos < total:
        # Skip only trailing empty separator line at EOF.
        if pos == total - 1 and raw[pos:pos + 1] == b"\n":
            break
        hdr, pos = read_line(pos)
        if not hdr.startswith(b"R|/proc/"):
            raise probe.ProbeError(f"Malformed proc snapshot header at byte {pos}: {hdr!r}")
        parts = hdr.split(b"|", 4)
        if len(parts) != 5 or not parts[1].startswith(b"/proc/"):
            raise probe.ProbeError(f"Malformed proc header fields: {hdr!r}")
        pid_bytes = parts[1][6:]
        if not re.fullmatch(rb"[1-9][0-9]*", pid_bytes):
            raise probe.ProbeError(f"Invalid PID in proc header: {hdr!r}")
        pid = int(pid_bytes)
        if pid in seen:
            raise probe.ProbeError(f"Duplicate PID {pid} in proc snapshot")
        seen.add(pid)
        if not re.fullmatch(rb"[0-9]+", parts[2]):
            raise probe.ProbeError(f"Invalid wc exit status for PID {pid}: {parts[2]!r}")
        wc_rc = int(parts[2])
        if not re.fullmatch(rb"\s*[0-9]+\s*", parts[3]):
            raise probe.ProbeError(f"Invalid cmdline byte length for PID {pid}: {parts[3]!r}")
        cmd_len = int(parts[3].strip())
        if cmd_len > 4096:
            raise probe.ProbeError(f"Unbounded cmdline length {cmd_len} for PID {pid}")
        exe_bytes = parts[4]

        # Read S|<stat_before> (supports multi-line comm up to the C| delimiter).
        s_lines: list[bytes] = []
        found_c = False
        while pos < total:
            line, pos = read_line(pos)
            if line == b"C|":
                found_c = True
                break
            s_lines.append(line)
        if not found_c or not s_lines or not s_lines[0].startswith(b"S|"):
            raise probe.ProbeError(f"Missing S|/C| stat block for PID {pid}: {s_lines!r}")
        stat_before = b"\n".join(s_lines)[2:].decode("latin-1")
        st_before_tick = _parse_stat_starttime(stat_before, pid)

        end_marker = f"E|/proc/{pid}".encode("ascii")
        raced_reason = None
        cmdline_raw = b""

        # Fast path: exact cmd_len bytes followed by LF + T|<c>|<stat_after> + E|/proc/<pid>.
        matched_exact = False
        if pos + cmd_len < total and raw[pos + cmd_len:pos + cmd_len + 1] == b"\n":
            cand_cmd = raw[pos:pos + cmd_len]
            after_cmd = pos + cmd_len + 1
            if raw[after_cmd:after_cmd + 2] == b"T|":
                # Locate E|/proc/<pid> following T| (supports multi-line comm in stat_after).
                t_lines: list[bytes] = []
                scan = after_cmd
                found_e = False
                while scan < total:
                    t_ln, scan = read_line(scan)
                    if t_ln == end_marker:
                        found_e = True
                        break
                    t_lines.append(t_ln)
                if found_e and t_lines:
                    cat_rc, stat_after = parse_t_block(b"\n".join(t_lines), pid)
                    pos = scan
                    matched_exact = True
                    if wc_rc != 0 or cat_rc != 0:
                        raced_reason = f"cmdline_read_error:wc={wc_rc},cat={cat_rc}"
                    elif not stat_after:
                        raced_reason = "exited_during_snapshot"
                    else:
                        st_after_tick = _parse_stat_starttime(stat_after, pid)
                        if st_after_tick != st_before_tick:
                            raced_reason = f"pid_reused:{st_before_tick}->{st_after_tick}"
                        else:
                            cmdline_raw = cand_cmd

        if not matched_exact:
            # Re-synchronize strictly to E|/proc/<pid> and validate the T|<c>|<stat_after> block.
            needle = b"\n" + end_marker + b"\n"
            idx = raw.find(needle, pos)
            if idx == -1 and raw[pos:].endswith(b"\n" + end_marker):
                idx = total - len(end_marker) - 1
                next_pos = total
            elif idx != -1:
                next_pos = idx + len(needle)
            else:
                raise probe.ProbeError(f"Malformed/unterminated proc record for PID {pid}")
            block = raw[pos:idx]
            t_pos = block.rfind(b"\nT|")
            if t_pos != -1:
                t_block = block[t_pos + 1:]
            elif block.startswith(b"T|"):
                t_block = block
            else:
                raise probe.ProbeError(f"Malformed T| trailer for PID {pid}: {block!r}")
            cat_rc, _stat_after = parse_t_block(t_block, pid)
            pos = next_pos
            if wc_rc != 0 or cat_rc != 0:
                raced_reason = f"cmdline_length_and_read_error:wc={wc_rc},cat={cat_rc}"
            else:
                raced_reason = "cmdline_length_changed"

        if raced_reason is not None:
            raced.append({"pid": pid, "reason": raced_reason, "starttime_before": st_before_tick})
            continue

        rows.append({
            "pid": pid,
            "exe": exe_bytes.decode("utf-8", "replace"),
            "exe_b64": base64.b64encode(exe_bytes).decode("ascii"),
            "stat": stat_before,
            "cmdline": cmdline_raw.decode("utf-8", "replace"),
            "cmdline_b64": base64.b64encode(cmdline_raw).decode("ascii"),
            "cmdline_bytes": len(cmdline_raw),
        })

    rows.sort(key=lambda r: r["pid"])
    if not rows:
        raise probe.ProbeError("Empty /proc process snapshot")
    raced_tracked = [r for r in raced if r["pid"] in TRACKED]
    if raced_tracked:
        raise probe.ProbeError(f"Tracked PID raced during snapshot: {raced_tracked!r}")
    present_pids = {r["pid"] for r in rows}
    missing_tracked = [p for p in TRACKED if p not in present_pids]
    if missing_tracked:
        raise probe.ProbeError(f"Tracked PID(s) missing from snapshot: {missing_tracked}")
    process_table(rows)
    return rows, raced


class PhaseBCollectGate(collect_base.Stage7CollectGate):
    """Parameterised read-only Senser gate; blocks all FileControl unless explicitly allowlisted."""

    def __init__(self, device, allowed_file_read_payloads: frozenset[bytes], receipt=None):
        super().__init__(device, receipt=receipt)
        self.allowed_file_read_payloads = frozenset(allowed_file_read_payloads)

    def sendSenserPacket(self, function, payload, output=None):
        pair = (function, payload)
        if pair in collect_base.PACKETS:
            return super().sendSenserPacket(function, payload, output)
        if function == 0xFF01 and payload in self.allowed_file_read_payloads:
            if not self.terminal_disable_verified:
                raise probe.ProbeError("FileControl blocked: terminal disable not verified")
            entry = {
                "kind": "file_read",
                "function": hex(function),
                "payload_len": len(payload),
                "ok": False,
                "response": None,
                "error": None,
            }
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


class PhaseBTerminalSession:
    """Byte-preserving framed terminal session that only poisons the gate on framing/transport loss.

    When a command receives a complete ordered ACK and shell prompt, returning a disallowed
    shell exit code raises CameraExitError WITHOUT poisoning the gate so finally-block cleanup
    commands still execute cleanly.
    """

    def __init__(self, camera, receipt: dict):
        self.camera = camera
        self.receipt = receipt

    def command_bytes(self, label: str, command: str, allowed=(0,), timeout: int = 20) -> tuple[bytes, int]:
        index = len(self.receipt["commands"])
        wire, begin, end = frame(command, index, self.receipt["nonce"])
        spec = (wire[:-1], begin, end)
        self.receipt["commands"].append({"step": index, "label": label, "command": command})
        self.camera.dev.next_frame = spec[0]
        raw, lines = bytearray(), []
        normalizer = terminal.ResponseLines(spec)
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
                    # Validate ACK directly on raw byte lines without lossy UTF-8 replacement.
                    end_matches = [
                        (i, re.fullmatch(re.escape(end) + rb"([0-9]+)__", ln))
                        for i, ln in enumerate(lines)
                    ]
                    end_matches = [(i, m) for i, m in end_matches if m]
                    markers = [ln for ln in lines if terminal.marker_like(ln)]
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
                    if lines[ends[0] + 1:] or normalizer.soft_parts or not terminal.SHELL_PROMPT.startswith(pending):
                        raise probe.ProbeError(f"{label}: unexpected trailing bytes after ACK")
                    if pending == terminal.SHELL_PROMPT:
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
                            raise CameraExitError(label, status, body_bytes)
                        return body_bytes, status
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

    def command(self, label: str, command: str, allowed=(0,), timeout: int = 20) -> tuple[str, int]:
        body_bytes, status = self.command_bytes(label, command, allowed=allowed, timeout=timeout)
        try:
            return body_bytes.decode("ascii"), status
        except UnicodeDecodeError as err:
            raise probe.ProbeError(f"{label}: unexpected non-ASCII byte in text output: {err}") from err


def _make_marker_plant_cmd(token: str) -> str:
    if not re.fullmatch(r"M7_PB_MARKER [0-9a-f]{12} [0-9]{8}T[0-9]{6}Z", token, re.ASCII):
        raise ValueError(f"Invalid marker token: {token!r}")
    return (
        f"t=/tmp_network;f={RAM_MARKER_PATH};"
        'if [ -d "$t" ]&&[ ! -L "$t" ]&&[ ! -e "$f" ]&&[ ! -L "$f" ];then '
        f"(set -C;/bin/busybox echo '{token}' > \"$f\")&&echo PLANTED||echo ERR;"
        'else echo REFUSED;(exit 1);fi'
    )


def _parse_marker_ls_meta(meta_body: str) -> tuple[dict | None, dict | None]:
    meta_lines = [ln for ln in meta_body.splitlines() if ln.strip()]
    if len(meta_lines) != 1:
        return None, {"state": "UNSAFE", "reason": "malformed_meta_lines"}
    m_ls = LS_FILE_INODE_RE.fullmatch(meta_lines[0])
    if not m_ls or not _is_valid_ls_mtime(m_ls[3]):
        return None, {"state": "UNSAFE", "reason": "unparseable_meta"}
    if m_ls[4] != RAM_MARKER_PATH:
        return None, {"state": "UNSAFE", "reason": "ls_path_mismatch", "observed_path": m_ls[4]}
    reported_size = int(m_ls[2])
    if reported_size != RAM_MARKER_BYTES:
        return None, {"state": "UNSAFE", "reason": "unexpected_size", "bytes": reported_size}
    return {"inode": int(m_ls[1]), "bytes": reported_size, "mtime": m_ls[3], "path": m_ls[4]}, None


def _inspect_ram_marker(session: PhaseBTerminalSession, tag: str) -> dict:
    """Strictly validate marker metadata (zero read), bounded 44-byte read, and post-read inode stability."""
    state_body, _ = session.command(f"marker_state_{tag}", MARKER_STATE_CMD, allowed=(0,), timeout=12)
    state = state_body.strip()
    if state not in ("REGULAR", "ABSENT", "UNSAFE"):
        return {"state": "UNSAFE", "reason": "unexpected_state_token", "raw_state": state}
    if state != "REGULAR":
        return {"state": state}

    meta_body, _ = session.command(f"marker_meta_{tag}", MARKER_META_CMD, allowed=(0,), timeout=12)
    meta_before, err = _parse_marker_ls_meta(meta_body)
    if err is not None:
        return err

    content_bytes, _ = session.command_bytes(f"marker_read_{tag}", MARKER_READ_CMD, allowed=(0,), timeout=12)
    if len(content_bytes) != RAM_MARKER_BYTES:
        return {
            "state": "UNSAFE",
            "reason": "content_size_mismatch",
            "bytes": meta_before["bytes"],
            "actual_bytes": len(content_bytes),
        }
    try:
        content = content_bytes.decode("ascii")
    except UnicodeDecodeError:
        return {"state": "UNSAFE", "reason": "non_ascii_marker"}
    if not RAM_MARKER_TOKEN_RE.fullmatch(content):
        return {"state": "UNSAFE", "reason": "invalid_marker_token"}

    meta_after_body, _ = session.command(f"marker_meta_verify_{tag}", MARKER_META_CMD, allowed=(0,), timeout=12)
    meta_after, err_after = _parse_marker_ls_meta(meta_after_body)
    if err_after is not None:
        return err_after
    if meta_after != meta_before:
        return {
            "state": "UNSAFE",
            "reason": "marker_mutated_during_read",
            "before": meta_before,
            "after": meta_after,
        }

    return {
        "state": "REGULAR",
        "path": RAM_MARKER_PATH,
        "inode": meta_before["inode"],
        "bytes": meta_before["bytes"],
        "mtime": meta_before["mtime"],
        "md5": hashlib.md5(content_bytes).hexdigest(),
        "content": content,
    }


def _make_statfs_cleanup_cmd(stage_dir: str, expected_inode: int) -> str:
    """Unlink our 3 known files inside a cwd-pinned directory inode, then rmdir the empty dir.

    Pinning cwd via `cd "$d"` before verifying `ls -ldi .` ensures `rm -f ./statfs.*` never
    deletes files in a different-inode replacement directory; `rmdir "$d"` is re-checked with
    `ls -ldi "$d"` and only succeeds on an empty directory (POSIX Linux 2.6 has no frmdir(fd)).
    """
    if not re.fullmatch(r"/tmp_network/\.m7-pb-[0-9a-f]{12}", stage_dir, re.ASCII):
        raise ValueError(f"Invalid statfs staging directory: {stage_dir!r}")
    if type(expected_inode) is not int or expected_inode <= 0:
        raise ValueError(f"Invalid statfs staging inode: {expected_inode!r}")
    return (
        f"b=/bin/busybox;t=/tmp_network;d={stage_dir};"
        '[ -d "$t" ]&&[ ! -L "$t" ]&&[ -d "$d" ]&&[ ! -L "$d" ]&&'
        f'(cd "$d"&&set -- $($b ls -ldi .)&&[ "$1" = "{expected_inode}" ]&&'
        '$b rm -f ./statfs.elf.gz ./statfs.elf ./statfs.out)&&'
        f'(set -- $($b ls -ldi "$d")&&[ "$1" = "{expected_inode}" ]&&$b rmdir "$d")'
    )


def _upload_and_run_statfs(session: PhaseBTerminalSession, inspector: dict, receipt: dict) -> dict[str, dict]:
    nonce = receipt["nonce"]
    stage_dir = f"/tmp_network/.m7-pb-{nonce}"
    gz_path = f"{stage_dir}/statfs.elf.gz"
    elf_path = f"{stage_dir}/statfs.elf"
    out_path = f"{stage_dir}/statfs.out"
    recovery_hint = (
        f"Verify {stage_dir} is absent in a fresh diagnostic session "
        "(or after full battery removal) rather than assuming an ordinary power-switch cycle clears tmpfs."
    )

    elf_bytes: bytes = inspector["data"]
    gz_bytes = gzip.compress(elf_bytes, compresslevel=9, mtime=0)
    gz_md5 = hashlib.md5(gz_bytes).hexdigest()

    body, _ = session.command(
        "statfs_stage_clean",
        f"[ -d /tmp_network ]&&[ ! -L /tmp_network ]&&[ ! -e {stage_dir} ]&&[ ! -L {stage_dir} ]&&echo CLEAN||echo DIRTY",
        allowed=(0,),
        timeout=12,
    )
    if body.strip() != "CLEAN":
        raise probe.ProbeError(f"Refusing dirty or unsafe statfs stage path: {body.strip()!r}")

    stage_state = "NOT_CREATED"
    stage_inode: int | None = None
    try:
        # Transition to UNKNOWN_CREATE BEFORE transmitting mkdir so lost ACKs cannot skip status reporting.
        stage_state = "UNKNOWN_CREATE"
        try:
            session.command("statfs_mkdir", f"/bin/busybox mkdir {stage_dir}", allowed=(0,), timeout=12)
        except CameraExitError:
            # Cleanly acknowledged non-zero mkdir exit means we did NOT create stage_dir; never delete it.
            stage_state = "NOT_CREATED"
            receipt["statfs_cleanup"] = "NOT_CREATED"
            raise
        stage_state = "OWNED_UNVERIFIED_INODE"

        chk, _ = session.command(
            "statfs_dir_check",
            f"[ -d {stage_dir} ]&&[ ! -L {stage_dir} ]&&[ ! -e {gz_path} ]&&[ ! -L {gz_path} ]&&/bin/busybox ls -ldi {stage_dir}",
            allowed=(0,),
            timeout=12,
        )
        chk_lines = [ln for ln in chk.splitlines() if ln.strip()]
        m_dir = LS_DIR_INODE_RE.fullmatch(chk_lines[0]) if len(chk_lines) == 1 else None
        if not m_dir or not _is_valid_ls_mtime(m_dir[2]) or m_dir[3] != stage_dir:
            raise probe.ProbeError(f"Unsafe or unparseable statfs staging directory: {chk!r}")
        stage_inode = int(m_dir[1])
        receipt["statfs_stage_inode"] = stage_inode
        stage_state = "OWNED"

        base_idx = len(receipt["commands"])
        chunks = ram.plan_upload_chunks(gz_bytes, gz_path, encoded=False, base_cmd_idx=base_idx, nonce=nonce)
        for i, chunk in enumerate(chunks):
            cmd = ram.upload_chunk_command(chunk, gz_path, encoded=False, first=(i == 0))
            session.command(f"statfs_gz_{i:02d}", cmd, allowed=(0,), timeout=12)

        gz_sz, _ = session.command("statfs_gz_wc", f"/bin/busybox wc -c {gz_path}", allowed=(0,), timeout=12)
        gz_md, _ = session.command("statfs_gz_md5", f"/bin/busybox md5sum {gz_path}", allowed=(0,), timeout=12)
        if gz_sz.strip().split()[:1] != [str(len(gz_bytes))] or gz_md.strip() != f"{gz_md5}  {gz_path}":
            raise probe.ProbeError(f"Uploaded statfs.elf.gz mismatch: sz={gz_sz!r} md5={gz_md!r}")

        session.command("statfs_gunzip", f"/bin/busybox gunzip {gz_path}", allowed=(0,), timeout=15)
        elf_sz, _ = session.command("statfs_elf_wc", f"/bin/busybox wc -c {elf_path}", allowed=(0,), timeout=12)
        elf_md, _ = session.command("statfs_elf_md5", f"/bin/busybox md5sum {elf_path}", allowed=(0,), timeout=12)
        if elf_sz.strip().split()[:1] != [str(inspector["bytes"])] or elf_md.strip() != f"{inspector['md5']}  {elf_path}":
            raise probe.ProbeError(f"Unpacked statfs.elf mismatch: sz={elf_sz!r} md5={elf_md!r}")

        session.command("statfs_chmod", f"/bin/busybox chmod 700 {elf_path}", allowed=(0,), timeout=12)
        _, run_rc = session.command("statfs_exec", f"{elf_path} > {out_path}", allowed=(0, 1), timeout=15)
        receipt["statfs_exec_rc"] = run_rc
        out_text, _ = session.command(
            "statfs_read",
            f"[ -f {out_path} ]&&[ ! -L {out_path} ]&&/bin/busybox cat {out_path}",
            allowed=(0,),
            timeout=12,
        )
        receipt["statfs_raw"] = out_text
        parsed = parse_statfs_output(out_text, expect_ok=(run_rc == 0))
        receipt["statfs"] = parsed
        if run_rc != 0:
            raise probe.ProbeError(f"phaseb_statfs.elf exited with rc={run_rc}")
        return parsed
    finally:
        if stage_state in ("UNKNOWN_CREATE", "OWNED_UNVERIFIED_INODE", "OWNED"):
            if getattr(session.camera.dev, "poisoned", False) or stage_state == "UNKNOWN_CREATE":
                receipt["statfs_cleanup"] = "POISONED_SESSION_UNVERIFIED"
                receipt["statfs_cleanup_recovery_hint"] = (
                    f"Terminal framing was lost while {stage_dir} creation/cleanup state was unknown. {recovery_hint}"
                )
            elif stage_state == "OWNED_UNVERIFIED_INODE" or stage_inode is None:
                receipt["statfs_cleanup"] = "UNSAFE_STAGE_NOT_DELETED"
                receipt["statfs_cleanup_recovery_hint"] = (
                    f"Staging directory {stage_dir} failed post-mkdir identity verification and was not deleted. {recovery_hint}"
                )
            else:
                try:
                    session.command("statfs_rm", _make_statfs_cleanup_cmd(stage_dir, stage_inode), allowed=(0,), timeout=12)
                    gone, _ = session.command(
                        "statfs_gone",
                        f"[ ! -e {stage_dir} ]&&[ ! -L {stage_dir} ]&&echo GONE||echo DIRTY",
                        allowed=(0,),
                        timeout=12,
                    )
                    receipt["statfs_cleanup"] = gone.strip()
                    if receipt["statfs_cleanup"] != "GONE":
                        receipt["statfs_cleanup_recovery_hint"] = recovery_hint
                except BaseException as err:
                    if getattr(session.camera.dev, "poisoned", False):
                        receipt["statfs_cleanup"] = "POISONED_SESSION_UNVERIFIED"
                        receipt["statfs_cleanup_error"] = f"{type(err).__name__}: {err}"
                        receipt["statfs_cleanup_recovery_hint"] = (
                            f"Terminal framing was lost during cleanup of {stage_dir}. {recovery_hint}"
                        )
                    else:
                        receipt["statfs_cleanup"] = f"ERROR: {type(err).__name__}: {err}"
                        receipt["statfs_cleanup_recovery_hint"] = recovery_hint


def extract_boot_diagnostic(camera, receipt: dict, inspector: dict) -> None:
    if receipt.get("model") != MODEL:
        raise probe.ProbeError(f"Unsupported model: {receipt.get('model')!r}")

    receipt.setdefault("terminal_toggles", [])
    receipt["ancestors_verified"] = False
    receipt["mounts_verified"] = False
    receipt["terminal_disable_verified"] = False
    receipt["terminal_disable_sent"] = False
    receipt["all_files_verified"] = False

    destination = validate_host_out_dir(Path(receipt["collection_directory"]))
    destination.mkdir(parents=True, exist_ok=False)

    session = PhaseBTerminalSession(camera, receipt)
    enable_attempted = False
    terminal_disabled = False
    terminal_disable_error = None
    inventory_sections: list[str] = []
    witness = None

    try:
        collect_base.toggle_terminal(camera, False, receipt["terminal_toggles"], phase="pre_disable")
        enable_attempted = True
        collect_base.toggle_terminal(camera, True, receipt["terminal_toggles"], phase="enable")
        with probe.deadline(10):
            receipt["shell_banner"] = read_ready(camera).decode("utf8", "replace")

        pre_cmds = (
            ("setup", SETUP_CMD, (0,), 15, False),
            ("mounts", MOUNTS_CMD, (0,), 20, False),
            ("check_ancestors", EXTRACT_ANCESTOR_CHECK_CMD, (0,), 20, False),
            ("version", VERSION_CMD, (0,), 15, False),
            ("boot_id", BOOT_ID_CMD, (0,), 15, False),
            ("uptime", UPTIME_CMD, (0,), 15, False),
            ("cmdline", CMDLINE_CMD, (0,), 15, False),
            ("upm_bootmode", UPM_BOOTMODE_CMD, (0,), 15, False),
            ("hotplug", HOTPLUG_CMD, (0,), 15, False),
            ("ls_boot", EXTRACT_LS_CMD, (0,), 20, True),
            ("dmesg", DMESG_CMD, (0,), 45, True),
        )
        for label, cmd, allowed, timeout, raw_mode in pre_cmds:
            if label == "check_ancestors" and not receipt["mounts_verified"]:
                raise probe.ProbeError("Refusing ancestor check before mount verification")
            if label == "version" and (not receipt["mounts_verified"] or not receipt["ancestors_verified"]):
                raise probe.ProbeError("Refusing version read before mount and ancestor verification")
            if raw_mode:
                raw_body, _ = session.command_bytes(label, cmd, allowed=allowed, timeout=timeout)
                body = raw_body.decode("utf-8", "replace")
                if label == "dmesg":
                    (destination / "dmesg.bin").write_bytes(raw_body)
                    receipt["dmesg_bytes"] = len(raw_body)
                    receipt["dmesg_lines"] = len(raw_body.splitlines())
                    receipt["dmesg_sha256"] = hashlib.sha256(raw_body).hexdigest()
            else:
                body, _ = session.command(label, cmd, allowed=allowed, timeout=timeout)
            inventory_sections.append(f"=== {label} ===\n{body}\n")
            if label == "mounts":
                receipt["verified_mounts"] = verify_extract_mounts(body)
                receipt["mounts_verified"] = True
            elif label == "check_ancestors":
                expected_anc = list(EXTRACT_ANCESTOR_DIRS) + ["/tmp_network"]
                receipt["verified_ancestors"] = collect_base.verify_ancestor_check(body, ancestor_dirs=expected_anc)
                receipt["ancestors_verified"] = True
            elif label == "version":
                actual_build = body.strip()
                receipt["build"] = actual_build
                if actual_build != BUILD:
                    raise probe.ProbeError(f"Expected original M7 build {BUILD!r}, got {actual_build!r}")
                print(f"BUILD_VERIFIED: {actual_build}", flush=True)
            elif label == "boot_id":
                receipt["boot_id"] = body.strip()
                uuid.UUID(receipt["boot_id"])
            elif label == "uptime":
                receipt["uptime"] = body.strip()
            elif label == "hotplug":
                receipt["hotplug"] = body.strip()
            elif label == "upm_bootmode":
                receipt["upm_bootmode"] = body.strip()

        statfs_parsed = _upload_and_run_statfs(session, inspector, receipt)
        if receipt.get("statfs_cleanup") != "GONE":
            raise probe.ProbeError(f"statfs staging dir cleanup not verified: {receipt.get('statfs_cleanup')!r}")
        inventory_sections.append(f"=== statfs ===\n{receipt.get('statfs_raw', '')}\n")
        print(f"STATFS_OK: {len(statfs_parsed)} volumes measured", flush=True)

        checksum_cmds = collect_base.build_checksum_commands(
            EXTRACT_PATHS, receipt["nonce"], start_index=len(receipt["commands"])
        )
        checksum_text: list[str] = []
        for label, cmd, allowed in checksum_cmds:
            body, _ = session.command(label, cmd, allowed=allowed, timeout=25)
            inventory_sections.append(f"=== {label} ===\n{body}\n")
            checksum_text.append(body)

        inv_path = destination / "inventory.txt"
        inv_text = "\n".join(inventory_sections)
        inv_path.write_text(inv_text, encoding="utf-8")
        try:
            receipt["inventory_path"] = str(inv_path.relative_to(ROOT))
        except ValueError:
            receipt["inventory_path"] = str(inv_path)
        receipt["inventory_sha256"] = hashlib.sha256(inv_text.encode("utf-8")).hexdigest()

        witness = collect_base.parse_camera_checksums(
            "\n".join(checksum_text),
            paths=EXTRACT_PATHS,
            required_paths=EXTRACT_REQUIRED_PATHS,
            max_file_bytes=MAX_FILE_BYTES,
        )
        receipt["camera_path_states"] = witness["states"]
        receipt["camera_expected_sizes"] = witness["sizes"]
        receipt["camera_expected_md5"] = witness["md5s"]
        receipt["camera_missing_paths"] = witness["missing"]
        receipt["camera_symlink_paths"] = witness["symlinks"]
        receipt["camera_nonreg_paths"] = witness["nonreg"]
        print(
            f"INVENTORY_OK: {len(witness['reg_paths'])} regular files, "
            f"{len(witness['missing'])} absent, {len(witness['symlinks'])} symlinks",
            flush=True,
        )
    finally:
        if enable_attempted:
            try:
                collect_base.toggle_terminal(camera, False, receipt["terminal_toggles"], phase="final_disable")
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
        opened_partial = False
        renamed = False
        try:
            with partial.open("xb") as stream:
                opened_partial = True
                sink = collect_base.BoundedSink(stream, limit=MAX_FILE_BYTES)
                with probe.deadline(max(30, min(180, exp // 200000 + 30))):
                    camera.readFile(path, sink)
            with partial.open("rb") as stream:
                first4 = stream.read(4)
            verify_extract_transfer(path, sink, sizes, md5s, first4)
            partial.rename(out_path)
            renamed = True
            done_bytes += sink.bytes
            try:
                host_rel = str(out_path.relative_to(ROOT))
            except ValueError:
                host_rel = str(out_path)
            receipt["files"][path] = {
                "host_path": host_rel,
                "bytes": sink.bytes,
                "sha256": sink.sha256.hexdigest(),
                "md5": sink.md5.hexdigest(),
                "verified": True,
            }
            print(f"  OK {sink.bytes:,} B sha256={sink.sha256.hexdigest()[:16]}...", flush=True)
        except BaseException as err:
            if opened_partial and not renamed:
                partial.unlink(missing_ok=True)
            receipt["files"][path] = {"error": f"{type(err).__name__}: {err}", "verified": False}
            print(f"  ERROR {path}: {err}", flush=True)
            raise

    receipt["total_transferred_bytes"] = done_bytes
    receipt["all_files_verified"] = (
        bool(present_paths)
        and EXTRACT_REQUIRED_PATHS.issubset(receipt["files"].keys())
        and set(receipt["files"].keys()) == set(present_paths)
        and all(receipt["files"][p].get("verified") is True for p in present_paths)
    )


def _utc_epoch_pair(now_seconds: float | None = None) -> tuple[str, float]:
    raw = time.time() if now_seconds is None else now_seconds
    ts_ms = int(math.floor(raw * 1000.0))
    epoch = ts_ms / 1000.0
    dt = datetime.fromtimestamp(epoch, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts_ms % 1000:03d}Z", epoch


def transition_probe_diagnostic(camera, receipt: dict, ram_marker: str) -> None:
    if receipt.get("model") != MODEL:
        raise probe.ProbeError(f"Unsupported model: {receipt.get('model')!r}")

    receipt.setdefault("terminal_toggles", [])
    receipt["ancestors_verified"] = False
    receipt["mounts_verified"] = False
    receipt["terminal_disable_requested"] = False
    receipt["terminal_disable_verified"] = False

    session = PhaseBTerminalSession(camera, receipt)
    enable_attempted = False
    try:
        collect_base.toggle_terminal(camera, False, receipt["terminal_toggles"], phase="pre_disable")
        enable_attempted = True
        collect_base.toggle_terminal(camera, True, receipt["terminal_toggles"], phase="enable")
        with probe.deadline(10):
            receipt["shell_banner"] = read_ready(camera).decode("utf8", "replace")

        session.command("setup", SETUP_CMD, allowed=(0,), timeout=15)
        mounts_body, _ = session.command("mounts", MOUNTS_CMD, allowed=(0,), timeout=20)
        receipt["mounts_raw"] = mounts_body
        receipt["verified_mounts"] = verify_transition_mounts(mounts_body)
        receipt["mounts_verified"] = True

        anc_body, _ = session.command("check_ancestors", TRANSITION_ANCESTOR_CHECK_CMD, allowed=(0,), timeout=15)
        receipt["verified_ancestors"] = collect_base.verify_ancestor_check(anc_body, ancestor_dirs=("/tmp_network",))
        receipt["ancestors_verified"] = True

        version_body, _ = session.command("version", VERSION_CMD, allowed=(0,), timeout=15)
        actual_build = version_body.strip()
        receipt["version_txt"] = actual_build
        if actual_build != BUILD:
            raise probe.ProbeError(f"Expected original M7 build {BUILD!r}, got {actual_build!r}")

        start_utc, start_epoch = _utc_epoch_pair()
        receipt["start_utc"] = start_utc
        receipt["wall_epoch_start"] = start_epoch

        boot_id_body, _ = session.command("boot_id", BOOT_ID_CMD, allowed=(0,), timeout=15)
        receipt["boot_id"] = boot_id_body.strip()
        uuid.UUID(receipt["boot_id"])

        uptime_body, _ = session.command("uptime", UPTIME_CMD, allowed=(0,), timeout=15)
        receipt["uptime"] = uptime_body.strip()

        date_body, _ = session.command("date", DATE_CMD, allowed=(0,), timeout=15)
        receipt["camera_date"] = date_body.strip()

        cmdline_body, _ = session.command("cmdline", CMDLINE_CMD, allowed=(0,), timeout=15)
        receipt["cmdline"] = cmdline_body.strip()

        bootmode_body, _ = session.command("upm_bootmode", UPM_BOOTMODE_CMD, allowed=(0,), timeout=15)
        receipt["upm_bootmode"] = bootmode_body.strip()

        hotplug_body, _ = session.command("hotplug", HOTPLUG_CMD, allowed=(0,), timeout=15)
        receipt["hotplug"] = hotplug_body.strip()

        ls_tmp_raw, _ = session.command_bytes("ls_tmp_network", TRANSITION_LS_TMP_CMD, allowed=(0,), timeout=15)
        ls_flash_raw, _ = session.command_bytes("ls_flash_dirs", TRANSITION_LS_FLASH_CMD, allowed=(0,), timeout=15)
        ls_tmp_body = ls_tmp_raw.decode("utf-8", "replace")
        receipt["ls_tmp_network"] = ls_tmp_body
        receipt["ls_flash_dirs"] = ls_flash_raw.decode("utf-8", "replace")
        receipt["tmp_network"] = parse_tmp_network_ls(ls_tmp_body)

        before_marker = _inspect_ram_marker(session, "before")
        after_marker = before_marker
        if ram_marker == "plant":
            if before_marker["state"] != "ABSENT":
                raise probe.ProbeError(f"Refusing to plant RAM marker when state is {before_marker['state']}")
            token = f"M7_PB_MARKER {receipt['nonce']} {receipt['utc']}"
            plant_body, _ = session.command("marker_plant", _make_marker_plant_cmd(token), allowed=(0,), timeout=12)
            if plant_body.strip() != "PLANTED":
                raise probe.ProbeError(f"RAM marker plant failed: {plant_body!r}")
            after_marker = _inspect_ram_marker(session, "after")
            exp_content = f"{token}\n"
            exp_md5 = hashlib.md5(exp_content.encode("ascii")).hexdigest()
            if (
                after_marker["state"] != "REGULAR"
                or after_marker["content"] != exp_content
                or after_marker["md5"] != exp_md5
            ):
                raise probe.ProbeError(f"Planted RAM marker readback mismatch: {after_marker!r}")
        receipt["marker"] = {"mode": ram_marker, "before": before_marker, "after": after_marker}

        proc_raw, _ = session.command_bytes("proc_snapshot", PROC_SNAPSHOT_CMD, allowed=(0,), timeout=90)
        rows, raced = parse_proc_snapshot_bytes(proc_raw)
        receipt["processes"] = rows
        receipt["raced_pids"] = raced

        dmesg_raw, _ = session.command_bytes("dmesg", DMESG_CMD, allowed=(0,), timeout=45)
        receipt["dmesg"] = dmesg_raw.decode("utf-8", "replace")
        receipt["dmesg_b64"] = base64.b64encode(dmesg_raw).decode("ascii")
        receipt["dmesg_bytes"] = len(dmesg_raw)
        receipt["dmesg_lines"] = len(dmesg_raw.splitlines())
        receipt["dmesg_sha256"] = hashlib.sha256(dmesg_raw).hexdigest()

        end_utc, end_epoch = _utc_epoch_pair()
        if end_epoch < start_epoch:
            raise probe.ProbeError(f"Host wall clock stepped backwards during capture ({end_epoch} < {start_epoch})")
        receipt["end_utc"] = end_utc
        receipt["wall_epoch_end"] = end_epoch
    finally:
        if enable_attempted:
            try:
                collect_base.toggle_terminal(camera, False, receipt["terminal_toggles"], phase="final_disable")
                receipt["terminal_disable_requested"] = True
                receipt["terminal_disable_verified"] = True
            except Exception as err:
                receipt["terminal_disable_requested"] = False
                receipt["terminal_disable_verified"] = False
                receipt["terminal_disable_error"] = f"{type(err).__name__}: {err}"


def _decode_b64_strict(value: str, name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"Invalid base64 field {name}")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as err:
        raise ValueError(f"Malformed base64 field {name}") from err


def process_table(rows):
    if not isinstance(rows, list) or not rows:
        raise ValueError("Empty or invalid process table")
    table = {}
    for row in rows:
        pid, values = _parse_stat_fields(row["stat"])
        if pid in table or row["pid"] != pid:
            raise ValueError(f"Duplicate or inconsistent PID {pid}")
        exe, cmdline = row["exe"], row["cmdline"]
        if not isinstance(exe, str) or not isinstance(cmdline, str):
            raise ValueError(f"Invalid process identity for PID {pid}")
        if "cmdline_b64" not in row or "cmdline_bytes" not in row or "exe_b64" not in row:
            raise ValueError(f"Missing mandatory binary process witnesses for PID {pid}")
        raw_cmd = _decode_b64_strict(row["cmdline_b64"], f"pid {pid} cmdline_b64")
        if len(raw_cmd) > 4096:
            raise ValueError(f"cmdline exceeds 4096-byte M7 proc_pid_cmdline limit for PID {pid}")
        if type(row["cmdline_bytes"]) is not int or row["cmdline_bytes"] != len(raw_cmd):
            raise ValueError(f"Inconsistent cmdline_bytes for PID {pid}")
        if cmdline != raw_cmd.decode("utf-8", "replace"):
            raise ValueError(f"Inconsistent cmdline display for PID {pid}")
        cmdline_b64 = row["cmdline_b64"]
        raw_exe = _decode_b64_strict(row["exe_b64"], f"pid {pid} exe_b64")
        if exe != raw_exe.decode("utf-8", "replace"):
            raise ValueError(f"Inconsistent exe display for PID {pid}")
        exe_b64 = row["exe_b64"]
        table[pid] = {
            "starttime": values[22 - 4],
            "minflt": values[10 - 4],
            "cutime": values[16 - 4],
            "exe": exe,
            "exe_b64": exe_b64,
            "cmdline": cmdline,
            "cmdline_b64": cmdline_b64,
        }
    return table


def _receipt_dmesg_bytes(receipt: dict) -> bytes:
    raw = _decode_b64_strict(receipt["dmesg_b64"], "dmesg_b64")
    if hashlib.sha256(raw).hexdigest() != receipt["dmesg_sha256"]:
        raise ValueError("Kernel log SHA-256 differs from dmesg_b64")
    if receipt["dmesg"] != raw.decode("utf-8", "replace"):
        raise ValueError("Kernel log display text differs from dmesg_b64")
    return raw


def resume_messages(log_or_bytes):
    text = log_or_bytes.decode("latin-1") if isinstance(log_or_bytes, (bytes, bytearray)) else log_or_bytes
    events = []
    for line in text.splitlines():
        if "[LIRO]:" not in line:
            continue
        match = re.search(r"\bentry_resume:\s*635c6078\(([01])\)", line)
        if match:
            events.append({"kind": "WBI" if match[1] == "1" else "ordinary", "line": line})
        elif "liro resume (WBI)" in line:
            events.append({"kind": "WBI", "line": line})
    return events


def number(value, name):
    if isinstance(value, bool) or not math.isfinite(float(value)):
        raise ValueError(f"Invalid {name}")
    return float(value)


def capture_time(receipt, point):
    epoch = number(receipt[f"wall_epoch_{point}"], f"wall_epoch_{point}")
    utc = receipt[f"{point}_utc"]
    timestamp = datetime.fromisoformat(utc.replace("Z", "+00:00"))
    if timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
        raise ValueError(f"Expected UTC for {point}")
    if abs(timestamp.timestamp() - epoch) >= 1:
        raise ValueError(f"{point} UTC and wall epoch disagree")
    return epoch


def _validate_marker_observation(observation: dict) -> None:
    if not isinstance(observation, dict):
        raise ValueError("Invalid marker observation")
    state = observation.get("state")
    if state not in ("REGULAR", "ABSENT", "UNSAFE"):
        raise ValueError("Invalid marker state")
    if state == "REGULAR":
        content = observation.get("content")
        if not isinstance(content, str) or not RAM_MARKER_TOKEN_RE.fullmatch(content):
            raise ValueError("REGULAR marker does not match strict M7_PB_MARKER token format")
        raw = content.encode("ascii")
        exp_md5 = hashlib.md5(raw).hexdigest()
        if observation.get("path") != RAM_MARKER_PATH:
            raise ValueError("REGULAR marker path mismatch")
        if observation.get("bytes") != len(raw):
            raise ValueError("REGULAR marker byte size mismatch")
        if observation.get("md5") != exp_md5:
            raise ValueError("REGULAR marker MD5 mismatch")
        if type(observation.get("inode")) is not int or observation["inode"] <= 0:
            raise ValueError("Invalid REGULAR marker inode")
        if not _is_valid_ls_mtime(observation.get("mtime")):
            raise ValueError("Missing or invalid REGULAR marker mtime")


def validate_receipt(receipt, *, require_final_ok: bool = False):
    if (receipt["mode"], receipt["model"], receipt["version_txt"]) != (
        "transition-probe", MODEL, BUILD
    ):
        raise ValueError("Expected a Phase B transition receipt for the exact M7 build")
    if not LABEL.fullmatch(receipt["label"]):
        raise ValueError("Invalid receipt label")
    stop_info = receipt.get("service_stop_transport")
    if (
        receipt.get("error") is not None
        or receipt.get("terminal_disable_error") is not None
        or (require_final_ok and receipt.get("transition_probe_ok") is not True)
        or (not require_final_ok and receipt.get("transition_probe_ok") is False)
        or receipt.get("ancestors_verified") is not True
        or receipt.get("mounts_verified") is not True
        or receipt.get("terminal_disable_requested") is not True
        or receipt.get("terminal_disable_verified") is not True
        or receipt.get("service_stop_requested") is not True
        or receipt.get("service_stop_error") is not None
        or not isinstance(stop_info, dict)
        or stop_info.get("observed") is not True
        or stop_info.get("transport_ok") is not True
        or stop_info.get("error") is not None
    ):
        raise ValueError("Incomplete probe, verification, or USB teardown")
    uuid.UUID(receipt["boot_id"])
    start = capture_time(receipt, "start")
    end = capture_time(receipt, "end")
    uptime = number(receipt["uptime"].split()[0], "uptime")
    if end < start or uptime < 0:
        raise ValueError("Invalid capture interval or uptime")
    raw = _receipt_dmesg_bytes(receipt)
    if receipt["dmesg_bytes"] != len(raw) or receipt["dmesg_lines"] != len(raw.splitlines()):
        raise ValueError("Kernel log counts differ from receipt")
    tmp = receipt["tmp_network"]
    if (
        not isinstance(tmp, dict)
        or type(tmp.get("inode")) is not int
        or tmp["inode"] <= 0
        or not _is_valid_ls_mtime(tmp.get("mtime"))
    ):
        raise ValueError("Invalid tmpfs directory metadata")
    marker = receipt["marker"]
    if not isinstance(marker, dict):
        raise ValueError("Invalid marker section")
    marker_mode = marker.get("mode")
    if marker_mode not in ("none", "plant", "check"):
        raise ValueError("Invalid marker mode")
    if "ram_marker_mode" in receipt and receipt["ram_marker_mode"] != marker_mode:
        raise ValueError("Inconsistent ram_marker_mode and marker.mode")
    for point in ("before", "after"):
        _validate_marker_observation(marker[point])
    m_before, m_after = marker["before"], marker["after"]
    if marker_mode in ("none", "check") and m_before != m_after:
        raise ValueError("Read-only marker mode has divergent before/after observations")
    if marker_mode == "plant" and (m_before["state"] != "ABSENT" or m_after["state"] != "REGULAR"):
        raise ValueError("Invalid marker transition for plant mode")
    table = process_table(receipt["processes"])
    missing_tracked = [p for p in TRACKED if p not in table]
    if missing_tracked:
        raise ValueError(f"Tracked PID(s) missing from receipt: {missing_tracked}")
    raced = receipt.get("raced_pids")
    if not isinstance(raced, list):
        raise ValueError("Missing or invalid raced_pids list")
    raced_seen: set[int] = set()
    for entry in raced:
        if (
            not isinstance(entry, dict)
            or set(entry.keys()) != {"pid", "reason", "starttime_before"}
            or type(entry.get("pid")) is not int
            or entry["pid"] <= 0
            or entry["pid"] in raced_seen
            or not isinstance(entry.get("reason"), str)
            or not RACED_REASON_RE.fullmatch(entry["reason"])
            or type(entry.get("starttime_before")) is not int
            or entry["starttime_before"] < 0
        ):
            raise ValueError("Malformed raced_pids entry")
        if entry["pid"] in TRACKED:
            raise ValueError(f"Tracked PID {entry['pid']} raced during capture")
        if entry["pid"] in table:
            raise ValueError(f"PID {entry['pid']} appears in both processes and raced_pids")
        raced_seen.add(entry["pid"])
    return start, end, uptime, table


def compare(before, after):
    start1, end1, up1, processes1 = validate_receipt(before, require_final_ok=True)
    start2, end2, up2, processes2 = validate_receipt(after, require_final_ok=True)
    if start2 < end1:
        raise ValueError("Receipts overlap or are in reverse order")
    changed = uuid.UUID(before["boot_id"]) != uuid.UUID(after["boot_id"])
    result = {
        "labels": [before["label"], after["label"]],
        "boot_id_changed": changed,
        "capture_intervals_utc": [[r["start_utc"], r["end_utc"]] for r in (before, after)],
        "uptime_delta_seconds": up2 - up1,
        "wall_start_delta_seconds": start2 - start1,
        "wall_delta_bounds_seconds": [start2 - end1, end2 - start1],
        "resume_events": [resume_messages(_receipt_dmesg_bytes(r)) for r in (before, after)],
        "processes": {},
        "tmp_network": [before["tmp_network"], after["tmp_network"]],
    }
    for pid in TRACKED:
        a, b = processes1.get(pid), processes2.get(pid)
        delta = {
            key: b[key] - a[key] if a and b else None
            for key in ("starttime", "minflt", "cutime")
        }
        result["processes"][str(pid)] = {
            "before": a,
            "after": b,
            "observed_difference": delta,
            "same_boot_and_start_tick": bool(a and b and not changed and a["starttime"] == b["starttime"]),
        }
    # Compare the first receipt's final validated token to the second receipt's initial
    # validated token so planting/clearing or unrelated files cannot manufacture retention.
    a, b = before["marker"]["after"], after["marker"]["before"]
    same = None
    if a["state"] == "REGULAR" and b["state"] != "UNSAFE":
        a_md5 = a.get("md5") or hashlib.md5(a["content"].encode("ascii")).hexdigest()
        b_md5 = b.get("md5") or (hashlib.md5(b["content"].encode("ascii")).hexdigest() if b["state"] == "REGULAR" else None)
        same = b["state"] == "REGULAR" and a["content"] == b["content"] and a_md5 == b_md5
    result["marker"] = {"before": a, "after": b, "same_contents_observed": same}
    result["tmp_network_changes"] = {
        k: before["tmp_network"][k] != after["tmp_network"][k] for k in ("inode", "mtime")
    }

    def users(table):
        return {
            (pid, p["starttime"], p["exe_b64"], p["cmdline_b64"], p["exe"], p["cmdline"])
            for pid, p in table.items()
            if p["exe_b64"] or p["cmdline_b64"]
        }

    result["new_userspace_observations"] = [
        {"pid": pid, "starttime": tick, "exe": exe, "cmdline": cmdline, "cmdline_b64": cb64}
        for pid, tick, _eb64, cb64, exe, cmdline in sorted(users(processes2) - users(processes1))
    ]
    return result


def run_extract_boot(out_dir: Path | None = None, inspector_dir: Path = INSPECTOR_DIR) -> int:
    inspector = verify_local_inspector(inspector_dir)
    utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    nonce = secrets.token_hex(6)
    target_dir = validate_host_out_dir(out_dir if out_dir is not None else Path(f"extracted/m7-stage7-phaseb-1.00-{utc}"))
    OUT_RECEIPT_DIR.mkdir(parents=True, exist_ok=True)

    receipt: dict = {
        "mode": "extract-boot",
        "stage": "7.3-phase-b-extract-boot",
        "utc": utc,
        "nonce": nonce,
        "pmca_commit": probe.PMCA_COMMIT,
        "tool_flash_writes_performed": False,
        "tool_sd_writes_performed": False,
        "acknowledged_stock_side_effects": [
            "Sony libsencore.so FileControl READ may update /setting/.etools (4096 B) if present.",
            "phaseb_statfs.elf statfs64 on /setting, /etc, /system may mark FAT32 FSInfo dirty if uncached.",
            "BusyBox ash HISTFILE=/dev/null is best-effort on this build.",
            "StopSenser transport success does not confirm physical return to normal camera UI.",
        ],
        "inspector_sha256": inspector["sha256"],
        "inspector_md5": inspector["md5"],
        "inspector_bytes": inspector["bytes"],
        "service_stop_transport": collect_base.make_stop_transport_record(),
        "collection_directory": str(target_dir),
        "commands": [],
        "steps": [],
        "terminal_toggles": [],
    }

    try:
        with collect_base.observe_stop_senser(receipt):
            probe.connect(
                receipt,
                diagnostic=lambda cam, rec: extract_boot_diagnostic(cam, rec, inspector),
                gate_factory=lambda dev: PhaseBCollectGate(
                    dev, PHASEB_ALLOWED_FILE_READ_PAYLOADS, receipt=receipt
                ),
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
        if "error" not in receipt:
            receipt["error"] = f"StopSenserTransportError: {stop_info.get('error')}"

    ok = (
        "error" not in receipt
        and receipt.get("ancestors_verified") is True
        and receipt.get("mounts_verified") is True
        and receipt.get("statfs_cleanup") == "GONE"
        and receipt.get("all_files_verified") is True
        and receipt.get("terminal_disable_verified") is True
        and receipt.get("terminal_disable_error") is None
        and receipt.get("service_stop_requested") is True
        and receipt.get("service_stop_error") is None
        and stop_info.get("observed") is True
        and stop_info.get("transport_ok") is True
        and stop_info.get("error") is None
    )
    if not ok and "error" not in receipt:
        receipt["error"] = "ExtractBootIncomplete: one or more verification or teardown checks did not pass"
    receipt["extract_boot_ok"] = ok
    receipt_path = OUT_RECEIPT_DIR / f"{utc}-{nonce}-extract-boot.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"RESULT={receipt_path}", flush=True)
    print(f"PHASEB_EXTRACT_OK={ok}", flush=True)
    return 0 if ok else 1


def run_transition_probe(label: str, ram_marker: str = "none") -> int:
    OUT_RECEIPT_DIR.mkdir(parents=True, exist_ok=True)
    utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    nonce = secrets.token_hex(6)

    receipt: dict = {
        "mode": "transition-probe",
        "stage": "7.3-phase-b-transition-probe",
        "label": label,
        "utc": utc,
        "nonce": nonce,
        "pmca_commit": probe.PMCA_COMMIT,
        "tool_flash_writes_performed": False,
        "tool_sd_writes_performed": False,
        "ram_marker_mode": ram_marker,
        "acknowledged_stock_side_effects": [
            "Zero FileControl operations, zero ELF uploads, and zero file deletions performed.",
            "BusyBox ash HISTFILE=/dev/null is best-effort on this build.",
            "RAM marker plant creates only one 43-byte token file at /tmp_network/.m7-pb-ret.txt via set -C; "
            "none/check make zero tmpfs writes. Full battery removal clears volatile tmpfs.",
            "StopSenser transport success does not confirm physical return to normal camera UI.",
        ],
        "service_stop_transport": collect_base.make_stop_transport_record(),
        "commands": [],
        "steps": [],
        "terminal_toggles": [],
    }

    try:
        with collect_base.observe_stop_senser(receipt):
            probe.connect(
                receipt,
                diagnostic=lambda cam, rec: transition_probe_diagnostic(cam, rec, ram_marker),
                gate_factory=lambda dev: PhaseBCollectGate(dev, frozenset(), receipt=receipt),
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

    valid_schema = False
    if "error" not in receipt:
        try:
            validate_receipt(receipt)
            valid_schema = True
        except Exception as err:
            receipt["error"] = f"ReceiptValidationError: {err}"
            print(f"ERROR={receipt['error']}", file=sys.stderr, flush=True)

    receipt["transition_probe_ok"] = valid_schema
    receipt_path = OUT_RECEIPT_DIR / f"{utc}-{nonce}-{label}.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"RESULT={receipt_path}", flush=True)
    print(f"PHASEB_TRANSITION_OK={valid_schema}", flush=True)
    return 0 if valid_schema else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--compare", nargs=2, type=Path, metavar=("BEFORE", "AFTER"))
    group.add_argument("--extract-boot", action="store_true")
    group.add_argument("--transition-probe", action="store_true")
    parser.add_argument("--label")
    parser.add_argument("--ram-marker", choices=("none", "plant", "check"))
    parser.add_argument("--out-dir", type=Path, help="Extraction destination for --extract-boot")
    parser.add_argument("--confirm-phaseb-boot-extract", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        EXTRACT_CONSENT,
        action="store_true",
        dest="extract_consent",
        help="Acknowledge possible .etools, VFAT FSInfo and ash history writes and physical UI check",
    )
    parser.add_argument(
        TRANSITION_CONSENT,
        action="store_true",
        dest="transition_consent",
        help="Acknowledge ash history uncertainty, volatile marker behavior and physical UI check",
    )
    args = parser.parse_args(argv)
    if (args.label is not None or args.ram_marker is not None) and not args.transition_probe:
        parser.error("--label and --ram-marker apply only to --transition-probe")
    if args.confirm_phaseb_boot_extract:
        parser.error(f"The former .etools confirmation is obsolete. Extraction requires {EXTRACT_CONSENT}")
    if (args.extract_consent or args.out_dir is not None) and not args.extract_boot:
        parser.error("Extraction options apply only to --extract-boot")
    if args.transition_consent and not args.transition_probe:
        parser.error("Transition confirmation applies only to --transition-probe")
    if args.extract_boot:
        if not args.extract_consent:
            parser.error(f"--extract-boot requires {EXTRACT_CONSENT}")
        try:
            verify_local_inspector(INSPECTOR_DIR)
            if args.out_dir is not None:
                validate_host_out_dir(args.out_dir)
        except (OSError, ValueError) as error:
            parser.error(f"Extraction prerequisite failed: {error}")
        return run_extract_boot(out_dir=args.out_dir)
    if args.transition_probe:
        if args.label is None or not LABEL.fullmatch(args.label):
            parser.error("--transition-probe requires a valid --label")
        if not args.transition_consent:
            parser.error(f"--transition-probe requires {TRANSITION_CONSENT}")
        return run_transition_probe(label=args.label, ram_marker=args.ram_marker or "none")
    try:
        print(
            json.dumps(
                compare(*(json.loads(path.read_text(encoding="utf-8")) for path in args.compare)),
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
        )
    except (OSError, ValueError, KeyError, IndexError, TypeError, OverflowError, AttributeError) as error:
        parser.error(f"Cannot compare receipts: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
