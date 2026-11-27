#!/usr/bin/env python3
"""Stage 7.3 Phase A hardware helper for DSC-RX100M7 1.00 — STRICTLY ZERO CAMERA FLASH WRITES.

Modes:
  --prep-card   Prepare authenticated M7SD1 MLV2.TAR on a mounted SD card root (preserves DCIM/).
  --boot-probe  Read-only M7 boot/process/warm-resume/SD-VBR/tmp_network telemetry over usbgcon-1.
  --ram-start   100% RAM-only SD-boot test: runs mlv2_card_read.elf + mlv2_sd_boot.sh from
                /tmp_network reading MLV2.TAR directly off /dev/mmca1 with a RAM-simulated
                durable preference file (ZERO writes to /setting, /etc, /tmp, /usr, or Backup.bin).
  --ram-collect Stop the Phase A RAM SD-boot session, collect logs & remembered-state proofs,
                run sd-disabled teardown + verified stock mlv2_guard uninstall, and clean RAM.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "prototype-stage7-persist"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(PROTO))

import build_stage7  # noqa: E402
import build_stage7_sd as sd_builder  # noqa: E402
import m7_burst_identity as identity  # noqa: E402
import m7_probe as usb  # noqa: E402
import stage7_ram_runner as ram  # noqa: E402

OUT_DIR = ROOT / "work/stage7-persist/sd-phase-a"
DEFAULT_KEY_FILE = ROOT / "work/stage7-persist/.sd-phase-a.key"
ACTIVE_SD_RAM = OUT_DIR / ".active-stage7-sd-ram.json"
SD_DAEMON_DIR = f"/tmp_network/.m7-s7-{sd_builder.SD_BOOT_NONCE}"
SD_SIM_PERSIST = "/tmp_network/mlv2/sim-setting-precap.cfg"
DISABLE_MARKERS = ("MLV2.OFF", "disable.txt", "disable_hook")

REMOTE_PHASE_A_UPLOAD_RE = re.compile(
    r"^/tmp_network/\.m7-(bp|s7sd)-[0-9a-f]{12}/"
    r"(mlv2_card_read\.elf|mlv2_sd_boot\.sh|sd\.key)$"
)
REMOTE_SIM_PERSIST_RE = re.compile(r"^/tmp_network/mlv2/sim-setting-precap\.cfg$")
REMOTE_STAGE_DIR_RE = re.compile(r"^/tmp_network/\.m7-s7sd-[0-9a-f]{12}$")
REMOTE_DAEMON_DIR_RE = re.compile(r"^/tmp_network/\.m7-s7-[0-9a-f]{12}$")
PRE_INSTALL_REFUSAL_LINES = (
    "MLV2_SD_NOT_READY",
    "MLV2_SD_PACKAGE_UNAVAILABLE",
    "MLV2_SD_LOST_BEFORE_INSTALL",
)
_RAM_COMPONENT = r"(?!.*\.\.)(?!\.(?:/|$))[A-Za-z0-9._-]+"
REMOTE_RAM_DIR_RE = re.compile(rf"^/tmp_network/{_RAM_COMPONENT}$")
REMOTE_RAM_LEAF_RE = re.compile(rf"^/tmp_network/{_RAM_COMPONENT}/{_RAM_COMPONENT}$")
_LEAF_DIRS_OK = "[ -d $t ]&&[ ! -L $t ]&&[ -d $d ]&&[ ! -L $d ]"
_LEAF_OK = "[ -f $f ]&&[ ! -L $f ]"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_or_create_key(key_path: Path, *, create: bool = False) -> bytes:
    resolved = key_path.resolve()
    if resolved.exists():
        data = resolved.read_bytes()
        if len(data) != 32:
            raise ValueError(f"Key file {resolved} must be exactly 32 bytes (got {len(data)})")
        return data
    if not create:
        raise FileNotFoundError(f"Missing Phase A owner key file: {resolved} (run --prep-card first)")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    fd = os.open(str(resolved), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    return key


def parse_probe_output(text: str) -> dict:
    out: dict[str, object] = {"raw": text}
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("RAM_STATFS "):
            stats = {}
            for tok in s.split()[1:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    stats[k] = int(v) if v.isdigit() else v
            out["ram_statfs"] = stats
        elif s == "RAM_STATFS=ERROR":
            out["ram_statfs"] = {"error": True}
        elif "=" in s:
            k, v = s.split("=", 1)
            out[k] = int(v) if v.isdigit() else v
    return out


def validate_sd_root(sd_root: Path) -> Path:
    if sd_root.is_symlink():
        raise ValueError(f"Refusing symlink SD card root: {sd_root}")
    root = sd_root.resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"SD card root does not exist: {root}")
    repo = ROOT.resolve()
    if root == repo or repo.is_relative_to(root):
        raise ValueError(f"Refusing to write MLV2.TAR to repository/ancestor directory: {root}")
    forbidden = {Path("/"), Path("/System"), Path("/Users"), Path.home().resolve()}
    if root in forbidden:
        raise ValueError(f"Refusing to treat system/home directory {root} as an SD card root")
    return root


def prep_card(
    sd_root: Path,
    *,
    key_file: Path = DEFAULT_KEY_FILE,
    release_seq: int = 1,
    clear_disable_markers: bool = False,
) -> dict:
    """Copy authenticated M7SD1 MLV2.TAR to SD root atomically without touching DCIM/."""
    sd_manifest = sd_builder.verify_seal()
    root = validate_sd_root(sd_root)
    key = load_or_create_key(key_file, create=True)
    ustar = (sd_builder.OUT_SD / "card.ustar").read_bytes()
    if sd_builder.sha256_bytes(ustar) != sd_manifest["artifacts"]["card_ustar"]["sha256"]:
        raise ValueError("out-sd/card.ustar changed after verify_seal()")
    signed = sd_builder.sign_mlv2_tar(ustar, key, release_seq=release_seq)
    expected_sha = sd_builder.sha256_bytes(signed)

    removed_markers: list[str] = []
    remaining_markers: list[str] = []
    for marker in DISABLE_MARKERS:
        mp = root / marker
        if mp.exists() or mp.is_symlink():
            if clear_disable_markers and mp.is_file() and not mp.is_symlink():
                mp.unlink()
                removed_markers.append(marker)
            else:
                remaining_markers.append(marker)

    dst = root / "MLV2.TAR"
    if dst.is_symlink() or dst.is_dir():
        raise ValueError(f"Refusing unsafe destination path {dst} (symlink or directory)")

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    tmp = root / f".MLV2.TAR.{secrets.token_hex(6)}.tmp"
    wfd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
    try:
        try:
            view = memoryview(signed)
            done = 0
            while done < len(signed):
                n = os.write(wfd, view[done:])
                if n <= 0:
                    raise OSError("Short write preparing MLV2.TAR")
                done += n
            os.fsync(wfd)
        finally:
            os.close(wfd)
        if dst.is_symlink() or dst.is_dir():
            raise ValueError(f"Refusing unsafe destination path {dst} (symlink or directory)")
        os.replace(tmp, dst)
    except BaseException:
        try:
            if tmp.exists() or tmp.is_symlink():
                tmp.unlink()
        except OSError:
            pass
        raise

    rfd = os.open(str(dst), os.O_RDONLY | nofollow)
    try:
        st = os.fstat(rfd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Destination {dst} is not a regular file after publication")
        chunks = []
        while True:
            b = os.read(rfd, 65536)
            if not b:
                break
            chunks.append(b)
        readback = b"".join(chunks)
    finally:
        os.close(rfd)
    actual_sha = sd_builder.sha256_bytes(readback)
    if actual_sha != expected_sha or len(readback) != len(signed):
        raise RuntimeError(f"SD readback mismatch for {dst}: {actual_sha} != {expected_sha}")

    return {
        "status": "sd_card_prepared",
        "sd_root": str(root),
        "mlv2_tar_path": str(dst),
        "mlv2_tar_bytes": len(readback),
        "mlv2_tar_sha256": actual_sha,
        "release_seq": release_seq,
        "key_file": str(key_file.resolve()),
        "key_sha256_prefix": sd_builder.sha256_bytes(key)[:16],
        "card_ustar_sha256": sd_manifest["artifacts"]["card_ustar"]["sha256"],
        "removed_disable_markers": removed_markers,
        "remaining_disable_markers": remaining_markers,
    }


def _send_secret_command(session, cmd: str, label: str, *, allowed=(0,), timeout: int = 12):
    """Run one terminal command while guaranteeing secret payload/reply/packets never persist in receipt."""
    cmd_idx = len(session.receipt["commands"])
    step_idx = len(session.receipt["steps"])
    dev = getattr(session.camera, "dev", None)
    pkt_log = getattr(dev, "packet_log", None)
    pkt_idx = len(pkt_log) if isinstance(pkt_log, list) else None
    try:
        return session.command(cmd, allowed=allowed, timeout=timeout)
    finally:
        if cmd_idx < len(session.receipt["commands"]):
            session.receipt["commands"][cmd_idx] = f"<REDACTED:{label}>"
        if step_idx < len(session.receipt["steps"]):
            session.receipt["steps"][step_idx]["response"] = f"<REDACTED:{label}>"
        if pkt_idx is not None and isinstance(pkt_log, list) and len(pkt_log) > pkt_idx:
            pkt_log[pkt_idx:] = [{"redacted": label}]


def _ram_leaf_vars(path: str) -> str:
    parent = path.rsplit("/", 1)[0]
    ram.require(
        REMOTE_RAM_LEAF_RE.fullmatch(path) and REMOTE_RAM_DIR_RE.fullmatch(parent),
        f"Invalid volatile leaf path: {path!r}",
    )
    return f"t=/tmp_network;d={parent};f={path};"


def _safe_cat_ram_file(session, path: str) -> tuple[bytes, int]:
    return session.command(
        _ram_leaf_vars(path) + f"{_LEAF_DIRS_OK}&&{_LEAF_OK}&&/bin/busybox cat $f 2>/dev/null",
        allowed=(0, 1),
    )


def _inspect_ram_leaf(session, path: str) -> str:
    """Only a missing leaf under a safe parent can be classified FILE_ABSENT."""
    out, rc = session.command(
        _ram_leaf_vars(path) + f"if {_LEAF_DIRS_OK};then "
        f"if {_LEAF_OK};then echo FILE_OK;"
        "elif [ -e $f ]||[ -L $f ];then echo FILE_UNSAFE;else echo FILE_ABSENT;fi;"
        "else echo FILE_UNSAFE;fi",
        allowed=(0, 1),
    )
    txt = out.decode("ascii", "replace").strip()
    return txt if rc == 0 and txt in ("FILE_OK", "FILE_ABSENT", "FILE_UNSAFE") else "FILE_UNSAFE"


_LOCK_VARS = "t=/tmp_network;m=$t/mlv2;l=$m/.boot.lock;b=/bin/busybox;"
_LOCK_DIRS_OK = "[ -d $t ]&&[ ! -L $t ]&&[ -d $m ]&&[ ! -L $m ]"
_COLLECT_OWNS_LOCK = (
    '[ -d $l ]&&[ ! -L $l ]&&[ -f $l/owner ]&&[ ! -L $l/owner ]&&'
    '[ "$($b cat $l/owner)" = collect ]'
)


def _acquire_collect_lock(session) -> str:
    out, rc = session.command(
        f"{{ {_LOCK_VARS}if {_LOCK_DIRS_OK};then "
        "if $b mkdir $l;then echo collect>$l/owner&&echo ACQ||{ $b rmdir $l;echo ERR; };"
        f"elif {_COLLECT_OWNS_LOCK};then echo REACQ;else echo HELD;fi;"
        "else echo UNSAFE;fi; } 2>/dev/null",
        allowed=(0, 1),
    )
    return out.decode("ascii", "replace").strip() if rc == 0 else "ERR"


def _release_collect_lock(session, *, try_rmdir_parent: bool) -> str:
    # Rename with the owner inside. A successor can acquire the original name as soon as mv returns.
    parent_cleanup = "$b rmdir $m;" if try_rmdir_parent else ""
    out, rc = session.command(
        f"{{ {_LOCK_VARS}r=$m/.boot.rel;if {_LOCK_DIRS_OK}&&{_COLLECT_OWNS_LOCK};then "
        "$b rm -rf $r&&[ ! -e $r ]&&[ ! -L $r ]&&$b mv $l $r&&"
        f"{{ $b rm -rf $r;{parent_cleanup}echo REL; }}||echo ERR;"
        "else echo NOT_OWNED;fi; } 2>/dev/null",
        allowed=(0, 1),
    )
    return out.decode("ascii", "replace").strip() if rc == 0 else "ERR"


def _safe_touch_ram_marker(session, parent_dir: str, leaf_path: str) -> bool:
    """Create/truncate a RAM marker ONLY when /tmp_network + parent are non-symlink dirs and leaf is absent/regular."""
    ram.require(
        bool(REMOTE_RAM_DIR_RE.fullmatch(parent_dir))
        and bool(REMOTE_RAM_LEAF_RE.fullmatch(leaf_path))
        and leaf_path.startswith(parent_dir + "/"),
        f"Invalid volatile marker path: {parent_dir!r} -> {leaf_path!r}",
    )
    out, rc = session.command(
        f"if [ -d /tmp_network ]&&[ ! -L /tmp_network ]&&[ -d {parent_dir} ]&&[ ! -L {parent_dir} ]"
        f"&&[ ! -L {leaf_path} ]&&{{ [ ! -e {leaf_path} ]||[ -f {leaf_path} ]; }};"
        f"then : > {leaf_path};echo OK;else echo REFUSED;fi",
        allowed=(0, 1),
    )
    return rc == 0 and out.decode("ascii", "replace").strip() == "OK"


def observe_boot_worker_clear(session, stage_dir: str) -> dict:
    """Scan /proc for any live mlv2_card_read.elf, guard, or stage-anchored worker process (fail-closed)."""
    ram.require(bool(REMOTE_STAGE_DIR_RE.fullmatch(stage_dir)), f"Invalid stage_dir: {stage_dir!r}")
    cmd = (
        f's={stage_dir};m=/tmp_network/mlv2;b=/bin/busybox;'
        'for p in /proc/[1-9]*;do [ -e "$p/stat" ]||continue;'
        'e=$($b readlink "$p/exe" 2>/dev/null);'
        'case "$e" in "$s/mlv2_card_read.elf"|"$m/guard"|"$m/mlv2_guard.elf") echo "R:$p";continue;;esac;'
        'c=$($b readlink "$p/cwd" 2>/dev/null);'
        '[ "$c" = "$m" ]||[ "$c" = "$s" ]&&echo "W:$p";done;echo WORKER_OK'
    )
    raw, rc = session.command(cmd, allowed=(0, 1), timeout=15)
    lines = [ln.strip() for ln in raw.decode("utf8", "replace").splitlines() if ln.strip()]
    worker_pids = [ln for ln in lines if ln.startswith("W:")]
    reader_pids = [ln for ln in lines if ln.startswith("R:")]
    complete = (rc == 0 and bool(lines) and lines[-1] == "WORKER_OK")
    return {
        "complete": complete,
        "worker_pids": worker_pids,
        "reader_pids": reader_pids,
        "certain_clear": complete and not worker_pids and not reader_pids,
    }


def upload_phase_a_file(
    session,
    image: bytes,
    remote_path: str,
    applets: set,
    label: str,
    mode: str,
    *,
    redact_secret: bool = False,
) -> None:
    ram.require(
        bool(REMOTE_PHASE_A_UPLOAD_RE.fullmatch(remote_path) or REMOTE_SIM_PERSIST_RE.fullmatch(remote_path)),
        f"Disallowed Phase A RAM upload path (flash writes forbidden): {remote_path!r}",
    )
    ram.require(mode in ("400", "444", "500", "600"), f"Disallowed chmod mode: {mode!r}")
    parent_dir = remote_path.rsplit("/", 1)[0]
    leaf_chk, _ = session.command(
        f"[ -d /tmp_network ]&&[ ! -L /tmp_network ]&&[ -d {parent_dir} ]&&[ ! -L {parent_dir} ]"
        f"&&[ ! -e {remote_path} ]&&[ ! -L {remote_path} ]&&echo OK||echo BAD"
    )
    ram.require(leaf_chk.decode("ascii", "replace").strip() == "OK", f"Unsafe upload target: {remote_path}")

    compressed = gzip.compress(image, mtime=0)
    packed = "gunzip" in applets and len(compressed) < len(image)
    payload = compressed if packed else image
    encoded = "base64" in applets
    dest = remote_path + ".gz" if packed else remote_path
    if packed:
        gz_chk, _ = session.command(f"[ ! -e {dest} ]&&[ ! -L {dest} ]&&echo OK||echo BAD")
        ram.require(gz_chk.decode("ascii", "replace").strip() == "OK", f"Unsafe gzip staging target: {dest}")

    def run(cmd: str, *, timeout: int = 12):
        if redact_secret:
            return _send_secret_command(session, cmd, label, timeout=timeout)
        return session.command(cmd, timeout=timeout)

    # Reserve eight-digit step markers for every upload frame, including retries.
    base_idx = max(10_000_000, len(session.receipt["commands"]))
    chunk_list = ram.plan_upload_chunks(payload, dest, encoded, base_idx, session.receipt["nonce"])
    for idx, chunk in enumerate(chunk_list, 1):
        cmd = ram.upload_chunk_command(chunk, dest, encoded, first=(idx == 1))
        run(cmd)
    if packed:
        run(f"/bin/busybox gunzip -c {dest} > {remote_path}", timeout=20)
        run(f"/bin/busybox rm -f {dest}")
    expected = hashlib.md5(image).hexdigest() + "  " + remote_path
    actual = run(f"/bin/busybox md5sum {remote_path}")[0].decode("ascii", "replace").strip()
    ram.require(
        actual == expected,
        f"MD5 mismatch uploading {label}" if redact_secret else f"MD5 mismatch uploading {label}: {actual!r} != {expected!r}",
    )
    session.command(f"/bin/busybox chmod {mode} {remote_path}")


def _with_terminal(camera, receipt: dict, fn):
    enable_attempted = False
    try:
        with usb.deadline(10):
            camera.setTerminalEnable(False)
            enable_attempted = True
            camera.setTerminalEnable(True)
            receipt["shell_banner"] = ram.read_ready(camera).decode("utf8", "replace")
        session = ram.Stage7Session(camera, receipt)
        return fn(session)
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


def do_boot_probe(camera, receipt: dict, reader_bin: bytes, *, key_file: Path = DEFAULT_KEY_FILE) -> None:
    """Inside usb.connect: capture read-only M7 boot/SD/RAM telemetry (zero flash/SD writes)."""
    ram.require(receipt.get("model") == "DSC-RX100M7", f"Unsupported model: {receipt.get('model')!r}")
    nonce = receipt["nonce"]
    probe_dir = f"/tmp_network/.m7-bp-{nonce}"
    remote_reader = f"{probe_dir}/mlv2_card_read.elf"
    remote_key = f"{probe_dir}/sd.key"

    def body(session):
        # Run full shared identity & volatile-tmpfs preflight BEFORE any write to /tmp_network!
        pf_cmds = identity.preflight_commands()
        pf_bodies = [
            session.command(c, allowed=(0, 1) if i == 4 else (0,), timeout=20 if i == 8 else 12)[0].decode("utf8", "replace")
            for i, c in enumerate(pf_cmds)
        ]
        preflight = identity.checked_preflight(pf_bodies, receipt["model"])
        receipt["preflight"] = preflight
        applets, applet_src = ram.detect_busybox_applets(session)
        receipt["busybox_applet_source"] = applet_src
        receipt["busybox_applet_count"] = len(applets)

        def read_text(cmd: str, allowed=(0, 1)) -> str:
            raw, _ = session.command(cmd, allowed=allowed)
            return raw.decode("utf8", "replace")

        receipt["version_txt"] = pf_bodies[1]
        receipt["mounts"] = pf_bodies[2].splitlines()
        receipt["boot_id"] = read_text("/bin/busybox cat /proc/sys/kernel/random/boot_id").strip()
        receipt["uptime"] = read_text("/bin/busybox cat /proc/uptime").strip()
        receipt["cmdline"] = read_text("/bin/busybox cat /proc/cmdline").strip()
        receipt["tmp_network_ls"] = read_text("/bin/busybox ls -la /tmp_network").splitlines()
        receipt["setting_mode_ls"] = read_text("/bin/busybox ls -la /setting/mode").splitlines()
        receipt["etc_preload_present"] = (
            read_text("[ -e /etc/ld.so.preload ] && echo YES || echo NO").strip() == "YES"
        )

        proc_cmd = (
            'for p in /proc/[1-9]*;do [ -e "$p/stat" ]||continue;'
            'e=$(/bin/busybox readlink "$p/exe" 2>/dev/null);'
            's=$(/bin/busybox cat "$p/stat" 2>/dev/null);'
            'echo "P|$p|$e|$s";done'
        )
        receipt["processes_raw"] = read_text(proc_cmd).splitlines()

        dmesg_cmd = (
            "/bin/busybox dmesg|/bin/busybox egrep -i "
            "'warm|ssboot|resume|hiber|wbi|mmc|nflash|sen|usbg|im\\.elf|bootin'|/bin/busybox tail -n 80"
        )
        receipt["dmesg_boot_lines"] = read_text(dmesg_cmd, allowed=(0, 1)).splitlines()

        pre_probe, _ = session.command(f"[ ! -e {probe_dir} ] && [ ! -L {probe_dir} ] && echo CLEAN || echo DIRTY")
        ram.require(pre_probe.decode("ascii", "replace").strip() == "CLEAN", f"Probe dir exists: {probe_dir}")

        try:
            session.command(f"/bin/busybox mkdir {probe_dir}")
            upload_phase_a_file(session, reader_bin, remote_reader, applets, "mlv2_card_read.elf", "500")
            probe_raw, probe_rc = session.command(
                f"{remote_reader} --probe --ram-path /tmp_network", allowed=(0, 1, 2, 3), timeout=15
            )
            probe_info = parse_probe_output(probe_raw.decode("ascii", "replace"))
            probe_info["exit_code"] = probe_rc
            receipt["card_probe"] = probe_info

            if key_file.resolve().is_file() and probe_info.get("MLV2_FOUND") == 1:
                key_bytes = load_or_create_key(key_file, create=False)
                upload_phase_a_file(
                    session, key_bytes, remote_key, applets, "sd.key", "400", redact_secret=True
                )
                pres_out, pres_rc = session.command(
                    f"{remote_reader} --present --key {remote_key} --version-file /version.txt",
                    allowed=(0, 1, 2, 3),
                    timeout=15,
                )
                ver_out, ver_rc = session.command(
                    f"{remote_reader} --verify --key {remote_key} --version-file /version.txt",
                    allowed=(0, 1, 2, 3),
                    timeout=20,
                )
                receipt["card_auth_check"] = {
                    "present_rc": pres_rc,
                    "present_out": pres_out.decode("ascii", "replace"),
                    "verify_rc": ver_rc,
                    "verify_out": ver_out.decode("ascii", "replace"),
                    "verified_ok": (pres_rc == 0 and ver_rc == 0),
                }
        finally:
            if not getattr(getattr(camera, "dev", None), "poisoned", False):
                try:
                    session.command(f"/bin/busybox rm -rf {probe_dir}", allowed=(0, 1))
                    gone, _ = session.command(
                        f"[ ! -e {probe_dir} ] && [ ! -L {probe_dir} ] && echo GONE || echo PRESENT",
                        allowed=(0, 1),
                    )
                    receipt["probe_dir_cleanup"] = gone.decode("ascii", "replace").strip()
                except Exception as cleanup_err:
                    receipt["probe_dir_cleanup_error"] = f"{type(cleanup_err).__name__}: {cleanup_err}"

    _with_terminal(camera, receipt, body)


def _load_and_validate_active(active_path: Path) -> dict:
    ram.require(active_path.is_file() and not active_path.is_symlink(), f"No active Phase A RAM state at {active_path}")
    active = json.loads(active_path.read_text(encoding="utf-8"))
    ram.require(isinstance(active, dict) and active.get("stage") == "7.3-phase-a-ram", "Invalid Phase A active state")
    ram.require(bool(re.fullmatch(r"[0-9a-f]{12}", str(active.get("nonce", "")))), "Invalid active nonce")
    ram.require(bool(REMOTE_STAGE_DIR_RE.fullmatch(str(active.get("stage_dir", "")))), "Invalid active stage_dir")
    ram.require(bool(REMOTE_DAEMON_DIR_RE.fullmatch(str(active.get("daemon_dir", "")))), "Invalid active daemon_dir")
    im_pid = active.get("im_pid")
    im_st = active.get("im_starttime")
    ram.require(type(im_pid) is int and 1 < im_pid < 0x80000000, f"Invalid active im_pid: {im_pid!r}")
    ram.require(type(im_st) is int and im_st >= 0, f"Invalid active im_starttime: {im_st!r}")
    dpid = active.get("daemon_pid")
    ram.require(dpid is None or (type(dpid) is int and 1 < dpid < 0x80000000), f"Invalid active daemon_pid: {dpid!r}")
    vb = active.get("view_bias")
    ram.require(vb is None or bool(re.fullmatch(r"[0-9a-f]{8}", str(vb))), f"Invalid active view_bias: {vb!r}")
    ram.require(type(active.get("guard_bytes")) is int and active["guard_bytes"] > 0, "Invalid active guard_bytes")
    ram.require(type(active.get("req_bytes")) is int and active["req_bytes"] > 0, "Invalid active req_bytes")
    ram.require(bool(re.fullmatch(r"[0-9a-f]{32}", str(active.get("guard_md5", "")))), "Invalid active guard_md5")
    ram.require(bool(re.fullmatch(r"[0-9a-f]{32}", str(active.get("req_md5", "")))), "Invalid active req_md5")
    return active


def do_ram_start(
    camera,
    receipt: dict,
    *,
    s7_manifest: dict,
    sd_manifest: dict,
    reader_bin: bytes,
    boot_sh: bytes,
    key_bytes: bytes,
    seed_line: str,
    active_path: Path = ACTIVE_SD_RAM,
) -> None:
    """Inside usb.connect: 100% RAM-only Phase A SD-boot start reading MLV2.TAR from /dev/mmca1."""
    with ram.custody_lock(active_path):
        ram.require(not active_path.exists(), f"Active Phase A RAM state exists at {active_path}; run --ram-collect.")
        ram.require(not ram.ACTIVE_STATE.exists(), f"Active Stage 7.2 RAM state exists at {ram.ACTIVE_STATE}.")
        ram.require(receipt.get("model") == "DSC-RX100M7", f"Unsupported model: {receipt.get('model')!r}")

        nonce = receipt["nonce"]
        stage_dir = f"/tmp_network/.m7-s7sd-{nonce}"
        remote_reader = f"{stage_dir}/mlv2_card_read.elf"
        remote_boot = f"{stage_dir}/mlv2_sd_boot.sh"
        remote_key = f"{stage_dir}/sd.key"
        guard_bytes_raw = (build_stage7.OUT / "mlv2_guard.elf").read_bytes()
        req_bytes_raw = (build_stage7.OUT / "mlv2.req").read_bytes()
        guard_md5 = hashlib.md5(guard_bytes_raw).hexdigest()
        req_md5 = hashlib.md5(req_bytes_raw).hexdigest()

        def body(session):
            preflight = ram.run_start_preflight(session, receipt)
            ram.check_no_existing_ram_state(session, receipt)
            extra_chk, _ = session.command(
                'for d in /tmp_network/.m7-s7sd-* /tmp_network/.m7-bp-*; '
                'do if [ -e "$d" ] || [ -L "$d" ]; then echo "$d"; fi; done'
            )
            extra_paths = [ln.strip() for ln in extra_chk.decode("ascii", "replace").splitlines() if ln.strip()]
            ram.require(not extra_paths, f"Leftover Phase A RAM path(s) present: {extra_paths}")
            applets, _ = ram.detect_busybox_applets(session)
            pre_sd, _ = session.command(f"[ ! -e {SD_DAEMON_DIR} ] && echo CLEAN || echo DIRTY")
            ram.require(pre_sd.decode("ascii", "replace").strip() == "CLEAN", f"{SD_DAEMON_DIR} already exists")

            active_doc = {
                "stage": "7.3-phase-a-ram",
                "status": "pending_boot",
                "nonce": nonce,
                "started_utc": receipt["utc"],
                "stage_dir": stage_dir,
                "daemon_dir": SD_DAEMON_DIR,
                "daemon_pid": None,
                "view_bias": None,
                "im_pid": preflight["pid"],
                "im_starttime": preflight["im_starttime"],
                "seed_pref": seed_line,
                "guard_bytes": len(guard_bytes_raw),
                "guard_md5": guard_md5,
                "guard_sha256": s7_manifest["artifacts"]["guard"]["sha256"],
                "req_bytes": len(req_bytes_raw),
                "req_md5": req_md5,
                "req_sha256": s7_manifest["artifacts"]["request"]["sha256"],
                "reader_sha256": sd_manifest["artifacts"]["reader"]["sha256"],
            }
            active_path.parent.mkdir(parents=True, exist_ok=True)
            ram.write_text_atomic(active_path, json.dumps(active_doc, indent=2) + "\n")

            session.command(f"/bin/busybox mkdir {stage_dir}")
            session.command("/bin/busybox mkdir /tmp_network/mlv2")
            upload_phase_a_file(session, reader_bin, remote_reader, applets, "mlv2_card_read.elf", "500")
            upload_phase_a_file(session, boot_sh, remote_boot, applets, "mlv2_sd_boot.sh", "500")
            upload_phase_a_file(
                session, key_bytes, remote_key, applets, "sd.key", "400", redact_secret=True
            )
            upload_phase_a_file(
                session, seed_line.encode("ascii"), SD_SIM_PERSIST, applets, "sim-setting-precap.cfg", "600"
            )

            before_raw, before_rc = session.command(
                f"{remote_reader} --probe --ram-path /tmp_network", allowed=(0, 1, 2, 3), timeout=15
            )
            receipt["probe_before"] = {
                **parse_probe_output(before_raw.decode("ascii", "replace")),
                "exit_code": before_rc,
            }
            if before_rc != 0 or receipt["probe_before"].get("MLV2_FOUND") != 1:
                for d in (stage_dir, "/tmp_network/mlv2"):
                    session.command(f"/bin/busybox rm -rf {d}", allowed=(0, 1))
                chk, _ = session.command(
                    f"[ ! -e {stage_dir} ] && [ ! -e /tmp_network/mlv2 ] && echo GONE || echo DIRTY",
                    allowed=(0, 1),
                )
                if chk.decode("ascii", "replace").strip() == "GONE" and active_path.exists():
                    active_path.unlink()
                raise usb.ProbeError(f"MLV2.TAR not ready on SD: {receipt['probe_before']}")

            boot_cmd = (
                f"d={stage_dir};s={SD_SIM_PERSIST};"
                f"MLV2_READER=$d/mlv2_card_read.elf MLV2_KEY=$d/sd.key "
                f"MLV2_PERSIST_SRC=$s MLV2_PERSIST_GATE_VALUE=$s "
                f"MLV2_WAIT_MOUNT=1 MLV2_WAIT_IM=2 MLV2_CARD_TRIES=0 MLV2_WAIT_DAEMON=5 "
                f"MLV2_ONCE=1 MLV2_KEEP_GUARD=1 /bin/busybox sh $d/mlv2_sd_boot.sh"
            )
            boot_out, boot_rc = session.command(boot_cmd, allowed=(0, 1), timeout=60)
            receipt["boot_rc"] = boot_rc
            receipt["boot_stdout"] = boot_out.decode("utf8", "replace")

            boot_log, _ = _safe_cat_ram_file(session, "/tmp_network/mlv2/sd-boot.log")
            receipt["sd_boot_log"] = boot_log.decode("utf8", "replace")

            after_raw, after_rc = session.command(
                f"{remote_reader} --probe --ram-path /tmp_network", allowed=(0, 1, 2, 3), timeout=15
            )
            receipt["probe_after"] = {
                **parse_probe_output(after_raw.decode("ascii", "replace")),
                "exit_code": after_rc,
            }

            precap_now, _ = _safe_cat_ram_file(session, "/tmp_network/mlv2/precap.cfg")
            receipt["precap_cfg_after_boot"] = precap_now.decode("ascii", "replace")
            precap_md5_raw, _ = session.command(
                _ram_leaf_vars("/tmp_network/mlv2/precap.cfg")
                + f"{_LEAF_DIRS_OK}&&{_LEAF_OK}&&/bin/busybox md5sum $f 2>/dev/null",
                allowed=(0, 1),
            )
            receipt["precap_cfg_after_boot_md5"] = precap_md5_raw.decode("ascii", "replace").strip()
            dpid_raw, _ = _safe_cat_ram_file(session, f"{SD_DAEMON_DIR}/daemon.pid")
            receipt["daemon_pid_text"] = dpid_raw.decode("ascii", "replace").strip()
            dlog_head, _ = _safe_cat_ram_file(session, f"{SD_DAEMON_DIR}/daemon.log")
            receipt["daemon_log_initial"] = dlog_head.decode("utf8", "replace")

            if boot_rc != 0 or "MLV2_SD_READY" not in receipt["sd_boot_log"]:
                log_lines = [ln.strip() for ln in receipt["sd_boot_log"].splitlines() if ln.strip()]
                saw_install = any(
                    ln.startswith("MLV2_GUARD_INSTALL_BEGIN") or ln.startswith("MLV2_SD_INSTALLED")
                    for ln in log_lines
                )
                saw_pre_refusal = any(
                    any(ln.startswith(tok) for tok in PRE_INSTALL_REFUSAL_LINES)
                    for ln in log_lines
                )
                if not saw_install and saw_pre_refusal:
                    mgr_chk, _ = session.command(
                        "[ ! -e /tmp_network/mlv2/sd-managed ] && [ ! -L /tmp_network/mlv2/sd-managed ] && "
                        "[ ! -e /tmp_network/mlv2/.boot.lock ] && [ ! -L /tmp_network/mlv2/.boot.lock ] "
                        "&& echo CLEAN || echo DIRTY",
                        allowed=(0, 1),
                    )
                    w_obs = observe_boot_worker_clear(session, stage_dir)
                    proc_obs = ram.observe_live_s7_processes(
                        session, f"{SD_DAEMON_DIR}/daemon.elf", f"{SD_DAEMON_DIR}/ring.elf"
                    )
                    if (
                        mgr_chk.decode("ascii", "replace").strip() == "CLEAN"
                        and w_obs["certain_clear"]
                        and proc_obs["certain_clear"]
                    ):
                        for d in (stage_dir, SD_DAEMON_DIR, "/tmp_network/mods", "/tmp_network/mlv2"):
                            session.command(f"/bin/busybox rm -rf {d}", allowed=(0, 1))
                        clean_chk, _ = session.command(
                            f"[ ! -e {stage_dir} ] && [ ! -e {SD_DAEMON_DIR} ] && "
                            f"[ ! -e /tmp_network/mods ] && [ ! -e /tmp_network/mlv2 ] && echo GONE || echo DIRTY",
                            allowed=(0, 1),
                        )
                        if clean_chk.decode("ascii", "replace").strip() == "GONE" and active_path.exists():
                            active_path.unlink()
                else:
                    active_doc["status"] = "boot_failed_pending_collect"
                    ram.write_text_atomic(active_path, json.dumps(active_doc, indent=2) + "\n")
                raise usb.ProbeError(f"mlv2_sd_boot.sh failed (rc={boot_rc}): {receipt['sd_boot_log']}")

            expected_precap_md5 = hashlib.md5(seed_line.encode("ascii")).hexdigest() + "  /tmp_network/mlv2/precap.cfg"
            ram.require(
                receipt["precap_cfg_after_boot"] == seed_line.rstrip("\n")
                and receipt["precap_cfg_after_boot_md5"] == expected_precap_md5,
                f"Restored precap.cfg mismatch: text={receipt['precap_cfg_after_boot']!r} "
                f"md5={receipt['precap_cfg_after_boot_md5']!r} expected_md5={expected_precap_md5!r}",
            )
            pin_s, pins_s, parsed_s, rc_s, text_s = ram.run_pinned_guard_command(
                session,
                "check",
                ram.REMOTE_REQ,
                guard_bytes=len(guard_bytes_raw),
                guard_md5=guard_md5,
                arg_bytes=len(req_bytes_raw),
                arg_md5=req_md5,
                timeout=15,
            )
            receipt["guard_check_after_boot"] = {
                "pin_ok": pin_s,
                "pins": pins_s,
                "rc": rc_s,
                "text": text_s,
                "parsed": parsed_s,
            }
            ram.require(
                pin_s
                and ram.guard_check_matches(
                    parsed_s,
                    rc_s,
                    expected_pid=preflight["pid"],
                    expected_hooks="v2",
                    expected_rects="patched",
                    expected_shim="shim",
                ),
                f"Post-boot guard check did not confirm installed v2 shim: {receipt['guard_check_after_boot']}",
            )
            dpid = ram.validate_pid(receipt["daemon_pid_text"])
            dexe_raw, dexe_rc = session.command(f"/bin/busybox readlink /proc/{dpid}/exe 2>/dev/null", allowed=(0, 1))
            dexe = dexe_raw.decode("utf8", "replace").strip() if dexe_rc == 0 else ""
            dstat_raw, dstat_rc = session.command(f"/bin/busybox cat /proc/{dpid}/stat 2>/dev/null", allowed=(0, 1))
            dstat_parsed = (
                ram.parse_any_proc_stat(dstat_raw.decode("utf8", "replace"), dpid)
                if dstat_rc == 0 else None
            )
            dlog_parsed = ram.parse_daemon_log(receipt["daemon_log_initial"])
            boot_rec = dlog_parsed.get("boot") or {}
            boot_dup_keys = [dk for dk in dlog_parsed.get("duplicate_keys", ()) if dk.get("kind") == "BOOT"]
            receipt["daemon_identity_after_boot"] = {
                "pid": dpid,
                "exe": dexe,
                "stat": dstat_parsed,
                "boot_count": dlog_parsed.get("boot_count", 0),
                "boot": boot_rec,
                "boot_duplicate_keys": boot_dup_keys,
            }
            ram.require(
                dexe == f"{SD_DAEMON_DIR}/daemon.elf"
                and dstat_parsed is not None
                and dstat_parsed.get("state") not in ("Z", "X", "x")
                and dlog_parsed.get("boot_count") == 1
                and not boot_dup_keys
                and boot_rec.get("self_pid") == str(dpid)
                and boot_rec.get("im_pid") == str(preflight["pid"])
                and boot_rec.get("im_st") == str(preflight["im_starttime"]),
                f"Daemon identity/BOOT verification failed: {receipt['daemon_identity_after_boot']}",
            )
            receipt["daemon_pid"] = dpid
            receipt["view_bias"] = parsed_s["view_bias"]
            receipt["start_ready"] = True
            active_doc["status"] = "running"
            active_doc["daemon_pid"] = dpid
            active_doc["view_bias"] = parsed_s["view_bias"]
            ram.write_text_atomic(active_path, json.dumps(active_doc, indent=2) + "\n")

        _with_terminal(camera, receipt, body)


def do_ram_collect(
    camera,
    receipt: dict,
    *,
    active_path: Path = ACTIVE_SD_RAM,
    out_dir: Path = OUT_DIR,
) -> None:
    """Inside usb.connect: verify live session identity first, then stop/collect/restore stock."""
    with ram.custody_lock(active_path):
        ram.require(receipt.get("model") == "DSC-RX100M7", f"Unsupported model: {receipt.get('model')!r}")
        active = _load_and_validate_active(active_path)
        receipt["active_loaded"] = active
        nonce = active["nonce"]
        stage_dir = active["stage_dir"]
        daemon_dir = active["daemon_dir"]
        stamp = receipt["utc"]

        def body(session):
            # ALWAYS verify camera build, tmpfs mount, stock libraries, and live im.elf identity BEFORE any write!
            preflight = ram.run_collect_preflight(
                session,
                receipt,
                expected_prev_pid=active["im_pid"],
                expected_prev_starttime=active["im_starttime"],
            )
            im_state = preflight["im_state"]
            same_im = (
                im_state == "verified_live"
                and preflight["pid"] == active["im_pid"]
                and preflight["im_starttime"] == active["im_starttime"]
            )
            receipt["same_im_session"] = same_im

            if im_state == "uncertain":
                receipt["collect_outcome"] = "uncertain_im_identity"
                receipt["active_state_cleared"] = False
                receipt["next_action"] = "Uncertain im.elf state; power-cycle camera and re-run --ram-collect."
                return

            if not same_im:
                # Camera rebooted (new im.elf pid/starttime or verified_absent): read-only check before clearing custody.
                proc_obs = ram.observe_live_s7_processes(
                    session, f"{daemon_dir}/daemon.elf", f"{daemon_dir}/ring.elf"
                )
                receipt["s7_processes_after_stop"] = proc_obs
                clean_chk, _ = session.command(
                    f"[ ! -e {stage_dir} ] && [ ! -e {daemon_dir} ] && "
                    f"[ ! -e /tmp_network/mods ] && [ ! -e /tmp_network/mlv2 ] && echo GONE || echo DIRTY",
                    allowed=(0, 1),
                )
                ram_state = clean_chk.decode("ascii", "replace").strip()
                receipt["ram_cleanup"] = ram_state
                if ram_state == "GONE" and proc_obs["certain_clear"]:
                    receipt["rebooted_clean_stock"] = True
                    receipt["collect_outcome"] = "rebooted_clean_stock"
                    active_path.unlink()
                    receipt["active_state_cleared"] = True
                else:
                    receipt["collect_outcome"] = "reboot_mismatch_dirty_ram"
                    receipt["active_state_cleared"] = False
                    receipt["next_action"] = "Different im.elf instance with leftover RAM paths; power-cycle camera."
                return

            # Same verified live im.elf session: acquire exclusive ownership of boot/collect transition
            # BEFORE writing stop/sd-disabled, running guard check/uninstall, or deleting any RAM path!
            worker_obs = observe_boot_worker_clear(session, stage_dir)
            receipt["boot_worker_check"] = worker_obs
            if not worker_obs["certain_clear"]:
                receipt["collect_outcome"] = "boot_worker_active"
                receipt["active_state_cleared"] = False
                receipt["next_action"] = (
                    "Boot worker/reader/guard is still active; wait a few seconds and re-run --ram-collect "
                    "(or power-cycle camera)."
                )
                return

            mlv2_raw, _ = session.command(
                "if [ -L /tmp_network/mlv2 ];then echo SYMLINK;"
                "elif [ -d /tmp_network/mlv2 ];then echo DIR;"
                "elif [ -e /tmp_network/mlv2 ];then echo OTHER;"
                "else echo ABSENT;fi",
                allowed=(0, 1),
            )
            mlv2_state = mlv2_raw.decode("ascii", "replace").strip()
            receipt["mlv2_dir_state"] = mlv2_state
            if mlv2_state in ("SYMLINK", "OTHER"):
                receipt["collect_outcome"] = "unsafe_mlv2_dir"
                receipt["active_state_cleared"] = False
                receipt["next_action"] = "Unexpected non-directory /tmp_network/mlv2; power-cycle camera."
                return
            if mlv2_state == "ABSENT":
                if active.get("status") == "stock_verified_pending_cleanup":
                    # Read-only fast path: if ALL Phase A RAM paths are already gone and no s7 process lives,
                    # clear local custody with ZERO camera writes!
                    proc_ro = ram.observe_live_s7_processes(
                        session, f"{daemon_dir}/daemon.elf", f"{daemon_dir}/ring.elf"
                    )
                    receipt["s7_processes_after_stop"] = proc_ro
                    ro_clean, _ = session.command(
                        f"[ ! -e {stage_dir} ] && [ ! -L {stage_dir} ] && "
                        f"[ ! -e {daemon_dir} ] && [ ! -L {daemon_dir} ] && "
                        f"[ ! -e /tmp_network/mods ] && [ ! -L /tmp_network/mods ] && "
                        f"[ ! -e /tmp_network/mlv2 ] && [ ! -L /tmp_network/mlv2 ] && echo GONE || echo DIRTY",
                        allowed=(0, 1),
                    )
                    ro_state = ro_clean.decode("ascii", "replace").strip()
                    receipt["ram_cleanup"] = ro_state
                    if ro_state == "GONE" and proc_ro["certain_clear"]:
                        receipt["daemon_stopped"] = True
                        receipt["uninstalled_clean"] = True
                        receipt["collect_outcome"] = "resumed_stock_verified_cleanup"
                        active_path.unlink()
                        receipt["active_state_cleared"] = True
                        return
                elif active.get("status") != "pending_boot":
                    receipt["collect_outcome"] = "unexpected_absent_mlv2_dir"
                    receipt["active_state_cleared"] = False
                    receipt["next_action"] = (
                        "Expected /tmp_network/mlv2 missing for active session; power-cycle camera and re-run --ram-collect."
                    )
                    return

            # Unconditionally acquire exclusive /tmp_network/mlv2/.boot.lock BEFORE any mutating operation!
            created_mlv2_dir = False
            if mlv2_state == "ABSENT":
                mk_raw, _ = session.command(
                    "if [ -d /tmp_network ]&&[ ! -L /tmp_network ]&&[ ! -e /tmp_network/mlv2 ]&&[ ! -L /tmp_network/mlv2 ];"
                    "then /bin/busybox mkdir /tmp_network/mlv2 2>/dev/null&&echo MK||echo RACE;else echo RACE;fi",
                    allowed=(0, 1),
                )
                created_mlv2_dir = mk_raw.decode("ascii", "replace").strip() == "MK"

            lock_res = _acquire_collect_lock(session)
            receipt["collect_lock_result"] = lock_res
            if lock_res not in ("ACQ", "REACQ"):
                receipt["collect_outcome"] = "boot_worker_lock_held"
                receipt["active_state_cleared"] = False
                receipt["next_action"] = (
                    "Boot worker still holds /tmp_network/mlv2/.boot.lock; wait a few seconds and re-run "
                    "--ram-collect (or power-cycle camera)."
                )
                return
            lock_owned = True

            try:
                ddir_chk, _ = session.command(
                    f"[ -d {daemon_dir} ] && [ ! -L {daemon_dir} ] && echo EXISTS || echo ABSENT",
                    allowed=(0, 1),
                )
                if ddir_chk.decode("ascii", "replace").strip() == "EXISTS":
                    receipt["stop_marker_written"] = _safe_touch_ram_marker(session, daemon_dir, f"{daemon_dir}/stop")
                dpid = active.get("daemon_pid")
                daemon_stopped = False
                for _ in range(30):
                    pid_gone = True
                    if dpid is not None:
                        chk, _ = session.command(
                            f"[ -e /proc/{dpid}/stat ] && echo ALIVE || echo GONE", allowed=(0, 1)
                        )
                        pid_gone = chk.decode("ascii", "replace").strip() == "GONE"
                    proc_obs = ram.observe_live_s7_processes(
                        session, f"{daemon_dir}/daemon.elf", f"{daemon_dir}/ring.elf"
                    )
                    receipt["s7_processes_after_stop"] = proc_obs
                    if pid_gone and proc_obs["certain_clear"]:
                        daemon_stopped = True
                        break
                    time.sleep(0.5)
                receipt["daemon_stopped"] = daemon_stopped

                def grab_with_rc(path: str, local_name: str) -> tuple[str, int]:
                    raw, rc = _safe_cat_ram_file(session, path)
                    text = raw.decode("utf8", "replace")
                    if rc == 0 and text:
                        ram.write_text_atomic(out_dir / f"{stamp}-{nonce}-{local_name}", text)
                    return text, rc

                def grab(path: str, local_name: str) -> str:
                    return grab_with_rc(path, local_name)[0]

                boot_log_state = _inspect_ram_leaf(session, "/tmp_network/mlv2/sd-boot.log")
                receipt["sd_boot_log_state"] = boot_log_state
                sd_boot_log_text, boot_log_rc = "", 1
                if boot_log_state == "FILE_OK":
                    sd_boot_log_text, boot_log_rc = grab_with_rc("/tmp_network/mlv2/sd-boot.log", "sd-boot.log")
                receipt["sd_boot_log"] = sd_boot_log_text
                receipt["sd_boot_log_rc"] = boot_log_rc
                dlog_text = grab(f"{daemon_dir}/daemon.log", "daemon.log")
                receipt["daemon_log_bytes"] = len(dlog_text.encode("utf-8"))
                receipt["daemon_summary"] = ram.parse_daemon_log(dlog_text) if dlog_text else {}
                receipt["mod_loader_log_before"] = grab("/tmp_network/mods/mod_loader.log", "mod_loader-before.log")
                receipt["precap_cfg_before_disable"] = grab("/tmp_network/mlv2/precap.cfg", "precap-before.cfg")
                receipt["sim_persist_before_disable"] = (
                    active.get("sim_persist_before_disable")
                    or grab(SD_SIM_PERSIST, "sim-persist-before.cfg")
                )
                if not active.get("sim_persist_before_disable") and receipt["sim_persist_before_disable"]:
                    active["sim_persist_before_disable"] = receipt["sim_persist_before_disable"]
                    ram.write_text_atomic(active_path, json.dumps(active, indent=2) + "\n")

                guard_state = ram.inspect_file_state(session, ram.REMOTE_GUARD)
                req_state = ram.inspect_file_state(session, ram.REMOTE_REQ)
                uninstalled_clean = False
                sd_stopped_present = False

                if not daemon_stopped:
                    # HARD SAFETY GATE: NEVER attempt live mlv2_guard uninstall while daemon/ring may still run!
                    receipt["collect_outcome"] = "daemon_still_running"
                elif active.get("status") == "stock_verified_pending_cleanup":
                    # Prior collect already verified stock im.elf before USB drop during rm -rf; finish cleanup cleanly.
                    uninstalled_clean = True
                    receipt["collect_outcome"] = "resumed_stock_verified_cleanup"
                elif guard_state == "FILE_OK" and req_state == "FILE_OK":
                    pin_pre, pins_pre, parsed_pre, rc_pre, text_pre = ram.run_pinned_guard_command(
                        session,
                        "check",
                        ram.REMOTE_REQ,
                        guard_bytes=active["guard_bytes"],
                        guard_md5=active["guard_md5"],
                        arg_bytes=active["req_bytes"],
                        arg_md5=active["req_md5"],
                        timeout=15,
                    )
                    receipt["guard_check_before"] = {
                        "pin_ok": pin_pre,
                        "pins": pins_pre,
                        "rc": rc_pre,
                        "text": text_pre,
                        "parsed": parsed_pre,
                    }
                    if pin_pre and ram.guard_check_matches(
                        parsed_pre,
                        rc_pre,
                        expected_pid=active["im_pid"],
                        expected_hooks="stock",
                        expected_rects="stock",
                        expected_shim="zero",
                        expected_view_bias=active.get("view_bias"),
                    ):
                        uninstalled_clean = True
                        receipt["collect_outcome"] = "already_stock_verified"
                    else:
                        receipt["sd_disabled_written"] = _safe_touch_ram_marker(
                            session, "/tmp_network/mlv2", "/tmp_network/mlv2/sd-disabled"
                        )
                        stopped_chk, _ = session.command(
                            "[ -f /tmp_network/mlv2/sd-stopped ] && [ ! -L /tmp_network/mlv2/sd-stopped ] "
                            "&& echo YES || echo NO",
                            allowed=(0, 1),
                        )
                        sd_stopped_present = stopped_chk.decode("ascii", "replace").strip() == "YES"
                        receipt["sd_stopped_present"] = sd_stopped_present

                        if sd_stopped_present:
                            pin_u, pins_u, parsed_u, rc_u, text_u = ram.run_pinned_guard_command(
                                session,
                                "uninstall",
                                ram.REMOTE_REQ,
                                guard_bytes=active["guard_bytes"],
                                guard_md5=active["guard_md5"],
                                arg_bytes=active["req_bytes"],
                                arg_md5=active["req_md5"],
                                timeout=25,
                            )
                            receipt["guard_uninstall"] = {
                                "pin_ok": pin_u,
                                "pins": pins_u,
                                "rc": rc_u,
                                "text": text_u,
                                "parsed": parsed_u,
                            }
                            pin_c, pins_c, parsed_c, rc_c, text_c = ram.run_pinned_guard_command(
                                session,
                                "check",
                                ram.REMOTE_REQ,
                                guard_bytes=active["guard_bytes"],
                                guard_md5=active["guard_md5"],
                                arg_bytes=active["req_bytes"],
                                arg_md5=active["req_md5"],
                                timeout=15,
                            )
                            receipt["guard_check_after"] = {
                                "pin_ok": pin_c,
                                "pins": pins_c,
                                "rc": rc_c,
                                "text": text_c,
                                "parsed": parsed_c,
                            }
                            expected_pid = active["im_pid"]
                            expected_bias = active.get("view_bias") or parsed_u.get("view_bias")
                            uninstalled_clean = (
                                pin_u
                                and expected_bias is not None
                                and ram.guard_uninstall_matches(
                                    parsed_u,
                                    rc_u,
                                    expected_pid=expected_pid,
                                    expected_view_bias=expected_bias,
                                )
                                and pin_c
                                and ram.guard_check_matches(
                                    parsed_c,
                                    rc_c,
                                    expected_pid=expected_pid,
                                    expected_hooks="stock",
                                    expected_rects="stock",
                                    expected_shim="zero",
                                    expected_view_bias=expected_bias,
                                )
                            )
                elif active.get("status") in ("pending_boot", "boot_failed_pending_collect"):
                    pre_chk, _ = session.command(
                        "[ ! -e /tmp_network/mlv2/sd-managed ] && [ ! -L /tmp_network/mlv2/sd-managed ] "
                        "&& echo PRE_BOOT_CLEAN || echo TOUCHED",
                        allowed=(0, 1),
                    )
                    if pre_chk.decode("ascii", "replace").strip() == "PRE_BOOT_CLEAN":
                        if (
                            active.get("status") == "pending_boot"
                            and boot_log_state == "FILE_ABSENT"
                        ):
                            pre_dirs, _ = session.command(
                                f"[ ! -e {daemon_dir} ] && [ ! -L {daemon_dir} ] && "
                                f"[ ! -e /tmp_network/mods ] && [ ! -L /tmp_network/mods ] && echo CLEAN || echo DIRTY",
                                allowed=(0, 1),
                            )
                            if pre_dirs.decode("ascii", "replace").strip() == "CLEAN":
                                uninstalled_clean = True
                                receipt["collect_outcome"] = "pre_boot_upload_aborted_clean"
                            else:
                                receipt["collect_outcome"] = "pre_boot_stock_unverified"
                        elif boot_log_state == "FILE_OK" and boot_log_rc == 0:
                            log_lines = [ln.strip() for ln in sd_boot_log_text.splitlines() if ln.strip()]
                            saw_install = any(
                                ln.startswith("MLV2_GUARD_INSTALL_BEGIN") or ln.startswith("MLV2_SD_INSTALLED")
                                for ln in log_lines
                            )
                            saw_pre_refusal = any(
                                any(ln.startswith(tok) for tok in PRE_INSTALL_REFUSAL_LINES)
                                for ln in log_lines
                            )
                            if log_lines and not saw_install and saw_pre_refusal:
                                uninstalled_clean = True
                                receipt["collect_outcome"] = "pre_boot_refusal_recovered"
                            else:
                                receipt["collect_outcome"] = "pre_boot_stock_unverified"
                        else:
                            receipt["collect_outcome"] = "pre_boot_stock_unverified"

                receipt["sd_stopped_present"] = sd_stopped_present
                receipt["sim_persist_after_disable"] = grab(SD_SIM_PERSIST, "sim-persist-after.cfg")
                receipt["mod_loader_log_after"] = grab("/tmp_network/mods/mod_loader.log", "mod_loader-after.log")
                receipt["sim_persist_preserved_across_disable"] = (
                    bool(receipt["sim_persist_before_disable"])
                    and receipt["sim_persist_before_disable"] == receipt["sim_persist_after_disable"]
                )
                receipt["uninstalled_clean"] = uninstalled_clean

                if uninstalled_clean and daemon_stopped:
                    # Durable stock-verified checkpoint BEFORE deleting guard/request/RAM directories!
                    if active.get("status") != "stock_verified_pending_cleanup":
                        active["status"] = "stock_verified_pending_cleanup"
                        ram.write_text_atomic(active_path, json.dumps(active, indent=2) + "\n")
                    # Hold .boot.lock across EVERY deletion; release .boot.lock + rmdir /tmp_network/mlv2 LAST!
                    for d in (stage_dir, daemon_dir, "/tmp_network/mods"):
                        session.command(f"/bin/busybox rm -rf {d}", allowed=(0, 1))
                    session.command(
                        'm=/tmp_network/mlv2;for f in $m/* $m/.*;do '
                        'case "$f" in "$m/."|"$m/.."|"$m/.boot.lock"|"$m/*"|"$m/.*") continue;;esac;'
                        '/bin/busybox rm -rf "$f";done',
                        allowed=(0, 1),
                    )
                    rel_res = _release_collect_lock(session, try_rmdir_parent=True)
                    receipt["collect_lock_release"] = rel_res
                    if rel_res in ("REL", "NOT_OWNED"):
                        lock_owned = False
                    clean_chk, _ = session.command(
                        f"[ ! -e {stage_dir} ] && [ ! -L {stage_dir} ] && "
                        f"[ ! -e {daemon_dir} ] && [ ! -L {daemon_dir} ] && "
                        f"[ ! -e /tmp_network/mods ] && [ ! -L /tmp_network/mods ] && "
                        f"[ ! -e /tmp_network/mlv2 ] && [ ! -L /tmp_network/mlv2 ] && echo GONE || echo DIRTY",
                        allowed=(0, 1),
                    )
                    receipt["ram_cleanup"] = clean_chk.decode("ascii", "replace").strip()
                    if receipt["ram_cleanup"] == "GONE":
                        lock_owned = False
                        active_path.unlink()
                        receipt["active_state_cleared"] = True
                else:
                    receipt["next_action"] = (
                        "Daemon/ring is still running; wait a moment and re-run --ram-collect (or power-cycle camera)."
                        if not daemon_stopped
                        else (
                            "Disconnect USB, press MENU once on camera so core.bin writes sd-stopped, "
                            "reconnect USB, and re-run --ram-collect."
                            if (guard_state == "FILE_OK" and not sd_stopped_present)
                            else "Inspect guard_uninstall / collect_outcome or power-cycle camera before re-running --ram-collect."
                        )
                    )
            finally:
                if lock_owned and not getattr(getattr(camera, "dev", None), "poisoned", False):
                    try:
                        rel_res = _release_collect_lock(session, try_rmdir_parent=created_mlv2_dir)
                        receipt["collect_lock_finally_release"] = rel_res
                        if rel_res in ("REL", "NOT_OWNED"):
                            lock_owned = False
                    except Exception:
                        pass

        _with_terminal(camera, receipt, body)


def run_boot_probe(*, key_file: Path = DEFAULT_KEY_FILE, out_dir: Path = OUT_DIR) -> dict:
    sd_manifest = sd_builder.verify_seal()
    reader_bin = (sd_builder.OUT_SD / "mlv2_card_read.elf").read_bytes()
    nonce = secrets.token_hex(6)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now()
    out_path = out_dir / f"{stamp}-{nonce}-boot-probe.json"
    receipt: dict[str, object] = {
        "stage": "7.3-phase-a-boot-probe",
        "nonce": nonce,
        "utc": stamp,
        "flash_writes_performed": False,
        "sd_writes_performed": False,
        "reader_sha256": sd_manifest["artifacts"]["reader"]["sha256"],
        "commands": [],
        "steps": [],
    }
    try:
        usb.connect(
            receipt,
            diagnostic=lambda cam, rec: do_boot_probe(cam, rec, reader_bin, key_file=key_file),
            gate_factory=ram.Stage7Gate,
        )
    except (Exception, KeyboardInterrupt) as err:
        receipt["error"] = f"{type(err).__name__}: {err}"
    ram.write_text_atomic(out_path, json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    receipt["result_path"] = str(out_path)
    return receipt


def run_ram_start(
    *,
    key_file: Path = DEFAULT_KEY_FILE,
    seed_pref: str = "S7PC1 1 8",
    active_path: Path = ACTIVE_SD_RAM,
    out_dir: Path = OUT_DIR,
) -> dict:
    seed_line = seed_pref.strip() + "\n"
    if not ram.parse_precap_cfg(seed_line)["valid"]:
        raise ValueError(f"Invalid --seed-pref {seed_pref!r}; expected 'S7PC1 <0|1> <1|2|3|5|8|10>'")
    s7_manifest = build_stage7.verify_seal()
    sd_manifest = sd_builder.verify_seal()
    key_bytes = load_or_create_key(key_file, create=False)
    reader_bin = (sd_builder.OUT_SD / "mlv2_card_read.elf").read_bytes()
    boot_sh = (sd_builder.OUT_SD / "mlv2_sd_boot.sh").read_bytes()
    nonce = secrets.token_hex(6)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now()
    out_path = out_dir / f"{stamp}-{nonce}-ram-start.json"
    receipt: dict[str, object] = {
        "stage": "7.3-phase-a-ram-start",
        "nonce": nonce,
        "utc": stamp,
        "flash_writes_performed": False,
        "sd_writes_performed": False,
        "seed_pref": seed_line,
        "sd_daemon_dir": SD_DAEMON_DIR,
        "sim_persist_path": SD_SIM_PERSIST,
        "commands": [],
        "steps": [],
    }
    try:
        usb.connect(
            receipt,
            diagnostic=lambda cam, rec: do_ram_start(
                cam,
                rec,
                s7_manifest=s7_manifest,
                sd_manifest=sd_manifest,
                reader_bin=reader_bin,
                boot_sh=boot_sh,
                key_bytes=key_bytes,
                seed_line=seed_line,
                active_path=active_path,
            ),
            gate_factory=ram.Stage7Gate,
        )
    except (Exception, KeyboardInterrupt) as err:
        receipt["error"] = f"{type(err).__name__}: {err}"
    ram.write_text_atomic(out_path, json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    receipt["result_path"] = str(out_path)
    return receipt


def run_ram_collect(*, active_path: Path = ACTIVE_SD_RAM, out_dir: Path = OUT_DIR) -> dict:
    with ram.custody_lock(active_path):
        active = _load_and_validate_active(active_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now()
    nonce = active["nonce"]
    out_path = out_dir / f"{stamp}-{nonce}-ram-collect.json"
    receipt: dict[str, object] = {
        "stage": "7.3-phase-a-ram-collect",
        "nonce": nonce,
        "utc": stamp,
        "flash_writes_performed": False,
        "sd_writes_performed": False,
        "commands": [],
        "steps": [],
    }
    try:
        usb.connect(
            receipt,
            diagnostic=lambda cam, rec: do_ram_collect(cam, rec, active_path=active_path, out_dir=out_dir),
            gate_factory=ram.Stage7Gate,
        )
    except (Exception, KeyboardInterrupt) as err:
        receipt["error"] = f"{type(err).__name__}: {err}"
    ram.write_text_atomic(out_path, json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    receipt["result_path"] = str(out_path)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prep-card", action="store_true", help="Write signed MLV2.TAR to mounted SD root")
    mode.add_argument("--boot-probe", action="store_true", help="Read-only M7 boot/SD/RAM telemetry")
    mode.add_argument("--ram-start", action="store_true", help="100% RAM-only SD-boot live test")
    mode.add_argument("--ram-collect", action="store_true", help="Collect Phase A RAM test & restore stock")

    parser.add_argument("--sd-root", type=Path, help="Mounted SD card root directory (for --prep-card)")
    parser.add_argument("--key-file", type=Path, default=DEFAULT_KEY_FILE, help="32-byte owner HMAC key file")
    parser.add_argument("--release-seq", type=int, default=1, help="Release sequence number (for --prep-card)")
    parser.add_argument("--clear-disable-markers", action="store_true")
    parser.add_argument("--seed-pref", default="S7PC1 1 8", help="Initial simulated durable preference")
    args = parser.parse_args(argv)

    if args.prep_card:
        if args.sd_root is None:
            parser.error("--prep-card requires --sd-root")
        res = prep_card(
            args.sd_root,
            key_file=args.key_file,
            release_seq=args.release_seq,
            clear_disable_markers=args.clear_disable_markers,
        )
        print(json.dumps(res, indent=2))
        return 0
    if args.boot_probe:
        res = run_boot_probe(key_file=args.key_file)
        print(f"RESULT={res['result_path']}")
        return 0 if not res.get("error") and res.get("probe_dir_cleanup") == "GONE" else 1
    if args.ram_start:
        res = run_ram_start(key_file=args.key_file, seed_pref=args.seed_pref)
        print(f"RESULT={res['result_path']}")
        return 0 if res.get("start_ready") and not res.get("error") else 1
    res = run_ram_collect()
    print(f"RESULT={res['result_path']}")
    return 0 if res.get("active_state_cleared") and not res.get("error") else 1


if __name__ == "__main__":
    raise SystemExit(main())
