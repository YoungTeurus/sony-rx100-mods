#!/usr/bin/env python3
"""Observe RX100M7 power transitions and a volatile Bluetooth-directory marker."""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
import uuid

import m7_stage7_phaseb_collect as pb

base = pb.collect_base
OUT = pb.OUT_RECEIPT_DIR
MARK = ".m7-pb-bt-ret.txt"
PREFIX = ".m7-pb-bt-ret."
NEW_NAME = re.compile(r"\.m7-pb-bt-ret\.([0-9a-f]{12})\.([0-9a-f]{32})\.[A-Za-z0-9]{6}", re.ASCII)
DISCOVER = (f'[ -r . ] && [ -x . ] || exit 1; set -- ./{PREFIX}*; for f; do if [ -e "$f" ] || [ -L "$f" ]; '
            'then echo "$f"; fi; done')
RECOVERY = ("Ownership of the incomplete marker is unverified. End this transition series, "
            "power the camera off and let volatile RAM lose power, then check for absence "
            "on a fresh Bluetooth tmpfs before planting again.")
INODE_TOKEN = re.compile(r"M7BT ([0-9a-f]{12}) ([0-9a-f]{24})\n", re.ASCII)
DISCLOSURE = [
    "Sony libsencore.so authentication and FileControl READ may update /setting/.etools (4096 B) if present.",
    "BusyBox ash HISTFILE=/dev/null is best-effort on this build.",
    "StopSenser transport success does not confirm physical return to normal camera UI.",
]
FS_PATHS = ("/tmp_bt", "/tmp_network", "/setting", "/etc", "/system")
MOUNTINFO = 'if [ -e /proc/self/mountinfo ]; then /bin/busybox cat /proc/self/mountinfo; fi'
ACTIONS = ("check", "plant", "check-and-remove")
# Functions defined in the interactive shell never change its cwd. Every
# marker command enters the checked directory in a short-lived subshell.
ENTER = 'cd -P /tmp_bt && bt_guard'


def state_command(name):
    return (f'f=./{name}; if [ -L "$f" ]; then echo UNSAFE; '
            'elif [ -f "$f" ]; then echo REGULAR; elif [ -e "$f" ]; then echo UNSAFE; else echo ABSENT; fi')


@contextlib.contextmanager
def custody(directory):
    """Pin each component of the receipt directory with O_NOFOLLOW."""
    directory = directory.absolute()
    flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY
    fd = os.open("/", flags)
    try:
        for index, part in enumerate(directory.parts[1:], start=1):
            if part in (".", ".."):
                raise ValueError("Noncanonical receipt directory")
            if index == len(directory.parts) - 1:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def tmpfs_rw(mounts):
    entries = pb._parse_mounts_strict(mounts)
    if any(path.startswith("/tmp_bt/" + PREFIX) for path in entries):
        raise ValueError("Unexpected mount over marker")
    rows = entries.get("/tmp_bt", [])
    return len(rows) == 1 and rows[0]["fstype"] == "tmpfs" and "rw" in rows[0]["opts"]


def mount_device(mountinfo):
    """Return the kernel device number of a single rw /tmp_bt tmpfs mount."""
    matches = []
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        fields, fs = before.split(), after.split()
        if not separator or len(fields) < 6 or len(fs) != 3:
            raise ValueError("Malformed mountinfo")
        if fields[4].startswith("/tmp_bt/" + PREFIX):
            raise ValueError("Unexpected mountinfo over marker")
        if fields[4] == "/tmp_bt":
            matches.append((fields, fs))
    if len(matches) != 1:
        return None
    fields, fs = matches[0]
    if (fs[0] != "tmpfs" or fields[3] != "/" or not all(n.isdecimal() for n in fields[:2])
            or any("rw" not in opts.split(",") or "ro" in opts.split(",") for opts in (fields[5], fs[2]))
            or not re.fullmatch(r"[0-9]+:[0-9]+", fields[2])):
        return None
    return tuple(int(value) for value in fields[2].split(":"))


def mount_guard(mounts, info):
    if not tmpfs_rw(mounts) or mount_device(info) is None:
        raise ValueError("Missing matching rw tmpfs mount and mountinfo witnesses")
    # Bind to the complete namespace snapshots, including mount ID, device,
    # flags and mount stack. Verify the pinned cwd against the visible name
    # after reading both kernel tables and immediately before the operation.
    mi, mt = (hashlib.md5(raw.encode("ascii")).hexdigest() for raw in (info, mounts))
    return ('bt_guard() { [ ! -L /tmp_bt ] && '
            'set -- $(/bin/busybox md5sum /proc/self/mountinfo /proc/mounts) && '
            f'[ "$#" = 4 ] && [ "$1" = "{mi}" ] && [ "$3" = "{mt}" ] && '
            '[ . -ef /tmp_bt ]; }')


def scoped(cmd):
    return f"({ENTER} && {{ {cmd}; }})"


def find_marker(session):
    names = session.command("marker_names", scoped(DISCOVER))[0].splitlines()
    if not names:
        return None
    if len(names) != 1 or not names[0].startswith("./"):
        raise ValueError("Ambiguous marker directory entries")
    name = names[0][2:]
    if name != MARK and not NEW_NAME.fullmatch(name):
        raise ValueError("Unexpected marker name")
    return name


def observe_marker(session, name):
    if name is None:
        return {"state": "ABSENT"}
    state = session.command("marker_state", scoped(state_command(name)))[0].strip()
    if state != "REGULAR":
        raise ValueError("Unsafe or changed marker type")
    meta_cmd = scoped(f"/bin/busybox ls -li ./{name}")
    meta = session.command("marker_meta", meta_cmd)[0].rstrip("\n")
    match = pb.LS_FILE_INODE_RE.fullmatch(meta)
    if (not match or match[4] != "./" + name or int(match[2]) > 43
            or not pb._is_valid_ls_mtime(match[3])):
        raise ValueError("Invalid marker metadata")
    raw = session.command_bytes("marker_read", scoped(f"/bin/busybox dd if=./{name} bs=1 count=44 2>/dev/null"))[0]
    content = raw.decode("ascii")
    if len(raw) != int(match[2]) or (len(raw) == 43 and not (
            INODE_TOKEN.fullmatch(content) or pb.RAM_MARKER_TOKEN_RE.fullmatch(content))):
        raise ValueError("Invalid marker content")
    if session.command("marker_meta_after", meta_cmd)[0].rstrip("\n") != meta:
        raise ValueError("Marker changed during read")
    return {"state": state, "inode": int(match[1]), "bytes": len(raw),
            "content": content, "md5": hashlib.md5(raw).hexdigest()}


def checkpoint(directory, name, payload):
    # Immutable records keep ownership evidence across process crashes and
    # failed final receipt writes. Publish only after the data reaches disk.
    temp = "." + name + "-" + secrets.token_hex(6)
    with receipt_output(directory, name, temp=temp) as output:
        json.dump(payload, output, ensure_ascii=True)


def read_record(directory, name):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(name, flags, dir_fd=directory), encoding="utf-8") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("Invalid custody record type")
        return json.load(source)


def inode_token(nonce, seed, inode):
    digest = hashlib.md5(f"{seed} {inode}\n".encode("ascii")).hexdigest()
    return f"M7BT {nonce} {digest[:24]}\n"


def known_marker(directory, observation):
    match = INODE_TOKEN.fullmatch(observation["content"])
    if match:
        nonce = match[1]
        name = f"bt-{nonce}.intent"
        intent = read_record(directory, name)
        if (intent.get("path") != "/tmp_bt/" + MARK or intent.get("nonce") != nonce
                or not re.fullmatch("[0-9a-f]{32}", intent.get("seed", ""))):
            raise ValueError("Invalid marker ownership record")
        expected = inode_token(nonce, intent["seed"], observation["inode"])
        if expected != observation["content"]:
            raise ValueError("Plant intent inode or content mismatch")
        return name

    # An r1 marker has no creation-inode tag. Only accept the inode and
    # bytes already captured by its plant receipt, independent of teardown.
    nonce, utc = pb.RAM_MARKER_TOKEN_RE.fullmatch(observation["content"]).groups()
    for name in os.listdir(directory):
        if name.startswith(f"{utc}-{nonce}-bt-") and name.endswith(".json"):
            prior = read_record(directory, name)
            record = prior.get("marker", {})
            if (prior.get("ram_marker_mode") == "plant" and prior.get("nonce") == nonce
                    and prior.get("utc") == utc and record.get("status") == "planted"
                    and record.get("after") == observation):
                return name
    raise ValueError("No verified plant receipt matches legacy marker bytes and inode")


def mount_row(receipt):
    return [line for line in receipt["mountinfo"].splitlines() if line.split()[4] == "/tmp_bt"]


def ownership(directory, name, before, receipt):
    match = NEW_NAME.fullmatch(name)
    if match:
        nonce, seed = match.groups()
        intent_name = f"bt-{nonce}.intent"
        intent = read_record(directory, intent_name)
        if intent.get("template") != f"{PREFIX}{nonce}.{seed}.XXXXXX" or intent.get("seed") != seed:
            raise ValueError("Invalid marker ownership record")
        try:
            bound = read_record(directory, f"bt-{nonce}.inode")
        except FileNotFoundError:
            # mkstemp created the unpredictable intent-scoped name, but no inode
            # was acknowledged. Never attribute retention or unlink a replacement.
            raise ValueError(RECOVERY)
        if bound != {"name": name, "inode": before["inode"]}:
            raise ValueError("Plant intent inode or content mismatch")
        expected = inode_token(nonce, seed, before["inode"])
        if before["bytes"] == 43:
            if expected != before["content"]:
                raise ValueError("Plant intent inode or content mismatch")
        elif (not expected.startswith(before["content"]) or intent.get("boot_id") != receipt["boot_id"]
              or intent.get("mount_row") != mount_row(receipt)):
            raise ValueError(RECOVERY)
        return intent_name
    if before["bytes"] == 43:
        return known_marker(directory, before)
    # Old intents alone cannot distinguish an empty fixed name from a foreign
    # file. A prior exact plant observation in this boot and mount can.
    for prior_name in os.listdir(directory):
        if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}-bt-.+\.json", prior_name):
            continue
        try:
            prior = read_record(directory, prior_name)
        except (OSError, ValueError):
            continue
        if prior.get("ram_marker_mode") != "plant" or prior.get("boot_id") != receipt["boot_id"]:
            continue
        marker_record = prior.get("marker", {})
        old = marker_record.get("after", {})
        if (marker_record.get("status") == "planted" and marker_record.get("name", MARK) == MARK
                and old.get("inode") == before["inode"] and old.get("bytes") == 43
                and old["content"].startswith(before["content"]) and mount_row(prior) == mount_row(receipt)):
            known_marker(directory, old)
            return prior_name
    raise ValueError(RECOVERY)


# A quoted empty heredoc on this ash is an anonymous pipe. Keep its write end
# alive until the host has duplicated the creator's exclusive file descriptor.
FD_FREE = '[ ! -L /proc/self/fd/7 ] && [ ! -L /proc/self/fd/8 ] && [ ! -L /proc/self/fd/9 ]'
PIPE_OPEN = r"""eval "$(/bin/busybox echo -e 'exec 8<<"M7EOF"\nM7EOF\n ')" && [ -p /proc/self/fd/8 ] && exec 9>/proc/self/fd/8"""
# Once this returns, only a bounded sleep retains the pipe writer. An abandoned
# terminal cannot leave the extractor blocked waiting for archive payload.
PIPE_DEADLINE = '(/bin/busybox sleep 10 0>&9 8<&- 9>&- >/dev/null 2>&1 &) && exec 9>&-'
PIPE_CLOSE = 'exec 9>&- 8<&- 7>&-'
CREATOR = '/bin/busybox cpio -i <&8 8<&- 9>&- 3>&- >/dev/null 2>&1 & echo $!'


def allocation_header(name):
    # One newc regular member. Its single archive payload byte is deliberately
    # withheld. On EOF BusyBox's exact-length copy dies before pathname chmod.
    # At 0x1fbca the original extractor unlinks only for a strictly greater
    # signed existing mtime. INT32_MAX forces every pre-existing name to skip.
    fields = (1, 0o100600, 0, 0, 1, 0x7fffffff, 1, 0, 0, 0, 0, len(name) + 1, 0)
    header = "070701" + "".join(f"{field:08x}" for field in fields) + name
    return header + r"\000" * (1 + (-(len(header) + 1) % 4))


def plant_marker(session, receipt, directory):
    nonce = receipt["nonce"]
    if not re.fullmatch(r"[0-9a-f]{12}", nonce):
        raise ValueError("Invalid nonce")
    seed = secrets.token_hex(16)
    prefix = f"{PREFIX}{nonce}.{seed}."
    name = prefix + secrets.token_hex(3)
    checkpoint(directory, f"bt-{nonce}.intent", dict(template=prefix + "XXXXXX", seed=seed,
               boot_id=receipt["boot_id"], mount_row=mount_row(receipt)))
    session.command("marker_fd_preflight", FD_FREE)
    try:
        session.command("marker_pipe", PIPE_OPEN)
        session.command("marker_header", f"/bin/busybox echo -ne '{allocation_header(name)}' >&9")
        session.command("marker_pipe_deadline", PIPE_DEADLINE)
        # cpio receives only our private pipe, with fd 3 closed on entry. Its
        # first member open is the O_WRONLY|O_CREAT|O_EXCL descriptor.
        receipt["project_write_destinations"].append("/tmp_bt/" + name)
        pid = session.command("marker_create", scoped(CREATOR))[0].strip()
        if not re.fullmatch(r"[1-9][0-9]{0,9}", pid):
            raise ValueError("Missing exclusive creator PID")
        # The loader may briefly use fd 3 for a shared library at startup.
        # Wait for the member pathname on the stock applet and our private pipe.
        session.command("marker_creator_ref", f'bt_p=/proc/{pid}; bt_c=$bt_p/fd/3; bt_target=/tmp_bt/{name}')
        session.command("marker_creator_guard", 'bt_owned() { [ "$bt_p/exe" -ef /bin/busybox ] && '
                        '[ "$bt_p/fd/0" -ef /proc/self/fd/8 ] && [ -f "$bt_c" ] && '
                        '[ "$(/bin/busybox readlink "$bt_c")" = "$bt_target" ]; }')
        pin = ('for i in 1 2 3 4 5; do bt_owned && break; /bin/busybox usleep 20000; done; '
               'bt_owned && exec 7<>"$bt_c" && bt_owned && [ /proc/self/fd/7 -ef "$bt_c" ] && '
               '/bin/busybox ls -Li /proc/self/fd/7')
        witness = session.command("marker_pin_creator", pin)[0].strip()
        matched = re.fullmatch(r"([1-9][0-9]{0,19})\s+/proc/self/fd/7", witness)
        if not matched:
            raise ValueError("Missing exclusive creation inode")
        inode = int(matched[1])
        identity = (f'f=./{name}; d=/proc/self/fd/7; [ ! -L "$f" ] && [ -f "$d" ] && '
                    '[ "$f" -ef "$d" ]')
        session.command("marker_created_identity", scoped(identity))
        checkpoint(directory, f"bt-{nonce}.inode", {"name": name, "inode": inode})
        token = inode_token(nonce, seed, inode).rstrip("\n")
        session.command("marker_plant", scoped(identity + f' && echo "{token}" >&7'))
        raw = session.command_bytes("marker_readback", scoped(identity + ' && /bin/busybox dd if="$d" bs=1 count=44 2>/dev/null'))[0]
        if raw != (token + "\n").encode("ascii") or find_marker(session) != name:
            raise ValueError("Planted marker readback mismatch")
        session.command("marker_final_identity", scoped(identity))
        return name, dict(state="REGULAR", inode=inode, bytes=len(raw), content=raw.decode("ascii"),
                          md5=hashlib.md5(raw).hexdigest())
    finally:
        active_error = sys.exc_info()[0]
        try:
            session.command("marker_close_descriptors", PIPE_CLOSE)
        except Exception as err:
            receipt["marker_fd_close_error"] = f"{type(err).__name__}: {err}"
            if active_error is None:
                raise


def marker(session, receipt, directory):
    mode = receipt["ram_marker_mode"]
    if not tmpfs_rw(receipt["mounts_raw"]):
        return {"status": "skipped_not_tmpfs"}
    session.command("define_mount_guard", mount_guard(receipt["mounts_raw"], receipt["mountinfo"]))
    name = find_marker(session)
    before = observe_marker(session, name)
    result = {"before": before, "name": name}
    if name:
        result["plant_receipt"] = ownership(directory, name, before, receipt)
    if mode == "check" or (mode == "check-and-remove" and name is None):
        status = "incomplete" if name and before["bytes"] < 43 else before["state"].lower()
        return dict(result, status=status, after=before)
    if mode == "plant":
        if name is not None:
            raise ValueError("Marker already exists. Use check-and-remove first.")
        name, after = plant_marker(session, receipt, directory)
        return dict(result, name=name, status="planted", after=after)
    inode = before["inode"]
    # Hold the checksum subject open and compare the final name to that fd
    # immediately before unlinking. rm receives only the validated basename.
    cmd = (f'f=./{name}; d=/proc/self/fd/7; [ ! -L "$f" ] && [ -f "$f" ] && exec 7<"$f" && '
           f'set -- $(/bin/busybox ls -Li "$d") && [ "$1" = "{inode}" ] && '
           f'set -- $(/bin/busybox md5sum "$d") && [ "$1" = "{before["md5"]}" ] && '
           'bt_guard && [ ! -L "$f" ] && [ "$f" -ef "$d" ] && /bin/busybox rm "$f"')
    receipt["project_write_destinations"].append("/tmp_bt/" + name)
    session.command("marker_remove", scoped(cmd))
    after = observe_marker(session, find_marker(session))
    if after["state"] != "ABSENT":
        raise ValueError("Marker removal unverified")
    return dict(result, status="removed", after=after)


def capture(camera, receipt, directory):
    if receipt.get("model") != pb.MODEL:
        raise ValueError("Unexpected camera model")
    session = pb.PhaseBTerminalSession(camera, receipt)
    toggles = receipt["terminal_toggles"]
    base.toggle_terminal(camera, False, toggles, phase="pre_disable")
    try:
        base.toggle_terminal(camera, True, toggles, phase="enable")
        with pb.probe.deadline(10):
            receipt["shell_banner"] = pb.read_ready(camera).decode("utf-8", "replace")
        session.command("setup", pb.SETUP_CMD)
        mounts = session.command("mounts", pb.MOUNTS_CMD)[0]
        receipt["mounts_raw"] = mounts
        receipt["verified_mounts"] = pb.verify_transition_mounts(mounts)
        ancestors = session.command("ancestors", pb.TRANSITION_ANCESTOR_CHECK_CMD)[0]
        base.verify_ancestor_check(ancestors, ("/tmp_network",))
        receipt["version_txt"] = session.command("version", pb.VERSION_CMD)[0].strip()
        if receipt["version_txt"] != pb.BUILD:
            raise ValueError("Unexpected camera build")
        receipt["boot_id"] = str(uuid.UUID(session.command("boot_id", pb.BOOT_ID_CMD)[0].strip()))
        receipt["uptime"] = session.command("uptime", pb.UPTIME_CMD)[0].strip()
        if not re.fullmatch(r"[0-9]+\.[0-9]+ [0-9]+\.[0-9]+", receipt["uptime"]):
            raise ValueError("Malformed /proc/uptime")
        receipt["cmdline"] = session.command("cmdline", pb.CMDLINE_CMD)[0].strip()
        if not receipt["cmdline"]:
            raise ValueError("Empty kernel command line")
        receipt["mountinfo"] = session.command("mountinfo", MOUNTINFO)[0]
        mount_device(receipt["mountinfo"])
        receipt["directories"] = {}
        for path in FS_PATHS[:2]:
            cmd = (f'if [ -L {path} ]; then (exit 1); elif [ -d {path} ]; then /bin/busybox ls -lai {path}; '
                   f'elif [ ! -e {path} ]; then echo ABSENT; else (exit 1); fi')
            listing = session.command_bytes("list" + path, cmd)[0].decode("utf-8", "replace")
            if listing.strip() == "ABSENT":
                if path == "/tmp_network" or path in pb._parse_mounts_strict(mounts):
                    raise ValueError("Mounted directory disappeared")
                receipt["directories"][path] = {"state": "absent"}
            else:
                receipt["directories"][path] = dict(pb.parse_tmp_network_ls(listing), listing=listing)
        receipt["df_k"] = {path: {"status": "df_unavailable", "mount_source": "/proc/mounts"}
                           for path in FS_PATHS}
        rows, raced = pb.parse_proc_snapshot_bytes(session.command_bytes("processes", pb.PROC_SNAPSHOT_CMD, timeout=90)[0])
        for row in rows:
            row["comm"] = row["stat"].split(" (", 1)[1].rsplit(") ", 1)[0]
        receipt["processes"], receipt["raced_pids"] = rows, raced
        log = session.command_bytes("dmesg", pb.DMESG_CMD, timeout=45)[0]
        if not log:
            raise ValueError("Empty dmesg")
        receipt.update(dmesg=log.decode("utf-8", "replace"), dmesg_b64=base64.b64encode(log).decode("ascii"),
                       dmesg_bytes=len(log), dmesg_sha256=hashlib.sha256(log).hexdigest())
        receipt["telemetry_complete"] = True
        receipt["marker"] = marker(session, receipt, directory)
        receipt["capture_complete"] = True
    except (Exception, KeyboardInterrupt) as err:
        receipt["error"] = f"{type(err).__name__}: {err}"
        raise
    finally:
        try:
            base.toggle_terminal(camera, False, toggles, phase="final_disable")
            receipt["terminal_disable_verified"] = True
        except Exception as err:
            receipt["terminal_disable_error"] = f"{type(err).__name__}: {err}"
            if "error" not in receipt:
                raise


def names_inode(directory, name, inode):
    try:
        entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return os.path.samestat(entry, inode)


@contextlib.contextmanager
def receipt_output(directory, filename, *, temp=None):
    temp = temp or "." + filename + ".partial"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(temp, flags, 0o600, dir_fd=directory), "wb") as staged:
        inode = os.fstat(staged.fileno())
        try:
            try:
                os.stat(filename, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(filename)
            # The held fd prevents inode reuse. Link through the macOS volume
            # inode namespace or Linux procfd so a late temp rename cannot
            # redirect the link. EEXIST still preserves a competing final name.
            if sys.platform == "darwin":
                source = f"/.vol/{inode.st_dev & 0xffffffff}/{inode.st_ino}"
            else:
                source = f"/proc/self/fd/{staged.fileno()}"
            if not os.path.samestat(inode, os.stat(source)):
                raise OSError("Host cannot resolve receipt staging inode")
            with io.StringIO() as output:
                yield output
                expected = output.getvalue().encode("utf-8")
            staged.write(expected)
            staged.flush()
            os.fsync(staged.fileno())
            if not names_inode(directory, temp, inode):
                raise OSError("Receipt staging name changed before publication")

            os.link(source, filename, dst_dir_fd=directory, follow_symlinks=True)
            try:
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                with os.fdopen(os.open(filename, flags, dir_fd=directory), "rb") as published:
                    final = os.fstat(published.fileno())
                    if (not os.path.samestat(final, inode) or final.st_size != len(expected)
                            or published.read(len(expected) + 1) != expected
                            or not names_inode(directory, filename, inode)):
                        raise OSError("Published receipt failed identity or byte verification")
            except BaseException:
                if names_inode(directory, filename, inode):
                    os.unlink(filename, dir_fd=directory)
                raise
        finally:
            if names_inode(directory, temp, inode):
                os.unlink(temp, dir_fd=directory)
    os.fsync(directory)


def run(label, mode, receipt_dir=None):
    if not pb.LABEL.fullmatch(label) or mode not in ACTIONS:
        raise ValueError("Invalid transition options")
    utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    nonce = secrets.token_hex(6)
    filename = f"{utc}-{nonce}-bt-{label}.json"
    dest = OUT if receipt_dir is None else Path(receipt_dir).absolute()
    if dest.parent != OUT.parent or not re.fullmatch(r"phaseb-probes(?:-[A-Za-z0-9_-]+)?", dest.name):
        raise ValueError("Use a phaseb-probes or phaseb-probes-<name> directory under work/stage7-persist")
    pb.validate_host_out_dir(dest / filename)
    with custody(dest) as directory:
        with receipt_output(directory, filename) as output:
            receipt = dict(mode="transition-probe", label=label, utc=utc, nonce=nonce, ram_marker_mode=mode,
                           capture_scope="boot_mount_process_and_marker", full_b5_complete=False,
                           commands=[], steps=[], terminal_toggles=[], terminal_disable_verified=False,
                           stock_side_effect_disclosure=DISCLOSURE, camera_staging="none",
                           project_write_destinations=[],
                           stock_flash_writes_observed=None,
                           service_stop_transport=base.make_stop_transport_record())
            try:
                with base.observe_stop_senser(receipt):
                    pb.probe.connect(receipt, diagnostic=lambda cam, rec: capture(cam, rec, directory),
                                     gate_factory=lambda dev: pb.PhaseBCollectGate(dev, frozenset(), receipt=receipt))
            except (Exception, KeyboardInterrupt) as err:
                receipt.setdefault("error", f"{type(err).__name__}: {err}")
            if mode == "plant":
                receipt["marker_baseline_established"] = receipt.get("marker", {}).get("status") == "planted"
            stop = receipt["service_stop_transport"]
            data_ok = bool(receipt.get("capture_complete") and receipt["terminal_disable_verified"] and "error" not in receipt)
            status = receipt.get("marker", {}).get("status")
            if mode == "check-and-remove":
                receipt["marker_cleanup_verified"] = status in ("absent", "removed")
                data_ok = data_ok and receipt["marker_cleanup_verified"]
            if status == "incomplete":
                data_ok = False
            stop_ok = bool(stop["observed"] and stop["attempted"] and stop["transport_ok"] and not stop["error"]
                           and receipt.get("service_stop_requested") and "service_stop_error" not in receipt)
            ok = data_ok and stop_ok and receipt.get("marker_baseline_established", True)
            receipt.update(telemetry_capture_ok=bool(receipt.get("telemetry_complete") and receipt["terminal_disable_verified"]),
                           data_capture_ok=data_ok, service_stop_transport_ok=stop_ok, bt_probe_ok=ok)
            json.dump(receipt, output, indent=2, allow_nan=False)
            output.write("\n")
    if RECOVERY in receipt.get("error", ""):
        print(RECOVERY, file=sys.stderr)
    print(f"RESULT={dest / filename}\nDATA_CAPTURE_OK={data_ok}\nSERVICE_STOP_TRANSPORT_OK={stop_ok}\nBT_PROBE_OK={ok}")
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--transition-probe", action="store_true")
    parser.add_argument("--receipt-dir", type=Path, help="Writable phaseb-probes-<name> sibling; reuse it across transitions")
    parser.add_argument("--label")
    parser.add_argument("--ram-marker", choices=ACTIONS)
    args = parser.parse_args(argv)
    if args.self_test:
        if args.label or args.ram_marker or args.receipt_dir:
            parser.error("Transition options require --transition-probe")
        import unittest
        suite = unittest.defaultTestLoader.discover(str(pb.PROTO), "test_stage7_phaseb_bt_probe.py")
        if suite.countTestCases() == 0:
            raise RuntimeError("BT probe test suite is missing")
        return 0 if unittest.TextTestRunner().run(suite).wasSuccessful() else 1
    if not args.label or not pb.LABEL.fullmatch(args.label) or not args.ram_marker:
        parser.error("A valid label and marker action are required")
    try:
        return run(args.label, args.ram_marker, args.receipt_dir)
    except PermissionError as err:
        print(f"Receipt directory access failed: {err}. Select a writable --receipt-dir under {OUT.parent}.", file=sys.stderr)
        return 1
    except (ValueError, OSError) as err:
        print(f"Receipt failed: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
