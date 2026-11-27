"""Offline ARM execution, original ABI, seal, framing, real-gate USB backend, and telemetry checks."""
import base64
import contextlib
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import (
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R7,
    UC_ARM_REG_SP,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
)

import build_stage7_phaseb as build
import stage7_ram_runner as ram

sys.path.insert(0, str(build.ROOT / "scripts"))
import m7_probe as probe  # noqa: E402
import m7_stage7_collect as collect_base  # noqa: E402
import m7_stage7_phaseb_collect as host  # noqa: E402
import m7_terminal_repaint as terminal  # noqa: E402
from m7_terminal_steps import frame  # noqa: E402

PATHS = ("/setting", "/etc", "/system", "/tmp_network")
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)

M7_BUSYBOX_APPLETS = frozenset((
    "[", "[[", "ash", "basename", "bunzip2", "bzcat", "cat", "chgrp", "chmod", "chown",
    "chroot", "cmp", "cp", "cpio", "cut", "date", "dd", "dirname", "dmesg", "echo", "egrep",
    "env", "expr", "false", "fgrep", "freeramdisk", "ftpget", "ftpput", "fuser", "getty",
    "grep", "gunzip", "gzip", "halt", "ifconfig", "insmod", "kill", "killall", "klogd",
    "ln", "logger", "login", "ls", "lsmod", "md5sum", "mkdir", "mkfifo", "mknod", "mktemp",
    "modprobe", "mount", "mv", "pidof", "ping", "ping6", "pivot_root", "poweroff",
    "pwd", "readlink", "reboot", "rm", "rmdir", "rmmod", "route", "sed", "sfdisk", "sh",
    "sha1sum", "sleep", "sort", "stty", "swapoff", "swapon", "switch_root", "sync",
    "syslogd", "tail", "tar", "taskset", "test", "touch", "true", "umount", "uname",
    "uniq", "usleep", "vconfig", "wc", "xargs", "zcat",
))

STOCK_MOUNTS = (
    "rootfs / rootfs rw 0 0\n"
    "proc /proc proc rw,relatime 0 0\n"
    "/dev/nflasha7 / ext2 ro,relatime,errors=continue 0 0\n"
    "/dev/nflasha15 /usr ext2 ro,relatime,errors=continue 0 0\n"
    "/dev/nflasha10 /tmp vfat rw,sync,dirsync,noatime,posix_attr 0 0\n"
    "/dev/nflasha10 /etc vfat rw,sync,dirsync,noatime,posix_attr 0 0\n"
    "/dev/nflasha3 /system vfat rw,sync,dirsync,noatime,posix_attr 0 0\n"
    "/dev/nflasha2 /setting vfat rw,sync,dirsync,noatime,posix_attr 0 0\n"
    "none /tmp_network tmpfs rw,sync,dirsync,noatime,size=1024k 0 0\n"
)


def make_marker_obs(token="M7_PB_MARKER 0123456789ab 20261127T160000Z", inode=77, mtime="Jan  1 00:01"):
    content = token + "\n"
    raw = content.encode("ascii")
    return {
        "state": "REGULAR",
        "path": host.RAM_MARKER_PATH,
        "inode": inode,
        "bytes": len(raw),
        "mtime": mtime,
        "md5": hashlib.md5(raw).hexdigest(),
        "content": content,
    }


def make_ok_stop_transport():
    return {
        "attempted": True,
        "observed": True,
        "transport_ok": True,
        "camera_exit_confirmed": False,
        "driver_class": "FakeDriver",
        "error": None,
    }


def original_serializer(va, source, size):
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    base = 0x60108000
    page = va & ~4095
    data = build.KERNEL.read_bytes()
    uc.mem_map(page, 4096)
    uc.mem_write(page, data[page - base:page - base + 4096])
    source_addr, user_addr, stop = 0x10000, 0x11000, 0x12000
    uc.mem_map(source_addr, 0x10000)
    uc.mem_write(source_addr, source)
    uc.reg_write(UC_ARM_REG_SP, 0x1f000)
    uc.mem_write(0x1e008, struct.pack("<I", 0x20000))
    uc.reg_write(UC_ARM_REG_R0, source_addr)
    uc.reg_write(UC_ARM_REG_R1, user_addr)
    uc.reg_write(UC_ARM_REG_LR, stop)
    for addr in (0x6025c300, 0x6025a1c0):
        uc.mem_map(addr & ~4095, 4096)

    def kernel_helper(vm, addr, length, unused):
        dst, src, count = (vm.reg_read(r) for r in REGS)
        if addr == 0x6025c300:
            vm.mem_write(dst, bytes(src))
        else:
            if (dst, count) != (user_addr, size):
                raise AssertionError("Unexpected original copy_to_user arguments")
            vm.mem_write(dst, bytes(vm.mem_read(src, count)))
            vm.reg_write(UC_ARM_REG_R0, 0)
        vm.reg_write(UC_ARM_REG_PC, vm.reg_read(UC_ARM_REG_LR))

    for addr in (0x6025c300, 0x6025a1c0):
        uc.hook_add(UC_HOOK_CODE, kernel_helper, begin=addr, end=addr)
    uc.emu_start(va, stop, count=300)
    if uc.reg_read(UC_ARM_REG_PC) != stop or uc.reg_read(UC_ARM_REG_R0):
        raise AssertionError("Original M7 ABI serializer failed")
    return bytes(uc.mem_read(user_addr, size))


def run_inspector(stat, fs, errors=None, write_limit=384, interrupt_once=False):
    errors = errors or {}
    binary = (build.OUT / build.BINARY).read_bytes()
    elf = ELFFile(io.BytesIO(binary))
    seg, = elf.iter_segments()
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(0x10000, 8192, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(seg["p_vaddr"], seg.data())
    uc.mem_map(0x30000, 0x10000)
    uc.reg_write(UC_ARM_REG_SP, 0x3ffe0)
    uc.mem_write(0x3ffe0, struct.pack("<III", 1, 0x31000, 0))
    uc.mem_write(0x31000, b"/arbitrary-input\0")
    calls, output, exits = [], bytearray(), []

    def syscall(vm, trap, unused):
        nonlocal interrupt_once
        if trap != 2:
            raise AssertionError(trap)
        nr = vm.reg_read(UC_ARM_REG_R7)
        a, b, c = (vm.reg_read(r) for r in REGS)
        if nr in (196, 266):
            path = bytes(vm.mem_read(a, 32)).split(b"\0")[0].decode("ascii")
            calls.append((nr, path))
            rc = errors.get((nr, path), 0)
            if nr == 266 and b != 84:
                raise AssertionError(f"statfs64 size {b}")
            if rc == 0:
                vm.mem_write(b if nr == 196 else c, stat if nr == 196 else fs)
        elif nr == 4:
            if a != 1 or c == 0 or c > 384:
                raise AssertionError(f"Unbounded or non-stdout write {(a, c)}")
            rc = min(c, write_limit)
            if interrupt_once:
                rc, interrupt_once = -4, False
            elif rc > 0:
                output.extend(vm.mem_read(b, rc))
        elif nr == 248:
            exits.append(a)
            vm.emu_stop()
            return
        else:
            raise AssertionError(f"Unapproved syscall {nr}")
        vm.reg_write(UC_ARM_REG_R0, rc & 0xffffffff)

    uc.hook_add(UC_HOOK_INTR, syscall)
    uc.emu_start(elf["e_entry"], 0, count=5_000_000)
    if len(exits) != 1:
        raise AssertionError("Inspector failed to exit")
    return calls, output.decode("ascii").splitlines(), exits[0]


class InMemoryCameraDevice:
    """Real USB-framed terminal + FileControl backend driving PhaseBCollectGate & PhaseBTerminalSession."""

    def __init__(self, handler, file_payloads=None, fail_stop=False, fail_final_disable=False):
        self.handler = handler
        self.file_payloads = file_payloads or {}
        self.fail_stop = fail_stop
        self.fail_final_disable = fail_final_disable
        self.disable_count = 0
        self.rx = bytearray()
        self.tx_buf = bytearray()
        self.commands_received = []
        self.pulls = []
        self.driver = self._make_driver()

    def _make_driver(self):
        parent = self
        sys.path.insert(0, str(probe.PMCA))
        from pmca.usb.driver.generic import GenericUsbException

        class BackendDev:
            def write(self, ep, chunk):
                parent.tx_buf.extend(chunk)
                if parent.tx_buf.endswith(b"\n"):
                    raw_line = bytes(parent.tx_buf)
                    parent.tx_buf.clear()
                    parent._handle_wire(raw_line)
                return len(chunk)

        class Driver:
            epOut = [0x02, 0x04]
            backend = types.SimpleNamespace(dev=BackendDev())

            def reset(self):
                pass

            def vendorRequestOut(self, *args, **kwargs):
                if parent.fail_stop:
                    raise GenericUsbException()

        return Driver()

    def _handle_wire(self, wire: bytes):
        # Parse echo __M7_B_<nonce>_<idx>__; <cmd>; m7_rc_<idx>=$?; echo; echo __M7_E_<nonce>_<idx>_${m7_rc_<idx>}__\n
        m = re.match(rb"^echo (__M7_B_[0-9a-f]{12}_[0-9]+__); (.*); m7_rc_[0-9]+=\$\?; echo; echo (__M7_E_[0-9a-f]{12}_[0-9]+_)", wire)
        assert m, f"Unexpected wire frame: {wire!r}"
        begin, cmd_bytes, end = m[1], m[2], m[3]
        cmd = cmd_bytes.decode("ascii")
        self.commands_received.append(cmd)
        result = self.handler(cmd)
        if result is None:
            # Simulate dropped ACK / timeout (write echo only, no END marker or prompt).
            self.rx.extend(wire.replace(b"\n", b"\r\n"))
            return
        body, status = result
        if isinstance(body, str):
            body = body.encode("ascii")
        # Simulate real usbgcon-1 ONLCR (\n -> \r\n) on body and framing.
        body_wire = body.replace(b"\n", b"\r\n")
        self.rx.extend(wire.replace(b"\n", b"\r\n"))
        self.rx.extend(begin + b"\r\n")
        self.rx.extend(body_wire + b"\r\n")
        self.rx.extend(end + str(status).encode("ascii") + b"__\r\n")
        self.rx.extend(terminal.SHELL_PROMPT)

    def sendSenserPacket(self, function, payload, output=None):
        sys.path.insert(0, str(probe.PMCA))
        from pmca.usb.driver.generic import GenericUsbException

        if (function, payload) == collect_base.TERM_DISABLE_P2:
            self.disable_count += 1
            if self.fail_final_disable and self.disable_count == 2:
                raise GenericUsbException()
        if (function, payload) == collect_base.TERM_ENABLE_P2:
            self.rx.extend(b"BusyBox v1.13.4\r\n" + terminal.SHELL_PROMPT)
        if function == 0xFF01:
            path = payload[4:].rstrip(b"\x00").decode("ascii")
            self.pulls.append(path)
            blob = self.file_payloads[path]
            if callable(blob):
                blob(output)
            elif output is not None:
                output.write(blob)
            return 1, b""
        return (0 if function == 0x40 else 1), b""

    def readTerminal(self):
        if not self.rx:
            return b""
        chunk = bytes(self.rx[:64])
        del self.rx[:64]
        return chunk


class InspectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kstat = bytearray(104)
        struct.pack_into("<IH", kstat, 8, (0xabc << 20) | 0xdef12, 0o40751)
        cls.stat = original_serializer(0x601c2d88, bytes(kstat), 104)
        kfs = bytearray(88)
        struct.pack_into("<IIQQQ", kfs, 0, 0x4d44, 16384, 2**32 + 123, 2**32 - 11, 7)
        struct.pack_into("<I", kfs, 60, 4096)
        cls.fs = original_serializer(0x601e4e44, bytes(kfs), 84)

    def test_original_kernel_structs_and_arm_output(self):
        calls, lines, rc = run_inspector(self.stat, self.fs, write_limit=9, interrupt_once=True)
        self.assertEqual(rc, 0)
        self.assertEqual(calls, [(nr, p) for p in PATHS for nr in (196, 266)])
        self.assertEqual(
            lines,
            [
                f"STATFS path={p} lstat_rc=0 dev=2748:913170 mode=40751 statfs_rc=0 type=0x4d44"
                f" bsize=16384 frsize=4096 blocks={2**32+123} bfree={2**32-11} bavail=7"
                f" free_bytes={(2**32-11)*16384} total_bytes={(2**32+123)*16384}"
                for p in PATHS
            ],
        )

    def test_errors_never_consume_stale_structs(self):
        calls, lines, rc = run_inspector(self.stat, self.fs, {(196, "/etc"): -2, (266, "/system"): -5})
        self.assertEqual(rc, 1)
        self.assertNotIn((266, "/etc"), calls)
        self.assertIn("lstat_rc=-2 dev=0:0 mode=0 statfs_rc=-125", lines[1])
        self.assertIn("statfs_rc=-5 type=0x0 bsize=0", lines[2])
        self.assertTrue(lines[2].endswith("free_bytes=0 total_bytes=0"))
        st = bytearray(self.stat)
        struct.pack_into("<I", st, 16, 0o120777)
        calls, _, rc = run_inspector(bytes(st), self.fs)
        self.assertEqual((calls, rc), ([(196, p) for p in PATHS], 1))

    def test_unsigned_boundary_overflow_and_stdout_failure(self):
        fs = bytearray(self.fs)
        struct.pack_into("<IQQ", fs, 4, 1, 2**64 - 1, 2**64 - 1)
        self.assertTrue(
            run_inspector(self.stat, bytes(fs))[1][0].endswith(
                "free_bytes=18446744073709551615 total_bytes=18446744073709551615"
            )
        )
        struct.pack_into("<I", fs, 4, 2)
        self.assertEqual(run_inspector(self.stat, bytes(fs))[1:], ([], 2))
        self.assertEqual(run_inspector(self.stat, self.fs, write_limit=0)[2], 3)

    def test_seal_and_syscall_tampering(self):
        build.verify_seal()
        binary = (build.OUT / build.BINARY).read_bytes()
        old, new = (struct.pack("<II", 0xe3007000 | n, 0xef000000) for n in (196, 26))
        self.assertEqual(binary.count(old), 1)
        with self.assertRaises(ValueError):
            build.inspect(binary.replace(old, new))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / build.BINARY).write_bytes(binary)
            (path / build.MANIFEST).write_text("{}\n")
            with self.assertRaises(ValueError):
                build.verify_seal(path)


def m7_stat_line(pid: int, comm: str, ticks: int, minor: int = 0, child: int = 0, ppid: int = 1) -> bytes:
    """Emit an exact 41-field numeric tail matching original M7 do_task_stat (VA 0x6045d4f7)."""
    fields = [0] * 41
    fields[0] = ppid
    fields[6] = minor
    fields[12] = child
    fields[14] = 20
    fields[16] = 1
    fields[17] = 0  # literal 0 in M7 do_task_stat
    fields[18] = ticks
    return f"{pid} ({comm}) S ".encode("latin-1") + " ".join(map(str, fields)).encode("ascii")


def process(pid, ticks, minor=0, child=0, exe="/sbin/init", cmdline="init\x00"):
    exe_raw = exe.encode("utf-8")
    cmd_raw = cmdline.encode("utf-8")
    return {
        "pid": pid,
        "stat": m7_stat_line(pid, "a ) process", ticks, minor=minor, child=child).decode("latin-1"),
        "exe": exe,
        "exe_b64": base64.b64encode(exe_raw).decode("ascii"),
        "cmdline": cmdline,
        "cmdline_b64": base64.b64encode(cmd_raw).decode("ascii"),
        "cmdline_bytes": len(cmd_raw),
    }


def snapshot():
    log = "stock line\n" * 2500 + "[LIRO]: liro resume (WBI)\n[LIRO]: entry_resume:635c6078(1)\n"
    raw = log.encode("utf-8")
    return {
        "mode": "transition-probe",
        "model": host.MODEL,
        "version_txt": host.BUILD,
        "label": "before",
        "transition_probe_ok": True,
        "ram_marker_mode": "plant",
        "ancestors_verified": True,
        "mounts_verified": True,
        "terminal_disable_requested": True,
        "terminal_disable_verified": True,
        "service_stop_requested": True,
        "service_stop_error": None,
        "service_stop_transport": make_ok_stop_transport(),
        "start_utc": "1970-01-01T00:16:40Z",
        "end_utc": "1970-01-01T00:16:41Z",
        "wall_epoch_start": 1000,
        "wall_epoch_end": 1001,
        "uptime": "10.50 42.0",
        "boot_id": "28321e77-82dc-4178-9baa-9099c7f86bbf",
        "processes": [process(pid, pid, 20, 7) for pid in host.TRACKED],
        "raced_pids": [],
        "tmp_network": {"inode": 5, "mtime": "Jan  1 00:00"},
        "marker": {"mode": "plant", "before": {"state": "ABSENT"}, "after": make_marker_obs()},
        "dmesg": log,
        "dmesg_b64": base64.b64encode(raw).decode("ascii"),
        "dmesg_bytes": len(raw),
        "dmesg_lines": 2502,
        "dmesg_sha256": hashlib.sha256(raw).hexdigest(),
    }


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.a = snapshot()
        self.b = copy.deepcopy(self.a)
        b_log = "[LIRO]: entry_resume:635c6078(0)\n"
        b_raw = b_log.encode("utf-8")
        self.b.update(
            wall_epoch_start=2500,
            wall_epoch_end=2504,
            label="after",
            ram_marker_mode="check",
            start_utc="1970-01-01T00:41:40Z",
            end_utc="1970-01-01T00:41:44Z",
            uptime="510.25 500",
            boot_id="8c40811f-54fb-411e-a6a7-4dcb686b6466",
            dmesg=b_log,
            dmesg_b64=base64.b64encode(b_raw).decode("ascii"),
            dmesg_bytes=len(b_raw),
            dmesg_lines=1,
            dmesg_sha256=hashlib.sha256(b_raw).hexdigest(),
        )
        self.b["marker"] = {"mode": "check", "before": self.a["marker"]["after"], "after": self.a["marker"]["after"]}
        self.b["processes"][1] = process(154, 154, 19, 3)
        self.b["processes"].extend([
            process(190, 107, exe="", cmdline="name with\0args\0"),
            process(191, 108, exe="", cmdline=""),
        ])
        self.b["tmp_network"]["inode"] = 7

    def test_wbi_and_ordinary_receipts_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as out:
            paths = [Path(tmp) / name for name in ("a.json", "b.json")]
            for path, receipt in zip(paths, (self.a, self.b)):
                path.write_text(json.dumps(receipt))
            host.main(["--compare", *map(str, paths)])
        result = json.loads(out.getvalue())
        self.assertTrue(result["boot_id_changed"])
        self.assertEqual(result["uptime_delta_seconds"], 499.75)
        self.assertEqual(result["wall_delta_bounds_seconds"], [1499, 1504])
        self.assertEqual([events[-1]["kind"] for events in result["resume_events"]], ["WBI", "ordinary"])
        self.assertEqual(
            result["processes"]["154"]["observed_difference"],
            {"starttime": 0, "minflt": -1, "cutime": -4},
        )
        self.assertFalse(result["processes"]["154"]["same_boot_and_start_tick"])
        self.assertTrue(result["marker"]["same_contents_observed"])
        self.assertEqual(result["tmp_network_changes"], {"inode": True, "mtime": False})
        self.assertEqual([p["pid"] for p in result["new_userspace_observations"]], [190])

    def test_unsafe_marker_returns_indeterminate(self):
        self.b["ram_marker_mode"] = "check"
        self.b["marker"] = {"mode": "check", "before": {"state": "UNSAFE"}, "after": {"state": "UNSAFE"}}
        r = host.compare(self.a, self.b)
        self.assertIsNone(r["marker"]["same_contents_observed"])

    def test_rejects_failed_teardown_missing_tracked_bad_marker_and_reverse_time(self):
        bad_stop = dict(make_ok_stop_transport(), transport_ok=False, error="GenericUsbException")
        bad_marker = {"state": "REGULAR", "content": "arbitrary contents\n"}
        bad_md5_marker = dict(make_marker_obs(), md5="0" * 32)
        no_mtime_marker = {k: v for k, v in make_marker_obs().items() if k != "mtime"}
        bad_mtime_marker = dict(make_marker_obs(), mtime="invalid")
        incomplete_marker = {"state": "REGULAR", "content": make_marker_obs()["content"]}
        missing_161 = [p for p in self.b["processes"] if p["pid"] != 161]
        short_19_stat_procs = copy.deepcopy(self.b["processes"])
        short_19_stat_procs[0]["stat"] = "1 (init) S " + " ".join(["0"] * 19)
        overlong_cmd_procs = copy.deepcopy(self.b["processes"])
        big_argv = b"x" * 4097
        overlong_cmd_procs[0].update(
            cmdline=big_argv.decode("ascii"),
            cmdline_bytes=len(big_argv),
            cmdline_b64=base64.b64encode(big_argv).decode("ascii"),
        )
        text_only_procs = [
            {k: v for k, v in p.items() if k not in ("cmdline_b64", "exe_b64", "cmdline_bytes")}
            for p in self.b["processes"]
        ]
        for key, value in (
            ("model", "DSC-RX100M7A"),
            ("version_txt", "2.00"),
            ("wall_epoch_start", 0),
            ("transition_probe_ok", False),
            ("terminal_disable_requested", False),
            ("terminal_disable_verified", False),
            ("terminal_disable_error", "AdjustControl failed"),
            ("service_stop_requested", False),
            ("service_stop_error", "GenericUsbException"),
            ("service_stop_transport", bad_stop),
            ("processes", []),
            ("processes", missing_161),
            ("processes", short_19_stat_procs),
            ("processes", overlong_cmd_procs),
            ("processes", text_only_procs),
            ("raced_pids", [{"pid": 161, "reason": "cmdline_read_error:wc=1,cat=1", "starttime_before": 105}]),
            ("raced_pids", [{"pid": 190}]),
            ("raced_pids", [{"pid": 190, "reason": "exited_during_snapshot", "starttime_before": 107}]),
            ("raced_pids", [{"pid": 999, "reason": "unknown_reason", "starttime_before": 10}]),
            ("dmesg_bytes", 10),
            ("dmesg_lines", 0),
            ("dmesg_sha256", "0" * 64),
            ("marker", {"mode": "check", "before": bad_marker, "after": bad_marker}),
            ("marker", {"mode": "check", "before": bad_md5_marker, "after": bad_md5_marker}),
            ("marker", {"mode": "check", "before": no_mtime_marker, "after": no_mtime_marker}),
            ("marker", {"mode": "check", "before": bad_mtime_marker, "after": bad_mtime_marker}),
            ("marker", {"mode": "check", "before": dict(make_marker_obs(), mtime="Nov 27 :::::"), "after": dict(make_marker_obs(), mtime="Nov 27 :::::")}),
            ("marker", {"mode": "check", "before": dict(make_marker_obs(), mtime="Xyz  0 99:99"), "after": dict(make_marker_obs(), mtime="Xyz  0 99:99")}),
            ("marker", {"mode": "check", "before": dict(make_marker_obs(), mtime="Jan\t1\t00000"), "after": dict(make_marker_obs(), mtime="Jan\t1\t00000")}),
            ("marker", {"mode": "check", "before": dict(make_marker_obs(), mtime="Feb 30 12:00"), "after": dict(make_marker_obs(), mtime="Feb 30 12:00")}),
            ("marker", {"mode": "check", "before": dict(make_marker_obs(), mtime="Feb 29  2021"), "after": dict(make_marker_obs(), mtime="Feb 29  2021")}),
            ("marker", {"mode": "check", "before": dict(make_marker_obs(), mtime="Nov 27 24:00"), "after": dict(make_marker_obs(), mtime="Nov 27 24:00")}),
            ("tmp_network", {"inode": 7, "mtime": "Nov 27 :::::"}),
            ("marker", {"mode": "check", "before": incomplete_marker, "after": incomplete_marker}),
            ("marker", {"mode": "clear", "before": make_marker_obs(), "after": {"state": "ABSENT"}}),
            ("marker", {"mode": "bogus", "before": {"state": "ABSENT"}, "after": {"state": "ABSENT"}}),
            ("marker", {"mode": "check", "before": make_marker_obs(), "after": {"state": "ABSENT"}}),
        ):
            with self.subTest(key=key, value=repr(value)[:60]), self.assertRaises(ValueError):
                host.compare(self.a, dict(self.b, **{key: value}))
        with self.assertRaisesRegex(ValueError, "reverse order"):
            host.compare(self.b, self.a)


class CollectorSafetyAndRealGateTests(unittest.TestCase):
    def test_consent_out_dir_and_inspector_guards_refuse_before_usb(self):
        bad_cases = (
            (["--extract-boot"], host.EXTRACT_CONSENT),
            (["--extract-boot", "--confirm-phaseb-boot-extract"], "obsolete"),
            (["--extract-boot", "--confirm-phaseb-boot-extract-etools"], "unrecognized"),
            (["--extract-boot", host.EXTRACT_CONSENT, "--out-dir", "evidence/nope"], "protected destination"),
            (["--extract-boot", host.EXTRACT_CONSENT, "--out-dir", "EVIDENCE/nope"], "protected destination"),
            (["--extract-boot", host.EXTRACT_CONSENT, "--out-dir", "SOURCES/nope"], "protected destination"),
            (["--transition-probe"], "valid --label"),
            (["--transition-probe", "--label", "../a", host.TRANSITION_CONSENT], "valid --label"),
            (["--transition-probe", "--label", "ok"], host.TRANSITION_CONSENT),
            (["--transition-probe", "--label", "ok", "--ram-marker", "plant"], host.TRANSITION_CONSENT),
            (["--transition-probe", "--label", "ok", "--ram-marker", "clear", host.TRANSITION_CONSENT], "invalid choice"),
            (["--compare", "a", "b", "--label", "ok"], "apply only to --transition-probe"),
            (["--compare", "a", "b", host.EXTRACT_CONSENT], "apply only to --extract-boot"),
            (["--compare", "a", "b", host.TRANSITION_CONSENT], "applies only to --transition-probe"),
        )
        for argv, needle in bad_cases:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()) as err:
                with patch.object(probe, "connect", side_effect=AssertionError("unexpected USB")):
                    with self.assertRaises(SystemExit) as raised:
                        host.main(argv)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn(needle, err.getvalue())

        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            (tdir / host.INSPECTOR_FILENAME).write_bytes(b"corrupt")
            (tdir / "build-phaseb.json").write_text("{}\n", encoding="utf-8")
            with patch.object(host, "INSPECTOR_DIR", tdir), \
                    patch.object(probe, "connect", side_effect=AssertionError("unexpected USB")), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit) as raised:
                    host.main(["--extract-boot", host.EXTRACT_CONSENT])
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("Extraction prerequisite failed", err.getvalue())

    def test_shell_commands_busybox_applets_syntax_and_strict_wire_budget(self):
        nonce = "0123456789ab"
        stage = f"/tmp_network/.m7-pb-{nonce}"
        inspector = host.verify_local_inspector()
        gz = gzip.compress(inspector["data"], compresslevel=9, mtime=0)
        upload_cmds = [
            ram.upload_chunk_command(chunk, f"{stage}/statfs.elf.gz", encoded=False, first=(i == 0))
            for i, chunk in enumerate(
                ram.plan_upload_chunks(gz, f"{stage}/statfs.elf.gz", encoded=False, base_cmd_idx=99, nonce=nonce)
            )
        ]
        checksum_cmds = [c for _, c, _ in collect_base.build_checksum_commands(host.EXTRACT_PATHS, nonce, start_index=50)]
        templates = [
            host.SETUP_CMD,
            host.MOUNTS_CMD,
            host.EXTRACT_ANCESTOR_CHECK_CMD,
            host.TRANSITION_ANCESTOR_CHECK_CMD,
            host.VERSION_CMD,
            host.BOOT_ID_CMD,
            host.UPTIME_CMD,
            host.DATE_CMD,
            host.CMDLINE_CMD,
            host.UPM_BOOTMODE_CMD,
            host.HOTPLUG_CMD,
            host.DMESG_CMD,
            host.EXTRACT_LS_CMD,
            host.TRANSITION_LS_TMP_CMD,
            host.TRANSITION_LS_FLASH_CMD,
            host.PROC_SNAPSHOT_CMD,
            host.MARKER_STATE_CMD,
            host.MARKER_META_CMD,
            host.MARKER_READ_CMD,
            host._make_marker_plant_cmd(f"M7_PB_MARKER {nonce} 20261127T160000Z"),
            f"[ -d /tmp_network ]&&[ ! -L /tmp_network ]&&[ ! -e {stage} ]&&[ ! -L {stage} ]&&echo CLEAN||echo DIRTY",
            f"/bin/busybox mkdir {stage}",
            f"[ -d {stage} ]&&[ ! -L {stage} ]&&[ ! -e {stage}/statfs.elf.gz ]&&[ ! -L {stage}/statfs.elf.gz ]&&/bin/busybox ls -ldi {stage}",
            f"/bin/busybox wc -c {stage}/statfs.elf.gz",
            f"/bin/busybox md5sum {stage}/statfs.elf.gz",
            f"/bin/busybox gunzip {stage}/statfs.elf.gz",
            f"/bin/busybox chmod 700 {stage}/statfs.elf",
            f"{stage}/statfs.elf > {stage}/statfs.out",
            f"[ -f {stage}/statfs.out ]&&[ ! -L {stage}/statfs.out ]&&/bin/busybox cat {stage}/statfs.out",
            host._make_statfs_cleanup_cmd(stage, 1234567890),
            f"[ ! -e {stage} ]&&[ ! -L {stage} ]&&echo GONE||echo DIRTY",
            *checksum_cmds,
            *upload_cmds,
        ]
        for idx, cmd in enumerate(templates):
            wire, _, _ = frame(cmd, 99, nonce)
            # Check strict < 512 bytes INCLUDING trailing LF transmitted by writeTerminal (wire[:-1]).
            self.assertLess(len(wire[:-1]), 512, f"template {idx} wire length >= 512: {cmd}")
            subprocess.run(["/bin/sh", "-n", "-c", cmd], check=True)
            for applet in re.findall(r"(?:/bin/busybox|\$b)\s+([A-Za-z0-9_.+\[\]-]+)", cmd):
                self.assertIn(applet, M7_BUSYBOX_APPLETS, f"Unverified BusyBox applet {applet!r} in {cmd}")
            for banned in ("printf", "sha256sum", "timeout", "awk", "base64", "tr", "df", "head", "od"):
                self.assertNotRegex(cmd, rf"(?<![A-Za-z0-9_./-]){banned}(?![A-Za-z0-9_./-])")

    def test_real_gate_upload_error_cleans_stage_and_lost_mkdir_ack_reports_unverified(self):
        """Blocking Finding #1 + r2 regressions through REAL PhaseBCollectGate & PhaseBTerminalSession."""
        sys.path.insert(0, str(probe.PMCA))
        from pmca.usb.sony import SonySenserCamera

        inspector = host.verify_local_inspector()

        # Case A: first gzip write cleanly returns shell exit 1 -> gate is NOT poisoned -> inode-checked rm/rmdir runs & verifies GONE.
        state_a = {"dir_exists": False, "inode": 101, "rm_seen": False}

        def handler_a(cmd):
            if "echo CLEAN||echo DIRTY" in cmd:
                return ("DIRTY\n" if state_a["dir_exists"] else "CLEAN\n"), 0
            if cmd.startswith("/bin/busybox mkdir "):
                state_a["dir_exists"] = True
                return "", 0
            if "/bin/busybox ls -ldi " in cmd:
                d = cmd.split()[-1]
                return f"    {state_a['inode']} drwx------ 2 0 0 40 May  6  2021 {d}\n", 0
            if "statfs.elf.gz" in cmd and "echo -ne" in cmd:
                return "", 1  # Cleanly acknowledged shell failure
            if "rmdir " in cmd and "rm -f " in cmd:
                exp_ino = int(re.search(r'\$1" = "([0-9]+)"', cmd)[1])
                if not state_a["dir_exists"] or state_a["inode"] != exp_ino:
                    return "", 1
                state_a["rm_seen"] = True
                state_a["dir_exists"] = False
                return "", 0
            if "echo GONE||echo DIRTY" in cmd:
                return ("DIRTY\n" if state_a["dir_exists"] else "GONE\n"), 0
            raise AssertionError(f"Unexpected cmd: {cmd}")

        dev_a = InMemoryCameraDevice(handler_a)
        rec_a = {"nonce": "abcdef012345", "commands": [], "steps": []}
        gate_a = host.PhaseBCollectGate(dev_a, host.PHASEB_ALLOWED_FILE_READ_PAYLOADS, receipt=rec_a)
        sess_a = host.PhaseBTerminalSession(SonySenserCamera(gate_a), rec_a)
        with patch.object(time, "sleep", lambda _: None):
            with self.assertRaises(host.CameraExitError):
                host._upload_and_run_statfs(sess_a, inspector, rec_a)
        self.assertFalse(gate_a.poisoned)
        self.assertTrue(state_a["rm_seen"])
        self.assertFalse(state_a["dir_exists"])
        self.assertEqual(rec_a["statfs_stage_inode"], 101)
        self.assertEqual(rec_a["statfs_cleanup"], "GONE")

        # Case B: mkdir executes on camera and ACK is lost -> gate IS poisoned -> no further frames sent, explicit status.
        state_b = {"dir_exists": False, "rm_seen": False}

        def handler_b(cmd):
            if "echo CLEAN||echo DIRTY" in cmd:
                return "CLEAN\n", 0
            if cmd.startswith("/bin/busybox mkdir "):
                state_b["dir_exists"] = True
                return None  # Lost ACK!
            if "rmdir " in cmd or "rm " in cmd:
                state_b["rm_seen"] = True
                return "", 0
            raise AssertionError(f"Unexpected cmd after poison: {cmd}")

        dev_b = InMemoryCameraDevice(handler_b)
        rec_b = {"nonce": "abcdef012345", "commands": [], "steps": []}
        gate_b = host.PhaseBCollectGate(dev_b, host.PHASEB_ALLOWED_FILE_READ_PAYLOADS, receipt=rec_b)
        sess_b = host.PhaseBTerminalSession(SonySenserCamera(gate_b), rec_b)
        clock_b = {"t": 0.0}

        def fake_mono_b():
            clock_b["t"] += 7.0 if state_b["dir_exists"] else 0.01
            return clock_b["t"]

        with patch.object(time, "sleep", lambda _: None), \
                patch.object(time, "monotonic", side_effect=fake_mono_b):
            with self.assertRaisesRegex(probe.ProbeError, "deadline exceeded"):
                host._upload_and_run_statfs(sess_b, inspector, rec_b)
        self.assertTrue(state_b["dir_exists"])
        self.assertTrue(gate_b.poisoned)
        self.assertFalse(state_b["rm_seen"])
        self.assertEqual(rec_b["statfs_cleanup"], "POISONED_SESSION_UNVERIFIED")
        self.assertIn("fresh diagnostic session", rec_b["statfs_cleanup_recovery_hint"])

        # Case C (Sol r2 regression): CLEAN -> another creator wins -> mkdir cleanly exits 1 (EEXIST).
        # Collector MUST NOT delete the unowned directory and MUST record NOT_CREATED!
        state_c = {"rm_seen": False}

        def handler_c(cmd):
            if "echo CLEAN||echo DIRTY" in cmd:
                return "CLEAN\n", 0
            if cmd.startswith("/bin/busybox mkdir "):
                return "mkdir: can't create directory: File exists\n", 1
            if "rmdir " in cmd or "rm " in cmd:
                state_c["rm_seen"] = True
                return "", 0
            raise AssertionError(f"Unexpected cleanup against unowned dir: {cmd}")

        dev_c = InMemoryCameraDevice(handler_c)
        rec_c = {"nonce": "abcdef012345", "commands": [], "steps": []}
        gate_c = host.PhaseBCollectGate(dev_c, host.PHASEB_ALLOWED_FILE_READ_PAYLOADS, receipt=rec_c)
        sess_c = host.PhaseBTerminalSession(SonySenserCamera(gate_c), rec_c)
        with patch.object(time, "sleep", lambda _: None):
            with self.assertRaises(host.CameraExitError):
                host._upload_and_run_statfs(sess_c, inspector, rec_c)
        self.assertFalse(gate_c.poisoned)
        self.assertFalse(state_c["rm_seen"])
        self.assertEqual(rec_c["statfs_cleanup"], "NOT_CREATED")

        # Case D (Sol r2 regression): mkdir + inode locked -> upload fails -> statfs_rm ACK lost ->
        # gate poisoned -> ZERO statfs_gone sent -> POISONED_SESSION_UNVERIFIED + hint!
        state_d = {"rm_started": False, "gone_seen": False}

        def handler_d(cmd):
            if "echo CLEAN||echo DIRTY" in cmd:
                return "CLEAN\n", 0
            if cmd.startswith("/bin/busybox mkdir "):
                return "", 0
            if "/bin/busybox ls -ldi " in cmd:
                d = cmd.split()[-1]
                return f"    101 drwx------ 2 0 0 40 May  6  2021 {d}\n", 0
            if "statfs.elf.gz" in cmd and "echo -ne" in cmd:
                return "", 1
            if "rmdir " in cmd and "rm -f " in cmd:
                state_d["rm_started"] = True
                return None  # Lost cleanup ACK!
            if "echo GONE||echo DIRTY" in cmd:
                state_d["gone_seen"] = True
                return "GONE\n", 0
            raise AssertionError(f"Unexpected cmd: {cmd}")

        dev_d = InMemoryCameraDevice(handler_d)
        rec_d = {"nonce": "abcdef012345", "commands": [], "steps": []}
        gate_d = host.PhaseBCollectGate(dev_d, host.PHASEB_ALLOWED_FILE_READ_PAYLOADS, receipt=rec_d)
        sess_d = host.PhaseBTerminalSession(SonySenserCamera(gate_d), rec_d)
        clock_d = {"t": 0.0}

        def fake_mono_d():
            clock_d["t"] += 7.0 if state_d["rm_started"] else 0.01
            return clock_d["t"]

        with patch.object(time, "sleep", lambda _: None), \
                patch.object(time, "monotonic", side_effect=fake_mono_d):
            with self.assertRaises(host.CameraExitError):
                host._upload_and_run_statfs(sess_d, inspector, rec_d)
        self.assertTrue(state_d["rm_started"])
        self.assertTrue(gate_d.poisoned)
        self.assertFalse(state_d["gone_seen"])
        self.assertEqual(rec_d["statfs_cleanup"], "POISONED_SESSION_UNVERIFIED")
        self.assertIn("statfs_cleanup_error", rec_d)
        self.assertIn("fresh diagnostic session", rec_d["statfs_cleanup_recovery_hint"])

        # Case E (Sol r3 regression): staging directory replaced by a different inode before cleanup ->
        # cleanup refuses via inode guard, leaves replacement intact, NEVER reports GONE!
        state_e = {"dir_exists": False, "inode": 101, "gone_seen": False}

        def handler_e(cmd):
            if "echo CLEAN||echo DIRTY" in cmd:
                return "CLEAN\n", 0
            if cmd.startswith("/bin/busybox mkdir "):
                state_e["dir_exists"] = True
                return "", 0
            if "/bin/busybox ls -ldi " in cmd:
                d = cmd.split()[-1]
                return f"    {state_e['inode']} drwx------ 2 0 0 40 May  6  2021 {d}\n", 0
            if "statfs.elf.gz" in cmd and "echo -ne" in cmd:
                # Replacement directory appears with a different inode!
                state_e["inode"] = 202
                return "", 1
            if "rmdir " in cmd and "rm -f " in cmd:
                exp_ino = int(re.search(r'\$1" = "([0-9]+)"', cmd)[1])
                if state_e["inode"] != exp_ino:
                    return "", 1  # Inode guard blocks removal!
                state_e["dir_exists"] = False
                return "", 0
            if "echo GONE||echo DIRTY" in cmd:
                state_e["gone_seen"] = True
                return "GONE\n", 0
            raise AssertionError(f"Unexpected cmd: {cmd}")

        dev_e = InMemoryCameraDevice(handler_e)
        rec_e = {"nonce": "abcdef012345", "commands": [], "steps": []}
        gate_e = host.PhaseBCollectGate(dev_e, host.PHASEB_ALLOWED_FILE_READ_PAYLOADS, receipt=rec_e)
        sess_e = host.PhaseBTerminalSession(SonySenserCamera(gate_e), rec_e)
        with patch.object(time, "sleep", lambda _: None):
            with self.assertRaises(host.CameraExitError):
                host._upload_and_run_statfs(sess_e, inspector, rec_e)
        self.assertFalse(gate_e.poisoned)
        self.assertTrue(state_e["dir_exists"])
        self.assertFalse(state_e["gone_seen"])
        self.assertTrue(rec_e["statfs_cleanup"].startswith("ERROR: CameraExitError"))
        self.assertIn("fresh diagnostic session", rec_e["statfs_cleanup_recovery_hint"])

        # Case F: dir_check fails post-mkdir -> unverified inode, NOT deleted -> UNSAFE_STAGE_NOT_DELETED!
        state_f = {"rm_seen": False}

        def handler_f(cmd):
            if "echo CLEAN||echo DIRTY" in cmd:
                return "CLEAN\n", 0
            if cmd.startswith("/bin/busybox mkdir "):
                return "", 0
            if "/bin/busybox ls -ldi " in cmd:
                return "", 1
            if "rmdir " in cmd or "rm " in cmd:
                state_f["rm_seen"] = True
                return "", 0
            raise AssertionError(f"Unexpected cmd: {cmd}")

        dev_f = InMemoryCameraDevice(handler_f)
        rec_f = {"nonce": "abcdef012345", "commands": [], "steps": []}
        gate_f = host.PhaseBCollectGate(dev_f, host.PHASEB_ALLOWED_FILE_READ_PAYLOADS, receipt=rec_f)
        sess_f = host.PhaseBTerminalSession(SonySenserCamera(gate_f), rec_f)
        with patch.object(time, "sleep", lambda _: None):
            with self.assertRaises(host.CameraExitError):
                host._upload_and_run_statfs(sess_f, inspector, rec_f)
        self.assertFalse(state_f["rm_seen"])
        self.assertEqual(rec_f["statfs_cleanup"], "UNSAFE_STAGE_NOT_DELETED")

        # Case G (Sol r4 exact shell-hook regression): directory replaced AFTER ls -ldi . with a
        # different-inode directory containing a foreign statfs.out -> cwd-pinned rm only touches
        # our original inode, replacement dir and its foreign file stay 100% intact, exit != 0!
        import shlex
        with tempfile.TemporaryDirectory() as scratch:
            parent = Path(scratch).resolve()
            stage = "/tmp_network/.m7-pb-0123456789ab"
            d = parent / Path(stage).name
            d.mkdir()
            (d / "statfs.out").write_text("ours\n", encoding="ascii")
            held = shlex.quote(str(parent / "directory-held"))
            target = shlex.quote(str(d))
            hook = (
                'swapped=0; bb() { if [ "$1" != ls ] || [ "$swapped" != 0 ]; then command "$@"; return; fi; '
                f'swapped=1; out=$(command "$@") || return; command mv {target} {held}; '
                f'command mkdir {target}; echo foreign > {target}/statfs.out; echo "$out"; }}; '
            )
            cmd = host._make_statfs_cleanup_cmd(stage, d.stat().st_ino)
            local_cmd = hook + cmd.replace("/tmp_network", str(parent)).replace("/bin/busybox", "bb")
            res = subprocess.run(["/bin/sh", "-c", local_cmd], capture_output=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertTrue(d.is_dir())
            self.assertEqual((d / "statfs.out").read_text(encoding="ascii"), "foreign\n")
            self.assertFalse((parent / "directory-held" / "statfs.out").exists())

    def test_real_gate_binary_dmesg_proc_newlines_and_raced_pids(self):
        """Blocking Finding #3 + r2/r3/r4 regressions: binary dmesg, exact 41-field M7 stat, tracked read error."""
        sys.path.insert(0, str(probe.PMCA))
        from pmca.usb.sony import SonySenserCamera

        raw_dmesg = b"foo\xff\x00\n[LIRO]: liro resume (WBI)\n[LIRO]: entry_resume:635c6078(1)\n"
        cmd_with_nl = b"one\x00second\nline\x00\xff"
        s1 = m7_stat_line(1, "launch_shell", 0, minor=10, ppid=0)
        s154 = m7_stat_line(154, "bootin.elf", 99, minor=360, child=2)
        s160 = m7_stat_line(160, "ash", 103, minor=15, child=1)
        s161 = m7_stat_line(161, "im.elf", 105, minor=500, child=3)
        s222 = m7_stat_line(222, "help\ner", 900, minor=12, ppid=161)
        s333_a = m7_stat_line(333, "short", 901, minor=1)
        s333_b = m7_stat_line(333, "reused", 950, minor=1)
        s444 = m7_stat_line(444, "gone", 902, minor=1)
        s555 = m7_stat_line(555, "grew", 903, minor=1)

        def mk_row(pid, w, n, exe, sb, cmd_b, c, sa):
            return (
                f"R|/proc/{pid}|{w}|{n}|".encode("ascii") + exe + b"\n"
                + b"S|" + sb + b"\nC|\n" + cmd_b + b"\nT|" + str(c).encode("ascii") + b"|" + sa
                + f"\nE|/proc/{pid}\n".encode("ascii")
            )

        proc_wire = (
            mk_row(1, 0, 0, b"/usr/bin/launch_shell.elf", s1, b"", 0, s1)
            + mk_row(154, 0, 0, b"/usr/bin/bootin.elf", s154, b"", 0, s154)
            + mk_row(160, 0, 0, b"/bin/busybox", s160, b"", 0, s160)
            + mk_row(161, 0, 0, b"/usr/bin/im.elf", s161, b"", 0, s161)
            + mk_row(222, 0, len(cmd_with_nl), b"/bin/busybox", s222, cmd_with_nl, 0, s222)
            + mk_row(333, 0, 4, b"/bin/sh", s333_a, b"abcd", 0, s333_b)
            + mk_row(444, 0, 8, b"/bin/sh", s444, b"", 1, b"")
            + mk_row(555, 0, 0, b"/bin/sh", s555, b"grew\x00", 0, s555)
        )

        def handler(cmd):
            if cmd == host.DMESG_CMD:
                return raw_dmesg, 0
            if cmd == host.PROC_SNAPSHOT_CMD:
                return proc_wire, 0
            raise AssertionError(cmd)

        dev = InMemoryCameraDevice(handler)
        rec = {"nonce": "abcdef012345", "commands": [], "steps": []}
        gate = host.PhaseBCollectGate(dev, frozenset(), receipt=rec)
        sess = host.PhaseBTerminalSession(SonySenserCamera(gate), rec)
        with patch.object(time, "sleep", lambda _: None):
            got_dmesg, _ = sess.command_bytes("dmesg", host.DMESG_CMD)
            got_proc, _ = sess.command_bytes("proc", host.PROC_SNAPSHOT_CMD)

        self.assertEqual(got_dmesg, raw_dmesg)
        rows, raced = host.parse_proc_snapshot_bytes(got_proc)
        by_pid = {r["pid"]: r for r in rows}
        self.assertEqual(base64.b64decode(by_pid[222]["cmdline_b64"]), cmd_with_nl)
        self.assertEqual(by_pid[222]["cmdline_bytes"], len(cmd_with_nl))
        self.assertIn("help\ner", by_pid[222]["stat"])
        self.assertEqual(
            {r["pid"]: r["reason"] for r in raced},
            {
                333: "pid_reused:901->950",
                444: "cmdline_length_and_read_error:wc=0,cat=1",
                555: "cmdline_length_changed",
            },
        )

        # Sol r4 regression: 19-field stat row, negative unsigned field, or nonzero literal-0 field MUST fail closed!
        short_161 = b"161 (im.elf) S " + b" ".join([b"0"] * 19)
        bad_161_short = proc_wire.replace(s161, short_161)
        with self.assertRaisesRegex(probe.ProbeError, "Malformed numeric tail"):
            host.parse_proc_snapshot_bytes(bad_161_short)

        neg_unsigned = m7_stat_line(161, "im.elf", -1, minor=500)
        with self.assertRaisesRegex(probe.ProbeError, "Malformed numeric tail"):
            host.parse_proc_snapshot_bytes(proc_wire.replace(s161, neg_unsigned))

        # Sol r2 regression: failing cmdline open on tracked PID 161 (w=1, c=1, matching stat) MUST fail closed!
        bad_161_read = proc_wire.replace(
            mk_row(161, 0, 0, b"/usr/bin/im.elf", s161, b"", 0, s161),
            mk_row(161, 1, 0, b"/usr/bin/im.elf", s161, b"", 1, s161),
        )
        with self.assertRaisesRegex(probe.ProbeError, "Tracked PID raced"):
            host.parse_proc_snapshot_bytes(bad_161_read)

        # Sol r3 regression: extra console line inside tracked PID 161's T| or S| stat block MUST fail closed!
        extra_t_line = proc_wire.replace(
            b"T|0|" + s161 + b"\nE|/proc/161\n",
            b"T|0|" + s161 + b"\nfops_se_ioctl_receive: async console line\nE|/proc/161\n",
        )
        with self.assertRaises(probe.ProbeError):
            host.parse_proc_snapshot_bytes(extra_t_line)

        extra_s_line = proc_wire.replace(
            b"S|" + s161 + b"\nC|\n",
            b"S|" + s161 + b"\nfops_se_ioctl_receive: async console line\nC|\n",
        )
        with self.assertRaises(probe.ProbeError):
            host.parse_proc_snapshot_bytes(extra_s_line)

        extra_t_fake_stat = proc_wire.replace(
            b"T|0|" + s161 + b"\nE|/proc/161\n",
            b"T|0|" + s161 + b"\nspoofed) S " + b" ".join([b"0"] * 41) + b"\nE|/proc/161\n",
        )
        with self.assertRaisesRegex(probe.ProbeError, "Overlong comm"):
            host.parse_proc_snapshot_bytes(extra_t_fake_stat)

        extra_empty_t = proc_wire + mk_row(777, 0, 0, b"/bin/sh", s444.replace(b"444", b"777"), b"", 0, b"\nasync_console")
        with self.assertRaises(probe.ProbeError):
            host.parse_proc_snapshot_bytes(extra_empty_t)

        # Sol r2 regression: malformed resync trailer (T|not stat) on untracked PID MUST fail closed!
        bad_resync = proc_wire + b"R|/proc/666|0|9|/bin/sh\nS|" + s444.replace(b"444", b"666") + b"\nC|\nab\nT|not stat\nE|/proc/666\n"
        with self.assertRaisesRegex(probe.ProbeError, "Malformed T\\|"):
            host.parse_proc_snapshot_bytes(bad_resync)

        # Missing tracked PID 161 MUST fail closed!
        drop_161 = proc_wire.replace(mk_row(161, 0, 0, b"/usr/bin/im.elf", s161, b"", 0, s161), b"")
        with self.assertRaisesRegex(probe.ProbeError, "Tracked PID\\(s\\) missing"):
            host.parse_proc_snapshot_bytes(drop_161)

        # Real-shell execution test: run PROC_SNAPSHOT_CMD on a synthetic proc tree where 161/cmdline is absent!
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp).resolve()
            for pid, st, has_cmd in ((1, s1, True), (154, s154, True), (160, s160, True), (161, s161, False)):
                d = pdir / str(pid)
                d.mkdir()
                (d / "stat").write_bytes(st)
                if has_cmd:
                    (d / "cmdline").write_bytes(b"ok\x00")
            local_cmd = host.PROC_SNAPSHOT_CMD.replace("b=/bin/busybox;", "b=;").replace("/proc/[1-9]*", f"{pdir}/[1-9]*")
            res = subprocess.run(["/bin/sh", "-c", local_cmd], capture_output=True, check=True)
            self.assertEqual(res.stderr, b"")
            rewritten = res.stdout.replace(str(pdir).encode("ascii"), b"/proc")
            with self.assertRaisesRegex(probe.ProbeError, "Tracked PID raced"):
                host.parse_proc_snapshot_bytes(rewritten)

    def test_real_gate_marker_adversarial_rejection(self):
        """Blocking Finding #4 + r2 regressions: bounded 44B dd, zero read before size check, mutation check."""
        sys.path.insert(0, str(probe.PMCA))
        from pmca.usb.sony import SonySenserCamera

        valid = make_marker_obs()
        ls_ok = f" 77 -rw------- 1 0 0 43 May  6  2021 {host.RAM_MARKER_PATH}\n"
        ls_mutated = f" 78 -rw------- 1 0 0 43 May  6  2021 {host.RAM_MARKER_PATH}\n"
        arb_bytes = b"A" * 42 + b"\n"
        cases = (
            ("wrong_ls_path", [f" 77 -rw------- 1 0 0 43 May  6  2021 /tmp_network/other\n"], valid["content"].encode("ascii"), "ls_path_mismatch"),
            ("bad_mtime_colons", [f" 77 -rw------- 1 0 0 43 Nov 27 ::::: {host.RAM_MARKER_PATH}\n"], valid["content"].encode("ascii"), "unparseable_meta"),
            ("bad_mtime_month_hour", [f" 77 -rw------- 1 0 0 43 Xyz  0 99:99 {host.RAM_MARKER_PATH}\n"], valid["content"].encode("ascii"), "unparseable_meta"),
            ("bad_mtime_tabs", [f" 77 -rw------- 1 0 0 43 Jan\t1\t00000 {host.RAM_MARKER_PATH}\n"], valid["content"].encode("ascii"), "unparseable_meta"),
            ("oversized_before_read", [f" 77 -rw------- 1 0 0 999 May  6  2021 {host.RAM_MARKER_PATH}\n"], b"x" * 44, "unexpected_size"),
            ("grew_to_44b_during_dd", [ls_ok, ls_ok], b"x" * 44, "content_size_mismatch"),
            ("arbitrary_43b", [ls_ok, ls_ok], arb_bytes, "invalid_marker_token"),
            ("mutated_inode_after_read", [ls_ok, ls_mutated], valid["content"].encode("ascii"), "marker_mutated_during_read"),
        )
        for name, meta_seq, read_out, exp_reason in cases:
            with self.subTest(name=name):
                read_called = []
                meta_iter = iter(meta_seq)

                def handler(cmd):
                    if cmd == host.MARKER_STATE_CMD:
                        return "REGULAR\n", 0
                    if cmd == host.MARKER_META_CMD:
                        return next(meta_iter), 0
                    if cmd == host.MARKER_READ_CMD:
                        read_called.append(True)
                        return read_out, 0
                    raise AssertionError(cmd)

                dev = InMemoryCameraDevice(handler)
                rec = {"nonce": "abcdef012345", "commands": [], "steps": []}
                gate = host.PhaseBCollectGate(dev, frozenset(), receipt=rec)
                sess = host.PhaseBTerminalSession(SonySenserCamera(gate), rec)
                with patch.object(time, "sleep", lambda _: None):
                    obs = host._inspect_ram_marker(sess, "before")
                self.assertEqual(obs["state"], "UNSAFE")
                self.assertEqual(obs["reason"], exp_reason)
                if name == "oversized_before_read":
                    self.assertEqual(read_called, [])

    def test_real_wrapper_extract_boot_and_transition_stop_failure(self):
        """Blocking Finding #2 + full real-gate multi-batch E2E for BOTH production wrappers."""
        sys.path.insert(0, str(probe.PMCA))
        from pmca.usb.sony import SonySenserAuthDevice, SonySenserCamera

        inspector = host.verify_local_inspector()
        statfs_out = "\n".join(
            f"STATFS path={p} lstat_rc=0 dev=252:2 mode=40755 statfs_rc=0 type=0x4d44 "
            f"bsize=16384 frsize=16384 blocks=1280 bfree=800 bavail=800 "
            f"free_bytes=13107200 total_bytes=20971520"
            for p in PATHS
        ) + "\n"
        file_blobs = {
            p: (b"\x7fELF" if p in host.EXTRACT_ELF_PATHS else b"TEXT") + p.encode("ascii")
            for p in host.EXTRACT_PATHS
        }

        def make_extract_handler():
            state = {"dir": False, "inode": 101, "gz": bytearray(), "elf": b""}

            def handler(cmd):
                if cmd == host.SETUP_CMD:
                    return "", 0
                if cmd == host.MOUNTS_CMD:
                    return STOCK_MOUNTS, 0
                if cmd == host.EXTRACT_ANCESTOR_CHECK_CMD:
                    return "\n".join(f"ANC OK {p}" for p in list(host.EXTRACT_ANCESTOR_DIRS) + ["/tmp_network", "/version.txt"]) + "\n", 0
                if cmd == host.VERSION_CMD:
                    return host.BUILD, 0
                if cmd == host.BOOT_ID_CMD:
                    return "28321e77-82dc-4178-9baa-9099c7f86bbf\n", 0
                if cmd == host.UPTIME_CMD:
                    return "42.50 120.00\n", 0
                if cmd in (host.CMDLINE_CMD, host.UPM_BOOTMODE_CMD, host.HOTPLUG_CMD, host.EXTRACT_LS_CMD):
                    return "ok\n", 0
                if cmd == host.DMESG_CMD:
                    return b"boot\xffline\n[LIRO]: liro resume (WBI)\n", 0
                if "echo CLEAN||echo DIRTY" in cmd:
                    return ("DIRTY\n" if state["dir"] else "CLEAN\n"), 0
                if cmd.startswith("/bin/busybox mkdir "):
                    state["dir"] = True
                    return "", 0
                if "/bin/busybox ls -ldi " in cmd:
                    d = cmd.split()[-1]
                    return f"    {state['inode']} drwx------ 2 0 0 40 May  6  2021 {d}\n", 0
                if "statfs.elf.gz" in cmd and "echo -ne" in cmd:
                    # Reconstruct exact uploaded gzip bytes from mixed ASCII + \0ooo octal escapes!
                    m = re.search(r"echo -ne '([^']+)'\s+(>>|>)\s+", cmd)
                    assert m, f"Unparseable upload chunk: {cmd}"
                    enc = m[1]
                    chunk = bytearray()
                    pos = 0
                    while pos < len(enc):
                        if enc[pos:pos + 2] == "\\0" and pos + 5 <= len(enc):
                            chunk.append(int(enc[pos + 2:pos + 5], 8))
                            pos += 5
                        else:
                            chunk.append(ord(enc[pos]))
                            pos += 1
                    if m[2] == ">":
                        state["gz"] = bytearray(chunk)
                    else:
                        state["gz"].extend(chunk)
                    return "", 0
                if cmd.startswith("/bin/busybox wc -c ") and cmd.endswith(".gz"):
                    return f"{len(state['gz']):9d} {cmd.split()[-1]}\n", 0
                if cmd.startswith("/bin/busybox md5sum ") and cmd.endswith(".gz"):
                    return f"{hashlib.md5(bytes(state['gz'])).hexdigest()}  {cmd.split()[-1]}\n", 0
                if cmd.startswith("/bin/busybox gunzip "):
                    state["elf"] = gzip.decompress(bytes(state["gz"]))
                    return "", 0
                if cmd.startswith("/bin/busybox wc -c ") and cmd.endswith("statfs.elf"):
                    return f"{len(state['elf']):9d} {cmd.split()[-1]}\n", 0
                if cmd.startswith("/bin/busybox md5sum ") and cmd.endswith("statfs.elf"):
                    return f"{hashlib.md5(state['elf']).hexdigest()}  {cmd.split()[-1]}\n", 0
                if cmd.startswith("/bin/busybox chmod 700 "):
                    return "", 0
                if "statfs.elf >" in cmd:
                    return "", 0
                if "cat " in cmd and cmd.endswith("statfs.out"):
                    return statfs_out, 0
                if "rmdir " in cmd and "rm -f " in cmd:
                    exp_ino = int(re.search(r'\$1" = "([0-9]+)"', cmd)[1])
                    if not state["dir"] or state["inode"] != exp_ino:
                        return "", 1
                    state["dir"] = False
                    return "", 0
                if "echo GONE||echo DIRTY" in cmd:
                    return ("DIRTY\n" if state["dir"] else "GONE\n"), 0
                if cmd.startswith("rc=0; for p in "):
                    batch_paths = cmd.split("for p in ", 1)[1].split("; do", 1)[0].split()
                    out_lines = []
                    for p in batch_paths:
                        blob = file_blobs[p]
                        out_lines.append(f"ST REG {p}")
                        out_lines.append(f"SZ {len(blob):9d} {p}")
                        out_lines.append(f"MD {hashlib.md5(blob).hexdigest()}  {p}")
                    return "\n".join(out_lines) + "\n", 0
                raise AssertionError(f"Unhandled extract cmd: {cmd}")

            return handler

        def fake_connect_for(dev):
            def _connect(receipt, diagnostic, gate_factory):
                receipt["model"] = host.MODEL
                gate = gate_factory(dev)
                cam = SonySenserCamera(gate)
                try:
                    diagnostic(cam, receipt)
                finally:
                    probe.finish_service(SonySenserAuthDevice(dev.driver), receipt)

            return _connect

        with tempfile.TemporaryDirectory() as tmp:
            # Resolve physical path so default invocation passes even when macOS TMPDIR is under /var -> /private/var.
            tpath = Path(tmp).resolve()
            receipt_dir = tpath / "receipts"
            ext_dir = tpath / "extracted-ok"
            dev_ok = InMemoryCameraDevice(make_extract_handler(), file_payloads=file_blobs)
            with patch.object(host, "OUT_RECEIPT_DIR", receipt_dir), \
                    patch.object(probe, "connect", fake_connect_for(dev_ok)), \
                    patch.object(time, "sleep", lambda _: None), \
                    patch("builtins.print"):
                rc = host.run_extract_boot(out_dir=ext_dir)
            self.assertEqual(rc, 0)
            self.assertEqual(len(dev_ok.pulls), len(host.EXTRACT_PATHS))
            self.assertEqual((ext_dir / "dmesg.bin").read_bytes(), b"boot\xffline\n[LIRO]: liro resume (WBI)\n")

            # Extraction StopSenser transport failure -> returns 1, explicit error, extract_boot_ok=False.
            dev_ext_stop_fail = InMemoryCameraDevice(make_extract_handler(), file_payloads=file_blobs, fail_stop=True)
            with patch.object(host, "OUT_RECEIPT_DIR", receipt_dir), \
                    patch.object(probe, "connect", fake_connect_for(dev_ext_stop_fail)), \
                    patch.object(time, "sleep", lambda _: None), \
                    patch("builtins.print"):
                rc_ext_stop = host.run_extract_boot(out_dir=tpath / "extracted-stopfail")
            self.assertEqual(rc_ext_stop, 1)

            # Extraction final-disable failure -> returns 1, ZERO FileControl pulls!
            dev_ext_dis_fail = InMemoryCameraDevice(make_extract_handler(), file_payloads=file_blobs, fail_final_disable=True)
            with patch.object(host, "OUT_RECEIPT_DIR", receipt_dir), \
                    patch.object(probe, "connect", fake_connect_for(dev_ext_dis_fail)), \
                    patch.object(time, "sleep", lambda _: None), \
                    patch("builtins.print"):
                rc_ext_dis = host.run_extract_boot(out_dir=tpath / "extracted-disfail")
            self.assertEqual(rc_ext_dis, 1)
            self.assertEqual(dev_ext_dis_fail.pulls, [])

            # Transition probe with StopSenser failure -> returns 1, error saved, validate_receipt rejects!
            s1 = m7_stat_line(1, "launch_shell", 0, minor=10, ppid=0)
            s154 = m7_stat_line(154, "bootin.elf", 99, minor=360, child=2)
            s160 = m7_stat_line(160, "ash", 103, minor=15, child=1)
            s161 = m7_stat_line(161, "im.elf", 105, minor=500, child=3)
            proc_wire = (
                b"R|/proc/1|0|0|/usr/bin/launch_shell.elf\nS|" + s1 + b"\nC|\n\nT|0|" + s1 + b"\nE|/proc/1\n"
                + b"R|/proc/154|0|0|/usr/bin/bootin.elf\nS|" + s154 + b"\nC|\n\nT|0|" + s154 + b"\nE|/proc/154\n"
                + b"R|/proc/160|0|0|/bin/busybox\nS|" + s160 + b"\nC|\n\nT|0|" + s160 + b"\nE|/proc/160\n"
                + b"R|/proc/161|0|0|/usr/bin/im.elf\nS|" + s161 + b"\nC|\n\nT|0|" + s161 + b"\nE|/proc/161\n"
            )

            def trans_handler(cmd):
                if cmd == host.SETUP_CMD:
                    return "", 0
                if cmd == host.MOUNTS_CMD:
                    return STOCK_MOUNTS, 0
                if cmd == host.TRANSITION_ANCESTOR_CHECK_CMD:
                    return "ANC OK /tmp_network\nANC OK /version.txt\n", 0
                if cmd == host.VERSION_CMD:
                    return host.BUILD, 0
                if cmd == host.BOOT_ID_CMD:
                    return "28321e77-82dc-4178-9baa-9099c7f86bbf\n", 0
                if cmd == host.UPTIME_CMD:
                    return "50.00 100.00\n", 0
                if cmd in (host.DATE_CMD, host.CMDLINE_CMD, host.UPM_BOOTMODE_CMD, host.HOTPLUG_CMD):
                    return "ok\n", 0
                if cmd == host.TRANSITION_LS_TMP_CMD:
                    return "/tmp_network:\n      5 drwxrwxrwt 4 0 0 80 May  6  2021 .\n", 0
                if cmd == host.TRANSITION_LS_FLASH_CMD:
                    return "/setting:\n", 0
                if cmd == host.MARKER_STATE_CMD:
                    return "ABSENT\n", 0
                if cmd == host.PROC_SNAPSHOT_CMD:
                    return proc_wire, 0
                if cmd == host.DMESG_CMD:
                    return b"[LIRO]: entry_resume:635c6078(0)\n", 0
                raise AssertionError(f"Unhandled trans cmd: {cmd}")

            dev_stop_fail = InMemoryCameraDevice(trans_handler, fail_stop=True)
            with patch.object(host, "OUT_RECEIPT_DIR", receipt_dir), \
                    patch.object(probe, "connect", fake_connect_for(dev_stop_fail)), \
                    patch.object(time, "sleep", lambda _: None), \
                    patch("builtins.print"):
                rc_fail = host.run_transition_probe(label="stopfail", ram_marker="check")
            self.assertEqual(rc_fail, 1)
            saved = next(receipt_dir.glob("*-stopfail.json"))
            saved_doc = json.loads(saved.read_text(encoding="utf-8"))
            self.assertIn("error", saved_doc)
            self.assertFalse(saved_doc["transition_probe_ok"])
            with self.assertRaises(ValueError):
                host.validate_receipt(saved_doc)

            # Happy-path transition probe (plant -> read-only check; zero rm in transition-probe!) + compare roundtrip!
            marker_mem = {"state": "ABSENT", "content": None, "inode": 77}

            def marker_trans_handler(cmd):
                if cmd == host.MARKER_STATE_CMD:
                    return marker_mem["state"] + "\n", 0
                if cmd == host.MARKER_META_CMD:
                    c = marker_mem["content"]
                    return (
                        f"     {marker_mem['inode']} -rw-------    1 0        0              {len(c)} Jan  1 00:01 {host.RAM_MARKER_PATH}\n"
                    ), 0
                if cmd == host.MARKER_READ_CMD:
                    return marker_mem["content"].encode("ascii")[:44], 0
                if "echo PLANTED" in cmd:
                    tok = re.search(r"'(M7_PB_MARKER [^']+)'", cmd)[1]
                    marker_mem["state"] = "REGULAR"
                    marker_mem["content"] = tok + "\n"
                    return "PLANTED\n", 0
                return trans_handler(cmd)

            dev_p1 = InMemoryCameraDevice(marker_trans_handler)
            dev_p2 = InMemoryCameraDevice(marker_trans_handler)
            with patch.object(host, "OUT_RECEIPT_DIR", receipt_dir), \
                    patch.object(probe, "connect", fake_connect_for(dev_p1)), \
                    patch.object(host, "_utc_epoch_pair", side_effect=[("2026-11-27T16:00:00.000Z", 1795795200.0), ("2026-11-27T16:00:02.000Z", 1795795202.0)]), \
                    patch.object(time, "sleep", lambda _: None), \
                    patch("builtins.print"):
                self.assertEqual(host.run_transition_probe(label="p1", ram_marker="plant"), 0)
            with patch.object(host, "OUT_RECEIPT_DIR", receipt_dir), \
                    patch.object(probe, "connect", fake_connect_for(dev_p2)), \
                    patch.object(host, "_utc_epoch_pair", side_effect=[("2026-11-27T16:00:10.000Z", 1795795210.0), ("2026-11-27T16:00:12.000Z", 1795795212.0)]), \
                    patch.object(time, "sleep", lambda _: None), \
                    patch("builtins.print"):
                self.assertEqual(host.run_transition_probe(label="p2", ram_marker="check"), 0)

            p1_doc = json.loads(next(receipt_dir.glob("*-p1.json")).read_text(encoding="utf-8"))
            p2_doc = json.loads(next(receipt_dir.glob("*-p2.json")).read_text(encoding="utf-8"))
            diff = host.compare(p1_doc, p2_doc)
            self.assertTrue(diff["marker"]["same_contents_observed"])
            self.assertFalse(diff["boot_id_changed"])
            self.assertEqual(p2_doc["marker"]["after"]["state"], "REGULAR")


if __name__ == "__main__":
    unittest.main(verbosity=2)
