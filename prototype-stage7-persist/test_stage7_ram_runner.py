#!/usr/bin/env python3
"""Offline mock unit & protocol tests for Stage 7.2 volatile RAM-only runner (ZERO USB access)."""
from __future__ import annotations

import base64
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts"))

import build_stage7 as builder
import stage7_ram_runner as runner
import m7_probe as usb
import m7_burst_identity as identity
import m7_terminal_repaint as terminal
from m7_terminal_check import PACKETS


def make_minimal_jpeg(width=5472, height=3648) -> bytes:
    sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + sof0 + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x00\x11\x22\x33" + b"\xff\xd9"


class FakeCameraShell:
    """In-memory mock of M7 service terminal, RAM tmpfs, /proc, mlv2_guard.elf, and stage7_daemon.elf."""

    def __init__(
        self,
        *,
        nonce: str = "abcdef012345",
        im_pid: int = 123,
        im_starttime: int = 4567,
        im_present: bool = True,
        im_tracer_pid: int = 0,
        pidof_false_negative: bool = False,
        im_readlink_fail: bool = False,
        daemon_readlink_fail: bool = False,
        proc_scan_fail: bool = False,
        crlf_framing: bool = False,
        view_bytes: int = runner.VIEWUNIFIED2_BYTES,
        view_md5: str = runner.VIEWUNIFIED2_MD5,
        has_gunzip: bool = True,
        has_base64: bool = False,
        leftover_paths: tuple[str, ...] = (),
        initial_hooks: str = "stock",
        initial_rects: str = "stock",
        initial_shim: str = "zero",
        fail_upload_md5_path: str | None = None,
        fail_install_mode: str | None = None,
        fail_post_install_check: bool = False,
        fail_daemon_launch_rc: int | None = None,
        daemon_emit_bad_witness: bool = False,
        daemon_emit_wrong_im_st: bool = False,
        daemon_stop_with_fault: bool = False,
        daemon_refuse_stop: bool = False,
        fail_uninstall_busy: bool = False,
        drop_ack_on_guard_check: bool = False,
        drop_ack_on_guard_readback: bool = False,
        printk_on_guard_readback: bool = False,
        append_printk_on_pin_fail: bool = False,
        fail_rm_guard_out: bool = False,
        drop_ack_on_rm_mlv2: bool = False,
        drop_ack_on_rm_nonce_dir: bool = False,
        mutate_guard_on_sd_disabled: bool = False,
        mutate_after_pin_md5_path: str | None = None,
        pre_populate_files: dict[str, bytes] | None = None,
        pre_populate_dirs: set[str] | None = None,
        pre_populate_symlinks: set[str] | None = None,
        pre_populate_fifos: set[str] | None = None,
        live_daemon_pid: int | None = None,
        live_daemon_starttime: int = 9999,
        live_daemon_exe: str | None = None,
        live_ring_pids: list[int] | None = None,
        live_ring_exe: str | None = None,
    ):
        self.nonce = nonce
        self.im_pid = im_pid
        self.im_starttime = im_starttime
        self.im_present = im_present
        self.im_tracer_pid = im_tracer_pid
        self.pidof_false_negative = pidof_false_negative
        self.im_readlink_fail = im_readlink_fail
        self.daemon_readlink_fail = daemon_readlink_fail
        self.proc_scan_fail = proc_scan_fail
        self.crlf_framing = crlf_framing
        self.view_bytes = view_bytes
        self.view_md5 = view_md5
        self.has_gunzip = has_gunzip
        self.has_base64 = has_base64
        self.leftover_paths = set(leftover_paths)
        self.hooks = initial_hooks
        self.rects = initial_rects
        self.shim = initial_shim
        self.fail_upload_md5_path = fail_upload_md5_path
        self.fail_install_mode = fail_install_mode
        self.fail_post_install_check = fail_post_install_check
        self.fail_daemon_launch_rc = fail_daemon_launch_rc
        self.daemon_emit_bad_witness = daemon_emit_bad_witness
        self.daemon_emit_wrong_im_st = daemon_emit_wrong_im_st
        self.daemon_stop_with_fault = daemon_stop_with_fault
        self.daemon_refuse_stop = daemon_refuse_stop
        self.fail_uninstall_busy = fail_uninstall_busy
        self.drop_ack_on_guard_check = drop_ack_on_guard_check
        self.drop_ack_on_guard_readback = drop_ack_on_guard_readback
        self.printk_on_guard_readback = printk_on_guard_readback
        self.append_printk_on_pin_fail = append_printk_on_pin_fail
        self.fail_rm_guard_out = fail_rm_guard_out
        self.drop_ack_on_rm_mlv2 = drop_ack_on_rm_mlv2
        self.drop_ack_on_rm_nonce_dir = drop_ack_on_rm_nonce_dir
        self.mutate_guard_on_sd_disabled = mutate_guard_on_sd_disabled
        self.mutate_after_pin_md5_path = mutate_after_pin_md5_path

        self.dirs: set[str] = set(pre_populate_dirs or ())
        self.files: dict[str, bytes] = dict(pre_populate_files or ())
        self.symlinks: set[str] = set(pre_populate_symlinks or ())
        self.fifos: set[str] = set(pre_populate_fifos or ())
        for p in self.leftover_paths:
            self.dirs.add(p)

        self.daemon_pid = live_daemon_pid
        self.daemon_starttime = live_daemon_starttime
        self.daemon_exe = live_daemon_exe
        self.ring_pids = list(live_ring_pids or [])
        self.ring_exe = live_ring_exe
        self.terminal_enables: list[bool] = []
        self.commands_seen: list[str] = []
        self.guard_execs: list[str] = []
        self.rx_buf = bytearray()
        self.out_buf = bytearray()
        self.view_bias = "00010000"

        class _BackendDev:
            def __init__(self, owner):
                self.owner = owner

            def write(self, _ep, chunk):
                self.owner._feed_write(chunk)
                return len(chunk)

        class _Backend:
            def __init__(self, owner):
                self.dev = _BackendDev(owner)

        class _Driver:
            def __init__(self, owner):
                self.backend = _Backend(owner)
                self.epOut = (0, 1)

        self.driver = _Driver(self)

    def sendSenserPacket(self, function, payload, output=None):
        return (0 if function == 0x40 else 1, b"")

    def setTerminalEnable(self, enable: bool):
        self.terminal_enables.append(enable)
        if enable:
            self.rx_buf.extend(b"BusyBox v1.13.4\n/ # ")

    def readTerminal(self):
        if not self.rx_buf:
            return b""
        data = bytes(self.rx_buf)
        self.rx_buf.clear()
        return data

    def _feed_write(self, chunk: bytes):
        self.out_buf.extend(chunk)
        if b"\n" not in self.out_buf:
            return
        line = bytes(self.out_buf)
        self.out_buf.clear()
        m = re.match(
            rb"^echo (__M7_B_[0-9a-f]{12}_[0-9]+__); (.*); (m7_rc_[0-9]+)=\$\?; echo; echo (__M7_E_[0-9a-f]{12}_[0-9]+_)\$\{\3\}__\n$",
            line,
        )
        if not m:
            raise AssertionError(f"Unexpected terminal frame: {line!r}")
        begin, cmd_b, _, end_prefix = m.groups()
        cmd = cmd_b.decode("ascii")
        self.commands_seen.append(cmd)
        if self.drop_ack_on_guard_check and 'then "$g" check "$a"' in cmd:
            self.drop_ack_on_guard_check = False
            self.rx_buf.extend(begin + b"\nPARTIAL_LOST_ACK")
            return
        if self.drop_ack_on_guard_readback and '/tmp_network/mlv2/.g' in cmd and 'cat /tmp_network/mlv2/.g' in cmd and self.hooks == 'v2':
            self.drop_ack_on_guard_readback = False
            self.rx_buf.extend(begin + b"\nLOST_READBACK_ACK")
            return
        if self.drop_ack_on_rm_mlv2 and cmd == f"/bin/busybox rm -rf {runner.REMOTE_MLV2_DIR}":
            self.drop_ack_on_rm_mlv2 = False
            self._exec(cmd)  # Deletion happened remotely right before ACK was lost!
            self.rx_buf.extend(begin + b"\nLOST_RM_ACK")
            return
        if self.drop_ack_on_rm_nonce_dir and re.fullmatch(r"/bin/busybox rm -rf /tmp_network/\.m7-s7-[0-9a-f]{12}", cmd):
            self.drop_ack_on_rm_nonce_dir = False
            self._exec(cmd)  # Deletion happened remotely right before ACK was lost!
            self.rx_buf.extend(begin + b"\nLOST_RM_NONCE_ACK")
            return
        out_raw, rc = self._exec_raw(cmd)
        resp = (
            begin + b"\n" +
            out_raw +
            (b"\n" if out_raw and not out_raw.endswith(b"\n") else b"") +
            b"\n" +
            end_prefix + str(rc).encode("ascii") + b"__\n" +
            terminal.SHELL_PROMPT
        )
        if self.crlf_framing:
            # Emulate Linux TTY ONLCR translating every LF to CRLF on the wire.
            resp = resp.replace(b"\n", b"\r\n")
        self.rx_buf.extend(resp)

    def _exists(self, p: str) -> bool:
        return p in self.dirs or p in self.files or p in self.symlinks

    def _exec_raw(self, cmd: str) -> tuple[bytes, int]:
        # Byte-exact precap.cfg sentinel read (preserves non-UTF-8 bytes such as 0xFF!)
        if cmd == f"/bin/busybox cat {runner.REMOTE_PRECAP_CFG} && /bin/busybox echo CFG_END_SENTINEL":
            if runner.REMOTE_PRECAP_CFG not in self.files:
                return b"", 1
            return self.files[runner.REMOTE_PRECAP_CFG] + b"CFG_END_SENTINEL\n", 0
        txt, rc = self._exec(cmd)
        return txt.encode("utf-8"), rc

    def _exec(self, cmd: str) -> tuple[str, int]:
        if cmd.startswith("HISTFILE=/dev/null"):
            return "", 0
        if cmd == "cat /version.txt":
            return identity.BUILD + "\n", 0
        if cmd == "cat /proc/mounts":
            return (
                "rootfs / rootfs rw 0 0\n"
                "/dev/mtdblock0 /usr ext2 ro,relatime 0 0\n"
                "proc /proc proc rw,relatime 0 0\n"
                "tmpfs /tmp_network tmpfs rw,relatime,size=1024k 0 0\n"
            ), 0
        if cmd.startswith("ls -ld ") and "/usr/lib/libObj.so" in cmd:
            lines = []
            for p, kind in identity.LISTING_PATHS.items():
                mode = "drwxr-xr-x" if kind == "d" else "-rwxr-xr-x"
                lines.append(f"{mode} 1 root root 100 Jan 1 1970 {p}")
            return "\n".join(lines) + "\n", 0
        if cmd == "ls -ld /usr/lib/viewUnified2.so":
            return f"-rwxr-xr-x 1 root root {self.view_bytes} Jan 1 1970 /usr/lib/viewUnified2.so\n", 0
        if cmd == "/bin/busybox --list":
            return "", 1
        if cmd == "/bin/busybox":
            apps = ["echo", "md5sum", "mkdir", "rmdir", "rm", "chmod", "test", "pidof", "readlink", "wc", "cat", "sleep"]
            if self.has_gunzip:
                apps.append("gunzip")
            if self.has_base64:
                apps.append("base64")
            return "BusyBox v1.13.4 multi-call binary\nCurrently defined functions:\n" + ", ".join(apps) + "\n", 0
        if cmd.startswith("/bin/busybox echo -e '"):
            return "M7_OCTAL_OK\n", 0
        if cmd == "/bin/busybox pidof im.elf":
            if self.pidof_false_negative or not self.im_present:
                return "", 1
            return f"{self.im_pid}\n", 0
        if cmd == "/bin/busybox wc -c /usr/lib/libObj.so":
            return f"{identity.LIBRARY_BYTES} /usr/lib/libObj.so\n", 0
        if cmd == "/bin/busybox md5sum /usr/lib/libObj.so":
            return f"{identity.LIBRARY_MD5}  /usr/lib/libObj.so\n", 0
        if cmd == "/bin/busybox wc -c /usr/lib/viewUnified2.so":
            return f"{self.view_bytes} /usr/lib/viewUnified2.so\n", 0
        if cmd == "/bin/busybox md5sum /usr/lib/viewUnified2.so":
            return f"{self.view_md5}  /usr/lib/viewUnified2.so\n", 0
        if cmd == "/bin/busybox sleep 1":
            return "", 0

        # /proc/*/exe im.elf scan (with UNREAD detection for unreadable userspace exe links)
        if cmd.startswith('n=; for p in /proc/[1-9]*; do [ -e "$p/stat" ] || continue;'):
            if self.proc_scan_fail:
                return "", 1
            lines = []
            if self.im_present:
                if self.im_readlink_fail:
                    lines.append(f"UNREAD:/proc/{self.im_pid}")
                else:
                    lines.append(f"IM:/proc/{self.im_pid}")
            if self.daemon_pid is not None and self.daemon_readlink_fail:
                lines.append(f"UNREAD:/proc/{self.daemon_pid}")
            lines.append("PROC_OK")
            return "\n".join(lines) + "\n", 0

        # /proc/*/exe s7 daemon/ring scan (with U: detection for unreadable userspace exe links)
        m = re.fullmatch(
            r'b=(/tmp_network/\.m7-s7-[0-9a-f]{12});x=/bin/busybox;n=;'
            r'for p in /proc/\[1-9\]\*;do \[ -e "\$p/stat" \]\|\|continue;n=1;'
            r'e=\$\(\$x readlink "\$p/exe" 2>/dev/null\);'
            r'if \[ -n "\$e" \];then case "\$e" in "\$b/daemon\.elf"\|"\$b/daemon\.elf "\*\)echo D:\$p;;"\$b/ring\.elf"\|"\$b/ring\.elf "\*\)echo R:\$p;;esac;'
            r'elif ! c=\$\(\$x cat "\$p/cmdline" 2>/dev/null\)\|\|\[ -n "\$c" \];then echo U:\$p;fi;'
            r'done;\[ -n "\$n" \]&&echo PROC_OK',
            cmd,
        )
        if m:
            if self.proc_scan_fail:
                return "", 1
            base_dir = m.group(1)
            d_target, r_target = base_dir + "/daemon.elf", base_dir + "/ring.elf"
            lines = []
            if self.im_present and self.im_readlink_fail:
                lines.append(f"U:/proc/{self.im_pid}")
            if self.daemon_pid is not None:
                if self.daemon_readlink_fail:
                    lines.append(f"U:/proc/{self.daemon_pid}")
                elif self.daemon_exe == d_target:
                    lines.append(f"D:/proc/{self.daemon_pid}")
            if self.ring_pids and self.ring_exe == r_target:
                lines.extend(f"R:/proc/{p}" for p in self.ring_pids)
            lines.append("PROC_OK")
            return "\n".join(lines) + "\n", 0

        # /proc/<pid> existence check for im.elf / daemon.elf / ring.elf
        m = re.fullmatch(r"if \[ ! -e /proc/([0-9]+) \]; then echo PID_GONE; else echo PID_EXISTS; fi", cmd)
        if m:
            pid = int(m.group(1))
            exists = (
                (self.im_present and pid == self.im_pid) or
                (self.daemon_pid is not None and pid == self.daemon_pid) or
                (pid in self.ring_pids)
            )
            return ("PID_EXISTS\n" if exists else "PID_GONE\n"), 0

        # /proc/<pid>/exe, stat, status
        m = re.fullmatch(r"/bin/busybox readlink /proc/([0-9]+)/exe 2>/dev/null", cmd)
        if m:
            pid = int(m.group(1))
            if self.im_present and pid == self.im_pid:
                if self.im_readlink_fail:
                    return "", 1
                return "/usr/bin/im.elf\n", 0
            if self.daemon_pid is not None and pid == self.daemon_pid and self.daemon_exe:
                if self.daemon_readlink_fail:
                    return "", 1
                return self.daemon_exe + "\n", 0
            return "", 1
        m = re.fullmatch(r"/bin/busybox cat /proc/([0-9]+)/stat 2>/dev/null", cmd)
        if m:
            pid = int(m.group(1))
            if self.im_present and pid == self.im_pid:
                tail = " ".join(["0"] * 18 + [str(self.im_starttime), "0", "0", "0", "0", "0", "0"])
                return f"{pid} (im.elf) S {tail}\n", 0
            if self.daemon_pid is not None and pid == self.daemon_pid:
                tail = " ".join(["0"] * 18 + [str(self.daemon_starttime), "0", "0", "0", "0", "0", "0"])
                return f"{pid} (daemon.elf) S {tail}\n", 0
            return "", 1
        m = re.fullmatch(r"/bin/busybox cat /proc/([0-9]+)/status 2>/dev/null", cmd)
        if m:
            pid = int(m.group(1))
            if self.im_present and pid == self.im_pid:
                return (
                    f"Name:\tim.elf\nPid:\t{pid}\nTgid:\t{pid}\nPPid:\t1\n"
                    f"TracerPid:\t{self.im_tracer_pid}\nUid:\t0\t0\t0\t0\n"
                ), 0
            if self.daemon_pid is not None and pid == self.daemon_pid:
                return f"Name:\tdaemon.elf\nPid:\t{pid}\nTgid:\t{pid}\nPPid:\t1\nTracerPid:\t0\n", 0
            return "", 1

        # Leftover check
        if cmd.startswith("for d in /tmp_network/.m7-s6-* /tmp_network/.m7-s7-*"):
            hits = sorted(
                p for p in (self.dirs | set(self.files.keys()) | self.symlinks)
                if p.startswith("/tmp_network/.m7-s6-") or p.startswith("/tmp_network/.m7-s7-")
                or p in ("/tmp_network/mlv2", "/tmp_network/mods")
            )
            return ("\n".join(hits) + ("\n" if hits else "")), 0

        # find_live_pids_for_exe
        m = re.fullmatch(
            r'for p in /proc/\[1-9\]\*; do case "\$\(/bin/busybox readlink "\$p/exe" 2>/dev/null\)" '
            r'in "([^"]+)"\|"[^"]+ "\*\) echo "\$p";; esac; done',
            cmd,
        )
        if m:
            target = m.group(1)
            hits = []
            if self.daemon_pid is not None and self.daemon_exe == target:
                hits.append(f"/proc/{self.daemon_pid}")
            if self.ring_pids and self.ring_exe == target:
                hits.extend(f"/proc/{p}" for p in self.ring_pids)
            return ("\n".join(hits) + ("\n" if hits else "")), 0

        # mkdir / chmod
        m = re.fullmatch(r"/bin/busybox mkdir (/tmp_network/\S+)", cmd)
        if m:
            self.dirs.add(m.group(1))
            return "", 0
        m = re.fullmatch(r"/bin/busybox chmod [0-7]{3} (/tmp_network/\S+)", cmd)
        if m:
            return "", 0

        # inspect_dir_state
        m = re.fullmatch(
            r"if \[ -d (/\S+) \] && \[ ! -L \1 \]; then echo DIR_OK; "
            r"elif \[ ! -e \1 \] && \[ ! -L \1 \]; then echo DIR_GONE; else echo BAD; fi",
            cmd,
        )
        if m:
            p = m.group(1)
            if p in self.symlinks:
                return "BAD\n", 0
            if p in self.dirs:
                return "DIR_OK\n", 0
            if p in self.files:
                return "BAD\n", 0
            return "DIR_GONE\n", 0

        # inspect_file_state
        m = re.fullmatch(
            r"if \[ -f (/\S+) \] && \[ ! -L \1 \]; then echo FILE_OK; "
            r"elif \[ ! -e \1 \] && \[ ! -L \1 \]; then echo FILE_ABSENT; else echo FILE_BAD; fi",
            cmd,
        )
        if m:
            p = m.group(1)
            if p in self.symlinks or p in self.fifos:
                return "FILE_BAD\n", 0
            if p in self.files:
                return "FILE_OK\n", 0
            if p in self.dirs:
                return "FILE_BAD\n", 0
            return "FILE_ABSENT\n", 0

        # rm -rf / rm -f
        m = re.fullmatch(r"/bin/busybox rm -f (/tmp_network/\S+)", cmd)
        if m:
            p = m.group(1)
            if self.fail_rm_guard_out and runner.REMOTE_GUARD_OUT_RE.fullmatch(p):
                return "", 1
            self.files.pop(p, None)
            return "", 0
        m = re.fullmatch(r"/bin/busybox rm -rf (/tmp_network/\S+)", cmd)
        if m:
            prefix = m.group(1)
            self.dirs.discard(prefix)
            for k in list(self.files):
                if k == prefix or k.startswith(prefix + "/"):
                    del self.files[k]
            return "", 0
        m = re.fullmatch(r"if \[ -e (/\S+) \] \|\| \[ -L \1 \]; then echo PRESENT; else echo GONE; fi", cmd)
        if m:
            return ("PRESENT\n" if self._exists(m.group(1)) else "GONE\n"), 0

        # Upload chunks (mixed-octal or base64)
        m = re.fullmatch(r"/bin/busybox echo -ne '([^']*)' (>|>>) (/tmp_network/\S+)", cmd)
        if m:
            enc, redir, dest = m.groups()
            data = self._decode_mixed_octal(enc)
            if redir == ">":
                self.files[dest] = data
            else:
                self.files[dest] = self.files.get(dest, b"") + data
            return "", 0
        m = re.fullmatch(r"/bin/busybox echo -n '([^']*)' \| /bin/busybox base64 -d (>|>>) (/tmp_network/\S+)", cmd)
        if m:
            b64, redir, dest = m.groups()
            data = base64.b64decode(b64)
            if redir == ">":
                self.files[dest] = data
            else:
                self.files[dest] = self.files.get(dest, b"") + data
            return "", 0
        m = re.fullmatch(r"/bin/busybox gunzip -c (/tmp_network/\S+\.gz) > (/tmp_network/\S+)", cmd)
        if m:
            src, dst = m.groups()
            self.files[dst] = gzip.decompress(self.files[src])
            return "", 0
        m = re.fullmatch(r"/bin/busybox wc -c (/tmp_network/\S+)", cmd)
        if m:
            p = m.group(1)
            if p not in self.files:
                return "", 1
            return f"{len(self.files[p])} {p}\n", 0
        m = re.fullmatch(r"/bin/busybox md5sum (/tmp_network/\S+)", cmd)
        if m:
            p = m.group(1)
            if p not in self.files:
                return "", 1
            if p == self.fail_upload_md5_path:
                return "0" * 32 + "  " + p + "\n", 0
            out = hashlib.md5(self.files[p]).hexdigest() + "  " + p + "\n"
            # Optional race-injection hook: mutate file same-length right AFTER verify_remote_file_pinned's md5sum!
            if p == self.mutate_after_pin_md5_path:
                self.mutate_after_pin_md5_path = None
                mut = bytearray(self.files[p])
                mut[-1] ^= 0xFF
                self.files[p] = bytes(mut)
            return out, 0

        # stop / sd-disabled writes (non-exiting test ! -L && echo ...)
        m = re.fullmatch(
            r"/bin/busybox test ! -L (/tmp_network/\S+) && /bin/busybox echo (stop|disabled) > \1",
            cmd,
        )
        if m:
            path, word = m.groups()
            if path in self.symlinks:
                return "", 1
            self.files[path] = (word + "\n").encode("ascii")
            if word == "disabled" and self.mutate_guard_on_sd_disabled and runner.REMOTE_GUARD in self.files:
                mut = bytearray(self.files[runner.REMOTE_GUARD])
                mut[-1] ^= 0xFF
                self.files[runner.REMOTE_GUARD] = bytes(mut)
            if word == "stop" and not self.daemon_refuse_stop and self.daemon_pid is not None:
                self.daemon_pid = None
                self.ring_pids = []
                log_p = str(Path(path).parent / "daemon.log")
                if log_p in self.files and b"\nSTOP " not in self.files[log_p] and not self.files[log_p].startswith(b"STOP "):
                    n_runs = self.files[log_p].count(b"\nRING_START ") + (1 if self.files[log_p].startswith(b"RING_START ") else 0)
                    n_exits = self.files[log_p].count(b"\nRING_EXIT ") + (1 if self.files[log_p].startswith(b"RING_EXIT ") else 0)
                    r_flt = 1 if self.daemon_stop_with_fault else 0
                    self.files[log_p] += (
                        f"STOP t=15000 trig_t=14900 reason=stop_file detail=0 ticks=300 rerr=0 ferr=0 "
                        f"r_reap=1 r_runs={n_runs} r_ok={n_exits} r_sav={n_exits} r_flt={r_flt} r_unres=0 trunc=0\n"
                    ).encode("ascii")
            return "", 0

        # guarded readback for fresh guard output file
        m = re.fullmatch(
            r"if \[ -f (/tmp_network/mlv2/\.g[0-9a-f]{6}) \]&&\[ ! -L \1 \];"
            r"then /bin/busybox cat \1;else echo M7_OUT_BAD;\(exit 126\);fi",
            cmd,
        )
        if m:
            p = m.group(1)
            if p in self.files and p not in self.symlinks and p not in self.fifos and p not in self.dirs:
                txt = self.files[p].decode("utf-8", "replace")
                if self.printk_on_guard_readback and "INSTALLED " in txt:
                    self.printk_on_guard_readback = False
                    txt = txt.replace("FREEZE ", "[  333.144999] fops_se_ioctl_receive(1000) FREEZE ", 1)
                return txt, 0
            return "M7_OUT_BAD\n", 126

        # cat conditional or direct
        m = re.fullmatch(r"if \[ -f (/tmp_network/\S+) \] && \[ ! -L \1 \]; then /bin/busybox cat \1; fi", cmd)
        if m:
            p = m.group(1)
            if p in self.files and p not in self.symlinks:
                return self.files[p].decode("utf-8", "replace"), 0
            return "", 0
        m = re.fullmatch(r"/bin/busybox cat (/tmp_network/\S+)", cmd)
        if m:
            p = m.group(1)
            if p in self.files:
                return self.files[p].decode("utf-8", "replace"), 0
            return "", 1

        # mlv2_guard.elf (atomic pre-exec md5sum + absent fresh output file .g<6hex>)
        m = re.fullmatch(
            r'd=(/tmp_network/mlv2);g=\$d/mlv2_guard\.elf;a=\$d/(core\.bin|mlv2\.req);o=\$d/(\.g[0-9a-f]{6});x=/bin/busybox;'
            r'if \[ -f "\$g" \]&&\[ ! -L "\$g" \]&&\[ -f "\$a" \]&&\[ ! -L "\$a" \]&&\[ ! -e "\$o" \]&&\[ ! -L "\$o" \]'
            r'&&\[ "\$\(\$x md5sum "\$g"\)" = "([0-9a-f]{32})  \$g" \]'
            r'&&\[ "\$\(\$x md5sum "\$a"\)" = "([0-9a-f]{32})  \$a" \];'
            r'then "\$g" (fnv|check|install|uninstall) "\$a">"\$o";else echo M7_PIN_FAIL;\(exit 125\);fi',
            cmd,
        )
        if m:
            d_dir, a_name, o_name, g_md5, a_md5, subcmd = m.groups()
            g_path = d_dir + "/mlv2_guard.elf"
            a_path = d_dir + "/" + a_name
            o_path = d_dir + "/" + o_name
            g_ok = (
                g_path in self.files and g_path not in self.symlinks and
                hashlib.md5(self.files[g_path]).hexdigest() == g_md5
            )
            a_ok = (
                a_path in self.files and a_path not in self.symlinks and
                hashlib.md5(self.files[a_path]).hexdigest() == a_md5
            )
            o_ok = (
                o_path not in self.files and o_path not in self.symlinks and
                o_path not in self.dirs and o_path not in self.fifos
            )
            if not (g_ok and a_ok and o_ok):
                if self.append_printk_on_pin_fail:
                    return "M7_PIN_FAIL[  333.144999] fops_se_ioctl_receive(1000)\n", 125
                return "M7_PIN_FAIL\n", 125
            self.guard_execs.append(subcmd)
            out_txt, rc = self._exec_guard(subcmd, a_path)
            self.files[o_path] = out_txt.encode("utf-8")
            # Emulate real M7 1.00 kernel console printk during PTRACE_ATTACH freeze on install/uninstall!
            console_noise = (
                "[  333.144999] fops_se_ioctl_receive(1000) fops_se_ioctl_receive(916) fops_se_ioctl_receive(986) "
                if subcmd in ("install", "uninstall")
                else ""
            )
            return console_noise, rc

        # daemon.elf launch
        m = re.fullmatch(r"/tmp_network/\.m7-s7-([0-9a-f]{12})/daemon\.elf", cmd)
        if m:
            if self.fail_daemon_launch_rc is not None:
                return "launch_error\n", self.fail_daemon_launch_rc
            ddir = f"/tmp_network/.m7-s7-{m.group(1)}"
            self.daemon_pid = 777
            self.daemon_starttime = 8888
            self.daemon_exe = cmd
            self.files[ddir + "/daemon.pid"] = b"777\n"
            pre_f = "5" if self.daemon_emit_bad_witness else "0"
            im_st = (self.im_starttime + 1) if self.daemon_emit_wrong_im_st else self.im_starttime
            self.files[ddir + "/daemon.log"] = (
                f"BOOT self_pid=777 im_pid={self.im_pid} im_st={im_st} "
                f"libobj=0x05ecd000 mwf=0x04460000 mpr=0x07400000 mprctrl=0x044a8000 "
                f"ranges=12 mon_proc=170 mon_mwf=170 csp_ptr_ok=1 in_ok=1 ih=27 if=14 "
                f"ring_ok=1 pre_f={pre_f} post=0 bcap=24 pmax=48 deb=100\n"
                f"STATE t=10 cam=1 drive=0x005f size=0x00b3 asp=0x00b9 qual=0x00bc fmt=0x00bd "
                f"pre_f={pre_f} sub_ok=1 sub_en=1 half_ok=1 half=0x0 full_ok=1 full=0x0 "
                f"elig=1 tog=0 gate=0 r_act=0\n"
            ).encode("ascii")
            return "", 0

        raise AssertionError(f"Unhandled mock shell command: {cmd!r}")

    def _exec_guard(self, subcmd: str, arg: str) -> tuple[str, int]:
        if subcmd == "fnv":
            data = self.files.get(arg)
            if data is None:
                return "FNV missing\n", 6
            return f"FNV size={len(data)} fnv={builder.fnv1a_32(data):08x}\n", 0
        if not self.im_present:
            return "MLV2_RESULT=-5 identity/maps\n", 5
        if subcmd == "check":
            h, r, s = self.hooks, self.rects, self.shim
            if self.fail_post_install_check and h == "v2":
                h = "unknown"
            return (
                f"TARGET /proc/{self.im_pid} view_bias={self.view_bias}\n"
                f"STATE hooks={h} rects={r} shim={s}\n"
                f"MLV2_RESULT=0 changed=0\n"
            ), 0
        if subcmd == "install":
            if self.fail_install_mode == "clean_rollback":
                return (
                    f"TARGET /proc/{self.im_pid} view_bias={self.view_bias}\n"
                    f"FREEZE threads=12\n"
                    f"STATE hooks={self.hooks} rects={self.rects} shim={self.shim}\n"
                    f"ROLLBACK step=3 failed=0\n"
                    f"RESUME count=12 result=0\n"
                    f"MLV2_RESULT=-15 changed=0\n"
                ), 1
            if self.fail_install_mode == "partial_dirty":
                self.hooks = "unknown"
                self.rects = "patched"
                self.shim = "shim"
                return (
                    f"TARGET /proc/{self.im_pid} view_bias={self.view_bias}\n"
                    f"FREEZE threads=12\n"
                    f"STATE hooks=stock rects=stock shim=zero\n"
                    f"ROLLBACK step=4 failed=1\n"
                    f"RESUME count=12 result=0\n"
                    f"MLV2_RESULT=-16 changed=1\n"
                ), 1
            req_data = self.files[arg]
            _, _, shim_addr, shim_len, h_sr, h_rf, h_oi, _, _ = struct.unpack_from("<9I", req_data, 0)
            vb = int(self.view_bias, 16)
            shim_start = (shim_addr + vb) & 0xFFFFFFFF
            shim_end = (shim_start + shim_len) & 0xFFFFFFFF
            hooks_s = ",".join(f"{(h + vb) & 0xFFFFFFFF:08x}" for h in (h_sr, h_rf, h_oi))
            self.hooks, self.rects, self.shim = "v2", "patched", "shim"
            return (
                f"TARGET /proc/{self.im_pid} view_bias={self.view_bias}\n"
                f"FREEZE threads=12\n"
                f"STATE hooks=stock rects=stock shim=zero\n"
                f"INSTALLED shim={shim_start:08x}..{shim_end:08x} hooks={hooks_s}\n"
                f"RESUME count=12 result=0\n"
                f"MLV2_RESULT=0 changed=1\n"
            ), 0
        if subcmd == "uninstall":
            if runner.REMOTE_SD_DISABLED not in self.files or runner.REMOTE_SD_STOPPED not in self.files:
                return (
                    f"TARGET /proc/{self.im_pid} view_bias={self.view_bias}\n"
                    f"MLV2_RESULT=-18 sd-disabled and sd-stopped required before live uninstall\n"
                ), 1
            if self.fail_uninstall_busy:
                return (
                    f"TARGET /proc/{self.im_pid} view_bias={self.view_bias}\n"
                    f"FREEZE threads=12\n"
                    f"STATE hooks={self.hooks} rects={self.rects} shim={self.shim}\n"
                    f"BUSY shim_active\n"
                    f"RESUME count=12 result=0\n"
                    f"MLV2_RESULT=-17 changed=0\n"
                ), 1
            self.hooks, self.rects, self.shim = "stock", "stock", "zero"
            return (
                f"TARGET /proc/{self.im_pid} view_bias={self.view_bias}\n"
                f"FREEZE threads=12\n"
                f"STATE hooks=v2 rects=patched shim=shim\n"
                f"UNINSTALLED restored=stock\n"
                f"RESUME count=12 result=0\n"
                f"MLV2_RESULT=0 changed=1\n"
            ), 0
        raise AssertionError(subcmd)

    @staticmethod
    def _decode_mixed_octal(s: str) -> bytes:
        out = bytearray()
        i = 0
        while i < len(s):
            if s[i] == "\\":
                assert s[i + 1] == "0"
                out.append(int(s[i + 2:i + 5], 8))
                i += 5
            else:
                out.append(ord(s[i]))
                i += 1
        return bytes(out)


class FakeCamera:
    def __init__(self, shell: FakeCameraShell):
        self.shell = shell
        self.dev = runner.Stage7Gate(shell)

    def setTerminalEnable(self, enable: bool):
        self.dev.sendSenserPacket(0x10, b"\x00\x00\xf1\x00" + (b"\x01" if enable else b"\x00"))
        self.shell.setTerminalEnable(enable)


def _new_receipt(action: str, nonce: str = "abcdef012345") -> dict:
    return dict(
        utc="20261126T235900Z",
        nonce=nonce,
        action=action,
        model="DSC-RX100M7",
        commands=[],
        steps=[],
        service_stop_requested=True,
    )


def _base_custody(
    artifacts: dict[str, bytes],
    *,
    status: str,
    nonce: str = "abcdef012345",
    install_attempted: bool = True,
    launch_attempted: bool | None = None,
    daemon_started: bool | None = None,
    mlv2_installed: bool = True,
    mlv2_stock_verified: bool = False,
    sd_disabled_confirmed: bool | None = None,
    daemon_collected: bool = False,
    daemon_log_lost: bool = False,
    daemon_pid=None,
    daemon_starttime=None,
    view_bias="00010000",
    saved_log_path=None,
    daemon_runtime_clean=None,
) -> dict:
    if daemon_started is None:
        daemon_started = status in ("running", "daemon_log_persisted") or daemon_collected
    if launch_attempted is None:
        launch_attempted = daemon_started or status == "pending_launch"
    if sd_disabled_confirmed is None:
        sd_disabled_confirmed = (status == "mlv2_disabled_pending_reboot_or_uninstall")
    return dict(
        schema_version=1,
        status=status,
        nonce=nonce,
        directory=f"/tmp_network/.m7-s7-{nonce}",
        mlv2_dir=runner.REMOTE_MLV2_DIR,
        mods_dir=runner.REMOTE_MODS_DIR,
        daemon_exe=f"/tmp_network/.m7-s7-{nonce}/daemon.elf",
        ring_exe=f"/tmp_network/.m7-s7-{nonce}/ring.elf",
        install_attempted=install_attempted,
        launch_attempted=launch_attempted,
        daemon_started=daemon_started,
        mlv2_installed=mlv2_installed,
        mlv2_stock_verified=mlv2_stock_verified,
        sd_disabled_confirmed=sd_disabled_confirmed,
        daemon_collected=daemon_collected,
        daemon_log_lost=daemon_log_lost,
        daemon_pid=daemon_pid,
        daemon_starttime=daemon_starttime,
        im_pid=123,
        im_starttime=4567,
        view_bias=view_bias,
        guard_bytes=len(artifacts["guard"]),
        guard_md5=hashlib.md5(artifacts["guard"]).hexdigest(),
        req_bytes=len(artifacts["request"]),
        req_md5=hashlib.md5(artifacts["request"]).hexdigest(),
        saved_log_path=saved_log_path,
        daemon_runtime_clean=daemon_runtime_clean,
    )


class Stage7RamRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts, cls.manifest = runner.load_and_verify_sealed_artifacts()

    def setUp(self):
        self._sleep_patch = mock.patch.object(runner.time, "sleep", lambda _s: None)
        self._sleep_patch.start()
        self.addCleanup(self._sleep_patch.stop)

    def _start_receipt(self, d_img: bytes, r_img: bytes, nonce: str = "abcdef012345") -> dict:
        rec = _new_receipt("start", nonce=nonce)
        rec.update(
            daemon_sha256=builder.sha(d_img),
            ring_sha256=builder.sha(r_img),
            core_sha256=self.manifest["artifacts"]["core"]["sha256"],
            guard_sha256=self.manifest["artifacts"]["guard"]["sha256"],
            req_sha256=self.manifest["artifacts"]["request"]["sha256"],
            precap_mod_sha256=self.manifest["artifacts"]["precap_mod"]["sha256"],
        )
        return rec

    def test_01_local_view_pin_and_gate_and_seals(self):
        p = ROOT / "extracted/m7-stage7-1.00-20261126T172306Z/usr/lib/viewUnified2.so"
        data = p.read_bytes()
        self.assertEqual(len(data), runner.VIEWUNIFIED2_BYTES)
        self.assertEqual(hashlib.md5(data).hexdigest(), runner.VIEWUNIFIED2_MD5)

        shell = FakeCameraShell()
        gate = runner.Stage7Gate(shell)
        for pkt in PACKETS:
            gate.sendSenserPacket(*pkt)
        for bad in ((0xFF01, b"\x02\x00\x00\x00"), (0x10, b"\x00\x00\x1f\x00\x00"), (0x20, b"")):
            with self.assertRaises(usb.ProbeError):
                gate.sendSenserPacket(*bad)
        with self.assertRaises(usb.ProbeError):
            gate.writeTerminal(b"reboot\n")

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            for src in builder.OUT.iterdir():
                shutil.copy2(src, out_dir / src.name)
            m = json.loads((out_dir / "build.json").read_text())
            m["artifacts"]["daemon"]["config_offset"] += 4
            (out_dir / "build.json").write_text(json.dumps(m))
            with self.assertRaises(ValueError):
                runner.load_and_verify_sealed_artifacts(out_dir)

        for bad_kw in (dict(duration_ms=0), dict(burst_cap=13), dict(after=True), dict(daemonize=1)):
            with self.assertRaises(ValueError):
                runner.configure_daemon(self.artifacts["daemon"], self.manifest, nonce="123456abcdef", **bad_kw)

    def test_02_full_start_and_two_phase_collect_live_uninstall(self):
        with tempfile.TemporaryDirectory() as td:
            active = Path(td) / ".active.json"
            out = Path(td)
            nonce = "abcdef012345"
            d_img = runner.configure_daemon(self.artifacts["daemon"], self.manifest, nonce=nonce)
            r_img = runner.configure_ring(self.artifacts["ring"], self.manifest, nonce=nonce)
            shell = FakeCameraShell(nonce=nonce)
            rec = self._start_receipt(d_img, r_img, nonce=nonce)
            runner.do_start(
                FakeCamera(shell), rec, self.artifacts, self.manifest, d_img, r_img,
                duration_ms=600000, after=0, burst_cap=24, post_max=48, backlog_cap=96,
                debounce_ms=100, focus_ms=300, active_path=active, log_out_dir=out,
            )
            rec["teardown_requested_clean"] = runner.teardown_clean(rec)
            self.assertTrue(runner.evaluate_cli_success("start", rec))
            self.assertEqual(shell.hooks, "v2")

            shell.files[runner.REMOTE_PRECAP_CFG] = b"S7PC1 1 5\n"
            shell.files[runner.REMOTE_MOD_LOG] = b"core_load 5c8af766\ncore_init 00000005\n"
            shell.files[f"/tmp_network/.m7-s7-{nonce}/daemon.log"] += (
                b"STATE t=4000 cam=1 drive=0x005f size=0x00b3 asp=0x00b9 qual=0x00bc fmt=0x00bd "
                b"pre_f=5 sub_ok=1 sub_en=1 half_ok=1 half=0x0 full_ok=1 full=0x0 elig=1 tog=1 gate=1 r_act=0\n"
                b"RING_START t=6000 seq=1 pid=900 tok=0x11223344 pre_f=5 ranges=12\n"
                b"RING_FILE t=7100 seq=1 file=PC000001.JPG drive=0 bytes=40 status=13\n"
                b"RING_EXIT t=7500 seq=1 pid=900 st=0x0 rc=0 sig=0 ev_n=10 unres=0 fault=0\n"
            )

            rec_c1 = _new_receipt("collect", nonce="111111222222")
            runner.do_collect(FakeCamera(shell), rec_c1, self.artifacts, self.manifest, active_path=active, log_out_dir=out)
            rec_c1["teardown_requested_clean"] = runner.teardown_clean(rec_c1)
            self.assertTrue(runner.evaluate_cli_success("collect", rec_c1))
            self.assertEqual(rec_c1["collect_outcome"], "collected_mlv2_disabled")
            self.assertTrue(rec_c1["precap_cfg"]["valid"] and rec_c1["precap_cfg"]["pre_frames"] == 5)

            shell.files[runner.REMOTE_SD_STOPPED] = b""
            rec_c2 = _new_receipt("collect", nonce="333333444444")
            runner.do_collect(FakeCamera(shell), rec_c2, self.artifacts, self.manifest, active_path=active, log_out_dir=out)
            rec_c2["teardown_requested_clean"] = runner.teardown_clean(rec_c2)
            self.assertTrue(runner.evaluate_cli_success("collect", rec_c2))
            self.assertEqual(rec_c2["collect_outcome"], "uninstalled_clean")
            self.assertFalse(active.exists())
            self.assertEqual(shell.dirs, set())

    def test_03_sol_r2_finding1_failed_readlink_and_empty_pidof_is_uncertain(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            active = Path(td) / ".active.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="mlv2_disabled_pending_reboot_or_uninstall", daemon_collected=True),
                active,
            )
            # Compound fault: pidof empty AND readlink /proc/123/exe fails while PID 123 has v2 hooks!
            shell = FakeCameraShell(
                im_pid=123, im_starttime=4567,
                pidof_false_negative=True, im_readlink_fail=True,
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                pre_populate_dirs={runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                },
            )
            rec = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell), rec, self.artifacts, self.manifest, active_path=active, log_out_dir=out)
            rec["teardown_requested_clean"] = runner.teardown_clean(rec)
            self.assertEqual(rec["preflight"]["im_state"], "uncertain")
            self.assertEqual(rec["collect_outcome"], "incomplete")
            self.assertFalse(runner.evaluate_cli_success("collect", rec))
            # MUST NOT delete mlv2/mods or clear custody!
            self.assertIn(runner.REMOTE_MLV2_DIR, shell.dirs)
            self.assertIn(runner.REMOTE_MODS_DIR, shell.dirs)
            self.assertTrue(active.exists())

    def test_04_sol_r2_finding2_checkpoints_pending_upload_stock_ack_and_card_retry(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            nonce = "abcdef012345"
            ddir = f"/tmp_network/.m7-s7-{nonce}"

            # 2a. pending_upload with mlv2.req already uploaded, guard absent, AND nonce dir present -> recovers cleanly!
            active_pu = Path(td) / ".active-pu.json"
            runner.write_active_state_exclusive(
                _base_custody(
                    self.artifacts, status="pending_upload", nonce=nonce,
                    install_attempted=False, mlv2_installed=False, view_bias=None,
                ),
                active_pu,
            )
            shell_pu = FakeCameraShell(
                nonce=nonce,
                pre_populate_dirs={ddir, runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={runner.REMOTE_REQ: self.artifacts["request"]},
            )
            rec_pu = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_pu), rec_pu, self.artifacts, self.manifest, active_path=active_pu, log_out_dir=out)
            rec_pu["teardown_requested_clean"] = runner.teardown_clean(rec_pu)
            self.assertEqual(rec_pu["collect_outcome"], "prelaunch_recovered")
            self.assertTrue(runner.evaluate_cli_success("collect", rec_pu))
            self.assertFalse(active_pu.exists())
            self.assertEqual(shell_pu.dirs, set())

            # 2b. ACK lost after confirmed stock during rm -rf mlv2 -> Checkpoint 3 allows next collect to finish cleanly!
            active_st = Path(td) / ".active-stock.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="mlv2_disabled_pending_reboot_or_uninstall", daemon_collected=True),
                active_st,
            )
            shell_st = FakeCameraShell(
                initial_hooks="stock", initial_rects="stock", initial_shim="zero",
                drop_ack_on_rm_mlv2=True,
                pre_populate_dirs={runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                },
            )
            rec_st1 = _new_receipt("collect", nonce="111111111111")
            with self.assertRaises(usb.ProbeError):
                runner.do_collect(FakeCamera(shell_st), rec_st1, self.artifacts, self.manifest, active_path=active_st, log_out_dir=out)
            self.assertTrue(runner.load_active_state(active_st)["mlv2_stock_verified"])
            # Next collect sees mlv2_stock_verified=True -> finishes cleanly even with same live im.elf!
            rec_st2 = _new_receipt("collect", nonce="222222222222")
            runner.do_collect(FakeCamera(shell_st), rec_st2, self.artifacts, self.manifest, active_path=active_st, log_out_dir=out)
            rec_st2["teardown_requested_clean"] = runner.teardown_clean(rec_st2)
            self.assertEqual(rec_st2["collect_outcome"], "uninstalled_clean")
            self.assertTrue(runner.evaluate_cli_success("collect", rec_st2))
            self.assertFalse(active_st.exists())

            # 2c. Card error does NOT skip Step B camera teardown, AND retry with fixed --card succeeds via saved_log_path!
            active_card = Path(td) / ".active-card.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="running", nonce=nonce, daemon_pid=777, daemon_starttime=8888),
                active_card,
            )
            jpg = make_minimal_jpeg(5472, 3648)
            good_card = Path(td) / "good-card"
            good_card.mkdir()
            (good_card / "PC000001.JPG").write_bytes(jpg)
            shell_card = FakeCameraShell(
                nonce=nonce,
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                live_daemon_pid=777, live_daemon_starttime=8888, live_daemon_exe=ddir + "/daemon.elf",
                pre_populate_dirs={ddir, runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                    ddir + "/daemon.pid": b"777\n",
                    ddir + "/daemon.log": (
                        f"BOOT self_pid=777 im_pid=123 im_st=4567 libobj=0x05ecd000 mwf=0x04460000 "
                        f"mpr=0x07400000 mprctrl=0x044a8000 ranges=12 mon_proc=170 mon_mwf=170 "
                        f"csp_ptr_ok=1 in_ok=1 ih=27 if=14 ring_ok=1 pre_f=0 post=0 bcap=24 pmax=48 deb=100\n"
                        f"RING_START t=6000 seq=1 pid=900 tok=0x11223344 pre_f=5 ranges=12\n"
                        f"RING_FILE t=7100 seq=1 file=PC000001.JPG drive=0 bytes={len(jpg)} status=13\n"
                        f"RING_EXIT t=7500 seq=1 pid=900 st=0x0 rc=0 sig=0 ev_n=10 unres=0 fault=0\n"
                    ).encode("ascii"),
                },
            )
            missing_card = Path(td) / "missing-card"
            rec_c1 = _new_receipt("collect", nonce="333333333333")
            runner.do_collect(
                FakeCamera(shell_card), rec_c1, self.artifacts, self.manifest,
                active_path=active_card, log_out_dir=out, card_root=missing_card,
            )
            rec_c1["teardown_requested_clean"] = runner.teardown_clean(rec_c1)
            # Step B STILL ran and wrote sd-disabled!
            self.assertIn(runner.REMOTE_SD_DISABLED, shell_card.files)
            self.assertFalse(runner.evaluate_cli_success("collect", rec_c1))
            # Retry with MENU opened + valid card -> uninstalls AND verifies card from saved_log_path -> rc 0!
            shell_card.files[runner.REMOTE_SD_STOPPED] = b""
            rec_c2 = _new_receipt("collect", nonce="444444444444")
            runner.do_collect(
                FakeCamera(shell_card), rec_c2, self.artifacts, self.manifest,
                active_path=active_card, log_out_dir=out, card_root=good_card,
            )
            rec_c2["teardown_requested_clean"] = runner.teardown_clean(rec_c2)
            self.assertTrue(rec_c2["card_check"]["all_ok"])
            self.assertEqual(rec_c2["collect_outcome"], "uninstalled_clean")
            self.assertTrue(runner.evaluate_cli_success("collect", rec_c2))
            self.assertFalse(active_card.exists())

    def test_05_sol_r2_finding3_runtime_fault_persists_across_retry_and_strict_stop_pairing(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            nonce = "abcdef012345"
            ddir = f"/tmp_network/.m7-s7-{nonce}"
            active = Path(td) / ".active.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="running", nonce=nonce, daemon_pid=777, daemon_starttime=8888),
                active,
            )
            # Lost guard ACK after persisting a MISSING-STOP faulty log -> retry MUST STILL return False (rc 1)!
            bad_log = (
                b"BOOT self_pid=777 im_pid=123 im_st=4567 libobj=0x05ecd000 mwf=0x04460000 "
                b"mpr=0x07400000 mprctrl=0x044a8000 ranges=12 mon_proc=170 mon_mwf=170 "
                b"csp_ptr_ok=1 in_ok=1 ih=27 if=14 ring_ok=1 pre_f=0 post=0 bcap=24 pmax=48 deb=100\n"
            )
            shell = FakeCameraShell(
                nonce=nonce,
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                drop_ack_on_guard_check=True,
                pre_populate_dirs={ddir, runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                    ddir + "/daemon.log": bad_log,
                },
            )
            rec1 = _new_receipt("collect", nonce="111111111111")
            with self.assertRaises(usb.ProbeError):
                runner.do_collect(FakeCamera(shell), rec1, self.artifacts, self.manifest, active_path=active, log_out_dir=out)
            self.assertIs(runner.load_active_state(active)["daemon_runtime_clean"], False)

            shell.files[runner.REMOTE_SD_STOPPED] = b""
            rec2 = _new_receipt("collect", nonce="222222222222")
            runner.do_collect(FakeCamera(shell), rec2, self.artifacts, self.manifest, active_path=active, log_out_dir=out)
            rec2["teardown_requested_clean"] = runner.teardown_clean(rec2)
            # Camera is cleaned to stock, custody cleared, AND CLI STILL reports fault (False / rc 1)!
            self.assertEqual(rec2["collect_outcome"], "uninstalled_with_prior_runtime_fault")
            self.assertFalse(runner.evaluate_cli_success("collect", rec2))
            self.assertFalse(active.exists())
            self.assertEqual(shell.hooks, "stock")

        # Malformed STOP missing r_flt/r_unres/trunc rejected; mismatched seq 1 vs seq 2 rejected!
        s_partial = runner.parse_daemon_log("STOP t=100 reason=stop_file r_reap=1\n")
        self.assertFalse(runner.compute_log_diagnostics(s_partial)["runtime_clean"])
        s_mismatched = runner.parse_daemon_log(
            "RING_START t=100 seq=1 pid=900\n"
            "RING_EXIT t=200 seq=2 pid=900 rc=0 sig=0 unres=0 fault=0\n"
            "STOP t=300 reason=stop_file r_reap=1 r_runs=1 r_ok=1 r_flt=0 r_unres=0 trunc=0\n"
        )
        self.assertFalse(runner.compute_log_diagnostics(s_mismatched)["runtime_clean"])

    def test_06_sol_r2_finding4_mid_collect_guard_mutation_and_strict_grammar(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            active = Path(td) / ".active.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="mlv2_disabled_pending_reboot_or_uninstall", daemon_collected=True),
                active,
            )
            # Mutate mlv2_guard.elf AFTER initial check (during sd-disabled write) -> uninstall MUST NOT run!
            shell = FakeCameraShell(
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                mutate_guard_on_sd_disabled=True,
                pre_populate_dirs={runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                    runner.REMOTE_SD_STOPPED: b"",
                },
            )
            rec = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell), rec, self.artifacts, self.manifest, active_path=active, log_out_dir=out)
            self.assertEqual(shell.guard_execs, ["check"])  # NEVER ran uninstall on mutated guard!
            self.assertEqual(rec["cleanup"], "DEFERRED_GUARD_PIN_MISMATCH")
            self.assertEqual(rec["collect_outcome"], "incomplete")
            self.assertTrue(active.exists())

        # Cross-operation extra records MUST be rejected by exact record_kinds grammar!
        chk_plus_fnv = runner.parse_guard_output(
            "TARGET /proc/123 view_bias=00010000\nSTATE hooks=stock rects=stock shim=zero\n"
            "FNV size=10 fnv=12345678\nMLV2_RESULT=0 changed=0\n"
        )
        self.assertFalse(runner.guard_check_matches(chk_plus_fnv, 0, expected_pid=123, expected_hooks="stock", expected_rects="stock", expected_shim="zero"))
        inst_plus_as = runner.parse_guard_output(
            "TARGET /proc/123 view_bias=00010000\nFREEZE threads=12\nSTATE hooks=stock rects=stock shim=zero\n"
            "INSTALLED shim=15d73800..15d73e98 hooks=15d73d8d,15d73dc1,15d73ddd\nALREADY_STOCK\n"
            "RESUME count=12 result=0\nMLV2_RESULT=0 changed=1\n"
        )
        self.assertFalse(runner.guard_install_matches(inst_plus_as, 0, expected_pid=123, expected_view_bias="00010000", manifest=self.manifest))
        un_plus_ai = runner.parse_guard_output(
            "TARGET /proc/123 view_bias=00010000\nFREEZE threads=12\nSTATE hooks=v2 rects=patched shim=shim\n"
            "UNINSTALLED restored=stock\nALREADY_INSTALLED\nRESUME count=12 result=0\nMLV2_RESULT=0 changed=1\n"
        )
        self.assertFalse(runner.guard_uninstall_matches(un_plus_ai, 0, expected_pid=123, expected_view_bias="00010000"))

    def test_07_sol_r2_finding5_raw_binary_precap_cfg_and_prelaunch_absent_with_empty_nonce_dir(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            nonce = "abcdef012345"
            ddir = f"/tmp_network/.m7-s7-{nonce}"

            # 5a. Malformed precap.cfg containing raw 0xFF byte saved byte-for-byte (NOT EF BF BD)!
            active_ff = Path(td) / ".active-ff.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="mlv2_disabled_pending_reboot_or_uninstall", daemon_collected=True),
                active_ff,
            )
            shell_ff = FakeCameraShell(
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                pre_populate_dirs={runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                    runner.REMOTE_PRECAP_CFG: b"S7PC1 \xff 5\n",
                },
            )
            rec_ff = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_ff), rec_ff, self.artifacts, self.manifest, active_path=active_ff, log_out_dir=out)
            self.assertFalse(rec_ff["precap_cfg"]["valid"])
            self.assertEqual(Path(rec_ff["saved_precap_cfg_path"]).read_bytes(), b"S7PC1 \xff 5\n")

            # 5b. Prelaunch pending_upload with empty nonce dir present AND im verified absent -> prelaunch_recovered!
            active_pl = Path(td) / ".active-pl.json"
            runner.write_active_state_exclusive(
                _base_custody(
                    self.artifacts, status="pending_upload", nonce=nonce,
                    install_attempted=False, mlv2_installed=False, view_bias=None,
                ),
                active_pl,
            )
            shell_pl = FakeCameraShell(
                nonce=nonce, im_present=False,
                pre_populate_dirs={ddir, runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
            )
            rec_pl = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_pl), rec_pl, self.artifacts, self.manifest, active_path=active_pl, log_out_dir=out)
            rec_pl["teardown_requested_clean"] = runner.teardown_clean(rec_pl)
            self.assertEqual(rec_pl["collect_outcome"], "prelaunch_recovered")
            self.assertTrue(rec_pl.get("prelaunch_recovered"))
            self.assertTrue(runner.evaluate_cli_success("collect", rec_pl))
            self.assertFalse(active_pl.exists())

    def test_08_flock_symlinks_failed_start_busy_and_base64(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            nonce = "abcdef012345"
            d_img = runner.configure_daemon(self.artifacts["daemon"], self.manifest, nonce=nonce)
            r_img = runner.configure_ring(self.artifacts["ring"], self.manifest, nonce=nonce)

            # Flock serialization
            active_lk = Path(td) / ".active-lk.json"
            lock_path = active_lk.resolve().with_name(active_lk.name + ".lock")
            fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(usb.ProbeError):
                    with runner.custody_lock(active_lk):
                        pass
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

            # Symlink at sd-disabled returns clean refusal without poisoning terminal
            shell_sym = FakeCameraShell(
                pre_populate_dirs={runner.REMOTE_MLV2_DIR},
                pre_populate_symlinks={runner.REMOTE_SD_DISABLED},
            )
            cam_sym = FakeCamera(shell_sym)
            cam_sym.setTerminalEnable(True)
            runner.read_ready(cam_sym)
            self.assertFalse(runner.write_sd_disabled_marker(runner.Stage7Session(cam_sym, _new_receipt("collect"))))
            self.assertFalse(cam_sym.dev.poisoned)

            # Failed start clean rollback vs daemon witness failure
            active_rb = Path(td) / ".active-rb.json"
            shell_rb = FakeCameraShell(nonce=nonce, fail_install_mode="clean_rollback")
            with self.assertRaises(usb.ProbeError):
                runner.do_start(
                    FakeCamera(shell_rb), self._start_receipt(d_img, r_img, nonce=nonce),
                    self.artifacts, self.manifest, d_img, r_img,
                    duration_ms=600000, after=0, burst_cap=24, post_max=48, backlog_cap=96,
                    debounce_ms=100, focus_ms=300, active_path=active_rb, log_out_dir=out,
                )
            self.assertFalse(active_rb.exists())
            self.assertEqual(shell_rb.dirs, set())

            active_badw = Path(td) / ".active-badw.json"
            shell_badw = FakeCameraShell(nonce=nonce, daemon_emit_bad_witness=True)
            rec_bw = self._start_receipt(d_img, r_img, nonce=nonce)
            with self.assertRaises(usb.ProbeError):
                runner.do_start(
                    FakeCamera(shell_badw), rec_bw, self.artifacts, self.manifest, d_img, r_img,
                    duration_ms=600000, after=0, burst_cap=24, post_max=48, backlog_cap=96,
                    debounce_ms=100, focus_ms=300, active_path=active_badw, log_out_dir=out,
                )
            self.assertTrue(active_badw.exists())
            self.assertIn(runner.REMOTE_SD_DISABLED, shell_badw.files)
            self.assertNotIn(runner.REMOTE_SD_STOPPED, shell_badw.files)

            # Busy uninstall preserves mlv2 & custody
            active_busy = Path(td) / ".active-busy.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="mlv2_disabled_pending_reboot_or_uninstall", daemon_collected=True),
                active_busy,
            )
            shell_busy = FakeCameraShell(
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                fail_uninstall_busy=True,
                pre_populate_dirs={runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                    runner.REMOTE_SD_DISABLED: b"disabled\n",
                    runner.REMOTE_SD_STOPPED: b"",
                },
            )
            rec_busy = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_busy), rec_busy, self.artifacts, self.manifest, active_path=active_busy, log_out_dir=out)
            self.assertEqual(rec_busy["collect_outcome"], "mlv2_uninstall_busy")
            self.assertTrue(active_busy.exists())

            # Base64 upload + packet audit
            active_b64 = Path(td) / ".active-b64.json"
            nonce_b = "fedcba987654"
            d_b = runner.configure_daemon(self.artifacts["daemon"], self.manifest, nonce=nonce_b)
            r_b = runner.configure_ring(self.artifacts["ring"], self.manifest, nonce=nonce_b)
            shell_b64 = FakeCameraShell(nonce=nonce_b, has_gunzip=True, has_base64=True)
            rec_b64 = self._start_receipt(d_b, r_b, nonce=nonce_b)
            runner.do_start(
                FakeCamera(shell_b64), rec_b64, self.artifacts, self.manifest, d_b, r_b,
                duration_ms=600000, after=0, burst_cap=24, post_max=48, backlog_cap=96,
                debounce_ms=100, focus_ms=300, active_path=active_b64, log_out_dir=out,
            )
            self.assertTrue(rec_b64["start_ready"])
            self.assertTrue(all(u["encoding"] == "base64" for u in rec_b64["uploads"]))
            self.assertEqual(len(rec_b64["packets"]), 3)

    def test_09_r4_retry_state_machine_hardening(self):
        """Verify retry invariants depending on what first collect or failed start left behind."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            nonce = "abcdef012345"
            ddir = f"/tmp_network/.m7-s7-{nonce}"

            # 9a. Non-reboot running session whose nonce dir vanished unexpectedly:
            # Collect #1 writes sd-disabled, latches daemon_log_lost=True + daemon_runtime_clean=False, returns incomplete (rc 1).
            # Collect #2 (after MENU sd-stopped) uninstalls mlv2 & clears custody, STILL returning fault (rc 1) - NEVER rc 0!
            active_lost = Path(td) / ".active-lost.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="running", nonce=nonce, daemon_pid=777, daemon_starttime=8888),
                active_lost,
            )
            shell_lost = FakeCameraShell(
                nonce=nonce,
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                pre_populate_dirs={runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                },
            )
            rec_l1 = _new_receipt("collect", nonce="111111111111")
            runner.do_collect(FakeCamera(shell_lost), rec_l1, self.artifacts, self.manifest, active_path=active_lost, log_out_dir=out)
            rec_l1["teardown_requested_clean"] = runner.teardown_clean(rec_l1)
            self.assertEqual(rec_l1["collect_outcome"], "incomplete")
            self.assertFalse(runner.evaluate_cli_success("collect", rec_l1))
            saved_lost = runner.load_active_state(active_lost)
            self.assertTrue(saved_lost["daemon_log_lost"])
            self.assertIs(saved_lost["daemon_runtime_clean"], False)
            self.assertIn(runner.REMOTE_SD_DISABLED, shell_lost.files)

            shell_lost.files[runner.REMOTE_SD_STOPPED] = b""
            rec_l2 = _new_receipt("collect", nonce="222222222222")
            runner.do_collect(FakeCamera(shell_lost), rec_l2, self.artifacts, self.manifest, active_path=active_lost, log_out_dir=out)
            rec_l2["teardown_requested_clean"] = runner.teardown_clean(rec_l2)
            self.assertEqual(rec_l2["collect_outcome"], "uninstalled_with_prior_runtime_fault")
            self.assertFalse(runner.evaluate_cli_success("collect", rec_l2))
            self.assertFalse(active_lost.exists())
            self.assertEqual(shell_lost.hooks, "stock")
            self.assertEqual(shell_lost.dirs, set())

            # 9b. Pre-launch mlv2_stock_verified with leftover empty nonce dir (failed start before launch):
            # Must NOT strand custody at DEFERRED_LOG_READ_FAILED; cleans up cleanly as prelaunch_recovered!
            active_plst = Path(td) / ".active-plst.json"
            runner.write_active_state_exclusive(
                _base_custody(
                    self.artifacts, status="mlv2_stock_verified", nonce=nonce,
                    install_attempted=True, launch_attempted=False, daemon_started=False,
                    mlv2_installed=False, mlv2_stock_verified=True, sd_disabled_confirmed=False,
                    daemon_collected=False,
                ),
                active_plst,
            )
            shell_plst = FakeCameraShell(
                nonce=nonce,
                pre_populate_dirs={ddir, runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
            )
            rec_plst = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_plst), rec_plst, self.artifacts, self.manifest, active_path=active_plst, log_out_dir=out)
            rec_plst["teardown_requested_clean"] = runner.teardown_clean(rec_plst)
            self.assertEqual(rec_plst["collect_outcome"], "prelaunch_recovered")
            self.assertTrue(runner.evaluate_cli_success("collect", rec_plst))
            self.assertFalse(active_plst.exists())
            self.assertEqual(shell_plst.dirs, set())

            # 9c. Clean run: ACK lost on guard check AFTER Checkpoint 2 (sd_disabled_confirmed=False):
            # Retry #2 writes sd-disabled, hydrates saved log, completes cleanly (collected_mlv2_disabled, rc 0);
            # Repeat Retry #3 (sd_disabled_confirmed=True, sd-stopped still absent) returns mlv2_waiting_sd_stopped (rc 1)!
            active_res = Path(td) / ".active-res.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="running", nonce=nonce, daemon_pid=777, daemon_starttime=8888),
                active_res,
            )
            clean_log = (
                b"BOOT self_pid=777 im_pid=123 im_st=4567 libobj=0x05ecd000 mwf=0x04460000 "
                b"mpr=0x07400000 mprctrl=0x044a8000 ranges=12 mon_proc=170 mon_mwf=170 "
                b"csp_ptr_ok=1 in_ok=1 ih=27 if=14 ring_ok=1 pre_f=0 post=0 bcap=24 pmax=48 deb=100\n"
                b"STOP t=15000 trig_t=14900 reason=stop_file detail=0 ticks=300 rerr=0 ferr=0 "
                b"r_reap=1 r_runs=0 r_ok=0 r_sav=0 r_flt=0 r_unres=0 trunc=0\n"
            )
            shell_res = FakeCameraShell(
                nonce=nonce,
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                drop_ack_on_guard_check=True,
                pre_populate_dirs={ddir, runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                    ddir + "/daemon.log": clean_log,
                },
            )
            rec_r1 = _new_receipt("collect", nonce="333333333333")
            with self.assertRaises(usb.ProbeError):
                runner.do_collect(FakeCamera(shell_res), rec_r1, self.artifacts, self.manifest, active_path=active_res, log_out_dir=out)
            mid_state = runner.load_active_state(active_res)
            self.assertTrue(mid_state["daemon_collected"])
            self.assertFalse(mid_state["sd_disabled_confirmed"])

            rec_r2 = _new_receipt("collect", nonce="444444444444")
            runner.do_collect(FakeCamera(shell_res), rec_r2, self.artifacts, self.manifest, active_path=active_res, log_out_dir=out)
            rec_r2["teardown_requested_clean"] = runner.teardown_clean(rec_r2)
            self.assertEqual(rec_r2["collect_outcome"], "collected_mlv2_disabled")
            self.assertTrue(runner.evaluate_cli_success("collect", rec_r2))
            self.assertTrue(runner.load_active_state(active_res)["sd_disabled_confirmed"])

            rec_r3 = _new_receipt("collect", nonce="555555555555")
            runner.do_collect(FakeCamera(shell_res), rec_r3, self.artifacts, self.manifest, active_path=active_res, log_out_dir=out)
            rec_r3["teardown_requested_clean"] = runner.teardown_clean(rec_r3)
            self.assertEqual(rec_r3["collect_outcome"], "mlv2_waiting_sd_stopped")
            self.assertFalse(runner.evaluate_cli_success("collect", rec_r3))

            # 9d. Duplicate STOP record (first fault, second clean) must be rejected!
            s_dup_stop = runner.parse_daemon_log(
                "STOP t=100 reason=stop_file r_reap=1 r_runs=0 r_ok=0 r_flt=1 r_unres=0 trunc=0\n"
                "STOP t=200 reason=stop_file r_reap=1 r_runs=0 r_ok=0 r_flt=0 r_unres=0 trunc=0\n"
            )
            self.assertFalse(runner.compute_log_diagnostics(s_dup_stop)["runtime_clean"])
            # Process comm containing ')' parsed accurately per proc(5).
            tail = " ".join(["0"] * 18 + ["9999", "0"])
            self.assertEqual(runner.parse_any_proc_stat(f"123 (foo)bar) S {tail}\n", 123)["comm"], "foo)bar")

    def test_10_sol_r4_all_8_findings_resolved(self):
        """Regression suite covering all 8 findings from work/stage7-persist/REVIEW-stage7-2-sol-r4.md."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            nonce = "abcdef012345"
            ddir = f"/tmp_network/.m7-s7-{nonce}"
            d_img = runner.configure_daemon(self.artifacts["daemon"], self.manifest, nonce=nonce)
            r_img = runner.configure_ring(self.artifacts["ring"], self.manifest, nonce=nonce)

            # F1: Live daemon PID 777 with unreadable /proc/777/exe & readable stat/status must NEVER be torn down!
            active_f1 = Path(td) / ".active-f1.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="running", nonce=nonce, daemon_pid=777, daemon_starttime=8888),
                active_f1,
            )
            shell_f1 = FakeCameraShell(
                nonce=nonce,
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                live_daemon_pid=777, live_daemon_starttime=8888, live_daemon_exe=ddir + "/daemon.elf",
                daemon_readlink_fail=True, daemon_refuse_stop=True,
                pre_populate_dirs={ddir, runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                    runner.REMOTE_SD_STOPPED: b"",
                    ddir + "/daemon.pid": b"777\n",
                    ddir + "/daemon.log": b"BOOT self_pid=777 im_pid=123 im_st=4567\n",
                },
            )
            rec_f1 = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_f1), rec_f1, self.artifacts, self.manifest, active_path=active_f1, log_out_dir=out)
            self.assertFalse(rec_f1["stopped_cleanly"])
            self.assertEqual(rec_f1["collect_outcome"], "incomplete")
            self.assertIn(ddir, shell_f1.dirs)
            self.assertIn(runner.REMOTE_MLV2_DIR, shell_f1.dirs)
            self.assertEqual(shell_f1.guard_execs, [])
            self.assertTrue(active_f1.exists())
            self.assertIn(ddir + "/stop", shell_f1.files)

            # F2: Lost-directory checkpoint interrupted on guard check MUST leave loadable custody (NOT status=running+pid=None)!
            active_f2 = Path(td) / ".active-f2.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="running", nonce=nonce, daemon_pid=777, daemon_starttime=8888),
                active_f2,
            )
            shell_f2 = FakeCameraShell(
                nonce=nonce,
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                drop_ack_on_guard_check=True,
                pre_populate_dirs={runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                },
            )
            with self.assertRaises(usb.ProbeError):
                runner.do_collect(FakeCamera(shell_f2), _new_receipt("collect"), self.artifacts, self.manifest, active_path=active_f2, log_out_dir=out)
            mid_f2 = runner.load_active_state(active_f2)  # MUST load cleanly!
            self.assertNotEqual(mid_f2["status"], "running")
            self.assertTrue(mid_f2["daemon_log_lost"])
            self.assertIs(mid_f2["daemon_runtime_clean"], False)
            shell_f2.files[runner.REMOTE_SD_STOPPED] = b""
            rec_f2b = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_f2), rec_f2b, self.artifacts, self.manifest, active_path=active_f2, log_out_dir=out)
            rec_f2b["teardown_requested_clean"] = runner.teardown_clean(rec_f2b)
            self.assertEqual(rec_f2b["collect_outcome"], "uninstalled_with_prior_runtime_fault")
            self.assertFalse(runner.evaluate_cli_success("collect", rec_f2b))
            self.assertFalse(active_f2.exists())

            # F3: Failed-start with faulty final log + lost ACK on rm -rf nonce dir -> Checkpoint 1 preserves fault on retry (rc 1)!
            active_f3 = Path(td) / ".active-f3.json"
            shell_f3 = FakeCameraShell(
                nonce=nonce, daemon_emit_bad_witness=True,
                daemon_stop_with_fault=True, drop_ack_on_rm_nonce_dir=True,
            )
            with self.assertRaises(usb.ProbeError):
                runner.do_start(
                    FakeCamera(shell_f3), self._start_receipt(d_img, r_img, nonce=nonce),
                    self.artifacts, self.manifest, d_img, r_img,
                    duration_ms=600000, after=0, burst_cap=24, post_max=48, backlog_cap=96,
                    debounce_ms=100, focus_ms=300, active_path=active_f3, log_out_dir=out,
                )
            st_f3 = runner.load_active_state(active_f3)
            self.assertEqual(st_f3["status"], "daemon_log_persisted")
            self.assertIs(st_f3["daemon_runtime_clean"], False)
            self.assertTrue(st_f3["saved_log_path"] and Path(st_f3["saved_log_path"]).is_file())
            rec_f3c = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_f3), rec_f3c, self.artifacts, self.manifest, active_path=active_f3, log_out_dir=out)
            rec_f3c["teardown_requested_clean"] = runner.teardown_clean(rec_f3c)
            self.assertEqual(rec_f3c["collect_outcome"], "collected_runtime_fault_mlv2_disabled")
            self.assertFalse(runner.evaluate_cli_success("collect", rec_f3c))

            # F4: Failed-start rollback to stock with failing Checkpoint 3 write MUST NOT delete mlv2/mods!
            active_f4 = Path(td) / ".active-f4.json"
            shell_f4 = FakeCameraShell(nonce=nonce, fail_install_mode="clean_rollback")
            real_replace = runner.replace_active_state_atomic

            def _fail_cp3(state, path=runner.ACTIVE_STATE):
                if state.get("status") == "mlv2_stock_verified":
                    raise OSError("injected disk full on cp3")
                return real_replace(state, path)

            with mock.patch.object(runner, "replace_active_state_atomic", side_effect=_fail_cp3):
                with self.assertRaises(usb.ProbeError):
                    runner.do_start(
                        FakeCamera(shell_f4), self._start_receipt(d_img, r_img, nonce=nonce),
                        self.artifacts, self.manifest, d_img, r_img,
                        duration_ms=600000, after=0, burst_cap=24, post_max=48, backlog_cap=96,
                        debounce_ms=100, focus_ms=300, active_path=active_f4, log_out_dir=out,
                    )
            self.assertIn(runner.REMOTE_MLV2_DIR, shell_f4.dirs)
            self.assertIn(runner.REMOTE_MODS_DIR, shell_f4.dirs)
            self.assertTrue(active_f4.exists())
            rec_f4c = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_f4), rec_f4c, self.artifacts, self.manifest, active_path=active_f4, log_out_dir=out)
            rec_f4c["teardown_requested_clean"] = runner.teardown_clean(rec_f4c)
            self.assertEqual(rec_f4c["collect_outcome"], "prelaunch_recovered")
            self.assertTrue(runner.evaluate_cli_success("collect", rec_f4c))
            self.assertFalse(active_f4.exists())

            # F5: Stopped daemon with readable, BOOT-less (STOP-only) log saves log as fault & STILL executes Step B!
            active_f5 = Path(td) / ".active-f5.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="running", nonce=nonce, daemon_pid=777, daemon_starttime=8888),
                active_f5,
            )
            shell_f5 = FakeCameraShell(
                nonce=nonce, initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                pre_populate_dirs={ddir, runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                    ddir + "/daemon.log": b"STOP t=100 reason=stop_file r_reap=1 r_runs=0 r_ok=0 r_flt=0 r_unres=0 trunc=0\n",
                },
            )
            rec_f5 = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_f5), rec_f5, self.artifacts, self.manifest, active_path=active_f5, log_out_dir=out)
            rec_f5["teardown_requested_clean"] = runner.teardown_clean(rec_f5)
            self.assertTrue(rec_f5.get("sd_disabled_written"))
            self.assertIn(runner.REMOTE_SD_DISABLED, shell_f5.files)
            self.assertTrue(rec_f5.get("log_persisted"))
            self.assertEqual(rec_f5["collect_outcome"], "collected_runtime_fault_mlv2_disabled")
            self.assertFalse(runner.evaluate_cli_success("collect", rec_f5))

            # F6: Out-of-order EXIT-before-START, non-terminal STOP, and duplicate key r_flt=1 r_flt=0 MUST all fail!
            for bad_txt in (
                "BOOT self_pid=1\nRING_EXIT t=10 seq=1 pid=9 rc=0 sig=0 unres=0 fault=0\n"
                "RING_START t=20 seq=1 pid=9\nSTOP t=30 reason=stop_file r_reap=1 r_runs=1 r_ok=1 r_flt=0 r_unres=0 trunc=0\n",
                "BOOT self_pid=1\nSTOP t=10 reason=stop_file r_reap=1 r_runs=1 r_ok=1 r_flt=0 r_unres=0 trunc=0\n"
                "RING_START t=20 seq=1 pid=9\nRING_EXIT t=30 seq=1 pid=9 rc=0 sig=0 unres=0 fault=0\n",
                "BOOT self_pid=1\nSTOP t=10 reason=stop_file r_reap=1 r_runs=0 r_ok=0 r_flt=1 r_flt=0 r_unres=0 trunc=0\n",
            ):
                self.assertFalse(runner.compute_log_diagnostics(runner.parse_daemon_log(bad_txt))["runtime_clean"])

            # F7: Same-length mutation injected AFTER verify_remote_file_pinned md5sum is caught BEFORE exec!
            for target_path, subcmd, arg_p in (
                (runner.REMOTE_GUARD, "check", runner.REMOTE_REQ),
                (runner.REMOTE_REQ, "uninstall", runner.REMOTE_REQ),
                (runner.REMOTE_CORE, "fnv", runner.REMOTE_CORE),
            ):
                shell_f7 = FakeCameraShell(
                    mutate_after_pin_md5_path=target_path,
                    pre_populate_dirs={runner.REMOTE_MLV2_DIR},
                    pre_populate_files={
                        runner.REMOTE_GUARD: self.artifacts["guard"],
                        runner.REMOTE_REQ: self.artifacts["request"],
                        runner.REMOTE_CORE: self.artifacts["core"],
                    },
                )
                cam_f7 = FakeCamera(shell_f7)
                cam_f7.setTerminalEnable(True)
                runner.read_ready(cam_f7)
                arg_data = self.artifacts["core"] if arg_p == runner.REMOTE_CORE else self.artifacts["request"]
                ok_f7, pins_f7, _, _, _ = runner.run_pinned_guard_command(
                    runner.Stage7Session(cam_f7, _new_receipt("collect")),
                    subcmd, arg_p,
                    guard_bytes=len(self.artifacts["guard"]),
                    guard_md5=hashlib.md5(self.artifacts["guard"]).hexdigest(),
                    arg_bytes=len(arg_data),
                    arg_md5=hashlib.md5(arg_data).hexdigest(),
                )
                self.assertFalse(ok_f7)
                self.assertTrue(pins_f7.get("preexec_pin_failed"))
                self.assertEqual(shell_f7.guard_execs, [])

            # F8: CRLF terminal framing altering 35 0d 0a -> 35 0a MUST NOT save altered bytes as precap.cfg!
            active_f8 = Path(td) / ".active-f8.json"
            runner.write_active_state_exclusive(
                _base_custody(self.artifacts, status="mlv2_disabled_pending_reboot_or_uninstall", daemon_collected=True),
                active_f8,
            )
            shell_f8 = FakeCameraShell(
                crlf_framing=True,
                initial_hooks="v2", initial_rects="patched", initial_shim="shim",
                pre_populate_dirs={runner.REMOTE_MLV2_DIR, runner.REMOTE_MODS_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                    runner.REMOTE_PRECAP_CFG: b"S7PC1 1 5\r\n",
                },
            )
            rec_f8 = _new_receipt("collect", nonce="888888888888")
            runner.do_collect(FakeCamera(shell_f8), rec_f8, self.artifacts, self.manifest, active_path=active_f8, log_out_dir=out)
            self.assertFalse(rec_f8["precap_cfg"]["valid"])
            self.assertTrue(rec_f8["precap_cfg"]["byte_fidelity_error"])
            self.assertNotIn("saved_precap_cfg_path", rec_f8)
            self.assertEqual(list(out.glob("*888888888888-precap.cfg")), [])

            # F9 (Sol r6): fresh .g<6hex> output file refuses symlink/dir/FIFO/stale file BEFORE exec,
            # handles printk appended to M7_PIN_FAIL (exit 125), rejects failed rm cleanup, and recovers
            # cleanly from both printk noise and ACK loss during post-install readback!
            fixed_out = runner.REMOTE_MLV2_DIR + "/.gaabbcc"
            for bad_kind in ("symlink", "dir", "fifo", "stale_file"):
                shell_o = FakeCameraShell(
                    pre_populate_dirs={runner.REMOTE_MLV2_DIR} | ({fixed_out} if bad_kind == "dir" else set()),
                    pre_populate_symlinks={fixed_out} if bad_kind == "symlink" else set(),
                    pre_populate_fifos={fixed_out} if bad_kind == "fifo" else set(),
                    pre_populate_files={
                        runner.REMOTE_GUARD: self.artifacts["guard"],
                        runner.REMOTE_REQ: self.artifacts["request"],
                        **({fixed_out: b"STALE_OUTPUT\n"} if bad_kind == "stale_file" else {}),
                    },
                )
                cam_o = FakeCamera(shell_o)
                cam_o.setTerminalEnable(True)
                runner.read_ready(cam_o)
                with mock.patch.object(runner.secrets, "token_hex", return_value="aabbcc"):
                    ok_o, pins_o, parsed_o, _, _ = runner.run_pinned_guard_command(
                        runner.Stage7Session(cam_o, _new_receipt("collect")),
                        "check", runner.REMOTE_REQ,
                        guard_bytes=len(self.artifacts["guard"]),
                        guard_md5=hashlib.md5(self.artifacts["guard"]).hexdigest(),
                        arg_bytes=len(self.artifacts["request"]),
                        arg_md5=hashlib.md5(self.artifacts["request"]).hexdigest(),
                    )
                self.assertFalse(ok_o)
                self.assertTrue(pins_o.get("preexec_pin_failed"))
                self.assertEqual(shell_o.guard_execs, [])
                if bad_kind == "stale_file":
                    self.assertIn(fixed_out, shell_o.files)  # stale file untouched & never read!
                    self.assertEqual(parsed_o["record_kinds"], [])

            # Printk appended directly to M7_PIN_FAIL still returns pin_ok=False (exit 125) without reading/deleting!
            shell_pf = FakeCameraShell(
                mutate_after_pin_md5_path=runner.REMOTE_REQ,
                append_printk_on_pin_fail=True,
                pre_populate_dirs={runner.REMOTE_MLV2_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                },
            )
            cam_pf = FakeCamera(shell_pf)
            cam_pf.setTerminalEnable(True)
            runner.read_ready(cam_pf)
            ok_pf, pins_pf, parsed_pf, _, _ = runner.run_pinned_guard_command(
                runner.Stage7Session(cam_pf, _new_receipt("collect")),
                "check", runner.REMOTE_REQ,
                guard_bytes=len(self.artifacts["guard"]),
                guard_md5=hashlib.md5(self.artifacts["guard"]).hexdigest(),
                arg_bytes=len(self.artifacts["request"]),
                arg_md5=hashlib.md5(self.artifacts["request"]).hexdigest(),
            )
            self.assertFalse(ok_pf)
            self.assertTrue(pins_pf.get("preexec_pin_failed"))
            self.assertEqual(shell_pf.guard_execs, [])
            self.assertEqual(parsed_pf["record_kinds"], [])

            # Failed rm -f cleanup of .g<6hex> MUST reject the guard result (fail-closed)!
            shell_rm = FakeCameraShell(
                fail_rm_guard_out=True,
                pre_populate_dirs={runner.REMOTE_MLV2_DIR},
                pre_populate_files={
                    runner.REMOTE_GUARD: self.artifacts["guard"],
                    runner.REMOTE_REQ: self.artifacts["request"],
                },
            )
            cam_rm = FakeCamera(shell_rm)
            cam_rm.setTerminalEnable(True)
            runner.read_ready(cam_rm)
            ok_rm, pins_rm, parsed_rm, rc_rm, txt_rm = runner.run_pinned_guard_command(
                runner.Stage7Session(cam_rm, _new_receipt("collect")),
                "check", runner.REMOTE_REQ,
                guard_bytes=len(self.artifacts["guard"]),
                guard_md5=hashlib.md5(self.artifacts["guard"]).hexdigest(),
                arg_bytes=len(self.artifacts["request"]),
                arg_md5=hashlib.md5(self.artifacts["request"]).hexdigest(),
            )
            self.assertTrue(ok_rm)
            self.assertIs(pins_rm.get("output_cleanup_ok"), False)
            self.assertEqual(pins_rm.get("output_cleanup_rc"), 1)
            self.assertEqual(txt_rm, "")
            self.assertFalse(runner.guard_check_matches(parsed_rm, rc_rm, expected_pid=123, expected_hooks="stock", expected_rects="stock", expected_shim="zero"))

            # Readback printk noise after install (unpoisoned) -> immediate sd-disabled -> clean uninstall on collect!
            active_rn = Path(td) / ".active-rn.json"
            shell_rn = FakeCameraShell(nonce=nonce, printk_on_guard_readback=True)
            with self.assertRaises(usb.ProbeError):
                runner.do_start(
                    FakeCamera(shell_rn), self._start_receipt(d_img, r_img, nonce=nonce),
                    self.artifacts, self.manifest, d_img, r_img,
                    duration_ms=600000, after=0, burst_cap=24, post_max=48, backlog_cap=96,
                    debounce_ms=100, focus_ms=300, active_path=active_rn, log_out_dir=out,
                )
            self.assertEqual(runner.load_active_state(active_rn)["status"], "mlv2_disabled_pending_reboot_or_uninstall")
            self.assertIn(runner.REMOTE_SD_DISABLED, shell_rn.files)
            shell_rn.files[runner.REMOTE_SD_STOPPED] = b""
            rec_rnc = _new_receipt("collect")
            runner.do_collect(FakeCamera(shell_rn), rec_rnc, self.artifacts, self.manifest, active_path=active_rn, log_out_dir=out)
            rec_rnc["teardown_requested_clean"] = runner.teardown_clean(rec_rnc)
            self.assertTrue(runner.evaluate_cli_success("collect", rec_rnc))
            self.assertFalse(active_rn.exists())
            self.assertEqual(shell_rn.hooks, "stock")

            # Readback ACK loss after install (poisoned) -> pending_install custody + leftover .g file ->
            # collect uses fresh .g tag, writes sd-disabled, and second collect uninstalls cleanly & wipes all dirs!
            active_ra = Path(td) / ".active-ra.json"
            shell_ra = FakeCameraShell(nonce=nonce, drop_ack_on_guard_readback=True)
            with self.assertRaises(usb.ProbeError):
                runner.do_start(
                    FakeCamera(shell_ra), self._start_receipt(d_img, r_img, nonce=nonce),
                    self.artifacts, self.manifest, d_img, r_img,
                    duration_ms=600000, after=0, burst_cap=24, post_max=48, backlog_cap=96,
                    debounce_ms=100, focus_ms=300, active_path=active_ra, log_out_dir=out,
                )
            self.assertEqual(runner.load_active_state(active_ra)["status"], "pending_install")
            self.assertEqual(shell_ra.hooks, "v2")
            rec_ra1 = _new_receipt("collect", nonce="111122223333")
            runner.do_collect(FakeCamera(shell_ra), rec_ra1, self.artifacts, self.manifest, active_path=active_ra, log_out_dir=out)
            rec_ra1["teardown_requested_clean"] = runner.teardown_clean(rec_ra1)
            self.assertEqual(rec_ra1["collect_outcome"], "collected_mlv2_disabled")
            self.assertTrue(runner.evaluate_cli_success("collect", rec_ra1))
            self.assertIn(runner.REMOTE_SD_DISABLED, shell_ra.files)
            shell_ra.files[runner.REMOTE_SD_STOPPED] = b""
            rec_ra2 = _new_receipt("collect", nonce="444455556666")
            runner.do_collect(FakeCamera(shell_ra), rec_ra2, self.artifacts, self.manifest, active_path=active_ra, log_out_dir=out)
            rec_ra2["teardown_requested_clean"] = runner.teardown_clean(rec_ra2)
            self.assertEqual(rec_ra2["collect_outcome"], "uninstalled_clean")
            self.assertTrue(runner.evaluate_cli_success("collect", rec_ra2))
            self.assertFalse(active_ra.exists())
            self.assertEqual(shell_ra.dirs, set())
            self.assertEqual(shell_ra.files, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
