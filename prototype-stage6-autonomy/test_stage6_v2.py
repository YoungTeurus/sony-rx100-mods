#!/usr/bin/env python3
"""Offline Unicorn ARMv7 emulation + host runner tests for Stage 6 WIP v2."""
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts"))

import build_stage6_v2 as builder
import stage6_v2_runner as runner
import m7_probe as usb
from m7_terminal_steps import frame


def pack_dirents(entries):
    out = bytearray()
    for idx, (ino, name) in enumerate(entries, start=1):
        raw_name = name + b"\x00"
        reclen = (19 + len(raw_name) + 7) & ~7
        hdr = struct.pack("<QqHB", ino, idx, reclen, 4)
        out.extend(hdr + raw_name + bytes(reclen - 19 - len(raw_name)))
    return bytes(out)


def fmt_m7cap(token, kind, phase, ms, *data):
    fields = [token, kind, phase, ms] + list(data[:8]) + [0] * max(0, 8 - len(data))
    return ("M7CAP1=" + "".join(f"{x & 0xFFFFFFFF:08x}" for x in fields) + "\n").encode("ascii")


def make_minimal_jpeg(width=5472, height=3648):
    sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + sof0 + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x00\x11\x22\x33" + b"\xff\xd9"


class DaemonV2Machine:
    LIBOBJ = 0x05ECD000
    LIBMWF = 0x04460000
    LIBMPR = 0x07400000
    LIBMPRCTRL = 0x044A8000
    LIBUIPC = 0x04053000
    HEAP = 0x02000000

    INPUT_ROOT = HEAP + 0x0100
    SPINAL = HEAP + 0x0400
    CAMERA = HEAP + 0x0800
    INPUT_CFG = HEAP + 0x1000
    INPUT_STATE = HEAP + 0x3000
    MON_OBJ = HEAP + 0x5000
    MON_HANDLE = HEAP + 0x5100
    PARAMS_BASE = HEAP + 0x6000

    def __init__(
        self,
        image: bytes,
        manifest: dict,
        *,
        daemonize=False,
        fork_role="grandchild",
        duration_ms=60000,
        poll_ms=50,
        heartbeat_ms=500,
        max_log_bytes=65536,
        nonce="abcdef012345",
        debounce_ms=100,
        scenario=None,
        ring_script=None,
        stop_file_ms=None,
        uipc_hang_worker=False,
        uipc_free_fail_at=None,
        worker_requests=None,
        bk_datasize=1,
        bk_val_init=0,
        ring_exe_present=True,
    ):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR
        import unicorn.arm_const as arm

        self.arm = arm
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.cpu.mem_map(0x10000, (len(image) + 4095) & ~4095)
        self.cpu.mem_map(0x00800000, 0x40000)
        self.cpu.reg_write(arm.UC_ARM_REG_SP, 0x0083F000)

        self.nonce = nonce
        self.manifest = manifest
        self.image = builder.configure_daemon(
            image, manifest,
            duration_ms=duration_ms,
            poll_ms=poll_ms,
            heartbeat_ms=heartbeat_ms,
            max_log_bytes=max_log_bytes,
            daemonize=daemonize,
            debounce_ms=debounce_ms,
            nonce=nonce,
        )
        self.cpu.mem_write(0x10000, self.image)

        self.daemonize = daemonize
        self.fork_role = fork_role
        self.scenario = scenario
        self.ring_script = ring_script
        self.stop_file_ms = stop_file_ms
        self.uipc_hang_worker = uipc_hang_worker
        self.uipc_free_fail_at = uipc_free_fail_at
        self.worker_requests = list(worker_requests) if worker_requests is not None else [0x01071472]
        self.bk_datasize = bk_datasize
        self.ring_exe_present = ring_exe_present

        self.clock_ms = 5000
        self.tick = 0
        self.exit_code = None
        self.next_mmap = 0x30000000
        self.next_fd = 10
        self.fds = {}
        self.fs = {}
        self.unlinked = []
        self.syscalls = []
        self.kills_sent = []
        self.execs = []
        self.fork_count = 0
        self.uipc_vallocs = 0
        self.uipc_frees = 0
        self.uipc_ops = []
        self.uipc_map_base = None
        self.uipc_reqs_while_ring_active = 0
        self.stdout_buf = bytearray()
        self.worker_replies_written = []
        self.pending_rep_bytes = bytearray()
        self.pipe_count = 0

        self.active_ring_pid = None
        self.active_ring_exit_ms = None
        self.active_ring_exit_status = 0
        self.active_ring_hang = False
        self.ring_pipe_bytes = bytearray()
        self.ring_launches = []
        self.next_ring_pid = 1400

        self.drive_act = 0x005F
        self.still_size = 0x00B3
        self.still_asp = 0x00B9
        self.jpeg_qual = 0x00BC
        self.file_fmt = 0x00BD
        self.bk_val = bk_val_init
        self.sub_enabled = 1
        self.half = 0
        self.full = 0

        self.urandom_seq = 0x11223344
        self.cpu.hook_add(UC_HOOK_INTR, self.on_syscall)

    def read_cstr(self, addr):
        out = bytearray()
        while len(out) < 256:
            b = self.cpu.mem_read(addr + len(out), 1)[0]
            if b == 0:
                return out.decode("ascii", "replace")
            out.append(b)
        raise AssertionError("unterminated C string")

    def maps_bytes(self):
        lines = [
            f"{self.HEAP:08x}-{self.HEAP+0x20000:08x} rw-p 00000000 00:00 0 [heap]",
            f"{self.LIBUIPC:08x}-{self.LIBUIPC+0x6000:08x} r-xp 00000000 fc:0f 49155 /usr/lib/libosal_uipc.so",
            f"{self.LIBMWF:08x}-{self.LIBMWF+0x3b000:08x} r-xp 00000000 fc:0f 49160 /usr/lib/libMWF.so",
            f"{self.LIBMPRCTRL:08x}-{self.LIBMPRCTRL+0x3b000:08x} r-xp 00000000 fc:0f 49161 /usr/lib/libmprctrl.so",
            f"{self.LIBOBJ:08x}-{self.LIBOBJ+0x1325000:08x} r-xp 00000000 fc:0f 49162 /usr/lib/libObj.so",
            f"{self.LIBOBJ+0x1425000:08x}-{self.LIBOBJ+0x1464000:08x} rw-p 00000000 00:00 0 ",
            f"{self.LIBMPR:08x}-{self.LIBMPR+0xc4c000:08x} r-xp 00000000 fc:0f 49163 /usr/lib/libmpr.so",
        ]
        return ("\n".join(lines) + "\n").encode("ascii")

    def build_im_memory(self):
        mem = {}

        def put(addr, *words):
            raw = struct.pack("<" + "I" * len(words), *words)
            for i, b in enumerate(raw):
                mem[addr + i] = b

        put(self.LIBMWF + 0x42CEC, 7, 0, 0)
        put(self.LIBMWF + 0x45478, 1, self.MON_OBJ)
        put(self.MON_OBJ, self.LIBMWF + 0x43088, 0, 0, 0, 0, self.MON_HANDLE, 170)
        put(self.MON_HANDLE, 0x66888866, 0, 170)

        put(self.LIBOBJ + 0x145F3E8, self.LIBOBJ + 0x145F3F0, 1)
        ftbl = self.LIBMWF + 0x42CEC
        slots = [
            (0x145F4F4, self.drive_act),
            (0x145F4FC, 0x0069),
            (0x1460CD4, 0x05BF),
            (0x145F5F0, self.still_size),
            (0x145F5F4, self.still_asp),
            (0x145F5F8, self.jpeg_qual),
            (0x145F5FC, self.file_fmt),
        ]
        for i, (slot_off, val) in enumerate(slots):
            p_addr = self.PARAMS_BASE + i * 16
            put(self.LIBOBJ + slot_off, p_addr)
            put(p_addr, val, ftbl)

        put(self.LIBOBJ + 0x145D230, self.INPUT_ROOT)
        put(self.LIBOBJ + 0x1463130, self.SPINAL)
        g = [0] * 24
        g[0] = self.INPUT_ROOT
        g[1] = self.CAMERA
        g[20] = self.half
        g[21] = self.full
        g[22] = 10
        g[23] = self.sub_enabled
        put(self.SPINAL, *g)
        put(self.CAMERA, self.LIBOBJ + 0x1390490)

        in_w = [0] * 10
        in_w[0] = self.LIBOBJ + 0x1387AF0
        in_w[6] = self.INPUT_CFG
        in_w[7] = 32
        in_w[9] = self.INPUT_STATE
        put(self.INPUT_ROOT, *in_w)
        for idx in range(32):
            key = 0xA7 if idx == 14 else (0x1F1 if idx == 27 else 0x1000 + idx)
            cfg = [0] * 12
            cfg[2] = key
            put(self.INPUT_CFG + idx * 0x30, *cfg)
            st = [0] * 10
            st[0] = key
            st[2] = self.full if idx == 14 else (self.half if idx == 27 else 0)
            st[4] = idx
            put(self.INPUT_STATE + idx * 0x28, *st)
        return mem

    def synthesize_bk_reply(self):
        if self.bk_datasize != 1:
            return struct.pack("<IiIIIiIi", 1, 0, 0, self.bk_datasize, 0xFFFFFFFF, -75, 0, 0)
        return struct.pack("<IiIIIiIi", 1, 0, 1, 1, self.bk_val & 0xFF, 0, 0, 0)

    def on_syscall(self, cpu, _intno, _user):
        a = self.arm
        r0 = cpu.reg_read(a.UC_ARM_REG_R0)
        r1 = cpu.reg_read(a.UC_ARM_REG_R1)
        r2 = cpu.reg_read(a.UC_ARM_REG_R2)
        r3 = cpu.reg_read(a.UC_ARM_REG_R3)
        r4 = cpu.reg_read(a.UC_ARM_REG_R4)
        r5 = cpu.reg_read(a.UC_ARM_REG_R5)
        nr = cpu.reg_read(a.UC_ARM_REG_R7)
        self.syscalls.append(nr)

        assert nr != 26, "daemon.elf must NEVER invoke ptrace!"

        res = 0
        if nr == 1:
            self.exit_code = r0
            cpu.emu_stop()
            return
        elif nr == 2:  # fork
            self.fork_count += 1
            worker_idx = 3 if self.daemonize else 1
            if self.fork_role == "worker":
                res = 0
            elif self.fork_role == "ring_exec" and self.fork_count > worker_idx:
                res = 0
            elif self.fork_count < worker_idx:
                res = 0
            elif self.fork_count == worker_idx:
                res = 888
            else:
                rpid = self.next_ring_pid
                self.next_ring_pid += 1
                self.active_ring_pid = rpid
                cfg_raw = self.fs.get(f"/tmp_network/.m7-s6-{self.nonce}/run.cfg", b"")
                self.ring_launches.append(dict(pid=rpid, ms=self.clock_ms - 5000, cfg=cfg_raw))
                if self.ring_script is not None:
                    self.ring_script(self, len(self.ring_launches), cfg_raw)
                else:
                    self.active_ring_exit_ms = self.clock_ms + 30
                    self.active_ring_exit_status = 0
                res = rpid
        elif nr == 11:  # execve (only tested in fork_role="ring_exec")
            path = self.read_cstr(r0)
            self.execs.append(path)
            self.exit_code = 0
            cpu.emu_stop()
            return
        elif nr == 42:  # pipe
            rfd = self.next_fd
            wfd = self.next_fd + 1
            self.next_fd += 2
            self.pipe_count += 1
            if self.pipe_count == 1:
                req_stream = b"".join(struct.pack("<I", x) for x in self.worker_requests)
                self.fds[rfd] = dict(kind="req_r", data=req_stream, pos=0)
                self.fds[wfd] = dict(kind="req_w")
            elif self.pipe_count == 2:
                self.fds[rfd] = dict(kind="rep_r")
                self.fds[wfd] = dict(kind="rep_w")
            else:
                self.fds[rfd] = dict(kind="ring_r")
                self.fds[wfd] = dict(kind="ring_w")
            cpu.mem_write(r0, struct.pack("<2i", rfd, wfd))
            res = 0
        elif nr == 55:
            assert r1 == 4 and r2 == 0x800
            res = 0
        elif nr == 3:  # read
            f = self.fds[r0]
            if f["kind"] == "rep_r":
                if self.uipc_hang_worker or not self.pending_rep_bytes:
                    res = -11
                else:
                    chunk = bytes(self.pending_rep_bytes[:r2])
                    del self.pending_rep_bytes[:len(chunk)]
                    cpu.mem_write(r1, chunk)
                    res = len(chunk)
            elif f["kind"] == "ring_r":
                if self.ring_pipe_bytes:
                    chunk = bytes(self.ring_pipe_bytes[:r2])
                    del self.ring_pipe_bytes[:len(chunk)]
                    cpu.mem_write(r1, chunk)
                    res = len(chunk)
                elif self.active_ring_pid is None:
                    res = 0
                else:
                    res = -11
            else:
                data = f["data"]
                pos = f["pos"]
                chunk = data[pos:pos + r2]
                cpu.mem_write(r1, chunk)
                f["pos"] = pos + len(chunk)
                res = len(chunk)
        elif nr == 4:  # write
            data = bytes(cpu.mem_read(r1, r2))
            if r0 == 1:
                self.stdout_buf.extend(data)
            elif self.fds[r0]["kind"] == "req_w":
                if self.active_ring_pid is not None:
                    self.uipc_reqs_while_ring_active += 1
                if not self.uipc_hang_worker:
                    self.pending_rep_bytes.extend(self.synthesize_bk_reply())
            elif self.fds[r0]["kind"] == "rep_w":
                self.worker_replies_written.append(struct.unpack("<IiIIIiIi", data))
            else:
                f = self.fds[r0]
                f["buf"].extend(data)
                self.fs[f["path"]] = bytes(f["buf"])
            res = len(data)
        elif nr == 5:  # open
            path = self.read_cstr(r0)
            flags = r1
            fd = self.next_fd
            self.next_fd += 1
            base_dir = f"/tmp_network/.m7-s6-{self.nonce}"
            if path == "/proc":
                entries = [(1, b"1"), (161, b"161")]
                self.fds[fd] = dict(kind="dir", path=path, data=pack_dirents(entries), pos=0)
            elif path == "/proc/161/task":
                entries = [(161, b"161"), (170, b"170"), (446, b"446")]
                self.fds[fd] = dict(kind="dir", path=path, data=pack_dirents(entries), pos=0)
            elif path == "/proc/161/stat":
                stat = b"161 (im.elf) S 1 161 161 0 -1 0 0 0 0 0 0 0 0 0 20 0 40 0 420 0 0\n"
                self.fds[fd] = dict(kind="file", path=path, data=stat, pos=0)
            elif path == "/proc/161/maps":
                self.fds[fd] = dict(kind="file", path=path, data=self.maps_bytes(), pos=0)
            elif path == "/proc/161/task/170/comm":
                self.fds[fd] = dict(kind="file", path=path, data=b"mwf_monitor_inp\n", pos=0)
            elif path == "/proc/161/task/446/comm":
                self.fds[fd] = dict(kind="file", path=path, data=b"ObjStillRecorde\n", pos=0)
            elif path == "/proc/161/mem":
                assert flags == 0
                self.fds[fd] = dict(kind="mem", path=path)
            elif path == "/dev/uipc":
                self.fds[fd] = dict(kind="uipc", path=path)
            elif path == "/dev/urandom":
                self.urandom_seq = (self.urandom_seq + 0x01020305) & 0xFFFFFFFF
                self.fds[fd] = dict(kind="file", path=path, data=struct.pack("<I", self.urandom_seq), pos=0)
            elif path == "/dev/null":
                self.fds[fd] = dict(kind="null", path=path, buf=bytearray())
            elif path == base_dir + "/ring.elf":
                if self.ring_exe_present:
                    self.fds[fd] = dict(kind="file", path=path, data=b"\x7fELF", pos=0)
                else:
                    fd = -2
            elif path == base_dir + "/stop":
                if (self.stop_file_ms is not None and (self.clock_ms - 5000) >= self.stop_file_ms) or path in self.fs:
                    self.fds[fd] = dict(kind="file", path=path, data=b"stop\n", pos=0)
                else:
                    fd = -2
            elif path.startswith(base_dir + "/"):
                if flags & 3:  # write
                    self.fds[fd] = dict(kind="out", path=path, buf=bytearray())
                    self.fs[path] = b""
                elif path in self.fs:
                    self.fds[fd] = dict(kind="file", path=path, data=self.fs[path], pos=0)
                else:
                    fd = -2
            else:
                fd = -2
            res = fd
        elif nr == 6:
            self.fds.pop(r0, None)
            res = 0
        elif nr == 10:  # unlink
            p = self.read_cstr(r0)
            self.unlinked.append(p)
            self.fs.pop(p, None)
            res = 0
        elif nr == 38:  # rename
            src = self.read_cstr(r0)
            dst = self.read_cstr(r1)
            self.fs[dst] = self.fs.pop(src)
            res = 0
        elif nr == 114:  # wait4
            if r0 == 888 and self.uipc_hang_worker:
                res = 0
            elif self.active_ring_pid is not None and r0 == self.active_ring_pid:
                if self.active_ring_hang:
                    res = 0
                elif (self.active_ring_exit_ms is not None and self.clock_ms >= self.active_ring_exit_ms) or (
                    f"/tmp_network/.m7-s6-{self.nonce}/disarm" in self.fs and not self.active_ring_hang
                ):
                    cpu.mem_write(r1, struct.pack("<I", self.active_ring_exit_status))
                    res = r0
                    self.active_ring_pid = None
                else:
                    res = 0
            else:
                cpu.mem_write(r1, struct.pack("<I", 0))
                res = r0
        elif nr in (12, 63, 66, 91, 174, 175):
            res = 0
        elif nr == 20:
            res = 999
        elif nr == 37:  # kill
            self.kills_sent.append((r0, r1))
            res = 0
        elif nr == 54:  # ioctl
            assert self.fork_role == "worker", "Main daemon must NEVER invoke /dev/uipc ioctl!"
            arg0, arg1 = struct.unpack("<2I", cpu.mem_read(r2, 8))
            if r1 == 0x80000010:
                cpu.mem_write(arg1, struct.pack("<4I", 0x10000, 0, 0, 0))
            elif r1 == 0x8000000A:
                out_ptr_va, sz, wait_flag = struct.unpack("<3I", cpu.mem_read(arg1, 12))
                assert wait_flag == 0 and sz == 0x40
                cpu.mem_write(out_ptr_va, struct.pack("<I", self.uipc_map_base + 0x100))
                self.uipc_vallocs += 1
            elif r1 == 0x80000005:
                msg_va, cb, _ = struct.unpack("<3I", cpu.mem_read(arg1, 12))
                assert cb == 0
                msg = list(struct.unpack("<16I", cpu.mem_read(msg_va, 64)))
                op, _, _, _, _, _, _, dst_buf = msg[:8]
                self.uipc_ops.append(op)
                if op == 0:
                    msg[1] = self.bk_datasize
                elif op == 3:
                    cpu.mem_write(dst_buf, bytes([self.bk_val & 0xFF]))
                    msg[1] = 1
                cpu.mem_write(msg_va, struct.pack("<16I", *msg))
            elif r1 == 0x8000000B:
                self.uipc_frees += 1
                if self.uipc_free_fail_at is not None and self.uipc_frees >= self.uipc_free_fail_at:
                    res = -5
            else:
                raise AssertionError(f"Unexpected ioctl {r1:#x}")
        elif nr == 85:  # readlink
            path = self.read_cstr(r0)
            target = b"/usr/bin/im.elf" if path == "/proc/161/exe" else b"/bin/ash"
            n = min(len(target), r2)
            cpu.mem_write(r1, target[:n])
            res = n
        elif nr == 177:  # rt_sigtimedwait
            sec, nsec = struct.unpack("<2I", cpu.mem_read(r2, 8))
            self.clock_ms += sec * 1000 + nsec // 1000000
            self.tick += 1
            if self.scenario is not None:
                self.scenario(self, self.clock_ms - 5000)
            res = -11
        elif nr == 180:  # pread64
            im_mem = self.build_im_memory()
            out = bytes(im_mem.get(r4 + i, 0) for i in range(r2))
            cpu.mem_write(r1, out)
            res = r2
        elif nr == 192:  # mmap2
            size = (r1 + 4095) & ~4095
            addr = self.next_mmap
            self.next_mmap += size + 0x10000
            self.cpu.mem_map(addr, size)
            if r4 != 0xFFFFFFFF and self.fds.get(r4, {}).get("kind") == "uipc":
                self.uipc_map_base = addr
            res = addr
        elif nr == 217:  # getdents64
            f = self.fds[r0]
            data, pos = f["data"], f["pos"]
            chunk = data[pos:pos + r2]
            cpu.mem_write(r1, chunk)
            f["pos"] = pos + len(chunk)
            res = len(chunk)
        elif nr == 263:  # clock_gettime
            cpu.mem_write(r1, struct.pack("<2I", self.clock_ms // 1000, (self.clock_ms % 1000) * 1000000))
            res = 0
        else:
            raise AssertionError(f"Unhandled ARM syscall {nr}")
        cpu.reg_write(a.UC_ARM_REG_R0, res & 0xFFFFFFFF)

    def run(self, count=6000000):
        self.cpu.emu_start(self.manifest["daemon"]["entry"], 0x10000 + len(self.image), count=count)
        return self.exit_code


class RingV2Machine:
    """Real Unicorn ARMv7 emulation of stage6_ring.elf with strict PT_LOAD[0] RX + PT_LOAD[1] RW->RO RELRO."""
    LIBOBJ = 0x05ECD000
    LIBMWF = 0x04460000
    LIBMPR = 0x07400000
    LIBMPRCTRL = 0x044A8000
    LIBUIPC = 0x04053000
    LIBPTHREAD = 0x04010000
    HEAP = 0x02000000

    # Key Sony objects inside HEAP
    INPUT_ROOT = HEAP + 0x0100
    SPINAL = HEAP + 0x0400
    CAMERA = HEAP + 0x0800
    INPUT_CFG = HEAP + 0x1000
    INPUT_STATE = HEAP + 0x3000

    REC_CORE = HEAP + 0x6000
    REC_MGR = HEAP + 0x6400
    REC_THREAD = HEAP + 0x10000
    REC_JOIN = HEAP + 0x10100
    REC_SIGNAL = HEAP + 0x10200
    REC_SIG_MUT = HEAP + 0x10300
    REC_DESC0 = HEAP + 0x10400
    REC_DESC1 = HEAP + 0x10500
    REC_DESC2 = HEAP + 0x10600
    REC_IMG0 = HEAP + 0x10700
    REC_IMG1 = HEAP + 0x10800
    REC_IMG2 = HEAP + 0x10900
    REC_PIN0 = HEAP + 0x10A00
    REC_WRAP0 = HEAP + 0x10B00
    REC_RES0 = HEAP + 0x10C00
    REC_REMOTE_OBJ = HEAP + 0x11000
    REC_STACK = HEAP + 0x1A000  # 0x4000 bytes below -> 0x16000..0x1A000
    REC_TLS = HEAP + 0x1B000

    SRC_CORE = HEAP + 0x1C000
    SRC_THREAD = HEAP + 0x1C500
    SRC_JOIN = HEAP + 0x1C600
    SRC_SIGNAL = HEAP + 0x1C700
    SRC_PIN0 = HEAP + 0x1C800
    SRC_PIN1 = HEAP + 0x1C900
    SRC_SND0 = HEAP + 0x1CA00
    SRC_SND1 = HEAP + 0x1CB00
    SRC_RCV0 = HEAP + 0x1CC00
    SRC_RCV1 = HEAP + 0x1CD00
    SRC_SW0 = HEAP + 0x1CE00
    SRC_SW1 = HEAP + 0x1CF00
    SRC_RW0 = HEAP + 0x1D000
    SRC_RW1 = HEAP + 0x1D100
    SRC_WRAP = HEAP + 0x1D200
    SRC_CB = HEAP + 0x1D300
    SRC_Q = HEAP + 0x1D400
    SRC_LIST = HEAP + 0x1D500

    REM_CORE = HEAP + 0x1E000
    REM_THREAD = HEAP + 0x1E400
    REM_JOIN = HEAP + 0x1E500
    REM_SIGNAL = HEAP + 0x1E600
    REM_SIG_MUT = HEAP + 0x1E700
    REM_PIN0 = HEAP + 0x1E800
    REM_PIN1 = HEAP + 0x1E900
    REM_PIN_CTRL = HEAP + 0x1EA00
    REM_SND = HEAP + 0x1EB00
    REM_RCV = HEAP + 0x1EC00
    REM_SW = HEAP + 0x1ED00
    REM_RW = HEAP + 0x1EE00
    REM_Q = HEAP + 0x1EF00
    REM_STACK = HEAP + 0x1F000  # wait: keep sp-0x4000 inside HEAP! Let's use HEAP2 for stacks.

    HEAP2 = 0x02100000
    REC_SP = HEAP2 + 0x8000
    REM_SP = HEAP2 + 0x10000
    POOL_ROOT = HEAP2 + 0x12000
    POOL_4100 = HEAP2 + 0x14000
    POOL_MUT = HEAP2 + 0x12100

    def __init__(
        self,
        ring_image: bytes,
        manifest: dict,
        cfg_bytes: bytes,
        *,
        nonce="abcdef012345",
        half_init=1,
        full_init=0,
        disarm_present=False,
        stop_present=False,
        ppid=999,
        bad_code_pin=False,
        abort_after_mode_set=False,
        disarm_in_armed=False,
        corrupt_cfg=False,
        sub_enabled_init=1,
        inject_input_eio_in_armed=False,
        full_with_disarm_in_armed=False,
        latch_spinal_s2_at_exit=False,
        sigterm_in_armed=False,
        detached_insert_ms=0,
        detached_pullout_ms=0,
        insert_sub_dip_ms=0,
        insert_sub_never_recovers=False,
    ):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
        import unicorn.arm_const as arm

        self.arm = arm
        self.UC_PROT_READ = UC_PROT_READ
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        r = manifest["ring"]
        self.manifest = manifest
        self.nonce = nonce
        self.ring_image = builder.configure_ring(ring_image, manifest, nonce=nonce)

        # Map PT_LOAD[0] strictly RX and PT_LOAD[1] strictly RW (non-executable)
        ro_map_sz = builder.align_up(r["ro_size"], 4096)
        self.cpu.mem_map(0x10000, ro_map_sz, UC_PROT_READ | UC_PROT_EXEC)
        self.cpu.mem_write(0x10000, self.ring_image[:r["ro_size"]])
        self.cpu.mem_map(r["rw_vaddr"], r["rw_memsz"], UC_PROT_READ | UC_PROT_WRITE)
        self.cpu.mem_write(r["rw_vaddr"], self.ring_image[r["rw_file_offset"]:r["rw_file_offset"] + r["rw_filesz"]])

        self.cpu.mem_map(0x00800000, 0x40000)
        self.cpu.reg_write(arm.UC_ARM_REG_SP, 0x0083F000)

        self.cfg_bytes = (cfg_bytes[:-1] + bytes([cfg_bytes[-1] ^ 0xFF])) if corrupt_cfg else cfg_bytes
        self.half = half_init
        self.full = full_init
        self.disarm_present = disarm_present
        self.stop_present = stop_present
        self.ppid = ppid
        self.bad_code_pin = bad_code_pin
        self.abort_after_mode_set = abort_after_mode_set
        self.disarm_in_armed = disarm_in_armed
        self.sub_enabled = sub_enabled_init
        self.inject_input_eio_in_armed = inject_input_eio_in_armed
        self.input_eio_fired = False
        self.full_with_disarm_in_armed = full_with_disarm_in_armed
        self.latch_spinal_s2_at_exit = latch_spinal_s2_at_exit
        self.sigterm_in_armed = sigterm_in_armed
        self.detached_insert_ms = detached_insert_ms
        self.detached_pullout_ms = detached_pullout_ms
        self.insert_sub_dip_ms = insert_sub_dip_ms
        self.insert_sub_never_recovers = insert_sub_never_recovers
        self.insert_t_ms = None
        self.pullout_t_ms = None
        self.pending_signal = 0
        self.sigprocmask_calls = []

        self.clock_ms = 10000
        self.exit_code = None
        self.next_mmap = 0x30000000
        self.next_fd = 10
        self.fds = {}
        self.stdout_buf = bytearray()
        self.syscalls = []
        self.mprotect_calls = []
        self.ptrace_calls = []
        self.poketext_log = []
        self.sony_ops = []
        self.sndcmd_calls = []

        # Live mutable model of Sony camera RAM
        self.im_mem = {}
        self.inserted_4100 = False
        self.mode_4100 = False
        self.mode_state = "init"  # "init" | "ram" | "sd_restored"
        self.trap_word_map = {}
        self.traced = {}  # tid -> dict(regs, vfp, stopped, sig)
        self.init_sony_memory()
        self.cpu.hook_add(UC_HOOK_INTR, self.on_syscall)

    def put_im(self, addr, *words):
        raw = struct.pack("<" + "I" * len(words), *words)
        for i, b in enumerate(raw):
            self.im_mem[addr + i] = b

    def put_im_bytes(self, addr, raw: bytes):
        for i, b in enumerate(raw):
            self.im_mem[addr + i] = b

    def get_im_u32(self, addr):
        raw = bytes(self.im_mem.get(addr + i, 0) for i in range(4))
        return struct.unpack("<I", raw)[0]

    def init_sony_memory(self):
        # 1. Populate all pinned Sony code bytes directly from Stage 5 pin generators!
        s5 = builder.s5_build
        for va, data in (
            s5.target_pins() + s5.media_pins() + s5.route_pins() + s5.create_pins() +
            s5.end_register_pins() + s5.receiver_pins() + s5.connect_pins() +
            s5.ram_capture_pins() + s5.burst_cancel_pins() + s5.mode_pins() + s5.start_pins()
        ):
            self.put_im_bytes(self.LIBOBJ + va, data)
        for va, data in s5.mpr_pins():
            self.put_im_bytes(self.LIBMPR + va, data)
        for va, data in s5.mprctrl_pins():
            self.put_im_bytes(self.LIBMPRCTRL + va, data)
        for va, data in (
            s5.mwf_pins() + s5.receiver_mwf_pins() + s5.connect_mwf_pins() +
            s5.mode_mwf_pins() + s5.start_mwf_pins()
        ):
            self.put_im_bytes(self.LIBMWF + va, data)
        for va, data in s5.start_uipc_pins():
            self.put_im_bytes(self.LIBUIPC + va, data)
        for va, data in s5.pthread_pins():
            self.put_im_bytes(self.LIBPTHREAD + va, data)

        if self.bad_code_pin:
            self.put_im_bytes(self.LIBOBJ + 0x55ABC, b"\x00\x00\x00\x00")

        # Expected instruction word at 0xa14c98 for capture_trap_set
        self.put_im(self.LIBOBJ + 0xA14C98, 0x531EF240)

        # 2. Input & Spinal
        self.put_im(self.LIBOBJ + 0x145D230, self.INPUT_ROOT)
        self.put_im(self.LIBOBJ + 0x1463130, self.SPINAL)
        self.put_im(self.CAMERA, self.LIBOBJ + 0x1390490)
        self.refresh_input_spinal()

        # 3. ObjStillRecorder registry (0x145d884)
        self.put_im(self.LIBOBJ + 0x145D884, self.REC_CORE, 0, 0, 0, 0)
        # REC_CORE head[0..9] + route + flags
        rec_head = [0] * 64
        rec_head[0] = self.LIBOBJ + 0x138D428
        rec_head[2] = self.REC_SIGNAL
        rec_head[5] = self.HEAP + 0x11100  # receiver 0
        rec_head[7] = self.HEAP + 0x11140  # receiver 1
        rec_head[8] = self.REC_THREAD
        rec_head[9] = 0xFFFFFFFF
        self.put_im(self.REC_CORE, *rec_head)
        self.put_im(self.REC_CORE + 0x58,
                    0, self.HEAP + 0x11180, 0, 0, 0, self.HEAP + 0x111C0, 0, 0, 0, self.HEAP + 0x11200)
        self.put_im(self.REC_CORE + 0x9C, self.REC_REMOTE_OBJ)
        self.put_im(self.REC_REMOTE_OBJ + 0x2044, 0)
        self.put_im(self.REC_CORE + 0xB4, 1)
        self.put_im(self.REC_CORE + 0xF0, self.REC_MGR)
        self.put_im(self.REC_CORE + 0xFC, 1, 0, 0, 0, 0)
        self.put_im(self.REC_CORE + 0x1CC, 0x200, 0)

        # Empty MWF receivers for ObjStillRecorder (8 total)
        rec_rcvs = [
            self.HEAP + 0x11100, self.HEAP + 0x11140, self.HEAP + 0x11180, self.HEAP + 0x111C0,
            self.HEAP + 0x11200, self.HEAP + 0x11240, self.HEAP + 0x11280, self.HEAP + 0x112C0,
        ]
        for idx, rcv in enumerate(rec_rcvs):
            lst = self.HEAP + 0x11400 + idx * 0x20
            self.put_im(rcv, self.LIBMWF + 0x42B78, 0, 0, lst, 0, 0)
            self.put_im(lst, 0, 0, 0, 0)

        self.put_im(self.REC_THREAD, self.LIBMWF + 0x43088, self.LIBMWF + 0x291E1, self.REC_CORE, 0, 0, self.REC_JOIN, 446)
        self.put_im_bytes(self.REC_THREAD + 28, b"ObjStillRecorder\x00")
        self.put_im(self.REC_THREAD + 60, 0x2F)
        self.put_im(self.REC_JOIN, 0x66888866, self.REC_TLS, 446)
        self.put_im(self.REC_SIGNAL + 0x38, self.REC_SIG_MUT, 0)
        self.put_im(self.REC_TLS + 0x7C, self.REC_SP + 0x20, 0, 2)

        # Idle futex frame on REC_SP
        frame_w = [0] * 34
        frame_w[0] = 7
        frame_w[1] = self.LIBPTHREAD + 0x8AC9
        frame_w[4] = 0
        frame_w[8] = self.LIBPTHREAD + 0x88CD
        frame_w[9] = self.REC_SP + 0x10
        frame_w[13] = self.REC_SIGNAL
        frame_w[15] = 0xFFFFFFFF
        frame_w[16] = self.REC_SP + 0x58
        frame_w[21] = self.LIBMWF + 0x31919
        frame_w[28] = self.REC_CORE
        frame_w[31] = self.REC_SP + 0x88
        frame_w[33] = self.LIBMWF + 0x296ED
        self.put_im(self.REC_SP, *frame_w)

        # REC_MGR + descriptors + images
        self.put_im(self.REC_MGR, self.REC_CORE, self.REC_DESC0, self.REC_DESC1, self.REC_DESC2)
        self.put_im(self.REC_MGR + 0x20, 0)
        self.put_im(self.REC_MGR + 0x88, 0, 0)  # empty queue
        self.put_im(self.REC_MGR + 0x69C8, 0, 0)  # busy=0
        for slot, (daddr, iaddr, rcv) in enumerate([
            (self.REC_DESC0, self.REC_IMG0, rec_rcvs[5]),
            (self.REC_DESC1, self.REC_IMG1, rec_rcvs[6]),
            (self.REC_DESC2, self.REC_IMG2, rec_rcvs[7]),
        ]):
            desc = [0] * 16
            desc[0] = self.REC_CORE
            desc[1] = self.REC_MGR + 0x10
            desc[3] = iaddr
            desc[6] = self.REC_RES0 if slot == 0 else (self.HEAP + 0x10D00 + slot * 0x40)
            desc[8] = rcv
            desc[9] = self.REC_PIN0 if slot == 0 else 0
            desc[10] = self.REC_WRAP0 if slot == 0 else 0
            desc[12] = 0x1000 if slot == 0 else 0xFFFFFFFF
            desc[13] = 0x12340000 if slot == 0 else 0xFFFFFFFF
            desc[14] = slot
            self.put_im(daddr, *desc)
            img = [0] * 18
            img[10] = self.REC_MGR + 0x10
            self.put_im(iaddr, *img)
        self.put_im(self.REC_RES0 + 8, 0x12345678)

        # 4. ObjIf class registry at LIBMWF + 0x4548C: entry 0 = ObjMedia, entry 1 = ObjCntMgr
        row0 = bytearray(108)
        struct.pack_into("<I", row0, 0, 1)
        row0[5:14] = b"ObjMedia\x00"
        struct.pack_into("<II", row0, 64, 1, self.SRC_CORE)
        self.put_im_bytes(self.LIBMWF + 0x4548C, bytes(row0))

        row1 = bytearray(108)
        struct.pack_into("<I", row1, 0, 1)
        row1[5:15] = b"ObjCntMgr\x00"
        struct.pack_into("<II", row1, 64, 1, self.REM_CORE)
        self.put_im_bytes(self.LIBMWF + 0x4548C + 108, bytes(row1))

        # ObjMedia (SRC_CORE)
        sh = [0] * 32
        sh[0] = self.LIBOBJ + 0x138DD00
        sh[2] = self.SRC_SIGNAL
        sh[5] = self.HEAP + 0x1D600
        sh[7] = self.HEAP + 0x1D640
        sh[8] = self.SRC_THREAD
        sh[9] = 0xFFFFFFFF
        sh[17] = self.SRC_SND0
        sh[18] = self.SRC_SND1
        sh[19] = self.SRC_RCV0
        sh[20] = self.SRC_RCV1
        sh[21] = self.SRC_PIN0
        sh[22] = self.SRC_PIN1
        sh[23] = self.SRC_WRAP
        sh[30] = 0x4100
        self.put_im(self.SRC_CORE, *sh)
        self.put_im(self.SRC_CORE + 0x84, 1)
        self.put_im(self.SRC_CORE + 0x2F8, 1)
        self.put_im(self.SRC_CORE + 0x358, self.SRC_LIST)
        self.put_im(self.SRC_LIST + 8, 0)
        flags_b = bytearray(68)
        flags_b[0x26] = 1
        flags_b[0x2A] = 1
        self.put_im_bytes(self.SRC_CORE + 0x21C, bytes(flags_b))
        self.put_im(self.SRC_THREAD, self.LIBMWF + 0x43088, self.LIBMWF + 0x291E1, self.SRC_CORE, 0, 0, self.SRC_JOIN, 409)
        self.put_im_bytes(self.SRC_THREAD + 28, b"ObjMedia\x00")
        self.put_im(self.SRC_THREAD + 60, 0x31)
        self.put_im(self.SRC_JOIN, 0x66888866, self.HEAP + 0x1D700, 409)
        self.put_im(self.SRC_SIGNAL + 0x38, 0, 0)
        for rcv, lst in [
            (self.HEAP + 0x1D600, self.HEAP + 0x1D800),
            (self.HEAP + 0x1D640, self.HEAP + 0x1D820),
            (self.SRC_RCV0, self.HEAP + 0x1D840),
            (self.SRC_RCV1, self.HEAP + 0x1D860),
        ]:
            self.put_im(rcv, self.LIBMWF + 0x42B78, 0, 0, lst, 0, 0)
            self.put_im(lst, 0, 0, 0, 0)
        self.put_im(self.SRC_SND0, self.LIBMWF + 0x42BA8, self.SRC_SW0)
        self.put_im(self.SRC_SND1, self.LIBMWF + 0x42BA8, self.SRC_SW1)
        self.put_im(self.SRC_RCV0 + 4, self.SRC_RW0)
        self.put_im(self.SRC_RCV1 + 4, self.SRC_RW1)
        self.put_im(self.SRC_SW0, self.LIBMWF + 0x42BC0, 0x7771)
        self.put_im(self.SRC_RW0, self.LIBMWF + 0x42BC0, 0, 0x7771)
        self.put_im(self.SRC_SW1, self.LIBMWF + 0x42BC0, 0x7772)
        self.put_im(self.SRC_RW1, self.LIBMWF + 0x42BC0, 0, 0x7772)
        self.put_im(self.SRC_PIN0, self.LIBMWF + 0x42FA0, 8, 0, 2, self.REM_PIN_CTRL, self.SRC_SND0, 0)
        self.put_im(self.SRC_PIN1, self.LIBMWF + 0x42FA0, 8, 1, 2, 0, self.SRC_SND1, 0)
        self.put_im(self.SRC_WRAP, self.LIBMWF + 0x42BC0, 0, 0x318474, self.LIBOBJ + 0xA41015, self.SRC_CORE, self.SRC_CB)
        self.put_im(self.SRC_CB, 0, 0, self.LIBUIPC + 0x3169, 0x100, 0, self.LIBMWF + 0x1EFE5, self.SRC_WRAP, 0)

        # ObjCntMgr (REM_CORE)
        rh = [0] * 32
        rh[0] = self.LIBOBJ + 0x1388968
        rh[2] = self.REM_SIGNAL
        rh[5] = self.HEAP + 0x1F000
        rh[7] = self.HEAP + 0x1F040
        rh[8] = self.REM_THREAD
        rh[9] = 0xFFFFFFFF
        rh[17] = 0x4100
        rh[20] = self.REM_PIN0
        rh[21] = self.REM_PIN1
        rh[26] = self.REM_PIN_CTRL
        self.put_im(self.REM_CORE, *rh)
        self.put_im(self.REM_CORE + 0x298, self.REM_Q)
        self.put_im(self.REM_Q, 0, 0, 0, 0)
        # 7 route pairs at REM_CORE + 0x78 (index 0: pin0, index 1: pin1, index 4: REM_CORE+0x98 ctrl pin)
        route_pairs = [0] * 14
        for idx in range(7):
            snd = self.HEAP + 0x1F100 + idx * 0x40
            rcv = self.HEAP + 0x1F120 + idx * 0x40
            sw = self.HEAP + 0x1F300 + idx * 0x20
            rw = self.HEAP + 0x1F400 + idx * 0x20
            lst = self.HEAP + 0x1F500 + idx * 0x20
            self.put_im(snd, self.LIBMWF + 0x42BA8, sw)
            self.put_im(rcv, self.LIBMWF + 0x42B78, rw, 0, lst, 0, 0)
            self.put_im(sw, self.LIBMWF + 0x42BC0, 0x8800 + idx)
            self.put_im(rw, self.LIBMWF + 0x42BC0, 0, 0x8800 + idx)
            self.put_im(lst, 0, 0, 0, 0)
            route_pairs[idx * 2] = snd
            route_pairs[idx * 2 + 1] = rcv
        self.put_im(self.REM_CORE + 0x78, *route_pairs)
        for rcv, lst in [(self.HEAP + 0x1F000, self.HEAP + 0x1F600), (self.HEAP + 0x1F040, self.HEAP + 0x1F620)]:
            self.put_im(rcv, self.LIBMWF + 0x42B78, 0, 0, lst, 0, 0)
            self.put_im(lst, 0, 0, 0, 0)
        self.put_im(self.REM_PIN0, self.LIBMWF + 0x42FA0, 6, 0, 0, 0, route_pairs[0], 0)
        self.put_im(self.REM_PIN_CTRL, self.LIBMWF + 0x42FA0, 8, 0, 2, self.SRC_PIN0, route_pairs[8], 0)
        self.put_im(self.REM_THREAD, self.LIBMWF + 0x43088, self.LIBMWF + 0x291E1, self.REM_CORE, 0, 0, self.REM_JOIN, 408)
        self.put_im_bytes(self.REM_THREAD + 28, b"ObjCntMgr\x00")
        self.put_im(self.REM_THREAD + 60, 0x30)
        self.put_im(self.REM_JOIN, 0x66888866, self.HEAP2 + 0x11000, 408)
        self.put_im(self.REM_SIGNAL + 0x38, self.REM_SIG_MUT, 0)
        self.put_im(self.HEAP2 + 0x11000 + 0x7C, self.REM_SP + 0x20, 0, 2)

        rem_frame = [0] * 34
        rem_frame[0] = 9
        rem_frame[1] = self.LIBPTHREAD + 0x8AC9
        rem_frame[8] = self.LIBPTHREAD + 0x88CD
        rem_frame[9] = self.REM_SP + 0x10
        rem_frame[13] = self.REM_SIGNAL
        rem_frame[15] = 0xFFFFFFFF
        rem_frame[16] = self.REM_SP + 0x58
        rem_frame[21] = self.LIBMWF + 0x31919
        rem_frame[28] = self.REM_CORE
        rem_frame[31] = self.REM_SP + 0x88
        rem_frame[33] = self.LIBMWF + 0x296ED
        self.put_im(self.REM_SP, *rem_frame)

        # Pool root (empty 0x4100 pool)
        self.put_im(self.LIBOBJ + 0x1463800, self.POOL_ROOT)
        self.put_im(self.POOL_ROOT, self.POOL_4100, 0, 0, 0, self.POOL_MUT)
        self.put_im(self.POOL_4100, self.POOL_MUT, 0, 0x4100)
        self.put_im(self.POOL_4100 + 0x70C4, 0, 0, 0)
        self.put_im(self.POOL_4100 + 0x71C8, 0)

        self.apply_media_topology()

    def refresh_input_spinal(self):
        g = [0] * 24
        g[0] = self.INPUT_ROOT
        g[1] = self.CAMERA
        g[20] = self.half
        g[21] = 1 if (self.latch_spinal_s2_at_exit and not self.inserted_4100 and self.poketext_log) else self.full
        g[22] = 10
        g[23] = self.sub_enabled
        self.put_im(self.SPINAL, *g)

        in_w = [0] * 10
        in_w[0] = self.LIBOBJ + 0x1387AF0
        in_w[6] = self.INPUT_CFG
        in_w[7] = 32
        in_w[9] = self.INPUT_STATE
        self.put_im(self.INPUT_ROOT, *in_w)
        for idx in range(32):
            key = 0xA7 if idx == 14 else (0x1F1 if idx == 27 else 0x1000 + idx)
            cfg = [0] * 12
            cfg[2] = key
            cfg[8] = 0xC0 if idx == 14 else (0x40 if idx == 27 else 0)
            self.put_im(self.INPUT_CFG + idx * 0x30, *cfg)
            st = [0] * 10
            st[0] = key
            st[2] = self.full if idx == 14 else (self.half if idx == 27 else 0)
            st[4] = idx
            self.put_im(self.INPUT_STATE + idx * 0x28, *st)

    def apply_media_topology(self):
        mmgr = 0x12340000
        if self.mode_state == "detached":
            # Intermediate Topology 2 (DETACHED) observed during real M7 Insert4100 and Pullout4100!
            self.put_im(self.LIBOBJ + 0x145D57C, 1)
            self.put_im(self.LIBOBJ + 0x145D5C4, 0x4100, 1 if self.inserted_4100 else 0, 0, 0)
            self.put_im(self.SRC_CORE + 0xA0, *((0, 1, 1, 1, 1, 0, 1, 0) if self.inserted_4100 else (0, 0, 0, 0, 1, 0, 0, 0)))
            self.put_im(self.SRC_CORE + 0x100, 0, 0, 0, 0, 0, 0)
            self.put_im(self.SRC_CORE + 0x3C4, 0, 8 if self.inserted_4100 else 1)
            self.put_im(self.REM_CORE + 0x268, 1 if self.inserted_4100 else 0, 0, 1 if self.inserted_4100 else 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, self.REM_Q, 0)
            self.put_im(self.REM_CORE + 0x1E0, 0x4100 if self.inserted_4100 else 0, 1 if self.inserted_4100 else 0)
            self.put_im(self.REM_PIN1, self.LIBMWF + 0x42FA0, 6, 1, 0, 0, self.HEAP + 0x1F140, 0)
            self.put_im(self.REC_PIN0, self.LIBMWF + 0x42FA0, 6, 0, 1, 0, 0, 0)
            self.put_im(self.REC_WRAP0, self.LIBOBJ + 0x13927F0, self.REC_PIN0, 0, 0, 0, 0)
            self.put_im(self.REC_DESC0 + 0x30, 0xFFFFFFFF, 0xFFFFFFFF)
            cfg = [0, 0, 1, 0xFFFFFFFF, 0xFFFFFFFF, mmgr, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, mmgr, 0xFFFFFFFF,
                   0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0x1000, 0xFFFFFFFF, 1, 0]
            self.put_im(self.REC_MGR + 0x30, *cfg)
        elif not self.inserted_4100:
            # Topology 1 (stock SD)
            self.put_im(self.LIBOBJ + 0x145D57C, 1)
            self.put_im(self.LIBOBJ + 0x145D5C4, 0x4100, 0, 0, 0)
            self.put_im(self.SRC_CORE + 0xA0, 0, 0, 0, 0, 1, 0, 0, 0)
            self.put_im(self.SRC_CORE + 0x100, 0, 0, 0, 0, 0, 0)
            self.put_im(self.SRC_CORE + 0x3C4, 0, 1)
            self.put_im(self.REM_CORE + 0x268, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, self.REM_Q, 0)
            self.put_im(self.REM_CORE + 0x1E0, 0, 0)
            sd_peer = self.HEAP + 0x10F00
            self.put_im(sd_peer, self.LIBMWF + 0x42FA0, 6, 0, 0, self.REC_PIN0, 0, 0)
            self.put_im(self.REC_PIN0, self.LIBMWF + 0x42FA0, 6, 0, 1, sd_peer, 0, 0)
            self.put_im(self.REC_WRAP0, self.LIBOBJ + 0x13927F0, self.REC_PIN0, 0, sd_peer, 0, 0)
            self.put_im(self.REC_DESC0 + 0x30, 0x1000, mmgr)
            self.put_im(self.REM_PIN1, self.LIBMWF + 0x42FA0, 6, 1, 0, 0, self.HEAP + 0x1F140, 0)
            cfg = [0, 0, 1, 0x1000, 0x1000, mmgr, 0, 0x1000, 0x1000, mmgr, 0,
                   0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0x1000, 0xFFFFFFFF, 1, 1]
            self.put_im(self.REC_MGR + 0x30, *cfg)
        elif self.mode_state == "init":
            # Topology 3 (Insert4100 active, mode still initial pre-mode_set)
            self.put_im(self.LIBOBJ + 0x145D57C, 1)
            self.put_im(self.LIBOBJ + 0x145D5C4, 0x4100, 1, 0, 0)
            self.put_im(self.SRC_CORE + 0xA0, *((0, 1, 1, 1, 1, 0, 1, 0) if self.inserted_4100 else (0, 0, 0, 0, 1, 0, 0, 0)))
            self.put_im(self.SRC_CORE + 0x100, 0, 0, 0, 0, 0, 0)
            self.put_im(self.SRC_CORE + 0x3C4, 0, 8)
            self.put_im(self.REM_CORE + 0x268, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, self.REM_Q, 0)
            self.put_im(self.REM_CORE + 0x1E0, 0x4100, 1)
            self.put_im(self.REM_PIN1, self.LIBMWF + 0x42FA0, 6, 1, 0, self.REC_PIN0, self.HEAP + 0x1F140, 0)
            self.put_im(self.REC_PIN0, self.LIBMWF + 0x42FA0, 6, 0, 1, self.REM_PIN1, 0, 0)
            self.put_im(self.REC_WRAP0, self.LIBOBJ + 0x13927F0, self.REC_PIN0, 0, self.REM_PIN1, 0, 0)
            self.put_im(self.REC_DESC0 + 0x30, 0x4100, 0)
            cfg = [0, 0, 1, 0xFFFFFFFF, 0xFFFFFFFF, mmgr, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, mmgr, 0xFFFFFFFF,
                   0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0x1000, 0xFFFFFFFF, 1, 0x101]
            self.put_im(self.REC_MGR + 0x30, *cfg)
        elif self.mode_state == "ram":
            # Mode 0x4100 applied!
            self.put_im(self.REM_CORE + 0x268, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, self.REM_Q, 0)
            cfg = [0, 0, 1, 0x4100, 0x4100, 0, 0, 0x4100, 0x4100, 0, 0,
                   0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0x4100, 0xFFFFFFFF, 1, 1]
            self.put_im(self.REC_MGR + 0x30, *cfg)
        else:
            # Mode SD (0x1000) requested while derived 0x4100 tuple awaits Pullout4100 (media_config.c:48-52)
            self.put_im(self.REM_CORE + 0x268, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, self.REM_Q, 0)
            cfg = [0, 0, 1, 0x4100, 0x4100, 0, 0, 0x4100, 0x4100, 0, 0,
                   0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0x1000, 0xFFFFFFFF, 1, 1]
            self.put_im(self.REC_MGR + 0x30, *cfg)

    def make_idle_regs(self, tid):
        if tid == 446:
            sp, sig, mut, r2 = self.REC_SP, self.REC_SIGNAL, self.REC_SIG_MUT, 7
        else:
            sp, sig, mut, r2 = self.REM_SP, self.REM_SIGNAL, self.REM_SIG_MUT, 9
        regs = [0] * 18
        regs[0] = sig + 0xC
        regs[1] = 0x80
        regs[2] = r2
        regs[3] = 0
        regs[6] = sig + 8
        regs[7] = 240
        regs[9] = mut + 4
        regs[12] = 240
        regs[13] = sp
        regs[14] = self.LIBPTHREAD + 0x8AC9
        regs[15] = self.LIBPTHREAD + 0xD144
        regs[16] = 0x30  # Thumb user mode
        regs[17] = sig + 0xC
        return regs

    def read_cstr(self, addr):
        out = bytearray()
        while len(out) < 256:
            b = self.cpu.mem_read(addr + len(out), 1)[0]
            if b == 0:
                return out.decode("ascii", "replace")
            out.append(b)
        raise AssertionError("unterminated C string")

    def on_syscall(self, cpu, _intno, _user):
        a = self.arm
        r0 = cpu.reg_read(a.UC_ARM_REG_R0)
        r1 = cpu.reg_read(a.UC_ARM_REG_R1)
        r2 = cpu.reg_read(a.UC_ARM_REG_R2)
        r3 = cpu.reg_read(a.UC_ARM_REG_R3)
        r4 = cpu.reg_read(a.UC_ARM_REG_R4)
        nr = cpu.reg_read(a.UC_ARM_REG_R7)
        self.syscalls.append(nr)

        res = 0
        if nr == 1:
            self.exit_code = r0
            cpu.emu_stop()
            return
        elif nr == 2:  # fork (sndcmd.elf)
            res = 1900 + len(self.sndcmd_calls)
            self.sndcmd_calls.append(res)
        elif nr == 3:  # read
            f = self.fds[r0]
            data, pos = f["data"], f["pos"]
            chunk = data[pos:pos + r2]
            cpu.mem_write(r1, chunk)
            f["pos"] = pos + len(chunk)
            res = len(chunk)
        elif nr == 4:  # write
            data = bytes(cpu.mem_read(r1, r2))
            if r0 == 1:
                self.stdout_buf.extend(data)
            res = len(data)
        elif nr == 5:  # open
            path = self.read_cstr(r0)
            fd = self.next_fd
            self.next_fd += 1
            base_dir = f"/tmp_network/.m7-s6-{self.nonce}"
            if path == base_dir + "/run.cfg":
                self.fds[fd] = dict(kind="file", data=self.cfg_bytes, pos=0)
            elif path == base_dir + "/stop":
                if self.stop_present:
                    self.fds[fd] = dict(kind="file", data=b"stop\n", pos=0)
                else:
                    fd = -2
            elif path == base_dir + "/disarm":
                if self.disarm_present:
                    self.fds[fd] = dict(kind="file", data=b"disarm\n", pos=0)
                else:
                    fd = -2
            elif path == "/proc/161/mem":
                self.fds[fd] = dict(kind="mem")
            elif path == "/proc/161/task/446/comm":
                self.fds[fd] = dict(kind="file", data=b"ObjStillRecorde\n", pos=0)
            elif path == "/proc/161/task/408/comm":
                self.fds[fd] = dict(kind="file", data=b"ObjCntMgr\n", pos=0)
            elif path == "/proc/161/task/170/comm":
                self.fds[fd] = dict(kind="file", data=b"mwf_monitor_inp\n", pos=0)
            else:
                fd = -2
            res = fd
        elif nr == 6:
            self.fds.pop(r0, None)
        elif nr == 20:
            res = 1400
        elif nr == 64:  # getppid
            res = self.ppid
        elif nr == 116:  # sysinfo
            info = [0] * 16
            info[5] = 65536
            info[13] = 4096
            cpu.mem_write(r0, struct.pack("<16I", *info))
            res = 0
        elif nr == 125:  # mprotect (RELRO!)
            self.mprotect_calls.append((r0, r1, r2))
            if r2 == 1:
                self.cpu.mem_protect(r0, r1, self.UC_PROT_READ)
            res = 0
        elif nr == 162:  # nanosleep
            sec, nsec = struct.unpack("<2I", cpu.mem_read(r0, 8))
            self.clock_ms += max(1, sec * 1000 + nsec // 1000000)
            if self.mode_state == "detached":
                if self.inserted_4100 and self.insert_t_ms is not None and (self.clock_ms - self.insert_t_ms) >= self.detached_insert_ms:
                    self.mode_state = "init"
                    self.apply_media_topology()
                elif (not self.inserted_4100) and self.pullout_t_ms is not None and (self.clock_ms - self.pullout_t_ms) >= self.detached_pullout_ms:
                    self.mode_state = "init"
                    self.apply_media_topology()
            if self.insert_t_ms is not None and not self.insert_sub_never_recovers and self.insert_sub_dip_ms > 0:
                if (self.clock_ms - self.insert_t_ms) >= self.insert_sub_dip_ms and not self.disarm_present:
                    self.sub_enabled = 1
            if self.disarm_in_armed and self.mode_4100 and (self.clock_ms - 10000) >= 2600:
                self.disarm_present = True
                self.sub_enabled = 0  # Simulate user pressing MENU during armed hold!
            if self.full_with_disarm_in_armed and self.mode_4100 and (self.clock_ms - 10000) >= 2600:
                self.disarm_present = True
                if (self.clock_ms - 10000) < 2750:
                    self.full = 1  # Same sample: both disarm AND new full press!
                else:
                    self.full = 0  # Photographer releases full press after click
            if self.sigterm_in_armed and self.mode_4100 and (self.clock_ms - 10000) >= 2600:
                self.pending_signal = 15  # Group SIGTERM delivered while armed!
            res = 0
        elif nr == 174 or nr == 91:
            res = 0
        elif nr == 175:  # rt_sigprocmask
            mask = struct.unpack("<2I", cpu.mem_read(r1, 8)) if r1 else (0, 0)
            self.sigprocmask_calls.append((r0, mask))
            res = 0
        elif nr == 177:  # rt_sigtimedwait
            if self.pending_signal:
                res = self.pending_signal
                self.pending_signal = 0
            else:
                res = (-11) & 0xFFFFFFFF  # -EAGAIN
        elif nr == 180:  # pread64
            self.refresh_input_spinal()
            if (self.inject_input_eio_in_armed and self.mode_4100 and
                    (self.clock_ms - 10000) >= 2610 and r4 == self.INPUT_STATE and not self.input_eio_fired):
                self.input_eio_fired = True
                res = (-5) & 0xFFFFFFFF  # Single transient -EIO on INPUT_STATE!
            else:
                out = bytes(self.im_mem.get(r4 + i, 0) for i in range(r2))
                cpu.mem_write(r1, out)
                res = r2
        elif nr == 192:  # mmap2
            size = (r1 + 4095) & ~4095
            addr = self.next_mmap
            self.next_mmap += size + 0x10000
            self.cpu.mem_map(addr, size)
            res = addr
        elif nr == 263:  # clock_gettime
            cpu.mem_write(r1, struct.pack("<2I", self.clock_ms // 1000, (self.clock_ms % 1000) * 1000000))
            res = 0
        elif nr == 268:  # tgkill(pid, tid, sig)
            tid, sig = r1, r2
            assert tid in self.traced and sig == 19
            self.traced[tid]["stopped"] = True
            self.traced[tid]["sig"] = 19
            res = 0
        elif nr == 114:  # wait4
            if r0 in self.traced:
                st = self.traced[r0]
                if st["stopped"]:
                    sig = st["sig"]
                    st["stopped"] = False
                    cpu.mem_write(r1, struct.pack("<I", (sig << 8) | 0x7F))
                    res = r0
                else:
                    res = 0
            else:
                # sndcmd.elf child exited 0
                cpu.mem_write(r1, struct.pack("<I", 0))
                res = r0
        elif nr == 26:  # ptrace
            req, tid, addr, data = r0, r1, r2, r3
            self.ptrace_calls.append((req, tid, addr, data))
            if req == 16:  # ATTACH
                self.traced[tid] = dict(regs=self.make_idle_regs(tid), vfp=[0] * 65, stopped=True, sig=19)
                res = 0
            elif req == 17:  # DETACH
                self.traced.pop(tid, None)
                res = 0
            elif req == 12:  # GETREGS
                cpu.mem_write(data, struct.pack("<18I", *self.traced[tid]["regs"]))
                res = 0
            elif req == 13:  # SETREGS
                self.traced[tid]["regs"] = list(struct.unpack("<18I", cpu.mem_read(data, 72)))
                res = 0
            elif req == 27:  # GETVFPREGS
                cpu.mem_write(data, struct.pack("<65I", *self.traced[tid]["vfp"]))
                res = 0
            elif req == 28:  # SETVFPREGS
                self.traced[tid]["vfp"] = list(struct.unpack("<65I", cpu.mem_read(data, 260)))
                res = 0
            elif req == 0x4202:  # GETSIGINFO
                info = [0] * 32
                info[0] = 19
                info[2] = 0xFFFFFFFA
                info[3] = 1400
                cpu.mem_write(data, struct.pack("<32I", *info))
                res = 0
            elif req in (4, 5):  # POKETEXT / POKEDATA
                self.put_im(addr, data)
                if req == 4:
                    self.poketext_log.append((addr, data))
                res = 0
            elif req == 7:  # CONT
                st = self.traced[tid]
                pc = st["regs"][15]
                trap_va = self.LIBOBJ + 0x55ABC
                if st["regs"][14] == (trap_va | 1):
                    # Emulate Sony call cleanly and stop at trap!
                    a0, a1, a2 = st["regs"][0], st["regs"][1], st["regs"][2]
                    self.sony_ops.append((pc, a0, a1, a2))
                    ret_val = 0
                    if pc == self.LIBPTHREAD + 0x9A48:  # pthread_setcancelstate
                        tls_addr = self.REC_TLS + 0x84
                        old_v = self.get_im_u32(tls_addr)
                        self.put_im(a1, old_v & 1)
                        self.put_im(tls_addr, (old_v & ~1) | (a0 & 1))
                        ret_val = 0
                    elif pc == self.LIBOBJ + 0xA34BE8:  # remote start/stop
                        arg1_ptr = self.get_im_u32(a1 + 4)
                        cmd_w = self.get_im_u32(arg1_ptr)
                        if cmd_w == 0x72617473:  # "star"(t)
                            self.inserted_4100 = True
                            self.insert_t_ms = self.clock_ms
                            self.mode_state = "detached" if self.detached_insert_ms > 0 else "init"
                            if self.insert_sub_dip_ms > 0 or self.insert_sub_never_recovers:
                                self.sub_enabled = 0
                        else:  # "stop"
                            self.inserted_4100 = False
                            self.mode_4100 = False
                            self.pullout_t_ms = self.clock_ms
                            self.mode_state = "detached" if self.detached_pullout_ms > 0 else "init"
                        self.apply_media_topology()
                        ret_val = 0
                    elif pc == self.LIBOBJ + 0xA1C4E0:  # mode_set
                        if not self.mode_4100:
                            self.mode_4100 = True
                            self.mode_state = "ram"
                        else:
                            self.mode_4100 = False
                            self.mode_state = "sd_restored"
                        self.apply_media_topology()
                        if self.mode_4100 and self.abort_after_mode_set:
                            self.disarm_present = True
                        ret_val = 0
                    st["regs"][0] = ret_val
                    st["regs"][15] = trap_va
                    st["regs"][16] = (st["regs"][16] & ~0x3F) | 0x30
                    st["stopped"] = True
                    st["sig"] = 5
                else:
                    # Resumed into idle wait (no trap hit while running idle)
                    st["stopped"] = False
                res = 0
            else:
                raise AssertionError(f"Unhandled ptrace req {req}")
        else:
            raise AssertionError(f"Unhandled ring syscall {nr}")
        cpu.reg_write(a.UC_ARM_REG_R0, res & 0xFFFFFFFF)

    def run(self):
        self.cpu.emu_start(self.manifest["ring"]["entry"], 0x10000 + self.manifest["ring"]["ro_size"], count=15000000)
        return self.exit_code


class Stage6V2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="s6v2-test-")
        cls.daemon_img, cls.ring_img, cls.manifest = builder.build_all(output=Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_01_build_structure_relro_and_seal(self):
        from elftools.elf.elffile import ELFFile
        import io

        d_elf = ELFFile(io.BytesIO(self.daemon_img))
        self.assertEqual(d_elf.num_segments(), 1)
        self.assertEqual(d_elf.get_segment(0)["p_flags"], 5)  # PF_R|PF_X only!

        r_elf = ELFFile(io.BytesIO(self.ring_img))
        self.assertEqual(r_elf.num_segments(), 2)
        s0, s1 = r_elf.get_segment(0), r_elf.get_segment(1)
        self.assertEqual(s0["p_flags"], 5)  # PF_R|PF_X
        self.assertEqual(s1["p_flags"], 6)  # PF_R|PF_W (non-executable)
        self.assertEqual(s1["p_offset"] % 4096, 0)
        self.assertEqual(s1["p_vaddr"] % 4096, 0)
        self.assertEqual(s1["p_vaddr"], self.manifest["ring"]["rw_vaddr"])
        self.assertEqual(s1["p_memsz"], self.manifest["ring"]["rw_memsz"])

        # Seal verifies cleanly in tmpdir and rejects tampering
        builder.verify_seal(Path(self._tmp.name))
        with tempfile.TemporaryDirectory(prefix="s6v2-bad-") as bad:
            bad_p = Path(bad)
            for name in ("build.json", "stage6_daemon.elf", "stage6_ring.elf"):
                (bad_p / name).write_bytes((Path(self._tmp.name) / name).read_bytes())
            raw = bytearray((bad_p / "stage6_ring.elf").read_bytes())
            raw[-1] ^= 1
            (bad_p / "stage6_ring.elf").write_bytes(raw)
            with self.assertRaises(ValueError):
                builder.verify_seal(bad_p)

    def test_02_daemon_passive_silence_and_strict_gating(self):
        def scen(m, t):
            if t < 400:
                # 1. Toggle OFF (bk=1), Continuous, JPEG, sub_en=1, half held -> MUST NOT ARM
                m.bk_val, m.drive_act, m.file_fmt, m.sub_enabled, m.half, m.full = 1, 0x5F, 0xBD, 1, 1, 0
            elif t < 800:
                # 2. Toggle ON (bk=0), Single (0x5e), half held -> MUST NOT ARM
                m.bk_val, m.drive_act, m.file_fmt, m.sub_enabled, m.half, m.full = 0, 0x5E, 0xBD, 1, 1, 0
            elif t < 1200:
                # 3. Toggle ON, Continuous, RAW+JPEG (0xbf), half held -> MUST NOT ARM
                m.bk_val, m.drive_act, m.file_fmt, m.sub_enabled, m.half, m.full = 0, 0x5F, 0xBF, 1, 1, 0
            elif t < 1600:
                # 4. Toggle ON, Continuous, JPEG, sub_en=0, half held -> MUST NOT ARM
                m.bk_val, m.drive_act, m.file_fmt, m.sub_enabled, m.half, m.full = 0, 0x5F, 0xBD, 0, 1, 0
            elif t < 1900:
                # 5. Idle then 50 ms glitch (< 100 ms debounce) -> MUST NOT ARM
                m.bk_val, m.drive_act, m.file_fmt, m.sub_enabled = 0, 0x5F, 0xBD, 1
                m.half = 1 if 1700 <= t < 1750 else 0
                m.full = 0
            elif t < 2300:
                # 6. Idle then fast smash to full-press (< 100 ms) -> MUST NOT ARM
                m.half = 1 if t >= 2000 else 0
                m.full = 1 if t >= 2050 else 0
            else:
                m.half = m.full = 0

        m = DaemonV2Machine(self.daemon_img, self.manifest, scenario=scen, stop_file_ms=2500, bk_val_init=1)
        m.run()
        self.assertEqual(m.exit_code, 0)
        self.assertEqual(len(m.ring_launches), 0)
        self.assertNotIn(26, m.syscalls)
        self.assertNotIn(54, m.syscalls)

    def test_03_daemon_spawns_ring_parses_m7cap_and_rearms_cleanly(self):
        def scen(m, t):
            m.bk_val, m.drive_act, m.file_fmt, m.sub_enabled = 0, 0x5F, 0xBD, 1
            if t < 150:
                m.half, m.full = 0, 0
            elif t < 900:
                # Hold half-press past 100 ms debounce -> launches ring #1; keep held after ring exits to test re-arm barrier!
                m.half, m.full = 1, 0
            elif t < 1600:
                # Lift finger (satisfies idle + 500 ms cooldown)
                m.half, m.full = 0, 0
            elif t < 2200:
                # Second half-press -> launches ring #2 with fresh token!
                m.half, m.full = 1, 0
            else:
                m.half, m.full = 0, 0

        def ring_script(m, seq, cfg_raw):
            token = struct.unpack_from("<I", cfg_raw, 28 + 8)[0]
            # Emit noisy lines + milestones + 3 saved PCxxxxxx.JPG files!
            buf = bytearray()
            buf.extend(fmt_m7cap(token, 60, 22, 10, 1, 1, 0, 0))
            buf.extend(fmt_m7cap(token, 92, 28, 20, 55, 0, 1, 20, 0, 0, 0))
            for i in range(200):
                buf.extend(fmt_m7cap(token, 92, 28, 21 + i, 57, i, 21 + i, 1, 0, 1, 0, 0))
            buf.extend(fmt_m7cap(token, 92, 28, 230, 1, 230, 2, 2, 0, 0, 0, 0))
            buf.extend(fmt_m7cap(token, 92, 28, 250, 2, 250, 2, 2, 100, 0, 1, 0))
            for idx in (1, 2, 3):
                name_tok = (token ^ (idx << 20)) | 0x80000000
                buf.extend(fmt_m7cap(token, 21, 8, 260 + idx, 10, 13, 9500000 + idx, 0, 0, name_tok, ord("A"), 13))
            buf.extend(fmt_m7cap(token, 92, 28, 280, 8, 1, 5, 2, 3, 0, 1, 0))
            buf.extend(fmt_m7cap(token, 9, 18, 290, 0, 100, 0, 205, 0, 0, 1, 0))
            m.ring_pipe_bytes.extend(buf)
            m.active_ring_exit_ms = m.clock_ms + 80
            m.active_ring_exit_status = 0

        m = DaemonV2Machine(self.daemon_img, self.manifest, scenario=scen, ring_script=ring_script, stop_file_ms=2500)
        m.run()
        self.assertEqual(m.exit_code, 0)
        self.assertEqual(len(m.ring_launches), 2)
        self.assertEqual(m.uipc_reqs_while_ring_active, 0)

        tok1 = struct.unpack_from("<I", m.ring_launches[0]["cfg"], 28 + 8)[0]
        tok2 = struct.unpack_from("<I", m.ring_launches[1]["cfg"], 28 + 8)[0]
        self.assertNotEqual(tok1, tok2)

        parsed = runner.parse_daemon_log(m.stdout_buf.decode("ascii"))
        self.assertEqual(parsed["ring_start_count"], 2)
        self.assertEqual(parsed["ring_exit_count"], 2)
        self.assertEqual(parsed["ring_file_count"], 6)
        self.assertEqual(parsed["stop"]["r_runs"], "2")
        self.assertEqual(parsed["stop"]["r_ok"], "2")
        self.assertEqual(parsed["stop"]["r_sav"], "6")
        self.assertEqual(parsed["stop"]["r_flt"], "0")
        self.assertEqual(parsed["stop"]["r_reap"], "1")
        self.assertLess(len(m.stdout_buf), 8192)  # 400 noisy M7CAP1 lines did NOT bloat daemon.log!

        # Verify child execve target path directly
        me = DaemonV2Machine(
            self.daemon_img, self.manifest, fork_role="ring_exec",
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
            stop_file_ms=1000,
        )
        me.run()
        self.assertEqual(me.execs, ["/tmp_network/.m7-s6-abcdef012345/ring.elf"])

    def test_04_daemon_disarm_fault_latch_and_never_sigkills_ring(self):
        # Case A: Gate drops mid-run -> daemon writes disarm file
        def scen_disarm(m, t):
            m.bk_val, m.file_fmt, m.sub_enabled = 0, 0xBD, 1
            m.half, m.full = (1, 0) if t >= 150 else (0, 0)
            m.drive_act = 0x5E if t >= 450 else 0x5F  # switch to Single mid-hold

        def hang_until_disarm(m, _seq, _cfg):
            m.active_ring_exit_ms = m.clock_ms + 5000
            m.active_ring_exit_status = 0

        md = DaemonV2Machine(self.daemon_img, self.manifest, scenario=scen_disarm, ring_script=hang_until_disarm, stop_file_ms=1000)
        md.run()
        pd = runner.parse_daemon_log(md.stdout_buf.decode("ascii"))
        self.assertTrue(any(e["ev"] == "DISARM_GATE" for e in pd["ring_events"]))
        self.assertEqual(pd["stop"]["r_reap"], "1")

        # Case B: ring.elf emits retain_unresolved (kind=13 stage=98) and hangs -> daemon MUST NOT SIGKILL ring_pid!
        def unres_script(m, _seq, cfg):
            tok = struct.unpack_from("<I", cfg, 28 + 8)[0]
            m.ring_pipe_bytes.extend(fmt_m7cap(tok, 13, 19, 50, 98, 218, 17, 446))
            m.active_ring_hang = True

        mu = DaemonV2Machine(
            self.daemon_img, self.manifest,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
            ring_script=unres_script, stop_file_ms=450,
        )
        mu.run()
        pu = runner.parse_daemon_log(mu.stdout_buf.decode("ascii"))
        self.assertEqual(pu["ring_unresolved_count"], 1)
        self.assertEqual(pu["stop"]["r_reap"], "0")
        self.assertEqual(pu["stop"]["r_flt"], "1")
        self.assertEqual(pu["stop"]["r_unres"], "1")
        # Crucial safety check: NEVER SIGKILL ring_pid (1400)!
        self.assertFalse(any(pid == 1400 and sig == 9 for pid, sig in mu.kills_sent))

        # Case C: Nonzero ring exit (rc=8) latches ring_fault=1 and blocks retries!
        def fail_script(m, _seq, _cfg):
            m.active_ring_exit_ms = m.clock_ms + 20
            m.active_ring_exit_status = 8 << 8

        def scen_retry(m, t):
            m.half = 1 if (150 <= t < 400 or 1200 <= t < 1600) else 0

        mf = DaemonV2Machine(self.daemon_img, self.manifest, scenario=scen_retry, ring_script=fail_script, stop_file_ms=2000)
        mf.run()
        self.assertEqual(len(mf.ring_launches), 1)  # 2nd press refused due to latched fault!
        pf = runner.parse_daemon_log(mf.stdout_buf.decode("ascii"))
        self.assertEqual(pf["stop"]["r_flt"], "1")
        self.assertEqual(pf["stop"]["r_ok"], "0")

    def _make_valid_ring_cfg(self, nonce="abcdef012345"):
        # Produce an exact run.cfg binary from stage6_daemon.elf itself!
        def one_shot(m, t):
            m.half = 1 if t >= 150 else 0
        m = DaemonV2Machine(self.daemon_img, self.manifest, nonce=nonce, scenario=one_shot, stop_file_ms=600)
        m.run()
        self.assertGreaterEqual(len(m.ring_launches), 1)
        raw = m.ring_launches[0]["cfg"]
        # Add HEAP2 range (0x02100000..0x02120000) to run.cfg for RingV2Machine stacks and recompute checksum
        buf = bytearray(raw)
        nr = struct.unpack_from("<I", buf, 28 + 20)[0]
        struct.pack_into("<I", buf, 28 + 20, nr + 1)
        struct.pack_into("<2I", buf, 28 + 60 + nr * 8, 0x02100000, 0x02120000)
        h = 0x811C9DC5
        for b in buf[16:]:
            h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
        struct.pack_into("<I", buf, 12, h)
        return bytes(buf)

    def test_05_ring_arm_relro_cfg_load_and_pre_mutation_aborts(self):
        cfg = self._make_valid_ring_cfg()

        # 1. Corrupt checksum -> exit 2 before mprotect or /proc/161/mem
        mbad = RingV2Machine(self.ring_img, self.manifest, cfg, corrupt_cfg=True)
        mbad.run()
        self.assertEqual(mbad.exit_code, 2)
        self.assertEqual(mbad.mprotect_calls, [])
        self.assertEqual(mbad.ptrace_calls, [])

        # 2. Early release (half=0) -> RELRO mprotect called, ZERO ptrace, clean exit 0!
        mrel = RingV2Machine(self.ring_img, self.manifest, cfg, half_init=0)
        mrel.run()
        self.assertEqual(mrel.exit_code, 0)
        self.assertEqual(len(mrel.mprotect_calls), 1)
        self.assertEqual(mrel.mprotect_calls[0], (self.manifest["ring"]["rw_vaddr"], self.manifest["ring"]["rw_memsz"], 1))
        self.assertEqual(mrel.ptrace_calls, [])

        # 3. Orphaned parent (ppid==1) -> clean abort, ZERO ptrace, exit 0!
        morph = RingV2Machine(self.ring_img, self.manifest, cfg, ppid=1)
        morph.run()
        self.assertEqual(morph.exit_code, 0)
        self.assertEqual(morph.ptrace_calls, [])

        # 4. Bad Sony code pin -> hard fault exit 8, ZERO ptrace!
        mpin = RingV2Machine(self.ring_img, self.manifest, cfg, bad_code_pin=True)
        mpin.run()
        self.assertEqual(mpin.exit_code, 8)
        self.assertEqual(mpin.ptrace_calls, [])

    def test_06_ring_full_arm_zero_gap_abort_and_armed_disarm_cancel(self):
        cfg = self._make_valid_ring_cfg()

        # 1. Disarm arrives during mode_set(0x4100) -> zero-gap abort while connect_pair(3) held!
        #    Must restore mode_set(0x1000) + Pullout4100, ZERO POKETEXT traps, exit 0!
        m1 = RingV2Machine(self.ring_img, self.manifest, cfg, abort_after_mode_set=True)
        m1.run()
        self.assertEqual(m1.exit_code, 0)
        self.assertEqual(m1.poketext_log, [])  # 0xde01 trap NEVER installed!
        self.assertFalse(m1.inserted_4100)     # Pullout4100 restored SD!
        self.assertFalse(m1.mode_4100)         # mode_set(0x1000) restored SD!
        self.assertEqual(m1.traced, {})        # All tracees detached!

        # 2. Full arming -> 0xde01 trap installed -> PRECAP_ARMED -> disarm arrives while half=1 ->
        #    clean cancel (reason=4) -> PRECAP_DRAIN -> trap restored -> detached -> mode_set(0x1000) -> Pullout4100 -> exit 0!
        m2 = RingV2Machine(self.ring_img, self.manifest, cfg, disarm_in_armed=True)
        m2.run()
        self.assertEqual(m2.exit_code, 0)
        self.assertEqual(len(m2.poketext_log), 2)
        self.assertEqual(m2.poketext_log[0][0], m2.LIBOBJ + 0xA14C98)
        self.assertEqual(m2.poketext_log[1], (m2.LIBOBJ + 0xA14C98, 0x531EF240))  # Exact original word restored!
        self.assertFalse(m2.inserted_4100)
        self.assertFalse(m2.mode_4100)
        self.assertEqual(m2.traced, {})
        # Verify daemon's log parser understands ring.elf's actual M7CAP1 output cleanly!
        out_lines = m2.stdout_buf.decode("ascii").splitlines()
        self.assertTrue(any(l.startswith("M7CAP1=") for l in out_lines))
        # Verify ZERO WriteFile (op 10 = libmpr + 0x19e664) calls during cancel!
        self.assertFalse(any(pc == m2.LIBMPR + 0x19E664 for pc, *_ in m2.sony_ops))

    def test_07_host_v2_runner_dual_elf_upload_custody_and_card_check(self):
        # 1. BusyBox --list rc 127 + help fallback enables gzip+octal, all frames < 512 B!
        cmds = []
        class UploadSess:
            def __init__(self):
                self.receipt = dict(nonce="abcdef012345", commands=[])
                self.files = {}
            def command(self, cmd, allowed=(0,), timeout=12):
                wire, _, _ = frame(cmd, len(self.receipt["commands"]), self.receipt["nonce"])
                assert len(wire) < 512, f"Frame >= 512 B: {len(wire)}"
                self.receipt["commands"].append(cmd)
                cmds.append(cmd)
                if cmd == "/bin/busybox --list":
                    return b"busybox: applet not found\n", 127
                if cmd == "/bin/busybox":
                    return b"BusyBox v1.20.2\nCurrently defined functions:\n\techo, gunzip, md5sum, rm\n", 0
                if "echo -ne '" in cmd:
                    # Decode exact BusyBox echo -ne '...' mixed-octal payload and reconstruct remote file!
                    inner = cmd.split("echo -ne '", 1)[1].rsplit("'", 1)[0]
                    dest = cmd.rsplit(" ", 1)[1]
                    append = ">>" in cmd
                    buf = bytearray()
                    i = 0
                    while i < len(inner):
                        if inner[i] == "\\":
                            assert inner[i + 1] == "0", f"Expected \\0NNN at {i}"
                            buf.append(int(inner[i + 2:i + 5], 8))
                            i += 5
                        else:
                            buf.append(ord(inner[i]))
                            i += 1
                    self.files[dest] = (self.files.get(dest, b"") if append else b"") + bytes(buf)
                    return b"", 0
                if "gunzip -c " in cmd:
                    import gzip
                    parts = cmd.split()
                    self.files[parts[5]] = gzip.decompress(self.files[parts[3]])
                    return b"", 0
                if "rm -f " in cmd:
                    self.files.pop(cmd.split()[-1], None)
                    return b"", 0
                if cmd.startswith("/bin/busybox md5sum "):
                    path = cmd.split()[-1]
                    return (hashlib.md5(self.files[path]).hexdigest() + "  " + path + "\n").encode("ascii"), 0
                raise AssertionError(cmd)

        sess = UploadSess()
        sess.daemon_data = builder.configure_daemon(self.daemon_img, self.manifest, nonce="abcdef012345")
        sess.ring_data = builder.configure_ring(self.ring_img, self.manifest, nonce="abcdef012345")
        applets, src = runner.detect_busybox_applets(sess)
        self.assertEqual(src, "busybox-help")
        self.assertIn("gunzip", applets)
        runner.upload_elf(sess, sess.ring_data, "/tmp_network/.m7-s6-abcdef012345/ring.elf", applets, "ring")
        runner.upload_elf(sess, sess.daemon_data, "/tmp_network/.m7-s6-abcdef012345/daemon.elf", applets, "daemon")
        self.assertEqual(sess.files["/tmp_network/.m7-s6-abcdef012345/ring.elf"], sess.ring_data)
        self.assertEqual(sess.files["/tmp_network/.m7-s6-abcdef012345/daemon.elf"], sess.daemon_data)
        self.assertEqual(len(sess.receipt["uploads"]), 2)
        self.assertEqual(sess.receipt["uploads"][0]["compression"], "gzip")
        self.assertEqual(sess.receipt["uploads"][0]["encoding"], "mixed-octal")
        self.assertLess(sess.receipt["uploads"][0]["chunks"], 850)
        self.assertEqual(sess.receipt["uploads"][1]["compression"], "gzip")
        self.assertLess(sess.receipt["uploads"][0]["transfer_bytes"], len(sess.ring_data) * 65 // 100)
        # Mixed-octal safety: '-' must NEVER appear raw (prevents BusyBox echo -ne '-n'/'-e' option parsing),
        # and octal digits '0'..'7' immediately after an escape must be escaped!
        enc_edge = runner.encode_echo_mixed(b"-ne-E\x000123456789'\\abc")
        self.assertNotIn("-", enc_edge)
        self.assertNotIn("'", enc_edge)
        self.assertIn("\\0000\\0060\\0061", enc_edge)
        self.assertTrue(enc_edge.endswith("89\\0047\\0134abc"))

        # 2. Dual-ELF stop check never emits kill and scans both daemon.elf and ring.elf
        stop_cmds = []
        class DualStopSess:
            def command(self, cmd, allowed=(0,)):
                stop_cmds.append(cmd)
                if "echo DIR_OK" in cmd:
                    return b"DIR_OK\n", 0
                if "echo stop >" in cmd or "sleep 1" in cmd:
                    return b"", 0
                if "for p in /proc/[1-9]*" in cmd:
                    return b"", 0
                if "readlink" in cmd or "/stat" in cmd or "/status" in cmd:
                    return b"", 1
                raise AssertionError(cmd)

        stopped, rem_d, rem_r = runner.request_stop_via_file(
            DualStopSess(),
            "/tmp_network/.m7-s6-abcdef012345",
            "/tmp_network/.m7-s6-abcdef012345/daemon.elf",
            "/tmp_network/.m7-s6-abcdef012345/ring.elf",
            expected_pid=999,
            expected_starttime=555,
            max_polls=3,
        )
        self.assertTrue(stopped)
        self.assertEqual((rem_d, rem_r), ([], []))
        self.assertFalse(any("kill" in c for c in stop_cmds))
        self.assertTrue(any("daemon.elf" in c for c in stop_cmds))
        self.assertTrue(any("ring.elf" in c for c in stop_cmds))

        # 3. Card readback check (read-only) passes valid 5472x3648 PC*.JPG and fails corrupt/wrong-size
        with tempfile.TemporaryDirectory(prefix="s6v2-card-") as card_tmp:
            card = Path(card_tmp)
            good_jpg = make_minimal_jpeg(5472, 3648)
            (card / "PC812345.JPG").write_bytes(good_jpg)
            ok_res = runner.verify_card_saved_files(
                card, [dict(file="PC812345.JPG", bytes=str(len(good_jpg)), status="13")]
            )
            self.assertTrue(ok_res["all_ok"])

            bad_res = runner.verify_card_saved_files(
                card, [dict(file="PC812345.JPG", bytes=str(len(good_jpg) + 1), status="13")]
            )
            self.assertFalse(bad_res["all_ok"])

        # 4. Initial witness verifier checks ring_ok=1, pre/post, bk_on, and rejects bad STATE
        good_sum = runner.parse_daemon_log(
            "BOOT self_pid=999 im_pid=161 mon_proc=170 mon_mwf=170 uipc_ok=1 bk_sz=1 bk_on=0 in_ok=1 ring_ok=1 pre=2 post=1\n"
            "STATE t=0 cam=1 bk_ok=1 bk=0x0 bk_rc=0 sub_ok=1 sub_en=0 half_ok=1 half=0x0 full_ok=1 full=0x0\n"
        )
        runner.verify_usable_initial_witnesses(good_sum, 999, 161, 2, 1, 0)
        bad_ring = runner.parse_daemon_log(
            "BOOT self_pid=999 im_pid=161 mon_proc=170 mon_mwf=170 uipc_ok=1 bk_sz=1 bk_on=0 in_ok=1 ring_ok=0 pre=2 post=1\n"
            "STATE t=0 cam=1 bk_ok=1 bk=0x0 bk_rc=0 sub_ok=1 sub_en=0 half_ok=1 half=0x0 full_ok=1 full=0x0\n"
        )
        with self.assertRaises(usb.ProbeError):
            runner.verify_usable_initial_witnesses(bad_ring, 999, 161, 2, 1, 0)

    def test_08_end_to_end_do_start_and_do_collect_custody_fixtures(self):
        class MockCam:
            def __init__(self):
                self.enables = []
                self.dev = type("D", (), {"poisoned": False})()
            def setTerminalEnable(self, flag):
                self.enables.append(flag)

        def make_preflight_replies(*, im_present=True):
            return [
                b"",
                b"29110_03.2021050601\n",
                (b"/dev/root / ext2 ro 0 0\n"
                 b"/dev/nflasha7 /usr ext2 ro,relatime 0 0\n"
                 b"proc /proc proc rw 0 0\n"
                 b"tmpfs /tmp_network tmpfs rw,size=1024k 0 0\n"),
                (b"drwxrwxrwt 2 0 0 40 Jan 1 00:00 /tmp_network\n"
                 b"dr-xr-xr-x 2 0 0 0 Jan 1 00:00 /proc\n"
                 b"drwxr-xr-x 2 0 0 40 Jan 1 00:00 /usr\n"
                 b"drwxr-xr-x 2 0 0 40 Jan 1 00:00 /usr/lib\n"
                 b"-rwxr-xr-x 1 0 0 21089716 Jan 1 00:00 /usr/lib/libObj.so\n"
                 b"drwxr-xr-x 2 0 0 40 Jan 1 00:00 /usr/bin\n"
                 b"-rwxr-xr-x 1 0 0 100 Jan 1 00:00 /usr/bin/im.elf\n"),
                b"BusyBox v1.20.2\nCurrently defined functions:\n echo, gunzip, md5sum, mkdir, rmdir, rm, chmod, test, pidof, readlink, wc\n",
                b"M7_OCTAL_OK\n",
                (b"161\n", 0) if im_present else (b"", 1),
                b"21089716 /usr/lib/libObj.so\n",
                b"99a06d3852bf744a5d454bd873f6d35c  /usr/lib/libObj.so\n",
            ]

        orig_read_ready = runner.read_ready
        orig_sess_cls = runner.Stage6Session
        nonce = "feedface1234"
        remote_dir = f"/tmp_network/.m7-s6-{nonce}"
        remote_daemon = remote_dir + "/daemon.elf"
        remote_ring = remote_dir + "/ring.elf"
        remote_log = remote_dir + "/daemon.log"
        valid_log = (
            "BOOT self_pid=999 w_pid=1001 im_pid=161 im_st=105 libobj=0x5ecd000 mwf=0x4460000 "
            "mpr=0x7400000 mprctrl=0x44a8000 uipc=0x4053000 ranges=235 mon_proc=170 mon_mwf=170 "
            "csp_ptr_ok=1 uipc_ok=1 uipc_err=0 bk_id=0x1071472 bk_on=0 bk_sz=1 bk_rc=0 in_ok=1 ih=27 if=14 ring_ok=1 pre=2 post=1 deb=100\n"
            "STATE t=10 cam=1 drive=0x5f size=0xb3 asp=0xb9 qual=0xbc fmt=0xbd bk_ok=1 bk=0x0 bk_rc=0 "
            "sub_ok=1 sub_en=1 half_ok=1 half=0x0 full_ok=1 full=0x0 elig=1 tog=1 gate=1 r_act=0\n"
            "STOP t=5000 trig_t=4950 reason=stop_file detail=0 ticks=100 rerr=0 ferr=0 uipc_dis=0 uipc_ferr=0 "
            "uipc_to=0 w_reap=1 r_reap=1 r_runs=1 r_ok=1 r_sav=3 r_flt=0 r_unres=0 trunc=0\n"
        )
        try:
            runner.read_ready = lambda _cam: b"/usr/share/app # "

            # Scenario A: Interrupted upload leaves pending_upload custody; --collect recovers it cleanly.
            with tempfile.TemporaryDirectory(prefix="s6v2-e2e-a-") as td:
                td_p = Path(td)
                active_p = td_p / ".active-stage6-v2.json"
                seen_cmds = []

                class FailUploadSess:
                    def __init__(self, _cam, rec):
                        self.receipt = rec
                        self.pf = list(make_preflight_replies())
                        self.upload_chunks = 0
                    def command(self, cmd, allowed=(0,), timeout=12):
                        seen_cmds.append(cmd)
                        self.receipt["commands"].append(cmd)
                        if self.pf:
                            r = self.pf.pop(0)
                            return r if isinstance(r, tuple) else (r, 0)
                        if "for d in /tmp_network/.m7-s6-*" in cmd:
                            return b"", 0
                        if cmd == "/bin/busybox --list":
                            return b"", 127
                        if cmd == "/bin/busybox":
                            return b"BusyBox v1.20.2\nCurrently defined functions:\n echo, gunzip, md5sum, rm\n", 0
                        if cmd.startswith("/bin/busybox mkdir ") or cmd.startswith("/bin/busybox chmod "):
                            return b"", 0
                        if "echo DIR_OK" in cmd:
                            return b"DIR_OK\n", 0
                        if "echo -ne '" in cmd:
                            self.upload_chunks += 1
                            if self.upload_chunks == 2:
                                raise usb.ProbeError("simulated USB unplug mid-upload")
                            return b"", 0
                        raise AssertionError(f"Unexpected start cmd: {cmd}")

                runner.Stage6Session = FailUploadSess
                cam = MockCam()
                rec = dict(utc="20261121T000000Z", nonce=nonce, model="DSC-RX100M7", daemon_sha256="aa", ring_sha256="bb", commands=[], steps=[])
                d_img = builder.configure_daemon(self.daemon_img, self.manifest, nonce=nonce)
                r_img = builder.configure_ring(self.ring_img, self.manifest, nonce=nonce)
                with self.assertRaises(usb.ProbeError):
                    runner.do_start(cam, rec, d_img, r_img, before=2, after=1, toggle_on_val=0, active_path=active_p)
                self.assertTrue(active_p.is_file())
                self.assertEqual(json.loads(active_p.read_text())["status"], "pending_upload")
                self.assertTrue(rec.get("terminal_disable_requested"))

                # Now --collect recovers pending_upload with LOG_ABSENT and deletes remote dir!
                class RecoverSess:
                    def __init__(self, _cam, rec2):
                        self.receipt = rec2
                        self.pf = list(make_preflight_replies())
                        self.removed = False
                    def command(self, cmd, allowed=(0,), timeout=12):
                        self.receipt["commands"].append(cmd)
                        if self.pf:
                            r = self.pf.pop(0)
                            return r if isinstance(r, tuple) else (r, 0)
                        if "echo DIR_OK" in cmd:
                            return (b"DIR_GONE\n" if self.removed else b"DIR_OK\n"), 0
                        if "for p in /proc/[1-9]*" in cmd:
                            return b"", 0
                        if "daemon.pid" in cmd:
                            return b"", 0
                        if "echo LOG_OK" in cmd:
                            return b"LOG_ABSENT\n", 0
                        if cmd == f"/bin/busybox rm -rf {remote_dir}":
                            self.removed = True
                            return b"", 0
                        if "echo PRESENT" in cmd:
                            return b"GONE\n", 0
                        raise AssertionError(f"Unexpected collect cmd: {cmd}")

                runner.Stage6Session = RecoverSess
                rec2 = dict(utc="20261121T000100Z", nonce="1234567890ab", model="DSC-RX100M7", commands=[], steps=[])
                runner.do_collect(MockCam(), rec2, active_path=active_p, log_out_dir=td_p)
                rec2["service_stop_requested"] = True
                rec2["teardown_requested_clean"] = runner.teardown_clean(rec2)
                self.assertEqual(rec2["collect_outcome"], "prelaunch_recovered")
                self.assertTrue(runner.evaluate_cli_success("collect", rec2))
                self.assertFalse(active_p.exists())

            # Scenario B: Live ring.elf stays alive after stop -> MUST NOT rm -rf, MUST persist log, MUST retain custody!
            with tempfile.TemporaryDirectory(prefix="s6v2-e2e-b-") as td:
                td_p = Path(td)
                active_p = td_p / ".active-stage6-v2.json"
                runner.write_active_state_exclusive(dict(
                    status="running", nonce=nonce, directory=remote_dir,
                    daemon_pid=999, daemon_starttime=555,
                    daemon_exe=remote_daemon, ring_exe=remote_ring,
                    daemon_sha256="aa", ring_sha256="bb",
                ), active_p)
                rm_called = []

                class LiveRingSess:
                    def __init__(self, _cam, rec):
                        self.receipt = rec
                        self.pf = list(make_preflight_replies())
                    def command(self, cmd, allowed=(0,), timeout=12):
                        self.receipt["commands"].append(cmd)
                        if self.pf:
                            r = self.pf.pop(0)
                            return r if isinstance(r, tuple) else (r, 0)
                        if "echo DIR_OK" in cmd:
                            return b"DIR_OK\n", 0
                        if "for p in /proc/[1-9]*" in cmd:
                            if "ring.elf" in cmd:
                                return b"/proc/1400\n", 0  # ring.elf STILL ALIVE (e.g. unresolved trap)!
                            return b"", 0
                        if "daemon.pid" in cmd or "readlink /proc/999" in cmd or "/proc/999/" in cmd:
                            return b"", 1
                        if "echo stop >" in cmd or "sleep 1" in cmd:
                            return b"", 0
                        if "echo LOG_OK" in cmd:
                            return b"LOG_OK\n", 0
                        if cmd == f"/bin/busybox cat {remote_log}":
                            return valid_log.encode("ascii"), 0
                        if "rm -rf" in cmd:
                            rm_called.append(cmd)
                            return b"", 0
                        raise AssertionError(f"Unexpected cmd: {cmd}")

                runner.Stage6Session = LiveRingSess
                orig_stop = runner.request_stop_via_file
                runner.request_stop_via_file = lambda *a, **kw: orig_stop(*a, max_polls=2, **kw)
                try:
                    rec_b = dict(utc="20261121T000200Z", nonce="aabbccddeeff", model="DSC-RX100M7", commands=[], steps=[])
                    runner.do_collect(MockCam(), rec_b, active_path=active_p, log_out_dir=td_p)
                finally:
                    runner.request_stop_via_file = orig_stop
                self.assertEqual(rm_called, [])
                self.assertEqual(rec_b["cleanup"], "DEFERRED_PROCESS_STILL_ALIVE")
                self.assertEqual(rec_b["collect_outcome"], "incomplete")
                self.assertEqual(rec_b["live_ring_pids_after_stop"], [1400])
                self.assertTrue(rec_b["log_persisted"])
                self.assertTrue(Path(rec_b["saved_log_path"]).is_file())
                self.assertTrue(active_p.is_file())  # Custody preserved!
                self.assertFalse(runner.evaluate_cli_success("collect", rec_b))

            # Scenario C: Normal collect persists daemon.log durably BEFORE rm -rf!
            with tempfile.TemporaryDirectory(prefix="s6v2-e2e-c-") as td:
                td_p = Path(td)
                active_p = td_p / ".active-stage6-v2.json"
                runner.write_active_state_exclusive(dict(
                    status="running", nonce=nonce, directory=remote_dir,
                    daemon_pid=999, daemon_starttime=555,
                    daemon_exe=remote_daemon, ring_exe=remote_ring,
                    daemon_sha256="aa", ring_sha256="bb",
                ), active_p)
                order = []

                class CleanCollectSess:
                    def __init__(self, _cam, rec):
                        self.receipt = rec
                        self.pf = list(make_preflight_replies(im_present=False))
                    def command(self, cmd, allowed=(0,), timeout=12):
                        self.receipt["commands"].append(cmd)
                        if self.pf:
                            r = self.pf.pop(0)
                            return r if isinstance(r, tuple) else (r, 0)
                        if "echo DIR_OK" in cmd:
                            return b"DIR_OK\n", 0
                        if "for p in /proc/[1-9]*" in cmd:
                            return b"", 0
                        if "daemon.pid" in cmd or "/proc/999/" in cmd:
                            return b"", 1
                        if "echo LOG_OK" in cmd:
                            return b"LOG_OK\n", 0
                        if cmd == f"/bin/busybox cat {remote_log}":
                            return valid_log.encode("ascii"), 0
                        if cmd == f"/bin/busybox rm -rf {remote_dir}":
                            # Log file MUST ALREADY EXIST on host before rm -rf runs!
                            saved = list(td_p.glob("*-daemon.log"))
                            assert len(saved) == 1 and "BOOT " in saved[0].read_text()
                            order.append("rm_after_persist")
                            return b"", 0
                        if "echo PRESENT" in cmd:
                            return b"GONE\n", 0
                        raise AssertionError(f"Unexpected cmd: {cmd}")

                runner.Stage6Session = CleanCollectSess
                rec_c = dict(utc="20261121T000300Z", nonce="112233445566", model="DSC-RX100M7", commands=[], steps=[])
                runner.do_collect(MockCam(), rec_c, active_path=active_p, log_out_dir=td_p)
                rec_c["service_stop_requested"] = True
                rec_c["teardown_requested_clean"] = runner.teardown_clean(rec_c)
                self.assertEqual(order, ["rm_after_persist"])
                self.assertEqual(rec_c["collect_outcome"], "collected")
                self.assertTrue(runner.evaluate_cli_success("collect", rec_c))
                self.assertFalse(active_p.exists())
        finally:
            runner.read_ready = orig_read_ready
            runner.Stage6Session = orig_sess_cls

    def test_09_regression_blockers_b2_b3_b4_b5_b6_and_signal_safety(self):
        cfg = self._make_valid_ring_cfg()

        # B2: Single transient -EIO on INPUT_STATE during armed disarm recovers via fresh live read -> clean SD restore!
        mb2 = RingV2Machine(self.ring_img, self.manifest, cfg, disarm_in_armed=True, inject_input_eio_in_armed=True)
        mb2.run()
        self.assertTrue(mb2.input_eio_fired)
        self.assertEqual(mb2.exit_code, 0)
        self.assertEqual(len(mb2.poketext_log), 2)
        self.assertEqual(mb2.poketext_log[1], (mb2.LIBOBJ + 0xA14C98, 0x531EF240))
        self.assertFalse(mb2.inserted_4100)
        self.assertFalse(mb2.mode_4100)
        self.assertEqual(mb2.traced, {})
        lines_b2 = [
            [int(raw[j:j + 8], 16) for j in range(7, 103, 8)]
            for raw in mb2.stdout_buf.splitlines() if raw.startswith(b"M7CAP1=")
        ]
        self.assertFalse(any(row[1] == 13 and row[4] == 98 for row in lines_b2))

        # B3: Pending Backup_read (uipc_inflight) returning OFF must block launch on cached ON!
        class PendingOffDaemon(DaemonV2Machine):
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                if nr == 3 and r0 in self.fds and self.fds[r0]["kind"] == "rep_r" and 5200 <= self.clock_ms < 5500:
                    cpu.reg_write(a.UC_ARM_REG_R0, (-11) & 0xFFFFFFFF)  # Delay OFF reply until t=500ms
                    return
                return super().on_syscall(cpu, _intno, _user)

        def scen_b3(m, t):
            m.half = 1 if t >= 150 else 0
            if t >= 200:
                m.bk_val = 1  # Switched OFF while request pending!

        mb3 = PendingOffDaemon(
            self.daemon_img, self.manifest,
            scenario=scen_b3,
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 300),
            stop_file_ms=950,
        )
        mb3.run()
        self.assertEqual(len(mb3.ring_launches), 0)

        # B4: Failed disarm file creation (-ENOSPC) MUST NOT set ring_disarm_sent and MUST retry until success!
        class EnospcDisarmDaemon(DaemonV2Machine):
            attempts = 0
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                r1 = cpu.reg_read(a.UC_ARM_REG_R1)
                if nr == 5 and (r1 & 0x40) and self.read_cstr(r0).endswith("/disarm"):
                    self.attempts += 1
                    if self.attempts <= 3:
                        cpu.reg_write(a.UC_ARM_REG_R0, (-28) & 0xFFFFFFFF)  # -ENOSPC
                        return
                return super().on_syscall(cpu, _intno, _user)

        def scen_b4(m, t):
            m.half = 1 if t >= 150 else 0
            m.drive_act = 0x5E if t >= 410 else 0x5F

        mb4 = EnospcDisarmDaemon(
            self.daemon_img, self.manifest,
            scenario=scen_b4,
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 2000),
            stop_file_ms=1000,
        )
        mb4.run()
        self.assertGreaterEqual(mb4.attempts, 4)
        pb4 = runner.parse_daemon_log(mb4.stdout_buf.decode("ascii"))
        self.assertTrue(any(e["ev"] == "DISARM_ERR" and e["b"] == "28" for e in pb4["ring_events"]))
        self.assertTrue(any(e["ev"] == "DISARM_GATE" for e in pb4["ring_events"]))
        self.assertEqual(pb4["stop"]["r_reap"], "1")

        # Invalid shutter (0xffffffff) during active capture drops gate and triggers DISARM_GATE!
        def scen_inv(m, t):
            m.half = 0xFFFFFFFF if t >= 410 else (1 if t >= 150 else 0)

        minv = DaemonV2Machine(
            self.daemon_img, self.manifest,
            scenario=scen_inv,
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 2000),
            stop_file_ms=1000,
        )
        minv.run()
        pinv = runner.parse_daemon_log(minv.stdout_buf.decode("ascii"))
        self.assertTrue(any(e["ev"] == "DISARM_GATE" for e in pinv["ring_events"]))
        self.assertFalse(any(s.get("half_ok") == "1" and s.get("half") == "0xffffffff" for s in pinv["states"]))

        # B5: Simultaneous full press + /disarm on same sample cancels cleanly (NEVER enters PRECAP_POST)!
        mb5 = RingV2Machine(self.ring_img, self.manifest, cfg, full_with_disarm_in_armed=True)
        mb5.run()
        self.assertEqual(mb5.exit_code, 0)
        self.assertFalse(mb5.inserted_4100)
        self.assertFalse(mb5.mode_4100)
        self.assertEqual(mb5.traced, {})
        lines_b5 = [
            [int(raw[j:j + 8], 16) for j in range(7, 103, 8)]
            for raw in mb5.stdout_buf.splitlines() if raw.startswith(b"M7CAP1=")
        ]
        # No PRECAP_POST (next==2) transition and no WriteFile calls!
        self.assertFalse(any(row[1] == 92 and row[4] == 55 and row[6] == 2 for row in lines_b5))
        self.assertFalse(any(pc == mb5.LIBMPR + 0x19E664 for pc, *_ in mb5.sony_ops))

        # B6: Latched Spinal S2 == 1 at exit MUST fail with rc == 7 (NOT 0)!
        mb6 = RingV2Machine(self.ring_img, self.manifest, cfg, disarm_in_armed=True, latch_spinal_s2_at_exit=True)
        mb6.run()
        self.assertEqual(mb6.exit_code, 7)

        # Group SIGTERM blocked by stage6_ring.elf and converted into clean cancel + SD restore!
        msig = RingV2Machine(self.ring_img, self.manifest, cfg, sigterm_in_armed=True)
        msig.run()
        self.assertEqual(msig.exit_code, 0)
        self.assertTrue(any(how == 0 and (mask[0] & ((1 << 1) | (1 << 14))) == ((1 << 1) | (1 << 14))
                            for how, mask in msig.sigprocmask_calls))
        self.assertEqual(len(msig.poketext_log), 2)
        self.assertEqual(msig.poketext_log[1], (msig.LIBOBJ + 0xA14C98, 0x531EF240))
        self.assertFalse(msig.inserted_4100)
        self.assertFalse(msig.mode_4100)
        self.assertEqual(msig.traced, {})

    def test_10_public_cli_wrapper_uses_usb_connect_b1_and_card_empty_check(self):
        # B1: Exercise public CLI runner.main for --start and --collect via usb.connect (zero hardware access)!
        with tempfile.TemporaryDirectory(prefix="s6v2-cli-") as td:
            td_p = Path(td)
            active_p = td_p / ".active-stage6-v2.json"
            connect_calls = []

            class FakeDev:
                poisoned = False
            class FakeCam:
                dev = FakeDev()
                def setTerminalEnable(self, enabled):
                    pass

            def fake_connect(receipt, diagnostic=None, gate_factory=None, **kw):
                self.assertIs(gate_factory, runner.Stage6Gate)
                receipt["model"] = "DSC-RX100M7"
                connect_calls.append(receipt["action"])
                diagnostic(FakeCam(), receipt)
                receipt["service_stop_requested"] = True

            def fake_do_start(cam, rec, d_img, r_img, **kw):
                self.assertEqual(rec["model"], "DSC-RX100M7")
                self.assertGreater(len(d_img), 10000)
                self.assertGreater(len(r_img), 50000)
                n = rec["nonce"]
                d = "/tmp_network/.m7-s6-" + n
                runner.write_active_state_exclusive(dict(
                    status="running", nonce=n, directory=d,
                    daemon_pid=999, daemon_starttime=555,
                    daemon_exe=d + "/daemon.elf", ring_exe=d + "/ring.elf",
                ), kw["active_path"])
                rec["terminal_disable_requested"] = True
                rec["start_ready"] = True

            def fake_do_collect(cam, rec, **kw):
                self.assertEqual(rec["model"], "DSC-RX100M7")
                kw["active_path"].unlink()
                rec["terminal_disable_requested"] = True
                rec["stopped_cleanly"] = True
                rec["active_state_cleared"] = True
                rec["collect_outcome"] = "collected"
                rec["cleanup"] = "GONE"
                rec["log_retrieved"] = True
                rec["log_persisted"] = True
                rec["saved_log_path"] = str(td_p / "fake.log")

            orig_out, orig_active = runner.OUT_DIR, runner.ACTIVE_STATE
            orig_connect = runner.usb.connect
            orig_start, orig_collect = runner.do_start, runner.do_collect
            try:
                runner.OUT_DIR = td_p
                runner.ACTIVE_STATE = active_p
                runner.usb.connect = fake_connect
                runner.do_start = fake_do_start
                runner.do_collect = fake_do_collect

                self.assertEqual(runner.main(["--start", "--duration-sec", "120"]), 0)
                self.assertTrue(active_p.is_file())
                self.assertEqual(runner.main(["--collect"]), 0)
                self.assertFalse(active_p.exists())
                self.assertEqual(connect_calls, ["start", "collect"])
            finally:
                runner.OUT_DIR = orig_out
                runner.ACTIVE_STATE = orig_active
                runner.usb.connect = orig_connect
                runner.do_start = orig_start
                runner.do_collect = orig_collect

            # Empty card check must fail by default in --check-card-only and pass only with --allow-empty!
            empty_log = td_p / "empty-daemon.log"
            empty_log.write_text("BOOT self_pid=999 im_pid=161\nSTOP reason=stop_file\n", encoding="utf-8")
            self.assertEqual(runner.main(["--check-card-only", "--card", str(td_p), "--log", str(empty_log)]), 1)
            self.assertEqual(
                runner.main(["--check-card-only", "--card", str(td_p), "--log", str(empty_log), "--allow-empty"]),
                0,
            )

    def test_11_regression_r2_prepare_off_disarm_retry_and_failed_start_custody(self):
        # 1. B3 (prepare_off + delayed reply + launch-boundary timestamp):
        #    Toggle flips OFF during run.cfg rename (+600 ms stall) -> MUST NOT launch!
        for delayed_reply in (False, True):
            class PrepOffDaemon(DaemonV2Machine):
                dropped = False
                def on_syscall(self, cpu, _intno, _user):
                    a = self.arm
                    nr = cpu.reg_read(a.UC_ARM_REG_R7)
                    fd = cpu.reg_read(a.UC_ARM_REG_R0)
                    t = self.clock_ms - 5000
                    if nr == 38 and not self.dropped:  # SYS_RENAME (run.cfg)
                        self.dropped = True
                        self.bk_val = 1  # Switched OFF during slow preparation!
                        self.clock_ms += 600
                    if delayed_reply and nr == 3 and self.fds.get(fd, {}).get("kind") == "rep_r" and 850 <= t < 1100:
                        cpu.reg_write(a.UC_ARM_REG_R0, (-11) & 0xFFFFFFFF)
                        return
                    return super().on_syscall(cpu, _intno, _user)

            mp = PrepOffDaemon(
                self.daemon_img, self.manifest, duration_ms=30000,
                scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
                ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 300),
                stop_file_ms=1500,
            )
            mp.run()
            self.assertTrue(mp.dropped)
            self.assertEqual(len(mp.ring_launches), 0)

        #    Control: Toggle stays ON through +600 ms prep stall -> forks at 850 ms and logs RING_START t=850!
        class PrepOnDaemon(DaemonV2Machine):
            stalled = False
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                if cpu.reg_read(a.UC_ARM_REG_R7) == 38 and not self.stalled:
                    self.stalled = True
                    self.clock_ms += 600
                return super().on_syscall(cpu, _intno, _user)

        mpon = PrepOnDaemon(
            self.daemon_img, self.manifest, duration_ms=30000,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 100),
            stop_file_ms=1300,
        )
        mpon.run()
        self.assertEqual(len(mpon.ring_launches), 1)
        pon = runner.parse_daemon_log(mpon.stdout_buf.decode("ascii"))
        self.assertEqual(pon["ring_starts"][0]["t"], "850")

        # 2. B4 (gate_recovers + pipe_error):
        #    Case A: 5 bad gate ticks (410..450), single ENOSPC at 450, gate recovers at 460 -> MUST retry & confirm DISARM_GATE at 460!
        class GateRecoversDaemon(DaemonV2Machine):
            creates = []
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                r1 = cpu.reg_read(a.UC_ARM_REG_R1)
                t = self.clock_ms - 5000
                if nr == 5 and (r1 & 0x40) and self.read_cstr(r0).endswith("/disarm"):
                    self.creates.append(t)
                    if len(self.creates) == 1:
                        cpu.reg_write(a.UC_ARM_REG_R0, (-28) & 0xFFFFFFFF)
                        return
                return super().on_syscall(cpu, _intno, _user)

        def scen_rec(dm, t):
            dm.half = 1 if t >= 150 else 0
            dm.drive_act = 0x5E if 410 <= t <= 450 else 0x5F

        mgr = GateRecoversDaemon(
            self.daemon_img, self.manifest,
            scenario=scen_rec,
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 2000),
            stop_file_ms=950,
        )
        mgr.run()
        self.assertEqual(mgr.creates, [450, 460])
        pgr = runner.parse_daemon_log(mgr.stdout_buf.decode("ascii"))
        self.assertTrue(any(e["ev"] == "DISARM_ERR" for e in pgr["ring_events"]))
        self.assertTrue(any(e["ev"] == "DISARM_GATE" and e["t"] == "460" for e in pgr["ring_events"]))
        self.assertEqual(pgr["stop"]["r_reap"], "1")

        #    Case B: fcntl(O_NONBLOCK) fails on ring pipe + single ENOSPC on first disarm -> MUST retry on next tick!
        class PipeErrDaemon(DaemonV2Machine):
            creates = []
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                r1 = cpu.reg_read(a.UC_ARM_REG_R1)
                t = self.clock_ms - 5000
                if nr == 55 and self.fds.get(r0, {}).get("kind") == "ring_r":
                    cpu.reg_write(a.UC_ARM_REG_R0, (-5) & 0xFFFFFFFF)
                    return
                if nr == 5 and (r1 & 0x40) and self.read_cstr(r0).endswith("/disarm"):
                    self.creates.append(t)
                    if len(self.creates) == 1:
                        cpu.reg_write(a.UC_ARM_REG_R0, (-28) & 0xFFFFFFFF)
                        return
                return super().on_syscall(cpu, _intno, _user)

        mpe = PipeErrDaemon(
            self.daemon_img, self.manifest,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 2000),
            stop_file_ms=950,
        )
        mpe.run()
        self.assertGreaterEqual(len(mpe.creates), 2)
        ppe = runner.parse_daemon_log(mpe.stdout_buf.decode("ascii"))
        self.assertTrue(any(e["ev"] == "DISARM_ERR" for e in ppe["ring_events"]))
        self.assertTrue(any(e["ev"] == "DISARM_PIPE_ERR" for e in ppe["ring_events"]))
        self.assertEqual(ppe["stop"]["r_reap"], "1")

        # 3. Failed-start log custody (final_read_error & persist_error MUST preserve RAM dir + custody; LOG_ABSENT cleans up!):
        from unittest.mock import patch
        from contextlib import ExitStack
        from types import SimpleNamespace

        boot_log = (
            b"BOOT self_pid=999 im_pid=161 uipc_ok=1 bk_sz=1 bk_on=0 in_ok=1 ring_ok=1 pre=2 post=1 mon_proc=170 mon_mwf=170\n"
            b"STATE cam=1 bk_ok=1 bk_rc=0 sub_ok=1 half_ok=1 full_ok=1\n"
        )
        for case in ("final_read_error", "persist_error", "log_absent_cleans"):
            with tempfile.TemporaryDirectory(prefix=f"s6v2-fs-{case}-") as td, ExitStack() as stack:
                td_p = Path(td)
                active_p = td_p / ".active-stage6-v2.json"
                rm_called = []

                class FailStartSess:
                    def __init__(self, _cam, rec):
                        self.receipt = rec
                    def command(self, cmd, allowed=(0,), timeout=12):
                        if "rm -rf" in cmd:
                            rm_called.append(cmd)
                            return b"", 0
                        if "echo PRESENT" in cmd:
                            return b"GONE\n", 0
                        if "daemon.pid" in cmd:
                            return b"999\n", 0
                        if case == "final_read_error" and cmd.startswith("/bin/busybox cat") and "daemon.log" in cmd:
                            return b"", 1
                        if "daemon.log" in cmd:
                            return boot_log, 0
                        return b"", 0

                stack.enter_context(patch.object(runner, "Stage6Session", FailStartSess))
                stack.enter_context(patch.object(runner, "read_ready", return_value=b""))
                stack.enter_context(patch.object(runner, "run_start_preflight", return_value={"pid": 161}))
                stack.enter_context(patch.object(runner, "check_no_existing_s6_dirs", return_value=None))
                stack.enter_context(patch.object(runner, "detect_busybox_applets", return_value=({"gunzip"}, "fake")))
                stack.enter_context(patch.object(runner, "verify_nonsymlink_dir", return_value=None))
                stack.enter_context(patch.object(runner, "upload_elf", return_value=None))
                stack.enter_context(patch.object(runner, "verify_live_daemon_identity", return_value=dict(
                    matches=True, stat=dict(starttime=77), status=dict(PPid="1", TracerPid="0"),
                )))
                stack.enter_context(patch.object(runner, "verify_usable_initial_witnesses", side_effect=runner.usb.ProbeError("bad")))
                stack.enter_context(patch.object(runner, "request_stop_via_file", return_value=(True, [], [])))
                stack.enter_context(patch.object(
                    runner, "inspect_log_file_state",
                    return_value=("LOG_ABSENT" if case == "log_absent_cleans" else "LOG_OK"),
                ))
                if case == "persist_error":
                    stack.enter_context(patch.object(runner, "persist_collected_log_atomic", side_effect=OSError(28, "disk full")))

                rec = dict(
                    utc="20261121T000900Z", nonce="abcdef012345", model="DSC-RX100M7",
                    daemon_sha256="aa", ring_sha256="bb", commands=[], steps=[],
                )
                cam = SimpleNamespace(dev=SimpleNamespace(poisoned=False), setTerminalEnable=lambda _: None)
                with self.assertRaises(runner.usb.ProbeError):
                    runner.do_start(
                        cam, rec, self.daemon_img, self.ring_img,
                        before=2, after=1, toggle_on_val=0, active_path=active_p, log_out_dir=td_p,
                    )
                if case in ("final_read_error", "persist_error"):
                    self.assertEqual(rm_called, [], f"{case} MUST NOT rm -rf when final log was not durably saved!")
                    self.assertTrue(active_p.is_file(), f"{case} MUST preserve custody for --collect!")
                else:
                    self.assertEqual(len(rm_called), 1)
                    self.assertFalse(active_p.exists())

        # 4. R3 regressions: retry_pipe_off, retry_fork_off, retry_pipe_on, late_boundary, stale_unlink_eio, empty_log_persist!
        for err_kind, turn_off in (("pipe", True), ("fork", True), ("pipe", False)):
            class RetryErrDaemon(DaemonV2Machine):
                failed_once = False
                def on_syscall(self, cpu, _intno, _user):
                    a = self.arm
                    nr = cpu.reg_read(a.UC_ARM_REG_R7)
                    if not self.failed_once and ((err_kind == "pipe" and nr == 42 and self.clock_ms >= 5200) or
                                                 (err_kind == "fork" and nr == 2 and self.clock_ms >= 5200)):
                        self.failed_once = True
                        if turn_off:
                            self.bk_val = 1
                        cpu.reg_write(a.UC_ARM_REG_R0, ((-24 if err_kind == "pipe" else -11) & 0xFFFFFFFF))
                        return
                    return super().on_syscall(cpu, _intno, _user)

            mr = RetryErrDaemon(
                self.daemon_img, self.manifest, duration_ms=30000,
                scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
                ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 100),
                stop_file_ms=800,
            )
            mr.run()
            self.assertTrue(mr.failed_once)
            self.assertEqual(len(mr.ring_launches), 0 if turn_off else 1)

        # Late pipe delay crossing 20,000 ms teardown margin MUST refuse fork cleanly!
        class LateBoundaryDaemon(DaemonV2Machine):
            delayed = False
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                if nr == 42 and self.clock_ms >= 5200 and not self.delayed:
                    self.delayed = True
                    self.clock_ms += 100
                return super().on_syscall(cpu, _intno, _user)

        mlb = LateBoundaryDaemon(
            self.daemon_img, self.manifest, duration_ms=30000,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 9850 else 0),
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 100),
            stop_file_ms=10500,
        )
        mlb.run()
        self.assertTrue(mlb.delayed)
        self.assertEqual(len(mlb.ring_launches), 0)

        # Stale disarm marker with unlink(-EIO) MUST prevent launch!
        class StaleDisarmEioDaemon(DaemonV2Machine):
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                if nr == 10 and self.read_cstr(r0).endswith("/disarm"):
                    cpu.reg_write(a.UC_ARM_REG_R0, (-5) & 0xFFFFFFFF)
                    return
                return super().on_syscall(cpu, _intno, _user)

        msd = StaleDisarmEioDaemon(
            self.daemon_img, self.manifest, duration_ms=30000,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 100),
            stop_file_ms=600,
        )
        msd.disarm_present = True
        msd.run()
        self.assertEqual(len(msd.ring_launches), 0)

        # Present 0-byte daemon.log on failed start MUST durably write a 0-byte standalone *-daemon.log BEFORE rm -rf!
        with tempfile.TemporaryDirectory(prefix="s6v2-fs-empty-") as td, ExitStack() as stack:
            td_p = Path(td)
            active_p = td_p / ".active-stage6-v2.json"
            rm_after_empty = []

            class EmptyLogSess:
                def __init__(self, _cam, rec):
                    self.receipt = rec
                def command(self, cmd, allowed=(0,), timeout=12):
                    if "rm -rf" in cmd:
                        saved = list(td_p.glob("*-daemon.log"))
                        assert len(saved) == 1 and saved[0].stat().st_size == 0
                        rm_after_empty.append(True)
                        return b"", 0
                    if "echo PRESENT" in cmd:
                        return b"GONE\n", 0
                    if "daemon.pid" in cmd:
                        return b"999\n", 0
                    if cmd.startswith("/bin/busybox cat") and "daemon.log" in cmd:
                        return b"", 0
                    if "daemon.log" in cmd:
                        return boot_log, 0
                    return b"", 0

            stack.enter_context(patch.object(runner, "Stage6Session", EmptyLogSess))
            stack.enter_context(patch.object(runner, "read_ready", return_value=b""))
            stack.enter_context(patch.object(runner, "run_start_preflight", return_value={"pid": 161}))
            stack.enter_context(patch.object(runner, "check_no_existing_s6_dirs", return_value=None))
            stack.enter_context(patch.object(runner, "detect_busybox_applets", return_value=({"gunzip"}, "fake")))
            stack.enter_context(patch.object(runner, "verify_nonsymlink_dir", return_value=None))
            stack.enter_context(patch.object(runner, "upload_elf", return_value=None))
            stack.enter_context(patch.object(runner, "verify_live_daemon_identity", return_value=dict(
                matches=True, stat=dict(starttime=77), status=dict(PPid="1", TracerPid="0"),
            )))
            stack.enter_context(patch.object(runner, "verify_usable_initial_witnesses", side_effect=runner.usb.ProbeError("bad")))
            stack.enter_context(patch.object(runner, "request_stop_via_file", return_value=(True, [], [])))
            stack.enter_context(patch.object(runner, "inspect_log_file_state", return_value="LOG_OK"))

            rec = dict(
                utc="20261121T000950Z", nonce="abcdef012345", model="DSC-RX100M7",
                daemon_sha256="aa", ring_sha256="bb", commands=[], steps=[],
            )
            cam = SimpleNamespace(dev=SimpleNamespace(poisoned=False), setTerminalEnable=lambda _: None)
            with self.assertRaises(runner.usb.ProbeError):
                runner.do_start(
                    cam, rec, self.daemon_img, self.ring_img,
                    before=2, after=1, toggle_on_val=0, active_path=active_p, log_out_dir=td_p,
                )
            self.assertEqual(rm_after_empty, [True])
            self.assertTrue(rec.get("log_persisted"))
            self.assertTrue(rec.get("failed_start_empty_log"))
            self.assertFalse(active_p.exists())

        # 5. R4 regressions: late stop lookup, stop lookup EMFILE, and parent fcntl delay timestamp!
        #    (a) 100 ms delay inside final stop-file open crossing 20,000 ms margin -> 0 forks!
        class LateStopLookupDaemon(DaemonV2Machine):
            delayed = False
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                if nr == 5 and self.clock_ms >= 14950 and self.read_cstr(r0).endswith("/stop") and not self.delayed:
                    # Only trigger once ring pipe exists (inside fork_prepared_ring)
                    if any(v.get("kind") == "ring_r" for v in self.fds.values()):
                        self.delayed = True
                        self.clock_ms += 100
                return super().on_syscall(cpu, _intno, _user)

        mlsl = LateStopLookupDaemon(
            self.daemon_img, self.manifest, duration_ms=30000,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 9850 else 0),
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 100),
            stop_file_ms=10500,
        )
        mlsl.run()
        self.assertTrue(mlsl.delayed)
        self.assertEqual(len(mlsl.ring_launches), 0)

        #    (b) EMFILE on final stop-file lookup while stop marker present -> MUST refuse launch (0 forks)!
        class StopEmfileDaemon(DaemonV2Machine):
            injected = False
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                if nr == 5 and self.read_cstr(r0).endswith("/stop") and any(v.get("kind") == "ring_r" for v in self.fds.values()):
                    self.injected = True
                    cpu.reg_write(a.UC_ARM_REG_R0, (-24) & 0xFFFFFFFF)  # -EMFILE
                    return
                return super().on_syscall(cpu, _intno, _user)

        mse = StopEmfileDaemon(
            self.daemon_img, self.manifest, duration_ms=30000,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 100),
            stop_file_ms=600,
        )
        mse.run()
        self.assertTrue(mse.injected)
        self.assertEqual(len(mse.ring_launches), 0)

        #    (c) 100 ms delay inside parent fcntl(O_NONBLOCK) -> fork at 250 MUST still log RING_START t=250!
        class ParentFcntlDelayDaemon(DaemonV2Machine):
            delayed = False
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                if nr == 55 and self.fds.get(r0, {}).get("kind") == "ring_r" and not self.delayed:
                    self.delayed = True
                    self.clock_ms += 100
                return super().on_syscall(cpu, _intno, _user)

        mpfd = ParentFcntlDelayDaemon(
            self.daemon_img, self.manifest, duration_ms=30000,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 100),
            stop_file_ms=800,
        )
        mpfd.run()
        self.assertTrue(mpfd.delayed)
        self.assertEqual(len(mpfd.ring_launches), 1)
        ppfd = runner.parse_daemon_log(mpfd.stdout_buf.decode("ascii"))
        self.assertEqual(ppfd["ring_starts"][0]["t"], "250")

    def test_12_hw1_regressions_topology2_and_insert4100_sub_en_dip(self):
        cfg = self._make_valid_ring_cfg()

        # 1. Ring survives real M7 Insert4100 1->2(500ms)->3 + sub_en=0 dip (800ms) + Pullout4100 3->2(600ms)->1!
        m_ok = RingV2Machine(
            self.ring_img, self.manifest, cfg,
            disarm_in_armed=True,
            detached_insert_ms=500,
            detached_pullout_ms=600,
            insert_sub_dip_ms=800,
        )
        m_ok.run()
        self.assertEqual(m_ok.exit_code, 0)
        self.assertEqual(len(m_ok.poketext_log), 2)
        self.assertEqual(m_ok.poketext_log[1], (m_ok.LIBOBJ + 0xA14C98, 0x531EF240))
        self.assertFalse(m_ok.inserted_4100)
        self.assertFalse(m_ok.mode_4100)
        self.assertEqual(m_ok.traced, {})
        rows_ok = [
            [int(raw[j:j + 8], 16) for j in range(7, 103, 8)]
            for raw in m_ok.stdout_buf.splitlines() if raw.startswith(b"M7CAP1=")
        ]
        # Verify stage6_route_wait actually observed intermediate topology==2 on BOTH insert (a=0) and pullout (a=1)!
        self.assertTrue(any(r[1] == 60 and r[4] == 5 and r[5] == 0 and r[7] == 2 for r in rows_ok))
        self.assertTrue(any(r[1] == 60 and r[4] == 5 and r[5] == 0 and r[7] == 3 and r[8] == 2 for r in rows_ok))
        self.assertTrue(any(r[1] == 60 and r[4] == 5 and r[5] == 1 and r[7] == 2 for r in rows_ok))
        self.assertTrue(any(r[1] == 60 and r[4] == 5 and r[5] == 1 and r[7] == 1 and r[8] == 2 for r in rows_ok))
        # Verify PRECAP_ARMED (kind=92, stage=55, next=1) was reached after sub_en recovered!
        self.assertTrue(any(r[1] == 92 and r[4] == 55 and r[6] == 1 for r in rows_ok))

        # 2. Ring aborts cleanly pre-mode_set (0 POKETEXT, 0 mode_set, Pullout4100 clean, exit 0) if sub_en stays 0 > 2000ms!
        m_sub_to = RingV2Machine(
            self.ring_img, self.manifest, cfg,
            detached_insert_ms=250,
            insert_sub_never_recovers=True,
        )
        m_sub_to.run()
        self.assertEqual(m_sub_to.exit_code, 0)
        self.assertEqual(m_sub_to.poketext_log, [])
        self.assertFalse(any(pc == m_sub_to.LIBOBJ + 0xA1C4E0 for pc, *_ in m_sub_to.sony_ops))
        self.assertFalse(m_sub_to.inserted_4100)
        self.assertEqual(m_sub_to.traced, {})

        # 3. Daemon tolerates 950 ms Insert4100 sub_en=0 dip during ring_phase==0 (ZERO false DISARM_GATE!),
        #    AND tolerates Pullout4100 sub_en=0 dip during ring_phase==4 (PRECAP_RESTORE)!
        def scen_dip_ok(dm, t):
            dm.half = 1 if 150 <= t < 1800 else 0
            # Ring forks at t=250: dip sub_en=0 from t=350..1300 (950 ms) during Insert4100,
            # then sub_en=1 during PRECAP_ARMED (1300..1800), then dip sub_en=0 at t=1850..2100 during Pullout4100!
            dm.sub_enabled = 0 if (350 <= t < 1300 or 1850 <= t < 2100) else 1

        def script_phase_ok(dm, _seq, cfg_raw):
            dm.active_ring_exit_ms = dm.clock_ms + 1950  # exits at t=2200
            dm._tok = struct.unpack_from("<I", cfg_raw, 28 + 8)[0]

        class PhaseInjectDaemon(DaemonV2Machine):
            sent_armed = False
            sent_drain = False
            sent_restore = False
            def on_syscall(self, cpu, _intno, _user):
                t = self.clock_ms - 5000
                if self.active_ring_pid is not None and hasattr(self, "_tok"):
                    if not self.sent_armed and t >= 1350:
                        self.sent_armed = True
                        self.ring_pipe_bytes.extend(fmt_m7cap(self._tok, 92, 28, t, 55, 0, 1, t, 0, 0, 0))
                    if not self.sent_drain and t >= 1810:
                        self.sent_drain = True
                        self.ring_pipe_bytes.extend(fmt_m7cap(self._tok, 92, 28, t, 55, 1, 3, t, 0, 0, 0))
                    if not self.sent_restore and t >= 1820:
                        self.sent_restore = True
                        self.ring_pipe_bytes.extend(fmt_m7cap(self._tok, 92, 28, t, 55, 3, 4, t, 0, 0, 0))
                return super().on_syscall(cpu, _intno, _user)

        md_ok = PhaseInjectDaemon(
            self.daemon_img, self.manifest,
            scenario=scen_dip_ok, ring_script=script_phase_ok, stop_file_ms=2500,
        )
        md_ok.run()
        pd_ok = runner.parse_daemon_log(md_ok.stdout_buf.decode("ascii"))
        self.assertEqual(pd_ok["ring_start_count"], 1)
        self.assertFalse(any(e["ev"] == "DISARM_GATE" for e in pd_ok["ring_events"]))
        self.assertEqual(pd_ok["stop"]["r_ok"], "1")

        # 4. Daemon MUST disarm in ~50 ms if sub_en drops to 0 AFTER PHASE next=1 (PRECAP_ARMED)!
        def scen_menu_armed(dm, t):
            dm.half = 1 if t >= 150 else 0
            dm.sub_enabled = 0 if t >= 600 else 1

        class ArmedMenuDaemon(DaemonV2Machine):
            sent_armed = False
            def on_syscall(self, cpu, _intno, _user):
                t = self.clock_ms - 5000
                if self.active_ring_pid is not None and not self.sent_armed and t >= 400:
                    self.sent_armed = True
                    tok = struct.unpack_from("<I", self.ring_launches[-1]["cfg"], 28 + 8)[0]
                    self.ring_pipe_bytes.extend(fmt_m7cap(tok, 92, 28, t, 55, 0, 1, t, 0, 0, 0))
                return super().on_syscall(cpu, _intno, _user)

        md_menu = ArmedMenuDaemon(
            self.daemon_img, self.manifest,
            scenario=scen_menu_armed,
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 3000),
            stop_file_ms=1000,
        )
        md_menu.run()
        pd_menu = runner.parse_daemon_log(md_menu.stdout_buf.decode("ascii"))
        disarms = [e for e in pd_menu["ring_events"] if e["ev"] == "DISARM_GATE"]
        self.assertEqual(len(disarms), 1)
        self.assertLessEqual(int(disarms[0]["t"]), 660)

        # 5. Daemon MUST fail closed with DISARM_GATE if sub_en stays 0 > 4000 ms in ring_phase==0!
        def scen_stuck_sub0(dm, t):
            dm.half = 1 if t >= 150 else 0
            dm.sub_enabled = 0 if t >= 350 else 1

        md_stuck = DaemonV2Machine(
            self.daemon_img, self.manifest, duration_ms=30000,
            scenario=scen_stuck_sub0,
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 8000),
            stop_file_ms=4800,
        )
        md_stuck.run()
        pd_stuck = runner.parse_daemon_log(md_stuck.stdout_buf.decode("ascii"))
        stuck_disarms = [e for e in pd_stuck["ring_events"] if e["ev"] == "DISARM_GATE"]
        self.assertEqual(len(stuck_disarms), 1)
        # Ring forks at t=250 -> 4000 ms bound hits at t=4250 + 40..50 ms (5 ticks) = ~4290 ms!
        self.assertGreaterEqual(int(stuck_disarms[0]["t"]), 4250)
        self.assertLessEqual(int(stuck_disarms[0]["t"]), 4350)

        # 6. Daemon STILL disarms in ~50 ms in ring_phase==0 if sub_ok==0 (Spinal/cam vtable broken, NOT just sub_en==0)!
        class BrokenSpinalDaemon(DaemonV2Machine):
            def build_im_memory(self):
                mem = super().build_im_memory()
                if (self.clock_ms - 5000) >= 400:
                    # Corrupt camera vtable pointer so sub_ok drops to 0!
                    raw = struct.pack("<I", 0xDEAD0000)
                    for i, b in enumerate(raw):
                        mem[self.CAMERA + i] = b
                return mem

        md_subok = BrokenSpinalDaemon(
            self.daemon_img, self.manifest,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 2000),
            stop_file_ms=800,
        )
        md_subok.run()
        pd_subok = runner.parse_daemon_log(md_subok.stdout_buf.decode("ascii"))
        subok_disarms = [e for e in pd_subok["ring_events"] if e["ev"] == "DISARM_GATE"]
        self.assertEqual(len(subok_disarms), 1)
        self.assertLessEqual(int(subok_disarms[0]["t"]), 460)

    def test_13_r6_review_regressions_route_timeout_clock_rollover_and_pipe_safety(self):
        cfg = self._make_valid_ring_cfg()

        # 1. Pullout sees SD (1) once, then 29 consecutive unknown samples -> MUST NOT exit 0 (UNRESOLVED 186/4)!
        class PulloutOneThenZeroRing(RingV2Machine):
            pullout_busy_reads = 0
            unresolved_seen = False
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r4 = cpu.reg_read(a.UC_ARM_REG_R4)
                if nr == 180 and self.pullout_t_ms is not None and r4 == self.REC_MGR + 0x69C8:
                    self.pullout_busy_reads += 1
                    if self.pullout_busy_reads >= 2:
                        # Corrupt recorder busy field so stage6_session_topology returns 0 on polls 2..30!
                        self.put_im(self.REC_MGR + 0x69C8, 0, 1)
                if nr == 4 and cpu.reg_read(a.UC_ARM_REG_R0) == 1:
                    data = bytes(cpu.mem_read(cpu.reg_read(a.UC_ARM_REG_R1), cpu.reg_read(a.UC_ARM_REG_R2)))
                    if data.startswith(b"M7CAP1=") and data[15:23] == b"0000000d" and data[39:47] == b"00000062":
                        self.stdout_buf.extend(data)
                        self.unresolved_seen = True
                        cpu.emu_stop()
                        return
                return super().on_syscall(cpu, _intno, _user)

        mp1 = PulloutOneThenZeroRing(self.ring_img, self.manifest, cfg, disarm_in_armed=True)
        mp1.run()
        self.assertTrue(mp1.unresolved_seen)
        self.assertNotEqual(mp1.exit_code, 0)
        rows_p1 = [
            [int(raw[j:j + 8], 16) for j in range(7, 103, 8)]
            for raw in mp1.stdout_buf.splitlines() if raw.startswith(b"M7CAP1=")
        ]
        self.assertTrue(any(r[1] == 13 and r[4] == 98 and r[5] == 186 and r[6] == 4 for r in rows_p1))

        # 2. Insert sees (2, 3, then 28 zeros) OR (29 zeros, then 3) -> MUST NOT arm (0 POKETEXT, 0 mode_set, exit 7)!
        for pattern in ("two_three_zeros", "zeros_then_three"):
            class InsertLoneThreeRing(RingV2Machine):
                route_polls = 0
                pat = pattern
                def on_syscall(self, cpu, _intno, _user):
                    a = self.arm
                    nr = cpu.reg_read(a.UC_ARM_REG_R7)
                    r4 = cpu.reg_read(a.UC_ARM_REG_R4)
                    if nr == 180 and self.insert_t_ms is not None and self.pullout_t_ms is None and r4 == self.REC_MGR + 0x69C8:
                        self.route_polls += 1
                        if self.pat == "two_three_zeros":
                            if self.route_polls == 1:
                                self.mode_state = "detached"; self.apply_media_topology(); self.put_im(self.REC_MGR + 0x69C8, 0, 0)
                            elif self.route_polls == 2:
                                self.mode_state = "init"; self.apply_media_topology(); self.put_im(self.REC_MGR + 0x69C8, 0, 0)
                            else:
                                self.put_im(self.REC_MGR + 0x69C8, 0, 1)
                        else:
                            if self.route_polls < 30:
                                self.put_im(self.REC_MGR + 0x69C8, 0, 1)
                            else:
                                self.mode_state = "init"; self.apply_media_topology(); self.put_im(self.REC_MGR + 0x69C8, 0, 0)
                    elif nr == 180 and self.pullout_t_ms is not None and r4 == self.REC_MGR + 0x69C8:
                        self.put_im(self.REC_MGR + 0x69C8, 0, 0)
                    return super().on_syscall(cpu, _intno, _user)

            mi3 = InsertLoneThreeRing(self.ring_img, self.manifest, cfg)
            mi3.run()
            self.assertEqual(mi3.exit_code, 7, f"{pattern} must fail capture cleanly with rc=7")
            self.assertEqual(mi3.poketext_log, [])
            self.assertFalse(any(pc == mi3.LIBOBJ + 0xA1C4E0 for pc, *_ in mi3.sony_ops))
            self.assertFalse(mi3.inserted_4100)

        # 3. 2,400 ms delay during first 25 ms sleep in sub_ready wait MUST abort pre-mode_set (exit 0, 0 POKETEXT)!
        def in_stock_capture(buf: bytearray) -> bool:
            return any(
                ln.startswith(b"M7CAP1=") and ln[15:23] == b"0000002d" and ln[39:47] == b"00000008"
                for ln in bytes(buf).splitlines()
            )

        class SubDelay2400Ring(RingV2Machine):
            jumped = False
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                if nr == 162 and not self.jumped and in_stock_capture(self.stdout_buf):
                    sec, nsec = struct.unpack("<2I", cpu.mem_read(cpu.reg_read(a.UC_ARM_REG_R0), 8))
                    if sec == 0 and nsec == 25_000_000:
                        self.jumped = True
                        self.clock_ms += 2400
                        self.sub_enabled = 1  # Subscription recovered AFTER 2,000 ms deadline!
                        cpu.reg_write(a.UC_ARM_REG_R0, 0)
                        return
                return super().on_syscall(cpu, _intno, _user)

        msd24 = SubDelay2400Ring(self.ring_img, self.manifest, cfg, insert_sub_never_recovers=True)
        msd24.run()
        self.assertTrue(msd24.jumped)
        self.assertEqual(msd24.exit_code, 0)
        self.assertEqual(msd24.poketext_log, [])
        self.assertFalse(any(pc == msd24.LIBOBJ + 0xA1C4E0 for pc, *_ in msd24.sony_ops))
        self.assertFalse(msd24.inserted_4100)

        #    Also: initial clock failure or 0 timestamp at sub_ready wait MUST abort pre-mode_set even if sub_en==1!
        for fail_mode in ("zero", "err"):
            class SubBadClockRing(RingV2Machine):
                injected = False
                fm = fail_mode
                def on_syscall(self, cpu, _intno, _user):
                    a = self.arm
                    nr = cpu.reg_read(a.UC_ARM_REG_R7)
                    if nr == 263 and not self.injected and in_stock_capture(self.stdout_buf):
                        self.injected = True
                        if self.fm == "zero":
                            cpu.mem_write(cpu.reg_read(a.UC_ARM_REG_R1), struct.pack("<2I", 0, 0))
                            cpu.reg_write(a.UC_ARM_REG_R0, 0)
                        else:
                            cpu.reg_write(a.UC_ARM_REG_R0, (-14) & 0xFFFFFFFF)
                        return
                    return super().on_syscall(cpu, _intno, _user)

            mbc = SubBadClockRing(self.ring_img, self.manifest, cfg)
            mbc.run()
            self.assertTrue(mbc.injected, f"{fail_mode} injection must trigger")
            self.assertEqual(mbc.exit_code, 0)
            self.assertEqual(mbc.poketext_log, [])
            self.assertFalse(mbc.inserted_4100)

        # 4. Release half-press for 100 ms and re-press during Insert4100 route wait -> MUST NOT arm (exit 0, 0 POKETEXT)!
        class LiftRepressInsertRing(RingV2Machine):
            def on_syscall(self, cpu, _intno, _user):
                if self.insert_t_ms is not None and self.pullout_t_ms is None:
                    dt = self.clock_ms - self.insert_t_ms
                    self.half = 0 if (250 <= dt < 350) else 1
                return super().on_syscall(cpu, _intno, _user)

        mlr = LiftRepressInsertRing(self.ring_img, self.manifest, cfg, detached_insert_ms=500)
        mlr.run()
        self.assertEqual(mlr.exit_code, 0)
        self.assertEqual(mlr.poketext_log, [])
        self.assertFalse(any(pc == mlr.LIBOBJ + 0xA1C4E0 for pc, *_ in mlr.sony_ops))
        self.assertFalse(mlr.inserted_4100)

        # 5. Daemon phase-0 4,000 ms timeout MUST still trigger across 32-bit ms clock rollover!
        class RolloverDaemon(DaemonV2Machine):
            def __init__(self, *args, **kw):
                super().__init__(*args, **kw)
                # Boot at 0xFFFFFCE0 (-800 ms before 32-bit wrap) so rollover happens at elapsed=800 ms!
                self.boot_ms = 0xFFFFFCE0
                self.clock_ms = self.boot_ms
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                if nr == 263:
                    ms32 = self.clock_ms & 0xFFFFFFFF
                    cpu.mem_write(cpu.reg_read(a.UC_ARM_REG_R1), struct.pack("<2I", ms32 // 1000, (ms32 % 1000) * 1000000))
                    cpu.reg_write(a.UC_ARM_REG_R0, 0)
                    return
                if nr == 177:  # rt_sigtimedwait advances clock and drives scenario with elapsed = (clock - boot) & 0xFFFFFFFF
                    sec, nsec = struct.unpack("<2I", cpu.mem_read(cpu.reg_read(a.UC_ARM_REG_R2), 8))
                    self.clock_ms = (self.clock_ms + max(1, sec * 1000 + nsec // 1000000)) & 0xFFFFFFFF
                    el = (self.clock_ms - self.boot_ms) & 0xFFFFFFFF
                    if self.scenario is not None:
                        self.scenario(self, el)
                    cpu.reg_write(a.UC_ARM_REG_R0, (-11) & 0xFFFFFFFF)
                    return
                if nr == 5:
                    path = self.read_cstr(cpu.reg_read(a.UC_ARM_REG_R0))
                    if path.endswith("/stop"):
                        el = (self.clock_ms - self.boot_ms) & 0xFFFFFFFF
                        if self.stop_file_ms is not None and el >= self.stop_file_ms:
                            fd = self.next_fd; self.next_fd += 1
                            self.fds[fd] = dict(kind="file", path=path, data=b"stop\n", pos=0)
                            cpu.reg_write(a.UC_ARM_REG_R0, fd)
                            return
                        cpu.reg_write(a.UC_ARM_REG_R0, (-2) & 0xFFFFFFFF)
                        return
                return super().on_syscall(cpu, _intno, _user)

        def scen_roll(dm, t):
            dm.half = 1 if t >= 150 else 0
            dm.sub_enabled = 0 if t >= 400 else 1

        mroll = RolloverDaemon(
            self.daemon_img, self.manifest, duration_ms=30000,
            scenario=scen_roll,
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", None),
            stop_file_ms=4750,
        )
        mroll.run()
        proll = runner.parse_daemon_log(mroll.stdout_buf.decode("ascii"))
        r_dis = [e for e in proll["ring_events"] if e["ev"] == "DISARM_GATE"]
        self.assertEqual(len(r_dis), 1)
        self.assertLessEqual(int(r_dis[0]["t"]), 4350)

        # 6. Daemon rejects wrong-token PHASE, rejects impossible 1->4 / 1->0 transitions with DISARM_PIPE_ERR,
        #    and disarms immediately with DISARM_PIPE_ERR on runtime pipe read() -EIO!
        class WrongTokenDaemon(DaemonV2Machine):
            sent = False
            def on_syscall(self, cpu, _intno, _user):
                t = self.clock_ms - 5000
                if self.active_ring_pid is not None and not self.sent and t >= 350:
                    self.sent = True
                    self.ring_pipe_bytes.extend(fmt_m7cap(0xDEADBEEF, 92, 28, t, 55, 0, 4, t, 0, 0, 0))
                return super().on_syscall(cpu, _intno, _user)

        mwt = WrongTokenDaemon(
            self.daemon_img, self.manifest,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 200),
            stop_file_ms=700,
        )
        mwt.run()
        pwt = runner.parse_daemon_log(mwt.stdout_buf.decode("ascii"))
        self.assertFalse(any(e["ev"] in ("PHASE", "PHASE_BAD") for e in pwt["ring_events"]))

        for bad_next in (4, 0):
            class BadEdgeDaemon(DaemonV2Machine):
                step = 0
                bn = bad_next
                def on_syscall(self, cpu, _intno, _user):
                    t = self.clock_ms - 5000
                    if self.active_ring_pid is not None:
                        tok = struct.unpack_from("<I", self.ring_launches[-1]["cfg"], 28 + 8)[0]
                        if self.step == 0 and t >= 320:
                            self.step = 1
                            self.ring_pipe_bytes.extend(fmt_m7cap(tok, 92, 28, t, 55, 0, 1, t, 0, 0, 0))
                        elif self.step == 1 and t >= 360:
                            self.step = 2
                            self.ring_pipe_bytes.extend(fmt_m7cap(tok, 92, 28, t, 55, 1, self.bn, t, 0, 0, 0))
                    return super().on_syscall(cpu, _intno, _user)

            mbe = BadEdgeDaemon(
                self.daemon_img, self.manifest,
                scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
                ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 3000),
                stop_file_ms=900,
            )
            mbe.run()
            pbe = runner.parse_daemon_log(mbe.stdout_buf.decode("ascii"))
            self.assertTrue(any(e["ev"] == "PHASE_BAD" for e in pbe["ring_events"]))
            pe_dis = [e for e in pbe["ring_events"] if e["ev"] == "DISARM_PIPE_ERR"]
            self.assertEqual(len(pe_dis), 1)
            self.assertLessEqual(int(pe_dis[0]["t"]), 400)

        class PipeReadEioDaemon(DaemonV2Machine):
            injected = False
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                fd = cpu.reg_read(a.UC_ARM_REG_R0)
                t = self.clock_ms - 5000
                if nr == 3 and self.fds.get(fd, {}).get("kind") == "ring_r" and t >= 400 and not self.injected:
                    self.injected = True
                    cpu.reg_write(a.UC_ARM_REG_R0, (-5) & 0xFFFFFFFF)  # -EIO on pipe read!
                    return
                return super().on_syscall(cpu, _intno, _user)

        mreio = PipeReadEioDaemon(
            self.daemon_img, self.manifest,
            scenario=lambda dm, t: setattr(dm, "half", 1 if t >= 150 else 0),
            ring_script=lambda dm, _s, _c: setattr(dm, "active_ring_exit_ms", dm.clock_ms + 3000),
            stop_file_ms=900,
        )
        mreio.run()
        self.assertTrue(mreio.injected)
        preio = runner.parse_daemon_log(mreio.stdout_buf.decode("ascii"))
        eio_dis = [e for e in preio["ring_events"] if e["ev"] == "DISARM_PIPE_ERR"]
        self.assertEqual(len(eio_dis), 1)
        self.assertLessEqual(int(eio_dis[0]["t"]), 420)

    def test_14_r7_review_regressions_focus_retries_sub_stale_and_clock_progress(self):
        cfg = self._make_valid_ring_cfg()

        def in_stock_capture(buf: bytearray) -> bool:
            return any(
                ln.startswith(b"M7CAP1=") and ln[15:23] == b"0000002d" and ln[39:47] == b"00000008"
                for ln in bytes(buf).splitlines()
            )

        # 1. Half-press released for 100 ms and re-pressed during 300 ms focus wait -> MUST NOT emit ARMED (0->1),
        #    MUST restore trap word, restore SD mode, Pullout4100, detach all, exit 0!
        class FocusReleaseRepressRing(RingV2Machine):
            focus_start_ms = None
            def on_syscall(self, cpu, _intno, _user):
                # Focus begins right after sender(o, 1, 1) (first fork of sndcmd.elf after trap is installed!)
                if self.focus_start_ms is None and len(self.sndcmd_calls) == 1 and len(self.poketext_log) == 1:
                    self.focus_start_ms = self.clock_ms
                if self.focus_start_ms is not None:
                    dt = self.clock_ms - self.focus_start_ms
                    self.half = 0 if (50 <= dt < 150) else 1
                return super().on_syscall(cpu, _intno, _user)

        m_foc = FocusReleaseRepressRing(self.ring_img, self.manifest, cfg)
        m_foc.run()
        self.assertIsNotNone(m_foc.focus_start_ms)
        self.assertEqual(m_foc.exit_code, 0)
        self.assertEqual(len(m_foc.poketext_log), 2)
        self.assertEqual(m_foc.poketext_log[1], (m_foc.LIBOBJ + 0xA14C98, 0x531EF240))
        self.assertFalse(m_foc.inserted_4100)
        self.assertFalse(m_foc.mode_4100)
        self.assertEqual(m_foc.traced, {})
        rows_foc = [
            [int(raw[j:j + 8], 16) for j in range(7, 103, 8)]
            for raw in m_foc.stdout_buf.splitlines() if raw.startswith(b"M7CAP1=")
        ]
        # Zero PHASE events (never emitted PRECAP_ARMED 0->1 or PRECAP_RESTORE 3->4)!
        self.assertFalse(any(r[1] == 92 and r[4] == 55 for r in rows_foc))
        # Both synthetic S1 down and S1 up (2 sndcmd.elf calls) ran!
        self.assertEqual(len(m_foc.sndcmd_calls), 2)

        # 2. Release + re-press during stage6_start_command(1) 100 ms busy retry -> ZERO Insert4100, ZERO mode_set, exit 0!
        class InsertRetryLiftRing(RingV2Machine):
            busy_once = False
            retry_start_ms = None
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                if nr == 26 and cpu.reg_read(a.UC_ARM_REG_R0) == 12 and not self.busy_once:
                    # First ptrace GETREGS (attempt 1 of start_command(1)) -> return busy PC so it retries after 100 ms!
                    self.busy_once = True
                    self.retry_start_ms = self.clock_ms
                    tid = cpu.reg_read(a.UC_ARM_REG_R1)
                    regs = list(self.traced[tid]["regs"])
                    regs[15] = self.LIBOBJ + 0x1000  # non-idle PC
                    cpu.mem_write(cpu.reg_read(a.UC_ARM_REG_R3), struct.pack("<18I", *regs))
                    cpu.reg_write(a.UC_ARM_REG_R0, 0)
                    return
                if self.retry_start_ms is not None:
                    dt = self.clock_ms - self.retry_start_ms
                    self.half = 0 if (20 <= dt < 80) else 1
                return super().on_syscall(cpu, _intno, _user)

        m_ins_r = InsertRetryLiftRing(self.ring_img, self.manifest, cfg)
        m_ins_r.run()
        self.assertTrue(m_ins_r.busy_once)
        self.assertEqual(m_ins_r.exit_code, 0)
        self.assertEqual(m_ins_r.sony_ops, [])  # Insert4100 NEVER even ran!
        self.assertEqual(m_ins_r.poketext_log, [])
        self.assertFalse(m_ins_r.inserted_4100)
        self.assertEqual(m_ins_r.traced, {})

        # 3. Release + re-press (AND separate sub_en=0 drop) during stage6_connect_pair(3) 250 ms busy retry ->
        #    ZERO mode_set, ZERO POKETEXT, Pullout4100 restores SD, exit 0!
        for mode in ("lift_repress", "sub_disabled"):
            class ConnectRetryRing(RingV2Machine):
                busy_once = False
                retry_start_ms = None
                m = mode
                def on_syscall(self, cpu, _intno, _user):
                    a = self.arm
                    nr = cpu.reg_read(a.UC_ARM_REG_R7)
                    if (nr == 26 and cpu.reg_read(a.UC_ARM_REG_R0) == 12 and
                            not self.busy_once and in_stock_capture(self.stdout_buf)):
                        self.busy_once = True
                        self.retry_start_ms = self.clock_ms
                        tid = cpu.reg_read(a.UC_ARM_REG_R1)
                        regs = list(self.traced[tid]["regs"])
                        regs[15] = self.LIBOBJ + 0x1000  # busy on attempt 1 of stage6_connect_pair(3)
                        cpu.mem_write(cpu.reg_read(a.UC_ARM_REG_R3), struct.pack("<18I", *regs))
                        cpu.reg_write(a.UC_ARM_REG_R0, 0)
                        return
                    if self.retry_start_ms is not None:
                        dt = self.clock_ms - self.retry_start_ms
                        if self.m == "lift_repress":
                            self.half = 0 if (50 <= dt < 150) else 1
                        else:
                            self.sub_enabled = 0  # Disabled through retry and stays disabled!
                    return super().on_syscall(cpu, _intno, _user)

            m_cr = ConnectRetryRing(self.ring_img, self.manifest, cfg)
            m_cr.run()
            self.assertTrue(m_cr.busy_once, f"{mode} must trigger busy retry")
            self.assertEqual(m_cr.exit_code, 0)
            self.assertEqual(m_cr.poketext_log, [])
            self.assertFalse(any(pc == m_cr.LIBOBJ + 0xA1C4E0 for pc, *_ in m_cr.sony_ops))
            self.assertFalse(m_cr.inserted_4100)
            self.assertEqual(m_cr.traced, {})

        # 4. Frozen clock in sub_ready wait (with late recovery during sleep) AND backward mid-window post-read clock jump
        #    MUST both abort cleanly pre-mode_set (exit 0, 0 POKETEXT)!
        class FrozenSubClockRing(RingV2Machine):
            frozen_val = None
            slept_once = False
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                if in_stock_capture(self.stdout_buf) and self.pullout_t_ms is None:
                    if nr == 263:
                        if self.frozen_val is None:
                            self.frozen_val = self.clock_ms
                        ms = self.frozen_val
                        cpu.mem_write(cpu.reg_read(a.UC_ARM_REG_R1), struct.pack("<2I", ms // 1000, (ms % 1000) * 1000000))
                        cpu.reg_write(a.UC_ARM_REG_R0, 0)
                        return
                    if nr == 162 and not self.slept_once:
                        self.slept_once = True
                        self.sub_enabled = 1  # Recovered during delayed sleep while clock stayed frozen!
                        cpu.reg_write(a.UC_ARM_REG_R0, 0)
                        return
                return super().on_syscall(cpu, _intno, _user)

        m_frz = FrozenSubClockRing(self.ring_img, self.manifest, cfg, insert_sub_never_recovers=True)
        m_frz.run()
        self.assertTrue(m_frz.slept_once)
        self.assertEqual(m_frz.exit_code, 0)
        self.assertEqual(m_frz.poketext_log, [])
        self.assertFalse(any(pc == m_frz.LIBOBJ + 0xA1C4E0 for pc, *_ in m_frz.sony_ops))
        self.assertFalse(m_frz.inserted_4100)

        class BackwardPostReadClockRing(RingV2Machine):
            sub_clocks = 0
            base_ms = None
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                if nr == 263 and in_stock_capture(self.stdout_buf) and self.pullout_t_ms is None and self.sub_clocks < 3:
                    self.sub_clocks += 1
                    if self.sub_clocks == 1:
                        self.base_ms = self.clock_ms
                        ms = self.base_ms
                    elif self.sub_clocks == 2:
                        ms = self.base_ms + 1800
                    else:
                        ms = self.base_ms + 100  # Backward jump still inside [base, base+2000)!
                    cpu.mem_write(cpu.reg_read(a.UC_ARM_REG_R1), struct.pack("<2I", ms // 1000, (ms % 1000) * 1000000))
                    cpu.reg_write(a.UC_ARM_REG_R0, 0)
                    return
                return super().on_syscall(cpu, _intno, _user)

        m_bwd = BackwardPostReadClockRing(self.ring_img, self.manifest, cfg)
        m_bwd.run()
        self.assertEqual(m_bwd.sub_clocks, 3)
        self.assertEqual(m_bwd.exit_code, 0)
        self.assertEqual(m_bwd.poketext_log, [])
        self.assertFalse(m_bwd.inserted_4100)

        # 5. One-sided pin graph on unconfirmed insert (REM_PIN1.peer == REC_PIN0, REC_PIN0.peer == 0)
        #    MUST fail closed with UNRESOLVED 186/2 (NOT admit pullout fallback)!
        class OneSidedPeerRing(RingV2Machine):
            unresolved_seen = False
            corrupted = False
            def on_syscall(self, cpu, _intno, _user):
                a = self.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r4 = cpu.reg_read(a.UC_ARM_REG_R4)
                if nr == 180 and self.insert_t_ms is not None and not self.corrupted and r4 == self.REC_MGR + 0x69C8:
                    self.corrupted = True
                    # Break reciprocal link on REC_PIN0 + 0x10 (set peer to 0) while leaving REM_PIN1.peer == REC_PIN0!
                    self.put_im(self.REC_PIN0 + 0x10, 0)
                    self.put_im(self.REC_MGR + 0x69C8, 0, 1)
                if nr == 4 and cpu.reg_read(a.UC_ARM_REG_R0) == 1:
                    data = bytes(cpu.mem_read(cpu.reg_read(a.UC_ARM_REG_R1), cpu.reg_read(a.UC_ARM_REG_R2)))
                    if data.startswith(b"M7CAP1=") and data[15:23] == b"0000000d" and data[39:47] == b"00000062":
                        self.stdout_buf.extend(data)
                        self.unresolved_seen = True
                        cpu.emu_stop()
                        return
                return super().on_syscall(cpu, _intno, _user)

        m_asym = OneSidedPeerRing(self.ring_img, self.manifest, cfg)
        m_asym.run()
        self.assertTrue(m_asym.unresolved_seen)
        rows_asym = [
            [int(raw[j:j + 8], 16) for j in range(7, 103, 8)]
            for raw in m_asym.stdout_buf.splitlines() if raw.startswith(b"M7CAP1=")
        ]
        self.assertTrue(any(r[1] == 13 and r[4] == 98 and r[5] == 186 and r[6] == 2 for r in rows_asym))

    def test_15_r8_review_regressions_mode_drain_waits_and_late_pre_trap_sub(self):
        from unicorn import UC_HOOK_CODE
        cfg = self._make_valid_ring_cfg()

        def rows_of(machine):
            return [
                [int(raw[j:j + 8], 16) for j in range(7, 103, 8)]
                for raw in machine.stdout_buf.splitlines() if raw.startswith(b"M7CAP1=")
            ]

        # 1. Both 250 ms waits inside mode_drain (busy connect_pair AND non-ready mode_snapshot),
        #    for BOTH temporary half release+re-press AND temporary sub_en dip+recovery ->
        #    MUST take zero-gap pre-trap SD restore: 0 POKETEXT, 0 sndcmd, 0 ARMED, 0 pulses, exit 0!
        for wait_kind in ("busy_connect", "nonready_snap"):
            for loss_kind in ("half", "sub"):
                class ModeDrainLossRing(RingV2Machine):
                    wk = wait_kind
                    lk = loss_kind
                    wait_start_ms = None
                    injected = False
                    def make_idle_regs(self, tid):
                        regs = super().make_idle_regs(tid)
                        if (self.wk == "busy_connect" and self.mode_4100 and
                                not self.poketext_log and not self.injected):
                            self.injected = True
                            self.wait_start_ms = self.clock_ms
                            regs[15] += 4  # Busy recorder forces 250 ms connect_pair retry inside mode_drain!
                        return regs
                    def on_syscall(self, cpu, _intno, _user):
                        a = self.arm
                        nr = cpu.reg_read(a.UC_ARM_REG_R7)
                        r4 = cpu.reg_read(a.UC_ARM_REG_R4)
                        if (self.wk == "nonready_snap" and self.mode_4100 and
                                not self.injected and nr == 180 and r4 == self.REC_MGR + 0x69C8):
                            # First mode_snapshot busy read after mode_set(0x4100) -> report busy so snapshot retries after 250 ms!
                            self.injected = True
                            self.wait_start_ms = self.clock_ms
                            self.put_im(self.REC_MGR + 0x69C8, 0x0100, 0)
                        elif (self.wk == "nonready_snap" and self.wait_start_ms is not None and
                                self.clock_ms >= self.wait_start_ms + 250 and nr == 180 and r4 == self.REC_MGR + 0x69C8):
                            self.put_im(self.REC_MGR + 0x69C8, 0, 0)
                        if self.wait_start_ms is not None:
                            lost = (self.clock_ms < self.wait_start_ms + 250)
                            if self.lk == "half":
                                self.half = 0 if lost else 1
                            else:
                                self.sub_enabled = 0 if lost else 1
                        return super().on_syscall(cpu, _intno, _user)

                m_md = ModeDrainLossRing(self.ring_img, self.manifest, cfg, disarm_in_armed=True)
                m_md.run()
                self.assertTrue(m_md.injected, f"{wait_kind}/{loss_kind} must inject wait")
                self.assertEqual(m_md.exit_code, 0, f"{wait_kind}/{loss_kind} must exit 0")
                self.assertEqual(m_md.poketext_log, [], f"{wait_kind}/{loss_kind} must install ZERO traps")
                self.assertEqual(m_md.sndcmd_calls, [], f"{wait_kind}/{loss_kind} must send ZERO S1/S2 commands")
                self.assertFalse(m_md.inserted_4100)
                self.assertFalse(m_md.mode_4100)
                self.assertEqual(m_md.traced, {})
                ev = rows_of(m_md)
                self.assertFalse(any(r[1] == 92 and r[4] == 55 and r[6] == 1 for r in ev))
                self.assertFalse(any(r[1] == 92 and r[4] == 34 for r in ev))

        # 2. Subscription loss occurring at entry of ram_precondition() (between mode_drain and capture_trap_set) ->
        #    MUST take pre-trap SD restore: 0 POKETEXT, 0 sndcmd, 0 ARMED, exit 0!
        m_pre = RingV2Machine(self.ring_img, self.manifest, cfg)
        site = self.manifest["ring"]["symbols"]["ram_precondition"]
        fired = []
        def drop_sub(*_args):
            fired.append(True)
            m_pre.sub_enabled = 0
        m_pre.cpu.hook_add(UC_HOOK_CODE, drop_sub, begin=site, end=site)
        m_pre.run()
        self.assertTrue(fired)
        self.assertEqual(m_pre.exit_code, 0)
        self.assertEqual(m_pre.poketext_log, [])
        self.assertEqual(m_pre.sndcmd_calls, [])
        self.assertFalse(m_pre.inserted_4100)
        self.assertFalse(m_pre.mode_4100)
        self.assertEqual(m_pre.traced, {})
        self.assertFalse(any(r[1] == 92 and r[4] == 55 and r[6] == 1 for r in rows_of(m_pre)))

    def test_16_r9_review_regressions_delayed_trace_stop_and_pre_s1_unwind(self):
        cfg = self._make_valid_ring_cfg()

        def rows_of(machine):
            return [
                [int(raw[j:j + 8], 16) for j in range(7, 103, 8)]
                for raw in machine.stdout_buf.splitlines() if raw.startswith(b"M7CAP1=")
            ]

        # 1. Delayed 250 ms recorder ptrace stop during ALL 4 pre-arm sites (Insert admission, pre-mode connect,
        #    mode_set call, and post-mode connect) with a 100 ms half-press or subscription loss (+50..+150 ms) ->
        #    MUST detect loss during wait_trace_stop, NEVER arm, ZERO capture pulses, restore cleanly, exit 0!
        for site in ("insert_attach", "premode_attach", "modeset_stop", "postmode_attach"):
            for gate in ("half", "sub"):
                class DelayedStopSiteRing(RingV2Machine):
                    st = site
                    gt = gate
                    start_ms = None
                    delayed_polls = 0
                    def on_syscall(self, cpu, _intno, _user):
                        a = self.arm
                        nr = cpu.reg_read(a.UC_ARM_REG_R7)
                        tid = cpu.reg_read(a.UC_ARM_REG_R0)
                        if nr == 114 and tid in self.traced:
                            match = False
                            if self.st == "insert_attach":
                                match = (not self.inserted_4100 and self.pullout_t_ms is None and len(self.sony_ops) == 0)
                            elif self.st == "premode_attach":
                                match = (self.inserted_4100 and not self.mode_4100 and self.pullout_t_ms is None and
                                         any(ln.startswith(b"M7CAP1=") and ln[15:23] == b"0000002d" and ln[39:47] == b"0000000a"
                                             for ln in bytes(self.stdout_buf).splitlines()))
                            elif self.st == "modeset_stop":
                                match = (self.mode_4100 and not self.poketext_log and len(self.traced) == 2)
                            elif self.st == "postmode_attach":
                                match = (self.mode_4100 and not self.poketext_log and len(self.traced) == 1)
                            if match and self.start_ms is None:
                                self.start_ms = self.clock_ms
                            if self.start_ms is not None:
                                age = self.clock_ms - self.start_ms
                                if age < 250:
                                    self.delayed_polls += 1
                                    cpu.reg_write(a.UC_ARM_REG_R0, 0)
                                    return
                        if self.start_ms is not None:
                            age = self.clock_ms - self.start_ms
                            low = (50 <= age < 150)
                            if self.gt == "half":
                                self.half = 0 if low else 1
                            else:
                                self.sub_enabled = 0 if low else 1
                        return super().on_syscall(cpu, _intno, _user)

                m_ds = DelayedStopSiteRing(self.ring_img, self.manifest, cfg, disarm_in_armed=True)
                m_ds.run()
                self.assertGreaterEqual(m_ds.delayed_polls, 10, f"{site}/{gate} must exercise delayed stop")
                self.assertEqual(m_ds.exit_code, 0, f"{site}/{gate} must exit 0")
                self.assertEqual(m_ds.poketext_log, [], f"{site}/{gate} must install ZERO traps")
                self.assertEqual(m_ds.sndcmd_calls, [], f"{site}/{gate} must send ZERO S1/S2 commands")
                if site == "insert_attach":
                    self.assertEqual(m_ds.sony_ops, [], f"{site}/{gate} must abort BEFORE Insert4100")
                self.assertFalse(m_ds.inserted_4100)
                self.assertFalse(m_ds.mode_4100)
                self.assertEqual(m_ds.traced, {})
                ev = rows_of(m_ds)
                self.assertFalse(any(r[1] == 92 and r[4] == 55 and r[6] == 1 for r in ev))
                self.assertFalse(any(r[1] == 92 and r[4] == 34 for r in ev))

        # 2. Loss occurring AFTER trap install during remote-owner detach (right before S1-down!) ->
        #    MUST unwind trap while rec_tid is still stopped, send ZERO S1 commands, restore SD, exit 0!
        for gate in ("half", "sub"):
            class PostTrapPreS1LossRing(RingV2Machine):
                gt = gate
                dropped = False
                def on_syscall(self, cpu, _intno, _user):
                    a = self.arm
                    nr = cpu.reg_read(a.UC_ARM_REG_R7)
                    # Trigger right as remote_tid (408) is detached (PTRACE_DETACH=17) after trap POKETEXT!
                    if nr == 26 and cpu.reg_read(a.UC_ARM_REG_R0) == 17 and cpu.reg_read(a.UC_ARM_REG_R1) == 408 and self.poketext_log and not self.dropped:
                        self.dropped = True
                        if self.gt == "half":
                            self.half = 0
                        else:
                            self.sub_enabled = 0
                    return super().on_syscall(cpu, _intno, _user)

            m_pt = PostTrapPreS1LossRing(self.ring_img, self.manifest, cfg)
            m_pt.run()
            self.assertTrue(m_pt.dropped)
            self.assertEqual(m_pt.exit_code, 0)
            self.assertEqual(len(m_pt.poketext_log), 2)
            self.assertEqual(m_pt.poketext_log[1], (m_pt.LIBOBJ + 0xA14C98, 0x531EF240))
            self.assertEqual(m_pt.sndcmd_calls, [], f"{gate}: MUST suppress S1-down completely!")
            self.assertFalse(m_pt.inserted_4100)
            self.assertFalse(m_pt.mode_4100)
            self.assertEqual(m_pt.traced, {})
            self.assertFalse(any(r[1] == 92 and r[4] == 55 and r[6] == 1 for r in rows_of(m_pt)))

        # 3. R10 regression: 100 ms subscription/half/disarm loss during pthread_setcancelstate preparation (BEFORE Insert4100!)
        #    MUST suppress Insert4100 itself, restore pthread cancel state, emit ZERO ARMED/pulses, and exit 0,
        #    while a legitimate 928 ms sub_en=0 dip starting WITH actual Insert4100 MUST still arm cleanly!
        for case in ("prep_sub", "prep_half", "prep_disarm", "insert_dip_928"):
            class PrepVsInsertRing(RingV2Machine):
                cs = case
                start_ms = None
                polls = 0
                def on_syscall(self, cpu, _intno, _user):
                    a = self.arm
                    nr = cpu.reg_read(a.UC_ARM_REG_R7)
                    tid = cpu.reg_read(a.UC_ARM_REG_R0)
                    pending = (nr == 114 and tid in self.traced)
                    if self.cs.startswith("prep_"):
                        if pending and self.start_ms is None and self.insert_t_ms is None and len(self.sony_ops) == 1:
                            assert self.sony_ops[0][0] == self.LIBPTHREAD + 0x9A48
                            self.start_ms = self.clock_ms
                        if self.start_ms is not None:
                            age = self.clock_ms - self.start_ms
                            low = (50 <= age < 150)
                            if self.cs == "prep_sub":
                                self.sub_enabled = 0 if low else 1
                            elif self.cs == "prep_half":
                                self.half = 0 if low else 1
                            else:
                                self.disarm_present = low
                            if pending and age < 250:
                                self.polls += 1
                                cpu.reg_write(a.UC_ARM_REG_R0, 0)
                                return
                    else:
                        # Positive control: delay actual Insert4100 return 250 ms while sub_en=0 for 928 ms from Insert start!
                        if pending and self.start_ms is None and self.insert_t_ms is not None:
                            self.start_ms = self.clock_ms
                        if self.start_ms is not None and pending and (self.clock_ms - self.start_ms) < 250:
                            self.polls += 1
                            cpu.reg_write(a.UC_ARM_REG_R0, 0)
                            return
                    return super().on_syscall(cpu, _intno, _user)

            m_pi = PrepVsInsertRing(
                self.ring_img, self.manifest, cfg,
                detached_insert_ms=550,
                insert_sub_dip_ms=(928 if case == "insert_dip_928" else 0),
                disarm_in_armed=True,
            )
            m_pi.run()
            self.assertEqual(m_pi.polls, 125, f"{case}: expected 125 delayed polls")
            self.assertEqual(m_pi.exit_code, 0)
            self.assertFalse(m_pi.inserted_4100)
            self.assertFalse(m_pi.mode_4100)
            self.assertEqual(m_pi.traced, {})
            ev = rows_of(m_pi)
            if case.startswith("prep_"):
                self.assertIsNone(m_pi.insert_t_ms, f"{case}: Insert4100 MUST NOT run!")
                self.assertEqual(m_pi.poketext_log, [])
                self.assertEqual(m_pi.sndcmd_calls, [])
                self.assertFalse(any(r[1] == 92 and r[4] == 55 and r[6] == 1 for r in ev))
            else:
                self.assertIsNotNone(m_pi.insert_t_ms)
                self.assertEqual(len(m_pi.poketext_log), 2)
                self.assertTrue(any(r[1] == 92 and r[4] == 55 and r[6] == 1 for r in ev))

        # 4. R11 regression: FIFO backpressure blocking kind-37 (pthread prep) OR kind-10 op-35 (Insert4100 announcement)
        #    while subscription drops before dispatch MUST suppress Insert4100 completely (zero ARMED/pulses/S1, exit 0)!
        for early in (11, 12):
            for gate in ("valid", "sub"):
                class FifoBackpressureRing(RingV2Machine):
                    def __init__(self, e_val, g_val):
                        super().__init__(
                            self_ring, self_man, cfg,
                            disarm_in_armed=True, detached_insert_ms=550,
                        )
                        self.early = e_val
                        self.gate = g_val
                        self.pending = 0
                        self.writes = 0
                        self.block = None
                        self.dispatch = None
                    def on_syscall(self, cpu, _intno, _user):
                        a = self.arm
                        nr = cpu.reg_read(a.UC_ARM_REG_R7)
                        fd = cpu.reg_read(a.UC_ARM_REG_R0)
                        buf = cpu.reg_read(a.UC_ARM_REG_R1)
                        n = cpu.reg_read(a.UC_ARM_REG_R2)
                        if nr == 4 and fd == 1 and self.block is None:
                            if self.writes == self.early:
                                self.pending = 0
                            if self.pending == 16 * (4096 // n):
                                line = bytes(cpu.mem_read(buf, n))
                                row = [int(line[j:j + 8], 16) for j in range(7, 103, 8)]
                                self.block = (self.clock_ms, row[1], row[4], self.writes)
                                self.clock_ms += 50
                                if self.gate == "sub":
                                    self.sub_enabled = 0
                                self.clock_ms += 200
                            self.writes += 1
                            self.pending += 1
                        if self.block is not None and self.gate == "sub":
                            self.sub_enabled = 1 if (self.clock_ms - self.block[0] >= 350) else 0
                        old_ins = self.insert_t_ms
                        en = self.sub_enabled
                        res = super().on_syscall(cpu, _intno, _user)
                        if old_ins is None and self.insert_t_ms is not None:
                            self.dispatch = (self.insert_t_ms, en)
                        return res

                self_ring, self_man = self.ring_img, self.manifest
                mf = FifoBackpressureRing(early, gate)
                mf.run()
                self.assertEqual(mf.block[1:3], (37, 0) if early == 11 else (10, 35))
                self.assertEqual(mf.exit_code, 0)
                self.assertFalse(mf.inserted_4100)
                self.assertFalse(mf.mode_4100)
                self.assertEqual(mf.traced, {})
                ev = rows_of(mf)
                if gate == "valid":
                    self.assertEqual(mf.dispatch, (10450, 1))
                    self.assertTrue(any(r[1] == 92 and r[4] == 55 and r[6] == 1 for r in ev))
                else:
                    self.assertIsNone(mf.dispatch, f"early={early} sub MUST suppress Insert4100!")
                    self.assertEqual(mf.poketext_log, [])
                    self.assertEqual(mf.sndcmd_calls, [])
                    self.assertFalse(any(r[1] == 92 and r[4] == 55 and r[6] == 1 for r in ev))

        # 5. R12 regression: indeterminate open() error (-EIO/-ENFILE/-EMFILE) on /stop or /disarm at the final
        #    Insert4100 dispatch gate MUST fail closed and suppress BOTH Insert4100 and Pullout4100!
        for marker in ("stop", "disarm"):
            for err in (0, 5, 23, 24):
                class MarkerLookupFaultRing(RingV2Machine):
                    mk = marker
                    er = err
                    setregs_seen = 0
                    injected = False
                    lookups = 0
                    def on_syscall(self, cpu, _intno, _user):
                        a = self.arm
                        nr = cpu.reg_read(a.UC_ARM_REG_R7)
                        r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                        # After kind-10 op-35 emit and PTRACE_SETREGS + PTRACE_GETREGS readback inside stage6_insert4100_call:
                        if nr == 26 and r0 == 12 and not self.injected and any(
                            ln.startswith(b"M7CAP1=") and ln[15:23] == b"0000000a" and ln[39:47] == b"00000023"
                            for ln in bytes(self.stdout_buf).splitlines()
                        ):
                            res = super().on_syscall(cpu, _intno, _user)
                            setattr(self, self.mk + "_present", True)
                            self.injected = True
                            return res
                        if self.injected and nr == 5 and self.read_cstr(r0).endswith("/" + self.mk):
                            self.lookups += 1
                            if self.lookups == 1 and self.er:
                                cpu.reg_write(a.UC_ARM_REG_R0, (-self.er) & 0xFFFFFFFF)
                                return
                        return super().on_syscall(cpu, _intno, _user)

                mm = MarkerLookupFaultRing(self.ring_img, self.manifest, cfg, detached_insert_ms=550)
                mm.run()
                self.assertTrue(mm.injected, f"{marker}/{err}: injection must fire")
                self.assertEqual(mm.exit_code, 0)
                self.assertIsNone(mm.insert_t_ms, f"{marker}/{err}: Insert4100 MUST be suppressed!")
                self.assertIsNone(mm.pullout_t_ms, f"{marker}/{err}: Pullout4100 MUST NOT run!")
                self.assertEqual(mm.poketext_log, [])
                self.assertEqual(mm.sndcmd_calls, [])
                self.assertEqual(mm.traced, {})
                self.assertFalse(any(r[1] == 92 and r[4] == 55 and r[6] == 1 for r in rows_of(mm)))

    def _make_custom_ring_cfg(self, *, before=5, after=0, burst_cap=16, backlog_cap=64, post_max=32, nonce="abcdef012345"):
        """Generate a valid run.cfg via real stage6_daemon.elf with custom WIP v3 cadence/window config."""
        def one_shot(m, t):
            m.half = 1 if t >= 150 else 0

        class CustomCfgDaemon(DaemonV2Machine):
            def __init__(self, img, man):
                super().__init__(img, man, nonce=nonce, scenario=one_shot, stop_file_ms=600)
                self.image = builder.configure_daemon(
                    img, man, duration_ms=60000, poll_ms=50, heartbeat_ms=500,
                    max_log_bytes=131072, daemonize=False, debounce_ms=100,
                    before=before, after=after, burst_cap=burst_cap,
                    backlog_cap=backlog_cap, post_max=post_max, nonce=nonce,
                )
                self.cpu.mem_write(0x10000, self.image)

        m = CustomCfgDaemon(self.daemon_img, self.manifest)
        m.run()
        self.assertGreaterEqual(len(m.ring_launches), 1)
        raw = m.ring_launches[0]["cfg"]
        buf = bytearray(raw)
        nr = struct.unpack_from("<I", buf, 28 + 20)[0]
        struct.pack_into("<I", buf, 28 + 20, nr + 1)
        struct.pack_into("<2I", buf, 28 + 60 + nr * 8, 0x02100000, 0x02200000)
        h = 0x811C9DC5
        for b in buf[16:]:
            h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
        struct.pack_into("<I", buf, 12, h)
        return bytes(buf)

    def _make_realistic_camera_ring(
        self,
        cfg,
        *,
        expose_period_ms=60,
        develop_period_ms=290,
        sndcmd_latency_ms=80,
        input_timeline=None,
        jpeg_bytes=None,
        trailing_bytes=None,
        sd_preexisting_files=None,
        stop_on_unresolved=False,
    ):
        from unicorn import UC_HOOK_CODE

        if jpeg_bytes is None:
            # 12 KiB valid 5472x3648 JPEG spanning > 1 S6_COPY_CHUNK (8192 B), plus EXIF APP1 + stuffed 0xFF 0x00!
            exif = b"\xff\xe1" + struct.pack(">H", 1024) + b"Exif\x00\x00" + (b"\xAB" * (1024 - 8))
            sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, 3648, 5472, 1) + b"\x01\x11\x00"
            sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
            scan = (b"\x11\x22\xff\x00\x33\x44" * 1800) + b"\xff\xd0" + (b"\x55\x66" * 300)
            jpeg_bytes = b"\xff\xd8" + exif + sof0 + sos + scan + b"\xff\xd9"
        if trailing_bytes is None:
            # Realistic Sony trailing MPF screennail JPEG (includes its own 0xFFD8 ... 0xFFD9!)
            trailing_bytes = b"\x00" * 128 + make_minimal_jpeg(1616, 1080) + b"\x00" * 64

        class RealisticCameraRing(RingV2Machine):
            MON_SP = 0x02104000
            REC_FRAME = 0x02120000
            REC_INFO = 0x02124000
            COMP_FRAME = 0x02125000
            COMP_MSG = 0x02125200
            COMP_PAIRS = 0x02125300
            COMP_VALS = 0x02125400
            POOL_NODES = 0x02130000
            JPEG_MMAP_META = 0x02142000
            MEDIA_PATH = 0x02143000
            STREAM_BASE = 0x20000000

            def __init__(self_m, ring_img, manifest, cfg_b):
                super().__init__(ring_img, manifest, cfg_b)
                self_m.expose_period_ms = expose_period_ms
                self_m.develop_period_ms = develop_period_ms
                self_m.sndcmd_latency_ms = sndcmd_latency_ms
                self_m.input_timeline = input_timeline
                self_m.main_jpeg = jpeg_bytes
                self_m.trailing_bytes = trailing_bytes
                self_m.stop_on_unresolved = stop_on_unresolved
                self_m.unresolved_seen = False

                # Real /dev/stream buffer: MWDI header (header[1] = 256) + main_jpeg + trailing MPF screennail!
                self_m.mwdi_hdr_len = 256
                self_m.mwdi_blob = (
                    struct.pack("<II", 0x4944574D, self_m.mwdi_hdr_len) +
                    bytes(self_m.mwdi_hdr_len - 8) +
                    self_m.main_jpeg +
                    self_m.trailing_bytes
                )
                self_m.stream_end = self_m.STREAM_BASE + ((len(self_m.mwdi_blob) + 0xFFFF) & ~0xFFFF)
                self_m.put_im(self_m.JPEG_MMAP_META + 0x28, self_m.STREAM_BASE, len(self_m.mwdi_blob))
                self_m.put_im_bytes(self_m.MEDIA_PATH, b"sd0\x00")

                # Extra Trap #2 / #3 original Sony instruction words
                self_m.put_im(self_m.LIBOBJ + 0xA146F4, 0xF0069602)
                self_m.put_im(self_m.LIBOBJ + 0xA126D8, 0x00F0F8D5)

                # Independent Sony camera physics state
                self_m.sw_s1 = 0
                self_m.sw_s2 = 0
                self_m.armed_clock_ms = None
                self_m.pending_sndcmd = {}  # pid -> (done_ms, key, pressed)
                self_m.last_cmd_intent = None
                self_m.sndcmd_events = []  # (ms, key, pressed)

                self_m.next_cap = 100
                self_m.next_uid = 5000
                self_m.rec_q_head = 0
                self_m.rec_q_tail = 0
                self_m.pending_frames = []  # list of (cap, uid)
                self_m.announced_log = []   # list of (ms, cap)
                self_m.next_expose_ms = None
                self_m.next_develop_ms = None

                self_m.pool_nodes = []  # list of dict(addr, uid, cap, user_count, mapped)
                self_m.held_by_helper = 0
                self_m.max_held_by_helper = 0
                self_m.helper_acquires = 0
                self_m.trap1_hits = 0
                self_m.trap2_hits = 0
                self_m.trap3_hits = 0
                self_m.active_frame = None  # dict(cap, uid, node)
                self_m.rec_stage = 0  # 0=idle/waiting trap1, 1=at trap1, 2=at trap2, 3=at trap3

                self_m.virtual_sd = {}
                if sd_preexisting_files:
                    for p_name, data in sd_preexisting_files.items():
                        self_m.virtual_sd[p_name] = bytearray(data)
                self_m.open_handles = {}
                self_m.next_handle = 100
                self_m.writefile_calls = 0
                self_m.closefile_calls = 0

                # Hook exact ARM symbol entries of sender() and s6_s2_spawn() to observe exact (key, val)
                syms = manifest["ring"]["symbols"]
                self_m.cpu.hook_add(UC_HOOK_CODE, self_m._on_sender, begin=syms["sender"], end=syms["sender"])
                self_m.cpu.hook_add(UC_HOOK_CODE, self_m._on_s2_spawn, begin=syms["s6_s2_spawn"], end=syms["s6_s2_spawn"])

            def _on_sender(self_m, cpu, _addr, _size, _ud):
                a = self_m.arm
                self_m.last_cmd_intent = (cpu.reg_read(a.UC_ARM_REG_R1), cpu.reg_read(a.UC_ARM_REG_R2))

            def _on_s2_spawn(self_m, cpu, _addr, _size, _ud):
                a = self_m.arm
                self_m.last_cmd_intent = (2, cpu.reg_read(a.UC_ARM_REG_R2))

            def _sync_pool_memory(self_m):
                active_any = any(n["mapped"] for n in self_m.pool_nodes)
                self_m.put_im(self_m.POOL_4100, self_m.POOL_MUT, 1 if active_any else 0, 0x4100)
                cnt = len(self_m.pool_nodes)
                first = self_m.pool_nodes[0]["addr"] if cnt else 0
                last = self_m.pool_nodes[-1]["addr"] if cnt else 0
                self_m.put_im(self_m.POOL_4100 + 0x70C4, first, last, cnt)
                self_m.put_im(self_m.POOL_4100 + 0x71C8, 0)
                for idx, n in enumerate(self_m.pool_nodes):
                    prev_a = self_m.pool_nodes[idx - 1]["addr"] if idx > 0 else 0
                    next_a = self_m.pool_nodes[idx + 1]["addr"] if idx + 1 < cnt else 0
                    self_m.put_im(n["addr"], prev_a, next_a, 0, n["uid"], n["cap"])
                    if n["mapped"]:
                        self_m.put_im(n["addr"] + 0x20, self_m.JPEG_MMAP_META, 0, 0, 0)
                        self_m.put_im(n["addr"] + 0x154, 1)
                        self_m.put_im(n["addr"] + 0x168, 1, 0, n["user_count"])
                    else:
                        self_m.put_im(n["addr"] + 0x20, 0, 0, 0, 0)
                        self_m.put_im(n["addr"] + 0x154, 0)
                        self_m.put_im(n["addr"] + 0x168, 0, 0, 0)

            def _make_ram_tuple(self_m, cap):
                return [0, 0x4100, 0, 0, 0x4100, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, cap, 2]

            def _step_camera_physics(self_m):
                if self_m.armed_clock_ms is not None and self_m.input_timeline is not None:
                    self_m.input_timeline(self_m, self_m.clock_ms - self_m.armed_clock_ms)

                # Complete any sndcmd children whose execution latency elapsed
                for pid, (done_ms, key, val) in list(self_m.pending_sndcmd.items()):
                    if self_m.clock_ms >= done_ms and key is not None:
                        if key == 1:
                            self_m.sw_s1 = val
                            if val == 1 and self_m.armed_clock_ms is None:
                                self_m.armed_clock_ms = self_m.clock_ms + 300
                        elif key == 2:
                            self_m.sw_s2 = val
                            if val == 1 and self_m.next_expose_ms is None:
                                self_m.next_expose_ms = self_m.clock_ms
                        self_m.sndcmd_events.append((self_m.clock_ms, key, val))
                        self_m.pending_sndcmd[pid] = (done_ms, None, None)

                if not self_m.mode_4100:
                    return

                # 1. Independent exposure clock (60 ms = 16.7 fps Continuous Hi, or slow shutter)
                if self_m.sw_s2 == 1 or self_m.full == 1:
                    if self_m.next_expose_ms is None:
                        self_m.next_expose_ms = self_m.clock_ms
                    while self_m.clock_ms >= self_m.next_expose_ms:
                        cap = self_m.next_cap
                        uid = self_m.next_uid
                        self_m.next_cap += 1
                        self_m.next_uid += 1
                        slot = self_m.rec_q_head
                        self_m.put_im(self_m.REC_MGR + 0x90 + slot * 52, *self_m._make_ram_tuple(cap))
                        self_m.rec_q_head = (slot + 1) % 513
                        self_m.put_im(self_m.REC_MGR + 0x88, self_m.rec_q_head, self_m.rec_q_tail)
                        self_m.pending_frames.append((cap, uid))
                        self_m.announced_log.append((self_m.next_expose_ms, cap))
                        if self_m.next_develop_ms is None:
                            self_m.next_develop_ms = self_m.next_expose_ms + self_m.develop_period_ms
                        self_m.next_expose_ms += self_m.expose_period_ms
                else:
                    self_m.next_expose_ms = None

                # 2. Independent BIONZ-X develop clock (290 ms = 3.45 fps) + real H-2 2-slot hardware stall!
                rec = self_m.traced.get(446)
                if (rec is not None and not rec["stopped"] and self_m.rec_stage == 0 and
                        self_m.pending_frames and self_m.next_develop_ms is not None and
                        self_m.clock_ms >= self_m.next_develop_ms):
                    # REAL H-2 LIMIT: Sony has only 2 mapped developed slots! If helper holds >= 2, develop STALLS!
                    if self_m.held_by_helper >= 2:
                        return
                    cap, uid = self_m.pending_frames.pop(0)
                    self_m.rec_q_tail = (self_m.rec_q_tail + 1) % 513
                    self_m.put_im(self_m.REC_MGR + 0x88, self_m.rec_q_head, self_m.rec_q_tail)

                    node_addr = self_m.POOL_NODES + len(self_m.pool_nodes) * 0x200
                    node = dict(addr=node_addr, uid=uid, cap=cap, user_count=1, mapped=True)
                    self_m.pool_nodes.append(node)
                    self_m._sync_pool_memory()

                    # Populate ObjStillRecorder frame & info at Trap #1 (0xa14c98)
                    self_m.put_im(self_m.REC_INFO, *self_m._make_ram_tuple(cap))
                    self_m.put_im(self_m.REC_FRAME, 0, 0, 0, uid)
                    self_m.put_im(self_m.REC_FRAME + 0x2938, uid, 0, 0)
                    self_m.put_im(self_m.REC_FRAME + 0x29AC, 0x000101)

                    assert (self_m.get_im_u32(self_m.LIBOBJ + 0xA14C98) & 0xFFFF) == 0xDE01, "Trap #1 must be armed!"
                    regs = list(rec["regs"])
                    regs[0] = 0
                    regs[4] = self_m.REC_CORE
                    regs[5] = self_m.REC_INFO
                    regs[6] = 0x99
                    regs[7] = self_m.REC_FRAME
                    regs[13] = self_m.REC_FRAME - 0x88
                    regs[15] = self_m.LIBOBJ + 0xA14C98
                    regs[16] = 0x30
                    rec["regs"] = regs
                    rec["stopped"] = True
                    rec["sig"] = 5
                    self_m.active_frame = dict(cap=cap, uid=uid, node=node)
                    self_m.rec_stage = 1
                    self_m.trap1_hits += 1

            def make_idle_regs(self_m, tid):
                if tid == 170:  # monitor_tid
                    regs = [0] * 18
                    regs[13] = self_m.MON_SP
                    regs[15] = self_m.LIBPTHREAD + 0xD144
                    regs[16] = 0x30
                    return regs
                return super().make_idle_regs(tid)

            def on_syscall(self_m, cpu, _intno, _user):
                a = self_m.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                r1 = cpu.reg_read(a.UC_ARM_REG_R1)
                r2 = cpu.reg_read(a.UC_ARM_REG_R2)
                r3 = cpu.reg_read(a.UC_ARM_REG_R3)

                if nr == 4 and r0 == 1 and self_m.stop_on_unresolved:
                    data = bytes(cpu.mem_read(r1, r2))
                    if data.startswith(b"M7CAP1=") and data[15:23] == b"0000000d" and data[39:47] == b"00000062":
                        self_m.stdout_buf.extend(data)
                        self_m.unresolved_seen = True
                        cpu.emu_stop()
                        return

                if nr == 5:
                    path = self_m.read_cstr(r0)
                    if path == "/proc/161/maps":
                        fd = self_m.next_fd; self_m.next_fd += 1
                        maps = (
                            f"{self_m.STREAM_BASE:08x}-{self_m.stream_end:08x} rw-s 00000000 00:00 0 /dev/stream\n"
                        ).encode("ascii")
                        self_m.fds[fd] = dict(kind="file", data=maps, pos=0)
                        cpu.reg_write(a.UC_ARM_REG_R0, fd)
                        return

                if nr == 2:  # fork (sndcmd.elf)
                    pid = 1900 + len(self_m.sndcmd_calls)
                    self_m.sndcmd_calls.append(pid)
                    key, val = self_m.last_cmd_intent if self_m.last_cmd_intent else (0, 0)
                    self_m.last_cmd_intent = None
                    self_m.pending_sndcmd[pid] = (self_m.clock_ms + self_m.sndcmd_latency_ms, key, val)
                    cpu.reg_write(a.UC_ARM_REG_R0, pid)
                    return

                if nr == 114 and r0 in self_m.pending_sndcmd:  # wait4 on sndcmd child
                    done_ms, _, _ = self_m.pending_sndcmd[r0]
                    self_m._step_camera_physics()
                    if self_m.clock_ms >= done_ms:
                        self_m.pending_sndcmd.pop(r0, None)
                        cpu.mem_write(r1, struct.pack("<I", 0))
                        cpu.reg_write(a.UC_ARM_REG_R0, r0)
                    else:
                        cpu.reg_write(a.UC_ARM_REG_R0, 0)
                    return

                if nr == 162:  # nanosleep -> advance clock and step camera physics!
                    res = super().on_syscall(cpu, _intno, _user)
                    self_m._step_camera_physics()
                    return res

                if nr == 26 and r0 == 7:  # PTRACE_CONT
                    tid = r1
                    st = self_m.traced[tid]
                    pc = st["regs"][15]
                    trap_va = self_m.LIBOBJ + 0x55ABC
                    if st["regs"][14] == (trap_va | 1):
                        a0, a1, a2 = st["regs"][0], st["regs"][1], st["regs"][2]
                        self_m.sony_ops.append((pc, a0, a1, a2))
                        ret_val = 0
                        if pc == self_m.LIBOBJ + 0x108B20 or pc == self_m.LIBOBJ + 0x10FAC4:
                            ret_val = 0
                        elif pc == (self_m.LIBOBJ + 0xDD1DD9) & ~1:  # GetImage
                            for n in self_m.pool_nodes:
                                if n["uid"] == a1:
                                    n["user_count"] += 1
                                    self_m.held_by_helper += 1
                                    self_m.helper_acquires += 1
                                    if self_m.held_by_helper > self_m.max_held_by_helper:
                                        self_m.max_held_by_helper = self_m.held_by_helper
                                    break
                            self_m._sync_pool_memory()
                            ret_val = 0
                        elif pc == (self_m.LIBOBJ + 0xDD1595) & ~1:  # ReleaseImage
                            for n in self_m.pool_nodes:
                                if n["uid"] == a1:
                                    n["user_count"] = max(0, n["user_count"] - 1)
                                    self_m.held_by_helper = max(0, self_m.held_by_helper - 1)
                                    if n["user_count"] == 0:
                                        n["mapped"] = False
                                    break
                            self_m._sync_pool_memory()
                            ret_val = 0
                        elif pc == self_m.LIBOBJ + 0x10D8DC:  # memcpy(dst, src, size)
                            off = a1 - self_m.STREAM_BASE
                            assert 0 <= off and off + a2 <= len(self_m.mwdi_blob), f"memcpy OOB off={off} n={a2}"
                            self_m.put_im_bytes(a0, self_m.mwdi_blob[off:off + a2])
                            ret_val = a0
                        elif pc == (self_m.LIBMPR + 0x7C54D5) & ~1:  # GetMediaPath
                            if a0 == 0:
                                self_m.put_im(a1, self_m.MEDIA_PATH)
                                ret_val = 1
                            else:
                                self_m.put_im(a1, 0)
                                ret_val = 0
                        elif pc == self_m.LIBMPR + 0x19E95C:  # GetDrive
                            ret_val = ord("A")
                        elif pc == self_m.LIBMPR + 0x19EC4C:  # GetMediaInfo
                            self_m.put_im(a1, 0x84000000)
                            ret_val = 0
                        elif pc == self_m.LIBMPR + 0x19E828:  # OpenFile(path, handle_out, flags)
                            raw_p = bytearray()
                            for k in range(64):
                                ch = self_m.im_mem.get(a0 + k, 0)
                                if ch == 0:
                                    break
                                raw_p.append(ch)
                            p_str = raw_p.decode("ascii")
                            if a2 == 1:
                                if p_str in self_m.virtual_sd:
                                    h = self_m.next_handle; self_m.next_handle += 1
                                    self_m.open_handles[h] = p_str
                                    self_m.put_im(a1, h)
                                    ret_val = 0
                                else:
                                    ret_val = 0x80000051
                            elif a2 == 7:
                                h = self_m.next_handle; self_m.next_handle += 1
                                self_m.open_handles[h] = p_str
                                self_m.virtual_sd[p_str] = bytearray()
                                self_m.put_im(a1, h)
                                ret_val = 0
                            else:
                                raise AssertionError(f"Unexpected OpenFile flags={a2}")
                        elif pc == self_m.LIBMPR + 0x19E664:  # WriteFile(handle, src, n)
                            p_str = self_m.open_handles[a0]
                            off = a1 - self_m.STREAM_BASE
                            assert 0 <= off and off + a2 <= len(self_m.mwdi_blob)
                            self_m.virtual_sd[p_str].extend(self_m.mwdi_blob[off:off + a2])
                            self_m.writefile_calls += 1
                            ret_val = a2
                        elif pc == self_m.LIBMPR + 0x19DD5C:  # CloseFile(handle)
                            self_m.open_handles.pop(a0, None)
                            self_m.closefile_calls += 1
                            ret_val = 0
                        else:
                            return super().on_syscall(cpu, _intno, _user)
                        st["regs"][0] = ret_val
                        st["regs"][15] = trap_va
                        st["regs"][16] = (st["regs"][16] & ~0x3F) | 0x30
                        st["stopped"] = True
                        st["sig"] = 5
                        cpu.reg_write(a.UC_ARM_REG_R0, 0)
                        return
                    elif tid == 446 and self_m.rec_stage == 1 and pc == self_m.LIBOBJ + 0xA153D2:
                        # Jumped from Trap #1 -> 0xa153d2 -> hits Trap #2 (0xa146f6)!
                        assert st["regs"][6] == 0, "r6 must be 0 at 0xa153d2"
                        assert (self_m.get_im_u32(self_m.LIBOBJ + 0xA146F4) >> 16) == 0xDE01, "Trap #2 must be armed!"
                        st["regs"][0] = self_m.REC_MGR
                        st["regs"][1] = 0xDEADBEEF  # Uninitialized [r7,#4], MUST be patched by ring.elf!
                        st["regs"][2] = 1
                        st["regs"][3] = self_m.REC_INFO
                        st["regs"][15] = self_m.LIBOBJ + 0xA146F6
                        st["regs"][16] = 0x30
                        st["stopped"] = True
                        st["sig"] = 5
                        self_m.rec_stage = 2
                        self_m.trap2_hits += 1
                        self_m.clock_ms += 1
                        cpu.reg_write(a.UC_ARM_REG_R0, 0)
                        return
                    elif tid == 446 and self_m.rec_stage == 2 and pc == self_m.LIBOBJ + 0xA146F6:
                        # Released at Trap #2 -> verify r1 == frame+0x2938!
                        assert st["regs"][1] == self_m.REC_FRAME + 0x2938, f"Bad r1 at Trap #2: {st['regs'][1]:#x}"
                        # Sony executes bl 0xa1b214 (ReleaseImage), decrementing Sony's own refcount!
                        node = self_m.active_frame["node"]
                        node["user_count"] = max(0, node["user_count"] - 1)
                        if node["user_count"] == 0:
                            node["mapped"] = False
                        self_m._sync_pool_memory()
                        trap3_armed = (self_m.get_im_u32(self_m.LIBOBJ + 0xA126D8) & 0xFFFF) == 0xDE01
                        if trap3_armed:
                            # Selected frame path -> populate ram_completion ParamMap and stop at Trap #3 (0xa126d8)!
                            cap = self_m.active_frame["cap"]
                            self_m.put_im(self_m.COMP_FRAME, *self_m._make_ram_tuple(cap))
                            self_m.put_im(self_m.COMP_FRAME + 0x5C, self_m.COMP_MSG)
                            self_m.put_im(self_m.COMP_MSG, 0, 0x3500, 0x10000004, 4, 0, self_m.COMP_PAIRS)
                            p0, p1, p2, p3 = self_m.COMP_VALS, self_m.COMP_VALS + 16, self_m.COMP_VALS + 32, self_m.COMP_VALS + 48
                            v2, pay2 = self_m.COMP_VALS + 64, self_m.COMP_VALS + 96
                            self_m.put_im(self_m.COMP_PAIRS, 0x1001, p0, 0x1002, p1, 0x100F, p2, 0x10000012, p3)
                            self_m.put_im(p0, 0, self_m.LIBMWF + 0x42CEC)
                            self_m.put_im(p1, cap, self_m.LIBMWF + 0x42CF8)
                            self_m.put_im(p2, v2, self_m.LIBMWF + 0x42C98)
                            self_m.put_im(p3, 0x200, self_m.LIBMWF + 0x42CF8)
                            self_m.put_im(v2, pay2, self_m.LIBMWF + 0x42D10, 52, 1)
                            self_m.put_im(pay2, *self_m._make_ram_tuple(cap))
                            st["regs"][5] = self_m.REC_CORE
                            st["regs"][7] = self_m.COMP_FRAME
                            st["regs"][13] = self_m.COMP_FRAME - 8
                            st["regs"][15] = self_m.LIBOBJ + 0xA126D8
                            st["regs"][16] = 0x30
                            st["stopped"] = True
                            st["sig"] = 5
                            self_m.rec_stage = 3
                            self_m.trap3_hits += 1
                        else:
                            # Fast unselected drop path -> Trap #3 skipped, Trap #1 already re-armed!
                            assert (self_m.get_im_u32(self_m.LIBOBJ + 0xA14C98) & 0xFFFF) == 0xDE01
                            st["regs"] = self_m.make_idle_regs(446)
                            st["stopped"] = False
                            self_m.active_frame = None
                            self_m.rec_stage = 0
                            self_m.next_develop_ms = max(self_m.next_develop_ms + self_m.develop_period_ms, self_m.clock_ms + 1)
                        cpu.reg_write(a.UC_ARM_REG_R0, 0)
                        return
                    elif tid == 446 and self_m.rec_stage == 3 and pc == self_m.LIBOBJ + 0xA126D8:
                        # Selected frame resumed after Trap #3 (ram_completion verified & Trap #1 re-armed)!
                        assert (self_m.get_im_u32(self_m.LIBOBJ + 0xA126D8) & 0xFFFF) != 0xDE01
                        assert (self_m.get_im_u32(self_m.LIBOBJ + 0xA14C98) & 0xFFFF) == 0xDE01
                        st["regs"] = self_m.make_idle_regs(446)
                        st["stopped"] = False
                        self_m.active_frame = None
                        self_m.rec_stage = 0
                        self_m.next_develop_ms = self_m.clock_ms + self_m.develop_period_ms
                        cpu.reg_write(a.UC_ARM_REG_R0, 0)
                        return

                return super().on_syscall(cpu, _intno, _user)

            def run(self_m):
                self_m.cpu.emu_start(self_m.manifest["ring"]["entry"], 0x10000 + self_m.manifest["ring"]["ro_size"], count=80000000)
                return self_m.exit_code

        return RealisticCameraRing(self.ring_img, self.manifest, cfg)

    def test_17_wip3_variant_a_two_phase_cadence_and_fast_unselected_drop(self):
        cfg = self._make_custom_ring_cfg(before=5, after=0, burst_cap=16, backlog_cap=64, post_max=32)

        def hold_5s_then_cancel(m, t_armed):
            if t_armed >= 5000:
                m.half = 0

        m = self._make_realistic_camera_ring(cfg, expose_period_ms=60, develop_period_ms=290, sndcmd_latency_ms=80, input_timeline=hold_5s_then_cancel)
        m.run()
        self.assertEqual(m.exit_code, 0)
        self.assertFalse(m.inserted_4100)
        self.assertFalse(m.mode_4100)
        self.assertEqual(m.traced, {})
        self.assertEqual(m.writefile_calls, 0)  # Cancel writes ZERO files!
        self.assertEqual(m.virtual_sd, {})

        # Parse M7CAP1 events
        rows = [
            [int(raw[j:j + 8], 16) for j in range(7, 103, 8)]
            for raw in m.stdout_buf.splitlines() if raw.startswith(b"M7CAP1=")
        ]
        summary = [r for r in rows if r[1] == 92 and r[4] == 8]
        cadence = [r for r in rows if r[1] == 92 and r[4] == 62]
        self.assertEqual(len(summary), 1)
        self.assertEqual(len(cadence), 1)

        delivered = summary[0][6]
        saved = summary[0][8]
        pulses, fast_drops, q_peak = cadence[0][5], cadence[0][6], cadence[0][7]
        self.assertEqual(saved, 0)
        # Frame #1 can legitimately arrive while queue==before (before frame #6 evicts it) and then be evicted/released;
        # all remaining >= 30 frames MUST take the fast unselected drop path (0 Trap #3, 0 hold_acquire)!
        self.assertGreaterEqual(fast_drops, delivered - 1)
        self.assertEqual(m.trap3_hits, delivered - fast_drops)
        self.assertEqual(m.helper_acquires, delivered - fast_drops)
        self.assertEqual(m.trap1_hits, delivered)
        self.assertEqual(m.trap2_hits, delivered)
        self.assertLessEqual(m.max_held_by_helper, 1)
        self.assertEqual(m.held_by_helper, 0)

        # Phase 1 proof: first 16 frames exposed at full ~16.7 fps (~1.0 s), with only ONE initial S2-down!
        self.assertGreaterEqual(len(m.announced_log), 28)
        phase1_dt = m.announced_log[15][0] - m.announced_log[0][0]
        self.assertLessEqual(phase1_dt, 1050, f"Phase 1 (16 frames) must hit ~15-17 fps, got dt={phase1_dt}ms")
        # Phase 2 proof: sustained rolling over 5 s delivers ~30+ frames (~6 fps incl Phase 1, >3.0 fps steady)
        # while keeping queue_peak bounded well below backlog_cap=64!
        self.assertGreaterEqual(delivered, 28)
        self.assertGreaterEqual(pulses, 3)  # Entered Phase 2 steady rolling after Phase 1!
        self.assertLessEqual(q_peak, 26)

    def test_18_wip3_hold_driven_unbounded_post_and_fast_save_25_files(self):
        cfg = self._make_custom_ring_cfg(before=5, after=0, burst_cap=16, backlog_cap=64, post_max=32)

        def hold_pre_then_hold_full_1200ms(m, t_armed):
            # Hold half for 1500 ms (Phase 1 fills pre=5), then hold full==1 for 1200 ms (~20 post frames!), then release!
            if 1500 <= t_armed < 2700:
                m.half = 1
                m.full = 1
            elif t_armed >= 2700:
                m.half = 0
                m.full = 0

        m = self._make_realistic_camera_ring(cfg, expose_period_ms=60, develop_period_ms=290, sndcmd_latency_ms=80, input_timeline=hold_pre_then_hold_full_1200ms)
        m.run()
        self.assertEqual(m.exit_code, 0)
        self.assertFalse(m.inserted_4100)
        self.assertFalse(m.mode_4100)
        self.assertEqual(m.traced, {})

        # Real H-2 single-slot guarantee across 25+ saved photos!
        self.assertLessEqual(m.max_held_by_helper, 1)

        # Must save > 20 unique PCxxxxxx.JPG files (> 16 proves zero 4-bit commit_sequence wrap collision!)
        self.assertGreaterEqual(len(m.virtual_sd), 22)
        self.assertEqual(len(m.virtual_sd), m.writefile_calls)
        self.assertEqual(m.closefile_calls, len(m.virtual_sd))
        for path, raw_bytes in m.virtual_sd.items():
            self.assertRegex(path, r"^A:\\PC[0-9A-F]{6}\.JPG$")
            # Byte-exact main JPEG length (trailing MPF screennail MUST NOT be included!)
            self.assertEqual(bytes(raw_bytes), m.main_jpeg)

        rows = [
            [int(raw[j:j + 8], 16) for j in range(7, 103, 8)]
            for raw in m.stdout_buf.splitlines() if raw.startswith(b"M7CAP1=")
        ]
        summary = [r for r in rows if r[1] == 92 and r[4] == 8]
        cadence = [r for r in rows if r[1] == 92 and r[4] == 62]
        self.assertEqual(summary[0][5], 1)  # saved_ok == 1
        self.assertEqual(summary[0][8], len(m.virtual_sd))
        self.assertEqual(summary[0][9], 0)  # reason == 0
        # Unselected frames before the 5 pre-frames took fast drop; ONLY selected (plus optional startup eviction) ran Trap #3 & hold_acquire!
        self.assertGreater(cadence[0][6], 10)  # fast_drops > 10
        self.assertEqual(m.trap3_hits, summary[0][6] - cadence[0][6])
        self.assertEqual(m.helper_acquires, summary[0][6] - cadence[0][6])
        self.assertLessEqual(m.trap3_hits, len(m.virtual_sd) + 1)
        self.assertEqual(m.held_by_helper, 0)

        # Feed real ring.elf stdout through real stage6_daemon.elf and verify card check end-to-end!
        ring_stdout = bytes(m.stdout_buf)
        ring_tok = struct.unpack_from("<I", cfg, 28 + 8)[0]

        def feed_real_ring_stream(dm, _seq, cfg_raw):
            # Rewrite token field in ring_stdout to match daemon's generated token
            d_tok = struct.unpack_from("<I", cfg_raw, 28 + 8)[0]
            old_h = f"M7CAP1={ring_tok:08x}".encode("ascii")
            new_h = f"M7CAP1={d_tok:08x}".encode("ascii")
            dm.ring_pipe_bytes.extend(ring_stdout.replace(old_h, new_h))
            dm.active_ring_exit_ms = dm.clock_ms + 200
            dm.active_ring_exit_status = 0

        dm = DaemonV2Machine(
            self.daemon_img, self.manifest, max_log_bytes=131072,
            scenario=lambda d, t: setattr(d, "half", 1 if 150 <= t < 500 else 0),
            ring_script=feed_real_ring_stream, stop_file_ms=1000,
        )
        dm.run(count=40000000)
        self.assertEqual(dm.exit_code, 0)
        parsed = runner.parse_daemon_log(dm.stdout_buf.decode("ascii"))
        self.assertEqual(parsed["ring_file_count"], len(m.virtual_sd))
        self.assertEqual(parsed["stop"]["r_sav"], str(len(m.virtual_sd)))
        self.assertEqual(parsed["stop"]["trunc"], "0")
        self.assertTrue(any(e["ev"] == "CADENCE" for e in parsed["ring_events"]))

        # Verify every logged RING_FILE against virtual SD files using real runner.verify_card_saved_files!
        with tempfile.TemporaryDirectory(prefix="s6v3-card-") as card_tmp:
            card = Path(card_tmp)
            for p_str, raw_b in m.virtual_sd.items():
                (card / p_str.split("\\")[-1]).write_bytes(bytes(raw_b))
            res = runner.verify_card_saved_files(card, parsed["ring_files"], expect_nonempty=True)
            self.assertTrue(res["all_ok"], f"Card check failed: {res}")
            self.assertEqual(res["checked"], len(m.virtual_sd))

    def test_19_wip3_edge_cases_chunk_boundary_jpeg_validation_slow_shutter_and_post_cap(self):
        # Case A: 0xFF | 0xD9 EOI straddling exact S6_COPY_CHUNK boundary (byte 8191 / 8192) + MPF screennail after it!
        sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, 3648, 5472, 1) + b"\x01\x11\x00"
        sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
        prefix = b"\xff\xd8" + sof0 + sos
        pad_len = 8191 - len(prefix)
        boundary_jpeg = prefix + (b"\x42" * pad_len) + b"\xff\xd9"
        self.assertEqual(len(boundary_jpeg), 8193)
        self.assertEqual(boundary_jpeg[8191], 0xFF)
        self.assertEqual(boundary_jpeg[8192], 0xD9)

        cfg_a = self._make_custom_ring_cfg(before=2, after=1, burst_cap=12, backlog_cap=40, post_max=16)
        def quick_trig(m, t):
            if 600 <= t < 800:
                m.full = 1
            elif t >= 800:
                m.half = 0; m.full = 0

        ma = self._make_realistic_camera_ring(cfg_a, input_timeline=quick_trig, jpeg_bytes=boundary_jpeg)
        ma.run()
        self.assertEqual(ma.exit_code, 0)
        self.assertEqual(len(ma.virtual_sd), 3)
        for raw_b in ma.virtual_sd.values():
            self.assertEqual(bytes(raw_b), boundary_jpeg)

        # Case B: Strict 5472x3648 lock rejects wrong resolution (3888x2592) cleanly (0 WriteFile calls, SD restored, reason=7)!
        bad_res_jpeg = make_minimal_jpeg(3888, 2592)
        mb = self._make_realistic_camera_ring(cfg_a, input_timeline=quick_trig, jpeg_bytes=bad_res_jpeg, stop_on_unresolved=True)
        mb.run()
        self.assertEqual(mb.exit_code, 0)
        self.assertFalse(mb.unresolved_seen)
        self.assertEqual(mb.writefile_calls, 0)
        self.assertEqual(mb.virtual_sd, {})
        self.assertEqual(mb.held_by_helper, 0)
        self.assertEqual(mb.traced, {})
        self.assertFalse(mb.mode_4100)
        self.assertFalse(mb.inserted_4100)

        # Case C: Truncated/missing EOI JPEG unwinds cleanly with ZERO WriteFile calls and SD restored!
        trunc_jpeg = boundary_jpeg[:-2]
        mc = self._make_realistic_camera_ring(cfg_a, input_timeline=quick_trig, jpeg_bytes=trunc_jpeg, trailing_bytes=b"\x00" * 64, stop_on_unresolved=True)
        mc.run()
        self.assertEqual(mc.exit_code, 0)
        self.assertFalse(mc.unresolved_seen)
        self.assertEqual(mc.writefile_calls, 0)
        self.assertEqual(mc.held_by_helper, 0)
        self.assertEqual(mc.traced, {})
        self.assertFalse(mc.mode_4100)

        # Case D: Existing file on SD (OpenFile flags=1 returns 0) refuses overwrite cleanly (0 WriteFile, CloseFile=1, SD restored)!
        tok_a = struct.unpack_from("<I", cfg_a, 28 + 8)[0]
        first_tok = (tok_a ^ 1) | 0x80000000
        first_name = f"A:\\PC{first_tok & 0xFFFFFF:06X}.JPG"
        md = self._make_realistic_camera_ring(cfg_a, input_timeline=quick_trig, sd_preexisting_files={first_name: b"ORIG"}, stop_on_unresolved=True)
        md.run()
        self.assertEqual(md.exit_code, 0)
        self.assertFalse(md.unresolved_seen)
        self.assertEqual(md.writefile_calls, 0)
        self.assertEqual(md.closefile_calls, 1)
        self.assertEqual(bytes(md.virtual_sd[first_name]), b"ORIG")
        self.assertEqual(md.held_by_helper, 0)
        self.assertEqual(md.traced, {})
        self.assertFalse(md.mode_4100)
        rows_d = [[int(v[j:j + 8], 16) for j in range(7, 103, 8)] for v in md.stdout_buf.splitlines() if v.startswith(b"M7CAP1=")]
        sum_d = [r for r in rows_d if r[1] == 92 and r[4] == 8]
        self.assertEqual(len(sum_d), 1)
        self.assertEqual(sum_d[0][5], 0)   # savedFlag == 0
        self.assertEqual(sum_d[0][9], 7)   # reason == 7 (clean save refusal)
        self.assertEqual(sum_d[0][10], 1)  # drained == 1

        # Case E: Hold-driven post_max safety ceiling (post_max=8) gracefully transitions PRECAP_POST->PRECAP_DRAIN & saves all 3+8=11!
        cfg_e = self._make_custom_ring_cfg(before=3, after=0, burst_cap=12, backlog_cap=40, post_max=8)
        def hold_past_post_max(m, t):
            if 800 <= t < 2500:
                m.full = 1  # Hold full way past 8 post frames (1700 ms = ~28 frames if uncapped!)
            elif t >= 2500:
                m.half = 0; m.full = 0

        me = self._make_realistic_camera_ring(cfg_e, input_timeline=hold_past_post_max)
        me.run()
        self.assertEqual(me.exit_code, 0)
        self.assertEqual(len(me.virtual_sd), 11)  # 3 pre + 8 post_max, cleanly saved!
        self.assertLessEqual(me.max_held_by_helper, 1)

        # Case F: Slow shutter / Continuous Lo (expose 350 ms > develop 290 ms) with before=5 -> ZERO H-2 2-slot deadlock!
        cfg_f = self._make_custom_ring_cfg(before=5, after=0, burst_cap=12, backlog_cap=40, post_max=16)
        def slow_shutter_trig(m, t):
            if 1800 <= t < 2600:
                m.full = 1
            elif t >= 2600:
                m.half = 0; m.full = 0

        mf = self._make_realistic_camera_ring(cfg_f, expose_period_ms=350, develop_period_ms=290, input_timeline=slow_shutter_trig)
        mf.run()
        self.assertEqual(mf.exit_code, 0)
        self.assertLessEqual(mf.max_held_by_helper, 1)  # Never deadlocked Sony's 2-slot buffer!
        self.assertGreaterEqual(len(mf.virtual_sd), 2)
        self.assertFalse(mf.inserted_4100)
        self.assertEqual(mf.traced, {})

    def test_20_wip3_astra_r1_blocker_regressions(self):
        from unicorn import UC_HOOK_CODE

        def parse_rows(buf: bytes):
            return [[int(v[j:j + 8], 16) for j in range(7, 103, 8)] for v in buf.splitlines() if v.startswith(b"M7CAP1=")]

        # 1a. Unreaped S2-down child (kill fails) MUST fail closed (UNRESOLVED 218/11), NEVER exit 0!
        cfg1 = self._make_custom_ring_cfg(before=2, after=1, burst_cap=8, backlog_cap=24, post_max=8)
        m0 = self._make_realistic_camera_ring(cfg1, input_timeline=lambda m, ms: setattr(m, "half", 0) if ms >= 3400 else None, stop_on_unresolved=True)
        class LateS2(type(m0)):
            pid = 0
            def on_syscall(self_m, cpu, intno, user):
                a = self_m.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0 = cpu.reg_read(a.UC_ARM_REG_R0)
                if nr == 2 and not self_m.pid and self_m.last_cmd_intent == (2, 1):
                    ret = super().on_syscall(cpu, intno, user)
                    self_m.pid = cpu.reg_read(a.UC_ARM_REG_R0)
                    _, k, v = self_m.pending_sndcmd[self_m.pid]
                    self_m.pending_sndcmd[self_m.pid] = (self_m.clock_ms + 60000, k, v)
                    return ret
                if nr == 37 and self_m.pid and r0 == self_m.pid:
                    cpu.reg_write(a.UC_ARM_REG_R0, (-1) & 0xFFFFFFFF)
                    return
                return super().on_syscall(cpu, intno, user)
        m_late = LateS2(self.ring_img, self.manifest, cfg1)
        m_late.run()
        self.assertTrue(m_late.unresolved_seen)
        self.assertIsNone(m_late.exit_code)

        # 1b. Reaped nonzero async S2-up and S2-down BOTH recover cleanly via compensating S2-up!
        for target_cmd in ((2, 0), (2, 1)):
            m_base = self._make_realistic_camera_ring(cfg1, input_timeline=lambda m, ms: setattr(m, "half", 0) if ms >= 3400 else None, stop_on_unresolved=True)
            class ReapedFailS2(type(m_base)):
                pid = 0
                injected = False
                def on_syscall(self_m, cpu, intno, user):
                    a = self_m.arm
                    nr = cpu.reg_read(a.UC_ARM_REG_R7)
                    r0, r1 = cpu.reg_read(a.UC_ARM_REG_R0), cpu.reg_read(a.UC_ARM_REG_R1)
                    if nr == 2 and not self_m.pid and self_m.last_cmd_intent == target_cmd:
                        ret = super().on_syscall(cpu, intno, user)
                        self_m.pid = cpu.reg_read(a.UC_ARM_REG_R0)
                        return ret
                    if nr == 114 and self_m.pid and r0 == self_m.pid:
                        ret = super().on_syscall(cpu, intno, user)
                        if cpu.reg_read(a.UC_ARM_REG_R0) == self_m.pid:
                            cpu.mem_write(r1, struct.pack("<I", 256))
                            self_m.injected = True
                        return ret
                    return super().on_syscall(cpu, intno, user)
            mf = ReapedFailS2(self.ring_img, self.manifest, cfg1)
            mf.run()
            self.assertTrue(mf.injected)
            self.assertEqual(mf.exit_code, 0)
            self.assertFalse(mf.unresolved_seen)
            self.assertEqual(mf.traced, {})
            self.assertEqual(mf.pending_sndcmd, {})
            self.assertFalse(mf.mode_4100)
            self.assertEqual(mf.sw_s2, 0)
            sums = [r for r in parse_rows(mf.stdout_buf) if r[1] == 92 and r[4] == 8]
            self.assertEqual(sums[0][9], 5)

        # 2. Held full past post_max (q-drain) AND past post_q_limit (short-queue) preserve ALL frozen frames!
        for tag, post_max, lo, hi, min_files in [("q-drain", 4, 600, 3000, 6), ("short-queue", 48, 800, 2000, 2)]:
            cfg2 = self._make_custom_ring_cfg(before=2, after=0, burst_cap=8, backlog_cap=24, post_max=post_max)
            def tl2(m, ms, _lo=lo, _hi=hi):
                if ms >= _lo: m.full = int(ms < _hi)
                if ms >= _hi: m.half = 0
            m2 = self._make_realistic_camera_ring(cfg2, input_timeline=tl2, stop_on_unresolved=True)
            m2.run()
            self.assertEqual(m2.exit_code, 0, tag)
            self.assertFalse(m2.unresolved_seen, tag)
            self.assertGreaterEqual(len(m2.virtual_sd), min_files, tag)
            sums = [r for r in parse_rows(m2.stdout_buf) if r[1] == 92 and r[4] == 8]
            self.assertEqual(sums[0][5], 1, tag)   # savedFlag == 1
            self.assertEqual(sums[0][9], 0, tag)   # reason == 0 (NOT erased by reason=12!)
            self.assertEqual(sums[0][8], len(m2.virtual_sd), tag)

        # 3. Shortened fixed after=24 window reports savedFlag=0, reason=13 (partial) + cutoff=3!
        cfg3 = self._make_custom_ring_cfg(before=5, after=24, burst_cap=12, backlog_cap=40, post_max=32)
        def tl3(m, ms):
            if ms >= 1800: m.full = int(ms < 3000)
            if ms >= 3000: m.half = 0
        m3 = self._make_realistic_camera_ring(cfg3, expose_period_ms=350, develop_period_ms=290, input_timeline=tl3, stop_on_unresolved=True)
        m3.run()
        self.assertEqual(m3.exit_code, 0)
        self.assertFalse(m3.unresolved_seen)
        self.assertEqual(len(m3.virtual_sd), 2)
        self.assertLessEqual(m3.max_held_by_helper, 1)
        rows3 = parse_rows(m3.stdout_buf)
        sum3 = [r for r in rows3 if r[1] == 92 and r[4] == 8][0]
        cad3 = [r for r in rows3 if r[1] == 92 and r[4] == 62][0]
        self.assertEqual(sum3[5], 0)    # savedFlag == 0 (partial fixed window!)
        self.assertEqual(sum3[8], 2)    # 2 files actually saved cleanly
        self.assertEqual(sum3[9], 13)   # reason == 13 (shortened fixed post window)
        self.assertEqual(sum3[11], 3)   # cutoff == 3 (H-2 single-slot guard)
        self.assertEqual(cad3[11], (24 << 16) | 3)

        # 4. Transient 8x busy pool-lock during save unwinds root lock & monitor_tid, releases ref, restores SD cleanly!
        m4_base = self._make_realistic_camera_ring(cfg1, input_timeline=lambda m, ms: (setattr(m, "full", int(600 <= ms < 800)), setattr(m, "half", 0) if ms >= 800 else None), stop_on_unresolved=True)
        class BusyLock8(type(m4_base)):
            sawsave = False
            busy_left = 8
            def on_syscall(self_m, cpu, intno, user):
                a = self_m.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0, r1, r2 = cpu.reg_read(a.UC_ARM_REG_R0), cpu.reg_read(a.UC_ARM_REG_R1), cpu.reg_read(a.UC_ARM_REG_R2)
                if nr == 4 and r0 == 1:
                    b = bytes(cpu.mem_read(r1, r2))
                    if b.startswith(b"M7CAP1=") and b[15:23] == b"0000005c" and b[39:47] == b"00000009":
                        self_m.sawsave = True
                if nr == 26 and r0 == 7 and r1 in self_m.traced and self_m.sawsave and self_m.busy_left > 0:
                    regs = self_m.traced[r1]["regs"]
                    if regs[15] == self_m.LIBOBJ + 0x108B20 and regs[0] == self_m.POOL_MUT + 4:
                        ret = super().on_syscall(cpu, intno, user)
                        regs[0] = 16  # EBUSY
                        self_m.busy_left -= 1
                        return ret
                return super().on_syscall(cpu, intno, user)
        m4 = BusyLock8(self.ring_img, self.manifest, cfg1)
        m4.run()
        self.assertEqual(m4.busy_left, 0)
        self.assertEqual(m4.exit_code, 0)
        self.assertFalse(m4.unresolved_seen)
        self.assertEqual(m4.held_by_helper, 0)
        self.assertEqual(m4.traced, {})
        self.assertFalse(m4.mode_4100)
        self.assertEqual(m4.writefile_calls, 0)
        self.assertEqual([r for r in parse_rows(m4.stdout_buf) if r[1] == 92 and r[4] == 8][0][9], 7)

        # 5. Malformed SOF (Nf=255) & SOS (Ns=0) rejected by BOTH native ring.elf AND host inspect_jpeg_file!
        base_j = make_minimal_jpeg()
        k_sos = base_j.index(b"\xff\xda")
        bad_sos = base_j[:k_sos + 4] + b"\x00" + base_j[k_sos + 5:]
        k_sof = base_j.index(b"\xff\xc0")
        bad_sof = base_j[:k_sof + 9] + b"\xff" + base_j[k_sof + 10:]
        with tempfile.TemporaryDirectory(prefix="s6v3-badj-") as tmp:
            for nm, blob in [("bad_sos.jpg", bad_sos), ("bad_sof.jpg", bad_sof)]:
                p = Path(tmp) / nm
                p.write_bytes(blob)
                self.assertFalse(runner.inspect_jpeg_file(p)["valid"], nm)
                m5 = self._make_realistic_camera_ring(
                    cfg1,
                    input_timeline=lambda m, ms: (setattr(m, "full", int(600 <= ms < 800)), setattr(m, "half", 0) if ms >= 800 else None),
                    jpeg_bytes=blob, stop_on_unresolved=True,
                )
                m5.run()
                self.assertEqual(m5.exit_code, 0, nm)
                self.assertFalse(m5.unresolved_seen, nm)
                self.assertEqual(len(m5.virtual_sd), 0, nm)
                self.assertEqual(m5.held_by_helper, 0, nm)
                self.assertEqual(m5.traced, {}, nm)

        # 6. 41-file slow save (5000 ms/close) cleanly stops at 75 s pre-save budget (reason=14, held=0, exit 0)!
        cfg6 = self._make_custom_ring_cfg(before=5, after=0, burst_cap=24, backlog_cap=96, post_max=48)
        m6_base = self._make_realistic_camera_ring(
            cfg6,
            input_timeline=lambda m, ms: (setattr(m, "full", int(800 <= ms < 4200)), setattr(m, "half", 0) if ms >= 4200 else None),
            stop_on_unresolved=True,
        )
        class SlowClose(type(m6_base)):
            def on_syscall(self_m, cpu, intno, user):
                prev = self_m.closefile_calls
                ret = super().on_syscall(cpu, intno, user)
                if self_m.closefile_calls != prev:
                    self_m.clock_ms += 5000
                return ret
        m6 = SlowClose(self.ring_img, self.manifest, cfg6)
        for step in range(4):
            if step == 0: m6.run()
            else: m6.cpu.emu_start(m6.cpu.reg_read(m6.arm.UC_ARM_REG_PC), 0x10000 + self.manifest["ring"]["ro_size"], count=80000000)
            if m6.unresolved_seen or m6.exit_code is not None:
                break
        self.assertEqual(m6.exit_code, 0)
        self.assertFalse(m6.unresolved_seen)
        self.assertEqual(m6.held_by_helper, 0)
        self.assertEqual(m6.traced, {})
        self.assertGreaterEqual(len(m6.virtual_sd), 10)
        self.assertLess(len(m6.virtual_sd), 41)
        sum6 = [r for r in parse_rows(m6.stdout_buf) if r[1] == 92 and r[4] == 8][0]
        self.assertEqual(sum6[9], 14)   # reason == 14 (save budget)
        self.assertEqual(sum6[8], len(m6.virtual_sd))

        # 7. Malformed pool header (count=1, head=0, tail=cand, cand.prev!=0) rejected by s6_retained_state!
        m7 = self._make_realistic_camera_ring(
            cfg1,
            input_timeline=lambda m, ms: (setattr(m, "full", int(600 <= ms < 800)), setattr(m, "half", 0) if ms >= 800 else None),
            stop_on_unresolved=True,
        )
        ret_holder = []
        def at_ret_state(c, _pc, _sz, _u):
            a = m7.arm
            cv = c.reg_read(a.UC_ARM_REG_R1)
            ret_lr = c.reg_read(a.UC_ARM_REG_LR)
            _, pool, _, cand, _, _, _, _ = struct.unpack("<8I", c.mem_read(cv, 32))
            m7.put_im(pool + 0x70C4, 0, cand, 1)
            m7.put_im(cand, 0x02168000, 0)
            c.hook_add(UC_HOOK_CODE, lambda cc, _p, _s, _uu: (ret_holder.append(cc.reg_read(a.UC_ARM_REG_R0)), cc.emu_stop()), begin=ret_lr, end=ret_lr)
        pc_rs = self.manifest["ring"]["symbols"]["s6_retained_state"]
        m7.cpu.hook_add(UC_HOOK_CODE, at_ret_state, begin=pc_rs, end=pc_rs)
        m7.run()
        self.assertEqual(ret_holder, [0])

        # 8. Native stage6_daemon.elf config validation parity (heartbeat, daemonize, toggle_bkid)!
        for idx, val in [(4, 0), (4, 60001), (6, 2), (7, 0)]:
            dx = DaemonV2Machine(self.daemon_img, self.manifest, stop_file_ms=400)
            dx.cpu.mem_write(0x10000 + self.manifest["daemon"]["config_offset"] + 4 * idx, struct.pack("<I", val))
            dx.run()
            self.assertEqual(dx.exit_code, 2, f"idx={idx} val={val}")
            self.assertEqual(dx.fork_count, 0, f"idx={idx} val={val}")

        # 9. Prolonged physical full==1 hold after empty pool drain does NOT fire 218/17 or 218/20!
        cfg9 = self._make_custom_ring_cfg(before=3, after=0, burst_cap=12, backlog_cap=40, post_max=8)
        m9 = self._make_realistic_camera_ring(
            cfg9, expose_period_ms=7000, develop_period_ms=400,
            input_timeline=lambda m, ms: (setattr(m, "full", int(800 <= ms < 34500)), setattr(m, "half", 0) if ms >= 34500 else None),
            stop_on_unresolved=True,
        )
        m9.run()
        self.assertEqual(m9.exit_code, 0)
        self.assertFalse(m9.unresolved_seen)
        self.assertEqual(len(m9.virtual_sd), 2)
        self.assertEqual(m9.held_by_helper, 0)
        self.assertEqual(m9.traced, {})
        self.assertFalse(m9.mode_4100)

    def test_21_wip3_astra_r2_blocker_regressions(self):
        def parse_rows(buf: bytes):
            return [[int(v[j:j + 8], 16) for j in range(7, 103, 8)] for v in buf.splitlines() if v.startswith(b"M7CAP1=")]

        # 1. Cancel overlapping a reaped failed S2-down, S2-up, or second-kill child MUST restore SD cleanly!
        cfg1 = self._make_custom_ring_cfg(before=2, after=0, burst_cap=8, backlog_cap=24, post_max=8)
        for case in ("cancel-down", "cancel-up", "kill-retry"):
            def tl1(m, ms, _c=case):
                a = getattr(m, "forked_at", None)
                if a is not None:
                    delta = m.clock_ms - a
                    if _c.startswith("cancel") or delta >= 600:
                        m.half = 0
                elif ms >= 4000:
                    m.half = 0
            m0 = self._make_realistic_camera_ring(cfg1, input_timeline=tl1, stop_on_unresolved=True)
            class CancelFailS2(type(m0)):
                pid = 0; forked_at = None; kills = 0; saw = False
                def on_syscall(self_m, c, i, u):
                    a = self_m.arm
                    nr, r0, r1 = [c.reg_read(x) for x in (a.UC_ARM_REG_R7, a.UC_ARM_REG_R0, a.UC_ARM_REG_R1)]
                    if nr == 2 and not self_m.pid and self_m.last_cmd_intent == (2, int(not case.endswith("up"))):
                        res = super().on_syscall(c, i, u)
                        self_m.pid = c.reg_read(a.UC_ARM_REG_R0)
                        self_m.forked_at = self_m.clock_ms
                        _, k, v = self_m.pending_sndcmd[self_m.pid]
                        self_m.pending_sndcmd[self_m.pid] = (self_m.clock_ms + (60000 if case == "kill-retry" else 240), k, v)
                        return res
                    if nr == 37 and self_m.pid and r0 == self_m.pid:
                        self_m.kills += 1
                        if case == "kill-retry":
                            if self_m.kills == 2:
                                self_m.pending_sndcmd[self_m.pid] = (self_m.clock_ms, None, None)
                            c.reg_write(a.UC_ARM_REG_R0, 0 if self_m.kills == 2 else 0xFFFFFFFF)
                            return
                    if nr == 114 and self_m.pid and r0 == self_m.pid:
                        ret = super().on_syscall(c, i, u)
                        if c.reg_read(a.UC_ARM_REG_R0) == self_m.pid:
                            self_m.saw = True
                            c.mem_write(r1, struct.pack("<I", 9 if case == "kill-retry" else 256))
                        return ret
                    return super().on_syscall(c, i, u)
            mc = CancelFailS2(self.ring_img, self.manifest, cfg1)
            mc.run()
            self.assertTrue(mc.saw, case)
            self.assertEqual(mc.exit_code, 0, case)
            self.assertFalse(mc.unresolved_seen, case)
            self.assertEqual(mc.held_by_helper, 0, case)
            self.assertEqual(mc.traced, {}, case)
            self.assertEqual(mc.pending_sndcmd, {}, case)
            self.assertFalse(mc.mode_4100, case)
            self.assertEqual(mc.sw_s2, 0, case)

        # 2. Fixed-window 30 s timer preserves frozen pre-frame and reports savedFlag=0, reason=13, cutoff=5!
        cfg2 = self._make_custom_ring_cfg(before=3, after=5, burst_cap=12, backlog_cap=40, post_max=8)
        def tl2(m, ms):
            if ms >= 850 and not hasattr(m, "jumped"):
                m.jumped = True
                m.clock_ms += 30000
            if ms >= 800:
                m.full = int(ms < 31200)
            if ms >= 31200:
                m.half = 0
        m2 = self._make_realistic_camera_ring(cfg2, expose_period_ms=60000, develop_period_ms=290, input_timeline=tl2, stop_on_unresolved=True)
        m2.run()
        self.assertEqual(m2.exit_code, 0)
        self.assertFalse(m2.unresolved_seen)
        self.assertEqual(len(m2.virtual_sd), 1)
        sum2 = [r for r in parse_rows(m2.stdout_buf) if r[1] == 92 and r[4] == 8][0]
        self.assertEqual(sum2[5], 0)   # savedFlag == 0 (partial fixed window)
        self.assertEqual(sum2[8], 1)   # 1 frozen pre-frame preserved & saved!
        self.assertEqual(sum2[9], 13)  # reason == 13
        self.assertEqual(sum2[11], 5)  # cutoff == 5 (post_timer)

        # 3. Mixed-latency progressing save (2.2 s closes + 28.6 s final close at ~58 s) completes inside daemon's 140 s hard stop!
        cfg3 = self._make_custom_ring_cfg(before=5, after=0, burst_cap=24, backlog_cap=96, post_max=48)
        m3_base = self._make_realistic_camera_ring(
            cfg3,
            input_timeline=lambda m, ms: (setattr(m, "full", int(800 <= ms < 4200)), setattr(m, "half", 0) if ms >= 4200 else None),
            stop_on_unresolved=True,
        )
        class MixedClose(type(m3_base)):
            drain = None; long_done = False
            def on_syscall(self_m, c, i, u):
                a = self_m.arm
                nr, fd, buf, n = [c.reg_read(q) for q in (a.UC_ARM_REG_R7, a.UC_ARM_REG_R0, a.UC_ARM_REG_R1, a.UC_ARM_REG_R2)]
                if nr == 4 and fd == 1 and n == 104:
                    b = bytes(c.mem_read(buf, n))
                    r = [int(b[j:j + 8], 16) for j in range(7, 103, 8)]
                    if r[1] == 92 and r[4] == 11:
                        self_m.drain = self_m.clock_ms
                prev = self_m.closefile_calls
                ret = super().on_syscall(c, i, u)
                if prev != self_m.closefile_calls and self_m.drain is not None:
                    el = self_m.clock_ms - self_m.drain
                    if not self_m.long_done and el > 56000:
                        self_m.clock_ms += 28600
                        self_m.long_done = True
                    elif not self_m.long_done:
                        self_m.clock_ms += 2200
                return ret
        m3 = MixedClose(self.ring_img, self.manifest, cfg3)
        for step in range(8):
            if step == 0: m3.run()
            else: m3.cpu.emu_start(m3.cpu.reg_read(m3.arm.UC_ARM_REG_PC), 0x10000 + self.manifest["ring"]["ro_size"], count=80000000)
            if m3.exit_code is not None or m3.unresolved_seen:
                break
        self.assertTrue(m3.long_done)
        self.assertEqual(m3.exit_code, 0)
        self.assertFalse(m3.unresolved_seen)
        self.assertEqual(m3.held_by_helper, 0)
        rows3 = parse_rows(m3.stdout_buf)
        dr3 = next(r[3] for r in rows3 if r[1] == 92 and r[4] == 11)
        exit_elapsed = m3.clock_ms - m3.drain
        self.assertLess(exit_elapsed, 130000)
        # Replay timestamped ring events through real stage6_daemon.elf aligned at DRAIN!
        timed = [(r[3] - dr3, r) for r in rows3 if r[3] >= dr3]
        def launch_cb(x, *_):
            x.active_ring_hang = True
            x.idx = 0
        def clock_cb(x, t):
            x.half = int(t >= 150)
            if x.active_ring_pid and t >= 600:
                tok = struct.unpack_from("<I", x.ring_launches[0]["cfg"], 36)[0]
                while x.idx < len(timed) and timed[x.idx][0] <= t - 600:
                    _, r = timed[x.idx]
                    x.idx += 1
                    x.ring_pipe_bytes.extend(fmt_m7cap(tok, r[1], r[2], r[3], *r[4:]))
                if t - 600 >= exit_elapsed:
                    x.active_ring_hang = False
        dm = DaemonV2Machine(self.daemon_img, self.manifest, scenario=clock_cb, ring_script=launch_cb, stop_file_ms=600)
        dm.run(count=80000000)
        stop_rec = runner.parse_daemon_log(dm.stdout_buf.decode("ascii"))["stop"]
        self.assertEqual(stop_rec["r_reap"], "1")
        self.assertEqual(stop_rec["r_sav"], str(len(m3.virtual_sd)))

        # 4. Impossible SOF2 + baseline SOS (Ss=0/Se=63), SOF0 precision=12, and RST before SOF rejected by BOTH!
        j = make_minimal_jpeg()
        def chg(blob, idx, val): return blob[:idx] + bytes([val]) + blob[idx + 1:]
        bad_variants = {
            "progressive-marker-only": chg(j, 3, 0xC2),
            "baseline12": chg(j, 6, 12),
            "restart-before-sof": j[:2] + b"\xff\xd0" + j[2:],
        }
        with tempfile.TemporaryDirectory(prefix="s6v3-r2jpg-") as tmp:
            for nm, blob in bad_variants.items():
                p = Path(tmp) / f"{nm}.jpg"
                p.write_bytes(blob)
                self.assertFalse(runner.inspect_jpeg_file(p)["valid"], nm)
                mj = self._make_realistic_camera_ring(
                    cfg1,
                    input_timeline=lambda m, ms: (setattr(m, "full", int(600 <= ms < 800)), setattr(m, "half", 0) if ms >= 800 else None),
                    jpeg_bytes=blob, trailing_bytes=b"", stop_on_unresolved=True,
                )
                mj.run()
                self.assertEqual(mj.exit_code, 0, nm)
                self.assertFalse(mj.unresolved_seen, nm)
                self.assertEqual(len(mj.virtual_sd), 0, nm)
                self.assertEqual(mj.held_by_helper, 0, nm)

        # 5. 85 s full hold after completing 2/2 selected saves keeps savedFlag=1, reason=0 (no spurious reason=14)!
        cfg5 = self._make_custom_ring_cfg(before=3, after=0, burst_cap=12, backlog_cap=40, post_max=8)
        m5 = self._make_realistic_camera_ring(
            cfg5, expose_period_ms=7000, develop_period_ms=400,
            input_timeline=lambda m, ms: (setattr(m, "full", int(800 <= ms < 85000)), setattr(m, "half", 0) if ms >= 85000 else None),
            stop_on_unresolved=True,
        )
        for step in range(5):
            if step == 0: m5.run()
            else: m5.cpu.emu_start(m5.cpu.reg_read(m5.arm.UC_ARM_REG_PC), 0x10000 + self.manifest["ring"]["ro_size"], count=80000000)
            if m5.exit_code is not None or m5.unresolved_seen:
                break
        self.assertEqual(m5.exit_code, 0)
        self.assertFalse(m5.unresolved_seen)
        self.assertEqual(len(m5.virtual_sd), 2)
        sum5 = [r for r in parse_rows(m5.stdout_buf) if r[1] == 92 and r[4] == 8][0]
        self.assertEqual(sum5[5], 1)  # savedFlag == 1!
        self.assertEqual(sum5[8], 2)  # both selected files saved
        self.assertEqual(sum5[9], 0)  # reason == 0 (NOT spurious 14!)

    def test_22_wip3_astra_r3_supervision_through_slow_drain_and_long_hold(self):
        # Verify daemon retains supervision across ring's full 180 s PRECAP_DRAIN_ABSOLUTE_MS + SD-restore envelope
        # (RING_STOP_HARD_MAX_MS = 210 s, collector max_polls = 220) while still reporting UNRESOLVED past 180 s.
        def parse_rows(buf: bytes):
            return [[int(v[j:j + 8], 16) for j in range(7, 103, 8)] for v in buf.splitlines() if v.startswith(b"M7CAP1=")]

        cfg = self._make_custom_ring_cfg(before=5, after=0, burst_cap=24, backlog_cap=128, post_max=96)
        for label, hi, expose, develop, expect_files, expect_reason, align_release in [
            ("release-align", 7300, 60, 1350, 41, 14, True),
            ("held-159s", 159000, 7000, 400, 2, 0, False),
        ]:
            def tl(m, ms, _hi=hi, _ar=align_release):
                m.full = int(800 <= ms < _hi)
                m.half = int(ms < _hi)
                if _ar and ms >= _hi and not m.stop_present:
                    m.disarm_present = True
                    m.stop_present = True
                    m.owner_stop = m.clock_ms

            base = self._make_realistic_camera_ring(
                cfg, input_timeline=tl, expose_period_ms=expose, develop_period_ms=develop, stop_on_unresolved=True,
            )
            class SupMon(type(base)):
                drain = None
                owner_stop = None
                def on_syscall(self_m, c, i, u):
                    a = self_m.arm
                    nr, fd, buf, n = [c.reg_read(q) for q in (a.UC_ARM_REG_R7, a.UC_ARM_REG_R0, a.UC_ARM_REG_R1, a.UC_ARM_REG_R2)]
                    if nr == 4 and fd == 1 and n == 104:
                        b = bytes(c.mem_read(buf, n))
                        r = [int(b[j:j + 8], 16) for j in range(7, 103, 8)]
                        if r[1] == 92 and r[4] == 11 and self_m.drain is None:
                            self_m.drain = self_m.clock_ms
                            if not align_release:
                                self_m.disarm_present = True
                                self_m.stop_present = True
                                self_m.owner_stop = self_m.clock_ms
                    return super().on_syscall(c, i, u)

            m = SupMon(self.ring_img, self.manifest, cfg)
            for k in range(35):
                if k == 0: m.run()
                else: m.cpu.emu_start(m.cpu.reg_read(m.arm.UC_ARM_REG_PC), 0x10000 + self.manifest["ring"]["ro_size"], count=80000000)
                if m.exit_code is not None or m.unresolved_seen:
                    break
            self.assertEqual(m.exit_code, 0, label)
            self.assertFalse(m.unresolved_seen, label)
            self.assertEqual(m.held_by_helper, 0, label)
            self.assertFalse(m.mode_4100, label)
            self.assertEqual(len(m.virtual_sd), expect_files, label)
            rows = parse_rows(m.stdout_buf)
            dr = next(r[3] for r in rows if r[1] == 92 and r[4] == 11)
            stop_offset = dr + (m.owner_stop - m.drain)
            exit_after_stop = m.clock_ms - m.owner_stop
            sum_r = [r for r in rows if r[1] == 92 and r[4] == 8][0]
            self.assertEqual(sum_r[8], expect_files, label)
            self.assertEqual(sum_r[9], expect_reason, label)

            # Full-stream replay through real stage6_daemon.elf from ring launch through stop & reap!
            start = 600
            stop_at = start + stop_offset
            def launch_cb(x, *_):
                x.idx = 0
                x.active_ring_hang = True
            def feed_cb(x, tm, _rows=rows, _start=start, _stop=stop_at, _el=exit_after_stop):
                x.half = int(tm >= 150)
                if x.active_ring_pid and tm >= _start:
                    tok = struct.unpack_from("<I", x.ring_launches[0]["cfg"], 36)[0]
                    while x.idx < len(_rows) and _rows[x.idx][3] <= tm - _start:
                        r = _rows[x.idx]
                        x.idx += 1
                        x.ring_pipe_bytes.extend(fmt_m7cap(tok, *r[1:]))
                    if tm - _stop >= _el:
                        x.active_ring_hang = False
            dm = DaemonV2Machine(self.daemon_img, self.manifest, scenario=feed_cb, ring_script=launch_cb, stop_file_ms=stop_at, max_log_bytes=131072)
            dm.run(count=800000000)
            log = dm.stdout_buf.decode("ascii")
            stop_rec = runner.parse_daemon_log(log)["stop"]
            self.assertEqual(stop_rec["r_reap"], "1", label)
            self.assertEqual(stop_rec["r_sav"], str(expect_files), label)
            self.assertEqual(stop_rec["trunc"], "0", label)
            self.assertEqual(log.count("ev=PHASE_BAD"), 0, label)
            self.assertEqual(log.count("ev=SUMMARY"), 1, label)

        # Stuck drain crossing 180 s PRECAP_DRAIN_ABSOLUTE_MS MUST still report explicit UNRESOLVED before 210 s daemon cap!
        def tl_stuck(m, ms):
            m.full = int(800 <= ms < 250000)
            m.half = int(ms < 250000)
            if ms >= 1200 and not hasattr(m, "jumped_post"):
                m.jumped_post = True
                m.clock_ms += 30500
            elif ms >= 35000 and len(m.virtual_sd) >= 1 and not hasattr(m, "jumped_drain"):
                m.jumped_drain = True
                m.clock_ms += 179000
        m_stuck = self._make_realistic_camera_ring(
            cfg, expose_period_ms=60000, develop_period_ms=400,
            input_timeline=tl_stuck, stop_on_unresolved=True,
        )
        m_stuck.run()
        self.assertTrue(m_stuck.unresolved_seen)
        self.assertIsNone(m_stuck.exit_code)
        stuck_rows = parse_rows(m_stuck.stdout_buf)
        unres_rows = [r for r in stuck_rows if r[1] == 13 and r[4] == 98]
        self.assertEqual(unres_rows[-1][5:7], [218, 22])
        # Verify daemon catches UNRESOLVED at 180 s immediately (well before 210 s hard stop) and latches fault!
        dr_st = next(r[3] for r in stuck_rows if r[1] == 92 and r[4] == 11)
        unres_dt = unres_rows[-1][3] - dr_st
        self.assertGreaterEqual(unres_dt, 180000)
        self.assertLess(unres_dt, 200000)
        def feed_stuck(x, tm):
            x.half = int(tm >= 150)
            if x.active_ring_pid and tm >= 600:
                tok = struct.unpack_from("<I", x.ring_launches[0]["cfg"], 36)[0]
                if (tm - 600) % 10000 == 0 and tm - 600 < unres_dt:
                    x.ring_pipe_bytes.extend(fmt_m7cap(tok, 92, 28, tm, 25, 3, 0, 1, 1))
                if tm - 600 >= unres_dt and not getattr(x, "sent_unres", False):
                    x.sent_unres = True
                    x.ring_pipe_bytes.extend(fmt_m7cap(tok, 13, 28, tm, 98, 218, 22, 446))
        dm_st = DaemonV2Machine(
            self.daemon_img, self.manifest, scenario=feed_stuck,
            ring_script=lambda x, *_: setattr(x, "active_ring_hang", True),
            stop_file_ms=600,
        )
        dm_st.run(count=200000000)
        st_stop = runner.parse_daemon_log(dm_st.stdout_buf.decode("ascii"))["stop"]
        self.assertEqual(st_stop["r_unres"], "1")
        self.assertEqual(st_stop["r_flt"], "1")
        self.assertEqual(st_stop["r_reap"], "0")
        self.assertLess(int(st_stop["t"]) - 600, 240000)

        # Bounded max-retry SD restoration (30.9 s post-SUMMARY) after 179.8 s drain MUST be reaped inside 240 s cap!
        b_events = []
        def b_buttons(m, ms):
            lifted = m.drain is not None and m.clock_ms - m.drain >= 179800
            m.half = int(not lifted)
            m.full = int(ms >= 800 and not lifted)
            if m.drain is not None and len(m.virtual_sd) >= 2 and not m.pending_frames and m.active_frame is None and not hasattr(m, "jumped_179"):
                m.jumped_179 = True
                m.clock_ms = m.drain + 179700
                m.next_expose_ms = m.clock_ms + 7000
        b_base = self._make_realistic_camera_ring(cfg, input_timeline=b_buttons, expose_period_ms=7000, develop_period_ms=400, stop_on_unresolved=True)
        class BoundedRestore(type(b_base)):
            drain = summary = None
            busy_caller = snapshot = False
            snapshots = busy = 0
            def make_idle_regs(self_m, tid):
                regs = super().make_idle_regs(tid)
                if self_m.busy_caller:
                    self_m.busy_caller = False
                    self_m.busy += 1
                    regs[15] += 4
                return regs
            def on_syscall(self_m, c, i, u):
                a = self_m.arm
                nr = c.reg_read(a.UC_ARM_REG_R7)
                if nr == 4 and c.reg_read(a.UC_ARM_REG_R0) == 1 and c.reg_read(a.UC_ARM_REG_R2) == 104:
                    b = bytes(c.mem_read(c.reg_read(a.UC_ARM_REG_R1), 104))
                    row = [int(b[j:j + 8], 16) for j in range(7, 103, 8)]
                    b_events.append((self_m.clock_ms, row))
                    if row[1] == 92 and row[4] == 11 and self_m.drain is None:
                        self_m.drain = self_m.clock_ms
                        self_m.stop_present = self_m.disarm_present = True
                    if row[1] == 92 and row[4] == 8:
                        self_m.summary = self_m.clock_ms
                    if self_m.summary is not None:
                        if (row[1], row[4], row[5]) in ((45, 10, 3), (58, 2, 2)):
                            self_m.busy_caller = row[6] < 8
                        if row[1] == 55 and row[4] == 50:
                            self_m.snapshot = True
                        if row[1] == 54 and row[4] == 8:
                            self_m.snapshots += 1
                            self_m.snapshot = False
                if nr == 180:
                    addr, buf = c.reg_read(a.UC_ARM_REG_R4), c.reg_read(a.UC_ARM_REG_R1)
                    res = super().on_syscall(c, i, u)
                    if self_m.snapshot and addr == self_m.REC_MGR + 0x69C8 and self_m.snapshots < 7:
                        c.mem_write(buf, struct.pack("<I", 0x100))
                    if self_m.pullout_t_ms is not None and addr == self_m.SRC_CORE + 0x3C4 and self_m.clock_ms - self_m.pullout_t_ms < 9600:
                        c.mem_write(buf + 4, struct.pack("<I", 8))
                    return res
                return super().on_syscall(c, i, u)
        mb = BoundedRestore(self.ring_img, self.manifest, cfg)
        mb.detached_pullout_ms = 12600
        for k in range(20):
            if k == 0: mb.run()
            else: mb.cpu.emu_start(mb.cpu.reg_read(mb.arm.UC_ARM_REG_PC), 0x10000 + self.manifest["ring"]["ro_size"], count=80000000)
            if mb.exit_code is not None or mb.unresolved_seen:
                break
        self.assertEqual(mb.exit_code, 0)
        self.assertFalse(mb.unresolved_seen)
        self.assertEqual(mb.mode_state, "init")
        self.assertEqual(len(mb.virtual_sd), 2)
        self.assertEqual(mb.busy, 70)
        self.assertEqual(mb.snapshots, 8)
        b_dr = next(r[3] for _, r in b_events if r[1] == 92 and r[4] == 11)
        b_origin = mb.drain - b_dr
        b_elapsed = mb.clock_ms - mb.drain
        self.assertGreater(b_elapsed, 210000)
        self.assertLess(b_elapsed, 240000)
        b_start, b_stop = 600, 600 + b_dr
        def b_feed(x, tm):
            x.half = int(tm >= 150)
            if x.active_ring_pid and tm >= b_start:
                tok = struct.unpack_from("<I", x.ring_launches[0]["cfg"], 36)[0]
                while x.idx < len(b_events) and b_events[x.idx][0] - b_origin <= tm - b_start:
                    x.ring_pipe_bytes.extend(fmt_m7cap(tok, *b_events[x.idx][1][1:]))
                    x.idx += 1
                # Emit the 1 s precap_blocked heartbeat across the fast-forwarded 170 s wait window.
                if b_stop + 5000 <= tm < b_stop + 179700 and tm >= x.next_hb:
                    x.next_hb = tm + 10000
                    x.ring_pipe_bytes.extend(fmt_m7cap(tok, 92, 28, tm - b_start, 25, 3, 0, 1, 1))
                if tm - b_stop >= b_elapsed:
                    x.active_ring_hang = False
        dm_b = DaemonV2Machine(self.daemon_img, self.manifest, scenario=b_feed, ring_script=lambda x, *_: (setattr(x, "idx", 0), setattr(x, "next_hb", 0), setattr(x, "active_ring_hang", True)), stop_file_ms=b_stop, max_log_bytes=131072)
        dm_b.run(count=800000000)
        b_log = dm_b.stdout_buf.decode("ascii")
        b_rec = runner.parse_daemon_log(b_log)["stop"]
        self.assertEqual(b_rec["r_reap"], "1")
        self.assertEqual(b_rec["r_sav"], "2")
        self.assertEqual(b_rec["r_unres"], "0")
        self.assertEqual(b_rec["r_flt"], "0")
        self.assertEqual(b_rec["trunc"], "0")
        self.assertEqual(b_log.count("ev=SUMMARY"), 1)

        # Host collector default max_polls (250) cleanly covers the 240 s daemon supervision bound.
        from unittest.mock import Mock, patch
        for cleared, expect_ok in [(249, True), (250, True), (251, False)]:
            samples = []
            def live(*_, _c=cleared, _s=samples):
                _s.append(1)
                return [], ([] if len(_s) >= _c else [1400])
            dpath = "/tmp_network/.m7-s6-abcdef012345"
            with patch.object(runner, "verify_nonsymlink_dir"), patch.object(runner, "find_all_live_s6_pids", side_effect=live):
                ok, _, _ = runner.request_stop_via_file(Mock(), dpath, dpath + "/daemon.elf", dpath + "/ring.elf")
            self.assertEqual(ok, expect_ok, f"cleared={cleared}")

    def test_23_live_hw3_linux_3_0_ptrace_esrch_and_concurrent_pool_retries(self):
        """Regression for Live Hardware Run #3/#3b/#3c (UNRESOLVED a=7 b=1407 c=170) and Astra r1:
        - Every non-ATTACH ptrace in stage6_ring.elf routes through s6_ptrace_retry (0 leaked Stage 5 callers).
        - Transient -ESRCH (-3) recovers across s6_sony_call4 (mode_set, GetImage, WriteFile, ReleaseImage),
          s6_copy_pixels_fast, s6_trace_begin, s6_rec_wait_trap_fast, and s6_burst_boundary.
        - Persistent -ESRCH (33 attempts) and non-ESRCH (-14, 1 attempt) in BOTH s6_copy_pixels_fast and
          s6_sony_call4 fail closed with exact stage=(220+op) and exact signed errno (NEVER 7/1407).
        - Concurrent torn ObjMedia4100 pool list & 10x EBUSY on s6_hold_acquire recover cleanly."""
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

        def parse_rows(buf):
            return [[int(ln[j:j + 8], 16) for j in range(7, 103, 8)]
                    for ln in buf.splitlines() if ln.startswith(b"M7CAP1=")]

        # 0. Static ARM verification on sealed stage6_ring.elf:
        #    ZERO old unhardened Stage 5 ptrace/sony_call symbols; ONLY 3 ptrace svc #0 sites total
        #    (1 PTRACE_ATTACH in s6_trace_begin, 2 in s6_ptrace_retry).
        syms = self.manifest["ring"]["symbols"]
        forbidden_old = {
            "sony_call4", "sony_call", "trace_begin", "trace_restore", "try_lock", "unlock_owned",
            "hold_lock", "hold_unlock", "commit_scratch", "commit_sd_drive", "commit_open", "commit_close",
            "create_cancel_state", "create_restore_cancel", "connect_release", "connect_pair",
            "mode_set", "mode_drain", "start_command", "capture_trap_set", "capture_trap_restore",
            "ram_restore_trap", "ram_next_trap", "ram_capture_complete",
            "burst_registers", "burst_own_stop", "burst_unchanged",
        }
        self.assertEqual(sorted(forbidden_old & set(syms.keys())), [])
        self.assertIn("s6_ptrace_retry", syms)
        self.assertIn("s6_ptrace_retry_n", syms)
        self.assertIn("s6_sony_call4", syms)
        self.assertIn("s6_trace_begin", syms)

        base = self.manifest["ring"]["base"]
        ro_size = self.manifest["ring"]["ro_size"]
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        entry_off = self.manifest["ring"]["entry"] - base
        sym_ranges = sorted((va, nm) for nm, va in syms.items() if base + entry_off <= va < base + ro_size and not nm.startswith("$"))
        def owner_fn(pc):
            best = None
            for va, nm in sym_ranges:
                if va <= pc:
                    best = nm
                else:
                    break
            return best
        ptrace_owners = []
        # Scan every 4-byte aligned ARM `svc #0` (0xef000000) across the full RX segment so literal pools never halt disassembly!
        for off in range(0, ro_size - (ro_size % 4), 4):
            if struct.unpack_from("<I", self.ring_img, off)[0] != 0xEF000000:
                continue
            svc_va = base + off
            win_start = max(entry_off, off - 80)
            win = list(md.disasm(self.ring_img[win_start:off + 4], base + win_start))
            r7_op = None
            for ins in reversed(win[:-1]):
                if ins.op_str.startswith("r7, "):
                    r7_op = ins.op_str
                    break
            if r7_op and ("#0x1a" in r7_op or "#26" in r7_op):
                ptrace_owners.append((owner_fn(svc_va), svc_va))
        self.assertEqual([nm for nm, _ in ptrace_owners], ["s6_trace_begin", "s6_ptrace_retry_n", "s6_ptrace_retry_n"])

        cfg = self._make_custom_ring_cfg(before=2, after=0, burst_cap=10, backlog_cap=32, post_max=6)
        tl = lambda m, ms: (setattr(m, "full", int(700 <= ms < 1100)), setattr(m, "half", 0) if ms >= 1100 else None)

        # 1. Transient -ESRCH (-3) on post-stop PTRACE_GETREGS across ALL paths:
        #    s6_sony_call4 (mode_set op=34, GetImage op=2, WriteFile op=10, ReleaseImage op=3),
        #    s6_copy_pixels_fast (memcpy op=7), s6_trace_begin (tid=170), s6_rec_wait_trap_fast, s6_burst_boundary!
        base1 = self._make_realistic_camera_ring(cfg, input_timeline=tl, stop_on_unresolved=True)
        class TransientEsrchAllPaths(type(base1)):
            saw_trap1_armed = False
            pending_op = {}       # tid -> tag for next wait4 return
            armed_esrch = {}      # tid -> count remaining
            quotas = {
                "mode_set": 2,
                "get_image": 3,
                "memcpy": 3,
                "write_file": 2,
                "release_image": 2,
                "attach_mon": 2,
                "rec_trap": 2,
                "rec_stop": 2,
            }
            def on_syscall(self_m, cpu, intno, user):
                a = self_m.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0, r1 = cpu.reg_read(a.UC_ARM_REG_R0), cpu.reg_read(a.UC_ARM_REG_R1)
                if nr == 26 and r0 == 4 and r1 == 446 and cpu.reg_read(a.UC_ARM_REG_R2) == (self_m.LIBOBJ + 0xA14C98):
                    self_m.saw_trap1_armed = True
                if nr == 26 and r0 == 16 and r1 == 170 and self_m.quotas["attach_mon"] > 0:
                    self_m.pending_op[170] = "attach_mon"
                if nr == 26 and r0 == 7 and r1 in self_m.traced:
                    pc = self_m.traced[r1]["regs"][15]
                    if r1 == 446 and pc == ((self_m.LIBOBJ + 0xA1C4E1) & ~1) and self_m.quotas["mode_set"] > 0:
                        self_m.pending_op[446] = "mode_set"
                    elif r1 == 170 and pc == ((self_m.LIBOBJ + 0xDD1DD9) & ~1) and self_m.quotas["get_image"] > 0:
                        self_m.pending_op[170] = "get_image"
                    elif r1 == 170 and pc == (self_m.LIBOBJ + 0x10D8DC) and self_m.quotas["memcpy"] > 0:
                        self_m.pending_op[170] = "memcpy"
                    elif r1 == 170 and pc == (self_m.LIBMPR + 0x19E664) and self_m.quotas["write_file"] > 0:
                        self_m.pending_op[170] = "write_file"
                    elif r1 == 170 and pc == ((self_m.LIBOBJ + 0xDD1595) & ~1) and self_m.quotas["release_image"] > 0:
                        self_m.pending_op[170] = "release_image"
                if nr == 114 and r0 in (170, 446):
                    ret = super().on_syscall(cpu, intno, user)
                    rc = cpu.reg_read(a.UC_ARM_REG_R0)
                    if rc in (170, 446):
                        tag = self_m.pending_op.pop(rc, None)
                        if tag is not None and self_m.quotas[tag] > 0:
                            self_m.armed_esrch[rc] = self_m.quotas[tag]
                            self_m.quotas[tag] = 0
                        elif rc == 446 and self_m.saw_trap1_armed and self_m.mode_4100:
                            st_w = struct.unpack("<I", cpu.mem_read(r1, 4))[0]
                            if st_w == 0x057F and self_m.quotas["rec_trap"] > 0:
                                self_m.armed_esrch[446] = self_m.quotas["rec_trap"]
                                self_m.quotas["rec_trap"] = 0
                            elif st_w == 0x137F and self_m.quotas["rec_stop"] > 0:
                                self_m.armed_esrch[446] = self_m.quotas["rec_stop"]
                                self_m.quotas["rec_stop"] = 0
                    return ret
                if nr == 26 and r0 == 12 and self_m.armed_esrch.get(r1, 0) > 0:
                    self_m.armed_esrch[r1] -= 1
                    cpu.reg_write(a.UC_ARM_REG_R0, (-3) & 0xFFFFFFFF)
                    return
                return super().on_syscall(cpu, intno, user)
        m1 = TransientEsrchAllPaths(self.ring_img, self.manifest, cfg)
        m1.run()
        self.assertEqual(m1.exit_code, 0)
        self.assertFalse(m1.unresolved_seen)
        self.assertEqual(m1.quotas, {k: 0 for k in m1.quotas})
        self.assertEqual({k: v for k, v in m1.armed_esrch.items() if v}, {})
        self.assertGreaterEqual(len(m1.virtual_sd), 2)
        self.assertEqual(m1.mode_state, "init")
        self.assertEqual(m1.traced, {})
        self.assertEqual(m1.held_by_helper, 0)

        # 2. Persistent -ESRCH (33 attempts) and non-ESRCH (-14, 1 attempt, 0 sleeps) MUST fail closed with
        #    exact stage=(220+op) and exact signed errno in BOTH s6_copy_pixels_fast AND s6_sony_call4 (NEVER 7/1407)!
        cases = [
            ("s6_copy_pixels_fast", lambda sm: sm.LIBOBJ + 0x10D8DC, 7, 227),
            ("s6_sony_call4_GetImage", lambda sm: (sm.LIBOBJ + 0xDD1DD9) & ~1, 2, 222),
            ("s6_sony_call4_WriteFile", lambda sm: sm.LIBMPR + 0x19E664, 10, 230),
        ]
        for label, pc_fn, _op, expect_stage in cases:
            for err_code, expect_attempts in [(-3, 33), (-14, 1)]:
                base_e = self._make_realistic_camera_ring(cfg, input_timeline=tl, stop_on_unresolved=True)
                class FailGetregs(type(base_e)):
                    err = err_code
                    target_pc = staticmethod(pc_fn)
                    in_op = False
                    armed = False
                    fail_attempts = 0
                    def on_syscall(self_m, cpu, intno, user):
                        a = self_m.arm
                        nr = cpu.reg_read(a.UC_ARM_REG_R7)
                        r0, r1 = cpu.reg_read(a.UC_ARM_REG_R0), cpu.reg_read(a.UC_ARM_REG_R1)
                        if nr == 26 and r0 == 7 and r1 == 170 and 170 in self_m.traced:
                            if self_m.traced[170]["regs"][15] == self_m.target_pc(self_m):
                                self_m.in_op = True
                        if nr == 114 and r0 == 170:
                            ret = super().on_syscall(cpu, intno, user)
                            if cpu.reg_read(a.UC_ARM_REG_R0) == 170 and self_m.in_op:
                                self_m.in_op = False
                                self_m.armed = True
                            return ret
                        if nr == 26 and r0 == 12 and r1 == 170 and self_m.armed:
                            self_m.fail_attempts += 1
                            cpu.reg_write(a.UC_ARM_REG_R0, self_m.err & 0xFFFFFFFF)
                            return
                        return super().on_syscall(cpu, intno, user)
                me = FailGetregs(self.ring_img, self.manifest, cfg)
                me.run()
                tag = f"{label} err={err_code}"
                self.assertTrue(me.unresolved_seen, tag)
                self.assertIsNone(me.exit_code, tag)
                self.assertEqual(me.fail_attempts, expect_attempts, tag)
                unres = [r for r in parse_rows(me.stdout_buf) if r[1] == 13 and r[4] == 98]
                self.assertEqual(unres[-1][5], expect_stage, tag)
                self.assertEqual(unres[-1][6], err_code & 0xFFFFFFFF, tag)
                self.assertEqual(unres[-1][7], 170, tag)

        # 3. Concurrent torn ObjMedia4100 list during ram_candidate (2x) + 10x EBUSY on s6_hold_acquire -> clean recovery!
        base_c = self._make_realistic_camera_ring(cfg, input_timeline=tl, stop_on_unresolved=True)
        class ConcurrentPoolRace(type(base_c)):
            torn_left = 2
            acq_busy_left = 10
            saw_trap1 = False
            def on_syscall(self_m, cpu, intno, user):
                a = self_m.arm
                nr = cpu.reg_read(a.UC_ARM_REG_R7)
                r0, r1, r2, r4 = (cpu.reg_read(a.UC_ARM_REG_R0), cpu.reg_read(a.UC_ARM_REG_R1),
                                  cpu.reg_read(a.UC_ARM_REG_R2), cpu.reg_read(a.UC_ARM_REG_R4))
                if nr == 114 and r0 == 446:
                    ret = super().on_syscall(cpu, intno, user)
                    if cpu.reg_read(a.UC_ARM_REG_R0) == 446 and struct.unpack("<I", cpu.mem_read(r1, 4))[0] == 0x057F:
                        if self_m.mode_4100 and self_m.active_frame is not None:
                            self_m.saw_trap1 = True
                    return ret
                if nr == 180 and r4 == self_m.POOL_4100 + 0x70C4 and r2 == 12 and self_m.saw_trap1 and self_m.torn_left > 0:
                    ret = super().on_syscall(cpu, intno, user)
                    # Corrupt list[2] transiently on first 2 unlocked ram_candidate reads (only after a frame is in pool)
                    h, t, cnt = struct.unpack("<3I", cpu.mem_read(r1, 12))
                    if cnt >= 1:
                        self_m.torn_left -= 1
                        cpu.mem_write(r1, struct.pack("<3I", h, t, cnt + 1))
                    return ret
                if nr == 26 and r0 == 7 and r1 == 170 and 170 in self_m.traced and self_m.saw_trap1 and self_m.acq_busy_left > 0:
                    regs = self_m.traced[170]["regs"]
                    if regs[15] == self_m.LIBOBJ + 0x108B20 and regs[0] == self_m.POOL_MUT + 4:
                        ret = super().on_syscall(cpu, intno, user)
                        regs[0] = 16  # EBUSY across >1 hold_lock attempt (8+2) -> forces outer s6_hold_acquire retry!
                        self_m.acq_busy_left -= 1
                        return ret
                return super().on_syscall(cpu, intno, user)
        mc = ConcurrentPoolRace(self.ring_img, self.manifest, cfg)
        mc.run()
        self.assertEqual(mc.exit_code, 0)
        self.assertFalse(mc.unresolved_seen)
        self.assertEqual(mc.torn_left, 0)
        self.assertEqual(mc.acq_busy_left, 0)
        self.assertGreaterEqual(len(mc.virtual_sd), 2)
        self.assertEqual(mc.mode_state, "init")
        self.assertEqual(mc.traced, {})

        # 4. Astra r2 regression: pre-dispatch revocation during Insert4100 PTRACE_CONT -ESRCH retry sleep
        #    AND pre-S1 rec_tid PTRACE_CONT -ESRCH retry sleep MUST suppress dispatch & unwind cleanly!
        valid_cfg = self._make_valid_ring_cfg()
        for rev_mode in ("held", "half_release", "sub_lost", "disarm"):
            class InsertRetryRevoke(RingV2Machine):
                mode = rev_mode
                refused_once = False
                revoked = False
                def on_syscall(self_m, cpu, intno, user):
                    a = self_m.arm
                    nr = cpu.reg_read(a.UC_ARM_REG_R7)
                    r0, r1 = cpu.reg_read(a.UC_ARM_REG_R0), cpu.reg_read(a.UC_ARM_REG_R1)
                    if nr == 26 and r0 == 7 and r1 == 446 and 446 in self_m.traced and not self_m.refused_once:
                        if self_m.traced[446]["regs"][15] == ((self_m.LIBOBJ + 0xA34BE9) & ~1):
                            self_m.refused_once = True
                            cpu.reg_write(a.UC_ARM_REG_R0, (-3) & 0xFFFFFFFF)
                            return
                    if nr == 162 and self_m.refused_once and not self_m.revoked:
                        self_m.revoked = True
                        if self_m.mode == "half_release":
                            self_m.half = 0
                        elif self_m.mode == "sub_lost":
                            self_m.sub_enabled = 0
                        elif self_m.mode == "disarm":
                            self_m.disarm_present = True
                    return super().on_syscall(cpu, intno, user)
            mr = InsertRetryRevoke(self.ring_img, self.manifest, valid_cfg, disarm_in_armed=(rev_mode == "held"))
            mr.run()
            self.assertTrue(mr.refused_once, rev_mode)
            self.assertTrue(mr.revoked, rev_mode)
            self.assertEqual(mr.exit_code, 0, rev_mode)
            self.assertEqual(mr.mode_state, "init", rev_mode)
            self.assertEqual(mr.traced, {}, rev_mode)
            insert_dispatched = any(pc == ((mr.LIBOBJ + 0xA34BE9) & ~1) for pc, *_ in mr.sony_ops)
            if rev_mode == "held":
                self.assertTrue(insert_dispatched, rev_mode)
            else:
                self.assertFalse(insert_dispatched, rev_mode)
                self.assertFalse(mr.inserted_4100, rev_mode)
                self.assertEqual(mr.poketext_log, [], rev_mode)

        for rev_mode in ("half_release", "sub_lost", "disarm"):
            class PreS1RetryRevoke(RingV2Machine):
                mode = rev_mode
                refused_once = False
                revoked = False
                def on_syscall(self_m, cpu, intno, user):
                    a = self_m.arm
                    nr = cpu.reg_read(a.UC_ARM_REG_R7)
                    r0, r1 = cpu.reg_read(a.UC_ARM_REG_R0), cpu.reg_read(a.UC_ARM_REG_R1)
                    if (nr == 26 and r0 == 7 and r1 == 446 and not self_m.refused_once and
                            len(self_m.poketext_log) == 1 and len(self_m.sndcmd_calls) == 0):
                        self_m.refused_once = True
                        cpu.reg_write(a.UC_ARM_REG_R0, (-3) & 0xFFFFFFFF)
                        return
                    if nr == 162 and self_m.refused_once and not self_m.revoked:
                        self_m.revoked = True
                        if self_m.mode == "half_release":
                            self_m.half = 0
                        elif self_m.mode == "sub_lost":
                            self_m.sub_enabled = 0
                        elif self_m.mode == "disarm":
                            self_m.disarm_present = True
                    return super().on_syscall(cpu, intno, user)
            ms1 = PreS1RetryRevoke(self.ring_img, self.manifest, valid_cfg)
            ms1.run()
            self.assertTrue(ms1.refused_once, f"pre_s1_{rev_mode}")
            self.assertTrue(ms1.revoked, f"pre_s1_{rev_mode}")
            self.assertEqual(ms1.exit_code, 0, f"pre_s1_{rev_mode}")
            self.assertEqual(ms1.sndcmd_calls, [], f"pre_s1_{rev_mode}")
            self.assertEqual(len(ms1.poketext_log), 2, f"pre_s1_{rev_mode}")
            self.assertEqual(ms1.poketext_log[1], (ms1.LIBOBJ + 0xA14C98, 0x531EF240), f"pre_s1_{rev_mode}")
            self.assertEqual(ms1.mode_state, "init", f"pre_s1_{rev_mode}")
            self.assertEqual(ms1.traced, {}, f"pre_s1_{rev_mode}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
