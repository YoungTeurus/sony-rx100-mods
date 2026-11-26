#!/usr/bin/env python3
"""Offline Unicorn ARMv7 emulation + host runner tests for Stage 6 WIP v1 probe."""
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

import build_stage6 as builder
import stage6_runner as runner
import m7_probe as usb


def pack_dirents(entries):
    """Pack Linux getdents64 entries: [(ino, name_bytes), ...]."""
    out = bytearray()
    for idx, (ino, name) in enumerate(entries, start=1):
        raw_name = name + b"\x00"
        reclen = (19 + len(raw_name) + 7) & ~7
        hdr = struct.pack("<QqHB", ino, idx, reclen, 4)
        out.extend(hdr + raw_name + bytes(reclen - 19 - len(raw_name)))
    return bytes(out)


class Stage6Machine:
    LIBOBJ = 0x05ECD000
    LIBMWF = 0x04460000
    LIBMPR = 0x07400000
    LIBMPRCTRL = 0x044A8000
    LIBUIPC = 0x04053000
    STR_UXC = 0x173A4000
    HEAP = 0x02000000
    HEAP2 = 0x02100000

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
        duration_ms=10000,
        poll_ms=50,
        heartbeat_ms=200,
        max_log_bytes=65536,
        nonce="abcdef012345",
        bk_datasize=1,
        bad_param_ptr=False,
        bad_ftbl=False,
        null_csp_ptr=False,
        im_exit_tick=None,
        sigterm_tick=None,
        stop_file_tick=None,
        dynamic_vma_tick=None,
        uipc_free_fail_at=None,
        uipc_hang_worker=False,
        uipc_late_reply_ms=None,
        uipc_copy_fault=False,
        uipc_copy_overrun=False,
        uipc_partial_reply=False,
        bk_val_init=0,
        shutter_sentinel_tick=None,
        shutter_fail_tick=None,
        sub_fail_tick=None,
        child1_exit_code=0,
        worker_requests=None,
    ):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR
        import unicorn.arm_const as arm

        self.arm = arm
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.cpu.mem_map(0x10000, (len(image) + 4095) & ~4095)
        self.cpu.mem_map(0x00800000, 0x40000)
        self.cpu.reg_write(arm.UC_ARM_REG_SP, 0x0083F000)

        self.nonce = nonce
        self.image = builder.configure_probe(
            image, manifest,
            duration_ms=duration_ms,
            poll_ms=poll_ms,
            heartbeat_ms=heartbeat_ms,
            max_log_bytes=max_log_bytes,
            daemonize=daemonize,
            nonce=nonce,
        )
        self.cpu.mem_write(0x10000, self.image)

        self.daemonize = daemonize
        self.fork_role = fork_role
        self.bk_datasize = bk_datasize
        self.bad_param_ptr = bad_param_ptr
        self.bad_ftbl = bad_ftbl
        self.null_csp_ptr = null_csp_ptr
        self.im_exit_tick = im_exit_tick
        self.sigterm_tick = sigterm_tick
        self.stop_file_tick = stop_file_tick
        self.dynamic_vma_tick = dynamic_vma_tick
        self.uipc_free_fail_at = uipc_free_fail_at
        self.uipc_hang_worker = uipc_hang_worker
        self.uipc_late_reply_ms = uipc_late_reply_ms
        self.uipc_copy_fault = uipc_copy_fault
        self.uipc_copy_overrun = uipc_copy_overrun
        self.uipc_partial_reply = uipc_partial_reply
        self.shutter_sentinel_tick = shutter_sentinel_tick
        self.shutter_fail_tick = shutter_fail_tick
        self.sub_fail_tick = sub_fail_tick
        self.child1_exit_code = child1_exit_code
        self.worker_requests = list(worker_requests) if worker_requests is not None else [0x01071472, 0x01071472]

        self.clock_ms = 5000
        self.tick = 0
        self.exit_code = None
        self.next_mmap = 0x30000000
        self.next_fd = 10
        self.fds = {}
        self.files_written = {}
        self.unlinked = []
        self.syscalls = []
        self.kills_sent = []
        self.fork_count = 0
        self.uipc_open_after_forks = None
        self.uipc_vallocs = 0
        self.uipc_frees = 0
        self.uipc_wait_args = []
        self.uipc_ops = []
        self.uipc_map_base = None
        self.stdout_buf = bytearray()
        self.worker_replies_written = []
        self.pending_rep_bytes = bytearray()
        self.pipe_pairs = []

        self.drive_act = 0x005E      # SINGLE
        self.burst_spd = 0x0069      # H
        self.bol_spd = 0x05BF        # H
        self.still_size = 0x00B3     # L (20M)
        self.still_asp = 0x00B9      # 3:2
        self.jpeg_qual = 0x00BB      # FINE
        self.file_fmt = 0x00BD       # JPEG
        self.redeye_set = 0x0153     # OFF
        self.redeye_act = 0x0153
        self.bk_val = bk_val_init
        self.sub_enabled = 0
        self.half = 0
        self.full = 0
        self.heap2_mapped = False

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
            f"{self.STR_UXC:08x}-{self.STR_UXC+0xa9000:08x} r--p 00000000 fc:0f 41094 /usr/share/app/string_russian.uxc",
        ]
        if self.heap2_mapped:
            lines.insert(1, f"{self.HEAP2:08x}-{self.HEAP2+0x10000:08x} rw-p 00000000 00:00 0 ")
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

        csp_ptr = 0 if self.null_csp_ptr else (self.LIBOBJ + 0x145F3F0)
        put(self.LIBOBJ + 0x145F3E8, csp_ptr, 1)
        ftbl = (self.LIBMWF + 0x42CF0) if self.bad_ftbl else (self.LIBMWF + 0x42CEC)
        pbase = self.HEAP2 + 0x100 if (self.dynamic_vma_tick is not None and self.tick >= self.dynamic_vma_tick) else self.PARAMS_BASE
        slots = [
            (0x145F4F4, self.drive_act),
            (0x145F4FC, self.burst_spd),
            (0x1460CD4, self.bol_spd),
            (0x145F5F0, self.still_size),
            (0x145F5F4, self.still_asp),
            (0x145F5F8, self.jpeg_qual),
            (0x145F5FC, self.file_fmt),
            (0x145F808, self.redeye_set),
            (0x145F80C, self.redeye_act),
        ]
        for i, (slot_off, val) in enumerate(slots):
            p_addr = (self.LIBOBJ + 0x1430000) if (self.bad_param_ptr and i == 0) else (pbase + i * 16)
            put(self.LIBOBJ + slot_off, p_addr)
            put(p_addr, val, ftbl)

        put(self.LIBOBJ + 0x145D230, self.INPUT_ROOT)
        put(self.LIBOBJ + 0x1463130, 0 if (self.sub_fail_tick is not None and self.tick >= self.sub_fail_tick) else self.SPINAL)
        g = [0] * 24
        g[0] = self.INPUT_ROOT
        g[1] = self.CAMERA
        g[20] = 0
        g[21] = 0
        g[22] = 10
        g[23] = self.sub_enabled
        put(self.SPINAL, *g)
        put(self.CAMERA, self.LIBOBJ + 0x1390490)

        in_w = [0] * 10
        in_w[0] = 0xDEADBEEF if (self.shutter_fail_tick is not None and self.tick >= self.shutter_fail_tick) else (self.LIBOBJ + 0x1387AF0)
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
            if idx == 27 and self.shutter_sentinel_tick is not None and self.tick >= self.shutter_sentinel_tick:
                st[2] = 0x7FFFFFFF
            else:
                st[2] = self.full if idx == 14 else (self.half if idx == 27 else 0)
            st[4] = idx
            put(self.INPUT_STATE + idx * 0x28, *st)

        return mem

    def advance_scenario(self):
        self.tick += 1
        if self.dynamic_vma_tick is not None and self.tick == self.dynamic_vma_tick:
            self.heap2_mapped = True
        if self.tick == 2:
            self.drive_act = 0x005F  # BURST
            self.sub_enabled = 1
        elif self.tick == 5:
            self.bk_val = 1
            self.half = 1
        elif self.tick == 7:
            self.file_fmt = 0x00BF   # RAW+JPEG -> elig=0
            self.half = 0
        elif self.tick == 9:
            self.file_fmt = 0x00BD   # JPEG
            self.drive_act = 0x0C89  # SPOT_BURST -> elig=0
        elif self.tick == 11:
            self.drive_act = 0x05BC  # BOL_BURST -> elig=1

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

        assert nr not in (11, 26), f"Forbidden syscall {nr} invoked!"

        res = 0
        if nr == 1:
            self.exit_code = r0
            cpu.emu_stop()
            return
        elif nr == 2:  # fork
            self.fork_count += 1
            if self.fork_role == "parent" and self.fork_count == 1:
                res = 500
            elif self.fork_role == "child1" and self.fork_count == 2:
                res = 501
            elif self.fork_role == "worker":
                # Enter worker child branch on the worker fork (fork #1 when daemonize=False, #3 when True)
                target_fork = 3 if self.daemonize else 1
                res = 0 if self.fork_count == target_fork else 0
            else:
                # Main daemon (grandchild): daemonize forks return 0, worker fork returns 888
                worker_fork_idx = 3 if self.daemonize else 1
                res = 888 if self.fork_count == worker_fork_idx else 0
        elif nr == 42:  # pipe
            rfd = self.next_fd
            wfd = self.next_fd + 1
            self.next_fd += 2
            idx = len(self.pipe_pairs)
            self.pipe_pairs.append((rfd, wfd))
            if idx == 0:
                # req pipe
                req_stream = b"".join(struct.pack("<I", x) for x in self.worker_requests)
                self.fds[rfd] = dict(kind="req_r", data=req_stream, pos=0)
                self.fds[wfd] = dict(kind="req_w")
            else:
                # rep pipe
                self.fds[rfd] = dict(kind="rep_r")
                self.fds[wfd] = dict(kind="rep_w")
            cpu.mem_write(r0, struct.pack("<2i", rfd, wfd))
            res = 0
        elif nr == 55:  # fcntl
            assert r1 == 4 and r2 == 0x800
            res = 0
        elif nr == 3:  # read
            f = self.fds[r0]
            if f["kind"] == "rep_r":
                if self.uipc_hang_worker:
                    res = -11
                elif self.uipc_late_reply_ms is not None and (self.clock_ms - 5000) < self.uipc_late_reply_ms:
                    res = -11
                elif not self.pending_rep_bytes:
                    res = -11  # EAGAIN
                else:
                    take = min(7, r2) if self.uipc_partial_reply else r2
                    chunk = bytes(self.pending_rep_bytes[:take])
                    del self.pending_rep_bytes[:len(chunk)]
                    cpu.mem_write(r1, chunk)
                    res = len(chunk)
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
                assert len(data) == 4
                if not self.uipc_hang_worker:
                    self.pending_rep_bytes.extend(self.synthesize_bk_reply())
            elif self.fds[r0]["kind"] == "rep_w":
                self.worker_replies_written.append(struct.unpack("<IiIIIiIi", data))
            else:
                f = self.fds[r0]
                f["buf"].extend(data)
                self.files_written[f["path"]] = bytes(f["buf"])
            res = len(data)
        elif nr == 5:  # open
            path = self.read_cstr(r0)
            flags = r1
            if path == "/proc/161/mem":
                assert flags == 0
            fd = self.next_fd
            self.next_fd += 1
            if path == "/proc":
                entries = [(1, b"1"), (2, b"self"), (160, b"160"), (161, b"161"), (784, b"784")]
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
                self.fds[fd] = dict(kind="mem", path=path)
            elif path == "/dev/uipc":
                self.uipc_open_after_forks = self.fork_count
                self.fds[fd] = dict(kind="uipc", path=path)
            elif path == "/dev/null":
                self.fds[fd] = dict(kind="null", path=path, buf=bytearray())
            elif path == f"/tmp_network/.m7-s6-{self.nonce}/stop":
                if self.stop_file_tick is not None and self.tick >= self.stop_file_tick:
                    self.fds[fd] = dict(kind="file", path=path, data=b"stop\n", pos=0)
                else:
                    fd = -2
            elif path.startswith(f"/tmp_network/.m7-s6-{self.nonce}/"):
                assert flags == 0xC1, f"Expected O_WRONLY|O_CREAT|O_EXCL on {path}, got {flags:#x}"
                self.fds[fd] = dict(kind="out", path=path, buf=bytearray())
                self.files_written[path] = b""
            else:
                fd = -2
            res = fd
        elif nr == 6:
            self.fds.pop(r0, None)
            res = 0
        elif nr == 10:
            self.unlinked.append(self.read_cstr(r0))
            res = 0
        elif nr == 114:  # wait4
            if r0 == 888 and self.uipc_hang_worker:
                res = 0  # hung worker does not exit on WNOHANG
            else:
                cpu.mem_write(r1, struct.pack("<I", (self.child1_exit_code & 0xFF) << 8))
                res = r0
        elif nr in (12, 63, 66, 91, 174, 175):
            res = 0
        elif nr == 20:
            res = 999
        elif nr == 37:  # kill
            self.kills_sent.append((r0, r1))
            if r0 == 161 and r1 == 0 and self.im_exit_tick is not None and self.tick >= self.im_exit_tick:
                res = -3
            else:
                res = 0
        elif nr == 54:  # ioctl (/dev/uipc - ONLY allowed in worker child!)
            assert self.fork_role == "worker", "Main watchdog process must NEVER invoke /dev/uipc ioctl!"
            assert self.fds[r0]["kind"] == "uipc"
            arg0, arg1 = struct.unpack("<2I", cpu.mem_read(r2, 8))
            if r1 == 0x80000010:
                cpu.mem_write(arg1, struct.pack("<4I", 0x10000, 0, 0, 0))
                res = 0
            elif r1 == 0x8000000A:
                assert arg0 == 0x003E014D
                out_ptr_va, sz, wait_flag = struct.unpack("<3I", cpu.mem_read(arg1, 12))
                self.uipc_wait_args.append(wait_flag)
                assert wait_flag == 0, f"valloc must be non-blocking (wait=0), got {wait_flag}"
                assert sz == 0x40 and self.uipc_map_base is not None
                msg_va = self.uipc_map_base + 0x100
                cpu.mem_write(out_ptr_va, struct.pack("<I", msg_va))
                self.uipc_vallocs += 1
                res = 0
            elif r1 == 0x80000005:
                assert arg0 == 0x003E014D
                msg_va, cb, _ = struct.unpack("<3I", cpu.mem_read(arg1, 12))
                assert cb == 0
                msg = list(struct.unpack("<16I", cpu.mem_read(msg_va, 64)))
                op, _ret, argc, qid, _u1, _u2, bkid, dst_buf = msg[:8]
                assert qid == 0x003E014D and bkid == 0x01071472
                self.uipc_ops.append(op)
                if op == 0:
                    assert argc == 1
                    msg[1] = self.bk_datasize
                elif op == 3:
                    assert argc == 2 and self.bk_datasize == 1
                    if self.uipc_copy_overrun:
                        cpu.mem_write(dst_buf, struct.pack("<I", 0x00000001))  # clobbers upper 3 sentinel bytes!
                    elif not self.uipc_copy_fault:
                        cpu.mem_write(dst_buf, bytes([self.bk_val & 0xFF]))
                    msg[1] = 1
                else:
                    raise AssertionError(f"Unexpected Backup op {op}")
                cpu.mem_write(msg_va, struct.pack("<16I", *msg))
                res = 0
            elif r1 == 0x8000000B:
                assert arg0 == 0x003E014D and arg1 == self.uipc_map_base + 0x100
                self.uipc_frees += 1
                if self.uipc_free_fail_at is not None and self.uipc_frees >= self.uipc_free_fail_at:
                    res = -5
                else:
                    res = 0
            else:
                raise AssertionError(f"Unexpected ioctl {r1:#x}")
        elif nr == 85:
            path = self.read_cstr(r0)
            target = b"/usr/bin/im.elf" if path == "/proc/161/exe" else b"/bin/ash"
            n = min(len(target), r2)
            cpu.mem_write(r1, target[:n])
            res = n
        elif nr == 177:
            sec, nsec = struct.unpack("<2I", cpu.mem_read(r2, 8))
            self.clock_ms += sec * 1000 + nsec // 1000000
            if self.sigterm_tick is not None and self.tick >= self.sigterm_tick:
                res = 15
            else:
                if sec * 1000 + nsec // 1000000 >= 50:
                    self.advance_scenario()
                res = -11
        elif nr == 180:
            assert self.fds[r0]["kind"] == "mem" and r3 == 0 and r5 == 0
            im_mem = self.build_im_memory()
            out = bytes(im_mem.get(r4 + i, 0) for i in range(r2))
            cpu.mem_write(r1, out)
            res = r2
        elif nr == 192:
            size = (r1 + 4095) & ~4095
            addr = self.next_mmap
            self.next_mmap += size + 0x10000
            self.cpu.mem_map(addr, size)
            if r4 != 0xFFFFFFFF and self.fds.get(r4, {}).get("kind") == "uipc":
                self.uipc_map_base = addr
            res = addr
        elif nr == 217:
            f = self.fds[r0]
            data = f["data"]
            pos = f["pos"]
            if pos >= len(data):
                res = 0
            else:
                chunk = data[pos:pos + r2]
                cpu.mem_write(r1, chunk)
                f["pos"] = pos + len(chunk)
                res = len(chunk)
        elif nr == 263:
            cpu.mem_write(r1, struct.pack("<2I", self.clock_ms // 1000, (self.clock_ms % 1000) * 1000000))
            res = 0
        else:
            raise AssertionError(f"Unhandled ARM syscall {nr}")

        cpu.reg_write(a.UC_ARM_REG_R0, res & 0xFFFFFFFF)

    def run(self):
        self.cpu.emu_start(self.manifest_entry, 0x10000 + len(self.image), count=3000000)
        return self.exit_code


class Stage6ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="s6-test-")
        cls.image, cls.manifest = builder.build_probe(output=Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _run_machine(self, **kwargs):
        m = Stage6Machine(self.image, self.manifest, **kwargs)
        m.manifest_entry = self.manifest["entry"]
        m.run()
        return m

    def test_01_main_watchdog_zero_ioctl_and_stop_file(self):
        m = self._run_machine(daemonize=False, stop_file_tick=14, duration_ms=60000, uipc_partial_reply=True)
        self.assertEqual(m.exit_code, 0)
        self.assertNotIn(26, m.syscalls)
        self.assertNotIn(11, m.syscalls)
        self.assertNotIn(54, m.syscalls)  # Main watchdog NEVER calls /dev/uipc ioctl!

        parsed = runner.parse_probe_log(m.stdout_buf.decode("ascii"))
        boot = parsed["boot"]
        self.assertEqual(boot["im_pid"], "161")
        self.assertEqual(boot["w_pid"], "888")
        self.assertEqual(boot["mon_proc"], "170")
        self.assertEqual(boot["mon_mwf"], "170")
        self.assertEqual(boot["csp_ptr_ok"], "1")
        self.assertEqual(boot["uipc_ok"], "1")
        self.assertEqual(boot["bk_sz"], "1")
        self.assertEqual(boot["bk_rc"], "0")
        self.assertEqual(parsed["drives_seen"], ["0x5bc", "0x5e", "0x5f", "0xc89"])
        self.assertEqual(parsed["bk_values_seen"], ["0x0", "0x1"])
        self.assertEqual(parsed["sub_enabled_seen"], ["0", "1"])
        self.assertEqual(parsed["half_values_seen"], ["0x0", "0x1"])
        self.assertEqual(parsed["stop"]["reason"], "stop_file")
        self.assertEqual(parsed["stop"]["w_reap"], "1")

    def test_02_isolated_uipc_worker_arm_code_sentinel_and_free_err(self):
        # Normal 1-byte read in worker child: wait=0, op=0 then op=3, clean EOF exit.
        mw = self._run_machine(daemonize=False, fork_role="worker", worker_requests=[0x01071472])
        self.assertEqual(mw.exit_code, 0)
        self.assertEqual(mw.uipc_open_after_forks, 1)
        self.assertEqual(mw.uipc_wait_args, [0, 0])
        self.assertEqual(mw.uipc_ops, [0, 3])
        self.assertEqual(mw.uipc_vallocs, mw.uipc_frees)
        self.assertEqual(len(mw.worker_replies_written), 1)
        rep = mw.worker_replies_written[0]
        self.assertEqual(rep[:6], (1, 0, 1, 1, 0, 0))  # uipc_ok=1, bk_valid=1, bk_size=1, bk_val=0, bk_rc=0

        # Non-1-byte BackupID: op=3 is NEVER invoked!
        m4 = self._run_machine(daemonize=False, fork_role="worker", bk_datasize=4, worker_requests=[0x01071472])
        self.assertEqual(m4.uipc_ops, [0])
        self.assertEqual(m4.worker_replies_written[0][2:6], (0, 4, 0xFFFFFFFF, -75))

        # Copy fault (both 0xA5 and 0x5A sentinels unchanged) -> bk_rc=-14, bk_valid=0
        mcf = self._run_machine(daemonize=False, fork_role="worker", uipc_copy_fault=True, worker_requests=[0x01071472])
        self.assertEqual(mcf.uipc_ops, [0, 3, 3])
        self.assertEqual(mcf.worker_replies_written[0][2:6], (0, 1, 0xFFFFFFFF, -14))

        # Legitimate byte 0xA5 is disambiguated via 0x5A sentinel -> bk_valid=1, bk_val=0xA5, bk_rc=0
        ma5 = self._run_machine(daemonize=False, fork_role="worker", bk_val_init=0xA5, worker_requests=[0x01071472])
        self.assertEqual(ma5.uipc_ops, [0, 3, 3])
        self.assertEqual(ma5.worker_replies_written[0][2:6], (1, 1, 0xA5, 0))

        # Overrun (>1 byte clobbers 0xA5A5A500 guard) -> bk_rc=-75, bk_valid=0
        mov = self._run_machine(daemonize=False, fork_role="worker", uipc_copy_overrun=True, worker_requests=[0x01071472])
        self.assertEqual(mov.worker_replies_written[0][2:6], (0, 1, 0xFFFFFFFF, -75))

        # Failed FREE_MSG disables subsequent Backup ioctls!
        mf = self._run_machine(daemonize=False, fork_role="worker", uipc_free_fail_at=1, worker_requests=[0x01071472, 0x01071472])
        self.assertEqual(mf.uipc_vallocs, 1)  # 2nd request did NOT touch /dev/uipc!
        self.assertEqual(mf.worker_replies_written[1][6], 1)   # uipc_disabled=1
        self.assertEqual(mf.worker_replies_written[1][7], -5)  # uipc_free_err=-5

    def test_03_hung_uipc_worker_never_blocks_watchdog_or_stop_file(self):
        # 1. Hung worker: main watchdog times out at 1000 ms and still obeys stop_file!
        m = self._run_machine(daemonize=False, uipc_hang_worker=True, stop_file_tick=2, duration_ms=10000)
        self.assertEqual(m.exit_code, 0)
        parsed = runner.parse_probe_log(m.stdout_buf.decode("ascii"))
        self.assertEqual(parsed["boot"]["bk_rc"], "-110")
        self.assertEqual(parsed["stop"]["reason"], "stop_file")
        self.assertEqual(parsed["stop"]["uipc_to"], "1")
        self.assertEqual(parsed["stop"]["w_reap"], "0")
        self.assertIn((888, 9), m.kills_sent)  # SIGKILL sent only to own unreaped child 888

        # 2. Late worker reply at 1020 ms MUST be rejected (not accepted past 1000 ms deadline)!
        ml = self._run_machine(daemonize=False, uipc_late_reply_ms=1020, stop_file_tick=2, duration_ms=10000)
        self.assertEqual(ml.exit_code, 0)
        pl = runner.parse_probe_log(ml.stdout_buf.decode("ascii"))
        self.assertEqual(pl["boot"]["bk_rc"], "-110")
        self.assertEqual(pl["stop"]["uipc_to"], "1")

        # 3. Startup duration_ms=100 with hung worker enforces timeout at trig_t=100 and single teardown pass (<= 200 ms)!
        ms = self._run_machine(daemonize=True, fork_role="grandchild", uipc_hang_worker=True, duration_ms=100, nonce="112233445566")
        self.assertEqual(ms.exit_code, 0)
        self.assertNotIn("/tmp_network/.m7-s6-112233445566/probe.pid", ms.files_written)
        ps = runner.parse_probe_log(ms.files_written["/tmp_network/.m7-s6-112233445566/probe.log"].decode("ascii"))
        self.assertIsNone(ps["boot"])
        self.assertEqual(ps["stop"]["reason"], "timeout")
        self.assertEqual(ps["stop"]["trig_t"], "100")
        self.assertEqual(ps["stop"]["t"], "300")  # 100 ms run + single 200 ms teardown pass (never double!)
        self.assertEqual(ms.clock_ms - 5000, 300)
        self.assertEqual(ps["stop"]["w_reap"], "0")
        self.assertEqual(ms.kills_sent.count((888, 9)), 1)  # Single teardown pass only!

    def test_04_double_fork_daemonization_and_nonce_paths(self):
        parent_ok = self._run_machine(daemonize=True, fork_role="parent", child1_exit_code=0)
        self.assertEqual(parent_ok.exit_code, 0)
        parent_fail = self._run_machine(daemonize=True, fork_role="parent", child1_exit_code=23)
        self.assertEqual(parent_fail.exit_code, 3)

        gc = self._run_machine(daemonize=True, fork_role="grandchild", stop_file_tick=3, nonce="deadbeef1234")
        self.assertEqual(gc.exit_code, 0)
        self.assertEqual(gc.fork_count, 3)  # 2 daemon forks + 1 uipc worker fork
        pid_path = "/tmp_network/.m7-s6-deadbeef1234/probe.pid"
        log_path = "/tmp_network/.m7-s6-deadbeef1234/probe.log"
        self.assertEqual(gc.files_written.get(pid_path), b"999\n")
        self.assertIn(pid_path, gc.unlinked)
        self.assertIn("BOOT ", gc.files_written[log_path].decode("ascii"))
        self.assertIn("STOP ", gc.files_written[log_path].decode("ascii"))

    def test_05_rejects_bss_param_wrong_ftbl_sentinel_and_invalid_filtering(self):
        m_bss = self._run_machine(daemonize=False, bad_param_ptr=True, sigterm_tick=2)
        p_bss = runner.parse_probe_log(m_bss.stdout_buf.decode("ascii"))
        self.assertEqual(p_bss["drives_seen"], [])  # invalid cam=0 rows filtered out!
        self.assertEqual(p_bss["formats_seen"], [])

        m_csp = self._run_machine(daemonize=False, null_csp_ptr=True, sigterm_tick=3)
        p_csp = runner.parse_probe_log(m_csp.stdout_buf.decode("ascii"))
        self.assertEqual(p_csp["boot"]["csp_ptr_ok"], "0")
        self.assertTrue(any(s["cam"] == "1" for s in p_csp["states"]))

        ms = self._run_machine(daemonize=False, shutter_sentinel_tick=0, sigterm_tick=3)
        ps = runner.parse_probe_log(ms.stdout_buf.decode("ascii"))
        self.assertTrue(all(s["half_ok"] == "1" and s["half"] == "0x7fffffff" for s in ps["states"]))

        mf = self._run_machine(daemonize=False, shutter_fail_tick=6, sigterm_tick=8)
        pf = runner.parse_probe_log(mf.stdout_buf.decode("ascii"))
        self.assertEqual(pf["states"][-1]["half_ok"], "0")
        self.assertEqual(pf["states"][-1]["half"], "0xffffffff")

        msub = self._run_machine(daemonize=False, sub_fail_tick=4, sigterm_tick=6)
        psub = runner.parse_probe_log(msub.stdout_buf.decode("ascii"))
        self.assertEqual(psub["states"][-1]["sub_ok"], "0")

    def test_06_dynamic_vma_stop_reserve_im_exit_and_timeout(self):
        m = self._run_machine(daemonize=False, dynamic_vma_tick=45, sigterm_tick=52, duration_ms=10000, heartbeat_ms=500)
        parsed = runner.parse_probe_log(m.stdout_buf.decode("ascii"))
        self.assertTrue(any(int(h["mref"]) >= 1 for h in parsed["heartbeats"]))

        mt = self._run_machine(daemonize=False, max_log_bytes=1024, sigterm_tick=14, duration_ms=60000)
        pt = runner.parse_probe_log(mt.stdout_buf.decode("ascii"))
        self.assertIsNotNone(pt["stop"])
        self.assertEqual(pt["stop"]["trunc"], "1")

        m_exit = self._run_machine(daemonize=False, im_exit_tick=2, duration_ms=10000)
        self.assertEqual(runner.parse_probe_log(m_exit.stdout_buf.decode("ascii"))["stop"]["reason"], "im_exit")

        m_to = self._run_machine(daemonize=False, duration_ms=250, poll_ms=50, heartbeat_ms=100)
        self.assertEqual(runner.parse_probe_log(m_to.stdout_buf.decode("ascii"))["stop"]["reason"], "timeout")

    def test_07_host_zero_kill_stop_file_witnesses_and_stale_recovery(self):
        # 1. Start witness check MUST reject all-invalid STATE even when uipc_ok=1
        bad_summary = runner.parse_probe_log(
            "BOOT self_pid=999 im_pid=161 mon_proc=170 mon_mwf=170 uipc_ok=1 bk_sz=1 in_ok=1\n"
            "STATE t=0 cam=0 bk_ok=0 bk_rc=-1021 sub_ok=0 half_ok=0 full_ok=0\n"
        )
        with self.assertRaises(usb.ProbeError):
            runner.verify_usable_initial_witnesses(bad_summary, 999, 161)

        good_summary = runner.parse_probe_log(
            "BOOT self_pid=999 im_pid=161 mon_proc=170 mon_mwf=170 uipc_ok=1 bk_sz=1 in_ok=1\n"
            "STATE t=0 cam=1 bk_ok=1 bk=0x0 bk_rc=0 sub_ok=1 half_ok=1 half=0x0 full_ok=1 full=0x0\n"
        )
        runner.verify_usable_initial_witnesses(good_summary, 999, 161)

        # 2. Incomplete collect (daemon still alive or failed log read) MUST fail evaluate_cli_success (exit 1)!
        self.assertFalse(runner.evaluate_cli_success("collect", dict(
            teardown_requested_clean=True,
            stopped_cleanly=False,
            cleanup="DEFERRED_DAEMON_STILL_ALIVE",
            collect_outcome="incomplete",
            active_state_cleared=False,
        )))
        self.assertFalse(runner.evaluate_cli_success("collect", dict(
            teardown_requested_clean=True,
            stopped_cleanly=True,
            cleanup="GONE",
            collect_outcome="collected",
            log_retrieved=False,
            log_persisted=False,
            active_state_cleared=True,
        )))
        # 3. Stale recovery and prelaunch recovery MUST succeed cleanly!
        self.assertTrue(runner.evaluate_cli_success("collect", dict(
            teardown_requested_clean=True,
            stale_active_recovered=True,
            stopped_cleanly=True,
            cleanup="DIR_ALREADY_ABSENT",
            collect_outcome="stale_recovered",
            active_state_cleared=True,
        )))
        self.assertTrue(runner.evaluate_cli_success("collect", dict(
            teardown_requested_clean=True,
            prelaunch_recovered=True,
            stopped_cleanly=True,
            cleanup="GONE",
            collect_outcome="prelaunch_recovered",
            active_state_cleared=True,
        )))

        # 4. request_stop_via_file NEVER emits any kill command and verifies /proc exe scan!
        cmds = []
        class StopSess:
            def command(self, cmd, allowed=(0,)):
                cmds.append(cmd)
                if "echo DIR_OK" in cmd:
                    return b"DIR_OK\n", 0
                if "echo stop >" in cmd or "sleep 1" in cmd:
                    return b"", 0
                if "for p in /proc/[1-9]*" in cmd:
                    return b"", 0
                if "readlink" in cmd or "/stat" in cmd or "/status" in cmd:
                    return b"", 1
                raise AssertionError(cmd)

        stopped, live = runner.request_stop_via_file(
            StopSess(), "/tmp_network/.m7-s6-abcdef012345",
            "/tmp_network/.m7-s6-abcdef012345/probe.elf",
            expected_pid=999, expected_starttime=555,
        )
        self.assertTrue(stopped)
        self.assertEqual(live, [])
        self.assertFalse(any("kill" in c for c in cmds))

        # 5. End-to-end do_start / do_collect fixtures covering Sol r2 blockers
        import hashlib
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
                b"BusyBox\nCurrently defined functions:\n echo, md5sum, mkdir, rmdir, rm, chmod, test, pidof, readlink, wc\n",
                b"M7_OCTAL_OK\n",
                (b"161\n", 0) if im_present else (b"", 1),
                b"21089716 /usr/lib/libObj.so\n",
                b"99a06d3852bf744a5d454bd873f6d35c  /usr/lib/libObj.so\n",
            ]

        class ScriptedSession:
            def __init__(self, camera, receipt, *, state):
                self.camera = camera
                self.receipt = receipt
                self.state = state
                self.pf_idx = 0

            def command(self, cmd, allowed=(0,), timeout=12):
                self.state["cmds"].append(cmd)
                self.receipt["commands"].append(cmd)
                if self.pf_idx < 9:
                    item = self.state["preflight"][self.pf_idx]
                    self.pf_idx += 1
                    body, rc = item if isinstance(item, tuple) else (item, 0)
                    runner.require(rc in allowed, f"rc {rc}")
                    return body, rc
                d = self.state["dir"]
                elf = d + "/probe.elf"
                if "for d in /tmp_network/.m7-s6-*" in cmd:
                    return (d + "\n").encode() if self.state["dir_exists"] else b"", 0
                if cmd == f"/bin/busybox mkdir {d}":
                    self.state["dir_exists"] = True
                    return b"", 0
                if cmd.startswith("/bin/busybox chmod") or cmd == "/bin/busybox sleep 1":
                    return b"", 0
                if cmd == "/bin/busybox --list":
                    return b"base64\ngunzip\n", 0
                if "base64 -d" in cmd or "gunzip -c" in cmd or cmd.endswith(".gz"):
                    if self.state.get("fail_upload_poison"):
                        self.camera.dev.poisoned = True
                        raise usb.ProbeError("Missing complete ACK/prompt")
                    return b"", 0
                if cmd == f"/bin/busybox md5sum {elf}":
                    return (hashlib.md5(self.state["image"]).hexdigest() + "  " + elf + "\n").encode(), 0
                if cmd == elf:
                    self.state["launched"] = True
                    self.state["daemon_alive"] = True
                    return b"", 0
                if "echo DIR_OK" in cmd:
                    return (b"DIR_OK\n" if self.state["dir_exists"] else b"DIR_GONE\n"), 0
                if "echo LOG_OK" in cmd:
                    return (self.state.get("log_state", "LOG_OK") + "\n").encode(), 0
                if "echo stop >" in cmd:
                    self.state["stop_written"] = True
                    if self.state.get("daemon_obeys_stop", True):
                        self.state["daemon_alive"] = False
                    return b"", 0
                if "for p in /proc/[1-9]*" in cmd:
                    return (b"/proc/999\n" if self.state["daemon_alive"] else b""), 0
                if "probe.pid" in cmd and "cat" in cmd:
                    return (b"999\n" if self.state["daemon_alive"] else b""), 0
                if "probe.log" in cmd and "cat" in cmd:
                    rc = self.state.get("log_read_rc", 0)
                    return (self.state["log"].encode(), 0) if rc == 0 else (b"", rc)
                if f"readlink /proc/999/exe" in cmd:
                    return (elf.encode() + b"\n", 0) if self.state["daemon_alive"] else (b"", 1)
                if "/proc/999/stat" in cmd and "status" not in cmd:
                    if not self.state["daemon_alive"]:
                        return b"", 1
                    return b"999 (probe.elf) S 1 999 999 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 555 0 0\n", 0
                if "/proc/999/status" in cmd:
                    if not self.state["daemon_alive"]:
                        return b"", 1
                    return b"Name:\tprobe.elf\nPid:\t999\nTgid:\t999\nPPid:\t1\nTracerPid:\t0\n", 0
                if cmd == f"/bin/busybox rm -rf {d}":
                    self.state["dir_exists"] = False
                    return b"", 0
                if "echo PRESENT" in cmd:
                    return (b"PRESENT\n" if self.state["dir_exists"] else b"GONE\n"), 0
                raise AssertionError(f"Unexpected cmd: {cmd}")

        orig_ready = runner.read_ready
        orig_sess = runner.Stage6Session
        orig_excl = runner.write_active_state_exclusive
        orig_repl = runner.replace_active_state_atomic
        try:
            with tempfile.TemporaryDirectory() as td:
                td_p = Path(td)
                nonce = "abcdef012345"
                rdir = "/tmp_network/.m7-s6-" + nonce
                good_log = (
                    "BOOT self_pid=999 w_pid=1000 im_pid=161 mon_proc=170 mon_mwf=170 uipc_ok=1 bk_sz=1 in_ok=1\n"
                    "STATE t=0 cam=1 drive=0x5e fmt=0xbd size=0xb3 asp=0xb9 qual=0xbb bk_ok=1 bk=0x0 bk_rc=0 sub_ok=1 half_ok=1 half=0x0 full_ok=1 full=0x0\n"
                )
                bad_log = (
                    "BOOT self_pid=999 w_pid=1000 im_pid=161 mon_proc=170 mon_mwf=170 uipc_ok=1 bk_sz=1 in_ok=1\n"
                    "STATE t=0 cam=0 bk_ok=0 bk_rc=-1021 sub_ok=0 half_ok=0 full_ok=0\n"
                )

                # 5a. Terminal disable always runs on read_ready() failure
                runner.read_ready = lambda _c: (_ for _ in ()).throw(usb.ProbeError("boom"))
                cam1 = MockCam()
                rec1 = dict(nonce=nonce, model="DSC-RX100M7", commands=[], steps=[], utc="t", probe_sha256="x")
                with self.assertRaises(usb.ProbeError):
                    runner.do_start(cam1, rec1, self.image, active_path=td_p / "a1.json")
                self.assertEqual(cam1.enables, [False, True, False])

                # 5b. do_start rejects all-invalid STATE, stops via stop file (zero kill), cleans RAM dir & custody
                runner.read_ready = lambda _c: b"ready"
                st_bad = dict(cmds=[], preflight=make_preflight_replies(), dir=rdir, dir_exists=False,
                              image=self.image, daemon_alive=False, log=bad_log, daemon_obeys_stop=True)
                runner.Stage6Session = lambda cam, rec: ScriptedSession(cam, rec, state=st_bad)
                ap_bad = td_p / "a_bad.json"
                rec_bad = dict(nonce=nonce, model="DSC-RX100M7", commands=[], steps=[], utc="t", probe_sha256="x")
                with self.assertRaises(usb.ProbeError):
                    runner.do_start(MockCam(), rec_bad, self.image, active_path=ap_bad)
                self.assertTrue(st_bad["stop_written"])
                self.assertFalse(st_bad["dir_exists"])
                self.assertFalse(ap_bad.exists())
                self.assertFalse(any("kill" in c for c in st_bad["cmds"]))

                # 5c. Disk-full on write_active_state_exclusive NEVER creates remote dir or launches probe.elf
                st_df1 = dict(cmds=[], preflight=make_preflight_replies(), dir=rdir, dir_exists=False,
                              image=self.image, daemon_alive=False, log=good_log)
                runner.Stage6Session = lambda cam, rec: ScriptedSession(cam, rec, state=st_df1)
                runner.write_active_state_exclusive = lambda *a, **k: (_ for _ in ()).throw(OSError("ENOSPC"))
                ap_df1 = td_p / "a_df1.json"
                rec_df1 = dict(nonce=nonce, model="DSC-RX100M7", commands=[], steps=[], utc="t", probe_sha256="x")
                with self.assertRaises(OSError):
                    runner.do_start(MockCam(), rec_df1, self.image, active_path=ap_df1)
                self.assertFalse(st_df1.get("launched", False))
                self.assertFalse(st_df1["dir_exists"])
                self.assertFalse(ap_df1.exists())
                runner.write_active_state_exclusive = orig_excl

                # 5c2. Interrupted poisoned upload leaves pending_upload custody; --collect recovers without reboot!
                st_up = dict(cmds=[], preflight=make_preflight_replies(), dir=rdir, dir_exists=False,
                             image=self.image, daemon_alive=False, log="", fail_upload_poison=True)
                runner.Stage6Session = lambda cam, rec: ScriptedSession(cam, rec, state=st_up)
                ap_up = td_p / "a_up.json"
                rec_up = dict(nonce=nonce, model="DSC-RX100M7", commands=[], steps=[], utc="t", probe_sha256="x")
                with self.assertRaises(usb.ProbeError):
                    runner.do_start(MockCam(), rec_up, self.image, active_path=ap_up)
                self.assertTrue(st_up["dir_exists"])
                self.assertTrue(ap_up.exists())
                self.assertEqual(json.loads(ap_up.read_text())["status"], "pending_upload")

                st_up_col = dict(cmds=[], preflight=make_preflight_replies(), dir=rdir, dir_exists=True,
                                 image=self.image, daemon_alive=False, log="", log_state="LOG_ABSENT")
                runner.Stage6Session = lambda cam, rec: ScriptedSession(cam, rec, state=st_up_col)
                rec_up_col = dict(nonce="444444444444", model="DSC-RX100M7", commands=[], steps=[], utc="t")
                runner.do_collect(MockCam(), rec_up_col, active_path=ap_up, log_out_dir=td_p)
                rec_up_col["teardown_requested_clean"] = True
                self.assertFalse(st_up_col["dir_exists"])
                self.assertFalse(ap_up.exists())
                self.assertTrue(rec_up_col["prelaunch_recovered"])
                self.assertEqual(rec_up_col["collect_outcome"], "prelaunch_recovered")
                self.assertTrue(runner.evaluate_cli_success("collect", rec_up_col))

                # 5d. Disk-full on replace_active_state_atomic(running) retains pending_launch custody when daemon stays alive
                st_df2 = dict(cmds=[], preflight=make_preflight_replies(), dir=rdir, dir_exists=False,
                              image=self.image, daemon_alive=False, log=good_log, daemon_obeys_stop=False)
                runner.Stage6Session = lambda cam, rec: ScriptedSession(cam, rec, state=st_df2)
                def fail_only_running(st, path=runner.ACTIVE_STATE):
                    if st.get("status") == "running":
                        raise OSError("ENOSPC")
                    return orig_repl(st, path)
                runner.replace_active_state_atomic = fail_only_running
                ap_df2 = td_p / "a_df2.json"
                rec_df2 = dict(nonce=nonce, model="DSC-RX100M7", commands=[], steps=[], utc="t", probe_sha256="x")
                with self.assertRaises(OSError):
                    runner.do_start(MockCam(), rec_df2, self.image, active_path=ap_df2)
                self.assertTrue(ap_df2.exists())
                self.assertEqual(json.loads(ap_df2.read_text())["status"], "pending_launch")
                runner.replace_active_state_atomic = orig_repl

                # 5e. do_collect recovers that pending_launch when daemon stops, even with im.elf exited (im_exit),
                #     persisting probe.log durably BEFORE deleting the camera dir!
                st_rec = dict(cmds=[], preflight=make_preflight_replies(im_present=False), dir=rdir, dir_exists=True,
                              image=self.image, daemon_alive=True, log=good_log + "STOP t=100 reason=im_exit\n",
                              daemon_obeys_stop=True)
                runner.Stage6Session = lambda cam, rec: ScriptedSession(cam, rec, state=st_rec)
                rec_c1 = dict(nonce="111111111111", model="DSC-RX100M7", commands=[], steps=[], utc="t")
                runner.do_collect(MockCam(), rec_c1, active_path=ap_df2, log_out_dir=td_p)
                rec_c1["teardown_requested_clean"] = True
                self.assertTrue(rec_c1["stopped_cleanly"])
                self.assertTrue(rec_c1["log_persisted"])
                self.assertTrue(Path(rec_c1["saved_log_path"]).is_file())
                self.assertEqual(rec_c1["cleanup"], "GONE")
                self.assertEqual(rec_c1["collect_outcome"], "collected")
                self.assertTrue(runner.evaluate_cli_success("collect", rec_c1))
                self.assertFalse(ap_df2.exists())
                self.assertFalse(rec_c1["preflight"]["im_present_at_collect"])
                self.assertFalse(any("kill" in c for c in st_rec["cmds"]))

                # 5f. do_collect on DIR_GONE (camera rebooted) clears stale active custody cleanly
                ap_stale = td_p / "a_stale.json"
                orig_excl(dict(status="running", nonce=nonce, directory=rdir, daemon_pid=999,
                               daemon_starttime=555, daemon_exe=rdir + "/probe.elf"), ap_stale)
                st_gone = dict(cmds=[], preflight=make_preflight_replies(), dir=rdir, dir_exists=False,
                               image=self.image, daemon_alive=False, log="")
                runner.Stage6Session = lambda cam, rec: ScriptedSession(cam, rec, state=st_gone)
                rec_g = dict(nonce="222222222222", model="DSC-RX100M7", commands=[], steps=[], utc="t")
                runner.do_collect(MockCam(), rec_g, active_path=ap_stale, log_out_dir=td_p)
                rec_g["teardown_requested_clean"] = True
                self.assertTrue(rec_g["stale_active_recovered"])
                self.assertEqual(rec_g["collect_outcome"], "stale_recovered")
                self.assertFalse(ap_stale.exists())
                self.assertTrue(runner.evaluate_cli_success("collect", rec_g))

                # 5g. do_collect when daemon stays alive preserves custody and returns cli_ok=False (exit 1)
                ap_alive = td_p / "a_alive.json"
                orig_excl(dict(status="running", nonce=nonce, directory=rdir, daemon_pid=999,
                               daemon_starttime=555, daemon_exe=rdir + "/probe.elf"), ap_alive)
                st_alive = dict(cmds=[], preflight=make_preflight_replies(), dir=rdir, dir_exists=True,
                                image=self.image, daemon_alive=True, log=good_log, daemon_obeys_stop=False)
                runner.Stage6Session = lambda cam, rec: ScriptedSession(cam, rec, state=st_alive)
                rec_a = dict(nonce="333333333333", model="DSC-RX100M7", commands=[], steps=[], utc="t")
                runner.do_collect(MockCam(), rec_a, active_path=ap_alive, log_out_dir=td_p)
                rec_a["teardown_requested_clean"] = True
                self.assertFalse(rec_a["stopped_cleanly"])
                self.assertEqual(rec_a["cleanup"], "DEFERRED_DAEMON_STILL_ALIVE")
                self.assertTrue(ap_alive.exists())
                self.assertFalse(runner.evaluate_cli_success("collect", rec_a))

                # 5h. do_collect when cat probe.log fails (rc=1) MUST NOT delete remote dir or active custody!
                ap_lfail = td_p / "a_lfail.json"
                orig_excl(dict(status="running", nonce=nonce, directory=rdir, daemon_pid=999,
                               daemon_starttime=555, daemon_exe=rdir + "/probe.elf"), ap_lfail)
                st_lfail = dict(cmds=[], preflight=make_preflight_replies(), dir=rdir, dir_exists=True,
                                image=self.image, daemon_alive=False, log=good_log, log_read_rc=1)
                runner.Stage6Session = lambda cam, rec: ScriptedSession(cam, rec, state=st_lfail)
                rec_lf = dict(nonce="555555555555", model="DSC-RX100M7", commands=[], steps=[], utc="t")
                runner.do_collect(MockCam(), rec_lf, active_path=ap_lfail, log_out_dir=td_p)
                rec_lf["teardown_requested_clean"] = True
                self.assertTrue(st_lfail["dir_exists"])
                self.assertTrue(ap_lfail.exists())
                self.assertEqual(rec_lf["cleanup"], "DEFERRED_LOG_READ_FAILED")
                self.assertEqual(rec_lf["collect_outcome"], "incomplete")
                self.assertFalse(runner.evaluate_cli_success("collect", rec_lf))

                # 5i. do_collect when local log persistence hits ENOSPC raises BEFORE deleting remote dir or active custody!
                ap_pfail = td_p / "a_pfail.json"
                orig_excl(dict(status="running", nonce=nonce, directory=rdir, daemon_pid=999,
                               daemon_starttime=555, daemon_exe=rdir + "/probe.elf"), ap_pfail)
                st_pfail = dict(cmds=[], preflight=make_preflight_replies(), dir=rdir, dir_exists=True,
                                image=self.image, daemon_alive=False, log=good_log)
                runner.Stage6Session = lambda cam, rec: ScriptedSession(cam, rec, state=st_pfail)
                orig_persist = runner.persist_collected_log_atomic
                runner.persist_collected_log_atomic = lambda *a, **k: (_ for _ in ()).throw(OSError("ENOSPC"))
                try:
                    rec_pf = dict(nonce="666666666666", model="DSC-RX100M7", commands=[], steps=[], utc="t")
                    with self.assertRaises(OSError):
                        runner.do_collect(MockCam(), rec_pf, active_path=ap_pfail, log_out_dir=td_p)
                    self.assertTrue(st_pfail["dir_exists"])
                    self.assertTrue(ap_pfail.exists())
                finally:
                    runner.persist_collected_log_atomic = orig_persist
        finally:
            runner.read_ready = orig_ready
            runner.Stage6Session = orig_sess
            runner.write_active_state_exclusive = orig_excl
            runner.replace_active_state_atomic = orig_repl

    def test_08_sealed_release_covers_shared_scripts_and_matches_rebuild(self):
        sealed_img, sealed_manifest = builder.verify_seal()
        self.assertEqual(sealed_img, self.image)
        self.assertEqual(sealed_manifest["sha256"], self.manifest["sha256"])
        self.assertIn("scripts/m7_burst_identity.py", sealed_manifest["host_source_hashes"])
        self.assertIn("scripts/m7_probe.py", sealed_manifest["host_source_hashes"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
