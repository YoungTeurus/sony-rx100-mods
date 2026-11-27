"""End-to-end offline ARM32 Unicorn verification of the sealed Stage 7.1 build.

Tests all seven sealed Stage 7.1 artifacts against the REAL extracted DSC-RX100M7 1.00
binaries (viewUnified2.so, libObj.so, libtestcmd.so) at shifted (relocated) load bases:
  1. Layout & seal integrity (Stage 7.1 + PreCapture.mod + Stage 6 v1/v2).
  2. mlv2_guard.elf (fnv, read-only check, BUSY PC refusal, install + relocation,
     idempotence, uninstall refusal without sd-stopped, clean uninstall restoring
     100% stock bytes in safe order, and mid-write failure rollback).
  3. Real hooked viewUnified2.so entry points -> mlv2 trampolines -> shim -> core ->
     PreCapture.mod SMNU submenu (OFF edit, ON, live cycling 8->10->1->2->3->5,
     OFF, < Back, stock open_item pass-through, and sd-disabled 7->6 restore).
  4. stage7_daemon.elf in Unicorn ARM32: zero-ptrace/zero-uipc verification,
     fail-closed precap.cfg gating, live pre_frames (8 and 10) propagation into
     atomic run.cfg, active-ring disarm on OFF, and indefinite duration_ms==0 mode.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import unittest
from pathlib import Path

import unicorn as uc
from unicorn import arm_const as A

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "out"

sys.path.insert(0, str(HERE))
import build_precap_mod  # noqa: E402
import build_stage7  # noqa: E402
import m7_100_layout as layout  # noqa: E402

VIEW_BYTES = (ROOT / layout.STAGE7 / "lib/viewUnified2.so").read_bytes()
TESTCMD_BYTES = (ROOT / layout.TESTCMD / "lib/libtestcmd.so").read_bytes()
LIBOBJ_BYTES = (ROOT / layout.ORIGINAL / "lib/libObj.so").read_bytes()


def load_elf_into_uc(m: uc.Uc, elf_bytes: bytes):
    """Map PT_LOAD segments of an ARM32 ELF into Unicorn and return entry address."""
    e_entry, e_phoff, _, _, _, e_phentsize, e_phnum = struct.unpack_from("<IIIIHHH", elf_bytes, 24)
    for i in range(e_phnum):
        p_type, p_off, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack_from(
            "<8I", elf_bytes, e_phoff + i * e_phentsize
        )
        if p_type != 1:
            continue
        lo = p_vaddr & ~0xFFF
        hi = (p_vaddr + p_memsz + 0xFFF) & ~0xFFF
        prot = 0
        if p_flags & 4:
            prot |= uc.UC_PROT_READ
        if p_flags & 2:
            prot |= uc.UC_PROT_WRITE
        if p_flags & 1:
            prot |= uc.UC_PROT_EXEC
        m.mem_map(lo, hi - lo, prot)
        m.mem_write(p_vaddr, elf_bytes[p_off:p_off + p_filesz])
    return e_entry


def pack_dirents(entries: list[tuple[str, int]]) -> bytes:
    buf = b""
    for name, dtype in entries:
        nm = name.encode("ascii") + b"\x00"
        rl = (19 + len(nm) + 7) & ~7
        buf += struct.pack("<QqHB", 1, 0, rl, dtype) + nm.ljust(rl - 19, b"\x00")
    return buf


class GuardHarness:
    """Runs the real sealed mlv2_guard.elf ARM32 binary against a simulated im.elf."""

    def __init__(self, guard_elf: bytes, files: dict[str, bytes],
                 view_base: int, testcmd_base: int = 0, tids=(149, 150, 151)):
        self.guard_elf = guard_elf
        self.files = dict(files)
        self.view_base = view_base
        self.testcmd_base = testcmd_base
        self.shim_base = view_base + layout.REF_SHIM_OFF
        self.tids = list(tids)
        self.thread_pcs = {t: 0x00020000 for t in tids}
        self.thread_lrs = {t: 0x00020100 for t in tids}
        self.thread_sps = {t: 0x5D001000 + i * 0x4000 for i, t in enumerate(tids)}
        self.fail_poke_call = None  # 1-based poke call index to fail
        # Target process memory backing: real M7 1.00 slices of viewUnified2.so + thread stacks
        self.regions: list[tuple[int, bytearray]] = []
        # Map 3 separate 16 KiB thread stacks with unmapped guard pages between them
        for i in range(len(tids)):
            self.regions.append((0x5D001000 + i * 0x4000, bytearray(0x3000)))
        # Map viewUnified2.so hooks page range (0x695000..0x698000)
        vh = bytearray(VIEW_BYTES[0x695000:0x698000])
        self.regions.append((view_base + 0x695000, vh))
        # Map viewUnified2.so rect tables page range (0x88c000..0x88d000)
        vr = bytearray(VIEW_BYTES[0x88C000:0x88D000])
        self.regions.append((view_base + 0x88C000, vr))
        # Map viewUnified2.so RX tail page (0x972000..0x973000; 0x9727f0..0x973000 is zero slack)
        vc = bytearray(VIEW_BYTES[0x972000:0x973000])
        self.regions.append((view_base + 0x972000, vc))
        stack_maps = "".join(
            f"{0x5D001000 + i * 0x4000:08x}-{0x5D001000 + i * 0x4000 + 0x3000:08x} rw-p 00000000 00:00 0\n"
            for i in range(len(tids))
        )
        self.maps_text = (
            f"{view_base:08x}-{view_base + 0x973000:08x} r-xp 00000000 fc:0f 49318 /usr/lib/viewUnified2.so\n"
            + stack_maps
        ).encode("ascii")

    def read_target(self, addr: int, n: int) -> bytes | None:
        for base, buf in self.regions:
            if base <= addr and addr + n <= base + len(buf):
                off = addr - base
                return bytes(buf[off:off + n])
        return None

    def write_target_word(self, addr: int, word: int) -> bool:
        for base, buf in self.regions:
            if base <= addr and addr + 4 <= base + len(buf):
                off = addr - base
                struct.pack_into("<I", buf, off, word)
                return True
        return False

    def run(self, argv: list[str]) -> tuple[int, str, dict]:
        m = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
        entry = load_elf_into_uc(m, self.guard_elf)
        stack_lo, stack_sz = 0x5F000000, 0x20000
        m.mem_map(stack_lo, stack_sz)
        # Layout argv strings + Linux EABI initial stack: [argc, argv[0], ..., 0]
        sp_str = stack_lo + stack_sz - 0x400
        ptrs = []
        for s in argv:
            raw = s.encode("ascii") + b"\x00"
            m.mem_write(sp_str, raw)
            ptrs.append(sp_str)
            sp_str += (len(raw) + 3) & ~3
        sp = stack_lo + stack_sz - 0x1000
        stack_frame = struct.pack("<I", len(argv)) + b"".join(struct.pack("<I", p) for p in ptrs) + struct.pack("<I", 0)
        m.mem_write(sp, stack_frame)
        m.reg_write(A.UC_ARM_REG_SP, sp)

        stdout = bytearray()
        fds: dict[int, list] = {}
        next_fd = 3
        mm_next = 0x40000000
        exit_code = [None]
        stats = dict(ptrace_calls=[], attached=set(), poke_addrs=[], poke_count=0)

        def read_cstr(addr: int) -> str:
            return bytes(m.mem_read(addr, 128)).split(b"\x00", 1)[0].decode("ascii")

        def syscall(cpu, intno, _):
            nonlocal next_fd, mm_next
            nr = cpu.reg_read(A.UC_ARM_REG_R7)
            r0 = cpu.reg_read(A.UC_ARM_REG_R0)
            r1 = cpu.reg_read(A.UC_ARM_REG_R1)
            r2 = cpu.reg_read(A.UC_ARM_REG_R2)
            r3 = cpu.reg_read(A.UC_ARM_REG_R3)
            r4 = cpu.reg_read(A.UC_ARM_REG_R4)
            rc = 0
            if nr == 1:  # exit
                exit_code[0] = r0
                cpu.emu_stop()
                return
            elif nr == 4:  # write
                data = bytes(cpu.mem_read(r1, r2))
                if r0 in (1, 2):
                    stdout.extend(data)
                rc = len(data)
            elif nr == 5:  # open
                path = read_cstr(r0)
                if path == "/proc":
                    fds[next_fd] = ["dir", [("1", 4), ("149", 4)], False]
                    rc = next_fd; next_fd += 1
                elif path == "/proc/149/task":
                    fds[next_fd] = ["dir", [(str(t), 4) for t in self.tids], False]
                    rc = next_fd; next_fd += 1
                elif path == "/proc/149/maps":
                    fds[next_fd] = ["file", self.maps_text, 0]
                    rc = next_fd; next_fd += 1
                elif path == "/proc/149/mem":
                    fds[next_fd] = ["mem", None, 0]
                    rc = next_fd; next_fd += 1
                elif path in self.files:
                    fds[next_fd] = ["file", self.files[path], 0]
                    rc = next_fd; next_fd += 1
                else:
                    rc = -2
            elif nr == 3:  # read
                f = fds[r0]
                assert f[0] == "file"
                chunk = f[1][f[2]:f[2] + r2]
                cpu.mem_write(r1, chunk)
                f[2] += len(chunk)
                rc = len(chunk)
            elif nr == 180:  # pread64 (r3=0 pad, r4=offset_lo)
                f = fds[r0]
                assert f[0] == "mem" and r3 == 0
                data = self.read_target(r4, r2)
                if data is None:
                    rc = -5
                else:
                    cpu.mem_write(r1, data)
                    rc = len(data)
            elif nr == 6:  # close
                fds.pop(r0, None)
            elif nr == 85:  # readlink
                path = read_cstr(r0)
                if path == "/proc/149/exe":
                    val = b"/usr/bin/im.elf"
                elif path == "/proc/1/exe":
                    val = b"/sbin/init"
                else:
                    rc = -2
                    val = b""
                if val:
                    n = min(len(val), r2)
                    cpu.mem_write(r1, val[:n])
                    rc = n
            elif nr == 217:  # getdents64
                f = fds[r0]
                assert f[0] == "dir"
                if f[2]:
                    rc = 0
                else:
                    raw = pack_dirents(f[1])
                    cpu.mem_write(r1, raw)
                    f[2] = True
                    rc = len(raw)
            elif nr == 192:  # mmap2
                sz = (r1 + 0xFFF) & ~0xFFF
                cpu.mem_map(mm_next, sz)
                rc = mm_next
                mm_next += sz + 0x1000
            elif nr == 197:  # fstat64
                st = bytearray(104)
                struct.pack_into("<I", st, 16, 0o100600)
                cpu.mem_write(r1, bytes(st))
                rc = 0
            elif nr == 91:  # munmap
                rc = 0
            elif nr == 26:  # ptrace
                req, pid, addr, data = r0, r1, r2, r3
                stats["ptrace_calls"].append((req, pid, addr))
                if req == 16:  # ATTACH
                    assert pid in self.tids and pid not in stats["attached"]
                    stats["attached"].add(pid)
                    rc = 0
                elif req == 17:  # DETACH
                    assert pid in stats["attached"]
                    stats["attached"].remove(pid)
                    rc = 0
                elif req == 12:  # GETREGS
                    assert pid in stats["attached"]
                    regs = [0] * 18
                    regs[13] = self.thread_sps[pid]
                    regs[14] = self.thread_lrs[pid]
                    regs[15] = self.thread_pcs[pid]
                    cpu.mem_write(data, struct.pack("<18I", *regs))
                    rc = 0
                elif req == 4:  # POKETEXT
                    assert pid in stats["attached"]
                    stats["poke_count"] += 1
                    stats["poke_addrs"].append(addr)
                    if self.fail_poke_call is not None and stats["poke_count"] == self.fail_poke_call:
                        rc = -5
                    else:
                        rc = 0 if self.write_target_word(addr, data) else -5
                else:
                    raise AssertionError(f"unexpected ptrace req {req}")
            elif nr == 114:  # wait4
                pid, st_ptr = r0, r1
                assert pid in stats["attached"]
                if st_ptr:
                    cpu.mem_write(st_ptr, struct.pack("<I", 0x137F))  # WIFSTOPPED(SIGSTOP)
                rc = pid
            else:
                raise AssertionError(f"unexpected syscall {nr}")
            cpu.reg_write(A.UC_ARM_REG_R0, rc & 0xFFFFFFFF)

        m.hook_add(uc.UC_HOOK_INTR, syscall)
        m.emu_start(entry, 0, count=20_000_000)
        assert exit_code[0] is not None, "mlv2_guard did not exit"
        return exit_code[0], stdout.decode("ascii"), stats


class EndToEndMenuHarness:
    """Runs the REAL hooked M7 viewUnified2.so entry points -> shim -> core -> PreCapture.mod."""

    def __init__(self, guard: GuardHarness, core_bin: bytes, precap_mod: bytes):
        self.view_base = guard.view_base
        self.shim_va = guard.view_base + layout.REF_SHIM_OFF
        self.libobj_base = layout.REF_LIBOBJ_BASE + 0x10000
        self.files: dict[str, bytes] = {
            "/tmp_network/mlv2/core.bin": core_bin,
            "/tmp_network/mods/PreCapture.mod": precap_mod,
        }
        self.maps_text = (
            f"{self.view_base:08x}-{self.view_base + 0x973000:08x} r-xp 00000000 fc:0f 2 /usr/lib/viewUnified2.so\n"
            f"{self.libobj_base:08x}-{self.libobj_base + 0x1325000:08x} r-xp 00000000 fc:0f 3 /usr/lib/libObj.so\n"
        ).encode("ascii")

        self.MENU = 0x30000000
        self.NODES = 0x31000000
        self.STUBS = 0x32000000
        self.MMAP0 = 0x40000000
        self.STACK = 0x50000000
        self.STOP = 0x5F000000
        self.mm_next = self.MMAP0
        self.munmap_calls: list[tuple[int, int]] = []
        self.fds: dict[int, list] = {}
        self.next_fd = 3
        self.texts: list[tuple[int, str]] = []
        self.set_mode_calls: list[tuple[int, int]] = []
        self.menu_refresh_calls = 0
        self.stock_open_item_hits = 0
        self.log: list[str] = []
        self.log_bytes = 0
        self.fsync_calls: list[str] = []
        self.fail_fsync_paths: set[str] = set()
        self.fail_rename_dsts: set[str] = set()
        self.fail_unlink_paths: set[str] = set()
        self.fail_fstat_once_paths: set[str] = set()
        self.files_at_failed_fstat: dict[str, bytes] = {}
        self.fifo_paths: set[str] = set()
        self.fifo_has_reader: bool = True
        self.open_events: list[tuple[str, int]] = []
        self.rename_unlink_paths: list[str] = []
        self.runtime_at_fsync: list[bytes | None] = []

        self.set_text_va = self.view_base + layout.CONSTANTS["SET_TEXT"]["offset"]
        self.set_mode_va = self.view_base + layout.CONSTANTS["SET_MODE"]["offset"]
        self.set_root_va = self.view_base + layout.HOOKS["set_root"]["offset"]
        self.refresh_va = self.view_base + layout.HOOKS["refresh"]["offset"]
        self.open_item_va = self.view_base + layout.HOOKS["open_item"]["offset"]
        self.menu_refresh_va = self.view_base + layout.MENU_REFRESH["offset"]

        m = self.m = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB)
        # Map live patched viewUnified2.so RX tail page (0x972000..0x973000) from mlv2_guard!
        vc_bytes = guard.read_target(self.view_base + 0x972000, 0x1000)
        assert vc_bytes is not None
        m.mem_map(self.view_base + 0x972000, 0x1000, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
        m.mem_write(self.view_base + 0x972000, vc_bytes)

        # Map viewUnified2.so PLT pages + live patched hooks page from mlv2_guard!
        m.mem_map(self.view_base + 0x160000, 0x10000)
        vh_bytes = guard.read_target(self.view_base + 0x695000, 0x3000)
        assert vh_bytes is not None
        m.mem_map(self.view_base + 0x695000, 0x3000)
        m.mem_write(self.view_base + 0x695000, vh_bytes)

        # Map MENU, NODES, STUBS, STACK, STOP
        for base, sz in (
            (self.MENU, 0x20000),
            (self.NODES, 0x10000),
            (self.STUBS, 0x1000),
            (self.STACK - 0x10000, 0x10000),
            (self.STOP, 0x1000),
        ):
            m.mem_map(base, sz)

        # Build stock 6-tab root node tree
        vt = self.NODES + 0x1000
        m.mem_write(vt, struct.pack("<72I", *[(self.STUBS + 4 * i) | 1 for i in range(72)]))
        kids = self.NODES + 0x2000
        tabs = [self.NODES + 0x3000 + 0x40 * i for i in range(6)]
        for t in tabs:
            m.mem_write(t, struct.pack("<10I", vt, 0, 0, 0, 0, 2, 1, 0, 0, 0))
        m.mem_write(kids, struct.pack("<6I", *tabs))
        self.root = self.NODES
        self.orig_kids = kids
        m.mem_write(self.root, struct.pack("<10I", vt, kids, 6, 0, 0, 1, 1, 0, 0, 0))
        m.mem_write(self.MENU + 0x1F0, struct.pack("<I", 7))  # tab 7 (Mods)
        m.mem_write(self.MENU + 0x1F4, struct.pack("<I", 1))  # page 1

        # Patch return stubs inside viewUnified2.so at the exact post-hook continuation points:
        # 1) set_root+0x10 (normal path after storing root into [menu+0x186ac]): return 1 via pop {r3,r4,r7,pc}
        m.mem_write(self.set_root_va + 0x10, bytes.fromhex("012098bd"))  # movs r0,#1; pop {r3,r4,r7,pc}
        # 2) set_root+0x1c (null root path): return 0 via pop {r3,r4,r7,pc}
        m.mem_write(self.set_root_va + 0x1c, bytes.fromhex("002098bd"))  # movs r0,#0; pop {r3,r4,r7,pc}
        # 3) refresh+0x0e (ml_orig_refresh continuation): unwind sub sp,#108 + stmdb {r4..r11,lr} and return!
        m.mem_write(self.refresh_va + 0x0e, bytes.fromhex("1bb0bde8f08f"))  # add sp,#108; pop.w {r4..r11,pc}
        # 4) open_item+0x08 (stock pass-through continuation): intercepted by code hook below.
        # 5) menu_refresh (0x696ec4): intercepted by code hook to clear texts and call real hooked refresh!

        m.hook_add(uc.UC_HOOK_INTR, self._syscall)
        m.hook_add(uc.UC_HOOK_CODE, self._code)

    def _ret(self, val: int = 0):
        self.m.reg_write(A.UC_ARM_REG_R0, val & 0xFFFFFFFF)
        self.m.reg_write(A.UC_ARM_REG_PC, self.m.reg_read(A.UC_ARM_REG_LR))

    def _code(self, cpu, pc, size, _):
        if pc == self.STOP:
            cpu.emu_stop()
        elif pc == self.set_text_va:
            r0 = cpu.reg_read(A.UC_ARM_REG_R0)
            r1 = cpu.reg_read(A.UC_ARM_REG_R1)
            txt = bytes(cpu.mem_read(r1, 48)).split(b"\x00", 1)[0].decode("ascii")
            self.texts.append((r0 - self.MENU, txt))
            self._ret()
        elif pc == self.set_mode_va:
            r0 = cpu.reg_read(A.UC_ARM_REG_R0)
            r1 = cpu.reg_read(A.UC_ARM_REG_R1)
            self.set_mode_calls.append((r0 - self.MENU, r1))
            self._ret()
        elif pc == self.open_item_va + 0x08:
            # Verify trampoline replayed original 8 bytes: r3 == menu + 0x186b0
            assert cpu.reg_read(A.UC_ARM_REG_R3) == self.MENU + 0x186B0
            self.stock_open_item_hits += 1
            self._ret(1)
        elif pc == self.menu_refresh_va:
            # Emulate Sony's 0x696ec4 tail: clear texts and branch to hooked refresh(menu, r1)
            self.menu_refresh_calls += 1
            self.texts.clear()
            cpu.reg_write(A.UC_ARM_REG_PC, self.refresh_va | 1)
        elif self.STUBS <= pc < self.STUBS + 0x1000:
            idx = (pc - self.STUBS) // 4
            if idx in (23, 32):
                r2 = cpu.reg_read(A.UC_ARM_REG_R2)
                cpu.mem_write(r2, struct.pack("<I", 0x020CC006))
                self._ret(1)
            else:
                self._ret(0)

    def _syscall(self, cpu, intno, _):
        nr = cpu.reg_read(A.UC_ARM_REG_R7)
        a = [cpu.reg_read(r) for r in (A.UC_ARM_REG_R0, A.UC_ARM_REG_R1, A.UC_ARM_REG_R2,
                                       A.UC_ARM_REG_R3, A.UC_ARM_REG_R4, A.UC_ARM_REG_R5)]
        rc = 0
        if nr == 5:  # open
            path = bytes(cpu.mem_read(a[0], 96)).split(b"\x00", 1)[0].decode("ascii")
            flags = a[1]
            self.open_events.append((path, flags))
            if path == "/proc/self/maps":
                rc = self.next_fd; self.next_fd += 1; self.fds[rc] = ["file", self.maps_text, 0, path]
            elif path.endswith("mod_loader.log"):
                if path in self.fifo_paths and not self.fifo_has_reader:
                    if flags & 0o4000:
                        rc = -6  # -ENXIO: non-blocking O_WRONLY open of FIFO with no reader
                    else:
                        raise AssertionError(f"Blocking open of FIFO {path} without O_NONBLOCK (flags={flags:#x})")
                else:
                    self.fds[99] = ["log", None, 0, path]
                    rc = 99
            elif flags & 0o40000:  # O_DIRECTORY
                entries = {}
                prefix = path + "/"
                for p in self.files:
                    if p.startswith(prefix):
                        rem = p[len(prefix):]
                        if "/" in rem:
                            entries[rem.split("/", 1)[0]] = 4
                        else:
                            entries.setdefault(rem, 8)
                if entries or path == "/tmp_network/mods":
                    rc = self.next_fd; self.next_fd += 1; self.fds[rc] = ["dir", sorted(entries.items()), False, path]
                else:
                    rc = -2
            elif (flags & 0o100) and (flags & 0o200):  # O_CREAT | O_EXCL (PreCapture.mod .tmp)
                if path in self.files:
                    rc = -17
                else:
                    self.files[path] = bytearray()
                    rc = self.next_fd; self.next_fd += 1; self.fds[rc] = ["wfile", path, 0, path]
            elif (flags & 0x3) == 1 and (flags & 0o100):  # create trunc/append (sd-stopped, reload.result)
                if (flags & 0o1000) or path not in self.files:
                    self.files[path] = bytearray()
                rc = self.next_fd; self.next_fd += 1; self.fds[rc] = ["wfile", path, 0, path]
            elif path in self.files:
                rc = self.next_fd; self.next_fd += 1; self.fds[rc] = ["file", bytes(self.files[path]), 0, path]
            else:
                rc = -2
        elif nr == 3:  # read
            f = self.fds[a[0]]
            chunk = f[1][f[2]:f[2] + a[2]]
            cpu.mem_write(a[1], chunk)
            f[2] += len(chunk)
            rc = len(chunk)
        elif nr == 4:  # write
            data = bytes(cpu.mem_read(a[1], a[2]))
            if a[0] == 99:
                self.log.append(data.decode("ascii").strip())
                self.log_bytes += len(data)
            else:
                f = self.fds[a[0]]
                assert f[0] == "wfile"
                self.files[f[1]] = bytes(self.files[f[1]]) + data
            rc = len(data)
        elif nr == 6:  # close
            self.fds.pop(a[0], None)
        elif nr == 10:  # unlink
            path = bytes(cpu.mem_read(a[0], 96)).split(b"\x00", 1)[0].decode("ascii")
            self.rename_unlink_paths.append(path)
            if path in self.fail_unlink_paths:
                rc = -13
            else:
                rc = 0 if self.files.pop(path, None) is not None else -2
        elif nr == 19:  # lseek
            if a[0] == 99:
                if a[2] == 2:  # SEEK_END
                    rc = self.log_bytes + a[1]
                else:
                    rc = a[1]
            else:
                if a[2] == 2:
                    self.fds[a[0]][2] = len(self.fds[a[0]][1]) + a[1]
                else:
                    self.fds[a[0]][2] = a[1]
                rc = self.fds[a[0]][2]
        elif nr == 118:  # fsync
            f = self.fds[a[0]]
            assert f[0] == "wfile"
            self.fsync_calls.append(f[1])
            self.runtime_at_fsync.append(
                bytes(self.files["/tmp_network/mlv2/precap.cfg"])
                if "/tmp_network/mlv2/precap.cfg" in self.files else None
            )
            rc = -5 if f[1] in self.fail_fsync_paths else 0
        elif nr == 197:  # fstat64
            f = self.fds[a[0]]
            fpath = f[3] if len(f) > 3 else ""
            if fpath in self.fail_fstat_once_paths:
                self.fail_fstat_once_paths.remove(fpath)
                self.files_at_failed_fstat = self.files.copy()
                rc = -5
            else:
                st = bytearray(104)
                mode = 0o010600 if fpath in self.fifo_paths else (0o040755 if f[0] == "dir" else 0o100600)
                struct.pack_into("<I", st, 16, mode)
                cpu.mem_write(a[1], bytes(st))
                rc = 0
        elif nr == 38:  # rename
            old = bytes(cpu.mem_read(a[0], 96)).split(b"\x00", 1)[0].decode("ascii")
            new = bytes(cpu.mem_read(a[1], 96)).split(b"\x00", 1)[0].decode("ascii")
            self.rename_unlink_paths.extend((old, new))
            assert old in self.files
            if new in self.fail_rename_dsts:
                rc = -5
            else:
                self.files[new] = self.files.pop(old)
                rc = 0
        elif nr == 217:  # getdents64
            f = self.fds[a[0]]
            if f[2]:
                rc = 0
            else:
                raw = pack_dirents(f[1])
                cpu.mem_write(a[1], raw)
                f[2] = True
                rc = len(raw)
        elif nr == 192:  # mmap2
            sz = (a[1] + 0xFFF) & ~0xFFF
            cpu.mem_map(self.mm_next, sz)
            rc = self.mm_next
            self.mm_next += sz + 0x1000
        elif nr == 91:  # munmap
            self.munmap_calls.append((a[0], a[1]))
            cpu.mem_unmap(a[0], a[1])
            rc = 0
        elif nr == 125:  # mprotect
            cpu.mem_protect(a[0], a[1], uc.UC_PROT_ALL)
            rc = 0
        elif nr == 242:  # sched_getaffinity
            cpu.mem_write(a[2], struct.pack("<I", 0xF))
            rc = 0
        elif nr in (241, 0x0F0002):  # sched_setaffinity / cacheflush
            rc = 0
        else:
            raise AssertionError(f"unexpected syscall {nr}")
        cpu.reg_write(A.UC_ARM_REG_R0, rc & 0xFFFFFFFF)

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.m.mem_read(addr, 4))[0]

    def call_real_set_root(self, root_ptr: int) -> int:
        # Real set_root prologue at 0x696406 is `push {r3, r4, r7, lr}` before the hook at 0x696408!
        sp = self.STACK - 0x100
        sp -= 16
        self.m.mem_write(sp, struct.pack("<4I", 0, 0, 0, self.STOP | 1))
        self.m.reg_write(A.UC_ARM_REG_SP, sp)
        self.m.reg_write(A.UC_ARM_REG_R0, self.MENU)
        self.m.reg_write(A.UC_ARM_REG_R1, root_ptr)
        self.m.reg_write(A.UC_ARM_REG_LR, self.STOP | 1)
        self.m.emu_start(self.set_root_va | 1, self.STOP, count=5_000_000)
        return self.m.reg_read(A.UC_ARM_REG_R0)

    def call_real_refresh(self):
        self.m.reg_write(A.UC_ARM_REG_SP, self.STACK - 0x100)
        self.m.reg_write(A.UC_ARM_REG_R0, self.MENU)
        self.m.reg_write(A.UC_ARM_REG_R1, 0)
        self.m.reg_write(A.UC_ARM_REG_LR, self.STOP | 1)
        self.m.emu_start(self.refresh_va | 1, self.STOP, count=5_000_000)

    def call_real_open_item(self, leaf_ptr: int) -> int:
        self.m.reg_write(A.UC_ARM_REG_SP, self.STACK - 0x100)
        self.m.reg_write(A.UC_ARM_REG_R0, self.MENU)
        self.m.reg_write(A.UC_ARM_REG_R1, leaf_ptr)
        self.m.reg_write(A.UC_ARM_REG_LR, self.STOP | 1)
        self.m.emu_start(self.open_item_va | 1, self.STOP, count=5_000_000)
        return self.m.reg_read(A.UC_ARM_REG_R0)

    def items(self, page_idx: int = 0) -> list[int]:
        kids = self.u32(self.root + 4)
        tab = self.u32(kids + 24)
        pages = self.u32(tab + 4)
        page = self.u32(pages + 4 * page_idx)
        items = self.u32(page + 4)
        return [self.u32(items + 4 * i) for i in range(self.u32(page + 8))]


class DaemonHarness:
    """Runs the real sealed stage7_daemon.elf ARM32 binary against a simulated M7 camera."""

    def __init__(self, daemon_elf: bytes, daemon_meta: dict, nonce: str = "a1b2c3d4e5f6",
                 duration_ms: int = 2000, poll_ms: int = 20, debounce_ms: int = 0):
        buf = bytearray(daemon_elf)
        cfg_off = daemon_meta["config_offset"]
        # Patch config for non-daemonized deterministic offline test
        struct.pack_into(
            "<13I12s", buf, cfg_off,
            build_stage7.DAEMON_MAGIC, build_stage7.DAEMON_VERSION,
            duration_ms, poll_ms, 500, 131072, 0,  # daemonize=0 -> logs to stdout
            0, 96, debounce_ms, 300, 24, 48,
            nonce.encode("ascii"),
        )
        self.elf = bytes(buf)
        self.nonce = nonce
        self.run_dir = f"/tmp_network/.m7-s7-{nonce}"
        self.libobj = 0x05ECD000
        self.mwf = 0x09000000
        self.mpr = 0x0A000000
        self.mprctrl = 0x0B000000
        self.heap = 0x20000000
        self.im_mem = self._build_im_mem()
        self.files: dict[str, bytes] = {
            f"{self.run_dir}/ring.elf": b"\x7fELF",
        }
        self.half = 0
        self.full = 0
        self.sub_en = 1
        self.on_tick = None  # callback(tick_num, harness)
        self.ring_exit_after_polls = 2
        self.ring_polls_left = 0
        self.ring_pid = None
        self.spawned_cfgs: list[dict] = []
        self.disarm_seen_during_ring = False

    def _build_im_mem(self) -> dict[int, bytearray]:
        # Sparse page-aligned target memory regions for /proc/149/mem
        libobj_bss = bytearray(0x40000)  # covers 0x1425000..0x1465000
        mwf_rw = bytearray(0x10000)      # covers 0x40000..0x50000
        heap = bytearray(0x10000)        # covers 0x20000000..0x20010000

        # CamSetParams header + int7 ftbl + 5 params (Continuous JPEG L 20M 3:2)
        struct.pack_into("<II", libobj_bss, 0x145F3E8 - 0x1425000, self.libobj + 0x145F3F0, 1)
        struct.pack_into("<I", mwf_rw, 0x42CEC - 0x40000, 7)
        params = [
            (0x145F4F4, 0x005F),  # Continuous drive
            (0x145F5F0, 0x00B3),  # L 20M
            (0x145F5F4, 0x00B9),  # 3:2
            (0x145F5F8, 0x0002),  # Fine
            (0x145F5FC, 0x00BD),  # JPEG
        ]
        p_off = 0x100
        for slot, val in params:
            struct.pack_into("<I", libobj_bss, slot - 0x1425000, self.heap + p_off)
            struct.pack_into("<II", heap, p_off, val, self.mwf + 0x42CEC)
            p_off += 16

        # Monitor TID (205) in libMWF
        mon_obj = self.heap + 0x400
        mon_hdr = self.heap + 0x500
        struct.pack_into("<II", mwf_rw, 0x45478 - 0x40000, 1, mon_obj)
        struct.pack_into("<I", heap, 0x400, self.mwf + 0x43088)
        struct.pack_into("<II", heap, 0x400 + 20, mon_hdr, 205)
        struct.pack_into("<III", heap, 0x500, 0x66888866, 0, 205)

        # InfraInput root (0x1000), config table (0x2000), state table (0x3000)
        in_root = self.heap + 0x1000
        in_cfg = self.heap + 0x2000
        in_st = self.heap + 0x3000
        struct.pack_into("<I", libobj_bss, 0x145D230 - 0x1425000, in_root)
        struct.pack_into("<I", heap, 0x1000, self.libobj + 0x1387AF0)
        struct.pack_into("<II", heap, 0x1000 + 24, in_cfg, 2)
        struct.pack_into("<I", heap, 0x1000 + 36, in_st)
        # Entry 0 = half (0x1f1), Entry 1 = full (0xa7)
        struct.pack_into("<I", heap, 0x2000 + 8, 0x1F1)
        struct.pack_into("<I", heap, 0x2000 + 0x30 + 8, 0x0A7)
        struct.pack_into("<5I", heap, 0x3000, 0x1F1, 0, 0, 0, 0)
        struct.pack_into("<5I", heap, 0x3000 + 0x28, 0x0A7, 0, 0, 0, 1)

        # Spinal (0x4000) + Camera obj (0x4200)
        spinal = self.heap + 0x4000
        cam_obj = self.heap + 0x4200
        struct.pack_into("<I", libobj_bss, 0x1463130 - 0x1425000, spinal)
        struct.pack_into("<I", heap, 0x4200, self.libobj + 0x1390490)
        struct.pack_into("<II", heap, 0x4000, in_root, cam_obj)
        struct.pack_into("<II", heap, 0x4000 + 88, 1, 1)  # cb=1, sub_en=1

        return {
            self.libobj + 0x1425000: libobj_bss,
            self.mwf + 0x40000: mwf_rw,
            self.heap: heap,
        }

    def sync_live_state(self):
        heap = self.im_mem[self.heap]
        struct.pack_into("<I", heap, 0x3000 + 8, self.half)
        struct.pack_into("<I", heap, 0x3000 + 0x28 + 8, self.full)
        struct.pack_into("<I", heap, 0x4000 + 92, self.sub_en)

    def read_im_mem(self, addr: int, size: int) -> bytes | None:
        self.sync_live_state()
        for base, buf in self.im_mem.items():
            if base <= addr and addr + size <= base + len(buf):
                off = addr - base
                return bytes(buf[off:off + size])
        return None

    def run(self) -> tuple[int, str]:
        m = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
        entry = load_elf_into_uc(m, self.elf)
        m.mem_map(0x5F000000, 0x20000)
        m.reg_write(A.UC_ARM_REG_SP, 0x5F01F000)

        maps_txt = (
            f"{self.libobj:08x}-{self.libobj + 0x1325000:08x} r-xp 00000000 fc:0f 1 /usr/lib/libObj.so\n"
            f"{self.mwf:08x}-{self.mwf + 0x40000:08x} r-xp 00000000 fc:0f 2 /usr/lib/libMWF.so\n"
            f"{self.mpr:08x}-{self.mpr + 0x10000:08x} r-xp 00000000 fc:0f 3 /usr/lib/libmpr.so\n"
            f"{self.mprctrl:08x}-{self.mprctrl + 0x10000:08x} r-xp 00000000 fc:0f 4 /usr/lib/libmprctrl.so\n"
            f"{self.heap:08x}-{self.heap + 0x10000:08x} rw-p 00000000 00:00 0 [heap]\n"
        ).encode("ascii")
        stat_txt = b"149 (im.elf) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 3 0 12345 0 0\n"

        stdout = bytearray()
        fds: dict[int, list] = {}
        next_fd = 3
        mm_next = 0x40000000
        now_ms = [1000]
        ticks = [0]
        exit_code = [None]
        next_child_pid = [900]

        def read_cstr(addr: int) -> str:
            return bytes(m.mem_read(addr, 128)).split(b"\x00", 1)[0].decode("ascii")

        def syscall(cpu, intno, _):
            nonlocal next_fd, mm_next
            nr = cpu.reg_read(A.UC_ARM_REG_R7)
            r0 = cpu.reg_read(A.UC_ARM_REG_R0)
            r1 = cpu.reg_read(A.UC_ARM_REG_R1)
            r2 = cpu.reg_read(A.UC_ARM_REG_R2)
            r3 = cpu.reg_read(A.UC_ARM_REG_R3)
            r4 = cpu.reg_read(A.UC_ARM_REG_R4)
            assert nr not in (26, 54), f"FORBIDDEN syscall {nr} in stage7_daemon!"
            rc = 0
            if nr == 1:  # exit
                exit_code[0] = r0
                cpu.emu_stop()
                return
            elif nr == 20:  # getpid
                rc = 500
            elif nr == 263:  # clock_gettime
                sec = now_ms[0] // 1000
                nsec = (now_ms[0] % 1000) * 1000000
                cpu.mem_write(r1, struct.pack("<II", sec, nsec))
                rc = 0
            elif nr in (174, 175):  # rt_sigaction / rt_sigprocmask
                rc = 0
            elif nr == 177:  # rt_sigtimedwait
                sec, nsec = struct.unpack("<II", cpu.mem_read(r2, 8))
                now_ms[0] += max(1, sec * 1000 + nsec // 1000000)
                ticks[0] += 1
                if self.on_tick:
                    self.on_tick(ticks[0], self)
                rc = -11  # -EAGAIN
            elif nr == 37:  # kill(im_pid, 0)
                rc = 0 if r0 == 149 else -3
            elif nr == 5:  # open
                path = read_cstr(r0)
                flags = r1
                if path == "/proc":
                    fds[next_fd] = ["dir", [("149", 4)], False]; rc = next_fd; next_fd += 1
                elif path == "/proc/149/task":
                    fds[next_fd] = ["dir", [("149", 4), ("205", 4)], False]; rc = next_fd; next_fd += 1
                elif path == "/proc/149/task/205/comm":
                    fds[next_fd] = ["file", b"mwf_monitor_inp\n", 0]; rc = next_fd; next_fd += 1
                elif path == "/proc/149/stat":
                    fds[next_fd] = ["file", stat_txt, 0]; rc = next_fd; next_fd += 1
                elif path == "/proc/149/maps":
                    fds[next_fd] = ["file", maps_txt, 0]; rc = next_fd; next_fd += 1
                elif path == "/proc/149/mem":
                    fds[next_fd] = ["mem", None, 0]; rc = next_fd; next_fd += 1
                elif path == "/dev/urandom":
                    fds[next_fd] = ["file", struct.pack("<I", 0x12345678), 0]; rc = next_fd; next_fd += 1
                elif (flags & 0x40) and (flags & 0x80):  # O_CREAT | O_EXCL
                    if path in self.files:
                        rc = -17
                    else:
                        self.files[path] = b""
                        fds[next_fd] = ["wfile", path, 0]; rc = next_fd; next_fd += 1
                elif path in self.files:
                    fds[next_fd] = ["file", self.files[path], 0]; rc = next_fd; next_fd += 1
                else:
                    rc = -2
            elif nr == 3:  # read
                f = fds[r0]
                if f[0] == "pipe_r":
                    rc = -11 if self.ring_pid is not None else 0
                else:
                    chunk = f[1][f[2]:f[2] + r2]
                    cpu.mem_write(r1, chunk)
                    f[2] += len(chunk)
                    rc = len(chunk)
            elif nr == 4:  # write
                data = bytes(cpu.mem_read(r1, r2))
                if r0 == 1:
                    stdout.extend(data)
                else:
                    f = fds[r0]
                    assert f[0] == "wfile"
                    self.files[f[1]] = self.files[f[1]] + data
                rc = len(data)
            elif nr == 6:  # close
                fds.pop(r0, None)
            elif nr == 10:  # unlink
                path = read_cstr(r0)
                rc = 0 if self.files.pop(path, None) is not None else -2
            elif nr == 38:  # rename
                old = read_cstr(r0)
                new = read_cstr(r1)
                self.files[new] = self.files.pop(old)
                rc = 0
            elif nr == 42:  # pipe
                rfd = next_fd; next_fd += 1
                wfd = next_fd; next_fd += 1
                fds[rfd] = ["pipe_r", b"", 0]
                fds[wfd] = ["pipe_w", b"", 0]
                cpu.mem_write(r0, struct.pack("<II", rfd, wfd))
                rc = 0
            elif nr == 55:  # fcntl
                rc = 0
            elif nr == 2:  # fork (spawning ring.elf)
                cfg_raw = self.files[f"{self.run_dir}/run.cfg"]
                magic, ver, total, csum, nonce_b = struct.unpack_from("<4I12s", cfg_raw, 0)
                assert magic == build_stage7.S7_RING_CFG_MAGIC if hasattr(build_stage7, "S7_RING_CFG_MAGIC") else magic == 0x31433753
                assert ver == 1 and total == len(cfg_raw)
                assert build_stage7.fnv1a_32(cfg_raw[16:]) == csum
                assert nonce_b == self.nonce.encode("ascii")
                # precap struct sits at the end (last 40 bytes)
                pmagic, prev, before, after, bcap, sms, wms, dms, burst_cap, pmax = struct.unpack_from(
                    "<10I", cfg_raw, len(cfg_raw) - 40
                )
                assert pmagic == 0x32525043 and prev == 8
                self.spawned_cfgs.append(dict(before=before, after=after, burst_cap=burst_cap, post_max=pmax, raw=cfg_raw))
                pid = next_child_pid[0]
                next_child_pid[0] += 1
                self.ring_pid = pid
                self.ring_polls_left = self.ring_exit_after_polls
                rc = pid
            elif nr == 114:  # wait4
                if self.ring_pid is not None and r0 == self.ring_pid:
                    if f"{self.run_dir}/disarm" in self.files:
                        self.disarm_seen_during_ring = True
                        self.ring_polls_left = 0
                    if self.ring_polls_left > 0:
                        self.ring_polls_left -= 1
                        rc = 0
                    else:
                        if r1:
                            cpu.mem_write(r1, struct.pack("<I", 0))  # clean exit 0
                        rc = self.ring_pid
                        self.ring_pid = None
                else:
                    rc = -10
            elif nr == 85:  # readlink
                path = read_cstr(r0)
                if path == "/proc/149/exe":
                    val = b"/usr/bin/im.elf"
                    cpu.mem_write(r1, val[:r2])
                    rc = min(len(val), r2)
                else:
                    rc = -2
            elif nr == 217:  # getdents64
                f = fds[r0]
                if f[2]:
                    rc = 0
                else:
                    raw = pack_dirents(f[1])
                    cpu.mem_write(r1, raw)
                    f[2] = True
                    rc = len(raw)
            elif nr == 180:  # pread64
                assert r3 == 0
                data = self.read_im_mem(r4, r2)
                if data is None:
                    rc = -5
                else:
                    cpu.mem_write(r1, data)
                    rc = len(data)
            elif nr == 192:  # mmap2
                sz = (r1 + 0xFFF) & ~0xFFF
                cpu.mem_map(mm_next, sz)
                rc = mm_next
                mm_next += sz + 0x1000
            elif nr == 197:  # fstat64
                st = bytearray(104)
                struct.pack_into("<I", st, 16, 0o100600)
                cpu.mem_write(r1, bytes(st))
                rc = 0
            elif nr == 91:  # munmap
                rc = 0
            else:
                raise AssertionError(f"unexpected daemon syscall {nr}")
            cpu.reg_write(A.UC_ARM_REG_R0, rc & 0xFFFFFFFF)

        m.hook_add(uc.UC_HOOK_INTR, syscall)
        m.emu_start(entry, 0, count=80_000_000)
        assert exit_code[0] is not None, "stage7_daemon did not exit"
        return exit_code[0], stdout.decode("ascii")


class Stage7IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = build_stage7.verify_seal(OUT)
        cls.guard_elf = (OUT / "mlv2_guard.elf").read_bytes()
        cls.req_bytes = (OUT / "mlv2.req").read_bytes()
        cls.core_bin = (OUT / "core.bin").read_bytes()
        cls.precap_mod = (OUT / "PreCapture.mod").read_bytes()
        cls.daemon_elf = (OUT / "stage7_daemon.elf").read_bytes()

    def test_1_seals_and_footprint(self):
        layout.verify(ROOT)
        build_precap_mod.verify_seal(OUT)
        # Verify Stage 6 v1 and v2 seals remain 100% intact.
        sys.path.insert(0, str(ROOT / "prototype-stage6-autonomy"))
        import build_stage6
        import build_stage6_v2
        build_stage6.verify_seal()
        build_stage6_v2.verify_seal()
        # Total Stage 7.1 payload must fit easily inside M7 /tmp_network (1,024 KiB tmpfs).
        self.assertLess(self.manifest["total_artifact_bytes"], 300 * 1024)
        census = self.manifest["artifacts"]["daemon"]["syscall_census"]
        self.assertNotIn(26, census["static_syscalls"])
        self.assertNotIn(54, census["static_syscalls"])

    def test_2_guard_check_install_uninstall_and_rollback(self):
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

        vbase = layout.REF_VIEW_BASE + 0x20000
        shim_va = vbase + layout.REF_SHIM_OFF
        gh = GuardHarness(
            self.guard_elf,
            {"/tmp_network/mlv2/mlv2.req": self.req_bytes,
             "/tmp_network/mlv2/core.bin": self.core_bin},
            view_base=vbase,
        )
        # 2a: fnv subcommand
        rc, out, st = gh.run(["mlv2_guard.elf", "fnv", "/tmp_network/mlv2/core.bin"])
        self.assertEqual(rc, 0, out)
        self.assertIn(f"FNV size={len(self.core_bin)} fnv={build_stage7.fnv1a_32(self.core_bin):08x}", out)

        # 2b: read-only check (zero ptrace!)
        rc, out, st = gh.run(["mlv2_guard.elf", "check", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(st["ptrace_calls"], [])
        self.assertIn("STATE hooks=stock rects=stock shim=zero", out)
        self.assertIn("MLV2_RESULT=0 changed=0", out)

        # 2c: BUSY PC refusal
        gh.thread_pcs[150] = vbase + layout.HOOKS["refresh"]["offset"] + 4
        rc, out, st = gh.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 1, out)
        self.assertIn("BUSY tid=150", out)
        self.assertIn("MLV2_RESULT=-17 changed=0", out)
        self.assertEqual(st["attached"], set())
        self.assertEqual(st["poke_count"], 0)
        gh.thread_pcs[150] = 0x00020000

        # 2d: mid-write failure rollback
        # shim writes take len(shim)/4 pokes, rect1=2, rect2=2, hook_sr=1 -> fail on hook_rf (1 word!)
        shim_words = self.manifest["artifacts"]["shim"]["bytes"] // 4
        gh.fail_poke_call = shim_words + 2 + 2 + 1 + 1
        orig_vc = gh.read_target(vbase + 0x972000, 0x1000)
        orig_vh = gh.read_target(vbase + 0x695000, 0x3000)
        orig_vr = gh.read_target(vbase + 0x88C000, 0x1000)
        rc, out, st = gh.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 1, out)
        self.assertIn("ROLLBACK step=4 failed=0", out)
        self.assertIn("MLV2_RESULT=-15 changed=0", out)
        self.assertEqual(st["attached"], set())
        self.assertEqual(gh.read_target(vbase + 0x972000, 0x1000), orig_vc)
        self.assertEqual(gh.read_target(vbase + 0x695000, 0x3000), orig_vh)
        self.assertEqual(gh.read_target(vbase + 0x88C000, 0x1000), orig_vr)
        gh.fail_poke_call = None

        # 2e: clean install + idempotence + Capstone verification of single-word 4-byte B.W hooks
        rc, out, st = gh.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 0, out)
        self.assertIn("INSTALLED", out)
        self.assertIn("MLV2_RESULT=0 changed=1", out)
        self.assertEqual(st["attached"], set())
        self.assertEqual(gh.read_target(vbase + 0x88C814, 8), layout.RECT_PATCH)
        self.assertEqual(gh.read_target(vbase + 0x88C894, 8), layout.RECT_PATCH)
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        entries = self.manifest["artifacts"]["shim"]["entries"]
        for hk_name, sym_name in (("set_root", "ml_hook_set_root"),
                                  ("refresh", "ml_hook_refresh"),
                                  ("open_item", "ml_hook_open_item")):
            hk_va = vbase + layout.HOOKS[hk_name]["offset"]
            want_target = (int(entries[sym_name], 16) - layout.REF_VIEW_BASE + vbase) & ~1
            ins = list(md.disasm(gh.read_target(hk_va, 4), hk_va))
            self.assertEqual(len(ins), 1)
            self.assertEqual(ins[0].mnemonic, "b.w")
            self.assertEqual(int(ins[0].op_str.lstrip("#"), 0), want_target)

        rc, out, st = gh.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 0, out)
        self.assertIn("ALREADY_INSTALLED", out)
        self.assertIn("MLV2_RESULT=0 changed=0", out)

        # 2f: uninstall refused without BOTH sd-disabled and sd-stopped (including lone stale sd-stopped!)
        rc, out, st = gh.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 1, out)
        self.assertIn("MLV2_RESULT=-18", out)
        gh.files["/tmp_network/mlv2/sd-stopped"] = b""
        rc, out, st = gh.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 1, out)
        self.assertIn("MLV2_RESULT=-18", out)

        # 2g: uninstall refuses exact-entry PC on hook
        gh.files["/tmp_network/mlv2/sd-disabled"] = b""
        gh.thread_pcs[150] = vbase + layout.HOOKS["refresh"]["offset"]
        rc, out, st = gh.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 1, out)
        self.assertIn("MLV2_RESULT=-17", out)
        gh.thread_pcs[150] = 0x00020000

        # 2h: uninstall after sd-disabled + sd-stopped restores 100% stock bytes in safe order (hooks -> rects -> cave)
        rc, out, st = gh.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 0, out)
        self.assertIn("UNINSTALLED restored=stock", out)
        self.assertIn("MLV2_RESULT=0 changed=1", out)
        self.assertEqual(st["attached"], set())
        self.assertEqual(st["poke_addrs"][0], vbase + layout.HOOKS["open_item"]["offset"])
        self.assertGreaterEqual(st["poke_addrs"][-1], shim_va)
        self.assertEqual(gh.read_target(vbase + 0x972000, 0x1000), orig_vc)
        self.assertEqual(gh.read_target(vbase + 0x695000, 0x3000), orig_vh)
        self.assertEqual(gh.read_target(vbase + 0x88C000, 0x1000), orig_vr)

    def test_3_end_to_end_menu_and_precapture_mod(self):
        vbase = layout.REF_VIEW_BASE + 0x20000
        gh = GuardHarness(
            self.guard_elf,
            {"/tmp_network/mlv2/mlv2.req": self.req_bytes},
            view_base=vbase,
        )
        rc, out, _ = gh.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 0, out)

        cam = EndToEndMenuHarness(gh, self.core_bin, self.precap_mod)

        # Open menu via REAL hooked set_root + refresh
        self.assertEqual(cam.call_real_set_root(cam.root), 1)
        self.assertEqual(cam.u32(cam.MENU + 0x186AC), cam.root)
        self.assertEqual(cam.u32(cam.root + 8), 7)
        cam.call_real_refresh()
        self.assertIn((0x97C, 3), cam.set_mode_calls)
        self.assertEqual(cam.texts, [
            (0x5470, "Mods"),
            (0x9350 + 0x7C8, "Pre-Capture"),
            (0x9350 + 0xB60, "OFF >"),
        ])

        # Stock open_item pass-through (leaf outside c->items)
        self.assertEqual(cam.call_real_open_item(cam.NODES + 0x3000), 1)
        self.assertEqual(cam.stock_open_item_hits, 1)

        # Enter Pre-Capture SMNU submenu via REAL hooked open_item
        cam.call_real_open_item(cam.items()[0])
        self.assertEqual(cam.menu_refresh_calls, 1)
        self.assertEqual(cam.texts, [
            (0x5470, "Pre-Capture"),
            (0x9350 + 0x7C8, "< Back"),
            (0x9350 + 0xB60, ""),
            (0x9350 + 0x1118 + 0x7C8, "Mod Status"),
            (0x9350 + 0x1118 + 0xB60, "OFF"),
            (0x9350 + 2 * 0x1118 + 0x7C8, "Pre-Frames"),
            (0x9350 + 2 * 0x1118 + 0xB60, "5"),
        ])

        # Edit Pre-Frames while OFF (5 -> 8): UI updates, precap.cfg still absent (not armed!)
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[2])
        self.assertEqual(cam.texts, [(0x9350 + 2 * 0x1118 + 0xB60, "8")])
        self.assertNotIn("/tmp_network/mlv2/precap.cfg", cam.files)

        # Toggle Mod Status ON -> PreCapture.mod writes atomic "S7PC1 1 8\n"
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[1])
        self.assertEqual(cam.texts, [(0x9350 + 0x1118 + 0xB60, "ON")])
        self.assertEqual(cam.files["/tmp_network/mlv2/precap.cfg"], b"S7PC1 1 8\n")

        # Live edit Pre-Frames while ON: cycles 10 -> 1 -> 2 -> 3 -> 5
        for expected in ("10", "1", "2", "3", "5"):
            cam.texts.clear()
            cam.call_real_open_item(cam.items()[2])
            self.assertEqual(cam.texts, [(0x9350 + 2 * 0x1118 + 0xB60, expected)])
            self.assertEqual(cam.files["/tmp_network/mlv2/precap.cfg"], f"S7PC1 1 {expected}\n".encode())

        # Toggle Mod Status OFF -> PreCapture.mod writes atomic "S7PC1 0 5\n"
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[1])
        self.assertEqual(cam.texts, [(0x9350 + 0x1118 + 0xB60, "OFF")])
        self.assertEqual(cam.files["/tmp_network/mlv2/precap.cfg"], b"S7PC1 0 5\n")

        # Press < Back -> returns to top-level Mods tab
        cam.call_real_open_item(cam.items()[0])
        self.assertEqual(cam.texts, [
            (0x5470, "Mods"),
            (0x9350 + 0x7C8, "Pre-Capture"),
            (0x9350 + 0xB60, "OFF >"),
        ])

        # Re-enable Pre-Capture ON, then test sd-disabled clean teardown
        cam.call_real_open_item(cam.items()[0])  # enter submenu
        cam.call_real_open_item(cam.items()[1])  # ON -> S7PC1 1 5\n
        self.assertEqual(cam.files["/tmp_network/mlv2/precap.cfg"], b"S7PC1 1 5\n")

        cam.files["/tmp_network/mlv2/sd-disabled"] = b""
        cam.set_mode_calls.clear()
        cam.call_real_set_root(cam.root)
        cam.call_real_refresh()
        self.assertEqual(cam.files["/tmp_network/mlv2/precap.cfg"], b"S7PC1 0 5\n")
        self.assertEqual(cam.u32(cam.root + 4), cam.orig_kids)
        self.assertEqual(cam.u32(cam.root + 8), 6)
        self.assertIn("/tmp_network/mlv2/sd-stopped", cam.files)
        self.assertEqual(cam.set_mode_calls, [])

    def test_4_stage7_daemon_gating_pre_frames_and_indefinite_mode(self):
        # 4a: Timed run testing OFF -> ON(8) -> ON(10) -> active disarm on OFF
        dh = DaemonHarness(self.daemon_elf, self.manifest["artifacts"]["daemon"], duration_ms=4000, poll_ms=20)
        dh.ring_exit_after_polls = 2

        def scenario(tick: int, h: DaemonHarness):
            if tick == 2:
                # precap.cfg absent -> half-press must NOT spawn ring
                h.half = 1
            elif tick == 5:
                # explicit OFF -> half-press still must NOT spawn ring
                h.files["/tmp_network/mlv2/precap.cfg"] = b"S7PC1 0 5\n"
                h.half = 0
            elif tick == 7:
                h.half = 1
            elif tick == 10:
                # Enable ON with 8 pre-frames, return to clean idle
                h.half = 0
                h.files["/tmp_network/mlv2/precap.cfg"] = b"S7PC1 1 8\n"
            elif tick == 12:
                # Half-press -> should spawn ring #1 with before=8!
                h.half = 1
            elif tick == 20:
                # Release to idle, wait cooldown (500ms = 25 ticks at 20ms), change to 10 frames
                h.half = 0
                h.files["/tmp_network/mlv2/precap.cfg"] = b"S7PC1 1 10\n"
                h.ring_exit_after_polls = 40  # hold ring #2 alive so we test active disarm!
            elif tick == 50:
                # Half-press -> should spawn ring #2 with before=10!
                h.half = 1
            elif tick == 55:
                # User flips Pre-Capture OFF while ring #2 is active -> daemon must write disarm!
                h.files["/tmp_network/mlv2/precap.cfg"] = b"S7PC1 0 10\n"
            elif tick == 75:
                h.files[f"{h.run_dir}/stop"] = b"stop\n"

        dh.on_tick = scenario
        rc, out = dh.run()
        self.assertEqual(rc, 0, out)
        self.assertEqual([c["before"] for c in dh.spawned_cfgs], [8, 10], out)
        self.assertTrue(all(c["after"] == 0 for c in dh.spawned_cfgs))
        self.assertTrue(dh.disarm_seen_during_ring, out)
        self.assertIn("DISARM_GATE", out)
        self.assertIn("STOP ", out)
        self.assertIn("reason=stop_file", out)
        self.assertIn("r_runs=2 r_ok=2", out)

        # 4b: Verify the REAL sealed stage7_ring.elf ARM32 binary loads BOTH run.cfg blobs
        # produced by stage7_daemon.elf, validates checksum/nonce/bounds, populates m7_precap_config,
        # and locks PT_LOAD[1] read-only via mprotect(PROT_READ=1) (full RELRO)!
        ring_elf_orig = (OUT / "stage7_ring.elf").read_bytes()
        ring_meta = self.manifest["artifacts"]["ring"]
        for expected_before, cfg_entry in zip((8, 10), dh.spawned_cfgs):
            rbuf = bytearray(ring_elf_orig)
            rbuf[ring_meta["nonce_offset"]:ring_meta["nonce_offset"] + 12] = dh.nonce.encode("ascii")
            m = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
            entry = load_elf_into_uc(m, bytes(rbuf))
            m.mem_map(0x5F000000, 0x20000)
            m.reg_write(A.UC_ARM_REG_SP, 0x5F01F000)
            mprotect_calls = []
            cfg_pos = [0]
            cfg_raw = cfg_entry["raw"]

            def ring_sc(cpu, intno, _):
                nr = cpu.reg_read(A.UC_ARM_REG_R7)
                r0 = cpu.reg_read(A.UC_ARM_REG_R0)
                r1 = cpu.reg_read(A.UC_ARM_REG_R1)
                r2 = cpu.reg_read(A.UC_ARM_REG_R2)
                rc = 0
                if nr == 5:  # open
                    path = bytes(cpu.mem_read(r0, 96)).split(b"\x00", 1)[0].decode("ascii")
                    if path == f"{dh.run_dir}/run.cfg":
                        rc = 3
                    else:
                        # Stop right after stage7_load_runtime_cfg + bounds validation pass!
                        cpu.emu_stop()
                        return
                elif nr == 3:  # read run.cfg
                    assert r0 == 3
                    chunk = cfg_raw[cfg_pos[0]:cfg_pos[0] + r2]
                    cpu.mem_write(r1, chunk)
                    cfg_pos[0] += len(chunk)
                    rc = len(chunk)
                elif nr == 6:  # close
                    rc = 0
                elif nr == 125:  # mprotect(PROT_READ) RELRO lock
                    mprotect_calls.append((r0, r1, r2))
                    cpu.mem_protect(r0, r1, uc.UC_PROT_READ)
                    rc = 0
                elif nr in (174, 175):  # rt_sigaction / rt_sigprocmask (reached ONLY after ALL config & precap bounds pass!)
                    cpu.emu_stop()
                    return
                elif nr == 1:  # exit -> should NOT fail config validation!
                    raise AssertionError(f"stage7_ring.elf exited early with code {r0}")
                else:
                    raise AssertionError(f"unexpected ring syscall {nr}")
                cpu.reg_write(A.UC_ARM_REG_R0, rc & 0xFFFFFFFF)

            m.hook_add(uc.UC_HOOK_INTR, ring_sc)
            m.emu_start(entry, 0, count=5_000_000)
            # Confirm RELRO mprotect(rw_vaddr, rw_memsz, PROT_READ=1) fired AND live precap.before matches!
            self.assertEqual(mprotect_calls, [(ring_meta["rw_vaddr"], ring_meta["rw_memsz"], 1)])
            rw_blob = bytes(m.mem_read(ring_meta["rw_vaddr"], ring_meta["rw_filesz"]))
            # Locate precap struct by magic 0x32525043 inside PT_LOAD[1]
            off = rw_blob.index(struct.pack("<II", 0x32525043, 8))
            before, after = struct.unpack_from("<II", rw_blob, off + 8)
            self.assertEqual((before, after), (expected_before, 0))

        # 4c: Indefinite mode (duration_ms == 0, for Stage 7.3 persistent boot)
        dh0 = DaemonHarness(self.daemon_elf, self.manifest["artifacts"]["daemon"], duration_ms=0, poll_ms=20)

        def stop_at_15(tick: int, h: DaemonHarness):
            if tick == 15:
                h.files[f"{h.run_dir}/stop"] = b"stop\n"

        dh0.on_tick = stop_at_15
        rc0, out0 = dh0.run()
        self.assertEqual(rc0, 0, out0)
        self.assertIn("reason=stop_file", out0)
        self.assertIn("ticks=15", out0)

    def test_5_adversarial_races_alignment_and_seal(self):
        import copy, json, shutil, tempfile
        from unittest.mock import patch
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

        vbase = layout.REF_VIEW_BASE + 0x20000
        shim_va = vbase + layout.REF_SHIM_OFF

        # 5a: verify_seal rejects missing/extra keys, wrong filename/stage/total/pins,
        #     mutated runner-facing ELF offsets (config_offset, boot_offset, entries, reference_bases),
        #     AND duplicate JSON object keys!
        with tempfile.TemporaryDirectory(prefix="s7-seal-") as tmp:
            dst = Path(tmp)
            for f in OUT.iterdir():
                if f.is_file():
                    shutil.copyfile(f, dst / f.name)
            mutations = [
                ("missing_key", lambda m: m["artifacts"].pop("ring")),
                ("extra_key", lambda m: m["artifacts"].__setitem__("extra", m["artifacts"]["ring"])),
                ("bad_filename", lambda m: m["artifacts"]["ring"].__setitem__("file", "q.elf")),
                ("bad_stage", lambda m: m.__setitem__("stage", "7.2")),
                ("bad_total", lambda m: m.__setitem__("total_artifact_bytes", 0)),
                ("bad_pin", lambda m: m["sony_library_pins"].__setitem__("libObj", "bad")),
                ("bad_daemon_cfg_off", lambda m: m["artifacts"]["daemon"].__setitem__("config_offset", 0)),
                ("bad_ring_boot_off", lambda m: m["artifacts"]["ring"].__setitem__("boot_offset", 0)),
                ("bad_ring_nonce_off", lambda m: m["artifacts"]["ring"].__setitem__("nonce_offset", 0)),
                ("bad_ring_rw_vaddr", lambda m: m["artifacts"]["ring"].__setitem__("rw_vaddr", 0x20000)),
                ("bad_shim_entry", lambda m: m["artifacts"]["shim"]["entries"].__setitem__("ml_hook_refresh", "0x15d63801")),
                ("bad_ref_base", lambda m: m["reference_bases"].__setitem__("viewUnified2", "0x10000000")),
                ("extra_top_key", lambda m: m.__setitem__("rogue", 1)),
            ]
            for name, fn in mutations:
                m = copy.deepcopy(self.manifest)
                fn(m)
                (dst / "build.json").write_text(json.dumps(m))
                with self.assertRaises(ValueError, msg=f"verify_seal accepted {name}"):
                    build_stage7.verify_seal(dst)
            # Duplicate JSON key AND JSON bool/float type coercion for int fields MUST be rejected!
            raw_json = (OUT / "build.json").read_text()
            dup_json = raw_json.replace('"stage": "7.1"', '"stage": "7.2", "stage": "7.1"', 1)
            (dst / "build.json").write_text(dup_json)
            with self.assertRaises(ValueError, msg="verify_seal accepted duplicate JSON key"):
                build_stage7.verify_seal(dst)
            for tname, tfn in (
                ("bool_for_int", lambda m: m["artifacts"]["core"].__setitem__("init_off", True)),
                ("float_for_int", lambda m: m["artifacts"]["daemon"].__setitem__(
                    "config_offset", float(m["artifacts"]["daemon"]["config_offset"]))),
            ):
                m = copy.deepcopy(self.manifest)
                tfn(m)
                (dst / "build.json").write_text(json.dumps(m))
                with self.assertRaises(ValueError, msg=f"verify_seal accepted {tname}"):
                    build_stage7.verify_seal(dst)

        # 5b: Dual-failure install AND uninstall rollbacks NEVER leave an invalid redirect
        #     and NEVER report changed=0 when target memory remains modified!
        class FailingGuard(GuardHarness):
            def __init__(self, *args, fail_writes=(), **kwargs):
                super().__init__(*args, **kwargs)
                self.fail_writes = set(fail_writes)
                self.wcalls = 0

            def write_target_word(self, addr, word):
                self.wcalls += 1
                if self.wcalls in self.fail_writes:
                    return False
                return super().write_target_word(addr, word)

        shim_bytes = self.manifest["artifacts"]["shim"]["bytes"]
        shim_words = shim_bytes // 4
        # Install: fail on hook_rf (1 word) AND on rolling back hook_sr (1 word)
        fail_inst = shim_words + 2 + 2 + 1 + 1
        df = FailingGuard(
            self.guard_elf, {"/tmp_network/mlv2/mlv2.req": self.req_bytes},
            view_base=vbase, fail_writes=(fail_inst, fail_inst + 1),
        )
        rc, out, st = df.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc, 1, out)
        self.assertIn("MLV2_RESULT=-16 changed=1", out)
        self.assertEqual(st["attached"], set())
        # Shim cave MUST remain 100% intact (not erased!) and EVERY hook word is valid stock OR valid B.W!
        self.assertNotEqual(df.read_target(shim_va, shim_bytes), b"\x00" * shim_bytes)
        self.assertEqual(df.read_target(vbase + layout.HOOKS["refresh"]["offset"], 4),
                         bytes.fromhex(layout.HOOKS["refresh"]["original"])[:4])
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        sr_va = vbase + layout.HOOKS["set_root"]["offset"]
        sr_ins = list(md.disasm(df.read_target(sr_va, 4), sr_va))
        self.assertEqual(len(sr_ins), 1)
        self.assertEqual(sr_ins[0].mnemonic, "b.w")

        # Uninstall: fail mid-way while zeroing shim cave -> hooks MUST STAY 100% STOCK (never re-armed!)
        du = FailingGuard(
            self.guard_elf, {"/tmp_network/mlv2/mlv2.req": self.req_bytes},
            view_base=vbase,
        )
        self.assertEqual(du.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])[0], 0)
        du.files["/tmp_network/mlv2/sd-disabled"] = b""
        du.files["/tmp_network/mlv2/sd-stopped"] = b""
        du.wcalls = 0
        # 3 hook words + 4 rect words = 7 writes; fail at 10th write (inside shim cave zeroing)
        du.fail_writes = {10, 11}
        rc_u, out_u, st_u = du.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc_u, 1, out_u)
        self.assertIn("MLV2_RESULT=-16 changed=1", out_u)
        self.assertEqual(st_u["attached"], set())
        for hk_name in ("set_root", "refresh", "open_item"):
            hk = layout.HOOKS[hk_name]
            self.assertEqual(du.read_target(vbase + hk["offset"], 4), bytes.fromhex(hk["original"])[:4])

        # 5c: AAPCS 8-byte SP alignment on BOTH ml_before_set_root AND ml_refresh_enter;
        #     active == 1 inside Sony's refresh body; absent core preserves backdrop;
        #     truncated core.bin calls munmap; A -> B -> sd-disabled -> C restores ALL roots (6,6,6)!
        gh = GuardHarness(self.guard_elf, {"/tmp_network/mlv2/mlv2.req": self.req_bytes}, vbase)
        self.assertEqual(gh.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])[0], 0)
        cam = EndToEndMenuHarness(gh, self.core_bin, self.precap_mod)
        # Decode the `bl` targets directly from the installed shim machine code to verify SP % 8 == 0!
        sr_entry = (int(self.manifest["artifacts"]["shim"]["entries"]["ml_hook_set_root"], 16)
                    - layout.REF_VIEW_BASE + vbase) & ~1
        rf_entry = (int(self.manifest["artifacts"]["shim"]["entries"]["ml_hook_refresh"], 16)
                    - layout.REF_VIEW_BASE + vbase) & ~1
        sr_bl = [i for i in md.disasm(bytes(cam.m.mem_read(sr_entry, 24)), sr_entry) if i.mnemonic == "bl"][0]
        rf_bl = [i for i in md.disasm(bytes(cam.m.mem_read(rf_entry, 24)), rf_entry) if i.mnemonic == "bl"][0]
        before_sr_va = int(sr_bl.op_str.lstrip("#"), 0)
        refresh_enter_va = int(rf_bl.op_str.lstrip("#"), 0)
        sp_mods_sr, sp_mods_rf, active_in_sony_refresh = [], [], []

        def check_abi(cpu, pc, size, _):
            if pc == before_sr_va:
                sp_mods_sr.append(cpu.reg_read(A.UC_ARM_REG_SP) % 8)
            elif pc == refresh_enter_va:
                sp_mods_rf.append(cpu.reg_read(A.UC_ARM_REG_SP) % 8)
            elif pc == cam.refresh_va + 0x0E:
                slot_p = cam.u32(shim_va)
                if slot_p:
                    active_in_sony_refresh.append(cam.u32(slot_p + 48))

        cam.m.hook_add(uc.UC_HOOK_CODE, check_abi)
        # Absent core.bin -> refresh must NOT call Widget::setMode(menu + 0x97c, 3), AND active==1 in Sony refresh!
        del cam.files["/tmp_network/mlv2/core.bin"]
        cam.call_real_set_root(cam.root)
        cam.call_real_refresh()
        self.assertEqual(sp_mods_sr, [0])
        self.assertEqual(sp_mods_rf, [0])
        self.assertEqual(active_in_sony_refresh, [1])
        self.assertEqual(cam.set_mode_calls, [])

        # Truncated core.bin -> must munmap on failure (zero leak)
        cam.files["/tmp_network/mlv2/core.bin"] = self.core_bin[:-16]
        cam.call_real_set_root(cam.root)
        self.assertEqual(len(cam.munmap_calls), 1)
        cam.call_real_set_root(cam.root)
        self.assertEqual(len(cam.munmap_calls), 2)

        # Multi-root history: A -> B -> sd-disabled -> C MUST restore A, B, and C to (6, 6, 6) with own arrays!
        cam.files["/tmp_network/mlv2/core.bin"] = self.core_bin
        root_a = cam.root
        root_b, root_c = cam.NODES + 0x4000, cam.NODES + 0x4200
        for r in (root_b, root_c):
            kids = r + 0x100
            cam.m.mem_write(kids, bytes(cam.m.mem_read(cam.orig_kids, 24)))
            cam.m.mem_write(r, struct.pack("<10I", cam.NODES + 0x1000, kids, 6, 0, 0, 1, 1, 0, 0, 0))
        self.assertEqual(cam.call_real_set_root(root_a), 1)
        self.assertEqual(cam.u32(root_a + 8), 7)
        # Switching to B MUST immediately restore A before reusing shared root_children[]!
        self.assertEqual(cam.call_real_set_root(root_b), 1)
        self.assertEqual((cam.u32(root_a + 8), cam.u32(root_b + 8)), (6, 7))
        self.assertEqual(cam.u32(root_a + 4), cam.orig_kids)
        cam.files["/tmp_network/mlv2/sd-disabled"] = b""
        self.assertEqual(cam.call_real_set_root(root_c), 1)
        self.assertEqual((cam.u32(root_a + 8), cam.u32(root_b + 8), cam.u32(root_c + 8)), (6, 6, 6))
        self.assertEqual(cam.u32(root_a + 4), cam.orig_kids)
        self.assertEqual(cam.u32(root_b + 4), root_b + 0x100)
        self.assertEqual(cam.u32(root_c + 4), root_c + 0x100)
        self.assertIn("/tmp_network/mlv2/sd-stopped", cam.files)

        # Mirror ShimState/Ctx/NODES into gh and verify guard checks tracked[0] (root_a) even when orig_root (root_b) is stock!
        slot_p = cam.u32(shim_va)
        ctx_p = cam.u32(slot_p + 16)
        self.assertTrue(gh.write_target_word(shim_va, slot_p))
        gh.regions += [
            (slot_p, bytearray(cam.m.mem_read(slot_p, 0x1000))),
            (ctx_p, bytearray(cam.m.mem_read(ctx_p, 0x1000))),
            (cam.NODES, bytearray(cam.m.mem_read(cam.NODES, 0x5000))),
        ]
        gh.files["/tmp_network/mlv2/sd-disabled"] = b""
        gh.files["/tmp_network/mlv2/sd-stopped"] = b""
        # Tamper tracked[0] (root_a->children) back to synthetic root_children (ctx + 520) -> guard MUST refuse!
        self.assertTrue(gh.write_target_word(root_a + 4, ctx_p + 520))
        rc_tr, out_tr, st_tr = gh.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc_tr, 1, out_tr)
        self.assertIn("BUSY orig_root_extended", out_tr)
        self.assertEqual(st_tr["poke_count"], 0)
        self.assertTrue(gh.write_target_word(root_a + 4, cam.orig_kids))

        # Deep stock refresh stack return at SP + 340 (even if active == 0!) MUST be refused by stack scan,
        # AND an -EINTR fault injected at SP + 256 MUST fail closed (-17), NEVER bypass SP + 340!
        sp_deep = gh.thread_sps[150]
        gh.thread_pcs[150] = cam.libobj_base + 0x3F1B5A
        gh.thread_lrs[150] = vbase + 0x70048F
        self.assertTrue(gh.write_target_word(sp_deep + 340, (shim_va + 0x4E3) | 1))
        rc_dp, out_dp, st_dp = gh.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc_dp, 1, out_dp)
        self.assertIn("stack_ret=", out_dp)
        self.assertIn("MLV2_RESULT=-17", out_dp)
        self.assertEqual(st_dp["poke_count"], 0)

        old_hook_add_stk = uc.Uc.hook_add

        def inject_eintr_at_256(self_uc, htype, cb, *a, **kw):
            if htype == uc.UC_HOOK_INTR:
                def intercept(cpu, intno, user):
                    if cpu.reg_read(A.UC_ARM_REG_R7) == 180 and cpu.reg_read(A.UC_ARM_REG_R4) == sp_deep + 256:
                        cpu.reg_write(A.UC_ARM_REG_R0, (-4) & 0xFFFFFFFF)
                        return
                    return cb(cpu, intno, user)
                return old_hook_add_stk(self_uc, htype, intercept, *a, **kw)
            return old_hook_add_stk(self_uc, htype, cb, *a, **kw)

        with patch.object(uc.Uc, "hook_add", inject_eintr_at_256):
            rc_ei, out_ei, st_ei = gh.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc_ei, 1, out_ei)
        self.assertIn("sp_read_err=-4", out_ei)
        self.assertIn("MLV2_RESULT=-17", out_ei)
        self.assertEqual(st_ei["poke_count"], 0)
        self.assertTrue(gh.write_target_word(sp_deep + 340, 0))
        gh.thread_pcs[150] = 0x00020000
        gh.thread_lrs[150] = 0x00020100

        # Overlapping concurrent first-entry core load MUST serialize via core_load_lock (only 1 load, never 2!)
        class PauseMidLoad(EndToEndMenuHarness):
            def __init__(self, *args):
                super().__init__(*args)
                self.saved = None
                self.paused_once = False

            def _syscall(self, cpu, intno, extra):
                is_payload = (
                    cpu.reg_read(A.UC_ARM_REG_R7) == 3 and
                    cpu.reg_read(A.UC_ARM_REG_R2) == len(Stage7IntegrationTests.core_bin) - 20
                )
                super()._syscall(cpu, intno, extra)
                if is_payload and not self.paused_once:
                    self.paused_once = True
                    self.saved = cpu.context_save()
                    cpu.emu_stop()

        gh_ov = GuardHarness(self.guard_elf, {"/tmp_network/mlv2/mlv2.req": self.req_bytes}, vbase)
        self.assertEqual(gh_ov.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])[0], 0)
        pov = PauseMidLoad(gh_ov, self.core_bin, self.precap_mod)
        pov.call_real_set_root(pov.root)
        self.assertIsNotNone(pov.saved)
        ov_slot = pov.u32(shim_va)
        self.assertEqual((pov.u32(ov_slot + 8), pov.u32(ov_slot + 48), pov.u32(ov_slot + 52)), (0, 1, 1))
        # Second concurrent entrant MUST return cleanly without loading a second core!
        saved_stack = pov.STACK
        pov.STACK -= 0x8000
        self.assertEqual(pov.call_real_set_root(pov.root), 1)
        self.assertEqual((pov.u32(ov_slot + 8), pov.u32(ov_slot + 12), pov.u32(ov_slot + 48)), (0, 0, 1))
        self.assertEqual(pov.u32(pov.root + 8), 6)
        pov.STACK = saved_stack
        # Resume first loader to completion -> exactly 1 load, active == 0, root extended to 7!
        pov.m.context_restore(pov.saved)
        pov.m.emu_start(pov.m.reg_read(A.UC_ARM_REG_PC) | 1, pov.STOP, count=5_000_000)
        self.assertNotEqual(pov.u32(ov_slot + 8), 0)
        self.assertEqual((pov.u32(ov_slot + 12), pov.u32(ov_slot + 48)), (1, 0))
        self.assertEqual(pov.u32(pov.root + 8), 7)

        # Also test failed /proc/<pid>/maps VMA lookup + next-page -EIO MUST fail closed (-17, 0 pokes)!
        gh_m = GuardHarness(self.guard_elf, {"/tmp_network/mlv2/mlv2.req": self.req_bytes}, vbase)
        self.assertEqual(gh_m.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])[0], 0)
        gh_m.files["/tmp_network/mlv2/sd-disabled"] = b""
        gh_m.files["/tmp_network/mlv2/sd-stopped"] = b""
        sp_m = gh_m.thread_sps[150] + 0xF00
        gh_m.thread_sps[150] = sp_m
        self.assertTrue(gh_m.write_target_word(sp_m + 340, (shim_va + 0x5B9) | 1))
        maps_opens_m = [0]

        def inject_maps_and_page_eio(self_uc, htype, cb, *a, **kw):
            if htype == uc.UC_HOOK_INTR:
                def intercept(cpu, intno, user):
                    nr = cpu.reg_read(A.UC_ARM_REG_R7)
                    if nr == 5 and bytes(cpu.mem_read(cpu.reg_read(A.UC_ARM_REG_R0), 15)) == b"/proc/149/maps\0":
                        maps_opens_m[0] += 1
                        if maps_opens_m[0] == 4:
                            cpu.reg_write(A.UC_ARM_REG_R0, (-5) & 0xFFFFFFFF)
                            return
                    if nr == 180 and cpu.reg_read(A.UC_ARM_REG_R4) == sp_m + 256:
                        cpu.reg_write(A.UC_ARM_REG_R0, (-5) & 0xFFFFFFFF)
                        return
                    return cb(cpu, intno, user)
                return old_hook_add_stk(self_uc, htype, intercept, *a, **kw)
            return old_hook_add_stk(self_uc, htype, cb, *a, **kw)

        with patch.object(uc.Uc, "hook_add", inject_maps_and_page_eio):
            rc_me, out_me, st_me = gh_m.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc_me, 1, out_me)
        self.assertIn("sp_vma_unknown", out_me)
        self.assertIn("MLV2_RESULT=-17", out_me)
        self.assertEqual(st_me["poke_count"], 0)
        self.assertNotEqual(gh_m.read_target(shim_va, shim_bytes), b"\x00" * shim_bytes)

        # Unterminated / truncated maps record at EOF AND malformed record missing dev:inode MUST refuse
        # both globally (-5 identity/maps, 0 pokes) AND when injected on the per-thread stack VMA lookup (-17 sp_vma_unknown, 0 pokes)!
        rows_m = gh_m.maps_text.splitlines(keepends=True)
        for label, bad_maps, expect_rc, expect_global in (
            ("unterminated_eof", b"".join(rows_m[:2] + rows_m[3:]) + rows_m[2].split(b"00:00")[0], 5, "MLV2_RESULT=-5"),
            ("malformed_cols", b"".join(rows_m[:2] + rows_m[3:]) + rows_m[2].split(b"00:00")[0] + b"\n", 1, "sp_vma_unknown"),
            ("embedded_nul", b"".join(rows_m[:2] + rows_m[3:]) + rows_m[2].replace(b" 0\n", b" 0\x00x\n"), 5, "MLV2_RESULT=-5"),
            ("addr_overflow", b"".join(rows_m[:2] + rows_m[3:]) + b"1" + rows_m[2].replace(b"-", b"-1", 1), 1, "sp_vma_unknown"),
            ("view_off_overflow", rows_m[0].replace(b" 00000000 ", b" 100000000 ") + b"".join(rows_m[1:]), 5, "MLV2_RESULT=-5"),
        ):
            gh_t = GuardHarness(self.guard_elf, {"/tmp_network/mlv2/mlv2.req": self.req_bytes}, vbase)
            self.assertEqual(gh_t.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])[0], 0)
            gh_t.files["/tmp_network/mlv2/sd-disabled"] = b""
            gh_t.files["/tmp_network/mlv2/sd-stopped"] = b""
            orig_maps_t = gh_t.maps_text
            gh_t.maps_text = bad_maps
            rc_t, out_t, st_t = gh_t.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
            self.assertEqual(rc_t, expect_rc, f"{label}: {out_t}")
            self.assertIn(expect_global, out_t, f"{label}: {out_t}")
            self.assertEqual(st_t["poke_count"], 0)
            self.assertEqual(st_t["attached"], set())
            self.assertNotEqual(gh_t.read_target(shim_va, shim_bytes), b"\x00" * shim_bytes)
            if label == "view_off_overflow":
                continue
            # Also inject bad_maps ONLY on the 4th maps open (TID 150 stack VMA lookup) -> MUST hit sp_vma_unknown (-17)!
            gh_t.maps_text = orig_maps_t
            m_opens = [0]

            def make_4th_open_bad(bm):
                def hook_4(self_uc, htype, cb, *a, **kw):
                    if htype != uc.UC_HOOK_INTR:
                        return old_hook_add_stk(self_uc, htype, cb, *a, **kw)
                    def intr(cpu, intno, user):
                        if cpu.reg_read(A.UC_ARM_REG_R7) == 5 and bytes(cpu.mem_read(cpu.reg_read(A.UC_ARM_REG_R0), 15)) == b"/proc/149/maps\0":
                            m_opens[0] += 1
                            if m_opens[0] == 4:
                                gh_t.maps_text = bm
                                try:
                                    return cb(cpu, intno, user)
                                finally:
                                    gh_t.maps_text = orig_maps_t
                        return cb(cpu, intno, user)
                    return old_hook_add_stk(self_uc, htype, intr, *a, **kw)
                return hook_4

            with patch.object(uc.Uc, "hook_add", make_4th_open_bad(bad_maps)):
                rc_4, out_4, st_4 = gh_t.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
            self.assertEqual(rc_4, 1, f"{label} 4th: {out_4}")
            self.assertIn("sp_vma_unknown", out_4, f"{label} 4th: {out_4}")
            self.assertIn("MLV2_RESULT=-17 changed=0", out_4)
            self.assertEqual(st_4["poke_count"], 0)
            self.assertEqual(st_4["attached"], set())

        # Pause mid-core_init AFTER callbacks are written (if ever) and BEFORE core_base publication:
        # concurrent refresh + set_root MUST NOT dispatch callbacks or hide backdrop until core_base != 0!
        class PauseAfterCoreInitCallbacks(EndToEndMenuHarness):
            def __init__(self, *args):
                super().__init__(*args)
                self.saved = None

            def _syscall(self, cpu, intno, extra):
                super()._syscall(cpu, intno, extra)
                if self.saved is None and cpu.reg_read(A.UC_ARM_REG_R7) == 5:
                    sl = self.u32(self.shim_va)
                    if sl and self.u32(sl + 20) and not self.u32(sl + 8):
                        self.saved = cpu.context_save()
                        cpu.emu_stop()

        gh_pi = GuardHarness(self.guard_elf, {"/tmp_network/mlv2/mlv2.req": self.req_bytes}, vbase)
        self.assertEqual(gh_pi.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])[0], 0)
        ppi = PauseAfterCoreInitCallbacks(gh_pi, self.core_bin, self.precap_mod)
        ppi.call_real_set_root(ppi.root)
        pi_slot = ppi.u32(shim_va)
        self.assertIsNotNone(ppi.saved)
        self.assertEqual(tuple(ppi.u32(pi_slot + o) for o in (8, 12, 48, 52)), (0, 0, 1, 1))
        saved_sp_pi = ppi.STACK
        ppi.STACK -= 0x8000
        ppi.call_real_refresh()
        self.assertEqual(ppi.call_real_set_root(ppi.root), 1)
        self.assertEqual(ppi.set_mode_calls, [])
        self.assertEqual(ppi.u32(ppi.root + 8), 6)
        self.assertEqual(tuple(ppi.u32(pi_slot + o) for o in (8, 12, 48, 52)), (0, 0, 1, 1))
        ppi.STACK = saved_sp_pi
        ppi.m.context_restore(ppi.saved)
        ppi.m.emu_start(ppi.m.reg_read(A.UC_ARM_REG_PC) | 1, ppi.STOP, count=5_000_000)
        self.assertNotEqual(ppi.u32(pi_slot + 8), 0)
        self.assertEqual((ppi.u32(pi_slot + 12), ppi.u32(pi_slot + 48)), (1, 0))
        self.assertEqual(ppi.u32(ppi.root + 8), 7)

        # sd-stopped alone (present OR -EACCES) MUST disable both shim backdrop and core root extension!
        class DenyPathMenu(EndToEndMenuHarness):
            def __init__(self, *args, deny_path: str):
                super().__init__(*args)
                self.deny_path = deny_path

            def _syscall(self, cpu, intno, extra):
                if cpu.reg_read(A.UC_ARM_REG_R7) == 5:
                    p = bytes(cpu.mem_read(cpu.reg_read(A.UC_ARM_REG_R0), 96)).split(b"\x00", 1)[0]
                    if p == self.deny_path.encode("ascii"):
                        cpu.reg_write(A.UC_ARM_REG_R0, (-13) & 0xFFFFFFFF)
                        return
                super()._syscall(cpu, intno, extra)

        for mk in ("/tmp_network/mlv2/sd-disabled", "/tmp_network/mlv2/sd-stopped"):
            dm = DenyPathMenu(gh_ov, self.core_bin, self.precap_mod, deny_path=mk)
            dm.files[mk] = b""
            dm.call_real_set_root(dm.root)
            dm.call_real_refresh()
            self.assertEqual((dm.u32(dm.root + 8), dm.set_mode_calls), (6, []), f"marker {mk} failed open")

        # 5d: Live PauseAtAck uninstall race MUST be refused by mlv2_guard.elf while callback is in flight,
        #     and MUST succeed cleanly after callback returns!
        class PauseAtAck(EndToEndMenuHarness):
            def __init__(self, *args):
                super().__init__(*args)
                self.armed = False
                self.paused_state = None

            def _syscall(self, cpu, intno, extra):
                is_ack = (
                    self.armed and cpu.reg_read(A.UC_ARM_REG_R7) == 5 and
                    cpu.reg_read(A.UC_ARM_REG_R1) == (0x441 | 0o4000 | 0o100000) and
                    bytes(cpu.mem_read(cpu.reg_read(A.UC_ARM_REG_R0), 64)).split(b"\x00", 1)[0] == b"/tmp_network/mlv2/sd-stopped"
                )
                super()._syscall(cpu, intno, extra)
                if is_ack:
                    self.paused_state = (
                        cpu.reg_read(A.UC_ARM_REG_PC),
                        cpu.reg_read(A.UC_ARM_REG_LR),
                        cpu.reg_read(A.UC_ARM_REG_SP),
                    )
                    cpu.emu_stop()

        gh2 = GuardHarness(self.guard_elf, {"/tmp_network/mlv2/mlv2.req": self.req_bytes}, vbase)
        self.assertEqual(gh2.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])[0], 0)
        pm = PauseAtAck(gh2, self.core_bin, self.precap_mod)
        self.assertEqual(pm.call_real_set_root(pm.root), 1)
        pm.files["/tmp_network/mlv2/sd-disabled"] = b""
        pm.armed = True
        pm.call_real_set_root(pm.root)
        self.assertIsNotNone(pm.paused_state)
        ppc, plr, psp = pm.paused_state
        slot_ptr = pm.u32(shim_va)
        self.assertTrue(gh2.write_target_word(shim_va, slot_ptr))
        gh2.regions.append((slot_ptr, bytearray(pm.m.mem_read(slot_ptr, 0x1000))))
        ctx_ptr = pm.u32(slot_ptr + 16)
        gh2.regions.append((ctx_ptr, bytearray(pm.m.mem_read(ctx_ptr, 0x1000))))
        gh2.regions.append((pm.NODES, bytearray(pm.m.mem_read(pm.NODES, 0x1000))))
        gh2.regions.append((pm.STACK - 0x2000, bytearray(pm.m.mem_read(pm.STACK - 0x2000, 0x2000))))
        gh2.maps_text += f"{pm.STACK - 0x2000:08x}-{pm.STACK:08x} rw-p 00000000 00:00 0\n".encode("ascii")
        gh2.files["/tmp_network/mlv2/sd-disabled"] = b""
        gh2.files["/tmp_network/mlv2/sd-stopped"] = b""
        gh2.thread_pcs[150] = ppc
        gh2.thread_lrs[150] = plr
        gh2.thread_sps[150] = psp
        rc_race, out_race, _ = gh2.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc_race, 1, out_race)
        self.assertIn("BUSY", out_race)
        self.assertIn("MLV2_RESULT=-17", out_race)

        pm.m.emu_start(ppc | 1, pm.STOP, count=50000)
        gh2.regions = [r for r in gh2.regions if r[0] != slot_ptr]
        gh2.regions.append((slot_ptr, bytearray(pm.m.mem_read(slot_ptr, 0x1000))))
        gh2.thread_pcs[150] = 0x00020000
        gh2.thread_lrs[150] = 0x00020100
        gh2.thread_sps[150] = 0x5D005000
        rc_ok, out_ok, _ = gh2.run(["mlv2_guard.elf", "uninstall", "/tmp_network/mlv2/mlv2.req"])
        self.assertEqual(rc_ok, 0, out_ok)
        self.assertIn("UNINSTALLED restored=stock", out_ok)

        # 5e: stage7_daemon.elf fails CLOSED on BOTH readable markers AND -EACCES marker open errors,
        #     and disarms active ring IMMEDIATELY (1 tick) when sd-disabled appears!
        old_hook_add = uc.Uc.hook_add
        for blocked_flag in ("/tmp_network/mlv2/sd-disabled", "/tmp_network/mlv2/sd-stopped"):
            def make_eacces_hook(target_path):
                def hook_wrap(self_uc, htype, cb, *a, **kw):
                    if htype == uc.UC_HOOK_INTR:
                        def intercept(cpu, intno, user):
                            if cpu.reg_read(A.UC_ARM_REG_R7) == 5:
                                p = bytes(cpu.mem_read(cpu.reg_read(A.UC_ARM_REG_R0), 96)).split(b"\x00", 1)[0]
                                if p == target_path.encode("ascii"):
                                    cpu.reg_write(A.UC_ARM_REG_R0, (-13) & 0xFFFFFFFF)  # -EACCES
                                    return
                            return cb(cpu, intno, user)
                        return old_hook_add(self_uc, htype, intercept, *a, **kw)
                    return old_hook_add(self_uc, htype, cb, *a, **kw)
                return hook_wrap

            d_err = DaemonHarness(self.daemon_elf, self.manifest["artifacts"]["daemon"], duration_ms=0, poll_ms=20)
            d_err.files["/tmp_network/mlv2/precap.cfg"] = b"S7PC1 1 10\n"
            d_err.files[blocked_flag] = b""

            def press_err(tick: int, h: DaemonHarness):
                if tick == 3:
                    h.half = 1
                elif tick == 20:
                    h.files[f"{h.run_dir}/stop"] = b"stop\n"

            d_err.on_tick = press_err
            with patch.object(uc.Uc, "hook_add", make_eacces_hook(blocked_flag)):
                rc_e, out_e = d_err.run()
            self.assertEqual(rc_e, 0, out_e)
            self.assertNotIn("RING_START", out_e, f"daemon armed despite -EACCES on {blocked_flag}")

        # Active ring + sd-disabled -> IMMEDIATE DISARM_GATE (must fire on the very next poll, < 5 ticks!)
        d_dis = DaemonHarness(self.daemon_elf, self.manifest["artifacts"]["daemon"], duration_ms=0, poll_ms=20)
        d_dis.ring_exit_after_polls = 200
        d_dis.files["/tmp_network/mlv2/precap.cfg"] = b"S7PC1 1 10\n"
        disarm_ticks = []

        def disable_mid_ring(tick: int, h: DaemonHarness):
            if tick == 3:
                h.half = 1
            elif tick == 10:
                h.files["/tmp_network/mlv2/sd-disabled"] = b""
            elif tick > 10 and f"{h.run_dir}/disarm" in h.files and not disarm_ticks:
                disarm_ticks.append(tick)
            elif tick == 40:
                h.files[f"{h.run_dir}/stop"] = b"stop\n"

        d_dis.on_tick = disable_mid_ring
        rc_d, out_d = d_dis.run()
        self.assertEqual(rc_d, 0, out_d)
        self.assertIn("DISARM_GATE", out_d)
        self.assertNotIn("DISARM_STOP", out_d)
        self.assertIn("r_reap=1", out_d)
        self.assertTrue(disarm_ticks and disarm_ticks[0] <= 12, f"disarm delayed: {disarm_ticks}")

    def check_menu(self, cam, status, frames):
        top_row = 0x9350 + 0xB60
        status_row = top_row + 0x1118
        count_row = top_row + 2 * 0x1118

        # Count edits can update just one row. The latest text per row is
        # the immediate display, including any previous text left on screen.
        def check_submenu():
            rows = dict(cam.texts)
            self.assertEqual((rows[status_row], rows[count_row]), (status, frames))

        check_submenu()
        cam.texts.clear()
        cam.call_real_refresh()
        check_submenu()
        cam.call_real_open_item(cam.items()[0])  # Back
        self.assertEqual(dict(cam.texts)[top_row], status + " >")
        cam.call_real_set_root(cam.root)  # rescan
        cam.texts.clear()
        cam.call_real_refresh()
        self.assertEqual(dict(cam.texts)[top_row], status + " >")
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[0])  # reopen
        check_submenu()

    def test_6_remembered_state_persistence_and_log_cap(self):
        vbase = layout.REF_VIEW_BASE + 0x20000
        gh = GuardHarness(
            self.guard_elf,
            {"/tmp_network/mlv2/mlv2.req": self.req_bytes},
            view_base=vbase,
        )
        self.assertEqual(gh.run(["mlv2_guard.elf", "install", "/tmp_network/mlv2/mlv2.req"])[0], 0)

        sim_dst = "/tmp_network/mlv2/sim-setting-precap.cfg"
        gate = "/tmp_network/mlv2/persist-cfg"
        cfg = "/tmp_network/mlv2/precap.cfg"

        # 6a: Cold boot with remembered ON/8 -> first MENU hydrates ON/8 without writing durable!
        cam = EndToEndMenuHarness(gh, self.core_bin, self.precap_mod)
        cam.files[cfg] = b"S7PC1 1 8\n"
        cam.files[sim_dst] = b"S7PC1 1 8\n"
        cam.files[gate] = (sim_dst + "\n").encode("ascii")
        self.assertEqual(cam.call_real_set_root(cam.root), 1)
        cam.call_real_refresh()
        self.assertEqual(cam.texts, [
            (0x5470, "Mods"),
            (0x9350 + 0x7C8, "Pre-Capture"),
            (0x9350 + 0xB60, "ON >"),
        ])
        self.assertEqual(cam.fsync_calls, [])
        self.assertEqual(cam.files[sim_dst], b"S7PC1 1 8\n")

        # Enter submenu: displays Mod Status=ON and Pre-Frames=8
        cam.call_real_open_item(cam.items()[0])
        self.assertEqual(cam.texts, [
            (0x5470, "Pre-Capture"),
            (0x9350 + 0x7C8, "< Back"),
            (0x9350 + 0xB60, ""),
            (0x9350 + 0x1118 + 0x7C8, "Mod Status"),
            (0x9350 + 0x1118 + 0xB60, "ON"),
            (0x9350 + 2 * 0x1118 + 0x7C8, "Pre-Frames"),
            (0x9350 + 2 * 0x1118 + 0xB60, "8"),
        ])
        # Reopen MENU: still no durable writes
        self.assertEqual(cam.call_real_set_root(cam.root), 1)
        self.assertEqual(cam.fsync_calls, [])

        # Explicit user edit while ON: 8 -> 10 persists to both runtime and durable
        cam.call_real_open_item(cam.items()[0])
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[2])
        self.assertEqual(cam.texts, [(0x9350 + 2 * 0x1118 + 0xB60, "10")])
        self.assertEqual(cam.files[cfg], b"S7PC1 1 10\n")
        self.assertEqual(cam.files[sim_dst], b"S7PC1 1 10\n")
        self.assertEqual(len(cam.fsync_calls), 1)

        # sd-disabled teardown disarms runtime (0 10) while PRESERVING durable ON (1 10)!
        cam.files["/tmp_network/mlv2/sd-disabled"] = b""
        cam.call_real_set_root(cam.root)
        self.assertEqual(cam.files[cfg], b"S7PC1 0 10\n")
        self.assertEqual(cam.files[sim_dst], b"S7PC1 1 10\n")
        self.assertEqual(len(cam.fsync_calls), 1)
        self.assertIn("/tmp_network/mlv2/sd-stopped", cam.files)

        # Reactivation: clear sd-disabled/sd-stopped and restore runtime from durable -> UI re-hydrates ON/10!
        del cam.files["/tmp_network/mlv2/sd-disabled"]
        del cam.files["/tmp_network/mlv2/sd-stopped"]
        cam.files[cfg] = cam.files[sim_dst]
        cam.texts.clear()
        cam.call_real_set_root(cam.root)
        cam.call_real_refresh()
        self.assertEqual(cam.texts[-1], (0x9350 + 0xB60, "ON >"))

        # Explicit user OFF + OFF-state count edit (10 -> 1) persists OFF/1 to BOTH runtime and durable!
        cam.call_real_open_item(cam.items()[0])
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[1])  # OFF
        self.assertEqual(cam.texts, [(0x9350 + 0x1118 + 0xB60, "OFF")])
        self.assertEqual(cam.files[cfg], b"S7PC1 0 10\n")
        self.assertEqual(cam.files[sim_dst], b"S7PC1 0 10\n")

        cam.texts.clear()
        cam.call_real_open_item(cam.items()[2])  # 10 -> 1 while OFF
        self.assertEqual(cam.texts, [(0x9350 + 2 * 0x1118 + 0xB60, "1")])
        self.assertEqual(cam.files[cfg], b"S7PC1 0 1\n")
        self.assertEqual(cam.files[sim_dst], b"S7PC1 0 1\n")

        # Durable write failures:
        # 1) ON failure NEVER exposes ON in runtime precap.cfg during fsync and keeps UI OFF!
        cam.fail_fsync_paths.add(sim_dst + ".tmp")
        cam.runtime_at_fsync.clear()
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[1])  # try ON -> fails fsync -> stays OFF!
        self.assertEqual(cam.texts, [(0x9350 + 0x1118 + 0xB60, "OFF")])
        self.assertEqual(cam.runtime_at_fsync, [b"S7PC1 0 1\n"])
        self.assertEqual(cam.files[cfg], b"S7PC1 0 1\n")
        self.assertEqual(cam.files[sim_dst], b"S7PC1 0 1\n")
        self.assertNotIn(sim_dst + ".tmp", cam.files)

        # 2) Count edit failure while OFF & while ON NEVER exposes uncommitted count in runtime!
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[2])  # try 1 -> 2 while OFF -> fails fsync -> stays 1!
        self.assertEqual(cam.texts, [(0x9350 + 2 * 0x1118 + 0xB60, "1")])
        self.assertEqual(cam.files[sim_dst], b"S7PC1 0 1\n")

        # 3) ON succeeds, then ON count edit fsync failure keeps runtime at old 1 during & after fsync!
        cam.fail_fsync_paths.clear()
        cam.call_real_open_item(cam.items()[1])  # ON succeeds -> 1 1
        self.assertEqual(cam.files[sim_dst], b"S7PC1 1 1\n")
        cam.fail_fsync_paths.add(sim_dst + ".tmp")
        cam.runtime_at_fsync.clear()
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[2])  # try 1 -> 2 while ON -> fails fsync -> stays 1!
        self.assertEqual(cam.texts, [(0x9350 + 2 * 0x1118 + 0xB60, "1")])
        self.assertEqual(cam.runtime_at_fsync, [b"S7PC1 1 1\n"])
        self.assertEqual(cam.files[cfg], b"S7PC1 1 1\n")
        cam.fail_fsync_paths.clear()

        # 4) Dual failure on OFF (runtime rename+unlink BOTH fail): MUST NOT claim OFF! while runtime stays ON!
        cam.fail_rename_dsts.add(cfg)
        cam.fail_unlink_paths.add(cfg)
        cam.fail_rename_dsts.add(sim_dst)
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[1])  # OFF fails runtime disarm -> displays ON! and stays enabled
        self.assertEqual(cam.texts, [(0x9350 + 0x1118 + 0xB60, "ON!")])
        self.assertEqual(cam.files[cfg], b"S7PC1 1 1\n")

        # 4b) Sol Part A r2 Finding 4 residual: dual failure + ONE fstat64 -EIO on readback MUST STILL display ON!
        #     (immediate AND on refresh), with ZERO durable writes while runtime stays ON/1!
        cam.fail_fstat_once_paths.add(cfg)
        cam.fsync_calls.clear()
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[1])
        self.assertEqual(cam.texts, [(0x9350 + 0x1118 + 0xB60, "ON!")])
        self.assertEqual(cam.fsync_calls, [])
        self.assertEqual(cam.files[cfg], b"S7PC1 1 1\n")
        cam.texts.clear()
        cam.call_real_refresh()
        self.assertIn((0x9350 + 0x1118 + 0xB60, "ON!"), cam.texts)
        cam.fail_rename_dsts.discard(cfg)
        cam.fail_unlink_paths.discard(cfg)

        # 4c) Sol Part A r2 New MAJOR #1: ON count edit runtime failure MUST preserve ON/1, revert UI & durable!
        cam.fail_rename_dsts.clear()
        cam.fail_rename_dsts.add(cfg)
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[2])  # ON 1 -> 2, durable writes ON/2, runtime rename fails -> reverts all to ON/1!
        self.assertEqual(cam.files[cfg], b"S7PC1 1 1\n")
        self.assertEqual(cam.files[sim_dst], b"S7PC1 1 1\n")
        self.assertIn((0x9350 + 0x1118 + 0xB60, "ON"), cam.texts)
        self.assertIn((0x9350 + 2 * 0x1118 + 0xB60, "1"), cam.texts)
        cam.texts.clear()
        cam.call_real_refresh()
        self.assertIn((0x9350 + 0x1118 + 0xB60, "ON"), cam.texts)
        self.assertIn((0x9350 + 2 * 0x1118 + 0xB60, "1"), cam.texts)

        # 4d) ON count edit runtime failure + fstat64 readback error -> reverts count to 1 AND flags ON! mismatch!
        cam.fail_fstat_once_paths.add(cfg)
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[2])
        self.assertEqual(cam.files[cfg], b"S7PC1 1 1\n")
        self.assertIn((0x9350 + 0x1118 + 0xB60, "ON!"), cam.texts)
        self.assertIn((0x9350 + 2 * 0x1118 + 0xB60, "1"), cam.texts)
        cam.texts.clear()
        cam.call_real_refresh()
        self.assertIn((0x9350 + 0x1118 + 0xB60, "ON!"), cam.texts)
        cam.fail_rename_dsts.discard(cfg)

        # 4e) Sol Part A r3: gate vanishes or retargets during rollback -> MUST NOT silently clear dirty flag
        #     and MUST NOT write compensation to the alternate destination!
        alt_dst = "/setting/mlv2_precap.cfg"
        top_row = 0x9350 + 0xB60
        status_row = top_row + 0x1118
        count_row = top_row + 2 * 0x1118

        class GateSwapHarness(EndToEndMenuHarness):
            fault_armed = False
            rollback_gate = None

            def _syscall(self, cpu, intno, extra):
                if self.fault_armed and cpu.reg_read(A.UC_ARM_REG_R7) == 38:
                    dst_ptr = cpu.reg_read(A.UC_ARM_REG_R1)
                    dst = bytes(cpu.mem_read(dst_ptr, 96)).split(b"\x00", 1)[0].decode("ascii")
                    if dst == cfg:
                        if self.rollback_gate is None:
                            self.files.pop(gate, None)
                        else:
                            self.files[gate] = (self.rollback_gate + "\n").encode("ascii")
                        cpu.reg_write(A.UC_ARM_REG_R0, (-5) & 0xFFFFFFFF)
                        return
                super()._syscall(cpu, intno, extra)

        def failed_menu_edit(initial, row, rollback_gate):
            h = GateSwapHarness(gh, self.core_bin, self.precap_mod)
            h.files[cfg] = h.files[alt_dst] = initial
            h.files[gate] = (alt_dst + "\n").encode("ascii")
            h.call_real_set_root(h.root)
            h.call_real_open_item(h.items()[0])
            h.rollback_gate = rollback_gate
            h.fault_armed = True
            before = len(h.texts)
            h.call_real_open_item(h.items()[row])
            h.fault_armed = False
            if row == 2:
                self.assertIn((count_row, "5"), h.texts[before:])
            self.assertIn((status_row, "ON!" if row == 2 else "OFF!"), h.texts[before:])
            self.assertNotIn(sim_dst, h.files)
            return h

        # The count write reaches /setting before the runtime rename fails.
        # Explicit OFF can reconcile only the destination authorized at that time.
        for rollback_gate, off_gate in ((None, None), (None, sim_dst),
                                        (None, alt_dst), (sim_dst, sim_dst)):
            with self.subTest(rollback_gate=rollback_gate, off_gate=off_gate):
                h = failed_menu_edit(b"S7PC1 1 5\n", 2, rollback_gate)
                self.check_menu(h, "ON!", "5")
                self.assertEqual(h.files[cfg], b"S7PC1 1 5\n")
                self.assertEqual(h.files[alt_dst], b"S7PC1 1 8\n")
                if off_gate:
                    h.files[gate] = (off_gate + "\n").encode("ascii")
                h.call_real_open_item(h.items()[1])
                self.assertEqual(h.files[cfg], b"S7PC1 0 5\n")
                if off_gate == alt_dst:
                    self.check_menu(h, "OFF", "5")
                    self.assertEqual(h.files[alt_dst], h.files[cfg])
                    continue

                self.check_menu(h, "OFF!", "5")
                self.assertEqual(h.files[alt_dst], b"S7PC1 1 8\n")
                self.assertEqual(h.files.get(sim_dst), h.files[cfg] if off_gate else None)
                h.files[gate] = (alt_dst + "\n").encode("ascii")
                h.call_real_open_item(h.items()[2])
                self.check_menu(h, "OFF", "8")
                self.assertEqual(h.files[cfg], b"S7PC1 0 8\n")
                self.assertEqual(h.files[alt_dst], h.files[cfg])

        # A second write failure can leave both destinations dirty at once.
        h = failed_menu_edit(b"S7PC1 1 5\n", 2, None)
        h.files[sim_dst] = b"S7PC1 1 5\n"
        h.files[gate] = (sim_dst + "\n").encode("ascii")
        h.fail_rename_dsts.add(sim_dst)
        h.call_real_open_item(h.items()[1])
        self.check_menu(h, "OFF!", "5")
        self.assertEqual(h.files[cfg], b"S7PC1 0 5\n")
        self.assertEqual(h.files[alt_dst], b"S7PC1 1 8\n")
        self.assertEqual(h.files[sim_dst], b"S7PC1 1 5\n")
        h.files[gate] = (alt_dst + "\n").encode("ascii")
        h.call_real_open_item(h.items()[2])
        self.check_menu(h, "OFF!", "8")
        self.assertEqual(h.files[alt_dst], b"S7PC1 0 8\n")
        self.assertEqual(h.files[sim_dst], b"S7PC1 1 5\n")
        h.fail_rename_dsts.remove(sim_dst)
        h.files[gate] = (sim_dst + "\n").encode("ascii")
        h.call_real_open_item(h.items()[2])
        self.check_menu(h, "OFF", "10")
        self.assertEqual(h.files[sim_dst], b"S7PC1 0 10\n")

        # Failed activation leaves runtime absent and /setting armed. Follow
        # one session through the ungated edit, the sim edit and reconciliation.
        for rollback_gate in (None, sim_dst):
            with self.subTest(activation_rollback_gate=rollback_gate):
                h = failed_menu_edit(b"S7PC1 0 5\n", 1, rollback_gate)
                self.check_menu(h, "OFF!", "5")
                self.assertEqual(h.files[alt_dst], b"S7PC1 1 5\n")
                self.assertNotIn(cfg, h.files)
                if rollback_gate is not None:
                    continue

                h.call_real_open_item(h.items()[2])
                self.check_menu(h, "OFF!", "8")
                self.assertNotIn(cfg, h.files)
                self.assertNotIn(sim_dst, h.files)
                self.assertEqual(h.files[alt_dst], b"S7PC1 1 5\n")

                h.files[gate] = (sim_dst + "\n").encode("ascii")
                h.call_real_open_item(h.items()[2])
                self.check_menu(h, "OFF!", "10")
                self.assertEqual(h.files[cfg], b"S7PC1 0 10\n")
                self.assertEqual(h.files[sim_dst], h.files[cfg])
                self.assertEqual(h.files[alt_dst], b"S7PC1 1 5\n")

                h.files[gate] = (alt_dst + "\n").encode("ascii")
                h.call_real_open_item(h.items()[2])
                self.check_menu(h, "OFF", "1")
                self.assertEqual(h.files[cfg], b"S7PC1 0 1\n")
                self.assertEqual(h.files[alt_dst], h.files[cfg])
                self.assertEqual(h.files[sim_dst], b"S7PC1 0 10\n")

        # 4f) Sol Part A r3: unexpected runtime disarm during ON count edit MUST display OFF! even if durable succeeds!
        class DisarmOnEditHarness(EndToEndMenuHarness):
            def __init__(self, *args):
                super().__init__(*args)
                self.armed = False

            def _syscall(self, cpu, intno, extra):
                if self.armed and cpu.reg_read(A.UC_ARM_REG_R7) == 38:
                    dst_p = bytes(cpu.mem_read(cpu.reg_read(A.UC_ARM_REG_R1), 96)).split(b"\x00", 1)[0].decode("ascii")
                    if dst_p == cfg:
                        self.files.pop(cfg, None)
                        cpu.reg_write(A.UC_ARM_REG_R0, (-5) & 0xFFFFFFFF)
                        return
                super()._syscall(cpu, intno, extra)

        hd = DisarmOnEditHarness(gh, self.core_bin, self.precap_mod)
        hd.files[cfg] = b"S7PC1 1 5\n"
        hd.files[sim_dst] = b"S7PC1 1 5\n"
        hd.files[gate] = (sim_dst + "\n").encode("ascii")
        hd.call_real_set_root(hd.root)
        hd.call_real_open_item(hd.items()[0])
        hd.armed = True
        hd.texts.clear()
        hd.call_real_open_item(hd.items()[2])
        self.assertIn((0x9350 + 0x1118 + 0xB60, "OFF!"), hd.texts)
        self.assertEqual(hd.files[sim_dst], b"S7PC1 0 5\n")
        hd.texts.clear()
        hd.call_real_refresh()
        self.assertIn((0x9350 + 0x1118 + 0xB60, "OFF!"), hd.texts)

        cam.fail_rename_dsts.add(sim_dst)

        # 5) Durable-only OFF failure disarms runtime immediately, displays "OFF!", AND keeps "OFF!" across refresh!
        cam.texts.clear()
        cam.call_real_open_item(cam.items()[1])  # OFF -> runtime disarms, durable fails -> "OFF!"
        self.assertEqual(cam.texts, [(0x9350 + 0x1118 + 0xB60, "OFF!")])
        self.assertEqual(cam.files[cfg], b"S7PC1 0 1\n")
        self.assertEqual(cam.files[sim_dst], b"S7PC1 1 1\n")
        cam.texts.clear()
        cam.call_real_refresh()
        self.assertIn((0x9350 + 0x1118 + 0xB60, "OFF!"), cam.texts)
        cam.fail_rename_dsts.clear()

        # 6) Same-core reactivation to OFF/10 refreshes displayed count from 1 to 10 (Sol Part A #3)!
        cam.files["/tmp_network/mlv2/sd-disabled"] = b""
        cam.call_real_set_root(cam.root)
        del cam.files["/tmp_network/mlv2/sd-disabled"]
        del cam.files["/tmp_network/mlv2/sd-stopped"]
        cam.files[cfg] = b"S7PC1 0 10\n"
        cam.files[sim_dst] = b"S7PC1 0 10\n"
        cam.call_real_set_root(cam.root)
        cam.call_real_open_item(cam.items()[0])
        self.assertIn((0x9350 + 0x1118 + 0xB60, "OFF"), cam.texts)
        self.assertIn((0x9350 + 2 * 0x1118 + 0xB60, "10"), cam.texts)

        # 7) Zero blocking open(..., 0) on persist-cfg or precap.cfg during OFF count edit (Sol Part A #2)!
        cam.open_events.clear()
        cam.call_real_open_item(cam.items()[2])  # OFF 10 -> 1
        for op_path, op_flags in cam.open_events:
            if op_path in (gate, cfg) and not (op_flags & 0o100):
                self.assertEqual(op_flags & 0o104000, 0o104000, f"Blocking open on {op_path}: {op_flags:#o}")

        # 6b: Cold boot with remembered OFF/8 -> first MENU shows OFF/8; enabling uses 8!
        cam_off = EndToEndMenuHarness(gh, self.core_bin, self.precap_mod)
        cam_off.files[cfg] = b"S7PC1 0 8\n"
        cam_off.files[sim_dst] = b"S7PC1 0 8\n"
        cam_off.files[gate] = (sim_dst + "\n").encode("ascii")
        cam_off.call_real_set_root(cam_off.root)
        cam_off.call_real_open_item(cam_off.items()[0])
        self.assertEqual(cam_off.texts[4], (0x9350 + 0x1118 + 0xB60, "OFF"))
        self.assertEqual(cam_off.texts[6], (0x9350 + 2 * 0x1118 + 0xB60, "8"))

        # 6c: Malformed runtime cfg, embedded-NUL gate (Sol Part A #1), and FIFO gate/cfg (Sol Part A #2) all rejected!
        cam_bad = EndToEndMenuHarness(gh, self.core_bin, self.precap_mod)
        cam_bad.files[cfg] = b"S7PC1 1 99\n"
        cam_bad.files["/setting/mlv2_precap.cfg"] = b"S7PC1 0 5\n"
        cam_bad.files[gate] = b"/setting/mlv2_precap.cfg\n\x00x"
        cam_bad.call_real_set_root(cam_bad.root)
        cam_bad.call_real_open_item(cam_bad.items()[0])
        self.assertEqual(cam_bad.texts[4], (0x9350 + 0x1118 + 0xB60, "OFF"))
        self.assertEqual(cam_bad.texts[6], (0x9350 + 2 * 0x1118 + 0xB60, "5"))
        cam_bad.texts.clear()
        cam_bad.call_real_open_item(cam_bad.items()[1])  # embedded-NUL gate -> refused, zero writes!
        self.assertEqual(cam_bad.texts, [(0x9350 + 0x1118 + 0xB60, "OFF")])
        self.assertEqual(cam_bad.files["/setting/mlv2_precap.cfg"], b"S7PC1 0 5\n")
        self.assertEqual(cam_bad.fsync_calls, [])

        # FIFO at persist-cfg -> refused via fstat64!
        cam_bad.files[gate] = b"/setting/mlv2_precap.cfg\n"
        cam_bad.fifo_paths.add(gate)
        cam_bad.texts.clear()
        cam_bad.call_real_open_item(cam_bad.items()[1])
        self.assertEqual(cam_bad.texts, [(0x9350 + 0x1118 + 0xB60, "OFF")])
        self.assertEqual(cam_bad.files["/setting/mlv2_precap.cfg"], b"S7PC1 0 5\n")
        self.assertEqual(cam_bad.fsync_calls, [])

        # A failed OFF through an unreadable gate has no known destination.
        # An absent gate preserves the warning. An idempotent authorized edit clears it.
        unknown = EndToEndMenuHarness(gh, self.core_bin, self.precap_mod)
        unknown.files[cfg] = b"S7PC1 1 5\n"
        unknown.files[sim_dst] = b"S7PC1 0 10\n"
        unknown.files[gate] = (sim_dst + "\n").encode("ascii")
        unknown.fifo_paths.add(gate)
        unknown.call_real_set_root(unknown.root)
        unknown.call_real_open_item(unknown.items()[0])
        unknown.call_real_open_item(unknown.items()[1])
        self.check_menu(unknown, "OFF!", "5")
        unknown.fifo_paths.remove(gate)
        del unknown.files[gate]
        unknown.call_real_open_item(unknown.items()[2])
        self.check_menu(unknown, "OFF!", "8")
        unknown.files[gate] = (sim_dst + "\n").encode("ascii")
        unknown.call_real_open_item(unknown.items()[2])
        self.check_menu(unknown, "OFF", "10")
        self.assertEqual(unknown.files[cfg], unknown.files[sim_dst])
        self.assertEqual(unknown.fsync_calls, [])

        # 6d: Absent gate (Stage 7.2 RAM-only isolation): pre-existing /setting/mlv2_precap.cfg stays UNTOUCHED!
        cam_ram = EndToEndMenuHarness(gh, self.core_bin, self.precap_mod)
        cam_ram.files["/setting/mlv2_precap.cfg"] = b"S7PC1 1 8\n"
        cam_ram.call_real_set_root(cam_ram.root)
        cam_ram.call_real_open_item(cam_ram.items()[0])
        self.check_menu(cam_ram, "OFF", "5")
        cam_ram.call_real_open_item(cam_ram.items()[1])  # ON
        self.check_menu(cam_ram, "ON", "5")
        cam_ram.call_real_open_item(cam_ram.items()[2])  # 5 -> 8
        self.check_menu(cam_ram, "ON", "8")
        cam_ram.call_real_open_item(cam_ram.items()[1])  # OFF
        self.check_menu(cam_ram, "OFF", "8")
        self.assertEqual(cam_ram.files["/setting/mlv2_precap.cfg"], b"S7PC1 1 8\n")
        self.assertEqual(cam_ram.fsync_calls, [])
        durable_paths = {alt_dst, alt_dst + ".tmp", sim_dst, sim_dst + ".tmp"}
        self.assertTrue(durable_paths.isdisjoint(path for path, _ in cam_ram.open_events))
        self.assertTrue(durable_paths.isdisjoint(cam_ram.rename_unlink_paths))

        # 6e: mod_loader.log strictly capped at 16,384 bytes AND serialized via ShimState.log_lock (Sol Part A #5)
        cam_cap = EndToEndMenuHarness(gh, self.core_bin, self.precap_mod)
        cam_cap.log_bytes = 16380
        cam_cap.call_real_set_root(cam_cap.root)
        self.assertEqual(cam_cap.log, [])
        self.assertEqual(cam_cap.log_bytes, 16380)

        cam_lock = EndToEndMenuHarness(gh, self.core_bin, self.precap_mod)
        cam_lock.call_real_set_root(cam_lock.root)
        slot_ptr_l = cam_lock.u32(cam_lock.shim_va)
        # Simulate another thread holding ShimState.log_lock (offset 56) at 16,365 bytes: core MUST skip append!
        cam_lock.log.clear()
        cam_lock.log_bytes = 16365
        cam_lock.m.mem_write(slot_ptr_l + 56, struct.pack("<I", 1))
        cam_lock.call_real_open_item(cam_lock.items()[0])
        cam_lock.call_real_open_item(cam_lock.items()[1])
        self.assertEqual(cam_lock.log, [])
        self.assertEqual(cam_lock.log_bytes, 16365)
        cam_lock.m.mem_write(slot_ptr_l + 56, struct.pack("<I", 0))

        # 6f: Sol Part A r2 New MAJOR #2: FIFO at mod_loader.log MUST NOT block under log_lock
        #     (O_NONBLOCK|O_NOFOLLOW -> -ENXIO with no reader, fstat64 S_IFIFO rejected with reader, lock released!)
        log_path = "/tmp_network/mods/mod_loader.log"
        for has_reader in (False, True):
            cam_fifo = EndToEndMenuHarness(gh, self.core_bin, self.precap_mod)
            cam_fifo.fifo_paths.add(log_path)
            cam_fifo.fifo_has_reader = has_reader
            cam_fifo.open_events.clear()
            self.assertEqual(cam_fifo.call_real_set_root(cam_fifo.root), 1)
            slot_f = cam_fifo.u32(cam_fifo.shim_va)
            self.assertEqual(cam_fifo.log, [])
            self.assertEqual(cam_fifo.log_bytes, 0)
            self.assertEqual(cam_fifo.u32(slot_f + 56), 0)  # log_lock MUST be released!
            log_opens = [fl for p, fl in cam_fifo.open_events if p == log_path]
            self.assertTrue(log_opens)
            for fl in log_opens:
                self.assertEqual(fl & 0o104000, 0o104000, f"Log open missing O_NONBLOCK|O_NOFOLLOW: {fl:#x}")


    def test_7_unverified_readback_and_failed_disarm(self):
        setting = "/setting/mlv2_precap.cfg"
        sim = "/tmp_network/mlv2/sim-setting-precap.cfg"
        gate = "/tmp_network/mlv2/persist-cfg"
        cfg = "/tmp_network/mlv2/precap.cfg"
        req = "/tmp_network/mlv2/mlv2.req"
        on5, on8, off5 = b"S7PC1 1 5\n", b"S7PC1 1 8\n", b"S7PC1 0 5\n"
        off2 = b"S7PC1 0 2\n"
        guard = GuardHarness(self.guard_elf, {req: self.req_bytes}, view_base=layout.REF_VIEW_BASE + 0x20000)
        self.assertEqual(guard.run(["mlv2_guard.elf", "install", req])[0], 0)

        def set_gate(cam, dest):
            if dest is None:
                cam.files.pop(gate, None)
            else:
                cam.files[gate] = (dest + "\n").encode("ascii")

        class DisarmFaultMenu(EndToEndMenuHarness):
            fault_nr = None
            gate_change = None

            def _syscall(self, cpu, intno, extra):
                nr = cpu.reg_read(A.UC_ARM_REG_R7)
                if nr == self.fault_nr and self.files.get(cfg) == off5:
                    arg = cpu.reg_read(A.UC_ARM_REG_R0)
                    if nr == 5:
                        path = bytes(cpu.mem_read(arg, 96)).split(b"\0", 1)[0].decode("ascii")
                    else:
                        path = self.fds[arg][3]
                    if path == cfg:
                        self.fault_nr = None
                        if self.gate_change:
                            self.gate_change()
                        if nr == 6:
                            self.fds.pop(arg)
                        cpu.reg_write(A.UC_ARM_REG_R0, (-5) & 0xffffffff)
                        return
                super()._syscall(cpu, intno, extra)

        def open_menu(original, initial=on5):
            cam = DisarmFaultMenu(guard, self.core_bin, self.precap_mod)
            cam.files[cfg] = initial
            for dest in (setting, sim):
                cam.files[dest] = initial if dest == original else off2
            set_gate(cam, original)
            self.assertEqual(cam.call_real_set_root(cam.root), 1)
            cam.call_real_open_item(cam.items()[0])
            return cam

        def assert_no_durable_io(cam, dest):
            protected = {dest, dest + ".tmp"}
            self.assertTrue(protected.isdisjoint(path for path, _ in cam.open_events))
            self.assertTrue(protected.isdisjoint(cam.rename_unlink_paths))

        def fail_count_readback(cam, original):
            cam.fail_fstat_once_paths.add(cfg)
            cam.call_real_open_item(cam.items()[2])
            self.assertFalse(cam.fail_fstat_once_paths)
            self.assertEqual(cam.files_at_failed_fstat[cfg], on8)
            if original:
                self.assertEqual(cam.files_at_failed_fstat[original], on8)
                self.assertEqual(cam.files[original], on5)
                self.assertEqual(cam.runtime_at_fsync, [on5, on8])
            self.check_menu(cam, "ON!", "5")
            self.assertEqual(cam.files[cfg], on8)

        for original, alternate in ((setting, sim), (sim, setting)):
            for follow_gate in (None, alternate, original):
                for row, record, status, frames in ((1, off5, "OFF", "5"), (2, on8, "ON", "8")):
                    with self.subTest(original=original, gate=follow_gate, action=status):
                        cam = open_menu(original)
                        fail_count_readback(cam, original)
                        assert_no_durable_io(cam, alternate)
                        cam.open_events.clear()
                        cam.rename_unlink_paths.clear()
                        set_gate(cam, follow_gate)
                        cam.call_real_open_item(cam.items()[row])
                        self.check_menu(cam, status if follow_gate == original else status + "!", frames)
                        self.assertEqual(cam.files[cfg], record)
                        for dest, before in ((original, on5), (alternate, off2)):
                            self.assertEqual(cam.files[dest], record if dest == follow_gate else before)
                            if dest != follow_gate:
                                assert_no_durable_io(cam, dest)

        def clear_trace(cam):
            cam.open_events.clear()
            cam.rename_unlink_paths.clear()
            cam.fsync_calls.clear()

        def disarm_case(original, alternate, mode, fault, retry):
            ram = mode == "ram"
            boot = mode == "boot-withdrawn"
            cam = open_menu(None if ram else original, on5 if boot else off5)
            if not boot:
                cam.call_real_open_item(cam.items()[1])
            self.check_menu(cam, "ON", "5")
            self.assertEqual(cam.files[cfg], on5)
            self.assertEqual(cam.files[original], off2 if ram else on5)
            if mode in ("removed", "boot-withdrawn"):
                set_gate(cam, None)
            elif mode == "retargeted":
                set_gate(cam, alternate)
            elif mode == "fifo":
                cam.fifo_paths.add(gate)
            elif mode == "malformed":
                cam.files[gate] += b"\0invalid"
            elif mode in ("withdraw-during", "retarget-during"):
                cam.gate_change = lambda: set_gate(cam, alternate if mode == "retarget-during" else None)

            clear_trace(cam)
            if fault is not None:
                if fault == "writer":
                    cam.fail_rename_dsts.add(cfg)
                    cam.fail_unlink_paths.add(cfg)
                else:
                    cam.fault_nr = fault
                cam.call_real_open_item(cam.items()[1])
                self.assertIsNone(cam.fault_nr)
                self.assertTrue(any(line.startswith("disarm_fail ") for line in cam.log))
                self.assertEqual(cam.files[cfg], on5 if fault == "writer" else off5)
                self.check_menu(cam, "ON!", "5")
                for dest in (original, alternate):
                    assert_no_durable_io(cam, dest)
                self.assertEqual(cam.fsync_calls, [])
                self.assertEqual(any(path == gate for path, _ in cam.open_events), ram)
                self.assertEqual(cam.files[original], off2 if ram else on5)
                self.assertEqual(cam.files[alternate], off2)
                cam.fail_rename_dsts.clear()
                cam.fail_unlink_paths.clear()
                cam.fifo_paths.discard(gate)
                set_gate(cam, retry)
                clear_trace(cam)

            cam.call_real_open_item(cam.items()[1])
            clean = ram or retry == original
            self.check_menu(cam, "OFF" if clean else "OFF!", "5")
            self.assertEqual(cam.files[cfg], off5)
            for dest, before in ((original, off2 if ram else on5), (alternate, off2)):
                self.assertEqual(cam.files[dest], off5 if dest == retry else before)
                if dest != retry:
                    assert_no_durable_io(cam, dest)
            if not clean:
                set_gate(cam, original)
                clear_trace(cam)
                cam.call_real_open_item(cam.items()[2])
                self.check_menu(cam, "OFF", "8")
                self.assertEqual(cam.files[cfg], b"S7PC1 0 8\n")
                self.assertEqual(cam.files[original], cam.files[cfg])
                assert_no_durable_io(cam, alternate)

        for original, alternate in ((setting, sim), (sim, setting)):
            all_faults = ("writer", 5, 197, 3, 6)  # rename+unlink, open, fstat64, read, close
            retries = (None, alternate, original)
            for mode, faults, gates in (
                ("valid", all_faults, retries),
                ("fifo", all_faults, retries),
                ("malformed", all_faults, retries),
                ("removed", all_faults, retries),
                ("withdraw-during", (197,), retries),
                ("retarget-during", (197,), retries),
                ("ram", all_faults, (None,)),
                ("boot-withdrawn", (197,), retries),
                ("removed", (None,), (None,)),
                ("retargeted", (None,), (alternate,)),
            ):
                for fault in faults:
                    for retry in gates:
                        with self.subTest(original=original, mode=mode, fault=fault, retry=retry):
                            disarm_case(original, alternate, mode, fault, retry)

        cam = open_menu(None)
        fail_count_readback(cam, None)
        cam.call_real_open_item(cam.items()[1])
        self.check_menu(cam, "OFF", "5")
        self.assertEqual(cam.files[cfg], off5)
        assert_no_durable_io(cam, setting)
        assert_no_durable_io(cam, sim)


if __name__ == "__main__":
    unittest.main(verbosity=2)
