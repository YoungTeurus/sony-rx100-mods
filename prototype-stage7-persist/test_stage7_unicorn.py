"""Offline tests of the sealed settings module and the freestanding config reader."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_INTR
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R7, UC_ARM_REG_SP)

import build_precap_mod as build

CFG = "/tmp_network/mlv2/precap.cfg"
TMP = CFG + ".tmp"


class Machine:
    """Each open descriptor holds one file generation, as for a tmpfs rename."""
    def __init__(self, code, base):
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.base = base
        self.cpu.mem_map(base, 0x1000)
        self.cpu.mem_write(base, code)
        self.cpu.mem_map(0x20000, 0x2000)
        self.cpu.hook_add(UC_HOOK_INTR, self.syscall)
        self.files = {}
        self.fifos = set()
        self.failure = None
        self.fd = None
        self.renames = []

    def path(self, address):
        return bytes(self.cpu.mem_read(address, 64)).split(b"\0")[0].decode()

    def syscall(self, cpu, interrupt, _):
        assert interrupt == 2
        nr, a, b, c = [cpu.reg_read(reg) for reg in
                       (UC_ARM_REG_R7, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        rc = 0
        if nr in (5, 10, 38):
            path = self.path(a)
            assert path in (CFG, TMP)
        if nr == self.failure:
            if nr == 6:
                self.fd = None
            rc = -5
        elif nr == 5:
            assert self.fd is None
            if path == TMP:
                assert b == 0o301 and c == 0o600 and path not in self.files
                self.files[path] = bytearray()
            else:
                assert b == 0o104000 and c == 0
            if path in self.files:
                self.fd = (path, 0)
                rc = 3
            else:
                rc = -2
        elif nr in (3, 4):
            assert a == 3 and self.fd is not None
            path, pos = self.fd
            if nr == 4:
                assert path == TMP
                rc = min(c, 2)  # force short writes
                self.files[path].extend(cpu.mem_read(b, rc))
            else:
                assert path == CFG
                part = self.files[path][pos:pos + min(c, 2)]
                if part:
                    cpu.mem_write(b, bytes(part))
                rc = len(part)
            self.fd = (path, pos + rc)
        elif nr == 6:
            assert a == 3 and self.fd is not None
            self.fd = None
        elif nr == 10:
            rc = 0 if self.files.pop(path, None) is not None else -2
        elif nr == 38:
            assert path == TMP and self.path(b) == CFG and self.fd is None
            self.files[CFG] = self.files.pop(TMP)
            self.renames.append(bytes(self.files[CFG]))
        elif nr == 197:
            assert a == 3 and self.fd is not None
            path, _ = self.fd
            st = bytearray(104)
            mode = 0o010600 if path in self.fifos else 0o100600
            struct.pack_into("<I", st, 16, mode)
            cpu.mem_write(b, bytes(st))
            rc = 0
        else:
            raise AssertionError(f"Unexpected syscall {nr}")
        cpu.reg_write(UC_ARM_REG_R0, rc & 0xffffffff)

    def call(self, entry, reason=0):
        self.cpu.reg_write(UC_ARM_REG_R0, reason)
        self.cpu.reg_write(UC_ARM_REG_LR, 0x20001)
        self.cpu.reg_write(UC_ARM_REG_SP, 0x22000)
        self.cpu.emu_start(self.base + entry, 0x20000, count=10000)
        assert self.cpu.reg_read(UC_ARM_REG_PC) == 0x20000
        return self.cpu.reg_read(UC_ARM_REG_R0)


class SettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        image = build.verify_seal()
        magic, version, flags, name, size, checksum, bss, on, off, hooks = struct.unpack_from(
            "<4sII32s6I", image)
        assert (magic, version, flags, name.rstrip(b"\0"), bss, hooks) == (
            b"SMOD", 2, 32, b"Pre-Capture", 1, 0)
        cls.code = image[68:68 + size]
        assert build.fnv(cls.code) == checksum
        trailer = image[68 + size:]
        magic, count, cfg, reserved, edit = struct.unpack_from("<4sBBHI", trailer)
        assert (magic, count, cfg, reserved) == (b"SMNU", 1, 0, 0)
        assert len(trailer) == 152 and build.fnv(trailer[:-4]) == struct.unpack_from("<I", trailer, 148)[0]
        options, cls.default, label, *values = struct.unpack_from("<BB2x24s" + "18s" * 6, trailer, 12)
        cls.frames = [s.rstrip(b"\0").decode() for s in values]
        assert (options, cls.default, label.rstrip(b"\0"), cls.frames) == (
            6, 3, b"Pre-Frames", ["1", "2", "3", "5", "8", "10"])
        cls.callbacks = (off, on, edit)
        with tempfile.TemporaryDirectory(dir=build.HERE) as tmp:
            source = Path(tmp) / "reader.c"
            source.write_text('#include "stage7_common.h"\nunsigned read_cfg(void) { return s7_pre_frames(); }\n')
            cls.reader, cls.read_entry = build.compile_thumb(source, "read_cfg", Path(tmp))

    def test_lifecycle(self):
        for base in (0x300000, 0x5a11000):
            machine = Machine(self.code, base)
            index = self.default
            for reason in (1, 2, 2, 2, 2, 2, 2, 0):
                if reason == 2:
                    index = (index + 1) % 6
                machine.cpu.mem_write(base + len(self.code), bytes([index]))
                machine.call(self.callbacks[reason], reason)
                record = f"S7PC1 {int(reason != 0)} {self.frames[index]}\n".encode()
                self.assertEqual(machine.files, {CFG: record})
                self.assertEqual(machine.renames[-1], record)
            self.assertEqual(len(machine.renames), 8)

    def test_failed_disable_discards_old_enabled_record(self):
        for syscall in (5, 4, 6, 38):
            machine = Machine(self.code, 0x300000)
            machine.files[CFG] = b"S7PC1 1 5\n"
            machine.failure = syscall
            machine.call(self.callbacks[0], 0)
            self.assertEqual(machine.files, {})

    def test_failed_on_edit_preserves_old_enabled_record(self):
        for syscall in (5, 4, 6, 38):
            machine = Machine(self.code, 0x300000)
            machine.files[CFG] = b"S7PC1 1 5\n"
            machine.cpu.mem_write(machine.base + len(self.code), bytes([4]))  # index 4 -> 8 frames
            machine.failure = syscall
            machine.call(self.callbacks[2], 2)
            self.assertEqual(machine.files, {CFG: b"S7PC1 1 5\n"})

    def test_invalid_option_disables(self):
        machine = Machine(self.code, 0x300000)
        machine.cpu.mem_write(machine.base + len(self.code), b"\xff")
        machine.call(self.callbacks[2], 2)
        self.assertEqual(machine.files, {CFG: b"S7PC1 0 5\n"})

    def test_poll_reads_exactly_one_record(self):
        machine = Machine(self.reader, 0x710000)
        self.assertEqual(machine.call(self.read_entry), 0)
        for value in self.frames:
            for enabled in (0, 1):
                machine.files[CFG] = f"S7PC1 {enabled} {value}\n".encode()
                self.assertEqual(machine.call(self.read_entry), enabled * int(value))
        for data in (b"", b"S7PC0 1 5\n", b"S7PC1 2 5\n", b"S7PC1 1 0\n",
                     b"S7PC1 1 4\n", b"S7PC1 1 05\n", b"S7PC1 1 11\n", b"S7PC1 1 5",
                     b"S7PC1 1 5\n\x00", b"S7PC1 1 10\nextra", b"S7PC1 1 5\n" * 2):
            machine.files[CFG] = data
            self.assertEqual(machine.call(self.read_entry), 0, data)
        machine.files[CFG] = b"S7PC1 1 5\n"
        machine.fifos.add(CFG)
        self.assertEqual(machine.call(self.read_entry), 0)
        machine.fifos.clear()
        for syscall in (5, 3, 6, 197):
            machine.failure = syscall
            self.assertEqual(machine.call(self.read_entry), 0)

    def test_stage6_seals(self):
        sys.path.insert(0, str(build.ROOT / "prototype-stage6-autonomy"))
        import build_stage6
        import build_stage6_v2
        build_stage6.verify_seal()
        build_stage6_v2.verify_seal()


if __name__ == "__main__":
    unittest.main(verbosity=2)
