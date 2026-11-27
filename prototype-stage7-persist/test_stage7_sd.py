"""Offline tests for Stage 7.3 Phase A: reader/extractor, seal, mlv2_sd_boot.sh, and Phase A probe."""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm_const import (
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R7,
    UC_ARM_REG_SP,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts"))

import build_stage7_sd as build  # noqa: E402
import m7_stage7_sd_probe as probe_cli  # noqa: E402
import m7_terminal_repaint as terminal  # noqa: E402
import stage7_ram_runner as ram  # noqa: E402

VERSION = b"29110_03.2021050601"
KEY = bytes(range(32))
MEMBERS = ("guard", "mlv2.req", "core.bin", "PreCapture.mod", "daemon", "ring.elf")


def archive(names=MEMBERS, large=False, typ=None):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for i, name in enumerate(names):
            info = tarfile.TarInfo(name)
            data = (b"fixture data\n" * 10500) if large and i == 0 else b"inert fixture\n"
            info.size = len(data)
            if typ and i == 0:
                info.type = typ
                info.linkname = "untrusted"
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def envelope(tar, seq=1, key=KEY):
    prefix = struct.pack(
        "<8s24sII24x32s", b"M7SD1", VERSION, seq, len(tar), hashlib.sha256(tar).digest()
    )
    return prefix + hmac.digest(key, prefix, "sha256") + tar


def exset(name, first, size, *, valid=None, contiguous=True):
    group = bytearray(96)
    group[:2] = b"\x85\x02"
    group[32:36] = bytes([0xC0, 3 if contiguous else 1, 0, len(name)])
    struct.pack_into("<Q", group, 40, size if valid is None else valid)
    struct.pack_into("<IQ", group, 52, first, size)
    group[64] = 0xC1
    group[66 : 66 + 2 * len(name)] = name.encode("utf-16-le")
    check = 0
    for i, b in enumerate(group):
        if i not in (2, 3):
            check = (((check >> 1) | (check << 15)) + b) & 65535
    struct.pack_into("<H", group, 2, check)
    return group


def fatname(name, first, size):
    base, _, ext = name.upper().partition(".")
    entry = bytearray(32)
    entry[:11] = (base[:8].ljust(8) + ext.ljust(3)).encode()
    entry[11] = 32
    struct.pack_into("<H", entry, 20, first >> 16)
    struct.pack_into("<HI", entry, 26, first & 65535, size)
    if name.lower() != "disable_hook":
        return entry
    entry[:11] = b"DISABL~1   "
    lfn = bytearray(32)
    lfn[0], lfn[11] = 0x41, 15
    for b in entry[:11]:
        lfn[13] = (((lfn[13] >> 1) | (lfn[13] << 7)) + b) & 255
    units = [ord(c) for c in name] + [0, 65535]
    for off, code in zip((1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30), units):
        struct.pack_into("<H", lfn, off, code)
    return lfn + entry


class Image:
    def __init__(
        self, path, raw, *, fat=False, fragmented=False, root_far=False, names=("mLv2.TaR",), valid=None
    ):
        self.path = path
        self.spc = 1 if fat else 256
        self.fat = 32 if fat else 24
        fat_len = 1024 if fat else 8192
        self.heap = self.fat + fat_len
        clusters = 100000 if fat else 976560
        sectors = self.heap + clusters * self.spc
        self.first = 500 if fat else 40000
        self.chain = []
        b = bytearray(512)
        b[510:] = b"\x55\xaa"
        if fat:
            struct.pack_into("<HBHB", b, 11, 512, self.spc, self.fat, 1)
            struct.pack_into("<II", b, 32, sectors, fat_len)
            struct.pack_into("<I", b, 44, 2)
        else:
            b[3:11] = b"EXFAT   "
            struct.pack_into("<QIIIII", b, 72, sectors, self.fat, fat_len, self.heap, clusters, 2)
            b[108:111] = bytes([9, 8, 1])
        with path.open("wb") as file:
            def put(off, data):
                file.seek(off)
                file.write(data)

            put(0, b)
            if root_far:
                cell = (b"\xe5" if fat else b"\x05") + bytes(31)
                put(self.at(2), cell * (257 * 16))
                for c in range(2, 2 + 257 // self.spc):
                    put(self.fat * 512 + 4 * c, struct.pack("<I", c + 1))
            entries = b"".join(
                fatname(n, self.first, len(raw))
                if fat
                else exset(n, self.first, len(raw), valid=valid, contiguous=not fragmented)
                for n in names
            )
            put(self.at(2) + (257 * 512 if root_far else 0), entries + bytes(32))
            span = self.spc * 512
            for i in range((len(raw) + span - 1) // span):
                self.chain.append(self.first + i * (7 if fragmented else 1))
            for i, c in enumerate(self.chain):
                put(self.at(c), raw[i * span : (i + 1) * span])
                target = self.chain[i + 1] if i + 1 < len(self.chain) else 0xFFFFFFFF
                put(self.fat * 512 + c * 4, struct.pack("<I", target))
            file.truncate(sectors * 512)

    def at(self, cluster):
        return (self.heap + (cluster - 2) * self.spc) * 512

    def patch(self, offset, data):
        with self.path.open("r+b") as f:
            f.seek(offset)
            f.write(data)


class Emulated:
    """Model the reader's 11 ARM syscalls; enforce zero write/unlink/rename in read-only modes."""

    def __init__(
        self,
        binary,
        path,
        args,
        key,
        version,
        *,
        fault=None,
        allow_extract=False,
        free_blocks=(1 << 25) + 5,
        total_blocks=1 << 27,
        pre_files=None,
    ):
        self.calls, self.seeks, self.stdout, self.rc = set(), [], bytearray(), None
        self.vfiles: dict[str, bytearray] = {k: bytearray(v) for k, v in (pre_files or {}).items()}
        u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        elf = ELFFile(io.BytesIO(binary))
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            va, n = segment["p_vaddr"], segment["p_memsz"]
            lo = va & -4096
            hi = (va + n + 4095) & -4096
            for page in range(lo, hi, 4096):
                if not any(start <= page <= end for start, end, _ in u.mem_regions()):
                    u.mem_map(page, 4096)
            u.mem_write(va, segment.data())
        u.mem_map(0x70000000, 0x40000)
        sp = 0x70020000
        addr = sp + 2048
        argv = []
        for a in ["reader", *args]:
            argv.append(addr)
            z = a.encode() + b"\0"
            u.mem_write(addr, z)
            addr += len(z)
        u.mem_write(sp, struct.pack("<" + "I" * (len(argv) + 2), len(argv), *argv, 0))
        u.reg_write(UC_ARM_REG_SP, sp)

        def cstr(addr):
            return bytes(u.mem_read(addr, 256)).split(b"\0")[0].decode()

        resources = {"/dev/mmca1": path.open("rb"), "key": io.BytesIO(key), "ver": io.BytesIO(version)}
        fds = {}
        once = set()

        def intr(machine, event, userdata):
            nr = u.reg_read(UC_ARM_REG_R7)
            self.calls.add(nr)
            a, b, c, d, e = [
                u.reg_read(x)
                for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4)
            ]
            result = 0
            if nr == 1:
                self.rc = a
                u.emu_stop()
            elif nr == 104:
                assert a == 0 and c == 0 and bytes(u.mem_read(b, 16)) == struct.pack("<4I", 0, 0, 8, 0)
                if fault == "timer":
                    result = -22
            elif nr == 5:
                name = cstr(a)
                if b == (0o100000 | 0o4000):
                    assert c == 0
                    if name in resources:
                        fd = 3 + len(fds)
                        while fd in fds:
                            fd += 1
                        fds[fd] = ("ro", resources[name], name)
                        result = fd
                    else:
                        result = -2
                elif b == 0o40000 and name == "/":
                    assert allow_extract and c == 0
                    fd = 3 + len(fds)
                    while fd in fds:
                        fd += 1
                    fds[fd] = ("dir", None, "/")
                    result = fd
                else:
                    raise AssertionError(f"Unexpected open flags {oct(b)} on {name}")
            elif nr == 322:  # openat(dirfd, name, flags, mode)
                assert allow_extract
                pkind, _, ppath = fds[a]
                assert pkind == "dir"
                leaf = cstr(b)
                full_path = f"/{leaf}" if ppath == "/" else f"{ppath}/{leaf}"
                if c == (0o40000 | 0o100000):
                    assert d == 0
                    if fault == "stage_symlink" and full_path == "/tmp_network/mlv2":
                        result = -40
                    elif fault == "intermediate_symlink" and leaf == "alias":
                        result = -40
                    else:
                        fd = 3 + len(fds)
                        while fd in fds:
                            fd += 1
                        fds[fd] = ("dir", None, full_path)
                        result = fd
                elif c == (1 | 0o100 | 0o200 | 0o100000):
                    assert d == 0o600
                    if full_path in self.vfiles:
                        result = -17
                    elif fault == "open_out":
                        result = -28
                    else:
                        self.vfiles[full_path] = bytearray()
                        fd = 3 + len(fds)
                        while fd in fds:
                            fd += 1
                        fds[fd] = ("wo", full_path, full_path)
                        result = fd
                else:
                    raise AssertionError(f"Unexpected openat flags {oct(c)} on {full_path}")
            elif nr == 197:
                kind, _, fname = fds[a]
                st = bytearray(104)
                if kind == "dir":
                    mode = 0o040755
                    rdev = 0
                elif fname == "/dev/mmca1":
                    mode = 0o100644 if fault == "mode" else 0o60600
                    rdev = 0xFA0C if fault == "rdev" else 0xFA0B
                else:
                    mode = 0o010600 if fault == "key_fifo" else 0o100600
                    rdev = 0
                struct.pack_into("<I", st, 16, mode)
                struct.pack_into("<Q", st, 32, rdev)
                u.mem_write(b, bytes(st))
            elif nr == 140:
                assert e == 0
                pos = (b << 32) | c
                self.seeks.append(pos)
                assert fds[a][0] == "ro"
                fds[a][1].seek(pos)
                u.mem_write(d, struct.pack("<Q", pos))
            elif nr == 3:
                if fault == "eio":
                    result = -5
                elif fault == "partial" and nr not in once:
                    once.add(nr)
                    result = -4
                else:
                    assert fds[a][0] == "ro"
                    part = fds[a][1].read(min(c, 77) if fault == "partial" else c)
                    u.mem_write(b, part)
                    result = len(part)
            elif nr == 4:
                if a == 1:
                    if fault == "partial" and nr not in once:
                        once.add(nr)
                        result = -4
                    else:
                        result = min(c, 3) if fault == "partial" else c
                        self.stdout.extend(u.mem_read(b, result))
                else:
                    assert allow_extract and fds[a][0] == "wo"
                    if fault == "write_out":
                        result = -28
                    elif fault == "partial" and ("wo", a) not in once:
                        once.add(("wo", a))
                        result = -4
                    else:
                        n = min(c, 111) if fault == "partial" else c
                        self.vfiles[fds[a][1]].extend(u.mem_read(b, n))
                        result = n
            elif nr == 328:  # unlinkat(dirfd, name, flag)
                assert allow_extract and c == 0
                pkind, _, ppath = fds[a]
                assert pkind == "dir"
                name = f"{ppath}/{cstr(b)}"
                result = 0 if self.vfiles.pop(name, None) is not None else -2
            elif nr == 329:  # renameat(olddir, oldn, newdir, newn)
                assert allow_extract
                okind, _, opath = fds[a]
                nkind, _, npath = fds[c]
                assert okind == "dir" and nkind == "dir" and a == c
                old, neu = f"{opath}/{cstr(b)}", f"{npath}/{cstr(d)}"
                if fault == "rename_out":
                    result = -5
                else:
                    assert old in self.vfiles
                    self.vfiles[neu] = self.vfiles.pop(old)
                    result = 0
            elif nr == 266:
                assert cstr(a) == "ram" and b == 84
                if fault == "statfs":
                    result = -22
                else:
                    buf = bytearray(84)
                    avail = min(free_blocks, max(0, free_blocks - 2)) if free_blocks > 2 else free_blocks
                    fstype = 0x4D44 if fault == "non_tmpfs" else 0x1021994
                    struct.pack_into("<IIQQQ", buf, 0, fstype, 4096, total_blocks, free_blocks, avail)
                    u.mem_write(c, bytes(buf))
            elif nr == 267:  # fstatfs64(fd, sz, buf)
                assert allow_extract and b == 84
                pkind, _, ppath = fds[a]
                assert pkind == "dir" and ppath.startswith("/tmp_network/")
                if fault == "statfs":
                    result = -22
                else:
                    buf = bytearray(84)
                    avail = min(free_blocks, max(0, free_blocks - 2)) if free_blocks > 2 else free_blocks
                    fstype = 0x4D44 if fault == "non_tmpfs" else 0x1021994
                    struct.pack_into("<IIQQQ", buf, 0, fstype, 4096, total_blocks, free_blocks, avail)
                    u.mem_write(c, bytes(buf))
            elif nr == 6:
                kind, _, fname = fds.pop(a)
                if fault == "close_out" and kind == "wo":
                    result = -5
                elif fault == "close_card" and fname == "/dev/mmca1":
                    result = -5
            else:
                raise AssertionError(f"Unexpected syscall {nr}")
            u.reg_write(UC_ARM_REG_R0, result & 0xFFFFFFFF)

        u.hook_add(UC_HOOK_INTR, intr)
        try:
            u.emu_start(elf["e_entry"], 0, timeout=15_000_000)
            if self.rc is None:
                raise AssertionError("Emulator deadline or premature return")
            if fds:
                raise AssertionError(f"Open descriptors at exit: {fds}")
        finally:
            for f in resources.values():
                f.close()


class CardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.dir = Path(cls.tmp.name)
        cls.host = cls.dir / "reader-host"
        subprocess.run(
            ["clang", "-DMLV2_HOST_TEST=1", "-O2", "-Wall", "-Wextra", "-Werror", build.SOURCE, "-o", cls.host],
            check=True,
        )
        cls.binary = build.build_once()
        cls.path = cls.dir / "card.img"

    def check(self, mode, valid, *, key=KEY, version=VERSION):
        if mode == "--probe":
            hargs = [mode, "--ram-path", str(self.dir)]
            args = [mode, "--ram-path", "ram"]
        else:
            (self.dir / "key").write_bytes(key)
            (self.dir / "ver").write_bytes(version)
            args = [mode, "--key", "key", "--version-file", "ver"]
            hargs = args
        host = subprocess.run(
            [self.host, *hargs],
            cwd=self.dir,
            capture_output=True,
            timeout=10,
            env={**os.environ, "MLV2_CARD_READ_IMAGE": str(self.path)},
        )
        arm = Emulated(self.binary, self.path, args, key, version, allow_extract=False)
        self.assertEqual(host.returncode == 0, valid, (hargs, host))
        self.assertEqual(arm.rc == 0, valid, (args, arm.rc, arm.stdout))
        for write_slot in (10, 38, 322, 328, 329):
            self.assertNotIn(write_slot, arm.calls)
        return host.stdout, arm

    def test_build_and_kernel_census(self):
        self.assertEqual(set(build.kernel_slots()), set(build.SLOTS) | {118})
        self.assertEqual(self.binary, build.build_once())
        self.assertEqual(self.binary, (build.OUT_SD / "mlv2_card_read.elf").read_bytes())

    def test_phase_a_release_seal(self):
        manifest = build.verify_seal()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name in ("mlv2_card_read.elf", "mlv2_sd_boot.sh", "card.ustar", "build-sd.json"):
                shutil.copy2(build.OUT_SD / name, directory / name)
            self.assertEqual(build.verify_seal(directory), manifest)

            # Mutate reader binary -> fails manifest check
            altered = self.binary + b"changed"
            (directory / "mlv2_card_read.elf").write_bytes(altered)
            with self.assertRaisesRegex(ValueError, "manifest mismatch"):
                build.verify_seal(directory)
            # Recompute manifest for altered reader -> fails clean rebuild check
            _, mmeta = build.build_card_ustar()
            bad_m = build.build_manifest(
                altered, (directory / "mlv2_sd_boot.sh").read_bytes(), (directory / "card.ustar").read_bytes(), mmeta
            )
            (directory / "build-sd.json").write_text(json.dumps(bad_m))
            with self.assertRaisesRegex(ValueError, "differs from a clean build"):
                build.verify_seal(directory)

    def test_high_offsets_root_and_fragmentation(self):
        for fat, fragmented in ((True, True), (False, False), (False, True)):
            with self.subTest(fat=fat, fragmented=fragmented):
                tar = archive(large=not fat)
                raw = envelope(tar)
                image = Image(self.path, raw, fat=fat, fragmented=fragmented, root_far=True)
                stdout, arm = self.check("--probe", True)
                for data in (stdout, arm.stdout):
                    self.assertIn(b"MLV2_FOUND=1\n", data)
                    self.assertIn(f"MLV2_BYTES={len(raw)}\n".encode(), data)
                    self.assertIn(b"DISABLE_MARKERS=0\n", data)
                    self.assertIn(b"FS_TYPE=" + (b"FAT32" if fat else b"exFAT"), data)
                self.assertIn(b"free_bytes=137438973952 total_bytes=549755813888", arm.stdout)
                self.check("--present", True)
                _, arm = self.check("--verify", True)
                if not fat:
                    self.assertGreater(image.at(image.first), 2**32)
                    self.assertIn(image.at(image.chain[1]), arm.seeks)

                # Also verify --extract produces byte-identical card.tar in BOTH host and ARM32 Unicorn!
                stage_host = (self.dir / f"stage-{fat}-{fragmented}").resolve()
                stage_host.mkdir(exist_ok=True)
                (self.dir / "key").write_bytes(KEY)
                (self.dir / "ver").write_bytes(VERSION)
                res = subprocess.run(
                    [self.host, "--extract", "--stage", str(stage_host), "--key", "key", "--version-file", "ver"],
                    cwd=self.dir,
                    capture_output=True,
                    timeout=10,
                    env={**os.environ, "MLV2_CARD_READ_IMAGE": str(self.path)},
                )
                self.assertEqual(res.returncode, 0, res)
                self.assertEqual((stage_host / "card.tar").read_bytes(), tar)
                self.assertFalse((stage_host / "card.tar.tmp").exists())

                arm_ext = Emulated(
                    self.binary,
                    self.path,
                    ["--extract", "--stage", "/tmp_network/mlv2", "--key", "key", "--version-file", "ver"],
                    KEY,
                    VERSION,
                    allow_extract=True,
                    pre_files={"/tmp_network/mlv2/card.tar.tmp": b"stale junk"},
                )
                self.assertEqual(arm_ext.rc, 0)
                self.assertEqual(bytes(arm_ext.vfiles["/tmp_network/mlv2/card.tar"]), tar)
                self.assertNotIn("/tmp_network/mlv2/card.tar.tmp", arm_ext.vfiles)
                self.assertEqual(arm_ext.calls, set(build.SLOTS) - {266})

    def test_extract_refusals_and_atomic_cleanup(self):
        tar = archive()
        raw = envelope(tar)
        Image(self.path, raw)

        # Insufficient RAM headroom (< tar_bytes + 64 KiB) -> refuses cleanly, creates zero files!
        arm_low = Emulated(
            self.binary,
            self.path,
            ["--extract", "--stage", "/tmp_network/mlv2", "--key", "key", "--version-file", "ver"],
            KEY,
            VERSION,
            allow_extract=True,
            free_blocks=8,  # 32 KiB free < tar + 64 KiB
            total_blocks=256,
        )
        self.assertNotEqual(arm_low.rc, 0)
        self.assertEqual(arm_low.vfiles, {})

        # Non-tmpfs / non-/tmp_network / traversal / symlink stage paths -> refused BEFORE creating any file!
        for bad_stage in ("/setting", "/tmp/mlv2", "/tmp_network/../setting", "/tmp_network/mlv2/", "/tmp_network//mlv2"):
            with self.subTest(bad_stage=bad_stage):
                arm_bs = Emulated(
                    self.binary,
                    self.path,
                    ["--extract", "--stage", bad_stage, "--key", "key", "--version-file", "ver"],
                    KEY,
                    VERSION,
                    allow_extract=True,
                )
                self.assertNotEqual(arm_bs.rc, 0)
                self.assertEqual(arm_bs.vfiles, {})
        for bad_fault, stage_arg in (
            ("non_tmpfs", "/tmp_network/mlv2"),
            ("stage_symlink", "/tmp_network/mlv2"),
            ("intermediate_symlink", "/tmp_network/alias/mlv2"),
            ("key_fifo", "/tmp_network/mlv2"),
            ("close_card", "/tmp_network/mlv2"),
        ):
            with self.subTest(bad_fault=bad_fault):
                arm_bf = Emulated(
                    self.binary,
                    self.path,
                    ["--extract", "--stage", stage_arg, "--key", "key", "--version-file", "ver"],
                    KEY,
                    VERSION,
                    allow_extract=True,
                    fault=bad_fault,
                )
                self.assertNotEqual(arm_bf.rc, 0)
                self.assertEqual(arm_bf.vfiles, {})

        # Host binary MUST also reject an intermediate parent symlink via component-wise openat(..., O_NOFOLLOW)!
        outside = (self.dir / "outside_target").resolve()
        outside.mkdir(exist_ok=True)
        (outside / "stage").mkdir(exist_ok=True)
        alias_parent = self.dir.resolve() / "alias_parent"
        if alias_parent.exists() or alias_parent.is_symlink():
            alias_parent.unlink()
        alias_parent.symlink_to(outside)
        (self.dir / "key").write_bytes(KEY)
        (self.dir / "ver").write_bytes(VERSION)
        host_sym = subprocess.run(
            [self.host, "--extract", "--stage", str(alias_parent / "stage"), "--key", "key", "--version-file", "ver"],
            cwd=self.dir,
            capture_output=True,
            timeout=10,
            env={**os.environ, "MLV2_CARD_READ_IMAGE": str(self.path)},
        )
        self.assertNotEqual(host_sym.returncode, 0)
        self.assertFalse((outside / "stage" / "card.tar").exists())

        # Tampered payload -> verifies & unlinks card.tar.tmp, never creates card.tar!
        bad = bytearray(raw)
        bad[128 + 512] ^= 1
        Image(self.path, bytes(bad))
        arm_bad = Emulated(
            self.binary,
            self.path,
            ["--extract", "--stage", "/tmp_network/mlv2", "--key", "key", "--version-file", "ver"],
            KEY,
            VERSION,
            allow_extract=True,
        )
        self.assertNotEqual(arm_bad.rc, 0)
        self.assertEqual(arm_bad.vfiles, {})

        # Write / close / rename faults -> cleans up .tmp, never publishes partial card.tar!
        Image(self.path, raw)
        for fault in ("open_out", "write_out", "close_out", "rename_out"):
            with self.subTest(fault=fault):
                arm_f = Emulated(
                    self.binary,
                    self.path,
                    ["--extract", "--stage", "/tmp_network/mlv2", "--key", "key", "--version-file", "ver"],
                    KEY,
                    VERSION,
                    allow_extract=True,
                    fault=fault,
                )
                self.assertNotEqual(arm_f.rc, 0)
                self.assertEqual(arm_f.vfiles, {})

        # Partial write + EINTR still succeeds atomically!
        arm_p = Emulated(
            self.binary,
            self.path,
            ["--extract", "--stage", "/tmp_network/mlv2", "--key", "key", "--version-file", "ver"],
            KEY,
            VERSION,
            allow_extract=True,
            fault="partial",
        )
        self.assertEqual(arm_p.rc, 0)
        self.assertEqual(bytes(arm_p.vfiles["/tmp_network/mlv2/card.tar"]), tar)

    def test_directory_rejections(self):
        raw = envelope(archive())
        for fat in (True, False):
            for names in (
                (),
                ("mlv2.tar", "MLV2.TAR"),
                *(("mlv2.tar", n) for n in ("DiSaBlE_hOoK", "DiSaBlE.TxT", "MLV2.OFF")),
            ):
                with self.subTest(fat=fat, names=names):
                    Image(self.path, raw, fat=fat, names=names)
                    self.check("--present", False)
                    self.check("--verify", False)
                    stdout, _ = self.check("--probe", True)
                    self.assertIn(f"MLV2_FOUND={sum(n.lower() == 'mlv2.tar' for n in names)}\n".encode(), stdout)
                    mask = {"disable_hook": 1, "disable.txt": 2, "mlv2.off": 4}
                    self.assertIn(
                        f"DISABLE_MARKERS={sum(mask.get(n.lower(), 0) for n in names)}\n".encode(), stdout
                    )
        Image(self.path, raw, valid=len(raw) - 1)
        self.check("--present", False)

    def test_authenticated_header(self):
        raw = envelope(archive())
        for offset in (0, 8, 27, 32, 36, 40, 64, 96, 127):
            mutated = bytearray(raw)
            mutated[offset] ^= 1
            if offset < 96:
                mutated[96:128] = hmac.digest(KEY, mutated[:96], "sha256")
            with self.subTest(offset=offset):
                Image(self.path, mutated)
                self.check("--present", offset == 64)
                self.check("--verify", False)
        Image(self.path, raw)
        for key in (KEY[:-1], KEY + b"x", bytes(32)):
            self.check("--present", False, key=key)
        for version in (VERSION + b"\n", VERSION[:-1], b"x" * 19):
            self.check("--present", False, version=version)
        for size in (0, 511, 513, 384 * 1024 + 512):
            Image(self.path, envelope(b"x" * size))
            self.check("--present", False)

    def test_ustar_and_payload(self):
        tar = archive()
        vectors = [
            archive(MEMBERS[:-1]),
            archive(MEMBERS + ("extra",)),
            archive(MEMBERS + (MEMBERS[0],)),
            archive(("../guard", *MEMBERS[1:])),
            archive(("a/guard", *MEMBERS[1:])),
            archive(typ=tarfile.SYMTYPE),
            archive(typ=tarfile.LNKTYPE),
            tar[:6144],
            tar[:6656],
            tar[:-512] + b"X" + bytes(511),
        ]
        for offset in (148, 257, 512 + 14, 345, 156, 124):
            t = bytearray(tar)
            t[offset] = ord("X")
            if offset != 148:
                t[148:156] = b" " * 8
                t[148:156] = f"{sum(t[:512]):06o}\0 ".encode()
            vectors.append(t)
        for i, t in enumerate(vectors):
            with self.subTest(case=i):
                Image(self.path, envelope(t))
                self.check("--present", True)
                self.check("--verify", False)
        modified = bytearray(envelope(tar))
        modified[128 + 512] ^= 1
        Image(self.path, modified)
        self.check("--present", True)
        self.check("--verify", False)

    def test_bad_geometry_chains_and_root_limit(self):
        raw = envelope(archive(large=True))
        for chain_target in (0, 1, 0xFFFFFFF7, 0xFFFFFFFF, 40000):
            im = Image(self.path, raw, fragmented=True)
            im.patch(im.fat * 512 + 40000 * 4, struct.pack("<I", chain_target))
            self.check("--verify", False)
        for offset, data in (
            (108, b"\x0a"),
            (109, b"\x0d"),
            (110, b"\x00"),
            (510, b"\x00"),
            (96, bytes(4)),
            (84, struct.pack("<I", 1)),
        ):
            im = Image(self.path, raw)
            im.patch(offset, data)
            self.check("--probe", False)
        im = Image(self.path, raw)
        im.patch(im.at(2), (b"\x05" + bytes(31)) * (im.spc * 16))
        im.patch(im.fat * 512 + 8, struct.pack("<I", 2))
        self.check("--probe", False)
        im = Image(self.path, raw)
        im.patch(im.at(2) + 2, b"\x00\x00")
        self.check("--present", False)

    def test_root_sector_budget(self):
        raw = envelope(archive())
        for offset, accepted in ((4095, True), (4096, False)):
            im = Image(self.path, raw)
            im.patch(im.at(2), (b"\x05" + bytes(31)) * (16 * offset))
            for i in range(offset // im.spc):
                im.patch(im.fat * 512 + 4 * (i + 2), struct.pack("<I", i + 3))
            im.patch(im.at(2) + offset * 512, exset("MLV2.TAR", im.first, len(raw)) + bytes(32))
            self.check("--present", accepted)

    def test_host_refuses_symlink_or_missing_fixture(self):
        Image(self.path, envelope(archive()))
        link = self.dir / "linked-card"
        link.symlink_to(self.path)
        for img in ("", str(link), str(self.dir)):
            result = subprocess.run(
                [self.host, "--probe", "--ram-path", str(self.dir)],
                env={**os.environ, "MLV2_CARD_READ_IMAGE": img},
                capture_output=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_syscall_failures_and_short_io(self):
        Image(self.path, envelope(archive()))
        args = ["--probe", "--ram-path", "ram"]
        for fault in ("mode", "rdev", "timer", "eio", "statfs"):
            with self.subTest(fault=fault):
                arm = Emulated(self.binary, self.path, args, KEY, VERSION, fault=fault)
                self.assertNotEqual(arm.rc, 0)
        arm = Emulated(self.binary, self.path, args, KEY, VERSION, fault="partial")
        self.assertEqual(arm.rc, 0)
        self.assertEqual(arm.calls, set(build.READONLY_SLOTS))
        arm = Emulated(
            self.binary, self.path, ["--verify", "--key", "key", "--version-file", "ver"], KEY, VERSION, fault="partial"
        )
        self.assertEqual(arm.rc, 0)

    def test_real_sealed_card_ustar_accepted_by_arm_reader(self):
        ustar = (build.OUT_SD / "card.ustar").read_bytes()
        signed = build.sign_mlv2_tar(ustar, KEY, release_seq=7)
        Image(self.path, signed, fat=False, fragmented=True, root_far=True)
        arm = Emulated(
            self.binary,
            self.path,
            ["--extract", "--stage", "/tmp_network/mlv2", "--key", "key", "--version-file", "ver"],
            KEY,
            VERSION,
            allow_extract=True,
        )
        self.assertEqual(arm.rc, 0)
        self.assertEqual(bytes(arm.vfiles["/tmp_network/mlv2/card.tar"]), ustar)


class BootScriptTests(unittest.TestCase):
    """Test prototype-stage7-persist/mlv2_sd_boot.sh with real /bin/sh."""

    def _make_fake_tar(
        self,
        guard_mode: str = "stock",
        daemon_boot_line: str | None = "BOOT self_pid=4321 im_pid=161 im_st=105 pre_f=8",
        daemon_boot_no_nl: bool = False,
    ) -> bytes:
        guard_sh = (
            "#!/bin/sh\n"
            'if [ "$1" = check ]; then\n'
            + (
                '  echo "STATE hooks=stock rects=stock shim=zero"\n'
                if guard_mode == "stock"
                else '  echo "STATE hooks=patched rects=patched shim=loaded"\n'
            )
            + '  echo "MLV2_RESULT=0 changed=0"\n'
            "  exit 0\n"
            "fi\n"
            'if [ "$1" = install ]; then\n'
            '  echo "INSTALLED shim=15d63800..15d63e98 hooks=1,2,3"\n'
            '  echo "MLV2_RESULT=0 changed=1"\n'
            "  exit 0\n"
            "fi\n"
            "exit 1\n"
        ).encode("ascii")
        if daemon_boot_line is None:
            boot_emit = ""
        elif daemon_boot_no_nl:
            boot_emit = f'printf "%s" "{daemon_boot_line}" > "$dir/daemon.log"\n'
        else:
            boot_emit = f'echo "{daemon_boot_line}" > "$dir/daemon.log"\n'
        daemon_sh = (
            "#!/bin/sh\n"
            'dir=$(dirname "$0")\n'
            + boot_emit
            + 'echo 4321 > "$dir/daemon.pid"\n'
            "exit 0\n"
        ).encode("ascii")
        out = io.BytesIO()
        files = {
            "guard": guard_sh,
            "mlv2.req": b"REQ",
            "core.bin": b"CORE",
            "PreCapture.mod": b"MOD",
            "daemon": daemon_sh,
            "ring.elf": b"RING",
        }
        with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            for name, data in files.items():
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                ti.mode = 0o700
                tf.addfile(ti, io.BytesIO(data))
        return out.getvalue()

    def _run_boot(self, tmp: Path, *, persist_bytes: bytes | None, card_present: bool = True,
                  guard_mode: str = "stock", version_bytes: bytes = VERSION, keep_guard: int = 0,
                  daemon_alive: bool = True, daemon_state: str = "S", daemon_exe_override: str | None = None,
                  daemon_boot_line: str | None = "BOOT self_pid=4321 im_pid=161 im_st=105 pre_f=8",
                  daemon_boot_no_nl: bool = False,
                  mounts_text: str | None = None, stage_override: Path | None = None,
                  pre_stage_setup=None):
        ram_root = tmp / "ram"
        stage = stage_override if stage_override is not None else (ram_root / "mlv2")
        mods = ram_root / "mods"
        ddir = ram_root / ".m7-s7-5d0000000001"
        proc = tmp / "proc"
        im_proc = proc / "161"
        ram_root.mkdir(parents=True, exist_ok=True)
        im_proc.mkdir(parents=True, exist_ok=True)
        (im_proc / "stat").write_text("161 (im.elf) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 186 0 105 0 0\n")
        (im_proc / "exe").symlink_to("/usr/bin/im.elf")
        (im_proc / "maps").write_text(
            "153f1000-15d64000 r-xp 00000000 00:00 1 /usr/lib/viewUnified2.so\n"
            "04000000-04010000 r-xp 00000000 00:00 2 /usr/lib/libtestcmd.so\n"
        )
        if mounts_text is not None:
            (proc / "mounts").write_text(mounts_text)
        if daemon_alive:
            (proc / "4321").mkdir(parents=True, exist_ok=True)
            (proc / "4321" / "stat").write_text(f"4321 (daemon.elf) {daemon_state} 1\n")
            (proc / "4321" / "exe").symlink_to(daemon_exe_override or str(ddir / "daemon.elf"))
        if pre_stage_setup is not None:
            pre_stage_setup(ram_root, stage, mods, ddir)
        ver = tmp / "version.txt"
        ver.write_bytes(version_bytes)
        dev = tmp / "mmca1"
        dev.write_bytes(b"blk")
        key = tmp / "sd.key"
        key.write_bytes(KEY)
        persist = tmp / "persist.cfg"
        if persist_bytes is not None:
            persist.write_bytes(persist_bytes)
        tar_payload = tmp / "payload.tar"
        tar_payload.write_bytes(
            self._make_fake_tar(
                guard_mode=guard_mode,
                daemon_boot_line=daemon_boot_line,
                daemon_boot_no_nl=daemon_boot_no_nl,
            )
        )
        reader = tmp / "fake_reader.sh"
        reader.write_text(
            "#!/bin/sh\n"
            + (
                f'if [ "$1" = --extract ]; then cp "{tar_payload}" "$3/card.tar"; exit 0; fi\n'
                "exit 0\n"
                if card_present
                else "exit 1\n"
            )
        )
        reader.chmod(0o700)
        env = {
            **os.environ,
            "MLV2_BB": "",
            "MLV2_RAM": str(ram_root),
            "MLV2_STAGE": str(stage),
            "MLV2_MODS": str(mods),
            "MLV2_DAEMON_DIR": str(ddir),
            "MLV2_READER": str(reader),
            "MLV2_KEY": str(key),
            "MLV2_VERSION_FILE": str(ver),
            "MLV2_PERSIST_SRC": str(persist),
            "MLV2_PERSIST_GATE_VALUE": "/tmp_network/mlv2/sim-setting-precap.cfg",
            "MLV2_DEV": str(dev),
            "MLV2_PROC": str(proc),
            "MLV2_WAIT_MOUNT": "0",
            "MLV2_WAIT_IM": "1",
            "MLV2_WAIT_DAEMON": "3",
            "MLV2_CARD_TRIES": "0",
            "MLV2_ONCE": "1",
            "MLV2_KEEP_GUARD": str(keep_guard),
            "MLV2_SKIP_MOUNT_CHECK": "0" if mounts_text is not None else "1",
            "MLV2_SKIP_DEV_BLK_CHECK": "1",
        }
        res = subprocess.run(["/bin/sh", str(build.BOOT_SCRIPT)], env=env, capture_output=True, text=True, timeout=15)
        return res, stage, mods, ddir

    def test_applet_compliance(self):
        build.check_boot_script(build.BOOT_SCRIPT.read_bytes())

    def test_symlinked_mount_sources_leave_stage_untouched(self):
        for layout in ("proc-root", "global-mounts", "pid-mounts", "pid-mounts-fifo", "pid-mounts-dir"):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                proc = tmp / "proc"
                ram = tmp / "ram"
                stage = ram / "mlv2"
                stage.mkdir(parents=True)
                log = stage / "sd-boot.log"
                log.write_bytes(b"original\n")
                if layout == "proc-root":
                    proc.symlink_to(tmp / "real-proc")
                    proc.resolve().mkdir()
                else:
                    proc.mkdir()
                table = tmp / "table"
                table.write_text(f"none {ram} tmpfs rw 0 0\n")
                if layout in ("proc-root", "pid-mounts", "pid-mounts-fifo", "pid-mounts-dir"):
                    # Keep a valid regular $proc/mounts present so non-regular $proc/$$/mounts MUST NOT fall through!
                    (proc / "mounts").write_bytes(table.read_bytes())
                elif layout == "global-mounts":
                    (proc / "mounts").symlink_to(table)
                version = tmp / "version"
                version.write_bytes(VERSION)
                command = ["/bin/sh", str(build.BOOT_SCRIPT)]
                if layout == "pid-mounts":
                    command = [
                        "/bin/sh", "-ec",
                        'mkdir "$MLV2_PROC/$$"; ln -s "$1" "$MLV2_PROC/$$/mounts"; exec /bin/sh "$2"',
                        "fixture", str(table), str(build.BOOT_SCRIPT),
                    ]
                elif layout == "pid-mounts-fifo":
                    command = [
                        "/bin/sh", "-ec",
                        'mkdir "$MLV2_PROC/$$"; mkfifo "$MLV2_PROC/$$/mounts"; exec /bin/sh "$2"',
                        "fixture", str(table), str(build.BOOT_SCRIPT),
                    ]
                elif layout == "pid-mounts-dir":
                    command = [
                        "/bin/sh", "-ec",
                        'mkdir -p "$MLV2_PROC/$$/mounts"; exec /bin/sh "$2"',
                        "fixture", str(table), str(build.BOOT_SCRIPT),
                    ]
                env = {
                    "PATH": os.defpath, "MLV2_BB": "", "MLV2_PROC": str(proc),
                    "MLV2_RAM": str(ram), "MLV2_STAGE": str(stage),
                    "MLV2_MODS": str(ram / "mods"), "MLV2_DAEMON_DIR": str(ram / "daemon"),
                    "MLV2_VERSION_FILE": str(version), "MLV2_WAIT_MOUNT": "0", "MLV2_WAIT_IM": "0",
                    "MLV2_DEV": str(tmp / "absent-device"),
                }
                result = subprocess.run(command, env=env, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(list(stage.iterdir()), [log])
                self.assertEqual(log.read_bytes(), b"original\n")

    def test_real_linux_proc_pid_mounts_with_symlinked_proc_mounts(self):
        # On real Linux 2.6.x/3.x (including M7 1.00), /proc/mounts is a kernel symlink to self/mounts,
        # while /proc/$$/mounts is a real non-symlink regular file under non-symlink /proc/$$.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ram_root = tmp / "ram"
            stage = ram_root / "mlv2"
            mods = ram_root / "mods"
            ddir = ram_root / ".m7-s7-5d0000000001"
            proc = tmp / "proc"
            im_proc = proc / "161"
            ram_root.mkdir(parents=True)
            im_proc.mkdir(parents=True)
            (im_proc / "stat").write_text("161 (im.elf) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 186 0 105 0 0\n")
            (im_proc / "exe").symlink_to("/usr/bin/im.elf")
            (im_proc / "maps").write_text(
                "153f1000-15d64000 r-xp 00000000 00:00 1 /usr/lib/viewUnified2.so\n"
                "04000000-04010000 r-xp 00000000 00:00 2 /usr/lib/libtestcmd.so\n"
            )
            (proc / "4321").mkdir(parents=True)
            (proc / "4321" / "stat").write_text("4321 (daemon.elf) S 1\n")
            (proc / "4321" / "exe").symlink_to(str(ddir / "daemon.elf"))
            # Model real Linux /proc/mounts -> self/mounts symlink!
            (proc / "mounts").symlink_to("self/mounts")
            table = tmp / "mounts.txt"
            table.write_text(f"none {ram_root} tmpfs rw,sync,dirsync,noatime,size=1024k 0 0\n")
            ver = tmp / "version.txt"
            ver.write_bytes(VERSION)
            dev = tmp / "mmca1"
            dev.write_bytes(b"blk")
            key = tmp / "sd.key"
            key.write_bytes(KEY)
            persist = tmp / "persist.cfg"
            persist.write_bytes(b"S7PC1 1 8\n")
            tar_payload = tmp / "payload.tar"
            tar_payload.write_bytes(self._make_fake_tar())
            reader = tmp / "fake_reader.sh"
            reader.write_text(
                f'#!/bin/sh\nif [ "$1" = --extract ]; then cp "{tar_payload}" "$3/card.tar"; exit 0; fi\nexit 0\n'
            )
            reader.chmod(0o700)
            env = {
                **os.environ,
                "MLV2_BB": "",
                "MLV2_RAM": str(ram_root),
                "MLV2_STAGE": str(stage),
                "MLV2_MODS": str(mods),
                "MLV2_DAEMON_DIR": str(ddir),
                "MLV2_READER": str(reader),
                "MLV2_KEY": str(key),
                "MLV2_VERSION_FILE": str(ver),
                "MLV2_PERSIST_SRC": str(persist),
                "MLV2_PERSIST_GATE_VALUE": "/tmp_network/mlv2/sim-setting-precap.cfg",
                "MLV2_DEV": str(dev),
                "MLV2_PROC": str(proc),
                "MLV2_WAIT_MOUNT": "0",
                "MLV2_WAIT_IM": "1",
                "MLV2_WAIT_DAEMON": "3",
                "MLV2_CARD_TRIES": "0",
                "MLV2_ONCE": "1",
                "MLV2_KEEP_GUARD": "1",
                "MLV2_SKIP_MOUNT_CHECK": "0",
                "MLV2_SKIP_DEV_BLK_CHECK": "1",
            }
            cmd = [
                "/bin/sh", "-ec",
                'mkdir "$MLV2_PROC/$$"; cp "$1" "$MLV2_PROC/$$/mounts"; exec /bin/sh "$2"',
                "fixture", str(table), str(build.BOOT_SCRIPT),
            ]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(res.returncode, 0, (res.stdout, res.stderr))
            log_text = (stage / "sd-boot.log").read_text()
            self.assertIn("MLV2_SD_READY daemon_pid=4321", log_text)
            self.assertEqual((stage / "precap.cfg").read_bytes(), b"S7PC1 1 8\n")

    def test_remembered_state_restoration_and_malformed_fallbacks(self):
        cases = [
            (b"S7PC1 1 8\n", b"S7PC1 1 8\n"),
            (b"S7PC1 0 10\n", b"S7PC1 0 10\n"),
            (None, b"S7PC1 0 5\n"),
            (b"S7PC1 1 5\n\n", b"S7PC1 0 5\n"),  # double-newline MUST fail closed!
            (b"S7PC1 1 5", b"S7PC1 0 5\n"),      # missing newline MUST fail closed!
            (b"S7PC1 1 99\n", b"S7PC1 0 5\n"),   # invalid frame count MUST fail closed!
            (b"S7PC1 1 5\n\x00", b"S7PC1 0 5\n"),
        ]
        for seed, expected in cases:
            with self.subTest(seed=seed), tempfile.TemporaryDirectory() as td:
                res, stage, mods, ddir = self._run_boot(Path(td), persist_bytes=seed, keep_guard=1)
                self.assertEqual(res.returncode, 0, (res.stdout, res.stderr))
                self.assertEqual((stage / "precap.cfg").read_bytes(), expected)
                self.assertEqual(
                    (stage / "persist-cfg").read_bytes(), b"/tmp_network/mlv2/sim-setting-precap.cfg\n"
                )
                self.assertTrue((mods / "PreCapture.mod").is_file())
                self.assertTrue((stage / "mlv2_guard.elf").is_file())
                self.assertTrue((ddir / "daemon.pid").is_file())
                self.assertFalse((stage / "card.tar").exists())
                self.assertIn("MLV2_SD_READY daemon_pid=4321", (stage / "sd-boot.log").read_text())

    def test_absent_card_bad_version_and_nonstock_guard_leave_passive(self):
        with tempfile.TemporaryDirectory() as td:
            res, stage, mods, ddir = self._run_boot(Path(td), persist_bytes=b"S7PC1 1 8\n", card_present=False)
            self.assertEqual(res.returncode, 0)
            self.assertFalse(stage.exists())
            self.assertFalse(mods.exists())
            self.assertFalse(ddir.exists())

        with tempfile.TemporaryDirectory() as td:
            res, stage, mods, ddir = self._run_boot(
                Path(td), persist_bytes=b"S7PC1 1 8\n", version_bytes=b"WRONG_BUILD_1234567"
            )
            self.assertEqual(res.returncode, 0)
            self.assertFalse(stage.exists())

        with tempfile.TemporaryDirectory() as td:
            res, stage, mods, ddir = self._run_boot(
                Path(td), persist_bytes=b"S7PC1 1 8\n", guard_mode="patched"
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertFalse(stage.exists())
            self.assertFalse(mods.exists())
            self.assertFalse(ddir.exists())

        with tempfile.TemporaryDirectory() as td:
            res, stage, mods, ddir = self._run_boot(
                Path(td), persist_bytes=b"S7PC1 1 8\n", keep_guard=1, daemon_alive=False
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertTrue((stage / "sd-disabled").is_file())
            self.assertTrue((stage / "mlv2_guard.elf").is_file())
            self.assertIn("MLV2_DAEMON_NOT_ALIVE pid=4321", (stage / "sd-boot.log").read_text())

        # Zombie or wrong-exe daemon PID MUST be rejected (Sol Part B #6)!
        for bad_kw in (dict(daemon_state="Z"), dict(daemon_exe_override="/usr/bin/other")):
            with self.subTest(bad_kw=bad_kw), tempfile.TemporaryDirectory() as td:
                res, stage, mods, ddir = self._run_boot(
                    Path(td), persist_bytes=b"S7PC1 1 8\n", keep_guard=1, **bad_kw
                )
                self.assertNotEqual(res.returncode, 0)
                self.assertIn("MLV2_DAEMON_NOT_ALIVE pid=4321", (stage / "sd-boot.log").read_text())

    def test_sol_r2_boot_script_confinement_boot_log_and_mounts(self):
        # 1) Intermediate parent symlink (Sol Part B r2 #1) MUST exit cleanly with ZERO writes outside ram_root!
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            outside = t / "outside"
            outside.mkdir()
            (outside / "stage").mkdir()
            ram_root = t / "ram"
            ram_root.mkdir()
            (ram_root / "alias").symlink_to(outside)
            mounts = f"none {ram_root} tmpfs rw,size=1024k 0 0\n"
            res, _, _, _ = self._run_boot(
                t, persist_bytes=b"S7PC1 1 8\n", mounts_text=mounts, stage_override=ram_root / "alias" / "stage"
            )
            self.assertEqual(res.returncode, 0)
            self.assertFalse((outside / "stage" / "sd-boot.log").exists())

        # 2) Conflicting second mount row over $ram_root (Sol Part B r2 #1) MUST refuse with zero writes!
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            ram_root = t / "ram"
            mounts = (
                f"none {ram_root} tmpfs rw,size=1024k 0 0\n"
                f"other {ram_root} ext2 rw 0 0\n"
            )
            res, stage, _, _ = self._run_boot(t, persist_bytes=b"S7PC1 1 8\n", mounts_text=mounts)
            self.assertEqual(res.returncode, 0)
            self.assertFalse(stage.exists())

        # 3) FIFO at sd-boot.log OR stale symlink at TAR member (guard) MUST refuse before writing/extracting!
        with tempfile.TemporaryDirectory() as td:
            def make_log_fifo(ram_root, stage, mods, ddir):
                stage.mkdir(parents=True, exist_ok=True)
                os.mkfifo(stage / "sd-boot.log")
            res, stage, _, _ = self._run_boot(Path(td), persist_bytes=b"S7PC1 1 8\n", pre_stage_setup=make_log_fifo)
            self.assertNotEqual(res.returncode, 0)

        with tempfile.TemporaryDirectory() as td:
            victim = Path(td) / "victim.txt"
            victim.write_bytes(b"KEEP")
            def make_guard_link(ram_root, stage, mods, ddir):
                stage.mkdir(parents=True, exist_ok=True)
                (stage / "guard").symlink_to(victim)
            res, stage, _, _ = self._run_boot(Path(td), persist_bytes=b"S7PC1 1 8\n", pre_stage_setup=make_guard_link)
            self.assertNotEqual(res.returncode, 0)
            self.assertEqual(victim.read_bytes(), b"KEEP")

        # 4) Missing, mismatched, contradictory duplicate-key, or unterminated second BOOT record (Sol Part B r2/r3 #6)!
        for bad_boot, no_trailing_nl in (
            (None, False),
            ("BOOT self_pid=4321 im_pid=161 im_st=999 pre_f=8", False),
            ("BOOT self_pid=9999 im_pid=161 im_st=105 pre_f=8", False),
            ("BOOT self_pid=4321 im_pid=162 im_st=105 pre_f=8", False),
            ("BOOT self_pid=4321 im_pid=161 im_st=105 pre_f=8 im_st=106", False),
            ("BOOT self_pid=4321 im_pid=161 im_st=105 pre_f=8\nBOOT self_pid=4321 im_pid=161 im_st=105 pre_f=8", False),
            ("BOOT self_pid=4321 im_pid=161 im_st=105 pre_f=8\nBOOT self_pid=4321 im_pid=161 im_st=106 pre_f=8", True),
            ("BOOT self_pid=4321 im_pid=161 im_st=105 pre_f=8", True),
        ):
            with self.subTest(bad_boot=bad_boot, no_trailing_nl=no_trailing_nl), tempfile.TemporaryDirectory() as td:
                res, stage, _, _ = self._run_boot(
                    Path(td),
                    persist_bytes=b"S7PC1 1 8\n",
                    keep_guard=1,
                    daemon_boot_line=bad_boot,
                    daemon_boot_no_nl=no_trailing_nl,
                )
                self.assertNotEqual(res.returncode, 0)
                log_txt = (stage / "sd-boot.log").read_text()
                self.assertIn("MLV2_DAEMON_BOOT_MISMATCH pid=4321", log_txt)
                self.assertNotIn("MLV2_SD_READY", log_txt)


def check_wire_budget(command):
    wire, _, _ = ram.frame(command, 99_999_999, "ffffffffffff")
    if len(wire) >= 512:
        raise AssertionError(f"Phase A command needs {len(wire)} wire bytes")


class FakeGate:
    def __init__(self, cam):
        self.cam = cam
        self.next_frame = None
        self.poisoned = False
        self.packet_log = []

    def writeTerminal(self, data: bytes):
        assert not self.poisoned and data == self.next_frame
        self.next_frame = None
        self.cam.writeTerminal(data)

    def readTerminal(self) -> bytes:
        return self.cam.readTerminal()


class FakePhaseACamera:
    """In-memory mock of M7 usbgcon-1 terminal for testing scripts/m7_stage7_sd_probe.py."""

    def __init__(self, handler):
        self.handler = handler
        self.dev = FakeGate(self)
        self.rx = bytearray()
        self.commands_seen: list[str] = []

    def setTerminalEnable(self, enabled: bool):
        if enabled:
            self.rx.extend(b"Welcome\r\n" + terminal.SHELL_PROMPT)

    def writeTerminal(self, data: bytes):
        assert len(data) < 512
        text = data.decode("utf8", "replace")
        m = terminal.re.search(
            r"echo (__M7_B_[0-9a-f]+_\d+__); (.*); m7_rc_\d+=\$\?; echo; echo (__M7_E_[0-9a-f]+_\d+_)\$\{m7_rc_\d+\}__",
            text,
        )
        assert m, f"Unexpected frame: {text!r}"
        begin, inner, end_pref = m.group(1), m.group(2), m.group(3)
        check_wire_budget(inner)  # Check actual terminal writes, including redacted uploads.
        self.commands_seen.append(inner)
        out, rc = self.handler(inner)
        body = (out + "\r\n") if out else ""
        resp = f"{begin}\r\n{body}{end_pref}{rc}__\r\n".encode("utf8") + terminal.SHELL_PROMPT
        self.rx.extend(resp)

    def readTerminal(self) -> bytes:
        out = bytes(self.rx)
        self.rx.clear()
        return out


class ProbeCliTests(unittest.TestCase):
    def test_cli_wire_budget_with_fixture_uploads(self):
        reader = hashlib.shake_256(b"fixture reader").digest(2048)
        boot = b"fixture worker\n" * 100
        for base64_available in (False, True):
            with self.subTest(base64=base64_available):
                self._exercise_boot_probe(reader, base64_available=base64_available)
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            guard, request = b"fixture guard", b"fixture request"
            (directory / "mlv2_guard.elf").write_bytes(guard)
            (directory / "mlv2.req").write_bytes(request)
            artifacts = {
                name: {"sha256": hashlib.sha256(data).hexdigest()}
                for name, data in (("guard", guard), ("request", request), ("reader", reader))
            }
            with patch.object(probe_cli.build_stage7, "OUT", directory):
                self._exercise_start_and_collect({"artifacts": artifacts}, {"artifacts": artifacts}, reader, boot)

    def test_prep_card_preserves_dcim_and_rejects_repo_root(self):
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td) / "SD"
            dcim = sd / "DCIM" / "100MSDCF"
            dcim.mkdir(parents=True)
            photo = dcim / "DSC00001.JPG"
            photo.write_bytes(b"\xff\xd8PHOTO\xff\xd9")
            # Stale symlink at fixed MLV2.TAR.tmp MUST NOT overwrite DCIM photo (Sol Part B #5)!
            (sd / "MLV2.TAR.tmp").symlink_to(photo)
            key_path = Path(td) / "owner.key"
            res = probe_cli.prep_card(sd, key_file=key_path, release_seq=3)
            self.assertEqual(res["status"], "sd_card_prepared")
            self.assertTrue((sd / "MLV2.TAR").is_file() and not (sd / "MLV2.TAR").is_symlink())
            self.assertEqual(photo.read_bytes(), b"\xff\xd8PHOTO\xff\xd9")
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)

            # Symlink at MLV2.TAR destination MUST be refused without modifying target photo!
            (sd / "MLV2.TAR").unlink()
            (sd / "MLV2.TAR").symlink_to(photo)
            with self.assertRaises(ValueError):
                probe_cli.prep_card(sd, key_file=key_path, release_seq=4)
            self.assertEqual(photo.read_bytes(), b"\xff\xd8PHOTO\xff\xd9")

            with self.assertRaises(ValueError):
                probe_cli.prep_card(ROOT, key_file=key_path)

    def test_boot_probe_is_strictly_zero_flash_and_cleans_up(self):
        self._exercise_boot_probe((build.OUT_SD / "mlv2_card_read.elf").read_bytes())

    def _exercise_boot_probe(self, reader_bin, *, base64_available=False):
        reader_md5 = hashlib.md5(reader_bin).hexdigest()
        key_bytes = bytes(range(0xA0, 0xC0))
        key_md5 = hashlib.md5(key_bytes).hexdigest()
        uploaded: dict[str, bytes] = {}
        fail_on_key_chunk = [False]

        def handler(cmd: str) -> tuple[str, int]:
            # Assert ZERO writes to /setting, /etc, /tmp/, /usr, Backup.bin!
            cmd_no_devnull = cmd.replace("2>/dev/null", "")
            for forbidden in ("/setting/", "/etc/", "/usr/", "Backup.bin"):
                if forbidden in cmd_no_devnull:
                    self.assertNotIn(">", cmd_no_devnull, f"Write to forbidden flash path: {cmd}")
                    self.assertNotIn("rm ", cmd_no_devnull, f"Delete on forbidden flash path: {cmd}")
            if cmd.startswith("HISTFILE=/dev/null"):
                return "", 0
            if cmd == "/bin/busybox":
                return "BusyBox v1.13.4 multi-call binary\nCurrently defined functions:\n\tcat, chmod, dmesg, echo, egrep, gunzip, ls, md5sum, mkdir, pidof, readlink, rm, rmdir, tail, test, wc", 0
            if cmd.startswith("/bin/busybox echo -e '"):
                return "M7_OCTAL_OK", 0
            if cmd == "/bin/busybox --list":
                names = "cat\nchmod\ndmesg\necho\negrep\ngunzip\nls\nmd5sum\nmkdir\npidof\nreadlink\nrm\nrmdir\ntail\ntest\nwc"
                return (names + "\nbase64" if base64_available else names), 0
            if cmd in ("cat /version.txt", "/bin/busybox cat /version.txt"):
                return "29110_03.2021050601", 0
            if cmd in ("cat /proc/mounts", "/bin/busybox cat /proc/mounts"):
                return (
                    "proc /proc proc rw,relatime 0 0\n"
                    "/dev/nflasha15 /usr ext2 ro,relatime 0 0\n"
                    "none /tmp_network tmpfs rw,sync,dirsync,noatime,size=1024k 0 0"
                ), 0
            if cmd.startswith("ls -ld "):
                return (
                    "dr-xr-xr-x 1 0 0 0 Jan 1 00:00 /proc\n"
                    "drwxrwxrwt 2 0 0 40 Jan 1 00:00 /tmp_network\n"
                    "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr\n"
                    "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr/bin\n"
                    "-r-xr-xr-x 1 0 0 21868 May 6 2021 /usr/bin/im.elf\n"
                    "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr/lib\n"
                    "-r-xr-xr-x 1 0 0 21089716 May 6 2021 /usr/lib/libObj.so"
                ), 0
            if cmd == "/bin/busybox pidof im.elf":
                return "161", 0
            if cmd == "/bin/busybox wc -c /usr/lib/libObj.so":
                return "21089716 /usr/lib/libObj.so", 0
            if cmd == "/bin/busybox md5sum /usr/lib/libObj.so":
                return "99a06d3852bf744a5d454bd873f6d35c  /usr/lib/libObj.so", 0
            if cmd == "/bin/busybox cat /proc/sys/kernel/random/boot_id":
                return "11111111-2222-3333-4444-555555555555", 0
            if cmd == "/bin/busybox cat /proc/uptime":
                return "42.50 120.00", 0
            if cmd == "/bin/busybox cat /proc/cmdline":
                return "warm.mode=2 cmpr.path=/system/sabin/ssboot.bin", 0
            if cmd.startswith("/bin/busybox ls -la"):
                return "drwxrwxrwt 2 0 0 40 Jan 1 00:00 .", 0
            if cmd.startswith("[ -e /etc/ld.so.preload ]"):
                return "NO", 0
            if cmd.startswith("for p in /proc/[1-9]*"):
                return "P|/proc/161|/usr/bin/im.elf|161 (im.elf) S 1", 0
            if "dmesg" in cmd:
                return "[    0.100000] warm.mode=2", 0
            if cmd.startswith("[ ! -e /tmp_network/.m7-bp-") and "CLEAN" in cmd:
                return "CLEAN", 0
            if cmd.startswith("[ -d /tmp_network") and "&&echo OK||echo BAD" in cmd:
                return "OK", 0
            if cmd.startswith("[ ! -e /tmp_network/") and "&&echo OK||echo BAD" in cmd:
                return "OK", 0
            if cmd.startswith("/bin/busybox mkdir /tmp_network/.m7-bp-"):
                return "", 0
            upload = cmd.startswith(("/bin/busybox echo -ne ", "/bin/busybox echo -n "))
            if upload and "sd.key" in cmd and fail_on_key_chunk[0]:
                return "ERR", 1
            if upload or cmd.startswith("/bin/busybox gunzip -c ") or cmd.startswith("/bin/busybox rm -f ") or cmd.startswith("/bin/busybox chmod "):
                return "", 0
            if cmd.startswith("/bin/busybox md5sum "):
                p = cmd.split()[-1]
                md5 = reader_md5 if p.endswith("mlv2_card_read.elf") else key_md5
                uploaded[p] = b"ok"
                return f"{md5}  {p}", 0
            if "--probe --ram-path /tmp_network" in cmd:
                return (
                    "DEV_OK=1\nFS_TYPE=exFAT\nBPS=512\nSPC=256\nTOTAL_SECTORS=250314752\n"
                    "DATA_LBA=8448\nROOT_CLUSTER=2\nMLV2_FOUND=1\nMLV2_BYTES=199808\n"
                    "MLV2_DATA_LEN=199808\nDISABLE_MARKERS=0\n"
                    "RAM_STATFS bsize=4096 blocks=256 bfree=240 bavail=240 free_bytes=983040 total_bytes=1048576"
                ), 0
            if "--present " in cmd or "--verify " in cmd:
                return "", 0
            if cmd.startswith("/bin/busybox rm -rf /tmp_network/.m7-bp-"):
                return "", 0
            if cmd.startswith("[ ! -e /tmp_network/.m7-bp-"):
                return "GONE", 0
            raise AssertionError(f"Unhandled mock cmd: {cmd}")

        with tempfile.TemporaryDirectory() as td:
            key_file = Path(td) / "sd.key"
            key_file.write_bytes(key_bytes)
            cam = FakePhaseACamera(handler)
            receipt = {"model": "DSC-RX100M7", "nonce": "aabbccddeeff", "utc": "20261127T120000Z", "commands": [], "steps": []}
            probe_cli.do_boot_probe(cam, receipt, reader_bin, key_file=key_file)
            self.assertEqual(receipt["probe_dir_cleanup"], "GONE")
            self.assertEqual(receipt["card_probe"]["FS_TYPE"], "exFAT")
            self.assertEqual(receipt["card_probe"]["ram_statfs"]["free_bytes"], 983040)
            self.assertTrue(receipt["card_auth_check"]["verified_ok"])
            self.assertFalse(receipt["etc_preload_present"])
            # Sol Part B #2: ZERO key material or key MD5 in serialized receipt!
            rec_blob = json.dumps(receipt)
            self.assertNotIn("\\0240\\0241", rec_blob)
            self.assertNotIn(key_md5, rec_blob)
            self.assertIn("<REDACTED:sd.key>", receipt["commands"])

            # Failure during key upload MUST ALSO keep key redacted from receipt!
            fail_on_key_chunk[0] = True
            cam_f = FakePhaseACamera(handler)
            rec_f = {"model": "DSC-RX100M7", "nonce": "aabbccddeeff", "utc": "20261127T120001Z", "commands": [], "steps": []}
            with self.assertRaises(Exception):
                probe_cli.do_boot_probe(cam_f, rec_f, reader_bin, key_file=key_file)
            rec_f_blob = json.dumps(rec_f)
            self.assertNotIn("\\0240\\0241", rec_f_blob)
            self.assertNotIn(key_md5, rec_f_blob)

    def test_ram_start_and_collect_preserve_sim_persist_and_zero_flash(self):
        import build_stage7

        s7_manifest = build_stage7.verify_seal()
        sd_manifest = build.verify_seal()
        reader_bin = (build.OUT_SD / "mlv2_card_read.elf").read_bytes()
        boot_sh = (build.OUT_SD / "mlv2_sd_boot.sh").read_bytes()
        self._exercise_start_and_collect(s7_manifest, sd_manifest, reader_bin, boot_sh)

    def _exercise_start_and_collect(self, s7_manifest, sd_manifest, reader_bin, boot_sh):
        guard_bytes = (probe_cli.build_stage7.OUT / "mlv2_guard.elf").read_bytes()
        req_bytes = (probe_cli.build_stage7.OUT / "mlv2.req").read_bytes()
        key_bytes = bytes([0x3C] * 32)
        seed_line = "S7PC1 1 8\n"

        md5_map = {
            "mlv2_card_read.elf": hashlib.md5(reader_bin).hexdigest(),
            "mlv2_sd_boot.sh": hashlib.md5(boot_sh).hexdigest(),
            "sd.key": hashlib.md5(key_bytes).hexdigest(),
            "sim-setting-precap.cfg": hashlib.md5(seed_line.encode()).hexdigest(),
            "mlv2_guard.elf": hashlib.md5(guard_bytes).hexdigest(),
            "mlv2.req": hashlib.md5(req_bytes).hexdigest(),
            "precap.cfg": hashlib.md5(seed_line.encode("ascii")).hexdigest(),
        }
        size_map = {
            "mlv2_guard.elf": len(guard_bytes),
            "mlv2.req": len(req_bytes),
        }
        state = {
            "daemon_alive": True,
            "sd_disabled": False,
            "sd_stopped": False,
            "uninstalled": False,
            "sim_persist": "S7PC1 1 8\n",
            "precap_cfg": "S7PC1 1 8\n",
            "guard_out": {},
        }

        def handler(cmd: str) -> tuple[str, int]:
            # Hard ZERO-flash-write invariant across BOTH start and collect!
            cmd_no_devnull = cmd.replace("2>/dev/null", "")
            for forbidden in ("/setting/", "/etc/", "/usr/", "Backup.bin"):
                if forbidden in cmd_no_devnull:
                    self.assertNotIn(">", cmd_no_devnull, f"Forbidden flash write: {cmd}")
                    self.assertNotIn("rm ", cmd_no_devnull, f"Forbidden flash delete: {cmd}")
            if cmd.startswith("HISTFILE=/dev/null"):
                return "", 0
            if cmd == "/bin/busybox":
                return "BusyBox v1.13.4 multi-call binary\nCurrently defined functions:\n\tcat, chmod, echo, gunzip, ls, md5sum, mkdir, pidof, readlink, rm, rmdir, test, wc", 0
            if cmd.startswith("/bin/busybox echo -e '"):
                return "M7_OCTAL_OK", 0
            if cmd == "/bin/busybox --list":
                return "cat\nchmod\necho\ngunzip\nls\nmd5sum\nmkdir\npidof\nreadlink\nrm\nrmdir\ntest\nwc", 0
            if cmd in ("cat /version.txt", "/bin/busybox cat /version.txt"):
                return "29110_03.2021050601", 0
            if cmd in ("cat /proc/mounts", "/bin/busybox cat /proc/mounts"):
                return (
                    "proc /proc proc rw,relatime 0 0\n"
                    "/dev/nflasha15 /usr ext2 ro,relatime 0 0\n"
                    "none /tmp_network tmpfs rw,sync,dirsync,noatime,size=1024k 0 0"
                ), 0
            if cmd == "ls -ld /usr/lib/viewUnified2.so":
                return f"-rwxr-xr-x 1 0 0 {ram.VIEWUNIFIED2_BYTES} May 6 2021 /usr/lib/viewUnified2.so", 0
            if cmd.startswith("ls -ld "):
                return (
                    "dr-xr-xr-x 1 0 0 0 Jan 1 00:00 /proc\n"
                    "drwxrwxrwt 2 0 0 40 Jan 1 00:00 /tmp_network\n"
                    "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr\n"
                    "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr/bin\n"
                    "-r-xr-xr-x 1 0 0 21868 May 6 2021 /usr/bin/im.elf\n"
                    "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr/lib\n"
                    "-r-xr-xr-x 1 0 0 21089716 May 6 2021 /usr/lib/libObj.so"
                ), 0
            if cmd == "/bin/busybox wc -c /usr/lib/libObj.so":
                return "21089716 /usr/lib/libObj.so", 0
            if cmd == "/bin/busybox md5sum /usr/lib/libObj.so":
                return "99a06d3852bf744a5d454bd873f6d35c  /usr/lib/libObj.so", 0
            if cmd == "/bin/busybox wc -c /usr/lib/viewUnified2.so":
                return f"{ram.VIEWUNIFIED2_BYTES} /usr/lib/viewUnified2.so", 0
            if cmd == "/bin/busybox md5sum /usr/lib/viewUnified2.so":
                return f"{ram.VIEWUNIFIED2_MD5}  /usr/lib/viewUnified2.so", 0
            if cmd.startswith("if [ -L /usr/lib/viewUnified2.so"):
                return "FILE_OK", 0
            if cmd == "/bin/busybox pidof im.elf":
                return "161", 0
            if cmd.startswith("n=; for p in /proc/[1-9]*"):
                return "IM:/proc/161\nPROC_OK", 0
            if cmd == "/bin/busybox readlink /proc/161/exe 2>/dev/null":
                return "/usr/bin/im.elf", 0
            if cmd == "/bin/busybox cat /proc/161/stat 2>/dev/null":
                return "161 (im.elf) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 186 0 105 0 0", 0
            if cmd == "/bin/busybox cat /proc/161/status 2>/dev/null":
                return "Name:\tim.elf\nTgid:\t161\nPid:\t161\nPPid:\t1\nTracerPid:\t0", 0
            if cmd.startswith("[ -d /tmp_network") and "&&echo OK||echo BAD" in cmd:
                return "OK", 0
            if cmd.startswith("[ ! -e /tmp_network/") and "&&echo OK||echo BAD" in cmd:
                return "OK", 0
            if cmd.startswith("for d in /tmp_network/.m7-s6-*") or cmd.startswith("for d in /tmp_network/.m7-s7sd-*"):
                return "", 0
            if "echo WORKER_OK" in cmd:
                return "WORKER_OK", 0
            if "if [ -L /tmp_network/mlv2 ];then echo SYMLINK" in cmd:
                return "DIR", 0
            if "$b mkdir $l" in cmd:
                return "ACQ", 0
            if "$b mv $l $r" in cmd:
                return "REL", 0
            if cmd.startswith("[ -d /tmp_network/.m7-s7-") or cmd.startswith("[ -d /tmp_network/mlv2 ]"):
                return "EXISTS", 0
            if cmd.startswith("b=/tmp_network/.m7-s7-"):
                return "PROC_OK", 0
            if cmd.startswith("if [ -f /tmp_network/mlv2/"):
                target = cmd.split()[3]
                if target.endswith(("mlv2_guard.elf", "mlv2.req")):
                    return "FILE_OK", 0
                if "/.g" in target:
                    if "cat " in cmd:
                        return state["guard_out"][target], 0
                    return "FILE_OK" if target in state["guard_out"] else "FILE_ABSENT", 0
                return "FILE_ABSENT", 0
            if cmd.startswith("[ ! -e /tmp_network/.m7-s7-"):
                return "CLEAN", 0
            if cmd.startswith("/bin/busybox mkdir ") or cmd.startswith("/bin/busybox echo -ne ") or cmd.startswith("/bin/busybox gunzip -c ") or cmd.startswith("/bin/busybox chmod "):
                return "", 0
            if cmd.startswith("/bin/busybox rm -f "):
                target = cmd.split()[-1]
                state["guard_out"].pop(target, None)
                return "", 0
            if cmd.startswith("/bin/busybox wc -c /tmp_network/mlv2/"):
                p = cmd.split()[3]
                leaf = p.rsplit("/", 1)[1]
                return f"{size_map[leaf]} {p}", 0
            if cmd.startswith("/bin/busybox md5sum "):
                p = cmd.split()[2]
                leaf = p.rsplit("/", 1)[1]
                return f"{md5_map[leaf]}  {p}", 0
            if "--probe --ram-path /tmp_network" in cmd:
                return (
                    "DEV_OK=1\nFS_TYPE=exFAT\nBPS=512\nSPC=256\nTOTAL_SECTORS=250314752\n"
                    "DATA_LBA=8448\nROOT_CLUSTER=2\nMLV2_FOUND=1\nMLV2_BYTES=204928\n"
                    "MLV2_DATA_LEN=204928\nDISABLE_MARKERS=0\n"
                    "RAM_STATFS bsize=4096 blocks=256 bfree=200 bavail=200 free_bytes=819200 total_bytes=1048576"
                ), 0
            if "mlv2_sd_boot.sh" in cmd:
                return "", 0
            if "f=/tmp_network/mlv2/sd-boot.log;" in cmd and "echo FILE_UNSAFE" in cmd:
                return "FILE_OK", 0
            if "f=/tmp_network/mlv2/precap.cfg;" in cmd and "/bin/busybox md5sum $f" in cmd:
                return f"{md5_map['precap.cfg']}  /tmp_network/mlv2/precap.cfg", 0
            if "f=/tmp_network/mlv2/sd-boot.log;" in cmd and "/bin/busybox cat $f" in cmd:
                return "MLV2_SD_START build=29110_03.2021050601\nMLV2_SD_INSTALLED\nMLV2_SD_READY daemon_pid=2345", 0
            if "f=/tmp_network/mlv2/precap.cfg;" in cmd and "/bin/busybox cat $f" in cmd:
                return state["precap_cfg"].rstrip("\n"), 0
            if f"f={probe_cli.SD_SIM_PERSIST};" in cmd and "/bin/busybox cat $f" in cmd:
                return state["sim_persist"].rstrip("\n"), 0
            if f"f={probe_cli.SD_DAEMON_DIR}/daemon.pid;" in cmd and "/bin/busybox cat $f" in cmd:
                return "2345", 0
            if cmd == "/bin/busybox readlink /proc/2345/exe 2>/dev/null":
                return f"{probe_cli.SD_DAEMON_DIR}/daemon.elf", 0
            if cmd == "/bin/busybox cat /proc/2345/stat 2>/dev/null":
                return "2345 (daemon.elf) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 200 0 0", 0
            if f"f={probe_cli.SD_DAEMON_DIR}/daemon.log;" in cmd and "/bin/busybox cat $f" in cmd:
                return (
                    "BOOT self_pid=2345 im_pid=161 im_st=105 pre_f=8\n"
                    "STOP reason=stop_file r_runs=0 r_ok=0 r_sav=0 r_flt=0 r_unres=0"
                ), 0
            if "f=/tmp_network/mods/mod_loader.log;" in cmd and "/bin/busybox cat $f" in cmd:
                return "core_init 00000005\nauto_on 5a000000", 0
            if f": > {probe_cli.SD_DAEMON_DIR}/stop" in cmd:
                state["daemon_alive"] = False
                return "OK", 0
            if cmd == "[ -e /proc/2345/stat ] && echo ALIVE || echo GONE":
                return ("ALIVE" if state["daemon_alive"] else "GONE"), 0
            if ": > /tmp_network/mlv2/sd-disabled" in cmd:
                state["sd_disabled"] = True
                return "OK", 0
            if cmd.startswith("[ -f /tmp_network/mlv2/sd-stopped ]"):
                return ("YES" if state["sd_stopped"] else "NO"), 0
            if "mlv2_guard.elf" in cmd and "uninstall" in cmd:
                m = terminal.re.search(r"o=\$d/(\.g[0-9a-f]{6})", cmd)
                out_p = f"/tmp_network/mlv2/{m.group(1)}"
                state["guard_out"][out_p] = (
                    "TARGET /proc/161 view_bias=00000000\n"
                    "FREEZE threads=186\n"
                    "STATE hooks=v2 rects=patched shim=shim\n"
                    "UNINSTALLED restored=stock\n"
                    "RESUME count=186 result=0\n"
                    "MLV2_RESULT=0 changed=1"
                )
                state["uninstalled"] = True
                return "", 0
            if "mlv2_guard.elf" in cmd and "check" in cmd:
                m = terminal.re.search(r"o=\$d/(\.g[0-9a-f]{6})", cmd)
                out_p = f"/tmp_network/mlv2/{m.group(1)}"
                if state["uninstalled"]:
                    state["guard_out"][out_p] = (
                        "TARGET /proc/161 view_bias=00000000\n"
                        "STATE hooks=stock rects=stock shim=zero\n"
                        "MLV2_RESULT=0 changed=0"
                    )
                else:
                    state["guard_out"][out_p] = (
                        "TARGET /proc/161 view_bias=00000000\n"
                        "STATE hooks=v2 rects=patched shim=shim\n"
                        "MLV2_RESULT=0 changed=0"
                    )
                return "", 0
            if cmd.startswith("if [ -f /tmp_network/mlv2/.g"):
                m = terminal.re.search(r"(/tmp_network/mlv2/\.g[0-9a-f]{6})", cmd)
                return state["guard_out"][m.group(1)], 0
            if cmd.startswith("/bin/busybox rm -rf ") or cmd.startswith("m=/tmp_network/mlv2;for f in "):
                return "", 0
            if "&& echo GONE || echo DIRTY" in cmd:
                return "GONE", 0
            raise AssertionError(f"Unhandled mock cmd: {cmd}")

        with tempfile.TemporaryDirectory() as td:
            active_path = Path(td) / ".active-stage7-sd-ram.json"
            out_dir = Path(td) / "out"
            out_dir.mkdir()

            # 1) --ram-start
            cam1 = FakePhaseACamera(handler)
            rec1 = {"model": "DSC-RX100M7", "nonce": "112233445566", "utc": "20261127T120000Z", "commands": [], "steps": []}
            probe_cli.do_ram_start(
                cam1, rec1,
                s7_manifest=s7_manifest, sd_manifest=sd_manifest,
                reader_bin=reader_bin, boot_sh=boot_sh,
                key_bytes=key_bytes, seed_line=seed_line,
                active_path=active_path,
            )
            self.assertTrue(rec1["start_ready"])
            self.assertEqual(rec1["daemon_pid"], 2345)
            self.assertTrue(active_path.is_file())

            # 2) First --ram-collect before user opens MENU (sd-stopped not yet written) -> writes sd-disabled, keeps active
            cam2 = FakePhaseACamera(handler)
            rec2 = {"model": "DSC-RX100M7", "nonce": "112233445566", "utc": "20261127T120100Z", "commands": [], "steps": []}
            probe_cli.do_ram_collect(cam2, rec2, active_path=active_path, out_dir=out_dir)
            self.assertTrue(rec2["daemon_stopped"])
            self.assertFalse(rec2["sd_stopped_present"])
            self.assertTrue(active_path.is_file())

            # 3) User opens MENU -> core.bin disarms runtime precap.cfg to 0, writes sd-stopped, PRESERVES sim_persist!
            state["precap_cfg"] = "S7PC1 0 8\n"
            state["sd_stopped"] = True

            # 4) Second --ram-collect -> pinned uninstall succeeds, sim_persist preserved, RAM cleaned, active cleared!
            cam3 = FakePhaseACamera(handler)
            rec3 = {"model": "DSC-RX100M7", "nonce": "112233445566", "utc": "20261127T120200Z", "commands": [], "steps": []}
            probe_cli.do_ram_collect(cam3, rec3, active_path=active_path, out_dir=out_dir)
            self.assertTrue(rec3["uninstalled_clean"])
            self.assertTrue(rec3["sim_persist_preserved_across_disable"])
            self.assertEqual(rec3["ram_cleanup"], "GONE")
            self.assertTrue(rec3["active_state_cleared"])
            self.assertFalse(active_path.exists())

            # Verify ZERO secret key bytes / MD5 leaked into start receipt (Sol Part B #2)!
            rec1_blob = json.dumps(rec1)
            self.assertNotIn("\\0074\\0074", rec1_blob)
            self.assertNotIn(md5_map["sd.key"], rec1_blob)
            self.assertIn("<REDACTED:sd.key>", rec1["commands"])

            # Verify collect ran preflight (cat /version.txt & /proc/mounts) BEFORE any stop/sd-disabled write!
            for r in (rec2, rec3):
                ver_idx = r["commands"].index("cat /version.txt")
                mnt_idx = r["commands"].index("cat /proc/mounts")
                write_indices = [
                    i for i, c in enumerate(r["commands"])
                    if ": > " in c or "rm -rf " in c
                ]
                self.assertTrue(write_indices)
                self.assertLess(ver_idx, min(write_indices))
                self.assertLess(mnt_idx, min(write_indices))

    def test_ram_collect_reboot_recovery_uncertain_refusal_and_post_install_fault(self):
        import build_stage7

        s7_manifest = build_stage7.verify_seal()
        sd_manifest = build.verify_seal()
        guard_bytes = (build_stage7.OUT / "mlv2_guard.elf").read_bytes()
        req_bytes = (build_stage7.OUT / "mlv2.req").read_bytes()
        base_active = {
            "stage": "7.3-phase-a-ram",
            "status": "running",
            "nonce": "aabbccddeeff",
            "started_utc": "20261127T120000Z",
            "stage_dir": "/tmp_network/.m7-s7sd-aabbccddeeff",
            "daemon_dir": probe_cli.SD_DAEMON_DIR,
            "daemon_pid": 2345,
            "view_bias": "00000000",
            "im_pid": 161,
            "im_starttime": 105,
            "seed_pref": "S7PC1 1 8\n",
            "guard_bytes": len(guard_bytes),
            "guard_md5": hashlib.md5(guard_bytes).hexdigest(),
            "guard_sha256": s7_manifest["artifacts"]["guard"]["sha256"],
            "req_bytes": len(req_bytes),
            "req_md5": hashlib.md5(req_bytes).hexdigest(),
            "req_sha256": s7_manifest["artifacts"]["request"]["sha256"],
            "reader_sha256": sd_manifest["artifacts"]["reader"]["sha256"],
        }

        def make_readonly_handler(*, im_starttime: int, readlink_fail: bool = False):
            writes = []

            def handler(cmd: str) -> tuple[str, int]:
                cmd_no_devnull = cmd.replace("2>/dev/null", "")
                if ": > " in cmd_no_devnull or "rm -rf " in cmd_no_devnull or ">" in cmd_no_devnull:
                    writes.append(cmd)
                if cmd.startswith("HISTFILE=/dev/null"):
                    return "", 0
                if cmd == "/bin/busybox":
                    return "BusyBox v1.13.4 multi-call binary\nCurrently defined functions:\n\tcat, chmod, echo, gunzip, ls, md5sum, mkdir, pidof, readlink, rm, rmdir, test, wc", 0
                if cmd.startswith("/bin/busybox echo -e '"):
                    return "M7_OCTAL_OK", 0
                if cmd in ("cat /version.txt", "/bin/busybox cat /version.txt"):
                    return "29110_03.2021050601", 0
                if cmd in ("cat /proc/mounts", "/bin/busybox cat /proc/mounts"):
                    return (
                        "proc /proc proc rw,relatime 0 0\n"
                        "/dev/nflasha15 /usr ext2 ro,relatime 0 0\n"
                        "none /tmp_network tmpfs rw,sync,dirsync,noatime,size=1024k 0 0"
                    ), 0
                if cmd == "ls -ld /usr/lib/viewUnified2.so":
                    return f"-rwxr-xr-x 1 0 0 {ram.VIEWUNIFIED2_BYTES} May 6 2021 /usr/lib/viewUnified2.so", 0
                if cmd.startswith("ls -ld "):
                    return (
                        "dr-xr-xr-x 1 0 0 0 Jan 1 00:00 /proc\n"
                        "drwxrwxrwt 2 0 0 40 Jan 1 00:00 /tmp_network\n"
                        "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr\n"
                        "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr/bin\n"
                        "-r-xr-xr-x 1 0 0 21868 May 6 2021 /usr/bin/im.elf\n"
                        "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr/lib\n"
                        "-r-xr-xr-x 1 0 0 21089716 May 6 2021 /usr/lib/libObj.so"
                    ), 0
                if cmd == "/bin/busybox wc -c /usr/lib/libObj.so":
                    return "21089716 /usr/lib/libObj.so", 0
                if cmd == "/bin/busybox md5sum /usr/lib/libObj.so":
                    return "99a06d3852bf744a5d454bd873f6d35c  /usr/lib/libObj.so", 0
                if cmd == "/bin/busybox wc -c /usr/lib/viewUnified2.so":
                    return f"{ram.VIEWUNIFIED2_BYTES} /usr/lib/viewUnified2.so", 0
                if cmd == "/bin/busybox md5sum /usr/lib/viewUnified2.so":
                    return f"{ram.VIEWUNIFIED2_MD5}  /usr/lib/viewUnified2.so", 0
                if cmd == "/bin/busybox pidof im.elf":
                    return "161", 0
                if cmd.startswith("n=; for p in /proc/[1-9]*"):
                    return ("UNREAD:/proc/161\nPROC_OK" if readlink_fail else "IM:/proc/161\nPROC_OK"), 0
                if cmd == "/bin/busybox readlink /proc/161/exe 2>/dev/null":
                    return ("", 1) if readlink_fail else ("/usr/bin/im.elf", 0)
                if cmd == "/bin/busybox cat /proc/161/stat 2>/dev/null":
                    return f"161 (im.elf) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 186 0 {im_starttime} 0 0", 0
                if cmd == "/bin/busybox cat /proc/161/status 2>/dev/null":
                    return "Name:\tim.elf\nTgid:\t161\nPid:\t161\nPPid:\t1\nTracerPid:\t0", 0
                if cmd.startswith("b=/tmp_network/.m7-s7-"):
                    return "PROC_OK", 0
                if "&& echo GONE || echo DIRTY" in cmd:
                    return "GONE", 0
                raise AssertionError(f"Unexpected cmd: {cmd}")

            return handler, writes

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            out_dir.mkdir()

            # 1) Rebooted camera (im_starttime=999 != 105, RAM clean) -> ZERO camera writes, clears custody!
            act1 = Path(td) / ".active-reboot.json"
            act1.write_text(json.dumps(base_active), encoding="utf-8")
            h1, w1 = make_readonly_handler(im_starttime=999, readlink_fail=False)
            rec1 = {"model": "DSC-RX100M7", "nonce": "aabbccddeeff", "utc": "20261127T121000Z", "commands": [], "steps": []}
            probe_cli.do_ram_collect(FakePhaseACamera(h1), rec1, active_path=act1, out_dir=out_dir)
            self.assertEqual(w1, [])
            self.assertTrue(rec1["rebooted_clean_stock"])
            self.assertTrue(rec1["active_state_cleared"])
            self.assertFalse(act1.exists())

            # 2) Uncertain im.elf identity -> ZERO camera writes, keeps custody!
            act2 = Path(td) / ".active-uncertain.json"
            act2.write_text(json.dumps(base_active), encoding="utf-8")
            h2, w2 = make_readonly_handler(im_starttime=105, readlink_fail=True)
            rec2 = {"model": "DSC-RX100M7", "nonce": "aabbccddeeff", "utc": "20261127T121100Z", "commands": [], "steps": []}
            probe_cli.do_ram_collect(FakePhaseACamera(h2), rec2, active_path=act2, out_dir=out_dir)
            self.assertEqual(w2, [])
            self.assertEqual(rec2["collect_outcome"], "uncertain_im_identity")
            self.assertFalse(rec2["active_state_cleared"])
            self.assertTrue(act2.exists())

    def test_part_b_sol_blockers_daemon_live_lost_ack_and_preboot_refusal(self):
        import build_stage7
        from unittest import mock

        s7_manifest = build_stage7.verify_seal()
        sd_manifest = build.verify_seal()
        guard_bytes = (build_stage7.OUT / "mlv2_guard.elf").read_bytes()
        req_bytes = (build_stage7.OUT / "mlv2.req").read_bytes()
        base_active = {
            "stage": "7.3-phase-a-ram",
            "status": "running",
            "nonce": "aabbccddeeff",
            "started_utc": "20261127T120000Z",
            "stage_dir": "/tmp_network/.m7-s7sd-aabbccddeeff",
            "daemon_dir": probe_cli.SD_DAEMON_DIR,
            "daemon_pid": 2345,
            "view_bias": "00000000",
            "im_pid": 161,
            "im_starttime": 105,
            "seed_pref": "S7PC1 1 8\n",
            "guard_bytes": len(guard_bytes),
            "guard_md5": hashlib.md5(guard_bytes).hexdigest(),
            "guard_sha256": s7_manifest["artifacts"]["guard"]["sha256"],
            "req_bytes": len(req_bytes),
            "req_md5": hashlib.md5(req_bytes).hexdigest(),
            "req_sha256": s7_manifest["artifacts"]["request"]["sha256"],
            "reader_sha256": sd_manifest["artifacts"]["reader"]["sha256"],
        }

        def make_handler(
            *,
            daemon_stays_alive: bool,
            guard_present: bool,
            boot_log: str = "",
            boot_log_state: str | None = None,
            boot_log_rc: int | None = None,
            lock_result: str = "ACQ",
            worker_active: bool = False,
            sd_stopped: bool = False,
            mlv2_state: str = "DIR",
            clean_reply: str = "GONE",
        ):
            uninstall_called = []
            writes = []
            seen_cmds = []

            def handler(cmd: str) -> tuple[str, int]:
                seen_cmds.append(cmd)
                if "mlv2_guard.elf" in cmd and "uninstall" in cmd:
                    uninstall_called.append(cmd)
                if ": > " in cmd or "/bin/busybox rm -rf " in cmd or cmd.startswith("m=/tmp_network/mlv2;for f in "):
                    writes.append(cmd)
                if cmd.startswith("HISTFILE=/dev/null"):
                    return "", 0
                if cmd == "/bin/busybox":
                    return "BusyBox v1.13.4 multi-call binary\nCurrently defined functions:\n\tcat, chmod, echo, gunzip, ls, md5sum, mkdir, pidof, readlink, rm, rmdir, test, wc", 0
                if cmd.startswith("/bin/busybox echo -e '"):
                    return "M7_OCTAL_OK", 0
                if cmd in ("cat /version.txt", "/bin/busybox cat /version.txt"):
                    return "29110_03.2021050601", 0
                if cmd in ("cat /proc/mounts", "/bin/busybox cat /proc/mounts"):
                    return (
                        "proc /proc proc rw,relatime 0 0\n"
                        "/dev/nflasha15 /usr ext2 ro,relatime 0 0\n"
                        "none /tmp_network tmpfs rw,sync,dirsync,noatime,size=1024k 0 0"
                    ), 0
                if cmd == "ls -ld /usr/lib/viewUnified2.so":
                    return f"-rwxr-xr-x 1 0 0 {ram.VIEWUNIFIED2_BYTES} May 6 2021 /usr/lib/viewUnified2.so", 0
                if cmd.startswith("ls -ld "):
                    return (
                        "dr-xr-xr-x 1 0 0 0 Jan 1 00:00 /proc\n"
                        "drwxrwxrwt 2 0 0 40 Jan 1 00:00 /tmp_network\n"
                        "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr\n"
                        "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr/bin\n"
                        "-r-xr-xr-x 1 0 0 21868 May 6 2021 /usr/bin/im.elf\n"
                        "drwxr-xr-x 2 0 0 1024 May 6 2021 /usr/lib\n"
                        "-r-xr-xr-x 1 0 0 21089716 May 6 2021 /usr/lib/libObj.so"
                    ), 0
                if cmd == "/bin/busybox wc -c /usr/lib/libObj.so":
                    return "21089716 /usr/lib/libObj.so", 0
                if cmd == "/bin/busybox md5sum /usr/lib/libObj.so":
                    return "99a06d3852bf744a5d454bd873f6d35c  /usr/lib/libObj.so", 0
                if cmd == "/bin/busybox wc -c /usr/lib/viewUnified2.so":
                    return f"{ram.VIEWUNIFIED2_BYTES} /usr/lib/viewUnified2.so", 0
                if cmd == "/bin/busybox md5sum /usr/lib/viewUnified2.so":
                    return f"{ram.VIEWUNIFIED2_MD5}  /usr/lib/viewUnified2.so", 0
                if cmd == "/bin/busybox pidof im.elf":
                    return "161", 0
                if cmd.startswith("n=; for p in /proc/[1-9]*"):
                    return "IM:/proc/161\nPROC_OK", 0
                if cmd == "/bin/busybox readlink /proc/161/exe 2>/dev/null":
                    return "/usr/bin/im.elf", 0
                if cmd == "/bin/busybox cat /proc/161/stat 2>/dev/null":
                    return "161 (im.elf) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 186 0 105 0 0", 0
                if cmd == "/bin/busybox cat /proc/161/status 2>/dev/null":
                    return "Name:\tim.elf\nTgid:\t161\nPid:\t161\nPPid:\t1\nTracerPid:\t0", 0
                if "echo WORKER_OK" in cmd:
                    return ("W:/proc/999\nWORKER_OK" if worker_active else "WORKER_OK"), 0
                if "if [ -L /tmp_network/mlv2 ];then echo SYMLINK" in cmd:
                    return mlv2_state, 0
                if "/bin/busybox mkdir /tmp_network/mlv2 2>/dev/null&&echo MK" in cmd:
                    return ("MK" if lock_result == "ACQ" else "RACE"), 0
                if "$b mkdir $l" in cmd:
                    return lock_result, 0
                if "$b mv $l $r" in cmd:
                    return "REL", 0
                if cmd.startswith("[ -d /tmp_network/.m7-s7-"):
                    return ("EXISTS" if daemon_stays_alive else "ABSENT"), 0
                if f": > {probe_cli.SD_DAEMON_DIR}/stop" in cmd:
                    return "OK", 0
                if cmd == "[ -e /proc/2345/stat ] && echo ALIVE || echo GONE":
                    return ("ALIVE" if daemon_stays_alive else "GONE"), 0
                if cmd.startswith("b=/tmp_network/.m7-s7-"):
                    return ("D:/proc/2345\nPROC_OK" if daemon_stays_alive else "PROC_OK"), 0
                if "f=/tmp_network/mlv2/sd-boot.log;" in cmd and "/bin/busybox cat $f" in cmd:
                    if boot_log_rc is not None:
                        return boot_log, boot_log_rc
                    return (boot_log, 0) if boot_log else ("", 1)
                if "/bin/busybox cat $f" in cmd:
                    return "", 1
                if "f=/tmp_network/mlv2/sd-boot.log;" in cmd and "echo FILE_UNSAFE" in cmd:
                    if boot_log_state is not None:
                        return boot_log_state, 0
                    return ("FILE_OK" if boot_log else "FILE_ABSENT"), 0
                if cmd.startswith("if [ -f /tmp_network/mlv2/"):
                    return ("FILE_OK" if guard_present else "FILE_ABSENT"), 0
                if cmd.startswith("[ -f /tmp_network/mlv2/sd-stopped ]"):
                    return ("YES" if sd_stopped else "NO"), 0
                if "PRE_BOOT_CLEAN" in cmd:
                    return "PRE_BOOT_CLEAN", 0
                if "&& echo CLEAN || echo DIRTY" in cmd:
                    return "CLEAN", 0
                if cmd.startswith("/bin/busybox rm -rf ") or cmd.startswith("m=/tmp_network/mlv2;for f in "):
                    return "", 0
                if "&& echo GONE || echo DIRTY" in cmd:
                    return clean_reply, 0
                raise AssertionError(f"Unexpected cmd: {cmd}")

            return handler, uninstall_called, writes, seen_cmds

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            out_dir.mkdir()

            # 1) Sol Part B #3: live daemon refuses to stop -> MUST NEVER call mlv2_guard uninstall!
            act1 = Path(td) / ".active-live-daemon.json"
            act1.write_text(json.dumps(base_active), encoding="utf-8")
            h1, u1, _, _ = make_handler(daemon_stays_alive=True, guard_present=True)
            rec1 = {"model": "DSC-RX100M7", "nonce": "aabbccddeeff", "utc": "20261127T122000Z", "commands": [], "steps": []}
            with mock.patch.object(probe_cli.time, "sleep"):
                probe_cli.do_ram_collect(FakePhaseACamera(h1), rec1, active_path=act1, out_dir=out_dir)
            self.assertEqual(u1, [])
            self.assertEqual(rec1["collect_outcome"], "daemon_still_running")
            self.assertFalse(rec1["daemon_stopped"])
            self.assertTrue(act1.exists())

            # 2) Sol Part B #4a & r3 N1: resumed collect when all RAM dirs already GONE clears custody READ-ONLY (0 writes)!
            act2 = Path(td) / ".active-resumed.json"
            act2.write_text(
                json.dumps({**base_active, "status": "stock_verified_pending_cleanup"}), encoding="utf-8"
            )
            h2, u2, w2, _ = make_handler(daemon_stays_alive=False, guard_present=False, mlv2_state="ABSENT")
            rec2 = {"model": "DSC-RX100M7", "nonce": "aabbccddeeff", "utc": "20261127T122100Z", "commands": [], "steps": []}
            probe_cli.do_ram_collect(FakePhaseACamera(h2), rec2, active_path=act2, out_dir=out_dir)
            self.assertEqual(u2, [])
            self.assertEqual(w2, [])
            self.assertEqual(rec2["collect_outcome"], "resumed_stock_verified_cleanup")
            self.assertTrue(rec2["active_state_cleared"])
            self.assertFalse(act2.exists())

            # 3) Sol Part B #4b: pending_boot with retained pre-install refusal sd-boot.log recovers cleanly,
            #    holding .boot.lock across all deletions and removing .boot.lock + /tmp_network/mlv2 LAST!
            act3 = Path(td) / ".active-preboot.json"
            act3.write_text(
                json.dumps({**base_active, "status": "pending_boot", "daemon_pid": None, "view_bias": None}),
                encoding="utf-8",
            )
            h3, u3, _, cmds3 = make_handler(
                daemon_stays_alive=False,
                guard_present=False,
                boot_log="MLV2_SD_START build=29110_03.2021050601\nMLV2_SD_PACKAGE_UNAVAILABLE rc=1",
            )
            rec3 = {"model": "DSC-RX100M7", "nonce": "aabbccddeeff", "utc": "20261127T122200Z", "commands": [], "steps": []}
            probe_cli.do_ram_collect(FakePhaseACamera(h3), rec3, active_path=act3, out_dir=out_dir)
            self.assertEqual(u3, [])
            self.assertEqual(rec3["collect_outcome"], "pre_boot_refusal_recovered")
            self.assertTrue(rec3["active_state_cleared"])
            self.assertFalse(act3.exists())
            rm_idx = [i for i, c in enumerate(cmds3) if "/bin/busybox rm -rf " in c or c.startswith("m=/tmp_network/mlv2;for f in ")]
            lock_rel_idx = [i for i, c in enumerate(cmds3) if "$b mv $l $r" in c]
            self.assertTrue(rm_idx and lock_rel_idx and max(rm_idx) < lock_rel_idx[0])

            # 4) Sol Part B r2/r3 N1 (BLOCKER): worker holds .boot.lock (both DIR and ABSENT race!) or live worker
            #    -> MUST refuse IMMEDIATELY with ZERO stop/sd-disabled/uninstall/rm-rf writes!
            for case, kw, expect_out in (
                ("lock_held", dict(lock_result="HELD"), "boot_worker_lock_held"),
                ("absent_race_held", dict(mlv2_state="ABSENT", lock_result="HELD"), "boot_worker_lock_held"),
                ("worker_live", dict(worker_active=True), "boot_worker_active"),
            ):
                with self.subTest(case=case):
                    act4 = Path(td) / f".active-n1-{case}.json"
                    act4.write_text(
                        json.dumps({**base_active, "status": "pending_boot", "daemon_pid": None, "view_bias": None}),
                        encoding="utf-8",
                    )
                    h4, u4, w4, _ = make_handler(
                        daemon_stays_alive=False,
                        guard_present=True,
                        sd_stopped=True,
                        boot_log="MLV2_SD_START build=29110_03.2021050601\nMLV2_GUARD_INSTALL_BEGIN",
                        **kw,
                    )
                    rec4 = {"model": "DSC-RX100M7", "nonce": "aabbccddeeff", "utc": "20261127T122300Z", "commands": [], "steps": []}
                    probe_cli.do_ram_collect(FakePhaseACamera(h4), rec4, active_path=act4, out_dir=out_dir)
                    self.assertEqual(rec4["collect_outcome"], expect_out)
                    self.assertEqual(u4, [])
                    self.assertEqual(w4, [])
                    self.assertFalse(rec4["active_state_cleared"])
                    self.assertTrue(act4.exists())

            # 5) Sol Part B r2/r3 N2 (MAJOR): MLV2_GUARD_NOT_STOCK, unreadable boot log, or empty boot log
            #    MUST NEVER clear recovery custody or write stock_verified_pending_cleanup!
            for case, st, kw in (
                ("not_stock", "boot_failed_pending_collect", dict(boot_log="MLV2_SD_START build=29110_03.2021050601\nMLV2_GUARD_NOT_STOCK")),
                ("unreadable_failed", "boot_failed_pending_collect", dict(boot_log="", boot_log_state="FILE_OK", boot_log_rc=1)),
                ("absent_failed", "boot_failed_pending_collect", dict(boot_log="", boot_log_state="FILE_ABSENT", boot_log_rc=1)),
                ("empty_pending", "pending_boot", dict(boot_log="", boot_log_state="FILE_OK", boot_log_rc=0)),
                ("unreadable_pending", "pending_boot", dict(boot_log="", boot_log_state="FILE_OK", boot_log_rc=1)),
            ):
                with self.subTest(case=case):
                    act5 = Path(td) / f".active-n2-{case}.json"
                    act5.write_text(
                        json.dumps({**base_active, "status": st, "daemon_pid": None, "view_bias": None}),
                        encoding="utf-8",
                    )
                    h5, u5, w5, _ = make_handler(daemon_stays_alive=False, guard_present=False, **kw)
                    rec5 = {"model": "DSC-RX100M7", "nonce": "aabbccddeeff", "utc": "20261127T122400Z", "commands": [], "steps": []}
                    probe_cli.do_ram_collect(FakePhaseACamera(h5), rec5, active_path=act5, out_dir=out_dir)
                    self.assertEqual(rec5["collect_outcome"], "pre_boot_stock_unverified")
                    self.assertFalse(rec5["uninstalled_clean"])
                    self.assertFalse(rec5.get("active_state_cleared", False))
                    self.assertEqual(u5, [])
                    self.assertEqual(w5, [])
                    self.assertTrue(act5.exists())
                    self.assertEqual(json.loads(act5.read_text())["status"], st)

            # 6) Confirmed pre-launch abort (pending_boot + FILE_ABSENT boot log + clean daemon/mods) recovers under lock!
            act6 = Path(td) / ".active-pending-absent.json"
            act6.write_text(
                json.dumps({**base_active, "status": "pending_boot", "daemon_pid": None, "view_bias": None}),
                encoding="utf-8",
            )
            h6, u6, _, cmds6 = make_handler(
                daemon_stays_alive=False,
                guard_present=False,
                mlv2_state="ABSENT",
                boot_log="",
                boot_log_state="FILE_ABSENT",
                boot_log_rc=1,
            )
            rec6 = {"model": "DSC-RX100M7", "nonce": "aabbccddeeff", "utc": "20261127T122500Z", "commands": [], "steps": []}
            probe_cli.do_ram_collect(FakePhaseACamera(h6), rec6, active_path=act6, out_dir=out_dir)
            self.assertEqual(rec6["collect_outcome"], "pre_boot_upload_aborted_clean")
            self.assertTrue(any("l=$m/.boot.lock" in c for c in cmds6))
            self.assertTrue(rec6["active_state_cleared"])
            self.assertFalse(act6.exists())


class LocalRamShell:
    """Run camera filesystem commands with /bin/sh inside a disposable host tree."""

    def __init__(self, directory):
        self.directory = directory
        self.stage = directory / "ram/mlv2"
        self.stage.mkdir(parents=True)
        self.commands = []
        self.fault = ""
        shim = directory / "bb"
        shim.write_text(
            '#!/bin/sh\n'
            'echo "$*" >> applets\n'
            'if [ "$1" = mv ];then\n'
            '  case "$FAULT" in\n'
            '    before_mv) kill -TERM "$PPID";exit 1;;\n'
            '    after_mv) "$@" || exit 1;kill -TERM "$PPID";exit 0;;\n'
            '  esac\n'
            'fi\n'
            'if [ "$FAULT:$1:$2" = successor:rmdir:./ram/mlv2 ];then\n'
            '  mkdir "$2/.boot.lock" && echo "worker 99" > "$2/.boot.lock/owner" || exit 1\n'
            'fi\n'
            'exec "$@"\n'
        )
        shim.chmod(0o700)

    def command(self, cmd, **kwargs):
        check_wire_budget(cmd)
        self.commands.append(cmd)
        local = cmd.replace("/tmp_network", "./ram").replace("/bin/busybox", "./bb")
        proc = subprocess.run(
            ["/bin/sh", "-c", local], cwd=self.directory, capture_output=True,
            env={**os.environ, "FAULT": self.fault}, timeout=3,
        )
        return proc.stdout, proc.returncode


class CollectorShellTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.shell = LocalRamShell(self.directory)
        self.lock = self.shell.stage / ".boot.lock"
        self.owner = self.lock / "owner"
        self.log = self.shell.stage / "sd-boot.log"
        self.active = self.directory / "active.json"
        self.output = self.directory / "receipts"
        self.output.mkdir()

    def collect(self, *, interrupt_after_release=False):
        nonce = "0123456789ab"
        state = {
            "stage": "7.3-phase-a-ram", "status": "pending_boot", "nonce": nonce,
            "stage_dir": f"/tmp_network/.m7-s7sd-{nonce}", "daemon_dir": probe_cli.SD_DAEMON_DIR,
            "daemon_pid": None, "im_pid": 161, "im_starttime": 105, "guard_bytes": 1, "req_bytes": 1,
            "guard_md5": "0" * 32, "req_md5": "0" * 32,
        }
        self.active.write_text(json.dumps(state))
        self.receipt = {"model": "DSC-RX100M7", "nonce": nonce, "utc": "fixture", "commands": [], "steps": []}

        def respond(cmd):
            if cmd.startswith("/bin/busybox rm -rf ") or cmd.startswith("m=/tmp_network/mlv2;for f in "):
                self.assertEqual(self.owner.read_text(), "collect\n")
                self.assertEqual(json.loads(self.active.read_text())["status"], "stock_verified_pending_cleanup")
            out, rc = self.shell.command(cmd)
            if interrupt_after_release and "$b mv $l $r" in cmd and out == b"REL\n":
                # The terminal still answers but the shell's REL confirmation was lost.
                return "", 1
            return out.decode().rstrip("\n"), rc

        live = {"im_state": "verified_live", "pid": 161, "im_starttime": 105}
        with (
            patch.object(ram, "run_collect_preflight", return_value=live),
            patch.object(ram, "observe_live_s7_processes", return_value={"certain_clear": True}),
            patch.object(probe_cli, "observe_boot_worker_clear", return_value={"certain_clear": True}),
        ):
            probe_cli.do_ram_collect(FakePhaseACamera(respond), self.receipt, active_path=self.active, out_dir=self.output)
        return self.receipt

    def test_successor_lock_and_stock_checkpoint_survive(self):
        self.log.write_text("MLV2_SD_PACKAGE_UNAVAILABLE rc=1\n")
        payload_dirs = [self.shell.stage.parent / d for d in (
            ".m7-s7sd-0123456789ab", probe_cli.SD_DAEMON_DIR.rsplit("/", 1)[1], "mods",
        )]
        for directory in payload_dirs:
            directory.mkdir()
            (directory / "payload").touch()
        self.shell.fault = "successor"
        receipt = self.collect()
        self.assertEqual(receipt["collect_lock_result"], "ACQ")
        self.assertEqual(receipt["collect_lock_release"], "REL")
        self.assertEqual(receipt["ram_cleanup"], "DIRTY")
        self.assertNotIn("collect_lock_finally_release", receipt)
        self.assertEqual(self.owner.read_text(), "worker 99\n")
        self.assertTrue(all(not d.exists() for d in payload_dirs))
        self.assertFalse(self.log.exists())
        self.assertEqual(json.loads(self.active.read_text())["status"], "stock_verified_pending_cleanup")

        stale = self.shell.stage / ".boot.rel"
        stale.write_text("leave this sibling alone")
        self.assertEqual(probe_cli._release_collect_lock(self.shell, try_rmdir_parent=True), "NOT_OWNED")
        self.assertEqual(self.owner.read_text(), "worker 99\n")
        self.assertEqual(stale.read_text(), "leave this sibling alone")

    def test_finalizer_after_unconfirmed_release_preserves_successor(self):
        self.log.write_text("MLV2_SD_PACKAGE_UNAVAILABLE rc=1\n")
        self.shell.fault = "successor"
        self.collect(interrupt_after_release=True)
        self.assertEqual(self.receipt["collect_lock_release"], "ERR")
        self.assertEqual(self.receipt["collect_lock_finally_release"], "NOT_OWNED")
        self.assertEqual(self.owner.read_text(), "worker 99\n")
        self.assertEqual(json.loads(self.active.read_text())["status"], "stock_verified_pending_cleanup")

    def test_interrupted_release_on_both_sides_of_rename(self):
        self.assertEqual(probe_cli._acquire_collect_lock(self.shell), "ACQ")
        released = self.shell.stage / ".boot.rel"
        released.mkdir()
        (released / "stale").touch()
        for fault, next_result in (("before_mv", "REACQ"), ("after_mv", "ACQ")):
            with self.subTest(fault=fault):
                self.shell.fault = fault
                self.assertEqual(probe_cli._release_collect_lock(self.shell, try_rmdir_parent=False), "ERR")
                if fault == "before_mv":
                    self.assertEqual(self.owner.read_text(), "collect\n")
                    self.assertFalse(released.exists())
                else:
                    self.assertFalse(self.lock.exists())
                    self.assertEqual((released / "owner").read_text(), "collect\n")
                self.assertEqual(probe_cli._acquire_collect_lock(self.shell), next_result)
        self.shell.fault = ""
        self.assertEqual(probe_cli._release_collect_lock(self.shell, try_rmdir_parent=True), "REL")
        self.assertFalse(self.shell.stage.exists())

    def test_unsafe_boot_log_keeps_custody_without_sending_cat(self):
        sentinel = self.directory / "outside"
        sentinel.write_text("synthetic outside sentinel")
        remote = "/tmp_network/mlv2/sd-boot.log"
        for kind in ("symlink", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.log.symlink_to(sentinel)
                else:
                    os.mkfifo(self.log)
                self.shell.commands.clear()
                receipt = self.collect()
                self.assertEqual(receipt["sd_boot_log_state"], "FILE_UNSAFE")
                self.assertEqual((receipt["sd_boot_log"], receipt["sd_boot_log_rc"]), ("", 1))
                self.assertFalse(any(remote in c and "cat " in c for c in self.shell.commands))
                self.assertEqual(receipt["collect_outcome"], "pre_boot_stock_unverified")
                self.assertEqual(receipt["collect_lock_finally_release"], "REL")
                self.assertEqual(json.loads(self.active.read_text())["status"], "pending_boot")
                self.assertNotIn(sentinel.read_text(), json.dumps(receipt))
                for path in self.output.rglob("*"):
                    if path.is_file():
                        self.assertNotIn(sentinel.read_bytes(), path.read_bytes())
                self.assertEqual(probe_cli._safe_cat_ram_file(self.shell, remote), (b"", 1))
                self.assertNotIn("cat ./ram/mlv2/sd-boot.log", (self.directory / "applets").read_text())
                self.log.unlink()

    def test_leaf_read_refuses_unsafe_ancestors_and_paths(self):
        remote = "/tmp_network/mlv2/sd-boot.log"
        self.assertEqual(probe_cli._inspect_ram_leaf(self.shell, remote), "FILE_ABSENT")
        self.assertEqual(probe_cli._safe_cat_ram_file(self.shell, remote), (b"", 1))
        self.log.mkdir()
        self.assertEqual(probe_cli._inspect_ram_leaf(self.shell, remote), "FILE_UNSAFE")
        self.assertEqual(probe_cli._safe_cat_ram_file(self.shell, remote), (b"", 1))
        self.log.rmdir()
        self.log.write_bytes(b"regular file")
        self.assertEqual(probe_cli._inspect_ram_leaf(self.shell, remote), "FILE_OK")
        self.assertEqual(probe_cli._safe_cat_ram_file(self.shell, remote), (b"regular file", 0))
        for directory in (self.shell.stage, self.shell.stage.parent):
            with self.subTest(directory=directory):
                moved = directory.with_suffix(".saved")
                directory.rename(moved)
                directory.symlink_to(moved)
                self.assertEqual(probe_cli._inspect_ram_leaf(self.shell, remote), "FILE_UNSAFE")
                self.assertEqual(probe_cli._safe_cat_ram_file(self.shell, remote), (b"", 1))
                directory.unlink()
                moved.rename(directory)
        for path in (remote + ";id", remote + "\n", remote + "..", "/tmp_network/../file", "/tmp_network/./file"):
            for read in (probe_cli._inspect_ram_leaf, probe_cli._safe_cat_ram_file):
                with self.subTest(path=path, read=read), self.assertRaises(probe_cli.usb.ProbeError):
                    read(self.shell, path)
                self.assertFalse(any(path == c or f"f={path};" in c for c in self.shell.commands))


if __name__ == "__main__":
    unittest.main()
