"""Unified reproducible builder and seal verifier for Stage 7.1 (DSC-RX100M7 1.00).

Builds and seals all seven Stage 7.1 native artifacts under prototype-stage7-persist/out/:
  1. shim.bin           (M7 1.00 mlv2 shim for libtestcmd.so RX cave)
  2. core.bin           (M7 1.00 position-independent mlv2 core with SMNU submenu)
  3. mlv2.req           (ML2Q v2 request with live relocation table)
  4. mlv2_guard.elf     (freestanding ARM32 guard: check / install / uninstall / fnv)
  5. PreCapture.mod     (Astra's sealed zero-hook SMNU settings module)
  6. stage7_daemon.elf  (zero-ptrace, zero-/dev/uipc precap.cfg supervisor daemon)
  7. stage7_ring.elf    (Run #4b-qualified capture worker with RELRO runtime config)
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "out"
PROTO_STAGE5 = ROOT / "prototype-producer-probe"
PROTO_STAGE6 = ROOT / "prototype-stage6-autonomy"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(PROTO_STAGE5))
import build_precap_mod  # noqa: E402
import m7_100_layout as layout  # noqa: E402
import build as s5_build  # noqa: E402

BASE = 0x10000
SHIM_CAP = 2048
SHIM_MOVE = 0x1000
VIEW_MOVE = 0x10000
CORE_MAGIC = 0x52434C4D
CORE_VERSION = 2
CORE_MAX = 64 * 1024
REQ_MAGIC = 0x5132484D

DAEMON_MAGIC = 0x31443753
DAEMON_VERSION = 1
DAEMON_CONFIG_BYTES = 13 * 4 + 12  # 64 bytes

RING_BOOT_MAGIC = 0x31523753
RING_BOOT_VERSION = 1
RING_BOOT_BYTES = 4 * 4 + 12  # 28 bytes
M7_CONFIG_BYTES = 60 + 512 * 8
M7_PRECAP_BYTES = 40

ALLOWED_RING_RW_SECTIONS = frozenset({
    ".rodata.m7_config",
    ".rodata.m7_precap_config",
})

FORBIDDEN_CORE_RELOC_TYPES = frozenset({
    2,   # R_ARM_ABS32
    24,  # R_ARM_GOTOFF32
    25,  # R_ARM_GOTPC
    26,  # R_ARM_GOT32
    27,  # R_ARM_PLT32
    38,  # R_ARM_TARGET1
    21,  # R_ARM_GLOB_DAT
    22,  # R_ARM_JUMP_SLOT
    96,  # R_ARM_GOT_PREL
})

FORBIDDEN_HELPER_SYMS = frozenset({
    "memcpy", "memset", "memmove", "memcmp",
    "__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8",
    "__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8",
    "__aeabi_memclr", "__aeabi_memclr4", "__aeabi_memclr8",
    "__aeabi_uidiv", "__aeabi_idiv", "__aeabi_uidivmod", "__aeabi_idivmod",
})

SEALED_NATIVE_SOURCES = (
    "prototype-stage7-persist/mlv2.h",
    "prototype-stage7-persist/mlv2_sys.h",
    "prototype-stage7-persist/shim.c",
    "prototype-stage7-persist/mlv2_trampoline.S",
    "prototype-stage7-persist/shim.ld",
    "prototype-stage7-persist/core.c",
    "prototype-stage7-persist/core.ld",
    "prototype-stage7-persist/mlv2_guard.c",
    "prototype-stage7-persist/precap_mod.c",
    "prototype-stage7-persist/stage7_common.h",
    "prototype-stage7-persist/stage7_v2_common.h",
    "prototype-stage7-persist/stage7_daemon.c",
    "prototype-stage7-persist/stage7_ring.c",
    "sources/bionz-x-research/tools/native_camera/mlv2/mod_v2.ld",
)

SEALED_HOST_SOURCES = (
    "prototype-stage7-persist/m7_100_layout.py",
    "prototype-stage7-persist/build_precap_mod.py",
    "prototype-stage7-persist/build_stage7.py",
    "prototype-stage7-persist/test_stage7_unicorn.py",
    "prototype-stage7-persist/test_stage7_integration.py",
    "prototype-producer-probe/build.py",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fnv1a_32(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    return h


def align_up(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


def linker_cmd() -> list[str]:
    return build_precap_mod.linker()


def collect_native_hashes() -> dict[str, str]:
    pending = [(ROOT / rel).resolve() for rel in SEALED_NATIVE_SOURCES]
    extra_dirs = [HERE, PROTO_STAGE5]
    hashes: dict[str, str] = {}
    while pending:
        path = pending.pop()
        rel = str(path.relative_to(ROOT))
        if rel in hashes:
            continue
        body = path.read_bytes()
        hashes[rel] = sha(body)
        if path.suffix in (".c", ".h", ".S"):
            for name_b in re.findall(rb'^\s*#include\s+"([^"]+)"', body, re.MULTILINE):
                name = name_b.decode("ascii")
                if name == "sony_pins.h":
                    continue
                found = None
                for base in (path.parent, *extra_dirs):
                    cand = (base / name).resolve()
                    if cand.is_file():
                        found = cand
                        break
                if found is None:
                    raise ValueError(f"Missing native #include {name!r} from {rel}")
                pending.append(found)
    return dict(sorted(hashes.items()))


def collect_host_hashes() -> dict[str, str]:
    out = {}
    for rel in SEALED_HOST_SOURCES:
        p = ROOT / rel
        if not p.is_file():
            raise ValueError(f"Missing host file: {rel}")
        out[rel] = sha(p.read_bytes())
    return dict(sorted(out.items()))


def extract_text_and_syms(elf_bytes: bytes, expected_addr: int) -> tuple[int, bytes, dict[str, int]]:
    elf = ELFFile(io.BytesIO(elf_bytes))
    sec = elf.get_section_by_name(".text")
    if sec is None:
        raise ValueError("Missing .text section")
    for s in elf.iter_sections():
        if (s["sh_flags"] & 2) and s["sh_size"] and s.name != ".text":
            raise ValueError(f"Unexpected allocated section {s.name} ({s['sh_size']} B)")
    addr = sec["sh_addr"]
    if addr != expected_addr:
        raise ValueError(f".text addr {addr:#x} != expected {expected_addr:#x}")
    syms: dict[str, int] = {}
    symtab = elf.get_section_by_name(".symtab")
    if symtab is not None:
        for sym in symtab.iter_symbols():
            if sym.name:
                if sym.name in FORBIDDEN_HELPER_SYMS:
                    raise ValueError(f"Forbidden runtime helper symbol in linked ELF: {sym.name}")
                syms[sym.name] = sym["st_value"]
    return addr, sec.data(), syms


def apply_arm_relocations(elf: ELFFile, sec_file_offsets: dict, sec_vaddrs: dict, image: bytearray):
    table = elf.get_section_by_name(".symtab")

    def sym_addr(sym):
        idx = sym["st_shndx"]
        if idx not in sec_vaddrs:
            raise ValueError(f"Unresolved or unplaced symbol: {sym.name!r} (shndx={idx!r})")
        return sec_vaddrs[idx] + sym["st_value"]

    symbols = {}
    for sym in table.iter_symbols():
        if sym.name and sym["st_shndx"] in sec_vaddrs:
            symbols[sym.name] = sym_addr(sym)

    for section in elf.iter_sections():
        if section["sh_type"] != "SHT_REL" or section["sh_info"] not in sec_file_offsets:
            continue
        sec_off = sec_file_offsets[section["sh_info"]]
        sec_va = sec_vaddrs[section["sh_info"]]
        for reloc in section.iter_relocations():
            r_off = reloc["r_offset"]
            file_at = sec_off + r_off
            va_at = sec_va + r_off
            word = struct.unpack_from("<I", image, file_at)[0]
            target = sym_addr(table.get_symbol(reloc["r_info_sym"]))
            kind = reloc["r_info_type"]
            if kind == 2:  # R_ARM_ABS32
                result = (word + target) & 0xFFFFFFFF
            elif kind in (28, 29):  # R_ARM_CALL / R_ARM_JUMP24
                disp = (word & 0xFFFFFF) << 2
                if disp & 0x2000000:
                    disp -= 0x4000000
                disp += target - va_at
                assert not (disp & 3) and -0x2000000 <= disp < 0x2000000
                result = (word & 0xFF000000) | ((disp >> 2) & 0xFFFFFF)
            else:
                raise ValueError(f"Unsupported ARM relocation {kind}")
            struct.pack_into("<I", image, file_at, result)
    return symbols, table


def generate_sony_pins_header(out_dir: Path) -> dict[str, str]:
    pins = s5_build.target_pins()
    header = ["struct code_pin { u32 va, size; const unsigned char *bytes; };"]
    for index, (_, data) in enumerate(pins):
        header.append("static const unsigned char pin_%d[] = {%s};" %
                      (index, ",".join(str(b) for b in data)))
    header.append("static const struct code_pin code_pins[] = {%s};" %
                  ",".join("{0x%x,%d,pin_%d}" % (va, len(data), i) for i, (va, data) in enumerate(pins)))
    fsys_pins = s5_build.mpr_pins()
    for index, (_, data) in enumerate(fsys_pins):
        header.append("static const unsigned char mpr_pin_%d[] = {%s};" %
                      (index, ",".join(str(b) for b in data)))
    header.append("static const struct code_pin mpr_code_pins[] = {%s};" %
                  ",".join("{0x%x,%d,mpr_pin_%d}" % (va, len(data), i) for i, (va, data) in enumerate(fsys_pins)))
    for name, group in (
        ("media", s5_build.media_pins()),
        ("mprctrl", s5_build.mprctrl_pins()),
        ("route", s5_build.route_pins()),
        ("create", s5_build.create_pins()),
        ("end_register", s5_build.end_register_pins()),
        ("mwf", s5_build.mwf_pins()),
        ("pthread", s5_build.pthread_pins()),
        ("receiver", s5_build.receiver_pins()),
        ("receiver_mwf", s5_build.receiver_mwf_pins()),
        ("connect", s5_build.connect_pins()),
        ("connect_mwf", s5_build.connect_mwf_pins()),
        ("ram_capture", s5_build.ram_capture_pins()),
        ("burst_cancel", s5_build.burst_cancel_pins()),
        ("mode", s5_build.mode_pins()),
        ("mode_mwf", s5_build.mode_mwf_pins()),
        ("start", s5_build.start_pins()),
        ("start_mwf", s5_build.start_mwf_pins()),
        ("start_uipc", s5_build.start_uipc_pins()),
    ):
        for index, (_, data) in enumerate(group):
            header.append("static const unsigned char %s_pin_%d[] = {%s};" %
                          (name, index, ",".join(str(b) for b in data)))
        header.append("static const struct code_pin %s_code_pins[] = {%s};" %
                      (name, ",".join("{0x%x,%d,%s_pin_%d}" % (va, len(data), name, i)
                                      for i, (va, data) in enumerate(group))))
    text = "\n".join(header) + "\n"
    (out_dir / "sony_pins.h").write_text(text)
    return dict(
        libObj=s5_build.SONY_SHA,
        libmpr=s5_build.MPR_SHA,
        libmprctrl=s5_build.MPRCTRL_SHA,
        libMWF=s5_build.MWF_SHA,
        libosal_uipc=s5_build.UIPC_SHA,
        libpthread=s5_build.PTHREAD_SHA,
        viewUnified2=layout.VIEWUNIFIED2_SHA256,
        im_elf=layout.IM_ELF_SHA256,
        libtestcmd=layout.TESTCMD_SHA256,
        sony_pins_header_sha256=sha(text.encode("utf-8")),
    )


def build_mlv2_shim_and_req(work_dir: Path, extra_defs: tuple[str, ...] = ()) -> tuple[bytes, bytes, dict]:
    ld = linker_cmd()
    shim_addr = layout.REF_SHIM_ADDR
    view_base = layout.REF_VIEW_BASE
    reloc_shim = shim_addr + VIEW_MOVE
    reloc_view = view_base + VIEW_MOVE

    reloc_ld = work_dir / "shim-reloc.ld"
    reloc_ld.write_text(
        (HERE / "shim.ld").read_text()
        .replace(f"{shim_addr:#010x}", f"{reloc_shim:#010x}")
        .replace(f"{shim_addr + SHIM_CAP:#010x}", f"{reloc_shim + SHIM_CAP:#010x}")
    )

    def link_shim(tag: str, ld_script: Path, s_addr: int, v_base: int) -> bytes:
        c_obj = work_dir / f"shim_{tag}.o"
        s_obj = work_dir / f"tramp_{tag}.o"
        elf_out = work_dir / f"shim_{tag}.elf"
        defs = [f"-DMLV2_SHIM_ADDR={s_addr:#x}u", f"-DMLV2_VIEW_BASE={v_base:#x}u", *extra_defs]
        subprocess.run([
            "clang", "--target=armv7-none-eabi", "-mthumb", "-mcpu=cortex-a5",
            "-mfloat-abi=soft", "-mno-movt", "-Os", "-fno-pic", "-fno-pie",
            "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
            "-fomit-frame-pointer", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
            "-Wall", "-Wextra", "-Werror", "-I", str(HERE), *defs,
            "-c", str(HERE / "shim.c"), "-o", str(c_obj),
        ], check=True)
        subprocess.run([
            "clang", "--target=armv7-none-eabi", "-mthumb", "-mcpu=cortex-a5",
            "-mfloat-abi=soft", "-fno-pic", "-fno-pie", "-I", str(HERE),
            f"-DMLV2_VIEW_BASE={v_base:#x}",
            "-c", str(HERE / "mlv2_trampoline.S"), "-o", str(s_obj),
        ], check=True)
        subprocess.run([
            *ld, "--build-id=none", "-e", "ml_hook_set_root", "-T", str(ld_script), "--no-undefined",
            str(c_obj), str(s_obj), "-o", str(elf_out),
        ], check=True)
        return elf_out.read_bytes()

    elf_a = link_shim("ref", HERE / "shim.ld", shim_addr, view_base)
    elf_b = link_shim("rel", reloc_ld, reloc_shim, reloc_view)

    addr_a, shim_a, syms_a = extract_text_and_syms(elf_a, shim_addr)
    _, shim_b, _ = extract_text_and_syms(elf_b, reloc_shim)

    if len(shim_a) > SHIM_CAP or (len(shim_a) & 3) or shim_a[:4] != b"\x00\x00\x00\x00":
        raise ValueError(f"Invalid shim size/slot: len={len(shim_a)} slot={shim_a[:4].hex()}")
    if len(shim_b) != len(shim_a):
        raise ValueError(f"Relocated shim size changed: {len(shim_a)} vs {len(shim_b)}")

    entries = {k: syms_a[k] for k in ("ml_hook_set_root", "ml_hook_refresh", "ml_hook_open_item")}
    if not all((v & 1) and shim_addr < v < shim_addr + len(shim_a) for v in entries.values()):
        raise ValueError(f"Invalid shim entries: {entries}")

    relocs: list[int] = []
    for off in range(0, len(shim_a), 4):
        wa = struct.unpack_from("<I", shim_a, off)[0]
        wb = struct.unpack_from("<I", shim_b, off)[0]
        if wa == wb:
            continue
        delta = (wb - wa) & 0xFFFFFFFF
        if delta == VIEW_MOVE:
            relocs.append(off | (1 << 30))
        else:
            raise ValueError(f"Shim word +{off:#x} differs by {delta:#x} (expected VIEW_MOVE {VIEW_MOVE:#x})")

    e = [entries["ml_hook_set_root"], entries["ml_hook_refresh"], entries["ml_hook_open_item"]]
    v1_triples = [(0, 0, 0)]  # M7 1.00 has no v1 loader
    req = struct.pack("<9I", REQ_MAGIC, 2, shim_addr, len(shim_a), *e, fnv1a_32(shim_a), len(v1_triples))
    req += b"".join(struct.pack("<3I", *t) for t in v1_triples) + shim_a
    req += struct.pack(f"<{1 + len(relocs)}I", len(relocs), *relocs)

    meta = dict(
        shim=dict(
            file="shim.bin",
            addr=addr_a,
            bytes=len(shim_a),
            cap=SHIM_CAP,
            fnv1a_32=f"{fnv1a_32(shim_a):#010x}",
            sha256=sha(shim_a),
            entries={k: f"{v:#010x}" for k, v in entries.items()},
            relocs=dict(
                view=[hex(r & 0x3FFFFFFF) for r in relocs],
            ),
        ),
        request=dict(
            file="mlv2.req",
            bytes=len(req),
            sha256=sha(req),
            reloc_count=len(relocs),
        ),
    )
    return shim_a, req, meta


def build_mlv2_core(work_dir: Path, extra_defs: tuple[str, ...] = ()) -> tuple[bytes, dict]:
    ld = linker_cmd()
    c_obj = work_dir / "core.o"
    c_elf = work_dir / "core.elf"
    subprocess.run([
        "clang", "--target=armv7-none-eabi", "-mthumb", "-mcpu=cortex-a5",
        "-mfloat-abi=soft", "-mno-movt", "-Os", "-fpie", "-fvisibility=hidden",
        "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
        "-fomit-frame-pointer", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-I", str(HERE), *extra_defs, "-c", str(HERE / "core.c"), "-o", str(c_obj),
    ], check=True)

    # Verify core.o has ZERO absolute/GOT/PLT relocations (strictly position-independent).
    obj_elf = ELFFile(io.BytesIO(c_obj.read_bytes()))
    symtab = obj_elf.get_section_by_name(".symtab")
    for sec in obj_elf.iter_sections():
        if sec["sh_type"] == "SHT_REL":
            for rel in sec.iter_relocations():
                rtype = rel["r_info_type"]
                if rtype in FORBIDDEN_CORE_RELOC_TYPES:
                    sname = symtab.get_symbol(rel["r_info_sym"]).name if symtab else "?"
                    raise ValueError(f"Forbidden relocation type {rtype} in core.o ({sec.name} -> {sname})")

    subprocess.run([
        *ld, "--build-id=none", "-e", "core_init", "-T", str(HERE / "core.ld"), "--no-undefined",
        str(c_obj), "-o", str(c_elf),
    ], check=True)

    _, core_code, csyms = extract_text_and_syms(c_elf.read_bytes(), 0)
    init_off = csyms.get("core_init", 0)
    if init_off != 1 or not core_code or len(core_code) > CORE_MAX or (len(core_code) & 3):
        raise ValueError(f"Invalid core_init ({init_off:#x}) or size ({len(core_code)})")

    core_bin = struct.pack("<5I", CORE_MAGIC, CORE_VERSION, len(core_code), fnv1a_32(core_code), init_off) + core_code
    meta = dict(
        file="core.bin",
        code_bytes=len(core_code),
        bytes=len(core_bin),
        fnv1a_32=f"{fnv1a_32(core_code):#010x}",
        init_off=init_off,
        sha256=sha(core_bin),
    )
    return core_bin, meta


def build_single_rx_arm_elf(source: Path, obj_name: str, out_name: str, work_dir: Path,
                            optimize: str = "-Os", extra_defs: tuple[str, ...] = ()) -> tuple[bytes, dict]:
    objpath = work_dir / obj_name
    subprocess.run([
        "clang", "--target=armv7-none-eabi", "-marm", "-mfloat-abi=soft",
        "-mno-movt", optimize, "-ffreestanding", "-fno-builtin",
        "-fno-stack-protector", "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables", "-fno-pic", "-fno-pie",
        "-Wall", "-Wextra", "-Werror",
        "-I", str(HERE), *extra_defs,
        "-c", str(source), "-o", str(objpath),
    ], check=True)
    object_data = objpath.read_bytes()

    header_sz = 52 + 32  # 1 PT_LOAD RX
    elf = ELFFile(io.BytesIO(object_data))
    image = bytearray(header_sz)
    sec_file_offsets, sec_vaddrs = {}, {}
    for i, section in enumerate(elf.iter_sections()):
        if section["sh_flags"] & 2 and section["sh_type"] == "SHT_PROGBITS":
            if section["sh_flags"] & 1:
                raise ValueError(f"{out_name} must have zero writable globals: {section.name}")
            align = max(4, section["sh_addralign"])
            pad = (-(BASE + len(image))) % align
            image.extend(bytes(pad))
            sec_file_offsets[i] = len(image)
            sec_vaddrs[i] = BASE + len(image)
            image.extend(section.data())
        elif section["sh_flags"] & 2 and section["sh_type"] == "SHT_NOBITS":
            if section["sh_size"] != 0:
                raise ValueError(f"{out_name} must have zero BSS: {section.name}")

    symbols, table = apply_arm_relocations(elf, sec_file_offsets, sec_vaddrs, image)
    size = len(image)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident, 2, 40, 1, symbols["_start"], 52, 0, 0x5000000, 52, 32, 1, 0, 0, 0,
    )
    phdr = struct.pack("<8I", 1, 0, BASE, BASE, size, size, 5, 4096)
    image[0:header_sz] = ehdr + phdr

    meta = dict(
        file=out_name,
        sha256=sha(bytes(image)),
        bytes=size,
        base=BASE,
        entry=symbols["_start"],
        symbols=symbols,
    )
    return bytes(image), meta, table


def assert_zero_ptrace_in_daemon_bytes(daemon_elf: bytes) -> dict:
    """Verify statically across ALL 4-byte code words of the sealed ELF binary (no symtab needed)
    that EVERY ARM `svc #0` resolves cleanly and excludes ptrace(26) and ioctl(54).
    """
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    if b"/dev/uipc" in daemon_elf:
        raise ValueError("Forbidden /dev/uipc string in stage7_daemon.elf")
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    text_off = 52 + 32
    svc_offsets = [
        off for off in range(text_off, len(daemon_elf) - 3, 4)
        if struct.unpack_from("<I", daemon_elf, off)[0] == 0xEF000000
    ]
    if not svc_offsets:
        raise ValueError("No svc #0 instructions found in stage7_daemon.elf")

    def resolve_r7(svc_off: int) -> int:
        for off in range(svc_off - 4, max(text_off - 4, svc_off - 400), -4):
            ins = next(md.disasm(daemon_elf[off:off + 4], BASE + off), None)
            if ins is None:
                continue
            op = ins.op_str
            if ins.mnemonic in ("mov", "movw") and op.startswith("r7, #"):
                return int(op.split("#", 1)[1], 0)
            if ins.mnemonic == "ldr" and op.startswith("r7, [pc, #"):
                imm = int(op.split("#", 1)[1].rstrip("]"), 0)
                lit_off = off + 8 + imm
                if 0 <= lit_off <= len(daemon_elf) - 4:
                    return struct.unpack_from("<I", daemon_elf, lit_off)[0]
            if ins.mnemonic not in ("push", "pop", "stm", "ldm", "str", "strb", "strh") and op.startswith("r7,"):
                raise ValueError(f"Dynamic r7 assignment ({ins.mnemonic} {op}) before svc at {BASE + svc_off:#x}")
        raise ValueError(f"Unresolved r7 before svc #0 at {BASE + svc_off:#x}")

    called_nrs = {resolve_r7(off) for off in svc_offsets}
    allowed = {1, 2, 3, 4, 5, 6, 10, 11, 12, 20, 37, 38, 42, 55, 63, 66, 85, 91, 114, 174, 175, 177, 180, 192, 197, 217, 263}
    unexpected = called_nrs - allowed
    if unexpected:
        raise ValueError(f"Unexpected/forbidden syscalls in stage7_daemon.elf: {sorted(unexpected)}")
    if not called_nrs:
        raise ValueError("Empty syscall census")
    return dict(svc_count=len(svc_offsets), resolved_svc_count=len(svc_offsets), static_syscalls=sorted(called_nrs))


def assert_zero_ptrace_in_daemon(daemon_elf: bytes, daemon_meta: dict) -> dict:
    """Verify statically across ALL 4-byte code words that EVERY svc #0 in stage7_daemon.elf
    is resolved and excludes ptrace(26) and ioctl(54), and matches the binary-only census.
    """
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    text_off = 52 + 32
    forbidden_syms = [s for s in daemon_meta["symbols"] if "ptrace" in s.lower() or "uipc" in s.lower()]
    if forbidden_syms:
        raise ValueError(f"Forbidden ptrace/uipc symbols in stage7_daemon.elf: {forbidden_syms}")
    if b"/dev/uipc" in daemon_elf:
        raise ValueError("Forbidden /dev/uipc string in stage7_daemon.elf")

    svc_offsets = [
        off for off in range(text_off, len(daemon_elf) - 3, 4)
        if struct.unpack_from("<I", daemon_elf, off)[0] == 0xEF000000
    ]
    if not svc_offsets:
        raise ValueError("No svc #0 instructions found in stage7_daemon.elf")

    func_starts = sorted((va, name) for name, va in daemon_meta["symbols"].items() if va >= BASE + text_off)

    def enclosing_func(va: int) -> tuple[int, str]:
        best = (BASE + text_off, "?")
        for fva, fname in func_starts:
            if fva <= va:
                best = (fva, fname)
            else:
                break
        return best

    def resolve_r7_for_svc(svc_off: int) -> int:
        fva, fname = enclosing_func(BASE + svc_off)
        func_off = max(text_off, fva - BASE)
        for off in range(svc_off - 4, max(func_off - 4, svc_off - 400), -4):
            ins = next(md.disasm(daemon_elf[off:off + 4], BASE + off), None)
            if ins is None:
                continue
            op = ins.op_str
            if ins.mnemonic in ("mov", "movw") and op.startswith("r7, #"):
                return int(op.split("#", 1)[1], 0)
            if ins.mnemonic == "ldr" and op.startswith("r7, [pc, #"):
                imm = int(op.split("#", 1)[1].rstrip("]"), 0)
                lit_off = (BASE + off + 8 + imm) - BASE
                if 0 <= lit_off <= len(daemon_elf) - 4:
                    return struct.unpack_from("<I", daemon_elf, lit_off)[0]
            if ins.mnemonic not in ("push", "pop", "stm", "ldm", "str", "strb", "strh") and op.startswith("r7,"):
                raise ValueError(f"Dynamic r7 assignment ({ins.mnemonic} {op}) before svc at {BASE + svc_off:#x} in {fname}")
        raise ValueError(f"Unresolved r7 before svc #0 at {BASE + svc_off:#x} in {fname}")

    called_nrs = {resolve_r7_for_svc(off) for off in svc_offsets}
    allowed = {1, 2, 3, 4, 5, 6, 10, 11, 12, 20, 37, 38, 42, 55, 63, 66, 85, 91, 114, 174, 175, 177, 180, 192, 197, 217, 263}
    unexpected = called_nrs - allowed
    if unexpected:
        raise ValueError(f"Unexpected/forbidden syscalls in stage7_daemon.elf: {sorted(unexpected)}")
    sym_census = dict(svc_count=len(svc_offsets), resolved_svc_count=len(svc_offsets), static_syscalls=sorted(called_nrs))
    bin_census = assert_zero_ptrace_in_daemon_bytes(daemon_elf)
    if sym_census != bin_census:
        raise ValueError(f"Symbol census {sym_census} != binary census {bin_census}")
    return sym_census


def build_stage7_ring(work_dir: Path, extra_defs: tuple[str, ...] = ()) -> tuple[bytes, dict]:
    objpath = work_dir / "stage7_ring.o"
    subprocess.run([
        "clang", "--target=armv7-none-eabi", "-marm", "-mfloat-abi=soft",
        "-mno-movt", "-Os", "-ffreestanding", "-fno-builtin",
        "-fno-stack-protector", "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables", "-fno-pic", "-fno-pie",
        "-fdata-sections",
        "-Wall", "-Wextra", "-Werror",
        "-I", str(work_dir),
        "-I", str(HERE),
        "-I", str(PROTO_STAGE5),
        *extra_defs,
        "-c", str(HERE / "stage7_ring.c"), "-o", str(objpath),
    ], check=True)
    object_data = objpath.read_bytes()

    header_sz = 52 + 2 * 32  # 2 PT_LOAD: RX + RW-RELRO
    elf = ELFFile(io.BytesIO(object_data))
    image = bytearray(header_sz)
    sec_file_offsets, sec_vaddrs = {}, {}
    rw_sections = []

    for i, section in enumerate(elf.iter_sections()):
        if section["sh_flags"] & 2 and section["sh_type"] == "SHT_PROGBITS":
            if section["sh_flags"] & 1:
                raise ValueError(f"stage7_ring must have zero writable C globals: {section.name}")
            if section.name in ALLOWED_RING_RW_SECTIONS:
                rw_sections.append((i, section))
                continue
            align = max(4, section["sh_addralign"])
            pad = (-(BASE + len(image))) % align
            image.extend(bytes(pad))
            sec_file_offsets[i] = len(image)
            sec_vaddrs[i] = BASE + len(image)
            image.extend(section.data())
        elif section["sh_flags"] & 2 and section["sh_type"] == "SHT_NOBITS":
            if section["sh_size"] != 0:
                raise ValueError(f"stage7_ring must have zero BSS: {section.name}")

    if {s.name for _, s in rw_sections} != ALLOWED_RING_RW_SECTIONS:
        raise ValueError(f"Unexpected ring RW sections: {[s.name for _, s in rw_sections]}")

    ro_size = len(image)
    rw_file_off = align_up(ro_size, 4096)
    image.extend(bytes(rw_file_off - ro_size))
    rw_vaddr = BASE + rw_file_off

    for i, section in rw_sections:
        align = max(4, section["sh_addralign"])
        pad = (-(BASE + len(image))) % align
        image.extend(bytes(pad))
        sec_file_offsets[i] = len(image)
        sec_vaddrs[i] = BASE + len(image)
        image.extend(section.data())

    rw_filesz = len(image) - rw_file_off
    rw_memsz = align_up(rw_filesz, 4096)

    symbols, table = apply_arm_relocations(elf, sec_file_offsets, sec_vaddrs, image)
    boot_sym = table.get_symbol_by_name("m7_s7_ring_boot")[0]
    cfg_sym = table.get_symbol_by_name("m7_config")[0]
    pre_sym = table.get_symbol_by_name("m7_precap_config")[0]
    assert boot_sym["st_size"] == RING_BOOT_BYTES
    assert cfg_sym["st_size"] == M7_CONFIG_BYTES
    assert pre_sym["st_size"] == M7_PRECAP_BYTES

    boot_offset = symbols["m7_s7_ring_boot"] - BASE
    assert header_sz <= boot_offset and boot_offset + RING_BOOT_BYTES <= ro_size
    assert rw_vaddr <= symbols["m7_config"] and symbols["m7_config"] + M7_CONFIG_BYTES <= rw_vaddr + rw_memsz
    assert rw_vaddr <= symbols["m7_precap_config"] and symbols["m7_precap_config"] + M7_PRECAP_BYTES <= rw_vaddr + rw_memsz

    struct.pack_into("<4I", image, boot_offset, RING_BOOT_MAGIC, RING_BOOT_VERSION, rw_vaddr, rw_memsz)

    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident, 2, 40, 1, symbols["_start"], 52, 0, 0x5000000, 52, 32, 2, 0, 0, 0,
    )
    phdr_rx = struct.pack("<8I", 1, 0, BASE, BASE, ro_size, ro_size, 5, 4096)
    phdr_rw = struct.pack("<8I", 1, rw_file_off, rw_vaddr, rw_vaddr, rw_filesz, rw_memsz, 6, 4096)
    image[0:header_sz] = ehdr + phdr_rx + phdr_rw

    meta = dict(
        file="stage7_ring.elf",
        sha256=sha(bytes(image)),
        bytes=len(image),
        base=BASE,
        entry=symbols["_start"],
        ro_size=ro_size,
        rw_file_offset=rw_file_off,
        rw_vaddr=rw_vaddr,
        rw_filesz=rw_filesz,
        rw_memsz=rw_memsz,
        boot_offset=boot_offset,
        boot_bytes=RING_BOOT_BYTES,
        nonce_offset=boot_offset + 16,
    )
    return bytes(image), meta


def build_all_once(ram_root: str = "/tmp_network") -> tuple[dict[str, bytes], dict]:
    layout.verify(ROOT)
    extra_defs: tuple[str, ...] = () if ram_root == "/tmp_network" else (f'-DS7_RAM_ROOT="{ram_root}"',)
    with tempfile.TemporaryDirectory(prefix="s7-build-", dir=HERE) as tmp:
        wdir = Path(tmp)
        pins_meta = generate_sony_pins_header(wdir)
        shim_bytes, req_bytes, shim_meta = build_mlv2_shim_and_req(wdir, extra_defs=extra_defs)
        core_bytes, core_meta = build_mlv2_core(wdir, extra_defs=extra_defs)
        guard_bytes, guard_meta_raw, _ = build_single_rx_arm_elf(
            HERE / "mlv2_guard.c", "mlv2_guard.o", "mlv2_guard.elf", wdir, extra_defs=extra_defs
        )
        guard_meta = {k: v for k, v in guard_meta_raw.items() if k != "symbols"}

        precap_bytes = build_precap_mod.build_module(extra_defs=extra_defs)
        if ram_root == "/tmp_network":
            # Confirm Astra's standalone PreCapture.mod seal still matches byte for byte.
            sealed_precap = build_precap_mod.verify_seal()
            if precap_bytes != sealed_precap:
                raise ValueError("PreCapture.mod build diverged from sealed precap-build.json")
        precap_meta = dict(
            file="PreCapture.mod",
            bytes=len(precap_bytes),
            sha256=sha(precap_bytes),
        )

        daemon_bytes, daemon_meta_raw, daemon_tbl = build_single_rx_arm_elf(
            HERE / "stage7_daemon.c", "stage7_daemon.o", "stage7_daemon.elf", wdir, extra_defs=extra_defs
        )
        cfg_sym = daemon_tbl.get_symbol_by_name("m7_s7_daemon_config")[0]
        if cfg_sym["st_size"] != DAEMON_CONFIG_BYTES:
            raise ValueError(f"m7_s7_daemon_config size {cfg_sym['st_size']} != {DAEMON_CONFIG_BYTES}")
        cfg_off = daemon_meta_raw["symbols"]["m7_s7_daemon_config"] - BASE
        if struct.unpack_from("<2I", daemon_bytes, cfg_off) != (DAEMON_MAGIC, DAEMON_VERSION):
            raise ValueError("m7_s7_daemon_config magic/version mismatch")
        census = assert_zero_ptrace_in_daemon(daemon_bytes, daemon_meta_raw)
        daemon_meta = dict(
            file="stage7_daemon.elf",
            sha256=daemon_meta_raw["sha256"],
            bytes=daemon_meta_raw["bytes"],
            base=BASE,
            entry=daemon_meta_raw["entry"],
            config_offset=cfg_off,
            config_bytes=DAEMON_CONFIG_BYTES,
            config_version=DAEMON_VERSION,
            syscall_census=census,
        )

        ring_bytes, ring_meta = build_stage7_ring(wdir, extra_defs=extra_defs)

    artifacts = {
        "shim.bin": shim_bytes,
        "core.bin": core_bytes,
        "mlv2.req": req_bytes,
        "mlv2_guard.elf": guard_bytes,
        "PreCapture.mod": precap_bytes,
        "stage7_daemon.elf": daemon_bytes,
        "stage7_ring.elf": ring_bytes,
    }
    manifest = dict(
        stage="7.1",
        target="DSC-RX100M7 1.00 (29110_03.2021050601)",
        ram_root=ram_root,
        reference_bases=dict(
            viewUnified2=f"{layout.REF_VIEW_BASE:#010x}",
            shim_cave=f"{layout.REF_SHIM_ADDR:#010x}",
            libObj=f"{layout.REF_LIBOBJ_BASE:#010x}",
        ),
        total_artifact_bytes=sum(len(v) for v in artifacts.values()),
        artifacts=dict(
            shim=shim_meta["shim"],
            request=shim_meta["request"],
            core=core_meta,
            guard=guard_meta,
            precap_mod=precap_meta,
            daemon=daemon_meta,
            ring=ring_meta,
        ),
        sony_library_pins=pins_meta,
        native_source_hashes=collect_native_hashes(),
        host_source_hashes=collect_host_hashes(),
    )
    return artifacts, manifest


EXPECTED_ARTIFACTS = {
    "shim": "shim.bin",
    "request": "mlv2.req",
    "core": "core.bin",
    "guard": "mlv2_guard.elf",
    "precap_mod": "PreCapture.mod",
    "daemon": "stage7_daemon.elf",
    "ring": "stage7_ring.elf",
}


def load_json_strict(path: Path) -> dict:
    def reject_dups(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError(f"Duplicate JSON key in {path}: {k!r}")
            obj[k] = v
        return obj

    parsed = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_dups)
    if not isinstance(parsed, dict):
        raise ValueError(f"Manifest {path} is not a JSON object")
    return parsed


def _parse_single_rx_elf(data: bytes, name: str) -> tuple[int, int]:
    if len(data) < 84 or data[:4] != b"\x7fELF":
        raise ValueError(f"{name}: invalid ELF header")
    e_type, e_machine, _, e_entry, e_phoff, _, _, e_ehsize, e_phentsize, e_phnum = struct.unpack_from(
        "<HHIIIIIHHH", data, 16
    )
    if (e_type, e_machine, e_phoff, e_ehsize, e_phentsize, e_phnum) != (2, 40, 52, 52, 32, 1):
        raise ValueError(f"{name}: unexpected ELF header layout")
    p_type, p_off, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack_from("<8I", data, 52)
    if (p_type, p_off, p_vaddr, p_filesz, p_memsz, p_flags) != (1, 0, BASE, len(data), len(data), 5):
        raise ValueError(f"{name}: unexpected single RX PT_LOAD segment")
    if not (BASE + 84 <= e_entry < BASE + len(data)):
        raise ValueError(f"{name}: entry {e_entry:#x} out of range")
    return BASE, e_entry


def derive_artifacts_metadata(out_dir: Path) -> tuple[dict, int]:
    """Independently re-derive EVERY runner-facing offset, entry, relocation, segment,
    header, and syscall census directly from the seven sealed files on disk.
    """
    raw: dict[str, bytes] = {}
    for key, fname in EXPECTED_ARTIFACTS.items():
        p = out_dir / fname
        if not p.is_file():
            raise ValueError(f"Missing sealed artifact: {p}")
        raw[key] = p.read_bytes()

    # 1. shim.bin & mlv2.req cross-check
    shim_data = raw["shim"]
    req_data = raw["request"]
    if len(shim_data) == 0 or len(shim_data) > SHIM_CAP or (len(shim_data) & 3) or shim_data[:4] != b"\x00\x00\x00\x00":
        raise ValueError("Invalid shim.bin size or slot")
    if len(req_data) < 36 + 12 + len(shim_data) + 4:
        raise ValueError("Truncated mlv2.req")
    h = struct.unpack_from("<9I", req_data, 0)
    if (h[0], h[1], h[2], h[3], h[7], h[8]) != (
        REQ_MAGIC, 2, layout.REF_SHIM_ADDR, len(shim_data), fnv1a_32(shim_data), 1
    ):
        raise ValueError("mlv2.req header mismatch against shim.bin / layout")
    v1_triple = struct.unpack_from("<3I", req_data, 36)
    if v1_triple != (0, 0, 0):
        raise ValueError(f"Unexpected v1 triple in mlv2.req: {v1_triple}")
    req_shim = req_data[48:48 + len(shim_data)]
    if req_shim != shim_data:
        raise ValueError("mlv2.req embedded shim payload differs from shim.bin")
    nrel = struct.unpack_from("<I", req_data, 48 + len(shim_data))[0]
    expected_req_len = 48 + len(shim_data) + 4 + nrel * 4
    if len(req_data) != expected_req_len:
        raise ValueError(f"mlv2.req length {len(req_data)} != expected {expected_req_len}")
    relocs = list(struct.unpack_from(f"<{nrel}I", req_data, 52 + len(shim_data)))
    for r in relocs:
        off = r & 0x3FFFFFFF
        if (r >> 30) != 1 or off < 4 or off + 4 > len(shim_data) or (off & 3):
            raise ValueError(f"Invalid relocation entry {r:#x} in mlv2.req")
    entries = {
        "ml_hook_set_root": h[4],
        "ml_hook_refresh": h[5],
        "ml_hook_open_item": h[6],
    }
    if not all((v & 1) and layout.REF_SHIM_ADDR < v < layout.REF_SHIM_ADDR + len(shim_data) for v in entries.values()):
        raise ValueError(f"Invalid shim entry addresses in mlv2.req: {entries}")
    shim_meta = dict(
        file="shim.bin",
        addr=layout.REF_SHIM_ADDR,
        bytes=len(shim_data),
        cap=SHIM_CAP,
        fnv1a_32=f"{fnv1a_32(shim_data):#010x}",
        sha256=sha(shim_data),
        entries={k: f"{v:#010x}" for k, v in entries.items()},
        relocs=dict(view=[hex(r & 0x3FFFFFFF) for r in relocs]),
    )
    req_meta = dict(
        file="mlv2.req",
        bytes=len(req_data),
        sha256=sha(req_data),
        reloc_count=nrel,
    )

    # 2. core.bin
    core_data = raw["core"]
    if len(core_data) <= 20:
        raise ValueError("Truncated core.bin")
    cmagic, cver, csize, cfnv, cinit = struct.unpack_from("<5I", core_data, 0)
    ccode = core_data[20:]
    if (cmagic, cver, csize, cfnv, cinit) != (CORE_MAGIC, CORE_VERSION, len(ccode), fnv1a_32(ccode), 1):
        raise ValueError("core.bin header/FNV mismatch")
    if len(ccode) > CORE_MAX or (len(ccode) & 3):
        raise ValueError("core.bin invalid code size")
    core_meta = dict(
        file="core.bin",
        code_bytes=len(ccode),
        bytes=len(core_data),
        fnv1a_32=f"{cfnv:#010x}",
        init_off=cinit,
        sha256=sha(core_data),
    )

    # 3. mlv2_guard.elf
    guard_data = raw["guard"]
    g_base, g_entry = _parse_single_rx_elf(guard_data, "mlv2_guard.elf")
    guard_meta = dict(
        file="mlv2_guard.elf",
        sha256=sha(guard_data),
        bytes=len(guard_data),
        base=g_base,
        entry=g_entry,
    )

    # 4. PreCapture.mod (also cross-verified by build_precap_mod.verify_seal)
    precap_data = raw["precap_mod"]
    precap_meta = dict(
        file="PreCapture.mod",
        bytes=len(precap_data),
        sha256=sha(precap_data),
    )

    # 5. stage7_daemon.elf
    daemon_data = raw["daemon"]
    d_base, d_entry = _parse_single_rx_elf(daemon_data, "stage7_daemon.elf")
    cfg_needle = struct.pack("<2I", DAEMON_MAGIC, DAEMON_VERSION)
    cfg_hits = [
        off for off in range(84, len(daemon_data) - DAEMON_CONFIG_BYTES + 1, 4)
        if daemon_data[off:off + 8] == cfg_needle and daemon_data[off + 52:off + 64] == b"0" * 12
    ]
    if len(cfg_hits) != 1:
        raise ValueError(f"Expected unique m7_s7_daemon_config in stage7_daemon.elf, found {cfg_hits}")
    daemon_meta = dict(
        file="stage7_daemon.elf",
        sha256=sha(daemon_data),
        bytes=len(daemon_data),
        base=d_base,
        entry=d_entry,
        config_offset=cfg_hits[0],
        config_bytes=DAEMON_CONFIG_BYTES,
        config_version=DAEMON_VERSION,
        syscall_census=assert_zero_ptrace_in_daemon_bytes(daemon_data),
    )

    # 6. stage7_ring.elf
    ring_data = raw["ring"]
    if len(ring_data) < 116 or ring_data[:4] != b"\x7fELF":
        raise ValueError("stage7_ring.elf: invalid ELF header")
    e_type, e_machine, _, r_entry, e_phoff, _, _, e_ehsize, e_phentsize, e_phnum = struct.unpack_from(
        "<HHIIIIIHHH", ring_data, 16
    )
    if (e_type, e_machine, e_phoff, e_ehsize, e_phentsize, e_phnum) != (2, 40, 52, 52, 32, 2):
        raise ValueError("stage7_ring.elf: unexpected ELF header layout")
    p0 = struct.unpack_from("<8I", ring_data, 52)
    p1 = struct.unpack_from("<8I", ring_data, 84)
    if (p0[0], p0[1], p0[2], p0[6]) != (1, 0, BASE, 5) or p0[4] != p0[5]:
        raise ValueError("stage7_ring.elf: unexpected RX PT_LOAD[0]")
    if (p1[0], p1[6]) != (1, 6) or p1[1] != align_up(p0[4], 4096) or p1[2] != BASE + p1[1]:
        raise ValueError("stage7_ring.elf: unexpected RW PT_LOAD[1]")
    if p1[1] + p1[4] != len(ring_data) or p1[5] != align_up(p1[4], 4096):
        raise ValueError("stage7_ring.elf: RW PT_LOAD[1] size mismatch")
    ro_size, rw_file_off, rw_vaddr, rw_filesz, rw_memsz = p0[4], p1[1], p1[2], p1[4], p1[5]
    boot_needle = struct.pack("<4I", RING_BOOT_MAGIC, RING_BOOT_VERSION, rw_vaddr, rw_memsz)
    boot_hits = [
        off for off in range(116, ro_size - RING_BOOT_BYTES + 1, 4)
        if ring_data[off:off + 16] == boot_needle and ring_data[off + 16:off + 28] == b"0" * 12
    ]
    if len(boot_hits) != 1:
        raise ValueError(f"Expected unique m7_s7_ring_boot in stage7_ring.elf, found {boot_hits}")
    ring_meta = dict(
        file="stage7_ring.elf",
        sha256=sha(ring_data),
        bytes=len(ring_data),
        base=BASE,
        entry=r_entry,
        ro_size=ro_size,
        rw_file_offset=rw_file_off,
        rw_vaddr=rw_vaddr,
        rw_filesz=rw_filesz,
        rw_memsz=rw_memsz,
        boot_offset=boot_hits[0],
        boot_bytes=RING_BOOT_BYTES,
        nonce_offset=boot_hits[0] + 16,
    )

    derived = dict(
        shim=shim_meta,
        request=req_meta,
        core=core_meta,
        guard=guard_meta,
        precap_mod=precap_meta,
        daemon=daemon_meta,
        ring=ring_meta,
    )
    return derived, sum(len(v) for v in raw.values())


def strict_equal(a, b) -> bool:
    """Strict structural & type equality (rejects bool==int and float==int in JSON)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(strict_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(strict_equal(x, y) for x, y in zip(a, b))
    return a == b


def verify_seal(out_dir: Path = OUT) -> dict:
    build_json = out_dir / "build.json"
    if not build_json.is_file():
        raise ValueError(f"Missing {build_json}")
    manifest = load_json_strict(build_json)
    with tempfile.TemporaryDirectory(prefix="s7-pin-") as tmp:
        expected_pins = generate_sony_pins_header(Path(tmp))
    derived_artifacts, total_bytes = derive_artifacts_metadata(out_dir)
    expected_manifest = dict(
        stage="7.1",
        target="DSC-RX100M7 1.00 (29110_03.2021050601)",
        ram_root="/tmp_network",
        reference_bases=dict(
            viewUnified2=f"{layout.REF_VIEW_BASE:#010x}",
            shim_cave=f"{layout.REF_SHIM_ADDR:#010x}",
            libObj=f"{layout.REF_LIBOBJ_BASE:#010x}",
        ),
        total_artifact_bytes=total_bytes,
        artifacts=derived_artifacts,
        sony_library_pins=expected_pins,
        native_source_hashes=collect_native_hashes(),
        host_source_hashes=collect_host_hashes(),
    )
    if not strict_equal(manifest, expected_manifest):
        if set(manifest.keys()) != set(expected_manifest.keys()):
            raise ValueError(f"Stage 7.1 manifest top-level keys mismatch: {sorted(manifest.keys())}")
        for k in sorted(expected_manifest.keys()):
            if not strict_equal(manifest[k], expected_manifest[k]):
                raise ValueError(f"Stage 7.1 manifest field {k!r} mismatch (rebuild required)")
        raise ValueError("Stage 7.1 manifest mismatch")
    build_precap_mod.verify_seal(out_dir)
    layout.verify(ROOT)
    return manifest


def main() -> int:
    art1, man1 = build_all_once()
    art2, man2 = build_all_once()
    if art1 != art2 or man1 != man2:
        raise RuntimeError("Reproducibility check failed: two clean builds differed")
    OUT.mkdir(exist_ok=True)
    for name, data in art1.items():
        (OUT / name).write_bytes(data)
    (OUT / "build.json").write_text(json.dumps(man1, indent=2, sort_keys=True) + "\n")
    verified = verify_seal(OUT)
    print(f"PASS: Stage 7.1 reproducible sealed build ({verified['total_artifact_bytes']} bytes total)")
    for k, info in verified["artifacts"].items():
        print(f"  {info['file']:18s} {info['bytes']:6d} B  {info['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
