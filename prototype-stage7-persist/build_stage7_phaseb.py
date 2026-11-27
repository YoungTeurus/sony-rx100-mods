"""Build or verify the offline Phase B filesystem inspector for M7 1.00."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile
from build_precap_mod import linker

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "out-phaseb"
SOURCE = HERE / "phaseb_statfs.c"
HOST = (Path(__file__).resolve(), HERE / "test_stage7_phaseb_collect.py",
        ROOT / "scripts/m7_stage7_phaseb_collect.py", HERE / "build_precap_mod.py")
BINARY = "phaseb_statfs.elf"
MANIFEST = "build-phaseb.json"
KERNEL = ROOT / "extracted/m7-kernel-file-20261105T210321Z-78319ef81a60/system/vmlinux.bin"
SYMBOLS = ROOT / "evidence/m7-kernel-analysis/m7.kallsyms"
PINS = {KERNEL: "fbc91e66ce27ea917041c33c53e038bfc92e0cf8aea6f254f9dae01acefdfaeb",
        SYMBOLS: "d4c990382c1071631863944ee8f09612e78542746d35b0ebe894d7d2bfcb546b"}
SLOTS = {4: "sys_write", 196: "sys_lstat64", 197: "sys_fstat64",
         248: "sys_exit_group", 266: "sys_statfs64_wrapper"}
FLAGS = ["--target=armv7-none-eabi", "-mcpu=cortex-a5", "-marm", "-mfloat-abi=soft",
         "-Os", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
         "-fno-unwind-tables", "-fomit-frame-pointer", "-nostdlib", "-Wall", "-Wextra", "-Werror"]
LAYOUT = """
ENTRY(_start)
PHDRS { image PT_LOAD FILEHDR PHDRS FLAGS(5); }
SECTIONS {
  . = 0x10000 + SIZEOF_HEADERS;
  .text : { *(.text*) } :image
  .rodata : { *(.rodata*) } :image
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) *(.note*) }
}
"""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def kernel_abi():
    data = {path: path.read_bytes() for path in PINS}
    if any(digest(data[path]) != value for path, value in PINS.items()):
        raise ValueError("Original kernel or symbol fingerprint mismatch")
    symbols = {name: int(addr, 16) for addr, _, name in
               (line.split() for line in data[SYMBOLS].decode().splitlines())}
    base = 0x60108000

    def word(va):
        return struct.unpack_from("<I", data[KERNEL], va - base)[0]

    for slot, name in SLOTS.items():
        if word(symbols["sys_call_table"] + 4 * slot) != symbols[name]:
            raise ValueError(f"Unexpected syscall slot {slot}")
    # Size check, copy_to_user lengths and stores to user st_dev and st_mode.
    for va, expected in {0x601e5298: 0xe3510054, 0x601e4f24: 0xe3a02054,
                         0x601c2ea4: 0xe3a02068, 0x601c2dcc: 0xe50b307c,
                         0x601c2e10: 0xe50b306c}.items():
        if word(va) != expected:
            raise ValueError(f"Unexpected ABI instruction at {va:#x}")
    return {str(slot): [name, hex(symbols[name])] for slot, name in SLOTS.items()}


def inspect(binary):
    elf = ELFFile(io.BytesIO(binary))
    segments = list(elf.iter_segments())
    if not (len(binary) <= 8192 and elf.elfclass == 32 and elf.little_endian
            and elf["e_machine"] == "EM_ARM" and elf["e_type"] == "ET_EXEC"
            and elf["e_flags"] >> 24 == 5 and len(segments) == 1
            and segments[0]["p_type"] == "PT_LOAD" and segments[0]["p_flags"] == 5):
        raise ValueError("Unexpected executable layout")
    symbols = list(elf.get_section_by_name(".symtab").iter_symbols())
    if any(s.name and s["st_shndx"] == "SHN_UNDEF" for s in symbols):
        raise ValueError("Undefined symbol")
    text = elf.get_section_by_name(".text")
    code = text.data()
    start = text["sh_addr"]
    segment = segments[0]
    if (not start <= elf["e_entry"] < start + len(code)
            or segment["p_memsz"] != segment["p_filesz"]
            or any(s["sh_size"] and s["sh_flags"] & 2 and s.name not in (".text", ".rodata")
                   for s in elf.iter_sections())):
        raise ValueError("Unexpected entry point or allocated section")
    wrappers = {"pb_lstat": 196, "pb_statfs": 266, "pb_stdout": 4, "pb_exit": 248}
    sites = set()
    for name, slot in wrappers.items():
        sym, = [s for s in symbols if s.name == name]
        off = sym["st_value"] - start
        words = [0xe1a0c007]  # mov ip, r7
        if name == "pb_stdout":
            words += [0xe1a02001, 0xe1a01000, 0xe3a00001]  # r0 = stdout
        words += [0xe3007000 | slot, 0xef000000, 0xe1a0700c, 0xe12fff1e]
        if struct.unpack_from("<" + "I" * len(words), code, off) != tuple(words):
            raise ValueError(f"Unexpected {name} instructions")
        sites.add(off + 4 * (len(words) - 3))
    actual = {i for i in range(0, len(code), 4) if code[i+3] & 0x0f == 0x0f}
    if actual != sites or any(s.name.split(".")[0] == "$t" for s in symbols):
        raise ValueError("Unexpected supervisor call sites or Thumb instructions")


def compile_once():
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        (directory / "layout.ld").write_text(LAYOUT)
        subprocess.run(["clang", *FLAGS, "-c", SOURCE, "-o", directory / "probe.o"], check=True)
        subprocess.run([*linker(), "-T", "layout.ld", "--no-undefined", "--build-id=none",
                        "-static", "probe.o", "-o", BINARY], cwd=directory, check=True)
        data = (directory / BINARY).read_bytes()
    inspect(data)
    return data


def manifest_bytes(binary):
    manifest = {
        "target": "DSC-RX100M7 29110_03.2021050601",
        "scope": "Offline filesystem inspector; no hardware qualification",
        "file": BINARY, "bytes": len(binary), "sha256": digest(binary),
        "md5": hashlib.md5(binary).hexdigest(), "kernel_slots": kernel_abi(),
        "original_hashes": {str(p.relative_to(ROOT)): h for p, h in PINS.items()},
        "host_source_hashes": {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in HOST},
        "native_source_hashes": {str(SOURCE.relative_to(ROOT)): digest(SOURCE.read_bytes())},
    }
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()


def verify_seal(directory=OUT):
    binary = (directory / BINARY).read_bytes()
    if binary != compile_once() or (directory / MANIFEST).read_bytes() != manifest_bytes(binary):
        raise ValueError("Phase B artifact or source seal mismatch")
    return digest(binary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    if not parser.parse_args().verify:
        data = compile_once()
        if data != compile_once():
            raise ValueError("Independent builds differ")
        manifest = manifest_bytes(data)
        OUT.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=OUT) as temp:
            staging = Path(temp)
            (staging / BINARY).write_bytes(data)
            (staging / BINARY).chmod(0o700)
            (staging / MANIFEST).write_bytes(manifest)
            for name in (BINARY, MANIFEST):
                os.replace(staging / name, OUT / name)
    print("PASS Phase B offline inspector", verify_seal())


if __name__ == "__main__":
    main()
