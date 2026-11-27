"""Build and verify the standalone Stage 7.1 settings module."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "out"
SCRIPT = ROOT / "sources/bionz-x-research/tools/native_camera/mlv2/mod_v2.ld"
OPTIONS = ("1", "2", "3", "5", "8", "10")


def fnv(data):
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    return value


def linker():
    if os.environ.get("LD_LLD"):
        return [os.environ["LD_LLD"]]
    if shutil.which("ld.lld"):
        return ["ld.lld"]
    candidates = sorted(Path.home().glob(".rustup/toolchains/stable-*/lib/rustlib/*/bin/rust-lld"))
    if candidates:
        return [str(candidates[0]), "-flavor", "gnu"]
    raise RuntimeError("Install LLVM LLD or set LD_LLD to the GNU-flavor ld.lld executable")


def compile_thumb(source, entry, directory, extra_defs=()):
    obj = directory / "component.o"
    elf = directory / "component.elf"
    subprocess.run(["clang", "--target=armv7-none-eabi", "-mthumb", "-mfloat-abi=soft",
                    "-Oz", "-fPIC", "-fomit-frame-pointer", "-ffreestanding", "-fno-builtin",
                    "-fno-stack-protector", "-fno-unwind-tables", "-Wall", "-Wextra", "-Werror",
                    "-I", str(HERE), *extra_defs, "-c", str(source), "-o", str(obj)], check=True)
    subprocess.run([*linker(), "-T", str(SCRIPT), "-e", entry, "--no-undefined",
                    str(obj), "-o", str(elf)], check=True)
    linked = ELFFile(io.BytesIO(elf.read_bytes()))
    section = linked.get_section_by_name(".text")
    if section["sh_addr"] != 0 or any(
        s["sh_flags"] & 2 and s["sh_size"] and s.name != ".text" for s in linked.iter_sections()
    ):
        raise ValueError("Unexpected module memory layout")
    code = section.data()
    offset = linked.header["e_entry"]
    if not (offset & 1 and offset < len(code)):
        raise ValueError("Invalid Thumb callback")
    return code, offset


def build_module(extra_defs=()):
    with tempfile.TemporaryDirectory(dir=HERE) as directory:
        code, entry = compile_thumb(HERE / "precap_mod.c", "precap_lifecycle", Path(directory), extra_defs=extra_defs)
    header = struct.pack("<4sII32s6I", b"SMOD", 2, 32, b"Pre-Capture", len(code),
                         fnv(code), 1, entry, entry, 0)
    submenu = struct.pack("<4sBBHI", b"SMNU", 1, 0, 0, entry)
    submenu += struct.pack("<BB2x24s" + "18s" * 6, len(OPTIONS), 3, b"Pre-Frames",
                           *(s.encode("ascii") for s in OPTIONS))
    return header + code + submenu + struct.pack("<I", fnv(submenu))


def manifest(image):
    def hashes(files):
        return {str(f.relative_to(ROOT)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    return {"scope": "standalone Pre-Capture settings module", "file": "PreCapture.mod",
            "bytes": len(image), "sha256": hashlib.sha256(image).hexdigest(),
            "native_source_hashes": hashes([HERE / "precap_mod.c", HERE / "stage7_common.h", SCRIPT]),
            "host_source_hashes": hashes([Path(__file__).resolve(), HERE / "test_stage7_unicorn.py"])}


def verify_seal(directory=OUT):
    image = (directory / "PreCapture.mod").read_bytes()
    if json.loads((directory / "precap-build.json").read_text()) != manifest(image):
        raise ValueError("Pre-Capture module or source hash mismatch")
    return image


if __name__ == "__main__":
    image = build_module()
    if build_module() != image:
        raise RuntimeError("Module builds differ")
    OUT.mkdir(exist_ok=True)
    (OUT / "PreCapture.mod").write_bytes(image)
    (OUT / "precap-build.json").write_text(json.dumps(manifest(image), indent=2, sort_keys=True) + "\n")
    verify_seal()
    print("PASS: two identical PreCapture.mod builds and module source seal")
