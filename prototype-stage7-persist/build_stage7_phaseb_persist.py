"""Reproducible builder and seal verifier for Stage 7.3 Phase B (DSC-RX100M7 1.00).

Builds and seals under prototype-stage7-persist/out-phaseb-persist/:
  1. mlv2_sd_boot_hook.so   (zero-dependency ARM32 EABI preload constructor targeting /usr/bin/bsa_server)
  2. mlv2_card_read.elf     (freestanding ARM32 FAT32/exFAT + HMAC-SHA256 reader for /tmp_bt + /setting/mlv2_owner.key)
  3. mlv2_sd_boot.sh        (BusyBox v1.13.4-strict S2R+WBI SD boot/monitor worker using /tmp_bt)
  4. card.ustar             (deterministic 6-member USTAR archive compiled for S7_RAM_ROOT="/tmp_bt")
  5. build-phaseb-persist.json (complete reproducible manifest & source/seal hashes)
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import build_stage7  # noqa: E402
import build_stage7_sd  # noqa: E402
from build_precap_mod import linker  # noqa: E402

OUT_PERSIST = HERE / "out-phaseb-persist"
HOOK_SOURCE = HERE / "mlv2_sd_boot_hook.c"
BOOT_SCRIPT = HERE / "mlv2_phaseb_sd_boot.sh"
INSTALL_SCRIPT = ROOT / "scripts/m7_stage7_phaseb_install.py"
TEST_SCRIPT = HERE / "test_stage7_phaseb_persist.py"
KERNEL_INFO = ROOT / "evidence/m7-kernel-analysis/analysis.json"

PHASEB_RAM_ROOT = "/tmp_bt"
PHASEB_KEY_PATH = "/setting/mlv2_owner.key"
PHASEB_DEFS = (
    f'-DS7_RAM_ROOT="{PHASEB_RAM_ROOT}"',
    f'-DS7_OWNER_KEY_PATH="{PHASEB_KEY_PATH}"',
)

HOOK_SLOTS = {
    1: "sys_exit",
    2: "sys_fork_wrapper",
    5: "sys_open",
    6: "sys_close",
    11: "sys_execve_wrapper",
    33: "sys_access",
    63: "sys_dup2",
    66: "sys_setsid",
    85: "sys_readlink",
    114: "sys_wait4",
    199: "sys_getuid",
}

HOOK_CFLAGS = [
    "--target=armv7-none-eabi",
    "-mcpu=cortex-a5",
    "-marm",
    "-mfloat-abi=soft",
    "-Os",
    "-fPIC",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fomit-frame-pointer",
    "-fno-unwind-tables",
    "-fno-asynchronous-unwind-tables",
    "-Wall",
    "-Wextra",
    "-Werror",
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_hook_kernel_slots() -> dict[int, tuple[str, str, str]]:
    info = json.loads(KERNEL_INFO.read_text(encoding="utf-8"))

    def checked(section: str) -> bytes:
        data = (ROOT / info[section]["path"]).read_bytes()
        if sha256_bytes(data) != info[section]["sha256"]:
            raise ValueError(f"{section} fingerprint mismatch")
        return data

    kernel = checked("kernel")
    symbols = {
        row[2]: int(row[0], 16)
        for row in (line.split() for line in checked("kallsyms").decode().splitlines())
    }
    base = info["base_address"]
    table = symbols["sys_call_table"] - base
    verified: dict[int, tuple[str, str, str]] = {}
    for slot, name in sorted(HOOK_SLOTS.items()):
        offset = table + 4 * slot
        (address,) = struct.unpack_from("<I", kernel, offset)
        if address != symbols[name]:
            raise ValueError(f"Hook syscall slot {slot} resolved to {address:#x} != {name}")
        verified[slot] = (name, hex(offset), hex(address))
    return verified


def inspect_hook_so(binary: bytes) -> dict:
    elf = ELFFile(io.BytesIO(binary))
    if elf.elfclass != 32 or elf["e_machine"] != "EM_ARM" or elf["e_type"] != "ET_DYN":
        raise ValueError("Expected ARM32 ET_DYN shared object for mlv2_sd_boot_hook.so")
    dyn = elf.get_section_by_name(".dynamic")
    if dyn is None:
        raise ValueError("Missing .dynamic section in mlv2_sd_boot_hook.so")
    tags = {t.entry.d_tag: t.entry.d_val for t in dyn.iter_tags()}
    needed = [t.needed for t in dyn.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
    if needed:
        raise ValueError(f"mlv2_sd_boot_hook.so must have zero DT_NEEDED entries, found {needed}")
    if "DT_INIT_ARRAY" not in tags or tags.get("DT_INIT_ARRAYSZ", 0) != 4:
        raise ValueError(f"Expected single 4-byte DT_INIT_ARRAY constructor, got {tags}")
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is not None:
        undef = [s.name for s in dynsym.iter_symbols() if s.name and s["st_shndx"] == "SHN_UNDEF"]
        if undef:
            raise ValueError(f"mlv2_sd_boot_hook.so has undefined dynamic symbols: {undef}")
    for sec in elf.iter_sections():
        if sec["sh_type"] == "SHT_REL":
            for rel in sec.iter_relocations():
                if rel["r_info_type"] != 23:  # R_ARM_RELATIVE
                    raise ValueError(f"Unexpected relocation type {rel['r_info_type']} in {sec.name}")
    # Verify exact ARM syscall census across $a instruction ranges in .text (skipping $d literal pools)
    text_idx = None
    text = None
    for idx, sec in enumerate(elf.iter_sections()):
        if sec.name == ".text":
            text_idx, text = idx, sec
            break
    if text is None or text["sh_size"] % 4 != 0:
        raise ValueError("Missing or unaligned .text in mlv2_sd_boot_hook.so")
    data = text.data()
    base = text["sh_addr"]
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        raise ValueError("Missing .symtab mapping symbols in mlv2_sd_boot_hook.so")
    maps = sorted(
        (sym["st_value"] - base, sym.name.split(".")[0])
        for sym in symtab.iter_symbols()
        if sym["st_shndx"] == text_idx and sym.name.startswith("$")
    )
    if not maps or maps[0][0] != 0 or any(kind not in ("$a", "$d") for _, kind in maps):
        raise ValueError(f"Unexpected ARM mapping symbols in .text: {maps}")
    code_ranges = []
    for k, (start_off, kind) in enumerate(maps):
        end_off = maps[k + 1][0] if k + 1 < len(maps) else len(data)
        if kind == "$a":
            code_ranges.append((start_off, end_off))
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    slots = set()
    for r_start, r_end in code_ranges:
        for i in range(r_start, r_end, 4):
            raw = int.from_bytes(data[i : i + 4], "little")
            if (raw >> 24) & 15 != 15:
                continue
            if raw != 0xEF000000:
                raise ValueError(f"Unexpected svc word {raw:#x} at +{i:#x}")
            found = None
            for back in range(i - 4, max(r_start - 4, i - 64), -4):
                ins = next(md.disasm(data[back : back + 4], base + back), None)
                if ins and ins.mnemonic in ("mov", "movw") and ins.op_str.startswith("r7, #"):
                    found = int(ins.op_str.split("#", 1)[1], 0)
                    break
            if found is None:
                raise ValueError(f"Unresolved r7 syscall slot before svc at +{i:#x}")
            slots.add(found)
    if slots != set(HOOK_SLOTS):
        raise ValueError(f"Hook syscall census mismatch: {sorted(slots)} != {sorted(HOOK_SLOTS)}")
    if b"/usr/bin/bsa_server\0" not in binary or b"/setting/disable_sd_boot\0" not in binary:
        raise ValueError("Hook binary missing required target/disable strings")
    if b"/tmp_network" in binary:
        raise ValueError("Unexpected /tmp_network string in hook binary")
    return {
        "file": "mlv2_sd_boot_hook.so",
        "bytes": len(binary),
        "sha256": sha256_bytes(binary),
        "init_array_va": hex(tags["DT_INIT_ARRAY"]),
        "syscalls": sorted(slots),
    }


def build_hook_once() -> bytes:
    with tempfile.TemporaryDirectory() as directory:
        obj = Path(directory) / "hook.o"
        so = Path(directory) / "mlv2_sd_boot_hook.so"
        subprocess.run(["clang", *HOOK_CFLAGS, "-c", HOOK_SOURCE, "-o", obj], check=True)
        subprocess.run(
            [
                *linker(),
                "-shared",
                "-Bsymbolic",
                "--build-id=none",
                "--no-undefined",
                "-z",
                "now",
                "-z",
                "noexecstack",
                "-z",
                "max-page-size=0x1000",
                obj,
                "-o",
                so,
            ],
            check=True,
        )
        binary = so.read_bytes()
    inspect_hook_so(binary)
    return binary


def build_phaseb_card_ustar() -> tuple[bytes, dict[str, dict[str, object]], dict]:
    artifacts, s7_manifest = build_stage7.build_all_once(ram_root=PHASEB_RAM_ROOT)
    for name, blob in artifacts.items():
        if b"/tmp_network" in blob:
            raise ValueError(f"Phase B artifact {name} still contains /tmp_network")
    daemon_bytes = build_stage7_sd.patch_sd_daemon(artifacts["stage7_daemon.elf"], s7_manifest)
    ring_bytes = build_stage7_sd.patch_sd_ring(artifacts["stage7_ring.elf"], s7_manifest)
    members = {
        "guard": artifacts["mlv2_guard.elf"],
        "mlv2.req": artifacts["mlv2.req"],
        "core.bin": artifacts["core.bin"],
        "PreCapture.mod": artifacts["PreCapture.mod"],
        "daemon": daemon_bytes,
        "ring.elf": ring_bytes,
    }
    member_meta: dict[str, dict[str, object]] = {}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name in build_stage7_sd.TAR_MEMBER_ORDER:
            data = members[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o500 if name in ("guard", "daemon", "ring.elf") else 0o444
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tf.addfile(info, io.BytesIO(data))
            member_meta[name] = {"bytes": len(data), "sha256": sha256_bytes(data)}
    payload = out.getvalue()
    if len(payload) == 0 or len(payload) % 512 != 0 or len(payload) > 384 * 1024:
        raise ValueError(f"Phase B card.ustar size {len(payload)} out of bounds")
    if b"/tmp_network" in payload:
        raise ValueError("Phase B card.ustar still contains /tmp_network")
    return payload, member_meta, s7_manifest


def check_phaseb_boot_script(script_bytes: bytes) -> None:
    build_stage7_sd.check_boot_script(script_bytes)
    if b"/tmp_network" in script_bytes:
        raise ValueError("mlv2_phaseb_sd_boot.sh must not reference /tmp_network")
    if b"/tmp_bt" not in script_bytes or b"/setting/mlv2_owner.key" not in script_bytes:
        raise ValueError("mlv2_phaseb_sd_boot.sh missing /tmp_bt or /setting/mlv2_owner.key defaults")


def build_manifest(
    hook_meta: dict,
    reader_bin: bytes,
    boot_sh: bytes,
    ustar_bytes: bytes,
    member_meta: dict,
    s7_manifest: dict,
) -> dict:
    source_paths = [
        HOOK_SOURCE,
        BOOT_SCRIPT,
        build_stage7_sd.SOURCE,
        Path(__file__).resolve(),
        INSTALL_SCRIPT,
        TEST_SCRIPT,
    ]
    test_signed = build_stage7_sd.sign_mlv2_tar(ustar_bytes, build_stage7_sd.TEST_SIGNING_KEY, release_seq=1)
    return {
        "scope": "Stage 7.3 Phase B persistent SD auto-boot release (/tmp_bt S2R-safe + bsa_server WBI trigger)",
        "target": "DSC-RX100M7 1.00 (29110_03.2021050601)",
        "ram_root": PHASEB_RAM_ROOT,
        "owner_key_path": PHASEB_KEY_PATH,
        "sd_boot_nonce": build_stage7_sd.SD_BOOT_NONCE,
        "artifacts": {
            "hook": hook_meta,
            "reader": {
                "file": "mlv2_card_read.elf",
                "bytes": len(reader_bin),
                "sha256": sha256_bytes(reader_bin),
            },
            "boot_script": {
                "file": "mlv2_sd_boot.sh",
                "bytes": len(boot_sh),
                "sha256": sha256_bytes(boot_sh),
            },
            "card_ustar": {
                "file": "card.ustar",
                "bytes": len(ustar_bytes),
                "sha256": sha256_bytes(ustar_bytes),
                "members": member_meta,
            },
        },
        "test_key_signed_mlv2_tar_bytes": len(test_signed),
        "test_key_signed_mlv2_tar_sha256": sha256_bytes(test_signed),
        "phaseb_native_source_hashes": s7_manifest["native_source_hashes"],
        "phaseb_host_source_hashes": {
            str(p.relative_to(ROOT)): sha256_bytes(p.read_bytes()) for p in source_paths
        },
    }


def verify_seal(directory: Path = OUT_PERSIST) -> dict:
    verify_hook_kernel_slots()
    build_stage7_sd.kernel_slots()
    hook_bin = (directory / "mlv2_sd_boot_hook.so").read_bytes()
    reader_bin = (directory / "mlv2_card_read.elf").read_bytes()
    boot_sh = (directory / "mlv2_sd_boot.sh").read_bytes()
    ustar_bytes = (directory / "card.ustar").read_bytes()

    hook_meta = inspect_hook_so(hook_bin)
    build_stage7_sd.inspect(reader_bin)
    if b"/tmp_network" in reader_bin:
        raise ValueError("Phase B mlv2_card_read.elf contains /tmp_network")
    if b"/tmp_bt" not in reader_bin or b"/setting/mlv2_owner.key" not in reader_bin:
        raise ValueError("Phase B mlv2_card_read.elf missing /tmp_bt or /setting/mlv2_owner.key")
    check_phaseb_boot_script(boot_sh)
    if boot_sh != BOOT_SCRIPT.read_bytes():
        raise ValueError("out-phaseb-persist/mlv2_sd_boot.sh differs from source mlv2_phaseb_sd_boot.sh")

    expected_ustar, member_meta, s7_manifest = build_phaseb_card_ustar()
    if ustar_bytes != expected_ustar:
        raise ValueError("Phase B card.ustar differs from clean rebuild")
    if hook_bin != build_hook_once():
        raise ValueError("Phase B mlv2_sd_boot_hook.so differs from clean rebuild")
    if reader_bin != build_stage7_sd.build_once(extra_defs=PHASEB_DEFS):
        raise ValueError("Phase B mlv2_card_read.elf differs from clean rebuild")

    manifest = build_manifest(hook_meta, reader_bin, boot_sh, ustar_bytes, member_meta, s7_manifest)
    stored = build_stage7.load_json_strict(directory / "build-phaseb-persist.json")
    if not build_stage7.strict_equal(stored, manifest):
        raise ValueError("Stage 7.3 Phase B manifest mismatch (rebuild required)")
    return manifest


def sign_package(owner_key_path: Path, out_path: Path, directory: Path = OUT_PERSIST, release_seq: int = 1) -> dict:
    manifest = verify_seal(directory)
    key = owner_key_path.read_bytes()
    ustar = (directory / "card.ustar").read_bytes()
    signed = build_stage7_sd.sign_mlv2_tar(ustar, key, release_seq=release_seq)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with tmp.open("wb") as f:
        f.write(signed)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out_path)
    return {
        "out_path": str(out_path),
        "bytes": len(signed),
        "sha256": sha256_bytes(signed),
        "card_ustar_sha256": manifest["artifacts"]["card_ustar"]["sha256"],
        "release_seq": release_seq,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="Read-only seal verification")
    parser.add_argument("--sign-package", action="store_true", help="Sign sealed card.ustar into MLV2.TAR")
    parser.add_argument("--owner-key", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--release-seq", type=int, default=1)
    args = parser.parse_args(argv)

    if args.verify:
        verified = verify_seal(OUT_PERSIST)
        print(
            f"PASS: Stage 7.3 Phase B sealed release verified "
            f"(hook={verified['artifacts']['hook']['bytes']} B, "
            f"reader={verified['artifacts']['reader']['bytes']} B, "
            f"boot_sh={verified['artifacts']['boot_script']['bytes']} B, "
            f"card.ustar={verified['artifacts']['card_ustar']['bytes']} B)"
        )
        return 0

    if args.sign_package:
        if args.owner_key is None or args.out is None:
            parser.error("--sign-package requires --owner-key and --out")
        res = sign_package(args.owner_key, args.out, release_seq=args.release_seq)
        print(json.dumps(res, indent=2))
        return 0

    verify_hook_kernel_slots()
    build_stage7_sd.kernel_slots()
    boot_sh = BOOT_SCRIPT.read_bytes()
    check_phaseb_boot_script(boot_sh)

    hook1 = build_hook_once()
    if hook1 != build_hook_once():
        raise RuntimeError("Non-reproducible mlv2_sd_boot_hook.so build")
    hook_meta = inspect_hook_so(hook1)

    reader1 = build_stage7_sd.build_once(extra_defs=PHASEB_DEFS)
    if reader1 != build_stage7_sd.build_once(extra_defs=PHASEB_DEFS):
        raise RuntimeError("Non-reproducible Phase B mlv2_card_read.elf build")
    if b"/tmp_network" in reader1 or b"/tmp_bt" not in reader1 or b"/setting/mlv2_owner.key" not in reader1:
        raise RuntimeError("Phase B mlv2_card_read.elf path verification failed")

    ustar1, member_meta, s7_manifest = build_phaseb_card_ustar()
    ustar2, _, _ = build_phaseb_card_ustar()
    if ustar1 != ustar2:
        raise RuntimeError("Non-reproducible Phase B card.ustar build")

    OUT_PERSIST.mkdir(exist_ok=True)
    manifest = build_manifest(hook_meta, reader1, boot_sh, ustar1, member_meta, s7_manifest)
    with tempfile.TemporaryDirectory(dir=OUT_PERSIST) as staging:
        sdir = Path(staging)
        (sdir / "mlv2_sd_boot_hook.so").write_bytes(hook1)
        (sdir / "mlv2_sd_boot_hook.so").chmod(0o755)
        (sdir / "mlv2_card_read.elf").write_bytes(reader1)
        (sdir / "mlv2_card_read.elf").chmod(0o755)
        (sdir / "mlv2_sd_boot.sh").write_bytes(boot_sh)
        (sdir / "mlv2_sd_boot.sh").chmod(0o755)
        (sdir / "card.ustar").write_bytes(ustar1)
        (sdir / "card.ustar").chmod(0o644)
        (sdir / "build-phaseb-persist.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        for name in (
            "mlv2_sd_boot_hook.so",
            "mlv2_card_read.elf",
            "mlv2_sd_boot.sh",
            "card.ustar",
            "build-phaseb-persist.json",
        ):
            os.replace(sdir / name, OUT_PERSIST / name)

    verified = verify_seal(OUT_PERSIST)
    print(
        f"PASS: Stage 7.3 Phase B sealed release built "
        f"(hook={verified['artifacts']['hook']['bytes']} B, "
        f"reader={verified['artifacts']['reader']['bytes']} B, "
        f"boot_sh={verified['artifacts']['boot_script']['bytes']} B, "
        f"card.ustar={verified['artifacts']['card_ustar']['bytes']} B)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
