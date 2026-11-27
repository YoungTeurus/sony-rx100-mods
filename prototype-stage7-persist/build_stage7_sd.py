"""Reproducible builder and seal verifier for Stage 7.3 Phase A (DSC-RX100M7 1.00).

Builds and seals under prototype-stage7-persist/out-sd/:
  1. mlv2_card_read.elf  (freestanding ARM32 FAT32/exFAT + HMAC-SHA256 + USTAR reader/extractor)
  2. mlv2_sd_boot.sh     (BusyBox v1.13.4-strict SD boot/monitor worker)
  3. card.ustar          (deterministic 6-member USTAR archive built from sealed Stage 7.1 artifacts)
  4. build-sd.json       (complete reproducible manifest & source/seal pins)

Also exports sign_mlv2_tar(ustar_bytes, key_32b, release_seq) for one-file M7SD1 MLV2.TAR signing.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import tempfile

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

import build_stage7
from build_precap_mod import linker

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT_SD = HERE / "out-sd"
SOURCE = HERE / "mlv2_card_read.c"
BOOT_SCRIPT = HERE / "mlv2_sd_boot.sh"
PROBE_SCRIPT = ROOT / "scripts/m7_stage7_sd_probe.py"
TEST_SCRIPT = HERE / "test_stage7_sd.py"
KERNEL_INFO = ROOT / "evidence/m7-kernel-analysis/analysis.json"

TARGET_BUILD = b"29110_03.2021050601"
SD_BOOT_NONCE = "5d0000000001"
SD_DAEMON_MAX_LOG_BYTES = 65536
TEST_SIGNING_KEY = bytes(range(32))

READONLY_SLOTS = {
    1: "sys_exit",
    3: "sys_read",
    4: "sys_write",
    5: "sys_open",
    6: "sys_close",
    104: "sys_setitimer",
    140: "sys_llseek",
    197: "sys_fstat64",
    266: "sys_statfs64_wrapper",
}
SLOTS = {
    **READONLY_SLOTS,
    267: "sys_fstatfs64_wrapper",
    322: "sys_openat",
    328: "sys_unlinkat",
    329: "sys_renameat",
}
FLAGS = [
    "--target=armv7-none-eabi",
    "-mcpu=cortex-a5",
    "-marm",
    "-mfloat-abi=soft",
    "-Os",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fomit-frame-pointer",
    "-nostdlib",
    "-Wall",
    "-Wextra",
    "-Werror",
]

# Applets confirmed ABSENT from M7 1.00 BusyBox v1.13.4 banner (RESEARCH-stage7-3.md).
FORBIDDEN_SHELL_APPLETS = (
    "timeout",
    "sha256sum",
    "printf",
    "df",
    "base64",
    "awk",
    "sed",  # present in BusyBox but not needed; keep script minimal
    "tr",
    "head",
    "seq",
    "stat",
    "mktemp",
    "od",
    "hexdump",
)

TAR_MEMBER_ORDER = (
    "guard",
    "mlv2.req",
    "core.bin",
    "PreCapture.mod",
    "daemon",
    "ring.elf",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def kernel_slots() -> dict[int, tuple[str, str, str]]:
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
    for slot, name in sorted({**SLOTS, 118: "sys_fsync"}.items()):
        offset = table + 4 * slot
        (address,) = struct.unpack_from("<I", kernel, offset)
        if address != symbols[name]:
            raise ValueError(f"Slot {slot} does not resolve to {name}")
        verified[slot] = (name, hex(offset), hex(address))

    for wname, target_name in (
        ("sys_statfs64_wrapper", "sys_statfs64"),
        ("sys_fstatfs64_wrapper", "sys_fstatfs64"),
    ):
        wrapper = symbols[wname]
        teq88, moveq84, branch = struct.unpack_from("<III", kernel, wrapper - base)
        disp = ((branch & 0xFFFFFF) ^ 0x800000) - 0x800000
        if (teq88, moveq84, branch >> 24, wrapper + 16 + 4 * disp) != (
            0xE3310058,
            0x03A01054,
            0xEA,
            symbols[target_name],
        ):
            raise ValueError(f"Unexpected ARM {wname}")

    # M7 do_sys_open adds LOOKUP_FOLLOW only if the 0x8000 input bit is clear.
    # path_openat tests that lookup bit and takes its -ELOOP exit when clear.
    open_va = symbols["do_sys_open"]
    path_va = symbols["path_openat"]
    for va, words in (
        (open_va + 0xA8, (0xE3130902, 0x03877001)),
        (open_va + 0xE4, (0xE1A03007,)),
        (path_va + 0x128, (0xE3120001, 0x1A000006)),
        (path_va + 0x144, (0xE3E07027,)),
    ):
        if struct.unpack_from("<" + "I" * len(words), kernel, va - base) != words:
            raise ValueError(f"Unexpected M7 no-follow handling at {va:#x}")
    return verified


def inspect(binary: bytes) -> None:
    elf = ELFFile(io.BytesIO(binary))
    if elf.elfclass != 32 or elf["e_machine"] != "EM_ARM" or elf["e_type"] != "ET_EXEC":
        raise ValueError("Expected ARM32 executable")
    if any(s["p_type"] in ("PT_DYNAMIC", "PT_INTERP") for s in elf.iter_segments()):
        raise ValueError("Dynamic loader dependency")
    for section in elf.iter_sections():
        if section.name.startswith((".got", ".plt", ".rel")) and section["sh_size"]:
            raise ValueError(f"Unexpected {section.name}")
    symbols = list(elf.get_section_by_name(".symtab").iter_symbols())
    if any(sym.name and sym["st_shndx"] == "SHN_UNDEF" for sym in symbols):
        raise ValueError("Undefined symbol")
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    slots = set()
    for index, section in enumerate(elf.iter_sections()):
        if not section["sh_flags"] & 4:
            continue
        mappings = {
            (sym.name.split(".")[0], sym["st_value"])
            for sym in symbols
            if sym["st_shndx"] == index and sym.name.startswith("$")
        }
        if mappings != {("$a", section["sh_addr"])} or section["sh_size"] % 4:
            raise ValueError("Expected a section of aligned ARM instructions")
        data = section.data()
        for i in range(0, len(data), 4):
            raw = int.from_bytes(data[i : i + 4], "little")
            if (raw >> 24) & 15 != 15:
                continue
            if raw != 0xEF000000 or i < 4:
                raise ValueError("Unexpected supervisor call")
            ins = next(md.disasm(data[i - 4 : i], section["sh_addr"] + i - 4))
            if ins.mnemonic != "movw" or not ins.op_str.startswith("r7, #"):
                raise ValueError("Missing immediate syscall number")
            slots.add(int(ins.op_str.split("#")[1], 0))
    if slots != set(SLOTS):
        raise ValueError(f"Syscall census mismatch {sorted(slots)} != {sorted(SLOTS)}")


def check_boot_script(script_bytes: bytes) -> None:
    if b"\r" in script_bytes:
        raise ValueError("mlv2_sd_boot.sh must use LF line endings only")
    text = script_bytes.decode("ascii")
    if not text.startswith("#!/bin/sh\n"):
        raise ValueError("mlv2_sd_boot.sh must start with #!/bin/sh")
    # Strip full-line comments before scanning for forbidden commands.
    active = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    for bad in FORBIDDEN_SHELL_APPLETS:
        if re.search(rf"(?:^|[;&|(\s]){re.escape(bad)}(?:$|[;&|)\s])", active, re.M):
            raise ValueError(f"mlv2_sd_boot.sh uses forbidden/unavailable applet {bad!r}")


def build_once(extra_defs: tuple[str, ...] = ()) -> bytes:
    with tempfile.TemporaryDirectory() as directory:
        obj, elf = (Path(directory) / name for name in ("reader.o", "reader.elf"))
        subprocess.run(["clang", *FLAGS, *extra_defs, "-c", SOURCE, "-o", obj], check=True)
        subprocess.run(
            [*linker(), "-static", "--build-id=none", "--no-undefined", "-e", "_start", obj, "-o", elf],
            check=True,
        )
        binary = elf.read_bytes()
    inspect(binary)
    return binary


def patch_sd_daemon(daemon_image: bytes, s7_manifest: dict, *, nonce: str = SD_BOOT_NONCE) -> bytes:
    d = s7_manifest["artifacts"]["daemon"]
    if len(daemon_image) != d["bytes"] or sha256_bytes(daemon_image) != d["sha256"]:
        raise ValueError("stage7_daemon.elf template hash/size mismatch")
    if not re.fullmatch(r"[0-9a-f]{12}", nonce):
        raise ValueError(f"Invalid SD boot nonce: {nonce!r}")
    off = d["config_offset"]
    if d["config_bytes"] != build_stage7.DAEMON_CONFIG_BYTES or d["config_version"] != build_stage7.DAEMON_VERSION:
        raise ValueError("stage7_daemon manifest config metadata mismatch")
    if struct.unpack_from("<2I", daemon_image, off) != (build_stage7.DAEMON_MAGIC, build_stage7.DAEMON_VERSION):
        raise ValueError("stage7_daemon config header mismatch")
    if daemon_image[off + 52 : off + 64] != b"0" * 12:
        raise ValueError("stage7_daemon template nonce placeholder mismatch")
    buf = bytearray(daemon_image)
    struct.pack_into(
        "<13I12s",
        buf,
        off,
        build_stage7.DAEMON_MAGIC,
        build_stage7.DAEMON_VERSION,
        0,  # duration_ms = 0 (indefinite cold-boot runtime)
        50,  # poll_ms
        2000,  # heartbeat_ms
        SD_DAEMON_MAX_LOG_BYTES,  # 64 KiB bounded daemon.log inside 1 MiB /tmp_network
        1,  # daemonize = True
        0,  # after = 0 (hold-driven post-capture)
        96,  # backlog_cap
        100,  # debounce_ms
        300,  # focus_ms
        24,  # burst_cap
        48,  # post_max
        nonce.encode("ascii"),
    )
    checked = bytearray(buf)
    checked[off : off + build_stage7.DAEMON_CONFIG_BYTES] = daemon_image[
        off : off + build_stage7.DAEMON_CONFIG_BYTES
    ]
    if bytes(checked) != daemon_image:
        raise ValueError("SD daemon config patch escaped config bounds")
    return bytes(buf)


def patch_sd_ring(ring_image: bytes, s7_manifest: dict, *, nonce: str = SD_BOOT_NONCE) -> bytes:
    r = s7_manifest["artifacts"]["ring"]
    if len(ring_image) != r["bytes"] or sha256_bytes(ring_image) != r["sha256"]:
        raise ValueError("stage7_ring.elf template hash/size mismatch")
    if not re.fullmatch(r"[0-9a-f]{12}", nonce):
        raise ValueError(f"Invalid SD boot nonce: {nonce!r}")
    boot_off = r["boot_offset"]
    nonce_off = r["nonce_offset"]
    if nonce_off != boot_off + 16 or r["boot_bytes"] != build_stage7.RING_BOOT_BYTES:
        raise ValueError("stage7_ring manifest boot metadata mismatch")
    if struct.unpack_from("<4I", ring_image, boot_off) != (
        build_stage7.RING_BOOT_MAGIC,
        build_stage7.RING_BOOT_VERSION,
        r["rw_vaddr"],
        r["rw_memsz"],
    ):
        raise ValueError("stage7_ring boot header mismatch")
    if ring_image[nonce_off : nonce_off + 12] != b"0" * 12:
        raise ValueError("stage7_ring template nonce placeholder mismatch")
    buf = bytearray(ring_image)
    buf[nonce_off : nonce_off + 12] = nonce.encode("ascii")
    checked = bytearray(buf)
    checked[nonce_off : nonce_off + 12] = ring_image[nonce_off : nonce_off + 12]
    if bytes(checked) != ring_image:
        raise ValueError("SD ring nonce patch escaped boot bounds")
    return bytes(buf)


def build_card_ustar(s7_out: Path = build_stage7.OUT) -> tuple[bytes, dict[str, dict[str, object]]]:
    s7_manifest = build_stage7.verify_seal(s7_out)
    guard_bytes = (s7_out / "mlv2_guard.elf").read_bytes()
    req_bytes = (s7_out / "mlv2.req").read_bytes()
    core_bytes = (s7_out / "core.bin").read_bytes()
    mod_bytes = (s7_out / "PreCapture.mod").read_bytes()
    daemon_bytes = patch_sd_daemon((s7_out / "stage7_daemon.elf").read_bytes(), s7_manifest)
    ring_bytes = patch_sd_ring((s7_out / "stage7_ring.elf").read_bytes(), s7_manifest)

    members = {
        "guard": guard_bytes,
        "mlv2.req": req_bytes,
        "core.bin": core_bytes,
        "PreCapture.mod": mod_bytes,
        "daemon": daemon_bytes,
        "ring.elf": ring_bytes,
    }
    member_meta: dict[str, dict[str, object]] = {}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name in TAR_MEMBER_ORDER:
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
        raise ValueError(f"card.ustar size {len(payload)} out of bounds")
    return payload, member_meta


def sign_mlv2_tar(ustar_bytes: bytes, key_32b: bytes, release_seq: int = 1) -> bytes:
    """Wrap a plain USTAR archive in the authenticated 128-byte M7SD1 envelope."""
    if len(key_32b) != 32:
        raise ValueError("Owner HMAC key must be exactly 32 bytes")
    if not (isinstance(release_seq, int) and not isinstance(release_seq, bool) and 1 <= release_seq <= 0xFFFFFFFF):
        raise ValueError(f"Invalid release_seq: {release_seq!r}")
    if len(ustar_bytes) < 512 or len(ustar_bytes) > 384 * 1024 or len(ustar_bytes) % 512 != 0:
        raise ValueError(f"Invalid USTAR payload length: {len(ustar_bytes)}")
    prefix = struct.pack(
        "<8s24sII24x32s",
        b"M7SD1",
        TARGET_BUILD,
        release_seq,
        len(ustar_bytes),
        hashlib.sha256(ustar_bytes).digest(),
    )
    tag = hmac.digest(key_32b, prefix, "sha256")
    return prefix + tag + ustar_bytes


def build_manifest(reader_bin: bytes, boot_sh: bytes, ustar_bytes: bytes, member_meta: dict) -> dict:
    source_paths = [SOURCE, BOOT_SCRIPT, Path(__file__).resolve(), TEST_SCRIPT, HERE / "out/build.json"]
    if PROBE_SCRIPT.is_file():
        source_paths.append(PROBE_SCRIPT)
    test_signed = sign_mlv2_tar(ustar_bytes, TEST_SIGNING_KEY, release_seq=1)
    return {
        "scope": "Stage 7.3 Phase A SD auto-boot bundle (RAM-only verification, zero flash writes)",
        "target": "DSC-RX100M7 1.00 (29110_03.2021050601)",
        "sd_boot_nonce": SD_BOOT_NONCE,
        "sd_daemon_max_log_bytes": SD_DAEMON_MAX_LOG_BYTES,
        "artifacts": {
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
        "source_and_parent_seal_hashes": {
            str(p.relative_to(ROOT)): sha256_bytes(p.read_bytes()) for p in source_paths
        },
    }


def verify_seal(directory: Path = OUT_SD) -> dict:
    build_stage7.verify_seal()
    kernel_slots()
    reader_bin = (directory / "mlv2_card_read.elf").read_bytes()
    boot_sh = (directory / "mlv2_sd_boot.sh").read_bytes()
    ustar_bytes = (directory / "card.ustar").read_bytes()
    check_boot_script(boot_sh)
    expected_ustar, member_meta = build_card_ustar()
    if ustar_bytes != expected_ustar:
        raise ValueError("card.ustar differs from sealed Stage 7.1 rebuild")
    if boot_sh != BOOT_SCRIPT.read_bytes():
        raise ValueError("out-sd/mlv2_sd_boot.sh differs from source mlv2_sd_boot.sh")
    manifest = build_manifest(reader_bin, boot_sh, ustar_bytes, member_meta)
    stored = build_stage7.load_json_strict(directory / "build-sd.json")
    if not build_stage7.strict_equal(stored, manifest):
        raise ValueError("Stage 7.3 Phase A manifest mismatch")
    if reader_bin != build_once():
        raise ValueError("mlv2_card_read.elf differs from a clean build")
    return manifest


def main() -> int:
    build_stage7.verify_seal()
    print(json.dumps(kernel_slots(), indent=2))
    boot_sh = BOOT_SCRIPT.read_bytes()
    check_boot_script(boot_sh)
    binary = build_once()
    if binary != build_once():
        raise ValueError("Clean reader builds differ")
    ustar1, member_meta = build_card_ustar()
    ustar2, _ = build_card_ustar()
    if ustar1 != ustar2:
        raise ValueError("Clean card.ustar builds differ")

    OUT_SD.mkdir(exist_ok=True)
    manifest = build_manifest(binary, boot_sh, ustar1, member_meta)
    with tempfile.TemporaryDirectory(dir=OUT_SD) as staging:
        sdir = Path(staging)
        (sdir / "mlv2_card_read.elf").write_bytes(binary)
        (sdir / "mlv2_card_read.elf").chmod(0o700)
        (sdir / "mlv2_sd_boot.sh").write_bytes(boot_sh)
        (sdir / "mlv2_sd_boot.sh").chmod(0o700)
        (sdir / "card.ustar").write_bytes(ustar1)
        (sdir / "card.ustar").chmod(0o600)
        (sdir / "build-sd.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        for name in ("mlv2_card_read.elf", "mlv2_sd_boot.sh", "card.ustar", "build-sd.json"):
            os.replace(sdir / name, OUT_SD / name)

    verified = verify_seal(OUT_SD)
    print(
        f"PASS: Stage 7.3 Phase A sealed build "
        f"(reader={verified['artifacts']['reader']['bytes']} B, "
        f"boot_sh={verified['artifacts']['boot_script']['bytes']} B, "
        f"card.ustar={verified['artifacts']['card_ustar']['bytes']} B)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
