"""Build and seal freestanding single-segment ARM ELF for Stage 6 WIP v1 probe."""
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "out"
BASE = 0x10000
HEADER = 84
CONFIG_MAGIC = 0x3653374D
CONFIG_VERSION = 2
CONFIG_BYTES = 44  # 8 * u32 + 12-byte ASCII nonce

SEALED_HOST_FILES = (
    "prototype-stage6-autonomy/stage6_probe.c",
    "prototype-stage6-autonomy/build_stage6.py",
    "prototype-stage6-autonomy/stage6_runner.py",
    "prototype-stage6-autonomy/test_stage6_probe.py",
    "scripts/m7_stage6_probe.py",
    "scripts/m7_probe.py",
    "scripts/m7_burst_identity.py",
    "scripts/m7_terminal_steps.py",
    "scripts/m7_terminal_repaint.py",
    "scripts/m7_terminal_check.py",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def current_host_hashes() -> dict:
    return {rel: sha((ROOT / rel).read_bytes()) for rel in SEALED_HOST_FILES}


def build_probe(source=None, output=None, optimize="-Os"):
    if optimize not in ("-Os", "-Oz"):
        raise ValueError("unsupported size optimization")
    source = HERE / "stage6_probe.c" if source is None else Path(source)
    output = OUT if output is None else Path(output)
    output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="s6-compile-", dir=output) as directory:
        objpath = Path(directory) / "stage6_probe.o"
        subprocess.run([
            "clang", "--target=armv7-none-eabi", "-marm", "-mfloat-abi=soft",
            "-mno-movt", optimize, "-ffreestanding", "-fno-builtin",
            "-fno-stack-protector", "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables", "-fno-pic", "-fno-pie",
            "-Wall", "-Wextra", "-Werror",
            "-c", str(source), "-o", str(objpath),
        ], check=True)
        object_data = objpath.read_bytes()
        objpath.replace(output / "stage6_probe.o")

    elf = ELFFile(io.BytesIO(object_data))
    offsets, payload = {}, bytearray()
    for i, section in enumerate(elf.iter_sections()):
        if section["sh_flags"] & 2 and section["sh_type"] == "SHT_PROGBITS":
            assert not (section["sh_flags"] & 1), f"unexpected writable section: {section.name}"
            align = max(4, section["sh_addralign"])
            payload.extend(bytes((-(BASE + HEADER + len(payload))) % align))
            offsets[i] = len(payload)
            payload.extend(section.data())
        elif section["sh_flags"] & 2 and section["sh_type"] == "SHT_NOBITS":
            assert section["sh_size"] == 0, f"unexpected BSS in {section.name}"

    table = elf.get_section_by_name(".symtab")
    symbols = {}

    def symbol_address(symbol):
        index = symbol["st_shndx"]
        assert index in offsets, (symbol.name, index)
        return BASE + HEADER + offsets[index] + symbol["st_value"]

    for symbol in table.iter_symbols():
        if symbol.name and symbol["st_shndx"] in offsets:
            symbols[symbol.name] = symbol_address(symbol)

    for section in elf.iter_sections():
        if section["sh_type"] != "SHT_REL" or section["sh_info"] not in offsets:
            continue
        for reloc in section.iter_relocations():
            at = offsets[section["sh_info"]] + reloc["r_offset"]
            word = struct.unpack_from("<I", payload, at)[0]
            target = symbol_address(table.get_symbol(reloc["r_info_sym"]))
            kind = reloc["r_info_type"]
            if kind == 2:  # R_ARM_ABS32
                result = (word + target) & 0xFFFFFFFF
            elif kind in (28, 29):  # R_ARM_CALL / R_ARM_JUMP24
                displacement = (word & 0xFFFFFF) << 2
                if displacement & 0x2000000:
                    displacement -= 0x4000000
                displacement += target - (BASE + HEADER + at)
                assert not (displacement & 3) and -0x2000000 <= displacement < 0x2000000
                result = (word & 0xFF000000) | ((displacement >> 2) & 0xFFFFFF)
            else:
                raise ValueError(f"unsupported ARM relocation {kind}")
            struct.pack_into("<I", payload, at, result)

    cfg_sym = table.get_symbol_by_name("m7_s6_config")[0]
    assert cfg_sym["st_size"] == CONFIG_BYTES, f"expected {CONFIG_BYTES}, got {cfg_sym['st_size']}"
    config_offset = symbols["m7_s6_config"] - BASE
    size = HEADER + len(payload)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident, 2, 40, 1, symbols["_start"], 52, 0, 0x5000000, 52, 32, 1, 0, 0, 0,
    )
    segment = struct.pack("<8I", 1, 0, BASE, BASE, size, size, 5, 4096)
    image = header + segment + payload
    assert config_offset >= HEADER and config_offset + CONFIG_BYTES <= size
    assert struct.unpack_from("<2I", image, config_offset) == (CONFIG_MAGIC, CONFIG_VERSION)

    (output / "stage6_probe.elf").write_bytes(image)
    manifest = dict(
        probe_kind="stage6-readonly-daemon-probe",
        config_version=CONFIG_VERSION,
        source=str(source.relative_to(ROOT)),
        source_sha256=sha(source.read_bytes()),
        host_source_hashes=current_host_hashes(),
        sha256=sha(image),
        bytes=size,
        optimization=optimize,
        base=BASE,
        entry=symbols["_start"],
        config_offset=config_offset,
        config_bytes=CONFIG_BYTES,
        symbols=symbols,
    )
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return bytes(image), manifest


def verify_seal(release_dir=None):
    """Verify sealed ELF and all native/host/shared source hashes match build.json."""
    release_dir = OUT if release_dir is None else Path(release_dir)
    manifest_path = release_dir / "build.json"
    elf_path = release_dir / "stage6_probe.elf"
    if not manifest_path.is_file() or not elf_path.is_file():
        raise ValueError(f"Missing sealed Stage 6 artifacts in {release_dir}")
    manifest = json.loads(manifest_path.read_text())
    image = elf_path.read_bytes()
    if manifest.get("probe_kind") != "stage6-readonly-daemon-probe":
        raise ValueError("Unexpected Stage 6 manifest probe_kind")
    if manifest.get("config_version") != CONFIG_VERSION or manifest.get("config_bytes") != CONFIG_BYTES:
        raise ValueError("Stage 6 manifest config version/size mismatch")
    if sha(image) != manifest.get("sha256") or len(image) != manifest.get("bytes"):
        raise ValueError("Sealed stage6_probe.elf hash or length mismatch")
    recorded_host = manifest.get("host_source_hashes")
    live_host = current_host_hashes()
    if recorded_host != live_host:
        changed = sorted(k for k in set(live_host) | set(recorded_host or {})
                         if live_host.get(k) != (recorded_host or {}).get(k))
        raise ValueError("Stage 6 sealed source hash mismatch; rebuild & retest required: " + ", ".join(changed))
    if manifest.get("source_sha256") != live_host["prototype-stage6-autonomy/stage6_probe.c"]:
        raise ValueError("Stage 6 native source_sha256 mismatch")
    return image, manifest


def configure_probe(
    image: bytes,
    manifest: dict,
    *,
    duration_ms: int = 240000,
    poll_ms: int = 50,
    heartbeat_ms: int = 2000,
    max_log_bytes: int = 65536,
    daemonize: bool = True,
    toggle_bkid: int = 0x01071472,
    nonce: str = "000000000000",
) -> bytes:
    if sha(image) != manifest["sha256"]:
        raise ValueError("stage6 probe template changed")
    if not (
        type(duration_ms) is int and 100 <= duration_ms <= 3600000 and
        type(poll_ms) is int and 10 <= poll_ms <= 1000 and
        type(heartbeat_ms) is int and 100 <= heartbeat_ms <= 60000 and
        type(max_log_bytes) is int and 1024 <= max_log_bytes <= 262144 and
        type(daemonize) is bool and
        type(toggle_bkid) is int and 0 < toggle_bkid <= 0xFFFFFFFF and
        type(nonce) is str and re.fullmatch(r"[0-9a-f]{12}", nonce)
    ):
        raise ValueError("invalid stage6 probe config")
    off = manifest["config_offset"]
    if struct.unpack_from("<2I", image, off) != (CONFIG_MAGIC, CONFIG_VERSION):
        raise ValueError("stage6 config header mismatch")
    result = bytearray(image)
    struct.pack_into(
        "<8I12s", result, off,
        CONFIG_MAGIC, CONFIG_VERSION,
        duration_ms, poll_ms, heartbeat_ms, max_log_bytes,
        int(daemonize), toggle_bkid, nonce.encode("ascii"),
    )
    checked = bytearray(result)
    checked[off:off + CONFIG_BYTES] = image[off:off + CONFIG_BYTES]
    assert checked == image
    return bytes(result)


if __name__ == "__main__":
    _, info = build_probe()
    print(json.dumps({k: info[k] for k in ("bytes", "sha256", "config_offset", "config_version")}))
