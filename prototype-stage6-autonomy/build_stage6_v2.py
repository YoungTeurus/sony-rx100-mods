"""Build and seal Stage 6 WIP v2 freestanding ARM ELFs (stage6_daemon.elf + stage6_ring.elf)."""
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "out-v2"
PROTO_STAGE5 = ROOT / "prototype-producer-probe"

sys.path.insert(0, str(PROTO_STAGE5))
import build as s5_build  # noqa: E402

BASE = 0x10000
DAEMON_MAGIC = 0x32443653
DAEMON_VERSION = 2
DAEMON_CONFIG_BYTES = 16 * 4 + 12  # 16 * u32 + 12-byte ASCII nonce = 76 bytes

RING_BOOT_MAGIC = 0x32523653
RING_BOOT_VERSION = 1
RING_BOOT_BYTES = 4 * 4 + 12  # 4 * u32 + 12-byte ASCII nonce = 28 bytes
M7_CONFIG_BYTES = 60 + 512 * 8
M7_PRECAP_BYTES = 40

SEALED_HOST_FILES = (
    "prototype-stage6-autonomy/build_stage6_v2.py",
    "prototype-stage6-autonomy/stage6_v2_runner.py",
    "prototype-stage6-autonomy/test_stage6_v2.py",
    "scripts/m7_stage6_precapture.py",
    "prototype-producer-probe/build.py",
    "scripts/build_m7_input_module_readers.py",
    "scripts/build_m7_mprctrl_reader.py",
    "scripts/build_m7_proc_mem_reader.py",
    "scripts/build_m7_testcmd_reader.py",
    "scripts/m7_anchor_probe.py",
    "scripts/m7_burst_identity.py",
    "scripts/m7_collect_input_modules.py",
    "scripts/m7_im_code_read.py",
    "scripts/m7_probe.py",
    "scripts/m7_ram_liveness.py",
    "scripts/m7_terminal_check.py",
    "scripts/m7_terminal_io.py",
    "scripts/m7_terminal_repaint.py",
    "scripts/m7_terminal_steps.py",
)

ALLOWED_RING_RW_SECTIONS = frozenset({
    ".rodata.m7_config",
    ".rodata.m7_precap_config",
})


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def align_up(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


def collect_native_includes(entry_sources, extra_include_dirs):
    """Recursively hash all local #include "..." files for sealed build verification."""
    pending = [Path(p).resolve() for p in entry_sources]
    hashes = {}
    search_dirs = [Path(d).resolve() for d in extra_include_dirs]
    while pending:
        path = pending.pop()
        rel = str(path.relative_to(ROOT))
        if rel in hashes:
            continue
        body = path.read_bytes()
        hashes[rel] = sha(body)
        for name_b in re.findall(rb'^\s*#include\s+"([^"]+)"', body, re.MULTILINE):
            name = name_b.decode("ascii")
            if name == "sony_pins.h":
                continue
            found = None
            for base in [path.parent, *search_dirs]:
                cand = (base / name).resolve()
                if cand.is_file():
                    found = cand
                    break
            if found is None:
                raise ValueError(f"Missing native #include {name!r} from {rel}")
            pending.append(found)
    return dict(sorted(hashes.items()))


def current_host_hashes() -> dict:
    return {rel: sha((ROOT / rel).read_bytes()) for rel in SEALED_HOST_FILES}


def generate_sony_pins_header(out_dir: Path) -> dict:
    """Reuse audited Stage 5 Sony library pin generators verbatim (zero duplication)."""
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
        sony_pins_header_sha256=sha(text.encode("utf-8")),
    )


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


def build_daemon(source: Path, output: Path, optimize="-Os"):
    with tempfile.TemporaryDirectory(prefix="s6v2-d-", dir=output) as directory:
        objpath = Path(directory) / "stage6_daemon.o"
        subprocess.run([
            "clang", "--target=armv7-none-eabi", "-marm", "-mfloat-abi=soft",
            "-mno-movt", optimize, "-ffreestanding", "-fno-builtin",
            "-fno-stack-protector", "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables", "-fno-pic", "-fno-pie",
            "-Wall", "-Wextra", "-Werror",
            "-I", str(HERE),
            "-c", str(source), "-o", str(objpath),
        ], check=True)
        object_data = objpath.read_bytes()
        objpath.replace(output / "stage6_daemon.o")

    header_sz = 52 + 32  # 1 PT_LOAD
    elf = ELFFile(io.BytesIO(object_data))
    image = bytearray(header_sz)
    sec_file_offsets, sec_vaddrs = {}, {}
    for i, section in enumerate(elf.iter_sections()):
        if section["sh_flags"] & 2 and section["sh_type"] == "SHT_PROGBITS":
            assert not (section["sh_flags"] & 1), f"daemon must have zero writable globals: {section.name}"
            align = max(4, section["sh_addralign"])
            pad = (-(BASE + len(image))) % align
            image.extend(bytes(pad))
            sec_file_offsets[i] = len(image)
            sec_vaddrs[i] = BASE + len(image)
            image.extend(section.data())
        elif section["sh_flags"] & 2 and section["sh_type"] == "SHT_NOBITS":
            assert section["sh_size"] == 0, f"daemon must have zero BSS: {section.name}"

    symbols, table = apply_arm_relocations(elf, sec_file_offsets, sec_vaddrs, image)
    cfg_sym = table.get_symbol_by_name("m7_s6_daemon_config")[0]
    assert cfg_sym["st_size"] == DAEMON_CONFIG_BYTES, f"expected {DAEMON_CONFIG_BYTES}, got {cfg_sym['st_size']}"
    config_offset = symbols["m7_s6_daemon_config"] - BASE
    size = len(image)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident, 2, 40, 1, symbols["_start"], 52, 0, 0x5000000, 52, 32, 1, 0, 0, 0,
    )
    phdr = struct.pack("<8I", 1, 0, BASE, BASE, size, size, 5, 4096)
    image[0:header_sz] = ehdr + phdr
    assert config_offset >= header_sz and config_offset + DAEMON_CONFIG_BYTES <= size
    assert struct.unpack_from("<2I", image, config_offset) == (DAEMON_MAGIC, DAEMON_VERSION)

    (output / "stage6_daemon.elf").write_bytes(image)
    return bytes(image), dict(
        file="stage6_daemon.elf",
        sha256=sha(bytes(image)),
        bytes=size,
        base=BASE,
        entry=symbols["_start"],
        config_offset=config_offset,
        config_bytes=DAEMON_CONFIG_BYTES,
        config_version=DAEMON_VERSION,
        symbols=symbols,
    )


def build_ring(source: Path, output: Path, optimize="-Os"):
    with tempfile.TemporaryDirectory(prefix="s6v2-r-", dir=output) as directory:
        objpath = Path(directory) / "stage6_ring.o"
        subprocess.run([
            "clang", "--target=armv7-none-eabi", "-marm", "-mfloat-abi=soft",
            "-mno-movt", optimize, "-ffreestanding", "-fno-builtin",
            "-fno-stack-protector", "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables", "-fno-pic", "-fno-pie",
            "-fdata-sections",
            "-Wall", "-Wextra", "-Werror",
            "-I", str(output),
            "-I", str(HERE),
            "-I", str(PROTO_STAGE5),
            "-c", str(source), "-o", str(objpath),
        ], check=True)
        object_data = objpath.read_bytes()
        objpath.replace(output / "stage6_ring.o")

    header_sz = 52 + 2 * 32  # 2 PT_LOAD segments: RX (code+rodata) and RW-RELRO (m7_config + m7_precap_config ONLY)
    elf = ELFFile(io.BytesIO(object_data))
    image = bytearray(header_sz)
    sec_file_offsets, sec_vaddrs = {}, {}
    rw_sections = []

    for i, section in enumerate(elf.iter_sections()):
        if section["sh_flags"] & 2 and section["sh_type"] == "SHT_PROGBITS":
            assert not (section["sh_flags"] & 1), f"ring must have zero writable C globals: {section.name}"
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
            assert section["sh_size"] == 0, f"ring must have zero BSS: {section.name}"

    assert {s.name for _, s in rw_sections} == ALLOWED_RING_RW_SECTIONS, (
        f"Unexpected ring RW config sections: {[s.name for _, s in rw_sections]}"
    )

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
    boot_sym = table.get_symbol_by_name("m7_s6_ring_boot")[0]
    cfg_sym = table.get_symbol_by_name("m7_config")[0]
    pre_sym = table.get_symbol_by_name("m7_precap_config")[0]
    assert boot_sym["st_size"] == RING_BOOT_BYTES
    assert cfg_sym["st_size"] == M7_CONFIG_BYTES
    assert pre_sym["st_size"] == M7_PRECAP_BYTES

    boot_offset = symbols["m7_s6_ring_boot"] - BASE
    assert header_sz <= boot_offset and boot_offset + RING_BOOT_BYTES <= ro_size
    assert rw_vaddr <= symbols["m7_config"] and symbols["m7_config"] + M7_CONFIG_BYTES <= rw_vaddr + rw_memsz
    assert rw_vaddr <= symbols["m7_precap_config"] and symbols["m7_precap_config"] + M7_PRECAP_BYTES <= rw_vaddr + rw_memsz

    # Stamp exact RELRO segment bounds into m7_s6_ring_boot inside PT_LOAD[0].
    struct.pack_into("<4I", image, boot_offset, RING_BOOT_MAGIC, RING_BOOT_VERSION, rw_vaddr, rw_memsz)

    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident, 2, 40, 1, symbols["_start"], 52, 0, 0x5000000, 52, 32, 2, 0, 0, 0,
    )
    phdr_rx = struct.pack("<8I", 1, 0, BASE, BASE, ro_size, ro_size, 5, 4096)  # PF_R|PF_X
    phdr_rw = struct.pack("<8I", 1, rw_file_off, rw_vaddr, rw_vaddr, rw_filesz, rw_memsz, 6, 4096)  # PF_R|PF_W
    image[0:header_sz] = ehdr + phdr_rx + phdr_rw

    (output / "stage6_ring.elf").write_bytes(image)
    return bytes(image), dict(
        file="stage6_ring.elf",
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
        boot_version=RING_BOOT_VERSION,
        symbols=symbols,
    )


def build_all(output=None, optimize="-Os"):
    if optimize not in ("-Os", "-Oz"):
        raise ValueError("unsupported size optimization")
    output = OUT if output is None else Path(output)
    output.mkdir(parents=True, exist_ok=True)
    daemon_src = HERE / "stage6_daemon.c"
    ring_src = HERE / "stage6_ring.c"

    sony_hashes = generate_sony_pins_header(output)
    daemon_img, daemon_info = build_daemon(daemon_src, output, optimize=optimize)
    ring_img, ring_info = build_ring(ring_src, output, optimize=optimize)

    manifest = dict(
        probe_kind="stage6-v2-autonomous-precapture",
        optimization=optimize,
        daemon=daemon_info,
        ring=ring_info,
        sony_library_hashes=sony_hashes,
        native_source_hashes=collect_native_includes([daemon_src, ring_src], [HERE, PROTO_STAGE5]),
        host_source_hashes=current_host_hashes(),
    )
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return daemon_img, ring_img, manifest


def verify_seal(release_dir=None):
    release_dir = OUT if release_dir is None else Path(release_dir)
    manifest_path = release_dir / "build.json"
    daemon_path = release_dir / "stage6_daemon.elf"
    ring_path = release_dir / "stage6_ring.elf"
    if not manifest_path.is_file() or not daemon_path.is_file() or not ring_path.is_file():
        raise ValueError(f"Missing sealed Stage 6 WIP v2 artifacts in {release_dir}")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("probe_kind") != "stage6-v2-autonomous-precapture":
        raise ValueError("Unexpected Stage 6 WIP v2 manifest probe_kind")

    daemon_img = daemon_path.read_bytes()
    ring_img = ring_path.read_bytes()
    d_info = manifest.get("daemon", {})
    r_info = manifest.get("ring", {})
    if sha(daemon_img) != d_info.get("sha256") or len(daemon_img) != d_info.get("bytes"):
        raise ValueError("Sealed stage6_daemon.elf hash or length mismatch")
    if sha(ring_img) != r_info.get("sha256") or len(ring_img) != r_info.get("bytes"):
        raise ValueError("Sealed stage6_ring.elf hash or length mismatch")
    if d_info.get("config_version") != DAEMON_VERSION or d_info.get("config_bytes") != DAEMON_CONFIG_BYTES:
        raise ValueError("Daemon config version/size mismatch")
    if r_info.get("boot_version") != RING_BOOT_VERSION or r_info.get("boot_bytes") != RING_BOOT_BYTES:
        raise ValueError("Ring boot config version/size mismatch")

    live_native = collect_native_includes([HERE / "stage6_daemon.c", HERE / "stage6_ring.c"], [HERE, PROTO_STAGE5])
    if manifest.get("native_source_hashes") != live_native:
        changed = sorted(k for k in set(live_native) | set(manifest.get("native_source_hashes") or {})
                         if live_native.get(k) != (manifest.get("native_source_hashes") or {}).get(k))
        raise ValueError("Stage 6 WIP v2 native source hash mismatch; rebuild & retest required: " + ", ".join(changed))

    live_host = current_host_hashes()
    if manifest.get("host_source_hashes") != live_host:
        changed = sorted(k for k in set(live_host) | set(manifest.get("host_source_hashes") or {})
                         if live_host.get(k) != (manifest.get("host_source_hashes") or {}).get(k))
        raise ValueError("Stage 6 WIP v2 host source hash mismatch; rebuild & retest required: " + ", ".join(changed))
    return daemon_img, ring_img, manifest


def configure_daemon(
    image: bytes,
    manifest: dict,
    *,
    duration_ms: int = 600000,
    poll_ms: int = 50,
    heartbeat_ms: int = 2000,
    max_log_bytes: int = 131072,
    daemonize: bool = True,
    toggle_bkid: int = 0x01071472,
    toggle_on_val: int = 0,
    before: int = 5,
    after: int = 0,
    backlog_cap: int = 96,
    debounce_ms: int = 100,
    focus_ms: int = 300,
    burst_cap: int = 24,
    post_max: int = 48,
    nonce: str = "000000000000",
) -> bytes:
    d = manifest["daemon"]
    if sha(image) != d["sha256"]:
        raise ValueError("stage6_daemon template changed")
    if not (
        type(duration_ms) is int and 100 <= duration_ms <= 3600000 and
        type(poll_ms) is int and 10 <= poll_ms <= 1000 and
        type(heartbeat_ms) is int and 100 <= heartbeat_ms <= 60000 and
        type(max_log_bytes) is int and 2048 <= max_log_bytes <= 262144 and
        type(daemonize) is bool and
        type(toggle_bkid) is int and 0 < toggle_bkid <= 0xFFFFFFFF and
        type(toggle_on_val) is int and toggle_on_val in (0, 1) and
        type(before) is int and 1 <= before <= 15 and
        type(after) is int and 0 <= after <= 64 and
        type(burst_cap) is int and 8 <= burst_cap <= 60 and burst_cap >= before + 4 and
        type(backlog_cap) is int and 24 <= backlog_cap <= 128 and backlog_cap >= burst_cap + 16 and
        type(post_max) is int and 1 <= post_max <= 96 and before + post_max <= 112 and
        type(debounce_ms) is int and 0 <= debounce_ms <= 2000 and
        type(focus_ms) is int and 100 <= focus_ms <= 1500 and
        type(nonce) is str and re.fullmatch(r"[0-9a-f]{12}", nonce)
    ):
        raise ValueError("invalid stage6_daemon config")
    off = d["config_offset"]
    if struct.unpack_from("<2I", image, off) != (DAEMON_MAGIC, DAEMON_VERSION):
        raise ValueError("stage6_daemon config header mismatch")
    result = bytearray(image)
    struct.pack_into(
        "<16I12s", result, off,
        DAEMON_MAGIC, DAEMON_VERSION,
        duration_ms, poll_ms, heartbeat_ms, max_log_bytes,
        int(daemonize), toggle_bkid, toggle_on_val,
        before, after, backlog_cap, debounce_ms, focus_ms,
        burst_cap, post_max,
        nonce.encode("ascii"),
    )
    checked = bytearray(result)
    checked[off:off + DAEMON_CONFIG_BYTES] = image[off:off + DAEMON_CONFIG_BYTES]
    assert checked == image
    return bytes(result)


def configure_ring(image: bytes, manifest: dict, *, nonce: str) -> bytes:
    r = manifest["ring"]
    if sha(image) != r["sha256"]:
        raise ValueError("stage6_ring template changed")
    if not (type(nonce) is str and re.fullmatch(r"[0-9a-f]{12}", nonce)):
        raise ValueError("invalid stage6_ring nonce")
    off = r["boot_offset"]
    if struct.unpack_from("<4I", image, off) != (RING_BOOT_MAGIC, RING_BOOT_VERSION, r["rw_vaddr"], r["rw_memsz"]):
        raise ValueError("stage6_ring boot header mismatch")
    result = bytearray(image)
    result[off + 16:off + 28] = nonce.encode("ascii")
    checked = bytearray(result)
    checked[off + 16:off + 28] = image[off + 16:off + 28]
    assert checked == image
    return bytes(result)


if __name__ == "__main__":
    _, _, info = build_all()
    print(json.dumps(dict(
        daemon={k: info["daemon"][k] for k in ("bytes", "sha256", "config_offset")},
        ring={k: info["ring"][k] for k in ("bytes", "sha256", "ro_size", "rw_vaddr", "rw_memsz", "boot_offset")},
        native_sources=len(info["native_source_hashes"]),
        host_sources=len(info["host_source_hashes"]),
    ), indent=2))
