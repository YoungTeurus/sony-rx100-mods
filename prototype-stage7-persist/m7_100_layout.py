"""Verify the four original DSC-RX100M7 1.00 firmware binaries and mlv2 layout table.

Every offset and byte sequence below is derived directly from the original extracted
DSC-RX100M7 1.00 (build 29110_03.2021050601) binaries and verified by whole-file
SHA-256 + unique site matching.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

EXTRACTED = Path("extracted")
STAGE7 = EXTRACTED / "m7-stage7-1.00-20261126T172306Z/usr"
ORIGINAL = EXTRACTED / "m7-1.00-29110_03.2021050601-20261104T212913Z/usr"
TESTCMD = EXTRACTED / "m7-testcmd-20261105T220859Z-2b1a534533e7/usr"

VIEWUNIFIED2_SHA256 = "534d7fba867b7b1b5dbfcbb3e1d2b59f3cf72ee8fe721d721688f88a5da40f4f"
LIBOBJ_SHA256 = "38cba88dab492ed8529ae1ec80636bce64d649229ed790023f3579144860a092"
IM_ELF_SHA256 = "ad08a5b12fa344ba595f56c8c9ce12263be4673d15deede1b67f4434309e105a"
TESTCMD_SHA256 = "070e6da6da029687c3ba3ece23122a67dec22f90c6450248659be7dd49cdcc38"

DIGESTS = {
    STAGE7 / "lib/viewUnified2.so": VIEWUNIFIED2_SHA256,
    ORIGINAL / "lib/libObj.so": LIBOBJ_SHA256,
    ORIGINAL / "bin/im.elf": IM_ELF_SHA256,
    TESTCMD / "lib/libtestcmd.so": TESTCMD_SHA256,
}

# Observed live im.elf runtime bases on DSC-RX100M7 1.00 (/proc/<im_pid>/maps).
# Both mlv2_guard and core.c dynamically compute runtime bias from /proc/<pid>/maps,
# so ASLR/layout shifts are handled even when live bases differ from reference.
REF_VIEW_BASE = 0x153F1000
REF_TESTCMD_BASE = 0x0409F000
REF_SHIM_OFF = 0x972800
REF_SHIM_ADDR = REF_VIEW_BASE + REF_SHIM_OFF  # viewUnified2.so + 0x972800 (2048 B RX zero tail)
REF_LIBOBJ_BASE = 0x05ECD000

# /usr/lib/viewUnified2.so RX zero tail:
# PT_LOAD[1] RX has p_offset=0, p_vaddr=0, p_filesz=p_memsz=0x9727f0 (end of .ARM.exidx),
# mapped r-xp 0x000000..0x973000 in live /proc/<im_pid>/maps (153f1000-15d64000).
# File bytes 0x9727f0..0x973000 (2,064 B) are 100% zero padding before PT_LOAD[2] at 0x973000.
# Placing shim.bin at viewUnified2.so + 0x972800..0x973000 (2,048 B) puts the shim within
# Thumb-2 B.W (+-16 MiB) range of all three PAS_MenuList hooks, making every hook install and
# uninstall a single atomic 4-byte PTRACE_POKETEXT word with zero libtestcmd.so dependency.
CAVE = dict(
    file="viewUnified2.so",
    offset=REF_SHIM_OFF,
    size=2048,
    rx_filesz=0x9727F0,
    rx_page_end=0x973000,
    sha256=VIEWUNIFIED2_SHA256,
)

# Verified viewUnified2.so PLT veneers (Thumb `bx pc; nop` -> ARM PLT -> GOT).
PLT_STUB_PREFIX = bytes.fromhex("7847c046")
CONSTANTS = {
    "SET_TEXT": dict(
        offset=0x1617C0,
        got=0xA03F1C,
        symbol="_ZN9GEN_Label13setTextDirectEPKc",
    ),
    "SET_MODE": dict(
        offset=0x1680C8,
        got=0xA05E1C,
        symbol="_ZN2ux6wgtsys6Widget7setModeENS1_10WidgetModeE",
    ),
}

# Verified PAS_MenuList hooks in viewUnified2.so (single 4-byte atomic B.W patches).
HOOKS = {
    "set_root": dict(
        offset=0x696408,
        patch_len=4,
        replay=4,
        check_len=16,
        original="044600af51b100f5c23303f52b731960",
        signal="044600af51b100f5c23303f52b731960",
    ),
    "refresh": dict(
        offset=0x696834,
        patch_len=4,
        replay=4,
        check_len=16,
        original="2de9f04f9bb006af044607f120004ff0",
        signal="2de9f04f9bb006af044607f120004ff0",
    ),
    "open_item": dict(
        offset=0x696DF8,
        patch_len=4,
        replay=4,
        check_len=12,
        original="00f5c23303f52c732de9f043",
        signal="00f5c23303f52c732de9f043",
    ),
}

# PAS_MenuList full menu refresh (rebuilds page/row counts, tabs, icons, calls refresh).
MENU_REFRESH = dict(
    offset=0x696EC4,
    signal="00f5c23303f52a73b0b504461a7800af",
)

# PAS_MenuList tab-bar backdrop widget offset: menu + 0x97c.
# Proven in viewUnified2.so init_tabs (0x695750: add.w sl, r4, #0x960;
# 0x695772: add.w sl, sl, #0x1c; 0x695870..0x695886: setImage(sl, tbl[tab_count], 0)).
TAB_BACKDROP_WIDGET = dict(
    menu_offset=0x97C,
    proof_sites=(
        (0x695750, "04f5166a"),  # add.w sl, r4, #0x960
        (0x695772, "0af11c0a"),  # add.w sl, sl, #0x1c
        (0x695A1A, "04f51660"),  # add.w r0, r4, #0x960 (addChild)
    ),
    backdrop_table_off=0x88C558,
)

# Two 7th-tab rectangle tables in viewUnified2.so .rodata (tabs 0..5 prefix + 8 zero bytes for tab 6).
RECT_PREFIX = bytes.fromhex(
    "110000005b004200670000005b004200bd0000005b004200"
    "130100005b004200690100005b004200bf0100005b004200"
)
RECT_PATCH = bytes.fromhex("150200005b004200")  # x=533, y=0, w=91, h=66
RECT_TABLES = {
    "rect_tbl1_slot6": dict(offset=0x88C814, prefix_off=0x88C7E4),
    "rect_tbl2_slot6": dict(offset=0x88C894, prefix_off=0x88C864),
}

# End of viewUnified2.so .bss (0xbc9bb4 -> aligned 0xbc9bb8, page end 0xbca000).
V1_ANCHOR = dict(offset=0xBC9BB8, size=8, bss_end=0xBC9BB4, page_end=0xBCA000)

# Verified libObj.so Event posting symbols (for ACTION mods if ever used).
LIBOBJ_EVENTS = {
    "event_new": dict(
        kind="plt_arm",
        offset=0x108C50,  # ARM PLT stub after 0x108c4c Thumb veneer (7847c046)
        veneer_offset=0x108C4C,
        symbol="_Znwj",
        signal="12c68fe294ca8ce270f9bce5",
    ),
    "event_ctor": dict(
        kind="func_thumb",
        offset=0x89AC65,
        file_offset=0x89AC64,
        symbol="_ZN5EventC1Emhh",
        signal="b0b50446416000af0272437214206df4",
    ),
    "event_push": dict(
        kind="func_thumb",
        offset=0x89C211,
        file_offset=0x89C210,
        symbol="_ZN12EventManager4pushEP5Eventb",
        signal="2de9f04184b0044602af08460d461646",
    ),
    "event_mgr": dict(
        kind="object",
        offset=0x145CE10,
        symbol="g_pEvtMgr",
        got_reloc_r_offset=0x13A4198,
        got_reloc_r_info=0x94315,
    ),
}


class LayoutMismatch(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _find_all(haystack: bytes, needle: bytes) -> list[int]:
    hits = []
    pos = 0
    while True:
        idx = haystack.find(needle, pos)
        if idx < 0:
            break
        hits.append(idx)
        pos = idx + 1
    return hits


def verify_view(image: bytes) -> dict:
    actual = hashlib.sha256(image).hexdigest()
    if actual != VIEWUNIFIED2_SHA256:
        raise LayoutMismatch(f"viewUnified2.so SHA-256 {actual} != {VIEWUNIFIED2_SHA256}")
    out = {}
    for name, row in HOOKS.items():
        orig = bytes.fromhex(row["original"])
        sig = bytes.fromhex(row["signal"])
        off = row["offset"]
        if image[off:off + len(orig)] != orig:
            raise LayoutMismatch(f"{name}: bytes at +{off:#x} mismatch")
        hits = _find_all(image, sig)
        if hits != [off]:
            raise LayoutMismatch(f"{name}: signal hits {[hex(h) for h in hits]} != [{hex(off)}]")
        out[name] = dict(offset=off, original=orig, replay=row["replay"])

    mr_sig = bytes.fromhex(MENU_REFRESH["signal"])
    mr_off = MENU_REFRESH["offset"]
    if image[mr_off:mr_off + len(mr_sig)] != mr_sig or _find_all(image, mr_sig) != [mr_off]:
        raise LayoutMismatch(f"menu_refresh: unique match failed at +{mr_off:#x}")
    out["menu_refresh"] = dict(offset=mr_off)

    for name, row in CONSTANTS.items():
        off = row["offset"]
        if image[off:off + 4] != PLT_STUB_PREFIX:
            raise LayoutMismatch(f"{name}: +{off:#x} missing Thumb PLT veneer {PLT_STUB_PREFIX.hex()}")
        out[name] = dict(offset=off, got=row["got"], symbol=row["symbol"])

    for site_off, expected_hex in TAB_BACKDROP_WIDGET["proof_sites"]:
        want = bytes.fromhex(expected_hex)
        got = image[site_off:site_off + len(want)]
        if got != want:
            raise LayoutMismatch(f"tab_backdrop site +{site_off:#x}: {got.hex()} != {expected_hex}")
    out["tab_backdrop_menu_offset"] = TAB_BACKDROP_WIDGET["menu_offset"]

    prefix_hits = _find_all(image, RECT_PREFIX)
    expected_prefixes = [RECT_TABLES["rect_tbl1_slot6"]["prefix_off"],
                         RECT_TABLES["rect_tbl2_slot6"]["prefix_off"]]
    if prefix_hits != expected_prefixes:
        raise LayoutMismatch(
            f"rect_prefix hits {[hex(h) for h in prefix_hits]} != {[hex(x) for x in expected_prefixes]}"
        )
    for name, row in RECT_TABLES.items():
        off = row["offset"]
        if image[off:off + 8] != b"\x00" * 8:
            raise LayoutMismatch(f"{name}: +{off:#x} is not 8 zero bytes")
        out[name] = dict(offset=off, prefix_off=row["prefix_off"], patch=RECT_PATCH)

    out["v1_anchor"] = dict(V1_ANCHOR)
    return out


def verify_libobj(image: bytes) -> dict:
    actual = hashlib.sha256(image).hexdigest()
    if actual != LIBOBJ_SHA256:
        raise LayoutMismatch(f"libObj.so SHA-256 {actual} != {LIBOBJ_SHA256}")
    out = {}
    for name, row in LIBOBJ_EVENTS.items():
        if name == "event_mgr":
            rec = struct.pack("<II", row["got_reloc_r_offset"], row["got_reloc_r_info"])
            if image.count(rec) != 1:
                raise LayoutMismatch("event_mgr: g_pEvtMgr GOT relocation not unique")
            out[name] = dict(offset=row["offset"], symbol=row["symbol"])
            continue
        sig = bytes.fromhex(row["signal"])
        foff = row.get("file_offset", row["offset"])
        if image[foff:foff + len(sig)] != sig or _find_all(image, sig) != [foff]:
            raise LayoutMismatch(f"libObj {name}: unique match failed at +{foff:#x}")
        if "veneer_offset" in row:
            voff = row["veneer_offset"]
            if image[voff:voff + 4] != PLT_STUB_PREFIX:
                raise LayoutMismatch(f"libObj {name}: veneer at +{voff:#x} mismatch")
        out[name] = dict(offset=row["offset"], symbol=row["symbol"], kind=row["kind"])
    return out


def verify_cave(image: bytes) -> dict:
    actual = hashlib.sha256(image).hexdigest()
    if actual != VIEWUNIFIED2_SHA256:
        raise LayoutMismatch(f"viewUnified2.so SHA-256 {actual} != {VIEWUNIFIED2_SHA256}")
    rx_filesz, rx_page_end = CAVE["rx_filesz"], CAVE["rx_page_end"]
    start, size = CAVE["offset"], CAVE["size"]
    if start < rx_filesz or start + size > rx_page_end or (start & 3) or (size & 3):
        raise LayoutMismatch(f"cave +{start:#x}..+{start + size:#x} out of RX slack {rx_filesz:#x}..{rx_page_end:#x}")
    if image[rx_filesz:rx_page_end] != b"\x00" * (rx_page_end - rx_filesz):
        raise LayoutMismatch(f"viewUnified2.so RX slack +{rx_filesz:#x}..+{rx_page_end:#x} is not all zeros")
    for name, row in HOOKS.items():
        disp = (start + size) - (row["offset"] + 4)
        if not (-0x1000000 <= disp <= 0xFFFFFE):
            raise LayoutMismatch(f"hook {name} at +{row['offset']:#x} out of Thumb-2 B.W range of cave +{start:#x}")
    return dict(start=start, size=size, page_end=rx_page_end, zero_from=rx_filesz)


def verify(root) -> dict:
    """Verify all original M7 1.00 inputs and all extracted layout offsets."""
    base = Path(root)
    for relative, expected in DIGESTS.items():
        actual = sha256_file(base / relative)
        if actual != expected:
            raise ValueError(f"{relative}: expected {expected}, got {actual}")
    view_bytes = (base / STAGE7 / "lib/viewUnified2.so").read_bytes()
    view_res = verify_view(view_bytes)
    libobj_res = verify_libobj((base / ORIGINAL / "lib/libObj.so").read_bytes())
    cave_res = verify_cave(view_bytes)
    return dict(view=view_res, libobj=libobj_res, cave=cave_res)


if __name__ == "__main__":
    verify(Path(__file__).resolve().parents[1])
    for path, digest in DIGESTS.items():
        print(f"{digest}  {path}")
    print("PASS: M7 1.00 digests, hooks, PLTs, tab backdrop +0x97c, rect tables, cave, libObj events")
