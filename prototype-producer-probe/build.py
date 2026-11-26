"""Build a freestanding ARM ELF; resolve only reviewed ARM relocations."""
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
OUT = HERE / "out"
BASE = 0x10000
HEADER = 84
CONFIG_BYTES = 60 + 512 * 8
SONY = HERE.parent / "extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/lib/libObj.so"
SONY_SHA = "38cba88dab492ed8529ae1ec80636bce64d649229ed790023f3579144860a092"
MPR = SONY.with_name("libmpr.so")
MPR_SHA = "2b1057ab5069127398fb077fd4bd332cc21e47601b4d19f95d92987e599fbbe0"
MPRCTRL = HERE.parent / "extracted/m7-mprctrl-20261105T104604Z-4ef9ad61f354/usr/lib/libmprctrl.so"
MPRCTRL_SHA = "fa688648fbe2873b34a2c1ce9efbd2d612bf6260688284a8a469c64c7a0b8126"
MWF = HERE.parent / "extracted/m7-mwf-20261105T130923Z-63c22574a4f9/usr/lib/libMWF.so"
MWF_SHA = "49e3199ca9dbcfbca612f6c2e4b2fae430ef510f33ce1300470a215c6ad9e4ba"
UIPC = SONY.with_name("libosal_uipc.so")
UIPC_SHA = "17c84895ce40c788ae84a6774dcdf23a4c073fdfb5770c3757e705d104942468"
PTHREAD = HERE.parent / "extracted/m7a-1.01/firmware.tar_unpacked/0700_part_image/dev/nflasha7_unpacked/lib/libpthread-2.11.2.so"
PTHREAD_SHA = "c70038f68c104b4b9b26fb623db08be4dce7725bb597f9706bed185b3f257f21"
PTHREAD_PIN_RANGES = tuple((va+offset,min(108,size-offset))
    for va,size in ((0x89f0,0x220),(0xd140,8),(0xa960,0x2c),(0xabe8,0x80),
                    (0xac68,0x6a),(0x5f8c,0xa),(0x88cc,0x124),(0x9a48,0xa0)) for offset in range(0,size,108))
CREATE_PIN_RANGES = tuple((va+offset,min(108,size-offset))
    for va,size in ((0xa1a0e0,0x1c),(0xa1700c,0x38),(0xa009d8,0xa4),(0xa1e92c,0x168),
                    (0x9fa350,0x30),(0xa17550,0x12))
    for offset in range(0,size,108))
MWF_PIN_RANGES = tuple((va+offset,min(108,size-offset))
    for va,size in ((0x2f6cc,0x28),(0x2f5ec,0x6e),(0x2f5d8,0x14),(0x2f4c8,0x110),
                    (0x30d18,0x9c),(0x30db4,0x7c),(0x30e98,0x4c),(0x31724,0x112),
                    (0x316b0,0x74),(0x42cf8,4),(0x42d04,4),
                    (0x291e0,0xc),(0x296c0,0xac),(0x318e8,0xb4),
                    (0x31a10,0x4c),(0x31b20,0x5c),(0x2976c,0x60),(0x31b7c,0x18))
    for offset in range(0,size,108))
MEDIA_PIN_RANGES = tuple((va+offset,min(108,size-offset))
    for va,size in ((0xd410c4,0xdc),(0xd411a0,0xa0),(0xd4125c,0x148),
                    (0xd410a8,0x1c),(0x1166edc,8),(0xd41240,0x1c),(0x1166f4c,0x28))
    for offset in range(0,size,108))
END_REGISTER_PIN_RANGES = tuple((va+offset,min(108,size-offset))
    for va,size in ((0xa18da4,0x46),(0xa16e34,0xe),(0x9fd1cc,0xa4),(0x9fd060,0x60),(0x9f8f30,0x86),(0x9f8d08,0x9c),(0xdd3a66,0x32),
                    (0xdc060c,0x13c),(0xdd13dc,0x2a),(0xdbf8bc,0x60))
    for offset in range(0,size,108))
MPRCTRL_PIN_RANGES = ((0x139b4,0x40),(0x12c44,0x22))
ROUTE_PIN_RANGES = ((0xa05bd8,0x30),(0xa05c08,0x30),(0x9ff8a4,0x24),
                    (0x9ffa3a,8),(0xa1752c,0x12),(0xa16cc0,0x22),(0xa1726e,0x18))
RECEIVER_PIN_RANGES = tuple((0x90533c+n,min(108,0x1a4-n)) for n in range(0,0x1a4,108))
RECEIVER_MWF_PIN_RANGES = tuple((va+n,min(108,size-n))
    for va,size in ((0x2a994,0x60),(0x2a9f4,0x98)) for n in range(0,size,108))
CONNECT_PIN_RANGES = tuple((va+n,min(108,size-n)) for va,size in (
    (0xd4475c,0x9e),(0xd447fa,0x70),(0xa16d48,0x22),(0x8eb974,0x1f4),(0x9fe030,0x148),
    (0x8ea4c0,0x120),(0x8ebdf8,0x24),(0x8e75ac,0x150),(0x9fad50,0x140),(0x9fadfc,0x94),
    (0xa186d0,0x88),(0xa183b0,0x44),(0xa16de0,0xe),(0xa17286,0xa),(0xa1a6da,0x146),
    (0xa020b8,0x90),(0xa01e48,0x1dc),(0xa176e2,0x26),(0xa16d2c,0x1c),
    (0xa00a98,0x50),(0xa00604,0x230),(0xa00834,0x1a4),(0xa1704c,0x14)) for n in range(0,size,108))
CONNECT_MWF_PIN_RANGES = tuple((va+n,min(108,size-n)) for va,size in (
    (0x2e33e,0x258),(0x2e04c,0x174),(0x1e8d0,0x2a),(0x1e5f0,8),
    (0x2f2cc,0x30),(0x2ee34,0x98)) for n in range(0,size,108))
RAM_CAPTURE_PIN_RANGES = tuple((va+n,min(108,size-n)) for va,size in (
    (0x9fc7bc,0x3c),(0xa14c50,0x74),(0xa1535e,0xa2),(0xa146c0,0x54),
    (0xa1b214,0x20),(0xa1b350,0x40),(0xa1261a,0xd0)) for n in range(0,size,108))
MODE_PIN_RANGES = tuple((va+n,min(108,size-n)) for va,size in (
    (0xa1c4e0,0x1a0),(0xa1bac8,0x154),(0xa1bc20,0xc0),(0xa17964,0x170),
    (0xa1c0cc,0x414),(0xa1859c,0x130),(0xa17590,0x140),(0xa17ad4,0x494),(0x8ec459,0x67)) for n in range(0,size,108))
MODE_MWF_PIN_RANGES = tuple((va+n,min(108,size-n)) for va,size in (
    (0x21e14,0x38),(0x21f08,0x24),(0x21fdc,0x76),(0x2595c,0x60)) for n in range(0,size,108))

MPR_PIN_RANGES = ((0x19e95c, 12), (0x19e828, 12), (0x19e664, 12),
                  (0x19dd5c, 12), (0x19f614, 12), (0x19ec4c, 12),
                  (0x7c54d4, 44), (0x7db360, 14), (0x7c4eac, 20), (0x788a7a, 6))
PIN_RANGES = ((0x55abc, 4), (0x108b20, 12), (0x10fac4, 12), (0xdd1dd8, 104), (0xdd1594, 108),
              (0x10d8dc, 12), (0xdd1342, 90), (0xdd139c, 64), (0xdc9e00, 76),
              (0xdc9d10, 108), (0xdc9d7c, 108), (0xdc9de8, 24))


def target_pins():
    data = SONY.read_bytes()
    if sha(data) != SONY_SHA:
        raise ValueError("original Sony code changed")
    elf = ELFFile(io.BytesIO(data))
    return [(va, data[next(elf.address_offsets(va)):next(elf.address_offsets(va))+size])
            for va, size in PIN_RANGES]


def mpr_pins():
    data = MPR.read_bytes()
    if sha(data) != MPR_SHA:
        raise ValueError("original libmpr changed")
    elf = ELFFile(io.BytesIO(data))
    return [(va, data[next(elf.address_offsets(va)):next(elf.address_offsets(va))+size])
            for va, size in MPR_PIN_RANGES]


def media_pins():
    return library_pins(SONY, SONY_SHA, MEDIA_PIN_RANGES)


def mprctrl_pins():
    return library_pins(MPRCTRL, MPRCTRL_SHA, MPRCTRL_PIN_RANGES)


def route_pins():
    return library_pins(SONY, SONY_SHA, ROUTE_PIN_RANGES)


def create_pins():
    return library_pins(SONY, SONY_SHA, CREATE_PIN_RANGES)


def end_register_pins():
    return library_pins(SONY, SONY_SHA, END_REGISTER_PIN_RANGES)


def mwf_pins():
    return library_pins(MWF, MWF_SHA, MWF_PIN_RANGES)


def pthread_pins():
    return library_pins(PTHREAD, PTHREAD_SHA, PTHREAD_PIN_RANGES)


def receiver_pins():
    return library_pins(SONY, SONY_SHA, RECEIVER_PIN_RANGES)


def receiver_mwf_pins():
    return library_pins(MWF, MWF_SHA, RECEIVER_MWF_PIN_RANGES)


def connect_pins():
    return library_pins(SONY, SONY_SHA, CONNECT_PIN_RANGES)


def connect_mwf_pins():
    return library_pins(MWF, MWF_SHA, CONNECT_MWF_PIN_RANGES)


def ram_capture_pins():
    return library_pins(SONY, SONY_SHA, RAM_CAPTURE_PIN_RANGES)


def burst_cancel_pins():
    return library_pins(SONY, SONY_SHA, tuple((va+n,min(108,size-n)) for va,size in (
        (0x9fdf62,0x24),(0x9f954c,0x88),(0xdd38e8,0x30),(0xdbc394,0x3c),
        (0xdd2228,0x74),(0xdd1fbc,0x30),(0xdbbc88,0x14),(0xdcfb28,0x10),
        (0xdcca58,0x12c),(0xdcc540,0xbc),(0xdcfc42,0x46),(0xdcfc88,0x9a),(0xdcfda8,0x90)
    ) for n in range(0,size,108)))


def mode_pins():
    return library_pins(SONY, SONY_SHA, MODE_PIN_RANGES)


def mode_mwf_pins():
    return library_pins(MWF, MWF_SHA, MODE_MWF_PIN_RANGES)


def start_pins():
    return library_pins(SONY,SONY_SHA,tuple((va+n,min(108,size-n)) for va,size in
        ((0x55abc,4),(0xa34be8,0x140),(0xa40d18,0x2fc),(0xa41014,8)) for n in range(0,size,108)))


def start_mwf_pins():
    return library_pins(MWF,MWF_SHA,tuple((va+n,min(108,size-n)) for va,size in
        ((0x1f11c,0x60),(0x1efe4,0x60),(0x296c0,0xac),(0x318e8,0xb4)) for n in range(0,size,108)))


def start_uipc_pins():
    return library_pins(UIPC,UIPC_SHA,tuple((va+n,min(108,size-n)) for va,size in
        ((0x3168,0x34),(0x3e7e,0x40)) for n in range(0,size,108)))


def library_pins(path, expected_sha, ranges):
    data = path.read_bytes()
    if sha(data) != expected_sha:
        raise ValueError(f"original library changed: {path.name}")
    elf = ELFFile(io.BytesIO(data))
    return [(va, data[next(elf.address_offsets(va)):next(elf.address_offsets(va))+size])
            for va, size in ranges]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build(source=None, output=None, optimize="-Os", ram_frames=1, ram_hold=False, ram_commit=False, ram_ring=False, ram_continuous=False, ram_late_register=False, ram_precapture=False, ram_probe=False):
    if optimize not in ("-Os", "-Oz"):
        raise ValueError("unsupported size optimization")
    output=OUT if output is None else Path(output)
    source=HERE / ("ram_native.c" if ram_precapture or ram_probe else "native.c") if source is None else Path(source)
    if type(ram_probe) is not bool or ram_probe and (
            source.name!="ram_native.c" or ram_frames!=1 or ram_hold or ram_commit or ram_ring or
            ram_continuous or ram_late_register or ram_precapture):
        raise ValueError("RAM probe requires one RAM frame without hold/commit/ring/continuous/precapture")
    if type(ram_precapture) is not bool or ram_precapture and (
            source.name!="ram_native.c" or type(ram_frames) is not int or ram_frames not in (1,2) or
            type(ram_commit) is not bool or type(ram_continuous) is not bool or ram_hold or ram_ring or ram_late_register):
        raise ValueError("RAM precapture requires ram_native.c without hold/ring/late-register")
    if ram_precapture:
        ram_frames=2
        ram_commit=ram_continuous=True
    if type(ram_late_register) is not bool or ram_late_register and not ram_continuous:
        raise ValueError("RAM late register observation requires continuous")
    if type(ram_continuous) is not bool or ram_continuous and (
            source.name!="ram_native.c" or ram_frames!=2 or ram_hold or ram_commit and not ram_precapture or ram_ring):
        raise ValueError("RAM continuous requires ram_native.c, two frames and no hold/commit/ring")
    if type(ram_ring) is not bool or ram_ring and (ram_frames!=3 or ram_hold or not ram_commit or source.name!="ram_native.c"):
        raise ValueError("RAM ring requires three frames and commit in ram_native.c")
    if type(ram_frames) is not int or ram_frames not in ((3,) if ram_ring else (1,2)) or (ram_frames!=1 and source.name!="ram_native.c"):
        raise ValueError("RAM frame count requires ram_native.c and one or two frames")
    if type(ram_hold) is not bool or ram_hold and (ram_frames!=2 or source.name!="ram_native.c"):
        raise ValueError("RAM hold requires exactly two frames in ram_native.c")
    if type(ram_commit) is not bool or ram_commit and not (ram_hold or ram_ring or ram_precapture):
        raise ValueError("RAM commit requires RAM hold")
    output.mkdir(parents=True,exist_ok=True)
    pins = target_pins()
    header = ["struct code_pin { u32 va, size; const unsigned char *bytes; };"]
    for index, (_, data) in enumerate(pins):
        header.append("static const unsigned char pin_%d[] = {%s};" %
                      (index, ",".join(str(b) for b in data)))
    header.append("static const struct code_pin code_pins[] = {%s};" %
                  ",".join("{0x%x,%d,pin_%d}" % (va, len(data), i) for i, (va, data) in enumerate(pins)))
    fsys_pins = mpr_pins()
    for index, (_, data) in enumerate(fsys_pins):
        header.append("static const unsigned char mpr_pin_%d[] = {%s};" %
                      (index, ",".join(str(b) for b in data)))
    header.append("static const struct code_pin mpr_code_pins[] = {%s};" %
                  ",".join("{0x%x,%d,mpr_pin_%d}" % (va, len(data), i) for i, (va, data) in enumerate(fsys_pins)))
    for name, group in (("media",media_pins()),("mprctrl",mprctrl_pins()),("route",route_pins()),
                        ("create",create_pins()),("end_register",end_register_pins()),("mwf",mwf_pins()),("pthread",pthread_pins()),
                        ("receiver",receiver_pins()),("receiver_mwf",receiver_mwf_pins()),
                        ("connect",connect_pins()),("connect_mwf",connect_mwf_pins()),
                        ("ram_capture",ram_capture_pins()),("burst_cancel",burst_cancel_pins()),("mode",mode_pins()),("mode_mwf",mode_mwf_pins()),
                        ("start",start_pins()),("start_mwf",start_mwf_pins()),("start_uipc",start_uipc_pins())):
        for index,(_,data) in enumerate(group):
            header.append("static const unsigned char %s_pin_%d[] = {%s};" %
                          (name,index,",".join(str(b) for b in data)))
        header.append("static const struct code_pin %s_code_pins[] = {%s};" %
                      (name,",".join("{0x%x,%d,%s_pin_%d}" % (va,len(data),name,i)
                                     for i,(va,data) in enumerate(group))))
    if ram_probe:
        probe_sites=(0xa1bac8,0x9fe42e,0xd447ec,0x8e75ac,0x9fcd04,0xa16250,0xa0efe8,0xa162b2)
        for i,(va,word) in enumerate(library_pins(SONY,SONY_SHA,[(va,4) for va in probe_sites])):
            header.append("static const unsigned char ram_probe_pin_%d[] = {%s};" %
                          (i, ",".join(str(b) for b in word)))
        header.append("static const struct code_pin ram_probe_code_pins[] = {%s};" %
                      ",".join("{0x%x,4,ram_probe_pin_%d}" % (va,i) for i,va in enumerate(probe_sites)))
    (output / "sony_pins.h").write_text("\n".join(header)+"\n")
    with tempfile.TemporaryDirectory(prefix="compile-", dir=output) as directory:
        objpath = Path(directory) / "native.o"
        subprocess.run(["clang", "--target=armv7-none-eabi", "-marm", "-mfloat-abi=soft",
            "-mno-movt", optimize, "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
            "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-fno-pic", "-fno-pie",
            "-Wall", "-Wextra", "-Werror", *([f"-DM7_RAM_FRAMES={ram_frames}"] if ram_frames!=1 else []),
            *(["-DM7_RAM_HOLD=1"] if ram_hold else []),
            *(["-DM7_RAM_COMMIT=1"] if ram_commit else []),
            *(["-DM7_RAM_RING=1"] if ram_ring else []),
            *(["-DM7_RAM_CONTINUOUS=1"] if ram_continuous else []),
            *(["-DM7_RAM_PRECAPTURE=1"] if ram_precapture else []),
            *(["-DM7_RAM_PROBE=1"] if ram_probe else []),
            *(["-DM7_RAM_LATE_REGISTER=1"] if ram_late_register else []),
            "-I", str(output), "-c", str(source), "-o", str(objpath)], check=True)
        object_data = objpath.read_bytes()
        objpath.replace(output / "native.o")
    elf = ELFFile(io.BytesIO(object_data))
    offsets, payload = {}, bytearray()
    for i, section in enumerate(elf.iter_sections()):
        if section["sh_flags"] & 2 and section["sh_type"] == "SHT_PROGBITS":
            assert not section["sh_flags"] & 1, "helper must have no writable global data"
            align = max(4, section["sh_addralign"])
            payload.extend(bytes((-(BASE + HEADER + len(payload))) % align))
            offsets[i] = len(payload)
            payload.extend(section.data())
        elif section["sh_flags"] & 2 and section["sh_type"] == "SHT_NOBITS":
            assert section["sh_size"] == 0, "unexpected BSS"
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
            if kind == 2:
                result = (word + target) & 0xffffffff
            elif kind in (28, 29):
                displacement = (word & 0xffffff) << 2
                if displacement & 0x2000000:
                    displacement -= 0x4000000
                displacement += target - (BASE + HEADER + at)
                assert not displacement & 3 and -0x2000000 <= displacement < 0x2000000
                result = (word & 0xff000000) | ((displacement >> 2) & 0xffffff)
            else:
                raise ValueError(f"unsupported ARM relocation {kind}")
            struct.pack_into("<I", payload, at, result)
    config = table.get_symbol_by_name("m7_config")[0]
    assert config["st_size"] == CONFIG_BYTES
    config_offset = symbols["m7_config"] - BASE
    size = HEADER + len(payload)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    header = struct.pack("<16sHHIIIIIHHHHHH", ident, 2, 40, 1, symbols["_start"],
                         52, 0, 0x5000000, 52, 32, 1, 0, 0, 0)
    segment = struct.pack("<8I", 1, 0, BASE, BASE, size, size, 5, 4096)
    image = header + segment + payload
    assert config_offset >= HEADER and config_offset + CONFIG_BYTES <= size
    (output / "template.elf").write_bytes(image)
    manifest = dict(source_sha256=sha(source.read_bytes()), sha256=sha(image), bytes=size, optimization=optimize,
        base=BASE, entry=symbols["_start"], config_offset=config_offset,
        config_bytes=CONFIG_BYTES, symbols=symbols,
        retain_sha256=sha((HERE/"retain.c").read_bytes()), sony_sha256=SONY_SHA,
        hold_sha256=sha((HERE/"hold.c").read_bytes()), jpeg_sha256=sha((HERE/"jpeg.c").read_bytes()),
        commit_sha256=sha((HERE/"commit.c").read_bytes()), mpr_sha256=MPR_SHA,
        ring_sha256=sha((HERE/"ring.c").read_bytes()),
        media_sha256=sha((HERE/"media.c").read_bytes()), mprctrl_sha256=MPRCTRL_SHA,
        media_route_sha256=sha((HERE/"media_route.c").read_bytes()),
        end_register_sha256=sha((HERE/"end_register.c").read_bytes()),
        receiver_sha256=sha((HERE/"receiver.c").read_bytes()),
        media_config_sha256=sha((HERE/"media_config.c").read_bytes()),
        media_connect_sha256=sha((HERE/"media_connect.c").read_bytes()),
        ram_capture_sha256=sha((HERE/"ram_capture.c").read_bytes()),
        capture_trap_sha256=sha((HERE/"capture_trap.c").read_bytes()),
        media_create_sha256=sha((HERE/"media_create.c").read_bytes()), mwf_sha256=MWF_SHA,
        pthread_candidate_sha256=PTHREAD_SHA,
        ring_controller_sha256=sha((HERE.parent/"prototype-ring/src/pre_capture.c").read_bytes()),
        ring_header_sha256=sha((HERE.parent/"prototype-ring/src/pre_capture.h").read_bytes()))
    if "m7_recovery_plan" in symbols:
        plan_symbol=table.get_symbol_by_name("m7_recovery_plan")[0]
        manifest.update(recovery_plan_offset=symbols["m7_recovery_plan"]-BASE,
                        recovery_plan_bytes=plan_symbol["st_size"],
                        included_native_sha256=sha((HERE/"native.c").read_bytes()))
    if source.name=="source_native.c":
        manifest.update(probe_kind="media-source",included_native_sha256=sha((HERE/"native.c").read_bytes()))
    if source.name=="start_native.c":
        manifest.update(probe_kind="media-start",included_native_sha256=sha((HERE/"native.c").read_bytes()),
                        source_graph_sha256=sha((HERE/"source_native.c").read_bytes()),uipc_sha256=UIPC_SHA)
    if source.name=="stock_sd_native.c":
        stock_symbol=table.get_symbol_by_name("m7_stock_sd_config")[0]
        stock_offset=symbols["m7_stock_sd_config"]-BASE
        if stock_symbol["st_size"]!=28 or image[stock_offset:stock_offset+8]!=struct.pack("<2I",0x31534450,1):
            raise ValueError("stock SD configuration signature mismatch")
        pending=[source.resolve()]
        sources={}
        while pending:
            path=pending.pop()
            key=str(path.relative_to(HERE.parent))
            if key in sources:
                continue
            body=path.read_bytes()
            sources[key]=sha(body)
            for name in re.findall(rb'^\s*#include\s+"([^"]+)"',body,re.MULTILINE):
                child=(path.parent/name.decode('ascii')).resolve()
                if child.is_file():
                    pending.append(child)
                elif name!=b'sony_pins.h':
                    raise ValueError("missing stock SD source include: "+name.decode('ascii'))
        manifest.update(probe_kind="stock-sd-precapture",stock_sd_revision=1,
                        stock_config_offset=stock_offset,stock_config_bytes=28,
                        source_hashes=dict(sorted(sources.items())),
                        source_graph_sha256=sha(json.dumps(sources,sort_keys=True).encode()))
    if source.name=="ram_native.c":
        manifest.update(probe_kind="ram-session",ram_frames=ram_frames,ram_hold=ram_hold,ram_commit=ram_commit,ram_ring=ram_ring,ram_continuous=ram_continuous,ram_precapture=ram_precapture,ram_probe=ram_probe,ram_probe_revision=5 if ram_probe else 0,ram_precapture_revision=7 if ram_precapture else 0,ram_ring_sha256=sha((HERE/"ram_ring.c").read_bytes()),included_native_sha256=sha((HERE/"native.c").read_bytes()),
                        source_graph_sha256=sha((HERE/"source_native.c").read_bytes()),
                        start_sha256=sha((HERE/"start_native.c").read_bytes()),uipc_sha256=UIPC_SHA,
                        ram_continuous_revision=5 if ram_continuous else 0,
                        ram_late_register=ram_late_register,
                        ram_late_register_revision=1 if ram_late_register else 0,
                        ram_late_register_sha256=sha((HERE/"ram_late_register.c").read_bytes()),
                        ram_continuous_diagnostics_revision=1 if ram_continuous else 0,
                        ram_stop_diagnostics_revision=6 if ram_continuous else 0,
                        ram_stop_diagnostics_sha256=sha((HERE/"ram_stop_diagnostics.c").read_bytes()),
                        ram_pending_diagnostics_sha256=sha((HERE/"ram_pending_diagnostics.c").read_bytes()),
                        ram_pin_lifecycle_sha256=sha((HERE/"ram_pin_lifecycle.c").read_bytes()),
                        ram_camera_state_sha256=sha((HERE/"ram_camera_state.c").read_bytes()),
                        ram_capture_wait_state_sha256=sha((HERE/"ram_capture_wait_state.c").read_bytes()),
                        ram_continuous_sha256=sha((HERE/"ram_continuous.c").read_bytes()),
                        shutter_start_sha256=sha((HERE/"shutter_start.c").read_bytes()))
    if ram_precapture:
        config_symbol=table.get_symbol_by_name("m7_precap_config")[0]
        assert config_symbol['st_size']==32
        manifest.update(precapture_config_offset=symbols['m7_precap_config']-BASE,
                        precapture_config_bytes=32,ram_ring_capacity_limit=4,
                        ram_ring_memory_limit=0,ram_backlog_default=12)
    if ram_probe or ram_precapture:
        pending=[source.resolve()];sources={}
        while pending:
            path=pending.pop();key=str(path.relative_to(HERE.parent))
            if key in sources: continue
            body=path.read_bytes();sources[key]=sha(body)
            for name in re.findall(rb'^\s*#include\s+"([^"]+)"',body,re.MULTILINE):
                child=(path.parent/name.decode('ascii')).resolve()
                if child.is_file(): pending.append(child)
                elif name!=b'sony_pins.h': raise ValueError("missing RAM source include: "+name.decode('ascii'))
        manifest['source_hashes']=dict(sorted(sources.items()))
        manifest['host_source_hashes']={str((HERE/name).relative_to(HERE.parent)):sha((HERE/name).read_bytes())
            for name in ('runner.py','build.py','verify_ram_precapture.py','verify_ram_precapture_historical.py','precapture_requirements.py','ram_session_verifier.py',
                         'ram_capture_verifier.py','ram_continuous_verifier.py','stock_sd_card.py')}
        if ram_probe: manifest['ram_probe_protocol']=dict(sample_kind=94,descriptor_kind=95,counter_kind=96,
            control_kind=97,record_kind=98,queue_kind=99,image_state_kind=100,stages=[27,28,29],walk_limit=96,
            interval_ms=20,timeout_ms=180000,after_teardown_ms=2000,
            burst_ack_mode="capture-context bypass; stock release",burst_ack_events=[10,11,12],burst_ack_drain_ms=30000,burst_version_bit=0x100,burst_hold_ms=4000,burst_tail_ms=2000,record_removal_slot_bit=0x80000000,
            counter_sites=list(probe_sites),counter_backend='perf hardware execution breakpoints; ENOSYS at first open -> sampled Image state',
            fallback_counts_available=False,fallback_image_offsets=[4,8,12,16],fallback_recorder_offsets=[0x1cc,0x1d0],
            counter_scope=['recorder','recorder','recorder','receiver','recorder','recorder','worker','recorder'])
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return bytes(image), manifest


def precapture_admission_budget(before,after):
    if type(before) is not int or not 1<=before<=4 or type(after) is not int or not 0<=after<=3:
        raise ValueError("invalid precapture N/M")
    # Selected files retire sequentially; no larger development queue is needed for larger N/M.
    return 12


def configure(image, manifest, pid, bias, ranges, token, focus=600, settle=1500, diagnose_only=False,
              retain_check=False, monitor_tid=0, hold_check=False, commit_check=False, mpr_bias=0, ring_check=False,
              media_check=False, mprctrl_bias=0, media_route_check=False, media_create_check=False, mwf_bias=0, end_register_check=False,
              receiver_check=False,media_connect_check=False,ram_capture_check=False,media_config_check=False,media_source_check=False,media_start_check=False,ram_burst_probe=False,ram_before=2,ram_after=1,ram_backlog=None):
    if type(ram_burst_probe) is not bool or ram_burst_probe and not (
            ram_capture_check and manifest.get('ram_probe') and manifest.get('ram_probe_revision')==5):
        raise ValueError("RAM burst requires a revision 5 probe payload")
    if sha(image) != manifest["sha256"]:
        raise ValueError("template changed")
    if not (type(pid) is int and 0 < pid <= 0x7fffffff and
            type(token) is int and 0 < token <= 0xffffffff and
            type(bias) is int and 0x10000 <= bias <= 0xbe000000 and bias % 4096 == 0 and
            0 < len(ranges) <= 512 and 100 <= focus <= 1500 and 100 <= settle <= 3000 and
            type(diagnose_only) is bool and type(retain_check) is bool and type(hold_check) is bool and
            type(commit_check) is bool and type(ring_check) is bool and type(media_check) is bool and
            type(media_route_check) is bool and not (media_route_check and diagnose_only) and
            type(media_create_check) is bool and type(end_register_check) is bool and
            type(receiver_check) is bool and not (receiver_check and diagnose_only) and
            type(media_source_check) is bool and not (media_source_check and diagnose_only) and
            type(media_start_check) is bool and not (media_start_check and diagnose_only) and
            type(media_connect_check) is bool and not (media_connect_check and diagnose_only) and
            type(media_config_check) is bool and not (media_config_check and diagnose_only) and
            type(ram_capture_check) is bool and not (ram_capture_check and diagnose_only) and
            sum((retain_check, hold_check, commit_check, ring_check, media_check, media_route_check, media_create_check, end_register_check, receiver_check, media_connect_check,ram_capture_check,media_config_check,media_source_check,media_start_check)) <= 1 and
            type(mpr_bias) is int and (0x10000 <= mpr_bias <= 0xbe000000 and mpr_bias % 4096 == 0
                                     if commit_check or ring_check or ram_capture_check and manifest.get('ram_commit') else mpr_bias == 0) and
            type(mprctrl_bias) is int and (0x10000 <= mprctrl_bias <= 0xbe000000 and mprctrl_bias % 4096 == 0
                                         if media_check or media_create_check or media_connect_check or ram_capture_check or media_config_check else mprctrl_bias == 0) and
            type(mwf_bias) is int and (0x10000 <= mwf_bias <= 0xbe000000 and mwf_bias % 4096 == 0
                                     if media_create_check or end_register_check or receiver_check or media_connect_check or ram_capture_check or media_config_check or media_source_check or media_start_check else mwf_bias == 0) and
            type(monitor_tid) is int and
            ((not (retain_check or hold_check or commit_check or ring_check or media_check or media_create_check or end_register_check or ram_capture_check) and monitor_tid == 0) or
             ((retain_check or hold_check or commit_check or ring_check or media_check or end_register_check or ram_capture_check) and not diagnose_only and 0 < monitor_tid < 0x80000000 and monitor_tid != pid) or
             ((media_create_check or media_connect_check or media_config_check or media_start_check) and not diagnose_only and 0 <= monitor_tid < 0x80000000 and monitor_tid != pid))):
        raise ValueError("invalid runtime config")
    result = bytearray(image)
    if manifest.get('ram_precapture'):
        if ram_backlog is None:ram_backlog=precapture_admission_budget(ram_before,ram_after)
        if type(ram_before) is not int or not 1<=ram_before<=4 or type(ram_after) is not int or not 0<=ram_after<=3 or type(ram_backlog) is not int or not precapture_admission_budget(ram_before,ram_after)<=ram_backlog<=64:
            raise ValueError("Reference RAM ring requires N=1..4, M=0..3, N<=C<=64")
        if manifest.get('ram_precapture_revision')!=7 or manifest.get('precapture_config_bytes')!=32:
            raise ValueError("RAM ring configuration revision mismatch")
        ring_offset=manifest['precapture_config_offset']
        if image[ring_offset:ring_offset+8]!=struct.pack('<2I',0x32525043,7):
            raise ValueError("RAM ring configuration signature mismatch")
        struct.pack_into('<3I',result,ring_offset+8,ram_before,ram_after,ram_backlog)
    off = manifest["config_offset"]
    struct.pack_into("<15I", result, off, 0x3143504d, 6 | (0x100 if ram_burst_probe else 0), token, pid, bias, len(ranges), 2,
                     focus, settle, int(diagnose_only), 14 if media_start_check else 13 if media_source_check else 12 if media_config_check else 11 if ram_capture_check else 10 if media_connect_check else 9 if receiver_check else 8 if end_register_check else 7 if media_create_check else 6 if media_route_check else 5 if media_check else 4 if ring_check else 3 if commit_check else 2 if hold_check else int(retain_check),
                     monitor_tid, mpr_bias, mprctrl_bias, mwf_bias)
    for i, (start, end) in enumerate(ranges):
        if not 0x10000 <= start < end <= 0xc0000000 or start % 4 or end % 4:
            raise ValueError("invalid private range")
        struct.pack_into("<2I", result, off + 60 + 8 * i, start, end)
    checked=bytearray(result)
    checked[off:off+CONFIG_BYTES]=image[off:off+CONFIG_BYTES]
    if manifest.get('ram_precapture'):
        checked[ring_offset+8:ring_offset+20]=image[ring_offset+8:ring_offset+20]
    assert checked==image
    return bytes(result)


if __name__ == "__main__":
    _, info = build()
    print(json.dumps({k: info[k] for k in ("bytes", "sha256", "config_offset")}))
