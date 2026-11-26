"""Inspect two stock menu controls in a local, extracted Sony usr directory."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


# Keys are Sony symbol suffixes. Values are the stock option counts documented
# for the DSC-RX100M7. A match establishes menu structure, not camera identity.
CONTROLS = {"ReleaseWOCard": 2, "AutoReview": 4}


def inspect_library(path, owner):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError(f"{path.name}: expected a little-endian ARM32 library")
        table = elf.get_section_by_name(".dynsym")
        if table is None:
            raise ValueError(f"{path.name}: missing dynamic symbol table")
        result = {}
        for control in CONTROLS:
            root_name = f"cmnViewSettingNodeRootCustom{control}"
            roots = table.get_symbol_by_name(root_name) or []
            if len(roots) != 1 or roots[0]["st_info"]["type"] != "STT_OBJECT":
                raise ValueError(f"{path.name}: missing or ambiguous {root_name}")
            root_section = roots[0]["st_shndx"]
            if not owner:
                if root_section != "SHN_UNDEF":
                    raise ValueError(f"{path.name}: expected an import for {control}")
                result[control] = {"root": "imported"}
                continue
            if not isinstance(root_section, int):
                raise ValueError(f"{path.name}: expected a definition for {control}")
            count_name = f"cmnViewSettingNodesNumOfCustom{control}Default"
            counts = table.get_symbol_by_name(count_name) or []
            if len(counts) != 1:
                raise ValueError(f"{path.name}: missing or ambiguous {count_name}")
            symbol = counts[0]
            if (symbol["st_size"] != 4 or symbol["st_info"]["type"] != "STT_OBJECT"
                    or not isinstance(symbol["st_shndx"], int)):
                raise ValueError(f"{path.name}: invalid count symbol for {control}")
            section = elf.get_section(symbol["st_shndx"])
            offset = symbol["st_value"] - section["sh_addr"]
            if section["sh_type"] != "SHT_PROGBITS" or not 0 <= offset <= section["sh_size"] - 4:
                raise ValueError(f"{path.name}: count for {control} has no file data")
            stream.seek(section["sh_offset"] + offset)
            data = stream.read(4)
            if len(data) != 4:
                raise ValueError(f"{path.name}: truncated count for {control}")
            result[control] = {"root": "defined", "option_count": int.from_bytes(data, "little")}
        stream.seek(0)
        digest = hashlib.sha256(stream.read()).hexdigest()
    return {"sha256": digest, "controls": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("usr", type=Path, help="Extracted directory containing lib/")
    args = parser.parse_args()
    libraries = {}
    try:
        for name in ("CautionConfig.so", "viewUnified2.so"):
            libraries[name] = inspect_library(args.usr / "lib" / name, owner=name == "CautionConfig.so")
    except (OSError, ELFError, ValueError) as exc:
        print(f"INCONCLUSIVE: {exc}", file=sys.stderr)
        return 2
    counts = libraries["CautionConfig.so"]["controls"]
    match = all(counts[name]["option_count"] == expected for name, expected in CONTROLS.items())
    print(json.dumps({"counts_match_manual": match, "libraries": libraries}, indent=2))
    return 0 if match else 1


if __name__ == "__main__":
    sys.exit(main())
