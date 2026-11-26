#!/usr/bin/env python3
"""Derive the fixed testcmd reader by changing data only; never execute ARM or USB."""
import hashlib
import json
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
import build_m7_mprctrl_reader as prior

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'artifacts/m7-testcmd-reader'
IMAGE_PATH = ARTIFACTS / 'm7-testcmd-reader.elf'
IMAGE_BYTES = 562
IMAGE_SHA256 = 'ad219be313f777b6aac0ec1cabefa30c5591a2f369bcc460fba5a99b8feacf19'
SOURCE = '/usr/lib/libtestcmd.so'
SOURCE_PATH = SOURCE.encode() + b'\0'
SOURCE_OFFSET, SOURCE_BYTES = 496, 23
MAX_BYTES = 512 * 1024
BEGIN, END, ERROR = prior.BEGIN, prior.END, prior.ERROR
decode_transfer = prior.decode_transfer
synthetic_transfer = prior.synthetic_transfer
check_decoder = prior.check_decoder


def expected_image():
    image = prior.IMAGE_PATH.read_bytes()
    prior.validate_reader(image)
    if (len(image) != IMAGE_BYTES or len(prior.SOURCE_PATH) != SOURCE_BYTES
            or image[SOURCE_OFFSET:SOURCE_OFFSET + SOURCE_BYTES] != prior.SOURCE_PATH):
        raise ValueError('Prior fixed-path reader layout changed')
    return (image[:SOURCE_OFFSET] + SOURCE_PATH + bytes(SOURCE_BYTES - len(SOURCE_PATH))
            + image[SOURCE_OFFSET + SOURCE_BYTES:])


def validate_reader(image):
    if (not isinstance(image, bytes) or len(image) != IMAGE_BYTES
            or hashlib.sha256(image).hexdigest() != IMAGE_SHA256 or image != expected_image()):
        raise ValueError('Fixed testcmd reader size/SHA256/data-only derivation mismatch')
    if image.count(SOURCE_PATH) != 1:
        raise ValueError('Expected exactly one fixed testcmd source pathname')
    return {'bytes': IMAGE_BYTES, 'sha256': IMAGE_SHA256, 'source': SOURCE,
            'open_flags': 0, 'max_source_bytes': MAX_BYTES, 'runtime_stack_bytes': 512,
            'instruction_bytes_unchanged': True, 'prior_reader_sha256': prior.IMAGE_SHA256}


def main():
    image = expected_image()
    proof = validate_reader(image)
    previous = prior.IMAGE_PATH.read_bytes()
    instructions = list(Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(image[84:480], 0x10054))
    if len(instructions) != 99 or image[:SOURCE_OFFSET] != previous[:SOURCE_OFFSET] or image[519:] != previous[519:]:
        raise ValueError('Change extends beyond the fixed source pathname')
    prior_manifest_path = prior.ARTIFACTS / 'manifest.json'
    prior_manifest = json.loads(prior_manifest_path.read_text())
    if (prior_manifest['sha256'] != prior.IMAGE_SHA256
            or len(prior_manifest['native_tests']) != 13
            or any(test['result'] != 'PASS' for test in prior_manifest['native_tests'])):
        raise ValueError('Prior native tests are absent or inconsistent')
    for key, path in (('source_sha256', ROOT / prior_manifest['source']),
                      ('builder_sha256', Path(prior.__file__))):
        if prior_manifest[key] != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError('Prior source/builder manifest drift')
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    IMAGE_PATH.write_bytes(image)
    (ARTIFACTS / 'disassembly.txt').write_text('\n'.join(
        f'{item.address:08x} {item.bytes.hex()} {item.mnemonic} {item.op_str}' for item in instructions) + '\n')
    result = {**proof, 'file': str(IMAGE_PATH.relative_to(ROOT)),
              'builder_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'prior_reader': str(prior.IMAGE_PATH.relative_to(ROOT)),
              'prior_manifest_sha256': hashlib.sha256(prior_manifest_path.read_bytes()).hexdigest(),
              'prior_native_tests_checked': 13, 'native_emulation_rerun': False,
              'instruction_count': len(instructions), 'data_patch': {'offset': SOURCE_OFFSET, 'bytes': SOURCE_BYTES,
              'before_hex': previous[496:519].hex(), 'after_hex': image[496:519].hex()},
              'decoder_tests': check_decoder(), 'camera_execution': False, 'sony_code_execution': False,
              'python': sys.version}
    (ARTIFACTS / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: 562-byte testcmd reader; all 99 instructions unchanged; 12 decoder rejections; no ARM/USB')


if __name__ == '__main__':
    main()
