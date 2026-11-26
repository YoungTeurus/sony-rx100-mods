#!/usr/bin/env python3
"""Derive two fixed module readers by replacing pathname data, without ARM execution."""
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
import build_m7_testcmd_reader as prior

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'artifacts/m7-input-module-readers'
SOURCES = ('/usr/kmod/osal_uipc.ko', '/usr/kmod/upm.ko')
IMAGE_BYTES, SOURCE_OFFSET, SOURCE_BYTES = 562, 496, 23
MAX_BYTES = 512 * 1024
IMAGE_SHA256S = {
    SOURCES[0]: '6a0e13c0a22055c042782b14221e0f475becb3253a0af83f3cc705b8f52b96ed',
    SOURCES[1]: 'ea4f57e5cfa838e1d24bfd57db810c2f373c2400a59bf9bab2805a66da689255',
}
IMAGE_PATHS = {source: ARTIFACTS / (Path(source).stem + '-reader.elf') for source in SOURCES}
BEGIN, END, ERROR = prior.BEGIN, prior.END, prior.ERROR
decode_transfer, synthetic_transfer = prior.decode_transfer, prior.synthetic_transfer


def expected_image(source):
    if source not in SOURCES:
        raise ValueError('Source is outside the two fixed module paths')
    image = prior.IMAGE_PATH.read_bytes()
    prior.validate_reader(image)
    value = source.encode('ascii') + b'\0'
    if len(value) > SOURCE_BYTES or len(image) != IMAGE_BYTES:
        raise ValueError('Fixed pathname span changed')
    return image[:SOURCE_OFFSET] + value + bytes(SOURCE_BYTES - len(value)) + image[SOURCE_OFFSET + SOURCE_BYTES:]


def validate_reader(image, source):
    if (source not in SOURCES or type(image) is not bytes or len(image) != IMAGE_BYTES
            or hashlib.sha256(image).hexdigest() != IMAGE_SHA256S[source] or image != expected_image(source)):
        raise ValueError('Fixed module reader size/SHA256/data-only derivation mismatch')
    return {'source': source, 'bytes': IMAGE_BYTES, 'sha256': IMAGE_SHA256S[source], 'open_flags': 0,
            'max_source_bytes': MAX_BYTES, 'instruction_bytes_unchanged': True,
            'prior_reader_sha256': prior.IMAGE_SHA256, 'runtime_stack_bytes': 512}


def main():
    previous = prior.IMAGE_PATH.read_bytes()
    instructions = list(Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(previous[84:480], 0x10054))
    if len(instructions) != 99:
        raise ValueError('Prior instruction count changed')
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    proofs = []
    for source in SOURCES:
        image = expected_image(source)
        proof = validate_reader(image, source)
        if image[:496] != previous[:496] or image[519:] != previous[519:]:
            raise ValueError('Change extends outside pathname data')
        path = IMAGE_PATHS[source]
        path.write_bytes(image)
        proofs.append({**proof, 'file': str(path.relative_to(ROOT)),
                       'data_patch': {'offset': 496, 'bytes': 23, 'before_hex': previous[496:519].hex(),
                                      'after_hex': image[496:519].hex()}})
    (ARTIFACTS / 'disassembly.txt').write_text('\n'.join(
        f'{i.address:08x} {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in instructions) + '\n')
    result = {'readers': proofs, 'instruction_count': 99, 'syscalls_unchanged': [1, 3, 4, 5, 6],
              'builder_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'prior_manifest_sha256': hashlib.sha256((prior.ARTIFACTS / 'manifest.json').read_bytes()).hexdigest(),
              'decoder_tests': prior.check_decoder(), 'native_execution': False, 'native_emulation': False,
              'camera_access': False, 'sony_execution': False}
    (ARTIFACTS / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: two 562-byte readers; 99 unchanged instructions each; data only; no ARM/USB')


if __name__ == '__main__':
    main()
