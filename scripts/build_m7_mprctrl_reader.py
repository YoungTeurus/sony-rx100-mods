#!/usr/bin/env python3
"""Build our fixed libmprctrl.so reader and emulate synthetic file I/O only."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

import capstone
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
import elftools
from elftools.elf.elffile import ELFFile
import unicorn
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR, UC_HOOK_MEM_WRITE,
                     UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R7, UC_ARM_REG_SP

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'artifacts/m7-mprctrl-reader'
IMAGE_PATH = ARTIFACTS / 'm7-mprctrl-reader.elf'
IMAGE_BYTES = 562
IMAGE_SHA256 = 'e6e1547266f7511e8fdc7fcc08b117bc6c4d24d5bed3cb7fb6cca78370cee5a2'
SOURCE = '/usr/lib/libmprctrl.so'
SOURCE_PATH = SOURCE.encode() + b'\0'
MAX_BYTES = 512 * 1024
BASE, ENTRY, WORK = 0x10000, 0x10054, 0x203e00
BEGIN, END, ERROR = b'M7_HEX_BEGIN', b'M7_HEX_END', b'M7_HEX_ERROR'
LIRO_SHA256 = 'da48f51476b8f951a644d245d4b321e4394992c6133ef428ba7fb5b0069dce60'


def validate_reader(image):
    if not isinstance(image, bytes) or len(image) != IMAGE_BYTES or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError('Fixed libmprctrl reader size/SHA256 mismatch')
    if image.count(SOURCE_PATH) != 1:
        raise ValueError('Fixed reader does not contain exactly one allowed source path')
    elf = ELFFile(io.BytesIO(image))
    if (elf['e_machine'] != 'EM_ARM' or elf['e_type'] != 'ET_EXEC' or elf.num_segments() != 1
            or elf.num_sections() != 0 or elf.get_segment(0)['p_flags'] != 5):
        raise ValueError('Unexpected fixed-reader ELF layout')
    return {'bytes': IMAGE_BYTES, 'sha256': IMAGE_SHA256, 'source': SOURCE,
            'open_flags': 0, 'max_source_bytes': MAX_BYTES, 'runtime_stack_bytes': 512}


def decode_transfer(output, expected_bytes=None, expected_md5=None):
    if not isinstance(output, bytes):
        raise TypeError('Reader output must be bytes')
    if len(output) > 2 * 1024 * 1024:
        raise ValueError('Native output exceeds its bounded transfer envelope')
    lines = output.replace(b'\r', b'').strip(b'\n').split(b'\n')
    if len(lines) < 2 or lines[0] != BEGIN or lines[-1] != END or lines.count(BEGIN) != 1 or lines.count(END) != 1:
        raise ValueError('Missing, duplicate or unordered native transfer markers')
    content = bytearray()
    for line in lines[1:-1]:
        match = re.fullmatch(rb'@([0-9a-f]{8}):([0-9a-f]{2}):([0-9a-f]+)', line)
        if not match:
            raise ValueError('Malformed, unknown or truncated native transfer record')
        offset, size = int(match[1], 16), int(match[2], 16)
        if not 0 < size <= 128 or len(match[3]) != size * 2 or offset != len(content):
            raise ValueError('Invalid transfer record offset/size')
        content.extend(bytes.fromhex(match[3].decode()))
        if len(content) > MAX_BYTES:
            raise ValueError('File exceeds the fixed source limit')
    data = bytes(content)
    if expected_bytes is not None and (type(expected_bytes) is not int or len(data) != expected_bytes):
        raise ValueError('Source and received byte counts disagree')
    if expected_md5 is not None and hashlib.md5(data).hexdigest() != expected_md5:
        raise ValueError('Source and received MD5 disagree')
    return data


def synthetic_transfer(data):
    records = [b'@%08x:%02x:' % (offset, len(data[offset:offset + 128])) + data[offset:offset + 128].hex().encode()
               for offset in range(0, len(data), 128)]
    return b'\n'.join([BEGIN] + records + [END]) + b'\n'


def emulate(image, content, fixture):
    machine = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    machine.mem_map(BASE, 4096)
    machine.mem_write(BASE, image)
    machine.mem_protect(BASE, 4096, UC_PROT_READ | UC_PROT_EXEC)
    machine.mem_map(0x200000, 16384, UC_PROT_READ | UC_PROT_WRITE)
    machine.reg_write(UC_ARM_REG_SP, 0x204000)
    state = {'position': 0, 'fd': None, 'open_calls': 0, 'read_calls': 0,
             'write_calls': 0, 'close_calls': 0, 'exit': None, 'closed_on_exit': False}
    output, trace = bytearray(), hashlib.sha256()
    syscalls = set()

    def ret(uc, value):
        uc.reg_write(UC_ARM_REG_R0, value & 0xffffffff)

    def store(uc, access, address, size, value, unused):
        assert WORK <= address and address + size <= 0x204000

    def syscall(uc, interrupt, unused):
        number = uc.reg_read(UC_ARM_REG_R7)
        r0, r1, r2 = (uc.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        syscalls.add(number)
        trace.update(struct.pack('<4I', number, r0, r1, r2))
        if number == 5:
            assert state['open_calls'] == 0 and (r0, r1, r2) == (BASE + 496, 0, 0)
            assert bytes(uc.mem_read(r0, len(SOURCE_PATH))) == SOURCE_PATH
            state['open_calls'] += 1
            value = -13 if fixture == 'open_error' else 0 if fixture == 'fd_zero' else 7
            if value >= 0:
                state['fd'] = value
            ret(uc, value)
        elif number == 3:
            assert state['fd'] is not None and (r0, r1, r2) == (state['fd'], WORK, 128)
            state['read_calls'] += 1
            assert state['read_calls'] <= MAX_BYTES + 1
            chunk = content[state['position']:state['position'] + (1 if fixture == 'short_reads' else r2)]
            value = -5 if fixture == 'read_error' else -4 if fixture == 'read_eintr' else len(chunk)
            if value > 0:
                uc.mem_write(r1, chunk)
                state['position'] += value
            ret(uc, value)
        elif number == 4:
            assert r0 == 1 and 0 < r2 <= 270
            assert BASE <= r1 and r1 + r2 <= BASE + len(image) or WORK <= r1 and r1 + r2 <= 0x204000
            state['write_calls'] += 1
            chunk = bytes(uc.mem_read(r1, r2))
            value = -5 if fixture == 'write_error' else r2 - 1 if fixture == 'short_write' else r2
            output.extend(chunk[:max(0, value)])
            ret(uc, value)
        elif number == 6:
            assert state['fd'] is not None and r0 == state['fd'] and state['close_calls'] == 0
            state['close_calls'] += 1
            value = -4 if fixture == 'close_eintr' else -9 if fixture == 'close_error' else 0
            if fixture != 'close_eintr':
                state['fd'] = None
            ret(uc, value)
        elif number == 1:
            state['exit'] = r0
            if state['fd'] is not None:
                state['closed_on_exit'] = True
                state['fd'] = None
            uc.emu_stop()
        else:
            raise AssertionError('Forbidden syscall ' + str(number))

    machine.hook_add(UC_HOOK_MEM_WRITE, store)
    machine.hook_add(UC_HOOK_INTR, syscall)
    machine.emu_start(ENTRY, BASE + len(image), count=20000000)
    success = fixture in ('normal', 'empty', 'boundary', 'short_reads', 'fd_zero')
    assert state['exit'] == (0 if success else 1) and state['fd'] is None, (fixture, state)
    if success:
        assert state['close_calls'] == 1 and decode_transfer(bytes(output)) == content
    else:
        try:
            decode_transfer(bytes(output), len(content), hashlib.md5(content).hexdigest())
        except ValueError:
            pass
        else:
            raise AssertionError('Failure trace accepted as a complete transfer')
    assert syscalls <= {1, 3, 4, 5, 6}
    return {'fixture': fixture, 'input_bytes': len(content), 'state': state,
            'stdout_bytes': len(output), 'stdout_sha256': hashlib.sha256(output).hexdigest(),
            'syscalls': sorted(syscalls), 'syscall_trace_sha256': trace.hexdigest(), 'result': 'PASS'}


def check_decoder():
    content = bytes(range(256)) + bytes(range(44))
    valid = synthetic_transfer(content)
    lines = valid.splitlines()
    invalid = [b'', valid + valid, valid[:-4], valid.replace(BEGIN, b'BAD'),
               valid.replace(END, ERROR), valid.replace(lines[2], b''),
               valid.replace(lines[2], lines[1]), valid.replace(lines[1], lines[1][:-1]),
               valid.replace(lines[1], lines[1][:-1] + b'g'),
               b'\n'.join([lines[0], lines[2], lines[1]] + lines[3:]) + b'\n',
               valid.replace(lines[1], lines[1] + b'00'), valid.replace(lines[1], b'@00000000:00:00')]
    for value in invalid:
        try:
            decode_transfer(value, len(content), hashlib.md5(content).hexdigest())
        except ValueError:
            continue
        raise AssertionError('Invalid native transfer accepted')
    assert decode_transfer(valid.replace(b'\n', b'\r\n')) == content
    return {'negative_cases': len(invalid), 'crlf_roundtrip': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assemble-only', action='store_true')
    args = parser.parse_args()
    state = json.loads((ROOT / 'work/autopilot/20261105-rx100-pre-capture/state.json').read_text())
    if state.get('stopped'):
        raise SystemExit('Autopilot stopped; no build/test iteration')
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    source, objpath = ROOT / 'scripts/native/m7_mprctrl_read.S', ARTIFACTS / 'm7-mprctrl-reader.o'
    argv = ['clang', '--target=armv7-none-eabi', '-c', str(source), '-o', str(objpath)]
    subprocess.run(argv, check=True)
    obj = ELFFile(io.BytesIO(objpath.read_bytes()))
    assert not any(s['sh_type'] in ('SHT_REL', 'SHT_RELA') and s.num_relocations() for s in obj.iter_sections())
    symbols = {s.name: s['st_value'] for s in obj.get_section_by_name('.symtab').iter_symbols()}
    assert symbols['source_path'] == 412 and symbols['code_end'] == 396
    code = obj.get_section_by_name('.text').data()
    size = len(code) + 84
    ident = b'\x7fELF' + bytes([1, 1, 1, 0]) + bytes(8)
    image = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 40, 1, ENTRY, 52, 0, 0x05000000, 52, 32, 1, 0, 0, 0)
    image += struct.pack('<IIIIIIII', 1, 0, BASE, BASE, size, size, 5, 4096) + code
    validate_reader(image)
    original = (ROOT / 'artifacts/m7-liro-reader/m7-liro-reader.elf').read_bytes()
    assert hashlib.sha256(original).hexdigest() == LIRO_SHA256
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    before = list(decoder.disasm(original[84:480], ENTRY))
    after = list(decoder.disasm(image[84:480], ENTRY))
    assert len(before) == len(after) == 99
    changes = []
    for a, b in zip(before, after):
        if a.bytes != b.bytes:
            assert a.mnemonic == b.mnemonic == 'add' and a.op_str.startswith('r1, pc, #') and b.op_str.startswith('r1, pc, #')
            old, new = (int(x.op_str.rsplit('#', 1)[1], 0) for x in (a, b))
            assert new == old + 4
            changes.append({'address': hex(a.address), 'old': a.op_str, 'new': b.op_str})
    assert len(changes) == 3
    IMAGE_PATH.write_bytes(image)
    (ARTIFACTS / 'disassembly.txt').write_text('\n'.join(f'{i.address:08x} {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in after) + '\n')
    decoder_tests = check_decoder()
    if args.assemble_only:
        print(json.dumps({'bytes': size, 'sha256': IMAGE_SHA256, 'changed_adr': changes, 'decoder': decoder_tests, 'native_emulation': False}))
        return
    fixture_data = bytes(range(256)) * 3 + b'\x00\r\n'
    fixtures = ('normal', 'open_error', 'read_error', 'read_eintr', 'write_error', 'short_write',
                'close_error', 'close_eintr', 'fd_zero', 'short_reads', 'empty', 'boundary', 'over_limit')
    tests = []
    for fixture in fixtures:
        content = b'' if fixture == 'empty' else b'x' * MAX_BYTES if fixture == 'boundary' else b'x' * (MAX_BYTES + 1) if fixture == 'over_limit' else fixture_data
        tests.append(emulate(image, content, fixture))
    manifest = {'source': str(source.relative_to(ROOT)), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'builder_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'compile_argv': argv,
                'file': str(IMAGE_PATH.relative_to(ROOT)), 'bytes': size, 'sha256': IMAGE_SHA256,
                'fixed_source': SOURCE, 'open_flags': 0, 'max_source_bytes': MAX_BYTES,
                'prior_liro_sha256': LIRO_SHA256, 'instruction_changes_vs_liro': changes,
                'invariants': {'no_relocations': True, 'one_rx_segment': True, 'all_other_instructions_identical_to_liro': True,
                               'only_own_stack_writes': True, 'stdout_only': True, 'no_path_cli': True},
                'versions': {'python': sys.version, 'host': platform.platform(), 'unicorn': unicorn.__version__,
                             'capstone': capstone.__version__, 'pyelftools': elftools.__version__,
                             'clang': subprocess.check_output(['clang', '--version'], text=True).splitlines()[0]},
                'native_tests': tests, 'decoder_tests': decoder_tests, 'camera_execution': False, 'sony_code_execution': False}
    (ARTIFACTS / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'bytes': size, 'sha256': IMAGE_SHA256, 'fixtures': len(tests), 'decoder_rejections': decoder_tests['negative_cases'], 'camera_execution': False}))


if __name__ == '__main__':
    main()
