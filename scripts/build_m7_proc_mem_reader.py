#!/usr/bin/env python3
"""Build an exact 32-byte proc reader and patch only its two input data regions."""
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
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR, UC_HOOK_CODE,
                     UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R7,
                               UC_ARM_REG_SP)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'artifacts/m7-proc-mem-reader'
TEMPLATE_PATH = ARTIFACTS / 'm7-proc-mem-reader-template.elf'
TEMPLATE_BYTES = 616
TEMPLATE_SHA256 = 'e5c05c8725cb6defc402a9327e9d2f29822b19164737fa20d167e91691369ef9'
PATH_OFFSET, PATH_CAPACITY, ADDRESS_OFFSET = 580, 32, 612
PATCH_REGIONS = ({'name': 'proc_path', 'offset': PATH_OFFSET, 'bytes': PATH_CAPACITY},
                 {'name': 'address_le32', 'offset': ADDRESS_OFFSET, 'bytes': 4})
BASE, ENTRY, STACK, STACK_BYTES, WORK_BYTES = 0x10000, 0x10054, 0x20000, 4096, 320
READ_BYTES = 32
MAX_ADDRESS = 0xffffffe0
UNKNOWN = 0x80000000
PREFIX = b'M7_MEM32_V1='
FIELDS = ('config_rc', 'open_rc', 'seek_rc', 'seek_lo', 'seek_hi', 'read_rc',
          'close_rc', 'address', 'data_valid')
LINE_BYTES = len(PREFIX) + len(FIELDS) * 8 + READ_BYTES * 2 + 1
SYSCALLS = (1, 3, 4, 5, 6, 140)
SYNTHETIC_DATA = bytes((index * 37) & 0xff for index in range(READ_BYTES))


def _validate_parameters(pid, address):
    if type(pid) is not int or not 1 <= pid <= 0x7fffffff:
        raise ValueError('PID must be a positive signed 32-bit integer')
    if type(address) is not int or not 2 <= address <= MAX_ADDRESS or address & 1:
        raise ValueError('Address must be nonzero, even, and contain the complete 32-byte span in uint32')


def validate_template(image):
    if not isinstance(image, bytes) or len(image) != TEMPLATE_BYTES:
        raise ValueError('Unexpected reader template type or size')
    if hashlib.sha256(image).hexdigest() != TEMPLATE_SHA256:
        raise ValueError('Reader template SHA256 mismatch')
    return {'bytes': TEMPLATE_BYTES, 'sha256': TEMPLATE_SHA256, 'patch_regions': PATCH_REGIONS}


def _load_template():
    image = TEMPLATE_PATH.read_bytes()
    validate_template(image)
    return image


def _configured_image(template, pid, address):
    _validate_parameters(pid, address)
    path = f'/proc/{pid}/mem'.encode('ascii')
    assert len(path) < PATH_CAPACITY
    image = bytearray(template)
    image[PATH_OFFSET:PATH_OFFSET + PATH_CAPACITY] = path + bytes(PATH_CAPACITY - len(path))
    struct.pack_into('<I', image, ADDRESS_OFFSET, address)
    return bytes(image)


def validate_patched(image, pid, address):
    _validate_parameters(pid, address)
    template = _load_template()
    expected = _configured_image(template, pid, address)
    if not isinstance(image, bytes) or image != expected:
        raise ValueError('Patched reader differs from the exact template and requested PID/address')
    changed = [index for index, pair in enumerate(zip(template, image)) if pair[0] != pair[1]]
    allowed = set(range(PATH_OFFSET, PATH_OFFSET + PATH_CAPACITY)) | set(range(ADDRESS_OFFSET, ADDRESS_OFFSET + 4))
    assert all(index in allowed for index in changed)
    return {'pid': pid, 'address': address, 'proc_path': f'/proc/{pid}/mem',
            'bytes': len(image), 'sha256': hashlib.sha256(image).hexdigest(),
            'template_sha256': TEMPLATE_SHA256, 'patch_regions': PATCH_REGIONS,
            'changed_offsets': changed, 'instructions_unchanged': True, 'read_bytes': READ_BYTES}


def patch_template(pid, address):
    _validate_parameters(pid, address)
    image = _configured_image(_load_template(), pid, address)
    validate_patched(image, pid, address)
    return image


def parse_record(output):
    if not isinstance(output, bytes):
        raise TypeError('Native output must be bytes')
    candidates = [line for line in output.replace(b'\r', b'').splitlines() if line.startswith(PREFIX)]
    if len(candidates) != 1:
        raise ValueError('Missing or duplicate native mem32 result')
    match = re.fullmatch(re.escape(PREFIX) + rb'([0-9a-f]{72})([0-9a-f]{64})', candidates[0])
    if not match:
        raise ValueError('Incomplete or malformed native mem32 result')
    raw = dict(zip(FIELDS, (int(match[1][offset:offset + 8], 16) for offset in range(0, 72, 8))))
    rc = {name: None if raw[name] == UNKNOWN else raw[name] if raw[name] < 0x80000000 else raw[name] - 0x100000000
          for name in FIELDS if name.endswith('_rc')}
    if rc['config_rc'] not in (0, -22) or raw['data_valid'] not in (0, 1):
        raise ValueError('Invalid native configuration/data-valid status')
    position = raw['seek_lo'] | raw['seek_hi'] << 32 if rc['seek_rc'] == 0 else None
    read_complete = (rc['config_rc'] == 0 and rc['open_rc'] is not None and rc['open_rc'] >= 0
                     and rc['seek_rc'] == 0 and position == raw['address'] and rc['read_rc'] == READ_BYTES)
    if bool(raw['data_valid']) != read_complete:
        raise ValueError('Data-valid flag disagrees with the completed fixed-length read')
    data_hex = match[2].decode('ascii')
    if not read_complete and data_hex != '00' * READ_BYTES:
        raise ValueError('Invalid read must contain zero padding, not purported measured bytes')
    close_ok = rc['close_rc'] == 0 and rc['open_rc'] is not None and rc['open_rc'] >= 0
    return {'version': 1, 'raw_words': raw, 'config_rc': rc['config_rc'],
            'syscalls': {name: value for name, value in rc.items() if name != 'config_rc'},
            'address': raw['address'], 'seek_position': position, 'read_complete': read_complete,
            'data_hex': data_hex if read_complete else None,
            'data_bytes': READ_BYTES if read_complete else None,
            'close_ok': close_ok, 'complete': read_complete and close_ok}


def emulate(image, fixture, pid, address):
    machine = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    machine.mem_map(BASE, 4096)
    machine.mem_write(BASE, image)
    machine.mem_protect(BASE, 4096, UC_PROT_READ | UC_PROT_EXEC)
    machine.mem_map(STACK, STACK_BYTES, UC_PROT_READ | UC_PROT_WRITE)
    machine.reg_write(UC_ARM_REG_SP, STACK + STACK_BYTES)
    work = STACK + STACK_BYTES - WORK_BYTES
    code_end = BASE + image.index(PREFIX)
    state = {'fd': None, 'position': None, 'read_calls': 0, 'exit': None,
             'instructions': 0, 'closed_on_exit': False}
    trace, output = [], bytearray()

    def result(uc, value):
        uc.reg_write(UC_ARM_REG_R0, value & 0xffffffff)

    def instruction(uc, at, size, unused):
        assert ENTRY <= at < code_end
        state['instructions'] += 1
        assert state['instructions'] < 10000

    def memory_write(uc, access, at, size, value, unused):
        assert work <= at and at + size <= STACK + STACK_BYTES

    def syscall(uc, interrupt, unused):
        number = uc.reg_read(UC_ARM_REG_R7)
        regs = [uc.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                            UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4)]
        r0, r1, r2, r3, r4 = regs
        assert number in SYSCALLS
        event = {'syscall': number, 'args': regs}
        if number == 5:
            assert state['fd'] is None and r0 == BASE + PATH_OFFSET and r1 == r2 == 0
            path = bytes(uc.mem_read(r0, PATH_CAPACITY))
            expected = f'/proc/{pid}/mem'.encode()
            assert path == expected + bytes(PATH_CAPACITY - len(expected))
            value = {'open_eacces': -13, 'open_eperm': -1, 'open_enoent': -2}.get(fixture, 0 if fixture == 'fd_zero' else 11)
            if value >= 0:
                state['fd'] = value
            result(uc, value)
            event.update(rc=value, path=expected.decode(), flags=0)
        elif number == 140:
            assert state['fd'] is not None and r0 == state['fd']
            assert (r1, r2, r3, r4) == (0, address, work + 12, 0)
            value = -5 if fixture == 'seek_error' else 0
            if value == 0:
                position = address + 2 if fixture == 'seek_wrong_low' else (1 << 32) | address if fixture == 'seek_wrong_high' else address
                uc.mem_write(r3, struct.pack('<Q', position))
                state['position'] = position
            result(uc, value)
            event['rc'] = value
        elif number == 3:
            state['read_calls'] += 1
            assert state['read_calls'] == 1 and state['fd'] is not None and r0 == state['fd']
            assert r1 == work + 64 and r2 == READ_BYTES and state['position'] == address
            value = {'read_eio': -5, 'read_esrch': -3, 'read_eof': 0,
                     'read_one_byte': 1, 'read_31_bytes': 31}.get(fixture, READ_BYTES)
            if value > 0:
                uc.mem_write(r1, SYNTHETIC_DATA[:value])
            result(uc, value)
            event.update(rc=value, supplied_bytes=SYNTHETIC_DATA[:max(value, 0)].hex())
        elif number == 6:
            assert state['fd'] is not None and r0 == state['fd']
            value = -9 if fixture == 'close_ebadf' else -4 if fixture in ('close_eintr', 'close_eintr_still_open') else 0
            if fixture != 'close_eintr_still_open':
                state['fd'] = None
            result(uc, value)
            event['rc'] = value
        elif number == 4:
            assert (r0, r1, r2) == (1, work + 128, LINE_BYTES)
            data = bytes(uc.mem_read(r1, r2))
            assert data.startswith(PREFIX) and data.endswith(b'\n')
            value = -5 if fixture == 'write_error' else LINE_BYTES - 2 if fixture == 'short_write' else LINE_BYTES
            output.extend(data[:max(value, 0)])
            result(uc, value)
            event['rc'] = value
        elif number == 1:
            state['exit'] = r0
            if state['fd'] is not None:
                state['closed_on_exit'] = True
                state['fd'] = None
            event['status'] = r0
            uc.emu_stop()
        trace.append(event)

    machine.hook_add(UC_HOOK_CODE, instruction)
    machine.hook_add(UC_HOOK_MEM_WRITE, memory_write)
    machine.hook_add(UC_HOOK_INTR, syscall)
    machine.emu_start(ENTRY, BASE + len(image), count=10000)
    expected_exit = 81 if fixture in ('short_write', 'write_error') else 0
    assert state['exit'] == expected_exit and state['fd'] is None
    parsed = None if expected_exit != 0 else parse_record(bytes(output))
    if parsed is not None:
        success = fixture in ('success', 'fd_zero', 'pid_one', 'pid_max', 'high_address', 'max_span', 'halfword_aligned')
        measured = success or fixture in ('close_eintr', 'close_eintr_still_open', 'close_ebadf')
        assert parsed['complete'] == success, (fixture, parsed)
        assert parsed['read_complete'] == measured
        assert parsed['data_hex'] == (SYNTHETIC_DATA.hex() if measured else None)
        if fixture.startswith('native_invalid') or fixture == 'unpatched_template':
            assert parsed['config_rc'] == -22
            assert [event['syscall'] for event in trace] == [4, 1]
    return {'fixture': fixture, 'pid': pid, 'address': address, 'trace': trace,
            'output': output.decode('ascii'), 'decoded': parsed, 'exit': state['exit'],
            'instructions': state['instructions'], 'closed_on_exit': state['closed_on_exit'],
            'image_sha256': hashlib.sha256(image).hexdigest()}


def check_patch_contract():
    rejected = 0
    for pid in (0, -1, 0x80000000, True, '161', 1.5):
        try:
            patch_template(pid, 0x8040000)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('Invalid PID accepted')
    for address in (0, -1, 1, 3, 0xffffffff, 0xffffffe2, 0x100000000, True, '0x8040000'):
        try:
            patch_template(161, address)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('Invalid address accepted')
    valid = patch_template(161, 0x8040000)
    for offset in (0, 83, 84, 568, PATH_OFFSET, PATH_OFFSET + PATH_CAPACITY - 1, ADDRESS_OFFSET):
        invalid = bytearray(valid)
        invalid[offset] ^= 1
        try:
            validate_patched(bytes(invalid), 161, 0x8040000)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('Mutation outside requested exact image accepted')
    try:
        validate_template(valid)
    except ValueError:
        rejected += 1
    else:
        raise AssertionError('Patched image accepted as empty template')
    return {'rejected_cases': rejected, 'changed_regions_only': validate_patched(valid, 161, 0x8040000)}


def check_parser(success):
    bad = [b'', success + success, success[:-2], success.replace(PREFIX, b'M7_MEM32_V2='),
           success[:-2] + b'g\n', success[:-1] + b'junk\n']
    raw = list(parse_record(success)['raw_words'].values())
    raw[-1] = 0
    bad.append(PREFIX + ''.join(f'{word:08x}' for word in raw).encode() + SYNTHETIC_DATA.hex().encode() + b'\n')
    raw[5] = 0
    bad.append(PREFIX + ''.join(f'{word:08x}' for word in raw).encode() + SYNTHETIC_DATA.hex().encode() + b'\n')
    for data in bad:
        try:
            parse_record(data)
        except ValueError:
            continue
        raise AssertionError('Malformed reader result accepted')
    assert parse_record(b'prompt\r\n' + success.replace(b'\n', b'\r\n') + b'prompt\r\n')['complete']
    return {'rejected_cases': len(bad), 'accepted_crlf_framing': True}


def main():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'scripts/native/m7_proc_mem_reader.S'
    object_path = ARTIFACTS / 'm7-proc-mem-reader.o'
    argv = ['clang', '--target=armv7-none-eabi', '-c', str(source), '-o', str(object_path)]
    subprocess.run(argv, check=True)
    obj = ELFFile(io.BytesIO(object_path.read_bytes()))
    assert obj['e_machine'] == 'EM_ARM'
    assert not any(section['sh_type'] in ('SHT_REL', 'SHT_RELA') and section.num_relocations()
                   for section in obj.iter_sections())
    symbols = {symbol.name: symbol['st_value'] for symbol in obj.get_section_by_name('.symtab').iter_symbols()}
    assert 84 + symbols['m7_reader_path'] == PATH_OFFSET
    assert 84 + symbols['m7_reader_address'] == ADDRESS_OFFSET
    code = obj.get_section_by_name('.text').data()
    size = 84 + len(code)
    ident = b'\x7fELF' + bytes([1, 1, 1, 0]) + bytes(8)
    header = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 40, 1, ENTRY, 52, 0, 0x05000000,
                         52, 32, 1, 0, 0, 0)
    template = header + struct.pack('<IIIIIIII', 1, 0, BASE, BASE, size, size, 5, 4096) + code
    validate_template(template)
    packaged = ELFFile(io.BytesIO(template))
    assert packaged.num_segments() == 1 and packaged.num_sections() == 0
    segment = packaged.get_segment(0)
    assert segment['p_type'] == 'PT_LOAD' and segment['p_flags'] == 5
    assert segment['p_filesz'] == segment['p_memsz'] == size
    assert template[PATH_OFFSET:ADDRESS_OFFSET + 4] == bytes(PATH_CAPACITY + 4)
    TEMPLATE_PATH.write_bytes(template)
    fixtures = ('success', 'open_eacces', 'open_eperm', 'open_enoent', 'seek_error',
                'seek_wrong_low', 'seek_wrong_high', 'read_eio', 'read_esrch', 'read_eof',
                'read_one_byte', 'read_31_bytes', 'close_eintr', 'close_eintr_still_open',
                'close_ebadf', 'short_write', 'write_error', 'fd_zero', 'pid_one', 'pid_max',
                'high_address', 'max_span', 'halfword_aligned', 'unpatched_template', 'native_invalid_path',
                'native_invalid_odd', 'native_invalid_wrap')
    tests = []
    for fixture in fixtures:
        pid = 1 if fixture == 'pid_one' else 0x7fffffff if fixture == 'pid_max' else 161
        address = (0xbeef0040 if fixture == 'high_address' else MAX_ADDRESS if fixture == 'max_span'
                   else 0x8040002 if fixture == 'halfword_aligned' else 0x8040000)
        image = patch_template(pid, address)
        if fixture == 'unpatched_template':
            image = template
        elif fixture.startswith('native_invalid'):
            mutable = bytearray(image)
            if fixture == 'native_invalid_path':
                mutable[PATH_OFFSET:PATH_OFFSET + PATH_CAPACITY] = bytes(PATH_CAPACITY)
            else:
                struct.pack_into('<I', mutable, ADDRESS_OFFSET, 0x8040001 if fixture == 'native_invalid_odd' else 0xfffffffe)
            image = bytes(mutable)
        tests.append(emulate(image, fixture, pid, address))
    patch_tests = check_patch_contract()
    parser_tests = check_parser(tests[0]['output'].encode())
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    disassembly = [f'{ins.address:08x} {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}'
                   for ins in decoder.disasm(code[:code.index(PREFIX)], ENTRY)]
    (ARTIFACTS / 'disassembly.txt').write_text('\n'.join(disassembly) + '\n')
    manifest = {'source': str(source.relative_to(ROOT)), 'compile_argv': argv,
                'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'builder_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'file': str(TEMPLATE_PATH.relative_to(ROOT)), 'bytes': size, 'sha256': TEMPLATE_SHA256,
                'entry': hex(ENTRY), 'patch_regions': PATCH_REGIONS,
                'invariants': {'one_rx_pt_load': True, 'no_interpreter': True, 'no_relocations': True,
                               'runtime_writable_data': 'own 320-byte stack', 'read_bytes': READ_BYTES,
                               'no_arbitrary_path_or_count_cli': True},
                'syscalls': SYSCALLS, 'record_bytes': LINE_BYTES, 'fields': FIELDS, 'unknown_word': hex(UNKNOWN),
                'versions': {'python': sys.version, 'host': platform.platform(),
                             'clang': subprocess.check_output(['clang', '--version'], text=True).splitlines()[0],
                             'unicorn': unicorn.__version__, 'capstone': capstone.__version__, 'pyelftools': elftools.__version__},
                'camera_execution': False, 'sony_code_execution': False,
                'tests': tests, 'patch_tests': patch_tests, 'parser_tests': parser_tests,
                'limits': 'Only own reader code runs under Unicorn. All proc reads return synthetic bytes. '
                          'Runner must independently gate the fresh PID/starttime, exact M7 ELF and RX mapping.'}
    (ARTIFACTS / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'bytes': size, 'sha256': TEMPLATE_SHA256, 'fixtures': len(tests),
                      'patch_rejections': patch_tests['rejected_cases'],
                      'parser_rejections': parser_tests['rejected_cases'], 'camera_execution': False}))


if __name__ == '__main__':
    main()
