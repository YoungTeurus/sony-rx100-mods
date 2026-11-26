#!/usr/bin/env python3
"""Observe fixed M7 object headers and two RAW descriptors with the unchanged proc32 reader."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import struct
import time

from elftools.elf.elffile import ELFFile

import m7_im_code_read as rx
from m7_terminal_steps import StepGate, frame, read_ready, run_step

probe = rx.probe
CORE_ROOT = 0x1541490
MPR_ROOT = 0x15405d0
CORE_VPTR = 0xa75b90
FEA_VPTR = 0xa7cce8
CORE_SIZE = 0x30990
RAW_OFFSET = 0x10b8
NAMES = ('core_root', 'mpr_root', 'mpr', 'fea', 'core', 'raw_before',
         'raw_after', 'core_after', 'fea_after', 'mpr_after', 'mpr_root_after', 'core_root_after')


def local_layout():
    rx.local_target()
    elf = ELFFile(io.BytesIO(rx.LIBRARY.read_bytes()))
    for name, va in (('_ZN9MprIfMcmd10mp_feaCoreE', CORE_ROOT),
                     ('_ZN9MprIfMcmd8mp_mprIfE', MPR_ROOT)):
        symbols = [s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name == name]
        if len(symbols) != 1 or symbols[0]['st_value'] != va or symbols[0]['st_size'] != 4:
            raise probe.ProbeError('Pinned M7 root symbol differs')
        section = elf.get_section(symbols[0]['st_shndx'])
        if section['sh_type'] != 'SHT_NOBITS' or not section['sh_addr'] <= va < section['sh_addr'] + section['sh_size']:
            raise probe.ProbeError('Pinned root is not in BSS')
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_flags'] == 6]
    if len(segments) != 1:
        raise probe.ProbeError('Ambiguous M7 RW segment')
    segment = segments[0]
    result = {k: segment[k] for k in ('p_vaddr', 'p_filesz', 'p_memsz', 'p_offset')}
    if result != {'p_vaddr': 0xc532e0, 'p_filesz': 0x2a408, 'p_memsz': 0x8f80f8, 'p_offset': 0xc4b2e0}:
        raise probe.ProbeError('Pinned M7 RW layout differs')
    return result


def map_rows(text):
    rows = []
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-f]+)-([0-9a-f]+) ([rwxps-]{4}) ([0-9a-f]+) '
                             r'([0-9a-f]+:[0-9a-f]+) ([0-9]+)\s*(.*)', line.strip())
        if not match:
            raise probe.ProbeError('Invalid maps row')
        start, end, flags, offset, device, inode, path = match.groups()
        row = dict(start=int(start, 16), end=int(end, 16), flags=flags, offset=int(offset, 16),
                   device=device, inode=int(inode), path=path)
        if row['start'] >= row['end'] or (rows and rows[-1]['end'] > row['start']):
            raise probe.ProbeError('Unordered or overlapping mappings')
        rows.append(row)
    return rows


def private_ram(rows, address, size=32):
    if not isinstance(address, int) or address & 3 or not 0x10000 <= address <= 0xc0000000 - size:
        raise probe.ProbeError('Null, unaligned or non-user RAM address')
    matches = [r for r in rows if r['start'] <= address and address + size <= r['end']]
    if len(matches) != 1:
        raise probe.ProbeError('RAM span crosses or misses a mapping')
    row = matches[0]
    if (row['flags'] != 'rw-p' or row['device'] != '00:00' or row['inode'] != 0
            or row['offset'] != 0 or row['path'] not in ('', '[heap]')):
        raise probe.ProbeError('Only private anonymous RAM or heap is allowed')
    return row


class AnchorPlan:
    def __init__(self, bias, layout):
        self.bias, self.layout = bias, layout
        self.values = {}
        self.index = 0

    def expected(self, name):
        if self.index >= len(NAMES) or name != NAMES[self.index]:
            raise probe.ProbeError('Unexpected read order or read count')
        if name.startswith('core_root'):
            return self.bias + CORE_ROOT
        if name.startswith('mpr_root'):
            return self.bias + MPR_ROOT
        if name.startswith('mpr'):
            return self.values['mpr_root'][0]
        if name.startswith('fea'):
            return self.values['mpr'][0]
        return self.values['core_root'][0] + (RAW_OFFSET if name.startswith('raw') else 0)

    def guard(self, name, rows):
        address = self.expected(name)
        row = private_ram(rows, address)
        if name.startswith(('core_root', 'mpr_root')):
            low = (self.bias + self.layout['p_vaddr'] + self.layout['p_filesz'] + 0xfff) & ~0xfff
            high = (self.bias + self.layout['p_vaddr'] + self.layout['p_memsz'] + 0xfff) & ~0xfff
            if row['path'] or row['start'] < low or row['end'] > high:
                raise probe.ProbeError('Root mapping is not the pinned libmpr anonymous BSS tail')
        if name.startswith(('core', 'raw')) and not name.startswith('core_root'):
            private_ram(rows, self.values['core_root'][0], CORE_SIZE)
        return address, row

    def accept(self, name, native):
        address = self.expected(name)
        if not native['complete'] or native['address'] != address or native['data_bytes'] != 32:
            raise probe.ProbeError('Incomplete native read or wrong target address')
        words = list(struct.unpack('<8I', bytes.fromhex(native['data_hex'])))
        first = name.removesuffix('_after')
        if name in ('core_root', 'mpr_root', 'mpr') and (words[0] & 3 or not 0x10000 <= words[0] < 0xc0000000):
            raise probe.ProbeError('Null or invalid object pointer')
        if name.startswith('fea') and words[:2] != [self.bias + FEA_VPTR, self.values['core_root'][0]]:
            raise probe.ProbeError('FeaIf vptr/core link mismatch')
        if name in ('core', 'core_after') and words[0] != self.bias + CORE_VPTR:
            raise probe.ProbeError('FeaCore vptr mismatch or teardown')
        if name.endswith('_after') and first in ('core_root', 'mpr_root', 'mpr'):
            if words[0] != self.values[first][0]:
                raise probe.ProbeError('Object chain changed across reads')
        self.values[name] = words
        self.index += 1
        return words


class MultiReadGate(StepGate):
    def __init__(self, device, specs):
        super().__init__(device, specs, 0)
        self.exec_allowed = True
        self.executions = set()
        self.armed = None

    def register(self, specs, execution=None):
        if any(s[0] in self.frames for s in specs):
            raise probe.ProbeError('Duplicate frame')
        self.frames.extend(s[0] for s in specs)
        if execution is not None:
            if execution[0] not in self.frames or self.armed is not None:
                raise probe.ProbeError('Invalid execution registration')
            self.executions.add(execution[0])

    def arm(self, spec):
        if spec[0] not in self.executions or self.armed is not None:
            raise probe.ProbeError('Invalid helper execution gate')
        self.armed = spec[0]

    def check_frame(self, data):
        if data not in self.frames:
            raise probe.ProbeError('Unknown terminal step')
        if data in self.executions:
            if self.armed != data:
                raise probe.ProbeError('Helper execution lacks current host checksum/identity approval')
            self.armed = None

    def writeTerminal(self, data):
        self.check_frame(data)
        return super().writeTerminal(data)


def descriptor(words):
    return {'raw_main': dict(zip(('virtual_address', 'size', 'physical_extent_pointer', 'physical_extent_count'), words[:4])),
            'raw_additional': dict(zip(('address', 'length', 'word2', 'word3'), words[4:]))}


def execute(camera, output, target, layout, initial_specs, artifact=None, stepper=run_step,
            pause=time.sleep, ready=read_ready):
    specs = list(initial_specs)
    output['commands'] = rx.preflight_commands()
    nonce = output['nonce']
    directory = '/tmp_network/.m7-anchors-' + nonce
    executable = directory + '/probe.elf'
    cleanup = '/bin/busybox rm -f ' + executable + ' && /bin/busybox rmdir ' + directory
    created = cleaned = False
    initial_identity = None

    def add(commands, execution_offset=None):
        first = len(specs)
        added = [frame(cmd, first+i, nonce) for i, cmd in enumerate(commands)]
        camera.dev.register(added, None if execution_offset is None else added[execution_offset])
        specs.extend(added)
        output['commands'].extend(commands)
        return first

    def step(index, **kwargs):
        return stepper(camera, specs[index], index, output['steps'], **kwargs)

    def identify(pid):
        first = add(rx.identity_commands(pid))
        bodies = [step(first+i).decode() for i in range(4)]
        identity = rx.parse_identity(pid, *bodies, target)
        if initial_identity is not None:
            rx.same_identity(initial_identity, identity)
        return identity, map_rows(bodies[3])

    def read(name, plan, pid):
        address = plan.expected(name)
        image = rx.patch_template(pid, address)
        patch = rx.validate_patched(image, pid, address)
        record = {'name': name, 'address': address, 'helper_patch': patch}
        output['reads'].append(record)
        if artifact is not None:
            artifact.mkdir(parents=True, exist_ok=True)
            image_file = artifact / (name + '.elf')
            image_file.write_bytes(image)
            record['host_helper'] = str(image_file.relative_to(probe.ROOT))
        upload = []
        for offset in range(0, len(image), 48):
            chunk = image[offset:offset+48]
            upload.append("/bin/busybox echo -ne '" + ''.join('\\0%03o' % b for b in chunk) +
                          "' " + ('>' if offset == 0 else '>>') + ' ' + executable)
        first = add(upload + ['/bin/busybox md5sum ' + executable, '/bin/busybox chmod 500 ' + executable])
        for i in range(first, first+len(upload)):
            step(i)
        checksum_index = first+len(upload)
        if step(checksum_index).decode().strip() != hashlib.md5(image).hexdigest() + '  ' + executable:
            raise probe.ProbeError('Uploaded reader checksum mismatch; no execution')
        record['helper_md5_verified_on_host'] = True
        step(checksum_index+1)
        identity, rows = identify(pid)
        guarded_address, row = plan.guard(name, rows)
        if guarded_address != address:
            raise probe.ProbeError('Read target changed before execution')
        record['identity_before_exec'], record['mapping'] = identity, row
        index = add([executable], execution_offset=0)
        camera.dev.arm(specs[index])
        native = rx.parse_record(step(index, timeout=12))
        record['native'] = native
        record['words'] = plan.accept(name, native)
        print('READ_OK: ' + name, flush=True)

    try:
        with probe.deadline(8):
            camera.setTerminalEnable(False)
            camera.setTerminalEnable(True)
        with probe.deadline(10):
            output['shell_banner'] = ready(camera).decode('utf-8', 'replace')
        bodies = [step(i, allowed_status=(0, 1) if i == 4 else (0,)).decode() for i in range(6)]
        output['preflight_checks'] = rx.checked_preflight(bodies)
        pid = rx.parse_pid(step(6).decode())
        initial_identity, rows = identify(pid)
        output['identity_before'] = initial_identity
        index = add(['/bin/busybox md5sum ' + rx.CAMERA_LIBRARY])
        if step(index).decode().strip() != target['library_md5'] + '  ' + rx.CAMERA_LIBRARY:
            raise probe.ProbeError('Camera libmpr checksum differs')
        output['library_md5_verified_on_host'] = True
        plan = AnchorPlan(initial_identity['load_bias'], layout)
        plan.guard('core_root', rows)
        print('PREFLIGHT_OK: оригинальная M7, fresh PID/maps, libmpr и tmpfs проверены.', flush=True)
        index = add(['/bin/busybox mkdir ' + directory])
        step(index)
        created = True
        output['ram_directory'] = directory
        for name in NAMES:
            if name == 'raw_after':
                print('M7_ANCHORS_READY: цепочка объектов сверена. Сделайте один обычный снимок в течение 15 секунд.', flush=True)
                output['photo_window_seconds'] = 15
                pause(15)
                print('PHOTO_WINDOW_ENDED: повторное чтение описаний и проверка объектов.', flush=True)
            read(name, plan, pid)
        after, _ = identify(pid)
        output['identity_after'] = after
        output['process_identity_unchanged'] = True
        output['object_chain_consistent_across_reads'] = True
        output['raw_before'] = descriptor(plan.values['raw_before'])
        output['raw_after'] = descriptor(plan.values['raw_after'])
        output['raw_descriptor_changed'] = plan.values['raw_before'] != plan.values['raw_after']
        output['photo_capture_confirmed'] = False
        output['coherent_frame_or_ownership_proved'] = False
        print('ANCHOR_READ_DONE: object_chain=True; descriptor_changed=' + str(output['raw_descriptor_changed']), flush=True)
    finally:
        if created:
            try:
                index = add([cleanup, 'ls -ld ' + directory])
                step(index)
                absent = step(index+1, allowed_status=(1,)).decode()
                if 'ls: ' + directory + ': No such file or directory' not in absent:
                    raise probe.ProbeError('RAM cleanup not confirmed')
                cleaned = True
            except Exception as error:
                output['cleanup_error'] = str(error)
        output['ram_cleanup_verified'] = cleaned
        try:
            with probe.deadline(8):
                camera.setTerminalEnable(False)
            output['terminal_disable_sent'] = True
        except Exception as error:
            output['terminal_disable_error'] = str(error)
        output['terminal_packets'] = camera.dev.packet_log
    if not cleaned:
        raise probe.ProbeError('RAM cleanup incomplete')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--connect', action='store_true')
    mode.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        from test_m7_anchor_probe import main as test
        test()
        return 0
    target, layout = rx.local_target(), local_layout()
    nonce = secrets.token_hex(6)
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    output = {'version': 1, 'utc': stamp, 'nonce': nonce,
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'target': target, 'layout': layout, 'file_control_allowed': False,
              'steps': [], 'reads': [], 'read_limit': 12, 'read_bytes_each': 32}
    initial = [frame(cmd, i, nonce) for i, cmd in enumerate(rx.preflight_commands())]
    artifact = probe.ROOT / 'artifacts/m7-anchor-probe' / stamp
    try:
        probe.connect(output, diagnostic=lambda camera, result: execute(camera, result, target, layout, initial, artifact),
                      gate_factory=lambda device: MultiReadGate(device, initial))
    except (Exception, KeyboardInterrupt) as error:
        output['error'] = type(error).__name__ + ': ' + str(error)
        print(output['error'], flush=True)
    destination = probe.ROOT / 'evidence' / ('m7-anchor-probe-' + stamp + '.json')
    destination.write_text(json.dumps(output, ensure_ascii=False, indent=2)+'\n')
    print('RESULT=' + str(destination), flush=True)
    return 1 if 'error' in output else 0


if __name__ == '__main__':
    raise SystemExit(main())
