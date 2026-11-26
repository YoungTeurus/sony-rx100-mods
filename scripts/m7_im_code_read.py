#!/usr/bin/env python3
"""Read exactly 32 bytes of the known M7 WriteStill RX mapping; no attach or writes."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import subprocess
import time

from elftools.elf.elffile import ELFFile

import m7_probe as probe
import m7_ram_liveness as ram
from build_m7_proc_mem_reader import patch_template, validate_patched, parse_record
from m7_terminal_steps import StepGate, frame, read_ready, run_step

LIBRARY = probe.ROOT / 'extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/lib/libmpr.so'
LIBRARY_SHA256 = '2b1057ab5069127398fb077fd4bd332cc21e47601b4d19f95d92987e599fbbe0'
SYMBOL = '_ZN5MprIf10WriteStillEPNS_15WriteStillParamEPN3MPR9StillInfoEm'
ELF_VA = 0x8cbf7a
READ_BYTES = 32
CAMERA_LIBRARY = '/usr/lib/libmpr.so'


def local_target():
    image = LIBRARY.read_bytes()
    if hashlib.sha256(image).hexdigest() != LIBRARY_SHA256:
        raise probe.ProbeError('Original M7 libmpr hash mismatch')
    elf = ELFFile(io.BytesIO(image))
    symbols = [s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name == SYMBOL]
    if len(symbols) != 1 or symbols[0]['st_value'] != (ELF_VA | 1) or symbols[0]['st_size'] < READ_BYTES:
        raise probe.ProbeError('M7 WriteStill symbol mismatch')
    loads = [p for p in elf.iter_segments() if p['p_type'] == 'PT_LOAD'
             and p['p_vaddr'] <= ELF_VA and ELF_VA + READ_BYTES <= p['p_vaddr'] + p['p_filesz']]
    if len(loads) != 1 or loads[0]['p_flags'] != 5:
        raise probe.ProbeError('WriteStill does not belong to the expected RX PT_LOAD')
    segment = loads[0]
    offset = segment['p_offset'] + ELF_VA - segment['p_vaddr']
    for section in elf.iter_sections():
        if section['sh_type'] in ('SHT_REL', 'SHT_RELA'):
            if any(ELF_VA <= r['r_offset'] < ELF_VA + READ_BYTES for r in section.iter_relocations()):
                raise probe.ProbeError('Target instructions have ELF relocations')
    return {'library_sha256': LIBRARY_SHA256, 'library_md5': hashlib.md5(image).hexdigest(),
            'symbol': SYMBOL, 'elf_va': ELF_VA, 'file_offset': offset, 'length': READ_BYTES,
            'segment_va': segment['p_vaddr'], 'segment_offset': segment['p_offset'],
            'expected_hex': image[offset:offset+READ_BYTES].hex()}


def parse_pid(text):
    text = text.strip()
    if not re.fullmatch(r'[1-9][0-9]{0,9}', text) or not 1 < int(text) <= 0x7fffffff:
        raise probe.ProbeError('Expected exactly one live im.elf PID')
    return int(text)


def parse_identity(pid, stat, status, executable, maps, target):
    prefix = str(pid) + ' (im.elf) '
    if not stat.strip().startswith(prefix):
        raise probe.ProbeError('Unexpected process stat identity')
    fields = stat.strip()[len(prefix):].split()
    if len(fields) < 25 or fields[0] not in ('R', 'S', 'D'):
        raise probe.ProbeError('im.elf is stopped, dead or has an unknown stat layout')
    if not all(re.fullmatch(r'-?[0-9]+', field) for field in fields[1:]):
        raise probe.ProbeError('Invalid numeric process stat fields')
    starttime = int(fields[19])
    if starttime <= 0:
        raise probe.ProbeError('Invalid process starttime')
    names = {}
    for line in status.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            if key in names:
                raise probe.ProbeError('Duplicate process status field')
            names[key] = value.strip()
    if (names.get('Name') != 'im.elf' or names.get('Pid') != str(pid)
            or names.get('Tgid') != str(pid) or names.get('TracerPid') != '0'
            or names.get('Uid', '').split() != ['0'] * 4):
        raise probe.ProbeError('Unexpected im.elf credentials, PID or tracer')
    if executable.strip() != '/usr/bin/im.elf':
        raise probe.ProbeError('Unexpected /proc/PID/exe target')
    rows = []
    for line in maps.splitlines():
        match = re.fullmatch(r'([0-9a-f]+)-([0-9a-f]+) ([rwxps-]{4}) ([0-9a-f]+) '
                             r'([0-9a-f]+:[0-9a-f]+) ([0-9]+)\s*(.*)', line.strip())
        if not match:
            raise probe.ProbeError('Unrecognized process maps line')
        start, end, flags, offset, device, inode, path = match.groups()
        rows.append({'start': int(start, 16), 'end': int(end, 16), 'flags': flags,
                     'offset': int(offset, 16), 'device': device, 'inode': int(inode), 'path': path})
    executable_rows = [r for r in rows if r['path'] == '/usr/bin/im.elf' and r['flags'] == 'r-xp']
    if len(executable_rows) != 1 or executable_rows[0]['inode'] <= 0:
        raise probe.ProbeError('No unique file-backed im.elf RX map')
    offset = target['file_offset']
    candidates = [r for r in rows if r['path'] == CAMERA_LIBRARY
                  and r['offset'] <= offset and offset + READ_BYTES <= r['offset'] + r['end'] - r['start']]
    if len(candidates) != 1:
        raise probe.ProbeError('No unique libmpr mapping covering the exact file bytes')
    row = candidates[0]
    if row['flags'] != 'r-xp' or row['inode'] <= 0 or row['device'] == '00:00':
        raise probe.ProbeError('Target is not private RX file-backed memory')
    address = row['start'] + offset - row['offset']
    if not 0x10000 <= address <= 0xc0000000 - READ_BYTES or address & 1:
        raise probe.ProbeError('Unexpected user-space instruction address')
    bias = row['start'] - (target['segment_va'] + row['offset'] - target['segment_offset'])
    if bias + ELF_VA != address:
        raise probe.ProbeError('ELF/maps address calculation disagrees')
    return {'pid': pid, 'starttime': starttime, 'state': fields[0], 'utime': int(fields[11]),
            'stime': int(fields[12]), 'threads': int(fields[17]), 'tracer_pid': 0,
            'mapping': row, 'executable_mapping': executable_rows[0], 'load_bias': bias,
            'address': address}


def same_identity(before, after):
    keys = ('pid', 'starttime', 'tracer_pid', 'mapping', 'executable_mapping', 'address')
    if any(before[key] != after[key] for key in keys):
        raise probe.ProbeError('Process identity or target mapping changed; no positive read conclusion')


def preflight_commands():
    return ['HISTFILE=/dev/null; export HISTFILE; ulimit -c 0 && umask 077',
            'cat /version.txt', 'cat /proc/mounts', 'ls -ld /tmp_network', '/bin/busybox',
            "/bin/busybox echo -e '" + ram.ECHO_ESCAPES + "'", '/bin/busybox pidof im.elf']


def identity_commands(pid):
    if parse_pid(str(pid)) != pid:
        raise probe.ProbeError('Invalid PID type')
    base = '/proc/' + str(pid)
    return ['cat ' + base + '/stat', 'cat ' + base + '/status',
            '/bin/busybox readlink ' + base + '/exe', 'cat ' + base + '/maps']


def payload_commands(image, nonce):
    if not re.fullmatch('[0-9a-f]{12}', nonce):
        raise ValueError('Invalid nonce')
    directory = '/tmp_network/.m7-imread-' + nonce
    path = directory + '/probe.elf'
    commands = ['/bin/busybox mkdir ' + directory]
    for offset in range(0, len(image), 48):
        chunk = image[offset:offset+48]
        commands.append("/bin/busybox echo -ne '" + ''.join('\\0%03o' % b for b in chunk) +
                        "' " + ('>' if offset == 0 else '>>') + ' ' + path)
    commands += ['/bin/busybox md5sum ' + path, '/bin/busybox chmod 500 ' + path]
    cleanup = '/bin/busybox rm -f ' + path + ' && /bin/busybox rmdir ' + directory
    return commands, directory, path, cleanup


class StagedGate(StepGate):
    def __init__(self, device, frames):
        super().__init__(device, frames, 0)
        self.exec_allowed = True
        self.reader_registered = False

    def register(self, specs, execution=None):
        if any(item[0] in self.frames for item in specs):
            raise probe.ProbeError('Duplicate terminal frame registration')
        self.frames.extend(item[0] for item in specs)
        if execution is not None:
            if self.reader_registered or execution[0] not in self.frames:
                raise probe.ProbeError('Invalid reader registration')
            self.reader_registered = True
            self.execute_index = self.frames.index(execution[0])
            self.exec_allowed = False


def checked_preflight(bodies):
    inventory = ('__BUILD__\n'+bodies[1].strip()+'\n__MOUNTS__\n'+bodies[2]+'\n__DIRECTORY__\n'+bodies[3]+
                 '\n__APPLETS__\n'+bodies[4]+'\n__ECHO_CHECK__\n'+bodies[5]+'\n')
    result = ram.validate_preflight(inventory)
    applets = set(re.findall(r'[A-Za-z0-9_.\[\]-]+', bodies[4].split('Currently defined functions:', 1)[1]))
    if not {'pidof', 'readlink'} <= applets:
        raise probe.ProbeError('BusyBox pidof/readlink unavailable')
    rows = [line.split() for line in bodies[2].splitlines() if line.strip()]
    proc = [r for r in rows if len(r) == 6 and r[1] == '/proc']
    if len(proc) != 1 or proc[0][2] != 'proc' or any(len(r) > 1 and r[1].startswith('/proc/') for r in rows):
        raise probe.ProbeError('/proc is not the expected procfs without nested mounts')
    usr = [r for r in rows if len(r) == 6 and r[1] == '/usr']
    if len(usr) != 1 or usr[0][2] != 'ext2' or 'ro' not in usr[0][3].split(','):
        raise probe.ProbeError('/usr is not the expected read-only filesystem')
    if any(len(r) > 1 and r[1].startswith('/usr/') for r in rows):
        raise probe.ProbeError('Unexpected nested /usr mount')
    return {**result, 'usr_mount': usr[0], 'proc_mount': proc[0], 'extra_applets': ['pidof', 'readlink']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--self-test', action='store_true')
    mode.add_argument('--connect', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    target = local_target()
    nonce = secrets.token_hex(6)
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    result = {'version': 1, 'utc': stamp, 'nonce': nonce,
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'target': target, 'file_control_allowed': False, 'steps': [], 'commands': []}
    initial = preflight_commands()
    initial_specs = [frame(cmd, i, nonce) for i, cmd in enumerate(initial)]

    def run(camera, output):
        specs = list(initial_specs)
        output['commands'] = list(initial)
        created = cleaned = False
        cleanup_index = None

        def add(commands, execution_offset=None):
            first = len(specs)
            added = [frame(cmd, first+i, nonce) for i, cmd in enumerate(commands)]
            execution = None if execution_offset is None else added[execution_offset]
            camera.dev.register(added, execution)
            specs.extend(added)
            output['commands'].extend(commands)
            return first

        def step(index, **kwargs):
            return run_step(camera, specs[index], index, output['steps'], **kwargs)

        def identify(pid, first):
            texts = [step(first+i).decode() for i in range(4)]
            return parse_identity(pid, *texts, target)

        try:
            with probe.deadline(8):
                camera.setTerminalEnable(False)
                camera.setTerminalEnable(True)
            with probe.deadline(10):
                output['shell_banner'] = read_ready(camera).decode('utf-8', 'replace')
            bodies = [step(i, allowed_status=(0, 1) if i == 4 else (0,)).decode() for i in range(6)]
            output['preflight_checks'] = checked_preflight(bodies)
            pid = parse_pid(step(6).decode())
            identity_first = add(identity_commands(pid) + ['/bin/busybox md5sum ' + CAMERA_LIBRARY])
            identity = identify(pid, identity_first)
            camera_checksum = step(identity_first+4).decode().strip()
            if camera_checksum != target['library_md5'] + '  ' + CAMERA_LIBRARY:
                raise probe.ProbeError('Camera libmpr MD5 differs from the pinned original M7 binary')
            output['library_md5_verified_on_host'] = True
            output['identity_before'] = identity
            print('PREFLIGHT_OK: свежий PID/maps и checksum оригинальной M7 libmpr подтверждены.', flush=True)
            image = patch_template(pid, identity['address'])
            output['helper_patch'] = validate_patched(image, pid, identity['address'])
            output['helper_sha256'] = hashlib.sha256(image).hexdigest()
            artifact = probe.ROOT / 'artifacts/m7-im-code-read' / stamp
            artifact.mkdir(parents=True, exist_ok=False)
            (artifact / 'reader.elf').write_bytes(image)
            (artifact / 'target.json').write_text(json.dumps({'identity': identity, 'target': target,
                                                             'helper_patch': output['helper_patch']}, indent=2)+'\n')
            output['host_helper'] = str((artifact / 'reader.elf').relative_to(probe.ROOT))
            upload, directory, executable, cleanup_command = payload_commands(image, nonce)
            output['ram_directory'] = directory
            first = add(upload + identity_commands(pid) + [executable] + identity_commands(pid)
                        + [cleanup_command, 'ls -ld ' + directory], execution_offset=len(upload)+4)
            checksum_index, chmod_index = first+len(upload)-2, first+len(upload)-1
            before_index, execute_index = first+len(upload), first+len(upload)+4
            after_index, cleanup_index = execute_index+1, execute_index+5
            step(first)
            created = True
            for i in range(first+1, checksum_index):
                step(i)
            checksum = step(checksum_index).decode().strip()
            if checksum != hashlib.md5(image).hexdigest() + '  ' + executable:
                raise probe.ProbeError('Mac rejected uploaded helper checksum; no execution')
            output['helper_md5_verified_on_host'] = True
            step(chmod_index)
            before_exec = identify(pid, before_index)
            same_identity(identity, before_exec)
            output['identity_before_exec'] = before_exec
            camera.dev.exec_allowed = True
            print('HELPER_VERIFIED_ON_MAC: одно O_RDONLY чтение 32 bytes из file-backed RX mapping.', flush=True)
            native = parse_record(step(execute_index, timeout=12))
            output['native'] = native
            if native['address'] != identity['address']:
                raise probe.ProbeError('Native result reports an unexpected address')
            after = identify(pid, after_index)
            output['identity_after'] = after
            same_identity(identity, after)
            output['process_identity_unchanged'] = True
            output['bytes_match_local_elf'] = native['read_complete'] and native['data_hex'] == target['expected_hex']
            step(cleanup_index)
            absent = step(cleanup_index+1, allowed_status=(1,)).decode()
            if 'No such file or directory' not in absent or directory not in absent:
                raise probe.ProbeError('RAM cleanup not confirmed')
            cleaned = True
            output['ram_cleanup_verified'] = True
            print('IM_CODE_READ_DONE: bytes_match=' + str(output['bytes_match_local_elf']) +
                  '; native_complete=' + str(native['complete']) + '; RAM helper удалён.', flush=True)
        finally:
            if created and not cleaned and cleanup_index is not None:
                try:
                    step(cleanup_index)
                    output['cleanup_command_completed'] = True
                except Exception as error:
                    output['cleanup_error'] = str(error)
            try:
                with probe.deadline(8):
                    camera.setTerminalEnable(False)
                output['terminal_disable_sent'] = True
            except Exception as error:
                output['terminal_disable_error'] = str(error)
            output['terminal_packets'] = camera.dev.packet_log
    try:
        probe.connect(result, diagnostic=run, gate_factory=lambda dev: StagedGate(dev, initial_specs))
    except (Exception, KeyboardInterrupt) as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        print(result['error'], flush=True)
    destination = probe.ROOT / 'evidence' / ('m7-im-code-read-' + stamp + '.json')
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print('RESULT=' + str(destination), flush=True)
    return 1 if 'error' in result else 0


def self_test():
    target = local_target()
    runtime = (LIBRARY.parents[2] / 'runtime.txt').read_text()
    maps = runtime.split('__M7_MAPS_PID_161__\n', 1)[1].split('__M7_STATUS_PID_161__', 1)[0]
    status = runtime.split('__M7_STATUS_PID_161__\n', 1)[1].split('__M7_FILE_CHECKSUMS__', 1)[0]
    stat_fields = ['S'] + ['0'] * 42
    stat_fields[17], stat_fields[19] = '186', '123456'
    stat = '161 (im.elf) ' + ' '.join(stat_fields)
    identity = parse_identity(161, stat, status, '/usr/bin/im.elf\n', maps, target)
    assert identity['starttime'] == 123456 and identity['threads'] == 186
    assert identity['address'] == 0x07400000 + ELF_VA
    assert identity['mapping']['offset'] == 0 and identity['tracer_pid'] == 0
    rejected = 0

    def reject(operation):
        nonlocal rejected
        try:
            operation()
        except (probe.ProbeError, ValueError):
            rejected += 1
        else:
            raise AssertionError('Invalid identity, mapping or terminal operation accepted')

    for bad in ('', '0', '1', '161 162', '161;cat', '161\n162', '2147483648'):
        reject(lambda value=bad: parse_pid(value))
    for key, replacement in (
        ('stat', stat.replace('(im.elf)', '(other)')),
        ('stat', stat.replace(' S ', ' T ')),
        ('status', status.replace('TracerPid:      0', 'TracerPid:      999')),
        ('status', status + '\nPid: 161\n'),
        ('executable', '/usr/bin/other'),
        ('maps', maps.replace('/usr/lib/libmpr.so', '/dev/mem')),
        ('maps', maps.replace('07400000-0804c000 r-xp', '07400000-0804c000 rwxp')),
        ('maps', maps.replace('07400000-0804c000 r-xp 00000000', '07400000-0804c000 r-xp 00c00000')),
    ):
        values = dict(stat=stat, status=status, executable='/usr/bin/im.elf', maps=maps)
        values[key] = replacement
        reject(lambda values=values: parse_identity(161, target=target, **values))
    reject(lambda: same_identity(identity, {**identity, 'starttime': identity['starttime'] + 1}))
    reject(lambda: same_identity(identity, {**identity, 'pid': 162}))
    changed_mapping = {**identity['mapping'], 'inode': identity['mapping']['inode'] + 1}
    reject(lambda: same_identity(identity, {**identity, 'mapping': changed_mapping}))

    prior = json.loads((probe.ROOT / 'evidence/m7-proc-mem-selftest-20261104T235025Z.json').read_text())
    prior_nonce = prior['ram_directory'].rsplit('-', 1)[1]
    bodies = []
    for i in range(6):
        lines = prior['steps'][i]['response'].replace('\r', '').splitlines()
        _, begin, end = frame('', i, prior_nonce)
        first = lines.index(begin.decode())
        last = next(j for j, line in enumerate(lines) if re.fullmatch(re.escape(end.decode()) + r'[01]__', line))
        bodies.append('\n'.join(lines[first+1:last]))
    checked_preflight(bodies)
    writable_usr = list(bodies)
    writable_usr[2] = writable_usr[2].replace('/usr ext2 ro,', '/usr ext2 rw,')
    reject(lambda: checked_preflight(writable_usr))
    wrong_proc = list(bodies)
    wrong_proc[2] = wrong_proc[2].replace('/proc proc ', '/proc ext2 ')
    reject(lambda: checked_preflight(wrong_proc))

    image = patch_template(161, identity['address'])
    patch = validate_patched(image, 161, identity['address'])
    assert patch['instructions_unchanged'] and patch['read_bytes'] == READ_BYTES
    upload, directory, executable, cleanup = payload_commands(image, '0123456789ab')
    commands = (preflight_commands() + identity_commands(161) + ['/bin/busybox md5sum ' + CAMERA_LIBRARY]
                + upload + identity_commands(161) + [executable] + identity_commands(161)
                + [cleanup, 'ls -ld ' + directory])
    specs = [frame(cmd, i, '0123456789ab') for i, cmd in enumerate(commands)]
    for spec in specs:
        subprocess.run(['/bin/sh', '-n'], input=spec[0], check=True)
    decoded = bytearray()
    for command in upload[1:-2]:
        encoded = command.split("'", 2)[1]
        assert re.fullmatch(r'(?:\\0[0-7]{3})+', encoded)
        decoded.extend(int(encoded[i+2:i+5], 8) for i in range(0, len(encoded), 5))
    assert bytes(decoded) == image
    class NoCamera:
        def writeTerminal(self, data):
            raise AssertionError('No USB in self-test')
        def sendSenserPacket(self, *args):
            raise AssertionError('No USB in self-test')
    gate = StagedGate(NoCamera(), specs[:7])
    execute_index = commands.index(executable)
    reject(lambda: gate.writeTerminal(specs[execute_index][0]))
    gate.register(specs[7:], specs[execute_index])
    reject(lambda: gate.writeTerminal(specs[execute_index][0]))
    reject(lambda: gate.sendSenserPacket(0xff01, b'\x02\x00'))
    reject(lambda: gate.writeTerminal(b'ptrace\n'))
    tests = json.loads((probe.ROOT / 'artifacts/m7-proc-mem-reader/manifest.json').read_text())['tests']
    for test in tests:
        if test['decoded'] is None:
            reject(lambda test=test: parse_record(test['output'].encode()))
        else:
            assert parse_record(test['output'].encode()) == test['decoded']
    evidence = {'camera_access': False, 'target': target, 'historic_maps_used_only_as_fixture': True,
                'synthetic_stat_starttime': 123456, 'fixture_identity': identity,
                'fixed_steps_for_616_byte_helper': len(commands),
                'maximum_frame_line_bytes': max(len(s[0].splitlines()[0]) for s in specs),
                'negative_identity_transport_parser_cases': rejected, 'native_fixtures_reparsed': len(tests),
                'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    folder = probe.ROOT / 'evidence/m7-im-code-read'
    folder.mkdir(exist_ok=True)
    (folder / 'runner-validation.json').write_text(json.dumps(evidence, indent=2)+'\n')
    print(f'SELF_TEST_OK: {len(commands)} steps, {rejected} rejected identity/transport/output cases, '
          f'{len(tests)} native fixtures; exact ELF/RX translation and data-only patch verified; no USB')


if __name__ == '__main__':
    raise SystemExit(main())
