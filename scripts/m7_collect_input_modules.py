#!/usr/bin/env python3
"""Read only original-M7 osal_uipc.ko and upm.ko in one bounded service session."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import struct
import time

import build_m7_input_module_readers as reader
import m7_probe as probe
import m7_ram_liveness as ram
from m7_terminal_io import TracedGate
from m7_terminal_steps import frame, read_ready

SOURCES = reader.SOURCES
TRANSFER_SECONDS = 240
OUTPUT_LIMIT = 2 * 1024 * 1024
EVENT_LIMIT = 200000
SHELL_PROMPT = b'/usr/share/app # '
PROMPT_SUFFIXES = frozenset(SHELL_PROMPT[i:] for i in range(len(SHELL_PROMPT) + 1))
BANNER_LIMIT = 32768


def profile_sources(profile):
    if profile == 'input-modules':
        return SOURCES
    if profile == 'upm':
        return ('/usr/kmod/upm.ko',)
    raise ValueError('Unknown fixed collector profile')


class InputModuleGate(TracedGate):
    def __init__(self, device, specs, output, profile='input-modules'):
        super().__init__(device, specs, output)
        self.terminal.trace['event_limit'] = EVENT_LIMIT
        output['transport_policy'] = {'event_limit': EVENT_LIMIT, 'max_file_bytes': reader.MAX_BYTES,
                                      'file_count': len(profile_sources(profile)), 'output_limit_per_step': OUTPUT_LIMIT,
                                      'automatic_retries': False}


def make_commands(images, nonce, profile='input-modules'):
    sources = profile_sources(profile)
    if set(images) != set(sources) or not re.fullmatch('[0-9a-f]{12}', nonce):
        raise ValueError('Expected exactly the fixed profile readers and a valid nonce')
    for source in sources:
        reader.validate_reader(images[source], source)
    directory = '/tmp_network/.m7-' + profile + '-' + nonce
    listing = 'ls -ld /tmp_network /usr /usr/kmod ' + ' '.join(sources)
    commands = ['HISTFILE=/dev/null; export HISTFILE; ulimit -c 0 && umask 077',
                'cat /version.txt', 'cat /proc/mounts', listing, '/bin/busybox',
                "/bin/busybox echo -e '" + ram.ECHO_ESCAPES + "'"]
    for source in sources:
        commands.extend(['/bin/busybox wc -c ' + source, '/bin/busybox md5sum ' + source])
    preflight_count = len(commands)
    commands.append('/bin/busybox mkdir ' + directory)
    stages = []
    for source in sources:
        image = images[source]
        executable = directory + '/' + Path(source).stem + '-reader.elf'
        stage = {'source': source, 'executable': executable, 'upload': len(commands)}
        for offset in range(0, len(image), 48):
            commands.append("/bin/busybox echo -ne '" + ''.join('\\0%03o' % v for v in image[offset:offset + 48]) +
                            "' " + ('>' if offset == 0 else '>>') + ' ' + executable)
        stage['checksum'] = len(commands)
        commands.extend(['/bin/busybox md5sum ' + executable, '/bin/busybox chmod 500 ' + executable])
        stage['refresh'] = len(commands)
        refresh = ['cat /proc/mounts', listing, '/bin/busybox wc -c ' + source, '/bin/busybox md5sum ' + source]
        commands.extend(refresh)
        stage['execution'] = len(commands)
        commands.append(executable)
        stage['postcheck'] = len(commands)
        commands.extend(['/bin/busybox md5sum ' + executable] + refresh)
        stage['end'] = len(commands)
        stages.append(stage)
    cleanup = len(commands)
    commands.extend(['/bin/busybox rm -f ' + ' '.join(s['executable'] for s in stages) +
                     ' && /bin/busybox rmdir ' + directory, 'ls -ld ' + directory])
    return commands, {'directory': directory, 'stages': stages, 'cleanup': cleanup,
                      'profile': profile, 'preflight_count': preflight_count}


def checked_preflight(bodies, source, profile='input-modules'):
    sources = profile_sources(profile)
    if source not in sources or len(bodies) != 8:
        raise probe.ProbeError('Incomplete fixed-module preflight')
    by_path = {}
    for line in bodies[3].strip().splitlines():
        path = line.split()[-1] if line.split() else ''
        if path in by_path:
            raise probe.ProbeError('Duplicate source listing entry')
        by_path[path] = line
    expected_paths = {'/tmp_network': 'd', '/usr': 'd', '/usr/kmod': 'd', **{s: '-' for s in sources}}
    if set(by_path) != set(expected_paths) or any(not by_path[p].startswith(k) for p, k in expected_paths.items()):
        raise probe.ProbeError('Expected nonsymlink directories and exactly the fixed regular source files')
    inventory = ('__BUILD__\n' + bodies[1].strip() + '\n__MOUNTS__\n' + bodies[2] +
                 '\n__DIRECTORY__\n' + by_path['/tmp_network'] + '\n__APPLETS__\n' + bodies[4] +
                 '\n__ECHO_CHECK__\n' + bodies[5] + '\n')
    checked = ram.validate_preflight(inventory)
    mounts = [line.split() for line in bodies[2].splitlines() if line.strip()]
    if any(len(row) != 6 for row in mounts):
        raise probe.ProbeError('Malformed mount table')
    usr = [row for row in mounts if row[1] == '/usr']
    if len(usr) != 1 or usr[0][2] != 'ext2' or 'ro' not in usr[0][3].split(',') or 'rw' in usr[0][3].split(','):
        raise probe.ProbeError('/usr must be read-only ext2')
    if any(row[1].startswith('/usr/') for row in mounts):
        raise probe.ProbeError('Nested mount under /usr is forbidden')
    sizes = [option[5:] for option in checked['mount'][3].split(',') if option.startswith('size=')]
    if len(sizes) != 1 or not re.fullmatch(r'[1-9][0-9]*[kKmM]?', sizes[0]):
        raise probe.ProbeError('Explicit bounded tmpfs size missing')
    suffix = sizes[0][-1].lower()
    capacity = int(sizes[0][:-1]) * {'k': 1024, 'm': 1024 * 1024}[suffix] if suffix in ('k', 'm') else int(sizes[0])
    if not len(sources) * reader.IMAGE_BYTES < capacity <= 1024 * 1024:
        raise probe.ProbeError('tmpfs capacity outside the permitted limit')
    applets = set(re.findall(r'[A-Za-z0-9_.\[\]-]+', bodies[4].split('Currently defined functions:', 1)[1]))
    if 'wc' not in applets:
        raise probe.ProbeError('BusyBox wc is unavailable')
    size = re.fullmatch(r'\s*([1-9][0-9]*)\s+' + re.escape(source) + r'\s*', bodies[6])
    digest = re.fullmatch(r'([0-9a-f]{32})\s+\*?' + re.escape(source) + r'\s*', bodies[7].strip())
    if not size or not digest or int(size[1]) > reader.MAX_BYTES:
        raise probe.ProbeError('Source size/MD5 missing or source exceeds 512 KiB')
    return {**checked, 'usr_mount': usr[0], 'tmpfs_capacity': capacity, 'source': source,
            'source_bytes': int(size[1]), 'source_md5': digest[1], 'no_source_symlinks': True}


def validate_module(data):
    def require(condition, message):
        if not condition:
            raise probe.ProbeError('Invalid bounded ARM ET_REL: ' + message)
    require(type(data) is bytes and 52 <= len(data) <= reader.MAX_BYTES, 'file size')
    h = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
    ident, typ, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = h
    require(ident[:7] == b'\x7fELF\x01\x01\x01', 'ELF32 little-endian version 1 required')
    require((typ, machine, version, entry, phoff, ehsize, phentsize, phnum, shentsize) ==
            (1, 40, 1, 0, 0, 52, 0, 0, 40), 'relocatable ARM header required; no loadable program headers')
    require(flags & 0xff000000 == 0x05000000, 'ARM EABI5 required')
    require(2 <= shnum <= 4096 and 0 < shstrndx < shnum and shoff >= 52 and shoff % 4 == 0
            and shoff + 40 * shnum <= len(data), 'section table bounds')
    sections = [struct.unpack_from('<10I', data, shoff + 40 * i) for i in range(shnum)]
    require(sections[0] == (0,) * 10, 'null section')
    for s in sections[1:]:
        name, stype, sflags, address, offset, size, link, info, alignment, entsize = s
        require(stype != 6, 'dynamic section in relocatable module')
        require(alignment == 0 or alignment & (alignment - 1) == 0, 'section alignment')
        require(stype == 8 or 52 <= offset <= len(data) and size <= len(data) - offset, 'section data bounds')
        if stype in (2, 4, 9):
            require(0 < link < shnum and entsize == {2: 16, 4: 12, 9: 8}[stype] and size % entsize == 0,
                    'symbol/relocation entry or link')
            require(sections[link][1] == (3 if stype == 2 else 2), 'symbol/relocation link type')
            require((info <= size // entsize) if stype == 2 else (0 < info < shnum), 'symbol/relocation info')
    strings = sections[shstrndx]
    require(strings[1] == 3 and strings[5] > 0, 'section-name string table')
    names_data = data[strings[4]:strings[4] + strings[5]]
    names = []
    for s in sections:
        require(s[0] < len(names_data) and b'\0' in names_data[s[0]:], 'terminated section name')
        names.append(names_data[s[0]:].split(b'\0', 1)[0])
    for name in (b'.text', b'.symtab', b'.modinfo'):
        require(names.count(name) == 1, 'missing/duplicate ' + name.decode())
    text = sections[names.index(b'.text')]
    require(text[1] == 1 and text[2] & 4 and text[5] > 0, 'code section layout')
    require(sections[names.index(b'.symtab')][1] == 2, 'symbol table layout')
    modinfo = sections[names.index(b'.modinfo')]
    require(modinfo[1] == 1 and modinfo[5] > 0, 'module metadata layout')
    return {'elf_type': 'ARM ELF32LE ET_REL', 'sections': shnum, 'loadable_program_headers': False}


def verify_transfer(body, expected):
    data = reader.decode_transfer(body, expected['source_bytes'], expected['source_md5'])
    validate_module(data)
    return data


def marker_like(line):
    return bool(line) and (b'__M7_'.startswith(line) or line.startswith(b'__M7_'))


class ResponseLines:
    def __init__(self, spec):
        self.command = spec[0].rstrip(b'\n')
        self.pending = bytearray()
        self.soft_parts = []
        self.echo_soft_wraps_removed = 0

    def feed(self, chunk):
        parts = chunk.split(b'\n')
        if len(parts) == 1:
            self.pending.extend(chunk)
            return []
        physical_lines = [bytes(self.pending) + parts[0]] + parts[1:-1]
        self.pending = bytearray(parts[-1])
        lines = []
        for physical in physical_lines:
            if physical.endswith(b'\r\r'):
                self.soft_parts.append(bytes(physical))
                continue
            line = bytes(physical).removesuffix(b'\r')
            if self.soft_parts:
                candidate = b''.join(p[:-2] for p in self.soft_parts) + line
                prefix = candidate[:-len(self.command)] if candidate.endswith(self.command) else None
                if prefix in PROMPT_SUFFIXES:
                    lines.append(candidate)
                    self.echo_soft_wraps_removed += len(self.soft_parts)
                else:
                    if any(marker_like(p.rstrip(b'\r')) for p in self.soft_parts):
                        raise probe.ProbeError('Soft-wrapped ACK is not an exact command echo')
                    lines.extend(p.rstrip(b'\r') for p in self.soft_parts)
                    lines.append(line)
                self.soft_parts.clear()
            else:
                lines.append(line)
        return lines

    def partial_marker(self):
        return any(marker_like(p.rstrip(b'\r')) for p in (*self.soft_parts, bytes(self.pending)))


def ack_status(record, spec, index):
    if record.get('step') != index:
        return None
    normalizer = ResponseLines(spec)
    try:
        lines = normalizer.feed(record.get('response', '').encode())
    except probe.ProbeError:
        return None
    begin, end = spec[1:]
    ends = [(i, re.fullmatch(re.escape(end) + rb'([0-9]+)__', line)) for i, line in enumerate(lines)]
    ends = [(i, m) for i, m in ends if m]
    markers = [line for line in lines if marker_like(line)]
    if (lines.count(begin) != 1 or len(ends) != 1 or lines.index(begin) >= ends[0][0]
            or len(markers) != 2 or normalizer.partial_marker()):
        return None
    return int(ends[0][1][1])


def command_step(camera, spec, index, transcript, allowed_status=(0,), timeout=12):
    if timeout not in (12, TRANSFER_SECONDS):
        raise ValueError('Unexpected terminal deadline')
    received, lines = bytearray(), []
    normalizer = ResponseLines(spec)
    started = time.monotonic()
    next_progress = started + 30
    deadline_exceeded, ack_committed_at = False, None

    def check_deadline():
        nonlocal deadline_exceeded
        elapsed = time.monotonic() - started
        if elapsed >= timeout:
            deadline_exceeded = True
            raise probe.ProbeError('Host terminal deadline exceeded; ACK not committed')
        return elapsed

    try:
        with probe.deadline(timeout + 10):
            camera.dev.writeTerminal(spec[0])
            while time.monotonic() - started < timeout:
                chunk = camera.dev.readTerminal()
                received.extend(chunk)
                check_deadline()
                if len(received) > OUTPUT_LIMIT:
                    raise probe.ProbeError('Terminal output limit exceeded')
                first_new = len(lines)
                lines.extend(normalizer.feed(chunk))
                markers = [line for line in lines[first_new:] if marker_like(line)]
                if any(line != spec[1] and not re.fullmatch(re.escape(spec[2]) + rb'[0-9]+__', line) for line in markers):
                    raise probe.ProbeError('Foreign or malformed terminal ACK')
                if any(line.startswith(spec[2]) for line in markers):
                    status = ack_status({'step': index, 'response': received.decode('utf-8', 'replace')}, spec, index)
                    if status is None:
                        raise probe.ProbeError('Missing, duplicate or unordered ACK')
                    pos = next(i for i, line in enumerate(lines) if line.startswith(spec[2]))
                    body = b'\n'.join(lines[lines.index(spec[1]) + 1:pos])
                    ack_committed_at = check_deadline()
                    if status not in allowed_status:
                        raise probe.ProbeError('Camera shell exit ' + str(status))
                    return body
                current = time.monotonic()
                if current >= next_progress:
                    print('TRANSFER_PROGRESS: %.0fs; %d console bytes.' % (current - started, len(received)), flush=True)
                    next_progress = current + 30
            deadline_exceeded = True
            raise probe.ProbeError('No complete ACK before host deadline; no automatic retry')
    finally:
        elapsed = time.monotonic() - started
        deadline_exceeded = deadline_exceeded or (ack_committed_at is None and elapsed >= timeout)
        transcript.append({'step': index, 'command_bytes': len(spec[0]), 'elapsed_seconds': elapsed,
                           'response': received.decode('utf-8', 'replace'),
                           'echo_soft_wraps_removed': normalizer.echo_soft_wraps_removed,
                           'deadline_seconds': timeout, 'deadline_exceeded': deadline_exceeded,
                           'ack_committed_at_seconds': ack_committed_at})


def execute(camera, output, images, commands, plan, specs, destination=None, stepper=command_step, ready=read_ready,
            profile='input-modules'):
    if output.get('model') != probe.MODEL:
        raise probe.ProbeError('Only exact original DSC-RX100M7 may use this collector')
    sources = profile_sources(profile)
    expected_commands, expected_plan = make_commands(images, output['nonce'], profile)
    if (commands != expected_commands or plan != expected_plan
            or specs != [frame(c, i, output['nonce']) for i, c in enumerate(commands)]):
        raise probe.ProbeError('Fixed module command plan changed')
    output.update(commands=commands, modules=[], collection_complete=False)
    created = cleaned = cleanup_attempted = False
    verified_data = {}

    def step(index, **kwargs):
        try:
            body = stepper(camera, specs[index], index, output['steps'], **kwargs)
            if output['steps'][-1].get('deadline_exceeded'):
                raise probe.ProbeError('Host terminal deadline exceeded; no later shell command')
            if ack_status(output['steps'][-1], specs[index], index) is None:
                raise probe.ProbeError('No unique complete ACK for step ' + str(index))
            return body
        except BaseException:
            if output['steps'] and output['steps'][-1].get('step') == index and output['steps'][-1].get('deadline_exceeded'):
                camera.dev.quarantine_terminal('Host terminal deadline exceeded; no later shell command')
            elif not output['steps'] or ack_status(output['steps'][-1], specs[index], index) is None:
                camera.dev.quarantine_terminal('No unique complete ACK for step ' + str(index))
            raise

    def cleanup():
        nonlocal cleaned, cleanup_attempted
        cleanup_attempted = True
        step(plan['cleanup'])
        if step(plan['cleanup'] + 1, allowed_status=(1,)).decode().strip() != 'ls: ' + plan['directory'] + ': No such file or directory':
            raise probe.ProbeError('Exact own RAM directory absence not confirmed')
        cleaned = True

    try:
        with probe.deadline(8):
            camera.setTerminalEnable(False)
            camera.setTerminalEnable(True)
        try:
            with probe.deadline(10):
                banner = ready(camera)
        except BaseException:
            camera.dev.quarantine_terminal('Fresh bounded shell banner unavailable; no shell frames allowed')
            raise
        if type(banner) is not bytes or not 0 < len(banner) <= BANNER_LIMIT:
            camera.dev.quarantine_terminal('Missing or oversized shell banner; no shell frames allowed')
            raise probe.ProbeError('Missing or oversized bounded shell banner')
        output['shell_banner'] = banner.decode('utf-8', 'replace')
        if banner.rsplit(b'\n', 1)[-1] != SHELL_PROMPT:
            camera.dev.quarantine_terminal('Unexpected fresh shell prompt; no shell frames allowed')
            raise probe.ProbeError('Fresh shell prompt differs from the fixed observed M7 prompt')
        output['shell_prompt_verified'] = True
        output['shell_prompt'] = SHELL_PROMPT.decode('ascii')
        initial = [step(i, allowed_status=(0, 1) if i == 4 else (0,)).decode() for i in range(plan['preflight_count'])]
        bases = {s: initial[:6] + initial[6 + 2 * i:8 + 2 * i] for i, s in enumerate(sources)}
        expected = {s: checked_preflight(bases[s], s, profile) for s in sources}
        output['preflight_checks'] = expected
        source_label = 'one regular module file' if profile == 'upm' else 'two regular module files'
        print('PREFLIGHT_OK: exact M7/build, ' + source_label + ', /usr ro, bounded tmpfs.', flush=True)
        step(plan['preflight_count'])
        created = True
        output['ram_directory'] = plan['directory']
        for stage in plan['stages']:
            source = stage['source']
            item = {'source': source}
            output['modules'].append(item)
            for i in range(stage['upload'], stage['checksum']):
                step(i)
            checksum = hashlib.md5(images[source]).hexdigest() + '  ' + stage['executable']
            if step(stage['checksum']).decode().strip() != checksum:
                raise probe.ProbeError('RAM helper MD5 mismatch; execution forbidden')
            item['reader_md5_before_verified'] = True
            step(stage['checksum'] + 1)
            fresh = list(bases[source])
            for offset, slot in enumerate((2, 3, 6, 7)):
                fresh[slot] = step(stage['refresh'] + offset).decode()
            if checked_preflight(fresh, source, profile) != expected[source]:
                raise probe.ProbeError('Source identity/storage changed before execution')
            item['source_rechecked_before_exec'] = True
            camera.dev.arm(specs[stage['execution']])
            print('READER_VERIFIED_ON_MAC: ' + source + '; read-only, 512 KiB maximum.', flush=True)
            body = step(stage['execution'], timeout=TRANSFER_SECONDS)
            data = verify_transfer(body, expected[source])
            if step(stage['postcheck']).decode().strip() != checksum:
                raise probe.ProbeError('RAM helper MD5 changed after execution')
            item['reader_md5_after_verified'] = True
            after = list(bases[source])
            for offset, slot in enumerate((2, 3, 6, 7)):
                after[slot] = step(stage['postcheck'] + 1 + offset).decode()
            if checked_preflight(after, source, profile) != expected[source]:
                raise probe.ProbeError('Source identity/storage changed after execution')
            item.update(source_rechecked_after_exec=True, transfer_verified=True, bytes=len(data),
                        sha256=hashlib.sha256(data).hexdigest(), source_md5=expected[source]['source_md5'],
                        **validate_module(data))
            verified_data[source] = data
            print('MODULE_TRANSFER_OK: ' + source + '; source MD5/size and ARM ET_REL verified.', flush=True)
        cleanup()
        if destination is not None:
            for item in output['modules']:
                path = destination / item['source'].lstrip('/')
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as handle:
                    handle.write(verified_data[item['source']])
                item['file'] = str(path.relative_to(probe.ROOT))
        output['collection_complete'] = True
        done = 'UPM_COLLECTION_DONE: one verified file' if profile == 'upm' else 'INPUT_MODULES_DONE: two verified files'
        print(done + '; RAM cleanup confirmed.', flush=True)
    finally:
        if created and camera.dev.terminal_quarantined:
            output['cleanup_skipped'] = 'Unknown terminal input state; no later shell command'
        elif created and not cleaned and not cleanup_attempted:
            try:
                cleanup()
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


def main(profile='input-modules'):
    sources = profile_sources(profile)
    description = 'Read only original-M7 /usr/kmod/upm.ko in one bounded service session.' if profile == 'upm' else __doc__
    parser = argparse.ArgumentParser(description=description)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--connect', action='store_true')
    mode.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        if profile == 'upm':
            from test_m7_collect_upm import main as test
        else:
            from test_m7_collect_input_modules import main as test
        test()
        return 0
    images = {s: reader.IMAGE_PATHS[s].read_bytes() for s in sources}
    proof = [reader.validate_reader(images[s], s) for s in sources]
    nonce = secrets.token_hex(6)
    commands, plan = make_commands(images, nonce, profile)
    specs = [frame(c, i, nonce) for i, c in enumerate(commands)]
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    entrypoint = probe.ROOT / 'scripts' / ('m7_collect_upm.py' if profile == 'upm' else 'm7_collect_input_modules.py')
    output = {'version': 1, 'utc': stamp, 'nonce': nonce, 'sources': sources, 'steps': [], 'profile': profile,
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'readers': proof,
              'entrypoint': str(entrypoint.relative_to(probe.ROOT)),
              'entrypoint_sha256': hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
              'file_control_allowed': False, 'sony_code_execution': False, 'source_open_flags': 0,
              'module_load_requested': False, 'target_memory_writes': False, 'automatic_retries': False,
              'transfer_timeout_seconds_per_file': TRANSFER_SECONDS, 'collection_complete': False}
    destination = probe.ROOT / 'extracted' / ('m7-' + profile + '-' + stamp + '-' + nonce)

    def gate_factory(device):
        gate = InputModuleGate(device, specs, output, profile)
        for stage in plan['stages']:
            gate.register([], specs[stage['execution']])
        return gate

    try:
        probe.connect(output, diagnostic=lambda camera, result: execute(camera, result, images, commands, plan, specs, destination,
                                                                      profile=profile),
                      gate_factory=gate_factory)
    except (Exception, KeyboardInterrupt) as error:
        output['error'] = type(error).__name__ + ': ' + str(error)
        print(output['error'], flush=True)
    receipt = probe.ROOT / 'evidence' / ('m7-' + profile + '-collect-' + stamp + '-' + nonce + '.json')
    receipt.write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n')
    print('RESULT=' + str(receipt), flush=True)
    return 1 if 'error' in output else 0


if __name__ == '__main__':
    raise SystemExit(main())
