#!/usr/bin/env python3
"""Run the audited 248-byte ARM liveness helper from verified tmpfs only."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import time

import m7_probe as probe
from m7_terminal_check import PACKETS

IMAGE = probe.ROOT / 'artifacts/m7-native/m7-liveness.elf'
IMAGE_SHA256 = 'f32b80d7de888f98d963e4d8b1636afb0795bb820b1d50781c0a8d50101a9855'
BUILD = '29110_03.2021050601'
STARTED = b'M7_NATIVE_STARTED_7ac91e'
FINISHED = b'M7_NATIVE_FINISHED_7ac91e'
BEGIN = b'__M7_RAM_PREFLIGHT_BEGIN__'
END = b'__M7_RAM_PREFLIGHT_END__'
RUN_BEGIN = b'__M7_RAM_RUN_BEGIN__'
RUN_END = b'__M7_RAM_RUN_END__'
REQUIRED_APPLETS = {'echo', 'md5sum', 'mkdir', 'rmdir', 'rm', 'chmod', 'test'}
ECHO_MARKER = 'M7_OCTAL_OK'
ECHO_ESCAPES = ''.join('\\0%03o' % byte for byte in ECHO_MARKER.encode('ascii'))
PREFLIGHT = (
    b'HISTFILE=/dev/null; export HISTFILE; echo __M7_RAM_PREFLIGHT_BEGIN__; '
    b'echo __BUILD__; cat /version.txt; echo; '
    b'echo __MOUNTS__; cat /proc/mounts; '
    b'echo __DIRECTORY__; ls -ld /tmp_network; '
    b'echo __APPLETS__; /bin/busybox; '
    b"echo __ECHO_CHECK__; /bin/busybox echo -e '" + ECHO_ESCAPES.encode('ascii') + b"'; " +
    b'echo __M7_RAM_PREFLIGHT_END__\n'
)


def validate_preflight(text):
    sections = {}
    for label, next_label in [('BUILD', 'MOUNTS'), ('MOUNTS', 'DIRECTORY'), ('DIRECTORY', 'APPLETS')]:
        match = re.search(r'__' + label + r'__\n(.*?)__' + next_label + r'__\n', text, re.S)
        if not match:
            raise probe.ProbeError('Неполный preflight: ' + label)
        sections[label] = match[1]
    if sections['BUILD'].strip() != BUILD:
        raise probe.ProbeError('Неизвестный internal build')
    mounts = [line.split() for line in sections['MOUNTS'].splitlines() if line.strip()]
    target = [row for row in mounts if len(row) == 6 and row[1] == '/tmp_network']
    if len(target) != 1 or target[0][2] != 'tmpfs':
        raise probe.ProbeError('/tmp_network не подтверждён как единственный tmpfs mount')
    options = set(target[0][3].split(','))
    if 'rw' not in options or 'noexec' in options:
        raise probe.ProbeError('tmpfs не разрешает запись/исполнение')
    if any(len(row) >= 2 and row[1].startswith('/tmp_network/') for row in mounts):
        raise probe.ProbeError('В tmpfs есть вложенный mount; запуск остановлен')
    listing = sections['DIRECTORY'].strip().splitlines()
    if len(listing) != 1 or not listing[0].startswith('d') or not listing[0].endswith(' /tmp_network'):
        raise probe.ProbeError('RAM path не подтверждён как каталог, а не symlink')
    applets_text = text.split('__APPLETS__\n', 1)[1].split('__ECHO_CHECK__\n', 1)[0]
    if 'Currently defined functions:' not in applets_text:
        raise probe.ProbeError('BusyBox не вывел распознаваемый список applets')
    applets = set(re.findall(r'[A-Za-z0-9_.\[\]-]+', applets_text.split('Currently defined functions:', 1)[1]))
    missing = REQUIRED_APPLETS - applets
    if missing:
        raise probe.ProbeError('Не хватает BusyBox applets: ' + ', '.join(sorted(missing)))
    if '__ECHO_CHECK__\n' + ECHO_MARKER + '\n' not in text + '\n':
        raise probe.ProbeError('BusyBox echo не подтвердил обработку octal escapes')
    return {'build': BUILD, 'mount': target[0], 'applets_checked': sorted(REQUIRED_APPLETS)}


def run_command(image, nonce):
    if not re.fullmatch('[0-9a-f]{12}', nonce):
        raise ValueError('Invalid nonce')
    directory = '/tmp_network/.m7-liveness-' + nonce
    path = directory + '/probe.elf'
    chunks = [image[i:i+64] for i in range(0, len(image), 64)]
    writes = ''.join(
        "/bin/busybox echo -ne '" + ''.join('\\0%03o' % byte for byte in chunk) +
        f"' {'>' if i == 0 else '>>'} {path} || exit 75; "
        for i, chunk in enumerate(chunks))
    checksum = hashlib.md5(image).hexdigest()
    command = (
        'HISTFILE=/dev/null; export HISTFILE; echo __M7_RAM_RUN_BEGIN__; '
        '( ulimit -c 0 || exit 70; umask 077; '
        f'/bin/busybox mkdir {directory} || exit 71; '
        f"trap '/bin/busybox rm -f {path}; /bin/busybox rmdir {directory}' 0 || "
        f'{{ /bin/busybox rmdir {directory}; exit 72; }}; '
        "trap 'exit 73' 1 2 15 || exit 74; "
        + writes +
        f'm7_sum=$(/bin/busybox md5sum {path}) || exit 76; '
        'set -- $m7_sum; '
        f'/bin/busybox test "$1" = {checksum} || exit 77; '
        'echo M7_RAM_BYTES_VERIFIED; '
        f'/bin/busybox chmod 500 {path} || exit 78; '
        f'{path}; m7_native_status=$?; echo M7_NATIVE_RC=$m7_native_status; '
        'exit "$m7_native_status" ); m7_shell_status=$?; echo M7_RAM_SHELL_RC=$m7_shell_status; '
        f'ls -ld {directory}; echo M7_RAM_DIRECTORY_LS_RC=$?; '
        'echo __M7_RAM_RUN_END__\n'
    ).replace('; ', ';\n').encode('ascii')
    if max(len(line) for line in command.splitlines()) >= 512:
        raise ValueError('Terminal input line exceeds conservative bound')
    return command, directory


class RamGate:
    def __init__(self, device, execute):
        self.device = device
        self.execute = execute
        self.run_allowed = False
        self.run_sent = False
        self.packet_log = []
        self.commit_allowed = False

    def sendSenserPacket(self, function, payload, output=None):
        if (function, payload) not in PACKETS:
            raise probe.ProbeError('Только terminal selection; FileControl и memory packets запрещены')
        event = {'function': hex(function), 'payload': payload.hex()}
        self.packet_log.append(event)
        try:
            response = self.device.sendSenserPacket(function, payload, output)
            event['status'] = response[0]
            event['response_bytes'] = len(response[1]) if response[1] is not None else None
            return response
        except Exception as error:
            event['error'] = type(error).__name__ + ': ' + str(error)
            raise

    def readTerminal(self):
        return self.device.readTerminal()

    def writeTerminal(self, data):
        if data == PREFLIGHT:
            return self.device.writeTerminal(data)
        if data == b'\n' and self.commit_allowed:
            self.commit_allowed = False
            return self.device.writeTerminal(data)
        if data == self.execute and self.run_allowed and not self.run_sent:
            self.run_sent = True
            return self.device.writeTerminal(data)
        raise probe.ProbeError('Команда не разрешена либо preflight ещё не завершён')


def parse_run(received, directory):
    lines = bytes(received).replace(b'\r', b'').split(b'\n')
    expected = [b'M7_RAM_BYTES_VERIFIED', STARTED, FINISHED, b'M7_NATIVE_RC=0',
                b'M7_RAM_SHELL_RC=0', RUN_END]
    unique = all(lines.count(marker) == 1 for marker in expected)
    ordered = unique and [lines.index(marker) for marker in expected] == sorted(lines.index(marker) for marker in expected)
    missing_directory = ('ls: ' + directory + ': No such file or directory').encode('ascii')
    return {'complete': RUN_END in lines, 'received_bytes': len(received),
            'text': bytes(received).decode('utf-8', 'replace'),
            'wrapper_begin_seen': RUN_BEGIN in lines,
            'native_start_seen': STARTED in lines, 'native_finish_seen': FINISHED in lines,
            'native_exit_zero': b'M7_NATIVE_RC=0' in lines,
            'shell_exit_zero': b'M7_RAM_SHELL_RC=0' in lines,
            'bytes_verified_before_exec': b'M7_RAM_BYTES_VERIFIED' in lines,
            'native_receipt_order_verified': ordered,
            'ram_directory_absent_after_run': missing_directory in lines}


def read_run(camera, directory):
    camera.dev.writeTerminal(camera.dev.execute)
    received = bytearray()
    started_at = None
    finished_at = None
    until = time.monotonic() + 35
    commit_at = time.monotonic() + 2
    committed = False
    while time.monotonic() < until and len(received) < probe.MAX_OUTPUT:
        received.extend(camera.dev.readTerminal())
        lines = bytes(received).replace(b'\r', b'').split(b'\n')
        if STARTED in lines and started_at is None:
            started_at = time.monotonic()
            print('M7_NATIVE_STARTED: сейчас 15 секунд — проверьте AF/экран и сделайте обычное фото.', flush=True)
        if FINISHED in lines and finished_at is None:
            finished_at = time.monotonic()
        if not committed and started_at is None and time.monotonic() >= commit_at:
            camera.dev.commit_allowed = True
            camera.dev.writeTerminal(b'\n')
            committed = True
        if RUN_END in lines:
            break
    return {**parse_run(received, directory),
            'host_marker_interval_seconds': None if started_at is None or finished_at is None else finished_at - started_at}


def self_test():
    image = IMAGE.read_bytes()
    assert hashlib.sha256(image).hexdigest() == IMAGE_SHA256 and len(image) == 248
    command, directory = run_command(image, '0123456789ab')
    subprocess.run(['/bin/sh', '-n'], input=PREFLIGHT, check=True)
    subprocess.run(['/bin/sh', '-n'], input=command, check=True)
    encoded = ''.join('\\0%03o' % byte for byte in image)
    assert subprocess.check_output(['/bin/sh', '-c', 'printf "%b" "$1"', 'sh', encoded]) == image
    assert subprocess.check_output(['/bin/bash', '-c', 'echo -ne "$1"', 'bash', encoded]) == image
    fixture = ('__BUILD__\n' + BUILD + '\n__MOUNTS__\n'
               'none /tmp_network tmpfs rw,noatime,size=1024k 0 0\n'
               '__DIRECTORY__\ndrwxrwxrwt 4 0 0 80 Jan 1 00:00 /tmp_network\n'
               '__APPLETS__\nBusyBox\nCurrently defined functions:\n' + ', '.join(sorted(REQUIRED_APPLETS)) +
               '\n__ECHO_CHECK__\n' + ECHO_MARKER + '\n')
    validate_preflight(fixture)
    for before, after in [('tmpfs rw', 'vfat rw'), ('tmpfs rw', 'tmpfs rw,noexec'),
                          ('drwxrwxrwt', 'lrwxrwxrwx'), (BUILD, 'other'), ('md5sum', 'missing'),
                          (ECHO_MARKER, 'wrong_echo')]:
        try:
            validate_preflight(fixture.replace(before, after))
        except probe.ProbeError:
            pass
        else:
            raise AssertionError('Unsafe preflight accepted')
    class Fake:
        def __init__(self): self.sent = []
        def writeTerminal(self, data): self.sent.append(data)
    device = Fake()
    gate = RamGate(device, command)
    for data in (command, b'reboot\n'):
        try: gate.writeTerminal(data)
        except probe.ProbeError: pass
        else: raise AssertionError('Command accepted before preflight')
    for function in (0xff01, 0xff03, 0x20):
        try: gate.sendSenserPacket(function, b'')
        except probe.ProbeError: pass
        else: raise AssertionError('Disallowed packet accepted')
    gate.run_allowed = True
    gate.writeTerminal(command)
    try: gate.writeTerminal(command)
    except probe.ProbeError: pass
    else: raise AssertionError('Duplicate execution accepted')
    assert device.sent == [command]
    observed = json.loads((probe.ROOT / 'evidence/m7-ram-liveness-20261104T220705Z.json').read_text())
    raw = observed['native_run']['partial_text'].encode('utf-8')
    parsed = parse_run(raw, observed['ram_directory'])
    assert parsed['native_receipt_order_verified'] and parsed['ram_directory_absent_after_run']
    assert not parsed['wrapper_begin_seen']
    for broken in (raw.replace(FINISHED, b'NO_FINISH'), raw.replace(b'M7_NATIVE_RC=0', b'M7_NATIVE_RC=1'),
                   raw.replace(STARTED, STARTED + b'\r\n' + STARTED), raw.replace(b'M7_RAM_BYTES_VERIFIED\r\n', b'')):
        assert not parse_run(broken, observed['ram_directory'])['native_receipt_order_verified']
    print('SELF_TEST_OK: transport/gates and actual console receipt regression; no USB')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--connect', action='store_true')
    choice.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    parser.error('Опыт уже подтверждён. Bulk-транспорт отключён после потери символов; новый terminal-only маршрут — scripts/m7_collect_liro_steps.py')
    image = IMAGE.read_bytes()
    if hashlib.sha256(image).hexdigest() != IMAGE_SHA256 or len(image) != 248:
        raise probe.ProbeError('Native helper отличается от проверенного образца')
    execute, directory = run_command(image, secrets.token_hex(6))
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    result = {'version': 5, 'utc': stamp, 'image_sha256': IMAGE_SHA256,
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'ram_directory': directory, 'file_control_allowed': False, 'hook_or_injection': False}

    def diagnose(camera, output):
        try:
            with probe.deadline(8):
                camera.setTerminalEnable(False)
                camera.setTerminalEnable(True)
            with probe.deadline(20):
                output['preflight'] = probe.terminal_snapshot(camera, PREFLIGHT, BEGIN, END, timeout=15)
            if not output['preflight']['complete']:
                output['preflight_initial'] = output['preflight']
                print('PREFLIGHT_LINE_COMMIT: отправляется один дополнительный перевод строки.', flush=True)
                camera.dev.commit_allowed = True
                with probe.deadline(20):
                    output['preflight'] = probe.terminal_snapshot(camera, b'\n', BEGIN, END, timeout=15)
                if not output['preflight']['complete']:
                    raise probe.ProbeError('Preflight не завершился даже после отдельного перевода строки')
            output['preflight_checks'] = validate_preflight(output['preflight']['text'])
            camera.dev.run_allowed = True
            print('PREFLIGHT_OK: tmpfs и утилиты проверены; запускается отдельный ARM процесс.', flush=True)
            with probe.deadline(40):
                output['native_run'] = read_run(camera, directory)
            native = output['native_run']
            if not all(native.get(key) for key in ('complete', 'native_start_seen', 'native_finish_seen',
                                                  'native_exit_zero', 'shell_exit_zero', 'bytes_verified_before_exec',
                                                  'native_receipt_order_verified', 'ram_directory_absent_after_run')):
                raise probe.ProbeError('Native helper не подтвердил штатный проход; см. RESULT')
            print('NATIVE_LIVENESS_OK: получены обе native marker lines и exit 0.', flush=True)
        finally:
            try:
                with probe.deadline(8):
                    camera.setTerminalEnable(False)
                output['terminal_disable_sent'] = True
            except Exception as error:
                output['terminal_disable_error'] = str(error)
            output['terminal_packets'] = camera.dev.packet_log
    try:
        probe.connect(result, diagnostic=diagnose, gate_factory=lambda device: RamGate(device, execute))
    except (Exception, KeyboardInterrupt) as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        print(result['error'], flush=True)
    output_path = probe.ROOT / 'evidence' / ('m7-ram-liveness-' + stamp + '.json')
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print('RESULT=' + str(output_path), flush=True)
    return 1 if 'error' in result else 0


if __name__ == '__main__':
    raise SystemExit(main())
