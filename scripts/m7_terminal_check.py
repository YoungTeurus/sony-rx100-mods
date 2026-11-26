#!/usr/bin/env python3
"""M7 terminal inventory without FileControl, HASP or native payload."""
import argparse
import json
import subprocess
import time

import m7_probe as probe

BEGIN = b'__M7_TERMINAL_CHECK_BEGIN__'
END = b'__M7_TERMINAL_CHECK_END__'
COMMAND = (
    b'HISTFILE=/dev/null; export HISTFILE; echo __M7_TERMINAL_CHECK_BEGIN__; '
    b'echo __VERSION__; cat /version.txt; echo; '
    b'echo __MOUNTS__; cat /proc/mounts; '
    b'echo __TRACE_FILE__; ls -ld /setting/.etools; echo TRACE_LS_STATUS=$?; '
    b'echo __RAM_DIRECTORY__; ls -ld /tmp_network; '
    b'echo __BUSYBOX__; ls -l /bin/busybox; /bin/busybox --list; echo BUSYBOX_LIST_STATUS=$?; '
    b'echo __CORE_PATTERN__; cat /proc/sys/kernel/core_pattern; '
    b'echo __M7_TERMINAL_CHECK_END__\n'
)
PACKETS = {
    (0x10, b'\x00\x00\xf1\x00\x00'),
    (0x10, b'\x00\x00\xf1\x00\x01'),
    (0x40, b'\x01\x06\x1f\x00\x00'),
    (0x40, b'\x01\x06\x1f\x00\x02'),
}


class TerminalGate:
    def __init__(self, device):
        self.device = device

    def sendSenserPacket(self, function, payload, output=None):
        if (function, payload) not in PACKETS:
            raise probe.ProbeError('Разрешены только четыре пакета выбора terminal; FileControl запрещён')
        return self.device.sendSenserPacket(function, payload, output)

    def readTerminal(self):
        return self.device.readTerminal()

    def writeTerminal(self, data):
        if data != COMMAND:
            raise probe.ProbeError('Разрешена только фиксированная terminal inventory команда')
        return self.device.writeTerminal(data)


def collect(camera, result):
    try:
        with probe.deadline(8):
            camera.setTerminalEnable(False)
            camera.setTerminalEnable(True)
        with probe.deadline(25):
            result['terminal_inventory'] = probe.terminal_snapshot(
                camera, COMMAND, BEGIN, END, timeout=20)
        if not result['terminal_inventory']['complete']:
            raise probe.ProbeError('Terminal inventory не подтвердил обе маркерные строки')
        print('TERMINAL_INVENTORY_COMPLETE: ответ сохранён; содержимое .etools не читалось', flush=True)
    finally:
        try:
            with probe.deadline(8):
                camera.setTerminalEnable(False)
            result['terminal_disable_sent'] = True
        except Exception as error:
            result['terminal_disable_error'] = str(error)


def self_test():
    import sys
    sys.path.insert(0, str(probe.PMCA))
    from pmca.usb.sony import SonySenserCamera

    class Fake:
        def __init__(self):
            self.calls = []
        def sendSenserPacket(self, *args):
            self.calls.append(args)
            return (0 if args[0] == 0x40 else 1, b'')
        def writeTerminal(self, data):
            self.calls.append(data)

    fake = Fake()
    gate = TerminalGate(fake)
    camera = SonySenserCamera(gate)
    camera.setTerminalEnable(False)
    camera.setTerminalEnable(True)
    camera.setTerminalEnable(False)
    gate.writeTerminal(COMMAND)
    assert len(fake.calls) == 7
    for function, payload in [(0xff01, bytes([cmd, 0, 0, 0])) for cmd in (1, 2, 3)] + [
        (0x10, b'\x00\x00\x1f\x00\x00'),
        (0x20, b''), (0xff03, b''),
        (0x40, b'\x03\x06\x0f\x00\x01'),
        (0x40, b'\x01\x06\x1f\x00\x03'),
    ]:
        try:
            gate.sendSenserPacket(function, payload)
        except probe.ProbeError:
            pass
        else:
            raise AssertionError('Forbidden packet passed')
    for command in (b'reboot\n', COMMAND + b'\n', b'cat /setting/.etools\n'):
        try:
            gate.writeTerminal(command)
        except probe.ProbeError:
            pass
        else:
            raise AssertionError('Unlisted terminal command passed')
    subprocess.run(['/bin/sh', '-n'], input=COMMAND, check=True)
    assert len(fake.calls) == 7
    print('SELF_TEST_OK: terminal allowlist, FileControl/HASP rejection and shell syntax; no USB')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--connect', action='store_true')
    choice.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    result = {'version': 1, 'utc': stamp, 'pmca_commit': probe.PMCA_COMMIT,
              'file_control_allowed': False, 'native_payload': False,
              'trace_contents_read': False}
    try:
        probe.connect(result, diagnostic=collect, gate_factory=TerminalGate)
    except (Exception, KeyboardInterrupt) as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        print(result['error'], flush=True)
    output = probe.ROOT / 'evidence' / ('m7-terminal-check-' + stamp + '.json')
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print('RESULT=' + str(output), flush=True)
    return 1 if 'error' in result else 0


if __name__ == '__main__':
    raise SystemExit(main())
