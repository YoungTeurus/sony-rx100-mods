#!/usr/bin/env python3
"""Bounded RX100M7 service diagnostic; no updater, backup or remote file writes."""
import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PMCA = ROOT / 'sources/sony-pmca-re'
PMCA_COMMIT = 'a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0'
MODEL = 'DSC-RX100M7'
BEGIN = b'__M7_PROBE_BEGIN__'
END = b'__M7_PROBE_END__'
COMMAND = (b'HISTFILE=/dev/null; export HISTFILE; echo __M7_PROBE_BEGIN__; '
           b'cat /proc/version; cat /proc/mounts; cat /proc/meminfo; ps; '
           b'echo __M7_PROBE_END__\n')
READ_PATHS = ('/version.txt', '/proc/version', '/proc/mounts')
MAX_OUTPUT = 512 * 1024

class ProbeError(Exception):
    pass

class BoundedBytes(io.BytesIO):
    def write(self, data):
        if self.tell() + len(data) > MAX_OUTPUT:
            raise ProbeError('Ответ превышает 512 KiB; приём остановлен')
        return super().write(data)

@contextlib.contextmanager
def deadline(seconds):
    def expired(signum, frame):
        raise ProbeError('Истёк срок ожидания операции')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)

class PacketGate:
    """Allow only audited reads and transient terminal selection packets."""
    def __init__(self, device):
        self.device = device

    def sendSenserPacket(self, function, payload, output=None):
        header = payload[:4]
        allowed = False
        if function == 0x10:
            allowed = ((header == b'\x00\x00\x1f\x00' and payload[4:] == b'\x00') or
                       (header == b'\x00\x00\xf1\x00' and payload[4:] in (b'\x00', b'\x01')))
        elif function == 0x40:
            allowed = header == b'\x01\x06\x1f\x00' and payload[4:] in (b'\x00', b'\x02')
        elif function == 0xff01 and int.from_bytes(payload[:2], 'little') == 2:
            length = int.from_bytes(payload[2:4], 'little')
            path = payload[4:4+length].rstrip(b'\0').decode('ascii')
            allowed = path in READ_PATHS and len(payload) == 4 + length
        if not allowed:
            raise ProbeError(f'Пакет вне списка разрешённых: function={function:#x}')
        return self.device.sendSenserPacket(function, payload, output)

    def readTerminal(self):
        return self.device.readTerminal()

    def writeTerminal(self, data):
        if data != COMMAND:
            raise ProbeError('Разрешена только фиксированная диагностическая команда')
        return self.device.writeTerminal(data)


def terminal_snapshot(camera, command=COMMAND, begin=BEGIN, end=END, timeout=10):
    camera.dev.writeTerminal(command)
    received = bytearray()
    until = time.monotonic() + timeout
    while time.monotonic() < until and len(received) < MAX_OUTPUT:
        received.extend(camera.dev.readTerminal())
        lines = bytes(received).replace(b'\r', b'').split(b'\n')
        if end in lines:
            break
    lines = bytes(received).replace(b'\r', b'').split(b'\n')
    if begin in lines and end in lines:
        first = lines.index(begin)
        last = lines.index(end, first + 1)
        return {'complete': True, 'text': b'\n'.join(lines[first+1:last]).decode('utf-8', 'replace')}
    return {'complete': False, 'received_bytes': len(received),
            'partial_text': bytes(received).decode('utf-8', 'replace'),
            'reason': 'Нет обеих маркерных строк; ответ команды не подтверждён'}


def observation_window(camera, enabled, result):
    print('Окно 15 секунд: проверьте, есть ли live view и реакция AF на полунажатие.', flush=True)
    print('Если штатная съёмка доступна, сделайте один обычный снимок кнопкой камеры.', flush=True)
    print('Отметьте: снимок получился во время окна или только после выхода из service mode.', flush=True)
    result['observation_window_started'] = True
    until = time.monotonic() + 15
    while time.monotonic() < until:
        if enabled:
            try:
                with deadline(2):
                    camera.dev.readTerminal()
            except Exception as error:
                result['observation_terminal_error'] = str(error)
                enabled = False
        else:
            time.sleep(min(0.1, max(0, until - time.monotonic())))
    result['observation_window_completed'] = True


def diagnose(camera, result):
    try:
        with deadline(8):
            camera.readHasp()
        result['hasp_read'] = True
    except Exception as error:
        result['hasp_error'] = str(error)
    result['files'] = {}
    for path in READ_PATHS:
        try:
            output = BoundedBytes()
            with deadline(8):
                camera.readFile(path, output)
            data = output.getvalue()
            result['files'][path] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                                     'text': data.decode('utf-8', 'replace')}
        except Exception as error:
            result['files'][path] = {'error': str(error)}
    enabled = False
    try:
        try:
            with deadline(8):
                camera.setTerminalEnable(False)
                camera.setTerminalEnable(True)
            enabled = True
            with deadline(12):
                result['terminal_before'] = terminal_snapshot(camera)
        except Exception as error:
            result['terminal_before_error'] = str(error)
        observation_window(camera, enabled, result)
        if enabled:
            try:
                with deadline(12):
                    result['terminal_after'] = terminal_snapshot(camera)
            except Exception as error:
                result['terminal_after_error'] = str(error)
    finally:
        try:
            with deadline(8):
                camera.setTerminalEnable(False)
            result['terminal_disable_sent'] = True
        except Exception as error:
            result['terminal_disable_error'] = str(error)
    result['terminal_enable_succeeded'] = enabled


def finish_service(auth, result, should_stop_service=None):
    if should_stop_service is not None and not should_stop_service():
        result['service_stop_deferred'] = True
        print('SERVICE_LEFT_ACTIVE: завершение helper не подтверждено; выход из service не запрошен', flush=True)
        return
    try:
        with deadline(8):
            auth.stop()
        result['service_stop_requested'] = True
        print('EXIT_SERVICE_REQUESTED: запрошен выход; проверьте возврат камеры', flush=True)
    except Exception as error:
        result['service_stop_error'] = str(error)


def connect(result, diagnostic=None, gate_factory=PacketGate, should_stop_service=None):
    if diagnostic is None:
        diagnostic = diagnose
    git = ['git', '-c', 'safe.directory=' + str(PMCA), '-C', str(PMCA)]
    revision = subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip()
    if revision != PMCA_COMMIT:
        raise ProbeError(f'Нужна проверенная версия PMCA {PMCA_COMMIT}, найдена {revision}')
    dirty = subprocess.check_output(git + ['diff', '--name-only', 'HEAD', '--', 'pmca'], text=True).strip()
    if dirty:
        raise ProbeError('Исходники pmca изменены; необходим повторный аудит')
    sys.path.insert(0, str(PMCA))
    import usb.core
    import usb.backend.libusb1
    import libusb_package
    from pmca.commands.usb import importDriver, getDevice, listDevices
    from pmca.usb.sony import (SonyMscExtCmdDevice, SonyExtCmdCamera, SonySenserDevice,
                              SonySenserAuthDevice, SonySenserCamera)
    backend = usb.backend.libusb1.get_backend(find_library=libusb_package.find_library)
    if backend is None:
        raise ProbeError('Bundled libusb не загрузился')
    original_find = usb.core.find
    def find_with_backend(*args, **kwargs):
        kwargs.setdefault('backend', backend)
        return original_find(*args, **kwargs)
    usb.core.find = find_with_backend
    with importDriver('libusb') as driver:
        result['phase'] = 'normal_model_info'
        with deadline(15):
            normal = getDevice(driver)
            if not isinstance(normal, SonyMscExtCmdDevice):
                raise ProbeError('Начните с включённой камеры в USB Mass Storage, не в service/updater mode')
            info = SonyExtCmdCamera(normal).getCameraInfo()
        result['model'] = info.modelName
        if info.modelName != MODEL:
            raise ProbeError(f'Модель {info.modelName!r} запрещена; разрешена только {MODEL}')
        print(f'MODEL={info.modelName}; серийный номер не сохраняется', flush=True)
        auth = SonySenserAuthDevice(normal.driver)
        try:
            result['phase'] = 'enter_service'
            print('ENTER_SERVICE: временное переключение USB, без загрузки payload', flush=True)
            with deadline(10):
                auth.start()
                auth.authenticate()
            service = None
            for _ in range(20):
                time.sleep(0.5)
                try:
                    with deadline(3):
                        devices = list(listDevices(driver, True))
                    if len(devices) == 1 and isinstance(devices[0], SonySenserDevice):
                        service = devices[0]
                        break
                except Exception:
                    pass
            if service is None:
                raise ProbeError('SERVICE_TIMEOUT: камера не появилась в service mode')
            auth = SonySenserAuthDevice(service.driver)
            result['phase'] = 'service_authentication'
            with deadline(10):
                auth.start()
                auth.authenticate()
            result['service_authenticated'] = True
            result['phase'] = 'diagnostic_reads'
            diagnostic(SonySenserCamera(gate_factory(service)), result)
            result['phase'] = 'diagnostic_finished'
        finally:
            finish_service(auth, result, should_stop_service)


def self_test():
    class Fake:
        def __init__(self): self.calls = []
        def sendSenserPacket(self, *args):
            self.calls.append(args)
            return (0 if args[0] == 0x40 else 1, b'')
        def writeTerminal(self, data): self.calls.append(data)
    fake = Fake()
    gate = PacketGate(fake)
    gate.sendSenserPacket(0x10, b'\0\0\x1f\0\0')
    gate.sendSenserPacket(0x10, b'\0\0\xf1\0\1')
    gate.sendSenserPacket(0x40, b'\1\6\x1f\0\2')
    path = b'/version.txt\0\0\0\0'
    gate.sendSenserPacket(0xff01, b'\2\0' + len(path).to_bytes(2, 'little') + path)
    gate.writeTerminal(COMMAND)
    for function, payload in [(0x20, b''), (0xff03, b''), (0x40, b'\3\6\3\0'),
                              (0xff01, b'\1\0' + len(path).to_bytes(2, 'little') + path),
                              (0xff01, b'\3\0' + len(path).to_bytes(2, 'little') + path)]:
        try: gate.sendSenserPacket(function, payload)
        except ProbeError: pass
        else: raise AssertionError('Недопустимый пакет пропущен')
    try: gate.writeTerminal(b'reboot\n')
    except ProbeError: pass
    else: raise AssertionError('Недопустимая команда пропущена')
    assert len(fake.calls) == 5
    sys.path.insert(0, str(PMCA))
    from pmca.usb.sony import SonySenserCamera
    camera = SonySenserCamera(gate)
    camera.readHasp()
    camera.readFile('/version.txt')
    camera.setTerminalEnable(False)
    camera.setTerminalEnable(True)
    camera.setTerminalEnable(False)
    assert len(fake.calls) == 13
    class DeniedTerminal:
        def __init__(self): self.selectors = []
        def readHasp(self): return b''
        def readFile(self, path, output): output.write(b'fixture')
        def setTerminalEnable(self, enable):
            self.selectors.append(enable)
            if enable: raise ProbeError('fixture terminal denied')
    denied = DeniedTerminal()
    result = {}
    original_window = globals()['observation_window']
    def observed(camera, enabled, output):
        assert camera is denied and not enabled
        output['observation_window_started'] = True
    globals()['observation_window'] = observed
    try:
        diagnose(denied, result)
    finally:
        globals()['observation_window'] = original_window
    assert result['observation_window_started'] and result['terminal_disable_sent']
    assert not result['terminal_enable_succeeded'] and denied.selectors == [False, True, False]
    print('SELF_TEST_OK: allowlist and denied-terminal observation/cleanup passed; USB was not opened')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--connect', action='store_true', help='Подключиться к физической оригинальной M7')
    choice.add_argument('--self-test', action='store_true', help='Проверить ограничения без доступа к USB')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    parser.error('Повтор FileControl READ приостановлен: M7 может писать /setting/.etools. Используйте m7_terminal_check.py; см. reports/M7_SERVICE_LOG.md')
    result = {'probe_version': 1, 'pmca_commit': PMCA_COMMIT, 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    try:
        connect(result)
    except (Exception, KeyboardInterrupt) as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        print(result['error'], flush=True)
    output = ROOT / 'evidence' / ('m7-probe-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '.json')
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print('RESULT=' + str(output), flush=True)
    return 1 if 'error' in result else 0

if __name__ == '__main__':
    raise SystemExit(main())
