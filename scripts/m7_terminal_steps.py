#!/usr/bin/env python3
"""Fixed terminal steps with bounded chunks, receive draining and host acknowledgements."""
import re
import time

import m7_probe as probe
from m7_terminal_check import PACKETS


def frame(command, index, nonce):
    if '\n' in command or '\r' in command or not re.fullmatch('[0-9a-f]{12}', nonce):
        raise ValueError('Invalid fixed terminal command')
    begin = f'__M7_B_{nonce}_{index:02d}__'.encode()
    end = f'__M7_E_{nonce}_{index:02d}_'.encode()
    variable = f'm7_rc_{index:02d}'
    data = (b'echo ' + begin + b'; ' + command.encode('ascii') + b'; ' +
            variable.encode() + b'=$?; echo; echo ' + end + b'${' + variable.encode() + b'}__\n\n')
    if len(data.splitlines()[0]) >= 512:
        raise ValueError('Terminal line too long')
    return data, begin, end


class StepGate:
    def __init__(self, device, frames, execute_index):
        self.device = device
        self.frames = [item[0] for item in frames]
        self.execute_index = execute_index
        self.exec_allowed = False
        self.received = bytearray()
        self.packet_log = []

    def sendSenserPacket(self, function, payload, output=None):
        if (function, payload) not in PACKETS:
            raise probe.ProbeError('Only terminal selection packets are allowed')
        event = {'function': hex(function), 'payload': payload.hex()}
        self.packet_log.append(event)
        try:
            answer = self.device.sendSenserPacket(function, payload, output)
            event['status'] = answer[0]
            return answer
        except Exception as error:
            event['error'] = str(error)
            raise

    def readTerminal(self):
        if self.received:
            data = bytes(self.received)
            self.received.clear()
            return data
        return self.device.readTerminal()

    def writeTerminal(self, data):
        if data not in self.frames:
            raise probe.ProbeError('Unknown terminal step')
        if data == self.frames[self.execute_index] and not self.exec_allowed:
            raise probe.ProbeError('Host has not verified the RAM executable checksum')
        for offset in range(0, len(data), 32):
            self.device.writeTerminal(data[offset:offset+32])
            self.received.extend(self.device.readTerminal())
            if len(self.received) > 2*1024*1024:
                raise probe.ProbeError('Console output limit exceeded during send')
            time.sleep(0.01)


def read_ready(camera):
    output = bytearray()
    until = time.monotonic() + 8
    while time.monotonic() < until and len(output) < 32768:
        output.extend(camera.dev.readTerminal())
        if re.search(rb'(?:^|\n)/[^\r\n]* # $', bytes(output)):
            return bytes(output)
    raise probe.ProbeError('Не получен prompt новой сервисной shell до отправки команд')


def run_step(camera, spec, index, transcript, allowed_status=(0,), timeout=12):
    data, begin, end = spec
    output = bytearray()
    prefix = end + rb'([0-9]+)__'
    try:
        with probe.deadline(timeout + 10):
            camera.dev.writeTerminal(data)
            until = time.monotonic() + timeout
            while time.monotonic() < until and len(output) < 2*1024*1024:
                output.extend(camera.dev.readTerminal())
                lines = bytes(output).replace(b'\r', b'').split(b'\n')
                for position, line in enumerate(lines):
                    match = re.fullmatch(prefix, line)
                    if not match:
                        continue
                    if lines[:position].count(begin) != 1:
                        raise probe.ProbeError(f'Step {index}: missing/duplicate start marker')
                    status = int(match[1])
                    first = lines.index(begin)
                    body = b'\n'.join(lines[first+1:position])
                    if status not in allowed_status:
                        raise probe.ProbeError(f'Step {index}: camera shell exit {status}: {body.decode("utf-8", "replace")[:200]}')
                    return body
            raise probe.ProbeError(f'Step {index}: no valid acknowledgement; later steps were not sent')
    finally:
        transcript.append({'step': index, 'command_bytes': len(data),
                           'response': bytes(output).decode('utf-8', 'replace')})
