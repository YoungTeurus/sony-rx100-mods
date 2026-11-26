#!/usr/bin/env python3
"""Keep terminal transfer counts and USB errors that the PMCA wrapper discards."""
import hashlib
from pathlib import Path
import time

from m7_anchor_probe import MultiReadGate
import m7_probe as probe


class TerminalIO:
    def __init__(self, device):
        from pmca.usb.driver.generic import GenericUsbDriver
        from pmca.usb.driver.generic.libusb import UsbBackend
        import usb.core

        driver = device.driver
        if type(driver) is not GenericUsbDriver or type(driver.backend) is not UsbBackend:
            raise probe.ProbeError('Terminal diagnostics require the audited libusb generic driver')
        if len(driver.epIn) != 2 or len(driver.epOut) != 2:
            raise probe.ProbeError('Unexpected service endpoint layout')
        self.in_endpoint, self.out_endpoint = driver.epIn[1], driver.epOut[1]
        if (not self.in_endpoint & 0x80 or self.out_endpoint & 0x80
                or not self.in_endpoint & 0xf or not self.out_endpoint & 0xf):
            raise probe.ProbeError('Invalid terminal endpoints')
        self.device, self.raw, self.usb = device, driver.backend.dev, usb.core
        self.started, self.step = time.monotonic(), None
        self.trace = {'version': 1, 'implementation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      'in_endpoint': self.in_endpoint, 'out_endpoint': self.out_endpoint,
                      'quarantined': False, 'events': [], 'event_limit': 50000,
                      'automatic_retries': False, 'payloads_saved': False}

    def quarantine(self, reason):
        self.trace['quarantined'] = True
        self.trace.setdefault('first_failure', reason)

    def event(self, operation, requested):
        if self.trace['quarantined']:
            raise probe.ProbeError('Terminal input state unknown; no more terminal I/O is allowed')
        if len(self.trace['events']) >= self.trace['event_limit']:
            self.quarantine('USB event limit reached')
            raise probe.ProbeError('USB event limit reached')
        event = {'operation': operation, 'step': self.step, 'requested': requested,
                 'at_seconds': time.monotonic() - self.started}
        self.trace['events'].append(event)
        return event

    def error_fields(self, event, error):
        event.update(error_type=type(error).__name__, errno=getattr(error, 'errno', None),
                     backend_error_code=getattr(error, 'backend_error_code', None))

    def sendSenserPacket(self, *args):
        return self.device.sendSenserPacket(*args)

    def readTerminal(self):
        event = self.event('read', 64)
        started = time.monotonic()
        try:
            data = self.raw.read(self.in_endpoint, 64, 100).tobytes()
            event['actual'] = len(data)
            return data
        except self.usb.USBError as error:
            self.error_fields(event, error)
            if isinstance(error, self.usb.USBTimeoutError) or event['backend_error_code'] == -7:
                event['timeout'] = True
                return b''
            reason = 'Terminal USB IN error: backend=%s errno=%s' % (event['backend_error_code'], event['errno'])
            self.quarantine(reason)
            raise probe.ProbeError(reason) from error
        finally:
            event['elapsed_seconds'] = time.monotonic() - started

    def writeTerminal(self, data):
        if not isinstance(data, bytes) or not 1 <= len(data) <= 32:
            raise probe.ProbeError('Terminal writes must be bounded chunks of at most 32 bytes')
        event = self.event('write', len(data))
        started = time.monotonic()
        try:
            actual = self.raw.write(self.out_endpoint, data)
            event['actual'] = actual
            if type(actual) is not int or actual != len(data):
                reason = 'Terminal USB OUT short write: %s/%s bytes' % (actual, len(data))
                self.quarantine(reason)
                raise probe.ProbeError(reason)
        except self.usb.USBError as error:
            self.error_fields(event, error)
            reason = 'Terminal USB OUT error: backend=%s errno=%s' % (event['backend_error_code'], event['errno'])
            self.quarantine(reason)
            raise probe.ProbeError(reason) from error
        finally:
            event['elapsed_seconds'] = time.monotonic() - started


class TracedGate(MultiReadGate):
    def __init__(self, device, specs, output):
        self.terminal = TerminalIO(device)
        output['terminal_io'] = self.terminal.trace
        super().__init__(self.terminal, specs)

    def writeTerminal(self, data):
        if data in self.frames:
            self.terminal.step = self.frames.index(data)
        return super().writeTerminal(data)

    @property
    def terminal_quarantined(self):
        return self.terminal.trace['quarantined']

    def quarantine_terminal(self, reason):
        self.terminal.quarantine(reason)
