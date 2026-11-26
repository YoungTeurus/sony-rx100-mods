#!/usr/bin/env python3
"""Recognize one bounded proper-prefix repaint before the exact current command echo.

ACK grammar, deadlines and I/O remain those of the pinned module collector.
The physical failed recording has no numeric END and must remain incomplete.
"""
import re
import time

from m7_collect_input_modules import (BANNER_LIMIT, OUTPUT_LIMIT, PROMPT_SUFFIXES,
                                      SHELL_PROMPT, TRANSFER_SECONDS, probe)


def marker_like(line):
    return bool(line) and (b'__M7_'.startswith(line) or line.startswith(b'__M7_'))


class ResponseLines:
    def __init__(self, spec):
        self.command = spec[0].rstrip(b'\n')
        self.marker_seen = False
        self.echo_repaints_removed = 0
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
                repeated = prefix[:-len(SHELL_PROMPT)] if prefix and prefix.endswith(SHELL_PROMPT) else b''
                if (0 < len(repeated) < len(self.command) < 512
                        and b'\r' not in self.command and b'\n' not in self.command
                        and self.command.startswith(repeated)):
                    if self.marker_seen or self.echo_repaints_removed:
                        raise probe.ProbeError('Repeated or late command echo repaint')
                    candidate = candidate[len(repeated):]
                    prefix = SHELL_PROMPT
                    self.echo_repaints_removed += 1
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
            self.marker_seen |= any(marker_like(value) for value in lines)
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

