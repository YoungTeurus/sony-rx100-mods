"""Host-only analysis functions from the Stage 6 qualification runner."""

import hashlib
import re
import struct
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_daemon_log(text: str) -> dict:
    boot = None
    states = []
    heartbeats = []
    ring_starts = []
    ring_events = []
    ring_files = []
    ring_exits = []
    stops = []
    unknown = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        kind = parts[0]
        kv = {}
        extra = []
        for token in parts[1:]:
            if "=" in token:
                k, v = token.split("=", 1)
                kv[k] = v
            else:
                extra.append(token)
        if extra:
            kv["_extra"] = " ".join(extra)
        if kind == "BOOT":
            boot = kv
        elif kind == "STATE":
            states.append(kv)
        elif kind == "HB":
            heartbeats.append(kv)
        elif kind == "RING_START":
            ring_starts.append(kv)
        elif kind == "RING_EVT":
            ring_events.append(kv)
        elif kind == "RING_FILE":
            ring_files.append(kv)
        elif kind == "RING_EXIT":
            ring_exits.append(kv)
        elif kind == "STOP":
            stops.append(kv)
        else:
            unknown.append(line)

    drives = sorted({s.get("drive") for s in states if s.get("cam") == "1" and s.get("drive")})
    formats = sorted({(s.get("fmt"), s.get("size"), s.get("asp"), s.get("qual"))
                      for s in states if s.get("cam") == "1"})
    bk_vals = sorted({s.get("bk") for s in states if s.get("bk_ok") == "1"})
    sub_ens = sorted({s.get("sub_en") for s in states if s.get("sub_ok") == "1"})
    gates = sorted({s.get("gate") for s in states if s.get("gate") is not None})
    hb_times = [int(h["t"]) for h in heartbeats if h.get("t", "").isdigit()]
    unresolved = [e for e in ring_events if e.get("ev") == "UNRESOLVED"]
    return dict(
        boot=boot,
        state_count=len(states),
        heartbeat_count=len(heartbeats),
        heartbeat_span_ms=(max(hb_times) - min(hb_times)) if len(hb_times) >= 2 else (hb_times[0] if hb_times else 0),
        ring_start_count=len(ring_starts),
        ring_exit_count=len(ring_exits),
        ring_file_count=len(ring_files),
        ring_unresolved_count=len(unresolved),
        stop=stops[-1] if stops else None,
        drives_seen=drives,
        formats_seen=[list(x) for x in formats],
        bk_values_seen=bk_vals,
        sub_enabled_seen=sub_ens,
        gates_seen=gates,
        states=states,
        heartbeats=heartbeats,
        ring_starts=ring_starts,
        ring_events=ring_events,
        ring_files=ring_files,
        ring_exits=ring_exits,
        unknown_lines=unknown,
    )


def inspect_jpeg_file(path: Path) -> dict:
    """Read-only strict JPEG SOI/SOF0-2/SOS/EOI structural verification (exact parity with stage6_ring.c)."""
    data = path.read_bytes()
    n = len(data)
    digest = hashlib.sha256(data).hexdigest()
    bad = dict(valid=False, size=n, width=0, height=0, sha256=digest)
    if n < 4 or data[:2] != b"\xff\xd8" or data[-2:] != b"\xff\xd9":
        return bad
    all_sof = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    supported_sof = {0xC0, 0xC1, 0xC2}
    pos = 2
    width = height = 0
    sof_marker = None
    sof_cids = None
    sos_seen = False
    eoi_seen = False
    while pos < n:
        if data[pos] != 0xFF:
            return bad
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            return bad
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            eoi_seen = True
            break
        if marker == 0x01:
            continue
        if marker == 0x00 or 0xD0 <= marker <= 0xD8:
            return bad
        if marker in all_sof and marker not in supported_sof:
            return bad
        if pos + 2 > n:
            return bad
        seg_len = struct.unpack_from(">H", data, pos)[0]
        if seg_len < 2 or pos + seg_len > n:
            return bad
        payload = data[pos + 2:pos + seg_len]
        pos += seg_len
        if marker in supported_sof:
            if sof_cids is not None or seg_len < 11:
                return bad
            prec = payload[0]
            height, width = struct.unpack_from(">HH", payload, 1)
            nf = payload[5]
            prec_ok = (prec == 8) if marker == 0xC0 else (prec in (8, 12))
            if not prec_ok or width == 0 or height == 0 or not (1 <= nf <= 4) or seg_len != 8 + 3 * nf:
                return bad
            cids = []
            for k in range(nf):
                cid, hv, tq = payload[6 + 3 * k:9 + 3 * k]
                hi, vi = hv >> 4, hv & 0x0F
                if cid in cids or not (1 <= hi <= 4) or not (1 <= vi <= 4) or tq > 3:
                    return bad
                cids.append(cid)
            sof_cids = cids
            sof_marker = marker
        elif marker == 0xDA:
            if sof_cids is None or seg_len < 8:
                return bad
            ns = payload[0]
            if not (1 <= ns <= len(sof_cids)) or seg_len != 6 + 2 * ns:
                return bad
            max_ht = 1 if sof_marker == 0xC0 else 3
            seen_cs = set()
            for k in range(ns):
                cs, tdta = payload[1 + 2 * k], payload[2 + 2 * k]
                if cs not in sof_cids or cs in seen_cs or (tdta >> 4) > max_ht or (tdta & 0x0F) > max_ht:
                    return bad
                seen_cs.add(cs)
            ss, se, ahal = payload[1 + 2 * ns:4 + 2 * ns]
            ah, al = ahal >> 4, ahal & 0x0F
            if sof_marker in (0xC0, 0xC1):
                if ss != 0 or se != 63 or ahal != 0:
                    return bad
            else:
                if ss == 0:
                    if se != 0:
                        return bad
                else:
                    if ns != 1 or not (1 <= ss <= se <= 63):
                        return bad
                if ah > 13 or al > 13 or (ah != 0 and ah != al + 1):
                    return bad
            sos_seen = True
            # Scan entropy-coded scan segment until next non-stuffed, non-RST marker.
            while pos < n:
                ff = data.find(b"\xff", pos)
                if ff < 0 or ff + 1 >= n:
                    return bad
                nxt = ff + 1
                while nxt < n and data[nxt] == 0xFF:
                    nxt += 1
                if nxt >= n:
                    return bad
                b = data[nxt]
                if b == 0x00 or (0xD0 <= b <= 0xD7):
                    pos = nxt + 1
                    continue
                pos = ff
                break
    valid = bool(eoi_seen and pos == n and sof_cids is not None and sos_seen and width > 0 and height > 0)
    return dict(valid=valid, size=n, width=width if valid else 0, height=height if valid else 0, sha256=digest)


def verify_card_saved_files(card_root: Path, ring_files: list, *, expect_nonempty: bool = False) -> dict:
    """Optional read-only verification of PC*.JPG files reported by daemon.log."""
    require(card_root.is_dir(), f"Card mount directory not found: {card_root}")
    results = []
    empty_file_list = len(ring_files) == 0
    all_ok = not (expect_nonempty and empty_file_list)
    for entry in ring_files:
        name = entry.get("file", "")
        expected_bytes = int(entry["bytes"]) if entry.get("bytes", "").isdigit() else -1
        status = entry.get("status", "")
        if not re.fullmatch(r"PC[0-9A-F]{6}\.JPG", name):
            results.append(dict(file=name, ok=False, reason="invalid_name"))
            all_ok = False
            continue
        fpath = card_root / name
        if not fpath.is_file():
            results.append(dict(file=name, ok=False, reason="missing_on_card", expected_bytes=expected_bytes))
            all_ok = False
            continue
        info = inspect_jpeg_file(fpath)
        ok = (
            status == "13" and
            info["valid"] and
            info["size"] == expected_bytes and
            info["width"] == 5472 and
            info["height"] == 3648
        )
        if not ok:
            all_ok = False
        results.append(dict(file=name, ok=ok, expected_bytes=expected_bytes, status=status, **info))
    return dict(
        card_root=str(card_root),
        checked=len(results),
        empty_file_list=empty_file_list,
        all_ok=all_ok,
        files=results,
    )
