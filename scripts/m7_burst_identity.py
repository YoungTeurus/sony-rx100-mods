#!/usr/bin/env python3
"""Pure host guards for the original M7 inline StillPool observer."""
import copy
import hashlib
import io
from pathlib import Path
import re

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / 'extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/lib/libObj.so'
CAMERA_LIBRARY = '/usr/lib/libObj.so'
MODEL = 'DSC-RX100M7'
BUILD = '29110_03.2021050601'
LIBRARY_SHA256 = '38cba88dab492ed8529ae1ec80636bce64d649229ed790023f3579144860a092'
LIBRARY_MD5 = '99a06d3852bf744a5d454bd873f6d35c'
LIBRARY_BYTES = 21089716
ROOT_VA = 0x1463800
PAGE = 0x1000
USER_END = 0xc0000000
MAP_LIMIT = 256
MAX_MAP_ROWS = 4096
ROOT_BYTES = 0x68
POOL_BYTES = 0x70ec
RECORD_BYTES = 0x1b8
RECORD_LIMIT = 8
LOADS = (
    dict(p_offset=0, p_vaddr=0, p_filesz=0x132417c, p_memsz=0x132417c, p_flags=5, p_align=0x8000),
    dict(p_offset=0x132417c, p_vaddr=0x132c17c, p_filesz=0xf8678, p_memsz=0x137784,
         p_flags=6, p_align=0x8000),
)
LISTING_PATHS = {'/tmp_network': 'd', '/proc': 'd', '/usr': 'd', '/usr/lib': 'd',
                 CAMERA_LIBRARY: '-', '/usr/bin': 'd', '/usr/bin/im.elf': '-'}
POOL_FIELDS = ('address', 'mutex_value', 'active', 'media', 'head', 'tail', 'count',
               'overflow_limit', 'store_mode')


class GuardError(ValueError):
    pass


class RetryableMapsError(GuardError):
    """Only a fresh snapshot may resolve an overlap outside protected mappings."""
    def __init__(self, identity, conflicts):
        super().__init__('Overlapping mappings outside protected ranges; fresh identity required')
        self.partial_identity = identity
        self.conflicts = conflicts


def _integer(value, minimum=0, maximum=0xffffffff):
    if type(value) is not int or not minimum <= value <= maximum:
        raise GuardError('Expected bounded integer, not bool or coerced value')
    return value


def _page_floor(value):
    return value & -PAGE


def _page_ceil(value):
    return (value + PAGE - 1) & -PAGE


def _span(address, size):
    _integer(address, 0x10000, USER_END - 1)
    _integer(size, 1, USER_END)
    if address % 4 or size > USER_END - address:
        raise GuardError('Unaligned or overflowing user span')
    return address, address + size


def _intersects(a, b):
    return a[0] < b[1] and b[0] < a[1]


def local_target(path=LIBRARY):
    image = Path(path).read_bytes()
    if (len(image) != LIBRARY_BYTES or hashlib.sha256(image).hexdigest() != LIBRARY_SHA256
            or hashlib.md5(image).hexdigest() != LIBRARY_MD5):
        raise GuardError('Original M7 libObj size/SHA256/MD5 mismatch')
    elf = ELFFile(io.BytesIO(image))
    if (elf.elfclass != 32 or not elf.little_endian or elf['e_machine'] != 'EM_ARM'
            or elf['e_type'] != 'ET_DYN'):
        raise GuardError('Expected original ELF32 little-endian ARM ET_DYN')
    loads = [{key: segment[key] for key in LOADS[0]} for segment in elf.iter_segments()
             if segment['p_type'] == 'PT_LOAD']
    if loads != list(LOADS):
        raise GuardError('Pinned libObj PT_LOAD layout differs')
    bss = elf.get_section_by_name('.bss')
    if (bss is None or bss['sh_type'] != 'SHT_NOBITS'
            or not bss['sh_addr'] <= ROOT_VA < ROOT_VA + 4 <= bss['sh_addr'] + bss['sh_size']):
        raise GuardError('StillPool slot is not within pinned libObj BSS')
    return dict(library=str(Path(path)), camera_library=CAMERA_LIBRARY,
                library_sha256=LIBRARY_SHA256, library_md5=LIBRARY_MD5,
                library_bytes=LIBRARY_BYTES, model=MODEL, build=BUILD,
                root_elf_va=ROOT_VA, loads=loads, page_size=PAGE)


def _validate_target(target):
    expected = dict(camera_library=CAMERA_LIBRARY, library_sha256=LIBRARY_SHA256,
                    library_md5=LIBRARY_MD5, library_bytes=LIBRARY_BYTES,
                    root_elf_va=ROOT_VA, loads=list(LOADS), model=MODEL, build=BUILD, page_size=PAGE)
    if any(target.get(key) != value for key, value in expected.items()):
        raise GuardError('Target description is not pinned original M7 libObj')


def parse_pid(text):
    if type(text) is not str or not re.fullmatch(r'[1-9][0-9]{0,9}', text.strip()):
        raise GuardError('Expected exactly one live im.elf PID')
    return _integer(int(text.strip()), 2, 0x7fffffff)


def preflight_commands():
    echo = ''.join('\\0%03o' % value for value in b'M7_OCTAL_OK')
    return ['HISTFILE=/dev/null; export HISTFILE; ulimit -c 0 && umask 077',
            'cat /version.txt', 'cat /proc/mounts', 'ls -ld ' + ' '.join(LISTING_PATHS),
            '/bin/busybox', "/bin/busybox echo -e '" + echo + "'",
            '/bin/busybox pidof im.elf', '/bin/busybox wc -c ' + CAMERA_LIBRARY,
            '/bin/busybox md5sum ' + CAMERA_LIBRARY]


def checked_preflight(bodies, model=MODEL):
    if model != MODEL or len(bodies) != 9 or not all(type(body) is str for body in bodies):
        raise GuardError('Expected original M7 model and nine complete preflight bodies')
    if bodies[1].strip() != BUILD:
        raise GuardError('Original M7 build differs')
    mounts = [line.split() for line in bodies[2].splitlines() if line.strip()]
    if any(len(row) != 6 for row in mounts):
        raise GuardError('Malformed mount table')
    selected = {}
    for path, fs in (('/usr', 'ext2'), ('/proc', 'proc'), ('/tmp_network', 'tmpfs')):
        matching = [row for row in mounts if row[1] == path]
        if len(matching) != 1 or matching[0][2] != fs:
            raise GuardError('Unexpected or ambiguous mount at ' + path)
        if any(row[1].startswith(path + '/') for row in mounts):
            raise GuardError('Nested mount is forbidden under ' + path)
        selected[path] = matching[0]
    usr_options = selected['/usr'][3].split(',')
    if 'ro' not in usr_options or 'rw' in usr_options:
        raise GuardError('/usr must be read-only ext2')
    ram_options = selected['/tmp_network'][3].split(',')
    if 'rw' not in ram_options or 'ro' in ram_options or 'noexec' in ram_options:
        raise GuardError('/tmp_network must be executable writable tmpfs')
    sizes = [value[5:] for value in ram_options if value.startswith('size=')]
    if len(sizes) != 1 or not re.fullmatch(r'[1-9][0-9]*[kKmM]?', sizes[0]):
        raise GuardError('Explicit single tmpfs size is required')
    suffix = sizes[0][-1].lower()
    capacity = (int(sizes[0][:-1]) * {'k': 1024, 'm': 1024 * 1024}[suffix]
                if suffix in ('k', 'm') else int(sizes[0]))
    if capacity != 1024 * 1024:
        raise GuardError('Expected exactly 1 MiB tmpfs')
    listings = {}
    for line in bodies[3].splitlines():
        fields = line.split()
        if len(fields) < 9 or fields[-1] not in LISTING_PATHS or fields[-1] in listings:
            raise GuardError('Unexpected or duplicate nonsymlink listing')
        path = fields[-1]
        if not re.fullmatch(LISTING_PATHS[path] + r'[rwxstST-]{9}', fields[0]):
            raise GuardError('Expected nonsymlink directory or regular source file')
        listings[path] = line
    if set(listings) != set(LISTING_PATHS):
        raise GuardError('Missing fixed-path nonsymlink listing')
    if bodies[4].count('Currently defined functions:') != 1:
        raise GuardError('Expected bounded BusyBox applet inventory')
    applets = set(re.findall(r'[A-Za-z0-9_.\[\]-]+', bodies[4].split('Currently defined functions:', 1)[1]))
    required = {'echo', 'md5sum', 'mkdir', 'rmdir', 'rm', 'chmod', 'test', 'pidof', 'readlink', 'wc'}
    if not required <= applets or bodies[5].strip() != 'M7_OCTAL_OK':
        raise GuardError('Required BusyBox applets or exact octal echo missing')
    size = re.fullmatch(r'\s*([1-9][0-9]*)\s+' + re.escape(CAMERA_LIBRARY) + r'\s*', bodies[7])
    digest = re.fullmatch(r'([0-9a-f]{32})\s+\*?' + re.escape(CAMERA_LIBRARY) + r'\s*', bodies[8].strip())
    if not size or int(size[1]) != LIBRARY_BYTES or not digest or digest[1] != LIBRARY_MD5:
        raise GuardError('On-camera libObj size/MD5 differs from pinned original M7')
    return dict(model=model, build=BUILD, pid=parse_pid(bodies[6]), usr_mount=selected['/usr'],
                proc_mount=selected['/proc'], mount=selected['/tmp_network'], tmpfs_capacity=capacity,
                no_source_symlinks=True, source=CAMERA_LIBRARY,
                source_bytes=LIBRARY_BYTES, source_md5=LIBRARY_MD5, required_applets=sorted(required))


def identity_commands(pid):
    _integer(pid, 2, 0x7fffffff)
    base = '/proc/' + str(pid)
    return ['cat ' + base + '/stat', 'cat ' + base + '/status',
            '/bin/busybox readlink ' + base + '/exe', 'cat ' + base + '/maps']


def _map_rows(text):
    if type(text) is not str or not text.strip() or len(text) > 1024 * 1024:
        raise GuardError('Missing or oversized maps snapshot')
    lines = text.strip().splitlines()
    if len(lines) > MAX_MAP_ROWS:
        raise GuardError('Map row limit exceeded')
    rows = []
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{1,8})-([0-9a-f]{1,8}) ([r-][w-][x-][ps]) '
                             r'([0-9a-f]{1,8}) ([0-9a-f]+:[0-9a-f]+) ([0-9]+)\s*(.*)', line.strip())
        if not match:
            raise GuardError('Malformed maps row')
        lo, hi, flags, offset, device, inode, path = match.groups()
        row = dict(start=int(lo, 16), end=int(hi, 16), flags=flags, offset=int(offset, 16),
                   device=device, inode=int(inode), path=path)
        if row['start'] >= row['end'] or any(row[key] % PAGE for key in ('start', 'end', 'offset')):
            raise GuardError('Invalid map bounds or page alignment')
        rows.append(row)
    return rows


def _eligible(row):
    return (row['flags'] == 'rw-p' and row['device'] == '00:00' and row['inode'] == 0
            and row['offset'] == 0 and row['path'] in ('', '[heap]'))


def private_ram(rows, address, size):
    lo, hi = _span(address, size)
    matching = [row for row in rows if row['start'] <= lo and hi <= row['end']]
    if len(matching) != 1 or not _eligible(matching[0]):
        raise GuardError('Span must fit exactly one private anonymous or heap mapping')
    return matching[0]


def _base_protected(identity):
    return [identity[key] for key in ('rx', 'gap', 'rw', 'bss', 'executable_mapping')]


def _check_order(rows):
    if any(a['start'] > b['start'] for a, b in zip(rows, rows[1:])):
        raise GuardError('Unordered maps snapshot is not retryable')
    conflicts = []
    previous = None
    for row in rows:
        if previous is not None and previous['end'] > row['start']:
            conflicts.append((min(previous['start'], row['start']), max(previous['end'], row['end'])))
        if previous is None or row['end'] > previous['end']:
            previous = row
    return conflicts


def parse_identity(pid, stat, status, executable, maps, target=None, protected_spans=()):
    _integer(pid, 2, 0x7fffffff)
    target = local_target() if target is None else target
    _validate_target(target)
    prefix = str(pid) + ' (im.elf) '
    if not stat.strip().startswith(prefix):
        raise GuardError('Unexpected process stat identity')
    fields = stat.strip()[len(prefix):].split()
    if (len(fields) < 25 or fields[0] not in ('R', 'S', 'D')
            or not all(re.fullmatch(r'-?[0-9]+', value) for value in fields[1:])):
        raise GuardError('Stopped/dead process or malformed stat fields')
    starttime = _integer(int(fields[19]), 1, 0xffffffffffffffff)
    names = {}
    for line in status.splitlines():
        if ':' not in line:
            raise GuardError('Malformed process status')
        key, value = line.split(':', 1)
        if key in names:
            raise GuardError('Duplicate process status field')
        names[key] = value.strip()
    if (names.get('Name') != 'im.elf' or names.get('Pid') != str(pid)
            or names.get('Tgid') != str(pid) or names.get('TracerPid') != '0'
            or names.get('Uid', '').split() != ['0'] * 4 or executable.strip() != '/usr/bin/im.elf'):
        raise GuardError('Unexpected process credentials, PID, tracer or executable')
    rows = _map_rows(maps)
    exe = [row for row in rows if row['path'] == '/usr/bin/im.elf' and row['flags'] == 'r-xp']
    if len(exe) != 1 or exe[0]['inode'] == 0 or exe[0]['device'] == '00:00' or exe[0]['offset'] != 0:
        raise GuardError('Expected unique file-backed im.elf RX mapping')
    library = [row for row in rows if row['path'] == CAMERA_LIBRARY]
    rx = [row for row in library if row['flags'] == 'r-xp' and row['offset'] == 0]
    if len(library) != 3 or len(rx) != 1 or rx[0]['inode'] == 0 or rx[0]['device'] != exe[0]['device']:
        raise GuardError('Expected three original libObj file mappings')
    rx = rx[0]; bias = rx['start']
    if bias < 0x10000 or bias % PAGE or bias + _page_ceil(LOADS[1]['p_vaddr'] + LOADS[1]['p_memsz']) > USER_END:
        raise GuardError('Invalid original libObj load bias')
    expected = (
        ('rx', bias, bias + _page_ceil(LOADS[0]['p_filesz']), 'r-xp', 0),
        ('gap', bias + _page_ceil(LOADS[0]['p_filesz']), bias + _page_floor(LOADS[1]['p_vaddr']),
         '---p', _page_ceil(LOADS[0]['p_filesz'])),
        ('rw', bias + _page_floor(LOADS[1]['p_vaddr']),
         bias + _page_ceil(LOADS[1]['p_vaddr'] + LOADS[1]['p_filesz']), 'rw-p', _page_floor(LOADS[1]['p_offset'])),
    )
    selected = {}
    for name, start, end, flags, offset in expected:
        matching = [row for row in library if (row['start'], row['end'], row['flags'], row['offset']) ==
                    (start, end, flags, offset)]
        if len(matching) != 1 or (matching[0]['device'], matching[0]['inode']) != (rx['device'], rx['inode']):
            raise GuardError('libObj RX/gap/RW file mapping disagrees with pinned PT_LOAD')
        selected[name] = matching[0]
    bss_lo = bias + _page_ceil(LOADS[1]['p_vaddr'] + LOADS[1]['p_filesz'])
    bss_hi = bias + _page_ceil(LOADS[1]['p_vaddr'] + LOADS[1]['p_memsz'])
    bss = [row for row in rows if row['start'] == bss_lo and row['end'] == bss_hi
           and _eligible(row) and row['path'] == '']
    if len(bss) != 1:
        raise GuardError('Expected exact anonymous libObj BSS tail')
    root_slot = bias + ROOT_VA
    if private_ram(rows, root_slot, 4) != bss[0]:
        raise GuardError('Root slot is not in the pinned libObj BSS tail')
    identity = dict(pid=pid, starttime=starttime, state=fields[0], utime=int(fields[11]),
                    stime=int(fields[12]), threads=int(fields[17]), tracer_pid=0,
                    executable_mapping=exe[0], load_bias=bias, root_slot=root_slot,
                    bss=bss[0], rows=rows, **selected)
    protected = _base_protected(identity) + [private_ram(rows, address, size) for address, size in protected_spans]
    conflicts = _check_order(rows)
    if conflicts:
        intervals = [(row['start'], row['end']) for row in protected]
        if any(_intersects(conflict, interval) for conflict in conflicts for interval in intervals):
            raise GuardError('Mapping overlap touches a protected VMA; retry forbidden')
        raise RetryableMapsError(identity, conflicts)
    return identity


def same_identity(before, after, protected_spans=()):
    keys = ('pid', 'starttime', 'tracer_pid', 'load_bias', 'root_slot',
            'rx', 'gap', 'rw', 'bss', 'executable_mapping')
    if any(before.get(key) != after.get(key) for key in keys):
        raise GuardError('Process identity or protected ELF mapping changed')
    for address, size in protected_spans:
        if private_ram(before['rows'], address, size) != private_ram(after['rows'], address, size):
            raise GuardError('Known object VMA changed between stages')


def build_allowlist(identity):
    rows = identity['rows']
    if _check_order(rows):
        raise GuardError('Allowlist requires a nonoverlapping fresh maps snapshot')
    allowed = []
    for row in rows:
        if _eligible(row) and row != identity['bss']:
            lo, hi = _span(row['start'], row['end'] - row['start'])
            allowed.append((lo, hi))
    if not 1 <= len(allowed) <= MAP_LIMIT:
        raise GuardError('Eligible VMA count outside 1..256; truncation forbidden')
    return allowed


def _validate_allowlist(identity, allowlist):
    if not isinstance(allowlist, (list, tuple)):
        raise GuardError('Expected explicit allowlist sequence')
    normalized = []
    for pair in allowlist:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise GuardError('Malformed allowlist range')
        lo, hi = pair
        _integer(lo); _integer(hi)
        if lo % PAGE or hi % PAGE:
            raise GuardError('Allowlist ranges must preserve actual VMA boundaries')
        normalized.append((lo, hi))
    if normalized != build_allowlist(identity):
        raise GuardError('Allowlist is not the full exact fresh anonymous VMA set')
    return normalized


def validate_anchor(native, identity, allowlist):
    allowed = _validate_allowlist(identity, allowlist)
    if (native.get('mode') not in ('A', 'C') or native.get('complete') is not True
            or native.get('status') != 'completed' or type(native.get('status_code')) is not int
            or native['status_code'] != 0 or len(native.get('events', [])) != 1):
        raise GuardError('Expected one complete native A/C header event')
    event = native['events'][0]
    root = _integer(native.get('root'), 0x10000, USER_END - 1)
    flag = _integer(native.get('flag'), 0, 1)
    if _integer(event.get('root')) != root or _integer(event.get('flag'), 0, 1) != flag:
        raise GuardError('Native header and event root/flag disagree')
    raw = native.get('raw_words')
    if not isinstance(raw, dict):
        raise GuardError('Missing native configuration receipt')
    expected = dict(root_slot=identity['root_slot'], map_count=len(allowed),
                    mode=1 if native['mode'] == 'A' else 3,
                    expected_root=0 if native['mode'] == 'A' else root,
                    expected_flag=0 if native['mode'] == 'A' else flag)
    if any(type(raw.get(key)) is not int or raw[key] != value for key, value in expected.items()):
        raise GuardError('Native configuration receipt differs from exact host identity/pins')
    for key in ('sample_index', 'start_sec', 'start_nsec', 'end_sec', 'end_nsec', 'total_records'):
        _integer(event.get(key))
    if (event['start_nsec'] >= 1000000000 or event['end_nsec'] >= 1000000000
            or (event['end_sec'], event['end_nsec']) < (event['start_sec'], event['start_nsec'])
            or event['total_records'] != 0 or event.get('records') != []):
        raise GuardError('Invalid header-only event timestamps or record payload')
    pools = event.get('pools')
    if not isinstance(pools, list) or len(pools) != 3:
        raise GuardError('Expected exactly three pool slots')
    private_ram(identity['rows'], root, ROOT_BYTES)
    spans = [(root, ROOT_BYTES)]
    object_spans = [('root', _span(root, ROOT_BYTES))]
    protected = [(row['start'], row['end']) for row in _base_protected(identity)]

    def add_object(name, address, size):
        private_ram(identity['rows'], address, size)
        interval = _span(address, size)
        if any(_intersects(interval, bound) for bound in protected):
            raise GuardError('Heap object aliases a protected ELF mapping')
        for old_name, old_span in object_spans:
            if _intersects(interval, old_span):
                raise GuardError('Known object extents alias: ' + old_name + '/' + name)
        object_spans.append((name, interval))
        spans.append((address, size))

    if any(_intersects(object_spans[0][1], bound) for bound in protected):
        raise GuardError('Root aliases protected ELF memory')
    total = 0
    for slot, pool in enumerate(pools):
        if not isinstance(pool, dict) or not set(POOL_FIELDS) <= set(pool):
            raise GuardError('Incomplete pool header')
        for key in POOL_FIELDS:
            _integer(pool[key])
        if pool['address'] == 0:
            if any(pool[key] != 0 for key in POOL_FIELDS):
                raise GuardError('Null pool has nonzero fields')
            continue
        add_object('pool' + str(slot), pool['address'], POOL_BYTES)
        _integer(pool['active'], 0, 1)
        total += pool['count']
        if total > RECORD_LIMIT:
            raise GuardError('Combined list count exceeds eight records')
        head, tail, count = pool['head'], pool['tail'], pool['count']
        if count == 0:
            if head != 0 or tail != 0:
                raise GuardError('Empty list must have null head and tail')
        else:
            if (count == 1) != (head == tail):
                raise GuardError('List count and head/tail equality disagree')
            add_object('head' + str(slot), head, RECORD_BYTES)
            if tail != head:
                add_object('tail' + str(slot), tail, RECORD_BYTES)
    return dict(root=root, flag=flag, pools=copy.deepcopy(pools), known_spans=spans,
                identity=copy.deepcopy(identity), allowlist=allowed, native_result=copy.deepcopy(native))


def watch_parameters(anchor, identity, allowlist):
    validated = validate_anchor(anchor['native_result'], anchor['identity'], anchor['allowlist'])
    if (validated['root'], validated['flag'], validated['known_spans']) != (
            anchor['root'], anchor['flag'], anchor['known_spans']):
        raise GuardError('Accepted A anchor was modified')
    same_identity(validated['identity'], identity, validated['known_spans'])
    current_allowlist = _validate_allowlist(identity, allowlist)
    return dict(pid=identity['pid'], root_slot=identity['root_slot'], allowlist=current_allowlist,
                mode='B', expected_root=validated['root'], expected_flag=validated['flag'])
