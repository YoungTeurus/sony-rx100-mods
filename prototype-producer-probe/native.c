typedef unsigned int u32;
typedef signed int s32;

#include "../prototype-ring/src/pre_capture.h"

#ifndef M7_RAM_CONTINUOUS
#define M7_RAM_CONTINUOUS 0
#endif
#ifndef M7_RAM_LATE_REGISTER
#define M7_RAM_LATE_REGISTER 0
#endif

#ifndef M7_RAM_COMMIT
#define M7_RAM_COMMIT 0
#endif

#define MAX_RANGES 512
#define MAX_EVENTS 384
#define ROUTE_WAIT_MS 20000

struct range { u32 start, end; };
struct config {
    u32 magic, version, token, pid, bias, nranges, interval_ms, focus_ms, settle_ms, diagnose_only;
    u32 retain_check, monitor_tid, mpr_bias, mprctrl_bias, mwf_bias;
    struct range ranges[MAX_RANGES];
};
const volatile struct config m7_config = { .magic = 0x3143504d, .version = 6 };

void __aeabi_memclr8(void *address, u32 size) {
    volatile unsigned char *p = address;
    while (size--) *p++ = 0;
}
void __aeabi_memclr(void *address, u32 size) __attribute__((alias("__aeabi_memclr8")));
void __aeabi_memclr4(void *address, u32 size) __attribute__((alias("__aeabi_memclr8")));

void __aeabi_memcpy8(void *destination, const void *source, u32 size) {
    volatile unsigned char *out=destination;
    const volatile unsigned char *in=source;
    while (size--) *out++=*in++;
}

struct held_image { u32 address, length, width, height, digest[8], valid, copies; };
struct ring_owner {
    u32 candidate[8], owned, released;
    struct held_image before;
};

struct observer {
#if M7_RAM_LATE_REGISTER
    u32 (*late_events)[12],late_count,late_overflow;
#endif
#if M7_RAM_CONTINUOUS
    void (*shutter_abort)(struct observer *);
    void *shutter_state;
#endif
#ifdef M7_SAMPLE_OVERRIDE
    void *extension;
#endif
    s32 fd;
    u32 trace_tid, owner_pthread_bias, caller_kind;
    u32 phase, started, reads, read_errors, events, dropped, io_errors;
    u32 snapshots[3][32][8], initialized[3][32];
    u32 pool_snapshots[3][6], pool_initialized[3], truncated;
    struct range added[16];
    u32 nadded, map_attempts;
    u32 route[16];
    u32 baseline[96][2], baseline_count, retain_window, retain_attempted, retain_ok;
    u32 held_candidate[8], held_owned;
    u32 end_register_attempted, end_register_ok;
    struct held_image jpeg_before, jpeg_after;
    u32 commit_drive, commit_status, commit_written, commit_read, commit_reads, commit_digest[8];
    u32 commit_allowed, b_observed;
    u32 commit_sequence;
    pc_ring ring;
    pc_frame ring_slots[2];
    struct ring_owner owners[3];
    u32 pending_capture, pending_write, pending_stop, write_slot, ring_captured;
#if M7_RAM_PROBE
    u32 (*probe_events)[12],probe_count,probe_capacity;
#endif
};

static s32 call(u32 n, u32 a, u32 b, u32 c, u32 d, u32 e, u32 f) {
    register u32 r0 __asm__("r0") = a;
    register u32 r1 __asm__("r1") = b;
    register u32 r2 __asm__("r2") = c;
    register u32 r3 __asm__("r3") = d;
    register u32 r4 __asm__("r4") = e;
    register u32 r5 __asm__("r5") = f;
    register u32 r7 __asm__("r7") = n;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3),
                     "r"(r4), "r"(r5), "r"(r7) : "memory", "cc");
    return (s32)r0;
}

static u32 now(void) {
    u32 ts[2];
    if (call(263, 1, (u32)ts, 0, 0, 0, 0) != 0) return 0;
    return ts[0] * 1000 + ts[1] / 1000000;
}

static void sleep_ms(u32 milliseconds) {
    u32 ts[2] = { milliseconds / 1000, (milliseconds % 1000) * 1000000 };
    call(162, (u32)ts, 0, 0, 0, 0, 0);
}

static void emit_fields(struct observer *o,const u32 *fields) {
    char line[105];
    const char prefix[] = "M7CAP1=";
    const char digits[] = "0123456789abcdef";
    u32 i, j, used = 0;
    for (i = 0; i < 7; ++i) line[used++] = prefix[i];
    for (i = 0; i < 12; ++i)
        for (j = 0; j < 8; ++j) line[used++] = digits[(fields[i] >> (28 - j * 4)) & 15];
    line[used++] = '\n';
    u32 sent = 0, tries = 0;
    while (sent < used && tries++ < used + 4) {
        s32 rc = call(4, 1, (u32)(line + sent), used - sent, 0, 0, 0);
        if (rc == -4) continue;
        if (rc <= 0 || (u32)rc > used - sent) { o->io_errors++; return; }
        sent += (u32)rc;
    }
    if (sent != used) o->io_errors++;
    if (fields[1] == 2 || fields[1] == 3) o->events++;
}

#if M7_RAM_LATE_REGISTER
#define RAM_LATE_EVENTS 128
static void late_flush(struct observer *o) {
    u32 (*events)[12]=o->late_events,count=o->late_count;
    o->late_events=0;o->late_count=0;
    for (u32 i=0;events && i<count;++i) emit_fields(o,events[i]);
}
#endif

#if M7_RAM_PROBE
static void probe_flush(struct observer *o) {
    u32 (*events)[12]=o->probe_events,count=o->probe_count;
    o->probe_events=0;o->probe_count=0;
    for (u32 i=0;events && i<count;++i) emit_fields(o,events[i]);
}
#endif

static void emit(struct observer *o, u32 kind, const u32 *data) {
    u32 fields[12] = {m7_config.token, kind, o->phase, now() - o->started};
    for (u32 i=0;i<8;++i) fields[4+i]=data?data[i]:0;
    if ((kind==2 || kind==3) && o->events>=MAX_EVENTS) { o->dropped++;return; }
#if M7_RAM_LATE_REGISTER
    /* Main can stop outside its idle wait; defer pipe writes until it resumes. */
    if (o->late_events) {
        if (o->late_count<RAM_LATE_EVENTS) {
            for (u32 i=0;i<12;++i) o->late_events[o->late_count][i]=fields[i];
            ++o->late_count;
        } else ++o->late_overflow;
        return;
    }
#endif
#if M7_RAM_PROBE
    /* Keep diagnostic pipe backpressure outside the stopped recorder's lifetime. */
    if (o->probe_events) {
        if (o->probe_count<o->probe_capacity) {
            for (u32 i=0;i<12;++i) o->probe_events[o->probe_count][i]=fields[i];
            ++o->probe_count;
        } else ++o->dropped;
        return;
    }
#endif
    emit_fields(o,fields);
}

static void proc_path(char *path, int maps) {
    const char prefix[] = "/proc/";
    char digits[10];
    u32 value = m7_config.pid, length = 0, at = 6;
    for (u32 i = 0; i < 6; ++i) path[i] = prefix[i];
    do { digits[length++] = '0' + value % 10; value /= 10; } while (value);
    while (length) path[at++] = digits[--length];
    path[at++]='/'; path[at++]='m'; path[at++]=maps ? 'a' : 'e';
    path[at++]=maps ? 'p' : 'm';
    if (maps) path[at++]='s';
    path[at]=0;
}

static u32 parse_hex(const char **cursor) {
    u32 value = 0;
    const char *p = *cursor;
    while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')) {
        value = value * 16 + (*p <= '9' ? *p-'0' : *p-'a'+10);
        ++p;
    }
    *cursor = p;
    return value;
}

static int matching_map(const char *line, u32 address, u32 size, struct range *found) {
    const char *p = line;
    u32 start = parse_hex(&p);
    if (*p++ != '-') return 0;
    u32 end = parse_hex(&p);
    if (*p++ != ' ' || p[0]!='r' || p[1]!='w' || p[2]!='-' || p[3]!='p' || p[4]!=' ') return 0;
    p += 5;
    if (parse_hex(&p) != 0 || *p++ != ' ') return 0;
    if (parse_hex(&p) != 0 || *p++ != ':' || parse_hex(&p) != 0 || *p++ != ' ') return 0;
    while (*p == ' ') ++p;
    if (*p++ != '0' || (*p != ' ' && *p != 0)) return 0;
    while (*p == ' ') ++p;
    if (*p) {
        const char expected[] = "[heap]";
        for (u32 i = 0; i < sizeof(expected); ++i) if (p[i] != expected[i]) return 0;
    }
    if ((start & 4095) || (end & 4095) || start < 0x10000 || end > 0xc0000000 ||
        address < start || address + size > end) return 0;
    found->start = start; found->end = end;
    return 1;
}

static int newly_allocated_range(struct observer *o, u32 address, u32 size) {
    if (o->nadded == 16 || o->map_attempts++ >= 16) return 0;
    char path[32], buffer[512], line[192];
    proc_path(path, 1);
    s32 fd = call(5, (u32)path, 0, 0, 0, 0, 0);
    if (fd < 0) return 0;
    u32 used = 0, skipped = 0, total = 0, found = 0;
    while (total < 256 * 1024 && !found) {
        s32 n = call(3, (u32)fd, (u32)buffer, sizeof(buffer), 0, 0, 0);
        if (n <= 0 || n > (s32)sizeof(buffer)) break;
        total += (u32)n;
        for (s32 i = 0; i < n; ++i) {
            char ch = buffer[i];
            if (ch == '\n') {
                line[used] = 0;
                if (!skipped && matching_map(line, address, size, &o->added[o->nadded])) {
                    o->nadded++;
                    found = 1;
                    break;
                }
                used = skipped = 0;
            } else if (used + 1 < sizeof(line)) line[used++] = ch;
            else skipped = 1;
        }
    }
    call(6, (u32)fd, 0, 0, 0, 0, 0);
    return found;
}

static int private_range(struct observer *o, u32 address, u32 size) {
    if ((address & 3) || address < 0x10000 || size > 0xc0000000 - address) return 0;
    for (u32 i = 0; i < m7_config.nranges; ++i)
        if (address >= m7_config.ranges[i].start && address + size <= m7_config.ranges[i].end)
            return 1;
    for (u32 i = 0; i < o->nadded; ++i)
        if (address >= o->added[i].start && address + size <= o->added[i].end) return 1;
    if (newly_allocated_range(o, address, size)) return 1;
    o->read_errors++;
    return 0;
}

static int read_mem(struct observer *o, u32 address, u32 *out, u32 size) {
    int slot = (size == 4 && (address == m7_config.bias + 0x1463800 ||
        address == m7_config.bias + 0x145d230 || address == m7_config.bias + 0x1463130)) ||
        (m7_config.retain_check >= 6 && size == 20 && address == m7_config.bias + 0x145d884) ||
        ((m7_config.retain_check == 7 || m7_config.retain_check >= 10) && size == 4 && address == m7_config.mwf_bias + 0x46a60) ||
        ((m7_config.retain_check == 9 || m7_config.retain_check >= 10) && size == 108 && !(address&3) &&
         address>=m7_config.mwf_bias+0x4548c && address<=m7_config.mwf_bias+0x4548c+49*108) ||
        (m7_config.retain_check >= 10 && size == 4 && !(address&3) &&
         address>=m7_config.mwf_bias+0x4548c && address<m7_config.mwf_bias+0x4548c+50*108 &&
         (address-m7_config.mwf_bias-0x4548c)%108>=0x44);
    if ((m7_config.retain_check==11 || m7_config.retain_check==12 || m7_config.retain_check==14) && ((size==4 && (address==m7_config.bias+0x145d5a4 ||
        address==m7_config.bias+0x145d57c || address==m7_config.bias+0x145d528)) ||
        (size==16 && address==m7_config.bias+0x145d5c4))) slot=1;
    if (!slot && !private_range(o, address, size)) return 0;
    o->reads++;
    s32 rc = call(180, (u32)o->fd, (u32)out, size, 0, address, 0);
    if (rc != (s32)size) { o->read_errors++; return 0; }
    return 1;
}

static int subscription(struct observer *o, int released_only, int report) {
    u32 input = 0, spinal = 0, g[24] = {0}, cam = 0, failed = 0, valid = 0;
    if (read_mem(o, m7_config.bias + 0x145d230, &input, 4)) valid |= 1;
    else failed |= 1;
    if (read_mem(o, m7_config.bias + 0x1463130, &spinal, 4)) valid |= 2;
    else failed |= 2;
    if (failed) goto done;
    if (!private_range(o, input, 0x224)) failed |= 4;
    if (!private_range(o, spinal, 0x7c)) failed |= 8;
    if (failed) goto done;
    if (!read_mem(o, spinal, g, sizeof(g))) { failed |= 16; goto done; }
    valid |= 4;
    if (g[0] != input) failed |= 32;
    if (!private_range(o, g[1], 0x240)) failed |= 64;
    if (failed) goto done;
    if (!read_mem(o, g[1], &cam, 4)) { failed |= 128; goto done; }
    valid |= 8;
    if (cam != m7_config.bias + 0x1390490) failed |= 256;
    if ((s32)g[22] <= 0) failed |= 512;
    if ((g[23] & 255) != 1) failed |= 1024;
    if (released_only && g[20] != 0 && g[20] != 0x7fffffff) failed |= 2048;
    if (released_only && g[21] != 0 && g[21] != 0x7fffffff) failed |= 4096;
done:;
    u32 route[8] = {failed, input, spinal, g[1], cam, g[22], valid, g[23] & 255};
    u32 keys[8] = {g[0], g[20], g[21], m7_config.bias + 0x1390490};
    for (u32 i = 0; i < 8; ++i) { o->route[i] = route[i]; o->route[i+8] = keys[i]; }
    if (report) { emit(o, 6, route); emit(o, 7, keys); }
    return failed == 0;
}

static int inactive_route(const struct observer *o) {
    return o->route[6] == 15 && o->route[7] == 0 && o->route[5] < 0x80000000 &&
        (o->route[0] == 1024 || o->route[0] == 1536);
}

static int wait_for_subscription(struct observer *o) {
    u32 progress[8] = {1, ROUTE_WAIT_MS, o->route[0]}, previous[16], stable = 0;
    emit(o, 4, progress);
    u32 start = now();
    int ready = 0;
    for (u32 attempt = 0; attempt < ROUTE_WAIT_MS / 100; ++attempt) {
        if (o->io_errors) break;
        sleep_ms(100);
        ready = subscription(o, 1, 0);
        if (ready) {
            u32 same = stable != 0;
            for (u32 i = 0; i < 16; ++i) if (stable && previous[i] != o->route[i]) same = 0;
            stable = same ? stable + 1 : 1;
            for (u32 i = 0; i < 16; ++i) previous[i] = o->route[i];
            if (stable >= 6) break;
        } else {
            stable = 0;
            if (!inactive_route(o)) break;
        }
        if (now() - start >= ROUTE_WAIT_MS) break;
    }
    emit(o, 6, o->route);
    emit(o, 7, o->route + 8);
    ready = ready && stable >= 6 && !o->io_errors;
    progress[0] = ready ? 2 : inactive_route(o) || stable ? 3 : 4;
    progress[2] = o->route[0]; progress[3] = now() - start; progress[4] = stable;
    emit(o, 4, progress);
    return ready && !o->io_errors;
}

#include "retain.c"
#include "hold.c"
#include "media.c"
#include "media_route.c"
#include "media_create.c"
#include "end_register.c"
#include "receiver.c"
#include "capture_trap.c"
static int sender(struct observer *, u32, u32);
static int release_buttons(struct observer *);
static void observe(struct observer *, u32);
#include "media_connect.c"

static void sample(struct observer *o) {
#ifdef M7_SAMPLE_OVERRIDE
    M7_SAMPLE_OVERRIDE(o);
#else
    u32 root, pools[3];
    if (!read_mem(o, m7_config.bias + 0x1463800, &root, 4) || !root) return;
    if (!private_range(o, root, 0x68) || !read_mem(o, root, pools, sizeof(pools))) return;
    for (u32 index = 0; index < 3; ++index) {
        u32 pool = pools[index], media, list[3];
        if (!pool) continue;
        if (!private_range(o, pool, 0x70d0) || !read_mem(o, pool + 8, &media, 4) ||
            !read_mem(o, pool + 0x70c4, list, sizeof(list))) continue;
        u32 pool_data[8] = {index, pool, media, list[0], list[1], list[2], 0, 0};
        u32 pool_changed = !o->pool_initialized[index];
        for (u32 j = 0; j < 6; ++j)
            if (o->pool_snapshots[index][j] != pool_data[j]) pool_changed = 1;
        if (pool_changed) {
            emit(o, 2, pool_data);
            for (u32 j = 0; j < 6; ++j) o->pool_snapshots[index][j] = pool_data[j];
            o->pool_initialized[index] = 1;
        }
        u32 record = list[0], seen[32], n = 0;
        while (record && n < 32) {
            u32 prefix[5], tail[3], verify[5], duplicate = 0;
            for (u32 j = 0; j < n; ++j) if (seen[j] == record) duplicate = 1;
            if (duplicate) break;
            seen[n++] = record;
            if (!private_range(o, record, 0x174) || !read_mem(o, record, prefix, sizeof(prefix)) ||
                !read_mem(o, record + 0x168, tail, sizeof(tail)) ||
                !read_mem(o, record, verify, sizeof(verify))) break;
            if (prefix[1] != verify[1] || prefix[3] != verify[3] || prefix[4] != verify[4]) {
                o->read_errors++;
                break;
            }
            u32 data[8] = {index, pool, media, record, prefix[3], prefix[4], tail[0], tail[2]};
            u32 known = 0;
            for (u32 j = 0; j < o->baseline_count; ++j)
                if (o->baseline[j][0] == media && o->baseline[j][1] == prefix[3]) known = 1;
            if ((o->phase < 5 || (m7_config.retain_check >= 3 && o->phase == 6) ||
                 (m7_config.retain_check == 4 && o->phase == 10)) &&
                !known && o->baseline_count < 96) {
                o->baseline[o->baseline_count][0] = media;
                o->baseline[o->baseline_count++][1] = prefix[3];
            }
            u32 changed = !o->initialized[index][n-1];
            for (u32 j = 0; j < 8; ++j) if (o->snapshots[index][n-1][j] != data[j]) changed = 1;
            if (changed) {
                emit(o, 3, data);
                for (u32 j = 0; j < 8; ++j) o->snapshots[index][n-1][j] = data[j];
                o->initialized[index][n-1] = 1;
            }
            if (m7_config.retain_check == 3 && o->phase == 7 && !known &&
                pool == o->held_candidate[1] && prefix[3] != o->held_candidate[4] &&
                (tail[0]&0xffff) == 1) o->b_observed=1;
            if (m7_config.retain_check && o->retain_window && !o->retain_attempted && !known &&
                (tail[0] & 0xffff) == 1 && tail[2] > 0 && tail[2] < 0x7fffffff) {
                o->retain_attempted = 1;
                o->retain_ok = m7_config.retain_check >= 2 ? hold_acquire(o, data) : retain_roundtrip(o, data);
                if (m7_config.retain_check == 8 && o->held_owned) {
                    o->end_register_attempted = 1;
                    o->end_register_ok = end_register_run(o);
                    /* EndRegister can remove other records from the traversed list. */
                    return;
                }
            }
            record = prefix[1];
        }
        if (record) o->truncated++;
    }
#endif
}

static void observe(struct observer *o, u32 duration) {
    u32 start = now(), loops = 0;
    do {
        sample(o);
        sleep_ms(m7_config.interval_ms);
    } while (now() - start < duration && ++loops < duration + 2);
}

void child_exec(u32 key, u32 pressed) {
    const char *path = "/usr/bin/sndcmd.elf";
    const char *argv[] = {path, "--sync", "0x007a018c", "d:2",
        key == 1 ? "d:0x1a00000d" : "d:0x1a00000e", "d:0",
        pressed ? "d:1" : "d:0", "d:0", 0};
    const char *env[] = {0};
    s32 fd = call(5, (u32)"/dev/null", 2, 0, 0, 0, 0);
    if (fd < 0) { call(1, 126, 0, 0, 0, 0, 0); return; }
    for (u32 i = 0; i < 3; ++i)
        if (call(63, (u32)fd, i, 0, 0, 0, 0) < 0) { call(1, 126, 0, 0, 0, 0, 0); return; }
    if (fd > 2) call(6, (u32)fd, 0, 0, 0, 0, 0);
    call(11, (u32)path, (u32)argv, (u32)env, 0, 0, 0);
    call(1, 127, 0, 0, 0, 0, 0);
}

static int sender(struct observer *o, u32 key, u32 pressed) {
    s32 pid = call(2, 0, 0, 0, 0, 0, 0);
    if (pid == 0) { child_exec(key, pressed); return 0; }
    u32 status = 0xffffffff, elapsed = 0, killed = 0, reaped = 0;
    if (pid > 0) {
        while (elapsed < 1800) {
            s32 rc = call(114, (u32)pid, (u32)&status, 1, 0, 0, 0);
            if (rc == pid) { reaped = 1; break; }
            if (rc < 0 && rc != -4) break;
            sample(o);
            sleep_ms(5);
            elapsed += 5;
            if (elapsed == 1500) { call(37, (u32)pid, 9, 0, 0, 0, 0); killed = 1; }
        }
    }
    u32 data[8] = {key, pressed, (u32)pid, status, killed, reaped, elapsed, 0};
    emit(o, 5, data);
    return pid > 0 && reaped && !killed && status == 0;
}

static int release_buttons(struct observer *o) {
    int s2 = sender(o, 2, 0);
    int s1 = sender(o, 1, 0);
    return s2 && s1;
}

static int wake_for_subscription(struct observer *o) {
    u32 progress[8] = {5, 200, 2000};
    emit(o, 4, progress);
    int pressed = sender(o, 1, 1);
    if (pressed) sleep_ms(200);
    int released = sender(o, 1, 0);
    if (!pressed || !released) {
        progress[0] = 6;
        progress[1] = pressed;
        progress[2] = released;
        emit(o, 4, progress);
        return 0;
    }
    sleep_ms(2000);
    return wait_for_subscription(o);
}

static void phase(struct observer *o, u32 number) {
    o->phase = number;
    for (u32 i = 0; i < 3; ++i) o->pool_initialized[i] = 0;
    emit(o, 1, 0);
}

static int capture(struct observer *o, u32 number) {
    phase(o, number);
    int ok = sender(o, 1, 1);
    if (ok) observe(o, m7_config.focus_ms);
    if (ok) {
        phase(o, number + 1);
        ok = sender(o, 2, 1);
        if (ok) observe(o, 80);
    }
    int released = release_buttons(o);
    o->retain_window = (number == 4 || m7_config.retain_check == 4) && ok && released;
    observe(o, m7_config.settle_ms);
    o->retain_window = 0;
    return ok && released;
}

#include "ring.c"
#include "ram_capture.c"

int probe_main(void) {
    struct observer o = {0};
    if (m7_config.magic != 0x3143504d || m7_config.version != 6 || !m7_config.token ||
        !m7_config.pid || m7_config.pid > 0x7fffffff ||
        m7_config.bias < 0x10000 || m7_config.bias > 0xbe000000 || (m7_config.bias & 4095) ||
        !m7_config.nranges || m7_config.nranges > MAX_RANGES ||
        !m7_config.interval_ms || m7_config.interval_ms > 20 ||
        m7_config.focus_ms < 100 || m7_config.focus_ms > 1500 ||
        m7_config.settle_ms < 100 || m7_config.settle_ms > 3000 ||
        m7_config.diagnose_only > 1 || m7_config.retain_check > 12 ||
        (m7_config.retain_check == 3 || m7_config.retain_check == 4 ? (m7_config.mpr_bias < 0x10000 || m7_config.mpr_bias > 0xbe000000 ||
         (m7_config.mpr_bias & 4095)) : m7_config.mpr_bias != 0) ||
        (m7_config.retain_check == 5 || m7_config.retain_check == 7 || m7_config.retain_check >= 10 ? (m7_config.mprctrl_bias < 0x10000 || m7_config.mprctrl_bias > 0xbe000000 ||
         (m7_config.mprctrl_bias & 4095)) : m7_config.mprctrl_bias != 0) ||
        (m7_config.retain_check >= 7 ? (m7_config.mwf_bias < 0x10000 || m7_config.mwf_bias > 0xbe000000 ||
         (m7_config.mwf_bias & 4095)) : m7_config.mwf_bias != 0) ||
        (m7_config.retain_check && m7_config.diagnose_only) ||
        (((m7_config.retain_check > 0 && m7_config.retain_check < 6) || m7_config.retain_check == 8) && (!m7_config.monitor_tid ||
         m7_config.monitor_tid > 0x7fffffff || m7_config.monitor_tid == m7_config.pid)) ||
        ((m7_config.retain_check == 7 || m7_config.retain_check == 10 || m7_config.retain_check == 12) && (m7_config.monitor_tid>0x7fffffff || m7_config.monitor_tid==m7_config.pid)) ||
        (m7_config.retain_check == 11 && (!m7_config.monitor_tid || m7_config.monitor_tid>0x7fffffff || m7_config.monitor_tid==m7_config.pid)) ||
        ((!m7_config.retain_check || m7_config.retain_check == 6 || m7_config.retain_check == 9) && m7_config.monitor_tid)) return 2;
    for (u32 i = 0; i < m7_config.nranges; ++i)
        if (m7_config.ranges[i].start < 0x10000 || m7_config.ranges[i].end > 0xc0000000 ||
            m7_config.ranges[i].start >= m7_config.ranges[i].end) return 2;
    u32 action[5] = {1, 0, 0, 0, 0};
    if (call(174, 13, (u32)action, 0, 8, 0, 0) != 0 ||
        call(174, 1, (u32)action, 0, 8, 0, 0) != 0) return 3;
    call(66, 0, 0, 0, 0, 0, 0);
    o.started = now();
    if (!o.started) return 4;
    char path[32];
    proc_path(path, 0);
    o.fd = call(5, (u32)path, 0, 0, 0, 0, 0);
    if (o.fd < 0) return 5;
    o.trace_tid=m7_config.monitor_tid;
    o.caller_kind=(m7_config.retain_check==7 || m7_config.retain_check>=10) ? 1 : 0;
    if (((m7_config.retain_check==7 || m7_config.retain_check>=10) && !create_discover_tid(&o)) ||
        (m7_config.retain_check && !(m7_config.retain_check == 6 ?
        check_media_pins(&o,route_code_pins,sizeof(route_code_pins)/sizeof(route_code_pins[0]),m7_config.bias,20) :
        m7_config.retain_check == 9 ?
        (check_media_pins(&o,receiver_code_pins,sizeof(receiver_code_pins)/sizeof(receiver_code_pins[0]),m7_config.bias,34) &&
         check_media_pins(&o,receiver_mwf_code_pins,sizeof(receiver_mwf_code_pins)/sizeof(receiver_mwf_code_pins[0]),m7_config.mwf_bias,36)) :
        retain_preflight(&o)))) {
        u32 failure[8] = {8, o.reads, o.read_errors};
        emit(&o, 9, failure);
        call(6, (u32)o.fd, 0, 0, 0, 0, 0);
        return 8;
    }
    int ready = subscription(&o, 1, 1);
    if (!ready && !m7_config.diagnose_only && inactive_route(&o)) ready = wake_for_subscription(&o);
    if (!ready || m7_config.diagnose_only) {
        u32 final[8] = {ready ? 0 : 6, o.reads, o.read_errors, 0, 0, o.io_errors, ready, 0};
        emit(&o, 9, final);
        call(6, (u32)o.fd, 0, 0, 0, 0, 0);
        return o.io_errors ? 7 : final[0];
    }
    int ok;
    if (m7_config.retain_check >= 10) {
        phase(&o,18);
        ok=media_connect_run(&o);
        goto finished;
    }
    if (m7_config.retain_check == 9) {
        phase(&o,17);
        ok=receiver_run(&o);
        goto finished;
    }
    if (m7_config.retain_check == 7) {
        phase(&o,15);
        ok = media_create_run(&o);
        goto finished;
    }
    if (m7_config.retain_check == 6) {
        phase(&o,14);
        ok = media_route_run(&o);
        goto finished;
    }
    if (m7_config.retain_check == 5) {
        phase(&o, 13);
        ok = media_run(&o);
        goto finished;
    }
    phase(&o, 1);
    observe(&o, 250);
    phase(&o, 2);
    ok = sender(&o, 1, 1);
    if (ok) observe(&o, m7_config.focus_ms);
    int released = release_buttons(&o);
    ok = ok && released;
    phase(&o, 3);
    observe(&o, 250);
    if (m7_config.retain_check == 4) {
        ok = ring_run(&o,ok);
        goto finished;
    }
    if (ok) ok = capture(&o, 4);
    if (m7_config.retain_check == 8 && !o.end_register_attempted) {
        o.end_register_attempted=1;
        o.end_register_ok=end_register_run(&o);
    }
    if (o.held_owned) hold_measure(&o);
    if (ok) ok = capture(&o, 6);
    o.commit_allowed = ok && o.b_observed;
    phase(&o, 8);
    if (o.held_owned) o.retain_ok = hold_finish(&o);
    if (m7_config.retain_check == 8) ok=ok && o.end_register_ok;
    if (m7_config.retain_check == 3) {
        if (o.commit_status == 1 && o.retain_ok && !o.held_owned) commit_verify(&o);
        commit_result(&o);
    }
finished:;
    int keys_clear = subscription(&o, 1, 1);
    if ((m7_config.retain_check && m7_config.retain_check < 5) || m7_config.retain_check == 8) {
        u32 retain[8] = {o.retain_attempted, o.retain_ok,
            m7_config.retain_check == 8 ? 2 : m7_config.retain_check >= 2 ? m7_config.retain_check : 0, o.held_owned,
            o.jpeg_before.valid, o.jpeg_after.valid};
        emit(&o, 14, retain);
    }
    u32 final[8] = {ok && keys_clear && !o.io_errors ? 0 : 7,
        o.reads, o.read_errors, o.events, o.dropped, o.io_errors, keys_clear, o.truncated};
    emit(&o, 9, final);
    call(6, (u32)o.fd, 0, 0, 0, 0, 0);
    return final[0] || o.io_errors ? 7 : 0;
}

__asm__(".arm\n.global _start\n.type _start,%function\n_start:\n"
        "bl probe_main\nmov r7,#1\nsvc 0\nb .\n.size _start,.-_start\n");
