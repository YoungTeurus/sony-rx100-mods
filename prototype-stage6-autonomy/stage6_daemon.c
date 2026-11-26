/*
 * Stage 6 WIP v2: Autonomous untethered RAM Pre-Capture supervisor daemon.
 *
 * Safety & architectural invariants:
 * - ZERO ptrace syscalls in daemon.elf (syscall 26 is never invoked).
 * - ZERO writable globals (single PF_R|PF_X PT_LOAD segment; state lives in mmap2).
 * - Passive zero-interference idle loop whenever Release w/o Card != Enable (0x0),
 *   Drive Mode != Continuous (0x5f/0x5bc), Format != JPEG L 20M 3:2, sub_en != 1,
 *   or shutter half-press is not held past debounce_ms.
 * - All /dev/uipc Backup_read(0x01071472) ioctls run in an isolated uipc_worker child
 *   (non-blocking valloc wait=0, two-sentinel guard, fail-closed FREE_MSG latch,
 *   1000 ms pre+post-read deadline, paused during active ring.elf capture, bounded
 *   <= 200 ms teardown).
 * - Spawns ONLY the sealed immutable ring.elf inside its own private nonce directory
 *   (/tmp_network/.m7-s6-<nonce>/ring.elf) after writing atomic run.cfg + verifying
 *   stop_file is absent.
 * - Drains ring.elf stdout pipe non-blockingly and logs compact milestones into
 *   bounded daemon.log (<= max_log_bytes, reserving STOP_RESERVE_BYTES for STOP).
 * - Never SIGKILLs a live ring.elf (which may hold a 0xde01 trap in im.elf); requests
 *   clean cancel via per-nonce disarm/stop files and waits up to RING_STOP_WAIT_MS.
 * - Latches ring_fault=1 fail-closed on any nonzero ring.elf exit or retain_unresolved
 *   (kind=13 stage=98) so a fault never retries in a loop.
 */
#include "stage6_v2_common.h"

typedef unsigned int u32;
typedef signed int s32;
typedef unsigned short u16;
typedef unsigned char u8;

#define MAX_RANGES            S6_MAX_RANGES
#define SD_INPUT_LIMIT        1024u
#define STOP_RESERVE_BYTES    384u
#define UIPC_REPLY_TIMEOUT_MS 1000u
#define RING_STOP_WAIT_MS     35000u
#define RING_STOP_HARD_MAX_MS 240000u
#define RING_MIN_REMAIN_MS    20000u
#define RING_COOLDOWN_MS      500u

/* ARM EABI Linux syscall numbers (verified in M7 1.00 sys_call_table @ 0x6010e084) */
#define SYS_EXIT             1u
#define SYS_FORK             2u
#define SYS_READ             3u
#define SYS_WRITE            4u
#define SYS_OPEN             5u
#define SYS_CLOSE            6u
#define SYS_UNLINK           10u
#define SYS_EXECVE           11u
#define SYS_CHDIR            12u
#define SYS_GETPID           20u
#define SYS_KILL             37u
#define SYS_RENAME           38u
#define SYS_PIPE             42u
#define SYS_IOCTL            54u
#define SYS_FCNTL            55u
#define SYS_DUP2             63u
#define SYS_SETSID           66u
#define SYS_READLINK         85u
#define SYS_MUNMAP           91u
#define SYS_WAIT4            114u
#define SYS_RT_SIGACTION     174u
#define SYS_RT_SIGPROCMASK   175u
#define SYS_RT_SIGTIMEDWAIT  177u
#define SYS_PREAD64          180u
#define SYS_MMAP2            192u
#define SYS_GETDENTS64       217u
#define SYS_CLOCK_GETTIME    263u

/* Open / fcntl / wait flags (ARM EABI Linux) */
#define O_RDONLY   0u
#define O_WRONLY   1u
#define O_RDWR     2u
#define O_CREAT    0x40u
#define O_EXCL     0x80u
#define O_TRUNC    0x200u
#define O_NONBLOCK 0x800u
#define F_SETFL    4u
#define WNOHANG    1u

/* M7 1.00 libObj.so / libMWF.so verified offsets */
#define LIBOBJ_BSS_START        0x1425000u
#define LIBOBJ_BSS_END          0x1464000u
#define LIBOBJ_INPUT_SLOT       0x145d230u
#define LIBOBJ_SPINAL_SLOT      0x1463130u
#define LIBOBJ_INPUT_VPTR       0x1387af0u
#define LIBOBJ_CAMERA_VPTR      0x1390490u
#define LIBOBJ_CAMSETPARAMS_PTR 0x145f3e8u
#define LIBOBJ_CAMSETPARAMS_GRD 0x145f3ecu
#define LIBOBJ_CAMSETPARAMS_OBJ 0x145f3f0u

#define SLOT_DRIVE_MODE_ACT     0x145f4f4u /* 0x9541 */
#define SLOT_BURST_SPEED_ACT    0x145f4fcu /* 0x9543 */
#define SLOT_BOL_BURST_SPD_ACT  0x1460cd4u /* 0x9b39 */
#define SLOT_STILL_SIZE_ACT     0x145f5f0u /* 0x9580 */
#define SLOT_STILL_ASPECT_ACT   0x145f5f4u /* 0x9581 */
#define SLOT_JPEG_QUALITY_ACT   0x145f5f8u /* 0x9582 */
#define SLOT_STILL_FORMAT_ACT   0x145f5fcu /* 0x9583 */

#define LIBMWF_PARAM_INT7_FTBL  0x42cecu
#define LIBMWF_MONITOR_FLAG     0x45478u
#define LIBMWF_MONITOR_PTR      0x4547cu
#define LIBMWF_MONITOR_VPTR     0x43088u

/* /dev/uipc Backup service constants (verified in M7 1.00 libosal_uipc.so + osal_uipc.ko) */
#define UIPC_IOCTL_INIT         0x80000010u
#define UIPC_IOCTL_SND_SYNC     0x80000005u
#define UIPC_IOCTL_VALLOC_WAIT  0x8000000au
#define UIPC_IOCTL_FREE_MSG     0x8000000bu
#define UIPC_BACKUP_QID         0x003e014du
#define UIPC_BACKUP_MSG_SIZE    0x40u
#define UIPC_EAGAIN_RETRY       (-1021)

struct s6_daemon_config {
    u32 magic;
    u32 version;
    u32 duration_ms;
    u32 poll_ms;
    u32 heartbeat_ms;
    u32 max_log_bytes;
    u32 daemonize;
    u32 toggle_bkid;
    u32 toggle_on_val; /* 0 = Enable (ВКЛ) confirmed by user 2026-11-21 */
    u32 before;
    u32 after;
    u32 backlog_cap;
    u32 debounce_ms;
    u32 focus_ms;
    u32 burst_cap;
    u32 post_max;
    char nonce[S6_NONCE_LEN];
};

const volatile struct s6_daemon_config m7_s6_daemon_config = {
    .magic = S6_DAEMON_MAGIC,
    .version = S6_DAEMON_VERSION,
    .duration_ms = 600000u,
    .poll_ms = 50u,
    .heartbeat_ms = 2000u,
    .max_log_bytes = 131072u,
    .daemonize = 1u,
    .toggle_bkid = 0x01071472u, /* Release w/o Card */
    .toggle_on_val = 0u,        /* ВКЛ = Pre-Capture ON, ВЫКЛ (1) = OFF */
    .before = 5u,
    .after = 0u,                /* 0 = hold-driven post while physical full-press held */
    .backlog_cap = 96u,
    .debounce_ms = 100u,
    .focus_ms = 300u,
    .burst_cap = 24u,
    .post_max = 48u,
    .nonce = {'0','0','0','0','0','0','0','0','0','0','0','0'},
};

void __aeabi_memclr8(void *address, u32 size) {
    volatile u8 *p = (volatile u8 *)address;
    while (size--) *p++ = 0;
}
void __aeabi_memclr(void *address, u32 size) __attribute__((alias("__aeabi_memclr8")));
void __aeabi_memclr4(void *address, u32 size) __attribute__((alias("__aeabi_memclr8")));

void __aeabi_memcpy8(void *destination, const void *source, u32 size) {
    volatile u8 *out = (volatile u8 *)destination;
    const volatile u8 *in = (const volatile u8 *)source;
    while (size--) *out++ = *in++;
}
void __aeabi_memcpy(void *destination, const void *source, u32 size) __attribute__((alias("__aeabi_memcpy8")));
void __aeabi_memcpy4(void *destination, const void *source, u32 size) __attribute__((alias("__aeabi_memcpy8")));

struct input_watch {
    u32 ok;
    u32 root, config, state, count;
    u32 idx_half, idx_full;
    u32 has_half, has_full;
};

struct bk_reply {
    u32 uipc_ok;
    s32 uipc_err;
    u32 bk_valid;
    u32 bk_size;
    u32 bk_val;
    s32 bk_rc;
    u32 uipc_disabled;
    s32 uipc_free_err;
};

struct sample {
    u32 valid_cam;
    u32 csp_ptr_ok;
    u32 drive_act, burst_spd, bol_spd;
    u32 still_size, still_asp, jpeg_qual, file_fmt;
    u32 bk_valid, bk_size, bk_val;
    s32 bk_rc;
    u32 sub_ok, sub_enabled, sub_raw;
    s32 sub_cb;
    u32 sub_s1, sub_s2;
    u32 half_ok, half_raw;
    u32 full_ok, full_raw;
    u32 elig;
    u32 tog;
    u32 gate;
};

struct daemon_state {
    u32 self_pid;
    u32 im_pid;
    u32 im_starttime;
    u32 libobj_bias;
    u32 mwf_bias;
    u32 mpr_bias;
    u32 mprctrl_bias;
    u32 uipc_bias;
    char log_path[64];
    char pid_path[64];
    char stop_path[64];
    char disarm_path[64];
    char cfg_path[64];
    char cfg_tmp_path[64];
    char ring_exe_path[64];
    u32 pid_published;
    u32 ring_exe_ok;
    u32 mon_tid_proc;
    u32 mon_tid_mwf;
    u32 nranges;
    struct s6_wire_range ranges[MAX_RANGES];
    struct s6_wire_range tmp_ranges[MAX_RANGES];
    u32 tmp_nranges;
    s32 mem_fd;
    s32 log_fd;
    u32 log_bytes;
    u32 log_truncated;
    /* /dev/uipc state (exclusively used inside uipc_worker child) */
    s32 uipc_fd;
    u32 uipc_map;
    u32 uipc_len;
    s32 uipc_err;
    u32 uipc_disabled;
    s32 uipc_free_err;
    /* Parent-side non-blocking worker pipe state */
    s32 worker_pid;
    s32 req_fd;
    s32 rep_fd;
    u8 rep_buf[sizeof(struct bk_reply)];
    u32 rep_got;
    u32 uipc_inflight;
    u32 uipc_req_ms;
    u32 uipc_timed_out;
    u32 uipc_ok_seen;
    u32 worker_stopped;
    u32 worker_reaped;
    u32 bk_reply_seq;
    struct bk_reply last_bk;
    /* Ring child supervisor state */
    s32 ring_pid;
    s32 ring_out_fd;
    u32 ring_seq;
    u32 ring_runs;
    u32 ring_ok_runs;
    u32 ring_saved_total;
    u32 ring_fault;
    u32 ring_unresolved;
    u32 ring_shutdown_done;
    u32 ring_reaped_final;
    u32 ring_disarm_sent;
    u32 ring_disarm_pending;
    u32 ring_disarm_reason;
    u32 ring_disarm_err_logged;
    u32 ring_bad_gate_streak;
    u32 ring_phase;
    u32 ring_events_seen;
    u32 ring_started_ms;
    u32 last_ring_exit_ms;
    u32 has_ring_exited;
    u32 seen_idle;
    u32 half_since_ms;
    u32 half_pending;
    u32 half_prep_done;
    u32 half_prep_token;
    u32 half_fresh_req_armed;
    u32 half_need_bk_seq;
    char ring_line[160];
    u32 ring_line_len;
    u32 ring_line_skip;
    u8 ring_pipe_buf[1024];
    struct s6_ring_cfg_file ring_cfg;
    /* Watchdog & telemetry */
    u32 started_ms;
    u32 last_maps_refresh_ms;
    u32 maps_refreshes;
    u32 read_errors;
    s32 first_read_err;
    u32 ticks;
    struct input_watch input;
    struct sample prev;
    u32 has_prev;
    u32 scratch_cfg[64 * 12];
};

static s32 sys_call(u32 n, u32 a, u32 b, u32 c, u32 d, u32 e, u32 f) {
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

static int now_ms_checked(u32 *out) {
    u32 ts[2];
    if (sys_call(SYS_CLOCK_GETTIME, 1u, (u32)ts, 0, 0, 0, 0) != 0) return 0;
    *out = ts[0] * 1000u + ts[1] / 1000000u;
    return 1;
}

static int str_eq(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == 0 && *b == 0;
}

static u32 append_str(char *dst, u32 pos, u32 cap, const char *s) {
    while (*s && pos + 1 < cap) dst[pos++] = *s++;
    return pos;
}

static u32 append_u32(char *dst, u32 pos, u32 cap, u32 v) {
    char tmp[12];
    u32 n = 0;
    do { tmp[n++] = (char)('0' + (v % 10u)); v /= 10u; } while (v);
    while (n && pos + 1 < cap) dst[pos++] = tmp[--n];
    return pos;
}

static u32 append_s32(char *dst, u32 pos, u32 cap, s32 v) {
    if (v < 0) {
        if (pos + 1 < cap) dst[pos++] = '-';
        return append_u32(dst, pos, cap, (u32)(-(v + 1)) + 1u);
    }
    return append_u32(dst, pos, cap, (u32)v);
}

static u32 append_hex(char *dst, u32 pos, u32 cap, u32 v) {
    const char digits[] = "0123456789abcdef";
    char tmp[8];
    u32 n = 0;
    pos = append_str(dst, pos, cap, "0x");
    do { tmp[n++] = digits[v & 15u]; v >>= 4; } while (v);
    while (n && pos + 1 < cap) dst[pos++] = tmp[--n];
    return pos;
}

static u32 append_pc_name(char *dst, u32 pos, u32 cap, u32 tok) {
    const char hex[] = "0123456789ABCDEF";
    pos = append_str(dst, pos, cap, "PC");
    for (u32 i = 0; i < 6u && pos + 1 < cap; ++i) {
        dst[pos++] = hex[(tok >> (20u - 4u * i)) & 15u];
    }
    return append_str(dst, pos, cap, ".JPG");
}

static void log_write_bounded(struct daemon_state *s, const char *buf, u32 len, int is_stop) {
    if (s->log_fd < 0 || !len) return;
    u32 limit = is_stop ? m7_s6_daemon_config.max_log_bytes
                        : (m7_s6_daemon_config.max_log_bytes - STOP_RESERVE_BYTES);
    if (len > limit || s->log_bytes > limit - len) {
        if (!is_stop) s->log_truncated = 1u;
        return;
    }
    u32 sent = 0, tries = 0;
    while (sent < len && tries++ < 8u) {
        s32 rc = sys_call(SYS_WRITE, (u32)s->log_fd, (u32)(buf + sent), len - sent, 0, 0, 0);
        if (rc == -4) continue;
        if (rc <= 0 || (u32)rc > len - sent) break;
        sent += (u32)rc;
    }
    if (sent < len) s->log_truncated = 1u;
    s->log_bytes += sent;
}

static int parse_dec_bounded(const char *s, u32 max_len, u32 *out) {
    u32 v = 0, len = 0;
    if (!max_len || !s[0]) return 0;
    while (len < max_len && s[len]) {
        char c = s[len];
        if (c < '0' || c > '9') return 0;
        u32 d = (u32)(c - '0');
        if (v > (0x7fffffffu - d) / 10u) return 0;
        v = v * 10u + d;
        ++len;
    }
    if (len == 0u || len == max_len) return 0;
    *out = v;
    return 1;
}

static u32 parse_hex(const char **cursor) {
    u32 v = 0;
    const char *p = *cursor;
    while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')) {
        v = (v << 4) | (u32)(*p <= '9' ? (*p - '0') : (*p - 'a' + 10));
        ++p;
    }
    *cursor = p;
    return v;
}

static int parse_hex8(const char *p, u32 *out) {
    u32 v = 0;
    for (u32 i = 0; i < 8u; ++i) {
        char c = p[i];
        u32 d;
        if (c >= '0' && c <= '9') d = (u32)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (u32)(c - 'a' + 10);
        else return 0;
        v = (v << 4) | d;
    }
    *out = v;
    return 1;
}

static void build_nonce_path(char *out, u32 cap, const char *nbuf, const char *leaf) {
    u32 p = 0;
    p = append_str(out, p, cap, "/tmp_network/.m7-s6-");
    p = append_str(out, p, cap, nbuf);
    p = append_str(out, p, cap, leaf);
    out[p] = 0;
}

static void build_run_paths(struct daemon_state *s) {
    char nbuf[S6_NONCE_LEN + 1u];
    for (u32 i = 0; i < S6_NONCE_LEN; ++i) nbuf[i] = m7_s6_daemon_config.nonce[i];
    nbuf[S6_NONCE_LEN] = 0;

    build_nonce_path(s->log_path, sizeof(s->log_path), nbuf, "/daemon.log");
    build_nonce_path(s->pid_path, sizeof(s->pid_path), nbuf, "/daemon.pid");
    build_nonce_path(s->stop_path, sizeof(s->stop_path), nbuf, "/stop");
    build_nonce_path(s->disarm_path, sizeof(s->disarm_path), nbuf, "/disarm");
    build_nonce_path(s->cfg_path, sizeof(s->cfg_path), nbuf, "/run.cfg");
    build_nonce_path(s->cfg_tmp_path, sizeof(s->cfg_tmp_path), nbuf, "/run.cfg.tmp");
    build_nonce_path(s->ring_exe_path, sizeof(s->ring_exe_path), nbuf, "/ring.elf");
}

static int file_exists_ro(const char *path) {
    s32 fd = sys_call(SYS_OPEN, (u32)path, O_RDONLY, 0, 0, 0, 0);
    if (fd >= 0) {
        sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
        return 1;
    }
    return 0;
}

static int file_confirmed_absent(const char *path) {
    s32 fd = sys_call(SYS_OPEN, (u32)path, O_RDONLY, 0, 0, 0, 0);
    if (fd >= 0) {
        sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
        return 0;
    }
    return (fd == -2 /* -ENOENT */) ? 1 : 0;
}

static int stop_file_present(const struct daemon_state *s) {
    return file_exists_ro(s->stop_path);
}

static void build_proc_subpath(char *out, u32 cap, u32 pid, const char *suffix) {
    u32 pos = 0;
    pos = append_str(out, pos, cap, "/proc/");
    pos = append_u32(out, pos, cap, pid);
    pos = append_str(out, pos, cap, suffix);
    out[pos] = 0;
}

static int read_proc_starttime(u32 pid, u32 *out_start) {
    char path[48], buf[512];
    build_proc_subpath(path, sizeof(path), pid, "/stat");
    s32 fd = sys_call(SYS_OPEN, (u32)path, O_RDONLY, 0, 0, 0, 0);
    if (fd < 0) return 0;
    s32 n = sys_call(SYS_READ, (u32)fd, (u32)buf, sizeof(buf) - 1u, 0, 0, 0);
    sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
    if (n <= 0 || (u32)n >= sizeof(buf)) return 0;
    buf[n] = 0;
    s32 rparen = -1;
    for (s32 i = 0; i < n; ++i) {
        if (buf[i] == ')') rparen = i;
    }
    if (rparen < 0 || rparen + 2 >= n || buf[rparen + 1] != ' ') return 0;
    const char *p = buf + rparen + 2;
    for (u32 field = 0; field < 19u; ++field) {
        while (*p && *p != ' ') ++p;
        if (*p != ' ') return 0;
        ++p;
    }
    u32 val = 0, digits = 0;
    while (*p >= '0' && *p <= '9') {
        val = val * 10u + (u32)(*p - '0');
        ++digits;
        ++p;
    }
    if (!digits) return 0;
    *out_start = val;
    return 1;
}

static int discover_im_pid(struct daemon_state *s) {
    s32 dfd = sys_call(SYS_OPEN, (u32)"/proc", O_RDONLY, 0, 0, 0, 0);
    if (dfd < 0) return 0;
    u8 dbuf[1024];
    u32 found = 0, count = 0;
    for (u32 rounds = 0; rounds < 256u; ++rounds) {
        s32 n = sys_call(SYS_GETDENTS64, (u32)dfd, (u32)dbuf, sizeof(dbuf), 0, 0, 0);
        if (n <= 0 || (u32)n > sizeof(dbuf)) break;
        u32 off = 0;
        while (off + 20u <= (u32)n) {
            u32 reclen = (u32)dbuf[off + 16u] | ((u32)dbuf[off + 17u] << 8);
            if (reclen < 20u || off + reclen > (u32)n) break;
            const char *name = (const char *)(dbuf + off + 19u);
            u32 pid = 0;
            if (parse_dec_bounded(name, reclen - 19u, &pid) && pid > 1u) {
                char epath[48], linkbuf[64];
                build_proc_subpath(epath, sizeof(epath), pid, "/exe");
                s32 ln = sys_call(SYS_READLINK, (u32)epath, (u32)linkbuf, sizeof(linkbuf) - 1u, 0, 0, 0);
                if (ln > 0 && (u32)ln < sizeof(linkbuf)) {
                    linkbuf[ln] = 0;
                    if (str_eq(linkbuf, "/usr/bin/im.elf")) {
                        found = pid;
                        ++count;
                    }
                }
            }
            off += reclen;
        }
    }
    sys_call(SYS_CLOSE, (u32)dfd, 0, 0, 0, 0, 0);
    if (count != 1u || !found) return 0;
    u32 st = 0;
    if (!read_proc_starttime(found, &st)) return 0;
    s->im_pid = found;
    s->im_starttime = st;
    return 1;
}

static int valid_lib_bias(u32 bias) {
    return bias >= 0x10000u && bias <= 0xbe000000u && (bias & 4095u) == 0u;
}

static int overlap(u32 a, u32 asz, u32 b, u32 bsz) {
    return a < b + bsz && b < a + asz;
}

static void parse_maps_line(struct daemon_state *s, const char *line, int initial) {
    const char *p = line;
    u32 start = parse_hex(&p);
    if (*p++ != '-') return;
    u32 end = parse_hex(&p);
    if (*p++ != ' ') return;
    if (!p[0] || !p[1] || !p[2] || !p[3] || p[4] != ' ') return;
    char r = p[0], w = p[1], x = p[2], priv = p[3];
    p += 5;
    u32 file_off = parse_hex(&p);
    if (*p++ != ' ') return;
    u32 dev_hi = parse_hex(&p);
    if (*p++ != ':') return;
    u32 dev_lo = parse_hex(&p);
    if (*p++ != ' ') return;
    while (*p == ' ') ++p;
    u32 inode = 0;
    while (*p >= '0' && *p <= '9') { inode = inode * 10u + (u32)(*p - '0'); ++p; }
    while (*p == ' ') ++p;
    const char *path = p;

    if ((start & 4095u) || (end & 4095u) || start < 0x10000u || end > 0xc0000000u || start >= end)
        return;

    if (initial && r == 'r' && w == '-' && x == 'x' && priv == 'p' && file_off == 0 && inode > 0) {
        if (str_eq(path, "/usr/lib/libObj.so") && !s->libobj_bias) s->libobj_bias = start;
        else if (str_eq(path, "/usr/lib/libMWF.so") && !s->mwf_bias) s->mwf_bias = start;
        else if (str_eq(path, "/usr/lib/libmpr.so") && !s->mpr_bias) s->mpr_bias = start;
        else if (str_eq(path, "/usr/lib/libmprctrl.so") && !s->mprctrl_bias) s->mprctrl_bias = start;
        else if (str_eq(path, "/usr/lib/libosal_uipc.so") && !s->uipc_bias) s->uipc_bias = start;
    }

    if (r == 'r' && w == 'w' && x == '-' && priv == 'p' && file_off == 0 &&
        dev_hi == 0 && dev_lo == 0 && inode == 0 && (*path == 0 || str_eq(path, "[heap]"))) {
        if (s->tmp_nranges < MAX_RANGES) {
            s->tmp_ranges[s->tmp_nranges].start = start;
            s->tmp_ranges[s->tmp_nranges].end = end;
            ++s->tmp_nranges;
        }
    }
}

static int parse_im_maps(struct daemon_state *s, int initial) {
    char mpath[48], buf[512], line[224];
    build_proc_subpath(mpath, sizeof(mpath), s->im_pid, "/maps");
    s32 fd = sys_call(SYS_OPEN, (u32)mpath, O_RDONLY, 0, 0, 0, 0);
    if (fd < 0) return 0;
    if (initial) {
        s->libobj_bias = s->mwf_bias = s->mpr_bias = s->mprctrl_bias = s->uipc_bias = 0;
    }
    s->tmp_nranges = 0;
    u32 used = 0, skipped = 0, total = 0;
    while (total < 512u * 1024u) {
        s32 n = sys_call(SYS_READ, (u32)fd, (u32)buf, sizeof(buf), 0, 0, 0);
        if (n <= 0 || (u32)n > sizeof(buf)) break;
        total += (u32)n;
        for (s32 i = 0; i < n; ++i) {
            char ch = buf[i];
            if (ch == '\n') {
                line[used] = 0;
                if (!skipped) parse_maps_line(s, line, initial);
                used = skipped = 0;
            } else if (used + 1u < sizeof(line)) {
                line[used++] = ch;
            } else {
                skipped = 1;
            }
        }
    }
    if (used && !skipped) {
        line[used] = 0;
        parse_maps_line(s, line, initial);
    }
    sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
    if (!valid_lib_bias(s->libobj_bias) || !valid_lib_bias(s->mwf_bias) ||
        !valid_lib_bias(s->mpr_bias) || !valid_lib_bias(s->mprctrl_bias)) {
        return 0;
    }

    u32 bss_s = s->libobj_bias + LIBOBJ_BSS_START;
    u32 bss_e = s->libobj_bias + LIBOBJ_BSS_END;
    u32 dst = 0;
    for (u32 i = 0; i < s->tmp_nranges; ++i) {
        u32 rs = s->tmp_ranges[i].start, re = s->tmp_ranges[i].end;
        if (overlap(rs, re - rs, bss_s, bss_e - bss_s)) continue;
        s->tmp_ranges[dst++] = s->tmp_ranges[i];
    }
    if (!dst) return 0;
    for (u32 i = 0; i < dst; ++i) s->ranges[i] = s->tmp_ranges[i];
    s->nranges = dst;
    return 1;
}

static int in_private_ranges(struct daemon_state *s, u32 addr, u32 size) {
    if ((addr & 3u) || addr < 0x10000u || addr >= 0xc0000000u || !size || size > 0xc0000000u - addr)
        return 0;
    for (u32 i = 0; i < s->nranges; ++i) {
        if (addr >= s->ranges[i].start && addr + size <= s->ranges[i].end) return 1;
    }
    u32 t = 0;
    if (now_ms_checked(&t) && (u32)(t - s->last_maps_refresh_ms) >= 2000u) {
        s->last_maps_refresh_ms = t;
        if (parse_im_maps(s, 0)) {
            ++s->maps_refreshes;
            for (u32 i = 0; i < s->nranges; ++i) {
                if (addr >= s->ranges[i].start && addr + size <= s->ranges[i].end) return 1;
            }
        }
    }
    return 0;
}

static int pread_raw(struct daemon_state *s, u32 addr, void *out, u32 size) {
    if (s->mem_fd < 0) return 0;
    s32 rc = sys_call(SYS_PREAD64, (u32)s->mem_fd, (u32)out, size, 0, addr, 0);
    if (rc != (s32)size) {
        ++s->read_errors;
        if (!s->first_read_err) s->first_read_err = (rc < 0) ? rc : -5;
        return 0;
    }
    return 1;
}

static int pread_private(struct daemon_state *s, u32 addr, void *out, u32 size) {
    if (!in_private_ranges(s, addr, size)) {
        ++s->read_errors;
        if (!s->first_read_err) s->first_read_err = -14;
        return 0;
    }
    return pread_raw(s, addr, out, size);
}

static void discover_monitor_tid(struct daemon_state *s) {
    char tdir[48];
    build_proc_subpath(tdir, sizeof(tdir), s->im_pid, "/task");
    s32 dfd = sys_call(SYS_OPEN, (u32)tdir, O_RDONLY, 0, 0, 0, 0);
    u32 found = 0, count = 0;
    if (dfd >= 0) {
        u8 dbuf[1024];
        for (u32 rounds = 0; rounds < 128u; ++rounds) {
            s32 n = sys_call(SYS_GETDENTS64, (u32)dfd, (u32)dbuf, sizeof(dbuf), 0, 0, 0);
            if (n <= 0 || (u32)n > sizeof(dbuf)) break;
            u32 off = 0;
            while (off + 20u <= (u32)n) {
                u32 reclen = (u32)dbuf[off + 16u] | ((u32)dbuf[off + 17u] << 8);
                if (reclen < 20u || off + reclen > (u32)n) break;
                const char *name = (const char *)(dbuf + off + 19u);
                u32 tid = 0;
                if (parse_dec_bounded(name, reclen - 19u, &tid) && tid != s->im_pid) {
                    char cpath[64], comm[32];
                    u32 pos = 0;
                    pos = append_str(cpath, pos, sizeof(cpath), "/proc/");
                    pos = append_u32(cpath, pos, sizeof(cpath), s->im_pid);
                    pos = append_str(cpath, pos, sizeof(cpath), "/task/");
                    pos = append_u32(cpath, pos, sizeof(cpath), tid);
                    pos = append_str(cpath, pos, sizeof(cpath), "/comm");
                    cpath[pos] = 0;
                    s32 cfd = sys_call(SYS_OPEN, (u32)cpath, O_RDONLY, 0, 0, 0, 0);
                    if (cfd >= 0) {
                        s32 cn = sys_call(SYS_READ, (u32)cfd, (u32)comm, sizeof(comm) - 1u, 0, 0, 0);
                        sys_call(SYS_CLOSE, (u32)cfd, 0, 0, 0, 0, 0);
                        if (cn > 0 && (u32)cn < sizeof(comm)) {
                            while (cn > 0 && (comm[cn - 1] == '\n' || comm[cn - 1] == '\r')) --cn;
                            comm[cn] = 0;
                            if (str_eq(comm, "mwf_monitor_inp")) {
                                found = tid;
                                ++count;
                            }
                        }
                    }
                }
                off += reclen;
            }
        }
        sys_call(SYS_CLOSE, (u32)dfd, 0, 0, 0, 0, 0);
    }
    s->mon_tid_proc = (count == 1u) ? found : 0u;

    u32 head[2] = {0, 0};
    s->mon_tid_mwf = 0;
    if (pread_raw(s, s->mwf_bias + LIBMWF_MONITOR_FLAG, head, 8u) &&
        (head[0] & 0xffu) == 1u && head[1] != 0u) {
        u32 obj[12];
        if (pread_private(s, head[1], obj, sizeof(obj)) &&
            obj[0] == s->mwf_bias + LIBMWF_MONITOR_VPTR && obj[5] != 0u) {
            u32 h[3];
            if (pread_private(s, obj[5], h, sizeof(h)) &&
                h[0] == 0x66888866u && h[2] == obj[6] && obj[6] != s->im_pid) {
                s->mon_tid_mwf = obj[6];
            }
        }
    }
}

/* --- Isolated /dev/uipc Backup_read worker --- */
static s32 uipc_ioctl_retry(s32 fd, u32 req, void *arg) {
    for (u32 i = 0; i < 8u; ++i) {
        s32 rc = sys_call(SYS_IOCTL, (u32)fd, req, (u32)arg, 0, 0, 0);
        if (rc != UIPC_EAGAIN_RETRY && rc != -4) return rc;
    }
    return UIPC_EAGAIN_RETRY;
}

static int uipc_init(struct daemon_state *s) {
    s->uipc_fd = -1;
    s->uipc_map = 0;
    s->uipc_len = 0;
    s->uipc_err = 0;
    s->uipc_disabled = 0;
    s->uipc_free_err = 0;
    s32 fd = sys_call(SYS_OPEN, (u32)"/dev/uipc", O_RDWR, 0, 0, 0, 0);
    if (fd < 0) { s->uipc_err = fd; return 0; }
    u32 info[4] = {0, 0, 0, 0};
    u32 ireq[2] = {0u, (u32)info};
    s32 rc = uipc_ioctl_retry(fd, UIPC_IOCTL_INIT, ireq);
    if (rc != 0 || info[0] < 4096u || info[0] > 16u * 1024u * 1024u || (info[0] & 4095u)) {
        s->uipc_err = rc ? rc : -22;
        sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
        return 0;
    }
    s32 map = sys_call(SYS_MMAP2, 0u, info[0], 3u, 1u, (u32)fd, 0u);
    if ((u32)map >= 0xfffff000u) {
        s->uipc_err = map;
        sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
        return 0;
    }
    s->uipc_fd = fd;
    s->uipc_map = (u32)map;
    s->uipc_len = info[0];
    return 1;
}

static void uipc_close(struct daemon_state *s) {
    if (s->uipc_map && s->uipc_len) {
        sys_call(SYS_MUNMAP, s->uipc_map, s->uipc_len, 0, 0, 0, 0);
        s->uipc_map = 0;
        s->uipc_len = 0;
    }
    if (s->uipc_fd >= 0) {
        sys_call(SYS_CLOSE, (u32)s->uipc_fd, 0, 0, 0, 0, 0);
        s->uipc_fd = -1;
    }
}

static s32 uipc_backup_call(struct daemon_state *s, u32 op, u32 argc, u32 arg0, u32 arg1, s32 *out_ret) {
    if (s->uipc_disabled) return s->uipc_free_err ? s->uipc_free_err : -5;
    if (s->uipc_fd < 0 || !s->uipc_map) return -19;
    u32 msg_va = 0;
    u32 vargs[3] = {(u32)&msg_va, UIPC_BACKUP_MSG_SIZE, 0u};
    u32 vreq[2] = {UIPC_BACKUP_QID, (u32)vargs};
    s32 rc = uipc_ioctl_retry(s->uipc_fd, UIPC_IOCTL_VALLOC_WAIT, vreq);
    if (rc != 0) return rc;
    if (msg_va < s->uipc_map || msg_va > s->uipc_map + s->uipc_len - UIPC_BACKUP_MSG_SIZE || (msg_va & 3u)) {
        u32 freq[2] = {UIPC_BACKUP_QID, msg_va};
        s32 frc = uipc_ioctl_retry(s->uipc_fd, UIPC_IOCTL_FREE_MSG, freq);
        if (frc != 0) { s->uipc_disabled = 1u; s->uipc_free_err = frc; }
        return -14;
    }
    volatile u32 *msg = (volatile u32 *)msg_va;
    for (u32 i = 0; i < 16u; ++i) msg[i] = 0u;
    msg[0] = op;
    msg[1] = 0u;
    msg[2] = argc;
    msg[3] = UIPC_BACKUP_QID;
    msg[6] = arg0;
    if (argc >= 2u) msg[7] = arg1;

    u32 sargs[3] = {msg_va, 0u, 0u};
    u32 sreq[2] = {UIPC_BACKUP_QID, (u32)sargs};
    rc = uipc_ioctl_retry(s->uipc_fd, UIPC_IOCTL_SND_SYNC, sreq);
    if (rc == 0) {
        if (sargs[1] != 0u) rc = -38;
        else *out_ret = (s32)msg[1];
    }

    u32 freq[2] = {UIPC_BACKUP_QID, msg_va};
    s32 frc = uipc_ioctl_retry(s->uipc_fd, UIPC_IOCTL_FREE_MSG, freq);
    if (frc != 0) {
        s->uipc_disabled = 1u;
        s->uipc_free_err = frc;
        if (rc == 0) rc = frc;
    }
    return rc;
}

static void worker_read_backup(struct daemon_state *s, u32 bkid, struct bk_reply *rep) {
    __aeabi_memclr8(rep, sizeof(*rep));
    rep->uipc_ok = (s->uipc_fd >= 0) ? 1u : 0u;
    rep->uipc_err = s->uipc_err;
    rep->bk_val = 0xffffffffu;
    rep->bk_rc = -19;
    rep->uipc_disabled = s->uipc_disabled;
    rep->uipc_free_err = s->uipc_free_err;

    if (s->uipc_disabled) {
        rep->bk_rc = s->uipc_free_err ? s->uipc_free_err : -5;
        return;
    }
    if (s->uipc_fd < 0) {
        rep->bk_rc = s->uipc_err ? s->uipc_err : -19;
        return;
    }
    s32 dsz = -1;
    s32 rc = uipc_backup_call(s, 0u, 1u, bkid, 0u, &dsz);
    rep->uipc_disabled = s->uipc_disabled;
    rep->uipc_free_err = s->uipc_free_err;
    if (rc != 0) { rep->bk_rc = rc; return; }
    rep->bk_size = (dsz > 0) ? (u32)dsz : 0u;
    if (dsz != 1) { rep->bk_rc = (dsz < 0) ? dsz : -75; return; }

    volatile u32 byte_box = 0xa5a5a5a5u;
    s32 rret = -1;
    rc = uipc_backup_call(s, 3u, 2u, bkid, (u32)&byte_box, &rret);
    rep->uipc_disabled = s->uipc_disabled;
    rep->uipc_free_err = s->uipc_free_err;
    if (rc != 0 || rret != 1) { rep->bk_rc = rc ? rc : rret; return; }
    u32 raw_box = byte_box;
    if ((raw_box & 0xffffff00u) != 0xa5a5a500u) { rep->bk_rc = -75; return; }
    u32 val = raw_box & 0xffu;
    if (val == 0xa5u) {
        volatile u32 box2 = 0x5a5a5a5au;
        s32 rret2 = -1;
        rc = uipc_backup_call(s, 3u, 2u, bkid, (u32)&box2, &rret2);
        rep->uipc_disabled = s->uipc_disabled;
        rep->uipc_free_err = s->uipc_free_err;
        if (rc != 0 || rret2 != 1) { rep->bk_rc = rc ? rc : rret2; return; }
        u32 raw2 = box2;
        if ((raw2 & 0xffffff00u) != 0x5a5a5a00u) { rep->bk_rc = -75; return; }
        if ((raw2 & 0xffu) == 0x5au) { rep->bk_rc = -14; return; }
        val = raw2 & 0xffu;
    }
    rep->bk_valid = 1u;
    rep->bk_val = val;
    rep->bk_rc = 0;
}

static void uipc_worker_main(struct daemon_state *s, s32 req_rfd, s32 rep_wfd, u32 state_bytes) {
    if (s->mem_fd >= 0) { sys_call(SYS_CLOSE, (u32)s->mem_fd, 0, 0, 0, 0, 0); s->mem_fd = -1; }
    if (m7_s6_daemon_config.daemonize && s->log_fd >= 0) {
        sys_call(SYS_CLOSE, (u32)s->log_fd, 0, 0, 0, 0, 0);
        s->log_fd = -1;
    }
    uipc_init(s);

    for (;;) {
        u32 bkid = 0, got = 0;
        while (got < 4u) {
            s32 n = sys_call(SYS_READ, (u32)req_rfd, (u32)((u8 *)&bkid + got), 4u - got, 0, 0, 0);
            if (n == -4) continue;
            if (n <= 0 || (u32)n > 4u - got) goto done;
            got += (u32)n;
        }
        struct bk_reply rep;
        worker_read_backup(s, bkid, &rep);
        u32 sent = 0;
        while (sent < sizeof(rep)) {
            s32 n = sys_call(SYS_WRITE, (u32)rep_wfd, (u32)((const u8 *)&rep + sent), sizeof(rep) - sent, 0, 0, 0);
            if (n == -4) continue;
            if (n <= 0 || (u32)n > sizeof(rep) - sent) goto done;
            sent += (u32)n;
        }
    }

done:
    uipc_close(s);
    sys_call(SYS_CLOSE, (u32)req_rfd, 0, 0, 0, 0, 0);
    sys_call(SYS_CLOSE, (u32)rep_wfd, 0, 0, 0, 0, 0);
    sys_call(SYS_MUNMAP, (u32)s, state_bytes, 0, 0, 0, 0);
    sys_call(SYS_EXIT, 0u, 0, 0, 0, 0, 0);
}

static int start_uipc_worker(struct daemon_state *s, u32 state_bytes) {
    s32 req_p[2] = {-1, -1}, rep_p[2] = {-1, -1};
    s->worker_pid = -1; s->req_fd = -1; s->rep_fd = -1;
    if (sys_call(SYS_PIPE, (u32)req_p, 0, 0, 0, 0, 0) != 0) return 0;
    if (sys_call(SYS_PIPE, (u32)rep_p, 0, 0, 0, 0, 0) != 0) {
        sys_call(SYS_CLOSE, (u32)req_p[0], 0, 0, 0, 0, 0);
        sys_call(SYS_CLOSE, (u32)req_p[1], 0, 0, 0, 0, 0);
        return 0;
    }
    s32 wpid = sys_call(SYS_FORK, 0, 0, 0, 0, 0, 0);
    if (wpid < 0) {
        sys_call(SYS_CLOSE, (u32)req_p[0], 0, 0, 0, 0, 0);
        sys_call(SYS_CLOSE, (u32)req_p[1], 0, 0, 0, 0, 0);
        sys_call(SYS_CLOSE, (u32)rep_p[0], 0, 0, 0, 0, 0);
        sys_call(SYS_CLOSE, (u32)rep_p[1], 0, 0, 0, 0, 0);
        return 0;
    }
    if (wpid == 0) {
        sys_call(SYS_CLOSE, (u32)req_p[1], 0, 0, 0, 0, 0);
        sys_call(SYS_CLOSE, (u32)rep_p[0], 0, 0, 0, 0, 0);
        uipc_worker_main(s, req_p[0], rep_p[1], state_bytes);
    }
    sys_call(SYS_CLOSE, (u32)req_p[0], 0, 0, 0, 0, 0);
    sys_call(SYS_CLOSE, (u32)rep_p[1], 0, 0, 0, 0, 0);
    if (sys_call(SYS_FCNTL, (u32)req_p[1], F_SETFL, O_NONBLOCK, 0, 0, 0) < 0 ||
        sys_call(SYS_FCNTL, (u32)rep_p[0], F_SETFL, O_NONBLOCK, 0, 0, 0) < 0) {
        sys_call(SYS_CLOSE, (u32)req_p[1], 0, 0, 0, 0, 0);
        sys_call(SYS_CLOSE, (u32)rep_p[0], 0, 0, 0, 0, 0);
        s->worker_pid = wpid;
        return 0;
    }
    s->worker_pid = wpid;
    s->req_fd = req_p[1];
    s->rep_fd = rep_p[0];
    s->rep_got = 0u;
    return 1;
}

static void uipc_fail_channel(struct daemon_state *s, s32 err) {
    s->uipc_inflight = 0u;
    s->rep_got = 0u;
    s->uipc_timed_out = 1u;
    s->last_bk.bk_valid = 0u;
    s->last_bk.bk_val = 0xffffffffu;
    s->last_bk.bk_rc = err;
    if (s->req_fd >= 0) { sys_call(SYS_CLOSE, (u32)s->req_fd, 0, 0, 0, 0, 0); s->req_fd = -1; }
    if (s->rep_fd >= 0) { sys_call(SYS_CLOSE, (u32)s->rep_fd, 0, 0, 0, 0, 0); s->rep_fd = -1; }
}

static void uipc_send_request(struct daemon_state *s, u32 now_val) {
    if (s->uipc_timed_out || s->uipc_inflight || s->req_fd < 0) return;
    u32 bkid = m7_s6_daemon_config.toggle_bkid;
    s32 n = sys_call(SYS_WRITE, (u32)s->req_fd, (u32)&bkid, 4u, 0, 0, 0);
    if (n == 4) {
        s->uipc_inflight = 1u;
        s->rep_got = 0u;
        s->uipc_req_ms = now_val;
    } else {
        uipc_fail_channel(s, (n < 0) ? n : -32);
    }
}

static int uipc_poll_reply(struct daemon_state *s, u32 now_val) {
    if (!s->uipc_inflight || s->rep_fd < 0) return 0;
    if ((u32)(now_val - s->uipc_req_ms) >= UIPC_REPLY_TIMEOUT_MS ||
        (u32)(now_val - s->started_ms) >= m7_s6_daemon_config.duration_ms) {
        uipc_fail_channel(s, -110);
        return 1;
    }
    while (s->rep_got < sizeof(struct bk_reply)) {
        u32 rem = (u32)sizeof(struct bk_reply) - s->rep_got;
        s32 n = sys_call(SYS_READ, (u32)s->rep_fd, (u32)(s->rep_buf + s->rep_got), rem, 0, 0, 0);
        if (n > 0 && (u32)n <= rem) {
            s->rep_got += (u32)n;
            continue;
        }
        if (n == -11 || n == -4) {
            u32 chk = now_val;
            now_ms_checked(&chk);
            if ((u32)(chk - s->uipc_req_ms) >= UIPC_REPLY_TIMEOUT_MS ||
                (u32)(chk - s->started_ms) >= m7_s6_daemon_config.duration_ms) {
                uipc_fail_channel(s, -110);
                return 1;
            }
            return 0;
        }
        uipc_fail_channel(s, (n < 0) ? n : -32);
        return 1;
    }
    u32 after_val = now_val;
    if (!now_ms_checked(&after_val) ||
        (u32)(after_val - s->uipc_req_ms) >= UIPC_REPLY_TIMEOUT_MS ||
        (u32)(after_val - s->started_ms) >= m7_s6_daemon_config.duration_ms) {
        uipc_fail_channel(s, -110);
        return 1;
    }
    struct bk_reply rep;
    __aeabi_memcpy8(&rep, s->rep_buf, sizeof(rep));
    s->rep_got = 0u;
    s->uipc_inflight = 0u;
    ++s->bk_reply_seq;
    s->last_bk = rep;
    s->uipc_ok_seen = rep.uipc_ok;
    s->uipc_err = rep.uipc_err;
    s->uipc_disabled = rep.uipc_disabled;
    s->uipc_free_err = rep.uipc_free_err;
    return 1;
}

static void apply_last_bk(const struct daemon_state *s, struct sample *out) {
    out->bk_valid = s->last_bk.bk_valid;
    out->bk_size = s->last_bk.bk_size;
    out->bk_val = s->last_bk.bk_val;
    out->bk_rc = s->last_bk.bk_rc;
}

static void stop_uipc_worker(struct daemon_state *s, const u32 *sigmask) {
    if (s->worker_stopped) return;
    s->worker_stopped = 1u;
    if (s->req_fd >= 0) { sys_call(SYS_CLOSE, (u32)s->req_fd, 0, 0, 0, 0, 0); s->req_fd = -1; }
    if (s->rep_fd >= 0) { sys_call(SYS_CLOSE, (u32)s->rep_fd, 0, 0, 0, 0, 0); s->rep_fd = -1; }
    if (s->worker_pid <= 0) { s->worker_reaped = 1u; return; }

    u32 wst = 0;
    for (u32 i = 0; i < 2u; ++i) {
        s32 w = sys_call(SYS_WAIT4, (u32)s->worker_pid, (u32)&wst, WNOHANG, 0, 0, 0);
        if (w == s->worker_pid || w == -10) {
            s->worker_reaped = 1u;
            s->worker_pid = -1;
            return;
        }
        u32 ts[2] = {0u, 50000000u};
        sys_call(SYS_RT_SIGTIMEDWAIT, (u32)sigmask, 0u, (u32)ts, 8u, 0, 0);
    }
    sys_call(SYS_KILL, (u32)s->worker_pid, 9u, 0, 0, 0, 0);
    for (u32 i = 0; i < 2u; ++i) {
        s32 w = sys_call(SYS_WAIT4, (u32)s->worker_pid, (u32)&wst, WNOHANG, 0, 0, 0);
        if (w == s->worker_pid || w == -10) {
            s->worker_reaped = 1u;
            s->worker_pid = -1;
            return;
        }
        u32 ts[2] = {0u, 50000000u};
        sys_call(SYS_RT_SIGTIMEDWAIT, (u32)sigmask, 0u, (u32)ts, 8u, 0, 0);
    }
    s32 w = sys_call(SYS_WAIT4, (u32)s->worker_pid, (u32)&wst, WNOHANG, 0, 0, 0);
    if (w == s->worker_pid || w == -10) {
        s->worker_reaped = 1u;
        s->worker_pid = -1;
    }
}

/* --- CamSetParams / Spinal / InfraInput zero-ptrace readers --- */
static int read_param_int7(struct daemon_state *s, u32 slot_va, u32 *out_val) {
    u32 ptr = 0;
    if (!pread_raw(s, s->libobj_bias + slot_va, &ptr, 4u) || !ptr) return 0;
    u32 pair[2] = {0, 0};
    if (!pread_private(s, ptr, pair, 8u)) return 0;
    if (pair[1] != s->mwf_bias + LIBMWF_PARAM_INT7_FTBL) return 0;
    *out_val = pair[0];
    return 1;
}

static void read_cam_params(struct daemon_state *s, struct sample *out) {
    u32 hdr[2] = {0, 0};
    out->valid_cam = 0u;
    out->csp_ptr_ok = 0u;
    out->drive_act = out->burst_spd = out->bol_spd = 0xffffffffu;
    out->still_size = out->still_asp = out->jpeg_qual = out->file_fmt = 0xffffffffu;
    if (!pread_raw(s, s->libobj_bias + LIBOBJ_CAMSETPARAMS_PTR, hdr, 8u)) return;
    out->csp_ptr_ok = (hdr[0] == s->libobj_bias + LIBOBJ_CAMSETPARAMS_OBJ) ? 1u : 0u;
    if (!out->csp_ptr_ok || (hdr[1] & 1u) != 1u) return;

    u32 ftbl0 = 0;
    if (!pread_raw(s, s->mwf_bias + LIBMWF_PARAM_INT7_FTBL, &ftbl0, 4u) || ftbl0 != 7u) return;

    int ok = 1;
    ok &= read_param_int7(s, SLOT_DRIVE_MODE_ACT, &out->drive_act);
    ok &= read_param_int7(s, SLOT_STILL_SIZE_ACT, &out->still_size);
    ok &= read_param_int7(s, SLOT_STILL_ASPECT_ACT, &out->still_asp);
    ok &= read_param_int7(s, SLOT_JPEG_QUALITY_ACT, &out->jpeg_qual);
    ok &= read_param_int7(s, SLOT_STILL_FORMAT_ACT, &out->file_fmt);
    if (!read_param_int7(s, SLOT_BURST_SPEED_ACT, &out->burst_spd)) out->burst_spd = 0xffffffffu;
    if (!read_param_int7(s, SLOT_BOL_BURST_SPD_ACT, &out->bol_spd)) out->bol_spd = 0xffffffffu;
    out->valid_cam = (u32)ok;
}

static void read_subscription(struct daemon_state *s, struct sample *out) {
    u32 input = 0, spinal = 0, g[24], cam_vptr = 0;
    out->sub_ok = 0u;
    out->sub_enabled = 0u;
    out->sub_raw = 0xffffffffu;
    out->sub_cb = 0;
    out->sub_s1 = 0u;
    out->sub_s2 = 0u;
    if (!pread_raw(s, s->libobj_bias + LIBOBJ_INPUT_SLOT, &input, 4u) ||
        !pread_raw(s, s->libobj_bias + LIBOBJ_SPINAL_SLOT, &spinal, 4u)) return;
    if (!in_private_ranges(s, input, 0x224u) || !in_private_ranges(s, spinal, 0x7cu)) return;
    if (!pread_private(s, spinal, g, sizeof(g))) return;
    if (g[0] != input || !pread_private(s, g[1], &cam_vptr, 4u)) return;
    if (cam_vptr != s->libobj_bias + LIBOBJ_CAMERA_VPTR) return;
    out->sub_ok = 1u;
    out->sub_s1 = g[20];
    out->sub_s2 = g[21];
    out->sub_cb = (s32)g[22];
    out->sub_raw = g[23] & 0xffu;
    out->sub_enabled = ((s32)g[22] > 0 && (g[23] & 0xffu) == 1u) ? 1u : 0u;
}

static int read_input_shape(struct daemon_state *s, u32 *root, u32 *cfg, u32 *st, u32 *cnt) {
    u32 r = 0, w[10];
    if (!pread_raw(s, s->libobj_bias + LIBOBJ_INPUT_SLOT, &r, 4u)) return 0;
    if (overlap(r, 0x224u, s->libobj_bias, LIBOBJ_BSS_END) || !pread_private(s, r, w, sizeof(w))) return 0;
    if (w[0] != s->libobj_bias + LIBOBJ_INPUT_VPTR || !w[7] || w[7] > SD_INPUT_LIMIT) return 0;
    u32 csz = w[7] * 0x30u, ssz = w[7] * 0x28u;
    if (!in_private_ranges(s, w[6], csz) || !in_private_ranges(s, w[9], ssz)) return 0;
    if (overlap(r, 0x224u, w[6], csz) || overlap(r, 0x224u, w[9], ssz) || overlap(w[6], csz, w[9], ssz))
        return 0;
    *root = r; *cfg = w[6]; *cnt = w[7]; *st = w[9];
    return 1;
}

static void init_input_watch(struct daemon_state *s) {
    struct input_watch *w = &s->input;
    __aeabi_memclr8(w, sizeof(*w));
    if (!read_input_shape(s, &w->root, &w->config, &w->state, &w->count)) return;
    for (u32 base = 0; base < w->count; base += 64u) {
        u32 chunk = w->count - base;
        if (chunk > 64u) chunk = 64u;
        if (!pread_private(s, w->config + base * 0x30u, s->scratch_cfg, chunk * 0x30u)) return;
        for (u32 i = 0; i < chunk; ++i) {
            u32 key = s->scratch_cfg[i * 12u + 2u];
            if (key == 0x1f1u && !w->has_half) { w->idx_half = base + i; w->has_half = 1u; }
            else if (key == 0xa7u && !w->has_full) { w->idx_full = base + i; w->has_full = 1u; }
        }
    }
    if (w->has_half && w->has_full) w->ok = 1u;
}

static int read_shutter_row(struct daemon_state *s, u32 idx, u32 expected_key, u32 *out_raw) {
    u32 a[5], b[5];
    u32 addr = s->input.state + idx * 0x28u;
    if (!pread_private(s, addr, a, sizeof(a)) || !pread_private(s, addr, b, sizeof(b))) return 0;
    if (a[0] != b[0] || a[1] != b[1] || a[2] != b[2] || a[4] != b[4]) return 0;
    if (a[0] != expected_key || a[4] != idx || a[2] > 1u) return 0;
    *out_raw = a[2];
    return 1;
}

static void read_shutter(struct daemon_state *s, struct sample *out) {
    u32 r, c, st, cnt;
    out->half_ok = 0u; out->half_raw = 0xffffffffu;
    out->full_ok = 0u; out->full_raw = 0xffffffffu;
    if (!s->input.ok) init_input_watch(s);
    if (!s->input.ok) return;
    if (!read_input_shape(s, &r, &c, &st, &cnt) ||
        r != s->input.root || c != s->input.config || st != s->input.state || cnt != s->input.count) {
        init_input_watch(s);
        if (!s->input.ok) return;
    }
    u32 raw = 0u;
    if (read_shutter_row(s, s->input.idx_half, 0x1f1u, &raw)) { out->half_ok = 1u; out->half_raw = raw; }
    if (read_shutter_row(s, s->input.idx_full, 0xa7u, &raw)) { out->full_ok = 1u; out->full_raw = raw; }
}

static void compute_gates(const struct daemon_state *s, struct sample *cur) {
    cur->elig = (cur->valid_cam &&
                 (cur->drive_act == 0x005fu || cur->drive_act == 0x05bcu) &&
                 cur->file_fmt == 0x00bdu && cur->still_size == 0x00b3u && cur->still_asp == 0x00b9u) ? 1u : 0u;
    cur->tog = (cur->bk_valid && cur->bk_rc == 0 && cur->bk_size == 1u &&
                !s->uipc_disabled && !s->uipc_timed_out &&
                cur->bk_val == m7_s6_daemon_config.toggle_on_val) ? 1u : 0u;
    cur->gate = (cur->tog && cur->elig && cur->sub_ok && cur->sub_enabled &&
                 cur->half_ok && cur->full_ok && cur->half_raw <= 1u && cur->full_raw <= 1u &&
                 !s->ring_fault) ? 1u : 0u;
}

/* --- Compact logging --- */
static void log_boot(struct daemon_state *s, const struct sample *first) {
    char line[512];
    u32 p = 0;
    p = append_str(line, p, sizeof(line), "BOOT self_pid=");
    p = append_u32(line, p, sizeof(line), s->self_pid);
    p = append_str(line, p, sizeof(line), " w_pid=");
    p = append_s32(line, p, sizeof(line), s->worker_pid);
    p = append_str(line, p, sizeof(line), " im_pid=");
    p = append_u32(line, p, sizeof(line), s->im_pid);
    p = append_str(line, p, sizeof(line), " im_st=");
    p = append_u32(line, p, sizeof(line), s->im_starttime);
    p = append_str(line, p, sizeof(line), " libobj=");
    p = append_hex(line, p, sizeof(line), s->libobj_bias);
    p = append_str(line, p, sizeof(line), " mwf=");
    p = append_hex(line, p, sizeof(line), s->mwf_bias);
    p = append_str(line, p, sizeof(line), " mpr=");
    p = append_hex(line, p, sizeof(line), s->mpr_bias);
    p = append_str(line, p, sizeof(line), " mprctrl=");
    p = append_hex(line, p, sizeof(line), s->mprctrl_bias);
    p = append_str(line, p, sizeof(line), " uipc=");
    p = append_hex(line, p, sizeof(line), s->uipc_bias);
    p = append_str(line, p, sizeof(line), " ranges=");
    p = append_u32(line, p, sizeof(line), s->nranges);
    p = append_str(line, p, sizeof(line), " mon_proc=");
    p = append_u32(line, p, sizeof(line), s->mon_tid_proc);
    p = append_str(line, p, sizeof(line), " mon_mwf=");
    p = append_u32(line, p, sizeof(line), s->mon_tid_mwf);
    p = append_str(line, p, sizeof(line), " csp_ptr_ok=");
    p = append_u32(line, p, sizeof(line), first->csp_ptr_ok);
    p = append_str(line, p, sizeof(line), " uipc_ok=");
    p = append_u32(line, p, sizeof(line), s->uipc_ok_seen);
    p = append_str(line, p, sizeof(line), " uipc_err=");
    p = append_s32(line, p, sizeof(line), s->uipc_err);
    p = append_str(line, p, sizeof(line), " bk_id=");
    p = append_hex(line, p, sizeof(line), m7_s6_daemon_config.toggle_bkid);
    p = append_str(line, p, sizeof(line), " bk_on=");
    p = append_u32(line, p, sizeof(line), m7_s6_daemon_config.toggle_on_val);
    p = append_str(line, p, sizeof(line), " bk_sz=");
    p = append_u32(line, p, sizeof(line), first->bk_size);
    p = append_str(line, p, sizeof(line), " bk_rc=");
    p = append_s32(line, p, sizeof(line), first->bk_rc);
    p = append_str(line, p, sizeof(line), " in_ok=");
    p = append_u32(line, p, sizeof(line), s->input.ok);
    p = append_str(line, p, sizeof(line), " ih=");
    p = append_u32(line, p, sizeof(line), s->input.idx_half);
    p = append_str(line, p, sizeof(line), " if=");
    p = append_u32(line, p, sizeof(line), s->input.idx_full);
    p = append_str(line, p, sizeof(line), " ring_ok=");
    p = append_u32(line, p, sizeof(line), s->ring_exe_ok);
    p = append_str(line, p, sizeof(line), " pre=");
    p = append_u32(line, p, sizeof(line), m7_s6_daemon_config.before);
    p = append_str(line, p, sizeof(line), " post=");
    p = append_u32(line, p, sizeof(line), m7_s6_daemon_config.after);
    p = append_str(line, p, sizeof(line), " bcap=");
    p = append_u32(line, p, sizeof(line), m7_s6_daemon_config.burst_cap);
    p = append_str(line, p, sizeof(line), " pmax=");
    p = append_u32(line, p, sizeof(line), m7_s6_daemon_config.post_max);
    p = append_str(line, p, sizeof(line), " deb=");
    p = append_u32(line, p, sizeof(line), m7_s6_daemon_config.debounce_ms);
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 0);
}

static void log_state(struct daemon_state *s, u32 t_ms, const struct sample *cur) {
    char line[384];
    u32 p = 0;
    p = append_str(line, p, sizeof(line), "STATE t=");
    p = append_u32(line, p, sizeof(line), t_ms);
    p = append_str(line, p, sizeof(line), " cam=");
    p = append_u32(line, p, sizeof(line), cur->valid_cam);
    p = append_str(line, p, sizeof(line), " drive=");
    p = append_hex(line, p, sizeof(line), cur->drive_act);
    p = append_str(line, p, sizeof(line), " size=");
    p = append_hex(line, p, sizeof(line), cur->still_size);
    p = append_str(line, p, sizeof(line), " asp=");
    p = append_hex(line, p, sizeof(line), cur->still_asp);
    p = append_str(line, p, sizeof(line), " qual=");
    p = append_hex(line, p, sizeof(line), cur->jpeg_qual);
    p = append_str(line, p, sizeof(line), " fmt=");
    p = append_hex(line, p, sizeof(line), cur->file_fmt);
    p = append_str(line, p, sizeof(line), " bk_ok=");
    p = append_u32(line, p, sizeof(line), cur->bk_valid);
    p = append_str(line, p, sizeof(line), " bk=");
    p = append_hex(line, p, sizeof(line), cur->bk_val);
    p = append_str(line, p, sizeof(line), " bk_rc=");
    p = append_s32(line, p, sizeof(line), cur->bk_rc);
    p = append_str(line, p, sizeof(line), " sub_ok=");
    p = append_u32(line, p, sizeof(line), cur->sub_ok);
    p = append_str(line, p, sizeof(line), " sub_en=");
    p = append_u32(line, p, sizeof(line), cur->sub_enabled);
    p = append_str(line, p, sizeof(line), " half_ok=");
    p = append_u32(line, p, sizeof(line), cur->half_ok);
    p = append_str(line, p, sizeof(line), " half=");
    p = append_hex(line, p, sizeof(line), cur->half_raw);
    p = append_str(line, p, sizeof(line), " full_ok=");
    p = append_u32(line, p, sizeof(line), cur->full_ok);
    p = append_str(line, p, sizeof(line), " full=");
    p = append_hex(line, p, sizeof(line), cur->full_raw);
    p = append_str(line, p, sizeof(line), " elig=");
    p = append_u32(line, p, sizeof(line), cur->elig);
    p = append_str(line, p, sizeof(line), " tog=");
    p = append_u32(line, p, sizeof(line), cur->tog);
    p = append_str(line, p, sizeof(line), " gate=");
    p = append_u32(line, p, sizeof(line), cur->gate);
    p = append_str(line, p, sizeof(line), " r_act=");
    p = append_u32(line, p, sizeof(line), s->ring_pid > 0 ? 1u : 0u);
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 0);
}

static void log_hb(struct daemon_state *s, u32 t_ms, const struct sample *cur) {
    char line[352];
    u32 p = 0;
    p = append_str(line, p, sizeof(line), "HB t=");
    p = append_u32(line, p, sizeof(line), t_ms);
    p = append_str(line, p, sizeof(line), " ticks=");
    p = append_u32(line, p, sizeof(line), s->ticks);
    p = append_str(line, p, sizeof(line), " rerr=");
    p = append_u32(line, p, sizeof(line), s->read_errors);
    p = append_str(line, p, sizeof(line), " ferr=");
    p = append_s32(line, p, sizeof(line), s->first_read_err);
    p = append_str(line, p, sizeof(line), " mref=");
    p = append_u32(line, p, sizeof(line), s->maps_refreshes);
    p = append_str(line, p, sizeof(line), " uipc_dis=");
    p = append_u32(line, p, sizeof(line), s->uipc_disabled);
    p = append_str(line, p, sizeof(line), " uipc_to=");
    p = append_u32(line, p, sizeof(line), s->uipc_timed_out);
    p = append_str(line, p, sizeof(line), " sub_en=");
    p = append_u32(line, p, sizeof(line), cur->sub_enabled);
    p = append_str(line, p, sizeof(line), " drive=");
    p = append_hex(line, p, sizeof(line), cur->drive_act);
    p = append_str(line, p, sizeof(line), " bk=");
    p = append_hex(line, p, sizeof(line), cur->bk_val);
    p = append_str(line, p, sizeof(line), " gate=");
    p = append_u32(line, p, sizeof(line), cur->gate);
    p = append_str(line, p, sizeof(line), " r_act=");
    p = append_u32(line, p, sizeof(line), s->ring_pid > 0 ? 1u : 0u);
    p = append_str(line, p, sizeof(line), " r_runs=");
    p = append_u32(line, p, sizeof(line), s->ring_runs);
    p = append_str(line, p, sizeof(line), " r_ok=");
    p = append_u32(line, p, sizeof(line), s->ring_ok_runs);
    p = append_str(line, p, sizeof(line), " r_sav=");
    p = append_u32(line, p, sizeof(line), s->ring_saved_total);
    p = append_str(line, p, sizeof(line), " r_flt=");
    p = append_u32(line, p, sizeof(line), s->ring_fault);
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 0);
}

static void log_ring_evt(struct daemon_state *s, u32 t_ms, const char *ev, u32 a, u32 b, u32 c, u32 d) {
    char line[224];
    u32 p = 0;
    p = append_str(line, p, sizeof(line), "RING_EVT t=");
    p = append_u32(line, p, sizeof(line), t_ms);
    p = append_str(line, p, sizeof(line), " seq=");
    p = append_u32(line, p, sizeof(line), s->ring_seq);
    p = append_str(line, p, sizeof(line), " ev=");
    p = append_str(line, p, sizeof(line), ev);
    p = append_str(line, p, sizeof(line), " a=");
    p = append_u32(line, p, sizeof(line), a);
    p = append_str(line, p, sizeof(line), " b=");
    p = append_u32(line, p, sizeof(line), b);
    p = append_str(line, p, sizeof(line), " c=");
    p = append_u32(line, p, sizeof(line), c);
    p = append_str(line, p, sizeof(line), " d=");
    p = append_u32(line, p, sizeof(line), d);
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 0);
}

static void log_ring_file(struct daemon_state *s, u32 t_ms, u32 name_tok, u32 drive, u32 bytes, u32 status) {
    char line[224];
    u32 p = 0;
    p = append_str(line, p, sizeof(line), "RING_FILE t=");
    p = append_u32(line, p, sizeof(line), t_ms);
    p = append_str(line, p, sizeof(line), " seq=");
    p = append_u32(line, p, sizeof(line), s->ring_seq);
    p = append_str(line, p, sizeof(line), " file=");
    p = append_pc_name(line, p, sizeof(line), name_tok);
    p = append_str(line, p, sizeof(line), " drive=");
    p = append_u32(line, p, sizeof(line), drive);
    p = append_str(line, p, sizeof(line), " bytes=");
    p = append_u32(line, p, sizeof(line), bytes);
    p = append_str(line, p, sizeof(line), " status=");
    p = append_u32(line, p, sizeof(line), status);
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 0);
}

static void log_stop(struct daemon_state *s, u32 t_ms, u32 trig_ms, const char *reason, s32 detail) {
    char line[320];
    u32 p = 0;
    p = append_str(line, p, sizeof(line), "STOP t=");
    p = append_u32(line, p, sizeof(line), t_ms);
    p = append_str(line, p, sizeof(line), " trig_t=");
    p = append_u32(line, p, sizeof(line), trig_ms);
    p = append_str(line, p, sizeof(line), " reason=");
    p = append_str(line, p, sizeof(line), reason);
    p = append_str(line, p, sizeof(line), " detail=");
    p = append_s32(line, p, sizeof(line), detail);
    p = append_str(line, p, sizeof(line), " ticks=");
    p = append_u32(line, p, sizeof(line), s->ticks);
    p = append_str(line, p, sizeof(line), " rerr=");
    p = append_u32(line, p, sizeof(line), s->read_errors);
    p = append_str(line, p, sizeof(line), " ferr=");
    p = append_s32(line, p, sizeof(line), s->first_read_err);
    p = append_str(line, p, sizeof(line), " uipc_dis=");
    p = append_u32(line, p, sizeof(line), s->uipc_disabled);
    p = append_str(line, p, sizeof(line), " uipc_ferr=");
    p = append_s32(line, p, sizeof(line), s->uipc_free_err);
    p = append_str(line, p, sizeof(line), " uipc_to=");
    p = append_u32(line, p, sizeof(line), s->uipc_timed_out);
    p = append_str(line, p, sizeof(line), " w_reap=");
    p = append_u32(line, p, sizeof(line), s->worker_reaped);
    p = append_str(line, p, sizeof(line), " r_reap=");
    p = append_u32(line, p, sizeof(line), s->ring_reaped_final);
    p = append_str(line, p, sizeof(line), " r_runs=");
    p = append_u32(line, p, sizeof(line), s->ring_runs);
    p = append_str(line, p, sizeof(line), " r_ok=");
    p = append_u32(line, p, sizeof(line), s->ring_ok_runs);
    p = append_str(line, p, sizeof(line), " r_sav=");
    p = append_u32(line, p, sizeof(line), s->ring_saved_total);
    p = append_str(line, p, sizeof(line), " r_flt=");
    p = append_u32(line, p, sizeof(line), s->ring_fault);
    p = append_str(line, p, sizeof(line), " r_unres=");
    p = append_u32(line, p, sizeof(line), s->ring_unresolved);
    p = append_str(line, p, sizeof(line), " trunc=");
    p = append_u32(line, p, sizeof(line), s->log_truncated);
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 1);
}

static int sample_changed(const struct sample *a, const struct sample *b) {
    return a->valid_cam != b->valid_cam || a->drive_act != b->drive_act ||
           a->still_size != b->still_size || a->still_asp != b->still_asp ||
           a->jpeg_qual != b->jpeg_qual || a->file_fmt != b->file_fmt ||
           a->bk_valid != b->bk_valid || a->bk_val != b->bk_val || a->bk_rc != b->bk_rc ||
           a->sub_ok != b->sub_ok || a->sub_enabled != b->sub_enabled ||
           a->half_ok != b->half_ok || a->half_raw != b->half_raw ||
           a->full_ok != b->full_ok || a->full_raw != b->full_raw ||
           a->elig != b->elig || a->tog != b->tog || a->gate != b->gate;
}

/* --- Ring child supervision --- */
static u32 generate_ring_token(struct daemon_state *s, u32 now_val) {
    u32 tok = 0;
    s32 fd = sys_call(SYS_OPEN, (u32)"/dev/urandom", O_RDONLY, 0, 0, 0, 0);
    if (fd >= 0) {
        s32 n = sys_call(SYS_READ, (u32)fd, (u32)&tok, 4u, 0, 0, 0);
        sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
        if (n != 4) tok = 0;
    }
    if (!tok) {
        tok = (now_val * 2654435761u) ^ (s->self_pid << 16) ^ ((s->ring_seq + 1u) * 0x9e3779b1u);
    }
    if ((tok & 0xfffffu) == 0u) tok |= 0x13579u;
    return tok;
}

static int ring_write_disarm(struct daemon_state *s, u32 t_ms, const char *why) {
    if (s->ring_disarm_sent) return 1;
    if (file_exists_ro(s->disarm_path)) {
        s->ring_disarm_sent = 1u;
        s->ring_disarm_err_logged = 0u;
        log_ring_evt(s, t_ms, why, (u32)s->ring_pid, 1u, 0u, 0u);
        return 1;
    }
    s32 fd = sys_call(SYS_OPEN, (u32)s->disarm_path, O_WRONLY | O_CREAT | O_EXCL, 0600u, 0, 0, 0);
    if (fd >= 0) {
        /* File creation itself is the disarm marker; write body best-effort. */
        sys_call(SYS_WRITE, (u32)fd, (u32)"disarm\n", 7u, 0, 0, 0);
        sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
    } else if (fd != -17 /* -EEXIST */) {
        if (!s->ring_disarm_err_logged) {
            s->ring_disarm_err_logged = 1u;
            log_ring_evt(s, t_ms, "DISARM_ERR", (u32)s->ring_pid, (u32)(-fd), 0u, 0u);
        }
        return 0;
    }
    if (!file_exists_ro(s->disarm_path)) {
        if (!s->ring_disarm_err_logged) {
            s->ring_disarm_err_logged = 1u;
            log_ring_evt(s, t_ms, "DISARM_ERR", (u32)s->ring_pid, 2u, 0u, 0u);
        }
        return 0;
    }
    s->ring_disarm_sent = 1u;
    s->ring_disarm_err_logged = 0u;
    log_ring_evt(s, t_ms, why, (u32)s->ring_pid, 0u, 0u, 0u);
    return 1;
}

static void handle_ring_m7cap_line(struct daemon_state *s, u32 t_ms, const char *line, u32 len) {
    if (len != 103u) return;
    const char prefix[] = "M7CAP1=";
    for (u32 i = 0; i < 7u; ++i) if (line[i] != prefix[i]) return;
    u32 f[12];
    for (u32 i = 0; i < 12u; ++i) {
        if (!parse_hex8(line + 7u + i * 8u, &f[i])) return;
    }
    if (f[0] != s->ring_cfg.cfg.token) return;
    ++s->ring_events_seen;
    u32 kind = f[1], stage = f[4];
    if (kind == 13u && stage == 98u) {
        s->ring_unresolved = 1u;
        s->ring_fault = 1u;
        log_ring_evt(s, t_ms, "UNRESOLVED", f[5], f[6], f[7], f[3]);
    } else if (kind == 60u && (stage == 1u || stage == 2u || stage == 3u || stage == 4u || stage == 9u || stage == 90u)) {
        log_ring_evt(s, t_ms, stage == 90u ? "ABORT" : "SESSION", stage, f[5], f[6], f[7]);
    } else if (kind == 92u) {
        if (stage == 55u) {
            u32 prev_p = f[5], next_p = f[6];
            int legal = (prev_p == s->ring_phase) && (
                (prev_p == 0u && next_p == 1u) ||
                (prev_p == 1u && (next_p == 2u || next_p == 3u)) ||
                (prev_p == 2u && next_p == 3u) ||
                (prev_p == 3u && next_p == 4u));
            if (legal) {
                s->ring_phase = next_p;
                log_ring_evt(s, t_ms, "PHASE", prev_p, next_p, f[8], f[10]);
            } else {
                log_ring_evt(s, t_ms, "PHASE_BAD", prev_p, next_p, s->ring_phase, f[10]);
                if (!s->ring_disarm_pending) {
                    s->ring_disarm_pending = 1u;
                    s->ring_disarm_reason = 2u;
                }
            }
        } else if (stage == 1u) {
            log_ring_evt(s, t_ms, "READY", f[5], f[6], f[7], f[3]);
        } else if (stage == 2u) {
            log_ring_evt(s, t_ms, "TRIGGER", f[5], f[7], f[10], f[11]);
        } else if (stage == 8u) {
            s->ring_saved_total += f[8];
            log_ring_evt(s, t_ms, "SUMMARY", f[5], f[6], f[7], (f[8] << 16) | (f[9] & 0xffffu));
        } else if (stage == 62u) {
            log_ring_evt(s, t_ms, "CADENCE", f[5], f[6], f[7], f[8]);
            log_ring_evt(s, t_ms, "WINDOW", f[9], f[10], f[11] >> 16, f[11] & 0xffffu);
        }
    } else if (kind == 21u && stage == 10u) {
        log_ring_file(s, t_ms, f[9], f[10], f[6], f[5]);
    } else if (kind == 9u) {
        log_ring_evt(s, t_ms, "FINAL", f[4], f[6], f[9], f[10]);
    }
}

static void drain_ring_pipe(struct daemon_state *s, u32 t_ms, u32 max_rounds) {
    if (s->ring_out_fd < 0) return;
    for (u32 rounds = 0; rounds < max_rounds; ++rounds) {
        s32 n = sys_call(SYS_READ, (u32)s->ring_out_fd, (u32)s->ring_pipe_buf, sizeof(s->ring_pipe_buf), 0, 0, 0);
        if (n > 0 && (u32)n <= sizeof(s->ring_pipe_buf)) {
            for (s32 i = 0; i < n; ++i) {
                char ch = (char)s->ring_pipe_buf[i];
                if (ch == '\n') {
                    if (!s->ring_line_skip && s->ring_line_len > 0u) {
                        s->ring_line[s->ring_line_len] = 0;
                        handle_ring_m7cap_line(s, t_ms, s->ring_line, s->ring_line_len);
                    }
                    s->ring_line_len = 0u;
                    s->ring_line_skip = 0u;
                } else if (ch != '\r') {
                    if (s->ring_line_len + 1u < sizeof(s->ring_line)) {
                        s->ring_line[s->ring_line_len++] = ch;
                    } else {
                        s->ring_line_skip = 1u;
                    }
                }
            }
            continue;
        }
        if (n == -4) continue;
        if (n == -11) break;
        /* EOF (n == 0) or runtime pipe error (n < 0 or short/impossible read). */
        sys_call(SYS_CLOSE, (u32)s->ring_out_fd, 0, 0, 0, 0, 0);
        s->ring_out_fd = -1;
        if (n != 0 && !s->ring_disarm_pending) {
            s->ring_disarm_pending = 1u;
            s->ring_disarm_reason = 2u;
        }
        break;
    }
}

static int poll_ring_exit(struct daemon_state *s, u32 now_val, u32 t_ms) {
    if (s->ring_pid <= 0) return 0;
    drain_ring_pipe(s, t_ms, 64u);
    u32 wst = 0;
    s32 w = sys_call(SYS_WAIT4, (u32)s->ring_pid, (u32)&wst, WNOHANG, 0, 0, 0);
    if (w != s->ring_pid && w != -10) return 0;

    /* Final drain of any remaining buffered pipe data after child exit. */
    drain_ring_pipe(s, t_ms, 2048u);
    if (s->ring_out_fd >= 0) {
        sys_call(SYS_CLOSE, (u32)s->ring_out_fd, 0, 0, 0, 0, 0);
        s->ring_out_fd = -1;
    }
    sys_call(SYS_UNLINK, (u32)s->disarm_path, 0, 0, 0, 0, 0);

    u32 sig = wst & 0x7fu;
    u32 rc = (wst >> 8) & 0xffu;
    int clean_ok = (w == s->ring_pid && sig == 0u && rc == 0u && !s->ring_unresolved);
    if (clean_ok) ++s->ring_ok_runs;
    else s->ring_fault = 1u;

    char line[256];
    u32 p = 0;
    p = append_str(line, p, sizeof(line), "RING_EXIT t=");
    p = append_u32(line, p, sizeof(line), t_ms);
    p = append_str(line, p, sizeof(line), " seq=");
    p = append_u32(line, p, sizeof(line), s->ring_seq);
    p = append_str(line, p, sizeof(line), " pid=");
    p = append_s32(line, p, sizeof(line), s->ring_pid);
    p = append_str(line, p, sizeof(line), " st=");
    p = append_hex(line, p, sizeof(line), wst);
    p = append_str(line, p, sizeof(line), " rc=");
    p = append_u32(line, p, sizeof(line), rc);
    p = append_str(line, p, sizeof(line), " sig=");
    p = append_u32(line, p, sizeof(line), sig);
    p = append_str(line, p, sizeof(line), " ev_n=");
    p = append_u32(line, p, sizeof(line), s->ring_events_seen);
    p = append_str(line, p, sizeof(line), " unres=");
    p = append_u32(line, p, sizeof(line), s->ring_unresolved);
    p = append_str(line, p, sizeof(line), " fault=");
    p = append_u32(line, p, sizeof(line), s->ring_fault);
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 0);

    s->ring_pid = -1;
    s->ring_disarm_sent = 0u;
    s->ring_disarm_pending = 0u;
    s->ring_disarm_reason = 0u;
    s->ring_disarm_err_logged = 0u;
    s->ring_bad_gate_streak = 0u;
    s->ring_phase = 0u;
    s->last_ring_exit_ms = now_val;
    s->has_ring_exited = 1u;
    s->seen_idle = 0u;
    s->half_pending = 0u;
    s->half_prep_done = 0u;
    s->half_prep_token = 0u;
    s->half_fresh_req_armed = 0u;
    s->half_need_bk_seq = 0u;
    return 1;
}

static int write_ring_cfg_atomic(struct daemon_state *s, u32 token) {
    struct s6_ring_cfg_file *f = &s->ring_cfg;
    __aeabi_memclr8(f, sizeof(*f));
    f->magic = S6_RING_CFG_MAGIC;
    f->version = S6_RING_CFG_VERSION;
    f->total_bytes = (u32)sizeof(*f);
    for (u32 i = 0; i < S6_NONCE_LEN; ++i) f->nonce[i] = m7_s6_daemon_config.nonce[i];

    f->cfg.magic = 0x3143504du;
    f->cfg.version = 6u;
    f->cfg.token = token;
    f->cfg.pid = s->im_pid;
    f->cfg.bias = s->libobj_bias;
    f->cfg.nranges = s->nranges;
    f->cfg.interval_ms = 2u;
    f->cfg.focus_ms = m7_s6_daemon_config.focus_ms;
    f->cfg.settle_ms = 1500u;
    f->cfg.diagnose_only = 0u;
    f->cfg.retain_check = 11u;
    f->cfg.monitor_tid = s->mon_tid_proc;
    f->cfg.mpr_bias = s->mpr_bias;
    f->cfg.mprctrl_bias = s->mprctrl_bias;
    f->cfg.mwf_bias = s->mwf_bias;
    for (u32 i = 0; i < s->nranges && i < MAX_RANGES; ++i) f->cfg.ranges[i] = s->ranges[i];

    f->precap.magic = 0x32525043u;
    f->precap.revision = 8u;
    f->precap.before = m7_s6_daemon_config.before;
    f->precap.after = m7_s6_daemon_config.after;
    f->precap.backlog_cap = m7_s6_daemon_config.backlog_cap;
    f->precap.sample_ms = 25u;
    f->precap.window_ms = 120000u;
    f->precap.drain_ms = 5000u;
    f->precap.burst_cap = m7_s6_daemon_config.burst_cap;
    f->precap.post_max = m7_s6_daemon_config.post_max;

    f->checksum = s6_ring_cfg_checksum(f);

    sys_call(SYS_UNLINK, (u32)s->cfg_tmp_path, 0, 0, 0, 0, 0);
    s32 fd = sys_call(SYS_OPEN, (u32)s->cfg_tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600u, 0, 0, 0);
    if (fd < 0) return 0;
    const u8 *raw = (const u8 *)f;
    u32 total = (u32)sizeof(*f), sent = 0, tries = 0;
    while (sent < total && tries++ < 64u) {
        s32 n = sys_call(SYS_WRITE, (u32)fd, (u32)(raw + sent), total - sent, 0, 0, 0);
        if (n == -4) continue;
        if (n <= 0 || (u32)n > total - sent) break;
        sent += (u32)n;
    }
    sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
    if (sent != total) {
        sys_call(SYS_UNLINK, (u32)s->cfg_tmp_path, 0, 0, 0, 0, 0);
        return 0;
    }
    if (sys_call(SYS_RENAME, (u32)s->cfg_tmp_path, (u32)s->cfg_path, 0, 0, 0, 0) != 0) {
        sys_call(SYS_UNLINK, (u32)s->cfg_tmp_path, 0, 0, 0, 0, 0);
        return 0;
    }
    return 1;
}

static const char *disarm_reason_str(u32 reason) {
    if (reason == 2u) return "DISARM_PIPE_ERR";
    if (reason == 3u) return "DISARM_STOP";
    return "DISARM_GATE";
}

static int prepare_ring_launch(struct daemon_state *s, u32 now_val) {
    if (s->ring_pid > 0 || s->ring_fault || !s->ring_exe_ok) return 0;
    if (!file_confirmed_absent(s->stop_path)) return 0;

    /* Refresh maps & verify monitor TID and publish run.cfg BEFORE requesting the final Backup ON witness. */
    if (!parse_im_maps(s, 0)) return 0;
    ++s->maps_refreshes;
    s->last_maps_refresh_ms = now_val;
    discover_monitor_tid(s);
    if (!s->mon_tid_proc || s->mon_tid_proc != s->mon_tid_mwf) return 0;

    u32 token = generate_ring_token(s, now_val);
    if (!write_ring_cfg_atomic(s, token)) return 0;
    s32 urc = sys_call(SYS_UNLINK, (u32)s->disarm_path, 0, 0, 0, 0, 0);
    if ((urc != 0 && urc != -2 /* -ENOENT */) || !file_confirmed_absent(s->disarm_path)) return 0;

    s->half_prep_done = 1u;
    s->half_prep_token = token;
    return 1;
}

static int fork_prepared_ring(struct daemon_state *s, u32 min_rem) {
    if (s->ring_pid > 0 || s->ring_fault || !s->ring_exe_ok || s->uipc_inflight || !s->half_prep_done) return 0;
    /* Consume this prepared attempt & ON witness unconditionally so any failure forces fresh post-prep re-verification! */
    u32 token = s->half_prep_token;
    s->half_prep_done = 0u;
    s->half_prep_token = 0u;
    s->half_fresh_req_armed = 0u;
    s->half_need_bk_seq = 0u;

    /* Allocate output pipe BEFORE the final stop/lifetime admission check so pipe latency cannot bypass teardown margin. */
    s32 pfd[2] = {-1, -1};
    if (sys_call(SYS_PIPE, (u32)pfd, 0, 0, 0, 0, 0) != 0) return 0;

    /* Final pre-fork recheck: gate/shutter, then confirmed stop absence, then clock/teardown margin LAST before fork(). */
    struct sample chk;
    __aeabi_memclr8(&chk, sizeof(chk));
    read_cam_params(s, &chk);
    apply_last_bk(s, &chk);
    read_subscription(s, &chk);
    read_shutter(s, &chk);
    compute_gates(s, &chk);
    int stop_absent = file_confirmed_absent(s->stop_path);
    u32 chk_now = s->started_ms;
    int clk_ok = now_ms_checked(&chk_now);
    u32 chk_el = clk_ok ? (u32)(chk_now - s->started_ms) : m7_s6_daemon_config.duration_ms;
    if (!chk.gate || chk.half_raw != 1u || chk.full_raw != 0u ||
        !stop_absent || !clk_ok ||
        chk_el >= m7_s6_daemon_config.duration_ms ||
        (m7_s6_daemon_config.duration_ms - chk_el) < min_rem) {
        sys_call(SYS_CLOSE, (u32)pfd[0], 0, 0, 0, 0, 0);
        sys_call(SYS_CLOSE, (u32)pfd[1], 0, 0, 0, 0, 0);
        return 0;
    }

    s32 cpid = sys_call(SYS_FORK, 0, 0, 0, 0, 0, 0);
    if (cpid < 0) {
        sys_call(SYS_CLOSE, (u32)pfd[0], 0, 0, 0, 0, 0);
        sys_call(SYS_CLOSE, (u32)pfd[1], 0, 0, 0, 0, 0);
        return 0;
    }
    if (cpid == 0) {
        /* Keep SIGINT/SIGTERM blocked across execve so group signals cannot kill ring.elf mid-trap! */
        sys_call(SYS_CLOSE, (u32)pfd[0], 0, 0, 0, 0, 0);
        if (s->mem_fd >= 0) sys_call(SYS_CLOSE, (u32)s->mem_fd, 0, 0, 0, 0, 0);
        if (m7_s6_daemon_config.daemonize && s->log_fd >= 0) sys_call(SYS_CLOSE, (u32)s->log_fd, 0, 0, 0, 0, 0);
        if (s->req_fd >= 0) sys_call(SYS_CLOSE, (u32)s->req_fd, 0, 0, 0, 0, 0);
        if (s->rep_fd >= 0) sys_call(SYS_CLOSE, (u32)s->rep_fd, 0, 0, 0, 0, 0);
        if (sys_call(SYS_DUP2, (u32)pfd[1], 1u, 0, 0, 0, 0) < 0) sys_call(SYS_EXIT, 125u, 0, 0, 0, 0, 0);
        s32 nfd = sys_call(SYS_OPEN, (u32)"/dev/null", O_RDWR, 0, 0, 0, 0);
        if (nfd < 0) sys_call(SYS_EXIT, 126u, 0, 0, 0, 0, 0);
        if (sys_call(SYS_DUP2, (u32)nfd, 0u, 0, 0, 0, 0) < 0 ||
            sys_call(SYS_DUP2, (u32)nfd, 2u, 0, 0, 0, 0) < 0) {
            sys_call(SYS_EXIT, 126u, 0, 0, 0, 0, 0);
        }
        if (nfd > 2) sys_call(SYS_CLOSE, (u32)nfd, 0, 0, 0, 0, 0);
        for (u32 fd = 3u; fd < 64u; ++fd) sys_call(SYS_CLOSE, fd, 0, 0, 0, 0, 0);
        const char *argv[2] = { s->ring_exe_path, 0 };
        const char *envp[1] = { 0 };
        sys_call(SYS_EXECVE, (u32)s->ring_exe_path, (u32)argv, (u32)envp, 0, 0, 0);
        sys_call(SYS_EXIT, 127u, 0, 0, 0, 0, 0);
    }
    /* Sample fork boundary timestamp immediately on parent return BEFORE descriptor setup! */
    u32 post_now = chk_now;
    if (now_ms_checked(&post_now)) {
        chk_now = post_now;
        chk_el = (u32)(chk_now - s->started_ms);
    }
    sys_call(SYS_CLOSE, (u32)pfd[1], 0, 0, 0, 0, 0);
    int pipe_nonblock_ok = 1;
    if (sys_call(SYS_FCNTL, (u32)pfd[0], F_SETFL, O_NONBLOCK, 0, 0, 0) < 0) {
        sys_call(SYS_CLOSE, (u32)pfd[0], 0, 0, 0, 0, 0);
        pfd[0] = -1;
        pipe_nonblock_ok = 0;
    }

    s->ring_pid = cpid;
    s->ring_out_fd = pfd[0];
    ++s->ring_seq;
    ++s->ring_runs;
    s->ring_disarm_sent = 0u;
    s->ring_disarm_pending = 0u;
    s->ring_disarm_reason = 0u;
    s->ring_disarm_err_logged = 0u;
    s->ring_bad_gate_streak = 0u;
    s->ring_phase = 0u;
    s->ring_events_seen = 0u;
    s->ring_line_len = 0u;
    s->ring_line_skip = 0u;
    s->ring_started_ms = chk_now;
    s->seen_idle = 0u;
    s->half_pending = 0u;
    if (!pipe_nonblock_ok) {
        s->ring_disarm_pending = 1u;
        s->ring_disarm_reason = 2u;
        ring_write_disarm(s, chk_el, disarm_reason_str(s->ring_disarm_reason));
    }

    char line[224];
    u32 p = 0;
    p = append_str(line, p, sizeof(line), "RING_START t=");
    p = append_u32(line, p, sizeof(line), chk_el);
    p = append_str(line, p, sizeof(line), " seq=");
    p = append_u32(line, p, sizeof(line), s->ring_seq);
    p = append_str(line, p, sizeof(line), " pid=");
    p = append_s32(line, p, sizeof(line), cpid);
    p = append_str(line, p, sizeof(line), " tok=");
    p = append_hex(line, p, sizeof(line), token);
    p = append_str(line, p, sizeof(line), " ranges=");
    p = append_u32(line, p, sizeof(line), s->nranges);
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 0);
    return 1;
}

static void wait_ring_shutdown(struct daemon_state *s, const u32 *sigmask) {
    if (s->ring_shutdown_done) return;
    s->ring_shutdown_done = 1u;
    if (s->ring_pid <= 0) { s->ring_reaped_final = 1u; return; }
    s->ring_disarm_pending = 1u;
    if (!s->ring_disarm_reason) s->ring_disarm_reason = 3u;
    const char *why = disarm_reason_str(s->ring_disarm_reason);
    u32 start_w = s->started_ms;
    int start_ok = now_ms_checked(&start_w);
    ring_write_disarm(s, start_ok ? (u32)(start_w - s->started_ms) : 0u, why);

    u32 max_loops = (RING_STOP_HARD_MAX_MS / 25u) + 20u;
    u32 last_ev = s->ring_events_seen;
    u32 last_prog_w = start_w;
    u32 idle_loops = 0u;
    u32 idle_max_loops = (RING_STOP_WAIT_MS / 25u) + 20u;
    for (u32 loop = 0; loop <= max_loops; ++loop) {
        u32 tv = start_w;
        int clk_ok = now_ms_checked(&tv);
        u32 t_ms = clk_ok ? (u32)(tv - s->started_ms) : (u32)(start_w - s->started_ms);
        if (!s->ring_disarm_sent) ring_write_disarm(s, t_ms, why);
        if (poll_ring_exit(s, tv, t_ms)) {
            s->ring_reaped_final = 1u;
            return;
        }
        if (s->ring_events_seen != last_ev) {
            last_ev = s->ring_events_seen;
            if (clk_ok) last_prog_w = tv;
            idle_loops = 0u;
        } else {
            ++idle_loops;
        }
        /* NEVER SIGKILL a live ring.elf: it may hold a 0xde01 trap in im.elf! */
        if (s->ring_unresolved || loop >= max_loops || idle_loops >= idle_max_loops ||
            (start_ok && clk_ok && (u32)(tv - start_w) >= RING_STOP_HARD_MAX_MS) ||
            (start_ok && clk_ok && (u32)(tv - last_prog_w) >= RING_STOP_WAIT_MS)) {
            s->ring_reaped_final = 0u;
            return;
        }
        u32 ts[2] = {0u, 25000000u};
        sys_call(SYS_RT_SIGTIMEDWAIT, (u32)sigmask, 0u, (u32)ts, 8u, 0, 0);
    }
}

static int write_pid_file(struct daemon_state *s) {
    char buf[16];
    u32 p = append_u32(buf, 0, sizeof(buf), s->self_pid);
    buf[p++] = '\n';
    s32 fd = sys_call(SYS_OPEN, (u32)s->pid_path, O_WRONLY | O_CREAT | O_EXCL, 0600u, 0, 0, 0);
    if (fd < 0) return 0;
    s32 wr = sys_call(SYS_WRITE, (u32)fd, (u32)buf, p, 0, 0, 0);
    sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
    if (wr != (s32)p) {
        sys_call(SYS_UNLINK, (u32)s->pid_path, 0, 0, 0, 0, 0);
        return 0;
    }
    s->pid_published = 1u;
    return 1;
}

static int daemonize_self(void) {
    s32 pid1 = sys_call(SYS_FORK, 0, 0, 0, 0, 0, 0);
    if (pid1 < 0) return -1;
    if (pid1 > 0) {
        u32 st = 0;
        s32 w = sys_call(SYS_WAIT4, (u32)pid1, (u32)&st, 0, 0, 0, 0);
        if (w != pid1 || (st & 0xffu) != 0u || ((st >> 8) & 0xffu) != 0u) return -2;
        return 1;
    }
    if (sys_call(SYS_SETSID, 0, 0, 0, 0, 0, 0) < 0) sys_call(SYS_EXIT, 21u, 0, 0, 0, 0, 0);
    u32 ign[5] = {1u, 0u, 0u, 0u, 0u};
    if (sys_call(SYS_RT_SIGACTION, 1u, (u32)ign, 0, 8u, 0, 0) != 0 ||
        sys_call(SYS_RT_SIGACTION, 13u, (u32)ign, 0, 8u, 0, 0) != 0) {
        sys_call(SYS_EXIT, 22u, 0, 0, 0, 0, 0);
    }
    s32 pid2 = sys_call(SYS_FORK, 0, 0, 0, 0, 0, 0);
    if (pid2 < 0) sys_call(SYS_EXIT, 23u, 0, 0, 0, 0, 0);
    if (pid2 > 0) sys_call(SYS_EXIT, 0u, 0, 0, 0, 0, 0);

    if (sys_call(SYS_CHDIR, (u32)"/", 0, 0, 0, 0, 0) != 0) sys_call(SYS_EXIT, 24u, 0, 0, 0, 0, 0);
    s32 nullfd = sys_call(SYS_OPEN, (u32)"/dev/null", O_RDWR, 0, 0, 0, 0);
    if (nullfd < 0) sys_call(SYS_EXIT, 25u, 0, 0, 0, 0, 0);
    if (sys_call(SYS_DUP2, (u32)nullfd, 0u, 0, 0, 0, 0) < 0 ||
        sys_call(SYS_DUP2, (u32)nullfd, 1u, 0, 0, 0, 0) < 0 ||
        sys_call(SYS_DUP2, (u32)nullfd, 2u, 0, 0, 0, 0) < 0) {
        sys_call(SYS_EXIT, 26u, 0, 0, 0, 0, 0);
    }
    if (nullfd > 2) sys_call(SYS_CLOSE, (u32)nullfd, 0, 0, 0, 0, 0);
    for (u32 fd = 3u; fd < 64u; ++fd) sys_call(SYS_CLOSE, fd, 0, 0, 0, 0, 0);
    return 0;
}

int daemon_main(void) {
    char nonce_copy[S6_NONCE_LEN];
    for (u32 i = 0; i < S6_NONCE_LEN; ++i) nonce_copy[i] = m7_s6_daemon_config.nonce[i];
    if (m7_s6_daemon_config.magic != S6_DAEMON_MAGIC ||
        m7_s6_daemon_config.version != S6_DAEMON_VERSION ||
        m7_s6_daemon_config.poll_ms < 10u || m7_s6_daemon_config.poll_ms > 1000u ||
        m7_s6_daemon_config.duration_ms < 100u || m7_s6_daemon_config.duration_ms > 3600000u ||
        m7_s6_daemon_config.heartbeat_ms < 100u || m7_s6_daemon_config.heartbeat_ms > 60000u ||
        m7_s6_daemon_config.max_log_bytes < 2048u || m7_s6_daemon_config.max_log_bytes > 262144u ||
        m7_s6_daemon_config.daemonize > 1u ||
        m7_s6_daemon_config.toggle_bkid == 0u ||
        m7_s6_daemon_config.toggle_on_val > 1u ||
        m7_s6_daemon_config.before < 1u || m7_s6_daemon_config.before > 15u ||
        m7_s6_daemon_config.after > 64u ||
        m7_s6_daemon_config.burst_cap < 8u || m7_s6_daemon_config.burst_cap > 60u ||
        m7_s6_daemon_config.burst_cap < m7_s6_daemon_config.before + 4u ||
        m7_s6_daemon_config.backlog_cap < 24u || m7_s6_daemon_config.backlog_cap > 128u ||
        m7_s6_daemon_config.backlog_cap < m7_s6_daemon_config.burst_cap + 16u ||
        m7_s6_daemon_config.post_max < 1u || m7_s6_daemon_config.post_max > 96u ||
        m7_s6_daemon_config.before + m7_s6_daemon_config.post_max > 112u ||
        m7_s6_daemon_config.debounce_ms > 2000u ||
        m7_s6_daemon_config.focus_ms < 100u || m7_s6_daemon_config.focus_ms > 1500u ||
        !s6_valid_nonce_chars(nonce_copy)) {
        return 2;
    }

    if (m7_s6_daemon_config.daemonize) {
        int drc = daemonize_self();
        if (drc < 0) return 3;
        if (drc > 0) return 0;
    } else {
        u32 ign[5] = {1u, 0u, 0u, 0u, 0u};
        if (sys_call(SYS_RT_SIGACTION, 1u, (u32)ign, 0, 8u, 0, 0) != 0 ||
            sys_call(SYS_RT_SIGACTION, 13u, (u32)ign, 0, 8u, 0, 0) != 0) {
            return 3;
        }
    }

    u32 sigmask[2] = {(1u << 1) | (1u << 14), 0u};
    if (sys_call(SYS_RT_SIGPROCMASK, 0u, (u32)sigmask, 0, 8u, 0, 0) != 0) return 4;

    u32 state_bytes = (sizeof(struct daemon_state) + 4095u) & ~4095u;
    s32 mem = sys_call(SYS_MMAP2, 0u, state_bytes, 3u, 0x22u, 0xffffffffu, 0u);
    if ((u32)mem >= 0xfffff000u) return 5;
    struct daemon_state *s = (struct daemon_state *)(u32)mem;
    __aeabi_memclr8(s, sizeof(*s));
    s->mem_fd = -1;
    s->log_fd = -1;
    s->uipc_fd = -1;
    s->worker_pid = -1;
    s->req_fd = -1;
    s->rep_fd = -1;
    s->ring_pid = -1;
    s->ring_out_fd = -1;
    s->ring_reaped_final = 1u;
    s->last_bk.bk_val = 0xffffffffu;
    s->last_bk.bk_rc = -19;
    build_run_paths(s);

    s->self_pid = (u32)sys_call(SYS_GETPID, 0, 0, 0, 0, 0, 0);
    int exit_rc = 0;

    if (m7_s6_daemon_config.daemonize) {
        s->log_fd = sys_call(SYS_OPEN, (u32)s->log_path, O_WRONLY | O_CREAT | O_EXCL, 0600u, 0, 0, 0);
        if (s->log_fd < 0) { exit_rc = 6; goto cleanup; }
    } else {
        s->log_fd = 1;
    }

    if (!now_ms_checked(&s->started_ms)) {
        log_stop(s, 0u, 0u, "clock_fail", 0);
        exit_rc = 7;
        goto cleanup;
    }
    s->last_maps_refresh_ms = s->started_ms;
    s->ring_exe_ok = (u32)file_exists_ro(s->ring_exe_path);

    if (!discover_im_pid(s)) {
        log_stop(s, 0u, 0u, "no_im_pid", 0);
        exit_rc = 10;
        goto cleanup;
    }
    if (!parse_im_maps(s, 1)) {
        log_stop(s, 0u, 0u, "maps_fail", 0);
        exit_rc = 11;
        goto cleanup;
    }
    char mpath[48];
    build_proc_subpath(mpath, sizeof(mpath), s->im_pid, "/mem");
    s->mem_fd = sys_call(SYS_OPEN, (u32)mpath, O_RDONLY, 0, 0, 0, 0);
    if (s->mem_fd < 0) {
        log_stop(s, 0u, 0u, "mem_open_fail", s->mem_fd);
        exit_rc = 12;
        goto cleanup;
    }

    discover_monitor_tid(s);
    init_input_watch(s);

    u32 t0 = s->started_ms;
    if (!now_ms_checked(&t0)) {
        log_stop(s, 0u, 0u, "clock_fail", 0);
        exit_rc = 7;
        goto cleanup;
    }
    if ((u32)(t0 - s->started_ms) >= m7_s6_daemon_config.duration_ms) {
        u32 trig = (u32)(t0 - s->started_ms);
        log_stop(s, trig, trig, "timeout", 0);
        goto cleanup;
    }
    if (stop_file_present(s)) {
        u32 trig = (u32)(t0 - s->started_ms);
        log_stop(s, trig, trig, "stop_file", 0);
        goto cleanup;
    }

    if (start_uipc_worker(s, state_bytes)) {
        uipc_send_request(s, t0);
        for (u32 i = 0; i < 60u && s->uipc_inflight; ++i) {
            u32 tv = t0;
            if (!now_ms_checked(&tv)) {
                stop_uipc_worker(s, sigmask);
                log_stop(s, 0u, 0u, "clock_fail", 0);
                exit_rc = 7;
                goto cleanup;
            }
            u32 el = (u32)(tv - s->started_ms);
            if (el >= m7_s6_daemon_config.duration_ms) {
                uipc_fail_channel(s, -110);
                stop_uipc_worker(s, sigmask);
                u32 end_ms = tv;
                now_ms_checked(&end_ms);
                log_stop(s, (u32)(end_ms - s->started_ms), el, "timeout", 0);
                goto cleanup;
            }
            if (uipc_poll_reply(s, tv)) break;
            if (stop_file_present(s)) {
                stop_uipc_worker(s, sigmask);
                u32 end_ms = tv;
                now_ms_checked(&end_ms);
                log_stop(s, (u32)(end_ms - s->started_ms), el, "stop_file", 0);
                goto cleanup;
            }
            u32 rem_run = m7_s6_daemon_config.duration_ms - el;
            u32 ipc_el = (u32)(tv - s->uipc_req_ms);
            u32 rem_ipc = (ipc_el < UIPC_REPLY_TIMEOUT_MS) ? (UIPC_REPLY_TIMEOUT_MS - ipc_el) : 0u;
            u32 step_ms = 20u;
            if (rem_run < step_ms) step_ms = rem_run;
            if (rem_ipc < step_ms) step_ms = rem_ipc;
            if (!step_ms) { uipc_fail_channel(s, -110); break; }
            u32 ts[2] = {0u, step_ms * 1000000u};
            s32 sig = sys_call(SYS_RT_SIGTIMEDWAIT, (u32)sigmask, 0u, (u32)ts, 8u, 0, 0);
            if (sig == 15 || sig == 2) {
                stop_uipc_worker(s, sigmask);
                u32 end_ms = tv;
                now_ms_checked(&end_ms);
                log_stop(s, (u32)(end_ms - s->started_ms), el, "signal", sig);
                goto cleanup;
            }
            if (sig != -11 && sig != -4) {
                stop_uipc_worker(s, sigmask);
                u32 end_ms = tv;
                now_ms_checked(&end_ms);
                log_stop(s, (u32)(end_ms - s->started_ms), el, "sigwait_err", sig);
                exit_rc = 8;
                goto cleanup;
            }
        }
        if (s->uipc_inflight) uipc_fail_channel(s, -110);
    } else {
        s->uipc_err = -11;
    }

    u32 post_init = s->started_ms;
    if (!now_ms_checked(&post_init)) {
        stop_uipc_worker(s, sigmask);
        log_stop(s, 0u, 0u, "clock_fail", 0);
        exit_rc = 7;
        goto cleanup;
    }
    if ((u32)(post_init - s->started_ms) >= m7_s6_daemon_config.duration_ms) {
        u32 trig = (u32)(post_init - s->started_ms);
        stop_uipc_worker(s, sigmask);
        u32 end_ms = post_init;
        now_ms_checked(&end_ms);
        log_stop(s, (u32)(end_ms - s->started_ms), trig, "timeout", 0);
        goto cleanup;
    }

    struct sample cur;
    __aeabi_memclr8(&cur, sizeof(cur));
    read_cam_params(s, &cur);
    apply_last_bk(s, &cur);
    read_subscription(s, &cur);
    read_shutter(s, &cur);
    compute_gates(s, &cur);

    log_boot(s, &cur);
    log_state(s, (u32)(post_init - s->started_ms), &cur);
    s->prev = cur;
    s->has_prev = 1u;

    if (m7_s6_daemon_config.daemonize) {
        if (!write_pid_file(s)) {
            stop_uipc_worker(s, sigmask);
            u32 end_ms = post_init;
            now_ms_checked(&end_ms);
            log_stop(s, (u32)(end_ms - s->started_ms), (u32)(post_init - s->started_ms), "pid_write_fail", 0);
            exit_rc = 13;
            goto cleanup;
        }
    }

    u32 last_hb = 0u;
    u32 last_bk_ms = post_init;
    const char *stop_reason = "timeout";
    s32 stop_detail = 0;
    u32 trig_ms = 0u;

    for (;;) {
        u32 now_val = 0;
        if (!now_ms_checked(&now_val)) { stop_reason = "clock_fail"; break; }
        u32 elapsed = (u32)(now_val - s->started_ms);
        trig_ms = elapsed;
        if (elapsed >= m7_s6_daemon_config.duration_ms) { stop_reason = "timeout"; break; }
        if (stop_file_present(s)) { stop_reason = "stop_file"; break; }

        u32 rem_run = m7_s6_daemon_config.duration_ms - elapsed;
        /* Poll faster (10 ms) while ring.elf is active so stdout pipe drains promptly. */
        u32 sleep_ms = (s->ring_pid > 0 && m7_s6_daemon_config.poll_ms > 10u) ? 10u : m7_s6_daemon_config.poll_ms;
        if (rem_run < sleep_ms) sleep_ms = rem_run;
        u32 ts[2] = { sleep_ms / 1000u, (sleep_ms % 1000u) * 1000000u };
        s32 sig = sys_call(SYS_RT_SIGTIMEDWAIT, (u32)sigmask, 0u, (u32)ts, 8u, 0, 0);
        if (sig == 15 || sig == 2) {
            if (now_ms_checked(&now_val)) trig_ms = (u32)(now_val - s->started_ms);
            stop_reason = "signal"; stop_detail = sig; break;
        }
        if (sig != -11 && sig != -4) {
            if (now_ms_checked(&now_val)) trig_ms = (u32)(now_val - s->started_ms);
            stop_reason = "sigwait_err"; stop_detail = sig; break;
        }

        ++s->ticks;
        if (!now_ms_checked(&now_val)) { stop_reason = "clock_fail"; break; }
        elapsed = (u32)(now_val - s->started_ms);
        trig_ms = elapsed;
        if (elapsed >= m7_s6_daemon_config.duration_ms) { stop_reason = "timeout"; break; }
        if (stop_file_present(s)) { stop_reason = "stop_file"; break; }
        if (sys_call(SYS_KILL, s->im_pid, 0u, 0, 0, 0, 0) != 0) { stop_reason = "im_exit"; break; }
        if ((u32)(elapsed - last_hb) >= m7_s6_daemon_config.heartbeat_ms) {
            u32 st = 0;
            if (!read_proc_starttime(s->im_pid, &st) || st != s->im_starttime) {
                stop_reason = "im_reused";
                break;
            }
        }

        /* Reap/drain active ring child first. */
        poll_ring_exit(s, now_val, elapsed);

        /* Poll /dev/uipc Backup_read every 200 ms ONLY while idle (zero IPC during active ring capture). */
        uipc_poll_reply(s, now_val);
        if (s->ring_pid <= 0 && !s->uipc_inflight && !s->uipc_timed_out &&
            (u32)(now_val - last_bk_ms) >= 200u) {
            uipc_send_request(s, now_val);
            last_bk_ms = now_val;
            uipc_poll_reply(s, now_val);
        }

        struct sample next = s->prev;
        read_cam_params(s, &next);
        apply_last_bk(s, &next);
        read_subscription(s, &next);
        read_shutter(s, &next);
        compute_gates(s, &next);

        if (sample_changed(&s->prev, &next)) {
            log_state(s, elapsed, &next);
            s->prev = next;
        }

        if (s->ring_pid > 0) {
            /*
             * Disarm active ring cleanly if core gates drop for 5 ticks (~50 ms).
             * Sony's Insert4100/Pullout4100 briefly dip sub_en=0 (~930 ms) while Spinal/cam/elig/tog/shutter
             * remain valid: allow transient sub_en=0 during pre-arm phase 0 (bounded to 4000 ms) and
             * post-capture teardown phases >= 3, while enforcing sub_en==1 immediately in PRECAP_ARMED (1)
             * and PRECAP_POST (2) so Menu/Playback/mode switches disarm within ~50 ms.
             */
            u32 active_core_ok = (next.tog && next.elig && next.valid_cam && next.sub_ok &&
                                  next.half_ok && next.full_ok &&
                                  next.half_raw <= 1u && next.full_raw <= 1u &&
                                  !s->ring_fault) ? 1u : 0u;
            u32 active_gate_ok = active_core_ok;
            if (s->ring_phase == 1u || s->ring_phase == 2u) {
                if (!next.sub_enabled) active_gate_ok = 0u;
            } else if (s->ring_phase == 0u) {
                if (!next.sub_enabled && (u32)(now_val - s->ring_started_ms) >= 4000u) {
                    active_gate_ok = 0u;
                }
            }
            if (!active_gate_ok) {
                ++s->ring_bad_gate_streak;
                if (s->ring_bad_gate_streak >= 5u && !s->ring_disarm_pending) {
                    s->ring_disarm_pending = 1u;
                    s->ring_disarm_reason = 1u;
                }
            } else {
                s->ring_bad_gate_streak = 0u;
            }
            /* Once cancellation is decided for this child, keep retrying until confirmed or child exits. */
            if (s->ring_disarm_pending && !s->ring_disarm_sent) {
                ring_write_disarm(s, elapsed, disarm_reason_str(s->ring_disarm_reason));
            }
        } else if (next.gate && !s->ring_fault && s->ring_exe_ok) {
            u32 cooldown_ok = !s->has_ring_exited || (u32)(now_val - s->last_ring_exit_ms) >= RING_COOLDOWN_MS;
            if (next.half_ok && next.full_ok && next.half_raw == 0u && next.full_raw == 0u) {
                if (cooldown_ok) s->seen_idle = 1u;
                s->half_pending = 0u;
                s->half_prep_done = 0u;
                s->half_prep_token = 0u;
                s->half_fresh_req_armed = 0u;
                s->half_need_bk_seq = 0u;
            } else if (s->seen_idle && next.half_ok && next.full_ok &&
                       next.half_raw == 1u && next.full_raw == 0u) {
                if (!s->half_pending) {
                    s->half_pending = 1u;
                    s->half_since_ms = now_val;
                    s->half_prep_done = 0u;
                    s->half_prep_token = 0u;
                    s->half_fresh_req_armed = 0u;
                    s->half_need_bk_seq = 0u;
                }
                u32 rem_launch = (elapsed < m7_s6_daemon_config.duration_ms)
                                 ? (m7_s6_daemon_config.duration_ms - elapsed) : 0u;
                /* Allow launch if remaining lifetime covers teardown margin (or in short offline tests). */
                u32 min_rem = (m7_s6_daemon_config.duration_ms >= 30000u) ? RING_MIN_REMAIN_MS : 200u;
                if ((u32)(now_val - s->half_since_ms) >= m7_s6_daemon_config.debounce_ms &&
                    rem_launch >= min_rem) {
                    /* Step 1: Finish potentially slow maps/TID/run.cfg preparation BEFORE requesting final ON witness. */
                    if (!s->half_prep_done) {
                        if (!prepare_ring_launch(s, now_val)) goto next_tick_hb;
                        if (!now_ms_checked(&now_val)) { stop_reason = "clock_fail"; break; }
                        elapsed = (u32)(now_val - s->started_ms);
                        trig_ms = elapsed;
                        if (elapsed >= m7_s6_daemon_config.duration_ms) { stop_reason = "timeout"; break; }
                        if (stop_file_present(s)) { stop_reason = "stop_file"; break; }
                        rem_launch = m7_s6_daemon_config.duration_ms - elapsed;
                        if (rem_launch < min_rem) {
                            s->half_prep_done = 0u;
                            s->half_prep_token = 0u;
                            goto next_tick_hb;
                        }
                        uipc_poll_reply(s, now_val);
                    }
                    /* Step 2: Arm & collect a fresh Backup_read started AFTER preparation completed. */
                    if (!s->half_fresh_req_armed) {
                        s->half_fresh_req_armed = 1u;
                        s->half_need_bk_seq = s->bk_reply_seq + (s->uipc_inflight ? 2u : 1u);
                    }
                    if (!s->uipc_inflight && !s->uipc_timed_out && s->bk_reply_seq < s->half_need_bk_seq) {
                        uipc_send_request(s, now_val);
                        last_bk_ms = now_val;
                        uipc_poll_reply(s, now_val);
                    }
                    /* Refresh live post-prep state before admitting fork. */
                    read_cam_params(s, &next);
                    apply_last_bk(s, &next);
                    read_subscription(s, &next);
                    read_shutter(s, &next);
                    compute_gates(s, &next);
                    if (sample_changed(&s->prev, &next)) {
                        log_state(s, elapsed, &next);
                        s->prev = next;
                    }
                    if (!next.gate || !next.half_ok || !next.full_ok || next.half_raw != 1u || next.full_raw != 0u) {
                        s->half_pending = 0u;
                        s->half_prep_done = 0u;
                        s->half_prep_token = 0u;
                        s->half_fresh_req_armed = 0u;
                        s->half_need_bk_seq = 0u;
                        if (!next.gate || (next.full_ok && next.full_raw != 0u)) s->seen_idle = 0u;
                    } else if (!s->uipc_inflight && s->bk_reply_seq >= s->half_need_bk_seq) {
                        fork_prepared_ring(s, min_rem);
                    }
                }
            } else {
                /* Full press or invalid shutter state resets debounce and requires clean idle again. */
                s->half_pending = 0u;
                s->half_prep_done = 0u;
                s->half_prep_token = 0u;
                s->half_fresh_req_armed = 0u;
                s->half_need_bk_seq = 0u;
                if (next.full_ok && next.full_raw != 0u) s->seen_idle = 0u;
            }
        } else {
            s->seen_idle = 0u;
            s->half_pending = 0u;
            s->half_prep_done = 0u;
            s->half_prep_token = 0u;
            s->half_fresh_req_armed = 0u;
            s->half_need_bk_seq = 0u;
        }

next_tick_hb:

        if ((u32)(elapsed - last_hb) >= m7_s6_daemon_config.heartbeat_ms) {
            log_hb(s, elapsed, &next);
            last_hb = elapsed;
        }
    }

    wait_ring_shutdown(s, sigmask);
    stop_uipc_worker(s, sigmask);
    u32 end_ms = s->started_ms;
    now_ms_checked(&end_ms);
    log_stop(s, (u32)(end_ms - s->started_ms), trig_ms, stop_reason, stop_detail);

cleanup:
    if (s->ring_pid > 0) wait_ring_shutdown(s, sigmask);
    if (s->ring_out_fd >= 0) sys_call(SYS_CLOSE, (u32)s->ring_out_fd, 0, 0, 0, 0, 0);
    if (!s->worker_stopped && (s->worker_pid > 0 || s->req_fd >= 0 || s->rep_fd >= 0)) stop_uipc_worker(s, sigmask);
    if (s->mem_fd >= 0) sys_call(SYS_CLOSE, (u32)s->mem_fd, 0, 0, 0, 0, 0);
    if (m7_s6_daemon_config.daemonize) {
        if (s->log_fd >= 0) sys_call(SYS_CLOSE, (u32)s->log_fd, 0, 0, 0, 0, 0);
        if (s->pid_published) sys_call(SYS_UNLINK, (u32)s->pid_path, 0, 0, 0, 0, 0);
    }
    sys_call(SYS_MUNMAP, (u32)s, state_bytes, 0, 0, 0, 0);
    return exit_rc;
}

__asm__(".arm\n.global _start\n.type _start,%function\n_start:\n"
        "bl daemon_main\nmov r7,#1\nsvc 0\nb .\n.size _start,.-_start\n");
