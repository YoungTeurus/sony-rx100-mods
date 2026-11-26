/*
 * Stage 6 WIP v1: Read-only self-discovering untethered RAM daemon probe.
 *
 * Safety invariants & scope bounds:
 * - ZERO ptrace syscalls (syscall 26 is never invoked).
 * - ZERO writes to /proc/<pid>/mem (opened O_RDONLY only).
 * - ZERO sndcmd.elf executions, ZERO traps, ZERO route changes.
 * - ZERO SD card or internal flash writes (logs only to private nonce tmpfs dir).
 * - Per-run stop-flag file (/tmp_network/.m7-s6-<nonce>/stop) eliminates host PID-reuse races.
 * - All /dev/uipc ioctls run in a dedicated uipc_worker child process (zero ioctl syscalls
 *   in the main watchdog), with non-blocking valloc (wait=0), two-sentinel copy verification,
 *   fail-closed FREE_MSG latching, a 1000 ms per-request reply deadline enforced before
 *   accepting any reply, startup + loop duration_ms enforcement, and a single bounded worker
 *   teardown budget (<= 200 ms after stop trigger).
 * - Kernel-internal waits outside userspace timers (pipe inode mutex, /proc/<pid>/mem
 *   mmap_sem, and backup.ko rt_down_read inside uipc_worker) are bounded only by the kernel;
 *   if a worker remains live after bounded teardown, host collection detects it via
 *   /proc/<pid>/exe scan, retains custody, and returns nonzero.
 */
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned short u16;
typedef unsigned char u8;

#define S6_MAGIC   0x3653374du /* "M7S6" */
#define S6_VERSION 2u

#define MAX_RANGES 512u
#define SD_INPUT_LIMIT 1024u
#define STOP_RESERVE_BYTES 256u
#define UIPC_REPLY_TIMEOUT_MS 1000u

/* ARM EABI Linux syscall numbers (verified in M7 1.00 sys_call_table @ 0x6010e084) */
#define SYS_EXIT             1u
#define SYS_FORK             2u
#define SYS_READ             3u
#define SYS_WRITE            4u
#define SYS_OPEN             5u
#define SYS_CLOSE            6u
#define SYS_UNLINK           10u
#define SYS_CHDIR            12u
#define SYS_GETPID           20u
#define SYS_KILL             37u
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
#define LIBOBJ_CAMSETPARAMS_PTR 0x145f3e8u /* CamStateMgr + 0x1a88 (0xb5ee02..0xb5ee0a) */
#define LIBOBJ_CAMSETPARAMS_GRD 0x145f3ecu /* C++11 static init guard (0xa6e388..0xa6e3be) */
#define LIBOBJ_CAMSETPARAMS_OBJ 0x145f3f0u /* CamSetParams singleton */

#define SLOT_DRIVE_MODE_ACT     0x145f4f4u /* 0x9541 */
#define SLOT_BURST_SPEED_ACT    0x145f4fcu /* 0x9543 */
#define SLOT_BOL_BURST_SPD_ACT  0x1460cd4u /* 0x9b39 */
#define SLOT_STILL_SIZE_ACT     0x145f5f0u /* 0x9580 */
#define SLOT_STILL_ASPECT_ACT   0x145f5f4u /* 0x9581 */
#define SLOT_JPEG_QUALITY_ACT   0x145f5f8u /* 0x9582 */
#define SLOT_STILL_FORMAT_ACT   0x145f5fcu /* 0x9583 */
#define SLOT_RED_EYE_SET        0x145f808u /* 0x9606 */
#define SLOT_RED_EYE_ACT        0x145f80cu /* 0x9607 */

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

struct s6_config {
    u32 magic;
    u32 version;
    u32 duration_ms;
    u32 poll_ms;
    u32 heartbeat_ms;
    u32 max_log_bytes;
    u32 daemonize;
    u32 toggle_bkid;
    char nonce[12];
};

const volatile struct s6_config m7_s6_config = {
    .magic = S6_MAGIC,
    .version = S6_VERSION,
    .duration_ms = 240000u,
    .poll_ms = 50u,
    .heartbeat_ms = 2000u,
    .max_log_bytes = 65536u,
    .daemonize = 1u,
    .toggle_bkid = 0x01071472u, /* Release w/o Card */
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

struct range {
    u32 start;
    u32 end;
};

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
    u32 redeye_set, redeye_act;
    u32 bk_valid, bk_size, bk_val;
    s32 bk_rc;
    u32 sub_ok, sub_enabled, sub_raw;
    s32 sub_cb;
    u32 sub_s1, sub_s2;
    u32 half_ok, half_raw;
    u32 full_ok, full_raw;
    u32 elig; /* Drive-mode + format eligibility only (toggle polarity is observed raw in bk) */
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
    u32 str_uxc_start;
    u32 str_uxc_end;
    char str_uxc_path[96];
    char log_path[64];
    char pid_path[64];
    char stop_path[64];
    u32 pid_published;
    u32 mon_tid_proc;
    u32 mon_tid_mwf;
    u32 nranges;
    struct range ranges[MAX_RANGES];
    struct range tmp_ranges[MAX_RANGES];
    u32 tmp_nranges;
    s32 mem_fd;
    s32 log_fd;
    u32 log_bytes;
    u32 log_truncated;
    /* /dev/uipc state (used exclusively inside uipc_worker child) */
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
    struct bk_reply last_bk;
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

static int str_starts(const char *s, const char *prefix) {
    while (*prefix) {
        if (*s++ != *prefix++) return 0;
    }
    return 1;
}

static int str_ends(const char *s, const char *suffix) {
    u32 sl = 0, xl = 0;
    while (s[sl]) ++sl;
    while (suffix[xl]) ++xl;
    if (xl > sl) return 0;
    return str_eq(s + sl - xl, suffix);
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

static void log_write_bounded(struct daemon_state *s, const char *buf, u32 len, int is_stop) {
    if (s->log_fd < 0 || !len) return;
    u32 limit = is_stop ? m7_s6_config.max_log_bytes
                        : (m7_s6_config.max_log_bytes - STOP_RESERVE_BYTES);
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

static int valid_nonce(void) {
    for (u32 i = 0; i < 12u; ++i) {
        char c = m7_s6_config.nonce[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static void build_run_paths(struct daemon_state *s) {
    char nbuf[13];
    for (u32 i = 0; i < 12u; ++i) nbuf[i] = m7_s6_config.nonce[i];
    nbuf[12] = 0;

    u32 p = 0;
    p = append_str(s->log_path, p, sizeof(s->log_path), "/tmp_network/.m7-s6-");
    p = append_str(s->log_path, p, sizeof(s->log_path), nbuf);
    p = append_str(s->log_path, p, sizeof(s->log_path), "/probe.log");
    s->log_path[p] = 0;

    p = 0;
    p = append_str(s->pid_path, p, sizeof(s->pid_path), "/tmp_network/.m7-s6-");
    p = append_str(s->pid_path, p, sizeof(s->pid_path), nbuf);
    p = append_str(s->pid_path, p, sizeof(s->pid_path), "/probe.pid");
    s->pid_path[p] = 0;

    p = 0;
    p = append_str(s->stop_path, p, sizeof(s->stop_path), "/tmp_network/.m7-s6-");
    p = append_str(s->stop_path, p, sizeof(s->stop_path), nbuf);
    p = append_str(s->stop_path, p, sizeof(s->stop_path), "/stop");
    s->stop_path[p] = 0;
}

static int stop_file_present(const struct daemon_state *s) {
    s32 fd = sys_call(SYS_OPEN, (u32)s->stop_path, O_RDONLY, 0, 0, 0, 0);
    if (fd >= 0) {
        sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
        return 1;
    }
    return 0;
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

    if (initial && r == 'r' && w == '-' && x == '-' && priv == 'p' && file_off == 0 &&
        str_starts(path, "/usr/share/app/string_") && str_ends(path, ".uxc") && !s->str_uxc_start) {
        s->str_uxc_start = start;
        s->str_uxc_end = end;
        u32 pos = append_str(s->str_uxc_path, 0, sizeof(s->str_uxc_path), path);
        s->str_uxc_path[pos] = 0;
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
        s->str_uxc_start = s->str_uxc_end = 0;
        s->str_uxc_path[0] = 0;
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
    if (!valid_lib_bias(s->libobj_bias) || !valid_lib_bias(s->mwf_bias)) return 0;

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

/*
 * Isolated /dev/uipc Backup_read worker (runs in a dedicated child process).
 * Opening /dev/uipc inside the worker binds file_priv->mm (task_struct+0xcc,
 * M7 osal_uipc.ko .text+0x640..0x650) to the worker's own mm_struct, while
 * isolating the main watchdog loop from any kernel lock contention inside ioctl.
 */
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
    s32 map = sys_call(SYS_MMAP2, 0u, info[0], 3u /* PROT_RW */, 1u /* MAP_SHARED */, (u32)fd, 0u);
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
    /* vargs[2] = 0 (non-blocking): M7 osal_uipc.ko .text+0x377c..0x3780 skips wait path. */
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
    s32 rc = uipc_backup_call(s, 0u /* Backup_get_datasize */, 1u, bkid, 0u, &dsz);
    rep->uipc_disabled = s->uipc_disabled;
    rep->uipc_free_err = s->uipc_free_err;
    if (rc != 0) {
        rep->bk_rc = rc;
        return;
    }
    rep->bk_size = (dsz > 0) ? (u32)dsz : 0u;
    if (dsz != 1) {
        rep->bk_rc = (dsz < 0) ? dsz : -75;
        return;
    }
    /* Two-sentinel guard detects >1-byte overrun (-75) and silent __copy_to_user fault (-14). */
    volatile u32 byte_box = 0xa5a5a5a5u;
    s32 rret = -1;
    rc = uipc_backup_call(s, 3u /* Backup_read */, 2u, bkid, (u32)&byte_box, &rret);
    rep->uipc_disabled = s->uipc_disabled;
    rep->uipc_free_err = s->uipc_free_err;
    if (rc != 0 || rret != 1) {
        rep->bk_rc = rc ? rc : rret;
        return;
    }
    u32 raw_box = byte_box;
    if ((raw_box & 0xffffff00u) != 0xa5a5a500u) {
        rep->bk_rc = -75; /* Overrun beyond 1 byte */
        return;
    }
    u32 val = raw_box & 0xffu;
    if (val == 0xa5u) {
        /* Disambiguate real 0xa5 value vs silent __copy_to_user failure with 0x5a sentinel. */
        volatile u32 box2 = 0x5a5a5a5au;
        s32 rret2 = -1;
        rc = uipc_backup_call(s, 3u /* Backup_read */, 2u, bkid, (u32)&box2, &rret2);
        rep->uipc_disabled = s->uipc_disabled;
        rep->uipc_free_err = s->uipc_free_err;
        if (rc != 0 || rret2 != 1) {
            rep->bk_rc = rc ? rc : rret2;
            return;
        }
        u32 raw2 = box2;
        if ((raw2 & 0xffffff00u) != 0x5a5a5a00u) {
            rep->bk_rc = -75;
            return;
        }
        if ((raw2 & 0xffu) == 0x5au) {
            rep->bk_rc = -14; /* Both sentinels untouched -> copy fault */
            return;
        }
        val = raw2 & 0xffu;
    }
    rep->bk_valid = 1u;
    rep->bk_val = val;
    rep->bk_rc = 0;
}

static void uipc_worker_main(struct daemon_state *s, s32 req_rfd, s32 rep_wfd, u32 state_bytes) {
    /* Worker owns zero fds in /proc/<im>/mem or the nonce log directory. */
    if (s->mem_fd >= 0) { sys_call(SYS_CLOSE, (u32)s->mem_fd, 0, 0, 0, 0, 0); s->mem_fd = -1; }
    if (m7_s6_config.daemonize && s->log_fd >= 0) {
        sys_call(SYS_CLOSE, (u32)s->log_fd, 0, 0, 0, 0, 0);
        s->log_fd = -1;
    }
    uipc_init(s);

    for (;;) {
        u32 bkid = 0;
        u32 got = 0;
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
    s32 req_p[2] = {-1, -1};
    s32 rep_p[2] = {-1, -1};
    s->worker_pid = -1;
    s->req_fd = -1;
    s->rep_fd = -1;
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
        s->worker_pid = wpid; /* Let cleanup kill and reap cleanly */
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
    u32 bkid = m7_s6_config.toggle_bkid;
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
    /* Enforce both per-IPC (1000 ms) and run-lifetime (duration_ms) deadlines BEFORE accepting any reply. */
    if ((u32)(now_val - s->uipc_req_ms) >= UIPC_REPLY_TIMEOUT_MS ||
        (u32)(now_val - s->started_ms) >= m7_s6_config.duration_ms) {
        uipc_fail_channel(s, -110); /* -ETIMEDOUT */
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
                (u32)(chk - s->started_ms) >= m7_s6_config.duration_ms) {
                uipc_fail_channel(s, -110); /* -ETIMEDOUT */
                return 1;
            }
            return 0;
        }
        uipc_fail_channel(s, (n < 0) ? n : -32);
        return 1;
    }
    /* Re-verify deadlines right after assembling the reply so a late read cannot slip past them. */
    u32 after_val = now_val;
    if (!now_ms_checked(&after_val) ||
        (u32)(after_val - s->uipc_req_ms) >= UIPC_REPLY_TIMEOUT_MS ||
        (u32)(after_val - s->started_ms) >= m7_s6_config.duration_ms) {
        uipc_fail_channel(s, -110);
        return 1;
    }
    struct bk_reply rep;
    __aeabi_memcpy8(&rep, s->rep_buf, sizeof(rep));
    s->rep_got = 0u;
    s->uipc_inflight = 0u;
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

    /* Single bounded teardown budget: up to 100 ms graceful EOF + SIGKILL + up to 100 ms reap (<= 200 ms). */
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
    /* Safe: worker_pid is our own unreaped child (PID cannot be reused before wait4). */
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

/* --- CamSetParams zero-ptrace reader --- */
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
    out->valid_cam = 0;
    out->csp_ptr_ok = 0;
    out->drive_act = out->burst_spd = out->bol_spd = 0xffffffffu;
    out->still_size = out->still_asp = out->jpeg_qual = out->file_fmt = 0xffffffffu;
    out->redeye_set = out->redeye_act = 0xffffffffu;
    if (!pread_raw(s, s->libobj_bias + LIBOBJ_CAMSETPARAMS_PTR, hdr, 8u)) return;
    out->csp_ptr_ok = (hdr[0] == s->libobj_bias + LIBOBJ_CAMSETPARAMS_OBJ) ? 1u : 0u;
    if ((hdr[1] & 1u) != 1u) return;

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
    if (!read_param_int7(s, SLOT_RED_EYE_SET, &out->redeye_set)) out->redeye_set = 0xffffffffu;
    if (!read_param_int7(s, SLOT_RED_EYE_ACT, &out->redeye_act)) out->redeye_act = 0xffffffffu;
    out->valid_cam = (u32)ok;
}

/* --- Subscription & sd_input zero-ptrace reader --- */
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
    if (a[0] != expected_key || a[4] != idx) return 0;
    *out_raw = a[2];
    return 1;
}

static void read_shutter(struct daemon_state *s, struct sample *out) {
    u32 r, c, st, cnt;
    out->half_ok = 0u;
    out->half_raw = 0xffffffffu;
    out->full_ok = 0u;
    out->full_raw = 0xffffffffu;
    if (!s->input.ok) init_input_watch(s);
    if (!s->input.ok) return;
    if (!read_input_shape(s, &r, &c, &st, &cnt) ||
        r != s->input.root || c != s->input.config || st != s->input.state || cnt != s->input.count) {
        init_input_watch(s);
        if (!s->input.ok) return;
    }
    u32 raw = 0u;
    if (read_shutter_row(s, s->input.idx_half, 0x1f1u, &raw)) {
        out->half_ok = 1u;
        out->half_raw = raw;
    }
    if (read_shutter_row(s, s->input.idx_full, 0xa7u, &raw)) {
        out->full_ok = 1u;
        out->full_raw = raw;
    }
}

static u32 compute_elig(const struct sample *cur) {
    return (cur->valid_cam &&
            (cur->drive_act == 0x005fu || cur->drive_act == 0x05bcu) &&
            cur->file_fmt == 0x00bdu && cur->still_size == 0x00b3u && cur->still_asp == 0x00b9u) ? 1u : 0u;
}

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
    p = append_hex(line, p, sizeof(line), m7_s6_config.toggle_bkid);
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
    p = append_str(line, p, sizeof(line), " str_uxc=");
    p = append_hex(line, p, sizeof(line), s->str_uxc_start);
    p = append_str(line, p, sizeof(line), "..");
    p = append_hex(line, p, sizeof(line), s->str_uxc_end);
    p = append_str(line, p, sizeof(line), " str_uxc_path=");
    p = append_str(line, p, sizeof(line), s->str_uxc_path[0] ? s->str_uxc_path : "none");
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
    p = append_str(line, p, sizeof(line), " bspd=");
    p = append_hex(line, p, sizeof(line), cur->burst_spd);
    p = append_str(line, p, sizeof(line), " bol=");
    p = append_hex(line, p, sizeof(line), cur->bol_spd);
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
    p = append_str(line, p, sizeof(line), " re=");
    p = append_hex(line, p, sizeof(line), cur->redeye_set);
    p = append_str(line, p, sizeof(line), " sub_ok=");
    p = append_u32(line, p, sizeof(line), cur->sub_ok);
    p = append_str(line, p, sizeof(line), " sub_en=");
    p = append_u32(line, p, sizeof(line), cur->sub_enabled);
    p = append_str(line, p, sizeof(line), " sub_raw=");
    p = append_hex(line, p, sizeof(line), cur->sub_raw);
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
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 0);
}

static void log_hb(struct daemon_state *s, u32 t_ms, const struct sample *cur) {
    char line[320];
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
    p = append_str(line, p, sizeof(line), " sub_ok=");
    p = append_u32(line, p, sizeof(line), cur->sub_ok);
    p = append_str(line, p, sizeof(line), " sub_en=");
    p = append_u32(line, p, sizeof(line), cur->sub_enabled);
    p = append_str(line, p, sizeof(line), " drive=");
    p = append_hex(line, p, sizeof(line), cur->drive_act);
    p = append_str(line, p, sizeof(line), " fmt=");
    p = append_hex(line, p, sizeof(line), cur->file_fmt);
    p = append_str(line, p, sizeof(line), " bk_ok=");
    p = append_u32(line, p, sizeof(line), cur->bk_valid);
    p = append_str(line, p, sizeof(line), " bk=");
    p = append_hex(line, p, sizeof(line), cur->bk_val);
    p = append_str(line, p, sizeof(line), " half_ok=");
    p = append_u32(line, p, sizeof(line), cur->half_ok);
    p = append_str(line, p, sizeof(line), " half=");
    p = append_hex(line, p, sizeof(line), cur->half_raw);
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 0);
}

static void log_stop(struct daemon_state *s, u32 t_ms, u32 trig_ms, const char *reason, s32 detail) {
    char line[240];
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
    p = append_str(line, p, sizeof(line), " trunc=");
    p = append_u32(line, p, sizeof(line), s->log_truncated);
    p = append_str(line, p, sizeof(line), "\n");
    log_write_bounded(s, line, p, 1);
}

static int sample_changed(const struct sample *a, const struct sample *b) {
    return a->valid_cam != b->valid_cam || a->drive_act != b->drive_act ||
           a->burst_spd != b->burst_spd || a->bol_spd != b->bol_spd ||
           a->still_size != b->still_size || a->still_asp != b->still_asp ||
           a->jpeg_qual != b->jpeg_qual || a->file_fmt != b->file_fmt ||
           a->bk_valid != b->bk_valid || a->bk_val != b->bk_val || a->bk_rc != b->bk_rc ||
           a->redeye_set != b->redeye_set ||
           a->sub_ok != b->sub_ok || a->sub_enabled != b->sub_enabled || a->sub_raw != b->sub_raw ||
           a->half_ok != b->half_ok || a->half_raw != b->half_raw ||
           a->full_ok != b->full_ok || a->full_raw != b->full_raw ||
           a->elig != b->elig;
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
    if (sys_call(SYS_RT_SIGACTION, 1u /* SIGHUP */, (u32)ign, 0, 8u, 0, 0) != 0 ||
        sys_call(SYS_RT_SIGACTION, 13u /* SIGPIPE */, (u32)ign, 0, 8u, 0, 0) != 0) {
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

int probe_main(void) {
    if (m7_s6_config.magic != S6_MAGIC || m7_s6_config.version != S6_VERSION ||
        m7_s6_config.poll_ms < 10u || m7_s6_config.poll_ms > 1000u ||
        m7_s6_config.duration_ms < 100u || m7_s6_config.duration_ms > 3600000u ||
        m7_s6_config.max_log_bytes < 1024u || m7_s6_config.max_log_bytes > 262144u ||
        !valid_nonce()) {
        return 2;
    }

    if (m7_s6_config.daemonize) {
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
    if (sys_call(SYS_RT_SIGPROCMASK, 0u /* SIG_BLOCK */, (u32)sigmask, 0, 8u, 0, 0) != 0) return 4;

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
    s->last_bk.bk_val = 0xffffffffu;
    s->last_bk.bk_rc = -19;
    build_run_paths(s);

    s->self_pid = (u32)sys_call(SYS_GETPID, 0, 0, 0, 0, 0, 0);
    int exit_rc = 0;

    if (m7_s6_config.daemonize) {
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

    /* Enforce duration_ms throughout startup before spawning/waiting on the worker. */
    u32 t0 = s->started_ms;
    if (!now_ms_checked(&t0)) {
        log_stop(s, 0u, 0u, "clock_fail", 0);
        exit_rc = 7;
        goto cleanup;
    }
    if ((u32)(t0 - s->started_ms) >= m7_s6_config.duration_ms) {
        u32 trig = (u32)(t0 - s->started_ms);
        log_stop(s, trig, trig, "timeout", 0);
        goto cleanup;
    }
    if (stop_file_present(s)) {
        u32 trig = (u32)(t0 - s->started_ms);
        log_stop(s, trig, trig, "stop_file", 0);
        goto cleanup;
    }

    /* Launch isolated /dev/uipc worker child and wait up to min(1000 ms, remaining duration_ms). */
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
            if (el >= m7_s6_config.duration_ms) {
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
            u32 rem_run = m7_s6_config.duration_ms - el;
            u32 ipc_el = (u32)(tv - s->uipc_req_ms);
            u32 rem_ipc = (ipc_el < UIPC_REPLY_TIMEOUT_MS) ? (UIPC_REPLY_TIMEOUT_MS - ipc_el) : 0u;
            u32 step_ms = 20u;
            if (rem_run < step_ms) step_ms = rem_run;
            if (rem_ipc < step_ms) step_ms = rem_ipc;
            if (!step_ms) {
                uipc_fail_channel(s, -110);
                break;
            }
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
    if ((u32)(post_init - s->started_ms) >= m7_s6_config.duration_ms) {
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
    cur.elig = compute_elig(&cur);

    log_boot(s, &cur);
    log_state(s, (u32)(post_init - s->started_ms), &cur);
    s->prev = cur;
    s->has_prev = 1u;

    if (m7_s6_config.daemonize) {
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
    u32 last_bk_tick = 0u;
    const char *stop_reason = "timeout";
    s32 stop_detail = 0;
    u32 trig_ms = 0u;

    for (;;) {
        u32 now_val = 0;
        if (!now_ms_checked(&now_val)) {
            stop_reason = "clock_fail";
            break;
        }
        u32 elapsed = (u32)(now_val - s->started_ms);
        trig_ms = elapsed;
        if (elapsed >= m7_s6_config.duration_ms) {
            stop_reason = "timeout";
            break;
        }
        if (stop_file_present(s)) {
            stop_reason = "stop_file";
            break;
        }

        u32 rem_run = m7_s6_config.duration_ms - elapsed;
        u32 sleep_ms = m7_s6_config.poll_ms;
        if (rem_run < sleep_ms) sleep_ms = rem_run;
        u32 ts[2] = { sleep_ms / 1000u, (sleep_ms % 1000u) * 1000000u };
        s32 sig = sys_call(SYS_RT_SIGTIMEDWAIT, (u32)sigmask, 0u, (u32)ts, 8u, 0, 0);
        if (sig == 15 || sig == 2) {
            if (now_ms_checked(&now_val)) trig_ms = (u32)(now_val - s->started_ms);
            stop_reason = "signal";
            stop_detail = sig;
            break;
        }
        if (sig != -11 && sig != -4) {
            if (now_ms_checked(&now_val)) trig_ms = (u32)(now_val - s->started_ms);
            stop_reason = "sigwait_err";
            stop_detail = sig;
            break;
        }

        ++s->ticks;
        if (!now_ms_checked(&now_val)) {
            stop_reason = "clock_fail";
            break;
        }
        elapsed = (u32)(now_val - s->started_ms);
        trig_ms = elapsed;
        if (elapsed >= m7_s6_config.duration_ms) {
            stop_reason = "timeout";
            break;
        }

        if (stop_file_present(s)) {
            stop_reason = "stop_file";
            break;
        }
        if (sys_call(SYS_KILL, s->im_pid, 0u, 0, 0, 0, 0) != 0) {
            stop_reason = "im_exit";
            break;
        }
        if ((u32)(elapsed - last_hb) >= m7_s6_config.heartbeat_ms) {
            u32 st = 0;
            if (!read_proc_starttime(s->im_pid, &st) || st != s->im_starttime) {
                stop_reason = "im_reused";
                break;
            }
        }

        uipc_poll_reply(s, now_val);
        if (!s->uipc_inflight && !s->uipc_timed_out && (s->ticks - last_bk_tick) >= 4u) {
            uipc_send_request(s, now_val);
            last_bk_tick = s->ticks;
            uipc_poll_reply(s, now_val);
        }

        struct sample next = s->prev;
        read_cam_params(s, &next);
        apply_last_bk(s, &next);
        read_subscription(s, &next);
        read_shutter(s, &next);
        next.elig = compute_elig(&next);

        if (sample_changed(&s->prev, &next)) {
            log_state(s, elapsed, &next);
            s->prev = next;
        }

        if ((u32)(elapsed - last_hb) >= m7_s6_config.heartbeat_ms) {
            log_hb(s, elapsed, &next);
            last_hb = elapsed;
        }
    }

    stop_uipc_worker(s, sigmask);
    u32 end_ms = s->started_ms;
    now_ms_checked(&end_ms);
    log_stop(s, (u32)(end_ms - s->started_ms), trig_ms, stop_reason, stop_detail);

cleanup:
    if (!s->worker_stopped && (s->worker_pid > 0 || s->req_fd >= 0 || s->rep_fd >= 0)) stop_uipc_worker(s, sigmask);
    if (s->mem_fd >= 0) sys_call(SYS_CLOSE, (u32)s->mem_fd, 0, 0, 0, 0, 0);
    if (m7_s6_config.daemonize) {
        if (s->log_fd >= 0) sys_call(SYS_CLOSE, (u32)s->log_fd, 0, 0, 0, 0, 0);
        if (s->pid_published) sys_call(SYS_UNLINK, (u32)s->pid_path, 0, 0, 0, 0, 0);
    }
    sys_call(SYS_MUNMAP, (u32)s, state_bytes, 0, 0, 0, 0);
    return exit_rc;
}

__asm__(".arm\n.global _start\n.type _start,%function\n_start:\n"
        "bl probe_main\nmov r7,#1\nsvc 0\nb .\n.size _start,.-_start\n");
