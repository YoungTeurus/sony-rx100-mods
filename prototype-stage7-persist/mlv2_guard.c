/* Freestanding ARM32 EABI Mod Loader v2 guard for DSC-RX100M7 1.00 (RAM-only).
 *
 * Zero libc dependencies, zero writable globals (state allocated via mmap2),
 * single PT_LOAD RX ELF compatible with M7 Linux 3.0.27.
 *
 * Places shim.bin in viewUnified2.so's own 2,048-byte RX zero tail (+0x972800..+0x973000)
 * and patches each of the three PAS_MenuList hooks with a SINGLE 4-byte atomic Thumb-2 B.W
 * instruction so no partial or invalid redirect can ever exist under any write failure.
 *
 * Usage:
 *   mlv2_guard.elf fnv FILE
 *   mlv2_guard.elf check REQUEST_FILE      (read-only, zero ptrace)
 *   mlv2_guard.elf install REQUEST_FILE    (stock -> v2, atomic freeze + readback + rollback)
 *   mlv2_guard.elf uninstall REQUEST_FILE  (v2 -> stock, requires sd-disabled + sd-stopped)
 */
#include <stdint.h>
#include "mlv2.h"

typedef uint32_t u32;
typedef int32_t  s32;
typedef uint8_t  u8;

#define REQ_MAGIC       0x5132484du /* "ML2Q" */
#define MAX_RELOCS      256u
#define MAX_TIDS        512u
#define STACK_SCAN_MAX  65536u      /* 64 KiB per thread stack scan on uninstall */

/* ARM Linux EABI syscalls */
#define SYS_EXIT        1u
#define SYS_READ        3u
#define SYS_WRITE       4u
#define SYS_OPEN        5u
#define SYS_CLOSE       6u
#define SYS_PTRACE      26u
#define SYS_READLINK    85u
#define SYS_MUNMAP      91u
#define SYS_WAIT4       114u
#define SYS_PREAD64     180u
#define SYS_MMAP2       192u
#define SYS_GETDENTS64  217u

#define O_RDONLY        0u
#define PTRACE_POKETEXT 4u
#define PTRACE_GETREGS  12u
#define PTRACE_ATTACH   16u
#define PTRACE_DETACH   17u
#define WNOHANG         1u
#define WALL_FLAG       0x40000000u

static const u8 orig_set_root[16] = {
    0x04, 0x46, 0x00, 0xaf, 0x51, 0xb1, 0x00, 0xf5, 0xc2, 0x33, 0x03, 0xf5, 0x2b, 0x73, 0x19, 0x60
};
static const u8 orig_refresh[16] = {
    0x2d, 0xe9, 0xf0, 0x4f, 0x9b, 0xb0, 0x06, 0xaf, 0x04, 0x46, 0x07, 0xf1, 0x20, 0x00, 0x4f, 0xf0
};
static const u8 orig_open_item[12] = {
    0x00, 0xf5, 0xc2, 0x33, 0x03, 0xf5, 0x2c, 0x73, 0x2d, 0xe9, 0xf0, 0x43
};
static const u8 orig_rect_prefix[48] = {
    0x11, 0x00, 0x00, 0x00, 0x5b, 0x00, 0x42, 0x00, 0x67, 0x00, 0x00, 0x00, 0x5b, 0x00, 0x42, 0x00,
    0xbd, 0x00, 0x00, 0x00, 0x5b, 0x00, 0x42, 0x00, 0x13, 0x01, 0x00, 0x00, 0x5b, 0x00, 0x42, 0x00,
    0x69, 0x01, 0x00, 0x00, 0x5b, 0x00, 0x42, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x5b, 0x00, 0x42, 0x00
};
static const u8 orig_rect[8] = {0, 0, 0, 0, 0, 0, 0, 0};
static const u8 patch_rect[8] = {0x15, 0x02, 0x00, 0x00, 0x5b, 0x00, 0x42, 0x00};

struct guard_state {
    u32 im_pid;
    u32 view_base;
    u32 view_bias;
    u32 shim_at;
    u32 shim_size;
    u32 hook_sr_at;
    u32 hook_rf_at;
    u32 hook_oi_at;
    u32 rect1_at;
    u32 rect2_at;
    u32 tids[MAX_TIDS];
    u32 tid_count;
    u32 attached;
    u8  owned[MAX_TIDS];
    u8  stopped[MAX_TIDS];
    u8  shim[MLV2_SHIM_CAP];
    u8  live_shim[MLV2_SHIM_CAP];
    u8  zeros[MLV2_SHIM_CAP];
    u8  buf[MLV2_SHIM_CAP];
    u32 rel[MAX_RELOCS];
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

void __aeabi_memclr8(void *dst, u32 n) {
    volatile u8 *p = (volatile u8 *)dst;
    while (n--) *p++ = 0;
}
void __aeabi_memclr(void *dst, u32 n) __attribute__((alias("__aeabi_memclr8")));
void __aeabi_memclr4(void *dst, u32 n) __attribute__((alias("__aeabi_memclr8")));

void __aeabi_memcpy8(void *dst, const void *src, u32 n) {
    volatile u8 *d = (volatile u8 *)dst;
    const volatile u8 *s = (const volatile u8 *)src;
    while (n--) *d++ = *s++;
}
void __aeabi_memcpy(void *dst, const void *src, u32 n) __attribute__((alias("__aeabi_memcpy8")));
void __aeabi_memcpy4(void *dst, const void *src, u32 n) __attribute__((alias("__aeabi_memcpy8")));

static int g_memcmp(const void *a, const void *b, u32 n) {
    const u8 *pa = (const u8 *)a, *pb = (const u8 *)b;
    while (n--) {
        if (*pa != *pb) return (int)*pa - (int)*pb;
        ++pa; ++pb;
    }
    return 0;
}

static int g_streq(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == 0 && *b == 0;
}

static u32 g_strlen(const char *s) {
    u32 n = 0;
    while (s[n]) ++n;
    return n;
}

static int g_endswith(const char *s, const char *suf) {
    u32 sl = g_strlen(s), fl = g_strlen(suf);
    if (sl < fl) return 0;
    return g_streq(s + sl - fl, suf);
}

static u32 app_str(char *dst, u32 p, u32 cap, const char *s) {
    while (*s && p + 1u < cap) dst[p++] = *s++;
    return p;
}

static u32 app_u32(char *dst, u32 p, u32 cap, u32 v) {
    char tmp[12];
    u32 n = 0;
    do { tmp[n++] = (char)('0' + (v % 10u)); v /= 10u; } while (v);
    while (n && p + 1u < cap) dst[p++] = tmp[--n];
    return p;
}

static u32 app_s32(char *dst, u32 p, u32 cap, s32 v) {
    if (v < 0) {
        if (p + 1u < cap) dst[p++] = '-';
        return app_u32(dst, p, cap, (u32)(-(v + 1)) + 1u);
    }
    return app_u32(dst, p, cap, (u32)v);
}

static u32 app_hex8(char *dst, u32 p, u32 cap, u32 v) {
    const char hex[] = "0123456789abcdef";
    for (int sh = 28; sh >= 0 && p + 1u < cap; sh -= 4)
        dst[p++] = hex[(v >> sh) & 0xfu];
    return p;
}

static void write_all(u32 fd, const char *buf, u32 len) {
    u32 sent = 0, tries = 0;
    while (sent < len && tries++ < 16u) {
        s32 rc = sys_call(SYS_WRITE, fd, (u32)(buf + sent), len - sent, 0, 0, 0);
        if (rc == -4) continue;
        if (rc <= 0 || (u32)rc > len - sent) break;
        sent += (u32)rc;
    }
}

static void out_line(const char *s) {
    write_all(1u, s, g_strlen(s));
    write_all(1u, "\n", 1u);
}

static void build_proc_path(char *out, u32 cap, u32 pid, const char *leaf) {
    u32 p = 0;
    p = app_str(out, p, cap, "/proc/");
    p = app_u32(out, p, cap, pid);
    p = app_str(out, p, cap, "/");
    p = app_str(out, p, cap, leaf);
    out[p] = 0;
}

static int parse_dec_bounded(const char *s, u32 max_len, u32 *out) {
    u32 v = 0, n = 0;
    if (!max_len || !s[0]) return 0;
    while (n < max_len && s[n]) {
        char c = s[n];
        if (c < '0' || c > '9') return 0;
        u32 d = (u32)(c - '0');
        if (v > (0x7fffffffu - d) / 10u) return 0;
        v = v * 10u + d;
        ++n;
    }
    if (!n || n == max_len) return 0;
    *out = v;
    return 1;
}

static u32 fnv1a(const u8 *b, u32 n) {
    u32 h = 2166136261u;
    for (u32 i = 0; i < n; ++i) h = (h ^ b[i]) * 16777619u;
    return h;
}

static int read_exact(s32 fd, void *dst, u32 n) {
    u8 *p = (u8 *)dst;
    u32 got = 0;
    while (got < n) {
        s32 rc = sys_call(SYS_READ, (u32)fd, (u32)(p + got), n - got, 0, 0, 0);
        if (rc == -4) continue;
        if (rc <= 0 || (u32)rc > n - got) return 0;
        got += (u32)rc;
    }
    return 1;
}

static s32 read_mem_rc(s32 mem_fd, u32 addr, void *dst, u32 n) {
    u8 *p = (u8 *)dst;
    u32 got = 0;
    while (got < n) {
        s32 rc = -4;
        for (u32 tries = 0; tries < 8u && rc == -4; ++tries)
            rc = sys_call(SYS_PREAD64, (u32)mem_fd, (u32)(p + got), n - got, 0u, addr + got, 0u);
        if (rc <= 0) return rc;
        if ((u32)rc > n - got) return -5;
        got += (u32)rc;
    }
    return (s32)got;
}

static int read_mem(s32 mem_fd, u32 addr, void *dst, u32 n) {
    return read_mem_rc(mem_fd, addr, dst, n) == (s32)n;
}

static int file_exists(const char *path) {
    s32 fd = -4;
    for (u32 tries = 0; tries < 8u && fd == -4; ++tries)
        fd = sys_call(SYS_OPEN, (u32)path, O_RDONLY, 0, 0, 0, 0);
    if (fd >= 0) {
        sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
        return 1;
    }
    return 0;
}

static int file_fnv(const char *path) {
    s32 fd = sys_call(SYS_OPEN, (u32)path, O_RDONLY, 0, 0, 0, 0);
    if (fd < 0) {
        out_line("FNV missing");
        return 6;
    }
    u8 buf[512];
    u32 h = 2166136261u, total = 0;
    for (;;) {
        s32 n = sys_call(SYS_READ, (u32)fd, (u32)buf, sizeof(buf), 0, 0, 0);
        if (n == -4) continue;
        if (n < 0) {
            sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
            out_line("FNV error");
            return 6;
        }
        if (n == 0) break;
        for (s32 i = 0; i < n; ++i) h = (h ^ buf[i]) * 16777619u;
        total += (u32)n;
    }
    sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
    char line[64];
    u32 p = 0;
    p = app_str(line, p, sizeof(line), "FNV size=");
    p = app_u32(line, p, sizeof(line), total);
    p = app_str(line, p, sizeof(line), " fnv=");
    p = app_hex8(line, p, sizeof(line), h);
    line[p] = 0;
    out_line(line);
    return 0;
}

/* ---- /proc discovery & maps verification ---- */
static int find_im_pid(struct guard_state *g) {
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
                build_proc_path(epath, sizeof(epath), pid, "exe");
                s32 ln = sys_call(SYS_READLINK, (u32)epath, (u32)linkbuf, sizeof(linkbuf) - 1u, 0, 0, 0);
                if (ln > 0 && (u32)ln < sizeof(linkbuf)) {
                    linkbuf[ln] = 0;
                    if (g_streq(linkbuf, "/usr/bin/im.elf")) {
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
    g->im_pid = found;
    return 1;
}

struct map_scan {
    u32 view_base;
    u32 want_shim_lo, want_shim_hi;
    u32 want_hooks_lo, want_hooks_hi;
    u32 want_rects_lo, want_rects_hi;
    u32 find_sp;
    u32 found_vma_hi;
    int check_ranges;
    int find_vma_mode;
    int shim_ok;
    int hooks_ok;
    int rects_ok;
};

static int parse_hex_req(const char **cursor, u32 *out) {
    u32 v = 0, digits = 0;
    const char *p = *cursor;
    while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
        u32 d;
        if (*p <= '9') d = (u32)(*p - '0');
        else if (*p <= 'F') d = (u32)(*p - 'A' + 10);
        else d = (u32)(*p - 'a' + 10);
        if (v > 0x0fffffffu) return 0;
        v = (v << 4) | d;
        ++digits;
        ++p;
    }
    if (!digits) return 0;
    *cursor = p;
    if (out) *out = v;
    return 1;
}

static void handle_map_line(const char *line, struct map_scan *ms) {
    const char *p = line;
    u32 lo = 0, hi = 0, off = 0;
    if (!parse_hex_req(&p, &lo) || *p++ != '-') return;
    if (!parse_hex_req(&p, &hi) || *p++ != ' ') return;
    if ((p[0] != 'r' && p[0] != '-') || (p[1] != 'w' && p[1] != '-') ||
        (p[2] != 'x' && p[2] != '-') || (p[3] != 'p' && p[3] != 's') || p[4] != ' ') return;
    char r = p[0], x = p[2];
    p += 5;
    if (!parse_hex_req(&p, &off) || *p++ != ' ') return;
    if (!parse_hex_req(&p, 0) || *p++ != ':' || !parse_hex_req(&p, 0) || *p++ != ' ') return;
    if (*p < '0' || *p > '9') return;
    while (*p >= '0' && *p <= '9') ++p;
    if (*p != 0 && *p != ' ') return;
    if ((lo & 4095u) || (hi & 4095u) || lo >= hi) return;

    if (ms->find_vma_mode) {
        if (r == 'r' && lo <= ms->find_sp && ms->find_sp < hi)
            ms->found_vma_hi = hi;
        return;
    }

    while (*p && *p != '/') ++p;
    if (*p != '/') return;
    const char *path = p;

    if (!ms->check_ranges) {
        if (!off && r == 'r' && x == 'x' && !ms->view_base && g_endswith(path, "/viewUnified2.so"))
            ms->view_base = lo;
    } else if (g_endswith(path, "/viewUnified2.so")) {
        if (r == 'r' && x == 'x' && lo <= ms->want_shim_lo && ms->want_shim_hi <= hi)
            ms->shim_ok = 1;
        if (r == 'r' && x == 'x' && lo <= ms->want_hooks_lo && ms->want_hooks_hi <= hi)
            ms->hooks_ok = 1;
        if (r == 'r' && lo <= ms->want_rects_lo && ms->want_rects_hi <= hi)
            ms->rects_ok = 1;
    }
}

static int scan_maps(u32 pid, struct map_scan *ms) {
    char mpath[48], buf[512], line[512];
    build_proc_path(mpath, sizeof(mpath), pid, "maps");
    s32 fd = -4;
    for (u32 tries = 0; tries < 8u && fd == -4; ++tries)
        fd = sys_call(SYS_OPEN, (u32)mpath, O_RDONLY, 0, 0, 0, 0);
    if (fd < 0) return 0;
    u32 used = 0, total = 0;
    int eof = 0, overlong = 0;
    while (total < 512u * 1024u) {
        s32 n = sys_call(SYS_READ, (u32)fd, (u32)buf, sizeof(buf), 0, 0, 0);
        if (n == -4) continue;
        if (n < 0 || (u32)n > sizeof(buf)) {
            sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
            return 0;
        }
        if (n == 0) {
            eof = 1;
            break;
        }
        total += (u32)n;
        for (s32 i = 0; i < n; ++i) {
            char ch = buf[i];
            if (ch == '\0') {
                sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
                return 0;
            }
            if (ch == '\n') {
                if (overlong) {
                    sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
                    return 0;
                }
                line[used] = 0;
                handle_map_line(line, ms);
                used = 0;
            } else if (used + 1u < sizeof(line)) {
                line[used++] = ch;
            } else {
                overlong = 1;
            }
        }
    }
    sys_call(SYS_CLOSE, (u32)fd, 0, 0, 0, 0, 0);
    /* Fail closed on any truncated / unterminated / empty / overlong / capped maps stream. */
    return eof && total > 0u && used == 0u && !overlong;
}

static int resolve_target(struct guard_state *g) {
    if (!find_im_pid(g)) return 0;
    struct map_scan ms;
    __aeabi_memclr8(&ms, sizeof(ms));
    if (!scan_maps(g->im_pid, &ms) || !ms.view_base) return 0;

    g->view_base = ms.view_base;
    g->view_bias = ms.view_base - MLV2_REF_VIEW_BASE;
    g->shim_at = MLV2_REF_SHIM_ADDR + g->view_bias;
    g->hook_sr_at = g->view_base + MLV2_HOOK_SET_ROOT_OFF;
    g->hook_rf_at = g->view_base + MLV2_HOOK_REFRESH_OFF;
    g->hook_oi_at = g->view_base + MLV2_HOOK_OPEN_ITEM_OFF;
    g->rect1_at = g->view_base + MLV2_RECT_TBL1_SLOT6;
    g->rect2_at = g->view_base + MLV2_RECT_TBL2_SLOT6;

    ms.check_ranges = 1;
    ms.want_shim_lo = g->shim_at;
    ms.want_shim_hi = g->shim_at + MLV2_SHIM_CAP;
    ms.want_hooks_lo = g->hook_sr_at;
    ms.want_hooks_hi = g->hook_oi_at + 12u;
    ms.want_rects_lo = g->rect1_at - 48u;
    ms.want_rects_hi = g->rect2_at + 8u;
    if (!scan_maps(g->im_pid, &ms)) return 0;
    return ms.shim_ok && ms.hooks_ok && ms.rects_ok;
}

/* ---- thread freeze / resume / poke ---- */
static int enumerate_tids(u32 pid, u32 *out, u32 *count) {
    char tpath[48];
    build_proc_path(tpath, sizeof(tpath), pid, "task");
    s32 dfd = sys_call(SYS_OPEN, (u32)tpath, O_RDONLY, 0, 0, 0, 0);
    if (dfd < 0) return -90;
    u8 dbuf[1024];
    u32 n = 0;
    for (u32 rounds = 0; rounds < 128u; ++rounds) {
        s32 got = sys_call(SYS_GETDENTS64, (u32)dfd, (u32)dbuf, sizeof(dbuf), 0, 0, 0);
        if (got <= 0 || (u32)got > sizeof(dbuf)) break;
        u32 off = 0;
        while (off + 20u <= (u32)got) {
            u32 reclen = (u32)dbuf[off + 16u] | ((u32)dbuf[off + 17u] << 8);
            if (reclen < 20u || off + reclen > (u32)got) break;
            const char *name = (const char *)(dbuf + off + 19u);
            u32 tid = 0;
            if (parse_dec_bounded(name, reclen - 19u, &tid) && tid > 0u) {
                if (n >= MAX_TIDS) {
                    sys_call(SYS_CLOSE, (u32)dfd, 0, 0, 0, 0, 0);
                    return -91;
                }
                out[n++] = tid;
            }
            off += reclen;
        }
    }
    sys_call(SYS_CLOSE, (u32)dfd, 0, 0, 0, 0, 0);
    if (!n) return -90;
    *count = n;
    return 0;
}

static int resume_threads(struct guard_state *g) {
    int result = 0;
    u32 resumed = 0;
    for (u32 i = g->attached; i; --i) {
        u32 n = i - 1u;
        if (!g->owned[n]) continue;
        if (!g->stopped[n]) {
            u32 st = 0;
            s32 got = sys_call(SYS_WAIT4, g->tids[n], (u32)&st, WALL_FLAG | WNOHANG, 0, 0, 0);
            if (got == (s32)g->tids[n] && (st & 0xffu) == 0x7fu) {
                g->stopped[n] = 1;
            } else if (got == (s32)g->tids[n] && ((st & 0x7fu) == 0u || (st & 0xffu) != 0x7fu)) {
                g->owned[n] = 0;
                continue;
            } else {
                result = -92;
                continue;
            }
        }
        if (sys_call(SYS_PTRACE, PTRACE_DETACH, g->tids[n], 0, 0, 0, 0) != 0) {
            result = -92;
        } else {
            g->owned[n] = 0;
            g->stopped[n] = 0;
            ++resumed;
        }
    }
    char line[64];
    u32 p = 0;
    p = app_str(line, p, sizeof(line), "RESUME count=");
    p = app_u32(line, p, sizeof(line), resumed);
    p = app_str(line, p, sizeof(line), " result=");
    p = app_s32(line, p, sizeof(line), result);
    line[p] = 0;
    out_line(line);
    return result;
}

static int freeze_threads(struct guard_state *g) {
    __aeabi_memclr8(g->owned, sizeof(g->owned));
    __aeabi_memclr8(g->stopped, sizeof(g->stopped));
    g->tid_count = 0;
    g->attached = 0;
    int err = enumerate_tids(g->im_pid, g->tids, &g->tid_count);
    if (err) return err;
    for (u32 i = 0; i < g->tid_count; ++i) {
        if (sys_call(SYS_PTRACE, PTRACE_ATTACH, g->tids[i], 0, 0, 0, 0) != 0) {
            resume_threads(g);
            return -93;
        }
        g->owned[i] = 1;
        g->attached++;
        u32 st = 0;
        s32 w = -4;
        while (w == -4) w = sys_call(SYS_WAIT4, g->tids[i], (u32)&st, WALL_FLAG, 0, 0, 0);
        if (w != (s32)g->tids[i] || (st & 0xffu) != 0x7fu) {
            resume_threads(g);
            return -94;
        }
        g->stopped[i] = 1;
    }
    u32 after[MAX_TIDS];
    u32 after_count = 0;
    err = enumerate_tids(g->im_pid, after, &after_count);
    if (err || after_count != g->tid_count) {
        resume_threads(g);
        return err ? err : -95;
    }
    for (u32 i = 0; i < g->tid_count; ++i) {
        if (after[i] != g->tids[i]) {
            resume_threads(g);
            return -95;
        }
    }
    char line[48];
    u32 p = 0;
    p = app_str(line, p, sizeof(line), "FREEZE threads=");
    p = app_u32(line, p, sizeof(line), g->tid_count);
    line[p] = 0;
    out_line(line);
    return 0;
}

static int addr_in_range(u32 a, u32 lo, u32 hi) {
    return lo < hi && a >= lo && a < hi;
}

static int addr_hits_target(const struct guard_state *g, u32 a, u32 core_lo, u32 core_hi) {
    return addr_in_range(a, g->hook_sr_at, g->hook_sr_at + 16u) ||
           addr_in_range(a, g->hook_rf_at, g->hook_rf_at + 16u) ||
           addr_in_range(a, g->hook_oi_at, g->hook_oi_at + 12u) ||
           addr_in_range(a, g->shim_at, g->shim_at + MLV2_SHIM_CAP) ||
           addr_in_range(a, core_lo, core_hi);
}

static int pcs_clear(struct guard_state *g, s32 mfd, u32 core_lo, u32 core_hi, int is_uninstall) {
    for (u32 i = 0; i < g->tid_count; ++i) {
        u32 regs[18];
        __aeabi_memclr8(regs, sizeof(regs));
        if (sys_call(SYS_PTRACE, PTRACE_GETREGS, g->tids[i], 0, (u32)regs, 0, 0) != 0)
            return -17;
        u32 pc = regs[15] & ~1u;
        u32 lr = regs[14] & ~1u;
        u32 sp = regs[13];
        if (addr_hits_target(g, pc, core_lo, core_hi) ||
            addr_hits_target(g, lr, core_lo, core_hi)) {
            char line[80];
            u32 p = 0;
            p = app_str(line, p, sizeof(line), "BUSY tid=");
            p = app_u32(line, p, sizeof(line), g->tids[i]);
            p = app_str(line, p, sizeof(line), " pc=");
            p = app_hex8(line, p, sizeof(line), pc);
            p = app_str(line, p, sizeof(line), " lr=");
            p = app_hex8(line, p, sizeof(line), lr);
            line[p] = 0;
            out_line(line);
            return -17;
        }
        if (is_uninstall) {
            if (!sp || (sp & 3u) || sp + 4u < sp) {
                char line[64];
                u32 p = app_str(line, 0, sizeof(line), "BUSY tid=");
                p = app_u32(line, p, sizeof(line), g->tids[i]);
                p = app_str(line, p, sizeof(line), " sp_unreadable");
                line[p] = 0;
                out_line(line);
                return -17;
            }
            /* Strict VMA-bounded stack scan up to STACK_SCAN_MAX (64 KiB) per thread.
             * Refuses teardown whenever /proc/<pid>/maps cannot prove the readable stack VMA
             * bound for SP, OR whenever any read before that bound fails.
             */
            struct map_scan sms;
            __aeabi_memclr8(&sms, sizeof(sms));
            sms.find_vma_mode = 1;
            sms.find_sp = sp;
            if (!scan_maps(g->im_pid, &sms) || sms.found_vma_hi <= sp) {
                char line[64];
                u32 p = app_str(line, 0, sizeof(line), "BUSY tid=");
                p = app_u32(line, p, sizeof(line), g->tids[i]);
                p = app_str(line, p, sizeof(line), " sp_vma_unknown");
                line[p] = 0;
                out_line(line);
                return -17;
            }
            u32 max_bytes = STACK_SCAN_MAX;
            if (sms.found_vma_hi - sp < max_bytes)
                max_bytes = sms.found_vma_hi - sp;
            u32 scanned = 0u;
            u32 cur = sp;
            u32 stk[64];
            while (scanned < max_bytes) {
                u32 page_rem = 4096u - (cur & 4095u);
                u32 left = max_bytes - scanned;
                u32 chunk = page_rem < left ? page_rem : left;
                if (chunk > sizeof(stk)) chunk = sizeof(stk);
                if (cur + chunk < cur) break;
                s32 rrc = read_mem_rc(mfd, cur, stk, chunk);
                if (rrc != (s32)chunk) {
                    char line[64];
                    u32 p = app_str(line, 0, sizeof(line), "BUSY tid=");
                    p = app_u32(line, p, sizeof(line), g->tids[i]);
                    p = app_str(line, p, sizeof(line), " sp_read_err=");
                    p = app_s32(line, p, sizeof(line), rrc);
                    line[p] = 0;
                    out_line(line);
                    return -17;
                }
                u32 words = chunk >> 2;
                for (u32 k = 0; k < words; ++k) {
                    u32 w = stk[k] & ~1u;
                    if (addr_hits_target(g, w, core_lo, core_hi)) {
                        char line[80];
                        u32 p = app_str(line, 0, sizeof(line), "BUSY tid=");
                        p = app_u32(line, p, sizeof(line), g->tids[i]);
                        p = app_str(line, p, sizeof(line), " stack_ret=");
                        p = app_hex8(line, p, sizeof(line), w);
                        line[p] = 0;
                        out_line(line);
                        return -17;
                    }
                }
                cur += chunk;
                scanned += chunk;
            }
        }
    }
    return 0;
}

static int poke_bytes(u32 leader_tid, u32 addr, const u8 *data, u32 n) {
    if ((addr & 3u) || (n & 3u)) return -1;
    for (u32 off = 0; off < n; off += 4u) {
        u32 w = 0;
        __aeabi_memcpy8(&w, data + off, 4u);
        if (sys_call(SYS_PTRACE, PTRACE_POKETEXT, leader_tid, addr + off, w, 0, 0) != 0)
            return -1;
    }
    return 0;
}

/* Encode Thumb-2 T4 unconditional 32-bit B.W from_va -> target_thumb (single atomic word). */
static int make_thumb_bw(u32 from_va, u32 target_thumb, u8 out[4]) {
    if (!(target_thumb & 1u)) return 0;
    u32 to_va = target_thumb & ~1u;
    s32 disp = (s32)(to_va - (from_va + 4u));
    if ((disp & 1) || disp < -16777216 || disp > 16777214) return 0;
    u32 u = (u32)disp;
    u32 S = (u >> 24) & 1u;
    u32 I1 = (u >> 23) & 1u;
    u32 I2 = (u >> 22) & 1u;
    u32 J1 = (~(I1 ^ S)) & 1u;
    u32 J2 = (~(I2 ^ S)) & 1u;
    u32 imm10 = (u >> 12) & 0x3ffu;
    u32 imm11 = (u >> 1) & 0x7ffu;
    u32 hw1 = 0xf000u | (S << 10) | imm10;
    u32 hw2 = 0x9000u | (J1 << 13) | (J2 << 11) | imm11;
    u32 word = hw1 | (hw2 << 16);
    __aeabi_memcpy8(out, &word, 4u);
    return 1;
}

static int make_branches(const struct guard_state *g, u32 sr, u32 rf, u32 oi,
                         u8 v2_sr[16], u8 v2_rf[16], u8 v2_oi[12]) {
    __aeabi_memcpy8(v2_sr, orig_set_root, 16u);
    __aeabi_memcpy8(v2_rf, orig_refresh, 16u);
    __aeabi_memcpy8(v2_oi, orig_open_item, 12u);
    return make_thumb_bw(g->hook_sr_at, sr, v2_sr) &&
           make_thumb_bw(g->hook_rf_at, rf, v2_rf) &&
           make_thumb_bw(g->hook_oi_at, oi, v2_oi);
}

struct patch_step {
    u32 addr;
    u32 size;
    const u8 *from;
    const u8 *to;
};

static int restore_step_verified(u32 leader_tid, s32 mfd, const struct patch_step *st, u8 *buf) {
    if (read_mem(mfd, st->addr, buf, st->size) && g_memcmp(buf, st->from, st->size) == 0)
        return 0;
    if (poke_bytes(leader_tid, st->addr, st->from, st->size) != 0)
        return -1;
    if (!read_mem(mfd, st->addr, buf, st->size) || g_memcmp(buf, st->from, st->size) != 0)
        return -1;
    return 0;
}

static int check_callback_ptr(u32 fn_va, u32 core_lo, u32 core_hi) {
    if (!fn_va) return 1;
    if (!(fn_va & 1u)) return 0;
    return addr_in_range(fn_va & ~1u, core_lo, core_hi);
}

int guard_main(int argc, char **argv) {
    if (argc == 3 && g_streq(argv[1], "fnv")) return file_fnv(argv[2]);
    int op = -1;
    if (argc == 3) {
        if (g_streq(argv[1], "check")) op = 0;
        else if (g_streq(argv[1], "install")) op = 1;
        else if (g_streq(argv[1], "uninstall")) op = 2;
    }
    if (op < 0) {
        out_line("usage: mlv2_guard.elf check|install|uninstall REQUEST");
        return 2;
    }

    u32 st_bytes = (sizeof(struct guard_state) + 4095u) & ~4095u;
    s32 mem = sys_call(SYS_MMAP2, 0u, st_bytes, 3u, 0x22u, 0xffffffffu, 0u);
    if ((u32)mem >= 0xfffff000u) {
        out_line("MLV2_RESULT=-2 mmap");
        return 2;
    }
    struct guard_state *g = (struct guard_state *)(u32)mem;
    __aeabi_memclr8(g, sizeof(*g));

    u32 h[9], v1[4][3], nrel = 0;
    s32 rfd = sys_call(SYS_OPEN, (u32)argv[2], O_RDONLY, 0, 0, 0, 0);
    int ok = rfd >= 0 &&
             read_exact(rfd, h, sizeof(h)) &&
             h[0] == REQ_MAGIC && h[1] == 2u && h[2] == MLV2_REF_SHIM_ADDR &&
             h[3] > 0u && h[3] <= MLV2_SHIM_CAP && !(h[3] & 3u) &&
             h[8] >= 1u && h[8] <= 4u &&
             read_exact(rfd, v1, h[8] * 12u) &&
             read_exact(rfd, g->shim, h[3]) &&
             read_exact(rfd, &nrel, 4u) && nrel <= MAX_RELOCS &&
             (!nrel || read_exact(rfd, g->rel, nrel * 4u));
    u8 trailing = 0;
    if (ok) {
        s32 extra = sys_call(SYS_READ, (u32)rfd, (u32)&trailing, 1u, 0, 0, 0);
        if (extra != 0) ok = 0;
    }
    if (rfd >= 0) sys_call(SYS_CLOSE, (u32)rfd, 0, 0, 0, 0, 0);
    for (u32 i = 0; ok && i < nrel; ++i) {
        u32 off = g->rel[i] & 0x3fffffffu;
        if (off < 4u || off + 4u > h[3] || (off & 3u) || (g->rel[i] >> 30) > 1u) ok = 0;
    }
    if (!ok || fnv1a(g->shim, h[3]) != h[7] || g_memcmp(g->shim, g->zeros, 4u) != 0) {
        out_line("MLV2_RESULT=-3 request invalid");
        sys_call(SYS_MUNMAP, (u32)g, st_bytes, 0, 0, 0, 0);
        return 3;
    }
    for (u32 i = 4u; i < 7u; ++i) {
        if (!(h[i] & 1u) || h[i] < MLV2_REF_SHIM_ADDR || h[i] >= MLV2_REF_SHIM_ADDR + h[3]) {
            out_line("MLV2_RESULT=-3 entries");
            sys_call(SYS_MUNMAP, (u32)g, st_bytes, 0, 0, 0, 0);
            return 3;
        }
    }
    g->shim_size = h[3];

    if (!resolve_target(g)) {
        out_line("MLV2_RESULT=-5 identity/maps");
        sys_call(SYS_MUNMAP, (u32)g, st_bytes, 0, 0, 0, 0);
        return 5;
    }

    {
        char line[96];
        u32 p = 0;
        p = app_str(line, p, sizeof(line), "TARGET /proc/");
        p = app_u32(line, p, sizeof(line), g->im_pid);
        p = app_str(line, p, sizeof(line), " view_bias=");
        p = app_hex8(line, p, sizeof(line), g->view_bias);
        line[p] = 0;
        out_line(line);
    }

    for (u32 i = 0; i < nrel; ++i) {
        u32 off = g->rel[i] & 0x3fffffffu, w = 0;
        __aeabi_memcpy8(&w, g->shim + off, 4u);
        w += g->view_bias;
        __aeabi_memcpy8(g->shim + off, &w, 4u);
    }
    for (u32 i = 4u; i < 7u; ++i) h[i] += g->view_bias;

    u8 v2_sr[16], v2_rf[16], v2_oi[12];
    if (!make_branches(g, h[4], h[5], h[6], v2_sr, v2_rf, v2_oi)) {
        out_line("MLV2_RESULT=-4 branch_range");
        sys_call(SYS_MUNMAP, (u32)g, st_bytes, 0, 0, 0, 0);
        return 4;
    }

    if (op == 2 && (!file_exists(MLV2_SD_DISABLED) || !file_exists(MLV2_SD_STOPPED))) {
        out_line("MLV2_RESULT=-18 sd-disabled and sd-stopped required before live uninstall");
        sys_call(SYS_MUNMAP, (u32)g, st_bytes, 0, 0, 0, 0);
        return 1;
    }

    char mpath[48];
    build_proc_path(mpath, sizeof(mpath), g->im_pid, "mem");
    s32 mfd = sys_call(SYS_OPEN, (u32)mpath, O_RDONLY, 0, 0, 0, 0);
    if (mfd < 0) {
        out_line("MLV2_RESULT=-10 mem_open");
        sys_call(SYS_MUNMAP, (u32)g, st_bytes, 0, 0, 0, 0);
        return 10;
    }

    int result = 0, changed = 0, frozen = 0;
    if (op != 0) {
        result = freeze_threads(g);
        if (result) {
            sys_call(SYS_CLOSE, (u32)mfd, 0, 0, 0, 0, 0);
            char line[64];
            u32 p = app_str(line, 0, sizeof(line), "MLV2_RESULT=");
            p = app_s32(line, p, sizeof(line), result);
            p = app_str(line, p, sizeof(line), " freeze");
            line[p] = 0;
            out_line(line);
            sys_call(SYS_MUNMAP, (u32)g, st_bytes, 0, 0, 0, 0);
            return 1;
        }
        frozen = 1;
    }

    if (op == 2 && (!file_exists(MLV2_SD_DISABLED) || !file_exists(MLV2_SD_STOPPED))) {
        result = -18;
        goto done;
    }

    u8 cur_sr[16], cur_rf[16], cur_oi[12];
    u8 pre1[48], pre2[48], cur_r1[8], cur_r2[8];
    if (!read_mem(mfd, g->hook_sr_at, cur_sr, 16u) ||
        !read_mem(mfd, g->hook_rf_at, cur_rf, 16u) ||
        !read_mem(mfd, g->hook_oi_at, cur_oi, 12u) ||
        !read_mem(mfd, g->rect1_at - 48u, pre1, 48u) ||
        !read_mem(mfd, g->rect1_at, cur_r1, 8u) ||
        !read_mem(mfd, g->rect2_at - 48u, pre2, 48u) ||
        !read_mem(mfd, g->rect2_at, cur_r2, 8u) ||
        !read_mem(mfd, g->shim_at, g->buf, g->shim_size)) {
        result = -11;
        goto done;
    }

    const char *state =
        (!g_memcmp(cur_sr, orig_set_root, 16u) && !g_memcmp(cur_rf, orig_refresh, 16u) &&
         !g_memcmp(cur_oi, orig_open_item, 12u)) ? "stock" :
        (!g_memcmp(cur_sr, v2_sr, 16u) && !g_memcmp(cur_rf, v2_rf, 16u) &&
         !g_memcmp(cur_oi, v2_oi, 12u)) ? "v2" : "unknown";
    const char *cave =
        !g_memcmp(g->buf, g->zeros, g->shim_size) ? "zero" :
        !g_memcmp(g->buf + 4u, g->shim + 4u, g->shim_size - 4u) ? "shim" : "other";
    int prefix_ok = !g_memcmp(pre1, orig_rect_prefix, 48u) && !g_memcmp(pre2, orig_rect_prefix, 48u);
    const char *rects =
        !prefix_ok ? "mismatch" :
        (!g_memcmp(cur_r1, orig_rect, 8u) && !g_memcmp(cur_r2, orig_rect, 8u)) ? "stock" :
        (!g_memcmp(cur_r1, patch_rect, 8u) && !g_memcmp(cur_r2, patch_rect, 8u)) ? "patched" : "other";

    {
        char line[96];
        u32 p = 0;
        p = app_str(line, p, sizeof(line), "STATE hooks=");
        p = app_str(line, p, sizeof(line), state);
        p = app_str(line, p, sizeof(line), " rects=");
        p = app_str(line, p, sizeof(line), rects);
        p = app_str(line, p, sizeof(line), " shim=");
        p = app_str(line, p, sizeof(line), cave);
        line[p] = 0;
        out_line(line);
    }

    if (op == 0) goto done;

    if (op == 1) {
        if (g_streq(state, "v2") && g_streq(cave, "shim") && g_streq(rects, "patched")) {
            out_line("ALREADY_INSTALLED");
            goto done;
        }
        if (!g_streq(cave, "zero")) { result = -12; goto done; }
        if (!g_streq(state, "stock")) { result = -13; goto done; }
        if (!g_streq(rects, "stock")) { result = -14; goto done; }
        if ((result = pcs_clear(g, mfd, 0u, 0u, 0)) != 0) goto done;

        /* Every hook step is a SINGLE 4-byte atomic Thumb-2 B.W instruction. */
        struct patch_step plan[6] = {
            {g->shim_at, g->shim_size, g->zeros, g->shim},
            {g->rect1_at, 8u, orig_rect, patch_rect},
            {g->rect2_at, 8u, orig_rect, patch_rect},
            {g->hook_sr_at, 4u, orig_set_root, v2_sr},
            {g->hook_rf_at, 4u, orig_refresh, v2_rf},
            {g->hook_oi_at, 4u, orig_open_item, v2_oi},
        };
        for (u32 i = 0; i < 6u; ++i) {
            if (poke_bytes(g->tids[0], plan[i].addr, plan[i].to, plan[i].size) != 0 ||
                !read_mem(mfd, plan[i].addr, g->buf, plan[i].size) ||
                g_memcmp(g->buf, plan[i].to, plan[i].size) != 0) {
                int rb = 0;
                /* Roll back 1-word hooks first; NEVER erase shim cave if any hook rollback fails. */
                for (u32 j = i + 1u; j > 3u; --j) {
                    if (restore_step_verified(g->tids[0], mfd, &plan[j - 1u], g->buf) != 0)
                        rb = 1;
                }
                if (!rb) {
                    u32 top = i < 2u ? (i + 1u) : 3u;
                    for (u32 j = top; j; --j) {
                        if (restore_step_verified(g->tids[0], mfd, &plan[j - 1u], g->buf) != 0)
                            rb = 1;
                    }
                }
                char line[64];
                u32 p = app_str(line, 0, sizeof(line), "ROLLBACK step=");
                p = app_u32(line, p, sizeof(line), i);
                p = app_str(line, p, sizeof(line), " failed=");
                p = app_s32(line, p, sizeof(line), rb);
                line[p] = 0;
                out_line(line);
                changed = rb ? 1 : 0;
                result = rb ? -16 : -15;
                goto done;
            }
        }
        changed = 1;
        {
            char line[128];
            u32 p = 0;
            p = app_str(line, p, sizeof(line), "INSTALLED shim=");
            p = app_hex8(line, p, sizeof(line), g->shim_at);
            p = app_str(line, p, sizeof(line), "..");
            p = app_hex8(line, p, sizeof(line), g->shim_at + g->shim_size);
            p = app_str(line, p, sizeof(line), " hooks=");
            p = app_hex8(line, p, sizeof(line), h[4]);
            p = app_str(line, p, sizeof(line), ",");
            p = app_hex8(line, p, sizeof(line), h[5]);
            p = app_str(line, p, sizeof(line), ",");
            p = app_hex8(line, p, sizeof(line), h[6]);
            line[p] = 0;
            out_line(line);
        }
    } else if (op == 2) {
        if (g_streq(state, "stock") && g_streq(cave, "zero") && g_streq(rects, "stock")) {
            out_line("ALREADY_STOCK");
            goto done;
        }
        if (!g_streq(state, "v2")) { result = -13; goto done; }
        if (!g_streq(cave, "shim")) { result = -12; goto done; }
        if (!g_streq(rects, "patched")) { result = -14; goto done; }

        /* Preserve exact live shim bytes (including slot word). */
        __aeabi_memcpy8(g->live_shim, g->buf, g->shim_size);

        u32 slot_ptr = 0, core_lo = 0, core_hi = 0;
        __aeabi_memcpy8(&slot_ptr, g->live_shim, 4u);
        if (slot_ptr) {
            ShimState st;
            __aeabi_memclr8(&st, sizeof(st));
            if (!read_mem(mfd, slot_ptr, &st, sizeof(st)) || st.magic != MLV2_SHIM_MAGIC) {
                result = -17;
                goto done;
            }
            if (st.active != 0u || st.core_loads > 1u || (!st.core_base && st.core_load_lock != 0u)) {
                out_line("BUSY shim_active");
                result = -17;
                goto done;
            }
            if (st.core_base) {
                if ((st.core_base & 4095u) || (st.core_size & 4095u) ||
                    st.core_size < 4096u || st.core_size > MLV2_CORE_MAX ||
                    st.core_base + st.core_size <= st.core_base) {
                    result = -17;
                    goto done;
                }
                core_lo = st.core_base;
                core_hi = st.core_base + st.core_size;
                if (!check_callback_ptr((u32)st.before_set_root, core_lo, core_hi) ||
                    !check_callback_ptr((u32)st.after_refresh, core_lo, core_hi) ||
                    !check_callback_ptr((u32)st.before_enter, core_lo, core_hi)) {
                    result = -17;
                    goto done;
                }
            } else if (st.core_size || st.before_set_root || st.after_refresh || st.before_enter) {
                result = -17;
                goto done;
            }
            if (st.ctx) {
                /* Verify orig_root AND every tracked root in Ctx.tracked[0..tracked_count-1]
                 * no longer points at Ctx.root_children (offset +520).
                 */
                u32 ctx_prefix[8u + MLV2_MAX_TRACKED_ROOTS * 3u];
                if (!read_mem(mfd, (u32)st.ctx, ctx_prefix, sizeof(ctx_prefix)) ||
                    ctx_prefix[0] != MLV2_CTX_MAGIC ||
                    ctx_prefix[7] > MLV2_MAX_TRACKED_ROOTS) {
                    result = -17;
                    goto done;
                }
                u32 synth_kids = (u32)st.ctx + MLV2_CTX_ROOT_CHILDREN_OFF;
                u32 orig_root = ctx_prefix[6];
                if (orig_root) {
                    u32 root_kids = 0;
                    if (!read_mem(mfd, orig_root + 4u, &root_kids, 4u) || root_kids == synth_kids) {
                        out_line("BUSY orig_root_extended");
                        result = -17;
                        goto done;
                    }
                }
                u32 tcnt = ctx_prefix[7];
                for (u32 ti = 0; ti < tcnt; ++ti) {
                    u32 tr_root = ctx_prefix[8u + ti * 3u];
                    if (!tr_root) continue;
                    u32 root_kids = 0;
                    if (!read_mem(mfd, tr_root + 4u, &root_kids, 4u) || root_kids == synth_kids) {
                        out_line("BUSY orig_root_extended");
                        result = -17;
                        goto done;
                    }
                }
            }
        }

        if ((result = pcs_clear(g, mfd, core_lo, core_hi, 1)) != 0) goto done;

        /* Safe uninstall order: restore 1-word hooks FIRST, then rects, then zero cave LAST. */
        struct patch_step plan[6] = {
            {g->hook_oi_at, 4u, v2_oi, orig_open_item},
            {g->hook_rf_at, 4u, v2_rf, orig_refresh},
            {g->hook_sr_at, 4u, v2_sr, orig_set_root},
            {g->rect2_at, 8u, patch_rect, orig_rect},
            {g->rect1_at, 8u, patch_rect, orig_rect},
            {g->shim_at, g->shim_size, g->live_shim, g->zeros},
        };
        for (u32 i = 0; i < 6u; ++i) {
            if (poke_bytes(g->tids[0], plan[i].addr, plan[i].to, plan[i].size) != 0 ||
                !read_mem(mfd, plan[i].addr, g->buf, plan[i].size) ||
                g_memcmp(g->buf, plan[i].to, plan[i].size) != 0) {
                int rb = 0;
                if (i < 3u) {
                    /* Cave & rects are still 100% intact; safe to restore already-changed 1-word hooks. */
                    for (u32 j = i + 1u; j; --j) {
                        if (restore_step_verified(g->tids[0], mfd, &plan[j - 1u], g->buf) != 0)
                            rb = 1;
                    }
                    changed = rb ? 1 : 0;
                    result = rb ? -16 : -15;
                } else {
                    /* All 3 hooks are ALREADY 100% stock: NEVER re-enable hooks into a damaged cave! */
                    rb = 1;
                    changed = 1;
                    result = -16;
                }
                char line[64];
                u32 p = app_str(line, 0, sizeof(line), "ROLLBACK step=");
                p = app_u32(line, p, sizeof(line), i);
                p = app_str(line, p, sizeof(line), " failed=");
                p = app_s32(line, p, sizeof(line), rb);
                line[p] = 0;
                out_line(line);
                goto done;
            }
        }
        changed = 1;
        out_line("UNINSTALLED restored=stock");
    }

done:
    if (frozen) {
        int r = resume_threads(g);
        if (!result) result = r;
    }
    sys_call(SYS_CLOSE, (u32)mfd, 0, 0, 0, 0, 0);
    {
        char line[64];
        u32 p = 0;
        p = app_str(line, p, sizeof(line), "MLV2_RESULT=");
        p = app_s32(line, p, sizeof(line), result);
        p = app_str(line, p, sizeof(line), " changed=");
        p = app_s32(line, p, sizeof(line), changed);
        line[p] = 0;
        out_line(line);
    }
    sys_call(SYS_MUNMAP, (u32)g, st_bytes, 0, 0, 0, 0);
    return result ? 1 : 0;
}

__asm__(".arm\n.global _start\n.type _start,%function\n_start:\n"
        "ldr r0, [sp, #0]\n"
        "add r1, sp, #4\n"
        "bic sp, sp, #7\n"
        "bl guard_main\n"
        "mov r7, #1\n"
        "svc 0\n"
        "b .\n"
        ".size _start,.-_start\n");
