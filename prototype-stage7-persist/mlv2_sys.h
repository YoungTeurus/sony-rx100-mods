/* Raw ARM Linux EABI syscalls and freestanding helpers for M7 1.00 mlv2 shim and core.
 * No libc, no globals; volatile byte loops prevent clang from emitting __aeabi_mem* calls.
 */
#ifndef MLV2_SYS_H
#define MLV2_SYS_H
#include <stdint.h>
#include "mlv2.h"

#define ML_O_RDONLY         0
#define ML_O_WR_CREAT_APP   0x441
#define ML_O_WR_CREAT_TRUNC 0x241
#define ML_O_NONBLOCK       04000
#define ML_O_DIRECTORY      040000
#define ML_O_NOFOLLOW       0100000
#define ML_PROT_RWX         7
#define ML_MAP_ANON_PRIV    0x22
#define MLV2_LOG_MAX_BYTES  16384u

static inline int ml_sc3(int n, int a, int b, int c) {
    register int r0 __asm__("r0") = a, r1 __asm__("r1") = b, r2 __asm__("r2") = c;
    register int r7 __asm__("r7") = n;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}

static inline int ml_open(const char *p, int flags) { return ml_sc3(5, (int)p, flags, 0644); }
static inline int ml_read(int fd, void *b, uint32_t n) { return ml_sc3(3, fd, (int)b, (int)n); }
static inline int ml_write(int fd, const void *b, uint32_t n) { return ml_sc3(4, fd, (int)b, (int)n); }
static inline int ml_close(int fd) { return ml_sc3(6, fd, 0, 0); }
static inline int ml_unlink(const char *p) { return ml_sc3(10, (int)p, 0, 0); }
static inline int ml_lseek(int fd, uint32_t off) { return ml_sc3(19, fd, (int)off, 0); }
static inline int ml_lseek_end(int fd) { return ml_sc3(19, fd, 0, 2); }
static inline int ml_getdents64(int fd, void *b, uint32_t n) { return ml_sc3(217, fd, (int)b, (int)n); }
static inline int ml_mprotect(uint32_t a, uint32_t n, int prot) { return ml_sc3(125, (int)a, (int)n, prot); }
static inline int ml_munmap(uint32_t a, uint32_t n) { return ml_sc3(91, (int)a, (int)((n + 0xfffu) & ~0xfffu), 0); }

/* Fail-closed non-blocking absence check: returns 1 ONLY when open() confirms -ENOENT (-2). */
static inline int ml_path_absent(const char *path) {
    int fd = -4;
    for (int i = 0; i < 8 && fd == -4; i++)
        fd = ml_open(path, ML_O_RDONLY | ML_O_NONBLOCK | ML_O_NOFOLLOW);
    if (fd >= 0) { ml_close(fd); return 0; }
    return fd == -2;
}

static inline uint32_t ml_atomic_cas_zero(volatile uint32_t *p, uint32_t desired) {
    uint32_t old, status;
    __asm__ volatile(
        "   dmb ish\n"
        "1: ldrex %0, [%2]\n"
        "   cmp %0, #0\n"
        "   bne 2f\n"
        "   strex %1, %3, [%2]\n"
        "   cmp %1, #0\n"
        "   bne 1b\n"
        "   dmb ish\n"
        "   b 3f\n"
        "2: clrex\n"
        "3:\n"
        : "=&r"(old), "=&r"(status)
        : "r"(p), "r"(desired)
        : "memory", "cc");
    return old;
}

static inline void ml_atomic_store_rel(volatile uint32_t *p, uint32_t val) {
    __asm__ volatile("dmb ish" ::: "memory");
    *p = val;
    __asm__ volatile("dmb ish" ::: "memory");
}

static inline int ml_is_disabled(void) {
    return !ml_path_absent(MLV2_SD_DISABLED) || !ml_path_absent(MLV2_SD_STOPPED);
}

static inline uint32_t ml_mmap_rwx(uint32_t len) {
    register int r0 __asm__("r0") = 0;
    register int r1 __asm__("r1") = (int)((len + 0xfffu) & ~0xfffu);
    register int r2 __asm__("r2") = ML_PROT_RWX;
    register int r3 __asm__("r3") = ML_MAP_ANON_PRIV;
    register int r4 __asm__("r4") = -1;
    register int r5 __asm__("r5") = 0;
    register int r7 __asm__("r7") = 192; /* mmap2 */
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r7) : "memory");
    return (uint32_t)r0 >= 0xfffff000u ? 0u : (uint32_t)r0;
}

static inline void ml_cacheflush(uint32_t beg, uint32_t end) {
    register uint32_t r0 __asm__("r0") = beg, r1 __asm__("r1") = end, r2 __asm__("r2") = 0;
    register uint32_t r7 __asm__("r7") = 0x0f0002u;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
}

static inline int ml_affinity(int nr, uint32_t *mask) { /* 241 set, 242 get */
    return ml_sc3(nr, 0, 4, (int)mask);
}

/* Flush I/D caches on all 4 Cortex-A5 CPUs on Linux 3.0.27 SMP. */
static inline void ml_flush_all(uint32_t beg, uint32_t end) {
    uint32_t old = 0, mask;
    ml_affinity(242, &old);
    for (uint32_t cpu = 0; cpu < 4u; cpu++) {
        mask = 1u << cpu;
        if (ml_affinity(241, &mask) == 0) ml_cacheflush(beg, end);
    }
    if (old) ml_affinity(241, &old);
}

static inline int ml_make_rwx(uint32_t addr, uint32_t len) {
    uint32_t beg = addr & ~0xfffu, end = (addr + len + 0xfffu) & ~0xfffu;
    return ml_mprotect(beg, end - beg, ML_PROT_RWX);
}

static inline uint32_t ml_fnv1a_more(uint32_t h, const uint8_t *d, uint32_t n) {
    while (n--) { h ^= *d++; h *= 0x01000193u; }
    return h;
}
static inline uint32_t ml_fnv1a(const uint8_t *d, uint32_t n) {
    return ml_fnv1a_more(0x811c9dc5u, d, n);
}

static inline void ml_memcpy(void *dst, const void *src, uint32_t n) {
    volatile uint8_t *d = (volatile uint8_t *)dst;
    const volatile uint8_t *s = (const volatile uint8_t *)src;
    while (n--) *d++ = *s++;
}

static inline void ml_memset(void *dst, uint8_t v, uint32_t n) {
    volatile uint8_t *d = (volatile uint8_t *)dst;
    while (n--) *d++ = v;
}

static inline int ml_memcmp(const void *a, const void *b, uint32_t n) {
    const uint8_t *pa = (const uint8_t *)a, *pb = (const uint8_t *)b;
    while (n--) { if (*pa != *pb) return (int)*pa - (int)*pb; pa++; pb++; }
    return 0;
}

static inline int ml_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(uint8_t)*a - (int)(uint8_t)*b;
}

static inline int ml_fd_is_regular(int fd) {
    uint8_t st[104];
    ml_memset(st, 0, sizeof(st));
    if (ml_sc3(197, fd, (int)st, 0) != 0) return 0;
    uint32_t mode = (uint32_t)st[16] | ((uint32_t)st[17] << 8) |
                    ((uint32_t)st[18] << 16) | ((uint32_t)st[19] << 24);
    return (mode & 0170000u) == 0100000u;
}

static inline void ml_log_to_locked(volatile uint32_t *lock, const char *path,
                                    int flags, const char *msg, uint32_t val) {
    int locked = 0;
    if (lock && flags == ML_O_WR_CREAT_APP) {
        for (uint32_t spin = 0u; spin < 4096u; spin++) {
            if (ml_atomic_cas_zero(lock, 1u) == 0u) {
                locked = 1;
                break;
            }
        }
        if (!locked) return;
    }
    int fd = ml_open(path, flags | ML_O_NONBLOCK | ML_O_NOFOLLOW);
    if (fd >= 0) {
        if (ml_fd_is_regular(fd)) {
            char buf[64];
            uint32_t i = 0;
            while (*msg && i + 12u < sizeof(buf)) buf[i++] = *msg++;
            buf[i++] = ' ';
            for (int s = 28; s >= 0; s -= 4) {
                uint32_t d = (val >> s) & 0xfu;
                buf[i++] = (char)(d < 10u ? ('0' + d) : ('a' + d - 10u));
            }
            buf[i++] = '\n';
            int allow = 1;
            if (flags == ML_O_WR_CREAT_APP) {
                int end = ml_lseek_end(fd);
                if (end < 0 || (uint32_t)end > MLV2_LOG_MAX_BYTES || i > MLV2_LOG_MAX_BYTES - (uint32_t)end) {
                    allow = 0;
                }
            }
            if (allow) ml_write(fd, buf, i);
        }
        ml_close(fd);
    }
    if (locked) ml_atomic_store_rel(lock, 0u);
}

static inline void ml_log_to(const char *path, int flags, const char *msg, uint32_t val) {
    ml_log_to_locked(0, path, flags, msg, val);
}

static inline void ml_log_s(ShimState *s, const char *msg, uint32_t val) {
    ml_log_to_locked(s ? &s->log_lock : 0, MLV2_LOG_PATH, ML_O_WR_CREAT_APP, msg, val);
}

static inline void ml_log(const char *msg, uint32_t val) {
    ml_log_to_locked(0, MLV2_LOG_PATH, ML_O_WR_CREAT_APP, msg, val);
}

#endif
