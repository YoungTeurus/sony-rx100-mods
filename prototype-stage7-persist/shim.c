/* Mod Loader v2 shim for DSC-RX100M7 1.00 (resident in viewUnified2.so RX zero tail).
 *
 * Loads /tmp_network/mlv2/core.bin into RWX mmap memory on set_root, tracks in-flight
 * callbacks with ARMv7 ldrex/strex + dmb ish atomics (including the full Sony refresh()
 * call stack via ml_refresh_enter/ml_refresh_leave), hides the 6-tab backdrop widget at
 * menu + 0x97c while active, and stays 100% pass-through when core.bin is absent or
 * sd-disabled is set.
 */
#include "mlv2.h"
#include "mlv2_sys.h"

__attribute__((section(".text.slot"), used)) const volatile uint32_t mlv2_slot = 0;
__attribute__((section(".text.slotb"), used)) const volatile uint32_t mlv2_view_bias = MLV2_VIEW_BASE - MLV2_REF_VIEW_BASE;
__attribute__((section(".text.slotb"), used)) const volatile uint32_t mlv2_shim_bias = MLV2_SHIM_ADDR - MLV2_REF_SHIM_ADDR;

static void atomic_inc(volatile uint32_t *p) {
    uint32_t v, status;
    __asm__ volatile(
        "1: ldrex %0, [%2]\n"
        "   add %0, %0, #1\n"
        "   strex %1, %0, [%2]\n"
        "   cmp %1, #0\n"
        "   bne 1b\n"
        "   dmb ish\n"
        : "=&r"(v), "=&r"(status)
        : "r"(p)
        : "memory", "cc");
}

static void atomic_dec(volatile uint32_t *p) {
    uint32_t v, status;
    __asm__ volatile(
        "   dmb ish\n"
        "1: ldrex %0, [%2]\n"
        "   sub %0, %0, #1\n"
        "   strex %1, %0, [%2]\n"
        "   cmp %1, #0\n"
        "   bne 1b\n"
        : "=&r"(v), "=&r"(status)
        : "r"(p)
        : "memory", "cc");
}

static ShimState *shim_state(int create) {
    volatile uint32_t *slot = (volatile uint32_t *)&mlv2_slot;
    ShimState *s = (ShimState *)*slot;
    if (s && s->magic == MLV2_SHIM_MAGIC) {
        if (s->layout_magic != MLV2_LAYOUT_MAGIC) {
            s->view_bias = mlv2_view_bias;
            s->shim_bias = mlv2_shim_bias;
            s->layout_magic = MLV2_LAYOUT_MAGIC;
        }
        return s;
    }
    if (!create) return 0;
    uint32_t m = ml_mmap_rwx(4096u);
    if (!m) return 0;
    if (ml_make_rwx((uint32_t)&mlv2_slot, 4u) < 0) {
        ml_munmap(m, 4096u);
        return 0;
    }
    s = (ShimState *)m;
    ml_memset(s, 0, sizeof(*s));
    s->magic = MLV2_SHIM_MAGIC;
    s->view_bias = mlv2_view_bias;
    s->shim_bias = mlv2_shim_bias;
    s->layout_magic = MLV2_LAYOUT_MAGIC;
    uint32_t prev = ml_atomic_cas_zero(slot, m);
    if (prev != 0u) {
        ml_munmap(m, 4096u);
        s = (ShimState *)prev;
        return (s->magic == MLV2_SHIM_MAGIC) ? s : 0;
    }
    return s;
}

static uint32_t atomic_load_acq(const volatile uint32_t *p) {
    uint32_t val = *p;
    __asm__ volatile("dmb ish" ::: "memory");
    return val;
}

static void shim_try_core(ShimState *s) {
    if (s->core_base) return;
    if (ml_atomic_cas_zero(&s->core_load_lock, 1u) != 0u) return;
    if (s->core_base) return;
    int fd = ml_open(MLV2_CORE_PATH, ML_O_RDONLY | ML_O_NONBLOCK | ML_O_NOFOLLOW);
    if (fd < 0) {
        ml_atomic_store_rel(&s->core_load_lock, 0u);
        return;
    }
    if (!ml_fd_is_regular(fd)) {
        ml_close(fd);
        ml_atomic_store_rel(&s->core_load_lock, 0u);
        return;
    }
    MlCoreHeader h;
    if (ml_read(fd, &h, sizeof(h)) != (int)sizeof(h) || h.magic != MLV2_CORE_MAGIC ||
        h.version != MLV2_CORE_VERSION || !h.code_size || h.code_size > MLV2_CORE_MAX ||
        (h.code_size & 3u) || !(h.init_off & 1u) || h.init_off >= h.code_size || h.fnv1a_32 == s->core_fnv) {
        ml_close(fd);
        ml_atomic_store_rel(&s->core_load_lock, 0u);
        return;
    }
    uint32_t base = ml_mmap_rwx(h.code_size);
    if (!base) {
        ml_close(fd);
        ml_atomic_store_rel(&s->core_load_lock, 0u);
        return;
    }
    int n = ml_read(fd, (void *)base, h.code_size);
    ml_close(fd);
    if (n != (int)h.code_size || ml_fnv1a((const uint8_t *)base, h.code_size) != h.fnv1a_32) {
        ml_munmap(base, h.code_size);
        ml_log_s(s, "core_bad", h.fnv1a_32);
        ml_atomic_store_rel(&s->core_load_lock, 0u);
        return;
    }
    ml_flush_all(base, base + h.code_size);
    int rc = ((int (*)(ShimState *))(base + h.init_off))(s);
    if (rc) {
        ml_munmap(base, h.code_size);
        ml_log_s(s, "core_reject", (uint32_t)rc);
        ml_atomic_store_rel(&s->core_load_lock, 0u);
        return;
    }
    s->core_fnv = h.fnv1a_32;
    s->core_size = (h.code_size + 0xfffu) & ~0xfffu;
    s->core_loads = 1u;
    ml_log_s(s, "core_load", h.fnv1a_32);
    ml_atomic_store_rel(&s->core_base, base);
}

uint32_t ml_before_set_root(uint32_t menu, uint32_t root) {
    ShimState *s = shim_state(1);
    if (!s) return root;
    atomic_inc(&s->active);
    shim_try_core(s);
    uint32_t out = (atomic_load_acq(&s->core_base) && s->before_set_root) ? s->before_set_root(menu, root) : root;
    atomic_dec(&s->active);
    return out;
}

ShimState *ml_refresh_enter(void) {
    ShimState *s = shim_state(1);
    if (s) atomic_inc(&s->active);
    return s;
}

void ml_refresh_leave(uint32_t menu, ShimState *s) {
    if (!s) return;
    if (atomic_load_acq(&s->core_base) && s->after_refresh) {
        if (!ml_is_disabled()) {
            ((void (*)(void *, int))MLV2_SET_MODE)((void *)(menu + MLV2_TAB_BACKDROP_OFF), 3);
        }
        s->after_refresh(menu);
    }
    atomic_dec(&s->active);
}

int ml_before_enter(uint32_t menu, uint32_t leaf) {
    ShimState *s = shim_state(0);
    if (!s || !atomic_load_acq(&s->core_base) || !s->before_enter) return -1;
    atomic_inc(&s->active);
    int rc = s->before_enter(menu, leaf);
    atomic_dec(&s->active);
    return rc;
}
