/*
 * Stage 6 WIP v2: Standalone lazy-armed RAM Pre-Capture worker (ring.elf).
 *
 * Architectural contract:
 * - Reuses Stage 5's unmodified verified Sony code pins, ptrace/trap engine,
 *   ObjMedia4100/ObjStillRecorder/ObjCntMgr route management, hold/hash/commit
 *   JPEG writer, and InfraInput reader directly via -I../prototype-producer-probe.
 * - Immutable on-camera ELF: compiled with -fdata-sections; PT_LOAD[0] (PF_R|PF_X)
 *   holds all code + read-only data + m7_s6_ring_boot (nonce + RW segment bounds);
 *   PT_LOAD[1] (PF_R|PF_W, non-executable) holds ONLY m7_config and m7_precap_config.
 * - At startup, loads /tmp_network/.m7-s6-<nonce>/run.cfg, validates magic/version/
 *   nonce/checksum/bounds, populates m7_config & m7_precap_config, and immediately
 *   locks PT_LOAD[1] read-only via mprotect(PROT_READ) (full RELRO) before touching
 *   im.elf!
 * - Lazy-armed: launched ONLY after stage6_daemon observes idle -> debounced physical
 *   half-press with Release w/o Card = ON, Continuous, JPEG L 20M 3:2, sub_en = 1.
 * - Zero-gap arming: checks half==1 && full==0 && !disarm && !stop BEFORE Insert4100,
 *   BEFORE mode_set(0x4100), and WHILE connect_pair(3) is held after mode_drain(3,1),
 *   installing the 0xde01 trap directly without releasing rec_tid in between!
 * - Responds to per-nonce /stop, /disarm, or parent orphan (getppid()==1) by cleanly
 *   cancelling via s->reason=4 -> PRECAP_DRAIN -> trap restore -> detach -> mode_set(SD)
 *   -> Pullout4100 -> exit 0.
 */
#include "stage6_v2_common.h"

#define M7_RAM_FRAMES     2
#define M7_RAM_COMMIT     1
#define M7_RAM_CONTINUOUS 1
#define M7_RAM_PRECAPTURE 1
#define M7_RAM_PROBE      0
#define M7_RAM_HOLD       0
#define M7_RAM_RING       0
#define M7_RAM_LATE_REGISTER 0

struct observer;
struct ram_capture;
struct precap_state;
static void precap_sample(struct observer *o);
static void precap_wait(struct observer *, unsigned int);
static void precap_save_sample(struct observer *);
static void precap_file_timing(struct observer *, unsigned int, unsigned int, unsigned int);
static int precap_keep_source(struct observer *, struct ram_capture *);
static void precap_progress(struct observer *, unsigned int, unsigned int, int);
static int precap_blocked(struct observer *, unsigned int, unsigned int, unsigned int, unsigned int);
static void precap_tick(struct observer *, struct ram_capture *);
static void precap_admission_idle(struct observer *);
static void precap_flush_ready(struct observer *, struct ram_capture *);
static void precap_retire_ring(struct observer *, struct precap_state *);
static int precap_boundary_done(struct observer *o, struct ram_capture *r);
#define M7_SAMPLE_OVERRIDE precap_sample

static int unused_start_main(void) __attribute__((unused));
#define START_ENTRY unused_start_main
#include "start_native.c"

_Static_assert(sizeof(struct config) == sizeof(struct s6_wire_config), "wire config size");

/* Sealed read-only boot header (stays in PT_LOAD[0] PF_R|PF_X). */
const volatile struct s6_ring_boot m7_s6_ring_boot = {
    .magic = S6_RING_BOOT_MAGIC,
    .version = S6_RING_BOOT_VERSION,
    .rw_vaddr = 0u,
    .rw_size = 0u,
    .nonce = {'0','0','0','0','0','0','0','0','0','0','0','0'},
};

void __aeabi_memcpy(void *destination, const void *source, u32 count) {
    volatile unsigned char *out = destination;
    const unsigned char *in = source;
    for (u32 i = 0; i < count; ++i) out[i] = in[i];
}

void __aeabi_memcpy4(void *destination, const void *source, u32 count) {
    __aeabi_memcpy(destination, source, count);
}

u32 __aeabi_uidiv(u32 numerator, u32 denominator) {
    u32 bit = 1, quotient = 0;
    if (!denominator) return 0;
    while (denominator < numerator && !(denominator & 0x80000000u)) { denominator <<= 1; bit <<= 1; }
    while (bit) {
        if (numerator >= denominator) { numerator -= denominator; quotient |= bit; }
        denominator >>= 1; bit >>= 1;
    }
    return quotient;
}

__asm__(".global __aeabi_uidivmod\n"
        "__aeabi_uidivmod:\n"
        "push {r0,r1,r4,lr}\n"
        "bl __aeabi_uidiv\n"
        "pop {r2,r3,r4,lr}\n"
        "mul r1,r0,r3\n"
        "sub r1,r2,r1\n"
        "bx lr\n");

static void session_notice(struct observer *o, u32 stage, u32 a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g) {
    u32 data[8] = {stage, a, b, c, d, e, f, g}, previous = o->phase;
    o->phase = 22; emit(o, 60, data); o->phase = previous;
}

#include "ram_continuous.c"
#include "ram_stop_diagnostics.c"
#include "sd_input.c"

#define PRECAP_MAX_PRE 16u
#define PRECAP_MAX_IDS 128u
#define PRECAP_MAX_HELD 2u
#define PRECAP_SLOTS 4u
#define PRECAP_POST_MS 30000u
#define PRECAP_DRAIN_FRAME_MS 2500u
#define PRECAP_HEARTBEAT_MS 500u
#define PRECAP_FRESH_MS 100u
#define PRECAP_REGISTRATION_SLICE 16u
#define PRECAP_DRAIN_ABSOLUTE_MS 180000u
#define S6_SAVE_BUDGET_MS 60000u
#define S6_SINGLE_SAVE_TIMEOUT_MS 30000u
#define PRECAP_NONE 0xffffffffu
#define S6_COPY_CHUNK 8192u

enum precap_phase { PRECAP_IDLE, PRECAP_ARMED, PRECAP_POST, PRECAP_DRAIN, PRECAP_RESTORE };

struct precap_config {
    u32 magic, revision, before, after, backlog_cap, sample_ms, window_ms, drain_ms;
    u32 burst_cap, post_max;
};
_Static_assert(sizeof(struct precap_config) == sizeof(struct s6_wire_precap_config), "wire precap size");
const volatile struct precap_config m7_precap_config = {0x32525043, 8, 5, 0, 96, 25, 120000, 5000, 24, 48};

struct precap_frame {
    struct ring_owner owner;
    u32 ordinal, capture, uid, ready_ms, role;
};
struct precap_identity { u32 capture, observed_ms, role; };
struct precap_state {
    struct sd_input input;
    struct sd_start_command start;
    struct precap_frame frames[PRECAP_MAX_HELD];
    struct precap_identity ids[PRECAP_MAX_IDS];
    u32 id_count, pre_frozen, announced, cursor, cursor_ready, backlog_at, backlog_seen, backlog_gap, backlog_busy, queue_depth, backlog_valid, committed;
    u32 half, full, state, trigger_ms, ready, input_serial, input_at, armed_at, armed_end;
    u32 count, delivered, evicted, saved, post, post_limit_hit, post_cutoff_cause, started, released, sampling, reason;
    u32 capacity, free_bytes, half_low, full_low, drained;
    u32 stop_at, save_active, save_started_at, blocked, drain_expired, drain_q_overflow;
    u32 drain_sample, drain_changed, drain_cap, drain_open, drain_valid, drain_seen, drain_state[6];
    u32 manager, queue, queue_peak, pace_at, pulses, pulse_active, roll_at;
    u32 phase_burst, s2_cmd_val, s2_cmd_active, s2_down, s2_changed_ms, s2_child_failed;
    u32 fast_drops, save_ms_total;
    u32 core, descriptor, hold_done, diagnostic_errors;
    u32 s2_up, s1_up, planned_up, abort_up, samples, max_gap, last_sample, heartbeat, pass_at, pass, pass_bytes;
    u32 disarm_checked_ms, disarm_seen, hold_lost, prearm_check_sub;
    char stop_path[64];
    char disarm_path[64];
    u32 pool_nodes[512];
    u32 pool_uids[512];
    unsigned char io_buf[S6_COPY_CHUNK] __attribute__((aligned(4)));
};

static u32 s6_append_str(char *dst, u32 pos, u32 cap, const char *s) {
    while (*s && pos + 1u < cap) dst[pos++] = *s++;
    return pos;
}

static void s6_build_path(char *out, u32 cap, const char *leaf) {
    char nbuf[S6_NONCE_LEN + 1u];
    for (u32 i = 0; i < S6_NONCE_LEN; ++i) nbuf[i] = m7_s6_ring_boot.nonce[i];
    nbuf[S6_NONCE_LEN] = 0;
    u32 p = 0;
    p = s6_append_str(out, p, cap, "/tmp_network/.m7-s6-");
    p = s6_append_str(out, p, cap, nbuf);
    p = s6_append_str(out, p, cap, leaf);
    out[p] = 0;
}

static int s6_path_exists(const char *path) {
    s32 fd = call(5, (u32)path, 0, 0, 0, 0, 0);
    if (fd >= 0) { call(6, (u32)fd, 0, 0, 0, 0, 0); return 1; }
    /* Only confirmed -ENOENT (-2) proves absence; fail closed on -EIO/-EMFILE/-ENFILE/etc. */
    return fd != -2;
}

static int s6_stop_or_disarm(const char *stop_path, const char *disarm_path) {
    if (s6_path_exists(stop_path) || s6_path_exists(disarm_path)) return 1;
    /* Orphaned child (parent daemon exited) must cancel and restore SD cleanly. */
    if (call(64 /* SYS_GETPPID */, 0, 0, 0, 0, 0, 0) == 1) return 1;
    /* Non-blocking check for blocked SIGINT/SIGTERM (e.g. group signal); fail closed if not -EAGAIN (-11). */
    u32 sm[2] = {(1u << 1) | (1u << 14), 0u};
    u32 zero_ts[2] = {0u, 0u};
    if (call(177 /* SYS_RT_SIGTIMEDWAIT */, (u32)sm, 0u, (u32)zero_ts, 8u, 0, 0) != -11) return 1;
    return 0;
}

static int precap_optional_stage(u32 stage) {
    return stage == 15 || stage == 26 || stage == 27 || stage == 32 || stage == 38 ||
           stage == 45 || stage == 50 || stage == 51 || stage == 52;
}

static void precap_notice_at(struct observer *o, u32 at, u32 stage, u32 a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g) {
    struct precap_state *s = o->extension;
    u32 errors = o->io_errors;
    u32 fields[12] = {m7_config.token, 92, 28, at, stage, a, b, c, d, e, f, g};
    emit_fields(o, fields);
    if (s && precap_optional_stage(stage)) {
        s->diagnostic_errors += o->io_errors - errors;
        o->io_errors = errors;
    }
}

static void precap_notice(struct observer *o, u32 stage, u32 a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g) {
    precap_notice_at(o, now() - o->started, stage, a, b, c, d, e, f, g);
}

static void precap_input_notice(struct observer *o, struct precap_state *s, u32 at) {
    precap_notice_at(o, at, 57, ++s->input_serial, at, s->input.entries[s->half].status,
                     s->input.entries[s->full].status, !s->input.failed, s->announced, s->delivered);
    s->input_at = at;
}

static void precap_transition(struct observer *o, struct precap_state *s, u32 next, u32 at) {
    u32 previous = s->state;
    if (!((previous == PRECAP_IDLE && next == PRECAP_ARMED) ||
          (previous == PRECAP_ARMED && (next == PRECAP_POST || next == PRECAP_DRAIN)) ||
          (previous == PRECAP_POST && next == PRECAP_DRAIN) ||
          (previous == PRECAP_DRAIN && next == PRECAP_RESTORE))) retain_unresolved(o, 218, 21);
    s->state = next;
    if (next == PRECAP_ARMED) s->armed_at = at;
    if (previous == PRECAP_ARMED) s->armed_end = s->half_low ? s->half_low - o->started : at;
    precap_notice_at(o, at, 55, previous, next, previous == PRECAP_ARMED ? s->armed_end : at,
                     s->announced, s->delivered, s->reason, 0);
}

static u32 precap_role(struct precap_state *, u32);
static void precap_backlog(struct observer *, struct precap_state *, int);
static void precap_dump_cells(struct observer *);

static void precap_hold_notice(struct observer *o, struct precap_state *s, u32 boundary) {
    if (s->hold_done) return;
    u32 root, pools[3], sd_list = 0, sd_rest = 0, ram_list = 0, ram_rest = 0, valid = 1;
    u32 flags[2] = {PRECAP_NONE, 0}, media = PRECAP_NONE;
    if (!read_mem(o, m7_config.bias + 0x1463800, &root, 4) || !read_mem(o, root, pools, 12)) valid = 0;
    else for (u32 i = 0; i < 3; ++i) if (pools[i]) {
        u32 header[3], list[3], rest;
        if (!read_mem(o, pools[i], header, 12)) { valid &= ~1u; continue; }
        if (header[2] != 0x1000 && header[2] != 0x4100) continue;
        if (!read_mem(o, pools[i] + 0x70c4, list, 12) || !read_mem(o, pools[i] + 0x71c8, &rest, 4) ||
            list[2] > 4096 || rest > 4096) { valid &= ~1u; continue; }
        if (header[2] == 0x1000) { valid |= 2; sd_list += list[2]; sd_rest += rest; }
        else { valid |= 4; ram_list += list[2]; ram_rest += rest; }
    }
    if (read_mem(o, s->core + 0x1cc, flags, 8)) valid |= 8 | ((flags[1] & 255) ? 32u : 0u);
    if (read_mem(o, s->descriptor + 0x30, &media, 4)) valid |= 16;
    s->roll_at = now();
    precap_notice(o, 38, sd_list, sd_rest, ram_list, ram_rest, flags[0], media, valid);
    if (boundary == 2) s->hold_done = 1;
}

static void precap_hold_tick(struct observer *o, struct precap_state *s) {
    if ((s->state >= PRECAP_ARMED && s->state <= PRECAP_DRAIN) && !s->hold_done &&
        now() - s->roll_at >= PRECAP_HEARTBEAT_MS)
        precap_hold_notice(o, s, 1);
}

static int precap_keys(struct precap_state *s) {
    u32 half = 0, full = 0;
    for (u32 i = 0; i < s->input.count; ++i) {
        struct sd_input_entry *e = &s->input.entries[i];
        if (e->config_key != 0x1f1 && e->config_key != 0xa7) continue;
        if (!e->valid || e->key != e->config_key || e->config_index != i ||
            e->local_code || e->remap || e->status > 1) return 0;
        if (e->key == 0x1f1) { if (e->config_flags != 0x40) return 0; s->half = i; ++half; }
        else { if (e->config_flags != 0xc0) return 0; s->full = i; ++full; }
    }
    return half == 1 && full == 1;
}

static int s6_read_live_shutter(struct observer *o, struct precap_state *s, u32 *out_half, u32 *out_full) {
    struct sd_input_shape shape = {0};
    if (!s->input.initialized || !sd_input_read_shape(o, &shape) || !sd_input_same_shape(&s->input, &shape))
        return 0;
    const u32 idxs[2] = {s->half, s->full};
    const u32 keys[2] = {0x1f1u, 0xa7u};
    const u32 flags[2] = {0x40u, 0xc0u};
    u32 vals[2] = {0u, 0u};
    for (u32 k = 0; k < 2u; ++k) {
        u32 idx = idxs[k];
        if (idx >= s->input.count) return 0;
        u32 cfg[12], a[5], b[5];
        if (!read_mem(o, s->input.config + idx * 0x30u, cfg, sizeof(cfg))) return 0;
        if (cfg[2] != keys[k] || cfg[3] != 0u || cfg[7] != 0u || cfg[8] != flags[k]) return 0;
        if (!read_mem(o, s->input.state + idx * 0x28u, a, sizeof(a)) ||
            !read_mem(o, s->input.state + idx * 0x28u, b, sizeof(b))) return 0;
        if (a[0] != b[0] || a[1] != b[1] || a[2] != b[2] || a[4] != b[4]) return 0;
        if (a[0] != keys[k] || a[4] != idx || a[2] > 1u) return 0;
        vals[k] = a[2];
    }
    if (!sd_input_read_shape(o, &shape) || !sd_input_same_shape(&s->input, &shape)) return 0;
    *out_half = vals[0];
    *out_full = vals[1];
    return 1;
}

static int s6_now_ms_checked(u32 *out) {
    u32 ts[2];
    if (call(263, 1, (u32)ts, 0, 0, 0, 0) != 0) return 0;
    *out = ts[0] * 1000u + ts[1] / 1000000u;
    return 1;
}

/* Bounded ptrace retry helper: retries ONLY -ESRCH (-3), requesting at most
 * max_retries one-millisecond sleeps (max_retries + 1 total ptrace calls).
 * Never retries PTRACE_ATTACH (16). Callers that require pre-dispatch gate
 * re-verification across retry sleeps (Insert4100 and pre-S1 resume) call
 * s6_ptrace_retry_n(..., 0u) inside an explicitly gated loop. Permanent or
 * non-ESRCH errors propagate exact signed errno so post-continue callers fail
 * closed via retain_unresolved without detaching an unknown mid-call state. */
static __attribute__((noinline)) s32 s6_ptrace_retry_n(struct observer *o, u32 request, u32 addr,
                                                       u32 data, u32 max_retries) {
    s32 rc = call(26, request, o->trace_tid, addr, data, 0, 0);
    if (request == 16u) return rc;
    for (u32 attempt = 0u; rc == -3 && attempt < max_retries; ++attempt) {
        sleep_ms(1);
        rc = call(26, request, o->trace_tid, addr, data, 0, 0);
    }
    return rc;
}

static __attribute__((noinline)) s32 s6_ptrace_retry(struct observer *o, u32 request, u32 addr, u32 data) {
    return s6_ptrace_retry_n(o, request, addr, data, 32u);
}

static __attribute__((noinline)) int s6_trace_restore(struct observer *o, struct trace_context *t) {
    if (!t->attached) return 1;
    if (t->dirty) {
        snapshot_sleep(o, t, 2);
        u32 core[18], vfp[65] __attribute__((aligned(8)));
        s32 prc = s6_ptrace_retry(o, 28u, 0u, (u32)t->vfp);
        if (prc != 0) retain_unresolved(o, 257u, (u32)prc);
        prc = s6_ptrace_retry(o, 13u, 0u, (u32)t->original);
        if (prc != 0) retain_unresolved(o, 258u, (u32)prc);
        prc = s6_ptrace_retry(o, 12u, 0u, (u32)core);
        if (prc != 0) retain_unresolved(o, 259u, (u32)prc);
        prc = s6_ptrace_retry(o, 27u, 0u, (u32)vfp);
        if (prc != 0) retain_unresolved(o, 260u, (u32)prc);
        for (u32 i = 0; i < 18u; ++i)
            if (core[i] != t->original[i]) retain_unresolved(o, 20u, i + 2u);
        for (u32 i = 0; i < 65u; ++i)
            if (vfp[i] != t->vfp[i]) retain_unresolved(o, 21u, i);
        retain_notice(o, 3, 18, 65);
    }
    s32 drc = s6_ptrace_retry(o, 17u, 0u, 0u);
    if (drc != 0) retain_unresolved(o, 261u, (u32)drc);
    t->attached = 0;
    retain_notice(o, 4, 1, 0);
    return 1;
}

static __attribute__((noinline)) int s6_trace_begin(struct observer *o, struct trace_context *t) {
    s32 rc = trace_request(o, 16u, 0u);
    if (rc != 0) { retain_notice(o, 91, (u32)rc, 0); return 0; }
    t->attached = 1;
    u32 status = wait_trace_stop(o, 1);
    if (status != 0x137fu) retain_unresolved(o, 2, status);
    s32 grc = s6_ptrace_retry(o, 12u, 0u, (u32)t->original);
    s32 vrc = (grc == 0) ? s6_ptrace_retry(o, 27u, 0u, (u32)t->vfp) : grc;
    if (grc != 0 || vrc != 0) {
        retain_notice(o, 92, 1, (u32)(grc ? grc : vrc));
        s6_trace_restore(o, t);
        return 0;
    }
    u32 sp = t->original[13], cpsr = t->original[16];
    u32 data[8] = {2, t->original[15], sp, cpsr, t->original[7], t->original[17], o->trace_tid};
    emit(o, 13, data);
    for (u32 offset = 0; offset < 18u; offset += 6u) {
        u32 core[8] = {offset, 6};
        for (u32 i = 0; i < 6u; ++i) core[2 + i] = t->original[offset + i];
        emit(o, 15, core);
    }
    if ((sp & 7u) || sp < 0x14000u || !private_range(o, sp - 0x4000u, 0x4000u) ||
        (cpsr & 0x1fu) != 0x10u || (cpsr & 0x01000200u)) {
        retain_notice(o, 92, 2, 0);
        s6_trace_restore(o, t);
        return 0;
    }
    snapshot_sleep(o, t, 1);
    return 1;
}

static __attribute__((noinline)) int s6_sony_call4(struct observer *o, struct trace_context *t, u32 operation,
                                                   u32 a0, u32 a1, u32 a2, u32 a3, u32 *result) {
    const u32 functions[] = {0, 0x108b20, 0xdd1dd9, 0xdd1595, 0x10fac4, 0x108b20, 0x10fac4, 0x10d8dc,
                            0x19e95c, 0x19e828, 0x19e664, 0x19dd5c, 0x19f614,
                            0x7c54d5, 0x19ec4c, 0xd4125d, 0xd411a1, 0xd410c5, 0x139b5,
                            0xa1a0e1, 0xa1e92d, 0x2f5d9, 0x30e99, 0x30ec5, 0x9a49, 0xa18da5,
                            0xd447a1, 0xd447d5, 0xa00a99, 0x21f09, 0x21e15, 0x25975, 0x2595d, 0x21fdd, 0xa1c4e1, 0xa34be9, 0x9fdf63};
    if (!operation || operation >= sizeof(functions) / sizeof(functions[0])) return 0;
    if (operation == 36u && (!M7_RAM_CONTINUOUS || m7_config.retain_check != 11u || o->caller_kind != 0u || o->phase != 26u)) return 0;
    if (m7_config.retain_check == 14u && (o->caller_kind != 1u ||
        !(operation == 24u || (operation >= 29u && operation <= 35u)))) return 0;
    if (operation == 35u && ((m7_config.retain_check != 11u && m7_config.retain_check != 14u) || o->caller_kind != 1u)) return 0;
    if ((m7_config.retain_check == 10u || m7_config.retain_check == 12u) && (o->caller_kind != 1u ||
        !(operation == 5u || operation == 6u || operation == 16u || operation == 17u ||
          (operation >= 19u && operation <= 24u) || operation >= 26u))) return 0;
    if (m7_config.retain_check == 11u && !(
        (o->caller_kind == 0u && (operation <= 7u || operation == 25u || operation == 36u ||
            (M7_RAM_COMMIT && operation >= 8u && operation <= 14u))) ||
        (o->caller_kind == 1u && (operation == 5u || operation == 6u || operation == 16u || operation == 17u ||
            (operation >= 19u && operation <= 24u) || operation >= 26u)))) return 0;
    int copying = operation == 7u, fsys = operation >= 8u && operation <= 14u, media = operation >= 15u && operation <= 24u;
    if (fsys && (m7_config.retain_check < 3u || !m7_config.mpr_bias)) return 0;
    if (media && m7_config.retain_check != 5u && m7_config.retain_check != 7u && m7_config.retain_check < 10u) return 0;
    if (operation >= 19u && operation <= 24u && m7_config.retain_check != 7u && m7_config.retain_check < 10u) return 0;
    if (operation == 25u && m7_config.retain_check != 8u && m7_config.retain_check != 11u) return 0;
    if (operation >= 26u && operation <= 35u && (m7_config.retain_check < 10u || o->caller_kind != 1u)) return 0;
    if (operation >= 29u && operation <= 34u &&
        ((m7_config.retain_check != 11u && m7_config.retain_check != 12u && m7_config.retain_check != 14u) || o->caller_kind != 1u)) return 0;
    if (operation == 24u && !o->owner_pthread_bias) return 0;
    u32 call_sp = t->original[13] - (copying || fsys || media || m7_config.retain_check == 7u ||
        (m7_config.retain_check >= 10u && o->caller_kind == 1u) || operation == 25u || operation == 36u ? 4096u : 0u);
    if (copying && (a0 != call_sp || !a2 || a2 > 4096u)) return 0;
    u32 target = (operation == 24u ? o->owner_pthread_bias :
                  (operation >= 21u && operation <= 23u) || (operation >= 29u && operation <= 33u) ? m7_config.mwf_bias :
                  operation == 18u ? m7_config.mprctrl_bias :
                  fsys ? m7_config.mpr_bias : m7_config.bias) + functions[operation];
    u32 trap = m7_config.bias + 0x55abcu;
    u32 data[8] = {operation, target, a0, a1, a2, a3};
    if (!copying && !fsys) emit(o, 10, data);
    for (u32 i = 0; i < 18u; ++i) t->work[i] = t->original[i];
    t->work[0] = a0; t->work[1] = a1; t->work[2] = a2; t->work[3] = a3;
    t->work[13] = call_sp;
    t->work[14] = trap | 1u;
    t->work[15] = target & ~1u;
    t->work[16] = (t->work[16] & ~0x0700ffe0u) | (target & 1u ? 0x20u : 0u);
    t->work[17] = 0xffffffffu;
    t->dirty = 1;
    s32 prc = s6_ptrace_retry(o, 13u, 0u, (u32)t->work);
    if (prc != 0) goto not_started;
    u32 verify[18];
    prc = s6_ptrace_retry(o, 12u, 0u, (u32)verify);
    if (prc != 0) goto not_started;
    for (u32 i = 0; i < 18u; ++i)
        if (verify[i] != t->work[i]) { prc = 0; goto not_started; }
    u32 started = now();
    precap_save_sample(o);
    prc = s6_ptrace_retry(o, 7u, 0u, 0u);
    if (prc != 0) goto not_started;
    u32 status = wait_trace_stop(o, 10u + operation);
    precap_save_sample(o);
    if (status != 0x057fu) retain_unresolved(o, 7u, status);
    {
        s32 grc = s6_ptrace_retry(o, 12u, 0u, (u32)t->work);
        if (grc != 0) retain_unresolved(o, 220u + operation, (u32)grc);
    }
    if ((t->work[15] != trap && t->work[15] != trap + 2u) || !(t->work[16] & 0x20u) ||
        t->work[13] != call_sp) retain_unresolved(o, 8u, t->work[15]);
    for (u32 i = 4u; i <= 11u; ++i)
        if (t->work[i] != t->original[i]) retain_unresolved(o, 9u, i);
    data[1] = t->work[0]; data[2] = t->work[15]; data[3] = t->work[16];
    data[4] = now() - started; data[5] = t->work[13];
    if (!copying && !fsys) emit(o, 11, data);
    if (fsys && (operation == 9u || operation == 11u)) precap_file_timing(o, operation, now() - started, t->work[0]);
    *result = t->work[0];
    return 1;
not_started:
    retain_notice(o, 94, operation, (u32)prc);
    return 0;
}

static int s6_sony_call(struct observer *o, struct trace_context *t, u32 operation,
                        u32 a0, u32 a1, u32 a2, u32 *result) {
    return s6_sony_call4(o, t, operation, a0, a1, a2, 0u, result);
}

static __attribute__((noinline)) int s6_commit_scratch(struct observer *o, struct trace_context *t, u32 offset,
                                                       const unsigned char *bytes, u32 size) {
    unsigned char verify[256] __attribute__((aligned(4)));
    if (!size || size > sizeof(verify) || (offset & 3u) || (size & 3u) || offset + size > 512u) return 0;
    u32 scratch = t->original[13] - 4096u + offset;
    for (u32 i = 0; i < size; i += 4u) {
        u32 word = 0;
        for (u32 j = 0; j < 4u; ++j) word |= (u32)bytes[i + j] << (8u * j);
        if (s6_ptrace_retry(o, 5u, scratch + i, word) != 0) return 0;
    }
    if (!read_mem(o, scratch, (u32 *)verify, size)) return 0;
    for (u32 i = 0; i < size; ++i) if (verify[i] != bytes[i]) return 0;
    return 1;
}

static __attribute__((noinline)) int s6_create_cancel_state(struct observer *o, struct trace_context *t,
                                                            struct create_owner *c, u32 stage) {
    u32 old[2] = {0x4d374d50u, 0x4d374d50u}, tls[3], result;
    u32 requested = stage ? (c->tls_state[2] & 1u) : 1u;
    u32 expected_old = stage ? 1u : (c->tls_state[2] & 1u);
    if (!s6_commit_scratch(o, t, 192u, (unsigned char *)old, sizeof(old)) ||
        !s6_sony_call(o, t, 24u, requested, t->original[13] - 4096u + 192u, 0u, &result)) return 0;
    if (result) return 0;
    if (!stage) c->cancel_owned = 1;
    if (!create_block(o, stage ? 46u : 41u, t->original[13] - 4096u + 192u, old, 2) ||
        old[0] != expected_old || old[1] != 0x4d374d50u) retain_unresolved(o, 80u, stage);
    if (!create_block(o, stage ? 45u : 43u, c->tls, tls, 3) ||
        tls[0] != c->tls_state[0] || tls[1] != c->tls_state[1] ||
        tls[2] != (stage ? c->tls_state[2] : (c->tls_state[2] | 1u))) retain_unresolved(o, 81u, stage);
    u32 data[8] = {stage, requested, old[0], c->tls, stage ? (c->tls_state[2] | 1u) : c->tls_state[2], tls[2]};
    emit(o, 37, data);
    if (stage) c->cancel_owned = 0;
    return 1;
}

static __attribute__((noinline)) void s6_create_restore_cancel(struct observer *o, struct trace_context *t,
                                                               struct create_owner *c) {
    u32 tls[3], frame[34];
    if (!create_block(o, 42u, t->original[13], frame, 34)) retain_unresolved(o, 82u, 0);
    for (u32 i = 0; i < 34u; ++i) if (frame[i] != c->frame[i]) retain_unresolved(o, 82u, i + 1u);
    if (!create_block(o, 44u, c->tls, tls, 3) || tls[0] != c->tls_state[0] ||
        tls[1] != c->tls_state[1] || tls[2] != (c->tls_state[2] | 1u)) retain_unresolved(o, 83u, 0);
    if (!s6_create_cancel_state(o, t, c, 1u)) retain_unresolved(o, 84u, 0);
}

static __attribute__((noinline)) void s6_connect_release(struct observer *o, struct connect_owner *c) {
    connect_caller(o, c, 1);
    if (c->recorder.cancel_owned) s6_create_restore_cancel(o, &c->rec_trace, &c->recorder);
    if (c->rec_trace.dirty) {
        u32 frame[34], tls[3];
        if (!create_block(o, 8u, c->rec_trace.original[13], frame, 34) ||
            !create_block(o, 40u, c->recorder.tls, tls, 3)) retain_unresolved(o, 100u, 1);
        for (u32 i = 0; i < 34u; ++i) if (frame[i] != c->recorder.frame[i]) retain_unresolved(o, 100u, i + 2u);
        for (u32 i = 0; i < 3u; ++i) if (tls[i] != c->recorder.tls_state[i]) retain_unresolved(o, 101u, i);
    }
    s6_trace_restore(o, &c->rec_trace);
    connect_caller(o, c, 2);
    s6_trace_restore(o, &c->remote_trace);
    connect_caller(o, c, 1);
}

static __attribute__((noinline)) int s6_connect_pair(struct observer *o, struct connect_owner *c, u32 barrier) {
    for (u32 attempt = 1u; attempt <= CONNECT_ATTEMPTS; ++attempt) {
        c->attempt = attempt; c->total_attempts++;
        c->rec_trace = (struct trace_context){0}; c->remote_trace = (struct trace_context){0};
        connect_notice(o, 10, barrier, attempt, 0, 0, 0, 0, 0);
        connect_caller(o, c, 1);
        int rec = s6_trace_begin(o, &c->rec_trace) && create_idle(o, &c->rec_trace, &c->recorder), remote = 0;
        if (rec) {
            connect_caller(o, c, 2);
            remote = s6_trace_begin(o, &c->remote_trace) && create_idle_for(o, &c->remote_trace, &c->remote,
                m7_config.bias + 0x1388968, "ObjCntMgr", 0x30);
        }
        if (rec && remote && connect_queues(o, c, barrier, 1) && connect_queues(o, c, barrier, 2) &&
            (!barrier || connect_state(o, c, barrier))) {
            u32 accessor;
            if (barrier && (!read_mem(o, c->recorder.resource + 8, &accessor, 4) || !accessor))
                retain_unresolved(o, 114u, barrier);
            connect_caller(o, c, 1);
            return 1;
        }
        s6_connect_release(o, c);
        if (attempt < CONNECT_ATTEMPTS) sleep_ms(250);
    }
    connect_notice(o, 90, 1, barrier, CONNECT_ATTEMPTS, 0, 0, 0, 0);
    return 0;
}

static __attribute__((noinline)) void s6_mode_set(struct observer *o, struct connect_owner *c,
                                                  u32 stage, const u32 *values) {
    struct trace_context *t = &c->rec_trace;
    const u32 keys[4] = {0x1007u, 0x1008u, 0x1009u, 0x101au};
    u32 scratch = t->original[13] - 4096u, msg = scratch + 256u, param = scratch + 264u, result, zero[4] = {0};
    if (!s6_create_cancel_state(o, t, &c->recorder, 0u) ||
        !s6_commit_scratch(o, t, 256u, (unsigned char *)zero, sizeof(zero)) ||
        !s6_sony_call(o, t, 29u, msg, 0x3500u, 0x2003u, &result)) retain_unresolved(o, 170u, stage);
    for (u32 i = 0; i < 4u; ++i) {
        if (!s6_sony_call(o, t, 31u, param, values[i], 0u, &result) ||
            !s6_sony_call(o, t, 33u, msg, keys[i], param, &result) ||
            !s6_sony_call(o, t, 32u, param, 0u, 0u, &result)) retain_unresolved(o, 171u, stage * 10u + i);
    }
    if (!s6_sony_call(o, t, 34u, c->recorder.manager, msg, 0u, &result)) retain_unresolved(o, 172u, stage);
    mode_notice(o, stage, c->recorder.manager, msg, result, values[0], values[1], values[2], values[3]);
    if (!s6_sony_call(o, t, 30u, msg, 0u, 0u, &result)) retain_unresolved(o, 173u, stage);
    c->mode_applied = 1;
    s6_connect_release(o, c);
}

static __attribute__((noinline)) int s6_mode_drain(struct observer *o, struct connect_owner *c,
                                                   u32 stage, int ram) {
    u32 pending_samples = 0;
    for (u32 attempt = 1u; attempt <= 8u; ++attempt) {
        if (!s6_connect_pair(o, c, 3u)) retain_unresolved(o, 174u, stage);
        u32 config[21], busy, remote[14];
        if (!mode_snapshot(o, c, stage, config, &busy, remote)) retain_unresolved(o, 175u, stage);
        int ready = mode_matches(c, config, busy, remote, ram);
        mode_notice(o, 8, stage, attempt, ready, config[6], config[10], config[13], busy);
        if (ready) { mode_notice(o, stage, 1, config[4], config[6], config[8], config[10], config[11], config[13]); return 1; }
        pending_samples = ram && mode_pending_unchanged(c, config, busy, remote) ? pending_samples + 1u : 0u;
        if (pending_samples == 2u) {
            mode_notice(o, 9, stage, attempt, config[20], busy, remote[1], remote[2], 0);
            return 0;
        }
        s6_connect_release(o, c);
        sleep_ms(250);
    }
    retain_unresolved(o, 176u, stage);
    return 0;
}

static int precap_check_still_holding(struct observer *o, struct precap_state *s) {
    if (s->hold_lost) return 0;
    if (s6_stop_or_disarm(s->stop_path, s->disarm_path)) {
        s->disarm_seen = 1u;
        s->hold_lost = 1u;
        return 0;
    }
    u32 half = 0u, full = 0u;
    if (!s6_read_live_shutter(o, s, &half, &full)) {
        s->hold_lost = 1u;
        return 0;
    }
    s->input.entries[s->half].status = half;
    s->input.entries[s->full].status = full;
    if (half != 1u || full != 0u) {
        s->hold_lost = 1u;
        return 0;
    }
    return 1;
}

static void stage6_sleep_hold(struct observer *o, struct precap_state *ps, u32 total_ms, int check_sub) {
    if (!ps) { sleep_ms(total_ms); return; }
    u32 rem = total_ms;
    while (rem > 0u) {
        u32 step = rem > 25u ? 25u : rem;
        sleep_ms(step);
        if (!precap_check_still_holding(o, ps) || (check_sub && !subscription(o, 0, 0))) {
            ps->hold_lost = 1u;
        }
        rem -= step;
    }
}

static int stage6_insert4100_call(struct observer *o, struct trace_context *t, u32 scratch,
                                  u32 *result, struct precap_state *ps) {
    u32 call_sp = t->original[13] - 4096u;
    u32 target = m7_config.bias + 0xa34be9u, trap = m7_config.bias + 0x55abcu;
    u32 data[8] = {35u, target, 2u, scratch, 0u, 0u, 0u, 0u};
    emit(o, 10, data);
    /* Re-verify hold + subscription AFTER the kind-10 pipe write so FIFO backpressure cannot bypass the gate! */
    if (ps && (!precap_check_still_holding(o, ps) || !subscription(o, 0, 0))) return 0;
    for (u32 i = 0u; i < 18u; ++i) t->work[i] = t->original[i];
    t->work[0] = 2u; t->work[1] = scratch; t->work[2] = 0u; t->work[3] = 0u;
    t->work[13] = call_sp;
    t->work[14] = trap | 1u;
    t->work[15] = target & ~1u;
    t->work[16] = (t->work[16] & ~0x0700ffe0u) | (target & 1u ? 0x20u : 0u);
    t->work[17] = 0xffffffffu;
    t->dirty = 1;
    s32 prc = s6_ptrace_retry(o, 13u, 0u, (u32)t->work);
    if (prc != 0) goto not_started;
    u32 verify[18];
    prc = s6_ptrace_retry(o, 12u, 0u, (u32)verify);
    if (prc != 0) goto not_started;
    for (u32 i = 0u; i < 18u; ++i)
        if (verify[i] != t->work[i]) { prc = 0; goto not_started; }
    u32 started = 0u;
    prc = -3;
    for (u32 attempt = 0u; attempt <= 32u; ++attempt) {
        if (ps && (!precap_check_still_holding(o, ps) || !subscription(o, 0, 0))) {
            s32 rrc = s6_ptrace_retry(o, 13u, 0u, (u32)t->original);
            if (rrc != 0) retain_unresolved(o, 258u, (u32)rrc);
            return 0;
        }
        started = now();
        /* Sony's Insert4100 itself transiently dips sub_en=0; clear right before PTRACE_CONT with zero pipe writes between! */
        if (ps) ps->prearm_check_sub = 0u;
        prc = s6_ptrace_retry_n(o, 7u, 0u, 0u, 0u);
        if (prc == 0) break;
        if (ps) ps->prearm_check_sub = 1u;
        if (prc != -3 || attempt == 32u) {
            s32 rrc = s6_ptrace_retry(o, 13u, 0u, (u32)t->original);
            if (rrc != 0) retain_unresolved(o, 258u, (u32)rrc);
            goto not_started;
        }
        sleep_ms(1);
    }
    u32 status = wait_trace_stop(o, 10u + 35u);
    precap_save_sample(o);
    if (status != 0x057fu) retain_unresolved(o, 7u, status);
    {
        s32 grc = s6_ptrace_retry(o, 12u, 0u, (u32)t->work);
        if (grc != 0) retain_unresolved(o, 220u + 35u, (u32)grc);
    }
    if ((t->work[15] != trap && t->work[15] != trap + 2u) || !(t->work[16] & 0x20u) ||
        t->work[13] != call_sp) retain_unresolved(o, 8, t->work[15]);
    for (u32 i = 4u; i <= 11u; ++i)
        if (t->work[i] != t->original[i]) retain_unresolved(o, 9, i);
    data[1] = t->work[0]; data[2] = t->work[15]; data[3] = t->work[16];
    data[4] = now() - started; data[5] = t->work[13];
    emit(o, 11, data);
    *result = t->work[0];
    return 1;
not_started:
    retain_notice(o, 94, 35u, (u32)prc);
    return 0;
}

static int stage6_start_command(struct observer *o, struct start_owner *c, u32 command, u32 *returned,
                                struct precap_state *ps) {
    struct trace_context t = {0};
    int admitted = 0;
    for (u32 attempt = 1u; attempt <= 8u; ++attempt) {
        if (ps && (!precap_check_still_holding(o, ps) || !subscription(o, 0, 0))) return 0;
        start_notice(o, 2, command, attempt, 0, 0, 0, 0, 0);
        if (s6_trace_begin(o, &t) && create_idle(o, &t, &c->caller)) { admitted = 1; break; }
        s6_trace_restore(o, &t); t = (struct trace_context){0};
        if (attempt < 8u) {
            stage6_sleep_hold(o, ps, 100u, 1);
            if (ps && ps->hold_lost) return 0;
        }
    }
    if (!admitted) return 0;
    if (ps && (!precap_check_still_holding(o, ps) || !subscription(o, 0, 0))) {
        s6_trace_restore(o, &t);
        return 0;
    }
    o->owner_pthread_bias = c->caller.pthread_bias;
    u32 scratch = t.original[13] - 4096u + 256u;
    u32 argv[8] = {scratch + 12u, scratch + 20u, 0u, 0x6f6d6572u, 0x00006574u,
                   command == 1u ? 0x72617473u : 0x706f7473u, command == 1u ? 0x74u : 0u, 0u};
    int ok = s6_commit_scratch(o, &t, 256u, (unsigned char *)argv, sizeof(argv)) &&
        create_block(o, 60, scratch, argv, 8) && s6_create_cancel_state(o, &t, &c->caller, 0u);
    if (ok && ps && command == 1u && (!precap_check_still_holding(o, ps) || !subscription(o, 0, 0))) {
        /* Hold, disarm, or subscription lost during pthread_setcancelstate prep -> restore cancel state, skip Insert4100! */
        ok = 0;
    }
    if (ok) {
        ok = (command == 1u)
            ? stage6_insert4100_call(o, &t, scratch, returned, ps)
            : s6_sony_call4(o, &t, 35u, 2u, scratch, 0u, 0u, returned);
    }
    if (c->caller.cancel_owned) s6_create_restore_cancel(o, &t, &c->caller);
    u32 frame[34], tls[3];
    if (t.dirty) {
        if (!create_block(o, 8, t.original[13], frame, 34) || !create_block(o, 40, c->caller.tls, tls, 3))
            retain_unresolved(o, 181, command);
        for (u32 i = 0; i < 34u; ++i) if (frame[i] != c->caller.frame[i]) retain_unresolved(o, 181, i);
        for (u32 i = 0; i < 3u; ++i) if (tls[i] != c->caller.tls_state[i]) retain_unresolved(o, 182, i);
    }
    s6_trace_restore(o, &t);
    start_notice(o, 4, command, ok, *returned, 0, 0, 0, 0);
    return ok;
}

static int stage6_connect_pair(struct observer *o, struct connect_owner *c, u32 barrier,
                               struct precap_state *ps, int abort_on_loss) {
    for (u32 attempt = 1u; attempt <= CONNECT_ATTEMPTS; ++attempt) {
        if (ps && (!precap_check_still_holding(o, ps) || !subscription(o, 0, 0))) {
            ps->hold_lost = 1u;
            if (abort_on_loss) return 0;
        }
        c->attempt = attempt; c->total_attempts++;
        c->rec_trace = (struct trace_context){0}; c->remote_trace = (struct trace_context){0};
        connect_notice(o, 10, barrier, attempt, 0, 0, 0, 0, 0);
        connect_caller(o, c, 1);
        int rec = s6_trace_begin(o, &c->rec_trace) && create_idle(o, &c->rec_trace, &c->recorder), remote = 0;
        if (rec) {
            connect_caller(o, c, 2);
            remote = s6_trace_begin(o, &c->remote_trace) && create_idle_for(o, &c->remote_trace, &c->remote,
                m7_config.bias + 0x1388968, "ObjCntMgr", 0x30);
        }
        if (rec && remote && connect_queues(o, c, barrier, 1) && connect_queues(o, c, barrier, 2) &&
            (!barrier || connect_state(o, c, barrier))) {
            u32 accessor;
            if (barrier && (!read_mem(o, c->recorder.resource + 8, &accessor, 4) || !accessor))
                retain_unresolved(o, 114, barrier);
            connect_caller(o, c, 1);
            return 1;
        }
        s6_connect_release(o, c);
        if (attempt < CONNECT_ATTEMPTS) {
            stage6_sleep_hold(o, ps, 250u, 1);
            if (ps && (ps->hold_lost || !subscription(o, 0, 0))) {
                ps->hold_lost = 1u;
                if (abort_on_loss) return 0;
            }
        }
    }
    connect_notice(o, 90, 1, barrier, CONNECT_ATTEMPTS, 0, 0, 0, 0);
    return 0;
}

static int stage6_mode_drain_ram(struct observer *o, struct connect_owner *c, u32 stage, struct precap_state *ps) {
    u32 pending_samples = 0u;
    for (u32 attempt = 1u; attempt <= 8u; ++attempt) {
        if (!stage6_connect_pair(o, c, 3, ps, 0)) retain_unresolved(o, 174, stage);
        if (ps && (!precap_check_still_holding(o, ps) || !subscription(o, 0, 0))) ps->hold_lost = 1u;
        u32 config[21], busy, remote[14];
        if (!mode_snapshot(o, c, stage, config, &busy, remote)) retain_unresolved(o, 175, stage);
        int ready = mode_matches(c, config, busy, remote, 1);
        mode_notice(o, 8, stage, attempt, ready, config[6], config[10], config[13], busy);
        if (ready) {
            mode_notice(o, stage, 1, config[4], config[6], config[8], config[10], config[11], config[13]);
            return 1;
        }
        pending_samples = mode_pending_unchanged(c, config, busy, remote) ? pending_samples + 1u : 0u;
        if (pending_samples == 2u) {
            mode_notice(o, 9, stage, attempt, config[20], busy, remote[1], remote[2], 0);
            return 0;
        }
        s6_connect_release(o, c);
        stage6_sleep_hold(o, ps, 250u, 1);
    }
    retain_unresolved(o, 176, stage);
    return 0;
}

static int stage6_start_wait(struct observer *o, struct start_owner *c, u32 active, u32 base, struct precap_state *ps) {
    struct start_state s = {0}, previous = {0};
    u32 streak = 0u;
    for (u32 i = 0u; i < START_POLLS; ++i) {
        if (ps && (!precap_check_still_holding(o, ps) || (!active && !subscription(o, 0, 0))) && !active) {
            ps->hold_lost = 1u;
            return 0;
        }
        int read = start_read_state(o, c, base + i, &s);
        int ready = read && start_ready(&s, active, c->allow_connected) &&
                    start_idle_queues(o, c, base + i, 0) && start_idle_queues(o, c, base + i, 1);
        if (ready && streak) {
            int same = 1;
            for (u32 n = 0u; n < sizeof(s); ++n) {
                if (((unsigned char *)&s)[n] != ((unsigned char *)&previous)[n]) same = 0;
            }
            if (!same) streak = 0u;
        }
        streak = ready ? streak + 1u : 0u;
        if (ready) previous = s;
        start_notice(o, 3, active, i, read, s.state[1], s.remote[2], streak, 0);
        if (streak == 2u) return 1;
        if (i + 1u < START_POLLS) {
            stage6_sleep_hold(o, ps, 200u, active ? 0 : 1);
            if (ps && ps->hold_lost && !active) return 0;
        }
    }
    return 0;
}

static u32 s6_post_q_limit(void) {
    return m7_precap_config.backlog_cap > 12u ? (m7_precap_config.backlog_cap - 12u) : m7_precap_config.backlog_cap;
}

static int s6_post_satisfied(const struct precap_state *s) {
    u32 expected = s->pre_frozen + s->post;
    if (m7_precap_config.after > 0u) return s->post >= m7_precap_config.after;
    return expected > 0u;
}

static int s6_post_done(struct observer *o, struct precap_state *s, u32 cur_now) {
    if (!s->trigger_ms) return 0;
    if (s->post_limit_hit) return 1;
    u32 q_lim = s6_post_q_limit();
    if (m7_precap_config.after > 0u) {
        if (s->post >= m7_precap_config.after) return 1;
        if (s->queue >= q_lim) {
            s->post_limit_hit = 1u;
            if (!s->post_cutoff_cause) s->post_cutoff_cause = 2u;
            return 1;
        }
        return 0;
    }
    if (s->post >= m7_precap_config.post_max) {
        s->post_limit_hit = 1u;
        if (!s->post_cutoff_cause) s->post_cutoff_cause = 1u;
        return 1;
    }
    if (s->queue >= q_lim) {
        s->post_limit_hit = 1u;
        if (!s->post_cutoff_cause) s->post_cutoff_cause = 2u;
        return 1;
    }
    if (s->full_low && (u32)(cur_now - s->full_low) >= 40u) {
        if (s->post >= 1u || (u32)(cur_now - o->started - s->trigger_ms) >= 150u) return 1;
    }
    return 0;
}

/* Strict child-reaping S2 poller: NEVER marks done without confirmed wait4 reap.
 * Any reaped failed child (S2-down or S2-up) takes the same unified recovery path
 * (reason=5 -> PRECAP_DRAIN -> compensating synchronous sender(o, 2, 0)).
 * Any child that cannot be killed & reaped after timeout fails closed (218/11). */
static void s6_s2_poll_once(struct observer *o, struct precap_state *s, int allow_unresolved) {
    if (!s->s2_cmd_active && (s->start.pid <= 0 || s->start.reaped)) return;
    if (s->start.pid <= 0) {
        s->s2_cmd_active = 0u;
        if (allow_unresolved) retain_unresolved(o, 218, 11);
        return;
    }
    u32 cur_now = now();
    u32 elapsed = cur_now - s->start.started;
    s32 rc = call(114, (u32)s->start.pid, (u32)&s->start.status, 1u /* WNOHANG */, 0, 0, 0);
    if (rc == s->start.pid) {
        s->start.reaped = 1u;
        s->start.done = 1u;
        s->s2_cmd_active = 0u;
        u32 data[8] = {2u, s->s2_cmd_val, (u32)s->start.pid, s->start.status,
                       s->start.killed, 1u, elapsed, 0u};
        emit(o, 5, data);
        if (!s->start.killed && s->start.status == 0u) {
            if (s->s2_cmd_val == 1u) {
                s->s2_down = 1u;
                s->s2_up = 0u;
            } else {
                s->s2_down = 0u;
                s->s2_up = 1u;
                precap_notice(o, 35, s->pulses, now() - s->pace_at, s->queue, s->phase_burst, 0, 0, 0);
            }
        } else {
            /* Confirmed reaped nonzero/killed child: button state unknown, recover via precap_stop(). */
            s->s2_down = 0u;
            s->s2_up = 0u;
            s->s2_child_failed = 1u;
            if (!s->reason) s->reason = 5u;
        }
        return;
    }
    if (rc == 0 || rc == -4) {
        if (elapsed >= 1500u) {
            s32 krc = 0;
            if (!s->start.killed) {
                krc = call(37 /* SYS_KILL */, (u32)s->start.pid, 9u, 0, 0, 0, 0);
                s->start.killed = 1u;
                s->start.killed_at = cur_now;
            } else if ((u32)(cur_now - s->start.killed_at) >= 300u) {
                krc = call(37 /* SYS_KILL */, (u32)s->start.pid, 9u, 0, 0, 0, 0);
                rc = call(114, (u32)s->start.pid, (u32)&s->start.status, 1u, 0, 0, 0);
                if (rc == s->start.pid) {
                    s->start.reaped = 1u;
                    s->start.done = 1u;
                    s->s2_cmd_active = 0u;
                    u32 data[8] = {2u, s->s2_cmd_val, (u32)s->start.pid, s->start.status,
                                   s->start.killed, 1u, elapsed, (u32)krc};
                    emit(o, 5, data);
                    s->s2_down = 0u;
                    s->s2_up = 0u;
                    s->s2_child_failed = 1u;
                    if (!s->reason) s->reason = 5u;
                    return;
                }
                u32 data[8] = {2u, s->s2_cmd_val, (u32)s->start.pid, s->start.status,
                               s->start.killed, 0u, elapsed, (u32)krc};
                emit(o, 5, data);
                if (allow_unresolved) retain_unresolved(o, 218, 11);
            }
        }
        return;
    }
    u32 data[8] = {2u, s->s2_cmd_val, (u32)s->start.pid, (u32)rc, s->start.killed, 0u, elapsed, 0u};
    emit(o, 5, data);
    if (allow_unresolved) retain_unresolved(o, 218, 11);
}

static void s6_s2_poll(struct observer *o, struct precap_state *s) {
    s6_s2_poll_once(o, s, 1);
}

static void precap_stop(struct observer *o, struct precap_state *s, int aborting) {
    u32 stop_wait_start = now();
    while (s->s2_cmd_active || (s->start.pid > 0 && !s->start.reaped)) {
        u32 prev_killed = s->start.killed;
        s6_s2_poll_once(o, s, !aborting);
        if (!s->s2_cmd_active && (s->start.pid <= 0 || s->start.reaped)) break;
        if (aborting &&
            ((s->start.killed && (u32)(now() - s->start.killed_at) >= 300u) ||
             (!prev_killed && !s->start.killed && (u32)(now() - s->start.started) < 1500u &&
              (u32)(now() - stop_wait_start) >= 50u) ||
             (u32)(now() - stop_wait_start) >= 2000u)) break;
        precap_wait(o, 5);
    }
    if (s->pulses && !sd_start_ok(&s->start)) {
        s->s2_child_failed = 1u;
        if (!s->reason) s->reason = 5u;
    }
    if (!s->s2_up) {
        if (aborting) ++s->abort_up; else ++s->planned_up;
        s->s2_up = sender(o, 2, 0);
        if (s->s2_up) s->s2_down = 0u;
        precap_notice(o, 24, s->s2_up, s->planned_up, s->abort_up, s->reason, s->post, s->saved, now() - s->stop_at);
    }
    if (!s->s1_up) s->s1_up = sender(o, 1, 0);
    s->released = s->s2_up && s->s1_up;
}

static void precap_abort(struct observer *o) {
    struct precap_state *s = o->extension;
    if (!s) return;
    s->sampling = 1; precap_stop(o, s, 1);
    o->shutter_state = 0;
}

static void precap_request_stop(struct observer *o, struct precap_state *s) {
    u32 cur_now = now();
    if (s->state == PRECAP_DRAIN || (!s->reason && !s6_post_done(o, s, cur_now))) return;
    precap_hold_notice(o, s, 2);
    precap_transition(o, s, PRECAP_DRAIN, cur_now - o->started); s->stop_at = cur_now; s->blocked = 1;
    s->drain_changed = s->stop_at; s->drain_cap = m7_precap_config.drain_ms;
    precap_notice(o, 11, s->reason, !!s->trigger_ms, s->input.entries[s->half].status,
                  s->input.entries[s->full].status, s->queue, s->queue_peak, s->pulses);
    if (s->s2_up) { ++s->planned_up; precap_notice(o, 24, 1, s->planned_up, 0, s->reason, s->post, s->saved, 0); }
}

static u32 precap_inert_count(struct observer *o, struct precap_state *s, u32 pool, const u32 *list) {
    u32 previous = 0, node = list[0], inert = 0, again[3];
    if (list[2] > 512u) return 0;
    for (u32 n = 0; n < list[2]; ++n) {
        u32 row[12], check[12];
        if (!node || (node & 3) || !private_range(o, node, 0x1ac) ||
            !read_mem(o, node, row, 20) || row[0] != previous || !row[3] || row[3] == PRECAP_NONE ||
            !read_mem(o, node + 0x168, row + 5, 12) || !read_mem(o, node + 0x20, row + 8, 16)) return 0;
        for (u32 j = 0; j < n; ++j) if (s->pool_nodes[j] == node || s->pool_uids[j] == row[3]) return 0;
        s->pool_nodes[n] = node; s->pool_uids[n] = row[3];
        if (!read_mem(o, node, check, 20) || !read_mem(o, node + 0x168, check + 5, 12) ||
            !read_mem(o, node + 0x20, check + 8, 16)) return 0;
        for (u32 j = 0; j < 12; ++j) if (row[j] != check[j]) return 0;
        if (!(row[5] & 0x00ffffff) && (row[5] >> 24) <= 1 && !(row[6] & 255) && !row[7] &&
            !row[8] && !row[9] && !row[10] && !row[11]) ++inert;
        previous = node; node = row[1];
    }
    if (node || previous != list[1] || !read_mem(o, pool + 0x70c4, again, 12)) return 0;
    for (u32 j = 0; j < 3; ++j) if (list[j] != again[j]) return 0;
    return inert;
}

static void precap_drain_sample(struct observer *o, struct precap_state *s) {
    if (s->state != PRECAP_DRAIN || s->save_active || s->drained ||
        (s->drain_seen && now() - s->drain_sample < 100)) return;
    s->drain_sample = now();
    u32 state[6] = {0, 0, 0, 0, 0, s->delivered}, queue[2], links[3], root, pools[3], valid = 1;
    if (!read_mem(o, s->manager + 0x88, queue, 8) || queue[0] > 512 || queue[1] > 512 ||
        !read_mem(o, s->manager + 4, links, 12)) valid = 0;
    if (valid) {
        state[0] = (queue[0] + 513 - queue[1]) % 513;
        for (u32 i = 0; i < 3; ++i) {
            u32 desc[16], image[18];
            if (!read_mem(o, links[i], desc, sizeof(desc)) || !read_mem(o, desc[3], image, sizeof(image))) { valid = 0; break; }
            if (image[1] || image[3] || image[4] || (image[11] & 255)) ++state[1];
        }
    }
    if (!read_mem(o, m7_config.bias + 0x1463800, &root, 4) || !read_mem(o, root, pools, 12)) valid = 0;
    else for (u32 i = 0; i < 3; ++i) if (pools[i]) {
        u32 header[3], list[3], rest, owned = 0;
        if (!read_mem(o, pools[i], header, 12)) { valid = 0; break; }
        if (header[2] != 0x4100) continue;
        if (!read_mem(o, pools[i] + 0x70c4, list, 12) || !read_mem(o, pools[i] + 0x71c8, &rest, 4) ||
            list[2] > 4096 || rest > 4096) { valid = 0; break; }
        for (u32 j = 0; j < s->count; ++j)
            if (s->frames[j].owner.owned && s->frames[j].owner.candidate[1] == pools[i]) ++owned;
        u32 closed = owned + precap_inert_count(o, s, pools[i], list);
        state[2] += list[2] > closed ? list[2] - closed : 0; state[3] += rest; state[4] += !!(header[1] & 255);
    }
    u32 changed = !s->drain_seen || valid != s->drain_valid;
    if (valid) for (u32 i = 0; i < 6; ++i) if (state[i] != s->drain_state[i]) changed = 1;
    if (valid) {
        s->drain_open = state[0] + state[1] + state[2] + state[3];
        if (changed) {
            s->drain_changed = now();
            s->drain_cap = now() - s->stop_at + s->drain_open * PRECAP_DRAIN_FRAME_MS + m7_precap_config.drain_ms;
            for (u32 i = 0; i < 6; ++i) s->drain_state[i] = state[i];
        }
    }
    s->drain_valid = valid; s->drain_seen = 1;
    if (changed) precap_notice(o, 37, valid ? s->drain_open : PRECAP_NONE, state[0], state[1], state[2], state[3],
                               now() - s->stop_at, s->drain_cap);
}

static int precap_kept_complete(struct observer *o, struct precap_state *s) {
    u32 expected = s->pre_frozen + s->post;
    return !!s->trigger_ms && !s->reason && s6_post_satisfied(s) &&
           s->saved == expected && !s->count && !o->held_owned && s->released;
}

static void precap_sample(struct observer *o) {
    struct precap_state *s = o->extension;
    if (!s || s->sampling) return;
    s->sampling = 1;
    u32 previous = o->phase; o->phase = 28;
    u32 before = s->input.last_ms; sd_input_sample(o, &s->input);
    if (before != s->input.last_ms) {
        u32 gap = s->last_sample ? s->input.last_ms - s->last_sample : 0;
        if (gap > s->max_gap) s->max_gap = gap;
        s->last_sample = s->input.last_ms; ++s->samples;
    }
    if (s->save_active && now() - s->heartbeat >= 250) {
        s->heartbeat = now();
        precap_notice(o, 26, s->pass, now() - s->pass_at, s->pass_bytes, s->samples, s->max_gap,
                      s->input.entries[s->half].status, s->input.entries[s->full].status);
    }
    if (s->state >= PRECAP_ARMED && s->state <= PRECAP_DRAIN) {
        u32 cur_now = now();
        u32 input_at = cur_now - o->started;
        if (s->state == PRECAP_ARMED && before != s->input.last_ms) precap_input_notice(o, s, input_at);
        u32 half = s->input.entries[s->half].status, full = s->input.entries[s->full].status;
        if (!s->reason && (s->input.failed || half > 1 || full > 1)) s->reason = 1;
        /* Check per-nonce disarm/stop/signal every 150 ms and immediately before accepting a new full press. */
        if (!s->disarm_seen &&
            ((u32)(cur_now - s->disarm_checked_ms) >= 150u || (s->state == PRECAP_ARMED && full))) {
            s->disarm_checked_ms = cur_now;
            if (s6_stop_or_disarm(s->stop_path, s->disarm_path)) s->disarm_seen = 1u;
        }
        /* Pending stop/disarm/orphan/signal ALWAYS takes precedence over accepting a new full press. */
        if (!s->trigger_ms && !s->reason && s->disarm_seen) {
            s->reason = 4;
        } else if (s->state == PRECAP_POST && s->disarm_seen) {
            /* Graceful stop of post window if stop/disarm arrives mid-hold: save already-captured frames & restore SD. */
            s->post_limit_hit = 1u;
            if (!s->post_cutoff_cause) s->post_cutoff_cause = 4u;
        }
        if (s->state == PRECAP_ARMED && !s->reason && !s->disarm_seen && full) {
            /* Capture any just-announced pre-frames in REC_MGR before freezing pre_frozen! */
            precap_backlog(o, s, 1);
            if (!s->reason) {
                s->trigger_ms = input_at ? input_at : 1u;
                s->pre_frozen = s->id_count;
                s->full_low = 0u;
                precap_transition(o, s, PRECAP_POST, input_at);
                struct precap_identity *last = s->id_count ? &s->ids[s->id_count - 1] : 0;
                precap_notice_at(o, input_at, 2, s->trigger_ms, s->capacity, s->pre_frozen, last ? last->capture : 0,
                                 0, m7_precap_config.after, s->reason);
            }
        }
        if (!half) { if (!s->half_low) s->half_low = o->started + input_at; }
        else s->half_low = 0;
        if (s->state == PRECAP_POST) {
            if (!full) { if (!s->full_low) s->full_low = cur_now; }
            else s->full_low = 0u;
        }
        if (!s->trigger_ms && !s->reason &&
            ((s->half_low && cur_now - s->half_low >= 40) ||
             cur_now - s->started >= m7_precap_config.window_ms)) {
            s->reason = 4;
        }
        precap_backlog(o, s, 0);
        precap_hold_tick(o, s);
        s6_s2_poll(o, s);
        if (s->reason || s->state == PRECAP_POST) precap_hold_notice(o, s, 2);
        if (!s->reason && s->state == PRECAP_POST && !!s->trigger_ms &&
            (u32)(cur_now - o->started - s->trigger_ms) >= PRECAP_POST_MS) {
            /* Preserve any frozen pre+post frames; fixed windows lacking post will report reason=13 after saving. */
            s->post_limit_hit = 1u;
            if (!s->post_cutoff_cause) s->post_cutoff_cause = 5u;
        }
        precap_request_stop(o, s);
        if (!s->released && (s->state == PRECAP_DRAIN)) {
            precap_stop(o, s, 0);
            if (!s->s2_up) retain_unresolved(o, 218, 1);
        }
        precap_drain_sample(o, s);
        u32 now_end = now();
        /* Fail closed if a single in-flight file save stalls beyond S6_SINGLE_SAVE_TIMEOUT_MS,
         * or if an idle/stuck DRAIN stalls beyond PRECAP_DRAIN_ABSOLUTE_MS while not saving. */
        if (s->save_active && (u32)(now_end - s->save_started_at) >= S6_SINGLE_SAVE_TIMEOUT_MS)
            retain_unresolved(o, 218, 22);
        if (s->state == PRECAP_DRAIN && !s->save_active && !s->drained &&
            (u32)(now_end - s->stop_at) >= PRECAP_DRAIN_ABSOLUTE_MS)
            retain_unresolved(o, 218, 22);
        /* Distinguish a healthy, empty pool waiting strictly for physical full-press lift from a stuck pool. */
        int waiting_user_release = (s->state == PRECAP_DRAIN) && !s->save_active && !s->drained &&
            s->released && !s->count && !o->held_owned && s->drain_valid && s->drain_open == 0u &&
            !s->input.failed && full == 1u;
        if (waiting_user_release) {
            s->drain_changed = now_end;
        }
        if (!waiting_user_release && (s->state == PRECAP_DRAIN) && !s->save_active && !s->drained && !s->drain_expired &&
            (u32)(now_end - s->stop_at) >= s->drain_cap && (u32)(now_end - s->drain_changed) >= m7_precap_config.drain_ms) {
            u32 predicates = (s->drain_open ? 1u : 0u) | 4u | (s->drain_valid ? 0u : 8u);
            precap_notice(o, 23, 10, s->blocked, now_end - s->stop_at,
                          s->drain_valid ? s->drain_open : PRECAP_NONE, now_end - s->drain_changed, s->drain_cap, predicates);
            precap_dump_cells(o);
            if (!precap_kept_complete(o, s)) { s->reason = 10; retain_unresolved(o, 218, 17); }
            s->drain_expired = now_end;
        }
        if (!waiting_user_release && s->drain_expired && !s->drained &&
            (u32)(now_end - s->drain_expired) >= m7_precap_config.drain_ms) {
            retain_unresolved(o, 218, 20);
        }
    } else if (s->state == PRECAP_IDLE && !s->hold_lost) {
        u32 half = s->input.entries[s->half].status, full = s->input.entries[s->full].status;
        if (s6_stop_or_disarm(s->stop_path, s->disarm_path)) {
            s->disarm_seen = 1u;
            s->hold_lost = 1u;
        } else if (s->input.failed || half != 1u || full != 0u ||
                   (s->prearm_check_sub && !subscription(o, 0, 0))) {
            s->hold_lost = 1u;
        }
    }
    o->phase = previous; s->sampling = 0;
}

static void precap_save_sample(struct observer *o) {
    struct precap_state *s = o->extension;
    if (s) precap_sample(o);
}

static void precap_wait(struct observer *o, u32 duration) {
    u32 started = now(), elapsed;
    precap_sample(o);
    while ((elapsed = now() - started) < duration) {
        u32 remaining = duration - elapsed;
        sleep_ms(remaining > 10 ? 10 : remaining);
        precap_sample(o);
    }
}

static void precap_file_timing(struct observer *o, unsigned int operation, unsigned int elapsed, unsigned int result) {
    struct precap_state *s = o->extension;
    if (s && s->save_active) precap_notice(o, 32, s->saved + 1, operation, elapsed, result, s->samples, 0, 0);
}

static void precap_progress(struct observer *o, unsigned int pass, unsigned int bytes, int finished) {
    struct precap_state *s = o->extension;
    if (!s || !s->save_active) return;
    if (s->pass != pass) { s->pass = pass; s->pass_at = now(); s->heartbeat = now(); }
    s->pass_bytes = bytes; precap_sample(o);
    if (finished) precap_notice(o, 27, pass, now() - s->pass_at, bytes, s->samples, s->max_gap, 0, 0);
}

static int precap_blocked(struct observer *o, u32 code, u32 a, u32 b, u32 c) {
    struct precap_state *s = o->extension;
    if (s && (s->blocked != code || now() - s->heartbeat >= 1000)) {
        s->blocked = code; s->heartbeat = now();
        precap_notice(o, 25, code, a, b, c, s->post, s->count, o->held_owned);
    }
    return 0;
}

static int precap_keep_source(struct observer *o, struct ram_capture *r) {
    struct precap_state *s = o->extension;
    return s && !s->reason && precap_role(s, r->capture);
}

static void precap_select(struct observer *o, struct precap_frame *f) {
    if (o->held_owned) retain_unresolved(o, 218, 2);
    for (u32 i = 0; i < 8; ++i) o->held_candidate[i] = f->owner.candidate[i];
    o->held_owned = f->owner.owned;
    o->jpeg_before = (struct held_image){0}; o->jpeg_after = (struct held_image){0};
}

/* Pool-length-safe (>32 records!) retained_state / hold_acquire / hold_release for long bursts (up to 4096 nodes).
 * Walks the complete doubly-linked chain from list[1] (tail) to list[0] (head), verifying endpoints, count,
 * prev/next links, termination (head->prev == 0), and unique candidate match while the pool mutex is held. */
static int s6_retained_state(struct observer *o, const u32 *candidate, u32 stage, u32 mutex, u32 *users) {
    u32 root, pool, header[3], list[3], prefix[5], tail[3];
    if (!read_mem(o, m7_config.bias + 0x1463800u, &root, 4) || !private_range(o, root, 0x68) ||
        !read_mem(o, root + candidate[0] * 4u, &pool, 4) || pool != candidate[1] ||
        !read_mem(o, pool, header, 12) || header[0] + 4u != mutex ||
        !pool_activity_allowed(header[1], stage >= 4u) || header[2] != candidate[2] ||
        !read_mem(o, pool + 0x70c4u, list, 12) ||
        !list[2] || list[2] > 4096u || !list[0] || !list[1] ||
        (list[0] & 3u) || (list[1] & 3u) || (list[2] == 1u && list[0] != list[1])) return 0;
    u32 record = list[1], next_expected = 0, last_visited = 0, visited = 0;
    u32 matches = 0, found_record = 0, found_uid = 0, found_cap = 0;
    for (; visited < list[2] && record; ++visited) {
        if ((record & 3u) || !private_range(o, record, 0x174u) ||
            !read_mem(o, record, prefix, 20) || prefix[1] != next_expected) return 0;
        if (prefix[3] == candidate[4]) {
            ++matches;
            found_record = record;
            found_uid = prefix[3];
            found_cap = prefix[4];
        }
        last_visited = record;
        next_expected = record;
        record = prefix[0];
    }
    if (record != 0u || visited != list[2] || last_visited != list[0] ||
        matches != 1u || found_record != candidate[3] || found_cap != candidate[5] ||
        !read_mem(o, found_record + 0x168u, tail, 12) || tail[2] >= 0x7fffffffu ||
        (stage == 6u ? (tail[0] & 0xffffu) > 1u : ((tail[0] & 0xffffu) != 1u || (stage != 1u && !tail[2])))) return 0;
    *users = tail[2];
    u32 data[8] = {stage, pool, found_record, found_uid, found_cap, tail[0], tail[2], mutex};
    emit(o, 12, data);
    return 1;
}

static __attribute__((noinline)) int s6_try_lock(struct observer *o, struct trace_context *t,
                                                 u32 operation, u32 mutex) {
    u32 result = 16u;
    for (u32 i = 0; i < 8u && result == 16u; ++i) {
        if (!s6_sony_call(o, t, operation, mutex, 0u, 0u, &result)) return 0;
        if (result == 16u) sleep_ms(5);
    }
    if (result != 0u) retain_notice(o, 93, operation, result);
    return result == 0u;
}

static __attribute__((noinline)) void s6_unlock_owned(struct observer *o, struct trace_context *t,
                                                      u32 operation, u32 mutex) {
    u32 result;
    if (!s6_sony_call(o, t, operation, mutex, 0u, 0u, &result) &&
        !s6_sony_call(o, t, operation, mutex, 0u, 0u, &result)) retain_unresolved(o, 32u, operation);
    if (result != 0u) retain_unresolved(o, 33u, result);
}

static __attribute__((noinline)) void s6_hold_unlock(struct observer *o, struct locked_frame *f) {
    if (f->pool_owned) s6_unlock_owned(o, &f->trace, 4u, f->mutex);
    if (f->root_owned) s6_unlock_owned(o, &f->trace, 6u, f->root_mutex);
    s6_trace_restore(o, &f->trace);
    f->pool_owned = f->root_owned = 0;
}

static __attribute__((noinline)) int s6_hold_lock(struct observer *o, struct locked_frame *f,
                                                  const u32 *candidate, int retained) {
    u32 root, root_lock, checked_root, checked_lock, header[3] = {0}, reason = 8u;
    if (retained && !o->held_owned) goto refused;
    if (!s6_trace_begin(o, &f->trace)) return 0;
    reason = 1u;
    if (!read_mem(o, m7_config.bias + 0x1463800u, &root, 4) || !private_range(o, root, 0x68u) ||
        !read_mem(o, root + 0x10u, &root_lock, 4) || !private_range(o, root_lock, 28u)) goto refused;
    f->root_mutex = root_lock + 4u;
    reason = 10u;
    if (!s6_try_lock(o, &f->trace, 5u, f->root_mutex)) goto refused;
    f->root_owned = 1;
    reason = 2u;
    if (!read_mem(o, m7_config.bias + 0x1463800u, &checked_root, 4) || checked_root != root ||
        !read_mem(o, root + 0x10u, &checked_lock, 4) || checked_lock != root_lock) goto refused;
    reason = 3u;
    if (candidate[0] >= 3u || !read_mem(o, root + candidate[0] * 4u, &f->pool, 4) ||
        f->pool != candidate[1]) goto refused;
    reason = 4u;
    if (!read_mem(o, f->pool, header, 12)) goto refused;
    reason = 5u;
    if (!pool_activity_allowed(header[1], retained)) goto refused;
    reason = 6u;
    if (header[2] != candidate[2]) goto refused;
    reason = 7u;
    if (!private_range(o, header[0], 28u)) goto refused;
    f->mutex = header[0] + 4u;
    hold_pool_notice(o, f, candidate, 0u, header, retained);
    u32 guard[8] = {5u, root, f->root_mutex, f->pool, f->mutex, candidate[0], candidate[4], candidate[5]};
    emit(o, 13, guard);
    reason = 9u;
    if (!s6_try_lock(o, &f->trace, 1u, f->mutex)) goto refused;
    f->pool_owned = 1;
    return 1;
refused:
    hold_pool_notice(o, f, candidate, reason, header, retained);
    return 0;
}

static __attribute__((noinline)) int s6_hold_lock_retry(struct observer *o, struct locked_frame *f,
                                                        const u32 *candidate, int retained) {
    for (u32 attempt = 0u; attempt < 16u; ++attempt) {
        if (s6_hold_lock(o, f, candidate, retained)) return 1;
        s6_hold_unlock(o, f);
        __aeabi_memclr(f, sizeof(*f));
        sleep_ms(20);
    }
    return 0;
}

static int s6_hold_acquire(struct observer *o, const u32 *candidate) {
    struct locked_frame f = {0};
    u32 before = 0, acquired = 0, result = 0;
    int ok = 0;
    if (!s6_hold_lock_retry(o, &f, candidate, 0)) return 0;
    if (!s6_retained_state(o, candidate, 1, f.mutex, &before) || before >= 0x7ffffffeu) goto done;
    if (!s6_sony_call(o, &f.trace, 2u, f.pool + 0x70b4u, candidate[4], 1u, &result)) goto done;
    if (!s6_retained_state(o, candidate, 2, f.mutex, &acquired)) retain_unresolved(o, 40, 1);
    if (acquired == before && result != 0u) goto done;
    if (result || acquired != before + 1u) retain_unresolved(o, 40, result);
    for (u32 i = 0; i < 8u; ++i) o->held_candidate[i] = candidate[i];
    o->held_owned = ok = 1;
done:
    s6_hold_unlock(o, &f);
    return ok;
}

static int s6_hold_release(struct observer *o) {
    struct locked_frame f = {0};
    u32 before = 0, after = 0, result = 0;
    if (!s6_hold_lock_retry(o, &f, o->held_candidate, 1)) retain_unresolved(o, 41, 1);
    if (!s6_retained_state(o, o->held_candidate, 5, f.mutex, &before)) retain_unresolved(o, 41, 2);
    if (!s6_sony_call(o, &f.trace, 3u, f.pool + 0x70b4u, o->held_candidate[4], 0u, &result) &&
        !s6_sony_call(o, &f.trace, 3u, f.pool + 0x70b4u, o->held_candidate[4], 0u, &result)) retain_unresolved(o, 42, 1);
    if (result != 0u) retain_unresolved(o, 42, result);
    o->held_owned = 0;
    int ok = s6_retained_state(o, o->held_candidate, 6, f.mutex, &after) && after + 1u == before;
    s6_hold_unlock(o, &f);
    return ok;
}

static void precap_release_source(struct observer *o, struct precap_frame *f) {
    if (!f->owner.owned) return;
    precap_select(o, f); ram_monitor(o);
    if (!s6_hold_release(o) || o->held_owned) retain_unresolved(o, 218, 3);
    f->owner.owned = 0; f->owner.released = 1;
    precap_notice(o, 21, f->ordinal, f->capture, f->uid, 1, 0, 0, 0);
}

static void precap_remove(struct observer *o, struct precap_state *s, u32 reason) {
    struct precap_frame *f = &s->frames[0];
    if (!s->count) retain_unresolved(o, 218, 5);
    u32 ordinal = f->ordinal, capture = f->capture, uid = f->uid;
    precap_release_source(o, f);
    for (u32 i = 1; i < s->count; ++i) s->frames[i - 1] = s->frames[i];
    --s->count; s->frames[s->count] = (struct precap_frame){0};
    precap_notice(o, 4, ordinal, capture, uid, reason, s->count, 0, s->evicted);
}

static void precap_memory(struct observer *o, struct precap_state *s) {
    u32 info[16] = {0}, status = call(116, (u32)info, 0, 0, 0, 0, 0);
    if (!status && info[13] && info[5] <= 0xffffffffu / info[13]) s->free_bytes = info[5] * info[13];
    s->capacity = m7_precap_config.before;
    precap_notice(o, 15, s->free_bytes, 0, 0, 0, s->capacity, s->capacity, status);
}

static u32 precap_role(struct precap_state *s, u32 capture) {
    for (u32 i = 0; i < s->id_count; ++i) if (s->ids[i].capture == capture) return s->ids[i].role;
    return 0;
}

static void s6_drop_id(struct precap_state *s, u32 capture) {
    for (u32 i = 0; i < s->id_count; ++i) {
        if (s->ids[i].capture == capture) {
            for (u32 j = i + 1u; j < s->id_count; ++j) s->ids[j - 1u] = s->ids[j];
            --s->id_count;
            return;
        }
    }
}

static void precap_backlog(struct observer *o, struct precap_state *s, int force) {
    if (!(s->state >= PRECAP_ARMED && s->state <= PRECAP_DRAIN) || s->backlog_busy ||
        (!force && s->backlog_seen && now() - s->backlog_at < m7_precap_config.sample_ms)) return;
    s->backlog_busy = 1; s->backlog_valid = 0;
    u32 at = now(), gap = s->backlog_seen ? at - s->backlog_at : 0;
    if (gap > s->backlog_gap) s->backlog_gap = gap;
    s->backlog_at = at; s->backlog_seen = 1;
    u32 cursor[2], valid = read_mem(o, s->manager + 0x88, cursor, 8), root, pools[3], list_count = 0, rest_count = 0;
    if (!valid || cursor[0] > 512 || cursor[1] > 512) goto invalid;
    if (!s->cursor_ready) {
        if (cursor[0] != cursor[1]) goto invalid;
        s->cursor = cursor[0]; s->cursor_ready = 1;
    }
    u32 pending = (cursor[0] + 513 - s->cursor) % 513;
    u32 max_pending = (s->state == PRECAP_DRAIN) ? 256u : 128u;
    if (pending > max_pending) goto invalid;
    u32 limit = force ? pending : ((s->state == PRECAP_DRAIN) ? 64u : PRECAP_REGISTRATION_SLICE);
    u32 post_cap = m7_precap_config.after ? m7_precap_config.after : m7_precap_config.post_max;
    u32 q_lim = s6_post_q_limit();
    for (u32 i = 0; i < pending && i < limit; ++i) {
        u32 slot = s->cursor, words[13], again[13];
        if (!read_mem(o, s->manager + 0x90 + slot * 52, words, 52) ||
            !read_mem(o, s->manager + 0x90 + slot * 52, again, 52)) goto invalid;
        for (u32 j = 0; j < 13; ++j) if (words[j] != again[j]) goto invalid;
        if (!ram_same_tuple(words, words[11], 0)) goto invalid;
        u32 capture = words[11], role = 0;
        if (precap_role(s, capture)) goto invalid;
        ++s->announced;
        if (s->state != PRECAP_DRAIN && !s->reason) {
            if (!s->trigger_ms) {
                if (s->id_count == s->capacity) {
                    precap_notice(o, 47, s->ids[0].capture, s->ids[0].observed_ms, 1, 0, 0, 0, 0);
                    for (u32 j = 1; j < s->id_count; ++j) s->ids[j - 1] = s->ids[j];
                    --s->id_count; ++s->evicted;
                }
                role = 1;
            } else {
                u32 cur_q = (s->announced >= s->delivered) ? (s->announced - s->delivered + s->count) : 0u;
                if (!s->post_limit_hit && cur_q >= q_lim) {
                    s->post_limit_hit = 1u;
                    if (!s->post_cutoff_cause) s->post_cutoff_cause = 2u;
                }
                if (!s->post_limit_hit && s->post < post_cap && s->id_count < PRECAP_MAX_IDS) {
                    role = 2; ++s->post;
                }
            }
            if (role && s->id_count < PRECAP_MAX_IDS)
                s->ids[s->id_count++] = (struct precap_identity){capture, at - o->started, role};
        }
        precap_notice(o, 46, s->announced, capture, at - o->started, slot, role, s->id_count, s->post);
        s->cursor = (s->cursor + 1) % 513;
        if (!s->ready && s->id_count == s->capacity && !s->trigger_ms && !s->reason) {
            s->ready = 1; precap_notice(o, 1, at - o->started, s->capacity, s->id_count, 0, 0, 0, 0);
            precap_hold_notice(o, s, 1);
        }
    }
    s->queue_depth = (cursor[0] + 513 - cursor[1]) % 513;
    if (s->announced < s->delivered) goto invalid;
    s->queue = s->announced - s->delivered + s->count;
    if (s->queue_depth > s->queue) s->queue = s->queue_depth;
    if (s->queue > s->queue_peak) s->queue_peak = s->queue;
    valid = read_mem(o, m7_config.bias + 0x1463800, &root, 4) && read_mem(o, root, pools, 12);
    if (valid) for (u32 i = 0; i < 3; ++i) if (pools[i]) {
        u32 header[3], list[3], rest;
        if (!read_mem(o, pools[i], header, 12)) { valid = 0; break; }
        if (header[2] != 0x4100) continue;
        if (!read_mem(o, pools[i] + 0x70c4, list, 12) || !read_mem(o, pools[i] + 0x71c8, &rest, 4)) { valid = 0; break; }
        list_count += list[2]; rest_count += rest;
    }
    precap_notice(o, 48, cursor[0], cursor[1], s->queue, list_count, rest_count, gap, valid);
    s->backlog_valid = valid && s->cursor == cursor[0];
    if (s->queue >= m7_precap_config.backlog_cap) {
        if (s->state == PRECAP_ARMED && !s->trigger_ms && !s->reason) {
            s->reason = 12;
        } else if (s->state == PRECAP_POST) {
            s->post_limit_hit = 1u;
            if (!s->post_cutoff_cause) s->post_cutoff_cause = 2u;
        } else if (s->state == PRECAP_DRAIN) {
            /* Late physical full-press exposures during DRAIN are fast-dropped; never erase frozen selection! */
            s->drain_q_overflow = 1u;
        }
    }
    s->backlog_busy = 0; return;
invalid:
    if (!s->reason) s->reason = 12;
    precap_notice(o, 48, PRECAP_NONE, PRECAP_NONE, PRECAP_NONE, 0, 0, gap, 0);
    s->backlog_busy = 0;
}

static void __attribute__((noinline)) precap_dump_cells(struct observer *o) {
    u32 root, pools[3];
    if (!read_mem(o, m7_config.bias + 0x1463800, &root, 4) || !read_mem(o, root, pools, 12)) {
        precap_notice(o, 51, 0, 0, 0, 0, 0, 0, 0); return;
    }
    for (u32 i = 0; i < 3; ++i) if (pools[i]) {
        u32 header[3], list[3];
        if (!read_mem(o, pools[i], header, 12) || header[2] != 0x4100) continue;
        if (!read_mem(o, pools[i] + 0x70c4, list, 12)) { precap_notice(o, 51, pools[i], 0, 0, 0, 0, 0, 0); continue; }
        precap_notice(o, 51, pools[i], list[0], list[1], list[2], 0, list[0], 0);
    }
}

/* Variant A Two-Phase Cadence Policy:
 * - Phase 1 (burst): hold software S2 continuously (full 15-20 fps Continuous Hi parity) until queue >= burst_cap.
 * - Phase 2 (steady): hysteresis [low_water, burst_cap] maintaining ~3.3-3.8 fps rolling with zero blind gaps.
 * - PRECAP_POST: hold software S2 continuously (full 15-20 fps) until full-press releases or post/queue safety cap.
 */
static u32 s6_cadence_want_s2(struct precap_state *s) {
    if (s->reason || s->state == PRECAP_DRAIN || s->state == PRECAP_RESTORE) return 0u;
    if (!s->backlog_valid || s->input.failed) return 0u;
    u32 at = now();
    if ((u32)(at - s->input.last_ms) > PRECAP_FRESH_MS ||
        (u32)(at - s->backlog_at) > PRECAP_FRESH_MS) return 0u;

    u32 bcap = m7_precap_config.burst_cap;
    u32 q_lim = s6_post_q_limit();

    if (s->state == PRECAP_POST) {
        u32 post_cap = m7_precap_config.after ? m7_precap_config.after : m7_precap_config.post_max;
        if (s->post_limit_hit || s->post >= post_cap || s->queue >= q_lim) return 0u;
        return 1u;
    }

    if (s->phase_burst) {
        if (s->queue >= bcap) {
            s->phase_burst = 0u;
            return 0u;
        }
        return 1u;
    }

    u32 low_water = (bcap > 3u) ? (bcap - 3u) : 1u;
    if (low_water < s->capacity + 1u && s->capacity + 1u < bcap) low_water = s->capacity + 1u;
    if (s->s2_down) return (s->queue >= bcap) ? 0u : 1u;
    return (s->queue <= low_water) ? 1u : 0u;
}

static void s6_s2_spawn(struct observer *o, struct precap_state *s, u32 val) {
    if (s->s2_cmd_active || (s->start.pid > 0 && !s->start.reaped)) return;
    u32 at = now();
    s->start = (struct sd_start_command){0};
    s->start.started = at;
    s->start.status = 0xffffffffu;
    s->s2_cmd_val = val;
    s->s2_cmd_active = 1u;
    s->s2_changed_ms = at;
    if (val == 1u) {
        s->pace_at = at;
        ++s->pulses;
        s->s2_up = 0u;
        s->s2_down = 1u;
    } else {
        s->s2_down = 0u;
        s->s2_up = 0u;
    }
    s->start.pid = call(2, 0, 0, 0, 0, 0, 0);
    if (!s->start.pid) { child_exec(2, val); return; }
    if ((s32)s->start.pid < 0) retain_unresolved(o, 218, 11);
    if (val == 1u) {
        precap_notice_at(o, at - o->started, 56, s->pulses, s->queue, s->phase_burst,
                         m7_precap_config.burst_cap, m7_precap_config.backlog_cap,
                         at - s->input.last_ms, at - s->backlog_at);
        precap_notice_at(o, at - o->started, 34, s->pulses, s->queue, m7_precap_config.backlog_cap,
                         s->count, s->evicted, !!s->trigger_ms, s->post);
    }
}

static void precap_tick_work(struct observer *o, struct ram_capture *r) {
    struct precap_state *s = o->extension;
    if (!s || !(s->state >= PRECAP_ARMED && s->state <= PRECAP_DRAIN)) return;
    precap_sample(o);
    while (s->count && (s->reason || !precap_role(s, s->frames[0].capture))) precap_remove(o, s, 3);
    connect_caller(o, &r->owners, 1);
    if (s->reason) { precap_request_stop(o, s); precap_sample(o); return; }
    if (s->state == PRECAP_DRAIN || s->s2_cmd_active) return;

    u32 want = s6_cadence_want_s2(s);
    if (want && s->s2_up) {
        s6_s2_spawn(o, s, 1u);
    } else if (!want && s->s2_down) {
        s6_s2_spawn(o, s, 0u);
    }
}

static void precap_admission_idle(struct observer *o) {
    (void)o;
}

static void precap_tick(struct observer *o, struct ram_capture *r) {
    u32 phase_prev = o->phase; o->phase = 28;
    precap_tick_work(o, r);
    o->phase = phase_prev;
}

static int precap_post_write_ready(struct precap_state *s) {
    return s->state == PRECAP_POST && !s->reason && !s->s2_cmd_active && s->s2_up &&
           !s->input.failed && !s->input.entries[s->half].status && !s->input.entries[s->full].status &&
           now() - s->input.last_ms <= PRECAP_FRESH_MS;
}

/* Fast memcpy copy_pixels using 8 KiB verified stack scratch (sp-8192 inside private_range sp-0x4000)
 * and brief WNOHANG spin before sleep_ms(2) to avoid 10 ms jiffy stalls on fast memcpy calls. */
static __attribute__((noinline)) int s6_copy_pixels_fast(struct observer *o, struct trace_context *t, u32 address, u32 size,
                               unsigned char *out, struct held_image *image) {
    if (!size || size > S6_COPY_CHUNK) return 0;
    u32 call_sp = t->original[13] - S6_COPY_CHUNK;
    u32 target = m7_config.bias + 0x10d8dcu; /* memcpy@plt, pinned in code_pins */
    u32 trap = m7_config.bias + 0x55abcu;
    for (u32 i = 0; i < 18u; ++i) t->work[i] = t->original[i];
    t->work[0] = call_sp;
    t->work[1] = address;
    t->work[2] = size;
    t->work[3] = 0u;
    t->work[13] = call_sp;
    t->work[14] = trap | 1u;
    t->work[15] = target & ~1u;
    t->work[16] = (t->work[16] & ~0x0700ffe0u) | (target & 1u ? 0x20u : 0u);
    t->work[17] = 0xffffffffu;
    t->dirty = 1;
    if (s6_ptrace_retry(o, 13u, 0u, (u32)t->work) != 0) return 0;
    u32 verify[18];
    if (s6_ptrace_retry(o, 12u, 0u, (u32)verify) != 0) return 0;
    for (u32 i = 0; i < 18u; ++i) if (verify[i] != t->work[i]) return 0;
    if (s6_ptrace_retry(o, 7u, 0u, 0u) != 0) return 0;

    u32 status = 0, started = now(), reported = 0, spins = 0;
    for (;;) {
        s32 rc = call(114, o->trace_tid, (u32)&status, 0x40000001, 0, 0, 0);
        if (rc == (s32)o->trace_tid) break;
        if (rc < 0 && rc != -4) retain_unresolved(o, 17u, (u32)rc);
        if (spins < 256u) {
            ++spins;
            continue;
        }
        precap_sample(o);
        if (!reported && now() - started >= 2000u) {
            retain_notice(o, 97, 17u, now() - started);
            reported = 1u;
        }
        precap_wait(o, 2);
    }
    if (status != 0x057fu) retain_unresolved(o, 7u, status);
    {
        s32 grc = s6_ptrace_retry(o, 12u, 0u, (u32)t->work);
        if (grc != 0) retain_unresolved(o, 220u + 7u, (u32)grc);
    }
    if ((t->work[15] != trap && t->work[15] != trap + 2u) || !(t->work[16] & 0x20u) ||
        t->work[13] != call_sp) retain_unresolved(o, 8, t->work[15]);
    for (u32 i = 4u; i <= 11u; ++i)
        if (t->work[i] != t->original[i]) retain_unresolved(o, 9, i);
    if (t->work[0] != call_sp) return 0;
    image->copies++;
    return read_mem(o, call_sp, (u32 *)out, size);
}

static int s6_jpeg_sof_supported(u32 marker) {
    return marker == 0xc0u || marker == 0xc1u || marker == 0xc2u;
}

/* Byte-exact SOI/SOF0-2/SOS/EOI JPEG validator without SHA-256 (O(1) segment skips + marker-specific SOF/SOS checks). */
static void s6_fast_jpeg_inspect(struct observer *o, struct locked_frame *f, struct precap_state *ps,
                                 u32 stage, struct held_image *image) {
    u32 metadata[8] = {stage}, ready = 0, header[2], status = 2;
    u32 *body = metadata + 5;
    u32 progress[8] = {stage, 0, o->held_candidate[4]};
    emit(o, 19, progress);
    if (read_mem(o, o->held_candidate[3] + 0x154, &ready, 4)) {
        metadata[1] = ready & 255u;
        metadata[7] |= 1u;
    }
    if (read_mem(o, o->held_candidate[3] + 0x20, metadata + 2, 12)) {
        metadata[7] |= 2u;
        if (metadata[2] && read_mem(o, metadata[2] + 0x28, body, 8)) metadata[7] |= 4u;
    }
    emit(o, 20, metadata);
    if ((metadata[7] & 6u) != 6u) goto done;
    status = 3;
    if (!pixel_map(o, body[0], body[1]) || body[1] < 8u) goto done;
    status = 4;
    if (!s6_copy_pixels_fast(o, &f->trace, body[0], 8u, (unsigned char *)header, image)) goto done;
    status = 5;
    if (header[0] != 0x4944574du || header[1] < 8u || header[1] >= body[1]) goto done;
    image->address = body[0] + header[1];

    u32 limit = body[1] - header[1], offset = 0;
    u32 st = 0, marker = 0, remaining = 0, seg_total = 0, seg_at = 0, length = 0, width = 0, height = 0;
    u32 sof = 0, sof_marker = 0, sof_nf = 0, sos = 0, sos_ns = 0, sos_seen = 0, sos_ss = 0;
    u32 comp_idx = 0, comp_sub = 0, done_flag = 0, err = 0;
    unsigned char sof_cids[4] = {0, 0, 0, 0};
    unsigned char *buf = ps->io_buf;
    status = 6;
    while (offset < limit && !done_flag && !err) {
        if ((offset & 0x3ffffu) == 0u) precap_sample(o);
        u32 n = limit - offset;
        if (n > S6_COPY_CHUNK) n = S6_COPY_CHUNK;
        if (!s6_copy_pixels_fast(o, &f->trace, image->address + offset, n, buf, image)) { status = 4; goto done; }
        u32 i = 0;
        while (i < n && !done_flag && !err) {
            if (st == 7u) {
                u32 s0 = i;
                while (i < n && buf[i] != 0xffu) ++i;
                length += (i - s0);
                if (i < n) { ++i; ++length; st = 8u; }
                continue;
            }
            if (st == 6u && !s6_jpeg_sof_supported(marker) && marker != 0xdau) {
                u32 avail = n - i;
                u32 skip = remaining < avail ? remaining : avail;
                i += skip;
                length += skip;
                remaining -= skip;
                if (!remaining) st = 2u;
                continue;
            }
            unsigned char v = buf[i++];
            ++length;
            switch (st) {
            case 0: if (v != 0xffu) err = 1u; else st = 1u; break;
            case 1: if (v != 0xd8u) err = 1u; else st = 2u; break;
            case 2: if (v != 0xffu) err = 1u; else st = 3u; break;
            case 3:
                if (v == 0xffu) break;
                if (v == 0xd9u) { done_flag = (sof && sos && width && height) ? 1u : 0u; err = !done_flag; }
                else if (v == 0x01u) st = 2u;
                else if (v == 0u || (v >= 0xd0u && v <= 0xd8u)) err = 1u;
                else if (jpeg_sof(v) && !s6_jpeg_sof_supported(v)) err = 1u;
                else { marker = v; st = 4u; }
                break;
            case 4: remaining = (u32)v << 8; st = 5u; break;
            case 5:
                remaining |= v;
                if (remaining < 2u ||
                    (s6_jpeg_sof_supported(marker) && (sof || remaining < 11u)) ||
                    (marker == 0xdau && (remaining < 8u || !sof))) { err = 1u; break; }
                remaining -= 2u; seg_total = remaining; seg_at = 0u;
                comp_idx = 0u; comp_sub = 0u; sos_ns = 0u; sos_seen = 0u; sos_ss = 0u;
                st = remaining ? 6u : 2u;
                break;
            case 6:
                if (s6_jpeg_sof_supported(marker)) {
                    if (seg_at == 0u) {
                        if (marker == 0xc0u) { if (v != 8u) err = 1u; }
                        else { if (v != 8u && v != 12u) err = 1u; }
                    } else if (seg_at == 1u) {
                        height = (u32)v << 8;
                    } else if (seg_at == 2u) {
                        height |= v;
                        if (!height) err = 1u;
                    } else if (seg_at == 3u) {
                        width = (u32)v << 8;
                    } else if (seg_at == 4u) {
                        width |= v;
                        if (!width) err = 1u;
                    } else if (seg_at == 5u) {
                        if (v < 1u || v > 4u || seg_total != 6u + 3u * (u32)v) err = 1u;
                        else { sof_nf = v; sof_marker = marker; }
                    } else {
                        if (comp_sub == 0u) {
                            for (u32 k = 0; k < comp_idx; ++k) if (sof_cids[k] == v) err = 1u;
                            if (comp_idx < 4u) sof_cids[comp_idx] = v;
                            comp_sub = 1u;
                        } else if (comp_sub == 1u) {
                            u32 hi = (u32)v >> 4, vi = (u32)v & 0x0fu;
                            if (hi < 1u || hi > 4u || vi < 1u || vi > 4u) err = 1u;
                            comp_sub = 2u;
                        } else {
                            if (v > 3u) err = 1u;
                            comp_sub = 0u;
                            ++comp_idx;
                        }
                    }
                    ++seg_at;
                    if (!--remaining) {
                        if (!err && sof_nf >= 1u && comp_idx == sof_nf && comp_sub == 0u) { sof = 1u; st = 2u; }
                        else err = 1u;
                    }
                } else if (marker == 0xdau) {
                    if (seg_at == 0u) {
                        if (v < 1u || v > sof_nf || seg_total != 4u + 2u * (u32)v) err = 1u;
                        else sos_ns = v;
                    } else if (seg_at <= 2u * sos_ns) {
                        if ((seg_at & 1u) == 1u) {
                            u32 found_c = 0u;
                            for (u32 k = 0; k < sof_nf; ++k) {
                                if (sof_cids[k] == v) {
                                    if (sos_seen & (1u << k)) err = 1u;
                                    sos_seen |= (1u << k);
                                    found_c = 1u;
                                    break;
                                }
                            }
                            if (!found_c) err = 1u;
                        } else {
                            u32 max_ht = (sof_marker == 0xc0u) ? 1u : 3u;
                            if (((u32)v >> 4) > max_ht || ((u32)v & 0x0fu) > max_ht) err = 1u;
                        }
                    } else {
                        u32 tail_idx = seg_at - (1u + 2u * sos_ns);
                        if (tail_idx == 0u) {
                            sos_ss = v;
                            if (sof_marker == 0xc0u || sof_marker == 0xc1u) {
                                if (v != 0u) err = 1u;
                            } else {
                                if (v > 63u || (v > 0u && sos_ns != 1u)) err = 1u;
                            }
                        } else if (tail_idx == 1u) {
                            if (sof_marker == 0xc0u || sof_marker == 0xc1u) {
                                if (v != 63u) err = 1u;
                            } else {
                                if (sos_ss == 0u) {
                                    if (v != 0u) err = 1u;
                                } else {
                                    if (v < sos_ss || v > 63u) err = 1u;
                                }
                            }
                        } else if (tail_idx == 2u) {
                            u32 ah = (u32)v >> 4, al = (u32)v & 0x0fu;
                            if (sof_marker == 0xc0u || sof_marker == 0xc1u) {
                                if (v != 0u) err = 1u;
                            } else {
                                if (ah > 13u || al > 13u || (ah != 0u && ah != al + 1u)) err = 1u;
                            }
                        } else {
                            err = 1u;
                        }
                    }
                    ++seg_at;
                    if (!--remaining) {
                        if (!err && sos_ns >= 1u) { sos = 1u; st = 7u; }
                        else err = 1u;
                    }
                } else {
                    err = 1u;
                }
                break;
            case 8:
                if (!v || (v >= 0xd0u && v <= 0xd7u)) st = 7u;
                else if (v == 0xffu) st = 8u;
                else if (v == 0xd9u) { done_flag = (sof && sos && width && height) ? 1u : 0u; err = !done_flag; }
                else if (v == 0x01u) st = 2u;
                else if (v >= 0xd0u && v <= 0xd8u) err = 1u;
                else if (jpeg_sof(v) && !s6_jpeg_sof_supported(v)) err = 1u;
                else { marker = v; st = 4u; }
                break;
            default: err = 1u; break;
            }
        }
        offset += n;
    }
    if (!done_flag || err) goto done;
    image->length = length; image->width = width; image->height = height;
    image->valid = 1; status = 1;
done:
    progress[1] = status; progress[2] = image->address; progress[3] = image->length;
    progress[4] = image->width; progress[5] = image->height; progress[6] = image->copies; progress[7] = body[0];
    emit(o, 17, progress);
}

/* Non-colliding 24-bit filename token supporting up to 255 saved files per ring run. */
static u32 s6_commit_name_token(struct observer *o) {
    return o->commit_sequence ? ((m7_config.token ^ o->commit_sequence) | 0x80000000u) : m7_config.token;
}

static void s6_commit_notice(struct observer *o, u32 stage, u32 a, u32 b, u32 c) {
    u32 data[8] = {stage, a, b, c, o->held_candidate[4], s6_commit_name_token(o), o->commit_drive, o->commit_status};
    emit(o, 21, data);
}

static int s6_commit_path(struct observer *o, struct trace_context *t) {
    const char hex[] = "0123456789ABCDEF";
    unsigned char path[68] = {0};
    u32 tok = s6_commit_name_token(o);
    path[0] = (unsigned char)o->commit_drive; path[1] = ':'; path[2] = '\\'; path[3] = 'P'; path[4] = 'C';
    for (u32 i = 0; i < 6u; ++i) path[5 + i] = hex[(tok >> (20u - 4u * i)) & 15u];
    path[11] = '.'; path[12] = 'J'; path[13] = 'P'; path[14] = 'G';
    return s6_commit_scratch(o, t, 0u, path, sizeof(path));
}

static __attribute__((noinline)) int s6_commit_sd_drive(struct observer *o, struct trace_context *t) {
    u32 mask = 0, complete = 1, scratch = t->original[13] - 4096u;
    const unsigned char zero[56] = {0};
    for (u32 index = 0; index < 5u; ++index) {
        unsigned char path[256] __attribute__((aligned(4))) = {0};
        u32 data[8] = {index, 0, 0, 0, 0xffffffffu, 0, 0, 0}, info[14] = {0}, copied = 0;
        if (!s6_commit_scratch(o, t, 256u, zero, sizeof(zero))) { data[7] = 1; goto report; }
        if (!s6_sony_call(o, t, 13u, index, scratch + 256u, 0u, &data[1])) { data[7] = 2; goto report; }
        if (!read_mem(o, scratch + 256u, &data[2], 4)) { data[7] = 3; goto report; }
        if (data[1] > 1u || data[1] != (data[2] != 0u)) { data[7] = 4; goto report; }
        if (!data[2]) goto report;
        if (!read_mem(o, data[2], (u32 *)path, sizeof(path))) { data[7] = 5; goto report; }
        while (data[6] < sizeof(path) && path[data[6]]) data[6]++;
        if (data[6] == sizeof(path)) { data[7] = 6; goto report; }
        copied = 1;
        if (!data[6]) goto report;
        if (!s6_commit_scratch(o, t, 0u, path, sizeof(path))) { data[7] = 7; goto report; }
        if (!s6_sony_call(o, t, 8u, scratch, 0u, 0u, &data[3])) { data[7] = 8; goto report; }
        if (!data[3]) goto report;
        if (data[3] >= 'a' && data[3] <= 'z') data[3] -= 'a' - 'A';
        if (data[3] < 'A' || data[3] > 'Z') { data[7] = 9; goto report; }
        if (!s6_sony_call(o, t, 14u, data[3], scratch + 256u, 0u, &data[4])) { data[7] = 10; goto report; }
        if (data[4] != 0u) { complete = 0; goto report; }
        if (!read_mem(o, scratch + 256u, info, sizeof(info))) { data[7] = 11; goto report; }
        data[5] = info[0];
        u32 type = info[0] >> 16;
        if (type == 0x8400u || type == 0x8401u || type == 0x8402u || type == 0x84ffu) {
            mask |= 1u << (data[3] - 'A');
            if (info[0] & 0x43u) complete = 0;
        }
report:
        if (data[7]) complete = 0;
        emit(o, 23, data);
        if (copied) for (u32 offset = 0; offset <= data[6]; offset += 24u) {
            u32 chunk[8] = {index, offset};
            for (u32 j = 0; j < 24u && offset + j <= data[6]; ++j)
                chunk[2 + j / 4u] |= (u32)path[offset + j] << (8u * (j % 4u));
            emit(o, 24, chunk);
        }
    }
    u32 count = 0, drive = 0;
    for (u32 i = 0; i < 26u; ++i) if (mask & (1u << i)) { count++; drive = 'A' + i; }
    o->commit_drive = complete && count == 1u ? drive : 0u;
    s6_commit_notice(o, 2, o->commit_drive, count, 5);
    return o->commit_drive != 0u;
}

static __attribute__((noinline)) int s6_commit_open(struct observer *o, struct trace_context *t,
                                                    u32 flags, u32 stage, u32 *handle, u32 *result) {
    u32 scratch = t->original[13] - 4096u;
    if (!s6_sony_call(o, t, 9u, scratch, scratch + 64u, flags, result)) return 0;
    if (*result == 0u && !read_mem(o, scratch + 64u, handle, 4)) retain_unresolved(o, 50u, stage);
    s6_commit_notice(o, stage, *result, *result == 0u ? *handle : 0u, flags);
    return 1;
}

static __attribute__((noinline)) void s6_commit_close(struct observer *o, struct trace_context *t,
                                                      u32 handle, u32 stage) {
    u32 result;
    if (!s6_sony_call(o, t, 11u, handle, 0u, 0u, &result) &&
        !s6_sony_call(o, t, 11u, handle, 0u, 0u, &result))
        retain_unresolved(o, 51u, stage);
    s6_commit_notice(o, stage, result, handle, 0);
    if (result != 0u) retain_unresolved(o, 52u, result);
}

static void s6_commit_write(struct observer *o, struct locked_frame *f) {
    struct held_image *b = &o->jpeg_after;
    o->commit_status = 2;
    s6_commit_notice(o, 1, m7_config.mpr_bias, b->address, b->length);
    if (!b->valid || b->width != 5472u || b->height != 3648u || !b->length) return;
    u32 result, handle = 0;
    o->commit_status = 3;
    if (!s6_commit_sd_drive(o, &f->trace)) return;
    o->commit_status = 4;
    if (!s6_commit_path(o, &f->trace)) return;
    o->commit_status = 6;
    if (!s6_commit_open(o, &f->trace, 1u, 3u, &handle, &result)) return;
    if (result == 0u) {
        s6_commit_close(o, &f->trace, handle, 11u);
        o->commit_status = 5; /* Never overwrite an existing file on SD */
        return;
    }
    if (result != 0x80000051u) return;
    o->commit_status = 7;
    if (!s6_commit_open(o, &f->trace, 7u, 4u, &handle, &result) || result != 0u) return;
    o->commit_status = 8;
    while (o->commit_written < b->length) {
        u32 n = b->length - o->commit_written;
        if (n > 1024u * 1024u) n = 1024u * 1024u;
        if (!s6_sony_call(o, &f->trace, 10u, handle, b->address + o->commit_written, n, &result)) {
            s6_commit_notice(o, 15, 10, 0, n);
            break;
        }
        if ((s32)result > 0 && result <= n) o->commit_written += result;
        if (result != n) { s6_commit_notice(o, 14, 10, result, n); break; }
    }
    s6_commit_notice(o, 5, o->commit_written, b->length, result);
    s6_commit_close(o, &f->trace, handle, 6u);
    if (o->commit_written == b->length) o->commit_status = 1;
}

static int precap_save(struct observer *o, struct precap_state *s, struct precap_frame *f, u32 role) {
    if (!s->trigger_ms || s->reason) return 0;
    if ((!s->released || s->state != PRECAP_DRAIN) && !precap_post_write_ready(s)) retain_unresolved(o, 218, 18);
    if (!f->owner.owned) retain_unresolved(o, 218, 18);
    u32 save_t0 = now();
    if (s->state == PRECAP_DRAIN && (u32)(save_t0 - s->stop_at) >= S6_SAVE_BUDGET_MS) {
        if (!s->reason) s->reason = 14u;
        if (!s->post_cutoff_cause) s->post_cutoff_cause = 6u;
        precap_notice(o, 28, 14, f->ordinal, s->saved, save_t0 - s->stop_at, S6_SAVE_BUDGET_MS, 0, 0);
        return 0;
    }
    if (s->state == PRECAP_POST)
        precap_notice(o, 61, s->saved + 1, s->s2_up, !s->s2_cmd_active, s->input.entries[s->half].status,
                      s->input.entries[s->full].status, s->state, save_t0 - s->input.last_ms);
    s->save_started_at = save_t0;
    s->save_active = 1; o->phase = 8;
    precap_notice(o, 9, s->saved + 1, f->capture, f->uid, role, f->ordinal, 0, 0);
    precap_select(o, f); ram_monitor(o);
    o->commit_sequence = s->saved + 1;
    o->commit_drive = o->commit_status = o->commit_written = o->commit_read = o->commit_reads = 0;
    for (u32 i = 0; i < 8; ++i) o->commit_digest[i] = 0;
    int wrote = 0;
    {
        struct locked_frame lock = {0};
        if (s6_hold_lock(o, &lock, o->held_candidate, 1)) {
            precap_progress(o, 1, 0, 0);
            s6_fast_jpeg_inspect(o, &lock, s, 3, &o->jpeg_after);
            o->jpeg_before = o->jpeg_after;
            precap_progress(o, 1, o->jpeg_after.length, 1);
            if (o->jpeg_after.valid && o->jpeg_after.width == 5472u && o->jpeg_after.height == 3648u) {
                precap_notice(o, 18, f->ordinal, f->capture, f->uid, o->jpeg_after.length, 5472, 3648, 1);
                precap_progress(o, 2, 0, 0); s6_commit_write(o, &lock);
                precap_progress(o, 2, o->commit_written, 1); wrote = o->commit_status == 1;
            }
        }
        /* ALWAYS unwind any partially acquired locks and detach monitor_tid even on s6_hold_lock refusal! */
        s6_hold_unlock(o, &lock);
        o->held_owned = 0;
    }
    if (wrote) {
        o->commit_status = 13;
        precap_notice(o, 54, f->ordinal, o->jpeg_after.length, o->jpeg_after.width, o->jpeg_after.height,
                      o->commit_written, 1, 0);
    }
    o->phase = 8; s6_commit_notice(o, 10, o->commit_status, o->commit_written, o->commit_read);
    int ok = o->commit_status == 13;
    precap_notice(o, 6, s->saved + 1, f->capture, f->uid, o->commit_written, o->commit_status, role, f->ordinal);
    if (ok) {
        ++s->saved;
        s->save_ms_total += (u32)(now() - save_t0);
    } else {
        /* Known save refusal/error with locks unwound & file handles closed: propagate cleanly through DRAIN/RESTORE. */
        s->reason = 7;
        precap_notice(o, 28, 7, f->ordinal, 0, 0, o->commit_status, 0, 0);
    }
    precap_release_source(o, f);
    s->drain_changed = now();
    s->save_active = 0;
    return ok;
}

static void precap_retire_ring(struct observer *o, struct precap_state *s) {
    while (s->count) {
        if (!!s->trigger_ms && !s->reason) precap_save(o, s, &s->frames[0], s->frames[0].role);
        precap_remove(o, s, 2);
    }
}

static void precap_flush_ready(struct observer *o, struct ram_capture *r) {
    struct precap_state *s = o->extension;
    if (s && s->count && precap_post_write_ready(s)) {
        u32 phase_prev = o->phase;
        precap_save(o, s, &s->frames[0], s->frames[0].role);
        precap_remove(o, s, 2);
        connect_caller(o, &r->owners, 1); o->phase = phase_prev;
    }
    if (s && (s->state == PRECAP_DRAIN) && s->released && s->count) {
        u32 phase_prev = o->phase;
        precap_retire_ring(o, s);
        connect_caller(o, &r->owners, 1); o->phase = phase_prev;
    }
}

static int precap_pool_closed(struct observer *o, struct precap_state *s, u32 pool, const u32 *list) {
    u32 previous = 0, node = list[0], again[12];
    if (list[2] > 512u) return 0;
    for (u32 n = 0; n < list[2]; ++n) {
        u32 row[12];
        if (!node || (node & 3) || !private_range(o, node, 0x1ac) ||
            !read_mem(o, node, row, 20) || row[0] != previous || !row[3] || row[3] == PRECAP_NONE ||
            !read_mem(o, node + 0x168, row + 5, 12) || !read_mem(o, node + 0x20, row + 8, 16)) return 0;
        for (u32 j = 0; j < n; ++j) if (s->pool_nodes[j] == node || s->pool_uids[j] == row[3]) return 0;
        s->pool_nodes[n] = node; s->pool_uids[n] = row[3];
        if ((row[5] & 0x00ffffff) || (row[5] >> 24) > 1 || (row[6] & 255) || row[7] ||
            row[8] || row[9] || row[10] || row[11]) return 0;
        if (!read_mem(o, node, again, 20) || !read_mem(o, node + 0x168, again + 5, 12) ||
            !read_mem(o, node + 0x20, again + 8, 16)) return 0;
        for (u32 j = 0; j < 12; ++j) if (row[j] != again[j]) return 0;
        previous = node; node = row[1];
    }
    if (node || previous != list[1] || !read_mem(o, pool + 0x70c4, again, 12)) return 0;
    for (u32 j = 0; j < 3; ++j) if (list[j] != again[j]) return 0;
    precap_notice(o, 42, pool, list[0], list[1], list[2], list[2], 0, 1);
    return 1;
}

static int precap_boundary_done(struct observer *o, struct ram_capture *r) {
    struct precap_state *s = o->extension;
    u32 queue[2], links[3], root, pools[3], images[3][18], addresses[3];
    if (!s) return 0;
    if (s->reason && s->count) {
        precap_retire_ring(o, s);
        connect_caller(o, &r->owners, 1);
    }
    int child_clean = !s->s2_cmd_active && (s->start.pid <= 0 || (s->start.done && s->start.reaped));
    if (s->state != PRECAP_DRAIN || !s->s2_up || !child_clean ||
        (s->s2_child_failed && !s->reason) || o->held_owned || s->count)
        return precap_blocked(o, 2, (s->state == PRECAP_DRAIN), s->s2_up, (u32)child_clean);
    /* Always require full-press released (full==0); allow half==1 after disarm/focus-abort/timeout or 3 s drain wait. */
    int allow_half_held = s->disarm_seen || s->hold_lost ||
                          ((s->reason == 4u || s->reason == 1u) && now() - s->stop_at >= 3000u) ||
                          (!!s->trigger_ms && now() - s->stop_at >= 3000u);
    u32 live_half = 0u, live_full = 0u;
    if (s->input.failed) {
        /* Recover cleanly from transient input read error ONLY via fresh verified live shutter read. */
        if (!s6_read_live_shutter(o, s, &live_half, &live_full))
            return precap_blocked(o, 3, 1u, s->input.entries[s->half].status, s->input.entries[s->full].status);
        s->input.entries[s->half].status = live_half;
        s->input.entries[s->full].status = live_full;
    } else {
        live_half = s->input.entries[s->half].status;
        live_full = s->input.entries[s->full].status;
    }
    if (live_full || (!allow_half_held && live_half))
        return precap_blocked(o, 3, s->input.failed, live_half, live_full);
    if (!s->released) return precap_blocked(o, 2, (s->state == PRECAP_DRAIN), s->released, s->start.done);
    if (!read_mem(o, r->owners.recorder.manager + 0x88, queue, 8) ||
        !read_mem(o, r->owners.recorder.manager + 4, links, 12)) return precap_blocked(o, 4, 1, 0, 0);
    if (queue[0] != queue[1]) return precap_blocked(o, 4, 2, queue[0], queue[1]);
    for (u32 i = 0; i < 3; ++i) {
        u32 desc[16], *image = images[i];
        if (!read_mem(o, links[i], desc, sizeof(desc)) || !read_mem(o, desc[3], image, sizeof(images[i])))
            return precap_blocked(o, 5 + i, 1, 0, 0);
        if (image[1] || image[3] || image[4] || (image[11] & 255))
            return precap_blocked(o, 5 + i, image[1], image[3], image[4] | ((image[11] & 255) << 24));
        addresses[i] = desc[3];
    }
    if (!read_mem(o, m7_config.bias + 0x1463800, &root, 4) || !read_mem(o, root, pools, 12)) return precap_blocked(o, 8, 1, 0, 0);
    for (u32 i = 0; i < 3; ++i) if (pools[i]) {
        u32 header[3], list[3], rest;
        if (!read_mem(o, pools[i], header, 12)) return precap_blocked(o, 8, 2, i, 0);
        if (header[2] != 0x4100) continue;
        if (!read_mem(o, pools[i] + 0x70c4, list, 12) || !read_mem(o, pools[i] + 0x71c8, &rest, 4)) return precap_blocked(o, 8, 3, i, 0);
        if ((header[1] & 255) || rest || !precap_pool_closed(o, s, pools[i], list))
            return precap_blocked(o, 8, header[1] & 255, list[2], rest);
    }
    s->drained = 1;
    u32 phase_before = o->phase; o->phase = 28;
    ram_words(o, 219, r->owners.recorder.manager + 0x88, queue, 2);
    for (u32 i = 0; i < 3; ++i) ram_words(o, 220 + i, addresses[i], images[i], 18);
    o->phase = phase_before;
    u32 expected_saved = s->pre_frozen + s->post;
    int post_ok = s6_post_satisfied(s);
    if (!!s->trigger_ms && !s->reason) {
        if (s->saved != expected_saved || !expected_saved) s->reason = 8u;
        else if (!post_ok) s->reason = 13u; /* Shortened fixed post window; all captured files saved & SD restored cleanly. */
    }
    s->blocked = 0; precap_notice(o, 5, s->drained, queue[0], queue[1], 0, 0, 0, 1); return 1;
}

static int stage6_session_topology(struct observer *o, struct start_owner *c, u32 sample, u32 mmgr) {
    u32 manager[4], config[21], desc[16], pin[7], peer[7] = {0}, wrapper[6], busy[2], size[5];
    int read = start_block(o, sample, 200, c->caller.manager, manager, 4) &&
        start_block(o, sample, 201, c->caller.manager + 0x30, config, 21) &&
        start_block(o, sample, 202, c->caller.manager + 0x69c8, busy, 2) &&
        start_block(o, sample, 203, c->caller.core + 0xfc, size, 5);
    if (read) read = start_block(o, sample, 204, manager[1], desc, 16);
    if (read) read = start_block(o, sample, 205, desc[9], pin, 7) &&
        start_block(o, sample, 207, desc[10], wrapper, 6);
    if (read && pin[4]) read = start_block(o, sample, 206, pin[4], peer, 7);
    if (!read || manager[0] != c->caller.core || desc[0] != c->caller.core ||
        desc[1] != c->caller.manager + 0x10 || desc[14] || (desc[15] & 0xffff) ||
        pin[0] != m7_config.mwf_bias + 0x42fa0 || pin[1] != 6 || pin[2] || pin[3] != 1 ||
        wrapper[0] != m7_config.bias + 0x13927f0 || wrapper[1] != desc[9] ||
        (wrapper[4] && !private_range(o, wrapper[4], 4)) || (wrapper[5] & 0xffffff) ||
        (busy[0] & 0xffffff00) || busy[1] || (size[0] & 255) != 1 || size[1]) return 0;
    u32 expected[21] = {0, 0, 1, 0x1000, 0x1000, mmgr, 0, 0x1000, 0x1000, mmgr, 0,
                        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0, 0, 0x1000, 0xffffffff, 1, 1};
    int detached = !pin[4] && desc[12] == 0xffffffff && desc[13] == 0xffffffff;
    u32 destination = 0;
    int stock = desc[12] == 0x4100 && !desc[13] && pin[4] &&
        start_block(o, sample, 208, c->remote + 0x54, &destination, 1) && destination == pin[4] &&
        peer[0] == pin[0] && peer[1] == 6 && peer[2] == 1 && !peer[3] && peer[4] == desc[9] &&
        wrapper[3] == destination;
    if (detached || stock) {
        const u32 positions[6] = {3, 4, 6, 7, 8, 10};
        for (u32 i = 0; i < 6; ++i) expected[positions[i]] = 0xffffffff;
        expected[20] = stock ? 0x101 : 0;
    } else if (desc[12] != 0x1000 || desc[13] != mmgr || !pin[4] || peer[0] != pin[0] ||
        peer[1] != 6 || peer[3] || peer[4] != desc[9] || wrapper[3] != pin[4]) return 0;
    for (u32 i = 0; i < 21; ++i) if (config[i] != expected[i]) return 0;
    return stock ? 3 : detached ? 2 : 1;
}

static int stage6_route_wait(struct observer *o, struct start_owner *c, u32 mmgr, u32 after_stop,
                             struct precap_state *ps, u32 *last_out) {
    /* Insert4100 transitions 1 (SD) -> 2 (DETACHED, ~250 ms) -> 3 (STOCK RAM 0x4100); require 2 consecutive want! */
    u32 want = after_stop ? 1u : 3u;
    u32 streak = 0u, last_seen = 0u;
    for (u32 i = 0; i < 30u; ++i) {
        if (!after_stop && ps) precap_check_still_holding(o, ps);
        u32 topology = stage6_session_topology(o, c, 300u + after_stop * 40u + i, mmgr);
        if (topology) last_seen = topology;
        streak = (topology == want) ? (streak + 1u) : 0u;
        session_notice(o, 5, after_stop, i, topology, streak, 0, 0, 0);
        if (streak >= 2u) {
            if (last_out) *last_out = want;
            return (int)want;
        }
        if (i + 1u < 30u) stage6_sleep_hold(o, after_stop ? 0 : ps, 100u, 0);
    }
    if (last_out) *last_out = last_seen;
    return 0; /* Exhausted without 2 consecutive want confirmations: fail closed! */
}

static __attribute__((noinline)) int s6_capture_trap_set(struct observer *o, struct capture_trap *trap,
                                                         u32 address, u32 expected_word) {
    u32 live, shift = (address & 2u) * 8u;
    if (trap->armed || !o->trace_tid || address < 0x10000u || address >= 0xc0000000u || (address & 1u)) {
        capture_trap_notice(o, trap, 90, 0, 1);
        return 0;
    }
    trap->address = address; trap->word = expected_word;
    trap->patched = (expected_word & ~(0xffffu << shift)) | (0xde01u << shift);
    if (trap->patched == expected_word || !capture_trap_word(o, address, &live) || live != expected_word) {
        capture_trap_notice(o, trap, 90, 0, 2);
        return 0;
    }
    s32 rc = s6_ptrace_retry(o, 4u, address & ~3u, trap->patched);
    trap->armed = 1;
    if (!capture_trap_word(o, address, &live)) retain_unresolved(o, 140, address);
    if (rc && live == expected_word) {
        trap->armed = 0;
        capture_trap_notice(o, trap, 90, (u32)rc, 3);
        return 0;
    }
    if (rc || live != trap->patched) retain_unresolved(o, 141, live);
    capture_trap_notice(o, trap, 10, 0, address & ~3u);
    return 1;
}

static __attribute__((noinline)) int s6_capture_trap_restore(struct observer *o, struct capture_trap *trap) {
    u32 live;
    if (!trap->armed) return 1;
    if (!capture_trap_word(o, trap->address, &live) || live != trap->patched)
        retain_unresolved(o, 142, trap->address);
    s32 rc = s6_ptrace_retry(o, 4u, trap->address & ~3u, trap->word);
    if (!capture_trap_word(o, trap->address, &live)) retain_unresolved(o, 143, trap->address);
    if (rc && live == trap->patched) {
        capture_trap_notice(o, trap, 90, (u32)rc, 4);
        return 0;
    }
    if (rc || live != trap->word) retain_unresolved(o, 144, live);
    trap->armed = 0;
    capture_trap_notice(o, trap, 12, 0, trap->address & ~3u);
    return 1;
}

static void s6_ram_restore_trap(struct observer *o, struct ram_capture *r) {
    if (!s6_capture_trap_restore(o, &r->trap)) retain_unresolved(o, 151, r->trap.address);
}

static void s6_ram_next_trap(struct observer *o, struct ram_capture *r, u32 va, u32 word) {
    s6_ram_restore_trap(o, r);
    if (!s6_capture_trap_set(o, &r->trap, m7_config.bias + va, word)) retain_unresolved(o, 152, va);
}

static void s6_ram_capture_complete(struct observer *o, struct ram_capture *r) {
    if (!ram_completion(o, r)) retain_unresolved(o, 163, 1);
    r->completion = 1;
    s6_ram_restore_trap(o, r);
}

static __attribute__((noinline)) void s6_burst_registers(struct observer *o, struct trace_context *t, u32 serial) {
    s32 prc = s6_ptrace_retry(o, 12u, 0u, (u32)t->original);
    if (prc != 0) retain_unresolved(o, 268u, (u32)prc);
    prc = s6_ptrace_retry(o, 27u, 0u, (u32)t->vfp);
    if (prc != 0) retain_unresolved(o, 269u, (u32)prc);
    for (u32 i = 0; i < 18u; ++i) t->work[i] = t->original[i];
    t->dirty = 0;
    burst_words(o, serial, 1, t->original, 18); burst_words(o, serial, 2, t->vfp, 65);
}

static __attribute__((noinline)) void s6_burst_unchanged(struct observer *o, struct trace_context *t, u32 serial) {
    u32 regs[18], vfp[65] __attribute__((aligned(8)));
    s32 prc = s6_ptrace_retry(o, 12u, 0u, (u32)regs);
    if (prc != 0) retain_unresolved(o, 270u, (u32)prc);
    prc = s6_ptrace_retry(o, 27u, 0u, (u32)vfp);
    if (prc != 0) retain_unresolved(o, 271u, (u32)prc);
    for (u32 i = 0; i < 18u; ++i) if (regs[i] != t->original[i]) retain_unresolved(o, 191, 3);
    for (u32 i = 0; i < 65u; ++i) if (vfp[i] != t->vfp[i]) retain_unresolved(o, 191, 4);
    burst_words(o, serial, 3, regs, 18); burst_words(o, serial, 4, vfp, 65);
}

static __attribute__((noinline)) void s6_burst_own_stop(struct observer *o, u32 serial, u32 helper) {
    u32 info[32] = {0};
    s32 prc = s6_ptrace_retry(o, 0x4202u, 0u, (u32)info);
    if (prc != 0) retain_unresolved(o, 272u, (u32)prc);
    burst_words(o, serial, 5, info, 32);
    if (info[0] != 19u || info[1] || info[2] != 0xfffffffau || info[3] != helper)
        retain_unresolved(o, 192, 2);
}

/* Fast, zero-spam trap wait & continue helpers for ObjStillRecorder (rec_tid),
 * routing all ptrace requests through s6_ptrace_retry with exact (stage, errno). */
static void s6_rec_wait_trap_fast(struct observer *o, struct ram_capture *r, u32 index) {
    struct trace_context *t = &r->owners.rec_trace;
    if (!r->trap.armed || !t->attached) {
        capture_trap_notice(o, &r->trap, 90, 0, 5);
        ram_timeout_snapshot(o, r, index, -1);
        retain_unresolved(o, 150, index);
    }
    u32 status = 0, started = now(), spins = 0;
    for (;;) {
        s32 waited = call(114, o->trace_tid, (u32)&status, 0x40000001, 0, 0, 0);
        if (waited == (s32)o->trace_tid) break;
        if (waited != 0 && waited != -4) {
            capture_trap_notice(o, &r->trap, 90, status, 6);
            retain_unresolved(o, 145, (u32)waited);
        }
        if (now() - started >= 15000u) {
            ram_timeout_snapshot(o, r, index, 0);
            retain_unresolved(o, 150, index);
        }
        if (spins < 256u) {
            ++spins;
            continue;
        }
        precap_sample(o);
        precap_wait(o, 1);
    }
    if (status != 0x057fu) {
        capture_trap_notice(o, &r->trap, 90, status, 6);
        retain_unresolved(o, 145, o->trace_tid);
    }
    {
        s32 prc = s6_ptrace_retry(o, 12u, 0u, (u32)t->original);
        if (prc != 0) retain_unresolved(o, 262u, (u32)prc);
        prc = s6_ptrace_retry(o, 27u, 0u, (u32)t->vfp);
        if (prc != 0) retain_unresolved(o, 263u, (u32)prc);
    }
    u32 live = 0;
    if (t->original[15] != r->trap.address || (t->original[16] & 0x3fu) != 0x30u ||
        !capture_trap_word(o, r->trap.address, &live) || live != r->trap.patched)
        retain_unresolved(o, 147, t->original[15]);
    for (u32 i = 0; i < 18u; ++i) t->work[i] = t->original[i];
    t->dirty = 0;
    capture_trap_notice(o, &r->trap, 11, status, t->original[16]);
    if (t->original[16] & 0x0600fc00u) retain_unresolved(o, 150, 10u + index);
}

static void s6_rec_continue_fast(struct observer *o, struct ram_capture *r, u32 index) {
    (void)index;
    struct trace_context *t = &r->owners.rec_trace;
    u32 checked[18], vfp[65] __attribute__((aligned(8)));
    s32 prc = s6_ptrace_retry(o, 13u, 0u, (u32)t->work);
    if (prc != 0) retain_unresolved(o, 264u, (u32)prc);
    prc = s6_ptrace_retry(o, 12u, 0u, (u32)checked);
    if (prc != 0) retain_unresolved(o, 265u, (u32)prc);
    prc = s6_ptrace_retry(o, 27u, 0u, (u32)vfp);
    if (prc != 0) retain_unresolved(o, 266u, (u32)prc);
    for (u32 i = 0; i < 18u; ++i) if (checked[i] != t->work[i]) retain_unresolved(o, 154, i);
    for (u32 i = 0; i < 65u; ++i) if (vfp[i] != t->vfp[i]) retain_unresolved(o, 155, i);
    for (u32 i = 0; i < 18u; ++i) t->original[i] = checked[i];
    t->dirty = 0;
    prc = s6_ptrace_retry(o, 7u, 0u, 0u);
    if (prc != 0) retain_unresolved(o, 267u, (u32)prc);
}

/* Stage 6 v3 boundary loop:
 * - While PRECAP_ARMED or PRECAP_POST: zero spurious SIGSTOPs interrupting ObjStillRecorder;
 *   crisp 5 ms wait4(WNOHANG) trap detection + async S2 cadence ticking.
 * - Once PRECAP_DRAIN: exact Stage 5 250 ms SIGSTOP idle/queue check + 2000 ms quiet drain
 *   and precap_boundary_done before restoring trap and detaching rec_tid.
 */
static int s6_burst_boundary(struct observer *o, struct ram_capture *r, struct capture_trap *next, u32 frame) {
    struct precap_state *ps = o->extension;
    struct trace_context *t = &r->owners.rec_trace;
    u32 previous = o->phase, started = now(), quiet_since = started, last = started;
    u32 serial = 0, pending = 0, streak = 0, diagnostics = 0, drain_seen = 0;
    u32 helper = (u32)call(20, 0, 0, 0, 0, 0, 0);
    if (!helper || helper >= 0x80000000u || helper == m7_config.pid) retain_unresolved(o, 192, 3);
    o->phase = 25;
    for (;;) {
        precap_sample(o);
        precap_tick(o, r);
        if (ps && ps->state == PRECAP_DRAIN && ps->released && !drain_seen) {
            drain_seen = 1u;
            quiet_since = now();
            last = quiet_since;
        }
        u32 status = 0;
        s32 waited = call(114, o->trace_tid, (u32)&status, 0x40000001, 0, 0, 0);
        if (waited == 0 || waited == -4) {
            if (ps && ps->state == PRECAP_DRAIN && !pending && now() - last >= 250u) {
                ++serial;
                if (call(268, m7_config.pid, o->trace_tid, 19, 0, 0, 0)) retain_unresolved(o, 192, 4);
                pending = 1u;
                burst_notice(o, 10, serial, helper, o->trace_tid, frame, now() - started, 0, 0);
            }
            if (ps && ps->state == PRECAP_DRAIN) precap_wait(o, 10u);
            else sleep_ms(5u);
            continue;
        }
        if (waited != (s32)o->trace_tid || (status != 0x057fu && status != 0x137fu))
            retain_unresolved(o, 193, status);
        if (status == 0x057fu) {
            s32 prc = s6_ptrace_retry(o, 12u, 0u, (u32)t->original);
            if (prc != 0) retain_unresolved(o, 268u, (u32)prc);
            prc = s6_ptrace_retry(o, 27u, 0u, (u32)t->vfp);
            if (prc != 0) retain_unresolved(o, 269u, (u32)prc);
            for (u32 i = 0; i < 18u; ++i) t->work[i] = t->original[i];
            t->dirty = 0;
            u32 live = 0;
            if (t->original[15] != next->address || (t->original[16] & 0x3fu) != 0x30u ||
                (t->original[16] & 0x0600fc00u) || !capture_trap_word(o, next->address, &live) || live != next->patched)
                retain_unresolved(o, 193, 2);
            if (pending) {
                prc = s6_ptrace_retry(o, 7u, 0u, 0u);
                if (prc != 0) retain_unresolved(o, 273u, (u32)prc);
                u32 until = now();
                do {
                    precap_sample(o);
                    waited = call(114, o->trace_tid, (u32)&status, 0x40000001, 0, 0, 0);
                    if (waited == 0 || waited == -4) precap_wait(o, 5);
                    else break;
                } while (now() - until < 1000u);
                if (waited != (s32)o->trace_tid || status != 0x137fu) retain_unresolved(o, 192, 6);
                s6_burst_own_stop(o, serial, helper); s6_burst_unchanged(o, t, serial); pending = 0;
            }
            r->ready_ms = now() - o->started;
            precap_flush_ready(o, r);
            o->phase = previous;
            return 1;
        }
        if (!pending) retain_unresolved(o, 192, 7);
        s6_burst_registers(o, t, serial);
        s6_burst_own_stop(o, serial, helper); pending = 0;
        int idle = (t->original[16] & 0x0100021fu) == 0x10u && !(t->original[13] & 7u) &&
            private_range(o, t->original[13], 136) &&
            create_idle(o, t, &r->owners.recorder) && connect_queues(o, &r->owners, 4, 1);
        streak = idle ? streak + 1u : 0u;
        if (!idle) precap_blocked(o, 1, serial, t->original[15], t->original[17]);
        if (!idle && (!diagnostics || (diagnostics == 1u && now() - started >= 14000u))) {
            burst_wait_diagnostics(o, r, serial); ++diagnostics;
        }
        s6_burst_unchanged(o, t, serial);
        precap_flush_ready(o, r);
        burst_notice(o, 12, serial, 0, frame, idle, streak, now() - quiet_since, 0);
        if (streak >= 2u && drain_seen && (u32)(now() - quiet_since) >= RAM_BURST_QUIET_MS &&
            precap_boundary_done(o, r)) {
            if (!s6_capture_trap_restore(o, next)) retain_unresolved(o, 194, 1);
            o->phase = previous;
            s6_trace_restore(o, t);
            burst_notice(o, 5, frame, 0, streak, now() - quiet_since, 0, 0, 0);
            return 0;
        }
        {
            s32 prc = s6_ptrace_retry(o, 7u, 0u, 0u);
            if (prc != 0) retain_unresolved(o, 274u, (u32)prc);
        }
        last = now();
    }
}

/* Handle one frame arriving at Trap #1 (0xa14c98):
 * - Unselected frames take the ARM-verified fast drop path: Trap #1 -> 0xa153d2 -> Trap #2 (0xa146f6, r1=frame+0x2938)
 *   -> directly re-arm Trap #1 (skipping ram_candidate, hold_acquire, Trap #3, and 40-packet diagnostic flood!).
 * - Selected frames run full ram_candidate + single-slot H-2 guard + hold_acquire + Trap #2 + Trap #3 + fast save.
 */
static void s6_handle_frame(struct observer *o, struct ram_capture *r, struct precap_state *ps) {
    struct connect_owner *c = &r->owners;
    u32 *regs = c->rec_trace.original, flags[2], info[13], head[4], uids[3], sflags = 0;
    r->image_ready = 1;
    if (!read_mem(o, c->recorder.core + 0x1cc, flags, 8) || flags[0] != 0x200u)
        retain_unresolved(o, 218, 12);
    r->mask = flags[0];
    if (regs[15] != m7_config.bias + 0xa14c98u || regs[0] || regs[4] != c->recorder.core ||
        regs[13] != regs[7] - 0x88u || !private_range(o, regs[7], 0x29b0u) ||
        !read_mem(o, regs[5], info, 52) || !ram_same_tuple(info, info[11], 0) ||
        !read_mem(o, regs[7], head, 16) || head[1] != c->recorder.slot ||
        !read_mem(o, regs[7] + 0x2938u, uids, 12) || uids[c->recorder.slot] != head[3] ||
        !read_mem(o, regs[7] + 0x29acu, &sflags, 4) || (sflags & 0xffffffu) != 0x000101u)
        retain_unresolved(o, 196, 1);

    r->capture = info[11];
    r->info = regs[5];
    r->frame = regs[7];
    r->uid = head[3];

    /* Synchronize announced IDs up to this exact instant before deciding drop vs keep! */
    precap_backlog(o, ps, 1);
    precap_sample(o);
    u32 role_here = precap_role(ps, r->capture);
    /* Only decline with reason=14 when an actual selected frame still awaits saving past the budget! */
    if (role_here != 0u && ps->state == PRECAP_DRAIN && !ps->reason &&
        (u32)(now() - ps->stop_at) >= S6_SAVE_BUDGET_MS) {
        ps->reason = 14u;
        if (!ps->post_cutoff_cause) ps->post_cutoff_cause = 6u;
        precap_notice(o, 28, 14, ps->delivered + 1u, ps->saved, now() - ps->stop_at, S6_SAVE_BUDGET_MS, 0, 0);
    }
    if (ps->reason && ps->count) precap_retire_ring(o, ps);

    int keep = (!ps->reason && role_here != 0u);
    if (!keep) {
        /* FAST UNSELECTED DROP PATH (~1-3 ms dwell): skip ram_candidate, hold_acquire, and Trap #3! */
        connect_caller(o, c, 1); o->phase = 19;
        s6_ram_next_trap(o, r, 0xa146f6u, 0xf0069602u);
        c->rec_trace.work[6] = 0u;
        c->rec_trace.work[15] = m7_config.bias + 0xa153d2u;
        s6_rec_continue_fast(o, r, 2);

        s6_rec_wait_trap_fast(o, r, 3);
        regs = c->rec_trace.original;
        if (regs[0] != c->recorder.manager || regs[2] != 1u || regs[3] != r->info ||
            !read_mem(o, r->frame + 0x2938u, uids, 12) || uids[c->recorder.slot] != r->uid)
            retain_unresolved(o, 162, 1);
        c->rec_trace.work[1] = r->frame + 0x2938u;
        /* Restore Trap #2 and re-arm Trap #1 (0xa14c98) directly (0xa126d8 has zero mutations!). */
        s6_ram_next_trap(o, r, 0xa14c98u, 0x531ef240u);
        s6_rec_continue_fast(o, r, 3);

        ++ps->delivered;
        ++ps->fast_drops;
        u32 continued_at = now() - o->started;
        precap_notice_at(o, continued_at, 50, ps->delivered, r->capture, r->ready_ms, continued_at, 1u, ps->queue, ps->saved);
        return;
    }

    /* SELECTED FRAME PATH: enforce H-2 single-slot cap (held_owned <= 1) BEFORE hold_acquire! */
    if (ps->count >= 1u) {
        if (ps->state == PRECAP_DRAIN && ps->released) {
            precap_retire_ring(o, ps);
        } else if (ps->state == PRECAP_ARMED) {
            u32 ev_cap = ps->frames[0].capture;
            precap_remove(o, ps, 3);
            s6_drop_id(ps, ev_cap);
        } else if (ps->state == PRECAP_POST) {
            ps->post_limit_hit = 1u;
            if (!ps->post_cutoff_cause) ps->post_cutoff_cause = 3u;
            precap_request_stop(o, ps);
            if (!ps->released) {
                precap_stop(o, ps, 0);
                if (!ps->s2_up) retain_unresolved(o, 218, 1);
            }
            precap_retire_ring(o, ps);
        }
        connect_caller(o, c, 1); o->phase = 19;
    }

    u32 candidate[8];
    int cand_ok = 0;
    for (u32 attempt = 0u; attempt < 8u; ++attempt) {
        if (ram_candidate(o, r, candidate)) { cand_ok = 1; break; }
        if (attempt + 1u < 8u) {
            sleep_ms(5);
            precap_sample(o);
        }
    }
    if (!cand_ok) retain_unresolved(o, 161, 1);
    for (u32 i = 0; i < 3u; ++i) if (o->owners[i].owned &&
        (o->owners[i].candidate[3] == candidate[3] ||
         (o->owners[i].candidate[1] == candidate[1] && o->owners[i].candidate[4] == candidate[4])))
        retain_unresolved(o, 161, 2);

    ram_monitor(o);
    int acq_ok = s6_hold_acquire(o, candidate);
    if (!acq_ok || !o->held_owned) retain_unresolved(o, 161, 3);
    r->users = candidate[7] + 1u;
    connect_caller(o, c, 1); o->phase = 19;
    ram_notice(o, 3, r->capture, r->uid, candidate[1], candidate[3], 0, 0, 0);

    /* Redirect to 0xa153d2 -> Trap #2 (0xa146f6) -> Trap #3 (0xa126d8) with fast wait! */
    s6_ram_next_trap(o, r, 0xa146f6u, 0xf0069602u);
    c->rec_trace.work[6] = 0u;
    c->rec_trace.work[15] = m7_config.bias + 0xa153d2u;
    s6_rec_continue_fast(o, r, 2);

    s6_rec_wait_trap_fast(o, r, 3);
    regs = c->rec_trace.original;
    if (regs[0] != c->recorder.manager || regs[2] != 1u || regs[3] != r->info ||
        !read_mem(o, r->frame + 0x2938u, uids, 12) || uids[c->recorder.slot] != r->uid)
        retain_unresolved(o, 162, 1);
    c->rec_trace.work[1] = r->frame + 0x2938u;
    s6_ram_next_trap(o, r, 0xa126d8u, 0x00f0f8d5u);
    s6_rec_continue_fast(o, r, 3);

    s6_rec_wait_trap_fast(o, r, 4);
    s6_ram_capture_complete(o, r);

    struct precap_frame f = {.ordinal = ++ps->delivered, .capture = r->capture, .uid = r->uid, .ready_ms = r->ready_ms};
    for (u32 i = 0; i < 8u; ++i) f.owner.candidate[i] = o->held_candidate[i];
    f.owner.owned = o->held_owned; o->held_owned = 0;
    if (f.owner.owned != 1u) retain_unresolved(o, 218, 13);
    precap_notice(o, 3, f.ordinal, f.capture, f.uid, 0, f.owner.owned, f.ready_ms, 0);

    precap_sample(o);
    if (ps->reason && ps->count) precap_retire_ring(o, ps);
    u32 role = precap_role(ps, f.capture);
    if (ps->reason || !role) {
        precap_release_source(o, &f);
    } else {
        if (ps->count >= PRECAP_MAX_HELD) retain_unresolved(o, 218, 13);
        f.role = role;
        ps->frames[ps->count++] = f;
        precap_notice(o, 19, f.ordinal, f.capture, f.uid, ps->count, ps->capacity, 0, 0);
    }
    precap_sample(o);
    if (ps->state == PRECAP_DRAIN && ps->released) precap_retire_ring(o, ps);
    precap_sample(o);
    connect_caller(o, c, 1); o->phase = 19;
    if (!s6_capture_trap_set(o, &r->trap, m7_config.bias + 0xa14c98u, 0x531ef240u)) retain_unresolved(o, 218, 14);
    s6_rec_continue_fast(o, r, 4);
    u32 continued_at = now() - o->started;
    precap_notice_at(o, continued_at, 50, ps->delivered, r->capture, r->ready_ms, continued_at, 0u, ps->queue, ps->saved);
}

/*
 * Zero-gap lazy-armed stock capture:
 * - Waits up to 2000 ms for Sony's Insert4100 transient sub_en=0 dip (~930 ms) to settle back to sub_en=1
 *   while verifying half==1 && full==0 && !disarm BEFORE mode_set(0x4100).
 * - After mode_drain(3, 1) returns WITH connect_pair(3) STILL HELD, checks
 *   half==1 && full==0 && !disarm && ram_precondition and immediately arms the
 *   0xde01 trap WITHOUT releasing rec_tid! If aborted before trap, restores SD
 *   immediately using the already-held connect_pair(3).
 */
static int stage6_session_stock_capture(struct observer *o, struct start_owner *st, struct precap_state *ps) {
    struct connect_owner c = {0};
    struct ram_capture r = {0};
    u32 previous = o->phase, manager[4], desc[16], busy, remote[14];
    int captured = 0;
    c.ram_only = 1; c.stock_connection = 1;
    o->phase = 18;
    connect_notice(o, 8, m7_config.bias, m7_config.mwf_bias, m7_config.mprctrl_bias, m7_config.pid, 0, 0, 0);

    /* Wait for Insert4100's transient sub_en=0 dip to recover while enforcing hold + disarm + strict 2000 ms monotonic bound. */
    int sub_ready = 0;
    u32 wait_start = 0u;
    if (s6_now_ms_checked(&wait_start) && wait_start != 0u) {
        u32 prev_t = wait_start;
        for (u32 step = 0u; step < 80u; ++step) {
            if (!precap_check_still_holding(o, ps)) {
                session_notice(o, 90, 2, ps->disarm_seen, 0, 0, 0, 0, 0);
                o->phase = previous;
                return 1; /* Clean pre-mode_set abort; caller still runs Pullout4100. */
            }
            u32 t_before = 0u;
            if (!s6_now_ms_checked(&t_before) || t_before == 0u ||
                (u32)(t_before - wait_start) >= 2000u ||
                (u32)(t_before - prev_t) >= 2000u ||
                (step > 0u && t_before == prev_t)) break;
            prev_t = t_before;
            if (subscription(o, 0, 0)) {
                u32 t_after = 0u;
                if (!s6_now_ms_checked(&t_after) || t_after == 0u ||
                    (u32)(t_after - wait_start) >= 2000u ||
                    (u32)(t_after - prev_t) >= 2000u) break;
                if (!precap_check_still_holding(o, ps)) {
                    session_notice(o, 90, 2, ps->disarm_seen, 0, 0, 0, 0, 0);
                    o->phase = previous;
                    return 1;
                }
                sub_ready = 1;
                break;
            }
            if (step + 1u < 80u) sleep_ms(25);
        }
    }
    if (!sub_ready) {
        o->extension = 0;
        session_notice(o, 90, 2, ps->disarm_seen, o->route[0], o->route[7], 0, 0, 0);
        o->phase = previous;
        return 1; /* Clean pre-mode_set abort (e.g. user entered Menu during Insert4100). */
    }
    ps->prearm_check_sub = 1u;
    if (!read_mem(o, st->caller.manager, manager, sizeof(manager)) ||
        !read_mem(o, manager[1], desc, sizeof(desc))) retain_unresolved(o, 187, 1);
    c.source = desc[9];
    if (c.source != st->recording_peer || !connect_discover(o, &c) ||
        c.recorder.core != st->caller.core || c.remote.core != st->remote ||
        c.rec_tid != o->trace_tid || c.remote_tid != st->remote_tid) retain_unresolved(o, 187, 2);
    c.recorder.slot = 0; c.recorder.descriptor = manager[1]; c.recorder.resource = desc[6];
    c.wrapper = desc[10]; c.ordinary = manager[1];
    if (!connect_block(o, 20, c.recorder.manager + 0x30, c.config_before, 15) ||
        !connect_block(o, 21, c.wrapper, c.wrapper_before, 6) ||
        !connect_block(o, 22, c.ordinary, c.ordinary_before, 16)) retain_unresolved(o, 187, 3);
    connect_notice(o, 0, c.recorder.core, c.recorder.manager, c.remote.core, c.rec_tid, c.remote_tid, 0, CONNECT_ATTEMPTS);
    session_notice(o, 6, c.recorder.descriptor, c.source, c.destination, c.wrapper, c.wrapper_before[4], 0, 0);

    o->phase = 20;
    mode_notice(o, 0, c.recorder.core, c.recorder.manager, c.remote.core, c.rec_tid, c.remote_tid, m7_config.bias, m7_config.mwf_bias);
    if (!stage6_connect_pair(o, &c, 3, ps, 1)) {
        /* Recorder busy or hold/subscription lost before mode_set: clean abort without mutating mode! */
        o->extension = 0;
        session_notice(o, 90, 3, ps->hold_lost, ps->disarm_seen, 0, 0, 0, 0);
        o->phase = previous;
        return 1;
    }
    if (!mode_snapshot(o, &c, 1, c.mode_before, &busy, remote)) {
        o->extension = 0;
        s6_connect_release(o, &c);
        retain_unresolved(o, 187, 4);
    }
    int mode_ok = 1;
    for (u32 i = 0; i < 15; ++i) if (c.mode_before[i] != c.config_before[i]) mode_ok = 0;
    if (c.mode_before[15] || c.mode_before[16] || c.mode_before[17] != 0x1000 ||
        c.mode_before[18] != 0xffffffff || c.mode_before[19] != 1 || c.mode_before[20] != 0x101 ||
        busy || remote[0] != 1 || remote[1] || remote[2] != 1 || remote[13] == 1) mode_ok = 0;
    if (!mode_ok || !precap_check_still_holding(o, ps) || !subscription(o, 0, 0)) {
        o->extension = 0;
        s6_connect_release(o, &c);
        session_notice(o, 90, 4, mode_ok, ps->disarm_seen, 0, 0, 0, 0);
        o->phase = previous;
        return 1; /* Clean pre-mode_set abort; Pullout4100 restores SD cleanly. */
    }

    const u32 ram[4] = {0, 0x4100, 0xffffffff, 1};
    s6_mode_set(o, &c, 2, ram);
    if (!stage6_mode_drain_ram(o, &c, 3, ps)) retain_unresolved(o, 187, 7);

    /* connect_pair(3) is ALREADY HELD here (rec_tid & remote_tid stopped & idle)! */
    o->extension = ps;
    o->phase = 28;
    precap_notice(o, 0, m7_precap_config.before, m7_precap_config.after, PRECAP_SLOTS,
                  m7_precap_config.window_ms, m7_precap_config.drain_ms, m7_precap_config.backlog_cap, 7);
    precap_memory(o, ps);
    precap_notice(o, 12, 0x1f1, 0xa7, ps->half, ps->full, 0, 0, 0);

    r.owners = c;
    o->phase = 19;
    ram_notice(o, 0, m7_config.bias, c.rec_tid, c.remote_tid, m7_config.monitor_tid, c.recorder.core, c.recorder.manager, 0);

    int armed_trap = 0;
    if (precap_check_still_holding(o, ps) && subscription(o, 0, 0) && !o->held_owned &&
        ram_precondition(o, &r) && precap_check_still_holding(o, ps) && subscription(o, 0, 0)) {
        ram_notice(o, 1, c.source, c.destination, r.image, r.mask, r.grouping, c.rec_tid, c.remote_tid);
        o->phase = 25;
        burst_notice(o, 4, 0, 1, m7_config.bias + 0xa14c98, 0, 0, 0, 0);
        if (precap_check_still_holding(o, ps) && subscription(o, 0, 0)) {
            armed_trap = s6_capture_trap_set(o, &r.trap, m7_config.bias + 0xa14c98, 0x531ef240);
            if (armed_trap && (!precap_check_still_holding(o, ps) || !subscription(o, 0, 0))) {
                /* Loss present immediately after trap write while both threads remain stopped: unwind trap with zero S1! */
                if (!s6_capture_trap_restore(o, &r.trap)) retain_unresolved(o, 194, 1);
                armed_trap = 0;
            }
        }
    }

    if (!armed_trap) {
        /* Clean zero-gap abort: trap is NOT installed; connect_pair(3) is still held! */
        o->extension = 0;
        session_notice(o, 90, 5, ps->disarm_seen, ps->hold_lost, 0, 0, 0, 0);
        c = r.owners;
        connect_caller(o, &c, 1);
        o->phase = 20;
        const u32 sd[4] = {0, 0x1000, 0xffffffff, 1};
        s6_mode_set(o, &c, 4, sd);
        s6_mode_drain(o, &c, 5, 0);
        s6_connect_release(o, &c);
        mode_notice(o, 6, 1, c.mode_applied, 0, 0, 0, 0, 0);
        o->phase = previous;
        return 1;
    }

    o->phase = 19;
    connect_caller(o, &r.owners, 2); s6_trace_restore(o, &r.owners.remote_trace);
    connect_caller(o, &r.owners, 1);
    s32 crc = -3;
    for (u32 attempt = 0u; attempt <= 32u; ++attempt) {
        if (!precap_check_still_holding(o, ps) || !subscription(o, 0, 0)) {
            /* Loss present after remote-owner detach while rec_tid is STILL stopped: unwind trap with zero S1-down! */
            o->extension = 0;
            if (!s6_capture_trap_restore(o, &r.trap)) retain_unresolved(o, 194, 1);
            s6_trace_restore(o, &r.owners.rec_trace);
            session_notice(o, 90, 5, ps->disarm_seen, ps->hold_lost, 1, 0, 0, 0);
            c = r.owners;
            o->phase = 20;
            if (!s6_connect_pair(o, &c, 3)) retain_unresolved(o, 187, 8);
            const u32 sd[4] = {0, 0x1000, 0xffffffff, 1};
            s6_mode_set(o, &c, 4, sd);
            s6_mode_drain(o, &c, 5, 0);
            s6_connect_release(o, &c);
            mode_notice(o, 6, 1, c.mode_applied, 0, 0, 0, 0, 0);
            o->phase = previous;
            return 1;
        }
        crc = s6_ptrace_retry_n(o, 7u, 0u, 0u, 0u);
        if (crc == 0 || crc != -3 || attempt == 32u) break;
        sleep_ms(1);
    }
    if (crc != 0 || !sender(o, 1, 1)) retain_unresolved(o, 218, 10);
    {
        u32 f_start = now(), f_loops = 0u;
        do {
            precap_sample(o);
            if (ps->hold_lost) break;
            sleep_ms(m7_config.interval_ms);
        } while ((u32)(now() - f_start) < m7_config.focus_ms && ++f_loops < m7_config.focus_ms + 2u);
    }

    ps->started = now(); ps->disarm_checked_ms = ps->started;
    ps->manager = c.recorder.manager;
    ps->core = c.recorder.core; ps->descriptor = c.recorder.descriptor;
    ps->start.done = 1; ps->start.status = 0; ps->s2_up = 1; ps->s2_down = 0; ps->s2_cmd_active = 0;
    ps->phase_burst = 1u;
    o->shutter_abort = precap_abort; o->shutter_state = &ps->start; r.shots = 1;

    int focus_abort = 0;
    if (ps->hold_lost || !precap_check_still_holding(o, ps) || !subscription(o, 0, 0)) {
        /* Hold, disarm, or subscription lost during focus wait: never enter PRECAP_ARMED; release S1 and drain/restore! */
        focus_abort = 1;
        ps->hold_lost = 1u;
        ps->reason = 4u;
        ps->state = PRECAP_DRAIN;
        ps->stop_at = ps->started;
        if (!sender(o, 1, 0)) retain_unresolved(o, 218, 1);
        ps->s1_up = 1u;
        ps->released = 1u;
        session_notice(o, 90, 8, ps->disarm_seen, ps->hold_lost, 0, 0, 0, 0);
    } else {
        precap_transition(o, ps, PRECAP_ARMED, ps->started - o->started);
        precap_input_notice(o, ps, ps->started - o->started);
        precap_hold_notice(o, ps, 0);
    }

    for (;;) {
        precap_sample(o);
        if (ps->reason && ps->count) precap_retire_ring(o, ps);
        connect_caller(o, &r.owners, 1); o->phase = 19;

        int more = s6_burst_boundary(o, &r, &r.trap, ps->delivered + 1);
        if (!more) break;
        s6_handle_frame(o, &r, ps);
    }

    precap_backlog(o, ps, 0);
    if (!focus_abort) precap_transition(o, ps, PRECAP_RESTORE, now() - o->started);
    precap_notice(o, 58, ps->input_serial, o->dropped, o->io_errors, ps->armed_at, ps->armed_end, ps->announced, ps->delivered);
    precap_notice(o, 60, ps->diagnostic_errors, 0, 0, 0, 0, 0, 0);
    if (!ps->drained || r.trap.armed || o->held_owned) retain_unresolved(o, 218, 15);
    precap_notice(o, 7, 1, 0, 0, 0, 0, 0, 0);
    precap_retire_ring(o, ps);
    if (ps->count || o->held_owned) retain_unresolved(o, 218, 15);
    u32 expected_saved = ps->pre_frozen + ps->post;
    int post_ok = s6_post_satisfied(ps);
    int saved = !ps->reason && (ps->trigger_ms != 0u) && post_ok && ps->saved == expected_saved;
    precap_notice(o, 8, saved, ps->delivered, ps->evicted, ps->saved, ps->reason, ps->drained, ps->post_cutoff_cause);
    precap_notice(o, 62, ps->pulses, ps->fast_drops, ps->queue_peak, ps->save_ms_total,
                  ps->pre_frozen, ps->post, (m7_precap_config.after << 16) | (ps->post_cutoff_cause & 0xffffu));
    o->phase = 19; ram_notice(o, 9, 1, ps->reason, 1, 0, 1, ps->released, 1);
    o->shutter_abort = 0; o->shutter_state = 0; o->extension = 0;
    captured = 1;

    /* Sync detached trace state back into c before restoring SD mode. */
    c = r.owners;
    o->phase = 20;
    if (!s6_connect_pair(o, &c, 3)) retain_unresolved(o, 187, 8);
    const u32 sd[4] = {0, 0x1000, 0xffffffff, 1};
    s6_mode_set(o, &c, 4, sd);
    s6_mode_drain(o, &c, 5, 0);
    s6_connect_release(o, &c);
    mode_notice(o, 6, 1, c.mode_applied, 0, 0, 0, 0, 0);
    o->phase = previous;
    return captured;
}

static int stage6_load_runtime_cfg(void) {
    char nonce_boot[S6_NONCE_LEN];
    for (u32 i = 0; i < S6_NONCE_LEN; ++i) nonce_boot[i] = m7_s6_ring_boot.nonce[i];
    if (m7_s6_ring_boot.magic != S6_RING_BOOT_MAGIC ||
        m7_s6_ring_boot.version != S6_RING_BOOT_VERSION ||
        !s6_valid_nonce_chars(nonce_boot) ||
        !m7_s6_ring_boot.rw_vaddr || (m7_s6_ring_boot.rw_vaddr & 4095u) ||
        !m7_s6_ring_boot.rw_size || (m7_s6_ring_boot.rw_size & 4095u)) {
        return 0;
    }

    char cfg_path[64];
    s6_build_path(cfg_path, sizeof(cfg_path), "/run.cfg");
    s32 fd = call(5, (u32)cfg_path, 0, 0, 0, 0, 0);
    if (fd < 0) return 0;

    struct s6_ring_cfg_file file;
    unsigned char *dst = (unsigned char *)&file;
    u32 got = 0, total = (u32)sizeof(file);
    while (got < total) {
        s32 n = call(3, (u32)fd, (u32)(dst + got), total - got, 0, 0, 0);
        if (n == -4) continue;
        if (n <= 0 || (u32)n > total - got) break;
        got += (u32)n;
    }
    unsigned char extra = 0;
    s32 trailing = (got == total) ? call(3, (u32)fd, (u32)&extra, 1u, 0, 0, 0) : 1;
    call(6, (u32)fd, 0, 0, 0, 0, 0);
    if (got != total || trailing != 0) return 0;

    if (file.magic != S6_RING_CFG_MAGIC || file.version != S6_RING_CFG_VERSION ||
        file.total_bytes != total || file.checksum != s6_ring_cfg_checksum(&file)) {
        return 0;
    }
    for (u32 i = 0; i < S6_NONCE_LEN; ++i) if (file.nonce[i] != nonce_boot[i]) return 0;

    /* Verify m7_config and m7_precap_config lie strictly inside PT_LOAD[1] before writing. */
    u32 cfg_a = (u32)&m7_config, pre_a = (u32)&m7_precap_config;
    u32 rw_s = m7_s6_ring_boot.rw_vaddr, rw_e = rw_s + m7_s6_ring_boot.rw_size;
    if (rw_e <= rw_s || cfg_a < rw_s || cfg_a + sizeof(m7_config) > rw_e ||
        pre_a < rw_s || pre_a + sizeof(m7_precap_config) > rw_e) {
        return 0;
    }

    __aeabi_memcpy((void *)&m7_config, &file.cfg, sizeof(m7_config));
    __aeabi_memcpy((void *)&m7_precap_config, &file.precap, sizeof(m7_precap_config));

    /* Full RELRO: lock PT_LOAD[1] read-only (PROT_READ=1) before touching im.elf. */
    if (call(125 /* SYS_MPROTECT */, rw_s, m7_s6_ring_boot.rw_size, 1u, 0, 0, 0) != 0) {
        return 0;
    }
    return 1;
}

int probe_main(void) {
    /* Silence unused Stage 5 static helpers from unmodified includes. */
    (void)retain_roundtrip;
    (void)session_continuous_frames;
    (void)media_connect_run;
    (void)media_config_roundtrip;
    (void)session_stop_checkpoint;
    (void)session_pin_checkpoint;
    (void)session_stop_diagnostics;
    (void)source_s1;
    (void)wake_for_subscription;
    (void)wait_for_subscription;
    (void)capture;
    (void)ring_run;
    (void)media_run;
    (void)media_route_run;
    (void)media_create_run;
    (void)receiver_run;
    (void)hold_measure;
    (void)hold_finish;
    (void)hold_release;
    (void)hold_hash;
    (void)hold_acquire;
    (void)hold_lock;
    (void)hold_unlock;
    (void)try_lock;
    (void)unlock_owned;
    (void)sony_call4;
    (void)sony_call;
    (void)trace_begin;
    (void)trace_restore;
    (void)commit_scratch;
    (void)commit_sd_drive;
    (void)commit_open;
    (void)commit_close;
    (void)commit_write;
    (void)commit_result;
    (void)commit_notice;
    (void)create_cancel_state;
    (void)create_restore_cancel;
    (void)connect_release;
    (void)connect_pair;
    (void)mode_set;
    (void)mode_drain;
    (void)start_command;
    (void)capture_trap_set;
    (void)capture_trap_restore;
    (void)ram_restore_trap;
    (void)ram_next_trap;
    (void)ram_capture_complete;
    (void)burst_registers;
    (void)burst_own_stop;
    (void)burst_unchanged;
    (void)burst_boundary;
    (void)burst_ready_image;
    (void)ram_capture_body;
    (void)precap_admission_idle;
    (void)precap_keep_source;
    (void)sd_start_poll;
    (void)observe;

    if (!stage6_load_runtime_cfg()) return 2;

    if (m7_precap_config.magic != 0x32525043 || m7_precap_config.revision != 8 ||
        !m7_precap_config.before || m7_precap_config.before > 15 ||
        m7_precap_config.after > 64 ||
        m7_precap_config.burst_cap < 8 || m7_precap_config.burst_cap > 60 ||
        m7_precap_config.burst_cap < m7_precap_config.before + 4 ||
        m7_precap_config.backlog_cap < 24 || m7_precap_config.backlog_cap > 128 ||
        m7_precap_config.backlog_cap < m7_precap_config.burst_cap + 16 ||
        m7_precap_config.post_max < 1 || m7_precap_config.post_max > 96 ||
        m7_precap_config.before + m7_precap_config.post_max > 112 ||
        m7_precap_config.sample_ms != 25 ||
        m7_precap_config.window_ms != 120000 ||
        m7_precap_config.drain_ms != 5000) return 2;

    if (m7_config.magic != 0x3143504d || m7_config.version != 6 || !m7_config.token ||
        !m7_config.pid || m7_config.pid >= 0x80000000 || m7_config.retain_check != 11 ||
        m7_config.diagnose_only ||
        m7_config.mpr_bias < 0x10000 || m7_config.mpr_bias > 0xbe000000 || (m7_config.mpr_bias & 4095) ||
        m7_config.bias < 0x10000 || m7_config.bias > 0xbe000000 || (m7_config.bias & 4095) ||
        m7_config.mwf_bias < 0x10000 || m7_config.mwf_bias > 0xbe000000 || (m7_config.mwf_bias & 4095) ||
        m7_config.mprctrl_bias < 0x10000 || m7_config.mprctrl_bias > 0xbe000000 || (m7_config.mprctrl_bias & 4095) ||
        !m7_config.nranges || m7_config.nranges > MAX_RANGES || !m7_config.monitor_tid ||
        m7_config.monitor_tid >= 0x80000000 || m7_config.monitor_tid == m7_config.pid ||
        !m7_config.interval_ms || m7_config.interval_ms > 20 ||
        m7_config.focus_ms < 100 || m7_config.focus_ms > 1500 ||
        m7_config.settle_ms < 100 || m7_config.settle_ms > 3000) return 2;
    for (u32 i = 0; i < m7_config.nranges; ++i) {
        if (m7_config.ranges[i].start < 0x10000 || m7_config.ranges[i].end > 0xc0000000 ||
            m7_config.ranges[i].start >= m7_config.ranges[i].end) return 2;
    }

    u32 action[5] = {1, 0, 0, 0, 0};
    u32 sigmask[2] = {(1u << 1) | (1u << 14), 0u};
    if (call(174, 13, (u32)action, 0, 8, 0, 0) ||
        call(174, 1, (u32)action, 0, 8, 0, 0) ||
        call(175 /* SYS_RT_SIGPROCMASK */, 0u /* SIG_BLOCK */, (u32)sigmask, 0, 8u, 0, 0)) return 3;

    /* Allocate observer + precap_state via mmap2 to keep stack usage tiny and clean. */
    u32 arena_sz = (sizeof(struct observer) + sizeof(struct precap_state) + 4095u) & ~4095u;
    s32 arena = call(192, 0u, arena_sz, 3u, 0x22u, 0xffffffffu, 0u);
    if ((u32)arena >= 0xfffff000u) return 4;
    struct observer *op = (struct observer *)(u32)arena;
    struct precap_state *ps = (struct precap_state *)((u32)arena + sizeof(struct observer));
    __aeabi_memclr8(op, sizeof(*op));
    __aeabi_memclr8(ps, sizeof(*ps));
    s6_build_path(ps->stop_path, sizeof(ps->stop_path), "/stop");
    s6_build_path(ps->disarm_path, sizeof(ps->disarm_path), "/disarm");

    op->started = now();
    if (!op->started) { call(91, (u32)arena, arena_sz, 0, 0, 0, 0); return 4; }
    char path[32]; proc_path(path, 0);
    op->fd = call(5, (u32)path, 0, 0, 0, 0, 0);
    if (op->fd < 0) { call(91, (u32)arena, arena_sz, 0, 0, 0, 0); return 5; }

    struct start_owner c = {0};
    c.allow_connected = 1;
    op->caller_kind = 1;
    int owner = create_discover_tid(op) && create_find_owner(op, &c.caller) && retain_preflight(op);
    u32 caller_tid = op->trace_tid;
    if (owner) {
        /* Verify monitor_tid + all pins up front while read-only so no pin failure happens mid-session. */
        ram_monitor(op);
        owner = retain_preflight(op);
        op->caller_kind = 1; op->trace_tid = caller_tid; op->owner_pthread_bias = c.caller.pthread_bias;
    }

    /* Lazy-armed: physical half-press (S1) is held, full-press (S2) must be 0. */
    int ready = subscription(op, 0, 1) && (op->route[10] == 0u || op->route[10] == 0x7fffffffu);
    int input_ok = owner && ready && sd_input_init(op, &ps->input) && precap_keys(ps);
    int holding = input_ok && precap_check_still_holding(op, ps);

    phase(op, 21);
    session_notice(op, 0, m7_config.bias, m7_config.mwf_bias, m7_config.pid, op->trace_tid,
                   m7_config.monitor_tid, M7_RAM_FRAMES, 4u);
    u32 planned[8] = {0, 1, m7_config.mpr_bias, m7_config.token, 0, 0, 0, 0};
    op->phase = 23; emit(op, 61, planned); op->phase = 21;

    int rc_exit = 0;
    if (!owner) {
        /* Hard preflight/pin failure -> return nonzero so daemon latches ring_fault. */
        session_notice(op, 9, 0, 0, 0, 0, 0, 0, 0);
        rc_exit = 8;
        goto out;
    }
    if (!ready || !holding) {
        /* Soft pre-mutation abort (user released/full-pressed/left shooting mode/disarmed). */
        session_notice(op, 90, 1, (u32)ready, (u32)input_ok, ps->disarm_seen, 0, 0, 0);
        session_notice(op, 9, 1, 0, 0, 0, 0, 0, 0);
        rc_exit = 0;
        goto out;
    }

    /* Enable live shutter/subscription sampling across ALL pre-arm wait_trace_stop() waits! */
    ps->prearm_check_sub = 1u;
    op->extension = ps;

    int admitted = 0, started = 0, inserted = 0, captured = 0, stopped = 0, restored = 0;
    u32 selected[2] = {0}, returned = 0, mmgr = 0, topology = 0;

    source_notice(op, 0, m7_config.bias, m7_config.mwf_bias, m7_config.pid, 50, 16, 2, 0);
    admitted = source_sample(op, 0, selected) && selected[0] && selected[1];
    c.source = selected[0]; c.remote = selected[1];
    int pins_ok = 1;
    if (admitted) {
        admitted = start_graph(op, &c, 0);
        if (admitted) {
            pins_ok =
                check_media_pins(op, start_code_pins, sizeof(start_code_pins) / sizeof(start_code_pins[0]), m7_config.bias, 54) &&
                check_media_pins(op, start_mwf_code_pins, sizeof(start_mwf_code_pins) / sizeof(start_mwf_code_pins[0]), m7_config.mwf_bias, 56) &&
                check_media_pins(op, start_uipc_code_pins, sizeof(start_uipc_code_pins) / sizeof(start_uipc_code_pins[0]), c.uipc, 58) &&
                check_media_pins(op, mode_code_pins, sizeof(mode_code_pins) / sizeof(mode_code_pins[0]), m7_config.bias, 50) &&
                check_media_pins(op, mode_mwf_code_pins, sizeof(mode_mwf_code_pins) / sizeof(mode_mwf_code_pins[0]), m7_config.mwf_bias, 52);
            admitted = pins_ok && stage6_start_wait(op, &c, 0, 0, ps) &&
                read_mem(op, c.caller.manager + 0x44, &mmgr, 4) && mmgr && mmgr != 0xffffffff;
        }
    }
    session_notice(op, 1, admitted, c.source, c.remote, c.source_tid, c.remote_tid, c.uipc, 0);

    if (!pins_ok) {
        op->extension = 0;
        session_notice(op, 9, 0, 0, 0, 0, 0, 0, 0);
        rc_exit = 8;
        goto out;
    }
    if (!admitted || !precap_check_still_holding(op, ps)) {
        /* Clean pre-Insert4100 abort (zero mutations). */
        op->extension = 0;
        session_notice(op, 90, 1, (u32)admitted, ps->disarm_seen, 0, 0, 0, 0);
        session_notice(op, 9, 1, (u32)admitted, 0, 0, 0, 0, 0);
        rc_exit = 0;
        goto out;
    }

    started = stage6_start_command(op, &c, 1, &returned, ps);
    ps->prearm_check_sub = 0u;
    if (!started) {
        /* start_command(1) refused cleanly before t.dirty (or hold/subscription lost on retry) -> zero mutations, soft skip. */
        op->extension = 0;
        session_notice(op, 90, 6, ps->hold_lost, ps->disarm_seen, 0, 0, 0, 0);
        session_notice(op, 9, 1, 1, 0, 0, 0, 0, 0);
        rc_exit = 0;
        goto out;
    }

    u32 last_topo = 0u;
    inserted = stage6_start_wait(op, &c, 1, 100, ps);
    if (inserted) topology = (u32)stage6_route_wait(op, &c, mmgr, 0, ps, &last_topo);
    if (topology == 3u) {
        u32 descriptor;
        if (!read_mem(op, c.caller.manager + 4, &descriptor, 4) ||
            !read_mem(op, descriptor + 0x24, &c.recording_peer, 4)) retain_unresolved(op, 186, 2);
    } else if (inserted) {
        /* If Insert4100 wired a reciprocal ObjCntMgr.pin1 <-> ObjStillRecorder.pin0 pair without 2x topology==3
         * confirmation, allow start_graph_state(2,0) + Pullout4100 to restore stock SD; fail closed on one-sided links! */
        u32 descriptor = 0u, rec_pin = 0u, rem_pin1 = 0u, peer_now = 0u, rec_back = 0u;
        if (read_mem(op, c.caller.manager + 4, &descriptor, 4) &&
            read_mem(op, descriptor + 0x24, &rec_pin, 4) &&
            read_mem(op, c.remote + 0x54, &rem_pin1, 4) &&
            read_mem(op, rem_pin1 + 0x10, &peer_now, 4) &&
            read_mem(op, rec_pin + 0x10, &rec_back, 4) &&
            peer_now && peer_now == rec_pin && rec_back == rem_pin1) {
            c.recording_peer = rec_pin;
        }
    }
    if (!start_graph_state(op, &c, 2, 0)) retain_unresolved(op, 186, 2);
    session_notice(op, 2, inserted, c.source, c.remote, c.source_tid, c.remote_tid, returned, 0);

    if (inserted && topology == 3u) {
        phase(op, 18);
        captured = stage6_session_stock_capture(op, &c, ps);
        session_notice(op, 3, captured, op->held_owned, 0, 0, 0, 0, 0);
        phase(op, 21);
    } else if (inserted) {
        /* Unexpected or unconfirmed non-stock topology -> skip capture and pull out cleanly. */
        session_notice(op, 90, 7, last_topo, 0, 0, 0, 0, 0);
        captured = 0;
    }

    op->extension = 0;
    op->caller_kind = 1; op->trace_tid = caller_tid; op->owner_pthread_bias = c.caller.pthread_bias;
    if (!start_graph_state(op, &c, 3, 0)) retain_unresolved(op, 186, 3);
    stopped = stage6_start_command(op, &c, 2, &returned, 0);
    if (!stopped) retain_unresolved(op, 183, 2);
    if (!start_wait(op, &c, 0, 200)) retain_unresolved(op, 183, 2);
    c.recording_peer = 0;
    u32 restore_last = 0u;
    restored = stage6_route_wait(op, &c, mmgr, 1, 0, &restore_last) == 1 && start_graph(op, &c, 10);
    if (!restored) retain_unresolved(op, 186, 4);
    restored = source_sample(op, 1, selected) && selected[0] == c.source && selected[1] == c.remote;
    if (!restored) retain_unresolved(op, 186, 5);
    source_notice(op, 2, 1, 0, 0, 0, 0, 0, 0);
    session_notice(op, 4, stopped, restored, 0, 0, 0, 0, 0);

    phase(op, 18);
    int sub_active = subscription(op, 0, 1);
    int sub_inactive = inactive_route(op);
    int s2_released = (op->route[10] == 0u || op->route[10] == 0x7fffffffu);
    int clear = (sub_active || sub_inactive) && s2_released;
    int ok = admitted && started && inserted && captured && stopped && restored && clear && !op->io_errors;
    session_notice(op, 9, ok, admitted, started, inserted, captured, stopped, restored);
    rc_exit = ok ? 0 : 7;

out:;
    u32 final[8] = {(u32)rc_exit, op->reads, op->read_errors, op->events, op->dropped, op->io_errors, 1, op->truncated};
    emit(op, 9, final);
    call(6, (u32)op->fd, 0, 0, 0, 0, 0);
    call(91, (u32)arena, arena_sz, 0, 0, 0, 0);
    return rc_exit;
}
