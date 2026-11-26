/*
 * Shared wire contract between stage6_daemon.elf and stage6_ring.elf (Stage 6 WIP v3).
 * Kept strictly freestanding (no libc headers) and layout-identical on ARMv7 EABI.
 */
#ifndef STAGE6_V2_COMMON_H
#define STAGE6_V2_COMMON_H

#define S6_DAEMON_MAGIC   0x32443653u /* "S6D2" */
#define S6_DAEMON_VERSION 2u

#define S6_RING_BOOT_MAGIC   0x32523653u /* "S6R2" */
#define S6_RING_BOOT_VERSION 1u

#define S6_RING_CFG_MAGIC   0x32433653u /* "S6C2" */
#define S6_RING_CFG_VERSION 2u

#define S6_MAX_RANGES 512u
#define S6_NONCE_LEN  12u

/* Matches prototype-producer-probe/native.c struct range / struct config layout exactly. */
struct s6_wire_range {
    unsigned int start;
    unsigned int end;
};

struct s6_wire_config {
    unsigned int magic, version, token, pid, bias, nranges, interval_ms, focus_ms, settle_ms, diagnose_only;
    unsigned int retain_check, monitor_tid, mpr_bias, mprctrl_bias, mwf_bias;
    struct s6_wire_range ranges[S6_MAX_RANGES];
};

/* Stage 6 WIP v3 precap config: Variant A two-phase cadence + hold-driven post + fast save. */
struct s6_wire_precap_config {
    unsigned int magic, revision, before, after, backlog_cap, sample_ms, window_ms, drain_ms;
    unsigned int burst_cap, post_max;
};

/* Binary runtime config written atomically by stage6_daemon and read once by stage6_ring. */
struct s6_ring_cfg_file {
    unsigned int magic;
    unsigned int version;
    unsigned int total_bytes;
    unsigned int checksum;
    char nonce[S6_NONCE_LEN];
    struct s6_wire_config cfg;
    struct s6_wire_precap_config precap;
};

/* Sealed boot header inside stage6_ring.elf PT_LOAD[0] (read-only). */
struct s6_ring_boot {
    unsigned int magic;
    unsigned int version;
    unsigned int rw_vaddr;
    unsigned int rw_size;
    char nonce[S6_NONCE_LEN];
};

static unsigned int s6_fnv1a32(const unsigned char *data, unsigned int len) {
    unsigned int h = 0x811c9dc5u;
    for (unsigned int i = 0; i < len; ++i) {
        h ^= (unsigned int)data[i];
        h *= 0x01000193u;
    }
    return h;
}

static int s6_valid_nonce_chars(const char *nonce) {
    for (unsigned int i = 0; i < S6_NONCE_LEN; ++i) {
        char c = nonce[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static unsigned int s6_ring_cfg_checksum(const struct s6_ring_cfg_file *f) {
    /* Checksum covers everything after the checksum field (offset 16..sizeof(*f)). */
    const unsigned char *base = (const unsigned char *)f;
    return s6_fnv1a32(base + 16u, (unsigned int)sizeof(*f) - 16u);
}

#endif
