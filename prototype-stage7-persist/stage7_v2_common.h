/* Shared wire contract between stage7_daemon.elf and stage7_ring.elf (Stage 7.1).
 * Strictly freestanding (no libc headers), layout-identical on ARMv7 EABI.
 */
#ifndef STAGE7_V2_COMMON_H
#define STAGE7_V2_COMMON_H

#define S7_DAEMON_MAGIC    0x31443753u /* "S7D1" */
#define S7_DAEMON_VERSION  1u

#define S7_RING_BOOT_MAGIC   0x31523753u /* "S7R1" */
#define S7_RING_BOOT_VERSION 1u

#define S7_RING_CFG_MAGIC    0x31433753u /* "S7C1" */
#define S7_RING_CFG_VERSION  1u

#define S7_MAX_RANGES 512u
#define S7_NONCE_LEN  12u
#ifndef S7_RAM_ROOT
#define S7_RAM_ROOT "/tmp_network"
#endif
#define S7_RUN_PREFIX S7_RAM_ROOT "/.m7-s7-"

/* Matches prototype-producer-probe/native.c struct range / struct config layout exactly. */
struct s7_wire_range {
    unsigned int start;
    unsigned int end;
};

struct s7_wire_config {
    unsigned int magic, version, token, pid, bias, nranges, interval_ms, focus_ms, settle_ms, diagnose_only;
    unsigned int retain_check, monitor_tid, mpr_bias, mprctrl_bias, mwf_bias;
    struct s7_wire_range ranges[S7_MAX_RANGES];
};

/* Variant A two-phase cadence + hold-driven post + fast save (identical to Stage 6 Run #4b). */
struct s7_wire_precap_config {
    unsigned int magic, revision, before, after, backlog_cap, sample_ms, window_ms, drain_ms;
    unsigned int burst_cap, post_max;
};

/* Binary runtime config written atomically by stage7_daemon and read once by stage7_ring. */
struct s7_ring_cfg_file {
    unsigned int magic;
    unsigned int version;
    unsigned int total_bytes;
    unsigned int checksum;
    char nonce[S7_NONCE_LEN];
    struct s7_wire_config cfg;
    struct s7_wire_precap_config precap;
};

/* Sealed boot header inside stage7_ring.elf PT_LOAD[0] (read-only). */
struct s7_ring_boot {
    unsigned int magic;
    unsigned int version;
    unsigned int rw_vaddr;
    unsigned int rw_size;
    char nonce[S7_NONCE_LEN];
};

static unsigned int s7_fnv1a32(const unsigned char *data, unsigned int len) {
    unsigned int h = 0x811c9dc5u;
    for (unsigned int i = 0; i < len; ++i) {
        h ^= (unsigned int)data[i];
        h *= 0x01000193u;
    }
    return h;
}

static int s7_valid_nonce_chars(const char *nonce) {
    for (unsigned int i = 0; i < S7_NONCE_LEN; ++i) {
        char c = nonce[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static unsigned int s7_ring_cfg_checksum(const struct s7_ring_cfg_file *f) {
    const unsigned char *base = (const unsigned char *)f;
    return s7_fnv1a32(base + 16u, (unsigned int)sizeof(*f) - 16u);
}

#endif
