#ifndef STAGE7_COMMON_H
#define STAGE7_COMMON_H

/* Freestanding ARM Linux EABI. Only ordinary file operations are used here. */
#ifndef S7_RAM_ROOT
#define S7_RAM_ROOT "/tmp_network"
#endif
#define PRECAP_CFG S7_RAM_ROOT "/mlv2/precap.cfg"
#define PRECAP_TMP PRECAP_CFG ".tmp"
#define PRECAP_PERSIST_GATE S7_RAM_ROOT "/mlv2/persist-cfg"
#define PRECAP_PERSIST_SETTING "/setting/mlv2_precap.cfg"
#define PRECAP_PERSIST_SETTING_TMP "/setting/mlv2_precap.cfg.tmp"
#define PRECAP_PERSIST_SIM S7_RAM_ROOT "/mlv2/sim-setting-precap.cfg"
#define PRECAP_PERSIST_SIM_TMP S7_RAM_ROOT "/mlv2/sim-setting-precap.cfg.tmp"

enum { S7_READ = 3, S7_WRITE = 4, S7_OPEN = 5, S7_CLOSE = 6,
       S7_UNLINK = 10, S7_RENAME = 38, S7_FSYNC = 118, S7_FSTAT64 = 197 };
enum { S7_WRONLY = 1, S7_CREAT = 0100, S7_EXCL = 0200,
       S7_NONBLOCK = 04000, S7_NOFOLLOW = 0100000 };

static inline long s7_file_call(long number, long a, long b, long c)
{
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r7 __asm__("r7") = number;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "cc", "memory");
    return r0;
}

/* Verify open fd refers to a regular file (ARM Linux stat64: u32 st_mode at +16). */
static inline int s7_fd_is_regular(long fd)
{
    unsigned char st[104];
    for (unsigned i = 0u; i < sizeof(st); ++i) st[i] = 0u;
    if (s7_file_call(S7_FSTAT64, fd, (long)st, 0) != 0) return 0;
    unsigned mode = (unsigned)st[16] | ((unsigned)st[17] << 8) |
                    ((unsigned)st[18] << 16) | ((unsigned)st[19] << 24);
    return (mode & 0170000u) == 0100000u;
}

static inline unsigned s7_index_to_frames(unsigned index)
{
    if (index == 0u) return 1u;
    if (index == 1u) return 2u;
    if (index == 2u) return 3u;
    if (index == 3u) return 5u;
    if (index == 4u) return 8u;
    if (index == 5u) return 10u;
    return 0u;
}

static inline unsigned s7_frames_to_index(unsigned frames)
{
    if (frames == 1u) return 0u;
    if (frames == 2u) return 1u;
    if (frames == 3u) return 2u;
    if (frames == 5u) return 3u;
    if (frames == 8u) return 4u;
    if (frames == 10u) return 5u;
    return 0xffu;
}

/* Parse an exact "S7PC1 <0|1> <1|2|3|5|8|10>\n" record.
 * Returns:
 *   1 = regular file affirmatively parsed as a valid record
 *   0 = path affirmatively confirmed absent (-ENOENT)
 *  -1 = open/fstat64/read/close error, non-regular file, or malformed content */
static inline int s7_parse_precap_record_status(const char *path, int *out_enabled, unsigned *out_frames)
{
    char buf[13];
    long fd = -4;
    for (unsigned tries = 0u; tries < 8u && fd == -4; ++tries) {
        fd = s7_file_call(S7_OPEN, (long)path, S7_NONBLOCK | S7_NOFOLLOW, 0);
    }
    if (fd == -2) return 0;
    if (fd < 0) return -1;
    if (!s7_fd_is_regular(fd)) {
        s7_file_call(S7_CLOSE, fd, 0, 0);
        return -1;
    }
    unsigned used = 0;
    int read_ok = 1;
    while (used < sizeof(buf)) {
        long n = s7_file_call(S7_READ, fd, (long)(buf + used), (long)(sizeof(buf) - used));
        if (n == -4) continue;
        if (n < 0) { read_ok = 0; break; }
        if (n == 0) break;
        used += (unsigned)n;
    }
    long closed = s7_file_call(S7_CLOSE, fd, 0, 0);
    if (!read_ok || closed < 0 || (used != 10u && used != 11u)) return -1;
    if (buf[0] != 'S' || buf[1] != '7' || buf[2] != 'P' ||
        buf[3] != 'C' || buf[4] != '1' || buf[5] != ' ' ||
        (buf[6] != '0' && buf[6] != '1') || buf[7] != ' ' ||
        buf[used - 1u] != '\n') {
        return -1;
    }
    unsigned frames = 0u;
    if (used == 11u) {
        if (buf[8] != '1' || buf[9] != '0') return -1;
        frames = 10u;
    } else {
        if (buf[8] == '1') frames = 1u;
        else if (buf[8] == '2') frames = 2u;
        else if (buf[8] == '3') frames = 3u;
        else if (buf[8] == '5') frames = 5u;
        else if (buf[8] == '8') frames = 8u;
        else return -1;
    }
    if (out_enabled) *out_enabled = (buf[6] == '1') ? 1 : 0;
    if (out_frames) *out_frames = frames;
    return 1;
}

/* Parse an exact "S7PC1 <0|1> <1|2|3|5|8|10>\n" record. Returns 1 on exact match, 0 otherwise. */
static inline int s7_parse_precap_record(const char *path, int *out_enabled, unsigned *out_frames)
{
    return s7_parse_precap_record_status(path, out_enabled, out_frames) == 1;
}

/* Return 1 ONLY when runtime precap.cfg is affirmatively absent (-ENOENT) or parsed as OFF (enabled == 0).
 * Any I/O error (e.g., fstat64 -EIO), non-regular file, malformed record, or enabled == 1 returns 0. */
static inline int s7_confirm_runtime_disarmed(void)
{
    int enabled = 1;
    unsigned frames = 0u;
    int st = s7_parse_precap_record_status(PRECAP_CFG, &enabled, &frames);
    return (st == 0) || (st == 1 && enabled == 0);
}

/* Atomically write an exact "S7PC1 <0|1> <N>\n" record. Never deletes existing path on failure. */
static inline int s7_write_precap_record(const char *path, const char *tmp_path,
                                         int enabled, unsigned frames, int do_fsync)
{
    if ((enabled != 0 && enabled != 1) || s7_frames_to_index(frames) >= 6u) return 0;
    char record[12];
    record[0] = 'S';
    record[1] = '7';
    record[2] = 'P';
    record[3] = 'C';
    record[4] = '1';
    record[5] = ' ';
    record[6] = enabled ? '1' : '0';
    record[7] = ' ';
    unsigned len;
    if (frames == 10u) {
        record[8] = '1';
        record[9] = '0';
        record[10] = '\n';
        len = 11u;
    } else {
        record[8] = (char)('0' + frames);
        record[9] = '\n';
        len = 10u;
    }

    s7_file_call(S7_UNLINK, (long)tmp_path, 0, 0);
    long fd = s7_file_call(S7_OPEN, (long)tmp_path,
                           S7_CREAT | S7_EXCL | S7_WRONLY, 0600);
    if (fd < 0) return 0;

    unsigned done = 0;
    while (done < len) {
        long n = s7_file_call(S7_WRITE, fd, (long)(record + done), (long)(len - done));
        if (n == -4) continue;
        if (n <= 0 || (unsigned)n > len - done) break;
        done += (unsigned)n;
    }
    long synced = 0;
    if (done == len && do_fsync) {
        do {
            synced = s7_file_call(S7_FSYNC, fd, 0, 0);
        } while (synced == -4);
    }
    long closed = s7_file_call(S7_CLOSE, fd, 0, 0);
    if (done == len && synced == 0 && closed == 0 &&
        s7_file_call(S7_RENAME, (long)tmp_path, (long)path, 0) == 0) {
        return 1;
    }
    s7_file_call(S7_UNLINK, (long)tmp_path, 0, 0);
    return 0;
}

/* Return the armed window, or zero for OFF, a malformed record, or an I/O error. */
static inline unsigned s7_pre_frames(void)
{
    int enabled = 0;
    unsigned frames = 0u;
    if (!s7_parse_precap_record(PRECAP_CFG, &enabled, &frames)) return 0u;
    return enabled ? frames : 0u;
}
#endif
