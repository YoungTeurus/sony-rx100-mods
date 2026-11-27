/* Fixed-path filesystem measurements for offline M7 ARM EABI verification. */
#include <stddef.h>
#include <stdint.h>

struct stat_result {
    uint64_t dev;
    uint32_t padding[2], mode;
    unsigned char rest[84];
};
struct __attribute__((packed, aligned(4))) fs_result {
    uint32_t type, bsize;
    uint64_t blocks, bfree, bavail, files, ffree;
    uint32_t fsid[2], namelen, frsize, flags, spare[4];
};
_Static_assert(sizeof(struct stat_result) == 104, "M7 cp_new_stat64 copy size");
_Static_assert(offsetof(struct stat_result, mode) == 16, "M7 st_mode");
_Static_assert(sizeof(struct fs_result) == 84, "M7 do_statfs64 copy size");
_Static_assert(offsetof(struct fs_result, frsize) == 60, "M7 f_frsize");

extern int pb_lstat(const char *, struct stat_result *);
extern int pb_statfs(const char *, unsigned, struct fs_result *);
extern int pb_stdout(const char *, unsigned);
extern __attribute__((noreturn)) void pb_exit(int);

/* Save callee-saved r7 before selecting a constant syscall slot. */
#define TRAP(name, setup, slot) \
    ".arm\n.type " #name ",%function\n" #name ":\n" \
    "mov ip,r7\n" setup "movw r7,#" #slot "\nsvc #0\nmov r7,ip\nbx lr\n" \
    ".size " #name ",.-" #name "\n"
__asm__(TRAP(pb_lstat, "", 196)
        TRAP(pb_statfs, "", 266)
        TRAP(pb_stdout, "mov r2,r1\nmov r1,r0\nmov r0,#1\n", 4)
        TRAP(pb_exit, "", 248));

static char *append(char *out, const char *value)
{
    while (*value) *out++ = *value++;
    return out;
}

/* No C runtime division helpers on the camera. */
static unsigned div10(uint64_t *value)
{
    uint64_t quotient = 0, input = *value;
    unsigned remainder = 0;
    for (unsigned bit = 0; bit < 64; ++bit) {
        remainder = remainder * 2 + (unsigned)(input >> 63);
        input <<= 1;
        quotient <<= 1;
        if (remainder >= 10) {
            remainder -= 10;
            ++quotient;
        }
    }
    *value = quotient;
    return remainder;
}

static char *number(char *out, uint64_t value, unsigned base)
{
    char digits[24];
    unsigned count = 0;
    do {
        unsigned digit;
        if (base == 10) digit = div10(&value);
        else {
            digit = (unsigned)value & (base - 1);
            value >>= base == 8 ? 3 : 4;
        }
        digits[count++] = "0123456789abcdef"[digit];
    } while (value);
    while (count) *out++ = digits[--count];
    return out;
}

static char *status(char *out, int rc)
{
    if (rc < 0) *out++ = '-';
    return number(out, rc < 0 ? 0u - (unsigned)rc : (unsigned)rc, 10);
}

static char *field(char *out, const char *label, uint64_t value)
{
    return number(append(out, label), value, 10);
}

static int inspect_path(const char *path)
{
    struct stat_result st;
    struct fs_result fs;
    int lrc = pb_lstat(path, &st);
    unsigned dev = lrc ? 0 : (unsigned)st.dev;
    unsigned mode = lrc ? 0 : st.mode;
    /* ECANCELED means the directory check prevented a following lookup. */
    int frc = (mode & 0170000) == 0040000 ? pb_statfs(path, sizeof(fs), &fs) : -125;
    uint64_t blocks = frc ? 0 : fs.blocks, free_blocks = frc ? 0 : fs.bfree;
    unsigned bsize = frc ? 0 : fs.bsize;
    char line[384];
    char *out = append(append(line, "STATFS path="), path);
    out = status(append(out, " lstat_rc="), lrc);
    out = field(out, " dev=", (dev >> 8) & 0xfff);
    out = field(out, ":", (dev & 255) | ((dev >> 12) & 0xfff00));
    out = number(append(out, " mode="), mode, 8);
    out = status(append(out, " statfs_rc="), frc);
    out = number(append(out, " type=0x"), frc ? 0 : fs.type, 16);
    out = field(out, " bsize=", bsize);
    out = field(out, " frsize=", frc ? 0 : fs.frsize);
    out = field(out, " blocks=", blocks);
    out = field(out, " bfree=", free_blocks);
    out = field(out, " bavail=", frc ? 0 : fs.bavail);
    uint64_t free_bytes, total_bytes;
    if (__builtin_mul_overflow(free_blocks, bsize, &free_bytes) ||
        __builtin_mul_overflow(blocks, bsize, &total_bytes)) pb_exit(2);
    out = field(out, " free_bytes=", free_bytes);
    out = field(out, " total_bytes=", total_bytes);
    *out++ = '\n';
    const char *start = line;
    while (start < out) {
        int n = pb_stdout(start, (unsigned)(out - start));
        if (n == -4) continue;
        if (n <= 0 || n > out - start) pb_exit(3);
        start += n;
    }
    return lrc || frc;
}

__attribute__((noreturn)) void _start(void)
{
    static const char *const paths[] = {"/setting", "/etc", "/system", "/tmp_network"};
    int failed = 0;
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
        failed |= inspect_path(paths[i]);
    pb_exit(failed);
}
