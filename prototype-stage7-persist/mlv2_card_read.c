/* M7 SD package verifier, diagnostic probe, and bounded authenticated extractor. */
#ifdef MLV2_HOST_TEST
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#endif
#include <stdint.h>

typedef unsigned char byte;
typedef uint32_t u32;
typedef uint64_t u64;
#define BLOCK 512u
#define MAX_ROOT_SECTORS 4096u
#define MAX_TAR (384u * 1024u)
#define BUILD "29110_03.2021050601"

static unsigned length(const char *s) {
  unsigned n = 0;
  while (s[n])
    n++;
  return n;
}
static int same(const void *a, const void *b, unsigned n) {
  const byte *p = a, *q = b;
  unsigned diff = 0;
  while (n--)
    diff |= *p++ ^ *q++;
  return diff == 0;
}
static int eq(const char *a, const char *b) {
  return length(a) == length(b) && same(a, b, length(a));
}
static int zeros(const byte *p, unsigned n) {
  while (n--)
    if (*p++)
      return 0;
  return 1;
}
static u32 le16(const byte *p) { return p[0] | ((u32)p[1] << 8); }
static u32 le32(const byte *p) { return le16(p) | (le16(p + 2) << 16); }
static u64 le64(const byte *p) { return le32(p) | ((u64)le32(p + 4) << 32); }
static u32 be32(const byte *p) {
  return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}
#define TMPFS_MAGIC_LINUX 0x01021994u
struct space {
  u32 fstype;
  u32 size;
  u64 blocks, free, avail;
};
#ifndef MLV2_HOST_TEST
/* Slots are cross-checked against the original kernel in test_stage7_sd.py. */
void __aeabi_memclr(void *buf, unsigned n) {
  volatile byte *p = buf;
  while (n--)
    *p++ = 0;
}
void __aeabi_memclr8(void *buf, unsigned n) { __aeabi_memclr(buf, n); }
static inline __attribute__((always_inline)) long call(long n, long a, long b,
                                                       long c, long d, long e) {
  register long r0 __asm__("r0") = a, r1 __asm__("r1") = b;
  register long r2 __asm__("r2") = c, r3 __asm__("r3") = d,
                   r4 __asm__("r4") = e;
  __asm__ volatile("movw r7, %c[nr]\n svc 0"
                   : "+r"(r0)
                   : [nr] "i"(n), "r"(r1), "r"(r2), "r"(r3), "r"(r4)
                   : "r7", "cc", "memory");
  return r0;
}
static int timer(void) {
  const int it[4] = {0, 0, 8, 0};
  return call(104, 0, (long)it, 0, 0, 0);
}
static int ro(const char *path) {
  return call(5, (long)path, 0100000 | 04000, 0, 0, 0);
}
static int open_dir_root(void) {
  return call(5, (long)"/", 040000, 0, 0, 0);
}
static int openat_dir_nofollow(int dirfd, const char *comp) {
  return call(322, dirfd, (long)comp, 040000 | 0100000, 0, 0);
}
static int create_excl_at(int dirfd, const char *name) {
  return call(322, dirfd, (long)name, 1 | 0100 | 0200 | 0100000, 0600, 0);
}
static int closefd(int fd) { return call(6, fd, 0, 0, 0, 0); }
static int unlinkat_raw(int dirfd, const char *name) {
  return call(328, dirfd, (long)name, 0, 0, 0);
}
static int renameat_raw(int olddir, const char *oldn, int newdir, const char *newn) {
  return call(329, olddir, (long)oldn, newdir, (long)newn, 0);
}
static long readfd(int fd, byte *p, unsigned n) {
  return call(3, fd, (long)p, n, 0, 0);
}
static long writefd(int fd, const byte *p, unsigned n) {
  return call(4, fd, (long)p, n, 0, 0);
}
static long output(const byte *p, unsigned n) { return writefd(1, p, n); }
static int seekfd(int fd, u64 off) {
  u64 actual = 0;
  long rc;
  do
    rc = call(140, fd, (u32)(off >> 32), (u32)off, (long)&actual, 0);
  while (rc == -4);
  return rc || actual != off;
}
static int is_card(int fd) {
  _Alignas(8) byte st[104];
  return !call(197, fd, (long)st, 0, 0, 0) &&
         (le32(st + 16) & 0170000) == 0060000 && le64(st + 32) == 0xfa0b;
}
static int is_reg_fd(int fd) {
  _Alignas(8) byte st[104];
  return !call(197, fd, (long)st, 0, 0, 0) &&
         (le32(st + 16) & 0170000) == 0100000;
}
static int is_dir_fd(int fd) {
  _Alignas(8) byte st[104];
  return !call(197, fd, (long)st, 0, 0, 0) &&
         (le32(st + 16) & 0170000) == 0040000;
}
static int space_at(const char *p, struct space *s) {
  _Alignas(8) byte buf[84];
  if (call(266, (long)p, sizeof(buf), (long)buf, 0, 0))
    return 0;
  s->fstype = le32(buf + 0);
  s->size = le32(buf + 4);
  s->blocks = le64(buf + 8);
  s->free = le64(buf + 16);
  s->avail = le64(buf + 24);
  return 1;
}
static int fspace_at(int fd, struct space *s) {
  _Alignas(8) byte buf[84];
  if (call(267, fd, sizeof(buf), (long)buf, 0, 0))
    return 0;
  s->fstype = le32(buf + 0);
  s->size = le32(buf + 4);
  s->blocks = le64(buf + 8);
  s->free = le64(buf + 16);
  s->avail = le64(buf + 24);
  return 1;
}
#else
static int timer(void) { return 0; }
static int ro(const char *p) {
  return open(p, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
}
static int open_dir_root(void) {
  return open("/", O_RDONLY | O_DIRECTORY);
}
static int openat_dir_nofollow(int dirfd, const char *comp) {
  return openat(dirfd, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
}
static int create_excl_at(int dirfd, const char *name) {
  return openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
}
static int closefd(int fd) { return close(fd); }
static int unlinkat_raw(int dirfd, const char *name) {
  return unlinkat(dirfd, name, 0);
}
static int renameat_raw(int olddir, const char *oldn, int newdir, const char *newn) {
  return renameat(olddir, oldn, newdir, newn);
}
static long readfd(int fd, byte *p, unsigned n) {
  ssize_t r = read(fd, p, n);
  return r < 0 ? -errno : r;
}
static long writefd(int fd, const byte *p, unsigned n) {
  ssize_t r = write(fd, p, n);
  return r < 0 ? -errno : r;
}
static long output(const byte *p, unsigned n) { return writefd(1, p, n); }
static int seekfd(int fd, u64 off) {
  return lseek(fd, (off_t)off, SEEK_SET) != (off_t)off;
}
static int is_card(int fd) {
  struct stat st;
  return !fstat(fd, &st) && S_ISREG(st.st_mode);
}
static int is_reg_fd(int fd) {
  struct stat st;
  return !fstat(fd, &st) && S_ISREG(st.st_mode);
}
static int is_dir_fd(int fd) {
  struct stat st;
  return !fstat(fd, &st) && S_ISDIR(st.st_mode);
}
static int space_at(const char *p, struct space *s) {
  struct statvfs v;
  if (statvfs(p, &v) || !v.f_frsize || v.f_frsize > UINT32_MAX)
    return 0;
  s->fstype = TMPFS_MAGIC_LINUX;
  s->size = (u32)v.f_frsize;
  s->blocks = v.f_blocks;
  s->free = v.f_bfree;
  s->avail = v.f_bavail;
  return 1;
}
static int fspace_at(int fd, struct space *s) {
  struct statvfs v;
  if (fstatvfs(fd, &v) || !v.f_frsize || v.f_frsize > UINT32_MAX)
    return 0;
  s->fstype = TMPFS_MAGIC_LINUX;
  s->size = (u32)v.f_frsize;
  s->blocks = v.f_blocks;
  s->free = v.f_bfree;
  s->avail = v.f_bavail;
  return 1;
}
#endif
/* Walk stage_dir component by component from "/" with O_DIRECTORY|O_NOFOLLOW and
 * return a pinned directory fd so no intermediate or final symlink can escape. */
static int open_stage_dir_anchored(const char *p) {
  unsigned n = length(p);
  if (!n || p[0] != '/' || p[n - 1] == '/')
    return -1;
#ifndef MLV2_HOST_TEST
#ifndef S7_RAM_ROOT
#define S7_RAM_ROOT "/tmp_network"
#endif
  const char pref[] = S7_RAM_ROOT "/";
  if (n < sizeof(pref) || !same(p, pref, sizeof(pref) - 1))
    return -1;
#endif
  int dirfd = open_dir_root();
  if (dirfd < 0)
    return -1;
  if (!is_dir_fd(dirfd)) {
    closefd(dirfd);
    return -1;
  }
  unsigned i = 1, comps = 0;
  while (i < n) {
    unsigned beg = i;
    while (i < n && p[i] != '/')
      ++i;
    unsigned len = i - beg;
    if (!len || len >= 64 ||
        (len == 1 && p[beg] == '.') ||
        (len == 2 && p[beg] == '.' && p[beg + 1] == '.')) {
      closefd(dirfd);
      return -1;
    }
    char comp[64];
    for (unsigned k = 0; k < len; ++k)
      comp[k] = p[beg + k];
    comp[len] = 0;
    int next_fd = openat_dir_nofollow(dirfd, comp);
    int closed_prev = closefd(dirfd);
    if (next_fd < 0 || closed_prev != 0 || !is_dir_fd(next_fd)) {
      if (next_fd >= 0)
        closefd(next_fd);
      return -1;
    }
    dirfd = next_fd;
    ++comps;
    if (i < n)
      ++i;
  }
  if (!comps) {
    closefd(dirfd);
    return -1;
  }
  return dirfd;
}
static int full(int fd, byte *p, unsigned n) {
  while (n) {
    long k = readfd(fd, p, n);
    if (k == -4)
      continue;
    if (k <= 0 || (unsigned long)k > n)
      return 0;
    p += k;
    n -= (unsigned)k;
  }
  return 1;
}
static int exact_file(const char *path, byte *p, unsigned n) {
  int fd = ro(path);
  if (fd < 0)
    return 0;
  int ok = is_reg_fd(fd) && full(fd, p, n);
  byte extra;
  long k = 0;
  if (ok) {
    do
      k = readfd(fd, &extra, 1);
    while (k == -4);
  }
  return !closefd(fd) && ok && !k;
}
static int at(int fd, u64 off, byte *p, unsigned n) {
  return off <= INT64_MAX && !seekfd(fd, off) && full(fd, p, n);
}
static int put(const char *s) {
  unsigned n = length(s);
  while (n) {
    long k = output((const byte *)s, n);
    if (k == -4)
      continue;
    if (k <= 0 || (unsigned long)k > n)
      return 0;
    s += k;
    n -= (unsigned)k;
  }
  return 1;
}
static int number(const char *label, u64 v) {
  /* Decimal conversion without a freestanding 64-bit division runtime. */
  char buf[21];
  byte digits[20] = {0};
  for (unsigned bit = 64; bit; --bit) {
    unsigned carry = (v >> (bit - 1)) & 1;
    for (unsigned i = 0; i < 20; ++i) {
      unsigned d = 2 * digits[i] + carry;
      carry = d >= 10;
      digits[i] = d - 10 * carry;
    }
  }
  unsigned n = 0, i = 20;
  while (i > 1 && !digits[i - 1])
    --i;
  while (i)
    buf[n++] = '0' + digits[--i];
  buf[n] = 0;
  return put(label) && put(buf);
}

struct volume {
  int fd, exfat;
  u32 fat, fat_len, heap, spc, last, root;
  u64 sectors;
};
struct item {
  u32 first;
  u64 size, valid;
  int contiguous, directory;
};
struct catalog {
  unsigned found, markers;
  struct item tar;
};

static int vbr(struct volume *v) {
  byte b[BLOCK];
  if (!at(v->fd, 0, b, BLOCK) || le16(b + 510) != 0xaa55)
    return 0;
  u32 fats, active, clusters;
  if (same(b + 3, "EXFAT   ", 8)) {
    v->exfat = 1;
    if (b[108] != 9 || b[109] > 12 || !zeros(b + 11, 53))
      return 0;
    v->spc = 1u << b[109];
    v->sectors = le64(b + 72);
    v->fat = le32(b + 80);
    v->fat_len = le32(b + 84);
    v->heap = le32(b + 88);
    clusters = le32(b + 92);
    v->root = le32(b + 96);
    fats = b[110];
    active = le16(b + 106) & 1u;
    if (v->fat < 24 || !clusters || clusters > 0xfffffff5u ||
        (u64)v->heap + (u64)clusters * v->spc > v->sectors)
      return 0;
  } else {
    v->exfat = 0;
    v->spc = b[13];
    v->sectors = le32(b + 32);
    v->fat = le16(b + 14);
    v->fat_len = le32(b + 36);
    v->root = le32(b + 44);
    fats = b[16];
    u32 flags = le16(b + 40);
    active = (flags & 0x80) ? flags & 15 : 0;
    if (le16(b + 11) != BLOCK || !v->spc || v->spc > 128 ||
        (v->spc & (v->spc - 1)) || !v->fat || le16(b + 17) || le16(b + 19) ||
        le16(b + 22) || le16(b + 42))
      return 0;
    u64 heap = (u64)v->fat + (u64)fats * v->fat_len;
    if (heap >= v->sectors)
      return 0;
    v->heap = (u32)heap;
    clusters = (u32)(v->sectors - heap);
    for (u32 s = v->spc; s > 1; s >>= 1)
      clusters >>= 1;
    if (clusters < 65525 || clusters > 0x0fffffeeu)
      return 0;
  }
  v->last = clusters + 1;
  if ((fats != 1 && fats != 2) || active >= fats ||
      v->sectors > INT64_MAX / BLOCK ||
      (u64)v->fat + (u64)fats * v->fat_len > v->heap ||
      (u64)v->fat_len * 128 <= v->last || v->root < 2 || v->root > v->last)
    return 0;
  v->fat += active * v->fat_len;
  return 1;
}
static u64 start(const struct volume *v, u32 c) {
  return ((u64)v->heap + (u64)(c - 2) * v->spc) * BLOCK;
}
/* Result 1 for a valid successor, 0 at end-of-chain, -1 on failure. */
static int next(const struct volume *v, u32 *c) {
  byte b[4];
  if (!at(v->fd, (u64)v->fat * BLOCK + 4ull * (*c), b, 4))
    return -1;
  u32 n = le32(b);
  if (!v->exfat)
    n &= 0x0fffffff;
  if (v->exfat ? n == 0xffffffffu : n >= 0x0ffffff8u)
    return 0;
  if (n < 2 || n > v->last)
    return -1;
  *c = n;
  return 1;
}
static unsigned match(const char *name) {
  const char *const names[] = {"mlv2.tar", "disable_hook", "disable.txt",
                               "mlv2.off"};
  for (unsigned i = 0; i < 4; ++i) {
    unsigned j = 0;
    for (; name[j] && names[i][j]; ++j) {
      char ch = name[j];
      if (ch >= 'A' && ch <= 'Z')
        ch += 'a' - 'A';
      if (ch != names[i][j])
        break;
    }
    if (!name[j] && !names[i][j])
      return 1u << i;
  }
  return 0;
}
static void record(struct catalog *r, unsigned mask, const struct item *f) {
  r->markers |= mask >> 1;
  if (mask & 1) {
    ++r->found;
    r->tar = *f;
  }
}
static unsigned short_name(const byte *e) {
  char name[13];
  unsigned k = 0;
  for (unsigned i = 0; i < 8 && e[i] != ' '; ++i)
    name[k++] = e[i];
  if (e[8] != ' ')
    name[k++] = '.';
  for (unsigned i = 8; i < 11 && e[i] != ' '; ++i)
    name[k++] = e[i];
  name[k] = 0;
  return match(name);
}
struct fat_names {
  int single;
  byte sum;
  char name[14];
};
static void fat_entry(struct fat_names *n, const byte *e, struct catalog *r) {
  if (e[0] == 0xe5) {
    n->single = 0;
    return;
  }
  if (e[11] == 15) {
    /* Every allowlisted or disabling long name fits in a single LFN slot. */
    static const byte offsets[13] = {1,  3,  5,  7,  9,  14, 16,
                                     18, 20, 22, 24, 28, 30};
    n->single = e[0] == 0x41 && !e[12] && !le16(e + 26);
    n->sum = e[13];
    if (!n->single)
      return;
    int ended = 0;
    for (unsigned i = 0; i < 13; ++i) {
      unsigned ch = le16(e + offsets[i]);
      if (ended && ch != 0xffff)
        n->single = 0;
      n->name[i] = ended || !ch ? 0 : ch <= 127 ? (char)ch : '?';
      if (!ch)
        ended = 1;
    }
    n->name[13] = 0;
    return;
  }
  if (!(e[11] & 8)) {
    unsigned mask = short_name(e);
    byte sum = 0;
    for (unsigned i = 0; i < 11; ++i)
      sum = ((sum >> 1) | (sum << 7)) + e[i];
    if (n->single && n->sum == sum)
      mask |= match(n->name);
    struct item f = {le16(e + 26) | (le16(e + 20) << 16), le32(e + 28),
                     le32(e + 28), 0, !!(e[11] & 16)};
    record(r, mask, &f);
  }
  n->single = 0;
}
struct ex_names {
  unsigned left, total, chars, consumed, checksum, expected, mask;
  struct item f;
};
static unsigned sum_entry(unsigned sum, const byte *e, int primary) {
  for (unsigned i = 0; i < 32; ++i) {
    if (primary && (i == 2 || i == 3))
      continue;
    sum = (((sum >> 1) | (sum << 15)) + e[i]) & 65535;
  }
  return sum;
}
static int ex_entry(struct ex_names *n, const byte *e, struct catalog *r) {
  if (!n->left) {
    if (e[0] != 0x85)
      return (e[0] & 0xc0) != 0xc0;
    n->left = n->total = e[1];
    n->expected = le16(e + 2);
    n->checksum = sum_entry(0, e, 1);
    n->f.directory = !!(le16(e + 4) & 16);
    n->mask = 0;
    n->consumed = 0;
    return n->left >= 2;
  }
  n->checksum = sum_entry(n->checksum, e, 0);
  if (n->left == n->total) {
    if (e[0] != 0xc0)
      return 0;
    n->chars = e[3];
    n->f.contiguous = !!(e[1] & 2);
    n->f.first = le32(e + 20);
    n->f.size = le64(e + 24);
    n->f.valid = le64(e + 8);
    if (!n->chars || n->total < 1 + (n->chars + 14) / 15)
      return 0;
  } else if (n->consumed < n->chars) {
    if (e[0] != 0xc1)
      return 0;
    char name[16];
    unsigned part = n->chars - n->consumed;
    if (part > 15)
      part = 15;
    for (unsigned i = 0; i < part; ++i) {
      unsigned ch = le16(e + 2 + i * 2);
      if (!ch)
        return 0;
      name[i] = ch < 128 ? (char)ch : '?';
    }
    name[part] = 0;
    if (!n->consumed && n->chars == part)
      n->mask = match(name);
    n->consumed += part;
  } else if ((e[0] & 0xe0) != 0xe0)
    return 0;
  if (!--n->left) {
    if (n->checksum != n->expected || n->consumed != n->chars)
      return 0;
    record(r, n->mask, &n->f);
  }
  return 1;
}
static int scan(const struct volume *v, struct catalog *r) {
  byte b[BLOCK];
  struct fat_names fat = {0};
  struct ex_names ex = {0};
  u32 c = v->root, checkpoint = c;
  unsigned interval = 1, steps = 0;
  for (unsigned sectors = 0; sectors < MAX_ROOT_SECTORS;) {
    for (unsigned s = 0; s < v->spc; ++s) {
      if (sectors++ >= MAX_ROOT_SECTORS ||
          !at(v->fd, start(v, c) + (u64)s * BLOCK, b, BLOCK))
        return 0;
      for (unsigned i = 0; i < BLOCK; i += 32) {
        if (!b[i])
          return !ex.left;
        if (v->exfat) {
          if (!ex_entry(&ex, b + i, r))
            return 0;
        } else
          fat_entry(&fat, b + i, r);
      }
    }
    int result = next(v, &c);
    if (result <= 0)
      return !result && !ex.left;
    /* Brent cycle detection, in addition to the unconditional sector budget. */
    if (c == checkpoint)
      return 0;
    if (++steps == interval) {
      checkpoint = c;
      steps = 0;
      interval *= 2;
    }
  }
  return 0;
}

struct sha256 {
  u32 h[8], bytes;
  byte block[64];
};
static u32 ror(u32 v, unsigned n) { return v >> n | v << (32 - n); }
static void compress(struct sha256 *s) {
  static const u32 k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  u32 w[64];
  for (unsigned i = 0; i < 16; ++i)
    w[i] = be32(s->block + i * 4);
  for (unsigned i = 16; i < 64; ++i) {
    u32 x = w[i - 15], y = w[i - 2];
    w[i] = w[i - 16] + (ror(x, 7) ^ ror(x, 18) ^ (x >> 3)) + w[i - 7] +
           (ror(y, 17) ^ ror(y, 19) ^ (y >> 10));
  }
  u32 a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4],
      f = s->h[5], g = s->h[6], h = s->h[7];
  for (unsigned i = 0; i < 64; ++i) {
    u32 t1 = h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) +
             k[i] + w[i];
    u32 t2 =
        (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  s->h[0] += a;
  s->h[1] += b;
  s->h[2] += c;
  s->h[3] += d;
  s->h[4] += e;
  s->h[5] += f;
  s->h[6] += g;
  s->h[7] += h;
}
static void sha_init(struct sha256 *s) {
  static const u32 init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  for (unsigned i = 0; i < 8; ++i)
    s->h[i] = init[i];
  s->bytes = 0;
}
static void sha_add(struct sha256 *s, const byte *p, unsigned n) {
  while (n--) {
    s->block[s->bytes++ & 63] = *p++;
    if (!(s->bytes & 63))
      compress(s);
  }
}
static void sha_end(struct sha256 *s, byte out[32]) {
  byte pad[64] = {0x80};
  u32 bits = s->bytes << 3;
  unsigned used = s->bytes & 63;
  sha_add(s, pad, used < 56 ? 56 - used : 64 - used);
  if (!(s->bytes & 63))
    sha_add(s, pad + 1, 56);
  byte len[8] = {0, 0, 0, 0, bits >> 24, bits >> 16, bits >> 8, bits};
  sha_add(s, len, 8);
  for (unsigned i = 0; i < 32; ++i)
    out[i] = s->h[i >> 2] >> (24 - 8 * (i & 3));
}
static int auth(const byte *h, const byte key[32]) {
  byte pad[64], digest[32];
  struct sha256 s;
  for (unsigned i = 0; i < 64; ++i)
    pad[i] = 0x36 ^ (i < 32 ? key[i] : 0);
  sha_init(&s);
  sha_add(&s, pad, 64);
  sha_add(&s, h, 96);
  sha_end(&s, digest);
  for (unsigned i = 0; i < 64; ++i)
    pad[i] ^= 0x36 ^ 0x5c;
  sha_init(&s);
  sha_add(&s, pad, 64);
  sha_add(&s, digest, 32);
  sha_end(&s, digest);
  /* Volatile accumulation keeps the complete tag comparison on both compilers.
   */
  volatile unsigned diff = 0;
  for (unsigned i = 0; i < 32; ++i)
    diff |= h[96 + i] ^ digest[i];
  return !diff;
}
struct stream {
  const struct volume *v;
  u32 cluster, pos, remaining;
  int contiguous;
  u32 visited[1 + MAX_TAR / BLOCK];
  unsigned count;
};
static int take(struct stream *s, byte *out, unsigned n) {
  if (n > s->remaining)
    return 0;
  unsigned span = s->v->spc * BLOCK;
  while (n) {
    if (s->pos == span) {
      u32 c = s->cluster;
      if (s->contiguous)
        ++c;
      else if (next(s->v, &c) != 1)
        return 0;
      if (c < 2 || c > s->v->last ||
          s->count >= sizeof(s->visited) / sizeof(s->visited[0]))
        return 0;
      for (unsigned i = 0; i < s->count; ++i)
        if (s->visited[i] == c)
          return 0;
      s->visited[s->count++] = c;
      s->cluster = c;
      s->pos = 0;
    }
    unsigned part = span - s->pos;
    if (part > n)
      part = n;
    if (!at(s->v->fd, start(s->v, s->cluster) + s->pos, out, part))
      return 0;
    s->pos += part;
    s->remaining -= part;
    out += part;
    n -= part;
  }
  return 1;
}
static int octal(const byte *p, unsigned n, u32 *out) {
  unsigned i = 0, first;
  u32 value = 0;
  while (i < n && p[i] == ' ')
    ++i;
  first = i;
  while (i < n && p[i] >= '0' && p[i] <= '7') {
    if (value > UINT32_MAX / 8)
      return 0;
    value = value * 8 + p[i++] - '0';
  }
  if (i == first || i == n)
    return 0;
  while (i < n) {
    if (p[i] && p[i] != ' ')
      return 0;
    ++i;
  }
  *out = value;
  return 1;
}
static int tar_header(const byte *b, unsigned *seen, u32 *size) {
  static const char *const names[] = {"guard",          "mlv2.req", "core.bin",
                                      "PreCapture.mod", "daemon",   "ring.elf"};
  u32 check, sum = 0;
  if (!same(b + 257,
            "ustar\0"
            "00",
            8) ||
      (b[156] && b[156] != '0') || !zeros(b + 157, 100) ||
      !zeros(b + 345, 167) || !octal(b + 148, 8, &check) ||
      !octal(b + 124, 12, size))
    return 0;
  for (unsigned i = 0; i < BLOCK; ++i)
    sum += i >= 148 && i < 156 ? 32 : b[i];
  if (check != sum)
    return 0;
  for (unsigned i = 0; i < 6; ++i) {
    unsigned n = length(names[i]);
    if (!same(b, names[i], n) || !zeros(b + n, 100 - n))
      continue;
    if (*seen & (1u << i))
      return 0;
    *seen |= 1u << i;
    return 1;
  }
  return 0;
}
static int write_all(int fd, const byte *p, unsigned n) {
  while (n) {
    long k = writefd(fd, p, n);
    if (k == -4)
      continue;
    if (k <= 0 || (unsigned long)k > n)
      return 0;
    p += k;
    n -= (unsigned)k;
  }
  return 1;
}
static int verify_tar(struct stream *s, const byte *digest, int out_fd) {
  unsigned seen = 0, trailer = 0;
  u32 data = 0;
  byte b[BLOCK], computed[32];
  struct sha256 sha;
  sha_init(&sha);
  while (s->remaining) {
    if (!take(s, b, BLOCK))
      return 0;
    sha_add(&sha, b, BLOCK);
    if (data) {
      unsigned used = data > BLOCK ? BLOCK : data;
      if (!zeros(b + used, BLOCK - used))
        return 0;
      data -= used;
    } else if (zeros(b, BLOCK))
      ++trailer;
    else if (trailer || !tar_header(b, &seen, &data) || data > s->remaining)
      return 0;
    if (out_fd >= 0 && !write_all(out_fd, b, BLOCK))
      return 0;
  }
  if (!s->contiguous && next(s->v, &s->cluster) != 0)
    return 0;
  sha_end(&sha, computed);
  return seen == 63 && trailer >= 2 && !data && same(computed, digest, 32);
}
static int verify(const struct volume *v, const struct catalog *r,
                  const char *keyfile, const char *version, int deep,
                  const char *stage_dir, int *card_fd_io) {
  byte key[32], build[sizeof(BUILD) - 1], h[128];
  const struct item *f = &r->tar;
  if (r->markers || r->found != 1 || f->directory || f->first < 2 ||
      f->first > v->last || f->valid != f->size || f->size < 128 + BLOCK ||
      f->size > 128 + MAX_TAR || !exact_file(keyfile, key, 32) ||
      !exact_file(version, build, sizeof(build)) ||
      !same(build, BUILD, sizeof(build)))
    return 0;
  if (f->contiguous && (u64)(v->last - f->first + 1) * v->spc * BLOCK < f->size)
    return 0;
  struct stream s;
  s.v = v;
  s.cluster = f->first;
  s.pos = 0;
  s.remaining = (u32)f->size;
  s.contiguous = f->contiguous;
  s.visited[0] = f->first;
  s.count = 1;
  if (!take(&s, h, sizeof(h)) || !same(h, "M7SD1\0\0", 8) ||
      !same(h + 8, build, sizeof(build)) ||
      !zeros(h + 8 + sizeof(build), 24 - sizeof(build)) || !le32(h + 32) ||
      le32(h + 36) != s.remaining || (s.remaining % 512) ||
      !zeros(h + 40, 24) || !auth(h, key))
    return 0;
  if (!stage_dir)
    return !deep || verify_tar(&s, h + 64, -1);

  /* Authenticated extract: pin stage_dir via component-wise O_NOFOLLOW openat from "/",
   * check tmpfs magic + free RAM headroom on THAT open dirfd via fstatfs64, stream+verify
   * into card.tar.tmp via openat, close all fds cleanly, and renameat to card.tar. */
  int stage_fd = open_stage_dir_anchored(stage_dir);
  if (stage_fd < 0)
    return 0;
  struct space sp;
  if (!fspace_at(stage_fd, &sp) || sp.fstype != TMPFS_MAGIC_LINUX ||
      !sp.size || sp.avail > sp.free || sp.free > sp.blocks ||
      sp.blocks > UINT64_MAX / sp.size ||
      sp.free * sp.size < (u64)s.remaining + 65536ull) {
    closefd(stage_fd);
    return 0;
  }
  unlinkat_raw(stage_fd, "card.tar.tmp");
  int out_fd = create_excl_at(stage_fd, "card.tar.tmp");
  if (out_fd < 0) {
    closefd(stage_fd);
    return 0;
  }
  int ok = verify_tar(&s, h + 64, out_fd);
  if (closefd(out_fd) != 0)
    ok = 0;
  /* Close the card fd BEFORE publishing card.tar so exit code 1 can never follow a rename. */
  if (card_fd_io && *card_fd_io >= 0) {
    if (closefd(*card_fd_io) != 0)
      ok = 0;
    *card_fd_io = -1;
  }
  int published = ok && renameat_raw(stage_fd, "card.tar.tmp", stage_fd, "card.tar") == 0;
  if (!published)
    unlinkat_raw(stage_fd, "card.tar.tmp");
  return closefd(stage_fd) == 0 && published;
}
static int probe(const struct volume *v, const struct catalog *r,
                 const char *ram) {
  struct space s;
  /* The caller sees device/geometry even when statfs fails. */
  if (!put(v->exfat ? "FS_TYPE=exFAT" : "FS_TYPE=FAT32") || !put("\nBPS=512") ||
      !number("\nSPC=", v->spc) || !number("\nTOTAL_SECTORS=", v->sectors) ||
      !number("\nDATA_LBA=", v->heap) || !number("\nROOT_CLUSTER=", v->root) ||
      !number("\nMLV2_FOUND=", r->found) ||
      !number("\nMLV2_BYTES=", r->tar.valid) ||
      !number("\nMLV2_DATA_LEN=", r->tar.size) ||
      !number("\nDISABLE_MARKERS=", r->markers) || !put("\n"))
    return 0;
  if (!space_at(ram, &s) || !s.size || s.avail > s.free || s.free > s.blocks ||
      s.blocks > UINT64_MAX / s.size) {
    put("RAM_STATFS=ERROR\n");
    return 0;
  }
  return number("RAM_STATFS bsize=", s.size) && number(" blocks=", s.blocks) &&
         number(" bfree=", s.free) && number(" bavail=", s.avail) &&
         number(" free_bytes=", s.free * s.size) &&
         number(" total_bytes=", s.blocks * s.size) && put("\n");
}
static int reader_main(int argc, char **argv) {
  if (argc < 2)
    return 2;
  int diagnostic = eq(argv[1], "--probe"), deep = eq(argv[1], "--verify"),
      extract = eq(argv[1], "--extract");
  if (!diagnostic && !deep && !extract && !eq(argv[1], "--present"))
    return 2;
#ifndef S7_RAM_ROOT
#define S7_RAM_ROOT "/tmp_network"
#endif
#ifndef S7_OWNER_KEY_PATH
#define S7_OWNER_KEY_PATH "/setting/mlv2_sd.key"
#endif
  const char *key = S7_OWNER_KEY_PATH, *version = "/version.txt",
             *ram = S7_RAM_ROOT, *stage = S7_RAM_ROOT "/mlv2";
  for (int i = 2; i < argc; i += 2) {
    if (i + 1 >= argc || !*argv[i + 1])
      return 2;
    if (diagnostic && eq(argv[i], "--ram-path"))
      ram = argv[i + 1];
    else if (extract && eq(argv[i], "--stage"))
      stage = argv[i + 1];
    else if (!diagnostic && eq(argv[i], "--key"))
      key = argv[i + 1];
    else if (!diagnostic && eq(argv[i], "--version-file"))
      version = argv[i + 1];
    else
      return 2;
  }
#ifdef MLV2_HOST_TEST
  const char *path = getenv("MLV2_CARD_READ_IMAGE");
  if (!path || !*path)
    return 3;
#else
  const char *path = "/dev/mmca1";
#endif
  if (timer())
    return 3;
  int fd = ro(path);
  if (fd < 0) {
    if (diagnostic)
      put("DEV_OK=0\n");
    return 3;
  }
  struct volume v = {.fd = fd};
  struct catalog r = {0};
  int ok = is_card(fd);
  if (diagnostic)
    ok = put(ok ? "DEV_OK=1\n" : "DEV_OK=0\n") && ok;
  if (ok)
    ok = vbr(&v) && scan(&v, &r);
  if (ok)
    ok = diagnostic
             ? probe(&v, &r, ram)
             : verify(&v, &r, key, version, deep || extract,
                      extract ? stage : 0, extract ? &fd : 0);
  int closed_ok = (fd < 0) ? 1 : (closefd(fd) == 0);
  return closed_ok && ok ? 0 : 1;
}
#ifdef MLV2_HOST_TEST
int main(int argc, char **argv) { return reader_main(argc, argv); }
#else
__attribute__((used, noreturn)) static void run(long *sp) {
  int rc = reader_main((int)sp[0], (char **)(sp + 1));
  call(1, rc, 0, 0, 0, 0);
  __builtin_unreachable();
}
__attribute__((naked, noreturn)) void _start(void) {
  __asm__ volatile("mov r0, sp\n b run");
}
#endif
