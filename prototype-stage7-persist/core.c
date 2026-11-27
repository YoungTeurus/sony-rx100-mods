/* Mod Loader v2 core for DSC-RX100M7 1.00 (position-independent, loaded by shim).
 *
 * Adapted from sources/bionz-x-research/tools/native_camera/mlv2/core.c:
 * - Builds the 7th "Mods" tab with fake menu nodes + SMNU submenu support.
 * - Scans ONLY /tmp_network/mods (RAM-staged mods; never auto-loads arbitrary SD files).
 * - Uses verified M7 1.00 viewUnified2.so (MLV2_SET_TEXT, MLV2_MENU_REFRESH) and
 *   libObj.so (g_pEvtMgr, _Znwj, Event::Event, EventManager::push) addresses.
 * - Reuses stock tab 6 icon safely (M7 has no v1 ModsTabLook hook).
 * - Clean sd-disabled teardown: switches all enabled mods OFF, restores orig_root to
 *   6 stock tabs on set_root, and writes /tmp_network/mlv2/sd-stopped.
 */
#include "mlv2.h"
#include "mlv2_sys.h"
#include "stage7_common.h"

#define CTX_MAGIC    MLV2_CTX_MAGIC
#define CTX_VERSION  5u
#define MAX_MODS     16u
#define MAX_PAGES    3u
#define MAX_FOLDERS  4u
#define KIND_V1      1u
#define KIND_V2      2u

typedef struct Node {
    void   **vtable;
    void   **children;
    int32_t  child_count;
    void    *props;
    void    *parent;
    uint32_t layer_depth;
    int32_t  selected_idx;
    uint32_t s1c, s20, s24;
} Node;

typedef struct {
    uint32_t target;
    uint8_t  size, fixup, pad[2];
    uint8_t  orig[SMOD_MAX_PATCH];
    uint8_t  patch[SMOD_MAX_PATCH];
} Hook;

typedef struct {
    char     name[32];
    char     path[80];
    char     folder[24];
    uint32_t fnv;
    uint8_t  kind, enabled, invalid, flags;
    uint8_t  hook_count, present, stale, off_called;
    uint32_t code_size;
    uint32_t extra_size;
    uint32_t addr;
    uint32_t map_size;
    uint32_t state_addr;
    uint32_t on_off, off_off;
    uint32_t data_off;
    Hook     hooks[SMOD_MAX_HOOKS];
    uint8_t  sub_count, sub_bss_off, sub_pad[2];
    uint8_t  sub_vals[SMOD_SUBMENU_MAX_ITEMS];
    uint32_t sub_cfg_off;
    SmodSubmenuItem sub_items[SMOD_SUBMENU_MAX_ITEMS];
} Mod;

typedef struct {
    Node    *root;
    void   **orig_children;
    int32_t  orig_child_count;
} TrackedRoot;

typedef struct {
    uint32_t magic, version;
    uint32_t mod_count, page_count;
    uint32_t vtable_ready;
    int32_t  sub_mod;
    Node    *orig_root;
    uint32_t tracked_count;
    TrackedRoot tracked[MLV2_MAX_TRACKED_ROOTS];
    Node    *orig_tab5;
    uint32_t last_menu;
    void    *vtable[72];
    void    *root_children[8];
    Node     tab_node;
    Node     pages[MAX_PAGES];
    Node     items[MAX_MODS];
    Node     opts[2];
    void    *page_ptrs[MAX_PAGES];
    void    *item_ptrs[MAX_MODS];
    void    *opt_ptrs[2];
    Mod      mods[MAX_MODS];
    Mod      scan[MAX_MODS];
    Mod      keep[MAX_MODS];
    Mod      tmp;
    uint32_t scan_count;
    uint8_t  scan_buf[512];
    uint32_t folder_count, view_count;
    char     folder_names[MAX_FOLDERS][24];
    int16_t  view_map[MAX_MODS];
    uint8_t  in_folder;
    uint8_t  need_rehydrate;
    uint8_t  persist_dirty;
    uint8_t  persist_armed_dest; /* Destinations last confirmed or hydrated as ON. */
} Ctx;

#define PERSIST_DIRTY_SETTING  1u
#define PERSIST_DIRTY_SIM      2u
#define PERSIST_DIRTY_RUNTIME  4u
#define PERSIST_DIRTY_GATE_ERR 8u

#define CTX_BYTES ((sizeof(Ctx) + 0xfffu) & ~0xfffu)
_Static_assert(sizeof(TrackedRoot) == 12u, "TrackedRoot ABI size");
_Static_assert(__builtin_offsetof(Ctx, orig_root) == MLV2_CTX_ORIG_ROOT_OFF, "Ctx.orig_root offset");
_Static_assert(__builtin_offsetof(Ctx, tracked_count) == MLV2_CTX_TRACKED_CNT_OFF, "Ctx.tracked_count offset");
_Static_assert(__builtin_offsetof(Ctx, tracked) == MLV2_CTX_TRACKED_OFF, "Ctx.tracked offset");
_Static_assert(__builtin_offsetof(Ctx, root_children) == MLV2_CTX_ROOT_CHILDREN_OFF, "Ctx.root_children offset");

/* Written once by core_init before hooks are registered; read PC-relative. */
__attribute__((section(".text.zdata"), used)) static volatile uint32_t core_view_bias = 0;
__attribute__((section(".text.zdata"), used)) static volatile uint32_t core_slot = 0;
__attribute__((section(".text.zdata"), used)) static volatile uint32_t core_libobj_bias = 0;
__attribute__((section(".text.zdata"), used)) static volatile uint32_t core_libobj_ok = 0;

#define VIEW(a) ((uint32_t)(a) + core_view_bias)

/* Verified M7 1.00 libObj.so event symbols (see m7_100_layout.py). */
#define REF_EVMGR_DIRECT (MLV2_REF_LIBOBJ_BASE + 0x0145ce10u)
#define REF_OP_NEW       (MLV2_REF_LIBOBJ_BASE + 0x00108c50u)  /* ARM PLT stub for _Znwj */
#define REF_EV_CTOR      (MLV2_REF_LIBOBJ_BASE + 0x0089ac65u)  /* Thumb _ZN5EventC1Emhh */
#define REF_EVMGR_PUSH   (MLV2_REF_LIBOBJ_BASE + 0x0089c211u)  /* Thumb _ZN12EventManager4pushEP5Eventb */
#define KEY_MENU_EVENT   0x15010102u

static Ctx *ctx_get(void) {
    if (!core_slot) return 0;
    ShimState *s = *(ShimState *volatile *)core_slot;
    if (!s || s->magic != MLV2_SHIM_MAGIC) return 0;
    Ctx *c = (Ctx *)s->ctx;
    return (c && c->magic == CTX_MAGIC) ? c : 0;
}

static volatile uint32_t *core_log_lock(void) {
    if (!core_slot) return 0;
    ShimState *s = *(ShimState *volatile *)core_slot;
    return (s && s->magic == MLV2_SHIM_MAGIC) ? &s->log_lock : 0;
}

#undef ml_log
#define ml_log(msg, val) ml_log_to_locked(core_log_lock(), MLV2_LOG_PATH, ML_O_WR_CREAT_APP, (msg), (val))

/* ---------------- fake menu node vtable entries ---------------- */
static int node_ret0(void) { return 0; }
static int node_ret1(void) { return 1; }
static int node_child_count(Node *n, int32_t *out) { *out = n->child_count; return 1; }
static int node_child(Node *n, int32_t idx1, void **out) {
    if (idx1 >= 1 && idx1 <= n->child_count) { *out = n->children[idx1 - 1]; return 1; }
    *out = 0;
    return 0;
}
static int node_cur_child(Node *n, void **out) {
    if (n->child_count > 0) { *out = n->children[0]; return 1; }
    *out = 0;
    return 0;
}
static int node_cur_idx(Node *n, int32_t *out) { (void)n; *out = 1; return 1; }

static int node_int_prop(Node *n, int32_t prop, int32_t *out) {
    if (prop == 11) { *out = 0; return 1; }
    Ctx *c = ctx_get();
    if (!c) return 0;
    if (prop == 12 && (uint32_t)n >= (uint32_t)&c->items[0] && (uint32_t)n < (uint32_t)&c->items[MAX_MODS]) {
        *out = 0;
        return 1;
    }
    if (n == &c->tab_node && c->orig_tab5) {
        typedef int (*fn_t)(void *, int32_t, int32_t *);
        return ((fn_t)c->orig_tab5->vtable[23])(c->orig_tab5, prop, out);
    }
    return 0;
}

static int node_resid_prop(Node *n, int32_t prop, uint32_t *out) {
    Ctx *c = ctx_get();
    if (c && n == &c->tab_node && (prop == 2 || prop == 29 || prop == 30 || prop == 31) && c->orig_tab5) {
        typedef int (*fn_t)(void *, int32_t, uint32_t *);
        return ((fn_t)c->orig_tab5->vtable[32])(c->orig_tab5, prop, out);
    }
    *out = 0;
    return 0;
}

static int node_is_disabled(Node *n, uint8_t *out) { (void)n; if (out) *out = 0; return 0; }

static void vtable_bind(Ctx *c) {
    if (!c->vtable_ready) {
        for (uint32_t i = 0; i < 72u; i++) c->vtable[i] = (void *)node_ret0;
        c->vtable[4] = (void *)node_child_count;
        c->vtable[9] = (void *)node_child;
        c->vtable[10] = (void *)node_cur_child;
        c->vtable[12] = (void *)node_cur_idx;
    } else {
        for (uint32_t i = 65u; i < 72u; i++) c->vtable[i] = (void *)node_ret0;
        c->vtable[35] = (void *)node_ret1;
    }
    c->vtable[23] = (void *)node_int_prop;
    c->vtable[32] = (void *)node_resid_prop;
    c->vtable[40] = (void *)node_is_disabled;
}

/* ---------------- scanning ---------------- */
struct dirent64 { uint64_t ino; int64_t off; uint16_t reclen; uint8_t type; char name[1]; };

static int ends_with_mod(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n > 4 && s[n - 4] == '.' && s[n - 3] == 'm' && s[n - 2] == 'o' && s[n - 1] == 'd';
}

static void join(char *out, uint32_t cap, const char *dir, const char *file) {
    uint32_t i = 0;
    while (*dir && i + 2u < cap) out[i++] = *dir++;
    out[i++] = '/';
    while (*file && i + 1u < cap) out[i++] = *file++;
    out[i] = 0;
}

static const char *base_name(const char *p) {
    const char *b = p;
    for (; *p; p++) if (*p == '/') b = p + 1;
    return b;
}

static int already_listed(Ctx *c, const char *path) {
    for (uint32_t i = 0; i < c->scan_count; i++)
        if (!ml_strcmp(base_name(c->scan[i].path), base_name(path))) return 1;
    return 0;
}

/* ---------------- SMOD v2 relocation (SMOD_V2_FLAG_RELOC) ---------------- */
static int maps_bases(const SmodRelocLib *libs, uint32_t n, uint32_t *base) {
    for (uint32_t i = 0; i < n; i++) base[i] = 0;
    int fd = ml_open("/proc/self/maps", ML_O_RDONLY);
    if (fd < 0) return 0;
    char buf[512], line[200];
    uint32_t len = 0;
    int got;
    while ((got = ml_read(fd, buf, sizeof(buf))) > 0) {
        for (int k = 0; k < got; k++) {
            char ch = buf[k];
            if (ch != '\n') { if (len + 1u < sizeof(line)) line[len++] = ch; continue; }
            line[len] = 0;
            uint32_t lo = 0, off = 0, i = 0;
            while (line[i] && line[i] != '-') {
                char chx = line[i++];
                lo = lo * 16u + (uint32_t)(chx <= '9' ? chx - '0' : (chx | 0x20) - 'a' + 10);
            }
            while (line[i] && line[i] != ' ') i++;
            while (line[i] == ' ') i++;
            while (line[i] && line[i] != ' ') i++;
            while (line[i] == ' ') i++;
            while (line[i] && line[i] != ' ') {
                char chx = line[i++];
                off = off * 16u + (uint32_t)(chx <= '9' ? chx - '0' : (chx | 0x20) - 'a' + 10);
            }
            const char *path = 0;
            for (uint32_t j = i; line[j]; j++) if (line[j] == '/') { path = line + j; break; }
            if (path && !off) {
                const char *leaf = base_name(path);
                for (uint32_t li = 0; li < n; li++)
                    if (!base[li] && !ml_strcmp(leaf, libs[li].name)) base[li] = lo;
            }
            len = 0;
        }
    }
    ml_close(fd);
    for (uint32_t i = 0; i < n; i++) if (!base[i]) return 0;
    return 1;
}

static int reloc_apply(int fd, uint32_t code_size, uint8_t *code, SmodRelocLib *libs, uint32_t *bias,
                       uint32_t *nlib_out) {
    uint32_t hdr[2], base[SMOD_RELOC_MAX_LIBS];
    if (ml_read(fd, hdr, 8) != 8 || hdr[0] != SMOD_RELOC_MAGIC) return -1;
    uint32_t nlib = hdr[1] & 0xffffu, nrel = hdr[1] >> 16;
    if (!nlib || nlib > SMOD_RELOC_MAX_LIBS || nrel > SMOD_RELOC_MAX) return -1;
    *nlib_out = nlib;
    uint32_t h = ml_fnv1a((const uint8_t *)hdr, 8);
    if (ml_read(fd, libs, nlib * sizeof(SmodRelocLib)) != (int)(nlib * sizeof(SmodRelocLib))) return -1;
    h = ml_fnv1a_more(h, (const uint8_t *)libs, nlib * sizeof(SmodRelocLib));
    for (uint32_t i = 0; i < nlib; i++) {
        libs[i].name[23] = 0;
        if (libs[i].ref_hi <= libs[i].ref_lo) return -1;
    }
    int have_bases = maps_bases(libs, nlib, base);
    if (have_bases) {
        for (uint32_t i = 0; i < nlib; i++) bias[i] = base[i] - libs[i].ref_lo;
    }
    uint32_t words[64];
    for (uint32_t done = 0; done < nrel;) {
        uint32_t chunk = nrel - done > 64u ? 64u : nrel - done;
        if (ml_read(fd, words, chunk * 4u) != (int)(chunk * 4u)) return -1;
        h = ml_fnv1a_more(h, (const uint8_t *)words, chunk * 4u);
        for (uint32_t k = 0; k < chunk; k++) {
            uint32_t off = words[k] & 0xffffffu, lib = words[k] >> 24;
            if (lib >= nlib || (off & 3u) || off + 4u > code_size) return -1;
            if (code && have_bases) {
                uint32_t w;
                ml_memcpy(&w, code + off, 4);
                w += bias[lib];
                ml_memcpy(code + off, &w, 4);
            }
        }
        done += chunk;
    }
    uint32_t want;
    if (ml_read(fd, &want, 4) != 4 || want != h) return -1;
    if (!have_bases) return -2;
    return (int)nrel;
}

static int submenu_parse(int fd, Mod *m) {
    SmodSubmenuHeader sh;
    if (ml_read(fd, &sh, sizeof(sh)) != (int)sizeof(sh) || sh.magic != SMOD_SUBMENU_MAGIC) return 0;
    if (!sh.item_count || sh.item_count > SMOD_SUBMENU_MAX_ITEMS) return 0;
    if ((uint32_t)sh.bss_cfg_off + (uint32_t)sh.item_count > m->extra_size) return 0;
    if (sh.cfg_call_off && (!(sh.cfg_call_off & 1u) || sh.cfg_call_off >= m->code_size)) return 0;
    uint32_t bytes = (uint32_t)sh.item_count * (uint32_t)sizeof(SmodSubmenuItem);
    if (ml_read(fd, m->sub_items, bytes) != (int)bytes) return 0;
    uint32_t h = ml_fnv1a((const uint8_t *)&sh, sizeof(sh));
    h = ml_fnv1a_more(h, (const uint8_t *)m->sub_items, bytes);
    uint32_t want = 0;
    if (ml_read(fd, &want, 4) != 4 || want != h) return 0;
    for (uint32_t i = 0; i < sh.item_count; i++) {
        SmodSubmenuItem *it = &m->sub_items[i];
        if (it->opt_count < 2u || it->opt_count > SMOD_SUBMENU_MAX_OPTS || it->default_val >= it->opt_count)
            return 0;
        it->label[23] = 0;
        for (uint32_t k = 0; k < SMOD_SUBMENU_MAX_OPTS; k++) it->opts[k][17] = 0;
        m->sub_vals[i] = it->default_val;
    }
    m->sub_count = sh.item_count;
    m->sub_bss_off = sh.bss_cfg_off;
    m->sub_cfg_off = sh.cfg_call_off;
    return 1;
}

static int parse_mod(const char *path, Mod *m) {
    int fd = ml_open(path, ML_O_RDONLY | ML_O_NONBLOCK | ML_O_NOFOLLOW);
    if (fd < 0) return 0;
    if (!ml_fd_is_regular(fd)) { ml_close(fd); return 0; }
    uint8_t hdr[68];
    int ok = ml_read(fd, hdr, sizeof(hdr)) == (int)sizeof(hdr);
    const SmodV1Header *h1 = (const SmodV1Header *)hdr;
    const SmodV2Header *h2 = (const SmodV2Header *)hdr;
    ml_memset(m, 0, sizeof(*m));
    if (ok && h1->magic == SMOD_MAGIC && h1->version == 1u && h1->hook_count <= SMOD_MAX_HOOKS &&
        h1->code_size && !(h1->code_size & 3u) && h1->code_addr >= 0x00100000u) {
        m->kind = KIND_V1;
        m->flags = (uint8_t)h1->flags;
        m->hook_count = (uint8_t)h1->hook_count;
        m->code_size = h1->code_size;
        m->extra_size = h1->state_size;
        m->addr = h1->code_addr;
        m->state_addr = h1->state_addr;
        m->fnv = h1->fnv1a_32;
        ml_memcpy(m->name, h1->name, 31);
        for (uint32_t i = 0; i < m->hook_count && ok; i++) {
            SmodV1Hook hk;
            ok = ml_read(fd, &hk, sizeof(hk)) == (int)sizeof(hk) && hk.patch_size >= 1u &&
                 hk.patch_size <= SMOD_MAX_PATCH && hk.target_addr >= 0x00100000u;
            if (!ok) break;
            m->hooks[i].target = hk.target_addr;
            m->hooks[i].size = (uint8_t)hk.patch_size;
            m->hooks[i].fixup = SMOD_V2_NO_FIXUP;
            ml_memcpy(m->hooks[i].orig, hk.orig_bytes, SMOD_MAX_PATCH);
            ml_memcpy(m->hooks[i].patch, hk.hook_bytes, SMOD_MAX_PATCH);
        }
        m->data_off = 68u + m->hook_count * 40u;
    } else if (ok && h2->magic == SMOD_MAGIC && h2->version == 2u && h2->hook_count <= SMOD_MAX_HOOKS &&
               h2->code_size && !(h2->code_size & 3u) && h2->code_size + h2->bss_size <= 1024u * 1024u &&
               (!h2->on_off || ((h2->on_off & 1u) && h2->on_off < h2->code_size)) &&
               (!h2->off_off || ((h2->off_off & 1u) && h2->off_off < h2->code_size))) {
        m->kind = KIND_V2;
        m->flags = (uint8_t)h2->flags;
        m->hook_count = (uint8_t)h2->hook_count;
        m->code_size = h2->code_size;
        m->extra_size = h2->bss_size;
        m->on_off = h2->on_off;
        m->off_off = h2->off_off;
        m->fnv = h2->fnv1a_32;
        ml_memcpy(m->name, h2->name, 31);
        for (uint32_t i = 0; i < m->hook_count && ok; i++) {
            SmodV2Hook hk;
            ok = ml_read(fd, &hk, sizeof(hk)) == (int)sizeof(hk) && hk.patch_size >= 1u &&
                 hk.patch_size <= SMOD_MAX_PATCH && hk.target_addr >= 0x00100000u &&
                 (hk.fixup_off == SMOD_V2_NO_FIXUP || hk.fixup_off + 4u <= hk.patch_size);
            if (!ok) break;
            m->hooks[i].target = hk.target_addr;
            m->hooks[i].size = hk.patch_size;
            m->hooks[i].fixup = hk.fixup_off;
            ml_memcpy(m->hooks[i].orig, hk.orig_bytes, SMOD_MAX_PATCH);
            ml_memcpy(m->hooks[i].patch, hk.tmpl, SMOD_MAX_PATCH);
        }
        m->data_off = 68u + m->hook_count * 40u;
        if (ok && (m->flags & SMOD_V2_FLAG_RELOC)) {
            SmodRelocLib libs[SMOD_RELOC_MAX_LIBS];
            uint32_t bias[SMOD_RELOC_MAX_LIBS];
            ml_lseek(fd, m->data_off + m->code_size);
            uint32_t nlib = 0;
            int nrel = reloc_apply(fd, m->code_size, 0, libs, bias, &nlib);
            if (nrel == -2) {
                m->invalid = 1;
                ml_log("reloc_nolib", 0);
            } else if (nrel < 0) {
                ok = 0;
            } else {
                for (uint32_t i = 0; i < m->hook_count; i++)
                    for (uint32_t li = 0; li < nlib; li++)
                        if (m->hooks[i].target >= libs[li].ref_lo && m->hooks[i].target < libs[li].ref_hi) {
                            m->hooks[i].target += bias[li];
                            break;
                        }
            }
        }
        if (ok && (m->flags & SMOD_V2_FLAG_SUBMENU)) {
            if (m->flags & SMOD_V2_FLAG_ACTION) {
                ok = 0;
            } else {
                if (!(m->flags & SMOD_V2_FLAG_RELOC)) ml_lseek(fd, m->data_off + m->code_size);
                if (!submenu_parse(fd, m)) ok = 0;
            }
        }
    } else {
        ok = 0;
    }
    ml_close(fd);
    if (!ok) { ml_log("scan_bad", h1->magic); return 0; }
    ml_memset(m->path, 0, sizeof(m->path));
    for (uint32_t k = 0; k < sizeof(m->path) - 1u && path[k]; k++) m->path[k] = path[k];
    m->name[31] = 0;
    m->present = 1;
    return 1;
}

static void scan_mods_in(Ctx *c, const char *dir, const char *folder) {
    int dfd = ml_open(dir, ML_O_RDONLY | ML_O_DIRECTORY | ML_O_NOFOLLOW);
    if (dfd < 0) return;
    char sub_paths[MAX_FOLDERS][80];
    char sub_names[MAX_FOLDERS][24];
    uint32_t nsub = 0;
    int n;
    while ((n = ml_getdents64(dfd, c->scan_buf, sizeof(c->scan_buf))) > 0 && c->scan_count < MAX_MODS) {
        for (int pos = 0; pos < n && c->scan_count < MAX_MODS;) {
            struct dirent64 *d = (struct dirent64 *)(c->scan_buf + pos);
            if (d->reclen < 20u || pos + (int)d->reclen > n) break;
            pos += d->reclen;
            if (d->name[0] == '.') continue;
            char path[80];
            join(path, sizeof(path), dir, d->name);
            if (!folder && d->type == 4u && !ends_with_mod(d->name)) {
                if (nsub < MAX_FOLDERS) {
                    ml_memcpy(sub_paths[nsub], path, sizeof(sub_paths[nsub]));
                    ml_memset(sub_names[nsub], 0, sizeof(sub_names[nsub]));
                    for (uint32_t k = 0; k < 23u && d->name[k]; k++) sub_names[nsub][k] = d->name[k];
                    nsub++;
                }
                continue;
            }
            if (!ends_with_mod(d->name)) continue;
            if (already_listed(c, path)) continue;
            Mod *m = &c->scan[c->scan_count];
            if (parse_mod(path, m)) {
                ml_memset(m->folder, 0, sizeof(m->folder));
                if (folder) {
                    for (uint32_t k = 0; k < 23u && folder[k]; k++) m->folder[k] = folder[k];
                }
                c->scan_count++;
            }
        }
    }
    ml_close(dfd);
    for (uint32_t s = 0; s < nsub && c->scan_count < MAX_MODS; s++)
        scan_mods_in(c, sub_paths[s], sub_names[s]);
}

static int is_action(const Mod *m) { return m->kind == KIND_V2 && (m->flags & SMOD_V2_FLAG_ACTION); }
static int has_submenu(const Mod *m) {
    return m->kind == KIND_V2 && (m->flags & SMOD_V2_FLAG_SUBMENU) && m->sub_count > 0u;
}
static int is_precap_mod(const Mod *m) {
    return !ml_strcmp(base_name(m->path), "PreCapture.mod") &&
           has_submenu(m) && m->sub_count == 1u && m->sub_items[0].opt_count == 6u;
}

static uint8_t persist_dest_bit(int dest_id) {
    if (dest_id == 1) return PERSIST_DIRTY_SETTING;
    if (dest_id == 2) return PERSIST_DIRTY_SIM;
    return 0u;
}

static void clear_persist_dirty_for(Ctx *c, int dest_id) {
    uint8_t cleared = PERSIST_DIRTY_RUNTIME;
    if (dest_id) cleared |= persist_dest_bit(dest_id) | PERSIST_DIRTY_GATE_ERR;
    c->persist_dirty &= (uint8_t)~cleared;
}

/* Inspect the gate only: 0 = absent, 1 = setting, 2 = sim, -1 = invalid or unreadable. */
static int read_persist_gate_dest(void) {
    char gate[64];
    long fd = -4;
    for (unsigned tries = 0u; tries < 8u && fd == -4; ++tries) {
        fd = s7_file_call(S7_OPEN, (long)PRECAP_PERSIST_GATE, S7_NONBLOCK | S7_NOFOLLOW, 0);
    }
    if (fd == -2) return 0;
    if (fd < 0) {
        ml_log("persist_gate_err", (uint32_t)(-fd));
        return -1;
    }
    if (!s7_fd_is_regular(fd)) {
        s7_file_call(S7_CLOSE, fd, 0, 0);
        ml_log("persist_gate_err", 0xfeu);
        return -1;
    }
    unsigned used = 0u;
    int read_ok = 1;
    while (used < sizeof(gate)) {
        long n = s7_file_call(S7_READ, fd, (long)(gate + used), (long)(sizeof(gate) - used));
        if (n == -4) continue;
        if (n < 0) { read_ok = 0; break; }
        if (n == 0) break;
        used += (unsigned)n;
    }
    long closed = s7_file_call(S7_CLOSE, fd, 0, 0);
    if (!read_ok || closed < 0 || used == 0u || used >= sizeof(gate)) {
        ml_log("persist_gate_err", 0xffu);
        return -1;
    }

    const unsigned len_set = (unsigned)(sizeof(PRECAP_PERSIST_SETTING "\n") - 1u);
    const unsigned len_sim = (unsigned)(sizeof(PRECAP_PERSIST_SIM "\n") - 1u);
    if (used == len_set && ml_memcmp(gate, PRECAP_PERSIST_SETTING "\n", len_set) == 0) return 1;
    if (used == len_sim && ml_memcmp(gate, PRECAP_PERSIST_SIM "\n", len_sim) == 0) return 2;
    ml_log("persist_bad_gate", used);
    return -1;
}

/* Compensation must re-authorize the same destination as the forward write. */
static int persist_precap_if_authorized(Ctx *c, int enabled, unsigned frames, int required_dest, int *out_dest) {
    if (out_dest) *out_dest = 0;
    int dest_id = read_persist_gate_dest();
    if (dest_id < 0) return 0;
    if (dest_id == 0) {
        if (required_dest) ml_log("persist_gate_gone", (uint32_t)required_dest);
        return required_dest == 0;
    }
    if (required_dest != 0 && dest_id != required_dest) {
        ml_log("persist_gate_changed", ((uint32_t)required_dest << 8) | (uint32_t)dest_id);
        return 0;
    }
    if (out_dest) *out_dest = dest_id;

    const char *dst = dest_id == 1 ? PRECAP_PERSIST_SETTING : PRECAP_PERSIST_SIM;
    const char *tmp = dest_id == 1 ? PRECAP_PERSIST_SETTING_TMP : PRECAP_PERSIST_SIM_TMP;
    int cur_en = 0;
    unsigned cur_fr = 0u;
    int matches = s7_parse_precap_record(dst, &cur_en, &cur_fr) && cur_en == enabled && cur_fr == frames;
    if (!matches) {
        if (!s7_write_precap_record(dst, tmp, enabled, frames, 1)) {
            ml_log("persist_err", ((uint32_t)(enabled ? 1u : 0u) << 8) | frames);
            return 0;
        }
        ml_log("persist_ok", ((uint32_t)(enabled ? 1u : 0u) << 8) | frames);
    }
    if (c) {
        if (enabled) c->persist_armed_dest |= persist_dest_bit(dest_id);
        else c->persist_armed_dest &= (uint8_t)~persist_dest_bit(dest_id);
    }
    return 1;
}

/* M7 1.00 scans ONLY RAM-staged /tmp_network/mods (never arbitrary SD folders). */
static void rescan(Ctx *c) {
    c->scan_count = 0;
    scan_mods_in(c, MLV2_MODS_DIR, 0);
    Mod *out = c->scan;
    Mod *keep = c->keep;
    uint32_t keep_n = 0;
    for (uint32_t i = 0; i < c->mod_count; i++) {
        Mod *m = &c->mods[i];
        if (!m->enabled) continue;
        m->present = 0;
        m->stale = 0;
        for (uint32_t j = 0; j < c->scan_count; j++)
            if (!ml_strcmp(out[j].path, m->path)) {
                m->present = 1;
                m->stale = out[j].fnv != m->fnv;
                out[j].present = 2;
            }
        ml_memcpy(&keep[keep_n++], m, sizeof(Mod));
    }
    for (uint32_t j = 0; j < c->scan_count && keep_n < MAX_MODS; j++) {
        if (out[j].present == 2) continue;
        Mod *nm = &out[j];
        int known = 0;
        for (uint32_t i = 0; i < c->mod_count; i++)
            if (!ml_strcmp(c->mods[i].path, nm->path)) known = 1;
        if (!known && nm->kind == KIND_V2 && (nm->flags & SMOD_V2_FLAG_AUTO_ON) &&
            !(nm->flags & SMOD_V2_FLAG_ACTION) && !nm->invalid)
            nm->present = 3;
        for (uint32_t i = 0; i < c->mod_count; i++) {
            Mod *old = &c->mods[i];
            if (old->enabled || ml_strcmp(old->path, nm->path)) continue;
            if (old->fnv == nm->fnv) {
                nm->invalid = old->invalid;
                if (nm->sub_count && old->sub_count == nm->sub_count)
                    ml_memcpy(nm->sub_vals, old->sub_vals, SMOD_SUBMENU_MAX_ITEMS);
            }
            if (old->kind == KIND_V2 && nm->kind == KIND_V2 && old->addr &&
                old->map_size >= nm->code_size + nm->extra_size) {
                nm->addr = old->addr;
                nm->map_size = old->map_size;
            }
        }
        /* Hydrate PreCapture.mod UI state from validated runtime precap.cfg on initial
         * discovery, after sd-disabled reactivation (both ON/N and OFF/N), or when armed. */
        if (is_precap_mod(nm) && !nm->invalid) {
            int pen = 0;
            unsigned pfr = 0u;
            if (s7_parse_precap_record(PRECAP_CFG, &pen, &pfr)) {
                unsigned pidx = s7_frames_to_index(pfr);
                if (pidx < nm->sub_items[0].opt_count && (!known || c->need_rehydrate || pen)) {
                    nm->sub_vals[0] = (uint8_t)pidx;
                    if (pen) {
                        int gdest = read_persist_gate_dest();
                        if (gdest > 0) c->persist_armed_dest |= persist_dest_bit(gdest);
                        nm->present = 3;
                    }
                }
            }
        }
        ml_memcpy(&keep[keep_n++], nm, sizeof(Mod));
    }
    for (uint32_t i = 1; i < keep_n; i++)
        for (uint32_t k = i; k > 0 && ml_strcmp(keep[k - 1].name, keep[k].name) > 0; k--) {
            ml_memcpy(&c->tmp, &keep[k], sizeof(Mod));
            ml_memcpy(&keep[k], &keep[k - 1], sizeof(Mod));
            ml_memcpy(&keep[k - 1], &c->tmp, sizeof(Mod));
        }
    for (uint32_t i = 0; i < keep_n; i++) ml_memcpy(&c->mods[i], &keep[i], sizeof(Mod));
    c->mod_count = keep_n;
    c->need_rehydrate = 0u;
}

/* ---------------- menu tree ---------------- */
static void rebuild_view(Ctx *c) {
    c->folder_count = 0;
    for (uint32_t i = 0; i < c->mod_count; i++) {
        const char *f = c->mods[i].folder;
        if (!f[0]) continue;
        int seen = 0;
        for (uint32_t k = 0; k < c->folder_count; k++)
            if (!ml_strcmp(c->folder_names[k], f)) seen = 1;
        if (!seen && c->folder_count < MAX_FOLDERS)
            ml_memcpy(c->folder_names[c->folder_count++], f, 24u);
    }
    if (c->in_folder > c->folder_count) c->in_folder = 0;
    uint32_t n = 0;
    if (!c->in_folder) {
        for (uint32_t f = 0; f < c->folder_count && n < MAX_MODS; f++)
            c->view_map[n++] = (int16_t)(-(int16_t)(f + 2u));
        for (uint32_t i = 0; i < c->mod_count && n < MAX_MODS; i++)
            if (!c->mods[i].folder[0]) c->view_map[n++] = (int16_t)i;
    } else {
        const char *fname = c->folder_names[c->in_folder - 1u];
        c->view_map[n++] = -1;
        for (uint32_t i = 0; i < c->mod_count && n < MAX_MODS; i++)
            if (!ml_strcmp(c->mods[i].folder, fname)) c->view_map[n++] = (int16_t)i;
    }
    c->view_count = n;
}

static void build_tree(Ctx *c) {
    uint32_t n_items;
    if (c->sub_mod >= 0 && (uint32_t)c->sub_mod < c->mod_count && has_submenu(&c->mods[c->sub_mod])) {
        n_items = 2u + (uint32_t)c->mods[c->sub_mod].sub_count;
    } else {
        c->sub_mod = -1;
        n_items = c->view_count ? c->view_count : 1u;
    }
    uint32_t n_pages = n_items > 12u ? 3u : (n_items > 6u ? 2u : 1u);
    c->page_count = n_pages;
    for (uint32_t i = 0; i < n_items && i < MAX_MODS; i++) {
        uint32_t pg_idx = i >= 12u ? 2u : (i >= 6u ? 1u : 0u);
        uint32_t pos1 = i - pg_idx * 6u + 1u;
        Node *it = &c->items[i];
        it->vtable = c->vtable;
        it->children = c->opt_ptrs;
        it->child_count = 2;
        it->parent = &c->pages[pg_idx];
        it->layer_depth = 4;
        it->selected_idx = 1;
        it->s1c = it->s20 = pos1;
        it->s24 = 1;
        c->item_ptrs[i] = it;
    }
    for (uint32_t o = 0; o < 2u; o++) {
        Node *op = &c->opts[o];
        op->vtable = c->vtable;
        op->children = 0;
        op->child_count = 0;
        op->parent = &c->items[0];
        op->selected_idx = -1;
        op->s1c = op->s20 = o + 1u;
        op->s24 = o ? 1u : 2u;
        c->opt_ptrs[o] = op;
    }
    for (uint32_t p = 0; p < n_pages; p++) {
        uint32_t start = p * 6u, rem = n_items - start;
        Node *pg = &c->pages[p];
        pg->vtable = c->vtable;
        pg->children = &c->item_ptrs[start];
        pg->child_count = (int32_t)(rem > 6u ? 6u : rem);
        pg->parent = &c->tab_node;
        pg->layer_depth = 3;
        pg->selected_idx = 1;
        pg->s1c = pg->s20 = p + 1u;
        pg->s24 = 1;
        c->page_ptrs[p] = pg;
    }
    c->tab_node.vtable = c->vtable;
    c->tab_node.children = c->page_ptrs;
    c->tab_node.child_count = (int32_t)n_pages;
    c->tab_node.layer_depth = 2;
    c->tab_node.selected_idx = 1;
    c->tab_node.s1c = c->tab_node.s20 = 7;
    c->tab_node.s24 = 1;
}

static void toggle(Mod *m);
static int process_reload(Ctx *c);

static int sd_disabled(Ctx *c) {
    if (!ml_is_disabled()) return 0;
    c->need_rehydrate = 1u;
    c->persist_dirty = 0u;
    c->persist_armed_dest = 0u;
    for (uint32_t i = 0; i < c->mod_count; i++) {
        Mod *m = &c->mods[i];
        if (m->enabled) toggle(m);
    }
    return 1;
}

static void sd_acknowledge_stop(const Ctx *c) {
    for (uint32_t i = 0; i < c->mod_count; i++)
        if (c->mods[i].enabled) return;
    int fd = ml_open(MLV2_SD_STOPPED, ML_O_WR_CREAT_APP | ML_O_NONBLOCK | ML_O_NOFOLLOW);
    if (fd >= 0) ml_close(fd);
}

static void restore_tracked_root(Ctx *c, TrackedRoot *tr) {
    if (tr->root && tr->root->children == c->root_children && tr->orig_children) {
        tr->root->children = tr->orig_children;
        tr->root->child_count = tr->orig_child_count;
    }
}

static int restore_all_tracked_roots(Ctx *c, Node *cur_root) {
    for (uint32_t i = 0; i < c->tracked_count && i < MLV2_MAX_TRACKED_ROOTS; i++) {
        restore_tracked_root(c, &c->tracked[i]);
    }
    for (uint32_t i = 0; i < c->tracked_count && i < MLV2_MAX_TRACKED_ROOTS; i++) {
        if (c->tracked[i].root && c->tracked[i].root->children == c->root_children)
            return 0;
    }
    if (cur_root && cur_root->children == c->root_children)
        return 0;
    return 1;
}

static TrackedRoot *find_or_alloc_tracked_root(Ctx *c, Node *root) {
    for (uint32_t i = 0; i < c->tracked_count && i < MLV2_MAX_TRACKED_ROOTS; i++) {
        if (c->tracked[i].root == root) return &c->tracked[i];
    }
    if (c->tracked_count < MLV2_MAX_TRACKED_ROOTS) {
        return &c->tracked[c->tracked_count++];
    }
    for (uint32_t i = 0; i < MLV2_MAX_TRACKED_ROOTS; i++) {
        if (!c->tracked[i].root || c->tracked[i].root->children != c->root_children)
            return &c->tracked[i];
    }
    return 0;
}

static uint32_t core_before_set_root(uint32_t menu, uint32_t root_addr) {
    (void)menu;
    Node *root = (Node *)root_addr;
    if (!root || root_addr < 0x00100000u || (root->child_count != 6 && root->child_count != 7)) return root_addr;
    if (!root->vtable || (uint32_t)root->vtable < 0x00100000u || !root->children ||
        (uint32_t)root->children < 0x00100000u) return root_addr;
    Ctx *c = ctx_get();
    if (!c) return root_addr;
    if (sd_disabled(c)) {
        if (restore_all_tracked_roots(c, root)) {
            sd_acknowledge_stop(c);
        }
        return root_addr;
    }
    if (!c->vtable_ready) {
        for (uint32_t i = 0; i < 65u; i++) c->vtable[i] = root->vtable[i];
        c->vtable_ready = 1;
        vtable_bind(c);
    }
    process_reload(c);
    c->in_folder = 0;
    rescan(c);
    rebuild_view(c);
    for (uint32_t i = 0; i < c->mod_count; i++) {
        Mod *m = &c->mods[i];
        if (m->present != 3) continue;
        m->present = 1;
        if (!m->enabled && !m->invalid) {
            toggle(m);
            ml_log("auto_on", m->enabled ? m->addr : 0u);
        }
    }
    c->sub_mod = -1;
    build_tree(c);
    if (root->children != c->root_children) {
        /* Restore any previously extended root before reusing the shared root_children[] array. */
        if (!restore_all_tracked_roots(c, 0)) return root_addr;
        TrackedRoot *tr = find_or_alloc_tracked_root(c, root);
        if (!tr) return root_addr;
        tr->root = root;
        tr->orig_children = root->children;
        tr->orig_child_count = root->child_count;
        c->orig_root = root;
        for (uint32_t i = 0; i < 6u; i++) c->root_children[i] = root->children[i];
        c->orig_tab5 = (Node *)root->children[5];
        root->children = c->root_children;
    }
    c->tab_node.parent = root;
    c->root_children[6] = &c->tab_node;
    root->child_count = 7;
    return root_addr;
}

static const char *state_text(const Mod *m) {
    if (m->invalid || (m->enabled && !m->present)) return "ERR";
    if (is_action(m)) {
        if (m->enabled && !m->off_off && m->addr && m->extra_size >= 20u) {
            const volatile uint32_t *st = (const volatile uint32_t *)(m->addr + m->code_size);
            if (st[0] == 0x46534c31u && ((const volatile char *)(st + 1))[0])
                return (const char *)(m->addr + m->code_size + 4u);
        }
        return (m->enabled && m->off_off) ? (m->stale ? "Active*" : "Active") : "";
    }
    const Ctx *c = ctx_get();
    if (m->enabled) {
        if (is_precap_mod(m) && c && c->persist_dirty) return "ON!";
        return m->stale ? "ON*" : "ON";
    }
    if (is_precap_mod(m) && c && c->persist_dirty) return "OFF!";
    return "OFF";
}

static const char *state_text_top(const Mod *m) {
    if (has_submenu(m) && !m->invalid && (!m->enabled || m->present)) {
        const Ctx *c = ctx_get();
        if (m->enabled) {
            if (is_precap_mod(m) && c && c->persist_dirty) return "ON! >";
            return m->stale ? "ON* >" : "ON >";
        }
        if (is_precap_mod(m) && c && c->persist_dirty) return "OFF! >";
        return "OFF >";
    }
    return state_text(m);
}

static int post_menu_key(void) {
    if (!core_libobj_ok) return 0;
    uint32_t b = core_libobj_bias;
    uint32_t mgr = *(volatile uint32_t *)(REF_EVMGR_DIRECT + b);
    if (!mgr) return 0;
    void *ev = ((void *(*)(uint32_t))(REF_OP_NEW + b))(16u);
    if (!ev) return 0;
    ((void (*)(void *, uint32_t, uint8_t, uint8_t))(REF_EV_CTOR + b))(ev, KEY_MENU_EVENT, 4u, 1u);
    ((void (*)(uint32_t, void *, uint32_t))(REF_EVMGR_PUSH + b))(mgr, ev, 1u);
    return 1;
}

static void refresh_rows(Ctx *c, uint32_t menu, int clear_unused) {
    if (!menu || *(volatile uint32_t *)(menu + 0x1f0u) != 7u) return;
    typedef void (*set_text_t)(void *, const char *);
    set_text_t set_text = (set_text_t)VIEW(MLV2_SET_TEXT);
    uint32_t page = *(volatile uint32_t *)(menu + 0x1f4u);
    if (!page) page = 1;
    uint32_t base = (page - 1u) * 6u;
    if (c->sub_mod >= 0 && (uint32_t)c->sub_mod < c->mod_count && has_submenu(&c->mods[c->sub_mod])) {
        const Mod *m = &c->mods[c->sub_mod];
        uint32_t total = 2u + (uint32_t)m->sub_count;
        set_text((void *)(menu + 0x5470u), m->name);
        for (uint32_t r = 0; r < 6u; r++) {
            uint32_t btn = menu + 0x9350u + r * 0x1118u, idx = base + r;
            if (idx < total) {
                if (idx == 0u) {
                    set_text((void *)(btn + 0x7c8u), "< Back");
                    set_text((void *)(btn + 0xb60u), "");
                } else if (idx == 1u) {
                    set_text((void *)(btn + 0x7c8u), "Mod Status");
                    set_text((void *)(btn + 0xb60u), state_text(m));
                } else {
                    uint32_t s = idx - 2u;
                    uint8_t v = m->sub_vals[s] < m->sub_items[s].opt_count ? m->sub_vals[s] : 0u;
                    set_text((void *)(btn + 0x7c8u), m->sub_items[s].label);
                    set_text((void *)(btn + 0xb60u), m->sub_items[s].opts[v]);
                }
            } else if (clear_unused) {
                set_text((void *)(btn + 0x7c8u), "");
                set_text((void *)(btn + 0xb60u), "");
            }
        }
        return;
    }
    set_text((void *)(menu + 0x5470u), c->in_folder ? c->folder_names[c->in_folder - 1u] : "Mods");
    for (uint32_t r = 0; r < 6u; r++) {
        uint32_t btn = menu + 0x9350u + r * 0x1118u, idx = base + r;
        if (idx < c->view_count) {
            int16_t v = c->view_map[idx];
            if (v == -1) {
                set_text((void *)(btn + 0x7c8u), "< Back");
                set_text((void *)(btn + 0xb60u), "");
            } else if (v <= -2) {
                const char *fname = c->folder_names[(uint32_t)(-v - 2)];
                const char *val = ">";
                for (uint32_t i = 0; i < c->mod_count; i++)
                    if (c->mods[i].enabled && !ml_strcmp(c->mods[i].folder, fname)) {
                        val = c->mods[i].name;
                        break;
                    }
                set_text((void *)(btn + 0x7c8u), fname);
                set_text((void *)(btn + 0xb60u), val);
            } else {
                set_text((void *)(btn + 0x7c8u), c->mods[v].name);
                set_text((void *)(btn + 0xb60u), state_text_top(&c->mods[v]));
            }
        } else if (!r && !c->view_count) {
            set_text((void *)(btn + 0x7c8u), "No mods found");
            set_text((void *)(btn + 0xb60u), "");
        } else if (clear_unused) {
            set_text((void *)(btn + 0x7c8u), "");
            set_text((void *)(btn + 0xb60u), "");
        }
    }
}

static void core_after_refresh(uint32_t menu) {
    Ctx *c = ctx_get();
    if (!c) return;
    if (sd_disabled(c)) return;
    process_reload(c);
    c->last_menu = menu;
    if (c->orig_root && c->orig_root->children == c->root_children) {
        c->root_children[6] = &c->tab_node;
        c->orig_root->child_count = 7;
    }
    if (!menu || *(volatile uint32_t *)(menu + 0x1f0u) != 7u) {
        if (c->sub_mod >= 0) {
            c->sub_mod = -1;
            build_tree(c);
        }
        return;
    }
    refresh_rows(c, menu, 0);
}

/* ---------------- loading and toggling ---------------- */
static void hook_bytes(const Mod *m, const Hook *hk, uint8_t *bytes) {
    ml_memcpy(bytes, hk->patch, SMOD_MAX_PATCH);
    if (m->kind == KIND_V2 && hk->fixup != SMOD_V2_NO_FIXUP) {
        uint32_t entry;
        ml_memcpy(&entry, bytes + hk->fixup, 4);
        entry += m->addr;
        ml_memcpy(bytes + hk->fixup, &entry, 4);
    }
}

static int hooks_revert(Mod *m, uint32_t upto) {
    int failed = 0;
    for (uint32_t h = 0; h < upto; h++) {
        Hook *hk = &m->hooks[h];
        void *target = (void *)hk->target;
        if (!ml_memcmp(target, hk->orig, hk->size)) continue;
        uint8_t bytes[SMOD_MAX_PATCH];
        hook_bytes(m, hk, bytes);
        if (ml_memcmp(target, bytes, hk->size) || ml_make_rwx(hk->target, hk->size) < 0) {
            failed = 1;
            continue;
        }
        ml_memcpy(target, hk->orig, hk->size);
        ml_flush_all(hk->target, hk->target + hk->size);
        if (ml_memcmp(target, hk->orig, hk->size)) failed = 1;
    }
    return failed;
}

static void call_entry(uint32_t addr, int arg) { ((void (*)(int))(addr | 1u))(arg); }

static int load_code(Mod *m) {
    uint32_t dst = m->addr, need = m->code_size + m->extra_size;
    if (m->kind == KIND_V2 && (!dst || m->map_size < need)) {
        dst = ml_mmap_rwx(need);
        if (!dst) return 4;
        m->addr = dst;
        m->map_size = (need + 0xfffu) & ~0xfffu;
    } else if (m->kind == KIND_V1 && ml_make_rwx(dst, m->code_size) < 0) {
        return 4;
    }
    int fd = ml_open(m->path, ML_O_RDONLY | ML_O_NONBLOCK | ML_O_NOFOLLOW);
    if (fd < 0) return 3;
    if (!ml_fd_is_regular(fd)) { ml_close(fd); return 3; }
    ml_lseek(fd, m->data_off);
    int n = ml_read(fd, (void *)dst, m->code_size);
    if (m->kind == KIND_V1 && (m->flags & SMOD_V1_FLAG_STATE_INIT)) {
        if (ml_read(fd, (void *)m->state_addr, m->extra_size) != (int)m->extra_size) n = -1;
    } else if (m->kind == KIND_V1 && m->state_addr && m->extra_size) {
        ml_memset((void *)m->state_addr, 0, m->extra_size);
    } else if (m->kind == KIND_V2 && m->extra_size) {
        ml_memset((void *)(dst + m->code_size), 0, m->extra_size);
    }
    ml_close(fd);
    if (n != (int)m->code_size) return 5;
    if (ml_fnv1a((const uint8_t *)dst, m->code_size) != m->fnv) return 6;
    if (m->kind == KIND_V2 && (m->flags & SMOD_V2_FLAG_RELOC)) {
        SmodRelocLib libs[SMOD_RELOC_MAX_LIBS];
        uint32_t bias[SMOD_RELOC_MAX_LIBS];
        fd = ml_open(m->path, ML_O_RDONLY | ML_O_NONBLOCK | ML_O_NOFOLLOW);
        if (fd < 0) return 3;
        if (!ml_fd_is_regular(fd)) { ml_close(fd); return 3; }
        ml_lseek(fd, m->data_off + m->code_size);
        uint32_t nlib = 0;
        int nrel = reloc_apply(fd, m->code_size, (uint8_t *)dst, libs, bias, &nlib);
        ml_close(fd);
        if (nrel < 0) return 8;
    }
    ml_flush_all(dst, dst + m->code_size);
    return 0;
}

static void sync_sub_config(const Mod *m) {
    if (m->kind != KIND_V2 || !m->sub_count || !m->addr) return;
    uint8_t *dst = (uint8_t *)(m->addr + m->code_size + m->sub_bss_off);
    for (uint32_t i = 0; i < m->sub_count; i++) dst[i] = m->sub_vals[i];
    ml_flush_all((uint32_t)dst, (uint32_t)dst + m->sub_count);
}

static void enable_loaded(Mod *m) {
    sync_sub_config(m);
    for (uint32_t h = 0; h < m->hook_count; h++) {
        Hook *hk = &m->hooks[h];
        uint8_t bytes[SMOD_MAX_PATCH];
        hook_bytes(m, hk, bytes);
        if (ml_make_rwx(hk->target, hk->size) < 0) {
            m->enabled = hooks_revert(m, h);
            m->off_called = 1;
            ml_log("tgl_err", 7u);
            m->invalid = 1;
            return;
        }
        ml_memcpy((void *)hk->target, bytes, hk->size);
        ml_flush_all(hk->target, hk->target + hk->size);
    }
    m->enabled = 1;
    m->off_called = 0;
    if (m->kind == KIND_V2 && m->on_off) call_entry(m->addr + m->on_off, 1);
    if (m->kind == KIND_V1 && (m->flags & SMOD_V1_FLAG_LIFECYCLE)) call_entry(m->addr, 1);
    ml_log("mod_on", m->addr);
}

static void toggle(Mod *m) {
    if (!m->enabled) {
        if (m->invalid) return;
        if (m->stale) { m->invalid = 1; return; }
        for (uint32_t h = 0; h < m->hook_count; h++)
            if (ml_memcmp((void *)m->hooks[h].target, m->hooks[h].orig, m->hooks[h].size)) {
                ml_log("tgl_err", 2u);
                m->invalid = 1;
                return;
            }
        int rc = load_code(m);
        if (rc) { ml_log("tgl_err", (uint32_t)rc); if (rc != 3) m->invalid = 1; return; }
        enable_loaded(m);
    } else {
        if (!m->off_called) {
            if (m->kind == KIND_V2 && m->off_off) call_entry(m->addr + m->off_off, 0);
            if (m->kind == KIND_V1 && (m->flags & SMOD_V1_FLAG_LIFECYCLE)) call_entry(m->addr, 0);
            m->off_called = 1;
        }
        if (hooks_revert(m, m->hook_count)) {
            m->invalid = 1;
            ml_log("mod_off_failed", m->addr);
            return;
        }
        m->invalid = 0;
        m->enabled = 0;
        ml_log("mod_off", m->addr);
    }
}

/* ---------------- reload ---------------- */
static int targets_original(const Mod *m) {
    for (uint32_t h = 0; h < m->hook_count; h++)
        if (ml_memcmp((void *)m->hooks[h].target, m->hooks[h].orig, m->hooks[h].size)) return 0;
    return 1;
}

static int reload_targets_ok(const Mod *old, const Mod *n) {
    for (uint32_t h = 0; h < n->hook_count; h++) {
        const Hook *hk = &n->hooks[h];
        int covered = 0;
        for (uint32_t k = 0; k < old->hook_count; k++) {
            const Hook *ok = &old->hooks[k];
            if (ok->target == hk->target) {
                if (ok->size != hk->size || ml_memcmp(ok->orig, hk->orig, hk->size)) return 0;
                covered = 1;
            } else if (ok->target < hk->target + hk->size && hk->target < ok->target + ok->size) {
                return 0;
            }
        }
        if (!covered && ml_memcmp((void *)hk->target, hk->orig, hk->size)) return 0;
    }
    return 1;
}

static void reload_result(const char *msg, uint32_t val) {
    ml_log_to(MLV2_RELOAD_RESULT, ML_O_WR_CREAT_TRUNC, msg, val);
    ml_log(msg, val);
}

static void reload_mod(Ctx *c, const char *name) {
    uint32_t i = 0;
    while (i < c->mod_count && ml_strcmp(base_name(c->mods[i].path), name)) i++;
    if (i >= c->mod_count || !c->mods[i].enabled) { reload_result("reload_scan", i < c->mod_count); return; }
    Mod *m = &c->mods[i], *n = &c->tmp;
    if (m->invalid) { reload_result("reload_err_state", 0); return; }
    if (!parse_mod(m->path, n)) { reload_result("reload_err_file", 0); return; }
    if (n->kind != KIND_V2) { reload_result("reload_err_kind", n->kind); return; }
    n->addr = 0;
    n->map_size = 0;
    int rc = load_code(n);
    if (rc) { reload_result("reload_err_load", (uint32_t)rc); return; }
    if (!reload_targets_ok(m, n)) { reload_result("reload_err_target", 0); return; }
    toggle(m);
    if (m->enabled || !targets_original(m)) { reload_result("reload_err_off", m->addr); return; }
    ml_memcpy(n->folder, m->folder, sizeof(n->folder));
    if (n->sub_count && m->sub_count == n->sub_count) {
        for (uint32_t k = 0; k < n->sub_count; k++)
            if (m->sub_vals[k] < n->sub_items[k].opt_count) n->sub_vals[k] = m->sub_vals[k];
    }
    ml_memcpy(m, n, sizeof(Mod));
    if (!targets_original(m)) { m->invalid = 1; reload_result("reload_err_target", 1); return; }
    enable_loaded(m);
    if (!m->enabled) { reload_result("reload_err_on", m->addr); return; }
    reload_result("reload_ok", m->addr);
}

static int process_reload(Ctx *c) {
    int fd = ml_open(MLV2_RELOAD_REQ, ML_O_RDONLY | ML_O_NONBLOCK | ML_O_NOFOLLOW);
    if (fd < 0) return 0;
    if (!ml_fd_is_regular(fd)) { ml_close(fd); return 0; }
    char name[48];
    ml_memset(name, 0, sizeof(name));
    int n = ml_read(fd, name, sizeof(name) - 1u);
    ml_close(fd);
    if (ml_unlink(MLV2_RELOAD_REQ) < 0) { reload_result("reload_err_unlink", 0); return 1; }
    int bad = n <= 0;
    for (int k = 0; k < n && !bad; k++) {
        if (name[k] == '\n' || name[k] == '\r') { name[k] = 0; break; }
        if (name[k] == '/' || name[k] < ' ') bad = 1;
    }
    if (bad || !ends_with_mod(name)) { reload_result("reload_err_request", (uint32_t)n); return 1; }
    reload_mod(c, name);
    return 1;
}

static void menu_switch_view(Ctx *c, uint32_t menu, int32_t new_sub_mod, uint32_t focus_idx) {
    c->sub_mod = new_sub_mod;
    build_tree(c);
    uint32_t pg = focus_idx >= 12u ? 2u : (focus_idx >= 6u ? 1u : 0u);
    if (pg >= c->page_count) pg = 0u;
    uint32_t rw = focus_idx - pg * 6u;
    if ((int32_t)rw >= c->pages[pg].child_count) rw = 0u;
    c->tab_node.selected_idx = (int32_t)(pg + 1u);
    for (uint32_t p = 0; p < c->page_count; p++)
        c->pages[p].selected_idx = (p == pg) ? (int32_t)(rw + 1u) : 1;
    *(volatile uint32_t *)(menu + 0x1f4u) = pg + 1u;
    *(volatile uint32_t *)(menu + 0x1f8u) = rw;
    ((void (*)(uint32_t, uint32_t))VIEW(MLV2_MENU_REFRESH))(menu, 0u);
}

static int core_before_enter(uint32_t menu, uint32_t leaf) {
    Ctx *c = ctx_get();
    if (!c) return -1;
    int disabled = sd_disabled(c);
    uint32_t lo = (uint32_t)&c->items[0], hi = (uint32_t)&c->items[MAX_MODS];
    if (leaf < lo || leaf >= hi) return -1;
    if (disabled) return 0;
    uint32_t idx = 0;
    while (idx < MAX_MODS && (uint32_t)&c->items[idx] != leaf) idx++;
    typedef void (*set_text_t)(void *, const char *);
    if (c->sub_mod >= 0 && (uint32_t)c->sub_mod < c->mod_count && has_submenu(&c->mods[c->sub_mod])) {
        uint32_t mi = (uint32_t)c->sub_mod;
        Mod *m = &c->mods[mi];
        if (idx == 0u) {
            uint32_t focus_idx = 0u;
            for (uint32_t k = 0; k < c->view_count; k++)
                if (c->view_map[k] == (int16_t)mi) { focus_idx = k; break; }
            menu_switch_view(c, menu, -1, focus_idx);
            return 0;
        }
        if (idx == 1u) {
            if (!m->enabled && m->folder[0]) {
                for (uint32_t i = 0; i < c->mod_count; i++)
                    if (&c->mods[i] != m && c->mods[i].enabled && !ml_strcmp(c->mods[i].folder, m->folder))
                        toggle(&c->mods[i]);
            }
            if (is_precap_mod(m)) {
                unsigned fr = s7_index_to_frames(m->sub_vals[0]);
                if (!fr) fr = 5u;
                if (!m->enabled) {
                    /* Persist durable ON BEFORE exposing ON to daemon in runtime precap.cfg. */
                    int dest_id = 0;
                    if (persist_precap_if_authorized(c, 1, fr, 0, &dest_id)) {
                        toggle(m);
                        int ren = 0;
                        unsigned rfr = 0u;
                        if (m->enabled && s7_parse_precap_record(PRECAP_CFG, &ren, &rfr) &&
                            ren == 1 && rfr == fr) {
                            clear_persist_dirty_for(c, dest_id);
                        } else {
                            if (m->enabled) toggle(m);
                            if (!s7_confirm_runtime_disarmed()) {
                                m->enabled = 1u;
                                m->off_called = 0u;
                                c->persist_dirty |= (uint8_t)(PERSIST_DIRTY_RUNTIME | persist_dest_bit(dest_id));
                                ml_log("arm_rollback_fail", fr);
                            } else if (dest_id && !persist_precap_if_authorized(c, 0, fr, dest_id, 0)) {
                                c->persist_dirty |= persist_dest_bit(dest_id);
                            } else {
                                clear_persist_dirty_for(c, dest_id);
                                c->persist_dirty |= c->persist_armed_dest;
                            }
                        }
                    }
                } else {
                    /* Disarm runtime FIRST, require affirmative disarm confirmation, then persist OFF. */
                    int off_dest = 0;
                    toggle(m);
                    if (!s7_confirm_runtime_disarmed()) {
                        m->enabled = 1u;
                        m->off_called = 0u;
                        uint8_t pending = c->persist_armed_dest;
                        if (!pending) {
                            int gdest = read_persist_gate_dest();
                            pending = gdest < 0 ? PERSIST_DIRTY_GATE_ERR : persist_dest_bit(gdest);
                        }
                        c->persist_dirty |= (uint8_t)(PERSIST_DIRTY_RUNTIME | pending);
                        ml_log("disarm_fail", s7_pre_frames());
                    } else if (!persist_precap_if_authorized(c, 0, fr, 0, &off_dest)) {
                        c->persist_dirty |= (uint8_t)(PERSIST_DIRTY_RUNTIME | c->persist_armed_dest |
                            (off_dest ? persist_dest_bit(off_dest) : PERSIST_DIRTY_GATE_ERR));
                    } else {
                        clear_persist_dirty_for(c, off_dest);
                        c->persist_dirty |= c->persist_armed_dest;
                    }
                }
            } else {
                toggle(m);
            }
            ((set_text_t)VIEW(MLV2_SET_TEXT))(
                (void *)(menu + 0x9350u + 1u * 0x1118u + 0xb60u),
                state_text(m));
            return 0;
        }
        uint32_t s = idx - 2u;
        if (s < m->sub_count) {
            uint8_t prev_val = m->sub_vals[s];
            uint8_t nxt = (uint8_t)(prev_val + 1u);
            if (nxt >= m->sub_items[s].opt_count) nxt = 0u;
            m->sub_vals[s] = nxt;
            int status_changed = 0;
            if (is_precap_mod(m) && s == 0u) {
                unsigned fr = s7_index_to_frames(nxt);
                if (m->enabled && m->kind == KIND_V2 && m->addr) {
                    /* Persist durable ON/new-count BEFORE updating daemon-visible precap.cfg. */
                    int dest_id = 0;
                    if (fr && !persist_precap_if_authorized(c, 1, fr, 0, &dest_id)) {
                        m->sub_vals[s] = prev_val;
                    } else if (fr) {
                        sync_sub_config(m);
                        if (m->sub_cfg_off) call_entry(m->addr + m->sub_cfg_off, 2);
                        int ren = 0;
                        unsigned rfr = 0u;
                        int rst = s7_parse_precap_record_status(PRECAP_CFG, &ren, &rfr);
                        if (rst == 1 && ren == 1 && rfr == fr) {
                            ml_log("mod_cfg", ((uint32_t)s << 8) | nxt);
                            uint8_t prev_dirty = c->persist_dirty;
                            clear_persist_dirty_for(c, dest_id);
                            c->persist_dirty |= (uint8_t)(c->persist_armed_dest & (uint8_t)~persist_dest_bit(dest_id));
                            if (c->persist_dirty != prev_dirty) status_changed = 1;
                        } else {
                            unsigned prev_fr = s7_index_to_frames(prev_val);
                            if (!prev_fr) prev_fr = 5u;
                            if (rst == 1 && ren == 1 &&
                                s7_frames_to_index(rfr) < m->sub_items[s].opt_count) {
                                m->sub_vals[s] = (uint8_t)s7_frames_to_index(rfr);
                                sync_sub_config(m);
                                if (dest_id && !persist_precap_if_authorized(c, 1, rfr, dest_id, 0)) {
                                    c->persist_dirty |= persist_dest_bit(dest_id);
                                } else {
                                    clear_persist_dirty_for(c, dest_id);
                                }
                                ml_log("mod_cfg_fail", rfr);
                            } else if (rst == 0 || (rst == 1 && ren == 0)) {
                                unsigned dis_fr = prev_fr;
                                if (rst == 1 && s7_frames_to_index(rfr) < m->sub_items[s].opt_count) {
                                    m->sub_vals[s] = (uint8_t)s7_frames_to_index(rfr);
                                    dis_fr = rfr;
                                } else {
                                    m->sub_vals[s] = prev_val;
                                }
                                m->enabled = 0u;
                                m->off_called = 1u;
                                sync_sub_config(m);
                                if (dest_id && !persist_precap_if_authorized(c, 0, dis_fr, dest_id, 0))
                                    c->persist_dirty |= persist_dest_bit(dest_id);
                                else
                                    clear_persist_dirty_for(c, dest_id);
                                /* Always alert user ("OFF!") when an ON count edit unexpectedly disarms. */
                                c->persist_dirty |= (uint8_t)(PERSIST_DIRTY_RUNTIME | c->persist_armed_dest);
                                ml_log("mod_cfg_disarmed", dis_fr);
                            } else {
                                m->sub_vals[s] = prev_val;
                                sync_sub_config(m);
                                if (dest_id) persist_precap_if_authorized(c, 1, prev_fr, dest_id, 0);
                                /* Even successful compensation leaves agreement with runtime unverified. */
                                c->persist_dirty |= (uint8_t)(PERSIST_DIRTY_RUNTIME | persist_dest_bit(dest_id));
                                ml_log("mod_cfg_unverified", fr);
                            }
                            status_changed = 1;
                        }
                    }
                } else if (fr) {
                    int dest_id = 0;
                    if (!persist_precap_if_authorized(c, 0, fr, 0, &dest_id)) {
                        m->sub_vals[s] = prev_val;
                    } else {
                        uint8_t prev_dirty = c->persist_dirty;
                        clear_persist_dirty_for(c, dest_id);
                        c->persist_dirty |= c->persist_armed_dest;
                        if (c->persist_dirty != prev_dirty) status_changed = 1;
                        if (dest_id || !ml_path_absent(PRECAP_CFG)) {
                            if (!s7_write_precap_record(PRECAP_CFG, PRECAP_TMP, 0, fr, 0)) {
                                s7_file_call(S7_UNLINK, (long)PRECAP_CFG, 0, 0);
                            }
                        }
                        ml_log("mod_cfg_off", ((uint32_t)s << 8) | nxt);
                    }
                }
            } else if (m->enabled && m->kind == KIND_V2 && m->addr) {
                sync_sub_config(m);
                if (m->sub_cfg_off) call_entry(m->addr + m->sub_cfg_off, 2);
                ml_log("mod_cfg", ((uint32_t)s << 8) | nxt);
            }
            if (status_changed) {
                ((set_text_t)VIEW(MLV2_SET_TEXT))(
                    (void *)(menu + 0x9350u + 1u * 0x1118u + 0xb60u), state_text(m));
            }
            uint32_t row = idx >= 12u ? idx - 12u : (idx >= 6u ? idx - 6u : idx);
            ((set_text_t)VIEW(MLV2_SET_TEXT))(
                (void *)(menu + 0x9350u + row * 0x1118u + 0xb60u), m->sub_items[s].opts[m->sub_vals[s]]);
        }
        return 0;
    }
    if (idx >= c->view_count) return 0;
    int16_t v = c->view_map[idx];
    if (v < 0) {
        c->in_folder = (v == -1) ? 0u : (uint8_t)(-v - 1);
        *(volatile uint32_t *)(menu + 0x1f4u) = 1u;
        rebuild_view(c);
        build_tree(c);
        refresh_rows(c, menu, 1);
        return 0;
    }
    Mod *m = &c->mods[v];
    if (has_submenu(m) && !m->invalid) {
        menu_switch_view(c, menu, (int32_t)v, 1u);
        return 0;
    }
    if (!m->enabled && m->folder[0]) {
        for (uint32_t i = 0; i < c->mod_count; i++)
            if (&c->mods[i] != m && c->mods[i].enabled && !ml_strcmp(c->mods[i].folder, m->folder))
                toggle(&c->mods[i]);
    }
    int was_on = m->enabled;
    if (is_action(m) && !m->off_off && was_on) {
        if (m->kind == KIND_V2 && m->on_off) call_entry(m->addr + m->on_off, 1);
        ml_log(post_menu_key() ? "action_close" : "action_close_unavailable", m->addr);
    } else {
        toggle(m);
        if (is_action(m) && !was_on && m->enabled)
            ml_log(post_menu_key() ? "action_close" : "action_close_unavailable", m->addr);
    }
    refresh_rows(c, menu, 0);
    return 0;
}

/* ---------------- init / upgrade ---------------- */
__attribute__((section(".text.core_init"), used))
int core_init(ShimState *s) {
    int layout = s->layout_magic == MLV2_LAYOUT_MAGIC;
    core_view_bias = layout ? s->view_bias : 0u;
    core_slot = MLV2_REF_SHIM_ADDR + (layout ? s->shim_bias : 0u);
    Ctx *c = (Ctx *)s->ctx;
    if (c && (c->magic != CTX_MAGIC || c->version != CTX_VERSION)) {
        if (c->magic == CTX_MAGIC && c->mod_count) { ml_log("core_refuse", c->version); return -1; }
        c = 0;
    }
    if (!c) {
        c = (Ctx *)ml_mmap_rwx(CTX_BYTES);
        if (!c) return -2;
        ml_memset(c, 0, sizeof(*c));
        c->magic = CTX_MAGIC;
        c->version = CTX_VERSION;
        c->sub_mod = -1;
    }
    vtable_bind(c);
    {
        SmodRelocLib lib;
        uint32_t base = 0;
        ml_memset(&lib, 0, sizeof(lib));
        lib.ref_lo = MLV2_REF_LIBOBJ_BASE;
        lib.ref_hi = MLV2_REF_LIBOBJ_BASE + 1u;
        ml_memcpy(lib.name, "libObj.so", 10);
        if (maps_bases(&lib, 1, &base)) {
            core_libobj_bias = base - MLV2_REF_LIBOBJ_BASE;
            core_libobj_ok = 1;
        }
        ml_log("tab_icon_tab6", core_libobj_bias);
    }
    s->ctx = c;
    s->before_set_root = core_before_set_root;
    s->after_refresh = core_after_refresh;
    s->before_enter = core_before_enter;
    ml_log("core_init", CTX_VERSION);
    if (core_view_bias) ml_log("core_view_bias", core_view_bias);
    return 0;
}
