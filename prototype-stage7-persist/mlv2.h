/* Mod Loader v2 shared ABI for DSC-RX100M7 1.00 (build 29110_03.2021050601).
 *
 * Adapted from sources/bionz-x-research/tools/native_camera/mlv2/mlv2.h for M7 1.00:
 * - Uses /tmp_network/mlv2 and /tmp_network/mods (M7 1.00 has no /tmp_bt).
 * - Uses verified M7 1.00 viewUnified2.so, libtestcmd.so, and libObj.so offsets.
 * - Both shim and core dynamically relocate from live /proc/<pid>/maps bases.
 */
#ifndef MLV2_H
#define MLV2_H
#include <stdint.h>

/* ---- Firmware reference addresses (DSC-RX100M7 1.00, verified by m7_100_layout.py) ---- */
#define MLV2_REF_VIEW_BASE      0x153f1000u
#define MLV2_SHIM_VIEW_OFF      0x00972800u  /* viewUnified2.so RX zero tail (past 0x9727f0, 2048 B) */
#define MLV2_REF_SHIM_ADDR      (MLV2_REF_VIEW_BASE + MLV2_SHIM_VIEW_OFF)
#define MLV2_REF_LIBOBJ_BASE    0x05ecd000u

#define MLV2_SET_TEXT_OFF       0x001617c0u  /* GEN_Label::setTextDirect Thumb PLT veneer */
#define MLV2_SET_MODE_OFF       0x001680c8u  /* Widget::setMode Thumb PLT veneer */
#define MLV2_MENU_REFRESH_OFF   0x00696ec4u  /* PAS_MenuList full refresh (rebuilds rows & tabs) */
#define MLV2_HOOK_SET_ROOT_OFF  0x00696408u
#define MLV2_HOOK_REFRESH_OFF   0x00696834u
#define MLV2_HOOK_OPEN_ITEM_OFF 0x00696df8u
#define MLV2_RECT_TBL1_SLOT6    0x0088c814u
#define MLV2_RECT_TBL2_SLOT6    0x0088c894u
#define MLV2_TAB_BACKDROP_OFF   0x0000097cu  /* PAS_MenuList tab-bar backdrop widget (0x695750+0x695772) */
#define MLV2_V1_ANCHOR_OFF      0x00bc9bb8u  /* viewUnified2.so .bss tail */

#ifndef MLV2_VIEW_BASE
#define MLV2_VIEW_BASE          MLV2_REF_VIEW_BASE
#endif
#define MLV2_SET_TEXT           (MLV2_VIEW_BASE + MLV2_SET_TEXT_OFF + 1u)
#define MLV2_SET_MODE           (MLV2_VIEW_BASE + MLV2_SET_MODE_OFF + 1u)
#define MLV2_MENU_REFRESH       (MLV2_VIEW_BASE + MLV2_MENU_REFRESH_OFF + 1u)
#define MLV2_V1_ANCHOR          (MLV2_REF_VIEW_BASE + MLV2_V1_ANCHOR_OFF)
#define MLV2_V1_MAGIC           0x444f4d53u  /* "SMOD" */
#define MLV2_V1_STATE_BYTES     8192u

/* ---- Shim ---- */
#ifndef MLV2_SHIM_ADDR
#define MLV2_SHIM_ADDR          MLV2_REF_SHIM_ADDR
#endif
#define MLV2_SHIM_CAP           2048u
#define MLV2_SHIM_SLOT          MLV2_SHIM_ADDR

/* ---- M7 1.00 RAM tmpfs paths (default /tmp_network; Phase B overrides via -DS7_RAM_ROOT) ---- */
#ifndef S7_RAM_ROOT
#define S7_RAM_ROOT             "/tmp_network"
#endif
#define MLV2_CORE_PATH          S7_RAM_ROOT "/mlv2/core.bin"
#define MLV2_SD_MANAGED         S7_RAM_ROOT "/mlv2/sd-managed"
#define MLV2_SD_DISABLED        S7_RAM_ROOT "/mlv2/sd-disabled"
#define MLV2_SD_STOPPED         S7_RAM_ROOT "/mlv2/sd-stopped"
#define MLV2_RELOAD_REQ         S7_RAM_ROOT "/mlv2/reload"
#define MLV2_RELOAD_RESULT      S7_RAM_ROOT "/mlv2/reload.result"
#define MLV2_MODS_DIR           S7_RAM_ROOT "/mods"
#define MLV2_LOG_PATH           S7_RAM_ROOT "/mods/mod_loader.log"

/* ---- Core image file ---- */
#define MLV2_CORE_MAGIC         0x52434c4du  /* "MLCR" */
#define MLV2_CORE_VERSION       2u
#define MLV2_CORE_MAX           (64u * 1024u)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t code_size;
    uint32_t fnv1a_32;
    uint32_t init_off;
} MlCoreHeader;

/* ---- State owned by the shim (one mmap page, never freed) ---- */
#define MLV2_SHIM_MAGIC            0x4853324du  /* "M2SH" */
#define MLV2_LAYOUT_MAGIC          0x3159414cu  /* "LAY1" */
#define MLV2_CTX_MAGIC             0x58544332u  /* "2CTX" */
#define MLV2_MAX_TRACKED_ROOTS     16u
#define MLV2_CTX_ORIG_ROOT_OFF     24u
#define MLV2_CTX_TRACKED_CNT_OFF   28u
#define MLV2_CTX_TRACKED_OFF       32u
#define MLV2_CTX_ROOT_CHILDREN_OFF 520u

typedef struct ShimState {
    uint32_t magic;
    uint32_t core_fnv;
    volatile uint32_t core_base;
    uint32_t core_loads;
    void    *ctx;
    uint32_t (*before_set_root)(uint32_t menu, uint32_t root);
    void     (*after_refresh)(uint32_t menu);
    int      (*before_enter)(uint32_t menu, uint32_t leaf);
    uint32_t layout_magic;
    uint32_t view_bias;
    uint32_t shim_bias;
    uint32_t core_size;
    volatile uint32_t active;
    volatile uint32_t core_load_lock;
    volatile uint32_t log_lock;
} ShimState;

/* ---- SMOD file formats (identical ABI to upstream mlv2) ---- */
#define SMOD_MAGIC              0x444f4d53u  /* "SMOD" */
#define SMOD_MAX_HOOKS          8u
#define SMOD_MAX_PATCH          16u
#define SMOD_V1_FLAG_STATE_INIT 1u
#define SMOD_V1_FLAG_LIFECYCLE  2u

typedef struct __attribute__((packed)) {
    uint32_t magic, version, flags;
    char     name[32];
    uint32_t code_addr, code_size, state_addr, state_size, hook_count, fnv1a_32;
} SmodV1Header;

typedef struct __attribute__((packed)) {
    uint32_t target_addr, patch_size;
    uint8_t  orig_bytes[SMOD_MAX_PATCH];
    uint8_t  hook_bytes[SMOD_MAX_PATCH];
} SmodV1Hook;

#define SMOD_V2_NO_FIXUP        0xffu
#define SMOD_V2_FLAG_RELOC      4u
#define SMOD_V2_FLAG_AUTO_ON    8u
#define SMOD_V2_FLAG_ACTION     16u
#define SMOD_V2_FLAG_SUBMENU    32u
#define SMOD_SUBMENU_MAGIC      0x554e4d53u  /* "SMNU" */
#define SMOD_SUBMENU_MAX_ITEMS  8u
#define SMOD_SUBMENU_MAX_OPTS   6u
#define SMOD_RELOC_MAGIC        0x31434c52u  /* "RLC1" */
#define SMOD_RELOC_MAX_LIBS     8u
#define SMOD_RELOC_MAX          1024u

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  item_count, bss_cfg_off;
    uint16_t reserved;
    uint32_t cfg_call_off;
} SmodSubmenuHeader;

typedef struct __attribute__((packed)) {
    uint8_t  opt_count, default_val, reserved[2];
    char     label[24];
    char     opts[SMOD_SUBMENU_MAX_OPTS][18];
} SmodSubmenuItem;

typedef struct __attribute__((packed)) {
    uint32_t ref_lo, ref_hi;
    char     name[24];
} SmodRelocLib;

typedef struct __attribute__((packed)) {
    uint32_t magic, version, flags;
    char     name[32];
    uint32_t code_size, fnv1a_32, bss_size, on_off, off_off, hook_count;
} SmodV2Header;

typedef struct __attribute__((packed)) {
    uint32_t target_addr;
    uint8_t  patch_size, fixup_off, pad[2];
    uint8_t  orig_bytes[SMOD_MAX_PATCH];
    uint8_t  tmpl[SMOD_MAX_PATCH];
} SmodV2Hook;

_Static_assert(sizeof(SmodV1Header) == 68 && sizeof(SmodV2Header) == 68, "SMOD header size");
_Static_assert(sizeof(SmodV1Hook) == 40 && sizeof(SmodV2Hook) == 40, "SMOD hook size");
_Static_assert(sizeof(SmodSubmenuHeader) == 12 && sizeof(SmodSubmenuItem) == 136, "SMNU layout");

#endif
