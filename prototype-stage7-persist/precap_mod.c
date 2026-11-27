#include "stage7_common.h"

/* The SMNU loader writes the selected option index to the first BSS byte. */
extern const volatile unsigned char __smod_bss[] __attribute__((visibility("hidden")));

void precap_lifecycle(int reason)
{
    unsigned index = __smod_bss[0];
    unsigned frames = s7_index_to_frames(index);
    int enabled = (frames != 0u) && (reason == 1 || reason == 2);
    if (!frames) frames = 5u;

    /* One UI-thread writer. Runtime RAM record only; durable edits live in core.c. */
    if (s7_write_precap_record(PRECAP_CFG, PRECAP_TMP, enabled, frames, 0)) return;
    /* Only disarming falls back to unlink (absent == OFF); preserve prior record on ON/edit failure. */
    if (!enabled) s7_file_call(S7_UNLINK, (long)PRECAP_CFG, 0, 0);
}
