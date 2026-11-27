.syntax unified
.thumb

/* Mod Loader v2 view-hook trampolines for DSC-RX100M7 1.00 viewUnified2.so.
 * Resident in viewUnified2.so RX zero tail (+0x972800..+0x973000), within Thumb-2
 * B.W (+-16 MiB) reach of all three hooks so every hook patch is a single atomic
 * 4-byte instruction and only 4 original bytes are replayed per hook.
 */
#ifndef MLV2_VIEW_BASE
#define MLV2_VIEW_BASE 0x153f1000
#endif
#define HOOK_SET_ROOT_OFF  0x696408
#define HOOK_REFRESH_OFF   0x696834
#define HOOK_OPEN_ITEM_OFF 0x696df8

.global ml_hook_set_root
.global ml_hook_refresh
.global ml_hook_open_item
.extern ml_before_set_root
.extern ml_refresh_enter
.extern ml_refresh_leave
.extern ml_before_enter

.thumb_func
ml_hook_set_root:
    cbz r1, 2f
    /* Push 4 registers (16 B) to preserve 8-byte AAPCS stack alignment for C callbacks. */
    push {r0, r1, r2, lr}
    bl ml_before_set_root
    mov r3, r0
    pop {r0, r1, r2, ip}
    mov lr, ip
    cmp r3, #0
    it ne
    movne r1, r3
2:
    /* Original 4 bytes at M7 viewUnified2.so + 0x696408 (after push {r3, r4, r7, lr}):
     * mov r4, r0
     * add r7, sp, #0
     */
    mov r4, r0
    add r7, sp, #0
    ldr.w ip, 1f
    bx ip
.align 2
1:  .word MLV2_VIEW_BASE + HOOK_SET_ROOT_OFF + 5

.thumb_func
ml_orig_refresh:
    /* Original 4 bytes at M7 viewUnified2.so + 0x696834:
     * stmdb sp!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
     */
    stmdb sp!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
    ldr.w ip, 2f
    bx ip
.align 2
2:  .word MLV2_VIEW_BASE + HOOK_REFRESH_OFF + 5

.thumb_func
ml_hook_refresh:
    /* Push 6 registers (24 B) -> SP % 8 == 0; preserves r0..r3 across ml_refresh_enter.
     * active counter is incremented BEFORE ml_orig_refresh so the entire Sony refresh
     * call stack (deep nested frames with saved shim LR) is covered by ShimState.active.
     */
    push {r0, r1, r2, r3, r4, lr}
    bl ml_refresh_enter
    mov r4, r0
    ldm sp, {r0, r1, r2, r3}
    bl ml_orig_refresh
    ldr r0, [sp, #0]
    mov r1, r4
    bl ml_refresh_leave
    add sp, #16
    pop {r4, pc}

.thumb_func
ml_hook_open_item:
    /* Entry hook for M7 viewUnified2.so + 0x696df8 (enter_selected(menu, leaf)). */
    push {r0, r1, r2, lr}
    bl ml_before_enter
    cmp r0, #0
    blt 3f
    add sp, #12
    pop {pc}
3:
    pop {r0, r1, r2, ip}
    mov lr, ip
    /* Original 4 bytes at M7 viewUnified2.so + 0x696df8:
     * add.w r3, r0, #0x18400 (99328)
     */
    add.w r3, r0, #99328
    ldr.w ip, 4f
    bx ip
.align 2
4:  .word MLV2_VIEW_BASE + HOOK_OPEN_ITEM_OFF + 5
