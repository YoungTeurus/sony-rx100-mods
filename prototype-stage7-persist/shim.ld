/* Mod Loader v2 shim for DSC-RX100M7 1.00: /usr/lib/viewUnified2.so RX zero tail
 * (reference 0x15d63800..0x15d64000, clears .ARM.exidx end 0x9727f0, 2048 B capacity).
 */
SECTIONS
{
    . = 0x15d63800;
    .text : {
        *(.text.slot)
        *(.text.slotb)
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    }
    ASSERT(. <= 0x15d64000, "shim exceeds the M7 viewUnified2.so 2048-byte RX tail")
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) *(.data*) *(.bss*) }
}
