/* Mod Loader v2 core for DSC-RX100M7 1.00: position-independent image linked at 0. */
SECTIONS
{
    . = 0;
    .text : {
        *(.text.core_init)
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    }
    ASSERT(SIZEOF(.data) == 0 && SIZEOF(.bss) == 0, "core must not have writable data")
    .data : { *(.data*) }
    .bss : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) *(.got*) *(.dynamic) }
}
