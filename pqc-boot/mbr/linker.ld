ENTRY(_start)

SECTIONS {
    . = 0x7E00; /* We are loaded here by Stage 1 */

    .text : {
        *(.text.entry) /* Ensure entry point is first */
        *(.text*)
    }

    .rodata : {
        *(.rodata*)
    }

    .data : {
        *(.data*)
    }

    .bss : {
        *(.bss*)
    }
}
