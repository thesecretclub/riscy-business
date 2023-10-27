ENTRY(_start)

LINK_BASE = 0x8000000;

SECTIONS
{
    . = LINK_BASE;
    __base = .;

    .text : ALIGN(16) {
        . = LINK_BASE;
        *(.text)
        *(.text.*)
    }

    .data : {
        *(.rodata)
        *(.rodata.*)
        *(.data)
        *(.data.*)
        *(.eh_frame)
    }

    .init : {
        __init_array_start = .;
        *(.init_array)
        __init_array_end = .;
    }

    .bss : {
        *(.bss)
        *(.bss.*)
        *(.sbss)
        *(.sbss.*)
    }

    .relocs : {
        . = . + SIZEOF(.bss);
        __relocs_start = .;
    }
}
