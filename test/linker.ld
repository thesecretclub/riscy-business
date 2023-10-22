ENTRY(_start)

BASE = 0x8000000;

SECTIONS
{
	. = BASE;
	__base = .;

	.text : ALIGN(16) {
        . = BASE;
		*(.text)
        *(.text.*)
	}

	.data : ALIGN(16) {
		*(.rodata)
		*(.rodata.*)
		*(.data)
		*(.data.*)
	}

    .init : ALIGN(16) {
        __init_array_start = .;
        *(.init_array)
        __init_array_end = .;
    }

    .bss : ALIGN(16) {
		*(.bss)
		*(.bss.*)
        *(.sbss)
		*(.sbss.*)
	}

    .relocs : ALIGN(16) {
		. = . + SIZEOF(.bss);
        __relocs_start = .;
    }
}
 