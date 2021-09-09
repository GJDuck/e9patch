SECTIONS
{
	.text : { *(.text .rodata .rodata.* .data .data.*) }
}
OUTPUT_FORMAT(binary)
