SECTIONS
{
	.text : { *(.text .rodata .rodata.*) }
}
OUTPUT_FORMAT(binary)
