SECTIONS
{
    .text : { *(.text.entry)
              *(.text .rodata .rodata.* .data .data.*) }
    /DISCARD/ : { *(*) }
}
OUTPUT_FORMAT(binary)
