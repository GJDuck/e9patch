
/*
 * TRAP instrumentation.
 */

void entry(void)
{
    asm volatile ("int3");
}

