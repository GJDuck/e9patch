/*
 * BOUNDS CHECK instrumentation.
 */

/*
 * SUMMARY:
 *  Bounds checking (memory safety) instrumentation for detecting:
 *      - Bounds overflows or underflows
 *      - Use-after-free
 *
 * DEPENDENCIES:
 *  This example program depends on the RedFat runtime (libredfat.so) to work.
 *  The runtime binary can be obtained by installing RedFat:
 *      - https://github.com/GJDuck/RedFat
 *
 * USAGE:
 *  To test this sample, it is recommended to use the bounds.sh script.
 *
 *      $ examples/bounds.sh xterm
 *      $ LD_PRELOAD=/usr/share/redfat/libredfat.so ./a.out
 *
 *  Otherwise, the basic instrumentation command sequence is the following:
 *
 *      $ e9compile bounds.c
 *      $ e9tool -M 'defined(mem[0]) and
 *                   mem[0].access in {r,w,rw} and
 *                   mem[0].seg == nil and
 *                   mem[0].base != nil and
 *                   mem[0].base != %rsp and
 *                   mem[0].base != %rip' \
 *               -P 'check((static)addr,
 *                         mem[0].base,
 *                         &mem[0],
 *                         mem[0].size,
 *                         asm)@bounds' \
 *               --option --mem-lb=0x400000 \
 *               xterm
 *      $ LD_PRELOAD=/usr/share/redfat/libredfat.so ./a.out
 *
 *  The matching (-M) can be broken down as follows:
 *      - defined(mem[0]):           The instruction uses a memory operand.
 *      - mem[0].access in {r,w,rw}: The memory operand actually reads or
 *                                   writes to memory (not NOP or LEA).
 *      - mem[0].seg == nil:         The memory operand does not use a
 *                                   segment register (%fs or %gs).
 *      - mem[0].base != nil:        The memory operand uses a base register.
 *      - mem[0].base != %rsp        The base register is not %rsp.
 *      - mem[0].base != %rip        The base register is not %rip.
 *
 *  The patching (-P) can be broken down as follows:
 *      - check(...)                 The check() function (below).
 *      - (static)addr               The instruction address before
 *                                   relocations are applied (static).
 *      - mem[0].base                The runtime value of the base register.
 *      - &mem[0]                    The runtime value of the address
 *                                   calculated by the memory operand.
 *      - mem[0].size                The size of the memory operation.
 *      - asm                        The asm string of the instruction.
 *      - @bounds                    The name of this module.
 *
 *  The remaining options are as follows:
 *      --option --mem-lb=0x400000   Prevents E9Patch putting trampolines
 *                                   in addresses used by the RedFat
 *                                   runtime.  Not needed for PIE.
 *
 * TESTING
 *    To test the instrumentation, use the REDFAT_TEST=N environment variable:
 *
 *      $ LD_PRELOAD=/usr/share/redfat/libredfat.so REDFAT_TEST=100 ./a.out
 *
 *    This will cause 1/100 allocations to be 1 byte "too short", which
 *    should be detected as a memory error by this instrumentation or in a
 *    library function.
 *
 * FURTHER READING:
 *  This sample program is essentially a simplified version of RedFat.  See
 *  the RedFat paper and implementation for more information:
 *      - Gregory J. Duck, Yuntong Zhang, Roland H. C. Yap, Hardening Binaries
 *        against More Memory Errors, European Conference on Computer Systems
 *        (EuroSys), 2022
 *      - https://github.com/GJDuck/RedFat
 *
 *  The "full" RedFat implementation is significantly faster and more accurate
 *  than this sample program.  However, the implementation of "full" RedFat
 *  is also more complicated.
 */

#include "stdlib.c"

static bool option_tty = false;

#define PAGE_SIZE   4096

#define RED         (option_tty? "\33[31m": "")
#define GREEN       (option_tty? "\33[32m": "")
#define YELLOW      (option_tty? "\33[33m": "")
#define OFF         (option_tty? "\33[0m" : "")

#define REDZONE     16

/*
 * RedFat config.
 * This should be the same as that used by libredfat.so.
 */
#define _REDFAT_SIZES ((size_t *)0x100000)
#define _REDFAT_MAGICS ((uint64_t *)0x180000)
#define _REDFAT_REGION_SIZE 34359738368ull

/*
 * RedFat index operation.
 */
static inline size_t redfat_index(const void *ptr)
{
    return (uintptr_t)ptr / _REDFAT_REGION_SIZE;
}

/*
 * RedFat size operation.
 */
static inline size_t redfat_size(const void *ptr)
{
    size_t idx = redfat_index(ptr);
    return _REDFAT_SIZES[idx];
}

/*
 * RedFat base operation.
 */
static inline void *redfat_base(const void *base, const void *access)
{
    size_t idx = redfat_index(access);
    unsigned __int128 tmp = (unsigned __int128)_REDFAT_MAGICS[idx] *
        (unsigned __int128)(uintptr_t)base;
    size_t objidx = (size_t)(tmp >> 64);
    return (size_t *)(objidx * _REDFAT_SIZES[idx]);
}

/*
 * Memory error check routine:
 *  - loc    = static instruction address.
 *  - base   = memory operand base pointer.
 *  - access = actual address that is accessed.
 *  - sz     = the size of the memory access.
 *  - _asm   = the ASM string of the instruction.
 */ 
void check(const void *loc, const void *base, const void *access, size_t sz,
    const char *_asm)
{
    /*
     * Step (1): Find the base of the allocation, which has the following
     *           layout (as guaranteed by libredfat.so):
     *
     *           +----+--------------+
     *           | Sz |    Object    |
     *           +----+--------------+
     *           Allocation
     *
     *           The allocation base stores the object size metadata (Sz)
     *           which is prepended to the start of the object.  The meta
     *           region also serves as an inaccessible redzone between
     *           objects.
     */
    const size_t *meta = (size_t *)redfat_base(base, access);
    if (meta == NULL)
        return;         // Not a RedFat pointer

    /*
     * Step (2): Do the bounds check.  Note that "free" objects will have a
     *           size==0, so will always fail the bounds check.
     */
    size_t size = *meta;
    const uint8_t *lb = (uint8_t *)meta + REDZONE;
    const uint8_t *ub = lb + size;
    const uint8_t *access8 = (uint8_t *)access;
    if (access8 >= lb && access8 + sz <= ub && size < redfat_size(access))
        return;         // Valid memory access

    /*
     * Step (3): A memory error has been detected.  Gather useful information
     *           and print the error to stderr, then abort.
     */
    const uint8_t *access_base = (uint8_t *)redfat_base(access, access);
    size_t access_size         = *(size_t *)access_base;
    bool access_free           = (access_size == 0x0);
    access_size                = (access_free? redfat_size(access): access_size);
    const uint8_t *access_lb   = access_base + REDZONE;
    const uint8_t *access_ub   = access_lb + access_size;

    const uint8_t *base_base   = (uint8_t *)redfat_base(base, access);
    size_t base_size           = *(size_t *)base_base;
    bool base_free             = (base_size == 0x0);
    base_size                  = (base_free? redfat_size(base): base_size);
    const uint8_t *base_lb     = base_base + REDZONE;
    const uint8_t *base_ub     = base_lb + base_size;

    const char *kind = "out-of-bounds";
    if (access_free && base_free)
        kind = "use-after-free";
    else if (size > redfat_size(access))
        kind = "size-metadata-corruption";

    const uint8_t *base8 = (uint8_t *)base;
    fprintf(stderr, "%sMEMORY ERROR%s: %s error detected!\n"
            "\tinstruction = %s%s%s [%s%p%s]\n"
            "\taccess.ptr  = %p\n"
            "\taccess.size = %zu\n"
            "\taccess.obj  = [%+ld..%+ld]%s\n"
            "\tbase.ptr    = %p (%+ld)\n"
            "\tbase.obj    = [%+ld..%+ld]%s\n",
            RED, OFF, kind,
            GREEN, _asm, OFF,
            YELLOW, loc, OFF,
            access, sz,
            access_lb - access8,
            access_ub - access8,
            (access_free? " (free)": ""),
            base, base8 - access8,
            base_lb - access8,
            base_ub - access8,
            (base_free? " (free)": ""));
    abort();
}

/*
 * Init.
 */
void init(int argc, char **argv)
{
    option_tty = isatty(STDERR_FILENO);

    if (msync((void *)_REDFAT_MAGICS, PAGE_SIZE, MS_ASYNC) == 0)
        return;        // RedFat library has been LD_PRELOAD'ed

    fprintf(stderr, "%serror%s: the libredfat.so library must be preloaded, "
                        "e.g.:\n"
                    "       %sLD_PRELOAD=/usr/share/redfat/libredfat.so %s "
                        "...%s\n",
                    RED, OFF, YELLOW, argv[0], OFF);
    abort();
}

