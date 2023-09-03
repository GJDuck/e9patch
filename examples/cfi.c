/*
 * CONTROL FLOW INTEGRITY (CFI) instrumentation.
 */

/*
 * A simple implementation of coarse-grained binary Control Flow Integrity.
 * Here, indirect jumps/calls are instrumented with a validity check based
 * on E9Tool's jump target analysis.
 *
 * EXAMPLE USAGE:
 *  $ e9compile cfi.c
 *  $ e9tool --plt --dump-all -M "(jmp or call) and defined(mem[0])" \
 *       -P 'entry((static)addr,(static)target,asm)@cfi' xterm
 *  $ ./a.out
 *  $ DEBUG=1 ./a.out
 *
 * INPUT:
 *  This example program parses the "a.out.TARGETs.csv" and 
 *  "a.out.DISASM.csv" files.  Use E9Tool's --dump-all option to generate
 *  these files.
 *
 * LIMITATIONS:
 *  - Only addresses within the instrumented binary are checked.
 *  - The accuracy depends on E9Tool's indirect jump/call analysis.
 *    The analysis is not 100% perfect, and tends to overapproximate.
 */

#include "stdlib.c"

static bool option_tty   = false;
static bool option_debug = false;

#define RED         (option_tty? "\33[31m": "")
#define GREEN       (option_tty? "\33[32m": "")
#define YELLOW      (option_tty? "\33[33m": "")
#define MAGENTA     (option_tty? "\33[35m": "")
#define OFF         (option_tty? "\33[0m" : "")

typedef struct
{
    uintptr_t *data;
    uintptr_t lb;
    uintptr_t ub;
    size_t size;
    size_t max;
} INFO;
static INFO TARGETs = {0};                      // All targets.

typedef enum
{
    VALID,
    INVALID,
    UNKNOWN
} RESULT;

/*
 * Error reporting.
 */
#define error(msg, ...)                                         \
    do {                                                        \
        fprintf(stderr, "%serror%s: " msg "\n", RED, OFF,       \
            ##__VA_ARGS__);                                     \
        abort();                                                \
    } while (false)
#define message(msg, ...)                                       \
    fprintf(stderr, msg "\n", ##__VA_ARGS__);                   \

/*
 * Target push.
 */
static void target_push(uintptr_t target)
{
    if (TARGETs.size >= TARGETs.max)
    {
        TARGETs.lb   = (TARGETs.max == 0? UINTPTR_MAX: TARGETs.lb);
        TARGETs.max  = (TARGETs.max == 0? 16: 2 * TARGETs.max);
        TARGETs.data = (uintptr_t *)realloc(TARGETs.data,
            TARGETs.max * sizeof(uintptr_t));
        if (TARGETs.data == NULL)
            error("failed to allocate memory: %s", strerror(errno));
    }
    TARGETs.data[TARGETs.size++] = target;
}

/*
 * Target range.
 */
static void target_range(uintptr_t lb, uintptr_t ub)
{
    TARGETs.lb = (lb < TARGETs.lb? lb: TARGETs.lb);
    TARGETs.ub = (ub > TARGETs.ub? ub: TARGETs.ub);
}

/*
 * Target check.
 */
static RESULT target_check(uintptr_t target)
{
    if (target < TARGETs.lb || target > TARGETs.ub)
        return UNKNOWN;
    ssize_t lo = 0, hi = TARGETs.size-1;
    while (lo <= hi)
    {
        ssize_t mid = (lo + hi) / 2;
        if (TARGETs.data[mid] < target)
            lo = mid+1;
        else if (TARGETs.data[mid] > target)
            hi = mid-1;
        else
            return VALID;
    }
    return INVALID;
}

/*
 * Entry point.
 */
void entry(const void *loc, const void *target, const char *_asm)
{
    switch (target_check((uintptr_t)target))
    {
        case INVALID:
            message("%s%p%s: %s%s%s: target %s%p%s is %sINVALID%s",
                MAGENTA, loc, OFF,
                GREEN, _asm, OFF,
                YELLOW, target, OFF,
                RED, OFF);
            if (!option_debug)
                abort();
            break;
        case VALID:
            if (!option_debug)
                return;
            message("%s%p%s: %s%s%s: target %s%p%s is %sVALID%s",
                MAGENTA, loc, OFF,
                GREEN, _asm, OFF,
                YELLOW, target, OFF,
                GREEN, OFF);
            break;
        case UNKNOWN:
            if (!option_debug)
                return;
            message("%s%p%s: %s%s%s: target %s%p%s is not tracked",
                MAGENTA, loc, OFF,
                GREEN, _asm, OFF,
                YELLOW, target, OFF);
            break;
    }
}

/*
 * Init.
 */
void init(int argc, char **argv, char **envp)
{
    environ = envp;
    option_tty   = isatty(STDERR_FILENO);
    option_debug = (getenv("DEBUG") != 0);
    const char *progname = argv[0];

    char *input;
    if (asprintf(&input, "%s.TARGETs.csv", progname) < 0)
        error("failed to create input filename: %s", strerror(errno));
    FILE *stream = fopen(input, "r");
    if (stream == NULL)
        error("failed to open \"%s%s%s\" for reading: %s", YELLOW, input,
            OFF, strerror(errno));
    char c;
    while ((c = getc(stream)) != '\n' && c != EOF)
        ;
    uintptr_t target, direct, indirect, func;
    while (fscanf(stream, "%zx,%zu,%zu,%zu", &target, &direct, &indirect, &func)
        == 4)
    {
        if (indirect)
            target_push(target);
    }
    TARGETs.max = TARGETs.size;
    TARGETs.data = (uintptr_t *)realloc(TARGETs.data,
        TARGETs.max * sizeof(uintptr_t));
    if (TARGETs.data == NULL)
        error("failed to allocate memory: %s", strerror(errno));
    fclose(stream);
    free(input);

    if (asprintf(&input, "%s.DISASM.csv", progname) < 0)
        error("failed to create input filename: %s", strerror(errno));
    stream = fopen(input, "r");
    if (stream == NULL)
        error("failed to open \"%s%s%s\" for reading: %s", YELLOW, input,
            OFF, strerror(errno));
    while ((c = getc(stream)) != '\n' && c != EOF)
        ;
    uintptr_t addr, offset, size;
    while (fscanf(stream, "%zx,%zu,%zu", &addr, &offset, &size) == 3)
        target_range(addr, addr+size);
    fclose(stream);
    free(input);
}

