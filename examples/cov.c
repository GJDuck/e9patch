/*
 * COVERAGE instrumentation.
 */

/*
 * Reports edge coverage information.
 *
 * EXAMPLE USAGE:
 *  $ e9compile cov.c
 *  $ e9tool --dump-all -M "jmp or call" \
 *       -P 'entry((static)BB,(static)next)@cov' xterm
 *  $ ./a.out
 *
 * INPUT:
 *  This example program parses the "a.out.BBs.csv" file in order to map jump
 *  targets to the corresponding basic block.  Use E9Tool's --dump-all option
 *  to generate this file.
 *
 * OUTPUT:
 *  This example program will write the resulting coverage into a
 *  "a.out.COV.csv" file with three columns:
 *      1) The "from" basic block
 *      2) The "to" basic block
 *      3) The count (number of times edge taken)
 *
 * NOTES:
 *  The output file will NOT be generated if the program crashes or calls fast
 *  exit (e.g., _Exit()).
 */

#include "stdlib.c"

static bool option_tty = false;

#define RED         (option_tty? "\33[31m": "")
#define GREEN       (option_tty? "\33[32m": "")
#define YELLOW      (option_tty? "\33[33m": "")
#define OFF         (option_tty? "\33[0m" : "")

typedef struct
{
    const uintptr_t from;
    const uintptr_t to;
    size_t count;
} ENTRY;

static void *COV = NULL;                    // Global state.
static mutex_t mutex = MUTEX_INITIALIZER;   // Global mutex.

static char *output = NULL;                 // Output filename.
static FILE *stream = NULL;                 // Output stream.

typedef struct
{
    uintptr_t *data;
    size_t size;
    size_t max;
} INFO;
static INFO BBs = {0};                      // All basic blocks.

/*
 * Error reporting.
 */
#define error(msg, ...)                                     \
    do {                                                    \
        fprintf(stderr, "%serror%s: " msg "\n", RED, OFF,   \
            ##__VA_ARGS__);                                 \
        abort();                                            \
    } while (false)

/*
 * Locking/unlocking.
 */
static bool LOCK(void)
{
    return (mutex_lock(&mutex) == 0);
}
static void UNLOCK(void)
{
    mutex_unlock(&mutex);
}

/*
 * BB lookup.
 */
static uintptr_t bb_lookup(uintptr_t target)
{
    ssize_t lo = 0, hi = BBs.size-1;
    while (lo <= hi)
    {
        ssize_t mid = (lo + hi) / 2;
        if (BBs.data[mid] < target)
            lo = mid+1;
        else if (BBs.data[mid] > target)
            hi = mid-1;
        else
            return BBs.data[mid];
    }
    return BBs.data[lo];
}

/*
 * ENTRY compare.
 */
static int compare(const void *n, const void *m)
{
    const ENTRY *a = (ENTRY *)n, *b = (ENTRY *)m;
    if (a->from != b->from)
        return (a->from < b->from? -1: 1);
    if (a->to != b->to)
        return (a->to < b->to? -1: 1);
    return 0;
}

/*
 * Entry point.
 */
void entry(const void *bb, const void *next)
{
    uintptr_t to   = (uintptr_t)next;
    uintptr_t from = (uintptr_t)bb;
    to = bb_lookup(to);
    ENTRY key = {from, to, 0};  

    if (!LOCK())
        return;

    void *node   = tfind(&key, &COV, compare);
    ENTRY *entry = (node != NULL? *(ENTRY **)node: NULL);
    if (entry == NULL)
    {
        entry = (ENTRY *)malloc(sizeof(ENTRY));
        if (entry == NULL)
            error("failed to allocate memory: %s", strerror(errno));
        memcpy(entry, &key, sizeof(ENTRY));
        (void)tsearch(entry, &COV, compare);
    }
    entry->count++;

    UNLOCK();
}

/*
 * Init.
 */
void init(int argc, char **argv, char **envp)
{
    option_tty = isatty(STDERR_FILENO);
    const char *progname = argv[0];
    
    char *input;
    if (asprintf(&input, "%s.BBs.csv", progname) < 0)
        error("failed to create input filename: %s", strerror(errno));
    stream = fopen(input, "r");
    if (stream == NULL)
        error("failed to open \"%s%s%s\" for reading: %s", YELLOW, input,
            OFF, strerror(errno));
    char c;
    while ((c = getc(stream)) != '\n' && c != EOF)
        ;
    void *lb, *ub;
    while (fscanf(stream, "%p,%p", &lb, &ub) == 2)
    {
        if (BBs.size >= BBs.max)
        {
            BBs.max  = (BBs.max == 0? 16: 2 * BBs.max);
            BBs.data = (uintptr_t *)realloc(BBs.data,
                BBs.max * sizeof(uintptr_t));
            if (BBs.data == NULL)
            {
                bad_realloc:
                error("failed to allocate memory: %s", strerror(errno));
            }
        }
        BBs.data[BBs.size++] = (uintptr_t)lb;
    }
    BBs.size++;
    BBs.max = BBs.size;
    BBs.data = (uintptr_t *)realloc(BBs.data, BBs.max * sizeof(uintptr_t));
    if (BBs.data == NULL)
        goto bad_realloc;
    BBs.data[BBs.size-1] = UINTPTR_MAX;
    fclose(stream);
    stream = NULL;
    fprintf(stderr, "%sCOV%s: parsed %s%zu%s basic-blocks from \"%s%s%s\"\n",
        GREEN, OFF, YELLOW, BBs.size-1, OFF, YELLOW, input, OFF);
    free(input);

    if (asprintf(&output, "%s.COV.csv", progname) < 0)
        error("failed to create output filename: %s", strerror(errno));
}

/*
 * Fini.
 */
void fini(void)
{
    LOCK();
    stream = fopen(output, "w");
    if (stream == NULL)
        error("failed to open file \"%s%s%s\" for writing: %s",
            YELLOW, output, OFF, strerror(errno));
    fputs("from,to,count\n", stream);
    for (void *node = tmin(&COV); node != NULL; node = tnext(node))
    {
        const ENTRY *entry = *(ENTRY **)node;
        fprintf(stream, "%p,%p,%zu\n",
            (void *)entry->from, (void *)entry->to, entry->count);
    }
    fclose(stream);
    fprintf(stderr, "%sCOV%s: saved edge coverage information to "
        "\"%s%s%s\"\n", GREEN, OFF, YELLOW, output, OFF);
    UNLOCK();
}

