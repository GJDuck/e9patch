/*
 * LIMIT instrumentation.
 */

/*
 * Associates a counter with each matching instruction address.
 * Once the LIMIT is reached, then abort() execution.
 *
 * EXAMPLE USAGE:
 *  $ e9compile limit.c
 *  $ e9tool -M jmp -P 'entry((static)addr)@limit' xterm
 *  $ ./a.out
 *  $ LIMIT=10000 ./a.out
 */

#include "stdlib.c"

typedef struct
{
    const void *addr;
    size_t count;
} ENTRY;

static void *TREE = NULL;                       // Global state.
static mutex_t mutex = MUTEX_INITIALIZER;       // Global mutex.
static size_t limit = 0;                        // Limit.

/*
 * ENTRY compare.
 */
static int compare(const void *n, const void *m)
{
    const ENTRY *a = (const ENTRY *)n, *b = (const ENTRY *)m;
    if (a->addr < b->addr)
        return -1;
    if (a->addr > b->addr)
        return 1;
    return 0;
}

/*
 * Entry point.
 */
void entry(const void *addr)
{
    if (mutex_lock(&mutex) < 0)
    {
        if (errno == EOWNERDEAD)
        {
            fputs("thread died with lock\n", stderr);
            abort();
        }
        return;
    }

    // This uses tfind()/tsearch() to track instruction counts.
    // For more information, see the tsearch manpage (man tsearch).
    ENTRY key = {addr, 0}, *entry = NULL;
    void *node = tfind(&key, &TREE, compare);
    if (node == NULL)
    {
        entry = (ENTRY *)malloc(sizeof(ENTRY));
        if (entry == NULL)
        {
error_no_mem:
            fputs("failed to allocate memory\n", stderr);
            abort();
        }
        entry->addr  = addr;
        entry->count = 0;
        node = tsearch(entry, &TREE, compare);
        if (node == NULL)
            goto error_no_mem;
    }
    entry = *(ENTRY **)node;
    entry->count++;
    if (entry->count > limit)
    {
        fprintf(stderr, "limit=%zu reached @ addr=%p\n", limit, addr);
        abort();
    }

    mutex_unlock(&mutex);
}

/*
 * Init.
 */
void init(int argc, char **argv, char **envp)
{
    environ = envp;
    limit   = 1000;
    const char *val = getenv("LIMIT");
    if (val != NULL)
        limit = atoll(val);
}

