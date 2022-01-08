/*
 * LIMIT instrumentation.
 */

/*
 * Associates a counter with each instruction address.  Once LIMIT is
 * reached, then abort() execution.
 */

#include "stdlib.c"

// Reuse the e9patch RB-tree implementation:
#define RB_AUGMENT(_)       /* NOP */
#include "rbtree.c"

struct NODE;
typedef struct NODE NODE;

struct TREE
{
    NODE *root;
};
typedef struct TREE TREE;

struct NODE
{
    const void *addr;
    RB_ENTRY(NODE) entry;
    int color;
    size_t count;
};

static int compare(const NODE *n, const NODE *m)
{
    if (n->addr < m->addr)
        return -1;
    if (n->addr > m->addr)
        return 1;
    return 0;
}

RB_GENERATE_STATIC(TREE, NODE, entry, compare);
#define find(t, n)      TREE_RB_FIND((t), (n))
#define insert(t, n)    TREE_RB_INSERT((t), (n))

static TREE t = {NULL};
static mutex_t mutex = MUTEX_INITIALIZER;
static size_t limit = 0;

/*
 * Entry point.
 *
 * call entry(addr)@limit
 */
void entry(const void *addr)
{
    if (mutex_lock(&mutex) < 0)
    {
        switch (errno)
        {
            case EOWNERDEAD:
                fputs("thread died with lock\n", stderr);
                abort();
            default:
                return;
        }
    }

    NODE key;
    key.addr = addr;
    NODE *n = find(&t, &key);
    if (n == NULL)
    {
        n = (NODE *)malloc_unlocked(sizeof(NODE));
        if (n == NULL)
        {
            fprintf(stderr, "failed to allocated %zu bytes\n",
                sizeof(NODE));
            abort();
        }
        n->addr  = addr;
        n->count = 0;
        insert(&t, n);
    }

    n->count++;
    if (n->count > limit)
    {
        fprintf(stderr, "limit=%zu reached @ addr=%p\n", limit, addr);
        abort();
    }

    mutex_unlock(&mutex);
}

void init(int argc, char **argv, char **envp)
{
    environ = envp;
    limit   = 100000;
    const char *val = getenv("LIMIT");
    if (val != NULL)
        limit = atoll(val);
}

