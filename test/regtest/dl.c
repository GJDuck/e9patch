#define LIBDL
#include "stdlib.c"

static void *handle       = NULL;
static void *fprintf_func = NULL;
static void *stderr_ptr   = NULL;
static void *func         = NULL;

void libc_fprintf(intptr_t x)
{
    dlcall(fprintf_func, stderr_ptr,
        "x = 0x%.16lx [%d %d %d %d %d %d %d %d %d %d]\n", x,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
}

void test_func(void)
{
    dlcall(func);
}

void test_func_2(void)
{
    void (*f)(void) = func;
    f();        // Direct call clobbers state
}

void init(int argc, char **argv, char **envp, const void *dynamic)
{
    if (dlinit(dynamic) != 0)
    {
        fprintf(stderr, "dlinit() failed: %s\n", strerror(errno));
        abort();
    }

    handle = dlopen("libc.so.6", RTLD_LAZY);
    if (handle == NULL)
    {
        fprintf(stderr, "dlopen(\"libc.so\") failed\n");
        abort();
    }

    // Get fprintf
    fprintf_func = dlsym(handle, "fprintf");
    if (fprintf_func == NULL)
    {
        fprintf(stderr, "dlsym(\"fprintf\") failed\n");
        abort();
    }
    fprintf(stderr, "found fprintf...\n");

    // Get stderr
    void **stderr_ptrptr = (void **)dlsym(handle, "stderr");
    if (stderr_ptrptr == NULL)
    {
        fprintf(stderr, "dlsym(\"stderr\") failed\n");
        abort();
    }
    stderr_ptr = *stderr_ptrptr;
    fprintf(stderr, "found stderr...\n");

    handle = dlopen("/proc/self/exe", RTLD_LAZY);
    if (handle == NULL)
    {
        fprintf(stderr, "dlopen(\"/proc/self/exe\") failed\n");
        abort();
    }

    // Get func()
    func = dlsym(handle, "func");
    if (func == NULL)
    {
        fprintf(stderr, "dlym(\"func\") failed\n");
        abort();
    }
    fprintf(stderr, "found func...\n");
}

