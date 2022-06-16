#define LIBDL
#include "stdlib.c"

static void clobber_xmm0(uint64_t x)
{
    asm volatile ("movq %0,%%xmm0": : "r"(x));
}

static void *handle       = NULL;
static void *fprintf_func = NULL;
static void *stderr_ptr   = NULL;

void libc_fprintf(intptr_t x)
{
    dlcall(fprintf_func, stderr_ptr,
        "x = 0x%.16lx [%d %d %d %d %d %d %d %d %d %d]\n", x,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
}

void test_dlcall_1(void)
{
    dlcall(clobber_xmm0, 0x3FD5555555555555ull);
}

void test_dlcall_2(void)
{
    clobber_xmm0(/*0.3333...~=*/0x3FD5555555555555ull);
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
}

