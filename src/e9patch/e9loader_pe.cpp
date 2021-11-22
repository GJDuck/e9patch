/*
 * e9loader_pe.cpp
 * Copyright (C) 2021 National University of Singapore
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * NOTE: As a special exception, this file is under the MIT license.  The
 *       rest of the E9Patch/E9Tool source code is under the GPLv3 license.
 */

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <wchar.h>

#include "e9loader.cpp"

#define CONTAINING_RECORD(addr,type,field)              \
    ((type *)((uint8_t *)(addr) - (uint8_t *)(&((type *)0)->field)))

typedef struct _UNICODE_STRING
{
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _PEB_LDR_DATA
{
    uint8_t    Reserved1[8];
    void      *Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    void          *Reserved1[2];
    LIST_ENTRY     InMemoryOrderLinks;
    void          *Reserved2[2];
    void          *DllBase;
    void          *Reserved3[2];
    UNICODE_STRING FullDllName;
    uint8_t        Reserved4[8];
    void          *Reserved5[3];
    union
    {
        uint64_t   CheckSum;
        void      *Reserved6;
    };
    uint64_t       TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    uint32_t MaximumLength;
    uint32_t Length;
    uint32_t Flags;
    uint32_t DebugFlags;
    void    *ConsoleHandle;
    uint32_t ConsoleFlags;
    void    *StdInputHandle;
    void    *StdOutputHandle;
    void    *StdErrorHandle;
    // ...etc.
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{
    uint8_t       Reserved1[2];
    uint8_t       BeingDebugged;
    uint8_t       Reserved2[1];
    void         *Reserved3[1];
    void         *ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    void         *SubSystemData;
    void         *ProcessHeap;
    uint8_t       Reserved4[88];
    void         *Reserved5[52];
    void         *PostProcessInitRoutine;
    uint8_t       Reserved6[128];
    void         *Reserved7[1];
    uint64_t      SessionId;
} PEB, *PPEB;

typedef struct _IMAGE_FILE_HEADER
{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_DIRECTORY_ENTRY_EXPORT    0

typedef struct _IMAGE_EXPORT_DIRECTORY
{
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef void *(*load_library_t)(const char *lib);
typedef void *(*get_proc_address_t)(const void *module, const char *name);
typedef int32_t *(*get_last_error_t)(void);
typedef int (*attach_console_t)(int32_t pid);
typedef void *(*get_std_handle_t)(int32_t handle);
typedef int8_t (*write_console_t)(void *handle, void *buf, int32_t len,
    int32_t *out, void *unused);
typedef void *(*create_file_t)(const wchar_t *name, int32_t access,
    int32_t mode, void *sec, int32_t disp, int32_t flags, void *temp);
typedef void *(*create_file_mapping_t)(void *file, void *sec, int32_t prot,
    int32_t min, int32_t max, const char *name);
typedef void *(*map_view_of_file_ex_t)(void *mapping, int32_t access,
    int32_t hi, int32_t lo, size_t size, void *base);
typedef int (*close_handle_t)(void *handle);
typedef int (*virtual_protect_t)(void *addr, size_t size, uint32_t prot,
    uint32_t *old_prot);

static get_proc_address_t get_proc_address = NULL;
static e9_nt_write_file_t nt_write_file    = NULL;
static e9_nt_read_file_t nt_read_file      = NULL;

#define DLL_PROCESS_ATTACH      1
#define STD_ERROR_HANDLE        (-12)
#define INVALID_HANDLE_VALUE    ((void *)(-1))

static inline void e9panic(void)
{
    asm volatile (
        "mov $0x7, %ecx\n"  // FAST_FAIL_FATAL_APP_EXIT
        "int $0x29"         // __fast_fail
    );
    while (true)
        asm volatile ("ud2");
    __builtin_unreachable();
}

/*
 * Write an error message and exit.
 */
static NO_INLINE NO_RETURN void e9error_impl(void *stderr,
    write_console_t WriteConsole, const char *msg, ...)
{
    char buf[BUFSIZ], *str = buf;
    str = e9write_str(str, "e9patch loader error: ");
    va_list ap;
    va_start(ap, msg);
    str = e9write_format(str, msg, ap);
    va_end(ap);
    str = e9write_char(str, '\n');

    size_t len = str - buf;
    WriteConsole(stderr, buf, len, NULL, NULL);
    while (true)
        asm volatile ("ud2");
    __builtin_unreachable();
}
#define e9error(msg, ...)                                                \
    e9error_impl(stderr, WriteConsole, msg, ##__VA_ARGS__)

/*
 * Write a debug message.
 */
static NO_INLINE void e9debug_impl(void *stderr, write_console_t WriteConsole,
    const char *msg, ...)
{
    char buf[BUFSIZ], *str = buf;
    str = e9write_str(str, "e9patch loader debug: ");
    va_list ap;
    va_start(ap, msg);
    str = e9write_format(str, msg, ap);
    va_end(ap);
    str = e9write_char(str, '\n');

    size_t len = str - buf;
    WriteConsole(stderr, buf, len, NULL, NULL);
}
#define e9debug(msg, ...)                                               \
    e9debug_impl(stderr, WriteConsole, msg, ##__VA_ARGS__)

extern "C"
{
    void *e9loader(PEB *peb, const struct e9_config_s *config);
}

asm (
    /*
     * E9Patch loader entry point.
     */
    ".globl _entry\n"
    ".type _entry,@function\n"
    ".section .text.entry,\"x\",@progbits\n"
    "_entry:\n"
    // %r9 = pointer to config.

    "\tpushq %rcx\n"            // Save DllMain() args
    "\tpushq %rdx\n"
    "\tpushq %r8\n"

    "\tmov %gs:0x60,%rcx\n"     // Call e9loader()
    "\tmov %edx, %r8d\n"
    "\tmov %r9, %rdx\n"
    "\tcallq e9loader\n"
    // %rax = real entry point.

    "\tpop %r8\n"               // Restore DllMain() args
    "\tpop %rdx\n"
    "\tpop %rcx\n"

    "\tjmpq *%rax\n"

    ".section .text\n"
);

/*
 * to_lower()
 */
static wchar_t e9towlower(wchar_t c)
{
    if (c >= L'A' && c <= L'Z')
        return L'a' + (c - L'A');
    return c;
}

/*
 * wcscasecmp()
 */
static int e9wcscasecmp(const wchar_t *s1, const wchar_t *s2)
{
    for (; e9towlower(*s1) == e9towlower(*s2) && *s1 != L'\0'; s1++, s2++)
        ;
    return (int)e9towlower(*s2) - (int)e9towlower(*s1);
}

/*
 * strcmp()
 */
static int e9strcmp(const char *s1, const char *s2)
{
    for (; *s1 == *s2 && *s1 != '\0'; s1++, s2++)
        ;
    return (int)*s2 - (int)*s1;
}

/*
 * Find a function from a DLL (a.k.a. GetProcAddress).
 */
static NO_INLINE const void *e9get(const uint8_t *dll, const char *target)
{
    if (dll == NULL)
        return NULL;

    uint32_t pe_offset = *(const uint32_t *)(dll + 0x3c);
    const IMAGE_FILE_HEADER *file_hdr =
        (PIMAGE_FILE_HEADER)(dll + pe_offset + sizeof(uint32_t));
    const IMAGE_OPTIONAL_HEADER64 *opt_hdr =
        (PIMAGE_OPTIONAL_HEADER64)(file_hdr + 1);
    const IMAGE_EXPORT_DIRECTORY *exports = (PIMAGE_EXPORT_DIRECTORY)(dll +
        opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    const uint32_t *names = (uint32_t *)(dll + exports->AddressOfNames);
    const uint32_t *funcs = (uint32_t *)(dll + exports->AddressOfFunctions);
    uint32_t num_names    = exports->NumberOfNames;

    int32_t lo = 0, hi = (int32_t)(num_names - 1);
    while (lo <= hi)
    {
        int32_t mid = (lo + hi) / 2;
        const char *name = (const char *)(dll + names[mid]);
        int cmp = e9strcmp(target, name);
        if (cmp < 0)
            lo = mid + 1;
        else if (cmp > 0)
            hi = mid - 1;
        else
            return (const void *)(dll + funcs[mid]);
    }
    return NULL;
}

/*
 * Unlike Linux, the Windows kernel uses extended registers (%xmm, etc.),
 * which means these must be preserved.  This is handled by the e9safe_call()
 * wrapper.
 */
extern "C"
{
    static intptr_t e9safe_call(const void *f, ...);
}
asm (
    ".globl e9safe_call\n"
    ".type e9safe_call, @function\n"
    "e9safe_call:\n"

    // Align the stack:
    "mov %rsp,%r11\n"
    "and $-64,%rsp\n"
    "push %r11\n"

    // Save extended state:
    "lea -(0x1000+64-8)(%rsp),%rsp\n"
    "mov %rdx,%r10\n"
    "xor %edx,%edx\n"
    "mov $0xe7,%eax\n"          // x87,SSE,AVX,AVX512
    "mov %rdx,512(%rsp)\n"      // Zero XSAVE header
    "mov %rdx,512+8(%rsp)\n"
    "mov %rdx,512+16(%rsp)\n"
    "mov %rdx,512+24(%rsp)\n"
    "xsave (%rsp)\n"

    // Call the function:
    "xchg %rcx,%r10\n"
    "mov %r8,%rdx\n"
    "mov %r9,%r8\n"
    "mov 0x28(%r11),%r9\n"
    "mov 0x88(%r11),%rax\n"
    "push %rax\n"
    "mov 0x80(%r11),%rax\n"
    "push %rax\n"
    "mov 0x78(%r11),%rax\n"
    "push %rax\n"
    "mov 0x70(%r11),%rax\n"
    "push %rax\n"
    "mov 0x68(%r11),%rax\n"
    "push %rax\n"
    "mov 0x60(%r11),%rax\n"
    "push %rax\n"
    "mov 0x58(%r11),%rax\n"
    "push %rax\n"
    "mov 0x50(%r11),%rax\n"
    "push %rax\n"
    "mov 0x48(%r11),%rax\n"
    "push %rax\n"
    "mov 0x40(%r11),%rax\n"
    "push %rax\n"
    "mov 0x38(%r11),%rax\n"
    "push %rax\n"
    "mov 0x30(%r11),%rax\n"
    "push %rax\n"
    "add $-0x20,%rsp\n"
    "callq *%r10\n"             // f(...)

    // Restore extended state:
    "mov %rax,%rcx\n"
    "xor %edx,%edx\n"
    "mov $0xe7,%eax\n"
    "xrstor 0x80(%rsp)\n"
    "mov %rcx,%rax\n"
    "lea 0x1000+64-8+0x80(%rsp),%rsp\n"

    // Unalign the stack:
    "pop %rsp\n"

    "retq\n"
);

/*
 * System/library call wrappers.
 */
static void *e9get_proc_address_wrapper(const void *module, const char *name)
{
    return (void *)e9safe_call((void *)get_proc_address, module, name);
}
static int32_t e9nt_write_file_wapper(intptr_t handle, intptr_t event,
    void *apc_routine, void *apc_ctx, void *status, void *buf,
    uint32_t len, void *byte_offset, void *key)
{
    return e9safe_call((void *)nt_write_file, handle, event, apc_routine,
        apc_ctx, status, buf, len, byte_offset, key);
}
static int32_t e9nt_read_file_wapper(intptr_t handle, intptr_t event,
    void *apc_routine, void *apc_ctx, void *status, void *buf,
    uint32_t len, void *byte_offset, void *key)
{
    return e9safe_call((void *)nt_read_file, handle, event, apc_routine,
        apc_ctx, status, buf, len, byte_offset, key);
}

/*
 * Main loader code.
 */
void *e9loader(PEB *peb, const struct e9_config_s *config)
{
    // Step (0): Sanity checks & initialization:
    const uint8_t *loader_base = (const uint8_t *)config;
    const uint8_t *image_base  = loader_base - config->base;
    void *entry = (void *)(image_base + config->entry);
    static bool inited = false;
    if (inited)
        return entry;   // Enforce single execution
    inited = true;

    // Step (1): Parse the PEB/LDR for kernel32.dll and our image path:
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY *curr = ldr->InMemoryOrderModuleList.Flink;
    const uint8_t *kernel32 = NULL, *user32 = NULL, *ntdll = NULL;
    const wchar_t *self = NULL;

    while (curr != NULL && curr != &ldr->InMemoryOrderModuleList &&
            (kernel32 == NULL || self == NULL || user32 == NULL))
    {
        const LDR_DATA_TABLE_ENTRY* entry =
            CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        const UNICODE_STRING *name = &entry->FullDllName;
        if (entry->DllBase == (void *)image_base)
            self = name->Buffer;
        name++;     // BaseDllName immediately follows FullDllName
        if (e9wcscasecmp(name->Buffer, L"kernel32.dll") == 0)
            kernel32 = (const uint8_t *)entry->DllBase;
        else if (e9wcscasecmp(name->Buffer, L"ntdll.dll") == 0)
            ntdll = (const uint8_t *)entry->DllBase;
        else if (e9wcscasecmp(name->Buffer, L"user32.dll") == 0)
            user32 = (const uint8_t *)entry->DllBase;
        curr = curr->Flink;
    }
    if (kernel32 == NULL || self == NULL)
        e9panic();

    // Step (2): Get critical functions necessary for output:
    get_proc_address_t GetProcAddress =
        (get_proc_address_t)e9get(kernel32, "GetProcAddress");
    if (GetProcAddress == NULL)
        e9panic();
    attach_console_t AttachConsole =
        (attach_console_t)GetProcAddress(kernel32, "AttachConsole");
    get_std_handle_t GetStdHandle =
        (get_std_handle_t)GetProcAddress(kernel32, "GetStdHandle");
    if (AttachConsole == NULL || GetStdHandle == NULL)
        e9panic();
    (void)AttachConsole(-1);
    void *stderr = GetStdHandle(STD_ERROR_HANDLE);
    write_console_t WriteConsole =
        (write_console_t)GetProcAddress(kernel32, "WriteConsoleA");
    if (WriteConsole == NULL)
        e9panic();

    if (config->magic[0] != 'E' || config->magic[1] != '9' ||
            config->magic[2] != 'P' || config->magic[3] != 'A' ||
            config->magic[4] != 'T' || config->magic[5] != 'C' ||
            config->magic[6] != 'H' || config->magic[7] != '\0')
        e9error("missing \"E9PATCH\" magic number");
    if (config->inits != 0x0)
        e9error("custom initialization functions are not-yet-implemented");
    if (config->finis != 0x0)
        e9error("custom finalization functions are not-yet-implemented");
    if (config->mmap != 0x0)
        e9error("custom memory mapping functions are not-yet-implemented");

    // Step (3): Get functions necessary for loader:
    get_last_error_t GetLastError =
        (get_last_error_t)GetProcAddress(kernel32, "GetLastError");
    if (GetLastError == NULL)
        e9error("GetProcAddress(name=\"GetLastError\") failed");
    create_file_t CreateFile =
        (create_file_t)GetProcAddress(kernel32, "CreateFileW");
    if (CreateFile == NULL)
        e9error("GetProcAddress(name=\"%s\") failed (error=%d)", "CreateFileW",
            GetLastError());
    create_file_mapping_t CreateFileMapping =
        (create_file_mapping_t)GetProcAddress(kernel32, "CreateFileMappingA");
    if (CreateFileMapping == NULL)
        e9error("GetProcAddress(name=\"%s\") failed (error=%d)",
            "CreateFileMappingA", GetLastError());
    map_view_of_file_ex_t MapViewOfFileEx =
        (map_view_of_file_ex_t)GetProcAddress(kernel32, "MapViewOfFileEx");
    if (MapViewOfFileEx == NULL)
        e9error("GetProcAddress(name=\"%s\") failed (error=%d)",
            "MapViewOfFileEx", GetLastError());
    close_handle_t CloseHandle =
        (close_handle_t)GetProcAddress(kernel32, "CloseHandle");
    if (CloseHandle == NULL)
        e9error("GetProcAddress(name=\"%s\") failed (error=%d)",
            "CloseHandle", GetLastError());

    // Step (4): Load the trampoline code:
#define GENERIC_READ            0x80000000
#define GENERIC_EXECUTE         0x20000000
#define OPEN_EXISTING           3
#define FILE_ATTRIBUTE_NORMAL   0x00000080
    void *file = CreateFile(self, GENERIC_READ | GENERIC_EXECUTE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, INVALID_HANDLE_VALUE);
    if (file == INVALID_HANDLE_VALUE)
        e9error("CreateFile(path=\"%S\") failed (error=%d)", self,
            GetLastError());

#define PAGE_EXECUTE_READ       0x20
#define PAGE_READONLY           0x02
#define SEC_COMMIT              0x8000000
#define PAGE_EXECUTE_WRITECOPY  0x80
    void *mapping = CreateFileMapping(file, NULL,
        PAGE_EXECUTE_READ | SEC_COMMIT, 0, 0, NULL);
    if (mapping == NULL)
        e9error("CreateFileMapping(file=\"%S\") failed (error=%d)", self,
            GetLastError());

#define FILE_MAP_COPY           0x0001
#define FILE_MAP_READ           0x0004
#define FILE_MAP_EXECUTE        0x0020
    const struct e9_map_s *maps =
        (const struct e9_map_s *)(loader_base + config->maps[1]);
    for (uint32_t i = 0; i < config->num_maps[1]; i++)
    {
        const uint8_t*addr = (maps[i].abs? (const uint8_t *)NULL: image_base);
        addr += (intptr_t)maps[i].addr * PAGE_SIZE;
        off_t offset = (off_t)maps[i].offset * PAGE_SIZE;
        size_t len = (size_t)maps[i].size * PAGE_SIZE;

        int32_t prot = 0x0;
        if (maps[i].w)
            prot |= FILE_MAP_COPY;
        else if (maps[i].r)
            prot |= FILE_MAP_READ;
        prot |= (maps[i].x? FILE_MAP_EXECUTE: 0x0);

#if 0
        e9debug("MapViewOfFileEx(addr=%p,size=%U,offset=+%U,prot=%c%c%c)",
            addr, len, offset,
            (maps[i].r? 'r': '-'), (maps[i].w? 'w': '-'),
            (maps[i].x? 'x': '-'));
#endif

        int32_t offset_lo = (int32_t)offset,
                offset_hi = (int32_t)(offset >> 32);
        void *result = MapViewOfFileEx(mapping, prot, offset_hi, offset_lo,
            len, (void *)addr);
        if (result == NULL)
            e9error("MapViewOfFileEx(addr=%p,size=%U,offset=+%U,prot=%c%c%c) "
                "failed (error=%d)", addr, len, offset,
                (maps[i].r? 'r': '-'), (maps[i].w? 'w': '-'),
                (maps[i].x? 'x': '-'), GetLastError());
    }
    if (!CloseHandle(file))
        e9error("failed to close %s handle (error=%d)", "file",
            GetLastError());
    if (!CloseHandle(mapping))
        e9error("failed to close %s handle (error=%d)", "mapping",
            GetLastError());

    // Step (5): Setup the platform-specific data:
    PRTL_USER_PROCESS_PARAMETERS params = peb->ProcessParameters;
    struct e9_config_pe_s *config_pe = (struct e9_config_pe_s *)(config + 1);

    config_pe->safe_call        = (e9_safe_call_t)&e9safe_call; 
    config_pe->get_proc_address =
        (e9_get_proc_address_t)&e9get_proc_address_wrapper;
    config_pe->nt_read_file     = &e9nt_read_file_wapper;
    config_pe->nt_write_file    = &e9nt_write_file_wapper;
    config_pe->ntdll            = ntdll;
    config_pe->kernel32         = kernel32;
    config_pe->user32           = user32;
    config_pe->stdin_handle     = (intptr_t)params->StdInputHandle;
    config_pe->stdout_handle    = (intptr_t)params->StdOutputHandle;
    config_pe->stderr_handle    = (intptr_t)params->StdErrorHandle;

    get_proc_address = GetProcAddress;
    nt_write_file = (e9_nt_write_file_t)GetProcAddress(ntdll, "NtWriteFile");
    nt_read_file  = (e9_nt_read_file_t)GetProcAddress(ntdll, "NtReadFile");
    
    virtual_protect_t VirtualProtect =
        (virtual_protect_t)GetProcAddress(kernel32, "VirtualProtect");
    if (VirtualProtect != NULL)
    {
        uint8_t *base = (uint8_t *)config;
        uint32_t old_prot;
        (void)VirtualProtect(base, config->size, PAGE_EXECUTE_READ, &old_prot);
    }
    
    return entry;
}

