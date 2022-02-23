/*
 * e9patch.h
 * Copyright (C) 2021 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __E9PATCH_H
#define __E9PATCH_H

#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <elf.h>
#include <sys/types.h>

#include <deque>
#include <map>
#include <set>
#include <vector>

#define NO_RETURN               __attribute__((__noreturn__))
#define NO_INLINE               __attribute__((__noinline__))

#define PAGE_SIZE               ((size_t)4096)

/*
 * States of each virtual memory byte.
 */
#define STATE_UNKNOWN           0x0     // Unknown or "don't care"
#define STATE_INSTRUCTION       0x1     // Used by an instruction.
#define STATE_PATCHED           0x2     // Used by a patched instruction.
#define STATE_FREE              0x3     // Was used by instruction, now free.
#define STATE_OVERFLOW          0x4     // Byte is past the end-of-file.
#define STATE_QUEUED            0x5     // Byte is queued for patching.
#define STATE_LOCKED            0x10    // Byte is locked (read-only).

/*
 * C-string comparator.
 */
struct CStrCmp
{
    bool operator()(const char* a, const char* b) const
    {
        return (strcmp(a, b) < 0);
    }
};

/*
 * Addresses.
 */
#define RELATIVE_ADDRESS_MAX        0x1FFFFFFFFFFFF000ll
#define RELATIVE_ADDRESS_MIN        (-0x1FFFFFFFFFFFF000ll)

#define ABSOLUTE_ADDRESS_MAX        0x7FFFFFFFFFFFF000ll
#define ABSOLUTE_ADDRESS_MIN        0x4000000000001000ll

#define RELATIVE_ADDRESS(p)         (p)
#define ABSOLUTE_ADDRESS(p)         ((p)+0x6000000000000000)

#define IS_RELATIVE(p)              \
    ((p) >= RELATIVE_ADDRESS_MIN && (p) <= RELATIVE_ADDRESS_MAX)
#define IS_ABSOLUTE(p)              \
    ((p) >= ABSOLUTE_ADDRESS_MIN && (p) <= ABSOLUTE_ADDRESS_MAX)

#define BASE_ADDRESS(p)             \
    (IS_ABSOLUTE(p)? (p)-0x6000000000000000: (p))

/*
 * Buffer.
 */
struct Buffer
{   
    unsigned i = 0; 
    const unsigned max;
    uint8_t * const buf;
    
    Buffer(uint8_t * bytes, unsigned max = UINT32_MAX) : buf(bytes), max(max)
    {
        ;
    }
    
    void push(uint8_t b)
    {
        if (buf != nullptr && i < max)
            buf[i] = b;
        i++;
    }
    
    void push(const uint8_t *data, unsigned len)
    {
        if (buf != nullptr && i < max)
        {
            unsigned size = (i + len > max? max - i: len);
            memcpy(buf + i, data, size);
        }
        i += len;
    }

    void push(uint8_t b, unsigned len)
    {
        if (buf != nullptr && i < max)
        {
            unsigned size = (i + len > max? max - i: len);
            memset(buf + i, b, size);
        }
        i += len;
    }

    size_t size(size_t start = 0)
    {
        return (size_t)i - start;
    }

    uint8_t *bytes()
    {
        return (i < max? buf + i: nullptr);
    }

    int commit(size_t start = 0)
    {
        if (i > max)
        {
            i = (unsigned)start;
            return -1;
        }
        return (int)i - (int)start;
    }

    void reset(size_t start = 0)
    {
        i = (unsigned)start;
    }
};

/*
 * Bounds.
 */
struct Bounds
{
    intptr_t lb;                        // Lower bound.
    intptr_t ub;                        // Upper bound.
};

/*
 * Trampoline template entry kind.
 */
enum EntryKind
{
    ENTRY_DEBUG,
    ENTRY_BYTES,
    ENTRY_ZEROES,
    ENTRY_LABEL,
    ENTRY_MACRO,
    ENTRY_REL8,
    ENTRY_REL32,
    ENTRY_INT8,
    ENTRY_INT16,
    ENTRY_INT32,
    ENTRY_INT64,
    ENTRY_INSTR,
    ENTRY_INSTR_BYTES,
    ENTRY_BREAK,
    ENTRY_TAKE,
};

/*
 * Trampoline template entry.
 */
struct Entry
{
    EntryKind kind;                     // Entry kind
    union
    {
        unsigned length;                // Entry length
        bool use;                       // Label use
        bool optimize;                  // Optimize break?
    };
    union
    {
        const uint8_t *bytes;           // Raw bytes
        const char *label;              // Label name
        const char *macro;              // Macro name
        uint8_t uint8;                  // 8bit integer constant
        uint16_t uint16;                // 16bit integer constant
        uint32_t uint32;                // 32bit integer constant
        uint64_t uint64;                // 64bit integer constant
    };
};

/*
 * A trampoline template.
 */
struct Trampoline
{
    int prot:31;                        // Protections.
    int preload:1;                      // Pre-load trampoline?
    unsigned num_entries;               // Number of entries.
    Entry entries[];                    // Entries.
};

/*
 * Trampoline comparator.
 */
struct TrampolineCmp
{
    bool operator()(const Trampoline *a, const Trampoline *b) const;
};

/*
 * The default evictee trampoline template.
 */
extern const Trampoline *evicteeTrampoline;

/*
 * Metadata entry.
 */
struct MetaEntry
{
    const char *name;                   // Name.
    const Trampoline *T;                // Trampoline.
};

/*
 * Metadata representation.
 */
struct Metadata
{
    size_t num_entries;                 // Number of entries.
    MetaEntry entries[];                // Entries.
};

/*
 * Instruction representation.
 */
struct Instr
{
    const size_t offset:46;             // The instruction offset
    const size_t size:4;                // The instruction size (bytes)
    const size_t pcrel32_idx:4;         // 32bit PC-relative imm idx (or 0)
    const size_t pcrel8_idx:4;          // 8bit PC-relative imm idx (or 0)
    const size_t pic:1;                 // PIC? (stored here for convenience)
    size_t       debug:1;               // Debug trampoline?
    size_t       patch:1;               // Will patch instruction?
    size_t       is_patched:1;          // Is the instruction patched?
    size_t       is_evicted:1;          // Is the instruction evicted?
    size_t       no_optimize:1;         // Disable -Ojump-elim?
    const intptr_t addr;                // The address of the instruction

    const struct Original
    {
        const uint8_t * const bytes;    // The (unmodified) instruction

        Original(const uint8_t *bytes) : bytes(bytes)
        {
            ;
        }
    } original;

    const struct Patched
    {
        uint8_t * const bytes;          // The (modified/patched) instruction
        uint8_t * const state;          // The instruction state

        Patched(uint8_t *bytes, uint8_t *state) : bytes(bytes), state(state)
        {
            ;
        }

    } patched;

    const Metadata *metadata = nullptr; // The instruction metadata.
    Instr *prev = nullptr;              // The previous instruction.
    Instr *next = nullptr;              // The next instruction.

    Instr(off_t offset, intptr_t addr, size_t size, const uint8_t *original,
            uint8_t *bytes, uint8_t *state,  size_t pcrel32_idx,
            size_t pcrel8_idx, bool pic) :
        offset((size_t)offset), addr(addr), size(size), original(original),
        patched(bytes, state), pcrel32_idx(pcrel32_idx),
        pcrel8_idx(pcrel8_idx), pic(pic), debug(false), patch(false),
        is_evicted(false), no_optimize(false), is_patched(false)
    {
        ;
    }
};

/*
 * Virtual address space allocation.
 */
struct Alloc
{
    intptr_t lb;                // Allocation lower bound
    intptr_t ub;                // Allocation upper bound
    const Instr *I;             // Instruction.
    union
    {
        const Trampoline *T;    // Trampoline.
        uint8_t *bytes;         // Flattened bytes.
    };
    unsigned entry;             // Entry offset.
};

/*
 * Interval tree.
 */
struct Node;
struct Tree
{
    Node *root;                 // Interval tree root
};

/*
 * Virtual address space allocator.
 */
struct Allocator
{
    Tree tree;                  // Interval tree

    /*
     * Iterators.
     */
    struct iterator
    {
        Node *node = nullptr;

        iterator() = default;
        iterator(const iterator &i) : node(i.node)
        {
            ;
        }
        iterator(Node *node) : node(node)
        {
            ;
        }

        Alloc *operator*();
        void operator++();
        bool operator!=(const iterator &i)
        {
            return (node != i.node);
        }
        bool operator==(const iterator &i)
        {
            return (node == i.node);
        }
        void operator=(const iterator &i)
        {
            node = i.node;
        }
    };

    iterator begin() const;
    static iterator end()
    {
        iterator i;
        return i;
    }
    iterator find(intptr_t addr) const;

    Allocator()
    {
        tree.root = nullptr;
    }
};

/*
 * The (minimal) ELF info needed for rewriting.
 */
struct ElfInfo
{
    Elf64_Ehdr *ehdr;               // EHDR (Elf header)
    Elf64_Phdr *phdr_note;          // PHDR PT_NOTE (used for loader?).
    Elf64_Phdr *phdr_gnu_relro;     // PHDR PT_GNU_RELRO (used for loader?).
    Elf64_Phdr *phdr_gnu_stack;     // PHDR PT_GNU_STACK (used for loader?).
    Elf64_Phdr *phdr_dynamic;       // PHDR PT_DYNAMIC else nullptr.
};

/*
 * The (minimal) PE info needed for rewriting.
 */
struct _IMAGE_FILE_HEADER;
struct _IMAGE_OPTIONAL_HEADER64;
struct _IMAGE_SECTION_HEADER;
typedef struct _IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
typedef struct _IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64,
    *PIMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_SECTION_HEADER
    IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
struct PEInfo
{
    PIMAGE_FILE_HEADER file_hdr;        // PE file header.
    PIMAGE_OPTIONAL_HEADER64 opt_hdr;   // PE optional header.
    PIMAGE_SECTION_HEADER shdr;         // All PE section headers.
    PIMAGE_SECTION_HEADER free_shdr;    // A free PE section header.
};
#define WINDOWS_VIRTUAL_ALLOC_SIZE      ((size_t)0x10000ull)    // 64KB

/*
 * Supported binary modes.
 */
enum Mode 
{
    MODE_ELF_EXE,                       // Linux ELF executable.
    MODE_ELF_DSO,                       // Linux ELF shared object.
    MODE_PE_EXE,                        // Windows PE executable.
    MODE_PE_DLL,                        // Windows PE DLL.
};

/*
 * Patch Queue entry.
 */
struct PatchEntry
{
    bool options;
    union
    {
        char * const *argv;             // Options.
        struct
        {
            Instr *I;                   // Instruction.
            const Trampoline *T;        // Trampoline.
        };
    };

    PatchEntry(char * const *argv) : options(true), argv(argv)
    {
        ;
    }

    PatchEntry(Instr *I, const Trampoline *T) : options(false), I(I), T(T)
    {
        ;
    }
};

/*
 * Trampoline entry point information.
 */
struct EntryPoint
{
    const Instr *I;                     // The to-be-patched instruction.
    intptr_t entry;                     // Trampoline entry address.
    bool target8;                       // Is 8bit relative jump target?
    bool target32;                      // Is 32bit relative jump target?
};
typedef std::map<intptr_t, EntryPoint> EntrySet;

/*
 * Jump instruction info.
 */
struct JumpInfo
{
    intptr_t addr;                      // Instruction address
    uint8_t *bytes;                     // Instruction bytes
    size_t size;                        // Instruction size
};

/*
 * Binary representation.
 */
typedef std::map<off_t, Instr *> InstrSet;
typedef std::deque<PatchEntry> PatchQueue;
typedef std::map<const char *, Trampoline *, CStrCmp> TrampolineSet;
typedef std::vector<intptr_t> FuncSet;
typedef std::vector<JumpInfo> JumpSet;
struct Binary
{
    const char *filename;               // The binary's path.
    size_t size;                        // The binary's size.
    const char *output;                 // The rewritten binary's path.
    union
    {
        ElfInfo elf;                    // ELF information.
        PEInfo pe;                      // PE information.
    };
    Mode mode;                          // Binary mode.
    intptr_t config;                    // Config pointer.
    bool pic;                           // Position independent?

    struct
    {
        const uint8_t *bytes;           // The original binary bytes.
        int fd;                         // The original binary file descr.
    } original;
    struct
    {
        uint8_t *bytes;                 // The patched binary bytes.
        uint8_t *state;                 // The patched binary state.
        size_t size;                    // The patched binary size.
    } patched;

    intptr_t cursor;                    // Patching cursor.
    PatchQueue Q;                       // Instructions queued for patching.

    off_t diff = 0;                     // Offset/address difference.
                                        // Used for optimization only.

    InstrSet Is;                        // All (known) instructions.
    TrampolineSet Ts;                   // All current trampoline templates.
    mutable EntrySet Es;                // All trampoline entry points.
    mutable JumpSet Js;                 // All observed jumps (-Opeephole).
    Allocator allocator;                // Virtual address allocation.

    FuncSet inits;                      // Initialization functions.
    FuncSet finis;                      // Finalization functions.
    intptr_t mmap = INTPTR_MIN;         // Mmap function.
};

/*
 * Binary helpers.
 */
extern Instr *findInstr(const Binary *B, intptr_t addr);

/*
 * Global options.
 */
extern bool option_is_tty;
extern bool option_debug;
extern bool option_batch;
extern unsigned option_Oepilogue;
extern unsigned option_Oepilogue_size;
extern bool option_Oorder;
extern bool option_Opeephole;
extern unsigned option_Oprologue;
extern unsigned option_Oprologue_size;
extern bool option_Oscratch_stack;
extern bool option_tactic_B1;
extern bool option_tactic_B2;
extern bool option_tactic_T1;
extern bool option_tactic_T2;
extern bool option_tactic_T3;
extern bool option_tactic_backward_T3;
extern intptr_t option_loader_base;
extern int option_loader_phdr;
extern bool option_loader_static;
extern std::set<intptr_t> option_trap;
extern bool option_trap_all;
extern bool option_trap_entry;
extern size_t option_mem_granularity;
extern size_t option_mem_mapping_size;
extern bool option_mem_multi_page;
extern intptr_t option_mem_rebase;
extern intptr_t option_mem_lb;
extern intptr_t option_mem_ub;
extern bool option_loader_base_set;
extern bool option_loader_phdr_set;
extern bool option_loader_static_set;
extern bool option_mem_rebase_set;
extern bool option_log;
extern int option_log_color;

/*
 * Special values for option_mem_rebase.
 */
#define OPTION_REBASE_NONE      0
#define OPTION_REBASE_AUTO      -1
#define OPTION_REBASE_RANDOM    -2

/*
 * Log colors.
 */
#define COLOR_NONE              0
#define COLOR_RED               1
#define COLOR_GREEN             2
#define COLOR_BLUE              3
#define COLOR_CYAN              4
#define COLOR_MAGENTA           5
#define COLOR_YELLOW            6

/*
 * Global statistics.
 */
extern size_t stat_num_patched;
extern size_t stat_num_failed;
extern size_t stat_num_B1;
extern size_t stat_num_B2;
extern size_t stat_num_T1;
extern size_t stat_num_T2;
extern size_t stat_num_T3;
extern size_t stat_num_virtual_mappings;
extern size_t stat_num_physical_mappings;
extern size_t stat_num_virtual_bytes;
extern size_t stat_num_physical_bytes;
extern size_t stat_input_file_size;
extern size_t stat_output_file_size;

extern void parseOptions(char * const argv[], bool api = false);
extern void NO_RETURN error(const char *msg, ...);
extern void warning(const char *msg, ...);
extern void debugImpl(const char *msg, ...);
extern void logSetColor(int color);

static inline void logImpl(char c)
{
    putchar(c);
}
static inline void logImpl(const char *s)
{
    fputs(s, stdout);
}

#define debug(msg, ...)                                                 \
    do {                                                                \
        if (__builtin_expect(option_debug, false))                      \
            debugImpl((msg), ##__VA_ARGS__);                            \
    } while (false)
#define log(color, msg, ...)                                            \
    do {                                                                \
        if (!option_log) break;                                         \
        if ((color) != option_log_color) logSetColor(color);            \
        logImpl(msg, ##__VA_ARGS__);                                    \
    } while (false)

#define ADDRESS_FORMAT              "%s%s0x%lx"
#define ADDRESS(p)                                                      \
    (IS_ABSOLUTE(p)? "[absolute] ": ""),                                \
    ((p) < 0? "-": ""),                                                 \
    std::abs(BASE_ADDRESS(p))

#endif
