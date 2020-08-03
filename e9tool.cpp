/*
 *        ___  _              _ 
 *   ___ / _ \| |_ ___   ___ | |
 *  / _ \ (_) | __/ _ \ / _ \| |
 * |  __/\__, | || (_) | (_) | |
 *  \___|  /_/ \__\___/ \___/|_|
 *                              
 * Copyright (C) 2020 National University of Singapore
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

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <regex>
#include <set>
#include <string>

#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include <elf.h>

#define PAGE_SIZE       4096

#define MAX_ACTIONS     (1 << 10)

#include "e9plugin.h"
#include "e9frontend.cpp"

/*
 * Options.
 */
static bool option_trap_all = false;
static bool option_detail    = false;
static bool option_debug     = false;
static std::string option_format("binary");
static std::string option_output("a.out");
static std::string option_syntax("att");

/*
 * Instruction location.
 */
struct Location
{
    const uint64_t offset:48;
    const uint64_t size:4;
    uint64_t       emitted:1;
    const uint64_t patch:1;
    const uint64_t action:10;

    Location(off_t offset, size_t size, bool patch, unsigned action) :
        offset(offset), size(size), emitted(0), patch(patch), action(action)
    {
        ;
    }
};

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
 * Match kinds.
 */
enum MatchKind
{
    MATCH_INVALID,
    MATCH_ASSEMBLY,
    MATCH_ADDRESS,
    MATCH_BYTES,
    MATCH_EMPTY,
    MATCH_ATTRIBUTES,
    MATCH_OFFSET,
    MATCH_RANDOM,
    MATCH_READ_REGS,
    MATCH_SIZE,
    MATCH_WRITE_REGS,
};

/*
 * Action kinds.
 */
enum ActionKind
{
    ACTION_INVALID,
    ACTION_CALL,
    ACTION_PASSTHRU,
    ACTION_PLUGIN,
    ACTION_PRINT,
    ACTION_TRAP,
};

/*
 * An action entry.
 */
struct ActionEntry
{
    const std::regex regex;
    const std::string regex_str;
    const MatchKind match;

    ActionEntry(ActionEntry &&entry) :
        regex(std::move(entry.regex)), regex_str(std::move(entry.regex_str)),
            match(entry.match)
    {
        ;
    }

    ActionEntry(const char *regex, MatchKind match) :
        regex(regex), regex_str(regex), match(match)
    {
        ;
    }
};
typedef std::vector<ActionEntry> ActionEntries;

/*
 * Actions.
 */
struct Action
{
    const ActionEntries entries;
    const ActionKind kind;
    const char * const name;
    const char * const filename;
    const char * const symbol;
    void *handle;
    PluginInit initFunc;
    PluginInstr instrFunc;
    PluginPatch patchFunc;
    PluginFini finiFunc;
    void *context;
    std::vector<Argument> args;
    bool clean;
    bool before;
    bool replace;

    Action(ActionEntries &&entries, ActionKind kind, const char *name, 
            const char *filename, const char *symbol,
            const std::vector<Argument> &&args,  bool clean, bool before,
            bool replace) :
        entries(std::move(entries)), kind(kind), name(name),
            filename(filename), symbol(symbol), handle(nullptr),
            initFunc(nullptr), instrFunc(nullptr), patchFunc(nullptr),
            context(nullptr), args(args), clean(clean),
            before(before), replace(replace)
    {
        ;
    }
};
typedef std::map<size_t, Action *> Actions;

/*
 * Action string parser.
 */
struct Parser
{
    const char * const buf;
    size_t i = 0;
    char s[BUFSIZ+1];

    Parser(const char *buf) : buf(buf)
    {
        ;
    }

    char getToken()
    {
        char c = buf[i];
        while (isspace(c))
            c = buf[++i];
        switch (c)
        {
            case '\0':
                return (s[0] = '\0');
            case '[': case ']': case '@': case ',': case '(': case ')':
                s[0] = c; s[1] = '\0';
                i++;
                return c;
            default:
                break;
        }
        if (isalnum(c) || buf[i] == '_' || buf[i] == '-')
        {
            unsigned j = 0;
            s[j++] = c;
            i++;
            while (isalnum(buf[i]) || buf[i] == '_')
                s[j++] = buf[i++];
            s[j++] = '\0';
            return c;
        }
        s[0] = c; s[1] = '\0';
        return EOF;
    }
};

/*
 * Parse an action.
 */
static Action *parseAction(const char *str)
{
    char buf[BUFSIZ];
    unsigned i = 0;
    const char *end = strchr(str, ':');
    if (end == nullptr)
        error("failed to parse action string \"%s\"; missing `:' separator",
            str);
    
    ActionEntries entries;
    while (true)
    {
        // Step (1): parse the match kind:
        while (isspace(str[i]))
            i++;
        if (str[i] == ':')
            break;
        for (unsigned j = 0; i < sizeof(buf); i++, j++)
        {
            if (!isalnum(str[i]) && str[i] != '.')
            {
                buf[j] = '\0';
                break;
            }
            buf[j] = str[i];
        }
        while (isspace(str[i]))
            i++;
        if (str[i] != '=')
            error("failed to parse action string \"%s\"; expected `=' "
                "separator after \"%s\" match-kind", str, buf);
        i++;
        MatchKind match = MATCH_INVALID;
        switch (buf[0])
        {
            case '\0':
                match = MATCH_EMPTY;
                break;
            case 'a':
                if (strcmp(buf, "asm") == 0)
                    match = MATCH_ASSEMBLY;
                else if (strcmp(buf, "addr") == 0)
                    match = MATCH_ADDRESS;
                else if (strcmp(buf, "attr") == 0)
                    match = MATCH_ATTRIBUTES;
                break;
            case 'b':
                if (strcmp(buf, "bytes") == 0)
                    match = MATCH_BYTES;
                break;
            case 'o':
                if (strcmp(buf, "offset") == 0)
                    match = MATCH_OFFSET;
                break;
            case 'r':
                if (strcmp(buf, "rand") == 0)
                    match = MATCH_RANDOM;
                else if (strcmp(buf, "regs.read") == 0)
                    match = MATCH_READ_REGS;
                else if (strcmp(buf, "regs.write") == 0)
                    match = MATCH_WRITE_REGS;
                break;
            case 's':
                if (strcmp(buf, "size") == 0)
                    match = MATCH_SIZE;
                break;
        }
        switch (match)
        {
            case MATCH_INVALID:
                error("failed to parse action string \"%s\"; invalid match-"
                    "kind \"%s\"", str, buf);
            case MATCH_ATTRIBUTES:
            case MATCH_READ_REGS:
            case MATCH_WRITE_REGS:
                option_detail = true;
                break;
            default:
                break;
        }

        // Step (2): parse the regular-expression:
        while (isspace(str[i]))
            i++;
        for (unsigned j = 0; j < sizeof(buf); i++, j++)
        {
            if (isspace(str[i]) || str[i] == ':')
            {
                buf[j] = '\0';
                break;
            }
            buf[j] = str[i];
        }

        ActionEntry entry(buf, match);
        entries.push_back(std::move(entry));
    }

    // Step (3): parse the instrumentation:
    ActionKind kind = ACTION_INVALID;
    Parser parser(end+1);
    switch (parser.getToken())
    {
        case 'c':
            if (strcmp(parser.s, "call") == 0)
                kind = ACTION_CALL;
            break;
        case 'p':
            if (strcmp(parser.s, "passthru") == 0)
                kind = ACTION_PASSTHRU;
            else if (strcmp(parser.s, "print") == 0)
                kind = ACTION_PRINT;
            else if (strcmp(parser.s, "plugin") == 0)
            {
                option_detail = true;
                kind = ACTION_PLUGIN;
            }
            break;
        case 't':
            if (strcmp(parser.s, "trap") == 0)
                kind = ACTION_TRAP;
            break;
    }
    if (kind == ACTION_INVALID)
        error("failed to parse action string \"%s\"; invalid instrumentation-"
            "kind \"%s\"", str, parser.s);

    // Step (5): parse call (if necessary):
    bool option_clean = false, option_naked = false, option_before = false,
         option_after = false, option_replace = false;
    const char *symbol   = nullptr;
    const char *filename = nullptr;
    std::vector<Argument> args;
    if (kind == ACTION_PLUGIN)
    {
        while (isspace(parser.buf[parser.i]))
            parser.i++;
        filename = strDup(parser.buf + parser.i);
    }
    else if (kind == ACTION_CALL)
    {
        char c = parser.getToken();
        if (c == '[')
        {
            while (true)
            {
                c = parser.getToken();
                bool ok = false;
                switch (c)
                {
                    case 'a':
                        if (strcmp(parser.s, "after") == 0)
                            ok = option_after = true;
                        break;
                    case 'b':
                        if (strcmp(parser.s, "before") == 0)
                            ok = option_before = true;
                        break;
                    case 'c':
                        if (strcmp(parser.s, "clean") == 0)
                            ok = option_clean = true;
                        break;
                    case 'n':
                        if (strcmp(parser.s, "naked") == 0)
                            ok = option_naked = true;
                        break;
                    case 'r':
                        if (strcmp(parser.s, "replace") == 0)
                            ok = option_replace = true;
                        break;
                }
                if (!ok)
                    error("failed to parse call action; expected call "
                        "attribute, found `%s'", parser.s);
                c = parser.getToken();
                if (c == ']')
                    break;
                if (c != ',')
                    error("failed to parse call action; expected `]' or `,', "
                        "found `%s'", parser.s);
            }
            c = parser.getToken();
        }
        if (!isalpha(c) && c != '_')
            error("failed to parse call action; expected symbol name, found "
                "`%s'", parser.s);
        symbol = strDup(parser.s);
        c = parser.getToken();
        if (c == '(')
        {
            while (true)
            {
                c = parser.getToken();
                const char *s = parser.s;
                ArgumentKind arg = ARGUMENT_INVALID;
                intptr_t value = 0x0;
                switch (c)
                {
                    case 'i':
                        if (strcmp(s, "instrAsmStr") == 0)
                            arg = ARGUMENT_ASM_STR;
                        else if (strcmp(s, "instrAsmStrLen") == 0)
                            arg = ARGUMENT_ASM_STR_LEN;
                        else if (strcmp(s, "instrAddr") == 0)
                            arg = ARGUMENT_ADDR;
                        else if (strcmp(s, "instrBytes") == 0)
                            arg = ARGUMENT_BYTES;
                        else if (strcmp(s, "instrBytesLen") == 0)
                            arg = ARGUMENT_BYTES_LEN;
                        break;
                    case 'r':
                        if (strcmp(s, "rax") == 0)
                            arg = ARGUMENT_RAX;
                        else if (strcmp(s, "rbx") == 0)
                            arg = ARGUMENT_RBX;
                        else if (strcmp(s, "rcx") == 0)
                            arg = ARGUMENT_RCX;
                        else if (strcmp(s, "rdx") == 0)
                            arg = ARGUMENT_RDX;
                        else if (strcmp(s, "rbp") == 0)
                            arg = ARGUMENT_RBP;
                        else if (strcmp(s, "rdi") == 0)
                            arg = ARGUMENT_RDI;
                        else if (strcmp(s, "rsi") == 0)
                            arg = ARGUMENT_RSI;
                        else if (strcmp(s, "r8") == 0)
                            arg = ARGUMENT_R8;
                        else if (strcmp(s, "r9") == 0)
                            arg = ARGUMENT_R9;
                        else if (strcmp(s, "r10") == 0)
                            arg = ARGUMENT_R10;
                        else if (strcmp(s, "r11") == 0)
                            arg = ARGUMENT_R11;
                        else if (strcmp(s, "r12") == 0)
                            arg = ARGUMENT_R12;
                        else if (strcmp(s, "r13") == 0)
                            arg = ARGUMENT_R13;
                        else if (strcmp(s, "r14") == 0)
                            arg = ARGUMENT_R14;
                        else if (strcmp(s, "r15") == 0)
                            arg = ARGUMENT_R15;
                        else if (strcmp(s, "rflags") == 0)
                            arg = ARGUMENT_RFLAGS;
                        else if (strcmp(s, "rip") == 0)
                            arg = ARGUMENT_RIP;
                        else if (strcmp(s, "rsp") == 0)
                            arg = ARGUMENT_RSP;
                        break;
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                    case '-':
                    {
                        const char *t = s;
                        bool neg = (t[0] == '-');
                        if (neg)
                            t++;
                        int base = (t[0] == '0' && t[1] == 'x'? 16: 10);
                        char *end = nullptr;
                        value = (intptr_t)strtoull(t, &end, base);
                        if (end == nullptr || *end != '\0')
                            break;
                        value = (neg? -value: value);
                        arg = ARGUMENT_INTEGER;
                        break;
                    }
                }
                if (arg == ARGUMENT_INVALID)
                    error("failed to parse call action; expected call "
                        "argument, found `%s'", s);
                args.push_back({arg, value});
                c = parser.getToken();
                if (c == ')')
                    break;
                if (c != ',')
                    error("failed to parse call action; expected `)' or `,', "
                        "found `%s'", s);
            }
            c = parser.getToken();
        }
        if (c != '@')
            error("failed to parse call action; expected `@', found `%s'",
                parser.s);
        filename = strDup(parser.buf + parser.i);
        if (filename[0] == '\0')
            error("failed to parse call action; expected filename");
        if (option_clean && option_naked)
            error("failed to parse call action; `clean' and `naked' "
                "attributes cannot be used together");
        option_clean = (option_clean? true: !option_naked);
        if ((int)option_before + (int)option_after + (int)option_replace > 1)
            error("failed to parse call action; only one of the `before', "
                "`after' and `replace' attributes can be used together");
        option_before = (option_before? true: !option_after);
    }
    else if (parser.getToken() != '\0')
        error("failed to parse action; expected end-of-string, found `%s'",
            parser.s);

    // Step(5): Build the action:
    const char *name = nullptr;
    switch (kind)
    {
        case ACTION_PRINT:
            name = "print";
            break;
        case ACTION_PASSTHRU:
            name = "passthru";
            break;
        case ACTION_TRAP:
            name = "trap";
            break;
        case ACTION_CALL:
        {
            std::string call_name("call_");
            call_name += (option_clean? 'C': 'N');
            call_name += (option_replace? 'R': (option_before? 'B': 'A'));
            call_name += '_';
            call_name += symbol;
            call_name += '_';
            call_name += filename;
            name = strDup(call_name.c_str());
            break;
        }
        case ACTION_PLUGIN:
        {
            std::string plugin_name("plugin_");
            plugin_name += filename;
            name = strDup(plugin_name.c_str());
            break;
        }
        default:
            break;
    }

    Action *action = new Action(std::move(entries), kind, name, filename,
        symbol, std::move(args), option_clean, option_before, option_replace);
    return action;
}

/*
 * Fast stream object.
 */
struct Stream
{
    static const unsigned MAX_SIZE = 1024;
    unsigned i = 0;
    char buf[MAX_SIZE + 1];

    Stream()
    {
        buf[0] = '\0';
    }

    const char *push(char c)
    {
        if (i >= MAX_SIZE)
            error("failed to push character into stream; maximum size (%zu) "
                "exceeded", MAX_SIZE);
        buf[i++] = c;
        buf[i]   = '\0';
        return buf;
    }

    const char *push(const char *str)
    {
        size_t len = strlen(str);
        if (i + len > MAX_SIZE)
            error("failed to push string into stream; maximum size (%zu) "
                "exceeded", MAX_SIZE);
        memcpy(buf + i, str, len + 1);
        i += len;
        return buf;
    }

    const char *pushFormat(const char *msg, ...)
    {
        va_list ap;
        va_start(ap, msg);
        int r = vsnprintf(buf + i, MAX_SIZE - i, msg, ap);
        if (r >= (int)MAX_SIZE - (int)i)
            error("failed to push formatted string into stream; maximum "
                "size (%zu) exceeded", MAX_SIZE);
        va_end(ap);
        i += (int)r;
        return buf;
    }

    const char *pushSep()
    {
        if (i == 0)
            return buf;
        return push(' ');
    }

    void clear()
    {
        i = 0;
        buf[0] = '\0';
    }
};

/*
 * Create match string.
 */
static const char *makeMatchString(csh handle, MatchKind match,
    const cs_insn *I, intptr_t text_addr, off_t text_offset, Stream &stream)
{
    const cs_detail *detail = I->detail;
    switch (match)
    {
        case MATCH_ASSEMBLY:
            if (I->op_str[0] == '\0')
                return I->mnemonic;
            else
                return stream.pushFormat("%s %s", I->mnemonic, I->op_str);
        case MATCH_ADDRESS:
            return stream.pushFormat("0x%lx", I->address);
        case MATCH_BYTES:
            for (int i = 0; i < I->size-1; i++)
                stream.pushFormat("0x%.2x ", I->bytes[i]);
            return stream.pushFormat("0x%.2x", I->bytes[I->size-1]);
        case MATCH_EMPTY:
            return "";
        case MATCH_OFFSET:
        {
            off_t offset = (off_t)(I->address - text_addr) + text_offset;
            return stream.pushFormat("+%zd", offset);
        }
        case MATCH_RANDOM:
        {
            int r = rand() % 10000;
            return stream.pushFormat("%.4u", r);
        }
        case MATCH_SIZE:
            return stream.pushFormat("%u", I->size);
        case MATCH_READ_REGS:
            for (uint8_t i = 0; i < detail->regs_read_count; i++)
            {
                stream.pushSep();
                stream.push(cs_reg_name(handle, detail->regs_read[i]));
            }
            for (uint8_t i = 0; i < detail->x86.op_count; i++)
            {
                switch (detail->x86.operands[i].type)
                {
                    case X86_OP_REG:
                        if ((detail->x86.operands[i].access & CS_AC_READ) == 0)
                            continue;
                        stream.pushSep();
                        stream.push(cs_reg_name(handle,
                            detail->x86.operands[i].reg));
                        break;
                    case X86_OP_MEM:
                        if (detail->x86.operands[i].mem.segment !=
                                X86_REG_INVALID)
                        {
                            stream.pushSep();
                            stream.push(cs_reg_name(handle,
                                detail->x86.operands[i].mem.segment));
                        }
                        if (detail->x86.operands[i].mem.base !=
                                X86_REG_INVALID)
                        {
                            stream.pushSep();
                            stream.push(cs_reg_name(handle,
                                detail->x86.operands[i].mem.base));
                        }
                        if (detail->x86.operands[i].mem.index !=
                                X86_REG_INVALID)
                        {
                            stream.pushSep();
                            stream.push(cs_reg_name(handle,
                                detail->x86.operands[i].mem.index));
                        }
                        break;
                    default:
                        break;
                }
            }
            return stream.buf;
        case MATCH_WRITE_REGS:
            for (uint8_t i = 0; i < detail->regs_write_count; i++)
            {
                stream.pushSep();
                stream.push(cs_reg_name(handle, detail->regs_write[i]));
            }
            for (uint8_t i = 0; i < detail->x86.op_count; i++)
            {
                if (detail->x86.operands[i].type != X86_OP_REG ||
                        (detail->x86.operands[i].access & CS_AC_WRITE) == 0)
                    continue;
                stream.pushSep();
                stream.push(cs_reg_name(handle,
                    detail->x86.operands[i].reg));
            }
            return stream.buf;
        case MATCH_ATTRIBUTES:
            for (uint8_t i = 0; i < detail->groups_count; i++)
            {
                stream.pushSep();
                stream.push(cs_group_name(handle, detail->groups[i]));
            }
            return stream.buf;
        default:
            return "";
    }
}

/*
 * Match an action.
 */
static bool matchAction(csh handle, const Action *action, const cs_insn *I,
    intptr_t text_addr, off_t text_offset)
{
    if (option_debug)
    {
        fprintf(stderr, "%lx: %s%s",
            I->address,
            (option_is_tty? "\33[35m": ""),
            I->mnemonic);
        if (I->op_str[0] != '\0')
            fprintf(stderr, " %s", I->op_str);
        fprintf(stderr, "%s\n",
            (option_is_tty? "\33[0m": ""));
    }

    Stream stream;
    std::cmatch cmatch;
    for (auto &entry: action->entries)
    {
        const char *match_str = makeMatchString(handle, entry.match, I,
            text_addr, text_offset, stream);
        if (option_debug)
            fprintf(stderr, "\tmatch %s\"%s\"%s against %s\"%s\"%s ",
                (option_is_tty? "\33[33m": ""),
                match_str,
                (option_is_tty? "\33[0m": ""),
                (option_is_tty? "\33[33m": ""),
                entry.regex_str.c_str(),
                (option_is_tty? "\33[0m": ""));
        if (!std::regex_match(match_str, cmatch, entry.regex))
        {
            if (option_debug)
                fprintf(stderr, "%s*** FAILED ***%s\n\n",
                    (option_is_tty? "\33[31m": ""),
                    (option_is_tty? "\33[0m": ""));
            return false;
        }
        else if (option_debug)
            fprintf(stderr, "%spassed%s\n",
                (option_is_tty? "\33[32m": ""),
                (option_is_tty? "\33[0m": ""));
        stream.clear();
    }
    if (option_debug)
        fputc('\n', stderr);
    return true;
}

/*
 * Send an instruction message (if necessary).
 */
static bool sendInstructionMessage(FILE *out, Location &loc, intptr_t addr,
    intptr_t text_addr, off_t text_offset)
{
    if (std::abs((intptr_t)(text_addr + loc.offset) - addr) >
            INT8_MAX + /*sizeof(short jmp)=*/2 + /*max instruction size=*/15)
        return false;

    if (loc.emitted)
        return true;
    loc.emitted = true;

    addr = text_addr + loc.offset;
    off_t offset = text_offset + loc.offset;
    size_t size = loc.size;

    sendInstructionMessage(out, addr, size, offset);
    return true;
}

/*
 * Build the ASM string of the given instruction.
 */
static void buildAsmStr(char *buf, size_t len, const cs_insn *I,
    bool newline = false)
{
    unsigned i;
    for (i = 0; i < len && I->mnemonic[i] != '\0'; i++)
        buf[i] = I->mnemonic[i];
    if (I->op_str[0] != '\0' && i < sizeof(buf)-1)
        buf[i++] = ' ';
    for (unsigned j = 0; i < len && I->op_str[j] != '\0'; i++, j++)
    buf[i] = I->op_str[j];
    if (newline && i < len)
        buf[i++] = '\n';
    if (i < len)
        buf[i++] = '\0';
    else
        buf[len] = '\0';
}

/*
 * Build metadata.
 */
static Metadata *buildMetadata(const Action *action, const cs_insn *J,
    Metadata *metadata, char *asm_str, size_t asm_str_len)
{
    if (action == nullptr || action->kind == ACTION_PASSTHRU ||
            action->kind == ACTION_TRAP ||
            (action->kind == ACTION_CALL && action->args.size() == 0))
    {
        return nullptr;
    }

    switch (action->kind)
    {
        case ACTION_PRINT:
            buildAsmStr(asm_str, asm_str_len, J, /*newline=*/true);

            metadata[0].name   = "$asmStr";
            metadata[0].kind   = METADATA_STRING;
            metadata[0].string = asm_str;

            metadata[1].name   = "$asmStrLen";
            metadata[1].kind   = METADATA_INT32;
            metadata[1].int32  = strlen(asm_str);

            metadata[2].name   = nullptr;
            metadata[2].kind   = METADATA_END;

            break;

        case ACTION_CALL:
        {
            bool asm_str_inited = false;
            unsigned i = 0;
            for (auto arg: action->args)
            {
                metadata[i].name = getArgumentName(arg.kind);
                switch (arg.kind)
                {
                    case ARGUMENT_ASM_STR:
                        if (!asm_str_inited)
                            buildAsmStr(asm_str, asm_str_len, J);
                        asm_str_inited = true;
                        metadata[i].kind   = METADATA_STRING;
                        metadata[i].string = asm_str;
                        break;
                    case ARGUMENT_ASM_STR_LEN:
                        if (!asm_str_inited)
                            buildAsmStr(asm_str, asm_str_len, J);
                        asm_str_inited = true;
                        metadata[i].kind   = METADATA_INT32;
                        metadata[i].int32  = strlen(asm_str);
                        break;
                    case ARGUMENT_BYTES:
                        metadata[i].kind   = METADATA_DATA;
                        metadata[i].length = J->size;
                        metadata[i].data   = J->bytes;
                        break;
                    case ARGUMENT_BYTES_LEN:
                        metadata[i].kind   = METADATA_INT32;
                        metadata[i].int32  = J->size;
                        break;
                    default:
                        continue;
                }
                i++;
            }
            metadata[i].name = nullptr;
            metadata[i].kind = METADATA_END;
            break;
        }

        default:
            metadata[0].name = nullptr;
            metadata[0].kind = METADATA_END;
            break;
    }
    
    return metadata;
}

/*
 * Convert a positon into an address.
 */
static intptr_t positionToAddr(const ELF &elf, const char *option,
    const char *pos)
{
    // Case #1: absolute address:
    if (pos[0] == '0' && pos[1] == 'x')
    {
        const char *str = pos + 2;
        errno = 0;
        char *end = nullptr;
        intptr_t abs_addr = strtoull(str, &end, 16);
        if (end != nullptr && *end != '\0')
            error("bad value for `%s' option; invalid absolute position "
                "string \"%s\"", option, pos);
        return abs_addr;
    }

    // Case #2: symbolic address:
    const Elf64_Sym *sym = elf.dynamic_symtab;
    const Elf64_Sym *sym_end = sym + (elf.dynamic_symsz / sizeof(Elf64_Sym));
    for (; sym < sym_end; sym++)
    {
        if (sym->st_name == 0 || sym->st_name >= elf.dynamic_strsz)
            continue;
        const char *name = elf.dynamic_strtab + sym->st_name;
        if (strcmp(pos, name) == 0)
        {
            intptr_t sym_addr = (intptr_t)sym->st_value;
            if (sym_addr < elf.text_addr ||
                    sym_addr >= elf.text_addr + (ssize_t)elf.text_size)
                error("bad value for `%s' option; dynamic symbol \"%s\" "
                    "points outside of the (.text) section", option, name);
            return sym_addr;
        }
    }
    error("bad value for `%s' option; failed to find dynamic symbol "
        "\"%s\"", option, pos);
}

/*
 * Usage.
 */
static void usage(FILE *stream, const char *progname)
{
    fputs("        ___  _              _\n", stream);
    fputs("   ___ / _ \\| |_ ___   ___ | |\n", stream);
    fputs("  / _ \\ (_) | __/ _ \\ / _ \\| |\n", stream);
    fputs(" |  __/\\__, | || (_) | (_) | |\n", stream);
    fputs("  \\___|  /_/ \\__\\___/ \\___/|_|\n", stream);
    fputc('\n', stream);
    fprintf(stream, "usage: %s [OPTIONS] input-file\n\n", progname);
    fputs("OPTIONS:\n", stream);
    fputs("\t--action ACTION, -A ACTION\n", stream);
    fputs("\t\tSpecifies a binary rewriting action in the following form:\n",
        stream);
    fputc('\n', stream);
    fputs("\t\t\tACTION ::= ( MATCH-KIND '='\n", stream);
    fputs("\t\t\t             REGULAR-EXPRESSION ) *\n", stream);
    fputs("\t\t\t             ':' INSTRUMENTATION\n", stream);
    fputc('\n', stream);
    fputs("\t\tHere, MATCH-KIND specifies an instruction attribute that can\n",
        stream);
    fputs("\t\tbe matched against.  Possible MATCH-KIND values are:\n",
        stream);
    fputc('\n', stream);
    fputs("\t\t\t- \"asm\"       : match the assembly string of the\n",
        stream);
    fputs("\t\t\t                instruction.  E.g.,\n", stream);
    fputs("\t\t\t                \"cmpb %r11b, 0x436fe0(%rdi)\".\n", stream);
    fputs("\t\t\t- \"addr\"      : match the instruction address.  E.g.,\n",
        stream);
    fputs("\t\t\t                E.g., \"0x4234a7\"\n", stream);
    fputs("\t\t\t- \"attr\"      : match instruction attributes.  E.g.,\n",
        stream);
    fputs("\t\t\t                \"branch_relative jump\".\n", stream);
    fputs("\t\t\t- \"bytes\"     : match the instruction bytes.  E.g.,\n",
        stream);
    fputs("\t\t\t                \"0xe8 0xb7 0x31 0x1a 0x00\".\n", stream);
    fputs("\t\t\t- \"off\"       : match the instruction file offset.\n",
        stream);
    fputs("\t\t\t                E.g., \"+49521\"\n", stream);
    fputs("\t\t\t- \"rand\"      : match a (zero-padded) pseudo random\n",
        stream);
    fputs("\t\t\t                number from the range \"0000\"..."
        "\"9999\".\n", stream);
    fputs("\t\t\t- \"regs.read\" : match registers that are read from.\n",
        stream);
    fputs("\t\t\t                E.g. \"r11b rdi\".\n", stream);
    fputs("\t\t\t- \"regs.write\": match registers that are written to.\n",
        stream);
    fputs("\t\t\t- \"size\"      : match the instruction size in bytes.\n",
        stream);
    fputs("\t\t\t                E.g., \"3\".\n", stream);
    fputs("\t\t\t- \"\"          : match the empty string.\n", stream);
    fputc('\n', stream);
    fputs("\t\tIf the REGULAR-EXPRESSION matches the instruction attribute\n",
        stream);
    fputs("\t\tcorresponding to MATCH-KIND, then the instruction will be\n",
        stream);
    fputs("\t\tinstrumented using INSTRUMENTATION.  Possible values for\n",
        stream);
    fputs("\t\tINSTRUMENTATION are:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- \"passthru\": empty (NOP) instrumentation;\n", stream);
    fputs("\t\t\t- \"print\"   : instruction printing instrumentation.\n",
        stream);
    fputs("\t\t\t- \"trap\"    : SIGTRAP instrumentation.\n", stream);
    fputs("\t\t\t- CALL      : call user instrumentation (see below).\n",
        stream);
    fputs("\t\t\t- PLUGIN    : plugin instrumentation (see below).\n",
        stream);
    fputc('\n', stream);
    fputs("\t\tThe CALL INSTRUMENTATION makes it possible to invoke a\n",
        stream);
    fputs("\t\tuser-function defined in a ELF file.  The ELF file can be\n",
        stream);
    fputs("\t\timplemented in C and compiled using the special "
        "\"e9compile.sh\"\n", stream);
    fputs("\t\tshell script.  This will generate a compatible ELF binary\n",
        stream);
    fputs("\t\tfile (BINARY).  The syntax for CALL is:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\tCALL ::= 'call' [OPTIONS] FUNCTION [ARGS] '@' BINARY\n",
        stream);
    fputs("\t\t\tOPTIONS ::= '[' OPTION ',' ... ']'\n", stream);
    fputs("\t\t\tARGS ::= '(' ARG ',' ... ')'\n", stream);
    fputc('\n', stream);
    fputs("\t\tWhere:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- OPTION is one of:\n", stream);
    fputs("\t\t\t  * \"clean\"/\"naked\" for clean/naked calls.\n", stream);
    fputs("\t\t\t  * \"before\"/\"after\"/\"replace\" for inserting the\n",
        stream);
    fputs("\t\t\t    call before/after the instruction, or replacing\n",
        stream);
    fputs("\t\t\t    the instruction by the call.\n", stream);
    fputs("\t\t\t- ARG is one of:\n", stream);
    fputs("\t\t\t  * \"instrAsmStr\" is a pointer to the string\n", stream);
    fputs("\t\t\t    representation of the instruction.\n", stream);
    fputs("\t\t\t  * \"instrAsmStrLen\" is the length of \"instrAsmStr\".\n",
        stream);
    fputs("\t\t\t  * \"instrAddr\" is the address of the instruction.\n",
        stream);
    fputs("\t\t\t  * \"instrBytes\" is the bytes of the instruction.\n",
        stream);
    fputs("\t\t\t  * \"instrBytesLen\" is the length of \"instrBytes\".\n",
        stream);
    fputs("\t\t\t  * \"rax\"...\"r15\", \"rip\", \"rflags\" is the\n",
        stream);
    fputs("\t\t\t    corresponding register value.\n", stream);
    fputs("\t\t\t  * An integer constant.\n", stream);
    fputs("\t\t\t  NOTE: a maximum of 6 arguments are supported.\n", stream);
    fputs("\t\t\t- FUNCTION is the name of the function to call from\n",
        stream);
    fputs("\t\t\t  the binary.\n", stream);
    fputs("\t\t\t- BINARY is a suitable ELF binary file.  You can use\n",
        stream);
    fputs("\t\t\t  the `e9compile.sh' script to compile C programs into\n",
        stream);
    fputs("\t\t\t  the correct binary format.\n", stream);
    fputc('\n', stream);
    fputs("\t\tThe PLUGIN INSTRUMENTATION lets a shared object plugin "
        "drive\n", stream);
    fputs("\t\tthe binary instrumentation/rewriting.  The syntax for "
        "PLUGIN\n", stream);
    fputs("\t\tis:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\tPLUGIN ::= 'plugin' FILENAME\n", stream);
    fputc('\n', stream);
    fputs("\t\twhere FILENAME is the path to the plugin shared object.  "
        "See\n", stream);
    fputs("\t\tthe `e9plugin.h' file for the plugin API documentation.\n",
        stream);
    fputc('\n', stream);
    fputs("\t\tIt is possible to specify multiple actions that will be\n",
        stream);
    fputs("\t\tapplied in the command-line order.\n", stream);
    fputc('\n', stream);
    fputs("\t--backend PROG\n", stream);
    fputs("\t\tUse PROG as the backend.  The default is \"e9patch\".\n",
        stream);
    fputc('\n', stream);
    fputs("\t--compression N, -c N\n", stream);
    fputs("\t\tSet the compression level to be N, where N is a number within\n",
        stream);
    fputs("\t\tthe range 0..9.  The default is 9 for maximum compression.\n",
        stream);
    fputs("\t\tHigher compression makes the output binary smaller, but also\n",
        stream);
    fputs("\t\tincreases the number of mappings (mmap() calls) required.\n",
        stream);
    fputc('\n', stream);
    fputs("\t--debug\n", stream);
    fputs("\t\tEnable debug output.\n", stream);
    fputc('\n', stream);
    fputs("\t--end END\n", stream);
    fputs("\t\tOnly patch the (.text) section up to the address or symbol\n",
        stream);
    fputs("\t\tEND.  By default, the whole (.text) section is patched.\n",
        stream);
    fputc('\n', stream);
    fputs("\t--executable\n", stream);
    fputs("\t\tTreat the input file as an executable, even if it appears "
        "to\n", stream);
    fputs("\t\tbe a shared library.  See the `--shared' option for more\n",
        stream);
    fputs("\t\tinformation.\n", stream);
    fputc('\n', stream);
    fputs("\t--format FORMAT\n", stream);
    fputs("\t\tSet the output format to FORMAT which is one of {binary,\n",
        stream);
    fputs("\t\tjson, patch, patch.gz, patch,bz2, patch.xz}.  Here:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- \"binary\" is a modified ELF executable file;\n", stream);
    fputs("\t\t\t- \"json\" is the raw JSON RPC stream for the e9patch\n",
        stream);
    fputs("\t\t\t  backend; or\n", stream);
    fputs("\t\t\t- \"patch\", \"patch.gz\", \"patch.bz2\" and \"patch.xz\"\n",
        stream);
    fputs("\t\t\t  are (compressed) binary diffs in xxd format.\n", stream);
    fputc('\n', stream);
    fputs("\t\tThe default format is \"binary\".\n", stream);
    fputc('\n', stream);
    fputs("\t--help, -h\n", stream);
    fputs("\t\tPrint this message and exit.\n", stream);
    fputc('\n', stream);
    fputs("\t--option OPTION\n", stream);
    fputs("\t\tPass OPTION to the e9patch backend.\n", stream);
    fputc('\n', stream);
    fputs("\t--output FILE, -o FILE\n", stream);
    fputs("\t\tSpecifies the path to the output file.  The default filename "
        "is\n", stream);
    fputs("\t\t\"a.out\".\n", stream);
    fputc('\n', stream);
    fputs("\t--shared\n", stream);
    fputs("\t\tTreat the input file as a shared library, even if it appears "
        "to\n", stream);
    fputs("\t\tbe an executable.  By default, the input file will only be\n",
        stream);
    fputs("\t\ttreated as a shared library if (1) it is a dynamic "
        "executable\n", stream);
    fputs("\t\t(ET_DYN) and (2) has a filename of the form:\n",
        stream);
    fputc('\n', stream);
    fputs("\t\t\t[PATH/]lib*.so[.VERSION]\n", stream);
    fputc('\n', stream);
    fputs("\t--start START\n", stream);
    fputs("\t\tOnly patch the (.text) section beginning from address or "
        "symbol\n", stream);
    fputs("\t\tSTART.  By default, the whole (.text) section is patched\n",
        stream);
    fputc('\n', stream);
    fputs("\t--static-loader, -s\n", stream);
    fputs("\t\tReplace patched pages statically.  By default, patched "
        "pages\n", stream);
    fputs("\t\tare loaded during program initialization as this is more\n",
        stream);
    fputs("\t\treliable for large/complex binaries.  However, this may "
        "bloat\n", stream);
    fputs("\t\tthe size of the output patched binary.\n", stream);
    fputc('\n', stream);
    fputs("\t--sync N\n", stream);
    fputs("\t\tSkip N instructions after the disassembler desyncs.  This\n",
        stream);
    fputs("\t\tcan be a useful hack if the disassembler (capstone) fails, "
        "or\n", stream);
    fputs("\t\tif the .text section contains data.\n", stream);
    fputc('\n', stream);
    fputs("\t--syntax SYNTAX\n", stream);
    fputs("\t\tSelects the assembly syntax to be SYNTAX.  Possible values "
        "are:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- \"att\"  : X86_64 ATT asm syntax; or\n", stream);
    fputs("\t\t\t- \"intel\": X86_64 Intel asm syntax.\n", stream);
    fputc('\n', stream);
    fputs("\t\tThe default syntax is \"att\".\n", stream);
    fputc('\n', stream);
    fputs("\t--trap-all\n", stream);
    fputs("\t\tInsert a trap (int3) instruction at each trampoline entry.\n",
        stream);
    fputs("\t\tThis can be used for debugging with gdb.\n", stream);
    fputc('\n', stream);
}

/*
 * Options.
 */
enum Option
{
    OPTION_ACTION,
    OPTION_BACKEND,
    OPTION_COMPRESSION,
    OPTION_DEBUG,
    OPTION_END,
    OPTION_EXECUTABLE,
    OPTION_FORMAT,
    OPTION_HELP,
    OPTION_OPTION,
    OPTION_OUTPUT,
    OPTION_SHARED,
    OPTION_START,
    OPTION_STATIC_LOADER,
    OPTION_SYNC,
    OPTION_SYNTAX,
    OPTION_TRAP_ALL,
};

/*
 * Entry.
 */
int main(int argc, char **argv)
{
    /*
     * Parse options.
     */
    static const struct option long_options[] =
    {
        {"action",         true,  nullptr, OPTION_ACTION},
        {"backend",        true,  nullptr, OPTION_BACKEND},
        {"compression",    true,  nullptr, OPTION_COMPRESSION},
        {"debug",          false, nullptr, OPTION_DEBUG},
        {"end",            true,  nullptr, OPTION_END},
        {"executable",     false, nullptr, OPTION_EXECUTABLE},
        {"format",         true,  nullptr, OPTION_FORMAT},
        {"help",           false, nullptr, OPTION_HELP},
        {"option",         true,  nullptr, OPTION_OPTION},
        {"output",         true,  nullptr, OPTION_OUTPUT},
        {"shared",         false, nullptr, OPTION_SHARED},
        {"start",          true,  nullptr, OPTION_START},
        {"static-loader",  false, nullptr, OPTION_STATIC_LOADER},
        {"sync",           true,  nullptr, OPTION_SYNC},
        {"syntax",         true,  nullptr, OPTION_SYNTAX},
        {"trap-all",       false, nullptr, OPTION_TRAP_ALL},
        {nullptr,          false, nullptr, 0}
    }; 
    option_is_tty = isatty(STDERR_FILENO);
    std::vector<Action *> option_actions;
    std::vector<char *> option_options;
    unsigned option_compression_level = 9;
    ssize_t option_sync = -1;
    bool option_executable = false, option_shared = false,
        option_static_loader = false;
    std::string option_start(""), option_end(""), option_backend("./e9patch");
    while (true)
    {
        int idx;
        int opt = getopt_long(argc, argv, "A:c:ho:s", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_ACTION:
            case 'A':
            {
                Action *action = parseAction(optarg);
                option_actions.push_back(action);
                break;
            }
            case OPTION_BACKEND:
                option_backend = optarg;
                break;
            case OPTION_COMPRESSION:
            case 'c':
                if (!isdigit(optarg[0]) || optarg[1] != '\0')
                    error("bad value \"%s\" for `--compression' "
                        "option; expected a number 0..9", optarg);
                option_compression_level = optarg[0] - '0';
                break;
            case OPTION_DEBUG:
                option_debug = true;
                break;
            case OPTION_END:
                option_end = optarg;
                break;
            case OPTION_EXECUTABLE:
                option_executable = true;
                break;
            case OPTION_FORMAT:
                option_format = optarg;
                if (option_format != "binary" &&
                        option_format != "json" &&
                        option_format != "patch" &&
                        option_format != "patch.gz" &&
                        option_format != "patch.bz2" &&
                        option_format != "patch.xz")
                    error("bad value \"%s\" for `--format' option; "
                        "expected one of \"binary\", \"json\", \"patch\", "
                        "\"patch.gz\", \"patch.bz2\", or \"patch.xz\"",
                        optarg);
                break;
            case OPTION_HELP:
            case 'h':
                usage(stdout, argv[0]);
                return EXIT_SUCCESS;
            case OPTION_OPTION:
                option_options.push_back(strDup(optarg));
                break;
            case OPTION_OUTPUT:
            case 'o':
                option_output = optarg;
                break;
            case OPTION_SHARED:
                option_shared = true;
                break;
            case OPTION_STATIC_LOADER:
            case 's':
                option_static_loader = true;
                break;
            case OPTION_START:
                option_start = optarg;
                break;
            case OPTION_SYNC:
            {
                errno = 0;
                char *end = nullptr;
                unsigned long r = strtoul(optarg, &end, 10);
                if (errno != 0 || end == optarg ||
                        (end != nullptr && *end != '\0') || r > 1000)
                    error("bad value \"%s\" for `--sync' option; "
                        "expected an integer 0..1000", optarg);
                option_sync = (ssize_t)r;
                break;
            }
            case OPTION_SYNTAX:
                option_syntax = optarg;
                if (option_syntax != "att" && option_syntax != "intel")
                    error("bad value \"%s\" for `--syntax' option; "
                        "expected \"att\" or \"intel\"", optarg);
                break;
            case OPTION_TRAP_ALL:
                option_trap_all = true;
                break;
            default:
                error("failed to parse command-line options; try `--help' "
                    "for more information");
                return EXIT_FAILURE;
        }
    }
    if (optind != argc-1)
    {
        error("missing input file; try `--help' for more information");
        return EXIT_FAILURE;
    }
    if (option_actions.size() > MAX_ACTIONS)
        error("too many actions (%zu); the maximum is %zu",
            option_actions.size(), MAX_ACTIONS);
    if (option_shared && option_executable)
        error("both `--shared' and `--executable' cannot be used at the "
            "same time");

    /*
     * Parse the ELF file.
     */
    const char *filename = argv[optind];
    ELF elf;
    parseELF(filename, 0x0, elf);

    /*
     * The ELF file seems OK, spawn and initialize the e9patch backend.
     */
    Backend backend;
    if (option_static_loader)
        option_options.push_back(strDup("--static-loader"));
    if (option_trap_all)
        option_options.push_back(strDup("--trap-all"));
    if (option_format == "json")
    {
        // Pseudo-backend:
        backend.pid = 0;
        if (option_output == "-")
            backend.out = stdout;
        else
        {
            std::string filename(option_output);
            if (!hasSuffix(option_output, ".json"))
                filename += ".json";
            backend.out = fopen(filename.c_str(), "w");
            if (backend.out == nullptr)
                error("failed to open output file \"%s\": %s",
                    filename.c_str(), strerror(errno));
        }
    }
    else
        spawnBackend(option_backend.c_str(), option_options, backend);
    const char *mode = 
        (option_executable? "exe":
        (option_shared?     "dso":
        (elf.dso? "dso": "exe")));
    sendBinaryMessage(backend.out, mode, filename);

    /*
     * Send trampoline definitions:
     */
    bool have_print = false, have_passthru = false, have_trap = false;
    std::map<const char *, ELF *, CStrCmp> files;
    std::set<const char *, CStrCmp> have_call;
    intptr_t file_addr = elf.free_addr + 0x1000000;     // XXX
    for (const auto action: option_actions)
    {
        switch (action->kind)
        {
            case ACTION_PRINT:
                have_print = true;
                break;
            case ACTION_PASSTHRU:
                have_passthru = true;
                break;
            case ACTION_TRAP:
                have_trap = true;
                break;
            case ACTION_CALL:
            {
                // Step (1): Ensure the ELF file is loaded:
                ELF *target_elf = nullptr;
                auto i = files.find(action->filename);
                if (i == files.end())
                {
                    // Load the called ELF file into the address space:
                    intptr_t free_addr = file_addr + 8 * PAGE_SIZE;
                    free_addr = (free_addr % PAGE_SIZE == 0? free_addr:
                        (free_addr + PAGE_SIZE) - (free_addr % PAGE_SIZE));
                    target_elf = new ELF;
    
                    parseELF(action->filename, free_addr, *target_elf);
                    if (!target_elf->pie)
                        error("failed to parse ELF file \"%s\"; file is "
                            "not a dynamic executable", action->filename);
                    sendELFFileMessage(backend.out, *target_elf);
                    files.insert({action->filename, target_elf});
                    size_t size = (size_t)target_elf->free_addr;
                    free_addr += size;
                    file_addr = free_addr;
                }
                else
                    target_elf = i->second;

                // Step (2): Create the trampoline:
                auto j = have_call.find(action->name);
                if (j == have_call.end())
                {
                    sendCallTrampolineMessage(backend.out, *target_elf,
                        action->filename, action->symbol, action->name,
                        action->args, action->clean, action->before,
                        action->replace);
                    have_call.insert(action->name);
                }
                break;
            }
            case ACTION_PLUGIN:
            {
                void *handle = dlopen(action->filename,
                    RTLD_LOCAL | RTLD_LAZY);
                if (handle == nullptr)
                    error("failed to load plugin \"%s\": %s", action->filename,
                        dlerror());
                action->initFunc = (PluginInit)dlsym(handle,
                    "e9_plugin_init_v1");
                action->instrFunc = (PluginInstr)dlsym(handle,
                    "e9_plugin_instr_v1");
                action->patchFunc = (PluginPatch)dlsym(handle,
                    "e9_plugin_patch_v1");
                action->finiFunc = (PluginFini)dlsym(handle,
                    "e9_plugin_fini_v1");
                if (action->initFunc == nullptr &&
                        action->instrFunc == nullptr &&
                        action->patchFunc == nullptr &&
                        action->finiFunc == nullptr)
                    error("failed to load plugin \"%s\"; the shared "
                        "object does not export any plugin API functions",
                        action->filename);
                if (action->initFunc != nullptr)
                    action->context = action->initFunc(backend.out, &elf);
                action->handle = handle;
                break;
            }
            default:
                break;
        }
    }
    if (have_passthru)
        sendPassthruTrampolineMessage(backend.out);
    if (have_print)
        sendPrintTrampolineMessage(backend.out);
    if (have_trap)
        sendTrapTrampolineMessage(backend.out);

    /*
     * Find the offset to disassemble from, if any.
     */
    if (option_start != "")
    {
        intptr_t start_addr = positionToAddr(elf, "--start",
            option_start.c_str());
        off_t offset = start_addr - elf.text_addr;
        elf.text_offset += offset;
        elf.text_addr   += offset;
        elf.text_size   -= offset;
    }
    if (option_end != "")
    {
        intptr_t end_addr = positionToAddr(elf, "--end", option_end.c_str());
        off_t offset = (elf.text_addr + elf.text_size) - end_addr;
        elf.text_size -= offset;
    }

    /*
     * Disassemble the ELF file.
     */
    csh handle;
    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (err != 0)
        error("failed to open capstone handle (err = %u)", err);
    if (option_detail)
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (option_syntax != "intel")
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    std::vector<Location> locs;
    const uint8_t *start = elf.data + elf.text_offset;
    const uint8_t *code  = start, *end = start + elf.text_size;
    size_t size = elf.text_size;
    uint64_t address = elf.text_addr;
    cs_insn *I = cs_malloc(handle);
    bool failed = false;
    unsigned sync = 0;
    while (cs_disasm_iter(handle, &code, &size, &address, I))
    {
        if (sync > 0)
        {
            sync--;
            continue;
        }
        if (I->mnemonic[0] == '.')
        {
            warning("failed to disassemble (%s %s) at address 0x%lx",
                I->mnemonic, I->op_str, I->address);
            failed = true;
            sync = option_sync;
            continue;
        }

        bool patch = false;
        unsigned i = 0, index = 0;
        off_t offset = ((intptr_t)I->address - elf.text_addr);
        for (const auto action: option_actions)
        {
            bool veto_patch = false;
            if (action->kind == ACTION_PLUGIN && action->instrFunc != nullptr)
                veto_patch = !action->instrFunc(backend.out, &elf, handle,
                    offset, I, action->context);
            if (!patch && !veto_patch &&
                matchAction(handle, action, I, elf.text_addr, elf.text_offset))
            {
                index = i;
                patch = true;
            }
            i++;
        }

        Location loc(offset, I->size, patch, index);
        locs.push_back(loc);
    }
    if (code != end)
        error("failed to disassemble the full (.text) section 0x%lx..0x%lx; "
            "could only disassemble the range 0x%lx..0x%lx",
            elf.text_addr, elf.text_addr + elf.text_size, elf.text_addr,
                elf.text_addr + (code - start));
    if (failed)
    {
        if (option_sync < 0)
            error("failed to disassemble the .text section of \"%s\"; "
                "this may be caused by (1) data in the .text section, or (2) "
                "a bug in the third party disassembler (capstone)", filename);
        else
            warning("failed to disassemble the .text section of \"%s\"; "
                "the rewritten binary may be corrupt", filename);
    }

    /*
     * Send instructions & patches.  Note: this MUST be done in reverse!
     */
    size_t count = locs.size();
    for (ssize_t i = (ssize_t)count - 1; i >= 0; i--)
    {
        Location &loc = locs[i];
        if (!loc.patch)
            continue;

        off_t offset = (off_t)loc.offset;
        intptr_t addr = elf.text_addr + offset;
        offset += elf.text_offset;

        // Disassmble the instruction again.
        const uint8_t *code = elf.data + offset;
        uint64_t address = (uint64_t)addr;
        size_t size = loc.size;
        bool ok = cs_disasm_iter(handle, &code, &size, &address, I);
        if (!ok)
            error("failed to disassemble instruction at address 0x%lx", addr);

        bool done = false;
        for (ssize_t j = i; !done && j >= 0; j--)
            done = !sendInstructionMessage(backend.out, locs[j], addr,
                elf.text_addr, elf.text_offset);
        done = false;
        for (size_t j = i + 1; !done && j < count; j++)
            done = !sendInstructionMessage(backend.out, locs[j], addr,
                elf.text_addr, elf.text_offset);

        const Action *action = option_actions[loc.action];
        if (action->kind == ACTION_PLUGIN &&
            action->patchFunc != nullptr)
        {
            // Special handling for plugins:
            action->patchFunc(backend.out, &elf, handle, offset, I,
                action->context);
        }
        else
        {
            // Builtin actions:
            char asm_str_buf[256];
            Metadata metadata_buf[MAX_ARGNO+1];
            Metadata *metadata = buildMetadata(action, I, metadata_buf,
                asm_str_buf, sizeof(asm_str_buf)-1);
            sendPatchMessage(backend.out, action->name, offset, metadata);
        }
    }
    cs_free(I, 1);
    cs_close(&handle);

    /*
     * Finalize all plugins.
     */
    for (const auto action: option_actions)
    {
        if (action->kind != ACTION_PLUGIN)
            continue;
        if (action->finiFunc != nullptr)
            action->finiFunc(backend.out, &elf, action->context);
        action->context = nullptr;
        dlclose(action->handle);
    }

    /*
     * Emit the final binary/patch file.
     */
    if (option_format == "patch" && !hasSuffix(option_output, ".patch"))
        option_output += ".patch";
    else if (option_format == "patch.gz" &&
            !hasSuffix(option_output, ".patch.gz"))
        option_output += ".patch.gz";
    else if (option_format == "patch.bz2" &&
            !hasSuffix(option_output, ".patch.bz2"))
        option_output += ".patch.bz2";
    else if (option_format == "patch.xz" &&
            !hasSuffix(option_output, ".patch.xz"))
        option_output += ".patch.xz";
    else if (option_format == "json")
    {
        option_output = "a.out";
        option_format = "binary";
    }
    size_t mapping_size = PAGE_SIZE * (1 << (9 - option_compression_level));
    sendEmitMessage(backend.out, option_output.c_str(),
        option_format.c_str(), mapping_size);

    /*
     * Wait for the e9patch to complete.
     */
    waitBackend(backend);

    return 0;
}

