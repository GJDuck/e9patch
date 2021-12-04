/*
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
#ifndef __E9CODEGEN_H
#define __E9CODEGEN_H

#include <cstdint>
#include <cstdio>

#include "e9tool.h"
#include "e9types.h"

/*
 * GPR register indexes.
 */
#define RDI_IDX         0
#define RSI_IDX         1
#define RDX_IDX         2
#define RCX_IDX         3
#define R8_IDX          4
#define R9_IDX          5
#define RFLAGS_IDX      6
#define RAX_IDX         7
#define R10_IDX         8
#define R11_IDX         9
#define RBX_IDX         10
#define RBP_IDX         11
#define R12_IDX         12
#define R13_IDX         13
#define R14_IDX         14
#define R15_IDX         15
#define RSP_IDX         16
#define RIP_IDX         17
#define RMAX_IDX        RIP_IDX


/*
 * Special stack slots.
 */
#define RSP_SLOT    0x4000
#define RIP_SLOT    (0x4000 - sizeof(int64_t))

/*
 * Prototypes.
 */
extern e9tool::Register getReg(int regno);
extern int getRegIdx(e9tool::Register reg);
extern int getArgRegIdx(bool sysv, int argno);
extern Type getRegType(e9tool::Register reg);
extern int32_t getRegSize(e9tool::Register reg);
extern e9tool::Register getCanonicalReg(e9tool::Register reg);
extern bool isHighReg(e9tool::Register reg);
extern const int *getCallerSaveRegs(bool sysv, bool clean, bool state,
    bool conditional, size_t num_args);
extern std::pair<bool, bool> sendPush(FILE *out, int32_t offset, bool before,
    e9tool::Register reg,
    e9tool::Register rscratch = e9tool::REGISTER_INVALID);
extern bool sendPop(FILE *out, bool conditional, e9tool::Register reg,
    e9tool::Register rscratch = e9tool::REGISTER_INVALID);
extern bool sendMovFromR64ToR64(FILE *out, int srcno, int dstno);
extern void sendMovFromR32ToR64(FILE *out, int srcno, int dstno);
extern void sendMovFromR16ToR64(FILE *out, int srcno, int dstno);
extern void sendMovFromR8ToR64(FILE *out, int srcno, bool srchi, int dstno);
extern void sendMovFromStackToR64(FILE *out, int32_t offset, int regno);
extern void sendMovFromStack32ToR64(FILE *out, int32_t offset, int regno);
extern void sendMovFromStack16ToR64(FILE *out, int32_t offset, int regno);
extern void sendMovFromStack8ToR64(FILE *out, int32_t offset, int regno);
extern void sendMovFromR64ToStack(FILE *out, int regno, int32_t offset);
extern void sendMovFromRAX16ToR64(FILE *out, int regno);
extern void sendSExtFromI32ToR64(FILE *out, const char *value, int regno);
extern void sendSExtFromI32ToR64(FILE *out, int32_t value, int regno);
extern void sendZExtFromI32ToR64(FILE *out, const char *value, int regno);
extern void sendZExtFromI32ToR64(FILE *out, int32_t value, int regno);
extern void sendMovFromI64ToR64(FILE *out, intptr_t value, int regno);
extern void sendMovFromI64ToR64(FILE *out, const char *value, int regno);
extern void sendMovFromPCRelToR64(FILE *out, int32_t offset, int regno);
extern void sendLeaFromPCRelToR64(FILE *out, const char *offset, int regno);
extern void sendLeaFromPCRelToR64(FILE *out, int32_t offset, int regno);
extern void sendLeaFromStackToR64(FILE *out, int32_t offset, int regno);

#endif
