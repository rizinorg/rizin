// SPDX-FileCopyrightText: 2015-2019 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_types.h>

typedef struct mcs96_op_t {
	const char *ins;
	const ut32 type;
} Mcs96Op;

#define MCS96_1B 0x1
#define MCS96_2B 0x2
#define MCS96_3B 0x4
#define MCS96_4B 0x8
#define MCS96_5B 0x10

#define MCS96_3B_OR_4B 0x20
#define MCS96_4B_OR_5B 0x40
#define MCS96_5B_OR_6B 0x80

#define MCS96_2OP 0x100
#define MCS96_3OP 0x200
#define MCS96_4OP 0x400
#define MCS96_5OP 0x800

#define MCS96_REG_8 0x1000

#define MCS96_FE 0x2000 // 0xfe extension

static Mcs96Op mcs96_op[] = {
	{ "skip", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "shr", MCS96_3B },
	{ "shl", MCS96_3B },
	{ "shra", MCS96_3B }, // 0x0a
	{ "invalid", MCS96_1B },
	{ "shrl", MCS96_3B },
	{ "shll", MCS96_3B },
	{ "shral", MCS96_3B },
	{ "norml", MCS96_3B },
	{ "invalid", MCS96_1B }, // 0x10
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "shrb", MCS96_3B },
	{ "shlb", MCS96_3B },
	{ "shrab", MCS96_3B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "sjmp", MCS96_2B }, // 0x20
	{ "sjmp", MCS96_2B },
	{ "sjmp", MCS96_2B },
	{ "sjmp", MCS96_2B },
	{ "sjmp", MCS96_2B },
	{ "sjmp", MCS96_2B },
	{ "sjmp", MCS96_2B },
	{ "sjmp", MCS96_2B },
	{ "scall", MCS96_2B }, // 0x28
	{ "scall", MCS96_2B },
	{ "scall", MCS96_2B },
	{ "scall", MCS96_2B },
	{ "scall", MCS96_2B },
	{ "scall", MCS96_2B },
	{ "scall", MCS96_2B },
	{ "scall", MCS96_2B },
	{ "jbc", MCS96_3B }, // 0x30
	{ "jbc", MCS96_3B },
	{ "jbc", MCS96_3B },
	{ "jbc", MCS96_3B },
	{ "jbc", MCS96_3B },
	{ "jbc", MCS96_3B },
	{ "jbc", MCS96_3B },
	{ "jbc", MCS96_3B },
	{ "jbs", MCS96_3B }, // 0x38
	{ "jbs", MCS96_3B },
	{ "jbs", MCS96_3B },
	{ "jbs", MCS96_3B },
	{ "jbs", MCS96_3B },
	{ "jbs", MCS96_3B },
	{ "jbs", MCS96_3B },
	{ "jbs", MCS96_3B },
	{ "and", MCS96_4B | MCS96_3OP }, // 0x40
	{ "and", MCS96_5B | MCS96_3OP },
	{ "and", MCS96_4B | MCS96_3OP },
	{ "and", MCS96_5B_OR_6B | MCS96_3OP },
	{ "add", MCS96_4B | MCS96_3OP },
	{ "add", MCS96_5B | MCS96_3OP },
	{ "add", MCS96_4B | MCS96_3OP },
	{ "add", MCS96_5B_OR_6B | MCS96_3OP },
	{ "sub", MCS96_4B | MCS96_3OP },
	{ "sub", MCS96_5B | MCS96_3OP },
	{ "sub", MCS96_4B | MCS96_3OP },
	{ "sub", MCS96_5B_OR_6B | MCS96_3OP },
	{ "mulu", MCS96_4B | MCS96_3OP | MCS96_FE },
	{ "mulu", MCS96_5B | MCS96_3OP | MCS96_FE },
	{ "mulu", MCS96_4B | MCS96_3OP | MCS96_FE },
	{ "mulu", MCS96_5B_OR_6B | MCS96_3OP | MCS96_FE }, // 0x4f
	{ "andb", MCS96_4B | MCS96_3OP | MCS96_REG_8 },
	{ "andb", MCS96_4B | MCS96_3OP },
	{ "andb", MCS96_4B | MCS96_3OP },
	{ "andb", MCS96_5B_OR_6B | MCS96_3OP }, // datasheet says that this is always 5 byte
	// that datasheet already has proven to have typos
	{ "addb", MCS96_4B | MCS96_3OP },
	{ "addb", MCS96_4B | MCS96_3OP },
	{ "addb", MCS96_4B | MCS96_3OP },
	{ "addb", MCS96_5B_OR_6B | MCS96_3OP },
	{ "subb", MCS96_4B | MCS96_3OP },
	{ "subb", MCS96_4B | MCS96_3OP },
	{ "subb", MCS96_4B | MCS96_3OP },
	{ "subb", MCS96_5B_OR_6B | MCS96_3OP },
	{ "mulub", MCS96_4B | MCS96_3OP | MCS96_FE },
	{ "mulub", MCS96_4B | MCS96_3OP | MCS96_FE },
	{ "mulub", MCS96_4B | MCS96_3OP | MCS96_FE },
	{ "mulub", MCS96_5B_OR_6B | MCS96_3OP | MCS96_FE }, // 0x5f
	{ "and", MCS96_3B | MCS96_2OP },
	{ "and", MCS96_4B | MCS96_2OP },
	{ "and", MCS96_3B | MCS96_2OP },
	{ "and", MCS96_4B_OR_5B | MCS96_2OP },
	{ "add", MCS96_3B | MCS96_2OP },
	{ "add", MCS96_4B | MCS96_2OP },
	{ "add", MCS96_3B | MCS96_2OP },
	{ "add", MCS96_4B_OR_5B | MCS96_2OP },
	{ "sub", MCS96_3B | MCS96_2OP },
	{ "sub", MCS96_4B | MCS96_2OP },
	{ "sub", MCS96_3B | MCS96_2OP },
	{ "sub", MCS96_4B_OR_5B | MCS96_2OP },
	{ "mulu", MCS96_3B | MCS96_2OP | MCS96_FE },
	{ "mulu", MCS96_4B | MCS96_2OP | MCS96_FE },
	{ "mulu", MCS96_3B | MCS96_2OP | MCS96_FE },
	{ "mulu", MCS96_4B_OR_5B | MCS96_2OP | MCS96_FE }, // 0x6f
	{ "andb", MCS96_3B | MCS96_2OP | MCS96_REG_8 },
	{ "andb", MCS96_3B | MCS96_2OP },
	{ "andb", MCS96_3B | MCS96_2OP },
	{ "andb", MCS96_4B_OR_5B | MCS96_2OP }, // again i don't trust the data-sheet here
	{ "addb", MCS96_3B | MCS96_2OP | MCS96_REG_8 },
	{ "addb", MCS96_3B | MCS96_2OP },
	{ "addb", MCS96_3B | MCS96_2OP },
	{ "addb", MCS96_4B_OR_5B | MCS96_2OP },
	{ "subb", MCS96_3B | MCS96_2OP | MCS96_REG_8 },
	{ "subb", MCS96_3B | MCS96_2OP },
	{ "subb", MCS96_3B | MCS96_2OP },
	{ "subb", MCS96_4B_OR_5B | MCS96_2OP },
	{ "mulub", MCS96_3B | MCS96_2OP | MCS96_FE | MCS96_REG_8 },
	{ "mulub", MCS96_3B | MCS96_2OP | MCS96_FE },
	{ "mulub", MCS96_3B | MCS96_2OP | MCS96_FE },
	{ "mulub", MCS96_4B_OR_5B | MCS96_2OP | MCS96_FE }, // 0x7f
	{ "or", MCS96_3B | MCS96_2OP },
	{ "or", MCS96_4B | MCS96_2OP },
	{ "or", MCS96_3B | MCS96_2OP },
	{ "or", MCS96_4B_OR_5B | MCS96_2OP },
	{ "xor", MCS96_3B | MCS96_2OP },
	{ "xor", MCS96_4B | MCS96_2OP },
	{ "xor", MCS96_3B | MCS96_2OP },
	{ "xor", MCS96_4B_OR_5B | MCS96_2OP },
	{ "cmp", MCS96_3B | MCS96_2OP },
	{ "cmp", MCS96_4B | MCS96_2OP },
	{ "cmp", MCS96_3B | MCS96_2OP },
	{ "cmp", MCS96_4B_OR_5B | MCS96_2OP },
	{ "divu", MCS96_3B | MCS96_2OP | MCS96_FE },
	{ "divu", MCS96_4B | MCS96_2OP | MCS96_FE },
	{ "divu", MCS96_3B | MCS96_2OP | MCS96_FE },
	{ "divu", MCS96_4B_OR_5B | MCS96_2OP | MCS96_FE }, // 0x8f
	{ "orb", MCS96_3B | MCS96_2OP | MCS96_REG_8 },
	{ "orb", MCS96_3B | MCS96_2OP },
	{ "orb", MCS96_3B | MCS96_2OP },
	{ "orb", MCS96_4B_OR_5B | MCS96_2OP },
	{ "xorb", MCS96_3B | MCS96_2OP | MCS96_REG_8 },
	{ "xorb", MCS96_3B | MCS96_2OP },
	{ "xorb", MCS96_3B | MCS96_2OP },
	{ "xorb", MCS96_4B_OR_5B | MCS96_2OP },
	{ "cmpb", MCS96_3B | MCS96_2OP | MCS96_REG_8 },
	{ "cmpb", MCS96_3B | MCS96_2OP },
	{ "cmpb", MCS96_3B | MCS96_2OP },
	{ "cmpb", MCS96_4B_OR_5B | MCS96_2OP },
	{ "divub", MCS96_3B | MCS96_2OP | MCS96_FE | MCS96_REG_8 },
	{ "divub", MCS96_3B | MCS96_2OP | MCS96_FE },
	{ "divub", MCS96_3B | MCS96_2OP | MCS96_FE },
	{ "divub", MCS96_4B_OR_5B | MCS96_2OP | MCS96_FE }, // 0x9f
	{ "ld", MCS96_3B | MCS96_2OP },
	{ "ld", MCS96_4B | MCS96_2OP },
	{ "ld", MCS96_3B | MCS96_2OP },
	{ "ld", MCS96_4B_OR_5B | MCS96_2OP },
	{ "addc", MCS96_3B | MCS96_2OP },
	{ "addc", MCS96_4B | MCS96_2OP },
	{ "addc", MCS96_3B | MCS96_2OP },
	{ "addc", MCS96_4B_OR_5B | MCS96_2OP },
	{ "subc", MCS96_3B | MCS96_2OP },
	{ "subc", MCS96_4B | MCS96_2OP },
	{ "subc", MCS96_3B | MCS96_2OP },
	{ "subc", MCS96_4B_OR_5B | MCS96_2OP },
	{ "lbsze", MCS96_3B | MCS96_2OP },
	{ "lbsze", MCS96_3B | MCS96_2OP },
	{ "lbsze", MCS96_3B | MCS96_2OP },
	{ "lbsze", MCS96_4B_OR_5B | MCS96_2OP }, // 0xaf
	{ "ldb", MCS96_3B | MCS96_2OP | MCS96_REG_8 },
	{ "ldb", MCS96_3B | MCS96_2OP },
	{ "ldb", MCS96_3B | MCS96_2OP },
	{ "ldb", MCS96_4B_OR_5B | MCS96_2OP },
	{ "addcb", MCS96_3B | MCS96_2OP | MCS96_REG_8 },
	{ "addcb", MCS96_3B | MCS96_2OP },
	{ "addcb", MCS96_3B | MCS96_2OP },
	{ "addcb", MCS96_4B_OR_5B | MCS96_2OP },
	{ "subcb", MCS96_3B | MCS96_2OP | MCS96_REG_8 },
	{ "subcb", MCS96_3B | MCS96_2OP },
	{ "subcb", MCS96_3B | MCS96_2OP },
	{ "subcb", MCS96_4B_OR_5B | MCS96_2OP },
	{ "ldbse", MCS96_3B | MCS96_2OP | MCS96_REG_8 },
	{ "ldbse", MCS96_3B | MCS96_2OP },
	{ "ldbse", MCS96_3B | MCS96_2OP },
	{ "ldbse", MCS96_4B_OR_5B | MCS96_2OP }, // 0xbf
	{ "st", MCS96_3B | MCS96_2OP },
	{ "invalid", MCS96_1B },
	{ "st", MCS96_3B | MCS96_2OP },
	{ "st", MCS96_4B_OR_5B | MCS96_2OP },
	{ "stb", MCS96_3B | MCS96_2OP },
	{ "invalid", MCS96_1B },
	{ "stb", MCS96_3B | MCS96_2OP },
	{ "stb", MCS96_4B_OR_5B | MCS96_2OP },
	{ "push", MCS96_2B },
	{ "push", MCS96_3B },
	{ "push", MCS96_2B },
	{ "push", MCS96_3B_OR_4B },
	{ "pop", MCS96_2B },
	{ "invalid", MCS96_1B },
	{ "pop", MCS96_2B },
	{ "pop", MCS96_3B_OR_4B }, // 0xcf
	{ "jnst", MCS96_2B },
	{ "jnh", MCS96_2B },
	{ "jgt", MCS96_2B },
	{ "jnc", MCS96_2B },
	{ "jnvt", MCS96_2B },
	{ "jnv", MCS96_2B },
	{ "jge", MCS96_2B },
	{ "jne", MCS96_2B },
	{ "jst", MCS96_2B },
	{ "jh", MCS96_2B },
	{ "jle", MCS96_2B },
	{ "jc", MCS96_2B },
	{ "jvt", MCS96_2B },
	{ "jv", MCS96_2B },
	{ "jlt", MCS96_2B },
	{ "je", MCS96_2B }, // 0xdf
	{ "djnz", MCS96_3B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "br", MCS96_2B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "ljmp", MCS96_3B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "lcall", MCS96_3B }, // 0xef
	{ "ret", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "pushf", MCS96_1B },
	{ "popf", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "trap", MCS96_1B },
	{ "clrc", MCS96_1B },
	{ "setc", MCS96_1B },
	{ "di", MCS96_1B },
	{ "ei", MCS96_1B },
	{ "clrvt", MCS96_1B },
	{ "nop", MCS96_1B },
	{ "invalid", MCS96_1B },
	{ "rst", MCS96_1B }
};

static const char *mcs96_fe_op[] = { "mul", "mulb", "mul", "mulb", "div", "divb", "invalid", "invalid" };
// in theory these invalids can never happen
