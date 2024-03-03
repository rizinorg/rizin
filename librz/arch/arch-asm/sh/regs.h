// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_SH_REGS_H
#define RZ_SH_REGS_H

/**
 * All registers
 */
static const char *sh_registers[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "pc",
	"sr", "gbr", "ssr", "spc", "sgr", "dbr", "vbr", "mach", "macl",
	"pr", "fpul", "fpscr",
	"fr0", "fr1", "fr2", "fr3", "fr4", "fr5", "fr6", "fr7",
	"fr8", "fr9", "fr10", "fr11", "fr12", "fr13", "fr14", "fr15",
	"xf0", "xf1", "xf2", "xf3", "xf4", "xf5", "xf6", "xf7",
	"xf8", "xf9", "xf10", "xf11", "xf12", "xf13", "xf14", "xf15",
	"r0b", "r1b", "r2b", "r3b", "r4b", "r5b", "r6b", "r7b"
};

#endif // RZ_SH_REGS_H
