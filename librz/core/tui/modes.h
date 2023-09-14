// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "../core_private.h"

#define NPF  5
#define PIDX (RZ_ABS(((RzCoreVisual *)core->visual)->printidx % NPF))

#define CMD_REGISTERS      "%== true `e cfg.debug`; %! dr=; %% ar=" // select dr= or ar= depending on cfg.debug
#define CMD_REGISTERS_REFS "%== true `e cfg.debug`; %! drr; %% arr" // select drr or arr depending on cfg.debug

extern const char *printfmtSingle[NPF];
extern const char *printfmtColumns[NPF];

// to print the stack in the debugger view
#define PRINT_HEX_FORMATS 10
#define PRINT_3_FORMATS   2
#define PRINT_4_FORMATS   5
#define PRINT_5_FORMATS   8

extern const char *printHexFormats[PRINT_HEX_FORMATS];
extern const char *print3Formats[PRINT_3_FORMATS];
extern const char *print4Formats[PRINT_4_FORMATS];
extern const char *print5Formats[PRINT_5_FORMATS];

#define lastPrintMode 6

extern const char *printCmds[lastPrintMode];
extern const char *printDisOptimized[];
