// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cons.h>
#include <rz_windows.h>
#include "../core_private.h"
#include "modes.h"

const char *printfmtSingle[NPF] = {
	"xc", // HEXDUMP
	"pd $r", // ASSEMBLY
	("pxw 64@r:SP;" CMD_REGISTERS ";pd $r"), // DEBUGGER
	"prc", // OVERVIEW
	"pss", // PC//  copypasteable views
};

const char *printfmtColumns[NPF] = {
	"pCx", // HEXDUMP // + pCw
	"pCd $r-1", // ASSEMBLY
	"pCD", // DEBUGGER
	"pCA", // OVERVIEW
	"pCc", // PC//  copypasteable views
};

const char *printHexFormats[PRINT_HEX_FORMATS] = {
	"px",
	"pxa",
	"pxr",
	"prx",
	"pxb",
	"pxh",
	"pxw",
	"pxq",
	"pxd",
	"pxr",
};

const char *print3Formats[PRINT_3_FORMATS] = { //  not used at all. its handled by the pd format
	"pxw 64@r:SP;" CMD_REGISTERS ";pd $r", // DEBUGGER
	"pCD"
};

const char *print4Formats[PRINT_4_FORMATS] = {
	"prc", "prc=a", "pxAv", "pxx", "p=e $r-2", "pk 64"
};

const char *print5Formats[PRINT_5_FORMATS] = {
	"pca", "pcA", "p8", "pcc", "pss", "pcp", "pcd", "pcj"
};

const char *printCmds[lastPrintMode] = {
	"pdf", "pd $r", "agf", "agl", "afi", "pxa"
};
