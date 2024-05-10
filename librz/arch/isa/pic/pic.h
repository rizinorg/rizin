// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only//

#ifndef RIZIN_PIC_H
#define RIZIN_PIC_H

#include <rz_io.h>

typedef struct {
	RzIODesc *mem_sram;
	RzIODesc *mem_stack;
	bool init_done;
	HtSU *pic18_mm;
} PicContext;

#endif // RIZIN_PIC_H
