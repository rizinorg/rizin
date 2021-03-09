// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PIC_PIC18_H
#define PIC_PIC18_H

#include <rz_asm.h>

int pic_pic18_disassemble(RzAsmOp *op, char *opbuf, const ut8 *b, int l);

#endif //PIC_PIC18_H
