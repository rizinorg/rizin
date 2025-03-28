// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (C) 2024 RizinOrg <info@rizin.re>
// Copyright (C) 2024 deroad <wargio@libero.it>
// Copyright (C) 2025 thedvlprguy <thedvlprguy@flash.co>

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

#include "../p_gnu/analysis/analysis_vax_gnu.c"
#include "vax_disasm.c"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
    RzStrBuf *sb = &op->buf_asm;
    int ret = vax_disassemble(sb, buf, len, a->pc);
    if (ret < 0) {
        rz_strbuf_set(sb, "(invalid)");
        return 1;
    }
    return ret;
}

RzAsmPlugin rz_asm_plugin_vax = {
    .name = "vax",
    .arch = "vax",
    .license = "LGPL3",
    .bits = 8 | 32,
    .endian = RZ_SYS_ENDIAN_LITTLE,
    .desc = "DEC VAX disassembler",
    .disassemble = &disassemble
};

RZ_ARCH_PLUGIN_DEFINE(vax);
