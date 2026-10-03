// SPDX-FileCopyrightText: 2026 Yashwin <iskalayashwinsai@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#ifndef ARC_CTX_H
#define ARC_CTX_H

#include <rz_util/rz_strbuf.h>
#include <common_gnu/disas-asm.h>

typedef struct {
	struct disassemble_info disasm_obj;
	ut32 Offset;
	RzStrBuf *buf_global;
	int buf_len;
	ut8 bytes[32];
	char post_address_buf[3 * 4];
	short enable_simd;
	short enable_insn_stream;
} ArcContext;

#endif
