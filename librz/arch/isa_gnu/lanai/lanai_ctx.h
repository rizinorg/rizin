// SPDX-FileCopyrightText: 2026 Yashwin <iskalayashwinsai@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#ifndef LANAI_CTX_H
#define LANAI_CTX_H

#include <rz_util/rz_strbuf.h>

struct lanai_opcode;

typedef struct {
	unsigned long Offset;
	RzStrBuf *buf_global;
	unsigned char bytes[4];
	struct lanai_opcode *opcodes;
} LanaiContext;

RZ_IPI void lanai_dis_context_init(RZ_NONNULL LanaiContext *ctx);
RZ_IPI void lanai_dis_context_fini(RZ_NONNULL LanaiContext *ctx);

#endif
