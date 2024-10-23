// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "xtensa.h"

bool xtensa_init(void **user) {
	if (*user) {
		return true;
	}
	XtensaContext *ctx = RZ_NEW0(XtensaContext);
	if (!ctx) {
		return false;
	}
	*user = ctx;
	return true;
}

bool xtensa_fini(void *user) {
	XtensaContext *ctx = user;
	cs_close(&ctx->handle);
	free(ctx);
	return true;
}

bool xtensa_open(XtensaContext *ctx, const char *cpu, bool big_endian) {
	if (!ctx) {
		return false;
	}
	if (RZ_STR_ISNOTEMPTY(cpu) && RZ_STR_NE(cpu, "xtensa")) {
		return false;
	}
	cs_mode mode = big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
	if (cs_open(CS_ARCH_XTENSA, mode, &ctx->handle) != CS_ERR_OK) {
		return false;
	}
	if (cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
		return false;
	}
	return true;
}

bool xtensa_disassemble(XtensaContext *self, const ut8 *buf, int len, ut64 addr) {
	self->count = cs_disasm(self->handle, buf, len, addr, 1, &self->insn);
	if (self->count == 0) {
		return false;
	}
	return true;
}

void xtensa_disassemble_fini(XtensaContext *self) {
	if (!self->insn)
		return;
	cs_free(self->insn, self->count);
	self->insn = NULL;
	self->count = 0;
}
