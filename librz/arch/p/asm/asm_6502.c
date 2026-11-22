// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// copypasta from asm_gb.c
#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include "asm_private.h"
#include <rz_lib.h>
#include <6502/6502dis.h>

static int _6520_disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	int dlen = disass_6502(a->pc, op, buf, len);
	return op->size = RZ_MAX(dlen, 0);
}

static bool _6520_config_magic_get(void *user, void *data) {
	ut64 *value = data;
	_6502State *state = user;
	if (!state) {
		return false;
	}
	*value = state->magic;
	return true;
}

static bool _6520_config_magic_set(void *user, const void *data) {
	const ut64 *value = data;
	_6502State *state = user;
	if (!state) {
		return false;
	}
	state->magic = *value;
	return true;
}

static RzConfig *_6502_get_config(void *plugin_data) {
	rz_return_val_if_fail(plugin_data, NULL);
	_6502State *state = (_6502State *)plugin_data;

	RzConfig *cfg = rz_config_new(NULL);
	if (!cfg) {
		return NULL;
	}

	// Add nodes
	rz_config_add_integer_bind(cfg,
		"plugins.6502.magic",
		"Determines the magic number certain illegal opcodes use.",
		_6520_config_magic_get,
		_6520_config_magic_set,
		NULL, state);

	return cfg;
}

static bool _6502_init(void **user) {
	_6502State *state = RZ_NEW0(_6502State);
	if (!state) {
		return false;
	}
	state->magic = 0xee;
	*user = state;
	return true;
}

static bool _6502_fini(void *user) {
	free(user);
	return true;
}

RzAsmPlugin rz_asm_plugin_6502 = {
	.name = "6502",
	.desc = "6502/NES/C64/Tamagotchi/T-1000 CPU",
	.arch = "6502",
	.bits = 8 | 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.license = "LGPL3",
	.disassemble = &_6520_disassemble,
	.init = _6502_init,
	.get_config = _6502_get_config,
	.fini = _6502_fini
};
