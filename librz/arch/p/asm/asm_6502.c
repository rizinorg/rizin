// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// copypasta from asm_gb.c
#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include <6502/6502dis.h>

static int _6520_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	int dlen = disass_6502(a->pc, op, buf, len);
	return op->size = RZ_MAX(dlen, 0);
}

RzConfig *_6502_get_config(void *plugin_data) {
	rz_return_val_if_fail(plugin_data, NULL);
	_6502State *state = (_6502State *)plugin_data;
	return rz_config_clone(state->cfg);
}

static bool _6502_cfg_set(void *user, void *data) {
	rz_return_val_if_fail(user && data, false);
	_6502State *state = user;
	RzConfig *pcfg = state->cfg;

	RzConfigNode *cnode = (RzConfigNode *)data; // Config node from core.
	RzConfigNode *pnode = rz_config_node_get(pcfg, cnode->name); // Config node of plugin.
	if (pnode == cnode) {
		return true;
	}
	if (cnode) {
		pnode->i_value = cnode->i_value;
		free(pnode->value);
		pnode->value = rz_str_dup(cnode->value);
		return true;
	}
	return false;
}

static bool _6502_init(void **user) {
	_6502State *state = _6502_state_new();
	rz_return_val_if_fail(state, false);
	RzConfig *cfg = state->cfg = rz_config_new(state);
	rz_return_val_if_fail(state->cfg, false);

	SETICB("plugins.6502.magic", 0xee, &_6502_cfg_set, "Determines the magic number certain illegal opcodes use.");
	*user = state;
	return true;
}

void _6502State_fini(_6502State *state) {
	if (!state) {
		return;
	}
	rz_config_free(state->cfg);
	return;
}

static bool _6502_fini(void *user) {
	_6502State_fini(user);
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
