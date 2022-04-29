// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: 96e220e6886868d6663d966ecc396befffc355e7
// LLVM commit date: 2022-01-05 11:01:52 +0000 (ISO 8601 format)
// Date of code generation: 2022-04-17 16:44:52+02:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "hexagon.h"
#include "hexagon_insn.h"
#include "hexagon_arch.h"

/**
 * \brief Disassembles a hexagon opcode, write info to op and returns its size.
 *
 * \param a The current RzAsm struct.
 * \param op The RzAsmOp which is be filled with the reversed opcode information.
 * \param buf The buffer with the opcode.
 * \param l The size to read from the buffer.
 * \return int Size of the reversed opcode.
 */
static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int l) {
	rz_return_val_if_fail(a && op && buf, -1);
	if (l < 4) {
		return -1;
	}
	ut32 addr = (ut32)a->pc;
	HexReversedOpcode rev = { .action = HEXAGON_DISAS, .ana_op = NULL, .asm_op = op };

	hexagon_reverse_opcode(a, &rev, buf, addr);

	return op->size;
}

/**
 * \brief Setter for the plugins RzConfig nodes.
 *
 * \param user The user of the RzConfig node. If this callback is called by Core \p user = RzCore.
 * If it is called by the plugins config setup \p user = HexState.
 * \param data The node to set. Again, if called by RzCore \p date = Node from RzCore config.
 * If it is called by the plugins config setup \p data = a plugins config node.
 * \return bool True if the config was set. False otherwise.
 */
static bool hex_cfg_set(void *user, void *data) {
	rz_return_val_if_fail(user && data, false);
	HexState *state = hexagon_get_state();
	if (!state) {
		return false;
	}
	RzConfig *pcfg = state->cfg;

	RzConfigNode *cnode = (RzConfigNode *)data; // Config node from core.
	RzConfigNode *pnode = rz_config_node_get(pcfg, cnode->name); // Config node of plugin.
	if (pnode == cnode) {
		return true;
	}
	if (cnode) {
		pnode->i_value = cnode->i_value;
		pnode->value = cnode->value;
		return true;
	}
	return false;
}

static bool hexagon_init(void **user) {
	HexState *state = hexagon_get_state();
	rz_return_val_if_fail(state, false);

	*user = state; // user = RzAsm.plugin_data
	state->cfg = rz_config_new(state);
	rz_return_val_if_fail(state->cfg, false);

	RzConfig *cfg = state->cfg; // Rename for SETCB macros.
	// Add nodes
	SETCB("plugins.hexagon.imm.hash", "true", &hex_cfg_set, "Display ## before 32bit immediates and # before immidiates with other width.");
	SETCB("plugins.hexagon.imm.sign", "true", &hex_cfg_set, "True: Print them with sign. False: Print signed immediates in unsigned representation.");
	SETCB("plugins.hexagon.sdk", "false", &hex_cfg_set, "Print packet syntax in objdump style.");
	SETCB("plugins.hexagon.reg.alias", "true", &hex_cfg_set, "Print the alias of registers (Alias from C0 = SA0).");

	return true;
}

RZ_API RZ_BORROW RzConfig *hexagon_get_config() {
	HexState *state = hexagon_get_state();
	rz_return_val_if_fail(state, NULL);
	return state->cfg;
}

RzAsmPlugin rz_asm_plugin_hexagon = {
	.name = "hexagon",
	.arch = "hexagon",
	.author = "Rot127",
	.license = "LGPL3",
	.bits = 32,
	.desc = "Qualcomm Hexagon (QDSP6) V6",
	.init = &hexagon_init,
	.disassemble = &disassemble,
	.get_config = &hexagon_get_config,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_hexagon
};
#endif
