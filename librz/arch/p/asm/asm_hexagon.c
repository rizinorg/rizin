// SPDX-FileCopyrightText: 2021 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: bc5ac5f3ebb0bc4fc65cef7160c817ca3174a68e
// LLVM commit date: 2026-03-15 10:22:07 -0700 (ISO 8601 format)
// Date of code generation: 2026-03-15 22:23:13+01:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include "asm_private.h"
#include <rz_lib.h>
#include <rz_vector.h>
#include <hexagon/hexagon.h>
#include <hexagon/hexagon_insn.h>
#include <hexagon/hexagon_arch.h>

#define TOKEN(_type, _pat) \
	do { \
		RzAsmTokenPattern *pat = RZ_NEW0(RzAsmTokenPattern); \
		pat->type = RZ_ASM_TOKEN_##_type; \
		pat->pattern = strdup(_pat); \
		rz_pvector_push(pvec, pat); \
	} while (0)

static RZ_OWN RzPVector /*<RzAsmTokenPattern *>*/ *get_token_patterns() {
	RzPVector *pvec = rz_pvector_new(rz_asm_token_pattern_free);

	TOKEN(META,
		// Packet prefix
		"^[\\[\\?\\/\\|\\\\\\{┌│└]|"
		// Endloop markers
		"(∎|[<\\}])[\\s:]endloop[01]{1,2}");

	TOKEN(META,
		// Immediate prefix, Closing packet bracket
		"\\#{1,2}|\\}$|"
		// .new and jump hints
		"\\.new|:n?t|:raw|<err>|"
		":after|:before|:single|:above|:retain|:deep|:dilate|:drop");

	// Special registers
	TOKEN(REGISTER,
		"\\b([A-Z]{2,}|acc|activation|weight|cvt|activation|bias|z)\\b");

	TOKEN(REGISTER,
		"[CNPRMQVO]\\d{1,2}(:\\d{1,2})?(in)?|"
		// Registers and double registers
		"([A-Z]{2,}[0-9]{1})");

	TOKEN(NUMBER,
		// Hexadecimal numbers
		"0x(\\d|[abcdef])+");

	TOKEN(MNEMONIC,
		// Mnemonics with a decimal number in the name.
		"\\w+_\\w+|[a-zA-Z]+\\d+[a-zA-Z]*");

	TOKEN(NUMBER,
		// Decimal numbers
		"\\d+");

	TOKEN(SEPARATOR,
		// Spaces and tabs
		"\\s+|"
		// Brackets and others
		"[,;\\.\\(\\)\\{\\}:]");

	TOKEN(OPERATOR,
		// +,-,=,],[, ! (not the packet prefix)
		"[+*&+?=!^\\/|~\\-]{1,2}");

	TOKEN(OPERATOR,
		// +,-,=,],[, ! (not the packet prefix)
		"\\]|\\[|<{1,2}|>{1,2}");

	TOKEN(MNEMONIC,
		// Alphanumeric mnemonics
		"\\w+");

	return pvec;
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
	HexState *state = user;
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

static bool hexagon_fini(void *user) {
	hexagon_state_fini(user);
	free(user);
	return true;
}

static bool hexagon_init(void **plugin_data) {
	HexState *state = hexagon_state_new();
	rz_return_val_if_fail(state, false);

	state->cfg = rz_config_new(state);
	rz_return_val_if_fail(state->cfg, false);

	RzConfig *cfg = state->cfg; // Rename for SETCB macros.
	// Add nodes
	SETCB("plugins.hexagon.imm.hash", "true", &hex_cfg_set, "Display ## before 32bit immediates and # before immidiates with other width.");
	SETCB("plugins.hexagon.imm.sign", "true", &hex_cfg_set, "True: Print them with sign. False: Print signed immediates in unsigned representation.");
	SETCB("plugins.hexagon.sdk", "false", &hex_cfg_set, "Print packet syntax in objdump style.");
	SETCB("plugins.hexagon.reg.alias", "true", &hex_cfg_set, "Print the alias of registers (Alias from C0 = SA0).");

	if (!state->token_patterns) {
		state->token_patterns = get_token_patterns();
	}
	rz_asm_compile_token_patterns(state->token_patterns);

	*plugin_data = state;
	return true;
}

RZ_API RZ_OWN RzConfig *hexagon_get_config(void *plugin_data) {
	rz_return_val_if_fail(plugin_data, NULL);
	HexState *state = plugin_data;
	return rz_config_clone(state->cfg);
}

/**
 * \brief Disassembles a hexagon opcode, write info to op and returns its size.
 *
 * \param a The current RzAsm struct.
 * \param op The RzAsmOp which is be filled with the reversed opcode information.
 * \param buf The buffer with the opcode.
 * \param l The size to read from the buffer.
 * \return int Size of the reversed opcode.
 */
static int disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int l) {
	rz_return_val_if_fail(a && op, -1);
	if (l < HEX_INSN_SIZE) {
		return -1;
	}

	ut32 addr = (ut32)a->pc;
	HexReversedOpcode rev = { .action = HEXAGON_DISAS, .ana_op = NULL, .asm_op = op, .state = NULL, .pkt_fully_decoded = false, .bytes_buf = buf, .bytes_buf_len = l };
	hexagon_reverse_opcode(&rev, addr, a, NULL);
	return op->size;
}

RzAsmPlugin rz_asm_plugin_hexagon = {
	.name = "hexagon",
	.arch = "hexagon",
	.author = "Rot127",
	.license = "LGPL3",
	.cpus = "v81llvm",
	.features = "HVX",
	.bits = 32,
	.desc = "Qualcomm Hexagon (QDSP6) V6",
	.init = &hexagon_init,
	.fini = &hexagon_fini,
	.disassemble = &disassemble,
	.get_config = &hexagon_get_config,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_hexagon
};
#endif
