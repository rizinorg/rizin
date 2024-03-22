// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: b6f51787f6c8e77143f0aef6b58ddc7c55741d5c
// LLVM commit date: 2023-11-15 07:10:59 -0800 (ISO 8601 format)
// Date of code generation: 2024-03-16 06:22:39-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include <rz_util/rz_print.h>
#include <rz_vector.h>
#include <hexagon/hexagon.h>
#include <hexagon/hexagon_insn.h>
#include <hexagon/hexagon_arch.h>

static RZ_OWN RzPVector /*<RzAsmTokenPattern *>*/ *get_token_patterns() {
	RzPVector *pvec = rz_pvector_new(rz_asm_token_pattern_free);

	RzAsmTokenPattern *pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_META;
	pat->pattern = strdup(
		"^[\\[\\?\\/\\|\\\\\\{┌│└]|" // Packet prefix
		"(∎|[<\\}])[\\s:]endloop[01]{1,2}" // Endloop markers
	);
	rz_pvector_push(pvec, pat);

	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_META;
	pat->pattern = strdup(
		"\\#{1,2}|\\}$|" // Immediate prefix, Closing packet bracket
		"\\.new|:n?t|:raw|<err>" // .new and jump hints
	);
	rz_pvector_push(pvec, pat);

	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_REGISTER;
	pat->pattern = strdup(
		"[CNPRMQVO]\\d{1,2}(:\\d{1,2})?(in)?" // Registers and double registers
	);
	rz_pvector_push(pvec, pat);

	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_REGISTER;
	pat->pattern = strdup(
		"GP|HTID|UGP|LR|FP|SP" // Other regs
	);
	rz_pvector_push(pvec, pat);

	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_NUMBER;
	pat->pattern = strdup(
		"0x(\\d|[abcdef])+" // Hexadecimal numbers
	);
	rz_pvector_push(pvec, pat);

	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_MNEMONIC;
	pat->pattern = strdup(
		"\\w+_\\w+|[a-zA-Z]+\\d+[a-zA-Z]*" // Mnemonics with a decimal number in the name.
	);
	rz_pvector_push(pvec, pat);

	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_NUMBER;
	pat->pattern = strdup(
		"\\d+" // Decimal numbers
	);
	rz_pvector_push(pvec, pat);

	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_SEPARATOR;
	pat->pattern = strdup(
		"\\s+|" // Spaces and tabs
		"[,;\\.\\(\\)\\{\\}:]" // Brackets and others
	);
	rz_pvector_push(pvec, pat);

	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_OPERATOR;
	pat->pattern = strdup(
		"[+*&+?=!^\\/|-]{1,2}" // +,-,=,],[, ! (not the packet prefix)
	);
	rz_pvector_push(pvec, pat);

	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_OPERATOR;
	pat->pattern = strdup(
		"\\]|\\[|<{1,2}|>{1,2}" // +,-,=,],[, ! (not the packet prefix)
	);
	rz_pvector_push(pvec, pat);

	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_MNEMONIC;
	pat->pattern = strdup(
		"\\w+" // Alphanumeric mnemonics
	);
	rz_pvector_push(pvec, pat);

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
	HexState *state = hexagon_state(false);
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

RZ_IPI void hexagon_state_fini(HexState *state) {
	if (!state) {
		return;
	}
	rz_config_free(state->cfg);
	rz_pvector_free(state->token_patterns);
	rz_list_free(state->const_ext_l);
	return;
}

static bool hexagon_fini(void *user) {
	hexagon_state_fini(hexagon_state(false));
	hexagon_state(true);
	return true;
}

static bool hexagon_init(void **user) {
	HexState *state = hexagon_state(false);
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

	return true;
}

RZ_API RZ_BORROW RzConfig *hexagon_get_config() {
	HexState *state = hexagon_state(false);
	rz_return_val_if_fail(state, NULL);
	return state->cfg;
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
static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int l) {
	rz_return_val_if_fail(a && op && buf, -1);
	if (l < HEX_INSN_SIZE) {
		return -1;
	}
	ut32 addr = (ut32)a->pc;
	// Disassemble as many instructions as possible from the buffer.
	ut32 buf_offset = 0;
	while (buf_offset + HEX_INSN_SIZE <= l && buf_offset <= HEX_INSN_SIZE * HEX_MAX_INSN_PER_PKT) {
		const ut32 buf_ptr = rz_read_at_le32(buf, buf_offset);
		if (buf_offset > 0 && (buf_ptr == HEX_INVALID_INSN_0 || buf_ptr == HEX_INVALID_INSN_F)) {
			// Do not disassemble invalid instructions, if we already have a valid one.
			break;
		}

		HexReversedOpcode rev = { .action = HEXAGON_DISAS, .ana_op = NULL, .asm_op = op };
		hexagon_reverse_opcode(a, &rev, buf + buf_offset, addr + buf_offset, false);
		buf_offset += HEX_INSN_SIZE;
	}
	// Copy operation actually requested.
	HexReversedOpcode rev = { .action = HEXAGON_DISAS, .ana_op = NULL, .asm_op = op };
	hexagon_reverse_opcode(a, &rev, buf, addr, true);
	return HEX_INSN_SIZE;
}

RzAsmPlugin rz_asm_plugin_hexagon = {
	.name = "hexagon",
	.arch = "hexagon",
	.author = "Rot127",
	.license = "LGPL3",
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
