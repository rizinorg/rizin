// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <capstone/capstone.h>

#include "../arch/tricore/tricore.inc"
#include <librz/asm/arch/tricore/tricore.h>

#define TRICORE_LONGEST_INSTRUCTION  4
#define TRICORE_SHORTEST_INSTRUCTION 2

static RzAsmTriCoreState *get_state() {
	static RzAsmTriCoreState *state = NULL;
	if (state) {
		return state;
	}

	state = RZ_NEW0(RzAsmTriCoreState);
	if (!state) {
		RZ_LOG_FATAL("Could not allocate memory for HexState!");
	}
	return state;
}

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!buf || len < TRICORE_SHORTEST_INSTRUCTION) {
		return -1;
	}

	csh handle = tricore_setup_cs_handle(a->cpu, a->features);
	if (handle == 0) {
		return -1;
	}

	cs_insn *insn = NULL;
	unsigned count = cs_disasm(handle, buf, len, a->pc, 1, &insn);
	if (count <= 0) {
		return -1;
	}

	op->size = insn->size;
	char *asmstr = rz_str_newf("%s%s%s", insn->mnemonic,
		RZ_STR_ISNOTEMPTY(insn->op_str) ? " " : "", insn->op_str);
	rz_asm_op_set_asm(op, asmstr);
	free(asmstr);
	cs_free(insn, count);
	return op->size;
}

#define TOKEN(_type, _pat) \
	do { \
		RzAsmTokenPattern *pat = RZ_NEW0(RzAsmTokenPattern); \
		pat->type = RZ_ASM_TOKEN_##_type; \
		pat->pattern = strdup(_pat); \
		rz_pvector_push(pvec, pat); \
	} while (0)

static RZ_OWN RzPVector /*<RzAsmTokenPattern *>*/ *get_token_patterns() {
	static RzPVector *pvec = NULL;
	if (pvec) {
		return pvec;
	}

	pvec = rz_pvector_new(rz_asm_token_pattern_free);

	TOKEN(META, "(\\[|\\]|-)");
	TOKEN(META, "(\\+[rc]?)");

	TOKEN(NUMBER, "(0x[[:digit:]abcdef]+)");

	TOKEN(REGISTER, "([adep][[:digit:]]{1,2})|(sp|psw|pcxi|pc|fcx|lcx|isp|icr|pipn|biv|btv)");

	TOKEN(SEPARATOR, "([[:blank:]]+)|([,;#\\(\\)\\{\\}:])");

	TOKEN(MNEMONIC, "([[:alpha:]]+[[:alnum:]\\.]*[[:alnum:]]+)|([[:alpha:]]+)");

	TOKEN(NUMBER, "([[:digit:]]+)");

	return pvec;
}

static bool init(void **user) {
	RzAsmTriCoreState *state = get_state();
	rz_return_val_if_fail(state, false);

	*user = state; // user = RzAsm.plugin_data

	state->token_patterns = get_token_patterns();
	rz_asm_compile_token_patterns(state->token_patterns);
	return true;
}

RzAsmPlugin rz_asm_plugin_tricore = {
	.name = "tricore",
	.arch = "tricore",
	.author = "billow",
	.license = "BSD",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Siemens TriCore CPU",
	.disassemble = &disassemble,
	.init = &init,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_tricore,
	.version = RZ_VERSION
};
#endif
