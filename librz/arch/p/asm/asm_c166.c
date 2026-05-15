// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file asm_c166.c
 * \brief Assembly and disassembly plugin for C166 architecture
 *
 * Provides functionality for disassembling C166 machine code into assembly language
 * representation and assembling C166 assembly code into machine code.
 */

#include <stdio.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include "asm_private.h"

#include "librz/arch/isa/c166/c166_disas.h"

static bool check_unused_opcode(const ut8 opcode) {
	switch (opcode) {
	case 0x3b:
	case 0x44:
	case 0x45:
	case 0x8B:
	case 0x95:
	case 0xC1:
	case 0xC7:
	case 0xE3:
	case 0xE5:
	case 0xF5:
	case 0xF8:
	case 0xF9:
		return true;
	default:
		break;
	}
	return false;
}

static _RzAnalysisOpType c166_analysis_op_type_by_opcode(const ut8 opcode) {
	switch (opcode) {
	case C166_ADD_Rwn_Rwm:
	case C166_ADDB_Rbn_Rbm:
	case C166_ADD_reg_mem:
	case C166_ADDB_reg_mem:
	case C166_ADD_mem_reg:
	case C166_ADDB_mem_reg:
	case C166_ADD_reg_data16:
	case C166_ADDB_reg_data8:
	case C166_ADD_Rwn_x:
	case C166_ADDB_Rbn_x:
	case C166_ADDC_Rwn_Rwm:
	case C166_ADDCB_Rbn_Rbm:
	case C166_ADDC_reg_mem:
	case C166_ADDCB_reg_mem:
	case C166_ADDC_mem_reg:
	case C166_ADDCB_mem_reg:
	case C166_ADDC_reg_data16:
	case C166_ADDCB_reg_data8:
	case C166_ADDC_Rwn_x:
	case C166_ADDCB_Rbn_x:
		return RZ_ANALYSIS_OP_TYPE_ADD;
	case C166_BFLDL_bitoff_x:
	case C166_BCLR_bitoff0:
	case C166_BSET_bitoff0:
	case C166_BFLDH_bitoff_x:
	case C166_BCLR_bitoff1:
	case C166_BSET_bitoff1:
	case C166_BCLR_bitoff2:
	case C166_BSET_bitoff2:
	case C166_BCLR_bitoff3:
	case C166_BSET_bitoff3:
	case C166_BCLR_bitoff4:
	case C166_BSET_bitoff4:
	case C166_BCLR_bitoff5:
	case C166_BSET_bitoff5:
	case C166_BCLR_bitoff6:
	case C166_BSET_bitoff6:
	case C166_BCLR_bitoff7:
	case C166_BSET_bitoff7:
	case C166_BCLR_bitoff8:
	case C166_BSET_bitoff8:
	case C166_BCLR_bitoff9:
	case C166_BSET_bitoff9:
	case C166_BCLR_bitoff10:
	case C166_BSET_bitoff10:
	case C166_BCLR_bitoff11:
	case C166_BSET_bitoff11:
	case C166_BCLR_bitoff12:
	case C166_BSET_bitoff12:
	case C166_BCLR_bitoff13:
	case C166_BSET_bitoff13:
	case C166_BCLR_bitoff14:
	case C166_BSET_bitoff14:
	case C166_BCLR_bitoff15:
	case C166_BSET_bitoff15:
		return RZ_ANALYSIS_OP_TYPE_STORE;
	case C166_MUL_Rwn_Rwm:
	case C166_MULU_Rwn_Rwm:
		return RZ_ANALYSIS_OP_TYPE_MUL;
	case C166_ROL_Rwn_Rwm:
	case C166_ROL_Rwn_data4:
		return RZ_ANALYSIS_OP_TYPE_ROL;
	case C166_JMPR_cc_UC_rel:
	case C166_JMPR_cc_NET_rel:
	case C166_JMPR_cc_EQ_or_Z_rel:
	case C166_JMPR_cc_NE_or_NZ_rel:
	case C166_JMPR_cc_V_rel:
	case C166_JMPR_cc_NV_rel:
	case C166_JMPR_cc_N_rel:
	case C166_JMPR_cc_NN_rel:
	case C166_JMPR_cc_C_or_ULT_rel:
	case C166_JMPR_cc_NC_or_NGE_rel:
	case C166_JMPR_cc_SGT_rel:
	case C166_JMPR_cc_SLE_rel:
	case C166_JMPR_cc_SLT_rel:
	case C166_JMPR_cc_SGE_rel:
	case C166_JMPA_cc_caddr:
	case C166_JMPR_cc_UGT_rel:
	case C166_JMPS_seg_caddr:
	case C166_JMPR_cc_ULE_rel:
	case C166_JB_bitaddr_rel:
	case C166_JBC_bitaddr_rel:
	case C166_JNB_bitaddr_rel:
	case C166_JNBS_bitaddr_rel:
		return RZ_ANALYSIS_OP_TYPE_CJMP;
	case C166_SUB_Rwn_Rwm:
	case C166_SUBB_Rbn_Rbm:
	case C166_SUB_reg_mem:
	case C166_SUBB_reg_mem:
	case C166_SUB_mem_reg:
	case C166_SUBB_mem_reg:
	case C166_SUB_reg_data16:
	case C166_SUBB_reg_data8:
	case C166_SUB_Rwn_x:
	case C166_SUBB_Rbn_x:
	case C166_SUBC_Rwn_Rwm:
	case C166_SUBCB_Rbn_Rbm:
	case C166_SUBC_reg_mem:
	case C166_SUBCB_reg_mem:
	case C166_SUBC_mem_reg:
	case C166_SUBCB_mem_reg:
	case C166_SUBC_reg_data16:
	case C166_SUBCB_reg_data8:
	case C166_SUBC_Rwn_x:
	case C166_SUBCB_Rbn_x:
		return RZ_ANALYSIS_OP_TYPE_SUB;
	case C166_BCMP_bitaddr_bitaddr:
	case C166_CMP_Rwn_Rwm:
	case C166_CMPB_Rbn_Rbm:
	case C166_CMP_reg_mem:
	case C166_CMPB_reg_mem:
	case C166_CMP_reg_data16:
	case C166_CMPB_reg_data8:
	case C166_CMP_Rwn_x:
	case C166_CMPB_Rbn_x:
	case C166_CMPI1_Rwn_data4:
	case C166_CMPI1_Rwn_mem:
	case C166_CMPI1_Rwn_data16:
	case C166_CMPI2_Rwn_data4:
	case C166_CMPI2_Rwn_mem:
	case C166_CMPI2_Rwn_data16:
	case C166_CMPD1_Rwn_data4:
	case C166_CMPD1_Rwn_mem:
	case C166_CMPD1_Rwn_data16:
	case C166_CMPD2_Rwn_data4:
	case C166_CMPD2_Rwn_mem:
	case C166_CMPD2_Rwn_data16:
		return RZ_ANALYSIS_OP_TYPE_CMP;
	case C166_XOR_Rwn_Rwm:
	case C166_XORB_Rbn_Rbm:
	case C166_XOR_reg_mem:
	case C166_XORB_reg_mem:
	case C166_XOR_mem_reg:
	case C166_XORB_mem_reg:
	case C166_XOR_reg_data16:
	case C166_XORB_reg_data8:
	case C166_XOR_Rwn_x:
	case C166_XORB_Rbn_x:
		return RZ_ANALYSIS_OP_TYPE_XOR;
	case C166_AND_Rwn_Rwm:
	case C166_ANDB_Rbn_Rbm:
	case C166_AND_reg_mem:
	case C166_ANDB_reg_mem:
	case C166_AND_mem_reg:
	case C166_ANDB_mem_reg:
	case C166_AND_reg_data16:
	case C166_ANDB_reg_data8:
	case C166_AND_Rwn_x:
	case C166_ANDB_Rbn_x:
		return RZ_ANALYSIS_OP_TYPE_AND;
	case C166_BMOVN_bitaddr_bitaddr:
	case C166_BMOV_bitaddr_bitaddr:
	case C166_MOV_oRwn_mem:
	case C166_MOV_noRwm_Rwn:
	case C166_MOVB_noRwm_Rbn:
	case C166_MOV_mem_oRwn:
	case C166_MOV_Rwn_oRwmp:
	case C166_MOVB_Rbn_oRwmp:
	case C166_MOVB_oRwn_mem:
	case C166_MOV_Rwn_oRwm:
	case C166_MOVB_Rbn_oRwm:
	case C166_MOVB_mem_oRwn:
	case C166_MOV_oRwm_Rwn:
	case C166_MOVB_oRwm_Rbn:
	case C166_MOVBZ_Rwn_Rbm:
	case C166_MOVBZ_reg_mem:
	case C166_MOV_oRwm_data16_Rwn:
	case C166_MOVBZ_mem_reg:
	case C166_MOV_oRwn_oRwm:
	case C166_MOVB_oRwn_oRwm:
	case C166_MOVBS_Rwn_Rbm:
	case C166_MOVBS_reg_mem:
	case C166_MOV_Rwn_oRwm_data16:
	case C166_MOVBS_mem_reg:
	case C166_MOV_oRwnp_oRwm:
	case C166_MOVB_oRwnp_oRwm:
	case C166_MOV_Rwn_data4:
	case C166_MOVB_Rbn_data4:
	case C166_MOVB_oRwm_data16_Rbn:
	case C166_MOV_reg_data16:
	case C166_MOVB_reg_data8:
	case C166_MOV_oRwn_oRwmp:
	case C166_MOVB_oRwn_oRwmp:
	case C166_MOV_Rwn_Rwm:
	case C166_MOVB_Rbn_Rbm:
	case C166_MOV_reg_mem:
	case C166_MOVB_reg_mem:
	case C166_MOVB_Rbn_oRwm_data16:
	case C166_MOV_mem_reg:
	case C166_MOVB_mem_reg:
		return RZ_ANALYSIS_OP_TYPE_MOV;
	case C166_OR_Rwn_Rwm:
	case C166_ORB_Rbn_Rbm:
	case C166_OR_reg_mem:
	case C166_ORB_reg_mem:
	case C166_OR_mem_reg:
	case C166_ORB_mem_reg:
	case C166_OR_reg_data16:
	case C166_ORB_reg_data8:
	case C166_OR_Rwn_x:
	case C166_ORB_Rbn_x:
		return RZ_ANALYSIS_OP_TYPE_OR;
	case C166_RET:
	case C166_RETS:
	case C166_RETP_reg:
	case C166_RETI:
		return RZ_ANALYSIS_OP_TYPE_RET;
	case C166_DIV_Rwn:
	case C166_DIVU_Rwn:
	case C166_DIVL_Rwn:
	case C166_DIVLU_Rwn:
		return RZ_ANALYSIS_OP_TYPE_DIV;
	case C166_ROR_Rwn_Rwm:
	case C166_ROR_Rwn_data4:
		return RZ_ANALYSIS_OP_TYPE_ROR;
	case C166_SHL_Rwn_Rwm:
	case C166_SHL_Rwn_data4:
		return RZ_ANALYSIS_OP_TYPE_SHL;
	case C166_SHR_Rwn_Rwm:
	case C166_SHR_Rwn_data4:
	case C166_ASHR_Rwn_Rwm:
	case C166_ASHR_Rwn_data4:
		return RZ_ANALYSIS_OP_TYPE_SHR;
	case C166_CPL_Rwn:
	case C166_NEGB_Rbn:
	case C166_CPLB_Rbn:
		return RZ_ANALYSIS_OP_TYPE_CPL;
	case C166_CALLR_rel:
	case C166_CALLS_seg_caddr:
	case C166_PCALL_reg_caddr:
		return RZ_ANALYSIS_OP_TYPE_CALL;
	case C166_TRAP_trap7:
		return RZ_ANALYSIS_OP_TYPE_TRAP;
	case C166_JMPI_cc_oRwn:
		return RZ_ANALYSIS_OP_TYPE_RCJMP;
	case C166_CALLI_cc_Rwn:
		return RZ_ANALYSIS_OP_TYPE_IRCALL;
	case C166_CALLA_cc_caddr:
		return RZ_ANALYSIS_OP_TYPE_CCALL;
	case C166_NOP:
		return RZ_ANALYSIS_OP_TYPE_NOP;
	case C166_PUSH_reg:
		return RZ_ANALYSIS_OP_TYPE_PUSH;
	case C166_POP_reg:
		return RZ_ANALYSIS_OP_TYPE_POP;
	case C166_PRIOR_Rwn_Rwm: // or RZ_ANALYSIS_OP_TYPE_LOAD,
	case C166_BOR_bitaddr_bitaddr:
	case C166_BAND_bitaddr_bitaddr:
	case C166_BXOR_bitaddr_bitaddr:
	case C166_NEG_Rwn:
	case C166_CoXXX_83:
	case C166_ENWDT:
	case C166_IDLE:
	case C166_SBRK:
	case C166_CoXXX_93:
	case C166_PWRDN:
	case C166_CoXXX_A3:
	case C166_DISWDT:
	case C166_SRVWDT:
	case C166_CoSTORE_B3:
	case C166_EINIT:
	case C166_SRST:
	case C166_CoSTORE_C3:
	case C166_SCXT_reg_data16:
	case C166_ATOMIC_or_EXTR_irang2:
	case C166_CoMOV:
	case C166_SCXT_reg_mem:
	case C166_EXTP_or_EXTS_pag10_or_seg8_irang2:
	case C166_EXTP_or_EXTS_Rwm_irang2:
		return RZ_ANALYSIS_OP_TYPE_UNK;
	default:
		printf("0x%02x\n", opcode);
		rz_warn_if_reached();
		return RZ_ANALYSIS_OP_TYPE_UNK;
	}
}

/**
 * \brief C166 disassembly function
 * \param a Pointer to RzAsm structure
 * \param op Pointer to RzAsmOp structure to be filled with disassembly data
 * \param buf Buffer containing instruction bytes
 * \param len Length of the buffer
 * \return Length of the disassembled instruction or 0 on failure
 *
 * Disassembles a single C166 instruction and populates the op->buf_asm with
 * human-readable assembly representation. Uses the c166_decode_command helper function
 * to perform the actual disassembly.
 */
static st32 disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *buf, st32 len) {
	if (!a || !op || !buf) {
		return -1;
	}

	if (len < 2) {
		rz_asm_op_setf_asm(op, FMT_WORD, buf[0], 0x00);
		op->size = 2;
		return op->size;
	}

	C166State *state = (C166State *)a->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.\n");
	}

	C166_Inst inst = RZ_EMPTY;
	inst.addr = (ut32)a->pc;
	if (check_unused_opcode(buf[0])) {
		rz_asm_op_setf_asm(op, FMT_WORD, buf[0], buf[1]);
		op->size = 2;
		return op->size;
	}
	op->size = c166_decode_command(state, &inst, buf, len);

	if (op->size == 4 && len == 3) {
		rz_asm_op_setf_asm(op, FMT_2WORD, buf[0], buf[1], buf[2], 0x00);
	} else if (op->size == 4 && len == 2) {
		rz_asm_op_setf_asm(op, FMT_2WORD, buf[0], buf[1], 0x00, 0x00);
	} else if (op->size == 2 && len == 1) {
		rz_asm_op_setf_asm(op, FMT_WORD, buf[0], 0x00);
	} else if (RZ_STR_EQ(inst.instr, "invalid")) {
		if (op->size == 2)
			rz_asm_op_setf_asm(op, FMT_WORD, buf[0], buf[1]);
		else
			rz_asm_op_setf_asm(op, FMT_2WORD, buf[0], buf[1], buf[2], buf[3]);
	} else {
		if (RZ_STR_ISNOTEMPTY(inst.operands)) {
			rz_asm_op_setf_asm(op, FMT7, inst.instr, inst.operands);
		} else {
			rz_asm_op_setf_asm(op, "%s", inst.instr);
		}
	}
	op->asm_toks = rz_asm_tokenize_asm_regex(&op->buf_asm, state->token_patterns);
	if (!op->asm_toks) {
		return op->size;
	}
	op->asm_toks->op_type = c166_analysis_op_type_by_opcode(inst.id);
	return op->size;
}

#define TOKEN(_type, _pat) \
	do { \
		RzAsmTokenPattern *pat = RZ_NEW0(RzAsmTokenPattern); \
		pat->type = RZ_ASM_TOKEN_##_type; \
		pat->pattern = rz_str_dup(_pat); \
		rz_pvector_push(pvec, pat); \
	} while (0)

static RZ_OWN RzPVector /*<RzAsmTokenPattern *>*/ *get_token_patterns() {
	RzPVector *pvec = rz_pvector_new(rz_asm_token_pattern_free);
	if (!pvec) {
		return NULL;
	}
	TOKEN(META, "^(.word.*)");
	TOKEN(SEPARATOR, "([\\s.,:]+)");
	TOKEN(REGISTER, "\\b0x([fF][eEfF][0-9a-fA-F]{2})\\b");
	TOKEN(MNEMONIC, "^(jmpa[+-]?)"); ///< jmpa+ jmpa-  mnemonics
	TOKEN(MNEMONIC, "^(calla[+-]?)"); ///< calla+ calla- mnemonics
	TOKEN(META, "^([\\- USR]+[012]?)");
	TOKEN(MNEMONIC, "\\b(Co[\\w]+[12]?)"); ///< CoXXX mnemonics
	TOKEN(META, "([\\[\\]\\-#])");
	// TOKEN(META, "(cc_\\w+)");
	TOKEN(META, "(cc_[\\w\\/]+)");
	// Hexadecimal numbers
	TOKEN(NUMBER, "(0x[0-9a-f]+)");
	/**
	 * Match normal registers which start with small r, optional h or l
	 * and a number.
	 * Or match special register names which are always upper case
	 * and possibly have numbers in it.
	 */
	TOKEN(REGISTER, "\\b(r[hl]?[0-9]{1,2}|[A-Z]+[A-Z0-9]*)\\b");
	TOKEN(MNEMONIC, "^([\\w]+[12]?)");
	// TOKEN(SEPARATOR, "([\\s.,:+]+)");
	TOKEN(SEPARATOR, "(\\+)");
	// Decimal numbers
	TOKEN(NUMBER, "(data[2,3,4,5,8])");
	TOKEN(NUMBER, "(\\d+)");
	/**
	 * These comments are technical,
	 * to avoid losing working token versions
	 * for functions that are not yet fully implemented.
	 */
	return pvec;
}

static bool c16x_init(void **user) {
	C166State *state = RZ_NEW0(C166State);
	if (!state) {
		RZ_LOG_FATAL("Could not allocate memory for C166State!\n");
		return false;
	}

	const C166ExtState ext = {
		.esfr = false,
		.mode = C166_EXT_MODE_NONE,
		.i = 0,
		.value = 0
	};

	state->ext = ext;
	state->last_addr = 0;

	state->token_patterns = get_token_patterns();
	rz_asm_compile_token_patterns(state->token_patterns);

	*user = state; ///< user = RzAsm.plugin_data
	return true;
}

static bool c16x_fini(void *user) {
	if (!user) {
		return false;
	}
	C166State *state = (C166State *)user;
	rz_pvector_free(state->token_patterns);
	free(state);
	return true;
}

static char **c166_cpu_descriptions() {
	static char *cpu_desc[] = {
		"c166-generic", "Siemens/Infineon C166 family",
		"c166v1", "Siemens/Infineon C16x v1 family",
		"c166v2", "Siemens/Infineon C16x v2 family",
		NULL
	};
	return cpu_desc;
}

RzAsmPlugin rz_asm_plugin_c166 = {
	.name = "c166",
	.arch = "c166",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Siemens/Infineon C166 microcontroller disassembler",
	.license = "LGPL3",
	.disassemble = &disassemble,
	.init = &c16x_init,
	.fini = &c16x_fini,
	.cpus =
		"c166-generic,"
		"c166v1,"
		"c166v2",
	.get_cpu_desc = c166_cpu_descriptions,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = rz_asm_plugin_c166,
	.version = RZ_VERSION
};
#endif
