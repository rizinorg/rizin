// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c166_disas.c
 * \brief C166 disassembler implementation
 *
 * Core disassembler implementation for the C166 microcontroller architecture.
 * Converts machine code bytes into human-readable assembly language strings.
 *
 * \see [Datasheet](https://www.infineon.com/row/public/documents/10/44/infineon-c166-ism-v2.0-2001-03.pdf)
 * \see [Mirror](https://www.mouser.com/ds/2/196/c166sv2um-1109557.pdf)
 */

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <string.h>

#include <c166/c166_disas.h>

static const char *c166_instr_name(ut8 instr) {
	switch (instr) {
	case C166_ADD_Rwn_Rwm:
	case C166_ADD_Rwn_x:
	case C166_ADD_mem_reg:
	case C166_ADD_reg_mem:
	case C166_ADD_reg_data16:
		return "add";
	case C166_ADDB_Rbn_Rbm:
	case C166_ADDB_Rbn_x:
	case C166_ADDB_mem_reg:
	case C166_ADDB_reg_mem:
	case C166_ADDB_reg_data8:
		return "addb";
	case C166_ADDC_Rwn_Rwm:
	case C166_ADDC_Rwn_x:
	case C166_ADDC_mem_reg:
	case C166_ADDC_reg_mem:
	case C166_ADDC_reg_data16:
		return "addc";
	case C166_ADDCB_Rbn_Rbm:
	case C166_ADDCB_Rbn_x:
	case C166_ADDCB_mem_reg:
	case C166_ADDCB_reg_mem:
	case C166_ADDCB_reg_data8:
		return "addcb";
	case C166_SUB_Rwn_Rwm:
	case C166_SUB_Rwn_x:
	case C166_SUB_mem_reg:
	case C166_SUB_reg_mem:
	case C166_SUB_reg_data16:
		return "sub";
	case C166_SUBB_Rbn_Rbm:
	case C166_SUBB_Rbn_x:
	case C166_SUBB_mem_reg:
	case C166_SUBB_reg_mem:
	case C166_SUBB_reg_data8:
		return "subb";
	case C166_SUBC_Rwn_Rwm:
	case C166_SUBC_Rwn_x:
	case C166_SUBC_mem_reg:
	case C166_SUBC_reg_mem:
	case C166_SUBC_reg_data16:
		return "subc";
	case C166_SUBCB_Rbn_Rbm:
	case C166_SUBCB_Rbn_x:
	case C166_SUBCB_mem_reg:
	case C166_SUBCB_reg_mem:
	case C166_SUBCB_reg_data8:
		return "subcb";
	case C166_MUL_Rwn_Rwm:
		return "mul";
	case C166_MULU_Rwn_Rwm:
		return "mulu";
	case C166_DIV_Rwn:
		return "div";
	case C166_DIVL_Rwn:
		return "divl";
	case C166_DIVLU_Rwn:
		return "divlu";
	case C166_DIVU_Rwn:
		return "divu";
	case C166_CPL_Rwn:
		return "cpl";
	case C166_CPLB_Rbn:
		return "cplb";
	case C166_NEG_Rwn:
		return "neg";
	case C166_NEGB_Rbn:
		return "negb";
	case C166_AND_mem_reg:
	case C166_AND_reg_data16:
	case C166_AND_reg_mem:
	case C166_AND_Rwn_Rwm:
	case C166_AND_Rwn_x:
		return "and";
	case C166_ANDB_mem_reg:
	case C166_ANDB_reg_data8:
	case C166_ANDB_reg_mem:
	case C166_ANDB_Rbn_Rbm:
	case C166_ANDB_Rbn_x:
		return "andb";
	case C166_OR_mem_reg:
	case C166_OR_reg_data16:
	case C166_OR_reg_mem:
	case C166_OR_Rwn_Rwm:
	case C166_OR_Rwn_x:
		return "or";
	case C166_ORB_mem_reg:
	case C166_ORB_reg_data8:
	case C166_ORB_reg_mem:
	case C166_ORB_Rbn_Rbm:
	case C166_ORB_Rbn_x:
		return "orb";
	case C166_XOR_mem_reg:
	case C166_XOR_reg_data16:
	case C166_XOR_reg_mem:
	case C166_XOR_Rwn_Rwm:
	case C166_XOR_Rwn_x:
		return "xor";
	case C166_XORB_mem_reg:
	case C166_XORB_reg_data8:
	case C166_XORB_reg_mem:
	case C166_XORB_Rbn_Rbm:
	case C166_XORB_Rbn_x:
		return "xorb";
	case C166_PRIOR_Rwn_Rwm:
		return "prior";
	case C166_CMP_reg_data16:
	case C166_CMP_reg_mem:
	case C166_CMP_Rwn_Rwm:
	case C166_CMP_Rwn_x:
		return "cmp";
	case C166_CMPB_reg_data8:
	case C166_CMPB_reg_mem:
	case C166_CMPB_Rbn_Rbm:
	case C166_CMPB_Rbn_x:
		return "cmpb";
	case C166_CMPD1_Rwn_data16:
	case C166_CMPD1_Rwn_data4:
	case C166_CMPD1_Rwn_mem:
		return "cmpd1";
	case C166_CMPD2_Rwn_data16:
	case C166_CMPD2_Rwn_data4:
	case C166_CMPD2_Rwn_mem:
		return "cmpd2";
	case C166_CMPI1_Rwn_data16:
	case C166_CMPI1_Rwn_data4:
	case C166_CMPI1_Rwn_mem:
		return "cmpi1";
	case C166_CMPI2_Rwn_data16:
	case C166_CMPI2_Rwn_data4:
	case C166_CMPI2_Rwn_mem:
		return "cmpi2";
	case C166_SCXT_reg_mem:
	case C166_SCXT_reg_data16:
		return "scxt";
	case C166_SHL_Rwn_data4:
	case C166_SHL_Rwn_Rwm:
		return "shl";
	case C166_SHR_Rwn_data4:
	case C166_SHR_Rwn_Rwm:
		return "shr";
	case C166_ROL_Rwn_data4:
	case C166_ROL_Rwn_Rwm:
		return "rol";
	case C166_ROR_Rwn_data4:
	case C166_ROR_Rwn_Rwm:
		return "ror";
	case C166_ASHR_Rwn_data4:
	case C166_ASHR_Rwn_Rwm:
		return "ashr";
	case C166_MOV_mem_oRwn:
	case C166_MOV_mem_reg:
	case C166_MOV_noRwm_Rwn:
	case C166_MOV_oRwn_mem:
	case C166_MOV_oRwn_oRwm:
	case C166_MOV_oRwn_oRwmp:
	case C166_MOV_oRwm_Rwn:
	case C166_MOV_oRwnp_oRwm:
	case C166_MOV_reg_data16:
	case C166_MOV_reg_mem:
	case C166_MOV_Rwn_data4:
	case C166_MOV_Rwn_oRwm_data16:
	case C166_MOV_oRwm_data16_Rwn:
	case C166_MOV_Rwn_oRwm:
	case C166_MOV_Rwn_oRwmp:
	case C166_MOV_Rwn_Rwm:
		return "mov";
	case C166_MOVB_mem_oRwn:
	case C166_MOVB_mem_reg:
	case C166_MOVB_noRwm_Rbn:
	case C166_MOVB_oRwm_data16_Rbn:
	case C166_MOVB_oRwn_mem:
	case C166_MOVB_oRwn_oRwm:
	case C166_MOVB_oRwn_oRwmp:
	case C166_MOVB_oRwm_Rbn:
	case C166_MOVB_oRwnp_oRwm:
	case C166_MOVB_Rbn_oRwm_data16:
	case C166_MOVB_Rbn_oRwm:
	case C166_MOVB_Rbn_oRwmp:
	case C166_MOVB_Rbn_Rbm:
	case C166_MOVB_reg_data8:
	case C166_MOVB_reg_mem:
	case C166_MOVB_Rbn_data4:
		return "movb";
	case C166_MOVBS_Rwn_Rbm:
	case C166_MOVBS_reg_mem:
	case C166_MOVBS_mem_reg:
		return "movbs";
	case C166_MOVBZ_Rwn_Rbm:
	case C166_MOVBZ_reg_mem:
	case C166_MOVBZ_mem_reg:
		return "movbz";
	case C166_JMPA_cc_caddr:
		return "jmpa";
	case C166_JMPI_cc_oRwn:
		return "jmpi";
	case C166_JMPR_cc_C_or_ULT_rel:
	case C166_JMPR_cc_EQ_or_Z_rel:
	case C166_JMPR_cc_N_rel:
	case C166_JMPR_cc_NC_or_NGE_rel:
	case C166_JMPR_cc_NE_or_NZ_rel:
	case C166_JMPR_cc_NET_rel:
	case C166_JMPR_cc_NN_rel:
	case C166_JMPR_cc_NV_rel:
	case C166_JMPR_cc_SGE_rel:
	case C166_JMPR_cc_SGT_rel:
	case C166_JMPR_cc_SLE_rel:
	case C166_JMPR_cc_SLT_rel:
	case C166_JMPR_cc_UC_rel:
	case C166_JMPR_cc_UGT_rel:
	case C166_JMPR_cc_ULE_rel:
	case C166_JMPR_cc_V_rel:
		return "jmpr";
	case C166_JMPS_seg_caddr:
		return "jmps";
	case C166_JB_bitaddr_rel:
		return "jb";
	case C166_JBC_bitaddr_rel:
		return "jbc";
	case C166_JNB_bitaddr_rel:
		return "jnb";
	case C166_JNBS_bitaddr_rel:
		return "jnbs";
	case C166_CALLA_cc_caddr:
		return "calla";
	case C166_CALLI_cc_Rwn:
		return "calli";
	case C166_CALLR_rel:
		return "callr";
	case C166_CALLS_seg_caddr:
		return "calls";
	case C166_PCALL_reg_caddr:
		return "pcall";
	case C166_POP_reg:
		return "pop";
	case C166_PUSH_reg:
		return "push";
	case C166_TRAP_trap7:
		return "trap";
	case C166_RET:
		return "ret";
	case C166_RETS:
		return "rets";
	case C166_RETP_reg:
		return "retp";
	case C166_RETI:
		return "reti";
	case C166_BAND_bitaddr_bitaddr:
		return "band";
	case C166_BOR_bitaddr_bitaddr:
		return "bor";
	case C166_BXOR_bitaddr_bitaddr:
		return "bxor";
	case C166_BCMP_bitaddr_bitaddr:
		return "bcmp";
	case C166_BMOV_bitaddr_bitaddr:
		return "bmov";
	case C166_BMOVN_bitaddr_bitaddr:
		return "bmovn";
	case C166_BFLDL_bitoff_x:
		return "bfldl";
	case C166_BFLDH_bitoff_x:
		return "bfldh";
	case C166_BCLR_bitoff0:
	case C166_BCLR_bitoff1:
	case C166_BCLR_bitoff2:
	case C166_BCLR_bitoff3:
	case C166_BCLR_bitoff4:
	case C166_BCLR_bitoff5:
	case C166_BCLR_bitoff6:
	case C166_BCLR_bitoff7:
	case C166_BCLR_bitoff8:
	case C166_BCLR_bitoff9:
	case C166_BCLR_bitoff10:
	case C166_BCLR_bitoff11:
	case C166_BCLR_bitoff12:
	case C166_BCLR_bitoff13:
	case C166_BCLR_bitoff14:
	case C166_BCLR_bitoff15:
		return "bclr";
	case C166_BSET_bitoff0:
	case C166_BSET_bitoff1:
	case C166_BSET_bitoff2:
	case C166_BSET_bitoff3:
	case C166_BSET_bitoff4:
	case C166_BSET_bitoff5:
	case C166_BSET_bitoff6:
	case C166_BSET_bitoff7:
	case C166_BSET_bitoff8:
	case C166_BSET_bitoff9:
	case C166_BSET_bitoff10:
	case C166_BSET_bitoff11:
	case C166_BSET_bitoff12:
	case C166_BSET_bitoff13:
	case C166_BSET_bitoff14:
	case C166_BSET_bitoff15:
		return "bset";
	case C166_EXTP_or_EXTS_Rwm_irang2:
	case C166_EXTP_or_EXTS_pag10_or_seg8_irang2:
		return "extp(r)/exts(r)"; // Requires op
	case C166_NOP:
		return "nop";
	case C166_SRST:
		return "srst";
	case C166_IDLE:
		return "idle";
	case C166_PWRDN:
		return "pwrdn";
	case C166_SRVWDT:
		return "srvwdt";
	case C166_DISWDT:
		return "diswdt";
	case C166_ENWDT:
		return "enwdt";
	case C166_EINIT:
		return "einit";
	default:
		return "invalid";
	}
}

const char *c166_extx_names[] = {
	"exts",
	"extp",
	"extsr",
	"extpr"
};

RZ_API void c166_activate_ext(RZ_NONNULL C166State *state, ut32 addr, C166ExtState ext) {
	// rz_return_if_fail(state->ext.i == 0); // realy need?
	rz_return_if_fail(ext.i <= 3);
	state->ext = ext;
	state->last_addr = addr;
}

RZ_API void c166_maybe_deactivate_ext(RZ_NONNULL C166State *state, ut32 addr) {
	if (addr == state->last_addr) {
		return;
	}
	if (state->ext.i > 0) {
		state->ext.i -= 1;
	}
	if (state->ext.i == 0) {
		state->ext = (C166ExtState){
			.esfr = false,
			.mode = C166_EXT_MODE_NONE,
			.value = 0,
			.i = 0
		};
	}
	state->last_addr = addr;
}

/**
 * Format a mem value into buf. Does not apply to seg or pag formats.
 * Caller must provide a buf with at least 13 characters.
 */
static const char *c166_fmt_mem(const C166ExtState *ext, char *buf, ut16 mem) {
	const st32 i = (mem >> 14) & 0b11;
	switch (ext->mode) {
	case C166_EXT_MODE_NONE: {
		const ut16 addr = BASE_SFR_ADDR + (i * 2);
		snprintf(buf, 16, "0x%x:0x%04x", addr, mem & 0x3FFF);
		break;
	}
	case C166_EXT_MODE_SEG: {
		const ut32 seg = ((ut32)(ext->value & 0xFF)) << 16;
		snprintf(buf, 12, "0x%06x", seg | (mem & 0x3FFF));
		break;
	}
	case C166_EXT_MODE_PAGE: {
		const ut32 page = ((ut32)ext->value & 0x3FF) << 14;
		snprintf(buf, 11, "0x%08x", page | (mem & 0x3FFF));
		break;
	}
	}
	return buf;
}

/**
 * Return the reg interpretation in word or byte mode.
 * Caller must provide a buf with at least 10 characters.
 */
static const char *c166_fmt_reg(const C166ExtState *ext, char *buf, ut8 reg, bool byte) {
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		return byte ? c166_rb[L_NIB(reg)] : c166_rw[L_NIB(reg)];
	}
	const ut16 base_addr = ext->esfr ? BASE_ESFR_ADDR : BASE_SFR_ADDR;
	const ut16 addr = base_addr + (2 * reg);
	return print_hex_word(buf, addr);
}

/**
 * Format a bitoff value into buf.
 * Caller must provide a buf with at least 12 characters.
 */
static const char *c166_fmt_bitoff(const C166ExtState *ext, char *buf, ut8 bitoff) {
	if (IS_GPR(bitoff)) {
		return c166_rw[L_NIB(bitoff)];
	}
	if (IS_RAM(bitoff)) {
		return print_hex_word(buf, BASE_RAM_B_ADDR + (2 * bitoff));
	}
	if (IS_bSFR(bitoff)) {
		const ut16 base_addr = ext->esfr ? BASE_ESFR_B_ADDR : BASE_SFR_B_ADDR;
		const ut16 addr = base_addr + (2 * (bitoff & 0x7F));
		return print_hex_word(buf, addr);
	}
	rz_warn_if_reached();
	return NULL;
}

static ut8 c166_instr_rw_rw(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	OPERANDS("r%i, r%i", H_NIB(reg), L_NIB(reg));
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_rw_x(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	const ut8 op = L_NIB(reg);
	if ((op & 0b1100) == 0b1100) {
		OPERANDS("r%i, [r%i+]", H_NIB(reg), op & 0b11); // [Rw+]
	} else if ((op & 0b1000) == 0b1000) {
		OPERANDS("r%i, [r%i]", H_NIB(reg), op & 0b11); // [Rw]
	} else {
		OPERANDS("r%i, #%i", H_NIB(reg), op); // #data3
	}
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_rb_rb(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	OPERANDS(FMT9, c166_rb[H_NIB(reg)], c166_rb[L_NIB(reg)]);
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_mov_mem_oRw(C166_Inst *instr) {
	const ut8 op = get_operand(instr, 1);
	const ut16 mem = rz_read_at_le16(&instr->d, 2);
	const ut8 n = L_NIB(op);

	bool swap = false;
	switch (instr->id) {
	case C166_MOV_oRwn_mem:
	case C166_MOVB_oRwn_mem:
		swap = true;
		break;
	default: break;
	}

	if (swap) {
		OPERANDS(FMT2, c166_rw[n], c166_fmt_mem(&instr->ext, SBUF_16, mem));
	} else {
		OPERANDS(FMT0, c166_fmt_mem(&instr->ext, SBUF_16, mem), c166_rw[n]);
	}
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_mov_nm_data(C166_Inst *instr) {
	const ut8 op = get_operand(instr, 1);
	const ut16 mem = rz_read_at_le16(&instr->d, 2);

	const ut8 n = H_NIB(op);
	const ut8 m = L_NIB(op);

	bool swap = false;
	bool rb = false;

	switch (instr->id) {
	case C166_MOV_Rwn_oRwm_data16:
		break;
	case C166_MOV_oRwm_data16_Rwn:
		swap = true;
		break;
	case C166_MOVB_Rbn_oRwm_data16:
		rb = true;
		break;
	case C166_MOVB_oRwm_data16_Rbn:
		swap = true;
		rb = true;
		break;
	default: break;
	}

	if (swap) {
		OPERANDS("[%s+#0x%04x], %s", c166_rw[m], mem, rb ? c166_rb[n] : c166_rw[n]);
	} else {
		OPERANDS("%s, [%s+#0x%04x]", rb ? c166_rb[n] : c166_rw[n], c166_rw[m], mem);
	}
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_mov_nm(C166_Inst *instr) {
	bool swap = false;
	bool rb = false;
	const char *format = NULL;

	ut8 op = get_operand(instr, 1);

	const ut8 n = H_NIB(op);
	const ut8 m = L_NIB(op);

	// clang-format off
	switch (instr->id) {
	case C166_MOV_Rwn_oRwm: ///< 0xA8              Rwn, [Rwm]
		format = FMT0;
		break;
	case C166_MOVB_Rbn_oRwm: ///< 0xA9             Rbn, [Rwm]
		rb = true;
		format = FMT0;
		break;
	case C166_MOV_Rwn_oRwmp: ///< 0x98             Rwn, [Rwm+]
		format = FMT1;
		break;
	case C166_MOVB_Rbn_oRwmp: ///< 0x99            Rbn, [Rwm+]
		rb = true;
		format = FMT1;
		break;
	case C166_MOV_oRwm_Rwn: ///< 0xB8              [Rwm], Rwn
		format = FMT2;
		swap = true;
		break;
	case C166_MOVB_oRwm_Rbn: ///< 0xB9             [Rwm], Rbn
		rb = true;
		swap = true;
		format = FMT2;
		break;
	case C166_MOV_noRwm_Rwn: ///< 0x88             [-Rwm], Rwn
		format = FMT3;
		swap = true;
		break;
	case C166_MOVB_noRwm_Rbn: ///< 0x89            [-Rwm], Rbn
		rb = true;
		swap = true;
		format = FMT3;
		break;
	case C166_MOV_oRwn_oRwm: ///< 0xC8             [Rwn], [Rwm]
	case C166_MOVB_oRwn_oRwm: ///< 0xC9            [Rwn], [Rwm]
		format = FMT4;
		break;
	case C166_MOV_oRwnp_oRwm: ///< 0xD8            [Rwn+], [Rwm]
	case C166_MOVB_oRwnp_oRwm: ///< 0xD9           [Rwn+], [Rwm]
		format = FMT5;
		break;
	case C166_MOV_oRwn_oRwmp: ///< 0xE8            [Rwn], [Rwm+]
	case C166_MOVB_oRwn_oRwmp: ///< 0xE9           [Rwn], [Rwm+]
		format = FMT6;
		break;
	default: break;
	}
	// clang-format on
	if (swap) {
		OPERANDS(format, c166_rw[m], rb ? c166_rb[n] : c166_rw[n]);
	} else {
		OPERANDS(format, rb ? c166_rb[n] : c166_rw[n], c166_rw[m]);
	}
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_jmp_rel(C166_Inst *instr) {
	const ut8 c = H_NIB(instr->id);
	const ut8 rr = get_operand(instr, 1);
	OPERANDS("%s, 0x%06x",
		conds(c),
		instr->addr + C166_BYTESIZE_2 + (2 * ((st8)rr)));
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_rw_data4(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	OPERANDS("r%i, #0x%02x", L_NIB(reg), H_NIB(reg));
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_cc_indirect(C166_Inst *instr) {
	const ut8 op = get_operand(instr, 1);
	const ut8 c = H_NIB(op);
	OPERANDS("%s, [r%i]", conds(c), L_NIB(op));
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_rb_data4(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	OPERANDS(FMT8, c166_rb[L_NIB(reg)], H_NIB(reg));
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_rb_x(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	const ut8 op = L_NIB(reg);
	const char *r = c166_rb[H_NIB(reg)];

	if ((op & 0b1100) == 0b1100) {
		///< [Rb+]
		OPERANDS(FMT1, r, c166_rb[op & 0b11]);
	} else if ((op & 0b1000) == 0b1000) {
		///< [Rb]
		OPERANDS(FMT0, r, c166_rb[op & 0b11]);
	} else {
		///< #data3
		OPERANDS(FMT8, r, op);
	}
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_rw_rb(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	///< NOTE: It is D0 mn , NOT nm, but displayed as Rwn, Rbm
	OPERANDS(FMT9, c166_rw[L_NIB(reg)], c166_rb[H_NIB(reg)]);
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_rw(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	const ut8 n = H_NIB(reg);
	switch (instr->id) {
	case C166_NEG_Rwn:
	case C166_CPL_Rwn:
		if ((L_NIB(reg)) != 0) {
			return 0;
		}
		break;
	case C166_DIV_Rwn:
	case C166_DIVL_Rwn:
	case C166_DIVLU_Rwn:
	case C166_DIVU_Rwn:
		if ((L_NIB(reg)) != n) {
			return 0;
		}
		break;
	default:
		rz_warn_if_reached();
		return 0;
	}
	OPERANDS("r%i", n);
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_rb(C166_Inst *instr) {
	const ut8 op1 = get_operand(instr, 1);
	OPERANDS("%s", c166_rb[H_NIB(op1)]);
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_reg_mem(C166_Inst *instr, bool byte) {
	const ut8 reg = get_operand(instr, 1);
	const ut16 mem = rz_read_at_le16(&instr->d, 2);
	OPERANDS(FMT9,
		c166_fmt_reg(&instr->ext, SBUF_16, reg, byte),
		c166_fmt_mem(&instr->ext, SBUF_16, mem));
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_mem_reg(C166_Inst *instr, bool byte) {
	///< f6 8e fcf0  F6 RR MM MM
	const ut8 reg = get_operand(instr, 1);
	const ut16 mem = rz_read_at_le16(&instr->d, 2);
	OPERANDS(FMT9,
		c166_fmt_mem(&instr->ext, SBUF_16, mem),
		c166_fmt_reg(&instr->ext, SBUF_16, reg, byte));
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_bitoff(C166_Inst *instr) {
	const ut8 bit = H_NIB(instr->id);
	OPERANDS("%s.%i",
		c166_fmt_bitoff(&instr->ext, SBUF_16, get_operand(instr, 1)), bit);
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_reg(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	OPERANDS("%s",
		c166_fmt_reg(&instr->ext, SBUF_16, reg, false));
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_reg_data16(C166_Inst *instr, bool byte) {
	const ut8 reg = get_operand(instr, 1);
	const ut16 data = rz_read_at_le16(&instr->d, 2);
	OPERANDS("%s, #0x%04x",
		c166_fmt_reg(&instr->ext, SBUF_16, reg, byte), data);
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_reg_data8(C166_Inst *instr, bool byte) {
	const ut8 reg = get_operand(instr, 1);
	const ut8 data = rz_read_at_le16(&instr->d, 2);

	/**
	 * 8-bit immediate constant
	 * (represented by #data8, where byte xx is not significant)
	 * rz_read_at_le16 swaps so use lower
	 */
	OPERANDS(FMT8,
		c166_fmt_reg(&instr->ext, SBUF_16, reg, byte), data & 0xFF);
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_seg_caddr(C166_Inst *instr) {
	const ut8 seg = get_operand(instr, 1);
	const ut16 caddr = rz_read_at_le16(&instr->d, 2);
	OPERANDS("0x%06x", (((ut32)seg) << 16) | caddr);
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_cc_caddr(C166_Inst *instr) {
	const ut8 op = get_operand(instr, 1);

	const ut32 segment = instr->addr & 0xFF0000;
	const ut32 addr = segment | rz_read_at_le16(&instr->d, 2);

	/**
	 * CALLA xcc, caddr  | CA d00a MM MM | 4
	 * JMPA  xcc, caddr  | CA d00a MM MM | 4
	 * d : 5-bit condition code specification (xcc)
	 * a : 1-bit branch assumption bit
	 */
	const ut8 d = op >> 3;
	const ut8 a = op & 0x1;
	INSTR("%s%s",
		(instr->id == C166_CALLA_cc_caddr) ? "calla" : "jmpa",
		a ? "-" : "+");
	OPERANDS("%s, 0x%04x", conds_extended(d), addr);
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_bitaddr_rel(C166_Inst *instr) {
	const ut8 qq = get_operand(instr, 1);
	const ut8 rr = get_operand(instr, 2);
	const ut8 op3 = get_operand(instr, 3);
	const ut8 q = H_NIB(op3);
	OPERANDS("%s.%i, 0x%06x",
		c166_fmt_bitoff(&instr->ext, SBUF_16, qq), q,
		instr->addr + C166_BYTESIZE_4 + (2 * ((st8)rr)));
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_reg_caddr(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	const ut16 caddr = rz_read_at_le16(&instr->d, 2);
	OPERANDS("%s, 0x%04x",
		c166_fmt_reg(&instr->ext, SBUF_16, reg, false), caddr);
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_rw_data16(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	const ut16 data = rz_read_at_le16(&instr->d, 2);
	OPERANDS("r%i, #0x%04x", L_NIB(reg), data);
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_rw_mem(C166_Inst *instr) {
	const ut8 reg = get_operand(instr, 1);
	const ut16 data = rz_read_at_le16(&instr->d, 2);
	OPERANDS("r%i, %s", L_NIB(reg),
		c166_fmt_mem(&instr->ext, SBUF_16, data));
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_bitaddr_bitaddr(C166_Inst *instr) {
	const ut8 qq = get_operand(instr, 1);
	const ut8 zz = get_operand(instr, 2);
	const ut8 qz = get_operand(instr, 3);

	const ut8 q = H_NIB(qz);
	const ut8 z = L_NIB(qz);
	OPERANDS("%s.%i, %s.%i",
		c166_fmt_bitoff(&instr->ext, SBUF_16, qq), q,
		c166_fmt_bitoff(&instr->ext, SBUF_16, zz), z);
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_bfld(C166_Inst *instr) {
	const ut8 bitoff = get_operand(instr, 1); // bitoffQ QQ
	const ut8 opt1 = get_operand(instr, 2); // #mask8  ##
	const ut8 opt2 = get_operand(instr, 3); // #data8  @@
	if (instr->id == C166_BFLDH_bitoff_x) {
		OPERANDS("%s, #0x%02x, #0x%02x", c166_fmt_bitoff(&instr->ext, SBUF_16, bitoff), opt2, opt1);
	} else {
		OPERANDS("%s, #0x%02x, #0x%02x", c166_fmt_bitoff(&instr->ext, SBUF_16, bitoff), opt1, opt2);
	}
	return C166_BYTESIZE_4;
}

static ut8 c166_instr_call_rel(C166_Inst *instr) {
	const ut8 rr = get_operand(instr, 1);
	OPERANDS("0x%04x", instr->addr + C166_BYTESIZE_2 + (2 * ((st8)rr)));
	return C166_BYTESIZE_2;
}

/**
 * Modes ATOMIC #irang2 D1 :00##-0 2
 * Modes EXTR   #irang2 D1 :10##-0 2
 */
static ut8 c166_instr_irang2(C166State *state, C166_Inst *instr) {
	const ut8 op = get_operand(instr, 1);
	const ut8 sub_op = (op >> 6) & 0b11;
	const ut8 irang2 = ((op >> 4) & 0b0011) + 1;

	if (sub_op == 0b00) {
		INSTR("%s", "atomic");
	} else if (sub_op == 0b10) {
		const C166ExtState ex = (C166ExtState){
			.esfr = true,
			.mode = C166_EXT_MODE_NONE,
			.value = (op & 3),
			.i = 0
		};
		c166_activate_ext(state, instr->addr, ex);
		INSTR("%s", "extr");
	} else
		INSTR("%s", "invalid");
	OPERANDS("#%x", irang2);
	return C166_BYTESIZE_2;
}

///< This modifies the ext state
static ut8 c166_instr_rw_irang2(C166State *state, C166_Inst *instr) {
	const ut8 op = get_operand(instr, 1);

	INSTR("%s", c166_extx_names[(op >> 6) & 0b11]);
	const ut8 m = L_NIB(op);
	const ut8 irang2 = ((op >> 4) & 0b0011) + 1;
	const C166ExtState ex = (C166ExtState){
		.esfr = true,
		.mode = C166_EXT_MODE_NONE,
		.value = 0,
		.i = irang2
	};
	c166_activate_ext(state, instr->addr, ex);
	OPERANDS(FMT10, c166_rw[m], irang2);
	return C166_BYTESIZE_2;
}

static ut8 c166_instr_seg_or_pag_irang2(C166State *state, C166_Inst *instr, ut16 data) {
	const ut8 op = get_operand(instr, 1);
	const ut8 sub_op = (op >> 6) & 0b11;

	INSTR("%s", c166_extx_names[sub_op]);

	bool seg = (sub_op == 0b00) || (sub_op == 0b10);

	const ut8 irang2 = ((op >> 4) & 0b0011) + 1;
	const bool esfr = (op >> 7) & 1;

	C166ExtState new_state = {
		.esfr = esfr,
		.mode = seg ? C166_EXT_MODE_SEG : C166_EXT_MODE_PAGE,
		.i = irang2,
		.value = 0
	};

	if (seg) {
		new_state.value = data & 0xFF;
		OPERANDS("#0x%04x, #%i", data & 0xFF, irang2);
	} else {
		new_state.value = data & 0x3FF;
		OPERANDS("#0x%04x, #%i", data & 0x3FF, irang2);
	}

	c166_activate_ext(state, instr->addr, new_state);
	return 4;
}

static ut8 c166_trap_instr(C166_Inst *instr) {
	ut8 trap7 = get_operand(instr, 1);
	const ut16 addr = 4 * (trap7 & 0x7F);
	INSTR("%s", "trap");
	OPERANDS("#0x%04x", addr);
	return 2;
}

/**
 * A3 nm CA rrr0:0000
 * 83 nm CA rrr0:0qqq
 * 93 Xm CA rrr0:0qqq
 *
 * DSP Instruction Set
 */
static const char *c166_instr_extended_name(C166_Inst *instr) {
	const ut8 opcode = instr->id;
	const ut8 extID = get_operand(instr, 2);

	if (opcode == 0xD3) {
		return extID == 0x00 ? "CoMOV" : "invalid";
	}

	if ((opcode == 0xB3) || (opcode == 0xC3)) {
		return "CoSTORE";
	}

	if ((opcode == 0xA3) && (extID == 0x8A)) {
		return "CoSHL";
	}

	if ((opcode == 0x83) && (extID == 0x8A)) {
		return "CoSHL";
	}

	if ((opcode == 0xA3) && (extID == 0x82)) {
		return "CoSHL";
	}

	if ((opcode == 0xA3) && (extID == 0xAA)) {
		return "CoASHR";
	}

	if ((opcode == 0xA3) && (extID == 0xA2)) {
		return "CoASHR";
	}

	if ((opcode == 0xA3) && (extID == 0xB2)) {
		///< or CoRND, is a shortname for CoASHR #0, rnd
		return "CoASHR";
	}

	if ((opcode == 0xA3) && (extID == 0xBA)) {
		return "CoASHR";
	}

	if ((opcode == 0x83) && (extID == 0xAA)) {
		return "CoASHR";
	}

	if ((opcode == 0x83) && (extID == 0xBA)) {
		return "CoASHR";
	}

	if ((opcode == 0xA3) && (extID == 0x9A)) {
		return "CoSHR";
	}

	if ((opcode == 0x83) && (extID == 0x9A)) {
		return "CoSHR";
	}

	if ((opcode == 0xA3) && (extID == 0x92)) {
		return "CoSHR";
	}

	if ((opcode == 0xA3) && (extID == 0x1A)) {
		return "CoABS";
	}

	if ((opcode == 0xA3) && (extID == 0x32)) {
		return "CoNEG";
	}

	if ((opcode == 0xA3) && (extID == 0x72)) {
		return "CoNEG";
	}

	if ((opcode == 0x83) && (extID == 0x9A)) {
		return "CoSHR";
	}

	if ((opcode == 0x93) && (extID == 0x5A)) {
		return "CoNOP";
	}

	if ((opcode == 0x93) && (extID == 0xE8)) {
		return "CoMACM-";
	}

	if (opcode == 0x93) {
		if ((extID == 0x18) || (extID == 0x19)) {
			return "CoMACMu";
		}

		if ((extID == 0x38) || (extID == 0x39)) {
			return "CoMACMRu";
		}

		if ((extID == 0x58) || (extID == 0x59)) {
			return "CoMACMsu";
		}

		if ((extID == 0x78) || (extID == 0x79)) {
			return "CoMACMRsu";
		}

		if ((extID == 0x98) || (extID == 0x99)) {
			return "CoMACMus";
		}

		if ((extID == 0xB8) || (extID == 0xB9)) {
			return "CoMACMRus";
		}

		if ((extID == 0xD8) || (extID == 0xD9)) {
			return "CoMACM";
		}

		if ((extID == 0xF8) || (extID == 0xF9)) {
			return "CoMACMR";
		}

		if (extID == 0xA8) {
			return "CoMACMus-";
		}

		if (extID == 0x28) {
			return "CoMACMu-";
		}

		if (extID == 0x68) {
			return "CoMACMsu-";
		}
	}
	if ((opcode == 0x83) || (opcode == 0x93) || (opcode == 0xA3)) {
		if ((extID == 0x00) || (extID == 0x01)) {
			return "CoMULu";
		}

		if ((extID == 0x80) || (extID == 0x81)) {
			return "CoMULus";
		}

		if (extID == 0x08) {
			return "CoMULu-";
		}

		if (extID == 0x88) {
			return "CoMULus-";
		}

		if (extID == 0x60) {
			return "CoMACsu-";
		}

		if ((extID == 0x70) || (extID == 0x71)) {
			return "CoMACRsu";
		}

		if ((extID == 0xB0) || (extID == 0xB1)) {
			return "CoMACRus";
		}

		if (extID == 0xA0) {
			return "CoMACus-";
		}

		if ((extID == 0x90) || (extID == 0x91)) {
			return "CoMACus";
		}

		if ((extID == 0x30) || (extID == 0x31)) {
			return "CoMACRu";
		}

		if ((extID == 0x10) || (extID == 0x11)) {
			return "CoMACu";
		}

		if (extID == 0x20) {
			return "CoMACu-";
		}

		if ((extID == 0x40) || (extID == 0x41)) {
			return "CoMULsu";
		}

		if ((extID == 0x50) || (extID == 0x51)) {
			return "CoMACsu";
		}

		if ((extID == 0xC0) || (extID == 0xC1)) {
			return "CoMUL";
		}

		if ((extID == 0xD0) || (extID == 0xD1)) {
			return "CoMAC";
		}

		if (extID == 0xE0) {
			return "CoMAC-";
		}

		if ((extID == 0xF0) || (extID == 0xF1)) {
			return "CoMACR";
		}

		if (extID == 0x02) {
			return "CoADD";
		}

		if (extID == 0x12) {
			return "CoSUBR";
		}

		if (extID == 0x22) {
			return "CoLOAD";
		}

		if (extID == 0x42) {
			return "CoADD2";
		}

		if (extID == 0x52) {
			return "CoSUB2R";
		}

		if (extID == 0x62) {
			return "CoLOAD2";
		}

		if (extID == 0xC2) {
			return "CoCMP";
		}

		if (extID == 0x0A) {
			return "CoSUB";
		}

		if (extID == 0x2A) {
			return "CoLOAD-";
		}

		if (extID == 0x3A) {
			return "CoMAX";
		}

		if (extID == 0x4A) {
			return "CoSUB2";
		}

		if (extID == 0x6A) {
			return "CoLOAD2-";
		}

		if (extID == 0x7A) {
			return "CoMIN";
		}

		if (extID == 0xCA) {
			return "CoABS";
		}

		if (extID == 0x48) {
			return "CoMULsu-";
		}

		if (extID == 0xC8) {
			return "CoMUL-";
		}
	}
	RZ_LOG_INFO("Unknown extID 0x%02x [0x%02x].\n", opcode, extID);
	return "invalid";
}

static const char *CoREG(ut8 bits) {
	switch (bits) {
	case 0b00000: {
		///< MAC-Unit Status Word
		return "0xffde";
	}
	case 0b00001: {
		///< MAC-Unit Accumulator High Word
		return "0xfe5e";
	}
	case 0b00010: {
		///< Limited MAC-Unit Accumulator High Word
		return "MAS";
	}
	case 0b00100: {
		///< MAC-Unit Accumulator Low Word
		return "0xfe5c";
	}
	case 0b00101: {
		///< MAC-Unit Control Word
		return "0xffdc";
	}
	case 0b00110: {
		///< MAC-Unit Repeat Word
		return "0xffda";
	}
	default:
		RZ_LOG_INFO("Unknown bits: 0x%02x.\n", bits);
		return NULL;
	}
}

static const char *idx_formatter(char *buf, ut8 nm) {
	const ut8 idx = (nm >> 7);
	const ut16 addr = (idx ? IDX1 : IDX0);
	const ut8 idx_op = (nm >> 4) & 0x7;

	const char *format = NULL;

	switch (idx_op) {
	case 0b010: { ///< IDX +2
		format = "[0x%04x +2]";
		break;
	}
	case 0b011: { ///< IDX -2
		format = "[0x%04x -2]";
		break;
	}
	case 0b100: { ///< IDX + QX0
		format = "[0x%04x + QX0]";
		break;
	}
	case 0b101: { ///< IDX - QX0
		format = "[0x%04x - QX0]";
		break;
	}
	case 0b110: { ///< IDX + QX1
		format = "[0x%04x + QX1]";
		break;
	}
	case 0b111: { ///< IDX - QX1
		format = "[0x%04x - QX1]";
		break;
	}
	case 0b000: ///< RESERVED
	case 0b001: ///< no-operation
	default:
		format = "[0x%04x]";
		break;
	}
	snprintf(buf, C166_INSTR_MAXLEN, format, addr);
	return buf;
}

static const char *qqq_formatter(char *buf, ut8 op, ut8 n) {
	ut8 q = op & 0x7;
	const char *format = NULL;
	switch (q) {
	case 0b010: { ///< Rw +2
		format = "[r%i +2]";
		break;
	}
	case 0b011: { ///< Rw -2
		format = "[r%i -2]";
		break;
	}
	case 0b100: { ///< Rw + QR0
		format = "[r%i + QR0]";
		break;
	}
	case 0b101: { ///< Rw - QR0
		format = "[r%i - QR0]";
		break;
	}
	case 0b110: { ///< Rw + QR1
		format = "[r%i + QR1]";
		break;
	}
	case 0b111: { ///< Rw - QR1
		format = "[r%i - QR1]";
		break;
	}
	case 0b000: ///< RESERVED
	case 0b001: ///< no-operation
	default:
		format = "[r%i]";
		break;
	}
	snprintf(buf, C166_INSTR_MAXLEN, format, n);
	return buf;
}

static const char *repeat_control(ut8 opt) {
	ut8 rrr = opt >> 5;
	switch (rrr) {
	case 0b010: { // 0x40
		return "- USR0 "; ///< ‘- USR0 CoXXX’ instruction, decrements repeat counter.
	}
	case 0b011: { // 0x60
		return "- USR1 "; ///< ‘- USR1 CoXXX’ instruction, decrements repeat counter.
	}
	default:
		///< 0b000: regular CoXXX instruction
		///< 0b001: RESERVED
		///< 0b1xx: RESERVED
		return NULL;
	}
}

static ut8 c166_instr_extended(C166_Inst *instr) {
	const ut8 nm = get_operand(instr, 1);
	const ut8 n = H_NIB(nm);
	const ut8 m = L_NIB(nm);
	const ut8 extID = get_operand(instr, 2);
	const ut8 opt2 = get_operand(instr, 3); ///< rrr0:0000 : 3-bit repeat control for CoXXX instructions
	///< wwww:w : 5-bit word address CoREG

	///< qqq : 3-bit addressing mode specifier for CoXXX instructions
	///< ut8 rrr = opt2 >> 5;
	const char *rrr = repeat_control(opt2);
	const ut8 opcode = instr->id;

	const char *instruction_name = c166_instr_extended_name(instr);
	if (RZ_STR_EQ(instruction_name, "invalid")) {
		goto err;
	}

	INSTR("%s%s", rrr ? rrr : "", instruction_name); ///< `- USRx` repeat control label

	if (opcode == 0xD3) {
		///< CoMOV [IDXi*], [Rwm*]
		///< D3 Xm 00 rrr0:0qqq
		OPERANDS("%s, %s",
			idx_formatter(SBUF_16, nm), // or maybe extID
			qqq_formatter(SBUF_16, opt2, m));
		goto end;
	}

	if (opcode == 0xB3) {
		///< CoSTORE [Rwn*], CoReg
		///< B3 nn wwww:w000 rrr0:0qqq
		const ut8 wwwww = (extID >> 3);
		OPERANDS("[r%i], %s", n, CoREG(wwwww));
		goto end;
	}

	if (opcode == 0xC3) {
		///< CoSTORE Rwn, CoReg
		///< C3 nn wwww:w000 rrr0:0000
		const ut8 wwwww = (extID >> 3);
		OPERANDS("r%i, %s", n, CoREG(wwwww)); // CoSTORE RWn, CoReg
		goto end;
	}

	if ((opcode == 0x83) && (extID == 0xAA)) {
		OPERANDS("[r%i]", m); // CoASHR [RWm*]
		goto end;
	} else if ((opcode == 0x83) && (extID == 0xBA)) {
		///< CoASHR [Rwm*], rnd
		///< 83 mm BA rrr0:0qqq
		OPERANDS("[r%i], rnd", m); // CoASHR [RWm*], rnd
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0xAA)) {
		OPERANDS("r%i", n); // CoASHR RWn
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0xBA)) {
		///< CoASHR Rwn, rnd
		///< A3 nn BA rrr0:0000
		OPERANDS("r%i, rnd", n); // CoASHR RWn, rnd
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0xA2)) {
		OPERANDS("#data5"); // CoXXX #data5
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0x92)) {
		OPERANDS("#data5"); // CoXXX #data5
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0x82)) {
		OPERANDS("#data5"); // CoXXX #data5
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0xA2)) {
		OPERANDS("#data5"); // CoXXX #data5
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0xB2)) {
		///< CoASHR #data5, rnd
		///< A3 00 B2 rrr#:#
		OPERANDS("#data5, rnd"); // CoXXX #data5, rnd
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0x72)) {
		OPERANDS("rnd"); // CoXXX rnd
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0x1A)) {
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0x32)) {
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0xB2)) {
		goto end;
	} else if ((opcode == 0x83) && (extID == 0x8A)) {
		OPERANDS("[r%i]", m); // ????? CoSHL [RWm*]
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0x8A)) {
		OPERANDS("r%i", n);
		goto end;
	} else if ((opcode == 0x83) && (extID == 0x9A)) {
		OPERANDS("[r%i]", m); // ????? CoSHR [RWm*]
		goto end;
	} else if ((opcode == 0xA3) && (extID == 0x9A)) {
		OPERANDS("r%i", n); // CoSHR RWn
		goto end;
	} else if ((opcode == 0x93) && (L_NIB(extID) == 0x00)) {
		// CoXXX_oIDXi_oRWm();
		OPERANDS("%s, [r%i]",
			idx_formatter(SBUF_16, nm), m); // CoXXX [IDXi*], [RWm*]
		goto end;
	} else if ((opcode == 0x93) && (L_NIB(extID) == 0x02)) {
		// CoXXX_RWn_oRWm();
		OPERANDS("%s, [r%i]",
			idx_formatter(SBUF_16, nm), m); // CoXXX [IDXi*], [RWm*]
		goto end;
	} else if ((opcode == 0x93) && (L_NIB(extID) == 0x0A)) {
		// CoXXX_RWn_oRWm();
		OPERANDS("%s, [r%i]",
			idx_formatter(SBUF_16, nm), m); // CoXXX [IDXi*], [RWm*]
		goto end;
	} else if ((opcode == 0x93) && (L_NIB(extID) == 0x08)) {
		// CoXXX_RWn_oRWm();
		OPERANDS("%s, [r%i]",
			idx_formatter(SBUF_16, nm), m); // CoXXX [IDXi*], [RWm*]
		goto end;
	} else if ((opcode == 0x93) && (L_NIB(extID) == 0x09)) {
		// CoXXX_RWn_oRWm();
		OPERANDS("%s, [r%i], rnd",
			idx_formatter(SBUF_16, nm), m); // CoXXX [IDXi*], [RWm*], rnd
		goto end;
	} else if ((opcode == 0x93) && (L_NIB(extID) == 0x01)) {
		// CoXXX_RWn_oRWm();
		OPERANDS("%s, [r%i], rnd",
			idx_formatter(SBUF_16, nm), m); // CoXXX [IDXi*], [RWm*], rnd
		goto end;
	} else if ((opcode == 0x83) && (L_NIB(extID) == 0x00)) {
		// CoXXX_RWn_oRWm();
		OPERANDS("r%i, [r%i]", n, m); // CoXXX RWn, [RWm*]
		goto end;
	} else if ((opcode == 0x83) && (L_NIB(extID) == 0x02)) {
		// CoXXX_RWn_oRWm();
		OPERANDS("r%i, [r%i]", n, m); // CoXXX RWn, [RWm*]
		goto end;
	} else if ((opcode == 0x83) && (L_NIB(extID) == 0x0A)) {
		// CoXXX_RWn_oRWm();
		OPERANDS("r%i, [r%i]", n, m); // CoXXX RWn, [RWm*]
		goto end;
	} else if ((opcode == 0x83) && (L_NIB(extID) == 0x01)) {
		// CoMULu_RWn_oRWm_rnd();
		OPERANDS("r%i, [r%i], rnd", n, m); // CoXXX RWn, [RWm*], rnd
		goto end;
	} else if (opcode == 0x83) {
		// CoMULu_RWn_oRWm();
		if ((extID == 0x08) ||
			(extID == 0x48) ||
			(extID == 0x88) ||
			(extID == 0xC8)) {
			OPERANDS("r%i, [r%i]", n, m); // CoXXX RWn, [RWm*]
			goto end;
		}
	} else if ((opcode == 0xA3) && (L_NIB(extID) == 0x01)) {
		// CoXXX_RWn_RWm_rnd();
		OPERANDS("r%i, r%i, rnd", n, m); // CoXXX RWn, [RWm*], rnd
		goto end;
	} else if ((opcode == 0xA3) && (L_NIB(extID) == 0x00)) {
		// CoXXX_RWn_RWm();
		OPERANDS("r%i, r%i", n, m); // CoXXX RWn, RWm
		goto end;
	} else if ((opcode == 0xA3) && (L_NIB(extID) == 0x02)) {
		// CoXXX_RWn_RWm();
		OPERANDS("r%i, r%i", n, m); // CoXXX RWn, RWm
		goto end;
	} else if ((opcode == 0xA3) && (L_NIB(extID) == 0x0A)) {
		// CoXXX_RWn_RWm();
		OPERANDS("r%i, r%i", n, m); // CoXXX RWn, RWm
		goto end;
	} else if (opcode == 0xA3) {
		// CoXXX_RWn_RWm();
		if ((extID == 0x08) || (extID == 0x48) ||
			(extID == 0x88) || (extID == 0xC8)) {
			OPERANDS("r%i, r%i", n, m); // CoXXX RWn, RWm
			goto end;
		}
	}
err:
	INSTR(".word 0x%02x%02x .word 0x%02x%02x", instr->id, nm, extID, opt2);
	memset(&instr->operands, 0, C166_INSTR_MAXLEN);
end:
	return C166_BYTESIZE_4;
}

/**
 * Disassemble C166 instruction
 *
 * \param state Pointer to state structure
 * \param instr Pointer to instruction structure
 * \param bytes Buffer containing instruction bytes
 * \param len Length of buffer
 * \return Instruction byte size, 2 or 4 or -1 on error
 */
RZ_IPI st32 c166_decode_command(RZ_NONNULL C166State *state, RZ_NONNULL C166_Inst *instr, RZ_NONNULL const ut8 *bytes, st32 len) {
	rz_return_val_if_fail(state && instr && bytes, -1);
	if (len < 2)
		return -1;

	RzBuffer *b = rz_buf_new_with_pointers(bytes, len, false);
	if (!b) {
		return -1;
	}

	if (!rz_buf_read(b, (ut8 *)&instr->d, RZ_MIN(8, len))) {
		goto err;
	}
	const ut8 opcode = rz_read_le8(&instr->d);
	instr->id = opcode;
	instr->ext = state->ext; // Copy state
	c166_maybe_deactivate_ext(state, instr->addr);

	switch (opcode) {
	case C166_ADD_Rwn_Rwm:
	case C166_ADDC_Rwn_Rwm:
	case C166_SUB_Rwn_Rwm:
	case C166_SUBC_Rwn_Rwm:
	case C166_MUL_Rwn_Rwm:
	case C166_MULU_Rwn_Rwm:
	case C166_AND_Rwn_Rwm:
	case C166_OR_Rwn_Rwm:
	case C166_XOR_Rwn_Rwm:
	case C166_PRIOR_Rwn_Rwm:
	case C166_CMP_Rwn_Rwm:
	case C166_SHL_Rwn_Rwm:
	case C166_SHR_Rwn_Rwm:
	case C166_ROL_Rwn_Rwm:
	case C166_ROR_Rwn_Rwm:
	case C166_ASHR_Rwn_Rwm:
	case C166_MOV_Rwn_Rwm:
		instr->byte_size = c166_instr_rw_rw(instr);
		break;
	case C166_ADDB_Rbn_Rbm:
	case C166_ADDCB_Rbn_Rbm:
	case C166_SUBB_Rbn_Rbm:
	case C166_SUBCB_Rbn_Rbm:
	case C166_ANDB_Rbn_Rbm:
	case C166_ORB_Rbn_Rbm:
	case C166_XORB_Rbn_Rbm:
	case C166_CMPB_Rbn_Rbm:
	case C166_MOVB_Rbn_Rbm:
		instr->byte_size = c166_instr_rb_rb(instr);
		break;
	case C166_ADD_Rwn_x:
	case C166_ADDC_Rwn_x:
	case C166_SUB_Rwn_x:
	case C166_SUBC_Rwn_x:
	case C166_CMP_Rwn_x:
	case C166_AND_Rwn_x:
	case C166_OR_Rwn_x:
	case C166_XOR_Rwn_x:
		instr->byte_size = c166_instr_rw_x(instr);
		break;
	case C166_ROL_Rwn_data4:
	case C166_ROR_Rwn_data4:
	case C166_SHL_Rwn_data4:
	case C166_SHR_Rwn_data4:
	case C166_CMPI1_Rwn_data4:
	case C166_CMPI2_Rwn_data4:
	case C166_CMPD1_Rwn_data4:
	case C166_CMPD2_Rwn_data4:
	case C166_ASHR_Rwn_data4:
	case C166_MOV_Rwn_data4:
		instr->byte_size = c166_instr_rw_data4(instr);
		break;
	case C166_MOVB_Rbn_data4:
		instr->byte_size = c166_instr_rb_data4(instr);
		break;
	case C166_ADDB_Rbn_x:
	case C166_ADDCB_Rbn_x:
	case C166_SUBB_Rbn_x:
	case C166_SUBCB_Rbn_x:
	case C166_CMPB_Rbn_x:
	case C166_ANDB_Rbn_x:
	case C166_ORB_Rbn_x:
	case C166_XORB_Rbn_x:
		instr->byte_size = c166_instr_rb_x(instr);
		break;
	case C166_DIV_Rwn: // 4B nn 2
	case C166_DIVL_Rwn: // 6B nn 2
	case C166_DIVLU_Rwn: // 7B nn 2
	case C166_DIVU_Rwn: // 5B nn 2
	case C166_NEG_Rwn: // 81 n0 2
	case C166_CPL_Rwn: // 91 n0 2
		instr->byte_size = c166_instr_rw(instr);
		if (instr->byte_size == 0) {
			INSTR("invalid");
			instr->byte_size = C166_BYTESIZE_2;
			goto ok;
		}
		break;
	case C166_NEGB_Rbn:
	case C166_CPLB_Rbn:
		instr->byte_size = c166_instr_rb(instr);
		break;
	case C166_MOVBS_Rwn_Rbm:
	case C166_MOVBZ_Rwn_Rbm:
		instr->byte_size = c166_instr_rw_rb(instr);
		break;
	case C166_POP_reg:
	case C166_PUSH_reg:
	case C166_RETP_reg:
		instr->byte_size = c166_instr_reg(instr);
		break;
	case C166_CALLR_rel:
		instr->byte_size = c166_instr_call_rel(instr);
		break;
	case C166_CALLI_cc_Rwn:
	case C166_JMPI_cc_oRwn:
		instr->byte_size = c166_instr_cc_indirect(instr);
		break;
	case C166_JMPR_cc_C_or_ULT_rel:
	case C166_JMPR_cc_EQ_or_Z_rel:
	case C166_JMPR_cc_N_rel:
	case C166_JMPR_cc_NC_or_NGE_rel:
	case C166_JMPR_cc_NE_or_NZ_rel:
	case C166_JMPR_cc_NET_rel:
	case C166_JMPR_cc_NN_rel:
	case C166_JMPR_cc_NV_rel:
	case C166_JMPR_cc_SGE_rel:
	case C166_JMPR_cc_SGT_rel:
	case C166_JMPR_cc_SLE_rel:
	case C166_JMPR_cc_SLT_rel:
	case C166_JMPR_cc_UC_rel:
	case C166_JMPR_cc_UGT_rel:
	case C166_JMPR_cc_ULE_rel:
	case C166_JMPR_cc_V_rel:
		instr->byte_size = c166_instr_jmp_rel(instr);
		break;
	case C166_BCLR_bitoff0:
	case C166_BCLR_bitoff1:
	case C166_BCLR_bitoff2:
	case C166_BCLR_bitoff3:
	case C166_BCLR_bitoff4:
	case C166_BCLR_bitoff5:
	case C166_BCLR_bitoff6:
	case C166_BCLR_bitoff7:
	case C166_BCLR_bitoff8:
	case C166_BCLR_bitoff9:
	case C166_BCLR_bitoff10:
	case C166_BCLR_bitoff11:
	case C166_BCLR_bitoff12:
	case C166_BCLR_bitoff13:
	case C166_BCLR_bitoff14:
	case C166_BCLR_bitoff15:
	case C166_BSET_bitoff0:
	case C166_BSET_bitoff1:
	case C166_BSET_bitoff2:
	case C166_BSET_bitoff3:
	case C166_BSET_bitoff4:
	case C166_BSET_bitoff5:
	case C166_BSET_bitoff6:
	case C166_BSET_bitoff7:
	case C166_BSET_bitoff8:
	case C166_BSET_bitoff9:
	case C166_BSET_bitoff10:
	case C166_BSET_bitoff11:
	case C166_BSET_bitoff12:
	case C166_BSET_bitoff13:
	case C166_BSET_bitoff14:
	case C166_BSET_bitoff15:
		instr->byte_size = c166_instr_bitoff(instr);
		break;
	case C166_MOV_Rwn_oRwm:
	case C166_MOV_Rwn_oRwmp:
	case C166_MOV_oRwm_Rwn:
	case C166_MOV_noRwm_Rwn:
	case C166_MOV_oRwn_oRwm:
	case C166_MOV_oRwnp_oRwm:
	case C166_MOV_oRwn_oRwmp:
	case C166_MOVB_Rbn_oRwm:
	case C166_MOVB_Rbn_oRwmp:
	case C166_MOVB_oRwm_Rbn: // 0xB9
	case C166_MOVB_noRwm_Rbn: // 0x89
	case C166_MOVB_oRwn_oRwm: // 0xC9
	case C166_MOVB_oRwnp_oRwm: // 0xD9
	case C166_MOVB_oRwn_oRwmp: // 0xE9
		instr->byte_size = c166_instr_mov_nm(instr);
		break;
	case C166_ATOMIC_or_EXTR_irang2:
		instr->byte_size = c166_instr_irang2(state, instr);
		goto ok;
	case C166_EXTP_or_EXTS_Rwm_irang2:
		instr->byte_size = c166_instr_rw_irang2(state, instr);
		goto ok;
	case C166_TRAP_trap7:
		instr->byte_size = c166_trap_instr(instr);
		goto ok;
	case C166_ADD_reg_mem:
	case C166_ADDC_reg_mem:
	case C166_SUB_reg_mem:
	case C166_SUBC_reg_mem:
	case C166_AND_reg_mem:
	case C166_OR_reg_mem:
	case C166_XOR_reg_mem:
	case C166_CMP_reg_mem:
	case C166_MOV_reg_mem:
	case C166_SCXT_reg_mem:
		instr->byte_size = c166_instr_reg_mem(instr, false);
		break;
	case C166_ADDB_reg_mem:
	case C166_ADDCB_reg_mem:
	case C166_SUBB_reg_mem:
	case C166_SUBCB_reg_mem:
	case C166_ANDB_reg_mem:
	case C166_ORB_reg_mem:
	case C166_XORB_reg_mem:
	case C166_CMPB_reg_mem:
	case C166_MOVB_reg_mem:
	case C166_MOVBS_reg_mem:
	case C166_MOVBZ_reg_mem:
		instr->byte_size = c166_instr_reg_mem(instr, true);
		break;
	case C166_ADD_mem_reg:
	case C166_ADDC_mem_reg:
	case C166_SUB_mem_reg:
	case C166_SUBC_mem_reg:
	case C166_AND_mem_reg:
	case C166_OR_mem_reg:
	case C166_XOR_mem_reg:
	case C166_MOV_mem_reg:
		instr->byte_size = c166_instr_mem_reg(instr, false);
		break;
	case C166_ADDB_mem_reg:
	case C166_ADDCB_mem_reg:
	case C166_SUBB_mem_reg:
	case C166_SUBCB_mem_reg:
	case C166_ANDB_mem_reg:
	case C166_ORB_mem_reg:
	case C166_XORB_mem_reg:
	case C166_MOVB_mem_reg:
	case C166_MOVBS_mem_reg:
	case C166_MOVBZ_mem_reg:
		instr->byte_size = c166_instr_mem_reg(instr, true);
		break;
	case C166_ADD_reg_data16:
	case C166_ADDC_reg_data16:
	case C166_SUB_reg_data16:
	case C166_SUBC_reg_data16:
	case C166_AND_reg_data16:
	case C166_OR_reg_data16:
	case C166_XOR_reg_data16:
	case C166_CMP_reg_data16:
	case C166_MOV_reg_data16:
	case C166_SCXT_reg_data16:
		instr->byte_size = c166_instr_reg_data16(instr, false);
		break;
	case C166_CMPD1_Rwn_data16:
	case C166_CMPD2_Rwn_data16:
	case C166_CMPI1_Rwn_data16:
	case C166_CMPI2_Rwn_data16:
		instr->byte_size = c166_instr_rw_data16(instr);
		break;
	case C166_CMPD1_Rwn_mem:
	case C166_CMPD2_Rwn_mem:
	case C166_CMPI1_Rwn_mem:
	case C166_CMPI2_Rwn_mem:
		instr->byte_size = c166_instr_rw_mem(instr);
		break;
	case C166_ADDB_reg_data8:
	case C166_ADDCB_reg_data8:
	case C166_SUBB_reg_data8:
	case C166_SUBCB_reg_data8:
	case C166_ANDB_reg_data8:
	case C166_ORB_reg_data8:
	case C166_XORB_reg_data8:
	case C166_CMPB_reg_data8:
	case C166_MOVB_reg_data8:
		instr->byte_size = c166_instr_reg_data8(instr, true);
		break;
	case C166_CALLS_seg_caddr:
	case C166_JMPS_seg_caddr:
		instr->byte_size = c166_instr_seg_caddr(instr);
		break;
	case C166_CALLA_cc_caddr:
	case C166_JMPA_cc_caddr:
		instr->byte_size = c166_instr_cc_caddr(instr);
		goto ok;
	case C166_JB_bitaddr_rel:
	case C166_JBC_bitaddr_rel:
	case C166_JNB_bitaddr_rel:
	case C166_JNBS_bitaddr_rel:
		instr->byte_size = c166_instr_bitaddr_rel(instr);
		break;
	case C166_PCALL_reg_caddr:
		instr->byte_size = c166_instr_reg_caddr(instr);
		break;
	case C166_MOV_mem_oRwn:
	case C166_MOV_oRwn_mem:
	case C166_MOVB_mem_oRwn:
	case C166_MOVB_oRwn_mem:
		instr->byte_size = c166_instr_mov_mem_oRw(instr);
		break;
	case C166_MOV_Rwn_oRwm_data16:
	case C166_MOV_oRwm_data16_Rwn:
	case C166_MOVB_Rbn_oRwm_data16:
	case C166_MOVB_oRwm_data16_Rbn:
		instr->byte_size = c166_instr_mov_nm_data(instr);
		break;
	case C166_BAND_bitaddr_bitaddr:
	case C166_BCMP_bitaddr_bitaddr:
	case C166_BMOV_bitaddr_bitaddr:
	case C166_BMOVN_bitaddr_bitaddr:
	case C166_BOR_bitaddr_bitaddr:
	case C166_BXOR_bitaddr_bitaddr:
		instr->byte_size = c166_instr_bitaddr_bitaddr(instr);
		break;
	case C166_BFLDH_bitoff_x:
	case C166_BFLDL_bitoff_x:
		instr->byte_size = c166_instr_bfld(instr);
		break;
	case C166_EXTP_or_EXTS_pag10_or_seg8_irang2: {
		instr->byte_size = c166_instr_seg_or_pag_irang2(state, instr, rz_read_at_le16(bytes, 2));
		goto ok;
	}
	case C166_SBRK:
	case C166_NOP:
	case C166_RET:
	case C166_RETS:
	case C166_RETI:
		instr->byte_size = C166_BYTESIZE_2;
		break;
	case C166_SRST: // B7 48 B7 B7
	case C166_IDLE: // 87 78 87 87
	case C166_PWRDN: // 97 68 97 97
	case C166_SRVWDT: // A7 58 A7 A7
	case C166_DISWDT: // A5 5A A5 A5
	case C166_EINIT: // B5 4A B5 B5
	case C166_ENWDT: // 85 7A 85 85
		instr->byte_size = C166_BYTESIZE_4;
		break;
	case C166_CoMOV:
	case C166_CoSTORE_B3:
	case C166_CoSTORE_C3:
	case C166_CoXXX_83:
	case C166_CoXXX_93:
	case C166_CoXXX_A3:
		instr->byte_size = c166_instr_extended(instr);
		goto ok;
	// case 0x3b:
	// case 0x44:
	// case 0x45:
	// case 0x8B:
	// case 0x95:
	// case 0xC1:
	// case 0xC7:
	// case 0xE3:
	// case 0xE5:
	// case 0xF5:
	// case 0xF8:
	// case 0xF9:
	default:
		INSTR("invalid");
		instr->byte_size = 2;
		goto ok;
	}
	PRINT_INSTR;
	if (instr->byte_size > len)
		INSTR("invalid");

ok:
	rz_buf_free(b);
	return instr->byte_size;
err:
	rz_buf_free(b);
	INSTR("invalid");
	instr->byte_size = -1;
	return -1;
}
