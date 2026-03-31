// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "mips_internal.h"

#if CS_NEXT_VERSION > 5
#include <rz_il/rz_il_opbuilder_begin.h>

#define VARG_REG(idx)     VARG(REG(idx))
#define VARG_MEMBASE(idx) VARG(MEMBASE(idx))

#include "il/hw.c"
#include "il/common.c"
#include "il/fp.c"
#include "il/cop2.c"
#include "il/atomic.c"

RZ_IPI RzILOpEffect *mips_il(RZ_NONNULL const csh *handle, RZ_NONNULL const cs_insn *insn, const ut32 gprlen) {
	rz_return_val_if_fail(handle && insn, NULL);

	switch (insn->id) {
	case MIPS_INS_ABS:
		return NULL;
	case MIPS_INS_ALIGN:
		return mips_il_align(handle, insn, gprlen);
	case MIPS_INS_BEQL:
		return mips_il_beq(handle, insn, gprlen); // beq Likely
	case MIPS_INS_BGE:
		return NULL;
	case MIPS_INS_BGEL:
		return NULL;
	case MIPS_INS_BGEU:
		return NULL;
	case MIPS_INS_BGEUL:
		return NULL;
	case MIPS_INS_BGT:
		return NULL;
	case MIPS_INS_BGTL:
		return NULL;
	case MIPS_INS_BGTU:
		return NULL;
	case MIPS_INS_BGTUL:
		return NULL;
	case MIPS_INS_BLE:
		return NULL;
	case MIPS_INS_BLEL:
		return NULL;
	case MIPS_INS_BLEU:
		return NULL;
	case MIPS_INS_BLEUL:
		return NULL;
	case MIPS_INS_BLT:
		return NULL;
	case MIPS_INS_BLTL:
		return NULL;
	case MIPS_INS_BLTU:
		return NULL;
	case MIPS_INS_BLTUL:
		return NULL;
	case MIPS_INS_BNEL:
		return mips_il_bne(handle, insn, gprlen); // bne Likely
	case MIPS_INS_B:
		return mips_il_b(handle, insn, gprlen);
	case MIPS_INS_BEQ:
		return mips_il_beq(handle, insn, gprlen);
	case MIPS_INS_BNE:
		return mips_il_bne(handle, insn, gprlen);
	case MIPS_INS_CFTC1:
		return NULL;
	case MIPS_INS_CTTC1:
		return NULL;
	case MIPS_INS_DMUL:
		return mips_il_dmul(handle, insn, gprlen);
	case MIPS_INS_DMULO:
		return NULL;
	case MIPS_INS_DMULOU:
		return NULL;
	case MIPS_INS_DROL:
		return NULL;
	case MIPS_INS_DROR:
		return NULL;
	case MIPS_INS_DDIV:
		return mips_il_div(handle, insn, gprlen); // removed from r6
	case MIPS_INS_DREM:
		return NULL;
	case MIPS_INS_DDIVU:
		return mips_il_divu(handle, insn, gprlen); // removed from r6
	case MIPS_INS_DREMU:
		return NULL;
	case MIPS_INS_JAL:
		return mips_il_jal(handle, insn, gprlen);
	case MIPS_INS_LD:
		return mips_il_ld(handle, insn, gprlen);
	case MIPS_INS_LWM:
		return NULL;
	case MIPS_INS_LA:
		return NULL;
	case MIPS_INS_DLA:
		return NULL;
	case MIPS_INS_LI:
		return NULL;
	case MIPS_INS_DLI:
		return NULL;
	case MIPS_INS_LI_D:
		return NULL;
	case MIPS_INS_LI_S:
		return NULL;
	case MIPS_INS_MFTACX:
		return NULL;
	case MIPS_INS_MFTC0:
		return NULL;
	case MIPS_INS_MFTC1:
		return NULL;
	case MIPS_INS_MFTDSP:
		return NULL;
	case MIPS_INS_MFTGPR:
		return NULL;
	case MIPS_INS_MFTHC1:
		return NULL;
	case MIPS_INS_MFTHI:
		return NULL;
	case MIPS_INS_MFTLO:
		return NULL;
	case MIPS_INS_MTTACX:
		return NULL;
	case MIPS_INS_MTTC0:
		return NULL;
	case MIPS_INS_MTTC1:
		return NULL;
	case MIPS_INS_MTTDSP:
		return NULL;
	case MIPS_INS_MTTGPR:
		return NULL;
	case MIPS_INS_MTTHC1:
		return NULL;
	case MIPS_INS_MTTHI:
		return NULL;
	case MIPS_INS_MTTLO:
		return NULL;
	case MIPS_INS_MUL:
		return mips_il_mul(handle, insn, gprlen);
	case MIPS_INS_MULO:
		return NULL;
	case MIPS_INS_MULOU:
		return NULL;
	case MIPS_INS_NOR:
		return mips_il_nor(handle, insn, gprlen);
	case MIPS_INS_ADDIU:
		return mips_il_addiu(handle, insn, gprlen);
	case MIPS_INS_ANDI:
		return mips_il_andi(handle, insn, gprlen);
	case MIPS_INS_SUBU:
		return mips_il_subu(handle, insn, gprlen);
	case MIPS_INS_TRUNC_W_D:
		return mips_il_trunc_w_fmt(handle, insn, gprlen);
	case MIPS_INS_TRUNC_W_S:
		return mips_il_trunc_w_fmt(handle, insn, gprlen);
	case MIPS_INS_ROL:
		return NULL;
	case MIPS_INS_ROR:
		return NULL;
	case MIPS_INS_S_D:
		return NULL;
	case MIPS_INS_SD:
		return mips_il_sd(handle, insn, gprlen);
	case MIPS_INS_DIV:
		return mips_il_div(handle, insn, gprlen);
	case MIPS_INS_SEQ:
		return NULL;
	case MIPS_INS_SGE:
		return NULL;
	case MIPS_INS_SGEU:
		return NULL;
	case MIPS_INS_SGT:
		return NULL;
	case MIPS_INS_SGTU:
		return NULL;
	case MIPS_INS_SLE:
		return NULL;
	case MIPS_INS_SLEU:
		return NULL;
	case MIPS_INS_SLT:
		return mips_il_slt(handle, insn, gprlen);
	case MIPS_INS_SLTU:
		return mips_il_sltu(handle, insn, gprlen);
	case MIPS_INS_SNE:
		return NULL;
	case MIPS_INS_REM:
		return NULL;
	case MIPS_INS_SWM:
		return NULL;
	case MIPS_INS_SAA:
		return NULL;
	case MIPS_INS_SAAD:
		return NULL;
	case MIPS_INS_DIVU:
		return mips_il_divu(handle, insn, gprlen);
	case MIPS_INS_REMU:
		return NULL;
	case MIPS_INS_ULH:
		return NULL;
	case MIPS_INS_ULHU:
		return NULL;
	case MIPS_INS_ULW:
		return NULL;
	case MIPS_INS_USH:
		return NULL;
	case MIPS_INS_USW:
		return NULL;
	case MIPS_INS_ABSQ_S_PH:
		return NULL;
	case MIPS_INS_ABSQ_S_QB:
		return NULL;
	case MIPS_INS_ABSQ_S_W:
		return NULL;
	case MIPS_INS_ADD:
		return mips_il_add(handle, insn, gprlen);
	case MIPS_INS_ADDIUPC:
		return mips_il_addiupc(handle, insn, gprlen);
	case MIPS_INS_ADDIUR1SP:
		return NULL;
	case MIPS_INS_ADDIUR2:
		return NULL;
	case MIPS_INS_ADDIUS5:
		return NULL;
	case MIPS_INS_ADDIUSP:
		return NULL;
	case MIPS_INS_ADDQH_PH:
		return NULL;
	case MIPS_INS_ADDQH_R_PH:
		return NULL;
	case MIPS_INS_ADDQH_R_W:
		return NULL;
	case MIPS_INS_ADDQH_W:
		return NULL;
	case MIPS_INS_ADDQ_PH:
		return NULL;
	case MIPS_INS_ADDQ_S_PH:
		return NULL;
	case MIPS_INS_ADDQ_S_W:
		return NULL;
	case MIPS_INS_ADDR_PS:
		return NULL;
	case MIPS_INS_ADDSC:
		return NULL;
	case MIPS_INS_ADDS_A_B:
		return NULL;
	case MIPS_INS_ADDS_A_D:
		return NULL;
	case MIPS_INS_ADDS_A_H:
		return NULL;
	case MIPS_INS_ADDS_A_W:
		return NULL;
	case MIPS_INS_ADDS_S_B:
		return NULL;
	case MIPS_INS_ADDS_S_D:
		return NULL;
	case MIPS_INS_ADDS_S_H:
		return NULL;
	case MIPS_INS_ADDS_S_W:
		return NULL;
	case MIPS_INS_ADDS_U_B:
		return NULL;
	case MIPS_INS_ADDS_U_D:
		return NULL;
	case MIPS_INS_ADDS_U_H:
		return NULL;
	case MIPS_INS_ADDS_U_W:
		return NULL;
	case MIPS_INS_ADDU16:
		return NULL;
	case MIPS_INS_ADDUH_QB:
		return NULL;
	case MIPS_INS_ADDUH_R_QB:
		return NULL;
	case MIPS_INS_ADDU:
		return mips_il_addu(handle, insn, gprlen);
	case MIPS_INS_ADDU_PH:
		return NULL;
	case MIPS_INS_ADDU_QB:
		return NULL;
	case MIPS_INS_ADDU_S_PH:
		return NULL;
	case MIPS_INS_ADDU_S_QB:
		return NULL;
	case MIPS_INS_ADDVI_B:
		return NULL;
	case MIPS_INS_ADDVI_D:
		return NULL;
	case MIPS_INS_ADDVI_H:
		return NULL;
	case MIPS_INS_ADDVI_W:
		return NULL;
	case MIPS_INS_ADDV_B:
		return NULL;
	case MIPS_INS_ADDV_D:
		return NULL;
	case MIPS_INS_ADDV_H:
		return NULL;
	case MIPS_INS_ADDV_W:
		return NULL;
	case MIPS_INS_ADDWC:
		return NULL;
	case MIPS_INS_ADD_A_B:
		return NULL;
	case MIPS_INS_ADD_A_D:
		return NULL;
	case MIPS_INS_ADD_A_H:
		return NULL;
	case MIPS_INS_ADD_A_W:
		return NULL;
	case MIPS_INS_ADDI:
		return mips_il_addi(handle, insn, gprlen);
	case MIPS_INS_ALUIPC:
		return mips_il_aluipc(handle, insn, gprlen);
	case MIPS_INS_AND:
		return mips_il_and(handle, insn, gprlen);
	case MIPS_INS_AND16:
		return NULL;
	case MIPS_INS_ANDI16:
		return NULL;
	case MIPS_INS_ANDI_B:
		return NULL;
	case MIPS_INS_AND_V:
		return NULL;
	case MIPS_INS_APPEND:
		return NULL;
	case MIPS_INS_ASUB_S_B:
		return NULL;
	case MIPS_INS_ASUB_S_D:
		return NULL;
	case MIPS_INS_ASUB_S_H:
		return NULL;
	case MIPS_INS_ASUB_S_W:
		return NULL;
	case MIPS_INS_ASUB_U_B:
		return NULL;
	case MIPS_INS_ASUB_U_D:
		return NULL;
	case MIPS_INS_ASUB_U_H:
		return NULL;
	case MIPS_INS_ASUB_U_W:
		return NULL;
	case MIPS_INS_AUI:
		return mips_il_aui(handle, insn, gprlen);
	case MIPS_INS_AUIPC:
		return mips_il_auipc(handle, insn, gprlen);
	case MIPS_INS_AVER_S_B:
		return NULL;
	case MIPS_INS_AVER_S_D:
		return NULL;
	case MIPS_INS_AVER_S_H:
		return NULL;
	case MIPS_INS_AVER_S_W:
		return NULL;
	case MIPS_INS_AVER_U_B:
		return NULL;
	case MIPS_INS_AVER_U_D:
		return NULL;
	case MIPS_INS_AVER_U_H:
		return NULL;
	case MIPS_INS_AVER_U_W:
		return NULL;
	case MIPS_INS_AVE_S_B:
		return NULL;
	case MIPS_INS_AVE_S_D:
		return NULL;
	case MIPS_INS_AVE_S_H:
		return NULL;
	case MIPS_INS_AVE_S_W:
		return NULL;
	case MIPS_INS_AVE_U_B:
		return NULL;
	case MIPS_INS_AVE_U_D:
		return NULL;
	case MIPS_INS_AVE_U_H:
		return NULL;
	case MIPS_INS_AVE_U_W:
		return NULL;
	case MIPS_INS_B16:
		return NULL;
	case MIPS_INS_BADDU:
		return NULL;
	case MIPS_INS_BAL:
		/* fall-thru */
	case MIPS_INS_BALC:
		return mips_il_bal(handle, insn, gprlen);
	case MIPS_INS_BALIGN:
		return NULL;
	case MIPS_INS_BALRSC:
		return NULL;
	case MIPS_INS_BBEQZC:
		return NULL;
	case MIPS_INS_BBIT0:
		return NULL;
	case MIPS_INS_BBIT032:
		return NULL;
	case MIPS_INS_BBIT1:
		return NULL;
	case MIPS_INS_BBIT132:
		return NULL;
	case MIPS_INS_BBNEZC:
		return NULL;
	case MIPS_INS_BC:
		return mips_il_b(handle, insn, gprlen);
	case MIPS_INS_BC16:
		return NULL;
	case MIPS_INS_BC1EQZ:
		return NULL;
	case MIPS_INS_BC1EQZC:
		return NULL;
	case MIPS_INS_BC1F:
		return mips_il_bc1f(handle, insn, gprlen);
	case MIPS_INS_BC1FL:
		return mips_il_bc1f(handle, insn, gprlen); // bc1f Likely
	case MIPS_INS_BC1NEZ:
		return NULL;
	case MIPS_INS_BC1NEZC:
		return NULL;
	case MIPS_INS_BC1T:
		return mips_il_bc1t(handle, insn, gprlen);
	case MIPS_INS_BC1TL:
		return mips_il_bc1t(handle, insn, gprlen); // bc1t Likely
	case MIPS_INS_BC2EQZ:
		return NULL;
	case MIPS_INS_BC2EQZC:
		return NULL;
	case MIPS_INS_BC2NEZ:
		return NULL;
	case MIPS_INS_BC2NEZC:
		return NULL;
	case MIPS_INS_BCLRI_B:
		return NULL;
	case MIPS_INS_BCLRI_D:
		return NULL;
	case MIPS_INS_BCLRI_H:
		return NULL;
	case MIPS_INS_BCLRI_W:
		return NULL;
	case MIPS_INS_BCLR_B:
		return NULL;
	case MIPS_INS_BCLR_D:
		return NULL;
	case MIPS_INS_BCLR_H:
		return NULL;
	case MIPS_INS_BCLR_W:
		return NULL;
	case MIPS_INS_BEQC:
		return mips_il_beq(handle, insn, gprlen);
	case MIPS_INS_BEQIC:
		return NULL;
	case MIPS_INS_BEQZ16:
		return NULL;
	case MIPS_INS_BEQZALC:
		return mips_il_beqzalc(handle, insn, gprlen);
	case MIPS_INS_BEQZC:
		return mips_il_beqz(handle, insn, gprlen);
	case MIPS_INS_BEQZC16:
		return NULL;
	case MIPS_INS_BGEC:
		return mips_il_bgec(handle, insn, gprlen);
	case MIPS_INS_BGEIC:
		return NULL;
	case MIPS_INS_BGEIUC:
		return NULL;
	case MIPS_INS_BGEUC:
		return mips_il_bgec(handle, insn, gprlen); // unsigned
	case MIPS_INS_BGEZ:
		return mips_il_bgez(handle, insn, gprlen);
	case MIPS_INS_BGEZAL:
		return mips_il_bgezal(handle, insn, gprlen);
	case MIPS_INS_BGEZALC:
		return mips_il_bgezal(handle, insn, gprlen); // bgezal Compact
	case MIPS_INS_BGEZALL:
		return mips_il_bgezal(handle, insn, gprlen); // bgezal Likely
	case MIPS_INS_BGEZALS:
		return NULL;
	case MIPS_INS_BGEZC:
		return mips_il_bgez(handle, insn, gprlen); // bgez compact
	case MIPS_INS_BGEZL:
		return mips_il_bgez(handle, insn, gprlen); // bgez Likely
	case MIPS_INS_BGTZ:
		return mips_il_bgtz(handle, insn, gprlen);
	case MIPS_INS_BGTZALC:
		return mips_il_bgtzalc(handle, insn, gprlen);
	case MIPS_INS_BGTZC:
		return mips_il_bgtz(handle, insn, gprlen); // compact
	case MIPS_INS_BGTZL:
		return mips_il_bgtz(handle, insn, gprlen); // bgtz Likely
	case MIPS_INS_BINSLI_B:
		return NULL;
	case MIPS_INS_BINSLI_D:
		return NULL;
	case MIPS_INS_BINSLI_H:
		return NULL;
	case MIPS_INS_BINSLI_W:
		return NULL;
	case MIPS_INS_BINSL_B:
		return NULL;
	case MIPS_INS_BINSL_D:
		return NULL;
	case MIPS_INS_BINSL_H:
		return NULL;
	case MIPS_INS_BINSL_W:
		return NULL;
	case MIPS_INS_BINSRI_B:
		return NULL;
	case MIPS_INS_BINSRI_D:
		return NULL;
	case MIPS_INS_BINSRI_H:
		return NULL;
	case MIPS_INS_BINSRI_W:
		return NULL;
	case MIPS_INS_BINSR_B:
		return NULL;
	case MIPS_INS_BINSR_D:
		return NULL;
	case MIPS_INS_BINSR_H:
		return NULL;
	case MIPS_INS_BINSR_W:
		return NULL;
	case MIPS_INS_BITREV:
		return NULL;
	case MIPS_INS_BITREVW:
		return NULL;
	case MIPS_INS_BITSWAP:
		return mips_il_bitswap(handle, insn, gprlen);
	case MIPS_INS_BLEZ:
		return mips_il_blez(handle, insn, gprlen);
	case MIPS_INS_BLEZALC:
		return mips_il_blezalc(handle, insn, gprlen);
	case MIPS_INS_BLEZC:
		return mips_il_blez(handle, insn, gprlen); // compact
	case MIPS_INS_BLEZL:
		return mips_il_blez(handle, insn, gprlen); // blez Likely
	case MIPS_INS_BLTC:
		return mips_il_bltc(handle, insn, gprlen);
	case MIPS_INS_BLTIC:
		return NULL;
	case MIPS_INS_BLTIUC:
		return NULL;
	case MIPS_INS_BLTUC:
		return mips_il_bltc(handle, insn, gprlen); // unsigned
	case MIPS_INS_BLTZ:
		return mips_il_bltz(handle, insn, gprlen);
	case MIPS_INS_BLTZAL:
		return mips_il_bltzal(handle, insn, gprlen);
	case MIPS_INS_BLTZALC:
		return mips_il_bltzal(handle, insn, gprlen); // bltzal Compact
	case MIPS_INS_BLTZALL:
		return mips_il_bltzal(handle, insn, gprlen); // bltzal Likely
	case MIPS_INS_BLTZALS:
		return NULL;
	case MIPS_INS_BLTZC:
		return mips_il_bltz(handle, insn, gprlen); // compact
	case MIPS_INS_BLTZL:
		return mips_il_bltz(handle, insn, gprlen); // blez Likely
	case MIPS_INS_BMNZI_B:
		return NULL;
	case MIPS_INS_BMNZ_V:
		return NULL;
	case MIPS_INS_BMZI_B:
		return NULL;
	case MIPS_INS_BMZ_V:
		return NULL;
	case MIPS_INS_BNEC:
		return mips_il_bne(handle, insn, gprlen);
	case MIPS_INS_BNEGI_B:
		return NULL;
	case MIPS_INS_BNEGI_D:
		return NULL;
	case MIPS_INS_BNEGI_H:
		return NULL;
	case MIPS_INS_BNEGI_W:
		return NULL;
	case MIPS_INS_BNEG_B:
		return NULL;
	case MIPS_INS_BNEG_D:
		return NULL;
	case MIPS_INS_BNEG_H:
		return NULL;
	case MIPS_INS_BNEG_W:
		return NULL;
	case MIPS_INS_BNEIC:
		return NULL;
	case MIPS_INS_BNEZ16:
		return NULL;
	case MIPS_INS_BNEZALC:
		return mips_il_bnezalc(handle, insn, gprlen);
	case MIPS_INS_BNEZC:
		return mips_il_bnez(handle, insn, gprlen);
	case MIPS_INS_BNEZC16:
		return NULL;
	case MIPS_INS_BNVC:
		return NULL;
	case MIPS_INS_BNZ_B:
		return NULL;
	case MIPS_INS_BNZ_D:
		return NULL;
	case MIPS_INS_BNZ_H:
		return NULL;
	case MIPS_INS_BNZ_V:
		return NULL;
	case MIPS_INS_BNZ_W:
		return NULL;
	case MIPS_INS_BOVC:
		return mips_il_bovc(handle, insn, gprlen);
	case MIPS_INS_BPOSGE32:
		return NULL;
	case MIPS_INS_BPOSGE32C:
		return NULL;
	case MIPS_INS_BREAK:
		return mips_il_break(handle, insn, gprlen);
	case MIPS_INS_BREAK16:
		return NULL;
	case MIPS_INS_BRSC:
		return NULL;
	case MIPS_INS_BSELI_B:
		return NULL;
	case MIPS_INS_BSEL_V:
		return NULL;
	case MIPS_INS_BSETI_B:
		return NULL;
	case MIPS_INS_BSETI_D:
		return NULL;
	case MIPS_INS_BSETI_H:
		return NULL;
	case MIPS_INS_BSETI_W:
		return NULL;
	case MIPS_INS_BSET_B:
		return NULL;
	case MIPS_INS_BSET_D:
		return NULL;
	case MIPS_INS_BSET_H:
		return NULL;
	case MIPS_INS_BSET_W:
		return NULL;
	case MIPS_INS_BYTEREVW:
		return NULL;
	case MIPS_INS_BZ_B:
		return NULL;
	case MIPS_INS_BZ_D:
		return NULL;
	case MIPS_INS_BZ_H:
		return NULL;
	case MIPS_INS_BZ_V:
		return NULL;
	case MIPS_INS_BZ_W:
		return NULL;
	case MIPS_INS_BEQZ:
		return NULL;
	case MIPS_INS_BNEZ:
		return NULL;
	case MIPS_INS_BTEQZ:
		return NULL;
	case MIPS_INS_BTNEZ:
		return NULL;
	case MIPS_INS_CACHE:
		return NOP(); // perform cache operation
	case MIPS_INS_CACHEE:
		return NOP(); // perform cache operation EVA
	case MIPS_INS_CEIL_L_D:
		return mips_il_ceil_l_fmt(handle, insn, gprlen);
	case MIPS_INS_CEIL_L_S:
		return mips_il_ceil_l_fmt(handle, insn, gprlen);
	case MIPS_INS_CEIL_W_D:
		return mips_il_ceil_w_fmt(handle, insn, gprlen);
	case MIPS_INS_CEIL_W_S:
		return mips_il_ceil_w_fmt(handle, insn, gprlen);
	case MIPS_INS_CEQI_B:
		return NULL;
	case MIPS_INS_CEQI_D:
		return NULL;
	case MIPS_INS_CEQI_H:
		return NULL;
	case MIPS_INS_CEQI_W:
		return NULL;
	case MIPS_INS_CEQ_B:
		return NULL;
	case MIPS_INS_CEQ_D:
		return NULL;
	case MIPS_INS_CEQ_H:
		return NULL;
	case MIPS_INS_CEQ_W:
		return NULL;
	case MIPS_INS_CFC1:
		return mips_il_cfc1(handle, insn, gprlen);
	case MIPS_INS_CFC2:
		return mips_il_cfc2(handle, insn, gprlen);
	case MIPS_INS_CFCMSA:
		return NULL;
	case MIPS_INS_CINS:
		return NULL;
	case MIPS_INS_CINS32:
		return NULL;
	case MIPS_INS_CLASS_D:
		return mips_il_class_fmt(handle, insn, gprlen);
	case MIPS_INS_CLASS_S:
		return mips_il_class_fmt(handle, insn, gprlen);
	case MIPS_INS_CLEI_S_B:
		return NULL;
	case MIPS_INS_CLEI_S_D:
		return NULL;
	case MIPS_INS_CLEI_S_H:
		return NULL;
	case MIPS_INS_CLEI_S_W:
		return NULL;
	case MIPS_INS_CLEI_U_B:
		return NULL;
	case MIPS_INS_CLEI_U_D:
		return NULL;
	case MIPS_INS_CLEI_U_H:
		return NULL;
	case MIPS_INS_CLEI_U_W:
		return NULL;
	case MIPS_INS_CLE_S_B:
		return NULL;
	case MIPS_INS_CLE_S_D:
		return NULL;
	case MIPS_INS_CLE_S_H:
		return NULL;
	case MIPS_INS_CLE_S_W:
		return NULL;
	case MIPS_INS_CLE_U_B:
		return NULL;
	case MIPS_INS_CLE_U_D:
		return NULL;
	case MIPS_INS_CLE_U_H:
		return NULL;
	case MIPS_INS_CLE_U_W:
		return NULL;
	case MIPS_INS_CLO:
		return mips_il_clo(handle, insn, gprlen);
	case MIPS_INS_CLTI_S_B:
		return NULL;
	case MIPS_INS_CLTI_S_D:
		return NULL;
	case MIPS_INS_CLTI_S_H:
		return NULL;
	case MIPS_INS_CLTI_S_W:
		return NULL;
	case MIPS_INS_CLTI_U_B:
		return NULL;
	case MIPS_INS_CLTI_U_D:
		return NULL;
	case MIPS_INS_CLTI_U_H:
		return NULL;
	case MIPS_INS_CLTI_U_W:
		return NULL;
	case MIPS_INS_CLT_S_B:
		return NULL;
	case MIPS_INS_CLT_S_D:
		return NULL;
	case MIPS_INS_CLT_S_H:
		return NULL;
	case MIPS_INS_CLT_S_W:
		return NULL;
	case MIPS_INS_CLT_U_B:
		return NULL;
	case MIPS_INS_CLT_U_D:
		return NULL;
	case MIPS_INS_CLT_U_H:
		return NULL;
	case MIPS_INS_CLT_U_W:
		return NULL;
	case MIPS_INS_CLZ:
		return mips_il_clz(handle, insn, gprlen);
	case MIPS_INS_CMPGDU_EQ_QB:
		return NULL;
	case MIPS_INS_CMPGDU_LE_QB:
		return NULL;
	case MIPS_INS_CMPGDU_LT_QB:
		return NULL;
	case MIPS_INS_CMPGU_EQ_QB:
		return NULL;
	case MIPS_INS_CMPGU_LE_QB:
		return NULL;
	case MIPS_INS_CMPGU_LT_QB:
		return NULL;
	case MIPS_INS_CMPU_EQ_QB:
		return NULL;
	case MIPS_INS_CMPU_LE_QB:
		return NULL;
	case MIPS_INS_CMPU_LT_QB:
		return NULL;
	case MIPS_INS_CMP_AF_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_AF_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_EQ_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_EQ_PH:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_EQ_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_LE_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_LE_PH:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_LE_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_LT_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_LT_PH:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_LT_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SAF_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SAF_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SEQ_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SEQ_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SLE_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SLE_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SLT_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SLT_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SUEQ_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SUEQ_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SULE_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SULE_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SULT_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SULT_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SUN_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_SUN_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_UEQ_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_UEQ_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_ULE_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_ULE_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_ULT_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_ULT_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_UN_D:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP_UN_S:
		return mips_il_cmp_condn_fmt(handle, insn, gprlen);
	case MIPS_INS_COPY_S_B:
		return NULL;
	case MIPS_INS_COPY_S_D:
		return NULL;
	case MIPS_INS_COPY_S_H:
		return NULL;
	case MIPS_INS_COPY_S_W:
		return NULL;
	case MIPS_INS_COPY_U_B:
		return NULL;
	case MIPS_INS_COPY_U_H:
		return NULL;
	case MIPS_INS_COPY_U_W:
		return NULL;
	case MIPS_INS_CRC32B:
		return NULL;
	case MIPS_INS_CRC32CB:
		return NULL;
	case MIPS_INS_CRC32CD:
		return NULL;
	case MIPS_INS_CRC32CH:
		return NULL;
	case MIPS_INS_CRC32CW:
		return NULL;
	case MIPS_INS_CRC32D:
		return NULL;
	case MIPS_INS_CRC32H:
		return NULL;
	case MIPS_INS_CRC32W:
		return NULL;
	case MIPS_INS_CTC1:
		return mips_il_ctc1(handle, insn, gprlen);
	case MIPS_INS_CTC2:
		return mips_il_ctc2(handle, insn, gprlen);
	case MIPS_INS_CTCMSA:
		return NULL;
	case MIPS_INS_CVT_D_S:
		return mips_il_cvt_d_fmt(handle, insn, gprlen);
	case MIPS_INS_CVT_D_W:
		return mips_il_cvt_d_fmt(handle, insn, gprlen);
	case MIPS_INS_CVT_D_L:
		return mips_il_cvt_d_fmt(handle, insn, gprlen);
	case MIPS_INS_CVT_L_D:
		return mips_il_cvt_l_fmt(handle, insn, gprlen);
	case MIPS_INS_CVT_L_S:
		return mips_il_cvt_l_fmt(handle, insn, gprlen);
	case MIPS_INS_CVT_PS_PW:
		return NULL;
	case MIPS_INS_CVT_PS_S:
		return mips_il_cvt_ps_s(handle, insn, gprlen);
	case MIPS_INS_CVT_PW_PS:
		return NULL;
	case MIPS_INS_CVT_S_D:
		return mips_il_cvt_s_fmt(handle, insn, gprlen);
	case MIPS_INS_CVT_S_L:
		return mips_il_cvt_s_fmt(handle, insn, gprlen);
	case MIPS_INS_CVT_S_PL:
		return mips_il_cvt_s_pl(handle, insn, gprlen);
	case MIPS_INS_CVT_S_PU:
		return mips_il_cvt_s_pu(handle, insn, gprlen);
	case MIPS_INS_CVT_S_W:
		return mips_il_cvt_s_fmt(handle, insn, gprlen);
	case MIPS_INS_CVT_W_D:
		return mips_il_cvt_w_fmt(handle, insn, gprlen);
	case MIPS_INS_CVT_W_S:
		return mips_il_cvt_w_fmt(handle, insn, gprlen);
	case MIPS_INS_C_EQ_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_EQ_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_F_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_F_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_LE_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_LE_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_LT_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_LT_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_NGE_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_NGE_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_NGLE_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_NGLE_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_NGL_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_NGL_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_NGT_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_NGT_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_OLE_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_OLE_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_OLT_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_OLT_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_SEQ_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_SEQ_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_SF_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_SF_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_UEQ_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_UEQ_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_ULE_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_ULE_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_ULT_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_ULT_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_UN_D:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_C_UN_S:
		return mips_il_c_cond_fmt(handle, insn, gprlen);
	case MIPS_INS_CMP:
		return NULL;
	case MIPS_INS_CMPI:
		return NULL;
	case MIPS_INS_DADD:
		return mips_il_add(handle, insn, gprlen); // Long word add signed
	case MIPS_INS_DADDI:
		return mips_il_addi(handle, insn, gprlen); // Long word add immediate signed
	case MIPS_INS_DADDIU:
		return mips_il_addiu(handle, insn, gprlen); // Long word add immediate unsigned
	case MIPS_INS_DADDU:
		return mips_il_addu(handle, insn, gprlen); // Long word add unsigned
	case MIPS_INS_DAHI:
		return mips_il_dahi(handle, insn, gprlen);
	case MIPS_INS_DALIGN:
		return mips_il_dalign(handle, insn, gprlen);
	case MIPS_INS_DATI:
		return mips_il_dati(handle, insn, gprlen);
	case MIPS_INS_DAUI:
		return mips_il_daui(handle, insn, gprlen);
	case MIPS_INS_DBITSWAP:
		return mips_il_bitswap(handle, insn, gprlen);
	case MIPS_INS_DCLO:
		return mips_il_clo(handle, insn, gprlen);
	case MIPS_INS_DCLZ:
		return mips_il_clz(handle, insn, gprlen);
	case MIPS_INS_DERET:
		return mips_il_deret(handle, insn, gprlen);
	case MIPS_INS_DEXT:
		return mips_il_ext(handle, insn, gprlen);
	case MIPS_INS_DEXTM:
		return mips_il_ext(handle, insn, gprlen);
	case MIPS_INS_DEXTU:
		return mips_il_ext(handle, insn, gprlen);
	case MIPS_INS_DI:
		return NOP(); // Disable Interrupts
	case MIPS_INS_DINS:
		return mips_il_ins(handle, insn, gprlen);
	case MIPS_INS_DINSM:
		return mips_il_ins(handle, insn, gprlen);
	case MIPS_INS_DINSU:
		return mips_il_ins(handle, insn, gprlen);
	case MIPS_INS_DIV_S_B:
		return NULL;
	case MIPS_INS_DIV_S_D:
		return NULL;
	case MIPS_INS_DIV_S_H:
		return NULL;
	case MIPS_INS_DIV_S_W:
		return NULL;
	case MIPS_INS_DIV_U_B:
		return NULL;
	case MIPS_INS_DIV_U_D:
		return NULL;
	case MIPS_INS_DIV_U_H:
		return NULL;
	case MIPS_INS_DIV_U_W:
		return NULL;
	case MIPS_INS_DLSA:
		return mips_il_lsa(handle, insn, gprlen);
	case MIPS_INS_DMFC0:
		return mips_il_mfc0(handle, insn, gprlen);
	case MIPS_INS_DMFC1:
		return mips_il_mfc1(handle, insn, gprlen);
	case MIPS_INS_DMFC2:
		return mips_il_mfc2(handle, insn, gprlen);
	case MIPS_INS_DMFGC0:
		return NULL;
	case MIPS_INS_DMOD:
		return mips_il_mod(handle, insn, gprlen);
	case MIPS_INS_DMODU:
		return mips_il_modu(handle, insn, gprlen);
	case MIPS_INS_DMT:
		return NULL;
	case MIPS_INS_DMTC0:
		return mips_il_mtc0(handle, insn, gprlen);
	case MIPS_INS_DMTC1:
		return mips_il_mtc1(handle, insn, gprlen);
	case MIPS_INS_DMTC2:
		return mips_il_mtc2(handle, insn, gprlen);
	case MIPS_INS_DMTGC0:
		return NULL;
	case MIPS_INS_DMUH:
		return mips_il_dmuh(handle, insn, gprlen);
	case MIPS_INS_DMUHU:
		return mips_il_dmuhu(handle, insn, gprlen);
	case MIPS_INS_DMULT:
		return mips_il_dmult(handle, insn, gprlen);
	case MIPS_INS_DMULTU:
		return mips_il_dmultu(handle, insn, gprlen);
	case MIPS_INS_DMULU:
		return mips_il_dmulu(handle, insn, gprlen);
	case MIPS_INS_DOTP_S_D:
		return NULL;
	case MIPS_INS_DOTP_S_H:
		return NULL;
	case MIPS_INS_DOTP_S_W:
		return NULL;
	case MIPS_INS_DOTP_U_D:
		return NULL;
	case MIPS_INS_DOTP_U_H:
		return NULL;
	case MIPS_INS_DOTP_U_W:
		return NULL;
	case MIPS_INS_DPADD_S_D:
		return NULL;
	case MIPS_INS_DPADD_S_H:
		return NULL;
	case MIPS_INS_DPADD_S_W:
		return NULL;
	case MIPS_INS_DPADD_U_D:
		return NULL;
	case MIPS_INS_DPADD_U_H:
		return NULL;
	case MIPS_INS_DPADD_U_W:
		return NULL;
	case MIPS_INS_DPAQX_SA_W_PH:
		return NULL;
	case MIPS_INS_DPAQX_S_W_PH:
		return NULL;
	case MIPS_INS_DPAQ_SA_L_W:
		return NULL;
	case MIPS_INS_DPAQ_S_W_PH:
		return NULL;
	case MIPS_INS_DPAU_H_QBL:
		return NULL;
	case MIPS_INS_DPAU_H_QBR:
		return NULL;
	case MIPS_INS_DPAX_W_PH:
		return NULL;
	case MIPS_INS_DPA_W_PH:
		return NULL;
	case MIPS_INS_DPOP:
		return NULL;
	case MIPS_INS_DPSQX_SA_W_PH:
		return NULL;
	case MIPS_INS_DPSQX_S_W_PH:
		return NULL;
	case MIPS_INS_DPSQ_SA_L_W:
		return NULL;
	case MIPS_INS_DPSQ_S_W_PH:
		return NULL;
	case MIPS_INS_DPSUB_S_D:
		return NULL;
	case MIPS_INS_DPSUB_S_H:
		return NULL;
	case MIPS_INS_DPSUB_S_W:
		return NULL;
	case MIPS_INS_DPSUB_U_D:
		return NULL;
	case MIPS_INS_DPSUB_U_H:
		return NULL;
	case MIPS_INS_DPSUB_U_W:
		return NULL;
	case MIPS_INS_DPSU_H_QBL:
		return NULL;
	case MIPS_INS_DPSU_H_QBR:
		return NULL;
	case MIPS_INS_DPSX_W_PH:
		return NULL;
	case MIPS_INS_DPS_W_PH:
		return NULL;
	case MIPS_INS_DROTR:
		return mips_il_rotr(handle, insn, gprlen);
	case MIPS_INS_DROTR32:
		return mips_il_drotr32(handle, insn, gprlen);
	case MIPS_INS_DROTRV:
		return mips_il_rotrv(handle, insn, gprlen);
	case MIPS_INS_DSBH:
		return mips_il_dsbh(handle, insn, gprlen);
	case MIPS_INS_DSHD:
		return mips_il_dshd(handle, insn, gprlen);
	case MIPS_INS_DSLL:
		return mips_il_sll(handle, insn, gprlen);
	case MIPS_INS_DSLL32:
		return mips_il_dsll32(handle, insn, gprlen);
	case MIPS_INS_DSLLV:
		return mips_il_sllv(handle, insn, gprlen);
	case MIPS_INS_DSRA:
		return mips_il_sra(handle, insn, gprlen);
	case MIPS_INS_DSRA32:
		return mips_il_dsra32(handle, insn, gprlen);
	case MIPS_INS_DSRAV:
		return mips_il_srav(handle, insn, gprlen);
	case MIPS_INS_DSRL:
		return mips_il_srl(handle, insn, gprlen);
	case MIPS_INS_DSRL32:
		return mips_il_dsrl32(handle, insn, gprlen);
	case MIPS_INS_DSRLV:
		return mips_il_srlv(handle, insn, gprlen);
	case MIPS_INS_DSUB:
		return mips_il_sub(handle, insn, gprlen);
	case MIPS_INS_DSUBU:
		return mips_il_subu(handle, insn, gprlen);
	case MIPS_INS_DVP:
		return NOP(); // Disable Virtual Processor
	case MIPS_INS_DVPE:
		return NULL;
	case MIPS_INS_EHB:
		return NOP(); // Execution Hazard Barrier
	case MIPS_INS_EI:
		return NOP(); // Enable Interrupts
	case MIPS_INS_EMT:
		return NULL;
	case MIPS_INS_ERET:
		return mips_il_eret(handle, insn, gprlen);
	case MIPS_INS_ERETNC:
		return mips_il_eretnc(handle, insn, gprlen);
	case MIPS_INS_EVP:
		return NOP(); // Enable Virtual Processor
	case MIPS_INS_EVPE:
		return NOP(); // Enable Virtual Processor Execution
	case MIPS_INS_EXT:
		return mips_il_ext(handle, insn, gprlen);
	case MIPS_INS_EXTP:
		return NULL;
	case MIPS_INS_EXTPDP:
		return NULL;
	case MIPS_INS_EXTPDPV:
		return NULL;
	case MIPS_INS_EXTPV:
		return NULL;
	case MIPS_INS_EXTRV_RS_W:
		return NULL;
	case MIPS_INS_EXTRV_R_W:
		return NULL;
	case MIPS_INS_EXTRV_S_H:
		return NULL;
	case MIPS_INS_EXTRV_W:
		return NULL;
	case MIPS_INS_EXTR_RS_W:
		return NULL;
	case MIPS_INS_EXTR_R_W:
		return NULL;
	case MIPS_INS_EXTR_S_H:
		return NULL;
	case MIPS_INS_EXTR_W:
		return NULL;
	case MIPS_INS_EXTS:
		return NULL;
	case MIPS_INS_EXTS32:
		return NULL;
	case MIPS_INS_EXTW:
		return NULL;
	case MIPS_INS_ABS_D:
		return mips_il_abs_fmt(handle, insn, gprlen);
	case MIPS_INS_ABS_S:
		return mips_il_abs_fmt(handle, insn, gprlen);
	case MIPS_INS_FADD_D:
		return NULL;
	case MIPS_INS_ADD_D:
		return mips_il_add_fmt(handle, insn, gprlen);
	case MIPS_INS_ADD_PS:
		return mips_il_add_fmt(handle, insn, gprlen);
	case MIPS_INS_ADD_S:
		return mips_il_add_fmt(handle, insn, gprlen);
	case MIPS_INS_FADD_W:
		return NULL;
	case MIPS_INS_FCAF_D:
		return NULL;
	case MIPS_INS_FCAF_W:
		return NULL;
	case MIPS_INS_FCEQ_D:
		return NULL;
	case MIPS_INS_FCEQ_W:
		return NULL;
	case MIPS_INS_FCLASS_D:
		return NULL;
	case MIPS_INS_FCLASS_W:
		return NULL;
	case MIPS_INS_FCLE_D:
		return NULL;
	case MIPS_INS_FCLE_W:
		return NULL;
	case MIPS_INS_FCLT_D:
		return NULL;
	case MIPS_INS_FCLT_W:
		return NULL;
	case MIPS_INS_FCNE_D:
		return NULL;
	case MIPS_INS_FCNE_W:
		return NULL;
	case MIPS_INS_FCOR_D:
		return NULL;
	case MIPS_INS_FCOR_W:
		return NULL;
	case MIPS_INS_FCUEQ_D:
		return NULL;
	case MIPS_INS_FCUEQ_W:
		return NULL;
	case MIPS_INS_FCULE_D:
		return NULL;
	case MIPS_INS_FCULE_W:
		return NULL;
	case MIPS_INS_FCULT_D:
		return NULL;
	case MIPS_INS_FCULT_W:
		return NULL;
	case MIPS_INS_FCUNE_D:
		return NULL;
	case MIPS_INS_FCUNE_W:
		return NULL;
	case MIPS_INS_FCUN_D:
		return NULL;
	case MIPS_INS_FCUN_W:
		return NULL;
	case MIPS_INS_FDIV_D:
		return NULL;
	case MIPS_INS_DIV_D:
		return mips_il_div_fmt(handle, insn, gprlen);
	case MIPS_INS_DIV_S:
		return mips_il_div_fmt(handle, insn, gprlen);
	case MIPS_INS_FDIV_W:
		return NULL;
	case MIPS_INS_FEXDO_H:
		return NULL;
	case MIPS_INS_FEXDO_W:
		return NULL;
	case MIPS_INS_FEXP2_D:
		return NULL;
	case MIPS_INS_FEXP2_W:
		return NULL;
	case MIPS_INS_FEXUPL_D:
		return NULL;
	case MIPS_INS_FEXUPL_W:
		return NULL;
	case MIPS_INS_FEXUPR_D:
		return NULL;
	case MIPS_INS_FEXUPR_W:
		return NULL;
	case MIPS_INS_FFINT_S_D:
		return NULL;
	case MIPS_INS_FFINT_S_W:
		return NULL;
	case MIPS_INS_FFINT_U_D:
		return NULL;
	case MIPS_INS_FFINT_U_W:
		return NULL;
	case MIPS_INS_FFQL_D:
		return NULL;
	case MIPS_INS_FFQL_W:
		return NULL;
	case MIPS_INS_FFQR_D:
		return NULL;
	case MIPS_INS_FFQR_W:
		return NULL;
	case MIPS_INS_FILL_B:
		return NULL;
	case MIPS_INS_FILL_D:
		return NULL;
	case MIPS_INS_FILL_H:
		return NULL;
	case MIPS_INS_FILL_W:
		return NULL;
	case MIPS_INS_FLOG2_D:
		return NULL;
	case MIPS_INS_FLOG2_W:
		return NULL;
	case MIPS_INS_FLOOR_L_D:
		return mips_il_floor_l_fmt(handle, insn, gprlen);
	case MIPS_INS_FLOOR_L_S:
		return mips_il_floor_l_fmt(handle, insn, gprlen);
	case MIPS_INS_FLOOR_W_D:
		return mips_il_floor_w_fmt(handle, insn, gprlen);
	case MIPS_INS_FLOOR_W_S:
		return mips_il_floor_w_fmt(handle, insn, gprlen);
	case MIPS_INS_FMADD_D:
		return NULL;
	case MIPS_INS_FMADD_W:
		return NULL;
	case MIPS_INS_FMAX_A_D:
		return NULL;
	case MIPS_INS_FMAX_A_W:
		return NULL;
	case MIPS_INS_FMAX_D:
		return NULL;
	case MIPS_INS_FMAX_W:
		return NULL;
	case MIPS_INS_FMIN_A_D:
		return NULL;
	case MIPS_INS_FMIN_A_W:
		return NULL;
	case MIPS_INS_FMIN_D:
		return NULL;
	case MIPS_INS_FMIN_W:
		return NULL;
	case MIPS_INS_MOV_D:
		return mips_il_mov_fmt(handle, insn, gprlen);
	case MIPS_INS_MOV_S:
		return mips_il_mov_fmt(handle, insn, gprlen);
	case MIPS_INS_FMSUB_D:
		return NULL;
	case MIPS_INS_FMSUB_W:
		return NULL;
	case MIPS_INS_FMUL_D:
		return NULL;
	case MIPS_INS_MUL_D:
		return mips_il_mul_fmt(handle, insn, gprlen);
	case MIPS_INS_MUL_PS:
		return mips_il_mul_fmt(handle, insn, gprlen);
	case MIPS_INS_MUL_S:
		return mips_il_mul_fmt(handle, insn, gprlen);
	case MIPS_INS_FMUL_W:
		return NULL;
	case MIPS_INS_NEG_D:
		return mips_il_neg_fmt(handle, insn, gprlen);
	case MIPS_INS_NEG_S:
		return mips_il_neg_fmt(handle, insn, gprlen);
	case MIPS_INS_FORK:
		return NULL;
	case MIPS_INS_FRCP_D:
		return NULL;
	case MIPS_INS_FRCP_W:
		return NULL;
	case MIPS_INS_FRINT_D:
		return NULL;
	case MIPS_INS_FRINT_W:
		return NULL;
	case MIPS_INS_FRSQRT_D:
		return NULL;
	case MIPS_INS_FRSQRT_W:
		return NULL;
	case MIPS_INS_FSAF_D:
		return NULL;
	case MIPS_INS_FSAF_W:
		return NULL;
	case MIPS_INS_FSEQ_D:
		return NULL;
	case MIPS_INS_FSEQ_W:
		return NULL;
	case MIPS_INS_FSLE_D:
		return NULL;
	case MIPS_INS_FSLE_W:
		return NULL;
	case MIPS_INS_FSLT_D:
		return NULL;
	case MIPS_INS_FSLT_W:
		return NULL;
	case MIPS_INS_FSNE_D:
		return NULL;
	case MIPS_INS_FSNE_W:
		return NULL;
	case MIPS_INS_FSOR_D:
		return NULL;
	case MIPS_INS_FSOR_W:
		return NULL;
	case MIPS_INS_FSQRT_D:
		return NULL;
	case MIPS_INS_SQRT_D:
		return mips_il_sqrt_fmt(handle, insn, gprlen);
	case MIPS_INS_SQRT_S:
		return mips_il_sqrt_fmt(handle, insn, gprlen);
	case MIPS_INS_FSQRT_W:
		return NULL;
	case MIPS_INS_FSUB_D:
		return NULL;
	case MIPS_INS_SUB_D:
		return mips_il_sub_fmt(handle, insn, gprlen);
	case MIPS_INS_SUB_PS:
		return mips_il_sub_fmt(handle, insn, gprlen);
	case MIPS_INS_SUB_S:
		return mips_il_sub_fmt(handle, insn, gprlen);
	case MIPS_INS_FSUB_W:
		return NULL;
	case MIPS_INS_FSUEQ_D:
		return NULL;
	case MIPS_INS_FSUEQ_W:
		return NULL;
	case MIPS_INS_FSULE_D:
		return NULL;
	case MIPS_INS_FSULE_W:
		return NULL;
	case MIPS_INS_FSULT_D:
		return NULL;
	case MIPS_INS_FSULT_W:
		return NULL;
	case MIPS_INS_FSUNE_D:
		return NULL;
	case MIPS_INS_FSUNE_W:
		return NULL;
	case MIPS_INS_FSUN_D:
		return NULL;
	case MIPS_INS_FSUN_W:
		return NULL;
	case MIPS_INS_FTINT_S_D:
		return NULL;
	case MIPS_INS_FTINT_S_W:
		return NULL;
	case MIPS_INS_FTINT_U_D:
		return NULL;
	case MIPS_INS_FTINT_U_W:
		return NULL;
	case MIPS_INS_FTQ_H:
		return NULL;
	case MIPS_INS_FTQ_W:
		return NULL;
	case MIPS_INS_FTRUNC_S_D:
		return NULL;
	case MIPS_INS_FTRUNC_S_W:
		return NULL;
	case MIPS_INS_FTRUNC_U_D:
		return NULL;
	case MIPS_INS_FTRUNC_U_W:
		return NULL;
	case MIPS_INS_GINVI:
		return NULL;
	case MIPS_INS_GINVT:
		return NULL;
	case MIPS_INS_HADD_S_D:
		return NULL;
	case MIPS_INS_HADD_S_H:
		return NULL;
	case MIPS_INS_HADD_S_W:
		return NULL;
	case MIPS_INS_HADD_U_D:
		return NULL;
	case MIPS_INS_HADD_U_H:
		return NULL;
	case MIPS_INS_HADD_U_W:
		return NULL;
	case MIPS_INS_HSUB_S_D:
		return NULL;
	case MIPS_INS_HSUB_S_H:
		return NULL;
	case MIPS_INS_HSUB_S_W:
		return NULL;
	case MIPS_INS_HSUB_U_D:
		return NULL;
	case MIPS_INS_HSUB_U_H:
		return NULL;
	case MIPS_INS_HSUB_U_W:
		return NULL;
	case MIPS_INS_HYPCALL:
		return NULL;
	case MIPS_INS_ILVEV_B:
		return NULL;
	case MIPS_INS_ILVEV_D:
		return NULL;
	case MIPS_INS_ILVEV_H:
		return NULL;
	case MIPS_INS_ILVEV_W:
		return NULL;
	case MIPS_INS_ILVL_B:
		return NULL;
	case MIPS_INS_ILVL_D:
		return NULL;
	case MIPS_INS_ILVL_H:
		return NULL;
	case MIPS_INS_ILVL_W:
		return NULL;
	case MIPS_INS_ILVOD_B:
		return NULL;
	case MIPS_INS_ILVOD_D:
		return NULL;
	case MIPS_INS_ILVOD_H:
		return NULL;
	case MIPS_INS_ILVOD_W:
		return NULL;
	case MIPS_INS_ILVR_B:
		return NULL;
	case MIPS_INS_ILVR_D:
		return NULL;
	case MIPS_INS_ILVR_H:
		return NULL;
	case MIPS_INS_ILVR_W:
		return NULL;
	case MIPS_INS_INS:
		return mips_il_ins(handle, insn, gprlen);
	case MIPS_INS_INSERT_B:
		return NULL;
	case MIPS_INS_INSERT_D:
		return NULL;
	case MIPS_INS_INSERT_H:
		return NULL;
	case MIPS_INS_INSERT_W:
		return NULL;
	case MIPS_INS_INSV:
		return NULL;
	case MIPS_INS_INSVE_B:
		return NULL;
	case MIPS_INS_INSVE_D:
		return NULL;
	case MIPS_INS_INSVE_H:
		return NULL;
	case MIPS_INS_INSVE_W:
		return NULL;
	case MIPS_INS_J:
		return mips_il_j(handle, insn, gprlen);
	case MIPS_INS_JALR:
		return mips_il_jalr(handle, insn, gprlen);
	case MIPS_INS_JALRC:
		return NULL;
	case MIPS_INS_JALRC_HB:
		return NULL;
	case MIPS_INS_JALRS16:
		return NULL;
	case MIPS_INS_JALRS:
		return NULL;
	case MIPS_INS_JALR_HB:
		return mips_il_jalr(handle, insn, gprlen); // jalr Hazard Barrier
	case MIPS_INS_JALS:
		return NULL;
	case MIPS_INS_JALX:
		return mips_il_jalx(handle, insn, gprlen);
	case MIPS_INS_JIALC:
		return mips_il_jialc(handle, insn, gprlen);
	case MIPS_INS_JIC:
		return mips_il_jic(handle, insn, gprlen);
	case MIPS_INS_JR:
		return mips_il_jr(handle, insn, gprlen);
	case MIPS_INS_JR16:
		return NULL;
	case MIPS_INS_JRADDIUSP:
		return NULL;
	case MIPS_INS_JRC:
		return NULL;
	case MIPS_INS_JRC16:
		return NULL;
	case MIPS_INS_JRCADDIUSP:
		return NULL;
	case MIPS_INS_JR_HB:
		return mips_il_jr(handle, insn, gprlen); // jr Hazard Barrier
	case MIPS_INS_LAPC_H:
		return NULL;
	case MIPS_INS_LAPC_B:
		return NULL;
	case MIPS_INS_LB:
		return mips_il_lb(handle, insn, gprlen);
	case MIPS_INS_LBE:
		return mips_il_lb(handle, insn, gprlen); // Load Byte EVA
	case MIPS_INS_LBU16:
		return NULL;
	case MIPS_INS_LBU:
		return mips_il_lbu(handle, insn, gprlen);
	case MIPS_INS_LBUX:
		return NULL;
	case MIPS_INS_LBX:
		return NULL;
	case MIPS_INS_LBUE:
		return mips_il_lbu(handle, insn, gprlen); // Load Byte Unsigned EVA
	case MIPS_INS_LDC1:
		return mips_il_ldc1(handle, insn, gprlen);
	case MIPS_INS_LDC2:
		return mips_il_ldc2(handle, insn, gprlen);
	case MIPS_INS_LDC3:
		return mips_il_ldxc1(handle, insn, gprlen);
	case MIPS_INS_LDI_B:
		return NULL;
	case MIPS_INS_LDI_D:
		return NULL;
	case MIPS_INS_LDI_H:
		return NULL;
	case MIPS_INS_LDI_W:
		return NULL;
	case MIPS_INS_LDL:
		return mips_il_ldl(handle, insn, gprlen);
	case MIPS_INS_LDPC:
		return mips_il_ldpc(handle, insn, gprlen);
	case MIPS_INS_LDR:
		return mips_il_ldr(handle, insn, gprlen);
	case MIPS_INS_LDXC1:
		return NULL;
	case MIPS_INS_LD_B:
		return NULL;
	case MIPS_INS_LD_D:
		return NULL;
	case MIPS_INS_LD_H:
		return NULL;
	case MIPS_INS_LD_W:
		return NULL;
	case MIPS_INS_LH:
		return mips_il_lh(handle, insn, gprlen);
	case MIPS_INS_LHE:
		return mips_il_lh(handle, insn, gprlen); // Load Half-Word EVA
	case MIPS_INS_LHU16:
		return NULL;
	case MIPS_INS_LHU:
		return mips_il_lhu(handle, insn, gprlen);
	case MIPS_INS_LHUXS:
		return NULL;
	case MIPS_INS_LHUX:
		return NULL;
	case MIPS_INS_LHX:
		return NULL;
	case MIPS_INS_LHXS:
		return NULL;
	case MIPS_INS_LHUE:
		return mips_il_lhu(handle, insn, gprlen); // Load Half-Word Unsigned EVA
	case MIPS_INS_LI16:
		return NULL;
	case MIPS_INS_LL:
		return mips_il_ll(handle, insn, gprlen);
	case MIPS_INS_LLD:
		return mips_il_lld(handle, insn, gprlen);
	case MIPS_INS_LLE:
		return mips_il_ll(handle, insn, gprlen); // Load Linked Word EVA
	case MIPS_INS_LLWP:
		return NULL;
	case MIPS_INS_LSA:
		return mips_il_lsa(handle, insn, gprlen);
	case MIPS_INS_LUI:
		return mips_il_lui(handle, insn, gprlen);
	case MIPS_INS_LUXC1:
		return mips_il_luxc1(handle, insn, gprlen);
	case MIPS_INS_LW:
		return mips_il_lw(handle, insn, gprlen);
	case MIPS_INS_LW16:
		return NULL;
	case MIPS_INS_LWC1:
		return mips_il_lwc1(handle, insn, gprlen);
	case MIPS_INS_LWC2:
		return mips_il_lwc2(handle, insn, gprlen);
	case MIPS_INS_LWC3:
		return NULL;
	case MIPS_INS_LWE:
		return mips_il_lw(handle, insn, gprlen); // Load Word Unsigned EVA
	case MIPS_INS_LWL:
		return mips_il_lwl(handle, insn, gprlen);
	case MIPS_INS_LWLE:
		return mips_il_lwl(handle, insn, gprlen); // Load Word Left EVA
	case MIPS_INS_LWM16:
		return NULL;
	case MIPS_INS_LWM32:
		return NULL;
	case MIPS_INS_LWPC:
		return mips_il_lwpc(handle, insn, gprlen);
	case MIPS_INS_LWP:
		return NULL;
	case MIPS_INS_LWR:
		return mips_il_lwr(handle, insn, gprlen);
	case MIPS_INS_LWRE:
		return mips_il_lwr(handle, insn, gprlen); // Load Word Right EVA
	case MIPS_INS_LWUPC:
		return mips_il_lwupc(handle, insn, gprlen);
	case MIPS_INS_LWU:
		return mips_il_lwu(handle, insn, gprlen);
	case MIPS_INS_LWX:
		return NULL;
	case MIPS_INS_LWXC1:
		return mips_il_lwxc1(handle, insn, gprlen);
	case MIPS_INS_LWXS:
		return NULL;
	case MIPS_INS_MADD:
		return mips_il_madd(handle, insn, gprlen);
	case MIPS_INS_MADDF_D:
		return mips_il_maddf_fmt(handle, insn, gprlen);
	case MIPS_INS_MADDF_S:
		return mips_il_maddf_fmt(handle, insn, gprlen);
	case MIPS_INS_MADDR_Q_H:
		return NULL;
	case MIPS_INS_MADDR_Q_W:
		return NULL;
	case MIPS_INS_MADDU:
		return mips_il_maddu(handle, insn, gprlen);
	case MIPS_INS_MADDV_B:
		return NULL;
	case MIPS_INS_MADDV_D:
		return NULL;
	case MIPS_INS_MADDV_H:
		return NULL;
	case MIPS_INS_MADDV_W:
		return NULL;
	case MIPS_INS_MADD_D:
		return mips_il_madd_fmt(handle, insn, gprlen);
	case MIPS_INS_MADD_Q_H:
		return mips_il_madd_fmt(handle, insn, gprlen);
	case MIPS_INS_MADD_Q_W:
		return mips_il_madd_fmt(handle, insn, gprlen);
	case MIPS_INS_MADD_S:
		return mips_il_madd_fmt(handle, insn, gprlen);
	case MIPS_INS_MAQ_SA_W_PHL:
		return NULL;
	case MIPS_INS_MAQ_SA_W_PHR:
		return NULL;
	case MIPS_INS_MAQ_S_W_PHL:
		return NULL;
	case MIPS_INS_MAQ_S_W_PHR:
		return NULL;
	case MIPS_INS_MAXA_D:
		return mips_il_maxa_fmt(handle, insn, gprlen);
	case MIPS_INS_MAXA_S:
		return mips_il_maxa_fmt(handle, insn, gprlen);
	case MIPS_INS_MAXI_S_B:
		return NULL;
	case MIPS_INS_MAXI_S_D:
		return NULL;
	case MIPS_INS_MAXI_S_H:
		return NULL;
	case MIPS_INS_MAXI_S_W:
		return NULL;
	case MIPS_INS_MAXI_U_B:
		return NULL;
	case MIPS_INS_MAXI_U_D:
		return NULL;
	case MIPS_INS_MAXI_U_H:
		return NULL;
	case MIPS_INS_MAXI_U_W:
		return NULL;
	case MIPS_INS_MAX_A_B:
		return NULL;
	case MIPS_INS_MAX_A_D:
		return NULL;
	case MIPS_INS_MAX_A_H:
		return NULL;
	case MIPS_INS_MAX_A_W:
		return NULL;
	case MIPS_INS_MAX_D:
		return mips_il_max_fmt(handle, insn, gprlen);
	case MIPS_INS_MAX_S:
		return mips_il_max_fmt(handle, insn, gprlen);
	case MIPS_INS_MAX_S_B:
		return NULL;
	case MIPS_INS_MAX_S_D:
		return NULL;
	case MIPS_INS_MAX_S_H:
		return NULL;
	case MIPS_INS_MAX_S_W:
		return NULL;
	case MIPS_INS_MAX_U_B:
		return NULL;
	case MIPS_INS_MAX_U_D:
		return NULL;
	case MIPS_INS_MAX_U_H:
		return NULL;
	case MIPS_INS_MAX_U_W:
		return NULL;
	case MIPS_INS_MFC0:
		return mips_il_mfc0(handle, insn, gprlen);
	case MIPS_INS_MFC1:
		return mips_il_mfc1(handle, insn, gprlen);
	case MIPS_INS_MFC2:
		return mips_il_mfc2(handle, insn, gprlen);
	case MIPS_INS_MFGC0:
		return NULL;
	case MIPS_INS_MFHC0:
		return mips_il_mfhc0(handle, insn, gprlen);
	case MIPS_INS_MFHC1:
		return mips_il_mfhc1(handle, insn, gprlen);
	case MIPS_INS_MFHC2:
		return mips_il_mfhc2(handle, insn, gprlen);
	case MIPS_INS_MFHGC0:
		return NULL;
	case MIPS_INS_MFHI:
		return mips_il_mfhi(handle, insn, gprlen);
	case MIPS_INS_MFHI16:
		return NULL;
	case MIPS_INS_MFLO:
		return mips_il_mflo(handle, insn, gprlen);
	case MIPS_INS_MFLO16:
		return NULL;
	case MIPS_INS_MFTR:
		return NULL;
	case MIPS_INS_MINA_D:
		return mips_il_mina_fmt(handle, insn, gprlen);
	case MIPS_INS_MINA_S:
		return mips_il_mina_fmt(handle, insn, gprlen);
	case MIPS_INS_MINI_S_B:
		return NULL;
	case MIPS_INS_MINI_S_D:
		return NULL;
	case MIPS_INS_MINI_S_H:
		return NULL;
	case MIPS_INS_MINI_S_W:
		return NULL;
	case MIPS_INS_MINI_U_B:
		return NULL;
	case MIPS_INS_MINI_U_D:
		return NULL;
	case MIPS_INS_MINI_U_H:
		return NULL;
	case MIPS_INS_MINI_U_W:
		return NULL;
	case MIPS_INS_MIN_A_B:
		return NULL;
	case MIPS_INS_MIN_A_D:
		return NULL;
	case MIPS_INS_MIN_A_H:
		return NULL;
	case MIPS_INS_MIN_A_W:
		return NULL;
	case MIPS_INS_MIN_D:
		return mips_il_min_fmt(handle, insn, gprlen);
	case MIPS_INS_MIN_S:
		return mips_il_min_fmt(handle, insn, gprlen);
	case MIPS_INS_MIN_S_B:
		return NULL;
	case MIPS_INS_MIN_S_D:
		return NULL;
	case MIPS_INS_MIN_S_H:
		return NULL;
	case MIPS_INS_MIN_S_W:
		return NULL;
	case MIPS_INS_MIN_U_B:
		return NULL;
	case MIPS_INS_MIN_U_D:
		return NULL;
	case MIPS_INS_MIN_U_H:
		return NULL;
	case MIPS_INS_MIN_U_W:
		return NULL;
	case MIPS_INS_MOD:
		return mips_il_mod(handle, insn, gprlen);
	case MIPS_INS_MODSUB:
		return NULL;
	case MIPS_INS_MODU:
		return mips_il_modu(handle, insn, gprlen);
	case MIPS_INS_MOD_S_B:
		return NULL;
	case MIPS_INS_MOD_S_D:
		return NULL;
	case MIPS_INS_MOD_S_H:
		return NULL;
	case MIPS_INS_MOD_S_W:
		return NULL;
	case MIPS_INS_MOD_U_B:
		return NULL;
	case MIPS_INS_MOD_U_D:
		return NULL;
	case MIPS_INS_MOD_U_H:
		return NULL;
	case MIPS_INS_MOD_U_W:
		return NULL;
	case MIPS_INS_MOVE:
		return NULL;
	case MIPS_INS_MOVE16:
		return NULL;
	case MIPS_INS_MOVE_BALC:
		return NULL;
	case MIPS_INS_MOVEP:
		return NULL;
	case MIPS_INS_MOVE_V:
		return NULL;
	case MIPS_INS_MOVF_D:
		return mips_il_movf_fmt(handle, insn, gprlen);
	case MIPS_INS_MOVF:
		return mips_il_movf(handle, insn, gprlen);
	case MIPS_INS_MOVF_S:
		return mips_il_movf_fmt(handle, insn, gprlen);
	case MIPS_INS_MOVN_D:
		return mips_il_movn_fmt(handle, insn, gprlen);
	case MIPS_INS_MOVN:
		return mips_il_movn(handle, insn, gprlen);
	case MIPS_INS_MOVN_S:
		return mips_il_movn_fmt(handle, insn, gprlen);
	case MIPS_INS_MOVT_D:
		return mips_il_movt_fmt(handle, insn, gprlen);
	case MIPS_INS_MOVT:
		return mips_il_movt(handle, insn, gprlen);
	case MIPS_INS_MOVT_S:
		return mips_il_movt_fmt(handle, insn, gprlen);
	case MIPS_INS_MOVZ_D:
		return mips_il_movz_fmt(handle, insn, gprlen);
	case MIPS_INS_MOVZ:
		return mips_il_movz(handle, insn, gprlen);
	case MIPS_INS_MOVZ_S:
		return mips_il_movz_fmt(handle, insn, gprlen);
	case MIPS_INS_MSUB:
		return mips_il_msub(handle, insn, gprlen);
	case MIPS_INS_MSUBF_D:
		return mips_il_msubf_fmt(handle, insn, gprlen);
	case MIPS_INS_MSUBF_S:
		return mips_il_msubf_fmt(handle, insn, gprlen);
	case MIPS_INS_MSUBR_Q_H:
		return NULL;
	case MIPS_INS_MSUBR_Q_W:
		return NULL;
	case MIPS_INS_MSUBU:
		return mips_il_msubu(handle, insn, gprlen);
	case MIPS_INS_MSUBV_B:
		return NULL;
	case MIPS_INS_MSUBV_D:
		return NULL;
	case MIPS_INS_MSUBV_H:
		return NULL;
	case MIPS_INS_MSUBV_W:
		return NULL;
	case MIPS_INS_MSUB_D:
		return mips_il_msub_fmt(handle, insn, gprlen);
	case MIPS_INS_MSUB_Q_H:
		return mips_il_msub_fmt(handle, insn, gprlen);
	case MIPS_INS_MSUB_Q_W:
		return mips_il_msub_fmt(handle, insn, gprlen);
	case MIPS_INS_MSUB_S:
		return mips_il_msub_fmt(handle, insn, gprlen);
	case MIPS_INS_MTC0:
		return mips_il_mtc0(handle, insn, gprlen);
	case MIPS_INS_MTC1:
		return mips_il_mtc1(handle, insn, gprlen);
	case MIPS_INS_MTC2:
		return mips_il_mtc2(handle, insn, gprlen);
	case MIPS_INS_MTGC0:
		return NULL;
	case MIPS_INS_MTHC0:
		return mips_il_mthc0(handle, insn, gprlen);
	case MIPS_INS_MTHC1:
		return mips_il_mthc1(handle, insn, gprlen);
	case MIPS_INS_MTHC2:
		return mips_il_mthc2(handle, insn, gprlen);
	case MIPS_INS_MTHGC0:
		return NULL;
	case MIPS_INS_MTHI:
		return mips_il_mthi(handle, insn, gprlen);
	case MIPS_INS_MTHLIP:
		return NULL;
	case MIPS_INS_MTLO:
		return mips_il_mtlo(handle, insn, gprlen);
	case MIPS_INS_MTM0:
		return NULL;
	case MIPS_INS_MTM1:
		return NULL;
	case MIPS_INS_MTM2:
		return NULL;
	case MIPS_INS_MTP0:
		return NULL;
	case MIPS_INS_MTP1:
		return NULL;
	case MIPS_INS_MTP2:
		return NULL;
	case MIPS_INS_MTTR:
		return NULL;
	case MIPS_INS_MUH:
		return mips_il_muh(handle, insn, gprlen);
	case MIPS_INS_MUHU:
		return mips_il_muhu(handle, insn, gprlen);
	case MIPS_INS_MULEQ_S_W_PHL:
		return NULL;
	case MIPS_INS_MULEQ_S_W_PHR:
		return NULL;
	case MIPS_INS_MULEU_S_PH_QBL:
		return NULL;
	case MIPS_INS_MULEU_S_PH_QBR:
		return NULL;
	case MIPS_INS_MULQ_RS_PH:
		return NULL;
	case MIPS_INS_MULQ_RS_W:
		return NULL;
	case MIPS_INS_MULQ_S_PH:
		return NULL;
	case MIPS_INS_MULQ_S_W:
		return NULL;
	case MIPS_INS_MULR_PS:
		return NULL;
	case MIPS_INS_MULR_Q_H:
		return NULL;
	case MIPS_INS_MULR_Q_W:
		return NULL;
	case MIPS_INS_MULSAQ_S_W_PH:
		return NULL;
	case MIPS_INS_MULSA_W_PH:
		return NULL;
	case MIPS_INS_MULT:
		return mips_il_mult(handle, insn, gprlen);
	case MIPS_INS_MULTU:
		return mips_il_multu(handle, insn, gprlen);
	case MIPS_INS_MULU:
		return mips_il_mulu(handle, insn, gprlen);
	case MIPS_INS_MULV_B:
		return NULL;
	case MIPS_INS_MULV_D:
		return NULL;
	case MIPS_INS_MULV_H:
		return NULL;
	case MIPS_INS_MULV_W:
		return NULL;
	case MIPS_INS_MUL_PH:
		return NULL;
	case MIPS_INS_MUL_Q_H:
		return NULL;
	case MIPS_INS_MUL_Q_W:
		return NULL;
	case MIPS_INS_MUL_S_PH:
		return NULL;
	case MIPS_INS_NLOC_B:
		return NULL;
	case MIPS_INS_NLOC_D:
		return NULL;
	case MIPS_INS_NLOC_H:
		return NULL;
	case MIPS_INS_NLOC_W:
		return NULL;
	case MIPS_INS_NLZC_B:
		return NULL;
	case MIPS_INS_NLZC_D:
		return NULL;
	case MIPS_INS_NLZC_H:
		return NULL;
	case MIPS_INS_NLZC_W:
		return NULL;
	case MIPS_INS_NMADD_D:
		return mips_il_nmadd_fmt(handle, insn, gprlen);
	case MIPS_INS_NMADD_S:
		return mips_il_nmadd_fmt(handle, insn, gprlen);
	case MIPS_INS_NMSUB_D:
		return mips_il_nmsub_fmt(handle, insn, gprlen);
	case MIPS_INS_NMSUB_S:
		return mips_il_nmsub_fmt(handle, insn, gprlen);
	case MIPS_INS_NOP32:
		return NULL;
	case MIPS_INS_NOP:
		return NOP();
	case MIPS_INS_NORI_B:
		return NULL;
	case MIPS_INS_NOR_V:
		return NULL;
	case MIPS_INS_NOT16:
		return NULL;
	case MIPS_INS_NOT:
		return NULL;
	case MIPS_INS_NEG:
		return NULL;
	case MIPS_INS_OR:
		return mips_il_or(handle, insn, gprlen);
	case MIPS_INS_OR16:
		return mips_il_or(handle, insn, gprlen);
	case MIPS_INS_ORI_B:
		return mips_il_ori(handle, insn, gprlen);
	case MIPS_INS_ORI:
		return mips_il_ori(handle, insn, gprlen);
	case MIPS_INS_OR_V:
		return NULL;
	case MIPS_INS_PACKRL_PH:
		return NULL;
	case MIPS_INS_PAUSE:
		return NOP(); // Wait for the LLBit to clear
	case MIPS_INS_PCKEV_B:
		return NULL;
	case MIPS_INS_PCKEV_D:
		return NULL;
	case MIPS_INS_PCKEV_H:
		return NULL;
	case MIPS_INS_PCKEV_W:
		return NULL;
	case MIPS_INS_PCKOD_B:
		return NULL;
	case MIPS_INS_PCKOD_D:
		return NULL;
	case MIPS_INS_PCKOD_H:
		return NULL;
	case MIPS_INS_PCKOD_W:
		return NULL;
	case MIPS_INS_PCNT_B:
		return NULL;
	case MIPS_INS_PCNT_D:
		return NULL;
	case MIPS_INS_PCNT_H:
		return NULL;
	case MIPS_INS_PCNT_W:
		return NULL;
	case MIPS_INS_PICK_PH:
		return NULL;
	case MIPS_INS_PICK_QB:
		return NULL;
	case MIPS_INS_PLL_PS:
		return mips_il_pll_ps(handle, insn, gprlen);
	case MIPS_INS_PLU_PS:
		return mips_il_plu_ps(handle, insn, gprlen);
	case MIPS_INS_POP:
		return NULL;
	case MIPS_INS_PRECEQU_PH_QBL:
		return NULL;
	case MIPS_INS_PRECEQU_PH_QBLA:
		return NULL;
	case MIPS_INS_PRECEQU_PH_QBR:
		return NULL;
	case MIPS_INS_PRECEQU_PH_QBRA:
		return NULL;
	case MIPS_INS_PRECEQ_W_PHL:
		return NULL;
	case MIPS_INS_PRECEQ_W_PHR:
		return NULL;
	case MIPS_INS_PRECEU_PH_QBL:
		return NULL;
	case MIPS_INS_PRECEU_PH_QBLA:
		return NULL;
	case MIPS_INS_PRECEU_PH_QBR:
		return NULL;
	case MIPS_INS_PRECEU_PH_QBRA:
		return NULL;
	case MIPS_INS_PRECRQU_S_QB_PH:
		return NULL;
	case MIPS_INS_PRECRQ_PH_W:
		return NULL;
	case MIPS_INS_PRECRQ_QB_PH:
		return NULL;
	case MIPS_INS_PRECRQ_RS_PH_W:
		return NULL;
	case MIPS_INS_PRECR_QB_PH:
		return NULL;
	case MIPS_INS_PRECR_SRA_PH_W:
		return NULL;
	case MIPS_INS_PRECR_SRA_R_PH_W:
		return NULL;
	case MIPS_INS_PREF:
		return NOP(); // Prefetch
	case MIPS_INS_PREFE:
		return NOP(); // Prefetch EVA
	case MIPS_INS_PREFX:
		return NOP(); // Prefetch Indexed
	case MIPS_INS_PREPEND:
		return NULL;
	case MIPS_INS_PUL_PS:
		return mips_il_pul_ps(handle, insn, gprlen);
	case MIPS_INS_PUU_PS:
		return mips_il_puu_ps(handle, insn, gprlen);
	case MIPS_INS_RADDU_W_QB:
		return NULL;
	case MIPS_INS_RDDSP:
		return NULL;
	case MIPS_INS_RDHWR:
		return mips_il_rdhwr(handle, insn, gprlen);
	case MIPS_INS_RDPGPR:
		return mips_il_rdpgpr(handle, insn, gprlen);
	case MIPS_INS_RECIP_D:
		return mips_il_recip_fmt(handle, insn, gprlen);
	case MIPS_INS_RECIP_S:
		return mips_il_recip_fmt(handle, insn, gprlen);
	case MIPS_INS_REPLV_PH:
		return NULL;
	case MIPS_INS_REPLV_QB:
		return NULL;
	case MIPS_INS_REPL_PH:
		return NULL;
	case MIPS_INS_REPL_QB:
		return NULL;
	case MIPS_INS_RESTORE_JRC:
		return NULL;
	case MIPS_INS_RESTORE:
		return NULL;
	case MIPS_INS_RINT_D:
		return mips_il_rint_fmt(handle, insn, gprlen);
	case MIPS_INS_RINT_S:
		return mips_il_rint_fmt(handle, insn, gprlen);
	case MIPS_INS_ROTR:
		return mips_il_rotr(handle, insn, gprlen);
	case MIPS_INS_ROTRV:
		return mips_il_rotrv(handle, insn, gprlen);
	case MIPS_INS_ROTX:
		return NULL;
	case MIPS_INS_ROUND_L_D:
		return mips_il_round_l_fmt(handle, insn, gprlen);
	case MIPS_INS_ROUND_L_S:
		return mips_il_round_l_fmt(handle, insn, gprlen);
	case MIPS_INS_ROUND_W_D:
		return mips_il_round_w_fmt(handle, insn, gprlen);
	case MIPS_INS_ROUND_W_S:
		return mips_il_round_w_fmt(handle, insn, gprlen);
	case MIPS_INS_RSQRT_D:
		return mips_il_rsqrt_fmt(handle, insn, gprlen);
	case MIPS_INS_RSQRT_S:
		return mips_il_rsqrt_fmt(handle, insn, gprlen);
	case MIPS_INS_SAT_S_B:
		return NULL;
	case MIPS_INS_SAT_S_D:
		return NULL;
	case MIPS_INS_SAT_S_H:
		return NULL;
	case MIPS_INS_SAT_S_W:
		return NULL;
	case MIPS_INS_SAT_U_B:
		return NULL;
	case MIPS_INS_SAT_U_D:
		return NULL;
	case MIPS_INS_SAT_U_H:
		return NULL;
	case MIPS_INS_SAT_U_W:
		return NULL;
	case MIPS_INS_SAVE:
		return NULL;
	case MIPS_INS_SB:
		return mips_il_sb(handle, insn, gprlen);
	case MIPS_INS_SB16:
		return NULL;
	case MIPS_INS_SBE:
		return mips_il_sb(handle, insn, gprlen); // Store Byte EVA
	case MIPS_INS_SBX:
		return NULL;
	case MIPS_INS_SC:
		return mips_il_sc(handle, insn, gprlen);
	case MIPS_INS_SCD:
		return mips_il_scd(handle, insn, gprlen);
	case MIPS_INS_SCE:
		return mips_il_sc(handle, insn, gprlen); // Store Conditional Word EVA
	case MIPS_INS_SCWP:
		return NULL;
	case MIPS_INS_SDBBP:
		return mips_il_sdbbp(handle, insn, gprlen);
	case MIPS_INS_SDBBP16:
		return NULL;
	case MIPS_INS_SDC1:
		return mips_il_sdc1(handle, insn, gprlen);
	case MIPS_INS_SDC2:
		return mips_il_sdc2(handle, insn, gprlen);
	case MIPS_INS_SDC3:
		return NULL;
	case MIPS_INS_SDL:
		return mips_il_sdl(handle, insn, gprlen);
	case MIPS_INS_SDR:
		return mips_il_sdr(handle, insn, gprlen);
	case MIPS_INS_SDXC1:
		return mips_il_sdxc1(handle, insn, gprlen);
	case MIPS_INS_SEB:
		return mips_il_seb(handle, insn, gprlen);
	case MIPS_INS_SEH:
		return mips_il_seh(handle, insn, gprlen);
	case MIPS_INS_SELEQZ:
		return mips_il_seleqz(handle, insn, gprlen);
	case MIPS_INS_SELEQZ_D:
		return mips_il_seleqz_fmt(handle, insn, gprlen);
	case MIPS_INS_SELEQZ_S:
		return mips_il_seleqz_fmt(handle, insn, gprlen);
	case MIPS_INS_SELNEZ:
		return mips_il_selnez(handle, insn, gprlen);
	case MIPS_INS_SELNEZ_D:
		return mips_il_selneqz_fmt(handle, insn, gprlen);
	case MIPS_INS_SELNEZ_S:
		return mips_il_selneqz_fmt(handle, insn, gprlen);
	case MIPS_INS_SEL_D:
		return mips_il_sel_fmt(handle, insn, gprlen);
	case MIPS_INS_SEL_S:
		return mips_il_sel_fmt(handle, insn, gprlen);
	case MIPS_INS_SEQI:
		return NULL;
	case MIPS_INS_SH:
		return mips_il_sh(handle, insn, gprlen);
	case MIPS_INS_SH16:
		return NULL;
	case MIPS_INS_SHE:
		return mips_il_sh(handle, insn, gprlen); // Store Half-Word EVA
	case MIPS_INS_SHF_B:
		return NULL;
	case MIPS_INS_SHF_H:
		return NULL;
	case MIPS_INS_SHF_W:
		return NULL;
	case MIPS_INS_SHILO:
		return NULL;
	case MIPS_INS_SHILOV:
		return NULL;
	case MIPS_INS_SHLLV_PH:
		return NULL;
	case MIPS_INS_SHLLV_QB:
		return NULL;
	case MIPS_INS_SHLLV_S_PH:
		return NULL;
	case MIPS_INS_SHLLV_S_W:
		return NULL;
	case MIPS_INS_SHLL_PH:
		return NULL;
	case MIPS_INS_SHLL_QB:
		return NULL;
	case MIPS_INS_SHLL_S_PH:
		return NULL;
	case MIPS_INS_SHLL_S_W:
		return NULL;
	case MIPS_INS_SHRAV_PH:
		return NULL;
	case MIPS_INS_SHRAV_QB:
		return NULL;
	case MIPS_INS_SHRAV_R_PH:
		return NULL;
	case MIPS_INS_SHRAV_R_QB:
		return NULL;
	case MIPS_INS_SHRAV_R_W:
		return NULL;
	case MIPS_INS_SHRA_PH:
		return NULL;
	case MIPS_INS_SHRA_QB:
		return NULL;
	case MIPS_INS_SHRA_R_PH:
		return NULL;
	case MIPS_INS_SHRA_R_QB:
		return NULL;
	case MIPS_INS_SHRA_R_W:
		return NULL;
	case MIPS_INS_SHRLV_PH:
		return NULL;
	case MIPS_INS_SHRLV_QB:
		return NULL;
	case MIPS_INS_SHRL_PH:
		return NULL;
	case MIPS_INS_SHRL_QB:
		return NULL;
	case MIPS_INS_SHXS:
		return NULL;
	case MIPS_INS_SHX:
		return NULL;
	case MIPS_INS_SIGRIE:
		return NOP(); // Signal Reserved Instruction Exception
	case MIPS_INS_SLDI_B:
		return NULL;
	case MIPS_INS_SLDI_D:
		return NULL;
	case MIPS_INS_SLDI_H:
		return NULL;
	case MIPS_INS_SLDI_W:
		return NULL;
	case MIPS_INS_SLD_B:
		return NULL;
	case MIPS_INS_SLD_D:
		return NULL;
	case MIPS_INS_SLD_H:
		return NULL;
	case MIPS_INS_SLD_W:
		return NULL;
	case MIPS_INS_SLL:
		return mips_il_sll(handle, insn, gprlen);
	case MIPS_INS_SLL16:
		return NULL;
	case MIPS_INS_SLLI_B:
		return NULL;
	case MIPS_INS_SLLI_D:
		return NULL;
	case MIPS_INS_SLLI_H:
		return NULL;
	case MIPS_INS_SLLI_W:
		return NULL;
	case MIPS_INS_SLLV:
		return mips_il_sllv(handle, insn, gprlen);
	case MIPS_INS_SLL_B:
		return NULL;
	case MIPS_INS_SLL_D:
		return NULL;
	case MIPS_INS_SLL_H:
		return NULL;
	case MIPS_INS_SLL_W:
		return NULL;
	case MIPS_INS_SLTIU:
		return mips_il_sltiu(handle, insn, gprlen);
	case MIPS_INS_SLTI:
		return mips_il_slti(handle, insn, gprlen);
	case MIPS_INS_SNEI:
		return NULL;
	case MIPS_INS_SOV:
		return NULL;
	case MIPS_INS_SPLATI_B:
		return NULL;
	case MIPS_INS_SPLATI_D:
		return NULL;
	case MIPS_INS_SPLATI_H:
		return NULL;
	case MIPS_INS_SPLATI_W:
		return NULL;
	case MIPS_INS_SPLAT_B:
		return NULL;
	case MIPS_INS_SPLAT_D:
		return NULL;
	case MIPS_INS_SPLAT_H:
		return NULL;
	case MIPS_INS_SPLAT_W:
		return NULL;
	case MIPS_INS_SRA:
		return mips_il_sra(handle, insn, gprlen);
	case MIPS_INS_SRAI_B:
		return NULL;
	case MIPS_INS_SRAI_D:
		return NULL;
	case MIPS_INS_SRAI_H:
		return NULL;
	case MIPS_INS_SRAI_W:
		return NULL;
	case MIPS_INS_SRARI_B:
		return NULL;
	case MIPS_INS_SRARI_D:
		return NULL;
	case MIPS_INS_SRARI_H:
		return NULL;
	case MIPS_INS_SRARI_W:
		return NULL;
	case MIPS_INS_SRAR_B:
		return NULL;
	case MIPS_INS_SRAR_D:
		return NULL;
	case MIPS_INS_SRAR_H:
		return NULL;
	case MIPS_INS_SRAR_W:
		return NULL;
	case MIPS_INS_SRAV:
		return mips_il_srav(handle, insn, gprlen);
	case MIPS_INS_SRA_B:
		return NULL;
	case MIPS_INS_SRA_D:
		return NULL;
	case MIPS_INS_SRA_H:
		return NULL;
	case MIPS_INS_SRA_W:
		return NULL;
	case MIPS_INS_SRL:
		return mips_il_srl(handle, insn, gprlen);
	case MIPS_INS_SRL16:
		return NULL;
	case MIPS_INS_SRLI_B:
		return NULL;
	case MIPS_INS_SRLI_D:
		return NULL;
	case MIPS_INS_SRLI_H:
		return NULL;
	case MIPS_INS_SRLI_W:
		return NULL;
	case MIPS_INS_SRLRI_B:
		return NULL;
	case MIPS_INS_SRLRI_D:
		return NULL;
	case MIPS_INS_SRLRI_H:
		return NULL;
	case MIPS_INS_SRLRI_W:
		return NULL;
	case MIPS_INS_SRLR_B:
		return NULL;
	case MIPS_INS_SRLR_D:
		return NULL;
	case MIPS_INS_SRLR_H:
		return NULL;
	case MIPS_INS_SRLR_W:
		return NULL;
	case MIPS_INS_SRLV:
		return mips_il_srlv(handle, insn, gprlen);
	case MIPS_INS_SRL_B:
		return NULL;
	case MIPS_INS_SRL_D:
		return NULL;
	case MIPS_INS_SRL_H:
		return NULL;
	case MIPS_INS_SRL_W:
		return NULL;
	case MIPS_INS_SSNOP:
		return NOP(); // Superscalar No Operation
	case MIPS_INS_ST_B:
		return NULL;
	case MIPS_INS_ST_D:
		return NULL;
	case MIPS_INS_ST_H:
		return NULL;
	case MIPS_INS_ST_W:
		return NULL;
	case MIPS_INS_SUB:
		return mips_il_sub(handle, insn, gprlen);
	case MIPS_INS_SUBQH_PH:
		return NULL;
	case MIPS_INS_SUBQH_R_PH:
		return NULL;
	case MIPS_INS_SUBQH_R_W:
		return NULL;
	case MIPS_INS_SUBQH_W:
		return NULL;
	case MIPS_INS_SUBQ_PH:
		return NULL;
	case MIPS_INS_SUBQ_S_PH:
		return NULL;
	case MIPS_INS_SUBQ_S_W:
		return NULL;
	case MIPS_INS_SUBSUS_U_B:
		return NULL;
	case MIPS_INS_SUBSUS_U_D:
		return NULL;
	case MIPS_INS_SUBSUS_U_H:
		return NULL;
	case MIPS_INS_SUBSUS_U_W:
		return NULL;
	case MIPS_INS_SUBSUU_S_B:
		return NULL;
	case MIPS_INS_SUBSUU_S_D:
		return NULL;
	case MIPS_INS_SUBSUU_S_H:
		return NULL;
	case MIPS_INS_SUBSUU_S_W:
		return NULL;
	case MIPS_INS_SUBS_S_B:
		return NULL;
	case MIPS_INS_SUBS_S_D:
		return NULL;
	case MIPS_INS_SUBS_S_H:
		return NULL;
	case MIPS_INS_SUBS_S_W:
		return NULL;
	case MIPS_INS_SUBS_U_B:
		return NULL;
	case MIPS_INS_SUBS_U_D:
		return NULL;
	case MIPS_INS_SUBS_U_H:
		return NULL;
	case MIPS_INS_SUBS_U_W:
		return NULL;
	case MIPS_INS_SUBU16:
		return NULL;
	case MIPS_INS_SUBUH_QB:
		return NULL;
	case MIPS_INS_SUBUH_R_QB:
		return NULL;
	case MIPS_INS_SUBU_PH:
		return NULL;
	case MIPS_INS_SUBU_QB:
		return NULL;
	case MIPS_INS_SUBU_S_PH:
		return NULL;
	case MIPS_INS_SUBU_S_QB:
		return NULL;
	case MIPS_INS_SUBVI_B:
		return NULL;
	case MIPS_INS_SUBVI_D:
		return NULL;
	case MIPS_INS_SUBVI_H:
		return NULL;
	case MIPS_INS_SUBVI_W:
		return NULL;
	case MIPS_INS_SUBV_B:
		return NULL;
	case MIPS_INS_SUBV_D:
		return NULL;
	case MIPS_INS_SUBV_H:
		return NULL;
	case MIPS_INS_SUBV_W:
		return NULL;
	case MIPS_INS_SUXC1:
		return mips_il_suxc1(handle, insn, gprlen);
	case MIPS_INS_SW:
		return mips_il_sw(handle, insn, gprlen);
	case MIPS_INS_SW16:
		return NULL;
	case MIPS_INS_SWC1:
		return mips_il_swc1(handle, insn, gprlen);
	case MIPS_INS_SWC2:
		return mips_il_swc2(handle, insn, gprlen);
	case MIPS_INS_SWC3:
		return NULL;
	case MIPS_INS_SWE:
		return mips_il_sw(handle, insn, gprlen); // Store Word EVA
	case MIPS_INS_SWL:
		return mips_il_swl(handle, insn, gprlen);
	case MIPS_INS_SWLE:
		return mips_il_swl(handle, insn, gprlen); // Store Word Left EVA
	case MIPS_INS_SWM16:
		return NULL;
	case MIPS_INS_SWM32:
		return NULL;
	case MIPS_INS_SWPC:
		return NULL;
	case MIPS_INS_SWP:
		return NULL;
	case MIPS_INS_SWR:
		return mips_il_swr(handle, insn, gprlen);
	case MIPS_INS_SWRE:
		return mips_il_swr(handle, insn, gprlen); // Store Word Right EVA
	case MIPS_INS_SWSP:
		return NULL;
	case MIPS_INS_SWXC1:
		return mips_il_swxc1(handle, insn, gprlen);
	case MIPS_INS_SWXS:
		return NULL;
	case MIPS_INS_SWX:
		return NULL;
	case MIPS_INS_SYNC:
		return NOP(); // Synchronize Caches
	case MIPS_INS_SYNCI:
		return NOP(); // Synchronize Caches to Make Instruction Writes Effective
	case MIPS_INS_SYSCALL:
		return mips_il_syscall(handle, insn, gprlen);
	case MIPS_INS_TEQ:
		return mips_il_teq(handle, insn, gprlen);
	case MIPS_INS_TEQI:
		return mips_il_teqi(handle, insn, gprlen);
	case MIPS_INS_TGE:
		return mips_il_tge(handle, insn, gprlen);
	case MIPS_INS_TGEI:
		return mips_il_tgei(handle, insn, gprlen);
	case MIPS_INS_TGEIU:
		return mips_il_tgeiu(handle, insn, gprlen);
	case MIPS_INS_TGEU:
		return mips_il_tgeu(handle, insn, gprlen);
	case MIPS_INS_TLBGINV:
		return NOP(); // TLB Invalidate
	case MIPS_INS_TLBGINVF:
		return NOP(); // TLB Invalidate Flush
	case MIPS_INS_TLBGP:
		return NULL;
	case MIPS_INS_TLBGR:
		return NULL;
	case MIPS_INS_TLBGWI:
		return NULL;
	case MIPS_INS_TLBGWR:
		return NULL;
	case MIPS_INS_TLBINV:
		return NOP(); // TLB Invalidate
	case MIPS_INS_TLBINVF:
		return NOP(); // TLB Invalidate Flush
	case MIPS_INS_TLBP:
		return NOP(); // Probe TLB for Matching Entry
	case MIPS_INS_TLBR:
		return NOP(); // Read Indexed TLB Entry
	case MIPS_INS_TLBWI:
		return NOP(); // Write Indexed TLB Entry
	case MIPS_INS_TLBWR:
		return NOP(); // Write Random TLB Entry
	case MIPS_INS_TLT:
		return mips_il_tlt(handle, insn, gprlen);
	case MIPS_INS_TLTI:
		return mips_il_tlti(handle, insn, gprlen);
	case MIPS_INS_TLTIU:
		return mips_il_tltiu(handle, insn, gprlen);
	case MIPS_INS_TLTU:
		return mips_il_tltu(handle, insn, gprlen);
	case MIPS_INS_TNE:
		return mips_il_tne(handle, insn, gprlen);
	case MIPS_INS_TNEI:
		return mips_il_tnei(handle, insn, gprlen);
	case MIPS_INS_TRUNC_L_D:
		return mips_il_trunc_l_fmt(handle, insn, gprlen);
	case MIPS_INS_TRUNC_L_S:
		return mips_il_trunc_l_fmt(handle, insn, gprlen);
	case MIPS_INS_UALH:
		return NULL;
	case MIPS_INS_UALWM:
		return NULL;
	case MIPS_INS_UALW:
		return NULL;
	case MIPS_INS_UASH:
		return NULL;
	case MIPS_INS_UASWM:
		return NULL;
	case MIPS_INS_UASW:
		return NULL;
	case MIPS_INS_V3MULU:
		return NULL;
	case MIPS_INS_VMM0:
		return NULL;
	case MIPS_INS_VMULU:
		return NULL;
	case MIPS_INS_VSHF_B:
		return NULL;
	case MIPS_INS_VSHF_D:
		return NULL;
	case MIPS_INS_VSHF_H:
		return NULL;
	case MIPS_INS_VSHF_W:
		return NULL;
	case MIPS_INS_WAIT:
		return NOP(); // Enter Standby Mode
	case MIPS_INS_WRDSP:
		return NULL;
	case MIPS_INS_WRPGPR:
		return mips_il_wrpgpr(handle, insn, gprlen);
	case MIPS_INS_WSBH:
		return mips_il_wsbh(handle, insn, gprlen);
	case MIPS_INS_XOR:
		return mips_il_xor(handle, insn, gprlen);
	case MIPS_INS_XOR16:
		return mips_il_xor(handle, insn, gprlen);
	case MIPS_INS_XORI_B:
		return mips_il_xori(handle, insn, gprlen);
	case MIPS_INS_XORI:
		return mips_il_xori(handle, insn, gprlen);
	case MIPS_INS_XOR_V:
		return NULL;
	case MIPS_INS_YIELD:
	default:
		return NULL;
	}
}

RZ_IPI RzAnalysisILConfig *mips_il_config(RzAnalysis *analysis) {
	// TODO: when RzArch is written this needs to be changed by ptr64..
	RzAnalysisILConfig *r = NULL;
	if (analysis->bits == 64) {
		r = rz_analysis_il_config_new(64, analysis->big_endian, 64);
	} else {
		r = rz_analysis_il_config_new(32, analysis->big_endian, 32);
	}
	return r;
}
#include <rz_il/rz_il_opbuilder_end.h>

#else // CS_NEXT_VERSION < 6
// Capstone before v6 has a very broken MIPS support.
// we cannot support it for RzIL.

RZ_IPI RzILOpEffect *mips_il(RZ_NONNULL const csh *handle, RZ_NONNULL const cs_insn *insn, const ut32 gprlen) {
	return NULL;
}

RZ_IPI RzAnalysisILConfig *mips_il_config(RzAnalysis *analysis) {
	return NULL;
}
#endif // CS_NEXT_VERSION
