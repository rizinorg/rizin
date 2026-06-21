// SPDX-FileCopyrightText: 2022 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc_il.h"
#include "capstone.h"
#include "ppc_analysis.h"
#include <capstone/ppc.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_assert.h>
#include <rz_endian.h>
#include <rz_analysis.h>
#include <rz_il.h>
#include <rz_types.h>

RZ_IPI RzAnalysisILConfig *rz_ppc_cs_64_il_config(bool big_endian) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(64, big_endian, 64);
	return r;
}

RZ_IPI RzAnalysisILConfig *rz_ppc_cs_32_il_config(bool big_endian) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(32, big_endian, 32);
	return r;
}

/**
 * \brief Returns true if the given load/store instruction is in X form (uses register RB as second operand).
 *
 * \param insn_id The instruction id.
 * \return bool True if the load/store instruction is in X form. False otherwise.
 */
RZ_IPI bool ppc_is_x_form(ut32 insn_id) {
	switch (insn_id) {
	default:
		return false;
	case PPC_INS_LBZUX:
	case PPC_INS_LBZX:
	case PPC_INS_LDARX:
	case PPC_INS_LDBRX:
	case PPC_INS_LDUX:
	case PPC_INS_LDX:
	case PPC_INS_LHAUX:
	case PPC_INS_LHAX:
	case PPC_INS_LHBRX:
	case PPC_INS_LHZUX:
	case PPC_INS_LHZX:
	case PPC_INS_LWARX:
	case PPC_INS_LWAUX:
	case PPC_INS_LWAX:
	case PPC_INS_LWBRX:
	case PPC_INS_LWZUX:
	case PPC_INS_LWZX:
	case PPC_INS_STBUX:
	case PPC_INS_STHUX:
	case PPC_INS_STWUX:
	case PPC_INS_STDUX:
	case PPC_INS_STBX:
	case PPC_INS_STHX:
	case PPC_INS_STWX:
	case PPC_INS_STDX:
	case PPC_INS_STDCX:
	case PPC_INS_STWCX:
	case PPC_INS_LBZCIX:
	case PPC_INS_LDCIX:
	case PPC_INS_LHZCIX:
	case PPC_INS_LWZCIX:
	case PPC_INS_STBCIX:
	case PPC_INS_STHCIX:
	case PPC_INS_STWCIX:
	case PPC_INS_STDCIX:
		return true;
	}
}

/**
 * \brief Returns the memory access size in bytes for a given load/store instruction.
 *
 * \param insn_id The instruction id.
 * \return st32 The memory access size in bytes.
 * Or 0 if the load instruction does not access the memory.
 * Or -1 if the instruction is no load/store instruction.
 */
RZ_IPI st32 ppc_get_mem_acc_size(ut32 insn_id) {
	switch (insn_id) {
	default:
		RZ_LOG_INFO("Memory access size for instruction %d requested. But it is not in the switch case.\n", insn_id);
		return -1;
	case PPC_INS_LI:
	case PPC_INS_LIS:
		// Doesn't read from memory.
		return 0;
	case PPC_INS_LBZ:
	case PPC_INS_LBZU:
	case PPC_INS_LBZUX:
	case PPC_INS_LBZX:
	case PPC_INS_STB:
	case PPC_INS_STBU:
	case PPC_INS_STBUX:
	case PPC_INS_STBX:
	case PPC_INS_STBCIX:
	case PPC_INS_LBZCIX:
		return PPC_BYTE;
	case PPC_INS_LHA:
	case PPC_INS_LHAU:
	case PPC_INS_LHAUX:
	case PPC_INS_LHAX:
	case PPC_INS_LHBRX:
	case PPC_INS_LHZ:
	case PPC_INS_LHZU:
	case PPC_INS_LHZUX:
	case PPC_INS_LHZX:
	case PPC_INS_STH:
	case PPC_INS_STHBRX:
	case PPC_INS_STHU:
	case PPC_INS_STHUX:
	case PPC_INS_STHX:
	case PPC_INS_LHZCIX:
	case PPC_INS_STHCIX:
		return PPC_HWORD;
	case PPC_INS_LWA:
	case PPC_INS_LWARX:
	case PPC_INS_LWAUX:
	case PPC_INS_LWAX:
	case PPC_INS_LWBRX:
	case PPC_INS_LWZ:
	case PPC_INS_LWZU:
	case PPC_INS_LWZUX:
	case PPC_INS_LWZX:
	case PPC_INS_LMW:
	case PPC_INS_STW:
	case PPC_INS_STWBRX:
	case PPC_INS_STWCX:
	case PPC_INS_STWU:
	case PPC_INS_STWUX:
	case PPC_INS_STWX:
	case PPC_INS_STMW:
	case PPC_INS_LWZCIX:
	case PPC_INS_STWCIX:
		return PPC_WORD;
	case PPC_INS_LD:
	case PPC_INS_LDARX:
	case PPC_INS_LDBRX:
	case PPC_INS_LDU:
	case PPC_INS_LDUX:
	case PPC_INS_LDX:
	case PPC_INS_STD:
	case PPC_INS_STDBRX:
	case PPC_INS_STDCX:
	case PPC_INS_STDU:
	case PPC_INS_STDUX:
	case PPC_INS_STDX:
	case PPC_INS_LDCIX:
	case PPC_INS_STDCIX:
		return PPC_DWORD;
	}
}

/**
 * \brief Returns true if the given load/store instruction updates the RA register with EA after memory access.
 *
 * \param insn_id The instruction id.
 * \return bool True if RA is set to EA after the instruction executed. False otherwise.
 */
RZ_IPI bool ppc_updates_ra_with_ea(ut32 insn_id) {
	switch (insn_id) {
	default:
		return false;
	case PPC_INS_LBZU:
	case PPC_INS_LBZUX:
	case PPC_INS_LDU:
	case PPC_INS_LDUX:
	case PPC_INS_LHAU:
	case PPC_INS_LHAUX:
	case PPC_INS_LHZU:
	case PPC_INS_LHZUX:
	case PPC_INS_LWAUX:
	case PPC_INS_LWZU:
	case PPC_INS_LWZUX:
	case PPC_INS_LFDU:
	case PPC_INS_LFDUX:
	case PPC_INS_LFSU:
	case PPC_INS_LFSUX:
	case PPC_INS_STBU:
	case PPC_INS_STDU:
	case PPC_INS_STHU:
	case PPC_INS_STWU:
	case PPC_INS_STBUX:
	case PPC_INS_STHUX:
	case PPC_INS_STWUX:
	case PPC_INS_STDUX:
	case PPC_INS_STFDU:
	case PPC_INS_STFDUX:
	case PPC_INS_STFSU:
	case PPC_INS_STFSUX:
		return true;
	}
}

/**
 * \brief Returns true if the given load instruction is algebraic.
 *
 * \param insn_id The instruction id.
 * \return bool True if the load instruction is algebraic. False otherwise.
 */
RZ_IPI bool ppc_is_algebraic(ut32 insn_id) {
	switch (insn_id) {
	default:
		return false;
	case PPC_INS_LA:
	case PPC_INS_LDARX:
	case PPC_INS_LHA:
	case PPC_INS_LHAU:
	case PPC_INS_LHAUX:
	case PPC_INS_LHAX:
	case PPC_INS_LWA:
	case PPC_INS_LWAX:
	case PPC_INS_LWARX:
	case PPC_INS_LWAUX:
		return true;
	}
}

/**
 * \brief Returns true if the given branch instruction sets the LR register.
 *
 * \param insn_id The instruction id.
 * \return bool True if the branch instruction writes the LR register. False otherwise.
 */
RZ_IPI bool ppc_insn_sets_lr(const cs_insn *insn) {
	rz_return_val_if_fail(insn, false);
	for (int i = 0; i < insn->detail->regs_write_count; ++i) {
		ppc_reg reg = insn->detail->regs_write[i];
		if (reg == PPC_REG_LR) {
			return true;
		}
	}
	return false;
}

/**
 * \brief Returns true if the given branch instruction sets the LR register.
 *
 * \param insn_id The instruction id.
 * \return bool True if the branch instruction writes the LR register. False otherwise.
 */
RZ_IPI bool ppc_sets_lr(ut32 insn_id) {
	switch (insn_id) {
	default:
		return false;
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	case PPC_INS_BEQCTRL:
	case PPC_INS_BFCTRL:
	case PPC_INS_BGECTRL:
	case PPC_INS_BGTCTRL:
	case PPC_INS_BLECTRL:
	case PPC_INS_BLTCTRL:
	case PPC_INS_BNECTRL:
	case PPC_INS_BNGCTRL:
	case PPC_INS_BNLCTRL:
	case PPC_INS_BNSCTRL:
	case PPC_INS_BNUCTRL:
	case PPC_INS_BSOCTRL:
	case PPC_INS_BTCTRL:
	case PPC_INS_BUNCTRL:
	case PPC_INS_BGEL:
	case PPC_INS_BGELRL:
	case PPC_INS_BGELA:
	case PPC_INS_BDNZL:
	case PPC_INS_BDNZLA:
	case PPC_INS_BDNZLRL:
	case PPC_INS_BDZL:
	case PPC_INS_BDZLA:
	case PPC_INS_BDZLRL:
	case PPC_INS_BDNZTL:
	case PPC_INS_BDNZTLA:
	case PPC_INS_BDNZFL:
	case PPC_INS_BDNZFLA:
	case PPC_INS_BDZTL:
	case PPC_INS_BDZTLA:
	case PPC_INS_BDZFL:
	case PPC_INS_BDZFLA:
#endif
	case PPC_INS_BCCTRL:
	case PPC_INS_BCL:
	case PPC_INS_BCLRL:
	case PPC_INS_BCTRL:
	case PPC_INS_BL:
	case PPC_INS_BLA:
	case PPC_INS_BLRL:
	case PPC_INS_BCLA:
		return true;
	}
}

#if CS_NEXT_VERSION >= 6
/**
 * \brief Returns true if the given branch instruction is conditional.
 *
 * \param insn_id The instruction id.
 * \return bool True if the branch instruction only branches if a condition is met. False otherwise.
 */
RZ_IPI bool ppc_insn_is_conditional(const cs_insn *insn) {
	rz_return_val_if_fail(insn, false);
	return PPC_DETAIL(insn).bc.pred_cr != PPC_PRED_INVALID || PPC_DETAIL(insn).bc.pred_ctr != PPC_PRED_INVALID;
}
#endif

/**
 * \brief Returns true if the given branch instruction is conditional.
 *
 * \param insn_id The instruction id.
 * \return bool True if the branch instruction only branches if a condition is met. False otherwise.
 */
RZ_IPI bool ppc_is_conditional(ut32 insn_id) {
	switch (insn_id) {
	default:
		return false;
	case PPC_INS_BC:
	case PPC_INS_BCCTR:
	case PPC_INS_BCCTRL:
	case PPC_INS_BCL:
	case PPC_INS_BCLR:
	case PPC_INS_BCLRL:
	case PPC_INS_BCA:
	case PPC_INS_BCLA:
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	case PPC_INS_BEQ:
	case PPC_INS_BEQA:
	case PPC_INS_BF:
	case PPC_INS_BFA:
	case PPC_INS_BGE:
	case PPC_INS_BGEA:
	case PPC_INS_BGT:
	case PPC_INS_BGTA:
	case PPC_INS_BLE:
	case PPC_INS_BLEA:
	case PPC_INS_BLT:
	case PPC_INS_BLTA:
	case PPC_INS_BNE:
	case PPC_INS_BNEA:
	case PPC_INS_BNG:
	case PPC_INS_BNGA:
	case PPC_INS_BNL:
	case PPC_INS_BNLA:
	case PPC_INS_BNS:
	case PPC_INS_BNSA:
	case PPC_INS_BNU:
	case PPC_INS_BNUA:
	case PPC_INS_BSO:
	case PPC_INS_BSOA:
	case PPC_INS_BT:
	case PPC_INS_BTA:
	case PPC_INS_BUN:
	case PPC_INS_BUNA:
	case PPC_INS_BGEL:
	case PPC_INS_BGELA:
	case PPC_INS_BGELR:
	case PPC_INS_BGELRL:
	case PPC_INS_BGECTR:
	case PPC_INS_BGECTRL:
	case PPC_INS_BDNZT:
	case PPC_INS_BDNZTL:
	case PPC_INS_BDNZTA:
	case PPC_INS_BDNZTLA:
	case PPC_INS_BDNZF:
	case PPC_INS_BDNZFL:
	case PPC_INS_BDNZFA:
	case PPC_INS_BDNZFLA:
	case PPC_INS_BDZT:
	case PPC_INS_BDZTA:
	case PPC_INS_BDZTL:
	case PPC_INS_BDZTLA:
	case PPC_INS_BDZF:
	case PPC_INS_BDZFA:
	case PPC_INS_BDZFL:
	case PPC_INS_BDZFLA:
	case PPC_INS_BDNZ:
	case PPC_INS_BDNZA:
	case PPC_INS_BDNZLR:
	case PPC_INS_BDNZLRL:
	case PPC_INS_BDZ:
	case PPC_INS_BDZA:
	case PPC_INS_BDZLA:
	case PPC_INS_BDZLR:
	case PPC_INS_BDZLRL:
#endif
		return true;
	}
}

/**
 * \brief Returns true if the given instruction sets a SPR register.
 *
 * \param insn_id The instruction id.
 * \return bool True if the instructions moves a value to a SPR. False otherwise.
 */
RZ_IPI bool ppc_moves_to_spr(ut32 insn_id) {
	switch (insn_id) {
	default:
		return false;
	case PPC_INS_MTCTR:
	case PPC_INS_MTCRF:
	case PPC_INS_MTDCR:
	case PPC_INS_MTFSB0:
	case PPC_INS_MTFSB1:
	case PPC_INS_MTFSF:
	case PPC_INS_MTLR:
	case PPC_INS_MTMSR:
	case PPC_INS_MTMSRD:
	case PPC_INS_MTOCRF:
	case PPC_INS_MTSPR:
	case PPC_INS_MTSR:
	case PPC_INS_MTSRIN:
	case PPC_INS_MTVSCR:
#if CS_NEXT_VERSION < 6
	case PPC_INS_MTCR:
	case PPC_INS_MTBR0:
	case PPC_INS_MTBR1:
	case PPC_INS_MTBR2:
	case PPC_INS_MTBR3:
	case PPC_INS_MTBR4:
	case PPC_INS_MTBR5:
	case PPC_INS_MTBR6:
	case PPC_INS_MTBR7:
	case PPC_INS_MTXER:
	case PPC_INS_MTDSCR:
	case PPC_INS_MTDSISR:
	case PPC_INS_MTDAR:
	case PPC_INS_MTSRR2:
	case PPC_INS_MTSRR3:
	case PPC_INS_MTCFAR:
	case PPC_INS_MTAMR:
	case PPC_INS_MTPID:
	case PPC_INS_MTTBL:
	case PPC_INS_MTTBU:
	case PPC_INS_MTTBLO:
	case PPC_INS_MTTBHI:
	case PPC_INS_MTDBATU:
	case PPC_INS_MTDBATL:
	case PPC_INS_MTIBATU:
	case PPC_INS_MTIBATL:
	case PPC_INS_MTDCCR:
	case PPC_INS_MTICCR:
	case PPC_INS_MTDEAR:
	case PPC_INS_MTESR:
	case PPC_INS_MTSPEFSCR:
	case PPC_INS_MTTCR:
#endif
	case PPC_INS_MFSRIN:
		return true;
	}
}

/**
 * \brief Returns true if the given branch instruction decrements the CTR register.
 *
 * \param insn Instruction id.
 * \param mode Capstone mode.
 * \return bool True if the instruction decrements the counter. False otherwise.
 */
RZ_IPI bool ppc_decrements_ctr(RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, false);
#if CS_NEXT_VERSION >= 6
	return cs_ppc_bc_decr_ctr(PPC_DETAIL(insn).bc.bo);
#else
	ut32 id = insn->id;

	switch (id) {
	default:
		return false;
	case PPC_INS_BC:
	case PPC_INS_BCL:
	case PPC_INS_BCA:
	case PPC_INS_BCLA:
	case PPC_INS_BCLR:
	case PPC_INS_BCLRL:
#if CS_API_MAJOR == 5
	case PPC_INS_BGEL:
	case PPC_INS_BGELA:
#endif
	case PPC_INS_BDNZ:
	case PPC_INS_BDNZA:
	case PPC_INS_BDNZL:
	case PPC_INS_BDNZLA:
	case PPC_INS_BDNZLR:
	case PPC_INS_BDNZLRL:
	case PPC_INS_BDZ:
	case PPC_INS_BDZA:
	case PPC_INS_BDZL:
	case PPC_INS_BDZLA:
	case PPC_INS_BDZLR:
	case PPC_INS_BDZLRL:
		return !(0x4 & PPC_READ_BO_FIELD); // not BO_2
	case PPC_INS_BDNZT:
	case PPC_INS_BDNZTL:
	case PPC_INS_BDNZTA:
	case PPC_INS_BDNZTLA:
	case PPC_INS_BDNZF:
	case PPC_INS_BDNZFL:
	case PPC_INS_BDNZFA:
	case PPC_INS_BDNZFLA:
	case PPC_INS_BDZT:
	case PPC_INS_BDZTA:
	case PPC_INS_BDZTL:
	case PPC_INS_BDZTLA:
	case PPC_INS_BDZF:
	case PPC_INS_BDZFA:
	case PPC_INS_BDZFL:
	case PPC_INS_BDZFLA:
		return true;
	}
#endif
}

//
// IL helper BEGIN
//

#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * \brief Returns the value of the a bit at position \p pos in CR.
 *
 * NOTE: The Condition Register and its fields (cr0-cr7) start at bit 32.
 * The CR reg is not defined for bits at positions smaller than 32 or larger than 63.
 *
 * \param pos The bit position to look up.
 * \return RzILOpBool* The value of the bit at position \p pos in the CR register.
 * Or IL_FALSE for invalid access.
 */
static RZ_OWN RzILOpBool *get_cr_bit(const ut8 pos) {
	if (pos > 63 || pos < 32) {
		RZ_LOG_WARN("Undefined access into CR register.\n");
		return IL_FALSE;
	}
	ut8 field_bit;
	RzILOpPure *cr_field;
	if (pos < 36) {
		field_bit = 0b1000 >> (pos - 32);
		cr_field = VARG("cr0");
	} else if (pos < 40) {
		field_bit = 0b1000 >> (pos - 36);
		cr_field = VARG("cr1");
	} else if (pos < 44) {
		field_bit = 0b1000 >> (pos - 40);
		cr_field = VARG("cr2");
	} else if (pos < 48) {
		field_bit = 0b1000 >> (pos - 44);
		cr_field = VARG("cr3");
	} else if (pos < 52) {
		field_bit = 0b1000 >> (pos - 48);
		cr_field = VARG("cr4");
	} else if (pos < 56) {
		field_bit = 0b1000 >> (pos - 52);
		cr_field = VARG("cr5");
	} else if (pos < 60) {
		field_bit = 0b1000 >> (pos - 56);
		cr_field = VARG("cr6");
	} else {
		field_bit = 0b1000 >> (pos - 60);
		cr_field = VARG("cr7");
	}
	return NON_ZERO(LOGAND(cr_field, UN(4, field_bit)));
}

/**
 * \brief Synchronizes the CR register with the CR0-CR7 registers.
 * Since CR contains CR0-CR7 but are separated in the register profile
 * this function should be called before CR as a whole is read and after it was written.
 *
 * \param to_cr True: CR0-CR7 are copied to CR. False: CR is copied to CR0-CR7 according to \p cr_mask.
 * \param cr_mask Masks the bits which are copied from CR to CR0-CR7. Ignored if \p crx_to_cr == true.
 * \return RzILOpEffect* Sequence of effects to sync the CR/CRx registers.
 */
RZ_IPI RZ_OWN RzILOpEffect *ppc_sync_crx_cr(const bool crx_to_cr, const ut32 cr_mask) {
	RzILOpEffect *effect;
	if (crx_to_cr) {
		effect = SETL("cr", LOGOR(UNSIGNED(32, VARG("cr7")), LOGOR(SHIFTL0(UNSIGNED(32, VARG("cr6")), U8(0x4)), LOGOR(SHIFTL0(UNSIGNED(32, VARG("cr5")), U8(0x8)), LOGOR(SHIFTL0(UNSIGNED(32, VARG("cr4")), U8(0xc)), LOGOR(SHIFTL0(UNSIGNED(32, VARG("cr3")), U8(0x10)), LOGOR(SHIFTL0(UNSIGNED(32, VARG("cr2")), U8(0x14)), LOGOR(SHIFTL0(UNSIGNED(32, VARG("cr1")), U8(0x18)), SHIFTL0(UNSIGNED(32, VARG("cr0")), U8(0x1c))))))))));
		return effect;
	}
	effect = SEQN(10,
		SETL("cr_mask", U32(cr_mask)),
		SETL("crm", LOGAND(VARL("cr"), U32(cr_mask))),
		BRANCH(IS_ZERO(LOGAND(VARL("cr_mask"), U32(0xf))), EMPTY(), SETG("cr7", UNSIGNED(4, VARL("crm")))),
		BRANCH(IS_ZERO(LOGAND(VARL("cr_mask"), U32(0xf0))), EMPTY(), SETG("cr6", UNSIGNED(4, SHIFTR0(VARL("crm"), U8(0x4))))),
		BRANCH(IS_ZERO(LOGAND(VARL("cr_mask"), U32(0xf00))), EMPTY(), SETG("cr5", UNSIGNED(4, SHIFTR0(VARL("crm"), U8(0x8))))),
		BRANCH(IS_ZERO(LOGAND(VARL("cr_mask"), U32(0xf000))), EMPTY(), SETG("cr4", UNSIGNED(4, SHIFTR0(VARL("crm"), U8(0xc))))),
		BRANCH(IS_ZERO(LOGAND(VARL("cr_mask"), U32(0xf0000))), EMPTY(), SETG("cr3", UNSIGNED(4, SHIFTR0(VARL("crm"), U8(0x10))))),
		BRANCH(IS_ZERO(LOGAND(VARL("cr_mask"), U32(0xf00000))), EMPTY(), SETG("cr2", UNSIGNED(4, SHIFTR0(VARL("crm"), U8(0x14))))),
		BRANCH(IS_ZERO(LOGAND(VARL("cr_mask"), U32(0xf000000))), EMPTY(), SETG("cr1", UNSIGNED(4, SHIFTR0(VARL("crm"), U8(0x18))))),
		BRANCH(IS_ZERO(LOGAND(VARL("cr_mask"), U32(0xf0000000))), EMPTY(), SETG("cr0", UNSIGNED(4, SHIFTR0(VARL("crm"), U8(0x1c))))));
	return effect;
}

/**
 * \brief Returns the mask for a given fxm operand.
 * For details look up the "mtcrf" instruction in the Power ISA
 *
 * \param fmx The fmx value.
 * \return ut32 The mask for writing to the CR register.
 */
RZ_IPI ut32 ppc_fmx_to_mask(const ut8 fmx) {
	ut32 x = 0xf;
	return (
		(fmx & 0x80 ? x << 28 : 0) |
		(fmx & 0x40 ? x << 24 : 0) |
		(fmx & 0x20 ? x << 20 : 0) |
		(fmx & 0x10 ? x << 16 : 0) |
		(fmx & 0x08 ? x << 12 : 0) |
		(fmx & 0x04 ? x << 8 : 0) |
		(fmx & 0x02 ? x << 4 : 0) |
		(fmx & 0x01 ? x : 0));
}

#if CS_NEXT_VERSION < 6
static const char *get_crx_reg(const csh handle, cs_insn *insn, size_t n) {
#if CS_API_MAJOR == 5 && CS_API_MINOR == 0
	// bug on crx not being populated in capstone v5.0
	ppc_reg reg = INSOP(n).reg;
	if (reg >= PPC_REG_CR0EQ && reg <= PPC_REG_CR7EQ) {
		reg = (reg - PPC_REG_CR0EQ) + PPC_REG_CR0;
	} else if (reg >= PPC_REG_CR0GT && reg <= PPC_REG_CR7GT) {
		reg = (reg - PPC_REG_CR0GT) + PPC_REG_CR0;
	} else if (reg >= PPC_REG_CR0LT && reg <= PPC_REG_CR7LT) {
		reg = (reg - PPC_REG_CR0LT) + PPC_REG_CR0;
	} else if (reg >= PPC_REG_CR0UN && reg <= PPC_REG_CR7UN) {
		reg = (reg - PPC_REG_CR0UN) + PPC_REG_CR0;
	} else {
		rz_warn_if_reached();
	}
	return cs_reg_name(handle, reg);
#else
	return cs_reg_name(handle, INSOP(n).crx.reg);
#endif
}

static ut32 get_crx_cond(const csh handle, cs_insn *insn, size_t n) {
#if CS_API_MAJOR == 5 && CS_API_MINOR == 0
	// bug on crx not being populated in capstone v5.0
	ppc_reg reg = INSOP(n).reg;
	if (reg >= PPC_REG_CR0EQ && reg <= PPC_REG_CR7EQ) {
		return PPC_BC_EQ;
	} else if (reg >= PPC_REG_CR0GT && reg <= PPC_REG_CR7GT) {
		return PPC_BC_GT;
	} else if (reg >= PPC_REG_CR0LT && reg <= PPC_REG_CR7LT) {
		return PPC_BC_LT;
	} else if (reg >= PPC_REG_CR0UN && reg <= PPC_REG_CR7UN) {
		return PPC_BC_UN;
	}
	rz_warn_if_reached();
	return PPC_BC_INVALID;
#else
	return INSOP(n).crx.cond;
#endif
}
#endif

/**
 * \brief Get the branch condition for a given instruction.
 * Checkout the "Simple Branch Mnemonics" in Appendix C in PowerISA v3.1B and
 * the chapter about branch instructions for an overview of possible conditions.
 *
 * NOTE: This function *does not* decrement CTR, if required by the instruction.
 * This should have been done before.
 *
 * \param insn The capstone instructions.
 * \param mode The capstone mode.
 * \return RzILOpPure* The condition the branch occurs as a Pure.
 */
RZ_IPI RZ_OWN RzILOpPure *ppc_get_branch_cond(const csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	ut32 id = insn->id;

#if CS_NEXT_VERSION >= 6
	ut8 bi = PPC_DETAIL(insn).bc.bi;
	ut8 bo = PPC_DETAIL(insn).bc.bo;
	RzILOpBool *decr_ctr = cs_ppc_bc_decr_ctr(bo) ? IL_TRUE : IL_FALSE;
	RzILOpBool *test_cr_bit = cs_ppc_bc_cr_is_tested(bo) ? IL_TRUE : IL_FALSE;
	RzILOpBool *check_ctr_is_zero = cs_ppc_bc_tests_ctr_is_zero(bo) ? IL_TRUE : IL_FALSE;
	RzILOpBool *check_cr_bit_is_one = cs_ppc_bc_cr_bit_is_one(bo) ? IL_TRUE : IL_FALSE;
#else
	ut8 bo = PPC_READ_BO_FIELD;
	ut8 bi = PPC_READ_BI_FIELD;
	RzILOpPure *bo_0;
	RzILOpPure *bo_1;
	RzILOpPure *bo_2;
	RzILOpPure *bo_3;
	RzILOpPure *cr;
	RzILOpPure *cr_bit;
#endif
	RzILOpPure *ctr_cond_fullfilled;
	RzILOpPure *cr_cond_fullfilled;

	switch (id) {
	default:
		RZ_LOG_WARN("Instruction %d has no condition implemented.\n", id);
		return IL_FALSE;
		// For learning how the conditions of BCxxx branch instructions are
		// formed see the Power ISA
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	case PPC_INS_BEQ:
	case PPC_INS_BEQA:
	case PPC_INS_BF:
	case PPC_INS_BFA:
	case PPC_INS_BGE:
	case PPC_INS_BGEA:
	case PPC_INS_BGT:
	case PPC_INS_BGTA:
	case PPC_INS_BLE:
	case PPC_INS_BLEA:
	case PPC_INS_BLT:
	case PPC_INS_BLTA:
	case PPC_INS_BNE:
	case PPC_INS_BNEA:
	case PPC_INS_BNG:
	case PPC_INS_BNGA:
	case PPC_INS_BNL:
	case PPC_INS_BNLA:
	case PPC_INS_BNS:
	case PPC_INS_BNSA:
	case PPC_INS_BNU:
	case PPC_INS_BNUA:
	case PPC_INS_BSO:
	case PPC_INS_BSOA:
	case PPC_INS_BT:
	case PPC_INS_BTA:
	case PPC_INS_BUN:
	case PPC_INS_BUNA:
	case PPC_INS_BGEL:
	case PPC_INS_BGELA:
	case PPC_INS_BGELR:
	case PPC_INS_BGELRL:
#endif
	case PPC_INS_BC:
	case PPC_INS_BCL:
	case PPC_INS_BCA:
	case PPC_INS_BCLA:
	case PPC_INS_BCLR:
	case PPC_INS_BCLRL:
#if CS_NEXT_VERSION >= 6
		ctr_cond_fullfilled = ITE(decr_ctr, XOR(NON_ZERO(VARG("ctr")), check_ctr_is_zero), IL_TRUE);
		cr_cond_fullfilled = ITE(test_cr_bit, XOR(get_cr_bit(bi + 32), INV(check_cr_bit_is_one)), IL_TRUE);
		return AND(ctr_cond_fullfilled, cr_cond_fullfilled);
#else
		// BO_2 == 0: Decrement CTR
		// BO_2 == 1: Don't use CTR
		bo_2 = NON_ZERO(LOGAND(UN(5, 0b00100), VARLP("bo")));

		// BO_3 == 0: Check CTR != 0
		// BO_3 == 1: Check CTR == 0
		bo_3 = NON_ZERO(LOGAND(UN(5, 0b00010), VARLP("bo")));
		ctr_cond_fullfilled = OR(bo_2, XOR(NON_ZERO(VARG("ctr")), bo_3)); // BO_2 | (CTR_M:63 ≠ 0) ⊕ BO_3

		// BO_0 == 0: Check CR_bi
		// BO_0 == 1: Don't check CR_bi
		bo_0 = NON_ZERO(LOGAND(UN(5, 0b10000), VARLP("bo")));

		// BO_1 == 0: Check CR_bi == 0
		// BO_1 == 1: Check CR_bi == 1
		bo_1 = NON_ZERO(LOGAND(UN(5, 0b01000), VARLP("bo")));
		cr_cond_fullfilled = OR(bo_0, XOR(get_cr_bit(bi + 32), INV(bo_1))); //  BO_0 | (CR_BI+32 ≡ BO_1)
		return LET("bo", UN(5, bo), AND(cr_cond_fullfilled, ctr_cond_fullfilled));
#endif
	case PPC_INS_BCCTR:
	case PPC_INS_BCCTRL:
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	case PPC_INS_BEQCTR:
	case PPC_INS_BEQCTRL:
	case PPC_INS_BFCTR:
	case PPC_INS_BFCTRL:
	case PPC_INS_BGTCTR:
	case PPC_INS_BGTCTRL:
	case PPC_INS_BLECTR:
	case PPC_INS_BLECTRL:
	case PPC_INS_BLTCTR:
	case PPC_INS_BLTCTRL:
	case PPC_INS_BNECTR:
	case PPC_INS_BNECTRL:
	case PPC_INS_BNGCTR:
	case PPC_INS_BNGCTRL:
	case PPC_INS_BNLCTR:
	case PPC_INS_BNLCTRL:
	case PPC_INS_BNSCTR:
	case PPC_INS_BNSCTRL:
	case PPC_INS_BNUCTR:
	case PPC_INS_BNUCTRL:
	case PPC_INS_BSOCTR:
	case PPC_INS_BSOCTRL:
	case PPC_INS_BTCTR:
	case PPC_INS_BTCTRL:
	case PPC_INS_BUNCTR:
	case PPC_INS_BUNCTRL:
	case PPC_INS_BGECTR:
	case PPC_INS_BGECTRL:
#endif
#if CS_NEXT_VERSION >= 6
		cr_cond_fullfilled = AND(test_cr_bit, XOR(get_cr_bit(bi + 32), INV(check_cr_bit_is_one)));
		return cr_cond_fullfilled;
#else
		bo_0 = NON_ZERO(LOGAND(UN(5, 0b10000), VARLP("bo")));
		bo_1 = NON_ZERO(LOGAND(UN(5, 0b01000), VARLP("bo")));
		cr_cond_fullfilled = OR(bo_0, XOR(get_cr_bit(bi + 32), INV(bo_1))); //  BO_0 | (CR_BI+32 ≡ BO_1)

		return LET("bo", UN(5, bo), cr_cond_fullfilled);
	// CTR != 0
	case PPC_INS_BDNZ:
	case PPC_INS_BDNZA:
	case PPC_INS_BDNZL:
	case PPC_INS_BDNZLA:
	case PPC_INS_BDNZLR:
	case PPC_INS_BDNZLRL:
		return NON_ZERO(VARG("ctr"));
	// CTR == 0
	case PPC_INS_BDZ:
	case PPC_INS_BDZA:
	case PPC_INS_BDZL:
	case PPC_INS_BDZLA:
	case PPC_INS_BDZLR:
	case PPC_INS_BDZLRL:
		return IS_ZERO(VARG("ctr"));
	// ctr != 0 && cr_bi == 1
	case PPC_INS_BDNZT:
	case PPC_INS_BDNZTL:
	case PPC_INS_BDNZTA:
	case PPC_INS_BDNZTLA:
	// ctr == 0 && cr_bi == 1
	case PPC_INS_BDZT:
	case PPC_INS_BDZTL:
	case PPC_INS_BDZTA:
	case PPC_INS_BDZTLA:
		if (insn->detail->ppc.op_count == 1) {
			// If Capstone doesn't provide a CR register it means that the LT bit in cr0 is checked.
			cr = VARG("cr0");
			// LT bit
			cr_bit = UN(4, 8);
		} else {
			cr = VARG(get_crx_reg(handle, insn, 0));
			ut32 cond = get_crx_cond(handle, insn, 0);
			cr_bit = UN(4, ((cond & PPC_BC_SO) ? 1 : ((cond & PPC_BC_EQ) ? 2 : ((cond & PPC_BC_GT) ? 4 : 8))));
		}
		if (id == PPC_INS_BDZT || id == PPC_INS_BDZTL || id == PPC_INS_BDZTA || id == PPC_INS_BDZTLA) {
			return AND(IS_ZERO(VARG("ctr")), NON_ZERO(LOGAND(cr, cr_bit)));
		}
		return AND(NON_ZERO(VARG("ctr")), NON_ZERO(LOGAND(cr, cr_bit)));
	// ctr != 0 && cr_bi == 0
	case PPC_INS_BDNZF:
	case PPC_INS_BDNZFL:
	case PPC_INS_BDNZFA:
	case PPC_INS_BDNZFLA:
	// ctr == 0 && cr_bi == 0
	case PPC_INS_BDZF:
	case PPC_INS_BDZFL:
	case PPC_INS_BDZFA:
	case PPC_INS_BDZFLA:
		if (insn->detail->ppc.op_count == 1) {
			cr = VARG("cr0");
			cr_bit = UN(4, 8);
		} else {
			cr = VARG(get_crx_reg(handle, insn, 0));
			ut32 cond = get_crx_cond(handle, insn, 0);
			cr_bit = UN(4, ((cond & PPC_BC_SO) ? 1 : ((cond & PPC_BC_EQ) ? 2 : ((cond & PPC_BC_GT) ? 4 : 8))));
		}
		cr = insn->detail->ppc.op_count == 1 ? VARG("cr0") : VARG(get_crx_reg(handle, insn, 0));
		if (id == PPC_INS_BDZF || id == PPC_INS_BDZFL || id == PPC_INS_BDZFA || id == PPC_INS_BDZFLA) {
			return AND(IS_ZERO(VARG("ctr")), IS_ZERO(LOGAND(cr, cr_bit)));
		}
		return AND(NON_ZERO(VARG("ctr")), IS_ZERO(LOGAND(cr, cr_bit)));
#endif
	}
}

/**
 * \brief Get the branch instruction's target address.
 * In case of conditional branches it returns the address if the condition would be fulfilled.
 *
 * There are five types of target addresses:
 * * Absolute address
 * * Relative address (relative to current instruction address)
 * * Address stored in LR
 * * Address stored in CTR
 * * Address stored in TAR
 *
 * NOTE: Capstone calculates the NIA and fills the operand member with it.
 * We don't need to do the shift, add and extend here.
 *
 * \param insn The capstone instructions.
 * \param mode The capstone mode.
 * \return RzILOpPure* The target address of the jump.
 */
RZ_IPI RZ_OWN RzILOpPure *ppc_get_branch_ta(RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	ut32 id = insn->id;

	switch (id) {
	default:
		RZ_LOG_WARN("Target address of branch instruction %d can not be resolved.\n", id);
		return UA(0);
	// Target address is pre-calculated by Capstone and stored in INSOP().imm
	// The comments show only the TA calculation according to the ISA.
	// Banch to absolute address
	case PPC_INS_BA:
	case PPC_INS_BLA:
	case PPC_INS_BCA:
	case PPC_INS_BCLA:
#if CS_NEXT_VERSION < 6
	case PPC_INS_BDNZTA:
	case PPC_INS_BDNZTLA:
	case PPC_INS_BDNZFA:
	case PPC_INS_BDNZFLA:
	case PPC_INS_BDZTA:
	case PPC_INS_BDZTLA:
	case PPC_INS_BDZFA:
	case PPC_INS_BDZFLA:
#endif
		// EXTS(LI || 0b00)
		// Branch to relative address
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	case PPC_INS_BEQ:
	case PPC_INS_BEQA:
	case PPC_INS_BF:
	case PPC_INS_BFA:
	case PPC_INS_BGE:
	case PPC_INS_BGEA:
	case PPC_INS_BGT:
	case PPC_INS_BGTA:
	case PPC_INS_BLE:
	case PPC_INS_BLEA:
	case PPC_INS_BLT:
	case PPC_INS_BLTA:
	case PPC_INS_BNE:
	case PPC_INS_BNEA:
	case PPC_INS_BNG:
	case PPC_INS_BNGA:
	case PPC_INS_BNL:
	case PPC_INS_BNLA:
	case PPC_INS_BNS:
	case PPC_INS_BNSA:
	case PPC_INS_BNU:
	case PPC_INS_BNUA:
	case PPC_INS_BSO:
	case PPC_INS_BSOA:
	case PPC_INS_BT:
	case PPC_INS_BTA:
	case PPC_INS_BUN:
	case PPC_INS_BUNA:
#endif
	case PPC_INS_B:
	case PPC_INS_BL:
#if CS_NEXT_VERSION < 6
	case PPC_INS_BDZF:
	case PPC_INS_BDZFL:
	case PPC_INS_BDZT:
	case PPC_INS_BDZTL:
	case PPC_INS_BDNZF:
	case PPC_INS_BDNZFL:
	case PPC_INS_BDNZT:
	case PPC_INS_BDNZTL:
#endif
		// CIA + EXTS(LI || 0b00)
		if (insn->detail->ppc.op_count == 2) {
			return UA(INSOP(1).imm);
		} else {
			return UA(INSOP(0).imm);
		}
#if CS_NEXT_VERSION < 6
	case PPC_INS_BDZA:
	case PPC_INS_BDZLA:
	case PPC_INS_BDNZA:
	case PPC_INS_BDNZLA:
#endif
		// EXTS(BD || 0b00)
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	case PPC_INS_BGEL:
	case PPC_INS_BGELA:
#endif
	case PPC_INS_BC:
	case PPC_INS_BCL:
#if CS_NEXT_VERSION >= 6
		return UA(INSOP(2).imm);
#else
	case PPC_INS_BDZ:
	case PPC_INS_BDZL:
	case PPC_INS_BDNZ:
	case PPC_INS_BDNZL:
		// If bits in cr0 are checked, the opcount is 1.
		// CIA + EXTS(BD || 0b00)
		if (insn->detail->ppc.op_count == 2) {
			return UA(INSOP(1).imm);
		} else {
			return UA(INSOP(0).imm);
		}
#endif
		// Branch to LR
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	case PPC_INS_BEQLR:
	case PPC_INS_BEQLRL:
	case PPC_INS_BLELR:
	case PPC_INS_BLELRL:
	case PPC_INS_BLTLR:
	case PPC_INS_BLTLRL:
	case PPC_INS_BGELR:
	case PPC_INS_BGELRL:
#endif
	case PPC_INS_BLR:
	case PPC_INS_BLRL:
	case PPC_INS_BCLR:
	case PPC_INS_BCLRL:
#if CS_NEXT_VERSION < 6
	case PPC_INS_BDZLR:
	case PPC_INS_BDZLRL:
	case PPC_INS_BDNZLR:
	case PPC_INS_BDNZLRL:
#endif
		//  LR_0:61 || 0b00
		return LOGAND(UA(-4), VARG("lr"));
		// Branch to CTR
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	case PPC_INS_BEQCTR:
	case PPC_INS_BEQCTRL:
	case PPC_INS_BFCTR:
	case PPC_INS_BFCTRL:
	case PPC_INS_BGECTR:
	case PPC_INS_BGECTRL:
	case PPC_INS_BGTCTR:
	case PPC_INS_BGTCTRL:
	case PPC_INS_BLECTR:
	case PPC_INS_BLECTRL:
	case PPC_INS_BLTCTR:
	case PPC_INS_BLTCTRL:
	case PPC_INS_BNECTR:
	case PPC_INS_BNECTRL:
	case PPC_INS_BNGCTR:
	case PPC_INS_BNGCTRL:
	case PPC_INS_BNLCTR:
	case PPC_INS_BNLCTRL:
	case PPC_INS_BNSCTR:
	case PPC_INS_BNSCTRL:
	case PPC_INS_BNUCTR:
	case PPC_INS_BNUCTRL:
	case PPC_INS_BSOCTR:
	case PPC_INS_BSOCTRL:
	case PPC_INS_BTCTR:
	case PPC_INS_BTCTRL:
	case PPC_INS_BUNCTR:
	case PPC_INS_BUNCTRL:
#endif
	case PPC_INS_BCTR:
	case PPC_INS_BCTRL:
	case PPC_INS_BCCTR:
	case PPC_INS_BCCTRL:
		//  CTR_0:61 || 0b00
		return LOGAND(UA(-4), VARG("ctr"));
	}
}

/**
 * \brief Returns true if the multiplication instruction operates on double words.
 *
 * \param id The instruction id.
 * \param mode The Capstone mode.
 * \return bool True if the instruction operates on double words. False otherwise;
 */
RZ_IPI bool ppc_is_mul_div_d(const ut32 id, const cs_mode mode) {
	return id == PPC_INS_MULHD || id == PPC_INS_MULLD || id == PPC_INS_MULHDU ||
		id == PPC_INS_DIVD || id == PPC_INS_DIVDU || ((id == PPC_INS_MULLI) && IN_64BIT_MODE);
}

/**
 * \brief Returns true if the division instruction operates on double words.
 *
 * \param id The instruction id.
 * \param mode The Capstone mode.
 * \return bool True if the instruction operates on double words. False otherwise;
 */
RZ_IPI bool ppc_is_mul_div_u(const ut32 id) {
	return id == PPC_INS_MULHDU || id == PPC_INS_MULHWU || id == PPC_INS_DIVWU || id == PPC_INS_DIVDU;
}

/**
 * \brief Assembles the current XER value by combining the values
 * from the flag registers "so", "ov", "ca".
 *
 * \param mode The capstone mode.
 * \return RzILOpPure* The Pure containing the current XER value.
 */
RZ_IPI RZ_OWN RzILOpPure *ppc_get_xer(cs_mode mode) {
	RzILOpPure *so = SHIFTL0(EXTZ(BOOL_TO_BV(VARG("so"), 1)), U8(31));
	RzILOpPure *ov = SHIFTL0(EXTZ(BOOL_TO_BV(VARG("ov"), 1)), U8(30));
	RzILOpPure *ca = SHIFTL0(EXTZ(BOOL_TO_BV(VARG("ca"), 1)), U8(29));
	// For ISA v3 CPUs register ca32 and ov32 should be handled here as well.
	// Currently they are ignored. If you want to add them take a look at:
	// https://github.com/Rot127/rizin/tree/Examples-ppc-rzil-isav3-regs
	return LOGOR(LOGOR(so, ov), ca);
}

/**
 * \brief Sets the XER register to \p val and updates the flag register "so", "ov", "ca" accordingly.
 *
 * \param val The new value of XER.
 * \param mode The capstone mode.
 * \return RzILOpEffect* The sequence of effects setting all registers to their respective values.
 */
RZ_IPI RZ_OWN RzILOpEffect *ppc_set_xer(RzILOpPure *val, cs_mode mode) {
	rz_return_val_if_fail(val, NULL);
	RzILOpPure *v = LOGAND(BIT_MASK(64, U8(32), U8(34)), UNSIGNED(64, val));
	return SEQ5(SETL("v", v), SETG("xer", VARL("v")),
		SETG("so", BIT_IS_SET(VARL("v"), 64, U8(32))),
		SETG("ov", BIT_IS_SET(VARL("v"), 64, U8(33))),
		SETG("ca", BIT_IS_SET(VARL("v"), 64, U8(34))));
	// For ISA v3 CPUs register ca32 and ov32 should be handled here as well.
	// Currently they are ignored. If you want to add them take a look at:
	// https://github.com/Rot127/rizin/tree/Examples-ppc-rzil-isav3-regs
}

#include <rz_il/rz_il_opbuilder_end.h>

//
// IL helper END
//