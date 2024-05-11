// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2013-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "arm_it.h"

typedef union arm_cs_itblock_t {
	ut8 off[4]; ///< offsets of the up to 4 conditioned instructions from the addr of the it, 0-terminated if less than 4.
	ut64 packed; ///< for putting into HtUU
} ArmCSITBlock;

typedef union arm_cs_itcond_t {
	struct {
		ut32 cond; ///< arm_cc
		ut8 off; ///< offset of this instruction from the it, for back-referencing to the ArmCSITBlock
		ut8 vpt; ///< >0 if it is a VCC condition. 0 otherwise.
	};
	ut64 packed; ///< for putting into HtUU
} ArmCSITCond;

RZ_API void rz_arm_it_context_init(RzArmITContext *ctx) {
	ctx->ht_itcond = ht_uu_new();
	ctx->ht_itblock = ht_uu_new();
}

RZ_API void rz_arm_it_context_fini(RzArmITContext *ctx) {
	ht_uu_free(ctx->ht_itblock);
	ht_uu_free(ctx->ht_itcond);
}

#if CS_NEXT_VERSION < 6
inline static arm_cc ARMCC_getOppositeCondition(arm_cc cc) {
	switch (cc) {
	default:
		// llvm_unreachable("Unknown condition code");
		rz_warn_if_reached();
		return ARM_CC_INVALID;
	case ARM_CC_EQ:
		return ARM_CC_NE;
	case ARM_CC_NE:
		return ARM_CC_EQ;
	case ARM_CC_HS:
		return ARM_CC_LO;
	case ARM_CC_LO:
		return ARM_CC_HS;
	case ARM_CC_MI:
		return ARM_CC_PL;
	case ARM_CC_PL:
		return ARM_CC_MI;
	case ARM_CC_VS:
		return ARM_CC_VC;
	case ARM_CC_VC:
		return ARM_CC_VS;
	case ARM_CC_HI:
		return ARM_CC_LS;
	case ARM_CC_LS:
		return ARM_CC_HI;
	case ARM_CC_GE:
		return ARM_CC_LT;
	case ARM_CC_LT:
		return ARM_CC_GE;
	case ARM_CC_GT:
		return ARM_CC_LE;
	case ARM_CC_LE:
		return ARM_CC_GT;
	}
}
#endif

/**
 * Signal a newly detected IT block
 * \p insn must be ARM_INS_IT
 */
RZ_API void rz_arm_it_update_block(RzArmITContext *ctx, cs_insn *insn) {
#if CS_NEXT_VERSION >= 6
	rz_return_if_fail(ctx && insn && (insn->id == ARM_INS_IT || insn->id == ARM_INS_VPT));
	bool is_vpt = insn->id == ARM_INS_VPT;
#else
	rz_return_if_fail(ctx && insn && (insn->id == ARM_INS_IT));
#endif
	bool found;
	ht_uu_find(ctx->ht_itblock, insn->address, &found);
	if (found) {
		return;
	}
	ArmCSITBlock block = { 0 };
	size_t size = rz_str_nlen(insn->mnemonic, 5);
	for (size_t i = 1; i < size; i++) {
		// At this point, we can't know whether each instruction in the block
		// is 2 or 4 bytes. We build up everything for 2 bytes for now and if
		// we later encounter a 4 byte instruction with a condition inside of it,
		// we readjust everything accordingly.
		ArmCSITCond cond = { 0 };
		cond.off = block.off[i - 1] = 2 * i;
		switch (insn->mnemonic[i]) {
#if CS_NEXT_VERSION >= 6
		case 0x74: //'t'
			cond.cond = is_vpt ? insn->detail->arm.vcc : insn->detail->arm.cc;
			break;
		case 0x65: //'e'
			if (is_vpt) {
				cond.cond = insn->detail->arm.vcc;
			} else if (insn->detail->arm.cc == ARMCC_AL) {
				cond.cond = ARMCC_AL;
			} else {
				cond.cond = ARMCC_getOppositeCondition(insn->detail->arm.cc);
			}
			break;
#else
		case 0x74: //'t'
			cond.cond = insn->detail->arm.cc;
			break;
		case 0x65: //'e'
			if (insn->detail->arm.cc == ARM_CC_AL) {
				cond.cond = ARM_CC_AL;
			} else {
				cond.cond = ARMCC_getOppositeCondition(insn->detail->arm.cc);
			}
			break;
#endif
		default:
			break;
		}
#if CS_NEXT_VERSION >= 6
		cond.vpt = is_vpt ? 1 : 0;
#else
		cond.vpt = 0;
#endif
		RZ_STATIC_ASSERT(sizeof(cond) == sizeof(cond.packed));
		ht_uu_update(ctx->ht_itcond, insn->address + cond.off, cond.packed, NULL);
	}
	RZ_STATIC_ASSERT(sizeof(block) == sizeof(block.packed));
	ht_uu_update(ctx->ht_itblock, insn->address, block.packed, NULL);
}

/**
 * Signal that a non-IT instruction was disassembled and clear any block at the same address.
 */
RZ_API void rz_arm_it_update_nonblock(RzArmITContext *ctx, cs_insn *insn) {
	rz_return_if_fail(ctx && insn);
	bool found;
	ArmCSITBlock block = { .packed = ht_uu_find(ctx->ht_itblock, insn->address, &found) };
	if (!found) {
		return;
	}
	for (size_t i = 0; i < 4 && block.off[i]; i++) {
		ht_uu_delete(ctx->ht_itcond, insn->address + block.off[i]);
	}
	ht_uu_delete(ctx->ht_itblock, insn->address);
}

/**
 * Apply any previously tracked IT condition to \p insn
 * \return true if a condition was found and applied
 */
RZ_API bool rz_arm_it_apply_cond(RzArmITContext *ctx, cs_insn *insn) {
	const ut64 addr = insn->address;
	bool found;
	ArmCSITCond cond = { .packed = ht_uu_find(ctx->ht_itcond, addr, &found) };
	if (!found) {
		return false;
	}
#if CS_NEXT_VERSION >= 6
	if (cond.vpt) {
		insn->detail->arm.vcc = cond.cond;
	} else {
		insn->detail->arm.cc = cond.cond;
	}
#else
	insn->detail->arm.cc = cond.cond;
#endif
	insn->detail->arm.update_flags = 0;

	// Readjust if we detected that the previous assumption of all-2-byte instructions in
	// analysis_itblock() was incorrect. See also the comment there.
	if (insn->size != 4) {
		return true;
	}
	cond.packed = ht_uu_find(ctx->ht_itcond, addr + 2, &found);
	if (!found) {
		// Everything fine, nothing to adjust
		return true;
	}
	// Now readjust everything starting with the addr+2 cond
	ut64 blockaddr = addr + 2 - cond.off;
	ArmCSITBlock itblock = { .packed = ht_uu_find(ctx->ht_itblock, blockaddr, &found) };
	if (!found) {
		return true;
	}
	for (size_t i = 0; i < 4; i++) {
		size_t idx = 3 - i; // Reverse loop so we don't overwrite anything by accident
		if (!itblock.off[idx]) {
			continue;
		}
		if (itblock.off[idx] < cond.off) {
			break;
		}
		ArmCSITCond adjcond = { .packed = ht_uu_find(ctx->ht_itcond, blockaddr + itblock.off[idx], &found) };
		if (!found) {
			continue;
		}
		ht_uu_delete(ctx->ht_itcond, blockaddr + itblock.off[idx]);
		adjcond.off = itblock.off[idx] += 2;
		ht_uu_update(ctx->ht_itcond, blockaddr + itblock.off[idx], adjcond.packed, NULL);
	}
	ht_uu_update(ctx->ht_itblock, blockaddr, itblock.packed, NULL);
	return true;
}
