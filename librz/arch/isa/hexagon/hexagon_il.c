// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: b6f51787f6c8e77143f0aef6b58ddc7c55741d5c
// LLVM commit date: 2023-11-15 07:10:59 -0800 (ISO 8601 format)
// Date of code generation: 2024-03-16 06:22:39-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <hexagon/hexagon.h>
#include <hexagon/hexagon_il.h>
#include <hexagon/hexagon_il_getter_table.h>
#include <hexagon/hexagon_arch.h>
#include <rz_list.h>
#include <rz_vector.h>
#include <rz_types.h>
#include <rz_util/rz_assert.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_il/rz_il_opbuilder_begin.h>

static HexILOp hex_jump_flag_init_op = {
	.attr = HEX_IL_INSN_ATTR_NONE,
	.get_il_op = (HexILOpGetter)hex_il_op_jump_flag_init,
};

static HexILOp hex_next_jump_to_next_pkt = {
	.attr = HEX_IL_INSN_ATTR_BRANCH | HEX_IL_INSN_ATTR_COND,
	.get_il_op = (HexILOpGetter)hex_il_op_next_pkt_jmp,
};

static HexILOp hex_pkt_commit = {
	.attr = HEX_IL_INSN_ATTR_NONE,
	.get_il_op = (HexILOpGetter)hex_commit_packet,
};

static HexILOp hex_endloop0_op = {
	.attr = HEX_IL_INSN_ATTR_BRANCH | HEX_IL_INSN_ATTR_COND,
	.get_il_op = (HexILOpGetter)hex_il_op_j2_endloop0,
};

static HexILOp hex_endloop1_op = {
	.attr = HEX_IL_INSN_ATTR_BRANCH | HEX_IL_INSN_ATTR_COND,
	.get_il_op = (HexILOpGetter)hex_il_op_j2_endloop1,
};

static HexILOp hex_endloop01_op = {
	.attr = HEX_IL_INSN_ATTR_BRANCH | HEX_IL_INSN_ATTR_COND,
	.get_il_op = (HexILOpGetter)hex_il_op_j2_endloop01,
};

/**
 * \brief Sends the IL op at \p start to the position \p newloc.
 *
 * Note: This is a copy of the same function implemented by Qualcomm in QEMU.
 * See: https://gitlab.com/qemu-project/qemu/-/blob/master/target/hexagon/decode.c :: decode_send_insn_to
 *
 * \param ops The IL ops list.
 * \param start Index of the op to move.
 * \param newloc Position the op shall be moved to.
 */
static void hex_send_insn_to_i(RzPVector /*<HexILOp *>*/ *ops, ut8 start, ut8 newloc) {
	rz_return_if_fail(ops && newloc < rz_pvector_len(ops));

	st32 direction;
	if (start == newloc) {
		return;
	}
	if (start < newloc) {
		/* Move towards end */
		direction = 1;
	} else {
		/* move towards beginning */
		direction = -1;
	}
	for (st32 i = start; i != newloc; i += direction) {
		HexILOp *neighbor_op = (HexILOp *)rz_pvector_at(ops, i + direction);
		HexILOp *to_move_op = (HexILOp *)rz_pvector_at(ops, i);
		rz_pvector_set(ops, i, neighbor_op);
		rz_pvector_set(ops, i + direction, to_move_op);
	}
}

/**
 * \brief Shuffles the IL operations of the packet instructions into the correct execution order
 * and stores the result in \p p->il_ops
 *
 * The shuffle algorithm implemented here is a copy of Qualcomm's implementation in QEMU:
 * https://gitlab.com/qemu-project/qemu/-/blob/master/target/hexagon/decode.c :: decode_shuffle_for_execution
 *
 * Though some changes were made:
 * * Endloops are not handled here (they are pushed to the ops list afterwards).
 * * ".new cmp jump" instructions were already split by us at this stage. So we don't check for them.
 *
 * \param p A valid packet which holds all instructions and the IL ops.
 * \return true Shuffle was successful.
 * \return false Shuffle failed.
 */
RZ_IPI bool hex_shuffle_insns(RZ_INOUT HexPkt *p) {
	rz_return_val_if_fail(p, false);
	if (!p->is_valid) {
		// Incomplete packets cannot be executed.
		return false;
	}
	if (rz_pvector_empty(p->il_ops)) {
		RZ_LOG_WARN("Valid packet without RZIL instructions encountered! pkt addr = 0x%" PFMT32x "\n", p->pkt_addr);
		return false;
	}
	RzPVector *ops = p->il_ops;

	// Do the shuffle
	bool changed = false;
	int i;
	bool flag; /* flag means we've seen a non-memory instruction */
	int n_mems; /* Number of memory instructions passed */
	int last_insn = rz_pvector_len(p->il_ops) - 1;
	HexILOp *op;

	do {
		changed = false;
		/*
		 * Stores go last, must not reorder.
		 * Cannot shuffle stores past loads, either.
		 * Iterate backwards.  If we see a non-memory instruction,
		 * then a store, shuffle the store to the front. Don't shuffle
		 * stores with regard to each other or a load.
		 */
		n_mems = 0;
		flag = false;
		for (flag = false, n_mems = 0, i = last_insn; i >= 0; i--) {
			op = (HexILOp *)rz_pvector_at(ops, i);
			if (!op) {
				RZ_LOG_FATAL("NULL il op at index %" PFMT32d "\n", i);
				return false;
			}
			if (flag && (op->attr & HEX_IL_INSN_ATTR_MEM_WRITE)) {
				hex_send_insn_to_i(ops, i, last_insn - n_mems);
				n_mems++;
				changed = true;
			} else if (op->attr & HEX_IL_INSN_ATTR_MEM_WRITE) {
				n_mems++;
			} else if (op->attr & HEX_IL_INSN_ATTR_MEM_READ) {
				/*
				 * Don't set flag, since we don't want to shuffle a
				 * store past a load
				 */
				n_mems++;
			} else if (op->attr & HEX_IL_INSN_ATTR_NEW) {
				/*
				 * Don't set flag, since we don't want to shuffle past
				 * a .new value
				 */
			} else {
				flag = true;
			}
		}
		if (changed) {
			continue;
		}

		/* Comparisons go first, may be reordered with regard to each other */
		for (flag = false, i = 0; i < last_insn + 1; i++) {
			op = (HexILOp *)rz_pvector_at(ops, i);
			if ((op->attr & HEX_IL_INSN_ATTR_WPRED) &&
				(op->attr & HEX_IL_INSN_ATTR_MEM_WRITE)) {
				/* This should be a comparison (not a store conditional) */
				if (flag) {
					hex_send_insn_to_i(ops, i, 0);
					changed = true;
					continue;
				}
			} else if (op->attr & HEX_IL_INSN_ATTR_WRITE_P3) /* && !is_endloop */ {
				// Endloops get pushed afterwards.
				if (flag) {
					hex_send_insn_to_i(ops, i, 0);
					changed = true;
					continue;
				}
			} else if (op->attr & HEX_IL_INSN_ATTR_WRITE_P0) /* && !is_new_cmp_jmp */ {
				// We have already split .new cmp jumps at this point. So no need to check for it.
				if (flag) {
					hex_send_insn_to_i(ops, i, 0);
					changed = true;
					continue;
				}
			} else {
				flag = true;
			}
		}
		if (changed) {
			continue;
		}
	} while (changed);

	/*
	 * If we have a .new register compare/branch, move that to the very
	 * very end, past stores
	 */
	for (i = 0; i < last_insn; i++) {
		op = (HexILOp *)rz_pvector_at(ops, i);
		if (op->attr & HEX_IL_INSN_ATTR_NEW) {
			hex_send_insn_to_i(ops, i, last_insn);
			break;
		}
	}
	return true;
}

static RzILOpEffect *hex_il_op_to_effect(const HexILOp *il_op, HexPkt *pkt) {
	rz_return_val_if_fail(il_op && il_op->get_il_op, NULL);
	HexInsnPktBundle bundle = { 0 };
	bundle.insn = (HexInsn *)il_op->hi;
	bundle.pkt = pkt;
	return il_op->get_il_op(&bundle);
}

/**
 * \brief Transforms a list of HexILOps into a single sequence.
 *
 * \param pkt The hexagon packet of the
 * \return RzILOpEffect* Sequence of operations to emulate the packet.
 */
static RZ_OWN RzILOpEffect *hex_pkt_to_il_seq(HexPkt *pkt) {
	rz_return_val_if_fail(pkt && pkt->il_ops, NULL);

	if (rz_pvector_len(pkt->il_ops) == 1) {
		rz_pvector_clear(pkt->il_ops);
		// We need at least the instruction op and the packet commit.
		// So if there aren't at least two ops something went wrong.
		RZ_LOG_WARN("Invalid il ops sequence! There should be at least two il ops per packet.\n");
		return NULL;
	}
	RzILOpEffect *complete_seq = EMPTY();
	for (ut32 i = 0; i < rz_pvector_len(pkt->il_ops); ++i) {
		complete_seq = SEQ2(complete_seq, hex_il_op_to_effect((HexILOp *)rz_pvector_at(pkt->il_ops, i), pkt));
	}
	return complete_seq;
}

static bool set_pkt_il_ops(RZ_INOUT HexPkt *p) {
	rz_return_val_if_fail(p, false);
	hex_il_pkt_stats_reset(&p->il_op_stats);
	// This function is a lot of unnecessary overhead so:
	// TODO The assignment of IL instructions to their actual instructions should be done in the instruction template.
	// But with the current separation between Asm and Analysis plugins this is not possible.
	// Because Asm is not allowed to depend on Analysis and the RZIL code.
	// This should be fixed ASAP after RzArch has been introduced.
	HexInsnContainer *pos;
	RzListIter *it;
	rz_list_foreach (p->bin, it, pos) {
		HexILInsn *cur_il_insn;
		if (pos->is_duplex) {
			// High sub-instructions
			pos->bin.sub[0]->il_insn = hex_il_getter_lt[pos->bin.sub[0]->identifier];
			cur_il_insn = &pos->bin.sub[0]->il_insn;
			// high sub operation 0
			cur_il_insn->op0.hi = pos->bin.sub[0];
			if (cur_il_insn->op0.attr == HEX_IL_INSN_ATTR_INVALID) {
				goto not_impl;
			}
			rz_pvector_push(p->il_ops, &cur_il_insn->op0);

			// high sub operation 1
			if (cur_il_insn->op1.attr != HEX_IL_INSN_ATTR_INVALID) {
				cur_il_insn->op1.hi = pos->bin.sub[0];
				rz_pvector_push(p->il_ops, &cur_il_insn->op1);
			}

			// Low sub-instructions
			pos->bin.sub[1]->il_insn = hex_il_getter_lt[pos->bin.sub[1]->identifier];
			cur_il_insn = &pos->bin.sub[1]->il_insn;
			// low sub operation 0
			cur_il_insn->op0.hi = pos->bin.sub[1];
			if (cur_il_insn->op0.attr == HEX_IL_INSN_ATTR_INVALID) {
				goto not_impl;
			}
			rz_pvector_push(p->il_ops, &cur_il_insn->op0);

			// low sub operation 1
			if (cur_il_insn->op1.attr != HEX_IL_INSN_ATTR_INVALID) {
				pos->bin.sub[1]->il_insn.op1.hi = pos->bin.sub[1];
				rz_pvector_push(p->il_ops, &cur_il_insn->op1);
			}
		} else {
			pos->bin.insn->il_insn = hex_il_getter_lt[pos->bin.insn->identifier];
			cur_il_insn = &pos->bin.insn->il_insn;
			// Insn operation 0
			cur_il_insn->op0.hi = pos->bin.insn;
			if (cur_il_insn->op0.attr == HEX_IL_INSN_ATTR_INVALID) {
				goto not_impl;
			}
			rz_pvector_push(p->il_ops, &cur_il_insn->op0);
			// Insn operation 1
			if (cur_il_insn->op1.attr != HEX_IL_INSN_ATTR_INVALID) {
				cur_il_insn->op1.hi = pos->bin.insn;
				rz_pvector_push(p->il_ops, &cur_il_insn->op1);
			}
		}
	}
	return true;
not_impl:
	RZ_LOG_INFO("Hexagon instruction %" PFMT32d " not implemented.\n", pos->bin.insn->identifier);
	return false;
}

static void check_for_jumps(const HexPkt *p, RZ_OUT bool *jump_flag) {
	rz_return_if_fail(p && jump_flag);
	void **it;
	HexILOp *op;
	rz_pvector_foreach (p->il_ops, it) {
		op = *it;
		if (op->attr & HEX_IL_INSN_ATTR_BRANCH) {
			*jump_flag = true;
		}
	}
}

/**
 * \brief Checks if the packet at \p addr has all conditions fulfilled
 * to be executed.
 *
 * \param pkt The packet to check.
 * \param addr Address of the requested IL operation.
 *
 * \return true If the packet can be set up for emulation.
 * \return false Otherwise.
 */
static inline bool pkt_at_addr_is_emu_ready(const HexPkt *pkt, const ut32 addr) {
	if (rz_list_length(pkt->bin) == 1) {
		const HexInsnContainer *hic = rz_list_get_n(pkt->bin, 0);
		if (hic->identifier == HEX_INS_INVALID_DECODE) {
			return false;
		}
	}
	return addr == pkt->pkt_addr && pkt->is_valid && pkt->last_instr_present;
}

/**
 * \brief Returns the IL operation of the instruction at \p addr. This will always be EMPTY().
 * Except for last instructions in a packet. Those will always return the complete IL operation
 * of the packet or NULL if one instruction was not implemented or an error occurred.
 *
 * \param addr Address of the requested IL operation.
 * \param get_pkt_op If true, it returns the IL operation of the whole packet at \p addr.
 * It will return EMPTY() if there is no packet which starts at \p addr.
 * If false, the behavior is as documented above.
 * \return RzILOpEffect* Sequence of operations to emulate the packet.
 */
RZ_IPI RzILOpEffect *hex_get_il_op(const ut32 addr, const bool get_pkt_op, HexState *state) {
	rz_return_val_if_fail(state, NULL);
	static bool might_has_jumped = false;
	HexPkt *p = hex_get_pkt(state, addr);
	if (!p) {
		RZ_LOG_WARN("Packet was NULL although it should have been disassembled at this point.\n");
		return NULL;
	}
	HexInsnContainer *hic = hex_get_hic_at_addr(state, addr);
	if (!hic) {
		return EMPTY();
	}
	if (hic->identifier == HEX_INS_INVALID_DECODE) {
		return NULL;
	}
	if (state->just_init || might_has_jumped) {
		// Assume that the instruction at the address the VM was initialized is the first instruction.
		// Also make it valid if a jump let to this packet.
		p->is_valid = true;
		hic->pkt_info.first_insn = true;
		state->just_init = false;
		might_has_jumped = false;
	}

	if (!get_pkt_op && !hic->pkt_info.last_insn) {
		// Only at the last instruction we execute all il ops of the packet.
		return EMPTY();
	}

	if (!(get_pkt_op && pkt_at_addr_is_emu_ready(p, addr)) || !pkt_at_addr_is_emu_ready(p, p->pkt_addr)) {
		// Invalid packet, EMPTY()
		return EMPTY();
	}

	if (!rz_pvector_empty(p->il_ops)) {
		check_for_jumps(p, &might_has_jumped);
		return hex_pkt_to_il_seq(p);
	}

	rz_pvector_push(p->il_ops, &hex_jump_flag_init_op);

	if (!set_pkt_il_ops(p)) {
		RZ_LOG_INFO("IL ops at 0x%" PFMT32x " contain not implemented instructions.\n", addr);
		return NULL;
	}

	if (!hex_shuffle_insns(p)) {
		RZ_LOG_WARN("Instruction shuffle failed at 0x%" PFMT32x "\n", addr);
		return NULL;
	}

	if (hex_get_loop_flag(p) == HEX_LOOP_0) {
		rz_pvector_push(p->il_ops, &hex_endloop0_op);
	} else if (hex_get_loop_flag(p) == HEX_LOOP_1) {
		rz_pvector_push(p->il_ops, &hex_endloop1_op);
	} else if (hex_get_loop_flag(p) == HEX_LOOP_01) {
		rz_pvector_push(p->il_ops, &hex_endloop01_op);
	}

	rz_pvector_push(p->il_ops, &hex_pkt_commit);
	// Add a jump to the next packet.
	rz_pvector_push(p->il_ops, &hex_next_jump_to_next_pkt);

	check_for_jumps(p, &might_has_jumped);

	return hex_pkt_to_il_seq(p);
}

static void log_reg_read(RZ_BORROW HexPkt *pkt, ut8 reg_num, HexRegClass reg_class, bool tmp_reg) {
	rz_return_if_fail(pkt);
	if (reg_num > 63 || (reg_class == HEX_REG_CLASS_PRED_REGS && reg_num > 3)) {
		rz_warn_if_reached();
		RZ_LOG_WARN("Register number %d should not be greater then 63 (gprs) or 3 (predicates).", reg_num);
	}
	switch (reg_class) {
	default:
		rz_warn_if_reached();
		RZ_LOG_WARN("Register reads of register class %d are not yet tracked!", reg_class);
		break;
	case HEX_REG_CLASS_DOUBLE_REGS:
	case HEX_REG_CLASS_GENERAL_DOUBLE_LOW8_REGS:
		if (tmp_reg) {
			rz_bv_set(pkt->il_op_stats.gpr_tmp_read, (reg_num + 1), true);
		} else {
			rz_bv_set(pkt->il_op_stats.gpr_read, (reg_num + 1), true);
		}
		// fallthrough
	case HEX_REG_CLASS_INT_REGS:
	case HEX_REG_CLASS_INT_REGS_LOW8:
	case HEX_REG_CLASS_GENERAL_SUB_REGS:
		if (tmp_reg) {
			rz_bv_set(pkt->il_op_stats.gpr_tmp_read, reg_num, true);
		} else {
			rz_bv_set(pkt->il_op_stats.gpr_read, reg_num, true);
		}
		break;
	case HEX_REG_CLASS_CTR_REGS64:
		if (tmp_reg) {
			rz_bv_set(pkt->il_op_stats.ctr_tmp_read, (reg_num + 1), true);
		} else {
			rz_bv_set(pkt->il_op_stats.ctr_read, (reg_num + 1), true);
		}
		// fallthrough
	case HEX_REG_CLASS_MOD_REGS:
	case HEX_REG_CLASS_CTR_REGS:
		if (tmp_reg) {
			rz_bv_set(pkt->il_op_stats.ctr_tmp_read, reg_num, true);
		} else {
			rz_bv_set(pkt->il_op_stats.ctr_read, reg_num, true);
		}
		break;
	case HEX_REG_CLASS_PRED_REGS:
		if (tmp_reg) {
			rz_bv_set(pkt->il_op_stats.pred_tmp_read, reg_num, true);
		} else {
			rz_bv_set(pkt->il_op_stats.pred_read, reg_num, true);
		}
		break;
	}
}

static inline void log_pred_write_slot(HexInsnPktBundle *bundle, ut32 pred_num) {
	ut32 pos = (pred_num * HEX_LOG_SLOT_LOG_WIDTH);
	rz_bv_set_range(bundle->pkt->il_op_stats.pred_written, HEX_LOG_SLOT_BIT_OFF + pos, HEX_LOG_SLOT_BIT_OFF + pos + 2, false);
	rz_bv_set(bundle->pkt->il_op_stats.pred_written, bundle->insn->slot + HEX_LOG_SLOT_BIT_OFF + pos, true);
}

static void log_reg_write(RZ_BORROW HexInsnPktBundle *bundle, ut8 reg_num, HexRegClass reg_class, bool read, bool tmp_reg) {
	rz_return_if_fail(bundle);
	HexPkt *pkt = bundle->pkt;

	if (reg_num > 63 || (reg_class == HEX_REG_CLASS_PRED_REGS && reg_num > 3)) {
		rz_warn_if_reached();
		RZ_LOG_WARN("Register number %d should not be greater then 63 (gprs) or 3 (predicates).", reg_num);
	}
	switch (reg_class) {
	default:
		rz_warn_if_reached();
		RZ_LOG_WARN("Register writes of register class %d are not yet tracked!", reg_class);
		break;
	case HEX_REG_CLASS_DOUBLE_REGS:
	case HEX_REG_CLASS_GENERAL_DOUBLE_LOW8_REGS:
		rz_bv_set(pkt->il_op_stats.gpr_written, (reg_num + 1), true);
		// fallthrough
	case HEX_REG_CLASS_INT_REGS:
	case HEX_REG_CLASS_INT_REGS_LOW8:
	case HEX_REG_CLASS_GENERAL_SUB_REGS:
		rz_bv_set(pkt->il_op_stats.gpr_written, reg_num, true);
		break;
	case HEX_REG_CLASS_CTR_REGS64:
		if (hex_ctr_immut_masks[reg_num + 1] != HEX_IMMUTABLE_REG) {
			rz_bv_set(pkt->il_op_stats.ctr_written, (reg_num + 1), true);
		}
		// fallthrough
	case HEX_REG_CLASS_MOD_REGS:
	case HEX_REG_CLASS_CTR_REGS:
		if (hex_ctr_immut_masks[reg_num] != HEX_IMMUTABLE_REG) {
			rz_bv_set(pkt->il_op_stats.ctr_written, reg_num, true);
		}
		break;
	case HEX_REG_CLASS_PRED_REGS:
		rz_bv_set(pkt->il_op_stats.pred_written, reg_num, true);
		if (bundle->insn) {
			log_pred_write_slot(bundle, reg_num);
		}
		break;
	}
}

static ut32 get_last_slot_w_to_p(const HexPkt *pkt, ut32 pred_num) {
	rz_return_val_if_fail(pkt, false);
	ut32 slots = (rz_bv_to_ut32(pkt->il_op_stats.pred_written) >> HEX_LOG_SLOT_BIT_OFF);
	return (slots >> (pred_num * HEX_LOG_SLOT_LOG_WIDTH)) & HEX_LOG_SLOT_LOG_MASK;
}

/**
 * \brief Checks if another slot wrote to a given predicate reg before.
 *
 * \param bundle The bundle currently in use.
 * \param pred_num The number of the predicate register to check.
 *
 * \return true The predicate was written before by another slot.
 * \return false The predicate was not written by another slot.
 */
static bool other_slot_wrote_to_pred(const HexInsnPktBundle *bundle, ut32 pred_num) {
	rz_return_val_if_fail(bundle && bundle->pkt && (pred_num < 4), false);
	const HexPkt *pkt = bundle->pkt;
	if (!bundle->insn) {
		// Non instruction ops
		return rz_bv_get(pkt->il_op_stats.pred_written, 1 << pred_num);
	}
	bool pw = rz_bv_get(pkt->il_op_stats.pred_written, 1 << pred_num);
	bool slot_w = get_last_slot_w_to_p(bundle->pkt, pred_num) != bundle->insn->slot;
	return pw && slot_w;
}

static inline RzILOpPure *get_masked_reg_val(RzILOpPure *reg_val, RzILOpPure *val, ut32 mask) {
	RzILOpPure *masked_val = LOGAND(val, LOGNOT(U32(mask)));
	RzILOpPure *masked_reg = LOGAND(reg_val, U32(mask));
	return LOGOR(masked_reg, masked_val);
}

/**
 * \brief Writes the given value to the register specified in \p op and logs the write.
 * If the register is a double register, each of its sub-registers are written separately.
 * The double register itself will *not* be written.
 *
 * \param pkt The currently executed packet.
 * \param op The HexOp of the register to write.
 * \param val The value to write.
 *
 * \return The effect which writes the register or NULL in case of failure.
 */
RZ_IPI RZ_OWN RzILOpEffect *hex_write_reg(RZ_BORROW HexInsnPktBundle *bundle, const HexOp *op, RzILOpPure *val) {
	rz_return_val_if_fail(bundle && op && val, NULL);

	const char *high_name = NULL;
	const char *low_name = NULL;
	RzILOpPure *high_val = NULL;
	RzILOpPure *low_val = NULL;
	RzILOpEffect *p3_0_write_seq = NULL; // If C4 (P3:0) is written this is non-NULL.
	ut32 reg_num = hex_resolve_reg_enum_id(op->class, op->op.reg);
	ut32 dest_width = HEX_GPR_WIDTH;
	switch (op->class) {
	default:
		rz_warn_if_reached();
		RZ_LOG_WARN("Writing ops of class %d is not implemented yet.", op->class);
		return NULL;
	case HEX_REG_CLASS_DOUBLE_REGS:
	case HEX_REG_CLASS_GENERAL_DOUBLE_LOW8_REGS:
		high_name = hex_get_reg_in_class(HEX_REG_CLASS_INT_REGS, reg_num + 1, false, true, true);
		if (!high_name) {
			return NULL;
		}
		high_val = SHIFTR0(DUP(val), U8(HEX_GPR_WIDTH));
		// fallthrough
	case HEX_REG_CLASS_INT_REGS:
	case HEX_REG_CLASS_INT_REGS_LOW8:
	case HEX_REG_CLASS_GENERAL_SUB_REGS:
		low_name = hex_get_reg_in_class(HEX_REG_CLASS_INT_REGS, reg_num, false, true, true);
		if (!low_name) {
			return NULL;
		}
		low_val = CAST(HEX_GPR_WIDTH, IL_FALSE, val);
		break;
	case HEX_REG_CLASS_CTR_REGS64:
		if (hex_ctr_immut_masks[reg_num + 1] != HEX_IMMUTABLE_REG) {
			high_name = hex_get_reg_in_class(HEX_REG_CLASS_CTR_REGS, reg_num + 1, false, true, true);
			if (!high_name) {
				return NULL;
			}
			high_val = SHIFTR0(DUP(val), U8(HEX_GPR_WIDTH));
			if (hex_ctr_immut_masks[reg_num + 1] != 0) {
				high_val = get_masked_reg_val(VARG(high_name), CAST(HEX_GPR_WIDTH, IL_FALSE, high_val), hex_ctr_immut_masks[reg_num + 1]);
			}
		}
		// fallthrough
	case HEX_REG_CLASS_MOD_REGS:
	case HEX_REG_CLASS_CTR_REGS:
		if (hex_ctr_immut_masks[reg_num] != HEX_IMMUTABLE_REG) {
			low_name = hex_get_reg_in_class(HEX_REG_CLASS_CTR_REGS, reg_num, false, true, true);
			if (!low_name) {
				return NULL;
			}
			low_val = CAST(HEX_GPR_WIDTH, IL_FALSE, val);
			if (hex_ctr_immut_masks[reg_num] != 0) {
				low_val = get_masked_reg_val(VARG(low_name), low_val, hex_ctr_immut_masks[reg_num]);
			}
			if (reg_num == 4) {
				HexOp pred_op = { 0 };
				pred_op.class = HEX_REG_CLASS_PRED_REGS;
				pred_op.op.reg = 0;
				p3_0_write_seq = hex_write_reg(bundle, &pred_op, CAST(8, IL_FALSE, DUP(low_val)));
				pred_op.op.reg = 1;
				p3_0_write_seq = SEQ2(hex_write_reg(bundle, &pred_op, CAST(8, IL_FALSE, SHIFTR0(DUP(low_val), U8(8)))), p3_0_write_seq);
				pred_op.op.reg = 2;
				p3_0_write_seq = SEQ2(hex_write_reg(bundle, &pred_op, CAST(8, IL_FALSE, SHIFTR0(DUP(low_val), U8(16)))), p3_0_write_seq);
				pred_op.op.reg = 3;
				p3_0_write_seq = SEQ2(hex_write_reg(bundle, &pred_op, CAST(8, IL_FALSE, SHIFTR0(DUP(low_val), U8(24)))), p3_0_write_seq);
				break;
			}
		}
		break;
	case HEX_REG_CLASS_PRED_REGS:
		low_name = hex_get_reg_in_class(HEX_REG_CLASS_PRED_REGS, reg_num, false, true, true);
		if (!low_name) {
			return NULL;
		}
		if (other_slot_wrote_to_pred(bundle, reg_num)) {
			// If the register was written before by another slot, the values get ANDed.
			low_val = LOGAND(VARG(low_name), val);
		} else {
			low_val = val;
		}
		dest_width = HEX_PRED_WIDTH;
		break;
	}
	RzILOpEffect *write_high = high_val ? SETG(high_name, CAST(dest_width, IL_FALSE, high_val)) : NULL;
	RzILOpEffect *write_low = low_val ? SETG(low_name, CAST(dest_width, IL_FALSE, low_val)) : NULL;
	if (p3_0_write_seq) {
		write_low = SEQ2(write_low, p3_0_write_seq);
	}
	log_reg_write(bundle, reg_num, op->class, false, true);

	if (write_high && write_low) {
		return SEQ2(write_low, write_high);
	} else if (write_low) {
		return write_low;
	} else if (write_high) {
		return write_high;
	}
	return EMPTY();
}

static inline bool read_cond_faulty(RzILOpPure *low_val, RzILOpPure *high_val, ut32 val_width) {
	if (!low_val || val_width == 0 || (val_width % 8 != 0)) {
		return true;
	}
	if (val_width == HEX_GPR64_WIDTH && !high_val) {
		return true;
	}
	return false;
}

/**
 * \brief Checks for rw registers (e.g. Rx) if reads and writes overlap.
 *
 * \param pkt The packet of the current instruction.
 * \param op The operand to check.
 * \param reg_num The number of the register to check.
 *
 * \return true If the register is a "x" register and it was read and written before.
 * \return false Otherwise.
 */
static bool x_reg_rw_overlap(const HexPkt *pkt, const HexOp *op, ut32 reg_num) {
	switch (op->class) {
	default:
		rz_warn_if_reached();
		RZ_LOG_WARN("Checking rw overlap of class %d not implemented yet.", op->class);
		return false;
	case HEX_REG_CLASS_INT_REGS:
	case HEX_REG_CLASS_INT_REGS_LOW8:
	case HEX_REG_CLASS_GENERAL_SUB_REGS:
	case HEX_REG_CLASS_DOUBLE_REGS:
	case HEX_REG_CLASS_GENERAL_DOUBLE_LOW8_REGS:
		return (rz_bv_get(pkt->il_op_stats.gpr_written, reg_num)) && (rz_bv_get(pkt->il_op_stats.gpr_read, reg_num)) && op->isa_id == 'x';
	case HEX_REG_CLASS_MOD_REGS:
	case HEX_REG_CLASS_CTR_REGS:
	case HEX_REG_CLASS_CTR_REGS64:
		return (rz_bv_get(pkt->il_op_stats.ctr_written, reg_num)) && (rz_bv_get(pkt->il_op_stats.ctr_read, reg_num)) && op->isa_id == 'x';
	case HEX_REG_CLASS_PRED_REGS:
		return (rz_bv_get(pkt->il_op_stats.pred_written, reg_num)) && (rz_bv_get(pkt->il_op_stats.pred_read, reg_num)) && op->isa_id == 'x';
	}
}

/**
 * \brief Reads a value from the register specified in \p op and logs the read.
 * If the register is a double register, each of its sub-registers are read separately.
 * The double register itself will *not* be read.
 *
 * \param pkt The currently executed packet.
 * \param op The HexOp of the register to read.
 * \param tmp_reg If true, the <reg>.new register will be read. Otherwise simply <reg>.
 *
 * \return The pure which with the value read or NULL in case of failure.
 */
RZ_IPI RZ_OWN RzILOpPure *hex_read_reg(RZ_BORROW HexPkt *pkt, const HexOp *op, bool tmp_reg) {
	rz_return_val_if_fail(pkt && op, NULL);

	const char *high_name = NULL;
	const char *low_name = NULL;
	RzILOpPure *high_val = NULL;
	RzILOpPure *low_val = NULL;
	ut32 reg_num = hex_resolve_reg_enum_id(op->class, op->op.reg);
	ut32 val_width = HEX_GPR_WIDTH;
	switch (op->class) {
	default:
		rz_warn_if_reached();
		RZ_LOG_WARN("Writing ops of class %d is not implemented yet.", op->class);
		return NULL;
	case HEX_REG_CLASS_DOUBLE_REGS:
	case HEX_REG_CLASS_GENERAL_DOUBLE_LOW8_REGS:
		if (x_reg_rw_overlap(pkt, op, reg_num + 1)) {
			// If read and writes overlap, return the new register for each read.
			tmp_reg = true;
		}
		high_name = hex_get_reg_in_class(HEX_REG_CLASS_INT_REGS, reg_num + 1, false, tmp_reg, true);
		if (!high_name) {
			return NULL;
		}
		high_val = SHIFTL0(CAST(HEX_GPR64_WIDTH, IL_FALSE, VARG(high_name)), U8(HEX_GPR_WIDTH));
		val_width = HEX_GPR64_WIDTH;
		// fallthrough
	case HEX_REG_CLASS_INT_REGS:
	case HEX_REG_CLASS_INT_REGS_LOW8:
	case HEX_REG_CLASS_GENERAL_SUB_REGS:
		if (x_reg_rw_overlap(pkt, op, reg_num)) {
			// If read and writes overlap, return the new register for each read.
			tmp_reg = true;
		}
		low_name = hex_get_reg_in_class(HEX_REG_CLASS_INT_REGS, reg_num, false, tmp_reg, true);
		if (!low_name) {
			return NULL;
		}
		low_val = VARG(low_name);
		break;
	case HEX_REG_CLASS_CTR_REGS64:
		if (x_reg_rw_overlap(pkt, op, reg_num + 1)) {
			// If read and writes overlap, return the new register for each read.
			tmp_reg = true;
		}
		high_name = hex_get_reg_in_class(HEX_REG_CLASS_CTR_REGS, reg_num + 1, false, tmp_reg, true);
		if (!high_name) {
			return NULL;
		}
		if (reg_num + 1 == 9) {
			// C9 = PC. Does not exist in VM as var
			high_val = SHIFTL0(CAST(HEX_GPR64_WIDTH, IL_FALSE, U32(pkt->pkt_addr)), U8(HEX_GPR_WIDTH));
		} else {
			high_val = SHIFTL0(CAST(HEX_GPR64_WIDTH, IL_FALSE, VARG(high_name)), U8(HEX_GPR_WIDTH));
		}
		val_width = HEX_GPR64_WIDTH;
		// fallthrough
	case HEX_REG_CLASS_MOD_REGS:
	case HEX_REG_CLASS_CTR_REGS:
		if (x_reg_rw_overlap(pkt, op, reg_num)) {
			// If read and writes overlap, return the new register for each read.
			tmp_reg = true;
		}
		if (reg_num == 4) {
			// C4 alias P3:0 register is the concatenation of all predicate registers.
			HexOp pred_op = { 0 };
			pred_op.class = HEX_REG_CLASS_PRED_REGS;
			pred_op.op.reg = 0;
			low_val = hex_read_reg(pkt, &pred_op, tmp_reg);
			pred_op.op.reg = 1;
			low_val = APPEND(hex_read_reg(pkt, &pred_op, tmp_reg), low_val);
			pred_op.op.reg = 2;
			low_val = APPEND(hex_read_reg(pkt, &pred_op, tmp_reg), low_val);
			pred_op.op.reg = 3;
			low_val = APPEND(hex_read_reg(pkt, &pred_op, tmp_reg), low_val);
			break;
		}
		low_name = hex_get_reg_in_class(HEX_REG_CLASS_CTR_REGS, reg_num, false, tmp_reg, true);
		if (!low_name) {
			return NULL;
		}
		if (reg_num == 9) {
			low_val = U32(pkt->pkt_addr);
		} else {
			low_val = VARG(low_name);
		}
		break;
	case HEX_REG_CLASS_PRED_REGS:
		if (x_reg_rw_overlap(pkt, op, reg_num)) {
			// If read and writes overlap, return the new register for each read.
			tmp_reg = true;
		}
		low_name = hex_get_reg_in_class(HEX_REG_CLASS_PRED_REGS, reg_num, false, tmp_reg, true);
		if (!low_name) {
			return NULL;
		}
		return VARG(low_name);
	}
	if (read_cond_faulty(low_val, high_val, val_width)) {
		rz_warn_if_reached();
		return NULL;
	}
	log_reg_read(pkt, reg_num, op->class, tmp_reg);

	if (val_width == HEX_GPR64_WIDTH) {
		return LOGOR(high_val, CAST(HEX_GPR64_WIDTH, IL_FALSE, low_val));
	}
	return low_val;
}

RZ_IPI RZ_OWN RzILOpEffect *hex_cancel_slot(RZ_BORROW HexPkt *pkt, ut8 slot) {
	rz_return_val_if_fail(pkt, NULL);
	if (slot > 3) {
		rz_warn_if_reached();
		RZ_LOG_WARN("Slot %d does not exist!", slot);
	}
	rz_bv_set(pkt->il_op_stats.slot_cancelled, slot, true);
	return EMPTY();
}

RzILOpPure *hex_get_corresponding_cs(RZ_BORROW HexPkt *pkt, const HexOp *Mu) {
	rz_return_val_if_fail(Mu && Mu->class == HEX_REG_CLASS_MOD_REGS, NULL);
	HexOp cs_reg = { 0 };
	if (Mu->op.reg == 0) {
		// M0 (C6) return CS0
		cs_reg.class = HEX_REG_CLASS_CTR_REGS;
		cs_reg.op.reg = 12;
		return hex_read_reg(pkt, &cs_reg, true);
	} else if (Mu->op.reg == 1) {
		// M1 (C7) return CS1
		cs_reg.class = HEX_REG_CLASS_CTR_REGS;
		cs_reg.op.reg = 13;
		return hex_read_reg(pkt, &cs_reg, true);
	}
	rz_warn_if_reached();
	return NULL;
}

RZ_IPI void hex_il_pkt_stats_fini(HexILExecData *stats) {
	rz_return_if_fail(stats);
	rz_bv_free(stats->slot_cancelled);
	rz_bv_free(stats->ctr_written);
	rz_bv_free(stats->gpr_written);
	rz_bv_free(stats->pred_written);
	rz_bv_free(stats->ctr_read);
	rz_bv_free(stats->gpr_read);
	rz_bv_free(stats->pred_read);
	rz_bv_free(stats->ctr_tmp_read);
	rz_bv_free(stats->gpr_tmp_read);
	rz_bv_free(stats->pred_tmp_read);
}

RZ_IPI void hex_il_pkt_stats_init(HexILExecData *stats) {
	rz_return_if_fail(stats);
	stats->slot_cancelled = rz_bv_new(64);
	stats->ctr_written = rz_bv_new(64);
	stats->gpr_written = rz_bv_new(64);
	stats->pred_written = rz_bv_new(32);
	stats->ctr_read = rz_bv_new(64);
	stats->gpr_read = rz_bv_new(64);
	stats->pred_read = rz_bv_new(32);
	stats->ctr_tmp_read = rz_bv_new(64);
	stats->gpr_tmp_read = rz_bv_new(64);
	stats->pred_tmp_read = rz_bv_new(32);
}

RZ_IPI void hex_il_pkt_stats_reset(HexILExecData *stats) {
	hex_il_pkt_stats_fini(stats);
	hex_il_pkt_stats_init(stats);
}

#include <rz_il/rz_il_opbuilder_end.h>
