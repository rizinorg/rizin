// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: 96e220e6886868d6663d966ecc396befffc355e7
// LLVM commit date: 2022-01-05 11:01:52 +0000 (ISO 8601 format)
// Date of code generation: 2022-01-05 11:54:26-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include "hexagon.h"
#include "hexagon_insn.h"
#include "hexagon_arch.h"

static inline bool is_last_instr(const ut8 parse_bits) {
	// Duplex instr. (parse bits = 0) are always the last.
	return ((parse_bits == 0x3) || (parse_bits == 0x0));
}

/**
 * \brief Checks if packet ends hardware loop 0.
 *
 * \param pb_hi_0 Parse bits instruction 0.
 * \param pb_hi_1 Parse bits instruction 1.
 * \return true Packet ends hardware loop 0.
 * \return false Packet does not end hardware loop 0.
 */
static inline bool is_endloop0_pkt(const ut8 pb_hi_0, const ut8 pb_hi_1) {
	return ((pb_hi_0 == 0x2) && ((pb_hi_1 == 0x1) || (pb_hi_1 == 0x3)));
}

/**
 * \brief Checks if packet ends hardware loop 0. But for an undocumented variant
 * 	where the packet has only two instructions and the last one is a Duplex.
 *
 * \param pb_hi_0 Parse bits instruction 0.
 * \param pb_hi_1 Parse bits instruction 1 (duplex and end of packet).
 * \return true Packet ends hardware loop 0.
 * \return false Packet does not end hardware loop 0.
 */
static inline bool is_undoc_endloop0_pkt(const ut8 pb_hi_0, const ut8 pb_hi_1) {
	return ((pb_hi_0 == 0x2) && (pb_hi_1 == 0x0));
}

/**
 * \brief Checks if packet ends hardware loop 1.
 *
 * \param pb_hi_0 Parse bits instruction 0.
 * \param pb_hi_1 Parse bits instruction 1.
 * \return true Packet ends hardware loop 1.
 * \return false Packet does not end hardware loop 1.
 */
static inline bool is_endloop1_pkt(const ut8 pb_hi_0, const ut8 pb_hi_1) {
	return ((pb_hi_0 == 0x1) && (pb_hi_1 == 0x2));
}

/**
 * \brief Checks if packet ends hardware loop 0 and hw-loop 1.
 *
 * \param pb_hi_0 Parse bits instruction 0.
 * \param pb_hi_1 Parse bits instruction 1.
 * \return true Packet ends hardware loop 0 and hw-loop 1.
 * \return false Packet does not end hardware loop 0 and hw-loop 1.
 */
static inline bool is_endloop01_pkt(const ut8 pb_hi_0, const ut8 pb_hi_1) {
	return ((pb_hi_0 == 0x2) && (pb_hi_1 == 0x2));
}

/**
 * \brief Gives the instruction at a given address from the state.
 *
 * \param state The state to operade on.
 * \param addr The address of the instruction.
 * \return Pointer to instruction or NULL if none was found.
 */
static HexInsn *hex_get_instr_at_addr(HexState *state, const ut32 addr) {
	HexPkt *p;
	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		p = &state->pkts[i];
		HexInsn *pi = NULL;
		RzListIter *iter = NULL;
		rz_list_foreach (p->insn, iter, pi) {
			if (addr == pi->addr) {
				p->last_access = rz_time_now();
				return pi;
			}
		}
	}
	return NULL;
}

/**
 * \brief Returns the index of an addr in a given packet.
 *
 * \param addr Address of an instruction.
 * \param p The packet. to search in.
 * \return ut8 The index of the addr if it is in the packet. UT8_MAX otherwise.
 */
RZ_API ut8 hexagon_get_pkt_index_of_addr(const ut32 addr, const HexPkt *p) {
	rz_return_val_if_fail(p, UT8_MAX);

	HexInsn *hi = NULL;
	RzListIter *it = NULL;
	ut8 i = 0;
	rz_list_foreach (p->insn, it, hi) {
		if (hi->addr == addr) {
			return i;
		}
		++i;
	}
	return UT8_MAX;
}

/**
 * \brief Clears a packet and sets its attributes to invalid values.
 *
 * \param p The packet to clear.
 */
static void hex_clear_pkt(RZ_NONNULL HexPkt *p) {
	p->last_instr_present = false;
	p->is_valid = false;
	p->last_access = 0;
	rz_list_purge(p->insn);
}

/**
 * \brief Gives the least used packet.
 *
 * \param state The state to operade on.
 * \return HexPkt* Pointer to the least used packet.
 */
static HexPkt *hex_get_stale_pkt(HexState *state) {
	HexPkt *stale_state_pkt = &state->pkts[0];
	ut64 oldest = UT64_MAX;

	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		if (state->pkts[i].last_access < oldest) {
			stale_state_pkt = &state->pkts[i];
		}
	}
	return stale_state_pkt;
}

/**
 * \brief Returns the packet which covers the given address.
 *
 * \param state The state to operade on.
 * \param addr The address of an instruction.
 * \return HexPkt* The packet to which this address belongs to or NULL if no packet was found.
 */
static HexPkt *hex_get_pkt(HexState *state, const ut32 addr) {
	HexPkt *p = NULL;
	HexInsn *pi = NULL;
	RzListIter *iter = NULL;
	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		p = &state->pkts[i];
		rz_list_foreach (p->insn, iter, pi) {
			if (addr == pi->addr) {
				return p;
			}
		}
	}
	return NULL;
}

/**
 * \brief Frees an instruction.
 *
 * \param i The instruction to be freed.
 */
RZ_API void hex_insn_free(RZ_NULLABLE HexInsn *i) {
	if (!i) {
		return;
	}
	free(i);
}

/**
 * \brief Frees an constant extender.
 *
 * \param ce The constant extender to be freed.
 */
RZ_API void hex_const_ext_free(RZ_NULLABLE HexConstExt *ce) {
	if (!ce) {
		return;
	}
	free(ce);
}

/**
 * \brief Get the index of a packet in the state
 *
 * \param state The state to operade on.
 * \param p The packet whichs index should be determined.
 * \return ut8 The index of the packet in the given state. UT8_MAX if it is not in the state.
 */
static ut8 get_state_pkt_index(HexState *state, const HexPkt *p) {
	HexPkt *sp;
	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		sp = &state->pkts[i];
		if (sp->pkt_addr == p->pkt_addr) {
			return i;
		}
	}
	return UT8_MAX;
}

/**
 * \brief Initializes each packet of the state once.
 *
 * \return The initialized state of the plugins.
 */
RZ_API HexState *hexagon_get_state() {
	static HexState *state = NULL;
	if (state) {
		return state;
	}

	state = calloc(1, sizeof(HexState));
	if (!state) {
		RZ_LOG_FATAL("Could not allocate memory for HexState!");
	}
	for (int i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		state->pkts[i].insn = rz_list_newf((RzListFree)hex_insn_free);
		if (!state->pkts[i].insn) {
			RZ_LOG_FATAL("Could not initialize instruction list!");
		}
		hex_clear_pkt(&(state->pkts[i]));
	}
	state->const_ext_l = rz_list_newf((RzListFree)hex_const_ext_free);
	return state;
}

/**
 * \brief Checks if the packet has 4 instructions set.
 *
 * \param p The packet to check.
 * \return true The packet stores already 4 instructions.
 * \return false The packet stores less than 4 instructions.
 */
static inline bool is_pkt_full(const HexPkt *p) {
	return rz_list_length(p->insn) >= 4;
}

/**
 * \brief Sets the packet related information in an instruction.
 *
 * \param hi The instruction.
 * \param p The packet the instruction belongs to.
 * \param k The index of the instruction within the packet.
 */
static void hex_set_pkt_info(const RzAsm *rz_asm, RZ_INOUT HexInsn *hi, const HexPkt *p, const ut8 k, const bool update_mnemonic) {
	rz_return_if_fail(hi && p);
	bool is_first = (k == 0);
	HexPktInfo *hi_pi = &hi->pkt_info;

	strncpy(hi_pi->mnem_postfix, "", 16);
	// Parse instr. position in pkt
	if (is_first && is_last_instr(hi->parse_bits)) { // Single instruction packet.
		hi_pi->first_insn = true;
		hi_pi->last_insn = true;
		// TODO No indent in visual mode for "[" without spaces.
		if (p->is_valid) {
			strncpy(hi_pi->mnem_prefix, HEX_PKT_SINGLE, 8);
		} else {
			strncpy(hi_pi->mnem_prefix, HEX_PKT_UNK, 8);
		}
	} else if (is_first) {
		hi_pi->first_insn = true;
		hi_pi->last_insn = false;
		if (p->is_valid) {
			strncpy(hi_pi->mnem_prefix, rz_asm->utf8 ? HEX_PKT_FIRST_UTF8 : HEX_PKT_FIRST, 8);
		} else {
			strncpy(hi_pi->mnem_prefix, HEX_PKT_UNK, 8);
		}
	} else if (is_last_instr(hi->parse_bits)) {
		hi_pi->first_insn = false;
		hi_pi->last_insn = true;
		if (p->is_valid) {
			strncpy(hi_pi->mnem_prefix, rz_asm->utf8 ? HEX_PKT_LAST_UTF8 : HEX_PKT_LAST, 8);

			switch (hex_get_loop_flag(p)) {
			default:
				break;
			case HEX_LOOP_01:
				strncpy(hi_pi->mnem_postfix, rz_asm->utf8 ? HEX_PKT_ELOOP_01_UTF8 : HEX_PKT_ELOOP_01, 24);
				break;
			case HEX_LOOP_0:
				strncpy(hi_pi->mnem_postfix, rz_asm->utf8 ? HEX_PKT_ELOOP_0_UTF8 : HEX_PKT_ELOOP_0, 24);
				break;
			case HEX_LOOP_1:
				strncpy(hi_pi->mnem_postfix, rz_asm->utf8 ? HEX_PKT_ELOOP_1_UTF8 : HEX_PKT_ELOOP_1, 24);
				break;
			}
		} else {
			strncpy(hi_pi->mnem_prefix, HEX_PKT_UNK, 8);
		}
	} else {
		hi_pi->first_insn = false;
		hi_pi->last_insn = false;
		if (p->is_valid) {
			strncpy(hi_pi->mnem_prefix, rz_asm->utf8 ? HEX_PKT_MID_UTF8 : HEX_PKT_MID, 8);
		} else {
			strncpy(hi_pi->mnem_prefix, HEX_PKT_UNK, 8);
		}
	}
	if (update_mnemonic) {
		sprintf(hi->mnem, "%s%s%s", hi_pi->mnem_prefix, hi->mnem_infix, hi_pi->mnem_postfix);
	}
}

/**
 * \brief Returns the loop type of a packet. Though only if this packet is
 * 	the last packet in last packet in a hardware loop. Otherwise it returns
 * 	HEX_NO_LOOP.
 *
 * \param p The instruction packet.
 * \return HexLoopAttr The loop type this packet belongs to.
 */
RZ_API HexLoopAttr hex_get_loop_flag(const HexPkt *p) {
	if (!p || rz_list_length(p->insn) < 2) {
		return HEX_NO_LOOP;
	}

	ut8 pb_0 = ((HexInsn *)rz_list_get_n(p->insn, 0))->parse_bits;
	ut8 pb_1 = ((HexInsn *)rz_list_get_n(p->insn, 1))->parse_bits;

	if (is_endloop0_pkt(pb_0, pb_1)) {
		return HEX_LOOP_0;
	} else if (is_endloop1_pkt(pb_0, pb_1)) {
		return HEX_LOOP_1;
	} else if (is_endloop01_pkt(pb_0, pb_1)) {
		return HEX_LOOP_01;
	} else if (is_undoc_endloop0_pkt(pb_0, pb_1)) {
		RZ_LOG_VERBOSE("Undocumented hardware loop 0 endloop packet.");
		return HEX_LOOP_0;
	} else {
		return HEX_NO_LOOP;
	}
}

/**
 * \brief Sets the packet after pkt to valid and updates its mnemonic.
 *
 * \param state The state to operade on.
 * \param pkt The packet which predecessor will be updated.
 */
static void make_next_packet_valid(HexState *state, const HexPkt *pkt) {
	HexInsn *tmp = rz_list_get_top(pkt->insn);
	if (!tmp) {
		return;
	}
	ut32 pkt_addr = tmp->addr + 4;

	HexPkt *p;
	for (int i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		p = &state->pkts[i];
		if (p->pkt_addr == pkt_addr) {
			if (p->is_valid) {
				break;
			}
			p->is_valid = true;
			HexInsn *hi = NULL;
			RzListIter *it = NULL;
			ut8 k = 0;
			rz_list_foreach (p->insn, it, hi) {
				hex_set_pkt_info(&state->rz_asm, hi, p, k, true);
				++k;
			}
			p->last_access = rz_time_now();
			break;
		}
	}
}

/**
 * \brief Allocates a new instruction on the heap.
 *
 * \return HexInsn* The new instruction.
 */
RZ_API HexInsn *alloc_instr() {
	HexInsn *hi = calloc(1, sizeof(HexInsn));
	if (!hi) {
		RZ_LOG_FATAL("Could not allocate memory for new instruction.\n");
	}

	return hi;
}

/**
 * \brief Copies an instruction to the packet p at position k.
 *
 * \param state The state to operade on.
 * \param new_ins The instruction to copy.
 * \param p The packet in which the instruction will hold the instruction.
 * \param k The index of the instruction in the packet.
 * \return HexInsn* Pointer to the copied instruction on the heap.
 */
static HexInsn *hex_add_to_pkt(HexState *state, const HexInsn *new_ins, RZ_INOUT HexPkt *p, const ut8 k) {
	if (k > 3) {
		RZ_LOG_FATAL("Instruction could not be set! A packet can only hold four instructions but k=%d.", k);
	}
	HexInsn *hi = alloc_instr();
	memcpy(hi, new_ins, sizeof(HexInsn));
	rz_list_insert(p->insn, k, hi);

	if (k == 0) {
		p->pkt_addr = hi->addr;
	}
	p->last_instr_present |= is_last_instr(hi->parse_bits);
	ut32 p_l = rz_list_length(p->insn);
	hex_set_pkt_info(&state->rz_asm, hi, p, k, false);
	if (k == 0 && p_l > 1) {
		// Update the instruction which was previously the first one.
		hex_set_pkt_info(&state->rz_asm, rz_list_get_n(p->insn, 1), p, 1, true);
	}
	p->last_access = rz_time_now();
	if (p->last_instr_present) {
		make_next_packet_valid(state, p);
	}
	return hi;
}

/**
 * \brief Cleans the packet \p new_p, copies the instruction \p new_ins and the attributes of \p p to it.
 *
 * \param state The state to operade on.
 * \param new_ins The instruction to copy.
 * \param p The old packet which attributes are copied to the new one.
 * \param new_p The new packet will hold the instruction.
 * \return HexInsn* Pointer to the copied instruction on the heap.
 */
static HexInsn *hex_to_new_pkt(HexState *state, const HexInsn *new_ins, const HexPkt *p, RZ_INOUT HexPkt *new_p) {
	hex_clear_pkt(new_p);

	HexInsn *hi = alloc_instr();
	memcpy(hi, new_ins, sizeof(HexInsn));
	rz_list_insert(new_p->insn, 0, hi);

	new_p->last_instr_present |= is_last_instr(hi->parse_bits);
	new_p->hw_loop0_addr = p->hw_loop0_addr;
	new_p->hw_loop1_addr = p->hw_loop1_addr;
	new_p->is_valid = (p->is_valid || p->last_instr_present);
	new_p->pkt_addr = hi->addr;
	new_p->last_access = rz_time_now();
	hex_set_pkt_info(&state->rz_asm, hi, new_p, 0, false);
	if (new_p->last_instr_present) {
		make_next_packet_valid(state, new_p);
	}
	return hi;
}

/**
 * \brief Cleans the least accessed packet and copies the given instruction into it.
 *
 * \param state The state to operade on.
 * \param new_ins The instruction to copy.
 * \return HexInsn* Pointer to the copied instruction on the heap.
 */
static HexInsn *hex_add_to_stale_pkt(HexState *state, const HexInsn *new_ins) {
	HexPkt *p = hex_get_stale_pkt(state);
	hex_clear_pkt(p);

	HexInsn *hi = alloc_instr();
	memcpy(hi, new_ins, sizeof(HexInsn));
	rz_list_insert(p->insn, 0, hi);

	p->last_instr_present |= is_last_instr(hi->parse_bits);
	p->pkt_addr = new_ins->addr;
	// p->is_valid = true; // Setting it true also detects a lot of data as valid assembly.
	p->last_access = rz_time_now();
	hex_set_pkt_info(&state->rz_asm, hi, p, 0, false);
	if (p->last_instr_present) {
		make_next_packet_valid(state, p);
	}
	return hi;
}

/**
 * \brief Copies the given instruction to a state packet it belongs to.
 * If the instruction does not fit to any packet, it will be written to a stale one.
 *
 * The instruction __must__ have its address and parse bits set!
 *
 * \param state The state to operade on.
 * \param new_ins The instruction to be copied.
 * \return The pointer to the added instruction. Null if the instruction could not be copied.
 */
static HexInsn *hex_add_instr_to_state(HexState *state, const HexInsn *new_ins) {
	if (!new_ins) {
		return NULL;
	}
	bool add_to_pkt = false;
	bool new_pkt = false;
	bool write_to_stale_pkt = false;
	bool insert_before_pkt_hi = false;
	ut8 k = 0; // New instruction position in packet.

	HexPkt *p;
	if (new_ins->addr == 0x0) {
		return hex_add_to_stale_pkt(state, new_ins);
	}

	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i, k = 0) {
		p = &(state->pkts[i]);

		HexInsn *pkt_instr = NULL; // Instructions already in the packet.
		RzListIter *iter = NULL;
		rz_list_foreach (p->insn, iter, pkt_instr) {
			if (new_ins->addr == (pkt_instr->addr - 4)) {
				// Instruction preceeds one in the packet.
				if (is_last_instr(new_ins->parse_bits) || is_pkt_full(p)) {
					write_to_stale_pkt = true;
					break;
				} else {
					insert_before_pkt_hi = true;
					add_to_pkt = true;
					break;
				}
			} else if (new_ins->addr == (pkt_instr->addr + 4)) {
				if (is_last_instr(pkt_instr->parse_bits) || is_pkt_full(p)) {
					new_pkt = true;
					break;
				} else {
					add_to_pkt = true;
					break;
				}
			}
			++k;
		}
		if (add_to_pkt || new_pkt || write_to_stale_pkt) {
			break;
		}
	}

	// Add the instruction to packet p
	if (add_to_pkt) {
		if (insert_before_pkt_hi) {
			return hex_add_to_pkt(state, new_ins, p, k);
		}
		return hex_add_to_pkt(state, new_ins, p, k + 1);

	} else if (new_pkt) {
		ut8 ni = (get_state_pkt_index(state, p) + 1) % HEXAGON_STATE_PKTS;
		return hex_to_new_pkt(state, new_ins, p, &state->pkts[ni]);
	} else {
		return hex_add_to_stale_pkt(state, new_ins);
	}
}

/**
 * \brief Set the up new instr.
 *
 * \param hi The instruction to set up.
 * \param rz_reverse RzAsmOp and RzAnalysisOp which could have some data, which needs to be copied.
 * \param addr The address of the instruction.
 * \param parse_bits The parse bits of the instruction
 */
static void setup_new_instr(HexInsn *hi, const HexReversedOpcode *rz_reverse, const ut32 addr, const ut8 parse_bits) {
	hi->instruction = HEX_INS_INVALID_DECODE;
	hi->addr = addr;
	hi->parse_bits = parse_bits;
	if (rz_reverse->asm_op) {
		memcpy(&(hi->asm_op), rz_reverse->asm_op, sizeof(RzAsmOp));
	}
	if (rz_reverse->ana_op) {
		memcpy(&(hi->ana_op), rz_reverse->ana_op, sizeof(RzAnalysisOp));
	}

	hi->ana_op.val = UT64_MAX;
	for (ut8 i = 0; i < 6; ++i) {
		hi->ana_op.analysis_vals[i].imm = ST64_MAX;
	}
	hi->ana_op.jump = UT64_MAX;
	hi->ana_op.fail = UT64_MAX;
	hi->ana_op.ptr = UT64_MAX;

	hi->asm_op.size = 4;
	hi->ana_op.size = 4;
}

static inline bool imm_is_scaled(const HexOpAttr attr) {
	return (attr & HEX_OP_IMM_SCALED);
}

/**
 * \brief Searched the constant extender in the ce_list, where addr is the key.
 *
 * \param ce_list The list with constant extender values.
 * \param addr The address of the instruction which gets the constant extender applied.
 * \return HexConstExt* A const. ext., if there is one which should be applied on the instruction at addr. Otherwise NULL.
 */
static HexConstExt *get_const_ext_from_addr(const RzList *ce_list, const ut32 addr) {
	HexConstExt *ce = NULL;
	RzListIter *iter = NULL;
	rz_list_foreach (ce_list, iter, ce) {
		if (addr == ce->addr) {
			return ce;
		}
	}
	return NULL;
}

/**
 * \brief Applies the constant extender to the immediate value in op.
 *
 * \param state The state to operade on.
 * \param op The operand the extender is applied to or taken from.
 * \param set_new_extender True if the immediate value of the op comes from immext() and sets the a new constant extender. False otherwise.
 * \param addr The address of the currently disassembled instruction.
 */
RZ_API void hex_extend_op(HexState *state, RZ_INOUT HexOp *op, const bool set_new_extender, const ut32 addr) {
	if (rz_list_length(state->const_ext_l) > MAX_CONST_EXT) {
		rz_list_purge(state->const_ext_l);
	}

	if (op->type != HEX_OP_TYPE_IMM) {
		return;
	}

	HexConstExt *ce;
	if (set_new_extender) {
		ce = calloc(1, sizeof(HexConstExt));
		ce->addr = addr + 4;
		ce->const_ext = op->op.imm;
		rz_list_append(state->const_ext_l, ce);
		return;
	}

	ce = get_const_ext_from_addr(state->const_ext_l, addr);
	if (ce) {
		op->op.imm = imm_is_scaled(op->attr) ? (op->op.imm >> op->shift) : op->op.imm;
		op->op.imm = ((op->op.imm & 0x3F) | ce->const_ext);
		rz_list_delete_data(state->const_ext_l, ce);
		return;
	}
}

/**
 * \brief Reverses a given opcode and copies the result into one of the rizin structs in rz_reverse.
 *
 * \param rz_reverse Rizin core structs which store asm and analysis information.
 * \param buf The buffer which stores the current opcode.
 * \param addr The address of the current opcode.
 */
RZ_API void hexagon_reverse_opcode(const RzAsm *rz_asm, HexReversedOpcode *rz_reverse, const ut8 *buf, const ut64 addr) {
	HexState *state = hexagon_get_state();
	if (!state) {
		RZ_LOG_FATAL("HexState was NULL.");
	}
	if (rz_asm) {
		memcpy(&state->rz_asm, rz_asm, sizeof(RzAsm));
	}
	HexInsn *hi = hex_get_instr_at_addr(state, addr);
	if (hi) {
		// Opcode was already reversed and is still in the state. Copy the result and return.
		switch (rz_reverse->action) {
		default:
			memcpy(rz_reverse->asm_op, &(hi->asm_op), sizeof(RzAsmOp));
			memcpy(rz_reverse->ana_op, &(hi->ana_op), sizeof(RzAnalysisOp));
			rz_strbuf_set(&rz_reverse->asm_op->buf_asm, hi->mnem);
			return;
		case HEXAGON_DISAS:
			memcpy(rz_reverse->asm_op, &(hi->asm_op), sizeof(RzAsmOp));
			rz_strbuf_set(&rz_reverse->asm_op->buf_asm, hi->mnem);
			return;
		case HEXAGON_ANALYSIS:
			memcpy(rz_reverse->ana_op, &(hi->ana_op), sizeof(RzAnalysisOp));
			return;
		}
	}

	ut32 data = rz_read_le32(buf);
	ut8 parse_bits = (data & 0x0000c000) >> 14;
	HexInsn instr = { 0 };
	setup_new_instr(&instr, rz_reverse, addr, parse_bits);
	// Add to state
	hi = hex_add_instr_to_state(state, &instr);
	if (!hi) {
		return;
	}
	HexPkt *p = hex_get_pkt(state, hi->addr);

	// Do disasassembly and analysis
	hexagon_disasm_instruction(&state->rz_asm, state, data, hi, p);

	switch (rz_reverse->action) {
	default:
		memcpy(rz_reverse->asm_op, &hi->asm_op, sizeof(RzAsmOp));
		memcpy(rz_reverse->ana_op, &hi->ana_op, sizeof(RzAnalysisOp));
		rz_strbuf_set(&rz_reverse->asm_op->buf_asm, hi->mnem);
		break;
	case HEXAGON_DISAS:
		memcpy(rz_reverse->asm_op, &hi->asm_op, sizeof(RzAsmOp));
		rz_strbuf_set(&rz_reverse->asm_op->buf_asm, hi->mnem);
		break;
	case HEXAGON_ANALYSIS:
		memcpy(rz_reverse->ana_op, &hi->ana_op, sizeof(RzAnalysisOp));
		break;
	}
}