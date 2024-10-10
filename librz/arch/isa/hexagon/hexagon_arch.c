// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: b6f51787f6c8e77143f0aef6b58ddc7c55741d5c
// LLVM commit date: 2023-11-15 07:10:59 -0800 (ISO 8601 format)
// Date of code generation: 2024-03-16 06:22:39-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include "rz_types.h"
#include <rz_util/rz_log.h>
#include <rz_util/rz_buf.h>
#include <rz_list.h>
#include <rz_util/rz_assert.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_vector.h>
#include <hexagon/hexagon.h>
#include <hexagon/hexagon_insn.h>
#include <hexagon/hexagon_arch.h>
#include <hexagon/hexagon_il.h>

RZ_IPI void hexagon_state_fini(RZ_NULLABLE HexState *state) {
	if (!state) {
		return;
	}
	rz_config_free(state->cfg);
	rz_pvector_free(state->token_patterns);
	rz_list_free(state->const_ext_l);
	for (size_t i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		rz_list_free(state->pkts[i].bin);
		rz_pvector_free(state->pkts[i].il_ops);
		hex_il_pkt_stats_fini(&state->pkts[i].il_op_stats);
	}
	return;
}

static inline bool is_invalid_insn_data(ut32 data) {
	return data == HEX_INVALID_INSN_0 || data == HEX_INVALID_INSN_F;
}

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
 * \brief Gives the instruction container at a given address from the state.
 *
 * \param state The state to operate on.
 * \param addr The address of the instruction.
 * \return Pointer to instruction or NULL if none was found.
 */
RZ_API HexInsnContainer *hex_get_hic_at_addr(HexState *state, const ut32 addr) {
	HexPkt *p;
	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		p = &state->pkts[i];
		HexInsnContainer *hic = NULL;
		RzListIter *iter = NULL;
		rz_list_foreach (p->bin, iter, hic) {
			if (addr == hic->addr) {
				p->last_access = rz_time_now_mono();
				RZ_LOG_DEBUG("===== RET buffed_pkts[%d] hic @ 0x010%x ====> \n", i, addr);
				return hic;
			}
		}
	}
	return NULL;
}

static inline bool sub_insn_at_addr(RZ_NONNULL const HexInsnContainer *hic, const ut32 addr) {
	rz_return_val_if_fail(hic, false);
	return (hic->bin.sub[0]->addr == addr || hic->bin.sub[1]->addr == addr);
}

static inline bool hic_at_addr(RZ_NONNULL const HexInsnContainer *hic, const ut32 addr) {
	rz_return_val_if_fail(hic, false);
	return (hic->addr == addr) || (hic->is_duplex && sub_insn_at_addr(hic, addr));
}

/**
 * \brief Gives for an ISA register character the register name.
 * E.g.: If the ISA instruction uses the variable "Rd", it passes 'd' as identifier to this function.
 * The function returns a concrete register name like "R3", "R10" or any other name which is associated with the id.
 *
 * \param hi The hexagon instruction.
 * \param isa_id The ISA register character.
 * \param new_reg If true it will return the .new register name ("R3_tmp", "R10_tmp" etc.)
 * \return const char * The concrete register name. Or NULL on error.
 */
RZ_API const HexOp *hex_isa_to_reg(const HexInsn *hi, const char isa_id, bool new_reg) {
	rz_return_val_if_fail(hi && isa_id, NULL);
	const HexOp *op = NULL;
	for (ut32 i = 0; i < hi->op_count; ++i) {
		if ((hi->ops[i].isa_id == isa_id) && (hi->ops[i].type == HEX_OP_TYPE_REG)) {
			op = &hi->ops[i];
			break;
		}
	}
	if (!op) {
		RZ_LOG_WARN("Could not find equivalent register for ISA variable \'%c\'\n", isa_id);
		return NULL;
	}
	return op;
}

/**
 * \brief Gives for an n-register the HexOp.
 *
 * \param bundle The packet and instruction bundle.
 * \param isa_id The ISA register character this reg is known to the instruction.
 * \return HexOp The HexOp. Or {0} on error.
 */
RZ_API const HexOp hex_nreg_to_op(const HexInsnPktBundle *bundle, const char isa_id) {
	rz_return_val_if_fail(bundle && isa_id, (HexOp){ 0 });
	const HexInsn *hi = bundle->insn;
	const HexOp *op = NULL;
	for (ut32 i = 0; i < hi->op_count; ++i) {
		if ((hi->ops[i].isa_id == isa_id) && (hi->ops[i].type == HEX_OP_TYPE_REG)) {
			op = &hi->ops[i];
			break;
		}
	}
	if (!op) {
		RZ_LOG_WARN("Could not find equivalent register for ISA variable \'%c\'\n", isa_id);
		return (HexOp){ 0 };
	}

	HexOp nop = *op;
	nop.op.reg = resolve_n_register(op->op.reg, hi->addr, bundle->pkt);

	return nop;
}

/**
 * \brief Gives for a ISA immediate character the immediate value stored in the instruction.
 *
 * \param hi The hexagon instruction.
 * \param isa_id The character which identifies the immediate.
 * \return ut64 The immediate value.
 */
RZ_API ut64 hex_isa_to_imm(const HexInsn *hi, const char isa_id) {
	rz_return_val_if_fail(hi && isa_id, 0);
	for (ut32 i = 0; i < hi->op_count; ++i) {
		if (hi->ops[i].isa_id == isa_id && (hi->ops[i].type == HEX_OP_TYPE_IMM)) {
			return hi->ops[i].op.imm;
		}
	}
	RZ_LOG_WARN("No immediate operand for \'%c\' found.\n", isa_id);
	return 0;
}

/**
 * \brief Returns the index of an addr in a given packet.
 *
 * \param addr Address of an instruction.
 * \param p The packet to search in.
 * \return ut8 The index of the addr if it is in the packet. UT8_MAX otherwise.
 */
RZ_API ut8 hexagon_get_pkt_index_of_addr(const ut32 addr, const HexPkt *p) {
	rz_return_val_if_fail(p, UT8_MAX);

	HexInsnContainer *hic = NULL;
	RzListIter *it = NULL;
	ut8 i = 0;
	rz_list_foreach (p->bin, it, hic) {
		if (hic_at_addr(hic, addr)) {
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
	p->is_eob = false;
	p->hw_loop = HEX_NO_LOOP;
	p->hw_loop0_addr = 0;
	p->hw_loop1_addr = 0;
	p->pkt_addr = 0;
	p->last_instr_present = false;
	p->is_valid = false;
	p->last_access = 0;
	rz_list_purge(p->bin);
	rz_pvector_clear(p->il_ops);
	hex_il_pkt_stats_reset(&p->il_op_stats);
}

/**
 * \brief Gives the least used packet.
 *
 * \param state The state to operate on.
 * \return HexPkt* Pointer to the least used packet.
 */
static HexPkt *hex_get_stale_pkt(HexState *state) {
	HexPkt *stale_state_pkt = &state->pkts[0];
	ut64 oldest = UT64_MAX;

	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		if (state->pkts[i].last_access < oldest) {
			oldest = state->pkts[i].last_access;
			stale_state_pkt = &state->pkts[i];
		}
	}
	return stale_state_pkt;
}

/**
 * \brief Returns the packet which covers the given address.
 *
 * \param state The state to operate on.
 * \param addr The address of an instruction.
 * \return HexPkt* The packet to which this address belongs to or NULL if no packet was found.
 */
RZ_API HexPkt *hex_get_pkt(RZ_BORROW HexState *state, const ut32 addr) {
	HexPkt *p = NULL;
	HexInsnContainer *hic = NULL;
	RzListIter *iter = NULL;
	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		p = &state->pkts[i];
		if (rz_list_length(p->bin) == 0) {
			continue;
		}
		rz_list_foreach (p->bin, iter, hic) {
			if (hic_at_addr(hic, addr)) {
				p->last_access = rz_time_now_mono();
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
	free(i);
}

/**
 * \brief Frees an instruction container.
 *
 * \param i The instruction container to be freed.
 */
RZ_API void hex_insn_container_free(RZ_NULLABLE HexInsnContainer *c) {
	if (c) {
		// bin is a uninion. Just free all of them.
		hex_insn_free(c->bin.sub[0]);
		hex_insn_free(c->bin.sub[1]);
	}
	free(c);
}

/**
 * \brief Moves one instruction container to another.
 *
 * \param dest The destination insruction container.
 * \param src The source instruction container.
 */
RZ_API void hex_move_insn_container(RZ_OUT HexInsnContainer *dest, const HexInsnContainer *src) {
	rz_return_if_fail(dest && src);
	memmove(dest, src, sizeof(HexInsnContainer));
}

/**
 * \brief Frees an constant extender.
 *
 * \param ce The constant extender to be freed.
 */
RZ_API void hex_const_ext_free(RZ_NULLABLE HexConstExt *ce) {
	free(ce);
}

/**
 * \brief Get the index of a packet in the state
 *
 * \param state The state to operate on.
 * \param p The packet which index should be determined.
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
 * Note that this state is not thread safe.
 * It requires RzArch for this.
 *
 * \param reset Reset the state to NULL. Assumes it was freed before.
 *
 * \return The initialized state of the plugins or NULL if \p reset = true.
 */
RZ_API HexState *hexagon_state_new() {
	HexState *state = RZ_NEW0(HexState);
	if (!state) {
		RZ_LOG_FATAL("Could not allocate memory for HexState!");
		return NULL;
	}
	for (int i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		state->pkts[i].bin = rz_list_newf((RzListFree)hex_insn_container_free);
		state->pkts[i].il_ops = rz_pvector_new(NULL);
		if (!state->pkts[i].bin) {
			RZ_LOG_FATAL("Could not initialize instruction list!");
			return NULL;
		}
		hex_clear_pkt(&(state->pkts[i]));
	}
	state->const_ext_l = rz_list_newf((RzListFree)hex_const_ext_free);
	state->token_patterns = NULL;
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
	return rz_list_length(p->bin) >= 4;
}

/**
 * \brief Get the pkt indicator string.
 *
 * \param utf8 True: Return UTF8 string. False: Return ASCII.
 * \param sdk True: Return SDK conforming string ('{', '}', ':endloop0' etc.).
 * False: Returns a non SDK conforming string
 * \param prefix True: Return the prefix indicator. False: Return the postfix.
 * If there is no prefix/postfix for a given indicator type (e.g. for the utf8 version of 'endloop01')
 * it returns an empty string.
 * \param ind_type The
 * \param prefix
 * \return char* The indicator string according to the given flags.
 */
static char *get_pkt_indicator(const bool utf8, const bool sdk, const bool prefix, HexPktSyntaxIndicator ind_type) {
	switch (ind_type) {
	default:
		return "";
	case SINGLE_IN_PKT:
		if (prefix) {
			if (sdk) {
				return HEX_PKT_FIRST_SDK;
			} else {
				return utf8 ? HEX_PKT_SINGLE_UTF8 : HEX_PKT_SINGLE;
			}
		} else {
			if (sdk) {
				return HEX_PKT_LAST_SDK;
			}
		}
		break;
	case FIRST_IN_PKT:
		if (!prefix) {
			break;
		}
		if (sdk) {
			return HEX_PKT_FIRST_SDK;
		}
		if (utf8) {
			return HEX_PKT_FIRST_UTF8;
		} else {
			return HEX_PKT_FIRST;
		}
		break;
	case MID_IN_PKT:
		if (!prefix) {
			break;
		}
		if (sdk) {
			return HEX_PKT_SDK_PADDING;
		}
		if (utf8) {
			return HEX_PKT_MID_UTF8;
		} else {
			return HEX_PKT_MID;
		}
		break;
	case LAST_IN_PKT:
		if (prefix) {
			if (sdk) {
				return HEX_PKT_SDK_PADDING;
			}
			if (utf8) {
				return HEX_PKT_LAST_UTF8;
			} else {
				return HEX_PKT_LAST;
			}
		} else {
			if (sdk) {
				return HEX_PKT_LAST_SDK;
			}
		}
		break;
	case ELOOP_0_PKT:
		if (prefix) {
			break;
		}
		if (sdk) {
			return HEX_PKT_ELOOP_0_SDK;
		}
		if (utf8) {
			return HEX_PKT_ELOOP_0_UTF8;
		} else {
			return HEX_PKT_ELOOP_0;
		}
		break;
	case ELOOP_1_PKT:
		if (prefix) {
			break;
		}
		if (sdk) {
			return HEX_PKT_ELOOP_1_SDK;
		}
		if (utf8) {
			return HEX_PKT_ELOOP_1_UTF8;
		} else {
			return HEX_PKT_ELOOP_1;
		}
		break;
	case ELOOP_01_PKT:
		if (prefix) {
			break;
		}
		if (sdk) {
			return HEX_PKT_ELOOP_01_SDK;
		}
		if (utf8) {
			return HEX_PKT_ELOOP_01_UTF8;
		} else {
			return HEX_PKT_ELOOP_01;
		}
		break;
	}
	return "";
}

/**
 * \brief Sets the instruction container testual disassmebly by concatinating text prefix, infix and postfix.
 *
 * \param hic The instruction container.
 */
void hex_set_hic_text(RZ_INOUT HexInsnContainer *hic) {
	rz_return_if_fail(hic);
	if (hic->is_duplex) {
		rz_return_if_fail(hic->bin.sub[0] && hic->bin.sub[1]);
		snprintf(hic->text, sizeof(hic->text), "%s%s%s%s%s", hic->pkt_info.text_prefix, hic->bin.sub[0]->text_infix, " ; ", hic->bin.sub[1]->text_infix, hic->pkt_info.text_postfix);
	} else {
		snprintf(hic->text, sizeof(hic->text), "%s%s%s", hic->pkt_info.text_prefix, hic->bin.insn->text_infix, hic->pkt_info.text_postfix);
	}
}

/**
 * \brief Sets the packet related information in an instruction.
 *
 * \param hi The instruction.
 * \param pkt The packet the instruction belongs to.
 * \param k The index of the instruction within the packet.
 */
static void hex_set_pkt_info(const RzAsm *rz_asm, RZ_INOUT HexInsnContainer *hic, const HexPkt *pkt, const ut8 k, const bool update_text, HexState *state) {
	rz_return_if_fail(hic && pkt && state);
	bool is_first = (k == 0);
	HexPktInfo *hi_pi = &hic->pkt_info;
	bool sdk_form = rz_config_get_b(state->cfg, "plugins.hexagon.sdk");

	strncpy(hi_pi->text_postfix, "", 16);
	// Parse instr. position in pkt
	if (is_first && is_last_instr(hic->parse_bits)) { // Single instruction packet.
		hi_pi->first_insn = true;
		hi_pi->last_insn = true;
		if (pkt->is_valid) {
			strncpy(hi_pi->text_prefix, get_pkt_indicator(rz_asm->utf8, sdk_form, true, SINGLE_IN_PKT), 8);
			if (sdk_form) {
				strncpy(hi_pi->text_postfix, get_pkt_indicator(rz_asm->utf8, sdk_form, false, SINGLE_IN_PKT), 8);
			}
		} else {
			strncpy(hi_pi->text_prefix, HEX_PKT_UNK, 8);
		}
	} else if (is_first) {
		hi_pi->first_insn = true;
		hi_pi->last_insn = false;
		if (pkt->is_valid) {
			strncpy(hi_pi->text_prefix, get_pkt_indicator(rz_asm->utf8, sdk_form, true, FIRST_IN_PKT), 8);
		} else {
			strncpy(hi_pi->text_prefix, HEX_PKT_UNK, 8);
		}
	} else if (is_last_instr(hic->parse_bits)) {
		hi_pi->first_insn = false;
		hi_pi->last_insn = true;
		if (pkt->is_valid) {
			strncpy(hi_pi->text_prefix, get_pkt_indicator(rz_asm->utf8, sdk_form, true, LAST_IN_PKT), 8);
			if (sdk_form) {
				strncpy(hi_pi->text_postfix, get_pkt_indicator(rz_asm->utf8, sdk_form, false, LAST_IN_PKT), 8);
			}

			switch (hex_get_loop_flag(pkt)) {
			default:
				break;
			case HEX_LOOP_01:
				strncat(hi_pi->text_postfix, get_pkt_indicator(rz_asm->utf8, sdk_form, false, ELOOP_01_PKT), 23 - strlen(hi_pi->text_postfix));
				break;
			case HEX_LOOP_0:
				strncat(hi_pi->text_postfix, get_pkt_indicator(rz_asm->utf8, sdk_form, false, ELOOP_0_PKT), 23 - strlen(hi_pi->text_postfix));
				break;
			case HEX_LOOP_1:
				strncat(hi_pi->text_postfix, get_pkt_indicator(rz_asm->utf8, sdk_form, false, ELOOP_1_PKT), 23 - strlen(hi_pi->text_postfix));
				break;
			}
		} else {
			strncpy(hi_pi->text_prefix, HEX_PKT_UNK, 8);
		}
	} else {
		hi_pi->first_insn = false;
		hi_pi->last_insn = false;
		if (pkt->is_valid) {
			strncpy(hi_pi->text_prefix, get_pkt_indicator(rz_asm->utf8, sdk_form, true, MID_IN_PKT), 8);
		} else {
			strncpy(hi_pi->text_prefix, HEX_PKT_UNK, 8);
		}
	}
	if (update_text) {
		hex_set_hic_text(hic);
	}
}

/**
 * \brief Returns the loop type of a packet. But only if this packet is
 * 	the last packet in a hardware loop. Otherwise it returns HEX_NO_LOOP.
 *
 * \param p The instruction packet.
 * \return HexLoopAttr The loop type this packet belongs to.
 */
RZ_API HexLoopAttr hex_get_loop_flag(const HexPkt *p) {
	if (!p || rz_list_length(p->bin) < 2) {
		return HEX_NO_LOOP;
	}

	ut8 pb_0 = ((HexInsnContainer *)rz_list_get_n(p->bin, 0))->parse_bits;
	ut8 pb_1 = ((HexInsnContainer *)rz_list_get_n(p->bin, 1))->parse_bits;

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
 * \brief Sets the given packet to valid and updates the packet information of
 * each instruction in it.
 *
 * \param state The to operate on.
 * \param pkt The packet to set to valid.
 */
static void make_packet_valid(RZ_BORROW HexState *state, RZ_BORROW HexPkt *pkt) {
	rz_return_if_fail(state && pkt);
	pkt->is_valid = true;
	HexInsnContainer *hi = NULL;
	RzListIter *it = NULL;
	ut8 i = 0;
	ut8 slot = 0;
	rz_list_foreach (pkt->bin, it, hi) {
		hex_set_pkt_info(&state->rz_asm, hi, pkt, i, true, state);
		if (hi->is_duplex) {
			hi->bin.sub[0]->slot = 0;
			hi->bin.sub[1]->slot = 1;
			slot = 2;
		} else {
			hi->bin.insn->slot = slot;
			++slot;
		}
		++i;
	}
	pkt->last_access = rz_time_now_mono();
}

/**
 * \brief Sets the packet after \p pkt to valid and updates its textual assembly.
 *
 * \param state The state to operate on.
 * \param pkt The packet which predecessor will be updated.
 */
static void make_next_packet_valid(HexState *state, const HexPkt *pkt) {
	HexInsnContainer *tmp = rz_list_get_n(pkt->bin, 0);
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
			make_packet_valid(state, p);
			break;
		}
	}
}

/**
 * \brief Allocates a new instruction on the heap.
 *
 * \return HexInsn* The new instruction or NULL on failure.
 */
RZ_API HexInsn *hexagon_alloc_instr() {
	HexInsn *hi = RZ_NEW0(HexInsn);
	if (!hi) {
		RZ_LOG_FATAL("Could not allocate memory for new instruction.\n");
		return NULL;
	}
	hi->fround_mode = RZ_FLOAT_RMODE_RNE;
	return hi;
}

/**
 * \brief Allocates a new instruction container on the heap.
 *
 * \return HexInsnContainer* The new instruction container or NULL on failure.
 */
RZ_API HexInsnContainer *hexagon_alloc_instr_container() {
	HexInsnContainer *hic = RZ_NEW0(HexInsnContainer);
	if (!hic) {
		RZ_LOG_FATAL("Could not allocate memory for new instruction container.\n");
		return NULL;
	}
	return hic;
}

/**
 * \brief Copies an instruction container to the packet p at position k.
 *
 * \param state The state to operate on.
 * \param new_hic The instruction container to copy.
 * \param pkt The packet in which will hold the instruction container.
 * \param k The index of the instruction container in the packet.
 * \return HexInsnContainer* Pointer to the copied instruction container on the heap.
 */
static HexInsnContainer *hex_add_to_pkt(HexState *state, const HexInsnContainer *new_hic, RZ_INOUT HexPkt *pkt, const ut8 k) {
	if (k > 3) {
		RZ_LOG_FATAL("Instruction could not be set! A packet can only hold four instructions but k=%d.", k);
		return NULL;
	}
	HexInsnContainer *hic = hexagon_alloc_instr_container();
	hex_move_insn_container(hic, new_hic);
	rz_list_del_n(pkt->bin, k);
	rz_list_insert(pkt->bin, k, hic);

	if (k == 0) {
		pkt->pkt_addr = hic->addr;
	}
	pkt->last_instr_present |= is_last_instr(hic->parse_bits);
	ut32 p_l = rz_list_length(pkt->bin);
	hex_set_pkt_info(&state->rz_asm, hic, pkt, k, false, state);
	if (k == 0 && p_l > 1) {
		// Update the instruction which was previously the first one.
		hex_set_pkt_info(&state->rz_asm, rz_list_get_n(pkt->bin, 1), pkt, 1, true, state);
	}
	pkt->last_access = rz_time_now_mono();
	if (pkt->last_instr_present) {
		make_next_packet_valid(state, pkt);
	}
	return hic;
}

/**
 * \brief Cleans the packet \p new_p, copies the instruction container \p new_hic and the attributes of \p p to it.
 *
 * \param state The state to operate on.
 * \param new_hic The instruction container to copy.
 * \param pkt The old packet which attributes are copied to the new one.
 * \param new_pkt The new packet will hold the instruction container.
 * \return HexInsnContainer* Pointer to the copied instruction container on the heap.
 */
static HexInsnContainer *hex_to_new_pkt(HexState *state, const HexInsnContainer *new_hic, const HexPkt *pkt, RZ_INOUT HexPkt *new_pkt) {
	hex_clear_pkt(new_pkt);

	HexInsnContainer *hic = hexagon_alloc_instr_container();
	hex_move_insn_container(hic, new_hic);
	rz_list_del_n(new_pkt->bin, 0);
	rz_list_insert(new_pkt->bin, 0, hic);

	new_pkt->last_instr_present |= is_last_instr(hic->parse_bits);
	new_pkt->hw_loop0_addr = pkt->hw_loop0_addr;
	new_pkt->hw_loop1_addr = pkt->hw_loop1_addr;
	new_pkt->is_valid = (pkt->is_valid || pkt->last_instr_present);
	new_pkt->pkt_addr = hic->addr;
	new_pkt->last_access = rz_time_now_mono();
	hex_set_pkt_info(&state->rz_asm, hic, new_pkt, 0, false, state);
	if (new_pkt->last_instr_present) {
		make_next_packet_valid(state, new_pkt);
	}
	return hic;
}

/**
 * \brief Cleans the least accessed packet and copies the given instruction container into it.
 *
 * \param state The state to operate on.
 * \param new_hic The instruction container to copy.
 * \return HexInsnContainer* Pointer to the copied instruction container on the heap.
 */
static HexInsnContainer *hex_add_to_stale_pkt(HexState *state, const HexInsnContainer *new_hic) {
	HexPkt *pkt = hex_get_stale_pkt(state);
	hex_clear_pkt(pkt);

	HexInsnContainer *hic = hexagon_alloc_instr_container();
	hex_move_insn_container(hic, new_hic);
	rz_list_insert(pkt->bin, 0, hic);

	pkt->last_instr_present |= is_last_instr(hic->parse_bits);
	pkt->pkt_addr = new_hic->addr;
	// p->is_valid = true; // Setting it true also detects a lot of data as valid assembly.
	pkt->last_access = rz_time_now_mono();
	hex_set_pkt_info(&state->rz_asm, hic, pkt, 0, false, state);
	if (pkt->last_instr_present) {
		make_next_packet_valid(state, pkt);
	}
	return hic;
}

#if RZ_BUILD_DEBUG
static char desc_letter_hic(const HexInsnContainer *hic) {
	char desc = ' ';
	if (!hic) {
		desc = ' ';
	} else if (hic->is_duplex) {
		desc = hic->bin.sub[0]->identifier != HEX_INS_INVALID_DECODE ? 'v' : 'i';
		desc = hic->pkt_info.last_insn ? 'l' : desc;
	} else {
		desc = hic->bin.insn->identifier != HEX_INS_INVALID_DECODE ? 'v' : 'i';
		desc = hic->pkt_info.last_insn ? 'l' : desc;
	}
	return desc;
}
#endif

static void print_state_pkt(const HexState *state, st32 index, HexBufferAction action, const HexInsnContainer *new_hic) {
#if RZ_BUILD_DEBUG
	ut32 oldest = 7;
	ut32 newest = 0;
	ut64 min_time = 0xffffffffffffffff;
	ut64 max_time = 0;
	for (int i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		const HexPkt *pkt = &state->pkts[i];
		if (pkt->last_access < min_time) {
			min_time = pkt->last_access;
			oldest = i;
		}
		if (pkt->last_access > max_time) {
			max_time = pkt->last_access;
			newest = i;
		}
	}
	RZ_LOG_DEBUG("╭─────┬──────────────┬─────┬──────────────────┬───────────────╮\n");
	RZ_LOG_DEBUG("│ pkt │   packet     │     │                  │ [i]n[v]alid   │\n");
	RZ_LOG_DEBUG("│ id  │   address    │ age │    last access   │ [l]ast        │\n");
	RZ_LOG_DEBUG("├─────┼──────────────┼─────┼──────────────────┼───┬───┬───┬───┤\n");
	RzStrBuf *pkt_line = rz_strbuf_new("");
	for (int i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		const HexPkt *pkt = &state->pkts[i];
		const char *time_ind = "   ";
		if (i == oldest) {
			time_ind = "old";
		} else if (i == newest) {
			time_ind = "new";
		}
		rz_strbuf_appendf(pkt_line, "│  %d  │ 0x%010x │ %s │ %016llu │ ", i, pkt->pkt_addr, time_ind, pkt->last_access);
		HexInsnContainer *hic = NULL;
		for (int j = 0; j < 4; ++j) {
			hic = rz_list_get_n(pkt->bin, j);
			const char desc = desc_letter_hic(hic);
			rz_strbuf_appendf(pkt_line, "%c │ ", desc);
		}
		if ((index < 0 && i == oldest) || (index == i)) {
			const char desc = desc_letter_hic(new_hic);
			rz_strbuf_append(pkt_line, " < ");
			if (action == HEX_BUF_ADD) {
				rz_strbuf_appendf(pkt_line, "%s %c", "ADDED", desc);
			} else if (action == HEX_BUF_STALE) {
				rz_strbuf_appendf(pkt_line, "added %c %s", desc, "to STALE");
			} else if (action == HEX_BUF_NEW) {
				rz_strbuf_appendf(pkt_line, "added %c %s", desc, "to NEW");
			}
		}
		rz_strbuf_append(pkt_line, "\n");
		RZ_LOG_DEBUG("%s", rz_strbuf_get(pkt_line));
		rz_strbuf_fini(pkt_line);
		if (i < HEXAGON_STATE_PKTS - 1) {
			RZ_LOG_DEBUG("├─────┼──────────────┼─────┼──────────────────┼───┼───┼───┼───┤\n");
		} else {
			RZ_LOG_DEBUG("╰─────┴──────────────┴─────┴──────────────────┴───┴───┴───┴───╯\n");
		}
	}
	rz_strbuf_free(pkt_line);
#endif
}

/**
 * \brief Copies the given instruction container to a state packet it belongs to.
 * If the instruction container does not fit to any packet, it will be written to a stale one.
 *
 * The instruction container __must__ have its address and parse bits set!
 *
 * \param state The state to operate on.
 * \param new_hic The instruction continer to be copied.
 * \return The pointer to the added instruction. Null if the instruction could not be copied.
 */
static HexInsnContainer *hex_add_hic_to_state(HexState *state, const HexInsnContainer *new_hic) {
	if (!new_hic) {
		return NULL;
	}
	bool add_to_pkt = false;
	bool new_pkt = false;
	bool write_to_stale_pkt = false;
	bool insert_before_pkt_hi = false;
	ut8 k = 0; // New instruction position in packet.

	HexPkt *p;
	if (new_hic->addr == 0x0) {
		return hex_add_to_stale_pkt(state, new_hic);
	}

	ut32 i = 0;
	for (; i < HEXAGON_STATE_PKTS; ++i, k = 0) {
		p = &(state->pkts[i]);

		HexInsnContainer *p_hic = NULL; // Instructions container already in the packet.
		RzListIter *iter = NULL;
		rz_list_foreach (p->bin, iter, p_hic) {
			if (new_hic->addr == (p_hic->addr - 4)) {
				// Instruction precedes one in the packet.
				if (is_last_instr(new_hic->parse_bits) || is_pkt_full(p)) {
					// Continue searching. The instruction might belong to another packet.
					continue;
				} else {
					insert_before_pkt_hi = true;
					add_to_pkt = true;
					break;
				}
			} else if (new_hic->addr == (p_hic->addr + 4)) {
				if (is_last_instr(p_hic->parse_bits) || is_pkt_full(p)) {
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
	if (!add_to_pkt && !new_pkt && !write_to_stale_pkt) {
		// No packet found this one belongs to.
		// Add to a stale one.
		write_to_stale_pkt = true;
	}

	// Add the instruction to packet p
	if (add_to_pkt) {
		if (insert_before_pkt_hi) {
			HexInsnContainer *result_hic = hex_add_to_pkt(state, new_hic, p, k);
			print_state_pkt(state, i, HEX_BUF_ADD, result_hic);
			return result_hic;
		}
		HexInsnContainer *result_hic = hex_add_to_pkt(state, new_hic, p, k + 1);
		print_state_pkt(state, i, HEX_BUF_ADD, result_hic);
		return result_hic;
	} else if (new_pkt) {
		ut8 ni = (get_state_pkt_index(state, p) + 1) % HEXAGON_STATE_PKTS;
		HexInsnContainer *result_hic = hex_to_new_pkt(state, new_hic, p, &state->pkts[ni]);
		print_state_pkt(state, ni, HEX_BUF_NEW, result_hic);
		return result_hic;
	}
	HexInsnContainer *result_hic = hex_add_to_stale_pkt(state, new_hic);
	print_state_pkt(state, -1, HEX_BUF_STALE, result_hic);
	return result_hic;
}

/**
 * \brief Set the up a new instruction container.
 *
 * \param hic The instruction container to set up.
 * \param rz_reverse RzAsmOp and RzAnalysisOp which could have some data, which needs to be copied.
 * \param addr The address of the instruction container.
 * \param parse_bits The parse bits of the instruction container.
 */
static void setup_new_hic(HexInsnContainer *hic, const HexReversedOpcode *rz_reverse, const ut32 addr, const ut8 parse_bits, ut32 data) {
	rz_return_if_fail(hic && rz_reverse);
	bool invalid = is_invalid_insn_data(data);
	hic->identifier = HEX_INS_INVALID_DECODE;
	hic->bytes = data;
	hic->addr = addr;
	hic->parse_bits = parse_bits;
	if (rz_reverse->asm_op) {
		memcpy(&(hic->asm_op), rz_reverse->asm_op, sizeof(RzAsmOp));
	}
	if (rz_reverse->ana_op) {
		memcpy(&(hic->ana_op), rz_reverse->ana_op, sizeof(RzAnalysisOp));
	}

	hic->ana_op.val = UT64_MAX;
	for (ut8 i = 0; i < 6; ++i) {
		hic->ana_op.analysis_vals[i].imm = ST64_MAX;
	}
	hic->ana_op.jump = UT64_MAX;
	hic->ana_op.fail = UT64_MAX;
	hic->ana_op.ptr = UT64_MAX;

	hic->asm_op.size = 4;
	hic->ana_op.size = 4;

	hic->bin.sub[0] = NULL;
	hic->bin.sub[1] = NULL;
	if (parse_bits == 0b00 && !invalid) {
		hic->is_duplex = true;
		hic->bin.sub[0] = hexagon_alloc_instr();
		hic->bin.sub[1] = hexagon_alloc_instr();
	} else {
		hic->bin.insn = hexagon_alloc_instr();
	}
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
static HexConstExt *get_const_ext_from_addr(const RzList /*<HexConstExt *>*/ *ce_list, const ut32 addr) {
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
 * \param state The state to operate on.
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
		ce = RZ_NEW0(HexConstExt);
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

static void copy_asm_ana_ops(HexState *state, RZ_BORROW HexReversedOpcode *rz_reverse, RZ_BORROW HexInsnContainer *hic) {
	rz_return_if_fail(state && rz_reverse && hic);
	rz_reverse->state = state;
	switch (rz_reverse->action) {
	default:
		memcpy(rz_reverse->asm_op, &hic->asm_op, sizeof(RzAsmOp));
		memcpy(rz_reverse->ana_op, &hic->ana_op, sizeof(RzAnalysisOp));
		rz_strbuf_set(&rz_reverse->asm_op->buf_asm, hic->text);
		rz_reverse->asm_op->asm_toks = rz_asm_tokenize_asm_regex(&rz_reverse->asm_op->buf_asm, state->token_patterns);
		if (rz_reverse->asm_op->asm_toks) {
			rz_reverse->asm_op->asm_toks->op_type = hic->ana_op.type;
		}
		break;
	case HEXAGON_DISAS:
		memcpy(rz_reverse->asm_op, &hic->asm_op, sizeof(RzAsmOp));
		rz_strbuf_set(&rz_reverse->asm_op->buf_asm, hic->text);
		rz_reverse->asm_op->asm_toks = rz_asm_tokenize_asm_regex(&rz_reverse->asm_op->buf_asm, state->token_patterns);
		if (rz_reverse->asm_op->asm_toks) {
			rz_reverse->asm_op->asm_toks->op_type = hic->ana_op.type;
		}
		break;
	case HEXAGON_ANALYSIS:
		memcpy(rz_reverse->ana_op, &hic->ana_op, sizeof(RzAnalysisOp));
		break;
	}
}

/**
 * \brief Checks if the packet \p pkt has a jump and deallocframe instructions.
 * This indicates it is a tail call.
 * It sets the relevant flags accordingly.
 *
 * \param pkt The instruction packet to check.
 */
RZ_IPI void hexagon_pkt_mark_tail_calls(HexPkt *pkt) {
	rz_return_if_fail(pkt);
	ut32 n = rz_list_length(pkt->bin);
	if (!pkt->last_instr_present || n < 2) {
		return;
	}
	HexInsnContainer *hic = rz_list_get_n(pkt->bin, 0);
	HexInsnContainer *hic1 = rz_list_get_n(pkt->bin, 1);
	if (hic->identifier != HEX_INS_L2_DEALLOCFRAME && hic1->identifier != HEX_INS_L2_DEALLOCFRAME) {
		// deallocframe is a store/load instruction and can only inhabit slot 0 and 1.
		return;
	}
	bool is_tail_call = false;
	for (size_t i = 0; i < n; ++i) {
		hic = rz_list_get_n(pkt->bin, i);
		if (hic->identifier == HEX_INS_J2_JUMP) {
			is_tail_call = true;
			break;
		}
	}
	if (!is_tail_call) {
		return;
	}
	for (size_t i = 0; i < n; ++i) {
		hic = rz_list_get_n(pkt->bin, i);
		hic->ana_op.type |= RZ_ANALYSIS_OP_TYPE_TAIL;
	}
	hic = rz_list_get_n(pkt->bin, n - 1);
	hic->ana_op.eob = true;
	// This is nonesense. And we can just hope it doesn't
	// break anything. The instruction is no return instruction.
	// But we just don't have any other way currently to signal the
	// block analysis, that the function ends here.
	// eob (end of block) is ignored.
	// So until RzArch is not done, there is no other way.
	hic->ana_op.type = RZ_ANALYSIS_OP_TYPE_TAIL | RZ_ANALYSIS_OP_TYPE_RET;
}

static RZ_BORROW HexInsnContainer *decode_hic(HexState *state, HexReversedOpcode *rz_reverse, RZ_BORROW RzBuffer *buffer, const ut64 addr) {
	ut8 tmp[HEX_INSN_SIZE] = { 0 };
	ut32 bytes = rz_buf_read(buffer, tmp, 4);
	if (bytes != HEX_INSN_SIZE) {
		RZ_LOG_DEBUG("Failed to read from buffer!\n");
		return NULL;
	}
	ut32 data = rz_read_le32(tmp);
	ut8 parse_bits = HEX_PARSE_BITS_FROM_UT32(data);
	HexInsnContainer hic_new = { 0 };
	setup_new_hic(&hic_new, rz_reverse, addr, parse_bits, data);

	// Add to state as not yet fully decoded packet.
	HexInsnContainer *hic = hex_add_hic_to_state(state, &hic_new);
	if (!hic) {
		RZ_LOG_ERROR("Could not add incsturction container to state.\n");
		return NULL;
	}
	HexPkt *p = hex_get_pkt(state, hic->addr);

	// Do disassembly and analysis
	hexagon_disasm_instruction(state, data, hic, p);
	return hic;
}

/**
 * \brief Returns the address at which the decoding must start to get a valid packet at \p addr.
 * The \p buffer seek is set to the position to start reading from.
 *
 * \return The address to start decoding. It always returns an address <= \p addr
 * and with an offset with an multiple of HEX_INSN_SIZE.
 */
static ut64 get_pre_decoding_start(RZ_BORROW RzBuffer *buffer, ut64 addr) {
	rz_return_val_if_fail(buffer, addr);	
	ut64 seek = rz_buf_tell(buffer);
	if (addr < HEX_INSN_SIZE && seek < HEX_INSN_SIZE) {
		goto seek_return;
	}

	size_t look_back = 0;
	bool is_last_insn = false;
	// Search until we cross a boundary or have found a last instruction.
	while (addr >= HEX_INSN_SIZE && seek >= HEX_INSN_SIZE && look_back < 4 && !is_last_insn) {
		ut8 tmp[HEX_INSN_SIZE] = { 0 };
		ut32 bytes = rz_buf_read(buffer, tmp, 4);
		if (bytes != HEX_INSN_SIZE) {
			goto seek_return;
		}
		ut32 data = rz_read_le32(tmp);
		is_last_insn = is_last_instr(HEX_PARSE_BITS_FROM_UT32(data));
		if (!rz_buf_seek(buffer, -HEX_INSN_SIZE, RZ_BUF_CUR)) {
			goto seek_return;
		}
		addr -= HEX_INSN_SIZE;
		look_back++;
	}

seek_return:
	if (rz_buf_seek(buffer, addr, RZ_BUF_CUR) != addr) {
		RZ_LOG_ERROR("Could not seek to address: 0x%" PFMT64x "\n", addr);
		return UT64_MAX;
	}
	return addr;
}

static bool perform_hacks(HexState **state, RzBuffer **buffer, RzAsm **rz_asm, RzAnalysis **rz_analysis, HexReversedOpcode *rz_reverse) {
	if (*rz_analysis) {
		*rz_asm = rz_analysis_to_rz_asm(*rz_analysis);
		assert(*rz_asm && (*rz_asm)->cur && (*rz_analysis)->cur && RZ_STR_EQ((*rz_asm)->cur->arch, (*rz_analysis)->cur->arch));
	} else if (*rz_asm) {
		*rz_analysis = rz_asm_to_rz_analysis(*rz_asm);
		if (*rz_analysis && (*rz_analysis)->cur) {
			assert(RZ_STR_EQ((*rz_asm)->cur->arch, (*rz_analysis)->cur->arch));
		}
	} else {
		assert(0 && "Requires either RzAsm or RzAnalysis");
	}

	// Set Buffer
	if (!((*rz_analysis) && (*rz_analysis)->cur)) {
		// Only RzAsm present (rz-test, rz-asm etc.). So also likely a test situation without IO.
		*buffer = rz_buf_new_with_bytes(rz_reverse->bytes_buf, rz_reverse->bytes_buf_len);
		rz_return_val_if_fail(*buffer, false);
	} else {
		*buffer = rz_buf_new_with_io(&(*rz_analysis)->iob);
		rz_return_val_if_fail(*buffer, false);
	}
	*state = (*rz_asm)->plugin_data;
	rz_return_val_if_fail(*state, false);
	return true;
}

/**
 * \brief Reverses a given opcode and copies the result into one of the rizin structs in rz_reverse
 * if \p copy_result is set.
 *
 * \param rz_reverse Rizin core structs which store asm and analysis information.
 * \param buf The buffer which stores the current opcode.
 * \param addr The address of the current opcode.
 * \param copy_result If set, it copies the result. Otherwise it only buffers it in the internal state.
 */
RZ_API void hexagon_reverse_opcode(HexReversedOpcode *rz_reverse, const ut64 addr, RzAsm *rz_asm, RzAnalysis *rz_analysis) {
	rz_return_if_fail(rz_reverse);
	HexState *state;
	RzBuffer *buffer;
	if (!perform_hacks(&state, &buffer, &rz_asm, &rz_analysis, rz_reverse)) {
		RZ_LOG_FATAL("Could not preform pointer hacks. Sorry.\n");
		return;
	}
	if (rz_asm) {
		memcpy(&state->rz_asm, rz_asm, sizeof(RzAsm));
	}
	ut64 pre_addr = get_pre_decoding_start(buffer, addr);
	//printf("addr: 0x%llx - seek: 0x%llx - pre_addr: 0x%llx\n", addr, rz_buf_tell(buffer), pre_addr);

	HexInsnContainer *hic = NULL;
	// Do pre-decoding to know the context.
	while (pre_addr < addr) {
		if (hex_get_hic_at_addr(state, pre_addr)) {
			// Already decoded.
			pre_addr += HEX_INSN_SIZE;
			continue;
		}
		hic = decode_hic(state, rz_reverse, buffer, pre_addr);
		if (!hic) {
			RZ_LOG_ERROR("Filed during pre-decoding.\n");
			rz_buf_free(buffer);
			return;
		}
		pre_addr += HEX_INSN_SIZE;
	}
	if (addr != 0) {
		// Only check for buffered instructions not at 0x0.
		// Because structs are 0 initialized.
		hic = hex_get_hic_at_addr(state, addr);
	}
	if (!hic) {
		hic = decode_hic(state, rz_reverse, buffer, addr);
	}
	if (!hic) {
		RZ_LOG_DEBUG("Could not decode packet.\n");
		rz_buf_free(buffer);
		return;
	}
	HexPkt *p = hex_get_pkt(state, hic->addr);
	rz_reverse->pkt_fully_decoded = p && p->is_valid;
	copy_asm_ana_ops(state, rz_reverse, hic);
	rz_buf_free(buffer);
}
