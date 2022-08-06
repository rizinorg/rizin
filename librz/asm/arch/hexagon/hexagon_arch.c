// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: 96e220e6886868d6663d966ecc396befffc355e7
// LLVM commit date: 2022-01-05 11:01:52 +0000 (ISO 8601 format)
// Date of code generation: 2022-08-06 14:13:29-04:00
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
 * \brief Gives the instruction container at a given address from the state.
 *
 * \param state The state to operate on.
 * \param addr The address of the instruction.
 * \return Pointer to instruction or NULL if none was found.
 */
static HexInsnContainer *hex_get_hic_at_addr(HexState *state, const ut32 addr) {
	HexPkt *p;
	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		p = &state->pkts[i];
		HexInsnContainer *hic = NULL;
		RzListIter *iter = NULL;
		rz_list_foreach (p->bin, iter, hic) {
			if (addr == hic->addr) {
				p->last_access = rz_time_now();
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
	p->last_access = 0;
	rz_list_purge(p->bin);
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
static HexPkt *hex_get_pkt(HexState *state, const ut32 addr) {
	HexPkt *p = NULL;
	HexInsnContainer *hic = NULL;
	RzListIter *iter = NULL;
	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i) {
		p = &state->pkts[i];
		rz_list_foreach (p->bin, iter, hic) {
			if (hic_at_addr(hic, addr)) {
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
	if (c && c->is_duplex) {
		hex_insn_free(c->bin.sub[0]);
		hex_insn_free(c->bin.sub[1]);
	} else if (c) {
		hex_insn_free(c->bin.insn);
	}
	free(c);
}

/**
 * \brief Copies one instruction container to another.
 *
 * \param dest The destination insruction container.
 * \param src The source instruction container.
 */
RZ_API void hex_copy_insn_container(RZ_OUT HexInsnContainer *dest, const HexInsnContainer *src) {
	rz_return_if_fail(dest && src);
	memcpy(dest, src, sizeof(HexInsnContainer));
	if (src->is_duplex) {
		memcpy(dest->bin.sub[0], src->bin.sub[0], sizeof(HexInsn));
		memcpy(dest->bin.sub[1], src->bin.sub[1], sizeof(HexInsn));
	} else {
		memcpy(dest->bin.insn, src->bin.insn, sizeof(HexInsn));
	}
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
		state->pkts[i].bin = rz_list_newf((RzListFree)hex_insn_container_free);
		if (!state->pkts[i].bin) {
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
 * \param p The packet the instruction belongs to.
 * \param k The index of the instruction within the packet.
 */
static void hex_set_pkt_info(const RzAsm *rz_asm, RZ_INOUT HexInsnContainer *hic, const HexPkt *p, const ut8 k, const bool update_text) {
	rz_return_if_fail(hic && p);
	bool is_first = (k == 0);
	HexPktInfo *hi_pi = &hic->pkt_info;
	HexState *state = hexagon_get_state();
	bool sdk_form = rz_config_get_b(state->cfg, "plugins.hexagon.sdk");

	strncpy(hi_pi->text_postfix, "", 16);
	// Parse instr. position in pkt
	if (is_first && is_last_instr(hic->parse_bits)) { // Single instruction packet.
		hi_pi->first_insn = true;
		hi_pi->last_insn = true;
		if (p->is_valid) {
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
		if (p->is_valid) {
			strncpy(hi_pi->text_prefix, get_pkt_indicator(rz_asm->utf8, sdk_form, true, FIRST_IN_PKT), 8);
		} else {
			strncpy(hi_pi->text_prefix, HEX_PKT_UNK, 8);
		}
	} else if (is_last_instr(hic->parse_bits)) {
		hi_pi->first_insn = false;
		hi_pi->last_insn = true;
		if (p->is_valid) {
			strncpy(hi_pi->text_prefix, get_pkt_indicator(rz_asm->utf8, sdk_form, true, LAST_IN_PKT), 8);
			if (sdk_form) {
				strncpy(hi_pi->text_postfix, get_pkt_indicator(rz_asm->utf8, sdk_form, false, LAST_IN_PKT), 8);
			}

			switch (hex_get_loop_flag(p)) {
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
		if (p->is_valid) {
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
 * \brief Sets the packet after pkt to valid and updates its textual assembly.
 *
 * \param state The state to operate on.
 * \param pkt The packet which predecessor will be updated.
 */
static void make_next_packet_valid(HexState *state, const HexPkt *pkt) {
	HexInsnContainer *tmp = rz_list_get_top(pkt->bin);
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
			HexInsnContainer *hi = NULL;
			RzListIter *it = NULL;
			ut8 k = 0;
			rz_list_foreach (p->bin, it, hi) {
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
 * \return HexInsn* The new instruction or NULL on failure.
 */
RZ_API HexInsn *hexagon_alloc_instr() {
	HexInsn *hi = calloc(1, sizeof(HexInsn));
	if (!hi) {
		RZ_LOG_FATAL("Could not allocate memory for new instruction.\n");
	}
	return hi;
}

/**
 * \brief Allocates a new instruction container on the heap.
 *
 * \return HexInsnContainer* The new instruction container or NULL on failure.
 */
RZ_API HexInsnContainer *hexagon_alloc_instr_container() {
	HexInsnContainer *hic = calloc(1, sizeof(HexInsnContainer));
	if (!hic) {
		RZ_LOG_FATAL("Could not allocate memory for new instruction container.\n");
	}
	return hic;
}

/**
 * \brief Copies an instruction container to the packet p at position k.
 *
 * \param state The state to operate on.
 * \param new_hic The instruction container to copy.
 * \param p The packet in which will hold the instruction container.
 * \param k The index of the instruction container in the packet.
 * \return HexInsnContainer* Pointer to the copied instruction container on the heap.
 */
static HexInsnContainer *hex_add_to_pkt(HexState *state, const HexInsnContainer *new_hic, RZ_INOUT HexPkt *p, const ut8 k) {
	if (k > 3) {
		RZ_LOG_FATAL("Instruction could not be set! A packet can only hold four instructions but k=%d.", k);
	}
	HexInsnContainer *hic = hexagon_alloc_instr_container();
	hex_copy_insn_container(hic, new_hic);
	rz_list_insert(p->bin, k, hic);

	if (k == 0) {
		p->pkt_addr = hic->addr;
	}
	p->last_instr_present |= is_last_instr(hic->parse_bits);
	ut32 p_l = rz_list_length(p->bin);
	hex_set_pkt_info(&state->rz_asm, hic, p, k, false);
	if (k == 0 && p_l > 1) {
		// Update the instruction which was previously the first one.
		hex_set_pkt_info(&state->rz_asm, rz_list_get_n(p->bin, 1), p, 1, true);
	}
	p->last_access = rz_time_now();
	if (p->last_instr_present) {
		make_next_packet_valid(state, p);
	}
	return hic;
}

/**
 * \brief Cleans the packet \p new_p, copies the instruction container \p new_hic and the attributes of \p p to it.
 *
 * \param state The state to operate on.
 * \param new_hic The instruction container to copy.
 * \param p The old packet which attributes are copied to the new one.
 * \param new_p The new packet will hold the instruction container.
 * \return HexInsnContainer* Pointer to the copied instruction container on the heap.
 */
static HexInsnContainer *hex_to_new_pkt(HexState *state, const HexInsnContainer *new_hic, const HexPkt *p, RZ_INOUT HexPkt *new_p) {
	hex_clear_pkt(new_p);

	HexInsnContainer *hic = hexagon_alloc_instr_container();
	hex_copy_insn_container(hic, new_hic);
	rz_list_insert(new_p->bin, 0, hic);

	new_p->last_instr_present |= is_last_instr(hic->parse_bits);
	new_p->hw_loop0_addr = p->hw_loop0_addr;
	new_p->hw_loop1_addr = p->hw_loop1_addr;
	new_p->is_valid = (p->is_valid || p->last_instr_present);
	new_p->pkt_addr = hic->addr;
	new_p->last_access = rz_time_now();
	hex_set_pkt_info(&state->rz_asm, hic, new_p, 0, false);
	if (new_p->last_instr_present) {
		make_next_packet_valid(state, new_p);
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
	HexPkt *p = hex_get_stale_pkt(state);
	hex_clear_pkt(p);

	HexInsnContainer *hic = hexagon_alloc_instr_container();
	hex_copy_insn_container(hic, new_hic);
	rz_list_insert(p->bin, 0, hic);

	p->last_instr_present |= is_last_instr(hic->parse_bits);
	p->pkt_addr = new_hic->addr;
	// p->is_valid = true; // Setting it true also detects a lot of data as valid assembly.
	p->last_access = rz_time_now();
	hex_set_pkt_info(&state->rz_asm, hic, p, 0, false);
	if (p->last_instr_present) {
		make_next_packet_valid(state, p);
	}
	return hic;
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

	for (ut8 i = 0; i < HEXAGON_STATE_PKTS; ++i, k = 0) {
		p = &(state->pkts[i]);

		HexInsnContainer *p_hic = NULL; // Instructions container already in the packet.
		RzListIter *iter = NULL;
		rz_list_foreach (p->bin, iter, p_hic) {
			if (new_hic->addr == (p_hic->addr - 4)) {
				// Instruction preceeds one in the packet.
				if (is_last_instr(new_hic->parse_bits) || is_pkt_full(p)) {
					write_to_stale_pkt = true;
					break;
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

	// Add the instruction to packet p
	if (add_to_pkt) {
		if (insert_before_pkt_hi) {
			return hex_add_to_pkt(state, new_hic, p, k);
		}
		return hex_add_to_pkt(state, new_hic, p, k + 1);

	} else if (new_pkt) {
		ut8 ni = (get_state_pkt_index(state, p) + 1) % HEXAGON_STATE_PKTS;
		return hex_to_new_pkt(state, new_hic, p, &state->pkts[ni]);
	} else {
		return hex_add_to_stale_pkt(state, new_hic);
	}
}

/**
 * \brief Set the up a new instruction container.
 *
 * \param hic The instruction container to set up.
 * \param rz_reverse RzAsmOp and RzAnalysisOp which could have some data, which needs to be copied.
 * \param addr The address of the instruction container.
 * \param parse_bits The parse bits of the instruction container.
 */
static void setup_new_hic(HexInsnContainer *hic, const HexReversedOpcode *rz_reverse, const ut32 addr, const ut8 parse_bits) {
	hic->identifier = HEX_INS_INVALID_DECODE;
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
	if (parse_bits == 0b00) {
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
	HexInsnContainer *hic = hex_get_hic_at_addr(state, addr);
	if (hic) {
		// Opcode was already reversed and is still in the state. Copy the result and return.
		switch (rz_reverse->action) {
		default:
			memcpy(rz_reverse->asm_op, &(hic->asm_op), sizeof(RzAsmOp));
			memcpy(rz_reverse->ana_op, &(hic->ana_op), sizeof(RzAnalysisOp));
			rz_strbuf_set(&rz_reverse->asm_op->buf_asm, hic->text);
			rz_reverse->asm_op->asm_toks = rz_asm_tokenize_asm_regex(&rz_reverse->asm_op->buf_asm, state->token_patterns);
			rz_reverse->asm_op->asm_toks->op_type = hic->ana_op.type;
			return;
		case HEXAGON_DISAS:
			memcpy(rz_reverse->asm_op, &(hic->asm_op), sizeof(RzAsmOp));
			rz_strbuf_set(&rz_reverse->asm_op->buf_asm, hic->text);
			rz_reverse->asm_op->asm_toks = rz_asm_tokenize_asm_regex(&rz_reverse->asm_op->buf_asm, state->token_patterns);
			rz_reverse->asm_op->asm_toks->op_type = hic->ana_op.type;
			return;
		case HEXAGON_ANALYSIS:
			memcpy(rz_reverse->ana_op, &(hic->ana_op), sizeof(RzAnalysisOp));
			return;
		}
	}

	ut32 data = rz_read_le32(buf);
	ut8 parse_bits = (data & HEX_PARSE_BITS_MASK) >> 14;
	HexInsnContainer hic_new = { 0 };
	setup_new_hic(&hic_new, rz_reverse, addr, parse_bits);
	// Add to state
	hic = hex_add_hic_to_state(state, &hic_new);
	if (!hic) {
		return;
	}
	HexPkt *p = hex_get_pkt(state, hic->addr);

	// Do disasassembly and analysis
	hexagon_disasm_instruction(state, data, hic, p);

	switch (rz_reverse->action) {
	default:
		memcpy(rz_reverse->asm_op, &hic->asm_op, sizeof(RzAsmOp));
		memcpy(rz_reverse->ana_op, &hic->ana_op, sizeof(RzAnalysisOp));
		rz_strbuf_set(&rz_reverse->asm_op->buf_asm, hic->text);
		rz_reverse->asm_op->asm_toks = rz_asm_tokenize_asm_regex(&rz_reverse->asm_op->buf_asm, state->token_patterns);
		rz_reverse->asm_op->asm_toks->op_type = hic->ana_op.type;
		break;
	case HEXAGON_DISAS:
		memcpy(rz_reverse->asm_op, &hic->asm_op, sizeof(RzAsmOp));
		rz_strbuf_set(&rz_reverse->asm_op->buf_asm, hic->text);
		rz_reverse->asm_op->asm_toks = rz_asm_tokenize_asm_regex(&rz_reverse->asm_op->buf_asm, state->token_patterns);
		rz_reverse->asm_op->asm_toks->op_type = hic->ana_op.type;
		break;
	case HEXAGON_ANALYSIS:
		memcpy(rz_reverse->ana_op, &hic->ana_op, sizeof(RzAnalysisOp));
		break;
	}
}
