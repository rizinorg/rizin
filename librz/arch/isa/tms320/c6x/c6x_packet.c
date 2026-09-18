// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c6x_packet.c
 * Execute-packet reconstruction.
 *
 * The C6000 issues an execute packet per cycle, so the semantics of a single
 * instruction are only defined relative to the packet it belongs to: every
 * instruction in a packet reads the register file and memory as they stood at
 * the packet's start, and writes become visible a per-instruction number of
 * cycles later. Anything that wants those semantics -- the lifter above all --
 * has to see the packet, not just the instruction.
 *
 * Packet boundaries come from the parallel bit, but where that bit lives
 * depends on the fetch packet. A fetch packet is eight words; when its last
 * word is a compact header (bits 31:28 == 1110) the other seven words may hold
 * two 16-bit opcodes each, and then the parallel bits for all fourteen slots
 * sit in the header rather than in the opcodes. That is the common case: most
 * of a C674x image is compact.
 *
 * Fetch packets are 32-byte aligned, so a packet is rebuilt by reading whole
 * fetch packets rather than by decoding backwards from an arbitrary address --
 * decoding backwards cannot work, since landing mid-word in a compact packet
 * gives a different instruction stream.
 */

#include "c6x.h"

/** Fields of the compact fetch-packet header word (SPRUFE8B 3.10.2). */
typedef enum {
	C6X_FPH_TAG_SHIFT = 28, ///< bits 31:28, C6X_FP_HEADER_TAG marks a header
	C6X_FPH_LAYOUT_SHIFT = 21, ///< bits 27:21, which words hold two 16-bit opcodes
	C6X_FPH_LAYOUT_MASK = 0x7f,
	C6X_FPH_PBITS_MASK = 0x3fff, ///< bits 13:0, the parallel bit of each slot
} C6xFetchPacketHeader;

/** Compact fetch-packet header: bits 31:28 == 1110. */
static inline bool is_compact_header(ut32 w) {
	return (w >> C6X_FPH_TAG_SHIFT) == C6X_FP_HEADER_TAG;
}

/**
 * \brief Expand one 32-byte fetch packet into its instruction slots.
 *
 * \param fp The 32 bytes of the fetch packet.
 * \param base Address the fetch packet starts at.
 * \param big_endian Byte order of the image.
 * \param out Receives the slots, in address order.
 *
 * \return The number of slots written, at most C6X_FP_SLOTS.
 */
RZ_IPI size_t c6x_fetch_packet_slots(const ut8 *fp, ut64 base, bool big_endian,
	RZ_OUT C6xSlotRef *out) {
	ut32 w[8];
	for (size_t i = 0; i < 8; i++) {
		w[i] = big_endian ? rz_read_be32(fp + i * 4) : rz_read_le32(fp + i * 4);
	}
	size_t n = 0;
	if (!is_compact_header(w[7])) {
		// every word is a 32-bit opcode carrying its own parallel bit
		for (size_t i = 0; i < 8; i++) {
			out[n].addr = base + i * 4;
			out[n].size = C6X_WORD_SIZE;
			out[n].opcode = w[i];
			out[n].parallel = w[i] & 1;
			n++;
		}
		return n;
	}
	// Layout says which of words 0..6 hold two 16-bit opcodes; the parallel bits
	// for all fourteen possible slots are packed into the header instead.
	ut32 layout = (w[7] >> C6X_FPH_LAYOUT_SHIFT) & C6X_FPH_LAYOUT_MASK;
	ut32 pbits = w[7] & C6X_FPH_PBITS_MASK;
	for (size_t i = 0; i < 7; i++) {
		if (layout & (1u << i)) {
			ut32 lo = big_endian ? (w[i] >> 16) : (w[i] & 0xffff);
			ut32 hi = big_endian ? (w[i] & 0xffff) : (w[i] >> 16);
			out[n].addr = base + i * 4;
			out[n].size = C6X_COMPACT_SIZE;
			out[n].opcode = lo;
			out[n].parallel = (pbits >> (2 * i)) & 1;
			n++;
			out[n].addr = base + i * 4 + 2;
			out[n].size = C6X_COMPACT_SIZE;
			out[n].opcode = hi;
			out[n].parallel = (pbits >> (2 * i + 1)) & 1;
			n++;
		} else {
			out[n].addr = base + i * 4;
			out[n].size = C6X_WORD_SIZE;
			out[n].opcode = w[i];
			out[n].parallel = (pbits >> (2 * i)) & 1;
			n++;
		}
	}
	// the header itself is not an instruction and always ends the packet
	out[n].addr = base + 7 * 4;
	out[n].size = C6X_WORD_SIZE;
	out[n].opcode = w[7];
	out[n].parallel = false;
	out[n].header = true;
	n++;
	return n;
}

/**
 * \brief Find the execute packet containing \p pc.
 *
 * An execute packet runs from a slot whose predecessor has its parallel bit
 * clear up to and including the first slot whose own parallel bit is clear. It
 * can cross a fetch-packet boundary, so up to two fetch packets are read.
 *
 * \param read Reader for image bytes; must fill the whole request.
 * \param user Passed through to \p read.
 * \param pc Any address inside the wanted packet.
 * \param big_endian Byte order of the image.
 * \param out Receives the packet.
 *
 * \return false if the image could not be read.
 */
RZ_IPI bool c6x_packet_at(C6xReadFn read, void *user, ut64 pc, bool big_endian,
	RZ_OUT C6xPacketRef *out) {
	rz_return_val_if_fail(read && out, false);
	ut64 base = c6x_packet_base(pc);
	ut8 fp[C6X_FETCH_PACKET_SIZE * 2];
	if (!read(user, base, fp, sizeof(fp))) {
		// the following fetch packet may be unmapped; the first one is enough
		// unless the execute packet runs past its end
		if (!read(user, base, fp, C6X_FETCH_PACKET_SIZE)) {
			return false;
		}
		memset(fp + C6X_FETCH_PACKET_SIZE, 0, C6X_FETCH_PACKET_SIZE);
	}
	C6xSlotRef slots[C6X_FP_SLOTS * 2];
	size_t n = c6x_fetch_packet_slots(fp, base, big_endian, slots);
	n += c6x_fetch_packet_slots(fp + C6X_FETCH_PACKET_SIZE,
		base + C6X_FETCH_PACKET_SIZE, big_endian, slots + n);

	// walk to the start of the execute packet holding pc
	size_t start = 0;
	for (size_t i = 0; i < n; i++) {
		if (slots[i].addr <= pc && pc < slots[i].addr + slots[i].size) {
			// step back while the previous slot claims parallel execution
			start = i;
			while (start > 0 && slots[start - 1].parallel) {
				start--;
			}
			break;
		}
	}
	out->n = 0;
	for (size_t i = start; i < n && out->n < C6X_FP_SLOTS; i++) {
		out->slots[out->n++] = slots[i];
		if (!slots[i].parallel) {
			break;
		}
	}
	out->addr = out->n ? out->slots[0].addr : pc;
	return out->n > 0;
}

/**
 * \brief Whether the instruction at \p pc continues the execute packet before it.
 *
 * TI writes "||" on an instruction that issues in the same cycle as the one
 * before it, which is true when the *preceding* slot has its parallel bit set.
 * Working that out from a look-back counter only works while disassembling
 * forwards; seeking straight to the middle of a packet loses it. Rebuilding the
 * packet answers it for any address.
 *
 * \param read Reader for image bytes.
 * \param user Passed through to \p read.
 * \param pc Address of the instruction.
 * \param big_endian Byte order of the image.
 * \param cont Set to true when the instruction continues the previous packet.
 *
 * \return false if the image could not be read, leaving \p cont untouched.
 */
RZ_IPI bool c6x_continues_packet(C6xReadFn read, void *user, ut64 pc, bool big_endian,
	RZ_OUT bool *cont) {
	rz_return_val_if_fail(cont, false);
	C6xPacketRef p;
	if (!c6x_packet_at(read, user, pc, big_endian, &p)) {
		return false;
	}
	// the packet's own first slot starts it; anything after continues it
	*cont = p.n > 0 && p.slots[0].addr != pc;
	return true;
}
