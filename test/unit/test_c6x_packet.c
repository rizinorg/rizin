// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

// Packet reconstruction is RZ_IPI, so it is not exported from librz_arch and
// cannot be linked against. Build it into the test instead, which is also what
// keeps the test honest: it exercises the same source the plugin uses.
#include "../../librz/arch/isa/tms320/c6x/c6x_packet.c"

// A compact fetch packet from a C674x image at 0xc0c009e0. Its last word is a
// header (0xe1000040), so the parallel bits for every slot live there and some
// of the words hold two 16-bit opcodes.
static const ut8 compact_fp[32] = {
	0x62, 0xa3, 0x8c, 0x00, 0xf6, 0x94, 0xbc, 0x01,
	0xf4, 0x62, 0x3c, 0x05, 0x46, 0x46, 0x4e, 0x02,
	0x20, 0xa1, 0x4c, 0xd0, 0x10, 0x6f, 0x96, 0x03,
	0x62, 0x81, 0x88, 0x01, 0x40, 0x00, 0x00, 0xe1
};

#define FP_BASE 0xc0c009e0ULL

// Only the one fetch packet is mapped, so anything else fails the way an
// unmapped read would.
//
// The whole range check is one unsigned comparison on the offset: an address
// below the packet wraps to a huge offset and is rejected by the same test, and
// the length is compared by subtraction so it cannot overflow. Written any other
// way, a compiler that inlines this and propagates a caller's constant address
// reports the copy as out of bounds on the path these checks already reject.
static bool read_compact(void *user, ut64 addr, ut8 *buf, size_t len) {
	ut64 off = addr - FP_BASE;
	if (off >= sizeof(compact_fp) || len > sizeof(compact_fp) - off) {
		return false;
	}
	memcpy(buf, compact_fp + (size_t)off, len);
	return true;
}

bool test_compact_header_slots(void) {
	C6xSlotRef slots[C6X_FP_SLOTS];
	size_t n = c6x_fetch_packet_slots(compact_fp, FP_BASE, false, slots);
	mu_assert_true(n > 8, "a compact fetch packet holds more slots than words");
	mu_assert_eq(slots[n - 1].addr, FP_BASE + 28, "the header is the last slot");
	mu_assert_true(slots[n - 1].header, "and is flagged as one");
	mu_assert_false(slots[n - 1].parallel, "a header never runs in parallel");

	size_t i;
	for (i = 0; i < n && slots[i].addr != FP_BASE + 12; i++) {
	}
	mu_assert_neq(i, n, "the word at +12 is covered");
	mu_assert_eq(slots[i].size, C6X_COMPACT_SIZE, "it holds a 16-bit opcode");
	mu_assert_eq(slots[i + 1].addr, FP_BASE + 14, "its sibling is two bytes on");
	mu_assert_true(slots[i].parallel, "and the two issue together");
	mu_end;
}

bool test_big_endian_slots(void) {
	// the same words, stored most significant byte first
	ut8 be[sizeof(compact_fp)];
	for (size_t i = 0; i < sizeof(be); i += 4) {
		rz_write_be32(be + i, rz_read_le32(compact_fp + i));
	}
	C6xSlotRef le_slots[C6X_FP_SLOTS];
	C6xSlotRef be_slots[C6X_FP_SLOTS];
	size_t n = c6x_fetch_packet_slots(compact_fp, FP_BASE, false, le_slots);
	mu_assert_eq(c6x_fetch_packet_slots(be, FP_BASE, true, be_slots), n, "as many slots in either byte order");
	for (size_t i = 0; i < n; i++) {
		mu_assert_eq(be_slots[i].addr, le_slots[i].addr, "at the same addresses");
		mu_assert_eq(be_slots[i].size, le_slots[i].size, "of the same sizes");
		// a word's less significant half is its first slot either way
		mu_assert_eq(be_slots[i].opcode, le_slots[i].opcode, "holding the same opcodes");
		mu_assert_eq(be_slots[i].parallel, le_slots[i].parallel, "with the same parallel bits");
	}
	mu_end;
}

bool test_plain_header_slots(void) {
	// no header in the last word, so each word carries its own parallel bit
	ut8 fp[32] = { 0 };
	fp[0] = 0x01;
	C6xSlotRef slots[C6X_FP_SLOTS];
	size_t n = c6x_fetch_packet_slots(fp, 0x1000, false, slots);
	mu_assert_eq(n, 8, "a plain fetch packet is eight slots");
	mu_assert_eq(slots[0].size, C6X_WORD_SIZE, "each holds a full word");
	mu_assert_true(slots[0].parallel, "the bit comes from the opcode");
	mu_assert_false(slots[1].parallel, "and the next word ends the packet");
	mu_end;
}

bool test_word_parallel_bit(void) {
	// cl6x 7.4.4 output for "mv a4,a0; mvkh 0x12340000,a4 || mv a4,a5": the
	// header leaves the p-bits of the 32-bit words clear
	static const ut8 fp[32] = {
		0xd8, 0x0f, 0x10, 0x00, 0x69, 0x1a, 0x09, 0x02,
		0x46, 0xa2, 0x47, 0x02, 0x6e, 0x0c, 0x6e, 0x0c,
		0x6e, 0x0c, 0x6e, 0x0c, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xe3
	};
	C6xSlotRef slots[C6X_FP_SLOTS];
	size_t n = c6x_fetch_packet_slots(fp, 0x1000, false, slots);
	mu_assert_true(n > 2, "slots found");
	mu_assert_eq(slots[1].size, C6X_WORD_SIZE, "the mvkh is a 32-bit opcode");
	mu_assert_true(slots[1].parallel, "its own p-bit joins it to the mv");
	mu_assert_eq(slots[2].size, C6X_COMPACT_SIZE, "the mv is compact");
	mu_assert_false(slots[2].parallel, "and its header bit ends the packet");
	mu_assert_false(slots[0].parallel, "the mv before them runs alone");
	mu_end;
}

bool test_packet_from_any_address(void) {
	C6xPacketRef first = { 0 };
	C6xPacketRef second = { 0 };
	// both halves of a parallel pair belong to one packet, whichever is asked for
	mu_assert_true(c6x_packet_at(read_compact, NULL, FP_BASE + 12, false, &first), "found");
	mu_assert_true(c6x_packet_at(read_compact, NULL, FP_BASE + 14, false, &second), "found");
	mu_assert_eq(first.addr, second.addr, "the same packet either way");
	mu_assert_eq(first.n, second.n, "of the same length");
	mu_assert_eq(first.addr, FP_BASE + 12, "starting at the first of the pair");

	// a lone instruction is a packet of one
	C6xPacketRef lone = { 0 };
	mu_assert_true(c6x_packet_at(read_compact, NULL, FP_BASE + 4, false, &lone), "found");
	mu_assert_eq(lone.addr, FP_BASE + 4, "starts at itself");
	mu_assert_eq(lone.n, 1, "and stands alone");
	mu_end;
}

bool test_next_packet(void) {
	C6xPacketRef p = { 0 };
	mu_assert_true(c6x_packet_at(read_compact, NULL, FP_BASE + 12, false, &p), "found");
	mu_assert_eq(p.next, FP_BASE + 16, "the next packet follows the pair");
	mu_assert_true(c6x_packet_at(read_compact, NULL, FP_BASE + 24, false, &p), "found");
	mu_assert_eq(p.next, FP_BASE + 32, "and starts past the header after the last word");
	mu_end;
}

// Two fetch packets of a TI-built C674x ELF from 0x81a0: a compact callp, the
// mvk beside it and, past the header, a 32-bit mvkh issue together.
static const ut8 span_fp[64] = {
	0xd8, 0x1f, 0x14, 0x02, 0x28, 0x02, 0x47, 0x02,
	0x1b, 0xe6, 0x27, 0x26, 0x68, 0x00, 0x00, 0x02,
	0x0a, 0x85, 0x26, 0x06, 0x28, 0x03, 0x47, 0x02,
	0x1b, 0xe6, 0x27, 0x6e, 0x30, 0xb0, 0x80, 0xea,
	0x68, 0x00, 0x00, 0x02, 0x58, 0xa3, 0x04, 0x02,
	0x62, 0xb3, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define SPAN_BASE 0x81a0ULL

static bool read_span(void *user, ut64 addr, ut8 *buf, size_t len) {
	ut64 off = addr - SPAN_BASE;
	if (off >= sizeof(span_fp) || len > sizeof(span_fp) - off) {
		return false;
	}
	memcpy(buf, span_fp + (size_t)off, len);
	return true;
}

bool test_packet_across_header(void) {
	C6xPacketRef p = { 0 };
	mu_assert_true(c6x_packet_at(read_span, NULL, SPAN_BASE + 0x20, false, &p), "found");
	mu_assert_eq(p.addr, SPAN_BASE + 0x18, "the mvkh continues the packet of the callp");
	mu_assert_eq(p.n, 3, "which holds the callp, the mvk and the mvkh");
	mu_assert_eq(p.slots[2].addr, SPAN_BASE + 0x20, "but not the header between");
	mu_assert_eq(p.next, SPAN_BASE + 0x24, "and ends past the mvkh");
	C6xPacketRef q = { 0 };
	mu_assert_true(c6x_packet_at(read_span, NULL, SPAN_BASE + 0x18, false, &q), "found");
	mu_assert_eq(q.n, p.n, "the same packet from its first slot");
	mu_assert_true(c6x_packet_at(read_span, NULL, SPAN_BASE + 0x1c, false, &q), "found");
	mu_assert_true(q.n == 1 && q.slots[0].header, "the header stands alone");
	mu_end;
}

bool test_unreadable_image(void) {
	C6xPacketRef p = { 0 };
	mu_assert_false(c6x_packet_at(read_compact, NULL, 0x1000, false, &p), "unmapped fails");
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_compact_header_slots);
	mu_run_test(test_big_endian_slots);
	mu_run_test(test_plain_header_slots);
	mu_run_test(test_word_parallel_bit);
	mu_run_test(test_packet_from_any_address);
	mu_run_test(test_next_packet);
	mu_run_test(test_packet_across_header);
	mu_run_test(test_unreadable_image);
	return tests_passed != tests_run;
}

mu_main(all_tests)
