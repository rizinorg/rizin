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

bool test_unreadable_image(void) {
	C6xPacketRef p = { 0 };
	mu_assert_false(c6x_packet_at(read_compact, NULL, 0x1000, false, &p), "unmapped fails");
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_compact_header_slots);
	mu_run_test(test_plain_header_slots);
	mu_run_test(test_packet_from_any_address);
	mu_run_test(test_unreadable_image);
	return tests_passed != tests_run;
}

mu_main(all_tests)
