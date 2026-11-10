// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

// The decoder is RZ_IPI, so it is built into the test, as test_c6x_packet does
// with the packet code.
#include "../../librz/arch/isa/tms320/c6x/c6x_decode.c"

// Two fetch packets from C674x images, mapped one after the other at 0. Only
// the header in each last word says which words hold two compact slots: word 0
// of the first ("mv .l1 a4,a0" and "[!a0] bnop .s1 0x154,0x5"), word 3 of the
// second, whose 32-bit BNOP at 0x30 is half-word scaled for being in it.
static const ut8 image_le[64] = {
	0x46, 0x02, 0xba, 0xea, 0x28, 0x74, 0xca, 0x01,
	0xe8, 0x05, 0xe0, 0x01, 0x74, 0x02, 0x80, 0x01,
	0x2a, 0xe0, 0x50, 0x02, 0xea, 0x05, 0x60, 0x02,
	0x76, 0x22, 0x00, 0x02, 0x00, 0x80, 0x20, 0xe0,
	0x62, 0xa3, 0x8c, 0x00, 0xf6, 0x94, 0xbc, 0x01,
	0xf4, 0x62, 0x3c, 0x05, 0x46, 0x46, 0x4e, 0x02,
	0x20, 0xa1, 0x4c, 0xd0, 0x10, 0x6f, 0x96, 0x03,
	0x62, 0x81, 0x88, 0x01, 0x40, 0x00, 0x00, 0xe1
};

// The first packet again, as big-endian memory holds it: the same words with
// their bytes reversed, so the header is only recognised when read that way.
static const ut8 image_be[32] = {
	0xea, 0xba, 0x02, 0x46, 0x01, 0xca, 0x74, 0x28,
	0x01, 0xe0, 0x05, 0xe8, 0x01, 0x80, 0x02, 0x74,
	0x02, 0x50, 0xe0, 0x2a, 0x02, 0x60, 0x05, 0xea,
	0x02, 0x00, 0x22, 0x76, 0xe0, 0x20, 0x80, 0x00
};

typedef struct {
	const ut8 *bytes;
	size_t size;
	bool big_endian;
} Image;

static bool read_image(void *user, ut64 addr, ut8 *buf, size_t len) {
	const Image *img = user;
	if (addr >= img->size || len > img->size - addr) {
		return false;
	}
	memcpy(buf, img->bytes + addr, len);
	return true;
}

static bool read_nothing(void *user, ut64 addr, ut8 *buf, size_t len) {
	return false;
}

static bool same_insn(const C6xInsn *a, const C6xInsn *b) {
	return a->id == b->id && a->size == b->size && a->word == b->word &&
		a->parallel == b->parallel && a->creg == b->creg && a->z == b->z &&
		a->compact_packet == b->compact_packet && a->nops == b->nops &&
		!memcmp(a->ops, b->ops, sizeof(a->ops));
}

// Decode every slot of \p img, first with the rest of the image in hand and then
// from every shorter buffer, and count the slots. Both get the reader, as the
// second slot of a big-endian word lies before its own address.
static size_t walk_image(const Image *img) {
	const C6xArchDesc *c674x = c6x_desc_from_cpu("c674x");
	C6xInsn whole = { 0 };
	C6xInsn part = { 0 };
	size_t slots = 0;
	for (ut64 pc = 0; pc < img->size; pc += whole.size) {
		int avail = (int)(img->size - pc);
		if (!c6x_decode(c674x, img->bytes + pc, avail, pc, img->big_endian, read_image, (void *)img, &whole)) {
			return 0;
		}
		for (int len = whole.size; len < avail; len++) {
			if (!c6x_decode(c674x, img->bytes + pc, len, pc, img->big_endian, read_image, (void *)img, &part) ||
				!same_insn(&part, &whole)) {
				return 0;
			}
		}
		slots++;
	}
	return slots;
}

bool test_slots_decode_with_any_buffer_length(void) {
	Image le = { image_le, sizeof(image_le), false };
	Image be = { image_be, sizeof(image_be), true };
	mu_assert_eq(walk_image(&le), 18, "both little-endian packets decode the same from any buffer");
	mu_assert_eq(walk_image(&be), 9, "and so does the big-endian one");
	mu_end;
}

bool test_header_out_of_reach(void) {
	const C6xArchDesc *c674x = c6x_desc_from_cpu("c674x");
	C6xInsn insn = { 0 };
	// the word at 0 is two compact slots, but nothing says so
	mu_assert_true(c6x_decode(c674x, image_le, 4, 0, false, NULL, NULL, &insn), "decoded");
	mu_assert_eq(insn.size, C6X_WORD_SIZE, "a word gets its 32-bit reading");
	mu_assert_eq(insn.id, C6X_INS_LDH, "as in a packet without a header");
	mu_assert_true(c6x_decode(c674x, image_le, 4, 0, false, read_nothing, NULL, &insn), "decoded");
	mu_assert_eq(insn.id, C6X_INS_LDH, "an image that cannot be read is the same");

	// a 32-bit opcode never starts at a half word, so this is a compact slot
	mu_assert_true(c6x_decode(c674x, image_le + 2, 4, 2, false, NULL, NULL, &insn), "consumed");
	mu_assert_eq(insn.size, C6X_COMPACT_SIZE, "a half word is a compact slot");
	mu_assert_eq(insn.id, C6X_INS_INVALID, "that cannot be decoded without its header");
	mu_assert_null(insn.mnemonic, "and prints as invalid");

	// the header is in reach, but in big endian the slot at 2 is the half word at 0
	mu_assert_true(c6x_decode(c674x, image_be + 2, (int)sizeof(image_be) - 2, 2, true, NULL, NULL, &insn), "consumed");
	mu_assert_eq(insn.size, C6X_COMPACT_SIZE, "a big-endian second slot is a compact slot");
	mu_assert_eq(insn.id, C6X_INS_INVALID, "that cannot be decoded without the half word before it");
	mu_end;
}

bool test_big_endian_is_the_same_program(void) {
	// TI keeps a word's value in either byte order and runs its less significant
	// half first, so image_be holds the instructions of the first packet of
	// image_le, in the same order
	const C6xArchDesc *c674x = c6x_desc_from_cpu("c674x");
	Image le = { image_le, sizeof(image_be), false };
	Image be = { image_be, sizeof(image_be), true };
	C6xInsn a = { 0 };
	C6xInsn b = { 0 };
	size_t slots = 0;
	for (ut64 pc = 0; pc < sizeof(image_be); pc += a.size) {
		int avail = (int)(sizeof(image_be) - pc);
		mu_assert_true(c6x_decode(c674x, image_le + pc, avail, pc, false, read_image, &le, &a), "little endian decodes");
		mu_assert_true(c6x_decode(c674x, image_be + pc, avail, pc, true, read_image, &be, &b), "big endian decodes");
		mu_assert_true(same_insn(&a, &b), "to the same instruction");
		slots++;
	}
	mu_assert_eq(slots, 9, "slot by slot");
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_slots_decode_with_any_buffer_length);
	mu_run_test(test_header_out_of_reach);
	mu_run_test(test_big_endian_is_the_same_program);
	return tests_passed != tests_run;
}

mu_main(all_tests)
