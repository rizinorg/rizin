// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "assembler.h"
#include "common.h"

#define MAX_TOKENS                      6
#define IS_INDIRECT_ADDRESS_REGISTER(x) ((x) == 'x' || (x) == 'y' || (x) == 'z')

#define throw_error(msg, ...) \
	do { \
		RZ_LOG_ERROR("[!] avr_assembler: " msg, ##__VA_ARGS__); \
		return AVR_INVALID_SIZE; \
	} while (0)

#define return_error_if_empty_input(a, b) \
	do { \
		if (RZ_STR_ISEMPTY(a) || b < 1) { \
			RZ_LOG_ERROR("[!] avr_assembler: the input is empty.\n"); \
			return AVR_INVALID_SIZE; \
		} \
	} while (0)

#define expected_const_or_error(a, exp) \
	do { \
		if (RZ_STR_ISEMPTY((a)) || strcmp((a), (exp))) { \
			RZ_LOG_ERROR("[!] avr_assembler: expected '%s' but got '%s'.\n", (exp), (a)); \
			return AVR_INVALID_SIZE; \
		} \
	} while (0)

#define parse_register_or_error_limit(rn, rs, min, max) \
	do { \
		cchar *tmp = (rs); \
		if (*tmp == 'r') { \
			tmp++; \
		} \
		if (RZ_STR_ISEMPTY(tmp)) { \
			RZ_LOG_ERROR("[!] avr_assembler: invalid register '%s'.\n", (rs)); \
			return AVR_INVALID_SIZE; \
		} \
		(rn) = strtoll(tmp, NULL, 0); \
		if ((rn) < (min) || (rn) > (max)) { \
			RZ_LOG_ERROR("[!] avr_assembler: expected register %u <= reg <= 31 (parsed %u).\n", (min), (rn)); \
			return AVR_INVALID_SIZE; \
		} \
	} while (0)

#define parse_register_or_error(rn, rs) \
	do { \
		cchar *tmp = (rs); \
		if (*tmp == 'r') { \
			tmp++; \
		} \
		if (RZ_STR_ISEMPTY(tmp)) { \
			RZ_LOG_ERROR("[!] avr_assembler: invalid register '%s'.\n", (rs)); \
			return AVR_INVALID_SIZE; \
		} \
		(rn) = strtoll(tmp, NULL, 0); \
		if ((rn) > 31) { \
			RZ_LOG_ERROR("[!] avr_assembler: expected register 0 <= reg <= 31 (parsed %u).\n", (rn)); \
			return AVR_INVALID_SIZE; \
		} \
	} while (0)

/// Parse things like "r25:r24" or just "r24". Result would be 24 in both cases.
#define parse_register_pair_or_error(rn, rs) \
	do { \
		cchar *tmp = (rs); \
		if (*tmp == 'r') { \
			tmp++; \
		} \
		if (RZ_STR_ISEMPTY(tmp)) { \
			RZ_LOG_ERROR("[!] avr_assembler: invalid register '%s'.\n", (rs)); \
			return AVR_INVALID_SIZE; \
		} \
		(rn) = strtoll(tmp, (char **)&tmp, 0); \
		if ((rn) > 31) { \
			RZ_LOG_ERROR("[!] avr_assembler: expected register 0 <= reg <= 31 (parsed %u).\n", (rn)); \
			return AVR_INVALID_SIZE; \
		} \
		if (*tmp == ':') { \
			tmp++; \
			ut16 high = (rn); \
			if (*tmp == 'r') { \
				tmp++; \
			} \
			(rn) = strtoll(tmp, NULL, 0); \
			if ((rn) > 31) { \
				RZ_LOG_ERROR("[!] avr_assembler: expected register 0 <= reg <= 31 (parsed %u).\n", (rn)); \
				return AVR_INVALID_SIZE; \
			} \
			if (high != (rn) + 1) { \
				RZ_LOG_ERROR("[!] avr_assembler: register pair r%u:r%u invalid: %u != %u + 1.\n", \
					(unsigned int)high, (unsigned int)(rn), (unsigned int)high, (unsigned int)(rn)); \
				return AVR_INVALID_SIZE; \
			} \
		} \
	} while (0)

#define parse_unsigned_or_error(rn, rs, limit) \
	do { \
		cchar *tmp = (rs); \
		ut32 base = 0; \
		if (tmp[0] == '$') { \
			tmp++; \
			base = 16; \
		} \
		if (RZ_STR_ISEMPTY(tmp)) { \
			RZ_LOG_ERROR("[!] avr_assembler: invalid unsigned number '%s'.\n", (rs)); \
			return AVR_INVALID_SIZE; \
		} \
		(rn) = strtoull(tmp, NULL, base); \
		if ((rn) > (limit)) { \
			RZ_LOG_ERROR("[!] avr_assembler: unsigned number '%s' >= %u.\n", (rs), limit); \
			return AVR_INVALID_SIZE; \
		} \
	} while (0)

#define parse_address_or_error(rn, rs, pc, llow, lhigh) \
	do { \
		cchar *tmp = (rs); \
		if (RZ_STR_ISEMPTY(tmp)) { \
			RZ_LOG_ERROR("[!] avr_assembler: invalid address '%s'.\n", (rs)); \
			return AVR_INVALID_SIZE; \
		} \
		if (tmp[0] == '.') { \
			(rn) = (st64)strtoull(tmp + 1, NULL, 0); \
		} else { \
			st64 abs = strtoull(tmp, NULL, 0); \
			(rn) = abs - pc; \
		} \
		if ((rn) < 0) { \
			(rn) = ~(-((rn)-1)); \
		} else { \
			(rn) -= 2; \
		} \
		(rn) /= 2; \
		if (((rn) < (llow) || (rn) > (lhigh))) { \
			RZ_LOG_ERROR("[!] avr_assembler: invalid address -64 <= addr <= 63 (parsed %d).\n", (rn)); \
			return AVR_INVALID_SIZE; \
		} \
	} while (0)

#define parse_signed_or_error(rn, rs, min, max) \
	do { \
		cchar *tmp = (rs); \
		if (RZ_STR_ISEMPTY(tmp)) { \
			RZ_LOG_ERROR("[!] avr_assembler: invalid unsigned number '%s'.\n", (rs)); \
			return AVR_INVALID_SIZE; \
		} \
		(rn) = atoi(tmp); \
		if ((rn) < (min)) { \
			RZ_LOG_ERROR("[!] avr_assembler: signed number '%s' < %u.\n", (rs), min); \
			return AVR_INVALID_SIZE; \
		} \
		if ((rn) > (max)) { \
			RZ_LOG_ERROR("[!] avr_assembler: signed number '%s' > %u.\n", (rs), max); \
			return AVR_INVALID_SIZE; \
		} \
	} while (0)

#define auto_write16(buf, val, be) \
	do { \
		if (be) { \
			rz_write_be16(buf, val); \
		} else { \
			rz_write_le16(buf, val); \
		} \
	} while (0)

typedef ut32 (*Encode)(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be);

typedef struct avr_decoder_t {
	cchar *opcode; /* instruction name */
	ut16 cbits; /*    constant bits */
	ut32 mintoks; /*  required min token number */
	ut32 maxtoks; /*  required max token number */
	Encode encode;
} AvrInstruction;

static ut32 avr_unique(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_rdddddrrrr(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd,Rr | 0 <= d <= 31 | 0 <= r <= 31 */
	ut16 Rd, Rr;
	parse_register_or_error(Rd, tokens[1]);
	parse_register_or_error(Rr, tokens[2]);

	cbins |= (Rr & 0x000F);
	cbins |= ((Rr << 5) & 0x0200);
	cbins |= ((Rd << 4) & 0x01F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_KKddKKKK(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd, K | d = {24,26,28,30}, 0 <= K <= 63 */
	ut16 Rd, K;
	parse_register_pair_or_error(Rd, tokens[1]);
	parse_unsigned_or_error(K, tokens[2], 63);

	if (Rd < 24 || Rd & 1) {
		throw_error("register must be Rd = {24,26,28,30} (parsed r%u)\n", Rd);
	}

	Rd -= 24;
	Rd >>= 1;

	cbins |= (K & 0x000F);
	cbins |= ((K << 2) & 0x00C0);
	cbins |= ((Rd << 4) & 0x0030);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_KKKKddddKKKK(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd, K | 16 <= d <= 31, 0 <= K <= 255 */
	ut16 Rd, K;
	parse_register_or_error_limit(Rd, tokens[1], 16, 31);
	parse_unsigned_or_error(K, tokens[2], 255);

	Rd -= 16;

	cbins |= (K & 0x000F);
	cbins |= ((K << 4) & 0x0F00);
	cbins |= ((Rd << 4) & 0x00F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_cbr(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd, K | 16 <= d <= 31, 0 <= K <= 255 */
	ut16 Rd, K;
	parse_register_or_error_limit(Rd, tokens[1], 16, 31);
	parse_unsigned_or_error(K, tokens[2], 255);

	Rd -= 16;
	K = 0xFF - K;

	cbins |= (K & 0x000F);
	cbins |= ((K << 4) & 0x0F00);
	cbins |= ((Rd << 4) & 0x00F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_dddddcccc(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd | 0 <= d <= 31 */
	ut16 Rd;
	parse_register_or_error(Rd, tokens[1]);
	cbins |= ((Rd << 4) & 0x01F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_dddddcbbb(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd, b | 0 <= d <= 31, 0 <= b <= 7 */

	ut16 Rd, b;
	parse_register_or_error(Rd, tokens[1]);
	parse_unsigned_or_error(b, tokens[2], 7);

	cbins |= (b & 0x0007);
	cbins |= ((Rd << 4) & 0x01F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_kkkkkkkccc(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> k | -64 <= k <= 63 */
	st16 k;
	parse_address_or_error(k, tokens[1], pc, -64, 63);
	cbins |= ((k << 3) & 0x03F8);
	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_kkkkkccck(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	// <opcode> k | 0 <= k < 0x7ffffe
	ut32 k;
	parse_unsigned_or_error(k, tokens[1], 0x7ffffe);

	k /= 2;

	ut16 kh = k >> 16;
	ut16 kl = k & 0xFFFF;

	cbins |= (kh & 0x0001);
	cbins |= ((kh << 3) & 0x01F0);

	auto_write16(data, cbins, be);
	auto_write16(data + 2, kl, be);
	return 4;
}

static ut32 avr_AAAAAbbb(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	// CBI A,b | 0 <= A <= 31 | 0 <= b <= 7
	ut16 A, b;
	parse_unsigned_or_error(A, tokens[1], 31);
	parse_unsigned_or_error(b, tokens[2], 7);

	cbins |= (b & 0x0007);
	cbins |= ((A << 3) & 0x00F8);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_dddddddddd(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd | 0 <= d <= 31 */
	ut16 Rd;
	parse_register_or_error(Rd, tokens[1]);

	cbins |= (Rd & 0x000F);
	cbins |= ((Rd << 5) & 0x0200);
	cbins |= ((Rd << 4) & 0x01F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_KKKKcccc(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> K | 0 <= K <= 0xF */
	ut16 K;
	parse_unsigned_or_error(K, tokens[1], 0xF);

	cbins |= ((K << 4) & 0x00F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_elpm(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	if (ntokens == 1) {
		/* elpm */
		/* 1001010111011000 */
		cbins = 0x95D8;
	} else if (ntokens == 3) {
		/* elpm Rd, Z  | 0 <= Rd <= 31 */
		ut16 Rd;
		parse_register_or_error(Rd, tokens[1]);
		expected_const_or_error(tokens[2], "z");

		/* 1001000ddddd0110 */
		cbins = 0x9006;
		cbins |= ((Rd << 4) & 0x01F0);
	} else if (ntokens == 4) {
		/* elpm Rd, Z+ | 0 <= Rd <= 31 */
		ut16 Rd;
		parse_register_or_error(Rd, tokens[1]);
		expected_const_or_error(tokens[2], "z");
		expected_const_or_error(tokens[3], "+");

		/* 1001000ddddd0111 */
		cbins = 0x9007;
		cbins |= ((Rd << 4) & 0x01F0);
	} else {
		throw_error("expected 'elpm' or 'elpm Rd, M' | 0 <= d <= 31 | M = {Z,Z+}\n");
	}

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_dddcrrr(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd,Rr | 16 <= d <= 23 | 16 <= r <= 23 */
	ut16 Rd, Rr;
	parse_register_or_error_limit(Rd, tokens[1], 16, 23);
	parse_register_or_error_limit(Rr, tokens[2], 16, 23);

	Rd -= 16;
	Rr -= 16;

	cbins |= (Rr & 0x0007);
	cbins |= ((Rd << 4) & 0x0070);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_AAdddddAAAA(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd, A | 0 <= d <= 31, 0 <= A <= 63 */
	ut16 Rd, A;
	parse_register_or_error(Rd, tokens[1]);
	parse_unsigned_or_error(A, tokens[2], 63);

	cbins |= (A & 0x000F);
	cbins |= ((A << 5) & 0x0600);
	cbins |= ((Rd << 4) & 0x01F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_rrrrrcccc(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd | 0 <= d <= 31 */
	ut16 Rd;
	expected_const_or_error(tokens[1], "z");
	parse_register_or_error(Rd, tokens[2]);
	cbins |= ((Rd << 4) & 0x01F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_ld(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* ld Rd, M | 0 <= d <= 31 | M = {X,Y,Z,X+,Y+,Z+,-X,-Y,-Z} */
	ut16 Rd;
	parse_register_or_error(Rd, tokens[1]);

	if (ntokens == 3) {
		if (!strcmp(tokens[2], "x")) {
			/* ld Rd, X */
			/* 1001000ddddd1100 */
			cbins = 0x900C;
		} else if (!strcmp(tokens[2], "y")) {
			/* ld Rd, Y */
			/* 1000000ddddd1000 */
			cbins = 0x8008;
		} else if (!strcmp(tokens[2], "z")) {
			/* ld Rd, Z */
			/* 1001000ddddd0000 */
			cbins = 0x8000;
		} else if (!strcmp(tokens[2], "-x")) {
			/* ld Rd, -X */
			/* 1001000ddddd1110 */
			cbins = 0x900E;
		} else if (!strcmp(tokens[2], "-y")) {
			/* ld Rd, -Y */
			/* 1001000ddddd1010 */
			cbins = 0x900A;
		} else if (!strcmp(tokens[2], "-z")) {
			/* ld Rd, -Z */
			/* 1001000ddddd0010 */
			cbins = 0x9002;
		} else {
			throw_error("expected 'X' or 'Y' or 'Z' or '-X' or '-Y' or '-Z', but got '%s'\n", tokens[2]);
		}
	} else if (ntokens == 4 && !strcmp(tokens[3], "+")) {
		if (!strcmp(tokens[2], "x")) {
			/* ld Rd, X+ */
			/* 1001000ddddd1101 */
			cbins = 0x900D;
		} else if (!strcmp(tokens[2], "y")) {
			/* ld Rd, Y+ */
			/* 1001000ddddd1001 */
			cbins = 0x9009;
		} else if (!strcmp(tokens[2], "z")) {
			/* ld Rd, Z+ */
			/* 1001000ddddd0001 */
			cbins = 0x9001;
		} else {
			throw_error("expected 'X+' or 'Y+' or 'Z+', but got '%s+'\n", tokens[2]);
		}
	} else {
		throw_error("expected ld Rd, M | 0 <= d <= 31 | M = {X,Y,Z,X+,Y+,Z+,-X,-Y,-Z}\n");
	}

	cbins |= ((Rd << 4) & 0x01F0);
	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_ldd(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* ldd Rd, M + q | 0 <= d <= 31 | M = {Y,Z} | 0 <= q <= 63*/
	ut16 Rd, q;
	parse_register_or_error(Rd, tokens[1]);
	parse_unsigned_or_error(q, tokens[4], 63);

	if (!strcmp(tokens[3], "+")) {
		if (!strcmp(tokens[2], "y")) {
			/* ldd Rd, Y+q */
			/* 10q0qq0ddddd1qqq */
			cbins = 0x8008;
		} else if (!strcmp(tokens[2], "z")) {
			/* ldd Rd, Z+q */
			/* 10q0qq0ddddd0qqq */
			cbins = 0x8000;
		} else {
			throw_error("expected 'Y+' or 'Z+', but got '%s+'\n", tokens[2]);
		}
	} else {
		throw_error("expected ldd Rd, M + q | 0 <= d <= 31 | M = {Y,Z} | 0 <= q <= 63\n");
	}

	cbins |= q & 0x0007;
	cbins |= ((q << 7) & 0x0C00);
	cbins |= ((q << 8) & 0x2000);
	cbins |= ((Rd << 4) & 0x01F0);
	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_lds(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	ut16 Rd;
	ut32 k;
	parse_register_or_error(Rd, tokens[1]);
	parse_unsigned_or_error(k, tokens[2], 0xFFFF);

#if 0
	// The STS (16-bit) and LDS (16-bit) instructions only exist in the reduced AVR cores.
	// This includes only the ATtiny4/5/9/10 family, and the ATtiny20/40 family.
	// They also lack some features like the lack of CPU registers R0 to R15.
	// On rizin these platforms are not supported, therefore this code is commented, but works as intended.
	if (k <= 127 && Rd >= 16) {
		/* lds Rd, k | 16 <= d <= 31 | 0 <= k <= 127 */
		/* 10100kkkddddkkkk */
		cbins = 0xA000;
		Rd -= 16;
		cbins |= k & 0x000F;
		cbins |= ((k << 4) & 0x0700);
		cbins |= ((Rd << 4) & 0x00F0);

		auto_write16(data, cbins, be);
		return 2;
	}
#endif
	/* lds Rd, k | 0 <= d <= 31 | 0 <= k <= 0xFFFF */
	/* 1001000ddddd0000 kkkkkkkkkkkkkkkk */
	cbins = 0x9000;
	cbins |= ((Rd << 4) & 0x01F0);
	auto_write16(data, cbins, be);
	auto_write16(data + 2, k, be);
	return 4;
}

static ut32 avr_lpm(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	if (ntokens == 1) {
		/* lpm */
		/* 1001010111001000 */
		cbins = 0x95C8;
	} else if (ntokens == 3) {
		/* lpm Rd, Z  | 0 <= Rd <= 31 */
		ut16 Rd;
		parse_register_or_error(Rd, tokens[1]);
		expected_const_or_error(tokens[2], "z");

		/* 1001000ddddd0100 */
		cbins = 0x9004;
		cbins |= ((Rd << 4) & 0x01F0);
	} else if (ntokens == 4) {
		/* lpm Rd, Z+ | 0 <= Rd <= 31 */
		ut16 Rd;
		parse_register_or_error(Rd, tokens[1]);
		expected_const_or_error(tokens[2], "z");
		expected_const_or_error(tokens[3], "+");

		/* 1001000ddddd0101 */
		cbins = 0x9005;
		cbins |= ((Rd << 4) & 0x01F0);
	} else {
		throw_error("expected 'lpm' or 'lpm Rd, M' | 0 <= d <= 31 | M = {Z,Z+}\n");
	}

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_kkkkkkkkkkkk(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> k | -4096 <= k <= 4096 */
	st16 k;
	parse_address_or_error(k, tokens[1], pc, -4096, 4096);
	cbins |= (k & 0x0FFF);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_ddddrrrr(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd, Rr | d = {0,2,...,30} | r = {0,2,...,30} */
	ut16 Rd, Rr;
	parse_register_or_error(Rd, tokens[1]);
	parse_register_or_error(Rr, tokens[2]);

	if (Rd & 1) {
		throw_error("register must be even, Rd = {0,2,...,30} (parsed r%u)\n", Rd);
	} else if (Rr & 1) {
		throw_error("register must be even, Rr = {0,2,...,30} (parsed r%u)\n", Rr);
	}

	Rr /= 2;
	Rd /= 2;
	cbins |= Rr & 0x000F;
	cbins |= ((Rd << 4) & 0x00F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_ddddrrrr_2x(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd, Rr | 16 <= d <= 31 | 16 <= r <= 31 */
	ut16 Rd, Rr;
	parse_register_or_error_limit(Rd, tokens[1], 16, 31);
	parse_register_or_error_limit(Rr, tokens[2], 16, 31);

	Rr -= 16;
	Rd -= 16;
	cbins |= Rr & 0x000F;
	cbins |= ((Rd << 4) & 0x00F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_AArrrrrAAAA(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd, A | 0 <= d <= 31, 0 <= A <= 63 */
	ut16 Rd, A;
	parse_unsigned_or_error(A, tokens[1], 63);
	parse_register_or_error(Rd, tokens[2]);

	cbins |= (A & 0x000F);
	cbins |= ((A << 5) & 0x0600);
	cbins |= ((Rd << 4) & 0x01F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_rrrrrcbbb(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rr, b | 0 <= d <= 31, 0 <= b <= 7 */
	ut16 Rr, b;
	parse_register_or_error(Rr, tokens[1]);
	parse_unsigned_or_error(b, tokens[2], 63);

	cbins |= (b & 0x0007);
	cbins |= ((Rr << 4) & 0x01F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_ddddcccc(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> Rd | 16 <= d <= 31 */
	ut16 Rd;
	parse_register_or_error_limit(Rd, tokens[1], 16, 31);

	Rd -= 16;
	cbins |= ((Rd << 4) & 0x00F0);

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_spm(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	if (ntokens == 1) {
		/* spm */
		/* 1001010111101000 */
		cbins = 0x95E8;
	} else if (ntokens == 3) {
		/* spm Z+  | 0 <= Rd <= 31 */
		expected_const_or_error(tokens[1], "z");
		expected_const_or_error(tokens[2], "+");

		/* 1001010111111000 */
		cbins = 0x95F8;
	} else {
		throw_error("expected 'spm' or 'spm Z+'\n");
	}

	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_st(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* st M, Rr | 0 <= r <= 31 | M = {X,Y,Z,-X,-Y,-Z} */
	ut16 Rr;
	parse_register_or_error(Rr, tokens[2]);

	if (ntokens == 3) {
		if (!strcmp(tokens[1], "x")) {
			/* st X, Rr */
			/* 1001001rrrrr1100 */
			cbins = 0x920C;
		} else if (!strcmp(tokens[1], "y")) {
			/* st Y, Rr */
			/* 1000001rrrrr1000 */
			cbins = 0x8208;
		} else if (!strcmp(tokens[1], "z")) {
			/* st Z, Rr */
			/* 1000001rrrrr0000 */
			cbins = 0x8200;
		} else if (!strcmp(tokens[1], "-x")) {
			/* st -X, Rr */
			/* 1001001rrrrr1110 */
			cbins = 0x920E;
		} else if (!strcmp(tokens[1], "-y")) {
			/* st -Y, Rr */
			/* 1001001rrrrr1010 */
			cbins = 0x920A;
		} else if (!strcmp(tokens[1], "-z")) {
			/* st -Z, Rr */
			/* 1001001rrrrr0010 */
			cbins = 0x9202;
		} else {
			throw_error("expected 'X' or 'Y' or 'Z' or '-X' or '-Y' or '-Z', but got '%s'\n", tokens[1]);
		}
	} else if (ntokens == 5 && !strcmp(tokens[2], "+") && !strcmp(tokens[3], "1")) {
		if (!strcmp(tokens[1], "x")) {
			/* st X+1, Rr */
			/* 1001001rrrrr1101 */
			cbins = 0x920D;
		} else if (!strcmp(tokens[1], "y")) {
			/* st Y+1, Rr */
			/* 1001001rrrrr1001 */
			cbins = 0x9209;
		} else if (!strcmp(tokens[1], "z")) {
			/* st Z+1, Rr */
			/* 1001001rrrrr0001 */
			cbins = 0x9201;
		} else {
			throw_error("expected 'X+' or 'Y+' or 'Z+', but got '%s+'\n", tokens[2]);
		}
	} else {
		throw_error("expected st M, Rr | 0 <= r <= 31 | M = {X,Y,Z,-X,-Y,-Z}\n");
	}

	cbins |= ((Rr << 4) & 0x01F0);
	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_std(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	if (ntokens == 4) {
		/* std M, Rr     | 0 <= r <= 31 | M = {X+,Y+,Z+} */
		ut16 Rr;
		expected_const_or_error(tokens[2], "+");
		parse_register_or_error(Rr, tokens[3]);

		if (!strcmp(tokens[1], "x")) {
			/* std X+, Rr */
			/* 1001001rrrrr1101 */
			cbins = 0x900D;
		} else if (!strcmp(tokens[1], "y")) {
			/* std Y+, Rr */
			/* 1001001rrrrr1001 */
			cbins = 0x9009;
		} else if (!strcmp(tokens[1], "z")) {
			/* std Z+, Rr */
			/* 1001001rrrrr0001 */
			cbins = 0x9001;
		} else {
			throw_error("expected 'X+' or 'Y+' or 'Z+', but got '%s+'\n", tokens[1]);
		}
		cbins |= ((Rr << 4) & 0x01F0);

		auto_write16(data, cbins, be);
		return 2;
	} else if (ntokens == 5) {
		/* std M + q, Rr | 0 <= r <= 31 | M = {Y,Z} | 0 <= q <= 63*/
		ut16 Rr, q;
		expected_const_or_error(tokens[2], "+");
		parse_unsigned_or_error(q, tokens[3], 63);
		parse_register_or_error(Rr, tokens[4]);

		if (!strcmp(tokens[1], "y")) {
			/* std Y+q, Rr */
			/* 10q0qq1rrrrr1qqq */
			cbins = 0x8208;
		} else if (!strcmp(tokens[1], "z")) {
			/* std Z+q, Rr */
			/* 10q0qq1rrrrr0qqq */
			cbins = 0x8200;
		} else {
			throw_error("expected 'Y' or 'Z', but got '%s'\n", tokens[1]);
		}

		cbins |= q & 0x0007;
		cbins |= ((q << 7) & 0x0C00);
		cbins |= ((q << 8) & 0x2000);
		cbins |= ((Rr << 4) & 0x01F0);

		auto_write16(data, cbins, be);
		return 2;
	}

	throw_error("expected std Rr, M + q | 0 <= d <= 31 | M = {Y,Z} | 0 <= q <= 63\n");
}

static ut32 avr_sts(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* sts k, Rr | 0 <= r <= 31, 0 <= k <= 0xFFFF */
	ut16 Rr;
	ut32 k;
	parse_unsigned_or_error(k, tokens[1], 0xFFFF);
	parse_register_or_error(Rr, tokens[2]);

#if 0
	// The STS (16-bit) and LDS (16-bit) instructions only exist in the reduced AVR cores.
	// This includes only the ATtiny4/5/9/10 family, and the ATtiny20/40 family.
	// They also lack some features like the lack of CPU registers R0 to R15.
	// On rizin these platforms are not supported, therefore this code is commented, but works as intended.
	if (k <= 127 && Rr >= 16) {
		/* sts k, Rr | 16 <= d <= 31 | 0 <= k <= 127 */
		/* 10101kkkddddkkkk */
		cbins = 0xA800;
		Rr -= 16;
		cbins |= k & 0x000F;
		cbins |= ((k << 4) & 0x0700);
		cbins |= ((Rr << 4) & 0x00F0);

		auto_write16(data, cbins, be);
		return 2;
	}
#endif
	/* sts k, Rr | 0 <= d <= 31 | 0 <= k <= 0xFFFF */
	/* 1001001ddddd0000 kkkkkkkkkkkkkkkk */
	cbins = 0x9200;
	cbins |= ((Rr << 4) & 0x01F0);
	auto_write16(data, cbins, be);
	auto_write16(data + 2, k, be);
	return 4;
}

static ut32 avr_ssscccc(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> b | 0 <= b <= 7 */
	ut16 b;
	parse_unsigned_or_error(b, tokens[1], 7);

	cbins |= ((b << 4) & 0x0070);
	auto_write16(data, cbins, be);
	return 2;
}

static ut32 avr_kkkkkkksss(ut16 cbins, cchar **tokens, ut32 ntokens, ut8 *data, ut64 pc, bool be) {
	/* <opcode> b, k | -64 <= k <= 63 | 0 <= b <= 7 */
	ut16 b;
	st16 k;
	parse_unsigned_or_error(b, tokens[1], 7);
	parse_address_or_error(k, tokens[2], pc, -64, 63);

	cbins |= (b & 0x0007);
	cbins |= ((k << 3) & 0x03F8);
	auto_write16(data, cbins, be);
	return 2;
}

// clang-format off
static const AvrInstruction instructions[] = {
	{ "adc" /*    000111rdddddrrrr                  */ , 0x1C00, 3, 3, avr_rdddddrrrr },
	{ "add" /*    000011rdddddrrrr                  */ , 0x0C00, 3, 3, avr_rdddddrrrr },
	{ "adiw" /*   10010110KKddKKKK                  */ , 0x9600, 3, 3, avr_KKddKKKK },
	{ "and" /*    001000rdddddrrrr                  */ , 0x2000, 3, 3, avr_rdddddrrrr },
	{ "andi" /*   0111KKKKddddKKKK                  */ , 0x7000, 3, 3, avr_KKKKddddKKKK },
	{ "asr" /*    1001010ddddd0101                  */ , 0x9405, 2, 2, avr_dddddcccc },
	{ "bclr" /*   100101001sss1000                  */ , 0x9488, 2, 2, avr_ssscccc },
	{ "bld" /*    1111100ddddd0bbb                  */ , 0xF800, 3, 3, avr_dddddcbbb },
	{ "brbc" /*   111101kkkkkkksss                  */ , 0xF400, 3, 3, avr_kkkkkkksss },
	{ "brbs" /*   111100kkkkkkksss                  */ , 0xF000, 3, 3, avr_kkkkkkksss },
	{ "brcc" /*   111101kkkkkkk000                  */ , 0xF400, 2, 2, avr_kkkkkkkccc },
	{ "brcs" /*   111100kkkkkkk000                  */ , 0xF000, 2, 2, avr_kkkkkkkccc },
	{ "break" /*  1001010110011000                  */ , 0x9598, 1, 1, avr_unique },
	{ "breq" /*   111100kkkkkkk001                  */ , 0xF001, 2, 2, avr_kkkkkkkccc },
	{ "brge" /*   111101kkkkkkk100                  */ , 0xF404, 2, 2, avr_kkkkkkkccc },
	{ "brhc" /*   111101kkkkkkk101                  */ , 0xF405, 2, 2, avr_kkkkkkkccc },
	{ "brhs" /*   111100kkkkkkk101                  */ , 0xF005, 2, 2, avr_kkkkkkkccc },
	{ "brid" /*   111101kkkkkkk111                  */ , 0xF407, 2, 2, avr_kkkkkkkccc },
	{ "brie" /*   111100kkkkkkk111                  */ , 0xF007, 2, 2, avr_kkkkkkkccc },
	{ "brlo" /*   111100kkkkkkk000                  */ , 0xF000, 2, 2, avr_kkkkkkkccc },
	{ "brlt" /*   111100kkkkkkk100                  */ , 0xF004, 2, 2, avr_kkkkkkkccc },
	{ "brmi" /*   111100kkkkkkk010                  */ , 0xF002, 2, 2, avr_kkkkkkkccc },
	{ "brne" /*   111101kkkkkkk001                  */ , 0xF401, 2, 2, avr_kkkkkkkccc },
	{ "brpl" /*   111101kkkkkkk010                  */ , 0xF402, 2, 2, avr_kkkkkkkccc },
	{ "brsh" /*   111101kkkkkkk000                  */ , 0xF400, 2, 2, avr_kkkkkkkccc },
	{ "brtc" /*   111101kkkkkkk110                  */ , 0xF406, 2, 2, avr_kkkkkkkccc },
	{ "brts" /*   111100kkkkkkk110                  */ , 0xF006, 2, 2, avr_kkkkkkkccc },
	{ "brvc" /*   111101kkkkkkk011                  */ , 0xF403, 2, 2, avr_kkkkkkkccc },
	{ "brvs" /*   111100kkkkkkk011                  */ , 0xF003, 2, 2, avr_kkkkkkkccc },
	{ "bset" /*   100101000sss1000                  */ , 0x9408, 2, 2, avr_ssscccc },
	{ "bst" /*    1111101ddddd0bbb                  */ , 0xFA00, 3, 3, avr_dddddcbbb },
	{ "call" /*   1001010kkkkk111k kkkkkkkkkkkkkkkk */ , 0x940E, 2, 2, avr_kkkkkccck },
	{ "cbi" /*    10011000AAAAAbbb                  */ , 0x9800, 3, 3, avr_AAAAAbbb },
	{ "cbr" /*    0111KKKKddddKKKK                  */ , 0x7000, 3, 3, avr_cbr },
	{ "clc" /*    1001010010001000                  */ , 0x9488, 1, 1, avr_unique },
	{ "clh" /*    1001010011011000                  */ , 0x94D8, 1, 1, avr_unique },
	{ "cli" /*    1001010011111000                  */ , 0x94F8, 1, 1, avr_unique },
	{ "cln" /*    1001010010101000                  */ , 0x94A8, 1, 1, avr_unique },
	{ "clr" /*    001001dddddddddd                  */ , 0x2400, 2, 2, avr_dddddddddd },
	{ "cls" /*    1001010011001000                  */ , 0x94C8, 1, 1, avr_unique },
	{ "clt" /*    1001010011101000                  */ , 0x94E8, 1, 1, avr_unique },
	{ "clv" /*    1001010010111000                  */ , 0x94B8, 1, 1, avr_unique },
	{ "clz" /*    1001010010011000                  */ , 0x9498, 1, 1, avr_unique },
	{ "com" /*    1001010ddddd0000                  */ , 0x9400, 2, 2, avr_dddddcccc },
	{ "cp" /*     000101rdddddrrrr                  */ , 0x1400, 3, 3, avr_rdddddrrrr },
	{ "cpc" /*    000001rdddddrrrr                  */ , 0x0400, 3, 3, avr_rdddddrrrr },
	{ "cpi" /*    0011KKKKddddKKKK                  */ , 0x3000, 3, 3, avr_KKKKddddKKKK },
	{ "cpse" /*   000100rdddddrrrr                  */ , 0x1000, 3, 3, avr_rdddddrrrr },
	{ "dec" /*    1001010ddddd1010                  */ , 0x940A, 2, 2, avr_dddddcccc },
	{ "des" /*    10010100KKKK1011                  */ , 0x940B, 2, 2, avr_KKKKcccc },
	{ "eicall" /* 1001010100011001                  */ , 0x9519, 1, 1, avr_unique },
	{ "eijmp" /*  1001010000011001                  */ , 0x9419, 1, 1, avr_unique },
	{ "elpm" /*                                     */ , 0x0000, 1, 5, avr_elpm },
	{ "eor" /*    001001rdddddrrrr                  */ , 0x2400, 3, 3, avr_rdddddrrrr },
	{ "fmul" /*   000000110ddd1rrr                  */ , 0x0308, 3, 3, avr_dddcrrr },
	{ "fmuls" /*  000000111ddd0rrr                  */ , 0x0380, 3, 3, avr_dddcrrr },
	{ "fmulsu" /* 000000111ddd1rrr                  */ , 0x0388, 3, 3, avr_dddcrrr },
	{ "icall" /*  1001010100001001                  */ , 0x9509, 1, 1, avr_unique },
	{ "ijmp" /*   1001010000001001                  */ , 0x9409, 1, 1, avr_unique },
	{ "in" /*     10110AAdddddAAAA                  */ , 0xB000, 3, 3, avr_AAdddddAAAA },
	{ "inc" /*    1001010ddddd0011                  */ , 0x9403, 2, 2, avr_dddddcccc },
	{ "jmp" /*    1001010kkkkk110k kkkkkkkkkkkkkkkk */ , 0x940C, 2, 2, avr_kkkkkccck },
	{ "lac" /*    1001001rrrrr0110                  */ , 0x9206, 3, 3, avr_rrrrrcccc },
	{ "las" /*    1001001rrrrr0101                  */ , 0x9205, 3, 3, avr_rrrrrcccc },
	{ "lat" /*    1001001rrrrr0111                  */ , 0x9207, 3, 3, avr_rrrrrcccc },
	{ "ld" /*                                       */ , 0x0000, 3, 5, avr_ld },
	{ "ldd" /*                                      */ , 0x0000, 5, 5, avr_ldd },
	{ "ldi" /*    1110KKKKddddKKKK                  */ , 0xE000, 3, 3, avr_KKKKddddKKKK },
	{ "lds" /*                                      */ , 0x0000, 3, 3, avr_lds },
	{ "lpm" /*                                      */ , 0x0000, 1, 5, avr_lpm },
	{ "lsl" /*    000011dddddddddd                  */ , 0x0C00, 2, 2, avr_dddddddddd },
	{ "lsr" /*    1001010ddddd0110                  */ , 0x9406, 2, 2, avr_dddddcccc },
	{ "mov" /*    001011rdddddrrrr                  */ , 0x2C00, 3, 3, avr_rdddddrrrr },
	{ "movw" /*   00000001ddddrrrr                  */ , 0x0100, 3, 3, avr_ddddrrrr },
	{ "mul" /*    100111rdddddrrrr                  */ , 0x9C00, 3, 3, avr_rdddddrrrr },
	{ "muls" /*   00000010ddddrrrr                  */ , 0x0200, 3, 3, avr_ddddrrrr_2x },
	{ "mulsu" /*  000000110ddd0rrr                  */ , 0x0300, 3, 3, avr_dddcrrr },
	{ "neg" /*    1001010ddddd0001                  */ , 0x9401, 2, 2, avr_dddddcccc },
	{ "nop" /*    0000000000000000                  */ , 0x0000, 1, 1, avr_unique },
	{ "or" /*     001010rdddddrrrr                  */ , 0x2800, 3, 3, avr_rdddddrrrr },
	{ "ori" /*    0110KKKKddddKKKK                  */ , 0x6000, 3, 3, avr_KKKKddddKKKK },
	{ "out" /*    10111AArrrrrAAAA                  */ , 0xB800, 3, 3, avr_AArrrrrAAAA },
	{ "pop" /*    1001000ddddd1111                  */ , 0x900F, 2, 2, avr_dddddcccc },
	{ "push" /*   1001001ddddd1111                  */ , 0x920F, 2, 2, avr_dddddcccc },
	{ "rcall" /*  1101kkkkkkkkkkkk                  */ , 0xD000, 2, 2, avr_kkkkkkkkkkkk },
	{ "ret" /*    1001010100001000                  */ , 0x9508, 1, 1, avr_unique },
	{ "reti" /*   1001010100011000                  */ , 0x9518, 1, 1, avr_unique },
	{ "rjmp" /*   1100kkkkkkkkkkkk                  */ , 0xC000, 2, 2, avr_kkkkkkkkkkkk },
	{ "rol" /*    000111dddddddddd                  */ , 0x1C00, 2, 2, avr_dddddddddd },
	{ "ror" /*    1001010ddddd0111                  */ , 0x9407, 2, 2, avr_dddddcccc },
	{ "sbc" /*    000010rdddddrrrr                  */ , 0x0800, 3, 3, avr_rdddddrrrr },
	{ "sbci" /*   0100KKKKddddKKKK                  */ , 0x4000, 3, 3, avr_KKKKddddKKKK },
	{ "sbi" /*    10011010AAAAAbbb                  */ , 0x9A00, 3, 3, avr_AAAAAbbb },
	{ "sbic" /*   10011001AAAAAbbb                  */ , 0x9900, 3, 3, avr_AAAAAbbb },
	{ "sbis" /*   10011011AAAAAbbb                  */ , 0x9B00, 3, 3, avr_AAAAAbbb },
	{ "sbiw" /*   10010111KKddKKKK                  */ , 0x9700, 3, 3, avr_KKddKKKK },
	{ "sbr" /*    0110KKKKddddKKKK                  */ , 0x6000, 3, 3, avr_KKKKddddKKKK },
	{ "sbrc" /*   1111110rrrrr0bbb                  */ , 0xFC00, 3, 3, avr_rrrrrcbbb },
	{ "sbrs" /*   1111111rrrrr0bbb                  */ , 0xFE00, 3, 3, avr_rrrrrcbbb },
	{ "sec" /*    1001010000001000                  */ , 0x9408, 1, 1, avr_unique },
	{ "seh" /*    1001010001011000                  */ , 0x9458, 1, 1, avr_unique },
	{ "sei" /*    1001010001111000                  */ , 0x9478, 1, 1, avr_unique },
	{ "sen" /*    1001010000101000                  */ , 0x9428, 1, 1, avr_unique },
	{ "ser" /*    11101111dddd1111                  */ , 0xEF0F, 2, 2, avr_ddddcccc },
	{ "ses" /*    1001010001001000                  */ , 0x9448, 1, 1, avr_unique },
	{ "set" /*    1001010001101000                  */ , 0x9468, 1, 1, avr_unique },
	{ "sev" /*    1001010000111000                  */ , 0x9438, 1, 1, avr_unique },
	{ "sez" /*    1001010000011000                  */ , 0x9418, 1, 1, avr_unique },
	{ "sleep" /*  1001010110001000                  */ , 0x9588, 1, 1, avr_unique },
	{ "spm" /*                                      */ , 0x0000, 1, 5, avr_spm },
	{ "st" /*                                       */ , 0x0000, 3, 5, avr_st },
	{ "std" /*                                      */ , 0x0000, 4, 5, avr_std },
	{ "sts" /*                                      */ , 0x0000, 3, 3, avr_sts },
	{ "sub" /*    000110rdddddrrrr                  */ , 0x1800, 3, 3, avr_rdddddrrrr },
	{ "subi" /*   0101KKKKddddKKKK                  */ , 0x5000, 3, 3, avr_KKKKddddKKKK },
	{ "swap" /*   1001010ddddd0010                  */ , 0x9402, 2, 2, avr_dddddcccc },
	{ "tst" /*    001000dddddddddd                  */ , 0x2000, 2, 2, avr_dddddddddd },
	{ "wdr" /*    1001010110101000                  */ , 0x95A8, 1, 1, avr_unique },
	{ "xch" /*    1001001rrrrr0100                  */ , 0x9204, 3, 3, avr_rrrrrcccc }
};
// clang-format on

static char *strdup_limit(cchar *begin, cchar *end) {
	ssize_t size = end - begin;
	if (size < 1) {
		return NULL;
	}
	char *str = malloc(size + 1);
	if (!str) {
		return NULL;
	}
	memcpy(str, begin, size);
	str[size] = 0;
	return str;
}

static void sanitize_input(char *cinput, st32 input_size) {
	for (st32 i = 0; i < input_size; ++i) {
		if (cinput[i] == ',') {
			cinput[i] = ' ';
		}
	}
}

static char **tokens_new(cchar *input, st32 input_size, ut32 *ntokens) {

	char *cinput = rz_str_dup(input);
	if (!cinput) {
		rz_warn_if_reached();
		return NULL;
	}

	sanitize_input(cinput, input_size);

	char **tokens = RZ_NEWS0(char *, MAX_TOKENS);
	if (!tokens) {
		free(cinput);
		rz_warn_if_reached();
		return NULL;
	}

	ut32 count;
	cchar *start, *end;
	char *copy;

	start = rz_str_trim_head_ro(cinput);
	for (count = 0; *start && count < MAX_TOKENS; count++) {
		end = rz_str_trim_head_wp(start);

		for (ut32 i = 0; i < end - start; ++i) {
			if (start[i] == '+') {
				end = start + 1;
				break;
			}
		}

		copy = strdup_limit(start, end);
		if (!copy) {
			rz_warn_if_reached();
			break;
		}

		tokens[count] = copy;
		start = rz_str_trim_head_ro(end);
	}

	rz_warn_if_fail(count < MAX_TOKENS);

	*ntokens = count;
	free(cinput);
	return tokens;
}

static void tokens_free(char **tokens) {
	if (!tokens) {
		return;
	}
	for (ut32 i = 0; i < MAX_TOKENS; ++i) {
		free(tokens[i]);
	}
	free(tokens);
}

// TODO handle endianness
ut32 avr_assembler(const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, bool be) {
	return_error_if_empty_input(input, input_size);

	ut32 written = AVR_INVALID_SIZE;
	ut32 ntokens = 0;
	char **tokens = tokens_new(input, input_size, &ntokens);
	if (!tokens || ntokens < 1) {
		RZ_LOG_ERROR("[!] avr_assembler: invalid assembly.\n");
		goto avr_assembler_end;
	}

	for (ut32 i = 0; i < RZ_ARRAY_SIZE(instructions); ++i) {
		if (!rz_str_casecmp(tokens[0], instructions[i].opcode)) {
			ut16 mintoks = instructions[i].mintoks;
			ut16 maxtoks = instructions[i].maxtoks;
			if (ntokens < mintoks || ntokens > maxtoks) {
				RZ_LOG_ERROR("[!] avr_assembler: '%s' requires %u <= ntokens <= %u, but %u tokens was provided.\n", tokens[0], mintoks, maxtoks, ntokens);
				goto avr_assembler_end;
			}
			written = instructions[i].encode(instructions[i].cbits, (cchar **)tokens, ntokens, output, pc, be);
			break;
		}
	}

avr_assembler_end:
	tokens_free(tokens);
	return written;
}
