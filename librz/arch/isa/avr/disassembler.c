// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "disassembler.h"
#include "common.h"

/** \file disassembler.c
 * Disassembles AVR instructions
 * Each instruction is decoded comparing the applied bitmask result with constants bits
 * Legend for function decoders names:
 * - r = Rr
 * - d = Rd
 * - K, k = immediate value
 * - b = bit offset
 * - A = i/o address
 * - c = constant value (see cbits)
 * - x, xp, xm = X, X+, -X
 * - y, yp, ym = Y, Y+, -Y
 * - z, zp, zm = Z, Z+, -Z
 * - q = displacement const
 */

typedef ut32 (*Decode)(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb);

typedef struct avr_decoder_t {
	cchar *name; /*  instruction name */
	AVROpMnem id; /* instruction identifier */
	ut32 cycles; /*  number of execution cycles */
	ut16 cbits; /*   constant bits */
	ut16 mbits; /*   mask to compare with constant bits */
	ut32 opsize; /*  instruction size */
	Decode decode;
} AvrInstruction;

static ut32 avr_unique(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	aop->mnemonic = id;
	rz_strbuf_set(sb, name);
	return 2;
}

static ut32 avr_rdddddrrrr(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = data[0] & 0x000F;
	ut16 Rd = ((data[0] & 0x01F0) >> 4);
	Rr |= ((data[0] & 0x0200) >> 5);

	aop->param[0] = Rd;
	aop->param[1] = Rr;
	if (Rd == Rr) {
		aop->param[0] = Rd;
		if (!strncmp(name, "adc", 3)) {
			aop->mnemonic = AVR_OP_ROL;
			rz_strbuf_setf(sb, "rol r%u", Rd);
		} else if (!strncmp(name, "add", 3)) {
			aop->mnemonic = AVR_OP_LSL;
			rz_strbuf_setf(sb, "lsl r%u", Rd);
		} else if (!strncmp(name, "and", 3)) {
			aop->mnemonic = AVR_OP_TST;
			rz_strbuf_setf(sb, "tst r%u", Rd);
		} else if (!strncmp(name, "eor", 3)) {
			aop->mnemonic = AVR_OP_CLR;
			rz_strbuf_setf(sb, "clr r%u", Rd);
		} else {
			aop->mnemonic = id;
			rz_strbuf_setf(sb, "%s r%u, r%u", name, Rd, Rr);
		}
	} else {
		aop->mnemonic = id;
		rz_strbuf_setf(sb, "%s r%u, r%u", name, Rd, Rr);
	}

	return 2;
}

static ut32 avr_KKddKKKK(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 K = data[0] & 0x000F;
	ut16 Rd = 24 + ((data[0] & 0x0030) >> 3);
	K |= ((data[0] & 0x00C0) >> 2);

	aop->mnemonic = id;
	aop->param[0] = Rd + 1;
	aop->param[1] = Rd;
	aop->param[2] = K;
	rz_strbuf_setf(sb, "%s r%u:r%u, 0x%02x", name, Rd + 1, Rd, K);
	return 2;
}

static ut32 avr_KKKKddddKKKK(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 K = data[0] & 0x000F;
	ut16 Rd = 16 + ((data[0] & 0x00F0) >> 4);
	K |= ((data[0] & 0x0F00) >> 4);

	aop->param[0] = Rd;
	if (K == 0xFF && !strncmp(name, "ldi", 3)) {
		aop->mnemonic = AVR_OP_SER;
		rz_strbuf_setf(sb, "ser r%u", Rd);
	} else {
		aop->mnemonic = id;
		aop->param[1] = K;
		rz_strbuf_setf(sb, "%s r%u, 0x%02x", name, Rd, K);
	}

	return 2;
}

static ut32 avr_dddddcccc(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	rz_strbuf_setf(sb, "%s r%u", name, Rd);
	return 2;
}

static ut32 avr_dddddcbbb(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 b = data[0] & 0x0007;
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = b;
	rz_strbuf_setf(sb, "%s r%u, %u", name, Rd, b);
	return 2;
}

static ut32 avr_kkkkkkkccc(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	st16 k = (data[0] & 0x03F8) >> 3;
	k *= 2;
	if (k & 0x0080) {
		// manually extend signed value
		k |= 0xFF00;
		k = -(~k) + 1;
	} else {
		k += 2;
	}
	pc += k;

	aop->mnemonic = id;
	aop->param[0] = pc;
	rz_strbuf_setf(sb, "%s 0x%" PFMT64x, name, pc);
	return 2;
}

static ut32 avr_kkkkkccck(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	st32 k = data[0] & 0x0001;
	k |= ((data[0] & 0x01F0) >> 3);
	k <<= 16;
	k |= data[1];
	k *= 2;

	aop->mnemonic = id;
	aop->param[0] = (k >> 16) & 0xFFFF;
	aop->param[1] = k & 0xFFFF;
	rz_strbuf_setf(sb, "%s 0x%x", name, k);
	return 4;
}

static ut32 avr_AAAAAbbb(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 b = data[0] & 0x0007;
	ut16 A = ((data[0] & 0x00F8) >> 3);

	aop->mnemonic = id;
	aop->param[0] = A;
	aop->param[1] = b;
	rz_strbuf_setf(sb, "%s 0x%02x, %u", name, A, b);
	return 2;
}

static ut32 avr_KKKKcccc(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 K = ((data[0] & 0x00F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = K;
	rz_strbuf_setf(sb, "%s 0x%02x", name, K);
	return 2;
}

static ut32 avr_dddddcccc_z(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'Z';
	rz_strbuf_setf(sb, "%s r%u, Z", name, Rd);
	return 2;
}

static ut32 avr_dddddcccc_zp(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'Z';
	aop->param[2] = '+';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s r%u, Z+", name, Rd);
	return 2;
}

static ut32 avr_dddcrrr(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = 16 + (data[0] & 0x0007);
	ut16 Rd = 16 + ((data[0] & 0x0070) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = Rr;
	rz_strbuf_setf(sb, "%s r%u, r%u", name, Rd, Rr);
	return 2;
}

static ut32 avr_AAdddddAAAA(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 A = data[0] & 0x000F;
	ut16 Rd = ((data[0] & 0x01F0) >> 4);
	A |= ((data[0] & 0x0600) >> 5);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = A;
	rz_strbuf_setf(sb, "%s r%u, 0x%02x", name, Rd, A);
	return 2;
}

static ut32 avr_dddddcccc_x(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'X';
	rz_strbuf_setf(sb, "%s r%u, X", name, Rd);
	return 2;
}

static ut32 avr_dddddcccc_xp(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'X';
	aop->param[2] = '+';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s r%u, X+", name, Rd);
	return 2;
}

static ut32 avr_dddddcccc_xm(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'X';
	aop->param[2] = '-';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s r%u, -X", name, Rd);
	return 2;
}

static ut32 avr_dddddcccc_y(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'Y';
	rz_strbuf_setf(sb, "%s r%u, Y", name, Rd);
	return 2;
}

static ut32 avr_dddddcccc_yp(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'Y';
	aop->param[2] = '+';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s r%u, Y+", name, Rd);
	return 2;
}

static ut32 avr_dddddcccc_ym(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'Y';
	aop->param[2] = '-';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s r%u, -Y", name, Rd);
	return 2;
}

static ut32 avr_qcqqcdddddcqqq_y(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 q = data[0] & 0x0007;
	ut16 Rd = ((data[0] & 0x01F0) >> 4);
	q |= ((data[0] & 0x0C00) >> 7);
	q |= ((data[0] & 0x2000) >> 8);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'Y';
	aop->param[2] = '+';
	aop->param[3] = q;
	rz_strbuf_setf(sb, "%s r%u, Y+%u", name, Rd, q);
	return 2;
}

static ut32 avr_dddddcccc_zm(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'Z';
	aop->param[2] = '-';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s r%u, -Z", name, Rd);
	return 2;
}

static ut32 avr_qcqqcdddddcqqq_z(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 q = data[0] & 0x0007;
	ut16 Rd = ((data[0] & 0x01F0) >> 4);
	q |= ((data[0] & 0x0C00) >> 7);
	q |= ((data[0] & 0x2000) >> 8);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = 'Z';
	aop->param[2] = '+';
	aop->param[3] = q;
	rz_strbuf_setf(sb, "%s r%u, Z+%u", name, Rd, q);
	return 2;
}

static ut32 avr_dddddcccc_load32(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);
	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = data[1];
	rz_strbuf_setf(sb, "%s r%u, 0x%02x", name, Rd, data[1]);
	return 4;
}

static ut32 avr_kkkddddkkkk_load16(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 k = data[0] & 0x000F;
	ut16 Rd = 16 + ((data[0] & 0x00F0) >> 4);
	k |= ((data[0] & 0x0700) >> 4);
	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = k;
	rz_strbuf_setf(sb, "%s r%u, 0x%02x", name, Rd, k);
	return 2;
}

static ut32 avr_ddddrrrr(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = data[0] & 0x000F;
	ut16 Rd = ((data[0] & 0x00F0) >> 4);

	Rr *= 2;
	Rd *= 2;

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = Rr;
	rz_strbuf_setf(sb, "%s r%u, r%u", name, Rd, Rr);
	return 2;
}

static ut32 avr_ddddrrrr_2x(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = data[0] & 0x000F;
	ut16 Rd = ((data[0] & 0x00F0) >> 4);
	Rr += 16;
	Rd += 16;

	aop->mnemonic = id;
	aop->param[0] = Rd;
	aop->param[1] = Rr;
	rz_strbuf_setf(sb, "%s r%u, r%u", name, Rd, Rr);
	return 2;
}

static ut32 avr_AArrrrrAAAA(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 A = data[0] & 0x000F;
	ut16 Rr = ((data[0] & 0x01F0) >> 4);
	A |= ((data[0] & 0x0600) >> 5);

	aop->mnemonic = id;
	aop->param[0] = A;
	aop->param[1] = Rr;
	rz_strbuf_setf(sb, "%s 0x%02x, r%u", name, A, Rr);
	return 2;
}

static ut32 avr_kkkkkkkkkkkk(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	st16 k = data[0] & 0x0FFF;
	k *= 2;
	if (k & 0x1000) {
		// manually extend signed value
		k |= 0xF000;
		k = -(~k) + 1;
	} else {
		k += 2;
	}

	pc += k;

	aop->mnemonic = id;
	aop->param[0] = k;
	rz_strbuf_setf(sb, "%s 0x%" PFMT64x, name, pc);
	return 2;
}

static ut32 avr_rrrrrcbbb(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 b = data[0] & 0x0007;
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = b;
	rz_strbuf_setf(sb, "%s r%u, %u", name, Rr, b);
	return 2;
}

static ut32 avr_ddddcccc(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = 16 + ((data[0] & 0x00F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rd;
	rz_strbuf_setf(sb, "%s r%u", name, Rd);
	return 2;
}

static ut32 avr_spmz(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	aop->mnemonic = id;
	aop->param[0] = 'Z';
	aop->param[1] = '+';
	rz_strbuf_setf(sb, "%s Z+", name);
	return 2;
}

static ut32 avr_rrrrrcccc_x(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'X';
	rz_strbuf_setf(sb, "%s X, r%u", name, Rr);
	return 2;
}

static ut32 avr_rrrrrcccc_xp(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'X';
	aop->param[2] = '+';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s X+1, r%u", name, Rr);
	return 2;
}

static ut32 avr_rrrrrcccc_xm(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'X';
	aop->param[2] = '-';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s -X, r%u", name, Rr);
	return 2;
}

static ut32 avr_rrrrrcccc_y(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'Y';
	rz_strbuf_setf(sb, "%s Y, r%u", name, Rr);
	return 2;
}

static ut32 avr_rrrrrcccc_yp(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'Y';
	aop->param[2] = '+';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s Y+1, r%u", name, Rr);
	return 2;
}

static ut32 avr_rrrrrcccc_ym(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'Y';
	aop->param[2] = '-';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s -Y, r%u", name, Rr);
	return 2;
}

static ut32 avr_qcqqcrrrrrcqqq_y(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 q = data[0] & 0x0007;
	ut16 Rr = ((data[0] & 0x01F0) >> 4);
	q |= ((data[0] & 0x0C00) >> 7);
	q |= ((data[0] & 0x2000) >> 8);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'Y';
	aop->param[2] = '+';
	aop->param[3] = q;
	rz_strbuf_setf(sb, "%s Y+%u, r%u", name, q, Rr);
	return 2;
}

static ut32 avr_rrrrrcccc_z(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'Z';
	rz_strbuf_setf(sb, "%s Z, r%u", name, Rr);
	return 2;
}

static ut32 avr_rrrrrcccc_zp(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'Z';
	aop->param[2] = '+';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s Z+1, r%u", name, Rr);
	return 2;
}

static ut32 avr_rrrrrcccc_zm(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'Z';
	aop->param[2] = '-';
	aop->param[3] = 1;
	rz_strbuf_setf(sb, "%s -Z, r%u", name, Rr);
	return 2;
}

static ut32 avr_qcqqcrrrrrcqqq_z(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 q = data[0] & 0x0007;
	ut16 Rr = ((data[0] & 0x01F0) >> 4);
	q |= ((data[0] & 0x0C00) >> 7);
	q |= ((data[0] & 0x2000) >> 8);

	aop->mnemonic = id;
	aop->param[0] = Rr;
	aop->param[1] = 'Z';
	aop->param[2] = '+';
	aop->param[3] = q;
	rz_strbuf_setf(sb, "%s Z+%u, r%u", name, q, Rr);
	return 2;
}

static ut32 avr_dddddcccc_store32(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	aop->mnemonic = id;
	aop->param[0] = data[1];
	aop->param[1] = Rd;
	rz_strbuf_setf(sb, "%s 0x%02x, r%u", name, data[1], Rd);
	return 4;
}

static ut32 avr_kkkddddkkkk_store16(cchar *name, AVROpMnem id, ut16 data[2], ut64 pc, AVROp *aop, RzStrBuf *sb) {
	ut16 k = data[0] & 0x000F;
	ut16 Rd = 16 + ((data[0] & 0x00F0) >> 4);
	k |= ((data[0] & 0x0700) >> 4);

	aop->mnemonic = id;
	aop->param[0] = k;
	aop->param[1] = Rd;
	rz_strbuf_setf(sb, "%s 0x%02x, r%u", name, k, Rd);
	return 2;
}

// clang-format off
static const AvrInstruction instructions[] = {
	{ "adc", AVR_OP_ADC /*       000111rdddddrrrr                  */, 2, 0x1C00, 0xFC00, 2, avr_rdddddrrrr },
	{ "add", AVR_OP_ADD /*       000011rdddddrrrr                  */, 2, 0x0C00, 0xFC00, 2, avr_rdddddrrrr },
	{ "adiw", AVR_OP_ADIW /*     10010110KKddKKKK                  */, 2, 0x9600, 0xFF00, 2, avr_KKddKKKK },
	{ "and", AVR_OP_AND /*       001000rdddddrrrr                  */, 2, 0x2000, 0xFC00, 2, avr_rdddddrrrr },
	{ "andi", AVR_OP_ANDI /*     0111KKKKddddKKKK                  */, 2, 0x7000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "asr", AVR_OP_ASR /*       1001010ddddd0101                  */, 2, 0x9405, 0xFE0F, 2, avr_dddddcccc },
	{ "bld", AVR_OP_BLD /*       1111100ddddd0bbb                  */, 2, 0xF800, 0xFE08, 2, avr_dddddcbbb },
	{ "brcc", AVR_OP_BRCC /*     111101kkkkkkk000                  */, 1, 0xF400, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brcs", AVR_OP_BRCS /*     111100kkkkkkk000                  */, 1, 0xF000, 0xFC07, 2, avr_kkkkkkkccc },
	{ "break", AVR_OP_BREAK /*   1001010110011000                  */, 1, 0x9598, 0xFFFF, 2, avr_unique },
	{ "breq", AVR_OP_BREQ /*     111100kkkkkkk001                  */, 1, 0xF001, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brge", AVR_OP_BRGE /*     111101kkkkkkk100                  */, 1, 0xF404, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brhc", AVR_OP_BRHC /*     111101kkkkkkk101                  */, 1, 0xF405, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brhs", AVR_OP_BRHS /*     111100kkkkkkk101                  */, 1, 0xF005, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brid", AVR_OP_BRID /*     111101kkkkkkk111                  */, 1, 0xF407, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brie", AVR_OP_BRIE /*     111100kkkkkkk111                  */, 1, 0xF007, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brlo", AVR_OP_BRLO /*     111100kkkkkkk000                  */, 1, 0xF000, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brlt", AVR_OP_BRLT /*     111100kkkkkkk100                  */, 1, 0xF004, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brmi", AVR_OP_BRMI /*     111100kkkkkkk010                  */, 1, 0xF002, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brne", AVR_OP_BRNE /*     111101kkkkkkk001                  */, 1, 0xF401, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brpl", AVR_OP_BRPL /*     111101kkkkkkk010                  */, 1, 0xF402, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brsh", AVR_OP_BRSH /*     111101kkkkkkk000                  */, 1, 0xF400, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brtc", AVR_OP_BRTC /*     111101kkkkkkk110                  */, 1, 0xF406, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brts", AVR_OP_BRTS /*     111100kkkkkkk110                  */, 1, 0xF006, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brvc", AVR_OP_BRVC /*     111101kkkkkkk011                  */, 1, 0xF403, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brvs", AVR_OP_BRVS /*     111100kkkkkkk011                  */, 1, 0xF003, 0xFC07, 2, avr_kkkkkkkccc },
	{ "bst", AVR_OP_BST /*       1111101ddddd0bbb                  */, 2, 0xFA00, 0xFE08, 2, avr_dddddcbbb },
	{ "call", AVR_OP_CALL /*     1001010kkkkk111k kkkkkkkkkkkkkkkk */, 4, 0x940E, 0xFE0E, 4, avr_kkkkkccck },
	{ "cbi", AVR_OP_CBI /*       10011000AAAAAbbb                  */, 2, 0x9800, 0xFF00, 2, avr_AAAAAbbb },
	{ "clc", AVR_OP_CLC /*       1001010010001000                  */, 2, 0x9488, 0xFFFF, 2, avr_unique },
	{ "clh", AVR_OP_CLH /*       1001010011011000                  */, 2, 0x94D8, 0xFFFF, 2, avr_unique },
	{ "cli", AVR_OP_CLI /*       1001010011111000                  */, 2, 0x94F8, 0xFFFF, 2, avr_unique },
	{ "cln", AVR_OP_CLN /*       1001010010101000                  */, 2, 0x94A8, 0xFFFF, 2, avr_unique },
	{ "cls", AVR_OP_CLS /*       1001010011001000                  */, 2, 0x94C8, 0xFFFF, 2, avr_unique },
	{ "clt", AVR_OP_CLT /*       1001010011101000                  */, 2, 0x94E8, 0xFFFF, 2, avr_unique },
	{ "clv", AVR_OP_CLV /*       1001010010111000                  */, 2, 0x94B8, 0xFFFF, 2, avr_unique },
	{ "clz", AVR_OP_CLZ /*       1001010010011000                  */, 2, 0x9498, 0xFFFF, 2, avr_unique },
	{ "com", AVR_OP_COM /*       1001010ddddd0000                  */, 2, 0x9400, 0xFE0F, 2, avr_dddddcccc },
	{ "cp", AVR_OP_CP /*         000101rdddddrrrr                  */, 2, 0x1400, 0xFC00, 2, avr_rdddddrrrr },
	{ "cpc", AVR_OP_CPC /*       000001rdddddrrrr                  */, 2, 0x0400, 0xFC00, 2, avr_rdddddrrrr },
	{ "cpi", AVR_OP_CPI /*       0011KKKKddddKKKK                  */, 2, 0x3000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "cpse", AVR_OP_CPSE /*     000100rdddddrrrr                  */, 1, 0x1000, 0xFC00, 2, avr_rdddddrrrr },
	{ "dec", AVR_OP_DEC /*       1001010ddddd1010                  */, 2, 0x940A, 0xFE0F, 2, avr_dddddcccc },
	{ "des", AVR_OP_DES /*       10010100KKKK1011                  */, 1, 0x940B, 0xFF0F, 2, avr_KKKKcccc },
	{ "eicall", AVR_OP_EICALL /* 1001010100011001                  */, 4, 0x9519, 0xFFFF, 2, avr_unique },
	{ "eijmp", AVR_OP_EIJMP /*   1001010000011001                  */, 2, 0x9419, 0xFFFF, 2, avr_unique },
	{ "elpm", AVR_OP_ELPM /*     1001010111011000                  */, 2, 0x95D8, 0xFFFF, 2, avr_unique },
	{ "elpm", AVR_OP_ELPM /*     1001000ddddd0110                  */, 2, 0x9006, 0xFE0F, 2, avr_dddddcccc_z },
	{ "elpm", AVR_OP_ELPM /*     1001000ddddd0111                  */, 2, 0x9007, 0xFE0F, 2, avr_dddddcccc_zp },
	{ "eor", AVR_OP_EOR /*       001001rdddddrrrr                  */, 2, 0x2400, 0xFC00, 2, avr_rdddddrrrr },
	{ "fmul", AVR_OP_FMUL /*     000000110ddd1rrr                  */, 2, 0x0308, 0xFF88, 2, avr_dddcrrr },
	{ "fmuls", AVR_OP_FMULS /*   000000111ddd0rrr                  */, 2, 0x0380, 0xFF88, 2, avr_dddcrrr },
	{ "fmulsu", AVR_OP_FMULSU /* 000000111ddd1rrr                  */, 2, 0x0388, 0xFF88, 2, avr_dddcrrr },
	{ "icall", AVR_OP_ICALL /*   1001010100001001                  */, 2, 0x9509, 0xFFFF, 2, avr_unique },
	{ "ijmp", AVR_OP_IJMP /*     1001010000001001                  */, 2, 0x9409, 0xFFFF, 2, avr_unique },
	{ "in", AVR_OP_IN /*         10110AAdddddAAAA                  */, 2, 0xB000, 0xF800, 2, avr_AAdddddAAAA },
	{ "inc", AVR_OP_INC /*       1001010ddddd0011                  */, 2, 0x9403, 0xFE0F, 2, avr_dddddcccc },
	{ "jmp", AVR_OP_JMP /*       1001010kkkkk110k kkkkkkkkkkkkkkkk */, 3, 0x940C, 0xFE0E, 4, avr_kkkkkccck },
	{ "lac", AVR_OP_LAC /*       1001001rrrrr0110                  */, 2, 0x9206, 0xFE0F, 2, avr_rrrrrcccc_z },
	{ "las", AVR_OP_LAS /*       1001001rrrrr0101                  */, 2, 0x9205, 0xFE0F, 2, avr_rrrrrcccc_z },
	{ "lat", AVR_OP_LAT /*       1001001rrrrr0111                  */, 2, 0x9207, 0xFE0F, 2, avr_rrrrrcccc_z },
	{ "ld", AVR_OP_LD /*         1001000ddddd1100                  */, 2, 0x900C, 0xFE0F, 2, avr_dddddcccc_x },
	{ "ld", AVR_OP_LD /*         1001000ddddd1101                  */, 2, 0x900D, 0xFE0F, 2, avr_dddddcccc_xp },
	{ "ld", AVR_OP_LD /*         1001000ddddd1110                  */, 2, 0x900E, 0xFE0F, 2, avr_dddddcccc_xm },
	{ "ld", AVR_OP_LD /*         1000000ddddd1000                  */, 2, 0x8008, 0xFE0F, 2, avr_dddddcccc_y },
	{ "ld", AVR_OP_LD /*         1001000ddddd1001                  */, 2, 0x9009, 0xFE0F, 2, avr_dddddcccc_yp },
	{ "ld", AVR_OP_LD /*         1001000ddddd1010                  */, 2, 0x900A, 0xFE0F, 2, avr_dddddcccc_ym },
	{ "ldd", AVR_OP_LDD /*       10q0qq0ddddd1qqq                  */, 2, 0x8008, 0xD208, 2, avr_qcqqcdddddcqqq_y },
	{ "ld", AVR_OP_LD /*         1001000ddddd0000                  */, 2, 0x8000, 0xFE0F, 2, avr_dddddcccc_z },
	{ "ld", AVR_OP_LD /*         1001000ddddd0001                  */, 2, 0x9001, 0xFE0F, 2, avr_dddddcccc_zp },
	{ "ld", AVR_OP_LD /*         1001000ddddd0010                  */, 2, 0x9002, 0xFE0F, 2, avr_dddddcccc_zm },
	{ "ldd", AVR_OP_LDD /*       10q0qq0ddddd0qqq                  */, 3, 0x8000, 0xD208, 2, avr_qcqqcdddddcqqq_z },
	{ "ldi", AVR_OP_LDI /*       1110KKKKddddKKKK                  */, 2, 0xE000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "lds", AVR_OP_LDS /*       1001000ddddd0000 kkkkkkkkkkkkkkkk */, 4, 0x9000, 0xFE0F, 4, avr_dddddcccc_load32 },
	{ "lds", AVR_OP_LDS /*       10100kkkddddkkkk                  */, 2, 0xA000, 0xF800, 2, avr_kkkddddkkkk_load16 },
	{ "lpm", AVR_OP_LPM /*       1001010111001000                  */, 2, 0x95C8, 0xFFFF, 2, avr_unique },
	{ "lpm", AVR_OP_LPM /*       1001000ddddd0100                  */, 2, 0x9004, 0xFE0F, 2, avr_dddddcccc_z },
	{ "lpm", AVR_OP_LPM /*       1001000ddddd0101                  */, 2, 0x9005, 0xFE0F, 2, avr_dddddcccc_zp },
	{ "lsr", AVR_OP_LSR /*       1001010ddddd0110                  */, 2, 0x9406, 0xFE0F, 2, avr_dddddcccc },
	{ "mov", AVR_OP_MOV /*       001011rdddddrrrr                  */, 2, 0x2C00, 0xFC00, 2, avr_rdddddrrrr },
	{ "movw", AVR_OP_MOVW /*     00000001ddddrrrr                  */, 2, 0x0100, 0xFF00, 2, avr_ddddrrrr },
	{ "mul", AVR_OP_MUL /*       100111rdddddrrrr                  */, 2, 0x9C00, 0xFC00, 2, avr_rdddddrrrr },
	{ "muls", AVR_OP_MULS /*     00000010ddddrrrr                  */, 2, 0x0200, 0xFF00, 2, avr_ddddrrrr_2x },
	{ "mulsu", AVR_OP_MULSU /*   000000110ddd0rrr                  */, 2, 0x0300, 0xFF88, 2, avr_dddcrrr },
	{ "neg", AVR_OP_NEG /*       1001010ddddd0001                  */, 2, 0x9401, 0xFE0F, 2, avr_dddddcccc },
	{ "nop", AVR_OP_NOP /*       0000000000000000                  */, 2, 0x0000, 0xFFFF, 2, avr_unique },
	{ "or", AVR_OP_OR /*         001010rdddddrrrr                  */, 2, 0x2800, 0xFC00, 2, avr_rdddddrrrr },
	{ "ori", AVR_OP_ORI /*       0110KKKKddddKKKK                  */, 2, 0x6000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "out", AVR_OP_OUT /*       10111AArrrrrAAAA                  */, 2, 0xB800, 0xF800, 2, avr_AArrrrrAAAA },
	{ "pop", AVR_OP_POP /*       1001000ddddd1111                  */, 2, 0x900F, 0xFE0F, 2, avr_dddddcccc },
	{ "push", AVR_OP_PUSH /*     1001001ddddd1111                  */, 2, 0x920F, 0xFE0F, 2, avr_dddddcccc },
	{ "rcall", AVR_OP_RCALL /*   1101kkkkkkkkkkkk                  */, 4, 0xD000, 0xF000, 2, avr_kkkkkkkkkkkk },
	{ "ret", AVR_OP_RET /*       1001010100001000                  */, 2, 0x9508, 0xFFFF, 2, avr_unique },
	{ "reti", AVR_OP_RETI /*     1001010100011000                  */, 2, 0x9518, 0xFFFF, 2, avr_unique },
	{ "rjmp", AVR_OP_RJMP /*     1100kkkkkkkkkkkk                  */, 2, 0xC000, 0xF000, 2, avr_kkkkkkkkkkkk },
	{ "ror", AVR_OP_ROR /*       1001010ddddd0111                  */, 2, 0x9407, 0xFE0F, 2, avr_dddddcccc },
	{ "sbc", AVR_OP_SBC /*       000010rdddddrrrr                  */, 2, 0x0800, 0xFC00, 2, avr_rdddddrrrr },
	{ "sbci", AVR_OP_SBCI /*     0100KKKKddddKKKK                  */, 2, 0x4000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "sbi", AVR_OP_SBI /*       10011010AAAAAbbb                  */, 1, 0x9A00, 0xFF00, 2, avr_AAAAAbbb },
	{ "sbic", AVR_OP_SBIC /*     10011001AAAAAbbb                  */, 1, 0x9900, 0xFF00, 2, avr_AAAAAbbb },
	{ "sbis", AVR_OP_SBIS /*     10011011AAAAAbbb                  */, 1, 0x9B00, 0xFF00, 2, avr_AAAAAbbb },
	{ "sbiw", AVR_OP_SBIW /*     10010111KKddKKKK                  */, 1, 0x9700, 0xFF00, 2, avr_KKddKKKK },
	{ "sbrc", AVR_OP_SBRC /*     1111110rrrrr0bbb                  */, 1, 0xFC00, 0xFE08, 2, avr_rrrrrcbbb },
	{ "sbrs", AVR_OP_SBRS /*     1111111rrrrr0bbb                  */, 1, 0xFE00, 0xFE08, 2, avr_rrrrrcbbb },
	{ "sec", AVR_OP_SEC /*       1001010000001000                  */, 2, 0x9408, 0xFFFF, 2, avr_unique },
	{ "seh", AVR_OP_SEH /*       1001010001011000                  */, 2, 0x9458, 0xFFFF, 2, avr_unique },
	{ "sei", AVR_OP_SEI /*       1001010001111000                  */, 2, 0x9478, 0xFFFF, 2, avr_unique },
	{ "sen", AVR_OP_SEN /*       1001010000101000                  */, 2, 0x9428, 0xFFFF, 2, avr_unique },
	{ "ser", AVR_OP_SER /*       11101111dddd1111                  */, 2, 0xEF0F, 0xFF0F, 2, avr_ddddcccc },
	{ "ses", AVR_OP_SES /*       1001010001001000                  */, 2, 0x9448, 0xFFFF, 2, avr_unique },
	{ "set", AVR_OP_SET /*       1001010001101000                  */, 2, 0x9468, 0xFFFF, 2, avr_unique },
	{ "sev", AVR_OP_SEV /*       1001010000111000                  */, 2, 0x9438, 0xFFFF, 2, avr_unique },
	{ "sez", AVR_OP_SEZ /*       1001010000011000                  */, 2, 0x9418, 0xFFFF, 2, avr_unique },
	{ "sleep", AVR_OP_SLEEP /*   1001010110001000                  */, 2, 0x9588, 0xFFFF, 2, avr_unique },
	{ "spm", AVR_OP_SPM /*       1001010111101000                  */, 1, 0x95E8, 0xFFFF, 2, avr_unique },
	{ "spm", AVR_OP_SPM /*       1001010111111000                  */, 1, 0x95F8, 0xFFFF, 2, avr_spmz },
	{ "st", AVR_OP_ST /*         1001001rrrrr1100                  */, 2, 0x920C, 0xFE0F, 2, avr_rrrrrcccc_x },
	{ "st", AVR_OP_ST /*         1001001rrrrr1101                  */, 2, 0x920D, 0xFE0F, 2, avr_rrrrrcccc_xp },
	{ "st", AVR_OP_ST /*         1001001rrrrr1110                  */, 2, 0x920E, 0xFE0F, 2, avr_rrrrrcccc_xm },
	{ "st", AVR_OP_ST /*         1000001rrrrr1000                  */, 2, 0x8208, 0xFE0F, 2, avr_rrrrrcccc_y },
	{ "st", AVR_OP_ST /*         1001001rrrrr1001                  */, 2, 0x9209, 0xFE0F, 2, avr_rrrrrcccc_yp },
	{ "st", AVR_OP_ST /*         1001001rrrrr1010                  */, 2, 0x920A, 0xFE0F, 2, avr_rrrrrcccc_ym },
	{ "std", AVR_OP_STD /*       10q0qq1rrrrr1qqq                  */, 2, 0x8208, 0xD208, 2, avr_qcqqcrrrrrcqqq_y },
	{ "st", AVR_OP_ST /*         1000001rrrrr0000                  */, 2, 0x8200, 0xFE0F, 2, avr_rrrrrcccc_z },
	{ "st", AVR_OP_ST /*         1001001rrrrr0001                  */, 2, 0x9201, 0xFE0F, 2, avr_rrrrrcccc_zp },
	{ "st", AVR_OP_ST /*         1001001rrrrr0010                  */, 2, 0x9202, 0xFE0F, 2, avr_rrrrrcccc_zm },
	{ "std", AVR_OP_STD /*       10q0qq1rrrrr0qqq                  */, 2, 0x8200, 0xD208, 2, avr_qcqqcrrrrrcqqq_z },
	{ "sts", AVR_OP_STS /*       1001001ddddd0000 kkkkkkkkkkkkkkkk */, 2, 0x9200, 0xFE0F, 4, avr_dddddcccc_store32 },
	{ "sts", AVR_OP_STS /*       10101kkkddddkkkk                  */, 2, 0xA800, 0xF800, 2, avr_kkkddddkkkk_store16 },
	{ "sub", AVR_OP_SUB /*       000110rdddddrrrr                  */, 2, 0x1800, 0xFC00, 2, avr_rdddddrrrr },
	{ "subi", AVR_OP_SUBI /*     0101KKKKddddKKKK                  */, 2, 0x5000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "swap", AVR_OP_SWAP /*     1001010ddddd0010                  */, 2, 0x9402, 0xFE0F, 2, avr_dddddcccc },
	{ "wdr", AVR_OP_WDR /*       1001010110101000                  */, 2, 0x95A8, 0xFFFF, 2, avr_unique },
	{ "xch", AVR_OP_XCH /*       1001001rrrrr0100                  */, 2, 0x9204, 0xFE0F, 2, avr_rrrrrcccc_z }
};
// clang-format on

ut32 avr_disassembler(const ut8 *buffer, const ut32 size, ut64 pc, bool be, AVROp *aop, RzStrBuf *sb) {
	rz_return_val_if_fail(buffer && size && aop && sb, false);
	if (size < 2) {
		return AVR_INVALID_SIZE;
	}

	ut16 masked;
	ut16 data[2] = { 0 };

	data[0] = rz_read_ble16(buffer, be);

	memset(aop, 0, sizeof(AVROp));
	for (ut32 i = 0; i < RZ_ARRAY_SIZE(instructions); ++i) {
		masked = data[0] & instructions[i].mbits;
		if (masked == instructions[i].cbits) {
			if (instructions[i].opsize > 2) {
				if (size < instructions[i].opsize) {
					return AVR_INVALID_SIZE;
				}
				data[1] = be ? rz_read_at_be16(buffer, 2) : rz_read_at_le16(buffer, 2);
			}
			const char *name = instructions[i].name;
			AVROpMnem id = instructions[i].id;
			aop->size = instructions[i].decode(name, id, data, pc, aop, sb);
			aop->mask = instructions[i].mbits;
			return aop->size;
		}
	}
	return AVR_INVALID_SIZE;
}
