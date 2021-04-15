// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "disassembler.h"
#include "common.h"

typedef ut32 (*Decode)(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb);

typedef struct avr_decoder_t {
	cchar* name; /*  instruction name */
	ut16 cbits; /*   constant bits */
	ut16 mbits; /*   mask to compare with constant bits */
	ut32 opsize; /*  instruction size */
	Decode decode;
} AvrInstruction;


static ut32 avr_unique(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	rz_strbuf_set(sb, name);
	return 2;
}


static ut32 avr_rdddddrrrr(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = data[0] & 0x000F;
	ut16 Rd = ((data[0] & 0x01F0) >> 4);
	Rr |= ((data[0] & 0x0200) >> 5);

	if (Rd == Rr) {
		if (!strncmp(name, "adc", 3)) {
			rz_strbuf_setf(sb, "rol r%u", Rd);
		} else if (!strncmp(name, "add", 3)) {
			rz_strbuf_setf(sb, "lsl r%u", Rd);
		} else if (!strncmp(name, "and", 3)) {
			rz_strbuf_setf(sb, "tst r%u", Rd);
		} else if (!strncmp(name, "eor", 3)) {
			rz_strbuf_setf(sb, "clr r%u", Rd);
		} else {
			rz_strbuf_setf(sb, "%s r%u, r%u", name, Rd, Rr);
		}
	} else {
		rz_strbuf_setf(sb, "%s r%u, r%u", name, Rd, Rr);
	}

	return 2;
}


static ut32 avr_KKddKKKK(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 K = data[0] & 0x000F;
	ut16 Rd = 24 + ((data[0] & 0x0030) >> 4);
	K |= ((data[0] & 0x00C0) >> 2);

	rz_strbuf_setf(sb, "%s r%u, 0x%02x", name, Rd, K);
	return 2;
}


static ut32 avr_KKKKddddKKKK(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 K = data[0] & 0x000F;
	ut16 Rd = 16 + ((data[0] & 0x00F0) >> 4);
	K |= ((data[0] & 0x0F00) >> 4);

	if (K == 0xFF && !strncmp(name, "ldi", 3)) {
		rz_strbuf_setf(sb, "ser r%u", Rd);
	} else {
		rz_strbuf_setf(sb, "%s r%u, 0x%02x", name, Rd, K);
	}

	return 2;
}


static ut32 avr_dddddcccc(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u", name, Rd);
	return 2;
}


static ut32 avr_dddddcbbb(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 b = data[0] & 0x0007;
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, %u", name, Rd, b);
	return 2;
}


static ut32 avr_kkkkkkkccc(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
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

	rz_strbuf_setf(sb, "%s 0x%" PFMT64x, name, pc);
	return 2;
}


static ut32 avr_kkkkkccck(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	st32 k = data[0] & 0x0001;
	k |= ((data[0] & 0x01F0) >> 3);
	k <<= 16;
	k |= data[1];
	k *= 2;

	rz_strbuf_setf(sb, "%s 0x%x", name, k);
	return 4;
}


static ut32 avr_AAAAAbbb(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 b = data[0] & 0x0007;
	ut16 A = ((data[0] & 0x00F8) >> 3);

	rz_strbuf_setf(sb, "%s 0x%02x, %u", name, A, b);
	return 2;
}


static ut32 avr_KKKKcccc(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 K = ((data[0] & 0x00F0) >> 4);

	rz_strbuf_setf(sb, "%s 0x%02x", name, K);
	return 2;
}


static ut32 avr_dddddcccc_z(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, Z", name, Rd);
	return 2;
}


static ut32 avr_dddddcccc_zp(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, Z+", name, Rd);
	return 2;
}


static ut32 avr_dddcrrr(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = 16 + (data[0] & 0x0007);
	ut16 Rd = 16 + ((data[0] & 0x0070) >> 4);

	rz_strbuf_setf(sb, "%s r%u, r%u", name, Rd, Rr);
	return 2;
}


static ut32 avr_AAdddddAAAA(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 A = data[0] & 0x000F;
	ut16 Rd = ((data[0] & 0x01F0) >> 4);
	A |= ((data[0] & 0x0600) >> 5);

	rz_strbuf_setf(sb, "%s r%u, 0x%02x", name, Rd, A);
	return 2;
}


static ut32 avr_dddddcccc_x(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, X", name, Rd);
	return 2;
}


static ut32 avr_dddddcccc_xp(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, X+", name, Rd);
	return 2;
}


static ut32 avr_dddddcccc_xm(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, -X", name, Rd);
	return 2;
}


static ut32 avr_dddddcccc_y(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, Y", name, Rd);
	return 2;
}


static ut32 avr_dddddcccc_yp(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, Y+", name, Rd);
	return 2;
}


static ut32 avr_dddddcccc_ym(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, -Y", name, Rd);
	return 2;
}


static ut32 avr_qcqqcdddddcqqq_y(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 q = data[0] & 0x0007;
	ut16 Rd = ((data[0] & 0x01F0) >> 5);
	q |= ((data[0] & 0x0C00) >> 7);
	q |= ((data[0] & 0x2000) >> 8);

	rz_strbuf_setf(sb, "%s r%u, Y+%u", name, Rd, q);
	return 2;
}


static ut32 avr_dddddcccc_zm(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, -Z", name, Rd);
	return 2;
}


static ut32 avr_qcqqcdddddcqqq_z(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 q = data[0] & 0x0007;
	ut16 Rd = ((data[0] & 0x01F0) >> 4);
	q |= ((data[0] & 0x0C00) >> 7);
	q |= ((data[0] & 0x2000) >> 8);

	rz_strbuf_setf(sb, "%s r%u, Z+%u", name, Rd, q);
	return 2;
}


static ut32 avr_dddddcccc_load32(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, 0x%02x", name, Rd, data[1]);
	return 4;
}


static ut32 avr_kkkddddkkkk_load16(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 k = data[0] & 0x000F;
	ut16 Rd = 16 + ((data[0] & 0x00F0) >> 4);
	k |= ((data[0] & 0x0700) >> 4);

	rz_strbuf_setf(sb, "%s r%u, 0x%02x", name, Rd, k);
	return 2;
}


static ut32 avr_ddddrrrr(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = data[0] & 0x000F;
	ut16 Rd = ((data[0] & 0x00F0) >> 4);

	Rr *= 2;
	Rd *= 2;

	rz_strbuf_setf(sb, "%s r%u, r%u", name, Rd, Rr);
	return 2;
}


static ut32 avr_ddddrrrr_2x(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = data[0] & 0x000F;
	ut16 Rd = ((data[0] & 0x00F0) >> 4);
	Rr += 16;
	Rd += 16;

	rz_strbuf_setf(sb, "%s r%u, r%u", name, Rd, Rr);
	return 2;
}


static ut32 avr_AArrrrrAAAA(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 A = data[0] & 0x000F;
	ut16 Rr = ((data[0] & 0x01F0) >> 4);
	A |= ((data[0] & 0x0600) >> 5);

	rz_strbuf_setf(sb, "%s 0x%02x, r%u", name, A, Rr);
	return 2;
}


static ut32 avr_kkkkkkkkkkkk(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
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

	rz_strbuf_setf(sb, "%s 0x%" PFMT64x, name, pc);
	return 2;
}


static ut32 avr_rrrrrcbbb(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 b = data[0] & 0x0007;
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u, %u", name, Rr, b);
	return 2;
}


static ut32 avr_ddddcccc(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = 16 + ((data[0] & 0x00F0) >> 4);

	rz_strbuf_setf(sb, "%s r%u", name, Rd);
	return 2;
}


static ut32 avr_spmz(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%s Z+", name);
	return 2;
}


static ut32 avr_rrrrrcccc_x(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s X, r%u", name, Rr);
	return 2;
}


static ut32 avr_rrrrrcccc_xp(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s X+1, r%u", name, Rr);
	return 2;
}


static ut32 avr_rrrrrcccc_xm(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s -X, r%u", name, Rr);
	return 2;
}


static ut32 avr_rrrrrcccc_y(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s Y, r%u", name, Rr);
	return 2;
}


static ut32 avr_rrrrrcccc_yp(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s Y+1, r%u", name, Rr);
	return 2;
}


static ut32 avr_rrrrrcccc_ym(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s -Y, r%u", name, Rr);
	return 2;
}


static ut32 avr_qcqqcrrrrrcqqq_y(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 q = data[0] & 0x0007;
	ut16 Rr = ((data[0] & 0x01F0) >> 4);
	q |= ((data[0] & 0x0C00) >> 7);
	q |= ((data[0] & 0x2000) >> 8);

	rz_strbuf_setf(sb, "%s Y+%u, r%u", name, q, Rr);
	return 2;
}


static ut32 avr_rrrrrcccc_z(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s Z, r%u", name, Rr);
	return 2;
}


static ut32 avr_rrrrrcccc_zp(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s Z+1, r%u", name, Rr);
	return 2;
}


static ut32 avr_rrrrrcccc_zm(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rr = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s -Z, r%u", name, Rr);
	return 2;
}


static ut32 avr_qcqqcrrrrrcqqq_z(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 q = data[0] & 0x0007;
	ut16 Rr = ((data[0] & 0x01F0) >> 4);
	q |= ((data[0] & 0x0C00) >> 7);
	q |= ((data[0] & 0x2000) >> 8);

	rz_strbuf_setf(sb, "%s Z+%u, r%u", name, q, Rr);
	return 2;
}


static ut32 avr_dddddcccc_store32(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 Rd = ((data[0] & 0x01F0) >> 4);

	rz_strbuf_setf(sb, "%s 0x%02x, r%u", name, data[1], Rd);
	return 4;
}


static ut32 avr_kkkddddkkkk_store16(cchar* name, ut16 data[2], ut64 pc, RzStrBuf *sb) {
	ut16 k = data[0] & 0x000F;
	ut16 Rd = 16 + ((data[0] & 0x00F0) >> 4);
	k |= ((data[0] & 0x0700) >> 4);

	rz_strbuf_setf(sb, "%s 0x%02x, r%u", name, k, Rd);
	return 2;
}



static const AvrInstruction instructions[] = {
	{ "adc" /*    000111rdddddrrrr                  */ , 0x1C00, 0xFC00, 2, avr_rdddddrrrr },
	{ "add" /*    000011rdddddrrrr                  */ , 0x0C00, 0xFC00, 2, avr_rdddddrrrr },
	{ "adiw" /*   10010110KKddKKKK                  */ , 0x9600, 0xFF00, 2, avr_KKddKKKK },
	{ "and" /*    001000rdddddrrrr                  */ , 0x2000, 0xFC00, 2, avr_rdddddrrrr },
	{ "andi" /*   0111KKKKddddKKKK                  */ , 0x7000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "asr" /*    1001010ddddd0101                  */ , 0x9405, 0xFE0F, 2, avr_dddddcccc },
	{ "bld" /*    1111100ddddd0bbb                  */ , 0xF800, 0xFE08, 2, avr_dddddcbbb },
	{ "brcc" /*   111101kkkkkkk000                  */ , 0xF400, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brcs" /*   111100kkkkkkk000                  */ , 0xF000, 0xFC07, 2, avr_kkkkkkkccc },
	{ "break" /*  1001010110011000                  */ , 0x9598, 0xFFFF, 2, avr_unique },
	{ "breq" /*   111100kkkkkkk001                  */ , 0xF001, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brge" /*   111101kkkkkkk100                  */ , 0xF404, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brhc" /*   111101kkkkkkk101                  */ , 0xF405, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brhs" /*   111100kkkkkkk101                  */ , 0xF005, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brid" /*   111101kkkkkkk111                  */ , 0xF407, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brie" /*   111100kkkkkkk111                  */ , 0xF007, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brlo" /*   111100kkkkkkk000                  */ , 0xF000, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brlt" /*   111100kkkkkkk100                  */ , 0xF004, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brmi" /*   111100kkkkkkk010                  */ , 0xF002, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brne" /*   111101kkkkkkk001                  */ , 0xF401, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brpl" /*   111101kkkkkkk010                  */ , 0xF402, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brsh" /*   111101kkkkkkk000                  */ , 0xF400, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brtc" /*   111101kkkkkkk110                  */ , 0xF406, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brts" /*   111100kkkkkkk110                  */ , 0xF006, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brvc" /*   111101kkkkkkk011                  */ , 0xF403, 0xFC07, 2, avr_kkkkkkkccc },
	{ "brvs" /*   111100kkkkkkk011                  */ , 0xF003, 0xFC07, 2, avr_kkkkkkkccc },
	{ "bst" /*    1111101ddddd0bbb                  */ , 0xFA00, 0xFE08, 2, avr_dddddcbbb },
	{ "call" /*   1001010kkkkk111k kkkkkkkkkkkkkkkk */ , 0x940E, 0xFE0E, 4, avr_kkkkkccck },
	{ "cbi" /*    10011000AAAAAbbb                  */ , 0x9800, 0xFF00, 2, avr_AAAAAbbb },
	{ "clc" /*    1001010010001000                  */ , 0x9488, 0xFFFF, 2, avr_unique },
	{ "clh" /*    1001010011011000                  */ , 0x94D8, 0xFFFF, 2, avr_unique },
	{ "cli" /*    1001010011111000                  */ , 0x94F8, 0xFFFF, 2, avr_unique },
	{ "cln" /*    1001010010101000                  */ , 0x94A8, 0xFFFF, 2, avr_unique },
	{ "cls" /*    1001010011001000                  */ , 0x94C8, 0xFFFF, 2, avr_unique },
	{ "clt" /*    1001010011101000                  */ , 0x94E8, 0xFFFF, 2, avr_unique },
	{ "clv" /*    1001010010111000                  */ , 0x94B8, 0xFFFF, 2, avr_unique },
	{ "clz" /*    1001010010011000                  */ , 0x9498, 0xFFFF, 2, avr_unique },
	{ "com" /*    1001010ddddd0000                  */ , 0x9400, 0xFE0F, 2, avr_dddddcccc },
	{ "cp" /*     000101rdddddrrrr                  */ , 0x1400, 0xFC00, 2, avr_rdddddrrrr },
	{ "cpc" /*    000001rdddddrrrr                  */ , 0x0400, 0xFC00, 2, avr_rdddddrrrr },
	{ "cpi" /*    0011KKKKddddKKKK                  */ , 0x3000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "cpse" /*   000100rdddddrrrr                  */ , 0x1000, 0xFC00, 2, avr_rdddddrrrr },
	{ "dec" /*    1001010ddddd1010                  */ , 0x940A, 0xFE0F, 2, avr_dddddcccc },
	{ "des" /*    10010100KKKK1011                  */ , 0x940B, 0xFF0F, 2, avr_KKKKcccc },
	{ "eicall" /* 1001010100011001                  */ , 0x9519, 0xFFFF, 2, avr_unique },
	{ "eijmp" /*  1001010000011001                  */ , 0x9419, 0xFFFF, 2, avr_unique },
	{ "elpm" /*   1001010111011000                  */ , 0x95D8, 0xFFFF, 2, avr_unique },
	{ "elpm" /*   1001000ddddd0110                  */ , 0x9006, 0xFE0F, 2, avr_dddddcccc_z },
	{ "elpm" /*   1001000ddddd0111                  */ , 0x9007, 0xFE0F, 2, avr_dddddcccc_zp },
	{ "eor" /*    001001rdddddrrrr                  */ , 0x2400, 0xFC00, 2, avr_rdddddrrrr },
	{ "fmul" /*   000000110ddd1rrr                  */ , 0x0308, 0xFF88, 2, avr_dddcrrr },
	{ "fmuls" /*  000000111ddd0rrr                  */ , 0x0380, 0xFF88, 2, avr_dddcrrr },
	{ "fmulsu" /* 000000111ddd1rrr                  */ , 0x0388, 0xFF88, 2, avr_dddcrrr },
	{ "icall" /*  1001010100001001                  */ , 0x9509, 0xFFFF, 2, avr_unique },
	{ "ijmp" /*   1001010000001001                  */ , 0x9409, 0xFFFF, 2, avr_unique },
	{ "in" /*     10110AAdddddAAAA                  */ , 0xB000, 0xF800, 2, avr_AAdddddAAAA },
	{ "inc" /*    1001010ddddd0011                  */ , 0x9403, 0xFE0F, 2, avr_dddddcccc },
	{ "jmp" /*    1001010kkkkk110k kkkkkkkkkkkkkkkk */ , 0x940C, 0xFE0E, 4, avr_kkkkkccck },
	{ "lac" /*    1001001rrrrr0110                  */ , 0x9206, 0xFE0F, 2, avr_rrrrrcccc_z },
	{ "las" /*    1001001rrrrr0101                  */ , 0x9205, 0xFE0F, 2, avr_rrrrrcccc_z },
	{ "lat" /*    1001001rrrrr0111                  */ , 0x9207, 0xFE0F, 2, avr_rrrrrcccc_z },
	{ "ld" /*     1001000ddddd1100                  */ , 0x900C, 0xFE0F, 2, avr_dddddcccc_x },
	{ "ld" /*     1001000ddddd1101                  */ , 0x900D, 0xFE0F, 2, avr_dddddcccc_xp },
	{ "ld" /*     1001000ddddd1110                  */ , 0x900E, 0xFE0F, 2, avr_dddddcccc_xm },
	{ "ld" /*     1000000ddddd1000                  */ , 0x8008, 0xFE0F, 2, avr_dddddcccc_y },
	{ "ld" /*     1001000ddddd1001                  */ , 0x9009, 0xFE0F, 2, avr_dddddcccc_yp },
	{ "ld" /*     1001000ddddd1010                  */ , 0x900A, 0xFE0F, 2, avr_dddddcccc_ym },
	{ "ldd" /*    10q0qq0ddddd1qqq                  */ , 0x8008, 0xD208, 2, avr_qcqqcdddddcqqq_y },
	{ "ld" /*     1001000ddddd0000                  */ , 0x8000, 0xFE0F, 2, avr_dddddcccc_z },
	{ "ld" /*     1001000ddddd0001                  */ , 0x9001, 0xFE0F, 2, avr_dddddcccc_zp },
	{ "ld" /*     1001000ddddd0010                  */ , 0x9002, 0xFE0F, 2, avr_dddddcccc_zm },
	{ "ldd" /*    10q0qq0ddddd0qqq                  */ , 0x8000, 0xD208, 2, avr_qcqqcdddddcqqq_z },
	{ "ldi" /*    1110KKKKddddKKKK                  */ , 0xE000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "lds" /*    1001000ddddd0000 kkkkkkkkkkkkkkkk */ , 0x9000, 0xFE0F, 4, avr_dddddcccc_load32 },
	{ "lds" /*    10100kkkddddkkkk                  */ , 0xA000, 0xF800, 2, avr_kkkddddkkkk_load16 },
	{ "lpm" /*    1001010111001000                  */ , 0x95C8, 0xFFFF, 2, avr_unique },
	{ "lpm" /*    1001000ddddd0100                  */ , 0x9004, 0xFE0F, 2, avr_dddddcccc_z },
	{ "lpm" /*    1001000ddddd0101                  */ , 0x9005, 0xFE0F, 2, avr_dddddcccc_zp },
	{ "lsr" /*    1001010ddddd0110                  */ , 0x9406, 0xFE0F, 2, avr_dddddcccc },
	{ "mov" /*    001011rdddddrrrr                  */ , 0x2C00, 0xFC00, 2, avr_rdddddrrrr },
	{ "movw" /*   00000001ddddrrrr                  */ , 0x0100, 0xFF00, 2, avr_ddddrrrr },
	{ "mul" /*    100111rdddddrrrr                  */ , 0x9C00, 0xFC00, 2, avr_rdddddrrrr },
	{ "muls" /*   00000010ddddrrrr                  */ , 0x0200, 0xFF00, 2, avr_ddddrrrr_2x },
	{ "mulsu" /*  000000110ddd0rrr                  */ , 0x0300, 0xFF88, 2, avr_dddcrrr },
	{ "neg" /*    1001010ddddd0001                  */ , 0x9401, 0xFE0F, 2, avr_dddddcccc },
	{ "nop" /*    0000000000000000                  */ , 0x0000, 0xFFFF, 2, avr_unique },
	{ "or" /*     001010rdddddrrrr                  */ , 0x2800, 0xFC00, 2, avr_rdddddrrrr },
	{ "ori" /*    0110KKKKddddKKKK                  */ , 0x6000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "out" /*    10111AArrrrrAAAA                  */ , 0xB800, 0xF800, 2, avr_AArrrrrAAAA },
	{ "pop" /*    1001000ddddd1111                  */ , 0x900F, 0xFE0F, 2, avr_dddddcccc },
	{ "push" /*   1001001ddddd1111                  */ , 0x920F, 0xFE0F, 2, avr_dddddcccc },
	{ "rcall" /*  1101kkkkkkkkkkkk                  */ , 0xD000, 0xF000, 2, avr_kkkkkkkkkkkk },
	{ "ret" /*    1001010100001000                  */ , 0x9508, 0xFFFF, 2, avr_unique },
	{ "reti" /*   1001010100011000                  */ , 0x9518, 0xFFFF, 2, avr_unique },
	{ "rjmp" /*   1100kkkkkkkkkkkk                  */ , 0xC000, 0xF000, 2, avr_kkkkkkkkkkkk },
	{ "ror" /*    1001010ddddd0111                  */ , 0x9407, 0xFE0F, 2, avr_dddddcccc },
	{ "sbc" /*    000010rdddddrrrr                  */ , 0x0800, 0xFC00, 2, avr_rdddddrrrr },
	{ "sbci" /*   0100KKKKddddKKKK                  */ , 0x4000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "sbi" /*    10011010AAAAAbbb                  */ , 0x9A00, 0xFF00, 2, avr_AAAAAbbb },
	{ "sbic" /*   10011001AAAAAbbb                  */ , 0x9900, 0xFF00, 2, avr_AAAAAbbb },
	{ "sbis" /*   10011011AAAAAbbb                  */ , 0x9B00, 0xFF00, 2, avr_AAAAAbbb },
	{ "sbiw" /*   10010111KKddKKKK                  */ , 0x9700, 0xFF00, 2, avr_KKddKKKK },
	{ "sbrc" /*   1111110rrrrr0bbb                  */ , 0xFC00, 0xFE08, 2, avr_rrrrrcbbb },
	{ "sbrs" /*   1111111rrrrr0bbb                  */ , 0xFE00, 0xFE08, 2, avr_rrrrrcbbb },
	{ "sec" /*    1001010000001000                  */ , 0x9408, 0xFFFF, 2, avr_unique },
	{ "seh" /*    1001010001011000                  */ , 0x9458, 0xFFFF, 2, avr_unique },
	{ "sei" /*    1001010001111000                  */ , 0x9478, 0xFFFF, 2, avr_unique },
	{ "sen" /*    1001010000101000                  */ , 0x9428, 0xFFFF, 2, avr_unique },
	{ "ser" /*    11101111dddd1111                  */ , 0xEF0F, 0xFF0F, 2, avr_ddddcccc },
	{ "ses" /*    1001010001001000                  */ , 0x9448, 0xFFFF, 2, avr_unique },
	{ "set" /*    1001010001101000                  */ , 0x9468, 0xFFFF, 2, avr_unique },
	{ "sev" /*    1001010000111000                  */ , 0x9438, 0xFFFF, 2, avr_unique },
	{ "sez" /*    1001010000011000                  */ , 0x9418, 0xFFFF, 2, avr_unique },
	{ "sleep" /*  1001010110001000                  */ , 0x9588, 0xFFFF, 2, avr_unique },
	{ "spm" /*    1001010111101000                  */ , 0x95E8, 0xFFFF, 2, avr_unique },
	{ "spm" /*    1001010111111000                  */ , 0x95F8, 0xFFFF, 2, avr_spmz },
	{ "st" /*     1001001rrrrr1100                  */ , 0x920C, 0xFE0F, 2, avr_rrrrrcccc_x },
	{ "st" /*     1001001rrrrr1101                  */ , 0x920D, 0xFE0F, 2, avr_rrrrrcccc_xp },
	{ "st" /*     1001001rrrrr1110                  */ , 0x920E, 0xFE0F, 2, avr_rrrrrcccc_xm },
	{ "st" /*     1000001rrrrr1000                  */ , 0x8208, 0xFE0F, 2, avr_rrrrrcccc_y },
	{ "st" /*     1001001rrrrr1001                  */ , 0x9209, 0xFE0F, 2, avr_rrrrrcccc_yp },
	{ "st" /*     1001001rrrrr1010                  */ , 0x920A, 0xFE0F, 2, avr_rrrrrcccc_ym },
	{ "std" /*    10q0qq1rrrrr1qqq                  */ , 0x8208, 0xD208, 2, avr_qcqqcrrrrrcqqq_y },
	{ "st" /*     1000001rrrrr0000                  */ , 0x8200, 0xFE0F, 2, avr_rrrrrcccc_z },
	{ "st" /*     1001001rrrrr0001                  */ , 0x9201, 0xFE0F, 2, avr_rrrrrcccc_zp },
	{ "st" /*     1001001rrrrr0010                  */ , 0x9202, 0xFE0F, 2, avr_rrrrrcccc_zm },
	{ "std" /*    10q0qq1rrrrr0qqq                  */ , 0x8200, 0xD208, 2, avr_qcqqcrrrrrcqqq_z },
	{ "sts" /*    1001001ddddd0000 kkkkkkkkkkkkkkkk */ , 0x9200, 0xFE0F, 4, avr_dddddcccc_store32 },
	{ "sts" /*    10101kkkddddkkkk                  */ , 0xA800, 0xF800, 2, avr_kkkddddkkkk_store16 },
	{ "sub" /*    000110rdddddrrrr                  */ , 0x1800, 0xFC00, 2, avr_rdddddrrrr },
	{ "subi" /*   0101KKKKddddKKKK                  */ , 0x5000, 0xF000, 2, avr_KKKKddddKKKK },
	{ "swap" /*   1001010ddddd0010                  */ , 0x9402, 0xFE0F, 2, avr_dddddcccc },
	{ "wdr" /*    1001010110101000                  */ , 0x95A8, 0xFFFF, 2, avr_unique },
	{ "xch" /*    1001001rrrrr0100                  */ , 0x9204, 0xFE0F, 2, avr_rrrrrcccc_z }
};

ut32 avr_disassembler(const ut8 *buffer, const ut32 size, ut64 pc, bool be, RzStrBuf *sb) {
	rz_return_val_if_fail(buffer && size > 1 && sb, false);

	ut16 masked;
	ut16 data[2] = {0};
	data[0] = be ? rz_read_be16(buffer) : rz_read_le16(buffer);

	for (ut32 i = 0; i < RZ_ARRAY_SIZE(instructions); ++i) {
		masked = data[0] & instructions[i].mbits;
		if (masked == instructions[i].cbits) {
			if (instructions[i].opsize > 2) {
				if (size < instructions[i].opsize) {
					return AVR_INVALID_SIZE;
				}
				data[1] = be ? rz_read_at_be16(buffer, 2) : rz_read_at_le16(buffer, 2);
			}
			return instructions[i].decode(instructions[i].name, data, pc, sb);
		}
	}
	return AVR_INVALID_SIZE;
}
