// SPDX-FileCopyrightText: 2012-2015 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2015 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2012-2015 Bhootravi <ravi2809@gmail.com>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <h8300/h8300_disas.h>

#define emit(frag) rz_strbuf_appendf(&op->esil, frag)
#define emitf(...) rz_strbuf_appendf(&op->esil, __VA_ARGS__)
// setting the appropriate flags, NOTE: semicolon included
#define setZ      rz_strbuf_appendf(&op->esil, ",$z,Z,:=") // zero flag
#define setN      rz_strbuf_appendf(&op->esil, ",15,$s,N,=") // negative(sign) flag
#define setV(val) rz_strbuf_appendf(&op->esil, ",%s,V,=", val) // overflow flag
#define setC_B    rz_strbuf_appendf(&op->esil, ",7,$c,C,:=") // carry flag for byte op
#define setC_W    rz_strbuf_appendf(&op->esil, ",15,$c,C,:=") // carryflag for word op
#define setCb_B   rz_strbuf_appendf(&op->esil, ",7,$b,C,:=") // borrow flag for byte
#define setCb_W   rz_strbuf_appendf(&op->esil, ",15,$b,C,:=") // borrow flag for word
#define setH_B    rz_strbuf_appendf(&op->esil, ",3,$c,H,:=") // half carry(byte)-bcd
#define setH_W    rz_strbuf_appendf(&op->esil, ",11,$c,H,:=") // half carry(word)-bcd
#define setHb_B   rz_strbuf_appendf(&op->esil, ",3,$b,H,:=") // half borrow(byte)-bcd
#define setHb_W   rz_strbuf_appendf(&op->esil, ",11,$b,H,:=") // halfborrow(word)-bcd

// get reg. from opcodes
#define rs()  (buf[1] & 0x70) >> 4 // upper nibble used as source generally
#define rsB() (buf[1] & 0x70) >> 4, buf[1] & 0x80 ? 'l' : 'h' // msb of nibble used for l/h
#define rd()  buf[1] & 0x07 // lower nibble used as dest generally
// a for compact instrs. (some instrs. have rd in 1st byte, others in 2nd byte)
#define rdB(a) buf[a] & 0x07, buf[a] & 0x8 ? 'l' : 'h'
// work around for z flag
// internally r=0xff on incr. stored as 0x100, which doesn't raise the z flag
// NOTE - use the mask and setZ at last, mask will affect other flags
#define mask()   rz_strbuf_appendf(&op->esil, ",0xffff,r%u,&=", rd());
#define maskB(a) rz_strbuf_appendf(&op->esil, ",0xff,r%u%c,&=", rdB(a));

// immediate values are always 2nd byte
#define imm buf[1]
/*
 * Reference Manual:
 *
https://www.classes.cs.uchicago.edu/archive/2006/winter/23000-1/docs/h8300.pdf
 */

int h8300_analyze_op_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf) {
	int ret = -1;
	ut8 opcode = buf[0];
	if (!op) {
		return 2;
	}
	rz_strbuf_init(&op->esil);
	rz_strbuf_set(&op->esil, "");
	switch (opcode >> 4) {
	case H8300_CMP_4BIT:
		// acc. to manual this is how it's done, could use == in esil
		rz_strbuf_appendf(&op->esil, "0x%02x,r%u%c,-", imm, rdB(0));
		// setZ
		setV("%o");
		setN;
		setHb_B;
		setCb_B;
		maskB(0);
		setZ;
		return 0;
	case H8300_OR_4BIT:
		rz_strbuf_appendf(&op->esil, "0x%02x,r%u%c,|=", imm, rdB(0));
		// setZ
		setV("0");
		setN;
		maskB(0);
		setZ;
		return 0;
	case H8300_XOR_4BIT:
		rz_strbuf_appendf(&op->esil, "0x%02x,r%u%c,^=", imm, rdB(0));
		// setZ
		setN;
		setV("0");
		maskB(0);
		setZ;
		return 0;
	case H8300_AND_4BIT:
		rz_strbuf_appendf(&op->esil, "0x%02x,r%u%c,&=", imm, rdB(0));
		// setZ
		setN;
		setV("0");
		maskB(0);
		setZ;
		return 0;
	case H8300_ADD_4BIT_8:
		rz_strbuf_appendf(&op->esil, "0x%02x,r%u%c,+=", imm, rdB(0));
		// setZ
		setV("%o");
		setN;
		setH_B;
		setC_B;
		maskB(0);
		setZ;
		return 0;
	case H8300_ADDX_4BIT:
		rz_strbuf_appendf(&op->esil, "0x%02x,C,+,r%u%c,+= ", imm, rdB(0));
		// setZ
		setV("%o");
		setN;
		setH_B;
		setC_B;
		maskB(0);
		setZ;
		return 0;
	case H8300_SUBX_4BIT:
		// Rd – imm – C → Rd
		rz_strbuf_appendf(&op->esil, "0x%02x,r%u%c,-=,C,r%u%c,-=", imm, rdB(0), rdB(0));
		// setZ
		setV("%o");
		setN;
		setHb_B;
		setCb_B;
		maskB(0);
		setZ;
		return 0;
	case H8300_MOV_4BIT_2: /*TODO*/
	case H8300_MOV_4BIT_3: /*TODO*/
	case H8300_MOV_4BIT: /*TODO*/
		return 0;
	default:
		break;
	};

	switch (opcode) {
	case H8300_NOP:
		rz_strbuf_set(&op->esil, ",");
		return 0;
	case H8300_SLEEP: /* TODO */
		return 0;
	case H8300_STC_B:
		rz_strbuf_appendf(&op->esil, "ccr,r%u%c,=", rdB(1));
		return 0;
	case H8300_LDC:
		rz_strbuf_appendf(&op->esil, "r%u%c,ccr,=", rdB(1));
		return 0;
	case H8300_ORC:
		rz_strbuf_appendf(&op->esil, "0x%02x,ccr,|=", imm);
		return 0;
	case H8300_XORC:
		rz_strbuf_appendf(&op->esil, "0x%02x,ccr,^=", imm);
		return 0;
	case H8300_ANDC:
		rz_strbuf_appendf(&op->esil, "0x%02x,ccr,&=", imm);
		return 0;
	case H8300_LDC_2:
		rz_strbuf_appendf(&op->esil, "0x%02x,ccr,=", imm);
		return 0;
	case H8300_ADD_B:
		rz_strbuf_appendf(&op->esil, "r%u%c,r%u%c,+=", rsB(), rdB(1));
		setH_B;
		setV("%o");
		setC_B;
		setN;
		// setZ;
		maskB(1);
		setZ;
		return 0;
	case H8300_ADD_W:
		rz_strbuf_appendf(&op->esil, "r%u,r%u,+=", rs(), rd());
		setH_W;
		setV("%o");
		setC_W;
		setN;
		mask();
		setZ;
		return 0;
	case H8300_INC:
		rz_strbuf_appendf(&op->esil, "1,r%u%c,+=", rdB(1));
		// setZ
		setV("%o");
		setN;
		maskB(1);
		setZ;
		return 0;
	case H8300_ADDS:
		rz_strbuf_appendf(&op->esil, "%d,r%u,+=",
			((buf[1] & 0xf0) == 0x80) ? 2 : 1, rd());
		return 0;
	case H8300_MOV_1:
		/*TODO check if flags are set internally or not*/
		rz_strbuf_appendf(&op->esil, "r%u%c,r%u%c,=", rsB(), rdB(1));
		// setZ
		setN;
		maskB(1);
		setZ;
		return 0;
	case H8300_MOV_2:
		rz_strbuf_appendf(&op->esil, "r%u,r%u,=", rs(), rd());
		// setZ
		setN;
		mask();
		setZ;
		return 0;
	case H8300_ADDX:
		// Rd + (Rs) + C → Rd
		rz_strbuf_appendf(&op->esil, "r%u%c,C,+,r%u%c,+=",
			rsB(), rdB(1));
		// setZ
		setV("%o");
		setN;
		setH_B;
		setC_B;
		maskB(1);
		setZ;
		return 0;
	case H8300_DAA: /*TODO*/
		return 0;
	case H8300_SHL: /*TODO*/
		return 0;
	case H8300_SHR: /*TODO*/
		return 0;
	case H8300_ROTL: /*TODO*/
		return 0;
	case H8300_ROTR: /*TODO*/
		return 0;
	case H8300_OR:
		rz_strbuf_appendf(&op->esil, "r%u%c,r%u%c,|=", rsB(), rdB(1));
		// setZ
		setV("0");
		setN;
		maskB(1);
		setZ;
		return 0;
	case H8300_XOR:
		rz_strbuf_appendf(&op->esil, "r%u%c,r%u%c,^=", rsB(), rdB(1));
		// setZ
		setV("0");
		setN;
		maskB(1);
		setZ;
		return 0;
	case H8300_AND:
		rz_strbuf_appendf(&op->esil, "r%u%c,r%u%c,&=", rsB(), rdB(1));
		// setZ
		setV("0");
		setN;
		maskB(1);
		setZ;
		return 0;
	case H8300_NOT_NEG:
		if ((buf[1] & 0xf0) == 0x80) { // NEG
			rz_strbuf_appendf(&op->esil, "r%u%c,0,-,r%u%c,=", rdB(1), rdB(1));
			// setZ
			setHb_B;
			setV("%o");
			setCb_B;
			setN;
			maskB(1);
			setZ;
		} else if ((buf[1] & 0xf0) == 0x00) { // NOT
			rz_strbuf_appendf(&op->esil, "r%u%c,!=", rdB(1));
			// setZ
			setV("0");
			setN;
			maskB(1);
			setZ;
		}
		return 0;
	case H8300_SUB_1:
		rz_strbuf_appendf(&op->esil, "r%u%c,r%u%c,-=", rsB(), rdB(1));
		// setZ
		setHb_B;
		setV("%o");
		setCb_B;
		setN;
		maskB(1);
		setZ;
		return 0;
	case H8300_SUB_W:
		rz_strbuf_appendf(&op->esil, "r%u,r%u,-=", rs(), rd());
		setHb_W;
		setV("%o");
		setCb_W;
		setN;
		mask();
		setZ;
		return 0;
	case H8300_DEC:
		rz_strbuf_appendf(&op->esil, "1,r%u%c,-=", rdB(1));
		// setZ
		setV("%o");
		setN;
		maskB(1);
		setZ;
		return 0;
	case H8300_SUBS:
		rz_strbuf_appendf(&op->esil, "%d,r%u,-=",
			((buf[1] & 0xf0) == 0x80) ? 2 : 1, rd());
		return 0;
	case H8300_CMP_B:
		rz_strbuf_appendf(&op->esil, "r%u%c,r%u%c,-", rsB(), rdB(1));
		// setZ
		setHb_B;
		setV("%o");
		setCb_B;
		setN;
		maskB(1);
		setZ;
		return 0;
	case H8300_CMP_W:
		rz_strbuf_appendf(&op->esil, "r%u,r%u,-", rs(), rd());
		// setZ
		setHb_W;
		setV("%o");
		setCb_W;
		setN;
		mask();
		setZ;
		return 0;
	case H8300_SUBX:
		// Rd – (Rs) – C → Rd
		rz_strbuf_appendf(&op->esil, "r%u%c,r%u%c,-=,C,r%u%c,-=",
			rsB(), rdB(1), rdB(1));
		// setZ
		setHb_B;
		setV("%o");
		setCb_B;
		setN;
		maskB(1);
		setZ;
		return 0;
	case H8300_DAS: /*TODO*/
		return 0;
	case H8300_BRA:
		rz_strbuf_appendf(&op->esil, "0x%02x,pc,+=", buf[1]);
		return 0;
	case H8300_BRN:
		rz_strbuf_appendf(&op->esil, ",");
		return 0;
	case H8300_BHI:
		rz_strbuf_appendf(&op->esil, "C,Z,|,!,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BLS:
		rz_strbuf_appendf(&op->esil, "C,Z,|,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BCC:
		rz_strbuf_appendf(&op->esil, "C,!,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BCS:
		rz_strbuf_appendf(&op->esil, "C,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BNE:
		rz_strbuf_appendf(&op->esil, "Z,!,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BEQ:
		rz_strbuf_appendf(&op->esil, "Z,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BVC:
		rz_strbuf_appendf(&op->esil, "V,!,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BVS:
		rz_strbuf_appendf(&op->esil, "V,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BPL:
		rz_strbuf_appendf(&op->esil, "N,!,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BMI:
		rz_strbuf_appendf(&op->esil, "N,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BGE:
		rz_strbuf_appendf(&op->esil, "N,V,^,!,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BLT:
		rz_strbuf_appendf(&op->esil, "N,V,^,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BGT:
		rz_strbuf_appendf(&op->esil, "Z,N,V,^,|,!,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_BLE:
		rz_strbuf_appendf(&op->esil, "Z,N,V,^,|,?{0x%02x,pc,+=}", buf[1]);
		return 0;
	case H8300_MULXU_B:
		// Refer to pg. 100 of the manual linked at the beginning
		rz_strbuf_appendf(&op->esil, "r%u%c,r%ul,*,r%u,=",
			rsB(), rd(), rd());
		return 0;
	case H8300_DIVXU: /*TODO*/ return 0;
	case H8300_RTS: /*TODO*/ return 0;
	case H8300_BSR: /*TODO*/ return 0;
	case H8300_RTE: /*TODO*/ return 0;
	case H8300_JMP_1: /*TODO*/ return 0;
	case H8300_JMP_2: /*TODO*/ return 0;
	case H8300_JMP_3: /*TODO*/ return 0;
	case H8300_JSR_1: /*TODO*/ return 0;
	case H8300_JSR_2: /*TODO*/ return 0;
	case H8300_JSR_3: /*TODO*/
		return 0;
		// NOTE - cases marked with TODO have mem. access also(not impl.)
	case H8300_BSET_1: /*TODO*/
		// set rs&0x7th bit of rd. expr.- rd|= 1<<(rs&0x07)
		rz_strbuf_appendf(&op->esil, "0x7,r%u%c,&,1,<<,r%u%c,|=", rsB(), rdB(1));
		return 0;
	case H8300_BNOT_1: /*TODO*/
		// invert rs&0x7th bit of rd. expr.- rd^= 1<<(rs&0x07)
		rz_strbuf_appendf(&op->esil, "0x07,r%u%c,&,1,<<,r%u%c,^=", rsB(), rdB(1));
		return 0;
	case H8300_BCLR_R2R8: /*TODO*/
		// clear rs&0x7th bit of rd. expr.- rd&= !(1<<(rs&0x07))
		rz_strbuf_appendf(&op->esil, "0x7,r%u%c,&,1,<<,!,r%u%c,&=", rsB(), rdB(1));
		return 0;
	case H8300_BTST_R2R8: /*TODO*/
		// ¬ (<Bit No.> of <EAd>) → Z, extract bit value and shift it back
		rz_strbuf_appendf(&op->esil, "0x7,r%u%c,&,0x7,r%u%c,&,1,<<,r%u%c,&,>>,!,Z,=",
			rsB(), rsB(), rdB(1));
		return 0;
	case H8300_BST_BIST: /*TODO*/
		if (!(buf[1] & 0x80)) { // BST
			rz_strbuf_appendf(&op->esil, "%d,C,<<,r%u%c,|=", rs(), rdB(1));
		} else { // BIST
			rz_strbuf_appendf(&op->esil, "%d,C,!,<<,r%u%c,|=", rs(), rdB(1));
		}
		return 0;
	case H8300_MOV_R82IND16: /*TODO*/ return 0;
	case H8300_MOV_IND162R16: /*TODO*/ return 0;
	case H8300_MOV_R82ABS16: /*TODO*/ return 0;
	case H8300_MOV_ABS162R16: /*TODO*/ return 0;
	case H8300_MOV_R82RDEC16: /*TODO*/ return 0;
	case H8300_MOV_INDINC162R16: /*TODO*/ return 0;
	case H8300_MOV_R82DISPR16: /*TODO*/ return 0;
	case H8300_MOV_DISP162R16: /*TODO*/
		return 0;
	case H8300_BSET_2: /*TODO*/
		// set imm bit of rd. expr.- rd|= (1<<imm)
		rz_strbuf_appendf(&op->esil, "%d,1,<<,r%u%c,|=", rs(), rdB(1));
		return 0;
	case H8300_BNOT_2: /*TODO*/
		// inv. imm bit of rd. expr.- rd^= (1<<imm)
		rz_strbuf_appendf(&op->esil, "%d,1,<<,r%u%c,^=", rs(), rdB(1));
		return 0;
	case H8300_BCLR_IMM2R8:
		// clear imm bit of rd. expr.- rd&= !(1<<imm)
		rz_strbuf_appendf(&op->esil, "%d,1,<<,!,r%u%c,&=", rs(), rdB(1));
		return 0;
	case H8300_BTST: /*TODO*/
		// see BTST above
		rz_strbuf_appendf(&op->esil, "%d,%d,1,<<,r%u%c,&,>>,!,Z,=",
			rs(), rs(), rdB(1));
		return 0;
	case H8300_BOR_BIOR: /*TODO*/
		if (!(buf[1] & 0x80)) { // BOR
			// C|=(rd&(1<<imm))>>imm
			rz_strbuf_appendf(&op->esil, "%d,%d,1,<<,r%u%c,&,>>,C,|=",
				rs(), rs(), rdB(1));
		} else { // BIOR
			// C|=!(rd&(1<<imm))>>imm
			rz_strbuf_appendf(&op->esil, "%d,%d,1,<<,r%u%c,&,>>,!,C,|=",
				rs(), rs(), rdB(1));
		}
		return 0;
	case H8300_BXOR_BIXOR: /*TODO*/
		if (!(buf[1] & 0x80)) { // BXOR
			// C^=(rd&(1<<imm))>>imm
			rz_strbuf_appendf(&op->esil, "%d,%d,1,<<,r%u%c,&,>>,C,^=",
				rs(), rs(), rdB(1));
		} else { // BIXOR
			rz_strbuf_appendf(&op->esil, "%d,%d,1,<<,r%u%c,&,>>,!,C,^=",
				rs(), rs(), rdB(1));
		}
		return 0;
	case H8300_BAND_BIAND:
		/*TODO check functionality*/
		// C&=(rd&(1<<imm))>>imm
		if (!(buf[1] & 0x80)) { // BAND
			rz_strbuf_appendf(&op->esil, "%d,%d,1,<<,r%u%c,&,>>,C,&=",
				rs(), rs(), rdB(1));
		} else { // BIAND
			rz_strbuf_appendf(&op->esil, "%d,%d,1,<<,r%u%c,&,>>,!,C,&=",
				rs(), rs(), rdB(1));
		}
		return 0;
	case H8300_BILD_IMM2R8:
		/*TODO*/
		if (!(buf[1] & 0x80)) { // BLD
			rz_strbuf_appendf(&op->esil, "%d,%d,1,<<,r%u%c,&,>>,C,=",
				rs(), rs(), rdB(1));
		} else { // BILD
			rz_strbuf_appendf(&op->esil, "%d,%d,1,<<,r%u%c,&,>>,!,C,=",
				rs(), rs(), rdB(1));
		}
		return 0;
	case H8300_MOV_IMM162R16: /*TODO*/ return 0;
	case H8300_EEPMOV: /*TODO*/ return 0;
	case H8300_BIAND_IMM2IND16: /*TODO*/ return 0;
	case H8300_BCLR_R2IND16: /*TODO*/ return 0;
	case H8300_BIAND_IMM2ABS8: /*TODO*/ return 0;
	case H8300_BCLR_R2ABS8: /*TODO*/ return 0;
	default:
		break;
	};

	return ret;
}
