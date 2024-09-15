// SPDX-FileCopyrightText: 2021-2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

#include "avr/disassembler.h"
#include "avr/avr_esil.h"
#include "avr/avr_il.h"

static void set_invalid_op(RzAnalysisOp *op, ut64 addr) {
	// Unknown or invalid instruction.
	op->family = RZ_ANALYSIS_OP_FAMILY_UNKNOWN;
	op->type = RZ_ANALYSIS_OP_TYPE_ILL;
	op->addr = addr;
	op->nopcode = 1;
	op->cycles = 1;
	op->size = 2;
	// set an esil trap to prevent the execution of it
	rz_strbuf_set(&op->esil, "1,$");
}

static void handle_skip_next_instruction(RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, bool big_endian, AVROp *aop) {
	RzStrBuf sb = { 0 };
	rz_strbuf_init(&sb);
	if (len > 1 && avr_disassembler(buf, len, addr, big_endian, aop, &sb)) {
		op->jump = op->addr + aop->size + 2;
		op->fail = op->addr + 2;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	}
	rz_strbuf_fini(&sb);
}

static int avr_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	AVROp aop = { 0 };
	AVROp next_op = { 0 };

	set_invalid_op(op, addr);

	RzStrBuf *sb = rz_strbuf_new("invalid");
	if (len < 2 || avr_disassembler(buf, len, addr, analysis->big_endian, &aop, sb) < 1) {
		op->mnemonic = rz_strbuf_drain(sb);
		op->eob = true;
		return -1;
	}

	op->mnemonic = rz_strbuf_drain(sb);
	op->size = aop.size;

	if (!op->mnemonic) {
		return -1;
	} else if (!strcmp(op->mnemonic, "invalid")) {
		op->nopcode = true;
		op->eob = true;
		return -1;
	}

	op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	op->type = RZ_ANALYSIS_OP_TYPE_NULL;
	op->cycles = aop.cycles;
	switch (aop.mnemonic) {
	case AVR_OP_ADIW:
		op->val = aop.param[2]; // K
		break;
	case AVR_OP_ANDI:
		op->val = aop.param[1]; // K
		break;
	case AVR_OP_BREAK:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case AVR_OP_BRCC:
		/* fall through */
	case AVR_OP_BRCS:
		/* fall through */
	case AVR_OP_BREQ:
		/* fall through */
	case AVR_OP_BRGE:
		/* fall through */
	case AVR_OP_BRHC:
		/* fall through */
	case AVR_OP_BRHS:
		/* fall through */
	case AVR_OP_BRID:
		/* fall through */
	case AVR_OP_BRIE:
		/* fall through */
	case AVR_OP_BRLO:
		/* fall through */
	case AVR_OP_BRLT:
		/* fall through */
	case AVR_OP_BRMI:
		/* fall through */
	case AVR_OP_BRNE:
		/* fall through */
	case AVR_OP_BRPL:
		/* fall through */
	case AVR_OP_BRSH:
		/* fall through */
	case AVR_OP_BRTC:
		/* fall through */
	case AVR_OP_BRTS:
		/* fall through */
	case AVR_OP_BRVC:
		/* fall through */
	case AVR_OP_BRVS:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = aop.param[0]; // address
		op->fail = addr + aop.size;
		break;
	case AVR_OP_CALL:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = aop.param[0]; // address (hi 16 bits)
		op->jump <<= 16;
		op->jump |= aop.param[1]; // address (low 16 bits)
		op->fail = addr + aop.size;
		break;
	case AVR_OP_CBI:
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->family = RZ_ANALYSIS_OP_FAMILY_IO;
		op->type2 = 1;
		op->val = aop.param[0]; // A
		break;
	case AVR_OP_CPSE:
		// cpse skips the next instruction when Rr != Rd
		handle_skip_next_instruction(op, addr, buf + aop.size, len - aop.size, analysis->big_endian, &next_op);
		break;
	case AVR_OP_DES:
		op->family = RZ_ANALYSIS_OP_FAMILY_CRYPTO;
		op->type = RZ_ANALYSIS_OP_TYPE_CRYPTO;
		break;
	case AVR_OP_EICALL:
		op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
		break;
	case AVR_OP_EIJMP:
		op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
		break;
	case AVR_OP_IJMP:
		op->type = RZ_ANALYSIS_OP_TYPE_IJMP;
		break;
	case AVR_OP_ICALL:
		op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
		break;
	case AVR_OP_IN:
		op->type2 = 0;
		op->val = op->mmio_address = aop.param[1]; // A
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->family = RZ_ANALYSIS_OP_FAMILY_IO;
		break;
	case AVR_OP_JMP:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = aop.param[0]; // address (hi 16 bits)
		op->jump <<= 16;
		op->jump |= aop.param[1]; // address (low 16 bits)
		break;
	case AVR_OP_LDI:
		op->val = aop.param[1]; // K
		break;
	case AVR_OP_LDS:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->ptr = aop.param[1]; // K
		break;
	case AVR_OP_MOV:
		/* fall through */
	case AVR_OP_MOVW:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case AVR_OP_ORI:
		op->val = aop.param[1]; // K
		break;
	case AVR_OP_OUT:
		op->type2 = 1;
		op->val = op->mmio_address = aop.param[0]; // A
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->family = RZ_ANALYSIS_OP_FAMILY_IO;
		break;
	case AVR_OP_RCALL:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = addr + (st16)aop.param[0]; // address
		op->fail = addr + aop.size;
		break;
	case AVR_OP_RET:
		op->eob = true;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case AVR_OP_RETI:
		op->eob = true;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case AVR_OP_RJMP:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + (st16)aop.param[0]; // address
		break;
	case AVR_OP_SBCI:
		/* fall through*/
	case AVR_OP_SUBI:
		op->val = aop.param[1]; // K
		break;
	case AVR_OP_SBI:
		op->type2 = 1;
		op->val = aop.param[0]; // A
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->family = RZ_ANALYSIS_OP_FAMILY_IO;
		break;
	case AVR_OP_SBIC:
		// skip next instruction if bit in i/o register is clear
		/* fall through*/
	case AVR_OP_SBIS:
		// skip next instruction if bit in i/o register is set
		handle_skip_next_instruction(op, addr, buf + aop.size, len - aop.size, analysis->big_endian, &next_op);
		op->type2 = 0;
		op->val = aop.param[0]; // A
		op->family = RZ_ANALYSIS_OP_FAMILY_IO;
		break;
	case AVR_OP_SBIW:
		op->val = aop.param[2]; // K
		break;
	case AVR_OP_SBRC:
		// skip next instruction if bit register is clear
		/* fall through*/
	case AVR_OP_SBRS:
		// skip next instruction if bit register is set
		handle_skip_next_instruction(op, addr, buf + aop.size, len - aop.size, analysis->big_endian, &next_op);
		break;
	case AVR_OP_STS:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->ptr = aop.param[0]; // K
		break;
	default:
		break;
	}

	// set RzIL
	rz_avr_il_opcode(analysis, op, addr, &aop, &next_op);

	// process opcode
	rz_avr_esil_opcode(analysis, op, addr, buf, len);

	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	pcl\n"
		"=SN	r24\n"
		"=SP	sp\n"
		"=BP	y\n"

		// explained in http://www.nongnu.org/avr-libc/user-manual/FAQ.html
		// and http://www.avrfreaks.net/forum/function-calling-convention-gcc-generated-assembly-file
		"=A0	r25\n"
		"=A1	r24\n"
		"=A2	r23\n"
		"=A3	r22\n"
		"=R0	r24\n"

		// PC: 16- or 22-bit program counter
		// SP: 8- or 16-bit stack pointer
		// SREG: 8-bit status register
		// RAMPX, RAMPY, RAMPZ, RAMPD and EIND:
		// 8bit registers x 32
		"gpr	r0	.8	0	0\n"
		"gpr	r1	.8	1	0\n"
		"gpr	r2	.8	2	0\n"
		"gpr	r3	.8	3	0\n"
		"gpr	r4	.8	4	0\n"
		"gpr	r5	.8	5	0\n"
		"gpr	r6	.8	6	0\n"
		"gpr	r7	.8	7	0\n"
		"gpr	r8	.8	8	0\n"
		"gpr	r9	.8	9	0\n"
		"gpr	r10	.8	10	0\n"
		"gpr	r11	.8	11	0\n"
		"gpr	r12	.8	12	0\n"
		"gpr	r13	.8	13	0\n"
		"gpr	r14	.8	14	0\n"
		"gpr	r15	.8	15	0\n"
		"gpr	r16	.8	16	0\n"
		"gpr	r17	.8	17	0\n"
		"gpr	r18	.8	18	0\n"
		"gpr	r19	.8	19	0\n"
		"gpr	r20	.8	20	0\n"
		"gpr	r21	.8	21	0\n"
		"gpr	r22	.8	22	0\n"
		"gpr	r23	.8	23	0\n"
		"gpr	r24	.8	24	0\n"
		"gpr	r25	.8	25	0\n"
		"gpr	r26	.8	26	0\n"
		"gpr	r27	.8	27	0\n"
		"gpr	r28	.8	28	0\n"
		"gpr	r29	.8	29	0\n"
		"gpr	r30	.8	30	0\n"
		"gpr	r31	.8	31	0\n"

		// 16 bit overlapped registers for memory addressing
		"gpr	x	.16	26	0\n"
		"gpr	y	.16	28	0\n"
		"gpr	z	.16	30	0\n"
		// program counter
		// NOTE: program counter size in AVR depends on the CPU model. It seems that
		// the PC may range from 16 bits to 22 bits.
		"gpr	pc	.32	32	0\n"
		"gpr	pcl	.16	32	0\n"
		"gpr	pch	.16	34	0\n"
		// special purpose registers
		"gpr	sp	.16	36	0\n"
		"gpr	spl	.8	36	0\n"
		"gpr	sph	.8	37	0\n"
		// status bit register (SREG)
		"gpr	sreg	.8	38	0\n"
		"gpr	cf	.1	38.0	0\n" // Carry. This is a borrow flag on subtracts.
		"gpr	zf	.1	38.1	0\n" // Zero. Set to 1 when an arithmetic result is zero.
		"gpr	nf	.1	38.2	0\n" // Negative. Set to a copy of the most significant bit of an arithmetic result.
		"gpr	vf	.1	38.3	0\n" // Overflow flag. Set in case of two's complement overflow.
		"gpr	sf	.1	38.4	0\n" // Sign flag. Unique to AVR, this is always (N ^ V) (xor), and shows the true sign of a comparison.
		"gpr	hf	.1	38.5	0\n" // Half carry. This is an internal carry from additions and is used to support BCD arithmetic.
		"gpr	tf	.1	38.6	0\n" // Bit copy. Special bit load and bit store instructions use this bit.
		"gpr	if	.1	38.7	0\n" // Interrupt flag. Set when interrupts are enabled.
		// 8bit segment registers to be added to X, Y, Z to get 24bit offsets
		"gpr	rampx	.8	39	0\n"
		"gpr	rampy	.8	40	0\n"
		"gpr	rampz	.8	41	0\n"
		"gpr	rampd	.8	42	0\n"
		"gpr	eind	.8	43	0\n"
		// memory mapping emulator registers
		//  _prog
		//      the program flash. It has its own address space.
		//  _ram
		//  _io
		//      start of the data addres space. It is the same address of IO,
		//      because IO is the first memory space addressable in the AVR.
		//  _sram
		//      start of the SRAM (this offset depends on IO size, and it is
		//      inside the _ram address space)
		//  _eeprom
		//      this is another address space, outside ram and flash
		//  _page
		//      this is the temporary page used by the SPM instruction. This
		//      memory is not directly addressable and it is used internally by
		//      the CPU when autoflashing.
		"gpr	_prog	.32	44	0\n"
		"gpr	_page	.32	48	0\n"
		"gpr	_eeprom	.32	52	0\n"
		"gpr	_ram	.32	56	0\n"
		"gpr	_io	.32	56	0\n"
		"gpr	_sram	.32	60	0\n"
		// other important MCU registers
		// spmcsr/spmcr
		// Store Program Memory Control and Status Register (SPMCSR)
		"gpr	spmcsr	.8	64	0\n";

	return rz_str_dup(p);
}

static int archinfo(RzAnalysis *analysis, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

static ut8 *analysis_mask_avr(RzAnalysis *analysis, int size, const ut8 *data, ut64 at) {
	ut8 *ret = NULL;
	AVROp aop = { 0 };
	RzStrBuf sb = { 0 };
	rz_strbuf_init(&sb);
	int opsize = avr_disassembler(data, size, at, analysis->big_endian, &aop, &sb);
	rz_strbuf_fini(&sb);

	if (opsize < 2 || !(ret = malloc(opsize))) {
		free(ret);
		return NULL;
	}

	memset(ret, 0xff, opsize);

	if (aop.size == 4) {
		// all the ops that consumes 4 bytes uses
		// the last 2 bytes as addresses, therefore
		// we need to mask them (i.e. set to zero)
		ret[2] = 0;
		ret[3] = 0;
	}

	switch (aop.mnemonic) {
	case AVR_OP_BRCC:
		/* fall through */
	case AVR_OP_BRCS:
		/* fall through */
	case AVR_OP_BREQ:
		/* fall through */
	case AVR_OP_BRGE:
		/* fall through */
	case AVR_OP_BRHC:
		/* fall through */
	case AVR_OP_BRHS:
		/* fall through */
	case AVR_OP_BRID:
		/* fall through */
	case AVR_OP_BRIE:
		/* fall through */
	case AVR_OP_BRLO:
		/* fall through */
	case AVR_OP_BRLT:
		/* fall through */
	case AVR_OP_BRMI:
		/* fall through */
	case AVR_OP_BRNE:
		/* fall through */
	case AVR_OP_BRPL:
		/* fall through */
	case AVR_OP_BRSH:
		/* fall through */
	case AVR_OP_BRTC:
		/* fall through */
	case AVR_OP_BRTS:
		/* fall through */
	case AVR_OP_BRVC:
		/* fall through */
	case AVR_OP_BRVS:
		/* fall through */
	case AVR_OP_CALL:
		/* fall through */
	case AVR_OP_CPSE:
		/* fall through */
	case AVR_OP_EIJMP:
		/* fall through */
	case AVR_OP_IJMP:
		/* fall through */
	case AVR_OP_JMP:
		/* fall through */
	case AVR_OP_RCALL:
		/* fall through */
	case AVR_OP_RJMP:
		/* fall through */
	case AVR_OP_SBIC:
		/* fall through */
	case AVR_OP_SBRC:
		/* fall through */
	case AVR_OP_LDS:
		/* fall through */
	case AVR_OP_STS:
		// jump & load instructions needs to be masked
		rz_write_ble16(ret, aop.mask, analysis->big_endian);
		break;
	default:
		// assume all the other instructions as un-maskable
		break;
	}

	return ret;
}

static int address_bits(RzAnalysis *analysis, int bits) {
	return bits == 8 ? 16 : -1;
}

RzAnalysisPlugin rz_analysis_plugin_avr = {
	.name = "avr",
	.desc = "AVR code analysis plugin",
	.license = "LGPL3",
	.arch = "avr",
	.esil = true,
	.archinfo = archinfo,
	.bits = 8 | 16, // 24 big regs conflicts
	.address_bits = address_bits,
	.op = &avr_op,
	.get_reg_profile = &get_reg_profile,
	.esil_init = rz_avr_esil_init,
	.esil_fini = rz_avr_esil_fini,
	.il_config = rz_avr_il_config,
	.analysis_mask = analysis_mask_avr,
};
