// SPDX-FileCopyrightText: 2011-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2011-2019 Roc Valles <vallesroc@gmail.com>
// SPDX-FileCopyrightText: 2011-2019 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2011-2019 killabyte <killabytenow@gmail.com>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "avr_esil.h"
#include <rz_crypto.h>

/** \file avr_esil.c
 * Converts AVR instructions into ESIL statements
 *
 * references:
 * - http://www.atmel.com/images/atmel-0856-avr-instruction-set-manual.pdf
 * - https://en.wikipedia.org/wiki/Atmel_AVR_instruction_set
 */

typedef struct _cpu_const_tag {
	const char *const key;
	ut8 type;
	ut32 value;
	ut8 size;
} CPU_CONST;

#define CPU_CONST_NONE  0
#define CPU_CONST_PARAM 1
#define CPU_CONST_REG   2

typedef struct _cpu_model_tag {
	const char *const model;
	int pc;
	char *inherit;
	struct _cpu_model_tag *inherit_cpu_p;
	CPU_CONST *consts[10];
} CPU_MODEL;

typedef void (*inst_handler_t)(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu);

typedef struct _opcodes_tag_ {
	const char *const name;
	int mask;
	int selector;
	inst_handler_t handler;
	int cycles;
	int size;
	ut64 type;
} OPCODE_DESC;

static OPCODE_DESC *avr_op_analyze(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, CPU_MODEL *cpu);

#define CPU_MODEL_DECL(model, pc, consts) \
	{ \
		model, \
			pc, \
			consts \
	}
#define MASK(bits)       ((bits) == 32 ? 0xffffffff : (~((~((ut32)0)) << (bits))))
#define CPU_PC_MASK(cpu) MASK((cpu)->pc)
#define CPU_PC_SIZE(cpu) ((((cpu)->pc) >> 3) + ((((cpu)->pc) & 0x07) ? 1 : 0))

#define INST_HANDLER(OPCODE_NAME) static void _inst__##OPCODE_NAME(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu)
#define INST_DECL(OP, M, SL, C, SZ, T) \
	{ \
#OP, (M), (SL), _inst__##OP, (C), (SZ), RZ_ANALYSIS_OP_TYPE_##T \
	}
#define INST_LAST \
	{ "unknown", 0, 0, (void *)0, 2, 1, RZ_ANALYSIS_OP_TYPE_UNK }

#define INST_CALL(OPCODE_NAME) _inst__##OPCODE_NAME(analysis, op, buf, len, fail, cpu)
#define INST_INVALID \
	{ \
		*fail = 1; \
		return; \
	}
#define INST_ASSERT(x) \
	{ \
		if (!(x)) { \
			INST_INVALID; \
		} \
	}

#define ESIL_A(e, ...) rz_strbuf_appendf(&op->esil, e, ##__VA_ARGS__)

#define STR_BEGINS(in, s) rz_str_ncasecmp(in, s, strlen(s))

// Following IO definitions are valid for:
//	ATmega8
//	ATmega88
CPU_CONST cpu_reg_common[] = {
	{ "spl", CPU_CONST_REG, 0x3d, sizeof(ut8) },
	{ "sph", CPU_CONST_REG, 0x3e, sizeof(ut8) },
	{ "sreg", CPU_CONST_REG, 0x3f, sizeof(ut8) },
	{ "spmcsr", CPU_CONST_REG, 0x37, sizeof(ut8) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_memsize_common[] = {
	{ "eeprom_size", CPU_CONST_PARAM, 512, sizeof(ut32) },
	{ "io_size", CPU_CONST_PARAM, 0x40, sizeof(ut32) },
	{ "sram_start", CPU_CONST_PARAM, 0x60, sizeof(ut32) },
	{ "sram_size", CPU_CONST_PARAM, 1024, sizeof(ut32) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_memsize_m640_m1280m_m1281_m2560_m2561[] = {
	{ "eeprom_size", CPU_CONST_PARAM, 512, sizeof(ut32) },
	{ "io_size", CPU_CONST_PARAM, 0x1ff, sizeof(ut32) },
	{ "sram_start", CPU_CONST_PARAM, 0x200, sizeof(ut32) },
	{ "sram_size", CPU_CONST_PARAM, 0x2000, sizeof(ut32) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_memsize_xmega128a4u[] = {
	{ "eeprom_size", CPU_CONST_PARAM, 0x800, sizeof(ut32) },
	{ "io_size", CPU_CONST_PARAM, 0x1000, sizeof(ut32) },
	{ "sram_start", CPU_CONST_PARAM, 0x800, sizeof(ut32) },
	{ "sram_size", CPU_CONST_PARAM, 0x2000, sizeof(ut32) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_pagesize_5_bits[] = {
	{ "page_size", CPU_CONST_PARAM, 5, sizeof(ut8) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_pagesize_7_bits[] = {
	{ "page_size", CPU_CONST_PARAM, 7, sizeof(ut8) },
	{ NULL, 0, 0, 0 },
};

CPU_MODEL cpu_models[] = {
	{
		.model = "ATmega640",
		.pc = 15,
		.consts = {
			cpu_reg_common,
			cpu_memsize_m640_m1280m_m1281_m2560_m2561,
			cpu_pagesize_7_bits,
			NULL },
	},
	{ .model = "ATxmega128a4u", .pc = 17, .consts = { cpu_reg_common, cpu_memsize_xmega128a4u, cpu_pagesize_7_bits, NULL } },
	{ .model = "ATmega1280", .pc = 16, .inherit = "ATmega640" },
	{ .model = "ATmega1281", .pc = 16, .inherit = "ATmega640" },
	{ .model = "ATmega2560", .pc = 17, .inherit = "ATmega640" },
	{ .model = "ATmega2561", .pc = 17, .inherit = "ATmega640" },
	{ .model = "ATmega88", .pc = 8, .inherit = "ATmega8" },
	//	CPU_MODEL_DECL ("ATmega168",   13, 512, 512),
	// last model is the default AVR - ATmega8 forever!
	{ .model = "ATmega8", .pc = 13, .consts = { cpu_reg_common, cpu_memsize_common, cpu_pagesize_5_bits, NULL } },
};

static CPU_MODEL *get_cpu_model(char *model);

static CPU_MODEL *__get_cpu_model_recursive(char *model) {
	if (!model) {
		return &cpu_models[0];
	}
	CPU_MODEL *cpu = NULL;

	for (cpu = cpu_models; cpu < cpu_models + ((sizeof(cpu_models) / sizeof(CPU_MODEL))) - 1; cpu++) {
		if (!rz_str_casecmp(model, cpu->model)) {
			break;
		}
	}

	// fix inheritance tree
	if (cpu->inherit && !cpu->inherit_cpu_p) {
		cpu->inherit_cpu_p = get_cpu_model(cpu->inherit);
		if (!cpu->inherit_cpu_p) {
			RZ_LOG_ERROR("Cannot inherit from unknown CPU model '%s'.\n", cpu->inherit);
		}
	}

	return cpu;
}

static CPU_MODEL *get_cpu_model(char *model) {
	if (!model) {
		return &cpu_models[0];
	}
	static CPU_MODEL *cpu = NULL;
	// cached value?
	if (cpu && !rz_str_casecmp(model, cpu->model)) {
		return cpu;
	}
	// do the real search
	cpu = __get_cpu_model_recursive(model);
	return cpu;
}

static ut32 const_get_value(CPU_CONST *c) {
	return c ? MASK(c->size * 8) & c->value : 0;
}

static CPU_CONST *const_by_name(CPU_MODEL *cpu, int type, char *c) {
	CPU_CONST **clist, *citem;

	for (clist = cpu->consts; *clist; clist++) {
		for (citem = *clist; citem->key; citem++) {
			if (!strcmp(c, citem->key) && (type == CPU_CONST_NONE || type == citem->type)) {
				return citem;
			}
		}
	}
	if (cpu->inherit_cpu_p) {
		return const_by_name(cpu->inherit_cpu_p, type, c);
	}
	RZ_LOG_ERROR("Cannot find const key[%s].\n", c);
	return NULL;
}

static int __esil_pop_argument(RzAnalysisEsil *esil, ut64 *v) {
	char *t = rz_analysis_esil_pop(esil);
	if (!t || !rz_analysis_esil_get_parm(esil, t, v)) {
		free(t);
		return false;
	}
	free(t);
	return true;
}

static CPU_CONST *const_by_value(CPU_MODEL *cpu, int type, ut32 v) {
	CPU_CONST **clist, *citem;

	for (clist = cpu->consts; *clist; clist++) {
		for (citem = *clist; citem && citem->key; citem++) {
			if (citem->value == (MASK(citem->size * 8) & v) && (type == CPU_CONST_NONE || type == citem->type)) {
				return citem;
			}
		}
	}
	if (cpu->inherit_cpu_p) {
		return const_by_value(cpu->inherit_cpu_p, type, v);
	}
	return NULL;
}

static RzStrBuf *__generic_io_dest(ut8 port, int write, CPU_MODEL *cpu) {
	RzStrBuf *r = rz_strbuf_new("");
	CPU_CONST *c = const_by_value(cpu, CPU_CONST_REG, port);
	if (c != NULL) {
		rz_strbuf_set(r, c->key);
		if (write) {
			rz_strbuf_append(r, ",=");
		}
	} else {
		rz_strbuf_setf(r, "_io,%d,+,%s[1]", port, write ? "=" : "");
	}

	return r;
}

static void __generic_ld_st(RzAnalysisOp *op, char *mem, char ireg, int use_ramp, int prepostdec, int offset, int st) {
	if (ireg) {
		// preincrement index register
		if (prepostdec < 0) {
			ESIL_A("1,%c,-,%c,=,", ireg, ireg);
		}
		// set register index address
		ESIL_A("%c,", ireg);
		// add offset
		if (offset != 0) {
			ESIL_A("%d,+,", offset);
		}
	} else {
		ESIL_A("%d,", offset);
	}
	if (use_ramp) {
		ESIL_A("16,ramp%c,<<,+,", ireg ? ireg : 'd');
	}
	// set SRAM base address
	ESIL_A("_%s,+,", mem);
	// read/write from SRAM
	ESIL_A("%s[1],", st ? "=" : "");
	// postincrement index register
	if (ireg && prepostdec > 0) {
		ESIL_A("1,%c,+,%c,=,", ireg, ireg);
	}
}

static void __generic_pop(RzAnalysisOp *op, int sz) {
	if (sz > 1) {
		ESIL_A("1,sp,+,_ram,+,"); // calc SRAM(sp+1)
		ESIL_A("[%d],", sz); // read value
		ESIL_A("%d,sp,+=,", sz); // sp += item_size
	} else {
		ESIL_A("1,sp,+=," // increment stack pointer
		       "sp,_ram,+,[1],"); // load SRAM[sp]
	}
}

static void __generic_push(RzAnalysisOp *op, int sz) {
	ESIL_A("sp,_ram,+,"); // calc pointer SRAM(sp)
	if (sz > 1) {
		ESIL_A("-%d,+,", sz - 1); // dec SP by 'sz'
	}
	ESIL_A("=[%d],", sz); // store value in stack
	ESIL_A("-%d,sp,+=,", sz); // decrement stack pointer
}

INST_HANDLER(adc) { // ADC Rd, Rr
	// ROL Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	const ut32 r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A("r%d,cf,+,r%d,+=,", r, d); // Rd + Rr + C
	ESIL_A("$z,zf,:=,");
	ESIL_A("3,$c,hf,:=,");
	ESIL_A("7,$c,cf,:=,");
	ESIL_A("7,$o,vf,:=,");
	ESIL_A("0x80,r%d,&,!,!,nf,:=", d);
}

INST_HANDLER(add) { // ADD Rd, Rr
	// LSL Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	const ut32 r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A("r%d,r%d,+=,", r, d); // Rd + Rr
	ESIL_A("$z,zf,:=,");
	ESIL_A("3,$c,hf,:=,");
	ESIL_A("7,$c,cf,:=,");
	ESIL_A("7,$o,vf,:=,");
	ESIL_A("0x80,r%d,&,!,!,nf,:=,", d);
}

INST_HANDLER(adiw) { // ADIW Rd+1:Rd, K
	if (len < 1) {
		return;
	}
	const ut32 d = ((buf[0] & 0x30) >> 3) + 24;
	const ut32 k = (buf[0] & 0x0f) | ((buf[0] >> 2) & 0x30);
	ESIL_A("7,r%d,>>,", d + 1); // remember previous highest bit
	ESIL_A("8,%d,8,r%d,<<,r%d,|,+,DUP,r%d,=,>>,r%d,=,", k, d + 1, d, d, d + 1); // Rd+1_Rd + k
										    // FLAGS:
	ESIL_A("DUP,!,7,r%d,>>,&,vf,:=,", d + 1); // V
	ESIL_A("r%d,0x80,&,!,!,nf,:=,", d + 1); // N
	ESIL_A("8,r%d,<<,r%d,|,!,zf,:=,", d + 1, d); // Z
	ESIL_A("7,r%d,>>,!,&,cf,:=,", d + 1); // C
	ESIL_A("vf,nf,^,sf,:="); // S
}

INST_HANDLER(and) { // AND Rd, Rr
	// TST Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	const ut32 r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A("r%d,r%d,&=,$z,zf,:=,r%d,0x80,&,!,!,nf,:=,0,vf,:=,nf,sf,:=,", r, d, d);
}

INST_HANDLER(andi) { // ANDI Rd, K
	// CBR Rd, K (= ANDI Rd, 1-K)
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) + 16;
	const ut32 k = ((buf[1] & 0x0f) << 4) | (buf[0] & 0x0f);
	ESIL_A("%d,r%d,&=,$z,zf,:=,r%d,0x80,&,!,!,nf,:=,0,vf,:=,nf,sf,:=,", k, d, d);
}

INST_HANDLER(asr) { // ASR Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	ESIL_A("r%d,0x1,&,cf,:=,0x1,r%d,>>,r%d,0x80,&,|,", d, d, d);
	// 0: R=(Rd >> 1) | Rd7
	ESIL_A("$z,zf,:=,"); // Z
	ESIL_A("r%d,0x80,&,!,!,nf,:=,", d); // N
	ESIL_A("nf,cf,^,vf,:=,"); // V
	ESIL_A("nf,vf,^,sf,:=,"); // S
}

INST_HANDLER(bclr) { // BCLR s
	// CLC
	// CLH
	// CLI
	// CLN
	// CLR
	// CLS
	// CLT
	// CLV
	// CLZ
	if (len < 1) {
		return;
	}
	int s = (buf[0] >> 4) & 0x7;
	ESIL_A("0xff,%d,1,<<,^,sreg,&=,", s);
}

INST_HANDLER(bld) { // BLD Rd, b
	if (len < 2) {
		return;
	}
	int d = ((buf[1] & 0x01) << 4) | ((buf[0] >> 4) & 0xf);
	int b = buf[0] & 0x7;
	ESIL_A("r%d,%d,1,<<,0xff,^,&,", d, b); // Rd/b = 0
	ESIL_A("%d,tf,<<,|,r%d,=,", b, d); // Rd/b |= T<<b
}

INST_HANDLER(brbx) { // BRBC s, k
	// BRBS s, k
	// BRBC/S 0:  BRCC  BRCS
	//            BRSH  BRLO
	// BRBC/S 1:  BREQ  BRNE
	// BRBC/S 2:  BRPL  BRMI
	// BRBC/S 3:  BRVC  BRVS
	// BRBC/S 4:  BRGE  BRLT
	// BRBC/S 5:  BRHC  BRHS
	// BRBC/S 6:  BRTC  BRTS
	// BRBC/S 7:  BRID  BRIE
	if (len < 2) {
		return;
	}
	int s = buf[0] & 0x7;
	ut64 jump = op->addr + ((((buf[1] & 0x03) << 6) | ((buf[0] & 0xf8) >> 2)) | (buf[1] & 0x2 ? ~((int)0x7f) : 0)) + 2;
	ESIL_A("%d,1,<<,sreg,&,", s); // SREG(s)
	ESIL_A(buf[1] & 0x4
			? "!," // BRBC => branch if cleared
			: "!,!,"); // BRBS => branch if set
	ESIL_A("?{,%" PFMT64d ",pc,=,},", jump); // ?true => jmp
}

INST_HANDLER(break) { // BREAK
	ESIL_A("BREAK");
}

INST_HANDLER(bset) { // BSET s
	// SEC
	// SEH
	// SEI
	// SEN
	// SER
	// SES
	// SET
	// SEV
	// SEZ
	if (len < 1) {
		return;
	}
	int s = (buf[0] >> 4) & 0x7;
	ESIL_A("%d,1,<<,sreg,|=,", s);
}

INST_HANDLER(bst) { // BST Rd, b
	if (len < 2) {
		return;
	}
	ESIL_A("r%d,%d,1,<<,&,!,!,tf,=,", // tf = Rd/b
		((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf), // r
		buf[0] & 0x7); // b
}

INST_HANDLER(call) { // CALL k
	if (len < 4) {
		return;
	}
	ut64 jump = (buf[2] << 1) | (buf[3] << 9) | (buf[1] & 0x01) << 23 | (buf[0] & 0x01) << 17 | (buf[0] & 0xf0) << 14;
	ESIL_A("pc,"); // esil is already pointing to
		       // next instruction (@ret)
	__generic_push(op, CPU_PC_SIZE(cpu)); // push @ret in stack
	ESIL_A("%" PFMT64d ",pc,=,", jump); // jump!
}

INST_HANDLER(cbi) { // CBI A, b
	if (len < 1) {
		return;
	}
	int a = (buf[0] >> 3) & 0x1f;
	int b = buf[0] & 0x07;
	RzStrBuf *io_port;

	// read port a and clear bit b
	io_port = __generic_io_dest(a, 0, cpu);
	ESIL_A("0xff,%d,1,<<,^,%s,&,", b, rz_strbuf_get(io_port));
	rz_strbuf_free(io_port);

	// write result to port a
	io_port = __generic_io_dest(a, 1, cpu);
	ESIL_A("%s,", rz_strbuf_get(io_port));
	rz_strbuf_free(io_port);
}

INST_HANDLER(com) { // COM Rd
	if (len < 2) {
		return;
	}
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 1) << 4);

	ESIL_A("r%d,0xff,-,r%d,=,$z,zf,:=,0,cf,:=,0,vf,:=,r%d,0x80,&,!,!,nf,:=,vf,nf,^,sf,:=", r, r, r);
	// Rd = 0xFF-Rd
}

INST_HANDLER(cp) { // CP Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 r = (buf[0] & 0x0f) | ((buf[1] << 3) & 0x10);
	const ut32 d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	ESIL_A("r%d,r%d,-,0x80,&,!,!,nf,:=,", r, d);
	ESIL_A("r%d,r%d,==,", r, d);
	ESIL_A("$z,zf,:=,");
	ESIL_A("3,$b,hf,:=,");
	ESIL_A("8,$b,cf,:=,");
	ESIL_A("7,$o,vf,:=,");
	ESIL_A("vf,nf,^,sf,:=");
}

INST_HANDLER(cpc) { // CPC Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 r = (buf[0] & 0x0f) | ((buf[1] << 3) & 0x10);
	const ut32 d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);

	ESIL_A("cf,r%d,+,DUP,r%d,-,0x80,&,!,!,nf,:=,", r, d); // Rd - Rr - C
	ESIL_A("r%d,==,", d);
	ESIL_A("$z,zf,:=,");
	ESIL_A("3,$b,hf,:=,");
	ESIL_A("8,$b,cf,:=,");
	ESIL_A("7,$o,vf,:=,");
	ESIL_A("vf,nf,^,sf,:=");
}

INST_HANDLER(cpi) { // CPI Rd, K
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) + 16;
	const ut32 k = (buf[0] & 0xf) | ((buf[1] & 0xf) << 4);
	ESIL_A("%d,r%d,-,0x80,&,!,!,nf,:=,", k, d); // Rd - k
	ESIL_A("%d,r%d,==,", k, d);
	ESIL_A("$z,zf,:=,");
	ESIL_A("3,$b,hf,:=,");
	ESIL_A("8,$b,cf,:=,");
	ESIL_A("7,$o,vf,:=,");
	ESIL_A("vf,nf,^,sf,:=");
}

INST_HANDLER(cpse) { // CPSE Rd, Rr
	if (len < 2) {
		return;
	}
	int r = (buf[0] & 0xf) | ((buf[1] & 0x2) << 3);
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	ESIL_A("r%d,r%d,^,!,", r, d); // Rr == Rd
	ESIL_A("?{,%" PFMT64d ",pc,=,},", op->jump); // ?true => jmp
}

INST_HANDLER(dec) { // DEC Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	ESIL_A("0x1,r%d,-=,", d); // Rd--
				  // FLAGS:
	ESIL_A("7,$o,vf,:=,"); // V
	ESIL_A("r%d,0x80,&,!,!,nf,:=,", d); // N
	ESIL_A("$z,zf,:=,"); // Z
	ESIL_A("vf,nf,^,sf,:=,"); // S
}

INST_HANDLER(des) { // DES k
	int round = (buf[0] >> 4);
	ESIL_A("%d,des", round);
}

INST_HANDLER(eijmp) { // EIJMP
	ESIL_A("1,z,16,eind,<<,+,<<,pc,=,");
}

INST_HANDLER(eicall) { // EICALL
	// push pc in stack
	ESIL_A("pc,"); // esil is already pointing to
		       // next instruction (@ret)
	__generic_push(op, CPU_PC_SIZE(cpu)); // push @ret in stack
	// do a standard EIJMP
	INST_CALL(eijmp);
}

INST_HANDLER(elpm) { // ELPM
	// ELPM Rd
	// ELPM Rd, Z+
	if (len < 2) {
		return;
	}
	int d = ((buf[1] & 0xfe) == 0x90)
		? ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf) // Rd
		: 0; // R0
	ESIL_A("16,rampz,<<,z,+,_prog,+,[1],"); // read RAMPZ:Z
	ESIL_A("r%d,=,", d); // Rd = [1]
	if ((buf[1] & 0xfe) == 0x90 && (buf[0] & 0xf) == 0x7) {
		ESIL_A("16,1,z,+,DUP,z,=,>>,1,&,rampz,+=,"); // ++(rampz:z)
	}
}

INST_HANDLER(eor) { // EOR Rd, Rr
	// CLR Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	const ut32 r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A("r%d,r%d,^=,$z,zf,:=,0,vf,:=,r%d,0x80,&,!,!,nf,:=,nf,sf,:=", r, d, d);
	// 0: Rd ^= Rr
}

INST_HANDLER(fmul) { // FMUL Rd, Rr
	if (len < 1) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0x7) + 16;
	const ut32 r = (buf[0] & 0x7) + 16;

	ESIL_A("8,");
	ESIL_A("0xffff,1,r%d,r%d,*,<<,&,DUP,r0,=,>>,r1,=,", r, d); // 0: r1_r0 = (rd * rr) << 1
	ESIL_A("8,r1,<<,r0,|,DUP,0x8000,&,!,!,cf,:=,"); // C = R/15
	ESIL_A("!,zf,:="); // Z = !R
}

INST_HANDLER(fmuls) { // FMULS Rd, Rr
	if (len < 1) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0x7) + 16;
	const ut32 r = (buf[0] & 0x7) + 16;

	ESIL_A("8,1,");
	ESIL_A("r%d,DUP,0x80,&,?{,0xff00,|,},", d); // sign extension Rd
	ESIL_A("r%d,DUP,0x80,&,?{,0xff00,|,},", r); // sign extension Rr
	ESIL_A("*,<<,DUP,r0,=,>>,r1,=,"); // 0: (Rd*Rr)<<1

	ESIL_A("8,r1,<<,r0,|,DUP,0x8000,&,!,!,cf,:=,"); // C = R/16
	ESIL_A("!,zf,:="); // Z = !R
}

INST_HANDLER(fmulsu) { // FMULSU Rd, Rr
	if (len < 1) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0x7) + 16;
	const ut32 r = (buf[0] & 0x7) + 16;

	ESIL_A("8,1,");
	ESIL_A("r%d,DUP,0x80,&,?{,0xff00,|,},", d); // sign extension Rd
	ESIL_A("r%d,*,<<,DUP,r0,=,>>,r1,=,", r); // 0: (Rd*Rr)<<1

	ESIL_A("8,r1,<<,r0,|,DUP,0x8000,&,!,!,cf,:=,"); // C = R/16
	ESIL_A("!,zf,:="); // Z = !R
}

INST_HANDLER(ijmp) { // IJMP k
	// read z for calculating jump address on runtime
	ESIL_A("1,z,<<,pc,=,"); // jump!
}

INST_HANDLER(icall) { // ICALL k
	// push pc in stack
	ESIL_A("pc,"); // esil is already pointing to
		       // next instruction (@ret)
	__generic_push(op, CPU_PC_SIZE(cpu)); // push @ret in stack
	// do a standard IJMP
	INST_CALL(ijmp);
}

INST_HANDLER(in) { // IN Rd, A
	if (len < 2) {
		return;
	}
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 0x01) << 4);
	int a = (buf[0] & 0x0f) | ((buf[1] & 0x6) << 3);
	RzStrBuf *io_src = __generic_io_dest(a, 0, cpu);
	ESIL_A("%s,r%d,=,", rz_strbuf_get(io_src), r);
	rz_strbuf_free(io_src);
}

INST_HANDLER(inc) { // INC Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	ESIL_A("1,r%d,+=,", d); // Rd++
				// FLAGS:
	ESIL_A("7,$o,vf,:=,"); // V
	ESIL_A("r%d,0x80,&,!,!,nf,:=,", d); // N
	ESIL_A("$z,zf,:=,"); // Z
	ESIL_A("vf,nf,^,sf,:=,"); // S
}

INST_HANDLER(jmp) { // JMP k
	if (len < 4) {
		return;
	}
	ut64 jump = (buf[2] << 1) | (buf[3] << 9) | (buf[1] & 0x01) << 23 | (buf[0] & 0x01) << 17 | (buf[0] & 0xf0) << 14;
	ESIL_A("%" PFMT64d ",pc,=,", jump); // jump!
}

INST_HANDLER(lac) { // LAC Z, Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st(op, "ram", 'z', 1, 0, 0, 0); // 0: Read (RAMPZ:Z)
	ESIL_A("r%d,0xff,^,&,", d); // 0: (Z) & ~Rd
	ESIL_A("DUP,r%d,=,", d); // Rd = [0]
	__generic_ld_st(op, "ram", 'z', 1, 0, 0, 1); // Store in RAM
}

INST_HANDLER(las) { // LAS Z, Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st(op, "ram", 'z', 1, 0, 0, 0); // 0: Read (RAMPZ:Z)
	ESIL_A("r%d,|,", d); // 0: (Z) | Rd
	ESIL_A("DUP,r%d,=,", d); // Rd = [0]
	__generic_ld_st(op, "ram", 'z', 1, 0, 0, 1); // Store in RAM
}

INST_HANDLER(lat) { // LAT Z, Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st(op, "ram", 'z', 1, 0, 0, 0); // 0: Read (RAMPZ:Z)
	ESIL_A("r%d,^,", d); // 0: (Z) ^ Rd
	ESIL_A("DUP,r%d,=,", d); // Rd = [0]
	__generic_ld_st(op, "ram", 'z', 1, 0, 0, 1); // Store in RAM
}

INST_HANDLER(ld) { // LD Rd, X
	// LD Rd, X+
	// LD Rd, -X
	if (len < 2) {
		return;
	}
	// read memory
	__generic_ld_st(
		op, "ram",
		'x', // use index register X
		0, // no use RAMP* registers
		(buf[0] & 0xf) == 0xe
			? -1 // pre decremented
			: (buf[0] & 0xf) == 0xd
			? 1 // post incremented
			: 0, // no increment
		0, // offset always 0
		0); // load operation (!st)
	// load register
	ESIL_A("r%d,=,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
}

INST_HANDLER(ldd) { // LD Rd, Y	LD Rd, Z
	// LD Rd, Y+	LD Rd, Z+
	// LD Rd, -Y	LD Rd, -Z
	// LD Rd, Y+q	LD Rd, Z+q
	if (len < 2) {
		return;
	}
	// calculate offset (this value only has sense in some opcodes,
	// but we are optimistic and we calculate it always)
	int offset = (buf[1] & 0x20) | ((buf[1] & 0xc) << 1) | (buf[0] & 0x7);
	// read memory
	__generic_ld_st(
		op, "ram",
		buf[0] & 0x8 ? 'y' : 'z', // index register Y/Z
		0, // no use RAMP* registers
		!(buf[1] & 0x10)
			? 0 // no increment
			: buf[0] & 0x1
			? 1 // post incremented
			: -1, // pre decremented
		!(buf[1] & 0x10) ? offset : 0, // offset or not offset
		0); // load operation (!st)
	// load register
	ESIL_A("r%d,=,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
}

INST_HANDLER(ldi) { // LDI Rd, K
	if (len < 2) {
		return;
	}
	int k = (buf[0] & 0xf) + ((buf[1] & 0xf) << 4);
	int d = ((buf[0] >> 4) & 0xf) + 16;
	ESIL_A("0x%x,r%d,=,", k, d);
}

INST_HANDLER(lds) { // LDS Rd, k
	if (len < 4) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	int k = (buf[3] << 8) | buf[2];

	// load value from RAMPD:k
	__generic_ld_st(op, "ram", 0, 1, 0, k, 0);
	ESIL_A("r%d,=,", d);
}

INST_HANDLER(sts) { // STS k, Rr
	if (len < 4) {
		return;
	}
	int r = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	int k = (buf[3] << 8) | buf[2];

	ESIL_A("r%d,", r);
	__generic_ld_st(op, "ram", 0, 1, 0, k, 1);
}

INST_HANDLER(lpm) { // LPM
	// LPM Rd, Z
	// LPM Rd, Z+
	if (len < 2) {
		return;
	}
	ut16 ins = (((ut16)buf[1]) << 8) | ((ut16)buf[0]);
	// read program memory
	__generic_ld_st(
		op, "prog",
		'z', // index register Y/Z
		1, // use RAMP* registers
		(ins & 0xfe0f) == 0x9005
			? 1 // post incremented
			: 0, // no increment
		0, // not offset
		0); // load operation (!st)
	// load register
	ESIL_A("r%d,=,",
		(ins == 0x95c8)
			? 0 // LPM (r0)
			: ((buf[0] >> 4) & 0xf) // LPM Rd
				| ((buf[1] & 0x1) << 4));
}

INST_HANDLER(lsr) { // LSR Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	ESIL_A("r%d,0x1,&,cf,:=,", d); // C = Rd0
	ESIL_A("1,r%d,>>=,", d); // 0: R=(Rd >> 1)
	ESIL_A("$z,zf,:=,"); // Z
	ESIL_A("0,nf,:=,"); // N
	ESIL_A("cf,vf,:=,"); // V
	ESIL_A("cf,sf,:=,"); // S
}

INST_HANDLER(mov) { // MOV Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[1] << 4) & 0x10) | ((buf[0] >> 4) & 0x0f);
	const ut32 r = ((buf[1] << 3) & 0x10) | (buf[0] & 0x0f);
	ESIL_A("r%d,r%d,=,", r, d);
}

INST_HANDLER(movw) { // MOVW Rd+1:Rd, Rr+1:Rr
	if (len < 1) {
		return;
	}
	const ut32 d = (buf[0] & 0xf0) >> 3;
	const ut32 r = (buf[0] & 0x0f) << 1;
	ESIL_A("r%d,r%d,=,r%d,r%d,=,", r, d, r + 1, d + 1);
}

INST_HANDLER(mul) { // MUL Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[1] << 4) & 0x10) | ((buf[0] >> 4) & 0x0f);
	const ut32 r = ((buf[1] << 3) & 0x10) | (buf[0] & 0x0f);

	ESIL_A("8,r%d,r%d,*,DUP,r0,=,>>,r1,=,", r, d); // 0: r1_r0 = rd * rr
	ESIL_A("8,r1,<<,r0,|,DUP,0x8000,&,!,!,cf,:=,"); // C = R/15
	ESIL_A("!,zf,:="); // Z = !R
}

INST_HANDLER(muls) { // MULS Rd, Rr
	if (len < 1) {
		return;
	}
	const ut32 d = (buf[0] >> 4 & 0x0f) + 16;
	const ut32 r = (buf[0] & 0x0f) + 16;

	ESIL_A("8,");
	ESIL_A("r%d,DUP,0x80,&,?{,0xff00,|,},", d); // sign extension Rd
	ESIL_A("r%d,DUP,0x80,&,?{,0xff00,|,},", r); // sign extension Rr
	ESIL_A("*,DUP,r0,=,>>,r1,=,"); // 0: (Rd*Rr)

	ESIL_A("8,r1,<<,r0,|,DUP,0x8000,&,!,!,cf,:=,"); // C = R/16
	ESIL_A("!,zf,:="); // Z = !R
}

INST_HANDLER(mulsu) { // MULSU Rd, Rr
	if (len < 1) {
		return;
	}
	const ut32 d = (buf[0] >> 4 & 0x07) + 16;
	const ut32 r = (buf[0] & 0x07) + 16;

	ESIL_A("8,");
	ESIL_A("r%d,DUP,0x80,&,?{,0xff00,|,},", d); // sign extension Rd
	ESIL_A("r%d,*,DUP,r0,=,>>,r1,=,", r); // 0: (Rd*Rr)

	ESIL_A("8,r1,<<,r0,|,DUP,0x8000,&,!,!,cf,:=,"); // C = R/16
	ESIL_A("!,zf,:="); // Z = !R
}

INST_HANDLER(neg) { // NEG Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	ESIL_A("r%d,0x00,-,0xff,&,", d); // 0: (0-Rd)
	ESIL_A("DUP,r%d,0xff,^,|,0x08,&,!,!,hf,=,", d); // H
	ESIL_A("DUP,0x80,-,!,vf,=,"); // V
	ESIL_A("DUP,0x80,&,!,!,nf,=,"); // N
	ESIL_A("DUP,!,zf,=,"); // Z
	ESIL_A("DUP,!,!,cf,=,"); // C
	ESIL_A("vf,nf,^,sf,=,"); // S
	ESIL_A("r%d,=,", d); // Rd = result
}

INST_HANDLER(nop) { // NOP
	ESIL_A(",,");
}

INST_HANDLER(or) { // OR Rd, Rr
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A("r%d,r%d,|=,", r, d); // 0: (Rd | Rr)
	ESIL_A("$z,zf,:=,"); // Z
	ESIL_A("r%d,&,!,!,nf,:=,", d); // N
	ESIL_A("0,vf,:=,"); // V
	ESIL_A("nf,sf,:="); // S
}

INST_HANDLER(ori) { // ORI Rd, K
	// SBR Rd, K
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) + 16;
	const ut32 k = (buf[0] & 0xf) | ((buf[1] & 0xf) << 4);
	ESIL_A("%d,r%d,|=,", k, d); // 0: (Rd | k)
	ESIL_A("$z,zf,:=,"); // Z
	ESIL_A("r%d,0x80,&,!,!,nf,:=,", d); // N
	ESIL_A("0,vf,:=,"); // V
	ESIL_A("nf,sf,:="); // S
}

INST_HANDLER(out) { // OUT A, Rr
	if (len < 2) {
		return;
	}
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 0x01) << 4);
	int a = (buf[0] & 0x0f) | ((buf[1] & 0x6) << 3);
	RzStrBuf *io_dst = __generic_io_dest(a, 1, cpu);
	ESIL_A("r%d,%s,", r, rz_strbuf_get(io_dst));
	rz_strbuf_free(io_dst);
}

INST_HANDLER(pop) { // POP Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[1] & 0x1) << 4) | ((buf[0] >> 4) & 0xf);
	__generic_pop(op, 1);
	ESIL_A("r%d,=,", d); // store in Rd
}

INST_HANDLER(push) { // PUSH Rr
	if (len < 2) {
		return;
	}
	int r = ((buf[1] & 0x1) << 4) | ((buf[0] >> 4) & 0xf);
	ESIL_A("r%d,", r); // load Rr
	__generic_push(op, 1); // push it into stack
}

INST_HANDLER(rcall) { // RCALL k
	if (len < 2) {
		return;
	}
	// target address
	ut64 jump = op->addr + ((((((buf[1] & 0xf) << 8) | buf[0]) << 1) | (((buf[1] & 0x8) ? ~((int)0x1fff) : 0))) + 2);
	// esil
	ESIL_A("pc,"); // esil already points to next
		       // instruction (@ret)
	__generic_push(op, CPU_PC_SIZE(cpu)); // push @ret addr
	ESIL_A("%" PFMT64d ",pc,=,", jump); // jump!
}

INST_HANDLER(ret) { // RET
	// esil
	__generic_pop(op, CPU_PC_SIZE(cpu));
	ESIL_A("pc,=,"); // jump!
}

INST_HANDLER(reti) { // RETI
	// first perform a standard 'ret'
	INST_CALL(ret);

	// RETI: The I-bit is cleared by hardware after an interrupt
	// has occurred, and is set by the RETI instruction to enable
	// subsequent interrupts
	ESIL_A("1,if,=,");
}

INST_HANDLER(rjmp) { // RJMP k
	st32 loc = (((((buf[1] & 0xf) << 9) | (buf[0] << 1))) | (buf[1] & 0x8 ? ~(0x1fff) : 0)) + 2;
	ut64 jump = op->addr + loc;
	ESIL_A("%" PFMT64d ",pc,=,", jump);
}

INST_HANDLER(ror) { // ROR Rd
	const ut32 d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	ESIL_A("cf,nf,:=,"); // N
	ESIL_A("r%d,0x1,&,", d); // C
	ESIL_A("1,r%d,>>,7,cf,<<,|,r%d,=,cf,:=,", d, d); // 0: (Rd>>1) | (cf<<7)
	ESIL_A("$z,zf,:=,"); // Z
	ESIL_A("nf,cf,^,vf,:=,"); // V
	ESIL_A("vf,nf,^,sf,:="); // S
}

INST_HANDLER(sbc) { // SBC Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 r = (buf[0] & 0x0f) | ((buf[1] & 0x2) << 3);
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	ESIL_A("cf,r%d,+,r%d,-=,", r, d); // 0: (Rd-Rr-C)
	ESIL_A("$z,zf,:=,");
	ESIL_A("3,$b,hf,:=,");
	ESIL_A("8,$b,cf,:=,");
	ESIL_A("7,$o,vf,:=,");
	ESIL_A("0x80,r%d,&,!,!,nf,:=,", d);
	ESIL_A("vf,nf,^,sf,:=");
}

INST_HANDLER(sbci) { // SBCI Rd, k
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) + 16;
	const ut32 k = ((buf[1] & 0xf) << 4) | (buf[0] & 0xf);

	ESIL_A("cf,%d,+,r%d,-=,", k, d); // 0: (Rd-k-C)
	ESIL_A("$z,zf,:=,");
	ESIL_A("3,$b,hf,:=,");
	ESIL_A("8,$b,cf,:=,");
	ESIL_A("7,$o,vf,:=,");
	ESIL_A("0x80,r%d,&,!,!,nf,:=,", d);
	ESIL_A("vf,nf,^,sf,:=");
}

INST_HANDLER(sub) { // SUB Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	const ut32 r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);

	ESIL_A("r%d,r%d,-=,", r, d); // 0: (Rd-k)
	ESIL_A("$z,zf,:=,");
	ESIL_A("3,$b,hf,:=,");
	ESIL_A("8,$b,cf,:=,");
	ESIL_A("7,$o,vf,:=,");
	ESIL_A("0x80,r%d,&,!,!,nf,:=,", d);
	ESIL_A("vf,nf,^,sf,:=");
}

INST_HANDLER(subi) { // SUBI Rd, k
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) + 16;
	const ut32 k = ((buf[1] & 0xf) << 4) | (buf[0] & 0xf);

	ESIL_A("%d,r%d,-=,", k, d); // 0: (Rd-k)
	ESIL_A("$z,zf,:=,");
	ESIL_A("3,$b,hf,:=,");
	ESIL_A("8,$b,cf,:=,");
	ESIL_A("7,$o,vf,:=,");
	ESIL_A("0x80,r%d,&,!,!,nf,:=,", d);
	ESIL_A("vf,nf,^,sf,:=");
}

INST_HANDLER(sbi) { // SBI A, b
	if (len < 1) {
		return;
	}
	int a = (buf[0] >> 3) & 0x1f;
	int b = buf[0] & 0x07;
	RzStrBuf *io_port;

	// read port a and clear bit b
	io_port = __generic_io_dest(a, 0, cpu);
	ESIL_A("0xff,%d,1,<<,|,%s,&,", b, rz_strbuf_get(io_port));
	rz_strbuf_free(io_port);

	// write result to port a
	io_port = __generic_io_dest(a, 1, cpu);
	ESIL_A("%s,", rz_strbuf_get(io_port));
	rz_strbuf_free(io_port);
}

INST_HANDLER(sbix) { // SBIC A, b
	// SBIS A, b
	if (len < 2) {
		return;
	}
	int a = (buf[0] >> 3) & 0x1f;
	int b = buf[0] & 0x07;
	RzStrBuf *io_port;

	// read port a and clear bit b
	io_port = __generic_io_dest(a, 0, cpu);
	ESIL_A("%d,1,<<,%s,&,", b, rz_strbuf_get(io_port)); // IO(A,b)
	ESIL_A((buf[1] & 0xe) == 0xc
			? "!," // SBIC => branch if 0
			: "!,!,"); // SBIS => branch if 1
	ESIL_A("?{,%" PFMT64d ",pc,=,},", op->jump); // ?true => jmp
	rz_strbuf_free(io_port);
}

INST_HANDLER(sbiw) { // SBIW Rd+1:Rd, K
	if (len < 1) {
		return;
	}
	int d = ((buf[0] & 0x30) >> 3) + 24;
	int k = (buf[0] & 0xf) | ((buf[0] >> 2) & 0x30);
	ESIL_A("7,r%d,>>,", d + 1); // remember previous highest bit
	ESIL_A("8,%d,8,r%d,<<,r%d,|,-,DUP,r%d,=,>>,r%d,=,", k, d + 1, d, d, d + 1); // 0(Rd+1_Rd - k)
	ESIL_A("$z,zf,:=,");
	ESIL_A("DUP,!,7,r%d,>>,&,cf,:=,", d + 1); // C
	ESIL_A("r%d,0x80,&,!,!,nf,:=,", d + 1); // N
	ESIL_A("7,r%d,>>,!,&,vf,:=,", d + 1); // V
	ESIL_A("vf,nf,^,sf,:="); // S
}

INST_HANDLER(sbrx) { // SBRC Rr, b
	// SBRS Rr, b
	if (len < 2) {
		return;
	}
	int b = buf[0] & 0x7;
	int r = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x01) << 4);
	ESIL_A("%d,1,<<,r%d,&,", b, r); // Rr(b)
	ESIL_A((buf[1] & 0xe) == 0xc
			? "!," // SBRC => branch if cleared
			: "!,!,"); // SBRS => branch if set
	ESIL_A("?{,%" PFMT64d ",pc,=,},", op->jump); // ?true => jmp
}

INST_HANDLER(sleep) { // SLEEP
	ESIL_A("BREAK");
}

INST_HANDLER(spm) { // SPM Z+
	ut64 spmcsr;

	// read SPM Control Register (SPMCR)
	rz_analysis_esil_reg_read(analysis->esil, "spmcsr", &spmcsr, NULL);

	// clear SPMCSR
	ESIL_A("0x7c,spmcsr,&=,");

	// decide action depending on the old value of SPMCSR
	switch (spmcsr & 0x7f) {
	case 0x03: // PAGE ERASE
		// invoke SPM_CLEAR_PAGE (erases target page writing
		// the 0xff value
		ESIL_A("16,rampz,<<,z,+,"); // push target address
		ESIL_A("SPM_PAGE_ERASE,"); // do magic
		break;

	case 0x01: // FILL TEMPORARY BUFFER
		ESIL_A("r1,r0,"); // push data
		ESIL_A("z,"); // push target address
		ESIL_A("SPM_PAGE_FILL,"); // do magic
		break;

	case 0x05: // WRITE PAGE
		ESIL_A("16,rampz,<<,z,+,"); // push target address
		ESIL_A("SPM_PAGE_WRITE,"); // do magic
		break;

	default:
		RZ_LOG_DEBUG("SPM: I dont know what to do with SPMCSR %02" PFMT64x ".\n", spmcsr);
		break;
	}
}

INST_HANDLER(st) { // ST X, Rr
	// ST X+, Rr
	// ST -X, Rr
	if (len < 2) {
		return;
	}
	// load register
	ESIL_A("r%d,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// write in memory
	__generic_ld_st(
		op, "ram",
		'x', // use index register X
		0, // no use RAMP* registers
		(buf[0] & 0xf) == 0xe
			? -1 // pre decremented
			: (buf[0] & 0xf) == 0xd
			? 1 // post increment
			: 0, // no increment
		0, // offset always 0
		1); // store operation (st)
}

INST_HANDLER(std) { // ST Y, Rr	ST Z, Rr
	// ST Y+, Rr	ST Z+, Rr
	// ST -Y, Rr	ST -Z, Rr
	// ST Y+q, Rr	ST Z+q, Rr
	if (len < 2) {
		return;
	}
	// load register
	ESIL_A("r%d,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// write in memory
	__generic_ld_st(
		op, "ram",
		buf[0] & 0x8 ? 'y' : 'z', // index register Y/Z
		0, // no use RAMP* registers
		!(buf[1] & 0x10)
			? 0 // no increment
			: buf[0] & 0x1
			? 1 // post incremented
			: -1, // pre decremented
		!(buf[1] & 0x10)
			? (buf[1] & 0x20) // offset
				| ((buf[1] & 0xc) << 1) | (buf[0] & 0x7)
			: 0, // no offset
		1); // load operation (!st)
}

INST_HANDLER(swap) { // SWAP Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[1] & 0x1) << 4) | ((buf[0] >> 4) & 0xf);
	ESIL_A("4,r%d,>>,0x0f,&,", d); // (Rd >> 4) & 0xf
	ESIL_A("4,r%d,<<,0xf0,&,", d); // (Rd >> 4) & 0xf
	ESIL_A("|,"); // S[0] | S[1]
	ESIL_A("r%d,=,", d); // Rd = result
}

OPCODE_DESC opcodes[] = {
	//         op     mask    select  cycles  size type
	INST_DECL(break, 0xffff, 0x9698, 1, 2, TRAP), // BREAK
	INST_DECL(eicall, 0xffff, 0x9519, 0, 2, UCALL), // EICALL
	INST_DECL(eijmp, 0xffff, 0x9419, 0, 2, UJMP), // EIJMP
	INST_DECL(icall, 0xffff, 0x9509, 0, 2, UCALL), // ICALL
	INST_DECL(ijmp, 0xffff, 0x9409, 0, 2, UJMP), // IJMP
	INST_DECL(lpm, 0xffff, 0x95c8, 3, 2, LOAD), // LPM
	INST_DECL(nop, 0xffff, 0x0000, 1, 2, NOP), // NOP
	INST_DECL(ret, 0xffff, 0x9508, 4, 2, RET), // RET
	INST_DECL(reti, 0xffff, 0x9518, 4, 2, RET), // RETI
	INST_DECL(sleep, 0xffff, 0x9588, 1, 2, NOP), // SLEEP
	INST_DECL(spm, 0xffff, 0x95e8, 1, 2, TRAP), // SPM ...
	INST_DECL(bclr, 0xff8f, 0x9488, 1, 2, MOV), // BCLR s
	INST_DECL(bset, 0xff8f, 0x9408, 1, 2, MOV), // BSET s
	INST_DECL(fmul, 0xff88, 0x0308, 2, 2, MUL), // FMUL Rd, Rr
	INST_DECL(fmuls, 0xff88, 0x0380, 2, 2, MUL), // FMULS Rd, Rr
	INST_DECL(fmulsu, 0xff88, 0x0388, 2, 2, MUL), // FMULSU Rd, Rr
	INST_DECL(mulsu, 0xff88, 0x0300, 2, 2, AND), // MUL Rd, Rr
	INST_DECL(des, 0xff0f, 0x940b, 0, 2, CRYPTO), // DES k
	INST_DECL(adiw, 0xff00, 0x9600, 2, 2, ADD), // ADIW Rd+1:Rd, K
	INST_DECL(sbiw, 0xff00, 0x9700, 2, 2, SUB), // SBIW Rd+1:Rd, K
	INST_DECL(cbi, 0xff00, 0x9800, 1, 2, IO), // CBI A, K
	INST_DECL(sbi, 0xff00, 0x9a00, 1, 2, IO), // SBI A, K
	INST_DECL(movw, 0xff00, 0x0100, 1, 2, MOV), // MOVW Rd+1:Rd, Rr+1:Rr
	INST_DECL(muls, 0xff00, 0x0200, 2, 2, AND), // MUL Rd, Rr
	INST_DECL(asr, 0xfe0f, 0x9405, 1, 2, SAR), // ASR Rd
	INST_DECL(com, 0xfe0f, 0x9400, 1, 2, NOT), // COM Rd
	INST_DECL(dec, 0xfe0f, 0x940a, 1, 2, SUB), // DEC Rd
	INST_DECL(elpm, 0xfe0f, 0x9006, 0, 2, LOAD), // ELPM Rd, Z
	INST_DECL(elpm, 0xfe0f, 0x9007, 0, 2, LOAD), // ELPM Rd, Z+
	INST_DECL(inc, 0xfe0f, 0x9403, 1, 2, ADD), // INC Rd
	INST_DECL(lac, 0xfe0f, 0x9206, 2, 2, LOAD), // LAC Z, Rd
	INST_DECL(las, 0xfe0f, 0x9205, 2, 2, LOAD), // LAS Z, Rd
	INST_DECL(lat, 0xfe0f, 0x9207, 2, 2, LOAD), // LAT Z, Rd
	INST_DECL(ld, 0xfe0f, 0x900c, 0, 2, LOAD), // LD Rd, X
	INST_DECL(ld, 0xfe0f, 0x900d, 0, 2, LOAD), // LD Rd, X+
	INST_DECL(ld, 0xfe0f, 0x900e, 0, 2, LOAD), // LD Rd, -X
	INST_DECL(lds, 0xfe0f, 0x9000, 0, 4, LOAD), // LDS Rd, k
	INST_DECL(sts, 0xfe0f, 0x9200, 2, 4, STORE), // STS k, Rr
	INST_DECL(lpm, 0xfe0f, 0x9004, 3, 2, LOAD), // LPM Rd, Z
	INST_DECL(lpm, 0xfe0f, 0x9005, 3, 2, LOAD), // LPM Rd, Z+
	INST_DECL(lsr, 0xfe0f, 0x9406, 1, 2, SHR), // LSR Rd
	INST_DECL(neg, 0xfe0f, 0x9401, 2, 2, SUB), // NEG Rd
	INST_DECL(pop, 0xfe0f, 0x900f, 2, 2, POP), // POP Rd
	INST_DECL(push, 0xfe0f, 0x920f, 0, 2, PUSH), // PUSH Rr
	INST_DECL(ror, 0xfe0f, 0x9407, 1, 2, SAR), // ROR Rd
	INST_DECL(st, 0xfe0f, 0x920c, 2, 2, STORE), // ST X, Rr
	INST_DECL(st, 0xfe0f, 0x920d, 0, 2, STORE), // ST X+, Rr
	INST_DECL(st, 0xfe0f, 0x920e, 0, 2, STORE), // ST -X, Rr
	INST_DECL(swap, 0xfe0f, 0x9402, 1, 2, SAR), // SWAP Rd
	INST_DECL(call, 0xfe0e, 0x940e, 0, 4, CALL), // CALL k
	INST_DECL(jmp, 0xfe0e, 0x940c, 2, 4, JMP), // JMP k
	INST_DECL(bld, 0xfe08, 0xf800, 1, 2, MOV), // BLD Rd, b
	INST_DECL(bst, 0xfe08, 0xfa00, 1, 2, MOV), // BST Rd, b
	INST_DECL(sbix, 0xff00, 0x9900, 2, 2, CJMP), // SBIC A, b
	INST_DECL(sbix, 0xff00, 0x9b00, 2, 2, CJMP), // SBIS A, b
	INST_DECL(sbrx, 0xfe08, 0xfc00, 2, 2, CJMP), // SBRC Rr, b
	INST_DECL(sbrx, 0xfe08, 0xfe00, 2, 2, CJMP), // SBRS Rr, b
	INST_DECL(ldd, 0xfe07, 0x9001, 0, 2, LOAD), // LD Rd, Y/Z+
	INST_DECL(ldd, 0xfe07, 0x9002, 0, 2, LOAD), // LD Rd, -Y/Z
	INST_DECL(std, 0xfe07, 0x9201, 0, 2, STORE), // ST Y/Z+, Rr
	INST_DECL(std, 0xfe07, 0x9202, 0, 2, STORE), // ST -Y/Z, Rr
	INST_DECL(adc, 0xfc00, 0x1c00, 1, 2, ADD), // ADC Rd, Rr
	INST_DECL(add, 0xfc00, 0x0c00, 1, 2, ADD), // ADD Rd, Rr
	INST_DECL(and, 0xfc00, 0x2000, 1, 2, AND), // AND Rd, Rr
	INST_DECL(brbx, 0xfc00, 0xf000, 0, 2, CJMP), // BRBS s, k
	INST_DECL(brbx, 0xfc00, 0xf400, 0, 2, CJMP), // BRBC s, k
	INST_DECL(cp, 0xfc00, 0x1400, 1, 2, CMP), // CP Rd, Rr
	INST_DECL(cpc, 0xfc00, 0x0400, 1, 2, CMP), // CPC Rd, Rr
	INST_DECL(cpse, 0xfc00, 0x1000, 0, 2, CJMP), // CPSE Rd, Rr
	INST_DECL(eor, 0xfc00, 0x2400, 1, 2, XOR), // EOR Rd, Rr
	INST_DECL(mov, 0xfc00, 0x2c00, 1, 2, MOV), // MOV Rd, Rr
	INST_DECL(mul, 0xfc00, 0x9c00, 2, 2, AND), // MUL Rd, Rr
	INST_DECL(or, 0xfc00, 0x2800, 1, 2, OR), // OR Rd, Rr
	INST_DECL(sbc, 0xfc00, 0x0800, 1, 2, SUB), // SBC Rd, Rr
	INST_DECL(sub, 0xfc00, 0x1800, 1, 2, SUB), // SUB Rd, Rr
	INST_DECL(in, 0xf800, 0xb000, 1, 2, IO), // IN Rd, A
	INST_DECL(out, 0xf800, 0xb800, 1, 2, IO), // OUT A, Rr
	INST_DECL(andi, 0xf000, 0x7000, 1, 2, AND), // ANDI Rd, K
	INST_DECL(cpi, 0xf000, 0x3000, 1, 2, CMP), // CPI Rd, K
	INST_DECL(ldi, 0xf000, 0xe000, 1, 2, LOAD), // LDI Rd, K
	INST_DECL(ori, 0xf000, 0x6000, 1, 2, OR), // ORI Rd, K
	INST_DECL(rcall, 0xf000, 0xd000, 0, 2, CALL), // RCALL k
	INST_DECL(rjmp, 0xf000, 0xc000, 2, 2, JMP), // RJMP k
	INST_DECL(sbci, 0xf000, 0x4000, 1, 2, SUB), // SBC Rd, Rr
	INST_DECL(subi, 0xf000, 0x5000, 1, 2, SUB), // SUBI Rd, Rr
	INST_DECL(ldd, 0xd200, 0x8000, 0, 2, LOAD), // LD Rd, Y/Z+q
	INST_DECL(std, 0xd200, 0x8200, 0, 2, STORE), // ST Y/Z+q, Rr
	// INST_DECL(lds16,  0xf800, 0xa000, 1, 2, LOAD), // LDS Rd, k

	INST_LAST
};

static OPCODE_DESC *avr_op_analyze(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, CPU_MODEL *cpu) {
	OPCODE_DESC *opcode_desc;
	if (len < 2) {
		return NULL;
	}
	ut16 ins = (buf[1] << 8) | buf[0];
	int fail;
	char *t;

	// process opcode
	for (opcode_desc = opcodes; opcode_desc->handler; opcode_desc++) {
		if ((ins & opcode_desc->mask) == opcode_desc->selector) {
			fail = 0;

			// start void esil expression
			rz_strbuf_set(&op->esil, "");

			// handle opcode
			opcode_desc->handler(analysis, op, buf, len, &fail, cpu);
			if (fail) {
				break;
			} else if (opcode_desc->cycles <= 0) {
				opcode_desc->cycles = 2;
			}

			// remove trailing coma (COMETE LA COMA)
			t = rz_strbuf_get(&op->esil);
			if (t && strlen(t) > 1) {
				t += strlen(t) - 1;
				if (*t == ',') {
					*t = '\0';
				}
			}

			return opcode_desc;
		}
	}

	return NULL;
}

static bool avr_custom_des(RzAnalysisEsil *esil) {
	if (!esil || !esil->analysis || !esil->analysis->reg) {
		return false;
	}
	ut64 arg;
	if (!__esil_pop_argument(esil, &arg)) {
		return false;
	}
	int round = arg;
	if (round < 0 || round > 15) {
		return false;
	}
	ut64 decrypt;
	rz_analysis_esil_reg_read(esil, "hf", &decrypt, NULL);
	if (decrypt) {
		round = 15 - round;
	}
	ut8 regs[0x10];
	static const char *reg_names[] = {
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
	};
	for (size_t i = 0; i < sizeof(regs); i++) {
		ut64 v = 0;
		rz_analysis_esil_reg_read(esil, reg_names[i], &v, NULL);
		regs[i] = v;
	}

	// Atmel's "AVR Instruction Set Manual" unfortunately is very ambiguous
	// regarding the details of this instruction and leaves the most interesting
	// questions open, especially what intermediate results are stored and how.
	// The below implementation has been developed based on observing the exact
	// results in the Simulator in Atmel/Microchip Studio emulating ATxmega128A1.
	// Things may seem very strange (especially hi/lo swapping), but it is all
	// intended to get the right behavior!
	ut32 buf_hi = rz_read_at_le32(regs, 0);
	ut32 buf_lo = rz_read_at_le32(regs, 4);
	ut32 key_orig_hi = rz_read_at_le32(regs, 8);
	ut32 key_orig_lo = rz_read_at_le32(regs, 0xc);
	ut32 key_lo = key_orig_lo;
	ut32 key_hi = key_orig_hi;
	rz_des_permute_key(&key_lo, &key_hi);
	int i = round;
	if (!decrypt) {
		rz_des_shift_key(i, false, &key_lo, &key_hi);
	}
	ut32 round_key_lo, round_key_hi;
	rz_des_pc2(&round_key_lo, &round_key_hi, key_lo, key_hi);
	if (decrypt) {
		rz_des_shift_key(i, true, &key_lo, &key_hi);
	}
	rz_des_permute_block0(&buf_lo, &buf_hi);
	rz_des_round(&buf_lo, &buf_hi, &round_key_lo, &round_key_hi);
	if (arg < 15) {
		rz_des_permute_block1(&buf_lo, &buf_hi);
	} else {
		rz_des_permute_block1(&buf_hi, &buf_lo);
		buf_lo ^= buf_hi;
		buf_hi ^= buf_lo;
		buf_lo ^= buf_hi;
	}
	rz_des_permute_key_inv(&key_lo, &key_hi); // un-permute so the rz_des_permute_key() in the next round will restore it
	key_lo |= key_orig_hi & 0x01010101; // restore the parity bits that got lost in PC-1
	key_hi |= key_orig_lo & 0x01010101;

	rz_write_at_le32(regs, buf_hi, 0);
	rz_write_at_le32(regs, buf_lo, 4);
	rz_write_at_le32(regs, key_lo, 8);
	rz_write_at_le32(regs, key_hi, 0xc);
	for (size_t i = 0; i < sizeof(regs); i++) {
		ut64 v = regs[i];
		rz_analysis_esil_reg_write(esil, reg_names[i], v);
	}
	return true;
}

// ESIL operation SPM_PAGE_ERASE
static bool avr_custom_spm_page_erase(RzAnalysisEsil *esil) {
	CPU_MODEL *cpu;
	ut8 c;
	ut64 addr, page_size_bits, i;

	// sanity check
	if (!esil || !esil->analysis || !esil->analysis->reg) {
		return false;
	}

	// get target address
	if (!__esil_pop_argument(esil, &addr)) {
		return false;
	}

	// get details about current MCU and fix input address
	cpu = get_cpu_model(esil->analysis->cpu);
	page_size_bits = const_get_value(const_by_name(cpu, CPU_CONST_PARAM, "page_size"));

	// align base address to page_size_bits
	addr &= ~(MASK(page_size_bits));

	// perform erase
	// RZ_LOG_DEBUG("SPM_PAGE_ERASE %ld bytes @ 0x%08" PFMT64x ".\n", page_size, addr);
	c = 0xff;
	for (i = 0; i < (1ULL << page_size_bits); i++) {
		rz_analysis_esil_mem_write(
			esil, (addr + i) & CPU_PC_MASK(cpu), &c, 1);
	}

	return true;
}

// ESIL operation SPM_PAGE_FILL
static bool avr_custom_spm_page_fill(RzAnalysisEsil *esil) {
	CPU_MODEL *cpu;
	ut64 addr, page_size_bits, i;
	ut8 r0, r1;

	// sanity check
	if (!esil || !esil->analysis || !esil->analysis->reg) {
		return false;
	}

	// get target address, r0, r1
	if (!__esil_pop_argument(esil, &addr)) {
		return false;
	}

	if (!__esil_pop_argument(esil, &i)) {
		return false;
	}
	r0 = i;

	if (!__esil_pop_argument(esil, &i)) {
		return false;
	}
	r1 = i;

	// get details about current MCU and fix input address
	cpu = get_cpu_model(esil->analysis->cpu);
	page_size_bits = const_get_value(const_by_name(cpu, CPU_CONST_PARAM, "page_size"));

	// align and crop base address
	addr &= (MASK(page_size_bits) ^ 1);

	// perform write to temporary page
	// RZ_LOG_DEBUG("SPM_PAGE_FILL bytes (%02x, %02x) @ 0x%08" PFMT64x ".\n", r1, r0, addr);
	rz_analysis_esil_mem_write(esil, addr++, &r0, 1);
	rz_analysis_esil_mem_write(esil, addr++, &r1, 1);

	return true;
}

// ESIL operation SPM_PAGE_WRITE
static bool avr_custom_spm_page_write(RzAnalysisEsil *esil) {
	CPU_MODEL *cpu;
	char *t = NULL;
	ut64 addr, page_size_bits, tmp_page;

	// sanity check
	if (!esil || !esil->analysis || !esil->analysis->reg) {
		return false;
	}

	// get target address
	if (!__esil_pop_argument(esil, &addr)) {
		return false;
	}

	// get details about current MCU and fix input address and base address
	// of the internal temporary page
	cpu = get_cpu_model(esil->analysis->cpu);
	page_size_bits = const_get_value(const_by_name(cpu, CPU_CONST_PARAM, "page_size"));
	rz_analysis_esil_reg_read(esil, "_page", &tmp_page, NULL);

	// align base address to page_size_bits
	addr &= (~(MASK(page_size_bits)) & CPU_PC_MASK(cpu));

	// perform writing
	// RZ_LOG_DEBUG("SPM_PAGE_WRITE %ld bytes @ 0x%08" PFMT64x ".\n", page_size, addr);
	if (!(t = malloc(1 << page_size_bits))) {
		RZ_LOG_ERROR("Cannot alloc a buffer for copying the temporary page.\n");
		return false;
	}
	rz_analysis_esil_mem_read(esil, tmp_page, (ut8 *)t, 1 << page_size_bits);
	rz_analysis_esil_mem_write(esil, addr, (ut8 *)t, 1 << page_size_bits);

	return true;
}

static int esil_avr_hook_reg_write(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	CPU_MODEL *cpu;

	if (!esil || !esil->analysis) {
		return 0;
	}

	// select cpu info
	cpu = get_cpu_model(esil->analysis->cpu);

	// crop registers and force certain values
	if (!strcmp(name, "pc")) {
		*val &= CPU_PC_MASK(cpu);
	} else if (!strcmp(name, "pcl")) {
		if (cpu->pc < 8) {
			*val &= MASK(8);
		}
	} else if (!strcmp(name, "pch")) {
		*val = cpu->pc > 8
			? *val & MASK(cpu->pc - 8)
			: 0;
	}

	return 0;
}

RZ_IPI int rz_avr_esil_init(RzAnalysisEsil *esil) {
	if (!esil) {
		return false;
	}
	rz_analysis_esil_set_op(esil, "des", avr_custom_des, 0, 0, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM); // better meta info plz
	rz_analysis_esil_set_op(esil, "SPM_PAGE_ERASE", avr_custom_spm_page_erase, 0, 0, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "SPM_PAGE_FILL", avr_custom_spm_page_fill, 0, 0, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "SPM_PAGE_WRITE", avr_custom_spm_page_write, 0, 0, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	esil->cb.hook_reg_write = esil_avr_hook_reg_write;

	return true;
}

RZ_IPI int rz_avr_esil_fini(RzAnalysisEsil *esil) {
	return true;
}

RZ_IPI void rz_avr_esil_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len) {
	// select cpu info
	CPU_MODEL *cpu = get_cpu_model(analysis->cpu);
	avr_op_analyze(analysis, op, addr, buf, len, cpu);
}
