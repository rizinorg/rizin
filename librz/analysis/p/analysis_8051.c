// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2019 dkreuter <dkreuter@gmail.com>
// SPDX-FileCopyrightText: 2013-2019 astuder <github@adrianstuder.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

#include <8051_ops.h>
#include "../asm/arch/8051/8051_disas.c"

typedef struct {
	const char *name;
	ut32 map_code;
	ut32 map_idata;
	ut32 map_sfr;
	ut32 map_xdata;
	ut32 map_pdata;
} i8051_cpu_model;

static i8051_cpu_model cpu_models[] = {
	{ .name = "8051-generic",
		.map_code = 0,
		.map_idata = 0x10000000,
		.map_sfr = 0x10000180,
		.map_xdata = 0x20000000,
		.map_pdata = 0x00000000 },
	{ .name = "8051-shared-code-xdata",
		.map_code = 0,
		.map_idata = 0x10000000,
		.map_sfr = 0x10000180,
		.map_xdata = 0x00000000,
		.map_pdata = 0x00000000 },
	{
		.name = NULL // last entry
	}
};

typedef enum i8051_registers_t {
	I8051_R0 = 0,
	I8051_R1,
	I8051_R2,
	I8051_R3,
	I8051_R4,
	I8051_R5,
	I8051_R6,
	I8051_R7,
	I8051_SP = 0x81,
	I8051_DPL,
	I8051_DPH,
	I8051_PCON = 0x87,
	I8051_TCON,
	I8051_TMOD,
	I8051_TL0,
	I8051_TL1,
	I8051_TH0,
	I8051_TH1,
	I8051_PSW = 0xD0,
	I8051_ACC = 0xE0,
	I8051_B = 0xF0
} I8051_REGISTERS;

static const i8051_cpu_model *cpu_curr_model = NULL;

static bool i8051_reg_write(RzILVM *vm, const char *regname, ut32 num) {
	rz_return_val_if_fail(vm && regname, false);
	RzILVal *val = rz_il_hash_find_val_by_name(vm, regname);
	if (!val) {
		return false;
	}
	for (int i = 0; i < vm->data_size; ++i) {
		rz_il_bv_set(val->data.bv, i, (num & 1) ? true : false);
		num >>= 1;
	}
	return true;
}

static ut32 i8051_reg_read(RzILVM *vm, const char *regname) {
	rz_return_val_if_fail(vm && regname, false);
	RzILVal *val = rz_il_hash_find_val_by_name(vm, regname);
	if (!val) {
		return 0;
	}
	return rz_il_bv_to_ut32(val->data.bv);
}

static ut32 map_direct_addr(RzILVM *vm, ut8 addr) {
	if (addr < 0x80) {
		return addr + i8051_reg_read(vm, "_idata");
	} else {
		return addr + i8051_reg_read(vm, "_sfr");
	}
}

typedef struct {
	RzIODesc *desc;
	ut32 addr;
	const char *name;
} i8051_map_entry;

static const int I8051_IDATA = 0;
static const int I8051_SFR = 1;
static const int I8051_XDATA = 2;

static i8051_map_entry mem_map[3] = {
	{ NULL, UT32_MAX, "idata" },
	{ NULL, UT32_MAX, "sfr" },
	{ NULL, UT32_MAX, "xdata" }
};

static void map_cpu_memory(RzAnalysis *analysis, int entry, ut32 addr, ut32 size, bool force) {
	RzIODesc *desc = mem_map[entry].desc;
	if (desc && analysis->iob.fd_get_name(analysis->iob.io, desc->fd)) {
		if (force || addr != mem_map[entry].addr) {
			// reallocate mapped memory if address changed
			analysis->iob.fd_remap(analysis->iob.io, desc->fd, addr);
		}
	} else {
		// allocate memory for address space
		char *mstr = rz_str_newf("malloc://%d", size);
		desc = analysis->iob.open_at(analysis->iob.io, mstr, RZ_PERM_RW, 0, addr, NULL);
		free(mstr);
		// set 8051 address space as name of mapped memory
		if (desc && analysis->iob.fd_get_name(analysis->iob.io, desc->fd)) {
			RzList *maps = analysis->iob.fd_get_map(analysis->iob.io, desc->fd);
			RzIOMap *current_map;
			RzListIter *iter;
			rz_list_foreach (maps, iter, current_map) {
				rz_io_map_resolve(analysis->iob.io, current_map->id);
				rz_io_map_set_name(current_map, mem_map[entry].name);
			}
			rz_list_free(maps);
		}
	}
	mem_map[entry].desc = desc;
	mem_map[entry].addr = addr;
}

static void set_cpu_model(RzAnalysis *analysis, bool force) {
	ut32 addr_idata, addr_sfr, addr_xdata;

	if (!analysis->reg) {
		return;
	}

	const char *cpu = analysis->cpu;
	if (!cpu || !cpu[0]) {
		cpu = cpu_models[0].name;
	}

	// if cpu model changed, reinitialize emulation
	if (force || !cpu_curr_model || rz_str_casecmp(cpu, cpu_curr_model->name)) {
		// find model by name
		int i = 0;
		while (cpu_models[i].name && rz_str_casecmp(cpu, cpu_models[i].name)) {
			i++;
		}
		if (!cpu_models[i].name) {
			i = 0; // if not found, default to generic 8051
		}
		cpu_curr_model = &cpu_models[i];

		// TODO: Add flags as needed - seek using pseudo registers works w/o flags

		// set memory map registers
		addr_idata = cpu_models[i].map_idata;
		addr_sfr = cpu_models[i].map_sfr;
		addr_xdata = cpu_models[i].map_xdata;
		i8051_reg_write(analysis->rzil->vm, "_code", cpu_models[i].map_code);
		i8051_reg_write(analysis->rzil->vm, "_idata", addr_idata);
		i8051_reg_write(analysis->rzil->vm, "_sfr", addr_sfr - 0x80);
		i8051_reg_write(analysis->rzil->vm, "_xdata", addr_xdata);
		i8051_reg_write(analysis->rzil->vm, "_pdata", cpu_models[i].map_pdata);
	} else {
		addr_idata = i8051_reg_read(analysis->rzil->vm, "_idata");
		addr_sfr = i8051_reg_read(analysis->rzil->vm, "_sfr") + 0x80;
		addr_xdata = i8051_reg_read(analysis->rzil->vm, "_xdata");
	}

	// (Re)allocate memory as needed.
	// We assume that code is allocated with firmware image
	if (analysis->iob.fd_get_name && analysis->coreb.cmd) {
		map_cpu_memory(analysis, I8051_IDATA, addr_idata, 0x100, force);
		map_cpu_memory(analysis, I8051_SFR, addr_sfr, 0x80, force);
		map_cpu_memory(analysis, I8051_XDATA, addr_xdata, 0x10000, force);
	}
}

static ut8 bitindex[] = {
	// bit 'i' can be found in (ram[bitindex[i>>3]] >> (i&7)) & 1
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, // 0x00
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, // 0x40
	0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, // 0x80
	0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8 // 0xC0
};

#if 0
typedef struct {
	const char *name;
	ut8 offset; // offset into memory, where the value is held
	ut8 resetvalue; // value the register takes in case of a reset
	ut8 num_bytes; // no more than sizeof(ut64)
	ut8 banked : 1;
	ut8 isdptr : 1;
} RI8051Reg;

// custom reg read/write temporarily disabled - see r2 issue #9242
static RI8051Reg registers[] = {
	// keep these sorted
	{"a",     0xE0, 0x00, 1, 0},
	{"b",     0xF0, 0x00, 1, 0},
	{"dph",   0x83, 0x00, 1, 0},
	{"dpl",   0x82, 0x00, 1, 0},
	{"dptr",  0x82, 0x00, 2, 0, 1},
	{"ie",    0xA8, 0x00, 1, 0},
	{"ip",    0xB8, 0x00, 1, 0},
	{"p0",    0x80, 0xFF, 1, 0},
	{"p1",    0x90, 0xFF, 1, 0},
	{"p2",    0xA0, 0xFF, 1, 0},
	{"p3",    0xB0, 0xFF, 1, 0},
	{"pcon",  0x87, 0x00, 1, 0},
	{"psw",   0xD0, 0x00, 1, 0},
	{"r0",    0x00, 0x00, 1, 1},
	{"r1",    0x01, 0x00, 1, 1},
	{"r2",    0x02, 0x00, 1, 1},
	{"r3",    0x03, 0x00, 1, 1},
	{"r4",    0x04, 0x00, 1, 1},
	{"r5",    0x05, 0x00, 1, 1},
	{"r6",    0x06, 0x00, 1, 1},
	{"r7",    0x07, 0x00, 1, 1},
	{"sbuf",  0x99, 0x00, 1, 0},
	{"scon",  0x98, 0x00, 1, 0},
	{"sp",    0x81, 0x07, 1, 0},
	{"tcon",  0x88, 0x00, 1, 0},
	{"th0",   0x8C, 0x00, 1, 0},
	{"th1",   0x8D, 0x00, 1, 0},
	{"tl0",   0x8A, 0x00, 1, 0},
	{"tl1",   0x8B, 0x00, 1, 0},
	{"tmod",  0x89, 0x00, 1, 0}
};
#endif

#define e(frag)       rz_strbuf_append(&op->esil, frag)
#define ef(frag, ...) rz_strbuf_appendf(&op->esil, frag, __VA_ARGS__)

#define flag_c  "7,$c,c,:=,"
#define flag_b  "8,$b,c,:=,"
#define flag_ac "3,$c,ac,:=,"
#define flag_ab "3,$b,ac,:=,"
#define flag_ov "6,$c,ov,:=,"
#define flag_ob "7,$b,6,$b,^,ov,:=,"
#define flag_p  "0xff,a,&=,$p,!,p,:=,"

#define ev_a     0
#define ev_bit   bitindex[buf[1] >> 3]
#define ev_c     0
#define ev_dir1  buf[1]
#define ev_dir2  buf[2]
#define ev_dp    0
#define ev_dpx   0
#define ev_imm1  buf[1]
#define ev_imm2  buf[2]
#define ev_imm16 op->val
#define ev_ri    (1 & buf[0])
#define ev_rix   (1 & buf[0])
#define ev_rn    (7 & buf[0])
#define ev_sp2   0
#define ev_sp1   0

static void exr_a(RzAnalysisOp *op, ut8 dummy) {
	e("a,");
}

static void exr_dir1(RzAnalysisOp *op, ut8 addr) {
	if (addr < 0x80) {
		ef("_idata,%d,+,[1],", addr);
	} else {
		ef("_sfr,%d,+,[1],", addr);
	}
}

static void exr_bit(RzAnalysisOp *op, ut8 addr) {
	exr_dir1(op, addr);
}

static void exr_dpx(RzAnalysisOp *op, ut8 dummy) {
	e("_xdata,dptr,+,[1],");
}

static void exr_imm1(RzAnalysisOp *op, ut8 val) {
	ef("%d,", val);
}

static void exr_imm2(RzAnalysisOp *op, ut8 val) {
	ef("%d,", val);
}

static void exr_imm16(RzAnalysisOp *op, ut16 val) {
	ef("%d,", val);
}

static void exr_ri(RzAnalysisOp *op, ut8 reg) {
	ef("_idata,r%d,+,[1],", reg);
}

static void exr_rix(RzAnalysisOp *op, ut8 reg) {
	ef("8,0xff,_pdata,&,<<,_xdata,+,r%d,+,[1],", reg);
}

static void exr_rn(RzAnalysisOp *op, ut8 reg) {
	ef("r%d,", reg);
}

static void exr_sp1(RzAnalysisOp *op, ut8 dummy) {
	e("_idata,sp,+,[1],");
	e("1,sp,-=,");
}

static void exr_sp2(RzAnalysisOp *op, ut8 dummy) {
	e("1,sp,-=,");
	e("_idata,sp,+,[2],");
	e("1,sp,-=,");
}

static void exw_a(RzAnalysisOp *op, ut8 dummy) {
	e("a,=,");
}

static void exw_c(RzAnalysisOp *op, ut8 dummy) {
	e("c,=,");
}

static void exw_dir1(RzAnalysisOp *op, ut8 addr) {
	if (addr < 0x80) {
		ef("_idata,%d,+,=[1],", addr);
	} else {
		ef("_sfr,%d,+,=[1],", addr);
	}
}

static void exw_dir2(RzAnalysisOp *op, ut8 addr) {
	exw_dir1(op, addr);
}

static void exw_bit(RzAnalysisOp *op, ut8 addr) {
	exw_dir1(op, addr);
}

static void exw_dp(RzAnalysisOp *op, ut8 dummy) {
	e("dptr,=,");
}

static void exw_dpx(RzAnalysisOp *op, ut8 dummy) {
	e("_xdata,dptr,+,=[1],");
}

static void exw_ri(RzAnalysisOp *op, ut8 reg) {
	ef("_idata,r%d,+,=[1],", reg);
}

static void exw_rix(RzAnalysisOp *op, ut8 reg) {
	ef("8,0xff,_pdata,&,<<,_xdata,+,r%d,+,=[1],", reg);
}

static void exw_rn(RzAnalysisOp *op, ut8 reg) {
	ef("r%d,=,", reg);
}

static void exw_sp1(RzAnalysisOp *op, ut8 dummy) {
	e("1,sp,+=,");
	e("_idata,sp,+,=[1],");
}

static void exw_sp2(RzAnalysisOp *op, ut8 dummy) {
	e("1,sp,+=,");
	e("_idata,sp,+,=[2],");
	e("1,sp,+=,");
}

static void exi_a(RzAnalysisOp *op, ut8 dummy, const char *operation) {
	ef("a,%s=,", operation);
}

static void exi_c(RzAnalysisOp *op, ut8 dummy, const char *operation) {
	ef("c,%s=,", operation);
}

static void exi_dp(RzAnalysisOp *op, ut8 dummy, const char *operation) {
	ef("dptr,%s=,", operation);
}

static void exi_dir1(RzAnalysisOp *op, ut8 addr, const char *operation) {
	if (addr < 0x80) {
		ef("_idata,%d,+,%s=[1],", addr, operation);
	} else {
		ef("_sfr,%d,+,%s=[1],", addr, operation);
	}
}

static void exi_bit(RzAnalysisOp *op, ut8 addr, const char *operation) {
	exi_dir1(op, addr, operation);
}

static void exi_ri(RzAnalysisOp *op, ut8 reg, const char *operation) {
	ef("_idata,r%d,+,%s=[1],", reg, operation);
}

static void exi_rn(RzAnalysisOp *op, ut8 reg, const char *operation) {
	ef("r%d,%s=,", reg, operation);
}

#define xr(subject)            exr_##subject(op, ev_##subject)
#define xw(subject)            exw_##subject(op, ev_##subject)
#define xi(subject, operation) exi_##subject(op, ev_##subject, operation)

#define bit_set ef("%d,1,<<,", buf[1] & 7) // 0 1 10 11 110 111 1110 1111
#define bit_mask \
	bit_set; \
	e("255,^,")
#define bit_r \
	ef("%d,", buf[1] & 7); \
	xr(bit); \
	e(">>,1,&,")
#define bit_c ef("%d,c,<<,", buf[1] & 7);

#define jmp ef("%" PFMT64d ",pc,=", op->jump)
#define cjmp \
	e("?{,"); \
	jmp; \
	e(",}")
#define call \
	ef("%" PFMT64d ",", op->fail); \
	xw(sp2); \
	jmp

#define alu_op(val, aluop, flags) \
	xr(val); \
	e("a," aluop "=," flags)
#define alu_op_c(val, aluop, flags) \
	e("c,"); \
	xr(val); \
	e("+,a," aluop "=," flags)
#define alu_op_d(val, aluop) \
	xr(val); \
	xi(dir1, aluop)

#define template_alu4_c(base, aluop, flags) \
	case base + 0x4: \
		alu_op_c(imm1, aluop, flags); \
		break; \
	case base + 0x5: \
		alu_op_c(dir1, aluop, flags); \
		break; \
	case base + 0x6: \
	case base + 0x7: \
		alu_op_c(ri, aluop, flags); \
		break; \
	case base + 0x8: \
	case base + 0x9: \
	case base + 0xA: \
	case base + 0xB: \
	case base + 0xC: \
	case base + 0xD: \
	case base + 0xE: \
	case base + 0xF: \
		alu_op_c(rn, aluop, flags); \
		break;

#define template_alu2(base, aluop) \
	case base + 0x2: \
		alu_op_d(a, aluop); \
		break; \
	case base + 0x3: \
		alu_op_d(imm2, aluop); \
		break;

#define template_alu4(base, aluop, flags) \
	case base + 0x4: \
		alu_op(imm1, aluop, flags); \
		break; \
	case base + 0x5: \
		alu_op(dir1, aluop, flags); \
		break; \
	case base + 0x6: \
	case base + 0x7: \
		alu_op(ri, aluop, flags); \
		break; \
	case base + 0x8: \
	case base + 0x9: \
	case base + 0xA: \
	case base + 0xB: \
	case base + 0xC: \
	case base + 0xD: \
	case base + 0xE: \
	case base + 0xF: \
		alu_op(rn, aluop, flags); \
		break;

static void analop_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, _8051_op_t _8051_ops) {
	rz_strbuf_init(&op->esil);
	rz_strbuf_set(&op->esil, "");

	switch (buf[0]) {
	// Irregulars sorted by lower nibble
	case 0x00: /* nop */
		e(",");
		break;

	case 0x10: /* jbc bit, offset */
		bit_r;
		e("?{,");
		bit_mask;
		xi(bit, "&");
		jmp;
		e(",}");
		break;
	case 0x20: /* jb bit, offset */
		bit_r;
		cjmp;
		break;
	case 0x30: /* jnb bit, offset */
		bit_r;
		e("!,");
		cjmp;
		break;
	case 0x40: /* jc offset */
		e("c,1,&,");
		cjmp;
		break;
	case 0x50: /* jnc offset */
		e("c,1,&,!,");
		cjmp;
		break;
	case 0x60: /* jz offset */
		e("a,0,==,$z,");
		cjmp;
		break;
	case 0x70: /* jnz offset */
		e("a,0,==,$z,!,");
		cjmp;
		break;

	case 0x11:
	case 0x31:
	case 0x51:
	case 0x71:
	case 0x91:
	case 0xB1:
	case 0xD1:
	case 0xF1: /* acall addr11 */
	case 0x12: /* lcall addr16 */
		call;
		break;
	case 0x01:
	case 0x21:
	case 0x41:
	case 0x61:
	case 0x81:
	case 0xA1:
	case 0xC1:
	case 0xE1: /* ajmp addr11 */
	case 0x02: /* ljmp addr16 */
	case 0x80: /* sjmp offset */
		jmp;
		break;

	case 0x22: /* ret */
	case 0x32: /* reti */
		xr(sp2);
		e("pc,=");
		break;

	case 0x03: /* rr a */
		e("1,a,0x101,*,>>,a,=," flag_p);
		break;
	case 0x04: /* inc a */
		xi(a, "++");
		e(flag_p);
		break;
	case 0x05: /* inc direct */
		xi(dir1, "++");
		break;
	case 0x06:
	case 0x07: /* inc @Ri */
		xi(ri, "++");
		break;
	case 0x08:
	case 0x09:
	case 0x0A:
	case 0x0B:
	case 0x0C:
	case 0x0D:
	case 0x0E:
	case 0x0F: /* inc @Rn */
		xi(rn, "++");
		break;
	case 0x13: /* rrc a */
		e("7,c,<<,1,a,&,c,=,0x7f,1,a,>>,&,+,a,=," flag_p);
		break;
	case 0x14: /* dec a */
		xi(a, "--");
		e(flag_p);
		break;
	case 0x15: /* dec direct */
		xi(dir1, "--");
		e(flag_p);
		break;
	case 0x16:
	case 0x17: /* dec @Ri */
		xi(ri, "--");
		break;
	case 0x18:
	case 0x19:
	case 0x1A:
	case 0x1B:
	case 0x1C:
	case 0x1D:
	case 0x1E:
	case 0x1F: /* dec @Rn */
		xi(rn, "--");
		break;
	case 0x23: /* rl a */
		e("7,a,0x101,*,>>,a,=," flag_p);
		break;
		template_alu4(0x20, "+", flag_c flag_ac flag_ov flag_p) /* 0x24..0x2f add a,.. */
			case 0x33 : /* rlc a */
				    e("c,1,&,a,a,+=,7,$c,c,:=,a,+=," flag_p);
		break;
		template_alu4_c(0x30, "+", flag_c flag_ac flag_ov flag_p) /* 0x34..0x3f addc a,.. */
			template_alu2(0x40, "|") /* 0x42..0x43 orl direct,.. */
			template_alu4(0x40, "|", flag_p) /* 0x44..0x4f orl a,.. */
			template_alu2(0x50, "&") /* 0x52..0x53 anl direct,.. */
			template_alu4(0x50, "&", flag_p) /* 0x54..0x5f anl a,.. */
			template_alu2(0x60, "^") /* 0x62..0x63 xrl direct,.. */
			template_alu4(0x60, "^", flag_p) /* 0x64..0x6f xrl a,.. */
			case 0x72 : /* orl C, bit */
				    bit_r;
		xi(c, "|");
		break;
	case 0x73: /* jmp @a+dptr */
		e("dptr,a,+,pc,=");
		break;
	case 0x74: /* mov a, imm */
		xr(imm1);
		xw(a);
		e(flag_p);
		break;
	case 0x75: /* mov direct, imm */
		xr(imm2);
		xw(dir1);
		break;
	case 0x76:
	case 0x77: /* mov @Ri, imm */
		xr(imm1);
		xw(ri);
		break;
	case 0x78:
	case 0x79:
	case 0x7A:
	case 0x7B:
	case 0x7C:
	case 0x7D:
	case 0x7E:
	case 0x7F: /* mov Rn, imm */
		xr(imm1);
		xw(rn);
		break;
	case 0x82: /* anl C, bit */
		bit_r;
		xi(c, "&");
		break;
	case 0x83: /* movc a, @a+pc */
		e("a,pc,--,+,[1],a,=," flag_p);
		break;
	case 0x84: /* div ab */
		// note: escape % if this becomes a format string
		e("b,0,==,$z,ov,:=,b,a,%,b,a,/=,b,=,0,c,=," flag_p);
		break;
	case 0x85: /* mov direct, direct */
		xr(dir1);
		xw(dir2);
		break;
	case 0x86:
	case 0x87: /* mov direct, @Ri */
		xr(ri);
		xw(dir1);
		break;
	case 0x88:
	case 0x89:
	case 0x8A:
	case 0x8B:
	case 0x8C:
	case 0x8D:
	case 0x8E:
	case 0x8F: /* mov direct, Rn */
		xr(rn);
		xw(dir1);
		break;
	case 0x90: /* mov dptr, imm */
		xr(imm16);
		xw(dp);
		break;
	case 0x92: /* mov bit, C */
		bit_c;
		bit_mask;
		xr(bit);
		e("&,|,");
		xw(bit);
		break;
	case 0x93: /* movc a, @a+dptr */
		e("a,dptr,+,[1],a,=," flag_p);
		break;
		template_alu4_c(0x90, "-", flag_b flag_ab flag_ob flag_p) /* 0x94..0x9f subb a,.. */
			case 0xA0 : /* orl C, /bit */
				    bit_r;
		e("!,");
		xi(c, "|");
		break;
	case 0xA2: /* mov C, bit */
		bit_r;
		xw(c);
		break;
	case 0xA3: /* inc dptr */
		xi(dp, "++");
		break;
	case 0xA4: /* mul ab */
		e("8,a,b,*,DUP,a,=,>>,DUP,b,=,0,==,$z,!,ov,:=,0,c,=," flag_p);
		break;
	case 0xA5: /* "reserved" */
		e("0,trap");
		break;
	case 0xA6:
	case 0xA7: /* mov @Ri, direct */
		xr(dir1);
		xw(ri);
		break;
	case 0xA8:
	case 0xA9:
	case 0xAA:
	case 0xAB:
	case 0xAC:
	case 0xAD:
	case 0xAE:
	case 0xAF: /* mov Rn, direct */
		xr(dir1);
		xw(rn);
		break;
	case 0xB0: /* anl C, /bit */
		bit_r;
		e("!,");
		xi(c, "&");
		break;
	case 0xB2: /* cpl bit */
		bit_set;
		xi(bit, "^");
		break;
	case 0xB3: /* cpl C */
		e("1,");
		xi(c, "^");
		break;
	case 0xB4: /* cjne a, imm, offset */
		xr(imm1);
		xr(a);
		e("==,$z,!," flag_b);
		cjmp;
		break;
	case 0xB5: /* cjne a, direct, offset */
		xr(dir1);
		xr(a);
		e("==,$z,!," flag_b);
		cjmp;
		break;
	case 0xB6:
	case 0xB7: /* cjne @ri, imm, offset */
		xr(imm1);
		xr(ri);
		e("==,$z,!," flag_b);
		cjmp;
		break;
	case 0xB8:
	case 0xB9:
	case 0xBA:
	case 0xBB:
	case 0xBC:
	case 0xBD:
	case 0xBE:
	case 0xBF: /* cjne Rn, imm, offset */
		xr(imm1);
		xr(rn);
		e("==,$z,!," flag_b);
		cjmp;
		break;
	case 0xC0: /* push direct */
		xr(dir1);
		xw(sp1);
		break;
	case 0xC2: /* clr bit */
		bit_mask;
		xi(bit, "&");
		break;
	case 0xC3: /* clr C */
		e("0,");
		xw(c);
		break;
	case 0xC4: /* swap a */
		e("0xff,4,a,0x101,*,>>,&,a,=," flag_p);
		break;
	case 0xC5: /* xch a, direct */
		xr(a);
		e("0,+,");
		xr(dir1);
		xw(a);
		xw(dir1);
		e(flag_p);
		break;
	case 0xC6:
	case 0xC7: /* xch a, @Ri */
		xr(a);
		e("0,+,");
		xr(ri);
		xw(a);
		xw(ri);
		e(flag_p);
		break;
	case 0xC8:
	case 0xC9:
	case 0xCA:
	case 0xCB:
	case 0xCC:
	case 0xCD:
	case 0xCE:
	case 0xCF: /* xch a, Rn */
		xr(a);
		e("0,+,");
		xr(rn);
		xw(a);
		xw(rn);
		e(flag_p);
		break;
	case 0xD0: /* pop direct */
		xr(sp1);
		xw(dir1);
		break;
	case 0xD2: /* setb bit */
		bit_set;
		xi(bit, "|");
		break;
	case 0xD3: /* setb C */
		e("1,");
		xw(c);
		break;
	case 0xD4: /* da a */
		// BCD adjust after add:
		// if (lower nibble > 9) or (AC == 1) add 6
		// if (higher nibble > 9) or (C == 1) add 0x60
		// carry |= carry caused by this operation
		e("a,0x0f,&,9,==,4,$b,ac,|,?{,6,a,+=,7,$c,c,|,c,:=,},a,0xf0,&,0x90,==,8,$b,c,|,?{,0x60,a,+=,7,$c,c,|,c,:=,}," flag_p);
		break;
	case 0xD5: /* djnz direct, offset */
		xi(dir1, "--");
		xr(dir1);
		e("0,==,$z,!,");
		cjmp;
		break;
	case 0xD6:
	case 0xD7: /* xchd a, @Ri*/
		xr(a);
		e("0xf0,&,");
		xr(ri);
		e("0x0f,&,|,");
		xr(ri);
		e("0xf0,&,");
		xr(a);
		e("0x0f,&,|,");
		xw(ri);
		xw(a);
		e(flag_p);
		break;
	case 0xD8:
	case 0xD9:
	case 0xDA:
	case 0xDB:
	case 0xDC:
	case 0xDD:
	case 0xDE:
	case 0xDF: /* djnz Rn, offset */
		xi(rn, "--");
		xr(rn);
		e("0,==,$z,!,");
		cjmp;
		break;
	case 0xE0: /* movx a, @dptr */
		xr(dpx);
		xw(a);
		e(flag_p);
		break;
	case 0xE2:
	case 0xE3: /* movx a, @Ri */
		xr(rix);
		xw(a);
		e(flag_p);
		break;
	case 0xE4: /* clr a */
		e("0,");
		xw(a);
		e(flag_p);
		break;
	case 0xE5: /* mov a, direct */
		xr(dir1);
		xw(a);
		e(flag_p);
		break;
	case 0xE6:
	case 0xE7: /* mov a, @Ri */
		xr(ri);
		xw(a);
		e(flag_p);
		break;
	case 0xE8:
	case 0xE9:
	case 0xEA:
	case 0xEB:
	case 0xEC:
	case 0xED:
	case 0xEE:
	case 0xEF: /* mov a, Rn */
		xr(rn);
		xw(a);
		e(flag_p);
		break;
	case 0xF0: /* movx @dptr, a */
		xr(a);
		xw(dpx);
		break;
	case 0xF2:
	case 0xF3: /* movx @Ri, a */
		xr(a);
		xw(rix);
		break;
	case 0xF4: /* cpl a */
		e("255,");
		xi(a, "^");
		e(flag_p);
		break;
	case 0xF5: /* mov direct, a */
		xr(a);
		xw(dir1);
		break;
	case 0xF6:
	case 0xF7: /* mov  @Ri, a */
		xr(a);
		xw(ri);
		break;
	case 0xF8:
	case 0xF9:
	case 0xFA:
	case 0xFB:
	case 0xFC:
	case 0xFD:
	case 0xFE:
	case 0xFF: /* mov Rn, a */
		xr(a);
		xw(rn);
		break;
	default:
		break;
	}
}

#if 0
// custom reg read/write temporarily disabled - see r2 issue #9242
static int i8051_hook_reg_read(RzAnalysisEsil *, const char *, ut64 *, int *);

static int i8051_reg_compare(const void *name, const void *reg) {
	return strcmp ((const char*)name, ((RI8051Reg*)reg)->name);
}

static RI8051Reg *i8051_reg_find(const char *name) {
	return (RI8051Reg *) bsearch (
		name, registers,
		sizeof (registers) / sizeof (registers[0]),
		sizeof (registers[0]),
		i8051_reg_compare);
}

static int i8051_reg_get_offset(RzAnalysisEsil *esil, RI8051Reg *ri) {
	ut8 offset = ri->offset;
	if (ri->banked) {
		ut64 psw = 0LL;
		i8051_hook_reg_read (esil, "psw", &psw, NULL);
		offset += psw & 0x18;
	}
	return offset;
}

// dkreuter: It would be nice if we could attach hooks to RzRegItems directly.
//           That way we could avoid doing a string lookup on register names
//           as rz_reg_get already does this. Also, the analysis esil callbacks
//           approach interferes with rz_reg_arena_swap.

static int i8051_hook_reg_read(RzAnalysisEsil *esil, const char *name, ut64 *res, int *size) {
	int ret = 0;
	ut64 val = 0LL;
	RI8051Reg *ri;
	RzAnalysisEsilCallbacks cbs = esil->cb;

	if ((ri = i8051_reg_find (name))) {
		ut8 offset = i8051_reg_get_offset(esil, ri);
		ret = rz_analysis_esil_mem_read (esil, IRAM_BASE + offset, (ut8*)res, ri->num_bytes);
	}
	esil->cb = ocbs;
	if (!ret && ocbs.hook_reg_read) {
		ret = ocbs.hook_reg_read (esil, name, res, NULL);
	}
	if (!ret && ocbs.reg_read) {
		ret = ocbs.reg_read (esil, name, &val, NULL);
	}
	esil->cb = cbs;

	return ret;
}

static int i8051_hook_reg_write(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	int ret = 0;
	RI8051Reg *ri;
	RzAnalysisEsilCallbacks cbs = esil->cb;
	if ((ri = i8051_reg_find (name))) {
		ut8 offset = i8051_reg_get_offset(esil, ri);
		ret = rz_analysis_esil_mem_write (esil, IRAM_BASE + offset, (ut8*)val, ri->num_bytes);
	}
	esil->cb = ocbs;
	if (!ret && ocbs.hook_reg_write) {
		ret = ocbs.hook_reg_write (esil, name, val);
	}
	esil->cb = cbs;
	return ret;
}
#endif

static char *get_regname_bybase(ut8 id, ut8 base) {
	ut8 idd = id - base;
	switch (idd) {
	case I8051_R0:
		return "R0";
	case I8051_R1:
		return "R1";
	case I8051_R2:
		return "R2";
	case I8051_R3:
		return "R3";
	case I8051_R4:
		return "R4";
	case I8051_R5:
		return "R5";
	case I8051_R6:
		return "R6";
	case I8051_R7:
		return "R7";
	default:
		return "R0";
	}
}

RzPVector *i8051_add_imm(RzILVM *vm, ut64 id, const ut8 *buf, bool carry) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0;
	int_->op.int_->length = 8;
	int_->op.int_->value = buf[2];

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = var;
	add->op.add->y = int_;

	// TODO: handle carry flag.

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = add;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, add, set, perform);
	return oplist;
}

RzPVector *i8051_add_direct(RzILVM *vm, ut64 id, const ut8 *buf, bool carry) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = map_direct_addr(vm, buf[1]);

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = var;
	add->op.add->y = load;

	// TODO: handle carry flag.

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = add;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;
	perform->op.perform = -1; // no return;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, load, add, set, perform);
	return oplist;
}

RzPVector *i8051_add_ri(RzILVM *vm, ut64 id, const ut8 *buf, bool carry) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0x26);
	RzILOp *var_tmp = rz_il_new_op(RZIL_OP_VAR);
	var_tmp->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var_tmp;

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = var;
	add->op.add->y = load;

	// TODO: handle carry flag.

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = add;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var, var_tmp, load, add, set, perform);
	return oplist;
}

RzPVector *i8051_add_rn(RzILVM *vm, ut64 id, const ut8 *buf, bool carry) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0x28);
	RzILOp *var_tmp = rz_il_new_op(RZIL_OP_VAR);
	var_tmp->op.var->v = regname;

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = var;
	add->op.add->y = var_tmp;

	// TODO: handle carry flag.

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = add;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, var_tmp, add, set, perform);
	return oplist;
}

RzPVector *i8051_add(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	bool carry = op.instr == OP_ADDC;
	RzPVector *oplist = NULL;
	switch (op.arg1) {
	case A_IMMEDIATE: {
		oplist = i8051_add_imm(vm, id, buf, carry);
		break;
	}
	case A_DIRECT: {
		oplist = i8051_add_direct(vm, id, buf, carry);
		break;
	}
	case A_RI: {
		oplist = i8051_add_ri(vm, id, buf, carry);
		break;
	}
	case A_RN: {
		oplist = i8051_add_rn(vm, id, buf, carry);
		break;
	}
	default:
		break;
	}

	return oplist;
}

RzPVector *i8051_sub_imm(RzILVM *vm, ut64 id, const ut8 *buf, bool carry) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0;
	int_->op.int_->length = 8;
	int_->op.int_->value = buf[2];

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.sub->x = var;
	sub->op.sub->y = int_;

	// TODO: handle carry flag.

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = sub;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, sub, set, perform);
	return oplist;
}

RzPVector *i8051_sub_direct(RzILVM *vm, ut64 id, const ut8 *buf, bool carry) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = map_direct_addr(vm, buf[1]);

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.sub->x = var;
	sub->op.sub->y = load;

	// TODO: handle carry flag.

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = sub;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, load, sub, set, perform);
	return oplist;
}

RzPVector *i8051_sub_ri(RzILVM *vm, ut64 id, const ut8 *buf, bool carry) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0x96);
	RzILOp *var_tmp = rz_il_new_op(RZIL_OP_VAR);
	var_tmp->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var_tmp;

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.sub->x = var;
	sub->op.sub->y = load;

	// TODO: handle carry flag.

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = sub;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var, var_tmp, load, sub, set, perform);
	return oplist;
}

RzPVector *i8051_sub_rn(RzILVM *vm, ut64 id, const ut8 *buf, bool carry) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0x98);
	RzILOp *var_tmp = rz_il_new_op(RZIL_OP_VAR);
	var_tmp->op.var->v = regname;

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.sub->x = var;
	sub->op.sub->y = var_tmp;

	// TODO: handle carry flag.

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = sub;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, var_tmp, sub, set, perform);
	return oplist;
}

RzPVector *i8051_sub(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	bool carry = op.instr == OP_ADDC;
	RzPVector *oplist = NULL;
	switch (op.arg1) {
	case A_IMMEDIATE: {
		oplist = i8051_sub_imm(vm, id, buf, carry);
		break;
	}
	case A_DIRECT: {
		oplist = i8051_sub_direct(vm, id, buf, carry);
		break;
	}
	case A_RI: {
		oplist = i8051_sub_ri(vm, id, buf, carry);
		break;
	}
	case A_RN: {
		oplist = i8051_sub_rn(vm, id, buf, carry);
		break;
	}
	default:
		break;
	}

	return oplist;
}

RzPVector *i8051_inc_a(RzILVM *vm, ut64 id) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = 8;

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = var;
	add->op.add->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = add;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, add, set, perform);
	return oplist;
}

RzPVector *i8051_inc_iram(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, (ut32)buf[1]);

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = 8;

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = load;
	add->op.add->y = int_;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = add;

	RzPVector *oplist = rz_il_make_oplist(id, 4, load, int_, add, store);
	return oplist;
}

RzPVector *i8051_inc_ri(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var_tmp = rz_il_new_op(RZIL_OP_VAR);
	char *regname = get_regname_bybase(buf[0], 0x06);
	var_tmp->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var_tmp;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = 8;

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = load;
	add->op.add->y = int_;

	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = regname;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = var;
	store->op.store->value = add;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var_tmp, load, int_, add, var, store);
	return oplist;
}

RzPVector *i8051_inc_rn(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var_tmp = rz_il_new_op(RZIL_OP_VAR);
	char *regname = get_regname_bybase(buf[0], 0x08);
	var_tmp->op.var->v = regname;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = 8;

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = var_tmp;
	add->op.add->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = add;
	set->op.set->v = regname;

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var_tmp, int_, add, set, perform);
	return oplist;
}

RzPVector *i8051_inc(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0x04: {
		return i8051_inc_a(vm, id);
	}
	case 0x05: {
		return i8051_inc_iram(vm, id, buf);
	}
	case 0x06:
	case 0x07: {
		return i8051_inc_ri(vm, id, buf);
	}
	case 0x08:
	case 0x09:
	case 0x0A:
	case 0x0B:
	case 0x0C:
	case 0x0D:
	case 0x0E:
	case 0x0F: {
		return i8051_inc_rn(vm, id, buf);
	}
	case 0xA3: {
		// TODO: INC DPTR
	}
	default:
		return NULL;
	}
}

RzPVector *i8051_dec_a(RzILVM *vm, ut64 id) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = 8;

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.sub->x = var;
	sub->op.sub->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = sub;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, sub, set, perform);
	return oplist;
}

RzPVector *i8051_dec_iram(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, (ut32)buf[1]);

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = 8;

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.sub->x = load;
	sub->op.sub->y = int_;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = sub;

	RzPVector *oplist = rz_il_make_oplist(id, 4, load, int_, sub, store);
	return oplist;
}

RzPVector *i8051_dec_ri(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var_tmp = rz_il_new_op(RZIL_OP_VAR);
	char *regname = get_regname_bybase(buf[0], 0x16);
	var_tmp->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var_tmp;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = 8;

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.sub->x = load;
	sub->op.sub->y = int_;

	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = regname;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = var;
	store->op.store->value = sub;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var_tmp, load, int_, sub, var, store);
	return oplist;
}

RzPVector *i8051_dec_rn(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var_tmp = rz_il_new_op(RZIL_OP_VAR);
	char *regname = get_regname_bybase(buf[0], 0x18);
	var_tmp->op.var->v = regname;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = 8;

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.sub->x = var_tmp;
	sub->op.sub->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = sub;
	set->op.set->v = regname;

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var_tmp, int_, sub, set, perform);
	return oplist;
}

RzPVector *i8051_dec(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0x14: {
		return i8051_dec_a(vm, id);
	}
	case 0x15: {
		return i8051_dec_iram(vm, id, buf);
	}
	case 0x16:
	case 0x17: {
		return i8051_dec_ri(vm, id, buf);
	}
	case 0x18:
	case 0x19:
	case 0x1A:
	case 0x1B:
	case 0x1C:
	case 0x1D:
	case 0x1E:
	case 0x1F: {
		return i8051_dec_rn(vm, id, buf);
	}
	default:
		return NULL;
	}
}

RzPVector *i8051_or_iram_a(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = load;
	logor->op.logor->y = var;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = logor;

	RzPVector *oplist = rz_il_make_oplist(id, 4, load, var, logor, store);
	return oplist;
}

RzPVector *i8051_or_iram_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = buf[2];
	int_->op.int_->length = 8;

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = load;
	logor->op.logor->y = int_;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = logor;

	RzPVector *oplist = rz_il_make_oplist(id, 4, load, int_, logor, store);
	return oplist;
}

RzPVector *i8051_or_a_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = buf[1];
	int_->op.int_->length = 8;

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = var;
	logor->op.logor->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logor;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = 3;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, logor, set, perform);
	return oplist;
}

RzPVector *i8051_or_a_iram(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = var;
	logor->op.logor->y = load;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logor;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = 3;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, load, logor, set, perform);
	return oplist;
}

RzPVector *i8051_or_a_ri(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0x46);
	RzILOp *var2 = rz_il_new_op(RZIL_OP_VAR);
	var2->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var2;

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = var;
	logor->op.logor->y = load;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logor;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var, var2, load, logor, set, perform);
	return oplist;
}

RzPVector *i8051_or_a_rn(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0x48);
	RzILOp *var2 = rz_il_new_op(RZIL_OP_VAR);
	var2->op.var->v = regname;

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = var;
	logor->op.logor->y = var2;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logor;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, var2, logor, set, perform);
	return oplist;
}

RzPVector *i8051_or(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0x42: {
		return i8051_or_iram_a(vm, id, buf);
	}
	case 0x43: {
		return i8051_or_iram_imm(vm, id, buf);
	}
	case 0x44: {
		return i8051_or_a_imm(vm, id, buf);
	}
	case 0x45: {
		return i8051_or_a_iram(vm, id, buf);
	}
	case 0x46:
	case 0x47: {
		return i8051_or_a_ri(vm, id, buf);
	}
	case 0x48:
	case 0x49:
	case 0x4A:
	case 0x4B:
	case 0x4C:
	case 0x4D:
	case 0x4E:
	case 0x4F: {
		return i8051_or_a_rn(vm, id, buf);
	}
	case 0xA0:
	case 0x72: {
		// TODO: ORL C,bit addr ORL C,/bit addr
	}
	default:
		return NULL;
	}
}

RzPVector *i8051_and_iram_a(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = load;
	logand->op.logand->y = var;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = logand;

	RzPVector *oplist = rz_il_make_oplist(id, 4, load, var, logand, store);
	return oplist;
}

RzPVector *i8051_and_iram_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = buf[2];
	int_->op.int_->length = 8;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = load;
	logand->op.logand->y = int_;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = logand;

	RzPVector *oplist = rz_il_make_oplist(id, 4, load, int_, logand, store);
	return oplist;
}

RzPVector *i8051_and_a_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = buf[1];
	int_->op.int_->length = 8;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = var;
	logand->op.logand->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logand;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = 3;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, logand, set, perform);
	return oplist;
}

RzPVector *i8051_and_a_iram(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = var;
	logand->op.logand->y = load;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logand;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, load, logand, set, perform);
	return oplist;
}

RzPVector *i8051_and_a_ri(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0x56);
	RzILOp *var2 = rz_il_new_op(RZIL_OP_VAR);
	var2->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var2;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = var;
	logand->op.logand->y = load;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logand;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var, var2, load, logand, set, perform);
	return oplist;
}

RzPVector *i8051_and_a_rn(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0x58);
	RzILOp *var2 = rz_il_new_op(RZIL_OP_VAR);
	var2->op.var->v = regname;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = var;
	logand->op.logand->y = var2;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logand;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, var2, logand, set, perform);
	return oplist;
}

RzPVector *i8051_and(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0x52: {
		return i8051_and_iram_a(vm, id, buf);
	}
	case 0x53: {
		return i8051_and_iram_imm(vm, id, buf);
	}
	case 0x54: {
		return i8051_and_a_imm(vm, id, buf);
	}
	case 0x55: {
		return i8051_and_a_iram(vm, id, buf);
	}
	case 0x56:
	case 0x57: {
		return i8051_and_a_ri(vm, id, buf);
	}
	case 0x58:
	case 0x59:
	case 0x5A:
	case 0x5B:
	case 0x5C:
	case 0x5D:
	case 0x5E:
	case 0x5F: {
		return i8051_and_a_rn(vm, id, buf);
	}
	case 0xB0:
	case 0x82: {
		// TODO: ANL C,bit addr ANL C,/bit addr
	}
	default:
		return NULL;
	}
}

RzPVector *i8051_xor_iram_a(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *logxor = rz_il_new_op(RZIL_OP_LOGXOR);
	logxor->op.logxor->x = load;
	logxor->op.logxor->y = var;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = logxor;

	RzPVector *oplist = rz_il_make_oplist(id, 4, load, var, logxor, store);
	return oplist;
}

RzPVector *i8051_xor_iram_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = buf[2];
	int_->op.int_->length = 8;

	RzILOp *logxor = rz_il_new_op(RZIL_OP_LOGXOR);
	logxor->op.logxor->x = load;
	logxor->op.logxor->y = int_;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = logxor;

	RzPVector *oplist = rz_il_make_oplist(id, 4, load, int_, logxor, store);
	return oplist;
}

RzPVector *i8051_xor_a_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = buf[1];
	int_->op.int_->length = 8;

	RzILOp *logxor = rz_il_new_op(RZIL_OP_LOGXOR);
	logxor->op.logxor->x = var;
	logxor->op.logxor->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logxor;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, logxor, set, perform);
	return oplist;
}

RzPVector *i8051_xor_a_iram(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *logxor = rz_il_new_op(RZIL_OP_LOGXOR);
	logxor->op.logxor->x = var;
	logxor->op.logxor->y = load;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logxor;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, load, logxor, set, perform);
	return oplist;
}

RzPVector *i8051_xor_a_ri(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0x66);
	RzILOp *var2 = rz_il_new_op(RZIL_OP_VAR);
	var2->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var2;

	RzILOp *logxor = rz_il_new_op(RZIL_OP_LOGXOR);
	logxor->op.logxor->x = var;
	logxor->op.logxor->y = load;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logxor;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var, var2, load, logxor, set, perform);
	return oplist;
}

RzPVector *i8051_xor_a_rn(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0x68);
	RzILOp *var2 = rz_il_new_op(RZIL_OP_VAR);
	var2->op.var->v = regname;

	RzILOp *logxor = rz_il_new_op(RZIL_OP_LOGXOR);
	logxor->op.logxor->x = var;
	logxor->op.logxor->y = var2;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logxor;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, var2, logxor, set, perform);
	return oplist;
}

RzPVector *i8051_xor(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0x62: {
		return i8051_xor_iram_a(vm, id, buf);
	}
	case 0x63: {
		return i8051_xor_iram_imm(vm, id, buf);
	}
	case 0x64: {
		return i8051_xor_a_imm(vm, id, buf);
	}
	case 0x65: {
		return i8051_xor_a_iram(vm, id, buf);
	}
	case 0x66:
	case 0x67: {
		return i8051_xor_a_ri(vm, id, buf);
	}
	case 0x68:
	case 0x69:
	case 0x6A:
	case 0x6B:
	case 0x6C:
	case 0x6D:
	case 0x6E:
	case 0x6F: {
		return i8051_xor_a_rn(vm, id, buf);
	}
	default:
		return NULL;
	}
}

RzPVector *i8051_xch_a_ri(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0xC6);
	RzILOp *var2 = rz_il_new_op(RZIL_OP_VAR);
	var2->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var2;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = load;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = var2;
	store->op.store->value = var;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var, var2, load, set, perform, store);
	return oplist;
}

RzPVector *i8051_xch_a_rn(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[1], 0xC8);
	RzILOp *var2 = rz_il_new_op(RZIL_OP_VAR);
	var2->op.var->v = regname;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = var2;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzILOp *set2 = rz_il_new_op(RZIL_OP_SET);
	set2->op.set->x = var;
	set2->op.set->v = regname;

	RzILOp *perform2 = rz_il_new_op(RZIL_OP_PERFORM);
	perform2->op.perform->eff = set2;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var, var2, set, perform, set2, perform2);
	return oplist;
}

RzPVector *i8051_xch_a_iram(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = load;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = load;
	store->op.store->value = var;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, load, set, perform, store);
	return oplist;
}

RzPVector *i8051_xch(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0xC6:
	case 0xC7: {
		return i8051_xch_a_ri(vm, id, buf);
	}
	case 0xC8:
	case 0xC9:
	case 0xCA:
	case 0xCB:
	case 0xCC:
	case 0xCD:
	case 0xCE:
	case 0xCF: {
		return i8051_xch_a_rn(vm, id, buf);
	}
	case 0xC5: {
		return i8051_xch_a_iram(vm, id, buf);
	}
	default:
		return NULL;
	}
}

RzPVector *i8051_mov_ri_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	char *regname = get_regname_bybase(buf[0], 0x76);
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->length = 8;
	int_->op.int_->value = buf[1];

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = var;
	store->op.store->value = int_;

	RzPVector *oplist = rz_il_make_oplist(id, 4, var, load, int_, store);
	return oplist;
}

RzPVector *i8051_mov_ri_a(RzILVM *vm, ut64 id, const ut8 *buf) {
	char *regname = get_regname_bybase(buf[0], 0xF6);
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = regname;

	RzILOp *var2 = rz_il_new_op(RZIL_OP_VAR);
	var2->op.var->v = "ACC";

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = var;
	store->op.store->value = var2;

	RzPVector *oplist = rz_il_make_oplist(id, 3, var, var2, store);
	return oplist;
}

RzPVector *i8051_mov_ri_iram(RzILVM *vm, ut64 id, const ut8 *buf) {
	char *regname = get_regname_bybase(buf[0], 0xA6);
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = regname;

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = var;
	store->op.store->value = load;

	RzPVector *oplist = rz_il_make_oplist(id, 3, var, load, store);
	return oplist;
}

RzPVector *i8051_mov_a_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->length = 8;
	int_->op.int_->value = buf[1];

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = int_;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 3, int_, set, perform);
	return oplist;
}

RzPVector *i8051_mov_a_ri(RzILVM *vm, ut64 id, const ut8 *buf) {
	char *regname = get_regname_bybase(buf[0], 0xE6);
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = load;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 4, var, load, set, perform);
	return oplist;
}

RzPVector *i8051_mov_a_rn(RzILVM *vm, ut64 id, const ut8 *buf) {
	char *regname = get_regname_bybase(buf[0], 0xE8);
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = regname;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = var;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 3, var, set, perform);
	return oplist;
}

RzPVector *i8051_mov_a_iram(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = load;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 3, load, set, perform);
	return oplist;
}

RzPVector *i8051_mov_dptr_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->length = 8;
	int_->op.int_->value = buf[1];

	RzILOp *int_2 = rz_il_new_op(RZIL_OP_INT);
	int_2->op.int_->length = 8;
	int_2->op.int_->value = buf[2];

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = int_;
	set->op.set->v = "DPH";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzILOp *set2 = rz_il_new_op(RZIL_OP_SET);
	set2->op.set->x = int_2;
	set2->op.set->v = "DPL";

	RzILOp *perform2 = rz_il_new_op(RZIL_OP_PERFORM);
	perform2->op.perform->eff = set2;

	RzPVector *oplist = rz_il_make_oplist(id, 6, int_, int_2, set, perform, set2, perform2);
	return oplist;
}

RzPVector *i8051_mov_rn_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->length = 8;
	int_->op.int_->value = buf[1];

	char *regname = get_regname_bybase(buf[0], 0x78);
	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = int_;
	set->op.set->v = regname;

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 3, int_, set, perform);
	return oplist;
}

RzPVector *i8051_mov_rn_a(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[0], 0xF8);
	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = var;
	set->op.set->v = regname;

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 3, var, set, perform);
	return oplist;
}

RzPVector *i8051_mov_rn_iram(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->key = addr;
	load->op.load->mem = 0;

	char *regname = get_regname_bybase(buf[0], 0xF8);
	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = load;
	set->op.set->v = regname;

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 3, load, set, perform);
	return oplist;
}

RzPVector *i8051_mov_iram_imm(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->length = 8;
	int_->op.int_->value = buf[2];

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = int_;

	RzPVector *oplist = rz_il_make_oplist(id, 2, int_, store);
	return oplist;
}

RzPVector *i8051_mov_iram_ri(RzILVM *vm, ut64 id, const ut8 *buf) {
	char *regname = get_regname_bybase(buf[0], 0x86);
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var;

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = load;

	RzPVector *oplist = rz_il_make_oplist(id, 3, var, load, store);
	return oplist;
}

RzPVector *i8051_mov_iram_rn(RzILVM *vm, ut64 id, const ut8 *buf) {
	char *regname = get_regname_bybase(buf[0], 0x88);
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = regname;

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = var;

	RzPVector *oplist = rz_il_make_oplist(id, 2, var, store);
	return oplist;
}

RzPVector *i8051_mov_iram_a(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = var;

	RzPVector *oplist = rz_il_make_oplist(id, 2, var, store);
	return oplist;
}

RzPVector *i8051_mov_iram_iram(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr_src = map_direct_addr(vm, buf[2]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr_src;

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = load;

	RzPVector *oplist = rz_il_make_oplist(id, 2, load, store);
	return oplist;
}

RzPVector *i8051_mov(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0x76:
	case 0x77:
		return i8051_mov_ri_imm(vm, id, buf);
	case 0xF6:
	case 0xF7:
		return i8051_mov_ri_a(vm, id, buf);
	case 0xA6:
	case 0xA7:
		return i8051_mov_ri_iram(vm, id, buf);
	case 0x74:
		return i8051_mov_a_imm(vm, id, buf);
	case 0xE6:
	case 0xE7:
		return i8051_mov_a_ri(vm, id, buf);
	case 0xE8:
	case 0xE9:
	case 0xEA:
	case 0xEB:
	case 0xEC:
	case 0xED:
	case 0xEE:
	case 0xEF:
		return i8051_mov_a_rn(vm, id, buf);
	case 0xE5:
		return i8051_mov_a_iram(vm, id, buf);
	case 0x90:
		return i8051_mov_dptr_imm(vm, id, buf);
	case 0x78:
	case 0x79:
	case 0x7A:
	case 0x7B:
	case 0x7C:
	case 0x7D:
	case 0x7E:
	case 0x7F:
		return i8051_mov_rn_imm(vm, id, buf);
	case 0xF8:
	case 0xF9:
	case 0xFA:
	case 0xFB:
	case 0xFC:
	case 0xFD:
	case 0xFE:
	case 0xFF:
		return i8051_mov_rn_a(vm, id, buf);
	case 0xA8:
	case 0xA9:
	case 0xAA:
	case 0xAB:
	case 0xAC:
	case 0xAD:
	case 0xAE:
	case 0xAF:
		return i8051_mov_rn_iram(vm, id, buf);
	case 0x75:
		return i8051_mov_iram_imm(vm, id, buf);
	case 0x86:
	case 0x87:
		return i8051_mov_iram_ri(vm, id, buf);
	case 0x88:
	case 0x89:
	case 0x8A:
	case 0x8B:
	case 0x8C:
	case 0x8D:
	case 0x8E:
	case 0x8F:
		return i8051_mov_iram_rn(vm, id, buf);
	case 0xF5:
		return i8051_mov_iram_a(vm, id, buf);
	case 0x85:
		return i8051_mov_iram_iram(vm, id, buf);
	case 0xA2:
		// TODO: MOV C,bit addr
	case 0x92:
		// TODO: MOV bit addr,C
	default:
		return NULL;
	}
}

RzPVector *i8051_setb_c(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "PSW";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0x80;
	int_->op.int_->length = 8;

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = var;
	logor->op.logor->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logor;
	set->op.set->v = "PSW";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, logor, set, perform);
	return oplist;
}

RzPVector *i8051_setb_bit(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0x1;
	int_->op.int_->length = 8;

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = load;
	logor->op.logor->y = int_;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = logor;

	RzPVector *oplist = rz_il_make_oplist(id, 4, load, int_, logor, store);
	return oplist;
}

RzPVector *i8051_setb(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0xD2:
		return i8051_setb_bit(vm, id, buf);
	case 0xD3:
		return i8051_setb_c(vm, id, buf);
	default:
		return NULL;
	}
}

RzPVector *i8051_cpl_c(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "PSW";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0x80;
	int_->op.int_->length = 8;

	RzILOp *logxor = rz_il_new_op(RZIL_OP_LOGXOR);
	logxor->op.logxor->x = var;
	logxor->op.logxor->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logxor;
	set->op.set->v = "PSW";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, logxor, set, perform);
	return oplist;
}

RzPVector *i8051_cpl_bit(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *not = rz_il_new_op(RZIL_OP_NOT);
	not ->op.not_->bv = load;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = not ;

	RzPVector *oplist = rz_il_make_oplist(id, 3, load, not, store);
	return oplist;
}

RzPVector *i8051_cpl_a(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *not = rz_il_new_op(RZIL_OP_NOT);
	not ->op.not_->bv = var;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = not ;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 4, var, not, set, perform);
	return oplist;
}

RzPVector *i8051_cpl(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0xB2:
		return i8051_cpl_bit(vm, id, buf);
	case 0xB3:
		return i8051_cpl_c(vm, id, buf);
	case 0xF4:
		return i8051_cpl_a(vm, id, buf);
	default:
		return NULL;
	}
}

RzPVector *i8051_clr_c(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "PSW";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0x7F;
	int_->op.int_->length = 8;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = var;
	logand->op.logand->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logand;
	set->op.set->v = "PSW";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, logand, set, perform);
	return oplist;
}

RzPVector *i8051_clr_bit(RzILVM *vm, ut64 id, const ut8 *buf) {
	ut32 addr = map_direct_addr(vm, buf[1]);

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0x0;
	int_->op.int_->length = 8;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = load;
	logand->op.logand->y = int_;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	// probably wrong
	store->op.store->key = addr;
	store->op.store->value = logand;

	RzPVector *oplist = rz_il_make_oplist(id, 4, load, int_, logand, store);
	return oplist;
}

RzPVector *i8051_clr_a(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ACC";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0x7F;
	int_->op.int_->length = 8;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = var;
	logand->op.logand->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = logand;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var, int_, logand, set, perform);
	return oplist;
}

RzPVector *i8051_clr(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0xC2:
		return i8051_clr_bit(vm, id, buf);
	case 0xC3:
		return i8051_clr_c(vm, id, buf);
	case 0xE4:
		return i8051_clr_a(vm, id, buf);
	default:
		return NULL;
	}
}

RzPVector *i8051_div(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	RzILOp *var_b = rz_il_new_op(RZIL_OP_VAR);
	var_b->op.var->v = "B";

	RzILOp *div = rz_il_new_op(RZIL_OP_DIV);
	div->op.div->x = var_a;
	div->op.div->y = var_b;

	RzILOp *mod = rz_il_new_op(RZIL_OP_MOD);
	mod->op.mod->x = var_a;
	mod->op.mod->y = var_b;

	RzILOp *set_a = rz_il_new_op(RZIL_OP_SET);
	set_a->op.set->x = div;
	set_a->op.set->v = "ACC";

	RzILOp *perform_a = rz_il_new_op(RZIL_OP_PERFORM);
	perform_a->op.perform->eff = set_a;

	RzILOp *set_b = rz_il_new_op(RZIL_OP_SET);
	set_b->op.set->x = mod;
	set_b->op.set->v = "B";

	RzILOp *perform_b = rz_il_new_op(RZIL_OP_PERFORM);
	perform_b->op.perform->eff = set_b;

	RzPVector *oplist = rz_il_make_oplist(id, 8, var_a, var_b, div, mod, set_a, perform_a, set_b, perform_b);
	return oplist;
}

RzPVector *i8051_mul(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	RzILOp *var_b = rz_il_new_op(RZIL_OP_VAR);
	var_b->op.var->v = "B";

	RzILOp *mul = rz_il_new_op(RZIL_OP_MUL);
	mul->op.mul->x = var_a;
	mul->op.mul->y = var_b;

	RzILOp *set_b = rz_il_new_op(RZIL_OP_SET);
	set_b->op.set->x = mul;
	set_b->op.set->v = "B";

	RzILOp *perform_b = rz_il_new_op(RZIL_OP_PERFORM);
	perform_b->op.perform->eff = set_b;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var_a, var_b, mul, set_b, perform_b);
	return oplist;
}

RzPVector *i8051_push(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	RzILOp *var_sp = rz_il_new_op(RZIL_OP_VAR);
	var_sp->op.var->v = "SP";

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = addr;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = var_sp;
	store->op.store->value = load;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0x1;
	int_->op.int_->length = 8;

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = var_sp;
	add->op.add->y = int_;

	RzILOp *set_sp = rz_il_new_op(RZIL_OP_SET);
	set_sp->op.set->x = add;
	set_sp->op.set->v = "SP";

	RzILOp *perform_sp = rz_il_new_op(RZIL_OP_PERFORM);
	perform_sp->op.perform->eff = set_sp;

	RzPVector *oplist = rz_il_make_oplist(id, 7, var_sp, load, store, int_, add, set_sp, perform_sp);
	return oplist;
}

RzPVector *i8051_pop(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	RzILOp *var_sp = rz_il_new_op(RZIL_OP_VAR);
	var_sp->op.var->v = "SP";

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var_sp;

	ut32 addr = map_direct_addr(vm, buf[1]);
	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = addr;
	store->op.store->value = load;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0x1;
	int_->op.int_->length = 8;

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.sub->x = var_sp;
	sub->op.sub->y = int_;

	RzILOp *set_sp = rz_il_new_op(RZIL_OP_SET);
	set_sp->op.set->x = sub;
	set_sp->op.set->v = "SP";

	RzILOp *perform_sp = rz_il_new_op(RZIL_OP_PERFORM);
	perform_sp->op.perform->eff = set_sp;

	RzPVector *oplist = rz_il_make_oplist(id, 7, var_sp, load, store, int_, sub, set_sp, perform_sp);
	return oplist;
}

RzPVector *i8051_rr(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	RzILOp *shiftr = rz_il_new_op(RZIL_OP_SHIFTR);
	shiftr->op.shiftr->x = var_a;
	shiftr->op.shiftr->y = 1;
	shiftr->op.shiftr->fill_bit = 7;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = shiftr;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 4, var_a, shiftr, set, perform);
	return oplist;
}

RzPVector *i8051_rrc(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	RzILOp *var_c = rz_il_new_op(RZIL_OP_VAR);
	var_c->op.var->v = "PSW";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0x80;
	int_->op.int_->length = 8;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = var_c;
	logand->op.logand->y = int_; // c bit

	RzILOp *int_1 = rz_il_new_op(RZIL_OP_INT);
	int_1->op.int_->value = 0x1;
	int_1->op.int_->length = 8;

	RzILOp *logand_1 = rz_il_new_op(RZIL_OP_LOGAND);
	logand_1->op.logand->x = var_a;
	logand_1->op.logand->y = int_1; // right-most bit

	RzILOp *shiftr = rz_il_new_op(RZIL_OP_SHIFTR);
	shiftr->op.shiftr->x = var_a;
	shiftr->op.shiftr->y = 1;

	RzILOp *shiftl = rz_il_new_op(RZIL_OP_SHIFTL);
	shiftl->op.shiftl->x = logand;
	shiftl->op.shiftl->y = 7; // c bit for or operation

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = shiftr;
	logor->op.logor->y = shiftl; // set acc

	RzILOp *shiftl_1 = rz_il_new_op(RZIL_OP_SHIFTL);
	shiftl_1->op.shiftl->x = logand;
	shiftl_1->op.shiftl->y = 7; // right-most bit for or operation

	RzILOp *logor_1 = rz_il_new_op(RZIL_OP_LOGOR);
	logor_1->op.logor->x = var_c;
	logor_1->op.logor->y = shiftl_1;

	RzILOp *set_a = rz_il_new_op(RZIL_OP_SET);
	set_a->op.set->x = logor;
	set_a->op.set->v = "ACC";

	RzILOp *perform_a = rz_il_new_op(RZIL_OP_PERFORM);
	perform_a->op.perform->eff = set_a;

	RzILOp *set_c = rz_il_new_op(RZIL_OP_SET);
	set_c->op.set->x = logor_1;
	set_c->op.set->v = "ACC";

	RzILOp *perform_c = rz_il_new_op(RZIL_OP_PERFORM);
	perform_c->op.perform->eff = set_c;

	RzPVector *oplist = rz_il_make_oplist(id, 15, var_a, var_c, int_, logand, int_1, logand_1, shiftr, shiftl, logor,
		shiftl_1, logor_1, set_a, perform_a, set_c, perform_c);
	return oplist;
}

RzPVector *i8051_rl(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	RzILOp *shiftl = rz_il_new_op(RZIL_OP_SHIFTL);
	shiftl->op.shiftl->x = var_a;
	shiftl->op.shiftl->y = 1;
	shiftl->op.shiftl->fill_bit = 0;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = shiftl;
	set->op.set->v = "ACC";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	RzPVector *oplist = rz_il_make_oplist(id, 4, var_a, shiftl, set, perform);
	return oplist;
}

RzPVector *i8051_rlc(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	RzILOp *var_c = rz_il_new_op(RZIL_OP_VAR);
	var_c->op.var->v = "PSW";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0x80;
	int_->op.int_->length = 8;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = var_c;
	logand->op.logand->y = int_; // c bit

	RzILOp *logand_1 = rz_il_new_op(RZIL_OP_LOGAND);
	logand_1->op.logand->x = var_a;
	logand_1->op.logand->y = int_; // left-most bit

	RzILOp *shiftl = rz_il_new_op(RZIL_OP_SHIFTL);
	shiftl->op.shiftr->x = var_a;
	shiftl->op.shiftr->y = 1;

	RzILOp *shiftr = rz_il_new_op(RZIL_OP_SHIFTR);
	shiftr->op.shiftl->x = logand;
	shiftr->op.shiftl->y = 7; // c bit for or operation

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = shiftl;
	logor->op.logor->y = shiftr; // set acc

	RzILOp *shiftl_1 = rz_il_new_op(RZIL_OP_SHIFTL);
	shiftl_1->op.shiftl->x = logand_1;
	shiftl_1->op.shiftl->y = 7; // right-most bit for or operation

	RzILOp *logor_1 = rz_il_new_op(RZIL_OP_LOGOR);
	logor_1->op.logor->x = var_c;
	logor_1->op.logor->y = shiftl_1; // set c bit

	RzILOp *set_a = rz_il_new_op(RZIL_OP_SET);
	set_a->op.set->x = logor;
	set_a->op.set->v = "ACC";

	RzILOp *perform_a = rz_il_new_op(RZIL_OP_PERFORM);
	perform_a->op.perform->eff = set_a;

	RzILOp *set_c = rz_il_new_op(RZIL_OP_SET);
	set_c->op.set->x = logor_1;
	set_c->op.set->v = "ACC";

	RzILOp *perform_c = rz_il_new_op(RZIL_OP_PERFORM);
	perform_c->op.perform->eff = set_c;

	RzPVector *oplist = rz_il_make_oplist(id, 14, var_a, var_c, int_, logand, logand_1, shiftl, shiftr, logor,
		shiftl_1, logor_1, set_a, perform_a, set_c, perform_c);
	return oplist;
}

RzPVector *i8051_xchd(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[0], 0xD6);
	RzILOp *var_reg = rz_il_new_op(RZIL_OP_VAR);
	var_reg->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = var_reg;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0xF;
	int_->op.int_->length = 8;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = var_a;
	logand->op.logand->y = int_; // A 0-3 bit

	RzILOp *logand_1 = rz_il_new_op(RZIL_OP_LOGAND);
	logand_1->op.logand->x = load;
	logand_1->op.logand->y = int_; // @Rn 0-3 bit

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = var_a;
	logor->op.logor->y = logand_1; // set A

	RzILOp *logor_1 = rz_il_new_op(RZIL_OP_LOGOR);
	logor_1->op.logor->x = load;
	logor_1->op.logor->y = logand;

	RzILOp *set_a = rz_il_new_op(RZIL_OP_SET);
	set_a->op.set->x = logor;
	set_a->op.set->v = "ACC";

	RzILOp *perform_a = rz_il_new_op(RZIL_OP_PERFORM);
	perform_a->op.perform->eff = set_a;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = var_reg;
	store->op.store->value = logor_1;

	RzPVector *oplist = rz_il_make_oplist(id, 11, var_a, var_reg, load, int_, logand, logand_1, logor, logor_1,
		set_a, perform_a, store);
	return oplist;
}

RzPVector *i8051_swap(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 0xF0;
	int_->op.int_->length = 8;

	RzILOp *logand = rz_il_new_op(RZIL_OP_LOGAND);
	logand->op.logand->x = var_a;
	logand->op.logand->y = int_;

	RzILOp *shiftr = rz_il_new_op(RZIL_OP_SHIFTR);
	shiftr->op.shiftr->x = logand;
	shiftr->op.shiftr->y = 4; // shift 4 bits (1111)

	RzILOp *shiftl = rz_il_new_op(RZIL_OP_SHIFTL);
	shiftl->op.shiftl->x = var_a;
	shiftl->op.shiftl->y = 4; // shift 4 bits

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = shiftr;
	logor->op.logor->y = shiftl; // SET

	RzILOp *set_a = rz_il_new_op(RZIL_OP_SET);
	set_a->op.set->x = 5;
	set_a->op.set->v = "ACC";

	RzILOp *perform_a = rz_il_new_op(RZIL_OP_PERFORM);
	perform_a->op.perform->eff = set_a;

	RzPVector *oplist = rz_il_make_oplist(id, 8, var_a, int_, logand, shiftr, shiftl, logor, set_a, perform_a);
	return oplist;
}

RzPVector *i8051_movc_a_dptr(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	RzILOp *var_dpl = rz_il_new_op(RZIL_OP_VAR);
	var_dpl->op.var->v = "DPL";

	RzILOp *var_dph = rz_il_new_op(RZIL_OP_VAR);
	var_dph->op.var->v = "DPH";

	RzILOp *shiftl = rz_il_new_op(RZIL_OP_SHIFTL);
	shiftl->op.shiftl->x = var_dph;
	shiftl->op.shiftl->y = 8;

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = var_dpl;
	logor->op.logor->y = shiftl;

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = var_a;
	add->op.add->y = logor;

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0;
	load->op.load->key = add;

	RzILOp *set_a = rz_il_new_op(RZIL_OP_SET);
	set_a->op.set->x = load;
	set_a->op.set->v = "ACC";

	RzILOp *perform_a = rz_il_new_op(RZIL_OP_PERFORM);
	perform_a->op.perform->eff = set_a;

	RzPVector *oplist = rz_il_make_oplist(id, 9, var_a, var_dpl, var_dph, shiftl, logor, add, load, set_a, perform_a);
	return oplist;
}

RzPVector *i8051_movc(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0x83:
		return i8051_movc_a_dptr(vm, id, buf);
	case 0x93:
		// TODO With PC reg
	default:
		return NULL;
	}
}

RzPVector *i8051_movx_dptr_a(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	RzILOp *var_dpl = rz_il_new_op(RZIL_OP_VAR);
	var_dpl->op.var->v = "DPL";

	RzILOp *var_dph = rz_il_new_op(RZIL_OP_VAR);
	var_dph->op.var->v = "DPH";

	RzILOp *shiftl = rz_il_new_op(RZIL_OP_SHIFTL);
	shiftl->op.shiftl->x = var_dph;
	shiftl->op.shiftl->y = 8;

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = var_dpl;
	logor->op.logor->y = shiftl;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->key = logor;
	store->op.store->mem = 0;
	store->op.store->value = var_a;

	RzPVector *oplist = rz_il_make_oplist(id, 6, var_a, var_dpl, var_dph, shiftl, logor, store);
	return oplist;
}

RzPVector *i8051_movx_ri_a(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[0], 0xF2);
	RzILOp *var_ri = rz_il_new_op(RZIL_OP_VAR);
	var_ri->op.var->v = regname;

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->key = var_ri;
	store->op.store->mem = 0;
	store->op.store->value = var_a;

	RzPVector *oplist = rz_il_make_oplist(id, 3, var_a, var_ri, store);
	return oplist;
}

RzPVector *i8051_movx_a_dptr(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	RzILOp *var_dpl = rz_il_new_op(RZIL_OP_VAR);
	var_dpl->op.var->v = "DPL";

	RzILOp *var_dph = rz_il_new_op(RZIL_OP_VAR);
	var_dph->op.var->v = "DPH";

	RzILOp *shiftl = rz_il_new_op(RZIL_OP_SHIFTL);
	shiftl->op.shiftl->x = var_dph;
	shiftl->op.shiftl->y = 8; // shift 8 bits

	RzILOp *logor = rz_il_new_op(RZIL_OP_LOGOR);
	logor->op.logor->x = var_dpl;
	logor->op.logor->y = shiftl; // DPL+DPH = DPTR

	RzILOp *load = rz_il_new_op(RZIL_OP_STORE);
	load->op.load->key = 4;
	load->op.load->mem = 0;

	RzILOp *set_a = rz_il_new_op(RZIL_OP_SET);
	set_a->op.set->x = load;
	set_a->op.set->v = "ACC";

	RzILOp *perform_a = rz_il_new_op(RZIL_OP_PERFORM);
	perform_a->op.perform->eff = set_a;

	RzPVector *oplist = rz_il_make_oplist(id, 8, var_a, var_dpl, var_dph, shiftl, logor, load, set_a, perform_a);
	return oplist;
}

RzPVector *i8051_movx_a_ri(RzILVM *vm, ut64 id, const ut8 *buf) {
	RzILOp *var_a = rz_il_new_op(RZIL_OP_VAR);
	var_a->op.var->v = "ACC";

	char *regname = get_regname_bybase(buf[0], 0xE2);
	RzILOp *var_ri = rz_il_new_op(RZIL_OP_VAR);
	var_ri->op.var->v = regname;

	RzILOp *load = rz_il_new_op(RZIL_OP_STORE);
	load->op.load->key = var_ri;
	load->op.load->mem = 0;

	RzILOp *set_a = rz_il_new_op(RZIL_OP_SET);
	set_a->op.set->x = load;
	set_a->op.set->v = "ACC";

	RzILOp *perform_a = rz_il_new_op(RZIL_OP_PERFORM);
	perform_a->op.perform->eff = set_a;

	RzPVector *oplist = rz_il_make_oplist(id, 5, var_a, var_ri, load, set_a, perform_a);
	return oplist;
}

RzPVector *i8051_movx(RzILVM *vm, ut64 id, const ut8 *buf, _8051_op_t op) {
	switch (op.op) {
	case 0xF0:
		return i8051_movx_dptr_a(vm, id, buf);
	case 0xF2:
	case 0xF3:
		return i8051_movx_ri_a(vm, id, buf);
	case 0xE0:
		return i8051_movx_a_dptr(vm, id, buf);
	case 0xE2:
	case 0xE3:
		return i8051_movx_a_ri(vm, id, buf);
	default:
		return NULL;
	}
}

static bool rzil_init_i8051(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);

	RzAnalysisRzil *rzil = analysis->rzil;

	if (rzil->inited) {
		eprintf("Already init\n");
		return true;
	}

	// create core theory VM
	if (!rz_il_vm_init(rzil->vm, 0, 16, 8)) {
		RZ_LOG_ERROR("RZIL : Init VM failed\n");
		return false;
	}

	rz_il_vm_add_reg(rzil->vm, "R0", 8);
	rz_il_vm_add_reg(rzil->vm, "R1", 8);
	rz_il_vm_add_reg(rzil->vm, "R2", 8);
	rz_il_vm_add_reg(rzil->vm, "R3", 8);
	rz_il_vm_add_reg(rzil->vm, "R4", 8);
	rz_il_vm_add_reg(rzil->vm, "R5", 8);
	rz_il_vm_add_reg(rzil->vm, "R6", 8);
	rz_il_vm_add_reg(rzil->vm, "R7", 8);
	rz_il_vm_add_reg(rzil->vm, "SP", 8);
	rz_il_vm_add_reg(rzil->vm, "DPL", 8);
	rz_il_vm_add_reg(rzil->vm, "DPH", 8);
	rz_il_vm_add_reg(rzil->vm, "PSW", 8);
	rz_il_vm_add_reg(rzil->vm, "ACC", 8);
	rz_il_vm_add_reg(rzil->vm, "B", 8);

	rz_il_vm_add_mem(rzil->vm, rzil->vm->data_size);

	rzil->inited = true;
	return true;
}

static bool rzil_fini_i8051(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);

	RzAnalysisRzil *rzil = analysis->rzil;
	if (rzil->vm) {
		rz_il_vm_fini(rzil->vm);
		rzil->vm = NULL;
	}

	rzil->inited = false;
	return true;
}

static bool set_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"gpr	r0	.8	0	0\n"
		"gpr	r1	.8	1	0\n"
		"gpr	r2	.8	2	0\n"
		"gpr	r3	.8	3	0\n"
		"gpr	r4	.8	4	0\n"
		"gpr	r5	.8	5	0\n"
		"gpr	r6	.8	6	0\n"
		"gpr	r7	.8	7	0\n"
		"gpr	a	.8	8	0\n"
		"gpr	b	.8	9	0\n"
		"gpr	dptr	.16	10	0\n"
		"gpr	dpl	.8	10	0\n"
		"gpr	dph	.8	11	0\n"
		"gpr	psw	.8	12	0\n"
		"gpr	p	.1	.96	0\n"
		"gpr	ov	.1	.98	0\n"
		"gpr	ac	.1	.102	0\n"
		"gpr	c	.1	.103	0\n"
		"gpr	sp	.8	13	0\n"
		"gpr	pc	.16	15	0\n"
		// ---------------------------------------------------
		// 8051 memory emulation control registers
		// These registers map 8051 memory classes to r2's
		// linear address space. Registers contain base addr
		// in r2 memory space representing the memory class.
		// Offsets are initialized based on asm.cpu, but can
		// be updated with ar command.
		//
		// _code
		//		program memory (CODE)
		// _idata
		//		internal data memory (IDATA, IRAM)
		// _sfr
		//		special function registers (SFR)
		// _xdata
		//		external data memory (XDATA, XRAM)
		// _pdata
		//		page accessed by movx @ri op (PDATA, XREG)
		//		r2 addr = (_pdata & 0xff) << 8 + x_data
		//		if 0xffffffnn, addr = ([SFRnn] << 8) + _xdata (TODO)
		"gpr	_code	.32	20 0\n"
		"gpr	_idata	.32 24 0\n"
		"gpr	_sfr	.32	28 0\n"
		"gpr	_xdata	.32 32 0\n"
		"gpr	_pdata	.32	36 0\n";

	int retval = rz_reg_set_profile_string(analysis->reg, p);
	if (retval) {
		// reset emulation control registers based on cpu
		set_cpu_model(analysis, true);
	}

	return retval;
}

static int i8051_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	set_cpu_model(analysis, false);

	int i = 0;
	while (_8051_ops[i].string && _8051_ops[i].op != (buf[0] & ~_8051_ops[i].mask)) {
		i++;
	}

	ut8 arg1 = _8051_ops[i].arg1;
	ut8 arg2 = _8051_ops[i].arg2;

	op->cycles = _8051_ops[i].cycles;
	op->failcycles = _8051_ops[i].cycles;
	op->nopcode = 1;
	op->size = _8051_ops[i].len;
	op->type = _8051_ops[i].type;
	op->family = RZ_ANALYSIS_OP_FAMILY_CPU; // maybe also FAMILY_IO...
	op->id = i;

	switch (_8051_ops[i].instr) {
	default:
		op->cond = RZ_TYPE_COND_AL;
		break;
	case OP_CJNE:
	case OP_DJNZ:
	case OP_JB:
	case OP_JBC:
	case OP_JNZ:
		op->cond = RZ_TYPE_COND_NE;
		break;
	case OP_JNB:
	case OP_JZ:
		op->cond = RZ_TYPE_COND_EQ;
		break;
	case OP_JC:
		op->cond = RZ_TYPE_COND_HS;
		break;
	case OP_JNC:
		op->cond = RZ_TYPE_COND_LO;
	}

	switch (_8051_ops[i].instr) {
	default:
		op->eob = false;
		break;
	case OP_CJNE:
	case OP_DJNZ:
	case OP_JB:
	case OP_JBC:
	case OP_JC:
	case OP_JMP:
	case OP_JNB:
	case OP_JNC:
	case OP_JNZ:
	case OP_JZ:
		op->eob = true;
	}

	// TODO: op->datatype

	switch (arg1) {
	default:
		break;
	case A_DIRECT:
		op->ptr = map_direct_addr(analysis->rzil->vm, buf[1]);
		break;
	case A_BIT:
		op->ptr = map_direct_addr(analysis->rzil->vm, arg_bit(buf[1]));
		break;
	case A_IMMEDIATE:
		op->val = buf[1];
		break;
	case A_IMM16:
		op->val = buf[1] * 256 + buf[2];
		op->ptr = op->val + i8051_reg_read(analysis->rzil->vm, "_xdata"); // best guess, it's a XRAM pointer
	}

	switch (arg2) {
	default:
		break;
	case A_DIRECT:
		if (arg1 == A_RI || arg1 == A_RN) {
			op->ptr = map_direct_addr(analysis->rzil->vm, buf[1]);
		} else if (arg1 != A_DIRECT) {
			op->ptr = map_direct_addr(analysis->rzil->vm, buf[2]);
		}
		break;
	case A_BIT:
		op->ptr = arg_bit((arg1 == A_RI || arg1 == A_RN) ? buf[1] : buf[2]);
		op->ptr = map_direct_addr(analysis->rzil->vm, op->ptr);
		break;
	case A_IMMEDIATE:
		op->val = (arg1 == A_RI || arg1 == A_RN) ? buf[1] : buf[2];
	}

	switch (_8051_ops[i].instr) {
	default:
		break;
	case OP_PUSH:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 1;
		break;
	case OP_POP:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -1;
		break;
	case OP_RET:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -2;
		break;
	case OP_CALL:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
		if (arg1 == A_ADDR11) {
			op->jump = arg_addr11(addr, addr + op->size, buf);
			op->fail = addr + op->size;
		} else if (arg1 == A_ADDR16) {
			op->jump = apply_bank(addr, 0x100 * buf[1] + buf[2]);
			op->fail = addr + op->size;
		}
		break;
	case OP_JMP:
		if (arg1 == A_ADDR11) {
			op->jump = arg_addr11(addr, addr + op->size, buf);
			op->fail = addr + op->size;
		} else if (arg1 == A_ADDR16) {
			op->jump = apply_bank(addr, 0x100 * buf[1] + buf[2]);
			op->fail = addr + op->size;
		} else if (arg1 == A_OFFSET) {
			op->jump = arg_offset(addr, addr + op->size, buf[1]);
			op->fail = addr + op->size;
		}
		break;
	case OP_CJNE:
	case OP_DJNZ:
	case OP_JC:
	case OP_JNC:
	case OP_JZ:
	case OP_JNZ:
	case OP_JB:
	case OP_JBC:
	case OP_JNB:
		op->jump = arg_offset(addr, addr + op->size, buf[op->size - 1]);
		op->fail = addr + op->size;
	}

	if (op->ptr != -1 && op->refptr == 0) {
		op->refptr = 1;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		ut8 copy[3] = { 0, 0, 0 };
		memcpy(copy, buf, len >= 3 ? 3 : len);
		analop_esil(analysis, op, addr, copy, _8051_ops[i]);
	}

	int olen = 0;
	op->mnemonic = rz_8051_disas(addr, buf, len, &olen);
	op->size = olen;

	if (mask & RZ_ANALYSIS_OP_MASK_HINT) {
		// TODO: op->hint
	}

	return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_8051 = {
	.name = "8051",
	.arch = "8051",
	.esil = true,
	.bits = 8 | 16,
	.desc = "8051 CPU code analysis plugin",
	.license = "LGPL3",
	.op = &i8051_op,
	.set_reg_profile = &set_reg_profile,
	.rzil_init = rzil_init_i8051,
	.rzil_fini = rzil_fini_i8051
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_8051,
	.version = RZ_VERSION
};
#endif
