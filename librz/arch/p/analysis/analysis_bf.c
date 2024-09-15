// SPDX-FileCopyrightText: 2011-2016 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

static int getid(char ch) {
	const char *keys = "[]<>+-,.";
	const char *cidx = strchr(keys, ch);
	return cidx ? cidx - keys + 1 : 0;
}

/* New IL uplift bf */
#define BF_ADDR_MEM  0x10000
#define BF_ADDR_SIZE 64
#define BF_BYTE_SIZE 8
#define BF_ID_STACK  32

#define bf_il_ptr()      rz_il_op_new_var("ptr", RZ_IL_VAR_KIND_GLOBAL)
#define bf_il_set_ptr(x) rz_il_op_new_set("ptr", false, x)
#define bf_il_one(l)     rz_il_op_new_bitv_from_ut64(l, 1)

static void bf_syscall_read(RzILVM *vm, RzILOpEffect *op) {
	ut8 c = getc(stdin);
	RzBitVector *bv = rz_bv_new_from_ut64(BF_BYTE_SIZE, c);
	RzILVal *ptr_val = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, "ptr");
	if (ptr_val->type == RZ_IL_TYPE_PURE_BITVECTOR) {
		rz_il_vm_mem_store(vm, 0, ptr_val->data.bv, bv);
	} else {
		rz_warn_if_reached();
	}
	rz_bv_free(bv);
}

static void bf_syscall_write(RzILVM *vm, RzILOpEffect *op) {
	RzILVal *ptr_val = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, "ptr");
	if (ptr_val->type != RZ_IL_TYPE_PURE_BITVECTOR) {
		rz_warn_if_reached();
		return;
	}
	RzBitVector *bv = rz_il_vm_mem_load(vm, 0, ptr_val->data.bv);
	ut32 c = rz_bv_to_ut32(bv);
	if (c) {
		putchar(c);
		fflush(stdout);
	}
	rz_bv_free(bv);
}

RzILOpEffect *bf_right_arrow() {
	// (set ptr (+ (val ptr) (int 1)))
	RzILOpBitVector *add = rz_il_op_new_add(bf_il_ptr(), bf_il_one(BF_ADDR_SIZE));
	return bf_il_set_ptr(add);
}

RzILOpEffect *bf_left_arrow() {
	// (set ptr (- (val ptr) (int 1)))
	RzILOpBitVector *sub = rz_il_op_new_sub(bf_il_ptr(), bf_il_one(BF_ADDR_SIZE));
	return bf_il_set_ptr(sub);
}

RzILOpEffect *bf_inc() {
	// (store mem (var ptr) (+ (load (var ptr)) (int 1)))
	// mem == 0 because is the only mem in bf
	RzILOpBitVector *load = rz_il_op_new_load(0, bf_il_ptr());
	RzILOpBitVector *add = rz_il_op_new_add(load, bf_il_one(BF_BYTE_SIZE));
	return rz_il_op_new_store(0, bf_il_ptr(), add);
}

RzILOpEffect *bf_dec() {
	// (store mem (var ptr) (- (load (var ptr)) (int 1)))
	// mem == 0 because is the only mem in bf
	RzILOpBitVector *load = rz_il_op_new_load(0, bf_il_ptr());
	RzILOpBitVector *sub = rz_il_op_new_sub(load, bf_il_one(BF_BYTE_SIZE));
	return rz_il_op_new_store(0, bf_il_ptr(), sub);
}

RzILOpEffect *bf_out() {
	// (goto write)
	return rz_il_op_new_goto("write");
}

RzILOpEffect *bf_in() {
	// (goto hook_read)
	return rz_il_op_new_goto("read");
}

/**
 * Search matching [ or ] starting at addr in direction given by dir (-1 or 1)
 */
static ut64 find_matching_bracket(RzAnalysis *analysis, ut64 addr, int dir) {
	if (!analysis->read_at) {
		return UT64_MAX;
	}
	static const ut64 max_dist = 2048; // some upper bound to avoid (almost) infinite loops
	ut64 dist = 0;
	int lev = dir;
	while (dist < max_dist) {
		dist++;
		addr += dir;
		if (addr == UT64_MAX) {
			break;
		}
		ut8 c;
		analysis->read_at(analysis, addr, &c, 1);
		switch (c) {
		case '[':
			lev++;
			break;
		case ']':
			lev--;
			break;
		case 0:
		case 0xff:
			// invalid code
			return UT64_MAX;
		default:
			continue;
		}
		if (lev == 0) {
			return addr;
		}
	}
	return UT64_MAX;
}

RzILOpEffect *bf_llimit(RzAnalysis *analysis, ut64 addr, ut64 target) {
	// (perform (branch (load mem (var ptr))
	//                  (do nothing)
	//                  (goto ]))
	RzILOpBitVector *var = rz_il_op_new_var("ptr", RZ_IL_VAR_KIND_GLOBAL);
	RzILOpBool *cond = rz_il_op_new_non_zero(rz_il_op_new_load(0, var));
	// goto ]
	RzILOpEffect *jmp = rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(64, target));
	// branch if (load mem (var ptr)) is false then goto ]
	return rz_il_op_new_branch(cond, NULL, jmp);
}

RzILOpEffect *bf_rlimit(RzAnalysis *analysis, ut64 addr, ut64 target) {
	// (perform (branch (load mem (var ptr))
	//                  (goto [)
	//                  (do nothing))
	RzILOpBitVector *var = rz_il_op_new_var("ptr", RZ_IL_VAR_KIND_GLOBAL);
	RzILOpBool *cond = rz_il_op_new_non_zero(rz_il_op_new_load(0, var));
	// goto [
	RzILOpEffect *jmp = rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(64, target));
	// branch if (load mem (var ptr)) is true then goto ]
	RzILOpEffect *branch = rz_il_op_new_branch(cond, jmp, NULL);
	return branch;
}

static RzAnalysisILConfig *il_config(RzAnalysis *analysis) {
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(64, false, 64);
	cfg->init_state = rz_analysis_il_init_state_new();
	if (!cfg->init_state) {
		rz_analysis_il_config_free(cfg);
		return NULL;
	}
	rz_analysis_il_init_state_set_var(cfg->init_state, "ptr", rz_il_value_new_bitv(rz_bv_new_from_ut64(64, BF_ADDR_MEM)));
	RzILEffectLabel *read_label = rz_il_effect_label_new("read", EFFECT_LABEL_SYSCALL);
	read_label->hook = bf_syscall_read;
	rz_analysis_il_config_add_label(cfg, read_label);
	RzILEffectLabel *write_label = rz_il_effect_label_new("write", EFFECT_LABEL_HOOK);
	write_label->hook = bf_syscall_write;
	rz_analysis_il_config_add_label(cfg, write_label);
	return cfg;
}

static int bf_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	rz_return_val_if_fail(analysis && op, -1);

	op->size = 1;
	op->id = getid(buf[0]);
	op->addr = addr;

	switch (buf[0]) {
	case '[':
		// Find the jump target, +1 because we jump directly after the matching bracket.
		// If not found this returns UT64_MAX, so this overflows to 0, which is considered the "invalid"
		// value for RzAnalysisOp, so it's fine.
		op->jump = find_matching_bracket(analysis, addr, 1) + 1;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = bf_llimit(analysis, addr, op->jump);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("while [ptr]");
		}
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->fail = addr + 1;
		break;
	case ']':
		// same idea for target as above
		op->jump = find_matching_bracket(analysis, addr, -1) + 1;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = bf_rlimit(analysis, addr, op->jump);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("loop");
		}
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		break;
	case '>':
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = bf_right_arrow();
		}
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("inc ptr");
		}
		break;
	case '<':
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = bf_left_arrow();
		}
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("dec ptr");
		}
		break;
	case '+':
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = bf_inc();
		}
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("inc [ptr]");
		}
		break;
	case '-':
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = bf_dec();
		}
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("dec [ptr]");
		}
		break;
	case '.':
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = bf_out();
		}
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("out [ptr]");
		}
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case ',':
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = bf_in();
		}
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("in [ptr]");
		}
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case 0x00:
	case 0xff:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("trap");
		}
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = rz_il_op_new_nop();
		}
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("nop");
		}
		break;
	}
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	return rz_str_dup(
		"=PC	pc\n"
		"=BP	ptr\n"
		"=SP	ptr\n"
		"=A0	ptr\n"
		"=A1	ptr\n"
		"=A2	ptr\n"
		"=A3	ptr\n"
		"gpr	ptr	.64	0	0\n" // data pointer
		"gpr	pc	.64	8	0\n" // program counter
	);
}

RzAnalysisPlugin rz_analysis_plugin_bf = {
	.name = "bf",
	.desc = "brainfuck code analysis plugin",
	.license = "LGPL3",
	.arch = "bf",
	.bits = 64, // RzIL emulation of bf and the reg definitions above use 64bit values
	.op = &bf_op,
	.get_reg_profile = get_reg_profile,
	.il_config = il_config
};
