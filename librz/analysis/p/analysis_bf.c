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

struct bf_stack_t {
	ut64 stack[BF_ID_STACK];
	int sp;
};
typedef struct bf_stack_t BfStack;

typedef struct bf_context_t {
	BfStack *stack;
	HtUP *label_names;
	ut64 op_count;
} BfContext;

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
	putchar(c);
	rz_bv_free(bv);
}

ut64 pop_astack(BfStack *stack) {
	if (stack->sp <= 0) {
		RZ_LOG_ERROR("RzIL: brainfuck: the stack is empty\n");
		return -1;
	}

	stack->sp -= 1;
	return stack->stack[stack->sp];
}

void push_astack(BfStack *stack, ut64 id) {
	if (stack->sp >= BF_ID_STACK - 1) {
		RZ_LOG_ERROR("RzIL: brainfuck: the stack is full\n");
		return;
	}
	stack->stack[stack->sp] = id;
	stack->sp += 1;
}

ut64 parse_label_id(char *lbl_name) {
	char *addr_str = strchr(lbl_name, ']') + 1;
	ut64 addr = rz_num_math(NULL, addr_str);
	return addr;
}

RzILOpEffect *bf_right_arrow(RzILVM *vm, ut64 id) {
	// (set ptr (+ (val ptr) (int 1)))
	RzILOpBitVector *add = rz_il_op_new_add(bf_il_ptr(), bf_il_one(BF_ADDR_SIZE));
	return bf_il_set_ptr(add);
}

RzILOpEffect *bf_left_arrow(RzILVM *vm, ut64 id) {
	// (set ptr (- (val ptr) (int 1)))
	RzILOpBitVector *sub = rz_il_op_new_sub(bf_il_ptr(), bf_il_one(BF_ADDR_SIZE));
	return bf_il_set_ptr(sub);
}

RzILOpEffect *bf_inc(RzILVM *vm, ut64 id) {
	// (store mem (var ptr) (+ (load (var ptr)) (int 1)))
	// mem == 0 because is the only mem in bf
	RzILOpBitVector *load = rz_il_op_new_load(0, bf_il_ptr());
	RzILOpBitVector *add = rz_il_op_new_add(load, bf_il_one(BF_BYTE_SIZE));
	return rz_il_op_new_store(0, bf_il_ptr(), add);
}

RzILOpEffect *bf_dec(RzILVM *vm, ut64 id) {
	// (store mem (var ptr) (- (load (var ptr)) (int 1)))
	// mem == 0 because is the only mem in bf
	RzILOpBitVector *load = rz_il_op_new_load(0, bf_il_ptr());
	RzILOpBitVector *sub = rz_il_op_new_sub(load, bf_il_one(BF_BYTE_SIZE));
	return rz_il_op_new_store(0, bf_il_ptr(), sub);
}

RzILOpEffect *bf_out(RzILVM *vm, ut64 id) {
	// (goto write)
	return rz_il_op_new_goto("write");
}

RzILOpEffect *bf_in(RzILVM *vm, ut64 id) {
	// (goto hook_read)
	return rz_il_op_new_goto("read");
}

RzILOpEffect *bf_llimit(RzILVM *vm, BfContext *ctx, ut64 id, ut64 addr) {
	// (perform (branch (load mem (var ptr))
	//                  (do nothing)
	//                  (goto ]))
	char *cur_lbl_name = NULL, *to_free = NULL, *dst_lbl_name = NULL;
	RzILEffectLabel *cur_label, *dst_label;
	RzBitVector *cur_addr;

	cur_lbl_name = ht_up_find(ctx->label_names, addr, NULL);
	if (!cur_lbl_name) {
		// no label name bind to current address
		cur_lbl_name = to_free = rz_str_newf("[%lld", addr);
		ht_up_insert(ctx->label_names, addr, cur_lbl_name);
		push_astack(ctx->stack, addr);

		// create a label in VM
		cur_label = rz_il_vm_find_label_by_name(vm, cur_lbl_name);
		if (!cur_label) {
			// should always reach here if enter "!cur_lbl_name" branch
			cur_addr = rz_bv_new_from_ut64(vm->addr_size, addr);
			rz_il_vm_create_label(vm, cur_lbl_name, cur_addr);
			rz_bv_free(cur_addr);
		}
	}

	dst_lbl_name = rz_str_newf("]%lld", addr);
	dst_label = rz_il_vm_find_label_by_name(vm, dst_lbl_name);
	if (!dst_label) {
		dst_label = rz_il_vm_create_label_lazy(vm, dst_lbl_name);
	}
	free(dst_lbl_name);
	free(to_free);

	RzILOpBitVector *var = rz_il_op_new_var("ptr", RZ_IL_VAR_KIND_GLOBAL);
	RzILOpBool *cond = rz_il_op_new_non_zero(rz_il_op_new_load(0, var));

	// goto ]
	RzILOpEffect *goto_ = rz_il_op_new_goto(dst_label->label_id);

	// branch if (load mem (var ptr)) is false then goto ]
	return rz_il_op_new_branch(cond, NULL, goto_);
}

RzILOpEffect *bf_rlimit(RzILVM *vm, BfContext *ctx, ut64 id, ut64 addr) {
	// (perform (branch (load mem (var ptr))
	//                  (goto [)
	//                  (do nothing))
	char *cur_lbl_name = NULL, *to_free = NULL, *dst_lbl_name = NULL;
	RzILEffectLabel *dst_label;
	ut64 dst_addr;

	cur_lbl_name = ht_up_find(ctx->label_names, addr, NULL);
	if (!cur_lbl_name) {
		dst_addr = pop_astack(ctx->stack);
		to_free = cur_lbl_name = rz_str_newf("]%lld", dst_addr);
		ht_up_insert(ctx->label_names, addr, cur_lbl_name);
	}

	if (!rz_il_hash_find_addr_by_lblname(vm, cur_lbl_name)) {
		RzBitVector *cur_bv_addr = rz_bv_new_from_ut64(vm->addr_size, addr);
		rz_il_vm_update_label(vm, cur_lbl_name, cur_bv_addr);
		rz_bv_free(cur_bv_addr);
	}

	// Get label of '['
	dst_addr = parse_label_id(cur_lbl_name);
	dst_lbl_name = ht_up_find(ctx->label_names, dst_addr, NULL);
	rz_return_val_if_fail(dst_lbl_name, NULL);
	dst_label = rz_il_vm_find_label_by_name(vm, dst_lbl_name);

	RzILOpBitVector *var = rz_il_op_new_var("ptr", RZ_IL_VAR_KIND_GLOBAL);
	RzILOpBool *cond = rz_il_op_new_non_zero(rz_il_op_new_load(0, var));

	// goto [
	RzILOpEffect *goto_ = rz_il_op_new_goto(dst_label->label_id);

	// branch if (load mem (var ptr)) is true then goto ]
	RzILOpEffect *branch = rz_il_op_new_branch(cond, goto_, NULL);

	free(to_free);
	return branch;
}

static void bf_free_kv(HtUPKv *kv) {
	free(kv->value);
}

static BfContext *bf_context_new() {
	BfContext *ctx = RZ_NEW0(BfContext);
	if (!ctx) {
		return NULL;
	}

	ctx->stack = RZ_NEW0(BfStack);
	ctx->label_names = ht_up_new((HtUPDupValue)strdup, bf_free_kv, NULL);
	return ctx;
}

static void bf_context_free(BfContext *ctx) {
	if (!ctx) {
		return;
	}
	ht_up_free(ctx->label_names);
	free(ctx->stack);
	free(ctx);
}

static bool bf_fini_rzil(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);

	RzAnalysisRzil *rzil = analysis->rzil;
	bf_context_free(rzil->user);

	rzil->user = NULL;
	rzil->inited = false;
	return true;
}

static bool bf_init_rzil(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);
	RzAnalysisRzil *rzil = analysis->rzil;

	if (rzil->inited) {
		RZ_LOG_ERROR("RzIL: brainfuck: already initialized\n");
		return true;
	}

	// TODO : get some arguments from rizin, predefined some for now.
	ut32 addrsize = BF_ADDR_SIZE;
	ut64 start_addr = 0;

	// create core theory VM
	if (!rz_il_vm_init(rzil->vm, start_addr, addrsize, false)) {
		RZ_LOG_ERROR("RzIL: brainfuck: failed to initialize VM\n");
		return false;
	}

	RzBuffer *buf = rz_buf_new_sparse_overlay(rzil->io_buf, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!buf) {
		rz_il_vm_fini(rzil->vm);
		return false;
	}
	RzILMem *mem = rz_il_mem_new(buf, 64);
	if (!mem) {
		rz_buf_free(buf);
		rz_il_vm_fini(rzil->vm);
		return false;
	}
	rz_il_vm_add_mem(rzil->vm, 0, mem);

	rzil->user = bf_context_new();

	// set ptr to BF_ADDR_MEM
	rz_reg_setv(analysis->reg, "ptr", BF_ADDR_MEM);

	RzILEffectLabel *read_label = rz_il_vm_create_label_lazy(rzil->vm, "read");
	RzILEffectLabel *write_label = rz_il_vm_create_label_lazy(rzil->vm, "write");
	read_label->addr = (void *)bf_syscall_read;
	write_label->addr = (void *)bf_syscall_write;
	read_label->type = EFFECT_LABEL_SYSCALL;
	write_label->type = EFFECT_LABEL_HOOK;

	rzil->inited = true;
	return true;
}

#define BUFSIZE_INC 32
static int bf_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (!op) {
		return -1;
	} else if (!analysis->rzil) {
		RZ_LOG_ERROR("RzIL: brainfuck: the VM hasn't been initialized\n");
		return -1;
	}

	op->size = 1;
	op->id = getid(buf[0]);
	op->addr = addr;

	BfContext *ctx = analysis->rzil->user;
	RzILVM *vm = analysis->rzil->vm;
	RzILOpEffect *ilop = NULL;
	op->rzil_op = RZ_NEW0(RzAnalysisRzilOp);
	if (!op->rzil_op) {
		RZ_LOG_ERROR("Fail to init rzil op\n");
		return -1;
	}
	ut64 dst = 0LL;

	switch (buf[0]) {
	case '[':
		ilop = bf_llimit(vm, ctx, op->id, addr);
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->fail = addr + 1;
		buf = rz_mem_dup((void *)buf, len);
		if (!buf) {
			break;
		}
		{
			const ut8 *p = buf + 1;
			int lev = 0, i = 1;
			len--;
			while (i < len && *p) {
				if (*p == '[') {
					lev++;
				}
				if (*p == ']') {
					lev--;
					if (lev == -1) {
						dst = addr + (size_t)(p - buf);
						dst++;
						op->jump = dst;
						goto beach;
					}
				}
				if (*p == 0x00 || *p == 0xff) {
					op->type = RZ_ANALYSIS_OP_TYPE_ILL;
					goto beach;
				}
				if (i == len - 1 && analysis->read_at) {
					int new_buf_len = len + 1 + BUFSIZE_INC;
					ut8 *new_buf = calloc(new_buf_len, 1);
					if (new_buf) {
						free((ut8 *)buf);
						(void)analysis->read_at(analysis, addr, new_buf, new_buf_len);
						buf = new_buf;
						p = buf + i;
						len += BUFSIZE_INC;
					}
				}
				p++;
				i++;
			}
		}
	beach:
		free((ut8 *)buf);
		break;
	case ']':
		ilop = bf_rlimit(vm, ctx, op->id, addr);
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		break;
	case '>':
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		ilop = bf_right_arrow(vm, op->id);
		break;
	case '<':
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		ilop = bf_left_arrow(vm, op->id);
		break;
	case '+':
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		ilop = bf_inc(vm, op->id);
		break;
	case '-':
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		ilop = bf_dec(vm, op->id);
		break;
	case '.':
		ilop = bf_out(vm, op->id);
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case ',':
		ilop = bf_in(vm, op->id);
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case 0x00:
	case 0xff:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		ilop = rz_il_op_new_nop();
		break;
	}
	if (ilop) {
		op->rzil_op->op = ilop;
	}
	ctx->op_count++;
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	return strdup(
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
	.bits = 8,
	.op = &bf_op,
	.get_reg_profile = get_reg_profile,
	.rzil_init = bf_init_rzil,
	.rzil_fini = bf_fini_rzil
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_bf,
	.version = RZ_VERSION
};
#endif
