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
#define BF_ADDR_SIZE  64
#define BF_ALIGN_SIZE 8
#define BF_ID_STACK   32

struct bf_stack_t {
	ut64 stack[BF_ID_STACK];
	int sp;
};
typedef struct bf_stack_t *BfStack;

typedef struct bf_context_t {
	BfStack stack;
	HtUP *label_names;
	ut64 op_count;
} BfContext;

static void bf_syscall_read(RzILVM *vm, RzILOp *op) {
	ut8 c = getc(stdin);
	RzILBitVector *bv = rz_il_bv_new_from_ut32(BF_ALIGN_SIZE, c);

	RzILVal *ptr_val = rz_il_value_dup(rz_il_hash_find_val_by_name(vm, "ptr"));

	rz_il_vm_mem_store(vm, 0, ptr_val->data.bv, bv);
	rz_il_value_free(ptr_val);
}

static void bf_syscall_write(RzILVM *vm, RzILOp *op) {
	RzILVal *ptr_val = rz_il_value_dup(rz_il_hash_find_val_by_name(vm, "ptr"));

	RzILBitVector *bv = rz_il_vm_mem_load(vm, 0, ptr_val->data.bv);
	if (!bv) {
		// default write nothing
		return;
	}
	ut32 c = rz_il_bv_to_ut32(bv);

	rz_il_value_free(ptr_val);
	rz_il_bv_free(bv);

	putchar(c);
}

ut64 pop_astack(BfStack stack) {
	if (stack->sp <= 0) {
		printf("Empty Stack\n");
		return -1;
	}

	stack->sp -= 1;
	ut64 ret = stack->stack[stack->sp];
	return ret;
}

void push_astack(BfStack stack, ut64 id) {
	if (stack->sp >= BF_ID_STACK - 1) {
		eprintf("Stack Full\n");
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

RzPVector *bf_right_arrow(RzILVM *vm, ut64 id) {
	// (set ptr (+ (val ptr) (int 1)))
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ptr";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->length = BF_ADDR_SIZE;
	int_->op.int_->value = 1;

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = var;
	add->op.add->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = add;
	set->op.set->v = "ptr";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	return rz_il_make_oplist(1, perform);
}

RzPVector *bf_left_arrow(RzILVM *vm, ut64 id) {
	// (set ptr (- (val ptr) (int 1)))
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ptr";

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = BF_ADDR_SIZE;

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.add->x = var;
	sub->op.add->y = int_;

	RzILOp *set = rz_il_new_op(RZIL_OP_SET);
	set->op.set->x = sub;
	set->op.set->v = "ptr";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = set;

	return rz_il_make_oplist(1, perform);
}

RzPVector *bf_inc(RzILVM *vm, ut64 id) {
	// (store mem (var ptr) (+ (load (var ptr)) (int 1)))
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ptr";

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0; // the only mem in bf
	load->op.load->key = var;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = BF_ALIGN_SIZE;

	RzILOp *add = rz_il_new_op(RZIL_OP_ADD);
	add->op.add->x = load;
	add->op.add->y = int_;

	RzILOp *var_2 = rz_il_new_op(RZIL_OP_VAR);
	var_2->op.var->v = "ptr";

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = var_2;
	store->op.store->value = add;

	return rz_il_make_oplist(1, store);
}

RzPVector *bf_dec(RzILVM *vm, ut64 id) {
	// (store mem (var ptr) (- (load (var ptr)) (int 1)))
	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	var->op.var->v = "ptr";

	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	load->op.load->mem = 0; // the only mem in bf
	load->op.load->key = var;

	RzILOp *int_ = rz_il_new_op(RZIL_OP_INT);
	int_->op.int_->value = 1;
	int_->op.int_->length = BF_ALIGN_SIZE;

	RzILOp *sub = rz_il_new_op(RZIL_OP_SUB);
	sub->op.sub->x = load;
	sub->op.sub->y = int_;

	RzILOp *var_2 = rz_il_new_op(RZIL_OP_VAR);
	var_2->op.var->v = "ptr";

	RzILOp *store = rz_il_new_op(RZIL_OP_STORE);
	store->op.store->mem = 0;
	store->op.store->key = var_2;
	store->op.store->value = sub;

	return rz_il_make_oplist(1, store);
}

RzPVector *bf_out(RzILVM *vm, ut64 id) {
	// (goto write)
	RzILOp *goto_ = rz_il_new_op(RZIL_OP_GOTO);
	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	goto_->op.goto_->lbl = "write";
	perform->op.perform->eff = goto_;

	return rz_il_make_oplist(1, perform);
}

RzPVector *bf_in(RzILVM *vm, ut64 id) {
	// (goto hook_read)
	RzILOp *goto_ = rz_il_new_op(RZIL_OP_GOTO);
	goto_->op.goto_->lbl = "read";

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = goto_;

	return rz_il_make_oplist(1, perform);
}

RzPVector *bf_llimit(RzILVM *vm, BfContext *ctx, ut64 id, ut64 addr) {
	// (perform (branch (load mem (var ptr))
	//                  (do nothing)
	//                  (goto ]))
	char *cur_lbl_name = NULL, *dst_lbl_name = NULL;
	RzILEffectLabel *cur_label, *dst_label;
	RzILBitVector *cur_addr;

	cur_lbl_name = ht_up_find(ctx->label_names, addr, NULL);
	if (!cur_lbl_name) {
		// no label name bind to current address
		cur_lbl_name = rz_str_newf("[%lld", addr);
		ht_up_insert(ctx->label_names, addr, cur_lbl_name);
		push_astack(ctx->stack, addr);

		// create a label in VM
		cur_label = rz_il_vm_find_label_by_name(vm, cur_lbl_name);
		if (!cur_label) {
			// should always reach here if enter "!cur_lbl_name" branch
			cur_addr = rz_il_ut64_addr_to_bv(addr);
			rz_il_vm_create_label(vm, cur_lbl_name, cur_addr);
			rz_il_free_bv_addr(cur_addr);
		}
	}

	dst_lbl_name = rz_str_newf("]%lld", addr);
	dst_label = rz_il_vm_find_label_by_name(vm, dst_lbl_name);
	if (!dst_label) {
		dst_label = rz_il_vm_create_label_lazy(vm, dst_lbl_name);
	}
	free(dst_lbl_name);

	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	RzILOp *branch = rz_il_new_op(RZIL_OP_BRANCH);
	RzILOp *goto_ = rz_il_new_op(RZIL_OP_GOTO);
	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);

	var->op.var->v = "ptr";

	load->op.load->mem = 0;
	load->op.load->key = var;

	// goto ]
	goto_->op.goto_->lbl = dst_label->label_id;

	// branch
	branch->op.branch->true_eff = NULL; // do nothing
	branch->op.branch->false_eff = goto_; // goto ]
	branch->op.branch->condition = load; // (load mem (var ptr))

	// perform
	perform->op.perform->eff = branch;

	return rz_il_make_oplist(1, perform);
}

RzPVector *bf_rlimit(RzILVM *vm, BfContext *ctx, ut64 id, ut64 addr) {
	// (perform (branch (load mem (var ptr))
	//                  (goto [)
	//                  (do nothing))
	char *cur_lbl_name = NULL, *dst_lbl_name = NULL;
	RzILEffectLabel *dst_label;
	ut64 dst_addr;

	cur_lbl_name = ht_up_find(ctx->label_names, addr, NULL);
	if (!cur_lbl_name) {
		dst_addr = pop_astack(ctx->stack);
		cur_lbl_name = rz_str_newf("]%lld", dst_addr);
		ht_up_insert(ctx->label_names, addr, cur_lbl_name);
	}

	if (!rz_il_hash_find_addr_by_lblname(vm, cur_lbl_name)) {
		RzILBitVector *cur_bv_addr = rz_il_ut64_addr_to_bv(addr);
		rz_il_vm_update_label(vm, cur_lbl_name, cur_bv_addr);
		rz_il_free_bv_addr(cur_bv_addr);
	}

	// Get label of '['
	dst_addr = parse_label_id(cur_lbl_name);
	dst_lbl_name = ht_up_find(ctx->label_names, dst_addr, NULL);
	rz_return_val_if_fail(dst_lbl_name, NULL);
	dst_label = rz_il_vm_find_label_by_name(vm, dst_lbl_name);

	RzILOp *var = rz_il_new_op(RZIL_OP_VAR);
	RzILOp *load = rz_il_new_op(RZIL_OP_LOAD);
	RzILOp *branch = rz_il_new_op(RZIL_OP_BRANCH);
	RzILOp *goto_ = rz_il_new_op(RZIL_OP_GOTO);
	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	RzILOp *inv = rz_il_new_op(RZIL_OP_INV);

	var->op.var->v = "ptr";

	load->op.load->mem = 0;
	load->op.load->key = var;

	inv->op.inv->x = load;

	// goto [
	goto_->op.goto_->lbl = dst_label->label_id;

	// branch
	branch->op.branch->true_eff = NULL; // do nothing
	branch->op.branch->false_eff = goto_; // goto [
	branch->op.branch->condition = inv; // (inv (load mem (var ptr)))

	// perform
	perform->op.perform->eff = branch;

	return rz_il_make_oplist(1, perform);
}

static bool bf_specific_init(RzAnalysisRzil *rzil) {
	RzILVM *vm = rzil->vm;

	// load reg
	// TODO use info of reg profile
	rz_il_vm_add_reg(vm, "ptr", BF_ADDR_SIZE);

	RzILEffectLabel *read_label = rz_il_vm_create_label_lazy(vm, "read");
	RzILEffectLabel *write_label = rz_il_vm_create_label_lazy(vm, "write");
	read_label->addr = (void *)bf_syscall_read;
	write_label->addr = (void *)bf_syscall_write;
	read_label->type = EFFECT_LABEL_SYSCALL;
	write_label->type = EFFECT_LABEL_HOOK;

	// init mem
	rz_il_vm_add_mem(vm, vm->data_size);
	rzil->inited = true;

	return true;
}

static bool bf_fini_rzil(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);

	RzAnalysisRzil *rzil = analysis->rzil;
	if (rzil->user) {
		BfContext *ctx = rzil->user;
		ht_up_free(ctx->label_names);
		free(ctx->stack);
		free(ctx);
		rzil->user = NULL;
	}

	if (rzil->vm) {
		rz_il_vm_fini(rzil->vm);
		rzil->vm = NULL;
	}

	rzil->inited = false;
	return true;
}

static bool bf_init_rzil(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);
	RzAnalysisRzil *rzil = analysis->rzil;

	if (rzil->inited) {
		eprintf("Already init\n");
		return true;
	}

	// TODO : get some arguments from rizin, predefined some for now.
	int addrsize = BF_ADDR_SIZE;
	int datasize = BF_ALIGN_SIZE;
	ut64 start_addr = 0;

	// create core theory VM
	if (!rz_il_vm_init(rzil->vm, start_addr, addrsize, datasize)) {
		RZ_LOG_ERROR("RZIL : Init VM failed\n");
		return false;
	}

	// init bf RZIL user-defined context
	BfStack astack = (BfStack)calloc(1, sizeof(struct bf_stack_t));
	HtUP *names = ht_up_new0();
	BfContext *context = RZ_NEW0(BfContext);
	context->stack = astack;
	context->op_count = 0;
	context->label_names = names;
	rzil->user = context;

	// bf specific init things
	return bf_specific_init(rzil);
}

#define BUFSIZE_INC 32
static int bf_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (!op) {
		return 1;
	}

	if (!analysis->rzil) {
		RZ_LOG_ERROR("RZIL VM hasn't been initialized\n");
		return 1;
	}

	/* Ayeeee! What's inside op? Do we have an initialized RzAnalysisOp? Are we going to have a leak here? :-( */
	memset(op, 0, sizeof(RzAnalysisOp)); /* We need to refactorize this. Something like rz_analysis_op_init would be more appropriate */
	op->size = 1;
	op->id = getid(buf[0]);
	op->addr = addr;
	op->rzil_op = NULL;

	BfContext *ctx = analysis->rzil->user;
	RzILVM *vm = analysis->rzil->vm;
	RzPVector *oplist;
	op->rzil_op = RZ_NEW0(RzAnalysisRzilOp);
	if (!op->rzil_op) {
		RZ_LOG_ERROR("Fail to init rzil op\n");
		return 1;
	}
	ut64 dst = 0LL;

	switch (buf[0]) {
	case '[':
		oplist = bf_llimit(vm, ctx, op->id, addr);
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
		oplist = bf_rlimit(vm, ctx, op->id, addr);
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		break;
	case '>':
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		oplist = bf_right_arrow(vm, op->id);
		break;
	case '<':
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		oplist = bf_left_arrow(vm, op->id);
		break;
	case '+':
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		oplist = bf_inc(vm, op->id);
		break;
	case '-':
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		oplist = bf_dec(vm, op->id);
		break;
	case '.':
		oplist = bf_out(vm, op->id);
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case ',':
		oplist = bf_in(vm, op->id);
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case 0x00:
	case 0xff:
		oplist = NULL;
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	default:
		oplist = NULL;
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	}
	if (oplist) {
		op->rzil_op->ops = oplist;
		op->rzil_op->root_node = NULL;
	}
	ctx->op_count++;
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	return strdup(
		"=PC	pc\n"
		"=BP	brk\n"
		"=SP	ptr\n"
		"=A0	rax\n"
		"=A1	rbx\n"
		"=A2	rcx\n"
		"=A3	rdx\n"
		"gpr	ptr	.32	0	0\n" // data pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	brk	.32	8	0\n" // brackets
		"gpr	scr	.32	12	0\n" // screen
		"gpr	kbd	.32	16	0\n" // keyboard
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
