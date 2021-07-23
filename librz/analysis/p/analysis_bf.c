// SPDX-FileCopyrightText: 2011-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

static size_t countChar(const ut8 *buf, int len, char ch) {
	int i;
	for (i = 0; i < len; i++) {
		if (buf[i] != ch) {
			break;
		}
	}
	return i;
}

static int getid(char ch) {
	const char *keys = "[]<>+-,.";
	const char *cidx = strchr(keys, ch);
	return cidx ? cidx - keys + 1 : 0;
}

/* New IL uplift bf */
#define BF_ADDR_SIZE 64
#define BF_ALIGN_SIZE 8

struct bf_stack_t {
        ut64 stack[32];
        int sp;
};
typedef struct bf_stack_t *BfStack;

static void bf_syscall_read(RzILVM vm, RzILOp op) {
        ut8 c = getc(stdin);
        BitVector bv = rz_il_bv_new_from_ut32(BF_ALIGN_SIZE, c);

        RzILVal ptr_val = rz_il_dump_value(rz_il_hash_find_val_by_name(vm, "ptr"));

	rz_il_vm_mem_store(vm, 0, ptr_val->data.bv, bv);
        rz_il_free_value(ptr_val);
}

static void bf_syscall_write(RzILVM vm, RzILOp op) {
        RzILVal ptr_val = rz_il_dump_value(rz_il_hash_find_val_by_name(vm, "ptr"));

        BitVector bv = rz_il_vm_mem_load(vm, 0, ptr_val->data.bv);
        ut32 c = rz_il_bv_to_ut32(bv);

        rz_il_free_value(ptr_val);
	rz_il_bv_free(bv);

        putchar(c);
}

ut64 pop_astack(BfStack stack) {
        if (stack->sp < 0) {
                printf("Empty Stack\n");
                return -1;
        }

        ut64 ret = stack->stack[stack->sp];
        stack->sp -= 1;
        return ret;
}

void push_astack(BfStack stack, ut64 id) {
        stack->sp += 1;
        stack->stack[stack->sp] = id;
}

ut64 alloc_id(BfStack stack, ut64 addr) {
        push_astack(stack, addr);
        return addr;
}

RzPVector *bf_right_arrow(RzILVM vm, ut64 id) {
        // (set ptr (+ (val ptr) (int 1)))
        RzILOp var = rz_il_new_op(RZIL_OP_VAR);
        var->op.var->v = "ptr";
        var->op.var->ret = 0;

        RzILOp int_ = rz_il_new_op(RZIL_OP_INT);
        int_->op.int_->length = BF_ADDR_SIZE;
        int_->op.int_->value = 1;
        int_->op.int_->ret = 1;

        RzILOp add = rz_il_new_op(RZIL_OP_ADD);
        add->op.add->x = 0;
        add->op.add->y = 1;
        add->op.add->ret = 2;

        RzILOp set = rz_il_new_op(RZIL_OP_SET);
        set->op.set->x = 2;
        set->op.set->v = "ptr";
        set->op.set->ret = 3; // eff

        RzILOp perform = rz_il_new_op(RZIL_OP_PERFORM);
        perform->op.perform->eff = 3;
        perform->op.perform->ret = -1; // no return;

        RzPVector *oplist = rz_il_make_oplist_with_id(id, 5, var, int_, add, set, perform);
        return oplist;
}

RzPVector *bf_left_arrow(RzILVM vm, ut64 id) {
        // (set ptr (- (val ptr) (int 1)))
        RzILOp var = rz_il_new_op(RZIL_OP_VAR);
        var->op.var->v = "ptr";
        var->op.var->ret = 0;

        RzILOp int_ = rz_il_new_op(RZIL_OP_INT);
        int_->op.int_->value = 1;
        int_->op.int_->length = BF_ADDR_SIZE;
        int_->op.int_->ret = 1;

        RzILOp sub = rz_il_new_op(RZIL_OP_SUB);
        sub->op.add->x = 0;
        sub->op.add->y = 1;
        sub->op.add->ret = 2;

        RzILOp set = rz_il_new_op(RZIL_OP_SET);
        set->op.set->x = 2;
        set->op.set->v = "ptr";
        set->op.set->ret = 3; // eff

        RzILOp perform = rz_il_new_op(RZIL_OP_PERFORM);
        perform->op.perform->eff = 3;
        perform->op.perform->ret = -1; // no return;

        RzPVector *oplist = rz_il_make_oplist_with_id(id, 5, var, int_, sub, set, perform);
        return oplist;
}

RzPVector *bf_inc(RzILVM vm, ut64 id) {
        // (store mem (var ptr) (+ (load (var ptr)) (int 1)))
        RzILOp var = rz_il_new_op(RZIL_OP_VAR);
        var->op.var->v = "ptr";
        var->op.var->ret = 0; // temp

        RzILOp load = rz_il_new_op(RZIL_OP_LOAD);
        load->op.load->mem = 0; // the only mem in bf
        load->op.load->key = 0;
        load->op.load->ret = 1;

        RzILOp int_ = rz_il_new_op(RZIL_OP_INT);
        int_->op.int_->value = 1;
        int_->op.int_->length = BF_ALIGN_SIZE;
        int_->op.int_->ret = 2;

        RzILOp add = rz_il_new_op(RZIL_OP_ADD);
        add->op.add->x = 1;
        add->op.add->y = 2;
        add->op.add->ret = 3;

        RzILOp var_2 = rz_il_new_op(RZIL_OP_VAR);
        var_2->op.var->v = "ptr";
        var_2->op.var->ret = 4;

        RzILOp store = rz_il_new_op(RZIL_OP_STORE);
        store->op.store->mem = 0;
        store->op.store->key = 4;
        store->op.store->value = 3;
        store->op.store->ret = -1;

        RzPVector *oplist = rz_il_make_oplist_with_id(id, 6, var, load, int_, add, var_2, store);
        return oplist;
}

RzPVector *bf_dec(RzILVM vm, ut64 id) {
        // (store mem (var ptr) (- (load (var ptr)) (int 1)))
        RzILOp var = rz_il_new_op(RZIL_OP_VAR);
        var->op.var->v = "ptr";
        var->op.var->ret = 0; // temp

        RzILOp load = rz_il_new_op(RZIL_OP_LOAD);
        load->op.load->mem = 0; // the only mem in bf
        load->op.load->key = 0;
        load->op.load->ret = 1;

        RzILOp int_ = rz_il_new_op(RZIL_OP_INT);
        int_->op.int_->value = 1;
        int_->op.int_->length = BF_ALIGN_SIZE;
        int_->op.int_->ret = 2;

        RzILOp sub = rz_il_new_op(RZIL_OP_SUB);
        sub->op.sub->x = 1;
        sub->op.sub->y = 2;
        sub->op.sub->ret = 3;

        RzILOp var_2 = rz_il_new_op(RZIL_OP_VAR);
        var_2->op.var->v = "ptr";
        var_2->op.var->ret = 4;

        RzILOp store = rz_il_new_op(RZIL_OP_STORE);
        store->op.store->mem = 0;
        store->op.store->key = 4;
        store->op.store->value = 3;
        store->op.store->ret = -1;

        RzPVector *oplist = rz_il_make_oplist_with_id(id, 6, var, load, int_, sub, var_2, store);
        return oplist;
}

RzPVector *bf_out(RzILVM vm, ut64 id) {
        // (goto write)
        RzILOp goto_ = rz_il_new_op(RZIL_OP_GOTO);
        RzILOp perform = rz_il_new_op(RZIL_OP_PERFORM);
        goto_->op.goto_->ret_ctrl_eff = 0;
        goto_->op.goto_->lbl = "write";

        perform->op.perform->eff = 0;
        perform->op.perform->ret = -1;

        RzPVector *oplist = rz_il_make_oplist_with_id(id, 2, goto_, perform);
        return oplist;
}

RzPVector *bf_in(RzILVM vm, ut64 id) {
        // (goto hook_read)
        RzILOp goto_ = rz_il_new_op(RZIL_OP_GOTO);
        goto_->op.goto_->ret_ctrl_eff = 0;
        goto_->op.goto_->lbl = "read";

        RzILOp perform = rz_il_new_op(RZIL_OP_PERFORM);
        perform->op.perform->eff = 0;
        perform->op.perform->ret = -1;

        RzPVector *oplist = rz_il_make_oplist_with_id(id, 2, goto_, perform);
        return oplist;
}

RzPVector *bf_llimit(RzILVM vm, BfStack assistant_stack, ut64 id, ut64 addr) {
        // (perform (branch (load mem (var ptr))
        //                  (do nothing)
        //                  (goto ]))
        string lbl_name;
        EffectLabel target_label;
        ut64 lable_count_id = alloc_id(assistant_stack, addr);

        // Create current label and goto target label
        lbl_name = rz_str_newf("[%lld", lable_count_id);

	// IMPORTANT : Analysis op will be entered multiple times
	//           : prevent redundant operations
	if (rz_il_vm_find_label_by_name(vm, lbl_name)) {
		free(lbl_name);
		return NULL;
        }

	// Normal create label
        BitVector current_addr = rz_il_ut64_addr_to_bv(addr);
        rz_il_vm_create_label(vm, lbl_name, current_addr);
        free(lbl_name);
        rz_il_free_bv_addr(current_addr);

        lbl_name = rz_str_newf("]%lld", lable_count_id);
        target_label = rz_il_vm_create_label_lazy(vm, lbl_name);
        free(lbl_name);

        RzILOp var = rz_il_new_op(RZIL_OP_VAR);
        RzILOp load = rz_il_new_op(RZIL_OP_LOAD);
        RzILOp branch = rz_il_new_op(RZIL_OP_BRANCH);
        RzILOp goto_ = rz_il_new_op(RZIL_OP_GOTO);
        RzILOp perform = rz_il_new_op(RZIL_OP_PERFORM);

        var->op.var->v = "ptr";
        var->op.var->ret = 0;

        load->op.load->mem = 0;
        load->op.load->key = 0;
        load->op.load->ret = 1;

        // goto ]
        goto_->op.goto_->lbl = target_label->label_id;
        goto_->op.goto_->ret_ctrl_eff = 2;

        // branch
        branch->op.branch->true_eff = -1; // do nothing
        branch->op.branch->false_eff = 2; // goto ]
        branch->op.branch->condition = 1; // (load mem (var ptr))
        branch->op.branch->ret = 3;

        // perform
        perform->op.perform->eff = 3;
        perform->op.perform->ret = -1;

        RzPVector *oplist = rz_il_make_oplist_with_id(id, 5, var, load, goto_, branch, perform);
        return oplist;
}

RzPVector *bf_rlimit(RzILVM vm, BfStack stack, ut64 id, ut64 addr) {
        // (perform (branch (load mem (var ptr))
        //                  (goto [)
        //                  (do nothing))
        string lbl_name;
        EffectLabel target_label;
        ut64 right_id = pop_astack(stack);

        lbl_name = rz_str_newf("]%lld", right_id);

	if (rz_il_hash_find_addr_by_lblname(vm, lbl_name)) {
		// Has been created, do nothing
		free(lbl_name);
		return NULL;
	}

        BitVector bv_addr = rz_il_ut64_addr_to_bv(addr);
        rz_il_vm_update_label(vm, lbl_name, bv_addr); // this label has been created in previous
        free(lbl_name);
        rz_il_free_bv_addr(bv_addr);

        lbl_name = rz_str_newf("[%lld", right_id);
        target_label = rz_il_vm_find_label_by_name(vm, lbl_name);
        free(lbl_name);

        RzILOp var = rz_il_new_op(RZIL_OP_VAR);
        RzILOp load = rz_il_new_op(RZIL_OP_LOAD);
        RzILOp branch = rz_il_new_op(RZIL_OP_BRANCH);
        RzILOp goto_ = rz_il_new_op(RZIL_OP_GOTO);
        RzILOp perform = rz_il_new_op(RZIL_OP_PERFORM);
        RzILOp inv = rz_il_new_op(RZIL_OP_INV);

        var->op.var->v = "ptr";
        var->op.var->ret = 0;

        load->op.load->mem = 0;
        load->op.load->key = 0;
        load->op.load->ret = 1;

        inv->op.inv->x = 1;
        inv->op.inv->ret = 2;

        // goto [
        goto_->op.goto_->lbl = target_label->label_id;
        goto_->op.goto_->ret_ctrl_eff = 3;

        // branch
        branch->op.branch->true_eff = -1; // do nothing
        branch->op.branch->false_eff = 3; // goto [
        branch->op.branch->condition = 2; // (inv (load mem (var ptr)))
        branch->op.branch->ret = 4;

        // perform
        perform->op.perform->eff = 4;
        perform->op.perform->ret = -1;

        RzPVector *oplist = rz_il_make_oplist_with_id(id, 6, var, load, inv, goto_, branch, perform);
        return oplist;
}

static int bf_vm_init(RzAnalysisRzil *rzil) {
	RzILVM vm = rzil->vm;

	// load reg
	// TODO use info of reg profile
        rz_il_vm_add_reg(vm, "ptr", BF_ADDR_SIZE);

        BfStack astack = (BfStack)calloc(1, sizeof(struct bf_stack_t));
	rzil->user = astack;

        EffectLabel read_label = rz_il_vm_create_label_lazy(vm, "read");
        EffectLabel write_label = rz_il_vm_create_label_lazy(vm, "write");
        read_label->addr = (void *)bf_syscall_read;
        write_label->addr = (void *)bf_syscall_write;
        read_label->type = EFFECT_LABEL_SYSCALL;
        write_label->type = EFFECT_LABEL_HOOK;

	return 0;
}

static int bf_vm_fini(RzAnalysisRzil *rzil) {
	if (rzil->user) {
		free(rzil->user);
	}
	return 0;
}

static void bf_init_rzil(RzAnalysis *analysis, ut64 addr) {
        int addrsize = 64;
        int datasize = 8;
        ut64 start_addr = addr;

        int romem = true;
        int stats = true;
        int nonull = true;

        RzAnalysisRzil *rzil;
        if (!(rzil = rz_analysis_rzil_new())) {
                return;
        }
        // init
        rz_il_vm_init(rzil->vm, start_addr, addrsize, datasize);
        rz_il_vm_add_reg(rzil->vm, "ptr", rzil->vm->addr_size);
        rz_analysis_rzil_setup(rzil, analysis, romem, stats, nonull);
	analysis->rzil = rzil;
}

#define BUFSIZE_INC 32
static int bf_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	ut64 dst = 0LL;
	if (!op) {
		return 1;
	}

	if (!analysis->rzil) {
		bf_init_rzil(analysis, addr);
	}

	/* Ayeeee! What's inside op? Do we have an initialized RzAnalysisOp? Are we going to have a leak here? :-( */
	memset(op, 0, sizeof(RzAnalysisOp)); /* We need to refactorize this. Something like rz_analysis_op_init would be more appropriate */
	rz_strbuf_init(&op->esil);
	op->size = 1;
	op->id = getid(buf[0]);
	op->addr = addr;

        BfStack stack_helper = analysis->rzil->user;
	RzILVM vm = analysis->rzil->vm;
	RzAnalysisRzil *rzil = analysis->rzil;
	RzPVector *oplist;

	switch (buf[0]) {
	case '[':
		oplist = bf_llimit(vm, stack_helper, op->id, addr);

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
						rz_strbuf_setf(&op->esil,
							"$$,brk,=[1],brk,++=,"
							"ptr,[1],!,?{,0x%" PFMT64x ",pc,=,brk,--=,}",
							dst);
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
		oplist = bf_rlimit(vm, stack_helper, op->id, addr);
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		// XXX This is wrong esil
		rz_strbuf_set(&op->esil, "brk,--=,brk,[1],pc,=");
		break;
	case '>':
                // FIXME : The original esil read multiple op at one
                //      : by using countChar, and change op->size
		//      : should we keep this hack ?
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		// op->size = countChar(buf, len, '>');
		rz_strbuf_setf(&op->esil, "%d,ptr,+=", op->size);
		oplist = bf_right_arrow(vm, op->id);
		break;
	case '<':
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		// op->size = countChar(buf, len, '<');
		rz_strbuf_setf(&op->esil, "%d,ptr,-=", op->size);
		oplist = bf_left_arrow(vm, op->id);
		break;
	case '+':
		// op->size = countChar(buf, len, '+');
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		rz_strbuf_setf(&op->esil, "%d,ptr,+=[1]", op->size);
		oplist = bf_inc(vm, op->id);
		break;
	case '-':
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		// op->size = countChar(buf, len, '-');
		rz_strbuf_setf(&op->esil, "%d,ptr,-=[1]", op->size);
		oplist = bf_dec(vm, op->id);
		break;
	case '.':
		oplist = bf_out(vm, op->id);

		// print element in stack to screen
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		rz_strbuf_set(&op->esil, "ptr,[1],scr,=[1],scr,++=");
		break;
	case ',':
		oplist = bf_in(vm, op->id);
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		rz_strbuf_set(&op->esil, "kbd,[1],ptr,=[1],kbd,++=");
		break;
	case 0x00:
	case 0xff:
		oplist = NULL;
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	default:
		oplist = NULL;
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		rz_strbuf_set(&op->esil, ",");
		break;
	}
	if (oplist) {
                rz_analysis_set_rzil_op(analysis->rzil, addr, oplist);
        }
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
	.esil = true,
	.op = &bf_op,
	.get_reg_profile = get_reg_profile,
	.rzil_init = bf_vm_init,
	.rzil_fini = bf_vm_fini
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_bf,
	.version = RZ_VERSION
};
#endif
