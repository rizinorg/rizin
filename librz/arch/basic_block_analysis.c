// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_regex.h>
#include <rz_analysis.h>
#include <rz_parse.h>
#include <rz_util.h>
#include <rz_list.h>
#include <basic_block_analysis.h>

// XXX must be configurable by the user
#define JMPTBL_LEA_SEARCH_SZ 64

const char *retpoline_reg(RzAnalysis *analysis, ut64 addr) {
	RzFlagItem *flag = analysis->flag_get(analysis->flb.f, addr);
	if (flag) {
		const char *token = "x86_indirect_thunk_";
		const char *thunk = strstr(flag->name, token);
		if (thunk) {
			return thunk + strlen(token);
		}
	}
	// TODO: implement following code analysis check for stripped binaries:
	// 1) op(addr).type == CALL
	// 2) call_dest = op(addr).addr
	// 3) op(call_dest).type == STORE
	// 4) op(call_dest + op(call_dest).size).type == RET
	// [0x00000a65]> pid 6
	// 0x00000a65  sym.__x86_indirect_thunk_rax:
	// 0x00000a65  .------- e807000000  call 0xa71
	// 0x00000a6a  |              f390  pause
	// 0x00000a6c  |            0faee8  lfence
	// 0x00000a6f  |              ebf9  jmp 0xa6a
	// 0x00000a71  `---->     48890424  mov qword [rsp], rax
	// 0x00000a75                   c3  ret
	return NULL;
}

bool isSymbolNextInstruction(RzAnalysis *analysis, RzAnalysisOp *op) {
	rz_return_val_if_fail(analysis && op && analysis->flb.get_at, false);

	RzFlagItem *fi = analysis->flb.get_at(analysis->flb.f, op->addr + op->size, false);
	return (fi && fi->name && (strstr(fi->name, "imp.") || strstr(fi->name, "sym.") || strstr(fi->name, "entry") || strstr(fi->name, "main")));
}

ut64 try_get_cmpval_from_parents(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *my_bb, const char *cmp_reg) {
	rz_return_val_if_fail(fcn && fcn->bbs && cmp_reg, UT64_MAX);

	RzAnalysisBlock *tmp_bb;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		tmp_bb = (RzAnalysisBlock *)*it;
		if (tmp_bb->jump != my_bb->addr && tmp_bb->fail != my_bb->addr) {
			continue;
		}
		if (tmp_bb->cmpreg != cmp_reg) {
			continue;
		}
		if (tmp_bb->cond &&
			(tmp_bb->cond->type == RZ_TYPE_COND_HI ||
				tmp_bb->cond->type == RZ_TYPE_COND_GT)) {
			return tmp_bb->cmpval + 1;
		}
		return tmp_bb->cmpval;
	}
	return UT64_MAX;
}

bool is_unknown_call_from_plt(RzAnalysis *analysis, ut64 op_address) {
	RzBinSection *s = analysis->binb.get_vsect_at(analysis->binb.bin, op_address);
	if (!s) {
		return false;
	}
	return RZ_STR_EQ(s->name, ".MIPS.stubs") ||
		RZ_STR_EQ(s->name, ".plt.got") ||
		RZ_STR_EQ(s->name, ".plt.sec") ||
		RZ_STR_EQ(s->name, ".plt");
}

bool is_delta_pointer_table(ReadAhead *ra, RzAnalysis *analysis, ut64 addr, ut64 lea_ptr, ut64 *jmptbl_addr, ut64 *casetbl_addr, RzAnalysisOp *jmp_aop) {
	int i;
	ut64 dst;
	st32 jmptbl[64] = { 0 };
	/* check if current instruction is followed by an ujmp */
	ut8 buf[JMPTBL_LEA_SEARCH_SZ];
	RzAnalysisOp *aop = jmp_aop;
	RzAnalysisOp omov_aop = { 0 };
	RzAnalysisOp mov_aop = { 0 };
	RzAnalysisOp add_aop = { 0 };
	RzRegItem *reg_src = NULL, *o_reg_dst = NULL;
	RzAnalysisValue cur_scr, cur_dst = { 0 };
	read_ahead(ra, analysis, addr, buf, sizeof(buf));
	bool isValid = false;
	for (i = 0; i + 8 < JMPTBL_LEA_SEARCH_SZ; i++) {
		ut64 at = addr + i;
		int left = JMPTBL_LEA_SEARCH_SZ - i;
		rz_analysis_op_init(aop);
		int len = rz_analysis_op(analysis, aop, at, buf + i, left, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT | RZ_ANALYSIS_OP_MASK_VAL);
		if (len < 1) {
			len = 1;
		}
		if (aop->type == RZ_ANALYSIS_OP_TYPE_UJMP || aop->type == RZ_ANALYSIS_OP_TYPE_RJMP) {
			isValid = true;
			break;
		} else if (aop->type == RZ_ANALYSIS_OP_TYPE_JMP || aop->type == RZ_ANALYSIS_OP_TYPE_CJMP) {
			break;
		}
		if (aop->type == RZ_ANALYSIS_OP_TYPE_MOV) {
			omov_aop = mov_aop;
			mov_aop = *aop;
			o_reg_dst = cur_dst.reg;
			if (mov_aop.dst) {
				cur_dst = *mov_aop.dst;
			}
			if (mov_aop.src[0]) {
				cur_scr = *mov_aop.src[0];
				reg_src = cur_scr.regdelta;
			}
		}
		if (aop->type == RZ_ANALYSIS_OP_TYPE_ADD) {
			add_aop = *aop;
		}
		rz_analysis_op_fini(aop);
		i += len - 1;
	}
	if (!isValid) {
		return false;
	}

	// check if we have a msvc 19xx style jump table using rva table entries
	// lea reg1, [base_addr]
	// mov reg2, dword [reg1 + tbl_off*4 + tbl_loc_off]
	// add reg2, reg1
	// jmp reg2
	if (mov_aop.type && add_aop.type && mov_aop.addr < add_aop.addr && add_aop.addr < jmp_aop->addr && mov_aop.disp && mov_aop.disp != UT64_MAX) {
		// disp in this case should be tbl_loc_off
		*jmptbl_addr += mov_aop.disp;
		if (o_reg_dst && reg_src && o_reg_dst->offset == reg_src->offset && omov_aop.disp != UT64_MAX) {
			// Special case for indirection
			// lea reg1, [base_addr]
			// movzx reg2, byte [reg1 + tbl_off + casetbl_loc_off]
			// mov reg3, dword [reg1 + reg2*4 + tbl_loc_off]
			// add reg3, reg1
			// jmp reg3
			*casetbl_addr += omov_aop.disp;
		}
	}

	/* check if jump table contains valid deltas */
	read_ahead(ra, analysis, *jmptbl_addr, (ut8 *)&jmptbl, 64);
	for (i = 0; i < 3; i++) {
		dst = lea_ptr + (st32)rz_read_le32(jmptbl);
		if (!analysis->iob.is_valid_offset(analysis->iob.io, dst, 0)) {
			RZ_LOG_VERBOSE("Jump table target is not valid: 0x%" PFMT64x "\n", dst);
			return false;
		}
		if (!UT64_ADD_OVFCHK(jmp_aop->addr, analysis->opt.jmptbl_maxoffset) &&
			dst > jmp_aop->addr + analysis->opt.jmptbl_maxoffset) {
			RZ_LOG_VERBOSE("Jump table target is too far away: 0x%" PFMT64x "\n", dst);
			return false;
		}
		if (analysis->opt.jmpabove && !UT64_SUB_OVFCHK(jmp_aop->addr, analysis->opt.jmptbl_maxoffset) &&
			dst < jmp_aop->addr - analysis->opt.jmptbl_maxoffset) {
			RZ_LOG_VERBOSE("Jump table target is too far away: 0x%" PFMT64x "\n", dst);
			return false;
		}
	}
	return true;
}

bool regs_exist(RzAnalysisValue *src, RzAnalysisValue *dst) {
	rz_return_val_if_fail(src && dst, false);
	return src->reg && dst->reg && src->reg->name && dst->reg->name;
}

void analyze_retpoline(RzAnalysis *analysis, RzAnalysisOp *op) {
	if (analysis->opt.retpoline) {
		const char *rr = retpoline_reg(analysis, op->jump);
		if (rr) {
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
			op->reg = rr;
		}
	}
}

int analyze_function_locally(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 address) {
	rz_return_val_if_fail(analysis && fcn, RZ_ANALYSIS_RET_ERROR);
	RzVector tasks;
	rz_vector_init(&tasks, sizeof(RzAnalysisTaskItem), NULL, NULL);
	RzAnalysisTaskItem item = { fcn, NULL, fcn->stack, address };
	rz_vector_push(&tasks, &item);
	int saved_stack = fcn->stack; // TODO: DO NOT use fcn->stack to keep track of stack during analysis
	int ret = rz_analysis_run_tasks(&tasks);
	rz_vector_fini(&tasks);
	fcn->stack = saved_stack;
	return ret;
}

// Create a new 0-sized basic block inside the function
RzAnalysisBlock *fcn_append_basic_block(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr) {
	RzAnalysisBlock *bb = rz_analysis_create_block(analysis, addr, 0);
	if (!bb) {
		return NULL;
	}
	rz_analysis_function_add_block(fcn, bb);
	return bb;
}

bool fcn_takeover_block_recursive_followthrough_cb(RzAnalysisBlock *block, void *user) {
	BlockTakeoverCtx *ctx = user;
	RzAnalysisFunction *our_fcn = ctx->fcn;
	rz_analysis_block_ref(block);
	while (!rz_list_empty(block->fcns)) {
		RzAnalysisFunction *other_fcn = rz_list_first_val(block->fcns);
		if (other_fcn->addr == block->addr) {
			return false;
		}
		// Steal vars from this block
		size_t i;
		for (i = 0; i < block->ninstr; i++) {
			const ut64 addr = rz_analysis_block_get_op_addr(block, i);
			RzPVector *vars_used = rz_analysis_function_get_vars_used_at(other_fcn, addr);
			if (!vars_used) {
				continue;
			}
			// vars_used will get modified if rz_analysis_var_remove_access_at gets called
			RzPVector *cloned_vars_used = rz_pvector_clone(vars_used);
			void **it;
			rz_pvector_foreach (cloned_vars_used, it) {
				RzAnalysisVar *other_var = *it;
				RzAnalysisVarStorage stor = other_var->storage;
				if (stor.type == RZ_ANALYSIS_VAR_STORAGE_STACK && other_fcn->bp_frame && our_fcn->bp_frame) {
					// re-adjust offsets if needed
					stor.stack_off += other_fcn->bp_off - our_fcn->bp_off;
				}
				RzAnalysisVar *our_var = rz_analysis_function_get_var_at(our_fcn, &stor);
				if (!our_var) {
					our_var = rz_analysis_function_set_var(our_fcn, &stor, other_var->type, 0, other_var->name);
				}
				if (our_var) {
					RzAnalysisVarAccess *acc = rz_analysis_var_get_access_at(other_var, addr);
					rz_analysis_var_set_access(our_var, acc->reg, addr, acc->type, acc->reg_addend);
				}
				rz_analysis_var_remove_access_at(other_var, addr);
				if (rz_vector_empty(&other_var->accesses)) {
					rz_analysis_function_delete_var(other_fcn, other_var);
				}
			}
			rz_pvector_free(cloned_vars_used);
		}

		// TODO: remove block->ninstr from other_fcn considering delay slots
		rz_analysis_function_remove_block(other_fcn, block);
	}
	block->sp_entry += ctx->stack_diff;
	rz_analysis_function_add_block(our_fcn, block);
	// TODO: add block->ninstr from our_fcn considering delay slots
	rz_analysis_block_unref(block);
	return true;
}

// Remove block and all of its recursive successors from all its functions and add them only to fcn
void fcn_takeover_block_recursive(RzAnalysisFunction *fcn, RzAnalysisBlock *start_block, RzStackAddr sp) {
	BlockTakeoverCtx ctx = { fcn, sp - start_block->sp_entry };
	rz_analysis_block_recurse_followthrough(start_block, fcn_takeover_block_recursive_followthrough_cb, &ctx);
}

int skip_hp(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisOp *op, RzAnalysisBlock *bb, ut64 addr,
	char *tmp_buf, int oplen, int un_idx, int *idx) {
	// this step is required in order to prevent infinite recursion in some cases
	if ((addr + un_idx - oplen) == fcn->addr) {
		// use addr instead of op->addr to mark repeat
		if (!analysis->flb.exist_at(analysis->flb.f, "skip", 4, addr)) {
			snprintf(tmp_buf + 5, MAX_FLG_NAME_SIZE - 6, "%" PFMT64u, addr);
			analysis->flb.set(analysis->flb.f, tmp_buf, addr, oplen);
			fcn->addr += oplen;
			rz_analysis_block_relocate(bb, bb->addr + oplen, bb->size - oplen);
			*idx = un_idx;
			return 1;
		}
		return 2;
	}
	return 0;
}

bool isInvalidMemory(RzAnalysis *analysis, const ut8 *buf, int len) {
	if (analysis->opt.nonull > 0) {
		int i;
		const int count = RZ_MIN(len, analysis->opt.nonull);
		for (i = 0; i < count; i++) {
			if (buf[i]) {
				break;
			}
		}
		if (i == count) {
			return true;
		}
	}
	return !memcmp(buf, "\xff\xff\xff\xff", RZ_MIN(len, 4));
}

// TODO: move into io :?
int read_ahead(ReadAhead *ra, RzAnalysis *analysis, ut64 addr, ut8 *buf, ssize_t len) {
	bool is_cached = false;
	if (len < 1) {
		return -1;
	}

	if (ra->cache_addr != UT64_MAX && addr >= ra->cache_addr && addr < ra->cache_addr + sizeof(ra->cache)) {
		ut64 addr_end = UT64_ADD_OVFCHK(addr, len) ? UT64_MAX : addr + len;
		ut64 cache_addr_end = UT64_ADD_OVFCHK(ra->cache_addr, sizeof(ra->cache)) ? UT64_MAX : ra->cache_addr + sizeof(ra->cache);
		is_cached = ((addr != UT64_MAX) && (addr >= ra->cache_addr) && (addr_end < cache_addr_end));
	}

	if (!is_cached) {
		if (len > sizeof(ra->cache)) {
			len = sizeof(ra->cache);
		}
		analysis->iob.read_at(analysis->iob.io, addr, ra->cache, sizeof(ra->cache));
		ra->cache_addr = addr;
	}
	ssize_t delta = addr - ra->cache_addr;
	if (delta >= 0) {
		size_t length = sizeof(ra->cache) - delta;
		memcpy(buf, ra->cache + delta, RZ_MIN(len, length));
		return len;
	}
	return -1;
}

void free_leaddr_pair(void *pair) {
	leaddr_pair *_pair = pair;
	free(_pair->reg);
	free(_pair);
}

RzAnalysisBlock *bbget(RzAnalysis *analysis, ut64 addr, bool jumpmid) {
	RzList *intersecting = rz_analysis_get_blocks_in(analysis, addr);
	RzListIter *iter;
	RzAnalysisBlock *bb;

	RzAnalysisBlock *ret = NULL;
	rz_list_foreach (intersecting, iter, bb) {
		ut64 eaddr = bb->addr + bb->size;
		if (((bb->addr >= eaddr && addr == bb->addr) ||
			    rz_analysis_block_contains(bb, addr)) &&
			(!jumpmid || rz_analysis_block_op_starts_at(bb, addr))) {
			if (analysis->opt.delay) {
				ut8 *buf = malloc(bb->size);
				if (analysis->iob.read_at(analysis->iob.io, bb->addr, buf, bb->size)) {
					const int last_instr_idx = bb->ninstr - 1;
					bool in_delay_slot = false;
					RzAnalysisOp op = { 0 };
					for (int i = last_instr_idx; i >= 0; i--) {
						const ut64 off = rz_analysis_block_get_op_offset(bb, i);
						const ut64 at = bb->addr + off;
						if (addr <= at || off >= bb->size) {
							continue;
						}
						rz_analysis_op_init(&op);
						int size = rz_analysis_op(analysis, &op, at, buf + off, bb->size - off, RZ_ANALYSIS_OP_MASK_BASIC);
						if (size > 0 && op.delay) {
							if (op.delay >= last_instr_idx - i) {
								in_delay_slot = true;
							}
							rz_analysis_op_fini(&op);
							break;
						}
						rz_analysis_op_fini(&op);
					}
					if (in_delay_slot) {
						free(buf);
						continue;
					}
				}
				free(buf);
			}
			ret = bb;
			break;
		}
	}
	rz_list_free(intersecting);
	return ret;
}

bool init_basic_block(BasicBlockAnalysisCtx *ctx, RzAnalysisTaskItem *item, RzVector /*RzAnalysisTaskItem*/ *tasks) {
	rz_return_val_if_fail(item && tasks, RZ_ANALYSIS_RET_ERROR);

	// fill context fields from item
	ctx->analysis = item->fcn->analysis;
	ctx->fcn = item->fcn;
	ctx->sp = item->sp;
	ctx->addr = item->start_address;
	ctx->len = RZ_MIN(ctx->analysis->opt.bb_max_size, RZ_ANALYSIS_BLOCK_MAX_SIZE);

	memset(&ctx->read_ahead_cache, 0, sizeof(ctx->read_ahead_cache));

	ctx->continue_after_jump = ctx->analysis->opt.afterjmp;
	ctx->addrbytes = ctx->analysis->iob.io ? ctx->analysis->iob.io->addrbytes : 1; // warning C4267: '=': conversion from 'size_t' to 'int', possible loss of data
	ctx->last_reg_mov_lea_name = NULL;
	ctx->movbasereg = NULL;
	ctx->bb = item->block;
	ctx->bbg = NULL;
	ctx->ret = RZ_ANALYSIS_RET_END, ctx->skip_ret = 0;
	ctx->overlapped = false;

	memset(&ctx->op, 0, sizeof(ctx->op));
	ctx->oplen = 0, ctx->idx = 0;
	ctx->varset = false;
	memset(&ctx->op, 0, sizeof(ctx->op));

	ctx->read_ahead_cache.cache_addr = UT64_MAX; // invalidate the cache
	strcpy(ctx->tmp_buf, "skip");
	ctx->arch_destroys_dst = does_arch_destroys_dst(ctx->analysis->cur->arch);
	if (ctx->analysis->cur->arch) {
		ctx->selected_architecture.is_arm = !strncmp(ctx->analysis->cur->arch, "arm", 3);
		ctx->selected_architecture.is_x86 = !strncmp(ctx->analysis->cur->arch, "x86", 3);
		ctx->selected_architecture.is_dalvik = !strncmp(ctx->analysis->cur->arch, "dalvik", 6);
		ctx->selected_architecture.is_hexagon = !strncmp(ctx->analysis->cur->arch, "hexagon", 7);
	}
	ctx->selected_architecture.is_amd64 = ctx->selected_architecture.is_x86 ? ctx->fcn->cc && !strcmp(ctx->fcn->cc, "amd64") : false;
	ctx->can_jmpmid = ctx->analysis->opt.jmpmid && (ctx->selected_architecture.is_dalvik || ctx->selected_architecture.is_x86);

	ctx->variadic_reg = NULL;
	if (ctx->selected_architecture.is_amd64) {
		ctx->variadic_reg = rz_reg_get(ctx->analysis->reg, "rax", RZ_REG_TYPE_GPR);
	}
	ctx->has_variadic_reg = !!ctx->variadic_reg;

	if (rz_cons_is_breaked()) {
		rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, ctx->bb, ctx->addr, ctx->sp);
		ctx->ret = RZ_ANALYSIS_RET_END;
		return false;
	}
	if (ctx->analysis->sleep) {
		rz_sys_usleep(ctx->analysis->sleep);
	}

	// check if address is readable
	if (!ctx->analysis->iob.is_valid_offset(ctx->analysis->iob.io, ctx->addr, 0)) {
		if (ctx->addr != UT64_MAX && !ctx->analysis->iob.io->va) {
			RZ_LOG_DEBUG("Invalid address 0x%" PFMT64x ". Try with io.va=true\n", ctx->addr);
		}
		ctx->ret = RZ_ANALYSIS_RET_ERROR; // MUST BE TOO DEEP
		return false;
	}

	RzAnalysisFunction *fcn_at_addr = rz_analysis_get_function_at(ctx->analysis, ctx->addr);
	if (fcn_at_addr && fcn_at_addr != ctx->fcn) {
		ctx->ret = RZ_ANALYSIS_RET_ERROR; // MUST BE NOT FOUND
		return false;
	}

	if (!ctx->bb) {
		RzAnalysisBlock *existing_bb = bbget(ctx->analysis, ctx->addr, ctx->can_jmpmid);
		if (existing_bb) {
			bool existing_in_fcn = rz_list_contains(existing_bb->fcns, ctx->fcn);
			existing_bb = rz_analysis_block_split(existing_bb, ctx->addr);
			if (!existing_in_fcn && existing_bb) {
				if (existing_bb->addr == ctx->fcn->addr) {
					// our function starts directly there, so we steal what is ours!
					fcn_takeover_block_recursive(ctx->fcn, existing_bb, ctx->sp);
				}
			}
			if (existing_bb) {
				rz_analysis_block_unref(existing_bb);
			}
			if (ctx->analysis->opt.recont) {
				ctx->ret = RZ_ANALYSIS_RET_END;
				return false;
			}
			RZ_LOG_DEBUG("%s fails at 0x%" PFMT64x ".\n", __FUNCTION__, ctx->addr);
			ctx->ret = RZ_ANALYSIS_RET_ERROR; // MUST BE NOT DUP
			return false;
		}

		item->block = ctx->bb = fcn_append_basic_block(ctx->analysis, ctx->fcn, ctx->addr);
		// we checked before whether there is a bb at addr, so the create should have succeeded
		rz_return_val_if_fail(ctx->bb, RZ_ANALYSIS_RET_ERROR);
	}
	// We are currently at the entrypoint of the basic block, so we may initialize
	// its entry sp value to our current tracked sp.
	ctx->bb->sp_entry = ctx->sp;

	if (!ctx->analysis->leaddrs) {
		ctx->analysis->leaddrs = rz_list_newf(free_leaddr_pair);
		if (!ctx->analysis->leaddrs) {
			RZ_LOG_ERROR("Cannot allocate list of pairs<reg, addr> values.\n");
			ctx->ret = RZ_ANALYSIS_RET_ERROR;
			return false;
		}
	}
	ctx->last_reg_mov_lea_val = UT64_MAX;
	ctx->last_is_reg_mov_lea = false;
	ctx->last_is_push = false;
	ctx->last_is_mov_lr_pc = false;
	ctx->last_is_add_lr_pc = false;
	ctx->last_push_addr = UT64_MAX;
	if (ctx->analysis->limit && ctx->addr + ctx->idx < ctx->analysis->limit->from) {
		ctx->ret = RZ_ANALYSIS_RET_END;
		return false;
	}
	RzAnalysisFunction *tmp_fcn = rz_analysis_get_fcn_in(ctx->analysis, ctx->addr, 0);
	if (tmp_fcn) {
		// Checks if var is already analyzed at given addr
		if (!rz_pvector_empty(&tmp_fcn->vars)) {
			ctx->varset = true;
		}
	}
	ctx->movdisp = UT64_MAX; // used by jmptbl when coded as "mov reg, [reg * scale + disp]"
	ctx->movscale = 0;
	// ut8 buf[32]; // 32 bytes is enough to hold any instruction.
	ctx->maxlen = ctx->len * ctx->addrbytes;

	// Dalvik import skipping
	if (ctx->selected_architecture.is_dalvik) {
		bool skipAnalysis = false;
		if (!strncmp(ctx->fcn->name, "sym.", 4)) {
			if (!strncmp(ctx->fcn->name + 4, "imp.", 4)) {
				skipAnalysis = true;
			} else if (strstr(ctx->fcn->name, "field")) {
				skipAnalysis = true;
			}
		}
		if (skipAnalysis) {
			ctx->ret = RZ_ANALYSIS_RET_END;
			return false;
		}
	}

	if ((ctx->maxlen - (ctx->addrbytes * ctx->idx)) > MAX_SCAN_SIZE) {
		// XXX idx is always 0 here, and maxlen comes from amalysis.bb.maxsize. This makes no sense.
		RZ_LOG_DEBUG("Skipping large memory region during basic block analysis.\n");
		ctx->maxlen = 0;
	}

	return true;
}

RzAnalysisBBEndCause analysis_basic_block(BasicBlockAnalysisCtx *ctx, RzAnalysisTaskItem *item, RzVector /*RzAnalysisTaskItem*/ *tasks) {
	while (true) {
		ut32 at_delta;
		ut64 at;
		if (!ctx->last_is_reg_mov_lea) {
			free(ctx->last_reg_mov_lea_name);
			ctx->last_reg_mov_lea_name = NULL;
		}
		if (ctx->analysis->limit && ctx->analysis->limit->to <= ctx->addr + ctx->idx) {
			break;
		}
	repeat:
		at_delta = ctx->addrbytes * ctx->idx;
		at = ctx->addr + at_delta;
		if (rz_cons_is_breaked()) {
			rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, ctx->bb, at, ctx->sp);
			break;
		}
		ut64 bytes_read = sizeof(ctx->buf);
		ctx->ret = read_ahead(&ctx->read_ahead_cache, ctx->analysis, at, ctx->buf, bytes_read);

		if (ctx->ret < 0) {
			RZ_LOG_ERROR("Failed to read ahead\n");
			break;
		}
		if (isInvalidMemory(ctx->analysis, ctx->buf, bytes_read)) {
			RZ_LOG_DEBUG("FFFF opcode at 0x%08" PFMT64x "\n", at);
			ctx->ret = RZ_ANALYSIS_RET_ERROR;
			return ctx->ret;
		}
		rz_analysis_op_fini(&ctx->op);
		rz_analysis_op_init(&ctx->op);
		if ((ctx->oplen = rz_analysis_op(ctx->analysis, &ctx->op, at, ctx->buf, bytes_read, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_HINT)) < 1) {
			RZ_LOG_DEBUG("Invalid instruction at 0x%" PFMT64x " with %d bits\n", at, ctx->analysis->bits);
			// cleanup_basic_block (RZ_ANALYSIS_RET_ERROR);
			// RET_END causes infinite loops somehow
			ctx->ret = RZ_ANALYSIS_RET_END; // ???
			return ctx->ret;
		}

		const char *bp_reg = ctx->analysis->reg->name[RZ_REG_NAME_BP];
		const char *sp_reg = ctx->analysis->reg->name[RZ_REG_NAME_SP];
		bool has_stack_regs = bp_reg && sp_reg;

		if (ctx->analysis->opt.nopskip && ctx->fcn->addr == at) {
			RzFlagItem *fi = ctx->analysis->flb.get_at(ctx->analysis->flb.f, ctx->addr, false);
			if (!fi || strncmp(fi->name, "sym.", 4)) {
				if ((ctx->addr + ctx->delay.un_idx - ctx->oplen) == ctx->fcn->addr) {
					if (rz_analysis_block_relocate(ctx->bb, ctx->bb->addr + ctx->oplen, ctx->bb->size - ctx->oplen)) {
						ctx->fcn->addr += ctx->oplen;
						ctx->idx = ctx->delay.un_idx;
						goto repeat;
					}
				}
			}
			switch (ctx->op.type & RZ_ANALYSIS_OP_TYPE_MASK) {
			case RZ_ANALYSIS_OP_TYPE_TRAP:
			case RZ_ANALYSIS_OP_TYPE_ILL:
			case RZ_ANALYSIS_OP_TYPE_NOP:
				if (rz_analysis_block_relocate(ctx->bb, at + ctx->op.size, ctx->bb->size)) {
					ctx->addr = at + ctx->op.size;
					ctx->fcn->addr = ctx->addr;
					goto repeat;
				}
			}
		}

		if (ctx->op.hint.new_bits) {
			rz_analysis_hint_set_bits(ctx->analysis, ctx->op.jump, ctx->op.hint.new_bits);
		}
		if (ctx->idx > 0 && !ctx->overlapped) {
			ctx->bbg = bbget(ctx->analysis, at, ctx->can_jmpmid);
			if (ctx->bbg && ctx->bbg != ctx->bb) {
				ctx->bb->jump = at;
				if (ctx->can_jmpmid) {
					// This happens when we purposefully walked over another block and overlapped it
					// and now we hit an offset where the instructions match again.
					// So we need to split the overwalked block.
					RzAnalysisBlock *split = rz_analysis_block_split(ctx->bbg, at);
					rz_analysis_block_unref(split);
				}
				ctx->overlapped = true;
				RZ_LOG_DEBUG("Overlapped at 0x%08" PFMT64x "\n", at);
			}
		}
		if (!ctx->overlapped) {
			ut64 newbbsize = ctx->bb->size + ctx->oplen;
			if (ctx->fcn->ninstr >= ctx->analysis->opt.fcn_max_size) {
				ctx->ret = RZ_ANALYSIS_RET_ERROR;
				return ctx->ret;
			}
			if (newbbsize >= ctx->len) {
				// Instruction offsets are stored in u16,
				// artificially introduce bb split to keep the offsets within limits.
				RzAnalysisBlock *next = fcn_append_basic_block(ctx->analysis, ctx->fcn, at);
				if (!next) {
					ctx->ret = RZ_ANALYSIS_RET_ERROR;
					return ctx->ret;
				}
				// If previous instruction was a jump there would already be a split.
				// So setting jump here shouldn't overwrite any real jumps.
				ctx->bb->jump = at;
				item->block = ctx->bb = next;
				next->sp_entry = ctx->sp;
				newbbsize = ctx->bb->size + ctx->oplen;
			}
			ctx->bb->ninstr++;
			rz_analysis_block_set_op_offset(ctx->bb, ctx->bb->ninstr - 1, at - ctx->bb->addr);
			rz_analysis_block_set_size(ctx->bb, newbbsize);
			ctx->fcn->ninstr++;
		}
		if (ctx->analysis->opt.trycatch) {
			const char *name = ctx->analysis->coreb.getName(ctx->analysis->coreb.core, at);
			if (name) {
				if (rz_str_startswith(name, "try.") && rz_str_endswith(name, ".from")) {
					char *handle = rz_str_dup(name);
					// handle = rz_str_replace (handle, ".from", ".to", 0);
					ut64 from_addr = ctx->analysis->coreb.numGet(ctx->analysis->coreb.core, handle);
					handle = rz_str_replace(handle, ".from", ".catch", 0);
					ut64 handle_addr = ctx->analysis->coreb.numGet(ctx->analysis->coreb.core, handle);
					handle = rz_str_replace(handle, ".catch", ".filter", 0);
					ut64 filter_addr = ctx->analysis->coreb.numGet(ctx->analysis->coreb.core, handle);
					if (filter_addr) {
						rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, filter_addr, RZ_ANALYSIS_XREF_TYPE_CALL);
					}
					ctx->bb->jump = at + ctx->oplen;
					if (from_addr != ctx->bb->addr) {
						ctx->bb->fail = handle_addr;
						ctx->ret = analyze_function_locally(ctx->analysis, ctx->fcn, handle_addr);
						if (ctx->bb->size == 0) {
							rz_analysis_function_remove_block(ctx->fcn, ctx->bb);
						}
						rz_analysis_block_update_hash(ctx->bb);
						rz_analysis_block_unref(ctx->bb);
						ctx->bb = fcn_append_basic_block(ctx->analysis, ctx->fcn, ctx->bb->jump);
						if (!ctx->bb) {
							ctx->ret = RZ_ANALYSIS_RET_ERROR;
							return ctx->ret;
						}
					}
				}
			}
		}
		ctx->idx += ctx->oplen;
		ctx->delay.un_idx = ctx->idx;
		if (ctx->analysis->opt.delay && ctx->op.delay > 0 && !ctx->delay.pending) {
			// Handle first pass through a branch delay jump:
			// Come back and handle the current instruction later.
			// Save the location of it in `delay.idx`
			// note, we have still increased size of basic block
			// (and function)
			RZ_LOG_DEBUG("Enter branch delay at 0x%08" PFMT64x ". bb->sz=%" PFMT64u "\n", at - ctx->oplen, ctx->bb->size);
			ctx->delay.idx = ctx->idx - ctx->oplen;
			ctx->delay.cnt = ctx->op.delay;
			ctx->delay.pending = 1; // we need this in case the actual idx is zero...
			ctx->delay.adjust = !ctx->overlapped; // adjustment is required later to avoid double count
			continue;
		}

		if (ctx->delay.cnt > 0) {
			// if we had passed a branch delay instruction, keep
			// track of how many still to process.
			ctx->delay.cnt--;
			if (!ctx->delay.cnt) {
				RZ_LOG_DEBUG("Last branch delayed opcode at 0x%08" PFMT64x ". bb->sz=%" PFMT64u "\n", ctx->addr + ctx->idx - ctx->oplen, ctx->bb->size);
				ctx->delay.after = ctx->idx;
				ctx->idx = ctx->delay.idx;
				// At this point, we are still looking at the
				// last instruction in the branch delay group.
				// Next time, we will again be looking
				// at the original instruction that entered
				// the branch delay.
			}
		} else if (ctx->op.delay > 0 && ctx->delay.pending) {
			RZ_LOG_DEBUG("Revisit branch delay jump at 0x%08" PFMT64x ". bb->sz=%" PFMT64u "\n", ctx->addr + ctx->idx - ctx->oplen, ctx->bb->size);
			// This is the second pass of the branch delaying opcode
			// But we also already counted this instruction in the
			// size of the current basic block, so we need to fix that
			if (ctx->delay.adjust) {
				rz_analysis_block_set_size(ctx->bb, (ut64)ctx->addrbytes * (ut64)ctx->delay.after);
				ctx->fcn->ninstr--;
				RZ_LOG_DEBUG("Correct for branch delay @ 0x%08" PFMT64x " bb.addr=0x%08" PFMT64x " corrected.bb=%" PFMT64u " f.uncorr=%" PFMT64u "\n",
					ctx->addr + ctx->idx - ctx->oplen, ctx->bb->addr, ctx->bb->size, rz_analysis_function_linear_size(ctx->fcn));
			}
			// Next time, we go to the opcode after the delay count
			// Take care not to use this below, use delay.un_idx instead ...
			ctx->idx = ctx->delay.after;
			ctx->delay.pending = ctx->delay.after = ctx->delay.idx = ctx->delay.adjust = 0;
		}
		// Note: if we got two branch delay instructions in a row due to an
		// compiler bug or junk or something it wont get treated as a delay
		if (ctx->analysis->opt.vars && !ctx->varset) {
			rz_analysis_extract_vars(ctx->analysis, ctx->fcn, &ctx->op, ctx->sp);
		}
		if (has_stack_regs && ctx->arch_destroys_dst) {
			if (op_is_set_bp(&ctx->op, bp_reg, sp_reg) && ctx->op.src[1]) {
				switch (ctx->op.type & RZ_ANALYSIS_OP_TYPE_MASK) {
				case RZ_ANALYSIS_OP_TYPE_ADD:
					ctx->fcn->bp_off = -ctx->sp - ctx->op.src[1]->imm;
					break;
				case RZ_ANALYSIS_OP_TYPE_SUB:
					ctx->fcn->bp_off = -ctx->sp + ctx->op.src[1]->imm;
					break;
				}
			}
		}
		ctx->sp = rz_analysis_op_apply_sp_effect(&ctx->op, ctx->sp);
		ctx->fcn->stack = -ctx->sp;
		if (-ctx->sp > ctx->fcn->maxstack) {
			ctx->fcn->maxstack = -ctx->sp;
		}
		if (!ctx->overlapped) {
			rz_analysis_block_set_op_sp_delta(ctx->bb, ctx->bb->ninstr - 1, ctx->sp - ctx->bb->sp_entry);
		}
		if (ctx->op.ptr && ctx->op.ptr != UT64_MAX && ctx->op.ptr != UT32_MAX) {
			// swapped parameters
			rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->op.ptr, RZ_ANALYSIS_XREF_TYPE_DATA);
		}
		analyze_retpoline(ctx->analysis, &ctx->op);

		switch (ctx->op.type & RZ_ANALYSIS_OP_TYPE_MASK) { // <---
		case RZ_ANALYSIS_OP_TYPE_CMOV:
		case RZ_ANALYSIS_OP_TYPE_MOV:
			ctx->last_is_reg_mov_lea = false;
			if (ctx->selected_architecture.is_arm) { // mov lr, pc
				const char *esil = rz_strbuf_get(&ctx->op.esil);
				if (!rz_str_cmp(esil, "pc,lr,=", -1)) {
					ctx->last_is_mov_lr_pc = true;
				}
			}
			if (has_stack_regs && op_is_set_bp(&ctx->op, bp_reg, sp_reg)) {
				ctx->fcn->bp_off = -ctx->sp;
			}
			// Is this a mov of immediate value into a register?
			if (ctx->op.dst && ctx->op.dst->reg && ctx->op.dst->reg->name && ctx->op.val > 0 && ctx->op.val != UT64_MAX) {
				free(ctx->last_reg_mov_lea_name);
				if ((ctx->last_reg_mov_lea_name = rz_str_dup(ctx->op.dst->reg->name))) {
					ctx->last_reg_mov_lea_val = ctx->op.val;
					ctx->last_is_reg_mov_lea = true;
				}
			}
			// skip mov reg, reg
			if (ctx->analysis->opt.jmptbl && ctx->op.scale && ctx->op.ireg) {
				ctx->movdisp = ctx->op.disp;
				ctx->movscale = ctx->op.scale;
				if (ctx->op.src[0] && ctx->op.src[0]->reg) {
					free(ctx->movbasereg);
					ctx->movbasereg = rz_str_dup(ctx->op.src[0]->reg->name);
				} else {
					RZ_FREE(ctx->movbasereg);
				}
			}
			if (ctx->analysis->opt.hpskip && regs_exist(ctx->op.src[0], ctx->op.dst) && !strcmp(ctx->op.src[0]->reg->name, ctx->op.dst->reg->name)) {
				ctx->skip_ret = skip_hp(ctx->analysis, ctx->fcn, &ctx->op, ctx->bb, ctx->addr, ctx->tmp_buf, ctx->oplen, ctx->delay.un_idx, &ctx->idx);
				if (ctx->skip_ret == 1) {
					goto repeat;
				}
				if (ctx->skip_ret == 2) {
					ctx->ret = RZ_ANALYSIS_RET_END;
					return ctx->ret;
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_LEA:
			ctx->last_is_reg_mov_lea = false;
			// if first byte in op.ptr is 0xff, then set leaddr assuming its a jumptable
			if (ctx->op.ptr != UT64_MAX) {
				leaddr_pair *pair = RZ_NEW(leaddr_pair);
				if (!pair) {
					RZ_LOG_ERROR("Cannot allocate pair<reg, addr> structure\n");
					ctx->ret = RZ_ANALYSIS_RET_ERROR;
					return ctx->ret;
				}
				pair->op_addr = ctx->op.addr;
				pair->leaddr = ctx->op.ptr; // XXX movdisp is dupped but seems to be trashed sometimes(?), better track leaddr separately
				pair->reg = ctx->op.reg
					? rz_str_dup(ctx->op.reg)
					: ctx->op.dst && ctx->op.dst->reg
					? rz_str_dup(ctx->op.dst->reg->name)
					: NULL;
				rz_list_append(ctx->analysis->leaddrs, pair);
			}
			if (has_stack_regs && op_is_set_bp(&ctx->op, bp_reg, sp_reg)) {
				ctx->fcn->bp_off = -ctx->sp - ctx->op.src[0]->delta;
			}
			if (ctx->op.dst && ctx->op.dst->reg && ctx->op.dst->reg->name && ctx->op.ptr > 0 && ctx->op.ptr != UT64_MAX) {
				free(ctx->last_reg_mov_lea_name);
				if ((ctx->last_reg_mov_lea_name = rz_str_dup(ctx->op.dst->reg->name))) {
					ctx->last_reg_mov_lea_val = ctx->op.ptr;
					ctx->last_is_reg_mov_lea = true;
				}
			}
			// skip lea reg,[reg]
			if (ctx->analysis->opt.hpskip && regs_exist(ctx->op.src[0], ctx->op.dst) && !strcmp(ctx->op.src[0]->reg->name, ctx->op.dst->reg->name)) {
				ctx->skip_ret = skip_hp(ctx->analysis, ctx->fcn, &ctx->op, ctx->bb, at, ctx->tmp_buf, ctx->oplen, ctx->delay.un_idx, &ctx->idx);
				if (ctx->skip_ret == 1) {
					goto repeat;
				}
				if (ctx->skip_ret == 2) {
					ctx->ret = RZ_ANALYSIS_RET_END;
					return ctx->ret;
				}
			}
			if (ctx->analysis->opt.jmptbl) {
				RzAnalysisOp jmp_aop = { 0 };
				ut64 jmptbl_addr = ctx->op.ptr;
				ut64 casetbl_addr = ctx->op.ptr;
				if (is_delta_pointer_table(&ctx->read_ahead_cache, ctx->analysis, ctx->op.addr, ctx->op.ptr, &jmptbl_addr, &casetbl_addr, &jmp_aop)) {
					// we require both checks here since rz_analysis_get_jmptbl_info uses
					// BB info of the final jmptbl jump, which is no present with
					// is_delta_pointer_table just scanning ahead
					// rz_analysis_get_delta_jmptbl_info doesn't work at times where the
					// lea comes after the cmp/default case cjmp, which can be
					// handled with rz_analysis_get_jmptbl_info
					RzAnalysisJmpTableParams params = {
						.jmp_address = jmp_aop.addr,
						.jmptbl_loc = jmptbl_addr,
						.casetbl_loc = casetbl_addr,
						.entry_size = 4,
						.jmptbl_off = ctx->op.ptr,
						.sp = ctx->sp,
						.tasks = tasks
					};
					if (rz_analysis_get_jmptbl_info(ctx->analysis, ctx->fcn, ctx->bb, jmp_aop.addr, &params) || rz_analysis_get_delta_jmptbl_info(ctx->analysis, ctx->fcn, jmp_aop.addr, ctx->op.addr, &params)) {
						ctx->ret = casetbl_addr == ctx->op.ptr
							? rz_analysis_walkthrough_jmptbl(ctx->analysis, ctx->fcn, ctx->bb, &params)
							: rz_analysis_walkthrough_casetbl(ctx->analysis, ctx->fcn, ctx->bb, &params);
						if (ctx->ret) {
							ctx->analysis->lea_jmptbl_ip = jmp_aop.addr;
						}
					}
				}
				rz_analysis_op_fini(&jmp_aop);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_LOAD:
			if (ctx->analysis->opt.loads) {
				if (ctx->analysis->iob.is_valid_offset(ctx->analysis->iob.io, ctx->op.ptr, 0)) {
					rz_meta_set(ctx->analysis, RZ_META_TYPE_DATA, ctx->op.ptr, 4, "");
				}
			}
			break;
			// Case of valid but unused "add [rax], al"
		case RZ_ANALYSIS_OP_TYPE_ADD:
			if (ctx->selected_architecture.is_arm && ctx->analysis->bits == 32) {
				if (!memcmp(ctx->buf, "\x00\xe0\x8f\xe2", 4)) {
					// TODO: support different values, not just 0
					// add lr, pc, 0 //
					ctx->last_is_add_lr_pc = true;
				}
			}
			if (ctx->analysis->opt.ijmp) {
				if ((ctx->op.size + 4 <= bytes_read) && !memcmp(ctx->buf + ctx->op.size, "\x00\x00\x00\x00", 4)) {
					rz_analysis_block_set_size(ctx->bb, ctx->bb->size - ctx->oplen);
					ctx->op.type = RZ_ANALYSIS_OP_TYPE_RET;
					ctx->ret = RZ_ANALYSIS_RET_END;
					return ctx->ret;
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_ILL:
			ctx->ret = RZ_ANALYSIS_RET_END;
			return ctx->ret;
		case RZ_ANALYSIS_OP_TYPE_TRAP:
			if (ctx->analysis->opt.aftertrap) {
				continue;
			}
			ctx->ret = RZ_ANALYSIS_RET_END;
			return ctx->ret;
		case RZ_ANALYSIS_OP_TYPE_NOP:
			// do nothing, because the nopskip goes before this switch
			break;
		case RZ_ANALYSIS_OP_TYPE_JMP:
			if (ctx->op.jump == UT64_MAX) {
				ctx->ret = RZ_ANALYSIS_RET_END;
				return ctx->ret;
			}
			{
				RzFlagItem *fi = ctx->analysis->flb.get_at(ctx->analysis->flb.f, ctx->op.jump, false);
				if (fi && strstr(fi->name, "imp.")) {
					ctx->ret = RZ_ANALYSIS_RET_END;
					return ctx->ret;
				}
			}
			if (rz_cons_is_breaked()) {
				ctx->ret = RZ_ANALYSIS_RET_END;
				return ctx->ret;
			}
			if (ctx->analysis->opt.jmpref) {
				(void)rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->op.jump, RZ_ANALYSIS_XREF_TYPE_CODE);
			}
			if (!ctx->analysis->opt.jmpabove && (ctx->op.jump < ctx->fcn->addr)) {
				ctx->ret = RZ_ANALYSIS_RET_END;
				return ctx->ret;
			}
			if (rz_analysis_noreturn_at(ctx->analysis, ctx->op.jump)) {
				if (ctx->continue_after_jump && ctx->selected_architecture.is_hexagon) {
					rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.jump, ctx->sp);
					rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.addr + ctx->op.size, ctx->sp);
					if (!ctx->overlapped) {
						set_bb_branches(ctx->bb, ctx->op.jump, ctx->op.addr + ctx->op.size);
					}
					ctx->ret = RZ_ANALYSIS_RET_BRANCH;
					return ctx->ret;
				}
				ctx->ret = RZ_ANALYSIS_RET_END;
				return ctx->ret;
			}
			{
				if (jump_leaves_mapped_mem(ctx->analysis, ctx->addr, ctx->op.jump)) {
					if (ctx->continue_after_jump && ctx->selected_architecture.is_hexagon) {
						rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.jump, ctx->sp);
						rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.addr + ctx->op.size, ctx->sp);
						if (!ctx->overlapped) {
							set_bb_branches(ctx->bb, ctx->op.jump, ctx->op.addr + ctx->op.size);
						}
						ctx->ret = RZ_ANALYSIS_RET_BRANCH;
						return ctx->ret;
					}
					ctx->op.jump = UT64_MAX;
					ctx->ret = RZ_ANALYSIS_RET_END;
					return ctx->ret;
				}
			}
			if (!ctx->overlapped) {
				set_bb_branches(ctx->bb, ctx->op.jump, UT64_MAX);
			}
			if (jumps_to_prelude(ctx->analysis, ctx->op.jump) || ctx->op.type & RZ_ANALYSIS_OP_TYPE_TAIL) {
				// Most archs don't set this flag. So we update it here.
				ctx->op.type |= RZ_ANALYSIS_OP_TYPE_TAIL;
				rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->op.jump, RZ_ANALYSIS_XREF_TYPE_CALL);
				if (ctx->selected_architecture.is_hexagon) {
					// After the jump should always follow a dealloc instruction.
					// It is not included in the block, if we do RET_END here.
					break;
				}
				ctx->ret = RZ_ANALYSIS_RET_END;
				return ctx->ret;
			}

			rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.jump, ctx->sp);
			if (ctx->continue_after_jump && (ctx->selected_architecture.is_hexagon || (ctx->selected_architecture.is_dalvik && ctx->op.cond == RZ_TYPE_COND_EXCEPTION))) {
				rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.addr + ctx->op.size, ctx->sp);
				ctx->ret = RZ_ANALYSIS_RET_BRANCH;
				return ctx->ret;
			}
			return ctx->ret;
			break;
		case RZ_ANALYSIS_OP_TYPE_SUB:
			if (ctx->op.val != UT64_MAX && ctx->op.val > 0 && ctx->op.val < ctx->analysis->opt.jmptbl_maxcount) {
				// if register is not stack
				ctx->analysis->cmpval = ctx->op.val;
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_CMP: {
			ut64 val = ctx->selected_architecture.is_x86 ? ctx->op.val : ctx->op.ptr;
			if (val) {
				if (val < ctx->analysis->opt.jmptbl_maxcount) {
					ctx->analysis->cmpval = val;
				}
				ctx->bb->cmpval = val;
				ctx->bb->cmpreg = ctx->op.reg;
				rz_analysis_cond_free(ctx->bb->cond);
				ctx->bb->cond = rz_analysis_cond_new_from_op(&ctx->op);
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_MCJMP:
		case RZ_ANALYSIS_OP_TYPE_RCJMP:
		case RZ_ANALYSIS_OP_TYPE_UCJMP:
			if (ctx->op.prefix & RZ_ANALYSIS_OP_PREFIX_HWLOOP_END) {
				if (ctx->op.jump != 0) {
					rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->op.jump, RZ_ANALYSIS_XREF_TYPE_CODE);
				}
				if (ctx->op.fail != 0) {
					rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->op.fail, RZ_ANALYSIS_XREF_TYPE_CODE);
				}
				if (ctx->continue_after_jump) {
					rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.addr + ctx->op.size, ctx->sp);
				}
				if (!ctx->overlapped) {
					// If it is an endloop01 instruction the jump to the inner loop is not added yet.
					set_bb_branches(ctx->bb, ctx->op.jump, ctx->op.addr + ctx->op.size);
				}
				ctx->ret = RZ_ANALYSIS_RET_BRANCH;
				return ctx->ret;
			}
			if (ctx->analysis->opt.cjmpref) {
				rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->op.jump, RZ_ANALYSIS_XREF_TYPE_CODE);
				if (ctx->selected_architecture.is_hexagon) {
					rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->op.fail, RZ_ANALYSIS_XREF_TYPE_CODE);
				}
			}
			if (!ctx->overlapped) {
				set_bb_branches(ctx->bb, ctx->op.jump, ctx->op.fail);
			}
			if (ctx->bb->cond) {
				ctx->bb->cond->type = ctx->op.cond;
			}
			if (ctx->analysis->opt.jmptbl) {
				if (ctx->op.ptr != UT64_MAX) {
					if (ctx->analysis->cmpval != UT64_MAX && ctx->op.fail != UT64_MAX && (ctx->op.reg || ctx->op.ireg)) {
						RzAnalysisJmpTableParams params = {
							.jmp_address = ctx->op.addr,
							.case_shift = 0,
							.jmptbl_loc = ctx->op.ptr,
							.casetbl_loc = UT64_MAX,
							.entry_size = ctx->analysis->bits >> 3,
							.table_count = ctx->analysis->cmpval + 1,
							.jmptbl_off = ctx->op.ptr,
							.default_case = ctx->op.fail,
							.sp = ctx->sp,
							.tasks = tasks
						};
						if (ctx->op.ireg) {
							rz_analysis_walkthrough_jmptbl(ctx->analysis, ctx->fcn, ctx->bb, &params);
						} else if (RZ_STR_EQ(ctx->analysis->arch_target->arch, "arm")) {
							rz_analysis_walkthrough_arm_jmptbl_style(ctx->analysis, ctx->fcn, ctx->bb, &params);
						}
						// check if op.jump and op.fail contain jump table location
						// clear jump address, because it's jump table location
						if (ctx->op.jump == ctx->op.ptr) {
							ctx->op.jump = UT64_MAX;
						} else if (ctx->op.fail == ctx->op.ptr) {
							ctx->op.fail = UT64_MAX;
						}
						ctx->analysis->cmpval = UT64_MAX;
					}
				}
			}
			rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.fail, ctx->sp);
			rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.jump, ctx->sp);
			if (ctx->continue_after_jump && ctx->selected_architecture.is_hexagon) {
				if (ctx->op.type == RZ_ANALYSIS_OP_TYPE_RCJMP) {
					break;
				}
				rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.addr + ctx->op.size, ctx->sp);
				ctx->ret = RZ_ANALYSIS_RET_BRANCH;
				return ctx->ret;
			}
			if (!ctx->continue_after_jump) {
				if (ctx->op.jump < ctx->fcn->addr) {
					if (!ctx->overlapped) {
						ctx->bb->jump = ctx->op.jump;
						ctx->bb->fail = UT64_MAX;
					}
					ctx->ret = RZ_ANALYSIS_RET_END;
					return ctx->ret;
				}
			}

			// XXX breaks mips analysis too !op.delay
			// this will be all x86, arm (at least)
			// without which the analysis is really slow,
			// presumably because each opcode would get revisited
			// (and already covered by a bb) many times
			if (!ctx->selected_architecture.is_dalvik) {
				return ctx->ret;
			}
			// For some reason, branch delayed code (MIPS) needs to continue
			break;
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_ICALL:
		case RZ_ANALYSIS_OP_TYPE_IRCALL:
			/* call [dst] */
			// XXX: this is TYPE_MCALL or indirect-call
			(void)rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->op.ptr, RZ_ANALYSIS_XREF_TYPE_CALL);

			if (is_unknown_call_from_plt(ctx->analysis, at) ||
				rz_analysis_noreturn_at(ctx->analysis, ctx->op.ptr)) {
				RzAnalysisFunction *f = rz_analysis_get_function_at(ctx->analysis, ctx->op.ptr);
				if (f) {
					f->is_noreturn = true;
				}
				ctx->ret = RZ_ANALYSIS_RET_END;
				return ctx->ret;
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_CCALL:
		case RZ_ANALYSIS_OP_TYPE_CALL:
			/* call dst */
			(void)rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->op.jump, RZ_ANALYSIS_XREF_TYPE_CALL);

			if (rz_analysis_noreturn_at(ctx->analysis, ctx->op.jump)) {
				RzAnalysisFunction *f = rz_analysis_get_function_at(ctx->analysis, ctx->op.jump);
				if (f) {
					f->is_noreturn = true;
				}
				ctx->ret = RZ_ANALYSIS_RET_END;
				return ctx->ret;
			}

			if (ctx->analysis->gnu_thumb1_case_uqi_addr && ctx->op.jump == ctx->analysis->gnu_thumb1_case_uqi_addr && ctx->analysis->opt.jmptbl) {
				RzAnalysisJmpTableParams params = {
					.jmp_address = ctx->op.addr,
					.entry_size = 1,
					.jmptbl_loc = ctx->op.addr + ctx->op.size,
					.jmptbl_off = ctx->op.addr + ctx->op.size,
					.sp = ctx->sp,
					.tasks = tasks
				};
				ctx->ret = rz_analysis_walkthrough_arm_thumb1_case_uqi_table(ctx->analysis, ctx->fcn, ctx->bb, &params);
				return RZ_ANALYSIS_RET_BRANCH; // ???
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_UJMP:
		case RZ_ANALYSIS_OP_TYPE_RJMP:
			if (ctx->selected_architecture.is_hexagon) {
				if (ctx->op.analysis_vals[0].plugin_specific == 31) {
					// jumpr Rs instruction which uses R31.
					// This is a return, but not typed as such.
					ctx->ret = RZ_ANALYSIS_RET_END;
					return ctx->ret;
				} else {
					// Ignore
					break;
				}
			} else if (ctx->selected_architecture.is_arm && ctx->analysis->bits == 32 && ctx->last_is_mov_lr_pc) {
				break;
			} else if (ctx->selected_architecture.is_arm && ctx->analysis->bits == 32 && ctx->last_is_add_lr_pc) {
				ctx->op.type = RZ_ANALYSIS_OP_TYPE_CALL;
				ctx->op.fail = ctx->op.addr + 4;
				break;
			}
			/* fall through */
		case RZ_ANALYSIS_OP_TYPE_MJMP:
		case RZ_ANALYSIS_OP_TYPE_IJMP:
		case RZ_ANALYSIS_OP_TYPE_IRJMP:
			// if the next instruction is a symbol
			if (ctx->analysis->opt.ijmp && isSymbolNextInstruction(ctx->analysis, &ctx->op)) {
				ctx->ret = RZ_ANALYSIS_RET_END;
				return ctx->ret;
			}
			// switch statement
			if (ctx->analysis->opt.jmptbl && ctx->analysis->lea_jmptbl_ip != ctx->op.addr) {
				RzAnalysisJmpTableParams params = {
					.jmp_address = ctx->op.addr,
					.entry_size = ctx->analysis->bits >> 3,
					.jmptbl_loc = ctx->op.ptr,
					.jmptbl_off = ctx->op.ptr,
					.sp = ctx->sp,
					.tasks = tasks
				};
				// op.ireg since rip relative addressing produces way too many false positives otherwise
				// op.ireg is 0 for rip relative, "rax", etc otherwise
				if (ctx->op.ptr != UT64_MAX && ctx->op.ireg) { // direct jump
					if (rz_analysis_get_jmptbl_info(ctx->analysis, ctx->fcn, ctx->bb, ctx->op.addr, &params)) {
						bool case_table = false;
						RzAnalysisOp prev_op;
						ctx->analysis->iob.read_at(ctx->analysis->iob.io, ctx->op.addr - ctx->op.size, ctx->buf, sizeof(ctx->buf));
						rz_analysis_op_init(&prev_op);
						if (rz_analysis_op(ctx->analysis, &prev_op, ctx->op.addr - ctx->op.size, ctx->buf, sizeof(ctx->buf), RZ_ANALYSIS_OP_MASK_VAL) > 0) {
							bool prev_op_has_dst_name = prev_op.dst && prev_op.dst->reg && prev_op.dst->reg->name;
							bool op_has_src_name = ctx->op.src[0] && ctx->op.src[0]->reg && ctx->op.src[0]->reg->name;
							bool same_reg = (ctx->op.ireg && prev_op_has_dst_name && !strcmp(ctx->op.ireg, prev_op.dst->reg->name)) || (op_has_src_name && prev_op_has_dst_name && !strcmp(ctx->op.src[0]->reg->name, prev_op.dst->reg->name));
							if (prev_op.type == RZ_ANALYSIS_OP_TYPE_MOV && prev_op.disp && prev_op.disp != UT64_MAX && same_reg) {
								//	movzx reg, byte [reg + case_table]
								//	jmp dword [reg*4 + jump_table]
								params.casetbl_loc = prev_op.disp;
								if (rz_analysis_walkthrough_casetbl(ctx->analysis, ctx->fcn, ctx->bb, &params)) {
									ctx->ret = case_table = true;
								}
							}
						}
						rz_analysis_op_fini(&prev_op);
						if (!case_table) {
							ctx->ret = rz_analysis_walkthrough_jmptbl(ctx->analysis, ctx->fcn, ctx->bb, &params);
						}
					}
				} else if (ctx->op.ptr != UT64_MAX && ctx->op.reg) { // direct jump
					if (rz_analysis_get_jmptbl_info(ctx->analysis, ctx->fcn, ctx->bb, ctx->op.addr, &params)) {
						ctx->ret = rz_analysis_walkthrough_jmptbl(ctx->analysis, ctx->fcn, ctx->bb, &params);
					}
				} else if (ctx->movdisp != UT64_MAX) {
					ut64 lea_op_off = UT64_MAX;
					RzListIter *iter;
					leaddr_pair *pair;
					params.jmptbl_off = 0;
					if (ctx->movbasereg) {
						// find nearest candidate leaddr before op.addr
						rz_list_foreach_prev(ctx->analysis->leaddrs, iter, pair) {
							if (pair->op_addr >= ctx->op.addr) {
								continue;
							}
							if ((lea_op_off == UT64_MAX || lea_op_off > ctx->op.addr - pair->op_addr) && pair->reg && !strcmp(ctx->movbasereg, pair->reg)) {
								lea_op_off = ctx->op.addr - pair->op_addr;
								params.jmptbl_off = pair->leaddr;
							}
						}
					}
					if (!rz_analysis_get_jmptbl_info(ctx->analysis, ctx->fcn, ctx->bb, ctx->op.addr, &params)) {
						params.table_count = ctx->analysis->cmpval + 1;
						params.default_case = -1;
					}
					params.jmptbl_loc = params.jmptbl_off + ctx->movdisp;
					params.entry_size = ctx->movscale;
					ctx->ret = rz_analysis_walkthrough_jmptbl(ctx->analysis, ctx->fcn, ctx->bb, &params);
					ctx->analysis->cmpval = UT64_MAX;
				} else if (ctx->selected_architecture.is_arm) {
					params.jmptbl_loc = ctx->op.addr + ctx->op.size;
					params.jmptbl_off = ctx->op.addr + 4;
					params.default_case = UT64_MAX;
					if (ctx->op.ptrsize == 1) { // TBB
						ut64 pred_cmpval = try_get_cmpval_from_parents(ctx->analysis, ctx->fcn, ctx->bb, ctx->op.ireg);
						params.table_count = 0;
						if (pred_cmpval != UT64_MAX) {
							params.table_count += pred_cmpval;
						} else {
							params.table_count += ctx->analysis->cmpval;
						}
						params.entry_size = 1;
						ctx->ret = rz_analysis_walkthrough_jmptbl(ctx->analysis, ctx->fcn, ctx->bb, &params);
						// skip inlined jumptable
						ctx->idx += params.table_count;
					} else if (ctx->op.ptrsize == 2) { // LDRH on thumb/arm
						ut64 pred_cmpval = try_get_cmpval_from_parents(ctx->analysis, ctx->fcn, ctx->bb, ctx->op.ireg);
						params.table_count = 1;
						if (pred_cmpval != UT64_MAX) {
							params.table_count += pred_cmpval;
						} else {
							params.table_count += ctx->analysis->cmpval;
						}
						params.entry_size = 2;
						ctx->ret = rz_analysis_walkthrough_jmptbl(ctx->analysis, ctx->fcn, ctx->bb, &params);
						// skip inlined jumptable
						ctx->idx += (params.table_count * 2);
					}
				}
			}
			if (ctx->analysis->lea_jmptbl_ip == ctx->op.addr) {
				ctx->analysis->lea_jmptbl_ip = UT64_MAX;
			}
			if (ctx->analysis->opt.ijmp) {
				if (ctx->continue_after_jump) {
					rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.fail, ctx->sp);
					rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.jump, ctx->sp);
					if (ctx->overlapped) {
						goto analyzeopfinish;
					}
				}
				if (rz_analysis_noreturn_at(ctx->analysis, ctx->op.jump) || ctx->op.eob) {
					goto analyzeopfinish;
				}
			} else {
			analyzeopfinish:
				if (ctx->op.type == RZ_ANALYSIS_OP_TYPE_RJMP) {
					ctx->ret = RZ_ANALYSIS_RET_NOP;
					return ctx->ret;
				} else {
					ctx->ret = RZ_ANALYSIS_RET_END;
					return ctx->ret;
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_PUSH:
			ctx->last_is_push = true;
			ctx->last_push_addr = ctx->op.val;
			if (ctx->analysis->iob.is_valid_offset(ctx->analysis->iob.io, ctx->last_push_addr, 1)) {
				(void)rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->last_push_addr, RZ_ANALYSIS_XREF_TYPE_DATA);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_UPUSH:
			if ((ctx->op.type & RZ_ANALYSIS_OP_TYPE_REG) && ctx->last_is_reg_mov_lea && ctx->op.src[0] && ctx->op.src[0]->reg && ctx->op.src[0]->reg->name && !strcmp(ctx->op.src[0]->reg->name, ctx->last_reg_mov_lea_name)) {
				ctx->last_is_push = true;
				ctx->last_push_addr = ctx->last_reg_mov_lea_val;
				if (ctx->analysis->iob.is_valid_offset(ctx->analysis->iob.io, ctx->last_push_addr, 1)) {
					(void)rz_analysis_xrefs_set(ctx->analysis, ctx->op.addr, ctx->last_push_addr, RZ_ANALYSIS_XREF_TYPE_DATA);
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_RET:
			if (ctx->op.family == RZ_ANALYSIS_OP_FAMILY_PRIV) {
				ctx->fcn->type = RZ_ANALYSIS_FCN_TYPE_INT;
			}
			if (ctx->last_is_push && ctx->analysis->opt.pushret) {
				ctx->op.type = RZ_ANALYSIS_OP_TYPE_JMP;
				ctx->op.jump = ctx->last_push_addr;
				ctx->bb->jump = ctx->op.jump;
				rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.jump, ctx->sp);
				return ctx->ret;
			}
			if (ctx->op.cond == RZ_TYPE_COND_AL) {
				RZ_LOG_DEBUG("RET 0x%08" PFMT64x ". overlap=%s %" PFMT64u " %" PFMT64u "\n",
					ctx->addr + ctx->delay.un_idx - ctx->oplen, rz_str_bool(ctx->overlapped),
					ctx->bb->size, rz_analysis_function_linear_size(ctx->fcn));
				ctx->ret = RZ_ANALYSIS_RET_END;
				return ctx->ret;
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_CRET:
			if (ctx->continue_after_jump && ctx->selected_architecture.is_hexagon) {
				rz_analysis_task_item_new(ctx->analysis, tasks, ctx->fcn, NULL, ctx->op.addr + ctx->op.size, ctx->sp);
				set_bb_branches(ctx->bb, ctx->op.addr + ctx->op.size, UT64_MAX); // function left
				ctx->ret = RZ_ANALYSIS_RET_COND;
				return ctx->ret;
			}
		}
		if (ctx->op.type != RZ_ANALYSIS_OP_TYPE_MOV && ctx->op.type != RZ_ANALYSIS_OP_TYPE_CMOV && ctx->op.type != RZ_ANALYSIS_OP_TYPE_LEA) {
			ctx->last_is_reg_mov_lea = false;
		}
		if (ctx->op.type != RZ_ANALYSIS_OP_TYPE_PUSH && ctx->op.type != RZ_ANALYSIS_OP_TYPE_RPUSH) {
			ctx->last_is_push = false;
		}
		if (ctx->selected_architecture.is_arm && ctx->op.type != RZ_ANALYSIS_OP_TYPE_MOV) {
			ctx->last_is_mov_lr_pc = false;
		}
		if (ctx->has_variadic_reg && !ctx->fcn->is_variadic) {
			ctx->variadic_reg = rz_reg_get(ctx->analysis->reg, "rax", RZ_REG_TYPE_GPR);
			bool dst_is_variadic = ctx->op.dst && ctx->op.dst->reg && ctx->variadic_reg && ctx->op.dst->reg->offset == ctx->variadic_reg->offset;
			bool op_is_cmp = (ctx->op.type == RZ_ANALYSIS_OP_TYPE_CMP) || ctx->op.type == RZ_ANALYSIS_OP_TYPE_ACMP;
			if (dst_is_variadic && !op_is_cmp) {
				ctx->has_variadic_reg = false;
			} else if (op_is_cmp) {
				if (ctx->op.src[0] && ctx->op.src[0]->reg && (ctx->op.dst->reg == ctx->op.src[0]->reg) && dst_is_variadic) {
					ctx->fcn->is_variadic = true;
				}
			}
		}
	}

	return ctx->ret;
}

void cleanup_basic_block(BasicBlockAnalysisCtx *ctx) {
	rz_analysis_op_fini(&ctx->op);
	RZ_FREE(ctx->last_reg_mov_lea_name);
	if (ctx->bb) {
		if (ctx->bb->size) {
			rz_analysis_block_update_hash(ctx->bb);
		} else {
			rz_analysis_function_remove_block(ctx->fcn, ctx->bb);
		}
		rz_analysis_block_unref(ctx->bb);
	}
	free(ctx->movbasereg);
}