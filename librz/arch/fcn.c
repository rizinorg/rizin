// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_regex.h>
#include <rz_analysis.h>
#include <rz_parse.h>
#include <rz_util.h>
#include <rz_list.h>

#define SDB_KEY_BB "bb.0x%" PFMT64x ".0x%" PFMT64x
// XXX must be configurable by the user
#define JMPTBL_LEA_SEARCH_SZ 64
#define BB_ALIGN             0x10
#define MAX_SCAN_SIZE        0x7ffffff

// 16 KB is the maximum size for a basic block
#define MAX_FLG_NAME_SIZE 64

// 64KB max size
// 256KB max function size
#define MAX_FCN_SIZE (1024 * 256)

#define DB             a->sdb_fcns
#define EXISTS(x, ...) snprintf(key, sizeof(key) - 1, x, ##__VA_ARGS__), sdb_exists(DB, key)
#define SETKEY(x, ...) snprintf(key, sizeof(key) - 1, x, ##__VA_ARGS__);

typedef struct fcn_tree_iter_t {
	int len;
	RBNode *cur;
	RBNode *path[RZ_RBTREE_MAX_HEIGHT];
} FcnTreeIter;

RZ_API const char *rz_analysis_fcntype_tostring(int type) {
	switch (type) {
	case RZ_ANALYSIS_FCN_TYPE_NULL: return "null";
	case RZ_ANALYSIS_FCN_TYPE_FCN: return "fcn";
	case RZ_ANALYSIS_FCN_TYPE_LOC: return "loc";
	case RZ_ANALYSIS_FCN_TYPE_SYM: return "sym";
	case RZ_ANALYSIS_FCN_TYPE_IMP: return "imp";
	case RZ_ANALYSIS_FCN_TYPE_INT: return "int"; // interrupt
	case RZ_ANALYSIS_FCN_TYPE_ROOT: return "root";
	}
	return "unk";
}

typedef struct {
	ut8 cache[1024];
	ut64 cache_addr;
} ReadAhead;

// TODO: move into io :?
static int read_ahead(ReadAhead *ra, RzAnalysis *analysis, ut64 addr, ut8 *buf, ssize_t len) {
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

RZ_API int rz_analysis_function_resize(RzAnalysisFunction *fcn, int newsize) {
	rz_return_val_if_fail(fcn, false);
	if (newsize < 1) {
		return false;
	}

	RzAnalysis *analysis = fcn->analysis;

	// XXX this is something we should probably do for all the archs
	bool is_arm = analysis->cur->arch && !strncmp(analysis->cur->arch, "arm", 3);
	if (is_arm) {
		return true;
	}

	ut64 eof = fcn->addr + newsize;

	// in this loop we remove basic blocks and since we modify the
	// pvector size we cannot loop normally.
	size_t count = rz_pvector_len(fcn->bbs);
	for (size_t i = 0; i < count;) {
		RzAnalysisBlock *bb = (RzAnalysisBlock *)rz_pvector_at(fcn->bbs, i);
		if (bb->addr >= eof) {
			rz_analysis_function_remove_block(fcn, bb);
			// the size of the pvector is changed, so we update count.
			count = rz_pvector_len(fcn->bbs);
			continue;
		}
		if (bb->addr + bb->size >= eof) {
			rz_analysis_block_set_size(bb, eof - bb->addr);
			rz_analysis_block_update_hash(bb);
		}
		if (bb->jump != UT64_MAX && bb->jump >= eof) {
			bb->jump = UT64_MAX;
		}
		if (bb->fail != UT64_MAX && bb->fail >= eof) {
			bb->fail = UT64_MAX;
		}
		i++;
	}

	return true;
}

// Create a new 0-sized basic block inside the function
static RzAnalysisBlock *fcn_append_basic_block(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr) {
	RzAnalysisBlock *bb = rz_analysis_create_block(analysis, addr, 0);
	if (!bb) {
		return NULL;
	}
	rz_analysis_function_add_block(fcn, bb);
	return bb;
}

#define gotoBeach(x) \
	ret = x; \
	goto beach;

static bool isInvalidMemory(RzAnalysis *analysis, const ut8 *buf, int len) {
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

static bool isSymbolNextInstruction(RzAnalysis *analysis, RzAnalysisOp *op) {
	rz_return_val_if_fail(analysis && op && analysis->flb.get_at, false);

	RzFlagItem *fi = analysis->flb.get_at(analysis->flb.f, op->addr + op->size, false);
	return (fi && fi->name && (strstr(fi->name, "imp.") || strstr(fi->name, "sym.") || strstr(fi->name, "entry") || strstr(fi->name, "main")));
}

static bool is_delta_pointer_table(ReadAhead *ra, RzAnalysis *analysis, ut64 addr, ut64 lea_ptr, ut64 *jmptbl_addr, ut64 *casetbl_addr, RzAnalysisOp *jmp_aop) {
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
#if 0
	// required for the last jmptbl.. but seems to work without it and breaks other tests
	if (mov_aop.type && mov_aop.ptr) {
		*jmptbl_addr += mov_aop.ptr;
		// absjmptbl
		lea_ptr = mov_aop.ptr;
	}
#endif
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

static ut64 try_get_cmpval_from_parents(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *my_bb, const char *cmp_reg) {
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

static bool regs_exist(RzAnalysisValue *src, RzAnalysisValue *dst) {
	rz_return_val_if_fail(src && dst, false);
	return src->reg && dst->reg && src->reg->name && dst->reg->name;
}

// 0 if not skipped; 1 if skipped; 2 if skipped before
static int skip_hp(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisOp *op, RzAnalysisBlock *bb, ut64 addr,
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

static bool purity_checked(HtUP *ht, RzAnalysisFunction *fcn) {
	bool checked;
	ht_up_find(ht, fcn->addr, &checked);
	return checked;
}

/*
 * Checks whether a given function is pure and sets its 'is_pure' field.
 * This function marks fcn 'not pure' if fcn, or any function called by fcn, accesses data
 * from outside, even if it only READS it.
 * Probably worth changing it in the future, so that it marks fcn 'impure' only when it
 * (or any function called by fcn) MODIFIES external data.
 */
static void check_purity(HtUP *ht, RzAnalysisFunction *fcn) {
	RzListIter *iter;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	RzAnalysisXRef *xref;
	ht_up_insert(ht, fcn->addr, NULL);
	fcn->is_pure = true;
	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_CALL || xref->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
			RzAnalysisFunction *called_fcn = rz_analysis_get_fcn_in(fcn->analysis, xref->to, 0);
			if (!called_fcn) {
				continue;
			}
			if (!purity_checked(ht, called_fcn)) {
				check_purity(ht, called_fcn);
			}
			if (!called_fcn->is_pure) {
				fcn->is_pure = false;
				break;
			}
		}
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_DATA) {
			fcn->is_pure = false;
			break;
		}
	}
	rz_list_free(xrefs);
}

typedef struct {
	ut64 op_addr;
	ut64 leaddr;
	char *reg;
} leaddr_pair;

static void free_leaddr_pair(void *pair) {
	leaddr_pair *_pair = pair;
	free(_pair->reg);
	free(_pair);
}

static RzAnalysisBlock *bbget(RzAnalysis *analysis, ut64 addr, bool jumpmid) {
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

typedef struct {
	RzAnalysisFunction *fcn;
	const st64 stack_diff;
} BlockTakeoverCtx;

static bool fcn_takeover_block_recursive_followthrough_cb(RzAnalysisBlock *block, void *user) {
	BlockTakeoverCtx *ctx = user;
	RzAnalysisFunction *our_fcn = ctx->fcn;
	rz_analysis_block_ref(block);
	while (!rz_list_empty(block->fcns)) {
		RzAnalysisFunction *other_fcn = rz_list_first(block->fcns);
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
static void fcn_takeover_block_recursive(RzAnalysisFunction *fcn, RzAnalysisBlock *start_block, RzStackAddr sp) {
	BlockTakeoverCtx ctx = { fcn, sp - start_block->sp_entry };
	rz_analysis_block_recurse_followthrough(start_block, fcn_takeover_block_recursive_followthrough_cb, &ctx);
}

static const char *retpoline_reg(RzAnalysis *analysis, ut64 addr) {
	RzFlagItem *flag = analysis->flag_get(analysis->flb.f, addr);
	if (flag) {
		const char *token = "x86_indirect_thunk_";
		const char *thunk = strstr(flag->name, token);
		if (thunk) {
			return thunk + strlen(token);
		}
	}
#if 0
// TODO: implement following code analysis check for stripped binaries:
// 1) op(addr).type == CALL
// 2) call_dest = op(addr).addr
// 3) op(call_dest).type == STORE
// 4) op(call_dest + op(call_dest).size).type == RET
[0x00000a65]> pid 6
0x00000a65  sym.__x86_indirect_thunk_rax:
0x00000a65  .------- e807000000  call 0xa71
0x00000a6a  |              f390  pause
0x00000a6c  |            0faee8  lfence
0x00000a6f  |              ebf9  jmp 0xa6a
0x00000a71  `---->     48890424  mov qword [rsp], rax
0x00000a75                   c3  ret
#endif
	return NULL;
}

static void analyze_retpoline(RzAnalysis *analysis, RzAnalysisOp *op) {
	if (analysis->opt.retpoline) {
		const char *rr = retpoline_reg(analysis, op->jump);
		if (rr) {
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
			op->reg = rr;
		}
	}
}

static inline bool op_is_set_bp(RzAnalysisOp *op, const char *bp_reg, const char *sp_reg) {
	bool has_dst_reg = op->dst && op->dst->reg && op->dst->reg->name;
	bool has_src_reg = op->src[0] && op->src[0]->reg && op->src[0]->reg->name;
	if (has_dst_reg && has_src_reg) {
		return !strcmp(bp_reg, op->dst->reg->name) && !strcmp(sp_reg, op->src[0]->reg->name);
	}
	return false;
}

static inline bool does_arch_destroys_dst(const char *arch) {
	return arch && (!strncmp(arch, "arm", 3) || !strcmp(arch, "riscv") || !strcmp(arch, "ppc"));
}

static int analyze_function_locally(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 address) {
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

static inline void set_bb_branches(RZ_OUT RzAnalysisBlock *bb, const ut64 jump, const ut64 fail) {
	bb->jump = jump;
	bb->fail = fail;
}

/**
 * \brief Analyses the given task item \p item for branches.
 *
 * Analysis starts for all instructions from \p item->start_address. If a branch is
 * encountered a new task item is added to the list \p tasks.
 * If an end of a basic function block is encountered (e.g. an invalid instruction),
 * the cause for it is returned.
 *
 * \param item The task item with the parent function and start address to start analysing from.
 * \param tasks The task list to append the new task items to.
 * \return RzAnalysisBBEndCause Cause a basic block ended.
 */
static RzAnalysisBBEndCause run_basic_block_analysis(RzAnalysisTaskItem *item, RzVector /*<RzAnalysisTaskItem>*/ *tasks) {
	rz_return_val_if_fail(item && tasks, RZ_ANALYSIS_RET_ERROR);
	RzAnalysis *analysis = item->fcn->analysis;
	RzAnalysisFunction *fcn = item->fcn;
	RzStackAddr sp = item->sp;
	ut64 addr = item->start_address;
	ut64 len = analysis->opt.bb_max_size;
	ReadAhead read_ahead_cache = { 0 };
	const int continue_after_jump = analysis->opt.afterjmp;
	const int addrbytes = analysis->iob.io ? analysis->iob.io->addrbytes : 1;
	char *last_reg_mov_lea_name = NULL;
	char *movbasereg = NULL;
	RzAnalysisBlock *bb = item->block;
	RzAnalysisBlock *bbg = NULL;
	RzAnalysisBBEndCause ret = RZ_ANALYSIS_RET_END, skip_ret = 0;
	bool overlapped = false;
	RzAnalysisOp op = { 0 };
	int oplen, idx = 0;
	bool varset = false;
	struct {
		int cnt;
		int idx;
		int after;
		int pending;
		int adjust;
		int un_idx; // delay.un_idx
	} delay = {
		0
	};

	read_ahead_cache.cache_addr = UT64_MAX; // invalidate the cache
	char tmp_buf[MAX_FLG_NAME_SIZE + 5] = "skip";
	bool arch_destroys_dst = does_arch_destroys_dst(analysis->cur->arch);
	bool is_arm = false, is_x86 = false, is_amd64 = false, is_dalvik = false, is_hexagon = false;
	if (analysis->cur->arch) {
		is_arm = !strncmp(analysis->cur->arch, "arm", 3);
		is_x86 = !strncmp(analysis->cur->arch, "x86", 3);
		is_dalvik = !strncmp(analysis->cur->arch, "dalvik", 6);
		is_hexagon = !strncmp(analysis->cur->arch, "hexagon", 7);
	}
	is_amd64 = is_x86 ? fcn->cc && !strcmp(fcn->cc, "amd64") : false;
	bool can_jmpmid = analysis->opt.jmpmid && (is_dalvik || is_x86);

	RzRegItem *variadic_reg = NULL;
	if (is_amd64) {
		variadic_reg = rz_reg_get(analysis->reg, "rax", RZ_REG_TYPE_GPR);
	}
	bool has_variadic_reg = !!variadic_reg;

	if (rz_cons_is_breaked()) {
		rz_analysis_task_item_new(analysis, tasks, fcn, bb, addr, sp);
		return RZ_ANALYSIS_RET_END;
	}
	if (analysis->sleep) {
		rz_sys_usleep(analysis->sleep);
	}

	// check if address is readable
	if (!analysis->iob.is_valid_offset(analysis->iob.io, addr, 0)) {
		if (addr != UT64_MAX && !analysis->iob.io->va) {
			RZ_LOG_DEBUG("Invalid address 0x%" PFMT64x ". Try with io.va=true\n", addr);
		}
		return RZ_ANALYSIS_RET_ERROR; // MUST BE TOO DEEP
	}

	RzAnalysisFunction *fcn_at_addr = rz_analysis_get_function_at(analysis, addr);
	if (fcn_at_addr && fcn_at_addr != fcn) {
		return RZ_ANALYSIS_RET_ERROR; // MUST BE NOT FOUND
	}

	if (!bb) {
		RzAnalysisBlock *existing_bb = bbget(analysis, addr, can_jmpmid);
		if (existing_bb) {
			bool existing_in_fcn = rz_list_contains(existing_bb->fcns, fcn);
			existing_bb = rz_analysis_block_split(existing_bb, addr);
			if (!existing_in_fcn && existing_bb) {
				if (existing_bb->addr == fcn->addr) {
					// our function starts directly there, so we steal what is ours!
					fcn_takeover_block_recursive(fcn, existing_bb, sp);
				}
			}
			if (existing_bb) {
				rz_analysis_block_unref(existing_bb);
			}
			if (analysis->opt.recont) {
				return RZ_ANALYSIS_RET_END;
			}
			RZ_LOG_DEBUG("%s fails at 0x%" PFMT64x ".\n", __FUNCTION__, addr);
			return RZ_ANALYSIS_RET_ERROR; // MUST BE NOT DUP
		}

		item->block = bb = fcn_append_basic_block(analysis, fcn, addr);
		// we checked before whether there is a bb at addr, so the create should have succeeded
		rz_return_val_if_fail(bb, RZ_ANALYSIS_RET_ERROR);
	}
	// We are currently at the entrypoint of the basic block, so we may initialize
	// its entry sp value to our current tracked sp.
	bb->sp_entry = sp;

	if (!analysis->leaddrs) {
		analysis->leaddrs = rz_list_newf(free_leaddr_pair);
		if (!analysis->leaddrs) {
			RZ_LOG_ERROR("Cannot allocate list of pairs<reg, addr> values.\n");
			gotoBeach(RZ_ANALYSIS_RET_ERROR);
		}
	}
	ut64 last_reg_mov_lea_val = UT64_MAX;
	bool last_is_reg_mov_lea = false;
	bool last_is_push = false;
	bool last_is_mov_lr_pc = false;
	bool last_is_add_lr_pc = false;
	ut64 last_push_addr = UT64_MAX;
	if (analysis->limit && addr + idx < analysis->limit->from) {
		gotoBeach(RZ_ANALYSIS_RET_END);
	}
	RzAnalysisFunction *tmp_fcn = rz_analysis_get_fcn_in(analysis, addr, 0);
	if (tmp_fcn) {
		// Checks if var is already analyzed at given addr
		if (!rz_pvector_empty(&tmp_fcn->vars)) {
			varset = true;
		}
	}
	ut64 movdisp = UT64_MAX; // used by jmptbl when coded as "mov reg, [reg * scale + disp]"
	ut64 movscale = 0;
	ut8 buf[32]; // 32 bytes is enough to hold any instruction.
	int maxlen = len * addrbytes;
	if (is_dalvik) {
		bool skipAnalysis = false;
		if (!strncmp(fcn->name, "sym.", 4)) {
			if (!strncmp(fcn->name + 4, "imp.", 4)) {
				skipAnalysis = true;
			} else if (strstr(fcn->name, "field")) {
				skipAnalysis = true;
			}
		}
		if (skipAnalysis) {
			gotoBeach(RZ_ANALYSIS_RET_END);
		}
	}
	if ((maxlen - (addrbytes * idx)) > MAX_SCAN_SIZE) {
		RZ_LOG_DEBUG("Skipping large memory region during basic block analysis.\n");
		maxlen = 0;
	}

	while (addrbytes * idx < maxlen) {
		ut32 at_delta;
		ut64 at;
		if (!last_is_reg_mov_lea) {
			free(last_reg_mov_lea_name);
			last_reg_mov_lea_name = NULL;
		}
		if (analysis->limit && analysis->limit->to <= addr + idx) {
			break;
		}
	repeat:
		at_delta = addrbytes * idx;
		at = addr + at_delta;
		if (rz_cons_is_breaked()) {
			rz_analysis_task_item_new(analysis, tasks, fcn, bb, at, sp);
			break;
		}
		ut64 bytes_read = RZ_MIN(len - at_delta, sizeof(buf));
		ret = read_ahead(&read_ahead_cache, analysis, at, buf, bytes_read);

		if (ret < 0) {
			RZ_LOG_ERROR("Failed to read ahead\n");
			break;
		}
		if (isInvalidMemory(analysis, buf, bytes_read)) {
			RZ_LOG_DEBUG("FFFF opcode at 0x%08" PFMT64x "\n", at);
			gotoBeach(RZ_ANALYSIS_RET_ERROR)
		}
		rz_analysis_op_fini(&op);
		rz_analysis_op_init(&op);
		if ((oplen = rz_analysis_op(analysis, &op, at, buf, bytes_read, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_HINT)) < 1) {
			RZ_LOG_DEBUG("Invalid instruction at 0x%" PFMT64x " with %d bits\n", at, analysis->bits);
			// gotoBeach (RZ_ANALYSIS_RET_ERROR);
			// RET_END causes infinite loops somehow
			gotoBeach(RZ_ANALYSIS_RET_END);
		}

		const char *bp_reg = analysis->reg->name[RZ_REG_NAME_BP];
		const char *sp_reg = analysis->reg->name[RZ_REG_NAME_SP];
		bool has_stack_regs = bp_reg && sp_reg;

		if (analysis->opt.nopskip && fcn->addr == at) {
			RzFlagItem *fi = analysis->flb.get_at(analysis->flb.f, addr, false);
			if (!fi || strncmp(fi->name, "sym.", 4)) {
				if ((addr + delay.un_idx - oplen) == fcn->addr) {
					if (rz_analysis_block_relocate(bb, bb->addr + oplen, bb->size - oplen)) {
						fcn->addr += oplen;
						idx = delay.un_idx;
						goto repeat;
					}
				}
			}
			switch (op.type & RZ_ANALYSIS_OP_TYPE_MASK) {
			case RZ_ANALYSIS_OP_TYPE_TRAP:
			case RZ_ANALYSIS_OP_TYPE_ILL:
			case RZ_ANALYSIS_OP_TYPE_NOP:
				if (rz_analysis_block_relocate(bb, at + op.size, bb->size)) {
					addr = at + op.size;
					fcn->addr = addr;
					goto repeat;
				}
			}
		}

		if (op.hint.new_bits) {
			rz_analysis_hint_set_bits(analysis, op.jump, op.hint.new_bits);
		}
		if (idx > 0 && !overlapped) {
			bbg = bbget(analysis, at, can_jmpmid);
			if (bbg && bbg != bb) {
				bb->jump = at;
				if (can_jmpmid) {
					// This happens when we purposefully walked over another block and overlapped it
					// and now we hit an offset where the instructions match again.
					// So we need to split the overwalked block.
					RzAnalysisBlock *split = rz_analysis_block_split(bbg, at);
					rz_analysis_block_unref(split);
				}
				overlapped = true;
				RZ_LOG_DEBUG("Overlapped at 0x%08" PFMT64x "\n", at);
			}
		}
		if (!overlapped) {
			ut64 newbbsize = bb->size + oplen;
			if (newbbsize > MAX_FCN_SIZE) {
				gotoBeach(RZ_ANALYSIS_RET_ERROR);
			}
			bb->ninstr++;
			rz_analysis_block_set_op_offset(bb, bb->ninstr - 1, at - bb->addr);
			rz_analysis_block_set_size(bb, newbbsize);
			fcn->ninstr++;
		}
		if (analysis->opt.trycatch) {
			const char *name = analysis->coreb.getName(analysis->coreb.core, at);
			if (name) {
				if (rz_str_startswith(name, "try.") && rz_str_endswith(name, ".from")) {
					char *handle = rz_str_dup(name);
					// handle = rz_str_replace (handle, ".from", ".to", 0);
					ut64 from_addr = analysis->coreb.numGet(analysis->coreb.core, handle);
					handle = rz_str_replace(handle, ".from", ".catch", 0);
					ut64 handle_addr = analysis->coreb.numGet(analysis->coreb.core, handle);
					handle = rz_str_replace(handle, ".catch", ".filter", 0);
					ut64 filter_addr = analysis->coreb.numGet(analysis->coreb.core, handle);
					if (filter_addr) {
						rz_analysis_xrefs_set(analysis, op.addr, filter_addr, RZ_ANALYSIS_XREF_TYPE_CALL);
					}
					bb->jump = at + oplen;
					if (from_addr != bb->addr) {
						bb->fail = handle_addr;
						ret = analyze_function_locally(analysis, fcn, handle_addr);
						if (bb->size == 0) {
							rz_analysis_function_remove_block(fcn, bb);
						}
						rz_analysis_block_update_hash(bb);
						rz_analysis_block_unref(bb);
						bb = fcn_append_basic_block(analysis, fcn, bb->jump);
						if (!bb) {
							gotoBeach(RZ_ANALYSIS_RET_ERROR);
						}
					}
				}
			}
		}
		idx += oplen;
		delay.un_idx = idx;
		if (analysis->opt.delay && op.delay > 0 && !delay.pending) {
			// Handle first pass through a branch delay jump:
			// Come back and handle the current instruction later.
			// Save the location of it in `delay.idx`
			// note, we have still increased size of basic block
			// (and function)
			RZ_LOG_DEBUG("Enter branch delay at 0x%08" PFMT64x ". bb->sz=%" PFMT64u "\n", at - oplen, bb->size);
			delay.idx = idx - oplen;
			delay.cnt = op.delay;
			delay.pending = 1; // we need this in case the actual idx is zero...
			delay.adjust = !overlapped; // adjustment is required later to avoid double count
			continue;
		}

		if (delay.cnt > 0) {
			// if we had passed a branch delay instruction, keep
			// track of how many still to process.
			delay.cnt--;
			if (!delay.cnt) {
				RZ_LOG_DEBUG("Last branch delayed opcode at 0x%08" PFMT64x ". bb->sz=%" PFMT64u "\n", addr + idx - oplen, bb->size);
				delay.after = idx;
				idx = delay.idx;
				// At this point, we are still looking at the
				// last instruction in the branch delay group.
				// Next time, we will again be looking
				// at the original instruction that entered
				// the branch delay.
			}
		} else if (op.delay > 0 && delay.pending) {
			RZ_LOG_DEBUG("Revisit branch delay jump at 0x%08" PFMT64x ". bb->sz=%" PFMT64u "\n", addr + idx - oplen, bb->size);
			// This is the second pass of the branch delaying opcode
			// But we also already counted this instruction in the
			// size of the current basic block, so we need to fix that
			if (delay.adjust) {
				rz_analysis_block_set_size(bb, (ut64)addrbytes * (ut64)delay.after);
				fcn->ninstr--;
				RZ_LOG_DEBUG("Correct for branch delay @ 0x%08" PFMT64x " bb.addr=0x%08" PFMT64x " corrected.bb=%" PFMT64u " f.uncorr=%" PFMT64u "\n",
					addr + idx - oplen, bb->addr, bb->size, rz_analysis_function_linear_size(fcn));
			}
			// Next time, we go to the opcode after the delay count
			// Take care not to use this below, use delay.un_idx instead ...
			idx = delay.after;
			delay.pending = delay.after = delay.idx = delay.adjust = 0;
		}
		// Note: if we got two branch delay instructions in a row due to an
		// compiler bug or junk or something it wont get treated as a delay
		if (analysis->opt.vars && !varset) {
			rz_analysis_extract_vars(analysis, fcn, &op, sp);
		}
		if (has_stack_regs && arch_destroys_dst) {
			if (op_is_set_bp(&op, bp_reg, sp_reg) && op.src[1]) {
				switch (op.type & RZ_ANALYSIS_OP_TYPE_MASK) {
				case RZ_ANALYSIS_OP_TYPE_ADD:
					fcn->bp_off = -sp - op.src[1]->imm;
					break;
				case RZ_ANALYSIS_OP_TYPE_SUB:
					fcn->bp_off = -sp + op.src[1]->imm;
					break;
				}
			}
		}
		sp = rz_analysis_op_apply_sp_effect(&op, sp);
		fcn->stack = -sp;
		if (-sp > fcn->maxstack) {
			fcn->maxstack = -sp;
		}
		if (!overlapped) {
			rz_analysis_block_set_op_sp_delta(bb, bb->ninstr - 1, sp - bb->sp_entry);
		}
		if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
			// swapped parameters
			rz_analysis_xrefs_set(analysis, op.addr, op.ptr, RZ_ANALYSIS_XREF_TYPE_DATA);
		}
		analyze_retpoline(analysis, &op);

		switch (op.type & RZ_ANALYSIS_OP_TYPE_MASK) {
		case RZ_ANALYSIS_OP_TYPE_CMOV:
		case RZ_ANALYSIS_OP_TYPE_MOV:
			last_is_reg_mov_lea = false;
			if (is_arm) { // mov lr, pc
				const char *esil = rz_strbuf_get(&op.esil);
				if (!rz_str_cmp(esil, "pc,lr,=", -1)) {
					last_is_mov_lr_pc = true;
				}
			}
			if (has_stack_regs && op_is_set_bp(&op, bp_reg, sp_reg)) {
				fcn->bp_off = -sp;
			}
			// Is this a mov of immediate value into a register?
			if (op.dst && op.dst->reg && op.dst->reg->name && op.val > 0 && op.val != UT64_MAX) {
				free(last_reg_mov_lea_name);
				if ((last_reg_mov_lea_name = rz_str_dup(op.dst->reg->name))) {
					last_reg_mov_lea_val = op.val;
					last_is_reg_mov_lea = true;
				}
			}
			// skip mov reg, reg
			if (analysis->opt.jmptbl && op.scale && op.ireg) {
				movdisp = op.disp;
				movscale = op.scale;
				if (op.src[0] && op.src[0]->reg) {
					free(movbasereg);
					movbasereg = rz_str_dup(op.src[0]->reg->name);
				} else {
					RZ_FREE(movbasereg);
				}
			}
			if (analysis->opt.hpskip && regs_exist(op.src[0], op.dst) && !strcmp(op.src[0]->reg->name, op.dst->reg->name)) {
				skip_ret = skip_hp(analysis, fcn, &op, bb, addr, tmp_buf, oplen, delay.un_idx, &idx);
				if (skip_ret == 1) {
					goto repeat;
				}
				if (skip_ret == 2) {
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_LEA:
			last_is_reg_mov_lea = false;
			// if first byte in op.ptr is 0xff, then set leaddr assuming its a jumptable
			if (op.ptr != UT64_MAX) {
				leaddr_pair *pair = RZ_NEW(leaddr_pair);
				if (!pair) {
					RZ_LOG_ERROR("Cannot allocate pair<reg, addr> structure\n");
					gotoBeach(RZ_ANALYSIS_RET_ERROR);
				}
				pair->op_addr = op.addr;
				pair->leaddr = op.ptr; // XXX movdisp is dupped but seems to be trashed sometimes(?), better track leaddr separately
				pair->reg = op.reg
					? rz_str_dup(op.reg)
					: op.dst && op.dst->reg
					? rz_str_dup(op.dst->reg->name)
					: NULL;
				rz_list_append(analysis->leaddrs, pair);
			}
			if (has_stack_regs && op_is_set_bp(&op, bp_reg, sp_reg)) {
				fcn->bp_off = -sp - op.src[0]->delta;
			}
			if (op.dst && op.dst->reg && op.dst->reg->name && op.ptr > 0 && op.ptr != UT64_MAX) {
				free(last_reg_mov_lea_name);
				if ((last_reg_mov_lea_name = rz_str_dup(op.dst->reg->name))) {
					last_reg_mov_lea_val = op.ptr;
					last_is_reg_mov_lea = true;
				}
			}
			// skip lea reg,[reg]
			if (analysis->opt.hpskip && regs_exist(op.src[0], op.dst) && !strcmp(op.src[0]->reg->name, op.dst->reg->name)) {
				skip_ret = skip_hp(analysis, fcn, &op, bb, at, tmp_buf, oplen, delay.un_idx, &idx);
				if (skip_ret == 1) {
					goto repeat;
				}
				if (skip_ret == 2) {
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}
			if (analysis->opt.jmptbl) {
				RzAnalysisOp jmp_aop = { 0 };
				ut64 jmptbl_addr = op.ptr;
				ut64 casetbl_addr = op.ptr;
				if (is_delta_pointer_table(&read_ahead_cache, analysis, op.addr, op.ptr, &jmptbl_addr, &casetbl_addr, &jmp_aop)) {
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
						.jmptbl_off = op.ptr,
						.sp = sp,
						.tasks = tasks
					};
					if (rz_analysis_get_jmptbl_info(analysis, fcn, bb, jmp_aop.addr, &params) || rz_analysis_get_delta_jmptbl_info(analysis, fcn, jmp_aop.addr, op.addr, &params)) {
						ret = casetbl_addr == op.ptr
							? rz_analysis_walkthrough_jmptbl(analysis, fcn, bb, &params)
							: rz_analysis_walkthrough_casetbl(analysis, fcn, bb, &params);
						if (ret) {
							analysis->lea_jmptbl_ip = jmp_aop.addr;
						}
					}
				}
				rz_analysis_op_fini(&jmp_aop);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_LOAD:
			if (analysis->opt.loads) {
				if (analysis->iob.is_valid_offset(analysis->iob.io, op.ptr, 0)) {
					rz_meta_set(analysis, RZ_META_TYPE_DATA, op.ptr, 4, "");
				}
			}
			break;
			// Case of valid but unused "add [rax], al"
		case RZ_ANALYSIS_OP_TYPE_ADD:
			if (is_arm && analysis->bits == 32) {
				if (!memcmp(buf, "\x00\xe0\x8f\xe2", 4)) {
					// TODO: support different values, not just 0
					// add lr, pc, 0 //
					last_is_add_lr_pc = true;
				}
			}
			if (analysis->opt.ijmp) {
				if ((op.size + 4 <= bytes_read) && !memcmp(buf + op.size, "\x00\x00\x00\x00", 4)) {
					rz_analysis_block_set_size(bb, bb->size - oplen);
					op.type = RZ_ANALYSIS_OP_TYPE_RET;
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_ILL:
			gotoBeach(RZ_ANALYSIS_RET_END);
		case RZ_ANALYSIS_OP_TYPE_TRAP:
			if (analysis->opt.aftertrap) {
				continue;
			}
			gotoBeach(RZ_ANALYSIS_RET_END);
		case RZ_ANALYSIS_OP_TYPE_NOP:
			// do nothing, because the nopskip goes before this switch
			break;
		case RZ_ANALYSIS_OP_TYPE_JMP:
			if (op.jump == UT64_MAX) {
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			{
				RzFlagItem *fi = analysis->flb.get_at(analysis->flb.f, op.jump, false);
				if (fi && strstr(fi->name, "imp.")) {
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}
			if (rz_cons_is_breaked()) {
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			if (analysis->opt.jmpref) {
				(void)rz_analysis_xrefs_set(analysis, op.addr, op.jump, RZ_ANALYSIS_XREF_TYPE_CODE);
			}
			if (!analysis->opt.jmpabove && (op.jump < fcn->addr)) {
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			if (rz_analysis_noreturn_at(analysis, op.jump)) {
				if (continue_after_jump && is_hexagon) {
					rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.jump, sp);
					rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.addr + op.size, sp);
					if (!overlapped) {
						set_bb_branches(bb, op.jump, op.addr + op.size);
					}
					gotoBeach(RZ_ANALYSIS_RET_BRANCH);
				}
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			{
				bool must_eob = true;
				RzIOMap *map = analysis->iob.map_get(analysis->iob.io, addr);
				if (map) {
					must_eob = (op.jump < map->itv.addr || op.jump >= map->itv.addr + map->itv.size);
				}
				if (must_eob) {
					if (continue_after_jump && is_hexagon) {
						rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.jump, sp);
						rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.addr + op.size, sp);
						if (!overlapped) {
							set_bb_branches(bb, op.jump, op.addr + op.size);
						}
						gotoBeach(RZ_ANALYSIS_RET_BRANCH);
					}
					op.jump = UT64_MAX;
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}
			if (!overlapped) {
				set_bb_branches(bb, op.jump, UT64_MAX);
			}
			rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.jump, sp);
			if (continue_after_jump && (is_hexagon || (is_dalvik && op.cond == RZ_TYPE_COND_EXCEPTION))) {
				rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.addr + op.size, sp);
				gotoBeach(RZ_ANALYSIS_RET_BRANCH);
			}
			int tc = analysis->opt.tailcall;
			if (tc) {
				int diff = op.jump - op.addr;
				if (tc < 0) {
					ut8 buf[32];
					(void)analysis->iob.read_at(analysis->iob.io, op.jump, (ut8 *)buf, sizeof(buf));
					if (rz_analysis_is_prelude(analysis, buf, sizeof(buf))) {
						rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.jump, sp);
					}
				} else if (RZ_ABS(diff) > tc) {
					(void)rz_analysis_xrefs_set(analysis, op.addr, op.jump, RZ_ANALYSIS_XREF_TYPE_CALL);
					rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.jump, sp);
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}
			goto beach;
			break;
		case RZ_ANALYSIS_OP_TYPE_SUB:
			if (op.val != UT64_MAX && op.val > 0 && op.val < analysis->opt.jmptbl_maxcount) {
				// if register is not stack
				analysis->cmpval = op.val;
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_CMP: {
			ut64 val = is_x86 ? op.val : op.ptr;
			if (val) {
				if (val < analysis->opt.jmptbl_maxcount) {
					analysis->cmpval = val;
				}
				bb->cmpval = val;
				bb->cmpreg = op.reg;
				rz_analysis_cond_free(bb->cond);
				bb->cond = rz_analysis_cond_new_from_op(&op);
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_MCJMP:
		case RZ_ANALYSIS_OP_TYPE_RCJMP:
		case RZ_ANALYSIS_OP_TYPE_UCJMP:
			if (op.prefix & RZ_ANALYSIS_OP_PREFIX_HWLOOP_END) {
				if (op.jump != 0) {
					rz_analysis_xrefs_set(analysis, op.addr, op.jump, RZ_ANALYSIS_XREF_TYPE_CODE);
				}
				if (op.fail != 0) {
					rz_analysis_xrefs_set(analysis, op.addr, op.fail, RZ_ANALYSIS_XREF_TYPE_CODE);
				}
				if (continue_after_jump) {
					rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.addr + op.size, sp);
				}
				if (!overlapped) {
					// If it is an endloop01 instruction the jump to the inner loop is not added yet.
					set_bb_branches(bb, op.jump, op.addr + op.size);
				}
				gotoBeach(RZ_ANALYSIS_RET_BRANCH);
			}
			if (analysis->opt.cjmpref) {
				rz_analysis_xrefs_set(analysis, op.addr, op.jump, RZ_ANALYSIS_XREF_TYPE_CODE);
				if (is_hexagon) {
					rz_analysis_xrefs_set(analysis, op.addr, op.fail, RZ_ANALYSIS_XREF_TYPE_CODE);
				}
			}
			if (!overlapped) {
				set_bb_branches(bb, op.jump, op.fail);
			}
			if (bb->cond) {
				bb->cond->type = op.cond;
			}
			if (analysis->opt.jmptbl) {
				if (op.ptr != UT64_MAX) {
					if (analysis->cmpval != UT64_MAX && op.fail != UT64_MAX && (op.reg || op.ireg)) {
						RzAnalysisJmpTableParams params = {
							.jmp_address = op.addr,
							.case_shift = 0,
							.jmptbl_loc = op.ptr,
							.casetbl_loc = UT64_MAX,
							.entry_size = analysis->bits >> 3,
							.table_count = analysis->cmpval + 1,
							.jmptbl_off = op.ptr,
							.default_case = op.fail,
							.sp = sp,
							.tasks = tasks
						};
						if (op.ireg) {
							rz_analysis_walkthrough_jmptbl(analysis, fcn, bb, &params);
						} else if (RZ_STR_EQ(analysis->arch_target->arch, "arm")) {
							rz_analysis_walkthrough_arm_jmptbl_style(analysis, fcn, bb, &params);
						}
						// check if op.jump and op.fail contain jump table location
						// clear jump address, because it's jump table location
						if (op.jump == op.ptr) {
							op.jump = UT64_MAX;
						} else if (op.fail == op.ptr) {
							op.fail = UT64_MAX;
						}
						analysis->cmpval = UT64_MAX;
					}
				}
			}
			rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.fail, sp);
			rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.jump, sp);
			if (continue_after_jump && is_hexagon) {
				if (op.type == RZ_ANALYSIS_OP_TYPE_RCJMP) {
					break;
				}
				rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.addr + op.size, sp);
				gotoBeach(RZ_ANALYSIS_RET_BRANCH);
			}
			if (!continue_after_jump) {
				if (op.jump < fcn->addr) {
					if (!overlapped) {
						bb->jump = op.jump;
						bb->fail = UT64_MAX;
					}
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}

			// XXX breaks mips analysis too !op.delay
			// this will be all x86, arm (at least)
			// without which the analysis is really slow,
			// presumably because each opcode would get revisited
			// (and already covered by a bb) many times
			if (!is_dalvik) {
				goto beach;
			}
			// For some reason, branch delayed code (MIPS) needs to continue
			break;
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_ICALL:
		case RZ_ANALYSIS_OP_TYPE_IRCALL:
			/* call [dst] */
			// XXX: this is TYPE_MCALL or indirect-call
			(void)rz_analysis_xrefs_set(analysis, op.addr, op.ptr, RZ_ANALYSIS_XREF_TYPE_CALL);

			if (rz_analysis_noreturn_at(analysis, op.ptr)) {
				RzAnalysisFunction *f = rz_analysis_get_function_at(analysis, op.ptr);
				if (f) {
					f->is_noreturn = true;
				}
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_CCALL:
		case RZ_ANALYSIS_OP_TYPE_CALL:
			/* call dst */
			(void)rz_analysis_xrefs_set(analysis, op.addr, op.jump, RZ_ANALYSIS_XREF_TYPE_CALL);

			if (rz_analysis_noreturn_at(analysis, op.jump)) {
				RzAnalysisFunction *f = rz_analysis_get_function_at(analysis, op.jump);
				if (f) {
					f->is_noreturn = true;
				}
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_UJMP:
		case RZ_ANALYSIS_OP_TYPE_RJMP:
			if (is_hexagon) {
				if (op.analysis_vals[0].plugin_specific == 31) {
					// jumpr Rs instruction which uses R31.
					// This is a return, but not typed as such.
					gotoBeach(RZ_ANALYSIS_RET_END);
				} else {
					// Ignore
					break;
				}
			} else if (is_arm && analysis->bits == 32 && last_is_mov_lr_pc) {
				break;
			} else if (is_arm && analysis->bits == 32 && last_is_add_lr_pc) {
				op.type = RZ_ANALYSIS_OP_TYPE_CALL;
				op.fail = op.addr + 4;
				break;
			}
			/* fall through */
		case RZ_ANALYSIS_OP_TYPE_MJMP:
		case RZ_ANALYSIS_OP_TYPE_IJMP:
		case RZ_ANALYSIS_OP_TYPE_IRJMP:
			// if the next instruction is a symbol
			if (analysis->opt.ijmp && isSymbolNextInstruction(analysis, &op)) {
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			// switch statement
			if (analysis->opt.jmptbl && analysis->lea_jmptbl_ip != op.addr) {
				RzAnalysisJmpTableParams params = {
					.jmp_address = op.addr,
					.entry_size = analysis->bits >> 3,
					.jmptbl_loc = op.ptr,
					.jmptbl_off = op.ptr,
					.sp = sp,
					.tasks = tasks
				};
				// op.ireg since rip relative addressing produces way too many false positives otherwise
				// op.ireg is 0 for rip relative, "rax", etc otherwise
				if (op.ptr != UT64_MAX && op.ireg) { // direct jump
					if (rz_analysis_get_jmptbl_info(analysis, fcn, bb, op.addr, &params)) {
						bool case_table = false;
						RzAnalysisOp prev_op;
						analysis->iob.read_at(analysis->iob.io, op.addr - op.size, buf, sizeof(buf));
						rz_analysis_op_init(&prev_op);
						if (rz_analysis_op(analysis, &prev_op, op.addr - op.size, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_VAL) > 0) {
							bool prev_op_has_dst_name = prev_op.dst && prev_op.dst->reg && prev_op.dst->reg->name;
							bool op_has_src_name = op.src[0] && op.src[0]->reg && op.src[0]->reg->name;
							bool same_reg = (op.ireg && prev_op_has_dst_name && !strcmp(op.ireg, prev_op.dst->reg->name)) || (op_has_src_name && prev_op_has_dst_name && !strcmp(op.src[0]->reg->name, prev_op.dst->reg->name));
							if (prev_op.type == RZ_ANALYSIS_OP_TYPE_MOV && prev_op.disp && prev_op.disp != UT64_MAX && same_reg) {
								//	movzx reg, byte [reg + case_table]
								//	jmp dword [reg*4 + jump_table]
								params.casetbl_loc = prev_op.disp;
								if (rz_analysis_walkthrough_casetbl(analysis, fcn, bb, &params)) {
									ret = case_table = true;
								}
							}
						}
						rz_analysis_op_fini(&prev_op);
						if (!case_table) {
							ret = rz_analysis_walkthrough_jmptbl(analysis, fcn, bb, &params);
						}
					}
				} else if (op.ptr != UT64_MAX && op.reg) { // direct jump
					if (rz_analysis_get_jmptbl_info(analysis, fcn, bb, op.addr, &params)) {
						ret = rz_analysis_walkthrough_jmptbl(analysis, fcn, bb, &params);
					}
				} else if (movdisp != UT64_MAX) {
					ut64 lea_op_off = UT64_MAX;
					RzListIter *iter;
					leaddr_pair *pair;
					params.jmptbl_off = 0;
					if (movbasereg) {
						// find nearest candidate leaddr before op.addr
						rz_list_foreach_prev(analysis->leaddrs, iter, pair) {
							if (pair->op_addr >= op.addr) {
								continue;
							}
							if ((lea_op_off == UT64_MAX || lea_op_off > op.addr - pair->op_addr) && pair->reg && !strcmp(movbasereg, pair->reg)) {
								lea_op_off = op.addr - pair->op_addr;
								params.jmptbl_off = pair->leaddr;
							}
						}
					}
					if (!rz_analysis_get_jmptbl_info(analysis, fcn, bb, op.addr, &params)) {
						params.table_count = analysis->cmpval + 1;
						params.default_case = -1;
					}
					params.jmptbl_loc = params.jmptbl_off + movdisp;
					params.entry_size = movscale;
					ret = rz_analysis_walkthrough_jmptbl(analysis, fcn, bb, &params);
					analysis->cmpval = UT64_MAX;
				} else if (is_arm) {
					params.jmptbl_loc = op.addr + op.size;
					params.jmptbl_off = op.addr + 4;
					params.default_case = UT64_MAX;
					if (op.ptrsize == 1) { // TBB
						ut64 pred_cmpval = try_get_cmpval_from_parents(analysis, fcn, bb, op.ireg);
						params.table_count = 0;
						if (pred_cmpval != UT64_MAX) {
							params.table_count += pred_cmpval;
						} else {
							params.table_count += analysis->cmpval;
						}
						params.entry_size = 1;
						ret = rz_analysis_walkthrough_jmptbl(analysis, fcn, bb, &params);
						// skip inlined jumptable
						idx += params.table_count;
					} else if (op.ptrsize == 2) { // LDRH on thumb/arm
						ut64 pred_cmpval = try_get_cmpval_from_parents(analysis, fcn, bb, op.ireg);
						params.table_count = 1;
						if (pred_cmpval != UT64_MAX) {
							params.table_count += pred_cmpval;
						} else {
							params.table_count += analysis->cmpval;
						}
						params.entry_size = 2;
						ret = rz_analysis_walkthrough_jmptbl(analysis, fcn, bb, &params);
						// skip inlined jumptable
						idx += (params.table_count * 2);
					}
				}
			}
			if (analysis->lea_jmptbl_ip == op.addr) {
				analysis->lea_jmptbl_ip = UT64_MAX;
			}
			if (analysis->opt.ijmp) {
				if (continue_after_jump) {
					rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.fail, sp);
					rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.jump, sp);
					if (overlapped) {
						goto analyzeopfinish;
					}
				}
				if (rz_analysis_noreturn_at(analysis, op.jump) || op.eob) {
					goto analyzeopfinish;
				}
			} else {
			analyzeopfinish:
				if (op.type == RZ_ANALYSIS_OP_TYPE_RJMP) {
					gotoBeach(RZ_ANALYSIS_RET_NOP);
				} else {
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_PUSH:
			last_is_push = true;
			last_push_addr = op.val;
			if (analysis->iob.is_valid_offset(analysis->iob.io, last_push_addr, 1)) {
				(void)rz_analysis_xrefs_set(analysis, op.addr, last_push_addr, RZ_ANALYSIS_XREF_TYPE_DATA);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_UPUSH:
			if ((op.type & RZ_ANALYSIS_OP_TYPE_REG) && last_is_reg_mov_lea && op.src[0] && op.src[0]->reg && op.src[0]->reg->name && !strcmp(op.src[0]->reg->name, last_reg_mov_lea_name)) {
				last_is_push = true;
				last_push_addr = last_reg_mov_lea_val;
				if (analysis->iob.is_valid_offset(analysis->iob.io, last_push_addr, 1)) {
					(void)rz_analysis_xrefs_set(analysis, op.addr, last_push_addr, RZ_ANALYSIS_XREF_TYPE_DATA);
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_RET:
			if (op.family == RZ_ANALYSIS_OP_FAMILY_PRIV) {
				fcn->type = RZ_ANALYSIS_FCN_TYPE_INT;
			}
			if (last_is_push && analysis->opt.pushret) {
				op.type = RZ_ANALYSIS_OP_TYPE_JMP;
				op.jump = last_push_addr;
				bb->jump = op.jump;
				rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.jump, sp);
				goto beach;
			}
			if (op.cond == RZ_TYPE_COND_AL) {
				RZ_LOG_DEBUG("RET 0x%08" PFMT64x ". overlap=%s %" PFMT64u " %" PFMT64u "\n",
					addr + delay.un_idx - oplen, rz_str_bool(overlapped),
					bb->size, rz_analysis_function_linear_size(fcn));
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_CRET:
			if (continue_after_jump && is_hexagon) {
				rz_analysis_task_item_new(analysis, tasks, fcn, NULL, op.addr + op.size, sp);
				set_bb_branches(bb, op.addr + op.size, UT64_MAX);
				gotoBeach(RZ_ANALYSIS_RET_COND);
			}
		}
		if (op.type != RZ_ANALYSIS_OP_TYPE_MOV && op.type != RZ_ANALYSIS_OP_TYPE_CMOV && op.type != RZ_ANALYSIS_OP_TYPE_LEA) {
			last_is_reg_mov_lea = false;
		}
		if (op.type != RZ_ANALYSIS_OP_TYPE_PUSH && op.type != RZ_ANALYSIS_OP_TYPE_RPUSH) {
			last_is_push = false;
		}
		if (is_arm && op.type != RZ_ANALYSIS_OP_TYPE_MOV) {
			last_is_mov_lr_pc = false;
		}
		if (has_variadic_reg && !fcn->is_variadic) {
			variadic_reg = rz_reg_get(analysis->reg, "rax", RZ_REG_TYPE_GPR);
			bool dst_is_variadic = op.dst && op.dst->reg && variadic_reg && op.dst->reg->offset == variadic_reg->offset;
			bool op_is_cmp = (op.type == RZ_ANALYSIS_OP_TYPE_CMP) || op.type == RZ_ANALYSIS_OP_TYPE_ACMP;
			if (dst_is_variadic && !op_is_cmp) {
				has_variadic_reg = false;
			} else if (op_is_cmp) {
				if (op.src[0] && op.src[0]->reg && (op.dst->reg == op.src[0]->reg) && dst_is_variadic) {
					fcn->is_variadic = true;
				}
			}
		}
	}
beach:
	rz_analysis_op_fini(&op);
	RZ_FREE(last_reg_mov_lea_name);
	if (bb) {
		if (bb->size) {
			rz_analysis_block_update_hash(bb);
		} else {
			rz_analysis_function_remove_block(fcn, bb);
		}
		rz_analysis_block_unref(bb);
	}
	free(movbasereg);
	return ret;
}

/**
 * \brief Adds a new task item to the `tasks` parameter.
 *
 * Used to create a new item to the `tasks` parameter
 * that can be worked on later by the `rz_analysis_run_tasks` function.
 *
 * \param analysis Pointer to RzAnalysis instance.
 * \param tasks Pointer to RzVector to add a new RzAnalysisTaskItem to.
 * \param fcn Pointer to RzAnalysisFunction in which analysis will be performed on.
 * \param block Pointer to RzAnalysisBlock in which analysis will be performed on. If null, analysis will take care of block creation.
 * \param address Address where analysis will start from
 * \param sp Tracked stack pointer value at \p address
 */
RZ_API bool rz_analysis_task_item_new(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzVector /*<RzAnalysisTaskItem>*/ *tasks, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NULLABLE RzAnalysisBlock *block, ut64 address, RzStackAddr sp) {
	rz_return_val_if_fail(analysis && tasks && fcn, false);
	RzAnalysisTaskItem item = { fcn, block, sp, address };
	RzAnalysisTaskItem *it;
	rz_vector_foreach (tasks, it) {
		if (item.start_address == it->start_address) {
			return true;
		}
	}
	return rz_vector_push(tasks, &item);
}

/**
 * \brief Runs analysis on the task items.
 *
 * Runs control-flow and variable usage analysis on each of the task items until tasks vector becomes empty.
 * Items are removed from the tasks vector as they are processed.
 * Items are added to the tasks vector as new basic blocks are found to be analyzed.
 *
 * \param tasks Pointer to RzVector of RzAnalysisTaskItem to be performed analysis on.
 */
RZ_API int rz_analysis_run_tasks(RZ_NONNULL RzVector /*<RzAnalysisTaskItem>*/ *tasks) {
	rz_return_val_if_fail(tasks, RZ_ANALYSIS_RET_ERROR);
	int ret = RZ_ANALYSIS_RET_ERROR;
	while (!rz_vector_empty(tasks)) {
		RzAnalysisTaskItem item;
		rz_vector_pop(tasks, &item);
		int r = run_basic_block_analysis(&item, tasks);
		switch (r) {
		case RZ_ANALYSIS_RET_BRANCH:
		case RZ_ANALYSIS_RET_COND:
			continue;
		case RZ_ANALYSIS_RET_NOP:
		case RZ_ANALYSIS_RET_ERROR:
			if (ret != RZ_ANALYSIS_RET_END) {
				ret = r;
			}
			break;
		case RZ_ANALYSIS_RET_END:
		default:
			ret = r;
			break;
		}
		if (rz_cons_is_breaked()) {
			break;
		}
	}
	return ret;
}

RZ_API bool rz_analysis_check_fcn(RzAnalysis *analysis, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high) {
	RzAnalysisOp op = { 0 };
	int i, oplen, opcnt = 0, pushcnt = 0, movcnt = 0, brcnt = 0;
	if (rz_analysis_is_prelude(analysis, buf, bufsz)) {
		return true;
	}
	for (i = 0; i < bufsz && opcnt < 10; i += oplen, opcnt++) {
		rz_analysis_op_init(&op);
		if ((oplen = rz_analysis_op(analysis, &op, addr + i, buf + i, bufsz - i, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT)) < 1) {
			rz_analysis_op_fini(&op);
			return false;
		}
		switch (op.type) {
		case RZ_ANALYSIS_OP_TYPE_PUSH:
		case RZ_ANALYSIS_OP_TYPE_UPUSH:
		case RZ_ANALYSIS_OP_TYPE_RPUSH:
			pushcnt++;
			break;
		case RZ_ANALYSIS_OP_TYPE_MOV:
		case RZ_ANALYSIS_OP_TYPE_CMOV:
			movcnt++;
			break;
		case RZ_ANALYSIS_OP_TYPE_JMP:
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_CALL:
			if (op.jump < low || op.jump >= high) {
				rz_analysis_op_fini(&op);
				return false;
			}
			brcnt++;
			break;
		case RZ_ANALYSIS_OP_TYPE_UNK:
			rz_analysis_op_fini(&op);
			return false;
		default:
			break;
		}
		rz_analysis_op_fini(&op);
	}
	return (pushcnt + movcnt + brcnt > 5);
}

RZ_API void rz_analysis_trim_jmprefs(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzAnalysisXRef *xref;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	RzListIter *iter;
	const bool is_x86 = analysis->cur->arch && !strcmp(analysis->cur->arch, "x86"); // HACK

	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_CODE && rz_analysis_function_contains(fcn, xref->to) && (!is_x86 || !rz_analysis_function_contains(fcn, xref->from))) {
			rz_analysis_xrefs_deln(analysis, xref->from, xref->to, xref->type);
		}
	}
	rz_list_free(xrefs);
}

RZ_API void rz_analysis_del_jmprefs(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzAnalysisXRef *xref;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	RzListIter *iter;

	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
			rz_analysis_xrefs_deln(analysis, xref->from, xref->to, xref->type);
		}
	}
	rz_list_free(xrefs);
}

/* Does NOT invalidate read-ahead cache. */
RZ_API int rz_analysis_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr, ut64 len, int reftype) {
	RzPVector *metas = rz_meta_get_all_in(analysis, addr, RZ_META_TYPE_ANY);
	void **it;
	rz_pvector_foreach (metas, it) {
		RzAnalysisMetaItem *meta = ((RzIntervalNode *)*it)->data;
		switch (meta->type) {
		case RZ_META_TYPE_DATA:
		case RZ_META_TYPE_STRING:
		case RZ_META_TYPE_FORMAT:
			rz_pvector_free(metas);
			return 0;
		default:
			break;
		}
	}
	rz_pvector_free(metas);
	if (analysis->opt.norevisit) {
		if (!analysis->visited) {
			analysis->visited = rz_set_u_new();
		}
		if (rz_set_u_contains(analysis->visited, addr)) {
			RZ_LOG_DEBUG("rz_analysis_fcn: analysis.norevisit at 0x%08" PFMT64x " %c\n", addr, reftype);
			return RZ_ANALYSIS_RET_END;
		}
		rz_set_u_add(analysis->visited, addr);
	} else {
		if (analysis->visited) {
			rz_set_u_free(analysis->visited);
			analysis->visited = NULL;
		}
	}
	/* defines fcn. or loc. prefix */
	fcn->type = (reftype == RZ_ANALYSIS_XREF_TYPE_CODE) ? RZ_ANALYSIS_FCN_TYPE_LOC : RZ_ANALYSIS_FCN_TYPE_FCN;
	if (fcn->addr == UT64_MAX) {
		fcn->addr = addr;
	}
	fcn->maxstack = 0;
	RzVector tasks;
	rz_vector_init(&tasks, sizeof(RzAnalysisTaskItem), NULL, NULL);
	rz_analysis_task_item_new(analysis, &tasks, fcn, NULL, addr, 0);
	int ret = rz_analysis_run_tasks(&tasks);
	rz_vector_fini(&tasks);
	return ret;
}

// XXX deprecate
RZ_API int rz_analysis_fcn_del_locs(RzAnalysis *analysis, ut64 addr) {
	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn, *f = rz_analysis_get_fcn_in(analysis, addr, RZ_ANALYSIS_FCN_TYPE_ROOT);
	if (!f) {
		return false;
	}
	rz_list_foreach_safe (analysis->fcns, iter, iter2, fcn) {
		if (fcn->type != RZ_ANALYSIS_FCN_TYPE_LOC) {
			continue;
		}
		if (rz_analysis_function_contains(fcn, addr)) {
			rz_analysis_function_delete(fcn);
		}
	}
	rz_analysis_fcn_del(analysis, addr);
	return true;
}

RZ_API int rz_analysis_fcn_del(RzAnalysis *a, ut64 addr) {
	RzAnalysisFunction *fcn;
	RzListIter *iter, *iter_tmp;
	rz_list_foreach_safe (a->fcns, iter, iter_tmp, fcn) {
		RZ_LOG_DEBUG("removing function at %" PFMT64x " %" PFMT64x "\n", fcn->addr, addr);
		if (fcn->addr == addr) {
			rz_analysis_function_delete(fcn);
		}
	}
	return true;
}

RZ_DEPRECATE RZ_API RzAnalysisFunction *rz_analysis_get_fcn_in(RzAnalysis *analysis, ut64 addr, int type) {
	RzList *list = rz_analysis_get_functions_in(analysis, addr);
	RzAnalysisFunction *ret = NULL;
	if (list && !rz_list_empty(list)) {
		if (type == RZ_ANALYSIS_FCN_TYPE_ROOT) {
			RzAnalysisFunction *fcn;
			RzListIter *iter;
			rz_list_foreach (list, iter, fcn) {
				if (fcn->addr == addr) {
					ret = fcn;
					break;
				}
			}
		} else {
			ret = rz_list_first(list);
		}
	}
	rz_list_free(list);
	return ret;
}

RZ_DEPRECATE RZ_API RzAnalysisFunction *rz_analysis_get_fcn_in_bounds(RzAnalysis *analysis, ut64 addr, int type) {
	RzAnalysisFunction *fcn, *ret = NULL;
	RzListIter *iter;
	if (type == RZ_ANALYSIS_FCN_TYPE_ROOT) {
		rz_list_foreach (analysis->fcns, iter, fcn) {
			if (addr == fcn->addr) {
				return fcn;
			}
		}
		return NULL;
	}
	rz_list_foreach (analysis->fcns, iter, fcn) {
		if (!type || (fcn && fcn->type & type)) {
			if (rz_analysis_function_contains(fcn, addr)) {
				return fcn;
			}
		}
	}
	return ret;
}

/**
 * \brief Returns function if exists given the \p name
 */
RZ_API RzAnalysisFunction *rz_analysis_get_function_byname(RzAnalysis *a, const char *name) {
	bool found = false;
	RzAnalysisFunction *f = ht_sp_find(a->ht_name_fun, name, &found);
	if (f && found) {
		return f;
	}
	return NULL;
}

/* rename RzAnalysisFunctionBB.add() */
RZ_API bool rz_analysis_fcn_add_bb(RzAnalysis *a, RzAnalysisFunction *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail) {
	if (size == 0) {
		RZ_LOG_ERROR("Empty basic block at 0x%08" PFMT64x " (not allowed).\n", addr);
		rz_warn_if_reached();
		return false;
	}
	if (size > a->opt.bb_max_size) {
		RZ_LOG_ERROR("Cannot allocate such big bb of %" PFMT64d " bytes at 0x%08" PFMT64x "\n", (st64)size, addr);
		rz_warn_if_reached();
		return false;
	}

	RzAnalysisBlock *block = rz_analysis_get_block_at(a, addr);
	if (block) {
		rz_analysis_delete_block(block);
		block = NULL;
	}

	block = rz_analysis_create_block(a, addr, size);
	if (!block) {
		return false;
	}

	rz_analysis_block_analyze_ops(block);
	rz_analysis_function_add_block(fcn, block);

	block->jump = jump;
	block->fail = fail;
	rz_analysis_block_unref(block);
	return true;
}

/**
 * \brief Returns the amount of loops located in the \p fcn function
 */
RZ_API ut32 rz_analysis_function_loops(RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	ut32 loops = 0;

	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		if (bb->jump != UT64_MAX && bb->jump < bb->addr) {
			loops++;
		}
		if (bb->fail != UT64_MAX && bb->fail < bb->addr) {
			loops++;
		}
	}
	return loops;
}

/**
 * \brief Returns cyclomatic complexity of the function
 *
 * It calculated using this formula:
 *
 * CC = E - N + 2P
 * where
 * E is the number of edges of the graph.
 * N is the number of nodes of the graph.
 * P is the number of connected components (exit nodes).
 *
 */
RZ_API ut32 rz_analysis_function_complexity(RzAnalysisFunction *fcn) {
	RzAnalysis *analysis = fcn->analysis;
	ut32 E = 0, N = 0, P = 0;
	RzAnalysisBlock *bb;

	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		N++; // nodes
		if (!analysis && bb->jump == UT64_MAX && bb->fail != UT64_MAX) {
			RZ_LOG_DEBUG("invalid bb jump/fail pair at 0x%08" PFMT64x " (fcn 0x%08" PFMT64x "\n", bb->addr, fcn->addr);
		}
		if (bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			P++; // exit nodes
		} else {
			E++; // edges
			if (bb->fail != UT64_MAX) {
				E++;
			}
		}
		if (bb->switch_op && bb->switch_op->cases) {
			E += rz_list_length(bb->switch_op->cases);
		}
	}

	return E - N + (2 * P);
}

/**
 * \brief Gets the RzCallable's arg count for the given function
 *
 * Derives the RzCallable type for the given function,
 * saves it if it exists, and returns its arguments count.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API int rz_analysis_function_get_arg_count(RzAnalysis *analysis, RzAnalysisFunction *f) {
	RzCallable *callable = rz_analysis_function_derive_type(analysis, f);
	if (!callable) {
		return -1;
	}
	rz_type_func_save(analysis->typedb, callable);
	return rz_pvector_len(callable->args);
}

// tfj and afsj call this function
RZ_API RZ_OWN char *rz_analysis_function_get_json(RzAnalysisFunction *function) {
	char *tmp = NULL;
	RzAnalysis *a = function->analysis;
	PJ *pj = pj_new();
	char *ret_type_str = NULL;
	RzType *ret_type = rz_type_func_ret(a->typedb, function->name);
	if (ret_type) {
		ret_type_str = rz_type_as_string(a->typedb, ret_type);
	}
	int argc = rz_analysis_function_get_arg_count(a, function);

	pj_o(pj);
	pj_ks(pj, "name", function->name);
	const bool no_return = rz_analysis_noreturn_at_addr(a, function->addr);
	pj_kb(pj, "noreturn", no_return);
	pj_ks(pj, "ret", ret_type_str ? ret_type_str : "void");
	if (function->cc) {
		pj_ks(pj, "cc", function->cc);
	}
	pj_k(pj, "args");
	pj_a(pj);
	for (int i = 0; i < argc; i++) {
		pj_o(pj);
		const char *arg_name = rz_type_func_args_name(a->typedb, function->name, i);
		RzType *arg_type = rz_type_func_args_type(a->typedb, function->name, i);
		tmp = rz_type_as_string(a->typedb, arg_type);
		pj_ks(pj, "name", arg_name);
		pj_ks(pj, "type", tmp);
		free(tmp);
		tmp = rz_str_newf("A%d", i);
		const char *cc_arg = rz_reg_get_name(a->reg, rz_reg_get_name_idx(tmp));
		free(tmp);
		if (cc_arg) {
			pj_ks(pj, "cc", cc_arg);
		}
		pj_end(pj);
	}
	pj_end(pj);
	pj_end(pj);
	free(ret_type_str);
	return pj_drain(pj);
}

/**
 * \brief Returns type signature (prototype) of the function
 *
 * If the type is presented in the type database it uses it,
 * otherwise it tries to derive the type from the analysis data
 */
RZ_API RZ_OWN char *rz_analysis_function_get_signature(RZ_NONNULL RzAnalysisFunction *function) {
	rz_return_val_if_fail(function, NULL);
	RzAnalysis *a = function->analysis;

	RzCallable *callable = rz_analysis_function_derive_type(a, function);
	if (!callable) {
		return NULL;
	}
	char *signature = rz_type_callable_as_string(a->typedb, callable);
	rz_type_callable_free(callable);
	char *result = rz_str_newf("%s;", signature);
	free(signature);
	return result;
}

/**
 * \brief Sets the RzCallable type for the given function
 *
 * Overwrites all arguments, the return type, calling convention and noreturn property of \p f to
 * match the contents of \p callable. This is done according to the calling convention in
 * \p callable, or \p f if it is not defined in \p callable.
 *
 * \param a RzAnalysis instance
 * \param f Function to update
 * \param callable A function type to apply to \p f
 */
RZ_API void rz_analysis_function_set_type(RzAnalysis *a, RZ_NONNULL RzAnalysisFunction *f, RZ_NONNULL RzCallable *callable) {
	rz_return_if_fail(a && f && callable);
	// Set the cc first, it will be used further down.
	if (callable->cc) {
		f->cc = rz_str_constpool_get(&a->constpool, callable->cc);
	}
	// All args will be overwritten
	rz_analysis_function_delete_arg_vars(f);
	RzStackAddr stack_off = rz_type_db_pointer_size(a->typedb) / 8; // return val
	if (f->cc) {
		stack_off += rz_analysis_cc_shadow_store(a, f->cc);
	}
	size_t args_count = rz_pvector_len(callable->args);
	for (size_t index = 0; index < args_count; index++) {
		RzCallableArg *arg = rz_pvector_at(callable->args, index);
		if (!arg || !arg->type) {
			continue;
		}
		RzAnalysisVarStorage stor = { 0 };
		const char *loc = f->cc ? rz_analysis_cc_arg(a, f->cc, index) : "stack";
		if (!loc || rz_str_startswith(loc, "stack")) {
			stor.type = RZ_ANALYSIS_VAR_STORAGE_STACK;
			stor.stack_off = stack_off;
			stack_off += (rz_type_db_get_bitsize(a->typedb, arg->type) + 7) / 8;
		} else {
			stor.type = RZ_ANALYSIS_VAR_STORAGE_REG;
			stor.reg = rz_str_constpool_get(&a->constpool, loc);
		}
		rz_analysis_function_set_var(f, &stor, arg->type, 0, arg->name);
	}
	f->is_noreturn = callable->noret;
	rz_type_free(f->ret_type);
	f->ret_type = callable->ret ? rz_type_clone(callable->ret) : NULL;
}

/**
 * \brief Parses the function type and sets it for the given function
 *
 * Checks if the type is defined already for this function, if yes -
 * it removes the existing one and parses the one defined in the signature.
 * The function type should be valid C syntax supplied with name, like
 * int *func(char arg0, const int *arg1, float foo[]);
 *
 * \param a RzAnalysis instance
 * \param f Function to update
 * \param sig A function type ("signature" or "prototype")
 */
RZ_API bool rz_analysis_function_set_type_str(RzAnalysis *a, RZ_NONNULL RzAnalysisFunction *f, RZ_NONNULL const char *sig) {
	rz_return_val_if_fail(a && f && sig, false);
	char *error_msg = NULL;
	// At first we should check if the type is already presented in the types database
	// and remove it if exists
	if (rz_type_func_exist(a->typedb, f->name)) {
		rz_type_func_delete(a->typedb, f->name);
	}
	// Then we create a new one by parsing the string
	RzType *result = rz_type_parse_string_declaration_single(a->typedb->parser, sig, &error_msg);
	if (!result) {
		if (error_msg) {
			RZ_LOG_ERROR("%s", error_msg);
			free(error_msg);
		}
		RZ_LOG_ERROR("Cannot parse callable type\n");
		return false;
	}
	// Parsed result should be RzCallable
	if (result->kind != RZ_TYPE_KIND_CALLABLE) {
		RZ_LOG_ERROR("Parsed function signature should be RzCallable\n");
		return false;
	}
	if (!result->callable) {
		RZ_LOG_ERROR("Parsed function signature should not be NULL\n");
		return false;
	}
	rz_analysis_function_set_type(a, f, result->callable);
	return true;
}

RZ_API RzAnalysisFunction *rz_analysis_fcn_next(RzAnalysis *analysis, ut64 addr) {
	RzAnalysisFunction *fcni;
	RzListIter *iter;
	RzAnalysisFunction *closer = NULL;
	rz_list_foreach (analysis->fcns, iter, fcni) {
		// if (fcni->addr == addr)
		if (fcni->addr > addr && (!closer || fcni->addr < closer->addr)) {
			closer = fcni;
		}
	}
	return closer;
}

RZ_API ut32 rz_analysis_fcn_count(RzAnalysis *analysis, ut64 from, ut64 to) {
	ut32 n = 0;
	RzAnalysisFunction *fcni;
	RzListIter *iter;
	rz_list_foreach (analysis->fcns, iter, fcni) {
		if (fcni->addr >= from && fcni->addr < to) {
			n++;
		}
	}
	return n;
}

/* return the basic block in fcn found at the given address.
 * NULL is returned if such basic block doesn't exist. */
RZ_API RzAnalysisBlock *rz_analysis_fcn_bbget_in(const RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr) {
	rz_return_val_if_fail(analysis && fcn, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	bool can_jmpmid = false;
	if (analysis->cur->arch) {
		bool is_x86 = !strncmp(analysis->cur->arch, "x86", 3);
		bool is_dalvik = !strncmp(analysis->cur->arch, "dalvik", 6);
		can_jmpmid = analysis->opt.jmpmid && (is_dalvik || is_x86);
	}
	RzAnalysisBlock *bb;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		if (addr >= bb->addr && addr < (bb->addr + bb->size) && (!can_jmpmid || rz_analysis_block_op_starts_at(bb, addr))) {
			return bb;
		}
	}
	return NULL;
}

RZ_API RzAnalysisBlock *rz_analysis_fcn_bbget_at(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr) {
	rz_return_val_if_fail(fcn && addr != UT64_MAX, NULL);
	RzAnalysisBlock *b = rz_analysis_get_block_at(analysis, addr);
	if (b) {
		return b;
	}
	RzAnalysisBlock *bb;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		if (addr == bb->addr) {
			return bb;
		}
	}
	return NULL;
}

// compute the cyclomatic cost
RZ_API ut32 rz_analysis_function_cost(RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	RzAnalysisOp op = { 0 };
	ut32 totalCycles = 0;
	if (!fcn) {
		return 0;
	}
	RzAnalysis *analysis = fcn->analysis;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc(bb->size);
		if (!buf) {
			continue;
		}
		(void)analysis->iob.read_at(analysis->iob.io, bb->addr, (ut8 *)buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			rz_analysis_op_init(&op);
			(void)rz_analysis_op(analysis, &op, at, buf + idx, bb->size - idx, RZ_ANALYSIS_OP_MASK_BASIC);
			if (op.size < 1) {
				op.size = 1;
			}
			idx += op.size;
			at += op.size;
			totalCycles += op.cycles;
			rz_analysis_op_fini(&op);
		}
		free(buf);
	}
	return totalCycles;
}

RZ_API ut32 rz_analysis_function_count_edges(const RzAnalysisFunction *fcn, RZ_NULLABLE int *ebbs) {
	rz_return_val_if_fail(fcn, 0);
	RzAnalysisBlock *bb;
	ut32 edges = 0;
	if (ebbs) {
		*ebbs = 0;
	}
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		if (ebbs && bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			*ebbs = *ebbs + 1;
		} else {
			if (bb->jump != UT64_MAX) {
				edges++;
			}
			if (bb->fail != UT64_MAX) {
				edges++;
			}
		}
	}
	return edges;
}

/**
 * \brief Returns if the function pure - accesses any external resources or not
 */
RZ_API bool rz_analysis_function_purity(RzAnalysisFunction *fcn) {
	if (fcn->has_changed) {
		HtUP *ht = ht_up_new(NULL, NULL);
		if (ht) {
			check_purity(ht, fcn);
			ht_up_free(ht);
		}
	}
	return fcn->is_pure;
}

static bool can_affect_bp(RzAnalysis *analysis, RzAnalysisOp *op) {
	RzAnalysisValue *dst = op->dst;
	RzAnalysisValue *src = op->src[0];
	const char *opdreg = (dst && dst->reg) ? dst->reg->name : NULL;
	const char *opsreg = (src && src->reg) ? src->reg->name : NULL;
	const char *bp_name = analysis->reg->name[RZ_REG_NAME_BP];
	bool is_bp_dst = opdreg && !dst->memref && !strcmp(opdreg, bp_name);
	bool is_bp_src = opsreg && !src->memref && !strcmp(opsreg, bp_name);
	if (op->type == RZ_ANALYSIS_OP_TYPE_XCHG) {
		return is_bp_src || is_bp_dst;
	}
	return is_bp_dst;
}

/*
 * This function checks whether any operation in a given function may change bp (excluding "mov bp, sp"
 * and "pop bp" at the end).
 */
static void __analysis_fcn_check_bp_use(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	if (!fcn) {
		return;
	}
	RzAnalysisOp op = { 0 };
	RzAnalysisBlock *bb;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc(bb->size);
		if (!buf) {
			continue;
		}
		(void)analysis->iob.read_at(analysis->iob.io, bb->addr, (ut8 *)buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			rz_analysis_op_init(&op);
			rz_analysis_op(analysis, &op, at, buf + idx, bb->size - idx, RZ_ANALYSIS_OP_MASK_VAL);
			if (op.size < 1) {
				op.size = 1;
			}
			switch (op.type) {
			case RZ_ANALYSIS_OP_TYPE_MOV:
			case RZ_ANALYSIS_OP_TYPE_LEA:
				if (can_affect_bp(analysis, &op) && op.src[0] && op.src[0]->reg && op.src[0]->reg->name && strcmp(op.src[0]->reg->name, analysis->reg->name[RZ_REG_NAME_SP])) {
					fcn->bp_frame = false;
					rz_analysis_op_fini(&op);
					free(buf);
					return;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_ADD:
			case RZ_ANALYSIS_OP_TYPE_AND:
			case RZ_ANALYSIS_OP_TYPE_CMOV:
			case RZ_ANALYSIS_OP_TYPE_NOT:
			case RZ_ANALYSIS_OP_TYPE_OR:
			case RZ_ANALYSIS_OP_TYPE_ROL:
			case RZ_ANALYSIS_OP_TYPE_ROR:
			case RZ_ANALYSIS_OP_TYPE_SAL:
			case RZ_ANALYSIS_OP_TYPE_SAR:
			case RZ_ANALYSIS_OP_TYPE_SHR:
			case RZ_ANALYSIS_OP_TYPE_SUB:
			case RZ_ANALYSIS_OP_TYPE_XOR:
			case RZ_ANALYSIS_OP_TYPE_SHL:
			case RZ_ANALYSIS_OP_TYPE_XCHG:
				if (can_affect_bp(analysis, &op)) {
					fcn->bp_frame = false;
					rz_analysis_op_fini(&op);
					free(buf);
					return;
				}
				break;
			default:
				break;
			}
			idx += op.size;
			at += op.size;
			rz_analysis_op_fini(&op);
		}
		free(buf);
	}
}

/**
 *  \brief This function checks whether any operation in a given function may change BP
 *
 *  Excludes pattern like "mov bp, sp" and "pop sp, bp" for saving stack pointer value
 */
RZ_API void rz_analysis_function_check_bp_use(RzAnalysisFunction *fcn) {
	rz_return_if_fail(fcn);
	__analysis_fcn_check_bp_use(fcn->analysis, fcn);
}

typedef struct {
	RzAnalysisFunction *fcn;
	HtUP *visited;
} BlockRecurseCtx;

static bool mark_as_visited(RzAnalysisBlock *bb, void *user) {
	BlockRecurseCtx *ctx = user;
	ht_up_insert(ctx->visited, bb->addr, NULL);
	return true;
}

static bool analize_addr_cb(ut64 addr, void *user) {
	BlockRecurseCtx *ctx = user;
	RzAnalysis *analysis = ctx->fcn->analysis;
	RzAnalysisBlock *existing_bb = rz_analysis_get_block_at(analysis, addr);
	if (!existing_bb || !rz_pvector_contains(ctx->fcn->bbs, existing_bb)) {
		size_t old_len = rz_pvector_len(ctx->fcn->bbs);
		analyze_function_locally(ctx->fcn->analysis, ctx->fcn, addr);
		if (old_len != rz_pvector_len(ctx->fcn->bbs)) {
			rz_analysis_block_recurse(rz_analysis_get_block_at(analysis, addr), mark_as_visited, user);
		}
	}
	ht_up_insert(ctx->visited, addr, NULL);
	return true;
}

static bool analize_descendents(RzAnalysisBlock *bb, void *user) {
	return rz_analysis_block_successor_addrs_foreach(bb, analize_addr_cb, user);
}

static void update_vars_analysis(RzAnalysisFunction *fcn, RzAnalysisBlock *block, int align, ut64 from, ut64 to) {
	RzAnalysis *analysis = fcn->analysis;
	ut64 cur_addr;
	int opsz;
	from = align ? from - (from % align) : from;
	to = align ? RZ_ROUND(to, align) : to;
	if (UT64_SUB_OVFCHK(to, from)) {
		return;
	}
	ut64 len = to - from;
	ut8 *buf = malloc(len);
	if (!buf) {
		return;
	}
	if (analysis->iob.read_at(analysis->iob.io, from, buf, len) < len) {
		return;
	}
	RzAnalysisOp op = { 0 };
	for (cur_addr = from; cur_addr < to; cur_addr += opsz, len -= opsz) {
		rz_analysis_op_init(&op);
		int ret = rz_analysis_op(analysis->coreb.core, &op, cur_addr, buf, len, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL);
		if (ret < 1 || op.size < 1) {
			rz_analysis_op_fini(&op);
			break;
		}
		opsz = op.size;
		rz_analysis_extract_vars(analysis, fcn, &op, rz_analysis_block_get_sp_at(block, cur_addr));
		rz_analysis_op_fini(&op);
	}
	free(buf);
}

// Clear function variable acesses inside in a block
static void clear_bb_vars(RzAnalysisFunction *fcn, RzAnalysisBlock *bb, ut64 from, ut64 to) {
	int i;
	if (rz_pvector_empty(&fcn->vars)) {
		return;
	}
	for (i = 0; i < bb->ninstr; i++) {
		const ut64 addr = rz_analysis_block_get_op_addr(bb, i);
		if (addr < from) {
			continue;
		}
		if (addr >= to || addr == UT64_MAX) {
			break;
		}
		RzPVector *vars = rz_analysis_function_get_vars_used_at(fcn, addr);
		if (vars) {
			RzPVector *vars_clone = rz_pvector_clone(vars);
			void **v;
			rz_pvector_foreach (vars_clone, v) {
				rz_analysis_var_remove_access_at((RzAnalysisVar *)*v, addr);
			}
			rz_pvector_clear(vars_clone);
		}
	}
}

static void update_analysis(RzAnalysis *analysis, RzList /*<RzAnalysisFunction *>*/ *fcns, HtUP *reachable) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	bool old_jmpmid = analysis->opt.jmpmid;
	analysis->opt.jmpmid = true;
	rz_list_foreach (fcns, it, fcn) {
		// Recurse through blocks of function, mark reachable,
		// analyze edges that don't have a block
		RzAnalysisBlock *bb = rz_analysis_get_block_at(analysis, fcn->addr);
		if (!bb) {
			analyze_function_locally(analysis, fcn, fcn->addr);
			bb = rz_analysis_get_block_at(analysis, fcn->addr);
			if (!bb) {
				continue;
			}
		}
		HtUP *ht = ht_up_new(NULL, NULL);
		ht_up_insert(ht, bb->addr, NULL);
		BlockRecurseCtx ctx = { fcn, ht };
		rz_analysis_block_recurse(bb, analize_descendents, &ctx);

		// in this loop we remove non-reachable basic blocks and since
		// we modify the pvector size we cannot loop normally.
		size_t count = rz_pvector_len(fcn->bbs);
		for (size_t i = 0; i < count;) {
			bb = (RzAnalysisBlock *)rz_pvector_at(fcn->bbs, i);
			if (ht_up_find_kv(ht, bb->addr, NULL)) {
				i++;
				continue;
			}
			HtUP *o_visited = ht_up_find(reachable, fcn->addr, NULL);
			if (!ht_up_find_kv(o_visited, bb->addr, NULL)) {
				// Avoid removing blocks that were already not reachable
				i++;
				continue;
			}
			fcn->ninstr -= bb->ninstr;
			rz_analysis_function_remove_block(fcn, bb);
			count = rz_pvector_len(fcn->bbs);
		}

		RzPVector *dup_bbs = rz_pvector_clone(fcn->bbs);
		rz_analysis_block_automerge(dup_bbs);
		rz_analysis_function_delete_unused_vars(fcn);
		rz_pvector_free(dup_bbs);
	}
	analysis->opt.jmpmid = old_jmpmid;
}

static void calc_reachable_and_remove_block(RzList /*<RzAnalysisFunction *>*/ *fcns, RzAnalysisFunction *fcn, RzAnalysisBlock *bb, HtUP *reachable) {
	clear_bb_vars(fcn, bb, bb->addr, bb->addr + bb->size);
	if (!rz_list_contains(fcns, fcn)) {
		rz_list_append(fcns, fcn);

		// Calculate reachable blocks from the start of function
		HtUP *ht = ht_up_new(NULL, NULL);
		BlockRecurseCtx ctx = { fcn, ht };
		rz_analysis_block_recurse(rz_analysis_get_block_at(fcn->analysis, fcn->addr), mark_as_visited, &ctx);
		ht_up_insert(reachable, fcn->addr, ht);
	}
	fcn->ninstr -= bb->ninstr;
	rz_analysis_function_remove_block(fcn, bb);
}

RZ_API void rz_analysis_update_analysis_range(RzAnalysis *analysis, ut64 addr, int size) {
	rz_return_if_fail(analysis);
	RzListIter *it, *it2, *tmp;
	RzAnalysisBlock *bb;
	RzAnalysisFunction *fcn;
	RzList *blocks = rz_analysis_get_blocks_intersect(analysis, addr, size);
	if (rz_list_empty(blocks)) {
		rz_list_free(blocks);
		return;
	}
	RzList *fcns = rz_list_new();
	HtUP *reachable = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);
	const int align = rz_analysis_archinfo(analysis, RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN);
	const ut64 end_write = addr + size;

	rz_list_foreach (blocks, it, bb) {
		if (!rz_analysis_block_was_modified(bb)) {
			continue;
		}
		rz_list_foreach_safe (bb->fcns, it2, tmp, fcn) {
			if (align > 1) {
				if ((end_write < rz_analysis_block_get_op_addr(bb, bb->ninstr - 1)) && (!bb->switch_op || end_write < bb->switch_op->addr)) {
					// Special case when instructions are aligned and we don't
					// need to worry about a write messing with the jump instructions
					clear_bb_vars(fcn, bb, addr > bb->addr ? addr : bb->addr, end_write);
					update_vars_analysis(fcn, bb, align, addr > bb->addr ? addr : bb->addr, end_write);
					rz_analysis_function_delete_unused_vars(fcn);
					continue;
				}
			}
			calc_reachable_and_remove_block(fcns, fcn, bb, reachable);
		}
	}
	rz_list_free(blocks); // This will call rz_analysis_block_unref to actually remove blocks from RzAnalysis
	update_analysis(analysis, fcns, reachable);
	ht_up_free(reachable);
	rz_list_free(fcns);
}

RZ_API void rz_analysis_function_update_analysis(RzAnalysisFunction *fcn) {
	rz_return_if_fail(fcn);
	RzListIter *it, *tmp;
	RzAnalysisBlock *bb;
	RzAnalysisFunction *f;
	RzList *fcns = rz_list_new();
	HtUP *reachable = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);

	// in this loop we modify the pvector size we cannot loop normally.
	size_t count = rz_pvector_len(fcn->bbs);
	for (size_t i = 0; i < count;) {
		bb = (RzAnalysisBlock *)rz_pvector_at(fcn->bbs, i);
		if (!rz_analysis_block_was_modified(bb)) {
			i++;
			continue;
		}
		rz_list_foreach_safe (bb->fcns, it, tmp, f) {
			calc_reachable_and_remove_block(fcns, f, bb, reachable);
		}
		count = rz_pvector_len(fcn->bbs);
	}
	update_analysis(fcn->analysis, fcns, reachable);
	ht_up_free(reachable);
	rz_list_free(fcns);
}

/**
 * \brief Returns vector of all function arguments
 *
 * \param a RzAnalysis instance
 * \param fcn Function
 */
RZ_API RZ_OWN RzPVector /*<RzAnalysisVar *>*/ *rz_analysis_function_args(RzAnalysis *a, RzAnalysisFunction *fcn) {
	if (!a || !fcn) {
		return NULL;
	}
	RzPVector *tmp = rz_pvector_new(NULL);
	if (!tmp) {
		return NULL;
	}
	RzAnalysisVar *var;
	void **it;
	int rarg_idx = 0;
	// Resort the pvector to order "reg_arg - stack_arg"
	rz_pvector_foreach (&fcn->vars, it) {
		var = *it;
		if (var->storage.type == RZ_ANALYSIS_VAR_STORAGE_REG) {
			rz_pvector_insert(tmp, rarg_idx++, var);
		} else {
			rz_pvector_push(tmp, var);
		}
	}

	RzPVector *args = rz_pvector_new(NULL);
	if (!args) {
		rz_pvector_free(tmp);
		return NULL;
	}
	rz_pvector_foreach (tmp, it) {
		var = *it;
		if (rz_analysis_var_is_arg(var)) {
			int argnum;
			if (var->storage.type == RZ_ANALYSIS_VAR_STORAGE_REG) {
				argnum = rz_analysis_var_get_argnum(var);
				if (argnum < 0) {
					RZ_LOG_INFO("%s : arg \"%s\" has wrong position: %d\n", fcn->name, var->name, argnum);
					continue;
				}
			} else {
				argnum = fcn->argnum;
			}
			// pvector api is a bit ugly here, essentially we make a (possibly sparse) array
			// where each var is assigned at its argnum
			if (argnum >= rz_pvector_len(args)) {
				if (!rz_pvector_reserve(args, argnum + 1)) {
					goto cleanup;
				}
				while (argnum >= rz_pvector_len(args)) {
					rz_pvector_push(args, NULL);
				}
			}
			rz_pvector_set(args, argnum, var);
			fcn->argnum++;
		}
	}
cleanup:
	rz_pvector_free(tmp);
	return args;
}

/**
 * \brief Returns vector of all function variables without arguments
 *
 * \param a RzAnalysis instance
 * \param fcn Function
 */
RZ_API RZ_OWN RzPVector /*<RzAnalysisVar *>*/ *rz_analysis_function_vars(RZ_NONNULL RzAnalysis *a, RZ_NONNULL RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(a && fcn, NULL);
	RzAnalysisVar *var;
	void **it;
	RzPVector *vars = rz_pvector_new(NULL);
	if (!vars) {
		return NULL;
	}
	rz_pvector_foreach (&fcn->vars, it) {
		var = *it;
		if (!rz_analysis_var_is_arg(var)) {
			rz_pvector_push(vars, var);
		}
	}
	return vars;
}

/**
 * \brief Gets the argument given its index
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_get_arg_idx(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *f, size_t index) {
	rz_return_val_if_fail(analysis && f, NULL);
	int argnum = rz_analysis_function_get_arg_count(analysis, f);
	if (argnum < 1) {
		return NULL;
	}
	if (index >= argnum) {
		RZ_LOG_VERBOSE("Function %s has less arguments (%d) than requested (%zu)\n",
			f->name, argnum, index);
	}
	RzPVector *args = rz_analysis_function_args(analysis, f);
	if (!args) {
		RZ_LOG_VERBOSE("Function %s has no arguments\n", f->name);
		return NULL;
	}
	if (rz_pvector_len(args) < index) {
		RZ_LOG_VERBOSE("Function %s has less arguments (%zu) than requested (%zu)\n",
			f->name, rz_pvector_len(args), index);
		return NULL;
	}
	return rz_pvector_at(args, index);
}

static int typecmp(const void *a, const void *b, void *user) {
	const RzType *t1 = a;
	const RzType *t2 = b;
	return !rz_types_equal(t1, t2);
}

/**
 * \brief Returns vector of all unique types used in a function
 *
 * Accounts for all types used in both arguments and variables, excluding return value type
 */
RZ_API RZ_OWN RzList /*<RzType *>*/ *rz_analysis_types_from_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzList *type_used = rz_list_new();
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		rz_list_append(type_used, var->type);
	}
	RzList *uniq = rz_list_uniq(type_used, typecmp, NULL);
	rz_list_free(type_used);
	return uniq;
}

/**
 * \brief Clones the RzCallable type for the given function
 *
 * Searches the types database for the given function and
 * returns a clone of the RzCallable type.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_OWN RzCallable *rz_analysis_function_clone_type(RzAnalysis *analysis, const RzAnalysisFunction *f) {
	rz_return_val_if_fail(analysis && f, NULL);
	// Check first if there is a match with some pre-existing RzCallable type in the database
	char *shortname = rz_analysis_function_name_guess(analysis->typedb, f->name);
	if (!shortname) {
		shortname = rz_str_dup(f->name);
	}
	// At this point the `callable` pointer is *borrowed*
	RzCallable *callable = rz_type_func_get(analysis->typedb, shortname);
	free(shortname);
	if (callable) {
		// TODO: Decide what to do if there is a mismatch between type
		// stored in the RzTypeDB database and the actual type of the
		// RzAnalysisFunction
		return rz_type_callable_clone(callable);
	}
	return NULL;
}

/**
 * \brief Creates the RzCallable type for the given function
 *
 * Creates the RzCallable type for the given function
 * by searching in the types database and returning it.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_OWN RzCallable *rz_analysis_function_create_type(RzAnalysis *analysis, RzAnalysisFunction *f) {
	// TODO: Figure out if we should use shortname or a fullname here
	RzCallable *callable = rz_type_func_new(analysis->typedb, f->name, NULL);
	if (!callable) {
		return NULL;
	}
	return callable;
}

/**
 * \brief Sets the RzCallable return type for the given function
 *
 * Checks if the given function's return type exists
 * and adds it to RzCallable by cloning it.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 * \param callable A function type
 */
RZ_API void rz_analysis_function_derive_return_type(RzAnalysisFunction *f, RzCallable **callable) {
	if (f->ret_type) {
		(*callable)->ret = rz_type_clone(f->ret_type);
	}
}

/**
 * \brief Sets the RzCallable args for the given function
 *
 * Gets the given function's arguments (names and types)
 * and if it has none it simply returns. Otherwise, it
 * creates RzCallableArgs and adds them to RzCallable.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 * \param callable A function type
 */
RZ_API bool rz_analysis_function_derive_args(RzAnalysis *analysis, RzAnalysisFunction *f, RzCallable **callable) {
	RzPVector *args = rz_analysis_function_args(analysis, f);
	if (!args || rz_pvector_empty(args)) {
		rz_pvector_free(args);
		return true;
	}
	void **it;
	rz_pvector_foreach (args, it) {
		RzAnalysisVar *var = *it;
		if (!var) {
			// TODO: maybe create a stub void arg here?
			continue;
		}
		RzType *cloned_type = rz_type_clone(var->type);
		if (!cloned_type) {
			rz_pvector_free(args);
			rz_type_callable_free(*callable);
			RZ_LOG_ERROR("Cannot parse function's argument type\n");
			return false;
		}
		RzCallableArg *arg = rz_type_callable_arg_new(analysis->typedb, var->name, cloned_type);
		if (!arg) {
			rz_pvector_free(args);
			rz_type_callable_free(*callable);
			RZ_LOG_ERROR("Cannot create callable argument\n");
			return false;
		}
		rz_type_callable_arg_add(*callable, arg);
	}
	rz_pvector_free(args);
	return true;
}

/**
 * \brief Derives the RzCallable type for the given function
 *
 * Checks if the type is defined already for this function, if yes -
 * it returns pointer to the one stored in the types database.
 * If not - it creates a new RzCallable instance based on the function name,
 * its arguments' names and types.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_OWN RzCallable *rz_analysis_function_derive_type(RzAnalysis *analysis, RzAnalysisFunction *f) {
	RzCallable *callable = rz_analysis_function_clone_type(analysis, f);
	if (!callable) {
		// If there is no match - create a new one.
		callable = rz_analysis_function_create_type(analysis, f);
		if (!callable) {
			return NULL;
		}
		// Derive retvar and args from that function
		rz_analysis_function_derive_return_type(f, &callable);
		if (!rz_analysis_function_derive_args(analysis, f, &callable)) {
			return NULL;
		}
	}
	return callable;
}

/**
 * \brief Determines if the given function is a memory allocating function (malloc, calloc etc.).
 *
 * The current methods of detection (tested in order):
 * - Name matches regex ".*\.([mc]|(re))?alloc.*"
 *
 * \param fcn The function to test.
 *
 * \return true If the function \p fcn is considered a memory allocating.
 * \return false Otherwise.
 */
RZ_API bool rz_analysis_function_is_malloc(const RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(fcn, false);
	// TODO We need more metrics here. Just the name is pretty naive.
	// E.g. we should compare it to signatures and other characterisitics.
	return rz_regex_contains(".*\\.([mc]|(re))?alloc.*", fcn->name, RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT);
}
