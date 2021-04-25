// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_parse.h>
#include <rz_util.h>
#include <rz_list.h>

#define READ_AHEAD 1
#define SDB_KEY_BB "bb.0x%" PFMT64x ".0x%" PFMT64x
// XXX must be configurable by the user
#define JMPTBLSZ             512
#define JMPTBL_LEA_SEARCH_SZ 64
#define JMPTBL_MAXFCNSIZE    4096
#define BB_ALIGN             0x10
#define MAX_SCAN_SIZE        0x7ffffff

// 16 KB is the maximum size for a basic block
#define MAX_FLG_NAME_SIZE 64

#define FIX_JMP_FWD 0
#define D           if (a->verbose)

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

#if READ_AHEAD
static ut64 cache_addr = UT64_MAX;

// TODO: move into io :?
static int read_ahead(RzAnalysis *analysis, ut64 addr, ut8 *buf, int len) {
	static ut8 cache[1024];
	const int cache_len = sizeof(cache);

	if (len < 1) {
		return 0;
	}
	if (len > cache_len) {
		int a = analysis->iob.read_at(analysis->iob.io, addr, buf, len); // double read
		memcpy(cache, buf, cache_len);
		cache_addr = addr;
		return a;
	}

	ut64 addr_end = UT64_ADD_OVFCHK(addr, len) ? UT64_MAX : addr + len;
	ut64 cache_addr_end = UT64_ADD_OVFCHK(cache_addr, cache_len) ? UT64_MAX : cache_addr + cache_len;
	bool isCached = ((addr != UT64_MAX) && (addr >= cache_addr) && (addr_end < cache_addr_end));
	if (isCached) {
		memcpy(buf, cache + (addr - cache_addr), len);
	} else {
		analysis->iob.read_at(analysis->iob.io, addr, cache, sizeof(cache));
		memcpy(buf, cache, len);
		cache_addr = addr;
	}
	return len;
}
#else
static int read_ahead(RzAnalysis *analysis, ut64 addr, ut8 *buf, int len) {
	return analysis->iob.read_at(analysis->iob.io, addr, buf, len);
}
#endif

RZ_API void rz_analysis_fcn_invalidate_read_ahead_cache(void) {
#if READ_AHEAD
	cache_addr = UT64_MAX;
#endif
}

static int cmpaddr(const void *_a, const void *_b) {
	const RzAnalysisBlock *a = _a, *b = _b;
	return a->addr > b->addr ? 1 : (a->addr < b->addr ? -1 : 0);
}

RZ_API int rz_analysis_function_resize(RzAnalysisFunction *fcn, int newsize) {
	RzAnalysis *analysis = fcn->analysis;
	RzAnalysisBlock *bb;
	RzListIter *iter, *iter2;

	rz_return_val_if_fail(fcn, false);

	if (newsize < 1) {
		return false;
	}

	// XXX this is something we should probably do for all the archs
	bool is_arm = analysis->cur->arch && !strncmp(analysis->cur->arch, "arm", 3);
	if (is_arm) {
		return true;
	}

	ut64 eof = fcn->addr + newsize;
	rz_list_foreach_safe (fcn->bbs, iter, iter2, bb) {
		if (bb->addr >= eof) {
			rz_analysis_function_remove_block(fcn, bb);
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
	bb->stackptr = fcn->stack;
	bb->parent_stackptr = fcn->stack;
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

static bool is_delta_pointer_table(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr, ut64 lea_ptr, ut64 *jmptbl_addr, ut64 *casetbl_addr, RzAnalysisOp *jmp_aop) {
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
	read_ahead(analysis, addr, (ut8 *)buf, sizeof(buf));
	bool isValid = false;
	for (i = 0; i + 8 < JMPTBL_LEA_SEARCH_SZ; i++) {
		ut64 at = addr + i;
		int left = JMPTBL_LEA_SEARCH_SZ - i;
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
	read_ahead(analysis, *jmptbl_addr, (ut8 *)&jmptbl, 64);
	for (i = 0; i < 3; i++) {
		dst = lea_ptr + (st32)rz_read_le32(jmptbl);
		if (!analysis->iob.is_valid_offset(analysis->iob.io, dst, 0)) {
			return false;
		}
		if (dst > fcn->addr + JMPTBL_MAXFCNSIZE) {
			return false;
		}
		if (analysis->opt.jmpabove && dst < (fcn->addr < JMPTBL_MAXFCNSIZE ? 0 : fcn->addr - JMPTBL_MAXFCNSIZE)) {
			return false;
		}
	}
	return true;
}

static ut64 try_get_cmpval_from_parents(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *my_bb, const char *cmp_reg) {
	rz_return_val_if_fail(fcn && fcn->bbs && cmp_reg, UT64_MAX);
	RzListIter *iter;
	RzAnalysisBlock *tmp_bb;
	rz_list_foreach (fcn->bbs, iter, tmp_bb) {
		if (tmp_bb->jump == my_bb->addr || tmp_bb->fail == my_bb->addr) {
			if (tmp_bb->cmpreg == cmp_reg) {
				if (tmp_bb->cond) {
					if (tmp_bb->cond->type == RZ_ANALYSIS_COND_HI || tmp_bb->cond->type == RZ_ANALYSIS_COND_GT) {
						return tmp_bb->cmpval + 1;
					}
				}
				return tmp_bb->cmpval;
			}
		}
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
		if (xref->type == RZ_ANALYSIS_REF_TYPE_CALL || xref->type == RZ_ANALYSIS_REF_TYPE_CODE) {
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
		if (xref->type == RZ_ANALYSIS_REF_TYPE_DATA) {
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
		if (((bb->addr >= eaddr && addr == bb->addr) || rz_analysis_block_contains(bb, addr)) && (!jumpmid || rz_analysis_block_op_starts_at(bb, addr))) {
			if (analysis->opt.delay) {
				ut8 *buf = malloc(bb->size);
				if (analysis->iob.read_at(analysis->iob.io, bb->addr, buf, bb->size)) {
					const int last_instr_idx = bb->ninstr - 1;
					bool in_delay_slot = false;
					int i;
					for (i = last_instr_idx; i >= 0; i--) {
						const ut64 off = rz_analysis_block_get_op_offset(bb, i);
						const ut64 at = bb->addr + off;
						if (addr <= at || off >= bb->size) {
							continue;
						}
						RzAnalysisOp op;
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
	const int stack_diff;
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
			RzPVector *cloned_vars_used = (RzPVector *)rz_vector_clone((RzVector *)vars_used);
			void **it;
			rz_pvector_foreach (cloned_vars_used, it) {
				RzAnalysisVar *other_var = *it;
				const int actual_delta = other_var->kind == RZ_ANALYSIS_VAR_KIND_SPV
					? other_var->delta + ctx->stack_diff
					: other_var->delta + (other_fcn->bp_off - our_fcn->bp_off);
				RzAnalysisVar *our_var = rz_analysis_function_get_var(our_fcn, other_var->kind, actual_delta);
				if (!our_var) {
					our_var = rz_analysis_function_set_var(our_fcn, actual_delta, other_var->kind, other_var->type, 0, other_var->isarg, other_var->name);
				}
				if (our_var) {
					RzAnalysisVarAccess *acc = rz_analysis_var_get_access_at(other_var, addr);
					rz_analysis_var_set_access(our_var, acc->reg, addr, acc->type, acc->stackptr);
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
	block->stackptr -= ctx->stack_diff;
	block->parent_stackptr -= ctx->stack_diff;
	rz_analysis_function_add_block(our_fcn, block);
	// TODO: add block->ninstr from our_fcn considering delay slots
	rz_analysis_block_unref(block);
	return true;
}

// Remove block and all of its recursive successors from all its functions and add them only to fcn
static void fcn_takeover_block_recursive(RzAnalysisFunction *fcn, RzAnalysisBlock *start_block) {
	BlockTakeoverCtx ctx = { fcn, start_block->parent_stackptr - fcn->stack };
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

static int fcn_recurse(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr, ut64 len, int depth) {
	const int continue_after_jump = analysis->opt.afterjmp;
	const int addrbytes = analysis->iob.io ? analysis->iob.io->addrbytes : 1;
	char *last_reg_mov_lea_name = NULL;
	char *movbasereg = NULL;
	RzAnalysisBlock *bb = NULL;
	RzAnalysisBlock *bbg = NULL;
	int ret = RZ_ANALYSIS_RET_END, skip_ret = 0;
	bool overlapped = false;
	RzAnalysisOp op = { 0 };
	int oplen, idx = 0;
	int lea_cnt = 0;
	static ut64 cmpval = UT64_MAX; // inherited across functions, otherwise it breaks :?
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
	bool arch_destroys_dst = does_arch_destroys_dst(analysis->cur->arch);
	bool is_arm = analysis->cur->arch && !strncmp(analysis->cur->arch, "arm", 3);
	char tmp_buf[MAX_FLG_NAME_SIZE + 5] = "skip";
	bool is_x86 = is_arm ? false : analysis->cur->arch && !strncmp(analysis->cur->arch, "x86", 3);
	bool is_amd64 = is_x86 ? fcn->cc && !strcmp(fcn->cc, "amd64") : false;
	bool is_dalvik = is_x86 ? false : analysis->cur->arch && !strncmp(analysis->cur->arch, "dalvik", 6);
	RzRegItem *variadic_reg = NULL;
	if (is_amd64) {
		variadic_reg = rz_reg_get(analysis->reg, "rax", RZ_REG_TYPE_GPR);
	}
	bool has_variadic_reg = !!variadic_reg;

	if (rz_cons_is_breaked()) {
		return RZ_ANALYSIS_RET_END;
	}
	if (analysis->sleep) {
		rz_sys_usleep(analysis->sleep);
	}

	if (depth < 1) {
		if (analysis->verbose) {
			eprintf("Analysis went too deep at address 0x%" PFMT64x ".\n", addr);
		}
		return RZ_ANALYSIS_RET_ERROR; // MUST BE TOO DEEP
	}

	// check if address is readable //:
	if (!analysis->iob.is_valid_offset(analysis->iob.io, addr, 0)) {
		if (addr != UT64_MAX && !analysis->iob.io->va) {
			if (analysis->verbose) {
				eprintf("Invalid address 0x%" PFMT64x ". Try with io.va=true\n", addr);
			}
		}
		return RZ_ANALYSIS_RET_ERROR; // MUST BE TOO DEEP
	}

	RzAnalysisFunction *fcn_at_addr = rz_analysis_get_function_at(analysis, addr);
	if (fcn_at_addr && fcn_at_addr != fcn) {
		return RZ_ANALYSIS_RET_ERROR; // MUST BE NOT FOUND
	}

	RzAnalysisBlock *existing_bb = bbget(analysis, addr, analysis->opt.jmpmid && is_x86);
	if (existing_bb) {
		bool existing_in_fcn = rz_list_contains(existing_bb->fcns, fcn);
		existing_bb = rz_analysis_block_split(existing_bb, addr);
		if (!existing_in_fcn && existing_bb) {
			if (existing_bb->addr == fcn->addr) {
				// our function starts directly there, so we steal what is ours!
				fcn_takeover_block_recursive(fcn, existing_bb);
			}
		}
		if (existing_bb) {
			rz_analysis_block_unref(existing_bb);
		}
		if (analysis->opt.recont) {
			return RZ_ANALYSIS_RET_END;
		}
		if (analysis->verbose) {
			eprintf("rz_analysis_fcn_bb() fails at 0x%" PFMT64x ".\n", addr);
		}
		return RZ_ANALYSIS_RET_ERROR; // MUST BE NOT DUP
	}

	bb = fcn_append_basic_block(analysis, fcn, addr);
	// we checked before whether there is a bb at addr, so the create should have succeeded
	rz_return_val_if_fail(bb, RZ_ANALYSIS_RET_ERROR);

	if (!analysis->leaddrs) {
		analysis->leaddrs = rz_list_newf(free_leaddr_pair);
		if (!analysis->leaddrs) {
			eprintf("Cannot create leaddr list\n");
			gotoBeach(RZ_ANALYSIS_RET_ERROR);
		}
	}
	static ut64 lea_jmptbl_ip = UT64_MAX;
	ut64 last_reg_mov_lea_val = UT64_MAX;
	bool last_is_reg_mov_lea = false;
	bool last_is_push = false;
	bool last_is_mov_lr_pc = false;
	ut64 last_push_addr = UT64_MAX;
	if (analysis->limit && addr + idx < analysis->limit->from) {
		gotoBeach(RZ_ANALYSIS_RET_END);
	}
	RzAnalysisFunction *tmp_fcn = rz_analysis_get_fcn_in(analysis, addr, 0);
	if (tmp_fcn) {
		// Checks if var is already analyzed at given addr
		RzList *list = rz_analysis_var_all_list(analysis, tmp_fcn);
		if (!rz_list_empty(list)) {
			varset = true;
		}
		rz_list_free(list);
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
		if (analysis->verbose) {
			eprintf("Warning: Skipping large memory region.\n");
		}
		maxlen = 0;
	}

	while (addrbytes * idx < maxlen) {
		if (!last_is_reg_mov_lea) {
			free(last_reg_mov_lea_name);
			last_reg_mov_lea_name = NULL;
		}
		if (analysis->limit && analysis->limit->to <= addr + idx) {
			break;
		}
	repeat:
		if (rz_cons_is_breaked()) {
			break;
		}
		ut32 at_delta = addrbytes * idx;
		ut64 at = addr + at_delta;
		ut64 bytes_read = RZ_MIN(len - at_delta, sizeof(buf));
		ret = read_ahead(analysis, at, buf, bytes_read);

		if (ret < 0) {
			eprintf("Failed to read\n");
			break;
		}
		if (isInvalidMemory(analysis, buf, bytes_read)) {
			if (analysis->verbose) {
				eprintf("Warning: FFFF opcode at 0x%08" PFMT64x "\n", at);
			}
			gotoBeach(RZ_ANALYSIS_RET_ERROR)
		}
		rz_analysis_op_fini(&op);
		if ((oplen = rz_analysis_op(analysis, &op, at, buf, bytes_read, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_HINT)) < 1) {
			if (analysis->verbose) {
				eprintf("Invalid instruction at 0x%" PFMT64x " with %d bits\n", at, analysis->bits);
			}
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
			bbg = bbget(analysis, at, analysis->opt.jmpmid && is_x86);
			if (bbg && bbg != bb) {
				bb->jump = at;
				if (analysis->opt.jmpmid && is_x86) {
					// This happens when we purposefully walked over another block and overlapped it
					// and now we hit an offset where the instructions match again.
					// So we need to split the overwalked block.
					RzAnalysisBlock *split = rz_analysis_block_split(bbg, at);
					rz_analysis_block_unref(split);
				}
				overlapped = true;
				if (analysis->verbose) {
					eprintf("Overlapped at 0x%08" PFMT64x "\n", at);
				}
			}
		}
		if (!overlapped) {
			ut64 newbbsize = bb->size + oplen;
			if (newbbsize > MAX_FCN_SIZE) {
				gotoBeach(RZ_ANALYSIS_RET_ERROR);
			}
			rz_analysis_block_set_op_offset(bb, bb->ninstr++, at - bb->addr);
			rz_analysis_block_set_size(bb, newbbsize);
			fcn->ninstr++;
		}
		if (analysis->opt.trycatch) {
			const char *name = analysis->coreb.getName(analysis->coreb.core, at);
			if (name) {
				if (rz_str_startswith(name, "try.") && rz_str_endswith(name, ".from")) {
					char *handle = strdup(name);
					// handle = rz_str_replace (handle, ".from", ".to", 0);
					ut64 from_addr = analysis->coreb.numGet(analysis->coreb.core, handle);
					handle = rz_str_replace(handle, ".from", ".catch", 0);
					ut64 handle_addr = analysis->coreb.numGet(analysis->coreb.core, handle);
					bb->jump = at + oplen;
					if (from_addr != bb->addr) {
						bb->fail = handle_addr;
						ret = rz_analysis_fcn_bb(analysis, fcn, handle_addr, depth);
						eprintf("(%s) 0x%08" PFMT64x "\n", handle, handle_addr);
						if (bb->size == 0) {
							rz_analysis_function_remove_block(fcn, bb);
						}
						rz_analysis_block_unref(bb);
						bb = fcn_append_basic_block(analysis, fcn, addr);
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
			if (analysis->verbose) {
				eprintf("Enter branch delay at 0x%08" PFMT64x ". bb->sz=%" PFMT64u "\n", at - oplen, bb->size);
			}
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
				if (analysis->verbose) {
					eprintf("Last branch delayed opcode at 0x%08" PFMT64x ". bb->sz=%" PFMT64u "\n", addr + idx - oplen, bb->size);
				}
				delay.after = idx;
				idx = delay.idx;
				// At this point, we are still looking at the
				// last instruction in the branch delay group.
				// Next time, we will again be looking
				// at the original instruction that entered
				// the branch delay.
			}
		} else if (op.delay > 0 && delay.pending) {
			if (analysis->verbose) {
				eprintf("Revisit branch delay jump at 0x%08" PFMT64x ". bb->sz=%" PFMT64u "\n", addr + idx - oplen, bb->size);
			}
			// This is the second pass of the branch delaying opcode
			// But we also already counted this instruction in the
			// size of the current basic block, so we need to fix that
			if (delay.adjust) {
				rz_analysis_block_set_size(bb, (ut64)addrbytes * (ut64)delay.after);
				fcn->ninstr--;
				if (analysis->verbose) {
					eprintf("Correct for branch delay @ %08" PFMT64x " bb.addr=%08" PFMT64x " corrected.bb=%" PFMT64u " f.uncorr=%" PFMT64u "\n",
						addr + idx - oplen, bb->addr, bb->size, rz_analysis_function_linear_size(fcn));
				}
			}
			// Next time, we go to the opcode after the delay count
			// Take care not to use this below, use delay.un_idx instead ...
			idx = delay.after;
			delay.pending = delay.after = delay.idx = delay.adjust = 0;
		}
		// Note: if we got two branch delay instructions in a row due to an
		// compiler bug or junk or something it wont get treated as a delay
		switch (op.stackop) {
		case RZ_ANALYSIS_STACK_INC:
			if (RZ_ABS(op.stackptr) < 8096) {
				fcn->stack += op.stackptr;
				if (fcn->stack > fcn->maxstack) {
					fcn->maxstack = fcn->stack;
				}
			}
			bb->stackptr += op.stackptr;
			break;
		case RZ_ANALYSIS_STACK_RESET:
			bb->stackptr = 0;
			break;
		default:
			break;
		}
		if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
			// swapped parameters
			rz_analysis_xrefs_set(analysis, op.addr, op.ptr, RZ_ANALYSIS_REF_TYPE_DATA);
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
				fcn->bp_off = fcn->stack;
			}
			// Is this a mov of immediate value into a register?
			if (op.dst && op.dst->reg && op.dst->reg->name && op.val > 0 && op.val != UT64_MAX) {
				free(last_reg_mov_lea_name);
				if ((last_reg_mov_lea_name = strdup(op.dst->reg->name))) {
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
					movbasereg = strdup(op.src[0]->reg->name);
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
					eprintf("Cannot create leaddr_pair\n");
					gotoBeach(RZ_ANALYSIS_RET_ERROR);
				}
				pair->op_addr = op.addr;
				pair->leaddr = op.ptr; // XXX movdisp is dupped but seems to be trashed sometimes(?), better track leaddr separately
				pair->reg = op.reg
					? strdup(op.reg)
					: op.dst && op.dst->reg
					? strdup(op.dst->reg->name)
					: NULL;
				lea_cnt++;
				rz_list_append(analysis->leaddrs, pair);
			}
			if (has_stack_regs && op_is_set_bp(&op, bp_reg, sp_reg)) {
				fcn->bp_off = fcn->stack - op.src[0]->delta;
			}
			if (op.dst && op.dst->reg && op.dst->reg->name && op.ptr > 0 && op.ptr != UT64_MAX) {
				free(last_reg_mov_lea_name);
				if ((last_reg_mov_lea_name = strdup(op.dst->reg->name))) {
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
				if (is_delta_pointer_table(analysis, fcn, op.addr, op.ptr, &jmptbl_addr, &casetbl_addr, &jmp_aop)) {
					ut64 table_size, default_case = 0;
					st64 case_shift;
					// we require both checks here since try_get_jmptbl_info uses
					// BB info of the final jmptbl jump, which is no present with
					// is_delta_pointer_table just scanning ahead
					// try_get_delta_jmptbl_info doesn't work at times where the
					// lea comes after the cmp/default case cjmp, which can be
					// handled with try_get_jmptbl_info
					if (try_get_jmptbl_info(analysis, fcn, jmp_aop.addr, bb, &table_size, &default_case, &case_shift) || try_get_delta_jmptbl_info(analysis, fcn, jmp_aop.addr, op.addr, &table_size, &default_case, &case_shift)) {
						ret = casetbl_addr == op.ptr
							? try_walkthrough_jmptbl(analysis, fcn, bb, depth, jmp_aop.addr, case_shift, jmptbl_addr, op.ptr, 4, table_size, default_case, 4)
							: try_walkthrough_casetbl(analysis, fcn, bb, depth, jmp_aop.addr, case_shift, jmptbl_addr, casetbl_addr, op.ptr, 4, table_size, default_case, 4);
						if (ret) {
							lea_jmptbl_ip = jmp_aop.addr;
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
				(void)rz_analysis_xrefs_set(analysis, op.addr, op.jump, RZ_ANALYSIS_REF_TYPE_CODE);
			}
			if (!analysis->opt.jmpabove && (op.jump < fcn->addr)) {
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			if (rz_analysis_noreturn_at(analysis, op.jump)) {
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			{
				bool must_eob = true;
				RzIOMap *map = analysis->iob.map_get(analysis->iob.io, addr);
				if (map) {
					must_eob = (op.jump < map->itv.addr || op.jump >= map->itv.addr + map->itv.size);
				}
				if (must_eob) {
					op.jump = UT64_MAX;
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}
#if FIX_JMP_FWD
			bb->jump = op.jump;
			bb->fail = UT64_MAX;
			FITFCNSZ();
			gotoBeach(RZ_ANALYSIS_RET_END);
#else
			if (!overlapped) {
				bb->jump = op.jump;
				bb->fail = UT64_MAX;
			}
			ret = rz_analysis_fcn_bb(analysis, fcn, op.jump, depth);
			int tc = analysis->opt.tailcall;
			if (tc) {
				// eprintf ("TAIL CALL AT 0x%llx\n", op.addr);
				int diff = op.jump - op.addr;
				if (tc < 0) {
					ut8 buf[32];
					(void)analysis->iob.read_at(analysis->iob.io, op.jump, (ut8 *)buf, sizeof(buf));
					if (rz_analysis_is_prelude(analysis, buf, sizeof(buf))) {
						fcn_recurse(analysis, fcn, op.jump, analysis->opt.bb_max_size, depth - 1);
					}
				} else if (RZ_ABS(diff) > tc) {
					(void)rz_analysis_xrefs_set(analysis, op.addr, op.jump, RZ_ANALYSIS_REF_TYPE_CALL);
					fcn_recurse(analysis, fcn, op.jump, analysis->opt.bb_max_size, depth - 1);
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}
			goto beach;
#endif
			break;
		case RZ_ANALYSIS_OP_TYPE_SUB:
			if (op.val != UT64_MAX && op.val > 0) {
				// if register is not stack
				cmpval = op.val;
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_CMP: {
			ut64 val = is_x86 ? op.val : op.ptr;
			if (val) {
				cmpval = val;
				bb->cmpval = cmpval;
				bb->cmpreg = op.reg;
				rz_analysis_cond_free(bb->cond);
				bb->cond = rz_analysis_cond_new_from_op(&op);
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_MCJMP:
		case RZ_ANALYSIS_OP_TYPE_RCJMP:
		case RZ_ANALYSIS_OP_TYPE_UCJMP:
			if (analysis->opt.cjmpref) {
				(void)rz_analysis_xrefs_set(analysis, op.addr, op.jump, RZ_ANALYSIS_REF_TYPE_CODE);
			}
			if (!overlapped) {
				bb->jump = op.jump;
				bb->fail = op.fail;
			}
			if (bb->cond) {
				bb->cond->type = op.cond;
			}
			if (analysis->opt.jmptbl) {
				if (op.ptr != UT64_MAX) {
					ut64 table_size, default_case;
					table_size = cmpval + 1;
					default_case = op.fail; // is this really default case?
					if (cmpval != UT64_MAX && default_case != UT64_MAX && (op.reg || op.ireg)) {
						if (op.ireg) {
							try_walkthrough_jmptbl(analysis, fcn, bb, depth, op.addr, 0, op.ptr, op.ptr, analysis->bits >> 3, table_size, default_case, ret);
						} else { // op.reg
							walkthrough_arm_jmptbl_style(analysis, fcn, bb, depth, op.addr, op.ptr, analysis->bits >> 3, table_size, default_case, ret);
						}
						// check if op.jump and op.fail contain jump table location
						// clear jump address, because it's jump table location
						if (op.jump == op.ptr) {
							op.jump = UT64_MAX;
						} else if (op.fail == op.ptr) {
							op.fail = UT64_MAX;
						}
						cmpval = UT64_MAX;
					}
				}
			}
			int saved_stack = fcn->stack;
			if (continue_after_jump) {
				rz_analysis_fcn_bb(analysis, fcn, op.jump, depth);
				fcn->stack = saved_stack;
				ret = rz_analysis_fcn_bb(analysis, fcn, op.fail, depth);
				fcn->stack = saved_stack;
			} else {
				rz_analysis_fcn_bb(analysis, fcn, op.jump, depth);
				fcn->stack = saved_stack;
				ret = rz_analysis_fcn_bb(analysis, fcn, op.fail, depth);
				fcn->stack = saved_stack;
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
			goto beach;
			// For some reason, branch delayed code (MIPS) needs to continue
			break;
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_ICALL:
		case RZ_ANALYSIS_OP_TYPE_IRCALL:
			/* call [dst] */
			// XXX: this is TYPE_MCALL or indirect-call
			(void)rz_analysis_xrefs_set(analysis, op.addr, op.ptr, RZ_ANALYSIS_REF_TYPE_CALL);

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
			(void)rz_analysis_xrefs_set(analysis, op.addr, op.jump, RZ_ANALYSIS_REF_TYPE_CALL);

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
			if (is_arm && last_is_mov_lr_pc) {
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
			if (analysis->opt.jmptbl && lea_jmptbl_ip != op.addr) {
				// op.ireg since rip relative addressing produces way too many false positives otherwise
				// op.ireg is 0 for rip relative, "rax", etc otherwise
				if (op.ptr != UT64_MAX && op.ireg) { // direct jump
					ut64 table_size, default_case;
					st64 case_shift;
					if (try_get_jmptbl_info(analysis, fcn, op.addr, bb, &table_size, &default_case, &case_shift)) {
						bool case_table = false;
						RzAnalysisOp prev_op;
						analysis->iob.read_at(analysis->iob.io, op.addr - op.size, buf, sizeof(buf));
						if (rz_analysis_op(analysis, &prev_op, op.addr - op.size, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_VAL) > 0) {
							bool prev_op_has_dst_name = prev_op.dst && prev_op.dst->reg && prev_op.dst->reg->name;
							bool op_has_src_name = op.src[0] && op.src[0]->reg && op.src[0]->reg->name;
							bool same_reg = (op.ireg && prev_op_has_dst_name && !strcmp(op.ireg, prev_op.dst->reg->name)) || (op_has_src_name && prev_op_has_dst_name && !strcmp(op.src[0]->reg->name, prev_op.dst->reg->name));
							if (prev_op.type == RZ_ANALYSIS_OP_TYPE_MOV && prev_op.disp && prev_op.disp != UT64_MAX && same_reg) {
								//	movzx reg, byte [reg + case_table]
								//	jmp dword [reg*4 + jump_table]
								if (try_walkthrough_casetbl(analysis, fcn, bb, depth, op.addr, case_shift, op.ptr, prev_op.disp, op.ptr, analysis->bits >> 3, table_size, default_case, ret)) {
									ret = case_table = true;
								}
							}
						}
						rz_analysis_op_fini(&prev_op);
						if (!case_table) {
							ret = try_walkthrough_jmptbl(analysis, fcn, bb, depth, op.addr, case_shift, op.ptr, op.ptr, analysis->bits >> 3, table_size, default_case, ret);
						}
					}
				} else if (op.ptr != UT64_MAX && op.reg) { // direct jump
					ut64 table_size, default_case;
					st64 case_shift;
					if (try_get_jmptbl_info(analysis, fcn, op.addr, bb, &table_size, &default_case, &case_shift)) {
						ret = try_walkthrough_jmptbl(analysis, fcn, bb, depth, op.addr, case_shift, op.ptr, op.ptr, analysis->bits >> 3, table_size, default_case, ret);
					}
				} else if (movdisp != UT64_MAX) {
					ut64 table_size;
					ut64 default_case;
					ut64 jmptbl_base = 0;
					ut64 lea_op_off = UT64_MAX;
					st64 case_shift;
					RzListIter *iter;
					leaddr_pair *pair;
					if (movbasereg) {
						// find nearest candidate leaddr before op.addr
						rz_list_foreach_prev(analysis->leaddrs, iter, pair) {
							if (pair->op_addr >= op.addr) {
								continue;
							}
							if ((lea_op_off == UT64_MAX || lea_op_off > op.addr - pair->op_addr) && pair->reg && !strcmp(movbasereg, pair->reg)) {
								lea_op_off = op.addr - pair->op_addr;
								jmptbl_base = pair->leaddr;
							}
						}
					}
					if (!try_get_jmptbl_info(analysis, fcn, op.addr, bb, &table_size, &default_case, &case_shift)) {
						table_size = cmpval + 1;
						default_case = -1;
					}
					ret = try_walkthrough_jmptbl(analysis, fcn, bb, depth, op.addr, case_shift, jmptbl_base + movdisp, jmptbl_base, movscale, table_size, default_case, ret);
					cmpval = UT64_MAX;
				} else if (is_arm) {
					if (op.ptrsize == 1) { // TBB
						ut64 pred_cmpval = try_get_cmpval_from_parents(analysis, fcn, bb, op.ireg);
						ut64 table_size = 0;
						if (pred_cmpval != UT64_MAX) {
							table_size += pred_cmpval;
						} else {
							table_size += cmpval;
						}
						ret = try_walkthrough_jmptbl(analysis, fcn, bb, depth, op.addr, 0, op.addr + op.size,
							op.addr + 4, 1, table_size, UT64_MAX, ret);
						// skip inlined jumptable
						idx += table_size;
					}
					if (op.ptrsize == 2) { // LDRH on thumb/arm
						ut64 pred_cmpval = try_get_cmpval_from_parents(analysis, fcn, bb, op.ireg);
						int tablesize = 1;
						if (pred_cmpval != UT64_MAX) {
							tablesize += pred_cmpval;
						} else {
							tablesize += cmpval;
						}
						ret = try_walkthrough_jmptbl(analysis, fcn, bb, depth, op.addr, 0, op.addr + op.size,
							op.addr + 4, 2, tablesize, UT64_MAX, ret);
						// skip inlined jumptable
						idx += (tablesize * 2);
					}
				}
			}
			if (lea_jmptbl_ip == op.addr) {
				lea_jmptbl_ip = UT64_MAX;
			}
			if (analysis->opt.ijmp) {
				if (continue_after_jump) {
					rz_analysis_fcn_bb(analysis, fcn, op.jump, depth);
					ret = rz_analysis_fcn_bb(analysis, fcn, op.fail, depth);
					if (overlapped) {
						goto analopfinish;
					}
				}
				if (rz_analysis_noreturn_at(analysis, op.jump) || op.eob) {
					goto analopfinish;
				}
			} else {
			analopfinish:
				if (op.type == RZ_ANALYSIS_OP_TYPE_RJMP) {
					gotoBeach(RZ_ANALYSIS_RET_NOP);
				} else {
					gotoBeach(RZ_ANALYSIS_RET_END);
				}
			}
			break;
		/* fallthru */
		case RZ_ANALYSIS_OP_TYPE_PUSH:
			last_is_push = true;
			last_push_addr = op.val;
			if (analysis->iob.is_valid_offset(analysis->iob.io, last_push_addr, 1)) {
				(void)rz_analysis_xrefs_set(analysis, op.addr, last_push_addr, RZ_ANALYSIS_REF_TYPE_DATA);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_UPUSH:
			if ((op.type & RZ_ANALYSIS_OP_TYPE_REG) && last_is_reg_mov_lea && op.src[0] && op.src[0]->reg && op.src[0]->reg->name && !strcmp(op.src[0]->reg->name, last_reg_mov_lea_name)) {
				last_is_push = true;
				last_push_addr = last_reg_mov_lea_val;
				if (analysis->iob.is_valid_offset(analysis->iob.io, last_push_addr, 1)) {
					(void)rz_analysis_xrefs_set(analysis, op.addr, last_push_addr, RZ_ANALYSIS_REF_TYPE_DATA);
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
				ret = rz_analysis_fcn_bb(analysis, fcn, op.jump, depth);
				goto beach;
			}
			if (!op.cond) {
				if (analysis->verbose) {
					eprintf("RET 0x%08" PFMT64x ". overlap=%s %" PFMT64u " %" PFMT64u "\n",
						addr + delay.un_idx - oplen, rz_str_bool(overlapped),
						bb->size, rz_analysis_function_linear_size(fcn));
				}
				gotoBeach(RZ_ANALYSIS_RET_END);
			}
			break;
		}
		if (has_stack_regs && arch_destroys_dst) {
			if (op_is_set_bp(&op, bp_reg, sp_reg) && op.src[1]) {
				switch (op.type & RZ_ANALYSIS_OP_TYPE_MASK) {
				case RZ_ANALYSIS_OP_TYPE_ADD:
					fcn->bp_off = fcn->stack - op.src[1]->imm;
					break;
				case RZ_ANALYSIS_OP_TYPE_SUB:
					fcn->bp_off = fcn->stack + op.src[1]->imm;
					break;
				}
			}
		}
		if (analysis->opt.vars && !varset) {
			rz_analysis_extract_vars(analysis, fcn, &op);
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
	while (lea_cnt > 0) {
		rz_list_delete(analysis->leaddrs, rz_list_tail(analysis->leaddrs));
		lea_cnt--;
	}
	rz_analysis_op_fini(&op);
	RZ_FREE(last_reg_mov_lea_name);
	if (bb && bb->size == 0) {
		rz_analysis_function_remove_block(fcn, bb);
	}
	rz_analysis_block_update_hash(bb);
	rz_analysis_block_unref(bb);
	free(movbasereg);
	return ret;
}

RZ_API int rz_analysis_fcn_bb(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr, int depth) {
	return fcn_recurse(analysis, fcn, addr, analysis->opt.bb_max_size, depth - 1);
}

RZ_API bool rz_analysis_check_fcn(RzAnalysis *analysis, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high) {
	RzAnalysisOp op = {
		0
	};
	int i, oplen, opcnt = 0, pushcnt = 0, movcnt = 0, brcnt = 0;
	if (rz_analysis_is_prelude(analysis, buf, bufsz)) {
		return true;
	}
	for (i = 0; i < bufsz && opcnt < 10; i += oplen, opcnt++) {
		rz_analysis_op_fini(&op);
		if ((oplen = rz_analysis_op(analysis, &op, addr + i, buf + i, bufsz - i, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT)) < 1) {
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
				return false;
			}
			brcnt++;
			break;
		case RZ_ANALYSIS_OP_TYPE_UNK:
			return false;
		default:
			break;
		}
	}
	return (pushcnt + movcnt + brcnt > 5);
}

RZ_API void rz_analysis_trim_jmprefs(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzAnalysisXRef *xref;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	RzListIter *iter;
	const bool is_x86 = analysis->cur->arch && !strcmp(analysis->cur->arch, "x86"); // HACK

	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type == RZ_ANALYSIS_REF_TYPE_CODE && rz_analysis_function_contains(fcn, xref->to) && (!is_x86 || !rz_analysis_function_contains(fcn, xref->from))) {
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
		if (xref->type == RZ_ANALYSIS_REF_TYPE_CODE) {
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
			analysis->visited = set_u_new();
		}
		if (set_u_contains(analysis->visited, addr)) {
			eprintf("rz_analysis_fcn: analysis.norevisit at 0x%08" PFMT64x " %c\n", addr, reftype);
			return RZ_ANALYSIS_RET_END;
		}
		set_u_add(analysis->visited, addr);
	} else {
		if (analysis->visited) {
			set_u_free(analysis->visited);
			analysis->visited = NULL;
		}
	}
	/* defines fcn. or loc. prefix */
	fcn->type = (reftype == RZ_ANALYSIS_REF_TYPE_CODE) ? RZ_ANALYSIS_FCN_TYPE_LOC : RZ_ANALYSIS_FCN_TYPE_FCN;
	if (fcn->addr == UT64_MAX) {
		fcn->addr = addr;
	}
	fcn->maxstack = 0;
	if (fcn->cc && !strcmp(fcn->cc, "ms")) {
		// Probably should put this on the cc sdb
		const int shadow_store = 0x28; // First 4 args + retaddr
		fcn->stack = fcn->maxstack = fcn->reg_save_area = shadow_store;
	}
	int ret = rz_analysis_fcn_bb(analysis, fcn, addr, analysis->opt.depth);
	if (ret < 0) {
		if (analysis->verbose) {
			eprintf("Failed to analyze basic block at 0x%" PFMT64x "\n", addr);
		}
	}
	if (analysis->opt.endsize && ret == RZ_ANALYSIS_RET_END && rz_analysis_function_realsize(fcn)) { // cfg analysis completed
		RzListIter *iter;
		RzAnalysisBlock *bb;
		ut64 endaddr = fcn->addr;
		const bool is_x86 = analysis->cur->arch && !strcmp(analysis->cur->arch, "x86");

		// set function size as length of continuous sequence of bbs
		rz_list_sort(fcn->bbs, &cmpaddr);
		rz_list_foreach (fcn->bbs, iter, bb) {
			if (endaddr == bb->addr) {
				endaddr += bb->size;
			} else if ((endaddr < bb->addr && bb->addr - endaddr < BB_ALIGN) || (analysis->opt.jmpmid && is_x86 && endaddr > bb->addr && bb->addr + bb->size > endaddr)) {
				endaddr = bb->addr + bb->size;
			} else {
				break;
			}
		}
		// fcn is not yet in analysis => pass NULL
		rz_analysis_function_resize(fcn, endaddr - fcn->addr);
		rz_analysis_trim_jmprefs(analysis, fcn);
	}
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
		D eprintf("fcn at %llx %llx\n", fcn->addr, addr);
		if (fcn->addr == addr) {
			rz_analysis_function_delete(fcn);
		}
	}
	return true;
}

RZ_API RzAnalysisFunction *rz_analysis_get_fcn_in(RzAnalysis *analysis, ut64 addr, int type) {
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

RZ_API RzAnalysisFunction *rz_analysis_get_fcn_in_bounds(RzAnalysis *analysis, ut64 addr, int type) {
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

RZ_API RzAnalysisFunction *rz_analysis_get_function_byname(RzAnalysis *a, const char *name) {
	bool found = false;
	RzAnalysisFunction *f = ht_pp_find(a->ht_name_fun, name, &found);
	if (f && found) {
		return f;
	}
	return NULL;
}

/* rename RzAnalysisFunctionBB.add() */
RZ_API bool rz_analysis_fcn_add_bb(RzAnalysis *a, RzAnalysisFunction *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail, RZ_BORROW RzAnalysisDiff *diff) {
	D eprintf("Add bb\n");
	if (size == 0) {
		eprintf("Warning: empty basic block at 0x%08" PFMT64x " is not allowed.\n", addr);
		rz_warn_if_reached();
		return false;
	}
	if (size > a->opt.bb_max_size) {
		eprintf("Warning: can't allocate such big bb of %" PFMT64d " bytes at 0x%08" PFMT64x "\n", (st64)size, addr);
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
	if (diff) {
		if (!block->diff) {
			block->diff = rz_analysis_diff_new();
		}
		if (block->diff) {
			block->diff->type = diff->type;
			block->diff->addr = diff->addr;
			if (diff->name) {
				RZ_FREE(block->diff->name);
				block->diff->name = strdup(diff->name);
			}
		}
	}
	rz_analysis_block_unref(block);
	return true;
}

RZ_API int rz_analysis_function_loops(RzAnalysisFunction *fcn) {
	RzListIter *iter;
	RzAnalysisBlock *bb;
	ut32 loops = 0;
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->jump != UT64_MAX && bb->jump < bb->addr) {
			loops++;
		}
		if (bb->fail != UT64_MAX && bb->fail < bb->addr) {
			loops++;
		}
	}
	return loops;
}

RZ_API int rz_analysis_function_complexity(RzAnalysisFunction *fcn) {
	/*
        CC = E - N + 2P
        E = the number of edges of the graph.
        N = the number of nodes of the graph.
        P = the number of connected components (exit nodes).
 */
	RzAnalysis *analysis = fcn->analysis;
	int E = 0, N = 0, P = 0;
	RzListIter *iter;
	RzAnalysisBlock *bb;

	rz_list_foreach (fcn->bbs, iter, bb) {
		N++; // nodes
		if ((!analysis || analysis->verbose) && bb->jump == UT64_MAX && bb->fail != UT64_MAX) {
			eprintf("Warning: invalid bb jump/fail pair at 0x%08" PFMT64x " (fcn 0x%08" PFMT64x "\n", bb->addr, fcn->addr);
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

	int result = E - N + (2 * P);
	if (result < 1 && (!analysis || analysis->verbose)) {
		eprintf("Warning: CC = E(%d) - N(%d) + (2 * P(%d)) < 1 at 0x%08" PFMT64x "\n", E, N, P, fcn->addr);
	}
	// rz_return_val_if_fail (result > 0, 0);
	return result;
}

// tfj and afsj call this function
RZ_API char *rz_analysis_function_get_json(RzAnalysisFunction *function) {
	RzAnalysis *a = function->analysis;
	PJ *pj = pj_new();
	unsigned int i;
	RzType *ret_type = rz_type_func_ret(a->typedb, function->name);
	if (!ret_type) {
		return NULL;
	}
	const char *ret_type_str = rz_type_as_string(a->typedb, ret_type);
	int argc = rz_type_func_args_count(a->typedb, function->name);

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
	for (i = 0; i < argc; i++) {
		pj_o(pj);
		const char *arg_name = rz_type_func_args_name(a->typedb, function->name, i);
		RzType *arg_type = rz_type_func_args_type(a->typedb, function->name, i);
		const char *arg_type_str = rz_type_as_string(a->typedb, arg_type);
		pj_ks(pj, "name", arg_name);
		pj_ks(pj, "type", arg_type_str);
		const char *cc_arg = rz_reg_get_name(a->reg, rz_reg_get_name_idx(sdb_fmt("A%d", i)));
		if (cc_arg) {
			pj_ks(pj, "cc", cc_arg);
		}
		pj_end(pj);
	}
	pj_end(pj);
	pj_end(pj);
	return pj_drain(pj);
}

RZ_API RZ_OWN char *rz_analysis_function_get_signature(RzAnalysisFunction *function) {
	RzAnalysis *a = function->analysis;
	const char *realname = NULL, *import_substring = NULL;

	RzFlagItem *flag = a->flag_get(a->flb.f, function->addr);
	// Can't access RZ_FLAGS_FS_IMPORTS, since it is defined in rz_core.h
	if (flag && flag->space && !strcmp(flag->space->name, "imports")) {
		// Get substring after last dot
		import_substring = rz_str_rchr(function->name, NULL, '.');
		if (import_substring) {
			realname = import_substring + 1;
		}
	} else {
		realname = function->name;
	}

	unsigned int i;
	RzType *ret_type = rz_type_func_ret(a->typedb, realname);
	if (!ret_type) {
		return NULL;
	}
	const char *ret_type_str = rz_type_as_string(a->typedb, ret_type);
	int argc = rz_type_func_args_count(a->typedb, realname);

	char *args = strdup("");
	for (i = 0; i < argc; i++) {
		const char *arg_name = rz_type_func_args_name(a->typedb, realname, i);
		RzType *arg_type = rz_type_func_args_type(a->typedb, realname, i);
		const char *arg_type_str = rz_type_as_string(a->typedb, arg_type);
		// Here we check if the type is a pointer, in this case we don't put
		// the space between type and name for the style reasons
		// "char *var" looks much better than "char * var"
		const char *maybe_space = arg_type->kind == RZ_TYPE_KIND_POINTER ? "" : " ";
		char *new_args = (i + 1 == argc)
			? rz_str_newf("%s%s%s%s", args, arg_type_str, maybe_space, arg_name)
			: rz_str_newf("%s%s%s%s, ", args, arg_type_str, maybe_space, arg_name);
		free(args);
		args = new_args;
	}
	char *signature = rz_str_newf("%s %s (%s);", ret_type_str ? ret_type_str : "void", realname, args);
	free(args);
	return signature;
}

/* set function signature from string */
RZ_API int rz_analysis_str_to_fcn(RzAnalysis *a, RzAnalysisFunction *f, const char *sig) {
	rz_return_val_if_fail(a || f || sig, false);
	char *error_msg = NULL;
	int result = rz_type_parse_c_string(a->typedb, sig, &error_msg);
	if (error_msg) {
		eprintf("%s", error_msg);
		free(error_msg);
	}

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

RZ_API int rz_analysis_fcn_count(RzAnalysis *analysis, ut64 from, ut64 to) {
	int n = 0;
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
	const bool is_x86 = analysis->cur->arch && !strcmp(analysis->cur->arch, "x86");
	RzListIter *iter;
	RzAnalysisBlock *bb;
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (addr >= bb->addr && addr < (bb->addr + bb->size) && (!analysis->opt.jmpmid || !is_x86 || rz_analysis_block_op_starts_at(bb, addr))) {
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
	RzListIter *iter;
	RzAnalysisBlock *bb;
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (addr == bb->addr) {
			return bb;
		}
	}
	return NULL;
}

// compute the cyclomatic cost
RZ_API ut32 rz_analysis_function_cost(RzAnalysisFunction *fcn) {
	RzListIter *iter;
	RzAnalysisBlock *bb;
	ut32 totalCycles = 0;
	if (!fcn) {
		return 0;
	}
	RzAnalysis *analysis = fcn->analysis;
	rz_list_foreach (fcn->bbs, iter, bb) {
		RzAnalysisOp op;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc(bb->size);
		if (!buf) {
			continue;
		}
		(void)analysis->iob.read_at(analysis->iob.io, bb->addr, (ut8 *)buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			memset(&op, 0, sizeof(op));
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

RZ_API int rz_analysis_function_count_edges(const RzAnalysisFunction *fcn, RZ_NULLABLE int *ebbs) {
	rz_return_val_if_fail(fcn, 0);
	RzListIter *iter;
	RzAnalysisBlock *bb;
	int edges = 0;
	if (ebbs) {
		*ebbs = 0;
	}
	rz_list_foreach (fcn->bbs, iter, bb) {
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

RZ_API bool rz_analysis_function_purity(RzAnalysisFunction *fcn) {
	if (fcn->has_changed) {
		HtUP *ht = ht_up_new(NULL, NULL, NULL);
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
	RzListIter *iter;
	RzAnalysisBlock *bb;
	char str_to_find[40] = "\"type\":\"reg\",\"value\":\"";
	char *pos;
	strncat(str_to_find, analysis->reg->name[RZ_REG_NAME_BP], 39);
	if (!fcn) {
		return;
	}
	rz_list_foreach (fcn->bbs, iter, bb) {
		RzAnalysisOp op;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc(bb->size);
		if (!buf) {
			continue;
		}
		(void)analysis->iob.read_at(analysis->iob.io, bb->addr, (ut8 *)buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			rz_analysis_op(analysis, &op, at, buf + idx, bb->size - idx, RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_OPEX);
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
				// op.dst is not filled for these operations, so for now, check for bp as dst looks like this; in the future it may be just replaced with call to can_affect_bp
				pos = op.opex.ptr ? strstr(op.opex.ptr, str_to_find) : NULL;
				if (pos && pos - op.opex.ptr < 60) {
					fcn->bp_frame = false;
					rz_analysis_op_fini(&op);
					free(buf);
					return;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_XCHG:
				if (op.opex.ptr && strstr(op.opex.ptr, str_to_find)) {
					fcn->bp_frame = false;
					rz_analysis_op_fini(&op);
					free(buf);
					return;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_POP:
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
	if (!existing_bb || !rz_list_contains(ctx->fcn->bbs, existing_bb)) {
		int old_len = rz_list_length(ctx->fcn->bbs);
		rz_analysis_fcn_bb(ctx->fcn->analysis, ctx->fcn, addr, analysis->opt.depth);
		if (old_len != rz_list_length(ctx->fcn->bbs)) {
			rz_analysis_block_recurse(rz_analysis_get_block_at(analysis, addr), mark_as_visited, user);
		}
	}
	ht_up_insert(ctx->visited, addr, NULL);
	return true;
}

static bool analize_descendents(RzAnalysisBlock *bb, void *user) {
	return rz_analysis_block_successor_addrs_foreach(bb, analize_addr_cb, user);
}

static void free_ht_up(HtUPKv *kv) {
	ht_up_free((HtUP *)kv->value);
}

static void update_varz_analysisysis(RzAnalysisFunction *fcn, int align, ut64 from, ut64 to) {
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
	for (cur_addr = from; cur_addr < to; cur_addr += opsz, len -= opsz) {
		RzAnalysisOp op;
		int ret = rz_analysis_op(analysis->coreb.core, &op, cur_addr, buf, len, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL);
		if (ret < 1 || op.size < 1) {
			rz_analysis_op_fini(&op);
			break;
		}
		opsz = op.size;
		rz_analysis_extract_vars(analysis, fcn, &op);
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
			RzPVector *vars_clone = (RzPVector *)rz_vector_clone((RzVector *)vars);
			void **v;
			rz_pvector_foreach (vars_clone, v) {
				rz_analysis_var_remove_access_at((RzAnalysisVar *)*v, addr);
			}
			rz_pvector_clear(vars_clone);
		}
	}
}

static void update_analysis(RzAnalysis *analysis, RzList *fcns, HtUP *reachable) {
	RzListIter *it, *it2, *tmp;
	RzAnalysisFunction *fcn;
	bool old_jmpmid = analysis->opt.jmpmid;
	analysis->opt.jmpmid = true;
	rz_analysis_fcn_invalidate_read_ahead_cache();
	rz_list_foreach (fcns, it, fcn) {
		// Recurse through blocks of function, mark reachable,
		// analyze edges that don't have a block
		RzAnalysisBlock *bb = rz_analysis_get_block_at(analysis, fcn->addr);
		if (!bb) {
			rz_analysis_fcn_bb(analysis, fcn, fcn->addr, analysis->opt.depth);
			bb = rz_analysis_get_block_at(analysis, fcn->addr);
			if (!bb) {
				continue;
			}
		}
		HtUP *ht = ht_up_new0();
		ht_up_insert(ht, bb->addr, NULL);
		BlockRecurseCtx ctx = { fcn, ht };
		rz_analysis_block_recurse(bb, analize_descendents, &ctx);

		// Remove non-reachable blocks
		rz_list_foreach_safe (fcn->bbs, it2, tmp, bb) {
			if (ht_up_find_kv(ht, bb->addr, NULL)) {
				continue;
			}
			HtUP *o_visited = ht_up_find(reachable, fcn->addr, NULL);
			if (!ht_up_find_kv(o_visited, bb->addr, NULL)) {
				// Avoid removing blocks that were already not reachable
				continue;
			}
			fcn->ninstr -= bb->ninstr;
			rz_analysis_function_remove_block(fcn, bb);
		}

		RzList *bbs = rz_list_clone(fcn->bbs);
		rz_analysis_block_automerge(bbs);
		rz_analysis_function_delete_unused_vars(fcn);
		rz_list_free(bbs);
	}
	analysis->opt.jmpmid = old_jmpmid;
}

static void calc_reachable_and_remove_block(RzList *fcns, RzAnalysisFunction *fcn, RzAnalysisBlock *bb, HtUP *reachable) {
	clear_bb_vars(fcn, bb, bb->addr, bb->addr + bb->size);
	if (!rz_list_contains(fcns, fcn)) {
		rz_list_append(fcns, fcn);

		// Calculate reachable blocks from the start of function
		HtUP *ht = ht_up_new0();
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
	HtUP *reachable = ht_up_new(NULL, free_ht_up, NULL);
	const int align = rz_analysis_archinfo(analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
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
					update_varz_analysisysis(fcn, align, addr > bb->addr ? addr : bb->addr, end_write);
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
	RzListIter *it, *it2, *tmp, *tmp2;
	RzAnalysisBlock *bb;
	RzAnalysisFunction *f;
	RzList *fcns = rz_list_new();
	HtUP *reachable = ht_up_new(NULL, free_ht_up, NULL);
	rz_list_foreach_safe (fcn->bbs, it, tmp, bb) {
		if (rz_analysis_block_was_modified(bb)) {
			rz_list_foreach_safe (bb->fcns, it2, tmp2, f) {
				calc_reachable_and_remove_block(fcns, f, bb, reachable);
			}
		}
	}
	update_analysis(fcn->analysis, fcns, reachable);
	ht_up_free(reachable);
	rz_list_free(fcns);
}

static int typecmp(const void *a, const void *b) {
	return strcmp(a, b);
}

RZ_API RZ_OWN RzList *rz_analysis_types_from_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzListIter *iter;
	RzAnalysisVar *var;
	RzList *list = rz_analysis_var_all_list(analysis, fcn);
	RzList *type_used = rz_list_new();
	rz_list_foreach (list, iter, var) {
		rz_list_append(type_used, var->type);
	}
	RzList *uniq = rz_list_uniq(type_used, typecmp);
	rz_list_free(type_used);
	rz_list_free(list);
	return uniq;
}
