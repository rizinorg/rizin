// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_anal.h>
#include <rz_parse.h>
#include <rz_util.h>
#include <rz_list.h>

#define READ_AHEAD 1
#define SDB_KEY_BB "bb.0x%"PFMT64x ".0x%"PFMT64x
// XXX must be configurable by the user
#define JMPTBLSZ 512
#define JMPTBL_LEA_SEARCH_SZ 64
#define JMPTBL_MAXFCNSIZE 4096
#define BB_ALIGN 0x10
#define MAX_SCAN_SIZE 0x7ffffff

/* speedup analysis by removing some function overlapping checks */
#define JAYRO_04 1

// 16 KB is the maximum size for a basic block
#define MAX_FLG_NAME_SIZE 64

#define FIX_JMP_FWD 0
#define D if (a->verbose)

// 64KB max size
// 256KB max function size
#define MAX_FCN_SIZE (1024 * 256)

#define DB a->sdb_fcns
#define EXISTS(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__), sdb_exists (DB, key)
#define SETKEY(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__);

typedef struct fcn_tree_iter_t {
	int len;
	RBNode *cur;
	RBNode *path[RZ_RBTREE_MAX_HEIGHT];
} FcnTreeIter;

RZ_API const char *rz_anal_fcntype_tostring(int type) {
	switch (type) {
	case RZ_ANAL_FCN_TYPE_NULL: return "null";
	case RZ_ANAL_FCN_TYPE_FCN: return "fcn";
	case RZ_ANAL_FCN_TYPE_LOC: return "loc";
	case RZ_ANAL_FCN_TYPE_SYM: return "sym";
	case RZ_ANAL_FCN_TYPE_IMP: return "imp";
	case RZ_ANAL_FCN_TYPE_INT: return "int"; // interrupt
	case RZ_ANAL_FCN_TYPE_ROOT: return "root";
	}
	return "unk";
}

#if READ_AHEAD
static ut64 cache_addr = UT64_MAX;

// TODO: move into io :?
static int read_ahead(RzAnal *anal, ut64 addr, ut8 *buf, int len) {
	static ut8 cache[1024];
	const int cache_len = sizeof (cache);

	if (len < 1) {
		return 0;
	}
	if (len > cache_len) {
		int a = anal->iob.read_at (anal->iob.io, addr, buf, len); // double read
		memcpy (cache, buf, cache_len);
		cache_addr = addr;
		return a;
	}

	ut64 addr_end = UT64_ADD_OVFCHK (addr, len)? UT64_MAX: addr + len;
	ut64 cache_addr_end = UT64_ADD_OVFCHK (cache_addr, cache_len)? UT64_MAX: cache_addr + cache_len;
	bool isCached = ((addr != UT64_MAX) && (addr >= cache_addr) && (addr_end < cache_addr_end));
	if (isCached) {
		memcpy (buf, cache + (addr - cache_addr), len);
	} else {
		anal->iob.read_at (anal->iob.io, addr, cache, sizeof (cache));
		memcpy (buf, cache, len);
		cache_addr = addr;
	}
	return len;
}
#else
static int read_ahead(RzAnal *anal, ut64 addr, ut8 *buf, int len) {
	return anal->iob.read_at (anal->iob.io, addr, buf, len);
}
#endif

RZ_API void rz_anal_fcn_invalidate_read_ahead_cache(void) {
#if READ_AHEAD
	cache_addr = UT64_MAX;
#endif
}

static int cmpaddr(const void *_a, const void *_b) {
	const RzAnalBlock *a = _a, *b = _b;
	return a->addr > b->addr ? 1 : (a->addr < b->addr ? -1 : 0);
}

RZ_API int rz_anal_function_resize(RzAnalFunction *fcn, int newsize) {
	RzAnal *anal = fcn->anal;
	RzAnalBlock *bb;
	RzListIter *iter, *iter2;

	rz_return_val_if_fail (fcn, false);

	if (newsize < 1) {
		return false;
	}

	// XXX this is something we should probably do for all the archs
	bool is_arm = anal->cur->arch && !strncmp (anal->cur->arch, "arm", 3);
	if (is_arm) {
		return true;
	}

	ut64 eof = fcn->addr + newsize;
	rz_list_foreach_safe (fcn->bbs, iter, iter2, bb) {
		if (bb->addr >= eof) {
			rz_anal_function_remove_block (fcn, bb);
			continue;
		}
		if (bb->addr + bb->size >= eof) {
			rz_anal_block_set_size (bb, eof - bb->addr);
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
static RzAnalBlock *fcn_append_basic_block(RzAnal *anal, RzAnalFunction *fcn, ut64 addr) {
	RzAnalBlock *bb = rz_anal_create_block (anal, addr, 0);
	if (!bb) {
		return NULL;
	}
	rz_anal_function_add_block (fcn, bb);
	bb->stackptr = fcn->stack;
	bb->parent_stackptr = fcn->stack;
	return bb;
}

#define gotoBeach(x) ret = x; goto beach;

static bool isInvalidMemory(RzAnal *anal, const ut8 *buf, int len) {
	if (anal->opt.nonull > 0) {
		int i;
		const int count = RZ_MIN (len, anal->opt.nonull);
		for (i = 0; i < count; i++) {
			if (buf[i]) {
				break;
			}
		}
		if (i == count) {
			return true;
		}
	}
	return !memcmp (buf, "\xff\xff\xff\xff", RZ_MIN (len, 4));
}

static bool isSymbolNextInstruction(RzAnal *anal, RzAnalOp *op) {
	rz_return_val_if_fail (anal && op && anal->flb.get_at, false);

	RzFlagItem *fi = anal->flb.get_at (anal->flb.f, op->addr + op->size, false);
	return (fi && fi->name && (strstr (fi->name, "imp.") || strstr (fi->name, "sym.")
			|| strstr (fi->name, "entry") || strstr (fi->name, "main")));
}

static bool is_delta_pointer_table(RzAnal *anal, RzAnalFunction *fcn, ut64 addr, ut64 lea_ptr, ut64 *jmptbl_addr, ut64 *casetbl_addr, RzAnalOp *jmp_aop) {
	int i;
	ut64 dst;
	st32 jmptbl[64] = {0};
	/* check if current instruction is followed by an ujmp */
	ut8 buf[JMPTBL_LEA_SEARCH_SZ];
	RzAnalOp *aop = jmp_aop;
	RzAnalOp omov_aop = {0};
	RzAnalOp mov_aop = {0};
	RzAnalOp add_aop = {0};
	RzRegItem *reg_src = NULL, *o_reg_dst = NULL;
	RzAnalValue cur_scr, cur_dst = { 0 };
	read_ahead (anal, addr, (ut8*)buf, sizeof (buf));
	bool isValid = false;
	for (i = 0; i + 8 < JMPTBL_LEA_SEARCH_SZ; i++) {
		ut64 at = addr + i;
		int left = JMPTBL_LEA_SEARCH_SZ - i;
		int len = rz_anal_op (anal, aop, at, buf + i, left, RZ_ANAL_OP_MASK_BASIC | RZ_ANAL_OP_MASK_HINT | RZ_ANAL_OP_MASK_VAL);
		if (len < 1) {
			len = 1;
		}
		if (aop->type == RZ_ANAL_OP_TYPE_UJMP || aop->type == RZ_ANAL_OP_TYPE_RJMP) {
			isValid = true;
			break;
		}
		if (aop->type == RZ_ANAL_OP_TYPE_MOV) {
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
		if (aop->type == RZ_ANAL_OP_TYPE_ADD) {
			add_aop = *aop;
		}
		rz_anal_op_fini (aop);
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
	if (mov_aop.type && add_aop.type && mov_aop.addr < add_aop.addr && add_aop.addr < jmp_aop->addr
	    && mov_aop.disp && mov_aop.disp != UT64_MAX) {
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
	read_ahead (anal, *jmptbl_addr, (ut8 *)&jmptbl, 64);
	for (i = 0; i < 3; i++) {
		dst = lea_ptr + (st32)rz_read_le32 (jmptbl);
		if (!anal->iob.is_valid_offset (anal->iob.io, dst, 0)) {
			return false;
		}
		if (dst > fcn->addr + JMPTBL_MAXFCNSIZE) {
			return false;
		}
		if (anal->opt.jmpabove && dst < (fcn->addr < JMPTBL_MAXFCNSIZE ? 0 : fcn->addr - JMPTBL_MAXFCNSIZE)) {
			return false;
		}
	}
	return true;
}

static ut64 try_get_cmpval_from_parents(RzAnal * anal, RzAnalFunction *fcn, RzAnalBlock *my_bb, const char * cmp_reg) {
	rz_return_val_if_fail (fcn && fcn->bbs && cmp_reg, UT64_MAX);
	RzListIter *iter;
	RzAnalBlock *tmp_bb;
	rz_list_foreach (fcn->bbs, iter, tmp_bb) {
		if (tmp_bb->jump == my_bb->addr || tmp_bb->fail == my_bb->addr) {
			if (tmp_bb->cmpreg == cmp_reg) {
				if (tmp_bb->cond) {
					if (tmp_bb->cond->type == RZ_ANAL_COND_HI || tmp_bb->cond->type == RZ_ANAL_COND_GT) {
						return tmp_bb->cmpval + 1;
					}
				}
				return tmp_bb->cmpval;
			}
		}
	}
	return UT64_MAX;
}

static bool regs_exist(RzAnalValue *src, RzAnalValue *dst) {
	rz_return_val_if_fail (src && dst, false);
	return src->reg && dst->reg && src->reg->name && dst->reg->name;
}

// 0 if not skipped; 1 if skipped; 2 if skipped before
static int skip_hp(RzAnal *anal, RzAnalFunction *fcn, RzAnalOp *op, RzAnalBlock *bb, ut64 addr,
                   char *tmp_buf, int oplen, int un_idx, int *idx) {
	// this step is required in order to prevent infinite recursion in some cases
	if ((addr + un_idx - oplen) == fcn->addr) {
		// use addr instead of op->addr to mark repeat
		if (!anal->flb.exist_at (anal->flb.f, "skip", 4, addr)) {
			snprintf (tmp_buf + 5, MAX_FLG_NAME_SIZE - 6, "%"PFMT64u, addr);
			anal->flb.set (anal->flb.f, tmp_buf, addr, oplen);
			fcn->addr += oplen;
			rz_anal_block_relocate (bb, bb->addr + oplen, bb->size - oplen);
			*idx = un_idx;
			return 1;
		}
		return 2;
	}
	return 0;
}

static bool purity_checked(HtUP *ht, RzAnalFunction *fcn) {
	bool checked;
	ht_up_find (ht, fcn->addr, &checked);
	return checked;
}

/*
 * Checks whether a given function is pure and sets its 'is_pure' field.
 * This function marks fcn 'not pure' if fcn, or any function called by fcn, accesses data
 * from outside, even if it only READS it.
 * Probably worth changing it in the future, so that it marks fcn 'impure' only when it
 * (or any function called by fcn) MODIFIES external data.
 */
static void check_purity(HtUP *ht, RzAnalFunction *fcn) {
	RzListIter *iter;
	RzList *refs = rz_anal_function_get_refs (fcn);
	RzAnalRef *ref;
	ht_up_insert (ht, fcn->addr, NULL);
	fcn->is_pure = true;
	rz_list_foreach (refs, iter, ref) {
		if (ref->type == RZ_ANAL_REF_TYPE_CALL || ref->type == RZ_ANAL_REF_TYPE_CODE) {
			RzAnalFunction *called_fcn = rz_anal_get_fcn_in (fcn->anal, ref->addr, 0);
			if (!called_fcn) {
				continue;
			}
			if (!purity_checked (ht, called_fcn)) {
				check_purity (ht, called_fcn);
			}
			if (!called_fcn->is_pure) {
				fcn->is_pure = false;
				break;
			}
		}
		if (ref->type == RZ_ANAL_REF_TYPE_DATA) {
			fcn->is_pure = false;
			break;
		}
	}
	rz_list_free (refs);
}

typedef struct {
	ut64 op_addr;
	ut64 leaddr;
} leaddr_pair;

static RzAnalBlock *bbget(RzAnal *anal, ut64 addr, bool jumpmid) {
	RzList *intersecting = rz_anal_get_blocks_in (anal, addr);
	RzListIter *iter;
	RzAnalBlock *bb;

	RzAnalBlock *ret = NULL;
	rz_list_foreach (intersecting, iter, bb) {
		ut64 eaddr = bb->addr + bb->size;
		if (((bb->addr >= eaddr && addr == bb->addr)
		     || rz_anal_block_contains (bb, addr))
		    && (!jumpmid || rz_anal_block_op_starts_at (bb, addr))) {
			if (anal->opt.delay) {
				ut8 *buf = malloc (bb->size);
				if (anal->iob.read_at (anal->iob.io, bb->addr, buf, bb->size)) {
					const int last_instr_idx = bb->ninstr - 1;
					bool in_delay_slot = false;
					int i;
					for (i = last_instr_idx; i >= 0; i--) {
						const ut64 off = rz_anal_bb_offset_inst (bb, i);
						const ut64 at = bb->addr + off;
						if (addr <= at || off >= bb->size) {
							continue;
						}
						RzAnalOp op;
						int size = rz_anal_op (anal, &op, at, buf + off, bb->size - off, RZ_ANAL_OP_MASK_BASIC);
						if (size > 0 && op.delay) {
							if (op.delay >= last_instr_idx - i) {
								in_delay_slot = true;
							}
							rz_anal_op_fini (&op);
							break;
						}
						rz_anal_op_fini (&op);
					}
					if (in_delay_slot) {
						free (buf);
						continue;
					}
				}
				free (buf);
			}
			ret = bb;
			break;
		}
	}
	rz_list_free (intersecting);
	return ret;
}

typedef struct {
	RzAnalFunction *fcn;
	const int stack_diff;
} BlockTakeoverCtx;

static bool fcn_takeover_block_recursive_followthrough_cb(RzAnalBlock *block, void *user) {
	BlockTakeoverCtx *ctx = user;
	RzAnalFunction *our_fcn = ctx->fcn;
	rz_anal_block_ref (block);
	while (!rz_list_empty (block->fcns)) {
		RzAnalFunction *other_fcn = rz_list_first (block->fcns);
		if (other_fcn->addr == block->addr) {
			return false;
		}
		// Steal vars from this block
		size_t i;
		for (i = 0; i + 1 < block->ninstr; i++) {
			const ut64 addr = rz_anal_bb_opaddr_i (block, i);
			RzPVector *vars_used = rz_anal_function_get_vars_used_at (other_fcn, addr);
			if (!vars_used) {
				continue;
			}
			// vars_used will get modified if rz_anal_var_remove_access_at gets called
			RzPVector *cloned_vars_used = (RzPVector *)rz_vector_clone ((RzVector *)vars_used);
			void **it;
			rz_pvector_foreach (cloned_vars_used, it) {
				RzAnalVar *other_var = *it;
				const int actual_delta = other_var->kind == RZ_ANAL_VAR_KIND_SPV
					? other_var->delta + ctx->stack_diff
					: other_var->delta + (other_fcn->bp_off - our_fcn->bp_off);
				RzAnalVar *our_var = rz_anal_function_get_var (our_fcn, other_var->kind, actual_delta);
				if (!our_var) {
					our_var = rz_anal_function_set_var (our_fcn, actual_delta, other_var->kind, other_var->type, 0, other_var->isarg, other_var->name);
				}
				if (our_var) {
					RzAnalVarAccess *acc = rz_anal_var_get_access_at (other_var, addr);
					rz_anal_var_set_access (our_var, acc->reg, addr, acc->type, acc->stackptr);
				}
				rz_anal_var_remove_access_at (other_var, addr);
				if (rz_vector_empty (&other_var->accesses)) {
					rz_anal_function_delete_var (other_fcn, other_var);
				}
			}
			rz_pvector_free (cloned_vars_used);
		}

		// TODO: remove block->ninstr from other_fcn considering delay slots
		rz_anal_function_remove_block (other_fcn, block);
	}
	block->stackptr -= ctx->stack_diff;
	block->parent_stackptr -= ctx->stack_diff;
	rz_anal_function_add_block (our_fcn, block);
	// TODO: add block->ninstr from our_fcn considering delay slots
	our_fcn += block->ninstr;
	rz_anal_block_unref (block);
	return true;
}

// Remove block and all of its recursive successors from all its functions and add them only to fcn
static void fcn_takeover_block_recursive(RzAnalFunction *fcn, RzAnalBlock *start_block) {
	BlockTakeoverCtx ctx = { fcn, start_block->parent_stackptr - fcn->stack};
	rz_anal_block_recurse_followthrough (start_block, fcn_takeover_block_recursive_followthrough_cb, &ctx);
}

static const char *retpoline_reg(RzAnal *anal, ut64 addr) {
	RzFlagItem *flag = anal->flag_get (anal->flb.f, addr);
	if (flag) {
		const char *token = "x86_indirect_thunk_";
		const char *thunk = strstr (flag->name, token);
		if (thunk) {
			return thunk + strlen (token);
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

static void analyze_retpoline(RzAnal *anal, RzAnalOp *op) {
	if (anal->opt.retpoline) {
		const char *rr = retpoline_reg (anal, op->jump);
		if (rr) {
			op->type = RZ_ANAL_OP_TYPE_RJMP;
			op->reg = rr;
		}
	}
}

static inline bool op_is_set_bp(RzAnalOp *op, const char *bp_reg, const char *sp_reg) {
	bool has_dst_reg = op->dst && op->dst->reg && op->dst->reg->name;
	bool has_src_reg = op->src[0] && op->src[0]->reg && op->src[0]->reg->name;
	if (has_dst_reg && has_src_reg) {
		return !strcmp (bp_reg, op->dst->reg->name) && !strcmp (sp_reg, op->src[0]->reg->name);
	}
	return false;
}

static inline bool does_arch_destroys_dst(const char *arch) {
	return arch && (!strncmp (arch, "arm", 3) || !strcmp (arch, "riscv") || !strcmp (arch, "ppc"));
}

static int fcn_recurse(RzAnal *anal, RzAnalFunction *fcn, ut64 addr, ut64 len, int depth) {
	const int continue_after_jump = anal->opt.afterjmp;
	const int addrbytes = anal->iob.io ? anal->iob.io->addrbytes : 1;
	char *last_reg_mov_lea_name = NULL;
	RzAnalBlock *bb = NULL;
	RzAnalBlock *bbg = NULL;
	int ret = RZ_ANAL_RET_END, skip_ret = 0;
	bool overlapped = false;
	RzAnalOp op = {0};
	int oplen, idx = 0;
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
	bool arch_destroys_dst = does_arch_destroys_dst (anal->cur->arch);
	bool is_arm = anal->cur->arch && !strncmp (anal->cur->arch, "arm", 3);
	char tmp_buf[MAX_FLG_NAME_SIZE + 5] = "skip";
	bool is_x86 = is_arm ? false: anal->cur->arch && !strncmp (anal->cur->arch, "x86", 3);
	bool is_amd64 = is_x86 ? fcn->cc && !strcmp (fcn->cc, "amd64") : false;
	bool is_dalvik = is_x86? false: anal->cur->arch && !strncmp (anal->cur->arch, "dalvik", 6);
	RzRegItem *variadic_reg = NULL;
	if (is_amd64) {
		variadic_reg = rz_reg_get (anal->reg, "rax", RZ_REG_TYPE_GPR);
	}
	bool has_variadic_reg = !!variadic_reg;

	if (rz_cons_is_breaked ()) {
		return RZ_ANAL_RET_END;
	}
	if (anal->sleep) {
		rz_sys_usleep (anal->sleep);
	}

	if (depth < 1) {
		if (anal->verbose) {
			eprintf ("Anal went too deep at address 0x%"PFMT64x ".\n", addr);
		}
		return RZ_ANAL_RET_ERROR; // MUST BE TOO DEEP
	}

	// check if address is readable //:
	if (!anal->iob.is_valid_offset (anal->iob.io, addr, 0)) {
		if (addr != UT64_MAX && !anal->iob.io->va) {
			if (anal->verbose) {
				eprintf ("Invalid address 0x%"PFMT64x ". Try with io.va=true\n", addr);
			}
		}
		return RZ_ANAL_RET_ERROR; // MUST BE TOO DEEP
	}

	RzAnalFunction *fcn_at_addr = rz_anal_get_function_at (anal, addr);
	if (fcn_at_addr && fcn_at_addr != fcn) {
		return RZ_ANAL_RET_ERROR; // MUST BE NOT FOUND
	}

	RzAnalBlock *existing_bb = bbget (anal, addr, anal->opt.jmpmid && is_x86);
	if (existing_bb) {
		bool existing_in_fcn = rz_list_contains (existing_bb->fcns, fcn);
		existing_bb = rz_anal_block_split (existing_bb, addr);
		if (!existing_in_fcn && existing_bb) {
			if (existing_bb->addr == fcn->addr) {
				// our function starts directly there, so we steal what is ours!
				fcn_takeover_block_recursive (fcn, existing_bb);
			}
		}
		if (existing_bb) {
			rz_anal_block_unref (existing_bb);
		}
		if (anal->opt.recont) {
			return RZ_ANAL_RET_END;
		}
		if (anal->verbose) {
			eprintf ("rz_anal_fcn_bb() fails at 0x%"PFMT64x ".\n", addr);
		}
		return RZ_ANAL_RET_ERROR; // MUST BE NOT DUP
	}

	bb = fcn_append_basic_block (anal, fcn, addr);
	// we checked before whether there is a bb at addr, so the create should have succeeded
	rz_return_val_if_fail (bb, RZ_ANAL_RET_ERROR);

	if (!anal->leaddrs) {
		anal->leaddrs = rz_list_newf (free);
		if (!anal->leaddrs) {
			eprintf ("Cannot create leaddr list\n");
			gotoBeach (RZ_ANAL_RET_ERROR);
		}
	}
	static ut64 lea_jmptbl_ip = UT64_MAX;
	ut64 last_reg_mov_lea_val = UT64_MAX;
	bool last_is_reg_mov_lea = false;
	bool last_is_push = false;
	bool last_is_mov_lr_pc = false;
	ut64 last_push_addr = UT64_MAX;
	if (anal->limit && addr + idx < anal->limit->from) {
		gotoBeach (RZ_ANAL_RET_END);
	}
	RzAnalFunction *tmp_fcn = rz_anal_get_fcn_in (anal, addr, 0);
	if (tmp_fcn) {
		// Checks if var is already analyzed at given addr
		RzList *list = rz_anal_var_all_list (anal, tmp_fcn);
		if (!rz_list_empty (list)) {
			varset = true;
		}
		rz_list_free (list);
	}
	ut64 movdisp = UT64_MAX; // used by jmptbl when coded as "mov reg,[R*4+B]"
	ut8 buf[32]; // 32 bytes is enough to hold any instruction.
	int maxlen = len * addrbytes;
	if (is_dalvik) {
		bool skipAnalysis = false;
		if (!strncmp (fcn->name, "sym.", 4)) {
			if (!strncmp (fcn->name + 4, "imp.", 4)) {
				skipAnalysis = true;
			} else if (strstr (fcn->name, "field")) {
				skipAnalysis = true;
			}
		}
		if (skipAnalysis) {
			ret = 0;
			gotoBeach (RZ_ANAL_RET_END);
		}
	}
	if ((maxlen - (addrbytes * idx)) > MAX_SCAN_SIZE) {
		if (anal->verbose) {
			eprintf ("Warning: Skipping large memory region.\n");
		}
		maxlen = 0;
	}

	while (addrbytes * idx < maxlen) {
		if (!last_is_reg_mov_lea) {
			free (last_reg_mov_lea_name);
			last_reg_mov_lea_name = NULL;
		}
		if (anal->limit && anal->limit->to <= addr + idx) {
			break;
		}
repeat:
		if (rz_cons_is_breaked ()) {
			break;
		}
		ut32 at_delta = addrbytes * idx;
		ut64 at = addr + at_delta;
		ut64 bytes_read = RZ_MIN (len - at_delta, sizeof (buf));
		ret = read_ahead (anal, at, buf, bytes_read);

		if (ret < 0) {
			eprintf ("Failed to read\n");
			break;
		}
		if (isInvalidMemory (anal, buf, bytes_read)) {
			if (anal->verbose) {
				eprintf ("Warning: FFFF opcode at 0x%08"PFMT64x "\n", at);
			}
			gotoBeach (RZ_ANAL_RET_ERROR)
		}
		rz_anal_op_fini (&op);
		if ((oplen = rz_anal_op (anal, &op, at, buf, bytes_read, RZ_ANAL_OP_MASK_ESIL | RZ_ANAL_OP_MASK_VAL | RZ_ANAL_OP_MASK_HINT)) < 1) {
			if (anal->verbose) {
				eprintf ("Invalid instruction at 0x%"PFMT64x" with %d bits\n", at, anal->bits);
			}
			// gotoBeach (RZ_ANAL_RET_ERROR);
			// RET_END causes infinite loops somehow
			gotoBeach (RZ_ANAL_RET_END);
		}
		const char *bp_reg = anal->reg->name[RZ_REG_NAME_BP];
		const char *sp_reg = anal->reg->name[RZ_REG_NAME_SP];
		bool has_stack_regs = bp_reg && sp_reg;

		if (anal->opt.nopskip && fcn->addr == at) {
			RzFlagItem *fi = anal->flb.get_at (anal->flb.f, addr, false);
			if (!fi || strncmp (fi->name, "sym.", 4)) {
				if ((addr + delay.un_idx - oplen) == fcn->addr) {
					if (rz_anal_block_relocate (bb, bb->addr + oplen, bb->size - oplen)) {
						fcn->addr += oplen;
						idx = delay.un_idx;
						goto repeat;
					}
				}
			}
			switch (op.type & RZ_ANAL_OP_TYPE_MASK) {
			case RZ_ANAL_OP_TYPE_TRAP:
			case RZ_ANAL_OP_TYPE_ILL:
			case RZ_ANAL_OP_TYPE_NOP:
				if (rz_anal_block_relocate (bb, at + op.size, bb->size)) {
					addr = at + op.size;
					fcn->addr = addr;
					goto repeat;
				}
			}
		}
		if (op.hint.new_bits) {
			rz_anal_hint_set_bits (anal, op.jump, op.hint.new_bits);
		}
		if (idx > 0 && !overlapped) {
			bbg = bbget (anal, at, anal->opt.jmpmid && is_x86);
			if (bbg && bbg != bb) {
				bb->jump = at;
				if (anal->opt.jmpmid && is_x86) {
					// This happens when we purposefully walked over another block and overlapped it
					// and now we hit an offset where the instructions match again.
					// So we need to split the overwalked block.
					RzAnalBlock *split = rz_anal_block_split (bbg, at);
					rz_anal_block_unref (split);
				}
				overlapped = true;
				if (anal->verbose) {
					eprintf ("Overlapped at 0x%08"PFMT64x "\n", at);
				}
			}
		}
		if (!overlapped) {
			ut64 newbbsize = bb->size + oplen;
			if (newbbsize > MAX_FCN_SIZE) {
				gotoBeach (RZ_ANAL_RET_ERROR);
			}
			rz_anal_bb_set_offset (bb, bb->ninstr++, at - bb->addr);
			rz_anal_block_set_size (bb, newbbsize);
			fcn->ninstr++;
		}
		if (anal->opt.trycatch) {
			const char *name = anal->coreb.getName (anal->coreb.core, at);
			if (name) {
				if (rz_str_startswith (name, "try.") && rz_str_endswith (name, ".from")) {
					char *handle = strdup (name);
					// handle = rz_str_replace (handle, ".from", ".to", 0);
					ut64 from_addr = anal->coreb.numGet (anal->coreb.core, handle);
					handle = rz_str_replace (handle, ".from", ".catch", 0);
					ut64 handle_addr = anal->coreb.numGet (anal->coreb.core, handle);
					bb->jump = at + oplen;
					if (from_addr != bb->addr) {
						bb->fail = handle_addr;
						ret = rz_anal_fcn_bb (anal, fcn, handle_addr, depth);
						eprintf ("(%s) 0x%08"PFMT64x"\n", handle, handle_addr);
						if (bb->size == 0) {
							rz_anal_function_remove_block (fcn, bb);
						}
						rz_anal_block_unref (bb);
						bb = fcn_append_basic_block (anal, fcn, addr);
						if (!bb) {
							gotoBeach (RZ_ANAL_RET_ERROR);
						}
					}
				}
			}
		}
		idx += oplen;
		delay.un_idx = idx;
		if (anal->opt.delay && op.delay > 0 && !delay.pending) {
			// Handle first pass through a branch delay jump:
			// Come back and handle the current instruction later.
			// Save the location of it in `delay.idx`
			// note, we have still increased size of basic block
			// (and function)
			if (anal->verbose) {
				eprintf("Enter branch delay at 0x%08"PFMT64x ". bb->sz=%"PFMT64u"\n", at - oplen, bb->size);
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
				if (anal->verbose) {
					eprintf("Last branch delayed opcode at 0x%08"PFMT64x ". bb->sz=%"PFMT64u"\n", addr + idx - oplen, bb->size);
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
			if (anal->verbose) {
				eprintf ("Revisit branch delay jump at 0x%08"PFMT64x ". bb->sz=%"PFMT64u"\n", addr + idx - oplen, bb->size);
			}
			// This is the second pass of the branch delaying opcode
			// But we also already counted this instruction in the
			// size of the current basic block, so we need to fix that
			if (delay.adjust) {
				rz_anal_block_set_size (bb, (ut64)addrbytes * (ut64)delay.after);
				fcn->ninstr--;
				if (anal->verbose) {
					eprintf ("Correct for branch delay @ %08"PFMT64x " bb.addr=%08"PFMT64x " corrected.bb=%"PFMT64u" f.uncorr=%"PFMT64u"\n",
					addr + idx - oplen, bb->addr, bb->size, rz_anal_function_linear_size (fcn));
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
		case RZ_ANAL_STACK_INC:
			if (RZ_ABS (op.stackptr) < 8096) {
				fcn->stack += op.stackptr;
				if (fcn->stack > fcn->maxstack) {
					fcn->maxstack = fcn->stack;
				}
			}
			bb->stackptr += op.stackptr;
			break;
		case RZ_ANAL_STACK_RESET:
			bb->stackptr = 0;
			break;
		default:
			break;
		}
		if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
			// swapped parameters wtf
			rz_anal_xrefs_set (anal, op.addr, op.ptr, RZ_ANAL_REF_TYPE_DATA);
		}
		analyze_retpoline (anal, &op);
		switch (op.type & RZ_ANAL_OP_TYPE_MASK) {
		case RZ_ANAL_OP_TYPE_CMOV:
		case RZ_ANAL_OP_TYPE_MOV:
			last_is_reg_mov_lea = false;
			if (is_arm) { // mov lr, pc
				const char *esil = rz_strbuf_get (&op.esil);
				if (!rz_str_cmp (esil, "pc,lr,=", -1)) {
					last_is_mov_lr_pc = true;
				}
			}
			if (has_stack_regs && op_is_set_bp (&op, bp_reg, sp_reg)) {
				fcn->bp_off = fcn->stack;
			}
			// Is this a mov of immediate value into a register?
			if (op.dst && op.dst->reg && op.dst->reg->name && op.val > 0 && op.val != UT64_MAX) {
				free (last_reg_mov_lea_name);
				if ((last_reg_mov_lea_name = strdup (op.dst->reg->name))) {
					last_reg_mov_lea_val = op.val;
					last_is_reg_mov_lea = true;
				}
			}
			// skip mov reg, reg
			if (anal->opt.jmptbl) {
				if (op.scale && op.ireg) {
					movdisp = op.disp;
				}
			}
			if (anal->opt.hpskip && regs_exist (op.src[0], op.dst)
			&& !strcmp (op.src[0]->reg->name, op.dst->reg->name)) {
				skip_ret = skip_hp (anal, fcn, &op, bb, addr, tmp_buf, oplen, delay.un_idx, &idx);
				if (skip_ret == 1) {
					goto repeat;
				}
				if (skip_ret == 2) {
					gotoBeach (RZ_ANAL_RET_END);
				}
			}
			break;
		case RZ_ANAL_OP_TYPE_LEA:
			last_is_reg_mov_lea = false;
			// if first byte in op.ptr is 0xff, then set leaddr assuming its a jumptable
			{
				ut8 buf[4];
				anal->iob.read_at (anal->iob.io, op.ptr, buf, sizeof (buf));
				if ((buf[2] == 0xff || buf[2] == 0xfe) && buf[3] == 0xff) {
					leaddr_pair *pair = RZ_NEW (leaddr_pair);
					if (!pair) {
						eprintf ("Cannot create leaddr_pair\n");
						gotoBeach (RZ_ANAL_RET_ERROR);
					}
					pair->op_addr = op.addr;
					pair->leaddr = op.ptr; // XXX movdisp is dupped but seems to be trashed sometimes(?), better track leaddr separately
					rz_list_append (anal->leaddrs, pair);
				}
				if (has_stack_regs && op_is_set_bp (&op, bp_reg, sp_reg)) {
					fcn->bp_off = fcn->stack - op.src[0]->delta;
				}
				if (op.dst && op.dst->reg && op.dst->reg->name && op.ptr > 0 && op.ptr != UT64_MAX) {
					free (last_reg_mov_lea_name);
					if ((last_reg_mov_lea_name = strdup (op.dst->reg->name))) {
						last_reg_mov_lea_val = op.ptr;
						last_is_reg_mov_lea = true;
					}
				}
			}
			// skip lea reg,[reg]
			if (anal->opt.hpskip && regs_exist (op.src[0], op.dst)
			&& !strcmp (op.src[0]->reg->name, op.dst->reg->name)) {
				skip_ret = skip_hp (anal, fcn, &op, bb, at, tmp_buf, oplen, delay.un_idx, &idx);
				if (skip_ret == 1) {
					goto repeat;
				}
				if (skip_ret == 2) {
					gotoBeach (RZ_ANAL_RET_END);
				}
			}
			if (anal->opt.jmptbl) {
				RzAnalOp jmp_aop = {0};
				ut64 jmptbl_addr = op.ptr;
				ut64 casetbl_addr = op.ptr;
				if (is_delta_pointer_table (anal, fcn, op.addr, op.ptr, &jmptbl_addr, &casetbl_addr, &jmp_aop)) {
					ut64 table_size, default_case = 0;
					// we require both checks here since try_get_jmptbl_info uses
					// BB info of the final jmptbl jump, which is no present with
					// is_delta_pointer_table just scanning ahead
					// try_get_delta_jmptbl_info doesn't work at times where the
					// lea comes after the cmp/default case cjmp, which can be
					// handled with try_get_jmptbl_info
					if (try_get_jmptbl_info (anal, fcn, jmp_aop.addr, bb, &table_size, &default_case)
						|| try_get_delta_jmptbl_info (anal, fcn, jmp_aop.addr, op.addr, &table_size, &default_case)) {
						ret = casetbl_addr == op.ptr
							? try_walkthrough_jmptbl (anal, fcn, bb, depth, jmp_aop.addr, jmptbl_addr, op.ptr, 4, table_size, default_case, 4)
							: try_walkthrough_casetbl (anal, fcn, bb, depth, jmp_aop.addr, jmptbl_addr, casetbl_addr, op.ptr, 4, table_size, default_case, 4);
						if (ret) {
							lea_jmptbl_ip = jmp_aop.addr;
						}
					}
				}
				rz_anal_op_fini (&jmp_aop);
			}
			break;
		case RZ_ANAL_OP_TYPE_LOAD:
			if (anal->opt.loads) {
				if (anal->iob.is_valid_offset (anal->iob.io, op.ptr, 0)) {
					rz_meta_set (anal, RZ_META_TYPE_DATA, op.ptr, 4, "");
				}
			}
			break;
			// Case of valid but unused "add [rax], al"
		case RZ_ANAL_OP_TYPE_ADD:
			if (anal->opt.ijmp) {
				if ((op.size + 4 <= bytes_read) && !memcmp (buf + op.size, "\x00\x00\x00\x00", 4)) {
					rz_anal_block_set_size (bb, bb->size - oplen);
					op.type = RZ_ANAL_OP_TYPE_RET;
					gotoBeach (RZ_ANAL_RET_END);
				}
			}
			break;
		case RZ_ANAL_OP_TYPE_ILL:
			gotoBeach (RZ_ANAL_RET_END);
		case RZ_ANAL_OP_TYPE_TRAP:
			gotoBeach (RZ_ANAL_RET_END);
		case RZ_ANAL_OP_TYPE_NOP:
			// do nothing, because the nopskip goes before this switch
			break;
		case RZ_ANAL_OP_TYPE_JMP:
			if (op.jump == UT64_MAX) {
				gotoBeach (RZ_ANAL_RET_END);
			}
			{
				RzFlagItem *fi = anal->flb.get_at (anal->flb.f, op.jump, false);
				if (fi && strstr (fi->name, "imp.")) {
					gotoBeach (RZ_ANAL_RET_END);
				}
			}
			if (rz_cons_is_breaked ()) {
				gotoBeach (RZ_ANAL_RET_END);
			}
			if (anal->opt.jmpref) {
				(void) rz_anal_xrefs_set (anal, op.addr, op.jump, RZ_ANAL_REF_TYPE_CODE);
			}
			if (!anal->opt.jmpabove && (op.jump < fcn->addr)) {
				gotoBeach (RZ_ANAL_RET_END);
			}
			if (rz_anal_noreturn_at (anal, op.jump)) {
				gotoBeach (RZ_ANAL_RET_END);
			}
			{
				bool must_eob = true;
				RzIOMap *map = anal->iob.map_get (anal->iob.io, addr);
				if (map) {
					must_eob = (op.jump < map->itv.addr || op.jump >= map->itv.addr + map->itv.size);
				}
				if (must_eob) {
					op.jump = UT64_MAX;
					gotoBeach (RZ_ANAL_RET_END);
				}
			}
#if FIX_JMP_FWD
			bb->jump = op.jump;
			bb->fail = UT64_MAX;
			FITFCNSZ ();
			gotoBeach (RZ_ANAL_RET_END);
#else
			if (!overlapped) {
				bb->jump = op.jump;
				bb->fail = UT64_MAX;
			}
			ret = rz_anal_fcn_bb (anal, fcn, op.jump, depth);
			int tc = anal->opt.tailcall;
			if (tc) {
				// eprintf ("TAIL CALL AT 0x%llx\n", op.addr);
				int diff = op.jump - op.addr;
				if (tc < 0) {
					ut8 buf[32];
					(void)anal->iob.read_at (anal->iob.io, op.jump, (ut8 *) buf, sizeof (buf));
					if (rz_anal_is_prelude (anal, buf, sizeof (buf))) {
						fcn_recurse (anal, fcn, op.jump, anal->opt.bb_max_size, depth - 1);
					}
				} else if (RZ_ABS (diff) > tc) {
					(void) rz_anal_xrefs_set (anal, op.addr, op.jump, RZ_ANAL_REF_TYPE_CALL);
					fcn_recurse (anal, fcn, op.jump, anal->opt.bb_max_size, depth - 1);
					gotoBeach (RZ_ANAL_RET_END);
				}
			}
			goto beach;
#endif
			break;
		case RZ_ANAL_OP_TYPE_SUB:
			if (op.val != UT64_MAX && op.val > 0) {
				// if register is not stack
				cmpval = op.val;
			}
			break;
		case RZ_ANAL_OP_TYPE_CMP: {
			ut64 val = is_x86 ? op.val : op.ptr;
			if (val) {
				cmpval = val;
				bb->cmpval = cmpval;
				bb->cmpreg = op.reg;
				bb->cond = rz_anal_cond_new_from_op (&op);
			}
		}
			break;
		case RZ_ANAL_OP_TYPE_CJMP:
		case RZ_ANAL_OP_TYPE_MCJMP:
		case RZ_ANAL_OP_TYPE_RCJMP:
		case RZ_ANAL_OP_TYPE_UCJMP:
			if (anal->opt.cjmpref) {
				(void) rz_anal_xrefs_set (anal, op.addr, op.jump, RZ_ANAL_REF_TYPE_CODE);
			}
			if (!overlapped) {
				bb->jump = op.jump;
				bb->fail = op.fail;
			}
			if (bb->cond) {
				bb->cond->type = op.cond;
			}
			if (anal->opt.jmptbl) {
				if (op.ptr != UT64_MAX) {
					ut64 table_size, default_case;
					table_size = cmpval + 1;
					default_case = op.fail; // is this really default case?
					if (cmpval != UT64_MAX && default_case != UT64_MAX && (op.reg || op.ireg)) {
						if (op.ireg) {
							ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
						} else { // op.reg
							ret = walkthrough_arm_jmptbl_style (anal, fcn, bb, depth, op.addr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
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
				rz_anal_fcn_bb (anal, fcn, op.jump, depth);
				fcn->stack = saved_stack;
				ret = rz_anal_fcn_bb (anal, fcn, op.fail, depth);
				fcn->stack = saved_stack;
			} else {
				ret = rz_anal_fcn_bb (anal, fcn, op.jump, depth);
				fcn->stack = saved_stack;
				ret = rz_anal_fcn_bb (anal, fcn, op.fail, depth);
				fcn->stack = saved_stack;
				if (op.jump < fcn->addr) {
					if (!overlapped) {
						bb->jump = op.jump;
						bb->fail = UT64_MAX;
					}
					gotoBeach (RZ_ANAL_RET_END);
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
		case RZ_ANAL_OP_TYPE_UCALL:
		case RZ_ANAL_OP_TYPE_RCALL:
		case RZ_ANAL_OP_TYPE_ICALL:
		case RZ_ANAL_OP_TYPE_IRCALL:
			/* call [dst] */
			// XXX: this is TYPE_MCALL or indirect-call
			(void) rz_anal_xrefs_set (anal, op.addr, op.ptr, RZ_ANAL_REF_TYPE_CALL);

			if (rz_anal_noreturn_at (anal, op.ptr)) {
				RzAnalFunction *f = rz_anal_get_function_at (anal, op.ptr);
				if (f) {
					f->is_noreturn = true;
				}
				gotoBeach (RZ_ANAL_RET_END);
			}
			break;
		case RZ_ANAL_OP_TYPE_CCALL:
		case RZ_ANAL_OP_TYPE_CALL:
			/* call dst */
			(void) rz_anal_xrefs_set (anal, op.addr, op.jump, RZ_ANAL_REF_TYPE_CALL);

			if (rz_anal_noreturn_at (anal, op.jump)) {
				RzAnalFunction *f = rz_anal_get_function_at (anal, op.jump);
				if (f) {
					f->is_noreturn = true;
				}
				gotoBeach (RZ_ANAL_RET_END);
			}
			break;
		case RZ_ANAL_OP_TYPE_UJMP:
		case RZ_ANAL_OP_TYPE_RJMP:
			if (is_arm && last_is_mov_lr_pc) {
				break;
			}
			/* fall through */
		case RZ_ANAL_OP_TYPE_MJMP:
		case RZ_ANAL_OP_TYPE_IJMP:
		case RZ_ANAL_OP_TYPE_IRJMP:
			// if the next instruction is a symbol
			if (anal->opt.ijmp && isSymbolNextInstruction (anal, &op)) {
				gotoBeach (RZ_ANAL_RET_END);
			}
			// switch statement
			if (anal->opt.jmptbl && lea_jmptbl_ip != op.addr) {
				// op.ireg since rip relative addressing produces way too many false positives otherwise
				// op.ireg is 0 for rip relative, "rax", etc otherwise
				if (op.ptr != UT64_MAX && op.ireg) { // direct jump
					ut64 table_size, default_case;
					if (try_get_jmptbl_info (anal, fcn, op.addr, bb, &table_size, &default_case)) {
						bool case_table = false;
						RzAnalOp prev_op;
						anal->iob.read_at (anal->iob.io, op.addr - op.size, buf, sizeof (buf));
						if (rz_anal_op (anal, &prev_op, op.addr - op.size, buf, sizeof (buf), RZ_ANAL_OP_MASK_VAL) > 0) {
							bool prev_op_has_dst_name = prev_op.dst && prev_op.dst->reg && prev_op.dst->reg->name;
							bool op_has_src_name = op.src[0] && op.src[0]->reg && op.src[0]->reg->name;
							bool same_reg = (op.ireg && prev_op_has_dst_name && !strcmp (op.ireg, prev_op.dst->reg->name))
								|| (op_has_src_name && prev_op_has_dst_name && !strcmp (op.src[0]->reg->name, prev_op.dst->reg->name));
							if (prev_op.type == RZ_ANAL_OP_TYPE_MOV && prev_op.disp && prev_op.disp != UT64_MAX && same_reg) {
								//	movzx reg, byte [reg + case_table]
								//	jmp dword [reg*4 + jump_table]
								if (try_walkthrough_casetbl (anal, fcn, bb, depth, op.addr, op.ptr, prev_op.disp, op.ptr, anal->bits >> 3, table_size, default_case, ret)) {
									ret = case_table = true;
								}
							}
						}
						rz_anal_op_fini (&prev_op);
						if (!case_table) {
							ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
						}
					}
				} else if (op.ptr != UT64_MAX && op.reg) { // direct jump
					ut64 table_size, default_case;
					if (try_get_jmptbl_info (anal, fcn, op.addr, bb, &table_size, &default_case)) {
						ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
					}
				} else if (movdisp == 0) {
					ut64 jmptbl_base = UT64_MAX;
					ut64 lea_op_off = UT64_MAX;
					RzListIter *lea_op_iter = NULL;
					RzListIter *iter;
					leaddr_pair *pair;
					// find nearest candidate leaddr before op.addr
					rz_list_foreach (anal->leaddrs, iter, pair) {
						if (pair->op_addr >= op.addr) {
							continue;
						}
						if (lea_op_off == UT64_MAX || lea_op_off > op.addr - pair->op_addr) {
							lea_op_off = op.addr - pair->op_addr;
							jmptbl_base = pair->leaddr;
							lea_op_iter = iter;
						}
					}
					if (lea_op_iter) {
						rz_list_delete (anal->leaddrs, lea_op_iter);
					}
					ut64 table_size = cmpval + 1;
					ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, jmptbl_base, jmptbl_base, 4, table_size, -1, ret);
					cmpval = UT64_MAX;
				} else if (movdisp != UT64_MAX) {
					ut64 table_size, default_case;

					if (try_get_jmptbl_info (anal, fcn, op.addr, bb, &table_size, &default_case)) {
						op.ptr = movdisp;
						ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
					}
					movdisp = UT64_MAX;
				} else if (is_arm) {
					if (op.ptrsize == 1) { // TBB
						ut64 pred_cmpval = try_get_cmpval_from_parents(anal, fcn, bb, op.ireg);
						ut64 table_size = 0;
						if (pred_cmpval != UT64_MAX) {
							table_size += pred_cmpval;
						} else {
							table_size += cmpval;
						}
						ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.addr + op.size,
							op.addr + 4, 1, table_size, UT64_MAX, ret);
						// skip inlined jumptable
						idx += table_size;
					}
					if (op.ptrsize == 2) { // LDRH on thumb/arm
						ut64 pred_cmpval = try_get_cmpval_from_parents(anal, fcn, bb, op.ireg);
						int tablesize = 1;
						if (pred_cmpval != UT64_MAX) {
							tablesize += pred_cmpval;
						} else {
							tablesize += cmpval;
						}
						ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.addr + op.size,
							op.addr + 4, 2, tablesize, UT64_MAX, ret);
						// skip inlined jumptable
						idx += (tablesize * 2);
					}
				}
			}
			if (lea_jmptbl_ip == op.addr) {
				lea_jmptbl_ip = UT64_MAX;
			}
			if (anal->opt.ijmp) {
				if (continue_after_jump) {
					rz_anal_fcn_bb (anal, fcn, op.jump, depth);
					ret = rz_anal_fcn_bb (anal, fcn, op.fail, depth);
					if (overlapped) {
						goto analopfinish;
					}
				}
				if (rz_anal_noreturn_at (anal, op.jump) || op.eob) {
					goto analopfinish;
				}
			} else {
analopfinish:
				if (op.type == RZ_ANAL_OP_TYPE_RJMP) {
					gotoBeach (RZ_ANAL_RET_NOP);
				} else {
					gotoBeach (RZ_ANAL_RET_END);
				}
			}
			break;
		/* fallthru */
		case RZ_ANAL_OP_TYPE_PUSH:
			last_is_push = true;
			last_push_addr = op.val;
			if (anal->iob.is_valid_offset (anal->iob.io, last_push_addr, 1)) {
				(void) rz_anal_xrefs_set (anal, op.addr, last_push_addr, RZ_ANAL_REF_TYPE_DATA);
			}
			break;
		case RZ_ANAL_OP_TYPE_UPUSH:
			if ((op.type & RZ_ANAL_OP_TYPE_REG) && last_is_reg_mov_lea && op.src[0] && op.src[0]->reg
				&& op.src[0]->reg->name && !strcmp (op.src[0]->reg->name, last_reg_mov_lea_name)) {
				last_is_push = true;
				last_push_addr = last_reg_mov_lea_val;
				if (anal->iob.is_valid_offset (anal->iob.io, last_push_addr, 1)) {
					(void) rz_anal_xrefs_set (anal, op.addr, last_push_addr, RZ_ANAL_REF_TYPE_DATA);
				}
			}
			break;
		case RZ_ANAL_OP_TYPE_RET:
			if (op.family == RZ_ANAL_OP_FAMILY_PRIV) {
				fcn->type = RZ_ANAL_FCN_TYPE_INT;
			}
			if (last_is_push && anal->opt.pushret) {
				op.type = RZ_ANAL_OP_TYPE_JMP;
				op.jump = last_push_addr;
				bb->jump = op.jump;
				ret = rz_anal_fcn_bb (anal, fcn, op.jump, depth);
				goto beach;
			}
			if (!op.cond) {
				if (anal->verbose) {
					eprintf ("RET 0x%08"PFMT64x ". overlap=%s %"PFMT64u" %"PFMT64u"\n",
						addr + delay.un_idx - oplen, rz_str_bool (overlapped),
						bb->size, rz_anal_function_linear_size (fcn));
				}
				gotoBeach (RZ_ANAL_RET_END);
			}
			break;
		}
		if (has_stack_regs && arch_destroys_dst) {
			if (op_is_set_bp (&op, bp_reg, sp_reg) && op.src[1]) {
				switch (op.type & RZ_ANAL_OP_TYPE_MASK) {
				case RZ_ANAL_OP_TYPE_ADD:
					fcn->bp_off = fcn->stack - op.src[1]->imm;
					break;
				case RZ_ANAL_OP_TYPE_SUB:
					fcn->bp_off = fcn->stack + op.src[1]->imm;
					break;
				}
			}
		}
		if (anal->opt.vars && !varset) {
			rz_anal_extract_vars (anal, fcn, &op);
		}
		if (op.type != RZ_ANAL_OP_TYPE_MOV && op.type != RZ_ANAL_OP_TYPE_CMOV && op.type != RZ_ANAL_OP_TYPE_LEA) {
			last_is_reg_mov_lea = false;
		}
		if (op.type != RZ_ANAL_OP_TYPE_PUSH && op.type != RZ_ANAL_OP_TYPE_RPUSH) {
			last_is_push = false;
		}
		if (is_arm && op.type != RZ_ANAL_OP_TYPE_MOV) {
			last_is_mov_lr_pc = false;
		}
		if (has_variadic_reg && !fcn->is_variadic) {
			variadic_reg = rz_reg_get (anal->reg, "rax", RZ_REG_TYPE_GPR);
			bool dst_is_variadic = op.dst && op.dst->reg
					&& variadic_reg && op.dst->reg->offset == variadic_reg->offset;
			bool op_is_cmp = (op.type == RZ_ANAL_OP_TYPE_CMP) || op.type == RZ_ANAL_OP_TYPE_ACMP;
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
	rz_anal_op_fini (&op);
	RZ_FREE (last_reg_mov_lea_name);
	if (bb && bb->size == 0) {
		rz_anal_function_remove_block (fcn, bb);
	}
	rz_anal_block_update_hash (bb);
	rz_anal_block_unref (bb);
	return ret;
}

RZ_API int rz_anal_fcn_bb(RzAnal *anal, RzAnalFunction *fcn, ut64 addr, int depth) {
	return fcn_recurse (anal, fcn, addr, anal->opt.bb_max_size, depth - 1);
}

RZ_API bool rz_anal_check_fcn(RzAnal *anal, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high) {
	RzAnalOp op = {
		0
	};
	int i, oplen, opcnt = 0, pushcnt = 0, movcnt = 0, brcnt = 0;
	if (rz_anal_is_prelude (anal, buf, bufsz)) {
		return true;
	}
	for (i = 0; i < bufsz && opcnt < 10; i += oplen, opcnt++) {
		rz_anal_op_fini (&op);
		if ((oplen = rz_anal_op (anal, &op, addr + i, buf + i, bufsz - i, RZ_ANAL_OP_MASK_BASIC | RZ_ANAL_OP_MASK_HINT)) < 1) {
			return false;
		}
		switch (op.type) {
		case RZ_ANAL_OP_TYPE_PUSH:
		case RZ_ANAL_OP_TYPE_UPUSH:
		case RZ_ANAL_OP_TYPE_RPUSH:
			pushcnt++;
			break;
		case RZ_ANAL_OP_TYPE_MOV:
		case RZ_ANAL_OP_TYPE_CMOV:
			movcnt++;
			break;
		case RZ_ANAL_OP_TYPE_JMP:
		case RZ_ANAL_OP_TYPE_CJMP:
		case RZ_ANAL_OP_TYPE_CALL:
			if (op.jump < low || op.jump >= high) {
				return false;
			}
			brcnt++;
			break;
		case RZ_ANAL_OP_TYPE_UNK:
			return false;
		default:
			break;
		}
	}
	return (pushcnt + movcnt + brcnt > 5);
}

RZ_API void rz_anal_trim_jmprefs(RzAnal *anal, RzAnalFunction *fcn) {
	RzAnalRef *ref;
	RzList *refs = rz_anal_function_get_refs (fcn);
	RzListIter *iter;
	const bool is_x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86"); // HACK

	rz_list_foreach (refs, iter, ref) {
		if (ref->type == RZ_ANAL_REF_TYPE_CODE && rz_anal_function_contains (fcn, ref->addr)
		    && (!is_x86 || !rz_anal_function_contains (fcn, ref->at))) {
			rz_anal_xrefs_deln (anal, ref->at, ref->addr, ref->type);
		}
	}
	rz_list_free (refs);
}

RZ_API void rz_anal_del_jmprefs(RzAnal *anal, RzAnalFunction *fcn) {
	RzAnalRef *ref;
	RzList *refs = rz_anal_function_get_refs (fcn);
	RzListIter *iter;

	rz_list_foreach (refs, iter, ref) {
		if (ref->type == RZ_ANAL_REF_TYPE_CODE) {
			rz_anal_xrefs_deln (anal, ref->at, ref->addr, ref->type);
		}
	}
	rz_list_free (refs);
}

/* Does NOT invalidate read-ahead cache. */
RZ_API int rz_anal_fcn(RzAnal *anal, RzAnalFunction *fcn, ut64 addr, ut64 len, int reftype) {
	RzPVector *metas = rz_meta_get_all_in(anal, addr, RZ_META_TYPE_ANY);
	void **it;
	rz_pvector_foreach (metas, it) {
		RzAnalMetaItem *meta = ((RIntervalNode *)*it)->data;
		switch (meta->type) {
		case RZ_META_TYPE_DATA:
		case RZ_META_TYPE_STRING:
		case RZ_META_TYPE_FORMAT:
			rz_pvector_free (metas);
			return 0;
		default:
			break;
		}
	}
	rz_pvector_free (metas);
	if (anal->opt.norevisit) {
		if (!anal->visited) {
			anal->visited = set_u_new ();
		}
		if (set_u_contains (anal->visited, addr)) {
			eprintf ("rz_anal_fcn: anal.norevisit at 0x%08"PFMT64x" %c\n", addr, reftype);
			return RZ_ANAL_RET_END;
		}
		set_u_add (anal->visited, addr);
	} else {
		if (anal->visited) {
			set_u_free (anal->visited);
			anal->visited = NULL;
		}
	}
	/* defines fcn. or loc. prefix */
	fcn->type = (reftype == RZ_ANAL_REF_TYPE_CODE) ? RZ_ANAL_FCN_TYPE_LOC : RZ_ANAL_FCN_TYPE_FCN;
	if (fcn->addr == UT64_MAX) {
		fcn->addr = addr;
	}
	fcn->maxstack = 0;
	if (fcn->cc && !strcmp (fcn->cc, "ms")) {
		// Probably should put this on the cc sdb
		const int shadow_store = 0x28; // First 4 args + retaddr
		fcn->stack = fcn->maxstack = fcn->reg_save_area = shadow_store;
	}
	int ret = rz_anal_fcn_bb (anal, fcn, addr, anal->opt.depth);
	if (ret < 0) {
		if (anal->verbose) {
			eprintf ("Failed to analyze basic block at 0x%"PFMT64x"\n", addr);
		}
	}
	if (anal->opt.endsize && ret == RZ_ANAL_RET_END && rz_anal_function_realsize (fcn)) {   // cfg analysis completed
		RzListIter *iter;
		RzAnalBlock *bb;
		ut64 endaddr = fcn->addr;
		const bool is_x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86");

		// set function size as length of continuous sequence of bbs
		rz_list_sort (fcn->bbs, &cmpaddr);
		rz_list_foreach (fcn->bbs, iter, bb) {
			if (endaddr == bb->addr) {
				endaddr += bb->size;
			} else if ((endaddr < bb->addr && bb->addr - endaddr < BB_ALIGN)
			           || (anal->opt.jmpmid && is_x86 && endaddr > bb->addr
			               && bb->addr + bb->size > endaddr)) {
				endaddr = bb->addr + bb->size;
			} else {
				break;
			}
		}
#if JAYRO_04
		// fcn is not yet in anal => pass NULL
		rz_anal_function_resize (fcn, endaddr - fcn->addr);
#endif
		rz_anal_trim_jmprefs (anal, fcn);
	}
	return ret;
}

// XXX deprecate
RZ_API int rz_anal_fcn_del_locs(RzAnal *anal, ut64 addr) {
	RzListIter *iter, *iter2;
	RzAnalFunction *fcn, *f = rz_anal_get_fcn_in (anal, addr, RZ_ANAL_FCN_TYPE_ROOT);
	if (!f) {
		return false;
	}
	rz_list_foreach_safe (anal->fcns, iter, iter2, fcn) {
		if (fcn->type != RZ_ANAL_FCN_TYPE_LOC) {
			continue;
		}
		if (rz_anal_function_contains (fcn, addr)) {
			rz_anal_function_delete (fcn);
		}
	}
	rz_anal_fcn_del (anal, addr);
	return true;
}

RZ_API int rz_anal_fcn_del(RzAnal *a, ut64 addr) {
	RzAnalFunction *fcn;
	RzListIter *iter, *iter_tmp;
	rz_list_foreach_safe (a->fcns, iter, iter_tmp, fcn) {
		D eprintf ("fcn at %llx %llx\n", fcn->addr, addr);
		if (fcn->addr == addr) {
			rz_anal_function_delete (fcn);
		}
	}
	return true;
}

RZ_API RzAnalFunction *rz_anal_get_fcn_in(RzAnal *anal, ut64 addr, int type) {
	RzList *list = rz_anal_get_functions_in (anal, addr);
	RzAnalFunction *ret = NULL;
	if (list && !rz_list_empty (list)) {
		if (type == RZ_ANAL_FCN_TYPE_ROOT) {
			RzAnalFunction *fcn;
			RzListIter *iter;
			rz_list_foreach (list, iter, fcn) {
				if (fcn->addr == addr) {
					ret = fcn;
					break;
				}
			}
		} else {
			ret = rz_list_first (list);
		}
	}
	rz_list_free (list);
	return ret;
}

RZ_API RzAnalFunction *rz_anal_get_fcn_in_bounds(RzAnal *anal, ut64 addr, int type) {
	RzAnalFunction *fcn, *ret = NULL;
	RzListIter *iter;
	if (type == RZ_ANAL_FCN_TYPE_ROOT) {
		rz_list_foreach (anal->fcns, iter, fcn) {
			if (addr == fcn->addr) {
				return fcn;
			}
		}
		return NULL;
	}
	rz_list_foreach (anal->fcns, iter, fcn) {
		if (!type || (fcn && fcn->type & type)) {
			if (rz_anal_function_contains (fcn, addr)) {
				return fcn;
			}
		}
	}
	return ret;
}

RZ_API RzAnalFunction *rz_anal_get_function_byname(RzAnal *a, const char *name) {
	bool found = false;
	RzAnalFunction *f = ht_pp_find (a->ht_name_fun, name, &found);
	if (f && found) {
		return f;
	}
	return NULL;
}

/* rename RzAnalFunctionBB.add() */
RZ_API bool rz_anal_fcn_add_bb(RzAnal *a, RzAnalFunction *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail, RZ_BORROW RzAnalDiff *diff) {
	D eprintf ("Add bb\n");
	if (size == 0) { // empty basic blocks allowed?
		eprintf ("Warning: empty basic block at 0x%08"PFMT64x" is not allowed. pending discussion.\n", addr);
		rz_warn_if_reached ();
		return false;
	}
	if (size > a->opt.bb_max_size) {
		eprintf ("Warning: can't allocate such big bb of %"PFMT64d" bytes at 0x%08"PFMT64x"\n", (st64)size, addr);
		rz_warn_if_reached ();
		return false;
	}

	RzAnalBlock *block = rz_anal_get_block_at (a, addr);
	if (block) {
		rz_anal_delete_block (block);
		block = NULL;
	}

	const bool is_x86 = a->cur->arch && !strcmp (a->cur->arch, "x86");
	// TODO fix this x86-ism
	if (is_x86) {
		rz_anal_fcn_invalidate_read_ahead_cache ();
		fcn_recurse (a, fcn, addr, size, 1);
		block = rz_anal_get_block_at (a, addr);
		if (block) {
			rz_anal_block_set_size (block, size);
		}
	} else {
		block = rz_anal_create_block (a, addr, size);
	}

	if (!block) {
		D eprintf ("Warning: rz_anal_fcn_add_bb failed in fcn 0x%08"PFMT64x" at 0x%08"PFMT64x"\n", fcn->addr, addr);
		return false;
	}

	rz_anal_function_add_block (fcn, block);

	block->jump = jump;
	block->fail = fail;
	block->fail = fail;
	if (diff) {
		if (!block->diff) {
			block->diff = rz_anal_diff_new ();
		}
		if (block->diff) {
			block->diff->type = diff->type;
			block->diff->addr = diff->addr;
			if (diff->name) {
				RZ_FREE (block->diff->name);
				block->diff->name = strdup (diff->name);
			}
		}
	}
	return true;
}

RZ_API int rz_anal_function_loops(RzAnalFunction *fcn) {
	RzListIter *iter;
	RzAnalBlock *bb;
	ut32 loops = 0;
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->jump != UT64_MAX && bb->jump < bb->addr) {
			loops ++;
		}
		if (bb->fail != UT64_MAX && bb->fail < bb->addr) {
			loops ++;
		}
	}
	return loops;
}

RZ_API int rz_anal_function_complexity(RzAnalFunction *fcn) {
/*
        CC = E - N + 2P
        E = the number of edges of the graph.
        N = the number of nodes of the graph.
        P = the number of connected components (exit nodes).
 */
	RzAnal *anal = fcn->anal;
	int E = 0, N = 0, P = 0;
	RzListIter *iter;
	RzAnalBlock *bb;

	rz_list_foreach (fcn->bbs, iter, bb) {
		N++; // nodes
		if ((!anal || anal->verbose) && bb->jump == UT64_MAX && bb->fail != UT64_MAX) {
			eprintf ("Warning: invalid bb jump/fail pair at 0x%08"PFMT64x" (fcn 0x%08"PFMT64x"\n", bb->addr, fcn->addr);
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
			E += rz_list_length (bb->switch_op->cases);
		}
	}

	int result = E - N + (2 * P);
	if (result < 1 && (!anal || anal->verbose)) {
		eprintf ("Warning: CC = E(%d) - N(%d) + (2 * P(%d)) < 1 at 0x%08"PFMT64x"\n", E, N, P, fcn->addr);
	}
	// rz_return_val_if_fail (result > 0, 0);
	return result;
}

// tfj and afsj call this function
RZ_API char *rz_anal_function_get_json(RzAnalFunction *function) {
	RzAnal *a = function->anal;
	PJ *pj = a->coreb.pjWithEncoding (a->coreb.core);
	char *args = strdup ("");
	char *sdb_ret = rz_str_newf ("func.%s.ret", function->name);
	char *sdb_args = rz_str_newf ("func.%s.args", function->name);
	// RzList *args_list = rz_list_newf ((RzListFree) free);
	unsigned int i;
	const char *ret_type = sdb_const_get (a->sdb_types, sdb_ret, 0);
	const char *argc_str = sdb_const_get (a->sdb_types, sdb_args, 0);

	int argc = argc_str? atoi (argc_str): 0;

	pj_o (pj);
	pj_ks (pj, "name", function->name);
	const bool no_return = rz_anal_noreturn_at_addr (a, function->addr);
	pj_kb (pj, "noreturn", no_return);
	pj_ks (pj, "ret", ret_type?ret_type: "void");
	if (function->cc) {
		pj_ks (pj, "cc", function->cc);
	}
	pj_k (pj, "args");
	pj_a (pj);
	for (i = 0; i < argc; i++) {
		pj_o (pj);
		char *sdb_arg_i = rz_str_newf ("func.%s.arg.%d", function->name, i);
		char *arg_i = sdb_get (a->sdb_types, sdb_arg_i, 0);
		char *comma = strchr (arg_i, ',');
		if (comma) {
			*comma = 0;
			pj_ks (pj, "name", comma + 1);
			pj_ks (pj, "type", arg_i);
			const char *cc_arg = rz_reg_get_name (a->reg, rz_reg_get_name_idx (sdb_fmt ("A%d", i)));
			if (cc_arg) {
				pj_ks (pj, "cc", cc_arg);
			}
		}
		free (arg_i);
		free (sdb_arg_i);
		pj_end (pj);
	}
	pj_end (pj);
	free (sdb_args);
	free (sdb_ret);
	free (args);
	pj_end (pj);
	return pj_drain (pj);
}

RZ_API char *rz_anal_function_get_signature(RzAnalFunction *function) {
	RzAnal *a = function->anal;
	const char *realname = NULL, *import_substring = NULL;

	RzFlagItem *flag = a->flag_get (a->flb.f, function->addr);
	// Can't access RZ_FLAGS_FS_IMPORTS, since it is defined in rz_core.h
	if (flag && flag->space && !strcmp (flag->space->name, "imports")) {
		// Get substring after last dot
		import_substring = rz_str_rchr (function->name, NULL, '.');
		if (import_substring) {
			realname = import_substring + 1;
		}
	} else {
		realname = function->name;
	}

	char *ret = NULL, *args = strdup ("");
	char *sdb_ret = rz_str_newf ("func.%s.ret", realname);
	char *sdb_args = rz_str_newf ("func.%s.args", realname);
	// RzList *args_list = rz_list_newf ((RzListFree) free);
	unsigned int i, j;
	const char *ret_type = sdb_const_get (a->sdb_types, sdb_ret, 0);
	const char *argc_str = sdb_const_get (a->sdb_types, sdb_args, 0);

	int argc = argc_str? atoi (argc_str): 0;

	for (i = 0; i < argc; i++) {
		char *sdb_arg_i = rz_str_newf ("func.%s.arg.%d", realname, i);
		char *arg_i = sdb_get (a->sdb_types, sdb_arg_i, 0);
		// parse commas
		int arg_i_len = strlen (arg_i);
		for (j = 0; j < arg_i_len; j++) {
			if (j > 0 && arg_i[j] == ',') {
				if (arg_i[j - 1] == '*') {
					// remove whitespace
					memmove (arg_i + j, arg_i + j + 1, strlen (arg_i) - j);
				} else {
					arg_i[j] = ' ';
				}
			}
		}
		char *new_args = (i + 1 == argc)
			? rz_str_newf ("%s%s", args, arg_i)
			: rz_str_newf ("%s%s, ", args, arg_i);
		free (args);
		args = new_args;

		free (arg_i);
		free (sdb_arg_i);
	}
	ret = rz_str_newf ("%s %s (%s);", ret_type? ret_type: "void", realname, args);

	free (sdb_args);
	free (sdb_ret);
	free (args);
	return ret;
}

/* set function signature from string */
RZ_API int rz_anal_str_to_fcn(RzAnal *a, RzAnalFunction *f, const char *sig) {
	rz_return_val_if_fail (a || f || sig, false);
	char *error_msg = NULL;
	const char *out = rz_parse_c_string (a, sig, &error_msg);
	if (out) {
		rz_anal_save_parsed_type (a, out);
	}
	if (error_msg) {
		eprintf ("%s", error_msg);
		free (error_msg);
	}

	return true;
}

RZ_API RzAnalFunction *rz_anal_fcn_next(RzAnal *anal, ut64 addr) {
	RzAnalFunction *fcni;
	RzListIter *iter;
	RzAnalFunction *closer = NULL;
	rz_list_foreach (anal->fcns, iter, fcni) {
		// if (fcni->addr == addr)
		if (fcni->addr > addr && (!closer || fcni->addr < closer->addr)) {
			closer = fcni;
		}
	}
	return closer;
}

RZ_API int rz_anal_fcn_count(RzAnal *anal, ut64 from, ut64 to) {
	int n = 0;
	RzAnalFunction *fcni;
	RzListIter *iter;
	rz_list_foreach (anal->fcns, iter, fcni) {
		if (fcni->addr >= from && fcni->addr < to) {
			n++;
		}
	}
	return n;
}

/* return the basic block in fcn found at the given address.
 * NULL is returned if such basic block doesn't exist. */
RZ_API RzAnalBlock *rz_anal_fcn_bbget_in(const RzAnal *anal, RzAnalFunction *fcn, ut64 addr) {
	rz_return_val_if_fail (anal && fcn, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	const bool is_x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86");
	RzListIter *iter;
	RzAnalBlock *bb;
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (addr >= bb->addr && addr < (bb->addr + bb->size)
			&& (!anal->opt.jmpmid || !is_x86 || rz_anal_block_op_starts_at (bb, addr))) {
			return bb;
		}
	}
	return NULL;
}

RZ_API RzAnalBlock *rz_anal_fcn_bbget_at(RzAnal *anal, RzAnalFunction *fcn, ut64 addr) {
	rz_return_val_if_fail (fcn && addr != UT64_MAX, NULL);
	RzAnalBlock *b = rz_anal_get_block_at (anal, addr);
	if (b) {
		return b;
	}
	RzListIter *iter;
	RzAnalBlock *bb;
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (addr == bb->addr) {
			return bb;
		}
	}
	return NULL;
}

// compute the cyclomatic cost
RZ_API ut32 rz_anal_function_cost(RzAnalFunction *fcn) {
	RzListIter *iter;
	RzAnalBlock *bb;
	ut32 totalCycles = 0;
	if (!fcn) {
		return 0;
	}
	RzAnal *anal = fcn->anal;
	rz_list_foreach (fcn->bbs, iter, bb) {
		RzAnalOp op;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc (bb->size);
		if (!buf) {
			continue;
		}
		(void)anal->iob.read_at (anal->iob.io, bb->addr, (ut8 *) buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			memset (&op, 0, sizeof (op));
			(void) rz_anal_op (anal, &op, at, buf + idx, bb->size - idx, RZ_ANAL_OP_MASK_BASIC);
			if (op.size < 1) {
				op.size = 1;
			}
			idx += op.size;
			at += op.size;
			totalCycles += op.cycles;
			rz_anal_op_fini (&op);
		}
		free (buf);
	}
	return totalCycles;
}

RZ_API int rz_anal_function_count_edges(const RzAnalFunction *fcn, RZ_NULLABLE int *ebbs) {
	rz_return_val_if_fail (fcn, 0);
	RzListIter *iter;
	RzAnalBlock *bb;
	int edges = 0;
	if (ebbs) {
		*ebbs = 0;
	}
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (ebbs && bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			*ebbs = *ebbs + 1;
		} else {
			if (bb->jump != UT64_MAX) {
				edges ++;
			}
			if (bb->fail != UT64_MAX) {
				edges ++;
			}
		}
	}
	return edges;
}

RZ_API bool rz_anal_function_purity(RzAnalFunction *fcn) {
	if (fcn->has_changed) {
		HtUP *ht = ht_up_new (NULL, NULL, NULL);
		if (ht) {
			check_purity (ht, fcn);
			ht_up_free (ht);
		}
	}
	return fcn->is_pure;
}

static bool can_affect_bp(RzAnal *anal, RzAnalOp* op) {
	RzAnalValue *dst = op->dst;
	RzAnalValue *src = op->src[0];
	const char *opdreg = (dst && dst->reg) ? dst->reg->name : NULL;
	const char *opsreg = (src && src->reg) ? src->reg->name : NULL;
	const char *bp_name = anal->reg->name[RZ_REG_NAME_BP];
	bool is_bp_dst = opdreg && !dst->memref && !strcmp (opdreg, bp_name);
	bool is_bp_src = opsreg && !src->memref && !strcmp (opsreg, bp_name);
	if (op->type == RZ_ANAL_OP_TYPE_XCHG) {
		return is_bp_src || is_bp_dst;
	}
	return is_bp_dst;
}

/*
 * This function checks whether any operation in a given function may change bp (excluding "mov bp, sp"
 * and "pop bp" at the end).
 */
static void __anal_fcn_check_bp_use(RzAnal *anal, RzAnalFunction *fcn) {
	RzListIter *iter;
	RzAnalBlock *bb;
	char str_to_find[40] = "\"type\":\"reg\",\"value\":\"";
	char *pos;
	strncat (str_to_find, anal->reg->name[RZ_REG_NAME_BP], 39);
	if (!fcn) {
		return;
	}
	rz_list_foreach (fcn->bbs, iter, bb) {
		RzAnalOp op;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc (bb->size);
		if (!buf) {
			continue;
		}
		(void)anal->iob.read_at (anal->iob.io, bb->addr, (ut8 *) buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			rz_anal_op (anal, &op, at, buf + idx, bb->size - idx, RZ_ANAL_OP_MASK_VAL | RZ_ANAL_OP_MASK_OPEX);
			if (op.size < 1) {
				op.size = 1;
			}
			switch (op.type) {
			case RZ_ANAL_OP_TYPE_MOV:
			case RZ_ANAL_OP_TYPE_LEA:
				if (can_affect_bp (anal, &op) && op.src[0] && op.src[0]->reg && op.src[0]->reg->name
				&& strcmp (op.src[0]->reg->name, anal->reg->name[RZ_REG_NAME_SP])) {
					fcn->bp_frame = false;
					rz_anal_op_fini (&op);
					free (buf);
					return;
				}
				break;
			case RZ_ANAL_OP_TYPE_ADD:
			case RZ_ANAL_OP_TYPE_AND:
			case RZ_ANAL_OP_TYPE_CMOV:
			case RZ_ANAL_OP_TYPE_NOT:
			case RZ_ANAL_OP_TYPE_OR:
			case RZ_ANAL_OP_TYPE_ROL:
			case RZ_ANAL_OP_TYPE_ROR:
			case RZ_ANAL_OP_TYPE_SAL:
			case RZ_ANAL_OP_TYPE_SAR:
			case RZ_ANAL_OP_TYPE_SHR:
			case RZ_ANAL_OP_TYPE_SUB:
			case RZ_ANAL_OP_TYPE_XOR:
			case RZ_ANAL_OP_TYPE_SHL:
// op.dst is not filled for these operations, so for now, check for bp as dst looks like this; in the future it may be just replaced with call to can_affect_bp
 				pos = op.opex.ptr ? strstr (op.opex.ptr, str_to_find) : NULL;
				if (pos && pos - op.opex.ptr < 60) {
					fcn->bp_frame = false;
					rz_anal_op_fini (&op);
					free (buf);
					return;
				}
				break;
			case RZ_ANAL_OP_TYPE_XCHG:
				if (op.opex.ptr && strstr (op.opex.ptr, str_to_find)) {
					fcn->bp_frame = false;
					rz_anal_op_fini (&op);
					free (buf);
					return;
				}
				break;
			case RZ_ANAL_OP_TYPE_POP:
				break;
			default:
				break;
			}
			idx += op.size;
			at += op.size;
			rz_anal_op_fini (&op);
		}
		free (buf);
	}
}

RZ_API void rz_anal_function_check_bp_use(RzAnalFunction *fcn) {
	rz_return_if_fail (fcn);
	__anal_fcn_check_bp_use (fcn->anal, fcn);
}

typedef struct {
	RzAnalFunction *fcn;
	HtUP *visited;
} BlockRecurseCtx;

static bool mark_as_visited(RzAnalBlock *bb, void *user) {
	BlockRecurseCtx *ctx = user;
	ht_up_insert (ctx->visited, bb->addr, NULL);
	return true;
}

static bool analize_addr_cb(ut64 addr, void *user) {
	BlockRecurseCtx *ctx = user;
	RzAnal *anal = ctx->fcn->anal;
	RzAnalBlock *existing_bb = rz_anal_get_block_at (anal, addr);
	if (!existing_bb || !rz_list_contains (ctx->fcn->bbs, existing_bb)) {
		int old_len = rz_list_length (ctx->fcn->bbs);
		rz_anal_fcn_bb (ctx->fcn->anal, ctx->fcn, addr, anal->opt.depth);
		if (old_len != rz_list_length (ctx->fcn->bbs)) {
			rz_anal_block_recurse (rz_anal_get_block_at (anal, addr), mark_as_visited, user);
		}
	}
	ht_up_insert (ctx->visited, addr, NULL);
	return true;
}

static bool analize_descendents(RzAnalBlock *bb, void *user) {
	return rz_anal_block_successor_addrs_foreach (bb, analize_addr_cb, user);
}

static void free_ht_up(HtUPKv *kv) {
	ht_up_free ((HtUP *)kv->value);
}

static void update_varz_analysis(RzAnalFunction *fcn, int align, ut64 from, ut64 to) {
	RzAnal *anal = fcn->anal;
	ut64 cur_addr;
	int opsz;
	from = align ? from - (from % align) : from;
	to = align ? RZ_ROUND (to, align) : to;
	if (UT64_SUB_OVFCHK (to, from)) {
		return;
	}
	ut64 len = to - from;
	ut8 *buf = malloc (len);
	if (!buf) {
		return;
	}
	if (anal->iob.read_at (anal->iob.io, from, buf, len) < len) {
		return;
	}
	for (cur_addr = from; cur_addr < to; cur_addr += opsz, len -= opsz) {
		RzAnalOp op;
		int ret = rz_anal_op (anal->coreb.core, &op, cur_addr, buf, len, RZ_ANAL_OP_MASK_ESIL | RZ_ANAL_OP_MASK_VAL);
		if (ret < 1 || op.size < 1) {
			rz_anal_op_fini (&op);
			break;
		}
		opsz = op.size;
		rz_anal_extract_vars (anal, fcn, &op);
		rz_anal_op_fini (&op);
	}
	free (buf);
}

// Clear function variable acesses inside in a block
static void clear_bb_vars(RzAnalFunction *fcn, RzAnalBlock *bb, ut64 from, ut64 to) {
	int i;
	if (rz_pvector_empty (&fcn->vars)) {
		return;
	}
	for (i = 0; i < bb->ninstr; i++) {
		const ut64 addr = rz_anal_bb_opaddr_i (bb, i);
		if (addr < from) {
			continue;
		}
		if (addr >= to || addr == UT64_MAX) {
			break;
		}
		RzPVector *vars = rz_anal_function_get_vars_used_at (fcn, addr);
		if (vars) {
			RzPVector *vars_clone = (RzPVector *)rz_vector_clone ((RzVector *)vars);
			void **v;
			rz_pvector_foreach (vars_clone, v) {
				rz_anal_var_remove_access_at ((RzAnalVar *)*v, addr);
			}
			rz_pvector_clear (vars_clone);
		}
	}
}

static void update_analysis(RzAnal *anal, RzList *fcns, HtUP *reachable) {
	RzListIter *it, *it2, *tmp;
	RzAnalFunction *fcn;
	bool old_jmpmid = anal->opt.jmpmid;
	anal->opt.jmpmid = true;
	rz_anal_fcn_invalidate_read_ahead_cache ();
	rz_list_foreach (fcns, it, fcn) {
		// Recurse through blocks of function, mark reachable,
		// analyze edges that don't have a block
		RzAnalBlock *bb = rz_anal_get_block_at (anal, fcn->addr);
		if (!bb) {
			rz_anal_fcn_bb (anal, fcn, fcn->addr, anal->opt.depth);
			bb = rz_anal_get_block_at (anal, fcn->addr);
			if (!bb) {
				continue;
			}
		}
		HtUP *ht = ht_up_new0 ();
		ht_up_insert (ht, bb->addr, NULL);
		BlockRecurseCtx ctx = { fcn, ht };
		rz_anal_block_recurse (bb, analize_descendents, &ctx);

		// Remove non-reachable blocks
		rz_list_foreach_safe (fcn->bbs, it2, tmp, bb) {
			if (ht_up_find_kv (ht, bb->addr, NULL)) {
				continue;
			}
			HtUP *o_visited = ht_up_find (reachable, fcn->addr, NULL);
			if (!ht_up_find_kv (o_visited, bb->addr, NULL)) {
				// Avoid removing blocks that were already not reachable
				continue;
			}
			fcn->ninstr -= bb->ninstr;
			rz_anal_function_remove_block (fcn, bb);
		}

		RzList *bbs = rz_list_clone (fcn->bbs);
		rz_anal_block_automerge (bbs);
		rz_anal_function_delete_unused_vars (fcn);
		rz_list_free (bbs);
	}
	anal->opt.jmpmid = old_jmpmid;
}

static void calc_reachable_and_remove_block(RzList *fcns, RzAnalFunction *fcn, RzAnalBlock *bb, HtUP *reachable) {
	clear_bb_vars (fcn, bb, bb->addr, bb->addr + bb->size);
	if (!rz_list_contains (fcns, fcn)) {
		rz_list_append (fcns, fcn);

		// Calculate reachable blocks from the start of function
		HtUP *ht = ht_up_new0 ();
		BlockRecurseCtx ctx = { fcn, ht };
		rz_anal_block_recurse (rz_anal_get_block_at (fcn->anal, fcn->addr), mark_as_visited, &ctx);
		ht_up_insert (reachable, fcn->addr, ht);
	}
	fcn->ninstr -= bb->ninstr;
	rz_anal_function_remove_block (fcn, bb);
}

RZ_API void rz_anal_update_analysis_range(RzAnal *anal, ut64 addr, int size) {
	rz_return_if_fail (anal);
	RzListIter *it, *it2, *tmp;
	RzAnalBlock *bb;
	RzAnalFunction *fcn;
	RzList *blocks = rz_anal_get_blocks_intersect (anal, addr, size);
	if (rz_list_empty (blocks)) {
		rz_list_free (blocks);
		return;
	}
	RzList *fcns = rz_list_new ();
	HtUP *reachable = ht_up_new (NULL, free_ht_up, NULL);
	const int align = rz_anal_archinfo (anal, RZ_ANAL_ARCHINFO_ALIGN);
	const ut64 end_write = addr + size;

	rz_list_foreach (blocks, it, bb) {
		if (!rz_anal_block_was_modified (bb)) {
			continue;
		}
		rz_list_foreach_safe (bb->fcns, it2, tmp, fcn) {
			if (align > 1) {
				if ((end_write < rz_anal_bb_opaddr_i (bb, bb->ninstr - 1))
					&& (!bb->switch_op || end_write < bb->switch_op->addr)) {
					// Special case when instructions are aligned and we don't
					// need to worry about a write messing with the jump instructions
					clear_bb_vars (fcn, bb, addr > bb->addr ? addr : bb->addr, end_write);
					update_varz_analysis (fcn, align, addr > bb->addr ? addr : bb->addr, end_write);
					rz_anal_function_delete_unused_vars (fcn);
					continue;
				}
			}
			calc_reachable_and_remove_block (fcns, fcn, bb, reachable);
		}
	}
	rz_list_free (blocks); // This will call rz_anal_block_unref to actually remove blocks from RzAnal
	update_analysis (anal, fcns, reachable);
	ht_up_free (reachable);
	rz_list_free (fcns);
}

RZ_API void rz_anal_function_update_analysis(RzAnalFunction *fcn) {
	rz_return_if_fail (fcn);
	RzListIter *it, *it2, *tmp, *tmp2;
	RzAnalBlock *bb;
	RzAnalFunction *f;
	RzList *fcns = rz_list_new ();
	HtUP *reachable = ht_up_new (NULL, free_ht_up, NULL);
	rz_list_foreach_safe (fcn->bbs, it, tmp, bb) {
		if (rz_anal_block_was_modified (bb)) {
			rz_list_foreach_safe (bb->fcns, it2, tmp2, f) {
				calc_reachable_and_remove_block (fcns, f, bb, reachable);
			}
		}
	}
	update_analysis (fcn->anal, fcns, reachable);
	ht_up_free (reachable);
	rz_list_free (fcns);
}
