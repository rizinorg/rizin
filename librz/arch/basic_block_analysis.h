// SPDX-FileCopyrightText: 2026  Mohit Ishpunyani <ishpunyanimohit@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ANALYSIS_BLOCK_H
#define RZ_ANALYSIS_BLOCK_H

#define MAX_SCAN_SIZE 0x7ffffff
// 16 KB is the maximum size for a basic block
#define MAX_FLG_NAME_SIZE 64

int skip_hp(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisOp *op, RzAnalysisBlock *bb, ut64 addr,
	char *tmp_buf, int oplen, int un_idx, int *idx);
bool isInvalidMemory(RzAnalysis *analysis, const ut8 *buf, int len);

typedef struct {
	ut8 cache[1024];
	ut64 cache_addr;
} ReadAhead;

int read_ahead(ReadAhead *ra, RzAnalysis *analysis, ut64 addr, ut8 *buf, ssize_t len);

typedef struct {
	ut64 op_addr;
	ut64 leaddr;
	char *reg;
} leaddr_pair;

void free_leaddr_pair(void *pair);
RzAnalysisBlock *bbget(RzAnalysis *analysis, ut64 addr, bool jumpmid);

static inline bool does_arch_destroys_dst(const char *arch) {
	return arch && (!strncmp(arch, "arm", 3) || !strcmp(arch, "riscv") || !strcmp(arch, "ppc"));
}

typedef struct {
	// Inputs
	// RzAnalysisTaskItem *item, RzVector *tasks;

	// Derived from item
	RzAnalysis *analysis;
	RzAnalysisFunction *fcn;
	RzStackAddr sp;
	ut64 addr; // start address of the block

	// Config
	ut64 len; // max block size
	int continue_after_jump; // TODO: initialise this when defining instance
	int addrbytes; // TODO: initialise this when defining instance
	bool arch_destroys_dst;
	struct {
		bool is_arm;
		bool is_x86;
		bool is_amd64;
		bool is_dalvik;
		bool is_hexagon;
	} selected_architecture;
	bool can_jmpmid;

	// State during analysis
	ReadAhead read_ahead_cache;
	char *last_reg_mov_lea_name;
	char *movbasereg;
	RzAnalysisBlock *bb;
	RzAnalysisBlock *bbg;
	RzAnalysisBBEndCause ret; // final result
	RzAnalysisBBEndCause skip_ret; // used by skip_hp
	bool overlapped;
	RzAnalysisOp op;
	int oplen;
	int idx; // current byte index in the block
	bool varset; // whether variables were extracted
	struct {
		int cnt;
		int idx;
		int after;
		int pending;
		int adjust;
		int un_idx;
	} delay;
	char tmp_buf[MAX_FLG_NAME_SIZE + 5];
	ut64 last_reg_mov_lea_val;
	bool last_is_reg_mov_lea;
	bool last_is_push;
	bool last_is_mov_lr_pc;
	bool last_is_add_lr_pc;
	ut64 last_push_addr;
	RzAnalysisFunction *tmp_fcn;
	ut64 movdisp;
	ut64 movscale;
	ut8 buf[32];
	int maxlen;

	// Variadic detection (amd64)
	RzRegItem *variadic_reg;
	bool has_variadic_reg;
} BasicBlockAnalysisCtx;

typedef struct {
	RzAnalysisFunction *fcn;
	const st64 stack_diff;
} BlockTakeoverCtx;

bool fcn_takeover_block_recursive_followthrough_cb(RzAnalysisBlock *block, void *user);
void fcn_takeover_block_recursive(RzAnalysisFunction *fcn, RzAnalysisBlock *start_block, RzStackAddr sp);
RzAnalysisBlock *fcn_append_basic_block(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr);
void analyze_retpoline(RzAnalysis *analysis, RzAnalysisOp *op);

static inline bool op_is_set_bp(RzAnalysisOp *op, const char *bp_reg, const char *sp_reg) {
	bool has_dst_reg = op->dst && op->dst->reg && op->dst->reg->name;
	bool has_src_reg = op->src[0] && op->src[0]->reg && op->src[0]->reg->name;
	if (has_dst_reg && has_src_reg) {
		return !strcmp(bp_reg, op->dst->reg->name) && !strcmp(sp_reg, op->src[0]->reg->name);
	}
	return false;
}

int analyze_function_locally(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 address);
bool regs_exist(RzAnalysisValue *src, RzAnalysisValue *dst);
bool is_delta_pointer_table(ReadAhead *ra, RzAnalysis *analysis, ut64 addr, ut64 lea_ptr, ut64 *jmptbl_addr, ut64 *casetbl_addr, RzAnalysisOp *jmp_aop);
bool is_unknown_call_from_plt(RzAnalysis *analysis, ut64 op_address);

static inline bool jump_leaves_mapped_mem(RzAnalysis *analysis, ut64 insn_addr, ut64 jump_target) {
	rz_return_val_if_fail(analysis, false);
	RzIOMap *map = analysis->iob.map_get(analysis->iob.io, insn_addr);
	return (jump_target < map->itv.addr || jump_target >= map->itv.addr + map->itv.size);
}

/**
 * \brief Peaks into the memory at the jump address.
 * If it finds a function prelude, at it it returns true.
 * False otherwise.
 */
static inline bool jumps_to_prelude(RzAnalysis *analysis, ut64 jmp_addr) {
	ut8 buf[32] = { 0 };
	(void)analysis->iob.read_at(analysis->iob.io, jmp_addr, (ut8 *)buf, sizeof(buf));
	return rz_analysis_is_prelude(analysis, buf, sizeof(buf));
}

static inline void set_bb_branches(RZ_OUT RzAnalysisBlock *bb, const ut64 jump, const ut64 fail) {
	bb->jump = jump;
	bb->fail = fail;
}

bool isSymbolNextInstruction(RzAnalysis *analysis, RzAnalysisOp *op);
ut64 try_get_cmpval_from_parents(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *my_bb, const char *cmp_reg);
const char *retpoline_reg(RzAnalysis *analysis, ut64 addr);

bool init_basic_block(BasicBlockAnalysisCtx *ctx, RzAnalysisTaskItem *item, RzVector /*RzAnalysisTaskItem*/ *tasks);
RzAnalysisBBEndCause analysis_basic_block(BasicBlockAnalysisCtx *ctx, RzAnalysisTaskItem *item, RzVector /*RzAnalysisTaskItem*/ *tasks);
void cleanup_basic_block(BasicBlockAnalysisCtx *ctx);

#endif