// SPDX-FileCopyrightText: 2014-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014-2021 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ANALYSIS_ESIL_H
#define RZ_ANALYSIS_ESIL_H

#include <rz_util.h>
#include <rz_reg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_ANALYSIS_ESIL_GOTO_LIMIT 4096

#define esilprintf(op, fmt, ...) rz_strbuf_setf(&op->esil, fmt, ##__VA_ARGS__)

typedef struct rz_analysis_esil_word_t {
	int type;
	const char *str;
} RzAnalysisEsilWord;

// only flags that affect control flow
enum {
	RZ_ANALYSIS_ESIL_FLAG_ZERO = 1,
	RZ_ANALYSIS_ESIL_FLAG_CARRY = 2,
	RZ_ANALYSIS_ESIL_FLAG_OVERFLOW = 4,
	RZ_ANALYSIS_ESIL_FLAG_PARITY = 8,
	RZ_ANALYSIS_ESIL_FLAG_SIGN = 16,
	// ...
};

enum {
	RZ_ANALYSIS_ESIL_PARM_INVALID = 0,
	RZ_ANALYSIS_ESIL_PARM_REG,
	RZ_ANALYSIS_ESIL_PARM_NUM,
};

// must be a char
#define ESIL_INTERNAL_PREFIX '$'
#define ESIL_STACK_NAME      "esil.ram"

typedef struct rz_analysis_esil_source_t {
	ut32 id;
	ut32 claimed;
	void *content;
} RzAnalysisEsilSource;

typedef struct rz_analysis_esil_t RzAnalysisEsil;

RZ_API void rz_analysis_esil_sources_init(RzAnalysisEsil *esil);
RZ_API ut32 rz_analysis_esil_load_source(RzAnalysisEsil *esil, const char *path);
RZ_API void *rz_analysis_esil_get_source(RzAnalysisEsil *esil, ut32 src_id);
RZ_API bool rz_analysis_esil_claim_source(RzAnalysisEsil *esil, ut32 src_id);
RZ_API void rz_analysis_esil_release_source(RzAnalysisEsil *esil, ut32 src_id);
RZ_API void rz_analysis_esil_sources_fini(RzAnalysisEsil *esil);

typedef bool (*RzAnalysisEsilInterruptCB)(RzAnalysisEsil *esil, ut32 interrupt, void *user);

typedef struct rz_analysis_esil_interrupt_handler_t {
	const ut32 num;
	const char *name;
	void *(*init)(RzAnalysisEsil *esil);
	RzAnalysisEsilInterruptCB cb;
	void (*fini)(void *user);
} RzAnalysisEsilInterruptHandler;

typedef struct rz_analysis_esil_change_reg_t {
	int idx;
	ut64 data;
} RzAnalysisEsilRegChange;

typedef struct rz_analysis_esil_change_mem_t {
	int idx;
	ut8 data;
} RzAnalysisEsilMemChange;

typedef struct rz_analysis_esil_trace_t {
	int idx;
	int end_idx;
	HtUP *registers;
	HtUP *memory;
	RzRegArena *arena[RZ_REG_TYPE_LAST];
	ut64 stack_addr;
	ut64 stack_size;
	ut8 *stack_data;
	RzPVector /*<RzILTraceInstruction *>*/ *instructions;
} RzAnalysisEsilTrace;

typedef int (*RzAnalysisEsilHookRegWriteCB)(RzAnalysisEsil *esil, const char *name, ut64 *val);

typedef struct rz_analysis_esil_callbacks_t {
	void *user;
	/* callbacks */
	int (*hook_flag_read)(RzAnalysisEsil *esil, const char *flag, ut64 *num);
	int (*hook_command)(RzAnalysisEsil *esil, const char *op);
	int (*hook_mem_read)(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len);
	int (*mem_read)(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len);
	int (*hook_mem_write)(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len);
	int (*mem_write)(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len);
	int (*hook_reg_read)(RzAnalysisEsil *esil, const char *name, ut64 *res, int *size);
	int (*reg_read)(RzAnalysisEsil *esil, const char *name, ut64 *res, int *size);
	RzAnalysisEsilHookRegWriteCB hook_reg_write;
	int (*reg_write)(RzAnalysisEsil *esil, const char *name, ut64 val);
} RzAnalysisEsilCallbacks;

/* During the analysis RzAnalysisEsil could be reset multiple times,
 * thus there is a need to preserve some values between those runs.
 */
typedef struct rz_analysis_esil_inter_state_t {
	bool analysis_stop;
	ut64 last_read;
	ut64 last_data;
	ut64 emustack_min;
	ut64 emustack_max;
	RzList /*<RzAnalysisEsilMemoryRegion *>*/ *memreads;
	RzList /*<RzAnalysisEsilMemoryRegion *>*/ *memwrites;
	RzAnalysisEsilCallbacks callbacks;
	bool callbacks_set;
} RzAnalysisEsilInterState;

struct rz_analysis_esil_t {
	void *pcore;
	void *panalysis;
	char **stack;
	ut64 addrmask;
	int stacksize;
	int stackptr;
	ut32 skip;
	int nowrite;
	int iotrap;
	int exectrap;
	int repeat;
	int parse_stop;
	int parse_goto;
	int parse_goto_count;
	int verbose;
	ut64 flags;
	ut64 address;
	ut64 stack_addr;
	ut32 stack_size;
	int delay; // mapped to $ds in ESIL
	ut64 jump_target; // mapped to $jt in ESIL
	int jump_target_set; // mapped to $js in ESIL
	int trap;
	ut32 trap_code; // extend into a struct to store more exception info?
	// parity flag? done with cur
	ut64 old; // used for carry-flagging and borrow-flagging
	ut64 cur; // used for carry-flagging and borrow-flagging
	ut8 lastsz; // in bits //used for signature-flag
	/* native ops and custom ops */
	HtSP *ops;
	RzStrBuf current_opstr;
	RzIDStorage *sources;
	HtUP *interrupts;
	/* deep esil parsing fills this */
	Sdb *stats;
	RzAnalysisEsilTrace *trace;
	RzAnalysisEsilCallbacks cb;
	// this is so cursed, can we please remove external commands from esil internals.
	// Function pointers are fine, but not commands
	char *cmd_step; // rizin (external) command to run before a step is performed
	char *cmd_step_out; // rizin (external) command to run after a step is performed
	char *cmd_intr; // rizin (external) command to run when an interrupt occurs
	char *cmd_trap; // rizin (external) command to run when a trap occurs
	char *cmd_mdev; // rizin (external) command to run when an memory mapped device address is used
	char *cmd_todo; // rizin (external) command to run when esil expr contains TODO
	char *cmd_ioer; // rizin (external) command to run when esil fails to IO
	char *mdev_range; // string containing the rz_str_range to match for read/write accesses
	bool (*cmd)(RzAnalysisEsil *esil, const char *name, ut64 a0, ut64 a1);
	void *user;
	int stack_fd; // ahem, let's not do this
	bool in_cmd_step;
	RzAnalysisEsilInterState *esilinterstate;
};

/* Alias RegChange and MemChange */
typedef RzAnalysisEsilRegChange RzAnalysisRzilRegChange;
typedef RzAnalysisEsilMemChange RzAnalysisRzilMemChange;

/* Alias esil strace */
typedef struct rz_analysis_esil_interrupt_t {
	RzAnalysisEsilInterruptHandler *handler;
	void *user;
	ut32 src_id;
	RzAnalysisEsil *esil;
} RzAnalysisEsilInterrupt;

enum {
	RZ_ANALYSIS_ESIL_OP_TYPE_UNKNOWN = 0x1,
	RZ_ANALYSIS_ESIL_OP_TYPE_CONTROL_FLOW,
	RZ_ANALYSIS_ESIL_OP_TYPE_MEM_READ = 0x4,
	RZ_ANALYSIS_ESIL_OP_TYPE_MEM_WRITE = 0x8,
	RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE = 0x10,
	RZ_ANALYSIS_ESIL_OP_TYPE_MATH = 0x20,
	RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM = 0x40
};

typedef bool (*RzAnalysisEsilOpCb)(RzAnalysisEsil *esil);

typedef struct rz_analysis_esil_operation_t {
	RzAnalysisEsilOpCb code;
	ut32 push; // amount of operands pushed
	ut32 pop; // amount of operands popped
	ut32 type;
} RzAnalysisEsilOp;

// this is 80-bit offsets so we can address every piece of esil in an instruction
typedef struct rz_analysis_esil_expr_offset_t {
	ut64 off;
	ut16 idx;
} RzAnalysisEsilEOffset;

typedef enum {
	RZ_ANALYSIS_ESIL_BLOCK_ENTER_NORMAL = 0,
	RZ_ANALYSIS_ESIL_BLOCK_ENTER_TRUE,
	RZ_ANALYSIS_ESIL_BLOCK_ENTER_FALSE,
	RZ_ANALYSIS_ESIL_BLOCK_ENTER_GLUE,
} RzAnalysisEsilBlockEnterType;

typedef struct rz_analysis_esil_basic_block_t {
	RzAnalysisEsilEOffset first;
	RzAnalysisEsilEOffset last;
	char *expr; // synthesized esil-expression for this block
	RzAnalysisEsilBlockEnterType enter; // maybe more type is needed here
} RzAnalysisEsilBB;

// Structure to represent memory reads and writes during ESIL tracing
typedef struct rz_analysis_esil_memory_region_t {
	ut64 addr; ///< memory address
	size_t size; ///< size of the region
} RzAnalysisEsilMemoryRegion;

RZ_API RzAnalysisEsil *rz_analysis_esil_new(int stacksize, int iotrap, unsigned int addrsize);
RZ_API bool rz_analysis_esil_set_pc(RzAnalysisEsil *esil, ut64 addr);
RZ_API bool rz_analysis_esil_setup(RzAnalysisEsil *esil, void /*RzAnalysis*/ *analysis, int romem, int stats, int nonull, void /*RzCore*/ *core);
RZ_API void rz_analysis_esil_free(RzAnalysisEsil *esil);
RZ_API bool rz_analysis_esil_runword(RzAnalysisEsil *esil, const char *word);
RZ_API bool rz_analysis_esil_parse(RzAnalysisEsil *esil, const char *str);
RZ_API int rz_analysis_esil_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len);
RZ_API int rz_analysis_esil_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len);
RZ_API int rz_analysis_esil_reg_read(RzAnalysisEsil *esil, const char *regname, ut64 *num, int *size);
RZ_API int rz_analysis_esil_reg_write(RzAnalysisEsil *esil, const char *dst, ut64 num);
RZ_API bool rz_analysis_esil_pushnum(RzAnalysisEsil *esil, ut64 num);
RZ_API bool rz_analysis_esil_push(RzAnalysisEsil *esil, const char *str);
RZ_API char *rz_analysis_esil_pop(RzAnalysisEsil *esil);
RZ_API const char *rz_analysis_esil_trapstr(int type);
RZ_API bool rz_analysis_esil_set_op(RzAnalysisEsil *esil, const char *op, RzAnalysisEsilOpCb code, ut32 push, ut32 pop, ut32 type);
RZ_API void rz_analysis_esil_stack_free(RzAnalysisEsil *esil);
RZ_API int rz_analysis_esil_get_parm_type(RzAnalysisEsil *esil, const char *str);
RZ_API int rz_analysis_esil_get_parm(RzAnalysisEsil *esil, const char *str, ut64 *num);
RZ_API int rz_analysis_esil_condition(RzAnalysisEsil *esil, const char *str);

// esil_interrupt.c
RZ_API void rz_analysis_esil_interrupts_init(RzAnalysisEsil *esil);
RZ_API RzAnalysisEsilInterrupt *rz_analysis_esil_interrupt_new(RzAnalysisEsil *esil, ut32 src_id, RzAnalysisEsilInterruptHandler *ih);
RZ_API void rz_analysis_esil_interrupt_free(RzAnalysisEsil *esil, RzAnalysisEsilInterrupt *intr);
RZ_API bool rz_analysis_esil_set_interrupt(RzAnalysisEsil *esil, RzAnalysisEsilInterrupt *intr);
RZ_API int rz_analysis_esil_fire_interrupt(RzAnalysisEsil *esil, ut32 intr_num);
RZ_API bool rz_analysis_esil_load_interrupts(RzAnalysisEsil *esil, RzAnalysisEsilInterruptHandler **handlers, ut32 src_id);
RZ_API bool rz_analysis_esil_load_interrupts_from_lib(RzAnalysisEsil *esil, const char *path);
RZ_API void rz_analysis_esil_interrupts_fini(RzAnalysisEsil *esil);

RZ_API void rz_analysis_esil_mem_ro(RzAnalysisEsil *esil, int mem_readonly);
RZ_API void rz_analysis_esil_stats(RzAnalysisEsil *esil, int enable);

/* ESIL trace */
RZ_API RZ_BORROW void /*RzILTraceInstruction*/ *rz_analysis_esil_get_instruction_trace(RZ_NONNULL RzAnalysisEsilTrace *etrace, int idx);
RZ_API RzAnalysisEsilTrace *rz_analysis_esil_trace_new(RzAnalysisEsil *esil);
RZ_API void rz_analysis_esil_trace_free(RzAnalysisEsilTrace *trace);
RZ_API void rz_analysis_esil_trace_op(RzAnalysisEsil *esil, ut64 pc, RZ_NULLABLE const char *esil_expr);
RZ_API void rz_analysis_esil_trace_list(RzAnalysisEsil *esil);
RZ_API void rz_analysis_esil_trace_show(RzAnalysisEsil *esil, int idx);
RZ_API void rz_analysis_esil_trace_restore(RzAnalysisEsil *esil, int idx);

#ifdef __cplusplus
}
#endif

#endif /* RZ_ANALYSIS_ESIL_H */
