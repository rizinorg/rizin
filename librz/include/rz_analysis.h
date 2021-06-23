// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 xvilka <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ANALYSIS_H
#define RZ_ANALYSIS_H

/* use old refs and function storage */
// still required by core in lot of places
#define USE_VARSUBS 0

#include <rz_types.h>
#include <rz_io.h>
#include <rz_reg.h>
#include <rz_list.h>
#include <rz_search.h>
#include <rz_util.h>
#include <rz_bind.h>
#include <rz_syscall.h>
#include <set.h>
#include <rz_flag.h>
#include <rz_bin.h>
#include <rz_type.h>
#include <rz_arch.h>

#define esilprintf(op, fmt, ...) rz_strbuf_setf(&op->esil, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_analysis);

/* dwarf processing context */
typedef struct rz_analysis_dwarf_context {
	const RzBinDwarfDebugInfo *info;
	HtUP /*<offset, RzBinDwarfLocList*>*/ *loc;
	// const RzBinDwarfCfa *cfa; TODO
} RzAnalysisDwarfContext;

// TODO: save memory2 : fingerprints must be pointers to a buffer
// containing a dupped file in memory

/* save memory:
   bb_has_ops=1 -> 600M
   bb_has_ops=0 -> 350MB
 */

typedef struct {
	struct rz_analysis_t *analysis;
	int type;
	int rad;
	SdbForeachCallback cb;
	void *user;
	int count;
	struct rz_analysis_function_t *fcn;
	PJ *pj;
} RzAnalysisMetaUserItem;

typedef struct rz_analysis_range_t {
	ut64 from;
	ut64 to;
	int bits;
	ut64 rb_max_addr;
	RBNode rb;
} RzAnalysisRange;

#define RZ_ANALYSIS_GET_OFFSET(x, y, z) \
	(x && x->binb.bin && x->binb.get_offset) ? x->binb.get_offset(x->binb.bin, y, z) : -1
enum {
	RZ_ANALYSIS_DATA_TYPE_NULL = 0,
	RZ_ANALYSIS_DATA_TYPE_UNKNOWN = 1,
	RZ_ANALYSIS_DATA_TYPE_STRING = 2,
	RZ_ANALYSIS_DATA_TYPE_WIDE_STRING = 3,
	RZ_ANALYSIS_DATA_TYPE_POINTER = 4,
	RZ_ANALYSIS_DATA_TYPE_NUMBER = 5,
	RZ_ANALYSIS_DATA_TYPE_INVALID = 6,
	RZ_ANALYSIS_DATA_TYPE_HEADER = 7,
	RZ_ANALYSIS_DATA_TYPE_SEQUENCE = 8,
	RZ_ANALYSIS_DATA_TYPE_PATTERN = 9,
};

// used from core/analysis.c
#define RZ_ANALYSIS_ADDR_TYPE_EXEC     1
#define RZ_ANALYSIS_ADDR_TYPE_READ     1 << 1
#define RZ_ANALYSIS_ADDR_TYPE_WRITE    1 << 2
#define RZ_ANALYSIS_ADDR_TYPE_FLAG     1 << 3
#define RZ_ANALYSIS_ADDR_TYPE_FUNC     1 << 4
#define RZ_ANALYSIS_ADDR_TYPE_HEAP     1 << 5
#define RZ_ANALYSIS_ADDR_TYPE_STACK    1 << 6
#define RZ_ANALYSIS_ADDR_TYPE_REG      1 << 7
#define RZ_ANALYSIS_ADDR_TYPE_PROGRAM  1 << 8
#define RZ_ANALYSIS_ADDR_TYPE_LIBRARY  1 << 9
#define RZ_ANALYSIS_ADDR_TYPE_ASCII    1 << 10
#define RZ_ANALYSIS_ADDR_TYPE_SEQUENCE 1 << 11

#define RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE 0
#define RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE 1
#define RZ_ANALYSIS_ARCHINFO_ALIGN       2
#define RZ_ANALYSIS_ARCHINFO_DATA_ALIGN  4

/* copypaste from rz_asm.h */

#define RZ_ANALYSIS_GET_OFFSET(x, y, z) \
	(x && x->binb.bin && x->binb.get_offset) ? x->binb.get_offset(x->binb.bin, y, z) : -1

#define RZ_ANALYSIS_GET_NAME(x, y, z) \
	(x && x->binb.bin && x->binb.get_name) ? x->binb.get_name(x->binb.bin, y, z) : NULL

/* type = (RZ_ANALYSIS_VAR_TYPE_BYTE & RZ_ANALYSIS_VAR_TYPE_SIZE_MASK) |
 *			( RANAL_VAR_TYPE_SIGNED & RANAL_VAR_TYPE_SIGN_MASK) |
 *			( RANAL_VAR_TYPE_CONST & RANAL_VAR_TYPE_MODIFIER_MASK)
 */
typedef struct rz_analysis_type_var_t {
	char *name;
	int index;
	int scope;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	union {
		ut8 v8;
		ut16 v16;
		ut32 v32;
		ut64 v64;
	} value;
} RzAnalysisTypeVar;

typedef struct rz_analysis_type_ptr_t {
	char *name;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	union {
		ut8 v8;
		ut16 v16;
		ut32 v32;
		ut64 v64;
	} value;
} RzAnalysisTypePtr;

typedef struct rz_analysis_type_array_t {
	char *name;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	ut64 count;
	union {
		ut8 *v8;
		ut16 *v16;
		ut32 *v32;
		ut64 *v64;
	} value;
} RzAnalysisTypeArray;

typedef struct rz_analysis_type_struct_t RzAnalysisTypeStruct;
typedef struct rz_analysis_type_t RzAnalysisType;

struct rz_analysis_type_struct_t {
	char *name;
	ut8 type;
	ut32 size;
	void *parent;
	RzAnalysisType *items;
};

typedef struct rz_analysis_type_union_t {
	char *name;
	ut8 type;
	ut32 size;
	void *parent;
	RzAnalysisType *items;
} RzAnalysisTypeUnion;

typedef struct rz_analysis_type_alloca_t {
	long address;
	long size;
	void *parent;
	RzAnalysisType *items;
} RzAnalysisTypeAlloca;

enum {
	RZ_ANALYSIS_FQUALIFIER_NONE = 0,
	RZ_ANALYSIS_FQUALIFIER_STATIC = 1,
	RZ_ANALYSIS_FQUALIFIER_VOLATILE = 2,
	RZ_ANALYSIS_FQUALIFIER_INLINE = 3,
	RZ_ANALYSIS_FQUALIFIER_NAKED = 4,
	RZ_ANALYSIS_FQUALIFIER_VIRTUAL = 5,
};

#define RZ_ANALYSIS_CC_MAXARG 16

enum {
	RZ_ANALYSIS_FCN_TYPE_NULL = 0,
	RZ_ANALYSIS_FCN_TYPE_FCN = 1 << 0,
	RZ_ANALYSIS_FCN_TYPE_LOC = 1 << 1,
	RZ_ANALYSIS_FCN_TYPE_SYM = 1 << 2,
	RZ_ANALYSIS_FCN_TYPE_IMP = 1 << 3,
	RZ_ANALYSIS_FCN_TYPE_INT = 1 << 4, /* privileged function - ends with iret/reti/.. */
	RZ_ANALYSIS_FCN_TYPE_ROOT = 1 << 5, /* matching flag */
	RZ_ANALYSIS_FCN_TYPE_ANY = -1 /* all the bits set */
};

#define RzAnalysisBlock struct rz_analysis_bb_t

enum {
	RZ_ANALYSIS_DIFF_TYPE_NULL = 0,
	RZ_ANALYSIS_DIFF_TYPE_MATCH = 'm',
	RZ_ANALYSIS_DIFF_TYPE_UNMATCH = 'u'
};

typedef struct rz_analysis_diff_t {
	int type;
	ut64 addr;
	double dist;
	char *name;
	ut32 size;
} RzAnalysisDiff;

typedef struct rz_analysis_attr_t RzAnalysisAttr;

struct rz_analysis_attr_t {
	char *key;
	long value;
	RzAnalysisAttr *next;
};

/* Stores useful function metadata */
/* TODO: Think about moving more stuff to this structure? */
typedef struct rz_analysis_fcn_meta_t {
	// _min and _max are calculated lazily when queried.
	// On changes, they will either be updated (if this can be done trivially) or invalidated.
	// They are invalid iff _min == UT64_MAX.
	ut64 _min; // PRIVATE, min address, use rz_analysis_function_min_addr() to access
	ut64 _max; // PRIVATE, max address, use rz_analysis_function_max_addr() to access

	int numrefs; // number of cross references
	int numcallrefs; // number of calls
} RzAnalysisFcnMeta;

typedef struct rz_analysis_function_t {
	char *name;
	int bits; // ((> bits 0) (set-bits bits))
	int type;
	const char *cc; // calling convention, should come from RzAnalysis.constpool
	ut64 addr;
	HtUP /*<ut64, char *>*/ *labels;
	HtPP /*<char *, ut64 *>*/ *label_addrs;
	RzPVector vars;
	HtUP /*<st64, RzPVector<RzAnalysisVar *>>*/ *inst_vars; // offset of instructions => the variables they access
	ut64 reg_save_area; // size of stack area pre-reserved for saving registers
	st64 bp_off; // offset of bp inside owned stack frame
	st64 stack; // stack frame size
	int maxstack;
	int ninstr;
	bool is_pure;
	bool is_variadic;
	bool has_changed; // true if function may have changed since last anaysis TODO: set this attribute where necessary
	bool bp_frame;
	bool is_noreturn; // true if function does not return
	ut8 *fingerprint; // TODO: make is fuzzy and smarter
	size_t fingerprint_size;
	RzAnalysisDiff *diff;
	RzList *bbs; // TODO: should be RzPVector
	RzAnalysisFcnMeta meta;
	RzList *imports; // maybe bound to class?
	struct rz_analysis_t *analysis; // this function is associated with this instance
} RzAnalysisFunction;

typedef struct rz_analysis_func_arg_t {
	const char *name;
	const char *fmt;
	const char *cc_source;
	RzType *orig_c_type;
	RzType *c_type;
	ut64 size;
	ut64 src; //Function-call argument value or pointer to it
} RzAnalysisFuncArg;

struct rz_analysis_type_t {
	char *name;
	ut32 type;
	ut32 size;
	RzList *content;
};

typedef enum {
	RZ_META_TYPE_ANY = -1,
	RZ_META_TYPE_DATA = 'd',
	RZ_META_TYPE_CODE = 'c',
	RZ_META_TYPE_STRING = 's',
	RZ_META_TYPE_FORMAT = 'f',
	RZ_META_TYPE_MAGIC = 'm',
	RZ_META_TYPE_HIDE = 'h',
	RZ_META_TYPE_COMMENT = 'C',
	RZ_META_TYPE_RUN = 'r',
	RZ_META_TYPE_HIGHLIGHT = 'H',
	RZ_META_TYPE_VARTYPE = 't',
} RzAnalysisMetaType;

/* meta */
typedef struct rz_analysis_meta_item_t {
	RzAnalysisMetaType type;
	int subtype;
	char *str;
	const RzSpace *space;
} RzAnalysisMetaItem;

// anal
typedef enum {
	RZ_ANALYSIS_OP_FAMILY_UNKNOWN = -1,
	RZ_ANALYSIS_OP_FAMILY_CPU = 0, /* normal cpu instruction */
	RZ_ANALYSIS_OP_FAMILY_FPU, /* fpu (floating point) */
	RZ_ANALYSIS_OP_FAMILY_MMX, /* multimedia instruction (packed data) */
	RZ_ANALYSIS_OP_FAMILY_SSE, /* extended multimedia instruction (packed data) */
	RZ_ANALYSIS_OP_FAMILY_PRIV, /* privileged instruction */
	RZ_ANALYSIS_OP_FAMILY_CRYPTO, /* cryptographic instructions */
	RZ_ANALYSIS_OP_FAMILY_THREAD, /* thread/lock/sync instructions */
	RZ_ANALYSIS_OP_FAMILY_VIRT, /* virtualization instructions */
	RZ_ANALYSIS_OP_FAMILY_SECURITY, /* security instructions */
	RZ_ANALYSIS_OP_FAMILY_IO, /* IO instructions (i.e. IN/OUT) */
	RZ_ANALYSIS_OP_FAMILY_LAST
} RzAnalysisOpFamily;

#if 0
On x86 according to Wikipedia

	Prefix group 1
	0xF0: LOCK prefix
	0xF2: REPNE/REPNZ prefix
	0xF3: REP or REPE/REPZ prefix
	Prefix group 2
	0x2E: CS segment override
	0x36: SS segment override
	0x3E: DS segment override
	0x26: ES segment override
	0x64: FS segment override
	0x65: GS segment override
	0x2E: Branch not taken    (hinting)
	0x3E: Branch taken
	Prefix group 3
	0x66: Operand-size override prefix
	Prefix group 4
	0x67: Address-size override prefix
#endif
typedef enum {
	RZ_ANALYSIS_OP_PREFIX_COND = 1,
	RZ_ANALYSIS_OP_PREFIX_REP = 1 << 1,
	RZ_ANALYSIS_OP_PREFIX_REPNE = 1 << 2,
	RZ_ANALYSIS_OP_PREFIX_LOCK = 1 << 3,
	RZ_ANALYSIS_OP_PREFIX_LIKELY = 1 << 4,
	RZ_ANALYSIS_OP_PREFIX_UNLIKELY = 1 << 5
	/* TODO: add segment override typemods? */
} RzAnalysisOpPrefix;

// XXX: this definition is plain wrong. use enum or empower bits
#define RZ_ANALYSIS_OP_TYPE_MASK 0x8000ffff
#define RZ_ANALYSIS_OP_HINT_MASK 0xf0000000
typedef enum {
	RZ_ANALYSIS_OP_TYPE_COND = 0x80000000, // TODO must be moved to prefix?
	//TODO: MOVE TO PREFIX .. it is used by analysis_java.. must be updated
	RZ_ANALYSIS_OP_TYPE_REP = 0x40000000, /* repeats next instruction N times */
	RZ_ANALYSIS_OP_TYPE_MEM = 0x20000000, // TODO must be moved to prefix?
	RZ_ANALYSIS_OP_TYPE_REG = 0x10000000, // operand is a register
	RZ_ANALYSIS_OP_TYPE_IND = 0x08000000, // operand is indirect
	RZ_ANALYSIS_OP_TYPE_NULL = 0,
	RZ_ANALYSIS_OP_TYPE_JMP = 1, /* mandatory jump */
	RZ_ANALYSIS_OP_TYPE_UJMP = 2, /* unknown jump (register or so) */
	RZ_ANALYSIS_OP_TYPE_RJMP = RZ_ANALYSIS_OP_TYPE_REG | RZ_ANALYSIS_OP_TYPE_UJMP,
	RZ_ANALYSIS_OP_TYPE_IJMP = RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_UJMP,
	RZ_ANALYSIS_OP_TYPE_IRJMP = RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_REG | RZ_ANALYSIS_OP_TYPE_UJMP,
	RZ_ANALYSIS_OP_TYPE_CJMP = RZ_ANALYSIS_OP_TYPE_COND | RZ_ANALYSIS_OP_TYPE_JMP, /* conditional jump */
	RZ_ANALYSIS_OP_TYPE_RCJMP = RZ_ANALYSIS_OP_TYPE_REG | RZ_ANALYSIS_OP_TYPE_CJMP, /* conditional jump register */
	RZ_ANALYSIS_OP_TYPE_MJMP = RZ_ANALYSIS_OP_TYPE_MEM | RZ_ANALYSIS_OP_TYPE_JMP, /* memory jump */
	RZ_ANALYSIS_OP_TYPE_MCJMP = RZ_ANALYSIS_OP_TYPE_MEM | RZ_ANALYSIS_OP_TYPE_CJMP, /* memory conditional jump */
	RZ_ANALYSIS_OP_TYPE_UCJMP = RZ_ANALYSIS_OP_TYPE_COND | RZ_ANALYSIS_OP_TYPE_UJMP, /* conditional unknown jump */
	RZ_ANALYSIS_OP_TYPE_CALL = 3, /* call to subroutine (branch+link) */
	RZ_ANALYSIS_OP_TYPE_UCALL = 4, /* unknown call (register or so) */
	RZ_ANALYSIS_OP_TYPE_RCALL = RZ_ANALYSIS_OP_TYPE_REG | RZ_ANALYSIS_OP_TYPE_UCALL,
	RZ_ANALYSIS_OP_TYPE_ICALL = RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_UCALL,
	RZ_ANALYSIS_OP_TYPE_IRCALL = RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_REG | RZ_ANALYSIS_OP_TYPE_UCALL,
	RZ_ANALYSIS_OP_TYPE_CCALL = RZ_ANALYSIS_OP_TYPE_COND | RZ_ANALYSIS_OP_TYPE_CALL, /* conditional call to subroutine */
	RZ_ANALYSIS_OP_TYPE_UCCALL = RZ_ANALYSIS_OP_TYPE_COND | RZ_ANALYSIS_OP_TYPE_UCALL, /* conditional unknown call */
	RZ_ANALYSIS_OP_TYPE_RET = 5, /* returns from subroutine */
	RZ_ANALYSIS_OP_TYPE_CRET = RZ_ANALYSIS_OP_TYPE_COND | RZ_ANALYSIS_OP_TYPE_RET, /* conditional return from subroutine */
	RZ_ANALYSIS_OP_TYPE_ILL = 6, /* illegal instruction // trap */
	RZ_ANALYSIS_OP_TYPE_UNK = 7, /* unknown opcode type */
	RZ_ANALYSIS_OP_TYPE_NOP = 8, /* does nothing */
	RZ_ANALYSIS_OP_TYPE_MOV = 9, /* register move */
	RZ_ANALYSIS_OP_TYPE_CMOV = 9 | RZ_ANALYSIS_OP_TYPE_COND, /* conditional move */
	RZ_ANALYSIS_OP_TYPE_TRAP = 10, /* it's a trap! */
	RZ_ANALYSIS_OP_TYPE_SWI = 11, /* syscall, software interrupt */
	RZ_ANALYSIS_OP_TYPE_CSWI = 11 | RZ_ANALYSIS_OP_TYPE_COND, /* syscall, software interrupt */
	RZ_ANALYSIS_OP_TYPE_UPUSH = 12, /* unknown push of data into stack */
	RZ_ANALYSIS_OP_TYPE_RPUSH = RZ_ANALYSIS_OP_TYPE_UPUSH | RZ_ANALYSIS_OP_TYPE_REG, /* push register */
	RZ_ANALYSIS_OP_TYPE_PUSH = 13, /* push value into stack */
	RZ_ANALYSIS_OP_TYPE_POP = 14, /* pop value from stack to register */
	RZ_ANALYSIS_OP_TYPE_CMP = 15, /* compare something */
	RZ_ANALYSIS_OP_TYPE_ACMP = 16, /* compare via and */
	RZ_ANALYSIS_OP_TYPE_ADD = 17,
	RZ_ANALYSIS_OP_TYPE_SUB = 18,
	RZ_ANALYSIS_OP_TYPE_IO = 19,
	RZ_ANALYSIS_OP_TYPE_MUL = 20,
	RZ_ANALYSIS_OP_TYPE_DIV = 21,
	RZ_ANALYSIS_OP_TYPE_SHR = 22,
	RZ_ANALYSIS_OP_TYPE_SHL = 23,
	RZ_ANALYSIS_OP_TYPE_SAL = 24,
	RZ_ANALYSIS_OP_TYPE_SAR = 25,
	RZ_ANALYSIS_OP_TYPE_OR = 26,
	RZ_ANALYSIS_OP_TYPE_AND = 27,
	RZ_ANALYSIS_OP_TYPE_XOR = 28,
	RZ_ANALYSIS_OP_TYPE_NOR = 29,
	RZ_ANALYSIS_OP_TYPE_NOT = 30,
	RZ_ANALYSIS_OP_TYPE_STORE = 31, /* store from register to memory */
	RZ_ANALYSIS_OP_TYPE_LOAD = 32, /* load from memory to register */
	RZ_ANALYSIS_OP_TYPE_LEA = 33, /* TODO add ulea */
	RZ_ANALYSIS_OP_TYPE_LEAVE = 34,
	RZ_ANALYSIS_OP_TYPE_ROR = 35,
	RZ_ANALYSIS_OP_TYPE_ROL = 36,
	RZ_ANALYSIS_OP_TYPE_XCHG = 37,
	RZ_ANALYSIS_OP_TYPE_MOD = 38,
	RZ_ANALYSIS_OP_TYPE_SWITCH = 39,
	RZ_ANALYSIS_OP_TYPE_CASE = 40,
	RZ_ANALYSIS_OP_TYPE_LENGTH = 41,
	RZ_ANALYSIS_OP_TYPE_CAST = 42,
	RZ_ANALYSIS_OP_TYPE_NEW = 43,
	RZ_ANALYSIS_OP_TYPE_ABS = 44,
	RZ_ANALYSIS_OP_TYPE_CPL = 45, /* complement */
	RZ_ANALYSIS_OP_TYPE_CRYPTO = 46,
	RZ_ANALYSIS_OP_TYPE_SYNC = 47,
//RZ_ANALYSIS_OP_TYPE_DEBUG = 43, // monitor/trace/breakpoint
#if 0
	RZ_ANALYSIS_OP_TYPE_PRIV = 40, /* privileged instruction */
	RZ_ANALYSIS_OP_TYPE_FPU = 41, /* floating point stuff */
#endif
} _RzAnalysisOpType;

typedef enum {
	RZ_ANALYSIS_OP_MASK_BASIC = 0, // Just fills basic op info , it's fast
	RZ_ANALYSIS_OP_MASK_ESIL = 1, // It fills RzAnalysisop->esil info
	RZ_ANALYSIS_OP_MASK_VAL = 2, // It fills RzAnalysisop->dst/src info
	RZ_ANALYSIS_OP_MASK_HINT = 4, // It calls rz_analysis_op_hint to override analysis options
	RZ_ANALYSIS_OP_MASK_OPEX = 8, // It fills RzAnalysisop->opex info
	RZ_ANALYSIS_OP_MASK_DISASM = 16, // It fills RzAnalysisop->mnemonic // should be RzAnalysisOp->disasm // only from rz_core_analysis_op()
	RZ_ANALYSIS_OP_MASK_ALL = 1 | 2 | 4 | 8 | 16
} RzAnalysisOpMask;

/* TODO: what to do with signed/unsigned conditionals? */
typedef enum {
	RZ_ANALYSIS_COND_AL = 0, // Always executed (no condition)
	RZ_ANALYSIS_COND_EQ, // Equal
	RZ_ANALYSIS_COND_NE, // Not equal
	RZ_ANALYSIS_COND_GE, // Greater or equal
	RZ_ANALYSIS_COND_GT, // Greater than
	RZ_ANALYSIS_COND_LE, // Less or equal
	RZ_ANALYSIS_COND_LT, // Less than
	RZ_ANALYSIS_COND_NV, // Never executed             must be a nop? :D
	RZ_ANALYSIS_COND_HS, // Carry set                  >, ==, or unordered
	RZ_ANALYSIS_COND_LO, // Carry clear                Less than
	RZ_ANALYSIS_COND_MI, // Minus, negative            Less than
	RZ_ANALYSIS_COND_PL, // Plus, positive or zero     >, ==, or unordered
	RZ_ANALYSIS_COND_VS, // Overflow                   Unordered
	RZ_ANALYSIS_COND_VC, // No overflow                Not unordered
	RZ_ANALYSIS_COND_HI, // Unsigned higher            Greater than, or unordered
	RZ_ANALYSIS_COND_LS // Unsigned lower or same     Less than or equal
} _RzAnalysisCond;

typedef enum {
	RZ_ANALYSIS_VAR_SCOPE_LOCAL = 0x01
} _RzAnalysisVarScope;

typedef enum {
	RZ_ANALYSIS_STACK_NULL = 0,
	RZ_ANALYSIS_STACK_NOP,
	RZ_ANALYSIS_STACK_INC,
	RZ_ANALYSIS_STACK_GET,
	RZ_ANALYSIS_STACK_SET,
	RZ_ANALYSIS_STACK_RESET,
	RZ_ANALYSIS_STACK_ALIGN,
} RzAnalysisStackOp;

enum {
	RZ_ANALYSIS_REFLINE_TYPE_UTF8 = 1,
	RZ_ANALYSIS_REFLINE_TYPE_WIDE = 2, /* reflines have a space between them */
	RZ_ANALYSIS_REFLINE_TYPE_MIDDLE_BEFORE = 4, /* do not consider starts/ends of
	                                        * reflines (used for comment lines before disasm) */
	RZ_ANALYSIS_REFLINE_TYPE_MIDDLE_AFTER = 8 /* as above but for lines after disasm */
};

enum {
	RZ_ANALYSIS_RET_NOP = 0,
	RZ_ANALYSIS_RET_ERROR = -1,
	RZ_ANALYSIS_RET_DUP = -2,
	RZ_ANALYSIS_RET_NEW = -3,
	RZ_ANALYSIS_RET_END = -4
};

typedef struct rz_analysis_case_obj_t {
	ut64 addr;
	ut64 jump;
	ut64 value;
} RzAnalysisCaseOp;

typedef struct rz_analysis_switch_obj_t {
	ut64 addr;
	ut64 min_val;
	ut64 def_val;
	ut64 max_val;
	RzList /*<RzAnalysisCaseOp>*/ *cases;
} RzAnalysisSwitchOp;

struct rz_analysis_t;
struct rz_analysis_bb_t;
typedef struct rz_analysis_callbacks_t {
	int (*on_fcn_new)(struct rz_analysis_t *, void *user, RzAnalysisFunction *fcn);
	int (*on_fcn_delete)(struct rz_analysis_t *, void *user, RzAnalysisFunction *fcn);
	int (*on_fcn_rename)(struct rz_analysis_t *, void *user, RzAnalysisFunction *fcn, const char *oldname);
	int (*on_fcn_bb_new)(struct rz_analysis_t *, void *user, RzAnalysisFunction *fcn, struct rz_analysis_bb_t *bb);
} RzAnalysisCallbacks;

#define RZ_ANALYSIS_ESIL_GOTO_LIMIT 4096

typedef struct rz_analysis_options_t {
	int depth;
	int graph_depth;
	bool vars; //analysisyze local var and arguments
	bool varname_stack; // name vars based on their offset in the stack
	int cjmpref;
	int jmpref;
	int jmpabove;
	bool ijmp;
	bool jmpmid; // continue analysis after jmp into middle of insn
	bool loads;
	bool ignbithints;
	int followdatarefs;
	int searchstringrefs;
	int followbrokenfcnsrefs;
	int bb_max_size;
	bool trycatch;
	bool norevisit;
	int afterjmp; // continue analysis after jmp eax or forward jmp // option
	int recont; // continue on recurse analysis mode
	int noncode;
	int nopskip; // skip nops at the beginning of functions
	int hpskip; // skip `mov reg,reg` and `lea reg,[reg]`
	int jmptbl; // analyze jump tables
	int nonull;
	bool pushret; // analyze push+ret as jmp
	bool armthumb; //
	bool endsize; // chop function size which is known to be buggy but goodie too
	bool delay;
	int tailcall;
	bool retpoline;
} RzAnalysisOptions;

typedef enum {
	RZ_ANALYSIS_CPP_ABI_ITANIUM = 0,
	RZ_ANALYSIS_CPP_ABI_MSVC
} RzAnalysisCPPABI;

typedef struct rz_analysis_hint_cb_t {
	//add more cbs as needed
	void (*on_bits)(struct rz_analysis_t *a, ut64 addr, int bits, bool set);
} RHintCb;

typedef struct rz_analysis_t {
	char *cpu; // analysis.cpu
	char *os; // asm.os
	int bits; // asm.bits
	int lineswidth; // asm.lines.width
	int big_endian; // cfg.bigendian
	int sleep; // analysis.sleep, sleep some usecs before analyzing more (avoid 100% cpu usages)
	RzAnalysisCPPABI cpp_abi; // analysis.cpp.abi
	void *plugin_data;
	void *core;
	ut64 gp; // analysis.gp, global pointer. used for mips. but can be used by other arches too in the future
	RBTree bb_tree; // all basic blocks by address. They can overlap each other, but must never start at the same address.
	RzList *fcns;
	HtUP *ht_addr_fun; // address => function
	HtPP *ht_name_fun; // name => function
	RzReg *reg;
	ut8 *last_disasm_reg;
	RzSyscall *syscall;
	int diff_ops;
	double diff_thbb;
	double diff_thfcn;
	RzIOBind iob;
	RzFlagBind flb;
	RzFlagSet flg_class_set;
	RzFlagGet flg_class_get;
	RzFlagSet flg_fcn_set;
	RzBinBind binb; // Set only from core when an analysis plugin is called.
	RzCoreBind coreb;
	int maxreflines; // asm.lines.maxref
	int esil_goto_limit; // esil.gotolimit
	int pcalign; // asm.pcalign
	struct rz_analysis_esil_t *esil;
	struct rz_analysis_plugin_t *cur;
	RzAnalysisRange *limit; // analysis.from, analysis.to
	RzList *plugins;
	Sdb *sdb_noret;
	Sdb *sdb_fmts;
	Sdb *sdb_zigns;
	HtUP *ht_xrefs_from;
	HtUP *ht_xrefs_to;
	bool recursive_noreturn; // analysis.rnr
	RzSpaces zign_spaces;
	char *zign_path; // dir.zigns
	PrintfCallback cb_printf;
	//moved from RzAnalysisFcn
	Sdb *sdb; // root
	Sdb *sdb_pins;
	HtUP /*<RzVector<RzAnalysisAddrHintRecord>>*/ *addr_hints; // all hints that correspond to a single address
	RBTree /*<RzAnalysisArchHintRecord>*/ arch_hints;
	RBTree /*<RzAnalysisArchBitsRecord>*/ bits_hints;
	RHintCb hint_cbs;
	RzIntervalTree meta;
	RzSpaces meta_spaces;
	RzTypeDB *typedb; // Types management
	HtUP *type_links; // Type links to the memory address or register
	Sdb *sdb_cc; // calling conventions
	Sdb *sdb_classes;
	Sdb *sdb_classes_attrs;
	RzAnalysisCallbacks cb;
	RzAnalysisOptions opt;
	RzList *reflines;
	//RzList *noreturn;
	RzListComparator columnSort;
	int stackptr;
	bool (*log)(struct rz_analysis_t *analysis, const char *msg);
	bool (*read_at)(struct rz_analysis_t *analysis, ut64 addr, ut8 *buf, int len);
	bool verbose;
	int seggrn;
	RzFlagGetAtAddr flag_get;
	RzEvent *ev;
	RzList /*<char *>*/ *imports; // global imports
	SetU *visited;
	RzStrConstPool constpool;
	RzList *leaddrs;
	RzArchTarget *arch_target;
	RzArchPlatformTarget *platform_target;
} RzAnalysis;

typedef enum rz_analysis_addr_hint_type_t {
	RZ_ANALYSIS_ADDR_HINT_TYPE_IMMBASE,
	RZ_ANALYSIS_ADDR_HINT_TYPE_JUMP,
	RZ_ANALYSIS_ADDR_HINT_TYPE_FAIL,
	RZ_ANALYSIS_ADDR_HINT_TYPE_STACKFRAME,
	RZ_ANALYSIS_ADDR_HINT_TYPE_PTR,
	RZ_ANALYSIS_ADDR_HINT_TYPE_NWORD,
	RZ_ANALYSIS_ADDR_HINT_TYPE_RET,
	RZ_ANALYSIS_ADDR_HINT_TYPE_NEW_BITS,
	RZ_ANALYSIS_ADDR_HINT_TYPE_SIZE,
	RZ_ANALYSIS_ADDR_HINT_TYPE_SYNTAX,
	RZ_ANALYSIS_ADDR_HINT_TYPE_OPTYPE,
	RZ_ANALYSIS_ADDR_HINT_TYPE_OPCODE,
	RZ_ANALYSIS_ADDR_HINT_TYPE_TYPE_OFFSET,
	RZ_ANALYSIS_ADDR_HINT_TYPE_ESIL,
	RZ_ANALYSIS_ADDR_HINT_TYPE_HIGH,
	RZ_ANALYSIS_ADDR_HINT_TYPE_VAL
} RzAnalysisAddrHintType;

typedef struct rz_analysis_addr_hint_record_t {
	RzAnalysisAddrHintType type;
	union {
		char *type_offset;
		int nword;
		ut64 jump;
		ut64 fail;
		int newbits;
		int immbase;
		ut64 ptr;
		ut64 retval;
		char *syntax;
		char *opcode;
		char *esil;
		int optype;
		ut64 size;
		ut64 stackframe;
		ut64 val;
	};
} RzAnalysisAddrHintRecord;

typedef struct rz_analysis_hint_t {
	ut64 addr;
	ut64 ptr;
	ut64 val; // used to hint jmp rax
	ut64 jump;
	ut64 fail;
	ut64 ret; // hint for function ret values
	char *arch;
	char *opcode;
	char *syntax;
	char *esil;
	char *offset;
	ut32 type;
	ut64 size;
	int bits;
	int new_bits; // change asm.bits after evaluating this instruction
	int immbase;
	bool high; // highlight hint
	int nword;
	ut64 stackframe;
} RzAnalysisHint;

typedef RzAnalysisFunction *(*RzAnalysisGetFcnIn)(RzAnalysis *analysis, ut64 addr, int type);
typedef RzAnalysisHint *(*RzAnalysisGetHint)(RzAnalysis *analysis, ut64 addr);

typedef struct rz_analysis_bind_t {
	RzAnalysis *analysis;
	RzAnalysisGetFcnIn get_fcn_in;
	RzAnalysisGetHint get_hint;
} RzAnalysisBind;

typedef const char *(*RzAnalysisLabelAt)(RzAnalysisFunction *fcn, ut64);

typedef enum {
	RZ_ANALYSIS_VAR_KIND_REG = 'r',
	RZ_ANALYSIS_VAR_KIND_BPV = 'b',
	RZ_ANALYSIS_VAR_KIND_SPV = 's'
} RzAnalysisVarKind;

#define VARPREFIX "var"
#define ARGPREFIX "arg"

typedef enum {
	RZ_ANALYSIS_VAR_ACCESS_TYPE_PTR = 0,
	RZ_ANALYSIS_VAR_ACCESS_TYPE_READ = (1 << 0),
	RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE = (1 << 1)
} RzAnalysisVarAccessType;

typedef struct rz_analysis_var_access_t {
	const char *reg; // register used for access
	st64 offset; // relative to the function's entrypoint
	st64 stackptr; // delta added to register to get the var, e.g. [rbp - 0x10]
	ut8 type; // RzAnalysisVarAccessType bits
} RzAnalysisVarAccess;

typedef struct rz_analysis_var_constraint_t {
	_RzAnalysisCond cond;
	ut64 val;
} RzAnalysisVarConstraint;

// generic for args and locals
typedef struct rz_analysis_var_t {
	RzAnalysisFunction *fcn;
	char *name; // name of the variable
	RzType *type; // type of the variable
	RzAnalysisVarKind kind;
	bool isarg;
	int delta; /* delta offset inside stack frame */
	char *regname; // name of the register
	RzVector /*<RzAnalysisVarAccess>*/ accesses; // ordered by offset, touch this only through API or expect uaf
	char *comment;
	RzVector /*<RzAnalysisVarConstraint>*/ constraints;

	// below members are just for caching, TODO: remove them and do it better
	int argnum;
} RzAnalysisVar;

// Refers to a variable or a struct field inside a variable, only for varsub
RZ_DEPRECATE typedef struct rz_analysis_var_field_t {
	char *name;
	st64 delta;
	bool field;
} RzAnalysisVarField;

typedef enum {
	RZ_ANALYSIS_ACC_UNKNOWN = 0,
	RZ_ANALYSIS_ACC_R = (1 << 0),
	RZ_ANALYSIS_ACC_W = (1 << 1),
} RzAnalysisValueAccess;

typedef enum {
	RZ_ANALYSIS_VAL_REG,
	RZ_ANALYSIS_VAL_MEM,
	RZ_ANALYSIS_VAL_IMM,
} RzAnalysisValueType;

// base+reg+regdelta*mul+delta
typedef struct rz_analysis_value_t {
	RzAnalysisValueType type;
	RzAnalysisValueAccess access;
	int absolute; // if true, unsigned cast is used
	int memref; // is memory reference? which size? 1, 2 ,4, 8
	ut64 base; // numeric address
	st64 delta; // numeric delta
	st64 imm; // immediate value
	int mul; // multiplier (reg*4+base)
	RzRegItem *seg; // segment selector register
	RzRegItem *reg; // register / register base used (-1 if no reg)
	RzRegItem *regdelta; // register index used (-1 if no reg)
} RzAnalysisValue;

typedef enum {
	RZ_ANALYSIS_OP_DIR_READ = 1,
	RZ_ANALYSIS_OP_DIR_WRITE = 2,
	RZ_ANALYSIS_OP_DIR_EXEC = 4,
	RZ_ANALYSIS_OP_DIR_REF = 8,
} RzAnalysisOpDirection;

typedef enum rz_analysis_data_type_t {
	RZ_ANALYSIS_DATATYPE_NULL = 0,
	RZ_ANALYSIS_DATATYPE_ARRAY,
	RZ_ANALYSIS_DATATYPE_OBJECT, // instance
	RZ_ANALYSIS_DATATYPE_STRING,
	RZ_ANALYSIS_DATATYPE_CLASS,
	RZ_ANALYSIS_DATATYPE_BOOLEAN,
	RZ_ANALYSIS_DATATYPE_INT16,
	RZ_ANALYSIS_DATATYPE_INT32,
	RZ_ANALYSIS_DATATYPE_INT64,
	RZ_ANALYSIS_DATATYPE_FLOAT,
} RzAnalysisDataType;

typedef struct rz_analysis_op_t {
	char *mnemonic; /* mnemonic.. it actually contains the args too, we should replace rasm with this */
	ut64 addr; /* address */
	ut32 type; /* type of opcode */
	RzAnalysisOpPrefix prefix; /* type of opcode prefix (rep,lock,..) */
	ut32 type2; /* used by java */
	RzAnalysisStackOp stackop; /* operation on stack? */
	_RzAnalysisCond cond; /* condition type */
	int size; /* size in bytes of opcode */
	int nopcode; /* number of bytes representing the opcode (not the arguments) TODO: find better name */
	int cycles; /* cpu-cycles taken by instruction */
	int failcycles; /* conditional cpu-cycles */
	RzAnalysisOpFamily family; /* family of opcode */
	int id; /* instruction id */
	bool eob; /* end of block (boolean) */
	bool sign; /* operates on signed values, false by default */
	/* Run N instructions before executing the current one */
	int delay; /* delay N slots (mips, ..)*/
	ut64 jump; /* true jmp */
	ut64 fail; /* false jmp */
	RzAnalysisOpDirection direction;
	st64 ptr; /* reference to memory */ /* XXX signed? */
	ut64 val; /* reference to value */ /* XXX signed? */
	int ptrsize; /* f.ex: zero extends for 8, 16 or 32 bits only */
	st64 stackptr; /* stack pointer */
	int refptr; /* if (0) ptr = "reference" else ptr = "load memory of refptr bytes" */
	RzAnalysisValue *src[3];
	RzAnalysisValue *dst;
	RzList *access; /* RzAnalysisValue access information */
	RzStrBuf esil;
	RzStrBuf opex;
	const char *reg; /* destination register */
	const char *ireg; /* register used for indirect memory computation*/
	int scale;
	ut64 disp;
	RzAnalysisSwitchOp *switch_op;
	RzAnalysisHint hint;
	RzAnalysisDataType datatype;
} RzAnalysisOp;

#define RZ_ANALYSIS_COND_SINGLE(x) (!x->arg[1] || x->arg[0] == x->arg[1])

typedef struct rz_analysis_cond_t {
	int type; // filled by CJMP opcode
	RzAnalysisValue *arg[2]; // filled by CMP opcode
} RzAnalysisCond;

typedef struct rz_analysis_bb_t {
	RBNode _rb; // private, node in the RBTree
	ut64 _max_end; // private, augmented value for RBTree

	ut64 addr;
	ut64 size;
	ut64 jump;
	ut64 fail;
	bool traced;
	ut32 colorize;
	ut8 *fingerprint;
	RzAnalysisDiff *diff;
	RzAnalysisCond *cond;
	RzAnalysisSwitchOp *switch_op;
	ut16 *op_pos; // offsets of instructions in this block, count is ninstr - 1 (first is always 0)
	ut8 *op_bytes;
	ut8 *parent_reg_arena;
	int op_pos_size; // size of the op_pos array
	int ninstr;
	int stackptr;
	int parent_stackptr;
	ut64 cmpval;
	const char *cmpreg;
	ut32 bbhash; // calculated with xxhash

	RzList *fcns;
	RzAnalysis *analysis;
	int ref;
#undef RzAnalysisBlock
} RzAnalysisBlock;

typedef enum {
	RZ_ANALYSIS_REF_TYPE_NULL = 0,
	RZ_ANALYSIS_REF_TYPE_CODE = 'c', // code ref
	RZ_ANALYSIS_REF_TYPE_CALL = 'C', // code ref (call)
	RZ_ANALYSIS_REF_TYPE_DATA = 'd', // mem ref
	RZ_ANALYSIS_REF_TYPE_STRING = 's' // string ref
} RzAnalysisXRefType;

typedef struct rz_analysis_ref_t {
	ut64 from;
	ut64 to;
	RzAnalysisXRefType type;
} RzAnalysisXRef;
RZ_API const char *rz_analysis_ref_type_tostring(RzAnalysisXRefType t);

/* represents a reference line from one address (from) to another (to) */
typedef struct rz_analysis_refline_t {
	ut64 from;
	ut64 to;
	int index;
	int level;
	int type;
	int direction;
} RzAnalysisRefline;

typedef struct rz_analysis_cycle_frame_t {
	ut64 naddr; //next addr
	RzList *hooks;
	struct rz_analysis_cycle_frame_t *prev;
} RzAnalysisCycleFrame;

typedef struct rz_analysis_cycle_hook_t { //rename ?
	ut64 addr;
	int cycles;
} RzAnalysisCycleHook;

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
	RZ_ANALYSIS_TRAP_NONE = 0,
	RZ_ANALYSIS_TRAP_UNHANDLED = 1,
	RZ_ANALYSIS_TRAP_BREAKPOINT = 2,
	RZ_ANALYSIS_TRAP_DIVBYZERO = 3,
	RZ_ANALYSIS_TRAP_WRITE_ERR = 4,
	RZ_ANALYSIS_TRAP_READ_ERR = 5,
	RZ_ANALYSIS_TRAP_EXEC_ERR = 6,
	RZ_ANALYSIS_TRAP_INVALID = 7,
	RZ_ANALYSIS_TRAP_UNALIGNED = 8,
	RZ_ANALYSIS_TRAP_TODO = 9,
	RZ_ANALYSIS_TRAP_HALT = 10,
};

enum {
	RZ_ANALYSIS_ESIL_PARM_INVALID = 0,
	RZ_ANALYSIS_ESIL_PARM_REG,
	RZ_ANALYSIS_ESIL_PARM_NUM,
};

typedef struct rz_analysis_ref_char {
	char *str;
	char *cols;
} RzAnalysisRefStr;

// must be a char
#define ESIL_INTERNAL_PREFIX '$'
#define ESIL_STACK_NAME      "esil.ram"
#define ESIL                 struct rz_analysis_esil_t

typedef struct rz_analysis_esil_source_t {
	ut32 id;
	ut32 claimed;
	void *content;
} RzAnalysisEsilSource;

RZ_API void rz_analysis_esil_sources_init(ESIL *esil);
RZ_API ut32 rz_analysis_esil_load_source(ESIL *esil, const char *path);
RZ_API void *rz_analysis_esil_get_source(ESIL *esil, ut32 src_id);
RZ_API bool rz_analysis_esil_claim_source(ESIL *esil, ut32 src_id);
RZ_API void rz_analysis_esil_release_source(ESIL *esil, ut32 src_id);
RZ_API void rz_analysis_esil_sources_fini(ESIL *esil);

typedef bool (*RzAnalysisEsilInterruptCB)(ESIL *esil, ut32 interrupt, void *user);

typedef struct rz_analysis_esil_interrupt_handler_t {
	const ut32 num;
	const char *name;
	void *(*init)(ESIL *esil);
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
	//TODO remove `db` and reuse info above
	Sdb *db;
} RzAnalysisEsilTrace;

typedef int (*RzAnalysisEsilHookRegWriteCB)(ESIL *esil, const char *name, ut64 *val);

typedef struct rz_analysis_esil_callbacks_t {
	void *user;
	/* callbacks */
	int (*hook_flag_read)(ESIL *esil, const char *flag, ut64 *num);
	int (*hook_command)(ESIL *esil, const char *op);
	int (*hook_mem_read)(ESIL *esil, ut64 addr, ut8 *buf, int len);
	int (*mem_read)(ESIL *esil, ut64 addr, ut8 *buf, int len);
	int (*hook_mem_write)(ESIL *esil, ut64 addr, const ut8 *buf, int len);
	int (*mem_write)(ESIL *esil, ut64 addr, const ut8 *buf, int len);
	int (*hook_reg_read)(ESIL *esil, const char *name, ut64 *res, int *size);
	int (*reg_read)(ESIL *esil, const char *name, ut64 *res, int *size);
	RzAnalysisEsilHookRegWriteCB hook_reg_write;
	int (*reg_write)(ESIL *esil, const char *name, ut64 val);
} RzAnalysisEsilCallbacks;

typedef struct rz_analysis_esil_t {
	RzAnalysis *analysis;
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
	ut64 old; //used for carry-flagging and borrow-flagging
	ut64 cur; //used for carry-flagging and borrow-flagging
	ut8 lastsz; //in bits //used for signature-flag
	/* native ops and custom ops */
	HtPP *ops;
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
	bool (*cmd)(ESIL *esil, const char *name, ut64 a0, ut64 a1);
	void *user;
	int stack_fd; // ahem, let's not do this
} RzAnalysisEsil;

#undef ESIL

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
	char *expr; //synthesized esil-expression for this block
	RzAnalysisEsilBlockEnterType enter; //maybe more type is needed here
} RzAnalysisEsilBB;

typedef struct rz_analysis_esil_cfg_t {
	RzGraphNode *start;
	RzGraphNode *end;
	RzGraph *g;
} RzAnalysisEsilCFG;

typedef enum {
	RZ_ANALYSIS_ESIL_DFG_BLOCK_CONST = 1,
	RZ_ANALYSIS_ESIL_DFG_BLOCK_VAR = 2,
	RZ_ANALYSIS_ESIL_DFG_BLOCK_PTR = 4,
	RZ_ANALYSIS_ESIL_DFG_BLOCK_RESULT = 8,
	RZ_ANALYSIS_ESIL_DFG_BLOCK_GENERATIVE = 16,
} RzAnalysisEsilDFGBlockType;

typedef struct rz_analysis_esil_dfg_t {
	ut32 idx;
	HtPP *reg_items_ht;
	HtPP *reg_nodes_ht;
	HtPP *var_nodes_ht;
	RContRBTree *reg_vars; //vars represented in regs
	RQueue *todo; //todo-queue allocated in this struct for perf
	void *insert; //needed for setting regs in dfg
	RzGraph *flow;
	RzGraphNode *cur;
	RzGraphNode *old;
	bool malloc_failed;
} RzAnalysisEsilDFG;

typedef struct rz_analysis_esil_dfg_node_t {
	// add more info here
	ut32 idx;
	RzStrBuf *content;
	RzAnalysisEsilDFGBlockType type;
} RzAnalysisEsilDFGNode;

// TODO: rm data + len
typedef int (*RzAnalysisOpCallback)(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask);

typedef bool (*RzAnalysisRegProfCallback)(RzAnalysis *a);
typedef char *(*RzAnalysisRegProfGetCallback)(RzAnalysis *a);
typedef int (*RzAnalysisFPBBCallback)(RzAnalysis *a, RzAnalysisBlock *bb);
typedef int (*RzAnalysisFPFcnCallback)(RzAnalysis *a, RzAnalysisFunction *fcn);
typedef int (*RzAnalysisDiffBBCallback)(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisFunction *fcn2);
typedef int (*RzAnalysisDiffFcnCallback)(RzAnalysis *analysis, RzList *fcns, RzList *fcns2);
typedef int (*RzAnalysisDiffEvalCallback)(RzAnalysis *analysis);

typedef int (*RzAnalysisEsilCB)(RzAnalysisEsil *esil);
typedef int (*RzAnalysisEsilLoopCB)(RzAnalysisEsil *esil, RzAnalysisOp *op);
typedef int (*RzAnalysisEsilTrapCB)(RzAnalysisEsil *esil, int trap_type, int trap_code);

typedef struct rz_analysis_plugin_t {
	const char *name;
	const char *desc;
	const char *license;
	const char *arch;
	const char *author;
	const char *version;
	int bits;
	int esil; // can do esil or not
	int fileformat_type;
	bool (*init)(void **user);
	bool (*fini)(void *user);
	//int (*reset_counter) (RzAnalysis *analysis, ut64 start_addr);
	int (*archinfo)(RzAnalysis *analysis, int query);
	ut8 *(*analysis_mask)(RzAnalysis *analysis, int size, const ut8 *data, ut64 at);
	RzList *(*preludes)(RzAnalysis *analysis);

	// legacy rz_analysis_functions
	RzAnalysisOpCallback op;

	RzAnalysisRegProfCallback set_reg_profile;
	RzAnalysisRegProfGetCallback get_reg_profile;
	RzAnalysisFPBBCallback fingerprint_bb;
	RzAnalysisFPFcnCallback fingerprint_fcn;
	RzAnalysisDiffBBCallback diff_bb;
	RzAnalysisDiffFcnCallback diff_fcn;
	RzAnalysisDiffEvalCallback diff_eval;

	RzAnalysisEsilCB esil_init; // initialize esil-related stuff
	RzAnalysisEsilLoopCB esil_post_loop; //cycle-counting, firing interrupts, ...
	RzAnalysisEsilTrapCB esil_trap; // traps / exceptions
	RzAnalysisEsilCB esil_fini; // deinitialize
} RzAnalysisPlugin;

/*----------------------------------------------------------------------------------------------*/
int *(rz_analysis_compare)(RzAnalysisFunction, RzAnalysisFunction);
/*----------------------------------------------------------------------------------------------*/

#ifdef RZ_API
/* --------- */ /* REFACTOR */ /* ---------- */
RZ_API RzListRange *rz_listrange_new(void);
RZ_API void rz_listrange_free(RzListRange *s);
RZ_API void rz_listrange_add(RzListRange *s, RzAnalysisFunction *f);
RZ_API void rz_listrange_del(RzListRange *s, RzAnalysisFunction *f);
RZ_API void rz_listrange_resize(RzListRange *s, RzAnalysisFunction *f, int newsize);
RZ_API RzAnalysisFunction *rz_listrange_find_in_range(RzListRange *s, ut64 addr);
RZ_API RzAnalysisFunction *rz_listrange_find_root(RzListRange *s, ut64 addr);
/* --------- */ /* REFACTOR */ /* ---------- */
/* type.c */
RZ_API RzAnalysisType *rz_analysis_type_new(void);
RZ_API void rz_analysis_type_add(RzAnalysis *l, RzAnalysisType *t);
RZ_API RzAnalysisType *rz_analysis_type_find(RzAnalysis *a, const char *name);
RZ_API void rz_analysis_type_list(RzAnalysis *a, short category, short enabled);
RZ_API const char *rz_analysis_datatype_to_string(RzAnalysisDataType t);
RZ_API RzAnalysisType *rz_analysis_str_to_type(RzAnalysis *a, const char *s);
RZ_API bool rz_analysis_op_nonlinear(int t);
RZ_API bool rz_analysis_op_ismemref(int t);
RZ_API const char *rz_analysis_optype_to_string(int t);
RZ_API int rz_analysis_optype_from_string(const char *type);
RZ_API const char *rz_analysis_op_family_to_string(int n);
RZ_API int rz_analysis_op_family_from_string(const char *f);
RZ_API int rz_analysis_op_hint(RzAnalysisOp *op, RzAnalysisHint *hint);
RZ_API RzAnalysisType *rz_analysis_type_free(RzAnalysisType *t);
RZ_API RzAnalysisType *rz_analysis_type_loadfile(RzAnalysis *a, const char *path);

/* block.c */
typedef bool (*RzAnalysisBlockCb)(RzAnalysisBlock *block, void *user);
typedef bool (*RzAnalysisAddrCb)(ut64 addr, void *user);

// lifetime
RZ_API void rz_analysis_block_ref(RzAnalysisBlock *bb);
RZ_API void rz_analysis_block_unref(RzAnalysisBlock *bb);

// Create one block covering the given range.
// This will fail if the range overlaps any existing blocks.
RZ_API RzAnalysisBlock *rz_analysis_create_block(RzAnalysis *analysis, ut64 addr, ut64 size);

static inline bool rz_analysis_block_contains(RzAnalysisBlock *bb, ut64 addr) {
	return addr >= bb->addr && addr < bb->addr + bb->size;
}

// Split the block at the given address into two blocks.
// bb will stay the first block, the second block will be returned (or NULL on failure)
// The returned block will always be refd, i.e. it is necessary to always call rz_analysis_block_unref() on the return value!
RZ_API RzAnalysisBlock *rz_analysis_block_split(RzAnalysisBlock *bb, ut64 addr);

static inline bool rz_analysis_block_is_contiguous(RzAnalysisBlock *a, RzAnalysisBlock *b) {
	return (a->addr + a->size) == b->addr;
}

// Merge block b into a.
// b will be FREED (not just unrefd) and is NOT VALID anymore if this function is successful!
// This only works if b follows directly after a and their function lists are identical.
// returns true iff the blocks could be merged
RZ_API bool rz_analysis_block_merge(RzAnalysisBlock *a, RzAnalysisBlock *b);

// Manually delete a block and remove it from all its functions
// If there are more references to it than from its functions only, it will not be removed immediately!
RZ_API void rz_analysis_delete_block(RzAnalysisBlock *bb);

RZ_API void rz_analysis_block_set_size(RzAnalysisBlock *block, ut64 size);

// Set the address and size of the block.
// This can fail (and return false) if there is already another block at the new address
RZ_API bool rz_analysis_block_relocate(RzAnalysisBlock *block, ut64 addr, ut64 size);

RZ_API RzAnalysisBlock *rz_analysis_get_block_at(RzAnalysis *analysis, ut64 addr);
RZ_API bool rz_analysis_blocks_foreach_in(RzAnalysis *analysis, ut64 addr, RzAnalysisBlockCb cb, void *user);
RZ_API RzList *rz_analysis_get_blocks_in(RzAnalysis *analysis, ut64 addr); // values from rz_analysis_blocks_foreach_in as a list
RZ_API void rz_analysis_blocks_foreach_intersect(RzAnalysis *analysis, ut64 addr, ut64 size, RzAnalysisBlockCb cb, void *user);
RZ_API RzList *rz_analysis_get_blocks_intersect(RzAnalysis *analysis, ut64 addr, ut64 size); // values from rz_analysis_blocks_foreach_intersect as a list

// Call cb on every direct successor address of block
// returns false if the loop was breaked by cb
RZ_API bool rz_analysis_block_successor_addrs_foreach(RzAnalysisBlock *block, RzAnalysisAddrCb cb, void *user);

// Call cb on block and every (recursive) successor of it
// returns false if the loop was breaked by cb
RZ_API bool rz_analysis_block_recurse(RzAnalysisBlock *block, RzAnalysisBlockCb cb, void *user);

// Call cb on block and every (recursive) successor of it
// If cb returns false, recursion stops only for that block
// returns false if the loop was breaked by cb
RZ_API bool rz_analysis_block_recurse_followthrough(RzAnalysisBlock *block, RzAnalysisBlockCb cb, void *user);

// Call cb on block and every (recursive) successor of it
// Call on_exit on block that doesn't have non-visited successors
// returns false if the loop was breaked by cb
RZ_API bool rz_analysis_block_recurse_depth_first(RzAnalysisBlock *block, RzAnalysisBlockCb cb, RZ_NULLABLE RzAnalysisBlockCb on_exit, void *user);

// same as rz_analysis_block_recurse, but returns the blocks as a list
RZ_API RzList *rz_analysis_block_recurse_list(RzAnalysisBlock *block);

// return one shortest path from block to dst or NULL if none exists.
RZ_API RZ_NULLABLE RzList /*<RzAnalysisBlock *>*/ *rz_analysis_block_shortest_path(RzAnalysisBlock *block, ut64 dst);

// Add a case to the block's switch_op.
// If block->switch_op is NULL, it will be created with the given switch_addr.
RZ_API void rz_analysis_block_add_switch_case(RzAnalysisBlock *block, ut64 switch_addr, ut64 case_value, ut64 case_addr);

// Chop off the block at the specified address and remove all destinations.
// Blocks that have become unreachable after this operation will be automatically removed from all functions of block.
// addr must be the address directly AFTER the noreturn call!
// After the chopping, an rz_analysis_block_automerge() is performed on the touched blocks.
// IMPORTANT: The automerge might also FREE block! This function returns block iff it is still valid afterwards.
// If this function returns NULL, the pointer to block MUST not be touched anymore!
RZ_API RzAnalysisBlock *rz_analysis_block_chop_noreturn(RzAnalysisBlock *block, ut64 addr);

// Merge every block in blocks with their contiguous predecessor, if possible.
// IMPORTANT: Merged blocks will be FREED! The blocks list will be updated to contain only the survived blocks.
RZ_API void rz_analysis_block_automerge(RzList *blocks);

// return true iff an instruction in the given basic block starts at the given address
RZ_API bool rz_analysis_block_op_starts_at(RzAnalysisBlock *block, ut64 addr);

// Updates bbhash based on current bytes inside the block
RZ_API void rz_analysis_block_update_hash(RzAnalysisBlock *block);

// returns true if a byte in the given basic block was modified
RZ_API bool rz_analysis_block_was_modified(RzAnalysisBlock *block);

RZ_API RzAnalysisBlock *rz_analysis_find_most_relevant_block_in(RzAnalysis *analysis, ut64 off);

RZ_API ut16 rz_analysis_block_get_op_offset(RzAnalysisBlock *block, size_t i);
RZ_API ut64 rz_analysis_block_get_op_addr(RzAnalysisBlock *block, size_t i);
RZ_API ut64 rz_analysis_block_get_op_addr_in(RzAnalysisBlock *bb, ut64 off);
RZ_API bool rz_analysis_block_set_op_offset(RzAnalysisBlock *block, size_t i, ut16 v);
RZ_API ut64 rz_analysis_block_get_op_size(RzAnalysisBlock *bb, size_t i);
RZ_API void rz_analysis_block_analyze_ops(RzAnalysisBlock *block);

// ---------------------------------------

/* function.c */

RZ_API RzAnalysisFunction *rz_analysis_function_new(RzAnalysis *analysis);
RZ_API void rz_analysis_function_free(void *fcn);

// Add a function created with rz_analysis_function_new() to anal
RZ_API bool rz_analysis_add_function(RzAnalysis *analysis, RzAnalysisFunction *fcn);

// Create a new function and add it to analysis (rz_analysis_function_new() + set members + rz_analysis_add_function())
RZ_API RzAnalysisFunction *rz_analysis_create_function(RzAnalysis *analysis, const char *name, ut64 addr, int type, RzAnalysisDiff *diff);

// returns all functions that have a basic block containing the given address
RZ_API RzList *rz_analysis_get_functions_in(RzAnalysis *analysis, ut64 addr);

// returns the function that has its entrypoint at addr or NULL
RZ_API RzAnalysisFunction *rz_analysis_get_function_at(RzAnalysis *analysis, ut64 addr);

RZ_API bool rz_analysis_function_delete(RzAnalysisFunction *fcn);

// returns the list of functions in the RzAnalysis instance
RZ_API RZ_BORROW RzList *rz_analysis_function_list(RzAnalysis *analysis);

// rhange the entrypoint of fcn
// This can fail (and return false) if there is already another function at the new address
RZ_API bool rz_analysis_function_relocate(RzAnalysisFunction *fcn, ut64 addr);

// rename the given function
// This can fail (and return false) if there is another function with the name given
RZ_API bool rz_analysis_function_rename(RzAnalysisFunction *fcn, const char *name);

RZ_API void rz_analysis_function_add_block(RzAnalysisFunction *fcn, RzAnalysisBlock *bb);
RZ_API void rz_analysis_function_remove_block(RzAnalysisFunction *fcn, RzAnalysisBlock *bb);

// size of the entire range that the function spans, including holes.
// this is exactly rz_analysis_function_max_addr() - rz_analysis_function_min_addr()
RZ_API ut64 rz_analysis_function_linear_size(RzAnalysisFunction *fcn);

// lowest address covered by the function
RZ_API ut64 rz_analysis_function_min_addr(RzAnalysisFunction *fcn);

// first address directly after the function
RZ_API ut64 rz_analysis_function_max_addr(RzAnalysisFunction *fcn);

// size from the function entrypoint (fcn->addr) to the end of the function (rz_analysis_function_max_addr)
RZ_API ut64 rz_analysis_function_size_from_entry(RzAnalysisFunction *fcn);

// the "real" size of the function, that is the sum of the size of the
// basicblocks this function is composed of
RZ_API ut64 rz_analysis_function_realsize(const RzAnalysisFunction *fcn);

// returns whether the function contains a basic block that contains addr
// This is completely independent of fcn->addr, which is only the entrypoint!
RZ_API bool rz_analysis_function_contains(RzAnalysisFunction *fcn, ut64 addr);

// returns true if function bytes were modified
RZ_API bool rz_analysis_function_was_modified(RzAnalysisFunction *fcn);

RZ_API bool rz_analysis_function_is_autonamed(RZ_NONNULL char *name);
RZ_API RZ_OWN char *rz_analysis_function_name_guess(RzTypeDB *typedb, RZ_NONNULL char *name);

/* analysis.c */
RZ_API RzAnalysis *rz_analysis_new(void);
RZ_API void rz_analysis_purge(RzAnalysis *analysis);
RZ_API RzAnalysis *rz_analysis_free(RzAnalysis *r);
RZ_API int rz_analysis_add(RzAnalysis *analysis, RzAnalysisPlugin *foo);
RZ_API int rz_analysis_archinfo(RzAnalysis *analysis, int query);
RZ_API bool rz_analysis_use(RzAnalysis *analysis, const char *name);
RZ_API bool rz_analysis_set_reg_profile(RzAnalysis *analysis);
RZ_API char *rz_analysis_get_reg_profile(RzAnalysis *analysis);
RZ_API bool rz_analysis_set_bits(RzAnalysis *analysis, int bits);
RZ_API bool rz_analysis_set_os(RzAnalysis *analysis, const char *os);
RZ_API void rz_analysis_set_cpu(RzAnalysis *analysis, const char *cpu);
RZ_API int rz_analysis_set_big_endian(RzAnalysis *analysis, int boolean);
RZ_API ut8 *rz_analysis_mask(RzAnalysis *analysis, int size, const ut8 *data, ut64 at);
RZ_API void rz_analysis_trace_bb(RzAnalysis *analysis, ut64 addr);
RZ_API const char *rz_analysis_fcntype_tostring(int type);
RZ_API int rz_analysis_fcn_bb(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr, int depth);
RZ_API void rz_analysis_bind(RzAnalysis *b, RzAnalysisBind *bnd);
RZ_API bool rz_analysis_set_triplet(RzAnalysis *analysis, const char *os, const char *arch, int bits);
RZ_API void rz_analysis_add_import(RzAnalysis *analysis, const char *imp);
RZ_API void rz_analysis_remove_import(RzAnalysis *analysis, const char *imp);
RZ_API void rz_analysis_purge_imports(RzAnalysis *analysis);

/* op.c */
RZ_API const char *rz_analysis_stackop_tostring(int s);
RZ_API RzAnalysisOp *rz_analysis_op_new(void);
RZ_API void rz_analysis_op_free(void *op);
RZ_API void rz_analysis_op_init(RzAnalysisOp *op);
RZ_API bool rz_analysis_op_fini(RzAnalysisOp *op);
RZ_API int rz_analysis_op_reg_delta(RzAnalysis *analysis, ut64 addr, const char *name);
RZ_API bool rz_analysis_op_is_eob(RzAnalysisOp *op);
RZ_API RzList *rz_analysis_op_list_new(void);
RZ_API int rz_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask);
RZ_API RzAnalysisOp *rz_analysis_op_hexstr(RzAnalysis *analysis, ut64 addr, const char *hexstr);
RZ_API char *rz_analysis_op_to_string(RzAnalysis *analysis, RzAnalysisOp *op);

RZ_API RzAnalysisEsil *rz_analysis_esil_new(int stacksize, int iotrap, unsigned int addrsize);
RZ_API bool rz_analysis_esil_set_pc(RzAnalysisEsil *esil, ut64 addr);
RZ_API bool rz_analysis_esil_setup(RzAnalysisEsil *esil, RzAnalysis *analysis, int romem, int stats, int nonull);
RZ_API void rz_analysis_esil_free(RzAnalysisEsil *esil);
RZ_API bool rz_analysis_esil_runword(RzAnalysisEsil *esil, const char *word);
RZ_API bool rz_analysis_esil_parse(RzAnalysisEsil *esil, const char *str);
RZ_API bool rz_analysis_esil_dumpstack(RzAnalysisEsil *esil);
RZ_API int rz_analysis_esil_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len);
RZ_API int rz_analysis_esil_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len);
RZ_API int rz_analysis_esil_reg_read(RzAnalysisEsil *esil, const char *regname, ut64 *num, int *size);
RZ_API int rz_analysis_esil_reg_write(RzAnalysisEsil *esil, const char *dst, ut64 num);
RZ_API bool rz_analysis_esil_pushnum(RzAnalysisEsil *esil, ut64 num);
RZ_API bool rz_analysis_esil_push(RzAnalysisEsil *esil, const char *str);
RZ_API char *rz_analysis_esil_pop(RzAnalysisEsil *esil);
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

/* trace */
RZ_API RzAnalysisEsilTrace *rz_analysis_esil_trace_new(RzAnalysisEsil *esil);
RZ_API void rz_analysis_esil_trace_free(RzAnalysisEsilTrace *trace);
RZ_API void rz_analysis_esil_trace_op(RzAnalysisEsil *esil, RzAnalysisOp *op);
RZ_API void rz_analysis_esil_trace_list(RzAnalysisEsil *esil);
RZ_API void rz_analysis_esil_trace_show(RzAnalysisEsil *esil, int idx);
RZ_API void rz_analysis_esil_trace_restore(RzAnalysisEsil *esil, int idx);

/* pin */
RZ_API void rz_analysis_pin_init(RzAnalysis *a);
RZ_API void rz_analysis_pin_fini(RzAnalysis *a);
RZ_API void rz_analysis_pin(RzAnalysis *a, ut64 addr, const char *name);
RZ_API void rz_analysis_pin_unset(RzAnalysis *a, ut64 addr);
RZ_API const char *rz_analysis_pin_call(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_pin_list(RzAnalysis *a);

RZ_API bool rz_analysis_add_device_peripheral_map(RzBinObject *o, RzAnalysis *analysis);

/* fcn.c */
RZ_API ut32 rz_analysis_function_cost(RzAnalysisFunction *fcn);
RZ_API int rz_analysis_function_count_edges(const RzAnalysisFunction *fcn, RZ_NULLABLE int *ebbs);

// Use rz_analysis_get_functions_in¿() instead
RZ_DEPRECATE RZ_API RzAnalysisFunction *rz_analysis_get_fcn_in(RzAnalysis *analysis, ut64 addr, int type);
RZ_DEPRECATE RZ_API RzAnalysisFunction *rz_analysis_get_fcn_in_bounds(RzAnalysis *analysis, ut64 addr, int type);

RZ_API RzAnalysisFunction *rz_analysis_get_function_byname(RzAnalysis *analysis, const char *name);

RZ_API int rz_analysis_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr, ut64 len, int reftype);
RZ_API int rz_analysis_fcn_del(RzAnalysis *analysis, ut64 addr);
RZ_API int rz_analysis_fcn_del_locs(RzAnalysis *analysis, ut64 addr);
RZ_API bool rz_analysis_fcn_add_bb(RzAnalysis *analysis, RzAnalysisFunction *fcn,
	ut64 addr, ut64 size,
	ut64 jump, ut64 fail, RZ_BORROW RzAnalysisDiff *diff);
RZ_API bool rz_analysis_check_fcn(RzAnalysis *analysis, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high);
RZ_API void rz_analysis_fcn_invalidate_read_ahead_cache(void);

RZ_API void rz_analysis_function_check_bp_use(RzAnalysisFunction *fcn);
RZ_API void rz_analysis_update_analysis_range(RzAnalysis *analysis, ut64 addr, int size);
RZ_API void rz_analysis_function_update_analysis(RzAnalysisFunction *fcn);

#define RZ_ANALYSIS_FCN_VARKIND_LOCAL 'v'

RZ_API int rz_analysis_fcn_var_del_byindex(RzAnalysis *a, ut64 fna, const char kind, int scope, ut32 idx);
/* args */
RZ_API int rz_analysis_var_count(RzAnalysis *a, RzAnalysisFunction *fcn, int kind, int type);

/* vars // globals. not here  */
RZ_API bool rz_analysis_var_display(RzAnalysis *analysis, RzAnalysisVar *var);

RZ_API int rz_analysis_function_complexity(RzAnalysisFunction *fcn);
RZ_API int rz_analysis_function_loops(RzAnalysisFunction *fcn);
RZ_API void rz_analysis_trim_jmprefs(RzAnalysis *analysis, RzAnalysisFunction *fcn);
RZ_API void rz_analysis_del_jmprefs(RzAnalysis *analysis, RzAnalysisFunction *fcn);
RZ_API char *rz_analysis_function_get_json(RzAnalysisFunction *function);
RZ_API RzAnalysisFunction *rz_analysis_fcn_next(RzAnalysis *analysis, ut64 addr);
RZ_API RZ_OWN char *rz_analysis_function_get_signature(RzAnalysisFunction *function);
RZ_API bool rz_analysis_function_set_type(RzAnalysis *a, RZ_NONNULL RzAnalysisFunction *f, RZ_NONNULL RzCallable *callable);
RZ_API bool rz_analysis_function_set_type_str(RzAnalysis *a, RZ_NONNULL RzAnalysisFunction *f, RZ_NONNULL const char *sig);
RZ_API int rz_analysis_fcn_count(RzAnalysis *a, ut64 from, ut64 to);
RZ_API RzAnalysisBlock *rz_analysis_fcn_bbget_in(const RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr);
RZ_API RzAnalysisBlock *rz_analysis_fcn_bbget_at(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr);
RZ_API bool rz_analysis_fcn_bbadd(RzAnalysisFunction *fcn, RzAnalysisBlock *bb);
RZ_API int rz_analysis_function_resize(RzAnalysisFunction *fcn, int newsize);
RZ_API bool rz_analysis_function_purity(RzAnalysisFunction *fcn);

typedef bool (*RzAnalysisRefCmp)(RzAnalysisXRef *ref, void *data);
RZ_API RzList *rz_analysis_xref_list_new(void);
RZ_API ut64 rz_analysis_xrefs_count(RzAnalysis *analysis);
RZ_API const char *rz_analysis_xrefs_type_tostring(RzAnalysisXRefType type);
RZ_API RzAnalysisXRefType rz_analysis_xrefs_type(char ch);
RZ_API RzList *rz_analysis_xrefs_get_to(RzAnalysis *analysis, ut64 addr);
RZ_API RzList *rz_analysis_xrefs_get_from(RzAnalysis *analysis, ut64 addr);
RZ_API void rz_analysis_xrefs_list(RzAnalysis *analysis, int rad);
RZ_API RzList *rz_analysis_function_get_xrefs_from(RzAnalysisFunction *fcn);
RZ_API RzList *rz_analysis_function_get_xrefs_to(RzAnalysisFunction *fcn);
RZ_API bool rz_analysis_xrefs_set(RzAnalysis *analysis, ut64 from, ut64 to, RzAnalysisXRefType type);
RZ_API bool rz_analysis_xrefs_deln(RzAnalysis *analysis, ut64 from, ut64 to, RzAnalysisXRefType type);
RZ_API bool rz_analysis_xref_del(RzAnalysis *analysis, ut64 from, ut64 to);

RZ_API RzList *rz_analysis_get_fcns(RzAnalysis *analysis);

/* var.c */
RZ_API RZ_OWN char *rz_analysis_function_autoname_var(RzAnalysisFunction *fcn, char kind, const char *pfx, int ptr);
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_set_var(RzAnalysisFunction *fcn, int delta, char kind, RZ_BORROW RZ_NULLABLE const RzType *type, int size, bool isarg, RZ_NONNULL const char *name);
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_get_var(RzAnalysisFunction *fcn, char kind, int delta);
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_get_var_byname(RzAnalysisFunction *fcn, const char *name);
RZ_API void rz_analysis_function_delete_vars_by_kind(RzAnalysisFunction *fcn, RzAnalysisVarKind kind);
RZ_API void rz_analysis_function_delete_all_vars(RzAnalysisFunction *fcn);
RZ_API void rz_analysis_function_delete_unused_vars(RzAnalysisFunction *fcn);
RZ_API void rz_analysis_function_delete_var(RzAnalysisFunction *fcn, RzAnalysisVar *var);
RZ_API bool rz_analysis_function_rebase_vars(RzAnalysis *a, RzAnalysisFunction *fcn);
RZ_API st64 rz_analysis_function_get_var_stackptr_at(RzAnalysisFunction *fcn, st64 delta, ut64 addr);
RZ_API const char *rz_analysis_function_get_var_reg_at(RzAnalysisFunction *fcn, st64 delta, ut64 addr);
RZ_API RZ_BORROW RzPVector *rz_analysis_function_get_vars_used_at(RzAnalysisFunction *fcn, ut64 op_addr);

// There could be multiple vars used in multiple functions. Use rz_analysis_get_functions_in()+rz_analysis_function_get_vars_used_at() instead.
RZ_API RZ_DEPRECATE RzAnalysisVar *rz_analysis_get_used_function_var(RzAnalysis *analysis, ut64 addr);

RZ_API bool rz_analysis_var_rename(RzAnalysisVar *var, const char *new_name, bool verbose);
RZ_API void rz_analysis_var_set_type(RzAnalysisVar *var, RZ_OWN RzType *type);
RZ_API void rz_analysis_var_delete(RzAnalysisVar *var);
RZ_API ut64 rz_analysis_var_addr(RzAnalysisVar *var);
RZ_API void rz_analysis_var_set_access(RzAnalysisVar *var, const char *reg, ut64 access_addr, int access_type, st64 stackptr);
RZ_API void rz_analysis_var_remove_access_at(RzAnalysisVar *var, ut64 address);
RZ_API void rz_analysis_var_clear_accesses(RzAnalysisVar *var);
RZ_API void rz_analysis_var_add_constraint(RzAnalysisVar *var, RZ_BORROW RzAnalysisVarConstraint *constraint);
RZ_API char *rz_analysis_var_get_constraints_readable(RzAnalysisVar *var);

// Get the access to var at exactly addr if there is one
RZ_API RzAnalysisVarAccess *rz_analysis_var_get_access_at(RzAnalysisVar *var, ut64 addr);

RZ_API int rz_analysis_var_get_argnum(RzAnalysisVar *var);

RZ_API void rz_analysis_extract_vars(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisOp *op);
RZ_API void rz_analysis_extract_rarg(RzAnalysis *analysis, RzAnalysisOp *op, RzAnalysisFunction *fcn, int *reg_set, int *count);

// Get the variable that var is written to at one of its accesses
// Useful for cases where a register-based argument is written away into a stack variable,
// so if var is the reg arg then this will return the stack var.
RZ_API RzAnalysisVar *rz_analysis_var_get_dst_var(RzAnalysisVar *var);

typedef struct rz_analysis_fcn_vars_cache {
	RzList *bvars;
	RzList *rvars;
	RzList *svars;
} RzAnalysisFcnVarsCache;
RZ_API void rz_analysis_fcn_vars_cache_init(RzAnalysis *analysis, RzAnalysisFcnVarsCache *cache, RzAnalysisFunction *fcn);
RZ_API void rz_analysis_fcn_vars_cache_fini(RzAnalysisFcnVarsCache *cache);

RZ_API char *rz_analysis_fcn_format_sig(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NULLABLE char *fcn_name,
	RZ_NULLABLE RzAnalysisFcnVarsCache *reuse_cache, RZ_NULLABLE const char *fcn_name_pre, RZ_NULLABLE const char *fcn_name_post);

RZ_API void rz_analysis_fcn_vars_add_types(RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn);

// Maintaining type links
RZ_API bool rz_analysis_type_link_exists(RzAnalysis *analysis, ut64 addr);
RZ_API RZ_BORROW RzType *rz_analysis_type_link_at(RzAnalysis *analysis, ut64 addr);
RZ_API bool rz_analysis_type_set_link(RzAnalysis *analysis, RZ_BORROW RzType *type, ut64 addr);
RZ_API bool rz_analysis_type_unlink(RzAnalysis *analysis, ut64 addr);
RZ_API bool rz_analysis_type_unlink_all(RzAnalysis *analysis);
RZ_API bool rz_analysis_type_link_offset(RzAnalysis *analysis, RZ_BORROW RzType *type, ut64 addr);
RZ_API RZ_OWN RzList /* RzType */ *rz_analysis_type_links(RzAnalysis *analysis);
RZ_API RZ_OWN RzList /* RzTypePath */ *rz_analysis_type_links_by_offset(RzAnalysis *analysis, ut64 offset);
RZ_API RZ_OWN RzList /* RzTypePath */ *rz_analysis_type_paths_by_address(RzAnalysis *analysis, ut64 addr);

/* project */
RZ_API bool rz_analysis_xrefs_init(RzAnalysis *analysis);

#define RZ_ANALYSIS_THRESHOLDFCN 0.7F
#define RZ_ANALYSIS_THRESHOLDBB  0.7F

/* diff.c */
RZ_API RzAnalysisDiff *rz_analysis_diff_new(void);
RZ_API void rz_analysis_diff_setup(RzAnalysis *analysis, int doops, double thbb, double thfcn);
RZ_API void rz_analysis_diff_setup_i(RzAnalysis *analysis, int doops, int thbb, int thfcn);
RZ_API void *rz_analysis_diff_free(RzAnalysisDiff *diff);
RZ_API int rz_analysis_diff_fingerprint_bb(RzAnalysis *analysis, RzAnalysisBlock *bb);
RZ_API size_t rz_analysis_diff_fingerprint_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn);
RZ_API bool rz_analysis_diff_bb(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisFunction *fcn2);
RZ_API int rz_analysis_diff_fcn(RzAnalysis *analysis, RzList *fcns, RzList *fcns2);
RZ_API int rz_analysis_diff_eval(RzAnalysis *analysis);

/* value.c */
RZ_API RzAnalysisValue *rz_analysis_value_new(void);
RZ_API RzAnalysisValue *rz_analysis_value_copy(RzAnalysisValue *ov);
RZ_API RzAnalysisValue *rz_analysis_value_new_from_string(const char *str);
RZ_API st64 rz_analysis_value_eval(RzAnalysisValue *value);
RZ_API char *rz_analysis_value_to_string(RzAnalysisValue *value);
RZ_API ut64 rz_analysis_value_to_ut64(RzAnalysis *analysis, RzAnalysisValue *val);
RZ_API int rz_analysis_value_set_ut64(RzAnalysis *analysis, RzAnalysisValue *val, ut64 num);
RZ_API void rz_analysis_value_free(RzAnalysisValue *value);

RZ_API RzAnalysisCond *rz_analysis_cond_new(void);
RZ_API RzAnalysisCond *rz_analysis_cond_new_from_op(RzAnalysisOp *op);
RZ_API void rz_analysis_cond_fini(RzAnalysisCond *c);
RZ_API void rz_analysis_cond_free(RzAnalysisCond *c);
RZ_API char *rz_analysis_cond_to_string(RzAnalysisCond *cond);
RZ_API int rz_analysis_cond_eval(RzAnalysis *analysis, RzAnalysisCond *cond);
RZ_API RzAnalysisCond *rz_analysis_cond_new_from_string(const char *str);
RZ_API const char *rz_analysis_cond_tostring(int cc);

/* jmptbl */
RZ_API bool rz_analysis_jmptbl(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *block, ut64 jmpaddr, ut64 table, ut64 tablesize, ut64 default_addr);

// TODO: should be renamed
RZ_API bool try_get_delta_jmptbl_info(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 jmp_addr, ut64 lea_addr, ut64 *table_size, ut64 *default_case, st64 *start_casenum_shift);
RZ_API bool try_walkthrough_jmptbl(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *block, int depth, ut64 ip, st64 start_casenum_shift, ut64 jmptbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0);
RZ_API bool try_walkthrough_casetbl(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *block, int depth, ut64 ip, st64 start_casenum_shift, ut64 jmptbl_loc, ut64 casetbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0);
RZ_API bool try_get_jmptbl_info(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr, RzAnalysisBlock *my_bb, ut64 *table_size, ut64 *default_case, st64 *start_casenum_shift);
RZ_API int walkthrough_arm_jmptbl_style(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *block, int depth, ut64 ip, ut64 jmptbl_loc, ut64 sz, ut64 jmptbl_size, ut64 default_case, int ret0);

/* reflines.c */
RZ_API RzList * /*<RzAnalysisRefline>*/ rz_analysis_reflines_get(RzAnalysis *analysis,
	ut64 addr, const ut8 *buf, ut64 len, int nlines, int linesout, int linescall);
RZ_API int rz_analysis_reflines_middle(RzAnalysis *analysis, RzList *list, ut64 addr, int len);
RZ_API RzAnalysisRefStr *rz_analysis_reflines_str(void *core, ut64 addr, int opts);
RZ_API void rz_analysis_reflines_str_free(RzAnalysisRefStr *refstr);
/* TODO move to rz_core */
RZ_API void rz_analysis_var_list_show(RzAnalysis *analysis, RzAnalysisFunction *fcn, int kind, int mode, PJ *pj);
RZ_API RzList *rz_analysis_var_list(RzAnalysis *analysis, RzAnalysisFunction *fcn, int kind);
RZ_API RZ_DEPRECATE RzList /*<RzAnalysisVar *>*/ *rz_analysis_var_all_list(RzAnalysis *analysis, RzAnalysisFunction *fcn);
RZ_API RZ_DEPRECATE RzList /*<RzAnalysisVarField *>*/ *rz_analysis_function_get_var_fields(RzAnalysisFunction *fcn, int kind);

// calling conventions API
RZ_API bool rz_analysis_cc_exist(RzAnalysis *analysis, const char *convention);
RZ_API void rz_analysis_cc_del(RzAnalysis *analysis, const char *name);
RZ_API bool rz_analysis_cc_set(RzAnalysis *analysis, const char *expr);
RZ_API char *rz_analysis_cc_get(RzAnalysis *analysis, const char *name);
RZ_API const char *rz_analysis_cc_arg(RzAnalysis *analysis, const char *convention, int n);
RZ_API const char *rz_analysis_cc_self(RzAnalysis *analysis, const char *convention);
RZ_API void rz_analysis_cc_set_self(RzAnalysis *analysis, const char *convention, const char *self);
RZ_API const char *rz_analysis_cc_error(RzAnalysis *analysis, const char *convention);
RZ_API void rz_analysis_cc_set_error(RzAnalysis *analysis, const char *convention, const char *error);
RZ_API int rz_analysis_cc_max_arg(RzAnalysis *analysis, const char *cc);
RZ_API const char *rz_analysis_cc_ret(RzAnalysis *analysis, const char *convention);
RZ_API const char *rz_analysis_cc_default(RzAnalysis *analysis);
RZ_API void rz_analysis_set_cc_default(RzAnalysis *analysis, const char *convention);
RZ_API const char *rz_analysis_syscc_default(RzAnalysis *analysis);
RZ_API void rz_analysis_set_syscc_default(RzAnalysis *analysis, const char *convention);
RZ_API const char *rz_analysis_cc_func(RzAnalysis *analysis, const char *func_name);
RZ_API RzList *rz_analysis_calling_conventions(RzAnalysis *analysis);

typedef struct rz_analysis_data_t {
	ut64 addr;
	int type;
	ut64 ptr;
	char *str;
	int len;
	ut8 *buf;
	ut8 sbuf[8];
} RzAnalysisData;

RZ_API RzAnalysisData *rz_analysis_data(RzAnalysis *analysis, ut64 addr, const ut8 *buf, int size, int wordsize);
RZ_API const char *rz_analysis_data_kind(RzAnalysis *analysis, ut64 addr, const ut8 *buf, int len);
RZ_API RzAnalysisData *rz_analysis_data_new_string(ut64 addr, const char *p, int size, int wide);
RZ_API RzAnalysisData *rz_analysis_data_new(ut64 addr, int type, ut64 n, const ut8 *buf, int len);
RZ_API void rz_analysis_data_free(RzAnalysisData *d);
#include <rz_cons.h>
RZ_API char *rz_analysis_data_to_string(RzAnalysisData *d, RzConsPrintablePalette *pal);

/* meta
 *
 * Meta uses Condret's Klemmbaustein Priciple, i.e. intervals are defined inclusive/inclusive.
 * A meta item from 0x42 to 0x42 has a size of 1. Items with size 0 do not exist.
 * Meta items are allowed to overlap and the internal data structure allows for multiple meta items
 * starting at the same address.
 * Meta items are saved in an RzIntervalTree. To access the interval of an item, use the members of RzIntervalNode.
 */

static inline ut64 rz_meta_item_size(ut64 start, ut64 end) {
	// meta items use inclusive/inclusive intervals
	return end - start + 1;
}

static inline ut64 rz_meta_node_size(RzIntervalNode *node) {
	return rz_meta_item_size(node->start, node->end);
}

// Set a meta item at addr with the given contents in the current space.
// If there already exists an item with this type and space at addr (regardless of its size) it will be overwritten.
RZ_API bool rz_meta_set(RzAnalysis *a, RzAnalysisMetaType type, ut64 addr, ut64 size, const char *str);

// Same as rz_meta_set() but also sets the subtype.
RZ_API bool rz_meta_set_with_subtype(RzAnalysis *m, RzAnalysisMetaType type, int subtype, ut64 addr, ut64 size, const char *str);

// Delete all meta items in the current space that intersect with the given interval.
// If size == UT64_MAX, everything in the current space will be deleted.
RZ_API void rz_meta_del(RzAnalysis *a, RzAnalysisMetaType type, ut64 addr, ut64 size);

// Same as rz_meta_set() with a size of 1.
RZ_API bool rz_meta_set_string(RzAnalysis *a, RzAnalysisMetaType type, ut64 addr, const char *s);

// Convenience function to get the str content of the item at addr with given type in the current space.
RZ_API const char *rz_meta_get_string(RzAnalysis *a, RzAnalysisMetaType type, ut64 addr);

// Convenience function to add an RZ_META_TYPE_DATA item at the given addr in the current space.
RZ_API void rz_meta_set_data_at(RzAnalysis *a, ut64 addr, ut64 wordsz);

// Returns the item with given type that starts at addr in the current space or NULL. The size of this item  optionally returned through size.
RZ_API RzAnalysisMetaItem *rz_meta_get_at(RzAnalysis *a, ut64 addr, RzAnalysisMetaType type, RZ_OUT RZ_NULLABLE ut64 *size);

// Returns the node for one meta item with the given type that contains addr in the current space or NULL.
// To get all the nodes, use rz_meta_get_all_in().
RZ_API RzIntervalNode *rz_meta_get_in(RzAnalysis *a, ut64 addr, RzAnalysisMetaType type);

// Returns all nodes for items starting at the given address in the current space.
RZ_API RzPVector /*<RzIntervalNode<RMetaItem> *>*/ *rz_meta_get_all_at(RzAnalysis *a, ut64 at);

// Returns all nodes for items with the given type containing the given address in the current space.
RZ_API RzPVector /*<RzIntervalNode<RMetaItem> *>*/ *rz_meta_get_all_in(RzAnalysis *a, ut64 at, RzAnalysisMetaType type);

// Returns all nodes for items with the given type intersecting the given interval in the current space.
RZ_API RzPVector /*<RzIntervalNode<RMetaItem> *>*/ *rz_meta_get_all_intersect(RzAnalysis *a, ut64 start, ut64 size, RzAnalysisMetaType type);

// Delete all meta items in the given space
RZ_API void rz_meta_space_unset_for(RzAnalysis *a, const RzSpace *space);

// Returns the number of meta items in the given space
RZ_API int rz_meta_space_count_for(RzAnalysis *a, const RzSpace *space);

// Shift all meta items by the given delta, for rebasing between different memory layouts.
RZ_API void rz_meta_rebase(RzAnalysis *analysis, ut64 diff);

// Calculate the total size covered by meta items of the given type.
RZ_API ut64 rz_meta_get_size(RzAnalysis *a, RzAnalysisMetaType type);

RZ_API const char *rz_meta_type_to_string(int type);
RZ_API void rz_meta_print(RzAnalysis *a, RzAnalysisMetaItem *d, ut64 start, ut64 size, int rad, PJ *pj, bool show_full);
RZ_API void rz_meta_print_list_all(RzAnalysis *a, int type, int rad);
RZ_API void rz_meta_print_list_at(RzAnalysis *a, ut64 addr, int rad);
RZ_API void rz_meta_print_list_in_function(RzAnalysis *a, int type, int rad, ut64 addr);

/* hints */

RZ_API void rz_analysis_hint_del(RzAnalysis *analysis, ut64 addr, ut64 size); // delete all hints that are contained within the given range, if size > 1, this operation is quite heavy!
RZ_API void rz_analysis_hint_clear(RzAnalysis *a);
RZ_API void rz_analysis_hint_free(RzAnalysisHint *h);
RZ_API void rz_analysis_hint_set_syntax(RzAnalysis *a, ut64 addr, const char *syn);
RZ_API void rz_analysis_hint_set_type(RzAnalysis *a, ut64 addr, int type);
RZ_API void rz_analysis_hint_set_jump(RzAnalysis *a, ut64 addr, ut64 jump);
RZ_API void rz_analysis_hint_set_fail(RzAnalysis *a, ut64 addr, ut64 fail);
RZ_API void rz_analysis_hint_set_newbits(RzAnalysis *a, ut64 addr, int bits);
RZ_API void rz_analysis_hint_set_nword(RzAnalysis *a, ut64 addr, int nword);
RZ_API void rz_analysis_hint_set_offset(RzAnalysis *a, ut64 addr, const char *typeoff);
RZ_API void rz_analysis_hint_set_immbase(RzAnalysis *a, ut64 addr, int base);
RZ_API void rz_analysis_hint_set_size(RzAnalysis *a, ut64 addr, ut64 size);
RZ_API void rz_analysis_hint_set_opcode(RzAnalysis *a, ut64 addr, const char *str);
RZ_API void rz_analysis_hint_set_esil(RzAnalysis *a, ut64 addr, const char *str);
RZ_API void rz_analysis_hint_set_pointer(RzAnalysis *a, ut64 addr, ut64 ptr);
RZ_API void rz_analysis_hint_set_ret(RzAnalysis *a, ut64 addr, ut64 val);
RZ_API void rz_analysis_hint_set_high(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_set_stackframe(RzAnalysis *a, ut64 addr, ut64 size);
RZ_API void rz_analysis_hint_set_val(RzAnalysis *a, ut64 addr, ut64 v);
RZ_API void rz_analysis_hint_set_arch(RzAnalysis *a, ut64 addr, RZ_NULLABLE const char *arch); // arch == NULL => use global default
RZ_API void rz_analysis_hint_set_bits(RzAnalysis *a, ut64 addr, int bits); // bits == NULL => use global default
RZ_API void rz_analysis_hint_unset_val(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_high(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_immbase(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_nword(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_size(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_type(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_esil(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_opcode(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_syntax(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_pointer(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_ret(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_offset(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_jump(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_fail(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_newbits(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_stackframe(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_arch(RzAnalysis *a, ut64 addr);
RZ_API void rz_analysis_hint_unset_bits(RzAnalysis *a, ut64 addr);
RZ_API RZ_NULLABLE const RzVector /*<const RzAnalysisAddrHintRecord>*/ *rz_analysis_addr_hints_at(RzAnalysis *analysis, ut64 addr);
typedef bool (*RzAnalysisAddrHintRecordsCb)(ut64 addr, const RzVector /*<const RzAnalysisAddrHintRecord>*/ *records, void *user);
RZ_API void rz_analysis_addr_hints_foreach(RzAnalysis *analysis, RzAnalysisAddrHintRecordsCb cb, void *user);
typedef bool (*RzAnalysisArchHintCb)(ut64 addr, RZ_NULLABLE const char *arch, void *user);
RZ_API void rz_analysis_arch_hints_foreach(RzAnalysis *analysis, RzAnalysisArchHintCb cb, void *user);
typedef bool (*RzAnalysisBitsHintCb)(ut64 addr, int bits, void *user);
RZ_API void rz_analysis_bits_hints_foreach(RzAnalysis *analysis, RzAnalysisBitsHintCb cb, void *user);

// get the hint-specified arch value to be considered at addr
// hint_addr will optionally be set to the address where the hint that specifies this arch is placed or UT64_MAX
// if there is no hint affecting addr.
RZ_API RZ_NULLABLE RZ_BORROW const char *rz_analysis_hint_arch_at(RzAnalysis *analysis, ut64 addr, RZ_NULLABLE ut64 *hint_addr);

// get the hint-specified bits value to be considered at addr
// hint_addr will optionally be set to the address where the hint that specifies this arch is placed or UT64_MAX
// if there is no hint affecting addr.
RZ_API int rz_analysis_hint_bits_at(RzAnalysis *analysis, ut64 addr, RZ_NULLABLE ut64 *hint_addr);

RZ_API RzAnalysisHint *rz_analysis_hint_get(RzAnalysis *analysis, ut64 addr); // accumulate all available hints affecting the given address

/* switch.c APIs */
RZ_API RzAnalysisSwitchOp *rz_analysis_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val, ut64 def_val);
RZ_API void rz_analysis_switch_op_free(RzAnalysisSwitchOp *swop);
RZ_API RzAnalysisCaseOp *rz_analysis_switch_op_add_case(RzAnalysisSwitchOp *swop, ut64 addr, ut64 value, ut64 jump);

/* cycles.c */
RZ_API RzAnalysisCycleFrame *rz_analysis_cycle_frame_new(void);
RZ_API void rz_analysis_cycle_frame_free(RzAnalysisCycleFrame *cf);

/* labels */
RZ_API ut64 rz_analysis_function_get_label(RzAnalysisFunction *fcn, const char *name);
RZ_API const char *rz_analysis_function_get_label_at(RzAnalysisFunction *fcn, ut64 addr);
RZ_API bool rz_analysis_function_set_label(RzAnalysisFunction *fcn, const char *name, ut64 addr);
RZ_API bool rz_analysis_function_delete_label(RzAnalysisFunction *fcn, const char *name);
RZ_API bool rz_analysis_function_delete_label_at(RzAnalysisFunction *fcn, ut64 addr);

/* limits */
RZ_API void rz_analysis_set_limits(RzAnalysis *analysis, ut64 from, ut64 to);
RZ_API void rz_analysis_unset_limits(RzAnalysis *analysis);

/* no-return stuff */
RZ_API bool rz_analysis_noreturn_add(RzAnalysis *analysis, const char *name, ut64 addr);
RZ_API bool rz_analysis_noreturn_drop(RzAnalysis *analysis, const char *expr);
RZ_API bool rz_analysis_noreturn_at_addr(RzAnalysis *analysis, ut64 addr);
RZ_API bool rz_analysis_noreturn_at(RzAnalysis *analysis, ut64 addr);
RZ_API RzList *rz_analysis_noreturn_functions(RzAnalysis *analysis);

/* zign spaces */
RZ_API int rz_sign_space_count_for(RzAnalysis *a, const RzSpace *space);
RZ_API void rz_sign_space_unset_for(RzAnalysis *a, const RzSpace *space);
RZ_API void rz_sign_space_rename_for(RzAnalysis *a, const RzSpace *space, const char *oname, const char *nname);

/* vtables */
typedef struct {
	RzAnalysis *analysis;
	RzAnalysisCPPABI abi;
	ut8 word_size;
	bool (*read_addr)(RzAnalysis *analysis, ut64 addr, ut64 *buf);
} RVTableContext;

typedef struct vtable_info_t {
	ut64 saddr; //starting address
	RzVector methods;
} RVTableInfo;

typedef struct vtable_method_info_t {
	ut64 addr; // addr of the function
	ut64 vtable_offset; // offset inside the vtable
} RVTableMethodInfo;

RZ_API void rz_analysis_vtable_info_free(RVTableInfo *vtable);
RZ_API ut64 rz_analysis_vtable_info_get_size(RVTableContext *context, RVTableInfo *vtable);
RZ_API bool rz_analysis_vtable_begin(RzAnalysis *analysis, RVTableContext *context);
RZ_API RVTableInfo *rz_analysis_vtable_parse_at(RVTableContext *context, ut64 addr);
RZ_API RzList *rz_analysis_vtable_search(RVTableContext *context);
RZ_API void rz_analysis_list_vtables(RzAnalysis *analysis, int rad);

/* rtti */
RZ_API char *rz_analysis_rtti_msvc_demangle_class_name(RVTableContext *context, const char *name);
RZ_API void rz_analysis_rtti_msvc_print_complete_object_locator(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_analysis_rtti_msvc_print_type_descriptor(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_analysis_rtti_msvc_print_class_hierarchy_descriptor(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_analysis_rtti_msvc_print_base_class_descriptor(RVTableContext *context, ut64 addr, int mode);
RZ_API bool rz_analysis_rtti_msvc_print_at_vtable(RVTableContext *context, ut64 addr, int mode, bool strict);
RZ_API void rz_analysis_rtti_msvc_recover_all(RVTableContext *vt_context, RzList *vtables);

RZ_API char *rz_analysis_rtti_itanium_demangle_class_name(RVTableContext *context, const char *name);
RZ_API void rz_analysis_rtti_itanium_print_class_type_info(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_analysis_rtti_itanium_print_si_class_type_info(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_analysis_rtti_itanium_print_vmi_class_type_info(RVTableContext *context, ut64 addr, int mode);
RZ_API bool rz_analysis_rtti_itanium_print_at_vtable(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_analysis_rtti_itanium_recover_all(RVTableContext *vt_context, RzList *vtables);

RZ_API char *rz_analysis_rtti_demangle_class_name(RzAnalysis *analysis, const char *name);
RZ_API void rz_analysis_rtti_print_at_vtable(RzAnalysis *analysis, ut64 addr, int mode);
RZ_API void rz_analysis_rtti_print_all(RzAnalysis *analysis, int mode);
RZ_API void rz_analysis_rtti_recover_all(RzAnalysis *analysis);

RZ_API RzList *rz_analysis_preludes(RzAnalysis *analysis);
RZ_API bool rz_analysis_is_prelude(RzAnalysis *analysis, const ut8 *data, int len);

/* classes */
typedef enum {
	RZ_ANALYSIS_CLASS_METHOD_DEFAULT = 0,
	RZ_ANALYSIS_CLASS_METHOD_VIRTUAL,
	RZ_ANALYSIS_CLASS_METHOD_VIRTUAL_DESTRUCTOR,
	RZ_ANALYSIS_CLASS_METHOD_DESTRUCTOR,
	RZ_ANALYSIS_CLASS_METHOD_CONSTRUCTOR
} RzAnalysisMethodType;

typedef struct rz_analysis_method_t {
	char *name;
	char *real_name;
	ut64 addr;
	st64 vtable_offset; // >= 0 if method is virtual, else -1
	RzAnalysisMethodType method_type;
} RzAnalysisMethod;

typedef struct rz_analysis_base_class_t {
	char *id; // id to identify the class attr
	ut64 offset; // offset of the base class inside the derived class
	char *class_name;
} RzAnalysisBaseClass;

typedef struct rz_analysis_vtable_t {
	char *id; // id to identify the class attr
	ut64 offset; // offset inside the class
	ut64 addr; // where the content of the vtable is
	ut64 size; // size (in bytes) of the vtable
} RzAnalysisVTable;

typedef enum {
	RZ_ANALYSIS_CLASS_ERR_SUCCESS = 0,
	RZ_ANALYSIS_CLASS_ERR_CLASH,
	RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_ATTR,
	RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_CLASS,
	RZ_ANALYSIS_CLASS_ERR_OTHER
} RzAnalysisClassErr;

RZ_API void rz_analysis_class_recover_from_rzbin(RzAnalysis *analysis);
RZ_API void rz_analysis_class_recover_all(RzAnalysis *analysis);
RZ_API void rz_analysis_class_create(RzAnalysis *analysis, const char *name);
RZ_API void rz_analysis_class_delete(RzAnalysis *analysis, const char *name);
RZ_API bool rz_analysis_class_exists(RzAnalysis *analysis, const char *name);
RZ_API SdbList *rz_analysis_class_get_all(RzAnalysis *analysis, bool sorted);
RZ_API void rz_analysis_class_foreach(RzAnalysis *analysis, SdbForeachCallback cb, void *user);
RZ_API RzAnalysisClassErr rz_analysis_class_rename(RzAnalysis *analysis, const char *old_name, const char *new_name);

RZ_API void rz_analysis_class_method_fini(RzAnalysisMethod *meth);
RZ_API RzAnalysisClassErr rz_analysis_class_method_get(RzAnalysis *analysis, const char *class_name, const char *meth_name, RzAnalysisMethod *meth);
RZ_API RzAnalysisClassErr rz_analysis_class_method_get_by_addr(RzAnalysis *analysis, const char *class_name, ut64 addr, RzAnalysisMethod *method);
RZ_API RzVector /*<RzAnalysisMethod>*/ *rz_analysis_class_method_get_all(RzAnalysis *analysis, const char *class_name);
RZ_API RzAnalysisClassErr rz_analysis_class_method_set(RzAnalysis *analysis, const char *class_name, RzAnalysisMethod *meth);
RZ_API RzAnalysisClassErr rz_analysis_class_method_rename(RzAnalysis *analysis, const char *class_name, const char *old_meth_name, const char *new_meth_name);
RZ_API RzAnalysisClassErr rz_analysis_class_method_delete(RzAnalysis *analysis, const char *class_name, const char *meth_name);
RZ_API bool rz_analysis_class_method_exists(RzAnalysis *analysis, const char *class_name, const char *meth_name);
RZ_API bool rz_analysis_class_method_exists_by_addr(RzAnalysis *analysis, const char *class_name, ut64 addr);
RZ_API void rz_analysis_class_method_recover(RzAnalysis *analysis, RzBinClass *cls, RzList *methods);

RZ_API void rz_analysis_class_base_fini(RzAnalysisBaseClass *base);
RZ_API RzAnalysisClassErr rz_analysis_class_base_get(RzAnalysis *analysis, const char *class_name, const char *base_id, RzAnalysisBaseClass *base);
RZ_API RzVector /*<RzAnalysisBaseClass>*/ *rz_analysis_class_base_get_all(RzAnalysis *analysis, const char *class_name);
RZ_API RzAnalysisClassErr rz_analysis_class_base_set(RzAnalysis *analysis, const char *class_name, RzAnalysisBaseClass *base);
RZ_API RzAnalysisClassErr rz_analysis_class_base_delete(RzAnalysis *analysis, const char *class_name, const char *base_id);

RZ_API void rz_analysis_class_vtable_fini(RzAnalysisVTable *vtable);
RZ_API RzAnalysisClassErr rz_analysis_class_vtable_get(RzAnalysis *analysis, const char *class_name, const char *vtable_id, RzAnalysisVTable *vtable);
RZ_API RzVector /*<RzAnalysisVTable>*/ *rz_analysis_class_vtable_get_all(RzAnalysis *analysis, const char *class_name);
RZ_API RzAnalysisClassErr rz_analysis_class_vtable_set(RzAnalysis *analysis, const char *class_name, RzAnalysisVTable *vtable);
RZ_API RzAnalysisClassErr rz_analysis_class_vtable_delete(RzAnalysis *analysis, const char *class_name, const char *vtable_id);

RZ_API void rz_analysis_class_print(RzAnalysis *analysis, const char *class_name, bool detailed);
RZ_API void rz_analysis_class_json(RzAnalysis *analysis, PJ *j, const char *class_name);
RZ_API void rz_analysis_class_list(RzAnalysis *analysis, int mode);
RZ_API void rz_analysis_class_list_bases(RzAnalysis *analysis, const char *class_name);
RZ_API void rz_analysis_class_list_vtables(RzAnalysis *analysis, const char *class_name);
RZ_API void rz_analysis_class_list_vtable_offset_functions(RzAnalysis *analysis, const char *class_name, ut64 offset);
RZ_API RzGraph /*<RzGraphNodeInfo>*/ *rz_analysis_class_get_inheritance_graph(RzAnalysis *analysis);

RZ_API RzAnalysisEsilCFG *rz_analysis_esil_cfg_expr(RzAnalysisEsilCFG *cfg, RzAnalysis *analysis, const ut64 off, char *expr);
RZ_API RzAnalysisEsilCFG *rz_analysis_esil_cfg_op(RzAnalysisEsilCFG *cfg, RzAnalysis *analysis, RzAnalysisOp *op);
RZ_API void rz_analysis_esil_cfg_merge_blocks(RzAnalysisEsilCFG *cfg);
RZ_API void rz_analysis_esil_cfg_free(RzAnalysisEsilCFG *cfg);

RZ_API RzAnalysisEsilDFGNode *rz_analysis_esil_dfg_node_new(RzAnalysisEsilDFG *edf, const char *c);
RZ_API RzAnalysisEsilDFG *rz_analysis_esil_dfg_new(RzReg *regs);
RZ_API void rz_analysis_esil_dfg_free(RzAnalysisEsilDFG *dfg);
RZ_API RzAnalysisEsilDFG *rz_analysis_esil_dfg_expr(RzAnalysis *analysis, RzAnalysisEsilDFG *dfg, const char *expr);
RZ_API RzStrBuf *rz_analysis_esil_dfg_filter(RzAnalysisEsilDFG *dfg, const char *reg);
RZ_API RzStrBuf *rz_analysis_esil_dfg_filter_expr(RzAnalysis *analysis, const char *expr, const char *reg);

RZ_API size_t rz_analysis_function_arg_count(RzAnalysis *a, RzAnalysisFunction *fcn);
RZ_API RZ_OWN RzPVector *rz_analysis_function_args(RzAnalysis *a, RzAnalysisFunction *fcn);
RZ_API RZ_OWN RzList *rz_analysis_types_from_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn);
RZ_API RZ_OWN RzCallable *rz_analysis_function_derive_type(RzAnalysis *analysis, RzAnalysisFunction *f);

/* PDB */
RZ_API void rz_parse_pdb_types(const RzTypeDB *typedb, const RzPdb *pdb);

/* DWARF */
RZ_API void rz_analysis_dwarf_process_info(const RzAnalysis *analysis, RzAnalysisDwarfContext *ctx);
RZ_API void rz_analysis_dwarf_integrate_functions(RzAnalysis *analysis, RzFlag *flags, Sdb *dwarf_sdb);

/* serialize */
RZ_API void rz_serialize_analysis_case_op_save(RZ_NONNULL PJ *j, RZ_NONNULL RzAnalysisCaseOp *op);
RZ_API void rz_serialize_analysis_switch_op_save(RZ_NONNULL PJ *j, RZ_NONNULL RzAnalysisSwitchOp *op);
RZ_API RzAnalysisSwitchOp *rz_serialize_analysis_switch_op_load(RZ_NONNULL const RzJson *json);

typedef void *RzSerializeAnalDiffParser;
RZ_API RzSerializeAnalDiffParser rz_serialize_analysis_diff_parser_new(void);
RZ_API void rz_serialize_analysis_diff_parser_free(RzSerializeAnalDiffParser parser);
RZ_API RZ_NULLABLE RzAnalysisDiff *rz_serialize_analysis_diff_load(RZ_NONNULL RzSerializeAnalDiffParser parser, RZ_NONNULL const RzJson *json);
RZ_API void rz_serialize_analysis_diff_save(RZ_NONNULL PJ *j, RZ_NONNULL RzAnalysisDiff *diff);
RZ_API void rz_serialize_analysis_blocks_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);

/**
 * RzAnalysis must not contain any blocks when calling this function!
 * All loaded blocks will have a ref of 1 after this function and should be unrefd once after loading functions.
 */
RZ_API bool rz_serialize_analysis_blocks_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RzSerializeAnalDiffParser diff_parser, RZ_NULLABLE RzSerializeResultInfo *res);

typedef void *RzSerializeAnalVarParser;
RZ_API RzSerializeAnalVarParser rz_serialize_analysis_var_parser_new(void);
RZ_API void rz_serialize_analysis_var_parser_free(RzSerializeAnalVarParser parser);
RZ_API RZ_NULLABLE RzAnalysisVar *rz_serialize_analysis_var_load(RZ_NONNULL RzAnalysisFunction *fcn, RZ_NONNULL RzSerializeAnalVarParser parser, RZ_NONNULL const RzJson *json);

RZ_API void rz_serialize_analysis_functions_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_functions_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RzSerializeAnalDiffParser diff_parser, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_analysis_function_noreturn_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_function_noreturn_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_analysis_xrefs_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_xrefs_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_analysis_meta_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_meta_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_analysis_hints_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_hints_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_analysis_classes_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_classes_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_analysis_types_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_types_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_analysis_sign_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_sign_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_analysis_imports_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_imports_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_analysis_pin_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_pin_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_analysis_cc_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_cc_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);

RZ_API void rz_serialize_analysis_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis);
RZ_API bool rz_serialize_analysis_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res);

/* plugin pointers */
extern RzAnalysisPlugin rz_analysis_plugin_null;
extern RzAnalysisPlugin rz_analysis_plugin_6502;
extern RzAnalysisPlugin rz_analysis_plugin_6502_cs;
extern RzAnalysisPlugin rz_analysis_plugin_8051;
extern RzAnalysisPlugin rz_analysis_plugin_amd29k;
extern RzAnalysisPlugin rz_analysis_plugin_arc;
extern RzAnalysisPlugin rz_analysis_plugin_arm_cs;
extern RzAnalysisPlugin rz_analysis_plugin_arm_gnu;
extern RzAnalysisPlugin rz_analysis_plugin_avr;
extern RzAnalysisPlugin rz_analysis_plugin_bf;
extern RzAnalysisPlugin rz_analysis_plugin_chip8;
extern RzAnalysisPlugin rz_analysis_plugin_cr16;
extern RzAnalysisPlugin rz_analysis_plugin_cris;
extern RzAnalysisPlugin rz_analysis_plugin_dalvik;
extern RzAnalysisPlugin rz_analysis_plugin_ebc;
extern RzAnalysisPlugin rz_analysis_plugin_gb;
extern RzAnalysisPlugin rz_analysis_plugin_h8300;
extern RzAnalysisPlugin rz_analysis_plugin_hexagon;
extern RzAnalysisPlugin rz_analysis_plugin_i4004;
extern RzAnalysisPlugin rz_analysis_plugin_i8080;
extern RzAnalysisPlugin rz_analysis_plugin_java;
extern RzAnalysisPlugin rz_analysis_plugin_m68k_cs;
extern RzAnalysisPlugin rz_analysis_plugin_m680x_cs;
extern RzAnalysisPlugin rz_analysis_plugin_malbolge;
extern RzAnalysisPlugin rz_analysis_plugin_mcore;
extern RzAnalysisPlugin rz_analysis_plugin_mips_cs;
extern RzAnalysisPlugin rz_analysis_plugin_mips_gnu;
extern RzAnalysisPlugin rz_analysis_plugin_msp430;
extern RzAnalysisPlugin rz_analysis_plugin_nios2;
extern RzAnalysisPlugin rz_analysis_plugin_or1k;
extern RzAnalysisPlugin rz_analysis_plugin_pic;
extern RzAnalysisPlugin rz_analysis_plugin_ppc_cs;
extern RzAnalysisPlugin rz_analysis_plugin_ppc_gnu;
extern RzAnalysisPlugin rz_analysis_plugin_propeller;
extern RzAnalysisPlugin rz_analysis_plugin_riscv;
extern RzAnalysisPlugin rz_analysis_plugin_riscv_cs;
extern RzAnalysisPlugin rz_analysis_plugin_rsp;
extern RzAnalysisPlugin rz_analysis_plugin_sh;
extern RzAnalysisPlugin rz_analysis_plugin_snes;
extern RzAnalysisPlugin rz_analysis_plugin_sparc_cs;
extern RzAnalysisPlugin rz_analysis_plugin_sparc_gnu;
extern RzAnalysisPlugin rz_analysis_plugin_spc700;
extern RzAnalysisPlugin rz_analysis_plugin_sysz;
extern RzAnalysisPlugin rz_analysis_plugin_tms320;
extern RzAnalysisPlugin rz_analysis_plugin_tms320c64x;
extern RzAnalysisPlugin rz_analysis_plugin_tricore;
extern RzAnalysisPlugin rz_analysis_plugin_v810;
extern RzAnalysisPlugin rz_analysis_plugin_v850;
extern RzAnalysisPlugin rz_analysis_plugin_vax;
extern RzAnalysisPlugin rz_analysis_plugin_wasm;
extern RzAnalysisPlugin rz_analysis_plugin_x86;
extern RzAnalysisPlugin rz_analysis_plugin_x86_cs;
extern RzAnalysisPlugin rz_analysis_plugin_x86_im;
extern RzAnalysisPlugin rz_analysis_plugin_x86_simple;
extern RzAnalysisPlugin rz_analysis_plugin_x86_udis;
extern RzAnalysisPlugin rz_analysis_plugin_xap;
extern RzAnalysisPlugin rz_analysis_plugin_xcore_cs;
extern RzAnalysisPlugin rz_analysis_plugin_xtensa;
extern RzAnalysisPlugin rz_analysis_plugin_z80;
extern RzAnalysisPlugin rz_analysis_plugin_pyc;
extern RzAnalysisPlugin rz_analysis_plugin_luac;
#ifdef __cplusplus
}
#endif

#endif
#endif
