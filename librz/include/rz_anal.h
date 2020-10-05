/* rizin - LGPL - Copyright 2009-2020 - nibble, pancake, xvilka */

#ifndef RZ_ANAL_H
#define RZ_ANAL_H

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

#define esilprintf(op, fmt, ...) rz_strbuf_setf (&op->esil, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_anal);

/* dwarf processing context */
typedef struct rz_anal_dwarf_context {
	const RBinDwarfDebugInfo *info;
	HtUP/*<offset, RBinDwarfLocList*>*/  *loc;
	// const RBinDwarfCfa *cfa; TODO
} RzAnalDwarfContext;

// TODO: save memory2 : fingerprints must be pointers to a buffer
// containing a dupped file in memory

/* save memory:
   bb_has_ops=1 -> 600M
   bb_has_ops=0 -> 350MB
 */

typedef struct {
	struct rz_anal_t *anal;
	int type;
	int rad;
	SdbForeachCallback cb;
	void *user;
	int count;
	struct rz_anal_function_t *fcn;
	PJ *pj;
} RzAnalMetaUserItem;

typedef struct rz_anal_range_t {
	ut64 from;
	ut64 to;
	int bits;
	ut64 rb_max_addr;
	RBNode rb;
} RzAnalRange;

#define RZ_ANAL_GET_OFFSET(x,y,z) \
	(x && x->binb.bin && x->binb.get_offset)? \
		x->binb.get_offset (x->binb.bin, y, z): -1
enum {
	RZ_ANAL_DATA_TYPE_NULL = 0,
	RZ_ANAL_DATA_TYPE_UNKNOWN = 1,
	RZ_ANAL_DATA_TYPE_STRING = 2,
	RZ_ANAL_DATA_TYPE_WIDE_STRING = 3,
	RZ_ANAL_DATA_TYPE_POINTER = 4,
	RZ_ANAL_DATA_TYPE_NUMBER = 5,
	RZ_ANAL_DATA_TYPE_INVALID = 6,
	RZ_ANAL_DATA_TYPE_HEADER = 7,
	RZ_ANAL_DATA_TYPE_SEQUENCE = 8,
	RZ_ANAL_DATA_TYPE_PATTERN = 9,
};

// used from core/anal.c
#define RZ_ANAL_ADDR_TYPE_EXEC      1
#define RZ_ANAL_ADDR_TYPE_READ      1 << 1
#define RZ_ANAL_ADDR_TYPE_WRITE     1 << 2
#define RZ_ANAL_ADDR_TYPE_FLAG      1 << 3
#define RZ_ANAL_ADDR_TYPE_FUNC      1 << 4
#define RZ_ANAL_ADDR_TYPE_HEAP      1 << 5
#define RZ_ANAL_ADDR_TYPE_STACK     1 << 6
#define RZ_ANAL_ADDR_TYPE_REG       1 << 7
#define RZ_ANAL_ADDR_TYPE_PROGRAM   1 << 8
#define RZ_ANAL_ADDR_TYPE_LIBRARY   1 << 9
#define RZ_ANAL_ADDR_TYPE_ASCII     1 << 10
#define RZ_ANAL_ADDR_TYPE_SEQUENCE  1 << 11

#define RZ_ANAL_ARCHINFO_MIN_OP_SIZE 0
#define RZ_ANAL_ARCHINFO_MAX_OP_SIZE 1
#define RZ_ANAL_ARCHINFO_ALIGN 2
#define RZ_ANAL_ARCHINFO_DATA_ALIGN 4

/* copypaste from rz_asm.h */

#define RZ_ANAL_GET_OFFSET(x,y,z) \
        (x && x->binb.bin && x->binb.get_offset)? \
                x->binb.get_offset (x->binb.bin, y, z): -1

#define RZ_ANAL_GET_NAME(x,y,z) \
        (x && x->binb.bin && x->binb.get_name)? \
                x->binb.get_name (x->binb.bin, y, z): NULL

/* type = (RZ_ANAL_VAR_TYPE_BYTE & RZ_ANAL_VAR_TYPE_SIZE_MASK) |
 *			( RANAL_VAR_TYPE_SIGNED & RANAL_VAR_TYPE_SIGN_MASK) |
 *			( RANAL_VAR_TYPE_CONST & RANAL_VAR_TYPE_MODIFIER_MASK)
 */
typedef struct rz_anal_type_var_t {
	char *name;
	int index;
	int scope;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	union {
		ut8  v8;
		ut16 v16;
		ut32 v32;
		ut64 v64;
	} value;
} RzAnalTypeVar;

typedef struct rz_anal_type_ptr_t {
	char *name;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	union {
		ut8  v8;
		ut16 v16;
		ut32 v32;
		ut64 v64;
	} value;
} RzAnalTypePtr;

typedef struct rz_anal_type_array_t {
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
} RzAnalTypeArray;

typedef struct rz_anal_type_struct_t RzAnalTypeStruct;
typedef struct rz_anal_type_t RzAnalType;

struct rz_anal_type_struct_t {
	char *name;
	ut8 type;
	ut32 size;
	void *parent;
	RzAnalType *items;
};

typedef struct rz_anal_type_union_t {
	char *name;
	ut8 type;
	ut32 size;
	void *parent;
	RzAnalType *items;
} RzAnalTypeUnion;

typedef struct rz_anal_type_alloca_t {
	long address;
	long size;
	void *parent;
	RzAnalType *items;
} RzAnalTypeAlloca;

enum {
	RZ_ANAL_FQUALIFIER_NONE = 0,
	RZ_ANAL_FQUALIFIER_STATIC = 1,
	RZ_ANAL_FQUALIFIER_VOLATILE = 2,
	RZ_ANAL_FQUALIFIER_INLINE = 3,
	RZ_ANAL_FQUALIFIER_NAKED	= 4,
	RZ_ANAL_FQUALIFIER_VIRTUAL = 5,
};

/*--------------------Function Conventions-----------*/
//XXX don't use them in the future
#define RZ_ANAL_CC_TYPE_STDCALL 0
#define RZ_ANAL_CC_TYPE_PASCAL 1
#define RZ_ANAL_CC_TYPE_FASTCALL 'A' // syscall
#define RZ_ANAL_CC_TYPE_SYSV 8
#define RZ_ANAL_CC_MAXARG 16

enum {
	RZ_ANAL_FCN_TYPE_NULL = 0,
	RZ_ANAL_FCN_TYPE_FCN = 1 << 0,
	RZ_ANAL_FCN_TYPE_LOC = 1 << 1,
	RZ_ANAL_FCN_TYPE_SYM = 1 << 2,
	RZ_ANAL_FCN_TYPE_IMP = 1 << 3,
	RZ_ANAL_FCN_TYPE_INT = 1 << 4,  /* privileged function - ends with iret/reti/.. */
	RZ_ANAL_FCN_TYPE_ROOT = 1 << 5, /* matching flag */
	RZ_ANAL_FCN_TYPE_ANY = -1       /* all the bits set */
};

#define RzAnalBlock struct rz_anal_bb_t

enum {
	RZ_ANAL_DIFF_TYPE_NULL = 0,
	RZ_ANAL_DIFF_TYPE_MATCH = 'm',
	RZ_ANAL_DIFF_TYPE_UNMATCH = 'u'
};

typedef struct rz_anal_enum_case_t {
	char *name;
	int val;
} RzAnalEnumCase;

typedef struct rz_anal_struct_member_t {
	char *name;
	char *type;
	size_t offset; // in bytes
	size_t size; // in bits?
} RzAnalStructMember;

typedef struct rz_anal_union_member_t {
	char *name;
	char *type;
	size_t offset; // in bytes
	size_t size; // in bits?
} RzAnalUnionMember;

typedef enum {
	RZ_ANAL_BASE_TYPE_KIND_STRUCT,
	RZ_ANAL_BASE_TYPE_KIND_UNION,
	RZ_ANAL_BASE_TYPE_KIND_ENUM,
	RZ_ANAL_BASE_TYPE_KIND_TYPEDEF, // probably temporary addition, dev purposes
	RZ_ANAL_BASE_TYPE_KIND_ATOMIC, // For real atomic base types
} RzAnalBaseTypeKind;

typedef struct rz_anal_base_type_struct_t {
	RzVector/*<RzAnalStructMember>*/ members;
} RzAnalBaseTypeStruct;

typedef struct rz_anal_base_type_union_t {
	RzVector/*<RzAnalUnionMember>*/ members;
} RzAnalBaseTypeUnion;

typedef struct rz_anal_base_type_enum_t {
	RzVector/*<RzAnalEnumCase*/ cases; // list of all the enum casessssss
} RzAnalBaseTypeEnum;

typedef struct rz_anal_base_type_t {
	char *name;
	char *type; // Used by typedef, atomic type, enum
	ut64 size; // size of the whole type in bits
	RzAnalBaseTypeKind kind;
	union {
		RzAnalBaseTypeStruct struct_data;
		RzAnalBaseTypeEnum enum_data;
		RzAnalBaseTypeUnion union_data;
	};
} RzAnalBaseType;

typedef struct rz_anal_diff_t {
	int type;
	ut64 addr;
	double dist;
	char *name;
	ut32 size;
} RzAnalDiff;
typedef struct rz_anal_attr_t RzAnalAttr;
struct rz_anal_attr_t {
	char *key;
	long value;
	RzAnalAttr *next;
};

/* Stores useful function metadata */
/* TODO: Think about moving more stuff to this structure? */
typedef struct rz_anal_fcn_meta_t {
	// _min and _max are calculated lazily when queried.
	// On changes, they will either be updated (if this can be done trivially) or invalidated.
	// They are invalid iff _min == UT64_MAX.
	ut64 _min;          // PRIVATE, min address, use rz_anal_function_min_addr() to access
	ut64 _max;          // PRIVATE, max address, use rz_anal_function_max_addr() to access

	int numrefs;        // number of cross references
	int numcallrefs;    // number of calls
} RzAnalFcnMeta;

typedef struct rz_anal_function_t {
	char *name;
	int bits; // ((> bits 0) (set-bits bits))
	int type;
	const char *cc; // calling convention, should come from RzAnal.constpool
	ut64 addr;
	HtUP/*<ut64, char *>*/ *labels;
	HtPP/*<char *, ut64 *>*/ *label_addrs;
	RzPVector vars;
	HtUP/*<st64, RzPVector<RzAnalVar *>>*/ *inst_vars; // offset of instructions => the variables they access
	ut64 reg_save_area; // size of stack area pre-reserved for saving registers 
	st64 bp_off; // offset of bp inside owned stack frame
	st64 stack;  // stack frame size
	int maxstack;
	int ninstr;
	bool folded;
	bool is_pure;
	bool is_variadic;
	bool has_changed; // true if function may have changed since last anaysis TODO: set this attribute where necessary
	bool bp_frame;
	bool is_noreturn; // true if function does not return
	ut8 *fingerprint; // TODO: make is fuzzy and smarter
	size_t fingerprint_size;
	RzAnalDiff *diff;
	RzList *bbs; // TODO: should be RzPVector
	RzAnalFcnMeta meta;
	RzList *imports; // maybe bound to class?
	struct rz_anal_t *anal; // this function is associated with this instance
} RzAnalFunction;

typedef struct rz_anal_func_arg_t {
	const char *name;
	const char *fmt;
	const char *cc_source;
	char *orig_c_type;
	char *c_type;
	ut64 size;
	ut64 src; //Function-call argument value or pointer to it
} RzAnalFuncArg;

struct rz_anal_type_t {
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
} RzAnalMetaType;

/* meta */
typedef struct rz_anal_meta_item_t {
	RzAnalMetaType type;
	int subtype;
	char *str;
	const RSpace *space;
} RzAnalMetaItem;

// anal
typedef enum {
	RZ_ANAL_OP_FAMILY_UNKNOWN = -1,
	RZ_ANAL_OP_FAMILY_CPU = 0,	/* normal cpu instruction */
	RZ_ANAL_OP_FAMILY_FPU,    	/* fpu (floating point) */
	RZ_ANAL_OP_FAMILY_MMX,    	/* multimedia instruction (packed data) */
	RZ_ANAL_OP_FAMILY_SSE,    	/* extended multimedia instruction (packed data) */
	RZ_ANAL_OP_FAMILY_PRIV,   	/* privileged instruction */
	RZ_ANAL_OP_FAMILY_CRYPTO, 	/* cryptographic instructions */
	RZ_ANAL_OP_FAMILY_THREAD, 	/* thread/lock/sync instructions */
	RZ_ANAL_OP_FAMILY_VIRT,   	/* virtualization instructions */
	RZ_ANAL_OP_FAMILY_SECURITY,	/* security instructions */
	RZ_ANAL_OP_FAMILY_IO,     	/* IO instructions (i.e. IN/OUT) */
	RZ_ANAL_OP_FAMILY_LAST
} RzAnalOpFamily;

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
		RZ_ANAL_OP_PREFIX_COND     = 1,
		RZ_ANAL_OP_PREFIX_REP      = 1<<1,
		RZ_ANAL_OP_PREFIX_REPNE    = 1<<2,
		RZ_ANAL_OP_PREFIX_LOCK     = 1<<3,
		RZ_ANAL_OP_PREFIX_LIKELY   = 1<<4,
		RZ_ANAL_OP_PREFIX_UNLIKELY = 1<<5
		/* TODO: add segment override typemods? */
	} RzAnalOpPrefix;

// XXX: this definition is plain wrong. use enum or empower bits
#define RZ_ANAL_OP_TYPE_MASK 0x8000ffff
#define RZ_ANAL_OP_HINT_MASK 0xf0000000
typedef enum {
	RZ_ANAL_OP_TYPE_COND  = 0x80000000, // TODO must be moved to prefix?
	//TODO: MOVE TO PREFIX .. it is used by anal_java.. must be updated
	RZ_ANAL_OP_TYPE_REP   = 0x40000000, /* repeats next instruction N times */
	RZ_ANAL_OP_TYPE_MEM   = 0x20000000, // TODO must be moved to prefix?
	RZ_ANAL_OP_TYPE_REG   = 0x10000000, // operand is a register
	RZ_ANAL_OP_TYPE_IND   = 0x08000000, // operand is indirect
	RZ_ANAL_OP_TYPE_NULL  = 0,
	RZ_ANAL_OP_TYPE_JMP   = 1,  /* mandatory jump */
	RZ_ANAL_OP_TYPE_UJMP  = 2,  /* unknown jump (register or so) */
	RZ_ANAL_OP_TYPE_RJMP  = RZ_ANAL_OP_TYPE_REG | RZ_ANAL_OP_TYPE_UJMP,
	RZ_ANAL_OP_TYPE_IJMP  = RZ_ANAL_OP_TYPE_IND | RZ_ANAL_OP_TYPE_UJMP,
	RZ_ANAL_OP_TYPE_IRJMP = RZ_ANAL_OP_TYPE_IND | RZ_ANAL_OP_TYPE_REG | RZ_ANAL_OP_TYPE_UJMP,
	RZ_ANAL_OP_TYPE_CJMP  = RZ_ANAL_OP_TYPE_COND | RZ_ANAL_OP_TYPE_JMP,  /* conditional jump */
	RZ_ANAL_OP_TYPE_RCJMP = RZ_ANAL_OP_TYPE_REG | RZ_ANAL_OP_TYPE_CJMP,  /* conditional jump register */
	RZ_ANAL_OP_TYPE_MJMP  = RZ_ANAL_OP_TYPE_MEM | RZ_ANAL_OP_TYPE_JMP,   /* memory jump */
	RZ_ANAL_OP_TYPE_MCJMP = RZ_ANAL_OP_TYPE_MEM | RZ_ANAL_OP_TYPE_CJMP,  /* memory conditional jump */
	RZ_ANAL_OP_TYPE_UCJMP = RZ_ANAL_OP_TYPE_COND | RZ_ANAL_OP_TYPE_UJMP, /* conditional unknown jump */
	RZ_ANAL_OP_TYPE_CALL  = 3,  /* call to subroutine (branch+link) */
	RZ_ANAL_OP_TYPE_UCALL = 4, /* unknown call (register or so) */
	RZ_ANAL_OP_TYPE_RCALL = RZ_ANAL_OP_TYPE_REG | RZ_ANAL_OP_TYPE_UCALL,
	RZ_ANAL_OP_TYPE_ICALL = RZ_ANAL_OP_TYPE_IND | RZ_ANAL_OP_TYPE_UCALL,
	RZ_ANAL_OP_TYPE_IRCALL= RZ_ANAL_OP_TYPE_IND | RZ_ANAL_OP_TYPE_REG | RZ_ANAL_OP_TYPE_UCALL,
	RZ_ANAL_OP_TYPE_CCALL = RZ_ANAL_OP_TYPE_COND | RZ_ANAL_OP_TYPE_CALL, /* conditional call to subroutine */
	RZ_ANAL_OP_TYPE_UCCALL= RZ_ANAL_OP_TYPE_COND | RZ_ANAL_OP_TYPE_UCALL, /* conditional unknown call */
	RZ_ANAL_OP_TYPE_RET   = 5, /* returns from subroutine */
	RZ_ANAL_OP_TYPE_CRET  = RZ_ANAL_OP_TYPE_COND | RZ_ANAL_OP_TYPE_RET, /* conditional return from subroutine */
	RZ_ANAL_OP_TYPE_ILL   = 6,  /* illegal instruction // trap */
	RZ_ANAL_OP_TYPE_UNK   = 7, /* unknown opcode type */
	RZ_ANAL_OP_TYPE_NOP   = 8, /* does nothing */
	RZ_ANAL_OP_TYPE_MOV   = 9, /* register move */
	RZ_ANAL_OP_TYPE_CMOV  = 9 | RZ_ANAL_OP_TYPE_COND, /* conditional move */
	RZ_ANAL_OP_TYPE_TRAP  = 10, /* it's a trap! */
	RZ_ANAL_OP_TYPE_SWI   = 11,  /* syscall, software interrupt */
	RZ_ANAL_OP_TYPE_CSWI  = 11 | RZ_ANAL_OP_TYPE_COND,  /* syscall, software interrupt */
	RZ_ANAL_OP_TYPE_UPUSH = 12, /* unknown push of data into stack */
	RZ_ANAL_OP_TYPE_RPUSH = RZ_ANAL_OP_TYPE_UPUSH | RZ_ANAL_OP_TYPE_REG, /* push register */
	RZ_ANAL_OP_TYPE_PUSH  = 13,  /* push value into stack */
	RZ_ANAL_OP_TYPE_POP   = 14,   /* pop value from stack to register */
	RZ_ANAL_OP_TYPE_CMP   = 15,  /* compare something */
	RZ_ANAL_OP_TYPE_ACMP  = 16,  /* compare via and */
	RZ_ANAL_OP_TYPE_ADD   = 17,
	RZ_ANAL_OP_TYPE_SUB   = 18,
	RZ_ANAL_OP_TYPE_IO    = 19,
	RZ_ANAL_OP_TYPE_MUL   = 20,
	RZ_ANAL_OP_TYPE_DIV   = 21,
	RZ_ANAL_OP_TYPE_SHR   = 22,
	RZ_ANAL_OP_TYPE_SHL   = 23,
	RZ_ANAL_OP_TYPE_SAL   = 24,
	RZ_ANAL_OP_TYPE_SAR   = 25,
	RZ_ANAL_OP_TYPE_OR    = 26,
	RZ_ANAL_OP_TYPE_AND   = 27,
	RZ_ANAL_OP_TYPE_XOR   = 28,
	RZ_ANAL_OP_TYPE_NOR   = 29,
	RZ_ANAL_OP_TYPE_NOT   = 30,
	RZ_ANAL_OP_TYPE_STORE = 31,  /* store from register to memory */
	RZ_ANAL_OP_TYPE_LOAD  = 32,  /* load from memory to register */
	RZ_ANAL_OP_TYPE_LEA   = 33, /* TODO add ulea */
	RZ_ANAL_OP_TYPE_LEAVE = 34,
	RZ_ANAL_OP_TYPE_ROR   = 35,
	RZ_ANAL_OP_TYPE_ROL   = 36,
	RZ_ANAL_OP_TYPE_XCHG  = 37,
	RZ_ANAL_OP_TYPE_MOD   = 38,
	RZ_ANAL_OP_TYPE_SWITCH = 39,
	RZ_ANAL_OP_TYPE_CASE = 40,
	RZ_ANAL_OP_TYPE_LENGTH = 41,
	RZ_ANAL_OP_TYPE_CAST = 42,
	RZ_ANAL_OP_TYPE_NEW = 43,
	RZ_ANAL_OP_TYPE_ABS = 44,
	RZ_ANAL_OP_TYPE_CPL = 45,	/* complement */
	RZ_ANAL_OP_TYPE_CRYPTO = 46,
	RZ_ANAL_OP_TYPE_SYNC = 47,
	//RZ_ANAL_OP_TYPE_DEBUG = 43, // monitor/trace/breakpoint
#if 0
	RZ_ANAL_OP_TYPE_PRIV = 40, /* privileged instruction */
	RZ_ANAL_OP_TYPE_FPU = 41, /* floating point stuff */
#endif
} _RzAnalOpType;

typedef enum {
	RZ_ANAL_OP_MASK_BASIC = 0, // Just fills basic op info , it's fast
	RZ_ANAL_OP_MASK_ESIL  = 1, // It fills RzAnalop->esil info
	RZ_ANAL_OP_MASK_VAL   = 2, // It fills RzAnalop->dst/src info
	RZ_ANAL_OP_MASK_HINT  = 4, // It calls rz_anal_op_hint to override anal options
	RZ_ANAL_OP_MASK_OPEX  = 8, // It fills RzAnalop->opex info
	RZ_ANAL_OP_MASK_DISASM = 16, // It fills RzAnalop->mnemonic // should be RzAnalOp->disasm // only from rz_core_anal_op()
	RZ_ANAL_OP_MASK_ALL   = 1 | 2 | 4 | 8 | 16
} RzAnalOpMask;

/* TODO: what to do with signed/unsigned conditionals? */
typedef enum {
	RZ_ANAL_COND_AL = 0,        // Always executed (no condition)
	RZ_ANAL_COND_EQ,            // Equal
	RZ_ANAL_COND_NE,            // Not equal
	RZ_ANAL_COND_GE,            // Greater or equal
	RZ_ANAL_COND_GT,            // Greater than
	RZ_ANAL_COND_LE,            // Less or equal
	RZ_ANAL_COND_LT,            // Less than
	RZ_ANAL_COND_NV,            // Never executed             must be a nop? :D
	RZ_ANAL_COND_HS,            // Carry set                  >, ==, or unordered
	RZ_ANAL_COND_LO,            // Carry clear                Less than
	RZ_ANAL_COND_MI,            // Minus, negative            Less than
	RZ_ANAL_COND_PL,            // Plus, positive or zero     >, ==, or unordered
	RZ_ANAL_COND_VS,            // Overflow                   Unordered
	RZ_ANAL_COND_VC,            // No overflow                Not unordered
	RZ_ANAL_COND_HI,            // Unsigned higher            Greater than, or unordered
	RZ_ANAL_COND_LS             // Unsigned lower or same     Less than or equal
} _RzAnalCond;

typedef enum {
	RZ_ANAL_VAR_SCOPE_LOCAL  = 0x01
} _RzAnalVarScope;

typedef enum {
	RZ_ANAL_STACK_NULL = 0,
	RZ_ANAL_STACK_NOP,
	RZ_ANAL_STACK_INC,
	RZ_ANAL_STACK_GET,
	RZ_ANAL_STACK_SET,
	RZ_ANAL_STACK_RESET,
	RZ_ANAL_STACK_ALIGN,
} RzAnalStackOp;

enum {
	RZ_ANAL_REFLINE_TYPE_UTF8 = 1,
	RZ_ANAL_REFLINE_TYPE_WIDE = 2,  /* reflines have a space between them */
	RZ_ANAL_REFLINE_TYPE_MIDDLE_BEFORE = 4, /* do not consider starts/ends of
	                                        * reflines (used for comment lines before disasm) */
	RZ_ANAL_REFLINE_TYPE_MIDDLE_AFTER = 8 /* as above but for lines after disasm */
};

enum {
	RZ_ANAL_RET_NOP = 0,
	RZ_ANAL_RET_ERROR = -1,
	RZ_ANAL_RET_DUP = -2,
	RZ_ANAL_RET_NEW = -3,
	RZ_ANAL_RET_END = -4
};

typedef struct rz_anal_case_obj_t {
	ut64 addr;
	ut64 jump;
	ut64 value;
} RzAnalCaseOp;

typedef struct rz_anal_switch_obj_t {
	ut64 addr;
	ut64 min_val;
	ut64 def_val;
	ut64 max_val;
	RzList/*<RzAnalCaseOp>*/ *cases;
} RzAnalSwitchOp;

struct rz_anal_t;
struct rz_anal_bb_t;
typedef struct rz_anal_callbacks_t {
	int (*on_fcn_new) (struct rz_anal_t *, void *user, RzAnalFunction *fcn);
	int (*on_fcn_delete) (struct rz_anal_t *, void *user, RzAnalFunction *fcn);
	int (*on_fcn_rename) (struct rz_anal_t *, void *user, RzAnalFunction *fcn, const char *oldname);
	int (*on_fcn_bb_new) (struct rz_anal_t *, void *user, RzAnalFunction *fcn, struct rz_anal_bb_t *bb);
} RzAnalCallbacks;

#define RZ_ANAL_ESIL_GOTO_LIMIT 4096

typedef struct rz_anal_options_t {
	int depth;
	int graph_depth;
	bool vars; //analyze local var and arguments
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
} RzAnalOptions;

typedef enum {
	RZ_ANAL_CPP_ABI_ITANIUM = 0,
	RZ_ANAL_CPP_ABI_MSVC
} RzAnalCPPABI;

typedef struct rz_anal_hint_cb_t {
	//add more cbs as needed
	void (*on_bits) (struct rz_anal_t *a, ut64 addr, int bits, bool set);
} RHintCb;

typedef struct rz_anal_t {
	char *cpu;      // anal.cpu
	char *os;       // asm.os
	int bits;       // asm.bits
	int lineswidth; // asm.lines.width
	int big_endian; // cfg.bigendian
	int sleep;      // anal.sleep, sleep some usecs before analyzing more (avoid 100% cpu usages)
	RzAnalCPPABI cpp_abi; // anal.cpp.abi
	void *user;
	ut64 gp;        // anal.gp, global pointer. used for mips. but can be used by other arches too in the future
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
	RBinBind binb; // Set only from core when an analysis plugin is called.
	RzCoreBind coreb;
	int maxreflines; // asm.lines.maxref
	int esil_goto_limit; // esil.gotolimit
	int pcalign; // asm.pcalign
	struct rz_anal_esil_t *esil;
	struct rz_anal_plugin_t *cur;
	RzAnalRange *limit; // anal.from, anal.to
	RzList *plugins;
	Sdb *sdb_types;
	Sdb *sdb_fmts;
	Sdb *sdb_zigns;
	HtUP *dict_refs;
	HtUP *dict_xrefs;
	bool recursive_noreturn; // anal.rnr
	RSpaces zign_spaces;
	char *zign_path; // dir.zigns
	PrintfCallback cb_printf;
	//moved from RzAnalFcn
	Sdb *sdb; // root
	Sdb *sdb_pins;
	HtUP/*<RzVector<RzAnalAddrHintRecord>>*/ *addr_hints; // all hints that correspond to a single address
	RBTree/*<RzAnalArchHintRecord>*/ arch_hints;
	RBTree/*<RzAnalArchBitsRecord>*/ bits_hints;
	RHintCb hint_cbs;
	RIntervalTree meta;
	RSpaces meta_spaces;
	Sdb *sdb_cc; // calling conventions
	Sdb *sdb_classes;
	Sdb *sdb_classes_attrs;
	RzAnalCallbacks cb;
	RzAnalOptions opt;
	RzList *reflines;
	//RzList *noreturn;
	RzListComparator columnSort;
	int stackptr;
	bool (*log)(struct rz_anal_t *anal, const char *msg);
	bool (*read_at)(struct rz_anal_t *anal, ut64 addr, ut8 *buf, int len);
	bool verbose;
	int seggrn;
	RzFlagGetAtAddr flag_get;
	REvent *ev;
	RzList/*<char *>*/ *imports; // global imports
	SetU *visited;
	RStrConstPool constpool;
	RzList *leaddrs;
} RzAnal;

typedef enum rz_anal_addr_hint_type_t {
	RZ_ANAL_ADDR_HINT_TYPE_IMMBASE,
	RZ_ANAL_ADDR_HINT_TYPE_JUMP,
	RZ_ANAL_ADDR_HINT_TYPE_FAIL,
	RZ_ANAL_ADDR_HINT_TYPE_STACKFRAME,
	RZ_ANAL_ADDR_HINT_TYPE_PTR,
	RZ_ANAL_ADDR_HINT_TYPE_NWORD,
	RZ_ANAL_ADDR_HINT_TYPE_RET,
	RZ_ANAL_ADDR_HINT_TYPE_NEW_BITS,
	RZ_ANAL_ADDR_HINT_TYPE_SIZE,
	RZ_ANAL_ADDR_HINT_TYPE_SYNTAX,
	RZ_ANAL_ADDR_HINT_TYPE_OPTYPE,
	RZ_ANAL_ADDR_HINT_TYPE_OPCODE,
	RZ_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET,
	RZ_ANAL_ADDR_HINT_TYPE_ESIL,
	RZ_ANAL_ADDR_HINT_TYPE_HIGH,
	RZ_ANAL_ADDR_HINT_TYPE_VAL
} RzAnalAddrHintType;

typedef struct rz_anal_addr_hint_record_t {
	RzAnalAddrHintType type;
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
} RzAnalAddrHintRecord;

typedef struct rz_anal_hint_t {
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
} RzAnalHint;

typedef RzAnalFunction *(* RzAnalGetFcnIn)(RzAnal *anal, ut64 addr, int type);
typedef RzAnalHint *(* RzAnalGetHint)(RzAnal *anal, ut64 addr);

typedef struct rz_anal_bind_t {
	RzAnal *anal;
	RzAnalGetFcnIn get_fcn_in;
	RzAnalGetHint get_hint;
} RzAnalBind;

typedef const char *(*RzAnalLabelAt) (RzAnalFunction *fcn, ut64);

typedef enum {
	RZ_ANAL_VAR_KIND_REG = 'r',
	RZ_ANAL_VAR_KIND_BPV = 'b',
	RZ_ANAL_VAR_KIND_SPV = 's'
} RzAnalVarKind;

#define VARPREFIX "var"
#define ARGPREFIX "arg"

typedef enum {
	RZ_ANAL_VAR_ACCESS_TYPE_READ = (1 << 0),
	RZ_ANAL_VAR_ACCESS_TYPE_WRITE = (1 << 1)
} RzAnalVarAccessType;

typedef struct rz_anal_var_access_t {
	const char *reg; // register used for access
	st64 offset; // relative to the function's entrypoint
	st64 stackptr; // delta added to register to get the var, e.g. [rbp - 0x10]
	ut8 type; // RzAnalVarAccessType bits
} RzAnalVarAccess;

typedef struct rz_anal_var_constraint_t {
	_RzAnalCond cond;
	ut64 val;
} RzAnalVarConstraint;

// generic for args and locals
typedef struct rz_anal_var_t {
	RzAnalFunction *fcn;
	char *name; // name of the variable
	char *type; // cparse type of the variable
	RzAnalVarKind kind;
	bool isarg;
	int delta;   /* delta offset inside stack frame */
	char *regname; // name of the register
	RzVector/*<RzAnalVarAccess>*/ accesses; // ordered by offset, touch this only through API or expect uaf
	char *comment;
	RzVector/*<RzAnalVarConstraint>*/ constraints;

	// below members are just for caching, TODO: remove them and do it better
	int argnum;
} RzAnalVar;

// Refers to a variable or a struct field inside a variable, only for varsub
RZ_DEPRECATE typedef struct rz_anal_var_field_t {
	char *name;
	st64 delta;
	bool field;
} RzAnalVarField;

typedef enum {
	RZ_ANAL_ACC_UNKNOWN = 0,
	RZ_ANAL_ACC_R = (1 << 0),
	RZ_ANAL_ACC_W = (1 << 1),
} RzAnalValueAccess;

typedef enum {
	RZ_ANAL_VAL_REG,
	RZ_ANAL_VAL_MEM,
	RZ_ANAL_VAL_IMM,
} RzAnalValueType;

// base+reg+regdelta*mul+delta
typedef struct rz_anal_value_t {
	RzAnalValueType type;
	RzAnalValueAccess access;
	int absolute; // if true, unsigned cast is used
	int memref; // is memory reference? which size? 1, 2 ,4, 8
	ut64 base ; // numeric address
	st64 delta; // numeric delta
	st64 imm; // immediate value
	int mul; // multiplier (reg*4+base)
	RzRegItem *seg; // segment selector register
	RzRegItem *reg; // register / register base used (-1 if no reg)
	RzRegItem *regdelta; // register index used (-1 if no reg)
} RzAnalValue;

typedef enum {
	RZ_ANAL_OP_DIR_READ = 1,
	RZ_ANAL_OP_DIR_WRITE = 2,
	RZ_ANAL_OP_DIR_EXEC = 4,
	RZ_ANAL_OP_DIR_REF = 8,
} RzAnalOpDirection;

typedef enum rz_anal_data_type_t {
	RZ_ANAL_DATATYPE_NULL = 0,
	RZ_ANAL_DATATYPE_ARRAY,
	RZ_ANAL_DATATYPE_OBJECT, // instance
	RZ_ANAL_DATATYPE_STRING,
	RZ_ANAL_DATATYPE_CLASS,
	RZ_ANAL_DATATYPE_BOOLEAN,
	RZ_ANAL_DATATYPE_INT16,
	RZ_ANAL_DATATYPE_INT32,
	RZ_ANAL_DATATYPE_INT64,
	RZ_ANAL_DATATYPE_FLOAT,
} RzAnalDataType;

typedef struct rz_anal_op_t {
	char *mnemonic; /* mnemonic.. it actually contains the args too, we should replace rasm with this */
	ut64 addr;      /* address */
	ut32 type;	/* type of opcode */
	RzAnalOpPrefix prefix;	/* type of opcode prefix (rep,lock,..) */
	ut32 type2;	/* used by java */
	RzAnalStackOp stackop;	/* operation on stack? */
	_RzAnalCond cond;	/* condition type */
	int size;       /* size in bytes of opcode */
	int nopcode;    /* number of bytes representing the opcode (not the arguments) TODO: find better name */
	int cycles;	/* cpu-cycles taken by instruction */
	int failcycles;	/* conditional cpu-cycles */
	RzAnalOpFamily family;	/* family of opcode */
	int id;         /* instruction id */
	bool eob;       /* end of block (boolean) */
	bool sign;      /* operates on signed values, false by default */
	/* Run N instructions before executing the current one */
	int delay;      /* delay N slots (mips, ..)*/
	ut64 jump;      /* true jmp */
	ut64 fail;      /* false jmp */
	RzAnalOpDirection direction;
	st64 ptr;       /* reference to memory */ /* XXX signed? */
	ut64 val;       /* reference to value */ /* XXX signed? */
	int ptrsize;    /* f.ex: zero extends for 8, 16 or 32 bits only */
	st64 stackptr;  /* stack pointer */
	int refptr;     /* if (0) ptr = "reference" else ptr = "load memory of refptr bytes" */
	RzAnalValue *src[3];
	RzAnalValue *dst;
	RzList *access; /* RzAnalValue access information */
	RStrBuf esil;
	RStrBuf opex;
	const char *reg; /* destination register */
	const char *ireg; /* register used for indirect memory computation*/
	int scale;
	ut64 disp;
	RzAnalSwitchOp *switch_op;
	RzAnalHint hint;
	RzAnalDataType datatype;
} RzAnalOp;

#define RZ_ANAL_COND_SINGLE(x) (!x->arg[1] || x->arg[0]==x->arg[1])

typedef struct rz_anal_cond_t {
	int type; // filled by CJMP opcode
	RzAnalValue *arg[2]; // filled by CMP opcode
} RzAnalCond;

typedef struct rz_anal_bb_t {
	RBNode _rb;     // private, node in the RBTree
	ut64 _max_end;  // private, augmented value for RBTree

	ut64 addr;
	ut64 size;
	ut64 jump;
	ut64 fail;
	bool traced;
	bool folded;
	ut32 colorize;
	ut8 *fingerprint;
	RzAnalDiff *diff;
	RzAnalCond *cond;
	RzAnalSwitchOp *switch_op;
	ut16 *op_pos; // offsets of instructions in this block, count is ninstr - 1 (first is always 0)
	ut8 *op_bytes;
	ut8 *parent_reg_arena;
	int op_pos_size; // size of the op_pos array
	int ninstr;
	int stackptr;
	int parent_stackptr;
	ut64 cmpval;
	const char *cmpreg;

	RzList *fcns;
	RzAnal *anal;
	int ref;
#undef RzAnalBlock
} RzAnalBlock;

typedef enum {
	RZ_ANAL_REF_TYPE_NULL = 0,
	RZ_ANAL_REF_TYPE_CODE = 'c', // code ref
	RZ_ANAL_REF_TYPE_CALL = 'C', // code ref (call)
	RZ_ANAL_REF_TYPE_DATA = 'd', // mem ref
	RZ_ANAL_REF_TYPE_STRING='s'  // string ref
} RzAnalRefType;

typedef struct rz_anal_ref_t {
	ut64 addr;
	ut64 at;
	RzAnalRefType type;
} RzAnalRef;
RZ_API const char *rz_anal_ref_type_tostring(RzAnalRefType t);

/* represents a reference line from one address (from) to another (to) */
typedef struct rz_anal_refline_t {
	ut64 from;
	ut64 to;
	int index;
	int level;
	int type;
	int direction;
} RzAnalRefline;

typedef struct rz_anal_cycle_frame_t {
	ut64 naddr;			//next addr
	RzList *hooks;
	struct rz_anal_cycle_frame_t *prev;
} RzAnalCycleFrame;

typedef struct rz_anal_cycle_hook_t {	//rename ?
	ut64 addr;
	int cycles;
} RzAnalCycleHook;

typedef struct rz_anal_esil_word_t {
	int type;
	const char *str;
} RzAnalEsilWord;

// only flags that affect control flow
enum {
	RZ_ANAL_ESIL_FLAG_ZERO = 1,
	RZ_ANAL_ESIL_FLAG_CARRY = 2,
	RZ_ANAL_ESIL_FLAG_OVERFLOW = 4,
	RZ_ANAL_ESIL_FLAG_PARITY = 8,
	RZ_ANAL_ESIL_FLAG_SIGN = 16,
	// ...
};

enum {
	RZ_ANAL_TRAP_NONE = 0,
	RZ_ANAL_TRAP_UNHANDLED = 1,
	RZ_ANAL_TRAP_BREAKPOINT = 2,
	RZ_ANAL_TRAP_DIVBYZERO = 3,
	RZ_ANAL_TRAP_WRITE_ERR = 4,
	RZ_ANAL_TRAP_READ_ERR = 5,
	RZ_ANAL_TRAP_EXEC_ERR = 6,
	RZ_ANAL_TRAP_INVALID = 7,
	RZ_ANAL_TRAP_UNALIGNED = 8,
	RZ_ANAL_TRAP_TODO = 9,
	RZ_ANAL_TRAP_HALT = 10,
};

enum {
	RZ_ANAL_ESIL_PARM_INVALID = 0,
	RZ_ANAL_ESIL_PARM_REG,
	RZ_ANAL_ESIL_PARM_NUM,
};

/* Constructs to convert from ESIL to REIL */
#define FOREACHOP(GENERATE)                     \
/* No Operation */               GENERATE(NOP)  \
/* Unknown/Undefined */          GENERATE(UNK)  \
/* Conditional Jump */           GENERATE(JCC)  \
/* Store Value to register */    GENERATE(STR)  \
/* Store value to memory */      GENERATE(STM)  \
/* Load value from memory */     GENERATE(LDM)  \
/* Addition */                   GENERATE(ADD)  \
/* Subtraction */                GENERATE(SUB)  \
/* Negation */                   GENERATE(NEG)  \
/* Multiplication */             GENERATE(MUL)  \
/* Division */                   GENERATE(DIV)  \
/* Modulo */                     GENERATE(MOD)  \
/* Signed Multiplication */      GENERATE(SMUL) \
/* Sugned Division */            GENERATE(SDIV) \
/* Signed Modulus */             GENERATE(SMOD) \
/* Shift Left */                 GENERATE(SHL)  \
/* Shift Right */                GENERATE(SHR)  \
/* Binary and */                 GENERATE(AND)  \
/* Binary or */                  GENERATE(OR)   \
/* Binary xor */                 GENERATE(XOR)  \
/* Binary not */                 GENERATE(NOT)  \
/* Equation */                   GENERATE(EQ)   \
/* Less Than */                  GENERATE(LT)

#define MAKE_ENUM(OP) REIL_##OP,
#define REIL_OP_STRING(STRING) #STRING,

typedef enum {
	FOREACHOP(MAKE_ENUM)
} RzAnalReilOpcode;

typedef enum {
	ARG_REG,           // CPU Register
	ARG_TEMP,          // Temporary register used by REIL
	ARG_CONST,         // Constant value
	ARG_ESIL_INTERNAL, // Used to resolve ESIL internal flags
	ARG_NONE           // Operand not used by the instruction
} RzAnalReilArgType;

// Arguments to a REIL instruction.
typedef struct rz_anal_reil_arg {
	RzAnalReilArgType type; // Type of the argument
	ut8 size;              // Size of the argument in bytes
	char name[32];         // Name of the argument
} RzAnalReilArg;

typedef struct rz_anal_ref_char {
	char *str;
	char *cols;
} RzAnalRefStr;

// Instruction arg1, arg2, arg3
typedef struct rz_anal_reil_inst {
	RzAnalReilOpcode opcode;
	RzAnalReilArg *arg[3];
} RzAnalReilInst;

typedef struct rz_anal_reil {
	char old[32]; // Used to compute flags.
	char cur[32];
	ut8 lastsz;
	ut64 reilNextTemp;   // Used to store the index of the next REIL temp register to be used.
	ut64 addr;           // Used for instruction sequencing. Check esil2reil.c for details.
	ut8 seq_num;         // Incremented and used when noInc is set to 1.
	int skip;
	int cmd_count;
	char if_buf[64];
	char pc[8];
} RzAnalReil;

// must be a char
#define ESIL_INTERNAL_PREFIX '$'
#define ESIL_STACK_NAME "esil.ram"
#define ESIL struct rz_anal_esil_t

typedef struct rz_anal_esil_source_t {
	ut32 id;
	ut32 claimed;
	void *content;
} RzAnalEsilSource;

RZ_API void rz_anal_esil_sources_init(ESIL *esil);
RZ_API ut32 rz_anal_esil_load_source(ESIL *esil, const char *path);
RZ_API void *rz_anal_esil_get_source(ESIL *esil, ut32 src_id);
RZ_API bool rz_anal_esil_claim_source(ESIL *esil, ut32 src_id);
RZ_API void rz_anal_esil_release_source(ESIL *esil, ut32 src_id);
RZ_API void rz_anal_esil_sources_fini(ESIL *esil);

typedef bool (*RzAnalEsilInterruptCB)(ESIL *esil, ut32 interrupt, void *user);

typedef struct rz_anal_esil_interrupt_handler_t {
	const ut32 num;
	const char* name;
	void *(*init)(ESIL *esil);
	RzAnalEsilInterruptCB cb;
	void (*fini)(void *user);
} RzAnalEsilInterruptHandler;

typedef struct rz_anal_esil_interrupt_t {
	RzAnalEsilInterruptHandler *handler;
	void *user;
	ut32 src_id;
} RzAnalEsilInterrupt;

typedef struct rz_anal_esil_change_reg_t {
	int idx;
	ut64 data;
} RzAnalEsilRegChange;

typedef struct rz_anal_esil_change_mem_t {
	int idx;
	ut8 data;
} RzAnalEsilMemChange;

typedef struct rz_anal_esil_trace_t {
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
} RzAnalEsilTrace;

typedef int (*RzAnalEsilHookRegWriteCB)(ESIL *esil, const char *name, ut64 *val);

typedef struct rz_anal_esil_callbacks_t {
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
	RzAnalEsilHookRegWriteCB hook_reg_write;
	int (*reg_write)(ESIL *esil, const char *name, ut64 val);
} RzAnalEsilCallbacks;

typedef struct rz_anal_esil_t {
	RzAnal *anal;
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
	int delay; 		// mapped to $ds in ESIL
	ut64 jump_target; 	// mapped to $jt in ESIL
	int jump_target_set; 	// mapped to $js in ESIL
	int trap;
	ut32 trap_code; // extend into a struct to store more exception info?
	// parity flag? done with cur
	ut64 old;	//used for carry-flagging and borrow-flagging
	ut64 cur;	//used for carry-flagging and borrow-flagging
	ut8 lastsz;	//in bits //used for signature-flag
	/* native ops and custom ops */
	HtPP *ops;
	char *current_opstr;
	RIDStorage *sources;
	SdbMini *interrupts;
	//this is a disgusting workaround, because we have no ht-like storage without magic keys, that you cannot use, with int-keys
	RzAnalEsilInterrupt *intr0;
	/* deep esil parsing fills this */
	Sdb *stats;
	RzAnalEsilTrace *trace;
	RzAnalEsilCallbacks cb;
	RzAnalReil *Reil;
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
	int stack_fd;	// ahem, let's not do this
} RzAnalEsil;

#undef ESIL


enum {
	RZ_ANAL_ESIL_OP_TYPE_UNKNOWN = 0x1,
	RZ_ANAL_ESIL_OP_TYPE_CONTROL_FLOW,
	RZ_ANAL_ESIL_OP_TYPE_MEM_READ = 0x4,
	RZ_ANAL_ESIL_OP_TYPE_MEM_WRITE = 0x8,
	RZ_ANAL_ESIL_OP_TYPE_REG_WRITE = 0x10,
	RZ_ANAL_ESIL_OP_TYPE_MATH = 0x20,
	RZ_ANAL_ESIL_OP_TYPE_CUSTOM = 0x40
};


typedef bool (*RzAnalEsilOpCb)(RzAnalEsil *esil);

typedef struct rz_anal_esil_operation_t {
	RzAnalEsilOpCb code;
	ut32 push;		// amount of operands pushed
	ut32 pop;		// amount of operands popped
	ut32 type;
} RzAnalEsilOp;


// this is 80-bit offsets so we can address every piece of esil in an instruction
typedef struct rz_anal_esil_expr_offset_t {
	ut64 off;
	ut16 idx;
} RzAnalEsilEOffset;

typedef enum {
	RZ_ANAL_ESIL_BLOCK_ENTER_NORMAL = 0,
	RZ_ANAL_ESIL_BLOCK_ENTER_TRUE,
	RZ_ANAL_ESIL_BLOCK_ENTER_FALSE,
	RZ_ANAL_ESIL_BLOCK_ENTER_GLUE,
} RzAnalEsilBlockEnterType;

typedef struct rz_anal_esil_basic_block_t {
	RzAnalEsilEOffset first;
	RzAnalEsilEOffset last;
	char *expr;	//synthesized esil-expression for this block
	RzAnalEsilBlockEnterType enter;	//maybe more type is needed here
} RzAnalEsilBB;

typedef struct rz_anal_esil_cfg_t {
	RGraphNode *start;
	RGraphNode *end;
	RGraph *g;
} RzAnalEsilCFG;

typedef enum {
	RZ_ANAL_ESIL_DFG_BLOCK_CONST = 1,
	RZ_ANAL_ESIL_DFG_BLOCK_VAR = 2,
	RZ_ANAL_ESIL_DFG_BLOCK_PTR = 4,
	RZ_ANAL_ESIL_DFG_BLOCK_RESULT = 8,
	RZ_ANAL_ESIL_DFG_BLOCK_GENERATIVE = 16,
} RzAnalEsilDFGBlockType;

typedef struct rz_anal_esil_dfg_t {
	ut32 idx;
	Sdb *regs;		//resolves regnames to intervals
	RContRBTree *reg_vars;	//vars represented in regs
	RQueue *todo;		//todo-queue allocated in this struct for perf
	void *insert;		//needed for setting regs in dfg
	RGraph *flow;
	RGraphNode *cur;
	RGraphNode *old;
	bool malloc_failed;
} RzAnalEsilDFG;

typedef struct rz_anal_esil_dfg_node_t {
	// add more info here
	ut32 idx;
	RStrBuf *content;
	RzAnalEsilDFGBlockType type;
} RzAnalEsilDFGNode;

typedef int (*RzAnalCmdExt)(/* Rcore */RzAnal *anal, const char* input);

// TODO: rm data + len
typedef int (*RzAnalOpCallback)(RzAnal *a, RzAnalOp *op, ut64 addr, const ut8 *data, int len, RzAnalOpMask mask);

typedef bool (*RzAnalRegProfCallback)(RzAnal *a);
typedef char*(*RzAnalRegProfGetCallback)(RzAnal *a);
typedef int (*RzAnalFPBBCallback)(RzAnal *a, RzAnalBlock *bb);
typedef int (*RzAnalFPFcnCallback)(RzAnal *a, RzAnalFunction *fcn);
typedef int (*RzAnalDiffBBCallback)(RzAnal *anal, RzAnalFunction *fcn, RzAnalFunction *fcn2);
typedef int (*RzAnalDiffFcnCallback)(RzAnal *anal, RzList *fcns, RzList *fcns2);
typedef int (*RzAnalDiffEvalCallback)(RzAnal *anal);

typedef int (*RzAnalEsilCB)(RzAnalEsil *esil);
typedef int (*RzAnalEsilLoopCB)(RzAnalEsil *esil, RzAnalOp *op);
typedef int (*RzAnalEsilTrapCB)(RzAnalEsil *esil, int trap_type, int trap_code);

typedef struct rz_anal_plugin_t {
	char *name;
	char *desc;
	char *license;
	char *arch;
	char *author;
	char *version;
	int bits;
	int esil; // can do esil or not
	int fileformat_type;
	int (*init)(void *user);
	int (*fini)(void *user);
	//int (*reset_counter) (RzAnal *anal, ut64 start_addr);
	int (*archinfo)(RzAnal *anal, int query);
	ut8* (*anal_mask)(RzAnal *anal, int size, const ut8 *data, ut64 at);
	RzList* (*preludes)(RzAnal *anal);

	// legacy rz_anal_functions
	RzAnalOpCallback op;

	// command extension to directly call any analysis functions
	RzAnalCmdExt cmd_ext;

	RzAnalRegProfCallback set_reg_profile;
	RzAnalRegProfGetCallback get_reg_profile;
	RzAnalFPBBCallback fingerprint_bb;
	RzAnalFPFcnCallback fingerprint_fcn;
	RzAnalDiffBBCallback diff_bb;
	RzAnalDiffFcnCallback diff_fcn;
	RzAnalDiffEvalCallback diff_eval;

	RzAnalEsilCB esil_init; // initialize esil-related stuff
	RzAnalEsilLoopCB esil_post_loop;	//cycle-counting, firing interrupts, ...
	RzAnalEsilTrapCB esil_trap; // traps / exceptions
	RzAnalEsilCB esil_fini; // deinitialize
} RzAnalPlugin;

/*----------------------------------------------------------------------------------------------*/
int * (rz_anal_compare) (RzAnalFunction , RzAnalFunction );
/*----------------------------------------------------------------------------------------------*/

#ifdef RZ_API
/* --------- */ /* REFACTOR */ /* ---------- */
RZ_API RzListRange* rz_listrange_new (void);
RZ_API void rz_listrange_free(RzListRange *s);
RZ_API void rz_listrange_add(RzListRange *s, RzAnalFunction *f);
RZ_API void rz_listrange_del(RzListRange *s, RzAnalFunction *f);
RZ_API void rz_listrange_resize(RzListRange *s, RzAnalFunction *f, int newsize);
RZ_API RzAnalFunction *rz_listrange_find_in_range(RzListRange* s, ut64 addr);
RZ_API RzAnalFunction *rz_listrange_find_root(RzListRange* s, ut64 addr);
/* --------- */ /* REFACTOR */ /* ---------- */
/* type.c */
RZ_API RzAnalType *rz_anal_type_new(void);
RZ_API void rz_anal_type_add(RzAnal *l, RzAnalType *t);
RZ_API RzAnalType *rz_anal_type_find(RzAnal *a, const char* name);
RZ_API void rz_anal_type_list(RzAnal *a, short category, short enabled);
RZ_API const char *rz_anal_datatype_to_string(RzAnalDataType t);
RZ_API RzAnalType *rz_anal_str_to_type(RzAnal *a, const char* s);
RZ_API bool rz_anal_op_nonlinear(int t);
RZ_API bool rz_anal_op_ismemref(int t);
RZ_API const char *rz_anal_optype_to_string(int t);
RZ_API int rz_anal_optype_from_string(const char *type);
RZ_API const char *rz_anal_op_family_to_string (int n);
RZ_API int rz_anal_op_family_from_string(const char *f);
RZ_API int rz_anal_op_hint(RzAnalOp *op, RzAnalHint *hint);
RZ_API RzAnalType *rz_anal_type_free(RzAnalType *t);
RZ_API RzAnalType *rz_anal_type_loadfile(RzAnal *a, const char *path);

/* block.c */
typedef bool (*RzAnalBlockCb)(RzAnalBlock *block, void *user);
typedef bool (*RzAnalAddrCb)(ut64 addr, void *user);

// lifetime
RZ_API void rz_anal_block_ref(RzAnalBlock *bb);
RZ_API void rz_anal_block_unref(RzAnalBlock *bb);

// Create one block covering the given range.
// This will fail if the range overlaps any existing blocks.
RZ_API RzAnalBlock *rz_anal_create_block(RzAnal *anal, ut64 addr, ut64 size);

static inline bool rz_anal_block_contains(RzAnalBlock *bb, ut64 addr) {
	return addr >= bb->addr && addr < bb->addr + bb->size;
}

// Split the block at the given address into two blocks.
// bb will stay the first block, the second block will be returned (or NULL on failure)
// The returned block will always be refd, i.e. it is necessary to always call rz_anal_block_unref() on the return value!
RZ_API RzAnalBlock *rz_anal_block_split(RzAnalBlock *bb, ut64 addr);

static inline bool rz_anal_block_is_contiguous(RzAnalBlock *a, RzAnalBlock *b) {
	return (a->addr + a->size) == b->addr;
}

// Merge block b into a.
// b will be FREED (not just unrefd) and is NOT VALID anymore if this function is successful!
// This only works if b follows directly after a and their function lists are identical.
// returns true iff the blocks could be merged
RZ_API bool rz_anal_block_merge(RzAnalBlock *a, RzAnalBlock *b);

// Manually delete a block and remove it from all its functions
// If there are more references to it than from its functions only, it will not be removed immediately!
RZ_API void rz_anal_delete_block(RzAnalBlock *bb);

RZ_API void rz_anal_block_set_size(RzAnalBlock *block, ut64 size);

// Set the address and size of the block.
// This can fail (and return false) if there is already another block at the new address
RZ_API bool rz_anal_block_relocate(RzAnalBlock *block, ut64 addr, ut64 size);

RZ_API RzAnalBlock *rz_anal_get_block_at(RzAnal *anal, ut64 addr);
RZ_API bool rz_anal_blocks_foreach_in(RzAnal *anal, ut64 addr, RzAnalBlockCb cb, void *user);
RZ_API RzList *rz_anal_get_blocks_in(RzAnal *anal, ut64 addr); // values from rz_anal_blocks_foreach_in as a list
RZ_API void rz_anal_blocks_foreach_intersect(RzAnal *anal, ut64 addr, ut64 size, RzAnalBlockCb cb, void *user);
RZ_API RzList *rz_anal_get_blocks_intersect(RzAnal *anal, ut64 addr, ut64 size); // values from rz_anal_blocks_foreach_intersect as a list

// Call cb on every direct successor address of block
// returns false if the loop was breaked by cb
RZ_API bool rz_anal_block_successor_addrs_foreach(RzAnalBlock *block, RzAnalAddrCb cb, void *user);

// Call cb on block and every (recursive) successor of it
// returns false if the loop was breaked by cb
RZ_API bool rz_anal_block_recurse(RzAnalBlock *block, RzAnalBlockCb cb, void *user);

// Call cb on block and every (recursive) successor of it
// If cb returns false, recursion stops only for that block
// returns false if the loop was breaked by cb
RZ_API bool rz_anal_block_recurse_followthrough(RzAnalBlock *block, RzAnalBlockCb cb, void *user);

// Call cb on block and every (recursive) successor of it
// Call on_exit on block that doesn't have non-visited successors
// returns false if the loop was breaked by cb
RZ_API bool rz_anal_block_recurse_depth_first(RzAnalBlock *block, RzAnalBlockCb cb, RZ_NULLABLE RzAnalBlockCb on_exit, void *user);

// same as rz_anal_block_recurse, but returns the blocks as a list
RZ_API RzList *rz_anal_block_recurse_list(RzAnalBlock *block);

// return one shortest path from block to dst or NULL if none exists.
RZ_API RZ_NULLABLE RzList/*<RzAnalBlock *>*/ *rz_anal_block_shortest_path(RzAnalBlock *block, ut64 dst);

// Add a case to the block's switch_op.
// If block->switch_op is NULL, it will be created with the given switch_addr.
RZ_API void rz_anal_block_add_switch_case(RzAnalBlock *block, ut64 switch_addr, ut64 case_value, ut64 case_addr);

// Chop off the block at the specified address and remove all destinations.
// Blocks that have become unreachable after this operation will be automatically removed from all functions of block.
// addr must be the address directly AFTER the noreturn call!
// After the chopping, an rz_anal_block_automerge() is performed on the touched blocks.
// IMPORTANT: The automerge might also FREE block! This function returns block iff it is still valid afterwards.
// If this function returns NULL, the pointer to block MUST not be touched anymore!
RZ_API RzAnalBlock *rz_anal_block_chop_noreturn(RzAnalBlock *block, ut64 addr);

// Merge every block in blocks with their contiguous predecessor, if possible.
// IMPORTANT: Merged blocks will be FREED! The blocks list will be updated to contain only the survived blocks.
RZ_API void rz_anal_block_automerge(RzList *blocks);

// return true iff an instruction in the given basic block starts at the given address
RZ_API bool rz_anal_block_op_starts_at(RzAnalBlock *block, ut64 addr);

// ---------------------------------------

/* function.c */

RZ_API RzAnalFunction *rz_anal_function_new(RzAnal *anal);
RZ_API void rz_anal_function_free(void *fcn);

// Add a function created with rz_anal_function_new() to anal
RZ_API bool rz_anal_add_function(RzAnal *anal, RzAnalFunction *fcn);

// Create a new function and add it to anal (rz_anal_function_new() + set members + rz_anal_add_function())
RZ_API RzAnalFunction *rz_anal_create_function(RzAnal *anal, const char *name, ut64 addr, int type, RzAnalDiff *diff);

// returns all functions that have a basic block containing the given address
RZ_API RzList *rz_anal_get_functions_in(RzAnal *anal, ut64 addr);

// returns the function that has its entrypoint at addr or NULL
RZ_API RzAnalFunction *rz_anal_get_function_at(RzAnal *anal, ut64 addr);

RZ_API bool rz_anal_function_delete(RzAnalFunction *fcn);

// rhange the entrypoint of fcn
// This can fail (and return false) if there is already another function at the new address
RZ_API bool rz_anal_function_relocate(RzAnalFunction *fcn, ut64 addr);

// rename the given function
// This can fail (and return false) if there is another function with the name given
RZ_API bool rz_anal_function_rename(RzAnalFunction *fcn, const char *name);

RZ_API void rz_anal_function_add_block(RzAnalFunction *fcn, RzAnalBlock *bb);
RZ_API void rz_anal_function_remove_block(RzAnalFunction *fcn, RzAnalBlock *bb);


// size of the entire range that the function spans, including holes.
// this is exactly rz_anal_function_max_addr() - rz_anal_function_min_addr()
RZ_API ut64 rz_anal_function_linear_size(RzAnalFunction *fcn);

// lowest address covered by the function
RZ_API ut64 rz_anal_function_min_addr(RzAnalFunction *fcn);

// first address directly after the function
RZ_API ut64 rz_anal_function_max_addr(RzAnalFunction *fcn);

// size from the function entrypoint (fcn->addr) to the end of the function (rz_anal_function_max_addr)
RZ_API ut64 rz_anal_function_size_from_entry(RzAnalFunction *fcn);

// the "real" size of the function, that is the sum of the size of the
// basicblocks this function is composed of
RZ_API ut64 rz_anal_function_realsize(const RzAnalFunction *fcn);

// returns whether the function contains a basic block that contains addr
// This is completely independent of fcn->addr, which is only the entrypoint!
RZ_API bool rz_anal_function_contains(RzAnalFunction *fcn, ut64 addr);

/* anal.c */
RZ_API RzAnal *rz_anal_new(void);
RZ_API void rz_anal_purge(RzAnal *anal);
RZ_API RzAnal *rz_anal_free(RzAnal *r);
RZ_API void rz_anal_set_user_ptr(RzAnal *anal, void *user);
RZ_API void rz_anal_plugin_free (RzAnalPlugin *p);
RZ_API int rz_anal_add(RzAnal *anal, RzAnalPlugin *foo);
RZ_API int rz_anal_archinfo(RzAnal *anal, int query);
RZ_API bool rz_anal_use(RzAnal *anal, const char *name);
RZ_API bool rz_anal_set_reg_profile(RzAnal *anal);
RZ_API char *rz_anal_get_reg_profile(RzAnal *anal);
RZ_API ut64 rz_anal_get_bbaddr(RzAnal *anal, ut64 addr);
RZ_API bool rz_anal_set_bits(RzAnal *anal, int bits);
RZ_API bool rz_anal_set_os(RzAnal *anal, const char *os);
RZ_API void rz_anal_set_cpu(RzAnal *anal, const char *cpu);
RZ_API int rz_anal_set_big_endian(RzAnal *anal, int boolean);
RZ_API ut8 *rz_anal_mask(RzAnal *anal, int size, const ut8 *data, ut64 at);
RZ_API void rz_anal_trace_bb(RzAnal *anal, ut64 addr);
RZ_API const char *rz_anal_fcntype_tostring(int type);
RZ_API int rz_anal_fcn_bb (RzAnal *anal, RzAnalFunction *fcn, ut64 addr, int depth);
RZ_API void rz_anal_bind(RzAnal *b, RzAnalBind *bnd);
RZ_API bool rz_anal_set_triplet(RzAnal *anal, const char *os, const char *arch, int bits);
RZ_API void rz_anal_add_import(RzAnal *anal, const char *imp);
RZ_API void rz_anal_remove_import(RzAnal *anal, const char *imp);
RZ_API void rz_anal_purge_imports(RzAnal *anal);

/* bb.c */
RZ_API RzAnalBlock *rz_anal_bb_from_offset(RzAnal *anal, ut64 off);
RZ_API bool rz_anal_bb_set_offset(RzAnalBlock *bb, int i, ut16 v);
RZ_API ut16 rz_anal_bb_offset_inst(RzAnalBlock *bb, int i);
RZ_API ut64 rz_anal_bb_opaddr_i(RzAnalBlock *bb, int i);
RZ_API ut64 rz_anal_bb_opaddr_at(RzAnalBlock *bb, ut64 addr);
RZ_API ut64 rz_anal_bb_size_i(RzAnalBlock *bb, int i);

/* op.c */
RZ_API const char *rz_anal_stackop_tostring(int s);
RZ_API RzAnalOp *rz_anal_op_new(void);
RZ_API void rz_anal_op_free(void *op);
RZ_API void rz_anal_op_init(RzAnalOp *op);
RZ_API bool rz_anal_op_fini(RzAnalOp *op);
RZ_API int rz_anal_op_reg_delta(RzAnal *anal, ut64 addr, const char *name);
RZ_API bool rz_anal_op_is_eob(RzAnalOp *op);
RZ_API RzList *rz_anal_op_list_new(void);
RZ_API int rz_anal_op(RzAnal *anal, RzAnalOp *op, ut64 addr, const ut8 *data, int len, RzAnalOpMask mask);
RZ_API RzAnalOp *rz_anal_op_hexstr(RzAnal *anal, ut64 addr, const char *hexstr);
RZ_API char *rz_anal_op_to_string(RzAnal *anal, RzAnalOp *op);

RZ_API RzAnalEsil *rz_anal_esil_new(int stacksize, int iotrap, unsigned int addrsize);
RZ_API bool rz_anal_esil_set_pc(RzAnalEsil *esil, ut64 addr);
RZ_API bool rz_anal_esil_setup(RzAnalEsil *esil, RzAnal *anal, int romem, int stats, int nonull);
RZ_API void rz_anal_esil_free(RzAnalEsil *esil);
RZ_API bool rz_anal_esil_runword(RzAnalEsil *esil, const char *word);
RZ_API bool rz_anal_esil_parse(RzAnalEsil *esil, const char *str);
RZ_API bool rz_anal_esil_dumpstack(RzAnalEsil *esil);
RZ_API int rz_anal_esil_mem_read(RzAnalEsil *esil, ut64 addr, ut8 *buf, int len);
RZ_API int rz_anal_esil_mem_write(RzAnalEsil *esil, ut64 addr, const ut8 *buf, int len);
RZ_API int rz_anal_esil_reg_read(RzAnalEsil *esil, const char *regname, ut64 *num, int *size);
RZ_API int rz_anal_esil_reg_write(RzAnalEsil *esil, const char *dst, ut64 num);
RZ_API bool rz_anal_esil_pushnum(RzAnalEsil *esil, ut64 num);
RZ_API bool rz_anal_esil_push(RzAnalEsil *esil, const char *str);
RZ_API char *rz_anal_esil_pop(RzAnalEsil *esil);
RZ_API bool rz_anal_esil_set_op(RzAnalEsil *esil, const char *op, RzAnalEsilOpCb code, ut32 push, ut32 pop, ut32 type);
RZ_API void rz_anal_esil_stack_free(RzAnalEsil *esil);
RZ_API int rz_anal_esil_get_parm_type(RzAnalEsil *esil, const char *str);
RZ_API int rz_anal_esil_get_parm(RzAnalEsil *esil, const char *str, ut64 *num);
RZ_API int rz_anal_esil_condition(RzAnalEsil *esil, const char *str);

// esil_interrupt.c
RZ_API void rz_anal_esil_interrupts_init(RzAnalEsil *esil);
RZ_API RzAnalEsilInterrupt *rz_anal_esil_interrupt_new(RzAnalEsil *esil, ut32 src_id, RzAnalEsilInterruptHandler *ih);
RZ_API void rz_anal_esil_interrupt_free(RzAnalEsil *esil, RzAnalEsilInterrupt *intr);
RZ_API bool rz_anal_esil_set_interrupt(RzAnalEsil *esil, RzAnalEsilInterrupt *intr);
RZ_API int rz_anal_esil_fire_interrupt(RzAnalEsil *esil, ut32 intr_num);
RZ_API bool rz_anal_esil_load_interrupts(RzAnalEsil *esil, RzAnalEsilInterruptHandler **handlers, ut32 src_id);
RZ_API bool rz_anal_esil_load_interrupts_from_lib(RzAnalEsil *esil, const char *path);
RZ_API void rz_anal_esil_interrupts_fini(RzAnalEsil *esil);

RZ_API void rz_anal_esil_mem_ro(RzAnalEsil *esil, int mem_readonly);
RZ_API void rz_anal_esil_stats(RzAnalEsil *esil, int enable);

/* trace */
RZ_API RzAnalEsilTrace *rz_anal_esil_trace_new(RzAnalEsil *esil);
RZ_API void rz_anal_esil_trace_free(RzAnalEsilTrace *trace);
RZ_API void rz_anal_esil_trace_op(RzAnalEsil *esil, RzAnalOp *op);
RZ_API void rz_anal_esil_trace_list(RzAnalEsil *esil);
RZ_API void rz_anal_esil_trace_show(RzAnalEsil *esil, int idx);
RZ_API void rz_anal_esil_trace_restore(RzAnalEsil *esil, int idx);

/* pin */
RZ_API void rz_anal_pin_init(RzAnal *a);
RZ_API void rz_anal_pin_fini(RzAnal *a);
RZ_API void rz_anal_pin(RzAnal *a, ut64 addr, const char *name);
RZ_API void rz_anal_pin_unset(RzAnal *a, ut64 addr);
RZ_API const char *rz_anal_pin_call(RzAnal *a, ut64 addr);
RZ_API void rz_anal_pin_list(RzAnal *a);

/* fcn.c */
RZ_API ut32 rz_anal_function_cost(RzAnalFunction *fcn);
RZ_API int rz_anal_function_count_edges(const RzAnalFunction *fcn, RZ_NULLABLE int *ebbs);

// Use rz_anal_get_functions_in¿() instead
RZ_DEPRECATE RZ_API RzAnalFunction *rz_anal_get_fcn_in(RzAnal *anal, ut64 addr, int type);
RZ_DEPRECATE RZ_API RzAnalFunction *rz_anal_get_fcn_in_bounds(RzAnal *anal, ut64 addr, int type);

RZ_API RzAnalFunction *rz_anal_get_function_byname(RzAnal *anal, const char *name);

RZ_API int rz_anal_fcn(RzAnal *anal, RzAnalFunction *fcn, ut64 addr, ut64 len, int reftype);
RZ_API int rz_anal_fcn_del(RzAnal *anal, ut64 addr);
RZ_API int rz_anal_fcn_del_locs(RzAnal *anal, ut64 addr);
RZ_API bool rz_anal_fcn_add_bb(RzAnal *anal, RzAnalFunction *fcn,
		ut64 addr, ut64 size,
		ut64 jump, ut64 fail, RZ_BORROW RzAnalDiff *diff);
RZ_API bool rz_anal_check_fcn(RzAnal *anal, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high);
RZ_API void rz_anal_fcn_invalidate_read_ahead_cache(void);

RZ_API void rz_anal_function_check_bp_use(RzAnalFunction *fcn);


#define RZ_ANAL_FCN_VARKIND_LOCAL 'v'


RZ_API int rz_anal_fcn_var_del_byindex (RzAnal *a, ut64 fna, const char kind, int scope, ut32 idx);
/* args */
RZ_API int rz_anal_var_count(RzAnal *a, RzAnalFunction *fcn, int kind, int type);

/* vars // globals. not here  */
RZ_API bool rz_anal_var_display(RzAnal *anal, RzAnalVar *var);

RZ_API int rz_anal_function_complexity(RzAnalFunction *fcn);
RZ_API int rz_anal_function_loops(RzAnalFunction *fcn);
RZ_API void rz_anal_trim_jmprefs(RzAnal *anal, RzAnalFunction *fcn);
RZ_API void rz_anal_del_jmprefs(RzAnal *anal, RzAnalFunction *fcn);
RZ_API char *rz_anal_function_get_json(RzAnalFunction *function);
RZ_API RzAnalFunction *rz_anal_fcn_next(RzAnal *anal, ut64 addr);
RZ_API char *rz_anal_function_get_signature(RzAnalFunction *function);
RZ_API int rz_anal_str_to_fcn(RzAnal *a, RzAnalFunction *f, const char *_str);
RZ_API int rz_anal_fcn_count (RzAnal *a, ut64 from, ut64 to);
RZ_API RzAnalBlock *rz_anal_fcn_bbget_in(const RzAnal *anal, RzAnalFunction *fcn, ut64 addr);
RZ_API RzAnalBlock *rz_anal_fcn_bbget_at(RzAnal *anal, RzAnalFunction *fcn, ut64 addr);
RZ_API bool rz_anal_fcn_bbadd(RzAnalFunction *fcn, RzAnalBlock *bb);
RZ_API int rz_anal_function_resize(RzAnalFunction *fcn, int newsize);
RZ_API bool rz_anal_function_purity(RzAnalFunction *fcn);

typedef bool (* RzAnalRefCmp)(RzAnalRef *ref, void *data);
RZ_API RzList *rz_anal_ref_list_new(void);
RZ_API ut64 rz_anal_xrefs_count(RzAnal *anal);
RZ_API const char *rz_anal_xrefs_type_tostring(RzAnalRefType type);
RZ_API RzAnalRefType rz_anal_xrefs_type(char ch);
RZ_API RzList *rz_anal_xrefs_get(RzAnal *anal, ut64 to);
RZ_API RzList *rz_anal_refs_get(RzAnal *anal, ut64 to);
RZ_API RzList *rz_anal_xrefs_get_from(RzAnal *anal, ut64 from);
RZ_API void rz_anal_xrefs_list(RzAnal *anal, int rad);
RZ_API RzList *rz_anal_function_get_refs(RzAnalFunction *fcn);
RZ_API RzList *rz_anal_function_get_xrefs(RzAnalFunction *fcn);
RZ_API int rz_anal_xrefs_from(RzAnal *anal, RzList *list, const char *kind, const RzAnalRefType type, ut64 addr);
RZ_API int rz_anal_xrefs_set(RzAnal *anal, ut64 from, ut64 to, const RzAnalRefType type);
RZ_API int rz_anal_xrefs_deln(RzAnal *anal, ut64 from, ut64 to, const RzAnalRefType type);
RZ_API int rz_anal_xref_del(RzAnal *anal, ut64 at, ut64 addr);

RZ_API RzList *rz_anal_get_fcns(RzAnal *anal);

/* type.c */
RZ_API void rz_anal_remove_parsed_type(RzAnal *anal, const char *name);
RZ_API void rz_anal_save_parsed_type(RzAnal *anal, const char *parsed);

/* var.c */
RZ_API RZ_OWN char *rz_anal_function_autoname_var(RzAnalFunction *fcn, char kind, const char *pfx, int ptr);
RZ_API RZ_BORROW RzAnalVar *rz_anal_function_set_var(RzAnalFunction *fcn, int delta, char kind, RZ_NULLABLE const char *type, int size, bool isarg, RZ_NONNULL const char *name);
RZ_API RZ_BORROW RzAnalVar *rz_anal_function_get_var(RzAnalFunction *fcn, char kind, int delta);
RZ_API RZ_BORROW RzAnalVar *rz_anal_function_get_var_byname(RzAnalFunction *fcn, const char *name);
RZ_API void rz_anal_function_delete_vars_by_kind(RzAnalFunction *fcn, RzAnalVarKind kind);
RZ_API void rz_anal_function_delete_all_vars(RzAnalFunction *fcn);
RZ_API void rz_anal_function_delete_var(RzAnalFunction *fcn, RzAnalVar *var);
RZ_API bool rz_anal_function_rebase_vars(RzAnal *a, RzAnalFunction *fcn);
RZ_API st64 rz_anal_function_get_var_stackptr_at(RzAnalFunction *fcn, st64 delta, ut64 addr);
RZ_API const char *rz_anal_function_get_var_reg_at(RzAnalFunction *fcn, st64 delta, ut64 addr);
RZ_API RZ_BORROW RzPVector *rz_anal_function_get_vars_used_at(RzAnalFunction *fcn, ut64 op_addr);

// There could be multiple vars used in multiple functions. Use rz_anal_get_functions_in()+rz_anal_function_get_vars_used_at() instead.
RZ_API RZ_DEPRECATE RzAnalVar *rz_anal_get_used_function_var(RzAnal *anal, ut64 addr);

RZ_API bool rz_anal_var_rename(RzAnalVar *var, const char *new_name, bool verbose);
RZ_API void rz_anal_var_set_type(RzAnalVar *var, const char *type);
RZ_API void rz_anal_var_delete(RzAnalVar *var);
RZ_API ut64 rz_anal_var_addr(RzAnalVar *var);
RZ_API void rz_anal_var_set_access(RzAnalVar *var, const char *reg, ut64 access_addr, int access_type, st64 stackptr);
RZ_API void rz_anal_var_remove_access_at(RzAnalVar *var, ut64 address);
RZ_API void rz_anal_var_clear_accesses(RzAnalVar *var);
RZ_API void rz_anal_var_add_constraint(RzAnalVar *var, RZ_BORROW RzAnalVarConstraint *constraint);
RZ_API char *rz_anal_var_get_constraints_readable(RzAnalVar *var);

// Get the access to var at exactly addr if there is one
RZ_API RzAnalVarAccess *rz_anal_var_get_access_at(RzAnalVar *var, ut64 addr);

RZ_API int rz_anal_var_get_argnum(RzAnalVar *var);

RZ_API void rz_anal_extract_vars(RzAnal *anal, RzAnalFunction *fcn, RzAnalOp *op);
RZ_API void rz_anal_extract_rarg(RzAnal *anal, RzAnalOp *op, RzAnalFunction *fcn, int *reg_set, int *count);

// Get the variable that var is written to at one of its accesses
// Useful for cases where a register-based argument is written away into a stack variable,
// so if var is the reg arg then this will return the stack var.
RZ_API RzAnalVar *rz_anal_var_get_dst_var(RzAnalVar *var);

typedef struct rz_anal_fcn_vars_cache {
	RzList *bvars;
	RzList *rvars;
	RzList *svars;
} RzAnalFcnVarsCache;
RZ_API void rz_anal_fcn_vars_cache_init(RzAnal *anal, RzAnalFcnVarsCache *cache, RzAnalFunction *fcn);
RZ_API void rz_anal_fcn_vars_cache_fini(RzAnalFcnVarsCache *cache);

RZ_API char *rz_anal_fcn_format_sig(RZ_NONNULL RzAnal *anal, RZ_NONNULL RzAnalFunction *fcn, RZ_NULLABLE char *fcn_name,
		RZ_NULLABLE RzAnalFcnVarsCache *reuse_cache, RZ_NULLABLE const char *fcn_name_pre, RZ_NULLABLE const char *fcn_name_post);


/* project */
RZ_API bool rz_anal_xrefs_init (RzAnal *anal);

#define RZ_ANAL_THRESHOLDFCN 0.7F
#define RZ_ANAL_THRESHOLDBB 0.7F

/* diff.c */
RZ_API RzAnalDiff *rz_anal_diff_new(void);
RZ_API void rz_anal_diff_setup(RzAnal *anal, int doops, double thbb, double thfcn);
RZ_API void rz_anal_diff_setup_i(RzAnal *anal, int doops, int thbb, int thfcn);
RZ_API void* rz_anal_diff_free(RzAnalDiff *diff);
RZ_API int rz_anal_diff_fingerprint_bb(RzAnal *anal, RzAnalBlock *bb);
RZ_API size_t rz_anal_diff_fingerprint_fcn(RzAnal *anal, RzAnalFunction *fcn);
RZ_API bool rz_anal_diff_bb(RzAnal *anal, RzAnalFunction *fcn, RzAnalFunction *fcn2);
RZ_API int rz_anal_diff_fcn(RzAnal *anal, RzList *fcns, RzList *fcns2);
RZ_API int rz_anal_diff_eval(RzAnal *anal);

/* value.c */
RZ_API RzAnalValue *rz_anal_value_new(void);
RZ_API RzAnalValue *rz_anal_value_copy (RzAnalValue *ov);
RZ_API RzAnalValue *rz_anal_value_new_from_string(const char *str);
RZ_API st64 rz_anal_value_eval(RzAnalValue *value);
RZ_API char *rz_anal_value_to_string (RzAnalValue *value);
RZ_API ut64 rz_anal_value_to_ut64(RzAnal *anal, RzAnalValue *val);
RZ_API int rz_anal_value_set_ut64(RzAnal *anal, RzAnalValue *val, ut64 num);
RZ_API void rz_anal_value_free(RzAnalValue *value);

RZ_API RzAnalCond *rz_anal_cond_new(void);
RZ_API RzAnalCond *rz_anal_cond_new_from_op(RzAnalOp *op);
RZ_API void rz_anal_cond_fini(RzAnalCond *c);
RZ_API void rz_anal_cond_free(RzAnalCond *c);
RZ_API char *rz_anal_cond_to_string(RzAnalCond *cond);
RZ_API int rz_anal_cond_eval(RzAnal *anal, RzAnalCond *cond);
RZ_API RzAnalCond *rz_anal_cond_new_from_string(const char *str);
RZ_API const char *rz_anal_cond_tostring(int cc);

/* jmptbl */
RZ_API bool rz_anal_jmptbl(RzAnal *anal, RzAnalFunction *fcn, RzAnalBlock *block, ut64 jmpaddr, ut64 table, ut64 tablesize, ut64 default_addr);

// TODO: should be renamed
RZ_API bool try_get_delta_jmptbl_info(RzAnal *anal, RzAnalFunction *fcn, ut64 jmp_addr, ut64 lea_addr, ut64 *table_size, ut64 *default_case);
RZ_API bool try_walkthrough_jmptbl(RzAnal *anal, RzAnalFunction *fcn, RzAnalBlock *block, int depth, ut64 ip, ut64 jmptbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0);
RZ_API bool try_walkthrough_casetbl(RzAnal *anal, RzAnalFunction *fcn, RzAnalBlock *block, int depth, ut64 ip, ut64 jmptbl_loc, ut64 casetbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0);
RZ_API bool try_get_jmptbl_info(RzAnal *anal, RzAnalFunction *fcn, ut64 addr, RzAnalBlock *my_bb, ut64 *table_size, ut64 *default_case);
RZ_API int walkthrough_arm_jmptbl_style(RzAnal *anal, RzAnalFunction *fcn, RzAnalBlock *block, int depth, ut64 ip, ut64 jmptbl_loc, ut64 sz, ut64 jmptbl_size, ut64 default_case, int ret0);

/* reflines.c */
RZ_API RzList* /*<RzAnalRefline>*/ rz_anal_reflines_get(RzAnal *anal,
		ut64 addr, const ut8 *buf, ut64 len, int nlines, int linesout, int linescall);
RZ_API int rz_anal_reflines_middle(RzAnal *anal, RzList *list, ut64 addr, int len);
RZ_API RzAnalRefStr *rz_anal_reflines_str(void *core, ut64 addr, int opts);
RZ_API void rz_anal_reflines_str_free(RzAnalRefStr *refstr);
/* TODO move to rz_core */
RZ_API void rz_anal_var_list_show(RzAnal *anal, RzAnalFunction *fcn, int kind, int mode, PJ* pj);
RZ_API RzList *rz_anal_var_list(RzAnal *anal, RzAnalFunction *fcn, int kind);
RZ_API RZ_DEPRECATE RzList/*<RzAnalVar *>*/ *rz_anal_var_all_list(RzAnal *anal, RzAnalFunction *fcn);
RZ_API RZ_DEPRECATE RzList/*<RzAnalVarField *>*/ *rz_anal_function_get_var_fields(RzAnalFunction *fcn, int kind);

// calling conventions API
RZ_API bool rz_anal_cc_exist(RzAnal *anal, const char *convention);
RZ_API void rz_anal_cc_del(RzAnal *anal, const char *name);
RZ_API bool rz_anal_cc_set(RzAnal *anal, const char *expr);
RZ_API char *rz_anal_cc_get(RzAnal *anal, const char *name);
RZ_API const char *rz_anal_cc_arg(RzAnal *anal, const char *convention, int n);
RZ_API const char *rz_anal_cc_self(RzAnal *anal, const char *convention);
RZ_API void rz_anal_cc_set_self(RzAnal *anal, const char *convention, const char *self);
RZ_API const char *rz_anal_cc_error(RzAnal *anal, const char *convention);
RZ_API void rz_anal_cc_set_error(RzAnal *anal, const char *convention, const char *error);
RZ_API int rz_anal_cc_max_arg(RzAnal *anal, const char *cc);
RZ_API const char *rz_anal_cc_ret(RzAnal *anal, const char *convention);
RZ_API const char *rz_anal_cc_default(RzAnal *anal);
RZ_API const char *rz_anal_cc_func(RzAnal *anal, const char *func_name);
RZ_API bool rz_anal_noreturn_at(RzAnal *anal, ut64 addr);

typedef struct rz_anal_data_t {
	ut64 addr;
	int type;
	ut64 ptr;
	char *str;
	int len;
	ut8 *buf;
	ut8 sbuf[8];
} RzAnalData;

RZ_API RzAnalData *rz_anal_data (RzAnal *anal, ut64 addr, const ut8 *buf, int size, int wordsize);
RZ_API const char *rz_anal_data_kind (RzAnal *anal, ut64 addr, const ut8 *buf, int len);
RZ_API RzAnalData *rz_anal_data_new_string (ut64 addr, const char *p, int size, int wide);
RZ_API RzAnalData *rz_anal_data_new (ut64 addr, int type, ut64 n, const ut8 *buf, int len);
RZ_API void rz_anal_data_free (RzAnalData *d);
#include <rz_cons.h>
RZ_API char *rz_anal_data_to_string(RzAnalData *d, RzConsPrintablePalette *pal);

/* meta
 *
 * Meta uses Condret's Klemmbaustein Priciple, i.e. intervals are defined inclusive/inclusive.
 * A meta item from 0x42 to 0x42 has a size of 1. Items with size 0 do not exist.
 * Meta items are allowed to overlap and the internal data structure allows for multiple meta items
 * starting at the same address.
 * Meta items are saved in an RIntervalTree. To access the interval of an item, use the members of RIntervalNode.
 */

static inline ut64 rz_meta_item_size(ut64 start, ut64 end) {
	// meta items use inclusive/inclusive intervals
	return end - start + 1;
}

static inline ut64 rz_meta_node_size(RIntervalNode *node) {
	return rz_meta_item_size (node->start, node->end);
}

// Set a meta item at addr with the given contents in the current space.
// If there already exists an item with this type and space at addr (regardless of its size) it will be overwritten.
RZ_API bool rz_meta_set(RzAnal *a, RzAnalMetaType type, ut64 addr, ut64 size, const char *str);

// Same as rz_meta_set() but also sets the subtype.
RZ_API bool rz_meta_set_with_subtype(RzAnal *m, RzAnalMetaType type, int subtype, ut64 addr, ut64 size, const char *str);

// Delete all meta items in the current space that intersect with the given interval.
// If size == UT64_MAX, everything in the current space will be deleted.
RZ_API void rz_meta_del(RzAnal *a, RzAnalMetaType type, ut64 addr, ut64 size);

// Same as rz_meta_set() with a size of 1.
RZ_API bool rz_meta_set_string(RzAnal *a, RzAnalMetaType type, ut64 addr, const char *s);

// Convenience function to get the str content of the item at addr with given type in the current space.
RZ_API const char *rz_meta_get_string(RzAnal *a, RzAnalMetaType type, ut64 addr);

// Convenience function to add an RZ_META_TYPE_DATA item at the given addr in the current space.
RZ_API void rz_meta_set_data_at(RzAnal *a, ut64 addr, ut64 wordsz);

// Returns the item with given type that starts at addr in the current space or NULL. The size of this item  optionally returned through size.
RZ_API RzAnalMetaItem *rz_meta_get_at(RzAnal *a, ut64 addr, RzAnalMetaType type, RZ_OUT RZ_NULLABLE ut64 *size);

// Returns the node for one meta item with the given type that contains addr in the current space or NULL.
// To get all the nodes, use rz_meta_get_all_in().
RZ_API RIntervalNode *rz_meta_get_in(RzAnal *a, ut64 addr, RzAnalMetaType type);

// Returns all nodes for items starting at the given address in the current space.
RZ_API RzPVector/*<RIntervalNode<RMetaItem> *>*/ *rz_meta_get_all_at(RzAnal *a, ut64 at);

// Returns all nodes for items with the given type containing the given address in the current space.
RZ_API RzPVector/*<RIntervalNode<RMetaItem> *>*/ *rz_meta_get_all_in(RzAnal *a, ut64 at, RzAnalMetaType type);

// Returns all nodes for items with the given type intersecting the given interval in the current space.
RZ_API RzPVector/*<RIntervalNode<RMetaItem> *>*/ *rz_meta_get_all_intersect(RzAnal *a, ut64 start, ut64 size, RzAnalMetaType type);

// Delete all meta items in the given space
RZ_API void rz_meta_space_unset_for(RzAnal *a, const RSpace *space);

// Returns the number of meta items in the given space
RZ_API int rz_meta_space_count_for(RzAnal *a, const RSpace *space);

// Shift all meta items by the given delta, for rebasing between different memory layouts.
RZ_API void rz_meta_rebase(RzAnal *anal, ut64 diff);

// Calculate the total size covered by meta items of the given type.
RZ_API ut64 rz_meta_get_size(RzAnal *a, RzAnalMetaType type);

RZ_API const char *rz_meta_type_to_string(int type);
RZ_API void rz_meta_print(RzAnal *a, RzAnalMetaItem *d, ut64 start, ut64 size, int rad, PJ *pj, bool show_full);
RZ_API void rz_meta_print_list_all(RzAnal *a, int type, int rad);
RZ_API void rz_meta_print_list_at(RzAnal *a, ut64 addr, int rad);
RZ_API void rz_meta_print_list_in_function(RzAnal *a, int type, int rad, ut64 addr);

/* hints */

RZ_API void rz_anal_hint_del(RzAnal *anal, ut64 addr, ut64 size); // delete all hints that are contained within the given range, if size > 1, this operation is quite heavy!
RZ_API void rz_anal_hint_clear (RzAnal *a);
RZ_API void rz_anal_hint_free (RzAnalHint *h);
RZ_API void rz_anal_hint_set_syntax (RzAnal *a, ut64 addr, const char *syn);
RZ_API void rz_anal_hint_set_type(RzAnal *a, ut64 addr, int type);
RZ_API void rz_anal_hint_set_jump(RzAnal *a, ut64 addr, ut64 jump);
RZ_API void rz_anal_hint_set_fail(RzAnal *a, ut64 addr, ut64 fail);
RZ_API void rz_anal_hint_set_newbits(RzAnal *a, ut64 addr, int bits);
RZ_API void rz_anal_hint_set_nword(RzAnal *a, ut64 addr, int nword);
RZ_API void rz_anal_hint_set_offset(RzAnal *a, ut64 addr, const char *typeoff);
RZ_API void rz_anal_hint_set_immbase(RzAnal *a, ut64 addr, int base);
RZ_API void rz_anal_hint_set_size(RzAnal *a, ut64 addr, ut64 size);
RZ_API void rz_anal_hint_set_opcode(RzAnal *a, ut64 addr, const char *str);
RZ_API void rz_anal_hint_set_esil(RzAnal *a, ut64 addr, const char *str);
RZ_API void rz_anal_hint_set_pointer(RzAnal *a, ut64 addr, ut64 ptr);
RZ_API void rz_anal_hint_set_ret(RzAnal *a, ut64 addr, ut64 val);
RZ_API void rz_anal_hint_set_high(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_set_stackframe(RzAnal *a, ut64 addr, ut64 size);
RZ_API void rz_anal_hint_set_val(RzAnal *a, ut64 addr, ut64 v);
RZ_API void rz_anal_hint_set_arch(RzAnal *a, ut64 addr, RZ_NULLABLE const char *arch); // arch == NULL => use global default
RZ_API void rz_anal_hint_set_bits(RzAnal *a, ut64 addr, int bits); // bits == NULL => use global default
RZ_API void rz_anal_hint_unset_val (RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_high(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_immbase(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_nword(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_size(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_type(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_esil(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_opcode(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_syntax(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_pointer(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_ret(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_offset(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_jump(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_fail(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_newbits(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_stackframe(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_arch(RzAnal *a, ut64 addr);
RZ_API void rz_anal_hint_unset_bits(RzAnal *a, ut64 addr);
RZ_API RZ_NULLABLE const RzVector/*<const RzAnalAddrHintRecord>*/ *rz_anal_addr_hints_at(RzAnal *anal, ut64 addr);
typedef bool (*RzAnalAddrHintRecordsCb)(ut64 addr, const RzVector/*<const RzAnalAddrHintRecord>*/ *records, void *user);
RZ_API void rz_anal_addr_hints_foreach(RzAnal *anal, RzAnalAddrHintRecordsCb cb, void *user);
typedef bool (*RzAnalArchHintCb)(ut64 addr, RZ_NULLABLE const char *arch, void *user);
RZ_API void rz_anal_arch_hints_foreach(RzAnal *anal, RzAnalArchHintCb cb, void *user);
typedef bool (*RzAnalBitsHintCb)(ut64 addr, int bits, void *user);
RZ_API void rz_anal_bits_hints_foreach(RzAnal *anal, RzAnalBitsHintCb cb, void *user);

// get the hint-specified arch value to be considered at addr
// hint_addr will optionally be set to the address where the hint that specifies this arch is placed or UT64_MAX
// if there is no hint affecting addr.
RZ_API RZ_NULLABLE RZ_BORROW const char *rz_anal_hint_arch_at(RzAnal *anal, ut64 addr, RZ_NULLABLE ut64 *hint_addr);

// get the hint-specified bits value to be considered at addr
// hint_addr will optionally be set to the address where the hint that specifies this arch is placed or UT64_MAX
// if there is no hint affecting addr.
RZ_API int rz_anal_hint_bits_at(RzAnal *anal, ut64 addr, RZ_NULLABLE ut64 *hint_addr);

RZ_API RzAnalHint *rz_anal_hint_get(RzAnal *anal, ut64 addr); // accumulate all available hints affecting the given address

/* switch.c APIs */
RZ_API RzAnalSwitchOp *rz_anal_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val, ut64 def_val);
RZ_API void rz_anal_switch_op_free(RzAnalSwitchOp * swop);
RZ_API RzAnalCaseOp* rz_anal_switch_op_add_case(RzAnalSwitchOp * swop, ut64 addr, ut64 value, ut64 jump);

/* cycles.c */
RZ_API RzAnalCycleFrame* rz_anal_cycle_frame_new (void);
RZ_API void rz_anal_cycle_frame_free (RzAnalCycleFrame *cf);

/* labels */
RZ_API ut64 rz_anal_function_get_label(RzAnalFunction *fcn, const char *name);
RZ_API const char *rz_anal_function_get_label_at(RzAnalFunction *fcn, ut64 addr);
RZ_API bool rz_anal_function_set_label(RzAnalFunction *fcn, const char *name, ut64 addr);
RZ_API bool rz_anal_function_delete_label(RzAnalFunction *fcn, const char *name);
RZ_API bool rz_anal_function_delete_label_at(RzAnalFunction *fcn, ut64 addr);

/* limits */
RZ_API void rz_anal_set_limits(RzAnal *anal, ut64 from, ut64 to);
RZ_API void rz_anal_unset_limits(RzAnal *anal);

/* ESIL to REIL */
RZ_API int rz_anal_esil_to_reil_setup (RzAnalEsil *esil, RzAnal *anal, int romem, int stats);

/* no-return stuff */
RZ_API void rz_anal_noreturn_list(RzAnal *anal, int mode);
RZ_API bool rz_anal_noreturn_add(RzAnal *anal, const char *name, ut64 addr);
RZ_API bool rz_anal_noreturn_drop(RzAnal *anal, const char *expr);
RZ_API bool rz_anal_noreturn_at_addr(RzAnal *anal, ut64 addr);

/* zign spaces */
RZ_API int rz_sign_space_count_for(RzAnal *a, const RSpace *space);
RZ_API void rz_sign_space_unset_for(RzAnal *a, const RSpace *space);
RZ_API void rz_sign_space_rename_for(RzAnal *a, const RSpace *space, const char *oname, const char *nname);

/* vtables */
typedef struct {
	RzAnal *anal;
	RzAnalCPPABI abi;
	ut8 word_size;
	bool (*read_addr) (RzAnal *anal, ut64 addr, ut64 *buf);
} RVTableContext;

typedef struct vtable_info_t {
	ut64 saddr; //starting address
	RzVector methods;
} RVTableInfo;

typedef struct vtable_method_info_t {
	ut64 addr;           // addr of the function
	ut64 vtable_offset;  // offset inside the vtable
} RVTableMethodInfo;

RZ_API void rz_anal_vtable_info_free(RVTableInfo *vtable);
RZ_API ut64 rz_anal_vtable_info_get_size(RVTableContext *context, RVTableInfo *vtable);
RZ_API bool rz_anal_vtable_begin(RzAnal *anal, RVTableContext *context);
RZ_API RVTableInfo *rz_anal_vtable_parse_at(RVTableContext *context, ut64 addr);
RZ_API RzList *rz_anal_vtable_search(RVTableContext *context);
RZ_API void rz_anal_list_vtables(RzAnal *anal, int rad);

/* rtti */
RZ_API char *rz_anal_rtti_msvc_demangle_class_name(RVTableContext *context, const char *name);
RZ_API void rz_anal_rtti_msvc_print_complete_object_locator(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_anal_rtti_msvc_print_type_descriptor(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_anal_rtti_msvc_print_class_hierarchy_descriptor(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_anal_rtti_msvc_print_base_class_descriptor(RVTableContext *context, ut64 addr, int mode);
RZ_API bool rz_anal_rtti_msvc_print_at_vtable(RVTableContext *context, ut64 addr, int mode, bool strict);
RZ_API void rz_anal_rtti_msvc_recover_all(RVTableContext *vt_context, RzList *vtables);

RZ_API char *rz_anal_rtti_itanium_demangle_class_name(RVTableContext *context, const char *name);
RZ_API void rz_anal_rtti_itanium_print_class_type_info(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_anal_rtti_itanium_print_si_class_type_info(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_anal_rtti_itanium_print_vmi_class_type_info(RVTableContext *context, ut64 addr, int mode);
RZ_API bool rz_anal_rtti_itanium_print_at_vtable(RVTableContext *context, ut64 addr, int mode);
RZ_API void rz_anal_rtti_itanium_recover_all(RVTableContext *vt_context, RzList *vtables);

RZ_API char *rz_anal_rtti_demangle_class_name(RzAnal *anal, const char *name);
RZ_API void rz_anal_rtti_print_at_vtable(RzAnal *anal, ut64 addr, int mode);
RZ_API void rz_anal_rtti_print_all(RzAnal *anal, int mode);
RZ_API void rz_anal_rtti_recover_all(RzAnal *anal);

RZ_API void rz_anal_colorize_bb(RzAnal *anal, ut64 addr, ut32 color);

RZ_API RzList *rz_anal_preludes(RzAnal *anal);
RZ_API bool rz_anal_is_prelude(RzAnal *anal, const ut8 *data, int len);

/* classes */
typedef struct rz_anal_method_t {
	char *name;
	ut64 addr;
	st64 vtable_offset; // >= 0 if method is virtual, else -1
} RzAnalMethod;

typedef struct rz_anal_base_class_t {
	char *id; // id to identify the class attr
	ut64 offset; // offset of the base class inside the derived class
	char *class_name;
} RzAnalBaseClass;

typedef struct rz_anal_vtable_t {
	char *id; // id to identify the class attr
	ut64 offset; // offset inside the class
	ut64 addr; // where the content of the vtable is
	ut64 size; // size (in bytes) of the vtable
} RzAnalVTable;

typedef enum {
	RZ_ANAL_CLASS_ERR_SUCCESS = 0,
	RZ_ANAL_CLASS_ERR_CLASH,
	RZ_ANAL_CLASS_ERR_NONEXISTENT_ATTR,
	RZ_ANAL_CLASS_ERR_NONEXISTENT_CLASS,
	RZ_ANAL_CLASS_ERR_OTHER
} RzAnalClassErr;

RZ_API void rz_anal_class_create(RzAnal *anal, const char *name);
RZ_API void rz_anal_class_delete(RzAnal *anal, const char *name);
RZ_API bool rz_anal_class_exists(RzAnal *anal, const char *name);
RZ_API SdbList *rz_anal_class_get_all(RzAnal *anal, bool sorted);
RZ_API void rz_anal_class_foreach(RzAnal *anal, SdbForeachCallback cb, void *user);
RZ_API RzAnalClassErr rz_anal_class_rename(RzAnal *anal, const char *old_name, const char *new_name);

RZ_API void rz_anal_class_method_fini(RzAnalMethod *meth);
RZ_API RzAnalClassErr rz_anal_class_method_get(RzAnal *anal, const char *class_name, const char *meth_name, RzAnalMethod *meth);
RZ_API RzVector/*<RzAnalMethod>*/ *rz_anal_class_method_get_all(RzAnal *anal, const char *class_name);
RZ_API RzAnalClassErr rz_anal_class_method_set(RzAnal *anal, const char *class_name, RzAnalMethod *meth);
RZ_API RzAnalClassErr rz_anal_class_method_rename(RzAnal *anal, const char *class_name, const char *old_meth_name, const char *new_meth_name);
RZ_API RzAnalClassErr rz_anal_class_method_delete(RzAnal *anal, const char *class_name, const char *meth_name);

RZ_API void rz_anal_class_base_fini(RzAnalBaseClass *base);
RZ_API RzAnalClassErr rz_anal_class_base_get(RzAnal *anal, const char *class_name, const char *base_id, RzAnalBaseClass *base);
RZ_API RzVector/*<RzAnalBaseClass>*/ *rz_anal_class_base_get_all(RzAnal *anal, const char *class_name);
RZ_API RzAnalClassErr rz_anal_class_base_set(RzAnal *anal, const char *class_name, RzAnalBaseClass *base);
RZ_API RzAnalClassErr rz_anal_class_base_delete(RzAnal *anal, const char *class_name, const char *base_id);

RZ_API void rz_anal_class_vtable_fini(RzAnalVTable *vtable);
RZ_API RzAnalClassErr rz_anal_class_vtable_get(RzAnal *anal, const char *class_name, const char *vtable_id, RzAnalVTable *vtable);
RZ_API RzVector/*<RzAnalVTable>*/ *rz_anal_class_vtable_get_all(RzAnal *anal, const char *class_name);
RZ_API RzAnalClassErr rz_anal_class_vtable_set(RzAnal *anal, const char *class_name, RzAnalVTable *vtable);
RZ_API RzAnalClassErr rz_anal_class_vtable_delete(RzAnal *anal, const char *class_name, const char *vtable_id);

RZ_API void rz_anal_class_print(RzAnal *anal, const char *class_name, bool detailed);
RZ_API void rz_anal_class_json(RzAnal *anal, PJ *j, const char *class_name);
RZ_API void rz_anal_class_list(RzAnal *anal, int mode);
RZ_API void rz_anal_class_list_bases(RzAnal *anal, const char *class_name);
RZ_API void rz_anal_class_list_vtables(RzAnal *anal, const char *class_name);
RZ_API void rz_anal_class_list_vtable_offset_functions(RzAnal *anal, const char *class_name, ut64 offset);
RZ_API RGraph/*<RGraphNodeInfo>*/ *rz_anal_class_get_inheritance_graph(RzAnal *anal);

RZ_API RzAnalEsilCFG *rz_anal_esil_cfg_expr(RzAnalEsilCFG *cfg, RzAnal *anal, const ut64 off, char *expr);
RZ_API RzAnalEsilCFG *rz_anal_esil_cfg_op(RzAnalEsilCFG *cfg, RzAnal *anal, RzAnalOp *op);
RZ_API void rz_anal_esil_cfg_merge_blocks(RzAnalEsilCFG *cfg);
RZ_API void rz_anal_esil_cfg_free(RzAnalEsilCFG *cfg);

RZ_API RzAnalEsilDFGNode *rz_anal_esil_dfg_node_new (RzAnalEsilDFG *edf, const char *c);
RZ_API RzAnalEsilDFG *rz_anal_esil_dfg_new(RzReg *regs);
RZ_API void rz_anal_esil_dfg_free(RzAnalEsilDFG *dfg);
RZ_API RzAnalEsilDFG *rz_anal_esil_dfg_expr(RzAnal *anal, RzAnalEsilDFG *dfg, const char *expr);
RZ_API RStrBuf *rz_anal_esil_dfg_filter(RzAnalEsilDFG *dfg, const char *reg);
RZ_API RStrBuf *rz_anal_esil_dfg_filter_expr(RzAnal *anal, const char *expr, const char *reg);
RZ_API RzList *rz_anal_types_from_fcn(RzAnal *anal, RzAnalFunction *fcn);

RZ_API RzAnalBaseType *rz_anal_get_base_type(RzAnal *anal, const char *name);
RZ_API void rz_parse_pdb_types(const RzAnal *anal, const RPdb *pdb);
RZ_API void rz_anal_save_base_type(const RzAnal *anal, const RzAnalBaseType *type);
RZ_API void rz_anal_base_type_free(RzAnalBaseType *type);
RZ_API RzAnalBaseType *rz_anal_base_type_new(RzAnalBaseTypeKind kind);
RZ_API void rz_anal_dwarf_process_info(const RzAnal *anal, RzAnalDwarfContext *ctx);
RZ_API void rz_anal_dwarf_integrate_functions(RzAnal *anal, RzFlag *flags, Sdb *dwarf_sdb);
/* plugin pointers */
extern RzAnalPlugin rz_anal_plugin_null;
extern RzAnalPlugin rz_anal_plugin_6502;
extern RzAnalPlugin rz_anal_plugin_6502_cs;
extern RzAnalPlugin rz_anal_plugin_8051;
extern RzAnalPlugin rz_anal_plugin_amd29k;
extern RzAnalPlugin rz_anal_plugin_arc;
extern RzAnalPlugin rz_anal_plugin_arm_cs;
extern RzAnalPlugin rz_anal_plugin_arm_gnu;
extern RzAnalPlugin rz_anal_plugin_avr;
extern RzAnalPlugin rz_anal_plugin_bf;
extern RzAnalPlugin rz_anal_plugin_chip8;
extern RzAnalPlugin rz_anal_plugin_cr16;
extern RzAnalPlugin rz_anal_plugin_cris;
extern RzAnalPlugin rz_anal_plugin_dalvik;
extern RzAnalPlugin rz_anal_plugin_ebc;
extern RzAnalPlugin rz_anal_plugin_gb;
extern RzAnalPlugin rz_anal_plugin_h8300;
extern RzAnalPlugin rz_anal_plugin_hexagon;
extern RzAnalPlugin rz_anal_plugin_i4004;
extern RzAnalPlugin rz_anal_plugin_i8080;
extern RzAnalPlugin rz_anal_plugin_java;
extern RzAnalPlugin rz_anal_plugin_m68k_cs;
extern RzAnalPlugin rz_anal_plugin_m680x_cs;
extern RzAnalPlugin rz_anal_plugin_malbolge;
extern RzAnalPlugin rz_anal_plugin_mcore;
extern RzAnalPlugin rz_anal_plugin_mips_cs;
extern RzAnalPlugin rz_anal_plugin_mips_gnu;
extern RzAnalPlugin rz_anal_plugin_msp430;
extern RzAnalPlugin rz_anal_plugin_nios2;
extern RzAnalPlugin rz_anal_plugin_or1k;
extern RzAnalPlugin rz_anal_plugin_pic;
extern RzAnalPlugin rz_anal_plugin_ppc_cs;
extern RzAnalPlugin rz_anal_plugin_ppc_gnu;
extern RzAnalPlugin rz_anal_plugin_propeller;
extern RzAnalPlugin rz_anal_plugin_riscv;
extern RzAnalPlugin rz_anal_plugin_riscv_cs;
extern RzAnalPlugin rz_anal_plugin_rsp;
extern RzAnalPlugin rz_anal_plugin_sh;
extern RzAnalPlugin rz_anal_plugin_snes;
extern RzAnalPlugin rz_anal_plugin_sparc_cs;
extern RzAnalPlugin rz_anal_plugin_sparc_gnu;
extern RzAnalPlugin rz_anal_plugin_sysz;
extern RzAnalPlugin rz_anal_plugin_tms320;
extern RzAnalPlugin rz_anal_plugin_tms320c64x;
extern RzAnalPlugin rz_anal_plugin_tricore;
extern RzAnalPlugin rz_anal_plugin_v810;
extern RzAnalPlugin rz_anal_plugin_v850;
extern RzAnalPlugin rz_anal_plugin_vax;
extern RzAnalPlugin rz_anal_plugin_wasm;
extern RzAnalPlugin rz_anal_plugin_ws;
extern RzAnalPlugin rz_anal_plugin_x86;
extern RzAnalPlugin rz_anal_plugin_x86_cs;
extern RzAnalPlugin rz_anal_plugin_x86_im;
extern RzAnalPlugin rz_anal_plugin_x86_simple;
extern RzAnalPlugin rz_anal_plugin_x86_udis;
extern RzAnalPlugin rz_anal_plugin_xap;
extern RzAnalPlugin rz_anal_plugin_xcore_cs;
extern RzAnalPlugin rz_anal_plugin_xtensa;
extern RzAnalPlugin rz_anal_plugin_z80;
extern RzAnalPlugin rz_anal_plugin_pyc;
#ifdef __cplusplus
}
#endif

#endif
#endif
