#ifndef R2_REG_H
#define R2_REG_H

#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/rz_hex.h>
#include <rz_util/rz_assert.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (rz_reg);

/*
 * various CPUs have registers within various types/classes
 * this enum aims to cover them all.
 */
typedef enum {
	R_REG_TYPE_GPR,
	R_REG_TYPE_DRX,
	R_REG_TYPE_FPU,
	R_REG_TYPE_MMX,
	R_REG_TYPE_XMM,
	R_REG_TYPE_YMM,
	R_REG_TYPE_FLG,
	R_REG_TYPE_SEG,
	R_REG_TYPE_LAST,
	R_REG_TYPE_ALL = -1, // TODO; rename to ANY
} RzRegisterType;

/*
 * pretty much all CPUs share some common registers
 * this enum aims to create an abstraction to ease cross-arch handling.
 */
typedef enum {
	R_REG_NAME_PC, // program counter
	R_REG_NAME_SP, // stack pointer
	R_REG_NAME_SR, // status register
	R_REG_NAME_BP, // base pointer
	R_REG_NAME_LR, // link register
	/* args */
	R_REG_NAME_A0, // arguments
	R_REG_NAME_A1,
	R_REG_NAME_A2,
	R_REG_NAME_A3,
	R_REG_NAME_A4,
	R_REG_NAME_A5,
	R_REG_NAME_A6,
	R_REG_NAME_A7,
	R_REG_NAME_A8,
	R_REG_NAME_A9,
	/* retval */
	R_REG_NAME_R0, // return registers
	R_REG_NAME_R1,
	R_REG_NAME_R2,
	R_REG_NAME_R3,
	/* flags */
	R_REG_NAME_ZF,
	R_REG_NAME_SF,
	R_REG_NAME_CF,
	R_REG_NAME_OF,
	/* syscall number (orig_eax,rax,r0,x0) */
	R_REG_NAME_SN,
	R_REG_NAME_LAST,
} RzRegisterId;

// TODO: use enum here?
#define R_REG_COND_EQ 0
#define R_REG_COND_NE 1
#define R_REG_COND_CF 2
#define R_REG_COND_CARRY 2
#define R_REG_COND_NEG 3
#define R_REG_COND_NEGATIVE 3
#define R_REG_COND_OF 4
#define R_REG_COND_OVERFLOW 4
// unsigned
#define R_REG_COND_HI 5
#define R_REG_COND_HE 6
#define R_REG_COND_LO 7
#define R_REG_COND_LOE 8
// signed
#define R_REG_COND_GE 9
#define R_REG_COND_GT 10
#define R_REG_COND_LT 11
#define R_REG_COND_LE 12
#define R_REG_COND_LAST 13

typedef struct rz_reg_item_t {
	char *name;
	int /*RzRegisterType*/ type;
	int size;	/* 8,16,32,64 ... 128/256 ??? */
	int offset;      /* offset in data structure */
	int packed_size; /* 0 means no packed register, 1byte pack, 2b pack... */
	bool is_float;
	char *flags;
	char *comment;
	int index;
	int arena; /* in which arena is this reg living */
} RzRegItem;

typedef struct rz_reg_arena_t {
	ut8 *bytes;
	int size;
} RzRegArena;

typedef struct rz_reg_set_t {
	RzRegArena *arena;
	RzList *pool;      /* RzRegArena */
	RzList *regs;      /* RzRegItem */
	HtPP *ht_regs;    /* name:RzRegItem */
	RzListIter *cur;
	int maskregstype; /* which type of regs have this reg set (logic mask with RzRegisterType  R_REG_TYPE_XXX) */
} RzRegSet;

typedef struct rz_reg_t {
	char *profile;
	char *reg_profile_cmt;
	char *reg_profile_str;
	char *name[R_REG_NAME_LAST]; // aliases
	RzRegSet regset[R_REG_TYPE_LAST];
	RzList *allregs;
	RzList *roregs;
	int iters;
	int arch;
	int bits;
	int size;
	bool is_thumb;
	bool big_endian;
} RzReg;

typedef struct rz_reg_flags_t {
	bool s; // sign, negative number (msb)
	bool z; // zero
	bool a; // half-carry adjust (if carry happens at nibble level)
	bool c; // carry
	bool o; // overflow
	bool p; // parity (lsb)
} RzRegFlags;

#ifdef RZ_API
RZ_API void rz_reg_free(RzReg *reg);
RZ_API void rz_reg_free_internal(RzReg *reg, bool init);
RZ_API RzReg *rz_reg_new(void);
RZ_API bool rz_reg_set_name(RzReg *reg, int role, const char *name);
RZ_API bool rz_reg_set_profile_string(RzReg *reg, const char *profile);
RZ_API char* rz_reg_profile_to_cc(RzReg *reg);
RZ_API bool rz_reg_set_profile(RzReg *reg, const char *profile);
RZ_API char *rz_reg_parse_gdb_profile(const char *profile);
RZ_API bool rz_reg_is_readonly(RzReg *reg, RzRegItem *item);

RZ_API RzRegSet *rz_reg_regset_get(RzReg *r, int type);
RZ_API ut64 rz_reg_getv(RzReg *reg, const char *name);
RZ_API ut64 rz_reg_setv(RzReg *reg, const char *name, ut64 val);
RZ_API const char *rz_reg_32_to_64(RzReg *reg, const char *rreg32);
RZ_API const char *rz_reg_64_to_32(RzReg *reg, const char *rreg64);
RZ_API const char *rz_reg_get_name_by_type(RzReg *reg, const char *name);
RZ_API const char *rz_reg_get_type(int idx);
RZ_API const char *rz_reg_get_name(RzReg *reg, int kind);
RZ_API const char *rz_reg_get_role(int role);
RZ_API RzRegItem *rz_reg_get(RzReg *reg, const char *name, int type);
RZ_API RzList *rz_reg_get_list(RzReg *reg, int type);
RZ_API RzRegItem *rz_reg_get_at(RzReg *reg, int type, int regsize, int delta);
RZ_API RzRegItem *rz_reg_next_diff(RzReg *reg, int type, const ut8 *buf, int buflen, RzRegItem *prev_ri, int regsize);

RZ_API void rz_reg_reindex(RzReg *reg);
RZ_API RzRegItem *rz_reg_index_get(RzReg *reg, int idx);

/* Item */
RZ_API void rz_reg_item_free(RzRegItem *item);

/* XXX: dupped ?? */
RZ_API int rz_reg_type_by_name(const char *str);
RZ_API int rz_reg_get_name_idx(const char *type);

RZ_API RzRegItem *rz_reg_cond_get(RzReg *reg, const char *name);
RZ_API void rz_reg_cond_apply(RzReg *r, RzRegFlags *f);
RZ_API bool rz_reg_cond_set(RzReg *reg, const char *name, bool val);
RZ_API int rz_reg_cond_get_value(RzReg *r, const char *name);
RZ_API bool rz_reg_cond_bits_set(RzReg *r, int type, RzRegFlags *f, bool v);
RZ_API int rz_reg_cond_bits(RzReg *r, int type, RzRegFlags *f);
RZ_API RzRegFlags *rz_reg_cond_retrieve(RzReg *r, RzRegFlags *);
RZ_API int rz_reg_cond(RzReg *r, int type);

/* integer value 8-64 bits */
RZ_API ut64 rz_reg_get_value(RzReg *reg, RzRegItem *item);
RZ_API ut64 rz_reg_get_value_big(RzReg *reg, RzRegItem *item, utX *val);
RZ_API ut64 rz_reg_get_value_by_role(RzReg *reg, RzRegisterId role);
RZ_API bool rz_reg_set_value(RzReg *reg, RzRegItem *item, ut64 value);
RZ_API bool rz_reg_set_value_by_role(RzReg *reg, RzRegisterId role, ut64 value);

/* float */
RZ_API float rz_reg_get_float(RzReg *reg, RzRegItem *item);
RZ_API bool rz_reg_set_float(RzReg *reg, RzRegItem *item, float value);

/* double */
RZ_API double rz_reg_get_double(RzReg *reg, RzRegItem *item);
RZ_API bool rz_reg_set_double(RzReg *reg, RzRegItem *item, double value);

/* long double */
RZ_API long double rz_reg_get_longdouble(RzReg *reg, RzRegItem *item);
RZ_API bool rz_reg_set_longdouble(RzReg *reg, RzRegItem *item, long double value);

/* boolean */
RZ_API char *rz_reg_get_bvalue(RzReg *reg, RzRegItem *item);
RZ_API ut64 rz_reg_set_bvalue(RzReg *reg, RzRegItem *item, const char *str);

/* packed registers */
RZ_API int rz_reg_set_pack(RzReg *reg, RzRegItem *item, int packidx, int packbits, ut64 val);
RZ_API ut64 rz_reg_get_pack(RzReg *reg, RzRegItem *item, int packidx, int packbits);

/* byte arena */
RZ_API ut8 *rz_reg_get_bytes(RzReg *reg, int type, int *size);
RZ_API bool rz_reg_set_bytes(RzReg *reg, int type, const ut8 *buf, const int len);
RZ_API bool rz_reg_read_regs(RzReg *reg, ut8 *buf, const int len);
RZ_API int rz_reg_arena_set_bytes(RzReg *reg, const char *str);
RZ_API RzRegArena *rz_reg_arena_new(int size);
RZ_API void rz_reg_arena_free(RzRegArena *ra);
RZ_API int rz_reg_fit_arena(RzReg *reg);
RZ_API void rz_reg_arena_swap(RzReg *reg, int copy);
RZ_API int rz_reg_arena_push(RzReg *reg);
RZ_API void rz_reg_arena_pop(RzReg *reg);
RZ_API void rz_reg_arena_zero(RzReg *reg);

RZ_API ut8 *rz_reg_arena_peek(RzReg *reg);
RZ_API void rz_reg_arena_poke(RzReg *reg, const ut8 *buf);
RZ_API ut8 *rz_reg_arena_dup(RzReg *reg, const ut8 *source);
RZ_API const char *rz_reg_cond_to_string(int n);
RZ_API int rz_reg_cond_from_string(const char *str);
RZ_API void rz_reg_arena_shrink(RzReg *reg);

#ifdef __cplusplus
}
#endif

#endif
#endif
