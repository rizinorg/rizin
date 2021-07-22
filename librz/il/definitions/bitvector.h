#ifndef CORE_THEORY_VM_BITVECTOR_H
#define CORE_THEORY_VM_BITVECTOR_H

#include <stdlib.h>
#include <stdio.h>
#include <rz_util.h>
#include <rz_types.h>
#include "common.h"

// can be replace with rizin's defs
#define NELEM(N, ELEMPER) ((N + (ELEMPER)-1) / (ELEMPER))
#define BV_ELEM_SIZE      sizeof(ut8)

/***
 * this enum type will decide
 * the msb/lsb of a bitvector when needed
 */
typedef enum {
	BV_BIG_END, // first bit is the most significant bit (MSB)
	BV_LITTLE_END // first bit is the less significant bit (LSB)
} BV_ENDIAN;

struct bitvector_t {
	ut8 *bits;
	int _elem_len; // length of ut8 array -- real / physical
	int len; // length of bits -- virtual / logical
	BV_ENDIAN endian;
};

typedef struct bitvector_t *BitVector;

/*** ***************************
 * BV related operations and definitions
 * *******************************/
// init
RZ_API BitVector rz_il_bv_new(int length);
RZ_API BitVector rz_il_bv_dump(BitVector bv);
RZ_API BitVector rz_il_bv_concat(BitVector bv1, BitVector bv2);
RZ_API int rz_il_bv_copy(BitVector src, BitVector dst);
RZ_API int rz_il_bv_copy_nbits(
	BitVector src, int src_start_pos,
	BitVector dst, int dst_start_pos,
	int nbit);
RZ_API void rz_il_bv_free(BitVector bv);
// read and write to a bit
RZ_API bool rz_il_bv_set(BitVector bv, int pos, bit b);
RZ_API bool rz_il_bv_set_all(BitVector bv, bit b);
RZ_API bool rz_il_bv_toggle(BitVector bv, int pos);
RZ_API bool rz_il_bv_toggle_all(BitVector bv);
RZ_API BitVector rz_il_bv_append_zero(BitVector bv, int delta_len);
RZ_API BitVector rz_il_bv_prepend_zero(BitVector bv, int delta_len);
RZ_API BitVector rz_il_bv_cut_head(BitVector bv, int delta_len);
RZ_API BitVector rz_il_bv_cut_tail(BitVector bv, int delta_len);
RZ_API bit rz_il_bv_get(BitVector bv, int pos);
// logic operations
RZ_API bool rz_il_bv_lshift(BitVector bv, int size);
RZ_API bool rz_il_bv_rshift(BitVector bv, int size);
RZ_API bool rz_il_bv_lshift_fill(BitVector bv, int size, bool fill_bit);
RZ_API bool rz_il_bv_rshift_fill(BitVector bv, int size, bool fill_bit);
RZ_API BitVector rz_il_bv_and(BitVector x, BitVector y);
RZ_API BitVector rz_il_bv_or(BitVector x, BitVector y);
RZ_API BitVector rz_il_bv_xor(BitVector x, BitVector y);
#define rz_il_bv_neg rz_il_bv_complement_2
#define rz_il_bv_not rz_il_bv_complement_1
RZ_API BitVector rz_il_bv_complement_1(BitVector bv);
RZ_API BitVector rz_il_bv_complement_2(BitVector bv);

// Module 2 arithmetic operations
RZ_API BitVector rz_il_bv_add(BitVector x, BitVector y);
RZ_API BitVector rz_il_bv_sub(BitVector x, BitVector y);
RZ_API BitVector rz_il_bv_mul(BitVector x, BitVector y);
RZ_API BitVector rz_il_bv_div(BitVector x, BitVector y);
RZ_API BitVector rz_il_bv_mod(BitVector x, BitVector y);
RZ_API BitVector rz_il_bv_sdiv(BitVector x, BitVector y);
RZ_API BitVector rz_il_bv_smod(BitVector x, BitVector y);

RZ_API bit rz_il_bv_msb(BitVector bv);
RZ_API bit rz_il_bv_lsb(BitVector bv);
RZ_API bool rz_il_bv_ule(BitVector x, BitVector y);
RZ_API bool rz_il_bv_sle(BitVector x, BitVector y);
// some convert functions
RZ_API ut32 rz_il_bv_to_ut32(BitVector x);
RZ_API ut64 rz_il_bv_to_ut64(BitVector x);
// misc
RZ_API bool rz_il_bv_is_zero_vector(BitVector x);
RZ_API void rz_il_print_bv(BitVector bv);
RZ_API BitVector rz_il_bv_new_from_ut32(int length, ut32 value);
RZ_API BitVector rz_il_bv_new_from_ut64(int length, ut64 value);

RZ_API int rz_il_bv_len(BitVector bv);
RZ_API int rz_il_bv_cmp(BitVector x, BitVector y);
ut32 rz_il_bv_hash(BitVector x);

#endif //CORE_THEORY_VM_BITVECTOR_H
