// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_BITVECTOR_H
#define RZ_IL_BITVECTOR_H

#include <stdlib.h>
#include <stdio.h>
#include <rz_util.h>
#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NELEM(N, ELEMPER) ((N + (ELEMPER)-1) / (ELEMPER))
#define BV_ELEM_SIZE      8U

typedef enum {
	BV_BIG_END, ///< first bit is the most significant bit (MSB)
	BV_LITTLE_END ///< first bit is the less significant bit (LSB)
} BV_ENDIAN;

/**
 *  \struct bitvector_t
 *  \brief structure for bitvector
 *
 *  Ref : https://web.cs.dal.ca/~jamie/UWO/BitVectors/README.html
 */
typedef struct bitvector_t {
	ut8 *bits; ///< bits data
	ut32 _elem_len; ///< length of ut8 array -- real / physical
	ut32 len; ///< length of bits -- virtual / logical
} RzILBitVector;

// init
RZ_API RzILBitVector *rz_il_bv_new(ut32 length);
RZ_API RzILBitVector *rz_il_bv_dup(RzILBitVector *bv);
RZ_API RzILBitVector *rz_il_bv_concat(RzILBitVector *bv1, RzILBitVector *bv2);
RZ_API int rz_il_bv_copy(RzILBitVector *src, RzILBitVector *dst);
RZ_API int rz_il_bv_copy_nbits(
	RzILBitVector *src, ut32 src_start_pos,
	RzILBitVector *dst, ut32 dst_start_pos,
	int nbit);
RZ_API void rz_il_bv_free(RzILBitVector *bv);
// read and write to a bit
RZ_API bool rz_il_bv_set(RzILBitVector *bv, ut32 pos, bool b);
RZ_API bool rz_il_bv_set_all(RzILBitVector *bv, bool b);
RZ_API bool rz_il_bv_toggle(RzILBitVector *bv, ut32 pos);
RZ_API bool rz_il_bv_toggle_all(RzILBitVector *bv);
RZ_API RzILBitVector *rz_il_bv_append_zero(RzILBitVector *bv, ut32 delta_len);
RZ_API RzILBitVector *rz_il_bv_prepend_zero(RzILBitVector *bv, ut32 delta_len);
RZ_API RzILBitVector *rz_il_bv_cut_head(RzILBitVector *bv, ut32 delta_len);
RZ_API RzILBitVector *rz_il_bv_cut_tail(RzILBitVector *bv, ut32 delta_len);
RZ_API bool rz_il_bv_get(RzILBitVector *bv, ut32 pos);
// logic operations
RZ_API bool rz_il_bv_lshift(RzILBitVector *bv, ut32 size);
RZ_API bool rz_il_bv_rshift(RzILBitVector *bv, ut32 size);
RZ_API bool rz_il_bv_lshift_fill(RzILBitVector *bv, ut32 size, bool fill_bit);
RZ_API bool rz_il_bv_rshift_fill(RzILBitVector *bv, ut32 size, bool fill_bit);
RZ_API RzILBitVector *rz_il_bv_and(RzILBitVector *x, RzILBitVector *y);
RZ_API RzILBitVector *rz_il_bv_or(RzILBitVector *x, RzILBitVector *y);
RZ_API RzILBitVector *rz_il_bv_xor(RzILBitVector *x, RzILBitVector *y);
#define rz_il_bv_neg rz_il_bv_complement_2
#define rz_il_bv_not rz_il_bv_complement_1
RZ_API RzILBitVector *rz_il_bv_complement_1(RzILBitVector *bv);
RZ_API RzILBitVector *rz_il_bv_complement_2(RzILBitVector *bv);

// Module 2 arithmetic operations
RZ_API RzILBitVector *rz_il_bv_add(RzILBitVector *x, RzILBitVector *y);
RZ_API RzILBitVector *rz_il_bv_sub(RzILBitVector *x, RzILBitVector *y);
RZ_API RzILBitVector *rz_il_bv_mul(RzILBitVector *x, RzILBitVector *y);
RZ_API RzILBitVector *rz_il_bv_div(RzILBitVector *x, RzILBitVector *y);
RZ_API RzILBitVector *rz_il_bv_mod(RzILBitVector *x, RzILBitVector *y);
RZ_API RzILBitVector *rz_il_bv_sdiv(RzILBitVector *x, RzILBitVector *y);
RZ_API RzILBitVector *rz_il_bv_smod(RzILBitVector *x, RzILBitVector *y);

RZ_API bool rz_il_bv_msb(RzILBitVector *bv);
RZ_API bool rz_il_bv_lsb(RzILBitVector *bv);
RZ_API bool rz_il_bv_ule(RzILBitVector *x, RzILBitVector *y);
RZ_API bool rz_il_bv_sle(RzILBitVector *x, RzILBitVector *y);
// some convert functions
RZ_API ut8 rz_il_bv_to_ut8(RzILBitVector *x);
RZ_API ut16 rz_il_bv_to_ut16(RzILBitVector *x);
RZ_API ut32 rz_il_bv_to_ut32(RzILBitVector *x);
RZ_API ut64 rz_il_bv_to_ut64(RzILBitVector *x);
// misc
RZ_API bool rz_il_bv_is_zero_vector(RzILBitVector *x);
RZ_API RzILBitVector *rz_il_bv_new_from_ut32(ut32 length, ut32 value);
RZ_API RzILBitVector *rz_il_bv_new_from_ut64(ut32 length, ut64 value);
RZ_API bool rz_il_bv_set_from_ut32(RZ_NONNULL RzILBitVector *bv, ut32 value);
RZ_API bool rz_il_bv_set_from_ut64(RZ_NONNULL RzILBitVector *bv, ut64 value);
RZ_API char *rz_il_bv_as_string(RzILBitVector *bv);
RZ_API char *rz_il_bv_as_hex_string(RzILBitVector *bv);

RZ_API ut32 rz_il_bv_len(RzILBitVector *bv);
RZ_API int rz_il_bv_cmp(RzILBitVector *x, RzILBitVector *y);
ut32 rz_il_bv_hash(RzILBitVector *x);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_BITVECTOR_H
