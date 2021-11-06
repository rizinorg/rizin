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
RZ_API RZ_OWN RzILBitVector *rz_il_bv_new(ut32 length);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_dup(const RZ_NONNULL RzILBitVector *bv);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_append(RZ_NONNULL RzILBitVector *bv1, RZ_NONNULL RzILBitVector *bv2);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_concat(RZ_NONNULL RzList *bvs);
RZ_API int rz_il_bv_copy(RZ_NONNULL RzILBitVector *src, RZ_NONNULL RzILBitVector *dst);
RZ_API int rz_il_bv_copy_nbits(
	RzILBitVector *src, ut32 src_start_pos,
	RzILBitVector *dst, ut32 dst_start_pos,
	int nbit);
RZ_API void rz_il_bv_free(RZ_NULLABLE RzILBitVector *bv);
// read and write to a bit
RZ_API bool rz_il_bv_set(RZ_NONNULL RzILBitVector *bv, ut32 pos, bool b);
RZ_API bool rz_il_bv_set_all(RZ_NONNULL RzILBitVector *bv, bool b);
RZ_API bool rz_il_bv_toggle(RZ_NONNULL RzILBitVector *bv, ut32 pos);
RZ_API bool rz_il_bv_toggle_all(RZ_NONNULL RzILBitVector *bv);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_append_zero(RZ_NONNULL RzILBitVector *bv, ut32 delta_len);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_prepend_zero(RZ_NONNULL RzILBitVector *bv, ut32 delta_len);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_cut_head(RZ_NONNULL RzILBitVector *bv, ut32 delta_len);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_cut_tail(RZ_NONNULL RzILBitVector *bv, ut32 delta_len);
RZ_API bool rz_il_bv_get(RZ_NONNULL RzILBitVector *bv, ut32 pos);
// logic operations
RZ_API bool rz_il_bv_lshift(RZ_NONNULL RzILBitVector *bv, ut32 size);
RZ_API bool rz_il_bv_rshift(RZ_NONNULL RzILBitVector *bv, ut32 size);
RZ_API bool rz_il_bv_lshift_fill(RZ_NONNULL RzILBitVector *bv, ut32 size, bool fill_bit);
RZ_API bool rz_il_bv_rshift_fill(RZ_NONNULL RzILBitVector *bv, ut32 size, bool fill_bit);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_and(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_or(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_xor(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);
#define rz_il_bv_neg rz_il_bv_complement_2
#define rz_il_bv_not rz_il_bv_complement_1
RZ_API RZ_OWN RzILBitVector *rz_il_bv_complement_1(RZ_NONNULL RzILBitVector *bv);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_complement_2(RZ_NONNULL RzILBitVector *bv);

// Module 2 arithmetic operations
RZ_API RZ_OWN RzILBitVector *rz_il_bv_add(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y, RZ_NULLABLE bool *carry);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_sub(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y, RZ_NULLABLE bool *borrow);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_mul(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_div(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_mod(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_sdiv(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_smod(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);

RZ_API bool rz_il_bv_msb(RZ_NONNULL RzILBitVector *bv);
RZ_API bool rz_il_bv_lsb(RZ_NONNULL RzILBitVector *bv);
RZ_API bool rz_il_bv_ule(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);
RZ_API bool rz_il_bv_sle(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);
// some convert functions
RZ_API ut8 rz_il_bv_to_ut8(RZ_NONNULL RzILBitVector *x);
RZ_API ut16 rz_il_bv_to_ut16(RZ_NONNULL RzILBitVector *x);
RZ_API ut32 rz_il_bv_to_ut32(RZ_NONNULL RzILBitVector *x);
RZ_API ut64 rz_il_bv_to_ut64(RZ_NONNULL RzILBitVector *x);
// misc
RZ_API bool rz_il_bv_is_zero_vector(RZ_NONNULL RzILBitVector *x);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_new_from_ut32(ut32 length, ut32 value);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_new_from_ut64(ut32 length, ut64 value);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_new_from_st32(ut32 length, st32 value);
RZ_API RZ_OWN RzILBitVector *rz_il_bv_new_from_st64(ut32 length, st64 value);
RZ_API bool rz_il_bv_set_from_ut32(RZ_NONNULL RzILBitVector *bv, ut32 value);
RZ_API bool rz_il_bv_set_from_ut64(RZ_NONNULL RzILBitVector *bv, ut64 value);
RZ_API bool rz_il_bv_set_from_st32(RZ_NONNULL RzILBitVector *bv, st32 value);
RZ_API bool rz_il_bv_set_from_st64(RZ_NONNULL RzILBitVector *bv, st64 value);
RZ_API char *rz_il_bv_as_string(RZ_NONNULL RzILBitVector *bv);
RZ_API char *rz_il_bv_as_hex_string(RZ_NONNULL RzILBitVector *bv);

RZ_API ut32 rz_il_bv_len(RZ_NONNULL RzILBitVector *bv);
RZ_API int rz_il_bv_cmp(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y);
ut32 rz_il_bv_hash(RZ_NULLABLE RzILBitVector *x);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_BITVECTOR_H
