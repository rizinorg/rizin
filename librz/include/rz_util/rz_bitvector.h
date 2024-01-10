// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BITVECTOR_H
#define RZ_BITVECTOR_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  \struct bitvector_t
 *  \brief structure for bitvector
 *
 *  Ref : https://web.cs.dal.ca/~jamie/UWO/BitVectors/README.html
 */
typedef struct bitvector_t {
	union {
		ut8 *large_a; ///< little endian array of bytes for bitvectors > 64 bits whose size is defined in _elem_len
		ut64 small_u; ///< value of the bitvector when the size is <= 64 bits
	} bits;
	ut32 _elem_len; ///< length of ut8 array (bits.large_a) -- real / physical
	ut32 len; ///< number of bits -- virtual / logical
} RzBitVector;

// init
RZ_API bool rz_bv_init(RZ_NONNULL RzBitVector *bv, ut32 length);
RZ_API RZ_OWN RzBitVector *rz_bv_new(ut32 length);
RZ_API RZ_OWN RzBitVector *rz_bv_dup(const RZ_NONNULL RzBitVector *bv);
RZ_API RZ_OWN RzBitVector *rz_bv_append(RZ_NONNULL RzBitVector *bv1, RZ_NONNULL RzBitVector *bv2);
RZ_API ut32 rz_bv_copy(RZ_NONNULL const RzBitVector *src, RZ_NONNULL RzBitVector *dst);
RZ_API ut32 rz_bv_copy_nbits(
	RZ_NONNULL const RzBitVector *src, ut32 src_start_pos,
	RZ_NONNULL RzBitVector *dst, ut32 dst_start_pos,
	ut32 nbit);
RZ_API void rz_bv_fini(RZ_NONNULL RzBitVector *bv);
RZ_API void rz_bv_free(RZ_NULLABLE RzBitVector *bv);
// read and write to a bit
RZ_API bool rz_bv_set(RZ_NONNULL RzBitVector *bv, ut32 pos, bool b);
RZ_API bool rz_bv_set_all(RZ_NONNULL RzBitVector *bv, bool b);
RZ_API bool rz_bv_set_range(RZ_NONNULL RzBitVector *bv, ut32 pos_start, ut32 pos_end, bool b);
RZ_API bool rz_bv_toggle(RZ_NONNULL RzBitVector *bv, ut32 pos);
RZ_API bool rz_bv_toggle_all(RZ_NONNULL RzBitVector *bv);
RZ_API RZ_OWN RzBitVector *rz_bv_append_zero(RZ_NONNULL RzBitVector *bv, ut32 delta_len);
RZ_API RZ_OWN RzBitVector *rz_bv_prepend_zero(RZ_NONNULL RzBitVector *bv, ut32 delta_len);
RZ_API RZ_OWN RzBitVector *rz_bv_cut_head(RZ_NONNULL RzBitVector *bv, ut32 delta_len);
RZ_API RZ_OWN RzBitVector *rz_bv_cut_tail(RZ_NONNULL RzBitVector *bv, ut32 delta_len);
RZ_API bool rz_bv_get(RZ_NONNULL const RzBitVector *bv, ut32 pos);
// logic operations
RZ_API bool rz_bv_lshift(RZ_NONNULL RzBitVector *bv, ut32 size);
RZ_API bool rz_bv_rshift(RZ_NONNULL RzBitVector *bv, ut32 size);
RZ_API bool rz_bv_lshift_fill(RZ_NONNULL RzBitVector *bv, ut32 size, bool fill_bit);
RZ_API bool rz_bv_rshift_fill(RZ_NONNULL RzBitVector *bv, ut32 size, bool fill_bit);
RZ_API RZ_OWN RzBitVector *rz_bv_and(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API RZ_OWN RzBitVector *rz_bv_or(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API RZ_OWN RzBitVector *rz_bv_xor(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
#define rz_bv_neg rz_bv_complement_2
#define rz_bv_not rz_bv_complement_1
RZ_API RZ_OWN RzBitVector *rz_bv_complement_1(RZ_NONNULL RzBitVector *bv);
RZ_API RZ_OWN RzBitVector *rz_bv_complement_2(RZ_NONNULL RzBitVector *bv);

// Module 2 arithmetic operations
RZ_API RZ_OWN RzBitVector *rz_bv_add(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y, RZ_NULLABLE bool *carry);
RZ_API RZ_OWN RzBitVector *rz_bv_sub(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y, RZ_NULLABLE bool *borrow);
RZ_API RZ_OWN RzBitVector *rz_bv_mul(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API RZ_OWN RzBitVector *rz_bv_div(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API RZ_OWN RzBitVector *rz_bv_mod(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API RZ_OWN RzBitVector *rz_bv_sdiv(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API RZ_OWN RzBitVector *rz_bv_smod(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);

RZ_API bool rz_bv_msb(RZ_NONNULL RzBitVector *bv);
RZ_API bool rz_bv_lsb(RZ_NONNULL RzBitVector *bv);
RZ_API bool rz_bv_eq(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API bool rz_bv_ule(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API bool rz_bv_sle(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);

RZ_API ut32 rz_bv_clz(RZ_NONNULL RzBitVector *bv);
RZ_API ut32 rz_bv_ctz(RZ_NONNULL RzBitVector *bv);

RZ_API RzBitVector *rz_bv_cast(RZ_NONNULL RzBitVector *bv, ut32 to_size, bool fill_bit);

// some convert functions
RZ_API ut8 rz_bv_to_ut8(RZ_NONNULL const RzBitVector *x);
RZ_API ut16 rz_bv_to_ut16(RZ_NONNULL const RzBitVector *x);
RZ_API ut32 rz_bv_to_ut32(RZ_NONNULL const RzBitVector *x);
RZ_API ut64 rz_bv_to_ut64(RZ_NONNULL const RzBitVector *x);
// misc
RZ_API bool rz_bv_is_zero_vector(RZ_NONNULL const RzBitVector *x);
RZ_API bool rz_bv_is_all_one(RZ_NONNULL const RzBitVector *x);
RZ_API RZ_OWN RzBitVector *rz_bv_new_from_ut64(ut32 length, ut64 value);
RZ_API RZ_OWN RzBitVector *rz_bv_new_from_st64(ut32 length, st64 value);
RZ_API RZ_OWN RzBitVector *rz_bv_new_from_bytes_le(RZ_IN RZ_NONNULL const ut8 *buf, ut32 bit_offset, ut32 size);
RZ_API RZ_OWN RzBitVector *rz_bv_new_from_bytes_be(RZ_IN RZ_NONNULL const ut8 *buf, ut32 bit_offset, ut32 size);
RZ_API bool rz_bv_set_from_ut64(RZ_NONNULL RzBitVector *bv, ut64 value);
RZ_API bool rz_bv_set_from_st64(RZ_NONNULL RzBitVector *bv, st64 value);
RZ_API void rz_bv_set_from_bytes_le(RZ_NONNULL RzBitVector *bv, RZ_IN RZ_NONNULL const ut8 *buf, ut32 bit_offset, ut32 size);
RZ_API void rz_bv_set_from_bytes_be(RZ_NONNULL RzBitVector *bv, RZ_IN RZ_NONNULL const ut8 *buf, ut32 bit_offset, ut32 size);
RZ_API void rz_bv_set_to_bytes_le(RZ_NONNULL const RzBitVector *bv, RZ_OUT RZ_NONNULL ut8 *buf);
RZ_API void rz_bv_set_to_bytes_be(RZ_NONNULL const RzBitVector *bv, RZ_OUT RZ_NONNULL ut8 *buf);
RZ_API RZ_OWN char *rz_bv_as_string(RZ_NONNULL const RzBitVector *bv);
RZ_API RZ_OWN char *rz_bv_as_hex_string(RZ_NONNULL const RzBitVector *bv, bool pad);

RZ_API ut32 rz_bv_len(RZ_NONNULL const RzBitVector *bv);
RZ_API ut32 rz_bv_len_bytes(RZ_NONNULL const RzBitVector *bv);
RZ_API bool rz_bv_cmp(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API ut32 rz_bv_hash(RZ_NULLABLE RzBitVector *x);
#define rz_bv_new_zero(l)      rz_bv_new(l)
#define rz_bv_new_one(l)       rz_bv_new_from_ut64(l, 1)
#define rz_bv_new_two(l)       rz_bv_new_from_ut64(l, 2)
#define rz_bv_new_minus_one(l) rz_bv_new_from_st64(l, -1)

// extra added to basic
RZ_API RZ_OWN RzBitVector *rz_bv_pred(RZ_NONNULL RzBitVector *bv);
RZ_API RZ_OWN RzBitVector *rz_bv_succ(RZ_NONNULL RzBitVector *bv);
RZ_API bool rz_bv_arshift(RZ_NONNULL RzBitVector *bv, ut32 dist);
RZ_API RZ_OWN RzBitVector *rz_bv_signed_cast(RZ_NONNULL RzBitVector *bv, ut32 to_size);
RZ_API RZ_OWN RzBitVector *rz_bv_unsigned_cast(RZ_NONNULL RzBitVector *bv, ut32 to_size);

RZ_API bool rz_bv_slt(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API bool rz_bv_ult(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API bool rz_bv_sgt(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API bool rz_bv_ugt(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API bool rz_bv_sge(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);
RZ_API bool rz_bv_uge(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_BITVECTOR_H
