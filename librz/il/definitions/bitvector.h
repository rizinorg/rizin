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
BitVector bv_new(int length);
BitVector bv_dump(BitVector bv);
BitVector bv_adjust(BitVector bv, int new_len);
BitVector bv_concat(BitVector bv1, BitVector bv2);
int bv_copy(BitVector src, BitVector dst);
int bv_copy_nbits(
	BitVector src, int src_start_pos,
	BitVector dst, int dst_start_pos,
	int nbit);
void bv_free(BitVector bv);
// read and write to a bit
bool bv_set(BitVector bv, int pos, bit b);
bool bv_set_all(BitVector bv, bit b);
bool bv_toggle(BitVector bv, int pos);
bool bv_toggle_all(BitVector bv);
BitVector bv_append_zero(BitVector bv, int delta_len);
BitVector bv_prepend_zero(BitVector bv, int delta_len);
BitVector bv_cut_head(BitVector bv, int delta_len);
BitVector bv_cut_tail(BitVector bv, int delta_len);
bit bv_get(BitVector bv, int pos);
// logic operations
bool bv_lshift(BitVector bv, int size);
bool bv_rshift(BitVector bv, int size);
bool bv_lshift_fill(BitVector bv, int size, bool fill_bit);
bool bv_rshift_fill(BitVector bv, int size, bool fill_bit);
BitVector bv_and(BitVector x, BitVector y);
BitVector bv_or(BitVector x, BitVector y);
BitVector bv_xor(BitVector x, BitVector y);
#define bv_neg bv_complement_2
#define bv_not bv_complement_1
BitVector bv_complement_1(BitVector bv);
BitVector bv_complement_2(BitVector bv);

// Module 2 arithmetic operations
BitVector bv_add(BitVector x, BitVector y);
BitVector bv_sub(BitVector x, BitVector y);
BitVector bv_mul(BitVector x, BitVector y);
BitVector bv_div(BitVector x, BitVector y);
BitVector bv_mod(BitVector x, BitVector y);
BitVector bv_sdiv(BitVector x, BitVector y);
BitVector bv_smod(BitVector x, BitVector y);

bit bv_msb(BitVector bv);
bit bv_lsb(BitVector bv);
bool bv_ule(BitVector x, BitVector y);
bool bv_sle(BitVector x, BitVector y);
// some convert functions
char *bv_to_string(BitVector bv);
ut32 bv_to_ut32(BitVector x);
// misc
bool bv_is_zero_vector(BitVector x);
void print_bv(BitVector bv);
BitVector bv_new_from_ut32(int length, ut32 value);
BitVector bv_new_from_ut64(int length, ut64 value);

int bv_len(BitVector bv);
int bv_cmp(BitVector x, BitVector y);
ut32 bv_hash(BitVector x);

#endif //CORE_THEORY_VM_BITVECTOR_H
