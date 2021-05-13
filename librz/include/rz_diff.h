// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DIFF_H
#define RZ_DIFF_H

#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/pj.h>
#include <rz_util/rz_strbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_diff);

typedef enum rz_diff_op_type_t {
	RZ_DIFF_OP_INVALID = 0,
	RZ_DIFF_OP_DELETE,
	RZ_DIFF_OP_EQUAL,
	RZ_DIFF_OP_INSERT,
	RZ_DIFF_OP_REPLACE,
} RzDiffOpType;

/**
 * This interface allows to analyze any data using the same algorithm
 * elem_at(array, index)   [required] must return the an element of the array at position 'index'
 * elem_hash(elem)         [required] must return the hash value of the element (use rz_diff_hash_data)
 * compare(a_elem, b_elem) [required] must return true if the two elements are the same
 * stringify(elem, sb)     [required] appends into sb the stringified element of the array
 * ignore(elem)            [optional] must return true if the element matches the user define 
 *                                     rule (if set to NULL, it will be considered as always false)
 */
typedef const void *(*RzDiffMethodElemAt)(const void *array, ut32 index);
typedef ut32 (*RzDiffMethodElemHash)(const void *elem);
typedef int (*RzDiffMethodCompare)(const void *a_elem, const void *b_elem);
typedef bool (*RzDiffMethodIgnore)(const void *elem);
typedef void (*RzDiffMethodStringify)(const void *elem, RzStrBuf *sb);
typedef struct rz_diff_methods_t {
	RzDiffMethodElemAt elem_at; ///< can be either be an element of A or B
	RzDiffMethodElemHash elem_hash; ///< can be either be an element of A or B
	RzDiffMethodCompare compare; ///< elements from A and B
	RzDiffMethodStringify stringify; ///< elements from A and B
	RzDiffMethodIgnore ignore; ///< elements from A and B
} RzDiffMethods;

typedef struct rz_diff_op_t {
	RzDiffOpType type;
	st32 a_beg;
	st32 a_end;
	st32 b_beg;
	st32 b_end;
} RzDiffOp;

#define RZ_DIFF_OP_SIZE_A(op)    (((op)->a_end) - ((op)->a_beg))
#define RZ_DIFF_OP_SIZE_B(op)    (((op)->b_end) - ((op)->b_beg))
#define RZ_DIFF_DEFAULT_N_GROUPS 3

typedef struct match_p_t {
	ut32 a;
	ut32 b;
	ut32 size;
} RzDiffMatch;

typedef bool (*RzDiffIgnoreByte)(const ut64 byte);
typedef bool (*RzDiffIgnoreLine)(const char *line);

typedef struct rz_diff_t RzDiff;

#ifdef RZ_API

/* To calculate the hash of a complex structure made of
 * various values, xor the results before returning the final value. */
RZ_API ut32 rz_diff_hash_data(const ut8 *buffer, ut32 size);

RZ_API RZ_OWN RzDiff *rz_diff_bytes_new(const ut8 *a, ut32 a_size, const ut8 *b, ut32 b_size, RzDiffIgnoreByte ignore);
RZ_API RZ_OWN RzDiff *rz_diff_lines_new(const char *a, const char *b, RzDiffIgnoreLine ignore);
RZ_API RZ_OWN RzDiff *rz_diff_generic_new(const void *a, ut32 a_size, const void *b, ut32 b_size, RzDiffMethods *methods);
RZ_API void rz_diff_free(RzDiff *diff);
RZ_API const void *rz_diff_get_a(RzDiff *diff);
RZ_API const void *rz_diff_get_b(RzDiff *diff);

RZ_API RZ_OWN RzList /*<RzDiffMatch>*/ *rz_diff_matches_new(RzDiff *diff);
RZ_API RZ_OWN RzList /*<RzDiffOp>*/ *rz_diff_opcodes_new(RzDiff *diff);
RZ_API RZ_OWN RzList /*<RzList<RzDiffOp>>*/ *rz_diff_opcodes_grouped_new(RzDiff *diff, ut32 n_groups);
RZ_API bool rz_diff_ratio(RzDiff *diff, double *result);
RZ_API bool rz_diff_sizes_ratio(RzDiff *diff, double *result);

RZ_API char *rz_diff_unified_text(RzDiff *diff, const char *from, const char *to, bool show_time, bool color);
RZ_API PJ *rz_diff_unified_json(RzDiff *diff, const char *from, const char *to, bool show_time);

/* Distances algorithms */
RZ_API bool rz_diff_myers_distance(const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
RZ_API bool rz_diff_levenstein_distance(const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);

#endif

#ifdef __cplusplus
}
#endif

#endif /* RZ_DIFF_H */
