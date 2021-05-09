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

typedef struct rz_diff_t RzDiff2;

#ifdef RZ_API

/* To calculate the hash of a complex structure made of
 * various values, xor the results before returning the final value. */
RZ_API ut32 rz_diff_hash_data(const ut8 *buffer, ut32 size);

RZ_API RZ_OWN RzDiff2 *rz_diff_bytes_new(const ut8 *a, ut32 a_size, const ut8 *b, ut32 b_size, RzDiffIgnoreByte ignore);
RZ_API RZ_OWN RzDiff2 *rz_diff_lines_new(const char *a, const char *b, RzDiffIgnoreLine ignore);
RZ_API RZ_OWN RzDiff2 *rz_diff_generic_new(const void *a, ut32 a_size, const void *b, ut32 b_size, RzDiffMethods *methods);
RZ_API void rz_diff_free2(RzDiff2 *diff);
RZ_API const void *rz_diff_get_a(RzDiff2 *diff);
RZ_API const void *rz_diff_get_b(RzDiff2 *diff);

RZ_API RZ_OWN RzList /*<RzDiffMatch>*/ *rz_diff_matches_new(RzDiff2 *diff);
RZ_API RZ_OWN RzList /*<RzDiffOp>*/ *rz_diff_opcodes_new(RzDiff2 *diff);
RZ_API RZ_OWN RzList /*<RzList<RzDiffOp>>*/ *rz_diff_opcodes_grouped_new(RzDiff2 *diff, ut32 n_groups);
RZ_API bool rz_diff_ratio(RzDiff2 *diff, double *result);
RZ_API bool rz_diff_sizes_ratio(RzDiff2 *diff, double *result);

RZ_API char *rz_diff_unified_text(RzDiff2 *diff, const char *from, const char *to, bool show_time, bool color);
RZ_API PJ *rz_diff_unified_json(RzDiff2 *diff, const char *from, const char *to, bool show_time);

/* Distances algorithms */
RZ_API bool rz_diff_myers_distance(const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
RZ_API bool rz_diff_levenstein_distance(const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);

/* |||||||||||||||||||||||||||||  DELETE ME ||||||||||||||||||||||||||||| */

typedef struct rz_diff_op_old_t {
	/* file A */
	ut64 a_off;
	const ut8 *a_buf;
	ut32 a_len;

	/* file B */
	ut64 b_off;
	const ut8 *b_buf;
	ut32 b_len;
} RzDiffOpOld;

typedef struct rz_diff_old_t {
	ut64 off_a;
	ut64 off_b;
	int delta;
	void *user;
	bool verbose;
	int type;
	const char **diff_cmd; // null-terminated array of cmd+args
	int (*callback)(struct rz_diff_old_t *diff, void *user, RzDiffOpOld *op);
} RzDiffOld;
typedef int (*RzDiffCallback)(RzDiffOld *diff, void *user, RzDiffOpOld *op);

typedef struct rz_diffchar_t {
	const ut8 *align_a;
	const ut8 *align_b;
	size_t len_buf;
	size_t start_align;
} RzDiffChar;
RZ_API RzDiffOld *rz_diff_new(void);
RZ_API RzDiffOld *rz_diff_new_from(ut64 off_a, ut64 off_b);
RZ_API void rz_diff_free(RzDiffOld *d);
RZ_API int rz_diff_buffers_static(RzDiffOld *d, const ut8 *a, int la, const ut8 *b, int lb);
RZ_API int rz_diff_buffers_delta(RzDiffOld *diff, const ut8 *sa, int la, const ut8 *sb, int lb);
RZ_API int rz_diff_buffers(RzDiffOld *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb);
RZ_API char *rz_diff_buffers_to_string(RzDiffOld *d, const ut8 *a, int la, const ut8 *b, int lb);
RZ_API int rz_diff_set_callback(RzDiffOld *d, RzDiffCallback callback, void *user);
RZ_API bool rz_diff_buffers_distance(RzDiffOld *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
RZ_API bool rz_diff_buffers_distance_myers(RzDiffOld *diff, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
RZ_API bool rz_diff_buffers_distance_levenshtein(RzDiffOld *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
RZ_API char *rz_diff_buffers_unified(RzDiffOld *d, const ut8 *a, int la, const ut8 *b, int lb);
/* static method !??! */
RZ_API int rz_diff_lines(const char *file1, const char *sa, int la, const char *file2, const char *sb, int lb);
RZ_API int rz_diff_set_delta(RzDiffOld *d, int delta);
RZ_API int rz_diff_gdiff(const char *file1, const char *file2, int rad, int va);

RZ_API RzDiffChar *rz_diffchar_new(const ut8 *a, const ut8 *b);
RZ_API void rz_diffchar_print(RzDiffChar *diffchar);
RZ_API void rz_diffchar_free(RzDiffChar *diffchar);
#endif
/* |||||||||||||||||||||||||||||  DELETE ME ||||||||||||||||||||||||||||| */

#ifdef __cplusplus
}
#endif

#endif /* RZ_DIFF_H */
