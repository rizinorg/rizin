#ifndef RZ_DIFF_H
#define RZ_DIFF_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_cons.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_diff);

#define Color_INSERT   Color_BGREEN
#define Color_DELETE   Color_BRED
#define Color_BGINSERT "\x1b[48;5;22m"
#define Color_BGDELETE "\x1b[48;5;52m"
#define Color_HLINSERT Color_BGINSERT Color_INSERT
#define Color_HLDELETE Color_BGDELETE Color_DELETE

typedef struct rz_diff_op_t {
	/* file A */
	ut64 a_off;
	const ut8 *a_buf;
	ut32 a_len;

	/* file B */
	ut64 b_off;
	const ut8 *b_buf;
	ut32 b_len;
} RzDiffOp;

//typedef struct rz_diff_t RzDiff;

typedef struct rz_diff_t {
	ut64 off_a;
	ut64 off_b;
	int delta;
	void *user;
	bool verbose;
	int type;
	const char *diff_cmd;
	int (*callback)(struct rz_diff_t *diff, void *user, RzDiffOp *op);
} RzDiff;

typedef int (*RzDiffCallback)(RzDiff *diff, void *user, RzDiffOp *op);

typedef struct rz_diffchar_t {
	const ut8 *align_a;
	const ut8 *align_b;
	size_t len_buf;
	size_t start_align;
} RzDiffChar;

/* XXX: this api needs to be reviewed , constructor with offa+offb?? */
#ifdef RZ_API
RZ_API RzDiff *rz_diff_new(void);
RZ_API RzDiff *rz_diff_new_from(ut64 off_a, ut64 off_b);
RZ_API RzDiff *rz_diff_free(RzDiff *d);

RZ_API int rz_diff_buffers(RzDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb);
RZ_API int rz_diff_buffers_static(RzDiff *d, const ut8 *a, int la, const ut8 *b, int lb);
RZ_API int rz_diff_buffers_radiff(RzDiff *d, const ut8 *a, int la, const ut8 *b, int lb);
RZ_API int rz_diff_buffers_delta(RzDiff *diff, const ut8 *sa, int la, const ut8 *sb, int lb);
RZ_API int rz_diff_buffers(RzDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb);
RZ_API char *rz_diff_buffers_to_string(RzDiff *d, const ut8 *a, int la, const ut8 *b, int lb);
RZ_API int rz_diff_set_callback(RzDiff *d, RzDiffCallback callback, void *user);
RZ_API bool rz_diff_buffers_distance(RzDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
RZ_API bool rz_diff_buffers_distance_myers(RzDiff *diff, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
RZ_API bool rz_diff_buffers_distance_levenshtein(RzDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
RZ_API char *rz_diff_buffers_unified(RzDiff *d, const ut8 *a, int la, const ut8 *b, int lb);
/* static method !??! */
RZ_API int rz_diff_lines(const char *file1, const char *sa, int la, const char *file2, const char *sb, int lb);
RZ_API int rz_diff_set_delta(RzDiff *d, int delta);
RZ_API int rz_diff_gdiff(const char *file1, const char *file2, int rad, int va);

RZ_API RzDiffChar *rz_diffchar_new(const ut8 *a, const ut8 *b);
RZ_API void rz_diffchar_print(RzDiffChar *diffchar);
RZ_API void rz_diffchar_free(RzDiffChar *diffchar);
#endif

#ifdef __cplusplus
}
#endif

#endif
