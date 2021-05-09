#include <rz_diff.h>

RZ_API void rz_diff_free(RzDiffOld *p) {
}

RZ_API RzDiffOld *rz_diff_new() {
	return NULL;
}

RZ_API RzDiffOld *rz_diff_new_from(ut64 off_a, ut64 off_b) {
	return NULL;
}

RZ_API int rz_diff_buffers_static(RzDiffOld *d, const ut8 *a, int la, const ut8 *b, int lb) {
	return 0;
}

RZ_API int rz_diff_buffers_delta(RzDiffOld *diff, const ut8 *sa, int la, const ut8 *sb, int lb) {
	return 0;
}

RZ_API int rz_diff_buffers(RzDiffOld *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb) {
	return 0;
}

RZ_API char *rz_diff_buffers_to_string(RzDiffOld *d, const ut8 *a, int la, const ut8 *b, int lb) {
	return NULL;
}

RZ_API int rz_diff_set_callback(RzDiffOld *d, RzDiffCallback callback, void *user) {
	return 0;
}

RZ_API bool rz_diff_buffers_distance(RzDiffOld *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	return NULL;
}

RZ_API bool rz_diff_buffers_distance_myers(RzDiffOld *diff, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	return NULL;
}

RZ_API bool rz_diff_buffers_distance_levenshtein(RzDiffOld *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	return NULL;
}

RZ_API char *rz_diff_buffers_unified(RzDiffOld *d, const ut8 *a, int la, const ut8 *b, int lb) {
	return NULL;
}

/* static method !??! */
RZ_API int rz_diff_lines(const char *file1, const char *sa, int la, const char *file2, const char *sb, int lb) {
	return 0;
}

RZ_API int rz_diff_set_delta(RzDiffOld *d, int delta) {
	return 0;
}

RZ_API int rz_diff_gdiff(const char *file1, const char *file2, int rad, int va) {
	return 0;
}

RZ_API RzDiffChar *rz_diffchar_new(const ut8 *a, const ut8 *b) {
	return NULL;
}

RZ_API void rz_diffchar_print(RzDiffChar *diffchar) {
}

RZ_API void rz_diffchar_free(RzDiffChar *diffchar) {
}
