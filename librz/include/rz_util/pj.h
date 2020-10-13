#ifndef RZ_PJ_H
#define RZ_PJ_H 1
#define RZ_PRINT_JSON_DEPTH_LIMIT 128

#include <rz_util/rz_strbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pj_t {
	RzStrBuf sb;
	bool is_first;
	bool is_key;
	char braces[RZ_PRINT_JSON_DEPTH_LIMIT];
	int level;
} PJ;

/* lifecycle */
RZ_API PJ *pj_new(void);
RZ_API void pj_free(PJ *j);
RZ_API void pj_reset(PJ *j); // clear the pj contents, but keep the buffer allocated to re-use it
RZ_API char *pj_drain(PJ *j);
RZ_API const char *pj_string(PJ *pj);
// RZ_API void pj_print(PJ *j, PrintfCallback cb);

/* nesting */
//RZ_API PJ *pj_begin(char type, PrintfCallback cb);
RZ_API PJ *pj_end(PJ *j);
RZ_API char *pj_fmt(PrintfCallback p, const char *fmt, ...);
/* object, array */
RZ_API PJ *pj_o(PJ *j);
RZ_API PJ *pj_a(PJ *j);
/* keys, values */
RZ_API PJ *pj_k(PJ *j, const char *k);
RZ_API PJ *pj_knull(PJ *j, const char *k);
RZ_API PJ *pj_kn(PJ *j, const char *k, ut64 n);
RZ_API PJ *pj_kN(PJ *j, const char *k, st64 n);
RZ_API PJ *pj_ks(PJ *j, const char *k, const char *v);
RZ_API PJ *pj_ka(PJ *j, const char *k);
RZ_API PJ *pj_ko(PJ *j, const char *k);
RZ_API PJ *pj_ki(PJ *j, const char *k, int d);
RZ_API PJ *pj_kd(PJ *j, const char *k, double d);
RZ_API PJ *pj_kf(PJ *j, const char *k, float d);
RZ_API PJ *pj_kb(PJ *j, const char *k, bool v);
RZ_API PJ *pj_null(PJ *j);
RZ_API PJ *pj_r(PJ *j, const unsigned char *v, size_t v_len);
RZ_API PJ *pj_kr(PJ *j, const char *k, const unsigned char *v, size_t v_len);
RZ_API PJ *pj_b(PJ *j, bool v);
RZ_API PJ *pj_s(PJ *j, const char *k);
RZ_API PJ *pj_n(PJ *j, ut64 n);
RZ_API PJ *pj_N(PJ *j, st64 n);
RZ_API PJ *pj_d(PJ *j, double d);
RZ_API PJ *pj_f(PJ *j, float d);
RZ_API PJ *pj_i(PJ *j, int d);
RZ_API PJ *pj_j(PJ *j, const char *k);

#ifdef __cplusplus
}
#endif

#endif

