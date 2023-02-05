#ifndef RZ_PJ_H
#define RZ_PJ_H

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
/* encode the pj data as a string */
RZ_API const char *pj_string(PJ *pj);
// RZ_API void pj_print(PJ *j, PrintfCallback cb);
RZ_API void pj_raw(PJ *j, const char *k);

/* nesting */
// RZ_API PJ *pj_begin(char type, PrintfCallback cb);
/* close the current json list or array */
RZ_API PJ *pj_end(PJ *j);
/* object, array */
/* open new json list { */
RZ_API PJ *pj_o(PJ *j);
/* open new array [ */
RZ_API PJ *pj_a(PJ *j);
/* keys, values */
/* new key with no value "name": */
RZ_API PJ *pj_k(PJ *j, const char *k);
/* "name":"null" */
RZ_API PJ *pj_knull(PJ *j, const char *k);
/* unsigned "name":n */
RZ_API PJ *pj_kn(PJ *j, const char *k, ut64 n);
/* signed "name":n */
RZ_API PJ *pj_kN(PJ *j, const char *k, st64 n);
/* literal key "name":"key" */
RZ_API PJ *pj_ks(PJ *j, const char *k, const char *v);

/* begin named array entry: "name": [...] */
RZ_API PJ *pj_ka(PJ *j, const char *k);
/* begin named json entry: "name": {...} */
RZ_API PJ *pj_ko(PJ *j, const char *k);

/* named entry for primitive types */
RZ_API PJ *pj_ki(PJ *j, const char *k, int d);
RZ_API PJ *pj_kd(PJ *j, const char *k, double d);
RZ_API PJ *pj_kf(PJ *j, const char *k, float d);
RZ_API PJ *pj_kb(PJ *j, const char *k, bool v);

/* named "null" */
RZ_API PJ *pj_null(PJ *j);

/* array with first v_len bytes of v */
RZ_API PJ *pj_r(PJ *j, const ut8 *v, size_t v_len);

/* named entry with pj_r */
RZ_API PJ *pj_kr(PJ *j, const char *k, const ut8 *v, size_t v_len);

/* string, escaped for json */
RZ_API PJ *pj_s(PJ *j, const char *k);
/* string, escaped for json without quotes */
RZ_API PJ *pj_S(PJ *j, const char *k);
/* string, raw */
RZ_API PJ *pj_j(PJ *j, const char *k);

/* formatted primitive types */
RZ_API PJ *pj_n(PJ *j, ut64 n);
RZ_API PJ *pj_N(PJ *j, st64 n);
RZ_API PJ *pj_i(PJ *j, int d);
RZ_API PJ *pj_d(PJ *j, double d);
RZ_API PJ *pj_f(PJ *j, float d);
RZ_API PJ *pj_b(PJ *j, bool v);

#ifdef __cplusplus
}
#endif

#endif
