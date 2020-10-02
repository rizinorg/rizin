#ifndef RZ_STRPOOL_H
#define RZ_STRPOOL_H

#define RZ_STRPOOL_INC 1024

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char *str;
	int len;
	int size;
} RStrpool;

RZ_API RStrpool* rz_strpool_new(int sz);
RZ_API char *rz_strpool_alloc(RStrpool *p, int l);
RZ_API int rz_strpool_memcat(RStrpool *p, const char *s, int len);
RZ_API int rz_strpool_ansi_chop(RStrpool *p, int n);
RZ_API int rz_strpool_append(RStrpool *p, const char *s);
RZ_API void rz_strpool_free(RStrpool *p);
RZ_API int rz_strpool_fit(RStrpool *p);
RZ_API char *rz_strpool_get(RStrpool *p, int index);
RZ_API char *rz_strpool_get_i(RStrpool *p, int index);
RZ_API int rz_strpool_get_index(RStrpool *p, const char *s);
RZ_API char *rz_strpool_next(RStrpool *p, int index);
RZ_API char *rz_strpool_slice(RStrpool *p, int index);
RZ_API char *rz_strpool_empty(RStrpool *p);

#ifdef __cplusplus
}
#endif

#endif //  RZ_STRPOOL_H
