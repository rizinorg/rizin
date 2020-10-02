#ifndef RZ_STRBUF_H
#define RZ_STRBUF_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char buf[32];
	size_t len; // string length in chars or binary buffer size
	char *ptr; // ptr replacing buf in case strlen > sizeof(buf)
	size_t ptrlen; // string length + 1 or binary buffer size
	bool weakref; // ptr is not owned
} RStrBuf;

#define RZ_STRBUF_SAFEGET(sb) (rz_strbuf_get (sb) ? rz_strbuf_get (sb) : "")
RZ_API RStrBuf *rz_strbuf_new(const char *s);
RZ_API const char *rz_strbuf_set(RStrBuf *sb, const char *s); // return = the string or NULL on fail
RZ_API bool rz_strbuf_slice(RStrBuf *sb, int from, int len);
RZ_API bool rz_strbuf_setbin(RStrBuf *sb, const ut8 *s, size_t len);
RZ_API ut8* rz_strbuf_getbin(RStrBuf *sb, int *len);
RZ_API const char *rz_strbuf_setf(RStrBuf *sb, const char *fmt, ...); // return = the string or NULL on fail
RZ_API const char *rz_strbuf_vsetf(RStrBuf *sb, const char *fmt, va_list ap); // return = the string or NULL on fail
RZ_API bool rz_strbuf_append(RStrBuf *sb, const char *s);
RZ_API bool rz_strbuf_append_n(RStrBuf *sb, const char *s, size_t l);
RZ_API bool rz_strbuf_prepend(RStrBuf *sb, const char *s);
RZ_API bool rz_strbuf_appendf(RStrBuf *sb, const char *fmt, ...);
RZ_API bool rz_strbuf_vappendf(RStrBuf *sb, const char *fmt, va_list ap);
RZ_API char *rz_strbuf_get(RStrBuf *sb);
RZ_API char *rz_strbuf_drain(RStrBuf *sb);
RZ_API char *rz_strbuf_drain_nofree(RStrBuf *sb);
RZ_API int rz_strbuf_length(RStrBuf *sb);
RZ_API int rz_strbuf_size(RStrBuf *sb);
RZ_API void rz_strbuf_free(RStrBuf *sb);
RZ_API void rz_strbuf_fini(RStrBuf *sb);
RZ_API void rz_strbuf_init(RStrBuf *sb);
RZ_API const char *rz_strbuf_initf(RStrBuf *sb, const char *fmt, ...); // same as init + setf for convenience
RZ_API bool rz_strbuf_copy(RStrBuf *dst, RStrBuf *src);
RZ_API bool rz_strbuf_equals(RStrBuf *sa, RStrBuf *sb);
RZ_API bool rz_strbuf_reserve(RStrBuf *sb, size_t len);
RZ_API bool rz_strbuf_is_empty(RStrBuf *sb);
RZ_API bool rz_strbuf_setptr(RStrBuf *sb, char *p, int l);

#ifdef __cplusplus
}
#endif

#endif //  RZ_STRBUF_H
