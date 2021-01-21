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
} RzStrBuf;

#define RZ_STRBUF_SAFEGET(sb) (rz_strbuf_get(sb) ? rz_strbuf_get(sb) : "")
RZ_API RzStrBuf *rz_strbuf_new(const char *s);
RZ_API const char *rz_strbuf_set(RzStrBuf *sb, const char *s); // return = the string or NULL on fail
RZ_API bool rz_strbuf_slice(RzStrBuf *sb, int from, int len);
RZ_API bool rz_strbuf_setbin(RzStrBuf *sb, const ut8 *s, size_t len);
RZ_API ut8 *rz_strbuf_getbin(RzStrBuf *sb, int *len);
RZ_API const char *rz_strbuf_setf(RzStrBuf *sb, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3); // return = the string or NULL on fail
RZ_API const char *rz_strbuf_vsetf(RzStrBuf *sb, const char *fmt, va_list ap); // return = the string or NULL on fail
RZ_API bool rz_strbuf_append(RzStrBuf *sb, const char *s);
RZ_API bool rz_strbuf_append_n(RzStrBuf *sb, const char *s, size_t l);
RZ_API bool rz_strbuf_prepend(RzStrBuf *sb, const char *s);
RZ_API bool rz_strbuf_appendf(RzStrBuf *sb, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API bool rz_strbuf_vappendf(RzStrBuf *sb, const char *fmt, va_list ap);
RZ_API char *rz_strbuf_get(RzStrBuf *sb);
RZ_API char *rz_strbuf_drain(RzStrBuf *sb);
RZ_API char *rz_strbuf_drain_nofree(RzStrBuf *sb);
RZ_API int rz_strbuf_length(RzStrBuf *sb);
RZ_API int rz_strbuf_size(RzStrBuf *sb);
RZ_API void rz_strbuf_free(RzStrBuf *sb);
RZ_API void rz_strbuf_fini(RzStrBuf *sb);
RZ_API void rz_strbuf_init(RzStrBuf *sb);
RZ_API const char *rz_strbuf_initf(RzStrBuf *sb, const char *fmt, ...); // same as init + setf for convenience
RZ_API bool rz_strbuf_copy(RzStrBuf *dst, RzStrBuf *src);
RZ_API bool rz_strbuf_equals(RzStrBuf *sa, RzStrBuf *sb);
RZ_API bool rz_strbuf_reserve(RzStrBuf *sb, size_t len);
RZ_API bool rz_strbuf_is_empty(RzStrBuf *sb);
RZ_API bool rz_strbuf_setptr(RzStrBuf *sb, char *p, int l);

#ifdef __cplusplus
}
#endif

#endif //  RZ_STRBUF_H
