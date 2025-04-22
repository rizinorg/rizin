#ifndef S_STRBUF_H
#define S_STRBUF_H

#ifndef RZ_FREE
#define RZ_FREE(x) { free(x); x = NULL; }
#endif
#ifndef RZ_NEW0
#define RZ_NEW0(x) (x*)calloc(1,sizeof(x))
#endif

#ifdef _MSC_VER
void out_printf(Output *out, char *str, ...);
#else
void out_printf(Output *out, char *str, ...) __attribute__ ((format (printf, 2, 3)));
#endif

#if USE_RZ_UTIL
#include <rz_util.h>
#else
SStrBuf *rz_strbuf_new(const char *s);
bool rz_strbuf_set(SStrBuf *sb, const char *s);
bool rz_strbuf_append(SStrBuf *sb, const char *s);
char *rz_strbuf_get(SStrBuf *sb);
char *rz_strbuf_drain(SStrBuf *sb);
void rz_strbuf_free(SStrBuf *sb);
void rz_strbuf_fini(SStrBuf *sb);
void rz_strbuf_init(SStrBuf *sb);
int rz_sys_setenv(const char *key, const char *value);
char *rz_sys_getenv(const char *key);
int rz_sys_getpid(void);
#endif

#endif
