#ifndef RZ_LANG_H
#define RZ_LANG_H

#include <rz_types.h>
#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_lang);

typedef char *(*RzCoreCmdStrCallback)(void *core, const char *s);
typedef int (*RzCoreCmdfCallback)(void *core, const char *s, ...);

typedef struct rz_lang_t {
	struct rz_lang_plugin_t *cur;
	void *user;
	RzList *defs;
	RzList *langs;
	PrintfCallback cb_printf;
	RzCoreCmdStrCallback cmd_str;
	RzCoreCmdfCallback cmdf;
} RzLang;

typedef struct rz_lang_plugin_t {
	const char *name;
	const char *alias;
	const char *desc;
	const char *license;
	const char **help;
	const char *ext;
	int (*init)(RzLang *user);
	bool (*setup)(RzLang *user);
	int (*fini)(RzLang *user);
	int (*prompt)(RzLang *user);
	int (*run)(RzLang *user, const char *code, int len);
	int (*run_file)(RzLang *user, const char *file);
	int (*set_argv)(RzLang *user, int argc, char **argv);
} RzLangPlugin;

typedef struct rz_lang_def_t {
	char *name;
	char *type;
	void *value;
} RzLangDef;

#ifdef RZ_API
RZ_API RzLang *rz_lang_new(void);
RZ_API void rz_lang_free(RzLang *lang);
RZ_API bool rz_lang_setup(RzLang *lang);
RZ_API bool rz_lang_add(RzLang *lang, RzLangPlugin *foo);
RZ_API bool rz_lang_list(RzLang *lang);
RZ_API bool rz_lang_use(RzLang *lang, const char *name);
RZ_API int rz_lang_run(RzLang *lang, const char *code, int len);
RZ_API int rz_lang_run_string(RzLang *lang, const char *code);
/* TODO: user_ptr must be deprecated */
RZ_API void rz_lang_set_user_ptr(RzLang *lang, void *user);
RZ_API bool rz_lang_set_argv(RzLang *lang, int argc, char **argv);
RZ_API int rz_lang_run(RzLang *lang, const char *code, int len);
RZ_API int rz_lang_run_file(RzLang *lang, const char *file);
RZ_API int rz_lang_prompt(RzLang *lang);
RZ_API void rz_lang_plugin_free(RzLangPlugin *p); // XXX
RZ_API RzLangPlugin *rz_lang_get_by_name(RzLang *lang, const char *name);
RZ_API RzLangPlugin *rz_lang_get_by_extension(RzLang *lang, const char *ext);
// TODO: rename rz_Lang_add for rz_lang_plugin_add

RZ_API bool rz_lang_define(RzLang *lang, const char *type, const char *name, void *value);
RZ_API void rz_lang_undef(RzLang *lang, const char *name);
RZ_API void rz_lang_def_free(RzLangDef *def);

#endif

#ifdef __cplusplus
}
#endif

#endif
