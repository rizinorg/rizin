#ifndef RZ_LIB_H
#define RZ_LIB_H

#include "rz_types.h"
#include "rz_list.h"

#if __UNIX__
#include <dlfcn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_lib);

// rename to '.' ??
#define RZ_LIB_SEPARATOR "."
#define RZ_LIB_SYMNAME   "rizin_plugin"
#define RZ_LIB_SYMFUNC   "rizin_plugin_function"

#define RZ_LIB_ENV "RZ_LIBR_PLUGINS"

/* TODO: This must depend on HOST_OS, and maybe move into rz_types */
#if __WINDOWS__
#include <windows.h>
#define RZ_LIB_EXT "dll"
#elif __APPLE__
#define RZ_LIB_EXT "dylib"
#else
#define RZ_LIB_EXT "so"
#endif

/* store list of loaded plugins */
typedef struct rz_lib_plugin_t {
	int type;
	char *file;
	void *data; /* user pointer */
	struct rz_lib_handler_t *handler;
	void *dl_handler; // DL HANDLER
	char *author;
	char *version;
	void (*free)(void *data);
} RzLibPlugin;

/* store list of initialized plugin handlers */
typedef struct rz_lib_handler_t {
	int type;
	char desc[128]; // TODO: use char *
	void *user; /* user pointer */
	int (*constructor)(RzLibPlugin *, void *user, void *data);
	int (*destructor)(RzLibPlugin *, void *user, void *data);
} RzLibHandler;

/* this structure should be pointed by the 'rizin_plugin' symbol
   found in the loaded .so */
typedef struct rz_lib_struct_t {
	int type;
	void *data; /* pointer to data handled by plugin handler */
	const char *version; /* rizin version */
	void (*free)(void *data);
	const char *pkgname; /* pkgname associated to this plugin */
} RzLibStruct;

typedef RzLibStruct *(*RzLibStructFunc)(void);

// order matters because of librz/util/lib.c
enum {
	RZ_LIB_TYPE_IO, /* io layer */
	RZ_LIB_TYPE_DBG, /* debugger */
	RZ_LIB_TYPE_LANG, /* language */
	RZ_LIB_TYPE_ASM, /* assembler */
	RZ_LIB_TYPE_ANALYSIS, /* analysis */
	RZ_LIB_TYPE_PARSE, /* parsers */
	RZ_LIB_TYPE_BIN, /* bin headers */
	RZ_LIB_TYPE_BIN_XTR, /* bin extractors */
	RZ_LIB_TYPE_BIN_LDR, /* bin loaders */
	RZ_LIB_TYPE_BP, /* breakpoint */
	RZ_LIB_TYPE_SYSCALL, /* syscall */
	RZ_LIB_TYPE_FASTCALL, /* fastcall */
	RZ_LIB_TYPE_CRYPTO, /* cryptography */
	RZ_LIB_TYPE_CORE, /* RzCore commands */
	RZ_LIB_TYPE_EGG, /* rz_egg plugin */
	RZ_LIB_TYPE_LAST
};

typedef struct rz_lib_t {
	/* linked list with all the plugin handler */
	/* only one handler per handler-id allowed */
	/* this is checked in add_handler function */
	char *symname;
	char *symnamefunc;
	RzList /*RzLibPlugin*/ *plugins;
	RzList /*RzLibHandler*/ *handlers;
} RzLib;

#ifdef RZ_API
/* low level api */
RZ_API void *rz_lib_dl_open(const char *libname);

RZ_API void *rz_lib_dl_sym(void *handler, const char *name);
RZ_API int rz_lib_dl_close(void *handler);

/* high level api */
typedef int (*RzLibCallback)(RzLibPlugin *, void *, void *);
RZ_API RzLib *rz_lib_new(const char *symname, const char *symnamefunc);
RZ_API void rz_lib_free(RzLib *lib);
RZ_API int rz_lib_run_handler(RzLib *lib, RzLibPlugin *plugin, RzLibStruct *symbol);
RZ_API RzLibHandler *rz_lib_get_handler(RzLib *lib, int type);
RZ_API int rz_lib_open(RzLib *lib, const char *file);
RZ_API bool rz_lib_opendir(RzLib *lib, const char *path);
RZ_API int rz_lib_open_ptr(RzLib *lib, const char *file, void *handler, RzLibStruct *stru);
RZ_API char *rz_lib_path(const char *libname);
RZ_API void rz_lib_list(RzLib *lib);
RZ_API bool rz_lib_add_handler(RzLib *lib, int type, const char *desc, RzLibCallback ct, RzLibCallback dt, void *user);
RZ_API bool rz_lib_del_handler(RzLib *lib, int type);
RZ_API int rz_lib_close(RzLib *lib, const char *file);

RZ_API const char *rz_lib_types_get(int idx);
RZ_API int rz_lib_types_get_i(const char *str);
#endif

#ifdef __cplusplus
}
#endif

#endif
