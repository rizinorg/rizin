#ifndef RZ_LIB_H
#define RZ_LIB_H

#include "rz_types.h"
#include "rz_list.h"
#include <rz_util/ht_su.h>

#if __UNIX__
#include <dlfcn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_lib);

#define RZ_LIB_SYMNAME "rizin_plugin"
#define RZ_LIB_SYMFUNC "rizin_plugin_function"

#define RZ_LIB_ENV "RZ_LIB_PLUGINS"

/* TODO: This must depend on HOST_OS, and maybe move into rz_types */
#if __WINDOWS__
#define RZ_LIB_EXT "dll"
#elif __APPLE__
#define RZ_LIB_EXT "dylib"
#else
#define RZ_LIB_EXT "so"
#endif

/**
 * \brief Identify the Plugin type
 */
typedef enum {
	RZ_LIB_TYPE_IO, ///< io layer
	RZ_LIB_TYPE_DBG, ///< debugger
	RZ_LIB_TYPE_LANG, ///< language
	RZ_LIB_TYPE_ASM, ///< assembler
	RZ_LIB_TYPE_ANALYSIS, ///< analysis
	RZ_LIB_TYPE_PARSE, ///< parsers
	RZ_LIB_TYPE_BIN, ///< bin headers
	RZ_LIB_TYPE_BIN_XTR, ///< bin extractors
	RZ_LIB_TYPE_BIN_LDR, ///< DEPRECATED
	RZ_LIB_TYPE_BP, ///< breakpoint
	RZ_LIB_TYPE_SYSCALL, ///< DEPRECATED
	RZ_LIB_TYPE_FASTCALL, ///< DEPRECATED
	RZ_LIB_TYPE_CRYPTO, ///< cryptography
	RZ_LIB_TYPE_HASH, ///< hashes / message digests
	RZ_LIB_TYPE_CORE, ///< RzCore commands
	RZ_LIB_TYPE_EGG, ///< rz_egg plugin
	RZ_LIB_TYPE_DEMANGLER, ///< demanglers
	RZ_LIB_TYPE_ARCH, ///< demanglers
	RZ_LIB_TYPE_UNKNOWN
} RzLibType;

/**
 * \brief Represent a single Plugin
 */
typedef struct rz_lib_plugin_t {
	RzLibType type; ///< Type of the plugin
	char *file; ///< File path
	void *data; ///< User pointer
	struct rz_lib_handler_t *handler; ///< Handler that handles this plugin
	char *author; ///< Author of the plugin
	char *version; ///< Version of the plugin
	void (*free)(void *data);
} RzLibPlugin;

typedef bool (*RzLibCallback)(RzLibPlugin *, void *, void *);

/**
 * \brief Identify how a type of plugins should be handled.
 */
typedef struct rz_lib_handler_t {
	RzLibType type; ///< Plugin type this handler handles
	char desc[128]; ///< Description of the handler
	void *user; ///< User pointer
	RzLibCallback constructor; ///< Callback to call when a new plugin of the right type is added
	RzLibCallback destructor; ///< Callback to call when a plugin of the right type is removed
} RzLibHandler;

/**
 * \brief Represent the content of a plugin
 *
 * This structure should be pointed by the 'rizin_plugin' symbol found in the
 * loaded library (e.g. .so file).
 */
typedef struct rz_lib_struct_t {
	RzLibType type; ///< type of the plugin to load
	void *data; ///< pointer to data handled by plugin handler (e.g. RzBinPlugin, RzAsmPlugin, etc.)
	const char *version; ///< rizin version this plugin was compiled for
	void (*free)(void *data);
} RzLibStruct;

typedef RzLibStruct *(*RzLibStructFunc)(void);

/**
 * \brief Handle all the opened plugins, the plugin-types handlers, etc.
 */
typedef struct rz_lib_t {
	char *symname;
	char *symnamefunc;
	RzList /*<RzLibPlugin *>*/ *plugins;
	RzList /*<RzLibHandler *>*/ *handlers;
	HtSU *opened_dirs; ///< Hashtable to keep track of already opened directories
} RzLib;

#define RZ_PLUGIN_CHECK_AND_ADD(plugins, plugin, py_type) \
	do { \
		RzListIter *_it; \
		py_type *_p; \
		rz_list_foreach ((plugins), _it, _p) { \
			if (!strcmp(_p->name, (plugin)->name)) { \
				return false; \
			} \
		} \
		rz_list_append(plugins, plugin); \
	} while (0)

#define RZ_PLUGIN_REMOVE(plugins, plugin) \
	do { \
		rz_list_delete_data(plugins, plugin); \
	} while (0)

#ifdef RZ_API
RZ_API RzLib *rz_lib_new(RZ_NULLABLE const char *symname, RZ_NULLABLE const char *symnamefunc);
RZ_API void rz_lib_free(RzLib *lib);
RZ_API bool rz_lib_open(RzLib *lib, RZ_NONNULL const char *file);
RZ_API bool rz_lib_opendir(RzLib *lib, const char *path, bool force);
RZ_API bool rz_lib_add_handler(RzLib *lib, RzLibType type, RZ_NONNULL const char *desc, RzLibCallback ct, RzLibCallback dt, void *user);
RZ_API bool rz_lib_close(RzLib *lib, const char *file);
#endif

#ifdef __cplusplus
}
#endif

#endif
