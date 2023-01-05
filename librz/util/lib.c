// SPDX-FileCopyrightText: 2008-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_lib.h>
#include <rz_windows.h>

RZ_LIB_VERSION(rz_lib);

RZ_API void *rz_lib_dl_open(const char *libname) {
	void *ret = NULL;
#if WANT_DYLINK
#if __UNIX__
	if (libname) {
		ret = dlopen(libname, RTLD_GLOBAL | RTLD_LAZY);
	} else {
		ret = dlopen(NULL, RTLD_NOW);
	}
	if (!ret) {
		RZ_LOG_ERROR("rz_lib_dl_open: error: %s (%s)\n", libname, dlerror());
	}
#elif __WINDOWS__
	LPTSTR libname_;
	if (libname && *libname) {
		libname_ = rz_sys_conv_utf8_to_win(libname);
	} else {
		libname_ = calloc(MAX_PATH, sizeof(TCHAR));
		if (!libname_) {
			RZ_LOG_ERROR("lib/rz_lib_dl_open: Failed to allocate memory.\n");
			return NULL;
		}
		if (!GetModuleFileName(NULL, libname_, MAX_PATH)) {
			libname_[0] = '\0';
		}
	}
	ret = LoadLibrary(libname_);
	free(libname_);
	if (!ret) {
		RZ_LOG_ERROR("rz_lib_dl_open: error: %s\n", libname);
	}
#endif
#endif
	return ret;
}

RZ_API void *rz_lib_dl_sym(void *handler, const char *name) {
#if WANT_DYLINK
#if __UNIX__
	return dlsym(handler, name);
#elif __WINDOWS__
	return GetProcAddress(handler, name);
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

RZ_API int rz_lib_dl_close(void *handler) {
#if __UNIX__
	return dlclose(handler);
#else
	return handler ? 0 : -1;
#endif
}

/**
 * \brief Create a new \p RzLib instance
 *
 * This instance recognizes \p symname as the structure containing the plugin
 * information inside a dynamic library and \p symnamefunc as the function
 * returning that structure.
 *
 * One of these symbols should be defined in the dynamic libraries so they can
 * be recognized as Rizin plugins and loaded/unloaded at runtime.
 *
 * \param symname Name of the symbol pointing to the \p RzLibStruct structure
 * \param symnamefunc Name of the symbol pointing to a \p RzLibStructFunc function
 * \return The new \p RzLib instance
 */
RZ_API RzLib *rz_lib_new(const char *symname, const char *symnamefunc) {
	RzLib *lib = RZ_NEW(RzLib);
	if (!lib) {
		return NULL;
	}
	lib->handlers = rz_list_newf(free);
	lib->plugins = rz_list_newf(free);
	lib->symname = strdup(symname ? symname : RZ_LIB_SYMNAME);
	lib->symnamefunc = strdup(symnamefunc ? symnamefunc : RZ_LIB_SYMFUNC);
	lib->opened_dirs = ht_pu_new0();
	return lib;
}

/**
 * \brief Free the \p RzLib instance \p lib
 *
 * \param lib Instance to free
 */
RZ_API void rz_lib_free(RzLib *lib) {
	if (!lib) {
		return;
	}
	rz_lib_close(lib, NULL);
	rz_list_free(lib->handlers);
	rz_list_free(lib->plugins);
	free(lib->symname);
	free(lib->symnamefunc);
	ht_pu_free(lib->opened_dirs);
	free(lib);
}

static bool __lib_dl_check_filename(const char *file) {
	return rz_str_endswith(file, "." RZ_LIB_EXT);
}

static int lib_run_handler(RzLib *lib, RzLibPlugin *plugin, RzLibStruct *symbol) {
	RzLibHandler *h = plugin->handler;
	if (h && h->constructor) {
		RZ_LOG_DEBUG("PLUGIN LOADED %p fcn %p\n", h, h->constructor);
		return h->constructor(plugin, h->user, symbol->data);
	}
	RZ_LOG_WARN("Cannot find plugin constructor\n");
	return -1;
}

static RzLibHandler *lib_get_handler(RzLib *lib, int type) {
	RzLibHandler *h;
	RzListIter *iter;
	rz_list_foreach (lib->handlers, iter, h) {
		if (h->type == type) {
			return h;
		}
	}
	return NULL;
}

/**
 * \brief Call the plugin destructor and remove it
 *
 * \param lib The \p RzLib instance keeping track of loaded plugins
 * \param file The plugin to remove
 * \return 0 for success, the rest of failure.
 */
RZ_API int rz_lib_close(RzLib *lib, const char *file) {
	RzLibPlugin *p;
	RzListIter *iter, *iter2;
	rz_list_foreach_safe (lib->plugins, iter, iter2, p) {
		if ((!file || !strcmp(file, p->file))) {
			int ret = 0;
			if (p->handler && p->handler->destructor) {
				ret = p->handler->destructor(p, p->handler->user, p->data);
			}
			if (p->free) {
				p->free(p->data);
			}
			free(p->file);
			rz_list_delete(lib->plugins, iter);
			if (file != NULL) {
				return ret;
			}
		}
	}
	if (!file) {
		return 0;
	}
	// delete similar plugin name
	rz_list_foreach (lib->plugins, iter, p) {
		if (strstr(p->file, file)) {
			int ret = 0;
			if (p->handler && p->handler->destructor) {
				ret = p->handler->destructor(p,
					p->handler->user, p->data);
			}
			RZ_LOG_INFO("Unloaded %s\n", p->file);
			free(p->file);
			rz_list_delete(lib->plugins, iter);
			return ret;
		}
	}
	return -1;
}

static bool __already_loaded(RzLib *lib, const char *file) {
	const char *fileName = rz_str_rstr(file, RZ_SYS_DIR);
	RzLibPlugin *p;
	RzListIter *iter;
	if (fileName) {
		rz_list_foreach (lib->plugins, iter, p) {
			const char *pFileName = rz_str_rstr(p->file, RZ_SYS_DIR);
			if (pFileName && !strcmp(fileName, pFileName)) {
				return true;
			}
		}
	}
	return false;
}

static char *major_minor(const char *s) {
	char *a = strdup(s);
	char *p = strchr(a, '.');
	if (p) {
		p = strchr(p + 1, '.');
		if (p) {
			*p = 0;
		}
	}
	return a;
}

static int lib_open_ptr(RzLib *lib, const char *file, void *handler, RzLibStruct *stru) {
	rz_return_val_if_fail(lib && file && stru, -1);
	if (stru->version) {
		char *mm0 = major_minor(stru->version);
		char *mm1 = major_minor(RZ_VERSION);
		bool mismatch = strcmp(mm0, mm1);
		free(mm0);
		free(mm1);
		if (mismatch) {
			RZ_LOG_WARN("Module version mismatch %s (%s) vs (%s)\n",
				file, stru->version, RZ_VERSION);
			return -1;
		}
	}

	RzLibHandler *lib_handler = lib_get_handler(lib, stru->type);
	if (!lib_handler) {
		// the handler was not assigned for this type therefore
		// we skip this library (this happens when not loading
		// all the plugins types, like rz-bin does).
		RZ_LOG_DEBUG("rz_lib_open: no handler was defined for %s with type %d\n", file, stru->type);
		rz_lib_dl_close(handler);
		return -1;
	}

	RzLibPlugin *p = RZ_NEW0(RzLibPlugin);
	if (!p) {
		RZ_LOG_ERROR("rz_lib_open: Cannot allocate RzLibPlugin\n");
		rz_lib_dl_close(handler);
		return -1;
	}

	p->type = stru->type;
	p->data = stru->data;
	p->file = strdup(file);
	p->handler = lib_handler;
	p->free = stru->free;

	int ret = lib_run_handler(lib, p, stru);
	if (ret == -1) {
		RZ_LOG_INFO("Library handler has failed for '%s'\n", file);
		free(p->file);
		free(p);
		rz_lib_dl_close(handler);
	} else {
		rz_list_append(lib->plugins, p);
	}

	return ret;
}

RZ_API int rz_lib_open(RzLib *lib, const char *file) {
	/* ignored by filename */
	if (!__lib_dl_check_filename(file)) {
		RZ_LOG_ERROR("Invalid library extension: %s\n", file);
		return -1;
	}

	if (__already_loaded(lib, file)) {
		RZ_LOG_INFO("Not loading library because it has already been loaded from somewhere else: '%s'\n", file);
		return -1;
	}

	void *handler = rz_lib_dl_open(file);
	if (!handler) {
		RZ_LOG_INFO("Cannot open library: '%s'\n", file);
		return -1;
	}

	RzLibStructFunc strf = (RzLibStructFunc)rz_lib_dl_sym(handler, lib->symnamefunc);
	RzLibStruct *stru = NULL;
	if (strf) {
		stru = strf();
	}
	if (!stru) {
		stru = (RzLibStruct *)rz_lib_dl_sym(handler, lib->symname);
	}
	if (!stru) {
		RZ_LOG_INFO("Cannot find symbol '%s' in library '%s'\n",
			lib->symname, file);
		rz_lib_dl_close(handler);
		return -1;
	}

	int res = lib_open_ptr(lib, file, handler, stru);
	if (strf) {
		free(stru);
	}
	return res;
}

/**
 * \brief Open all the libraries in the given directory, if it wasn't already
 * opened.
 *
 * Opens all the files ending with the right library extension (e.g. ".so")
 * present in the directory pointed by \p path . If \p path was already opened,
 * it is not opened again unless \p force is set to true.
 *
 * \param lib Reference to RzLib
 * \param path Directory to open
 * \param force When true, a directory is re-scanned even if it was already opened
 * \return True when the directory is scanned for libs, false otherwise
 */
RZ_API bool rz_lib_opendir(RzLib *lib, const char *path, bool force) {
	rz_return_val_if_fail(lib && path, false);

	if (!force && ht_pu_find(lib->opened_dirs, path, NULL)) {
		return false;
	}
#if WANT_DYLINK
	rz_return_val_if_fail(lib && path, false);
#if __WINDOWS__
	wchar_t file[1024];
	WIN32_FIND_DATAW dir;
	HANDLE fh;
	wchar_t directory[MAX_PATH];
	wchar_t *wcpath;
	char *wctocbuff;
#else
	char file[1024];
	struct dirent *de;
	DIR *dh;
#endif
#ifdef RZ_LIBR_PLUGINS
	if (!path) {
		path = RZ_LIBR_PLUGINS;
	}
#endif
	if (!path) {
		return false;
	}
#if __WINDOWS__
	wcpath = rz_utf8_to_utf16(path);
	if (!wcpath) {
		return false;
	}
	swprintf(directory, _countof(directory), L"%ls\\*.*", wcpath);
	fh = FindFirstFileW(directory, &dir);
	if (fh == INVALID_HANDLE_VALUE) {
		RZ_LOG_INFO("Cannot open directory %ls\n", wcpath);
		free(wcpath);
		return false;
	}
	do {
		swprintf(file, _countof(file), L"%ls/%ls", wcpath, dir.cFileName);
		wctocbuff = rz_utf16_to_utf8(file);
		if (wctocbuff) {
			if (__lib_dl_check_filename(wctocbuff)) {
				rz_lib_open(lib, wctocbuff);
			} else {
				RZ_LOG_INFO("Cannot open %ls\n", dir.cFileName);
			}
			free(wctocbuff);
		}
	} while (FindNextFileW(fh, &dir));
	FindClose(fh);
	free(wcpath);
#else
	dh = opendir(path);
	if (!dh) {
		RZ_LOG_INFO("Cannot open directory '%s'\n", path);
		return false;
	}
	while ((de = (struct dirent *)readdir(dh))) {
		if (de->d_name[0] == '.' || strstr(de->d_name, ".dSYM")) {
			continue;
		}
		snprintf(file, sizeof(file), "%s/%s", path, de->d_name);
		if (__lib_dl_check_filename(file)) {
			RZ_LOG_INFO("Loading %s\n", file);
			rz_lib_open(lib, file);
		} else {
			RZ_LOG_INFO("Cannot open %s\n", file);
		}
	}
	closedir(dh);
#endif
#endif
	ht_pu_insert(lib->opened_dirs, path, 1);
	return true;
}

RZ_API bool rz_lib_add_handler(RzLib *lib,
	int type, const char *desc,
	int (*cb)(RzLibPlugin *, void *, void *), /* constructor */
	int (*dt)(RzLibPlugin *, void *, void *), /* destructor */
	void *user) {
	RzLibHandler *h;
	RzListIter *iter;
	RzLibHandler *handler = NULL;

	rz_list_foreach (lib->handlers, iter, h) {
		if (type == h->type) {
			RZ_LOG_INFO("Redefining library handler constructor for %d\n", type);
			handler = h;
			break;
		}
	}
	if (!handler) {
		handler = RZ_NEW(RzLibHandler);
		if (!handler) {
			return false;
		}
		handler->type = type;
		rz_list_append(lib->handlers, handler);
	}
	strncpy(handler->desc, desc, sizeof(handler->desc) - 1);
	handler->user = user;
	handler->constructor = cb;
	handler->destructor = dt;

	return true;
}
