// SPDX-FileCopyrightText: 2008-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_lib.h>

RZ_LIB_VERSION(rz_lib);

/* TODO: avoid globals */
#define IFDBG if (__has_debug)
static bool __has_debug = false;

/* XXX : this must be registered in runtime */
static const char *rz_lib_types[] = {
	"io", "dbg", "lang", "asm", "analysis", "parse", "bin", "bin_xtr", "bin_ldr",
	"bp", "syscall", "fastcall", "crypto", "core", "egg", NULL
};

static const char *__lib_types_get(int idx) {
	if (idx < 0 || idx > RZ_LIB_TYPE_LAST - 1) {
		return "unk";
	}
	return rz_lib_types[idx];
}

RZ_API int rz_lib_types_get_i(const char *str) {
	int i;
	for (i = 0; rz_lib_types[i]; i++) {
		if (!strcmp(str, rz_lib_types[i])) {
			return i;
		}
	}
	return -1;
}

RZ_API void *rz_lib_dl_open(const char *libname) {
	void *ret = NULL;
#if WANT_DYLINK
#if __UNIX__
	if (libname) {
		ret = dlopen(libname, RTLD_GLOBAL | RTLD_LAZY);
	} else {
		ret = dlopen(NULL, RTLD_NOW);
	}
	if (!ret && __has_debug) {
		eprintf("rz_lib_dl_open: error: %s (%s)\n", libname, dlerror());
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
	if (!ret && __has_debug) {
		eprintf("rz_lib_dl_open: error: %s\n", libname);
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

RZ_API char *rz_lib_path(const char *libname) {
#if __WINDOWS__
	char *tmp = rz_str_newf("%s." RZ_LIB_EXT, libname);
	if (!tmp) {
		return NULL;
	}
	WCHAR *name = rz_utf8_to_utf16(tmp);
	free(tmp);
	WCHAR *path = NULL;
	if (!name) {
		goto err;
	}

	int count;
	if (!(count = SearchPathW(NULL, name, NULL, 0, NULL, NULL))) {
		rz_sys_perror("SearchPath");
		goto err;
	}
	path = malloc(count * sizeof(WCHAR));
	if (!path) {
		goto err;
	}
	if (!(count = SearchPathW(NULL, name, NULL, count, path, NULL))) {
		RZ_FREE(path);
		rz_sys_perror("SearchPath");
		goto err;
	}
	tmp = rz_utf16_to_utf8(path);
	free(name);
	free(path);
	return tmp;
err:
	free(name);
	return NULL;
#else
#if __APPLE__
	char *env = rz_sys_getenv("DYLD_LIBRARY_PATH");
	env = rz_str_append(env, ":/lib:/usr/lib:/usr/local/lib");
#elif __UNIX__
	char *env = rz_sys_getenv("LD_LIBRARY_PATH");
	env = rz_str_append(env, ":/lib:/usr/lib:/usr/local/lib");
#endif
	if (!env) {
		env = strdup(".");
	}
	char *next, *path0 = env;
	do {
		next = strchr(path0, ':');
		if (next) {
			*next = 0;
		}
		char *libpath = rz_str_newf("%s/%s." RZ_LIB_EXT, path0, libname);
		if (rz_file_exists(libpath)) {
			free(env);
			return libpath;
		}
		free(libpath);
		path0 = next + 1;
	} while (next);
	free(env);
	return NULL;
#endif
}

RZ_API RzLib *rz_lib_new(const char *symname, const char *symnamefunc) {
	RzLib *lib = RZ_NEW(RzLib);
	if (lib) {
		__has_debug = rz_sys_getenv_asbool("RZ_DEBUG");
		lib->handlers = rz_list_newf(free);
		lib->plugins = rz_list_newf(free);
		lib->symname = strdup(symname ? symname : RZ_LIB_SYMNAME);
		lib->symnamefunc = strdup(symnamefunc ? symnamefunc : RZ_LIB_SYMFUNC);
	}
	return lib;
}

RZ_API void rz_lib_free(RzLib *lib) {
	if (lib) {
		rz_lib_close(lib, NULL);
		rz_list_free(lib->handlers);
		rz_list_free(lib->plugins);
		free(lib->symname);
		free(lib->symnamefunc);
		free(lib);
	}
}

static bool __lib_dl_check_filename(const char *file) {
	return rz_str_endswith(file, "." RZ_LIB_EXT);
}

RZ_API int rz_lib_run_handler(RzLib *lib, RzLibPlugin *plugin, RzLibStruct *symbol) {
	RzLibHandler *h = plugin->handler;
	if (h && h->constructor) {
		IFDBG eprintf("PLUGIN LOADED %p fcn %p\n", h, h->constructor);
		return h->constructor(plugin, h->user, symbol->data);
	}
	IFDBG eprintf("Cannot find plugin constructor\n");
	return -1;
}

RZ_API RzLibHandler *rz_lib_get_handler(RzLib *lib, int type) {
	RzLibHandler *h;
	RzListIter *iter;
	rz_list_foreach (lib->handlers, iter, h) {
		if (h->type == type) {
			return h;
		}
	}
	return NULL;
}

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
			eprintf("Unloaded %s\n", p->file);
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

RZ_API int rz_lib_open(RzLib *lib, const char *file) {
	/* ignored by filename */
	if (!__lib_dl_check_filename(file)) {
		eprintf("Invalid library extension: %s\n", file);
		return -1;
	}

	if (__already_loaded(lib, file)) {
		eprintf("Not loading library because it has already been loaded from somewhere else: '%s'\n", file);
		return -1;
	}

	void *handler = rz_lib_dl_open(file);
	if (!handler) {
		IFDBG eprintf("Cannot open library: '%s'\n", file);
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
		IFDBG eprintf("Cannot find symbol '%s' in library '%s'\n",
			lib->symname, file);
		rz_lib_dl_close(handler);
		return -1;
	}

	int res = rz_lib_open_ptr(lib, file, handler, stru);
	if (strf) {
		free(stru);
	}
	return res;
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

RZ_API int rz_lib_open_ptr(RzLib *lib, const char *file, void *handler, RzLibStruct *stru) {
	rz_return_val_if_fail(lib && file && stru, -1);
	if (stru->version) {
		char *mm0 = major_minor(stru->version);
		char *mm1 = major_minor(RZ_VERSION);
		bool mismatch = strcmp(mm0, mm1);
		free(mm0);
		free(mm1);
		if (mismatch) {
			eprintf("Module version mismatch %s (%s) vs (%s)\n",
				file, stru->version, RZ_VERSION);
			if (stru->pkgname) {
				const char *dot = strchr(stru->version, '.');
				int major = atoi(stru->version);
				int minor = dot ? atoi(dot + 1) : 0;
				// The pkgname member was introduced in 4.2.0
				if (major > 4 || (major == 4 && minor >= 2)) {
					printf("rz_pm -ci %s\n", stru->pkgname);
				}
			}
			return -1;
		}
	}
	RzLibPlugin *p = RZ_NEW0(RzLibPlugin);
	p->type = stru->type;
	p->data = stru->data;
	p->file = strdup(file);
	p->dl_handler = handler;
	p->handler = rz_lib_get_handler(lib, p->type);
	p->free = stru->free;

	int ret = rz_lib_run_handler(lib, p, stru);
	if (ret == -1) {
		IFDBG eprintf("Library handler has failed for '%s'\n", file);
		free(p->file);
		free(p);
		rz_lib_dl_close(handler);
	} else {
		rz_list_append(lib->plugins, p);
	}

	return ret;
}

RZ_API bool rz_lib_opendir(RzLib *lib, const char *path) {
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
		IFDBG eprintf("Cannot open directory %ls\n", wcpath);
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
				IFDBG eprintf("Cannot open %ls\n", dir.cFileName);
			}
			free(wctocbuff);
		}
	} while (FindNextFileW(fh, &dir));
	FindClose(fh);
	free(wcpath);
#else
	dh = opendir(path);
	if (!dh) {
		IFDBG eprintf("Cannot open directory '%s'\n", path);
		return false;
	}
	while ((de = (struct dirent *)readdir(dh))) {
		if (de->d_name[0] == '.' || strstr(de->d_name, ".dSYM")) {
			continue;
		}
		snprintf(file, sizeof(file), "%s/%s", path, de->d_name);
		if (__lib_dl_check_filename(file)) {
			IFDBG eprintf("Loading %s\n", file);
			rz_lib_open(lib, file);
		} else {
			IFDBG eprintf("Cannot open %s\n", file);
		}
	}
	closedir(dh);
#endif
#endif
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
			IFDBG eprintf("Redefining library handler constructor for %d\n", type);
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

RZ_API bool rz_lib_del_handler(RzLib *lib, int type) {
	RzLibHandler *h;
	RzListIter *iter;
	// TODO: remove all handlers for that type? or only one?
	/* No _safe loop necessary because we return immediately after the delete. */
	rz_list_foreach (lib->handlers, iter, h) {
		if (type == h->type) {
			rz_list_delete(lib->handlers, iter);
			return true;
		}
	}
	return false;
}

// TODO _list methods should not exist.. only used in ../core/cmd_log.c: rz_lib_list (core->lib);
RZ_API void rz_lib_list(RzLib *lib) {
	RzListIter *iter;
	RzLibPlugin *p;
	rz_list_foreach (lib->plugins, iter, p) {
		printf(" %5s %p %s \n", __lib_types_get(p->type),
			p->dl_handler, p->file);
	}
}
