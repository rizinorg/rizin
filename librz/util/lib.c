// SPDX-FileCopyrightText: 2008-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_lib.h>
#include <rz_windows.h>

RZ_LIB_VERSION(rz_lib);

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
RZ_API RzLib *rz_lib_new(RZ_NULLABLE const char *symname, RZ_NULLABLE const char *symnamefunc) {
	RzLib *lib = RZ_NEW(RzLib);
	if (!lib) {
		return NULL;
	}
	lib->handlers = rz_list_newf(free);
	lib->plugins = rz_list_new();
	lib->symname = strdup(symname ? symname : RZ_LIB_SYMNAME);
	lib->symnamefunc = strdup(symnamefunc ? symnamefunc : RZ_LIB_SYMFUNC);
	lib->opened_dirs = ht_su_new(HT_STR_DUP);
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
	ht_su_free(lib->opened_dirs);
	free(lib);
}

static bool lib_dl_check_filename(const char *file) {
	return rz_str_endswith(file, "." RZ_LIB_EXT);
}

static bool lib_run_handler(RzLib *lib, RzLibPlugin *plugin, RzLibStruct *symbol) {
	RzLibHandler *h = plugin->handler;
	if (h->constructor) {
		return h->constructor(plugin, h->user, symbol->data);
	}
	return true;
}

static RzLibHandler *lib_get_handler(RzLib *lib, RzLibType type) {
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
 * \param file The plugin to remove or NULL to remove all of them
 * \return true for success, false otherwise
 */
RZ_API bool rz_lib_close(RzLib *lib, const char *file) {
	RzLibPlugin *p;
	RzListIter *iter, *iter2;
	rz_list_foreach_safe (lib->plugins, iter, iter2, p) {
		if ((!file || !strcmp(file, p->file))) {
			bool ret = true;
			if (p->handler->destructor) {
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
	return file == NULL;
}

static bool lib_already_loaded(RzLib *lib, const char *file) {
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

static bool lib_open_ptr(RzLib *lib, const char *file, void *handler, RzLibStruct *stru) {
	rz_return_val_if_fail(lib && file && stru, false);
	if (stru->version) {
		char *mm0 = major_minor(stru->version);
		char *mm1 = major_minor(RZ_VERSION);
		bool mismatch = strcmp(mm0, mm1);
		free(mm0);
		free(mm1);
		if (mismatch) {
			RZ_LOG_DEBUG("rz_lib_open: skip plugin %s because for a different Rizin version (%s vs %s)\n",
				file, stru->version, RZ_VERSION);
			return false;
		}
	}

	RzLibHandler *lib_handler = lib_get_handler(lib, stru->type);
	if (!lib_handler) {
		// the handler was not assigned for this type therefore
		// we skip this library (this happens when not loading
		// all the plugins types, like rz-bin does).
		RZ_LOG_DEBUG("rz_lib_open: no handler was defined for %s with type %d\n", file, stru->type);
		return false;
	}

	RzLibPlugin *p = RZ_NEW0(RzLibPlugin);
	if (!p) {
		RZ_LOG_ERROR("rz_lib_open: Cannot allocate RzLibPlugin\n");
		return false;
	}

	p->type = stru->type;
	p->data = stru->data;
	p->file = strdup(file);
	p->handler = lib_handler;
	p->free = stru->free;

	bool ret = lib_run_handler(lib, p, stru);
	if (!ret) {
		free(p->file);
		free(p);
		return false;
	}

	rz_list_append(lib->plugins, p);
	return true;
}

/**
 * \brief Open a plugin file
 *
 * \param lib \p RzLib instance
 * \param file Dynamic library to load
 * \return true if the plugin is correctly loaded, false otherwise
 */
RZ_API bool rz_lib_open(RzLib *lib, RZ_NONNULL const char *file) {
	rz_return_val_if_fail(lib && file, false);
	/* ignored by filename */
	if (!lib_dl_check_filename(file)) {
		RZ_LOG_ERROR("Invalid library extension: %s\n", file);
		return false;
	}

	if (lib_already_loaded(lib, file)) {
		RZ_LOG_INFO("Not loading library because it has already been loaded from somewhere else: '%s'\n", file);
		return false;
	}

	void *handler = rz_sys_dlopen(file);
	if (!handler) {
		RZ_LOG_INFO("Cannot open library: '%s'\n", file);
		return -1;
	}

	RzLibStructFunc strf = (RzLibStructFunc)rz_sys_dlsym(handler, lib->symnamefunc);
	RzLibStruct *stru = NULL;
	if (strf) {
		stru = strf();
	}
	if (!stru) {
		stru = (RzLibStruct *)rz_sys_dlsym(handler, lib->symname);
	}
	if (!stru) {
		RZ_LOG_INFO("Cannot find symbol '%s' in library '%s'\n", lib->symname, file);
		rz_sys_dlclose(handler);
		return false;
	}

	bool res = lib_open_ptr(lib, file, handler, stru);
	if (!res) {
		rz_sys_dlclose(handler);
	}

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

	if (!force && ht_su_find(lib->opened_dirs, path, NULL)) {
		return false;
	}
#if WANT_DYLINK
#if __WINDOWS__
	wchar_t file[1024];
	WIN32_FIND_DATAW dir;
	HANDLE fh;
	wchar_t directory[MAX_PATH];
	wchar_t *wcpath;
	char *wctocbuff;
	int cx;

	wcpath = rz_utf8_to_utf16(path);
	if (!wcpath) {
		return false;
	}
	cx = swprintf(directory, _countof(directory), L"%ls\\*.*", wcpath);
	if (cx < 0) {
		RZ_LOG_ERROR("Cannot create dir path for %ls (too long?)\n", wcpath);
		free(wcpath);
		return false;
	}
	fh = FindFirstFileW(directory, &dir);
	if (fh == INVALID_HANDLE_VALUE) {
		RZ_LOG_INFO("Cannot open directory %ls\n", wcpath);
		free(wcpath);
		return false;
	}
	do {
		int cx = swprintf(file, _countof(file), L"%ls/%ls", wcpath, dir.cFileName);
		if (cx < 0) {
			RZ_LOG_ERROR("Cannot create full path for %ls (too long?)\n", dir.cFileName);
			continue;
		}
		wctocbuff = rz_utf16_to_utf8(file);
		if (wctocbuff) {
			if (lib_dl_check_filename(wctocbuff)) {
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
	struct dirent *de;
	DIR *dh;

	dh = opendir(path);
	if (!dh) {
		RZ_LOG_INFO("Cannot open directory '%s'\n", path);
		return false;
	}
	while ((de = (struct dirent *)readdir(dh))) {
		if (de->d_name[0] == '.' || strstr(de->d_name, ".dSYM")) {
			continue;
		}
		char *file = rz_file_path_join(path, de->d_name);
		if (!file) {
			RZ_LOG_ERROR("Cannot create full path for %s\n", de->d_name);
		}
		if (lib_dl_check_filename(file)) {
			RZ_LOG_INFO("Loading %s\n", file);
			rz_lib_open(lib, file);
		} else {
			RZ_LOG_INFO("Cannot open %s\n", file);
		}
		free(file);
	}
	closedir(dh);
#endif
#endif
	ht_su_insert(lib->opened_dirs, path, 1);
	return true;
}

/**
 * \brief Add a plugin handler for a given type of plugins
 *
 * \param lib  \p RzLib instance
 * \param type type of plugins this new handler will handle
 * \param desc description of the handler
 * \param cb Callback called when adding a new plugin of the right type
 * \param dt Callback called when removing a plugin of the right type
 * \param user Pointer to data to pass to the callbacks
 * \return true if the handler is correctly added, false otherwise
 */
RZ_API bool rz_lib_add_handler(RzLib *lib,
	RzLibType type, RZ_NONNULL const char *desc,
	RzLibCallback cb,
	RzLibCallback dt,
	void *user) {
	rz_return_val_if_fail(lib && desc, false);

	RzLibHandler *handler = lib_get_handler(lib, type);
	if (!handler) {
		handler = RZ_NEW0(RzLibHandler);
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
