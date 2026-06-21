// SPDX-FileCopyrightText: 2021 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_path.h>
#include <rz_util/rz_file.h>
#include <rz_util/rz_sys.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_utf8.h>
#include <rz_windows.h>

#if RZ_IS_PORTABLE
#include <rz_th.h>

static char *set_portable_prefix(void) {
	char *pid_to_path = rz_sys_pid_to_path(rz_sys_getpid());
	if (!pid_to_path) {
		return NULL;
	}

	const char *filename = rz_file_basename(pid_to_path);
	char *it = rz_file_dirname(pid_to_path);

	for (int i = 0; i < RZ_BINDIR_DEPTH && it; i++) {
		char *tmp = it;
		it = rz_file_dirname(tmp);
		free(tmp);
	}
	if (!it) {
		free(pid_to_path);
		goto err;
	}

	char *bindir = rz_file_path_join(it, RZ_BINDIR);
	if (!bindir) {
		goto err;
	}
	char *bindir_real = rz_path_realpath(bindir);
	free(bindir);
	bool in_bindir = bindir_real != NULL;
	if (!in_bindir) {
		goto err;
	}

	char *exe_path = rz_file_path_join(bindir_real, filename);
	free(pid_to_path);
	free(bindir_real);
	char *exe_path_real = rz_path_realpath(exe_path);
	free(exe_path);
	bool exe_exists = exe_path_real != NULL;
	free(exe_path_real);

	if (in_bindir && exe_exists && rz_file_is_directory(it)) {
		return it;
	}
err:
	free(it);
	return NULL;
}
#endif

/**
 * \brief Return \p path prefixed by the Rizin install prefix
 *
 * The install prefix is taken from \p path unless path is empty. In such a case the portable prefix is
 * computed.
 * \param sys_path RzPath* contains install prefix and mutex.
 * \param path Path to use when prefixing or NULL to use the executable location
 */
RZ_API void rz_path_set_prefix(RZ_BORROW RZ_NONNULL RzPath *sys_path, RZ_NONNULL const char *path) {
#if RZ_IS_PORTABLE
	rz_return_if_fail(sys_path && sys_path->prefix_mutex);
	rz_th_lock_enter(sys_path->prefix_mutex);
	free(sys_path->prefix);
	if (RZ_STR_ISNOTEMPTY(path)) {
		sys_path->prefix = rz_str_dup(path);
	} else {
		sys_path->prefix = set_portable_prefix();
	}
	sys_path->prefix_searched = true;
	rz_th_lock_leave(sys_path->prefix_mutex);
#endif
}

/**
 * \brief Return \p path prefixed by the Rizin install prefix
 *
 * The install prefix is taken from the build-time configuration RZ_PREFIX,
 * unless Rizin was compiled as "portable". In such a case the prefix is
 * provided via \p sys_path->prefix
 * \param sys_path RzPath* contains install prefix and mutex.
 */
RZ_API const char *rz_path_prefix(RZ_BORROW RZ_NONNULL RzPath *sys_path) {
#if RZ_IS_PORTABLE
	rz_return_val_if_fail(sys_path && sys_path->prefix_mutex, RZ_PREFIX);
	rz_th_lock_enter(sys_path->prefix_mutex);
	if (!sys_path->prefix_searched) {
		sys_path->prefix = set_portable_prefix();
		sys_path->prefix_searched = true;
	}
	rz_th_lock_leave(sys_path->prefix_mutex);

	if (sys_path->prefix) {
		return sys_path->prefix;
	}

#endif
	return RZ_PREFIX;
}

/**
 * \brief Return the directory where include files are placed
 */
RZ_API RZ_OWN char *rz_path_incdir(RZ_BORROW RZ_NULLABLE RzPath *sys_path) {
	const char *prefix = rz_path_prefix(sys_path);
	return rz_file_path_join(prefix, RZ_INCDIR);
}

/**
 * \brief Return the directory where the Rizin binaries are placed
 */
RZ_API RZ_OWN char *rz_path_bindir(RZ_BORROW RZ_NULLABLE RzPath *sys_path) {
	const char *prefix = rz_path_prefix(sys_path);
	return rz_file_path_join(prefix, RZ_BINDIR);
}

/**
 * \brief Return the directory where the Rizin libraries are placed
 */
RZ_API RZ_OWN char *rz_path_libdir(RZ_BORROW RZ_NULLABLE RzPath *sys_path) {
	const char *prefix = rz_path_prefix(sys_path);
	return rz_file_path_join(prefix, RZ_LIBDIR);
}

/**
 * \brief Return the full system path of the given subpath \p path
 */
RZ_API RZ_OWN char *rz_path_system(RZ_BORROW RZ_NULLABLE RzPath *sys_path, RZ_NULLABLE const char *path) {
	const char *prefix = rz_path_prefix(sys_path);
	return rz_file_path_join(prefix, path);
}

/**
 * \brief Return the full path of the given subpath \p path in the "extra prefix"
 *
 * Returns NULL if RZ_EXTRA_PREFIX is not defined or in case of errors.
 * See RZ_EXTRA_PREFIX in rz_userconf.h for more info about it.
 */
RZ_API RZ_OWN char *rz_path_extra(RZ_NULLABLE const char *path) {
	if (!RZ_EXTRA_PREFIX) {
		return NULL;
	}
	return rz_file_path_join(RZ_EXTRA_PREFIX, path);
}

/**
 * \brief Return the system path of the global rizinrc file
 * \param sys_path RzPath* contains mutex and install prefix.
 */
RZ_API RZ_OWN char *rz_path_system_rc(RZ_BORROW RZ_NULLABLE RzPath *sys_path) {
	const char *prefix = rz_path_prefix(sys_path);
	return rz_file_path_join(prefix, RZ_GLOBAL_RC);
}

/**
 * \brief Return \p path prefixed by the home prefix
 *
 * Return \p path prefixed by the home prefix. Please note that this is not the
 * home directory, but it is usually something like `~/.local`.
 *
 * \param path Path to put in the home prefix context or NULL to just get the home prefix
 * \return \p path prefixed by the home prefix or just the home prefix
 */
RZ_API RZ_OWN char *rz_path_home_prefix(RZ_NULLABLE const char *path) {
	char *home = rz_sys_getenv(RZ_SYS_HOME);
	if (!home) {
		home = rz_file_tmpdir();
		if (!home) {
			return NULL;
		}
	}
	char *res = rz_str_newf("%s" RZ_SYS_DIR "%s" RZ_SYS_DIR "%s", home, RZ_HOME_PREFIX, path);
	free(home);
	return res;
}

/**
 * \brief Return the home directory for config files (e.g. ~/.config/rizin)
 */
RZ_API RZ_OWN char *rz_path_home_config(void) {
	return rz_path_home(RZ_HOME_CONFIGDIR);
}

/**
 * \brief Return the home directory for cache files (e.g. ~/.cache/rizin)
 */
RZ_API RZ_OWN char *rz_path_home_cache(void) {
	return rz_path_home(RZ_HOME_CACHEDIR);
}

/**
 * \brief Return the path for the command history file
 */
RZ_API RZ_OWN char *rz_path_home_history(void) {
	return rz_path_home(RZ_HOME_HISTORY);
}

/**
 * \brief Return the path of the rizinrc file in the home directory
 */
RZ_API RZ_OWN char *rz_path_home_rc(void) {
	return rz_path_home(RZ_HOME_RC);
}

/**
 * \brief Return the path of the rizinrc file in the home config directory
 */
RZ_API RZ_OWN char *rz_path_home_config_rc(void) {
	return rz_path_home(RZ_HOME_CONFIG_RC);
}

/**
 * \brief Return the home directory of config rizinrc.d
 */
RZ_API RZ_OWN char *rz_path_home_config_rcdir(void) {
	return rz_path_home(RZ_HOME_CONFIG_RC_DIR);
}

/**
 * \brief Return a new path relative to the home directory
 *
 * \param path Sub-path relative to the home directory
 * \return New path prefixed by the home directory
 */
RZ_API RZ_OWN char *rz_path_home(RZ_NULLABLE const char *path) {
	char *home = rz_sys_getenv(RZ_SYS_HOME);
	if (!home) {
		home = rz_file_tmpdir();
		if (!home) {
			return NULL;
		}
	}
	char *res;
	if (path) {
		res = rz_file_path_join(home, path);
		free(home);
	} else {
		res = home;
	}
	return res;
}

/**
 * \brief Return a new path with the `~` char expanded to the home directory
 *
 * \param path Original path that may or may not contain the `~` prefix to refer
 *             to the home directory
 * \return New path with the `~` character replaced with the full path of the home directory
 */
RZ_API RZ_OWN char *rz_path_home_expand(RZ_NULLABLE const char *path) {
	// if the path does not start with `~`, there is nothing to expand
	if (path && path[0] != '~') {
		return rz_str_dup(path);
	}

	// if the path starts with `~` but it is not `~/` or just `~`, then it is a
	// valid name (e.g. `~hello`)
	if (path && path[0] && path[1] && path[1] != '/') {
		return rz_str_dup(path);
	}

	return rz_path_home(path + 1);
}

/**
 * \brief Return a canonicalized absolute path. Expands all symbolic links and resolves
 * references to /./, /../ and extra '/' characters.
 *
 * \param path Original file path.
 * \return New canonicalized absolute path.
 */
RZ_API RZ_OWN char *rz_path_realpath(RZ_NULLABLE const char *path) {
	if (!path) {
		return NULL;
	}
#if HAVE_REALPATH
	char buf[PATH_MAX] = { 0 };
	const char *rp = realpath(path, buf);
	if (rp) {
		return rz_str_dup(rp);
	}
#elif __WINDOWS__
	wchar_t buf[MAX_PATH] = { 0 };

	wchar_t *wpath = rz_utf8_to_utf16(path);
	DWORD len = GetFullPathNameW(wpath, MAX_PATH, buf, NULL);
	free(wpath);
	if (len > 0 && len < MAX_PATH - 1) {
		return rz_utf16_to_utf8_l(buf, len);
	}
#endif
	return NULL;
}

/**
 * \brief Return new RzPath pointer
 */
RZ_API RZ_OWN RzPath *rz_path_new(void) {
	RzPath *p = RZ_NEW0(RzPath);
	if (!p) {
		return NULL;
	}
	p->prefix = NULL;
	p->prefix_searched = false;
	p->prefix_mutex = rz_th_lock_new(false);
	return p;
}

/**
 * \brief This function converts arbitrary user input into a safe, normalized path:
 *  - Empty string ("") is converted to the current directory (".")
 *  - Relative paths are prefixed with "./"
 *  - Absolute paths are returned unchanged
 *  - On Windows, drive-letter paths (e.g. "C:\\") are preserved
 *
 * \param usr_input The raw path string provided by the user. May be NULL or empty.
 * \param len The lenth of the user input path , it may be a partial or a full path , will be null if path is empty.
 * \return A new normalized path string.
 */
RZ_API RZ_OWN char *rz_path_normalize_expand(char *usr_input, size_t len) {
	char *input = rz_str_ndup(usr_input, len);
	if (RZ_STR_ISEMPTY(input)) {
		free(input);
		input = rz_str_dup(".");
	} else if (!rz_file_is_abspath(input) && !rz_str_startswith(input, ".")) {
		const char *fmt = ".%s%s";
#if __WINDOWS__
		if (strchr(input, ':')) {
			fmt = "%.0s%s";
		}
#endif
		char *tmp = rz_str_newf(fmt, RZ_SYS_DIR, input);
		free(input);
		if (!tmp) {
			return NULL;
		}
		input = tmp;
	}

	char *exp_path = rz_path_home_expand(input);

#if __WINDOWS__
	rz_str_replace_ch(exp_path, '/', '\\', true);
#endif

	free(input);
	return exp_path;
}

/**
 * \brief Deallocate memory that the RzPath* \p p is pointing to.
 * \param p RzPath* contains install prefix and mutex.
 */
RZ_API void rz_path_free(RZ_OWN RZ_NULLABLE RzPath *p) {
	if (!p) {
		return;
	}
	free(p->prefix);
	rz_th_lock_free(p->prefix_mutex);
	free(p);
}