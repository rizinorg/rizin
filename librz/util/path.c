// SPDX-FileCopyrightText: 2021 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_path.h>
#include <rz_util/rz_file.h>
#include <rz_util/rz_sys.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_utf8.h>
#include <rz_windows.h>

#if RZ_IS_PORTABLE
#include <rz_constructor.h>
#include <rz_th.h>

static char *portable_prefix = NULL;
static bool portable_prefix_searched = false;
static RzThreadLock *portable_prefix_mutex = NULL;

#ifdef RZ_DEFINE_CONSTRUCTOR_NEEDS_PRAGMA
#pragma RZ_DEFINE_CONSTRUCTOR_PRAGMA_ARGS(init_portable_prefix)
#endif
RZ_DEFINE_CONSTRUCTOR(init_portable_prefix)
static void init_portable_prefix(void) {
	portable_prefix_mutex = rz_th_lock_new(false);
}

#ifdef RZ_DEFINE_DESTRUCTOR_NEEDS_PRAGMA
#pragma RZ_DEFINE_DESTRUCTOR_PRAGMA_ARGS(fini_portable_prefix)
#endif
RZ_DEFINE_DESTRUCTOR(fini_portable_prefix)
static void fini_portable_prefix(void) {
	RZ_FREE(portable_prefix);
	portable_prefix_searched = false;
	RZ_FREE_CUSTOM(portable_prefix_mutex, rz_th_lock_free);
}

static char *set_portable_prefix(void) {
	char *pid_to_path = rz_sys_pid_to_path(rz_sys_getpid());
	if (!pid_to_path) {
		return NULL;
	}

	const char *filename = rz_file_basename(pid_to_path);
	char *it = rz_file_dirname(pid_to_path);
	free(pid_to_path);

	for (int i = 0; i < RZ_BINDIR_DEPTH && it; i++) {
		char *tmp = it;
		it = rz_file_dirname(tmp);
		free(tmp);
	}
	if (!it) {
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
 * The install prefix is taken from the build-time configuration RZ_PREFIX,
 * unless Rizin was not compiled as "portable". In such a case the prefix is
 * either discovered from the path of the executable calling this function or
 * stored via the path variable
 *
 * \param path Path to use when to prefix or NULL to use the binary location
 */
RZ_API void rz_path_set_prefix(RZ_NONNULL const char *path) {
#if RZ_IS_PORTABLE
	rz_th_lock_enter(portable_prefix_mutex);
	free(portable_prefix);
	if (RZ_STR_ISNOTEMPTY(path)) {
		portable_prefix = rz_str_dup(path);
	} else {
		portable_prefix = set_portable_prefix();
	}
	portable_prefix_searched = true;
	rz_th_lock_leave(portable_prefix_mutex);
#endif
}

/**
 * \brief Return \p path prefixed by the Rizin install prefix
 *
 * The install prefix is taken from the build-time configuration RZ_PREFIX,
 * unless Rizin was not compiled as "portable". In such a case the prefix is
 * discovered from the path of the executable calling this function.
 *
 * \param path Path to put in the install prefix context or NULL to just get the install prefix
 * \return \p path prefixed by the Rizin install prefix or just the install prefix
 */
RZ_API RZ_OWN char *rz_path_prefix(RZ_NULLABLE const char *path) {
#if RZ_IS_PORTABLE
	rz_th_lock_enter(portable_prefix_mutex);
	if (!portable_prefix_searched) {
		portable_prefix = set_portable_prefix();
		portable_prefix_searched = true;
	}
	rz_th_lock_leave(portable_prefix_mutex);

	if (portable_prefix) {
		return rz_file_path_join(portable_prefix, path);
	}

#endif
	return rz_file_path_join(RZ_PREFIX, path);
}

/**
 * \brief Return the directory where include files are placed
 */
RZ_API RZ_OWN char *rz_path_incdir(void) {
	return rz_path_prefix(RZ_INCDIR);
}

/**
 * \brief Return the directory where the Rizin binaries are placed
 */
RZ_API RZ_OWN char *rz_path_bindir(void) {
	return rz_path_prefix(RZ_BINDIR);
}

/**
 * \brief Return the directory where the Rizin libraries are placed
 */
RZ_API RZ_OWN char *rz_path_libdir(void) {
	return rz_path_prefix(RZ_LIBDIR);
}

/**
 * \brief Return the full system path of the given subpath \p path
 */
RZ_API RZ_OWN char *rz_path_system(RZ_NULLABLE const char *path) {
	return rz_path_prefix(path);
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
 */
RZ_API RZ_OWN char *rz_path_system_rc(void) {
	return rz_path_prefix(RZ_GLOBAL_RC);
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
