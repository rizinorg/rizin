// SPDX-FileCopyrightText: 2021 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_path.h>
#include <rz_util/rz_file.h>
#include <rz_util/rz_sys.h>
#include <rz_util/rz_str.h>

/**
 * \brief Return \p path prefixed by the Rizin install prefix
 *
 * \param path Path to put in the install prefix context or NULL to just get the install prefix
 * \return \p path prefixed by the Rizin install prefix or just the install prefix
 */
RZ_API RZ_OWN char *rz_path_prefix(RZ_NULLABLE const char *path) {
#if RZ_IS_PORTABLE
	char *pid_to_path = rz_sys_pid_to_path(rz_sys_getpid());
	if (pid_to_path) {
		char *t = rz_file_dirname(pid_to_path);
		free(pid_to_path);
		// When rz_path_prefix is called from a unit test or from a
		// not-yet-instazled rizin binary this would return the wrong path.
		// In those cases, just return RZ_PREFIX.
		char *result = NULL;
		if (rz_str_endswith(t, RZ_SYS_DIR RZ_BINDIR)) {
			char *r = rz_file_dirname(t);
			result = rz_file_path_join(r, path);
			free(r);
		}
		free(t);
		if (result) {
			return result;
		}
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
 * \brief Return the system path of the global rizinrc file
 */
RZ_API RZ_OWN char *rz_path_system_rc(void) {
	return rz_path_prefix(RZ_GLOBAL_RC);
}

/**
 * \brief Return \p path prefixed by the home prefix
 *
 * \param path Path to put in the home prefix context or NULL to just get the home prefix
 * \return \p path prefixed by the home prefix or just the home prefix
 */
RZ_API RZ_OWN char *rz_path_home(RZ_NULLABLE const char *path) {
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
