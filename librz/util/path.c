#include <rz_util/rz_path.h>
#include <rz_util/rz_file.h>
#include <rz_util/rz_sys.h>

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
 * \brief Return the system path of the global rizinrc file
 */
RZ_API RZ_OWN char *rz_path_system_rc(void) {
	return rz_path_prefix(RZ_GLOBAL_RC);
}

/**
 * \brief Return the system directory where plugins are loaded from
 */
RZ_API RZ_OWN char *rz_path_system_plugins(void) {
	return rz_path_prefix(RZ_PLUGINS);
}

/**
 * \brief Return the system directory where bindings are loaded from
 */
RZ_API RZ_OWN char *rz_path_system_bindings(void) {
	return rz_path_prefix(RZ_BINDINGS);
}

/**
 * \brief Return the system directory where arch-independent data are placed
 */
RZ_API RZ_OWN char *rz_path_system_data(void) {
	return rz_path_prefix(RZ_DATDIR_RZ);
}

/**
 * \brief Return the system directory where sdb files are placed
 */
RZ_API RZ_OWN char *rz_path_system_sdb(void) {
	return rz_path_prefix(RZ_SDB);
}

/**
 * \brief Return the system directory of sdb types files
 */
RZ_API RZ_OWN char *rz_path_system_sdb_types(void) {
	return rz_path_prefix(RZ_SDB_TYPES);
}

/**
 * \brief Return the system directory of sdb arch/platforms files
 */
RZ_API RZ_OWN char *rz_path_system_sdb_arch_platforms(void) {
	return rz_path_prefix(RZ_SDB_ARCH_PLATFORMS);
}

/**
 * \brief Return the system directory of sdb arch/cpus files
 */
RZ_API RZ_OWN char *rz_path_system_sdb_arch_cpus(void) {
	return rz_path_prefix(RZ_SDB_ARCH_CPUS);
}

/**
 * \brief Return the system directory where sdb registers files are placed
 */
RZ_API RZ_OWN char *rz_path_system_sdb_reg(void) {
	return rz_path_prefix(RZ_SDB_REG);
}
/**
 * \brief Return the system directory of sdb opcodes files
 */
RZ_API RZ_OWN char *rz_path_system_sdb_opcodes(void) {
	return rz_path_prefix(RZ_SDB_OPCODES);
}

/**
 * \brief Return the system directory of sdb magic files
 */
RZ_API RZ_OWN char *rz_path_system_sdb_magic(void) {
	return rz_path_prefix(RZ_SDB_MAGIC);
}

/**
 * \brief Return the system directory of sdb format files
 */
RZ_API RZ_OWN char *rz_path_system_sdb_format(void) {
	return rz_path_prefix(RZ_SDB_FORMAT);
}

/**
 * \brief Return the system directory of zignatures files
 */
RZ_API RZ_OWN char *rz_path_system_zigns(void) {
	return rz_path_prefix(RZ_ZIGNS);
}

/**
 * \brief Return the system directory of color themes files
 */
RZ_API RZ_OWN char *rz_path_system_themes(void) {
	return rz_path_prefix(RZ_THEMES);
}

/**
 * \brief Return the system directory of fortunes files
 */
RZ_API RZ_OWN char *rz_path_system_fortunes(void) {
	return rz_path_prefix(RZ_FORTUNES);
}

/**
 * \brief Return the system directory of flag files
 */
RZ_API RZ_OWN char *rz_path_system_flags(void) {
	return rz_path_prefix(RZ_FLAGS);
}

/**
 * \brief Return the system directory of hud files
 */
RZ_API RZ_OWN char *rz_path_system_hud(void) {
	return rz_path_prefix(RZ_HUD);
}

/**
 * \brief Return the system directory of www files
 */
RZ_API RZ_OWN char *rz_path_system_wwwroot(void) {
	return rz_path_prefix(RZ_WWWROOT);
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
	char *res = rz_file_path_join(home, path);
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
 * \brief Return the home directory for arch-independent data files (e.g. ~/.local/share/rizin)
 */
RZ_API RZ_OWN char *rz_path_home_data(void) {
	return rz_path_home(RZ_HOME_DATADIR);
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
 * \brief Return the home directory for Rizin plugins
 */
RZ_API RZ_OWN char *rz_path_home_plugins(void) {
	return rz_path_home(RZ_HOME_PLUGINS);
}

/**
 * \brief Return the home directory for PDB files
 */
RZ_API RZ_OWN char *rz_path_home_pdb(void) {
	return rz_path_home(RZ_HOME_PDB);
}

/**
 * \brief Return the home directory for project files
 */
RZ_API RZ_OWN char *rz_path_home_projects(void) {
	return rz_path_home(RZ_HOME_PROJECTS);
}

/**
 * \brief Return the home directory for SDB files
 */
RZ_API RZ_OWN char *rz_path_home_sdb(void) {
	return rz_path_home(RZ_HOME_SDB);
}

/**
 * \brief Return the home directory for types files
 */
RZ_API RZ_OWN char *rz_path_home_sdb_types(void) {
	return rz_path_home(RZ_HOME_SDB_TYPES);
}

/**
 * \brief Return the home directory for opcodes files
 */
RZ_API RZ_OWN char *rz_path_home_sdb_opcodes(void) {
	return rz_path_home(RZ_HOME_SDB_OPCODES);
}

/**
 * \brief Return the home directory for SDB magic files
 */
RZ_API RZ_OWN char *rz_path_home_sdb_magic(void) {
	return rz_path_home(RZ_HOME_SDB_MAGIC);
}

/**
 * \brief Return the home directory for SDB format files
 */
RZ_API RZ_OWN char *rz_path_home_sdb_format(void) {
	return rz_path_home(RZ_HOME_SDB_FORMAT);
}

/**
 * \brief Return the home directory for zignatures files
 */
RZ_API RZ_OWN char *rz_path_home_zigns(void) {
	return rz_path_home(RZ_HOME_ZIGNS);
}

/**
 * \brief Return the home directory for themes files
 */
RZ_API RZ_OWN char *rz_path_home_themes(void) {
	return rz_path_home(RZ_HOME_THEMES);
}

/**
 * \brief Return the home directory for HUD files
 */
RZ_API RZ_OWN char *rz_path_home_hud(void) {
	return rz_path_home(RZ_HOME_HUD);
}

/**
 * \brief Return the home directory for binrc files
 */
RZ_API RZ_OWN char *rz_path_home_binrcdir(void) {
	return rz_path_home(RZ_HOME_BINRC);
}
