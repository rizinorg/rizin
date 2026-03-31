// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>
#include <rz_util.h>

#ifdef RZ_PACKAGER_VERSION
#ifdef RZ_PACKAGER
#define RZ_STR_PKG_VERSION_STRING ", package: " RZ_PACKAGER_VERSION " (" RZ_PACKAGER ")"
#else
#define RZ_STR_PKG_VERSION_STRING ", package: " RZ_PACKAGER_VERSION
#endif
#else
#define RZ_STR_PKG_VERSION_STRING ""
#endif

/**
 * \brief Returns the saved git commit hash of the build.
 *
 * \return The saved git commit hash as a string, or NULL if it's not available.
 */
RZ_API RZ_OWN char *rz_version_gittip(RZ_BORROW RZ_NONNULL RzPath *sys_path) {
	rz_return_val_if_fail(sys_path, NULL);
	char *datadir = rz_path_system(sys_path, RZ_DATADIR);
	if (!datadir) {
		return NULL;
	}
	char *gittip_pathname = rz_file_path_join(datadir, "gittip");
	free(datadir);
	if (!gittip_pathname) {
		return NULL;
	}
	char *gittip = rz_file_slurp(gittip_pathname, NULL);
	free(gittip_pathname);
	if (!gittip || !*rz_str_trim_head_ro(gittip)) {
		free(gittip);
		return NULL;
	}
	return gittip;
}

/**
 * \brief Returns a version string.
 *
 * Returns a version string containing the program version and the OS that the
 * program is compiled against, and the program name, packager information and
 * git commit hash if available.
 * \param sys_path RzPath *
 * \param program The program name, or NULL if it's not needed.
 * \return The version string.
 */
RZ_API RZ_OWN char *rz_version_str(RZ_BORROW RZ_NONNULL RzPath *sys_path, RZ_NULLABLE const char *program) {
	rz_return_val_if_fail(sys_path, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (program) {
		rz_strbuf_appendf(sb, "%s ", program);
	}
	rz_strbuf_appendf(sb, RZ_VERSION " @ " RZ_SYS_OS "-" RZ_SYS_ARCH "-%d",
		(RZ_SYS_BITS & 8) ? 64 : 32);
	if (RZ_STR_ISNOTEMPTY(RZ_STR_PKG_VERSION_STRING)) {
		rz_strbuf_append(sb, RZ_STR_PKG_VERSION_STRING);
	}
	char *gittip = rz_version_gittip(sys_path);
	if (gittip) {
		rz_strbuf_append(sb, "\n");
		rz_strbuf_appendf(sb, "commit: %s", gittip);
		free(gittip);
	}
	return rz_strbuf_drain(sb);
}
