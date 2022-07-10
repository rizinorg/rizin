// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>
#include <rz_build.h>
#include <rz_util.h>

#ifndef RZ_GITTIP
#define RZ_GITTIP ""
#endif

#ifndef RZ_BIRTH
#define RZ_BIRTH "unknown"
#endif

#ifdef RZ_PACKAGER_VERSION
#ifdef RZ_PACKAGER
#define RZ_STR_PKG_VERSION_STRING ", package: " RZ_PACKAGER_VERSION " (" RZ_PACKAGER ")"
#else
#define RZ_STR_PKG_VERSION_STRING ", package: " RZ_PACKAGER_VERSION
#endif
#else
#define RZ_STR_PKG_VERSION_STRING ""
#endif

RZ_API char *rz_str_version(const char *program) {
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (program) {
		rz_strbuf_appendf(sb, "%s ", program);
	}
	rz_strbuf_appendf(sb, RZ_VERSION " @ " RZ_SYS_OS "-" RZ_SYS_ARCH "-%d",
		(RZ_SYS_BITS & 8) ? 64 : 32);
	if (RZ_STR_ISNOTEMPTY(RZ_STR_PKG_VERSION_STRING)) {
		rz_strbuf_append(sb, RZ_STR_PKG_VERSION_STRING);
	}
	if (RZ_STR_ISNOTEMPTY(RZ_GITTIP)) {
		rz_strbuf_append(sb, "\n");
		rz_strbuf_append(sb, "commit: " RZ_GITTIP ", build: " RZ_BIRTH);
	}
	return rz_strbuf_drain(sb);
}
