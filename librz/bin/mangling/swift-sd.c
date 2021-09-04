// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_libswift.h>
#include <rz_bin.h>

RZ_API RZ_OWN char *rz_bin_demangle_swift(RZ_NULLABLE const char *mangled) {
	if (!mangled) {
		return NULL;
	}
	if (mangled[0] == '_' && mangled[1] == '_') {
		mangled++;
	}
	return rz_libswift_demangle_line(mangled);
}
