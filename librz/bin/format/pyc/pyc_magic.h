// SPDX-FileCopyrightText: 2016-2020 c0riolis
// SPDX-FileCopyrightText: 2016-2020 x0urc3
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PYC_MAGIC_H
#define PYC_MAGIC_H

#include <rz_types.h>

struct pyc_version {
	ut32 magic;
	char *version;
	char *revision;
};

struct pyc_version get_pyc_version(ut32 magic);

void parse_version_major_minor(const char *version, unsigned *o_major, unsigned *o_minor);

bool magic_int_within(ut32 target_magic, ut32 lower, ut32 uppper, bool *error);

#endif
