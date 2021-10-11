// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PDB_GDATA_H
#define PDB_GDATA_H

#include <rz_util.h>

typedef struct {
	ut16 leaf_type;
	ut32 symtype;
	ut32 offset;
	ut16 segment;
	char *name;
	ut8 name_len;
} GDataGlobal;

#endif