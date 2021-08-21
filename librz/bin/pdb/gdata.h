// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef GDATA_H
#define GDATA_H

typedef struct {
	ut16 leaf_type;
	ut32 symtype;
	ut32 offset;
	ut16 segment;
	char *name;
	ut8 name_len;
} GDataGlobal;

typedef struct {
	RzList /* GDataGlobal */ *global_list;
} GDataStream;

#endif // GDATA_H
