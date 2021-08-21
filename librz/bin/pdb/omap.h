// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef OMAP_H
#define OMAP_H

typedef struct {
	ut32 from;
	ut32 to;
} OmapEntry;

typedef struct
{
	RzList /* OmapEntry */ *entries;
	ut32 *froms;
} OmapStream;

#endif // OMAP_H
