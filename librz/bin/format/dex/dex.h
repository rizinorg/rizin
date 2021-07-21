// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DEX_H
#define RZ_DEX_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>

typedef struct dex_t {
	ut8 magic[4];
	ut8 version[4];


} RzBinDex;

RZ_API RzBinDex *rz_bin_dex_new(RzBuffer *buf, ut64 base, Sdb *kv);

#endif /* RZ_DEX_H */
