// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2020 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2017 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2017-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DES_H
#define RZ_DES_H

#include <rz_types.h>

#define DES_KEY_SIZE   8
#define DES_BLOCK_SIZE 8

#ifdef __cplusplus
extern "C" {
#endif

RZ_API void rz_des_permute_key(ut32 *keylo, ut32 *keyhi);
RZ_API void rz_des_permute_key_inv(ut32 *keylo, ut32 *keyhi);
RZ_API void rz_des_permute_block0(ut32 *blocklo, ut32 *blockhi);
RZ_API void rz_des_permute_block1(ut32 *blocklo, ut32 *blockhi);
RZ_API void rz_des_shift_key(int i, bool decrypt, ut32 *deskeylo, ut32 *deskeyhi);
RZ_API void rz_des_pc2(RZ_OUT ut32 *keylo, RZ_OUT ut32 *keyhi, RZ_IN ut32 deslo, RZ_IN ut32 deshi);
RZ_API void rz_des_round_key(int i, ut32 *keylo, ut32 *keyhi, ut32 *deskeylo, ut32 *deskeyhi);
RZ_API void rz_des_round(ut32 *buflo, ut32 *bufhi, ut32 *roundkeylo, ut32 *roundkeyhi);

#ifdef __cplusplus
}
#endif

#endif //  RZ_DES_H
