// SPDX-FileCopyrightText: 2000, 2001, 2002 Rafael R. Sevilla, Niels Möller
// SPDX-FileCopyrightText: 2013 Niels Möller
// SPDX-License-Identifier: LGPL-3.0-only

/* aes-set-decrypt-key.c

   Inverse key setup for the aes/rijndael block cipher.

   Copyright (C) 2000, 2001, 2002 Rafael R. Sevilla, Niels Möller
   Copyright (C) 2013 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

/* This file implements and uses deprecated functions */
#define _NETTLE_ATTRIBUTE_DEPRECATED

#include "aes.h"

void
aes_invert_key(struct aes_ctx *dst,
	       const struct aes_ctx *src)
{
  switch (src->key_size)
    {
    default: abort();
    case AES128_KEY_SIZE:
      aes128_invert_key(&dst->u.ctx128, &src->u.ctx128);
      break;
    case AES192_KEY_SIZE:
      aes192_invert_key(&dst->u.ctx192, &src->u.ctx192);
      break;
    case AES256_KEY_SIZE:
      aes256_invert_key(&dst->u.ctx256, &src->u.ctx256);
      break;
    }

  dst->key_size = src->key_size;
}

void
aes_set_decrypt_key(struct aes_ctx *ctx,
		    size_t keysize, const uint8_t *key)
{
  /* We first create subkeys for encryption,
   * then modify the subkeys for decryption. */
  aes_set_encrypt_key(ctx, keysize, key);
  aes_invert_key(ctx, ctx);
}

