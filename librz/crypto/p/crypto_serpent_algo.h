// SPDX-FileCopyrightText: 2017 NicsTr <nicolas.bordes@grenoble-inp.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CRYPTO_SERPENT_ALGO_H
#define CRYPTO_SERPENT_ALGO_H

#include <rz_crypto.h>
#include <rz_util.h>
#define DW_BY_BLOCK       4
#define DW_BY_USERKEY     8
#define NB_ROUNDS         32
#define NB_SUBKEYS        33
#define NIBBLES_BY_SUBKEY 32

typedef struct serpent_state {
	ut32 key[8];
	int key_size;
} serpent_state_t;

/*
 * st: A pointer to a serpent_state structure containing the key and the key size.
 * in: A block of data to be encrypted.
 * out: When the function returns, the block of data encrypted by serpent
 *      with the key contained in st.
 */
void serpent_encrypt(serpent_state_t *st, ut32 in[DW_BY_BLOCK], ut32 out[DW_BY_BLOCK]);

/*
 * st: A pointer to a serpent_state structure containing the key and the key size.
 * in: A block of data to be decrypted.
 * out: When the function returns, the block of data decrypted by serpent
 *      with the key contained in st.
 */
void serpent_decrypt(serpent_state_t *st, ut32 in[DW_BY_BLOCK], ut32 out[DW_BY_BLOCK]);

/*
 * st: A serpent_state structure containing the key and the key size.
 * subkeys: When the function returns, an array of double words containings
 *          all the subkeys needed for the encryptio/dcryption with serpent.
 */
void serpent_keyschedule(const serpent_state_t *st, ut32 subkeys[NB_SUBKEYS * DW_BY_BLOCK]);

#endif
