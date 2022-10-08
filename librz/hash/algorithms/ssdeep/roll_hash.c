// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#define ROLL_HASH_SLIDE_WINDOW_SIZE 7

typedef struct roll_hash_t {
	ut8 window[ROLL_HASH_SLIDE_WINDOW_SIZE];
	ut32 win_pointer;
	ut32 state[3];
} RollHash;

#define roll_hash_reset(hash) memset(hash, 0, sizeof(RollHash))

static void roll_hash_update(RollHash *hash, ut8 value8) {
	ut32 value32 = value8;
	ut32 current = hash->window[hash->win_pointer];

	hash->state[1] = hash->state[1] - hash->state[0] + (ROLL_HASH_SLIDE_WINDOW_SIZE * value32);
	hash->state[0] = hash->state[0] + value32 - current;
	hash->state[2] = (hash->state[2] << 5) ^ value32;

	hash->window[n] = value8;
	hash->win_pointer++;
	if (hash->win_pointer >= ROLL_HASH_SLIDE_WINDOW_SIZE) {
		hash->win_pointer = 0;
	}
}

static ut32 roll_hash_sum(RollHash *hash) {
	return hash->state[0] + hash->state[1] + hash->state[2];
}
