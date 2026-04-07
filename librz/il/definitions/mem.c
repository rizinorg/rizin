// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/mem.h>

#define KEY_LEN_MAX 64 // because RzBuffer uses ut64 addresses

static RzILMem *mem_new(RZ_NONNULL RzBuffer *buf, ut32 key_len, bool take_buf_ownerhip) {
	rz_return_val_if_fail(buf && key_len, NULL);
	if (key_len > KEY_LEN_MAX) {
		// no assertion because it's not stricly a programming error to call this
		// with a higher len. It's just not supported.
		return NULL;
	}
	RzILMem *ret = RZ_NEW0(RzILMem);
	if (!ret) {
		return NULL;
	}
	if (!take_buf_ownerhip) {
		// Increment reference count to ensure it is not freed by the owner while
		// this object still uses it.
		rz_buf_ref(buf);
	}
	ret->buf = buf;
	ret->key_len = key_len;
	return ret;
}

/**
 * Create a memory for accessing the given buffer.
 * The buffer ownership is transferred to the RzILMem object.
 *
 * \param buf The buffer of the memory.
 * \param key_len The number of bits a memory key requires.
 * \param take_buf_ownerhip If set, RzILMem takes ownership of the buffer.
 *
 * \return The new RzILMem object, or NULL in case of failure.
 */
RZ_API RZ_OWN RzILMem *rz_il_mem_new_owned(RZ_NONNULL RZ_OWN RzBuffer *buf, ut32 key_len) {
	rz_return_val_if_fail(buf && key_len, NULL);
	return mem_new(buf, key_len, true);
}

/**
 * Create a memory for accessing the given buffer.
 * The buffer is borrowed to the RzILMem object.
 *
 * \param buf The buffer of the memory.
 * \param key_len The number of bits a memory key requires.
 * \param take_buf_ownerhip If set, RzILMem takes ownership of the buffer.
 *
 * \return The new RzILMem object, or NULL in case of failure.
 */
RZ_API RZ_OWN RzILMem *rz_il_mem_new_borrowed(RZ_NONNULL RZ_BORROW RzBuffer *buf, ut32 key_len) {
	rz_return_val_if_fail(buf && key_len, NULL);
	return mem_new(buf, key_len, false);
}

/**
 * Free a Mem
 * \param mem memory to be free
 */
RZ_API void rz_il_mem_free(RzILMem *mem) {
	if (!mem) {
		return;
	}
	// The buffer is not owned. But the reference was incremented.
	// So if there is still another owner using it, this call will
	// only decrement the reference count and return.
	rz_buf_free(mem->buf);
	free(mem);
}

/**
 * \brief Get the bit-size of a key (address) into the memory
 *
 * For all k, `rz_bv_len(rz_il_mem_load(mem, k)) == rz_il_mem_value_len(mem)`.
 * So this could be seen as the size of a byte. Because we only support RzBuffer-based mems
 * at the moment, this is always 8, but more options may be available in the future.
 */
RZ_API ut32 rz_il_mem_key_len(RzILMem *mem) {
	return mem->key_len;
}

/**
 * \brief Get the bit-size of a value in the memory
 *
 * For all k, `rz_bv_len(rz_il_mem_load(mem, k)) == rz_il_mem_value_len(mem)`.
 * So this could be seen as the size of a byte. Because we only support RzBuffer-based mems
 * at the moment, this is always 8, but more options may be available in the future.
 */
RZ_API ut32 rz_il_mem_value_len(RzILMem *mem) {
	return 8;
}

#define return_val_if_key_len_wrong(mem, key, ret) \
	do { \
		if (rz_bv_len(key) != rz_il_mem_key_len(mem)) { \
			RZ_LOG_ERROR("RzIL: Memory key size mismatch (expected size = %u, but got %u)\n", \
				(unsigned int)rz_il_mem_key_len(mem), (unsigned int)rz_bv_len(key)); \
			return ret; \
		} \
	} while (0);

/**
 * Load a single memory value (bitvector) from current address (bitvector)
 * \param mem Memory
 * \param key address (bitvector)
 * \return data (bitvector)
 */
RZ_API RzBitVector *rz_il_mem_load(RzILMem *mem, RzBitVector *key) {
	rz_return_val_if_fail(mem && key, NULL);
	return_val_if_key_len_wrong(mem, key, NULL);
	ut8 v = 0;
	rz_buf_read_at(mem->buf, rz_bv_to_ut64(key), &v, 1);
	return rz_bv_new_from_ut64(rz_il_mem_value_len(mem), v);
}

/**
 * Store a single memory value (bitvector) into an address (bitvector)
 * \param key address
 * \param value data
 * \return whether the store succeeded
 */
RZ_API bool rz_il_mem_store(RzILMem *mem, RzBitVector *key, RzBitVector *value) {
	rz_return_val_if_fail(mem && key && value, false);
	return_val_if_key_len_wrong(mem, key, false);
	if (rz_bv_len(value) != rz_il_mem_value_len(mem)) {
		RZ_LOG_ERROR("RzIL: Memory write value size mismatch (expected size = %u, but got %u)\n",
			(unsigned int)rz_il_mem_value_len(mem), (unsigned int)rz_bv_len(value));
		return false;
	}
	ut8 v = rz_bv_to_ut8(value);
	return rz_buf_write_at(mem->buf, rz_bv_to_ut64(key), &v, 1) == 1;
}

static RzBitVector *read_n_bits(RzBuffer *buf, ut32 n_bits, RzBitVector *key, bool big_endian) {
	RzBitVector *value = rz_bv_new_zero(n_bits);

	if (!value) {
		rz_warn_if_reached();
		return NULL;
	}

	if (rz_buf_seek(buf, rz_bv_to_ut64(key), RZ_BUF_SET) < 0) {
		// Seek failed
		RZ_LOG_WARN("Attempted read beyond ST64_MAX. See issue #5806.");
		return value;
	}

	rz_bv_set_from_buffer_ble(value, buf, rz_bv_len(value), big_endian);
	return value;
}

static bool write_n_bits(RzBuffer *buf, RzBitVector *key, RzBitVector *value, bool big_endian) {
	ut64 address = rz_bv_to_ut64(key);
	ut32 n_bytes = rz_bv_len_bytes(value);

	ut8 *data = calloc(n_bytes, 1);
	if (!data) {
		return false;
	}

	if (big_endian) {
		rz_bv_set_to_bytes_be(value, data);
	} else {
		rz_bv_set_to_bytes_le(value, data);
	}

	bool succ = rz_buf_write_at(buf, address, data, n_bytes) == n_bytes;
	free(data);
	return succ;
}

/**
 * Load an entire word of the given size from the given address
 * \param key address (bitvector)
 * \param n_bits How many bits to read. This also determines the size of the returned bitvector
 * \return data (bitvector)
 */
RZ_API RzBitVector *rz_il_mem_loadw(RzILMem *mem, RzBitVector *key, ut32 n_bits, bool big_endian) {
	rz_return_val_if_fail(mem && key && n_bits, NULL);
	return_val_if_key_len_wrong(mem, key, NULL);
	return read_n_bits(mem->buf, n_bits, key, big_endian);
}

/**
 * Store an entire word or arbitrary size at an address
 * \param key address
 * \param value data
 * \return whether the store succeeded
 */
RZ_API bool rz_il_mem_storew(RzILMem *mem, RzBitVector *key, RzBitVector *value, bool big_endian) {
	rz_return_val_if_fail(mem && key && value, false);
	return_val_if_key_len_wrong(mem, key, false);
	return write_n_bits(mem->buf, key, value, big_endian);
}
