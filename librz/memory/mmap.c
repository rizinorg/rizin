// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file: mmap.c
 *
 * This file describes a memory map links a memory region to a RzBuffer area.
 *
 * Memory maps has permissions and can have bigger mappings than their own
 * readable/writable RzBuffer area.
 */

#include "memory_internal.h"

/**
 * \brief      Frees a RzMemory structure.
 *
 * \param      memory  The memory to free
 */
RZ_IPI void rz_memory_map_free(RZ_NULLABLE RzMemoryMap *mmap) {
	if (!mmap) {
		return;
	}

	free(mmap->name);
	rz_buf_free(mmap->buffer);
	free(mmap);
}

/**
 * \brief      Allocates and initialize a memory maps.
 *
 * \param[in]  name        The name of the memory map
 * \param[in]  perms       The permissions of the memory map
 * \param      buffer      The buffer to map at
 * \param[in]  buf_offset  The buffer offset to map from
 * \param[in]  mem_offset  The memory offset to map to
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RzMemoryMap *rz_memory_map_new(RZ_NONNULL const char *name, ut32 perms, RZ_NONNULL RzBuffer *buffer, RZ_NONNULL const RzInterval *buf_offset, RZ_NONNULL const RzInterval *mem_offset) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(name) && buffer && buf_offset && mem_offset, false);

	if (!memory_is_valid_interval(*buf_offset) ||
		!memory_is_valid_interval(*mem_offset)) {
		// do not accept invalid addresses.
		return NULL;
	}

	RzMemoryMap *mmap = RZ_NEW0(RzMemoryMap);
	if (!mmap) {
		return NULL;
	}

	mmap->name = rz_str_dup(name);
	mmap->permissions = perms;
	mmap->buffer = rz_buf_ref(buffer);
	mmap->buf_offset = *buf_offset;
	mmap->mem_offset = *mem_offset;

	if (mmap->name) {
		return mmap;
	}

	rz_memory_map_free(mmap);
	return NULL;
}

/**
 * \brief      Returns the name of the memory map
 *
 * \param[in]  mmap  The RzMemoryMap to use
 *
 * \return     On success returns a valid null-delimited string, otherwise NULL.
 */
RZ_API const char *rz_memory_map_get_name(RZ_NONNULL const RzMemoryMap *mmap) {
	rz_return_val_if_fail(mmap, NULL);
	return mmap->name;
}

/**
 * \brief      Returns the permissions of the memory map
 *
 * \param[in]  mmap  The RzMemoryMap to use
 *
 * \return     Returns the permissions
 */
RZ_API ut32 rz_memory_map_get_permissions(RZ_NONNULL const RzMemoryMap *mmap) {
	rz_return_val_if_fail(mmap, 0);
	return mmap->permissions;
}

/**
 * \brief      Returns the assigned identifier of the memory map
 *
 * \param[in]  mmap  The mmap
 *
 * \return     Returns the identifier
 */
RZ_API size_t rz_memory_map_get_identifier(RZ_NONNULL const RzMemoryMap *mmap) {
	rz_return_val_if_fail(mmap, 0);
	return mmap->id;
}

/**
 * \brief      Sets the permissions of the memory map
 *
 * \param[in]  mmap  The mmap to modify
 */
RZ_API void rz_memory_map_set_permissions(RZ_NONNULL RzMemoryMap *mmap, ut32 permissions) {
	rz_return_if_fail(mmap);
	mmap->permissions = permissions;
}

/**
 * \brief      Returns the memory boundaries linked to the buffer
 *
 * \param[in]  mmap        The RzMemoryMap to use
 * \param      mem_offset  The memory boundaries to write to
 */
RZ_API void rz_memory_map_get_memory_boundaries(RZ_NONNULL const RzMemoryMap *mmap, RZ_NONNULL RzInterval *mem_offset) {
	rz_return_if_fail(mmap && mem_offset);
	*mem_offset = mmap->mem_offset;
}

/**
 * \brief      Returns the buffer boundaries linked to the memory
 *
 * \param[in]  mmap        The RzMemoryMap to use
 * \param      buf_offset  The memory boundaries to write to
 */
RZ_API void rz_memory_map_get_buffer_boundaries(RZ_NONNULL const RzMemoryMap *mmap, RZ_NONNULL RzInterval *buf_offset) {
	rz_return_if_fail(mmap && buf_offset);
	*buf_offset = mmap->buf_offset;
}

/**
 * \brief      Converts a memory offset/address into a buffer offset/address
 *
 * \param[in]  mmap        The RzMemoryMap to use
 * \param[in]  mem_offset  The memory offset to convert
 * \param      buf_offset  The output buffer offset
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_memory_map_convert_memory_to_buffer(RZ_NONNULL const RzMemoryMap *mmap, ut64 mem_offset, RZ_NONNULL ut64 *buf_offset) {
	rz_return_val_if_fail(mmap && buf_offset, false);
	if (!rz_itv_contain(mmap->mem_offset, mem_offset)) {
		return false;
	}

	ut64 difference = mem_offset - rz_itv_begin(mmap->mem_offset);
	*buf_offset = rz_itv_begin(mmap->buf_offset) + difference;
	return true;
}

/**
 * \brief      Converts a buffer offset/address into a memory offset/address
 *
 * \param[in]  mmap        The RzMemoryMap to use
 * \param[in]  buf_offset  The buffer offset to convert
 * \param      mem_offset  The output memory offset
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_memory_map_convert_buffer_to_memory(RZ_NONNULL const RzMemoryMap *mmap, ut64 buf_offset, RZ_NONNULL ut64 *mem_offset) {
	rz_return_val_if_fail(mmap && mem_offset, false);
	if (!rz_itv_contain(mmap->buf_offset, buf_offset)) {
		return false;
	}

	ut64 difference = buf_offset - rz_itv_begin(mmap->buf_offset);
	*mem_offset = rz_itv_begin(mmap->mem_offset) + difference;
	return true;
}

/**
 * \brief      Reads the buffer of a given memory offset and writes it into output.
 *
 * \param[in]  mmap        The RzMemoryMap to use
 * \param[in]  mem_offset  The memory offset to read from
 * \param      output      The output buffer to write to
 * \param[in]  out_len     The out length of the buffer
 * \param      read_len    The actual read length (read_len can be <= out_len)
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_memory_map_read_memory(RZ_NONNULL const RzMemoryMap *mmap, ut64 mem_offset, RZ_NONNULL RZ_OUT ut8 *output, size_t out_len, RZ_NULLABLE size_t *read_len) {
	rz_return_val_if_fail(mmap && output && out_len > 0, false);

	ut64 buf_offset = 0;
	if (!rz_memory_map_convert_memory_to_buffer(mmap, mem_offset, &buf_offset)) {
		return false;
	}

	return rz_memory_map_read_buffer(mmap, buf_offset, output, out_len, read_len);
}

static RzInterval memory_map_intersection(RzInterval mapped_area, ut64 offset, size_t size) {
	RzInterval requested = {
		.addr = offset,
		.size = size,
	};
	return rz_itv_intersect(requested, mapped_area);
}

/**
 * \brief      Reads the buffer of a given RzBuffer offset and writes it into output.
 *
 * \param[in]  mmap        The RzMemoryMap to use
 * \param[in]  buf_offset  The buffer offset to read from
 * \param      output      The output buffer to write to
 * \param[in]  out_len     The out length of the buffer
 * \param      read_len    The actual read length (read_len can be <= out_len)
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_memory_map_read_buffer(RZ_NONNULL const RzMemoryMap *mmap, ut64 buf_offset, RZ_NONNULL RZ_OUT ut8 *output, size_t out_len, RZ_NULLABLE size_t *read_len) {
	rz_return_val_if_fail(mmap && output && out_len > 0, false);

	if (!rz_itv_contain(mmap->buf_offset, buf_offset) ||
		!(mmap->permissions & RZ_PERM_R)) {
		return false;
	}

	RzInterval intersection = memory_map_intersection(mmap->buf_offset, buf_offset, out_len);
	if (!memory_is_valid_interval(intersection)) {
		return false;
	}

	size_t max_size = rz_itv_size(intersection);

	ssize_t n_bytes = rz_buf_read_at(mmap->buffer, buf_offset, output, max_size);
	if (n_bytes < 1) {
		return false;
	}
	if (read_len) {
		*read_len = n_bytes;
	}
	return true;
}

/**
 * \brief      Writes a given buffer to a memory offset.
 *
 * \param[in]  mmap        The RzMemoryMap to use
 * \param[in]  mem_offset  The memory offset to read from
 * \param      input       The input buffer to read from
 * \param[in]  in_len      The input length of the buffer
 * \param      write_len   The actual read length (write_len can be <= in_len)
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_memory_map_write_memory(RZ_NONNULL RzMemoryMap *mmap, ut64 mem_offset, const RZ_NONNULL ut8 *input, size_t in_len, RZ_NULLABLE size_t *write_len) {
	rz_return_val_if_fail(mmap && input && in_len > 0, false);

	ut64 buf_offset = 0;
	if (!rz_memory_map_convert_memory_to_buffer(mmap, mem_offset, &buf_offset)) {
		return false;
	}

	return rz_memory_map_write_buffer(mmap, buf_offset, input, in_len, write_len);
}

/**
 * \brief      Writes a given buffer to a RzBuffer offset.
 *
 * \param[in]  mmap        The RzMemoryMap to use
 * \param[in]  buf_offset  The memory offset to read from
 * \param      input       The input buffer to read from
 * \param[in]  in_len      The input length of the buffer
 * \param      write_len   The actual read length (write_len can be <= in_len)
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_memory_map_write_buffer(RZ_NONNULL RzMemoryMap *mmap, ut64 buf_offset, const RZ_NONNULL ut8 *input, size_t in_len, RZ_NULLABLE size_t *write_len) {
	rz_return_val_if_fail(mmap && input && in_len > 0, false);

	if (!rz_itv_contain(mmap->buf_offset, buf_offset) ||
		!(mmap->permissions & RZ_PERM_W)) {
		return false;
	}

	RzInterval intersection = memory_map_intersection(mmap->buf_offset, buf_offset, in_len);
	if (!memory_is_valid_interval(intersection)) {
		return false;
	}

	size_t max_size = rz_itv_size(intersection);

	ssize_t n_bytes = rz_buf_write_at(mmap->buffer, buf_offset, input, max_size);
	if (n_bytes < 1) {
		return false;
	}
	if (write_len) {
		*write_len = n_bytes;
	}
	return true;
}
