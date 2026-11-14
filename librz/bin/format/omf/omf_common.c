// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "omf/omf_common.h"
#include "omf_specs.h"

RZ_API ut16 omf_get_idx_offset(RZ_NONNULL const void *src, const size_t buf_size, RZ_NONNULL RZ_INOUT size_t *offset) {
	if (buf_size < 2) {
		return 0;
	}
	const ut16 ret = rz_read_le8_offset(src, offset);
	if (ret & 0x80) {
		if (buf_size < 3) {
			*offset -= 1;
			return 0;
		}
		return (ut16)(ret & 0x7f) * 0x100 + rz_read_le8_offset(src, offset);
	}
	return ret;
}

RZ_API ut8 c166_memory_model_type(ut8 modinfo) {
	return (modinfo & 0x1C) >> 2;
}

RZ_API char *c166_get_memory_model(ut8 modinfo) {
	const ut8 MEMORY_MODEL = c166_memory_model_type(modinfo); ///< The three bit model specifier gives the memory model choosen on translation:
	switch (MEMORY_MODEL) {
	case OMF166_MEMORY_MODEL_TINY: {
		return rz_str_dup("Tiny: program 64K or less");
	}
	case OMF166_MEMORY_MODEL_SMALL: {
		return rz_str_dup("Small: 'near' functions and data");
	}
	case OMF166_MEMORY_MODEL_COMPACT: {
		return rz_str_dup("Compact: 'far' data, 'near' funcs");
	}
	case OMF166_MEMORY_MODEL_MEDIUM: {
		return rz_str_dup("Medium: 'near' data, 'far' funcs");
	}
	case OMF166_MEMORY_MODEL_LARGE: {
		return rz_str_dup("Large: 'far' functions and data");
	}
	case OMF166_MEMORY_MODEL_HCOMPACT: {
		return rz_str_dup("HCompact: 'huge' data, 'near' funcs");
	}
	case OMF166_MEMORY_MODEL_HLARGE: {
		return rz_str_dup("HLarge: 'huge' data, 'far' funcs");
	}
	case OMF166_MEMORY_MODEL_XLARGE: {
		return rz_str_dup("XLarge: 'xhuge' data, 'far' funcs");
	}
	default:
		RZ_LOG_ERROR("Unknown MEMORY_MODEL: 0x%02x.\n", MEMORY_MODEL);
		return rz_str_dup("Unknown MEMORY_MODEL");
	}
}

bool rz_bin_checksum_omf_ok(RZ_NONNULL const ut8 *buf, const ut64 buf_size) {
	ut8 checksum = 0;
	if (!buf) {
		RZ_LOG_ERROR("Invalid record (buf is null)\n");
		return false;
	}

	if (buf_size < 3) {
		RZ_LOG_ERROR("Invalid record (too short)\n");
		return false;
	}
	ut16 size = rz_read_le16(buf + 1);
	if (size == 0 || size == UINT16_MAX) {
		///< TODO: affects other tests
		// RZ_LOG_ERROR("Invalid record (untrusted value)\n");
		return false;
	}
	if (buf_size < size + 3) {
		///< TODO: affects other tests
		// RZ_LOG_ERROR("Invalid record (too short)\n");
		return false;
	}
	// Some compiler set checksum to 0
	if (!buf[size + 2]) {
		return true;
	}
	size += 3;
	for (; size; size--) {
		if (buf_size < size) {
			RZ_LOG_ERROR("Invalid record (too short)\n");
			return false;
		}
		checksum += buf[size - 1];
	}
	return !checksum ? true : false;
}

int omf_cmp_pes(const void *a, const void *b) {
	const OMF_pes *s_a = a;
	const OMF_pes *s_b = b;
	if (s_a->seg_idx > s_b->seg_idx) {
		return 1;
	}
	if (s_a->seg_idx < s_b->seg_idx) {
		return -1;
	}
	return s_a->paddr - s_b->paddr;
}

static OMF_record *rz_bin_format_omf_load_record_omf(RZ_NONNULL rz_bin_omf_base_obj *base_obj, const ut8 *buf, ut64 global_ct, ut64 buf_size) {
	if (!base_obj->is_valid_omf_type) {
		return NULL;
	}
	if (!base_obj->is_valid_omf_type(*buf) || !rz_bin_checksum_omf_ok(buf, buf_size)) {
		return NULL;
	}

	OMF_record *new = RZ_NEW0(OMF_record);
	if (!new) {
		return NULL;
	}
	size_t offset = 0;
	new->type = rz_read_le8_offset(buf, &offset);
	const ut16 tainted_value = rz_read_le16_offset(buf, &offset);
	if (tainted_value == 0 || tainted_value == UINT16_MAX) {
		RZ_LOG_WARN("File may be corrupted (Overflow detected or untrusted value).\n");
		RZ_FREE(new);
		return NULL;
	}
	ut16 max_record_size = RECORD_MAX_SIZE;
	if (base_obj->max_record_size) {
		max_record_size = base_obj->max_record_size();
	}
	// at least a record have a type a size and a checksum
	if (tainted_value > max_record_size ||
		tainted_value > buf_size - 3 || buf_size < 4) {
		RZ_LOG_ERROR("Invalid record (too long)\n");
		RZ_FREE(new);
		return NULL;
	}
	new->size = tainted_value;

	if (!base_obj->load_omf_content) {
		RZ_FREE(new);
		return NULL;
	}
	if (!base_obj->load_omf_content(base_obj->target_obj, new, buf, global_ct, buf_size)) {
		RZ_FREE(new);
		return NULL;
	}
	new->checksum = buf[offset + new->size];
	return new;
}

bool rz_bin_format_omf_load_all_records(RZ_NONNULL rz_bin_omf_base_obj *base_obj, RZ_NONNULL const ut8 *buf, const ut64 size) {
	if (!base_obj) {
		return false;
	}

	ut64 ct = 0;
	OMF_record *new_rec = NULL;

	if (base_obj->init_internal_storage) {
		base_obj->init_internal_storage(base_obj->target_obj);
	}

	while (ct < size) {
		new_rec = rz_bin_format_omf_load_record_omf(base_obj, buf + ct, ct, size - ct);
		if (!new_rec) {
			return false;
		}
		ct += 3 + new_rec->size;
		free(new_rec);
	}
	base_obj->bits = base_obj->get_bits(base_obj->target_obj);

	if (base_obj->post_init) {
		base_obj->post_init(base_obj->target_obj);
	}
	return true;
}

ut32 get_perm_by_type(ut8 data_type) {
	switch (data_type) {
	case 0: ///< BIT
	case 1: { ///< DATA
		return RZ_PERM_RW;
	}
	case 2: {
		return RZ_PERM_RX; ///< CODE
	}
	case 3: {
		return RZ_PERM_R; ///< CONST
	}
	default: {
		rz_warn_if_reached();
		return RZ_PERM_R;
	}
	}
}

RZ_IPI OMF_FILE_TARGET_TYPE check_omf_type(RZ_NONNULL RzBuffer *b) {
	OMF_FILE_TARGET_TYPE ret_type = OMF_FILE_TARGET_NOT_OMF;
	const ut64 length = rz_buf_size(b);
	if (!length) {
		return OMF_FILE_TARGET_NOT_OMF;
	}
	ut8 ch;
	if (!rz_buf_read_at(b, 0, &ch, 1)) {
		return ret_type;
	}
	ut16 rec_size;
	if (!rz_buf_read_le16_at(b, 1, &rec_size)) {
		return ret_type;
	}

	if (ch == 0x80 || ch == 0x82) {
		ut8 str_size;
		(void)rz_buf_read_at(b, 3, &str_size, 1);

		if (str_size + 2 != rec_size || length < rec_size + 3) {
			return ret_type;
		}
		// check that the string is ASCII
		for (ut16 i = 4; i < str_size + 4; i++) {
			if (!rz_buf_read_at(b, i, &ch, 1)) {
				return ret_type;
			}
			if (ch > 0x7f) {
				return ret_type;
			}
		}
		ret_type = OMF_FILE_TARGET_96;
	}
	if (ch == 0x70 || ch == 0x72) {
		if (length < rec_size + 3) {
			return OMF_FILE_TARGET_NOT_OMF;
		}
		ut8 in[5] = RZ_EMPTY;
		const st64 read_count = rz_buf_read_at(b, 5, in, sizeof(in));
		if (read_count != 5) {
			return OMF_FILE_TARGET_NOT_OMF;
		}
		if (!memcmp(in, "C166 ", read_count) || !memcmp(in, "A166 ", read_count)) {
			ret_type = OMF_FILE_TARGET_C166;
		} else if (!memcmp(in, "CX51 ", read_count) || !memcmp(in, "AX51 ", read_count)) {
			ret_type = OMF_FILE_TARGET_51;
		}
	}

	ut64 size;
	const ut8 *buf = rz_buf_data(b, &size);
	if (!buf) {
		// hackaround until we make this plugin not use RBuf.data
		ut8 tmp_buf[1024] = RZ_EMPTY;
		rz_buf_read_at(b, 0, tmp_buf, sizeof(tmp_buf));
		if (!rz_bin_checksum_omf_ok(tmp_buf, sizeof(tmp_buf))) {
			return OMF_FILE_TARGET_NOT_OMF;
		}
		return ret_type;
	}
	if (!rz_bin_checksum_omf_ok(buf, length)) {
		return OMF_FILE_TARGET_NOT_OMF;
	}
	return ret_type;
}

RZ_IPI bool omf_check_buffer(RzBuffer *b) {
	const OMF_FILE_TARGET_TYPE omf_type = check_omf_type(b);
	if (omf_type == OMF_FILE_TARGET_NOT_OMF) {
		return false;
	}
	return true;
}

void omf_linnums_free(void *it) {
	OMF_linnums *p = it;
	RZ_FREE(p);
}

int omf_line_sample_cmp(const void *a, const void *b, void *user) {
	(void)user;
	const OMF_linnums *sa = a;
	const OMF_linnums *sb = b;
	// first, sort by addr
	if (sa->address < sb->address) {
		return -1;
	}
	if (sa->address > sb->address) {
		return 1;
	}
	// then sort by line
	if (sa->LineNumber < sb->LineNumber) {
		return -1;
	}
	if (sa->LineNumber > sb->LineNumber) {
		return 1;
	}
	// and eventually by file because this is the most expensive operation
	if (!strnlen(sa->filename, MAX_NAME_LEN) && !strnlen(sb->filename, MAX_NAME_LEN)) {
		return 0;
	}
	if (!strnlen(sa->filename, MAX_NAME_LEN)) {
		return -1;
	}
	if (!strnlen(sb->filename, MAX_NAME_LEN)) {
		return 1;
	}
	return strcmp(sa->filename, sb->filename);
}
