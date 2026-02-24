// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only
#include "luajit.h"
#include <rz_util/rz_str.h>

static ut64 luajit_get_flag(RzBuffer *b, ut64 off_at) {
	if (!b) {
		RZ_LOG_ERROR("NULL Buffer\n");
		return 0;
	}
	ut8 ret;
	if (!rz_buf_read8_at(b, off_at, &ret)) {
		return 0;
	}
	return (ut64)ret;
}

static void luajit_parse_filename(RzBuffer *buf, char *dest, ut64 offset_at, int len) {
	if (!buf) {
		return;
	}
	rz_buf_read_at(buf, offset_at, (ut8 *)dest, len);
	dest[len] = '\0';
}

RZ_IPI RzBinInfo *luajit_header_parser(RzBinFile *bf, LuaJITBinInfo *bin_info, int min) {
	RzBinInfo *info = NULL;
	RzBuffer *r_buffer;
	r_buffer = bf->buf;

	if (!(info = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}

	info->file = rz_str_dup(bf->file);
	info->type = rz_str_newf("luajit 2.%d compiled file", min);
	info->bclass = rz_str_dup("luajit compiled file");
	info->rclass = rz_str_dup("luajit");
	info->arch = rz_str_newf("luajit");
	info->bits = 8;
	info->cpu = rz_str_newf("2.%d", min);
	info->lang = rz_str_dup("lua");
	info->compiler = rz_str_newf("luajit 2.%d compiler", min);

	ut64 flag = luajit_get_flag(r_buffer, LUAJIT_FLAG_OFFSET_AT);

	if (IS_FLAG(flag, LUAJIT_BCDUMP_F_BE)) {
		info->big_endian = 1;
	} else {
		info->big_endian = 0;
	}
	bin_info->hdr_flags = flag;
	bin_info->version = rz_str_newf("2.%c", min + '0');
	bin_info->header_end = LUAJIT_FILE_LEN_START;

	char *file_name = NULL;
	ut64 name_len;
	if (!IS_FLAG(flag, LUAJIT_BCDUMP_F_STRIP)) {
		int end_len;
		end_len = rz_buf_uleb128_at(r_buffer, LUAJIT_FILE_LEN_START, &name_len);
		if (check_malformed_ULEB128(end_len)) {
			RZ_FREE(info);
			return NULL;
		}
		file_name = RZ_NEWS(char, name_len + 1);
		if (file_name) {
			luajit_parse_filename(r_buffer, file_name, LUAJIT_FILE_LEN_START + end_len, (st32)name_len);
			info->guid = rz_str_dup(file_name);
			bin_info->file_name = rz_str_dup(file_name);
		} else {
			info->guid = "stripped";
			bin_info->file_name = "stripped";
		}
		// Header is not fixed size due to (ULEB128)
		bin_info->header_end = LUAJIT_FILE_LEN_START + end_len + name_len; // File Len start + uleb128 len of name length + name length
		RZ_FREE(file_name);
	}
	return info;
}

static ut64 handle_value_type(RzBuffer *buff, LuaJITValue *_value, ut64 offset, LuaJITValueType type) {
	_value->offset = offset;
	_value->type = type;

	ut64 _val, lo_val, hi_val, combined;
	int end_len;
	switch (type) {
	case LUAJIT_TNILL: // nil
	case LUAJIT_TTRUE: // true
	case LUAJIT_TFALSE: // false
		_value->size += 1;
		break;
	case LUAJIT_TINT:
		end_len = rz_buf_uleb128_at(buff, offset, &_val);
		if (check_malformed_ULEB128(end_len)) {
			free_luajit_value(_value);
			return offset;
		}
		offset += end_len;
		_value->size += end_len;

		ut64 *heap_int = RZ_NEW(ut64);
		if (heap_int) {
			*heap_int = _val;
			_value->data = heap_int;
		}
		break;

	case LUAJIT_TFLT:
		end_len = rz_buf_uleb128_at(buff, offset, &lo_val);
		if (check_malformed_ULEB128(end_len)) {
			free_luajit_value(_value);
			return offset;
		}
		offset += end_len;
		_value->size += end_len;

		end_len = rz_buf_uleb128_at(buff, offset, &hi_val);
		if (check_malformed_ULEB128(end_len)) {
			free_luajit_value(_value);
			return offset;
		}
		offset += end_len;
		_value->size += end_len;

		double *heap_double = RZ_NEW(double);
		if (heap_double) {
			combined = (hi_val << 32) | (lo_val & 0xFFFFFFFF);
			memcpy(heap_double, &combined, sizeof(double));
			_value->data = heap_double;
		}
		break;
	default:
		_value->type = type;
		char *ret = NULL;
		offset = luajit_parse_string(buff, offset, type, &ret);
		_value->data = ret;
		_value->size += (type - 5);
		break;
	}
	return offset;
}

static ut64 luajit_parse_table(LuaJITProto *proto, LuaJITKgcObj *kgc_obj, RzBuffer *buf, ut64 offset) {
	LuaJITTable *table = luajit_new_table();
	luajit_return_if_null(table, offset);

	ut64 ret;
	int i, end_len;
	i = 0;

	table->offset = offset;
	end_len = rz_buf_uleb128_at(buf, offset, &ret);
	if (check_malformed_ULEB128(end_len)) {
		luajit_free_table(table);
		return offset;
	}
	table->narray = ret;
	offset += end_len;
	table->size += end_len;

	end_len = rz_buf_uleb128_at(buf, offset, &ret);
	if (check_malformed_ULEB128(end_len)) {
		luajit_free_table(table);
		return offset;
	}
	table->nhash = ret;
	offset += end_len;
	table->size += end_len;

	for (i = 0; i < table->narray; i++) {
		end_len = rz_buf_uleb128_at(buf, offset, &ret);
		if (check_malformed_ULEB128(end_len)) {
			luajit_free_table(table);
			return offset;
		}
		offset += end_len;
		table->size += end_len;

		LuaJITValue *array_value = luajit_new_val();
		luajit_return_if_null(array_value, offset);
		offset = handle_value_type(buf, array_value, offset, ret);
		table->size += array_value->size;
		rz_list_append(table->array_items, array_value);
	}

	for (i = 0; i < table->nhash; i++) {
		end_len = rz_buf_uleb128_at(buf, offset, &ret);
		if (check_malformed_ULEB128(end_len)) {
			luajit_free_table(table);
			return offset;
		}
		offset += end_len;

		LuaJITValue *hash_key = luajit_new_val(); // For hash key
		luajit_return_if_null(hash_key, offset);
		offset = handle_value_type(buf, hash_key, offset, ret);
		table->size += hash_key->size;
		rz_list_append(table->hash_keys, hash_key);

		end_len = rz_buf_uleb128_at(buf, offset, &ret);
		if (check_malformed_ULEB128(end_len)) {
			luajit_free_table(table);
			return offset;
		}
		offset += end_len;

		LuaJITValue *hash_val = luajit_new_val(); // For hash value
		luajit_return_if_null(hash_val, offset);
		offset = handle_value_type(buf, hash_val, offset, ret);
		table->size += hash_val->size;
		rz_list_append(table->hash_values, hash_val);
	}
	kgc_obj->size += table->size;
	rz_list_append(proto->table, table);
	return offset;
}

static ut64 handle_kgc_type(LuaJITProto *proto, LuaJITKgcObj *kgc_obj, RzBuffer *buf, RzList /*LuaJITProto*/ *proto_stack, ut64 offset, LuaJITKGCTypes type) {
	kgc_obj->type = type;

	switch (type) {
	case LUAJIT_KGCCHILD: {
		void *tmp = rz_list_pop(proto_stack);
		LuaJITProto *child = (LuaJITProto *)rz_list_pop(proto_stack);
		rz_list_append(proto->proto_entries, child);
		rz_list_append(proto_stack, tmp);
		break;
	}
	case LUAJIT_KGCTABLE:
		offset = luajit_parse_table(proto, kgc_obj, buf, offset);
		break;

	case LUAJIT_KGCINT:
	case LUAJIT_KGCFLT: {
		ut64 combined;
		READ_SPLIT_64(combined);

		ut64 *num_val = RZ_NEW(ut64);
		if (num_val) {
			*num_val = combined;
			kgc_obj->data = num_val;
		}
		break;
	}
	case LUAJIT_KGCCMPLX: {
		ut64 r_combined, i_combined;

		READ_SPLIT_64(r_combined);
		READ_SPLIT_64(i_combined);

		memcpy(&(kgc_obj->cmplx.r_bits), &r_combined, sizeof(double));
		memcpy(&(kgc_obj->cmplx.i_bits), &i_combined, sizeof(double));
		break;
	}
	default: {
		kgc_obj->type = type;
		char *ret = NULL;
		offset = luajit_parse_string(buf, offset, type, &ret);
		kgc_obj->size += (type - 5);
		kgc_obj->data = ret;
		break;
	}
	}
	return offset;
}

static ut64 parse_kgc_objects(RzBuffer *buff, LuaJITProto *proto, RzList /*<LuaJITProto>*/ *proto_stack, ut64 offset_from) {
	int i, end_len;
	ut64 off = offset_from;
	ut64 ret;
	for (i = 0; i < proto->k_const; i++) {
		LuaJITKgcObj *kgc_obj = luajit_kgc_obj_new();
		luajit_return_if_null(kgc_obj, off);
		kgc_obj->offset = off;
		end_len = rz_buf_uleb128_at(buff, off, &ret);
		if (check_malformed_ULEB128(end_len)) {
			luajit_free_kgc_obj(kgc_obj);
			return off;
		}
		off += end_len;
		kgc_obj->size += end_len;
		off = handle_kgc_type(proto, kgc_obj, buff, proto_stack, off, ret);
		rz_list_append(proto->kgc_obj, kgc_obj);
	}
	return off;
}

static ut64 parse_constant_entries(RzBuffer *buf, LuaJITProto *proto, ut64 offset) {
	int i, end_len;
	ut64 ret;

	for (i = 0; i < proto->num_const; i++) {
		LuaJITConstEntry *constant = luajit_new_constant();
		luajit_return_if_null(constant, offset);
		end_len = rz_buf_uleb128_at(buf, offset, &ret);
		if (check_malformed_ULEB128(end_len)) {
			RZ_FREE(constant);
			return offset;
		}
		constant->offset = offset;
		offset += end_len;
		constant->size += end_len;

		if ((ret & 1) == 0) {
			constant->type = LUAJIT_TINT;
			ut32 *int_val = RZ_NEW(ut32);
			if (!int_val) {
				RZ_FREE(constant);
				return offset;
			}
			*int_val = (ut32)(ret >> 1);
			constant->constant_val = int_val;
		} else {
			constant->type = LUAJIT_TFLT;
			ut32 lo = (ut32)(ret >> 1);
			ut64 hi_val;

			end_len = rz_buf_uleb128_at(buf, offset, &hi_val);
			if (check_malformed_ULEB128(end_len)) {
				RZ_FREE(constant);
				return offset;
			}
			offset += end_len;
			constant->size += end_len;

			ut32 hi = (ut32)hi_val;
			ut64 *float_val = RZ_NEW(ut64);
			if (!float_val) {
				RZ_FREE(constant);
				return offset;
			}

			*float_val = ((ut64)hi << 32) | (ut64)lo;
			constant->constant_val = float_val;
		}
		rz_list_append(proto->constant_entries, constant);
	}
	return offset;
}

static void parse_debug_info(RzBuffer *buf, LuaJITProto *proto, ut64 offset) {
	ut64 curr = offset;
	proto->debug_info_offset = offset;
	int width = (proto->hdr_dbg->lines_covered < 256) ? 1 : (proto->hdr_dbg->lines_covered < 65536) ? 2
													: 4;

	int iter = 0;
	if (curr >= proto->end_offset) {
		return;
	}
	int line_info_size = proto->num_istr_cnt * width;
	proto->dbg_info_size += line_info_size;
	curr += line_info_size;

	iter = 0;
	while (curr < proto->end_offset && iter < proto->num_up_val) {
		ut8 byte;
		// TODO: End of bytes or string check
		if (rz_buf_read8_at(buf, curr, &byte) != 1 || byte == 0) {
			break;
		}
		LuaJITUpValue *up_val = luajit_new_upvalue();
		if (!up_val) {
			break;
		}
		up_val->offset = curr;
		rz_buf_seek(buf, curr, RZ_BUF_SET);
		char *str = NULL;
		int len = rz_buf_read_string(buf, &str);
		if (len < 0 && str == NULL) {
			free(up_val);
			break;
		}
		up_val->uv_name = str;
		curr += len;
		up_val->size = curr - up_val->offset;
		rz_list_append(proto->up_val_info, up_val);
		iter++;
	}

	while (curr < proto->end_offset) {
		ut8 byte;
		// TODO: End of bytes or string check
		if (rz_buf_read8_at(buf, curr, &byte) != 1 || byte == 0) {
			break;
		}

		LuaJITLocalVar *local_var = luajit_new_localvar();
		if (!local_var) {
			break;
		}
		local_var->offset = curr;
		rz_buf_seek(buf, curr, RZ_BUF_SET);
		char *str = NULL;
		ut64 len = rz_buf_read_string(buf, &str);
		if (len < 0 && str == NULL) {
			free(local_var);
			break;
		}
		local_var->varname = str;
		curr += len;

		ut64 tmp_val;
		int end_len = rz_buf_uleb128_at(buf, curr, &tmp_val);
		if (check_malformed_ULEB128(end_len)) {
			free(local_var->varname);
			free(local_var);
			break;
		}
		local_var->start_pc = tmp_val;
		curr += end_len;
		end_len = rz_buf_uleb128_at(buf, curr, &tmp_val);
		if (check_malformed_ULEB128(end_len)) {
			free(local_var->varname);
			free(local_var);
			break;
		}
		local_var->varname_len = len;
		curr += end_len;
		local_var->size = curr - local_var->offset;
		rz_list_append(proto->local_var_entry, local_var);
	}
}

RZ_IPI LuaJITProto *luajit_parse_proto(RzBuffer *buff, RzList /*<LuaJITProto>*/ *proto_list, ut64 base_offset, ut64 byte_rd, bool last_proto) {
	LuaJITProto *proto = luajit_new_proto();
	luajit_return_if_null(proto, NULL);
	RzListIter *iter;
	ut64 offset, U_ret;
	ut8 ret;
	int buff_size, bytes_read_rem, end_len;
	buff_size = rz_buf_size(buff);
	if (last_proto) {
		bytes_read_rem = buff_size - byte_rd;
	} else {
		bytes_read_rem = byte_rd;
	}
	rz_list_append(proto_list, proto); // The nested proto is added to the list which will be attached to parent proto while parsing KGC object

	// Proto Header
	offset = base_offset;
	proto->start_offset = offset;
	end_len = rz_buf_uleb128_at(buff, offset, &U_ret);
	if (check_malformed_ULEB128(end_len)) {
		return NULL;
	}
	proto->hdr_size += end_len;
	bytes_read_rem = bytes_read_rem - (U_ret + end_len); // reamaining_bytes_to_read - (size_of_proto + number of bytes holding size)
	proto->size = U_ret;
	proto->end_offset = proto->start_offset + proto->size + end_len;
	offset += end_len;
	proto->hdr_size += 1; // Flags skip
	offset += 1;
	if (!rz_buf_read8_at(buff, offset, &ret)) {
		return NULL;
	}
	proto->hdr_size += 1; // Number of params skip
	offset += 1;

	if (!rz_buf_read8_at(buff, offset, &ret)) {
		return NULL;
	}
	proto->hdr_size += 1; // Frame size skip
	offset += 1;

	if (!rz_buf_read8_at(buff, offset, &ret)) {
		return NULL;
	}
	proto->hdr_size += 1;
	proto->num_up_val = (st32)ret;
	offset += 1;

	end_len = rz_buf_uleb128_at(buff, offset, &U_ret);
	if (check_malformed_ULEB128(end_len)) {
		return NULL;
	}
	proto->hdr_size += end_len;
	offset += end_len;
	proto->k_const = U_ret;

	end_len = rz_buf_uleb128_at(buff, offset, &U_ret);
	if (check_malformed_ULEB128(end_len)) {
		return NULL;
	}
	proto->hdr_size += end_len;
	offset += end_len;
	proto->num_const = U_ret;

	end_len = rz_buf_uleb128_at(buff, offset, &U_ret);
	if (check_malformed_ULEB128(end_len)) {
		return NULL;
	}
	proto->hdr_size += end_len;
	offset += end_len;
	proto->num_istr_cnt = U_ret;

	proto->hdr_dbg->offset = offset;
	end_len = rz_buf_uleb128_at(buff, offset, &U_ret);
	if (check_malformed_ULEB128(end_len)) {
		return NULL;
	}
	proto->hdr_size += end_len;
	offset += end_len;
	proto->hdr_dbg->size += end_len;
	proto->hdr_dbg->dbg_len = U_ret;

	if (proto->hdr_dbg->dbg_len > 0) {
		end_len = rz_buf_uleb128_at(buff, offset, &U_ret);
		if (check_malformed_ULEB128(end_len)) {
			return NULL;
		}
		proto->hdr_size += end_len;
		offset += end_len;
		proto->hdr_dbg->first_line = U_ret;
		proto->hdr_dbg->size += end_len;
		end_len = rz_buf_uleb128_at(buff, offset, &U_ret);
		if (check_malformed_ULEB128(end_len)) {
			return NULL;
		}
		proto->hdr_size += end_len;
		offset += end_len;
		proto->hdr_dbg->lines_covered = U_ret;
		proto->hdr_dbg->size += end_len;
	} else {
		proto->hdr_dbg->lines_covered = 0;
		proto->hdr_dbg->first_line = 0;
	}

	// Proto Body
	if (proto->num_istr_cnt > 0) {
		proto->instr_offset = offset;
		offset += proto->num_istr_cnt * 4; //< Instructions 4 bytes
	}

	if (proto->num_up_val > 0) {
		proto->up_val_entry_offset = offset;
		offset += proto->num_up_val * 2; //< Halfword (2 bytes)
	}

	/* NOTE: parse_kgc_objects() and parse_constant_entries() returns the next read offset
	 but its not same in parse_debbug_info it returns the last offset where the proto ends */
	if (proto->k_const > 0) {
		offset = parse_kgc_objects(buff, proto, proto_list, offset);
	}
	if (proto->num_const > 0) {
		offset = parse_constant_entries(buff, proto, offset);
	}
	parse_debug_info(buff, proto, offset);

	last_proto = false;

	if (bytes_read_rem > 1) { // The last bytes will be 00
		return luajit_parse_proto(buff, proto_list, proto->end_offset, bytes_read_rem, last_proto);
	} else { // Left children are merged to main
		LuaJITProto *left_children;
		rz_list_pop(proto_list);
		rz_list_foreach (proto_list, iter, left_children) {
			rz_list_append(proto->proto_entries, left_children);
		}
	}
	return proto;
}