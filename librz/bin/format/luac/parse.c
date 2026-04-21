// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "librz/bin/format/luac/luac_common.h"

#ifdef RZ_DEBUG
#define CHECK_SIZE \
	if (offset >= bf->size) { \
		RZ_LOG_ERROR("Truncated Header (line: %d)\n", __LINE__); \
		return 0; \
	}
#else
#define CHECK_SIZE rz_return_val_if_fail((offset < bf->size), 0)
#endif

static ut8 read8(RzBuffer *buffer, ut64 *offset, ut8 *receiver) {
	ut8 tmp;
	if (!rz_buf_read_ble8_offset(buffer, offset, &tmp, false)) {
		return 0;
	}
	*receiver = tmp;
	return tmp;
}

#define READ8_CHECK_SIZE(buffer, offset, receiver) \
	{ \
		read8(buffer, &offset, &receiver); \
		CHECK_SIZE; \
	}

static int read8_check_val(RzBuffer *buffer, ut64 *offset, const ut16 val, const char *err) {
	ut8 tmp = 0;
	read8(buffer, offset, &tmp);
	if (tmp != val) {
		RZ_LOG_ERROR("%s\n", err);
		return 0;
	}
	return 1;
}

#define READ8_CHECK_VAL(buffer, offset, val, err) \
	read8_check_val(buffer, offset, val, err); \
	CHECK_SIZE;

static ut64 lua_load_integer(RzBuffer *buffer, ut64 offset) {
	ut64 x = 0;
	rz_buf_read_le64_at(buffer, offset, &x);
	return x;
}

static double lua_load_number(RzBuffer *buffer, ut64 offset) {
	double x = 0;
	rz_buf_read_le64_at(buffer, offset, (ut64 *)&x);
	return x;
}

static ut32 lua_load_int(RzBuffer *buffer, ut64 offset) {
	ut32 x = 0;
	rz_buf_read_le32_at(buffer, offset, &x);
	return x;
}

// return an offset to skip string, return 1 if no string (0x80)
static ut64 lua_parse_szint(RzBuffer *buffer, st32 *size, ut64 offset, ut64 data_size, ut8 minor) {
	st32 result = 0;
	st32 i = 0;
	ut8 b;
	st32 shift = 0;
	while (offset + i < data_size) {
		if (!rz_buf_read8_at(buffer, offset + i, &b)) {
			return 0;
		}
		i++;
		if (minor == 4) {
			result = (result << 7) | (b & 0x7f);
			if (b & 0x80) {
				*size = result;
				return i;
			}
		} else if (minor == 5) {
			result |= (b & 0x7f) << shift;
			if (!(b & 0x80)) {
				*size = result;
				return i;
			}
			shift += 7;
			if (shift >= 64)
				break;
		}
	}
	return i;
}

static ut64 lua_parse_number(RzBuffer *buffer, st32 *size, ut64 offset, ut64 data_size, ut8 minor) {
	if (minor >= 4) {
		return lua_parse_szint(buffer, size, offset, data_size, minor);
	}
	if (minor <= 3) {
		const size_t size_offset = sizeof(LUA_INT);
		if (size_offset + offset > data_size) {
			RZ_LOG_ERROR("file truncated, offset: %" PFMT64u ", data size: %" PFMT64u "\n", offset, data_size);
			return 0;
		}
		*size = (st32)lua_load_int(buffer, offset);
		return size_offset;
	}
	return 0;
}

static ut64 lua_parse_line_defined(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, ut8 minor) {
	ut64 size_offset = 0;
	int line_defined = 0;
	int last_line_defined = 0;

	size_offset = lua_parse_number(buffer, &line_defined, offset, data_size, minor);
	lua_check_error_offset(size_offset);

	/* Set Proto Member */
	proto->line_defined = (ut32)line_defined;

	if (minor == 0) {
		return size_offset;
	}

	const ut64 delta_offset = lua_parse_number(buffer, &last_line_defined, offset + size_offset, data_size, minor);
	lua_check_error_offset(delta_offset);
	size_offset += delta_offset;

	proto->lastline_defined = (ut32)last_line_defined;
	return size_offset;
}

static ut64 lua_parse_string(RzBuffer *buffer, ut8 **dest, int *str_len, ut64 offset, ut64 data_size, ut8 minor, ut8 num_size) {
	ut64 size_offset = 0;
	int ret_buf_size = 0;
	int string_len = 0;
	ut8 *ret = 0x00;

	const ut64 base_offset = offset;

	if (minor <= 2) {
		ut16 tmp16 = 0;
		if (!rz_buf_read_le16_at(buffer, offset, &tmp16)) {
			return 0;
		}
		ret_buf_size = (int)tmp16;
		size_offset = num_size;
		offset += size_offset;
	} else if (minor == 3) {
		ut8 tmp = 0;
		if (!rz_buf_read8_at(buffer, offset, &tmp)) {
			return 0;
		}
		ret_buf_size = (int)tmp;
		size_offset = 1;
		if (ret_buf_size == 0xFF) {
			offset += size_offset;
			ut16 tmp16 = 0;
			if (!rz_buf_read_le16_at(buffer, offset, &tmp16)) {
				return 0;
			}
			ret_buf_size = (int)tmp16;
			size_offset = num_size;
		}
		offset += size_offset;
	} else if (minor >= 4) {
		size_offset = lua_parse_szint(buffer, &ret_buf_size, offset, data_size, minor);
		lua_check_error_offset(size_offset);
		offset += size_offset;
	}

	/* no string */
	if (ret_buf_size == 0) {
		ret = NULL;
		string_len = 0;
	} else {
		/* skip size byte */
		string_len = ret_buf_size - 1;
		ret = RZ_NEWS(ut8, ret_buf_size);
		if (ret == NULL) {
			string_len = 0;
		} else {
			rz_buf_read_at(buffer, offset, ret, string_len);
			ret[string_len] = 0x00;
		}
		offset += string_len;
	}

	/* set to outside vars */
	if (dest && str_len) {
		*dest = ret;
		*str_len = string_len;
	} else {
		RZ_LOG_ERROR("Cannot store string\n");
	}

	if (((minor == 0) && (ret_buf_size > 0)) || (minor == 2) || (minor == 5))
		offset++;
	return offset - base_offset;
}

static ut64 lua_parse_name(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, ut8 minor) {
	return lua_parse_string(buffer, &proto->proto_name, &proto->name_size, offset, data_size, minor, proto->num_size);
}

static ut64 lua_parse_code(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, ut8 minor) {
	ut64 size_offset = 0;
	int code_size = 0; ///< instructions

	size_offset = lua_parse_number(buffer, &code_size, offset, data_size, minor);
	lua_check_error_offset(size_offset);

	if (minor == 5) {
		const ut64 aligned_size = (offset + size_offset + 3) & ~3;
		size_offset = aligned_size - offset;
	}
	const ut8 instruction_size = (minor == 0) ? 8 : 4;
	const ut64 total_size = code_size * instruction_size + size_offset;
	if (total_size + offset > data_size) {
		RZ_LOG_ERROR("Truncated Code at [0x%" PFMT64x "]\n", offset);
		return 0;
	}

	/* Set Proto Member */
	proto->code_size = code_size * instruction_size;
	proto->code_skipped = size_offset;
	return total_size;
}

static ut64 lua_parse_const_entry(const LuaProto *proto, RzBuffer *buffer, int index, ut64 offset, ut64 prev_offset, ut64 data_size, ut8 minor) {
	ut8 *recv_data = NULL;
	int data_len = 0;

	LuaConstEntry *current_entry = lua_new_const_entry();
	const ut64 k_vaddr_base = K_VADDRESS_BASE(proto->index);
	current_entry->offset = offset;
	current_entry->prev_offset = prev_offset;
	current_entry->voffset = k_vaddr_base + prev_offset;
	current_entry->string_start = current_entry->voffset + 2;
	const ut64 base_offset = offset;
	ut64 delta_offset = 0;

	/* read TAG byte */
	if (offset + 1 > data_size) {
		return 0;
	}
	if (!rz_buf_read8_at(buffer, offset, &current_entry->tag)) {
		return 0;
	}
	offset += 1;

	ut8 tmp;
	/* read data */
	switch (current_entry->tag) {
	case LUA_VNUMINT:
		data_len = sizeof(LUA_NUMBER);
		recv_data = RZ_NEWS(ut8, data_len);
		rz_buf_read_le64_at(buffer, offset, (ut64 *)recv_data);
		if (offset + data_len > data_size) {
			RZ_FREE(recv_data);
			return 0;
		}
		delta_offset = data_len;
		if (minor == 3) {
			current_entry->tag = LUA_VNUMFLT; // keep the same with 5.4 tag
			break;
		}
		if ((minor == 0) || (minor == 1) || (minor == 2)) {
			double intPart1;
			const double r = *(double *)recv_data;
			const double fractionalPart = modf(r, &intPart1);
			if (fractionalPart == 0.0) {
				current_entry->tag = LUA_VNUMINT; // keep the same with 5.4 tag
				*(ut64 *)recv_data = (ut64)intPart1;
			} else {
				current_entry->tag = LUA_VNUMFLT; // keep the same with 5.4 tag
			}
		}
		break;
	case LUA_VNUMFLT:
#if 0
		// TODO: need check on other platforms
		if (minor >= 4) {
			data_len = 8;
		} else if (minor == 2) {
			data_len = sizeof(LUA_NUMBER);
		} else if (minor == 3) {
			data_len = sizeof(LUA_INTEGER);
		}
#else
		data_len = sizeof(LUA_NUMBER);
		if (minor == 3) {
			data_len = sizeof(LUA_INTEGER);
		}
#endif
		recv_data = RZ_NEWS(ut8, data_len);
		rz_buf_read_le64_at(buffer, offset, (ut64 *)recv_data);
		if (offset + data_len > data_size) {
			RZ_FREE(recv_data);
			return 0;
		}
		delta_offset = data_len;
		current_entry->tag = LUA_VNUMINT; // keep the same with 5.4 tag
		break;
	case LUA_VSHRSTR:
	case LUA_VLNGSTR:
		delta_offset = lua_parse_string(buffer, &recv_data, &data_len, offset, data_size, minor, proto->num_size);
		lua_check_error_offset(delta_offset);
		if (minor == 1)
			delta_offset++;
		if (!recv_data) {
			if (!rz_buf_read8_at(buffer, offset + 1, &tmp)) {
				return 0;
			}
			tmp -= 1;
			data_len = 1;
			recv_data = RZ_NEWS(ut8, data_len);
			rz_write_ble8(recv_data, tmp);
			current_entry->tag = LUA_VSTRING_IDX;
		}
		break;
	case LUA_VFALSE:
	case LUA_VTRUE:
		recv_data = RZ_NEWS(ut8, 1);
		data_len = 1;
		delta_offset = 0;
		if (minor == 4 || minor == 5) {
			*recv_data = current_entry->tag == LUA_VTRUE ? 1 : 0;
		} else {
			if (!rz_buf_read8_at(buffer, offset, (ut8 *)recv_data)) {
				return 0;
			}
			delta_offset++;
		}
		break;
	case LUA_OPENWRT_INT32:
		data_len = 4;
		recv_data = RZ_NEWS(ut8, data_len);
		rz_buf_read_le16_at(buffer, offset, (ut16 *)recv_data);
		if (offset + data_len > data_size) {
			RZ_FREE(recv_data);
			return 0;
		}
		delta_offset += data_len;
		break;
	case LUA_TNIL:
	default:
		recv_data = NULL;
		data_len = 0;
		delta_offset = 0;
		break;
	}
	offset += delta_offset;

	current_entry->data = recv_data;
	current_entry->data_len = data_len;

	/* add to list */
	rz_pvector_push(proto->const_entries, current_entry);
	return offset - base_offset;
}

static ut64 lua_parse_consts(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, ut8 minor) {
	int consts_cnt = 0;
	ut64 delta_offset = 0;

	const ut64 base_offset = offset;

	/* parse number of constants */
	delta_offset = lua_parse_number(buffer, &consts_cnt, offset, data_size, minor);
	lua_check_error_offset(delta_offset);

	offset += delta_offset;
	ut64 prev_offset = 0;
	for (int i = 0; i < consts_cnt; ++i) {
		delta_offset = lua_parse_const_entry(proto, buffer, i, offset, prev_offset, data_size, minor);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;
		prev_offset += delta_offset;
	}

	proto->const_size = offset - (base_offset + 1);
	return offset - base_offset;
}

static ut64 lua_parse_upvalue_entry(const LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, ut8 minor) {
	const ut64 base_offset = offset;
	LuaUpvalueEntry *current_entry = lua_new_upvalue_entry();
	current_entry->offset = base_offset;
	current_entry->voffset = proto->index * 0x1000 + UPVALUE_OFFSET;

	// no kind in lua 5.3
	const int need_kind = (minor <= 3) ? 2 : 3;

	if (offset + need_kind > data_size) {
		return 0;
	}

	/* read instack/idx attr */
	if (!rz_buf_read8_at(buffer, offset + 0, &current_entry->instack)) {
		return 0;
	}
	if (!rz_buf_read8_at(buffer, offset + 1, &current_entry->idx)) {
		return 0;
	}
	current_entry->kind = 0;
	if (minor <= 3) {
		if (!rz_buf_read8_at(buffer, offset + 2, &current_entry->kind)) {
			return 0;
		}
	}
	offset += need_kind;

	/* add to list */
	rz_pvector_push(proto->upvalue_entries, current_entry);
	return offset - base_offset;
}

static ut64 lua_parse_upvalues(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, ut8 minor) { // ?
	int upvalues_cnt = 0;
	ut64 delta_offset = 0;
	const ut64 base_offset = offset;

	/* parse number of upvalues */
	delta_offset = lua_parse_number(buffer, &upvalues_cnt, offset, data_size, minor);
	lua_check_error_offset(delta_offset);

	offset += delta_offset;
	for (int i = 0; i < upvalues_cnt; ++i) {
		delta_offset = lua_parse_upvalue_entry(proto, buffer, offset, data_size, minor);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;
	}
	proto->upvalue_size = offset - base_offset + 1;

	if (minor == 2)
		proto->upvalue_size++; // TODO: check this

	return offset - base_offset;
}

static ut64 lua_parse_debug(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, ut8 minor) {
	int entries_cnt = 0;
	ut64 delta_offset = 0;
	ut64 base_offset = offset;

	/* parse line info */
	delta_offset = lua_parse_number(buffer, &entries_cnt, offset, data_size, minor);
	lua_check_error_offset(delta_offset);

	offset += delta_offset;
	ut32 line_num = proto->line_defined;
	for (int i = 0; i < entries_cnt; ++i) {
		LuaLineinfoEntry *info_entry = lua_new_lineinfo_entry();
		if (minor > 3) {
			ut64 ad = PROTO_VADDRESS(proto->index);
			// READ8(buffer, offset, info_entry->info_data);
			read8(buffer, &offset, &info_entry->info_data);
			info_entry->info_data = line_num += DEBUG_LINE_OFFSET((st32)info_entry->info_data);
			info_entry->offset = ad += i * 4;
		} else {
			info_entry->offset = offset;
			info_entry->info_data = lua_load_int(buffer, offset);
			offset += sizeof(LUA_INT);
		}
		rz_list_append(proto->line_info_entries, info_entry);
	}
	if (minor >= 4) {
		/* parse absline info */
		delta_offset = lua_parse_szint(buffer, &entries_cnt, offset, data_size, minor);
		lua_check_error_offset(delta_offset);
		RZ_LOG_DEBUG("abs_info_entry entries_cnt: %d (offset: 0x%" PFMT64x ")\n", entries_cnt, offset);
		offset += delta_offset;
		for (int i = 0; i < entries_cnt; ++i) {
			LuaAbsLineinfoEntry *abs_info_entry = lua_new_abs_lineinfo_entry();
			abs_info_entry->offset = offset;

			delta_offset = lua_parse_szint(buffer, &abs_info_entry->pc, offset, data_size, minor);
			lua_check_error_offset(delta_offset);
			offset += delta_offset;

			delta_offset = lua_parse_szint(buffer, &abs_info_entry->line, offset, data_size, minor);
			lua_check_error_offset(delta_offset);
			offset += delta_offset;

			rz_list_append(proto->abs_line_info_entries, abs_info_entry);
		}
	}

	/* parse local vars */
	delta_offset = lua_parse_number(buffer, &entries_cnt, offset, data_size, minor);
	lua_check_error_offset(delta_offset);

	offset += delta_offset;
	proto->local_var_offset = offset;
	proto->local_var_size = 0;
	ut64 prev_offset = 0;
	for (int i = 0; i < entries_cnt; ++i) {
		LuaLocalVarEntry *var_entry = lua_new_local_var_entry();
		var_entry->offset = offset;

		const ut64 k_vaddr_base = VAR_VADDRESS_BASE(proto->index);
		var_entry->voffset = k_vaddr_base + prev_offset;
		/* string */
		delta_offset = lua_parse_string(
			buffer,
			&var_entry->varname, &var_entry->varname_len,
			offset, data_size, minor, proto->num_size);
		lua_check_error_offset(delta_offset);
		if (minor == 1)
			delta_offset++;
		offset += delta_offset;

		/* start pc -- int */
		delta_offset = lua_parse_number(buffer, &var_entry->start_pc, offset, data_size, minor);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;

		/* end pc -- int */
		delta_offset = lua_parse_number(buffer, &var_entry->end_pc, offset, data_size, minor);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;

		prev_offset += (offset - var_entry->offset);
		var_entry->var_size = (offset - var_entry->offset);
		proto->local_var_size += var_entry->var_size;
		rz_pvector_push(proto->local_var_info_entries, var_entry);
	}

	/* parse upvalue */
	delta_offset = lua_parse_number(buffer, &entries_cnt, offset, data_size, minor);
	lua_check_error_offset(delta_offset);
	offset += delta_offset;
	for (int i = 0; i < entries_cnt; ++i) {
		LuaUpvalueEntry *up = rz_pvector_at(proto->upvalue_entries, i);
		if (!up) {
			RZ_LOG_ERROR("invalid upvalue");
			continue;
		}
		up->name_offset = offset;

		delta_offset = lua_parse_string(
			buffer,
			&up->upvalue_name,
			&up->name_len,
			offset, data_size, minor, proto->num_size);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;
	}

	proto->debug_size = offset - base_offset + 1;
	return offset - base_offset;
}

static ut64 lua_parse_protos(LuaProto *proto, RzBuffer *buffer, LuaHeaderInfo *header, ut64 offset, ut64 data_size) {
	rz_return_val_if_fail(proto, 0);
	int proto_cnt = 0;
	ut64 delta_offset = 0;
	const ut64 base_offset = offset; // store origin offset
	const ut8 minor = header->minor;

	delta_offset = lua_parse_number(buffer, &proto_cnt, offset, data_size, minor);
	lua_check_error_offset(delta_offset);
	offset += delta_offset;
	for (int i = 0; i < proto_cnt; ++i) {
		LuaProto *current_proto = lua_parse_body(buffer, header, offset, data_size);
		lua_return_if_null(current_proto);
		rz_list_append(proto->proto_entries, current_proto);
		offset += current_proto->size - 1; // update offset
	}
	// return the delta between offset and base_offset
	return offset - base_offset;
}

LuaProto *lua_parse_body(RzBuffer *buffer, LuaHeaderInfo *header, ut64 base_offset, ut64 data_size) {
	LuaProto *ret_proto = lua_new_proto_entry(); /* constructed proto for return */
	rz_return_val_if_fail(ret_proto, NULL);
	ret_proto->index = header->proto_count;
	header->proto_count++;
	ret_proto->num_size = header->is_openwrt ? 4 : sizeof(LUA_NUMBER);

	const ut8 minor = header->minor;
	ut64 delta_offset = 0;

	// start parsing
	ut64 offset = base_offset; /* record offset */

	/* record offset of main proto */
	ret_proto->offset = offset;

	if ((minor == 0) || (minor == 1) || (minor == 3) || (minor == 4)) {
		/* parse proto name of main proto */
		delta_offset = lua_parse_name(ret_proto, buffer, offset, data_size, minor);
		if (minor == 1) {
			if (delta_offset > sizeof(LUA_NUMBER)) {
				delta_offset += 2;
			}
		}
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;
	}

	/* parse line defined info */
	delta_offset = lua_parse_line_defined(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	if ((minor == 1) && (ret_proto->line_defined > 0)) {
		offset++;
	}

	if (minor == 0) {
		int size_upvalues = 0;
		ut8 tmp;
		if (!rz_buf_read8_at(buffer, offset, &tmp)) {
			return 0;
		}
		offset++;
		size_upvalues = tmp;
		(void)size_upvalues;
	}

	/* parse num params max_stack_size */
	if (offset + 3 > data_size) {
		lua_free_proto_entry(ret_proto);
		return NULL;
	}

	if (!rz_buf_read8_at(buffer, offset + 0, &ret_proto->num_params) ||
		!rz_buf_read8_at(buffer, offset + 1, &ret_proto->is_vararg) ||
		!rz_buf_read8_at(buffer, offset + 2, &ret_proto->max_stack_size)) {
		lua_free_proto_entry(ret_proto);
		return NULL;
	}
	offset += 3;

	if (minor == 0) {
		/* parse debug */
		ret_proto->debug_offset = offset;
		delta_offset = lua_parse_debug(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* parse constants */
		ret_proto->const_offset = offset;
		delta_offset = lua_parse_consts(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* parse inner protos */
		ret_proto->inner_proto_offset = offset;
		delta_offset = lua_parse_protos(ret_proto, buffer, header, offset, data_size);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* specially handle recursive protos size */
		ret_proto->inner_proto_size = offset - ret_proto->inner_proto_offset;
	}

	/* parse code */
	ret_proto->code_offset = offset;
	delta_offset = lua_parse_code(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	if (minor == 0) {
		ret_proto->size = offset - base_offset + 1;
		return ret_proto;
	}

	/* parse constants */
	ret_proto->const_offset = offset + 1;
	delta_offset = lua_parse_consts(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	if ((minor == 1) || (minor == 2)) {
		/* parse inner protos */
		ret_proto->inner_proto_offset = offset;
		delta_offset = lua_parse_protos(ret_proto, buffer, header, offset, data_size);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* specially handle recursive protos size */
		ret_proto->inner_proto_size = offset - ret_proto->inner_proto_offset;
	}

	if (minor > 2) {
		/* parse upvalues */
		ret_proto->upvalue_offset = offset;
		delta_offset = lua_parse_upvalues(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* parse inner protos */
		ret_proto->inner_proto_offset = offset;
		delta_offset = lua_parse_protos(ret_proto, buffer, header, offset, data_size);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* specially handle recursive protos size */
		ret_proto->inner_proto_size = offset - ret_proto->inner_proto_offset;
	}

	if (minor == 5) {
		/* parse proto name of main proto */
		delta_offset = lua_parse_name(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);

		if (ret_proto->proto_name) {
			header->src_file_name = rz_str_dup((char *)ret_proto->proto_name);
		}

		offset += delta_offset;
	}

	if (minor == 2) {
		/* parse upvalues */
		ret_proto->upvalue_offset = offset;
		delta_offset = lua_parse_upvalues(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* parse proto name of main proto */
		delta_offset = lua_parse_name(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;
	}
	/* parse debug */
	ret_proto->debug_offset = offset;
	delta_offset = lua_parse_debug(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	ret_proto->size = offset - base_offset + 1;
	return ret_proto;
}

size_t parse_header(const RzBinFile *bf, LuaHeaderInfo *header) {
	RzBuffer *buffer = bf->buf;
	ut8 major_minor_version = 0x00;

	ut64 offset = strlen(LUAC_MAGIC);
	CHECK_SIZE;

	rz_buf_read8_at(buffer, offset, &major_minor_version); /* 1-byte in fact */
	const ut8 major = (ut8)(major_minor_version & 0xF0) >> 4;
	const ut8 minor = (ut8)(major_minor_version & 0x0F);

	if (major != 5) {
		RZ_LOG_ERROR("currently support lua 5.x only\n");
		return 0;
	}

	if (minor > 5) {
		RZ_LOG_ERROR("lua 5.%c not support now\n", header->minor + '0');
		return 0;
	}

	offset++;
	CHECK_SIZE;

	/* read header members from work buffer */
	/* is official compiler (minor > 0) */
	if (minor > 0) {
		READ8_CHECK_SIZE(buffer, offset, header->format);
	}

	/* check luac data if minor > 2 */
	if (minor > 2) {
		offset += strlen(LUAC_DATA);
		CHECK_SIZE;
	} else {
		READ8_CHECK_SIZE(buffer, offset, header->endianness);
	}

	/* get int size on 5.1, 5.2, 5.3, 5.5 */
	if (minor == 5) {
		st32 tmp = 0;
		const ut64 size_offset = lua_parse_szint(buffer, &tmp, offset, bf->size, minor);
		header->int_size = (ut32)tmp;
		offset += size_offset;
		CHECK_SIZE;
		const ut32 test_valid = lua_load_int(buffer, offset);
		(void)test_valid;
		offset += header->int_size;
	} else if (minor <= 3) { ///< TODO: ????? need 3?
		READ8_CHECK_SIZE(buffer, offset, header->int_size);
		header->integer_size = 4;
	} else {
		header->int_size = 4;
	}
	CHECK_SIZE;

	/* get size_t size on 5.1, 5.2, 5.3 */
	if (minor <= 3) {
		READ8_CHECK_SIZE(buffer, offset, header->size_t_size);
	}

	/* get instruction size */
	if (minor == 5) {
		st32 tmp = 0;
		const ut64 size_offset = lua_parse_szint(buffer, &tmp, offset, bf->size, minor);
		header->instruction_size = (ut32)tmp;
		offset += size_offset;
		CHECK_SIZE;

		const ut32 test_valid = lua_load_int(buffer, offset);
		offset += header->instruction_size;
		CHECK_SIZE;

		if (test_valid != LUAC5_INT_VALIDATION) {
			RZ_LOG_ERROR("Integer format does not match with the expected integer\n");
			return 0;
		}
	} else {
		READ8_CHECK_SIZE(buffer, offset, header->instruction_size);
	}

	if (minor == 0) {
		READ8_CHECK_VAL(buffer, &offset, 6, "Wrong size of SIZE_OP");
		READ8_CHECK_VAL(buffer, &offset, 8, "Wrong size of SIZE_A");
		READ8_CHECK_VAL(buffer, &offset, 9, "Wrong size of SIZE_B");
		READ8_CHECK_VAL(buffer, &offset, 9, "Wrong size of SIZE_C");
	}

	/* get lua integer size on luac > 5.3 */
	if (minor == 5) {
		st32 tmp = 0;
		const ut64 size_offset = lua_parse_szint(buffer, &tmp, offset, bf->size, minor);
		header->integer_size = (ut32)tmp;
		offset += size_offset;
		CHECK_SIZE;
		const ut64 test_valid = lua_load_integer(buffer, offset);
		offset += header->integer_size;
		(void)test_valid;
		CHECK_SIZE;
		/*
		if (test_valid != LUAC5_INT_VALIDATION) {
			RZ_LOG_ERROR("Integer format does not match with the expected integer\n");
			return NULL;
		}
		*/
	} else if ((minor == 3) || (minor == 4)) {
		READ8_CHECK_SIZE(buffer, offset, header->integer_size);
	}

	/* get lua number size */
	if (minor == 5) {
		st32 tmp = 0;
		const ut64 size_offset = lua_parse_szint(buffer, &tmp, offset, bf->size, minor);
		header->number_size = (ut32)tmp;
		offset += size_offset;
		CHECK_SIZE;
		const double test_valid = lua_load_number(buffer, offset);
		offset += header->number_size;
		CHECK_SIZE;
		if (test_valid != LUAC5_NUMBER_VALIDATION) {
			RZ_LOG_ERROR("Number format does not match with the expected number\n");
			return 0;
		}
	} else {
		READ8_CHECK_SIZE(buffer, offset, header->number_size);
	}
	if (minor == 0) {
		const double number_valid = lua_load_number(buffer, offset);
		if (number_valid != LUAC0_NUMBER_VALIDATION) {
			RZ_LOG_ERROR("Number format does not match with the expected number (expected: %f, actual: %f)\n", LUAC0_NUMBER_VALIDATION, number_valid);
			return 0;
		}
		offset += header->number_size;
		CHECK_SIZE;
	}

	/* check lua number is integral on 5.1, 5.2 */
	if ((minor == 1) || (minor == 2)) {
		if (!rz_buf_read8_at(buffer, offset, &header->is_number_integral)) {
			return 0;
		}
		offset++;
		if (header->is_number_integral > 0x01) {
			header->is_openwrt = true;
			if (!rz_buf_read8_at(buffer, offset, &header->is_number_integral)) {
				return 0;
			}
			offset += 1;
		}
	}
	if (minor == 2) {
		offset += strlen(LUAC_DATA);
	}
	CHECK_SIZE;

	/* check int and num values on 5.3, 5.4 */
	if ((minor == 3) || (minor == 4)) {
		ut64 integer_valid = lua_load_integer(buffer, offset);
		if (integer_valid != LUAC_INT_VALIDATION) {
			RZ_LOG_ERROR("Integer format does not match with the expected integer\n");
			return 0;
		}
		offset += header->integer_size;
		CHECK_SIZE;
		double number_valid = lua_load_number(buffer, offset);
		if (number_valid != LUAC_NUMBER_VALIDATION) {
			RZ_LOG_ERROR("Number format does not match with the expected number (expected: %f, actual: %f)\n", LUAC_NUMBER_VALIDATION, number_valid);
			return 0;
		}
		offset += header->number_size;
		CHECK_SIZE;
	}

	header->psize = offset;
	header->major = major;
	header->minor = minor;

	if (header->minor >= 3) {
		/* size upvalues */
		if ((header->minor == 3) || (header->minor == 4)) {
			ut8 size_upvalues = 0;
			READ8_CHECK_SIZE(buffer, offset, size_upvalues);
		} else {
			st32 size_upvalues = 0;
			const ut64 delta_offset = lua_parse_szint(buffer, &size_upvalues, offset, bf->size, minor);
			lua_check_error_offset(delta_offset);
			offset += delta_offset;
		}
	}
	/* parse source file name */
	if ((minor == 2) || (minor == 5))
		return offset;

	int name_len;
	lua_parse_string(buffer, ((ut8 **)&(header->src_file_name)), &name_len, offset, bf->size, header->minor, header->is_openwrt ? 4 : sizeof(LUA_NUMBER));
	(void)name_len;

	return offset;
}

RzBinInfo *lua_parse_bin_info(const RzBinFile *bf, const LuaHeaderInfo *header) {
	/* Common Ret */
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	rz_return_val_if_fail(ret, NULL);

	ret->has_va = true;
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_newf("Lua %c.%c compiled file", header->major + '0', header->minor + '0');
	ret->bclass = rz_str_dup("Lua compiled file");
	ret->rclass = rz_str_dup("luac");
	ret->arch = rz_str_dup("luac");
	ret->machine = rz_str_newf("Lua %c.%c VM%s", header->major + '0', header->minor + '0', header->is_openwrt ? " (openwrt)" : "");
	ret->os = rz_str_newf("%c.%c", header->major + '0', header->minor + '0');
	ret->cpu = rz_str_newf("%c.%c", header->major + '0', header->minor + '0');
	ret->bits = 32;

	/* official format */
	if (header->format != LUAC_FORMAT) {
		ret->compiler = rz_str_dup("Unofficial Lua Compiler");
		return ret;
	}
	ret->compiler = rz_str_dup("Official Lua Compiler");
	if ((header->minor == 2) || (header->minor == 1))
		return ret;

	/* Check Size */
	// TODO : remove this check and process different compiler options
	if (header->minor == 0) {
		if ((header->instruction_size != sizeof(ut64)) ||
			(header->number_size != sizeof(LUA_NUMBER))) {
			RZ_LOG_ERROR("Size definition does not match with the expected size (minor = 0)\n");
			return ret;
		}
	} else {
		if ((header->instruction_size != sizeof(LUA_INSTRUCTION)) ||
			(header->integer_size != sizeof(LUA_INTEGER)) ||
			(header->number_size != sizeof(LUA_NUMBER))) {
			RZ_LOG_ERROR("Size definition does not match with the expected size\n");
			return ret;
		}
	}

	if (header->minor < 4) {
		if (header->size_t_size != sizeof(size_t)) {
			RZ_LOG_ERROR("Size definition does not match with the expected size\n");
			return ret;
		}
	}

	if (header->minor == 4) {
		if (header->int_size != sizeof(LUA_INT)) {
			RZ_LOG_ERROR("Int size definition does not match with the expected size\n");
			return ret;
		}
	}

	/* put source file info into GUID */
	ret->guid = rz_str_dup(header->src_file_name ? header->src_file_name + 1 : "stripped");
	return ret;
}
