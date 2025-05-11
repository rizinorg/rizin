// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "luac_specs_54.h"

static void lua_load_block(RzBuffer *buffer, void *dest, size_t size, ut64 offset, ut64 data_size) {
	if (offset + size > data_size) {
		RZ_LOG_ERROR("Truncated load block at 0x%llx\n", offset);
		return;
	}
	rz_buf_read_at(buffer, offset, dest, size);
}

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

// return an offset to skip string, return 1 if no string (0x80)
// TODO : clean type related issues
static ut64 lua_parse_szint(RzBuffer *buffer, int *size, ut64 offset, ut64 data_size) {
	int x = 0;
	int b;
	int i = 0;
	ut32 limit = (~(ut32)0);
	limit >>= 7;

	// 1 byte at least
	if (offset + 1 > data_size) {
		RZ_LOG_ERROR("Truncated integer size at 0x%llx\n", offset);
		return 0;
	}

	do {
		ut8 tmp;
		if (!rz_buf_read8_at(buffer, offset + i, &tmp)) {
			return 0;
		}

		b = tmp;

		i += 1;
		if (x >= limit) {
			RZ_LOG_ERROR("integer overflow while decoding integer size\n");
			return 0;
		}
		x = (x << 7) | (b & 0x7f);
	} while (((b & 0x80) == 0) && (i + offset < data_size));

	*size = x;
	return i;
}

static ut64 lua_parse_string(RzBuffer *buffer, ut8 **dest, int *str_len, ut64 offset, ut64 data_size) {
	ut64 size_offset;
	ut64 total_offset;
	int ret_buf_size;
	int string_len;
	ut8 *ret;

	size_offset = lua_parse_szint(buffer, &ret_buf_size, offset, data_size);
	lua_check_error_offset(size_offset);

	/* no string */
	if (ret_buf_size == 0) {
		ret = NULL;
		string_len = 0;
	} else {
		/* skip size byte */
		string_len = ret_buf_size - 1;
		if ((ret = RZ_NEWS(ut8, ret_buf_size)) == NULL) {
			string_len = 0;
		} else {
			rz_buf_read_at(buffer, offset + size_offset, ret, string_len);
			ret[string_len] = 0x00;
		}
	}

	/* set to outside vars */
	if (dest && str_len) {
		*dest = ret;
		*str_len = string_len;
	} else {
		RZ_LOG_ERROR("cannot store string\n");
	}

	total_offset = size_offset + string_len;
	return total_offset;
}

static ut64 lua_parse_name(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size) {
	return lua_parse_string(buffer, &proto->proto_name, &proto->name_size, offset, data_size);
}

static ut64 lua_parse_line_defined(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size) {
	ut64 size_offset;
	ut64 delta_offset;
	int line_defined;
	int last_line_defined;

	size_offset = lua_parse_szint(buffer, &line_defined, offset, data_size);
	lua_check_error_offset(size_offset);

	delta_offset = lua_parse_szint(buffer, &last_line_defined, offset + size_offset, data_size);
	lua_check_error_offset(delta_offset);

	size_offset += delta_offset;

	/* Set Proto Member */
	proto->line_defined = line_defined;
	proto->lastline_defined = last_line_defined;

	return size_offset;
}

static ut64 lua_parse_code(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size) {
	ut64 size_offset;
	ut64 total_size;
	int code_size;

	size_offset = lua_parse_szint(buffer, &code_size, offset, data_size);
	lua_check_error_offset(size_offset);
	total_size = code_size * 4 + size_offset;

	if (total_size + offset > data_size) {
		RZ_LOG_ERROR("Truncated Code at [0x%llx]\n", offset);
		return 0;
	}

	/* Set Proto Member */
	proto->code_size = code_size * 4;
	proto->code_skipped = size_offset;

	return total_size;
}

static ut64 lua_parse_const_entry(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size) {
	LuaConstEntry *current_entry;
	ut64 base_offset;
	ut8 *recv_data;
	ut64 delta_offset;
	int data_len;

	current_entry = lua_new_const_entry();
	current_entry->offset = offset;
	base_offset = offset;
	delta_offset = 0;

	/* read TAG byte */
	if (offset + 1 > data_size) {
		return 0;
	}

	if (!rz_buf_read8_at(buffer, offset, &current_entry->tag)) {
		return 0;
	}

	offset += 1;

	/* read data */
	// TODO : replace 8 with Macro
	switch (current_entry->tag) {
	case LUA_VNUMFLT:
	case LUA_VNUMINT:
		data_len = 8;
		recv_data = RZ_NEWS(ut8, data_len);
		lua_load_block(buffer, recv_data, data_len, offset, data_size);
		if (offset + data_len > data_size) {
			return 0;
		}
		delta_offset = data_len;
		break;
	case LUA_VSHRSTR:
	case LUA_VLNGSTR:
		delta_offset = lua_parse_string(buffer, &recv_data, &data_len, offset, data_size);
		lua_check_error_offset(delta_offset);
		break;
	case LUA_VNIL:
	case LUA_VFALSE:
	case LUA_VTRUE:
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
	rz_list_append(proto->const_entries, current_entry);

	return offset - base_offset;
}

static ut64 lua_parse_consts(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size) {
	int consts_cnt;
	int i;
	ut64 base_offset;
	ut64 delta_offset;

	base_offset = offset;

	/* parse number of constants */
	delta_offset = lua_parse_szint(buffer, &consts_cnt, offset, data_size);
	lua_check_error_offset(delta_offset);
	offset += delta_offset;

	for (i = 0; i < consts_cnt; ++i) {
		// add an entry of constant
		delta_offset = lua_parse_const_entry(proto, buffer, offset, data_size);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;
	}

	proto->const_size = offset - base_offset + 1;
	return offset - base_offset;
}

static ut64 lua_parse_upvalue_entry(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size) {
	LuaUpvalueEntry *current_entry;
	ut64 base_offset;

	base_offset = offset;
	current_entry = lua_new_upvalue_entry();
	current_entry->offset = base_offset;

	if (offset + 3 > data_size) {
		return 0;
	}

	/* read instack/idx/kind attr */
	if (!rz_buf_read8_at(buffer, offset + 0, &current_entry->instack)) {
		return 0;
	}

	if (!rz_buf_read8_at(buffer, offset + 1, &current_entry->idx)) {
		return 0;
	}

	if (!rz_buf_read8_at(buffer, offset + 2, &current_entry->kind)) {
		return 0;
	}

	offset += 3;

	/* add to list */
	rz_list_append(proto->upvalue_entries, current_entry);

	return offset - base_offset;
}

static ut64 lua_parse_upvalues(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size) {
	int upvalues_cnt;
	int i;
	ut64 base_offset;
	ut64 delta_offset;

	base_offset = offset;

	/* parse number of upvalues */
	delta_offset = lua_parse_szint(buffer, &upvalues_cnt, offset, data_size);
	lua_check_error_offset(delta_offset);
	offset += delta_offset;

	for (i = 0; i < upvalues_cnt; ++i) {
		delta_offset = lua_parse_upvalue_entry(proto, buffer, offset, data_size);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;
	}

	proto->upvalue_size = offset - base_offset + 1;

	return offset - base_offset;
}
static ut64 lua_parse_debug(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size) {
	int entries_cnt;
	int i;
	ut64 base_offset;
	ut64 delta_offset;

	base_offset = offset;

	/* parse line info */
	delta_offset = lua_parse_szint(buffer, &entries_cnt, offset, data_size);
	lua_check_error_offset(delta_offset);
	offset += delta_offset;
	LuaLineinfoEntry *info_entry;
	for (i = 0; i < entries_cnt; ++i) {
		info_entry = lua_new_lineinfo_entry();
		info_entry->offset = offset;
		ut8 tmp;
		if (!rz_buf_read8_at(buffer, offset, &tmp)) {
			free(info_entry);
			return 0;
		}
		info_entry->info_data = tmp;
		rz_list_append(proto->line_info_entries, info_entry);
		offset += 1;
	}

	/* parse absline info */
	delta_offset = lua_parse_szint(buffer, &entries_cnt, offset, data_size);
	lua_check_error_offset(delta_offset);
	offset += delta_offset;
	LuaAbsLineinfoEntry *abs_info_entry;
	for (i = 0; i < entries_cnt; ++i) {
		abs_info_entry = lua_new_abs_lineinfo_entry();
		abs_info_entry->offset = offset;

		delta_offset = lua_parse_szint(buffer, &abs_info_entry->pc, offset, data_size);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;

		delta_offset = lua_parse_szint(buffer, &abs_info_entry->line, offset, data_size);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;

		rz_list_append(proto->abs_line_info_entries, abs_info_entry);
	}

	/* parse local vars */
	delta_offset = lua_parse_szint(buffer, &entries_cnt, offset, data_size);
	lua_check_error_offset(delta_offset);
	offset += delta_offset;
	LuaLocalVarEntry *var_entry;
	for (i = 0; i < entries_cnt; ++i) {
		var_entry = lua_new_local_var_entry();
		var_entry->offset = offset;

		/* string */
		delta_offset = lua_parse_string(
			buffer,
			&var_entry->varname, &var_entry->varname_len,
			offset, data_size);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;

		/* start pc -- int */
		delta_offset = lua_parse_szint(buffer, &var_entry->start_pc, offset, data_size);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;

		/* end pc -- int */
		delta_offset = lua_parse_szint(buffer, &var_entry->end_pc, offset, data_size);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;

		rz_list_append(proto->local_var_info_entries, var_entry);
	}

	/* parse upvalue */
	delta_offset = lua_parse_szint(buffer, &entries_cnt, offset, data_size);
	lua_check_error_offset(delta_offset);
	offset += delta_offset;
	LuaDbgUpvalueEntry *dbg_upvalue_entry;
	for (i = 0; i < entries_cnt; ++i) {
		dbg_upvalue_entry = lua_new_dbg_upvalue_entry();
		dbg_upvalue_entry->offset = offset;

		delta_offset = lua_parse_string(
			buffer,
			&dbg_upvalue_entry->upvalue_name, &dbg_upvalue_entry->name_len,
			offset, data_size);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;

		rz_list_append(proto->dbg_upvalue_entries, dbg_upvalue_entry);
	}

	proto->debug_size = offset - base_offset + 1;
	return offset - base_offset;
}

static ut64 lua_parse_protos(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size) {
	rz_return_val_if_fail(proto, 0);

	int proto_cnt;
	int i;
	ut64 base_offset;
	ut64 delta_offset;

	base_offset = offset; // store origin offset
	delta_offset = lua_parse_szint(buffer, &proto_cnt, offset, data_size); // skip size bytes
	lua_check_error_offset(delta_offset);
	offset += delta_offset;

	LuaProto *current_proto;
	for (i = 0; i < proto_cnt; ++i) {
		current_proto = lua_parse_body_54(buffer, offset, data_size);
		lua_return_if_null(current_proto);
		rz_list_append(proto->proto_entries, current_proto);
		offset += current_proto->size - 1; // update offset
	}

	// return the delta between offset and base_offset
	return offset - base_offset;
}

LuaProto *lua_parse_body_54(RzBuffer *buffer, ut64 base_offset, ut64 data_size) {
	LuaProto *ret_proto = lua_new_proto_entry(); /* construted proto for return */
	ut64 offset; /* record offset */
	ut64 delta_offset;
	rz_return_val_if_fail(ret_proto, NULL);

	// start parsing
	offset = base_offset;

	/* record offset of main proto */
	ret_proto->offset = offset;

	/* parse proto name of main proto */
	delta_offset = lua_parse_name(ret_proto, buffer, offset, data_size);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse line defined info */
	delta_offset = lua_parse_line_defined(ret_proto, buffer, offset, data_size);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

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

	/* parse code */
	ret_proto->code_offset = offset;
	delta_offset = lua_parse_code(ret_proto, buffer, offset, data_size);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse constants */
	ret_proto->const_offset = offset;
	delta_offset = lua_parse_consts(ret_proto, buffer, offset, data_size);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse upvalues */
	ret_proto->upvalue_offset = offset;
	delta_offset = lua_parse_upvalues(ret_proto, buffer, offset, data_size);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse inner protos */
	ret_proto->inner_proto_offset = offset;
	delta_offset = lua_parse_protos(ret_proto, buffer, offset, data_size);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* specially handle recursive protos size */
	ret_proto->inner_proto_size = offset - ret_proto->inner_proto_offset;

	/* parse debug */
	ret_proto->debug_offset = offset;
	delta_offset = lua_parse_debug(ret_proto, buffer, offset, data_size);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	ret_proto->size = offset - base_offset + 1;

	return ret_proto;
}

RzBinInfo *lua_parse_header_54(RzBinFile *bf, st32 major, st32 minor) {
	RzBinInfo *ret = NULL;
	RzBuffer *buffer;

	st64 reat = bf->size;
	if (reat < LUAC_54_HDRSIZE) {
		RZ_LOG_ERROR("Truncated Header\n");
		return NULL;
	}
	buffer = bf->buf;

	/* read header members from work buffer */
	ut8 luac_format;
	if (!rz_buf_read8_at(buffer, LUAC_54_FORMAT_OFFSET, &luac_format)) {
		return NULL;
	}

	ut8 instruction_size;
	if (!rz_buf_read8_at(buffer, LUAC_54_INSTRUCTION_SIZE_OFFSET, &instruction_size)) {
		return NULL;
	}

	ut8 integer_size;
	if (!rz_buf_read8_at(buffer, LUAC_54_INTEGER_SIZE_OFFSET, &integer_size)) {
		return NULL;
	}

	ut8 number_size;
	if (!rz_buf_read8_at(buffer, LUAC_54_NUMBER_SIZE_OFFSET, &number_size)) {
		return NULL;
	}

	ut64 int_valid = lua_load_integer(buffer, LUAC_54_INTEGER_VALID_OFFSET);
	double number_valid = lua_load_number(buffer, LUAC_54_NUMBER_VALID_OFFSET);

	/* Common Ret */
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_newf("Lua %c.%c compiled file", major + '0', minor + '0');
	ret->bclass = rz_str_dup("Lua compiled file");
	ret->rclass = rz_str_dup("luac");
	ret->arch = rz_str_dup("luac");
	ret->machine = rz_str_newf("Lua %c.%c VM", major + '0', minor + '0');
	ret->os = rz_str_newf("%c.%c", major + '0', minor + '0');
	ret->cpu = rz_str_newf("%c.%c", major + '0', minor + '0');
	ret->bits = 8;

	/* official format ? */
	if (luac_format != LUAC_54_FORMAT) {
		ret->compiler = rz_str_dup("Unofficial Lua Compiler");
		return ret;
	}
	ret->compiler = rz_str_dup("Official Lua Compiler");

	/* Check Size */
	if ((instruction_size != sizeof(LUA_INSTRUCTION)) ||
		(integer_size != sizeof(LUA_INTEGER)) ||
		(number_size != sizeof(LUA_NUMBER))) {
		RZ_LOG_ERROR("Size definition does not match with the expected size\n");
		return ret;
	}

	/* Check endian */
	if (int_valid != LUAC_54_INT_VALIDATION) {
		RZ_LOG_ERROR("Integer format does not match with the expected integer\n");
		return ret;
	} else if (number_valid != LUAC_54_NUMBER_VALIDATION) {
		RZ_LOG_ERROR("Number format does not match with the expected number\n");
		return ret;
	}

	/* parse source file name */
	char *src_file_name = NULL;
	int name_len;
	lua_parse_string(buffer, ((ut8 **)&(src_file_name)), &name_len, LUAC_FILENAME_OFFSET, bf->size);

	/* put source file info into GUID */
	ret->guid = rz_str_dup(src_file_name ? src_file_name : "stripped");
	free(src_file_name);

	return ret;
}
