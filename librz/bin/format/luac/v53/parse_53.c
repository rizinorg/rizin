#include "luac_specs_53.h"
static void lua_load_block(RzBuffer *buffer, void *dest, size_t size, ut64 offset, ut64 data_size) {
        if (offset + size > data_size) {
                eprintf("Bad Luac File : Truncated load block at 0x%llx\n", offset);
                return;
        }
        rz_buf_read_at(buffer, offset, dest, size);
}

static ut64 lua_load_integer(RzBuffer *buffer, ut64 offset) {
        ut64 x;
        rz_buf_read_at(buffer, offset, (ut8 *)&x, sizeof(ut64));
        return x;
}

static double lua_load_number(RzBuffer *buffer, ut64 offset) {
        double x;
        rz_buf_read_at(buffer, offset, (ut8 *)&x, sizeof(double));
        return x;
}

static ut64 lua_parse_size(RzBuffer *buffer, int *size, ut64 offset, ut64 data_size) {
	ut64 base_offset;
	base_offset = offset;

}

static ut64 lua_parse_string(RzBuffer *buffer, ut8 **dest, int *str_len, ut64 offset, ut64 data_size) {
	int string_buf_size = rz_buf_read8_at(buffer, offset);
	int len = 0;
	ut64 base_offset = 0;
	ut64 size_offset = 1;
	ut8 *ret;

	base_offset = offset;

	// Long string
	if (string_buf_size == 0xFF) {
                offset += size_offset;
		size_offset = lua_parse_size(buffer, &string_buf_size, offset, data_size);
	}

	offset += size_offset;

	if (string_buf_size == 0 || size_offset == 0) {
		ret = NULL;
		len = 0;
	} else {
		len = string_buf_size - 1;
		if ((ret = RZ_NEWS(ut8, string_buf_size)) == NULL) {
			len = 0;
		} else {
			rz_buf_read_at(buffer, offset, ret, len);
			ret[len] = 0x00;
		}
	}

	if (dest && str_len) {
		*dest = ret;
		*str_len = len;
	} else {
		eprintf("cannot store string\n");
	}

	return offset + len - base_offset;
}

static ut64 lua_parse_name(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size) {
	return lua_parse_string(buffer, &proto->proto_name, &proto->name_size, offset, data_size);
}

RzBinInfo *lua_parse_header_53(RzBinFile *bf, st32 major, st32 minor) {
        RzBinInfo *ret = NULL;
        RzBuffer *buffer;

        st64 reat = bf->size;
        if (reat < LUAC_53_HDRSIZE) {
                eprintf("Truncated Header\n");
                return NULL;
        }
        buffer = bf->buf;

        /* read header members from work buffer */
        ut8 luac_format = rz_buf_read8_at(buffer, LUAC_53_FORMAT_OFFSET);
	ut8 int_size = rz_buf_read8_at(buffer, LUAC_53_INT_SIZE_OFFSET);
	ut8 sizet_size = rz_buf_read8_at(buffer, LUAC_53_SIZET_SIZE_OFFSET);
        ut8 instruction_size = rz_buf_read8_at(buffer, LUAC_53_INSTRUCTION_SIZE_OFFSET);
        ut8 integer_size = rz_buf_read8_at(buffer, LUAC_53_INTEGER_SIZE_OFFSET);
        ut8 number_size = rz_buf_read8_at(buffer, LUAC_53_NUMBER_SIZE_OFFSET);
        ut64 integer_valid = lua_load_integer(buffer, LUAC_53_INTEGER_VALID_OFFSET);
        double number_valid = lua_load_number(buffer, LUAC_53_NUMBER_VALID_OFFSET);

        /* Common Ret */
        if (!(ret = RZ_NEW0(RzBinInfo))) {
                return NULL;
        }
        ret->file = rz_str_new(bf->file);
        ret->type = rz_str_newf("Lua %c.%c compiled file", major + '0', minor + '0');
        ret->bclass = rz_str_new("Lua compiled file");
        ret->rclass = rz_str_new("luac");
        ret->arch = rz_str_new("luac");
        ret->machine = rz_str_newf("Lua %c.%c VM", major + '0', minor + '0');
        ret->os = rz_str_newf("%c.%c", major + '0', minor + '0');
        ret->bits = 8;

        /* official format ? */
        if (luac_format != LUAC_54_FORMAT) {
                ret->compiler = rz_str_new("Unofficial Lua Compiler");
                return ret;
        }
        ret->compiler = rz_str_new("Official Lua Compiler");

        /* Check Size */
	// TODO : remove this check and process different compiler options
        if ((instruction_size != sizeof(LUA_INSTRUCTION)) ||
            (integer_size != sizeof(LUA_INTEGER)) ||
            (number_size != sizeof(LUA_NUMBER)) ||
		(int_size != sizeof(LUA_INT)) ||
                (sizet_size != sizeof(size_t))){
                eprintf("Size Definition not matched\n");
                return ret;
        }

        /* Check endian */
        if (integer_valid != LUAC_53_INT_VALIDATION) {
                eprintf("Integer Format Not Matched\n");
                return ret;
        }
        if (number_valid != LUAC_53_NUMBER_VALIDATION) {
                eprintf("Number Format Not Matched\n");
                return ret;
        }

        /* parse source file name */
        char *src_file_name = NULL;
        int name_len;
        lua_parse_string(buffer, ((ut8 **)&(src_file_name)), &name_len, LUAC_FILENAME_OFFSET, bf->size);

        /* put source file info into GUID */
        ret->guid = rz_str_new(src_file_name ? src_file_name : "stripped");
        free(src_file_name);

        return ret;
}

LuaProto *lua_parse_body_53(RzBuffer *buffer, ut64 base_offset, ut64 data_size) {
	ut64 offset;
	ut64 delta_offset;

        LuaProto *ret_proto = lua_new_proto_entry();
	if (ret_proto == NULL) {
		eprintf("unable to init proto\n");
	}

	// start parsing
	offset = base_offset;

	// record offset of main proto
	ret_proto->offset = offset;

	// parse proto name
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
        ret_proto->num_params = rz_buf_read8_at(buffer, offset + 0);
        ret_proto->is_vararg = rz_buf_read8_at(buffer, offset + 1);
        ret_proto->max_stack_size = rz_buf_read8_at(buffer, offset + 2);
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