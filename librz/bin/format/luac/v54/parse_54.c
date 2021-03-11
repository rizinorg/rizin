#include "luac_specs_54.h"

void luaLoadBlock(void *src, void *dest, size_t size) {
        memcpy(dest, src, size);
}

LUA_INTEGER luaLoadInteger(ut8 *src) {
        LUA_INTEGER x;
        luaLoadVar(src, x);
        return x;
}

LUA_NUMBER luaLoadNumber(ut8 *src) {
        LUA_NUMBER x;
        luaLoadVar(src, x);
        return x;
}

/* Luac load method , defined in lua source code lundump.c */
size_t luaLoadUnsigned(ut8 *src, size_t src_buf_limit, size_t limit) {
        size_t x = 0;
        ut32 b;
        int i = 0;
        limit >>= 7;
        do {
                b = src[i++];
                if (x >= limit) {
                        eprintf("integer overflow\n");
                        return 0;
                }
                x = (x << 7) | (b & 0x7f);
        } while (((b & 0x80) == 0) && (i < src_buf_limit));
        return x;
}

size_t luaLoadSize(ut8 *src, size_t src_buf_limit) {
        return luaLoadUnsigned(src, src_buf_limit, ~(size_t)0);
}

/* load a null-terminated string, return a malloced string */
char *luaLoadString(ut8 *src, size_t src_buf_limit) {
        /* size is the buffer's size */
        size_t size = luaLoadSize(src, src_buf_limit);
        char *ret;

        /* no string */
        if (size == 0) {
                return NULL;
        }

        /* skip size byte */
        void *string_start = src + 1;
        size -= 1;

        if ((ret = RZ_NEWS(char, size + 1)) == NULL) {
                eprintf("error in string init\n");
                return NULL;
        }

        memcpy(ret, string_start, size);
        ret[size] = 0x00;

        return ret;
}

/* read 'n' bytes and construct a variable in dest
 * then return 'n' */
size_t lua_parse_unsigned(const ut8 *src, size_t *dest,size_t src_buf_limit, size_t limit){
        size_t x = 0;
        ut32 b;
        int i = 0;
        limit >>= 7;
        do {
                b = src[i++];
                if (x >= limit) {
                        eprintf("integer overflow\n");
                        return 0;
                }
                x = (x << 7) | (b & 0x7f);
        } while (((b & 0x80) == 0) && (i < src_buf_limit));

	*dest = x;
        return i;
}

size_t lua_parse_size(const ut8 *src, size_t *dest,size_t src_buf_limit){
        return lua_parse_unsigned(src, dest, src_buf_limit, ~(size_t)0);
}

ut64 lua_parse_function(const ut8 *data, ut64 offset, ut64 size, LuaFunction *parent_func, LuaParseStruct *lua_parse, LuaMetaData *lua_data){
	LuaFunction *function = lua_find_function_by_addr(offset, lua_data);
	if (function){
		if (lua_parse != NULL && lua_parse->onString != NULL){
			lua_parse_constants(data, function->const_offset, size, lua_parse, lua_data);
		}
		lua_parse_protos(data, function->protos_offset, size, function, lua_parse, lua_data);

		if (lua_parse != NULL && lua_parse->onString != NULL){
			lua_parse_debug(data, function->debug_offset, size, lua_parse, lua_data);
		}

		if (lua_parse != NULL && lua_parse->onFunction != NULL){
			lua_parse->onFunction(function, lua_parse);
		}
	}
	else {
		ut64 function_base_offset = offset;

		function = RZ_NEW0(LuaFunction);
		function->parent_func = parent_func;
		function->offset = offset;

		// parse function name
		offset = lua_parse_string_n(
			data, offset, size,
			&function->name_ptr, &function->name_size,
			lua_parse, lua_data);
		if (offset == 0){
			free(function);
			return 0;
		}

		// parse proto meta info - variable bytes
		offset += lua_parse_size(data + offset, &function->line_defined, size);
		offset += lua_parse_size(data + offset, &function->lastline_defined, size);

		// parse numparams - 1 byte
		function->num_params = data[offset];
		offset += 1;

		// parse is_vararg - 1 byte
		function->is_vararg = data[offset];
		offset += 1;

		// parse max_stack_size - 1 byte
		function->max_stack_size = data[offset];
		offset += 1;

		// parse code, code size is variable
		// code => code_size(variable bytes) + code([code_size] bytes)
		function->code_offset = offset;
		function->code_size = luaLoadSize(data + offset, size);
		offset = lua_parse_code(data, offset, size, lua_parse, lua_data);
		if (offset == 0){
			free(function);
			return 0;
		}

		// parse constants
		function->const_offset = offset;
		function->const_size = luaLoadSize(data + offset, size);
		offset = lua_parse_constants(data, offset, size, lua_parse, lua_data);
                if (offset == 0){
                        free(function);
                        return 0;
                }

		// parse upvalues
		function->upvalue_offset = offset;
		function->upvalue_size = luaLoadSize(data + offset, size);
		offset = lua_parse_upvalues(data, offset, size, lua_parse, lua_data);
		if (offset == 0){
			free(function);
			return 0;
		}

		// parse protos
		function->protos_offset = offset;
		function->protos_size = luaLoadSize(data + offset, size);
		offset = lua_parse_protos(data, offset, size, function, lua_parse, lua_data);
		if (offset == 0){
			free(function);
			return 0;
		}

		// parse debug
		function->debug_offset = offset;
		offset = lua_parse_debug(data, offset, size, lua_parse, lua_data);
		if (offset == 0){
			free(function);
			return 0;
		}

		function->size = offset - function_base_offset;
		if (lua_parse && lua_parse->onFunction){
			lua_parse->onFunction(function, lua_parse);
		}

		if (!lua_store_function(function, lua_data)){
			free(function);
		}
		return offset;
        }
}

ut64 lua_parse_string_n(const ut8 *data, ut64 offset, ut64 size, char **str_ptr, ut64 *str_len, LuaParseStruct *lua_parse, LuaMetaData *lua_data){
        // read 'n' size byte
        ut64 length;
        ut64 size_len = lua_parse_size(data + offset, &length, size);

        // skip n size bytes
        offset += size_len;

	if (length != 0){
		if (str_ptr){
			*str_ptr = (char *)data + offset;
		}
		if (str_len){
			*str_len = length - 1;
		}
		if (lua_parse && lua_parse->onString){
			lua_parse->onString(data, offset, length, lua_parse);
		}
		offset += length - 1;
	}

	return offset;
}

ut64 lua_parse_string(const ut8 *data, ut64 offset, ut64 size, LuaParseStruct *lua_parse, LuaMetaData *lua_data){
	lua_parse_string_n(data, offset, size, NULL, NULL, lua_parse, lua_data);
}

ut64 lua_parse_code(const ut8 *data, ut64 offset, ut64 size, LuaParseStruct *lua_parse, LuaMetaData *lua_data){
	// read 'n' size byte
	ut64 length;
	ut64 size_len = lua_parse_size(data + offset, &length, size);

	// skip n size bytes
	offset += size_len;

        // check enough space for code
	if (offset + length * lua_data->instruction_size >= size){
		return 0;
	}

	return offset + length * lua_data->instruction_size;
}

ut64 lua_parse_constants(const ut8 *data, ut64 offset, ut64 size, LuaParseStruct *lua_parse, LuaMetaData *lua_data){
	// read n byte for constants size
	ut64 const_cnt;
	ut64 size_len = lua_parse_size(data + offset, &const_cnt, size);
	ut64 str_len;

	// skip n size bytes
	offset += size_len;

	// iterate on constants
	int i;
	ut8 tag;
	for (i = 0; i < const_cnt; ++i){
		// load 1 byte for tag
		tag = data[offset + 0];
		offset += 1;

		switch (tag) {
		case LUA_VTRUE:
		case LUA_VFALSE:
		case LUA_VNIL:
			break;

		case LUA_VNUMFLT:       /* number type 8 bytes */
			offset += 8;
			break;

		case LUA_VNUMINT:       /* integer type 8 bytes */
			offset += 8;
			break;

		case LUA_VSHRSTR:       /* string type */
		case LUA_VLNGSTR:
			offset += lua_parse_string(data, offset, size, lua_parse, lua_data);
			break;
		default:
			eprintf("Invlid Lua Type\n");
			return 0;
		}
	}
	return offset;
}

ut64 lua_parse_upvalues(const ut8 *data, ut64 offset, ut64 size, LuaParseStruct *lua_parse, LuaMetaData *lua_data){
        // read 'n' size byte
        ut64 upvalues_cnt;
        ut64 size_len = lua_parse_size(data + offset, &upvalues_cnt, size);

	// skip n size bytes
        offset += size_len;

        // check enough space for upvalues
        if (offset + upvalues_cnt * 3 >= size){
                return 0;
        }

	// iterate on upvalues
	int i = 0;
	for (i = 0; i < upvalues_cnt; ++i){
		// 3 member of upvalue :
		// instack, idx, kind, 1 byte for each, skip for now
		printf("upvalue[%d]\n", i);
	}

        return offset + upvalues_cnt * 3;
}

ut64 lua_parse_protos(const ut8 *data, ut64 offset, ut64 size, LuaFunction *parent_func, LuaParseStruct *lua_parse, LuaMetaData *lua_data){
        // read 'n' size byte
        ut64 protos_cnt;
        ut64 size_len = lua_parse_size(data + offset, &protos_cnt, size);
        offset += size_len;

	// The same as parse_function
	int i = 0;
	for (i = 0; i < protos_cnt; ++i){
		offset = lua_parse_function(data, offset, size, parent_func, lua_parse, lua_data);
		if (offset == 0){
			return 0;
		}
	}

	return offset;
}

ut64 lua_parse_debug(const ut8 *data, ut64 offset, ut64 size, LuaParseStruct *lua_parse, LuaMetaData *lua_data){
	// TODO : Collect Debug Info For Analysis

        ut64 entry_cnt;
	ut64 size_len;
	int i;

	/* Debug-lineinfo */
	size_len = lua_parse_size(data + offset, &entry_cnt, size);
	offset += size_len;
	// simply skip it for now (signed byte for each line info)
	offset += entry_cnt;

	/* Debug-asblineinfo */
	size_len = lua_parse_size(data + offset, &entry_cnt, size);
	offset += size_len;
        // every abslineinfo contains `pc` and `line`
        ut64 pc;
	ut64 line;
	for (i = 0; i < entry_cnt; ++i){
		offset += lua_parse_size(data + offset, &pc, size);
		offset += lua_parse_size(data + offset, &line, size);
	}

	/* Debug-localvars */
        size_len = lua_parse_size(data + offset, &entry_cnt, size);
        offset += size_len;
        // every local vars contain `varname` `startpc` and `endpc`
	char *varname;
	ut64 varname_len;
        ut64 start_pc;
        ut64 end_pc;
        for (i = 0; i < entry_cnt; ++i){
		offset += lua_parse_string_n(data, offset, size, &varname, &varname_len, lua_parse, lua_data);
                offset += lua_parse_size(data + offset, &start_pc, size);
                offset += lua_parse_size(data + offset, &end_pc, size);
        }

	/* Debug-upvalues */
        size_len = lua_parse_size(data + offset, &entry_cnt, size);
        offset += size_len;
        // every upvalues contain `name` only
        char *name;
        ut64 name_len;
        for (i = 0; i < entry_cnt; ++i){
                offset += lua_parse_string_n(data, offset, size, &name, &name_len, lua_parse, lua_data);
        }

}