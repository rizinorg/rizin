#include "luac_common.h"

void luac_add_section(RzList *section_list, char *name, ut64 offset, ut32 size, bool is_func){
	RzBinSection *bin_sec;
	rz_return_if_fail(bin_sec = RZ_NEW0(RzBinSection));

	bin_sec->name = rz_str_new(name);
	bin_sec->vaddr = bin_sec->paddr = offset;
	bin_sec->size = bin_sec->vsize = size;
	bin_sec->add = true;
	bin_sec->is_data = false;
	bin_sec->bits = is_func ? sizeof(LUA_INSTRUCTION) * 8 : 8;
	// bin_sec->has_strings = !is_func;
	bin_sec->has_strings = false;
	bin_sec->arch = rz_str_new("luac");

	if (is_func){
		bin_sec->perm = RZ_PERM_R | RZ_PERM_X;
	} else {
		bin_sec->perm = RZ_PERM_R;
	}

	rz_list_append(section_list, bin_sec);
}

void luac_add_symbol(RzList *symbol_list, char *name, ut64 offset, ut64 size, const char *type){
	RzBinSymbol *bin_sym;
	rz_return_if_fail(bin_sym = RZ_NEW0(RzBinSymbol));

	bin_sym->name = rz_str_new(name);
	bin_sym->vaddr = bin_sym->paddr = offset;
	bin_sym->size = size;
	bin_sym->type = type;

	rz_list_append(symbol_list, bin_sym);
}

void luac_add_entry(RzList *entry_list, ut64 offset, int entry_type){
	RzBinAddr *entry;
	rz_return_if_fail(entry = RZ_NEW0(RzBinAddr));

	entry->vaddr = offset;
	entry->paddr = offset;
	entry->type = entry_type;

	rz_list_append(entry_list, entry);
}


LuacBinInfo *luac_build_info(LuaProto *proto){
	if (proto == NULL){
		eprintf("no proto to build info\n");
		return NULL;
	}

	LuacBinInfo *ret;
	ret = RZ_NEW0(LuacBinInfo);
	if (ret == NULL){
		eprintf("cannot build luac bin info\n");
		return NULL;
	}

	// TODO check NULL
	ret->entry_list = rz_list_new();
	ret->symbol_list = rz_list_new();
	ret->section_list = rz_list_new();

	_luac_build_info(proto, ret);

	// add entry of main
	ut64 main_entry_offset;
	main_entry_offset = proto->code_offset + proto->code_skipped;
	luac_add_entry(ret->entry_list, main_entry_offset, RZ_BIN_ENTRY_TYPE_PROGRAM);

	return ret;
}

static const char *get_tag_string(ut8 tag){
	switch (tag) {
	case LUA_VNIL:
		return "CONST_NIL";
	case LUA_VTRUE:
	case LUA_VFALSE:
		return "CONST_BOOL";
	case LUA_VSHRSTR:
	case LUA_VLNGSTR:
		return "CONST_STRING";
	case LUA_VNUMFLT:
	case LUA_VNUMINT:
		return "CONST_NUM";
	default:
		return "CONST_UNKNOWN";
	}
}

void _luac_build_info(LuaProto *proto, LuacBinInfo *info){
	/* process proto header info */
	char *section_name;
	char *symbol_name;
	char *proto_name;
	RzListIter *iter;

	ut64 current_offset;
	ut64 current_size;

	// 0. check if stripped (proto name is lost)
	if (proto->name_size == 0 || proto->proto_name == NULL){
		// replace name with current offset
		proto_name = rz_str_newf("fcn.%08llx", proto->offset);
	} else {
		proto_name = rz_str_new((char *)proto->proto_name);
	}

	// 1.1 set section name as function_name.header
	current_offset = proto->offset;
	current_size = proto->size;
	section_name = rz_str_newf("%s.header", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, false);
        RZ_FREE(section_name);

        // 1.2 set section name as function_name.code
	current_offset = proto->code_offset;
	current_size = proto->code_size;
	section_name = rz_str_newf("%s.code", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, true);
        RZ_FREE(section_name);

        // 1.3 set const section
	current_offset = proto->const_offset;
	current_size = proto->const_size;
	section_name = rz_str_newf("%s.const", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, false);
        RZ_FREE(section_name);

        // 1.4 upvalue section
	current_offset = proto->upvalue_offset;
	current_size = proto->upvalue_size;
	section_name = rz_str_newf("%s.upvalues", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, false);
        RZ_FREE(section_name);

        // 1.5 inner protos section
	current_offset = proto->inner_proto_offset;
	current_size = proto->inner_proto_size;
	section_name = rz_str_newf("%s.protos", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, false);
        RZ_FREE(section_name);

	// 1.6 debug section
	current_offset = proto->debug_offset;
	current_size = proto->debug_size;
	section_name = rz_str_newf("%s.debug", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, false);
        RZ_FREE(section_name);

	// 2. should I construct symbols of proto attr ?
	//     (for example linedefined ?)
	// TODO : better symbol name (e.g const_i_am_string)

        // 3.1 construct constant symbols
	LuaConstEntry *const_entry;
	rz_list_foreach(proto->const_entries, iter, const_entry){
		symbol_name = rz_str_newf(
			"%s_const_%08llx",
			proto_name,
			const_entry->offset);
		luac_add_symbol(
			info->symbol_list,
			symbol_name,
			const_entry->offset,
			const_entry->data_len,
			get_tag_string(const_entry->tag));
		RZ_FREE(symbol_name);
	}

	// 3.2 construct upvalue symbols
	LuaUpvalueEntry *upvalue_entry;
        rz_list_foreach(proto->upvalue_entries, iter, upvalue_entry){
                        symbol_name = rz_str_newf(
                                "%s_upvalue_%08llx",
                                proto_name,
                                upvalue_entry->offset);
                        luac_add_symbol(
                                info->symbol_list,
                                symbol_name,
                                upvalue_entry->offset,
                                3,
                                "UPVALUE");
                        RZ_FREE(symbol_name);
	}

	// 3.3 TODO parse debug info

	// 4. parse sub proto
	LuaProto *sub_proto;
	rz_list_foreach(proto->proto_entries, iter, sub_proto){
		_luac_build_info(sub_proto, info);
	}

	RZ_FREE(proto_name);
}

