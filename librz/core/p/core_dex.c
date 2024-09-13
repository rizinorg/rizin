// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_demangler.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <string.h>
#include <rz_analysis.h>

#include "../format/dex/dex.h"

#define name_args(name)    (cmd_##name##_args)
#define name_help(name)    (cmd_##name##_help)
#define name_handler(name) (rz_cmd_##name##_handler)
#define static_description_without_args(command, summ) \
	static const RzCmdDescArg name_args(command)[] = { \
		{ 0 }, \
	}; \
	static const RzCmdDescHelp name_help(command) = { \
		.summary = summ, \
		.args = name_args(command), \
	}
#define rz_cmd_desc_argv_modes_new_warn(rcmd, root, cmd, flags) \
	rz_warn_if_fail(rz_cmd_desc_argv_state_new(rcmd, root, #cmd, flags, name_handler(cmd), &name_help(cmd)))

static RzBinDex *core_dex_get_class(RzCore *core) {
	if (!core) {
		return NULL;
	}
	RzAnalysis *analysis = core->analysis;
	if (!analysis || !analysis->binb.bin) {
		return NULL;
	}
	RzBin *b = analysis->binb.bin;
	if (!b->cur || !b->cur->o) {
		return NULL;
	}
	RzBinPlugin *plugin = b->cur->o->plugin;
	return plugin && !strcmp(plugin->name, "dex") ? (RzBinDex *)b->cur->o->bin_obj : NULL;
}

static char *decode_access_flags(ut32 access_flags) {
	char *str = rz_bin_dex_access_flags_readable(access_flags);
	if (!str) {
		return rz_str_dup("");
	}
	for (size_t i = 0; i < strlen(str); ++i) {
		str[i] = toupper(str[i]);
	}
	return str;
}

static void dex_print_encoded_field(RzBinDex *dex, ut32 index, DexEncodedField *encoded_field) {
	if (dex->field_ids_size < encoded_field->field_idx) {
		rz_cons_printf("    #%-14u: unknown id %" PFMT64u "\n", index, encoded_field->field_idx);
		return;
	}
	DexFieldId *field_id = (DexFieldId *)rz_pvector_at(dex->field_ids, encoded_field->field_idx);

	char *tmp = rz_bin_dex_resolve_type_id_by_idx(dex, field_id->class_idx);
	rz_cons_printf("    #%-14u: (in %s)\n", index, tmp);
	free(tmp);
	tmp = rz_bin_dex_resolve_string_by_idx(dex, field_id->name_idx);
	rz_cons_printf("      name          : '%s'\n", tmp);
	free(tmp);
	tmp = rz_bin_dex_resolve_type_id_by_idx(dex, field_id->type_idx);
	rz_cons_printf("      type          : '%s'\n", tmp);
	free(tmp);
	tmp = decode_access_flags(encoded_field->access_flags);
	rz_cons_printf("      access        : 0x%04" PFMT64x " (%s)\n", encoded_field->access_flags, tmp ? tmp : "");
	free(tmp);
}

static void dex_print_encoded_method(RzBinDex *dex, ut32 index, DexEncodedMethod *encoded_method) {
	if (dex->method_ids_size < encoded_method->method_idx) {
		rz_cons_printf("    #%-14u: unknown id %" PFMT64u "\n", index, encoded_method->method_idx);
		return;
	}
	DexMethodId *method_id = (DexMethodId *)rz_pvector_at(dex->method_ids, encoded_method->method_idx);

	char *tmp = rz_bin_dex_resolve_type_id_by_idx(dex, method_id->class_idx);
	rz_cons_printf("    #%-14u: (in %s)\n", index, tmp);
	free(tmp);
	tmp = rz_bin_dex_resolve_string_by_idx(dex, method_id->name_idx);
	rz_cons_printf("      name          : '%s'\n", tmp);
	free(tmp);
	tmp = rz_bin_dex_resolve_proto_by_idx(dex, method_id->proto_idx);
	rz_cons_printf("      type          : '%s'\n", tmp);
	free(tmp);
	tmp = decode_access_flags(encoded_method->access_flags);
	rz_cons_printf("      access        : 0x%04" PFMT64x " (%s)\n", encoded_method->access_flags, tmp ? tmp : "");
	free(tmp);
	rz_cons_printf("      method_idx    : %" PFMT64u "\n", encoded_method->method_idx);
	rz_cons_printf("      code          : (%s)\n", encoded_method->code_offset >= RZ_DEX_RELOC_ADDRESS ? "none" : "available");
}

static void dex_print_class_def(RzBinDex *dex, ut32 index, DexClassDef *class_def) {
	ut32 j;
	RzListIter *it;
	DexEncodedField *encoded_field;
	DexEncodedMethod *encoded_method;
	rz_cons_printf("Class #%u header:\n", index);
	rz_cons_printf("offset              : 0x%" PFMT64x "\n", class_def->offset);
	rz_cons_printf("class_idx           : %u\n", class_def->class_idx);
	rz_cons_printf("access_flags        : %u (0x%04x)\n", class_def->access_flags, class_def->access_flags);
	rz_cons_printf("superclass_idx      : %u\n", class_def->superclass_idx);
	rz_cons_printf("interfaces_off      : %u (0x%06x)\n", class_def->interfaces_offset, class_def->interfaces_offset);
	rz_cons_printf("source_file_idx     : %u\n", class_def->source_file_idx);
	rz_cons_printf("annotations_off     : %u (0x%06x)\n", class_def->annotations_offset, class_def->annotations_offset);
	rz_cons_printf("class_data_off      : %u (0x%06x)\n", class_def->class_data_offset, class_def->class_data_offset);
	rz_cons_printf("static_values_offset: %u (0x%06x)\n", class_def->static_values_offset, class_def->static_values_offset);
	j = rz_list_length(class_def->static_fields);
	rz_cons_printf("static_fields_size  : %u\n", j);
	j = rz_list_length(class_def->instance_fields);
	rz_cons_printf("instance_fields_size: %u\n", j);
	j = rz_list_length(class_def->direct_methods);
	rz_cons_printf("direct_methods_size : %u\n", j);
	j = rz_list_length(class_def->virtual_methods);
	rz_cons_printf("virtual_methods_size: %u\n\n", j);

	rz_cons_printf("Class #%-13u-\n", index);
	char *tmp = rz_bin_dex_resolve_type_id_by_idx(dex, class_def->class_idx);
	rz_cons_printf("  Class descriptor  : '%s'\n", tmp);
	free(tmp);
	tmp = decode_access_flags(class_def->access_flags);
	rz_cons_printf("  Access flags      : 0x%04x (%s)\n", class_def->access_flags, tmp ? tmp : "");
	free(tmp);
	tmp = rz_bin_dex_resolve_type_id_by_idx(dex, class_def->superclass_idx);
	rz_cons_printf("  Superclass        : '%s'\n", tmp);
	free(tmp);
	rz_cons_printf("  Interfaces        -\n");
	for (j = 0; j < class_def->n_interfaces; ++j) {
		tmp = rz_bin_dex_resolve_type_id_by_idx(dex, class_def->interfaces[j]);
		rz_cons_printf("    #%-15u: '%s'\n", j, tmp);
		free(tmp);
	}
	rz_cons_printf("  Static fields     -\n");
	j = 0;
	rz_list_foreach (class_def->static_fields, it, encoded_field) {
		dex_print_encoded_field(dex, j, encoded_field);
		j++;
	}
	rz_cons_printf("  Instance fields   -\n");
	j = 0;
	rz_list_foreach (class_def->instance_fields, it, encoded_field) {
		dex_print_encoded_field(dex, j, encoded_field);
		j++;
	}
	rz_cons_printf("  Direct methods    -\n");
	j = 0;
	rz_list_foreach (class_def->direct_methods, it, encoded_method) {
		dex_print_encoded_method(dex, j, encoded_method);
		j++;
	}
	rz_cons_printf("  Virtual methods   -\n");
	j = 0;
	rz_list_foreach (class_def->virtual_methods, it, encoded_method) {
		dex_print_encoded_method(dex, j, encoded_method);
		j++;
	}
}

RZ_IPI RzCmdStatus rz_cmd_dexs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzBinDex *dex = core_dex_get_class(core);
	if (!dex) {
		return RZ_CMD_STATUS_ERROR;
	}

	// mimic dexdump output
	char *tmp = NULL;
	rz_cons_printf("DEX file header:\n");
	tmp = rz_bin_dex_version(dex);
	rz_cons_printf("version             : %s\n", tmp);
	free(tmp);
	rz_cons_printf("checksum            : %08x\n", dex->checksum);
	rz_cons_printf("signature           : %02x%02x...%02x%02x\n", dex->signature[0], dex->signature[1], dex->signature[18], dex->signature[19]);
	rz_cons_printf("file_size           : %u\n", dex->file_size);
	rz_cons_printf("header_size         : %u\n", dex->header_size);
	rz_cons_printf("link_size           : %u\n", dex->link_size);
	rz_cons_printf("link_off            : %u (0x%06x)\n", dex->link_offset, dex->link_offset);
	rz_cons_printf("string_ids_size     : %u\n", dex->string_ids_size);
	rz_cons_printf("string_ids_off      : %u (0x%06x)\n", dex->string_ids_offset, dex->string_ids_offset);
	rz_cons_printf("type_ids_size       : %u\n", dex->type_ids_size);
	rz_cons_printf("type_ids_off        : %u (0x%06x)\n", dex->type_ids_offset, dex->type_ids_offset);
	rz_cons_printf("proto_ids_size      : %u\n", dex->proto_ids_size);
	rz_cons_printf("proto_ids_off       : %u (0x%06x)\n", dex->proto_ids_offset, dex->proto_ids_offset);
	rz_cons_printf("field_ids_size      : %u\n", dex->field_ids_size);
	rz_cons_printf("field_ids_off       : %u (0x%06x)\n", dex->field_ids_offset, dex->field_ids_offset);
	rz_cons_printf("method_ids_size     : %u\n", dex->method_ids_size);
	rz_cons_printf("method_ids_off      : %u (0x%06x)\n", dex->method_ids_offset, dex->method_ids_offset);
	rz_cons_printf("class_defs_size     : %u\n", dex->class_defs_size);
	rz_cons_printf("class_defs_off      : %u (0x%06x)\n", dex->class_defs_offset, dex->class_defs_offset);
	rz_cons_printf("data_size           : %u\n", dex->data_size);
	rz_cons_printf("data_off            : %u (0x%06x)\n\n", dex->data_offset, dex->data_offset);

	for (ut32 i = 0; i < rz_pvector_len(dex->class_defs); ++i) {
		DexClassDef *class_def = rz_pvector_at(dex->class_defs, i);
		dex_print_class_def(dex, i, class_def);
	}

	return RZ_CMD_STATUS_OK;
}

static void dex_print_class_def_exports(RzBinDex *dex, ut32 index, DexClassDef *class_def) {
	ut32 j;
	RzListIter *it;
	DexEncodedField *encoded_field;
	DexEncodedMethod *encoded_method;
	rz_cons_printf("Class #%-13u-\n", index);
	char *tmp = rz_bin_dex_resolve_type_id_by_idx(dex, class_def->class_idx);
	rz_cons_printf("  Class descriptor  : '%s'\n", tmp);
	free(tmp);
	tmp = decode_access_flags(class_def->access_flags);
	rz_cons_printf("  Access flags      : 0x%04x (%s)\n", class_def->access_flags, tmp ? tmp : "");
	free(tmp);
	tmp = rz_bin_dex_resolve_type_id_by_idx(dex, class_def->superclass_idx);
	rz_cons_printf("  Superclass        : '%s'\n", tmp);
	free(tmp);
	rz_cons_printf("  Interfaces        -\n");
	for (j = 0; j < class_def->n_interfaces; ++j) {
		tmp = rz_bin_dex_resolve_type_id_by_idx(dex, class_def->interfaces[j]);
		rz_cons_printf("    #%-15u: '%s'\n", j, tmp);
		free(tmp);
	}
	rz_cons_printf("  Static fields     -\n");
	j = 0;
	rz_list_foreach (class_def->static_fields, it, encoded_field) {
		if ((encoded_field->access_flags & (ACCESS_FLAG_PUBLIC | ACCESS_FLAG_PROTECTED)) != 0) {
			dex_print_encoded_field(dex, j, encoded_field);
		}
		j++;
	}
	rz_cons_printf("  Instance fields   -\n");
	j = 0;
	rz_list_foreach (class_def->instance_fields, it, encoded_field) {
		if ((encoded_field->access_flags & (ACCESS_FLAG_PUBLIC | ACCESS_FLAG_PROTECTED)) != 0) {
			dex_print_encoded_field(dex, j, encoded_field);
		}
		j++;
	}
	rz_cons_printf("  Direct methods    -\n");
	j = 0;
	rz_list_foreach (class_def->direct_methods, it, encoded_method) {
		if ((encoded_method->access_flags & (ACCESS_FLAG_PUBLIC | ACCESS_FLAG_PROTECTED)) != 0) {
			dex_print_encoded_method(dex, j, encoded_method);
		}
		j++;
	}
	rz_cons_printf("  Virtual methods   -\n");
	j = 0;
	rz_list_foreach (class_def->virtual_methods, it, encoded_method) {
		if ((encoded_method->access_flags & (ACCESS_FLAG_PUBLIC | ACCESS_FLAG_PROTECTED)) != 0) {
			dex_print_encoded_method(dex, j, encoded_method);
		}
		j++;
	}
}

RZ_IPI RzCmdStatus rz_cmd_dexe_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzBinDex *dex = core_dex_get_class(core);
	if (!dex) {
		return RZ_CMD_STATUS_ERROR;
	}

	for (ut32 i = 0; i < rz_pvector_len(dex->class_defs); ++i) {
		DexClassDef *class_def = rz_pvector_at(dex->class_defs, i);
		if ((class_def->access_flags & ACCESS_FLAG_PUBLIC) != 0) {
			dex_print_class_def_exports(dex, i, class_def);
		}
	}

	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescHelp dex_usage = {
	.summary = "Core plugin to visualize dex class information",
};

static_description_without_args(dexs, "prints the dex structure");
static_description_without_args(dexe, "prints the dex exported methods");

static bool rz_cmd_dex_init_handler(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		return false;
	}

	RzCmdDesc *dex = rz_cmd_desc_group_new(rcmd, root_cd, "dex", NULL, NULL, &dex_usage);
	if (!dex) {
		rz_warn_if_reached();
		return false;
	}

	rz_cmd_desc_argv_modes_new_warn(rcmd, dex, dexs, RZ_OUTPUT_MODE_STANDARD);
	rz_cmd_desc_argv_modes_new_warn(rcmd, dex, dexe, RZ_OUTPUT_MODE_STANDARD);

	return true;
}

static bool rz_cmd_dex_fini_handler(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *cd = rz_cmd_get_desc(rcmd, "dex");
	rz_return_val_if_fail(cd, false);
	return rz_cmd_desc_remove(rcmd, cd);
}

RzCorePlugin rz_core_plugin_dex = {
	.name = "dex",
	.desc = "Suite of dex commands, type `dex` for more info",
	.license = "LGPL-3.0-only",
	.author = "deroad",
	.version = "1.0",
	.init = rz_cmd_dex_init_handler,
	.fini = rz_cmd_dex_fini_handler,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_dex,
	.version = RZ_VERSION
};
#endif
