// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_demangler.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <string.h>
#include <rz_analysis.h>

#include "../format/java/class_bin.h"

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
	rz_warn_if_fail(rz_cmd_desc_argv_modes_new(rcmd, root, #cmd, flags, name_handler(cmd), &name_help(cmd)))

#define rz_cmd_desc_argv_new_warn(rcmd, root, cmd) \
	rz_warn_if_fail(rz_cmd_desc_argv_new(rcmd, root, #cmd, name_handler(cmd), &name_help(cmd)))

static RzBinJavaClass *core_java_get_class(RzCore *core) {
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
	return plugin && !strcmp(plugin->name, "java") ? (RzBinJavaClass *)b->cur->o->bin_obj : NULL;
}

RZ_IPI RzCmdStatus rz_cmd_javac_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzBinJavaClass *jclass = core_java_get_class(core);
	if (!jclass) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (mode & RZ_OUTPUT_MODE_JSON) {
		PJ *pj = pj_new();
		if (!pj) {
			return RZ_CMD_STATUS_ERROR;
		}

		rz_bin_java_class_as_json(jclass, pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} else {
		RzStrBuf *sb = rz_strbuf_new("");
		if (!sb) {
			return RZ_CMD_STATUS_ERROR;
		}

		rz_bin_java_class_as_text(jclass, sb);
		rz_cons_print(rz_strbuf_get(sb));
		rz_strbuf_free(sb);
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_javap_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzBinJavaClass *jclass = core_java_get_class(core);
	if (!jclass) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (mode & RZ_OUTPUT_MODE_JSON) {
		PJ *pj = pj_new();
		if (!pj) {
			return RZ_CMD_STATUS_ERROR;
		}

		rz_bin_java_class_const_pool_as_json(jclass, pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} else {
		RzStrBuf *sb = rz_strbuf_new("");
		if (!sb) {
			return RZ_CMD_STATUS_ERROR;
		}

		rz_bin_java_class_const_pool_as_text(jclass, sb);
		rz_cons_print(rz_strbuf_get(sb));
		rz_strbuf_free(sb);
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_javai_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzBinJavaClass *jclass = core_java_get_class(core);
	if (!jclass) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (mode & RZ_OUTPUT_MODE_JSON) {
		PJ *pj = pj_new();
		if (!pj) {
			return RZ_CMD_STATUS_ERROR;
		}

		rz_bin_java_class_interfaces_as_json(jclass, pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} else {
		RzStrBuf *sb = rz_strbuf_new("");
		if (!sb) {
			return RZ_CMD_STATUS_ERROR;
		}

		rz_bin_java_class_interfaces_as_text(jclass, sb);
		rz_cons_print(rz_strbuf_get(sb));
		rz_strbuf_free(sb);
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_javam_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzBinJavaClass *jclass = core_java_get_class(core);
	if (!jclass) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (mode & RZ_OUTPUT_MODE_JSON) {
		PJ *pj = pj_new();
		if (!pj) {
			return RZ_CMD_STATUS_ERROR;
		}

		rz_bin_java_class_methods_as_json(jclass, pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} else {
		RzStrBuf *sb = rz_strbuf_new("");
		if (!sb) {
			return RZ_CMD_STATUS_ERROR;
		}

		rz_bin_java_class_methods_as_text(jclass, sb);
		rz_cons_print(rz_strbuf_get(sb));
		rz_strbuf_free(sb);
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_javaf_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzBinJavaClass *jclass = core_java_get_class(core);
	if (!jclass) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (mode & RZ_OUTPUT_MODE_JSON) {
		PJ *pj = pj_new();
		if (!pj) {
			return RZ_CMD_STATUS_ERROR;
		}

		rz_bin_java_class_fields_as_json(jclass, pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} else {
		RzStrBuf *sb = rz_strbuf_new("");
		if (!sb) {
			return RZ_CMD_STATUS_ERROR;
		}

		rz_bin_java_class_fields_as_text(jclass, sb);
		rz_cons_print(rz_strbuf_get(sb));
		rz_strbuf_free(sb);
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_javas_handler(RzCore *core, int argc, const char **argv) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzBinJavaClass *jclass = core_java_get_class(core);
	if (!jclass) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		return RZ_CMD_STATUS_ERROR;
	}

	rz_bin_java_class_as_source_code(jclass, sb);
	rz_cons_print(rz_strbuf_get(sb));
	rz_strbuf_free(sb);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_javar_handler(RzCore *core, int argc, const char **argv) {
	if (argc != 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzBinJavaClass *jclass = core_java_get_class(core);
	if (!jclass) {
		return RZ_CMD_STATUS_ERROR;
	}

	st32 index = rz_num_math(core->num, argv[1]);

	if (index < 1) {
		RZ_LOG_ERROR("can't resolve constant pool index %d\n", index);
		return RZ_CMD_STATUS_INVALID;
	}

	char *resolved = rz_bin_java_class_const_pool_resolve_index(jclass, index);
	if (!resolved) {
		RZ_LOG_ERROR("can't resolve constant pool index %d\n", index);
		return RZ_CMD_STATUS_INVALID;
	}

	RzDemanglerFlag dflags = rz_demangler_get_flags(core->bin->demangler);
	char *demangled = rz_demangler_java(resolved, dflags);
	if (demangled) {
		rz_cons_println(demangled);
	} else {
		rz_cons_println(resolved);
	}

	free(resolved);
	free(demangled);
	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescHelp java_usage = {
	.summary = "Core plugin to visualize java class information",
};

static_description_without_args(javac, "prints the class structure");
static_description_without_args(javaf, "prints the class fields");
static_description_without_args(javai, "prints the class interfaces");
static_description_without_args(javam, "prints the class methods");
static_description_without_args(javap, "prints the class constant pool");
static_description_without_args(javas, "prints the class like a java source code");

static const RzCmdDescArg name_args(javar)[] = {
	{
		.name = "index",
		.type = RZ_CMD_ARG_TYPE_NUM,
	},
	{ 0 },
};

static const RzCmdDescHelp name_help(javar) = {
	.summary = "resolves the class constant pool value at a given index",
	.args = name_args(javar),
};

static bool rz_cmd_java_init_handler(RzCore *core, void **private_data) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		return false;
	}

	RzCmdDesc *java = rz_cmd_desc_group_new(rcmd, root_cd, "java", NULL, NULL, &java_usage);
	if (!java) {
		rz_warn_if_reached();
		return false;
	}

	rz_cmd_desc_argv_modes_new_warn(rcmd, java, javac, RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON);
	rz_cmd_desc_argv_modes_new_warn(rcmd, java, javaf, RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON);
	rz_cmd_desc_argv_modes_new_warn(rcmd, java, javai, RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON);
	rz_cmd_desc_argv_modes_new_warn(rcmd, java, javam, RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON);
	rz_cmd_desc_argv_modes_new_warn(rcmd, java, javap, RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON);
	rz_cmd_desc_argv_new_warn(rcmd, java, javas);
	rz_cmd_desc_argv_new_warn(rcmd, java, javar);

	return true;
}

static bool rz_cmd_java_fini_handler(RzCore *core, void **private_data) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *cd = rz_cmd_get_desc(rcmd, "java");
	rz_return_val_if_fail(cd, false);
	return rz_cmd_desc_remove(rcmd, cd);
}

RzCorePlugin rz_core_plugin_java = {
	.name = "java",
	.desc = "Suite of java commands, type `java` for more info",
	.license = "LGPL-3.0-only",
	.author = "deroad",
	.version = "1.0",
	.init = rz_cmd_java_init_handler,
	.fini = rz_cmd_java_fini_handler,
	.get_config = NULL,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_java,
	.version = RZ_VERSION
};
#endif
