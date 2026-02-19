// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "core_private.h"

#if RZ_SYS_BITS == RZ_SYS_BITS_64
#define CORE_DEFAULT_BITS 64
#else
#define CORE_DEFAULT_BITS 32
#endif

#define CORE_DEFAULT_ARCH     RZ_SYS_ARCH
#define CORE_DEFAULT_PLATFORM ""
#define CORE_DEFAULT_FEATURES ""
#define CORE_DEFAULT_OS       RZ_SYS_OS
#define CORE_DEFAULT_PARSER   RZ_SYS_ARCH ".pseudo"

#define core_update_config_s core_update_config_node_without_callback_string
#define core_update_config_i core_update_config_node_without_callback_int
#define core_update_config_b core_update_config_node_without_callback_bool

RZ_DEPRECATE RZ_IPI const char *rz_core_get_arch(RzCore *core) {
	rz_return_val_if_fail(core && core->rasm, CORE_DEFAULT_ARCH);

	if (core->rasm->cur && RZ_STR_ISNOTEMPTY(core->rasm->cur->name)) {
		return core->rasm->cur->name;
	}
	return CORE_DEFAULT_ARCH;
}

RZ_DEPRECATE RZ_IPI ut32 rz_core_get_bits(RzCore *core) {
	rz_return_val_if_fail(core && core->rasm, CORE_DEFAULT_BITS);

	if (core->rasm->bits > 0) {
		return core->rasm->bits;
	}
	return CORE_DEFAULT_BITS;
}

RZ_DEPRECATE RZ_IPI ut32 rz_core_get_pc_align(RzCore *core) {
	rz_return_val_if_fail(core && core->rasm, 1);

	if (core->rasm->pcalign > 0) {
		return core->rasm->pcalign;
	}
	return 1;
}

RZ_DEPRECATE RZ_IPI const char *rz_core_get_cpu(RzCore *core) {
	rz_return_val_if_fail(core && core->rasm, CORE_DEFAULT_ARCH);

	if (RZ_STR_ISNOTEMPTY(core->rasm->cpu)) {
		return core->rasm->cpu;
	}
	return rz_core_get_arch(core);
}

RZ_DEPRECATE RZ_IPI const char *rz_core_get_platform(RzCore *core) {
	rz_return_val_if_fail(core && core->rasm, CORE_DEFAULT_PLATFORM);

	if (RZ_STR_ISNOTEMPTY(core->rasm->platforms)) {
		return core->rasm->platforms;
	}
	return CORE_DEFAULT_PLATFORM;
}

RZ_DEPRECATE RZ_IPI const char *rz_core_get_features(RzCore *core) {
	rz_return_val_if_fail(core && core->rasm, CORE_DEFAULT_FEATURES);

	if (RZ_STR_ISNOTEMPTY(core->rasm->features)) {
		return core->rasm->features;
	}
	return CORE_DEFAULT_FEATURES;
}

RZ_DEPRECATE RZ_IPI const char *rz_core_get_os(RzCore *core) {
	rz_return_val_if_fail(core && core->analysis, CORE_DEFAULT_OS);

	if (RZ_STR_ISNOTEMPTY(core->analysis->os)) {
		return core->analysis->os;
	}
	return CORE_DEFAULT_OS;
}

RZ_DEPRECATE RZ_IPI const char *rz_core_get_parser(RzCore *core) {
	rz_return_val_if_fail(core && core->parser, CORE_DEFAULT_OS);

	if (core->parser->cur && RZ_STR_ISNOTEMPTY(core->parser->cur->name)) {
		return core->parser->cur->name;
	}
	return CORE_DEFAULT_PARSER;
}

// copied from cconfig.c & cleaned
RZ_DEPRECATE static void core_update_config_bits_options(RzCore *core, const char *name) {
	RzConfigNode *node = rz_config_node_get(core->config, name);
	if (!node) {
		return;
	} else if (!core->rasm->cur) {
		node->options->free = free;
		rz_list_purge(node->options);
		return;
	}

	node->options->free = free;
	rz_list_purge(node->options);

	ut32 bits = core->rasm->cur->bits;
	for (ut32 i = 1; i <= bits; i <<= 1) {
		if (i & bits) {
			rz_list_append(node->options, rz_str_newf("%u", i));
		}
	}
}

RZ_DEPRECATE static void core_update_config_options(RzConfigNode *node, const char *list_comma_sep) {
	node->options->free = free;
	rz_list_purge(node->options);

	if (RZ_STR_ISEMPTY(list_comma_sep)) {
		return;
	}

	char *c = rz_str_dup(list_comma_sep);
	if (!c) {
		return;
	}

	size_t n = rz_str_split(c, ',');
	for (size_t i = 0; i < n; i++) {
		const char *word = rz_str_word_get0(c, i);
		if (RZ_STR_ISNOTEMPTY(word)) {
			rz_list_append(node->options, rz_str_dup(word));
		}
	}
	free(c);
}

// copied from cconfig.c & cleaned
RZ_DEPRECATE static void core_update_config_cpu_options(RzCore *core, const char *name) {
	RzConfigNode *node = rz_config_node_get(core->config, name);
	if (!node) {
		return;
	} else if (!core->rasm->cur) {
		node->options->free = free;
		rz_list_purge(node->options);
		return;
	}

	core_update_config_options(node, core->rasm->cur->cpus);
}

// copied from cconfig.c & cleaned
static void core_update_config_platform_options(RzCore *core, const char *name) {
	RzConfigNode *node = rz_config_node_get(core->config, name);
	if (!node) {
		return;
	} else if (!core->rasm->cur) {
		node->options->free = free;
		rz_list_purge(node->options);
		return;
	}

	core_update_config_options(node, core->rasm->cur->platforms);
}

// copied from cconfig.c & cleaned
static void core_update_config_features_options(RzCore *core, const char *name) {
	RzConfigNode *node = rz_config_node_get(core->config, name);
	if (!node) {
		return;
	} else if (!core->rasm->cur) {
		node->options->free = free;
		rz_list_purge(node->options);
		return;
	}

	core_update_config_options(node, core->rasm->cur->features);
}

RZ_DEPRECATE static const RzBinInfo *core_arch_find_bin_info(RzCore *core, const char *arch) {
	if (RZ_STR_ISEMPTY(arch)) {
		return NULL;
	}
	const RzCoreFile *cf = NULL;
	RzListIter *lit;
	void **vit;

	rz_list_foreach (core->files, lit, cf) {
		rz_pvector_foreach (&cf->binfiles, vit) {
			const RzBinFile *bf = *vit;
			const RzBinInfo *info = rz_bin_object_get_info(bf->o);
			if (info && info->arch && RZ_STR_EQ(info->arch, arch)) {
				return info;
			}
		}
	}

	return NULL;
}

static bool core_arch_default_is_big_endian(RzCore *core) {
	bool big_endian = core->rasm->big_endian;
	const char *arch = rz_core_get_arch(core);

	const RzBinInfo *info = core_arch_find_bin_info(core, arch);
	if (info) {
		// always follow what the RzBin says first.
		big_endian = info->big_endian;
	}

	ut32 endian = rz_asm_get_endianness(core->rasm);
	if (endian == RZ_SYS_ENDIAN_NONE || endian == RZ_SYS_ENDIAN_BI) {
		// always return what the bin or default endianness of the system
		return big_endian;
	}

	if (big_endian && endian & RZ_SYS_ENDIAN_BIG) {
		// the endianness must be big endian.
		return true;
	}

	// the user must have asked for an arch that does not follow
	// what the bin says (or is just little endian) so, we return
	// as little endian.
	return false;
}

RZ_DEPRECATE static void core_update_endianness(RzCore *core) {
	bool big_endian = core_arch_default_is_big_endian(core);

	rz_asm_set_big_endian(core->rasm, big_endian);
	rz_analysis_set_big_endian(core->analysis, big_endian);

	// While analysis sets endianess for TypesDB there might
	// be cases when it isn't availble for the chosen analysis
	// plugin but types and printing commands still need the
	// corresponding endianness. Thus we set these explicitly:
	rz_type_db_set_endian(core->analysis->typedb, big_endian);
	core->print->big_endian = big_endian;

	// the big endian should also be assigned to dbg->bp->endian
	if (core->dbg && core->dbg->bp) {
		core->dbg->bp->endian = big_endian;
	}
}

// most of this code is a copy from cconfig
RZ_DEPRECATE static void core_update_syscall_db(RzCore *core) {
	if (core->analysis->syscall->db) {
		sdb_ns_set(core->sdb, "syscall", core->analysis->syscall->db);
	} else {
		sdb_ns_unset(core->sdb, "syscall", NULL);
	}
}

RZ_DEPRECATE static inline void core_update_asm_segoff(RzCore *core, const char *arch, ut32 bits) {
	bool autoseg = bits == 16 && RZ_STR_EQ(arch, "x86");
	rz_config_set_b(core->config, "asm.segoff", autoseg);
}

RZ_DEPRECATE static bool core_arch_set_os(RzCore *core, const char *arch, ut32 bits, const char *cpu, const char *os) {
	rz_analysis_set_os(core->analysis, os);

	if (RZ_STR_ISEMPTY(cpu)) {
		cpu = rz_core_get_cpu(core);
	}

	rz_syscall_setup(core->analysis->syscall, core->sys_path, arch, bits, cpu, os);
	core_update_syscall_db(core);
	core_update_asm_segoff(core, arch, bits);

	rz_core_analysis_cc_init(core);
	return true;
}

RZ_DEPRECATE static void core_update_text_align(RzCore *core) {
	int align = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN);
	if (align < 1) {
		align = 1;
	}

	core->rasm->pcalign = align;
	core->analysis->pcalign = align;
}

RZ_DEPRECATE static bool core_arch_set_cpu(RzCore *core, const char *arch, const char *cpu, const char *platform) {
	if (RZ_STR_ISNOTEMPTY(cpu)) {
		rz_asm_set_cpu(core->rasm, cpu);
		rz_analysis_set_cpu(core->analysis, cpu);
	} else {
		cpu = rz_core_get_cpu(core);
	}

	core_update_text_align(core);

	char *cpus_dir = rz_path_system(core->sys_path, RZ_SDB_ARCH_CPUS);
	if (!cpus_dir) {
		RZ_LOG_WARN("core: failed to get " RZ_SDB_ARCH_CPUS " via sys path\n");
		return false;
	}
	rz_platform_profiles_init(core->analysis->arch_target, cpu, arch, cpus_dir);
	free(cpus_dir);

	if (RZ_STR_ISNOTEMPTY(platform)) {
		free(core->rasm->platforms);
		core->rasm->platforms = rz_str_dup(platform);
	} else {
		platform = rz_core_get_platform(core);
	}

	char *platforms_dir = rz_path_system(core->sys_path, RZ_SDB_ARCH_PLATFORMS);
	if (!platforms_dir) {
		RZ_LOG_WARN("core: failed to get " RZ_SDB_ARCH_PLATFORMS " via sys path\n");
		return false;
	}

	rz_platform_target_index_init(core->analysis->platform_target, arch, cpu, platform, platforms_dir);
	free(platforms_dir);
	return true;
}

static ut32 core_arch_get_default_bits(RzCore *core, const char *arch) {
	const RzBinInfo *info = core_arch_find_bin_info(core, arch);
	if (!info || info->bits < 1) {
		return core->rasm->bits;
	}
	return info->bits;
}

RZ_DEPRECATE static bool core_update_arch(RzCore *core, const char *arch, ut32 bits, const char *cpu, const char *os, const char *platform) {
	char asmparser[32] = { 0 };

	if (RZ_STR_ISNOTEMPTY(arch)) {
		rz_strf(asmparser, "%s.pseudo", arch);
		if (!rz_asm_use(core->rasm, arch)) {
			RZ_LOG_ERROR("core: asm.arch: cannot set '%s'\n", arch);
			return false;
		} else if (!rz_analysis_use(core->analysis, arch)) {
			RZ_LOG_INFO("core: analysis.arch: cannot set '%s'\n", arch);
			// there are some plugins like the m68k which do not have a valid analysis plugin.
		}

		if (!bits) {
			bits = core_arch_get_default_bits(core, arch);
		}
	}

	if (bits > 0) {
		if (!rz_asm_set_bits(core->rasm, bits)) {
			RZ_LOG_ERROR("core: asm.bits: cannot set '%u'\n", bits);
			return false;
		} else if (!rz_analysis_set_bits(core->analysis, bits)) {
			RZ_LOG_INFO("core: analysis.bits: cannot set '%u'\n", bits);
			// there are some plugins like the m68k which do not have a valid analysis plugin.
		}
	} else {
		// we now need the current bits.
		bits = rz_core_get_bits(core);
	}

	// always update the endianness
	core_update_endianness(core);

	if (RZ_STR_ISEMPTY(arch)) {
		// we now need the current arch.
		arch = rz_core_get_arch(core);
	}

	if (RZ_STR_ISEMPTY(os)) {
		// we now need the current os.
		os = rz_core_get_os(core);
	}

	rz_egg_setup(core->egg, arch, bits, 0, os);

	if (asmparser[0]) {
		// only set when arch is set
		rz_parse_use(core->parser, asmparser);
	}

	rz_debug_set_arch(core->dbg, arch, bits);

	core_arch_set_cpu(core, arch, cpu, platform);

	// changing asm.arch changes analysis.arch
	// changing analysis.arch sets types db
	// so resetting is redundant and may lead to bugs
	// 1 case this is usefull is when types is null
	if (!core->analysis->typedb) {
		rz_core_analysis_type_init(core);
	}

	core_arch_set_os(core, arch, bits, cpu, os);

	return true;
}

// this is a ugly hack
RZ_DEPRECATE static void core_update_config_node_without_callback_string(RzCore *core, const char *name, const char *value) {
	RzConfigNode *node = rz_config_node_get(core->config, name);
	if (!node) {
		// the node does not exist yet and we can set stuff without worring about the callback
		rz_config_set(core->config, name, value);
		return;
	}

	if (node->value == value) {
		// avoid setting itself.
		return;
	}

	RzConfigCallback setter = node->setter;

	node->setter = NULL;
	rz_config_set(core->config, name, value);
	node->setter = setter;
}

// this is a ugly hack
RZ_DEPRECATE static void core_update_config_node_without_callback_int(RzCore *core, const char *name, ut64 value) {
	RzConfigNode *node = rz_config_node_get(core->config, name);
	if (!node) {
		// the node does not exist yet and we can set stuff without worring about the callback
		rz_config_set_i(core->config, name, value);
		return;
	}

	RzConfigCallback setter = node->setter;

	node->setter = NULL;
	rz_config_set_i(core->config, name, value);
	node->setter = setter;
}

// this is a ugly hack
RZ_DEPRECATE static void core_update_config_node_without_callback_bool(RzCore *core, const char *name, bool value) {
	RzConfigNode *node = rz_config_node_get(core->config, name);
	if (!node) {
		// the node does not exist yet and we can set stuff without worring about the callback
		rz_config_set_b(core->config, name, value);
		return;
	}

	RzConfigCallback setter = node->setter;

	node->setter = NULL;
	rz_config_set_b(core->config, name, value);
	node->setter = setter;
}

RZ_DEPRECATE static void core_update_config_from_arch(RzCore *core, bool new_arch) {
	// this is a terrible way to update the values but the current config
	// does weird callback calls which should not be done in this way and
	// instead rely on the actual store data in a structure.

	const char *arch = rz_core_get_arch(core);
	ut32 bits = rz_core_get_bits(core);
	ut32 pcalign = rz_core_get_pc_align(core);
	const char *cpu = rz_core_get_cpu(core);
	const char *platform = rz_core_get_platform(core);
	const char *features = rz_core_get_features(core);
	const char *os = rz_core_get_os(core);
	const char *parser = rz_core_get_parser(core);

	core_update_config_s(core, "asm.arch", arch);
	core_update_config_s(core, "asm.cpu", cpu);
	core_update_config_s(core, "asm.os", os);
	core_update_config_i(core, "asm.bits", bits);
	core_update_config_s(core, "asm.platform", platform);
	core_update_config_s(core, "asm.features", features);
	core_update_config_s(core, "asm.parser", parser);
	core_update_config_i(core, "asm.pcalign", pcalign);
	core_update_config_s(core, "analysis.arch", arch);
	core_update_config_s(core, "analysis.cpu", cpu);
	core_update_config_i(core, "analysis.bits", bits);
	core_update_config_b(core, "cfg.bigendian", core->rasm->big_endian);

	if (new_arch) {
		core_update_config_bits_options(core, "asm.bits");
		core_update_config_bits_options(core, "analysis.bits");
		core_update_config_cpu_options(core, "asm.cpu");
		core_update_config_cpu_options(core, "analysis.cpu");
		core_update_config_platform_options(core, "asm.platform");
		core_update_config_features_options(core, "asm.features");
	}
}

static bool core_can_update_value(const char *new_val, const char *old_val) {
	if (old_val && RZ_STR_ISNOTEMPTY(new_val)) {
		return true;
	}

	return RZ_STR_ISEMPTY(old_val) || RZ_STR_NE(new_val, old_val);
}

RZ_DEPRECATE static bool core_can_update(RzCore *core, const char *u_arch, ut32 u_bits, const char *u_cpu, const char *u_os, const char *u_platform) {
	// this is a terrible way to update the values but the current config
	// does weird callback calls which should not be done in this way and
	// instead rely on the actual store data in a structure.

	ut32 bits = rz_core_get_bits(core);
	const char *arch = rz_core_get_arch(core);
	const char *cpu = rz_core_get_cpu(core);
	const char *platform = rz_core_get_platform(core);
	const char *os = rz_core_get_os(core);

	return core_can_update_value(u_arch, arch) ||
		core_can_update_value(u_cpu, cpu) ||
		core_can_update_value(u_platform, platform) ||
		core_can_update_value(u_os, os) ||
		u_bits > bits;
}

/**
 * \brief      Sets the core correctly and in order when a specific configuration changes.
 *
 * \param      core      The core to configure
 * \param[in]  arch      The arch to set
 * \param[in]  bits      The bits to set
 * \param[in]  cpu       The cpu to set
 * \param[in]  os        The operating system to set
 * \param[in]  platform  The platform to set
 *
 * \return     On success returns true, otherwise false.
 */
RZ_DEPRECATE RZ_API bool rz_core_arch_configure(RZ_NONNULL RzCore *core, RZ_NULLABLE const char *arch, int bits, RZ_NULLABLE const char *cpu, RZ_NULLABLE const char *os, RZ_NULLABLE const char *platform) {
	rz_return_val_if_fail(core && core->config && core->bin && core->rasm && core->analysis && core->parser && core->dbg && core->egg, false);

	if (bits < 1) {
		// ensure we never have negative bits.
		bits = 0;
	}

	if (RZ_STR_ISEMPTY(arch) &&
		RZ_STR_ISEMPTY(cpu) &&
		RZ_STR_ISEMPTY(os) &&
		RZ_STR_ISEMPTY(platform) &&
		bits < 1) {
		RZ_LOG_INFO("core: cannot configure core when no information is provided\n");
		return false;
	}

	if (!core_can_update(core, arch, bits, cpu, os, platform)) {
		return true;
	}

	bool is_new_arch = RZ_STR_ISNOTEMPTY(arch);

	if (!core_update_arch(core, arch, bits, cpu, os, platform)) {
		return false;
	}

	core_update_config_from_arch(core, is_new_arch);
	return true;
}