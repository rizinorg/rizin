// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cons.h>
#include <rz_basefind.h>
#include <rz_th.h>
#include <rz_windows.h>
#include <rz_config.h>

#include "core_private.h"

static bool boolify_var_cb(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value || rz_str_is_false(node->value)) {
		free(node->value);
		node->value = rz_str_dup(rz_str_bool(node->i_value));
	}
	return true;
}

static void set_options(RzConfigNode *node, ...) {
	va_list argp;
	char *option = NULL;
	va_start(argp, node);
	option = va_arg(argp, char *);
	while (option) {
		rz_list_append(node->options, option);
		option = va_arg(argp, char *);
	}
	va_end(argp);
}

static bool isGdbPlugin(RzCore *core) {
	if (core->io && core->io->desc && core->io->desc->plugin) {
		if (core->io->desc->plugin->name && !strcmp(core->io->desc->plugin->name, "gdb")) {
			return true;
		}
	}
	return false;
}

static void print_node_options(RzConfigNode *node) {
	RzListIter *iter;
	char *option;
	rz_list_foreach (node->options, iter, option) {
		rz_cons_printf("%s\n", option);
	}
}

static int compareName(const RzAnalysisFunction *a, const RzAnalysisFunction *b, void *user) {
	return (a && b && a->name && b->name ? strcmp(a->name, b->name) : 0);
}

static int compareNameLen(const RzAnalysisFunction *a, const RzAnalysisFunction *b, void *user) {
	size_t la, lb;
	if (!a || !b || !a->name || !b->name) {
		return 0;
	}
	la = strlen(a->name);
	lb = strlen(a->name);
	return (la > lb) - (la < lb);
}

static int compareAddress(const RzAnalysisFunction *a, const RzAnalysisFunction *b, void *user) {
	return (a && b && a->addr && b->addr ? (a->addr > b->addr) - (a->addr < b->addr) : 0);
}

static int compareSize(const RzAnalysisFunction *a, const RzAnalysisFunction *b, void *user) {
	ut64 sa, sb;
	// return a && b && a->_size < b->_size;
	if (!a || !b) {
		return 0;
	}
	sa = rz_analysis_function_realsize(a);
	sb = rz_analysis_function_realsize(b);
	return (sa > sb) - (sa < sb);
}

static bool cb_search_case_sensitive(void *_core, void *_node) {
	RzConfigNode *node = _node;
	const char *case_sensitive = node->value;
	RzCore *core = _core;
	if (case_sensitive) {
		if (!strcmp(case_sensitive, "smart")) {
			core->cons->grep_icase = RZ_CONS_SEARCH_CASE_SMART;
		} else if (!strcmp(case_sensitive, "insensitive")) {
			core->cons->grep_icase = RZ_CONS_SEARCH_CASE_INSENSITIVE;
		} else if (!strcmp(case_sensitive, "sensitive")) {
			core->cons->grep_icase = RZ_CONS_SEARCH_CASE_SENSITIVE;
		} else {
			goto err;
		}
		return true;
	}
err:
	RZ_LOG_ERROR("grep: search.sensitive: invalid value (%s), support only `smart, sensitive, insensitive`\n", case_sensitive);
	return false;
}

static bool cb_diff_sort(void *_core, void *_node) {
	RzConfigNode *node = _node;
	const char *column = node->value;
	RzCore *core = _core;
	if (column && strcmp(column, "?")) {
		if (!strcmp(column, "name")) {
			core->analysis->columnSort = (RzListComparator)compareName;
		} else if (!strcmp(column, "namelen")) {
			core->analysis->columnSort = (RzListComparator)compareNameLen;
		} else if (!strcmp(column, "addr")) {
			core->analysis->columnSort = (RzListComparator)compareAddress;
		} else if (!strcmp(column, "size")) {
			core->analysis->columnSort = (RzListComparator)compareSize;
		} else {
			goto fail;
		}
		return true;
	}
fail:
	RZ_LOG_ERROR("core: diff.sort: invalid value (%s), supported only `name, namelen, addr, type, size, dist`\n", column);
	return false;
}

static inline void __setsegoff(RzConfig *cfg, const char *asmarch, int asmbits) {
	int autoseg = (!strncmp(asmarch, "x86", 3) && asmbits == 16);
	rz_config_set(cfg, "asm.segoff", rz_str_bool(autoseg));
}

static bool cb_debug_hitinfo(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->hitinfo = node->i_value;
	return true;
}

static bool cb_analysis_jmpretpoline(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.retpoline = node->i_value;
	return true;
}

static bool cb_analysis_armthumb(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.armthumb = node->i_value;
	return true;
}

static bool cb_analysis_depth(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.depth = node->i_value;
	return true;
}

static bool cb_analysis_graphdepth(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.graph_depth = node->i_value;
	return true;
}

static bool cb_analysis_afterjmp(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.afterjmp = node->i_value;
	return true;
}

static bool cb_analysis_aftertrap(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.aftertrap = node->i_value;
	return true;
}

static bool cb_analysis_delay(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.delay = node->i_value;
	return true;
}

static bool cb_analysis_vars(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.vars = node->i_value;
	return true;
}

static bool cb_analysis_nonull(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.nonull = node->i_value;
	return true;
}

static bool cb_analysis_strings(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		rz_config_set(core->config, "bin.strings", "false");
	}
	return true;
}

static bool cb_analysis_ignbithints(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.ignbithints = node->i_value;
	return true;
}

static bool cb_analysis_sleep(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->sleep = node->i_value;
	return true;
}

static bool cb_analysis_maxrefs(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->maxreflines = node->i_value;
	return true;
}

static bool cb_analysis_norevisit(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.norevisit = node->i_value;
	return true;
}

static bool cb_analysis_nopskip(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.nopskip = node->i_value;
	return true;
}

static bool cb_analysis_hpskip(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.hpskip = node->i_value;
	return true;
}

static void update_analysis_arch_options(RzCore *core, RzConfigNode *node) {
	RzAnalysisPlugin *h;
	RzListIter *it;
	if (core && core->analysis && node) {
		rz_list_purge(node->options);
		rz_list_foreach (core->analysis->plugins, it, h) {
			SETOPTIONS(node, h->name, NULL);
		}
	}
}

static bool cb_analysis_arch(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		update_analysis_arch_options(core, node);
		print_node_options(node);
		return false;
	}
	if (*node->value) {
		if (rz_analysis_use(core->analysis, node->value)) {
			return true;
		}
		const char *aa = rz_config_get(core->config, "asm.arch");
		if (!aa || strcmp(aa, node->value)) {
			RZ_LOG_ERROR("core: analysis.arch: cannot find '%s'\n", node->value);
		}
	}
	return false;
}

static bool cb_analysis_cpu(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	rz_analysis_set_cpu(core->analysis, node->value);
	/* set pcalign */
	{
		int v = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN);
		rz_config_set_i(core->config, "asm.pcalign", (v != -1) ? v : 0);
	}
	return true;
}

static bool cb_analysis_recont(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.recont = node->i_value;
	return true;
}

static bool cb_analysis_ijmp(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.ijmp = node->i_value;
	return true;
}

static bool cb_asmsubvarmin(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->parser->minval = node->i_value;
	return true;
}

static bool cb_asmsubtail(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->parser->subtail = node->i_value;
	return true;
}

static bool cb_scrlast(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->context->lastEnabled = node->i_value;
	return true;
}

static bool cb_scr_vi(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cons->line->enable_vi_mode = node->i_value;
	return true;
}

static bool cb_scr_prompt_mode(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cons->line->prompt_mode = node->i_value;
	return true;
}

static bool cb_scr_wideoff(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->print->wide_offsets = node->i_value;
	return true;
}

static bool cb_asmpseudo(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->rasm->pseudo = node->i_value;
	return true;
}

static bool cb_asmsubsec(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_SECSUB;
	} else {
		core->print->flags &= (~RZ_PRINT_FLAGS_SECSUB);
	}
	rz_print_set_flags(core->print, core->print->flags);
	return true;
}

static bool cb_asmassembler(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	rz_asm_use_assembler(core->rasm, node->value);
	return true;
}

static void update_asmcpu_options(RzCore *core, RzConfigNode *node) {
	RzAsmPlugin *h;
	RzListIter *iter;
	rz_return_if_fail(core && core->rasm);
	const char *arch = rz_config_get(core->config, "asm.arch");
	if (RZ_STR_ISEMPTY(arch)) {
		return;
	}
	rz_list_purge(node->options);
	rz_list_foreach (core->rasm->plugins, iter, h) {
		if (h->cpus && !strcmp(arch, h->name)) {
			char *c = rz_str_dup(h->cpus);
			int i, n = rz_str_split(c, ',');
			for (i = 0; i < n; i++) {
				const char *word = rz_str_word_get0(c, i);
				if (word && *word) {
					node->options->free = free;
					SETOPTIONS(node, rz_str_dup(word), NULL);
				}
			}
			free(c);
		}
	}
}

static bool cb_asm_cpu(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		update_asmcpu_options(core, node);
		/* print verbose help instead of plain option listing */
		RzCmdStateOutput state = { 0 };
		rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STANDARD);
		rz_core_asm_plugins_print(core, rz_config_get(core->config, "asm.arch"), &state);
		rz_cmd_state_output_print(&state);
		rz_cmd_state_output_fini(&state);
		return 0;
	}
	rz_asm_set_cpu(core->rasm, node->value);
	rz_config_set(core->config, "analysis.cpu", node->value);

	char *cpus_dir = rz_path_system(RZ_SDB_ARCH_CPUS);
	rz_platform_profiles_init(core->analysis->arch_target, node->value, rz_config_get(core->config, "asm.arch"), cpus_dir);
	free(cpus_dir);
	const char *platform = rz_config_get(core->config, "asm.platform");
	char *platforms_dir = rz_path_system(RZ_SDB_ARCH_PLATFORMS);
	rz_platform_target_index_init(core->analysis->platform_target, rz_config_get(core->config, "asm.arch"), node->value, platform, platforms_dir);
	free(platforms_dir);

	return true;
}

static void update_asmarch_options(RzCore *core, RzConfigNode *node) {
	RzAsmPlugin *h;
	RzListIter *iter;
	if (core && node && core->rasm) {
		rz_list_purge(node->options);
		rz_list_foreach (core->rasm->plugins, iter, h) {
			SETOPTIONS(node, h->name, NULL);
		}
	}
}

static void update_asmbits_options(RzCore *core, RzConfigNode *node) {
	if (core && core->rasm && core->rasm->cur && node) {
		int bits = core->rasm->cur->bits;
		int i;
		node->options->free = free;
		rz_list_purge(node->options);
		for (i = 1; i <= bits; i <<= 1) {
			if (i & bits) {
				SETOPTIONS(node, rz_str_newf("%d", i), NULL);
			}
		}
	}
}

static void update_syscall_ns(RzCore *core) {
	if (core->analysis->syscall->db) {
		sdb_ns_set(core->sdb, "syscall", core->analysis->syscall->db);
	} else {
		sdb_ns_unset(core->sdb, "syscall", NULL);
	}
}

static bool cb_asm_varfold(void *core, void *node) {
	char *choice[] = { "none", "group", "hide" };
	RzConfigNode *n = node;
	const char *user_choice = n->value;
	for (int i = 0; i < sizeof(choice) / sizeof(choice[0]); i++) {
		if (!strcmp(choice[i], user_choice)) {
			return true;
		}
	}
	RZ_LOG_ERROR("asm.var.fold: Invalid choice. Only support `none, group, hide`\n");
	return false;
}

static void handle_supported_cpus(RzConfig *config, const char *supported, const char *cpu) {
	// strdup is required when calling rz_config_set, because it will free the old value
	char *cpu_copy = rz_str_dup(cpu);

	// we need to duplicate supported because rz_str_split_list will modify the string.
	char *supported_copy = rz_str_dup(supported);
	RzList *cpu_list = rz_str_split_list(supported_copy, ",", 0);
	RzListIter *it = NULL;
	const char *lcpu = NULL;
	rz_list_foreach (cpu_list, it, lcpu) {
		if (!strcmp(lcpu, cpu_copy)) {
			rz_config_set(config, "asm.cpu", cpu_copy);
			break;
		}
	}

	if (lcpu && strcmp(lcpu, cpu_copy) != 0) {
		RZ_LOG_ERROR("asm.cpu: unknown cpu: %s\n", cpu_copy)
	}

	rz_list_free(cpu_list);
	free(supported_copy);
	free(cpu_copy);
}

static bool cb_asm_arch(void *user, void *data) {
	char asmparser[32];
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	const char *asmos = NULL;
	int bits = RZ_SYS_BITS;
	if (!*node->value || !core || !core->rasm) {
		return false;
	}
	asmos = rz_config_get(core->config, "asm.os");
	if (core && core->analysis && core->analysis->bits) {
		bits = core->analysis->bits;
	}
	if (node->value[0] == '?') {
		update_asmarch_options(core, node);
		if (strlen(node->value) > 1 && node->value[1] == '?') {
			/* print more verbose help instead of plain option values */
			RzCmdStateOutput state = { 0 };
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STANDARD);
			rz_core_asm_plugins_print(core, NULL, &state);
			rz_cmd_state_output_print(&state);
			rz_cmd_state_output_fini(&state);
			return false;
		} else {
			print_node_options(node);
			return false;
		}
	}
	rz_egg_setup(core->egg, node->value, bits, 0, RZ_SYS_OS);

	if (!rz_asm_use(core->rasm, node->value)) {
		RZ_LOG_ERROR("core: asm.arch: cannot find (%s)\n", node->value);
		return false;
	}
	char *asm_cpu = rz_str_dup(rz_config_get(core->config, "asm.cpu"));
	if (core->rasm->cur) {
		const char *cpus_supported = core->rasm->cur->cpus;
		if (RZ_STR_ISNOTEMPTY(cpus_supported) &&
			RZ_STR_ISNOTEMPTY(asm_cpu)) {
			handle_supported_cpus(core->config, cpus_supported, asm_cpu);
		} else {
			rz_config_set(core->config, "asm.cpu", "");
		}
		bits = core->rasm->cur->bits;
		if (8 & bits) {
			bits = 8;
		} else if (16 & bits) {
			bits = 16;
		} else if (32 & bits) {
			bits = 32;
		} else {
			bits = 64;
		}
		update_asmbits_options(core, rz_config_node_get(core->config, "asm.bits"));
	} else {
		rz_config_set(core->config, "asm.cpu", "");
	}
	snprintf(asmparser, sizeof(asmparser), "%s.pseudo", node->value);
	rz_config_set(core->config, "asm.parser", asmparser);
	if (core->rasm->cur && core->analysis &&
		!(core->rasm->cur->bits & core->analysis->bits)) {
		rz_config_set_i(core->config, "asm.bits", bits);
	}

	rz_debug_set_arch(core->dbg, node->value, bits);
	if (!rz_config_set(core->config, "analysis.arch", node->value)) {
		char *p, *s = rz_str_dup(node->value);
		if (s) {
			p = strchr(s, '.');
			if (p) {
				*p = 0;
			}
			if (!rz_config_set(core->config, "analysis.arch", s)) {
				/* fall back to the analysis.null plugin */
				rz_config_set(core->config, "analysis.arch", "null");
			}
			free(s);
		}
	}
	// set pcalign
	if (core->analysis) {
		const char *asmcpu = rz_config_get(core->config, "asm.cpu");
		const char *platform = rz_config_get(core->config, "asm.platform");
		rz_syscall_setup(core->analysis->syscall, node->value, core->analysis->bits, asmcpu, asmos);
		update_syscall_ns(core);
		char *platforms_dir = rz_path_system(RZ_SDB_ARCH_PLATFORMS);
		char *cpus_dir = rz_path_system(RZ_SDB_ARCH_CPUS);
		rz_platform_target_index_init(core->analysis->platform_target, node->value, asmcpu, platform, platforms_dir);
		rz_platform_profiles_init(core->analysis->arch_target, asmcpu, node->value, cpus_dir);
		free(platforms_dir);
		free(cpus_dir);
	}
	__setsegoff(core->config, node->value, core->rasm->bits);

	// set a default endianness
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");

	// try to set endian of RzAsm to match binary
	rz_asm_set_big_endian(core->rasm, big_endian);
	// set endian of display to match binary
	core->print->big_endian = big_endian;

	rz_asm_set_cpu(core->rasm, asm_cpu);
	free(asm_cpu);
	RzConfigNode *asmcpu = rz_config_node_get(core->config, "asm.cpu");
	if (asmcpu) {
		update_asmcpu_options(core, asmcpu);
	}
	{
		int v = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN);
		if (v != -1) {
			rz_config_set_i(core->config, "asm.pcalign", v);
		} else {
			rz_config_set_i(core->config, "asm.pcalign", 0);
		}
	}
	/* reload types and cc info */
	// changing asm.arch changes analysis.arch
	// changing analysis.arch sets types db
	// so ressetting is redundant and may lead to bugs
	// 1 case this is usefull is when types is null
	if (!core->analysis || !core->analysis->typedb) {
		rz_core_analysis_type_init(core);
	}
	// set endian of RzAnalysis to match binary
	rz_analysis_set_big_endian(core->analysis, big_endian);
	rz_core_analysis_cc_init(core);

	const char *platform = rz_config_get(core->config, "asm.platform");
	if (asmcpu) {
		char *platforms_dir = rz_path_system(RZ_SDB_ARCH_PLATFORMS);
		char *cpus_dir = rz_path_system(RZ_SDB_ARCH_CPUS);
		rz_platform_target_index_init(core->analysis->platform_target, node->value, asmcpu->value, platform, platforms_dir);
		rz_platform_profiles_init(core->analysis->arch_target, asmcpu->value, node->value, cpus_dir);
		free(cpus_dir);
		free(platforms_dir);
	}

	return true;
}

static bool cb_dbgbtdepth(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->btdepth = node->i_value;
	return true;
}

static bool cb_asm_bits(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;

	if (node->value[0] == '?') {
		update_asmbits_options(core, node);
		print_node_options(node);
		return false;
	}

	bool ret = false;

	int bits = node->i_value;
	if (!bits) {
		return false;
	}
	if (bits > 0) {
		ret = rz_asm_set_bits(core->rasm, bits);
		if (!ret) {
			RzAsmPlugin *h = core->rasm->cur;
			if (!h) {
				RZ_LOG_ERROR("core: asm.bits: cannot set value, no plugins defined yet\n");
				ret = true;
			}
		}
		if (!rz_analysis_set_bits(core->analysis, bits)) {
			RZ_LOG_ERROR("core: asm.arch: cannot setup '%d' bits analysis engine\n", bits);
			ret = false;
		}
		core->print->bits = bits;
	}
	if (core->dbg && core->analysis && core->analysis->cur) {
		rz_debug_set_arch(core->dbg, core->analysis->cur->arch, bits);
		rz_analysis_set_reg_profile(core->analysis);
	}
	rz_core_analysis_cc_init(core);
	const char *asmos = rz_config_get(core->config, "asm.os");
	const char *asmarch = rz_config_get(core->config, "asm.arch");
	const char *asmcpu = rz_config_get(core->config, "asm.cpu");
	if (core->analysis) {
		if (!rz_syscall_setup(core->analysis->syscall, asmarch, bits, asmcpu, asmos)) {
			// eprintf ("asm.arch: Cannot setup syscall '%s/%s' from '%s'\n",
			//	node->value, asmos, RZ_LIBDIR"/rizin/"RZ_VERSION"/syscall");
		}
		update_syscall_ns(core);
		__setsegoff(core->config, asmarch, core->analysis->bits);
		if (core->dbg) {
			rz_bp_use(core->dbg->bp, asmarch);
		}
		/* set pcalign */
		int v = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN);
		rz_config_set_i(core->config, "asm.pcalign", (v != -1) ? v : 0);
	}
	return ret;
}

static void update_asmfeatures_options(RzCore *core, RzConfigNode *node) {
	int i, argc;

	if (core && core->rasm && core->rasm->cur) {
		if (core->rasm->cur->features) {
			char *features = rz_str_dup(core->rasm->cur->features);
			rz_list_purge(node->options);
			argc = rz_str_split(features, ',');
			for (i = 0; i < argc; i++) {
				node->options->free = free;
				const char *feature = rz_str_word_get0(features, i);
				if (feature) {
					rz_list_append(node->options, rz_str_dup(feature));
				}
			}
			free(features);
		}
	}
}

static bool cb_flag_realnames(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->flags->realnames = node->i_value;
	return true;
}

static bool cb_asm_features(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		update_asmfeatures_options(core, node);
		print_node_options(node);
		return 0;
	}
	RZ_FREE(core->rasm->features);
	RZ_FREE(core->analysis->features);
	if (node->value[0]) {
		core->rasm->features = rz_str_dup(node->value);
		core->analysis->features = rz_str_dup(node->value);
	}
	return 1;
}

static void update_asmplatforms_options(RzCore *core, RzConfigNode *node) {
	int i, argc;

	if (core && core->rasm && core->rasm->cur) {
		if (core->rasm->cur->platforms) {
			char *platforms = rz_str_dup(core->rasm->cur->platforms);
			rz_list_purge(node->options);
			argc = rz_str_split(platforms, ',');
			for (i = 0; i < argc; i++) {
				node->options->free = free;
				const char *feature = rz_str_word_get0(platforms, i);
				if (feature) {
					rz_list_append(node->options, rz_str_dup(feature));
				}
			}
			free(platforms);
		}
	}
}

static bool cb_asmplatform(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (!core) {
		return false;
	}
	if (*node->value == '?') {
		update_asmplatforms_options(core, node);
		print_node_options(node);
		return 0;
	}
	RZ_FREE(core->rasm->platforms);
	if (node->value[0]) {
		core->rasm->platforms = rz_str_dup(node->value);
	}
	const char *asmcpu = rz_config_get(core->config, "asm.cpu");
	const char *asmarch = rz_config_get(core->config, "asm.arch");
	char *platforms_dir = rz_path_system(RZ_SDB_ARCH_PLATFORMS);
	rz_platform_target_index_init(core->analysis->platform_target, asmarch, asmcpu, node->value, platforms_dir);
	free(platforms_dir);
	return 1;
}

static bool cb_asmlineswidth(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->lineswidth = node->i_value;
	return true;
}

static bool cb_emustr(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		rz_config_set(core->config, "asm.emu", "true");
	}
	return true;
}

static bool cb_emuskip(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		if (strlen(node->value) > 1 && node->value[1] == '?') {
			rz_cons_printf("Concatenation of meta types encoded as characters:\n"
				       "'d': data\n'c': code\n's': string\n'f': format\n'm': magic\n"
				       "'h': hide\n'C': comment\n'r': run\n"
				       "(default is 'ds' to skip data and strings)\n");
		} else {
			print_node_options(node);
		}
		return false;
	}
	return true;
}

static bool cb_asm_immhash(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->rasm->immdisp = node->i_value ? true : false;
	return true;
}

static bool cb_asm_invhex(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->rasm->invhex = node->i_value;
	return true;
}

static bool cb_asm_pcalign(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	int align = node->i_value;
	if (align < 0) {
		align = 0;
	}
	core->rasm->pcalign = align;
	core->analysis->pcalign = align;
	return true;
}

static bool cb_asmos(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	int asmbits = rz_config_get_i(core->config, "asm.bits");
	RzConfigNode *asmarch, *node = (RzConfigNode *)data;

	if (*node->value == '?') {
		print_node_options(node);
		return 0;
	}
	if (!node->value[0]) {
		free(node->value);
		node->value = rz_str_dup(RZ_SYS_OS);
	}
	asmarch = rz_config_node_get(core->config, "asm.arch");
	if (asmarch) {
		const char *asmcpu = rz_config_get(core->config, "asm.cpu");
		rz_syscall_setup(core->analysis->syscall, asmarch->value, core->analysis->bits, asmcpu, node->value);
		update_syscall_ns(core);
		__setsegoff(core->config, asmarch->value, asmbits);
	}
	rz_analysis_set_os(core->analysis, node->value);
	rz_core_analysis_cc_init(core);
	return true;
}

static void update_asmparser_options(RzCore *core, RzConfigNode *node) {
	RzListIter *iter;
	RzParsePlugin *parser;
	if (core && node && core->parser && core->parser->parsers) {
		rz_list_purge(node->options);
		rz_list_foreach (core->parser->parsers, iter, parser) {
			SETOPTIONS(node, parser->name, NULL);
		}
	}
}

static bool cb_asmparser(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->value[0] == '?') {
		update_asmparser_options(core, node);
		print_node_options(node);
		return false;
	}

	return rz_parse_use(core->parser, node->value);
}

static bool cb_binfilter(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->bin->filter = node->i_value;
	return true;
}

static bool cb_binat(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->binat = node->i_value;
	return true;
}

static bool cb_usextr(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->bin->use_xtr = node->i_value;
	return true;
}

static bool cb_strpurge(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		rz_cons_printf(
			"There can be multiple entries separated by commas. No whitespace before/after entries.\n"
			"Possible entries:\n"
			"  all          : purge all strings\n"
			"  true         : use the false_positive() classifier in cbin.c\n"
			"  addr         : purge string at addr\n"
			"  addr1-addr2  : purge all strings in the range addr1-addr2 inclusive\n"
			"  !addr        : prevent purge of string at addr by prev entries\n"
			"  !addr1-addr2 : prevent purge of strings in range addr1-addr2 inclusive by prev entries\n"
			"Neither !true nor !false is supported.\n"
			"\n"
			"Examples:\n"
			"  e bin.str.purge=true,0-0xff,!0x1a\n"
			"    -- purge strings using the false_positive() classifier in cbin.c and also strings \n"
			"       with addresses in the range 0-0xff, but not the string at 0x1a.\n"
			"  e bin.str.purge=all,!0x1000-0x1fff\n"
			"    -- purge all strings except the strings with addresses in the range 0x1000-0x1fff.\n");
		return false;
	}
	free(core->bin->strpurge);
	core->bin->strpurge = !*node->value || !strcmp(node->value, "false")
		? NULL
		: rz_str_dup(node->value);
	return true;
}

static bool cb_maxname(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	RzCore *core = (RzCore *)user;
	core->parser->maxflagnamelen = node->i_value;
	return true;
}

static bool cb_midflags(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->value[0] == '?') {
		print_node_options(node);
		return false;
	}
	return true;
}

static bool cb_strfilter(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->value[0] == '?') {
		if (strlen(node->value) > 1 && node->value[1] == '?') {
			rz_cons_printf("Valid values for bin.str.filter:\n"
				       "a  only alphanumeric printable\n"
				       "8  only strings with utf8 chars\n"
				       "p  file/directory paths\n"
				       "e  email-like addresses\n"
				       "u  urls\n"
				       "i  IPv4 address-like strings\n"
				       "U  only uppercase strings\n"
				       "f  format-strings\n");
		} else {
			print_node_options(node);
		}
		return false;
	} else {
		core->bin->strfilter = node->value[0];
	}
	return true;
}

static bool cb_binforce(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	rz_bin_force_plugin(core->bin, node->value);
	return true;
}

static bool cb_bindemangle(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->bin->demangle = node->i_value;
	return true;
}

static bool cb_bindemangle_flags(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		print_node_options(node);
		return false;
	}
	if (!strcmp(node->value, "all")) {
		rz_bin_demangle_with_flags(core->bin, RZ_DEMANGLER_FLAG_ENABLE_ALL);
	} else if (!strcmp(node->value, "base")) {
		rz_bin_demangle_with_flags(core->bin, RZ_DEMANGLER_FLAG_BASE);
	} else if (!strcmp(node->value, "simplify")) {
		rz_bin_demangle_with_flags(core->bin, RZ_DEMANGLER_FLAG_SIMPLIFY);
	} else {
		RZ_LOG_ERROR("config: invalid option for bin.demangle.flags\n");
		return false;
	}
	return true;
}

static bool cb_asmsyntax(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		print_node_options(node);
		return false;
	} else {
		int syntax = rz_asm_syntax_from_string(node->value);
		if (syntax == -1) {
			return false;
		}
		rz_asm_set_syntax(core->rasm, syntax);
	}
	return true;
}

static bool cb_bigendian(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	// Try to set endian based on preference, restrict by RzAsmPlugin
	bool isbig = rz_asm_set_big_endian(core->rasm, node->i_value);
	// Set analysis endianness the same as asm
	rz_analysis_set_big_endian(core->analysis, isbig);
	// While analysis sets endianess for TypesDB there might
	// be cases when it isn't availble for the chosen analysis
	// plugin but types and printing commands still need the
	// corresponding endianness. Thus we set these explicitly:
	rz_type_db_set_endian(core->analysis->typedb, node->i_value);
	core->print->big_endian = node->i_value;
	// the big endian should also be assigned to dbg->bp->endian
	if (core->dbg && core->dbg->bp) {
		core->dbg->bp->endian = isbig;
	}
	return true;
}

static bool cb_cfgdatefmt(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	snprintf(core->print->datefmt, 32, "%s", node->value);
	return true;
}

static bool cb_timezone(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->print->datezone = node->i_value;
	return true;
}

static bool cb_cfgdebug(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (!core) {
		return false;
	}
	if (core->io) {
		rz_config_set_b(core->config, "io.va", !node->i_value);
	}
	if (core->dbg && node->i_value) {
		const char *dbgbackend = rz_config_get(core->config, "dbg.backend");
		core->bin->is_debugger = true;
		rz_debug_use(core->dbg, dbgbackend);
		if (!strcmp(dbgbackend, "bf")) {
			rz_config_set(core->config, "asm.arch", "bf");
		}
		if (core->file) {
			rz_debug_select(core->dbg, rz_io_fd_get_pid(core->io, core->file->fd),
				rz_io_fd_get_tid(core->io, core->file->fd));
		}
	} else {
		rz_debug_use(core->dbg, NULL);
		core->bin->is_debugger = false;
	}
	return true;
}

static bool cb_dirhome(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->value) {
		rz_sys_setenv(RZ_SYS_HOME, node->value);
	}
	return true;
}

static bool cb_dirtmp(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	char *value = RZ_STR_ISNOTEMPTY(node->value) ? node->value : NULL;
	rz_sys_setenv(RZ_SYS_TMP, value);
	return true;
}

static bool cb_dirsrc(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	RzCore *core = (RzCore *)user;
	free(core->bin->srcdir);
	core->bin->srcdir = rz_str_dup(node->value);
	return true;
}

static bool cb_str_escbslash(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->print->esc_bslash = node->i_value;
	return true;
}

static bool cb_str_search_max_threads(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	RzThreadNCores max_threads = rz_th_max_threads(node->i_value);
	if (node->value[0] == '?') {
		rz_cons_printf("%d\n", max_threads);
		return false;
	}
	core->bin->str_search_cfg.max_threads = max_threads;
	return true;
}

static bool cb_str_search_min_length(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value < 1) {
		RZ_LOG_ERROR("str.search.min_length cannot be less than 1.\n");
		return false;
	} else if (node->i_value >= core->bin->str_search_cfg.buffer_size) {
		RZ_LOG_ERROR("str.search.buffer_size cannot be greater or equal to %" PFMTSZu ".\n", core->bin->str_search_cfg.buffer_size);
		return false;
	}

	core->bin->str_search_cfg.min_length = node->i_value;
	if (core->bin && rz_config_get_b(core->config, "str.search.reload")) {
		RzBinFile *bf = rz_bin_cur(core->bin);
		if (bf && bf->o) {
			rz_bin_object_reset_strings(core->bin, bf, bf->o);
		}
	}
	return true;
}

static bool cb_str_search_buffer_size(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;

	size_t min_buffer_size = RZ_MIN(core->bin->str_search_cfg.min_length, RZ_BIN_STRING_SEARCH_BUFFER_SIZE);
	if (node->i_value < min_buffer_size) {
		RZ_LOG_ERROR("str.search.buffer_size cannot be less than %" PFMTSZu ".\n", min_buffer_size);
		return false;
	}

	core->bin->str_search_cfg.buffer_size = node->i_value;
	if (core->bin && rz_config_get_b(core->config, "str.search.reload")) {
		RzBinFile *bf = rz_bin_cur(core->bin);
		if (bf && bf->o) {
			rz_bin_object_reset_strings(core->bin, bf, bf->o);
		}
	}
	return true;
}

static bool cb_str_search_max_uni_blocks(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value < 1) {
		RZ_LOG_ERROR("str.search.max_uni_blocks cannot be less than 1.\n");
		return false;
	}
	core->bin->str_search_cfg.max_uni_blocks = node->i_value;
	if (core->bin && rz_config_get_b(core->config, "str.search.reload")) {
		RzBinFile *bf = rz_bin_cur(core->bin);
		if (bf && bf->o) {
			rz_bin_object_reset_strings(core->bin, bf, bf->o);
		}
	}
	return true;
}

static bool cb_str_search_max_region_size(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value < RZ_BIN_STRING_SEARCH_MAX_REGION_SIZE) {
		RZ_LOG_ERROR("str.search.max_region_size cannot be less than " RZ_STR(RZ_BIN_STRING_SEARCH_MAX_REGION_SIZE) ".\n");
		return false;
	}
	core->bin->str_search_cfg.max_region_size = node->i_value;
	if (core->bin && rz_config_get_b(core->config, "str.search.reload")) {
		RzBinFile *bf = rz_bin_cur(core->bin);
		if (bf && bf->o) {
			rz_bin_object_reset_strings(core->bin, bf, bf->o);
		}
	}
	return true;
}

static bool cb_str_search_raw_alignment(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value < 8) {
		RZ_LOG_ERROR("str.search.raw_alignment cannot be less than 8.\n");
		return false;
	}
	core->bin->str_search_cfg.raw_alignment = node->i_value;
	return true;
}

static bool cb_str_search_check_ascii_freq(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->value[0] == '?') {
		rz_cons_printf("true\nfalse\n");
		return false;
	} else if (!rz_str_is_bool(node->value)) {
		RZ_LOG_ERROR("Invalid value for str.search.check_ascii_freq (%s).\n", node->value);
		return false;
	}
	core->bin->str_search_cfg.check_ascii_freq = rz_str_is_true(node->value);
	if (core->bin && rz_config_get_b(core->config, "str.search.reload")) {
		RzBinFile *bf = rz_bin_cur(core->bin);
		if (bf && bf->o) {
			rz_bin_object_reset_strings(core->bin, bf, bf->o);
		}
	}
	return true;
}

static bool find_encoding(RzConfigNode *node, RzStrEnc *encoding) {
	RzListIter *iter;
	const char *option;
	rz_list_foreach (node->options, iter, option) {
		if (rz_str_casecmp(option, node->value)) {
			continue;
		}
		free(node->value);
		node->value = rz_str_dup(option);
		*encoding = rz_str_enc_string_as_type(option);
		return true;
	}
	return false;
}

static bool cb_str_search_encoding(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	RzStrEnc encoding = RZ_STRING_ENC_GUESS;
	if (node->value[0] == '?') {
		print_node_options(node);
		rz_cons_printf("  -- if string's 2nd & 4th bytes are 0 then utf16le else "
			       "if 2nd - 4th & 6th bytes are 0 & no char > 0x10ffff then utf32le else "
			       "if utf8 char detected then utf8 else 8bit\n");
		return false;
	} else if (rz_str_casecmp("guess", node->value) && !find_encoding(node, &encoding)) {
		RZ_LOG_ERROR("Invalid value for str.search.encoding (%s).\n", node->value);
		return false;
	}

	core->bin->str_search_cfg.string_encoding = encoding;
	if (core->bin && rz_config_get_b(core->config, "str.search.reload")) {
		RzBinFile *bf = rz_bin_cur(core->bin);
		if (bf && bf->o) {
			rz_bin_object_reset_strings(core->bin, bf, bf->o);
		}
	}
	return true;
}

static bool cb_str_search_mode(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->value[0] == '?') {
		print_node_options(node);
		return false;
	} else if (!rz_str_casecmp("auto", node->value)) {
		core->bin->str_search_cfg.mode = RZ_BIN_STRING_SEARCH_MODE_AUTO;
		return true;
	} else if (!rz_str_casecmp("rosections", node->value)) {
		core->bin->str_search_cfg.mode = RZ_BIN_STRING_SEARCH_MODE_READ_ONLY_SECTIONS;
		return true;
	} else if (!rz_str_casecmp("raw", node->value)) {
		core->bin->str_search_cfg.mode = RZ_BIN_STRING_SEARCH_MODE_RAW_BINARY;
		return true;
	}
	RZ_LOG_ERROR("Invalid value for str.search.mode (%s).\n", node->value);
	if (core->bin && rz_config_get_b(core->config, "str.search.reload")) {
		RzBinFile *bf = rz_bin_cur(core->bin);
		if (bf && bf->o) {
			rz_bin_object_reset_strings(core->bin, bf, bf->o);
		}
	}
	return false;
}

static bool cb_completion_maxtab(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cons->line->completion.args_limit = node->i_value;
	return true;
}

static bool cb_cfg_fortunes(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	// TODO CN_BOOL option does not receive the right hand side of assignment as an argument
	if (node->value[0] == '?') {
		rz_core_fortune_list(core);
		return false;
	}
	return true;
}

static bool cb_cfg_fortunes_file(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->value[0] == '?') {
		rz_core_fortune_list_types();
		return false;
	}
	return true;
}

static bool cb_cmdtimes(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cmdtimes = node->value;
	return true;
}

static bool cb_cmdrepeat(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cmdrepeat = node->i_value;
	return true;
}

static bool cb_scrnull(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cons->null = node->i_value;
	return true;
}

static bool cb_color(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_COLOR;
	} else {
		core->print->flags &= (~RZ_PRINT_FLAGS_COLOR);
	}
	if (!strcmp(node->value, "true")) {
		node->i_value = 1;
	} else if (!strcmp(node->value, "false")) {
		node->i_value = 0;
	}
	rz_cons_singleton()->context->color_mode = (node->i_value > COLOR_MODE_16M)
		? COLOR_MODE_16M
		: node->i_value;
	rz_cons_pal_update_event();
	rz_print_set_flags(core->print, core->print->flags);
	return true;
}

static bool cb_color_getter(void *user, RzConfigNode *node) {
	(void)user;
	node->i_value = rz_cons_singleton()->context->color_mode;
	char buf[128];
	rz_config_node_value_format_i(buf, sizeof(buf), rz_cons_singleton()->context->color_mode, node);
	if (!node->value || strcmp(node->value, buf) != 0) {
		free(node->value);
		node->value = rz_str_dup(buf);
	}
	return true;
}

static bool cb_decoff(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_ADDRDEC;
	} else {
		core->print->flags &= (~RZ_PRINT_FLAGS_ADDRDEC);
	}
	rz_print_set_flags(core->print, core->print->flags);
	return true;
}

static bool cb_dbgbep(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		print_node_options(node);
		return false;
	}
	return true;
}

static bool cb_dbg_btalgo(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		print_node_options(node);
		return false;
	}
	free(core->dbg->btalgo);
	core->dbg->btalgo = rz_str_dup(node->value);
	return true;
}

static bool cb_dbg_libs(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	free(core->dbg->glob_libs);
	core->dbg->glob_libs = rz_str_dup(node->value);
	return true;
}

static bool cb_dbg_unlibs(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	free(core->dbg->glob_unlibs);
	core->dbg->glob_unlibs = rz_str_dup(node->value);
	return true;
}

static bool cb_dbg_bpinmaps(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->bp->bpinmaps = node->i_value;
	return true;
}

static bool cb_dbg_forks(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->trace_forks = node->i_value;
	if (core->bin->is_debugger) {
		rz_debug_attach(core->dbg, core->dbg->pid);
	}
	return true;
}

static bool cb_dbg_gdb_page_size(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value < 64) { // 64 is hardcoded min packet size
		return false;
	}
	if (isGdbPlugin(core)) {
		char cmd[64];
		snprintf(cmd, sizeof(cmd), "page_size %" PFMT64d, node->i_value);
		free(rz_io_system(core->io, cmd));
	}
	return true;
}

static bool cb_dbg_gdb_retries(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value <= 0) {
		return false;
	}
	if (isGdbPlugin(core)) {
		char cmd[64];
		snprintf(cmd, sizeof(cmd), "retries %" PFMT64d, node->i_value);
		free(rz_io_system(core->io, cmd));
	}
	return true;
}

static bool cb_dbg_execs(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
#if __linux__
	RzCore *core = (RzCore *)user;
	core->dbg->trace_execs = node->i_value;
	if (core->bin->is_debugger) {
		rz_debug_attach(core->dbg, core->dbg->pid);
	}
#else
	if (node->i_value) {
		RZ_LOG_WARN("core: dbg.execs: not supported in this platform.\n");
	}
#endif
	return true;
}

static bool cb_dbg_clone(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->trace_clone = node->i_value;
	if (core->bin->is_debugger) {
		rz_debug_attach(core->dbg, core->dbg->pid);
	}
	return true;
}

static bool cb_dbg_follow_child(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->follow_child = node->i_value;
	return true;
}

static bool cb_dbg_create_new_console(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->create_new_console = node->i_value;
	return true;
}

static bool cb_dbg_trace_continue(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->trace_continue = node->i_value;
	return true;
}

static bool cb_dbg_aftersc(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->trace_aftersyscall = node->i_value;
	if (core->bin->is_debugger) {
		rz_debug_attach(core->dbg, core->dbg->pid);
	}
	return true;
}

static bool cb_runprofile(void *user, void *data) {
	RzCore *r = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	free((void *)r->io->runprofile);
	if (!node || !*(node->value)) {
		r->io->runprofile = NULL;
	} else {
		r->io->runprofile = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_dbg_args(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (!node || !*(node->value)) {
		core->io->args = NULL;
	} else {
		core->io->args = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_dbgbackend(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	RzCmdStateOutput state = { 0 };
	rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_QUIET);
	if (!strcmp(node->value, "?")) {
		rz_core_debug_plugins_print(core, &state);
		rz_cmd_state_output_print(&state);
		rz_cmd_state_output_fini(&state);
		return false;
	}
	if (!strcmp(node->value, "bf")) {
		// hack
		rz_config_set(core->config, "asm.arch", "bf");
	}
	rz_debug_use(core->dbg, node->value);
	return true;
}

static bool cb_gotolimit(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (core->analysis->esil) {
		core->analysis->esil_goto_limit = node->i_value;
	}
	return true;
}

static bool cb_esilverbose(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (core->analysis->esil) {
		core->analysis->esil->verbose = node->i_value;
	}
	return true;
}

static bool cb_esilstackdepth(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value < 3) {
		RZ_LOG_ERROR("core: esil.stack.depth: value must be greater than 2\n");
		node->i_value = 32;
	}
	return true;
}

static bool cb_fixrows(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->fix_rows = (int)node->i_value;
	return true;
}

static bool cb_fixcolumns(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->fix_columns = atoi(node->value);
	return true;
}

static bool cb_rows(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->force_rows = node->i_value;
	return true;
}

static bool cb_cmd_hexcursor(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->print->cfmt = node->value;
	return true;
}

static bool cb_hexcompact(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_COMPACT;
	} else {
		core->print->flags &= (~RZ_PRINT_FLAGS_COMPACT);
	}
	return true;
}

static bool cb_hex_pairs(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->print->pairs = node->i_value;
	return true;
}

static bool cb_hex_section(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_SECTION;
	} else {
		core->print->flags &= ~RZ_PRINT_FLAGS_SECTION;
	}
	return true;
}

static bool cb_hex_align(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_ALIGN;
	} else {
		core->print->flags &= ~RZ_PRINT_FLAGS_ALIGN;
	}
	return true;
}

static bool cb_io_unalloc(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_UNALLOC;
	} else {
		core->print->flags &= ~RZ_PRINT_FLAGS_UNALLOC;
	}
	return true;
}

static bool cb_io_unalloc_ch(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->print->io_unalloc_ch = *node->value ? node->value[0] : ' ';
	return true;
}

static bool cb_hex_header(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_HEADER;
	} else {
		core->print->flags &= ~RZ_PRINT_FLAGS_HEADER;
	}
	return true;
}

static bool cb_hex_bytes(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags &= ~RZ_PRINT_FLAGS_NONHEX;
	} else {
		core->print->flags |= RZ_PRINT_FLAGS_NONHEX;
	}
	return true;
}

static bool cb_hex_ascii(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags &= ~RZ_PRINT_FLAGS_NONASCII;
	} else {
		core->print->flags |= RZ_PRINT_FLAGS_NONASCII;
	}
	return true;
}

static bool cb_hex_style(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_STYLE;
	} else {
		core->print->flags &= ~RZ_PRINT_FLAGS_STYLE;
	}
	return true;
}

static bool cb_hex_hdroff(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_HDROFF;
	} else {
		core->print->flags &= ~RZ_PRINT_FLAGS_HDROFF;
	}
	return true;
}

static bool cb_log_events(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->log_events = node->i_value;
	return true;
}

static bool cb_hexcomments(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_COMMENT;
	} else {
		core->print->flags &= ~RZ_PRINT_FLAGS_COMMENT;
	}
	return true;
}

static bool cb_iopcache(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if ((bool)node->i_value) {
		if (core) {
			rz_config_set_b(core->config, "io.pcache.read", true);
			rz_config_set_b(core->config, "io.pcache.write", true);
		}
	} else {
		if (core && core->io) {
			rz_io_desc_cache_fini_all(core->io);
			rz_config_set_b(core->config, "io.pcache.read", false);
			rz_config_set_b(core->config, "io.pcache.write", false);
		}
	}
	return true;
}

static bool cb_iopcacheread(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if ((bool)node->i_value) {
		if (core && core->io) {
			core->io->p_cache |= 1;
		}
	} else {
		if (core && core->io && core->io->p_cache) {
			core->io->p_cache &= 2;
			if (!(core->io->p_cache & 2)) {
				rz_io_desc_cache_fini_all(core->io);
				rz_config_set_b(core->config, "io.pcache", false);
			}
		}
	}
	return true;
}

static bool cb_iopcachewrite(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if ((bool)node->i_value) {
		if (core && core->io) {
			core->io->p_cache |= 2;
		}
	} else {
		if (core && core->io && core->io->p_cache) {
			core->io->p_cache &= 1;
			if (!(core->io->p_cache & 1)) {
				rz_io_desc_cache_fini_all(core->io);
				rz_config_set_b(core->config, "io.pcache", false);
			}
		}
	}
	return true;
}

RZ_API bool rz_core_esil_cmd(RzAnalysisEsil *esil, const char *cmd, ut64 a1, ut64 a2) {
	if (cmd && *cmd) {
		RzCore *core = esil->analysis->core;
		rz_core_cmdf(core, "%s %" PFMT64d " %" PFMT64d, cmd, a1, a2);
		return core->num->value;
	}
	return false;
}

static void config_print_node(RzConfig *cfg, RzConfigNode *node, RzCmdStateOutput *state) {
	rz_return_if_fail(cfg && node && state);
	char *option;
	bool isFirst;
	RzOutputMode mode = state->mode;
	PJ *pj = state->d.pj;
	RzListIter *iter;
	char *es = NULL;

	switch (mode) {
	case RZ_OUTPUT_MODE_JSON:
		if (rz_str_isnumber(node->value)) {
			pj_kn(pj, node->name, rz_num_math(NULL, node->value));
			return;
		} else if (rz_str_is_bool(node->value)) {
			pj_kb(pj, node->name, (node->value));
			return;
		} else {
			pj_ks(pj, node->name, node->value);
		}
		break;
	case RZ_OUTPUT_MODE_LONG_JSON:
		pj_o(pj);
		pj_ks(pj, "name", node->name);
		if (rz_str_isnumber(node->value)) {
			pj_kn(pj, "value", rz_num_math(NULL, node->value));
		} else if (rz_str_is_bool(node->value)) {
			pj_kb(pj, "value", (node->value));
		} else {
			pj_ks(pj, "value", node->value);
		}
		pj_ks(pj, "type", rz_config_node_type(node));
		es = rz_str_escape(node->desc);
		if (es) {
			pj_ks(pj, "desc", es);
			free(es);
		}
		pj_kb(pj, "ro", rz_config_node_is_ro(node));
		if (!rz_list_empty(node->options)) {
			pj_ka(pj, "options");
			rz_list_foreach (node->options, iter, option) {
				pj_s(pj, option);
			}
			pj_end(pj);
		}
		pj_end(pj);
		break;
	case RZ_OUTPUT_MODE_LONG:
		rz_cons_printf("%s = %s %s; %s",
			node->name, node->value,
			rz_config_node_is_ro(node) ? "(ro)" : "",
			node->desc);
		if (!rz_list_empty(node->options)) {
			isFirst = true;
			rz_cons_printf(" [");
			rz_list_foreach (node->options, iter, option) {
				if (isFirst) {
					isFirst = false;
				} else {
					rz_cons_printf(", ");
				}
				rz_cons_printf("%s", option);
			}
			rz_cons_printf("]");
		}
		rz_cons_println("");
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%s=%s\n", node->name, node->value);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		es = rz_cmd_escape_arg(node->value, RZ_CMD_ESCAPE_ONE_ARG);
		rz_cons_printf("e %s=%s\n", node->name, es);
		free(es);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%20s: %s\n", node->name,
			node->desc ? node->desc : "");
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

/**
 * \brief Prints the configuation variables with their description and its values
 *
 * \param cfg reference to RzConfig
 * \param str reference to the key that can be passed to filter the output
 * \param state reference to RzCmdStateOutput
 */
RZ_API void rz_core_config_print_all(RzConfig *cfg, const char *str, RzCmdStateOutput *state) {
	rz_return_if_fail(cfg);
	RzConfigNode *node;
	RzListIter *iter;
	PJ *pj = state->d.pj;
	RzOutputMode mode = state->mode;

	if (mode == RZ_OUTPUT_MODE_LONG_JSON) {
		pj_a(pj);
	} else if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(pj);
	}

	rz_list_foreach (cfg->nodes, iter, node) {
		if (rz_str_startswith(node->name, str)) {
			config_print_node(cfg, node, state);
		}
	}

	if (mode == RZ_OUTPUT_MODE_LONG_JSON || mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
	}
}

static bool cb_cmd_esil_ioer(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (core && core->analysis && core->analysis->esil) {
		core->analysis->esil->cmd = rz_core_esil_cmd;
		free(core->analysis->esil->cmd_ioer);
		core->analysis->esil->cmd_ioer = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_cmd_esil_todo(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (core && core->analysis && core->analysis->esil) {
		core->analysis->esil->cmd = rz_core_esil_cmd;
		free(core->analysis->esil->cmd_todo);
		core->analysis->esil->cmd_todo = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_cmd_esil_intr(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (core && core->analysis && core->analysis->esil) {
		core->analysis->esil->cmd = rz_core_esil_cmd;
		free(core->analysis->esil->cmd_intr);
		core->analysis->esil->cmd_intr = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_mdevrange(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (core && core->analysis && core->analysis->esil) {
		core->analysis->esil->cmd = rz_core_esil_cmd;
		free(core->analysis->esil->mdev_range);
		core->analysis->esil->mdev_range = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_cmd_esil_step(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (core && core->analysis && core->analysis->esil) {
		core->analysis->esil->cmd = rz_core_esil_cmd;
		free(core->analysis->esil->cmd_step);
		core->analysis->esil->cmd_step = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_cmd_esil_step_out(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (core && core->analysis && core->analysis->esil) {
		core->analysis->esil->cmd = rz_core_esil_cmd;
		free(core->analysis->esil->cmd_step_out);
		core->analysis->esil->cmd_step_out = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_cmd_esil_mdev(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (core && core->analysis && core->analysis->esil) {
		core->analysis->esil->cmd = rz_core_esil_cmd;
		free(core->analysis->esil->cmd_mdev);
		core->analysis->esil->cmd_mdev = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_cmd_esil_trap(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (core && core->analysis && core->analysis->esil) {
		core->analysis->esil->cmd = rz_core_esil_cmd;
		core->analysis->esil->cmd_trap = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_cmddepth(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	int c = RZ_MAX(((RzConfigNode *)data)->i_value, 0);
	core->max_cmd_depth = c;
	core->cons->context->cmd_depth = c;
	return true;
}

static bool cb_hexcols(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	int c = RZ_MIN(1024, RZ_MAX(((RzConfigNode *)data)->i_value, 0));
	core->print->cols = c; // & ~1;
	core->dbg->regcols = c / 4;
	return true;
}

static bool cb_hexstride(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	((RzCore *)user)->print->stride = node->i_value;
	return true;
}

static bool cb_search_kwidx(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->search->n_kws = node->i_value;
	return true;
}

static bool cb_io_cache_mode(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->io->cachemode = true;
	} else {
		core->io->cachemode = false;
	}
	return true;
}

static bool cb_io_cache_read(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->io->cached |= RZ_PERM_R;
	} else {
		core->io->cached &= ~RZ_PERM_R;
	}
	return true;
}

static bool cb_io_cache_write(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->io->cached |= RZ_PERM_W;
	} else {
		core->io->cached &= ~RZ_PERM_W;
	}
	return true;
}

static bool cb_io_cache(void *user, void *data) {
	(void)cb_io_cache_read(user, data);
	(void)cb_io_cache_write(user, data);
	return true;
}

static bool cb_ioaslr(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value != core->io->aslr) {
		core->io->aslr = node->i_value;
	}
	return true;
}

static bool cb_io_pava(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->print->pava = node->i_value;
	if (node->i_value && core->io->va) {
		RZ_LOG_WARN("core: you may probably want to disable io.va too\n");
	}
	return true;
}

static bool cb_iova(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value != core->io->va) {
		core->io->va = node->i_value;
		/* ugly fix for rizin -d ... "rizin is going to die soon ..." */
		if (core->io->desc) {
			rz_core_block_read(core);
		}
#if 0
		/* reload symbol information */
		if (rz_list_length (rz_bin_get_sections (core->bin)) > 0) {
			rz_core_cmd0 (core, ".ia*");
		}
#endif
	}
	return true;
}

static bool cb_ioff(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->io->ff = node->i_value;
	return true;
}

static bool cb_io_oxff(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->io->Oxff = node->i_value;
	return true;
}

static bool cb_filepath(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	char *pikaboo = strstr(node->value, "://");
	if (pikaboo) {
		if (pikaboo[3] == '/') {
			rz_config_set(core->config, "file.lastpath", node->value);
			char *ovalue = node->value;
			node->value = rz_str_dup(pikaboo + 3);
			free(ovalue);
			return true;
		}
		return false;
	}
	rz_config_set(core->config, "file.lastpath", node->value);
	return true;
}

static bool cb_ioautofd(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->io->autofd = node->i_value;
	return true;
}

static bool cb_scr_color_grep(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;

	/* Let cons know we have a new pager. */
	core->cons->grep_color = node->i_value;
	return true;
}

static bool cb_scr_color_grep_highlight(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cons->grep_highlight = node->i_value;
	return true;
}

static bool cb_pager(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (!strcmp(node->value, "?")) {
		RZ_LOG_ERROR("usage: scr.pager must be '..' for internal less, or the path to a program in $PATH\n");
		return false;
	}
	/* Let cons know we have a new pager. */
	free(core->cons->pager);
	core->cons->pager = rz_str_dup(node->value);
	return true;
}

static bool cb_breaklines(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->break_lines = node->i_value;
	return true;
}

static bool cb_scr_gadgets(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->scr_gadgets = node->i_value;
	return true;
}

static bool cb_scrbreakword(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value) {
		rz_cons_breakword(node->value);
	} else {
		rz_cons_breakword(NULL);
	}
	return true;
}

static bool cb_scrcolumns(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	RzCore *core = (RzCore *)user;
	int n = atoi(node->value);
	core->cons->force_columns = n;
	core->dbg->regcols = n / 20;
	rz_cons_get_size(NULL);
	return true;
}

static bool cb_scrfgets(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cons->user_fgets = node->i_value
		? NULL
		: (void *)rz_core_fgets;
	core->cons->user_fgets_user = core;
	return true;
}

static bool cb_scrhtml(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->is_html = node->i_value;
	// TODO: control error and restore old value (return false?) show errormsg?
	return true;
}

static bool cb_scrhighlight(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_highlight(node->value);
	return true;
}

#if __WINDOWS__
static bool scr_vtmode(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (rz_str_is_true(node->value)) {
		node->i_value = RZ_VIRT_TERM_MODE_OUTPUT_ONLY;
	}
	node->i_value = node->i_value > RZ_VIRT_TERM_MODE_COMPLETE ? RZ_VIRT_TERM_MODE_COMPLETE : node->i_value;
	RzCons *cons = rz_cons_singleton();
	cons->line->vtmode = cons->vtmode = node->i_value;

	DWORD mode;
	HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(input, &mode);
	if (node->i_value == RZ_VIRT_TERM_MODE_COMPLETE) {
		SetConsoleMode(input, mode & ENABLE_VIRTUAL_TERMINAL_INPUT);
		cons->term_raw |= ENABLE_VIRTUAL_TERMINAL_INPUT;
	} else {
		SetConsoleMode(input, mode & ~ENABLE_VIRTUAL_TERMINAL_INPUT);
		cons->term_raw &= ~ENABLE_VIRTUAL_TERMINAL_INPUT;
	}
	HANDLE streams[] = { GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE) };
	int i;
	if (node->i_value > RZ_VIRT_TERM_MODE_DISABLE) {
		for (i = 0; i < RZ_ARRAY_SIZE(streams); i++) {
			GetConsoleMode(streams[i], &mode);
			SetConsoleMode(streams[i],
				mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
		}
	} else {
		for (i = 0; i < RZ_ARRAY_SIZE(streams); i++) {
			GetConsoleMode(streams[i], &mode);
			SetConsoleMode(streams[i],
				mode & ~ENABLE_VIRTUAL_TERMINAL_PROCESSING & ~ENABLE_WRAP_AT_EOL_OUTPUT);
		}
	}
	return true;
}
#endif

static bool cb_screcho(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->echo = node->i_value;
	return true;
}

static bool cb_scrlinesleep(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->linesleep = node->i_value;
	return true;
}

static bool cb_scrpagesize(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->pagesize = node->i_value;
	return true;
}

static bool cb_scrflush(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->flush = node->i_value;
	return true;
}

static bool cb_scrstrconv(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->value[0] == '?') {
		if (strlen(node->value) > 1 && node->value[1] == '?') {
			rz_cons_printf("Valid values for scr.strconv:\n"
				       "  asciiesc  convert to ascii with non-ascii chars escaped\n"
				       "  asciidot  convert to ascii with non-ascii chars turned into a dot (except control chars stated below)\n"
				       "\n"
				       "Ascii chars are in the range 0x20-0x7e. Always escaped control chars are alert (\\a),\n"
				       "backspace (\\b), formfeed (\\f), newline (\\n), carriage return (\\r), horizontal tab (\\t)\n"
				       "and vertical tab (\\v). Also, double quotes (\\\") are always escaped, but backslashes (\\\\)\n"
				       "are only escaped if str.escbslash = true.\n");
		} else {
			print_node_options(node);
		}
		return false;
	} else {
		free((char *)core->print->strconv_mode);
		core->print->strconv_mode = rz_str_dup(node->value);
	}
	return true;
}

static bool cb_graphformat(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (!strcmp(node->value, "?")) {
		rz_cons_printf("png\njpg\npdf\nps\nsvg\njson\n");
		return false;
	}
	return true;
}

static bool cb_exectrap(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	RzCore *core = (RzCore *)user;
	if (core->analysis && core->analysis->esil) {
		core->analysis->esil->exectrap = node->i_value;
	}
	return true;
}

static bool cb_iotrap(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	RzCore *core = (RzCore *)user;
	if (core->analysis && core->analysis->esil) {
		core->analysis->esil->iotrap = node->i_value;
	}
	return true;
}

static bool cb_scr_bgfill(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_BGFILL;
	} else {
		core->print->flags &= (~RZ_PRINT_FLAGS_BGFILL);
	}
	rz_print_set_flags(core->print, core->print->flags);
	return true;
}

static bool cb_scrint(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->context->is_interactive = node->i_value;
	return true;
}

static bool cb_scrnkey(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (!strcmp(node->value, "help") || *node->value == '?') {
		print_node_options(node);
		return false;
	}
	return true;
}

static bool cb_scr_histblock(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->print->histblock = node->i_value;
	return true;
}

static bool cb_scrprompt(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->print->scr_prompt = node->i_value;
	core->cons->line->echo = node->i_value;
	return true;
}

static bool cb_scrrows(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	int n = atoi(node->value);
	core->cons->force_rows = n;
	return true;
}

static bool cb_contiguous(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->search->contiguous = node->i_value;
	return true;
}

static bool cb_searchalign(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->search->align = node->i_value;
	core->print->addrmod = node->i_value;
	return true;
}

static bool cb_segoff(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= RZ_PRINT_FLAGS_SEGOFF;
	} else {
		core->print->flags &= (((ut32)-1) & (~RZ_PRINT_FLAGS_SEGOFF));
	}
	return true;
}

static bool cb_seggrn(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->rasm->seggrn = node->i_value;
	core->analysis->seggrn = node->i_value;
	core->print->seggrn = node->i_value;
	return true;
}

static bool cb_stopthreads(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->stop_all_threads = node->i_value;
	return true;
}

static bool cb_scr_prompt_popup(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cons->show_autocomplete_widget = node->i_value;
	return true;
}

static bool cb_swstep(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->swstep = node->i_value;
	return true;
}

static bool cb_consbreak(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->consbreak = node->i_value;
	return true;
}

static bool cb_teefile(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	rz_cons_singleton()->teefile = node->value;
	return true;
}

static bool cb_trace(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->trace->enabled = node->i_value;
	return true;
}

static bool cb_tracetag(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->trace->tag = node->i_value;
	return true;
}

static bool cb_utf8(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->rasm->utf8 = (bool)node->i_value;
	rz_cons_set_utf8((bool)node->i_value);
	return true;
}

static bool cb_utf8_curvy(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cons->use_utf8_curvy = node->i_value;
	return true;
}

static bool cb_visual_mode(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value > RZ_CORE_VISUAL_MODE_CD) {
		node->i_value = RZ_CORE_VISUAL_MODE_PX;
	}
	RzCore *core = (RzCore *)user;
	((RzCoreVisual *)core->visual)->printidx = node->i_value;
	return true;
}

static bool cb_dotted(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->cons->dotted_lines = node->i_value;
	return true;
}

static bool cb_zoombyte(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	switch (*node->value) {
	case 'p':
	case 'f':
	case 's':
	case '0':
	case 'F':
	case 'e':
	case 'h':
		core->print->zoom->mode = *node->value;
		break;
	default:
		RZ_LOG_ERROR("core: invalid zoom.byte value. See pz? for help\n");
		rz_cons_printf("pzp\npzf\npzs\npz0\npzF\npze\npzh\n");
		return false;
	}
	return true;
}

static bool cb_binverbose(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->bin->verbose = node->i_value;
	return true;
}

static bool cb_binhashesdefault(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		print_node_options(node);
		rz_cons_printf("Multiple algorithms can be specified in a comma-separated list (no spaces).\n");
		return false;
	}
	rz_list_free(core->bin->default_hashes);
	core->bin->default_hashes = rz_str_split_duplist(node->value, ",", true);
	if (!core->bin->default_hashes) {
		core->bin->default_hashes = rz_list_new();
	}
	return true;
}

static bool cb_debase64(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->bin->debase64 = node->i_value;
	return true;
}

static bool cb_binstrings(void *user, void *data) {
	const ut32 req = RZ_BIN_REQ_STRINGS;
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->i_value) {
		core->bin->filter_rules |= req;
	} else {
		core->bin->filter_rules &= ~req;
	}
	return true;
}

static bool cb_bindbginfo(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (!core || !core->bin) {
		return false;
	}
	core->bin->want_dbginfo = node->i_value;
	return true;
}

static bool cb_binprefix(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (!core || !core->bin) {
		return false;
	}
	if (node->value && *node->value) {
		if (!strcmp(node->value, "auto")) {
			if (!core->bin->file) {
				return false;
			}
			char *name = (char *)rz_file_basename(core->bin->file);
			if (name) {
				rz_name_filter(name, strlen(name), true);
				rz_str_filter(name);
				core->bin->prefix = rz_str_dup(name);
				free(name);
			}
		} else {
			core->bin->prefix = node->value;
		}
	}
	return true;
}

static bool cb_searchin(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	if (node->value[0] == '?') {
		if (strlen(node->value) > 1 && node->value[1] == '?') {
			rz_cons_printf("Valid values for search.in (depends on .from/.to and io.va):\n"
				       "raw                search in raw io (ignoring bounds)\n"
				       "block              search in the current block\n"
				       "io.map             search in current map\n"
				       "io.sky.[rwx]       search in all skyline segments\n"
				       "io.maps            search in all maps\n"
				       "io.maps.[rwx]      search in all r-w-x io maps\n"
				       "bin.segment        search in current mapped segment\n"
				       "bin.segments       search in all mapped segments\n"
				       "bin.segments.[rwx] search in all r-w-x segments\n"
				       "bin.section        search in current mapped section\n"
				       "bin.sections       search in all mapped sections\n"
				       "bin.sections.[rwx] search in all r-w-x sections\n"
				       "dbg.stack          search in the stack\n"
				       "dbg.heap           search in the heap\n"
				       "dbg.map            search in current memory map\n"
				       "dbg.maps           search in all memory maps\n"
				       "dbg.maps.[rwx]     search in all executable marked memory maps\n"
				       "analysis.fcn           search in the current function\n"
				       "analysis.bb            search in the current basic-block\n");
		} else {
			print_node_options(node);
		}
		return false;
	}
	// Set analysis.noncode if exec bit set in analysis.in
	if (rz_str_startswith(node->name, "analysis")) {
		core->analysis->opt.noncode = (strchr(node->value, 'x') == NULL);
	}
	return true;
}

static int __dbg_swstep_getter(void *user, RzConfigNode *node) {
	RzCore *core = (RzCore *)user;
	node->i_value = core->dbg->swstep;
	return true;
}

static bool cb_analysis_roregs(RzCore *core, RzConfigNode *node) {
	if (core && core->analysis && core->analysis->reg) {
		rz_list_free(core->analysis->reg->roregs);
		core->analysis->reg->roregs = rz_str_split_duplist(node->value, ",", true);
	}
	return true;
}

static bool cb_analysissyscc(RzCore *core, RzConfigNode *node) {
	if (core && core->analysis) {
		if (!strcmp(node->value, "?")) {
			rz_core_types_calling_conventions_print(core, RZ_OUTPUT_MODE_STANDARD);
			return false;
		}
		rz_analysis_set_syscc_default(core->analysis, node->value);
	}
	return true;
}

static bool cb_analysiscc(RzCore *core, RzConfigNode *node) {
	if (core && core->analysis) {
		if (!strcmp(node->value, "?")) {
			rz_core_types_calling_conventions_print(core, RZ_OUTPUT_MODE_STANDARD);
			return false;
		}
		rz_analysis_set_cc_default(core->analysis, node->value);
	}
	return true;
}

static bool cb_analysis_gp(RzCore *core, RzConfigNode *node) {
	core->analysis->gp = node->i_value;
	return true;
}

static bool cb_analysis_from(RzCore *core, RzConfigNode *node) {
	if (rz_config_get_i(core->config, "analysis.limits")) {
		rz_analysis_set_limits(core->analysis,
			rz_config_get_i(core->config, "analysis.from"),
			rz_config_get_i(core->config, "analysis.to"));
	}
	return true;
}

static bool cb_analysis_limits(void *user, RzConfigNode *node) {
	RzCore *core = (RzCore *)user;
	if (node->i_value) {
		rz_analysis_set_limits(core->analysis,
			rz_config_get_i(core->config, "analysis.from"),
			rz_config_get_i(core->config, "analysis.to"));
	} else {
		rz_analysis_unset_limits(core->analysis);
	}
	return 1;
}

static bool cb_analysis_rnr(void *user, RzConfigNode *node) {
	RzCore *core = (RzCore *)user;
	core->analysis->recursive_noreturn = node->i_value;
	return 1;
}

static bool cb_analysis_jmptbl(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.jmptbl = node->i_value;
	return true;
}

static bool cb_analysis_jmptblmax(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.jmptbl_maxcount = node->i_value;
	return true;
}

static bool cb_analysis_jmptblmaxoffset(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.jmptbl_maxoffset = node->i_value > UT32_MAX ? UT32_MAX : node->i_value;
	return true;
}

static bool cb_analysis_cjmpref(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.cjmpref = node->i_value;
	return true;
}

static bool cb_analysis_jmpref(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.jmpref = node->i_value;
	return true;
}

static bool cb_analysis_jmpabove(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.jmpabove = node->i_value;
	return true;
}

static bool cb_analysis_loads(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.loads = node->i_value;
	return true;
}

static bool cb_analysis_followdatarefs(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.followdatarefs = node->i_value;
	return true;
}

static bool cb_analysis_jmpmid(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.jmpmid = node->i_value;
	return true;
}

static bool cb_analysis_searchstringrefs(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.searchstringrefs = node->i_value;
	return true;
}

static bool cb_analysis_pushret(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.pushret = node->i_value;
	return true;
}

static bool cb_analysis_brokenrefs(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.followbrokenfcnsrefs = node->i_value;
	return true;
}

static bool cb_analysis_trycatch(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.trycatch = node->i_value;
	return true;
}

static bool cb_analysis_bb_max_size(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->analysis->opt.bb_max_size = node->i_value;
	return true;
}

static bool cb_analysis_cpp_abi(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;

	if (*node->value == '?') {
		print_node_options(node);
		return false;
	}

	if (*node->value) {
		if (strcmp(node->value, "itanium") == 0) {
			core->analysis->cpp_abi = RZ_ANALYSIS_CPP_ABI_ITANIUM;
			return true;
		} else if (strcmp(node->value, "msvc") == 0) {
			core->analysis->cpp_abi = RZ_ANALYSIS_CPP_ABI_MSVC;
			return true;
		}
		RZ_LOG_ERROR("core: analysis.cpp.abi: cannot find '%s'\n", node->value);
	}
	return false;
}

static bool cb_malloc(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;

	if (node->value) {
		if (!strcmp("jemalloc", node->value) || !strcmp("glibc", node->value)) {
			if (core->dbg) {
				core->dbg->malloc = data;
			}
		}
	}
	return true;
}

static bool cb_log_config_level(void *coreptr, void *nodeptr) {
	RzConfigNode *node = (RzConfigNode *)nodeptr;
	rz_log_set_level(node->i_value);
	return true;
}

#if RZ_BUILD_DEBUG
static bool cb_log_config_abortlevel(void *coreptr, void *nodeptr) {
	RzConfigNode *node = (RzConfigNode *)nodeptr;
	rz_log_set_abortlevel(node->i_value);
	return true;
}
#endif /* RZ_BUILD_DEBUG */

static bool cb_log_file(void *coreptr, void *nodeptr) {
	RzConfigNode *node = (RzConfigNode *)nodeptr;
	if (!rz_log_set_file(node->value)) {
		RZ_LOG_ERROR("log.file: cannot open '%s'\n", node->value);
		return false;
	}
	return true;
}

static bool cb_log_config_show_sources(void *coreptr, void *nodeptr) {
	RzConfigNode *node = (RzConfigNode *)nodeptr;
	const char *value = node->value;
	if (rz_str_is_true(value)) {
		rz_log_set_show_sources(true);
	} else if (rz_str_is_false(value)) {
		rz_log_set_show_sources(false);
	} else {
		return false;
	}
	return true;
}

static bool cb_log_config_colors(void *coreptr, void *nodeptr) {
	RzConfigNode *node = (RzConfigNode *)nodeptr;
	const char *value = node->value;
	if (rz_str_is_true(value)) {
		rz_log_set_colors(true);
	} else if (rz_str_is_false(value)) {
		rz_log_set_colors(false);
	} else {
		return false;
	}
	return true;
}

static bool cb_dbg_verbose(void *user, void *data) {
	RzCore *core = (RzCore *)user;
	RzConfigNode *node = (RzConfigNode *)data;
	core->dbg->verbose = node->i_value;
	return true;
}

static bool cb_flirt(void *user, void *data) {
	rz_return_val_if_fail(data, false);
	RzConfigNode *node = (RzConfigNode *)data;
	if (*node->value == '?') {
		print_node_options(node);
		return false;
	}
	return true;
}

RZ_API int rz_core_config_init(RzCore *core) {
	int i;
	char buf[128], *p, *tmpdir;
	RzConfigNode *n;
	RzConfig *cfg = core->config = rz_config_new(core);
	if (!cfg) {
		return 0;
	}
	cfg->num = core->num;
	/* dir.prefix is used in other modules, set it first */
	{
		char *pfx = rz_sys_getenv("RZ_PREFIX");
		if (!pfx) {
			pfx = rz_path_prefix(NULL);
		}
		SETCB("dir.prefix", pfx, NULL, "Default prefix rizin was compiled for");
		free(pfx);
	}
#if __ANDROID__
	{ // use dir.home and also adjust check for permissions in directory before choosing a home
		char *h = rz_sys_getenv(RZ_SYS_HOME);
		if (h) {
			if (!strcmp(h, "/")) {
				rz_sys_setenv(RZ_SYS_HOME, "/data/local/tmp");
			}
			free(h);
		}
	}
#endif
	SETCB("cmd.times", "", &cb_cmdtimes, "Run when a command is repeated (number prefix)");
	/* pdb */
	SETPREF("pdb.server", "https://msdl.microsoft.com/download/symbols", "Semi-colon separated list of base URLs for Microsoft symbol servers");
	{
		char *pdb_path = rz_path_home_prefix(RZ_PDB);
		SETPREF("pdb.symstore", pdb_path, "Path to downstream symbol store");
		RZ_FREE(pdb_path);
	}
	SETI("pdb.extract", 1, "Avoid extract of the pdb file, just download");
	SETI("pdb.autoload", false, "Automatically load the required pdb files for loaded DLLs");

	/* elf */
	SETBPREF("elf.checks.sections", "true", "Check elf sections during loading");
	SETBPREF("elf.checks.segments", "true", "Check elf segments during loading");
	SETBPREF("elf.load.sections", "true", "Automatically load elf sections");

	/* analysis */
	SETBPREF("analysis.detectwrites", "false", "Automatically reanalyze function after a write");
	SETPREF("analysis.fcnprefix", "fcn", "Prefix new function names with this");
	const char *analysiscc = rz_analysis_cc_default(core->analysis);
	SETCB("analysis.cc", analysiscc ? analysiscc : "", (RzConfigCallback)&cb_analysiscc, "Specify default calling convention");
	const char *analysissyscc = rz_analysis_syscc_default(core->analysis);
	SETCB("analysis.syscc", analysissyscc ? analysissyscc : "", (RzConfigCallback)&cb_analysissyscc, "Specify default syscall calling convention");
	SETCB("analysis.roregs", "gp,zero", (RzConfigCallback)&cb_analysis_roregs, "Comma separated list of register names to be readonly");
	SETICB("analysis.gp", 0, (RzConfigCallback)&cb_analysis_gp, "Set the value of the GP register (MIPS)");
	SETBPREF("analysis.gpfixed", "true", "Set gp register to analysis.gp before emulating each instruction in aae");
	SETCB("analysis.limits", "false", (RzConfigCallback)&cb_analysis_limits, "Restrict analysis to address range [analysis.from:analysis.to]");
	SETCB("analysis.rnr", "false", (RzConfigCallback)&cb_analysis_rnr, "Recursive no return checks (EXPERIMENTAL)");
	SETCB("analysis.limits", "false", (RzConfigCallback)&cb_analysis_limits, "Restrict analysis to address range [analysis.from:analysis.to]");
	SETICB("analysis.from", -1, (RzConfigCallback)&cb_analysis_from, "Lower limit on the address range for analysis");
	SETICB("analysis.to", -1, (RzConfigCallback)&cb_analysis_from, "Upper limit on the address range for analysis");
	n = NODECB("analysis.in", "io.maps.x", &cb_searchin);
	SETDESC(n, "Specify search boundaries for analysis");
	SETOPTIONS(n, "range", "block",
		"bin.segment", "bin.segments", "bin.segments.x", "bin.segments.r", "bin.section", "bin.sections", "bin.sections.rwx", "bin.sections.r", "bin.sections.rw", "bin.sections.rx", "bin.sections.wx", "bin.sections.x",
		"io.map", "io.maps", "io.maps.rwx", "io.maps.r", "io.maps.rw", "io.maps.rx", "io.maps.wx", "io.maps.x",
		"dbg.stack", "dbg.heap",
		"dbg.map", "dbg.maps", "dbg.maps.rwx", "dbg.maps.r", "dbg.maps.rw", "dbg.maps.rx", "dbg.maps.wx", "dbg.maps.x",
		"analysis.fcn", "analysis.bb",
		NULL);
	SETI("analysis.timeout", 0, "Stop analyzing after a couple of seconds");
	SETCB("analysis.jmp.retpoline", "true", &cb_analysis_jmpretpoline, "Analyze retpolines, may be slower if not needed");

	SETCB("analysis.armthumb", "false", &cb_analysis_armthumb, "aae computes arm/thumb changes (lot of false positives ahead)");
	SETCB("analysis.jmp.after", "true", &cb_analysis_afterjmp, "Continue analysis after jmp/ujmp");
	SETCB("analysis.trap.after", "false", &cb_analysis_aftertrap, "Continue analysis after trap instructions.");
	SETCB("analysis.delay", "true", &cb_analysis_delay, "Enable delay slot analysis if supported by the architecture");
	SETICB("analysis.depth", 64, &cb_analysis_depth, "Max depth at code analysis"); // XXX: warn if depth is > 50 .. can be problematic
	SETICB("analysis.graph_depth", 256, &cb_analysis_graphdepth, "Max depth for path search");
	SETICB("analysis.sleep", 0, &cb_analysis_sleep, "Sleep N usecs every so often during analysis. Avoid 100% CPU usage");
	SETCB("analysis.ignbithints", "false", &cb_analysis_ignbithints, "Ignore the ahb hints (only obey asm.bits)");
	SETBPREF("analysis.calls", "false", "Make basic af analysis walk into calls");
	SETBPREF("analysis.autoname", "false", "Speculatively set a name for the functions, may result in some false positives");
	SETBPREF("analysis.hasnext", "false", "Continue analysis after each function");
	SETICB("analysis.nonull", 0, &cb_analysis_nonull, "Do not analyze regions of N null bytes");
	SETBPREF("analysis.esil", "false", "Use the new ESIL code analysis");
	SETCB("analysis.strings", "false", &cb_analysis_strings, "Identify and register strings during analysis (aar only)");
	SETPREF("analysis.types.spec", "gcc", "Set profile for specifying format chars used in type analysis");
	SETBPREF("analysis.types.verbose", "false", "Verbose output from type analysis");
	SETBPREF("analysis.types.constraint", "false", "Enable constraint types analysis for variables");
	SETCB("analysis.vars", "true", &cb_analysis_vars, "Analyze local variables and arguments");
	SETBPREF("analysis.vinfun", "true", "Search values in functions (aav) (false by default to only find on non-code)");
	SETBPREF("analysis.vinfunrange", "false", "Search values outside function ranges (requires analysis.vinfun=false)\n");
	SETCB("analysis.norevisit", "false", &cb_analysis_norevisit, "Do not visit function analysis twice (EXPERIMENTAL)");
	SETCB("analysis.nopskip", "true", &cb_analysis_nopskip, "Skip nops at the beginning of functions");
	SETCB("analysis.hpskip", "false", &cb_analysis_hpskip, "Skip `mov reg, reg` and `lea reg, [reg] at the beginning of functions");
	n = NODECB("analysis.arch", RZ_SYS_ARCH, &cb_analysis_arch);
	SETDESC(n, "Select the architecture to use");
	update_analysis_arch_options(core, n);
	SETCB("analysis.cpu", RZ_SYS_ARCH, &cb_analysis_cpu, "Specify the analysis.cpu to use");
	SETPREF("analysis.prelude", "", "Specify an hexpair to find preludes in code");
	SETI("analysis.prelude.limit", 1024 * 1024 * 20, "Maximum size of the range to scan for preludes");
	SETCB("analysis.recont", "false", &cb_analysis_recont, "End block after splitting a basic block instead of error"); // testing
	SETCB("analysis.jmp.indir", "false", &cb_analysis_ijmp, "Follow the indirect jumps in function analysis"); // testing
	SETI("analysis.ptrdepth", 3, "Maximum number of nested pointers to follow in analysis");
	SETICB("asm.lines.maxref", 0, &cb_analysis_maxrefs, "Maximum number of reflines to be analyzed and displayed in asm.lines with pd");

	SETCB("analysis.jmp.tbl", "true", &cb_analysis_jmptbl, "Analyze jump tables in switch statements");
	SETICB("analysis.jmp.tblmax", 512, &cb_analysis_jmptblmax, "Maximum amount of entries to analyze in jump tables");
	SETICB("analysis.jmp.tblmaxoffset", 4096, &cb_analysis_jmptblmaxoffset, "Maximum offset from the jump table jump instruction to consider it valid");

	SETCB("analysis.jmp.cref", "false", &cb_analysis_cjmpref, "Create references for conditional jumps");
	SETCB("analysis.jmp.ref", "true", &cb_analysis_jmpref, "Create references for unconditional jumps");

	SETCB("analysis.jmp.above", "true", &cb_analysis_jmpabove, "Jump above function pointer");
	SETCB("analysis.loads", "false", &cb_analysis_loads, "Define as dword/string/qword when analyzing load instructions");
	SETCB("analysis.datarefs", "false", &cb_analysis_followdatarefs, "Follow data references for code coverage");
	SETCB("analysis.brokenrefs", "false", &cb_analysis_brokenrefs, "Follow function references as well if function analysis was failed");
	SETCB("analysis.jmp.mid", "true", &cb_analysis_jmpmid, "Continue analysis after jump to middle of instruction (x86 only)");

	SETCB("analysis.refstr", "false", &cb_analysis_searchstringrefs, "Search string references in data references");
	SETCB("analysis.trycatch", "false", &cb_analysis_trycatch, "Honor try.X.Y.{from,to,catch} flags");
	SETCB("analysis.bb.maxsize", "512K", &cb_analysis_bb_max_size, "Maximum basic block size");
	SETCB("analysis.pushret", "false", &cb_analysis_pushret, "Analyze push+ret as jmp");

	n = NODECB("analysis.cpp.abi", "itanium", &cb_analysis_cpp_abi);
	SETDESC(n, "Select C++ ABI (Compiler)");
	SETOPTIONS(n, "itanium", "msvc", NULL);
	SETB("analysis.apply.signature", true, "enables/disables auto-applying signatures to the loaded binary (see also flirt.sigdb.path)");
	SETB("analysis.resolve.pointers", true, "enables/disables analysis of pointers to data sections.");

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
	SETCB("dbg.malloc", "glibc", &cb_malloc, "Choose malloc structure parser");
#else
	SETCB("dbg.malloc", "jemalloc", &cb_malloc, "Choose malloc structure parser");
#endif
#if __GLIBC_MINOR__ > 25
	SETBPREF("dbg.glibc.tcache", "true", "Set glib tcache parsing");
#else
	SETBPREF("dbg.glibc.tcache", "false", "Set glib tcache parsing");
#endif
#if __x86_64__
	SETI("dbg.glibc.ma_offset", 0x000000, "Main_arena offset from his symbol");
	SETI("dbg.glibc.fc_offset", 0x00280, "First chunk offset from brk_start");
#else
	SETI("dbg.glibc.ma_offset", 0x1bb000, "Main_arena offset from his symbol");
	SETI("dbg.glibc.fc_offset", 0x148, "First chunk offset from brk_start");
#endif
	SETI("dbg.glibc.fastbinmax", 10, "Upper bound on the number of fastbins printed");

	SETBPREF("esil.prestep", "true", "Step before esil evaluation in `de` commands");
	SETPREF("esil.fillstack", "", "Initialize ESIL stack with (random, debrujn, sequence, zeros, ...)");
	SETICB("esil.verbose", 0, &cb_esilverbose, "Show ESIL verbose level (0, 1, 2)");
	SETICB("esil.gotolimit", core->analysis->esil_goto_limit, &cb_gotolimit, "Maximum number of gotos per ESIL expression");
	SETICB("esil.stack.depth", 256, &cb_esilstackdepth, "Number of elements that can be pushed on the esilstack");
	SETI("esil.stack.size", 0xf0000, "Set stack size in ESIL VM");
	SETI("esil.stack.addr", 0x100000, "Set stack address in ESIL VM");
	SETPREF("esil.stack.pattern", "0", "Specify fill pattern to initialize the stack (0, w, d, i)");
	SETI("esil.addr.size", 64, "Maximum address size in accessed by the ESIL VM");
	SETBPREF("esil.breakoninvalid", "false", "Break esil execution when instruction is invalid");
	SETI("esil.timeout", 0, "A timeout (in seconds) for when we should give up emulating");
	/* asm */
	// asm.os needs to be first, since other asm.* depend on it
	n = NODECB("asm.os", "none", &cb_asmos);
	SETDESC(n, "Select operating system (kernel)");
	SETOPTIONS(n, "ios", "dos", "darwin", "linux", "freebsd", "openbsd", "netbsd", "windows", "s110", "none", NULL);
	SETI("asm.xrefs.fold", 5, "Maximum number of xrefs to be displayed as list (use columns above)");
	SETBPREF("asm.xrefs.code", "true", "Show the code xrefs (generated by jumps instead of calls)");
	SETI("asm.xrefs.max", 20, "Maximum number of xrefs to be displayed without folding");
	SETCB("asm.invhex", "false", &cb_asm_invhex, "Show invalid instructions as hexadecimal numbers");
	SETBPREF("asm.instr", "true", "Display the disassembled instruction");
	SETBPREF("asm.meta", "true", "Display the code/data/format conversions in disasm");
	SETBPREF("asm.bytes", "false", "Display the bytes of each instruction");
	SETBPREF("asm.bytes.right", "false", "Display the bytes at the right of the disassembly");
	SETI("asm.types", 1, "Display the fcn types in calls (0=no,1=quiet,2=verbose)");
	SETBPREF("asm.midcursor", "false", "Cursor in visual disasm mode breaks the instruction");
	SETBPREF("asm.cmt.flgrefs", "true", "Show comment flags associated to branch reference");
	SETBPREF("asm.cmt.right", "true", "Show comments at right of disassembly if they fit in screen");
	SETBPREF("asm.cmt.esil", "false", "Show ESIL expressions as comments");
	SETBPREF("asm.cmt.il", "false", "Show RzIL expressions as comments");
	SETI("asm.cmt.col", 71, "Column to align comments");
	SETICB("asm.pcalign", 0, &cb_asm_pcalign, "Only recognize as valid instructions aligned to this value");
	// maybe rename to asm.cmt.calls
	SETBPREF("asm.calls", "true", "Show callee function related info as comments in disasm");
	SETBPREF("asm.comments", "true", "Show comments in disassembly view");
	SETBPREF("asm.usercomments", "false", "Show user comments even if asm.comments is false");
	SETBPREF("asm.sub.jmp", "true", "Always substitute jump, call and branch targets in disassembly");
	SETBPREF("asm.hints", "true", "Disable all asm.hint* if false");
	SETBPREF("asm.hint.jmp", "false", "Show jump hints [numbers] in disasm");
	SETBPREF("asm.hint.call", "true", "Show call hints [numbers] in disasm");
	SETBPREF("asm.hint.call.indirect", "true", "Hints for indirect call intructions go to the call destination");
	SETBPREF("asm.hint.lea", "false", "Show LEA hints [numbers] in disasm");
	SETBPREF("asm.hint.emu", "false", "Show asm.emu hints [numbers] in disasm");
	SETBPREF("asm.hint.cdiv", "false", "Show CDIV hints optimization hint");
	SETI("asm.hint.pos", 1, "Shortcut hint position (-1, 0, 1)");
	SETBPREF("asm.slow", "true", "Perform slow analysis operations in disasm");
	SETBPREF("asm.decode", "false", "Use code analysis as a disassembler");
	SETICB("asm.imm.hash", 0, &cb_asm_immhash, "Display # for immediates in ARM and Hexagon (0 = on)");
	SETBPREF("asm.imm.str", "true", "Show immediates values as strings");
	SETBPREF("asm.imm.trim", "false", "Remove all offsets and constants from disassembly");
	SETBPREF("asm.indent", "false", "Indent disassembly based on reflines depth");
	SETI("asm.indentspace", 2, "How many spaces to indent the code");
	SETBPREF("asm.debuginfo", "false", "Show debug information in disassembly");
	SETBPREF("asm.debuginfo.abspath", "false", "Show absolute path from the debug information");
	SETBPREF("asm.debuginfo.file", "true", "Show file name from the debug information in disassembly");
	SETBPREF("asm.debuginfo.lines", "true", "Show source line information from debug metadata in disassembly");
	SETBPREF("asm.esil", "false", "Show ESIL instead of mnemonic");
	SETBPREF("asm.nodup", "false", "Do not show dupped instructions (collapse disasm)");
	SETBPREF("asm.emu", "false", "Run ESIL emulation analysis on disasm");
	SETBPREF("emu.pre", "false", "Run ESIL emulation starting at the closest flag in pd");
	SETBPREF("asm.refptr", "true", "Show refpointer information in disasm");
	SETBPREF("emu.lazy", "false", "Do not emulate all instructions with aae (optimization)");
	SETBPREF("emu.stack", "false", "Create a temporary fake stack when emulating in disasm (asm.emu)");
	SETCB("emu.str", "false", &cb_emustr, "Show only strings if any in the asm.emu output");
	SETBPREF("emu.str.lea", "true", "Disable this in ARM64 code to remove some false positives");
	SETBPREF("emu.str.off", "false", "Always show offset when printing asm.emu strings");
	SETBPREF("emu.str.inv", "true", "Color-invert emu.str strings");
	SETBPREF("emu.str.flag", "true", "Also show flag (if any) for asm.emu string");
	SETBPREF("emu.write", "false", "Allow asm.emu to modify memory (WARNING)");
	SETBPREF("emu.ssa", "false", "Perform SSA checks and show the ssa reg names as comments");
	n = NODECB("emu.skip", "ds", &cb_emuskip);
	SETDESC(n, "Skip metadata of given types in asm.emu");
	SETOPTIONS(n, "d", "c", "s", "f", "m", "h", "C", "r", NULL);
	SETBPREF("asm.sub.names", "true", "Replace numeric values by flags (e.g. 0x4003e0 -> sym.imp.printf)");
	SETPREF("asm.strip", "", "strip all instructions given comma separated types");
	SETBPREF("asm.optype", "false", "show opcode type next to the instruction bytes");
	SETBPREF("asm.lines.fcn", "true", "Show function boundary lines");
	SETBPREF("asm.flags", "true", "Show flags");
	SETICB("asm.flags.maxname", 0, &cb_maxname, "Maximum length of flag name with smart chopping");
	SETI("asm.flags.limit", 0, "Maximum number of flags to show in a single offset");
	SETBPREF("asm.flags.offset", "false", "Show offset in flags");
	SETBPREF("asm.flags.inbytes", "false", "Display flags inside the bytes space");
	SETBPREF("asm.flags.inline", "false", "Display flags in line separated by commas instead of newlines");
	n = NODEICB("asm.flags.middle", 2, &cb_midflags);
	SETOPTIONS(n, "0 = do not show flag", "1 = show without realign", "2 = realign at middle flag",
		"3 = realign at middle flag if sym.*", NULL);
	SETDESC(n, "Realign disassembly if there is a flag in the middle of an instruction");
	SETCB("asm.flags.real", "false", &cb_flag_realnames,
		"Show flags' unfiltered realnames instead of names, except realnames from demangling");
	SETBPREF("asm.bb.line", "false", "Show empty line after every basic block");
	SETBPREF("asm.bb.middle", "true", "Realign disassembly if a basic block starts in the middle of an instruction");
	SETBPREF("asm.lbytes", "true", "Align disasm bytes to left");
	SETBPREF("asm.lines", "true", "Show ASCII-art lines at disassembly");
	SETBPREF("asm.lines.bb", "true", "Show flow lines at jumps");
	SETBPREF("asm.lines.call", "false", "Enable call lines");
	SETBPREF("asm.lines.ret", "false", "Show separator lines after ret");
	SETBPREF("asm.lines.out", "true", "Show out of block lines");
	SETBPREF("asm.lines.right", "false", "Show lines before opcode instead of offset");
	SETBPREF("asm.lines.wide", "false", "Put a space between lines");
	SETBPREF("asm.fcn.signature", "true", "Show function signature in disasm");
	SETBPREF("asm.fcn.size", "false", "Show function size in disasm");
	SETICB("asm.lines.width", 7, &cb_asmlineswidth, "Number of columns for program flow arrows");
	SETICB("asm.sub.varmin", 0x100, &cb_asmsubvarmin, "Minimum value to substitute in instructions (asm.sub.var)");
	SETCB("asm.sub.tail", "false", &cb_asmsubtail, "Replace addresses with prefix .. syntax");
	SETBPREF("asm.middle", "false", "Allow disassembling jumps in the middle of an instruction");
	SETBPREF("asm.noisy", "true", "Show comments considered noisy but possibly useful");
	SETBPREF("asm.offset", "true", "Show offsets in disassembly");
	SETBPREF("hex.offset", "true", "Show offsets in hex-dump");
	SETBPREF("scr.square", "true", "Use square pixels or not");
	SETCB("scr.prompt.vi", "false", &cb_scr_vi, "Use vi mode for input prompt");
	SETCB("scr.prompt.mode", "false", &cb_scr_prompt_mode, "Set prompt color based on vi mode");
	SETCB("scr.wideoff", "false", &cb_scr_wideoff, "Adjust offsets to match asm.bits");
	SETCB("scr.last", "true", &cb_scrlast, "Cache last output after flush to make _ command work (disable for performance)");
	SETBPREF("asm.reloff", "false", "Show relative offsets instead of absolute address in disasm");
	SETBPREF("asm.reloff.flags", "false", "Show relative offsets to flags (not only functions)");
	SETBPREF("asm.section", "false", "Show section name before offset");
	SETBPREF("asm.section.perm", "false", "Show section permissions in the disasm");
	SETBPREF("asm.section.name", "true", "Show section name in the disasm");
	SETI("asm.section.col", 30, "Columns width to show asm.section");
	SETCB("asm.sub.section", "false", &cb_asmsubsec, "Show offsets in disasm prefixed with section/map name");
	SETCB("asm.pseudo", "false", &cb_asmpseudo, "Enable pseudo syntax");
	SETBPREF("asm.size", "false", "Show size of opcodes in disassembly (pd)");
	SETBPREF("asm.stackptr", "false", "Show stack pointer at disassembly");
	SETBPREF("asm.cyclespace", "false", "Indent instructions depending on CPU-cycles");
	SETBPREF("asm.cycles", "false", "Show CPU-cycles taken by instruction at disassembly");
	SETI("asm.tabs", 6, "Use tabs in disassembly");
	SETBPREF("asm.tabs.once", "true", "Only tabulate the opcode, not the arguments");
	SETI("asm.tabs.off", 0, "tabulate spaces after the offset");
	SETBPREF("asm.trace", "false", "Show execution traces for each opcode");
	SETBPREF("asm.tracespace", "false", "Indent disassembly with trace.count information");
	SETBPREF("asm.ucase", "false", "Use uppercase syntax at disassembly");
	SETBPREF("asm.capitalize", "false", "Use camelcase at disassembly");
	SETBPREF("asm.var", "true", "Show local function variables in disassembly");
	SETBPREF("asm.var.access", "false", "Show accesses of local variables");
	SETBPREF("asm.sub.var", "true", "Substitute variables in disassembly");
	SETI("asm.var.summary", 0, "Show variables summary instead of full list in disasm (0, 1, 2)");
	n = NODECB("asm.var.fold", "none", &cb_asm_varfold);
	SETDESC(n, "Fold same-typed variables (support none, group, hide)");
	SETOPTIONS(n, "none", "group", "hide", NULL);
	SETBPREF("asm.sub.varonly", "true", "Substitute the entire variable expression with the local variable name (e.g. [local10h] instead of [ebp+local10h])");
	SETBPREF("asm.sub.reg", "false", "Substitute register names with their associated role name (drp~=)");
	SETBPREF("asm.sub.rel", "true", "Substitute pc relative expressions in disasm");
	SETBPREF("asm.family", "false", "Show family name in disasm");
	SETBPREF("asm.symbol", "false", "Show symbol+delta instead of absolute offset");
	SETBPREF("asm.analysis", "false", "Analyze code and refs while disassembling (see analysis.strings)");
	SETI("asm.symbol.col", 40, "Columns width to show asm.section");
	SETCB("asm.assembler", "", &cb_asmassembler, "Set the plugin name to use when assembling");
	SETBPREF("asm.minicols", "false", "Only show the instruction in the column disasm");
	RzConfigNode *asmcpu = NODECB("asm.cpu", "", &cb_asm_cpu);
	SETDESC(asmcpu, "Set the kind of asm.arch cpu");
	RzConfigNode *asmarch = NODECB("asm.arch", RZ_SYS_ARCH, &cb_asm_arch);
	SETDESC(asmarch, "Set the arch to be used by asm");
	/* we need to have both asm.arch and asm.cpu defined before updating options */
	update_asmarch_options(core, asmarch);
	update_asmcpu_options(core, asmcpu);
	n = NODECB("asm.features", "", &cb_asm_features);
	SETDESC(n, "Specify supported features by the target CPU");
	update_asmfeatures_options(core, n);
	n = NODECB("asm.platform", "", &cb_asmplatform);
	SETDESC(n, "Specify supported platforms by the target architecture");
	update_asmplatforms_options(core, n);
	n = NODECB("asm.parser", "x86.pseudo", &cb_asmparser);
	SETDESC(n, "Set the asm parser to use");
	update_asmparser_options(core, n);
	SETCB("asm.segoff", "false", &cb_segoff, "Show segmented address in prompt (x86-16)");
	SETCB("asm.decoff", "false", &cb_decoff, "Show segmented address in prompt (x86-16)");
	SETICB("asm.seggrn", 4, &cb_seggrn, "Segment granularity in bits (x86-16)");
	n = NODECB("asm.syntax", "intel", &cb_asmsyntax);
	SETDESC(n, "Select assembly syntax");
	SETOPTIONS(n, "att", "intel", "masm", "jz", "regnum", NULL);
	SETI("asm.nbytes", 6, "Number of bytes for each opcode at disassembly");
	SETBPREF("asm.bytes.space", "false", "Separate hexadecimal bytes with a whitespace");
#if RZ_SYS_BITS == RZ_SYS_BITS_64
	SETICB("asm.bits", 64, &cb_asm_bits, "Word size in bits at assembler");
#else
	SETICB("asm.bits", 32, &cb_asm_bits, "Word size in bits at assembler");
#endif
	n = rz_config_node_get(cfg, "asm.bits");
	update_asmbits_options(core, n);
	SETBPREF("asm.functions", "true", "Show functions in disassembly");
	SETBPREF("asm.xrefs", "true", "Show xrefs in disassembly");
	SETBPREF("asm.demangle", "true", "Show demangled symbols in disasm");
	SETBPREF("asm.describe", "false", "Show opcode description");
	SETPREF("asm.highlight", "", "Highlight current line");
	SETBPREF("asm.marks", "true", "Show marks before the disassembly");
	SETBPREF("asm.cmt.refs", "false", "Show flag and comments from refs in disasm");
	SETBPREF("asm.cmt.patch", "false", "Show patch comments in disasm");
	SETBPREF("asm.cmt.off", "nodup", "Show offset comment in disasm (true, false, nodup)");
	SETBPREF("asm.payloads", "false", "Show payload bytes in disasm");

	/* bin */
	SETPREF("bin.hashlimit", "10M", "Only compute hash when opening a file if smaller than this size");
	SETCB("bin.usextr", "true", &cb_usextr, "Use extract plugins when loading files");
	SETCB("bin.str.purge", "", &cb_strpurge, "Purge strings (e bin.str.purge=? provides more detail)");
	SETBPREF("bin.b64str", "false", "Try to debase64 the strings");
	SETCB("bin.at", "false", &cb_binat, "RzBin.cur depends on RzCore.offset");
	SETBPREF("bin.libs", "false", "Try to load libraries after loading main binary");
	n = NODECB("bin.str.filter", "", &cb_strfilter);
	SETDESC(n, "Filter strings");
	SETOPTIONS(n, "a", "8", "p", "e", "u", "i", "U", "f", NULL);
	SETCB("bin.filter", "true", &cb_binfilter, "Filter symbol names to fix dupped names");
	SETCB("bin.force", "", &cb_binforce, "Force that rbin plugin");
	SETPREF("bin.lang", "", "Language for bin.demangle");
	SETCB("bin.demangle", "true", &cb_bindemangle, "Demangles all symbols parsed via RzBin");
	SETBPREF("bin.demangle.libs", "false", "Show library name on demangled symbols names");
	n = NODECB("bin.demangle.flags", "base", &cb_bindemangle_flags);
	SETDESC(n, "Sets the flags of the parsed symbols via RzBin");
	SETOPTIONS(n, "base", "simplify", "all", NULL);
	SETI("bin.baddr", -1, "Base address of the binary");
	SETI("bin.laddr", 0, "Base address for loading library ('*.so')");
	SETCB("bin.dbginfo", "true", &cb_bindbginfo, "Load debug information at startup if available");
	SETCB("bin.dbginfo.dwo_path", "", NULL, "Load separate debug information (DWARF) file if available");
	SETCB("bin.dbginfo.debug_file_directory", "/usr/lib/debug", NULL,
		"Set the directories which searches for separate debugging information files to directory");
	SETCB("bin.dbginfo.debuginfod", "false", NULL,
		"Load debug file from bin.dbginfo.debuginfod_urls or DEBUGINFOD_URLS environment variable");
	SETCB("bin.dbginfo.debuginfod_urls", "http://debuginfod.elfutils.org/", NULL,
		"Looks for debug symbols on the debuginfod servers, the value is a string of a space separated URLs");
	SETBPREF("bin.relocs", "true", "Load relocs information at startup if available");
	SETCB("bin.prefix", "", &cb_binprefix, "Prefix all symbols/sections/relocs with a specific string");
	SETCB("bin.strings", "true", &cb_binstrings, "Load strings from rbin on startup");
	SETCB("bin.debase64", "false", &cb_debase64, "Try to debase64 all strings");
	SETBPREF("bin.classes", "true", "Load classes from rbin on startup");
	SETCB("bin.verbose", "false", &cb_binverbose, "Show RzBin warnings when loading binaries");
	SETCB("bin.hashes.default", "md5,sha1,sha256,crc32,entropy", &cb_binhashesdefault, "Select hash algorithms");

	/* prj */
	SETPREF("prj.file", "", "Path of the currently opened project");
	SETBPREF("prj.compress", "false", "Compress the project file while saving");

	/* cfg */
	SETBPREF("cfg.plugins", "true", "Load plugins at startup");
	SETCB("time.fmt", "%Y-%m-%d %H:%M:%S %z", &cb_cfgdatefmt, "Date format (%Y-%m-%d %H:%M:%S %z)");
	SETICB("time.zone", 0, &cb_timezone, "Time zone, in hours relative to GMT: +2, -1,..");
	SETCB("cfg.debug", "false", &cb_cfgdebug, "Debugger mode");
	p = rz_sys_getenv("EDITOR");
#if __WINDOWS__
	rz_config_set(cfg, "cfg.editor", p ? p : "notepad");
#else
	rz_config_set(cfg, "cfg.editor", p ? p : "vi");
#endif
	free(p);
	rz_config_desc(cfg, "cfg.editor", "Select default editor program");
	SETPREF("cfg.user", rz_sys_whoami(buf), "Set current username/pid");
	SETCB("cfg.fortunes", "true", &cb_cfg_fortunes, "If enabled show tips at start");
	SETCB("cfg.fortunes.file", "tips", &cb_cfg_fortunes_file, "Type of fortunes to show (tips, fun)");
	SETBPREF("cfg.fortunes.clippy", "false", "Use 'clippy' instead of 'echo'");
	SETPREF("cfg.prefixdump", "dump", "Filename prefix for automated dumps");
	SETBPREF("cfg.wseek", "false", "Seek after write");
	SETICB("cfg.seek.histsize", 63, NULL, "Maximum size of the seek history");
	SETCB("cfg.seek.silent", "false", NULL, "When true, seek movements are not logged in seek history");
	SETCB("cfg.bigendian", "false", &cb_bigendian, "Use little (false) or big (true) endianness");
	SETI("cfg.cpuaffinity", 0, "Run on cpuid");

	/* log */
	// RZ_LOGLEVEL / log.level
	p = rz_sys_getenv("RZ_LOGLEVEL");
	SETICB("log.level", p ? atoi(p) : RZ_DEFAULT_LOGLVL, cb_log_config_level, "Target log level/severity"
										  " (0:DEBUG, 1:VERBOSE, 2:INFO, 3:WARN, 4:ERROR, 5:FATAL)");
	free(p);

#if RZ_BUILD_DEBUG
	// RZ_ABORTLEVEL / log.abortlevel
	p = rz_sys_getenv("RZ_ABORTLEVEL");
	SETICB("log.abortlevel", p ? atoi(p) : RZ_DEFAULT_LOGLVL_ABORT, cb_log_config_abortlevel, "Target log level/severity when to abort."
												  " (0:DEBUG, 1:VERBOSE, 2:INFO, 3:WARN, 4:ERROR, 5:FATAL)");
	free(p);
#endif /* RZ_BUILD_DEBUG */

	// RZ_LOGFILE / log.file
	p = rz_sys_getenv("RZ_LOGFILE");
	SETCB("log.file", p ? p : "", cb_log_file, "Logging output filename / path");
	free(p);

	// RZ_LOGSHOWSOURCES / log.show.sources
	p = rz_sys_getenv("RZ_LOGSHOWSOURCES");
	SETCB("log.show.sources", p ? p : "false", cb_log_config_show_sources, "Should the log output contain src info (filename:lineno)");
	free(p);

	// RZ_LOGCOLORS / log.colors
	p = rz_sys_getenv("RZ_LOGCOLORS");
	SETCB("log.colors", p ? p : "false", cb_log_config_colors, "Should the log output use colors (TODO)");
	free(p);

	SETCB("log.events", "false", &cb_log_events, "Remote HTTP server to sync events with");

	/* diff */
	n = NODECB("diff.sort", "addr", &cb_diff_sort);
	SETDESC(n, "Specify function diff sorting column");
	SETOPTIONS(n, "name", "namelen", "addr", "size", NULL);
	SETI("diff.from", 0, "Set source diffing address for px (uses cc command)");
	SETI("diff.to", 0, "Set destination diffing address for px (uses cc command)");
	SETBPREF("diff.bare", "false", "Never show function names in diff output");

	/* dir */
	SETI("dir.depth", 10, "Maximum depth when searching recursively for files");
	{
		char *path = rz_path_system(RZ_SDB_MAGIC);
		SETPREF("dir.magic", path, "Path to rz_magic files");
		free(path);
		path = rz_path_system(RZ_PLUGINS);
		SETPREF("dir.plugins", path, "Path to plugin files to be loaded at startup");
		free(path);
	}
	SETCB("dir.source", "", &cb_dirsrc, "Path to find source files");
	SETPREF("dir.types", "/usr/include", "Default path to look for cparse type files");
	SETPREF("dir.libs", "", "Specify path to find libraries to load when bin.libs=true");
	p = rz_sys_getenv(RZ_SYS_HOME);
	SETCB("dir.home", p ? p : "/", &cb_dirhome, "Path for the home directory");
	free(p);
	p = rz_sys_getenv(RZ_SYS_TMP);
	SETCB("dir.tmp", p ? p : "", &cb_dirtmp, "Path of the tmp directory");
	free(p);
#if __ANDROID__
	SETPREF("dir.projects", "/data/data/org.rizin.rizininstaller/rizin/projects", "Default path for projects");
#else
	char *projects_dir = rz_path_home_prefix(RZ_PROJECTS);
	SETPREF("dir.projects", projects_dir, "Default path for projects");
	free(projects_dir);
#endif
	SETPREF("stack.reg", "SP", "Which register to use as stack pointer in the visual debug");
	SETBPREF("stack.bytes", "true", "Show bytes instead of words in stack");
	SETBPREF("stack.anotated", "false", "Show anotated hexdump in visual debug");
	SETI("stack.size", 64, "Size in bytes of stack hexdump in visual debug");
	SETI("stack.delta", 0, "Delta for the stack dump");

	SETCB("dbg.libs", "", &cb_dbg_libs, "If set stop when loading matching libname");
	SETBPREF("dbg.skipover", "false", "Make dso perform a dss (same goes for esil and visual/graph");
	SETB("dbg.hwbp", false, "Use hardware instead of software breakpoints by default");
	SETCB("dbg.unlibs", "", &cb_dbg_unlibs, "If set stop when unloading matching libname");
	SETCB("dbg.verbose", "false", &cb_dbg_verbose, "Verbose debug output");
	SETBPREF("dbg.slow", "false", "Show stack and regs in visual mode in a slow but verbose mode");
	SETBPREF("dbg.funcarg", "false", "Display arguments to function call in visual mode");

	SETCB("dbg.bpinmaps", "true", &cb_dbg_bpinmaps, "Activate breakpoints only if they are inside a valid map");
	SETCB("dbg.forks", "false", &cb_dbg_forks, "Stop execution if fork() is done (see dbg.threads)");
#if __WINDOWS__
	n = NODECB("dbg.btalgo", "default", &cb_dbg_btalgo);
#else
	n = NODECB("dbg.btalgo", "fuzzy", &cb_dbg_btalgo);
#endif
	SETDESC(n, "Select backtrace algorithm");
	SETOPTIONS(n, "default", "fuzzy", "analysis", "trace", NULL);
	SETCB("dbg.threads", "false", &cb_stopthreads, "Stop all threads when debugger breaks (see dbg.forks)");
	SETCB("dbg.clone", "false", &cb_dbg_clone, "Stop execution if new thread is created");
	SETCB("dbg.aftersyscall", "true", &cb_dbg_aftersc, "Stop execution before the syscall is executed (see dcs)");
	SETCB("dbg.profile", "", &cb_runprofile, "Path to RzRunProfile file");
	SETCB("dbg.args", "", &cb_dbg_args, "Set the args of the program to debug");
	SETCB("dbg.follow.child", "false", &cb_dbg_follow_child, "Continue tracing the child process on fork. By default the parent process is traced");
	SETCB("dbg.trace_continue", "true", &cb_dbg_trace_continue, "Trace every instruction between the initial PC position and the PC position at the end of continue's execution");
	SETCB("dbg.create_new_console", "true", &cb_dbg_create_new_console, "Create a new console window for the debugee on debug start");
	/* debug */
	SETBPREF("dbg.status", "false", "Set cmd.prompt to '.dr*' or '.dr*;drd;sr PC;pi 1;shu'");
#if DEBUGGER
	SETCB("dbg.backend", "native", &cb_dbgbackend, "Select the debugger backend");
#else
	SETCB("dbg.backend", "esil", &cb_dbgbackend, "Select the debugger backend");
#endif
	n = NODECB("dbg.bep", "loader", &cb_dbgbep);
	SETDESC(n, "Break on entrypoint");
	SETOPTIONS(n, "loader", "entry", "constructor", "main", NULL);
	if (core->cons->rows > 30) { // HACKY
		rz_config_set_i(cfg, "dbg.follow", 64);
	} else {
		rz_config_set_i(cfg, "dbg.follow", 32);
	}
	rz_config_desc(cfg, "dbg.follow", "Follow program counter when pc >= core->offset + dbg.follow");
	SETBPREF("dbg.rebase", "true", "Rebase analysis/meta/comments/flags when reopening file in debugger");
	SETCB("dbg.swstep", "false", &cb_swstep, "Force use of software steps (code analysis+breakpoint)");
	SETBPREF("dbg.trace.inrange", "false", "While tracing, avoid following calls outside specified range");
	SETBPREF("dbg.trace.libs", "true", "Trace library code too");
	SETBPREF("dbg.exitkills", "true", "Kill process on exit");
	SETPREF("dbg.exe.path", "", "Path to binary being debugged");
	SETCB("dbg.execs", "false", &cb_dbg_execs, "Stop execution if new thread is created");
	SETICB("dbg.gdb.page_size", 4096, &cb_dbg_gdb_page_size, "Page size on gdb target (useful for QEMU)");
	SETICB("dbg.gdb.retries", 10, &cb_dbg_gdb_retries, "Number of retries before gdb packet read times out");
	SETCB("dbg.consbreak", "false", &cb_consbreak, "SIGINT handle for attached processes");

	rz_config_set_getter(cfg, "dbg.swstep", (RzConfigCallback)__dbg_swstep_getter);

	SETBPREF("dbg.bpsysign", "false", "Ignore system breakpoints");
	SETICB("dbg.btdepth", 128, &cb_dbgbtdepth, "Depth of backtrace");
	SETCB("dbg.trace", "false", &cb_trace, "Trace program execution (see asm.trace)");
	SETICB("dbg.trace.tag", 0, &cb_tracetag, "Trace tag");

	/* cmd */
	SETICB("cmd.depth", 10, &cb_cmddepth, "Maximum command depth");
	SETPREF("cmd.bp", "", "Run when a breakpoint is hit");
	SETPREF("cmd.onsyscall", "", "Run when a syscall is hit");
	SETICB("cmd.hitinfo", 1, &cb_debug_hitinfo, "Show info when a tracepoint/breakpoint is hit");
	SETPREF("cmd.stack", "", "Command to display the stack in visual debug mode");
	SETPREF("cmd.cprompt", "", "Column visual prompt commands");
	SETPREF("cmd.gprompt", "", "Graph visual prompt commands");
	SETPREF("cmd.hit", "", "Run when a search hit is found");
	SETPREF("cmd.open", "", "Run when file is opened");
	SETPREF("cmd.load", "", "Run when binary is loaded");
	SETPREF("cmd.prompt", "", "Prompt commands");
	SETCB("cmd.repeat", "false", &cb_cmdrepeat, "Empty command an alias for '..' (repeat last command)");
	SETPREF("cmd.fcn.new", "", "Run when new function is analyzed");
	SETPREF("cmd.fcn.delete", "", "Run when a function is deleted");
	SETPREF("cmd.fcn.rename", "", "Run when a function is renamed");
	SETPREF("cmd.visual", "", "Replace current print mode");
	SETPREF("cmd.vprompt", "", "Visual prompt commands");

	SETCB("cmd.esil.step", "", &cb_cmd_esil_step, "Command to run before performing a step in the emulator");
	SETCB("cmd.esil.stepout", "", &cb_cmd_esil_step_out, "Command to run after performing a step in the emulator");
	SETCB("cmd.esil.mdev", "", &cb_cmd_esil_mdev, "Command to run when memory device address is accessed");
	SETCB("cmd.esil.intr", "", &cb_cmd_esil_intr, "Command to run when an esil interrupt happens");
	SETCB("cmd.esil.trap", "", &cb_cmd_esil_trap, "Command to run when an esil trap happens");
	SETCB("cmd.esil.todo", "", &cb_cmd_esil_todo, "Command to run when the esil instruction contains TODO");
	SETCB("cmd.esil.ioer", "", &cb_cmd_esil_ioer, "Command to run when esil fails to IO (invalid read/write)");

	/* hexdump */
	SETCB("hex.header", "true", &cb_hex_header, "Show header in hexdump");
	SETCB("hex.bytes", "true", &cb_hex_bytes, "Show bytes column in hexdump");
	SETCB("hex.ascii", "true", &cb_hex_ascii, "Show ascii column in hexdump");
	SETCB("hex.hdroff", "false", &cb_hex_hdroff, "Show aligned 1 byte in header instead of delta nibble");
	SETCB("hex.style", "false", &cb_hex_style, "Improve the hexdump header style");
	SETCB("hex.pairs", "true", &cb_hex_pairs, "Show bytes paired in 'px' hexdump");
	SETCB("hex.align", "false", &cb_hex_align, "Align hexdump with flag + flagsize");
	SETCB("hex.section", "false", &cb_hex_section, "Show section name before the offset");
	SETCB("hex.compact", "false", &cb_hexcompact, "Show smallest 16 byte col hexdump (60 columns)");
	SETCB("cmd.hexcursor", "", &cb_cmd_hexcursor, "If set and cursor is enabled display given pf format string");
	SETI("hex.flagsz", 0, "If non zero, overrides the flag size in pxa");
	SETICB("hex.cols", 16, &cb_hexcols, "Number of columns in hexdump");
	SETI("hex.depth", 5, "Maximal level of recurrence while telescoping memory");
	SETBPREF("hex.onechar", "false", "Number of columns in hexdump");
	SETICB("hex.stride", 0, &cb_hexstride, "Line stride in hexdump (default is 0)");
	SETCB("hex.comments", "true", &cb_hexcomments, "Show comments in 'px' hexdump");

	/* http */
	SETBPREF("http.log", "true", "Show HTTP requests processed");
	SETBPREF("http.colon", "false", "Only accept the : command");
	SETPREF("http.logfile", "", "Specify a log file instead of stderr for http requests");
	SETBPREF("http.cors", "false", "Enable CORS");
	SETPREF("http.referer", "", "CSFR protection if set");
	SETBPREF("http.dirlist", "false", "Enable directory listing");
	SETPREF("http.allow", "", "Only accept clients from the comma separated IP list");
#if __WINDOWS__
	rz_config_set(cfg, "http.browser", "start");
#else
	if (rz_file_exists("/usr/bin/openURL")) { // iOS ericautils
		rz_config_set(cfg, "http.browser", "/usr/bin/openURL");
	} else if (rz_file_exists("/system/bin/toolbox")) {
		rz_config_set(cfg, "http.browser",
			"LD_LIBRARY_PATH=/system/lib am start -a android.intent.action.VIEW -d");
	} else if (rz_file_exists("/usr/bin/xdg-open")) {
		rz_config_set(cfg, "http.browser", "xdg-open");
	} else if (rz_file_exists("/usr/bin/open")) {
		rz_config_set(cfg, "http.browser", "open");
	} else {
		rz_config_set(cfg, "http.browser", "firefox");
	}
	rz_config_desc(cfg, "http.browser", "Command to open HTTP URLs");
#endif
	SETI("http.maxsize", 0, "Maximum file size for upload");
	SETPREF("http.index", "index.html", "Main html file to check in directory");
	SETPREF("http.bind", "localhost", "Server address");
	char *wwwroot_dir = rz_path_home_prefix(RZ_WWWROOT);
	SETPREF("http.homeroot", wwwroot_dir, "http home root directory");
	free(wwwroot_dir);
#if __ANDROID__
	SETPREF("http.root", "/data/data/org.rizin.rizininstaller/www", "http root directory");
#else
	char *wwwroot = rz_path_system(RZ_WWWROOT);
	SETPREF("http.root", wwwroot, "http root directory");
	free(wwwroot);
#endif
	SETPREF("http.port", "9090", "HTTP server port");
	SETI("http.timeout", 3, "Disconnect clients after N seconds of inactivity");
	SETI("http.stop.after", 0, "Stops the http server after N seconds if there are no client connected");
	SETBPREF("http.verbose", "false", "Output server logs to stdout");
	SETBPREF("http.upget", "false", "/up/ answers GET requests, in addition to POST");
	SETBPREF("http.upload", "false", "Enable file uploads to /up/<filename>");
	SETPREF("http.uri", "", "Address of HTTP proxy");
	SETBPREF("http.auth", "false", "Enable/Disable HTTP Authentification");
	p = rz_sys_getenv("RZ_HTTP_AUTHFILE");
	SETPREF("http.authfile", p ? p : "", "HTTP Authentification user file");
	tmpdir = rz_file_tmpdir();
	rz_config_set(cfg, "http.uproot", tmpdir);
	free(tmpdir);
	rz_config_desc(cfg, "http.uproot", "Path where files are uploaded");

	/* tcp */
	SETBPREF("tcp.islocal", "false", "Bind a loopback for tcp command server");

	/* graph */
	SETBPREF("graph.aeab", "false", "Show aeab info on each basic block instead of disasm");
	SETBPREF("graph.trace", "false", "Fold all non-traced basic blocks");
	SETBPREF("graph.dummy", "true", "Create dummy nodes in the graph for better layout (20% slower)");
	SETBPREF("graph.few", "false", "Show few basic blocks in the graph");
	SETBPREF("graph.comments", "true", "Show disasm comments in graph");
	SETBPREF("graph.cmtright", "false", "Show comments at right");
	SETCB("graph.gv.format", "gif", &cb_graphformat, "Graph image extension when using 'w' format (png, jpg, pdf, ps, svg, json)");
	SETBPREF("graph.refs", "false", "Graph references in callgraphs (.agc*;aggi)");
	SETBPREF("graph.json.usenames", "true", "Use names instead of addresses in Global Call Graph (agCj)");
	SETI("graph.edges", 2, "0=no edges, 1=simple edges, 2=avoid collisions");
	SETI("graph.layout", 0, "Graph layout (0=vertical, 1=horizontal)");
	SETI("graph.linemode", 1, "Graph edges (0=diagonal, 1=square)");
	SETPREF("graph.font", "Courier", "Font for dot graphs");
	SETBPREF("graph.offset", "false", "Show offsets in graphs");
	SETBPREF("graph.bytes", "false", "Show opcode bytes in graphs");
	SETI("graph.from", UT64_MAX, "Lower bound address when drawing global graphs");
	SETI("graph.to", UT64_MAX, "Upper bound address when drawing global graphs");
	SETI("graph.scroll", 5, "Scroll speed in ascii-art graph");
	SETBPREF("graph.invscroll", "false", "Invert scroll direction in ascii-art graph");
	SETPREF("graph.title", "", "Title of the graph");
	SETBPREF("graph.body", "true", "Show body of the nodes in the graph");
	SETBPREF("graph.ntitles", "true", "Display title of node");
	SETPREF("graph.gv.node", "", "Graphviz node style. (color=gray, style=filled shape=box)");
	SETPREF("graph.gv.edge", "", "Graphviz edge style. (arrowhead=\"vee\")");
	SETPREF("graph.gv.spline", "", "Graphviz spline style. (splines=\"ortho\")");
	SETPREF("graph.gv.graph", "", "Graphviz global style attributes. (bgcolor=white)");
	SETPREF("graph.gv.current", "false", "Highlight the current node in graphviz graph.");
	SETBPREF("graph.nodejmps", "true", "Enables shortcuts for every node.");
	SETBPREF("graph.hints", "true", "Show true (t) and false (f) hints for conditional edges in graph");
	SETCB("graph.dotted", "false", &cb_dotted, "Dotted lines for conditional jumps in graph");

	/* hud */
	SETPREF("hud.path", "", "Set a custom path for the HUD file");

	SETCB("esil.exectrap", "false", &cb_exectrap, "trap when executing code in non-executable memory");
	SETCB("esil.iotrap", "true", &cb_iotrap, "invalid read or writes produce a trap exception");
	SETBPREF("esil.romem", "false", "Set memory as read-only for ESIL");
	SETBPREF("esil.stats", "false", "Statistics from ESIL emulation stored in sdb");
	SETBPREF("esil.nonull", "false", "Prevent memory read, memory write at null pointer");
	SETCB("esil.mdev.range", "", &cb_mdevrange, "Specify a range of memory to be handled by cmd.esil.mdev");

	/* scr */
#if __EMSCRIPTEN__
	rz_config_set_cb(cfg, "scr.fgets", "true", cb_scrfgets);
#else
	rz_config_set_cb(cfg, "scr.fgets", "false", cb_scrfgets);
#endif
	rz_config_desc(cfg, "scr.fgets", "Use fgets() instead of dietline for prompt input");
	SETCB("scr.echo", "false", &cb_screcho, "Show rcons output in realtime to stderr and buffer");
	SETICB("scr.linesleep", 0, &cb_scrlinesleep, "Flush sleeping some ms in every line");
	SETICB("scr.maxtab", 4096, &cb_completion_maxtab, "Change max number of auto completion suggestions");
	SETICB("scr.pagesize", 1, &cb_scrpagesize, "Flush in pages when scr.linesleep is != 0");
	SETCB("scr.flush", "false", &cb_scrflush, "Force flush to console in realtime (breaks scripting)");
	SETBPREF("scr.slow", "true", "Do slow stuff on visual mode like RzFlag.get_at(true)");
	SETCB("scr.prompt.popup", "false", &cb_scr_prompt_popup, "Show widget dropdown for autocomplete");
#if __WINDOWS__
	SETICB("scr.vtmode", rz_cons_singleton()->vtmode,
		&scr_vtmode, "Use VT sequences on Windows (0: Disable, 1: Output, 2: Input & Output)");
#endif
#if __ANDROID__
	SETBPREF("scr.responsive", "true", "Auto-adjust Visual depending on screen (e.g. unset asm.bytes)");
	SETI("scr.wheel.speed", 1, "Mouse wheel speed");
#else
	SETBPREF("scr.responsive", "false", "Auto-adjust Visual depending on screen (e.g. unset asm.bytes)");
	SETI("scr.wheel.speed", 4, "Mouse wheel speed");
#endif
	SETBPREF("scr.wheel.nkey", "false", "Use sn/sp and scr.nkey on wheel instead of scroll");
	// RENAME TO scr.mouse
	SETBPREF("scr.wheel", "true", "Mouse wheel in Visual; temporaryly disable/reenable by right click/Enter)");
	SETPREF("scr.layout", "", "Name of the selected layout");
	// DEPRECATED: USES hex.cols now SETI ("scr.colpos", 80, "Column position of cmd.cprompt in visual");
	SETCB("scr.breakword", "", &cb_scrbreakword, "Emulate console break (^C) when a word is printed (useful for pD)");
	SETCB("scr.breaklines", "false", &cb_breaklines, "Break lines in Visual instead of truncating them");
	SETCB("scr.gadgets", "true", &cb_scr_gadgets, "Run pg in prompt, visual and panels");
	SETBPREF("scr.panelborder", "false", "Specify panels border active area (0 by default)");
	SETICB("scr.columns", 0, &cb_scrcolumns, "Force console column count (width)");
	SETBPREF("scr.dumpcols", "false", "Prefer pC commands before p ones");
	SETCB("scr.rows", "0", &cb_scrrows, "Force console row count (height) ");
	SETICB("scr.rows", 0, &cb_rows, "Force console row count (height) (duplicate?)");
	SETICB("scr.fix.rows", 0, &cb_fixrows, "Workaround for Linux TTY");
	SETICB("scr.fix.columns", 0, &cb_fixcolumns, "Workaround for Prompt iOS SSH client");
	SETCB("scr.highlight", "", &cb_scrhighlight, "Highlight that word at RzCons level");
	SETCB("scr.interactive", "true", &cb_scrint, "Start in interactive mode");
	SETCB("scr.bgfill", "false", &cb_scr_bgfill, "Fill background for ascii art when possible");
	SETI("scr.feedback", 1, "Set visual feedback level (1=arrow on jump, 2=every key (useful for videos))");
	SETCB("scr.html", "false", &cb_scrhtml, "Disassembly uses HTML syntax");
	n = NODECB("scr.nkey", "flag", &cb_scrnkey);
	SETDESC(n, "Select visual seek mode (affects n/N visual commands)");
	SETOPTIONS(n, "fun", "hit", "flag", NULL);
	SETCB("scr.pager", "", &cb_pager, "System program (or '..') to use when output exceeds screen boundaries");
	SETI("scr.scrollbar", 0, "Show flagzone (fz) scrollbar in visual mode (0=no,1=right,2=top,3=bottom)");
	SETBPREF("scr.randpal", "false", "Random color palete or just get the next one from 'eco'");
	SETCB("scr.highlight.grep", "false", &cb_scr_color_grep_highlight, "Highlight (INVERT) the grepped words");
	SETBPREF("scr.prompt.file", "false", "Show user prompt file (used by rizin -q)");
	SETBPREF("scr.prompt.flag", "false", "Show flag name in the prompt");
	SETBPREF("scr.prompt.flag.only", "false", "Show the flag name only in the prompt");
	SETBPREF("scr.prompt.sect", "false", "Show section name in the prompt");
	SETCB("scr.hist.block", "true", &cb_scr_histblock, "Use blocks for histogram");
	SETCB("scr.prompt", "true", &cb_scrprompt, "Show user prompt (used by rizin -q)");
	SETCB("scr.tee", "", &cb_teefile, "Pipe output to file of this name");
	SETPREF("scr.seek", "", "Seek to the specified address on startup");
	SETICB("scr.color", (core->print->flags & RZ_PRINT_FLAGS_COLOR) ? COLOR_MODE_16 : COLOR_MODE_DISABLED, &cb_color, "Enable colors (0: none, 1: ansi, 2: 256 colors, 3: truecolor)");
	rz_config_set_getter(cfg, "scr.color", (RzConfigCallback)cb_color_getter);
	SETCB("scr.color.grep", "false", &cb_scr_color_grep, "Enable colors when using ~grep");
	SETBPREF("scr.color.pipe", "false", "Enable colors when using pipes");
	SETBPREF("scr.color.ops", "true", "Colorize numbers and registers in opcodes");
	SETBPREF("scr.color.args", "true", "Colorize arguments and variables of functions");
	SETBPREF("scr.color.bytes", "true", "Colorize bytes that represent the opcodes of the instruction");
	SETCB("scr.null", "false", &cb_scrnull, "Show no output");
	SETCB("scr.utf8", rz_str_bool(rz_cons_is_utf8()), &cb_utf8, "Show UTF-8 characters instead of ANSI");
	SETCB("scr.utf8.curvy", "false", &cb_utf8_curvy, "Show curved UTF-8 corners (requires scr.utf8)");
	SETBPREF("scr.histsave", "true", "Always save history on exit");
	n = NODECB("scr.strconv", "asciiesc", &cb_scrstrconv);
	SETDESC(n, "Convert string before display");
	SETOPTIONS(n, "asciiesc", "asciidot", NULL);
	SETBPREF("scr.confirmquit", "false", "Confirm on quit");
	SETICB("scr.visual.mode", RZ_CORE_VISUAL_MODE_PX, &cb_visual_mode, "Visual mode (0: hexdump, 1: disassembly, 2: debug, 3: color blocks, 4: strings)");

	/* str */
	SETCB("str.escbslash", "false", &cb_str_escbslash, "Escape the backslash");

	/* string search options */
	SETB("str.search.reload", true, "When enabled, any change to any option `str.search.*` will reload the bin strings.");
	SETICB("str.search.max_threads", RZ_THREAD_N_CORES_ALL_AVAILABLE, &cb_str_search_max_threads, "Maximum core number (0 for all cores).");
	SETICB("str.search.min_length", RZ_BIN_STRING_SEARCH_MIN_STRING, &cb_str_search_min_length, "Smallest string length that is possible to find.");
	SETICB("str.search.buffer_size", RZ_BIN_STRING_SEARCH_BUFFER_SIZE, &cb_str_search_buffer_size, "Maximum buffer size, which will also determine the maximum string length.");
	SETICB("str.search.max_uni_blocks", RZ_BIN_STRING_SEARCH_MAX_UNI_BLOCKS, &cb_str_search_max_uni_blocks, "Maximum number of unicode blocks.");
	SETICB("str.search.max_region_size", RZ_BIN_STRING_SEARCH_MAX_REGION_SIZE, &cb_str_search_max_region_size, "Maximum allowable size for the string search interval between two memory regions.");
	SETICB("str.search.raw_alignment", RZ_BIN_STRING_SEARCH_RAW_FILE_ALIGNMENT, &cb_str_search_raw_alignment, "Memory sector alignment used for the raw string search.");
	SETICB("str.search.check_ascii_freq", RZ_BIN_STRING_SEARCH_CHECK_ASCII_FREQ, &cb_str_search_check_ascii_freq, "If true, perform check on ASCII frequencies when looking for false positives during string search");
	n = NODECB("str.search.encoding", "guess", &cb_str_search_encoding);
	SETDESC(n, "The default string encoding type (when set to guess, it is automatically guessed).");
	SETOPTIONS(n, "ascii", "8bit", "utf8", "utf16le", "utf32le", "utf16be", "utf32be", "guess", NULL);
	n = NODECB("str.search.mode", "auto", &cb_str_search_mode);
	SETDESC(n, "String search mode which can override how strings are found (auto, rosections or raw)");
	SETOPTIONS(n, "auto", "rosections", "raw", NULL);

	/* search */
	SETCB("search.contiguous", "true", &cb_contiguous, "Accept contiguous/adjacent search hits");
	SETICB("search.align", 0, &cb_searchalign, "Only catch aligned search hits");
	SETI("search.chunk", 0, "Chunk size for /+ (default size is asm.bits/8");
	SETI("search.esilcombo", 8, "Stop search after N consecutive hits");
	SETI("search.distance", 0, "Search string distance");
	SETBPREF("search.flags", "true", "All search results are flagged, otherwise only printed");
	SETBPREF("search.overlap", "false", "Look for overlapped search hits");
	SETI("search.maxhits", 0, "Maximum number of hits (0: no limit)");
	SETI("search.from", -1, "Search start address");
	n = NODECB("search.in", "io.maps", &cb_searchin);
	SETDESC(n, "Specify search boundaries");
	SETOPTIONS(n, "raw", "block",
		"bin.section", "bin.sections", "bin.sections.rwx", "bin.sections.r", "bin.sections.rw", "bin.sections.rx", "bin.sections.wx", "bin.sections.x",
		"io.map", "io.maps", "io.maps.rwx", "io.maps.r", "io.maps.rw", "io.maps.rx", "io.maps.wx", "io.maps.x",
		"dbg.stack", "dbg.heap",
		"dbg.map", "dbg.maps", "dbg.maps.rwx", "dbg.maps.r", "dbg.maps.rw", "dbg.maps.rx", "dbg.maps.wx", "dbg.maps.x",
		"analysis.fcn", "analysis.bb",
		NULL);
	SETICB("search.kwidx", 0, &cb_search_kwidx, "Store last search index count");
	SETPREF("search.prefix", "hit", "Prefix name in search hits label");
	SETBPREF("search.show", "true", "Show search results");
	SETI("search.to", -1, "Search end address");
	n = NODECB("search.case_sensitive", "smart", &cb_search_case_sensitive);
	SETDESC(n, "Set grep(~) as case smart/sensitive/insensitive");
	SETOPTIONS(n, "smart", "sensitive", "insensitive", NULL);

	/* rop */
	SETI("rop.len", 5, "Maximum ROP gadget length");
	SETBPREF("rop.cache", "false", "Cache rop gadget results(experimental)");
	SETBPREF("rop.subchains", "false", "Display every length gadget from rop.len=X to 2 in /Rl");
	SETBPREF("rop.conditional", "false", "Include conditional jump, calls and returns in ropsearch");
	SETBPREF("rop.comments", "false", "Display comments in rop search output");

	/* io */
	SETCB("io.cache", "false", &cb_io_cache, "Change both of io.cache.{read,write}");
	SETCB("io.cache.auto", "false", &cb_io_cache_mode, "Automatic cache all reads in the IO backend");
	SETCB("io.cache.read", "false", &cb_io_cache_read, "Enable read cache for vaddr (or paddr when io.va=0)");
	SETCB("io.cache.write", "false", &cb_io_cache_write, "Enable write cache for vaddr (or paddr when io.va=0)");
	SETCB("io.pcache", "false", &cb_iopcache, "io.cache for p-level");
	SETCB("io.pcache.write", "false", &cb_iopcachewrite, "Enable write-cache");
	SETCB("io.pcache.read", "false", &cb_iopcacheread, "Enable read-cache");
	SETCB("io.ff", "true", &cb_ioff, "Fill invalid buffers with 0xff instead of returning error");
	SETBPREF("io.exec", "true", "See !!rizin -h~-x");
	SETICB("io.0xff", 0xff, &cb_io_oxff, "Use this value instead of 0xff to fill unallocated areas");
	SETCB("io.aslr", "false", &cb_ioaslr, "Disable ASLR for spawn and such");
	SETCB("io.va", "true", &cb_iova, "Use virtual address layout");
	SETCB("io.pava", "false", &cb_io_pava, "Use EXPERIMENTAL paddr -> vaddr address mode");
	SETCB("io.autofd", "true", &cb_ioautofd, "Change fd when opening a new file");
	SETCB("io.unalloc", "false", &cb_io_unalloc, "Check each byte if it's allocated");
	SETCB("io.unalloc.ch", ".", &cb_io_unalloc_ch, "Char to display if byte is unallocated");

	/* file */
	SETBPREF("file.info", "true", "RzBin info loaded");
	SETPREF("file.offset", "", "Offset where the file will be mapped at");
	SETCB("file.path", "", &cb_filepath, "Path of current file");
	SETPREF("file.lastpath", "", "Path of current file");
	SETPREF("file.type", "", "Type of current file");
	SETI("file.loadalign", 1024, "Alignment of load addresses");
	SETI("file.openmany", 1, "Maximum number of files opened at once");
	/* magic */
	SETI("magic.depth", 100, "Recursivity depth in magic description strings");

	/* rap */
	SETBPREF("rap.loop", "true", "Run rap as a forever-listening daemon (=:9090)");

	/* basefind */
	SETB("basefind.progress", false, "Basefind threads progress (true: enable, false: disable)");
	SETI("basefind.search.start", RZ_BASEFIND_BASE_MIN_ADDRESS, "Basefind start search address");
	SETI("basefind.search.end", RZ_BASEFIND_BASE_MAX_ADDRESS, "Basefind end search address");
	SETI("basefind.alignment", RZ_BASEFIND_BASE_ALIGNMENT, "Basefind alignment in bytes");
	SETI("basefind.min.score", RZ_BASEFIND_SCORE_MIN_VALUE, "Basefind min score value to consider it valid");
	SETI("basefind.min.string", RZ_BASEFIND_STRING_MIN_LENGTH, "Basefind min string size to find to consider it valid");
	SETI("basefind.max.threads", RZ_THREAD_N_CORES_ALL_AVAILABLE, "Basefind max threads number (when 0 uses all available cores)");

	/* nkeys */
	SETPREF("key.s", "", "override step into action");
	SETPREF("key.S", "", "override step over action");
	for (i = 1; i < 13; i++) {
		snprintf(buf, sizeof(buf), "key.f%d", i);
		snprintf(buf + 10, sizeof(buf) - 10,
			"Run this when F%d key is pressed in visual mode", i);
		switch (i) {
		default: p = ""; break;
		}
		rz_config_set(cfg, buf, p);
		rz_config_desc(cfg, buf, buf + 10);
	}

	/* zoom */
	SETCB("zoom.byte", "h", &cb_zoombyte, "Zoom callback to calculate each byte (See pz? for help)");
	SETI("zoom.from", 0, "Zoom start address");
	SETI("zoom.maxsz", 512, "Zoom max size of block");
	SETI("zoom.to", 0, "Zoom end address");
	n = NODECB("zoom.in", "io.map", &cb_searchin);
	SETDESC(n, "Specify  boundaries for zoom");
	SETOPTIONS(n, "raw", "block",
		"bin.section", "bin.sections", "bin.sections.rwx", "bin.sections.r", "bin.sections.rw", "bin.sections.rx", "bin.sections.wx", "bin.sections.x",
		"io.map", "io.maps", "io.maps.rwx", "io.maps.r", "io.maps.rw", "io.maps.rx", "io.maps.wx", "io.maps.x",
		"dbg.stack", "dbg.heap",
		"dbg.map", "dbg.maps", "dbg.maps.rwx", "dbg.maps.r", "dbg.maps.rw", "dbg.maps.rx", "dbg.maps.wx", "dbg.maps.x",
		"analysis.fcn", "analysis.bb",
		NULL);

	/* RzIL config */
	SETB("rzil.step.events.read", false, "enables/disables printing aezse read event");
	SETB("rzil.step.events.write", true, "enables/disables printing aezse write event");

	/* FLIRT config */
	SETBPREF("flirt.sig.library", RZ_FLIRT_LIBRARY_NAME_DFL, "FLIRT library name for sig format");
	SETI("flirt.sig.version", 10, "FLIRT version for sig format");
	n = NODECB("flirt.sig.file", "all", &cb_flirt);
	SETDESC(n, "FLIRT file list (comma separated) for sig format");
	SETOPTIONS(n, "msdos", "win", "os2", "netware", "unix", "other", "all", "none", NULL);
	n = NODECB("flirt.sig.os", "all", &cb_flirt);
	SETDESC(n, "FLIRT operating system list (comma separated) for sig format");
	SETOPTIONS(n,
		"aixar", "aout", "ar", "bin", "coff", "dos:com", "dos:com:old", "dos:exe", "dos:exe:old",
		"dosdrv", "elf", "intelhex", "le", "loader", "lx", "moshex", "ne", "nlm", "omf", "omflib",
		"pe", "pilot", "srec", "w32run", "zip", "all", "none", NULL);
	SETB("flirt.sig.deflate", false, "Enables/disables FLIRT zlib compression when creating a signature file (available only for .sig files)");
	SETI("flirt.node.optimize", RZ_FLIRT_NODE_OPTIMIZE_MAX, "FLIRT optimization option when creating a signature file (none: 0, normal: 1, smallest: 2)");
	SETB("flirt.ignore.unknown", true, "When enabled, on FLIRT creation it will ignore any function starting with `fcn.`");
	SETPREF("flirt.sigdb.path", "", "Additional user defined rizin sigdb location to load on the filesystem.");
	SETB("flirt.sigdb.load.system", true, "Load signatures from the system path");
	SETB("flirt.sigdb.load.extra", true, "Load signatures from the extra path");
	SETB("flirt.sigdb.load.home", true, "Load signatures from the home path");

	rz_config_lock(cfg, true);
	return true;
}

RZ_API void rz_core_parse_rizinrc(RzCore *r) {
	bool has_debug = rz_sys_getenv_asbool("RZ_DEBUG");
	char *rcfile = rz_sys_getenv("RZ_RCFILE");
	char *homerc = NULL;
	if (!RZ_STR_ISEMPTY(rcfile)) {
		homerc = rcfile;
	} else {
		free(rcfile);
		homerc = rz_path_home_rc();
	}
	if (homerc && rz_file_is_regular(homerc)) {
		if (has_debug) {
			RZ_LOG_INFO("USER CONFIG loaded from %s\n", homerc);
		}
		rz_core_cmd_file(r, homerc);
	}
	free(homerc);
	homerc = rz_path_home_config_rc();
	if (homerc && rz_file_is_regular(homerc)) {
		if (has_debug) {
			RZ_LOG_INFO("USER CONFIG loaded from %s\n", homerc);
		}
		rz_core_cmd_file(r, homerc);
	}
	free(homerc);
	homerc = rz_path_home_config_rcdir();
	if (homerc) {
		if (rz_file_is_directory(homerc)) {
			char *file;
			RzListIter *iter;
			RzList *files = rz_sys_dir(homerc);
			rz_list_foreach (files, iter, file) {
				if (*file != '.') {
					char *path = rz_str_newf("%s/%s", homerc, file);
					if (rz_file_is_regular(path)) {
						if (has_debug) {
							RZ_LOG_INFO("USER CONFIG loaded from %s\n", homerc);
						}
						rz_core_cmd_file(r, path);
					}
					free(path);
				}
			}
			rz_list_free(files);
		}
		free(homerc);
	}
}

/**
 * \brief Get config variable spaces
 * \param core The RzCore instance
 * \param space The config space
 * \return RzList of config variable spaces
 */
RZ_API RZ_OWN RzList /*<char *>*/ *rz_core_config_in_space(RZ_NONNULL RzCore *core, RZ_NULLABLE const char *space) {
	rz_return_val_if_fail(core && core->config, NULL);
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	RzConfigNode *node;
	RzListIter *iter;
	rz_list_foreach (core->config->nodes, iter, node) {
		char *name = rz_str_dup(node->name);
		if (!name) {
			continue;
		}
		char *dot = strchr(name, '.');
		if (dot) {
			*dot = 0;
		}

		if (RZ_STR_ISNOTEMPTY(space)) {
			if (0 == strcmp(name, space) && dot && !rz_list_find(list, dot + 1, (RzListComparator)strcmp, NULL)) {
				rz_list_append(list, rz_str_dup(dot + 1));
			}
		} else {
			if (!rz_list_find(list, name, (RzListComparator)strcmp, NULL)) {
				rz_list_append(list, rz_str_dup(name));
			}
		}
		free(name);
	}
	return list;
}
