// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_egg.h>

static const char *RzEggConfigOptions[] = {
	"egg.shellcode",
	"egg.encoder",
	"egg.padding",
	"key",
	"cmd",
	"suid",
	NULL
};

static void egg_option(RzEgg *egg, const char *key, const char *input) {
	if (!*input) {
		return;
	}
	if (input[1] != ' ') {
		char *a = rz_egg_option_get(egg, key);
		if (a) {
			rz_cons_println(a);
			free(a);
		}
	} else {
		rz_egg_option_set(egg, key, input + 2);
	}
}

static void showBuffer(RzBuffer *b) {
	int i;
	if (b && rz_buf_size(b) > 0) {
		rz_buf_seek(b, 0, RZ_BUF_SET);
		for (i = 0; i < rz_buf_size(b); i++) {
			ut8 tmp;
			if (!rz_buf_read8(b, &tmp)) {
				return;
			}
			rz_cons_printf("%02x", tmp);
		}
		rz_cons_newline();
	}
}

static bool egg_compile(RzEgg *egg) {
	rz_egg_compile(egg);
	if (!rz_egg_assemble(egg)) {
		RZ_LOG_ERROR("core: rz_egg_assemble: invalid assembly\n");
		return false;
	}
	char *p = rz_egg_option_get(egg, "egg.padding");
	if (p && *p) {
		rz_egg_padding(egg, p);
		free(p);
	}
	p = rz_egg_option_get(egg, "egg.encoder");
	if (p && *p) {
		rz_egg_encode(egg, p);
		free(p);
	}
	RzBuffer *b;
	if ((b = rz_egg_get_bin(egg))) {
		showBuffer(b);
		return true;
	}
	return false;
}

static bool rz_core_egg_compile(RzEgg *egg) {
	int ret = false;
	char *p = rz_egg_option_get(egg, "egg.shellcode");
	if (p && *p) {
		if (!rz_egg_shellcode(egg, p)) {
			RZ_LOG_ERROR("core: Unknown shellcode '%s'\n", p);
			free(p);
			return false;
		}
		free(p);
	} else {
		RZ_LOG_ERROR("core: Setup a shellcode before (gi command)\n");
		free(p);
		return false;
	}
	ret = egg_compile(egg);
	rz_egg_option_set(egg, "egg.shellcode", "");
	rz_egg_option_set(egg, "egg.padding", "");
	rz_egg_option_set(egg, "egg.encoder", "");
	rz_egg_option_set(egg, "key", "");

	rz_egg_reset(egg);
	return ret;
}

static RzEgg *rz_core_egg_setup(RzCore *core) {
	RzEgg *egg = core->egg;
	const char *arch = rz_config_get(core->config, "asm.arch");
	const char *os = rz_config_get(core->config, "asm.os");
	int bits = rz_config_get_i(core->config, "asm.bits");

	if (!rz_egg_setup(egg, arch, bits, 0, os)) {
		RZ_LOG_ERROR("Cannot setup shellcode compiler for chosen configuration\n");
		return NULL;
	}
	return egg;
}

static RzCmdStatus rz_core_egg_compile_file(RzCore *core, const char *file) {
	rz_return_val_if_fail(file, false);
	RzEgg *egg = rz_core_egg_setup(core);
	if (!egg) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_egg_load_file(egg, file)) {
		RZ_LOG_ERROR("Cannot load file \"%s\"\n", file);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!egg_compile(egg)) {
		RZ_LOG_ERROR("Cannot compile file \"%s\"\n", file);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_egg_compile_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		return rz_core_egg_compile_file(core, argv[1]);
	} else {
		RzEgg *egg = rz_core_egg_setup(core);
		if (!egg) {
			return RZ_CMD_STATUS_ERROR;
		}
		if (!rz_core_egg_compile(egg)) {
			RZ_LOG_ERROR("Cannot compile the shellcode\n");
			return RZ_CMD_STATUS_ERROR;
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_egg_config_handler(RzCore *core, int argc, const char **argv) {
	RzEgg *egg = rz_core_egg_setup(core);
	if (!egg) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc < 2) {
		// List all available config options and their values
		size_t i;
		for (i = 0; RzEggConfigOptions[i]; i++) {
			const char *p = RzEggConfigOptions[i];
			if (rz_egg_option_get(egg, p)) {
				rz_cons_printf("%s : %s\n", p, rz_egg_option_get(egg, p));
			} else {
				rz_cons_printf("%s : %s\n", p, "");
			}
		}
		return RZ_CMD_STATUS_OK;
	}
	int i;
	for (i = 1; i < argc; i++) {
		// Set the config option
		RzList *l = rz_str_split_duplist_n(argv[i], "=", 1, false);
		if (!l) {
			return RZ_CMD_STATUS_ERROR;
		}
		size_t llen = rz_list_length(l);
		if (!llen) {
			return RZ_CMD_STATUS_ERROR;
		}
		char *key = rz_list_get_n(l, 0);
		if (RZ_STR_ISEMPTY(key)) {
			RZ_LOG_ERROR("No config option name specified\n");
			rz_list_free(l);
			return RZ_CMD_STATUS_ERROR;
		}
		// If there is value specified - set it, if not - just show the value
		if (llen == 1) {
			// No value
			char *o = rz_egg_option_get(egg, key);
			if (!o) {
				RZ_LOG_ERROR("No such config option exists\n");
				rz_list_free(l);
				return RZ_CMD_STATUS_ERROR;
			}
			rz_cons_print(o);
			free(o);
		} else if (llen == 2) {
			char *value = rz_list_get_n(l, 1);
			if (RZ_STR_ISEMPTY(value)) {
				RZ_LOG_ERROR("No config option value  specified\n");
				rz_list_free(l);
				return RZ_CMD_STATUS_ERROR;
			}
			rz_egg_option_set(egg, key, value);
		}
		rz_list_free(l);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_egg_list_plugins_handler(RzCore *core, int argc, const char **argv) {
	RzEgg *egg = rz_core_egg_setup(core);
	if (!egg) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzIterator *iter = ht_sp_as_iter(egg->plugins);
	RzEggPlugin **val;
	rz_iterator_foreach(iter, val) {
		RzEggPlugin *p = *val;
		rz_cons_printf("%s  %6s : %s\n",
			(p->type == RZ_EGG_PLUGIN_SHELLCODE) ? "shc" : "enc", p->name, p->desc);
	}
	rz_iterator_free(iter);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_egg_syscall_handler(RzCore *core, int argc, const char **argv) {
	RzEgg *egg = rz_core_egg_setup(core);
	if (!egg) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzBuffer *buf = NULL;
	if (argc > 2) {
		// With syscall parameters specified
		buf = rz_core_syscall(core, argv[1], argv[2]);
	} else {
		// Without any parameters
		buf = rz_core_syscall(core, argv[1], "");
	}
	if (buf) {
		showBuffer(buf);
	}
	egg->lang.nsyscalls = 0;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_egg_type_handler(RzCore *core, int argc, const char **argv) {
	RzEgg *egg = rz_core_egg_setup(core);
	if (!egg) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_egg_option_set(egg, "egg.shellcode", argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_egg_padding_handler(RzCore *core, int argc, const char **argv) {
	RzEgg *egg = rz_core_egg_setup(core);
	if (!egg) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_egg_option_set(egg, "egg.padding", argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_egg_encoder_handler(RzCore *core, int argc, const char **argv) {
	RzEgg *egg = rz_core_egg_setup(core);
	if (!egg) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_egg_option_set(egg, "key", argv[2]);
	rz_egg_option_set(egg, "egg.encoder", argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_egg_reset_handler(RzCore *core, int argc, const char **argv) {
	RzEgg *egg = rz_core_egg_setup(core);
	if (!egg) {
		return RZ_CMD_STATUS_ERROR;
	}
	egg_option(egg, "egg.padding", "");
	egg_option(egg, "egg.shellcode", "");
	egg_option(egg, "egg.encoder", "");
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_egg_show_config_handler(RzCore *core, int argc, const char **argv) {
	RzEgg *egg = rz_core_egg_setup(core);
	if (!egg) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("Configuration options\n");
	int i;
	for (i = 0; RzEggConfigOptions[i]; i++) {
		const char *p = RzEggConfigOptions[i];
		if (rz_egg_option_get(egg, p)) {
			rz_cons_printf("%s : %s\n", p, rz_egg_option_get(egg, p));
		} else {
			rz_cons_printf("%s : %s\n", p, "");
		}
	}
	rz_cons_printf("\nTarget options\n");
	rz_cons_printf("arch : %s\n", core->analysis->cpu);
	rz_cons_printf("os   : %s\n", core->analysis->os);
	rz_cons_printf("bits : %d\n", core->analysis->bits);
	return RZ_CMD_STATUS_OK;
}
