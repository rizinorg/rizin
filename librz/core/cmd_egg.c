// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_cons.h"
#include "rz_core.h"
#include "rz_egg.h"

static const char *help_msg_g[] = {
	"Usage:", "g[wcilper] [arg]", "Go compile shellcodes",
	"g", " ", "Compile the shellcode",
	"g", " foo.r", "Compile rz_egg source file",
	"gw", "", "Compile and write",
	"gc", " cmd=/bin/ls", "Set config option for shellcodes and encoders",
	"gc", "", "List all config options",
	"gl", "[?]", "List plugins (shellcodes, encoders)",
	"gs", " name args", "Compile syscall name(args)",
	"gi", " [type]", "Define the shellcode type",
	"gp", " padding", "Define padding for command",
	"ge", " [encoder] [key]", "Specify an encoder and a key",
	"gr", "", "Reset rz_egg",
	"gS", "", "Show the current configuration",
	"EVAL VARS:", "", "asm.arch, asm.bits, asm.os",
	NULL
};

static void cmd_egg_option(RzEgg *egg, const char *key, const char *input) {
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
			rz_cons_printf("%02x", rz_buf_read8(b));
		}
		rz_cons_newline();
	}
}

#if 0
static int compileShellcode(RzEgg *egg, const char *input){
	int i = 0;
	RzBuffer *b;
	if (!rz_egg_shellcode (egg, input)) {
		eprintf ("Unknown shellcode '%s'\n", input);
		return 1;
	}
	if (!rz_egg_assemble (egg)) {
		eprintf ("rz_egg_assemble : invalid assembly\n");
		rz_egg_reset (egg);
		return 1;
	}
	if (!egg->bin) {
		egg->bin = rz_buf_new ();
	}
	if (!(b = rz_egg_get_bin (egg))) {
		eprintf ("rz_egg_get_bin: invalid egg :(\n");
		rz_egg_reset (egg);
		return 1;
	}
	rz_egg_finalize (egg);
	for (i = 0; i < b->length; i++) {
		rz_cons_printf ("%02x", b->buf[i]);
	}
	rz_cons_newline ();
	rz_egg_reset (egg);
	return 0;
}
#endif

static int cmd_egg_compile(RzEgg *egg) {
	RzBuffer *b;
	int ret = false;
	char *p = rz_egg_option_get(egg, "egg.shellcode");
	if (p && *p) {
		if (!rz_egg_shellcode(egg, p)) {
			eprintf("Unknown shellcode '%s'\n", p);
			free(p);
			return false;
		}
		free(p);
	} else {
		eprintf("Setup a shellcode before (gi command)\n");
		free(p);
		return false;
	}

	rz_egg_compile(egg);
	if (!rz_egg_assemble(egg)) {
		eprintf("rz_egg_assemble: invalid assembly\n");
		return false;
	}
	p = rz_egg_option_get(egg, "egg.padding");
	if (p && *p) {
		rz_egg_padding(egg, p);
		free(p);
	}
	p = rz_egg_option_get(egg, "egg.encoder");
	if (p && *p) {
		rz_egg_encode(egg, p);
		free(p);
	}
	if ((b = rz_egg_get_bin(egg))) {
		showBuffer(b);
		ret = true;
	}
	// we do not own this buffer!!
	// rz_buf_free (b);
	rz_egg_option_set(egg, "egg.shellcode", "");
	rz_egg_option_set(egg, "egg.padding", "");
	rz_egg_option_set(egg, "egg.encoder", "");
	rz_egg_option_set(egg, "key", "");

	rz_egg_reset(egg);
	return ret;
}

RZ_IPI int rz_cmd_egg(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	RzEgg *egg = core->egg;
	char *oa, *p;
	rz_egg_setup(egg,
		rz_config_get(core->config, "asm.arch"),
		core->rasm->bits, 0,
		rz_config_get(core->config, "asm.os")); // XXX
	switch (*input) {
	case 's': // "gs"
		// TODO: pass args to rz_core_syscall without vararg
		if (input[1] == ' ') {
			RzBuffer *buf = NULL;
			const char *ooaa = input + 2;
			while (IS_WHITESPACE(*ooaa) && *ooaa)
				ooaa++;
			oa = strdup(ooaa);
			p = strchr(oa + 1, ' ');
			if (p) {
				*p = 0;
				buf = rz_core_syscall(core, oa, p + 1);
			} else {
				buf = rz_core_syscall(core, oa, "");
			}
			free(oa);
			if (buf) {
				showBuffer(buf);
			}
			egg->lang.nsyscalls = 0;
		} else {
			eprintf("Usage: gs [syscallname] [parameters]\n");
		}
		break;
	case ' ': // "g "
		if (input[1] && input[2]) {
			rz_egg_load(egg, input + 2, 0);
			if (!cmd_egg_compile(egg)) {
				eprintf("Cannot compile '%s'\n", input + 2);
			}
		} else {
			eprintf("wat\n");
		}
		break;
	case '\0': // "g"
		if (!cmd_egg_compile(egg)) {
			eprintf("Cannot compile\n");
		}
		break;
	case 'p': // "gp"
		if (input[1] == ' ') {
			if (input[0] && input[2]) {
				rz_egg_option_set(egg, "egg.padding", input + 2);
			}
		} else {
			eprintf("Usage: gp [padding]\n");
		}
		break;
	case 'e': // "ge"
		if (input[1] == ' ') {
			const char *encoder = input + 2;
			while (IS_WHITESPACE(*encoder) && *encoder) {
				encoder++;
			}

			oa = strdup(encoder);
			p = strchr(oa + 1, ' ');

			if (p) {
				*p = 0;
				rz_egg_option_set(egg, "key", p + 1);
				rz_egg_option_set(egg, "egg.encoder", oa);
			} else {
				eprintf("Usage: ge [encoder] [key]\n");
			}
			free(oa);
		} else {
			eprintf("Usage: ge [encoder] [key]\n");
		}
		break;
	case 'i': // "gi"
		if (input[1] == ' ') {
			if (input[0] && input[2]) {
				rz_egg_option_set(egg, "egg.shellcode", input + 2);
			} else {
				eprintf("Usage: gi [shellcode-type]\n");
			}
		} else {
			eprintf("Usage: gi [shellcode-type]\n");
		}
		break;
	case 'l': // "gl"
	{
		RzListIter *iter;
		RzEggPlugin *p;
		rz_list_foreach (egg->plugins, iter, p) {
			rz_cons_printf("%s  %6s : %s\n",
				(p->type == RZ_EGG_PLUGIN_SHELLCODE) ? "shc" : "enc", p->name, p->desc);
		}
	} break;
	case 'S': // "gS"
	{
		static const char *configList[] = {
			"egg.shellcode",
			"egg.encoder",
			"egg.padding",
			"key",
			"cmd",
			"suid",
			NULL
		};
		rz_cons_printf("Configuration options\n");
		int i;
		for (i = 0; configList[i]; i++) {
			const char *p = configList[i];
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
	} break;
	case 'r': // "gr"
		cmd_egg_option(egg, "egg.padding", "");
		cmd_egg_option(egg, "egg.shellcode", "");
		cmd_egg_option(egg, "egg.encoder", "");
		break;
	case 'c': // "gc"
		// list, get, set egg options
		switch (input[1]) {
		case ' ':
			oa = strdup(input + 2);
			p = strchr(oa, '=');
			if (p) {
				*p = 0;
				rz_egg_option_set(egg, oa, p + 1);
			} else {
				char *o = rz_egg_option_get(egg, oa);
				if (o) {
					rz_cons_print(o);
					free(o);
				}
			}
			free(oa);
			break;
		case '\0':
			// rz_pair_list (egg->pair,NULL);
			eprintf("TODO: list options\n");
			break;
		default:
			eprintf("Usage: gc [k=v]\n");
			break;
		}
		break;
	case '?':
		rz_core_cmd_help(core, help_msg_g);
		break;
	}
	return true;
}
