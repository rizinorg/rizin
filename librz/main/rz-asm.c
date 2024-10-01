// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2021 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include <rz_types.h>
#include <rz_util.h>
#include <stdio.h>
#include <string.h>
#include <rz_main.h>
#include <rz_core.h>

typedef struct {
	RzLib *l;
	RzAsm *a;
	RzAnalysis *analysis;
	bool oneliner;
	bool coutput;
	bool json;
	bool quiet;
} RzAsmState;

static void __load_plugins(RzAsmState *as);

static void __as_set_archbits(RzAsmState *as) {
	rz_asm_use(as->a, RZ_SYS_ARCH);
	rz_analysis_use(as->analysis, RZ_SYS_ARCH);
	int sysbits = (RZ_SYS_BITS & RZ_SYS_BITS_64) ? 64 : 32;
	rz_asm_set_bits(as->a, sysbits);
	rz_analysis_set_bits(as->analysis, sysbits);
}

static RzAsmState *__as_new(void) {
	RzAsmState *as = RZ_NEW0(RzAsmState);
	if (as) {
		as->l = rz_lib_new(NULL, NULL);
		as->a = rz_asm_new();
		if (as->a) {
			as->a->num = rz_num_new(NULL, NULL, NULL);
		}
		as->analysis = rz_analysis_new();
		__load_plugins(as);
		__as_set_archbits(as);
	}
	return as;
}

static void __as_free(RzAsmState *as) {
	if (as->a) {
		rz_num_free(as->a->num);
	}
	rz_asm_free(as->a);
	rz_analysis_free(as->analysis);
	rz_lib_free(as->l);
	free(as);
}

static char *stackop2str(int type) {
	switch (type) {
	case RZ_ANALYSIS_STACK_NULL: return rz_str_dup("null");
	case RZ_ANALYSIS_STACK_NOP: return rz_str_dup("nop");
	// case RZ_ANALYSIS_STACK_INCSTACK: return rz_str_dup ("incstack");
	case RZ_ANALYSIS_STACK_GET: return rz_str_dup("get");
	case RZ_ANALYSIS_STACK_SET: return rz_str_dup("set");
	}
	return rz_str_dup("unknown");
}

static void showanalysis(RzAsmState *as, RzAnalysisOp *op, ut64 offset, ut8 *buf, int len, PJ *pj) {
	char *stackop = stackop2str(op->stackop);
	const char *optype = rz_analysis_optype_to_string(op->type);
	char *bytes = rz_hex_bin2strdup(buf, RZ_MIN(len, op->size));
	if (as->json) {
		pj_o(pj);
		pj_kn(pj, "opcode", offset);
		pj_ks(pj, "bytes", bytes);
		pj_ks(pj, "type", optype);
		if (op->jump != UT64_MAX) {
			pj_kn(pj, "jump", op->jump);
		}
		if (op->fail != UT64_MAX) {
			pj_kn(pj, "fail", op->fail);
		}
		if (op->val != UT64_MAX) {
			pj_kn(pj, "val", op->val);
		}
		if (op->ptr != UT64_MAX) {
			pj_kn(pj, "ptr", op->ptr);
		}
		pj_ks(pj, "stackop", stackop);
		pj_ks(pj, "esil", rz_strbuf_get(&op->esil));
		pj_kn(pj, "stackptr", op->stackptr);
		pj_end(pj);
	} else {
		printf("offset:   0x%08" PFMT64x "\n", offset);
		printf("bytes:    %s\n", bytes);
		printf("type:     %s\n", optype);
		if (op->jump != -1LL) {
			printf("jump:     0x%08" PFMT64x "\n", op->jump);
		}
		if (op->fail != -1LL) {
			printf("fail:     0x%08" PFMT64x "\n", op->fail);
		}
		// if (op->ref != -1LL)
		//       printf ("ref:      0x%08"PFMT64x"\n", op->ref);
		if (op->val != -1LL) {
			printf("value:    0x%08" PFMT64x "\n", op->val);
		}
		printf("stackop:  %s\n", stackop);
		printf("esil:     %s\n", rz_strbuf_get(&op->esil));
		printf("stackptr: %" PFMT64d "\n", op->stackptr);
		// produces (null) printf ("decode str: %s\n", rz_analysis_op_to_string (analysis, op));
		printf("\n");
	}
	free(stackop);
	free(bytes);
}

// TODO: add israw/len
static int show_analinfo(RzAsmState *as, const char *arg, ut64 offset) {
	ut8 *buf = (ut8 *)rz_str_dup((const char *)arg);
	int ret, len = rz_hex_str2bin((char *)buf, buf);
	PJ *pj = NULL;
	if (as->json) {
		pj = pj_new();
		if (!pj) {
			free(buf);
			return 0;
		}
	}

	RzAnalysisOp aop = { 0 };

	if (pj) {
		pj_a(pj);
	}
	for (ret = 0; ret < len;) {
		aop.size = 0;
		rz_analysis_op_init(&aop);
		if (rz_analysis_op(as->analysis, &aop, offset, buf + ret, len - ret, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_ESIL) < 1) {
			eprintf("Error analyzing instruction at 0x%08" PFMT64x "\n", offset);
			break;
		}
		if (aop.size < 1) {
			if (pj) {
				pj_o(pj);
				pj_ks(pj, "bytes", rz_hex_bin2strdup(buf, ret));
				pj_ks(pj, "type", "Invalid");
				pj_end(pj);
			} else {
				eprintf("Invalid\n");
			}
			break;
		}
		showanalysis(as, &aop, offset, buf + ret, len - ret, pj);
		ret += aop.size;
		rz_analysis_op_fini(&aop);
	}
	if (pj) {
		pj_end(pj);
		printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
	free(buf);
	return ret;
}

static int rasm_show_help(int v) {
	if (v < 2) {
		printf("%s%s", Color_CYAN, "Usage: ");
		printf(Color_RESET "rz-asm [-ACdDehLBvw] [-a arch] [-b bits] [-o addr] [-s syntax]\n"
				   "             [-f file] [-F fil:ter] [-i skip] [-l len] 'code'|hex|-\n");
	}
	const char *options[] = {
		// clang-format off
		"-a",       "[arch]",           "Set architecture to assemble/disassemble (see -L)",
		"-A",       "",                 "Show Analysis information from given hexpairs",
		"-b",       "[bits]",           "Set cpu register size (8, 16, 32, 64) (RZ_ASM_BITS)",
		"-B",       "",                 "Binary input/output (-l is mandatory for binary input)",
		"-c",       "[cpu]",            "Select specific CPU (depends on arch)",
		"-C",       "",                 "Output in C format",
		"-d, -D",   "",                 "Disassemble from hexpair bytes (-D show hexpairs)",
		"-e",       "",                 "Use big endian instead of little endian",
		"-I",       "",                 "Display lifted RzIL code (same input as in -d, IL is also validated)",
		"-E",       "",                 "Display ESIL expression (same input as in -d)",
		"-f",       "[file]",           "Read data from file",
		"-F",       "[in:out]",         "Specify input and/or output filters (att2intel, x86.pseudo, ...)",
		"-h, -hh",  "",                 "Show this help, -hh for long",
		"-i",       "[len]",            "Ignore N bytes of the input buffer",
		"-j",       "",                 "Output in JSON format",
		"-k",       "[kernel]",         "Select operating system (linux, windows, darwin, ..)",
		"-l",       "[len]",            "Input/Output length",
		"-L",       "",                 "List Asm plugins: (a=asm, d=disasm, A=analyze, e=ESIL)",
		"-o, -@",   "[addr]",           "Set start address for code (default 0)",
		"-O",       "[file]",           "Output file name (rz-asm -Bf a.asm -O a)",
		"-p",       "",                 "Run SPP over input for assembly",
		"-q",       "",                 "Quiet mode",
		"-r",       "",                 "Output in rizin commands",
		"-s",       "[syntax]",         "Select syntax (intel, att)",
		"-v",       "",                 "Show version information",
		"-x",       "",                 "Use hex dwords instead of hex pairs when assembling.",
		"-w",       "",                 "Describe opcode",
		// clang-format on
	};
	if (v != 1) {
		size_t maxOptionAndArgLength = 0;
		for (int i = 0; i < sizeof(options) / sizeof(options[0]); i += 3) {
			size_t optionLength = strlen(options[i]);
			size_t argLength = strlen(options[i + 1]);
			size_t totalLength = optionLength + argLength;
			if (totalLength > maxOptionAndArgLength) {
				maxOptionAndArgLength = totalLength;
			}
		}
		for (int i = 0; i < sizeof(options) / sizeof(options[0]); i += 3) {
			if (i + 1 < sizeof(options) / sizeof(options[0])) {
				rz_print_colored_help_option(options[i], options[i + 1], options[i + 2], maxOptionAndArgLength);
			}
		}
	}
	printf(" If '-l' value is greater than output length, output is padded with nops\n"
	       " If the last argument is '-' reads from stdin\n"
	       "Environment:\n"
	       " RZ_ARCH      e asm.arch # architecture to assemble/disassemble (same as rz-asm -a)\n"
	       " RZ_ASM_ARCH             # architecture to assemble/disassemble (same as rz-asm -a)\n"
	       " RZ_ASM_BITS             # cpu register size (8, 16, 32, 64) (same as rz-asm -b)\n"
	       " RZ_BITS      e asm.bits # cpu register size (8, 16, 32, 64) (same as rz-asm -b)\n"
	       " RZ_DEBUG                # if defined, show error messages and crash signal\n"
	       " RZ_NOPLUGINS            # do not load shared plugins (speedup loading)\n"
	       "");
	if (v == 2) {
		printf("Supported Assembler directives:\n");
		rz_asm_list_directives();
	}
	return 0;
}

typedef enum {
	DISASM_MODE_DONT = 0,
	DISASM_MODE_DEFAULT,
	DISASM_MODE_WITH_BYTES,
	DISASM_MODE_ESIL,
	DISASM_MODE_IL
} DisasmMode;

static bool print_and_check_il(RzAsmState *as, RzAnalysisOp *op) {
	if (op->size < 1 || !op->il_op) {
		eprintf("Invalid instruction of lifting not implemented.\n");
		return false;
	}
	RzAnalysisILVM *vm = rz_analysis_il_vm_new(as->analysis, NULL);
	if (!vm) {
		eprintf("Failed to initialize IL VM for this architecture.\n");
		return false;
	}
	bool ret = true;
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_from_vm(vm->vm);
	if (!ctx) {
		eprintf("Failed to derive context from IL VM.\n");
		ret = false;
		goto error_vm;
	}
	RzILOpEffect *il_op = op->il_op;
	if (il_op) {
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		rz_il_op_effect_stringify(il_op, &sb, false);
		printf("%s\n", rz_strbuf_get(&sb));
		fflush(stdout); // to appear before validation report
		rz_strbuf_fini(&sb);
	}
	char *report;
	if (!rz_il_validate_effect(il_op, ctx, NULL, NULL, &report)) {
		ret = false;
		eprintf("IL Validation failed%c\n", report ? ':' : '.');
	}
	if (report) {
		eprintf("%s\n", report);
		free(report);
	}
	rz_il_validate_global_context_free(ctx);
error_vm:
	rz_analysis_il_vm_free(vm);
	return ret;
}

static int rasm_disasm(RzAsmState *as, ut64 addr, const char *buf, int len, int bits, int bin, DisasmMode mode) {
	RzAsmCode *acode;
	ut8 *data = NULL;
	int ret = 0;
	ut64 clen = 0;
	if (bits == 1) {
		len /= 8;
	}
	if (bin) {
		if (len < 0) {
			return false;
		}
		clen = len; // XXX
		data = (ut8 *)buf;
	} else {
		clen = rz_hex_str2bin(buf, NULL);
		if ((int)clen < 1 || !(data = malloc(clen))) {
			ret = 0;
			goto beach;
		}
		rz_hex_str2bin(buf, data);
		len = clen;
	}

	if (!len || clen <= len) {
		len = clen;
	}

	switch (mode) {
	case DISASM_MODE_ESIL: {
		RzAnalysisOp aop = { 0 };
		while (ret < len) {
			aop.size = 0;
			rz_analysis_op_init(&aop);
			if (rz_analysis_op(as->analysis, &aop, addr, data + ret, len - ret, RZ_ANALYSIS_OP_MASK_ESIL) > 0) {
				printf("%s\n", RZ_STRBUF_SAFEGET(&aop.esil));
			}
			if (aop.size < 1) {
				eprintf("Invalid\n");
				break;
			}
			ret += aop.size;
			rz_analysis_op_fini(&aop);
		}
		break;
	}
	case DISASM_MODE_IL: {
		RzAnalysisOp aop = { 0 };
		while (ret < len) {
			aop.size = 0;
			rz_analysis_op_init(&aop);
			if (rz_analysis_op(as->analysis, &aop, addr, data + ret, len - ret, RZ_ANALYSIS_OP_MASK_IL) <= 0) {
				eprintf("Invalid\n");
				ret = 0;
				break;
			}
			if (!print_and_check_il(as, &aop)) {
				rz_analysis_op_fini(&aop);
				ret = 0;
				break;
			}
			ret += aop.size;
			rz_analysis_op_fini(&aop);
		}
		break;
	}
	case DISASM_MODE_WITH_BYTES: {
		RzAsmOp op;
		rz_asm_set_pc(as->a, addr);
		while ((len - ret) > 0) {
			int dr = rz_asm_disassemble(as->a, &op, data + ret, len - ret);
			if (dr == -1 || op.size < 1) {
				op.size = 1;
				rz_asm_op_set_asm(&op, "invalid");
			}
			char *op_hex = rz_asm_op_get_hex(&op);
			printf("0x%08" PFMT64x "  %2d %24s  %s\n",
				as->a->pc, op.size, op_hex,
				rz_asm_op_get_asm(&op));
			free(op_hex);
			ret += op.size;
			rz_asm_set_pc(as->a, addr + ret);
		}
		break;
	}
	default: {
		rz_asm_set_pc(as->a, addr);
		if (!(acode = rz_asm_mdisassemble(as->a, data, len))) {
			goto beach;
		}
		if (as->oneliner) {
			rz_str_replace_char(acode->assembly, '\n', ';');
			printf("%s\"\n", acode->assembly);
		} else {
			printf("%s", acode->assembly);
		}
		ret = acode->len;
		rz_asm_code_free(acode);
		break;
	}
	}
beach:
	if (data && data != (ut8 *)buf) {
		free(data);
	}
	return ret;
}

static void print_buf(RzAsmState *as, char *str) {
	int i;
	if (as->coutput) {
		printf("\"");
		for (i = 1; *str; str += 2, i += 2) {
			if (!(i % 41)) {
				printf("\" \\\n\"");
				i = 1;
			}
			printf("\\x%c%c", *str, str[1]);
		}
		printf("\"\n");
	} else {
		printf("%s\n", str);
	}
}

static bool print_label(void *user, const char *k, const char *v) {
	printf("f label.%s @ %s\n", k, v);
	return true;
}

static int rasm_asm(RzAsmState *as, const char *buf, ut64 offset, ut64 len, int bits, int bin, bool use_spp, bool hexwords) {
	RzAsmCode *acode;
	int i, j, ret = 0;
	rz_asm_set_pc(as->a, offset);
	if (!(acode = rz_asm_rasm_assemble(as->a, buf, use_spp))) {
		return 0;
	}
	if (acode->len) {
		ret = acode->len;
		if (bin) {
			if ((ret = write(1, acode->bytes, acode->len)) != acode->len) {
				eprintf("Failed to write buffer\n");
				rz_asm_code_free(acode);
				return 0;
			}
		} else {
			int b = acode->len;
			if (bits == 1) {
				int bytes = (b / 8) + 1;
				for (i = 0; i < bytes; i++) {
					for (j = 0; j < 8 && b--; j++) {
						printf("%c", (acode->bytes[i] & (1 << j)) ? '1' : '0');
					}
				}
				printf("\n");
			} else {
				if (hexwords) {
					size_t i = 0;
					for (i = 0; i < acode->len; i += sizeof(ut32)) {
						ut32 dword = rz_read_ble32(acode->bytes + i, RZ_SYS_ENDIAN);
						printf("0x%08x ", dword);
						if ((i / 4) == 7) {
							printf("\n");
						}
					}
					printf("\n");
				} else {
					char *str = rz_asm_code_get_hex(acode);
					if (str) {
						print_buf(as, str);
						free(str);
					}
				}
			}
		}
	}
	rz_asm_code_free(acode);
	return (ret > 0);
}

/* asm callback */
static bool lib_asm_cb(RzLibPlugin *pl, void *user, void *data) {
	RzAsmPlugin *hand = (RzAsmPlugin *)data;
	RzAsmState *as = (RzAsmState *)user;
	return rz_asm_plugin_add(as->a, hand);
}

/* analysis callback */
static bool lib_analysis_cb(RzLibPlugin *pl, void *user, void *data) {
	RzAnalysisPlugin *hand = (RzAnalysisPlugin *)data;
	RzAsmState *as = (RzAsmState *)user;
	return rz_analysis_plugin_add(as->analysis, hand);
}

/* arch callback */
static bool lib_arch_cb(RzLibPlugin *pl, void *user, void *data) {
	RzArchPlugin *hand = (RzArchPlugin *)data;
	RzAsmState *as = (RzAsmState *)user;
	if (!hand->p_asm && !hand->p_analysis) {
		// TODO: add new structure.
		// return rz_arch_plugin_add(as->a, hand);
		return false;
	}
	if (hand->p_asm && !rz_asm_plugin_add(as->a, hand->p_asm)) {
		// deprecated structure
		return false;
	}
	if (hand->p_analysis && !rz_analysis_plugin_add(as->analysis, hand->p_analysis)) {
		// deprecated structure
		return false;
	}
	return true;
}

static int print_assembly_output(RzAsmState *as, const char *buf, ut64 offset, ut64 len, int bits,
	int bin, bool use_spp, bool rad, bool hexwords, const char *arch) {
	if (rad) {
		printf("e asm.arch=%s\n", arch ? arch : RZ_SYS_ARCH);
		printf("e asm.bits=%d\n", bits);
		if (offset) {
			printf("s 0x%" PFMT64x "\n", offset);
		}
		printf("wx ");
	}
	int ret = rasm_asm(as, (char *)buf, offset, len, as->a->bits, bin, use_spp, hexwords);
	if (rad) {
		printf("f entry @ $$\n");
		printf("f label.main @ $$ + 1\n");
		ht_ss_foreach(as->a->flags, print_label, NULL);
	}
	return ret;
}

static void __load_plugins(RzAsmState *as) {
	char *tmp = rz_sys_getenv("RZ_NOPLUGINS");
	if (tmp) {
		free(tmp);
		return;
	}
	rz_lib_add_handler(as->l, RZ_LIB_TYPE_ASM, "(dis)assembly plugins (deprecated)", &lib_asm_cb, NULL, as);
	rz_lib_add_handler(as->l, RZ_LIB_TYPE_ANALYSIS, "analysis/emulation plugins (deprecated)", &lib_analysis_cb, NULL, as);
	rz_lib_add_handler(as->l, RZ_LIB_TYPE_ARCH, "(dis)assembly/analysis/emulation plugins", &lib_arch_cb, NULL, as);

	char *path = rz_sys_getenv(RZ_LIB_ENV);
	if (!RZ_STR_ISEMPTY(path)) {
		rz_lib_opendir(as->l, path, false);
	}

	char *homeplugindir = rz_path_home_prefix(RZ_PLUGINS);
	char *sysplugindir = rz_path_system(RZ_PLUGINS);
	char *extraplugindir = rz_path_extra(RZ_PLUGINS);
	rz_lib_opendir(as->l, homeplugindir, false);
	rz_lib_opendir(as->l, sysplugindir, false);
	if (extraplugindir) {
		rz_lib_opendir(as->l, extraplugindir, false);
	}
	free(homeplugindir);
	free(sysplugindir);
	free(extraplugindir);

	free(tmp);
	free(path);
}

RZ_API int rz_main_rz_asm(int argc, const char *argv[]) {
	eprintf("* begin rz_main_rz_asm\n"); // DBG
	const char *env_arch = rz_sys_getenv("RZ_ASM_ARCH");
	const char *env_bits = rz_sys_getenv("RZ_ASM_BITS");
	const char *arch = NULL;
	const char *cpu = NULL;
	const char *kernel = NULL;
	const char *filters = NULL;
	const char *file = NULL;
	bool isbig = false;
	bool rad = false;
	bool use_spp = false;
	bool hexwords = false;
	ut64 offset = 0;
	int fd = -1, bin = 0, ret = 0, bits = 32, c, whatsop = 0;
	DisasmMode dis = DISASM_MODE_DONT;
	int help = 0;
	ut64 len = 0, idx = 0, skip = 0;
	bool analinfo = false;

	if (argc < 2) {
		return rasm_show_help(1);
	}

	RzAsmState *as = __as_new();

	// TODO set addrbytes
	char *rz_arch = rz_sys_getenv("RZ_ARCH");
	if (rz_arch) {
		arch = rz_arch;
	}

	char *rz_bits = rz_sys_getenv("RZ_BITS");
	if (rz_bits) {
		bits = rz_num_math(NULL, rz_bits);
		free(rz_bits);
	}

	RzGetopt opt;
	rz_getopt_init(&opt, argc, argv, "a:Ab:Bc:CdDeEIf:F:hi:jk:l:L@:o:O:pqrs:vwx");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'a':
			arch = opt.arg;
			break;
		case 'A':
			analinfo = true;
			break;
		case 'b':
			bits = rz_num_math(NULL, opt.arg);
			break;
		case 'B':
			bin = 1;
			break;
		case 'c':
			cpu = opt.arg;
			break;
		case 'C':
			as->coutput = true;
			break;
		case 'd':
			dis = DISASM_MODE_DEFAULT;
			break;
		case 'D':
			dis = DISASM_MODE_WITH_BYTES;
			break;
		case 'e':
			isbig = true;
			break;
		case 'E':
			dis = DISASM_MODE_ESIL;
			break;
		case 'I':
			dis = DISASM_MODE_IL;
			break;
		case 'f':
			file = opt.arg;
			break;
		case 'F':
			filters = opt.arg;
			break;
		case 'h':
			help++;
			// fallthrough
		case 'i':
			skip = rz_num_math(NULL, opt.arg);
			break;
		case 'j':
			as->json = true;
			break;
		case 'k':
			kernel = opt.arg;
			break;
		case 'l':
			len = rz_num_math(NULL, opt.arg);
			break;
		case 'L': {
			// create a dummy RzCore with the current RzAsm/RzAnalysis
			RzCore *core = rz_core_new();
			RzAsm *tmp_asm = core->rasm;
			RzAnalysis *tmp_analysis = core->analysis;
			core->rasm = as->a;
			core->analysis = as->analysis;
			RzCmdStateOutput state = { 0 };
			rz_cmd_state_output_init(&state, as->json ? RZ_OUTPUT_MODE_JSON : RZ_OUTPUT_MODE_STANDARD);
			rz_core_asm_plugins_print(core, opt.argv[opt.ind], &state);
			rz_cmd_state_output_print(&state);
			rz_cmd_state_output_fini(&state);
			rz_cons_flush();
			core->rasm = tmp_asm;
			core->analysis = tmp_analysis;
			rz_core_free(core);
			ret = 1;
			goto beach;
		}
		case '@':
		case 'o':
			offset = rz_num_math(NULL, opt.arg);
			break;
		case 'O':
			fd = open(opt.arg, O_TRUNC | O_RDWR | O_CREAT, 0644);
			if (fd != -1) {
				dup2(fd, 1);
			}
			break;
		case 'p':
			use_spp = true;
			break;
		case 'q':
			as->quiet = true;
			break;
		case 'r':
			rad = true;
			break;
		case 's':
			if (*opt.arg == '?') {
				printf("att\nintel\nmasm\njz\nregnum\n");
				__as_free(as);
				return 0;
			} else {
				int syntax = rz_asm_syntax_from_string(opt.arg);
				if (syntax == -1) {
					__as_free(as);
					return 1;
				}
				rz_asm_set_syntax(as->a, syntax);
			}
			break;
		case 'v':
			if (as->quiet) {
				printf("%s\n", RZ_VERSION);
			} else {
				ret = rz_main_version_print("rz-asm");
			}
			goto beach;
		case 'w':
			whatsop = true;
			break;
		case 'x':
			hexwords = true;
			break;
		default:
			ret = rasm_show_help(0);
			goto beach;
		}
	}

	if (help > 0) {
		ret = rasm_show_help(help > 1 ? 2 : 0);
		goto beach;
	}

	if (arch) {
		eprintf("** before rz_asm_use\n"); // DBG
		if (!rz_asm_use(as->a, arch)) {
			eprintf("rz-asm: Unknown asm plugin '%s'\n", arch);
			ret = 0;
			goto beach;
		}
		eprintf("** before rz_analysis_use\n"); // DBG
		rz_analysis_use(as->analysis, arch);
		eprintf("** after rz_analysis_use\n"); // DBG
	} else if (env_arch) {
		if (!rz_asm_use(as->a, env_arch)) {
			eprintf("rz-asm: Unknown asm plugin '%s'\n", env_arch);
			ret = 0;
			goto beach;
		}
	} else if (!rz_asm_use(as->a, "x86")) {
		eprintf("rz-asm: Cannot find asm.x86 plugin\n");
		ret = 0;
		goto beach;
	}
	rz_asm_set_cpu(as->a, cpu);
	rz_analysis_set_cpu(as->analysis, cpu);
	rz_asm_set_bits(as->a, (env_bits && *env_bits) ? atoi(env_bits) : bits);
	rz_analysis_set_bits(as->analysis, (env_bits && *env_bits) ? atoi(env_bits) : bits);
	as->a->syscall = rz_syscall_new();
	rz_syscall_setup(as->a->syscall, arch, bits, cpu, kernel);
	{
		bool canbebig = rz_asm_set_big_endian(as->a, isbig);
		if (isbig && !canbebig) {
			eprintf("Warning: This architecture can't swap to big endian.\n");
		}
		rz_analysis_set_big_endian(as->analysis, canbebig);
	}
	if (whatsop) {
		const char *s = rz_asm_describe(as->a, opt.argv[opt.ind]);
		ret = 1;
		if (s) {
			printf("%s\n", s);
			ret = 0;
		}
		goto beach;
	}
	if (filters) {
		char *p = strchr(filters, ':');
		if (p) {
			*p = 0;
			if (*filters) {
				rz_asm_sub_names_input(as->a, filters);
			}
			if (p[1]) {
				rz_asm_sub_names_output(as->a, p + 1);
			}
			*p = ':';
		} else {
			if (dis) {
				rz_asm_sub_names_output(as->a, filters);
			} else {
				rz_asm_sub_names_input(as->a, filters);
			}
		}
	}

	if (file) {
		char *content;
		size_t length = 0;
		if (!strcmp(file, "-")) {
			int sz = 0;
			ut8 *buf = (ut8 *)rz_stdin_slurp(&sz);
			if (!buf || sz < 1) {
				eprintf("Nothing to do.\n");
				goto beach;
			}
			len = (ut64)sz;
			if (dis) {
				if (skip && length > skip) {
					if (bin) {
						memmove(buf, buf + skip, length - skip);
						length -= skip;
					}
				}
				ret = rasm_disasm(as, offset, (char *)buf, len, as->a->bits, bin, dis);
			} else if (analinfo) {
				ret = show_analinfo(as, (const char *)buf, offset);
			} else {
				ret = print_assembly_output(as, (char *)buf, offset, len,
					as->a->bits, bin, use_spp, rad, hexwords, arch);
			}
			ret = !ret;
			free(buf);
		} else {
			content = rz_file_slurp(file, &length);
			if (content) {
				if (length > ST32_MAX) {
					eprintf("rz-asm: File %s is too big\n", file);
					ret = 1;
				} else {
					if (len && len > 0 && len < length) {
						length = len;
					}
					content[length] = '\0';
					if (skip && length > skip) {
						if (bin) {
							memmove(content, content + skip, length - skip);
							length -= skip;
						}
					}
					if (dis) {
						ret = rasm_disasm(as, offset, content,
							length, as->a->bits, bin, dis);
					} else if (analinfo) {
						ret = show_analinfo(as, (const char *)content, offset);
					} else {
						ret = print_assembly_output(as, content, offset, length,
							as->a->bits, bin, use_spp, rad, hexwords, arch);
					}
					ret = !ret;
				}
				free(content);
			} else {
				eprintf("rz-asm: Cannot open file %s\n", file);
				ret = 1;
			}
		}
	} else if (opt.argv[opt.ind]) {
		if (!strcmp(opt.argv[opt.ind], "-")) {
			int length;
			do {
				char buf[1024]; // TODO: use(implement) rz_stdin_line() or so
				length = read(0, buf, sizeof(buf) - 1);
				if (length < 1) {
					break;
				}
				if (len > 0 && len < length) {
					length = len;
				}
				buf[length] = 0;
				if ((!bin || !dis) && feof(stdin)) {
					break;
				}
				if (skip && length > skip) {
					if (bin) {
						memmove(buf, buf + skip, length - skip + 1);
						length -= skip;
					}
				}
				if (!bin || !dis) {
					int buflen = strlen((const char *)buf);
					if (buf[buflen] == '\n') {
						buf[buflen - 1] = '\0';
					}
				}
				if (dis) {
					ret = rasm_disasm(as, offset, (char *)buf, length, as->a->bits, bin, dis);
				} else if (analinfo) {
					ret = show_analinfo(as, (const char *)buf, offset);
				} else {
					ret = rasm_asm(as, (const char *)buf, offset, length, as->a->bits, bin, use_spp, hexwords);
				}
				idx += ret;
				offset += ret;
				if (!ret) {
					goto beach;
				}
			} while (!len || idx < length);
			ret = idx;
			goto beach;
		}
		if (dis) {
			char *usrstr = rz_str_dup(opt.argv[opt.ind]);
			if (!usrstr) {
				eprintf("rz-asm: disassemble rz_str_dup OOM\n");
				ret = 1;
				goto beach;
			}
			len = strlen(usrstr);
			if (skip && len > skip) {
				skip *= 2;
				// eprintf ("SKIP (%s) (%lld)\n", usrstr, skip);
				memmove(usrstr, usrstr + skip, len - skip);
				len -= skip;
				usrstr[len] = 0;
			}
			// XXX this is a wrong usage of endianness
			if (!strncmp(usrstr, "0x", 2)) {
				memmove(usrstr, usrstr + 2, strlen(usrstr + 2) + 1);
			}
			if (rad) {
				as->oneliner = true;
				printf("e asm.arch=%s\n", arch ? arch : RZ_SYS_ARCH);
				printf("e asm.bits=%d\n", bits);
				printf("\"wa ");
			}
			eprintf("** before rasm_disasm\n"); // DBG
			ret = rasm_disasm(as, offset, (char *)usrstr, len, as->a->bits, bin, dis);
			eprintf("** after rasm_disasm\n"); // DBG
			free(usrstr);
		} else if (analinfo) {
			ret = show_analinfo(as, (const char *)opt.argv[opt.ind], offset);
		} else {
			eprintf("** before print_assembly_output\n"); // DBG
			ret = print_assembly_output(as, opt.argv[opt.ind], offset, len, as->a->bits,
				bin, use_spp, rad, hexwords, arch);
			eprintf("** after print_assembly_output\n"); // DBG
		}
		ret = !ret;
	}
beach:
	__as_free(as);

	free(rz_arch);
	if (fd != -1) {
		close(fd);
	}
	eprintf("* end rz_main_rz_asm\n"); // DBG
	return ret;
}
