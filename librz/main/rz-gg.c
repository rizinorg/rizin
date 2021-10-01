// SPDX-FileCopyrightText: 2011-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_egg.h>
#include <rz_bin.h>
#include <rz_main.h>
#include <rz_util/rz_print.h>
#include <rz_util.h>

static int usage(int v) {
	printf("Usage: rz-gg [-FOLsrxhvz] [-a arch] [-b bits] [-k os] [-o file] [-I path]\n"
	       "             [-i sc] [-e enc] [-B hex] [-c k=v] [-C file] [-p pad] [-q off]\n"
	       "             [-S string] [-f fmt] [-nN dword] [-dDw off:hex] file|f.asm|-\n");
	if (v) {
		printf(
			" -a [arch]       select architecture (x86, mips, arm)\n"
			" -b [bits]       register size (32, 64, ..)\n"
			" -B [hexpairs]   append some hexpair bytes\n"
			" -c [k=v]        set configuration options\n"
			" -C [file]       append contents of file\n"
			" -d [off:dword]  patch dword (4 bytes) at given offset\n"
			" -D [off:qword]  patch qword (8 bytes) at given offset\n"
			" -e [encoder]    use specific encoder. see -L\n"
			" -f [format]     output format (raw, c, pe, elf, mach0, python, javascript)\n"
			" -F              output native format (osx=mach0, linux=elf, ..)\n"
			" -h              show this help\n"
			" -i [shellcode]  include shellcode plugin, uses options. see -L\n"
			" -I [path]       add include path\n"
			" -k [os]         operating system's kernel (linux,bsd,osx,w32)\n"
			" -L              list all plugins (shellcodes and encoders)\n"
			" -n [dword]      append 32bit number (4 bytes)\n"
			" -N [dword]      append 64bit number (8 bytes)\n"
			" -o [file]       output file\n"
			" -O              use default output file (filename without extension or a.out)\n"
			" -p [padding]    add padding after compilation (padding=n10s32)\n"
			"                 ntas : begin nop, trap, 'a', sequence\n"
			"                 NTAS : same as above, but at the end\n"
			" -P [size]       prepend debruijn pattern\n"
			" -q [fragment]   debruijn pattern offset\n"
			" -r              show raw bytes instead of hexpairs\n"
			" -s              show assembler\n"
			" -S [string]     append a string\n"
			" -v              show version\n"
			" -w [off:hex]    patch hexpairs at given offset\n"
			" -x              execute\n"
			" -X [hexpairs]   execute rop chain, using the stack provided\n"
			" -z              output in C string syntax\n");
	}
	return 1;
}

static void list(RzEgg *egg) {
	RzListIter *iter;
	RzEggPlugin *p;
	printf("shellcodes:\n");
	rz_list_foreach (egg->plugins, iter, p) {
		if (p->type == RZ_EGG_PLUGIN_SHELLCODE) {
			printf("%10s : %s\n", p->name, p->desc);
		}
	}
	printf("encoders:\n");
	rz_list_foreach (egg->plugins, iter, p) {
		if (p->type == RZ_EGG_PLUGIN_ENCODER) {
			printf("%10s : %s\n", p->name, p->desc);
		}
	}
}

static int create(const char *format, const char *arch, int bits, const ut8 *code, int codelen) {
	RzBin *bin = rz_bin_new();
	RzBinArchOptions opts;
	RzBuffer *b;
	rz_bin_arch_options_init(&opts, arch, bits);
	b = rz_bin_create(bin, format, code, codelen, NULL, 0, &opts);
	if (b) {
		ut64 blen;
		const ut8 *tmp = rz_buf_data(b, &blen);
		if (write(1, tmp, blen) != blen) {
			eprintf("Failed to write buffer\n");
		}
		rz_buf_free(b);
	} else {
		eprintf("Cannot create binary for this format '%s'.\n", format);
	}
	rz_bin_free(bin);
	return 0;
}

static int openfile(const char *f, int x) {
	int fd = open(f, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		fd = open(f, O_RDWR);
		if (fd == -1) {
			return -1;
		}
	}
#if __UNIX__
	if (x) {
		fchmod(fd, 0755);
	}
#endif
#if _MSC_VER
	int r = _chsize(fd, 0);
#else
	int r = ftruncate(fd, 0);
#endif
	if (r != 0) {
		eprintf("Could not resize\n");
	}
	close(1);
	dup2(fd, 1);
	return fd;
}
#define ISEXEC (fmt != 'r')

RZ_API int rz_main_rz_gg(int argc, const char **argv) {
	const char *file = NULL;
	const char *padding = NULL;
	const char *pattern = NULL;
	const char *str = NULL;
	char *bytes = NULL;
	const char *contents = NULL;
	const char *arch = RZ_SYS_ARCH;
	const char *os = RZ_EGG_OS_NAME;
	const char *format = "raw";
	bool show_execute = false;
	bool show_execute_rop = false;
	int show_hex = 1;
	int show_asm = 0;
	int show_raw = 0;
	int append = 0;
	int show_str = 0;
	ut64 get_offset = 0;
	const char *shellcode = NULL;
	const char *encoder = NULL;
	char *sequence = NULL;
	int bits = (RZ_SYS_BITS & RZ_SYS_BITS_64) ? 64 : 32;
	int fmt = 0;
	const char *ofile = NULL;
	int ofileauto = 0;
	RzBuffer *b;
	int c, i, fd = -1;
	RzEgg *egg = rz_egg_new();

	RzGetopt opt;
	rz_getopt_init(&opt, argc, argv, "n:N:he:a:b:f:o:sxXrk:FOI:Li:c:p:P:B:C:vd:D:w:zq:S:");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'a':
			arch = opt.arg;
			if (!strcmp(arch, "trace")) {
				show_asm = 1;
				show_hex = 0;
			}
			break;
		case 'e':
			encoder = opt.arg;
			break;
		case 'b':
			bits = atoi(opt.arg);
			break;
		case 'B':
			bytes = rz_str_append(bytes, opt.arg);
			break;
		case 'C':
			if (RZ_STR_ISEMPTY(opt.arg)) {
				eprintf("Cannot open empty contents path\n");
				free(sequence);
				rz_egg_free(egg);
				return 1;
			}
			contents = opt.arg;
			break;
		case 'w': {
			char *arg = strdup(opt.arg);
			char *p = strchr(arg, ':');
			if (p) {
				int len, off;
				ut8 *b;
				*p++ = 0;
				off = rz_num_math(NULL, arg);
				b = malloc(strlen(opt.arg) + 1);
				len = rz_hex_str2bin(p, b);
				if (len > 0) {
					rz_egg_patch(egg, off, (const ut8 *)b, len);
				} else {
					eprintf("Invalid hexstr for -w\n");
				}
				free(b);
			} else {
				eprintf("Missing colon in -w\n");
			}
			free(arg);
		} break;
		case 'n': {
			ut32 n = rz_num_math(NULL, opt.arg);
			append = 1;
			rz_egg_patch(egg, -1, (const ut8 *)&n, 4);
		} break;
		case 'N': {
			ut64 n = rz_num_math(NULL, opt.arg);
			rz_egg_patch(egg, -1, (const ut8 *)&n, 8);
			append = 1;
		} break;
		case 'd': {
			ut32 off, n;
			char *p = strchr(opt.arg, ':');
			if (p) {
				*p = 0;
				off = rz_num_math(NULL, opt.arg);
				n = rz_num_math(NULL, p + 1);
				*p = ':';
				// TODO: honor endianness here
				rz_egg_patch(egg, off, (const ut8 *)&n, 4);
			} else {
				eprintf("Missing colon in -d\n");
			}
		} break;
		case 'D': {
			char *p = strchr(opt.arg, ':');
			if (p) {
				ut64 n, off = rz_num_math(NULL, opt.arg);
				n = rz_num_math(NULL, p + 1);
				// TODO: honor endianness here
				rz_egg_patch(egg, off, (const ut8 *)&n, 8);
			} else {
				eprintf("Missing colon in -d\n");
			}
		} break;
		case 'S':
			str = opt.arg;
			break;
		case 'o':
			ofile = opt.arg;
			break;
		case 'O':
			ofileauto = 1;
			break;
		case 'I':
			if (RZ_STR_ISEMPTY(opt.arg)) {
				eprintf("Cannot open empty include path\n");
				free(sequence);
				rz_egg_free(egg);
				return 1;
			}
			rz_egg_lang_include_path(egg, opt.arg);
			break;
		case 'i':
			shellcode = opt.arg;
			break;
		case 'p':
			padding = opt.arg;
			break;
		case 'P':
			pattern = opt.arg;
			break;
		case 'c': {
			char *p = strchr(opt.arg, '=');
			if (p) {
				*p++ = 0;
				rz_egg_option_set(egg, opt.arg, p);
			} else {
				rz_egg_option_set(egg, opt.arg, "true");
			}
		} break;
		case 'F':
#if __APPLE__
			format = "mach0";
#elif __WINDOWS__
			format = "pe";
#else
			format = "elf";
#endif
			show_asm = 0;
			break;
		case 'f':
			format = opt.arg;
			show_asm = 0;
			break;
		case 's':
			show_asm = 1;
			show_hex = 0;
			break;
		case 'k':
			os = opt.arg;
			break;
		case 'r':
			show_raw = 1;
			break;
		case 'x':
			// execute
			show_execute = true;
			break;
		case 'X':
			// execute rop chain
			show_execute = 1;
			show_execute_rop = 1;
			break;
		case 'L':
			list(egg);
			rz_egg_free(egg);
			free(sequence);
			return 0;
		case 'h':
			rz_egg_free(egg);
			free(sequence);
			return usage(1);
		case 'v':
			free(sequence);
			rz_egg_free(egg);
			return rz_main_version_print("rz-gg");
		case 'z':
			show_str = 1;
			break;
		case 'q':
			get_offset = 1;
			sequence = strdup(opt.arg);
			break;
		default:
			free(sequence);
			rz_egg_free(egg);
			return 1;
		}
	}

	if (opt.ind == argc && !shellcode && !bytes && !contents && !encoder && !padding && !pattern && !append && !get_offset && !str) {
		free(sequence);
		rz_egg_free(egg);
		return usage(0);
	} else {
		file = argv[opt.ind];
	}

	if (bits == 64) {
		if (!strcmp(format, "mach0")) {
			format = "mach064";
		} else if (!strcmp(format, "elf")) {
			format = "elf64";
		}
	}

	// catch this first
	if (get_offset) {
		if (strncmp(sequence, "0x", 2)) {
			eprintf("Need hex value with `0x' prefix e.g. 0x41414142\n");
			free(sequence);
			rz_egg_free(egg);
			return 1;
		}

		get_offset = rz_num_math(0, sequence);
		printf("Little endian: %d\n", rz_debruijn_offset(get_offset, false));
		printf("Big endian: %d\n", rz_debruijn_offset(get_offset, true));
		free(sequence);
		rz_egg_free(egg);
		return 0;
	}

	// initialize egg
	rz_egg_setup(egg, arch, bits, 0, os);
	if (file) {
		if (RZ_STR_ISEMPTY(file)) {
			eprintf("Cannot open empty path\n");
			goto fail;
		}
		if (!strcmp(file, "-")) {
			char buf[1024];
			for (;;) {
				if (!fgets(buf, sizeof(buf), stdin)) {
					break;
				}
				if (feof(stdin)) {
					break;
				}
				rz_egg_load(egg, buf, 0);
			}
		} else if (strstr(file, ".c")) {
			char *fileSanitized = strdup(file);
			rz_str_sanitize(fileSanitized);
			char *textFile = rz_egg_Cfile_parser(fileSanitized, arch, os, bits);

			if (!textFile) {
				eprintf("Failure while parsing '%s'\n", fileSanitized);
				goto fail;
			}

			size_t l;
			char *buf = rz_file_slurp(textFile, &l);
			if (buf && l > 0) {
				rz_egg_raw(egg, (const ut8 *)buf, (int)l);
			} else {
				eprintf("Error loading '%s'\n", textFile);
			}

			rz_file_rm(textFile);
			free(fileSanitized);
			free(textFile);
			free(buf);
		} else {
			if (strstr(file, ".s") || strstr(file, ".asm")) {
				fmt = 'a';
			} else {
				fmt = 0;
			}
			if (!rz_egg_include(egg, file, fmt)) {
				eprintf("Cannot open '%s'\n", file);
				goto fail;
			}
		}
	}

	// compile source code to assembly
	if (!rz_egg_compile(egg)) {
		if (!fmt) {
			eprintf("rz_egg_compile: fail\n");
			free(sequence);
			rz_egg_free(egg);
			return 1;
		}
	}

	// append the provided string
	if (str) {
		int l = strlen(str);
		if (l > 0) {
			rz_egg_raw(egg, (const ut8 *)str, l);
		}
	}

	// add raw file
	if (contents) {
		size_t l;
		char *buf = rz_file_slurp(contents, &l);
		if (buf && l > 0) {
			rz_egg_raw(egg, (const ut8 *)buf, (int)l);
		} else {
			eprintf("Error loading '%s'\n", contents);
		}
		free(buf);
	}

	// add shellcode
	if (shellcode) {
		if (!rz_egg_shellcode(egg, shellcode)) {
			eprintf("Unknown shellcode '%s'\n", shellcode);
			goto fail;
		}
	}

	// add raw bytes
	if (bytes) {
		ut8 *b = malloc(strlen(bytes) + 1);
		int len = rz_hex_str2bin(bytes, b);
		if (len > 0) {
			if (!rz_egg_raw(egg, b, len)) {
				eprintf("Unknown '%s'\n", shellcode);
				free(b);
				goto fail;
			}
		} else {
			eprintf("Invalid hexpair string for -B\n");
		}
		free(b);
		free(bytes);
		bytes = NULL;
	}

	/* set output (create output file if needed) */
	if (ofileauto) {
		if (file) {
			char *o, *q, *p = strdup(file);
			if ((o = strchr(p, '.'))) {
				while ((q = strchr(o + 1, '.'))) {
					o = q;
				}
				*o = 0;
				fd = openfile(p, ISEXEC);
			} else {
				fd = openfile("a.out", ISEXEC);
			}
			free(p);
		} else {
			fd = openfile("a.out", ISEXEC);
		}
		if (fd == -1) {
			eprintf("cannot open file '%s'\n", opt.arg);
			goto fail;
		}
		close(fd);
	}
	if (ofile) {
		fd = openfile(ofile, ISEXEC);
		if (fd == -1) {
			eprintf("cannot open file '%s'\n", ofile);
			goto fail;
		}
	}

	// assemble to binary
	if (!rz_egg_assemble(egg)) {
		eprintf("rz_egg_assemble: invalid assembly\n");
		goto fail;
	}
	if (encoder) {
		if (!rz_egg_encode(egg, encoder)) {
			eprintf("Invalid encoder '%s'\n", encoder);
			goto fail;
		}
	}

	// add padding
	if (padding) {
		rz_egg_padding(egg, padding);
	}

	// add pattern
	if (pattern) {
		rz_egg_pattern(egg, rz_num_math(NULL, pattern));
	}

	// apply patches
	if (!egg->bin) {
		egg->bin = rz_buf_new_with_bytes(NULL, 0);
	}
	if (!rz_egg_get_bin(egg)) {
		eprintf("rz_egg_get_bin: invalid egg :(\n");
		goto fail;
	}
	rz_egg_finalize(egg);

	if (show_asm) {
		printf("%s\n", rz_egg_get_assembly(egg));
	}

	if (show_raw || show_hex || show_execute) {
		if (show_execute) {
			int r;
			if (show_execute_rop) {
				r = rz_egg_run_rop(egg);
			} else {
				r = rz_egg_run(egg);
			}
			rz_egg_free(egg);
			return r;
		}
		b = rz_egg_get_bin(egg);
		if (show_raw) {
			ut64 blen;
			const ut8 *tmp = rz_buf_data(b, &blen);
			if (write(1, tmp, blen) != blen) {
				eprintf("Failed to write buffer\n");
				goto fail;
			}
		} else {
			if (!format) {
				eprintf("No format specified\n");
				goto fail;
			}
			RzPrint *p = rz_print_new();
			ut64 tmpsz;
			const ut8 *tmp = rz_buf_data(b, &tmpsz);
			switch (*format) {
			case 'c':
				rz_print_code(p, 0, tmp, tmpsz, 'c');
				break;
			case 'j': // JavaScript
				rz_print_code(p, 0, tmp, tmpsz, 'j');
				break;
			case 'r':
				if (show_str) {
					printf("\"");
					for (i = 0; i < tmpsz; i++) {
						printf("\\x%02x", tmp[i]);
					}
					printf("\"\n");
				} else if (show_hex) {
					rz_buf_seek(b, 0, RZ_BUF_SET);
					for (i = 0; i < tmpsz; i++) {
						printf("%02x", tmp[i]);
					}
					printf("\n");
				} // else show_raw is_above()
				break;
			case 'p': // PE
				if (strlen(format) >= 2 && format[1] == 'y') { // Python
					rz_print_code(p, 0, tmp, tmpsz, 'p');
				}
				break;
			case 'e': // ELF
			case 'm': // MACH0
				create(format, arch, bits, tmp, tmpsz);
				break;
			default:
				eprintf("unknown executable format (%s)\n", format);
				goto fail;
			}
			rz_print_free(p);
		}
	}
	if (fd != -1) {
		close(fd);
	}
	free(sequence);
	rz_egg_free(egg);
	return 0;
fail:
	if (fd != -1) {
		close(fd);
	}
	free(sequence);
	rz_egg_free(egg);
	return 1;
}
