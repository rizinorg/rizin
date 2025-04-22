// SPDX-FileCopyrightText: 2011-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_egg.h>

// compilation environment
struct cEnv_t {
	char *SFLIBPATH;
	char *CC;
	const char *OBJCOPY;
	char *CFLAGS;
	char *LDFLAGS;
	const char *JMP;
	const char *FMT;
	char *SHDR;
	char *TRIPLET;
	const char *TEXT;
};

static char *rz_egg_Cfile_getCompiler(void) {
	size_t i;
	const char *compilers[] = { "llvm-gcc", "clang", "gcc" };
	char *output = rz_sys_getenv("CC");

	if (output) {
		return output;
	}

	for (i = 0; i < 3; i++) {
		output = rz_file_path(compilers[i]);
		if (strcmp(output, compilers[i])) {
			free(output);
			return rz_str_dup(compilers[i]);
		}
		free(output);
	}

	eprintf("Couldn't find a compiler ! Please, set CC.\n");
	return NULL;
}

static inline bool rz_egg_Cfile_armOrMips(const char *arch) {
	return (!strcmp(arch, "arm") || !strcmp(arch, "arm64") || !strcmp(arch, "aarch64") || !strcmp(arch, "thumb") || !strcmp(arch, "arm32") || !strcmp(arch, "mips") || !strcmp(arch, "mips32") || !strcmp(arch, "mips64"));
}

static void rz_egg_Cfile_free_cEnv(struct cEnv_t *cEnv) {
	if (cEnv) {
		free(cEnv->SFLIBPATH);
		free(cEnv->CC);
		free(cEnv->CFLAGS);
		free(cEnv->LDFLAGS);
		free(cEnv->SHDR);
		free(cEnv->TRIPLET);
	}
	free(cEnv);
}

static inline bool rz_egg_Cfile_check_cEnv(struct cEnv_t *cEnv) {
	return (!cEnv->SFLIBPATH || !cEnv->CC || !cEnv->CFLAGS || !cEnv->LDFLAGS || !cEnv->SHDR || !cEnv->TRIPLET);
}

static inline bool isXNU(const char *os) {
	return (!strcmp(os, "darwin") || !strcmp(os, "macos") || !strcmp(os, "tvos") || !strcmp(os, "watchos") || !strcmp(os, "ios"));
}

static struct cEnv_t *rz_egg_Cfile_set_cEnv(const char *arch, const char *os, int bits) {
	struct cEnv_t *cEnv = calloc(1, sizeof(struct cEnv_t));
	bool use_clang;
	char *buffer = NULL;
	char *incdir = NULL;

	if (!cEnv) {
		return NULL;
	}

	if (!(cEnv->CC = rz_egg_Cfile_getCompiler())) {
		goto fail;
	}

	cEnv->SFLIBPATH = rz_sys_getenv("SFLIBPATH");
	if (!cEnv->SFLIBPATH) {
		incdir = rz_path_incdir();

		if (!(cEnv->SFLIBPATH = rz_str_newf("%s/sflib", incdir))) {
			goto fail;
		}
	}

	cEnv->JMP = rz_egg_Cfile_armOrMips(arch) ? "b" : "jmp";

	// TODO: Missing -Os .. caused some rip-relative LEA to be MOVQ on PIE in CLANG.. so sad
	if (isXNU(os)) {
		cEnv->OBJCOPY = "gobjcopy";
		cEnv->FMT = "mach0";
		if (!strcmp(arch, "x86")) {
			if (bits == 32) {
				cEnv->CFLAGS = rz_str_dup("-arch i386 -fPIC -fPIE");
				cEnv->LDFLAGS = rz_str_dup("-arch i386 -shared -c -fPIC -fPIE -pie");
			} else {
				cEnv->CFLAGS = rz_str_dup("-arch x86_64 -fPIC -fPIE");
				cEnv->LDFLAGS = rz_str_dup("-arch x86_64 -shared -c -fPIC -fPIE -pie");
			}
		} else {
			cEnv->CFLAGS = rz_str_dup("-shared -c -fPIC -pie -fPIE");
			cEnv->LDFLAGS = rz_str_dup("-shared -c -fPIC -pie -fPIE");
		}
		cEnv->SHDR = rz_str_newf("\n.text\n%s _main\n", cEnv->JMP);
	} else {
		cEnv->OBJCOPY = "objcopy";
		cEnv->FMT = "elf";
		cEnv->SHDR = rz_str_newf("\n.section .text\n.globl  main\n"
					 "// .type   main, @function\n%s main\n",
			cEnv->JMP);
		if (!strcmp(arch, "x86")) {
			if (bits == 32) {
				cEnv->CFLAGS = rz_str_dup("-fPIC -fPIE -pie -fpic -m32");
				cEnv->LDFLAGS = rz_str_dup("-fPIC -fPIE -pie -fpic -m32");
			} else {
				cEnv->CFLAGS = rz_str_dup("-fPIC -fPIE -pie -fpic -m64");
				cEnv->LDFLAGS = rz_str_dup("-fPIC -fPIE -pie -fpic -m64");
			}
		} else {
			cEnv->CFLAGS = rz_str_dup("-fPIC -fPIE -pie -fpic -nostartfiles");
			cEnv->LDFLAGS = rz_str_dup("-fPIC -fPIE -pie -fpic -nostartfiles");
		}
	}

	cEnv->TRIPLET = rz_str_newf("%s-%s-%d", os, arch, bits);

	if (!strcmp(os, "windows")) {
		cEnv->TEXT = ".text";
		cEnv->FMT = "pe";
	} else if (isXNU(os)) {
		// cEnv->TEXT = "0.__TEXT.__text";
		cEnv->TEXT = "0..__text";
	} else {
		cEnv->TEXT = ".text";
	}

	use_clang = false;
	if (!strcmp(cEnv->TRIPLET, "darwin-arm-64")) {
		free(cEnv->CC);
		cEnv->CC = rz_str_dup("xcrun --sdk iphoneos gcc -arch arm64 -miphoneos-version-min=0.0");
		use_clang = true;
		cEnv->TEXT = "0.__TEXT.__text";
	} else if (!strcmp(cEnv->TRIPLET, "darwin-arm-32")) {
		free(cEnv->CC);
		cEnv->CC = rz_str_dup("xcrun --sdk iphoneos gcc -arch armv7 -miphoneos-version-min=0.0");
		use_clang = true;
		cEnv->TEXT = "0.__TEXT.__text";
	}

	buffer = rz_str_newf("%s -fno-stack-protector -nostdinc -include '%s'/'%s'/sflib.h",
		cEnv->CFLAGS, cEnv->SFLIBPATH, cEnv->TRIPLET);
	if (!buffer) {
		goto fail;
	}
	free(cEnv->CFLAGS);
	cEnv->CFLAGS = rz_str_dup(buffer);

	if (use_clang) {
		free(buffer);
		buffer = rz_str_newf("%s -fomit-frame-pointer"
				     " -fno-zero-initialized-in-bss",
			cEnv->CFLAGS);
		if (!buffer) {
			goto fail;
		}
		free(cEnv->CFLAGS);
		cEnv->CFLAGS = rz_str_dup(buffer);
	} else {
		free(buffer);
		buffer = rz_str_newf("%s -z execstack -fomit-frame-pointer"
				     " -finline-functions -fno-zero-initialized-in-bss",
			cEnv->CFLAGS);
		if (!buffer) {
			goto fail;
		}
		free(cEnv->CFLAGS);
		cEnv->CFLAGS = rz_str_dup(buffer);
	}
	free(buffer);
	buffer = rz_str_newf("%s -nostdlib", cEnv->LDFLAGS);
	if (!buffer) {
		goto fail;
	}
	free(cEnv->LDFLAGS);
	cEnv->LDFLAGS = rz_str_dup(buffer);

	if (rz_egg_Cfile_check_cEnv(cEnv)) {
		eprintf("Error with cEnv allocation!\n");
		goto fail;
	}

	free(buffer);
	free(incdir);
	return cEnv;

fail:
	free(buffer);
	free(incdir);
	rz_egg_Cfile_free_cEnv(cEnv);
	return NULL;
}

static bool rz_egg_Cfile_parseCompiled(const char *file) {
	char *fileExt = rz_str_newf("%s.tmp", file);
	char *buffer = rz_file_slurp(fileExt, NULL);
	if (!buffer) {
		eprintf("Could not open '%s'.\n", fileExt);
		goto fail;
	}

	buffer = rz_str_replace(buffer, "rdata", "text", false);
	buffer = rz_str_replace(buffer, "rodata", "text", false);
	buffer = rz_str_replace(buffer, "get_pc_thunk.bx", "__getesp__", true);

	const char *words[] = { ".cstring", "size", "___main", "section", "__alloca", "zero", "cfi" };
	size_t i;
	for (i = 0; i < 7; i++) {
		rz_str_stripLine(buffer, words[i]);
	}

	free(fileExt);
	fileExt = rz_str_newf("%s.s", file);
	if (!rz_file_dump(fileExt, (const ut8 *)buffer, strlen(buffer), true)) {
		eprintf("Error while opening %s.s\n", file);
		goto fail;
	}

	free(buffer);
	free(fileExt);
	return true;

fail:
	free(buffer);
	free(fileExt);
	return false;
}

RZ_API char *rz_egg_Cfile_parser(const char *file, const char *arch, const char *os, int bits) {
	char *output = NULL;
	char *fileExt = NULL; // "file" with extension (.s, .text, ...)
	struct cEnv_t *cEnv = rz_egg_Cfile_set_cEnv(arch, os, bits);

	if (!cEnv) {
		goto fail;
	}

	rz_str_sanitize(cEnv->CC);

	// Compile
	char *cmd = rz_str_newf("'%s' %s -o '%s.tmp' -S '%s'\n", cEnv->CC, cEnv->CFLAGS, file, file);
	eprintf("%s\n", cmd);
	int rc = rz_sys_system(cmd);
	free(cmd);
	if (rc != 0) {
		goto fail;
	}
	if (!(fileExt = rz_str_newf("%s.s", file))) {
		goto fail;
	}

	if (!rz_file_dump(fileExt, (const ut8 *)cEnv->SHDR, strlen(cEnv->SHDR), false)) {
		eprintf("Error while opening %s.s\n", file);
		goto fail;
	}

	if (!rz_egg_Cfile_parseCompiled(file)) {
		goto fail;
	}
	// Assemble
	cmd = rz_str_newf("'%s' %s -o '%s.o' '%s.s'", cEnv->CC, cEnv->LDFLAGS, file, file);
	eprintf("%s\n", cmd);
	rc = rz_sys_system(cmd);
	free(cmd);
	if (rc != 0) {
		goto fail;
	}

	// Link
	printf("rz-bin -o '%s.text' -O d/S/'%s' '%s.o'\n", file, cEnv->TEXT, file);
	output = rz_sys_cmd_strf("rz-bin -o '%s.text' -O d/S/'%s' '%s'.o",
		file, cEnv->TEXT, file);
	if (!output) {
		eprintf("Linkage failed!\n");
		goto fail;
	}

	free(fileExt);
	if (!(fileExt = rz_str_newf("%s.o", file))) {
		goto fail;
	}

	if (!rz_file_exists(fileExt)) {
		eprintf("Cannot find %s.o\n", file);
		goto fail;
	}

	free(fileExt);
	if (!(fileExt = rz_str_newf("%s.text", file))) {
		goto fail;
	}
	if (rz_file_size(fileExt) == 0) {
		eprintf("FALLBACK: Using objcopy instead of rz_bin");
		free(output);
		output = rz_sys_cmd_strf("'%s' -j .text -O binary '%s.o' '%s.text'",
			cEnv->OBJCOPY, file, file);
		if (!output) {
			eprintf("objcopy failed!\n");
			goto fail;
		}
	}

	size_t i;
	const char *extArray[] = { "bin", "tmp", "s", "o" };
	for (i = 0; i < 4; i++) {
		free(fileExt);
		if (!(fileExt = rz_str_newf("%s.%s", file, extArray[i]))) {
			goto fail;
		}
		rz_file_rm(fileExt);
	}

	free(fileExt);
	if ((fileExt = rz_str_newf("%s.text", file)) == NULL) {
		goto fail;
	}

	free(output);
	rz_egg_Cfile_free_cEnv(cEnv);
	return fileExt;

fail:
	free(fileExt);
	free(output);
	rz_egg_Cfile_free_cEnv(cEnv);
	return NULL;
}
