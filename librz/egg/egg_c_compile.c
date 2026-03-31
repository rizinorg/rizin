// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_egg.h>

typedef struct egg_c_config {
	const char *triplet; ///< <os>-<arch>-<bits>
	const char *exe_compiler; ///< special compiler to override the normal one.
	const char *add_cflags; ///< CFLAGS to append
	const char *add_ldflags; ///< LDFLAGS to append
	const char *asm_text_segment; ///< hardcoded `.text` segment name to use for dumping the compiled code.
	const char *asm_text_header; ///< hardcoded header of the assembly.
} egg_c_config_t;

// compilation environment
typedef struct c_env_s {
	const char *asm_text_segment; ///< hardcoded `.text` segment name to use for dumping the compiled code.
	const char *asm_text_header; ///< hardcoded header of the assembly.
	char *exe_objcopy; ///< objcopy exec
	char *exe_compiler; ///< compiler exec
	char *cflags; ///< compiler CFLAGS
	char *ldflags; ///< compiler LDFLAGS
} c_env_t;

const egg_c_config_t c_configs[] = {
	{
		/* triplet          */ "ios-arm-32",
		/* exe_compiler     */ "xcrun --sdk iphoneos gcc -arch armv7 -miphoneos-version-min=0.0",
		/* add_cflags       */ "-shared -c -pie -fomit-frame-pointer -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-shared -c -pie",
		/* asm_text_segment */ "0.__TEXT.__text",
		/* asm_text_header  */ "\n"
				       ".text\n"
				       "b _main\n",
	},
	{
		/* triplet          */ "ios-arm-64",
		/* exe_compiler     */ "xcrun --sdk iphoneos gcc -arch arm64 -miphoneos-version-min=0.0",
		/* add_cflags       */ "-shared -c -pie -fomit-frame-pointer -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-shared -c -pie",
		/* asm_text_segment */ "0.__TEXT.__text",
		/* asm_text_header  */ "\n"
				       ".text\n"
				       "b _main\n",
	},
	{
		/* triplet          */ "darwin-arm-64",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-O1 -fomit-frame-pointer -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-shared -c -pie",
		/* asm_text_segment */ "0..__text",
		/* asm_text_header  */ "\n"
				       ".text\n"
				       "b _main\n",
	},
	{
		/* triplet          */ "darwin-x86-32",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-arch i386 -fomit-frame-pointer -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-arch i386 -shared -c -pie",
		/* asm_text_segment */ "0..__text",
		/* asm_text_header  */ "\n"
				       ".text\n"
				       "jmp _main\n",
	},
	{
		/* triplet          */ "darwin-x86-64",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-arch x86_64 -fomit-frame-pointer -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-arch x86_64 -shared -c -pie",
		/* asm_text_segment */ "0..__text",
		/* asm_text_header  */ "\n"
				       ".text\n"
				       "jmp _main\n",
	},
	{
		/* triplet          */ "linux-arm-32",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-pie -fpic -nostartfiles -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-pie -fpic -nostartfiles",
		/* asm_text_segment */ ".text",
		/* asm_text_header  */ "\n"
				       ".section .text\n"
				       ".globl  main\n"
				       "b main\n",
	},
	{
		/* triplet          */ "linux-arm-64",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-pie -fpic -nostartfiles -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-pie -fpic -nostartfiles",
		/* asm_text_segment */ ".text",
		/* asm_text_header  */ "\n"
				       ".section .text\n"
				       ".globl  main\n"
				       "b main\n",
	},
	{
		/* triplet          */ "linux-x86-32",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-pie -fpic -m32 -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-pie -fpic -m32",
		/* asm_text_segment */ ".text",
		/* asm_text_header  */ "\n"
				       ".section .text\n"
				       ".globl  main\n"
				       "jmp main\n",
	},
	{
		/* triplet          */ "linux-x86-64",
		/* exe_compiler     */ NULL,
		/* add_cflags       */ "-pie -fpic -m64 -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss",
		/* add_ldflags      */ "-pie -fpic -m64",
		/* asm_text_segment */ ".text",
		/* asm_text_header  */ "\n"
				       ".section .text\n"
				       ".globl  main\n"
				       "jmp main\n",
	},
};

static char *egg_find_executable(const char *env_name, const char *exes[], const size_t length) {
	char *output = rz_sys_getenv(env_name);
	if (RZ_STR_ISNOTEMPTY(output)) {
		return output;
	}

	for (size_t i = 0; i < length; i++) {
		output = rz_file_path(exes[i]);
		if (!output || RZ_STR_EQ(output, exes[i])) {
			free(output);
			continue;
		}
		return output;
	}
	return NULL;
}

static char *egg_find_compiler(const egg_c_config_t *config) {
	if (config->exe_compiler) {
		return rz_str_dup(config->exe_compiler);
	}

	const char *cc_exes[] = { "llvm-gcc", "clang", "gcc" };
	char *found = egg_find_executable("CC", cc_exes, RZ_ARRAY_SIZE(cc_exes));
	if (found) {
		return found;
	}
	RZ_LOG_ERROR("egg: Couldn't find a compiler! Please, set the 'CC' environment variable.\n");
	return NULL;
}

static char *egg_find_objcopy(void) {
	const char *objcopy_exes[] = { "objcopy", "gobjcopy" };
	char *found = egg_find_executable("OBJCOPY", objcopy_exes, RZ_ARRAY_SIZE(objcopy_exes));
	if (found) {
		return found;
	}
	RZ_LOG_WARN("egg: Couldn't find a objcopy! You can set the 'OBJCOPY' environment variable.\n");
	return NULL;
}

static char *egg_find_sflib(RzPath *sys_path, const char *triplet) {
	char *sflib_path = rz_sys_getenv("SFLIBPATH");
	if (RZ_STR_ISNOTEMPTY(sflib_path)) {
		return sflib_path;
	}
	RZ_FREE(sflib_path);
	char *incdir = rz_path_incdir(sys_path);
	sflib_path = rz_str_newf(RZ_JOIN_4_PATHS("%s", "sflib", "%s", "sflib.h"), incdir, triplet);
	free(incdir);

	return sflib_path;
}

static char *egg_get_cflags(const egg_c_config_t *config, RzPath *sys_path, const char *triplet) {
	char *sflib_path = egg_find_sflib(sys_path, triplet);
	char *env_cflags = rz_sys_getenv("CFLAGS");
	char *cflags = rz_str_newf("%s %s"
				   " -fno-stack-protector"
				   " -nostdinc"
				   " -fPIC"
				   " -fPIE"
				   " -include '%s'",
		rz_str_get(env_cflags), rz_str_get(config->add_cflags), rz_str_get(sflib_path));
	free(sflib_path);
	free(env_cflags);
	return cflags;
}

static char *egg_get_ldflags(const egg_c_config_t *config, RzPath *sys_path) {
	char *env_ldflags = rz_sys_getenv("LDFLAGS");
	char *ldflags = rz_str_newf("%s %s"
				    " -fno-stack-protector"
				    " -nostdlib"
				    " -fPIC"
				    " -fPIE",
		rz_str_get(env_ldflags), rz_str_get(config->add_ldflags));
	free(env_ldflags);
	return ldflags;
}

static void egg_c_env_free(c_env_t *env) {
	if (!env) {
		return;
	}

	free(env->exe_objcopy);
	free(env->exe_compiler);
	free(env->cflags);
	free(env->ldflags);
	free(env);
}

static c_env_t *egg_c_env_new(RzPath *sys_path, const char *arch, const char *os, int bits) {
	char triplet[256] = { 0 };
	const egg_c_config_t *config = NULL;

	rz_strf(triplet, "%s-%s-%d", os, arch, bits);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(c_configs); ++i) {
		config = &c_configs[i];
		if (RZ_STR_EQ(triplet, config->triplet)) {
			break;
		}
		config = NULL;
	}

	if (!config) {
		return NULL;
	}

	c_env_t *env = RZ_NEW0(c_env_t);
	if (!env) {
		return NULL;
	}

	env->asm_text_segment = config->asm_text_segment;
	env->asm_text_header = config->asm_text_header;
	// heap allocated below
	env->exe_objcopy = egg_find_objcopy();
	env->exe_compiler = egg_find_compiler(config);
	env->cflags = egg_get_cflags(config, sys_path, triplet);
	env->ldflags = egg_get_ldflags(config, sys_path);

	if (!env->exe_compiler ||
		!env->cflags ||
		!env->ldflags) {
		egg_c_env_free(env);
		return NULL;
	}

	rz_str_sanitize(env->exe_compiler);
	return env;
}

// strips any line containing the keyword
static void egg_str_strip_line(char *input, size_t input_len, const char *key) {
	size_t klen = strlen(key);
	const char *end = input + input_len;
	const char *cur = input;
	while (cur < end) {
		const char *newline = strchr(cur, '\n');
		if (!newline) {
			newline = end;
		}

		const char *found = (const char *)rz_mem_mem((const ut8 *)cur, newline - cur, (const ut8 *)key, klen);
		if (found) {
			memset((char *)cur, ' ', newline - cur);
		}
		cur = newline + 1;
	}
}

static bool egg_append_tmp_to_assembly_file(const char *outfile_tmp, const char *assembly_file) {
	size_t buffer_size = 0;
	char *buffer = rz_file_slurp(outfile_tmp, &buffer_size);
	if (!buffer) {
		RZ_LOG_ERROR("egg: Could not open '%s'.\n", outfile_tmp);
		goto fail;
	}
	buffer = rz_str_replace(buffer, "rdata", "text", false);
	buffer = rz_str_replace(buffer, "rodata", "text", false);
	buffer = rz_str_replace(buffer, "get_pc_thunk.bx", "__getesp__", true);

	const char *words[] = { ".cstring", "size", "___main", "section", "__alloca", "zero", "cfi" };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(words); i++) {
		egg_str_strip_line(buffer, buffer_size, words[i]);
	}

	// the buffer size contains also the `\0` char
	if (!rz_file_dump(assembly_file, (const ut8 *)buffer, buffer_size - 1, true)) {
		RZ_LOG_ERROR("egg: Error while opening %s\n", assembly_file);
		goto fail;
	}

	free(buffer);
	return true;

fail:
	free(buffer);
	return false;
}

static bool egg_compile_c_source_to_assembly(const c_env_t *env, const char *infile_C, const char *outfile_tmp) {
	char *cmd = rz_str_newf("'%s' %s -o '%s' -S '%s'", env->exe_compiler, env->cflags, outfile_tmp, infile_C);
	RZ_LOG_INFO("egg: executing sys command: %s\n", cmd);
	int rc = rz_sys_system(cmd);
	free(cmd);
	// when zero, then no error.
	return !rc;
}

static bool egg_compile_assembly_to_object(const c_env_t *env, const char *infile_asm, const char *outfile_obj) {
	char *cmd = rz_str_newf("'%s' %s -o '%s' '%s'", env->exe_compiler, env->ldflags, outfile_obj, infile_asm);
	RZ_LOG_INFO("egg: executing command: %s\n", cmd);
	int rc = rz_sys_system(cmd);
	free(cmd);
	// when zero, then no error.
	return !rc;
}

static bool egg_link_object_via_rz_bin(const c_env_t *env, const char *infile_obj, const char *outfile_text) {
	// "d/S/<section>" is a command of rz-bin to dump a specific section
	char *cmd = rz_str_newf("rz-bin -o '%s' -O 'd/S/%s' '%s'", outfile_text, env->asm_text_segment, infile_obj);
	RZ_LOG_INFO("egg: executing command: %s\n", cmd);
	int rc = rz_sys_system(cmd);
	free(cmd);
	// when zero, then no error.
	return !rc;
}

static bool egg_link_object_via_objdump(const c_env_t *env, const char *infile_obj, const char *outfile_text) {
	char *cmd = rz_str_newf("'%s' -j .text -O binary '%s' '%s'", env->exe_objcopy, infile_obj, outfile_text);
	RZ_LOG_INFO("egg: executing command: %s\n", cmd);
	int rc = rz_sys_system(cmd);
	free(cmd);
	// when zero, then no error.
	return !rc;
}

static bool egg_link_object(const c_env_t *env, const char *infile_obj, const char *outfile_text) {
	if (!egg_link_object_via_rz_bin(env, infile_obj, outfile_text)) {
		return false;
	} else if (rz_file_size(outfile_text) > 0) {
		return true;
	} else if (RZ_STR_ISEMPTY(env->exe_objcopy)) {
		return false;
	}
	RZ_LOG_WARN("egg: linked file generated by rz-bin is empty, using objcopy instead.\n");
	return egg_link_object_via_objdump(env, infile_obj, outfile_text);
}

/**
 * \brief      Compiles a given C source and returns the file path hexdump of the compiled code.
 *
 * \param[in]  source_file  The file
 * \param[in]  arch         The arch name
 * \param[in]  os           The operating system
 * \param[in]  bits         The arch bits
 * \param      sys_path     The system path
 *
 * \return     { description_of_the_return_value }
 */
RZ_API RZ_OWN char *rz_egg_compile_c_source(RZ_NONNULL const char *source_file, RZ_NONNULL const char *arch, RZ_NONNULL const char *os, int bits, RZ_BORROW RZ_NONNULL RzPath *sys_path) {
	rz_return_val_if_fail(sys_path && source_file && arch && os, NULL);

	bool ok = true;
	c_env_t *env = NULL;
	char *outfile_tmp = rz_str_newf("%s.tmp", source_file);
	char *outfile_asm = rz_str_newf("%s.s", source_file);
	char *outfile_obj = rz_str_newf("%s.o", source_file);
	char *outfile_text = rz_str_newf("%s.text", source_file);
	if (!outfile_tmp || !outfile_asm || !outfile_obj || !outfile_text) {
		RZ_LOG_ERROR("egg: failed to allocate memory\n");
		ok = false;
		goto fail;
	}

	if (!(env = egg_c_env_new(sys_path, arch, os, bits))) {
		RZ_LOG_ERROR("egg: failed to initialize C environment for '%s-%s-%d'\n", os, arch, bits);
		ok = false;
		goto fail;
	}

	// prepare assembly file.
	if (!rz_file_dump(outfile_asm, (const ut8 *)env->asm_text_header, strlen(env->asm_text_header), false)) {
		RZ_LOG_ERROR("egg: Error while opening %s\n", outfile_asm);
		ok = false;
	} else if (!egg_compile_c_source_to_assembly(env, source_file, outfile_tmp)) {
		RZ_LOG_ERROR("egg: failed to compile source file: %s\n", source_file);
		ok = false;
	} else if (!egg_append_tmp_to_assembly_file(outfile_tmp, outfile_asm)) {
		RZ_LOG_ERROR("egg: failed to append '%s' to %s\n", outfile_tmp, outfile_asm);
		ok = false;
	} else if (!egg_compile_assembly_to_object(env, outfile_asm, outfile_obj)) {
		RZ_LOG_ERROR("egg: failed to compile to object file: %s\n", outfile_asm);
		ok = false;
	} else if (!egg_link_object(env, outfile_obj, outfile_text)) {
		RZ_LOG_ERROR("egg: failed to link object: %s\n", outfile_obj);
		ok = false;
	}

	// cleanup.
	rz_file_rm(outfile_tmp);
	rz_file_rm(outfile_asm);
	rz_file_rm(outfile_obj);

fail:
	free(outfile_tmp);
	free(outfile_asm);
	free(outfile_obj);
	if (!ok) {
		RZ_FREE(outfile_text)
	}
	egg_c_env_free(env);

	return outfile_text;
}
