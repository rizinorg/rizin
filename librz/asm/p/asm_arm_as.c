/* radare - LGPL - Copyright 2015-2020 pancake */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

// USE ARM_AS environment variable
#define ARM32_AS "arm-linux-androideabi-as"
#define ARM64_AS "aarch64-linux-android-as"
// toolchains/arm-linux-androideabi-4.8/prebuilt/darwin-arm_64/bin/
// toolchains/aarch64-linux-android-4.9/prebuilt/darwin-arm_64/bin/

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	const char *bitconfig = "";
	char *ipath, *opath;
	char *as = NULL;

	int ifd = rz_file_mkstemp ("rz_as", &ipath);
	if (ifd == -1) {
		return -1;
	}

	int ofd = rz_file_mkstemp ("rz_as", &opath);
	if (ofd == -1) {
		free (ipath);
		return -1;
	}

	as = rz_sys_getenv ("ARM_AS");
	if (!as || !*as) {
		free (as);
		if (a->bits == 64) {
			as = strdup (ARM64_AS);
		} else {
			as = strdup (ARM32_AS);
		}
	}
	if (a->bits == 16) {
		bitconfig = ".thumb";
	}

	char *asm_buf = rz_str_newf ("%s\n" //.org 0x%"PFMT64x"\n"
			".ascii \"BEGINMARK\"\n"
			"%s\n"
			".ascii \"ENDMARK\"\n",
			bitconfig, buf); // a->pc ??
	if (asm_buf) {
		const size_t asm_buf_len = strlen (asm_buf);
		const bool success = write (ifd, asm_buf, asm_buf_len) != asm_buf_len;
		(void)close (ifd);
		free (asm_buf);
		if (!success) {
			free (as);
			free (ipath);
			free (opath);
			return -1;
		}
	}

	int len = 0;
	if (!rz_sys_cmdf ("%s %s -o %s", as, ipath, opath)) {
		const ut8 *begin, *end;
		close (ofd);
		ofd = rz_sandbox_open (opath, O_BINARY|O_RDONLY, 0644);
		if (ofd < 0) {
			free (as);
			free (ipath);
			free (opath);
			return -1;
		}
		ut8 buf[4096];
		len = read (ofd, buf, sizeof (buf));
		begin = rz_mem_mem (buf, len, (const ut8*)"BEGINMARK", 9);
		end = rz_mem_mem (buf, len, (const ut8*)"ENDMARK", 7);
		if (!begin || !end) {
			eprintf ("Cannot find water marks\n");
			len = 0;
		} else {
			len = (int)(size_t)(end - begin - 9);
			if (len > 0) {
				rz_strbuf_setbin (&op->buf, begin + 9, len);
			} else {
				len = 0;
			}
		}
	} else {
		eprintf ("Error running: %s %s -o %s", as, ipath, opath);
		eprintf ("export PATH=~/NDK/toolchains/arm-linux*/prebuilt/darwin-arm_64/bin\n");
	}

	close (ofd);

	unlink (ipath);
	unlink (opath);
	free (ipath);
	free (opath);
	free (as);

	return op->size = len;
}

RzAsmPlugin rz_asm_plugin_arm_as = {
	.name = "arm.as",
	.desc = "as ARM Assembler (use ARM_AS environment)",
	.arch = "arm",
	.author = "pancake",
	.license = "LGPL3",
	.bits = 16|32|64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.assemble = &assemble,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_arm_as,
	.version = R2_VERSION
};
#endif
