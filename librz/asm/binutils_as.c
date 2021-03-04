// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 eagleoflqj <liumeo@pku.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "binutils_as.h"

int binutils_assemble(RzAsm *a, RzAsmOp *op, const char *buf, const char *as, const char *env, const char *header, const char *cmd_opt) {
	char *user_as = rz_sys_getenv(env);
	if (user_as) {
		as = user_as;
	}
	if (RZ_STR_ISEMPTY(as)) {
		eprintf("Please set %s env to define a %s assembler program\n", env, a->cur->arch);
		return 1;
	}

	char *ipath, *opath;
	int ifd = rz_file_mkstemp("rz_as", &ipath);
	if (ifd == -1) {
		free(user_as);
		return -1;
	}
	int ofd = rz_file_mkstemp("rz_as", &opath);
	if (ofd == -1) {
		free(user_as);
		free(ipath);
		close(ifd);
		return -1;
	}

	int res = -1;
	char *asm_buf = rz_str_newf("%s"
				    ".ascii \"   BEGINMARK\"\n" // 4 bit align
				    "%s\n"
				    ".ascii \"ENDMARK\"\n",
		header, buf);
	if (!asm_buf) {
		goto beach;
	}
	const size_t asm_buf_len = strlen(asm_buf);
	const bool success = write(ifd, asm_buf, asm_buf_len) == asm_buf_len;
	free(asm_buf);
	if (!success) {
		goto beach;
	}

	char cmd[4096];
	snprintf(cmd, sizeof(cmd), "%s %s %s -o %s", as, cmd_opt, ipath, opath);
	if (!rz_sys_system(cmd)) {
		int len = 0;
		const ut8 *begin, *end;
		close(ofd);
		ofd = rz_sys_open(opath, O_BINARY | O_RDONLY, 0644);
		if (ofd < 0) {
			goto skip_ofd;
		}
		ut8 obuf[4096];
		len = read(ofd, obuf, sizeof(obuf));
		begin = rz_mem_mem(obuf, len, (const ut8 *)"BEGINMARK", 9);
		end = rz_mem_mem(obuf, len, (const ut8 *)"ENDMARK", 7);
		if (!begin || !end) {
			eprintf("Cannot find water marks\n");
			len = 0;
		} else {
			len = (int)(size_t)(end - begin - 9);
			if (len > 0) {
				rz_strbuf_setbin(&op->buf, begin + 9, len);
			} else {
				len = 0;
			}
		}
		res = op->size = len;
	} else {
		eprintf("Error running: %s", cmd);
	}

beach:
	close(ofd);
skip_ofd:
	close(ifd);

	unlink(ipath);
	unlink(opath);

	free(ipath);
	free(opath);
	free(user_as);

	return res;
}
