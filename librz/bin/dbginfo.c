// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_bin.h>

RZ_API bool rz_bin_addr2line(RzBin *bin, ut64 addr, char *file, int len, int *line) {
	rz_return_val_if_fail(bin, false);
	RzBinFile *binfile = rz_bin_cur(bin);
	RzBinObject *o = rz_bin_cur_object(bin);
	RzBinPlugin *cp = rz_bin_file_cur_plugin(binfile);
	ut64 baddr = rz_bin_get_baddr(bin);
	if (cp && cp->dbginfo) {
		if (o && addr >= baddr && addr < baddr + bin->cur->o->size) {
			if (cp->dbginfo->get_line) {
				return cp->dbginfo->get_line(
					bin->cur, addr, file, len, line);
			}
		}
	}
	return false;
}

RZ_API char *rz_bin_addr2text(RzBin *bin, ut64 addr, int origin) {
	rz_return_val_if_fail(bin, NULL);
	char file[4096];
	int line;
	char *out = NULL, *out2 = NULL;
	char *file_nopath = NULL;
	if (!bin->cur) {
		return NULL;
	}
	char *key = rz_str_newf("0x%" PFMT64x, addr);
	char *file_line = sdb_get(bin->cur->sdb_addrinfo, key, 0);
	if (file_line) {
		char *token = strchr(file_line, '|');
		if (token) {
			*token++ = 0;
			line = atoi(token);
			out = rz_file_slurp_line(file_line, line, 0);
			*token++ = ':';
		} else {
			return file_line;
		}
	}
	free(key);
	if (out) {
		if (origin > 1) {
			file_nopath = file_line;
		} else {
			file_nopath = strrchr(file_line, '/');
			if (file_nopath) {
				file_nopath++;
			} else {
				file_nopath = file_line;
			}
		}
		if (origin) {
			char *res = rz_str_newf("%s:%d%s%s",
				file_nopath ? file_nopath : "",
				line, file_nopath ? " " : "",
				out ? out : "");
			free(out);
			out = res;
		}
		free(file_line);
		return out;
	}
	RZ_FREE(file_line);

	file[0] = 0;
	if (rz_bin_addr2line(bin, addr, file, sizeof(file), &line)) {
		if (bin->srcdir && *bin->srcdir) {
			char *slash = strrchr(file, '/');
			char *nf = rz_str_newf("%s/%s", bin->srcdir, slash ? slash + 1 : file);
			strncpy(file, nf, sizeof(file) - 1);
			free(nf);
		}
		// TODO: this is slow. must use a cached pool of mapped files and line:off entries
		out = rz_file_slurp_line(file, line, 0);
		if (!out) {
			if (origin > 1) {
				file_nopath = file;
			} else {
				file_nopath = strrchr(file, '/');
				if (file_nopath) {
					file_nopath++;
				} else {
					file_nopath = file;
				}
			}
			return rz_str_newf("%s:%d", file_nopath ? file_nopath : "", line);
		}
		out2 = malloc((strlen(file) + 64 + strlen(out)) * sizeof(char));
		if (origin > 1) {
			file_nopath = NULL;
		} else {
			file_nopath = strrchr(file, '/');
		}
		if (origin) {
			snprintf(out2, strlen(file) + 63 + strlen(out), "%s:%d%s%s",
				file_nopath ? file_nopath + 1 : file, line, *out ? " " : "", out);
		} else {
			snprintf(out2, 64, "%s", out);
		}
		free(out);
	}
	return out2;
}

RZ_API char *rz_bin_addr2fileline(RzBin *bin, ut64 addr) {
	rz_return_val_if_fail(bin, NULL);
	char file[1024];
	int line = 0;

	if (rz_bin_addr2line(bin, addr, file, sizeof(file) - 1, &line)) {
		char *file_nopath = strrchr(file, '/');
		return rz_str_newf("%s:%d", file_nopath ? file_nopath + 1 : file, line);
	}
	return NULL;
}
