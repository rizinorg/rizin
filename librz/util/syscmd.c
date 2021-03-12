// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <errno.h>

#define FMT_NONE 0
#define FMT_RAW  1
#define FMT_JSON 2

static int needs_newline = 0;

static char *showfile(char *res, const int nth, const char *fpath, const char *name, int printfmt) {
#if __UNIX__
	struct stat sb;
#endif
	const char *n = fpath;
	char *nn, *u_rwx = NULL;
	int sz = rz_file_size(n);
	int perm, uid = 0, gid = 0;
	int fch = '-';
	if (!strncmp(fpath, "./", 2)) {
		fpath = fpath + 2;
	}
	const bool isdir = rz_file_is_directory(n);
	if (isdir) {
		nn = rz_str_append(strdup(fpath), "/");
	} else {
		nn = strdup(fpath);
	}
	if (!*nn) {
		free(nn);
		return res;
	}
	perm = isdir ? 0755 : 0644;
	if (!printfmt) {
		needs_newline = ((nth + 1) % 4) ? 1 : 0;
		res = rz_str_appendf(res, "%18s%s", nn, needs_newline ? "  " : "\n");
		free(nn);
		return res;
	}
	// TODO: escape non-printable chars in filenames
	// TODO: Implement more real info in ls -l
	// TODO: handle suid
#if __UNIX__
	if (lstat(n, &sb) != -1) {
		ut32 ifmt = sb.st_mode & S_IFMT;
		uid = sb.st_uid;
		gid = sb.st_gid;
		perm = sb.st_mode & 0777;
		if (!(u_rwx = strdup(rz_str_rwx_i(perm >> 6)))) {
			free(nn);
			return res;
		}
		if (sb.st_mode & S_ISUID) {
			u_rwx[2] = (sb.st_mode & S_IXUSR) ? 's' : 'S';
		}
		if (isdir) {
			fch = 'd';
		} else {
			switch (ifmt) {
			case S_IFCHR: fch = 'c'; break;
			case S_IFBLK: fch = 'b'; break;
			case S_IFLNK: fch = 'l'; break;
			case S_IFIFO: fch = 'p'; break;
#ifdef S_IFSOCK
			case S_IFSOCK: fch = 's'; break;
#endif
			}
		}
	}
#else
	u_rwx = strdup("-");
	fch = isdir ? 'd' : '-';
#endif
	if (printfmt == 'q') {
		res = rz_str_appendf(res, "%s\n", nn);
	} else if (printfmt == 'e') {
		const char *eDIR = "📁";
		const char *eLNK = "📎";
		const char *eIMG = "🌅";
		const char *eUID = "🔼";
		const char *eHID = "👀";
		const char *eANY = "  ";
		// --
		const char *icon = eANY;
		if (isdir) {
			icon = eDIR;
#if __UNIX__
		} else if ((sb.st_mode & S_IFMT) == S_IFLNK) {
			icon = eLNK;
		} else if (sb.st_mode & S_ISUID) {
			icon = eUID;
#endif
		} else if (rz_str_casestr(nn, ".jpg") || rz_str_casestr(nn, ".png") || rz_str_casestr(nn, ".gif")) {
			icon = eIMG;
		} else if (*nn == '.') {
			icon = eHID;
		}
		res = rz_str_appendf(res, "%s %s\n", icon, nn);
	} else if (printfmt == FMT_RAW) {
		res = rz_str_appendf(res, "%c%s%s%s  1 %4d:%-4d  %-10d  %s\n",
			isdir ? 'd' : fch,
			u_rwx ? u_rwx : "-",
			rz_str_rwx_i((perm >> 3) & 7),
			rz_str_rwx_i(perm & 7),
			uid, gid, sz, nn);
	} else if (printfmt == FMT_JSON) {
		if (nth > 0) {
			res = rz_str_append(res, ",");
		}
		res = rz_str_appendf(res, "{\"name\":\"%s\",\"size\":%d,\"uid\":%d,"
					  "\"gid\":%d,\"perm\":%d,\"isdir\":%s}",
			name, sz, uid, gid, perm, isdir ? "true" : "false");
	}
	free(nn);
	free(u_rwx);
	return res;
}

// TODO: Move into rz_util .. rz_print maybe? rz_cons dep is annoying
RZ_API char *rz_syscmd_ls(const char *input) {
	char *res = NULL;
	const char *path = ".";
	char *d = NULL;
	char *p = NULL;
	char *homepath = NULL;
	char *pattern = NULL;
	int printfmt = 0;
	RzListIter *iter;
	RzList *files;
	char *name;
	char *dir;
	int off;
	if (!input) {
		input = "";
		path = ".";
	}
	if (*input == 'q') {
		printfmt = 'q';
		input++;
	}
	if (*input && input[0] == ' ') {
		input++;
	}
	if (*input) {
		if ((!strncmp(input, "-h", 2))) {
			eprintf("Usage: ls ([-e,-l,-j,-q]) ([path]) # long, json, quiet\n");
		} else if ((!strncmp(input, "-e", 2))) {
			printfmt = 'e';
			path = rz_str_trim_head_ro(path + 1);
		} else if ((!strncmp(input, "-q", 2))) {
			printfmt = 'q';
			path = rz_str_trim_head_ro(path + 1);
		} else if ((!strncmp(input, "-l", 2)) || (!strncmp(input, "-j", 2))) {
			// mode = 'l';
			if (input[2]) {
				printfmt = (input[2] == 'j') ? FMT_JSON : FMT_RAW;
				path = rz_str_trim_head_ro(input + 2);
				if (!*path) {
					path = ".";
				}
			} else {
				printfmt = FMT_RAW;
			}
		} else {
			path = input;
		}
	}
	if (!path || !*path) {
		path = ".";
	} else if (!strncmp(path, "~/", 2)) {
		homepath = rz_str_home(path + 2);
		if (homepath) {
			path = (const char *)homepath;
		}
	} else if (*path == '$') {
		if (!strncmp(path + 1, "home", 4) || !strncmp(path + 1, "HOME", 4)) {
			homepath = rz_str_home((strlen(path) > 5) ? path + 6 : NULL);
			if (homepath) {
				path = (const char *)homepath;
			}
		}
	}
	if (!rz_file_is_directory(path)) {
		p = strrchr(path, '/');
		if (p) {
			off = p - path;
			d = (char *)calloc(1, off + 1);
			if (!d) {
				free(homepath);
				return NULL;
			}
			memcpy(d, path, off);
			path = (const char *)d;
			pattern = strdup(p + 1);
		} else {
			pattern = strdup(path);
			path = ".";
		}
	} else {
		pattern = strdup("*");
	}
	if (rz_file_is_regular(path)) {
		res = showfile(res, 0, path, path, printfmt);
		free(homepath);
		free(pattern);
		free(d);
		return res;
	}
	files = rz_sys_dir(path);

	if (path[strlen(path) - 1] == '/') {
		dir = strdup(path);
	} else {
		dir = rz_str_append(strdup(path), "/");
	}
	int nth = 0;
	if (printfmt == FMT_JSON) {
		res = strdup("[");
	}
	needs_newline = 0;
	rz_list_foreach (files, iter, name) {
		char *n = rz_str_append(strdup(dir), name);
		if (!n) {
			break;
		}
		if (rz_str_glob(name, pattern)) {
			if (*n) {
				res = showfile(res, nth, n, name, printfmt);
			}
			nth++;
		}
		free(n);
	}
	if (printfmt == FMT_JSON) {
		res = rz_str_append(res, "]");
	}
	if (needs_newline) {
		res = rz_str_append(res, "\n");
	}
	free(dir);
	free(d);
	free(homepath);
	free(pattern);
	rz_list_free(files);
	return res;
}

static int cmpstr(const void *_a, const void *_b) {
	const char *a = _a, *b = _b;
	return (int)strcmp(a, b);
}

RZ_API char *rz_syscmd_sort(const char *file) {
	const char *p = NULL;
	RzList *list = NULL;
	if (file) {
		if ((p = strchr(file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = strdup(p);
		rz_str_trim(filename);
		char *data = rz_file_slurp(filename, NULL);
		if (!data) {
			eprintf("No such file or directory\n");
		} else {
			list = rz_str_split_list(data, "\n", 0);
			rz_list_sort(list, cmpstr);
			data = rz_list_to_str(list, '\n');
			rz_list_free(list);
		}
		free(filename);
		return data;
	} else {
		eprintf("Usage: sort [file]\n");
	}
	return NULL;
}

RZ_API char *rz_syscmd_head(const char *file, int count) {
	const char *p = NULL;
	if (file) {
		if ((p = strchr(file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = strdup(p);
		rz_str_trim(filename);
		char *data = rz_file_slurp_lines(filename, 1, count);
		if (!data) {
			eprintf("No such file or directory\n");
		}
		free(filename);
		return data;
	} else {
		eprintf("Usage: head 7 [file]\n");
	}
	return NULL;
}

RZ_API char *rz_syscmd_tail(const char *file, int count) {
	const char *p = NULL;
	if (file) {
		if ((p = strchr(file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = strdup(p);
		rz_str_trim(filename);
		char *data = rz_file_slurp_lines_from_bottom(filename, count);
		if (!data) {
			eprintf("No such file or directory\n");
		}
		free(filename);
		return data;
	} else {
		eprintf("Usage: tail 7 [file]\n");
	}
	return NULL;
}

RZ_API char *rz_syscmd_uniq(const char *file) {
	const char *p = NULL;
	RzList *list = NULL;
	if (file) {
		if ((p = strchr(file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = strdup(p);
		rz_str_trim(filename);
		char *data = rz_file_slurp(filename, NULL);
		if (!data) {
			eprintf("No such file or directory\n");
		} else {
			list = rz_str_split_list(data, "\n", 0);
			RzList *uniq_list = rz_list_uniq(list, cmpstr);
			data = rz_list_to_str(uniq_list, '\n');
			rz_list_free(uniq_list);
			rz_list_free(list);
		}
		free(filename);
		return data;
	} else {
		eprintf("Usage: uniq [file]\n");
	}
	return NULL;
}

RZ_API char *rz_syscmd_join(const char *file1, const char *file2) {
	const char *p1 = NULL, *p2 = NULL;
	RzList *list1, *list2, *list = rz_list_newf(NULL);
	if (!list) {
		return NULL;
	}
	if (file1) {
		if ((p1 = strchr(file1, ' '))) {
			p1 = p1 + 1;
		} else {
			p1 = file1;
		}
	}
	if (file2) {
		if ((p2 = strchr(file2, ' '))) {
			p2 = p2 + 1;
		} else {
			p2 = file2;
		}
	}
	if (p1 && *p1 && p2 && *p2) {
		char *filename1 = strdup(p1);
		char *filename2 = strdup(p2);
		rz_str_trim(filename1);
		rz_str_trim(filename2);
		char *data1 = rz_file_slurp(filename1, NULL);
		char *data2 = rz_file_slurp(filename2, NULL);
		char *data = NULL;
		RzListIter *iter1, *iter2;
		if (!data1 && !data2) {
			eprintf("No such files or directory\n");
		} else {
			list1 = rz_str_split_list(data1, "\n", 0);
			list2 = rz_str_split_list(data2, "\n", 0);

			char *str1, *str2;
			rz_list_foreach (list1, iter1, str1) {
				char *field = strdup(str1); // extract comman field
				char *end = strchr(field, ' ');
				if (end) {
					*end = '\0';
				} else {
					free(field);
					continue;
				}
				rz_list_foreach (list2, iter2, str2) {
					if (rz_str_startswith(str2, field)) {
						char *out = rz_str_new(field);
						char *first = strchr(str1, ' ');
						char *second = strchr(str2, ' ');
						rz_str_append(out, first ? first : " ");
						rz_str_append(out, second ? second : " ");
						rz_list_append(list, out);
					}
				}
				free(field);
			}
			data = rz_list_to_str(list, '\n');
			rz_list_free(list);
			rz_list_free(list1);
			rz_list_free(list2);
		}
		free(filename1);
		free(filename2);
		return data;
	} else {
		eprintf("Usage: join file1 file2\n");
	}
	return NULL;
}

RZ_API char *rz_syscmd_cat(const char *file) {
	const char *p = NULL;
	if (file) {
		if ((p = strchr(file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = strdup(p);
		rz_str_trim(filename);
		char *data = rz_file_slurp(filename, NULL);
		if (!data) {
			eprintf("No such file or directory\n");
		}
		free(filename);
		return data;
	} else {
		eprintf("Usage: cat [file]\n");
	}
	return NULL;
}

RZ_API char *rz_syscmd_mkdir(const char *dir) {
	const char *suffix = rz_str_trim_head_ro(strchr(dir, ' '));
	if (!suffix || !strncmp(suffix, "-p", 3)) {
		return rz_str_dup(NULL, "Usage: mkdir [-p] [directory]\n");
	}
	int ret;
	char *dirname = (!strncmp(suffix, "-p ", 3))
		? strdup(suffix + 3)
		: strdup(suffix);
	rz_str_trim(dirname);
	ret = rz_sys_mkdirp(dirname);
	if (!ret) {
		if (rz_sys_mkdir_failed()) {
			char *res = rz_str_newf("Cannot create \"%s\"\n", dirname);
			free(dirname);
			return res;
		}
	}
	free(dirname);
	return NULL;
}

RZ_API bool rz_syscmd_mv(const char *input) {
	if (strlen(input) < 3) {
		eprintf("Usage: mv src dst\n");
		return false;
	}
	input = input + 2;
#if __WINDOWS__
	rz_sys_cmdf("move %s >nul", input);
#else
	rz_sys_cmdf("mv %s", input);
#endif
	return false;
}
