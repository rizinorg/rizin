// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <errno.h>

static int cmpstr(const void *_a, const void *_b, void *user) {
	const char *a = _a, *b = _b;
	return (int)strcmp(a, b);
}

RZ_API RZ_OWN char *rz_syscmd_sort(RZ_NONNULL const char *file) {
	rz_return_val_if_fail(file, NULL);

	const char *p = NULL;
	RzList *list = NULL;
	if ((p = strchr(file, ' '))) {
		p = p + 1;
	} else {
		p = file;
	}
	if (p && *p) {
		char *filename = rz_str_dup(p);
		rz_str_trim(filename);
		char *data = rz_file_slurp(filename, NULL);
		if (!data) {
			eprintf("No such file or directory\n");
		} else {
			list = rz_str_split_list(data, "\n", 0);
			rz_list_sort(list, cmpstr, NULL);
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

RZ_API RZ_OWN char *rz_syscmd_head(RZ_NONNULL const char *file, int count) {
	rz_return_val_if_fail(file, NULL);

	const char *p = NULL;
	if ((p = strchr(file, ' '))) {
		p = p + 1;
	} else {
		p = file;
	}
	if (p && *p) {
		char *filename = rz_str_dup(p);
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

RZ_API RZ_OWN char *rz_syscmd_tail(RZ_NONNULL const char *file, int count) {
	rz_return_val_if_fail(file, NULL);

	const char *p = NULL;
	if (file) {
		if ((p = strchr(file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = rz_str_dup(p);
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

RZ_API RZ_OWN char *rz_syscmd_uniq(RZ_NONNULL const char *file) {
	rz_return_val_if_fail(file, NULL);

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
		char *filename = rz_str_dup(p);
		rz_str_trim(filename);
		char *data = rz_file_slurp(filename, NULL);
		if (!data) {
			eprintf("No such file or directory\n");
		} else {
			list = rz_str_split_list(data, "\n", 0);
			RzList *uniq_list = rz_list_uniq(list, cmpstr, NULL);
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

RZ_API RZ_OWN char *rz_syscmd_join(RZ_NONNULL const char *file1, RZ_NONNULL const char *file2) {
	rz_return_val_if_fail(file1 && file2, NULL);

	const char *p1 = NULL, *p2 = NULL;
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
		char *filename1 = rz_str_dup(p1);
		char *filename2 = rz_str_dup(p2);
		rz_str_trim(filename1);
		rz_str_trim(filename2);
		char *data1 = rz_file_slurp(filename1, NULL);
		char *data2 = rz_file_slurp(filename2, NULL);
		char *data = NULL;
		if (!data1 && !data2) {
			eprintf("No such files or directory\n");
		} else {
			RzList *list = rz_list_newf(NULL);
			RzList *list1 = rz_str_split_list(data1, "\n", 0);
			RzList *list2 = rz_str_split_list(data2, "\n", 0);
			if (!list || !list1 || !list2) {
				rz_list_free(list2);
				rz_list_free(list1);
				rz_list_free(list);
				return NULL;
			}
			char *str1, *str2;
			RzListIter *iter1, *iter2;
			rz_list_foreach (list1, iter1, str1) {
				char *field = rz_str_dup(str1); // extract comman field
				char *end = strchr(field, ' ');
				if (end) {
					*end = '\0';
				} else {
					free(field);
					continue;
				}
				rz_list_foreach (list2, iter2, str2) {
					if (rz_str_startswith(str2, field)) {
						char *out = rz_str_dup(field);
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
			rz_list_free(list2);
			rz_list_free(list1);
			rz_list_free(list);
		}
		free(filename1);
		free(filename2);
		return data;
	} else {
		eprintf("Usage: join file1 file2\n");
	}
	return NULL;
}

RZ_API RZ_OWN char *rz_syscmd_cat(RZ_NONNULL const char *file) {
	rz_return_val_if_fail(file, NULL);

	const char *p = NULL;
	if (file) {
		if ((p = strchr(file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = rz_str_dup(p);
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

RZ_API RZ_OWN char *rz_syscmd_mkdir(RZ_NONNULL const char *dir) {
	rz_return_val_if_fail(dir, NULL);

	const char *suffix = rz_str_trim_head_ro(strchr(dir, ' '));
	if (!suffix || !strncmp(suffix, "-p", 3)) {
		return rz_str_dup("Usage: mkdir [-p] [directory]\n");
	}
	int ret;
	char *dirname = (!strncmp(suffix, "-p ", 3))
		? rz_str_dup(suffix + 3)
		: rz_str_dup(suffix);
	rz_str_trim(dirname);
	ret = rz_sys_mkdirp(dirname);
	if (!ret && rz_sys_mkdir_failed()) {
		char *res = rz_str_newf("Cannot create \"%s\"\n", dirname);
		free(dirname);
		return res;
	}
	free(dirname);
	return NULL;
}
