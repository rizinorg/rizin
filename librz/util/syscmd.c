// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_types.h"
#include "rz_util/rz_sys.h"
#include <rz_util/rz_str.h>
#include <rz_core.h>
#include <errno.h>
#include <string.h>

static int cmpstr(const void *_a, const void *_b, void *user) {
	const char *a = _a, *b = _b;
	return (int)strcmp(a, b);
}

RZ_API RZ_OWN char *rz_syscmd_sort(RZ_NONNULL const char *file) {
	rz_return_val_if_fail(file, NULL);

	const char *p = NULL;
	char *sorted_str = NULL;
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
			sorted_str = rz_syscmd_sort_str(data);
		}
		free(data);
		free(filename);
		return sorted_str;
	} else {
		eprintf("Usage: sort [file]\n");
	}
	return NULL;
}

/**
 * \brief Sort the given piped text.
 * \param input piped text to sort.
 * \param length Length of the command result string.
 * \return Newly allocated sorted string.
 *
 * Takes the input text and returns its sorted form (for shell).
 */
RZ_API RZ_OWN char *rz_syscmd_sort_pipe(RZ_NULLABLE const char *input, int *length) {
	if (RZ_STR_ISEMPTY(input)) {
		return NULL;
	}

	char *sorted_str = rz_syscmd_sort_str(input);
	*length = strlen((const char *)sorted_str);

	return sorted_str;
}

/**
 * \brief Sort the given text.
 * \param input text to sort.
 * \return Newly allocated sorted string.
 *
 * Takes the input text and returns its sorted form.
 */
RZ_API RZ_OWN char *rz_syscmd_sort_str(RZ_NONNULL const char *input) {
	if (RZ_STR_ISEMPTY(input)) {
		return NULL;
	}

	RzList *list = NULL;

	char *data = rz_str_dup(input);
	if (!data) {
		return NULL;
	}

	list = rz_str_split_list(data, "\n", 0);
	if (!list) {
		free(data);
		return NULL;
	}

	rz_list_sort(list, cmpstr, NULL);
	rz_list_del_n(list, 0);
	char *sorted_str = rz_list_to_str(list, '\n');

	rz_list_free(list);
	free(data);
	return sorted_str;
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
	char *uniq_str = NULL;
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
			uniq_str = rz_syscmd_uniq_str(data);
		}
		free(data);
		free(filename);
		return uniq_str;
	} else {
		eprintf("Usage: uniq [file]\n");
	}
	return NULL;
}

/**
 * \brief Produce the unique filtered form of the piped input.
 * \param input piped string to process.
 * \param length Length of the command result string.
 * \return Newly allocated string containing the uniq output.
 *
 * Takes the input text and returns its unique filtered result.
 */
RZ_API RZ_OWN char *rz_syscmd_uniq_pipe(RZ_NULLABLE const char *input, int *length) {
	if (RZ_STR_ISEMPTY(input)) {
		return NULL;
	}

	char *return_data = rz_syscmd_uniq_str(input);

	*length = strlen((const char *)return_data);
	return return_data;
}

/**
 * \brief Produce the unique filtered form of the input.
 * \param input string to process.
 * \return Newly allocated string containing the uniq output.
 *
 * Takes the input text and returns its unique filtered result.
 */
RZ_API RZ_OWN char *rz_syscmd_uniq_str(RZ_NONNULL const char *input) {
	if (RZ_STR_ISEMPTY(input)) {
		return NULL;
	}

	RzList *list = NULL;
	char *data = rz_str_dup(input);
	if (!data) {
		return NULL;
	}

	list = rz_str_split_list(data, "\n", 0);
	if (!list) {
		free(data);
		return NULL;
	}

	RzList *uniq_list = rz_list_uniq(list, cmpstr, NULL);
	if (!uniq_list) {
		rz_list_free(list);
		free(data);
		return NULL;
	}
	rz_list_del_n(uniq_list, rz_list_length(uniq_list) - 1);
	char *return_str = rz_list_to_str(uniq_list, '\n');

	rz_list_free(uniq_list);
	rz_list_free(list);
	free(data);
	return return_str;
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
