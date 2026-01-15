// SPDX-FileCopyrightText: 2011-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
/* $OpenBSD: magic.c,v 1.8 2009/10/27 23:59:37 deraadt Exp $ */

#include <rz_magic.h>
#include <rz_util.h>
#include "magic.h"

RZ_LIB_VERSION(rz_magic);

#ifdef _MSC_VER
#include <io.h>
#include <sys\stat.h>
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_IFIFO     (-1)
#define S_ISFIFO(m) (((m) & S_IFIFO) == S_IFIFO)
#define MAXPATHLEN  255
#endif

static void magic_node_free_rb(RBNode *node, void *user) {
	RzMagicLine *ml = container_of(node, RzMagicLine, rb);
	rz_magic_line_free(ml);
}

static bool magic_load_file(RZ_NONNULL RZ_BORROW RzMagic *m, const char *file_path) {
	rz_return_val_if_fail(m, false);

	int result;
	FILE *file = fopen(file_path, "r");
	if (!file) {
		return false;
	}
	result = magic_load(m, file);
	fclose(file);
	return result;
}

/* API */

RZ_API RZ_OWN RzMagic *rz_magic_new() {
	return RZ_NEW0(RzMagic);
}

RZ_API void rz_magic_free(RZ_NULLABLE RZ_OWN RzMagic *m) {
	if (!m) {
		return;
	}
	free(m->path);
	rz_rbtree_free(m->magic_tree, magic_node_free_rb, NULL);
	rz_rbtree_free(m->magic_named_tree, magic_node_free_rb, NULL);
	rz_regex_free(m->format_short);
	rz_regex_free(m->format_long);
	rz_regex_free(m->format_quad);
	rz_regex_free(m->format_float);
	rz_regex_free(m->format_string);
	free(m);
}

/**
 * \brief Load magic rules from magic_path and store them in the RzMagic context
 *
 */
RZ_API bool rz_magic_load(RZ_NONNULL RZ_BORROW RzMagic *m, RZ_NONNULL const char *magic_path) {
	rz_return_val_if_fail(m, false);

	if (m->path) {
		free(m->path);
	}
	m->path = rz_str_dup(magic_path);

	if (rz_file_is_directory(magic_path)) {
		RzList *files = rz_sys_dir(magic_path);
		if (!files) {
			return false;
		}
		RzListIter *it;
		const char *subname;
		char *filepath = NULL;
		RzStrBuf subpath;
		rz_strbuf_init(&subpath);
		bool result = true;
		rz_list_foreach (files, it, subname) {
			if (RZ_STR_EQ(subname, ".")) {
				continue;
			}
			if (RZ_STR_EQ(subname, "..")) {
				continue;
			}
			filepath = rz_file_path_join(magic_path, subname);
			result &= magic_load_file(m, filepath);
			if (!result) {
				RZ_LOG_WARN("Failed to load magic file '%s'.\n", filepath);
				break;
			}
			free(filepath);
		}
		rz_list_free(files);
		return result;
	}
	return magic_load_file(m, magic_path);
}

/**
 * \brief Test buf against the loaded magic rules
 */
RZ_API RZ_OWN char *rz_magic_buffer(RZ_NONNULL const RzMagic *m, RZ_NONNULL const ut8 *buf, size_t nb) {
	rz_return_val_if_fail(m && buf, NULL);

	if (nb == 0) {
		return NULL;
	}

	char *output = magic_test(m, buf, nb, MAGIC_TEST_TEXT);
	if (!output) {
		return magic_test(m, buf, nb, 0);
	}
	return output;
}

RZ_OWN RzMagicLine *rz_magic_line_new(void) {
	RzMagicLine *ml = RZ_NEW0(RzMagicLine);
	if (!ml) {
		return NULL;
	}
	ml->children = rz_list_new();
	if (!ml->children) {
		rz_magic_line_free(ml);
		return NULL;
	}
	return ml;
}

void rz_magic_line_free(RZ_OWN RZ_NULLABLE RzMagicLine *ml) {
	if (!ml) {
		return;
	}
	while (!rz_list_empty(ml->children)) {
		RzMagicLine *child = rz_list_pop(ml->children);
		rz_magic_line_free(child);
	}
	rz_list_free(ml->children);
	free(ml->type_string);
	free(ml->result);
	free(ml->mimetype);
	free(ml->name);
	free(ml->test_string);
	free(ml);
}