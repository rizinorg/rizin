// SPDX-FileCopyrightText: 2017 xarkes <antide.petit@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_io.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_cons.h>
#include "ar.h"
#include "rz_io_plugins.h"

static bool rz_io_ar_plugin_open(RzIO *io, const char *file, bool many) {
	return !strncmp("ar://", file, 5) || !strncmp("lib://", file, 6);
}

static RzList /*<RzIODesc *>*/ *rz_io_ar_open_many(RzIO *io, const char *file, int perm, int mode) {
	const char *arname = strstr(file, "://");
	if (!arname) {
		return NULL;
	}
	arname += 3;

	RzList *all = ar_open_all(arname, rz_sys_open_perms(perm));
	if (!all) {
		RZ_LOG_ERROR("ar: cannot open all .o files in '%s'\n", file);
		return NULL;
	}

	RzList *list_fds = rz_list_new();
	if (!list_fds) {
		rz_list_free(all);
		return NULL;
	}

	RzArFp *arfp;
	RzListIter *it;

	rz_list_foreach (all, it, arfp) {
		char *uri_name = rz_str_newf("%s//%s", file, arfp->name);
		RzIODesc *desc = rz_io_desc_new(io, &rz_io_plugin_ar, uri_name, perm, mode, arfp);
		free(uri_name);
		if (!desc) {
			rz_list_free(all);
			rz_list_free(list_fds);
			return NULL;
		}
		desc->name = rz_str_dup(arfp->name);
		if (!rz_list_append(list_fds, desc)) {
			rz_list_free(all);
			rz_list_free(list_fds);
			return NULL;
		}
		rz_list_iter_set_data(it, NULL);
	}
	rz_list_free(all);
	return list_fds;
}

static RzIODesc *rz_io_ar_open(RzIO *io, const char *file, int perm, int mode) {
	rz_return_val_if_fail(io && file, NULL);
	RzIODesc *res = NULL;
	char *uri = rz_str_dup(file);
	if (!uri) {
		return NULL;
	}
	const char *arname = strstr(uri, "://");
	if (!arname) {
		goto err;
	}
	arname += 3;

	char *filename = strstr(arname, "//");
	if (!filename) {
		goto err;
	}
	*filename = 0;
	filename += 2;

	RzArFp *arf = ar_open_file(arname, rz_sys_open_perms(perm), filename);
	if (!arf) {
		goto err;
	}
	res = rz_io_desc_new(io, &rz_io_plugin_ar, filename, perm, mode, arf);
	if (!res) {
		goto err;
	}
	res->name = rz_str_dup(filename);
err:
	free(uri);
	return res;
}

static ut64 rz_io_ar_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	rz_return_val_if_fail(io && fd && fd->data, -1);

	RzArFp *arf = (RzArFp *)fd->data;
	ut64 size = arf->end - arf->start;
	switch (whence) {
	case SEEK_SET:
		io->off = RZ_MIN(size, offset);
		break;
	case SEEK_CUR:
		io->off = RZ_MIN(size, io->off + offset);
		break;
	case SEEK_END:
		io->off = size;
		break;
	default:
		return -1;
	}

	return io->off;
}

static int rz_io_ar_read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	int res = ar_read_at((RzArFp *)fd->data, io->off, buf, count);
	if (res > 0) {
		io->off += res;
	}
	return res;
}

static int rz_io_ar_write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	int res = ar_write_at((RzArFp *)fd->data, io->off, (void *)buf, count);
	if (res > 0) {
		io->off += res;
	}
	return res;
}

static int rz_io_ar_close(RzIODesc *fd) {
	if (!fd || !fd->data) {
		return -1;
	}
	ar_close((RzArFp *)fd->data);
	fd->data = NULL;
	return 0;
}

RzIOPlugin rz_io_plugin_ar = {
	.name = "ar",
	.desc = "Open ar/lib files",
	.license = "LGPL3",
	.author = "xarkes",
	.uris = "ar://,lib://",
	.open = rz_io_ar_open,
	.open_many = rz_io_ar_open_many,
	.write = rz_io_ar_write,
	.read = rz_io_ar_read,
	.close = rz_io_ar_close,
	.lseek = rz_io_ar_lseek,
	.check = rz_io_ar_plugin_open
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_ar,
	.version = RZ_VERSION
};
#endif
