// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#define URI_SCHEME     "vfile://"
#define URI_SCHEME_LEN 8

typedef struct {
	RzBinFile *bf;
	RzBinVirtualFile *vfile;
	ut64 off;
} VFileCtx;

extern RzIOPlugin rz_core_io_plugin_vfile;

static bool vf_check(RzIO *io, const char *pathname, bool many) {
	// be careful if changing this, vf_open relies on its behavior!
	return !strncmp(pathname, URI_SCHEME, URI_SCHEME_LEN);
}

static RzBinVirtualFile *find_vfile(RzBinFile *bf, const char *name) {
	if (!bf->o || !bf->o->vfiles) {
		return NULL;
	}
	void **it;
	RzBinVirtualFile *vfile;
	rz_pvector_foreach (bf->o->vfiles, it) {
		vfile = *it;
		if (!strcmp(vfile->name, name)) {
			return vfile;
		}
	}
	return NULL;
}

static RzIODesc *vf_open(RzIO *io, const char *pathname, int rw, int mode) {
	if (!vf_check(io, pathname, false)) {
		return NULL;
	}
	char *vfile_path = rz_str_dup(pathname + URI_SCHEME_LEN); // path like "<binfile id>/<filename>"
	if (!vfile_path) {
		return NULL;
	}
	RzIODesc *desc = NULL;
	char *filename = strchr(vfile_path, '/');
	if (!filename) {
		RZ_LOG_ERROR("Invalid URI \"%s\", expected " URI_SCHEME "<fd>/<filename>\n", pathname);
		goto beach;
	}
	*filename++ = '\0';
	ut32 bfid = (ut32)strtoull(vfile_path, NULL, 0);
	RzCore *core = io->corebind.core; // We are in the core already so this is fine.
	RzBinFile *bf = rz_bin_file_find_by_id(core->bin, bfid);
	if (!bf) {
		RZ_LOG_ERROR("No bin file for id %" PFMT32u " from URI \"%s\"\n", bfid, pathname);
		goto beach;
	}
	RzBinVirtualFile *vfile = find_vfile(bf, filename);
	if (!vfile) {
		RZ_LOG_ERROR("No virtual file called \"%s\" for bin file id %" PFMT32u " from URI \"%s\"\n", filename, bfid, pathname);
		goto beach;
	}
	VFileCtx *ctx = RZ_NEW(VFileCtx);
	if (!ctx) {
		goto beach;
	}
	ctx->bf = bf;
	ctx->vfile = vfile;
	ctx->off = 0;
	desc = rz_io_desc_new(io, &rz_core_io_plugin_vfile, pathname, rw, mode, ctx);
	if (!desc) {
		free(ctx);
	}
beach:
	free(vfile_path);
	return desc;
}

static int vf_write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	rz_return_val_if_fail(fd && fd->data, -1);
	if (!(fd->perm & RZ_PERM_W)) {
		return -1;
	}
	VFileCtx *ctx = fd->data;
	return rz_buf_write_at(ctx->vfile->buf, ctx->off, buf, count);
}

static int vf_read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	rz_return_val_if_fail(fd && fd->data, -1);
	VFileCtx *ctx = fd->data;
	return rz_buf_read_at(ctx->vfile->buf, ctx->off, buf, count);
}

static int vf_close(RzIODesc *fd) {
	rz_return_val_if_fail(fd && fd->data, -1);
	VFileCtx *ctx = fd->data;
	free(ctx);
	fd->data = NULL;
	return 0;
}

static ut64 vf_lseek(struct rz_io_t *io, RzIODesc *fd, ut64 offset, int whence) {
	rz_return_val_if_fail(fd && fd->data, UT64_MAX);
	VFileCtx *ctx = fd->data;
	// we store the offset ourselves instead of using the RzBuffer's because
	// there might be multiple io files accessing the same vfile.
	switch (whence) {
	case SEEK_SET:
		ctx->off = offset;
		break;
	case SEEK_CUR:
		ctx->off += offset;
		break;
	case SEEK_END:
		ctx->off = rz_buf_size(ctx->vfile->buf);
		break;
	}
	return ctx->off;
}

static bool vf_resize(RzIO *io, RzIODesc *fd, ut64 size) {
	rz_return_val_if_fail(fd && fd->data, false);
	VFileCtx *ctx = fd->data;
	return rz_buf_resize(ctx->vfile->buf, size);
}

/**
 * \brief IO Plugin that opens RzBinVirtualFiles supplied by the plugin of an RzBinFile.
 *
 * URIs look like `vfile://1/decompressed_data_0` where `1` is the id of a loaded RzBinFile
 * and `decompressed_data_0` is the name of the RzBinVirtualFile inside this RzBinFile
 * that provides the data.
 */
RZ_IPI RzIOPlugin rz_core_io_plugin_vfile = {
	.name = "vfile",
	.desc = "Virtual Files provided by RzBin Files",
	.uris = URI_SCHEME,
	.license = "LGPL",
	.open = vf_open,
	.close = vf_close,
	.read = vf_read,
	.check = vf_check,
	.lseek = vf_lseek,
	.write = vf_write,
	.resize = vf_resize
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_vfile,
	.version = RZ_VERSION
};
#endif

RZ_IPI void rz_core_vfile_bin_file_deleted(RzCore *core, RzBinFile *bf) {
	// close all vfile descs that point into the binfile that is about to be closed
	// This is strictly necessary because VFileCtx holds pointers into it!
	RzList *descs = rz_id_storage_list(core->io->files);
	if (!descs) {
		return;
	}
	RzListIter *it;
	RzIODesc *desc;
	rz_list_foreach (descs, it, desc) {
		if (strcmp(desc->plugin->name, rz_core_io_plugin_vfile.name)) {
			continue;
		}
		VFileCtx *ctx = desc->data;
		if (ctx->bf == bf) {
			rz_io_desc_close(desc);
		}
	}
	rz_list_free(descs);
}
