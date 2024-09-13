// SPDX-FileCopyrightText: 2012-2016 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2016 Adam Pridgen <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_cons.h>
#include <zip.h>

#include "rz_io_plugins.h"

typedef enum {
	RZ_IO_PARENT_ZIP = 0x0001,
	RZ_IO_CHILD_FILE = 0x0002,
	RZ_IO_NEW_FILE = 0x0004,
	RZ_IO_EXISTING_FILE = 0x0008,
	RZ_IO_MODIFIED_FILE = 0x0010,
	RZ_IO_DELETED_FILE = 0x0020,
} RZ_IO_ZIP_ARCHIVE_TYPE;

typedef struct rz_io_zip_uri_const_t {
	const char *name;
	ut32 len;
} RzIOZipConstURI;

static RzIOZipConstURI ZIP_URIS[] = {
	{ "zip://", 6 },
	{ "apk://", 6 },
	{ "ipa://", 6 },
	{ "jar://", 6 },
	{ NULL, 0 }
};

static RzIOZipConstURI ZIP_ALL_URIS[] = {
	{ "zipall://", 9 },
	{ "apkall://", 9 },
	{ "ipaall://", 9 },
	{ "jarall://", 9 },
	{ NULL, 0 }
};

typedef struct rz_io_zfo_t {
	char *name;
	char *archivename;
	int mode;
	int rw;
	int fd;
	int opened;
	ut64 entry;
	int perm;
	ut8 modified;
	RzBuffer *b;
	char *password;
	ut8 encryption_value;
	RzIO *io_backref;
} RzIOZipFileObj;

static int rz_io_zip_has_uri_substr(const char *file) {
	return (file && strstr(file, "://"));
}

static int rz_io_zip_check_uri_many(const char *file) {
	int i;
	if (rz_io_zip_has_uri_substr(file)) {
		for (i = 0; ZIP_ALL_URIS[i].name != NULL; i++) {
			if (!strncmp(file, ZIP_ALL_URIS[i].name, ZIP_ALL_URIS[i].len) && file[ZIP_ALL_URIS[i].len]) {
				return true;
			}
		}
	}
	return false;
}

static int rz_io_zip_check_uri(const char *file) {
	int i;
	if (rz_io_zip_has_uri_substr(file)) {
		for (i = 0; ZIP_URIS[i].name != NULL; i++) {
			if (!strncmp(file, ZIP_URIS[i].name, ZIP_URIS[i].len) && file[ZIP_URIS[i].len]) {
				return true;
			}
		}
	}
	return false;
}

static bool rz_io_zip_plugin_open(RzIO *io, const char *file, bool many) {
	if (io && file) {
		if (many) {
			return rz_io_zip_check_uri_many(file);
		}
		return rz_io_zip_check_uri(file);
	}
	return false;
}

struct zip *rz_io_zip_open_archive(const char *archivename, ut32 perm, int mode, int rw) {
	struct zip *zipArch = NULL;
	int zip_errorp;
	if (!archivename) {
		return NULL;
	}
	if ((zipArch = zip_open(archivename, perm, &zip_errorp))) {
		return zipArch;
	}
	if (zip_errorp == ZIP_ER_INVAL) {
		eprintf("ZIP File Error: Invalid file name (NULL).\n");
	} else if (zip_errorp == ZIP_ER_OPEN) {
		eprintf("ZIP File Error: File could not be opened file name.\n");
	} else if (zip_errorp == ZIP_ER_NOENT) {
		eprintf("ZIP File Error: File does not exist.\n");
	} else if (zip_errorp == ZIP_ER_READ) {
		eprintf("ZIP File Error: Read error occurred.\n");
	} else if (zip_errorp == ZIP_ER_NOZIP) {
		eprintf("ZIP File Error: File is not a valid ZIP archive.\n");
	} else if (zip_errorp == ZIP_ER_INCONS) {
		eprintf("ZIP File Error: ZIP file had some inconsistencies archive.\n");
	} else {
		eprintf("ZIP File Error: Something bad happened, get your debug on.\n");
	}
	return NULL;
}

static int rz_io_zip_slurp_file(RzIOZipFileObj *zfo) {
	struct zip_file *zFile = NULL;
	struct zip *zipArch;
	struct zip_stat sb;
	bool res = false;
	if (!zfo) {
		return res;
	}
	zipArch = rz_io_zip_open_archive(
		zfo->archivename, zfo->perm,
		zfo->mode, zfo->rw);

	if (zipArch && zfo && zfo->entry != -1) {
		zFile = zip_fopen_index(zipArch, zfo->entry, 0);
		if (!zFile) {
			zip_close(zipArch);
			return false;
		}
		if (!zfo->b) {
			zfo->b = rz_buf_new_with_bytes(NULL, 0);
		}
		zip_stat_init(&sb);
		if (zfo->b && !zip_stat_index(zipArch, zfo->entry, 0, &sb)) {
			ut8 *buf = calloc(1, sb.size);
			if (buf) {
				zip_fread(zFile, buf, sb.size);
				rz_buf_set_bytes(zfo->b, buf, sb.size);
				res = true;
				zfo->opened = true;
				free(buf);
			}
		}
		zip_fclose(zFile);
	}
	zip_close(zipArch);
	return res;
}

RzList /*<char *>*/ *rz_io_zip_get_files(const char *archivename, ut32 perm, int mode, int rw) {
	struct zip *zipArch = rz_io_zip_open_archive(archivename, perm, mode, rw);
	ut64 num_entries = 0, i = 0;
	struct zip_stat sb;
	char *name = NULL;
	RzList *files = NULL;
	if (!zipArch) {
		return NULL;
	}

	files = rz_list_newf(free);
	if (!files) {
		zip_close(zipArch);
		return NULL;
	}

	num_entries = zip_get_num_files(zipArch);
	for (i = 0; i < num_entries; i++) {
		zip_stat_init(&sb);
		zip_stat_index(zipArch, i, 0, &sb);
		if ((name = rz_str_dup(sb.name))) {
			rz_list_append(files, name);
		}
	}
	zip_close(zipArch);
	return files;
}

int rz_io_zip_flush_file(RzIOZipFileObj *zfo) {
	int res = false;
	struct zip *zipArch;

	if (!zfo) {
		return res;
	}

	zipArch = rz_io_zip_open_archive(
		zfo->archivename, zfo->perm, zfo->mode, zfo->rw);
	if (!zipArch) {
		return res;
	}

	ut64 tmpsz;
	const ut8 *tmp = rz_buf_data(zfo->b, &tmpsz);
	struct zip_source *s = zip_source_buffer(zipArch, tmp, tmpsz, 0);
	if (s && zfo->entry != -1) {
		if (zip_replace(zipArch, zfo->entry, s) == 0) {
			res = true;
		}
	} else if (s && zfo->name) {
		if (zip_add(zipArch, zfo->name, s) == 0) {
			zfo->entry = zip_name_locate(zipArch, zfo->name, 0);
			res = true;
		}
	}
	// s (zip_source) is freed when the archive is closed, i think - dso
	zip_close(zipArch);
	if (s) {
		zip_source_free(s);
	}
	return res;
}

static void rz_io_zip_free_zipfileobj(RzIOZipFileObj *zfo) {
	if (!zfo) {
		return;
	}
	if (zfo->modified) {
		rz_io_zip_flush_file(zfo);
	}
	free(zfo->name);
	free(zfo->password);
	rz_buf_free(zfo->b);
	free(zfo);
}

RzIOZipFileObj *rz_io_zip_create_new_file(const char *archivename, const char *filename, struct zip_stat *sb, ut32 perm, int mode, int rw) {
	RzIOZipFileObj *zfo = RZ_NEW0(RzIOZipFileObj);
	if (zfo) {
		zfo->b = rz_buf_new_with_bytes(NULL, 0);
		zfo->archivename = rz_str_dup(archivename);
		zfo->name = rz_str_dup(sb ? sb->name : filename);
		zfo->entry = !sb ? -1 : sb->index;
		zfo->fd = rz_num_rand32(0xFFFF); // XXX: Use rz_io_fd api
		zfo->perm = perm;
		zfo->mode = mode;
		zfo->rw = rw;
	}
	return zfo;
}

/* The file can be a file in the archive or ::[num].  */
RzIOZipFileObj *rz_io_zip_alloc_zipfileobj(const char *archivename, const char *filename, ut32 perm, int mode, int rw) {
	RzIOZipFileObj *zfo = NULL;
	ut64 i, num_entries;
	struct zip_stat sb;
	struct zip *zipArch = rz_io_zip_open_archive(archivename, perm, mode, rw);
	if (!zipArch) {
		return NULL;
	}
	num_entries = zip_get_num_files(zipArch);

	for (i = 0; i < num_entries; i++) {
		zip_stat_init(&sb);
		zip_stat_index(zipArch, i, 0, &sb);
		if (sb.name != NULL) {
			if (strcmp(sb.name, filename) == 0) {
				zfo = rz_io_zip_create_new_file(
					archivename, filename, &sb,
					perm, mode, rw);
				rz_io_zip_slurp_file(zfo);
				break;
			}
		}
	}
	if (!zfo) {
		zfo = rz_io_zip_create_new_file(archivename,
			filename, NULL, perm, mode, rw);
	}
	zip_close(zipArch);
	return zfo;
}

// Below this line are the rz_io_zip plugin APIs
static RzList /*<RzIODesc *>*/ *rz_io_zip_open_many(RzIO *io, const char *file, int rw, int mode) {
	RzList *list_fds = NULL;
	RzListIter *iter;
	RzList *filenames = NULL;
	RzIODesc *res = NULL;
	RzIOZipFileObj *zfo = NULL;
	char *filename_in_zipfile, *zip_filename = NULL, *zip_uri;

	if (!rz_io_zip_plugin_open(io, file, true)) {
		return NULL;
	}

	zip_uri = rz_str_dup(file);
	if (!zip_uri) {
		return NULL;
	}
	// 1) Tokenize to the '//' and find the base file directory ('/')
	zip_filename = strstr(zip_uri, "//");
	if (zip_filename && zip_filename[2]) {
		if (zip_filename[0] && zip_filename[0] == '/' &&
			zip_filename[1] && zip_filename[1] == '/') {
			*zip_filename++ = 0;
		}
		*zip_filename++ = 0;
	} else {
		free(zip_uri);
		return NULL;
	}

	filenames = rz_io_zip_get_files(zip_filename, 0, mode, rw);

	if (!filenames) {
		free(zip_uri);
		return NULL;
	}

	list_fds = rz_list_new();
	rz_list_foreach (filenames, iter, filename_in_zipfile) {
		size_t v = strlen(filename_in_zipfile);

		if (filename_in_zipfile[v - 1] == '/') {
			continue;
		}

		zfo = rz_io_zip_alloc_zipfileobj(zip_filename,
			filename_in_zipfile, ZIP_CREATE, mode, rw);

		if (zfo && zfo->entry == -1) {
			eprintf("Warning: File did not exist, creating a new one.\n");
		}

		if (zfo) {
			zfo->io_backref = io;
			res = rz_io_desc_new(io, &rz_io_plugin_zip,
				zfo->name, rw, mode, zfo);
		}
		rz_list_append(list_fds, res);
	}

	free(zip_uri);
	rz_list_free(filenames);
	return list_fds;
}

char *rz_io_zip_get_by_file_idx(const char *archivename, const char *idx, ut32 perm, int mode, int rw) {
	char *filename = NULL;
	ut64 i, num_entries;
	ut32 file_idx = -1;
	struct zip_stat sb;
	struct zip *zipArch = rz_io_zip_open_archive(archivename, perm, mode, rw);
	if (!idx || !zipArch) {
		zip_close(zipArch);
		return filename;
	}
	num_entries = zip_get_num_files(zipArch);
	file_idx = atoi(idx);
	if ((file_idx == 0 && idx[0] != '0') || (file_idx >= num_entries)) {
		zip_close(zipArch);
		return filename;
	}
	for (i = 0; i < num_entries; i++) {
		zip_stat_init(&sb);
		zip_stat_index(zipArch, i, 0, &sb);
		if (file_idx == i) {
			filename = rz_str_dup(sb.name);
			break;
		}
	}
	zip_close(zipArch);
	return filename;
}

static char *find_ipa_binary(const char *filename, int rw, int mode) {
	RzList *files = NULL;
	RzListIter *iter;
	char *name;
	int app_size = 0;
	const char *app_name;
	const char *last_slash;

	char *zip_filename = NULL;
	files = rz_io_zip_get_files(filename, 0, mode, rw);

	rz_list_foreach (files, iter, name) {
		/* Find matching file */
		app_name = strstr(name, ".app/");
		if (!app_name) {
			continue;
		}
		last_slash = rz_str_rchr(name, app_name, '/');
		if (!last_slash) {
			continue;
		}
		app_size = (app_name - last_slash) - 1;
		zip_filename = rz_str_newf("//Payload/%.*s.app/%.*s", app_size, last_slash + 1, app_size, last_slash + 1);
		if (zip_filename && !strcmp(name, zip_filename + 2)) {
			break;
		}
		RZ_FREE(zip_filename);
	}
	rz_list_free(files);

	return zip_filename;
}

static char *find_apk_binary(const char *filename, int rw, int mode, RzIO *io) {
	RzList *files = NULL;
	RzListIter *iter = NULL;
	char *name = NULL;
	RzIOZipFileObj *zfo = NULL;
	char *zip_filename = rz_str_newf("//%s//classes.dex", filename);
	files = rz_io_zip_get_files(filename, 0, mode, rw);

	if (files) {
		rz_list_foreach (files, iter, name) {
			/* Find matching file */
			if (!strcmp(name, "classes.dex")) {
				continue;
			} else if (rz_str_endswith(name, ".dex")) {
				RZ_LOG_INFO("Adding extra IO descriptor to file %s\n", name);
				zfo = rz_io_zip_alloc_zipfileobj(filename, name, ZIP_CREATE, mode, rw);
				if (!zfo) {
					eprintf("Error: cannot allocate zip file object.\n");
					continue;
				}
				if (zfo->entry == -1) {
					if (!rw) {
						eprintf("Warning: File %s does not exist.\n", name);
						rz_io_zip_free_zipfileobj(zfo);
						continue;
					}
					eprintf("Warning: File %s does not exist, creating a new one.\n", name);
				}
				zfo->io_backref = io;
				RzIODesc *desc = rz_io_desc_new(io, &rz_io_plugin_zip, zfo->name, rw, mode, zfo);
				desc->name = rz_str_dup(name);
				rz_io_desc_add(io, desc);
			}
		}
		rz_list_free(files);
	}

	return zip_filename;
}

static RzIODesc *rz_io_zip_open(RzIO *io, const char *file, int rw, int mode) {
	RzIODesc *res = NULL;
	char *uri_path, *tmp;
	RzIOZipFileObj *zfo = NULL;
	char *zip_uri = NULL, *zip_filename = NULL, *filename_in_zipfile = NULL;

	if (!rz_io_zip_plugin_open(io, file, false)) {
		return NULL;
	}
	zip_uri = rz_str_dup(file);
	if (!zip_uri) {
		return NULL;
	}
	uri_path = strstr(zip_uri, "://");
	if (uri_path) {
		tmp = strstr(uri_path + 3, "//");
		zip_filename = rz_str_dup(tmp);
		// 1) Tokenize to the '//' and find the base file directory ('/')
		if (!zip_filename) {
			if (!strncmp(zip_uri, "apk://", 6)) {
				zip_filename = find_apk_binary(uri_path + 3, rw, mode, io);
			} else if (!strncmp(zip_uri, "ipa://", 6)) {
				zip_filename = find_ipa_binary(uri_path + 3, rw, mode);
			} else {
				zip_filename = rz_str_dup(uri_path + 1);
			}
		} else {
			free(zip_filename);
			zip_filename = rz_str_dup(uri_path + 1);
		}
	}
	tmp = zip_filename;
	if (zip_filename && zip_filename[1] && zip_filename[2]) {
		if (zip_filename[0] && zip_filename[0] == '/' &&
			zip_filename[1] && zip_filename[1] == '/') {
			*zip_filename++ = 0;
		}
		*zip_filename++ = 0;

		// check for // for file in the archive
		if ((filename_in_zipfile = strstr(zip_filename, "//")) && filename_in_zipfile[2]) {
			// null terminating uri to filename here.
			*filename_in_zipfile++ = 0;
			*filename_in_zipfile++ = 0;
			filename_in_zipfile = rz_str_dup(filename_in_zipfile);
			// check for :: index
		} else if ((filename_in_zipfile = strstr(zip_filename, "::")) &&
			filename_in_zipfile[2]) {
			// null terminating uri to filename here.
			*filename_in_zipfile++ = 0;
			*filename_in_zipfile++ = 0;
			filename_in_zipfile = rz_io_zip_get_by_file_idx(
				zip_filename, filename_in_zipfile,
				ZIP_CREATE, mode, rw);
		} else {
			filename_in_zipfile = rz_str_newf("%s", zip_filename);
			RZ_FREE(tmp);
			zip_filename = rz_str_dup(uri_path + 3);
			if (!strcmp(zip_filename, filename_in_zipfile)) {
				// RZ_FREE (zip_filename);
				RZ_FREE(filename_in_zipfile);
			}
		}
	}

	if (!zip_filename) { // && !filename_in_zipfile) {
		// free (zip_uri);
		eprintf("usage: zip:///path/to/archive//filepath\n"
			"usage: zip:///path/to/archive::[number]\n"
			"Archive was not found.\n");
		// return res;
	}

	// Failed to find the file name the archive.
	if (!filename_in_zipfile) {
		RzList *files = NULL;
		RzListIter *iter;
		char *name;
		// eprintf("usage: zip:///path/to/archive//filepath\n");
		files = rz_io_zip_get_files(zip_filename, 0, mode, rw);
		if (files) {
			ut32 i = 0;
			rz_list_foreach (files, iter, name) {
				io->cb_printf("%d %s\n", i, name);
				i++;
			}
			rz_list_free(files);
		}
		goto done;
	}
	// eprintf("After parsing the given uri: %s\n", file);
	// eprintf("Zip filename the given uri: %s\n", zip_filename);
	// eprintf("File in the zip: %s\n", filename_in_zipfile);
	zfo = rz_io_zip_alloc_zipfileobj(zip_filename,
		filename_in_zipfile, ZIP_CREATE, mode, rw);

	if (zfo) {
		if (zfo->entry == -1) {
			eprintf("Warning: File %s does not exist, creating a new one.\n", filename_in_zipfile);
		}
		zfo->io_backref = io;
		res = rz_io_desc_new(io, &rz_io_plugin_zip,
			zfo->name, rw, mode, zfo);
	}

	if (!res) {
		eprintf("Failed to open the archive %s and file %s\n",
			zip_filename, filename_in_zipfile);
		// free (zfo); zfo is already freed by rz_io_desc_new
		rz_io_desc_free(res);
		res = NULL;
	}
done:
	free(filename_in_zipfile);
	free(zip_uri);
	free(tmp);
	return res;
}

static ut64 rz_io_zip_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	RzIOZipFileObj *zfo;
	ut64 seek_val = 0;

	if (!fd || !fd->data) {
		return -1;
	}

	zfo = fd->data;
	seek_val = rz_buf_tell(zfo->b);

	switch (whence) {
	case SEEK_SET:
		seek_val = (rz_buf_size(zfo->b) < offset) ? rz_buf_size(zfo->b) : offset;
		io->off = seek_val;
		rz_buf_seek(zfo->b, seek_val, RZ_BUF_SET);
		return seek_val;
	case SEEK_CUR:
		seek_val = (rz_buf_size(zfo->b) < (offset + rz_buf_tell(zfo->b))) ? rz_buf_size(zfo->b) : offset + rz_buf_tell(zfo->b);
		io->off = seek_val;
		rz_buf_seek(zfo->b, seek_val, RZ_BUF_SET);
		return seek_val;
	case SEEK_END:
		seek_val = rz_buf_size(zfo->b);
		io->off = seek_val;
		rz_buf_seek(zfo->b, seek_val, RZ_BUF_SET);
		return seek_val;
	}
	return seek_val;
}

static int rz_io_zip_read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	RzIOZipFileObj *zfo = NULL;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	zfo = fd->data;
	if (rz_buf_size(zfo->b) < io->off) {
		io->off = rz_buf_size(zfo->b);
	}
	int r = rz_buf_read_at(zfo->b, io->off, buf, count);
	if (r >= 0) {
		rz_buf_seek(zfo->b, r, RZ_BUF_CUR);
	}
	return r;
}

static int rz_io_zip_realloc_buf(RzIOZipFileObj *zfo, size_t count) {
	return rz_buf_resize(zfo->b, rz_buf_tell(zfo->b) + count);
}

static bool rz_io_zip_truncate_buf(RzIOZipFileObj *zfo, int size) {
	return rz_buf_resize(zfo->b, size > 0 ? size : 0);
}

static bool rz_io_zip_resize(RzIO *io, RzIODesc *fd, ut64 size) {
	RzIOZipFileObj *zfo;
	if (!fd || !fd->data) {
		return false;
	}
	zfo = fd->data;
	if (rz_io_zip_truncate_buf(zfo, size)) {
		zfo->modified = 1;
		rz_io_zip_flush_file(zfo);
		return true;
	}
	return false;
}

static int rz_io_zip_write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	RzIOZipFileObj *zfo;
	int ret = 0;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	zfo = fd->data;
	if (!(zfo->perm & RZ_PERM_W)) {
		return -1;
	}
	if (rz_buf_tell(zfo->b) + count >= rz_buf_size(zfo->b)) {
		rz_io_zip_realloc_buf(zfo, count);
	}
	if (rz_buf_size(zfo->b) < io->off) {
		io->off = rz_buf_size(zfo->b);
	}
	zfo->modified = 1;
	ret = rz_buf_write_at(zfo->b, io->off, buf, count);
	if (ret >= 0) {
		rz_buf_seek(zfo->b, ret, RZ_BUF_CUR);
	}
	// XXX - Implement a flush of some sort, but until then, lets
	// just write through
	rz_io_zip_flush_file(zfo);
	return ret;
}

static int rz_io_zip_close(RzIODesc *fd) {
	RzIOZipFileObj *zfo;
	if (!fd || !fd->data) {
		return -1;
	}
	zfo = fd->data;
	rz_io_zip_free_zipfileobj(zfo);
	zfo = fd->data = NULL;
	return 0;
}

RzIOPlugin rz_io_plugin_zip = {
	.name = "zip",
	.desc = "Open zip files",
	.uris = "zip://,apk://,ipa://,jar://,zipall://,apkall://,ipaall://,jarall://",
	.license = "BSD",
	.open = rz_io_zip_open,
	.open_many = rz_io_zip_open_many,
	.write = rz_io_zip_write,
	.read = rz_io_zip_read,
	.close = rz_io_zip_close,
	.lseek = rz_io_zip_lseek,
	.check = rz_io_zip_plugin_open,
	.resize = rz_io_zip_resize,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_zip,
	.version = RZ_VERSION
};
#endif
