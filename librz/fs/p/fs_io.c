/* radare - LGPL - Copyright 2017-2019 - pancake */

#include <rz_fs.h>
#include <rz_lib.h>
#include <sys/stat.h>

static RzFSFile *fs_io_open(RzFSRoot *root, const char *path, bool create) {
	char *cmd = rz_str_newf ("m %s", path);
	char *res = root->iob.system (root->iob.io, cmd);
	R_FREE (cmd);
	if (res) {
		ut32 size = 0;
		if (sscanf (res, "%u", &size) != 1) {
			size = 0;
		}
		R_FREE (res);
		if (size == 0) {
			return NULL;
		}
		RzFSFile *file = rz_fs_file_new (root, path);
		if (!file) {
			return NULL;
		}
		file->ptr = NULL;
		file->p = root->p;
		file->size = size;
		return file;
	}
	return NULL;
}

static bool fs_io_read(RzFSFile *file, ut64 addr, int len) {
	RzFSRoot *root = file->root;
	char *abs_path = rz_fs_file_copy_abs_path (file);
	if (!abs_path) {
		return false;
	}
	char *cmd = rz_str_newf ("mg %s", abs_path);
	R_FREE (abs_path);
	if (!cmd) {
		return false;
	}
	char *res = root->iob.system (root->iob.io, cmd);
	R_FREE (cmd);
	if (res) {
		int encoded_size = strlen (res);
		if (encoded_size != len * 2) {
			eprintf ("Unexpected size (%d vs %d)\n", encoded_size, len*2);
			R_FREE (res);
			return false;
		}
		file->data = (ut8 *) calloc (1, len);
		if (!file->data) {
			R_FREE (res);
			return false;
		}
		int ret = rz_hex_str2bin (res, file->data);
		if (ret != len) {
			eprintf ("Inconsistent read\n");
			R_FREE (file->data);
		}
		R_FREE (res);
	}
	return false;
}

static void fs_io_close(RzFSFile *file) {
	// fclose (file->ptr);
}

static void append_file(RzList *list, const char *name, int type, int time, ut64 size) {
	RzFSFile *fsf = rz_fs_file_new (NULL, name);
	if (!fsf) {
		return;
	}
	fsf->type = type;
	fsf->time = time;
	fsf->size = size;
	rz_list_append (list, fsf);
}

static RzList *fs_io_dir(RzFSRoot *root, const char *path, int view /*ignored*/) {
	RzList *list = rz_list_new ();
	if (!list) {
		return NULL;
	}
	char *cmd = rz_str_newf ("md %s", path);
	char *res = root->iob.system (root->iob.io, cmd);
	if (res) {
		size_t i, count = 0;
		size_t *lines = rz_str_split_lines (res, &count);
		if (lines) {
			for (i = 0; i < count; i++) {
				const char *line = res + lines[i];
				if (!*line) {
					continue;
				}
				char type = 'f';
				if (line[1] == ' ' && line[0] != ' ') {
					type = line[0];
					line += 2;
				}
				append_file (list, line, type, 0, 0);
			}
			R_FREE (res);
			R_FREE (lines);
		}
	}
	R_FREE (cmd);
	return list;
}

static int fs_io_mount(RzFSRoot *root) {
	root->ptr = NULL;
	return true;
}

static void fs_io_umount(RzFSRoot *root) {
	root->ptr = NULL;
}

RzFSPlugin rz_fs_plugin_io = {
	.name = "io",
	.desc = "rz_io based filesystem",
	.license = "MIT",
	.open = fs_io_open,
	.read = fs_io_read,
	.close = fs_io_close,
	.dir = &fs_io_dir,
	.mount = fs_io_mount,
	.umount = fs_io_umount,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &rz_fs_plugin_io,
	.version = R2_VERSION
};
#endif
