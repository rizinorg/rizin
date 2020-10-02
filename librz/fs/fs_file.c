/* radare - LGPL - Copyright 2011-2019 - pancake */

#include <rz_fs.h>

RZ_API RzFSFile* rz_fs_file_new(RzFSRoot* root, const char* path) {
	RzFSFile* file = RZ_NEW0 (RzFSFile);
	if (!file) {
		return NULL;
	}
	file->root = root;
	if (root) {
		file->p = file->root->p; // XXX dupe
	}
	file->path = strdup (path);
	char *last = (char *)rz_str_rchr (file->path, NULL, '/');
	if (last) {
		*last++ = 0;
		file->name = strdup (last);
	} else {
		file->name = strdup (path);
	}
	return file;
}

RZ_API void rz_fs_file_free(RzFSFile* file) {
	if (file) {
		free (file->path);
		free (file->name);
		free (file->data);
		free (file);
	}
}

RZ_API char* rz_fs_file_copy_abs_path(RzFSFile* file) {
	if (!file) {
		return NULL;
	}
	if (!strcmp (file->path, file->name)) {
		return strdup (file->path);
	}
	return rz_str_newf ("%s/%s", file->path, file->name);
}

// TODO: Use RzFSRoot and pass it in the stack instead of heap? problematic with bindings
RZ_API RzFSRoot* rz_fs_root_new(const char* path, ut64 delta) {
	char* p;
	RzFSRoot* root = RZ_NEW0 (RzFSRoot);
	if (!root) {
		return NULL;
	}
	root->path = strdup (path);
	if (!root->path) {
		RZ_FREE (root);
		return NULL;
	}
	p = root->path + strlen (path);
	if (*p == '/') {
		*p = 0;        // chop tailing slash
	}
	root->delta = delta;
	return root;
}

RZ_API void rz_fs_root_free(RzFSRoot* root) {
	if (root) {
		if (root->p && root->p->umount) {
			root->p->umount (root);
		}
		free (root->path);
		free (root);
	}
}

RZ_API RzFSPartition* rz_fs_partition_new(int num, ut64 start, ut64 length) {
	RzFSPartition* p = RZ_NEW0 (RzFSPartition);
	if (!p) {
		return NULL;
	}
	p->number = num;
	p->type = 0; // TODO we need an enum with all the partition types
	p->start = start;
	p->length = length;
	return p;
}

RZ_API void rz_fs_partition_free(RzFSPartition* p) {
	free (p);
}
