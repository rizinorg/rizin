/* radare - LGPL - Copyright 2011-2017 - pancake */

#include <rz_fs.h>
#include <rz_lib.h>
#include <sys/stat.h>
#ifdef _MSC_VER
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define MAXPATHLEN 255
#endif
static RzFSFile* fs_posix_open(RzFSRoot *root, const char *path, bool create) {
	FILE *fd;
	RzFSFile *file = rz_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}
	file->ptr = NULL;
	file->p = root->p;
	fd = rz_sandbox_fopen (path, create? "wb": "rb");
	if (fd) {
		fseek (fd, 0, SEEK_END);
		file->size = ftell (fd);
		fclose (fd);
	} else {
		rz_fs_file_free (file);
		file = NULL;
	}
	return file;
}

static bool fs_posix_read(RzFSFile *file, ut64 addr, int len) {
	free (file->data);
	file->data = (void*)rz_file_slurp_range (file->name, 0, len, NULL);
	return false;
}

static void fs_posix_close(RzFSFile *file) {
	//fclose (file->ptr);
}

static RzList *fs_posix_dir(RzFSRoot *root, const char *path, int view /*ignored*/) {
	RzList *list;
	char fullpath[4096];
	struct stat st;
#if __WINDOWS__
	WIN32_FIND_DATAW entry;
	HANDLE fh;
	wchar_t *wcpath;
	char *wctocbuff;
	wchar_t directory[MAX_PATH];
#else
	struct dirent *de;
	DIR *dir;
#endif
	list = rz_list_new ();
	if (!list) {
		return NULL;
	}
#if __WINDOWS__
	wcpath = rz_utf8_to_utf16 (path);
	if (!wcpath) {
		return NULL;
	}
	swprintf (directory, _countof (directory), L"%ls\\*.*", wcpath);
	fh = FindFirstFileW (directory, &entry);
	if (fh == INVALID_HANDLE_VALUE) {
		free (wcpath);
		return NULL;
	}
	do {
		if ((wctocbuff = rz_utf16_to_utf8 (entry.cFileName))) {
			RzFSFile *fsf = rz_fs_file_new (NULL, wctocbuff);
			if (!fsf) {
				rz_list_free (list);
				FindClose (fh);
				return NULL;
			}
			fsf->type = 'f';
			snprintf (fullpath, sizeof (fullpath)-1, "%s/%s", path, wctocbuff);
			if (!stat (fullpath, &st)) {
				fsf->type = S_ISDIR (st.st_mode)?'d':'f';
				fsf->time = st.st_atime;
			} else {
				fsf->type = 'f';
				fsf->time = 0;
			}
			rz_list_append (list, fsf);
			free (wctocbuff);
		}

	} while (FindNextFileW (fh, &entry));
	FindClose (fh);
#else
	dir = opendir (path);
	if (!dir) {
		rz_list_free (list);
		return NULL;
	}
	while ((de = readdir (dir))) {
		RzFSFile *fsf = rz_fs_file_new (NULL, de->d_name);
		if (!fsf) {
			rz_list_free (list);
			closedir (dir);
			return NULL;
		}
		fsf->type = 'f';
		snprintf (fullpath, sizeof (fullpath)-1, "%s/%s", path, de->d_name);
		if (!stat (fullpath, &st)) {
			fsf->type = S_ISDIR (st.st_mode)?'d':'f';
			fsf->time = st.st_atime;
		} else {
			fsf->type = 'f';
			fsf->time = 0;
		}
		rz_list_append (list, fsf);
	}
	closedir (dir);
#endif
	return list;
}

static int fs_posix_mount(RzFSRoot *root) {
	root->ptr = NULL; // XXX: TODO
	return true;
}

static void fs_posix_umount(RzFSRoot *root) {
	root->ptr = NULL;
}

RzFSPlugin rz_fs_plugin_posix = {
	.name = "posix",
	.desc = "POSIX filesystem",
	.license = "MIT",
	.open = fs_posix_open,
	.read = fs_posix_read,
	.close = fs_posix_close,
	.dir = &fs_posix_dir,
	.mount = fs_posix_mount,
	.umount = fs_posix_umount,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
        .type = RZ_LIB_TYPE_FS,
        .data = &rz_fs_plugin_posix,
        .version = RZ_VERSION
};
#endif
