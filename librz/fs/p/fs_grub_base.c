/* radare - LGPL - Copyright 2011-2020 - pancake */

#include <rz_fs.h>
#include "grubfs.h"

#if WITH_GPL

static RzFSFile* FSP(_open)(RzFSRoot *root, const char *path, bool create) {
	RzFSFile *file = rz_fs_file_new (root, path);
	GrubFS *gfs = grubfs_new (&FSIPTR, &root->iob);
	file->ptr = gfs;
	file->p = root->p;
	grubfs_bind_io (NULL, file->root->delta);
	if (gfs->file->fs->open (gfs->file, path)) {
		rz_fs_file_free (file);
		grubfs_free (gfs);
		file = NULL;
	} else {
		file->size = gfs->file->size;
		file->off = gfs->file->offset;
	}
	return file;
}

static bool FSP(_read)(RzFSFile *file, ut64 addr, int len) {
	GrubFS *gfs = file->ptr;
	grubfs_bind_io (NULL, file->root->delta);
	gfs->file->fs->read (gfs->file, (char*)file->data, len);
	file->off = grub_hack_lastoff; //gfs->file->offset;
	return false;
}

static void FSP(_close)(RzFSFile *file) {
	GrubFS *gfs = file->ptr;
	gfs->file->fs->close (gfs->file);
}

static RzList *list = NULL;

static int dirhook (const char *filename, const struct grub_dirhook_info *info, void *closure) {
	RzFSFile *fsf = rz_fs_file_new (NULL, filename);
	fsf->type = info->dir? 'd':'f';
	fsf->time = info->mtime;
	rz_list_append (list, fsf);
	//info->mtimeset
	//info->case_insensitive
	//printf ("DIRFILE: %c (%d) %s\n", info->dir?'d':'f', info->mtime, filename);
	return 0;
}

static RzList *FSP(_dir)(RzFSRoot *root, const char *path, int view) {
	GrubFS *gfs;

	if (!root)
		return NULL;

	gfs = root->ptr;
	list = rz_list_new ();
//	eprintf ("rz_fs_???_dir: %s\n", path);
	//gfs->file->device->data = &root->iob;
	grubfs_bind_io (&root->iob, root->delta);
	gfs->file->fs->dir (gfs->file->device, path, dirhook, 0);
	grubfs_bind_io (NULL, root->delta);
	return list;
}

static int do_nothing (const char *a, const struct grub_dirhook_info *b, void *c) { return 0; }

static int FSP(_mount)(RzFSRoot *root) {
	int ret;
	GrubFS *gfs = grubfs_new (&FSIPTR, &root->iob);
	root->ptr = gfs;
	grubfs_bind_io (&root->iob, root->delta);
	// XXX: null hook seems to be problematic on some filesystems
	//return gfs->file->fs->dir (gfs->file->device, "/", NULL, 0)? false:true;
	ret = gfs->file->fs->dir (gfs->file->device, "/", do_nothing, 0)? false:true;
	grubfs_bind_io (NULL, root->delta);
	return ret;
}

static void FSP(_umount)(RzFSRoot *root) {
	grubfs_free (root->ptr);
	root->ptr = NULL;
}

RzFSPlugin FSS(rz_fs_plugin) = {
	.name = FSNAME,
	.desc = FSDESC,
	.license = "GPL2",
	.open = FSP(_open),
	.read = FSP(_read),
	.close = FSP(_close),
	.dir = FSP(_dir),
	.mount = FSP(_mount),
	.umount = FSP(_umount),
};
#else
RzFSPlugin FSS(rz_fs_plugin) = {
	.name = FSNAME,
	.desc = FSDESC,
};
#endif
