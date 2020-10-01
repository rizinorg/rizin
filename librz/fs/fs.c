/* rizin - LGPL - Copyright 2011-2019 - pancake */

#include <rz_fs.h>
#include "config.h"
#include "types.h"
#include <errno.h>
#include "../../shlr/grub/include/grub/msdos_partition.h"

#if WITH_GPL
# ifndef USE_GRUB
#  define USE_GRUB 1
# endif
#endif

R_LIB_VERSION (rz_fs);

static RzFSPlugin* fs_static_plugins[] = {
	R_FS_STATIC_PLUGINS
};

RZ_API RzFS* rz_fs_new(void) {
	int i;
	RzFSPlugin* static_plugin;
	RzFS* fs = R_NEW0 (RzFS);
	if (fs) {
		fs->view = R_FS_VIEW_NORMAL;
		fs->roots = rz_list_new ();
		if (!fs->roots) {
			rz_fs_free (fs);
			return NULL;
		}
		fs->roots->free = (RzListFree) rz_fs_root_free;
		fs->plugins = rz_list_new ();
		if (!fs->plugins) {
			rz_fs_free (fs);
			return NULL;
		}
		fs->plugins->free = free;
		// XXX fs->roots->free = rz_fs_plugin_free;
		for (i = 0; fs_static_plugins[i]; i++) {
			static_plugin = R_NEW (RzFSPlugin);
			if (!static_plugin) {
				continue;
			}
			memcpy (static_plugin, fs_static_plugins[i], sizeof (RzFSPlugin));
			rz_fs_add (fs, static_plugin);
			free (static_plugin);
		}
	}
	return fs;
}

RZ_API RzFSPlugin* rz_fs_plugin_get(RzFS* fs, const char* name) {
	RzListIter* iter;
	RzFSPlugin* p;
	if (!fs || !name) {
		return NULL;
	}
	rz_list_foreach (fs->plugins, iter, p) {
		if (!strcmp (p->name, name)) {
			return p;
		}
	}
	return NULL;
}

RZ_API void rz_fs_free(RzFS* fs) {
	if (!fs) {
		return;
	}
	//rz_io_free (fs->iob.io);
	//root makes use of plugin so revert to avoid UaF
	rz_list_free (fs->roots);
	rz_list_free (fs->plugins);
	free (fs);
}

/* plugins */
RZ_API void rz_fs_add(RzFS* fs, RzFSPlugin* p) {
	// TODO: find coliding plugin name
	if (p && p->init) {
		p->init ();
	}
	RzFSPlugin* sp = R_NEW0 (RzFSPlugin);
	if (sp) {
		if (p) {
			memcpy (sp, p, sizeof (RzFSPlugin));
		}
		rz_list_append (fs->plugins, sp);
	}
}

RZ_API void rz_fs_del(RzFS* fs, RzFSPlugin* p) {
	// TODO: implement rz_fs_del
}

/* mountpoint */
RZ_API RzFSRoot* rz_fs_mount(RzFS* fs, const char* fstype, const char* path, ut64 delta) {
	RzFSPlugin* p;
	RzFSRoot* root;
	RzListIter* iter;
	char* str;
	int len, lenstr;
	char *heapFsType = NULL;

	if (path[0] != '/') {
		eprintf ("rz_fs_mount: invalid mountpoint %s\n", path);
		return NULL;
	}
	if (!fstype || !*fstype) {
		heapFsType = rz_fs_name (fs, delta);
		fstype = (const char *)heapFsType;
	}
	if (!(p = rz_fs_plugin_get (fs, fstype))) {
		// eprintf ("rz_fs_mount: Invalid filesystem type\n");
		free (heapFsType);
		return NULL;
	}
	str = strdup (path);
	if (!str) {
		free (heapFsType);
		return NULL;
	}
	rz_str_trim_path (str);
	if (*str && strchr (str + 1, '/')) {
		eprintf ("rz_fs_mount: mountpoint must have no subdirectories\n");
		free (heapFsType);
		return NULL;
	}
	/* Check if path exists */
	rz_list_foreach (fs->roots, iter, root) {
		len = strlen (root->path);
		lenstr = strlen (str);
		if (!strncmp (str, root->path, len)) {
			if (len < lenstr && str[len] != '/') {
				continue;
			}
			if (len > lenstr && root->path[lenstr] == '/') {
				continue;
			}
			eprintf ("rz_fs_mount: Invalid mount point\n");
			free (str);
			free (heapFsType);
			return NULL;
		}
	}
	RzFSFile* file = rz_fs_open (fs, str, false);
	if (file) {
		rz_fs_close (fs, file);
		eprintf ("rz_fs_mount: Invalid mount point\n");
		free (heapFsType);
		free (str);
		return NULL;
	}
	RzList *list = rz_fs_dir (fs, str);
	if (!rz_list_empty (list)) {
		//XXX: list need free ??
		eprintf ("rz_fs_mount: Invalid mount point\n");
		free (str);
		free (heapFsType);
		return NULL;
	}
	// TODO: we should just construct the root with the rfs instance
	root = rz_fs_root_new (str, delta);
	root->p = p;
	root->iob = fs->iob;
	root->cob = fs->cob;
	if (!p->mount (root)) {
		free (str);
		free (heapFsType);
		rz_fs_root_free (root);
		return NULL;
	}
	rz_list_append (fs->roots, root);
	eprintf ("Mounted %s on %s at 0x%" PFMT64x "\n", fstype, str, delta);
	free (str);
	free (heapFsType);
	return root;
}

static inline bool rz_fs_match(const char* root, const char* path, int len) {
	return (!strncmp (path, root, len));
}

RZ_API bool rz_fs_umount(RzFS* fs, const char* path) {
	int len;
	RzFSRoot* root;
	RzListIter* iter, * riter = NULL;

	if (!path) {
		return false;
	}

	rz_list_foreach (fs->roots, iter, root) {
		len = strlen (root->path);
		if (rz_fs_match (path, root->path, len)) {
			riter = iter;
		}
	}
	if (riter) {
		rz_list_delete (fs->roots, riter);
		return true;
	}
	return false;
}

RZ_API RzList* rz_fs_root(RzFS* fs, const char* p) {
	RzList* roots;
	RzFSRoot* root;
	RzListIter* iter;
	int len, olen;
	char* path = strdup (p);
	if (!path) {
		return NULL;
	}
	roots = rz_list_new ();
	rz_str_trim_path (path);
	rz_list_foreach (fs->roots, iter, root) {
		len = strlen (root->path);
		if (rz_fs_match (path, root->path, len)) {
			olen = strlen (path);
			if (len == 1 || olen == len) {
				rz_list_append (roots, root);
			} else if (olen > len && path[len] == '/') {
				rz_list_append (roots, root);
			}
		}
	}
	free (path);
	return roots;
}

/* filez */
RZ_API RzFSFile* rz_fs_open(RzFS* fs, const char* p, bool create) {
	RzFSRoot* root;
	RzListIter* iter;
	RzFSFile* f = NULL;
	const char* dir;
	char* path = rz_str_trim_dup (p);
	RzList *roots = rz_fs_root (fs, path);
	if (!rz_list_empty (roots)) {
		rz_list_foreach (roots, iter, root) {
			if (create) {
				if (root && root->p && root->p->write) {
					f = rz_fs_file_new (root, path + strlen (root->path));
					break;
				}
				continue;
			}
			if (root && root->p && root->p->open) {
				if (strlen (root->path) == 1) {
					dir = path;
				} else {
					dir = path + strlen (root->path);
				}
				f = root->p->open (root, dir, false);
				if (f) {
					break;
				}
			}
		}
	}
	free (roots);
	free (path);
	return f;
}

// NOTE: close doesnt free
RZ_API void rz_fs_close(RzFS* fs, RzFSFile* file) {
	if (fs && file) {
		R_FREE (file->data);
		if (file->p && file->p->close) {
			file->p->close (file);
		}
	}
}

RZ_API int rz_fs_write(RzFS* fs, RzFSFile* file, ut64 addr, const ut8 *data, int len) {
	if (len < 1) {
		return false;
	}
	if (fs && file) {
		// TODO: fill file->data ? looks like dupe of rbuffer 
		if (file->p && file->p->write) {
			file->p->write (file, addr, data, len);
			return true;
		}
		eprintf ("rz_fs_write: file->p->write is null\n");
	}
	return false;
}

RZ_API int rz_fs_read(RzFS* fs, RzFSFile* file, ut64 addr, int len) {
	if (len < 1) {
		eprintf ("rz_fs_read: too short read\n");
		return false;
	}
	if (fs && file) {
		if (file->p && file->p->read) {
			if (!file->data) {
				free (file->data);
				file->data = calloc (1, len + 1);
			}
			file->p->read (file, addr, len);
			return true;
		} else {
			eprintf ("rz_fs_read: file->p->read is null\n");
		}
	}
	return false;
}

RZ_API RzList* rz_fs_dir(RzFS* fs, const char* p) {
	RzList *ret = NULL;
	RzFSRoot* root;
	RzListIter* iter;
	const char* dir;
	char* path = strdup (p);
	rz_str_trim_path (path);
	RzList *roots = rz_fs_root (fs, path);
	rz_list_foreach (roots, iter, root) {
		if (root) {
			if (strlen (root->path) == 1) {
				dir = path;
			} else {
				dir = path + strlen (root->path);
			}
			if (!*dir) {
				dir = "/";
			}
			ret = root->p->dir (root, dir, fs->view);
			if (ret) {
				break;
			}
		}
	}
	free (roots);
	free (path);
	return ret;
}

RZ_API int rz_fs_dir_dump(RzFS* fs, const char* path, const char* name) {
	RzList* list;
	RzListIter* iter;
	RzFSFile* file, * item;
	char* str, * npath;

	list = rz_fs_dir (fs, path);
	if (!list) {
		return false;
	}
	if (!rz_sys_mkdir (name)) {
		if (rz_sys_mkdir_failed ()) {
			eprintf ("Cannot create \"%s\"\n", name);
			return false;
		}
	}
	rz_list_foreach (list, iter, file) {
		if (!strcmp (file->name, ".") || !strcmp (file->name, "..")) {
			continue;
		}
		str = (char*) malloc (strlen (name) + strlen (file->name) + 2);
		if (!str) {
			return false;
		}
		strcpy (str, name);
		strcat (str, "/");
		strcat (str, file->name);
		npath = malloc (strlen (path) + strlen (file->name) + 2);
		if (!npath) {
			free (str);
			return false;
		}
		strcpy (npath, path);
		strcat (npath, "/");
		strcat (npath, file->name);
		switch (file->type) {
		// DON'T FOLLOW MOUNTPOINTS
		case R_FS_FILE_TYPE_DIRECTORY:
			if (!rz_fs_dir_dump (fs, npath, str)) {
				free (npath);
				free (str);
				return false;
			}
			break;
		case R_FS_FILE_TYPE_REGULAR:
			item = rz_fs_open (fs, npath, false);
			if (item) {
				rz_fs_read (fs, item, 0, item->size);
				if (!rz_file_dump (str, item->data, item->size, 0)) {
					free (npath);
					free (str);
					return false;
				}
				rz_fs_close (fs, item);
			}
			break;
		}
		free (npath);
		free (str);
	}
	return true;
}

static void rz_fs_find_off_aux(RzFS* fs, const char* name, ut64 offset, RzList* list) {
	RzList* dirs;
	RzListIter* iter;
	RzFSFile* item, * file;
	char* found = NULL;

	dirs = rz_fs_dir (fs, name);
	rz_list_foreach (dirs, iter, item) {
		if (!strcmp (item->name, ".") || !strcmp (item->name, "..")) {
			continue;
		}

		found = (char*) malloc (strlen (name) + strlen (item->name) + 2);
		if (!found) {
			break;
		}
		strcpy (found, name);
		strcat (found, "/");
		strcat (found, item->name);

		if (item->type == R_FS_FILE_TYPE_DIRECTORY) {
			rz_fs_find_off_aux (fs, found, offset, list);
		} else {
			file = rz_fs_open (fs, found, false);
			if (file) {
				rz_fs_read (fs, file, 0, file->size);
				if (file->off == offset) {
					rz_list_append (list, found);
				}
				rz_fs_close (fs, file);
			}
		}
		free (found);
	}
}

RZ_API RzList* rz_fs_find_off(RzFS* fs, const char* name, ut64 off) {
	RzList* list = rz_list_new ();
	if (!list) {
		return NULL;
	}
	list->free = free;
	rz_fs_find_off_aux (fs, name, off, list);
	return list;
}

static void rz_fs_find_name_aux(RzFS* fs, const char* name, const char* glob, RzList* list) {
	RzList* dirs;
	RzListIter* iter;
	RzFSFile* item;
	char* found;

	dirs = rz_fs_dir (fs, name);
	rz_list_foreach (dirs, iter, item) {
		if (rz_str_glob (item->name, glob)) {
			found = (char*) malloc (strlen (name) + strlen (item->name) + 2);
			if (!found) {
				break;
			}
			strcpy (found, name);
			strcat (found, "/");
			strcat (found, item->name);
			rz_list_append (list, found);
		}
		if (!strcmp (item->name, ".") || !strcmp (item->name, "..")) {
			continue;
		}
		if (item->type == R_FS_FILE_TYPE_DIRECTORY) {
			found = (char*) malloc (strlen (name) + strlen (item->name) + 2);
			if (!found) {
				break;
			}
			strcpy (found, name);
			strcat (found, "/");
			strcat (found, item->name);
			rz_fs_find_name_aux (fs, found, glob, list);
			free (found);
		}
	}
}

RZ_API RzList* rz_fs_find_name(RzFS* fs, const char* name, const char* glob) {
	RzList* list = rz_list_newf (free);
	if (list) {
		rz_fs_find_name_aux (fs, name, glob, list);
	}
	return list;
}

RZ_API RzFSFile* rz_fs_slurp(RzFS* fs, const char* path) {
	RzFSFile* file = NULL;
	RzFSRoot* root;
	RzList* roots = rz_fs_root (fs, path);
	RzListIter* iter;
	rz_list_foreach (roots, iter, root) {
		if (!root || !root->p) {
			continue;
		}
		if (root->p->open && root->p->read && root->p->close) {
			file = root->p->open (root, path, false);
			if (file) {
				root->p->read (file, 0, file->size); //file->data
			}else {
				eprintf ("rz_fs_slurp: cannot open file\n");
			}
		} else {
			if (root->p->slurp) {
				free (roots);
				return root->p->slurp (root, path);
			}
			eprintf ("rz_fs_slurp: null root->p->slurp\n");
		}
	}
	free (roots);
	return file;
}

// TODO: move into grubfs
#include "../../shlr/grub/include/grubfs.h"

#if USE_GRUB
static int grub_parhook(void* disk, void* ptr, void* closure) {
	struct grub_partition* par = ptr;
	RzList* list = (RzList*) closure;
	RzFSPartition* p = rz_fs_partition_new (
		rz_list_length (list),
		par->start * 512, 512 * par->len);
	p->type = par->msdostype;
	rz_list_append (list, p);
	return 0;
}
#endif

static int fs_parhook(void* disk, void* ptr, void* closure) {
	RzFSPartition* par = ptr;
	RzList* list = (RzList*) closure;
	rz_list_append (list, par);
	return 0;
}

#include "p/part_dos.c"

static RzFSPartitionType partitions[] = {
	/* LGPL code */
	{"dos", &fs_part_dos, fs_parhook},
#if USE_GRUB
	/* WARNING GPL code */
#if !__EMSCRIPTEN__
// wtf for some reason is not available on emscripten
	{"msdos", &grub_msdos_partition_map, grub_parhook},
#endif
	{"apple", &grub_apple_partition_map, grub_parhook},
	{"sun", &grub_sun_partition_map, grub_parhook},
	{"sunpc", &grub_sun_pc_partition_map, grub_parhook},
	{"amiga", &grub_amiga_partition_map, grub_parhook},
	{"bsdlabel", &grub_bsdlabel_partition_map, grub_parhook},
	{"gpt", &grub_gpt_partition_map, grub_parhook},
#endif
	// XXX: In BURG all bsd partition map are in bsdlabel
	//{ "openbsdlabel", &grub_openbsd_partition_map },
	//{ "netbsdlabel", &grub_netbsd_partition_map },
	//{ "acorn", &grub_acorn_partition_map },
	{ NULL }
};

RZ_API const char* rz_fs_partition_type_get(int n) {
	if (n < 0 || n >= R_FS_PARTITIONS_LENGTH) {
		return NULL;
	}
	return partitions[n].name;
}

RZ_API int rz_fs_partition_get_size(void) {
	return R_FS_PARTITIONS_LENGTH;
}

RZ_API RzList* rz_fs_partitions(RzFS* fs, const char* ptype, ut64 delta) {
	int i, cur = -1;
	for (i = 0; partitions[i].name; i++) {
		if (!strcmp (ptype, partitions[i].name)) {
			cur = i;
			break;
		}
	}
	if (cur != -1) {
		RzList* list = rz_list_newf ((RzListFree) rz_fs_partition_free);
#if USE_GRUB
		void* disk = NULL;
		if (partitions[i].iterate == grub_parhook) {
			struct grub_partition_map* gpt = partitions[i].ptr;
			grubfs_bind_io (NULL, 0);
			disk = (void*) grubfs_disk (&fs->iob);
			if (gpt) {
				gpt->iterate (disk,
					(void*) partitions[i].iterate, list);
			}
			grubfs_free (disk);
		} else {
#else
		{
#endif
			RzFSPartitionIterator iterate = partitions[i].ptr;
			iterate (fs, partitions[i].iterate, list); //grub_parhook, list);
		}
		return list;
	}
	if (ptype && *ptype) {
		eprintf ("Unknown partition type '%s'.\n", ptype);
	}
	eprintf ("Supported types:\n");
	for (i = 0; partitions[i].name; i++) {
		eprintf (" %s", partitions[i].name);
	}
	eprintf ("\n");
	return NULL;
}

RZ_API int rz_fs_partition_type_str(const char* type) {
	// TODO: implement
	return 0;
}

RZ_API const char* rz_fs_partition_type(const char* part, int type) {
	// XXX: part is ignored O_o
	switch (type) {
	case GRUB_PC_PARTITION_TYPE_FAT12:
	case GRUB_PC_PARTITION_TYPE_FAT16_GT32M:
	case GRUB_PC_PARTITION_TYPE_FAT16_LT32M:
	case GRUB_PC_PARTITION_TYPE_FAT32:
	case GRUB_PC_PARTITION_TYPE_FAT32_LBA:
	case GRUB_PC_PARTITION_TYPE_FAT16_LBA:
		return strdup ("fat");

	case GRUB_PC_PARTITION_TYPE_EXT2FS:
		return strdup ("ext2");

	case GRUB_PC_PARTITION_TYPE_MINIX:
	case GRUB_PC_PARTITION_TYPE_LINUX_MINIX:
		return strdup ("minix");

	case GRUB_PC_PARTITION_TYPE_NTFS:
		return strdup ("ntfs");

	case GRUB_PC_PARTITION_TYPE_EXTENDED:
	case GRUB_PC_PARTITION_TYPE_LINUX_EXTENDED:
		return strdup ("ext3");

	case GRUB_PC_PARTITION_TYPE_HFS:
		return strdup ("hfs");

	case GRUB_PC_PARTITION_TYPE_WIN95_EXTENDED: // fat?
	case GRUB_PC_PARTITION_TYPE_EZD:
	case GRUB_PC_PARTITION_TYPE_VSTAFS:
	case GRUB_PC_PARTITION_TYPE_FREEBSD: // ufs
	case GRUB_PC_PARTITION_TYPE_OPENBSD: // ufs
	case GRUB_PC_PARTITION_TYPE_NETBSD:  // ufs
	case GRUB_PC_PARTITION_TYPE_GPT_DISK:
	case GRUB_PC_PARTITION_TYPE_LINUX_RAID:
	case GRUB_PC_PARTITION_TYPE_NONE:
	default:
		return NULL;
	}
}

RZ_API char* rz_fs_name(RzFS* fs, ut64 offset) {
	ut8 buf[1024];
	int i, j, len, ret = false;

	for (i = 0; fstypes[i].name; i++) {
		RzFSType* f = &fstypes[i];
		len = R_MIN (f->buflen, sizeof (buf) - 1);
		fs->iob.read_at (fs->iob.io, offset + f->bufoff, buf, len);
		if (f->buflen > 0 && !memcmp (buf, f->buf, f->buflen)) {
			ret = true;
			len = R_MIN (f->bytelen, sizeof (buf));
			fs->iob.read_at (fs->iob.io, offset + f->byteoff, buf, len);
			// for (j = 0; j < f->bytelen; j++) {
			for (j = 0; j < len; j++) {
				if (buf[j] != f->byte) {
					ret = false;
					break;
				}
			}
			if (ret) {
				return strdup (f->name);
			}
		}
	}
	return NULL;
}

RZ_API void rz_fs_view(RzFS* fs, int view) {
	fs->view = view;
}

RZ_API bool rz_fs_check(RzFS *fs, const char *p) {
	RzFSRoot *root;
	RzListIter *iter;
	char* path = strdup (p);
	if (!path) {
		return false;
	}
	rz_str_trim_path (path);
	rz_list_foreach (fs->roots, iter, root) {
		if (rz_fs_match (path, root->path, strlen (root->path))) {
			free (path);
			return true;
		}
	}
	free (path);
	return false;
}
