#ifndef R2_FS_H
#define R2_FS_H

#include <rz_types.h>
#include <rz_list.h>
#include <rz_bind.h> // RzCoreBind
#include <rz_io.h> // RzIOBind
#include <rz_util.h>
#include <rz_cons.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (rz_fs);

struct rz_fs_plugin_t;
struct rz_fs_root_t;
struct rz_fs_t;

typedef struct rz_fs_t {
	RzIOBind iob;
	RzCoreBind cob;
	RzConsBind csb;
	RzList /*<RzFSPlugin>*/ *plugins;
	RzList /*<RzFSRoot>*/ *roots;
	int view;
	void *ptr;
} RzFS;

typedef struct rz_fs_partition_plugin_t {
	const char *name;
} RzFSPartitionPlugin;

typedef struct rz_fs_file_t {
	char *name;
	char *path;
	ut64 off;
	ut32 size;
	ut8 *data;
	void *ctx;
	char type;
	ut64 time;
	struct rz_fs_plugin_t *p;
	struct rz_fs_root_t *root;
	void *ptr; // internal pointer
} RzFSFile;

typedef struct rz_fs_root_t {
	char *path;
	ut64 delta;
	struct rz_fs_plugin_t *p;
	void *ptr;
	// TODO: deprecate
	RzIOBind iob;
	RzCoreBind cob;
} RzFSRoot;

typedef struct rz_fs_plugin_t {
	const char *name;
	const char *desc;
	const char *license;
	RzFSFile* (*slurp)(RzFSRoot *root, const char *path);
	RzFSFile* (*open)(RzFSRoot *root, const char *path, bool create);
	bool (*unlink)(RzFSRoot *root, const char *path);
	bool (*write)(RzFSFile *fs, ut64 addr, const ut8 *data, int len);
	bool (*read)(RzFSFile *fs, ut64 addr, int len);
	void (*close)(RzFSFile *fs);
	RzList *(*dir)(RzFSRoot *root, const char *path, int view);
	void (*init)(void);
	void (*fini)(void);
	int (*mount)(RzFSRoot *root);
	void (*umount)(RzFSRoot *root);
} RzFSPlugin;

typedef struct rz_fs_partition_t {
	int number;
	ut64 start;
	ut64 length;
	int index;
	int type;
} RzFSPartition;

typedef struct rz_fs_shell_t {
	char **cwd;
	void (*set_prompt)(const char *prompt);
	const char* (*readline)(void);
	int (*hist_add)(const char *line);
} RzFSShell;

#define R_FS_FILE_TYPE_MOUNTPOINT 'm'
#define R_FS_FILE_TYPE_DIRECTORY 'd'
#define R_FS_FILE_TYPE_REGULAR 'r'
#define R_FS_FILE_TYPE_DELETED 'x'
#define R_FS_FILE_TYPE_SPECIAL 's'
#define R_FS_FILE_TYPE_MOUNT 'm'

typedef int (*RzFSPartitionIterator)(void *disk, void *ptr, void *user);
typedef struct rz_fs_partition_type_t {
	const char *name;
	void *ptr; // grub_msdos_partition_map
	RzFSPartitionIterator iterate;
	//RzFSPartitionIterator parhook;
} RzFSPartitionType;
#define R_FS_PARTITIONS_LENGTH (int)(sizeof (partitions)/sizeof(RzFSPartitionType)-1)

enum {
	R_FS_VIEW_NORMAL = 0,
	R_FS_VIEW_DELETED = 1,
	R_FS_VIEW_SPECIAL = 2,
	R_FS_VIEW_ALL = 0xff,
};

#ifdef RZ_API
RZ_API RzFS *rz_fs_new(void);
RZ_API void rz_fs_view(RzFS* fs, int view);
RZ_API void rz_fs_free(RzFS* fs);
RZ_API void rz_fs_add(RzFS *fs, RzFSPlugin *p);
RZ_API void rz_fs_del(RzFS *fs, RzFSPlugin *p);
RZ_API RzFSRoot *rz_fs_mount(RzFS* fs, const char *fstype, const char *path, ut64 delta);
RZ_API bool rz_fs_umount(RzFS* fs, const char *path);
RZ_API RzList *rz_fs_root(RzFS *fs, const char *path);
RZ_API RzFSFile *rz_fs_open(RzFS* fs, const char *path, bool create);
RZ_API void rz_fs_close(RzFS* fs, RzFSFile *file);
RZ_API int rz_fs_read(RzFS* fs, RzFSFile *file, ut64 addr, int len);
RZ_API int rz_fs_write(RzFS* fs, RzFSFile* file, ut64 addr, const ut8 *data, int len);
RZ_API RzFSFile *rz_fs_slurp(RzFS* fs, const char *path);
RZ_API RzList *rz_fs_dir(RzFS* fs, const char *path);
RZ_API int rz_fs_dir_dump(RzFS* fs, const char *path, const char *name);
RZ_API RzList *rz_fs_find_name(RzFS* fs, const char *name, const char *glob);
RZ_API RzList *rz_fs_find_off(RzFS* fs, const char *name, ut64 off);
RZ_API RzList *rz_fs_partitions(RzFS* fs, const char *ptype, ut64 delta);
RZ_API char *rz_fs_name(RzFS *fs, ut64 offset);
RZ_API int rz_fs_prompt(RzFS *fs, const char *root);
RZ_API bool rz_fs_check(RzFS *fs, const char *p);
RZ_API int rz_fs_shell_prompt(RzFSShell *shell, RzFS *fs, const char *root);

/* file.c */
RZ_API RzFSFile *rz_fs_file_new(RzFSRoot *root, const char *path);
RZ_API void rz_fs_file_free(RzFSFile *file);
RZ_API char* rz_fs_file_copy_abs_path(RzFSFile* file);
RZ_API RzFSRoot *rz_fs_root_new(const char *path, ut64 delta);
RZ_API void rz_fs_root_free(RzFSRoot *root);
RZ_API RzFSPartition *rz_fs_partition_new(int num, ut64 start, ut64 length);
RZ_API void rz_fs_partition_free(RzFSPartition *p);
RZ_API const char *rz_fs_partition_type(const char *part, int type);
RZ_API const char *rz_fs_partition_type_get(int n);
RZ_API int rz_fs_partition_get_size(void); // WTF. wrong function name

/* plugins */
extern RzFSPlugin rz_fs_plugin_io;
extern RzFSPlugin rz_fs_plugin_rz;
extern RzFSPlugin rz_fs_plugin_ext2;
extern RzFSPlugin rz_fs_plugin_fat;
extern RzFSPlugin rz_fs_plugin_ntfs;
extern RzFSPlugin rz_fs_plugin_hfs;
extern RzFSPlugin rz_fs_plugin_hfsplus;
extern RzFSPlugin rz_fs_plugin_reiserfs;
extern RzFSPlugin rz_fs_plugin_tar;
extern RzFSPlugin rz_fs_plugin_iso9660;
extern RzFSPlugin rz_fs_plugin_udf;
extern RzFSPlugin rz_fs_plugin_ufs;
extern RzFSPlugin rz_fs_plugin_ufs2;
extern RzFSPlugin rz_fs_plugin_sfs;
extern RzFSPlugin rz_fs_plugin_tar;
extern RzFSPlugin rz_fs_plugin_btrfs;
extern RzFSPlugin rz_fs_plugin_jfs;
extern RzFSPlugin rz_fs_plugin_afs;
extern RzFSPlugin rz_fs_plugin_affs;
extern RzFSPlugin rz_fs_plugin_cpio;
extern RzFSPlugin rz_fs_plugin_xfs;
extern RzFSPlugin rz_fs_plugin_fb;
extern RzFSPlugin rz_fs_plugin_minix;
extern RzFSPlugin rz_fs_plugin_posix;
#endif

#ifdef __cplusplus
}
#endif

#endif
