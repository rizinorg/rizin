#ifndef FS_TYPES_H
#define FS_TYPES_H

typedef struct rz_fs_type_t {
	const char *name;
	int bufoff;
	const char *buf;
	int buflen;
	int byteoff;
	ut8 byte;
	int bytelen;
} RzFSType;

static RzFSType fstypes[] = {
	{ "hfs", 0x400, "BD", 2, 0, 0, 0x400 },
	{ "hfsplus", 0x400, "H+", 2, 0, 0, 0x400 },
	{ "fat", 0x36, "FAT12", 5, 0, 0, 0 },
	{ "fat", 0x52, "FAT32", 5, 0, 0, 0 },
	{ "ext2", 0x438, "\x53\xef", 2, 0, 0, 0 },
	{ "btrfs", 0x10040, "_BHRfS_M", 8, 0, 0, 0x0 },
	{ "iso9660", 0x8000, "\x01" "CD0", 4, 0, 0, 0x8000 },
	{ NULL }
};

#endif
