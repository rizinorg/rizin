#ifndef ZIMG_H
#define ZIMG_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define R_BIN_ZIMG_MAXSTR 256

struct zimg_header_t {
	ut8 magic[8];
	ut32 filler[6];
	ut8 arm_magic[4];
	ut32 kernel_start;
	ut32 kernel_end;
};

typedef struct rz_bin_zimg_obj_t {
	int size;
	const char *file;
	RBuffer *b;
	struct zimg_header_t header;
	ut32 *strings;
	RzList *methods_list;
	RzList *imports_list;
	ut64 code_from;
	ut64 code_to;
	Sdb *kv;
} RBinZimgObj;

struct rz_bin_zimg_str_t {
	char str[R_BIN_ZIMG_MAXSTR];
	ut64 offset;
	ut64 ordinal;
	int size;
	int last;
};

struct rz_bin_zimg_obj_t *rz_bin_zimg_new_buf(RBuffer *buf);
struct rz_bin_zimg_str_t *rz_bin_zimg_get_strings (struct rz_bin_zimg_obj_t *bin);

#endif
