// SPDX-FileCopyrightText: 2013 xvilka <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#ifndef _INCLUDE_RZ_BIN_TE_H_
#define _INCLUDE_RZ_BIN_TE_H_

#define RZ_BIN_TE_SCN_IS_SHAREABLE(x)  x &TE_IMAGE_SCN_MEM_SHARED
#define RZ_BIN_TE_SCN_IS_EXECUTABLE(x) x &TE_IMAGE_SCN_MEM_EXECUTE
#define RZ_BIN_TE_SCN_IS_READABLE(x)   x &TE_IMAGE_SCN_MEM_READ
#define RZ_BIN_TE_SCN_IS_WRITABLE(x)   x &TE_IMAGE_SCN_MEM_WRITE

struct rz_bin_te_section_t {
	ut8 name[TE_IMAGE_SIZEOF_NAME];
	ut64 size;
	ut64 vsize;
	ut64 vaddr;
	ut64 paddr;
	ut64 flags;
	int last;
};

struct rz_bin_te_string_t {
	char string[TE_STRING_LENGTH];
	ut64 vaddr;
	ut64 paddr;
	ut64 size;
	char type;
	int last;
};

struct rz_bin_te_obj_t {
	TE_image_file_header *header;
	TE_image_section_header *section_header;
	int size;
	int endian;
	const char *file;
	RzBuffer *b;
	Sdb *kv;
};

char *rz_bin_te_get_arch(struct rz_bin_te_obj_t *bin);
RzBinAddr *rz_bin_te_get_entrypoint(struct rz_bin_te_obj_t *bin);
ut64 rz_bin_te_get_main_paddr(struct rz_bin_te_obj_t *bin);
ut64 rz_bin_te_get_image_base(struct rz_bin_te_obj_t *bin);
int rz_bin_te_get_image_size(struct rz_bin_te_obj_t *bin);
char *rz_bin_te_get_machine(struct rz_bin_te_obj_t *bin);
char *rz_bin_te_get_cpu(struct rz_bin_te_obj_t *bin);
int rz_bin_te_get_bits(struct rz_bin_te_obj_t *bin);
char *rz_bin_te_get_os(struct rz_bin_te_obj_t *bin);
struct rz_bin_te_section_t *rz_bin_te_get_sections(struct rz_bin_te_obj_t *bin);
char *rz_bin_te_get_subsystem(struct rz_bin_te_obj_t *bin);
void *rz_bin_te_free(struct rz_bin_te_obj_t *bin);
struct rz_bin_te_obj_t *rz_bin_te_new(const char *file);
struct rz_bin_te_obj_t *rz_bin_te_new_buf(RzBuffer *buf);

#endif
