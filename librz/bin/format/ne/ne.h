#ifndef NE_H
#define NE_H
#include <rz_types.h>
#include <rz_list.h>
#include <rz_util.h>
#include <rz_bin.h>
#include "ne_specs.h"

typedef struct {
	char *name;
	ut32 offset;
	ut32 size;
} rz_ne_resource_entry;

typedef struct {
	char *name;
	RzList /*<rz_ne_resource_entry>*/ *entry;
} rz_ne_resource;

typedef struct {
	NE_image_header *ne_header;
	ut16 header_offset;
	ut16 alignment;
	NE_image_segment_entry *segment_entries;
	ut8 *entry_table;
	ut8 *resident_name_table;
	RzBuffer *buf;
	RzList *segments;
	RzList *entries;
	RzList *resources;
	RzList *imports;
	RzList *symbols;
	char *os;
} rz_bin_ne_obj_t;

void rz_bin_ne_free(rz_bin_ne_obj_t *bin);
rz_bin_ne_obj_t *rz_bin_ne_new_buf(RzBuffer *buf, bool verbose);
RzList *rz_bin_ne_get_relocs(rz_bin_ne_obj_t *bin);
RzList *rz_bin_ne_get_imports(rz_bin_ne_obj_t *bin);
RzList *rz_bin_ne_get_symbols(rz_bin_ne_obj_t *bin);
RzList *rz_bin_ne_get_segments(rz_bin_ne_obj_t *bin);
RzList *rz_bin_ne_get_entrypoints(rz_bin_ne_obj_t *bin);

#endif
