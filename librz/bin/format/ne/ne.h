// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

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
	ut16 flags;
} rz_ne_resource_entry;

typedef struct {
	char *name;
	RzList /*<rz_ne_resource_entry *>*/ *entry;
} rz_ne_resource;

typedef struct ne_s {
	NE_image_header *ne_header;
	ut16 header_offset;
	ut16 alignment;
	RzVector /*<NE_image_segment_entry>*/ *image_segment_entries;
	RzVector /*<NE_resident_name_entry>*/ *resident_name_entries;
	RzVector /*<NE_resident_name_entry>*/ *nonresident_name_entries;
	RzVector /*<NE_segment_entry>*/ *segment_entries;
	RzVector /*<NE_relocation_entry>*/ *relocation_entries;
	RzVector /*<ut16>*/ *module_refs;
	RzPVector /*<char *>*/ *imported_modules;
	RzList /*<rz_ne_resource *>*/ *resources;
	RzPath *path;
	char *os;
} ne_t;

RZ_IPI void ne_free(ne_t *bin);
RZ_IPI ne_t *ne_new_buf(RzBuffer *buf);
RZ_IPI RzPVector /*<RzBinReloc *>*/ *ne_get_relocs(ne_t *bin);
RZ_IPI RzPVector /*<RzBinImport *>*/ *ne_get_imports(ne_t *bin);
RZ_IPI RzPVector /*<RzBinSymbol *>*/ *ne_get_symbols(ne_t *bin);
RZ_IPI RzPVector /*<RzBinSection *>*/ *ne_get_sections(ne_t *bin);
RZ_IPI RzPVector /*<RzBinAddr *>*/ *ne_get_entrypoints(ne_t *bin);
RZ_IPI RzPVector /*<RzBinResource *>*/ *ne_get_resources(ne_t *bin);
RZ_IPI RzPVector /*<char *>*/ *ne_get_libraries(ne_t *bin);
RZ_IPI RzList /*<char *>*/ *ne_convert_section_flag_to_rzlist(ut64 flag);
RZ_IPI char *ne_convert_section_type_to_string(ut64 type);

#endif
