// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014-2016 jfrankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FLIRT_H
#define RZ_FLIRT_H

#include <rz_list.h>
#include <rz_analysis.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_flirt);

#define RZ_FLIRT_NAME_MAX 1024

typedef struct RzFlirtTailByte {
	ut16 offset; // from pattern_size + crc_length
	ut8 value;
} RzFlirtTailByte;

typedef struct RzFlirtFunction {
	char name[RZ_FLIRT_NAME_MAX];
	ut16 offset; // function offset from the module start
	ut8 negative_offset; // true if offset is negative, for referenced functions
	ut8 is_local; // true if function is static
	ut8 is_collision; // true if was an unresolved collision
} RzFlirtFunction;

typedef struct RzFlirtModule {
	ut32 crc_length;
	ut32 crc16; // crc16 of the module after the pattern bytes
	// until but not including the first variant byte
	// this is a custom crc16
	ut16 length; // total length of the module, should be < 0x8000
	RzList *public_functions;
	RzList *tail_bytes;
	RzList *referenced_functions;
} RzFlirtModule;

typedef struct RzFlirtNode {
	RzList *child_list;
	RzList *module_list;
	ut32 length; // length of the pattern
	ut64 variant_mask; // this is the mask that will define variant bytes in ut8 *pattern_bytes
	ut8 *pattern_bytes; // holds the pattern bytes of the signature
	ut8 *variant_bool_array; // bool array, if true, byte in pattern_bytes is a variant byte
} RzFlirtNode;

RZ_API RZ_OWN RzFlirtNode *rz_flirt_parse_buffer(RZ_NONNULL RzBuffer *buffer);
RZ_API void rz_flirt_node_free(RZ_NULLABLE RzFlirtNode *node);
RZ_API ut8 rz_flirt_get_version(RZ_NONNULL RzBuffer *buffer);
RZ_API void rz_flirt_apply_signatures(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL const char *flirt_file);

#ifdef __cplusplus
}
#endif

#endif /* RZ_FLIRT_H */
