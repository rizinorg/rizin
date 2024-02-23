// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PDB_PRIVATE_INCLUDE_H_
#define PDB_PRIVATE_INCLUDE_H_

#include <rz_pdb.h>
#include "dbi.h"
#include "omap.h"
#include "stream_pe.h"
#include "tpi.h"
#include "symbol.h"
#include "modi.h"

#define map_err(x) \
	if (!(x)) { \
		goto err; \
	}

static inline RzBuffer *buf_take(RzBuffer *b, ut32 len) {
	if (!(b && len)) {
		return NULL;
	}
	RzBuffer *type_buffer = rz_buf_new_slice(b, rz_buf_tell(b), len);
	if (!type_buffer) {
		return NULL;
	}
	rz_buf_seek(b, len, RZ_BUF_CUR);
	return type_buffer;
}

static inline bool buf_empty(RzBuffer *b) {
	if (!b) {
		return true;
	}
	return rz_buf_tell(b) >= rz_buf_size(b);
}

static inline void buf_read_padding(RzBuffer *b) {
	if (!b) {
		return;
	}
	while (!buf_empty(b) && rz_buf_peek(b) > 0xf0) {
		ut8 padding = 0;
		if (!rz_buf_read8(b, &padding)) {
			return;
		}
		if (padding > 0xf0) {
			rz_buf_seek(b, (padding & 0x0f) - 1, RZ_BUF_CUR);
		}
	}
}

static inline bool buf_read_u8_pascal_string(RzBuffer *b, char **result) {
	ut8 length = 0;
	if (!rz_buf_read8(b, &length)) {
		return false;
	}
	*result = RZ_NEWS0(char, length);
	if (!*result) {
		return false;
	}
	return rz_buf_read(b, (ut8 *)*result, length);
}

static inline bool buf_align(RzBuffer *b, ut64 alignment) {
	const ut64 diff = rz_buf_tell(b) % alignment;
	if (diff <= 0) {
		return true;
	}
	ut64 off = rz_buf_tell(b);
	if (rz_buf_size(b) - off < alignment - diff) {
		return false;
	}
	return rz_buf_seek(b, alignment - diff, RZ_BUF_CUR) == off + alignment - diff;
}

RZ_IPI RzPdbMsfStream *pdb_raw_steam(const RzPdb *pdb, ut16 index);
RZ_IPI PDBSymbolTable *pdb_global_symbols(const RzPdb *pdb);

// OMAP
RZ_IPI bool omap_stream_parse(RzPdb *pdb, RzPdbMsfStream *stream);
RZ_IPI void omap_stream_free(RzPdbOmapStream *stream);
RZ_IPI int omap_remap(void *stream, int address);

// GDATA
RZ_IPI bool gdata_stream_parse(RzPdb *pdb, RzPdbMsfStream *stream);
RZ_IPI void gdata_stream_free(RzPdbGDataStream *stream);

// PE
RZ_IPI bool pe_stream_parse(RzPdb *pdb, RzPdbMsfStream *stream);
RZ_IPI void pe_stream_free(RzPdbPeStream *stream);

#endif
