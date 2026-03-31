// SPDX-FileCopyrightText: 2014-2016 iniside <inisider@gmail.com>
// SPDX-FileCopyrightText: 2014-2016 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

RZ_IPI bool omap_stream_parse(RzPdb *pdb, RzPdbMsfStream *stream) {
	rz_return_val_if_fail(pdb && stream, false);
	if (!pdb->s_omap) {
		pdb->s_omap = RZ_NEW0(RzPdbOmapStream);
	}
	RzBuffer *buf = stream->stream_data;
	RzPdbOmapStream *s = pdb->s_omap;
	if (!s) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		return false;
	}
	if (!s->entries) {
		s->entries = rz_list_new();
	}
	ut32 size = rz_buf_size(buf);
	ut32 read_len = 0;
	while (read_len < size) {
		OmapEntry *entry = RZ_NEW0(OmapEntry);
		if (!entry) {
			rz_list_free(s->entries);
			return false;
		}
		if (!rz_buf_read_le32(buf, &entry->from) ||
			!rz_buf_read_le32(buf, &entry->to)) {
			free(entry);
			rz_list_free(s->entries);
			return false;
		}
		read_len += sizeof(ut32) * 2;
		rz_list_append(s->entries, entry);
	}
	return true;
}

RZ_IPI void omap_stream_free(RzPdbOmapStream *stream) {
	if (!stream) {
		return;
	}
	OmapEntry *entry;
	RzListIter *it;
	rz_list_foreach (stream->entries, it, entry) {
		RZ_FREE(entry);
	}
	rz_list_free(stream->entries);
	free(stream);
}

static int cmp_ut64(const void *pa, const void *pb) {
	ut64 a = *(ut64 *)pb;
	ut64 b = *(ut64 *)pa;
	if (a < b) {
		return -1;
	}
	if (a > b) {
		return 1;
	}
	return 0;
}

/**
 * \brief return remapped symbol address
 *
 * \param omap_stream RzPdbOmapStream
 * \param address Where to remap
 * \return int
 */
static ut64 pdb_omap_remap(RZ_NONNULL RzPdbOmapStream *omap_stream, ut64 address) {
	OmapEntry *omap_entry = 0;
	RzListIter *it = 0;
	int i = 0;

	if (!omap_stream) {
		return address;
	}

	ut32 len = rz_list_length(omap_stream->entries);

	if (omap_stream->froms == 0) {
		omap_stream->froms = (ut64 *)malloc(sizeof(ut64) * len);
		if (!omap_stream->froms) {
			return -1;
		}
		it = rz_list_iterator(omap_stream->entries);
		while (it) {
			omap_entry = (OmapEntry *)rz_list_val(it);
			omap_stream->froms[i] = omap_entry->from;
			i++;
			it = rz_list_next(it);
		}
	}

	const ut64 *p = bsearch(&address, omap_stream->froms, len, sizeof(ut64), cmp_ut64);
	if (!p) {
		return -1;
	}

	omap_entry = (OmapEntry *)rz_list_get_n(omap_stream->entries, *p);
	if (!omap_entry) {
		return -1;
	}
	if (omap_entry->to == 0) {
		return omap_entry->to;
	}
	return omap_entry->to + (address - omap_entry->from);
}

/**
 * \brief Convert the section offset to relative virtual address
 *
 * \param pdb The PDB reference
 * \param section_offset The section offset
 * \return The relative virtual address
 */
RZ_API ut64 rz_bin_pdb_to_rva(
	RZ_BORROW RZ_NONNULL const RzPdb *pdb,
	RZ_BORROW RZ_NONNULL const PDBSectionOffset *section_offset) {
	static const ut64 DEFAULT = UT64_MAX;
	rz_return_val_if_fail(pdb && pdb->s_pe && section_offset, DEFAULT);
	PeImageSectionHeader *section_hdr = pdb_section_hdr_by_index(pdb->s_pe, section_offset->section_index);
	if (!section_hdr) {
		return DEFAULT;
	}
	ut64 internal_rva = section_offset->offset + section_hdr->virtual_address;
	if (pdb->s_omap) {
		return pdb_omap_remap(pdb->s_omap, internal_rva);
	}
	return internal_rva;
}
