// SPDX-FileCopyrightText: 2014-2016 iniside <inisider@gmail.com>
// SPDX-FileCopyrightText: 2014-2016 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

RZ_IPI bool parse_omap_stream(RzPdb *pdb, RzPdbMsfStream *stream) {
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

RZ_IPI void free_omap_stream(RzPdbOmapStream *stream) {
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

// inclusive indices
//   0 <= imin when using truncate toward zero divide
//     imid = (imin+imax)/2;
//   imin unrestricted when using truncate toward minus infinity divide
//     imid = (imin+imax)>>1; or
//     imid = (int)floor((imin+imax)/2.0);
static int binary_search(unsigned int *A, int key, int imin, int imax) {
	int imid;

	// continually narrow search until just one element remains
	while (imin < imax) {
		imid = (imin + imax) / 2;
		if (A[imid] < key) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}
	// At exit of while:
	//   if A[] is empty, then imax < imin
	//   otherwise imax == imin

	// deferred test for equality
	if ((imax == imin) && (A[imin] == key)) {
		return imin;
	}
	return -1;
}

/**
 * \brief return remapped symbol address
 *
 * \param omap_stream RzPdbOmapStream
 * \param address Where to remap
 * \return int
 */
RZ_API int rz_bin_pdb_omap_remap(RZ_NONNULL RzPdbOmapStream *omap_stream, int address) {
	OmapEntry *omap_entry = 0;
	RzListIter *it = 0;
	int i = 0;
	int pos = 0;
	int len = 0;

	if (!omap_stream) {
		return address;
	}

	len = rz_list_length(omap_stream->entries);

	if (omap_stream->froms == 0) {
		omap_stream->froms = (unsigned int *)malloc(4 * len);
		if (!omap_stream->froms) {
			return -1;
		}
		it = rz_list_iterator(omap_stream->entries);
		while (rz_list_iter_next(it)) {
			omap_entry = (OmapEntry *)rz_list_iter_get(it);
			omap_stream->froms[i] = omap_entry->from;
			i++;
		}
	}

	// mb (len -1) ???
	pos = binary_search(omap_stream->froms, address, 0, (len));

	if (pos == -1) {
		return -1;
	}

	if (omap_stream->froms[pos] != address) {
		pos -= 1;
	}
	omap_entry = (OmapEntry *)rz_list_get_n(omap_stream->entries, pos);
	if (!omap_entry) {
		return -1;
	}
	if (omap_entry->to == 0) {
		return omap_entry->to;
	}
	return omap_entry->to + (address - omap_entry->from);
}
