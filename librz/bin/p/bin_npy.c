// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Reference: https://github.com/numpy/numpy/blob/v2.0.0/numpy/lib/format.py
 *            https://github.com/numpy/numpy/blob/v2.0.0/numpy/lib/format.pyi
 *            https://numpy.org/devdocs/reference/generated/numpy.lib.format.html
 */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "../format/npy/npy.h"

typedef struct {
	ut8 ver_major;
	ut8 ver_minor;
	NPYheader header;
	ut64 data_offset;
} NpyContainer;

static const ut8 NPY_MAGIC[NPY_ARRAY_MAGIC_LENGTH] = { 0x93, 'N', 'U', 'M', 'P', 'Y' };

static void npy_container_free(NpyContainer *c) {
	if (c) {
		free(c);
	}
}

static ut64 npy_total_elements(const NPYheader *hdr) {
	if (!hdr || hdr->ndim == 0)
		return 0;

	ut64 total = 1;

	for (ut64 i = 0; i < hdr->ndim; i++) {
		if (!hdr->shape[i] || total > UT64_MAX / hdr->shape[i])
			return 0;
		total *= hdr->shape[i];
	}
	return total;
}

static bool parse_descr(NPYheader *h) {
	const char *d = h->descr;

	if (!d || strlen(d) < 3) {
		return false;
	}

	const char *p = d;
	if (*p == '<' || *p == '>' || *p == '|' || *p == '=') {
		p++;
	}

	if (!isalpha((unsigned char)*p)) {
		return false;
	}
	p++;

	if (!isdigit((unsigned char)*p)) {
		return false;
	}

	h->elem_size = rz_num_get(NULL, p);
	return h->elem_size > 0;
}

static bool read_npy_header(NpyContainer *c, RzBuffer *b) {
	rz_return_val_if_fail(c && b, false);

	ut64 offset = 0;
	ut64 buf_size = rz_buf_size(b);
	ut8 magic[NPY_ARRAY_MAGIC_LENGTH];

	if (!rz_buf_read_offset(b, &offset, magic, NPY_ARRAY_MAGIC_LENGTH)) {
		return false;
	}

	if (memcmp(magic, NPY_MAGIC, NPY_ARRAY_MAGIC_LENGTH) != 0) {
		return false;
	}

	if (!rz_buf_read_offset(b, &offset, &c->ver_major, 1) ||
		!rz_buf_read_offset(b, &offset, &c->ver_minor, 1)) {
		return false;
	}

	if (c->ver_major < 1 || c->ver_major > 3) {
		return false;
	}

	ut32 header_len = 0;

	if (c->ver_major == 1) {
		ut16 len16;
		if (!rz_buf_read_le16_offset(b, &offset, &len16)) {
			return false;
		}
		header_len = len16;
	} else {
		if (!rz_buf_read_le32_offset(b, &offset, &header_len)) {
			return false;
		}
	}

	if (!header_len || header_len > 1024 * 1024 ||
		offset + header_len > buf_size) {
		return false;
	}

	char *dict = RZ_NEWS(char, header_len + 1);
	if (!dict) {
		return false;
	}

	if (rz_buf_read_at(b, offset, (ut8 *)dict, header_len) != header_len) {
		free(dict);
		return false;
	}

	dict[header_len] = '\0';
	offset += header_len;
	c->data_offset = offset;

	memset(&c->header, 0, sizeof(NPYheader));

	char *d = strstr(dict, "'descr':");
	if (!d)
		d = strstr(dict, "\"descr\":");
	if (!d) {
		free(dict);
		return false;
	}

	char *colon = strchr(d, ':');
	if (!colon) {
		free(dict);
		return false;
	}

	char *start = strchr(colon, '\'');
	if (!start)
		start = strchr(colon, '"');
	if (!start) {
		free(dict);
		return false;
	}
	start++;

	char *end = strchr(start, start[-1]);
	if (!end) {
		free(dict);
		return false;
	}

	size_t len = RZ_MIN((size_t)(end - start), sizeof(c->header.descr) - 1);
	memcpy(c->header.descr, start, len);
	c->header.descr[len] = '\0';

	if (!parse_descr(&c->header)) {
		free(dict);
		return false;
	}

	char *f = strstr(dict, "fortran_order");
	if (f) {
		c->header.fortran_order =
			(strstr(f, "True") != NULL);
	}

	char *s = strstr(dict, "shape");
	if (s) {
		char *p = strchr(s, '(');
		if (p) {
			p++;
			while (*p && *p != ')' &&
				c->header.ndim < NPY_ARRAY_MAX_DIMENSIONS) {

				while (*p == ' ' || *p == ',')
					p++;

				if (!isdigit((unsigned char)*p))
					break;

				c->header.shape[c->header.ndim] = rz_num_get(NULL, p);
				c->header.ndim++;

				while (*p && *p != ',' && *p != ')')
					p++;
			}
		}
	}
	free(dict);
	return true;
}

static bool npy_check_buffer(RzBuffer *buf) {
	if (!buf || rz_buf_size(buf) < NPY_ARRAY_MAGIC_LENGTH + 2) {
		return false;
	}

	ut8 magic[NPY_ARRAY_MAGIC_LENGTH];
	if (rz_buf_read_at(buf, 0, magic, NPY_ARRAY_MAGIC_LENGTH) != NPY_ARRAY_MAGIC_LENGTH) {
		return false;
	}

	if (memcmp(magic, NPY_MAGIC, NPY_ARRAY_MAGIC_LENGTH) != 0) {
		return false;
	}

	ut8 ver_major;
	if (rz_buf_read_at(buf, NPY_ARRAY_MAGIC_LENGTH, &ver_major, 1) != 1) {
		return false;
	}

	return (ver_major >= 1 && ver_major <= 3);
}

static bool npy_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && buf, false);

	if (!npy_check_buffer(buf)) {
		return false;
	}

	NpyContainer *c = RZ_NEW0(NpyContainer);
	if (!c) {
		return false;
	}

	if (!read_npy_header(c, buf)) {
		npy_container_free(c);
		return false;
	}

	ut64 total = npy_total_elements(&c->header);

	obj->bin_obj = c;

	if (sdb) {
		sdb_num_set(sdb, "npy.version_major", c->ver_major);
		sdb_num_set(sdb, "npy.version_minor", c->ver_minor);
		sdb_num_set(sdb, "npy.ndim", c->header.ndim);
		sdb_num_set(sdb, "npy.elem_size", c->header.elem_size);
		sdb_num_set(sdb, "npy.element_count", total);
		sdb_num_set(sdb, "npy.data_size", total * c->header.elem_size);
		sdb_num_set(sdb, "npy.data_offset", c->data_offset);
		sdb_set(sdb, "npy.descr", c->header.descr);
		sdb_set(sdb, "npy.fortran_order", c->header.fortran_order ? "True" : "False");
	}

	return true;
}

static void npy_destroy(RzBinFile *bf) {
	if (bf && bf->o && bf->o->bin_obj) {
		npy_container_free((NpyContainer *)bf->o->bin_obj);
		bf->o->bin_obj = NULL;
	}
}

static RzBinInfo *npy_info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	NpyContainer *c = bf->o->bin_obj;
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->file = strdup(bf->file);
	ret->type = strdup("NumPy Array");
	ret->bclass = strdup("data");
	ret->rclass = strdup("npy");
	ret->os = strdup("any");
	ret->arch = NULL;
	ret->machine = strdup("NumPy");
	ret->bits = (int)(8 * c->header.elem_size);
	ret->has_va = false;
	ret->big_endian = (c->header.descr[0] == '>');

	return ret;
}

static RzPVector /*<RzBinSection *>*/ *npy_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	NpyContainer *c = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	RzBinSection *header = RZ_NEW0(RzBinSection);
	if (header) {
		header->name = strdup(".header");
		header->paddr = 0;
		header->vaddr = 0;
		header->perm = RZ_PERM_R;
		header->size = c->data_offset;
		header->vsize = c->data_offset;
		rz_pvector_push(ret, header);
	}

	RzBinSection *data = RZ_NEW0(RzBinSection);
	if (data) {
		ut64 total = npy_total_elements(&c->header);

		data->name = strdup(".data");
		data->paddr = c->data_offset;
		data->vaddr = 0;
		data->perm = RZ_PERM_R;
		data->size = total * c->header.elem_size;
		data->vsize = data->size;
		rz_pvector_push(ret, data);
	}

	return ret;
}

static RzStructuredData *npy_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	NpyContainer *c = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *npy = rz_structured_data_map_add_map(info, "npy");
	if (!npy) {
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *header = rz_structured_data_map_add_map(npy, "header");
	if (!header) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_bytes(header, "magic", NPY_MAGIC, NPY_ARRAY_MAGIC_LENGTH, RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_unsigned(header, "version_major", c->ver_major, false);
	rz_structured_data_map_add_unsigned(header, "version_minor", c->ver_minor, false);
	rz_structured_data_map_add_string(header, "dtype_descr", c->header.descr);
	rz_structured_data_map_add_boolean(header, "fortran_order", c->header.fortran_order);
	rz_structured_data_map_add_unsigned(header, "ndim", c->header.ndim, false);

	RzStructuredData *shape_arr = rz_structured_data_map_add_array(header, "shape");
	if (shape_arr) {
		for (size_t i = 0; i < c->header.ndim; i++) {
			rz_structured_data_array_add_unsigned(shape_arr, c->header.shape[i], false);
		}
	}
	ut64 total = npy_total_elements(&c->header);

	rz_structured_data_map_add_unsigned(header, "element_size", c->header.elem_size, false);
	rz_structured_data_map_add_unsigned(header, "element_count", total, false);
	rz_structured_data_map_add_unsigned(header, "data_size", total * c->header.elem_size, false);
	rz_structured_data_map_add_unsigned(header, "data_offset", c->data_offset, false);

	return info;
}

RZ_API RzBinPlugin rz_bin_plugin_npy = {
	.name = "npy",
	.desc = "NumPy Array Format (.npy)",
	.license = "LGPL3",
	.author = "farhan-25",
	.check_buffer = &npy_check_buffer,
	.load_buffer = &npy_load_buffer,
	.destroy = &npy_destroy,
	.sections = &npy_sections,
	.info = &npy_info,
	.bin_structure = &npy_structure
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_npy,
	.version = RZ_VERSION
};
#endif