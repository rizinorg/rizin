// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#define RZ_MACBIN_FINDER_FLAG_INITED    (1 << 0)
#define RZ_MACBIN_FINDER_FLAG_CHANGED   (1 << 1)
#define RZ_MACBIN_FINDER_FLAG_BUSY      (1 << 2)
#define RZ_MACBIN_FINDER_FLAG_BOZO      (1 << 3)
#define RZ_MACBIN_FINDER_FLAG_SYSTEM    (1 << 4)
#define RZ_MACBIN_FINDER_FLAG_BUNDLE    (1 << 5)
#define RZ_MACBIN_FINDER_FLAG_INVISIBLE (1 << 6)
#define RZ_MACBIN_FINDER_FLAG_LOCKED    (1 << 7)

typedef struct rz_macbin_header_t {
	ut8 ver_old;
	ut8 filename_len;
	char filename[63];
	char file_type[4];
	char file_creator[4];
	ut8 finder_flags;
	ut16 pos_vert;
	ut16 pos_horz;
	ut16 window_folder_id;
	ut8 protected_flag;
	ut32 data_fork_len;
	ut32 resource_fork_len;
	ut32 creation_date;
	ut32 last_modified_date;
	ut16 get_info_len; ///< first proposed extension to MacBinary I
	// Below is new in MacBinary II
	ut8 finder_flags_low;
	ut32 total_files_len;
	ut16 secondary_hdr_len;
	ut8 macbinii_ver;
	ut8 macbinii_ver_min;
	ut16 crc;
} RzMacBinHeader;

RZ_API bool rz_macbin_header_read(RZ_NONNULL RZ_IN RzBuffer *buf, RZ_NONNULL RZ_OUT RzMacBinHeader *dst) {
	rz_return_val_if_fail(buf && dst, false);
	ut8 raw[128];
	if (rz_buf_read_at(buf, 0, raw, sizeof(raw)) != sizeof(raw)) {
		return false;
	}
	// MacBinary I
	dst->ver_old = raw[0];
	if (dst->ver_old || raw[74] || raw[82]) {
		// early validity check for fields that must be zero
		return false;
	}
	dst->filename_len = raw[1];
	memcpy(dst->filename, raw + 2, sizeof(dst->filename));
	memcpy(dst->file_type, raw + 65, sizeof(dst->file_type));
	memcpy(dst->file_creator, raw + 69, sizeof(dst->file_creator));
	dst->finder_flags = raw[73];
	dst->pos_vert = rz_read_at_be16(raw, 75);
	dst->pos_horz = rz_read_at_be16(raw, 77);
	dst->window_folder_id = rz_read_at_be16(raw, 79);
	dst->protected_flag = raw[81];
	dst->data_fork_len = rz_read_at_be32(raw, 83);
	dst->resource_fork_len = rz_read_at_be32(raw, 87);
	dst->creation_date = rz_read_at_be32(raw, 91);
	dst->last_modified_date = rz_read_at_be32(raw, 95);
	// Extensions to MacBinary I start here
	dst->get_info_len = rz_read_at_be16(raw, 99);
	// MacBinary II
	dst->finder_flags_low = raw[101];
	dst->total_files_len = rz_read_at_be32(raw, 116);
	dst->secondary_hdr_len = rz_read_at_be16(raw, 120);
	dst->macbinii_ver = raw[122];
	dst->macbinii_ver_min = raw[123];
	dst->crc = rz_read_at_be16(raw, 124);
	return true;
}

RZ_API ut64 rz_macbin_header_resource_fork_offset(RZ_NONNULL const RzMacBinHeader *hdr) {
	ut64 r = 128 + hdr->data_fork_len;
	r += rz_num_align_delta(r, 128);
	return r;
}

#if MACBIN_TOOL
static void usage() {
	printf("Usage: macbin <file>\n");
	printf(
		"  <no options> print the file's MacBinary header in a readable form\n"
		"  -h           this help message\n"
		"  -d           dump the file's data fork to stdout\n"
		"  -r           dump the file's resource fork to stdout\n"
		"");
}

static void table_row_escaped(RzTable *t, const char *name, const char *val, size_t val_len) {
	char *b = malloc(val_len + 1);
	if (!b) {
		return;
	}
	memcpy(b, val, val_len);
	b[val_len] = 0;
	char *escaped = rz_str_escape(b);
	free(b);
	if (!escaped) {
		return;
	}
	rz_table_add_rowf(t, "ss", name, escaped);
	free(escaped);
}

static void print_header(RzMacBinHeader *hdr) {
	RzTable *t = rz_table_new();
	if (!t) {
		return;
	}
	rz_table_set_columnsf(t, "ss", "field", "value");
	rz_table_add_rowf(t, "sx", "MacBinary I version", (ut64)hdr->ver_old);
	rz_table_add_rowf(t, "sx", "filename length", (ut64)hdr->filename_len);
	table_row_escaped(t, "filename", hdr->filename, RZ_MIN(sizeof(hdr->filename), hdr->filename_len));
	table_row_escaped(t, "file type", hdr->file_type, sizeof(hdr->file_type));
	table_row_escaped(t, "file creator", hdr->file_creator, sizeof(hdr->file_creator));
	rz_table_add_rowf(t, "sx", "Finder flags (high)", (ut64)hdr->finder_flags);
	rz_table_add_rowf(t, "sx", "vertical position", (ut64)hdr->pos_vert);
	rz_table_add_rowf(t, "sx", "horizontal position", (ut64)hdr->pos_horz);
	rz_table_add_rowf(t, "sx", "window/folder id", (ut64)hdr->window_folder_id);
	rz_table_add_rowf(t, "sx", "protected flag", (ut64)hdr->protected_flag);
	rz_table_add_rowf(t, "sx", "data fork length", (ut64)hdr->data_fork_len);
	rz_table_add_rowf(t, "sx", "resource fork length", (ut64)hdr->resource_fork_len);
	rz_table_add_rowf(t, "sx", "creation date", (ut64)hdr->creation_date);
	rz_table_add_rowf(t, "sx", "last modified date", (ut64)hdr->last_modified_date);
	rz_table_add_rowf(t, "sx", "get info length", (ut64)hdr->get_info_len);

	// Mac Binary II
	rz_table_add_rowf(t, "sx", "Finder flags (low)", (ut64)hdr->finder_flags_low);
	rz_table_add_rowf(t, "sx", "total files length", (ut64)hdr->total_files_len);
	rz_table_add_rowf(t, "sx", "secondary header length", (ut64)hdr->secondary_hdr_len);
	rz_table_add_rowf(t, "su", "MacBinary II version", (ut64)hdr->macbinii_ver);
	rz_table_add_rowf(t, "su", "MacBinary II minimal version", (ut64)hdr->macbinii_ver_min);
	rz_table_add_rowf(t, "sx", "crc", (ut64)hdr->crc);

	char *s = rz_table_tostring(t);
	rz_table_free(t);
	if (!s) {
		return;
	}
	printf("%s", s);
	free(s);
}

int main(int argc, const char *argv[]) {
	RzGetopt opt;
	rz_getopt_init(&opt, argc, argv, "hdr");
	char c;
	char dump = 0;
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'd':
		case 'r':
			if (dump) {
				eprintf("Only one fork may be dumped at a time.\n");
				return 1;
			}
			dump = c;
			break;
		case 'h':
		default:
			usage();
			return c == 'h' ? 0 : 1;
		}
	}
	argc -= opt.ind;
	argv += opt.ind;
	if (argc != 1) {
		usage();
		return 1;
	}
	const char *filename = argv[0];
	RzBuffer *buf = rz_buf_new_file(filename, O_RDONLY, 0);
	if (!buf) {
		eprintf("Failed to open file %s\n", filename);
		return 1;
	}
	RzMacBinHeader hdr;
	int ret = 1;
	if (!rz_macbin_header_read(buf, &hdr)) {
		eprintf("Failed to read header or file is not a MacBinary.\n");
		goto end;
	}
	if (dump) {
		ut64 offset = dump == 'r' ? rz_macbin_header_resource_fork_offset(&hdr) : 128;
		ut32 size = dump == 'r' ? hdr.resource_fork_len : hdr.data_fork_len;
		ut8 *tmp = malloc(size);
		if (!tmp) {
			eprintf("Memory allocation for dumping fork failed.\n");
			goto end;
		}
		if (rz_buf_read_at(buf, offset, tmp, size) != size) {
			eprintf("Failed to read fork from file for dumping.\n");
			free(tmp);
			goto end;
		}
		size_t r = fwrite(tmp, size, 1, stdout);
		free(tmp);
		if (!r) {
			eprintf("Failed to write fork data to stdout.\n");
			goto end;
		}
	} else {
		print_header(&hdr);
	}
	ret = 0;
end:
	rz_buf_free(buf);
	return ret;
}
#endif
