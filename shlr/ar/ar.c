// SPDX-FileCopyrightText: 2017 xarkes <antide.petit@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <stdio.h>
#include <rz_util.h>
#include "ar.h"

#define AR_MAGIC_HEADER    "!<arch>\n"
#define AR_FILE_HEADER_END "`\n"

typedef struct Filetable {
	char *data;
	ut64 size;
	ut64 offset;
} filetable;

static RzArFp *arfp_new(RzBuffer *b, ut32 *refcount) {
	rz_return_val_if_fail(b, NULL);
	RzArFp *f = RZ_NEW(RzArFp);
	if (f) {
		if (refcount) {
			(*refcount)++;
		}
		f->name = NULL;
		f->refcount = refcount;
		f->buf = b;
		f->start = 0;
		f->end = 0;
	}
	return f;
}

bool ar_check_magic(RzBuffer *b) {
	char buf[sizeof(AR_MAGIC_HEADER) - 1];
	if (rz_buf_read(b, (ut8 *)buf, sizeof(buf)) != sizeof(buf)) {
		return false;
	}
	if (strncmp(buf, AR_MAGIC_HEADER, 8)) {
		eprintf("Wrong file type.\n");
		return false;
	}
	return true;
}

static inline void arf_clean_name(RzArFp *arf) {
	free(arf->name);
	arf->name = NULL;
}

static char *name_from_table(ut64 off, filetable *tbl) {
	if (off > tbl->size) {
		eprintf("Malformed ar: name lookup out of bounds for header at offset 0x%" PFMT64x "\n", off);
		return NULL;
	}
	// files are suppose to be line feed seperated but we also stop on invalid
	// chars, such as '/' or '\0'

	char *buf = tbl->data;
	ut64 i;
	for (i = off; i < tbl->size; i++) {
		char c = buf[i];
		if (c == '\n' || c == '\0') {
			break;
		}
	}
	if (i == off) {
		return NULL;
	}
	return rz_str_newlen(buf + off, i - off - 1);
}

#define VERIFY_AR_NUM_FIELD(x, s) \
	x[sizeof(x) - 1] = '\0'; \
	rz_str_trim_tail(x); \
	if (x[0] != '\0' && (x[0] == '-' || !rz_str_isnumber(x))) { \
		eprintf("Malformed AR: bad %s in header at offset 0x%" PFMT64x "\n", s, h_off); \
		return -1; \
	}

/* -1 error, 0 end, 1 contnue */
static int ar_parse_header(RzArFp *arf, filetable *tbl, ut64 arsize) {
	rz_return_val_if_fail(arf && arf->buf && tbl, -1);
	RzBuffer *b = arf->buf;

	ut64 h_off = rz_buf_tell(b);
	if (h_off % 2 == 1) {
		// headers start at even offset
		ut8 tmp[1];
		if (rz_buf_read(b, tmp, 1) != 1 || tmp[0] != '\n') {
			return -1;
		}
		h_off++;
	}

	struct header {
		char name[16];
		char timestamp[12];
		char oid[6];
		char gid[6];
		char mode[8];
		char size[10];
		char end[2];
	} h;

	int r = rz_buf_read(b, (ut8 *)&h, sizeof(h));
	if (r != sizeof(h)) {
		if (r == 0) {
			return 0; // no more file
		}
		if (r < 0) {
			eprintf("io_ar: io error\n");
		} else {
			eprintf("io_ar: Invalid file length\n");
		}
		return -1;
	}

	if (strncmp(h.end, AR_FILE_HEADER_END, sizeof(h.end))) {
		eprintf("Invalid header at offset 0x%" PFMT64x ": bad end field\n", h_off);
		return -1;
	}

	// remove trailing spaces from fields and verify they are valid
	VERIFY_AR_NUM_FIELD(h.timestamp, "timestamp")
	VERIFY_AR_NUM_FIELD(h.oid, "oid")
	VERIFY_AR_NUM_FIELD(h.gid, "gid")
	VERIFY_AR_NUM_FIELD(h.mode, "mode")
	VERIFY_AR_NUM_FIELD(h.size, "size")

	if (h.size[0] == '\0') {
		eprintf("Malformed AR: bad size in header at offset 0x%" PFMT64x "\n", h_off);
		return -1;
	}
	ut64 size = atol(h.size);

	h.timestamp[0] = '\0'; // null terminate h.name
	rz_str_trim_tail(h.name);

	/*
	 * handle fake files
	*/
	if (!strcmp(h.name, "/")) {
		// skip over symbol table
		if (rz_buf_seek(b, size, RZ_BUF_CUR) <= 0 || rz_buf_tell(b) > arsize) {
			eprintf("Malformed ar: too short\n");
			return -1;
		}
		// return next entry
		return ar_parse_header(arf, tbl, arsize);
	} else if (!strcmp(h.name, "//")) {
		// table of file names
		if (tbl->data || tbl->size != 0) {
			eprintf("invalid ar file: two filename lookup tables (at 0x%" PFMT64x ", and 0x%" PFMT64x ")\n", tbl->offset, h_off);
			return -1;
		}
		tbl->data = (char *)malloc(size + 1);
		if (!tbl->data || rz_buf_read(b, (ut8 *)tbl->data, size) != size) {
			return -1;
		}
		tbl->data[size] = '\0';
		tbl->size = size;
		tbl->offset = h_off;

		// return next entry
		return ar_parse_header(arf, tbl, arsize);
	}

	/*
	 * handle real files
	*/
	RzList *list = rz_str_split_duplist(h.name, "/", false); // don't strip spaces
	if (rz_list_length(list) != 2) {
		rz_list_free(list);
		eprintf("invalid ar file: invalid file name in header at: 0x%" PFMT64x "\n", h_off);
		return -1;
	}

	char *tmp = rz_list_pop_head(list);
	if (tmp[0] == '\0') {
		free(tmp);
		tmp = rz_list_pop(list);
		if (rz_str_isnumber(tmp)) {
			arf->name = name_from_table(atol(tmp), tbl);
		} else {
			eprintf("invalid ar file: invalid file name in header at: 0x%" PFMT64x "\n", h_off);
		}
		free(tmp);
	} else {
		arf->name = tmp;
		tmp = rz_list_pop(list);
		if (tmp[0]) {
			arf_clean_name(arf);
			eprintf("invalid ar file: invalid file name in header at: 0x%" PFMT64x "\n", h_off);
		}
		free(tmp);
	}
	rz_list_free(list);

	if (!arf->name) {
		return -1;
	}
	arf->start = rz_buf_tell(b);
	arf->end = arf->start + size;

	// skip over file content and make sure it is all there
	if (rz_buf_seek(b, size, RZ_BUF_CUR) <= 0 || rz_buf_tell(b) > arsize) {
		eprintf("Malformed ar: missing the end of %s (header offset: 0x%" PFMT64x ")\n", arf->name, h_off);
		arf_clean_name(arf);
		return -1;
	}

	return 1;
}
#undef VERIFY_AR_NUM_FIELD

/**
 * \brief Open specific file withen a ar/lib file.
 * \param arname the name of the .a file
 * \param filename the name of file in the .a file that you wish to open
 * \return a handle of the internal filename or NULL
 *
 * Open an ar/lib file by name. If filename is NULL, then archive files will be
 * listed.
 */
RZ_API RzArFp *ar_open_file(const char *arname, int perm, const char *filename) {
	RzBuffer *b = rz_buf_new_file(arname, perm, 0);
	if (!b) {
		rz_sys_perror(__FUNCTION__);
		return NULL;
	}

	ut64 arsize = rz_buf_size(b);

	if (!ar_check_magic(b)) {
		rz_buf_free(b);
		return NULL;
	}

	RzArFp *arf = arfp_new(b, NULL);
	if (!arf) {
		rz_buf_free(b);
		return NULL;
	}

	filetable tbl = { NULL, 0, 0 };
	int r;
	while ((r = ar_parse_header(arf, &tbl, arsize)) > 0) {
		if (filename) {
			if (!strcmp(filename, arf->name)) {
				// found the right file
				break;
			}
		} else {
			printf("%s\n", arf->name);
		}

		// clean RzArFp for next loop
		arf_clean_name(arf);
	}

	free(tbl.data);

	if (r <= 0) {
		if (r == 0 && filename) {
			eprintf("Cound not find file '%s' in archive '%s'\n", filename, arname);
		}
		ar_close(arf); // results in buf being free'd
		return NULL;
	}

	return arf;
}

RZ_API int ar_close(RzArFp *f) {
	if (f) {
		free(f->name);
		if (f->refcount) {
			(*f->refcount)--;
		}

		// no more files open, clean underlying buffer
		if (!f->refcount || f->refcount == 0) {
			free(f->refcount);
			rz_buf_free(f->buf);
		}
		free(f);
	}
	return 0;
}

RZ_API int ar_read_at(RzArFp *f, ut64 off, void *buf, int count) {
	off += f->start;
	if (off > f->end) {
		return -1;
	}
	if (count + off > f->end) {
		count = f->end - off;
	}
	return rz_buf_read_at(f->buf, off, buf, count);
}

RZ_API int ar_write_at(RzArFp *f, ut64 off, void *buf, int count) {
	off += f->start;
	if (off > f->end) {
		return -1;
	}
	if (count + off > f->end) {
		count = f->end - off;
	}
	return rz_buf_write_at(f->buf, off + f->start, buf, count);
}
