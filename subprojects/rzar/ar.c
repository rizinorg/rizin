// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2017 xarkes <antide.petit@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <stdio.h>
#include <sys/stat.h>
#include "ar.h"

#define IS_PATH(c) (IS_ALPHANUM(c) || (c == '/') || (c == '\\') || (c == '.'))

#define AR_MAGIC_HEADER       "!<arch>\n"
#define AR_ENTRY_DELIMITER    "`\n"
#define AR_ENTRY_NAME_LEN     16
#define AR_ENTRY_DATE_LEN     12
#define AR_ENTRY_UID_LEN      6
#define AR_ENTRY_GID_LEN      6
#define AR_ENTRY_MODE_LEN     8
#define AR_ENTRY_SIZE_LEN     10
#define AR_ENTRY_DELIM_LEN    2
#define AR_ENTRY_MODE_OFF     (AR_ENTRY_DATE_LEN + AR_ENTRY_UID_LEN + AR_ENTRY_GID_LEN)
#define AR_ENTRY_MODE_INVALID UT32_MAX

typedef struct Filetable {
	char *data;
	ut64 size;
	ut64 offset;
} filetable;

static RzArFp *arfp_new(RzBuffer *b, bool shared_buf) {
	rz_return_val_if_fail(b, NULL);
	RzArFp *f = RZ_NEW(RzArFp);
	if (f) {
		f->name = NULL;
		f->shared_buf = shared_buf;
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
		RZ_LOG_ERROR("ar: Wrong file type.\n");
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
		RZ_LOG_ERROR("ar: Malformed ar: name lookup out of bounds for header at offset 0x%" PFMT64x "\n", off);
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
	return rz_str_newlen(buf + off, i - off);
}

static ut64 pow8[] = {
	01, 010, 0100, 01000, 010000, 0100000, 01000000, 010000000, 0100000000
};

static ut32 parse_st_mode(const char *s_mode) {
	if (!s_mode[0]) {
		return 0;
	}
	ut32 decimal = 0;
	ut32 result = 0;
	ut32 octal = atoi(s_mode);

	if (octal > 177777) {
		// atoi will convert 177777oct into 177777dec, so we test for this.
		return AR_ENTRY_MODE_INVALID;
	}

	while (octal > 0) {
		ut32 y = octal % 10;
		octal /= 10;
		result += y * pow8[decimal];
		++decimal;
		if (decimal >= RZ_ARRAY_SIZE(pow8)) {
			// this should never happen.
			return AR_ENTRY_MODE_INVALID;
		}
	}

	return result;
}

static bool ar_read_entry(RzBuffer *buffer, char *e_name, ut64 *e_size, ut32 *e_mode) {
	st64 cursor = rz_buf_tell(buffer);
	if (cursor >= rz_buf_size(buffer)) {
		return false;
	}

	// always ensure the strings are null terminated.
	char s_mode[AR_ENTRY_MODE_LEN + 1] = { 0 };
	char s_size[AR_ENTRY_SIZE_LEN + 1] = { 0 };
	char s_delimiter[AR_ENTRY_DELIM_LEN] = { 0 };

	if (rz_buf_read(buffer, (ut8 *)e_name, AR_ENTRY_NAME_LEN) != AR_ENTRY_NAME_LEN) {
		cursor = rz_buf_tell(buffer);
		RZ_LOG_ERROR("ar: expected entry name at 0x%" PFMT64x " but couldn't read.\n", cursor);
		return false;
	}

	cursor = rz_buf_tell(buffer);
	if (rz_buf_seek(buffer, AR_ENTRY_MODE_OFF, RZ_BUF_CUR) <= cursor) {
		cursor += AR_ENTRY_MODE_OFF;
		RZ_LOG_ERROR("ar: failed to seek at 0x%" PFMT64x ".\n", cursor);
		return false;
	}

	if (rz_buf_read(buffer, (ut8 *)s_mode, AR_ENTRY_MODE_LEN) != AR_ENTRY_MODE_LEN) {
		cursor = rz_buf_tell(buffer);
		RZ_LOG_ERROR("ar: expected entry mode at 0x%" PFMT64x " but couldn't read.\n", cursor);
		return false;
	}

	if (rz_buf_read(buffer, (ut8 *)s_size, AR_ENTRY_SIZE_LEN) != AR_ENTRY_SIZE_LEN) {
		cursor = rz_buf_tell(buffer);
		RZ_LOG_ERROR("ar: expected entry size at 0x%" PFMT64x " but couldn't read.\n", cursor);
		return false;
	}

	if (rz_buf_read(buffer, (ut8 *)s_delimiter, sizeof(s_delimiter)) != sizeof(s_delimiter) ||
		s_delimiter[0] != '`' || s_delimiter[1] != '\n') {
		cursor = rz_buf_tell(buffer);
		RZ_LOG_ERROR("ar: expected entry delimiter at 0x%" PFMT64x " but it wasn't found.\n", cursor);
		return false;
	}

	rz_str_trim_tail(e_name);
	rz_str_trim_tail(s_mode);
	rz_str_trim_tail(s_size);

	*e_size = s_size[0] ? atol(s_size) : 0;
	*e_mode = parse_st_mode(s_mode);
	return true;
}

static void ar_sanitize_name(RzArFp *arf) {
	bool trim_end = true;
	st64 len = strlen(arf->name);
	if (len < 1) {
		return;
	}

	// cleanup path which could be present in names
	for (st64 i = len - 1; i >= 0; i--) {
		if (trim_end && (arf->name[i] == '\\' || arf->name[i] == '/')) {
			// files shall never end with path delimeters.
			arf->name[i] = '_';
		} else if (arf->name[i] == '\\') {
			// we use URI to access a single file
			// thus the path needs to be unix only
			arf->name[i] = '/';
		} else if (!IS_PATH(arf->name[i])) {
			arf->name[i] = '_';
		} else {
			trim_end = false;
		}
	}
}

/* -1 error, 0 end, 1 continue */
static int ar_parse_entry(RzArFp *arf, filetable *tbl, ut64 arsize) {
	rz_return_val_if_fail(arf && arf->buf && tbl, -1);
	RzBuffer *b = arf->buf;
	// always ensure the strings are null terminated.
	char e_name[AR_ENTRY_NAME_LEN + 1] = { 0 };
	ut64 e_size = 0;
	ut32 e_mode = 0;

	ut64 e_offset = rz_buf_tell(b);
	if (e_offset % 2 == 1) {
		// headers start at even offset
		ut8 tmp[1];
		if (rz_buf_read(b, tmp, 1) != 1 || tmp[0] != '\n') {
			return -1;
		}
		e_offset++;
	}

	if (!ar_read_entry(b, e_name, &e_size, &e_mode)) {
		return -1;
	}

	/*
	 * handle fake files
	 */
	if (!strcmp(e_name, "/")) {
		// skip over symbol table
		if (rz_buf_seek(b, e_size, RZ_BUF_CUR) <= 0 || rz_buf_tell(b) > arsize) {
			RZ_LOG_ERROR("ar: Malformed ar: too short\n");
			return -1;
		}
		// return next entry
		return ar_parse_entry(arf, tbl, arsize);
	} else if (!strcmp(e_name, "//")) {
		// table of file names
		if (tbl->data || tbl->size != 0) {
			RZ_LOG_ERROR("ar: invalid ar file: two filename lookup tables (at 0x%" PFMT64x ", and 0x%" PFMT64x ")\n", tbl->offset, e_offset);
			return -1;
		}
		tbl->data = (char *)malloc(e_size + 1);
		if (!tbl->data || rz_buf_read(b, (ut8 *)tbl->data, e_size) != e_size) {
			return -1;
		}
		tbl->data[e_size] = '\0';
		tbl->size = e_size;
		tbl->offset = e_offset;

		// return next entry
		return ar_parse_entry(arf, tbl, arsize);
	}

	/*
	 * handle real files
	 */
	RzList *list = rz_str_split_duplist(e_name, "/", false); // don't strip spaces
	if (rz_list_length(list) != 2) {
		rz_list_free(list);
		RZ_LOG_ERROR("ar: invalid ar file: invalid file name in header at: 0x%" PFMT64x "\n", e_offset);
		return -1;
	}

	char *tmp = rz_list_pop_head(list);
	if (tmp[0] == '\0') {
		free(tmp);
		tmp = rz_list_pop(list);
		if (rz_str_isnumber(tmp)) {
			arf->name = name_from_table(atol(tmp), tbl);
		} else {
			RZ_LOG_ERROR("ar: invalid ar file: invalid file name in header at: 0x%" PFMT64x "\n", e_offset);
		}
		free(tmp);
	} else {
		arf->name = tmp;
		tmp = rz_list_pop(list);
		if (tmp[0]) {
			arf_clean_name(arf);
			RZ_LOG_ERROR("ar: invalid ar file: invalid file name in header at: 0x%" PFMT64x "\n", e_offset);
		}
		free(tmp);
	}
	rz_list_free(list);

	if (!arf->name) {
		return -1;
	}

	arf->start = rz_buf_tell(b);
	arf->end = arf->start + e_size;
	arf->st_mode = e_mode;
	ar_sanitize_name(arf);

	// skip over file content and make sure it is all there
	if (rz_buf_seek(b, e_size, RZ_BUF_CUR) <= 0 || rz_buf_tell(b) > arsize) {
		RZ_LOG_ERROR("ar: Malformed ar: missing the end of %s (header offset: 0x%" PFMT64x ")\n", arf->name, e_offset);
		arf_clean_name(arf);
		return -1;
	}

	return 1;
}

/**
 * \brief Open specific file withen a ar/lib file.
 * \param arname the name of the .a file
 * \return a list of files or NULL
 *
 * Open an ar/lib and returns all the object files inside it.
 */
RZ_API RzList /*<RzArFp *>*/ *ar_open_all(const char *arname, int perm) {
	ut32 fmode = 0;
	if (!arname) {
		rz_sys_perror(__FUNCTION__);
		return NULL;
	}

	RzList *files = rz_list_newf((RzListFree)ar_close);
	if (!files) {
		rz_sys_perror(__FUNCTION__);
		return NULL;
	}

	RzBuffer *b = rz_buf_new_file(arname, perm, 0);
	if (!b) {
		rz_list_free(files);
		rz_sys_perror(__FUNCTION__);
		return NULL;
	}

	ut64 arsize = rz_buf_size(b);

	if (!ar_check_magic(b)) {
		rz_list_free(files);
		rz_buf_free(b);
		return NULL;
	}

	filetable tbl = { NULL, 0, 0 };
	int res = -1;
	bool shared = false;

	do {
		shared = !rz_list_empty(files);
		RzArFp *arf = arfp_new(b, shared);
		if (!arf) {
			rz_list_free(files);
			if (!shared) {
				rz_buf_free(b);
			}
			return NULL;
		}

		if ((res = ar_parse_entry(arf, &tbl, arsize)) <= 0) {
			// on error or when it has reached the EOF
			free(tbl.data);
			ar_close(arf);
			return files;
		}
		// on linux the fmode is always 0, but arf->mode is non-zero
		if (!arf->st_mode ||
			((fmode = (arf->st_mode & S_IFMT)) && fmode != S_IFREG) ||
			arf->start >= arf->end) {
			// open only regular files.
			// we do not need to close the buffer
			arf->shared_buf = true;
			ar_close(arf);
			continue;
		}

		if (!rz_list_append(files, arf)) {
			free(tbl.data);
			ar_close(arf);
			rz_list_free(files);
			return NULL;
		}
	} while (res > 0);

	// this portion should never be reached
	free(tbl.data);
	return files;
}

/**
 * \brief Open specific file withen a ar/lib file.
 * \param arname the name of the .a file
 * \param filename the name of file in the .a file that you wish to open
 * \return a handle of the internal filename or NULL
 *
 * Open an ar/lib file by name.
 */
RZ_API RzArFp *ar_open_file(const char *arname, int perm, const char *filename) {
	if (!filename || !arname) {
		rz_sys_perror(__FUNCTION__);
		return NULL;
	}

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

	RzArFp *arf = arfp_new(b, false);
	if (!arf) {
		rz_buf_free(b);
		return NULL;
	}

	filetable tbl = { NULL, 0, 0 };
	int r;
	while ((r = ar_parse_entry(arf, &tbl, arsize)) > 0) {
		if (filename) {
			if (!strcmp(filename, arf->name)) {
				// found the right file
				break;
			}
		}

		// clean RzArFp for next loop
		arf_clean_name(arf);
	}

	free(tbl.data);

	if (r <= 0) {
		if (r == 0 && filename) {
			RZ_LOG_ERROR("ar: Cound not find file '%s' in archive '%s'\n", filename, arname);
		}
		ar_close(arf); // results in buf being free'd
		return NULL;
	}

	return arf;
}

RZ_API void ar_close(RzArFp *f) {
	if (!f) {
		return;
	}
	free(f->name);
	if (!f->shared_buf) {
		rz_buf_free(f->buf);
	}
	free(f);
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
