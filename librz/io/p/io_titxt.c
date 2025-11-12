// SPDX-FileCopyrightText: 2025 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/*
 * Rizin IO plugin for the Texas Instruments TI-TXT file format
 * https://manpages.org/srec_ti_txt/5
 */

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_util.h>

#include "rz_io_plugins.h"

#define TITXT_PATH_PREFIX     "titxt://"
#define TITXT_PATH_PREFIX_LEN (sizeof(TITXT_PATH_PREFIX) - 1)
#define TITXT_SECTION_PREFIX  '@'
#define TITXT_EOF_MARKER      'q'

typedef struct titxt_t {
	st32 fd;
	RzBuffer *buf;
} TITxt;

static void write_titxt_section(FILE *out, ut64 address, const ut8 *data, ut64 size) {
	fprintf(out, "@%" PRIx64 "\n", address);
	for (ut64 i = 0; i < size; i++) {
		bool new_line = i % 16 == 15;
		bool last_byte = i == size - 1;
		fprintf(out, "%02X%c", data[i], (new_line || last_byte) ? '\n' : ' ');
	}
}

static st32 __write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	rz_return_val_if_fail(fd && fd->data && fd->perm & RZ_PERM_W && count > 0, -1);

	const char *pathname = NULL;
	FILE *file_out = NULL;
	TITxt *ctx = NULL;
	size_t chunks_count = 0;
	const RzBufferSparseChunk *chunks = NULL;

	ctx = (TITxt *)fd->data;
	pathname = fd->name + TITXT_PATH_PREFIX_LEN;
	file_out = rz_sys_fopen(pathname, "w");

	if (!file_out) {
		RZ_LOG_ERROR("titxt:write(): cannot open '%s' for writing\n", pathname);
		return -1;
	}

	/* Write to RzBuffer */
	if (rz_buf_write_at(ctx->buf, io->off, buf, count) != count) {
		RZ_LOG_ERROR("titxt:write(): cannot write %zu bytes into buffer\n", count);
		fclose(file_out);
		return -1;
	}

	rz_buf_seek(ctx->buf, count, RZ_BUF_CUR);
	chunks = rz_buf_sparse_get_chunks(ctx->buf, &chunks_count);

	for (size_t i = 0; i < chunks_count; i++) {
		write_titxt_section(file_out, chunks[i].from, chunks[i].data, chunks[i].to - chunks[i].from + 1);
	}

	// Write EOF marker
	fprintf(file_out, "%c\n", TITXT_EOF_MARKER);
	fclose(file_out);
	file_out = NULL;
	return count;
}

static st32 __read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	rz_return_val_if_fail(io && fd && fd->data && buf && count > 0, -1);

	TITxt *ctx = (TITxt *)fd->data;
	memset(buf, io->Oxff, count);
	st32 r = rz_buf_read_at(ctx->buf, io->off, buf, count);
	if (r >= 0) {
		rz_buf_seek(ctx->buf, r, RZ_BUF_CUR);
	}
	// sparse read return >= 0 but < count still means everything was read successfully,
	// just maybe not entirely populated by chunks:
	return r < 0 ? -1 : count;
}

static st32 __close(RzIODesc *fd) {
	rz_return_val_if_fail(fd && fd->data, -1);

	TITxt *ctx = (TITxt *)fd->data;
	rz_buf_free(ctx->buf);
	free(ctx);
	fd->data = NULL;
	return 0;
}

static ut64 __lseek(struct rz_io_t *io, RzIODesc *fd, ut64 offset, st32 whence) {
	rz_return_val_if_fail(fd && fd->data, 0);
	TITxt *ctx = (TITxt *)fd->data;
	io->off = rz_buf_seek(ctx->buf, offset, whence);
	return io->off;
}

static bool __plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, TITXT_PATH_PREFIX, TITXT_PATH_PREFIX_LEN));
}

static const char *skip_ws(const char *str) {
	if (!str) {
		return NULL;
	}
	while (*str == ' ' || *str == '\t') {
		str++;
	}
	return str;
}

static const char *skip_ws_and_nl(const char *str) {
	if (!str) {
		return NULL;
	}
	while (*str == ' ' || *str == '\n' || *str == '\r') {
		str++;
	}
	return str;
}

static int parse_hex_digit(ut8 c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

static bool titxt_parse_section(const char **str, RzBuffer *buf) {
	const char *p = *str;

	// Expect section prefix
	if (*(p++) != TITXT_SECTION_PREFIX) {
		return false;
	}

	ut64 address = 0;
	int digit = 0;
	ut8 digit_count = 0;

	// Parse address (up to 64 bit address)
	while (*p && (digit = parse_hex_digit(*p)) >= 0 && digit_count++ < 16) {
		address = (address << 4) | (ut64)digit;
		p++;
	}

	// Validate address format
	if (digit_count == 0 || digit_count > 16) {
		RZ_LOG_ERROR("titxt:parse_section(): invalid address format\n");
		*str = p;
		return false;
	}

	// Move past new line
	p = skip_ws_and_nl(p);

	// Parse data bytes until next section or EOF marker
	ut64 byte_count = 0;
	ut8 local_buffer[4096];
	ut8 local_buffer_size = 0;

	while (*p) {
		ut8 nibble1;
		ut8 nibble2;

		// Parse 2 nibbles
		if ((nibble1 = parse_hex_digit(*(p++))) < 0 || (nibble2 = parse_hex_digit(*(p++))) < 0) {
			RZ_LOG_ERROR("titxt:parse_section(): invalid hex digit\n");
			*str = p;
			return false;
		}

		// Expect a whitespace or newline
		if (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
			RZ_LOG_ERROR("titxt:parse_section(): expected whitespace / newline after byte\n");
			*str = p;
			return false;
		}

		// Skip whitespaces
		p = skip_ws_and_nl(p);
		bool end_of_section = *p == TITXT_EOF_MARKER || *p == TITXT_SECTION_PREFIX;

		// Write to local buffer
		local_buffer[local_buffer_size++] = (nibble1 << 4) | nibble2;
		byte_count++;

		// Flush to RzBuffer if local buffer is full or we've reached end of section
		if (local_buffer_size == sizeof(local_buffer) || end_of_section) {
			ut64 offset = address + byte_count - local_buffer_size;
			if (rz_buf_write_at(buf, offset, local_buffer, local_buffer_size) != local_buffer_size) {
				RZ_LOG_ERROR("titxt:parse_section(): cannot write data bytes to RzBuffer\n");
				*str = p;
				return false;
			}
			local_buffer_size = 0;
		}

		// Terminate if we've reached end of section
		if (end_of_section) {
			*str = p;
			break;
		}
	}

	return true;
}

static void titxt_get_line_and_column(const char *str, size_t max_chars, int *line, int *column) {
	*line = 1;
	*column = 1;

	while (*str && max_chars--) {
		if (*(str++) == '\n') {
			(*line)++;
			*column = 1;
		} else {
			(*column)++;
		}
	}
}

static bool titxt_parse(RzBuffer *buf, char *str_base) {
	rz_return_val_if_fail(buf && str_base, false);
	const char *str = str_base;

	// Consider an empty file valid
	if (*str == TITXT_EOF_MARKER) {
		return true;
	}

	// Otherwise the file needs to start with a section prefix
	if (*str != TITXT_SECTION_PREFIX) {
		return false;
	}

	// Find and parse each section
	do {
		// str should always point to a section prefix in a valid TI-TXT file
		if (!titxt_parse_section(&str, buf)) {
			int l, c;
			titxt_get_line_and_column(str_base, str - str_base, &l, &c);
			RZ_LOG_ERROR("titxt:parse(): failed to parse section in TI-TXT file at line %d, column %d\n", l, c);
			return false;
		}
	} while (*str != TITXT_EOF_MARKER);

	return true;
}

static RzIODesc *__open(RzIO *io, const char *pathname, st32 rw, st32 mode) {
	rz_return_val_if_fail(io && pathname, NULL);

	TITxt *ctx = NULL;
	char *file_content = NULL;

	if (__plugin_open(io, pathname, 0)) {
		file_content = rz_file_slurp(pathname + TITXT_PATH_PREFIX_LEN, NULL);
		if (!file_content) {
			return NULL;
		}
		ctx = RZ_NEW0(TITxt);
		if (!ctx) {
			free(file_content);
			return NULL;
		}
		ctx->buf = rz_buf_new_sparse(io->Oxff);
		if (!ctx->buf) {
			free(file_content);
			free(ctx);
			return NULL;
		}
		if (!titxt_parse(ctx->buf, file_content)) {
			RZ_LOG_ERROR("titxt: failed to parse file\n");
			free(file_content);
			rz_buf_free(ctx->buf);
			free(ctx);
			return NULL;
		}
		free(file_content);
		return rz_io_desc_new(io, &rz_io_plugin_titxt, pathname, rw, ctx);
	}
	return NULL;
}

static bool __resize(RzIO *io, RzIODesc *fd, ut64 size) {
	rz_return_val_if_fail(fd && fd->data, false);

	TITxt *ctx = (TITxt *)fd->data;
	return rz_buf_resize(ctx->buf, size);
}

RzIOPlugin rz_io_plugin_titxt = {
	.name = "titxt",
	.desc = "Texas Instruments TI-TXT file format",
	.uris = TITXT_PATH_PREFIX,
	.license = "LGPL-3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_titxt,
	.version = RZ_VERSION
};
#endif
