// SPDX-FileCopyrightText: 2021 Manolache183 <manolache.alexandru8@gmail.com>
// SPDX-FileCopyrightText: 2021 swym  <0xfd000000@gmail.com>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/* Motorola S-record file format
 * +--------+------------+---------+------+----------+----+
 * | S type | byte count | address | data | checksum | \n |
 * +--------+------------+---------+------+----------+----+
 * 0        1            2         4      N         N+1  N+2
 *
 * https://en.wikipedia.org/wiki/SREC_(file_format)
 */

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_util.h>

#include "rz_io_plugins.h"

#define SREC_SIZE        64
#define NMAX             100
#define SREC_PATH_PREFIX "srec://"

typedef struct srec_t {
	st32 fd;
	RzBuffer *buf;
} SRecord;

static void write_S3_record(FILE *fd, ut32 address, const ut8 *buffer, ut16 size) {
	rz_return_if_fail(fd && buffer);

	ut8 record_size = 4 + size + 1;
	ut8 checksum = record_size;
	checksum += address & 0xff;
	checksum += (address >> 8) & 0xff;
	checksum += (address >> 16) & 0xff;
	checksum += address >> 24;

	fprintf(fd, "S3%02x%08x", record_size, address);

	for (ut16 j = 0; j < size; j++) {
		checksum += buffer[j];
		fprintf(fd, "%02x", buffer[j]);
	}

	fprintf(fd, "%02" PFMT32x "\n", ~checksum & UT8_MAX);
}

static st32 __write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	rz_return_val_if_fail(fd && fd->data && fd->perm & RZ_PERM_W && count > 0, -1);

	const char *pathname = NULL;
	FILE *out = NULL;
	SRecord *srec = NULL;
	ut32 address = 0, size = 0;
	ut8 n_bytes = 0;
	size_t chunks_count = 0;
	const RzBufferSparseChunk *chunks = NULL;
	const RzBufferSparseChunk *sparse = NULL;

	srec = (SRecord *)fd->data;
	pathname = fd->name + strlen(SREC_PATH_PREFIX);
	out = rz_sys_fopen(pathname, "w");

	if (!out) {
		RZ_LOG_ERROR("srec:write(): cannot open '%s' for writing\n", pathname);
		return -1;
	}

	// starting record, contains "rizin-srec\0"
	fprintf(out, "S00E000072697A696E2D7372656300EB\n");

	/* mem write */
	if (rz_buf_write_at(srec->buf, io->off, buf, count) != count) {
		RZ_LOG_ERROR("srec:write(): cannot write into buffer\n");
		fclose(out);
		return -1;
	}

	rz_buf_seek(srec->buf, count, RZ_BUF_CUR);
	chunks = rz_buf_sparse_get_chunks(srec->buf, &chunks_count);

	for (size_t i = 0; i < chunks_count; i++) {
		sparse = &chunks[i];
		size = sparse->to - sparse->from;
		for (ut32 offset = 0; offset < size; offset += SREC_SIZE) {
			address = sparse->from + offset;
			n_bytes = SREC_SIZE;
			if (offset + SREC_SIZE > size) {
				n_bytes = size - offset + 1;
			}
			write_S3_record(out, address, sparse->data + offset, n_bytes);
		}
	}

	// termination
	fprintf(out, "S70500000000FA\n");
	fclose(out);
	out = NULL;
	return count;
}

static st32 __read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	rz_return_val_if_fail(io && fd && fd->data && buf && count > 0, -1);

	SRecord *srec = (SRecord *)fd->data;
	memset(buf, io->Oxff, count);
	st32 r = rz_buf_read_at(srec->buf, io->off, buf, count);
	if (r >= 0) {
		rz_buf_seek(srec->buf, r, RZ_BUF_CUR);
	}
	// sparse read return >= 0 but < count still means everything was read successfully,
	// just maybe not entirely populated by chunks:
	return r < 0 ? -1 : count;
}

static st32 __close(RzIODesc *fd) {
	rz_return_val_if_fail(fd && fd->data, -1);

	SRecord *srec = (SRecord *)fd->data;
	rz_buf_free(srec->buf);
	free(srec);
	fd->data = NULL;
	return 0;
}

static ut64 __lseek(struct rz_io_t *io, RzIODesc *fd, ut64 offset, st32 whence) {
	rz_return_val_if_fail(fd && fd->data, 0);
	SRecord *srec = (SRecord *)fd->data;
	io->off = rz_buf_seek(srec->buf, offset, whence);
	return io->off;
}

static bool __plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, SREC_PATH_PREFIX, strlen(SREC_PATH_PREFIX)));
}

/**
 * Parse a value formatted like "%02x" of exactly 2 chars
 */
static bool parse_hex_byte(const char *str, RZ_OUT ut8 *out) {
	if (!str[0] || !str[1]) {
		return false;
	}
	*out = 0;
	return !rz_hex_to_byte(out, str[0]) && !rz_hex_to_byte(out, str[1]);
}

/**
 * Parse an n-byte big endian hex value of exactly 2*n chars
 */
static bool parse_hex_bytes(const char *str, size_t count, RZ_OUT ut32 *out) {
	*out = 0;
	while (count--) {
		ut8 byte;
		if (!parse_hex_byte(str, &byte)) {
			return false;
		}
		*out = *out << 8 | (ut32)byte;
		str += 2;
	}
	return true;
}

/**
 * Parse a prefix formatted like "S%c%02x" of exactly 4 chars
 */
static bool parse_srecord_prefix(const char *str, RZ_OUT char *record_type, RZ_OUT st32 *byte_count) {
	if (*str != 'S') {
		return false;
	}
	*record_type = str[1];
	if (!*record_type) {
		return false;
	}
	ut8 bc;
	if (!parse_hex_byte(str + 2, &bc)) {
		return false;
	}
	*byte_count = bc;
	return true;
}

static bool srecord_parse(RzBuffer *buf, char *str) {
	if (!str || *str != 'S') {
		return false;
	}
	ut8 *record_data = NULL;
	ut32 record_size = 0;
	ut32 record_begin = 0;
	ut32 record_addr = 0;
	ut32 record_next = 0;
	char record_type = 0;
	char *eol = NULL;
	ut8 cksum = 0;
	st32 byte_count = 0;
	st32 i = 0, counter = 0;
	int line = 0;

	record_data = malloc(UT16_MAX);
	if (!record_data) {
		goto fail;
	}

	do {
		line++;
		if (!parse_srecord_prefix(str, &record_type, &byte_count)) {
			RZ_LOG_ERROR("srec:parse(): invalid prefix in Motorola S-record file at line %d\n", line);
			goto fail;
		}

		byte_count &= 0xff;

		switch (record_type) {
		case '0': // Header with 16-bit address
			counter = byte_count - 3;
			if (!parse_hex_bytes(str + 4, 2, &record_addr)) {
				RZ_LOG_ERROR("srec:parse(): invalid header hexadecimal address 16-bit at line %d\n", line);
				goto fail;
			}
			record_addr &= 0xffff;

			cksum = byte_count;
			cksum += record_addr & 0xff;
			cksum += record_addr >> 8;

			for (i = 0; i < counter; i++) {
				ut8 byte;
				if (!parse_hex_byte(str + 8 + (i * 2), &byte)) {
					RZ_LOG_ERROR("srec:parse(): invalid hexadecimal value! at line %d\n", line);
					goto fail;
				}
				cksum += byte;
			}
			break;

		case '1': // Data with 16-bit address
			counter = byte_count - 3;
			if (!parse_hex_bytes(str + 4, 2, &record_addr)) {
				RZ_LOG_ERROR("srec:parse(): invalid data hexadecimal address 16-bit at line %d\n", line);
				goto fail;
			}
			record_addr &= 0xffff;

			cksum = byte_count;
			cksum += record_addr & 0xff;
			cksum += record_addr >> 8;

			if ((record_next != record_addr) || ((record_size + counter) > UT16_MAX)) {
				if (record_size && record_size < UT16_MAX) {
					if (rz_buf_write_at(buf, record_begin, record_data, (st32)record_size) != record_size) {
						RZ_LOG_ERROR("srec:parse(): cannot write buffer at 0x%x\n", record_begin);
						goto fail;
					}
				}
				record_begin = record_addr;
				record_next = record_addr;
				record_size = 0;
			}

			for (i = 0; i < byte_count - 3; i++) {
				ut8 byte;
				if (!parse_hex_byte(str + 8 + (i * 2), &byte)) {
					RZ_LOG_ERROR("srec:parse(): invalid hexadecimal value at line %d\n", line);
					goto fail;
				}
				if (record_size + i < UT16_MAX) {
					record_data[record_size + i] = (ut8)byte & 0xff;
				}
				cksum += byte;
			}
			record_size += counter;
			record_next += counter;
			break;

		case '5': // Count with 16-bit address
			if (!parse_hex_bytes(str + 4, 2, &record_addr)) {
				RZ_LOG_ERROR("srec:parse(): invalid count hexadecimal address 16-bit at line %d\n", line);
				goto fail;
			}
			record_addr &= 0xffff;
			cksum = byte_count;
			cksum += record_addr & 0xff;
			cksum += record_addr >> 8;
			break;

		case '9': // Terminator with 16-bit address
			if (!parse_hex_bytes(str + 4, 2, &record_addr)) {
				RZ_LOG_ERROR("srec:parse(): invalid terminator hexadecimal address 16-bit at line %d\n", line);
				goto fail;
			}

			eol = strchr(str + 1, 'S');
			if (eol) {
				*eol = 0;
			}

			record_addr &= 0xffff;
			cksum = byte_count;
			cksum += record_addr & 0xff;
			cksum += record_addr >> 8;
			break;
		case '2': // Data with 24-bit address
			counter = byte_count - 4;
			if (!parse_hex_bytes(str + 4, 3, &record_addr)) {
				RZ_LOG_ERROR("srec:parse(): invalid data hexadecimal address 24-bit at line %d\n", line);
				goto fail;
			}
			record_addr &= 0xffffff;

			cksum = byte_count;
			cksum += record_addr & 0xff;
			cksum += (record_addr >> 8) & 0xff;
			cksum += record_addr >> 16;

			if ((record_next != record_addr) || ((record_size + counter) > UT16_MAX)) {
				if (record_size && record_size < UT16_MAX) {
					if (rz_buf_write_at(buf, record_begin, record_data, (st32)record_size) != record_size) {
						RZ_LOG_ERROR("srec:parse(): cannot write buffer at 0x%x\n", record_begin);
						goto fail;
					}
				}
				record_begin = record_addr;
				record_next = record_addr;
				record_size = 0;
			}

			for (i = 0; i < byte_count - 4; i++) {
				ut8 byte;
				if (!parse_hex_byte(str + 10 + (i * 2), &byte)) {
					RZ_LOG_ERROR("srec:parse(): invalid hexadecimal value at line %d\n", line);
					goto fail;
				}
				if (record_size + i < UT16_MAX) {
					record_data[record_size + i] = (ut8)byte & 0xff;
				}
				cksum += byte;
			}
			record_size += counter;
			record_next += counter;
			break;

		case '6': // Count with 24-bit address
			if (!parse_hex_bytes(str + 4, 3, &record_addr)) {
				RZ_LOG_ERROR("srec:parse(): invalid hexadecimal address 24-bit at line %d\n", line);
				goto fail;
			}
			record_addr &= 0xffffff;
			cksum = byte_count;
			cksum += record_addr & 0xff;
			cksum += (record_addr >> 8) & 0xff;
			cksum += record_addr >> 16;
			break;

		case '8': // Terminator with 24-bit address
			if (!parse_hex_bytes(str + 4, 3, &record_addr)) {
				RZ_LOG_ERROR("srec:parse(): invalid hexadecimal address 24-bit at line %d\n", line);
				goto fail;
			}
			record_addr &= 0xffffff;

			eol = strchr(str + 1, 'S');
			if (eol) {
				*eol = 0;
			}

			cksum = byte_count;
			cksum += record_addr & 0xff;
			cksum += (record_addr >> 8) & 0xff;
			cksum += record_addr >> 16;
			break;

		case '3': // Data with 32-bit address
			counter = byte_count - 5;
			if (!parse_hex_bytes(str + 4, 4, &record_addr)) {
				RZ_LOG_ERROR("srec:parse(): invalid hexadecimal address 32-bit at line %d\n", line);
				goto fail;
			}
			record_addr &= 0xffffffff;

			cksum = byte_count;
			cksum += record_addr & 0xff;
			cksum += (record_addr >> 8) & 0xff;
			cksum += (record_addr >> 16) & 0xff;
			cksum += record_addr >> 24;

			if ((record_next != record_addr) || ((record_size + counter) > UT16_MAX)) {
				if (record_size && record_size < UT16_MAX) {
					if (rz_buf_write_at(buf, record_begin, record_data, (st32)record_size) != record_size) {
						RZ_LOG_ERROR("srec:parse(): cannot write buffer at 0x%x\n", record_begin);
						goto fail;
					}
				}
				record_begin = record_addr;
				record_next = record_addr;
				record_size = 0;
			}

			for (i = 0; i < byte_count - 5; i++) {
				ut8 byte;
				if (!parse_hex_byte(str + 12 + (i * 2), &byte)) {
					RZ_LOG_ERROR("srec:parse(): invalid hexadecimal value at line %d\n", line);
					goto fail;
				}
				if (record_size + i < UT16_MAX) {
					record_data[record_size + i] = (ut8)byte & 0xff;
				}
				cksum += byte;
			}
			record_size += counter;
			record_next += counter;
			break;

		case '7': // Terminator with 32-bit address
			if (!parse_hex_bytes(str + 4, 4, &record_addr)) {
				RZ_LOG_ERROR("srec:parse(): invalid hexadecimal address 32-bit at line %d\n", line);
				goto fail;
			}
			record_addr &= 0xffffffff;

			eol = strchr(str + 1, 'S');
			if (eol) {
				*eol = 0;
			}

			cksum = byte_count;
			cksum += record_addr & 0xff;
			cksum += (record_addr >> 8) & 0xff;
			cksum += (record_addr >> 16) & 0xff;
			cksum += record_addr >> 24;
			break;

		case '4': // reserved
			continue;
		default:
			RZ_LOG_ERROR("srec:parse(): invalid Motorola S-record type '%c' at line %d\n", record_type, line);
			goto fail;
		}

		// Validate checksum
		cksum = ~cksum;
		ut8 cksum_expect;
		if (!parse_hex_byte(str + 2 + (byte_count * 2), &cksum_expect)) {
			RZ_LOG_ERROR("srec:parse(): invalid hexadecimal value! at line %d\n", line);
			goto fail;
		}
		if (cksum != cksum_expect) {
			RZ_LOG_ERROR("srec:parse(): checksum test failed (calculated %02x, but expected %02x) at line %d\n", cksum, cksum_expect, line);
			goto fail;
		}
		str = strchr(str + 1, 'S');
	} while (str);

	if (record_size && record_size < UT16_MAX) {
		if (rz_buf_write_at(buf, record_begin, record_data, (st32)record_size) != record_size) {
			RZ_LOG_ERROR("srec:parse(): cannot write buffer at 0x%x\n", record_begin);
			goto fail;
		}
	}

	free(record_data);
	return true;
fail:
	free(record_data);
	return false;
}

static RzIODesc *__open(RzIO *io, const char *pathname, st32 rw, st32 mode) {
	rz_return_val_if_fail(io && pathname, NULL);

	SRecord *mal = NULL;
	char *str = NULL;
	if (__plugin_open(io, pathname, 0)) {
		str = rz_file_slurp(pathname + 7, NULL);
		if (!str) {
			return NULL;
		}
		mal = RZ_NEW0(SRecord);
		if (!mal) {
			free(str);
			return NULL;
		}
		mal->buf = rz_buf_new_sparse(io->Oxff);
		if (!mal->buf) {
			free(str);
			free(mal);
			return NULL;
		}
		if (!srecord_parse(mal->buf, str)) {
			RZ_LOG_ERROR("srec: failed to parse file\n");
			free(str);
			rz_buf_free(mal->buf);
			free(mal);
			return NULL;
		}
		free(str);
		return rz_io_desc_new(io, &rz_io_plugin_srec, pathname, rw, mal);
	}
	return NULL;
}

static bool __resize(RzIO *io, RzIODesc *fd, ut64 size) {
	rz_return_val_if_fail(fd && fd->data, false);

	SRecord *srec = (SRecord *)fd->data;
	if (srec) {
		return rz_buf_resize(srec->buf, size);
	}
	return false;
}

RzIOPlugin rz_io_plugin_srec = {
	.name = "srec",
	.desc = "Motorola S-record file format",
	.uris = SREC_PATH_PREFIX,
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
	.data = &rz_io_plugin_srec,
	.version = RZ_VERSION
};
#endif
