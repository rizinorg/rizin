#include <stdio.h>
#include <stdlib.h>
#include "rz_io.h"
#include "rz_hash.h"

int main(int argc, char **argv) {
	RzIODesc *fd;
	ut8 *buf;
	ut64 size;
	struct rz_io_t *io;

	if (argc < 2) {
		printf("Usage: %s [file]\n", argv[0]);
		return 1;
	}

	io = rz_io_new();

	fd = rz_io_open_nomap(io, argv[1], RZ_IO_READ, 0);
	if (fd == NULL) {
		eprintf("Cannot open file\n");
		return 1;
	}

	/* get file size */
	size = rz_io_size(io);

	/* read bytes */
	buf = (ut8 *)malloc(size);
	if (buf == NULL) {
		printf("Big too file\n");
		rz_io_close(io, fd);
		rz_io_free(io);
		return 1;
	}

	memset(buf, 0, size);
	rz_io_read(io, buf, size);
	printf("----\n%s\n----\n", buf);

	printf("file size = %" PFMT64d "\n", size);
	printf("CRC32: 0x%08x\n", rz_hash_crc32(buf, size));

	{
		struct rz_hash_t *ctx;
		const ut8 *c;
		int i;
		//rz_hash_init(&ctx, true, RZ_HASH_ALL);
		ctx = rz_hash_new(true, RZ_HASH_ALL);
		c = rz_hash_do_md5(ctx, buf, size);
		printf("MD5: ");
		for (i = 0; i < RZ_HASH_SIZE_MD5; i++) {
			printf("%02x", c[i]);
		}
		printf("\n");

		c = rz_hash_do_sha1(ctx, buf, size);
		printf("SHA1: ");
		for (i = 0; i < RZ_HASH_SIZE_SHA1; i++) {
			printf("%02x", c[i]);
		}
		printf("\n");

		c = rz_hash_do_sha256(ctx, buf, size);
		printf("SHA256: ");
		for (i = 0; i < RZ_HASH_SIZE_SHA256; i++) {
			printf("%02x", c[i]);
		}
		printf("\n");
		rz_hash_free(ctx);
	}

	rz_io_close(io, fd);
	rz_io_free(io);
	free(buf);
	return 0;
}
