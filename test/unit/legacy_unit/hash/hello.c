#include <stdio.h>
#include <stdlib.h>
#include <rz_io.h>
#include <rz_msg_digest.h>

int main(int argc, char **argv) {
	RzIODesc *fd = NULL;
	ut8 *buf = NULL;
	ut64 size = 0;
	RzIO *io = NULL;
	char *digest = NULL;
	RzMsgDigest *md = NULL;
	int result = 1;

	if (argc < 2) {
		printf("Usage: %s [file]\n", argv[0]);
		return 1;
	}

	io = rz_io_new();
	if (io == NULL) {
		eprintf("Cannot alloc io\n");
		goto main_fail;
	}

	fd = rz_io_open_nomap(io, argv[1], RZ_IO_READ, 0);
	if (fd == NULL) {
		eprintf("Cannot open file\n");
		goto main_fail;
	}

	/* get file size */
	size = rz_io_size(io);

	/* read bytes */
	buf = (ut8 *)malloc(size);
	if (buf == NULL) {
		printf("Big too file\n");
		goto main_fail;
	}

	memset(buf, 0, size);
	rz_io_read(io, buf, size);
	printf("----\n%s\n----\n", buf);

	printf("file size = %" PFMT64d "\n", size);

	const ut8 *c;
	int i;
	md = rz_msg_digest_new_with_algo2("all");
	if (!md) {
		goto main_fail;
	}
	rz_msg_digest_update(md, buf, size);
	rz_msg_digest_final(md);

	digest = rz_msg_digest_get_result_string(md, "crc32", NULL, false);
	printf("CRC32:  %s\n", digest);
	free(digest);

	digest = rz_msg_digest_get_result_string(md, "md5", NULL, false);
	printf("MD5:    %s\n", digest);
	free(digest);

	digest = rz_msg_digest_get_result_string(md, "sha1", NULL, false);
	printf("SHA1:   %s\n", digest);
	free(digest);

	digest = rz_msg_digest_get_result_string(md, "sha256", NULL, false);
	printf("SHA256: %s\n", digest);
	free(digest);

	result = 0;

main_fail:
	rz_msg_digest_free(md);
	rz_io_close(io, fd);
	rz_io_free(io);
	free(buf);
	return result;
}
