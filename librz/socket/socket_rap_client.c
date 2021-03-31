// SPDX-FileCopyrightText: 2011-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_socket.h>
#include <rz_util.h>

static ut8 *rz_rap_packet(ut8 type, ut32 len) {
	ut8 *buf = malloc(len + 5);
	if (buf) {
		buf[0] = type;
		rz_write_be32(buf + 1, len);
	}
	return buf;
}

static void rz_rap_packet_fill(ut8 *buf, const ut8 *src, int len) {
	if (buf && src && len > 0) {
		ut32 curlen = rz_read_be32(buf + 1);
		memcpy(buf + 5, src, RZ_MIN(curlen, len));
	}
}

RZ_API int rz_socket_rap_client_open(RzSocket *s, const char *file, int rw) {
	rz_socket_block_time(s, true, 1, 0);
	size_t file_len0 = strlen(file) + 1;
	if (file_len0 > 255) {
		eprintf("Filename too long\n");
		return -1;
	}
	char *buf = malloc(file_len0 + 7);
	if (!buf) {
		return -1;
	}
	// >>
	buf[0] = RAP_PACKET_OPEN;
	buf[1] = rw;
	buf[2] = (ut8)(file_len0 & 0xff);
	memcpy(buf + 3, file, file_len0);
	(void)rz_socket_write(s, buf, 3 + file_len0);
	rz_socket_flush(s);
	// <<
	int fd = -1;
	memset(buf, 0, 5);
	int r = rz_socket_read_block(s, (ut8 *)buf, 5);
	if (r == 5) {
		if (buf[0] == (char)(RAP_PACKET_OPEN | RAP_PACKET_REPLY)) {
			fd = rz_read_at_be32(buf + 1, 1);
		} else {
			eprintf("RapClientOpen: Bad packet 0x%02x\n", buf[0]);
		}
	} else {
		eprintf("Cannot read 5 bytes from server\n");
	}
	free(buf);
	return fd;
}

RZ_API char *rz_socket_rap_client_command(RzSocket *s, const char *cmd, RzCoreBind *c) {
	char *buf = malloc(strlen(cmd) + 8);
	if (!buf) {
		return NULL;
	}
	/* send request */
	buf[0] = RAP_PACKET_CMD;
	size_t i = strlen(cmd) + 1;
	rz_write_be32(buf + 1, i);
	memcpy(buf + 5, cmd, i);
	rz_socket_write(s, buf, 5 + i);
	rz_socket_flush(s);
	free(buf);
	/* read response */
	char bufr[8];
	rz_socket_read_block(s, (ut8 *)bufr, 5);
	while (bufr[0] == (char)(RAP_PACKET_CMD)) {
		size_t cmd_len = rz_read_at_be32(bufr, 1);
		char *rcmd = calloc(1, cmd_len + 1);
		if (rcmd) {
			rz_socket_read_block(s, (ut8 *)rcmd, cmd_len);
			// char *res = rz_core_cmd_str (core, rcmd);
			char *res = c->cmdstr(c->core, rcmd);
			if (res) {
				int res_len = strlen(res) + 1;
				ut8 *pkt = rz_rap_packet((RAP_PACKET_CMD | RAP_PACKET_REPLY), res_len);
				rz_rap_packet_fill(pkt, (const ut8 *)res, res_len);
				rz_socket_write(s, pkt, 5 + res_len);
				rz_socket_flush(s);
				free(res);
				free(pkt);
			}
			free(rcmd);
		}
		/* read response */
		bufr[0] = -1;
		(void)rz_socket_read_block(s, (ut8 *)bufr, 5);
	}
	if (bufr[0] != (char)(RAP_PACKET_CMD | RAP_PACKET_REPLY)) {
		eprintf("Error: Wrong reply for command 0x%02x\n", bufr[0]);
		return NULL;
	}
	size_t cmd_len = rz_read_at_be32(bufr, 1);
	if (cmd_len < 1 || cmd_len > 16384) {
		eprintf("Error: cmd_len is wrong\n");
		return NULL;
	}
	char *cmd_output = calloc(1, cmd_len + 1);
	if (!cmd_output) {
		eprintf("Error: Allocating cmd output\n");
		return NULL;
	}
	rz_socket_read_block(s, (ut8 *)cmd_output, cmd_len);
	//ensure the termination
	cmd_output[cmd_len] = 0;
	return cmd_output;
}

RZ_API int rz_socket_rap_client_write(RzSocket *s, const ut8 *buf, int count) {
	ut8 *tmp;
	int ret;
	if (count < 1) {
		return count;
	}
	// TOOD: if count > RAP_PACKET_MAX iterate !
	if (count > RAP_PACKET_MAX) {
		count = RAP_PACKET_MAX;
	}
	if (!(tmp = (ut8 *)malloc(count + 5))) {
		eprintf("__rap_write: malloc failed\n");
		return -1;
	}
	tmp[0] = RAP_PACKET_WRITE;
	rz_write_be32(tmp + 1, count);
	memcpy(tmp + 5, buf, count);

	(void)rz_socket_write(s, tmp, count + 5);
	rz_socket_flush(s);
	if (rz_socket_read_block(s, tmp, 5) != 5) { // TODO read_block?
		eprintf("__rap_write: error\n");
		ret = -1;
	} else {
		ret = rz_read_be32(tmp + 1);
		if (!ret) {
			ret = -1;
		}
	}
	free(tmp);
	return ret;
}

RZ_API int rz_socket_rap_client_read(RzSocket *s, ut8 *buf, int count) {
	ut8 tmp[32];
	if (count < 1) {
		return count;
	}
	rz_socket_block_time(s, 1, 1, 0);
	// XXX. if count is > RAP_PACKET_MAX, just perform multiple queries
	if (count > RAP_PACKET_MAX) {
		count = RAP_PACKET_MAX;
	}
	// send
	tmp[0] = RAP_PACKET_READ;
	rz_write_be32(tmp + 1, count);
	(void)rz_socket_write(s, tmp, 5);
	rz_socket_flush(s);
	// recv
	int ret = rz_socket_read_block(s, tmp, 5);
	if (ret != 5 || tmp[0] != (RAP_PACKET_READ | RAP_PACKET_REPLY)) {
		eprintf("__rap_read: Unexpected rap read reply "
			"(%d=0x%02x) expected (%d=0x%02x)\n",
			ret, tmp[0], 2, (RAP_PACKET_READ | RAP_PACKET_REPLY));
		return -1;
	}
	int i = rz_read_at_be32(tmp, 1);
	if (i > count) {
		eprintf("__rap_read: Unexpected data size %d vs %d\n", i, count);
		return -1;
	}
	rz_socket_read_block(s, buf, i);
	return count;
}

RZ_API int rz_socket_rap_client_seek(RzSocket *s, ut64 offset, int whence) {
	ut8 tmp[10];
	tmp[0] = RAP_PACKET_SEEK;
	tmp[1] = (ut8)whence;
	rz_write_be64(tmp + 2, offset);
	(void)rz_socket_write(s, &tmp, 10);
	rz_socket_flush(s);
	int ret = rz_socket_read_block(s, (ut8 *)&tmp, 9);
	if (ret != 9) {
		eprintf("Truncated socket read\n");
		return -1;
	}
	if (tmp[0] != (RAP_PACKET_SEEK | RAP_PACKET_REPLY)) {
		// eprintf ("%d %d  - %02x %02x %02x %02x %02x %02x %02x\n",
		// ret, whence, tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6]);
		eprintf("Unexpected seek reply (%02x -> %02x)\n", tmp[0], (RAP_PACKET_SEEK | RAP_PACKET_REPLY));
		return -1;
	}
	return rz_read_at_be64(tmp, 1);
}
