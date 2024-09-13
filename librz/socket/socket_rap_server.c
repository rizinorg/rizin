// SPDX-FileCopyrightText: 2014-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014-2019 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_socket.h>
#include <rz_util.h>

RZ_API RzSocketRapServer *rz_socket_rap_server_new(bool use_ssl, const char *port) {
	rz_return_val_if_fail(port, NULL);
	RzSocketRapServer *s = RZ_NEW0(RzSocketRapServer);
	if (s) {
		s->port = rz_str_dup(port);
		s->fd = rz_socket_new(use_ssl);
		if (s->fd) {
			return s;
		}
		rz_socket_free(s->fd);
		free(s);
	}
	return NULL;
}

RZ_API RzSocketRapServer *rz_socket_rap_server_create(const char *pathname) {
	rz_return_val_if_fail(pathname, NULL);
	if (strlen(pathname) < 11) {
		return NULL;
	}
	if (strncmp(pathname, "rap", 3)) {
		return NULL;
	}
	bool is_ssl = (pathname[3] == 's');
	const char *port = &pathname[7 + is_ssl];
	return rz_socket_rap_server_new(is_ssl, port);
}

RZ_API void rz_socket_rap_server_free(RzSocketRapServer *s) {
	if (s) {
		rz_socket_free(s->fd);
		free(s);
	}
}

RZ_API bool rz_socket_rap_server_listen(RzSocketRapServer *s, const char *certfile) {
	rz_return_val_if_fail(s && s->port && *s->port, false);
	return rz_socket_listen(s->fd, s->port, certfile);
}

RZ_API RzSocket *rz_socket_rap_server_accept(RzSocketRapServer *s) {
	rz_return_val_if_fail(s && s->fd, NULL);
	return rz_socket_accept(s->fd);
}

RZ_API bool rz_socket_rap_server_continue(RzSocketRapServer *s) {
	rz_return_val_if_fail(s && s->fd, false);

	int i;
	char *ptr = NULL;

	if (!rz_socket_is_connected(s->fd)) {
		return false;
	}
	rz_socket_read_block(s->fd, s->buf, 1);
	switch (s->buf[0]) {
	case RAP_PACKET_OPEN:
		rz_socket_read_block(s->fd, &s->buf[1], 2);
		rz_socket_read_block(s->fd, &s->buf[3], (int)s->buf[2]);
		{
			int fd = s->open(s->user, (const char *)&s->buf[3], (int)s->buf[1], 0);
			s->buf[0] = RAP_PACKET_OPEN | RAP_PACKET_REPLY;
			eprintf("REPLY BACK %d\n", fd);
			rz_write_be32(s->buf + 1, fd);
		}
		rz_socket_write(s->fd, s->buf, 5);
		rz_socket_flush(s->fd);
		break;
	case RAP_PACKET_READ:
		rz_socket_read_block(s->fd, &s->buf[1], 4);
		i = rz_read_be32(&s->buf[1]);
		if (i > RAP_PACKET_MAX || i < 0) {
			i = RAP_PACKET_MAX;
		}
		s->read(s->user, &s->buf[5], i);
		s->buf[0] = RAP_PACKET_READ | RAP_PACKET_REPLY;
		rz_socket_write(s->fd, s->buf, i + 5);
		rz_socket_flush(s->fd);
		break;
	case RAP_PACKET_WRITE:
		rz_socket_read_block(s->fd, s->buf + 1, 4);
		i = rz_read_be32(s->buf + 1);
		if (i > RAP_PACKET_MAX || i < 0) {
			i = RAP_PACKET_MAX;
		}
		rz_socket_read_block(s->fd, s->buf + 5, i);
		rz_write_be32(s->buf + 1, s->write(s->user, s->buf + 5, i));
		s->buf[0] = RAP_PACKET_WRITE | RAP_PACKET_REPLY;
		rz_socket_write(s->fd, s->buf, 5);
		rz_socket_flush(s->fd);
		break;
	case RAP_PACKET_SEEK: {
		rz_socket_read_block(s->fd, &s->buf[1], 9);
		int whence = s->buf[0];
		ut64 offset = rz_read_be64(s->buf + 1);
		offset = s->seek(s->user, offset, whence);
		/* prepare reply */
		s->buf[0] = RAP_PACKET_SEEK | RAP_PACKET_REPLY;
		rz_write_be64(s->buf + 1, offset);
		rz_socket_write(s->fd, s->buf, 9);
		rz_socket_flush(s->fd);
	} break;
	case RAP_PACKET_CMD:
		rz_socket_read_block(s->fd, &s->buf[1], 4);
		i = rz_read_be32(&s->buf[1]);
		if (rz_socket_read_block(s->fd, &s->buf[5], i) > 0) {
			ptr = s->cmd(s->user, (const char *)s->buf + 5);
			i = (ptr) ? strlen(ptr) + 1 : 0;
			rz_write_be32(&s->buf[1], i);
			s->buf[0] = RAP_PACKET_CMD | RAP_PACKET_REPLY;
			rz_socket_write(s->fd, s->buf, 5);
			if (i) {
				rz_socket_write(s->fd, ptr, i);
			}
			rz_socket_flush(s->fd);
			RZ_FREE(ptr);
		}
		break;
	case RAP_PACKET_CLOSE:
		rz_socket_read_block(s->fd, &s->buf[1], 4);
		i = rz_read_be32(&s->buf[1]);
		s->close(s->user, i);
		s->buf[0] = RAP_PACKET_CLOSE | RAP_PACKET_REPLY;
		rz_socket_write(s->fd, s->buf, 5);
		rz_socket_flush(s->fd);
		break;
	default:
		eprintf("unknown command 0x%02x\n", (ut8)(s->buf[0] & 0xff));
		rz_socket_close(s->fd);
		return false;
	}
	return true;
}
