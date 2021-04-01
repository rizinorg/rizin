// SPDX-FileCopyrightText: 2006-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/* must be included first because of winsock2.h and windows.h */
#include <rz_socket.h>
#include <rz_types.h>
#include <rz_util.h>
#include <errno.h>

#if EMSCRIPTEN
#define NETWORK_DISABLED 1
#else
#define NETWORK_DISABLED 0
#endif

#define D if (0)

RZ_LIB_VERSION(rz_socket);

#if NETWORK_DISABLED
/* no network */
RZ_API RzSocket *rz_socket_new(bool is_ssl) {
	return NULL;
}
RZ_API bool rz_socket_is_connected(RzSocket *s) {
	return false;
}
RZ_API bool rz_socket_connect(RzSocket *s, const char *host, const char *port, int proto, unsigned int timeout) {
	return false;
}
RZ_API bool rz_socket_spawn(RzSocket *s, const char *cmd, unsigned int timeout) {
	return -1;
}
RZ_API int rz_socket_close_fd(RzSocket *s) {
	return -1;
}
RZ_API int rz_socket_close(RzSocket *s) {
	return -1;
}
RZ_API int rz_socket_free(RzSocket *s) {
	return -1;
}
RZ_API int rz_socket_port_by_name(const char *name) {
	return -1;
}
RZ_API bool rz_socket_listen(RzSocket *s, const char *port, const char *certfile) {
	return false;
}
RZ_API RzSocket *rz_socket_accept(RzSocket *s) {
	return NULL;
}
RZ_API RzSocket *rz_socket_accept_timeout(RzSocket *s, unsigned int timeout) {
	return NULL;
}
RZ_API bool rz_socket_block_time(RzSocket *s, bool block, int sec, int usec) {
	return false;
}
RZ_API int rz_socket_flush(RzSocket *s) {
	return -1;
}
RZ_API int rz_socket_ready(RzSocket *s, int secs, int usecs) {
	return -1;
}
RZ_API char *rz_socket_to_string(RzSocket *s) {
	return NULL;
}
RZ_API int rz_socket_write(RzSocket *s, void *buf, int len) {
	return -1;
}
RZ_API int rz_socket_puts(RzSocket *s, char *buf) {
	return -1;
}
RZ_API void rz_socket_printf(RzSocket *s, const char *fmt, ...) {
	/* nothing here */
}
RZ_API int rz_socket_read(RzSocket *s, unsigned char *buf, int len) {
	return -1;
}
RZ_API int rz_socket_read_block(RzSocket *s, unsigned char *buf, int len) {
	return -1;
}
RZ_API int rz_socket_gets(RzSocket *s, char *buf, int size) {
	return -1;
}
RZ_API RzSocket *rz_socket_new_from_fd(int fd) {
	return NULL;
}
RZ_API ut8 *rz_socket_slurp(RzSocket *s, int *len) {
	return NULL;
}
#else

#if 0
winsock api notes
=================
close: closes the socket without flushing the data
WSACleanup: closes all network connections
#endif
#define BUFFER_SIZE 4096

RZ_API bool rz_socket_is_connected(RzSocket *s) {
#if __WINDOWS__
	char buf[2];
	rz_socket_block_time(s, false, 0, 0);
#ifdef _MSC_VER
	int ret = recv(s->fd, (char *)&buf, 1, MSG_PEEK);
#else
	ssize_t ret = recv(s->fd, (char *)&buf, 1, MSG_PEEK);
#endif
	rz_socket_block_time(s, true, 0, 0);
	return ret == 1;
#else
	int error = 0;
	socklen_t len = sizeof(error);
	int ret = getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret != 0) {
		perror("getsockopt");
		return false;
	}
	return (error == 0);
#endif
}

#if __UNIX__
static bool __connect_unix(RzSocket *s, const char *file) {
	struct sockaddr_un addr;
	int sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		free(s);
		return false;
	}
	// TODO: set socket options
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, file, sizeof(addr.sun_path) - 1);

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(sock);
		free(s);
		return false;
	}
	s->fd = sock;
	s->is_ssl = false;
	return true;
}

static bool __listen_unix(RzSocket *s, const char *file) {
	struct sockaddr_un unix_name;
	int sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		return false;
	}
	// TODO: set socket options
	unix_name.sun_family = AF_UNIX;
	strncpy(unix_name.sun_path, file, sizeof(unix_name.sun_path) - 1);

	/* just to make sure there is no other socket file */
	unlink(unix_name.sun_path);

	if (bind(sock, (struct sockaddr *)&unix_name, sizeof(unix_name)) < 0) {
		close(sock);
		return false;
	}
	rz_sys_signal(SIGPIPE, SIG_IGN);

	/* change permissions */
	if (chmod(unix_name.sun_path, 0777) != 0) {
		close(sock);
		return false;
	}
	if (listen(sock, 1)) {
		close(sock);
		return false;
	}
	s->fd = sock;
	return true;
}
#endif

RZ_API RzSocket *rz_socket_new(bool is_ssl) {
	RzSocket *s = RZ_NEW0(RzSocket);
	if (!s) {
		return NULL;
	}
	s->is_ssl = is_ssl;
	s->port = 0;
#if __UNIX_
	rz_sys_signal(SIGPIPE, SIG_IGN);
#endif
	s->local = 0;
	s->fd = RZ_INVALID_SOCKET;
#if HAVE_LIB_SSL
	if (is_ssl) {
		s->sfd = NULL;
		s->ctx = NULL;
		s->bio = NULL;
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
		if (!SSL_library_init()) {
			rz_socket_free(s);
			return NULL;
		}
		SSL_load_error_strings();
#endif
	}
#endif
	return s;
}

RZ_API bool rz_socket_spawn(RzSocket *s, const char *cmd, unsigned int timeout) {
	// XXX TODO: dont use sockets, we can achieve the same with pipes
	const int port = 2000 + rz_num_rand(2000);
	int childPid = rz_sys_fork();
	if (childPid == 0) {
		char *a = rz_str_replace(strdup(cmd), "\\", "\\\\", true);
		int res = rz_sys_cmdf("rz-run system=\"%s\" listen=%d", a, port);
		free(a);
#if 0
		// TODO: use the api
		char *profile = rz_str_newf (
				"system=%s\n"
				"listen=%d\n", cmd, port);
		RzRunProfile *rp = rz_run_new (profile);
		rz_run_start (rp);
		rz_run_free (rp);
		free (profile);
#endif
		if (res != 0) {
			eprintf("rz_socket_spawn: rz-run failed\n");
			exit(1);
		}
		eprintf("rz_socket_spawn: %s is dead\n", cmd);
		exit(0);
	}
	rz_sys_sleep(1);
	rz_sys_usleep(timeout);

	char aport[32];
	sprintf(aport, "%d", port);
	// redirect stdin/stdout/stderr
	bool sock = rz_socket_connect(s, "127.0.0.1", aport, RZ_SOCKET_PROTO_TCP, 2000);
	if (!sock) {
		return false;
	}
#if __UNIX__
	rz_sys_sleep(4);
	rz_sys_usleep(timeout);

	int status = 0;
	int ret = waitpid(childPid, &status, WNOHANG);
	if (ret != 0) {
		rz_socket_close(s);
		return false;
	}
#endif
	return true;
}

RZ_API bool rz_socket_connect(RzSocket *s, const char *host, const char *port, int proto, unsigned int timeout) {
	rz_return_val_if_fail(s, false);
#if __WINDOWS__
#define gai_strerror gai_strerrorA
	WSADATA wsadata;

	if (WSAStartup(MAKEWORD(1, 1), &wsadata) == SOCKET_ERROR) {
		eprintf("Error creating socket.");
		return false;
	}
#endif
	int ret;
	struct addrinfo hints = { 0 };
	struct addrinfo *res, *rp;
	if (proto == RZ_SOCKET_PROTO_NONE) {
		proto = RZ_SOCKET_PROTO_DEFAULT;
	}
#if __UNIX__
	rz_sys_signal(SIGPIPE, SIG_IGN);
#endif
	if (proto == RZ_SOCKET_PROTO_UNIX) {
#if __UNIX__
		if (!__connect_unix(s, host)) {
			return false;
		}
#endif
	} else {
		hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
		hints.ai_protocol = proto;
		int gai = getaddrinfo(host, port, &hints, &res);
		if (gai != 0) {
			eprintf("rz_socket_connect: Error in getaddrinfo: %s (%s:%s)\n",
				gai_strerror(gai), host, port);
			return false;
		}
		for (rp = res; rp != NULL; rp = rp->ai_next) {
			int flag = 1;

			s->fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (s->fd == -1) {
				perror("socket");
				continue;
			}

			switch (proto) {
			case RZ_SOCKET_PROTO_TCP:
				ret = setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
				if (ret < 0) {
					perror("setsockopt");
					close(s->fd);
					s->fd = -1;
					continue;
				}
				rz_socket_block_time(s, true, 1, 0);
				ret = connect(s->fd, rp->ai_addr, rp->ai_addrlen);
				break;
			case RZ_SOCKET_PROTO_UDP:
				memset(&s->sa, 0, sizeof(s->sa));
				s->sa.sin_family = AF_INET;
				s->sa.sin_addr.s_addr = htonl(s->local ? INADDR_LOOPBACK : INADDR_ANY);
				s->port = rz_socket_port_by_name(port);
				if (s->port < 1) {
					continue;
				}
				s->sa.sin_port = htons(s->port);
				if (bind(s->fd, (struct sockaddr *)&s->sa, sizeof(s->sa)) < 0) {
					rz_sys_perror("bind");
#ifdef __WINDOWS__
					closesocket(s->fd);
#else
					close(s->fd);
#endif
					continue;
				}
				ret = connect(s->fd, rp->ai_addr, rp->ai_addrlen);
				break;
			default:
				rz_socket_block_time(s, true, 1, 0);
				ret = connect(s->fd, rp->ai_addr, rp->ai_addrlen);
				break;
			}

			if (ret == 0) {
				freeaddrinfo(res);
				return true;
			}
			if (errno == EINPROGRESS) {
				struct timeval tv = { timeout, 0 };
				fd_set wfds;
				FD_ZERO(&wfds);
				FD_SET(s->fd, &wfds);

				if (select(s->fd + 1, NULL, &wfds, NULL, &tv) != -1) {
					if (rz_socket_is_connected(s)) {
						freeaddrinfo(res);
						goto success;
					}
				} else {
					perror("connect");
				}
			}
			rz_socket_close(s);
		}
		freeaddrinfo(res);
		if (!rp) {
			eprintf("Could not resolve address '%s' or failed to connect\n", host);
			return false;
		}
	}
success:
#if HAVE_LIB_SSL
	if (s->is_ssl) {
		s->ctx = SSL_CTX_new(SSLv23_client_method());
		if (!s->ctx) {
			rz_socket_close(s);
			return false;
		}
		s->sfd = SSL_new(s->ctx);
		SSL_set_fd(s->sfd, s->fd);
		int ret = SSL_connect(s->sfd);
		if (ret != 1) {
			int error = SSL_get_error(s->sfd, ret);
			int tries = 10;
			while (tries && ret && (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)) {
				struct timeval tv = { 1, 0 };
				fd_set rfds, wfds;
				FD_ZERO(&rfds);
				FD_ZERO(&wfds);
				if (error == SSL_ERROR_WANT_READ) {
					FD_SET(s->fd, &rfds);
				} else {
					FD_SET(s->fd, &wfds);
				}
				if ((ret = select(s->fd + 1, &rfds, &wfds, NULL, &tv)) < 1) {
					rz_socket_close(s);
					return false;
				}
				ret = SSL_connect(s->sfd);
				if (ret == 1) {
					return true;
				}
				error = SSL_get_error(s->sfd, ret);
				tries--;
			}
			rz_socket_close(s);
			return false;
		}
	}
#endif
	return true;
}

/* close the file descriptor associated with the RzSocket s */
RZ_API int rz_socket_close_fd(RzSocket *s) {
#ifdef _MSC_VER
	return s->fd != INVALID_SOCKET ? closesocket(s->fd) : false;
#else
	return s->fd != -1 ? close(s->fd) : false;
#endif
}

/* shutdown the socket and close the file descriptor */
RZ_API int rz_socket_close(RzSocket *s) {
	int ret = false;
	if (!s) {
		return false;
	}
	if (s->fd != RZ_INVALID_SOCKET) {
#if __UNIX__
		shutdown(s->fd, SHUT_RDWR);
#endif
#if __WINDOWS__
		// https://msdn.microsoft.com/en-us/library/windows/desktop/ms740481(v=vs.85).aspx
		shutdown(s->fd, SD_SEND);
		if (rz_socket_ready(s, 0, 250)) {
			do {
				char buf = 0;
				ret = recv(s->fd, &buf, 1, 0);
			} while (ret != 0 && ret != SOCKET_ERROR);
		}
		ret = closesocket(s->fd);
#else
		ret = close(s->fd);
#endif
		s->fd = RZ_INVALID_SOCKET;
	}
#if HAVE_LIB_SSL
	if (s->is_ssl && s->sfd) {
		SSL_free(s->sfd);
		s->sfd = NULL;
	}
#endif
	return ret;
}

/* shutdown the socket, close the file descriptor and free the RzSocket */
RZ_API int rz_socket_free(RzSocket *s) {
	int res = rz_socket_close(s);
#if HAVE_LIB_SSL
	if (s && s->is_ssl) {
		if (s->sfd) {
			SSL_free(s->sfd);
		}
		if (s->ctx) {
			SSL_CTX_free(s->ctx);
		}
	}
#endif
	free(s);
	return res;
}

RZ_API int rz_socket_port_by_name(const char *name) {
	struct servent *p = getservbyname(name, "tcp");
	return (p && p->s_port) ? ntohs(p->s_port) : rz_num_get(NULL, name);
}

RZ_API bool rz_socket_listen(RzSocket *s, const char *port, const char *certfile) {
	int optval = 1;
	int ret;
	struct linger linger = { 0 };

	if (s->proto == RZ_SOCKET_PROTO_UNIX) {
#if __UNIX__
		return __listen_unix(s, port);
#endif
		return false;
	}

#if __WINDOWS__
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(1, 1), &wsadata) == SOCKET_ERROR) {
		eprintf("Error creating socket.");
		return false;
	}
#endif
	if (s->proto == RZ_SOCKET_PROTO_NONE) {
		s->proto = RZ_SOCKET_PROTO_DEFAULT;
	}
	switch (s->proto) {
	case RZ_SOCKET_PROTO_TCP:
		if ((s->fd = socket(AF_INET, SOCK_STREAM, RZ_SOCKET_PROTO_TCP)) == RZ_INVALID_SOCKET) {
			return false;
		}
		break;
	case RZ_SOCKET_PROTO_UDP:
		if ((s->fd = socket(AF_INET, SOCK_DGRAM, RZ_SOCKET_PROTO_UDP)) == RZ_INVALID_SOCKET) {
			return false;
		}
		break;
	default:
		eprintf("Invalid protocol for socket\n");
		return false;
	}

	linger.l_onoff = 1;
	linger.l_linger = 1;
	ret = setsockopt(s->fd, SOL_SOCKET, SO_LINGER, (void *)&linger, sizeof(linger));
	if (ret < 0) {
		return false;
	}
	{ // fix close after write bug //
		int x = 1500; // FORCE MTU
		ret = setsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, (void *)&x, sizeof(int));
		if (ret < 0) {
			return false;
		}
	}
	ret = setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof optval);
	if (ret < 0) {
		return false;
	}

	memset(&s->sa, 0, sizeof(s->sa));
	s->sa.sin_family = AF_INET;
	s->sa.sin_addr.s_addr = htonl(s->local ? INADDR_LOOPBACK : INADDR_ANY);
	s->port = rz_socket_port_by_name(port);
	if (s->port < 1) {
		return false;
	}
	s->sa.sin_port = htons(s->port); // TODO honor etc/services
	if (bind(s->fd, (struct sockaddr *)&s->sa, sizeof(s->sa)) < 0) {
		rz_sys_perror("bind");
#ifdef _MSC_VER
		closesocket(s->fd);
#else
		close(s->fd);
#endif
		return false;
	}
#if __UNIX__
	rz_sys_signal(SIGPIPE, SIG_IGN);
#endif
	if (s->proto == RZ_SOCKET_PROTO_TCP) {
		if (listen(s->fd, 32) < 0) {
			rz_sys_perror("listen");
#ifdef _MSC_VER
			closesocket(s->fd);
#else
			close(s->fd);
#endif
			return false;
		}
	}
#if HAVE_LIB_SSL
	if (s->is_ssl) {
		s->ctx = SSL_CTX_new(SSLv23_method());
		if (!s->ctx) {
			rz_socket_free(s);
			return false;
		}
		if (!SSL_CTX_use_certificate_chain_file(s->ctx, certfile)) {
			rz_socket_free(s);
			return false;
		}
		if (!SSL_CTX_use_PrivateKey_file(s->ctx, certfile, SSL_FILETYPE_PEM)) {
			rz_socket_free(s);
			return false;
		}
		SSL_CTX_set_verify_depth(s->ctx, 1);
	}
#endif
	return true;
}

RZ_API RzSocket *rz_socket_accept(RzSocket *s) {
	RzSocket *sock;
	socklen_t salen = sizeof(s->sa);
	if (!s) {
		return NULL;
	}
	sock = RZ_NEW0(RzSocket);
	if (!sock) {
		return NULL;
	}
	//signal (SIGPIPE, SIG_DFL);
	sock->fd = accept(s->fd, (struct sockaddr *)&s->sa, &salen);
	if (sock->fd == RZ_INVALID_SOCKET) {
		if (errno != EWOULDBLOCK) {
			// not just a timeout
			rz_sys_perror("accept");
		}
		free(sock);
		return NULL;
	}
#if HAVE_LIB_SSL
	sock->is_ssl = s->is_ssl;
	if (sock->is_ssl) {
		sock->sfd = NULL;
		sock->ctx = NULL;
		sock->bio = NULL;
		BIO *sbio = BIO_new_socket(sock->fd, BIO_NOCLOSE);
		sock->sfd = SSL_new(s->ctx);
		SSL_set_bio(sock->sfd, sbio, sbio);
		if (SSL_accept(sock->sfd) <= 0) {
			rz_socket_free(sock);
			return NULL;
		}
		sock->bio = BIO_new(BIO_f_buffer());
		sbio = BIO_new(BIO_f_ssl());
		BIO_set_ssl(sbio, sock->sfd, BIO_CLOSE);
		BIO_push(sock->bio, sbio);
	}
#else
	sock->is_ssl = 0;
#endif
	return sock;
}

RZ_API RzSocket *rz_socket_accept_timeout(RzSocket *s, unsigned int timeout) {
	fd_set read_fds;
	fd_set except_fds;

	FD_ZERO(&read_fds);
	FD_SET(s->fd, &read_fds);

	FD_ZERO(&except_fds);
	FD_SET(s->fd, &except_fds);

	struct timeval t = { timeout, 0 };

	int r = select(s->fd + 1, &read_fds, NULL, &except_fds, &t);
	if (r < 0) {
		perror("select");
	} else if (r > 0 && FD_ISSET(s->fd, &read_fds)) {
		return rz_socket_accept(s);
	}

	return NULL;
}

// Only applies to read in UNIX
RZ_API bool rz_socket_block_time(RzSocket *s, bool block, int sec, int usec) {
#if __UNIX__
	int ret, flags;
#endif
	if (!s) {
		return false;
	}
#if __UNIX__
	flags = fcntl(s->fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	ret = fcntl(s->fd, F_SETFL, block ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK));
	if (ret < 0) {
		return false;
	}
#elif __WINDOWS__
	ioctlsocket(s->fd, FIONBIO, (u_long FAR *)&block);
#endif
	if (sec > 0 || usec > 0) {
		struct timeval tv = { sec, usec };
		if (setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0) {
			return false;
		}
	}
	return true;
}

RZ_API int rz_socket_flush(RzSocket *s) {
#if HAVE_LIB_SSL
	if (s->is_ssl && s->bio) {
		return BIO_flush(s->bio);
	}
#endif
	return true;
}

/* waits secs until new data is received.	  */
/* returns -1 on error, 0 is false, 1 is true */
RZ_API int rz_socket_ready(RzSocket *s, int secs, int usecs) {
	fd_set rfds;
	struct timeval tv = { secs, usecs };
	if (s->fd == RZ_INVALID_SOCKET) {
		return -1;
	}
	FD_ZERO(&rfds);
	FD_SET(s->fd, &rfds);
	return select(s->fd + 1, &rfds, NULL, NULL, &tv);
}

RZ_API char *rz_socket_to_string(RzSocket *s) {
#if __WINDOWS__
	return rz_str_newf("fd%d", (int)(size_t)s->fd);
#elif __UNIX__
	char *str = NULL;
	struct sockaddr sa;
	socklen_t sl = sizeof(sa);
	memset(&sa, 0, sizeof(sa));
	if (!getpeername(s->fd, &sa, &sl)) {
		struct sockaddr_in *sain = (struct sockaddr_in *)&sa;
		ut8 *a = (ut8 *)&(sain->sin_addr);
		if ((str = malloc(32))) {
			sprintf(str, "%d.%d.%d.%d:%d",
				a[0], a[1], a[2], a[3], ntohs(sain->sin_port));
		}
	} else {
		eprintf("getperrname: failed\n"); //rz_sys_perror ("getpeername");
	}
	return str;
#else
	return NULL;
#endif
}

/* Read/Write functions */
RZ_API int rz_socket_write(RzSocket *s, void *buf, int len) {
	D {
		eprintf("WRITE ");
		int i;
		ut8 *b = buf;
		for (i = 0; i < len; i++) {
			eprintf("%02x ", b[i]);
		}
		eprintf("\n");
	}
	int ret, delta = 0;
#if __UNIX__
	rz_sys_signal(SIGPIPE, SIG_IGN);
#endif
	for (;;) {
		int b = 1500; //65536; // Use MTU 1500?
		if (b > len) {
			b = len;
		}
#if HAVE_LIB_SSL
		if (s->is_ssl) {
			if (s->bio) {
				ret = BIO_write(s->bio, buf + delta, b);
			} else {
				ret = SSL_write(s->sfd, buf + delta, b);
			}
		} else
#endif
		{
			ret = send(s->fd, (char *)buf + delta, b, 0);
		}
		//if (ret == 0) return -1;
		if (ret < 1) {
			break;
		}
		if (ret == len) {
			return len;
		}
		delta += ret;
		len -= ret;
	}
	return (ret == -1) ? -1 : delta;
}

RZ_API int rz_socket_puts(RzSocket *s, char *buf) {
	return rz_socket_write(s, buf, strlen(buf));
}

RZ_API void rz_socket_printf(RzSocket *s, const char *fmt, ...) {
	char buf[BUFFER_SIZE];
	va_list ap;
	if (s->fd != RZ_INVALID_SOCKET) {
		va_start(ap, fmt);
		vsnprintf(buf, BUFFER_SIZE, fmt, ap);
		(void)rz_socket_write(s, buf, strlen(buf));
		va_end(ap);
	}
}

RZ_API int rz_socket_read(RzSocket *s, unsigned char *buf, int len) {
	if (!s) {
		return -1;
	}
#if HAVE_LIB_SSL
	if (s->is_ssl) {
		if (s->bio) {
			return BIO_read(s->bio, buf, len);
		}
		return SSL_read(s->sfd, buf, len);
	}
#endif
	// int r = read (s->fd, buf, len);
	int r = recv(s->fd, (char *)buf, len, 0);
	D {
		eprintf("READ ");
		int i;
		for (i = 0; i < len; i++) {
			eprintf("%02x ", buf[i]);
		}
		eprintf("\n");
	}
	return r;
}

RZ_API int rz_socket_read_block(RzSocket *s, ut8 *buf, int len) {
	int ret = 0;
	for (ret = 0; ret < len;) {
		int r = rz_socket_read(s, buf + ret, len - ret);
		if (r == -1) {
#if HAVE_LIB_SSL
			if (s->is_ssl && SSL_get_error(s->sfd, r) == SSL_ERROR_WANT_READ) {
				if (rz_socket_ready(s, 1, 0) == 1) {
					continue;
				}
			}
#endif
			return -1;
		}
		if (r < 1) {
			break;
		}
		ret += r;
	}
	return ret;
}

RZ_API int rz_socket_gets(RzSocket *s, char *buf, int size) {
	int i = 0;
	int ret = 0;

	if (s->fd == RZ_INVALID_SOCKET) {
		return -1;
	}
	while (i < size) {
		ret = rz_socket_read(s, (ut8 *)buf + i, 1);
		if (ret == 0) {
			if (i > 0) {
				return i;
			}
			return -1;
		}
		if (ret < 0) {
			rz_socket_close(s);
			return i == 0 ? -1 : i;
		}
		if (buf[i] == '\r' || buf[i] == '\n') {
			buf[i] = 0;
			break;
		}
		i += ret;
	}
	buf[i] = '\0';
	return i;
}

RZ_API RzSocket *rz_socket_new_from_fd(int fd) {
	RzSocket *s = RZ_NEW0(RzSocket);
	if (s) {
		s->fd = fd;
		s->proto = RZ_SOCKET_PROTO_DEFAULT;
	}
	return s;
}

RZ_API ut8 *rz_socket_slurp(RzSocket *s, int *len) {
	int blockSize = 4096;
	ut8 *ptr, *buf = malloc(blockSize);
	if (!buf) {
		return NULL;
	}
	int copied = 0;
	if (len) {
		*len = 0;
	}
	for (;;) {
		int rc = rz_socket_read(s, buf + copied, blockSize);
		if (rc > 0) {
			copied += rc;
		}
		ptr = realloc(buf, copied + blockSize);
		if (!ptr) {
			break;
		}
		buf = ptr;
		if (rc < 1) {
			break;
		}
	}
	if (copied == 0) {
		RZ_FREE(buf);
	}
	if (len) {
		*len = copied;
	}
	return buf;
}

#endif // EMSCRIPTEN
