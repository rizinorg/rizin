#ifndef RZ_SOCKET_H
#define RZ_SOCKET_H

#include "rz_types.h"
#include "rz_bind.h"
#include "rz_list.h"

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_socket);

#if __UNIX__
#include <netinet/in.h>
#include <sys/un.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#endif

#if HAVE_LIB_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#if __UNIX__
#include <netinet/tcp.h>
#endif

/* For the Mingw-W64 toolchain */
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#ifndef SD_BOTH
#define SD_RECEIVE 0
#define SD_SEND    1
#define SD_BOTH    2
#endif

#if _MSC_VER
#define RZ_INVALID_SOCKET INVALID_SOCKET
#else
#define RZ_INVALID_SOCKET -1
#endif

typedef struct {
	int child;
#if __WINDOWS__
	HANDLE pipe;
#else
	int input[2];
	int output[2];
#endif
	RzCoreBind coreb;
} RzPipe;

typedef struct rz_socket_t {
#ifdef _MSC_VER
	SOCKET fd;
#else
	int fd;
#endif
	bool is_ssl;
	int proto;
	int local; // TODO: merge ssl with local -> flags/options
	int port;
	struct sockaddr_in sa;
#if HAVE_LIB_SSL
	SSL_CTX *ctx;
	SSL *sfd;
	BIO *bio;
#endif
} RzSocket;

typedef struct rz_socket_http_options {
	RzList *authtokens;
	bool accept_timeout;
	int timeout;
	bool httpauth;
} RzSocketHTTPOptions;

#define RZ_SOCKET_PROTO_TCP     IPPROTO_TCP
#define RZ_SOCKET_PROTO_UDP     IPPROTO_UDP
#define RZ_SOCKET_PROTO_UNIX    0x1337
#define RZ_SOCKET_PROTO_NONE    0
#define RZ_SOCKET_PROTO_DEFAULT RZ_SOCKET_PROTO_TCP

#ifdef RZ_API
RZ_API RzSocket *rz_socket_new_from_fd(int fd);
RZ_API RzSocket *rz_socket_new(bool is_ssl);
RZ_API bool rz_socket_spawn(RzSocket *s, const char *cmd, unsigned int timeout);
RZ_API bool rz_socket_connect(RzSocket *s, const char *host, const char *port, int proto, unsigned int timeout);
RZ_API int rz_socket_connect_serial(RzSocket *sock, const char *path, int speed, int parity);
#define rz_socket_connect_tcp(a, b, c, d) rz_socket_connect(a, b, c, RZ_SOCKET_PROTO_TCP, d)
#define rz_socket_connect_udp(a, b, c, d) rz_socket_connect(a, b, c, RZ_SOCKET_PROTO_UDP, d)
#if __UNIX__
#define rz_socket_connect_unix(a, b) rz_socket_connect(a, b, b, RZ_SOCKET_PROTO_UNIX, 0)
#else
#define rz_socket_connect_unix(a, b) (false)
#endif
RZ_API bool rz_socket_listen(RzSocket *s, const char *port, const char *certfile);
RZ_API int rz_socket_port_by_name(const char *name);
RZ_API int rz_socket_close_fd(RzSocket *s);
RZ_API int rz_socket_close(RzSocket *s);
RZ_API int rz_socket_free(RzSocket *s);
RZ_API RzSocket *rz_socket_accept(RzSocket *s);
RZ_API RzSocket *rz_socket_accept_timeout(RzSocket *s, unsigned int timeout);
RZ_API bool rz_socket_block_time(RzSocket *s, bool block, int sec, int usec);
RZ_API int rz_socket_flush(RzSocket *s);
RZ_API int rz_socket_ready(RzSocket *s, int secs, int usecs);
RZ_API char *rz_socket_to_string(RzSocket *s);
RZ_API int rz_socket_write(RzSocket *s, void *buf, int len);
RZ_API int rz_socket_puts(RzSocket *s, char *buf);
RZ_API void rz_socket_printf(RzSocket *s, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API int rz_socket_read(RzSocket *s, ut8 *read, int len);
RZ_API int rz_socket_read_block(RzSocket *s, unsigned char *buf, int len);
RZ_API int rz_socket_gets(RzSocket *s, char *buf, int size);
RZ_API ut8 *rz_socket_slurp(RzSocket *s, int *len);
RZ_API bool rz_socket_is_connected(RzSocket *);

/* process */
typedef struct rz_socket_proc_t {
	int fd0[2];
	int fd1[2];
	int pid;
} RzSocketProc;

RZ_API RzSocketProc *rz_socket_proc_open(char *const argv[]);
RZ_API int rz_socket_proc_close(RzSocketProc *sp);
RZ_API int rz_socket_proc_read(RzSocketProc *sp, unsigned char *buf, int len);
RZ_API int rz_socket_proc_gets(RzSocketProc *sp, char *buf, int size);
RZ_API int rz_socket_proc_write(RzSocketProc *sp, void *buf, int len);
RZ_API void rz_socket_proc_printf(RzSocketProc *sp, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API int rz_socket_proc_ready(RzSocketProc *sp, int secs, int usecs);

/* HTTP */
RZ_API char *rz_socket_http_get(const char *url, int *code, int *rlen);
RZ_API char *rz_socket_http_post(const char *url, const char *data, int *code, int *rlen);
RZ_API void rz_socket_http_server_set_breaked(bool *b);

typedef struct rz_socket_http_request {
	RzSocket *s;
	char *path;
	char *host;
	char *agent;
	char *method;
	char *referer;
	ut8 *data;
	int data_length;
	bool auth;
} RzSocketHTTPRequest;

RZ_API RzSocketHTTPRequest *rz_socket_http_accept(RzSocket *s, RzSocketHTTPOptions *so);
RZ_API void rz_socket_http_response(RzSocketHTTPRequest *rs, int code, const char *out, int x, const char *headers);
RZ_API void rz_socket_http_close(RzSocketHTTPRequest *rs);
RZ_API ut8 *rz_socket_http_handle_upload(const ut8 *str, int len, int *olen);

typedef int (*rap_server_open)(void *user, const char *file, int flg, int mode);
typedef int (*rap_server_seek)(void *user, ut64 offset, int whence);
typedef int (*rap_server_read)(void *user, ut8 *buf, int len);
typedef int (*rap_server_write)(void *user, ut8 *buf, int len);
typedef char *(*rap_server_cmd)(void *user, const char *command);
typedef int (*rap_server_close)(void *user, int fd);

enum {
	RAP_PACKET_OPEN = 1,
	RAP_PACKET_READ = 2,
	RAP_PACKET_WRITE = 3,
	RAP_PACKET_SEEK = 4,
	RAP_PACKET_CLOSE = 5,
	// system was deprecated in slot 6,
	RAP_PACKET_CMD = 7,
	RAP_PACKET_REPLY = 0x80,
	RAP_PACKET_MAX = 4096
};

typedef struct rz_socket_rap_server_t {
	RzSocket *fd;
	char *port;
	ut8 buf[RAP_PACKET_MAX + 32]; // This should be used as a static buffer for everything done by the server
	rap_server_open open;
	rap_server_seek seek;
	rap_server_read read;
	rap_server_write write;
	rap_server_cmd system;
	rap_server_cmd cmd;
	rap_server_close close;
	void *user; // Always first arg for callbacks
} RzSocketRapServer;

RZ_API RzSocketRapServer *rz_socket_rap_server_new(bool is_ssl, const char *port);
RZ_API RzSocketRapServer *rz_socket_rap_server_create(const char *pathname);
RZ_API void rz_socket_rap_server_free(RzSocketRapServer *rap_s);
RZ_API bool rz_socket_rap_server_listen(RzSocketRapServer *rap_s, const char *certfile);
RZ_API RzSocket *rz_socket_rap_server_accept(RzSocketRapServer *rap_s);
RZ_API bool rz_socket_rap_server_continue(RzSocketRapServer *rap_s);

/* rap client */
RZ_API int rz_socket_rap_client_open(RzSocket *s, const char *file, int rw);
RZ_API char *rz_socket_rap_client_command(RzSocket *s, const char *cmd, RzCoreBind *c);
RZ_API int rz_socket_rap_client_write(RzSocket *s, const ut8 *buf, int count);
RZ_API int rz_socket_rap_client_read(RzSocket *s, ut8 *buf, int count);
RZ_API int rz_socket_rap_client_seek(RzSocket *s, ut64 offset, int whence);

/* run.c */
#define RZ_RUN_PROFILE_NARGS 512
typedef struct rz_run_profile_t {
	char *_args[RZ_RUN_PROFILE_NARGS];
	int _argc;
	bool _daemon;
	char *_system;
	char *_program;
	char *_runlib;
	char *_runlib_fcn;
	char *_stdio;
	char *_stdin;
	char *_stdout;
	char *_stderr;
	char *_chgdir;
	char *_chroot;
	char *_libpath;
	char *_preload;
	int _bits;
	int _pid;
	char *_pidfile;
	int _rzpreload;
	int _docore;
	int _dofork;
	int _dodebug;
	int _aslr;
	int _maxstack;
	int _maxproc;
	int _maxfd;
	int _rzsleep;
	int _execve;
	char *_setuid;
	char *_seteuid;
	char *_setgid;
	char *_setegid;
	char *_input;
	char *_connect;
	char *_listen;
	int _pty;
	int _timeout;
	int _timeout_sig;
	int _nice;
} RzRunProfile;

RZ_API RzRunProfile *rz_run_new(const char *str);
RZ_API bool rz_run_parse(RzRunProfile *pf, const char *profile);
RZ_API void rz_run_free(RzRunProfile *r);
RZ_API bool rz_run_parseline(RzRunProfile *p, const char *b);
RZ_API const char *rz_run_help(void);
RZ_API int rz_run_config_env(RzRunProfile *p);
RZ_API int rz_run_start(RzRunProfile *p);
RZ_API void rz_run_reset(RzRunProfile *p);
RZ_API bool rz_run_parsefile(RzRunProfile *p, const char *b);
RZ_API char *rz_run_get_environ_profile(char **env);

/* rapipe */
RZ_API RzPipe *rap_open(const char *cmd);
RZ_API RzPipe *rap_open_corebind(RzCoreBind *coreb);
RZ_API int rap_close(RzPipe *rap);

RZ_API char *rap_cmd(RzPipe *rap, const char *str);
RZ_API char *rap_cmdf(RzPipe *rap, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);

RZ_API int rap_write(RzPipe *rap, const char *str);
RZ_API char *rap_read(RzPipe *rap);

RZ_API int rzpipe_write(RzPipe *rzpipe, const char *str);
RZ_API char *rzpipe_read(RzPipe *rzpipe);
RZ_API int rzpipe_close(RzPipe *rzpipe);
RZ_API RzPipe *rzpipe_open_corebind(RzCoreBind *coreb);
RZ_API RzPipe *rzpipe_open(const char *cmd);
RZ_API RzPipe *rzpipe_open_dl(const char *file);
RZ_API char *rzpipe_cmd(RzPipe *rzpipe, const char *str);
RZ_API char *rzpipe_cmdf(RzPipe *rzpipe, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
#endif

#ifdef __cplusplus
}
#endif

#endif
