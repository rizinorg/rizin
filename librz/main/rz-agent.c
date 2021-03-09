// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "index.h"
#include <rz_main.h>
#include <rz_core.h>

#if __APPLE__ && (__arm__ || __arm64__ || __aarch64__)
#define USE_IOS_JETSAM 1

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
extern int memorystatus_control(uint32_t command, pid_t pid, uint32_t flags, void *buffer, size_t buffersize);

#else
#define USE_IOS_JETSAM 0
#endif

static int usage(int v) {
	printf("Usage: rz-agent [-adhs] [-p port]\n"
	       "  -a        listen for everyone (localhost by default)\n"
	       "  -d        run in daemon mode (background)\n"
	       "  -h        show this help message\n"
	       "  -u        enable http Authorization access\n"
	       "  -t        user:password authentication file\n"
	       "  -p [port] specify listening port (defaults to 8080)\n");
	return !v;
}

static int showversion(void) {
	return rz_main_version_print("rz_agent");
}

RZ_API int rz_main_rz_agent(int argc, const char **argv) {
	RzSocket *s;
	RzSocketHTTPOptions so;
	RzSocketHTTPRequest *rs;
	int c;
	int dodaemon = 0;
	bool listenlocal = true;
	const char *port = "8080";
	const char *httpauthfile = NULL;
	char *pfile = NULL;
	memset(&so, 0, sizeof(so));

	RzGetopt opt;
	rz_getopt_init(&opt, argc, argv, "adhup:t:sv");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'a':
			listenlocal = false;
			break;
		case 'd':
			dodaemon = 1;
			break;
		case 'h':
			return usage(1);
		case 'v':
			return showversion();
		case 'u':
			so.httpauth = true;
			break;
		case 't':
			httpauthfile = opt.arg;
			break;
		case 'p':
			port = opt.arg;
			break;
		default:
			return usage(0);
		}
	}
	if (opt.ind != argc) {
		return usage(0);
	}

	so.accept_timeout = 0;
	so.timeout = 3;

	if (so.httpauth) {
		if (!httpauthfile) {
			eprintf("No authentication user list set\n");
			return usage(0);
		}

		size_t sz;
		pfile = rz_file_slurp(httpauthfile, &sz);
		if (pfile) {
			so.authtokens = rz_str_split_list(pfile, "\n", 0);
		} else {
			eprintf("Empty list of HTTP users\\n");
			return usage(0);
		}
	}
#if USE_IOS_JETSAM
	memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid(), 256, NULL, 0);
#endif
	if (dodaemon) {
#if LIBC_HAVE_FORK
		int pid = rz_sys_fork();
		if (pid > 0) {
			printf("%d\n", pid);
			return 0;
		}
#endif
	}
	s = rz_socket_new(false);
	s->local = listenlocal;
	if (!rz_socket_listen(s, port, NULL)) {
		eprintf("Cannot listen on %d\n", s->port);
		rz_socket_free(s);
		return 1;
	}

	eprintf("http://localhost:%d/\n", s->port);

	(void)rz_cons_new();

	while (!rz_cons_singleton()->context->breaked) {
		char *result_heap = NULL;
		const char *result = page_index;

		rs = rz_socket_http_accept(s, &so);
		if (!rs) {
			continue;
		}
		if (!rs->auth) {
			rz_socket_http_response(rs, 401, "", 0, NULL);
		}
		if (!strcmp(rs->method, "GET")) {
			if (!strncmp(rs->path, "/proc/kill/", 11)) {
				// TODO: show page here?
				int pid = atoi(rs->path + 11);
				if (pid > 0) {
#if __WINDOWS__
					rz_sys_kill(pid, 0);
#else
					rz_sys_kill(pid, SIGKILL);
#endif
				}
			} else if (!strncmp(rs->path, "/file/open/", 11)) {
				int pid;
				int session_port = 3000 + rz_num_rand(1024);
				char *filename = rs->path + 11;
				char *escaped_filename = rz_str_escape(filename);
				size_t escaped_len = strlen(escaped_filename);
				size_t cmd_len = escaped_len + 40;
				char *cmd;

				if (!(cmd = malloc(cmd_len))) {
					perror("malloc");
					return 1;
				}
				snprintf(cmd, cmd_len, "rizin -q %s-e http.port=%d -c=h \"%s\"",
					listenlocal ? "" : "-e http.bind=public ",
					session_port, escaped_filename);

				// TODO: use rz_sys api to get pid when running in bg
				pid = rz_sys_cmdbg(cmd);
				free(cmd);
				free(escaped_filename);
				result = result_heap = malloc(1024 + escaped_len);
				if (!result) {
					perror("malloc");
					free(pfile);
					rz_list_free(so.authtokens);
					return 1;
				}
				sprintf(result_heap,
					"<html><body>"
					"<a href='/'>back</a><hr size=1/>"
					" - <a target='_blank' href='http://localhost:%d/'>open</a><br />"
					" - <a href='/proc/kill/%d'>kill</a><br />"
					"</body></html>",
					session_port, pid);
				eprintf("\nchild pid %d\n\n", pid);
			}
		}
		rz_socket_http_response(rs, 200, result, 0, NULL);
		rz_socket_http_close(rs);
		free(result_heap);
		result_heap = NULL;
	}
	rz_cons_free();
	free(pfile);
	rz_list_free(so.authtokens);
	rz_socket_free(s);
	return 0;
}
