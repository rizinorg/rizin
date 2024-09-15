// SPDX-FileCopyrightText: 2012-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
// included from rtr.c

typedef int (*rz_core_rtr_http_handler_ptr)(RzCore *, RzSocketHTTPRequest *, char *);
typedef rz_core_rtr_http_handler_ptr (*rz_core_rtr_http_handler)();
static int LOOP_CONTINUE_VALUE = 66;

static int rz_core_rtr_http_cmd(RzCore *core, RzSocketHTTPRequest *rs, char *cmd, char *out, char *headers) {
	if ((!strcmp(cmd, "Rh*") ||
		    !strcmp(cmd, "Rh--"))) {
		out = NULL;
	} else if (*cmd == ':') {
		/* commands in /cmd/: starting with : do not show any output */
		rz_core_cmd0(core, cmd + 1);
		out = NULL;
	} else {
		out = rz_core_cmd_str_pipe(core, cmd);
	}

	if (out) {
		char *res = rz_str_uri_encode(out);
		char *newheaders = rz_str_newf(
			"Content-Type: text/plain\n%s", headers);
		rz_socket_http_response(rs, 200, out, 0, newheaders);
		free(out);
		free(newheaders);
		free(res);
	} else {
		rz_socket_http_response(rs, 200, "", 0, headers);
	}
	return 0;
}

static int rz_core_rtr_http_handler_ok(RzCore *core, RzSocketHTTPRequest *rs, char *headers) {
	rz_socket_http_response(rs, 200, "", 0, headers);
	return 1;
}

static int rz_core_rtr_http_handler_invalid(RzCore *core, RzSocketHTTPRequest *rs, char *headers) {
	rz_socket_http_response(rs, 404, "Invalid protocol", 0, headers);
	return 1;
}

static int rz_core_rtr_http_handler_get_file(RzCore *core, RzSocketHTTPRequest *rs, char *headers) {
	char *dir = NULL;
	if (rz_config_get_i(core->config, "http.dirlist")) {
		if (rz_file_is_directory(rs->path)) {
			dir = rz_str_dup(rs->path);
		}
	}
	if (rz_config_get_i(core->config, "http.upget")) {
		const char *uproot = rz_config_get(core->config, "http.uproot");
		if (!rs->path[3] || (rs->path[3] == '/' && !rs->path[4])) {
			char *ptr = rtr_dir_files(uproot);
			rz_socket_http_response(rs, 200, ptr, 0, headers);
			free(ptr);
		} else {
			char *path = rz_file_root(uproot, rs->path + 4);
			if (rz_file_exists(path)) {
				size_t sz = 0;
				char *f = rz_file_slurp(path, &sz);
				if (f) {
					rz_socket_http_response(rs, 200, f, (int)sz, headers);
					free(f);
				} else {
					rz_socket_http_response(rs, 403, "Permission denied", 0, headers);
					http_logf(core, "http: Cannot open '%s'\n", path);
				}
			} else {
				if (dir) {
					char *resp = rtr_dir_files(dir);
					rz_socket_http_response(rs, 404, resp, 0, headers);
					free(resp);
				} else {
					http_logf(core, "File '%s' not found\n", path);
					rz_socket_http_response(rs, 404, "File not found\n", 0, headers);
				}
			}
			free(path);
			free(dir);
		}
	} else {
		rz_socket_http_response(rs, 403, "", 0, NULL);
	}
	return 1;
}

static int rz_core_rtr_http_handler_get_cmd(RzCore *core, RzSocketHTTPRequest *rs, char *headers) {
	const bool colon = rz_config_get_i(core->config, "http.colon");
	const char *port = rz_config_get(core->config, "http.port");
	if (colon && rs->path[5] != ':') {
		rz_socket_http_response(rs, 403, "Permission denied", 0, headers);
	} else {
		char *cmd = rs->path + 5;
		const char *httpcmd = rz_config_get(core->config, "http.uri");
		const char *httpref = rz_config_get(core->config, "http.referer");
		const bool httpref_enabled = (httpref && *httpref);
		char *refstr = NULL;
		if (httpref_enabled) {
			if (strstr(httpref, "http")) {
				refstr = rz_str_dup(httpref);
			} else {
				refstr = rz_str_newf("http://localhost:%d/", atoi(port));
			}
		}

		while (*cmd == '/') {
			cmd++;
		}
		if (httpref_enabled && (!rs->referer || (refstr && !strstr(rs->referer, refstr)))) {
			rz_socket_http_response(rs, 503, "", 0, headers);
		} else {
			if (httpcmd && *httpcmd) {
				int len; // do remote http query and proxy response
				char *res, *bar = rz_str_newf("%s/%s", httpcmd, cmd);
				void *bed = rz_cons_sleep_begin();
				res = rz_socket_http_get(bar, NULL, &len);
				rz_cons_sleep_end(bed);
				if (res) {
					res[len] = 0;
					rz_cons_println(res);
				}
				free(bar);
			} else {
				char *out = NULL, *cmd = rs->path + 5;
				rz_str_uri_decode(cmd);
				rz_config_set(core->config, "scr.interactive", "false");

				rz_core_rtr_http_cmd(core, rs, cmd, out, headers);

				if (!strcmp(cmd, "Rh*")) {
					rz_socket_http_close(rs);
					free(refstr);
					return -2;
				} else if (!strcmp(cmd, "Rh--")) {
					rz_socket_http_close(rs);
					free(refstr);
					return 0;
				}
			}
		}
		free(refstr);
	}
	return 1;
}

static int rz_core_rtr_http_handler_get_index(RzCore *core, RzSocketHTTPRequest *rs, char *headers) {
	char *dir = NULL;
	const char *index = rz_config_get(core->config, "http.index");
	if (rz_config_get_i(core->config, "http.dirlist")) {
		if (rz_file_is_directory(rs->path)) {
			dir = rz_str_dup(rs->path);
		}
	}
	const char *root = rz_config_get(core->config, "http.root");
	const char *homeroot = rz_config_get(core->config, "http.homeroot");
	char *path = NULL;
	if (!strcmp(rs->path, "/")) {
		free(rs->path);
		if (*index == '/') {
			rs->path = rz_str_dup(index);
			path = rz_str_dup(index);
		} else {
			rs->path = rz_str_newf("/%s", index);
			path = rz_file_root(root, rs->path);
		}
	} else if (homeroot && *homeroot) {
		char *homepath = rz_file_abspath(homeroot);
		path = rz_file_root(homepath, rs->path);
		free(homepath);
		if (!rz_file_exists(path) && !rz_file_is_directory(path)) {
			free(path);
			path = rz_file_root(root, rs->path);
		}
	} else {
		if (*index == '/') {
			path = rz_str_dup(index);
		} else {
		}
	}
	// FD IS OK HERE
	if (rs->path[strlen(rs->path) - 1] == '/') {
		path = (*index == '/') ? rz_str_dup(index) : rz_str_append(path, index);
	} else {
		if (rz_file_is_directory(path)) {
			char *res = rz_str_newf("Location: %s/\n%s", rs->path, headers);
			rz_socket_http_response(rs, 302, NULL, 0, res);
			rz_socket_http_close(rs);
			free(path);
			free(res);
			RZ_FREE(dir);
			return LOOP_CONTINUE_VALUE;
		}
	}
	if (rz_file_exists(path)) {
		size_t sz = 0;
		char *f = rz_file_slurp(path, &sz);
		if (f) {
			const char *ct = NULL;
			if (strstr(path, ".js")) {
				ct = "Content-Type: application/javascript\n";
			}
			if (strstr(path, ".css")) {
				ct = "Content-Type: text/css\n";
			}
			if (strstr(path, ".html")) {
				ct = "Content-Type: text/html\n";
			}
			char *hdr = rz_str_newf("%s%s", ct, headers);
			rz_socket_http_response(rs, 200, f, (int)sz, hdr);
			free(hdr);
			free(f);
		} else {
			rz_socket_http_response(rs, 403, "Permission denied", 0, headers);
			http_logf(core, "http: Cannot open '%s'\n", path);
		}
	} else {
		if (dir) {
			char *resp = rtr_dir_files(dir);
			http_logf(core, "Dirlisting %s\n", dir);
			rz_socket_http_response(rs, 404, resp, 0, headers);
			free(resp);
		} else {
			http_logf(core, "File '%s' not found\n", path);
			rz_socket_http_response(rs, 404, "File not found\n", 0, headers);
		}
	}
	free(path);
	return 1;
}

static int rz_core_rtr_http_handler_post_upload(RzCore *core, RzSocketHTTPRequest *rs, char *headers) {
	ut8 *ret;
	int retlen;
	char buf[128];
	if (rz_config_get_i(core->config, "http.upload")) {
		ret = rz_socket_http_handle_upload(rs->data, rs->data_length, &retlen);
		if (ret) {
			ut64 size = rz_config_get_i(core->config, "http.maxsize");
			if (size && retlen > size) {
				rz_socket_http_response(rs, 403, "403 File too big\n", 0, headers);
			} else {
				char *filename = rz_file_root(
					rz_config_get(core->config, "http.uproot"),
					rs->path + 8);
				http_logf(core, "UPLOADED '%s'\n", filename);
				rz_file_dump(filename, ret, retlen, 0);
				free(filename);
				snprintf(buf, sizeof(buf),
					"<html><body><h2>uploaded %d byte(s). Thanks</h2>\n", retlen);
				rz_socket_http_response(rs, 200, buf, 0, headers);
			}
			free(ret);
		}

	} else {
		rz_socket_http_response(rs, 403, "403 Forbidden\n", 0, headers);
	}
	return 1;
}

static int rz_core_rtr_http_handler_post_cmd(RzCore *core, RzSocketHTTPRequest *rs, char *headers) {
	char *out = NULL;
	rz_config_set(core->config, "scr.interactive", "false");
	rz_core_rtr_http_cmd(core, rs, (char *)rs->data, out, headers);
	if (!strcmp((char *)rs->data, "Rh*")) {
		rz_socket_http_close(rs);
		return -2;
	} else if (!strcmp((char *)rs->data, "Rh--")) {
		rz_socket_http_close(rs);
		return 0;
	}
	return 1;
}

static rz_core_rtr_http_handler_ptr rz_core_rtr_http_router(RzSocketHTTPRequest *rs) {
	if (!strcmp(rs->method, "OPTIONS")) {
		return &rz_core_rtr_http_handler_ok;
	} else if (!strcmp(rs->method, "GET")) {
		if (!strncmp(rs->path, "/up/", strlen("/up/"))) {
			return rz_core_rtr_http_handler_get_file;
		} else if (!strncmp(rs->path, "/cmd/", strlen("/cmd/"))) {
			return rz_core_rtr_http_handler_get_cmd;
		} else {
			return rz_core_rtr_http_handler_get_index;
		}
	} else if (!strcmp(rs->method, "POST")) {
		if (!strncmp(rs->path, "/upload/", strlen("/upload/"))) {
			return rz_core_rtr_http_handler_post_upload;
		} else if (!strncmp(rs->path, "/cmd/", strlen("/cmd/"))) {
			return rz_core_rtr_http_handler_post_cmd;
		}
	}

	return rz_core_rtr_http_handler_invalid;
}

static bool is_localhost(const char *address) {
	if (RZ_STR_ISEMPTY(address)) {
		return false;
	}
	return !strcmp(address, "::1") ||
		!strcmp(address, "localhost") ||
		!strcmp(address, "127.0.0.1") ||
		!strcmp(address, "local");
}

static int rtr_http_stop(RzCore *u) {
	RzCore *core = (RzCore *)u;
	const int timeout = 1; // 1 second
	const char *port;
	RzSocket *sock;

#if __WINDOWS__
	rz_socket_http_server_set_breaked(&rz_cons_singleton()->context->breaked);
#endif
	if (((size_t)u) > 0xff) {
		port = rz_config_get(core->config, "http.port");
		sock = rz_socket_new(0);
		(void)rz_socket_connect(sock, "localhost", port, RZ_SOCKET_PROTO_TCP, timeout);
		rz_socket_free(sock);
	}
	rz_socket_free(s);
	s = NULL;
	return 0;
}

// return 1 on error
static int rz_core_rtr_http_run(RzCore *core, int launch, int browse, const char *path) {
	char headers[128] = RZ_EMPTY;
	RzSocketHTTPRequest *rs;
	char buf[32];
	int ret = 0;
	RzSocket *s;
	RzSocketHTTPOptions so;
	char *dir;
	int iport;
	const char *bind = rz_config_get(core->config, "http.bind");
	const char *root = rz_config_get(core->config, "http.root");
	const char *homeroot = rz_config_get(core->config, "http.homeroot");
	const char *port = rz_config_get(core->config, "http.port");
	const char *allow = rz_config_get(core->config, "http.allow");
	const char *httpauthfile = rz_config_get(core->config, "http.authfile");
	char *pfile = NULL;

	if (!rz_file_is_directory(root)) {
		if (!rz_file_is_directory(homeroot)) {
			RZ_LOG_ERROR("core: cannot find http.root or http.homeroot\n");
		}
	}
	if (!path) {
		return false;
	}
	char *arg = strchr(path, ' ');
	if (arg) {
		path = arg + 1;
	}
	if (path && atoi(path)) {
		port = path;
		rz_config_set(core->config, "http.port", port);
		path = NULL;
	}

	if (!strcmp(port, "0")) {
		rz_num_irand();
		iport = 1024 + rz_num_rand32(45256);
		snprintf(buf, sizeof(buf), "%d", iport);
		port = buf;
	}
	s = rz_socket_new(false);
	s->local = is_localhost(bind);
	memset(&so, 0, sizeof(so));
	if (!rz_socket_listen(s, port, NULL)) {
		rz_socket_free(s);
		RZ_LOG_ERROR("core: cannot listen on http.port\n");
		return 1;
	}

	if (browse == 'H') {
		const char *browser = rz_config_get(core->config, "http.browser");
		rz_sys_cmdf("%s http://%s:%d/%s &",
			browser, bind, atoi(port), path ? path : "");
	}

	so.httpauth = rz_config_get_i(core->config, "http.auth");

	if (so.httpauth) {
		if (!httpauthfile) {
			rz_socket_free(s);
			RZ_LOG_ERROR("core: user list was not set for HTTP Authentication\n");
			return 1;
		}

		pfile = rz_file_slurp(httpauthfile, NULL);

		if (pfile) {
			so.authtokens = rz_str_split_list(pfile, "\n", 0);
		} else {
			rz_socket_free(s);
			RZ_LOG_ERROR("core: the list of HTTP users is empty\n");
			return 1;
		}

		so.timeout = rz_config_get_i(core->config, "http.timeout");
		so.accept_timeout = 1;
	}

	// store current configs
	RzConfigHold *hc = rz_config_hold_new(core->config);
	if (!hc) {
		return 0;
	}
	rz_config_hold_i(hc, "scr.color", "scr.html", "scr.interactive", "asm.cmt.right", "asm.bytes", NULL);

	// set new configs
	rz_config_set(core->config, "asm.cmt.right", "false");
	rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
	rz_config_set(core->config, "asm.bytes", "false");
	rz_config_set(core->config, "scr.interactive", "false");

	RZ_LOG_WARN("core: Starting http server...\nTo open a remote session, please use `rizin -C http://%s:%s/cmd/`\n", bind, port);
	core->http_up = true;

	ut64 newoff, origoff = core->offset;
	int newblksz, origblksz = core->blocksize;
	ut8 *newblk, *origblk = core->block;

	newblk = malloc(core->blocksize);
	if (!newblk) {
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		rz_socket_free(s);
		rz_list_free(so.authtokens);
		free(pfile);
		return 1;
	}
	memcpy(newblk, core->block, core->blocksize);

	core->block = newblk;
	// TODO: handle mutex lock/unlock here
	rz_cons_break_push((RzConsBreak)rtr_http_stop, core);
	while (!rz_cons_is_breaked()) {

		core->http_up = 0; // DAT IS NOT TRUE AT ALL.. but its the way to enable visual

		newoff = core->offset;
		newblk = core->block;
		newblksz = core->blocksize;

		core->offset = origoff;
		core->block = origblk;
		core->blocksize = origblksz;

		// backup and restore offset and blocksize

		/* this is blocking */
		activateDieTime(core);

		void *bed = rz_cons_sleep_begin();
		rs = rz_socket_http_accept(s, &so);
		rz_cons_sleep_end(bed);

		origoff = core->offset;
		origblk = core->block;
		origblksz = core->blocksize;
		core->offset = newoff;
		core->block = newblk;
		core->blocksize = newblksz;

		core->http_up = 1;

		if (!rs) {
			bed = rz_cons_sleep_begin();
			rz_sys_usleep(100);
			rz_cons_sleep_end(bed);
			continue;
		}
		if (allow && *allow) {
			bool accepted = false;
			const char *allows_host;
			char *p, *peer = rz_socket_to_string(rs->s);
			char *allows = rz_str_dup(allow);
			// eprintf ("Firewall (%s)\n", allows);
			int i, count = rz_str_split(allows, ',');
			p = strchr(peer, ':');
			if (p) {
				*p = 0;
			}
			for (i = 0; i < count; i++) {
				allows_host = rz_str_word_get0(allows, i);
				// eprintf ("--- (%s) (%s)\n", bind, peer);
				if (!strcmp(allows_host, peer)) {
					accepted = true;
					break;
				}
			}
			free(peer);
			free(allows);
			if (!accepted) {
				rz_socket_http_close(rs);
				continue;
			}
		}
		if (!rs->method || !rs->path) {
			http_logf(core, "Invalid http headers received from client\n");
			rz_socket_http_close(rs);
			continue;
		}
		dir = NULL;

		if (!rs->auth) {
			rz_socket_http_response(rs, 401, "", 0, NULL);
		}

		if (rz_config_get_i(core->config, "http.verbose")) {
			char *peer = rz_socket_to_string(rs->s);
			http_logf(core, "[HTTP] %s %s\n", peer, rs->path);
			free(peer);
		}
		if (rz_config_get_i(core->config, "http.dirlist")) {
			if (rz_file_is_directory(rs->path)) {
				dir = rz_str_dup(rs->path);
			}
		}
		if (rz_config_get_i(core->config, "http.cors")) {
			strcpy(headers, "Access-Control-Allow-Origin: *\n"
					"Access-Control-Allow-Headers: Origin, "
					"X-Requested-With, Content-Type, Accept\n");
		}

		int response_result = (*rz_core_rtr_http_router(rs))(core, rs, headers);
		if (response_result == 0 || response_result == -2) {
			ret = response_result;
			goto the_end;
		} else if (response_result == LOOP_CONTINUE_VALUE) {
			continue;
		}

		rz_socket_http_close(rs);
		free(dir);
	}
the_end:
	rz_cons_break_pop();
	core->http_up = false;
	free(pfile);
	rz_socket_free(s);

	// restore saved configs
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	return ret;
}

RZ_API int rz_core_rtr_http(RzCore *core, int launch, int browse, const char *path) {
	int ret = 0;
	if (launch == '-') {
		return 0;
	}
	if (core->http_up) {
		RZ_LOG_ERROR("core: http server is already running\n");
		return 1;
	}
	if (launch == '&') {
		while (*path == '&') {
			path++;
		}
		return rz_core_cmdf(core, "& Rh%s", path);
	}
	do {
		ret = rz_core_rtr_http_run(core, launch, browse, path);
	} while (ret == -2);
	return ret;
}
