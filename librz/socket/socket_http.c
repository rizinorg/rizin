// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_socket.h>
#include <rz_util.h>

#if __WINDOWS__
#include <WinInet.h>
#endif

#define SOCKET_HTTP_MAX_HEADER_LENGTH 0x2000
#define SOCKET_HTTP_MAX_REDIRECTS     5

static size_t socket_slurp(RzSocket *s, RzBuffer *buf) {
	size_t i;
	if (rz_socket_ready(s, 1, 0) != 1) {
		return 0;
	}
	rz_socket_block_time(s, true, 0, 1000);
	for (i = 0; i < SOCKET_HTTP_MAX_HEADER_LENGTH; i += 1) {
		ut8 c;
		int olen = rz_socket_read_block(s, &c, 1);
		if (olen != 1) {
			rz_buf_append_bytes(buf, (ut8 *)"", 1);
			break;
		}
		rz_buf_append_bytes(buf, &c, 1);
	}
	return i;
}

static char *socket_http_get_recursive(const char *url, int *code, int *rlen, ut32 redirections);

static char *socket_http_answer(RzSocket *s, int *code, int *rlen, ut32 redirections) {
	rz_return_val_if_fail(s, NULL);
	const char *p;
	int ret, len = 0, delta = 0;
	char *dn = NULL;
	RzBuffer *b = rz_buf_new();
	if (!b) {
		return NULL;
	}
	char *res = NULL;
	size_t olen = socket_slurp(s, b);
	char *buf = malloc(olen + 1);
	if (!buf) {
		goto exit;
	}
	rz_buf_read_at(b, 0, (ut8 *)buf, olen);
	buf[olen] = 0;
	char *dnn = (char *)rz_str_casestr(buf, "\n\n");
	char *drn = (char *)rz_str_casestr(buf, "\r\n\r\n");
	if (dnn) {
		if (drn && (drn < dnn)) {
			dn = drn;
			delta = 4;
		} else {
			dn = dnn;
			delta = 2;
		}
	} else {
		dn = drn;
		delta = 4;
	}
	if (!dn) {
		goto exit;
	}

	olen -= delta;
	*dn = 0; // chop headers

	/* Follow redirects */
	p = rz_str_casestr(buf, "Location:");
	if (p) {
		if (!redirections) {
			eprintf("Too many redirects\n");
			goto exit;
		}
		p += strlen("Location:");
		char *end_url = strchr(p, '\n');
		if (end_url) {
			int url_len = end_url - p;
			char *url = rz_str_ndup(p, url_len);
			rz_str_trim(url);
			res = socket_http_get_recursive(url, code, rlen, --redirections);
			free(url);
			len = *rlen;
		}
		goto exit;
	}

	/* Parse Len */
	p = rz_str_casestr(buf, "Content-Length: ");
	if (p) {
		len = atoi(p + 16);
	} else {
		len = olen - (dn - buf);
	}
	if (len > 0) {
		if (len > olen) {
			res = malloc(len + 2);
			if (!res) {
				goto exit;
			}
			olen -= dn - buf;
			memcpy(res, dn + delta, olen);
			do {
				ret = rz_socket_read_block(s, (ut8 *)res + olen, len - olen);
				if (ret < 1) {
					break;
				}
				olen += ret;
			} while (olen < len);
			res[len] = 0;
		} else {
			res = malloc(len + 1);
			if (res) {
				memcpy(res, dn + delta, len);
				res[len] = 0;
			}
		}
	} else {
		res = strdup("");
	}
exit:
	free(buf);
	rz_buf_free(b);
	rz_socket_close(s);
	if (rlen) {
		*rlen = len;
	}
	return res;
}

#if __WINDOWS__
static char *http_get_w32(const char *url, int *code, int *rlen) {
	HINTERNET hInternet = InternetOpenA("rizin " RZ_VERSION, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInternet) {
		rz_sys_perror("InternetOpenA");
		return NULL;
	}
	HINTERNET hOpenUrl = InternetOpenUrlA(hInternet, url, NULL, 0, 0, 0);
	if (!hOpenUrl) {
		rz_sys_perror("InternetOpenUrlA");
		InternetCloseHandle(hInternet);
		return NULL;
	}

	char *ret = NULL;
	size_t read_sz = 0x100000;
	DWORD r = 0, w = 0;
	bool res = true;
	do {
		w += r;
		if (!res && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			read_sz *= 2;
		}
		char *tmp = realloc(ret, read_sz + w);
		if (!tmp) {
			RZ_FREE(ret);
			goto exit;
		}
		ret = tmp;
	} while (!(res = InternetReadFile(hOpenUrl, ret + w, read_sz, &r)) || r);

	if (res) {
		char *tmp = realloc(ret, (size_t)w + 1);
		if (tmp) {
			ret = tmp;
			ret[w] = 0;
		} else {
			RZ_FREE(ret);
		}
	} else {
		RZ_FREE(ret);
	}

exit:
	if (rlen) {
		*rlen = w;
	}
	if (code && w) {
		*code = 200;
	}
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hOpenUrl);
	return ret;
}
#endif

static char *socket_http_get_recursive(const char *url, int *code, int *rlen, ut32 redirections) {
	if (code) {
		*code = 0;
	}
	if (rlen) {
		*rlen = 0;
	}
	char *curl_env = rz_sys_getenv("RZ_CURL");
	if (!RZ_STR_ISEMPTY(curl_env) && atoi(curl_env)) {
		int len;
		char *escaped_url = rz_str_escape_sh(url);
		char *command = rz_str_newf("curl -sfL -o - \"%s\"", escaped_url);
		char *res = rz_sys_cmd_str(command, NULL, &len);
		free(escaped_url);
		free(command);
		free(curl_env);
		if (!res) {
			return NULL;
		}
		if (res) {
			if (code) {
				*code = 200;
			}
			if (rlen) {
				*rlen = len;
			}
		}
		return res;
	}
	free(curl_env);
#if __WINDOWS__
	return http_get_w32(url, code, rlen);
#else
	RzSocket *s;
	bool ssl = rz_str_startswith(url, "https://");
#if !HAVE_LIB_SSL
	if (ssl) {
		eprintf("Tried to get '%s', but SSL support is disabled, set RZ_CURL=1 to use curl\n", url);
		return NULL;
	}
#endif
	char *response, *host, *path, *port = "80";
	char *uri = strdup(url);
	if (!uri) {
		return NULL;
	}
	host = strstr(uri, "://");
	if (!host) {
		free(uri);
		eprintf("rz_socket_http_get: Invalid URI");
		return NULL;
	}
	host += 3;
	port = strchr(host, ':');
	if (!port) {
#if HAVE_LIB_SSL
		port = ssl ? "443" : "80";
#else
		port = "80";
#endif
		path = host;
	} else {
		*port++ = 0;
		path = port;
	}
	path = strchr(path, '/');
	if (!path) {
		path = "";
	} else {
		*path++ = 0;
	}
	s = rz_socket_new(ssl);
	if (!s) {
		eprintf("rz_socket_http_get: Cannot create socket\n");
		free(uri);
		return NULL;
	}
	if (rz_socket_connect_tcp(s, host, port, 0)) {
		rz_socket_printf(s,
			"GET /%s HTTP/1.1\r\n"
			"User-Agent: rizin " RZ_VERSION "\r\n"
			"Accept: */*\r\n"
			"Host: %s:%s\r\n"
			"\r\n",
			path, host, port);
		response = socket_http_answer(s, code, rlen, redirections);
	} else {
		eprintf("Cannot connect to %s:%s\n", host, port);
		response = NULL;
	}
	free(uri);
	rz_socket_free(s);
	return response;
#endif
}

RZ_API char *rz_socket_http_get(const char *url, int *code, int *rlen) {
	return socket_http_get_recursive(url, code, rlen, SOCKET_HTTP_MAX_REDIRECTS);
}

RZ_API char *rz_socket_http_post(const char *url, const char *data, int *code, int *rlen) {
	RzSocket *s;
	bool ssl = rz_str_startswith(url, "https://");
	char *uri = strdup(url);
	if (!uri) {
		return NULL;
	}

	char *host = strstr(uri, "://");
	if (!host) {
		free(uri);
		printf("Invalid URI");
		return NULL;
	}
	host += 3;
	char *port = strchr(host, ':');
	if (!port) {
		port = (ssl) ? "443" : "80";
	} else {
		*port++ = 0;
	}
	char *path = strchr(host, '/');
	if (!path) {
		path = "";
	} else {
		*path++ = 0;
	}
	s = rz_socket_new(ssl);
	if (!s) {
		printf("Cannot create socket\n");
		free(uri);
		return NULL;
	}
	if (!rz_socket_connect_tcp(s, host, port, 0)) {
		eprintf("Cannot connect to %s:%s\n", host, port);
		free(uri);
		return NULL;
	}
	/* Send */
	rz_socket_printf(s,
		"POST /%s HTTP/1.0\r\n"
		"User-Agent: rizin " RZ_VERSION "\r\n"
		"Accept: */*\r\n"
		"Host: %s\r\n"
		"Content-Length: %i\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"\r\n",
		path, host, (int)strlen(data));
	free(uri);
	rz_socket_write(s, (void *)data, strlen(data));
	return socket_http_answer(s, code, rlen, 0);
}
