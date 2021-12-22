// SPDX-FileCopyrightText: 2013-2020 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#if __UNIX__
#include <unistd.h>
#elif __WINDOWS__
#include <windows.h>
#endif
#include "spp.h"
#include "rz_api.h"

SStrBuf *rz_strbuf_new(const char *str) {
	SStrBuf *s = RZ_NEW0 (SStrBuf);
	if (str) rz_strbuf_set (s, str);
	return s;
}

void rz_strbuf_init(SStrBuf *sb) {
	memset (sb, 0, sizeof (SStrBuf));
}

bool rz_strbuf_set(SStrBuf *sb, const char *s) {
	int l;
	if (!sb) return false;
	if (!s) {
		rz_strbuf_init (sb);
		return true;
	}
	l = strlen (s);
	if (l >= sizeof (sb->buf)) {
		char *ptr = sb->ptr;
		if (!ptr || l+1 > sb->ptrlen) {
			ptr = malloc (l + 1);
			if (!ptr) return false;
			sb->ptrlen = l + 1;
			sb->ptr = ptr;
		}
		memcpy (ptr, s, l+1);
	} else {
		sb->ptr = NULL;
		memcpy (sb->buf, s, l+1);
	}
	sb->len = l;
	return true;
}

bool rz_strbuf_append(SStrBuf *sb, const char *s) {
	int l = strlen (s);
	if (l < 1) {
		return false;
	}
	if ((sb->len + l + 1) < sizeof (sb->buf)) {
		memcpy (sb->buf + sb->len, s, l + 1);
		RZ_FREE (sb->ptr);
	} else {
		int newlen = sb->len + l + 128;
		char *p = sb->ptr;
		bool allocated = true;
		if (!sb->ptr) {
			p = malloc (newlen);
			if (p && sb->len > 0) {
				memcpy (p, sb->buf, sb->len);
			}
		} else if (sb->len + l + 1 > sb->ptrlen) {
			p = realloc (sb->ptr, newlen);
		} else {
			allocated = false;
		}
		if (allocated) {
			if (!p) return false;
			sb->ptr = p;
			sb->ptrlen = newlen;
		}
		memcpy (p + sb->len, s, l + 1);
	}
	sb->len += l;
	return true;
}

char *rz_strbuf_get(SStrBuf *sb) {
	return sb? (sb->ptr? sb->ptr: sb->buf) : NULL;
}

char *rz_strbuf_drain(SStrBuf *sb) {
	char *res = sb->ptr? sb->ptr: strdup (sb->buf);
	sb->ptr = NULL;
	rz_strbuf_fini (sb);
	free (sb);
	return res;
}

void rz_strbuf_free(SStrBuf *sb) {
	rz_strbuf_fini (sb);
	free (sb);
}

void rz_strbuf_fini(SStrBuf *sb) {
	if (sb && sb->ptr)
		RZ_FREE (sb->ptr);
}

/* --------- */
int rz_sys_setenv(const char *key, const char *value) {
	if (!key) {
		return 0;
	}
#if __UNIX__
	if (!value) {
		unsetenv (key);
		return 0;
	}
	return setenv (key, value, 1);
#elif __WINDOWS__
	int ret = SetEnvironmentVariableA (key, value);
	return ret ? 0 : -1;
#else
#warning rz_sys_setenv : unimplemented for this platform
	return 0;
#endif
}

char *rz_sys_getenv(const char *key) {
#if __WINDOWS__
	DWORD dwRet;
	char *envbuf = NULL, *tmp_ptr;
	char *val = NULL;
	const int TMP_BUFSIZE = 4096;
	if (!key) {
		return NULL;
	}
	envbuf = malloc (sizeof (envbuf) * TMP_BUFSIZE);
	if (!envbuf) {
		goto err_r_sys_get_env;
	}
	dwRet = GetEnvironmentVariableA (key, envbuf, TMP_BUFSIZE);
	if (dwRet == 0) {
		if (GetLastError () == ERROR_ENVVAR_NOT_FOUND) {
			goto err_r_sys_get_env;
		}
	} else if (TMP_BUFSIZE < dwRet) {
		tmp_ptr = realloc (envbuf, dwRet);
		if (!tmp_ptr) {
			goto err_r_sys_get_env;
		}
		envbuf = tmp_ptr;
		dwRet = GetEnvironmentVariableA (key, envbuf, dwRet);
		if (!dwRet) {
			goto err_r_sys_get_env;
		}
	}
	val = strdup (envbuf);
err_r_sys_get_env:
	free (envbuf);
	return val;
#else
	char *b;
	if (!key) {
		return NULL;
	}
	b = getenv (key);
	return b? strdup (b): NULL;
#endif
}

int rz_sys_getpid() {
#if __UNIX__
	return getpid();
#elif __WINDOWS__
	return GetCurrentProcessId();
#else
#warning rz_sys_getpid not implemented for this platform
	return -1;
#endif
}
