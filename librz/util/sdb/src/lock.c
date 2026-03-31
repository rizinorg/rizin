// SPDX-FileCopyrightText: 2012-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include <rz_userconf.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <rz_util/rz_sys.h>
#include "sdb.h"
#if __WINDOWS__
#include <windows.h>
#endif

RZ_API RZ_OWN char *sdb_lock_file(const char *f) {
	char *buf = calloc(128, sizeof(char));
	size_t len;
	if (!f || !*f) {
		return NULL;
	}
	len = strlen(f);
	if (len + 10 > sizeof buf) {
		return NULL;
	}
	memcpy(buf, f, len);
	strcpy(buf + len, ".lock");
	return buf;
}

RZ_API bool sdb_lock(const char *s) {
	int fd;
	char *pid, pidstr[64];
	if (!s) {
		return false;
	}
	fd = open(s, O_CREAT | O_TRUNC | O_WRONLY | O_EXCL, SDB_MODE);
	if (fd == -1) {
		return false;
	}
	pid = sdb_itoa(rz_sys_getpid(), pidstr, 10);
	if (pid) {
		if ((write(fd, pid, strlen(pid)) < 0) || (write(fd, "\n", 1) < 0)) {
			close(fd);
			return false;
		}
	}
	close(fd);
	return true;
}

RZ_API int sdb_lock_wait(const char *s) {
	// TODO use flock() here
	// wait forever here?
	while (!sdb_lock(s)) {
		// TODO: if waiting too much return 0
		rz_sys_sleep(1);
	}
	return 1;
}

RZ_API void sdb_unlock(const char *s) {
	// flock (fd, LOCK_UN);
	unlink(s);
}
