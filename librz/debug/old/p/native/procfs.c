// SPDX-FileCopyrightText: 2009-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>
#include <rz_debug.h>

int procfs_pid_slurp(int pid, char *prop, char *out, size_t len) {
	int fd, ret = -1;
	ssize_t nr;

	char *filename = rz_str_newf("/proc/%d/%s", pid, prop);
	if (!filename) {
		return -1;
	}
	fd = rz_sys_open(filename, O_RDONLY, 0);
	if (fd == -1) {
		free(filename);
		return -1;
	}
	nr = read(fd, out, len);
	out[len - 1] = 0;
	if (nr > 0) {
		out[nr - 1] = '\0'; /* terminate at newline */
		ret = 0;
	} else if (nr < 0) {
		rz_sys_perror("read");
	}
	close(fd);
	free(filename);
	return ret;
}
