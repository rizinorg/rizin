// SPDX-FileCopyrightText: 2011-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if __UNIX__

#define GETCWD_BUFFER_SIZE 4096

typedef struct {
	char oper;
	mode_t mode;
} chmod_t;

static bool parse_options(const char *str, chmod_t *chm) {
	char *end;
	const char *p;
	int octal;
	mode_t mask = 0;

	octal = strtol(str, &end, 8);
	if (*end == '\0') {
		if (octal & 04000) {
			chm->mode |= S_ISUID;
		}
		if (octal & 02000) {
			chm->mode |= S_ISGID;
		}
		if (octal & 00400) {
			chm->mode |= S_IRUSR;
		}
		if (octal & 00200) {
			chm->mode |= S_IWUSR;
		}
		if (octal & 00100) {
			chm->mode |= S_IXUSR;
		}
		if (octal & 00040) {
			chm->mode |= S_IRGRP;
		}
		if (octal & 00020) {
			chm->mode |= S_IWGRP;
		}
		if (octal & 00010) {
			chm->mode |= S_IXGRP;
		}
		if (octal & 00004) {
			chm->mode |= S_IROTH;
		}
		if (octal & 00002) {
			chm->mode |= S_IWOTH;
		}
		if (octal & 00001) {
			chm->mode |= S_IXOTH;
		}
		return true;
	}
	for (p = str; *p; p++) {
		switch (*p) {
		/* masks */
		case 'u':
			mask |= S_IRWXU;
			break;
		case 'g':
			mask |= S_IRWXG;
			break;
		case 'o':
			mask |= S_IRWXO;
			break;
		case 'a':
			mask |= S_IRWXU | S_IRWXG | S_IRWXO;
			break;
		/* opers */
		case '+':
		case '-':
		case '=':
			chm->oper = *p;
			break;
		/* modes */
		case 'r':
			chm->mode |= S_IRUSR | S_IRGRP | S_IROTH;
			break;
		case 'w':
			chm->mode |= S_IWUSR | S_IWGRP | S_IWOTH;
			break;
		case 'x':
			chm->mode |= S_IXUSR | S_IXGRP | S_IXOTH;
			break;
		case 's':
			chm->mode |= S_ISUID | S_ISGID;
			break;
		/* error */
		default:
			eprintf("%s: invalid mode\n", str);
			return false;
		}
	}
	if (mask) {
		chm->mode &= mask;
	}
	return true;
}

static char *agetcwd(void) {
	char *buf = malloc(GETCWD_BUFFER_SIZE);
	if (!buf) {
		return NULL;
	}
	if (!getcwd(buf, GETCWD_BUFFER_SIZE)) {
		eprintf("getcwd:");
	}
	return buf;
}

static void recurse(const char *path, int rec, bool (*fn)(const char *, int, chmod_t *), chmod_t *chm) {
	char *cwd;
	struct dirent *d;
	struct stat st;
	DIR *dp;

	if (lstat(path, &st) == -1 || !S_ISDIR(st.st_mode)) {
		return;
	} else if (!(dp = opendir(path))) {
		eprintf("opendir %s:", path);
		return;
	}
	cwd = agetcwd();
	if (chdir(path) == -1) {
		eprintf("chdir %s:", path);
		closedir(dp);
		free(cwd);
		return;
	}
	while ((d = readdir(dp))) {
		if (strcmp(d->d_name, ".") && strcmp(d->d_name, "..")) {
			fn(d->d_name, 1, chm);
		}
	}

	closedir(dp);
	if (chdir(cwd) == -1) {
		eprintf("chdir %s:", cwd);
	}
	free(cwd);
}

/* copied from sbase/chmod.c (suckless.org) */
static bool chmodr(const char *path, int rflag, chmod_t *chm) {
	struct stat st;

	if (stat(path, &st) == -1) {
		return false;
	}

	switch (chm->oper) {
	case '+':
		st.st_mode |= chm->mode;
		break;
	case '-':
		st.st_mode &= ~chm->mode;
		break;
	case '=':
		st.st_mode = chm->mode;
		break;
	}
	if (chmod(path, st.st_mode) == -1) {
		eprintf("chmod %s:", path);
		return false;
	}
	if (rflag) {
		recurse(path, rflag, chmodr, chm);
	}
	return true;
}

#endif

RZ_API bool rz_file_chmod(const char *file, const char *mod, int recursive) {
#if __UNIX__
	chmod_t chm;
	chm.oper = '=';
	chm.mode = 0;
	if (!parse_options(mod, &chm)) {
		return false;
	}
	return chmodr(file, recursive, &chm);
#else
	return false;
#endif
}
