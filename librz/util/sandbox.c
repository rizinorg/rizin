// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <signal.h>
#if _MSC_VER
#include <process.h> // to compile execl under msvc windows
#include <direct.h>  // to compile chdir under msvc windows
#endif

#if HAVE_CAPSICUM
#include <sys/capsicum.h>
#endif

#if LIBC_HAVE_PRIV_SET
#include <priv.h>
#endif


RZ_API bool rz_sandbox_creat (const char *path, int mode) {
	int fd = open (path, O_CREAT | O_TRUNC | O_WRONLY, mode);
	if (fd != -1) {
		close (fd);
		return true;
	}
	return false;
}

static inline char *expand_home(const char *p) {
	return (*p == '~')? rz_str_home (p): strdup (p);
}

RZ_API int rz_sandbox_lseek(int fd, ut64 addr, int whence) {
	return lseek (fd, (off_t)addr, whence);
}

RZ_API int rz_sandbox_truncate(int fd, ut64 length) {
#ifdef _MSC_VER
	return _chsize_s (fd, length);
#else
	return ftruncate (fd, (off_t)length);
#endif
}

RZ_API int rz_sandbox_read(int fd, ut8 *buf, int len) {
	return read (fd, buf, len);
}

RZ_API int rz_sandbox_write(int fd, const ut8* buf, int len) {
	return write (fd, buf, len);
}

RZ_API int rz_sandbox_close(int fd) {
	return close (fd);
}

/* perm <-> mode */
RZ_API int rz_sandbox_open(const char *path, int perm, int mode) {
	rz_return_val_if_fail (path, -1);
	char *epath = expand_home (path);
	int ret = -1;
#if __WINDOWS__
	if (!strcmp (path, "/dev/null")) {
		path = "NUL";
	}
	{
		DWORD flags = 0;
		if (perm & O_RANDOM) {
			flags = FILE_FLAG_RANDOM_ACCESS;
		} else if (perm & O_SEQUENTIAL) {
			flags = FILE_FLAG_SEQUENTIAL_SCAN;
		}
		if (perm & O_TEMPORARY) {
			flags |= FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_TEMPORARY;
		} else if (perm & _O_SHORT_LIVED) {
			flags |= FILE_ATTRIBUTE_TEMPORARY;
		} else {
			flags |= FILE_ATTRIBUTE_NORMAL;
		}
		DWORD creation = 0;
		bool read_only = false;
		if (perm & O_CREAT) {
			if (perm & O_EXCL) {
				creation = CREATE_NEW;
			} else {
				creation = OPEN_ALWAYS;
			}
			if (mode & S_IREAD && !(mode & S_IWRITE)) {
				flags = FILE_ATTRIBUTE_READONLY;
				read_only = true;
			}
		} else if (perm & O_TRUNC) {
			creation = TRUNCATE_EXISTING;
		}
		if (!creation || !strcasecmp ("NUL", path)) {
			creation = OPEN_EXISTING;
		}
		DWORD permission = 0;
		if (perm & O_WRONLY) {
			permission = GENERIC_WRITE;
		} else if (perm & O_RDWR) {
			permission = GENERIC_WRITE | GENERIC_READ;
		} else {
			permission = GENERIC_READ;
		}
		if (perm & O_APPEND) {
			permission |= FILE_APPEND_DATA;
		}

		wchar_t *wepath = rz_utf8_to_utf16 (epath);
		if (!wepath) {
			free (epath);
			return -1;
		}
		HANDLE h = CreateFileW (wepath, permission, FILE_SHARE_READ | (read_only ? 0 : FILE_SHARE_WRITE), NULL, creation, flags, NULL);
		if (h != INVALID_HANDLE_VALUE) {
			ret = _open_osfhandle ((intptr_t)h, perm);
		}
		free (wepath);
	}
#else // __WINDOWS__
	ret = open (epath, perm, mode);
#endif // __WINDOWS__
	free (epath);
	return ret;
}

RZ_API FILE *rz_sandbox_fopen (const char *path, const char *mode) {
	rz_return_val_if_fail (path && mode, NULL);
	FILE *ret = NULL;
	char *epath = NULL;
	if (!epath) {
		epath = expand_home (path);
	}
	if ((strchr (mode, 'w') || strchr (mode, 'a') || rz_file_is_regular (epath))) {
#if __WINDOWS__
		wchar_t *wepath = rz_utf8_to_utf16 (epath);
		if (!wepath) {
			free (epath);
			return ret;
		}
		wchar_t *wmode = rz_utf8_to_utf16 (mode);
		if (!wmode) {
			free (wepath);
			free (epath);
			return ret;
		}
		ret = _wfopen (wepath, wmode);
		free (wmode);
		free (wepath);
#else // __WINDOWS__
		ret = fopen (epath, mode);
#endif // __WINDOWS__
	}
	free (epath);
	return ret;
}

RZ_API int rz_sandbox_chdir(const char *path) {
	rz_return_val_if_fail (path, -1);
	return chdir (path);
}

RZ_API int rz_sandbox_kill(int pid, int sig) {
	rz_return_val_if_fail (pid != -1, -1);
#if __UNIX__
	return kill (pid, sig);
#endif
	return -1;
}
#if __WINDOWS__
RZ_API HANDLE rz_sandbox_opendir (const char *path, WIN32_FIND_DATAW *entry) {
	rz_return_val_if_fail (path, NULL);
	wchar_t dir[MAX_PATH];
	wchar_t *wcpath = 0;
	if (!(wcpath = rz_utf8_to_utf16 (path))) {
		return NULL;
	}
	swprintf (dir, MAX_PATH, L"%ls\\*.*", wcpath);
	free (wcpath);
	return FindFirstFileW (dir, entry);
}
#else
RZ_API DIR* rz_sandbox_opendir (const char *path) {
	rz_return_val_if_fail (path, NULL);
	return opendir (path);
}
#endif
RZ_API bool rz_sys_stop (void) {
#if __UNIX__
	return !rz_sandbox_kill (0, SIGTSTP);
#else
	return false;
#endif
}
