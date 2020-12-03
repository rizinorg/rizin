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

static bool enabled = false;
static bool disabled = false;

static bool inHomeWww(const char *path) {
	rz_return_val_if_fail (path, false);
	bool ret = false;
	char *homeWww = rz_str_home (RZ_HOME_WWWROOT RZ_SYS_DIR);
	if (homeWww) {
		if (!strncmp (path, homeWww, strlen (homeWww))) {
			ret = true;
		}
		free (homeWww);
	}
	return ret;
}

/**
 * This function verifies that the given path is allowed. Paths are allowed only if they don't
 * contain .. components (which would indicate directory traversal) and they are relative.
 * Paths pointing into the webroot are an exception: For reaching the webroot, .. and absolute
 * path are ok.
 */
RZ_API bool rz_sandbox_check_path (const char *path) {
	rz_return_val_if_fail (path, false);
	size_t root_len;
	char *p;
	/* XXX: the sandbox can be bypassed if a directory is symlink */
	root_len = strlen (RZ_LIBDIR"/rizin");
	if (!strncmp (path, RZ_LIBDIR"/rizin", root_len)) {
		return true;
	}
	root_len = strlen (RZ_DATDIR"/rizin");
	if (!strncmp (path, RZ_DATDIR"/rizin", root_len)) {
		return true;
	}
	if (inHomeWww (path)) {
		return true;
	}
	// Accessing stuff inside the webroot is ok even if we need .. or leading / for that
	root_len = strlen (RZ_WWWROOT);
	if (RZ_WWWROOT[0] && !strncmp (path, RZ_WWWROOT, root_len) && (
			RZ_WWWROOT[root_len-1] == '/' || path[root_len] == '/' || path[root_len] == '\0')) {
		path += strlen (RZ_WWWROOT);
		while (*path == '/') {
			path++;
		}
	}

	// ./ path is not allowed
        if (path[0]=='.' && path[1]=='/') {
		return false;
	}
	// Properly check for directory traversal using "..". First, does it start with a .. part?
	if (path[0] == '.' && path[1] == '.' && (path[2] == '\0' || path[2] == '/')) {
		return 0;
	}

	// Or does it have .. in some other position?
	for (p = strstr (path, "/.."); p; p = strstr(p, "/..")) {
		if (p[3] == '\0' || p[3] == '/') {
			return false;
		}
	}
	// Absolute paths are forbidden.
	if (*path == '/') {
		return false;
	}
#if __UNIX__
	char ch;
	if (readlink (path, &ch, 1) != -1) {
		return false;
	}
#endif
	return true;
}

RZ_API bool rz_sandbox_disable (bool e) {
	if (e) {
#if LIBC_HAVE_PLEDGE
		if (enabled) {
			eprintf ("sandbox mode couldn't be disabled when pledged\n");
			return enabled;
		}
#endif
#if HAVE_CAPSICUM
		if (enabled) {
			eprintf ("sandbox mode couldn't be disabled in capability mode\n");
			return enabled;
		}
#endif
#if LIBC_HAVE_PRIV_SET
		if (enabled) {
			eprintf ("sandbox mode couldn't be disabled in priv mode\n");
			return enabled;
		}
#endif
		disabled = enabled;
		enabled = false;
	} else {
		enabled = disabled;
		disabled = false;
	}
	return enabled;
}

RZ_API bool rz_sandbox_enable (bool e) {
	if (enabled) {
		if (!e) {
			// eprintf ("Can't disable sandbox\n");
		}
		return true;
	}
	enabled = e;
#if LIBC_HAVE_PLEDGE
	if (enabled && pledge ("stdio rpath tty prot_exec inet", NULL) == -1) {
		eprintf ("sandbox: pledge call failed\n");
		return false;
	}
#endif
#if HAVE_CAPSICUM
	if (enabled) {
#if __FreeBSD_version >= 1000000
		cap_rights_t wrt, rdr;

		if (!cap_rights_init (&wrt, CAP_READ, CAP_WRITE)) {
			eprintf ("sandbox: write descriptor failed\n");
			return false;
		}

		if (!cap_rights_init (&rdr, CAP_READ, CAP_EVENT, CAP_FCNTL)) {
			eprintf ("sandbox: read descriptor failed\n");
			return false;
		}

		if (cap_rights_limit (STDIN_FILENO, &rdr) == -1) {
			eprintf ("sandbox: stdin protection failed\n");
			return false;
		}

		if (cap_rights_limit (STDOUT_FILENO, &wrt) == -1) {
			eprintf ("sandbox: stdout protection failed\n");
			return false;
		}

		if (cap_rights_limit (STDERR_FILENO, &wrt) == -1) {
			eprintf ("sandbox: stderr protection failed\n");
			return false;
		}
#endif

		if (cap_enter () != 0) {
			eprintf ("sandbox: call_enter failed\n");
			return false;
		}
	}
#endif
#if LIBC_HAVE_PRIV_SET
	if (enabled) {
		priv_set_t *priv = priv_allocset();
		const char *const privrules[] = {
			PRIV_PROC_INFO,
			PRIV_PROC_SESSION,
			PRIV_PROC_ZONE,
			PRIV_NET_OBSERVABILITY
		};

		size_t i, privrulescnt = sizeof (privrules) / sizeof (privrules[0]);
		
		if (!priv) {
			eprintf ("sandbox: priv_allocset failed\n");
			return false;
		}
		priv_basicset(priv);
		
		for (i = 0; i < privrulescnt; i ++) {
			if (priv_delset (priv, privrules[i]) != 0) {
				priv_emptyset (priv);
				priv_freeset (priv);
				eprintf ("sandbox: priv_delset failed\n");
				return false;
			}
		}

		priv_freeset (priv);
	}
#endif
	return enabled;
}

RZ_API int rz_sandbox_system(const char *x, int n) {
	rz_return_val_if_fail (x, -1);
	if (enabled) {
		eprintf ("sandbox: system call disabled\n");
		return -1;
	}
#if LIBC_HAVE_FORK
#if LIBC_HAVE_SYSTEM
	if (n) {
#if APPLE_SDK_IPHONEOS
#include <spawn.h>
		int argc;
		char *cmd = strdup (x);
		char **argv = rz_str_argv (cmd, &argc);
		if (argv) {
			char *argv0 = rz_file_path (argv[0]);
			pid_t pid = 0;
			int r = posix_spawn (&pid, argv0, NULL, NULL, argv, NULL);
			int status;
			int s = waitpid (pid, &status, 0);
			return WEXITSTATUS (s);
		}
#else
		return rz_sys_system (x);
#endif
	}
	return rz_sys_execl ("/bin/sh", "sh", "-c", x, (const char*)NULL);
#else
	#include <spawn.h>
	if (n && !strchr (x, '|')) {
		char **argv, *cmd = strdup (x);
		int rc, pid, argc;
		char *isbg = strchr (cmd, '&');
		// XXX this is hacky
		if (isbg) {
			*isbg = 0;
		}
		argv = rz_str_argv (cmd, &argc);
		if (argv) {
			char *argv0 = rz_file_path (argv[0]);
			if (!argv0) {
				eprintf ("Cannot find '%s'\n", argv[0]);
				return -1;
			}
			pid = 0;
			posix_spawn (&pid, argv0, NULL, NULL, argv, NULL);
			if (isbg) {
				// XXX. wait for children
				rc = 0;
			} else {
				rc = waitpid (pid, NULL, 0);
			}
			rz_str_argv_free (argv);
			free (argv0);
			return rc;
		}
		eprintf ("Error parsing command arguments\n");
		return -1;
	}
	int child = fork ();
	if (child == -1) {
		return -1;
	}
	if (child) {
		return waitpid (child, NULL, 0);
	}
	if (rz_sys_execl ("/bin/sh", "sh", "-c", x, (const char*)NULL) == -1) {
		perror ("execl");
	}
	exit (1);
#endif
#endif
	return -1;
}

RZ_API bool rz_sandbox_creat (const char *path, int mode) {
	if (enabled) {
		return false;
#if 0
		if (mode & O_CREAT) return -1;
		if (mode & O_RDWR) return -1;
		if (!rz_sandbox_check_path (path))
			return -1;
#endif
	}
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
	if (enabled) {
		return -1;
	}
	return lseek (fd, (off_t)addr, whence);
}

RZ_API int rz_sandbox_truncate(int fd, ut64 length) {
	if (enabled) {
		return -1;
	}
#ifdef _MSC_VER
	return _chsize_s (fd, length);
#else
	return ftruncate (fd, (off_t)length);
#endif
}

RZ_API int rz_sandbox_read(int fd, ut8 *buf, int len) {
	return enabled? -1: read (fd, buf, len);
}

RZ_API int rz_sandbox_write(int fd, const ut8* buf, int len) {
	return enabled? -1: write (fd, buf, len);
}

RZ_API int rz_sandbox_close(int fd) {
	return enabled? -1: close (fd);
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
#endif
	if (enabled) {
		if ((perm & O_CREAT) || (perm & O_RDWR)
			|| (!rz_sandbox_check_path (epath))) {
			free (epath);
			return -1;
		}
	}
#if __WINDOWS__
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
	if (enabled) {
		if (strchr (mode, 'w') || strchr (mode, 'a') || strchr (mode, '+')) {
			return NULL;
		}
		epath = expand_home (path);
		if (!rz_sandbox_check_path (epath)) {
			free (epath);
			return NULL;
		}
	}
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
	if (enabled) {
		// TODO: check path
		if (strstr (path, "../")) {
			return -1;
		}
		if (*path == '/') {
			return -1;
		}
		return -1;
	}
	return chdir (path);
}

RZ_API int rz_sandbox_kill(int pid, int sig) {
	rz_return_val_if_fail (pid != -1, -1);
	// XXX: fine-tune. maybe we want to enable kill for child?
	if (enabled) {
		return -1;
	}
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
	if (rz_sandbox_enable (0)) {
		if (path && !rz_sandbox_check_path (path)) {
			return NULL;
		}
	}
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
	if (rz_sandbox_enable (0)) {
		if (path && !rz_sandbox_check_path (path)) {
			return NULL;
		}
	}
	return opendir (path);
}
#endif
RZ_API bool rz_sys_stop (void) {
	if (enabled) {
		return false;
	}
#if __UNIX__
	return !rz_sandbox_kill (0, SIGTSTP);
#else
	return false;
#endif
}
