/* radare - LGPL - Copyright 2007-2020 - pancake */

#include "rz_types.h"
#include "rz_util.h"
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <rz_lib.h>
#if __UNIX__
#include <sys/time.h>
#include <sys/mman.h>
#include <limits.h>
#endif
#if __APPLE__ && __MAC_10_5
#define HAVE_COPYFILE_H 1
#else
#define HAVE_COPYFILE_H 0
#endif
#if HAVE_COPYFILE_H
#include <copyfile.h>
#endif
#if _MSC_VER
#include <process.h>
#endif

#define BS 1024

static int file_stat (const char *file, struct stat* const pStat) {
	rz_return_val_if_fail (file && pStat, -1);
#if __WINDOWS__
	wchar_t *wfile = rz_utf8_to_utf16 (file);
	if (!wfile) {
		return -1;
	}
	int ret = _wstat (wfile, pStat);
	free (wfile);
	return ret;
#else // __WINDOWS__
	return stat (file, pStat);
#endif // __WINDOWS__
}

RZ_API bool rz_file_truncate(const char *filename, ut64 newsize) {
	rz_return_val_if_fail (filename, false);
	int fd;
	if (rz_file_is_directory (filename)) {
		return false;
	}
	if (!rz_file_exists (filename) || !rz_file_is_regular (filename)) {
		return false;
	}
#if __WINDOWS__
	fd = rz_sandbox_open (filename, O_RDWR, 0644);
#else
	fd = rz_sandbox_open (filename, O_RDWR | O_SYNC, 0644);
#endif
	if (fd == -1) {
		return false;
	}
#ifdef _MSC_VER
	int r = _chsize (fd, newsize);
#else
	int r = ftruncate (fd, newsize);
#endif
	if (r != 0) {
		eprintf ("Could not resize %s file\n", filename);
		close (fd);
		return false;
	}
	close (fd);
	return true;
}

/*
Example:
	str = rz_file_basename ("home/inisider/Downloads/user32.dll");
	// str == user32.dll
*/
RZ_API const char *rz_file_basename(const char *path) {
	rz_return_val_if_fail (path, NULL);
	const char *ptr = rz_str_rchr (path, NULL, '/');
	if (ptr) {
		path = ptr + 1;
	} else {
		if ((ptr = rz_str_rchr (path, NULL, '\\'))) {
			path = ptr + 1;
		}
	}
	return path;
}

/*
Example:
	str = rz_file_basename ("home/inisider/Downloads");
	// str == "home/inisider/Downloads"
	free (str);
*/
RZ_API char *rz_file_dirname(const char *path) {
	rz_return_val_if_fail (path, NULL);
	char *newpath = strdup (path);
	char *ptr = (char*)rz_str_rchr (newpath, NULL, '/');
	if (ptr) {
		*ptr = 0;
	} else {
		ptr = (char*)rz_str_rchr (newpath, NULL, '\\');
		if (ptr) {
			*ptr = 0;
		}
	}
	return newpath;
}

RZ_API bool rz_file_is_c(const char *file) {
	rz_return_val_if_fail (file, false);
	const char *ext = rz_str_lchr (file, '.'); // TODO: add api in rz_file_extension or rz_str_ext for this
	if (ext) {
		ext++;
		if (!strcmp (ext, "cparse")
		||  !strcmp (ext, "c")
		||  !strcmp (ext, "h")) {
			return true;
		}
	}
	return false;
}

RZ_API bool rz_file_is_regular(const char *str) {
	struct stat buf = {0};
	if (!str || !*str || file_stat (str, &buf) == -1) {
		return false;
	}
	return ((S_IFREG & buf.st_mode) == S_IFREG);
}

RZ_API bool rz_file_is_directory(const char *str) {
	struct stat buf = {0};
	rz_return_val_if_fail (!RZ_STR_ISEMPTY (str), false);
	if (file_stat (str, &buf) == -1) {
		return false;
	}
#ifdef S_IFBLK
	if ((S_IFBLK & buf.st_mode) == S_IFBLK) {
		return false;
	}
#endif
	return S_IFDIR == (S_IFDIR & buf.st_mode);
}

RZ_API bool rz_file_fexists(const char *fmt, ...) {
	int ret;
	char string[BS];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (string, sizeof (string), fmt, ap);
	ret = rz_file_exists (string);
	va_end (ap);
	return ret;
}

RZ_API bool rz_file_exists(const char *str) {
	char *absfile = rz_file_abspath (str);
	struct stat buf = {0};
	rz_return_val_if_fail (!RZ_STR_ISEMPTY (str), false);
	if (file_stat (absfile, &buf) == -1) {
		free (absfile);
		return false;
	}
	free (absfile);
	return S_IFREG == (S_IFREG & buf.st_mode);
}

RZ_API ut64 rz_file_size(const char *str) {
	rz_return_val_if_fail (!RZ_STR_ISEMPTY (str), 0);
	struct stat buf = {0};
	if (file_stat (str, &buf) == -1) {
		return 0;
	}
	return (ut64)buf.st_size;
}

RZ_API bool rz_file_is_abspath(const char *file) {
	rz_return_val_if_fail (!RZ_STR_ISEMPTY (file), 0);
	return ((*file && file[1]==':') || *file == '/');
}

RZ_API char *rz_file_abspath_rel(const char *cwd, const char *file) {
	char *ret = NULL;
	if (!file || !strcmp (file, ".") || !strcmp (file, "./")) {
		return rz_sys_getdir ();
	}
	if (strstr (file, "://")) {
		return strdup (file);
	}
	if (!strncmp (file, "~/", 2) || !strncmp (file, "~\\", 2)) {
		ret = rz_str_home (file + 2);
	} else {
#if __UNIX__
		if (cwd && *file != '/') {
			ret = rz_str_newf ("%s" RZ_SYS_DIR "%s", cwd, file);
		}
#elif __WINDOWS__
		// Network path
		if (!strncmp (file, "\\\\", 2)) {
			return strdup (file);
		}
		if (!strchr (file, ':')) {
			PTCHAR abspath = malloc (MAX_PATH * sizeof (TCHAR));
			if (abspath) {
				PTCHAR f = rz_sys_conv_utf8_to_win (file);
				int s = GetFullPathName (f, MAX_PATH, abspath, NULL);
				if (s > MAX_PATH) {
					RZ_LOG_ERROR ("rz_file_abspath/GetFullPathName: Path to file too long.\n");
				} else if (!s) {
					rz_sys_perror ("rz_file_abspath/GetFullPathName");
				} else {
					ret = rz_sys_conv_win_to_utf8 (abspath);
				}
				free (abspath);
				free (f);
			}
		}
#endif
	}
	if (!ret) {
		ret = strdup (file);
	}
#if __UNIX__
	char *abspath = realpath (ret, NULL);
	if (abspath) {
		free (ret);
		ret = abspath;
	}
#endif
	return ret;
}

RZ_API char *rz_file_abspath(const char *file) {
	rz_return_val_if_fail (file, NULL);
	char *cwd = rz_sys_getdir ();
	if (cwd) {
		char *ret = rz_file_abspath_rel (cwd, file);
		free (cwd);
		return ret;
	}
	return NULL;
}

RZ_API char *rz_file_path(const char *bin) {
	rz_return_val_if_fail (bin, NULL);
	char *file = NULL;
	char *path = NULL;
	char *str, *ptr;
	const char *extension = "";
	if (!strncmp (bin, "./", 2)) {
		return rz_file_exists (bin)
			? rz_file_abspath (bin): NULL;
	}
	char *path_env = (char *)rz_sys_getenv ("PATH");
#if __WINDOWS__
	if (!rz_str_endswith (bin, ".exe")) {
		extension = ".exe";
	}
#endif
	if (path_env) {
		str = path = strdup (path_env);
		do {
			ptr = strchr (str, RZ_SYS_ENVSEP[0]);
			if (ptr) {
				*ptr = '\0';
				file = rz_str_newf (RZ_JOIN_2_PATHS ("%s", "%s%s"), str, bin, extension);
				if (rz_file_exists (file)) {
					free (path);
					free (path_env);
					return file;
				}
				str = ptr + 1;
				free (file);
			}
		} while (ptr);
	}
	free (path_env);
	free (path);
	return strdup (bin);
}

RZ_API char *rz_stdin_slurp (int *sz) {
#if __UNIX__ || __WINDOWS__
	int i, ret, newfd;
	if ((newfd = dup (0)) < 0) {
		return NULL;
	}
	char *buf = malloc (BS);
	if (!buf) {
		close (newfd);
		return NULL;
	}
	for (i = ret = 0; i >= 0; i += ret) {
		char *new = realloc (buf, i + BS);
		if (!new) {
			eprintf ("Cannot realloc to %d\n", i+BS);
			free (buf);
			return NULL;
		}
		buf = new;
		ret = read (0, buf + i, BS);
		if (ret < 1) {
			break;
		}
	}
	if (i < 1) {
		i = 0;
		RZ_FREE (buf);
	} else {
		buf[i] = 0;
		dup2 (newfd, 0);
		close (newfd);
	}
	if (sz) {
		*sz = i;
	}
	if (!i) {
		RZ_FREE (buf);
	}
	return buf;
#else
#warning TODO rz_stdin_slurp
	return NULL;
#endif
}

RZ_API char *rz_file_slurp(const char *str, RZ_NULLABLE size_t *usz) {
	rz_return_val_if_fail (str, NULL);
	if (usz) {
		*usz = 0;
	}
	if (!rz_file_exists (str)) {
		return NULL;
	}
	FILE *fd = rz_sandbox_fopen (str, "rb");
	if (!fd) {
		return NULL;
	}
	if (fseek (fd, 0, SEEK_END) == -1) {
		// cannot determine the size of the file
	}
	long sz = ftell (fd);
	if (sz < 0) {
		fclose (fd);
		return NULL;
	}
	if (!sz) {
		if (rz_file_is_regular (str)) {
			char *buf = NULL;
			long size = 0;
			(void)fseek (fd, 0, SEEK_SET);
			do {
				char *nbuf = realloc (buf, size + BS);
				if (!nbuf) {
					break;
				}
				buf = nbuf;
				size_t r = fread (buf + size, 1, BS, fd);
				if (ferror (fd)) {
					RZ_FREE (buf);
					goto regular_err;
				}
				size += r;
			} while (!feof (fd));
			char *nbuf = realloc (buf, size + 1);
			if (!nbuf) {
				free (buf);
				return NULL;
			}
			buf = nbuf;
			buf[size] = '\0';
			if (usz) {
				*usz = size;
			}
		regular_err:
			fclose (fd);
			return buf;
		}
		// try to read 64K
		sz = UT16_MAX;
	}
	rewind (fd);
	char *ret = (char *)malloc (sz + 1);
	if (!ret) {
		fclose (fd);
		return NULL;
	}
	size_t rsz = fread (ret, 1, sz, fd);
	if (rsz != sz) {
		eprintf ("Warning: rz_file_slurp: fread: truncated read\n");
		sz = rsz;
	}
	fclose (fd);
	ret[sz] = '\0';
	if (usz) {
		*usz = sz;
	}
	return ret;
}

RZ_API ut8 *rz_file_gzslurp(const char *str, int *outlen, int origonfail) {
	rz_return_val_if_fail (str, NULL);
	if (outlen) {
		*outlen = 0;
	}
	size_t sz;
	ut8 *in = (ut8*)rz_file_slurp (str, &sz);
	if (!in) {
		return NULL;
	}
	ut8 *out = rz_inflate (in, (int)sz, NULL, outlen);
	if (!out && origonfail) {
		// if uncompression fails, return orig buffer ?
		if (outlen) {
			*outlen = (int)sz;
		}
		in[sz] = 0;
		return in;
	}
	free (in);
	return out;
}

RZ_API ut8 *rz_file_slurp_hexpairs(const char *str, int *usz) {
	rz_return_val_if_fail (str, NULL);
	if (usz) {
		*usz = 0;
	}
	ut8 *ret;
	long sz;
	int c, bytes = 0;
	FILE *fd = rz_sandbox_fopen (str, "rb");
	if (!fd) {
		return NULL;
	}
	(void) fseek (fd, 0, SEEK_END);
	sz = ftell (fd);
	(void) fseek (fd, 0, SEEK_SET);
	ret = (ut8*)malloc ((sz>>1)+1);
	if (!ret) {
		fclose (fd);
		return NULL;
	}
	for (;;) {
		if (fscanf (fd, " #%*[^\n]") == 1)  {
			continue;
		}
		if (fscanf (fd, "%02x", &c) == 1) {
			ret[bytes++] = c;
			continue;
		}
		if (feof (fd)) {
			break;
		}
		free (ret);
		fclose (fd);
		return NULL;
	}
	ret[bytes] = '\0';
	fclose (fd);
	if (usz) {
		*usz = bytes;
	}
	return ret;
}

RZ_API char *rz_file_slurp_range(const char *str, ut64 off, int sz, int *osz) {
	char *ret;
	size_t read_items;
	FILE *fd = rz_sandbox_fopen (str, "rb");
	if (!fd) {
		return NULL;
	}
	// XXX handle out of bound reads (eof)
	if (fseek (fd, off, SEEK_SET) < 0) {
		fclose (fd);
		return NULL;
	}
	ret = (char *) malloc (sz + 1);
	if (ret) {
		if (osz) {
			*osz = (int)(size_t) fread (ret, 1, sz, fd);
		} else {
			read_items = fread (ret, 1, sz, fd);
			if (!read_items) {
				fclose (fd);
				return ret;
			}
		}
		ret[sz] = '\0';
	}
	fclose (fd);
	return ret;
}

RZ_API char *rz_file_slurp_random_line(const char *file) {
	rz_return_val_if_fail (file, NULL);
	int i = 0;
	return rz_file_slurp_random_line_count (file, &i);
}

RZ_API char *rz_file_slurp_random_line_count(const char *file, int *line) {
	rz_return_val_if_fail (file && line, NULL);
	/* Reservoir Sampling */
	char *ptr = NULL, *str;
	size_t i, lines, selection = -1;
	int start = *line;
	if ((str = rz_file_slurp (file, NULL))) {
		rz_num_irand ();
		for (i = 0; str[i]; i++) {
			if (str[i] == '\n') {
				//here rand doesn't have any security implication
				// https://www.securecoding.cert.org/confluence/display/c/MSC30-C.+Do+not+use+the+rand()+function+for+generating+pseudorandom+numbers
				if (!(rz_num_rand ((++(*line))))) {
					selection = (*line - 1);  /* The line we want. */
				}
			}
		}
		if ((selection < start) || (selection == -1)) {
			free (str);
			return NULL;
		} else {
			lines = selection - start;
		}
		if (lines > 0) {
			for (i = 0; str[i] && lines; i++) {
				if (str[i] == '\n') {
					lines--;
				}
			}
			ptr = str + i;
			for (i = 0; ptr[i]; i++) {
				if (ptr[i] == '\n') {
					ptr[i] = '\0';
					break;
				}
			}
			ptr = strdup (ptr);
		}
		free (str);
	}
	return ptr;
}

RZ_API char *rz_file_slurp_line(const char *file, int line, int context) {
	rz_return_val_if_fail (file, NULL);
	int i, lines = 0;
	size_t sz;
	char *ptr = NULL, *str = rz_file_slurp (file, &sz);
	// TODO: Implement context
	if (str) {
		for (i = 0; str[i]; i++) {
			if (str[i] == '\n') {
				lines++;
			}
		}
		if (line > lines) {
			free (str);
			return NULL;
		}
		lines = line - 1;
		for (i = 0; str[i]&&lines; i++) {
			if (str[i] == '\n') {
				lines--;
			}
		}
		ptr = str+i;
		for (i = 0; ptr[i]; i++) {
			if (ptr[i] == '\n') {
				ptr[i] = '\0';
				break;
			}
		}
		ptr = strdup (ptr);
		free (str);
	}
	return ptr;
}

RZ_API char *rz_file_slurp_lines_from_bottom(const char *file, int line) {
	rz_return_val_if_fail (file, NULL);
	int i, lines = 0;
	size_t sz;
	char *ptr = NULL, *str = rz_file_slurp (file, &sz);
	// TODO: Implement context
	if (str) {
		for (i = 0; str[i]; i++) {
			if (str[i] == '\n') {
				lines++;
			}
		}
		if (line > lines) {
			return strdup (str);	// number of lines requested in more than present, return all
		}
		i--;
		for (; str[i] && line; i--) {
			if (str[i] == '\n') {
				line--;
			}
		}
		ptr = str+i;
		ptr = strdup (ptr);
		free (str);
	}
	return ptr;
}

RZ_API char *rz_file_slurp_lines(const char *file, int line, int count) {
	rz_return_val_if_fail (file, NULL);
	int i, lines = 0;
	size_t sz;
	char *ptr = NULL, *str = rz_file_slurp (file, &sz);
	// TODO: Implement context
	if (str) {
		for (i = 0; str[i]; i++) {
			if (str[i] == '\n') {
				lines++;
			}
		}
		if (line > lines) {
			free (str);
			return NULL;
		}
		lines = line - 1;
		for (i = 0; str[i]&&lines; i++) {
			if (str[i] == '\n') {
				lines--;
			}
		}
		ptr = str+i;
		for (i = 0; ptr[i]; i++) {
			if (ptr[i] == '\n') {
				if (count) {
					count--;
				} else {
					ptr[i] = '\0';
					break;
				}
			}
		}
		ptr = strdup (ptr);
		free (str);
	}
	return ptr;
}

RZ_API char *rz_file_root(const char *root, const char *path) {
	rz_return_val_if_fail (root && path, NULL);
	char *ret, *s = rz_str_replace (strdup (path), "..", "", 1);
	// XXX ugly hack
	while (strstr (s, "..")) {
		s = rz_str_replace (s, "..", "", 1);
	}
	while (strstr (s, "./")) {
		s = rz_str_replace (s, "./", "", 1);
	}
	while (strstr (s, "//")) {
		s = rz_str_replace (s, "//", "", 1);
	}
	ret = rz_str_append (strdup (root), RZ_SYS_DIR);
	ret = rz_str_append (ret, s);
	free (s);
	return ret;
}

RZ_API bool rz_file_hexdump(const char *file, const ut8 *buf, int len, int append) {
	FILE *fd;
	int i,j;
	if (!file || !*file || !buf || len < 0) {
		eprintf ("rz_file_hexdump file: %s buf: %p\n", file, buf);
		return false;
	}
	if (append) {
		fd = rz_sandbox_fopen (file, "ab");
	} else {
		rz_sys_truncate (file, 0);
		fd = rz_sandbox_fopen (file, "wb");
	}
	if (!fd) {
		eprintf ("Cannot open '%s' for writing\n", file);
		return false;
	}
	for (i = 0; i < len; i += 16) {
		int l = RZ_MIN (16, len - i);
		fprintf (fd, "0x%08"PFMT64x"  ", (ut64)i);
		for (j = 0; j + 2 <= l; j += 2) {
			fprintf (fd, "%02x%02x ", buf[i +j], buf[i+j+1]);
		}
		if (j < l) {
			fprintf (fd, "%02x   ", buf[i + j]);
			j += 2;
		}
		if (j < 16) {
			fprintf (fd, "%*s ", (16 - j) / 2 * 5, "");
		}
		for (j = 0; j < 16; j++) {
			fprintf (fd, "%c", j < l && IS_PRINTABLE (buf[i + j])? buf[i+j]: '.');
		}
		fprintf (fd, "\n");
	}
	fclose (fd);
	return true;
}

RZ_API bool rz_file_touch(const char *file) {
	rz_return_val_if_fail (file, false);
	return rz_file_dump (file, NULL, 0, true);
}

RZ_API bool rz_file_dump(const char *file, const ut8 *buf, int len, bool append) {
	rz_return_val_if_fail (!RZ_STR_ISEMPTY (file), false);
	FILE *fd;
	if (append) {
		fd = rz_sandbox_fopen (file, "ab");
	} else {
		rz_sys_truncate (file, 0);
		fd = rz_sandbox_fopen (file, "wb");
	}
	if (!fd) {
		eprintf ("Cannot open '%s' for writing\n", file);
		return false;
	}
	if (buf) {
		if (len < 0) {
			len = strlen ((const char *)buf);
		}
		if (len > 0 && fwrite (buf, len, 1, fd) != 1) {
			rz_sys_perror ("rz_file_dump: fwrite: error\n");
			fclose (fd);
			return false;
		}
	}
	fclose (fd);
	return true;
}

RZ_API bool rz_file_rm(const char *file) {
	rz_return_val_if_fail (!RZ_STR_ISEMPTY (file), false);
	if (rz_sandbox_enable (0)) {
		return false;
	}
	if (rz_file_is_directory (file)) {
#if __WINDOWS__
		LPTSTR file_ = rz_sys_conv_utf8_to_win (file);
		bool ret = RemoveDirectory (file_);

		free (file_);
		return !ret;
#else
		return !rmdir (file);
#endif
	} else {
#if __WINDOWS__
		LPTSTR file_ = rz_sys_conv_utf8_to_win (file);
		bool ret = DeleteFile (file_);

		free (file_);
		return !ret;
#else
		return !unlink (file);
#endif
	}
}

RZ_API char *rz_file_readlink(const char *path) {
	rz_return_val_if_fail (!RZ_STR_ISEMPTY (path), false);
	if (!rz_sandbox_enable (0)) {
#if __UNIX__
		int ret;
		char pathbuf[4096] = {0};
		strncpy (pathbuf, path, sizeof (pathbuf) - 1);
		repeat:
		ret = readlink (path, pathbuf, sizeof (pathbuf)-1);
		if (ret != -1) {
			pathbuf[ret] = 0;
			path = pathbuf;
			goto repeat;
		}
		return strdup (pathbuf);
#endif
	}
	return NULL;
}

RZ_API int rz_file_mmap_write(const char *file, ut64 addr, const ut8 *buf, int len) {
#if __WINDOWS__
	HANDLE fh = INVALID_HANDLE_VALUE;
	DWORD written = 0;
	LPTSTR file_ = NULL;
	int ret = -1;

	if (rz_sandbox_enable (0)) {
		return -1;
	}
	file_ = rz_sys_conv_utf8_to_win (file);
	fh = CreateFile (file_, GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (fh == INVALID_HANDLE_VALUE) {
		rz_sys_perror ("rz_file_mmap_write/CreateFile");
		goto err_r_file_mmap_write;
	}
	SetFilePointer (fh, addr, NULL, FILE_BEGIN);
	if (!WriteFile (fh, buf, (DWORD)len,  &written, NULL)) {
		rz_sys_perror ("rz_file_mmap_write/WriteFile");
		goto err_r_file_mmap_write;
	}
	ret = len;
err_r_file_mmap_write:
	free (file_);
	if (fh != INVALID_HANDLE_VALUE) {
		CloseHandle (fh);
	}
	return ret;
#elif __UNIX__
	int fd = rz_sandbox_open (file, O_RDWR|O_SYNC, 0644);
	const int pagesize = getpagesize ();
	int mmlen = len + pagesize;
	int rest = addr % pagesize;
        ut8 *mmap_buf;
	if (fd == -1) {
		return -1;
	}
	if ((st64)addr < 0) {
		return -1;
	}
	mmap_buf = mmap (NULL, mmlen*2, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)addr - rest);
	if (((int)(size_t)mmap_buf) == -1) {
		return -1;
	}
	memcpy (mmap_buf+rest, buf, len);
	msync (mmap_buf+rest, len, MS_INVALIDATE);
	munmap (mmap_buf, mmlen*2);
	close (fd);
	return len;
#else
	return -1;
#endif
}

RZ_API int rz_file_mmap_read (const char *file, ut64 addr, ut8 *buf, int len) {
#if __WINDOWS__
	HANDLE fm = NULL, fh = INVALID_HANDLE_VALUE;
	LPTSTR file_ = NULL;
	int ret = -1;
	if (rz_sandbox_enable (0)) {
		return -1;
	}
	file_ = rz_sys_conv_utf8_to_win (file);
	fh = CreateFile (file_, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (fh == INVALID_HANDLE_VALUE) {
		rz_sys_perror ("rz_file_mmap_read/CreateFile");
		goto err_r_file_mmap_read;
	}
	fm = CreateFileMapping (fh, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!fm) {
		rz_sys_perror ("CreateFileMapping");
		goto err_r_file_mmap_read;
	}
	ut8 *obuf = MapViewOfFile (fm, FILE_MAP_READ, 0, 0, len);
	if (!obuf) {
		goto err_r_file_mmap_read;
	}
	memcpy (obuf, buf, len);
	UnmapViewOfFile (obuf);
	ret = len;
err_r_file_mmap_read:
	if (fh != INVALID_HANDLE_VALUE) {
		CloseHandle (fh);
	}
	if (fm) {
		CloseHandle (fm);
	}
	free (file_);
	return ret;
#elif __UNIX__
	int fd = rz_sandbox_open (file, O_RDONLY, 0644);
	const int pagesize = 4096;
	int mmlen = len+pagesize;
	int rest = addr%pagesize;
	ut8 *mmap_buf;
	if (fd == -1) {
		return -1;
	}
	mmap_buf = mmap (NULL, mmlen*2, PROT_READ, MAP_SHARED, fd, (off_t)addr-rest);
	if (((int)(size_t)mmap_buf) == -1) {
		return -1;
	}
	memcpy (buf, mmap_buf+rest, len);
	munmap (mmap_buf, mmlen*2);
	close (fd);
	return len;
#endif
	return 0;
}

#if __UNIX__
static RMmap *rz_file_mmap_unix (RMmap *m, int fd) {
	ut8 empty = m->len == 0;
	m->buf = mmap (NULL, (empty?BS:m->len) ,
		m->rw?PROT_READ|PROT_WRITE:PROT_READ,
		MAP_SHARED, fd, (off_t)m->base);
	if (m->buf == MAP_FAILED) {
		RZ_FREE (m);
	}
	return m;
}
#elif __WINDOWS__
static RMmap *rz_file_mmap_windows(RMmap *m, const char *file) {
	LPTSTR file_ = rz_sys_conv_utf8_to_win (file);
	bool success = false;

	m->fh = CreateFile (file_, GENERIC_READ | (m->rw ? GENERIC_WRITE : 0),
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (m->fh == INVALID_HANDLE_VALUE) {
		rz_sys_perror ("CreateFile");
		goto err_r_file_mmap_windows;
	}
	m->fm = CreateFileMapping (m->fh, NULL, PAGE_READONLY, 0, 0, NULL);
		//m->rw?PAGE_READWRITE:PAGE_READONLY, 0, 0, NULL);
	if (!m->fm) {
		rz_sys_perror ("CreateFileMapping");
		goto err_r_file_mmap_windows;

	}
	m->buf = MapViewOfFile (m->fm,
		// m->rw?(FILE_MAP_READ|FILE_MAP_WRITE):FILE_MAP_READ,
		FILE_MAP_COPY,
		UT32_HI (m->base), UT32_LO (m->base), 0);
	success = true;
err_r_file_mmap_windows:
	if (!success) {
		if (m->fh != INVALID_HANDLE_VALUE) {
			CloseHandle (m->fh);
		}
		RZ_FREE (m);
	}
	free (file_);
	return m;
}
#else
static RMmap *file_mmap_other (RMmap *m) {
	ut8 empty = m->len == 0;
	m->buf = malloc ((empty? BS: m->len));
	if (!empty && m->buf) {
		lseek (m->fd, (off_t)0, SEEK_SET);
		read (m->fd, m->buf, m->len);
	} else {
		RZ_FREE (m);
	}
	return m;
}
#endif

RZ_API RMmap *rz_file_mmap_arch(RMmap *mmap, const char *filename, int fd) {
#if __WINDOWS__
	(void)fd;
	return rz_file_mmap_windows (mmap, filename);
#elif __UNIX__
	(void)filename;
	return rz_file_mmap_unix (mmap, fd);
#else
	(void)filename;
	(void)fd;
	return file_mmap_other (mmap);
#endif
}

// TODO: add rwx support?
RZ_API RMmap *rz_file_mmap(const char *file, bool rw, ut64 base) {
	RMmap *m = NULL;
	int fd = -1;
	if (!rw && !rz_file_exists (file)) {
		return m;
	}
	fd = rz_sandbox_open (file, rw? O_RDWR: O_RDONLY, 0644);
	if (fd == -1 && !rw) {
		eprintf ("rz_file_mmap: file does not exis.\n");
		//m->buf = malloc (m->len);
		return m;
	}
	m = RZ_NEW (RMmap);
	if (!m) {
		if (fd != -1) {
			close (fd);
		}
		return NULL;
	}
	m->base = base;
	m->rw = rw;
	m->fd = fd;
	m->len = fd != -1? lseek (fd, (off_t)0, SEEK_END) : 0;
	m->filename = strdup (file);

	if (m->fd == -1) {
		return m;
	}

	if (m->len == (off_t)-1) {
		close (fd);
		RZ_FREE (m);
		return NULL;
	}
#if __UNIX__
	return rz_file_mmap_unix (m, fd);
#elif __WINDOWS__
	close (fd);
	m->fd = -1;
	return rz_file_mmap_windows (m, file);
#else
	return file_mmap_other (m);
#endif
}

RZ_API void rz_file_mmap_free(RMmap *m) {
	if (!m) {
		return;
	}
#if __WINDOWS__
	if (m->fm != INVALID_HANDLE_VALUE) {
		CloseHandle (m->fm);
	}
	if (m->fh != INVALID_HANDLE_VALUE) {
		CloseHandle (m->fh);
	}
	if (m->buf) {
		UnmapViewOfFile (m->buf);
	}
#endif
	if (m->fd == -1) {
		free (m);
		return;
	}
	free (m->filename);
#if __UNIX__
	munmap (m->buf, m->len);
#endif
	close (m->fd);
	free (m);
}

RZ_API char *rz_file_temp (const char *prefix) {
	if (!prefix) {
		prefix = "";
	}
	char *path = rz_file_tmpdir ();
	char *res = rz_str_newf ("%s/%s.%"PFMT64x, path, prefix, rz_time_now ());
	free (path);
	return res;
}

RZ_API int rz_file_mkstemp(RZ_NULLABLE const char *prefix, char **oname) {
	int h = -1;
	char *path = rz_file_tmpdir ();
	if (!prefix) {
		prefix = "r2";
	}
#if __WINDOWS__
	LPTSTR name = NULL;
	LPTSTR path_ = rz_sys_conv_utf8_to_win (path);
	LPTSTR prefix_ = rz_sys_conv_utf8_to_win (prefix);

	name = (LPTSTR)malloc (sizeof (TCHAR) * (MAX_PATH + 1));
	if (!name) {
		goto err_r_file_mkstemp;
	}
	if (GetTempFileName (path_, prefix_, 0, name)) {
		char *name_ = rz_sys_conv_win_to_utf8 (name);
		h = rz_sandbox_open (name_, O_RDWR|O_EXCL|O_BINARY, 0644);
		if (oname) {
			if (h != -1) {
				*oname = name_;
			} else {
				*oname = NULL;
				free (name_);
			}
		} else {
			free (name_);
		}
	}
err_r_file_mkstemp:
	free (name);
	free (path_);
	free (prefix_);
#else
	char pfxx[1024];
	const char *suffix = strchr (prefix, '*');

	if (suffix) {
		suffix++;
		rz_str_ncpy (pfxx, prefix, (size_t)(suffix - prefix));
		prefix = pfxx;
	} else {
		suffix = "";
	}

	char *name = rz_str_newf ("%s/r2.%s.XXXXXX%s", path, prefix, suffix);
	mode_t mask = umask (S_IWGRP | S_IWOTH);
	if (suffix && *suffix) {
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && 2 <= __GLIBC__ && 19 <= __GLIBC__MINOR__
		h = mkstemps (name, strlen (suffix));
#else
		char *const xpos = strrchr (name, 'X');
		const char c = (char)(NULL != xpos ? *(xpos + 1) : 0);
		if (0 != c) {
			xpos[1] = 0;
			h = mkstemp (name);
			xpos[1] = c;
		} else {
			h = -1;
		}
#endif
	} else {
		h = mkstemp (name);
	}
	umask (mask);
	if (oname) {
		*oname = (h!=-1)? strdup (name): NULL;
	}
	free (name);
#endif
	free (path);
	return h;
}

RZ_API char *rz_file_tmpdir(void) {
#if __WINDOWS__
	LPTSTR tmpdir;
	char *path = NULL;
	DWORD len = 0;

	tmpdir = (LPTSTR)calloc (1, sizeof (TCHAR) * (MAX_PATH + 1));
	if (!tmpdir) {
		return NULL;
	}
	if ((len = GetTempPath (MAX_PATH + 1, tmpdir)) == 0) {
		path = rz_sys_getenv ("TEMP");
		if (!path) {
			path = strdup ("C:\\WINDOWS\\Temp\\");
		}
	} else {
		tmpdir[len] = 0;
		DWORD (WINAPI *glpn)(LPCTSTR, LPCTSTR, DWORD) = rz_lib_dl_sym (GetModuleHandle (TEXT ("kernel32.dll")), W32_TCALL("GetLongPathName"));
		if (glpn) {
			// Windows XP sometimes returns short path name
			glpn (tmpdir, tmpdir, MAX_PATH + 1);
		}
		path = rz_sys_conv_win_to_utf8 (tmpdir);
	}
	free (tmpdir);
	// Windows 7, stat() function fail if tmpdir ends with '\\'
	if (path) {
		size_t path_len = strlen (path);
		if (path_len > 0 && path[path_len - 1] == '\\') {
			path[path_len - 1] = '\0';
		}
	}
#else
	char *path = rz_sys_getenv ("TMPDIR");
	if (path && !*path) {
		RZ_FREE (path);
	}
	if (!path) {
#if __ANDROID__
		path = strdup ("/data/data/org.radare.rizininstaller/rizin/tmp");
#else
		path = strdup ("/tmp");
#endif
	}
#endif
	if (!rz_file_is_directory (path)) {
		eprintf ("Cannot find temporary directory '%s'\n", path);
	}
	return path;
}

RZ_API bool rz_file_copy (const char *src, const char *dst) {
	/* TODO: implement in C */
	/* TODO: Use NO_CACHE for iOS dyldcache copying */
#if HAVE_COPYFILE_H
	return copyfile (src, dst, 0, COPYFILE_DATA | COPYFILE_XATTR) != -1;
#elif __WINDOWS__
	PTCHAR s = rz_sys_conv_utf8_to_win (src);
	PTCHAR d = rz_sys_conv_utf8_to_win (dst);
	if (!s || !d) {
		RZ_LOG_ERROR ("rz_file_copy: Failed to allocate memory\n");
		free (s);
		free (d);
		return false;
	}
	bool ret = CopyFile (s, d, 0);
	if (!ret) {
		rz_sys_perror ("rz_file_copy");
	}
	free (s);
	free (d);
	return ret;
#else
	char *src2 = rz_str_replace (strdup (src), "'", "\\'", 1);
	char *dst2 = rz_str_replace (strdup (dst), "'", "\\'", 1);
	int rc = rz_sys_cmdf ("cp -f '%s' '%s'", src2, dst2);
	free (src2);
	free (dst2);
	return rc == 0;
#endif
}

static void recursive_search_glob (const char *path, const char *glob, RzList* list, int depth) {
	if (depth < 1) {
		return;
	}
	char* file;
	RzListIter *iter;
	RzList *dir = rz_sys_dir (path);
	rz_list_foreach (dir, iter, file) {
		if (!strcmp (file, ".") || !strcmp (file, "..")) {
			continue;
		}
		char *filename = malloc (strlen (path) + strlen (file) + 2);
		strcpy (filename, path);
		strcat (filename, file);
		if (rz_file_is_directory (filename)) {
			strcat (filename, RZ_SYS_DIR);
			recursive_search_glob (filename, glob, list, depth - 1);
			free (filename);
		} else if (rz_str_glob (file, glob)) {
			rz_list_append (list, filename);
		} else {
			free (filename);
		}
	}
	rz_list_free (dir);
}

RZ_API RzList* rz_file_globsearch (const char *_globbed_path, int maxdepth) {
	char *globbed_path = strdup (_globbed_path);
	RzList *files = rz_list_newf (free);
	char *glob = strchr (globbed_path, '*');
	if (!glob) {
		rz_list_append (files, strdup (globbed_path));
	} else {
		*glob = '\0';
		char *last_slash = (char *)rz_str_last (globbed_path, RZ_SYS_DIR);
		*glob = '*';
		char *path, *glob_ptr;
		if (last_slash) {
			glob_ptr = last_slash + 1;
			if (globbed_path[0] == '~') {
				char *rpath = rz_str_newlen (globbed_path + 2, last_slash - globbed_path - 1);
				path = rz_str_home (rpath ? rpath : "");
				free (rpath);
			} else {
				path = rz_str_newlen (globbed_path, last_slash - globbed_path + 1);
			}
		} else {
			glob_ptr = globbed_path;
			path = rz_str_newf (".%s", RZ_SYS_DIR);
		}

		if (!path) {
			rz_list_free (files);
			free (globbed_path);
			return NULL;
		}

		if (*(glob + 1) == '*') {  // "**"
			recursive_search_glob (path, glob_ptr, files, maxdepth);
		} else {                   // "*"
			recursive_search_glob (path, glob_ptr, files, 1);
		}
		free (path);
	}
	free (globbed_path);
	return files;
}
