#ifndef RZ_FILE_H
#define RZ_FILE_H

#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_mmap_t {
	ut8 *buf;
	ut64 base;
	ut64 len;
	int perm;
	int mode;
	char *filename;
	int fd;
#if __WINDOWS__
	void *fm;
#endif
} RzMmap;

/* is */
RZ_API bool rz_file_is_abspath(const char *file);
RZ_API bool rz_file_is_c(const char *file);
RZ_API bool rz_file_is_directory(const char *str);
RZ_API bool rz_file_is_regular(const char *str);

RZ_API bool rz_file_truncate(const char *filename, ut64 newsize);
RZ_API ut64 rz_file_size(const char *str);
RZ_API char *rz_file_root(const char *root, const char *path);
RZ_API RzMmap *rz_file_mmap(const char *file, int perm, int mode, ut64 base);
RZ_API void *rz_file_mmap_resize(RzMmap *m, ut64 newsize);
RZ_API void rz_file_mmap_free(RzMmap *m);
RZ_API bool rz_file_chmod(const char *file, const char *mod, int recursive);
RZ_API char *rz_file_temp(const char *prefix);
RZ_API char *rz_file_path(const char *bin);
RZ_API RZ_OWN char *rz_file_path_join(RZ_NONNULL const char *s1, RZ_NULLABLE const char *s2);
RZ_API const char *rz_file_basename(const char *path);
RZ_API const char *rz_file_dos_basename(RZ_BORROW RZ_NONNULL const char *path);
RZ_API char *rz_file_dirname(const char *path);
RZ_API RZ_OWN char *rz_file_abspath_rel(const char *cwd, const char *file);
RZ_API RZ_OWN char *rz_file_abspath(const char *file);
// make path relative to base
RZ_API char *rz_file_relpath(const char *base, const char *path);
RZ_API char *rz_file_path_local_to_unix(const char *path);
RZ_API char *rz_file_path_unix_to_local(const char *path);
RZ_API char *rz_file_binsh(void);
RZ_API ut8 *rz_inflatew(RZ_NONNULL const ut8 *src, int srcLen, int *srcConsumed, int *dstLen, int wbits);
RZ_API ut8 *rz_inflate(RZ_NONNULL const ut8 *src, int srcLen, int *srcConsumed, int *dstLen);
RZ_API ut8 *rz_inflate_ignore_header(RZ_NONNULL const ut8 *src, int srcLen, int *srcConsumed, int *dstLen);
RZ_API ut8 *rz_deflatew(RZ_NONNULL const ut8 *src, int srcLen, int *srcConsumed, int *dstLen, int wbits);
RZ_API ut8 *rz_deflate(RZ_NONNULL const ut8 *src, int srcLen, int *srcConsumed, int *dstLen);
RZ_API ut8 *rz_file_gzslurp(const char *str, int *outlen, int origonfail);
RZ_API char *rz_stdin_slurp(int *sz);
RZ_API RZ_OWN char *rz_file_slurp(const char *str, RZ_NULLABLE size_t *usz);
RZ_API char *rz_file_slurp_range(const char *str, ut64 off, int sz, int *osz);
RZ_API char *rz_file_slurp_random_line(const char *file);
RZ_API char *rz_file_slurp_random_line_count(const char *file, int *linecount);
RZ_API ut8 *rz_file_slurp_hexpairs(const char *str, int *usz);
RZ_API bool rz_file_dump(const char *file, const ut8 *buf, int len, bool append);
RZ_API bool rz_file_touch(const char *file);
RZ_API bool rz_file_hexdump(const char *file, const ut8 *buf, int len, int append);
RZ_API bool rz_file_rm(const char *file);
RZ_API bool rz_file_exists(const char *str);
RZ_API bool rz_file_fexists(const char *fmt, ...) RZ_PRINTF_CHECK(1, 2);
RZ_API char *rz_file_slurp_line(const char *file, int line, int context);
RZ_API char *rz_file_slurp_lines(const char *file, int line, int count);
RZ_API RZ_OWN char *rz_file_slurp_lines_from_bottom(const char *file, int line);
RZ_API int rz_file_mkstemp(RZ_NULLABLE const char *prefix, char **oname);
RZ_API char *rz_file_tmpdir(void);
RZ_API char *rz_file_readlink(const char *path);
RZ_API bool rz_file_copy(const char *src, const char *dst);
RZ_API RzList /*<char *>*/ *rz_file_globsearch(const char *globbed_path, int maxdepth);
RZ_API bool rz_file_deflate(RZ_NONNULL const char *src, RZ_NONNULL const char *dst);
RZ_API bool rz_file_inflate(RZ_NONNULL const char *src, RZ_NONNULL const char *dst);
RZ_API bool rz_file_is_deflated(RZ_NONNULL const char *src);

#ifdef __cplusplus
}
#endif

#endif //  RZ_FILE_H
