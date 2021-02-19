#ifndef RZ_SYS_H
#define RZ_SYS_H

#include <rz_list.h>

#if __WINDOWS__
#define RZ_SYS_DEVNULL "nul"
#else
#define RZ_SYS_DEVNULL "/dev/null"
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
	RZ_SYS_BITS_8 = 1,
	RZ_SYS_BITS_16 = 2,
	RZ_SYS_BITS_32 = 4,
	RZ_SYS_BITS_64 = 8,
};

typedef struct {
	char *sysname;
	char *nodename;
	char *release;
	char *version;
	char *machine;
} RSysInfo;

RZ_API RSysInfo *rz_sys_info(void);
RZ_API void rz_sys_info_free(RSysInfo *si);

RZ_API int rz_sys_sigaction(int *sig, void (*handler)(int));
RZ_API int rz_sys_signal(int sig, void (*handler)(int));
RZ_API void rz_sys_env_init(void);
RZ_API char **rz_sys_get_environ(void);
RZ_API void rz_sys_set_environ(char **e);

RZ_API int rz_sys_fork(void);
RZ_API int rz_sys_kill(int pid, int sig);
// nocleanup = false => exit(); true => _exit()
RZ_API void rz_sys_exit(int status, bool nocleanup);
RZ_API bool rz_is_heap(void *p);
RZ_API bool rz_sys_stop(void);
RZ_API char *rz_sys_pid_to_path(int pid);
RZ_API int rz_sys_run(const ut8 *buf, int len);
RZ_API int rz_sys_run_rop(const ut8 *buf, int len);
RZ_API int rz_sys_getpid(void);
#if !HAVE_PIPE || (__UNIX__ && HAVE_PIPE)
RZ_API int rz_sys_pipe(int pipefd[2], bool close_on_exec);
RZ_API int rz_sys_pipe_close(int fd);
#else
#define rz_sys_pipe       pipe
#define rz_sys_pipe_close close
#endif
#if !HAVE_EXECV || (__UNIX__ && HAVE_EXECV && HAVE_PIPE && !HAVE_PIPE2)
RZ_API int rz_sys_execv(const char *pathname, char *const argv[]);
#else
#define rz_sys_execv execv
#endif
#if !HAVE_EXECVE || (__UNIX__ && HAVE_EXECVE && HAVE_PIPE && !HAVE_PIPE2)
RZ_API int rz_sys_execve(const char *pathname, char *const argv[], char *const envp[]);
#else
#define rz_sys_execve execve
#endif
#if !HAVE_EXECVP || (__UNIX__ && HAVE_EXECVP && HAVE_PIPE && !HAVE_PIPE2)
RZ_API int rz_sys_execvp(const char *file, char *const argv[]);
#else
#define rz_sys_execvp execvp
#endif
#if !HAVE_EXECL || (__UNIX__ && HAVE_EXECL && HAVE_PIPE && !HAVE_PIPE2)
RZ_API int rz_sys_execl(const char *pathname, const char *arg, ...);
#else
#define rz_sys_execl execl
#endif
#if !HAVE_SYSTEM || (__UNIX__ && HAVE_SYSTEM && HAVE_PIPE && !HAVE_PIPE2)
RZ_API int rz_sys_system(const char *command);
#else
#define rz_sys_system system
#endif
#define rz_sys_xsystem(cmd) RZ_V_NOT(rz_sys_system(cmd), -1)

RZ_API int rz_sys_crash_handler(const char *cmd);
RZ_API const char *rz_sys_arch_str(int arch);
RZ_API int rz_sys_arch_id(const char *arch);
RZ_API bool rz_sys_arch_match(const char *archstr, const char *arch);
RZ_API RzList *rz_sys_dir(const char *path);
RZ_API void rz_sys_perror_str(const char *fun);
#if __WINDOWS__
#define rz_sys_mkdir_failed() (GetLastError() != ERROR_ALREADY_EXISTS)
#else
#define rz_sys_mkdir_failed() (errno != EEXIST)
#endif
RZ_API const char *rz_sys_prefix(const char *pfx);
RZ_API bool rz_sys_mkdir(const char *dir);
RZ_API bool rz_sys_mkdirp(const char *dir);
RZ_API int rz_sys_sleep(int secs);
RZ_API int rz_sys_usleep(int usecs);
RZ_API char *rz_sys_getenv(const char *key);
RZ_API bool rz_sys_getenv_asbool(const char *key);
RZ_API int rz_sys_setenv(const char *key, const char *value);
RZ_API int rz_sys_clearenv(void);
RZ_API char *rz_sys_whoami(char *buf);
RZ_API char *rz_sys_getdir(void);
RZ_API int rz_sys_chdir(const char *s);
RZ_API bool rz_sys_aslr(int val);
RZ_API int rz_sys_thp_mode(void);
RZ_API int rz_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr);
#if __WINDOWS__
#if UNICODE
#define W32_TCHAR_FSTR                      "%S"
#define W32_TCALL(name)                     name "W"
#define rz_sys_conv_utf8_to_win(buf)        rz_utf8_to_utf16(buf)
#define rz_sys_conv_utf8_to_win_l(buf, len) rz_utf8_to_utf16_l(buf, len)
#define rz_sys_conv_win_to_utf8(buf)        rz_utf16_to_utf8(buf)
#define rz_sys_conv_win_to_utf8_l(buf, len) rz_utf16_to_utf8_l((wchar_t *)buf, len)
#else
#define W32_TCHAR_FSTR                      "%s"
#define W32_TCALL(name)                     name "A"
#define rz_sys_conv_utf8_to_win(buf)        rz_utf8_to_acp(buf)
#define rz_sys_conv_utf8_to_win_l(buf, len) rz_utf8_to_acp_l(buf, len)
#define rz_sys_conv_win_to_utf8(buf)        rz_acp_to_utf8(buf)
#define rz_sys_conv_win_to_utf8_l(buf, len) rz_acp_to_utf8_l(buf, len)
#endif
RZ_API char *rz_sys_get_src_dir_w32(void);
RZ_API bool rz_sys_cmd_str_full_w32(const char *cmd, const char *input, char **output, int *outlen, char **sterr);
RZ_API bool rz_sys_create_child_proc_w32(const char *cmdline, HANDLE in, HANDLE out, HANDLE err);
#endif
RZ_API int rz_sys_open_perms(int rizin_perms);
RZ_API int rz_sys_open(const char *path, int perm, int mode);
RZ_API FILE *rz_sys_fopen(const char *path, const char *mode);
RZ_API int rz_sys_truncate_fd(int fd, ut64 length);
RZ_API int rz_sys_truncate(const char *file, int sz);
RZ_API int rz_sys_cmdbg(const char *cmd);
RZ_API int rz_sys_cmdf(const char *fmt, ...) RZ_PRINTF_CHECK(1, 2);
RZ_API char *rz_sys_cmd_str(const char *cmd, const char *input, int *len);
RZ_API char *rz_sys_cmd_strf(const char *cmd, ...) RZ_PRINTF_CHECK(1, 2);
//#define rz_sys_cmd_str(cmd, input, len) rz_sys_cmd_str_full(cmd, input, len, 0)
RZ_API void rz_sys_backtrace(void);

#if __WINDOWS__
#define rz_sys_breakpoint() \
	{ __debugbreak(); }
#else
#if __GNUC__
#define rz_sys_breakpoint() __builtin_trap()
#elif __i386__ || __x86_64__
#define rz_sys_breakpoint() __asm__ volatile("int3");
#elif __arm64__ || __aarch64__
#define rz_sys_breakpoint() __asm__ volatile("brk 0");
// #define rz_sys_breakpoint() __asm__ volatile ("brk #1");
#elif (__arm__ || __thumb__)
#if __ARM_ARCH > 5
#define rz_sys_breakpoint() __asm__ volatile("bkpt $0");
#else
#define rz_sys_breakpoint() __asm__ volatile("svc $1");
#endif
#elif __mips__
#define rz_sys_breakpoint() __asm__ volatile("break");
// #  define rz_sys_breakpoint() __asm__ volatile ("teq $0, $0");
#elif __EMSCRIPTEN__
// TODO: cannot find a better way to breakpoint in wasm/asm.js
#define rz_sys_breakpoint() \
	{ \
		char *a = NULL; \
		*a = 0; \
	}
#else
#warning rz_sys_breakpoint not implemented for this platform
#define rz_sys_trap() __asm__ __volatile__(".word 0");
#define rz_sys_breakpoint() \
	{ \
		char *a = NULL; \
		*a = 0; \
	}
#endif
#endif

/* syscmd */
RZ_API char *rz_syscmd_ls(const char *input);
RZ_API char *rz_syscmd_cat(const char *file);
RZ_API char *rz_syscmd_mkdir(const char *dir);
RZ_API bool rz_syscmd_mv(const char *input);
RZ_API char *rz_syscmd_uniq(const char *file);
RZ_API char *rz_syscmd_head(const char *file, int count);
RZ_API char *rz_syscmd_tail(const char *file, int count);
RZ_API char *rz_syscmd_join(const char *file1, const char *file2);
RZ_API char *rz_syscmd_sort(const char *file);

#ifdef __cplusplus
}
#endif

#endif //  RZ_SYS_H
