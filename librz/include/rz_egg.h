#ifndef RZ_EGG_H
#define RZ_EGG_H

#include <rz_asm.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_syscall.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_egg);

#define RZ_EGG_INCDIR_ENV  "EGG_INCDIR"
#define RZ_EGG_INCDIR_PATH "/lib/rizin/" RZ_VERSION "/egg"

// rename to RzEggShellcode
#define RZ_EGG_PLUGIN_SHELLCODE 0
#define RZ_EGG_PLUGIN_ENCODER   1

typedef struct rz_egg_plugin_t {
	const char *name;
	const char *desc;
	int type;
	RzBuffer *(*build)(void *egg);
} RzEggPlugin;

typedef struct rz_egg_lang_t {
	int pushargs;
	int nalias;
	int nsyscalls;
	char *conditionstr;
	char *syscallbody;
	char *includefile;
	char *setenviron;
	char *mathline;
	// used for confusing mathop
	int commentmode;
	int varsize;
	int varxs;
	int lastctxdelta;
	int nargs;
	int docall;
	int nfunctions;
	int nbrackets;
	int slurpin;
	int slurp;
	int line;
	char elem[1024];
	int attsyntax;
	int elem_n;
	char *callname;
	char *endframe;
	char *ctxpush[32];
	char *file;
	char *dstvar;
	char *dstval;
	char *includedir;
	char *ifelse_table[32][32];
	// used to solve if-else problem in a not so ugly way
	int ndstval;
	int skipline; // BOOL
	int quoteline;
	int quotelinevar;
	int stackframe;
	int stackfixed;
	int oc;
	int mode;
	int inlinectr;
	struct {
		char *name;
		char *body;
		// int fastcall; /* TODO: NOT YET USED */
	} inlines[256];
	int ninlines;
	struct {
		char *name;
		char *arg;
	} syscalls[256];
	struct {
		char *name;
		char *content;
	} aliases[256];
	char *nested[32];
	char *nested_callname[32];
	// char *nestede[32] = {0};
	// seems nestede are not used any more
	// (only one place that gives nestede[] value, where could be replaced)
	int nestedi[32];
} RzEggLang;

typedef struct rz_egg_t {
	RzBuffer *src;
	RzBuffer *buf;
	RzBuffer *bin;
	// RzList *shellcodes; // XXX is plugins nao?
	RzAsm *rasm;
	RzSyscall *syscall;
	RzEggLang lang;
	Sdb *db;
	HtSP /*<RzEggPlugin *>*/ *plugins;
	RzList /*<struct egg_patch_t *>*/ *patches; // <RzBuffer>
	struct rz_egg_emit_t *remit;
	int arch;
	int endian;
	int bits;
	ut32 os;
	int context;
} RzEgg;

#define RZ_EGG_OS_LINUX   0x5ca62a43
#define RZ_EGG_OS_OSX     0x0ad593a1
#define RZ_EGG_OS_DARWIN  0xd86d1ae2
#define RZ_EGG_OS_WATCHOS 0x14945c70
#define RZ_EGG_OS_IOS     0x0ad58830
#define RZ_EGG_OS_MACOS   0x5cb23c16
#define RZ_EGG_OS_W32     0x0ad5fbb3
#define RZ_EGG_OS_WINDOWS 0x05b7de9a
#define RZ_EGG_OS_BEOS    0x506108be
#define RZ_EGG_OS_FREEBSD 0x73a72944

#if __APPLE__
#define RZ_EGG_OS_DEFAULT     RZ_EGG_OS_OSX
#define RZ_EGG_OS_NAME        "darwin"
#define RZ_EGG_FORMAT_DEFAULT "mach0"
#elif __WINDOWS__
#define RZ_EGG_OS_DEFAULT     RZ_EGG_OS_W32
#define RZ_EGG_OS_NAME        "windows"
#define RZ_EGG_FORMAT_DEFAULT "pe"
#else
#define RZ_EGG_OS_DEFAULT     RZ_EGG_OS_LINUX
#define RZ_EGG_OS_NAME        "linux"
#define RZ_EGG_FORMAT_DEFAULT "elf"
#endif

typedef struct rz_egg_emit_t {
	const char *arch;
	int size; /* in bytes.. 32bit arch is 4, 64bit is 8 .. */
	const char *retvar;
	// const char *syscall_body;
	const char *(*regs)(RzEgg *egg, int idx);
	void (*init)(RzEgg *egg);
	void (*call)(RzEgg *egg, const char *addr, int ptr);
	void (*jmp)(RzEgg *egg, const char *addr, int ptr);
	// void (*sc)(int num);
	void (*frame)(RzEgg *egg, int sz);
	char *(*syscall)(RzEgg *egg, int num);
	void (*trap)(RzEgg *egg);
	void (*frame_end)(RzEgg *egg, int sz, int ctx);
	void (*comment)(RzEgg *egg, const char *fmt, ...);
	void (*push_arg)(RzEgg *egg, int xs, int num, const char *str);
	void (*set_string)(RzEgg *egg, const char *dstvar, const char *str, int j);
	void (*equ)(RzEgg *egg, const char *key, const char *value);
	void (*get_result)(RzEgg *egg, const char *ocn);
	void (*restore_stack)(RzEgg *egg, int size);
	void (*syscall_args)(RzEgg *egg, int nargs);
	void (*get_var)(RzEgg *egg, int type, char *out, int idx);
	void (*get_ar)(RzEgg *egg, char *out, int idx);
	void (*while_end)(RzEgg *egg, const char *label);
	void (*load)(RzEgg *egg, const char *str, int sz);
	void (*load_ptr)(RzEgg *egg, const char *str);
	void (*branch)(RzEgg *egg, char *b, char *g, char *e, char *n, int sz, const char *dst);
	void (*mathop)(RzEgg *egg, int ch, int sz, int type, const char *eq, const char *p);
	void (*get_while_end)(RzEgg *egg, char *out, const char *ctxpush, const char *label);
} RzEggEmit;

#ifdef RZ_API
RZ_API RzEgg *rz_egg_new(void);
RZ_API void rz_egg_lang_init(RzEgg *egg);
RZ_API void rz_egg_lang_free(RzEgg *egg);
RZ_API const char *rz_egg_os_as_string(int os);
RZ_API char *rz_egg_to_string(RzEgg *egg);
RZ_API void rz_egg_free(RzEgg *egg);
RZ_API bool rz_egg_plugin_add(RzEgg *a, RZ_NONNULL RzEggPlugin *plugin);
RZ_API bool rz_egg_plugin_del(RzEgg *a, RZ_NONNULL RzEggPlugin *plugin);
RZ_API void rz_egg_reset(RzEgg *egg);
RZ_API bool rz_egg_setup(RzEgg *egg, const char *arch, int bits, int endian, const char *os);
RZ_API int rz_egg_include(RzEgg *egg, const char *file, int format);
RZ_API void rz_egg_load(RzEgg *egg, const char *code, int format);
RZ_API bool rz_egg_load_file(RzEgg *egg, const char *file);
RZ_API void rz_egg_syscall(RzEgg *egg, const char *arg, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API void rz_egg_alloc(RzEgg *egg, int n);
RZ_API void rz_egg_label(RzEgg *egg, const char *name);
RZ_API int rz_egg_raw(RzEgg *egg, const ut8 *b, int len);
RZ_API int rz_egg_encode(RzEgg *egg, const char *name);
RZ_API int rz_egg_shellcode(RzEgg *egg, const char *name);
#define rz_egg_get_shellcodes(x) x->plugins
RZ_API void rz_egg_option_set(RzEgg *egg, const char *k, const char *v);
RZ_API char *rz_egg_option_get(RzEgg *egg, const char *k);
RZ_API void rz_egg_if(RzEgg *egg, const char *reg, char cmp, int v);
RZ_API void rz_egg_printf(RzEgg *egg, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API int rz_egg_compile(RzEgg *egg);
RZ_API int rz_egg_padding(RzEgg *egg, const char *pad);
RZ_API bool rz_egg_assemble(RzEgg *egg);
RZ_API bool rz_egg_assemble_asm(RzEgg *egg, char **asm_list);
RZ_API bool rz_egg_pattern(RzEgg *egg, int size);
// RZ_API int rz_egg_dump (RzEgg *egg, const char *file) { }
RZ_API char *rz_egg_get_source(RzEgg *egg);
RZ_API RzBuffer *rz_egg_get_bin(RzEgg *egg);
RZ_API char *rz_egg_get_assembly(RzEgg *egg);
RZ_API void rz_egg_append(RzEgg *egg, const char *src);
RZ_API int rz_egg_run(RzEgg *egg);
RZ_API int rz_egg_run_rop(RzEgg *egg);
RZ_API int rz_egg_patch(RzEgg *egg, int off, const ut8 *b, int l);
RZ_API bool rz_egg_patch_num(RzEgg *egg, int off, ut64 val, ut32 bits);
RZ_API void rz_egg_finalize(RzEgg *egg);

/* rz_egg_Cfile.c */
RZ_API char *rz_egg_Cfile_parser(const char *file, const char *arch, const char *os, int bits);

/* lang.c */
RZ_API char *rz_egg_mkvar(RzEgg *egg, char *out, const char *_str, int delta);
RZ_API int rz_egg_lang_parsechar(RzEgg *egg, char c);
RZ_API void rz_egg_lang_include_path(RzEgg *egg, const char *path);
RZ_API void rz_egg_lang_include_init(RzEgg *egg);

#endif

#ifdef __cplusplus
}
#endif

#endif
