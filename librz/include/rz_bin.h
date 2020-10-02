#ifndef RZ_BIN_H
#define RZ_BIN_H

#include <rz_util.h>
#include <rz_types.h>
#include <rz_io.h>
#include <rz_cons.h>
#include <rz_list.h>

typedef struct rz_bin_t RBin;

#include <rz_bin_dwarf.h>
#include <rz_pdb.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (rz_bin);

#define R_BIN_DBG_STRIPPED 0x01
#define R_BIN_DBG_STATIC   0x02
#define R_BIN_DBG_LINENUMS 0x04
#define R_BIN_DBG_SYMS     0x08
#define R_BIN_DBG_RELOCS   0x10

#define R_BIN_ENTRY_TYPE_PROGRAM 0
#define R_BIN_ENTRY_TYPE_MAIN    1
#define R_BIN_ENTRY_TYPE_INIT    2
#define R_BIN_ENTRY_TYPE_FINI    3
#define R_BIN_ENTRY_TYPE_TLS     4
#define R_BIN_ENTRY_TYPE_PREINIT 5

#define R_BIN_SIZEOF_STRINGS 512
#define R_BIN_MAX_ARCH 1024

#define R_BIN_REQ_ALL       UT64_MAX
#define R_BIN_REQ_UNK       0x000000
#define R_BIN_REQ_ENTRIES   0x000001
#define R_BIN_REQ_IMPORTS   0x000002
#define R_BIN_REQ_SYMBOLS   0x000004
#define R_BIN_REQ_SECTIONS  0x000008
#define R_BIN_REQ_INFO      0x000010
#define R_BIN_REQ_OPERATION 0x000020
#define R_BIN_REQ_HELP      0x000040
#define R_BIN_REQ_STRINGS   0x000080
#define R_BIN_REQ_FIELDS    0x000100
#define R_BIN_REQ_LIBS      0x000200
#define R_BIN_REQ_SRCLINE   0x000400
#define R_BIN_REQ_MAIN      0x000800
#define R_BIN_REQ_EXTRACT   0x001000
#define R_BIN_REQ_RELOCS    0x002000
#define R_BIN_REQ_LISTARCHS 0x004000
#define R_BIN_REQ_CREATE    0x008000
#define R_BIN_REQ_CLASSES   0x010000
#define R_BIN_REQ_DWARF     0x020000
#define R_BIN_REQ_SIZE      0x040000
#define R_BIN_REQ_PDB       0x080000
#define R_BIN_REQ_PDB_DWNLD 0x100000
#define R_BIN_REQ_DLOPEN    0x200000
#define R_BIN_REQ_EXPORTS   0x400000
#define R_BIN_REQ_VERSIONINFO 0x800000
#define R_BIN_REQ_PACKAGE   0x1000000
#define R_BIN_REQ_HEADER    0x2000000
#define R_BIN_REQ_LISTPLUGINS 0x4000000
#define R_BIN_REQ_RESOURCES 0x8000000
#define R_BIN_REQ_INITFINI  0x10000000
#define R_BIN_REQ_SEGMENTS  0x20000000
#define R_BIN_REQ_HASHES    0x40000000
#define R_BIN_REQ_SIGNATURE 0x80000000
#define R_BIN_REQ_TRYCATCH 0x100000000
#define R_BIN_REQ_SECTIONS_MAPPING 0x200000000

/* RBinSymbol->method_flags : */
#define R_BIN_METH_CLASS 0x0000000000000001L
#define R_BIN_METH_STATIC 0x0000000000000002L
#define R_BIN_METH_PUBLIC 0x0000000000000004L
#define R_BIN_METH_PRIVATE 0x0000000000000008L
#define R_BIN_METH_PROTECTED 0x0000000000000010L
#define R_BIN_METH_INTERNAL 0x0000000000000020L
#define R_BIN_METH_OPEN 0x0000000000000040L
#define R_BIN_METH_FILEPRIVATE 0x0000000000000080L
#define R_BIN_METH_FINAL 0x0000000000000100L
#define R_BIN_METH_VIRTUAL 0x0000000000000200L
#define R_BIN_METH_CONST 0x0000000000000400L
#define R_BIN_METH_MUTATING 0x0000000000000800L
#define R_BIN_METH_ABSTRACT 0x0000000000001000L
#define R_BIN_METH_SYNCHRONIZED 0x0000000000002000L
#define R_BIN_METH_NATIVE 0x0000000000004000L
#define R_BIN_METH_BRIDGE 0x0000000000008000L
#define R_BIN_METH_VARARGS 0x0000000000010000L
#define R_BIN_METH_SYNTHETIC 0x0000000000020000L
#define R_BIN_METH_STRICT 0x0000000000040000L
#define R_BIN_METH_MIRANDA 0x0000000000080000L
#define R_BIN_METH_CONSTRUCTOR 0x0000000000100000L
#define R_BIN_METH_DECLARED_SYNCHRONIZED 0x0000000000200000L

#define R_BIN_BIND_LOCAL_STR "LOCAL"
#define R_BIN_BIND_GLOBAL_STR "GLOBAL"
#define R_BIN_BIND_WEAK_STR "WEAK"
#define R_BIN_BIND_NUM_STR "NUM"
#define R_BIN_BIND_LOOS_STR "LOOS"
#define R_BIN_BIND_HIOS_STR "HIOS"
#define R_BIN_BIND_LOPROC_STR "LOPROC"
#define R_BIN_BIND_HIPROC_STR "HIPROC"
#define R_BIN_BIND_UNKNOWN_STR "UNKNOWN"

#define R_BIN_TYPE_NOTYPE_STR "NOTYPE"
#define R_BIN_TYPE_OBJECT_STR "OBJ"
#define R_BIN_TYPE_FUNC_STR "FUNC"
#define R_BIN_TYPE_METH_STR "METH"
#define R_BIN_TYPE_STATIC_STR "STATIC"
#define R_BIN_TYPE_SECTION_STR "SECT"
#define R_BIN_TYPE_FILE_STR "FILE"
#define R_BIN_TYPE_COMMON_STR "COMMON"
#define R_BIN_TYPE_TLS_STR "TLS"
#define R_BIN_TYPE_NUM_STR "NUM"
#define R_BIN_TYPE_LOOS_STR "LOOS"
#define R_BIN_TYPE_HIOS_STR "HIOS"
#define R_BIN_TYPE_LOPROC_STR "LOPROC"
#define R_BIN_TYPE_HIPROC_STR "HIPROC"
#define R_BIN_TYPE_SPECIAL_SYM_STR "SPCL"
#define R_BIN_TYPE_UNKNOWN_STR "UNK"

enum {
	R_BIN_SYM_ENTRY,
	R_BIN_SYM_INIT,
	R_BIN_SYM_MAIN,
	R_BIN_SYM_FINI,
	R_BIN_SYM_LAST
};

// name mangling types
// TODO: Rename to R_BIN_LANG_
enum {
	R_BIN_NM_NONE = 0,
	R_BIN_NM_JAVA = 1,
	R_BIN_NM_C = 1<<1,
	R_BIN_NM_GO = 1<<2,
	R_BIN_NM_CXX = 1<<3,
	R_BIN_NM_OBJC = 1<<4,
	R_BIN_NM_SWIFT = 1<<5,
	R_BIN_NM_DLANG = 1<<6,
	R_BIN_NM_MSVC = 1<<7,
	R_BIN_NM_RUST = 1<<8,
	R_BIN_NM_KOTLIN = 1<<9,
	R_BIN_NM_BLOCKS = 1<<31,
	R_BIN_NM_ANY = -1,
};

enum {
	R_STRING_TYPE_DETECT = '?',
	R_STRING_TYPE_ASCII = 'a',
	R_STRING_TYPE_UTF8 = 'u',
	R_STRING_TYPE_WIDE = 'w', // utf16 / widechar string
	R_STRING_TYPE_WIDE32 = 'W', // utf32
	R_STRING_TYPE_BASE64 = 'b',
};

enum {
	R_BIN_CLASS_PRIVATE,
	R_BIN_CLASS_PUBLIC,
	R_BIN_CLASS_FRIENDLY,
	R_BIN_CLASS_PROTECTED,
};

enum {
	R_BIN_RELOC_8 = 8,
	R_BIN_RELOC_16 = 16,
	R_BIN_RELOC_32 = 32,
	R_BIN_RELOC_64 = 64
};

enum {
	R_BIN_TYPE_DEFAULT = 0,
	R_BIN_TYPE_CORE = 1
};

typedef struct rz_bin_addr_t {
	ut64 vaddr;
	ut64 paddr;
	ut64 hvaddr;
	ut64 hpaddr;
	int type;
	int bits;
} RBinAddr;

typedef struct rz_bin_hash_t {
	const char *type;
	ut64 addr;
	int len;
	ut64 from;
	ut64 to;
	ut8 buf[32];
	const char *cmd;
} RBinHash;

typedef struct rz_bin_file_hash_t {
	const char *type;
	const char *hex;
} RBinFileHash;

typedef struct rz_bin_info_t {
	char *file;
	char *type;
	char *bclass;
	char *rclass;
	char *arch;
	char *cpu;
	char *machine;
	char *head_flag;
	char *features;
	char *os;
	char *subsystem;
	char *rpath;
	char *guid;
	char *debug_file_name;
	const char *lang;
	char *default_cc;
	RzList/*<RBinFileHash>*/ *file_hashes;
	int bits;
	int has_va;
	int has_pi; // pic/pie
	int has_canary;
	int has_retguard;
	int has_sanitizers;
	int has_crypto;
	int has_nx;
	int big_endian;
	bool has_lit;
	char *actual_checksum;
	char *claimed_checksum;
	int pe_overlay;
	bool signature;
	ut64 dbg_info;
	RBinHash sum[3];
	ut64 baddr;
	char *intrp;
	char *compiler;
} RBinInfo;

typedef struct rz_bin_object_t {
	ut64 baddr;
	st64 baddr_shift;
	ut64 loadaddr;
	ut64 boffset;
	ut64 size;
	ut64 obj_size;
	RzList/*<RBinSection>*/ *sections;
	RzList/*<RBinImport>*/ *imports;
	RzList/*<RBinSymbol>*/ *symbols;
	RzList/*<??>*/ *entries;
	RzList/*<??>*/ *fields;
	RzList/*<??>*/ *libs;
	RBNode/*<RBinReloc>*/ *relocs;
	RzList/*<??>*/ *strings;
	RzList/*<RBinClass>*/ *classes;
	HtPP *classes_ht;
	HtPP *methods_ht;
	RzList/*<RBinDwarfRow>*/ *lines;
	HtUP *strings_db;
	RzList/*<??>*/ *mem;	//RBinMem maybe?
	RzList/*<BinMap*/ *maps;
	char *regstate;
	RBinInfo *info;
	RBinAddr *binsym[R_BIN_SYM_LAST];
	struct rz_bin_plugin_t *plugin;
	int lang;
	Sdb *kv;
	Sdb *addrzklassmethod;
	void *bin_obj; // internal pointer used by formats
} RBinObject;

// XXX: RbinFile may hold more than one RBinObject
/// XX curplugin == o->plugin
typedef struct rz_bin_file_t {
	char *file;
	int fd;
	int size;
	int rawstr;
	int strmode;
	ut32 id;
	RBuffer *buf;
	ut64 offset;
	RBinObject *o;
	void *xtr_obj;
	ut64 loadaddr;
	/* values used when searching the strings */
	int minstrlen;
	int maxstrlen;
	int narch;
	struct rz_bin_xtr_plugin_t *curxtr;
	// struct rz_bin_plugin_t *curplugin; // use o->plugin
	RzList *xtr_data;
	Sdb *sdb;
	Sdb *sdb_info;
	Sdb *sdb_addrinfo;
	struct rz_bin_t *rbin;
} RBinFile;

typedef struct rz_bin_file_options_t {
	int rawstr;
	ut64 baddr; // base address
	ut64 laddr; // load address
	ut64 paddr; // offset
	const char *plugname; // force a plugin? why do i need this?
	// const char *xtrname;
} RBinFileOptions;

struct rz_bin_t {
	const char *file;
	RBinFile *cur; // TODO: deprecate
	int narch;
	void *user;
	/* preconfigured values */
	int debase64;
	int minstrlen;
	int maxstrlen;
	ut64 maxstrbuf;
	int rawstr;
	Sdb *sdb;
	RIDStorage *ids;
	RzList/*<RBinPlugin>*/ *plugins;
	RzList/*<RBinXtrPlugin>*/ *binxtrs;
	RzList/*<RBinLdrPlugin>*/ *binldrs;
	RzList/*<RBinFile>*/ *binfiles;
	PrintfCallback cb_printf;
	int loadany;
	RzIOBind iob;
	RzConsBind consb;
	char *force;
	int is_debugger;
	bool want_dbginfo;
	int filter; // symbol filtering
	char strfilter; // string filtering
	char *strpurge; // purge false positive strings
	char *srcdir; // dir.source
	char *prefix; // bin.prefix
	char *strenc;
	ut64 filter_rules;
	bool demanglercmd;
	bool verbose;
	bool use_xtr; // use extract plugins when loading a file?
	bool use_ldr; // use loader plugins when loading a file?
	RStrConstPool constpool;
	bool is_reloc_patched; // used to indicate whether relocations were patched or not
};

typedef struct rz_bin_xtr_metadata_t {
	char *arch;
	int bits;
	char *libname;
	char *machine;
	char *type;
	const char *xtr_type;
} RBinXtrMetadata;

typedef int (*FREE_XTR)(void *xtr_obj);
typedef struct rz_bin_xtr_extract_t {
	char *file;
	RBuffer *buf;
	ut64 size;
	ut64 offset;
	ut64 baddr;
	ut64 laddr;
	int file_count;
	int loaded;
	RBinXtrMetadata *metadata;
} RBinXtrData;

RZ_API RBinXtrData *rz_bin_xtrdata_new(RBuffer *buf, ut64 offset, ut64 size, ut32 file_count, RBinXtrMetadata *metadata);
RZ_API void rz_bin_xtrdata_free(void /*RBinXtrData*/ *data);

typedef struct rz_bin_xtr_plugin_t {
	char *name;
	char *desc;
	char *license;
	int (*init)(void *user);
	int (*fini)(void *user);
	bool (*check_buffer)(RBuffer *b);

	RBinXtrData *(*extract_from_bytes)(RBin *bin, const ut8 *buf, ut64 size, int idx);
	RBinXtrData *(*extract_from_buffer)(RBin *bin, RBuffer *buf, int idx);
	RzList *(*extractall_from_bytes)(RBin *bin, const ut8 *buf, ut64 size);
	RzList *(*extractall_from_buffer)(RBin *bin, RBuffer *buf);
	RBinXtrData *(*extract)(RBin *bin, int idx);
	RzList *(*extractall)(RBin *bin);

	bool (*load)(RBin *bin);
	int (*size)(RBin *bin);
	void (*destroy)(RBin *bin);
	void (*free_xtr)(void *xtr_obj);
} RBinXtrPlugin;

typedef struct rz_bin_ldr_plugin_t {
	char *name;
	char *desc;
	char *license;
	int (*init)(void *user);
	int (*fini)(void *user);
	bool (*load)(RBin *bin);
} RBinLdrPlugin;

typedef struct rz_bin_arch_options_t {
	const char *arch;
	int bits;
} RBinArchOptions;

typedef struct rz_bin_trycatch_t {
	ut64 source;
	ut64 from;
	ut64 to;
	ut64 handler;
	ut64 filter;
	// TODO: add type/name of exception
} RBinTrycatch;

RZ_API RBinTrycatch *rz_bin_trycatch_new(ut64 source, ut64 from, ut64 to, ut64 handler, ut64 filter);
RZ_API void rz_bin_trycatch_free(RBinTrycatch *tc);

typedef struct rz_bin_plugin_t {
	char *name;
	char *desc;
	char *author;
	char *version;
	char *license;
	int (*init)(void *user);
	int (*fini)(void *user);
	Sdb * (*get_sdb)(RBinFile *obj);
	bool (*load_buffer)(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb);
	ut64 (*size)(RBinFile *bin); // return ut64 maybe? meh
	void (*destroy)(RBinFile *bf);
	bool (*check_bytes)(const ut8 *buf, ut64 length);
	bool (*check_buffer)(RBuffer *buf);
	ut64 (*baddr)(RBinFile *bf);
	ut64 (*boffset)(RBinFile *bf);
	RBinAddr* (*binsym)(RBinFile *bf, int num);
	RzList/*<RBinAddr>*/* (*entries)(RBinFile *bf);
	RzList/*<RBinSection>*/* (*sections)(RBinFile *bf);
	R_BORROW RzList/*<RBinDwarfRow>*/* (*lines)(RBinFile *bf);
	RzList/*<RBinSymbol>*/* (*symbols)(RBinFile *bf);
	RzList/*<RBinImport>*/* (*imports)(RBinFile *bf);
	RzList/*<RBinString>*/* (*strings)(RBinFile *bf);
	RBinInfo/*<RBinInfo>*/* (*info)(RBinFile *bf);
	RzList/*<RBinField>*/* (*fields)(RBinFile *bf);
	RzList/*<char *>*/* (*libs)(RBinFile *bf);
	RzList/*<RBinReloc>*/* (*relocs)(RBinFile *bf);
	RzList/*<RBinTrycatch>*/* (*trycatch)(RBinFile *bf);
	RzList/*<RBinClass>*/* (*classes)(RBinFile *bf);
	RzList/*<RBinMem>*/* (*mem)(RBinFile *bf);
	RzList/*<RBinReloc>*/* (*patch_relocs)(RBin *bin);
	RzList/*<RBinMap>*/* (*maps)(RBinFile *bf);
	RzList/*<RBinFileHash>*/* (*hashes)(RBinFile *bf);
	void (*header)(RBinFile *bf);
	char* (*signature)(RBinFile *bf, bool json);
	int (*demangle_type)(const char *str);
	struct rz_bin_dbginfo_t *dbginfo;
	struct rz_bin_write_t *write;
	int (*get_offset)(RBinFile *bf, int type, int idx);
	char* (*get_name)(RBinFile *bf, int type, int idx, bool simplified);
	ut64 (*get_vaddr)(RBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr);
	RBuffer* (*create)(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt);
	char* (*demangle)(const char *str);
	char* (*regstate)(RBinFile *bf);
	int (*file_type)(RBinFile *bf);
	/* default value if not specified by user */
	int minstrlen;
	char strfilter;
	void *user;
} RBinPlugin;

typedef void (*RBinSymbollCallback)(RBinObject *obj, void *symbol);

typedef struct rz_bin_section_t {
	char *name;
	ut64 size;
	ut64 vsize;
	ut64 vaddr;
	ut64 paddr;
	ut32 perm;
	// per section platform info
	const char *arch;
	char *format;
	int bits;
	bool has_strings;
	bool add; // indicates when you want to add the section to io `S` command
	bool is_data;
	bool is_segment;
} RBinSection;

typedef struct rz_bin_class_t {
	char *name;
	// TODO: char *module;
	char *super;
	char *visibility_str; // XXX only used by java
	int index;
	ut64 addr;
	RzList *methods; // <RBinSymbol>
	RzList *fields; // <RBinField>
	// RzList *interfaces; // <char *>
	int visibility;
} RBinClass;

#define RBinSectionName rz_offsetof(RBinSection, name)
#define RBinSectionOffset rz_offsetof(RBinSection, offset)

#define REBASE_PADDR(o, l, type_t)\
	do { \
		RzListIter *_it;\
		type_t *_el;\
		rz_list_foreach ((l), _it, _el) { \
			_el->paddr += (o)->loadaddr;\
		}\
	} while (0)


typedef struct rz_bin_symbol_t {
	/* heap-allocated */
	char *name;
	char *dname;
	char *libname;
	char *classname;
	/* const-unique-strings */
	const char *forwarder;
	const char *bind;
	const char *type;
  	const char *rtype;
	bool is_imported;
	/* only used by java */
	const char *visibility_str;
	// ----------------
	//char descriptor[R_BIN_SIZEOF_STRINGS+1];
	ut64 vaddr;
	ut64 paddr;
	ut32 size;
	ut32 ordinal;
	ut32 visibility;
	int bits;
	/* see R_BIN_METH_* constants */
	ut64 method_flags;
	int dup_count;
} RBinSymbol;

typedef struct rz_bin_import_t {
	char *name;
	char *libname;
	const char *bind;
	const char *type;
	char *classname;
	char *descriptor;
	ut32 ordinal;
	ut32 visibility;
} RBinImport;

typedef struct rz_bin_reloc_t {
	ut8 type;
	ut8 additive;
	RBinSymbol *symbol;
	RBinImport *import;
	st64 addend;
	ut64 vaddr;
	ut64 paddr;
	ut32 visibility;
	/* is_ifunc: indirect function, `addend` points to a resolver function
	 * that returns the actual relocation value, e.g. chooses
	 * an optimized version depending on the CPU.
	 * cf. https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html
	 */
	bool is_ifunc;
	RBNode vrb;
} RBinReloc;

typedef struct rz_bin_string_t {
	// TODO: rename string->name (avoid colisions)
	char *string;
	ut64 vaddr;
	ut64 paddr;
	ut32 ordinal;
	ut32 size; // size of buffer containing the string in bytes
	ut32 length; // length of string in chars
	char type; // Ascii Wide cp850 utf8 base64 ...
} RBinString;

typedef struct rz_bin_field_t {
	ut64 vaddr;
	ut64 paddr;
	int size;
	int offset;
	ut32 visibility;
	char *name;
	char *type;
	char *comment;
	char *format;
	bool format_named; // whether format is the name of a format or a raw pf format string
	ut64 flags;
} RBinField;

RZ_API RBinField *rz_bin_field_new(ut64 paddr, ut64 vaddr, int size, const char *name, const char *comment, const char *format, bool format_named);
RZ_API void rz_bin_field_free(void *);

typedef struct rz_bin_mem_t {
	char *name;
	ut64 addr;
	int size;
	int perms;
	RzList *mirrors;		//for mirror access; stuff here should only create new maps not new fds
} RBinMem;

typedef struct rz_bin_map_t {
	ut64 addr;
	ut64 offset;
	int size;
	int perms;
	char *file;
} RBinMap;

typedef struct rz_bin_dbginfo_t {
	bool (*get_line)(RBinFile *arch, ut64 addr, char *file, int len, int *line);
} RBinDbgInfo;

typedef struct rz_bin_write_t {
	ut64 (*scn_resize)(RBinFile *bf, const char *name, ut64 size);
	bool (*scn_perms)(RBinFile *bf, const char *name, int perms);
	int (*rpath_del)(RBinFile *bf);
	bool (*entry)(RBinFile *bf, ut64 addr);
	bool (*addlib)(RBinFile *bf, const char *lib);
} RBinWrite;

// TODO: deprecate rz_bin_is_big_endian
// TODO: has_dbg_syms... maybe flags?

typedef int (*RBinGetOffset)(RBin *bin, int type, int idx);
typedef const char *(*RBinGetName)(RBin *bin, int type, int idx, bool sd);
typedef RzList *(*RBinGetSections)(RBin *bin);
typedef RBinSection *(*RBinGetSectionAt)(RBin *bin, ut64 addr);
typedef char *(*RBinDemangle)(RBinFile *bf, const char *def, const char *str, ut64 vaddr, bool libs);

typedef struct rz_bin_bind_t {
	RBin *bin;
	RBinGetOffset get_offset;
	RBinGetName get_name;
	RBinGetSections get_sections;
	RBinGetSectionAt get_vsect_at;
	RBinDemangle demangle;
	ut32 visibility;
} RBinBind;

R_IPI RBinSection *rz_bin_section_new(const char *name);
R_IPI void rz_bin_section_free(RBinSection *bs);
RZ_API void rz_bin_info_free(RBinInfo *rb);
RZ_API void rz_bin_import_free(void *_imp);
RZ_API void rz_bin_symbol_free(void *_sym);
RZ_API RBinSymbol *rz_bin_symbol_new(const char *name, ut64 paddr, ut64 vaddr);
RZ_API void rz_bin_string_free(void *_str);

#ifdef RZ_API

typedef struct rz_bin_options_t {
	const char *pluginname;
	ut64 baseaddr; // where the linker maps the binary in memory
	ut64 loadaddr; // starting physical address to read from the target file
	ut64 sz;
	int xtr_idx; // load Nth binary
	int rawstr;
	int fd;
	const char *filename;
} RBinOptions;

RZ_API RBinImport *rz_bin_import_clone(RBinImport *o);
RZ_API const char *rz_bin_symbol_name(RBinSymbol *s);
typedef void (*RBinSymbolCallback)(RBinObject *obj, RBinSymbol *symbol);

// options functions
RZ_API void rz_bin_options_init(RBinOptions *opt, int fd, ut64 baseaddr, ut64 loadaddr, int rawstr);
RZ_API void rz_bin_arch_options_init(RBinArchOptions *opt, const char *arch, int bits);

// open/close/reload functions
RZ_API RBin *rz_bin_new(void);
RZ_API void rz_bin_free(RBin *bin);
RZ_API bool rz_bin_open(RBin *bin, const char *file, RBinOptions *opt);
RZ_API bool rz_bin_open_io(RBin *bin, RBinOptions *opt);
RZ_API bool rz_bin_open_buf(RBin *bin, RBuffer *buf, RBinOptions *opt);
RZ_API bool rz_bin_reload(RBin *bin, ut32 bf_id, ut64 baseaddr);

// plugins/bind functions
RZ_API void rz_bin_bind(RBin *b, RBinBind *bnd);
RZ_API bool rz_bin_add(RBin *bin, RBinPlugin *foo);
RZ_API bool rz_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo);
RZ_API bool rz_bin_ldr_add(RBin *bin, RBinLdrPlugin *foo);
RZ_API void rz_bin_list(RBin *bin, int format);
RZ_API bool rz_bin_list_plugin(RBin *bin, const char *name, int json);
RZ_API RBinPlugin *rz_bin_get_binplugin_by_bytes(RBin *bin, const ut8 *bytes, ut64 sz);
RZ_API RBinPlugin *rz_bin_get_binplugin_by_buffer(RBin *bin, RBuffer *buf);
RZ_API void rz_bin_force_plugin(RBin *bin, const char *pname);

// get/set various bin information
RZ_API ut64 rz_bin_get_baddr(RBin *bin);
RZ_API ut64 rz_bin_file_get_baddr(RBinFile *bf);
RZ_API void rz_bin_set_user_ptr(RBin *bin, void *user);
RZ_API RBinInfo *rz_bin_get_info(RBin *bin);
RZ_API void rz_bin_set_baddr(RBin *bin, ut64 baddr);
RZ_API ut64 rz_bin_get_laddr(RBin *bin);
RZ_API ut64 rz_bin_get_size(RBin *bin);
RZ_API RBinAddr *rz_bin_get_sym(RBin *bin, int sym);
RZ_API RzList *rz_bin_raw_strings(RBinFile *a, int min);
RZ_API RzList *rz_bin_dump_strings(RBinFile *a, int min, int raw);

// use RBinFile instead
RZ_API RzList *rz_bin_get_entries(RBin *bin);
RZ_API RzList *rz_bin_get_fields(RBin *bin);
RZ_API RzList *rz_bin_get_imports(RBin *bin);
RZ_API RzList *rz_bin_get_libs(RBin *bin);
RZ_API RBNode *rz_bin_patch_relocs(RBin *bin);
RZ_API RzList *rz_bin_patch_relocs_list(RBin *bin);
RZ_API RBNode *rz_bin_get_relocs(RBin *bin);
RZ_API RzList *rz_bin_get_relocs_list(RBin *bin);
RZ_API RzList *rz_bin_get_sections(RBin *bin);
RZ_API RzList *rz_bin_get_classes(RBin *bin);
RZ_API RzList *rz_bin_get_strings(RBin *bin);
RZ_API RzList *rz_bin_file_get_trycatch(RBinFile *bf);
RZ_API RzList *rz_bin_get_symbols(RBin *bin);
RZ_API RzList *rz_bin_reset_strings(RBin *bin);
RZ_API int rz_bin_is_string(RBin *bin, ut64 va);
RZ_API int rz_bin_is_big_endian(RBin *bin);
RZ_API int rz_bin_is_static(RBin *bin);
RZ_API ut64 rz_bin_get_vaddr(RBin *bin, ut64 paddr, ut64 vaddr);
RZ_API ut64 rz_bin_file_get_vaddr(RBinFile *bf, ut64 paddr, ut64 vaddr);
RZ_API ut64 rz_bin_a2b(RBin *bin, ut64 addr);

RZ_API int rz_bin_load_languages(RBinFile *binfile);
RZ_API RBinFile *rz_bin_cur(RBin *bin);
RZ_API RBinObject *rz_bin_cur_object(RBin *bin);

// select/list binfiles functions
RZ_API bool rz_bin_select(RBin *bin, const char *arch, int bits, const char *name);
RZ_API bool rz_bin_select_bfid(RBin *bin, ut32 bf_id);
RZ_API bool rz_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name);
RZ_API void rz_bin_list_archs(RBin *bin, int mode);
RZ_API RBuffer *rz_bin_create(RBin *bin, const char *plugin_name, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt);
RZ_API RBuffer *rz_bin_package(RBin *bin, const char *type, const char *file, RzList *files);

RZ_API const char *rz_bin_string_type(int type);
RZ_API const char *rz_bin_entry_type_string(int etype);

RZ_API bool rz_bin_file_object_new_from_xtr_data(RBin *bin, RBinFile *bf, ut64 baseaddr, ut64 loadaddr, RBinXtrData *data);


// RBinFile lifecycle
// R_IPI RBinFile *rz_bin_file_new(RBin *bin, const char *file, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr);
RZ_API bool rz_bin_file_close(RBin *bin, int bd);
RZ_API void rz_bin_file_free(void /*RBinFile*/ *bf_);
// RBinFile.get
RZ_API RBinFile *rz_bin_file_at(RBin *bin, ut64 addr);
RZ_API RBinFile *rz_bin_file_find_by_object_id(RBin *bin, ut32 binobj_id);
RZ_API RzList *rz_bin_file_get_symbols(RBinFile *bf);
//
RZ_API ut64 rz_bin_file_get_vaddr(RBinFile *bf, ut64 paddr, ut64 vaddr);
// RBinFile.add
RZ_API RBinClass *rz_bin_file_add_class(RBinFile *binfile, const char *name, const char *super, int view);
RZ_API RBinSymbol *rz_bin_file_add_method(RBinFile *bf, const char *classname, const char *name, int nargs);
RZ_API RBinField *rz_bin_file_add_field(RBinFile *binfile, const char *classname, const char *name);
// RBinFile.find
RZ_API RBinFile *rz_bin_file_find_by_arch_bits(RBin *bin, const char *arch, int bits);
RZ_API RBinFile *rz_bin_file_find_by_id(RBin *bin, ut32 bin_id);
RZ_API RBinFile *rz_bin_file_find_by_fd(RBin *bin, ut32 bin_fd);
RZ_API RBinFile *rz_bin_file_find_by_name(RBin *bin, const char *name);

RZ_API bool rz_bin_file_set_cur_binfile(RBin *bin, RBinFile *bf);
RZ_API bool rz_bin_file_set_cur_by_name(RBin *bin, const char *name);
RZ_API bool rz_bin_file_deref(RBin *bin, RBinFile *a);
RZ_API bool rz_bin_file_set_cur_by_fd(RBin *bin, ut32 bin_fd);
RZ_API bool rz_bin_file_set_cur_by_id(RBin *bin, ut32 bin_id);
RZ_API bool rz_bin_file_set_cur_by_name(RBin *bin, const char *name);
RZ_API ut64 rz_bin_file_delete_all(RBin *bin);
RZ_API bool rz_bin_file_delete(RBin *bin, ut32 bin_id);
RZ_API RzList *rz_bin_file_compute_hashes(RBin *bin, ut64 limit);
RZ_API RzList *rz_bin_file_set_hashes(RBin *bin, RzList *new_hashes);
RZ_API RBinPlugin *rz_bin_file_cur_plugin(RBinFile *binfile);
RZ_API void rz_bin_file_hash_free(RBinFileHash *fhash);

// binobject functions
RZ_API int rz_bin_object_set_items(RBinFile *binfile, RBinObject *o);
RZ_API bool rz_bin_object_delete(RBin *bin, ut32 binfile_id);
RZ_API void rz_bin_mem_free(void *data);

// demangle functions
RZ_API char *rz_bin_demangle(RBinFile *binfile, const char *lang, const char *str, ut64 vaddr, bool libs);
RZ_API char *rz_bin_demangle_java(const char *str);
RZ_API char *rz_bin_demangle_cxx(RBinFile *binfile, const char *str, ut64 vaddr);
RZ_API char *rz_bin_demangle_msvc(const char *str);
RZ_API char *rz_bin_demangle_swift(const char *s, bool syscmd);
RZ_API char *rz_bin_demangle_objc(RBinFile *binfile, const char *sym);
RZ_API char *rz_bin_demangle_rust(RBinFile *binfile, const char *str, ut64 vaddr);
RZ_API int rz_bin_demangle_type(const char *str);
RZ_API void rz_bin_demangle_list(RBin *bin);
RZ_API char *rz_bin_demangle_plugin(RBin *bin, const char *name, const char *str);
RZ_API const char *rz_bin_get_meth_flag_string(ut64 flag, bool compact);

RZ_API RBinSection *rz_bin_get_section_at(RBinObject *o, ut64 off, int va);

/* dbginfo.c */
RZ_API bool rz_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line);
RZ_API char *rz_bin_addr2text(RBin *bin, ut64 addr, int origin);
RZ_API char *rz_bin_addr2fileline(RBin *bin, ut64 addr);
/* bin_write.c */
RZ_API bool rz_bin_wr_addlib(RBin *bin, const char *lib);
RZ_API ut64 rz_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size);
RZ_API bool rz_bin_wr_scn_perms(RBin *bin, const char *name, int perms);
RZ_API bool rz_bin_wr_rpath_del(RBin *bin);
RZ_API bool rz_bin_wr_entry(RBin *bin, ut64 addr);
RZ_API bool rz_bin_wr_output(RBin *bin, const char *filename);

RZ_API RzList *rz_bin_get_mem(RBin *bin);

/* filter.c */
RZ_API void rz_bin_load_filter(RBin *bin, ut64 rules);
RZ_API void rz_bin_filter_symbols(RBinFile *bf, RzList *list);
RZ_API void rz_bin_filter_sections(RBinFile *bf, RzList *list);
RZ_API char *rz_bin_filter_name(RBinFile *bf, Sdb *db, ut64 addr, char *name);
RZ_API void rz_bin_filter_sym(RBinFile *bf, HtPP *ht, ut64 vaddr, RBinSymbol *sym);
RZ_API bool rz_bin_strpurge(RBin *bin, const char *str, ut64 addr);
RZ_API bool rz_bin_string_filter(RBin *bin, const char *str, ut64 addr);

/* plugin pointers */
extern RBinPlugin rz_bin_plugin_any;
extern RBinPlugin rz_bin_plugin_fs;
extern RBinPlugin rz_bin_plugin_cgc;
extern RBinPlugin rz_bin_plugin_elf;
extern RBinPlugin rz_bin_plugin_elf64;
extern RBinPlugin rz_bin_plugin_p9;
extern RBinPlugin rz_bin_plugin_ne;
extern RBinPlugin rz_bin_plugin_le;
extern RBinPlugin rz_bin_plugin_pe;
extern RBinPlugin rz_bin_plugin_mz;
extern RBinPlugin rz_bin_plugin_pe64;
extern RBinPlugin rz_bin_plugin_pebble;
extern RBinPlugin rz_bin_plugin_bios;
extern RBinPlugin rz_bin_plugin_bf;
extern RBinPlugin rz_bin_plugin_te;
extern RBinPlugin rz_bin_plugin_symbols;
extern RBinPlugin rz_bin_plugin_mach0;
extern RBinPlugin rz_bin_plugin_mach064;
extern RBinPlugin rz_bin_plugin_mdmp;
extern RBinPlugin rz_bin_plugin_java;
extern RBinPlugin rz_bin_plugin_dex;
extern RBinPlugin rz_bin_plugin_coff;
extern RBinPlugin rz_bin_plugin_ningb;
extern RBinPlugin rz_bin_plugin_ningba;
extern RBinPlugin rz_bin_plugin_ninds;
extern RBinPlugin rz_bin_plugin_nin3ds;
extern RBinPlugin rz_bin_plugin_xbe;
extern RBinPlugin rz_bin_plugin_bflt;
extern RBinXtrPlugin rz_bin_xtr_plugin_xtr_fatmach0;
extern RBinXtrPlugin rz_bin_xtr_plugin_xtr_dyldcache;
extern RBinXtrPlugin rz_bin_xtr_plugin_xtr_pemixed;
extern RBinXtrPlugin rz_bin_xtr_plugin_xtr_sep64;
extern RBinLdrPlugin rz_bin_ldr_plugin_ldr_linux;
extern RBinPlugin rz_bin_plugin_zimg;
extern RBinPlugin rz_bin_plugin_omf;
extern RBinPlugin rz_bin_plugin_art;
extern RBinPlugin rz_bin_plugin_bootimg;
extern RBinPlugin rz_bin_plugin_dol;
extern RBinPlugin rz_bin_plugin_nes;
extern RBinPlugin rz_bin_plugin_qnx;
extern RBinPlugin rz_bin_plugin_mbn;
extern RBinPlugin rz_bin_plugin_smd;
extern RBinPlugin rz_bin_plugin_sms;
extern RBinPlugin rz_bin_plugin_psxexe;
extern RBinPlugin rz_bin_plugin_spc700;
extern RBinPlugin rz_bin_plugin_vsf;
extern RBinPlugin rz_bin_plugin_dyldcache;
extern RBinPlugin rz_bin_plugin_xnu_kernelcache;
extern RBinPlugin rz_bin_plugin_avr;
extern RBinPlugin rz_bin_plugin_menuet;
extern RBinPlugin rz_bin_plugin_wasm;
extern RBinPlugin rz_bin_plugin_nro;
extern RBinPlugin rz_bin_plugin_nso;
extern RBinPlugin rz_bin_plugin_sfc;
extern RBinPlugin rz_bin_plugin_z64;
extern RBinPlugin rz_bin_plugin_prg;
extern RBinPlugin rz_bin_plugin_dmp64;
extern RBinPlugin rz_bin_plugin_pyc;

#ifdef __cplusplus
}
#endif

#endif
#endif
