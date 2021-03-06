#ifndef RZ_BIN_H
#define RZ_BIN_H

#include <rz_util.h>
#include <rz_types.h>
#include <rz_io.h>
#include <rz_cons.h>
#include <rz_list.h>

typedef struct rz_bin_t RzBin;

#include <rz_bin_dwarf.h>
#include <rz_pdb.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_bin);

#define RZ_BIN_DBG_STRIPPED 0x01
#define RZ_BIN_DBG_STATIC   0x02
#define RZ_BIN_DBG_LINENUMS 0x04
#define RZ_BIN_DBG_SYMS     0x08
#define RZ_BIN_DBG_RELOCS   0x10

#define RZ_BIN_ENTRY_TYPE_PROGRAM 0
#define RZ_BIN_ENTRY_TYPE_MAIN    1
#define RZ_BIN_ENTRY_TYPE_INIT    2
#define RZ_BIN_ENTRY_TYPE_FINI    3
#define RZ_BIN_ENTRY_TYPE_TLS     4
#define RZ_BIN_ENTRY_TYPE_PREINIT 5

#define RZ_BIN_SIZEOF_STRINGS 512
#define RZ_BIN_MAX_ARCH       1024

#define RZ_BIN_REQ_ALL              UT64_MAX
#define RZ_BIN_REQ_UNK              0x000000
#define RZ_BIN_REQ_ENTRIES          0x000001
#define RZ_BIN_REQ_IMPORTS          0x000002
#define RZ_BIN_REQ_SYMBOLS          0x000004
#define RZ_BIN_REQ_SECTIONS         0x000008
#define RZ_BIN_REQ_INFO             0x000010
#define RZ_BIN_REQ_OPERATION        0x000020
#define RZ_BIN_REQ_HELP             0x000040
#define RZ_BIN_REQ_STRINGS          0x000080
#define RZ_BIN_REQ_FIELDS           0x000100
#define RZ_BIN_REQ_LIBS             0x000200
#define RZ_BIN_REQ_SRCLINE          0x000400
#define RZ_BIN_REQ_MAIN             0x000800
#define RZ_BIN_REQ_EXTRACT          0x001000
#define RZ_BIN_REQ_RELOCS           0x002000
#define RZ_BIN_REQ_LISTARCHS        0x004000
#define RZ_BIN_REQ_CREATE           0x008000
#define RZ_BIN_REQ_CLASSES          0x010000
#define RZ_BIN_REQ_DWARF            0x020000
#define RZ_BIN_REQ_SIZE             0x040000
#define RZ_BIN_REQ_PDB              0x080000
#define RZ_BIN_REQ_PDB_DWNLD        0x100000
#define RZ_BIN_REQ_DLOPEN           0x200000
#define RZ_BIN_REQ_EXPORTS          0x400000
#define RZ_BIN_REQ_VERSIONINFO      0x800000
#define RZ_BIN_REQ_PACKAGE          0x1000000
#define RZ_BIN_REQ_HEADER           0x2000000
#define RZ_BIN_REQ_LISTPLUGINS      0x4000000
#define RZ_BIN_REQ_RESOURCES        0x8000000
#define RZ_BIN_REQ_INITFINI         0x10000000
#define RZ_BIN_REQ_SEGMENTS         0x20000000
#define RZ_BIN_REQ_HASHES           0x40000000
#define RZ_BIN_REQ_SIGNATURE        0x80000000
#define RZ_BIN_REQ_TRYCATCH         0x100000000
#define RZ_BIN_REQ_SECTIONS_MAPPING 0x200000000

/* RzBinSymbol->method_flags : */
#define RZ_BIN_METH_CLASS                 0x0000000000000001L
#define RZ_BIN_METH_STATIC                0x0000000000000002L
#define RZ_BIN_METH_PUBLIC                0x0000000000000004L
#define RZ_BIN_METH_PRIVATE               0x0000000000000008L
#define RZ_BIN_METH_PROTECTED             0x0000000000000010L
#define RZ_BIN_METH_INTERNAL              0x0000000000000020L
#define RZ_BIN_METH_OPEN                  0x0000000000000040L
#define RZ_BIN_METH_FILEPRIVATE           0x0000000000000080L
#define RZ_BIN_METH_FINAL                 0x0000000000000100L
#define RZ_BIN_METH_VIRTUAL               0x0000000000000200L
#define RZ_BIN_METH_CONST                 0x0000000000000400L
#define RZ_BIN_METH_MUTATING              0x0000000000000800L
#define RZ_BIN_METH_ABSTRACT              0x0000000000001000L
#define RZ_BIN_METH_SYNCHRONIZED          0x0000000000002000L
#define RZ_BIN_METH_NATIVE                0x0000000000004000L
#define RZ_BIN_METH_BRIDGE                0x0000000000008000L
#define RZ_BIN_METH_VARARGS               0x0000000000010000L
#define RZ_BIN_METH_SYNTHETIC             0x0000000000020000L
#define RZ_BIN_METH_STRICT                0x0000000000040000L
#define RZ_BIN_METH_MIRANDA               0x0000000000080000L
#define RZ_BIN_METH_CONSTRUCTOR           0x0000000000100000L
#define RZ_BIN_METH_DECLARED_SYNCHRONIZED 0x0000000000200000L

#define RZ_BIN_BIND_LOCAL_STR   "LOCAL"
#define RZ_BIN_BIND_GLOBAL_STR  "GLOBAL"
#define RZ_BIN_BIND_WEAK_STR    "WEAK"
#define RZ_BIN_BIND_NUM_STR     "NUM"
#define RZ_BIN_BIND_LOOS_STR    "LOOS"
#define RZ_BIN_BIND_HIOS_STR    "HIOS"
#define RZ_BIN_BIND_LOPROC_STR  "LOPROC"
#define RZ_BIN_BIND_HIPROC_STR  "HIPROC"
#define RZ_BIN_BIND_UNKNOWN_STR "UNKNOWN"

#define RZ_BIN_TYPE_NOTYPE_STR      "NOTYPE"
#define RZ_BIN_TYPE_OBJECT_STR      "OBJ"
#define RZ_BIN_TYPE_FUNC_STR        "FUNC"
#define RZ_BIN_TYPE_METH_STR        "METH"
#define RZ_BIN_TYPE_STATIC_STR      "STATIC"
#define RZ_BIN_TYPE_SECTION_STR     "SECT"
#define RZ_BIN_TYPE_FILE_STR        "FILE"
#define RZ_BIN_TYPE_COMMON_STR      "COMMON"
#define RZ_BIN_TYPE_TLS_STR         "TLS"
#define RZ_BIN_TYPE_NUM_STR         "NUM"
#define RZ_BIN_TYPE_LOOS_STR        "LOOS"
#define RZ_BIN_TYPE_HIOS_STR        "HIOS"
#define RZ_BIN_TYPE_LOPROC_STR      "LOPROC"
#define RZ_BIN_TYPE_HIPROC_STR      "HIPROC"
#define RZ_BIN_TYPE_SPECIAL_SYM_STR "SPCL"
#define RZ_BIN_TYPE_UNKNOWN_STR     "UNK"

enum {
	RZ_BIN_SYM_ENTRY,
	RZ_BIN_SYM_INIT,
	RZ_BIN_SYM_MAIN,
	RZ_BIN_SYM_FINI,
	RZ_BIN_SYM_LAST
};

// name mangling types
// TODO: Rename to RZ_BIN_LANG_
enum {
	RZ_BIN_NM_NONE = 0,
	RZ_BIN_NM_JAVA = 1,
	RZ_BIN_NM_C = 1 << 1,
	RZ_BIN_NM_GO = 1 << 2,
	RZ_BIN_NM_CXX = 1 << 3,
	RZ_BIN_NM_OBJC = 1 << 4,
	RZ_BIN_NM_SWIFT = 1 << 5,
	RZ_BIN_NM_DLANG = 1 << 6,
	RZ_BIN_NM_MSVC = 1 << 7,
	RZ_BIN_NM_RUST = 1 << 8,
	RZ_BIN_NM_KOTLIN = 1 << 9,
	RZ_BIN_NM_BLOCKS = 1 << 31,
	RZ_BIN_NM_ANY = -1,
};

enum {
	RZ_STRING_TYPE_DETECT = '?',
	RZ_STRING_TYPE_ASCII = 'a',
	RZ_STRING_TYPE_UTF8 = 'u',
	RZ_STRING_TYPE_WIDE = 'w', // utf16 / widechar string
	RZ_STRING_TYPE_WIDE32 = 'W', // utf32
	RZ_STRING_TYPE_BASE64 = 'b',
};

enum {
	RZ_BIN_CLASS_PRIVATE,
	RZ_BIN_CLASS_PUBLIC,
	RZ_BIN_CLASS_FRIENDLY,
	RZ_BIN_CLASS_PROTECTED,
};

enum {
	RZ_BIN_RELOC_8 = 8,
	RZ_BIN_RELOC_16 = 16,
	RZ_BIN_RELOC_32 = 32,
	RZ_BIN_RELOC_64 = 64
};

enum {
	RZ_BIN_TYPE_DEFAULT = 0,
	RZ_BIN_TYPE_CORE = 1
};

typedef struct rz_bin_addr_t {
	ut64 vaddr;
	ut64 paddr;
	ut64 hvaddr;
	ut64 hpaddr;
	int type;
	int bits;
} RzBinAddr;

typedef struct rz_bin_hash_t {
	const char *type;
	ut64 addr;
	int len;
	ut64 from;
	ut64 to;
	ut8 buf[32];
	const char *cmd;
} RzBinHash;

typedef struct rz_bin_file_hash_t {
	const char *type;
	const char *hex;
} RzBinFileHash;

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
	RzList /*<RzBinFileHash>*/ *file_hashes;
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
	RzBinHash sum[3];
	ut64 baddr;
	char *intrp;
	char *compiler;
} RzBinInfo;

typedef struct rz_bin_object_t {
	ut64 baddr;
	st64 baddr_shift;
	ut64 loadaddr;
	ut64 boffset;
	ut64 size;
	ut64 obj_size;
	RzList /*<RzBinSection>*/ *sections;
	RzList /*<RzBinImport>*/ *imports;
	RzList /*<RzBinSymbol>*/ *symbols;
	RzList /*<??>*/ *entries;
	RzList /*<??>*/ *fields;
	RzList /*<??>*/ *libs;
	RBNode /*<RzBinReloc>*/ *relocs;
	RzList /*<??>*/ *strings;
	RzList /*<RzBinClass>*/ *classes;
	HtPP *classes_ht;
	HtPP *methods_ht;
	RzList /*<RzBinDwarfRow>*/ *lines;
	HtUP *strings_db;
	RzList /*<??>*/ *mem; //RzBinMem maybe?
	RzList /*<BinMap*/ *maps;
	char *regstate;
	RzBinInfo *info;
	RzBinAddr *binsym[RZ_BIN_SYM_LAST];
	struct rz_bin_plugin_t *plugin;
	int lang;
	Sdb *kv;
	HtUP *addrzklassmethod;
	void *bin_obj; // internal pointer used by formats
} RzBinObject;

// XXX: RbinFile may hold more than one RzBinObject
/// XX curplugin == o->plugin
typedef struct rz_bin_file_t {
	char *file;
	int fd;
	int size;
	int rawstr;
	int strmode;
	ut32 id;
	RzBuffer *buf;
	ut64 offset;
	RzBinObject *o;
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
} RzBinFile;

typedef struct rz_bin_file_options_t {
	int rawstr;
	ut64 baddr; // base address
	ut64 laddr; // load address
	ut64 paddr; // offset
	const char *plugname; // force a plugin? why do i need this?
	// const char *xtrname;
} RzBinFileOptions;

struct rz_bin_t {
	const char *file;
	RzBinFile *cur; // TODO: deprecate
	int narch;
	void *user;
	/* preconfigured values */
	int debase64;
	int minstrlen;
	int maxstrlen; //< <= 0 means no limit
	ut64 maxstrbuf;
	int rawstr;
	Sdb *sdb;
	RzIDStorage *ids;
	RzList /*<RzBinPlugin>*/ *plugins;
	RzList /*<RzBinXtrPlugin>*/ *binxtrs;
	RzList /*<RzBinLdrPlugin>*/ *binldrs;
	RzList /*<RzBinFile>*/ *binfiles;
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
	RzStrConstPool constpool;
	bool is_reloc_patched; // used to indicate whether relocations were patched or not
};

typedef struct rz_bin_xtr_metadata_t {
	char *arch;
	int bits;
	char *libname;
	char *machine;
	char *type;
	const char *xtr_type;
} RzBinXtrMetadata;

typedef int (*FREE_XTR)(void *xtr_obj);
typedef struct rz_bin_xtr_extract_t {
	char *file;
	RzBuffer *buf;
	ut64 size;
	ut64 offset;
	ut64 baddr;
	ut64 laddr;
	int file_count;
	int loaded;
	RzBinXtrMetadata *metadata;
} RzBinXtrData;

RZ_API RzBinXtrData *rz_bin_xtrdata_new(RzBuffer *buf, ut64 offset, ut64 size, ut32 file_count, RzBinXtrMetadata *metadata);
RZ_API void rz_bin_xtrdata_free(void /*RzBinXtrData*/ *data);

typedef struct rz_bin_xtr_plugin_t {
	char *name;
	char *desc;
	char *license;
	int (*init)(void *user);
	int (*fini)(void *user);
	bool (*check_buffer)(RzBuffer *b);

	RzBinXtrData *(*extract_from_bytes)(RzBin *bin, const ut8 *buf, ut64 size, int idx);
	RzBinXtrData *(*extract_from_buffer)(RzBin *bin, RzBuffer *buf, int idx);
	RzList *(*extractall_from_bytes)(RzBin *bin, const ut8 *buf, ut64 size);
	RzList *(*extractall_from_buffer)(RzBin *bin, RzBuffer *buf);
	RzBinXtrData *(*extract)(RzBin *bin, int idx);
	RzList *(*extractall)(RzBin *bin);

	bool (*load)(RzBin *bin);
	int (*size)(RzBin *bin);
	void (*destroy)(RzBin *bin);
	void (*free_xtr)(void *xtr_obj);
} RzBinXtrPlugin;

typedef struct rz_bin_ldr_plugin_t {
	char *name;
	char *desc;
	char *license;
	int (*init)(void *user);
	int (*fini)(void *user);
	bool (*load)(RzBin *bin);
} RzBinLdrPlugin;

typedef struct rz_bin_arch_options_t {
	const char *arch;
	int bits;
} RzBinArchOptions;

typedef struct rz_bin_trycatch_t {
	ut64 source;
	ut64 from;
	ut64 to;
	ut64 handler;
	ut64 filter;
	// TODO: add type/name of exception
} RzBinTrycatch;

RZ_API RzBinTrycatch *rz_bin_trycatch_new(ut64 source, ut64 from, ut64 to, ut64 handler, ut64 filter);
RZ_API void rz_bin_trycatch_free(RzBinTrycatch *tc);

typedef struct rz_bin_plugin_t {
	char *name;
	char *desc;
	char *author;
	char *version;
	char *license;
	int (*init)(void *user);
	int (*fini)(void *user);
	Sdb *(*get_sdb)(RzBinFile *obj);
	bool (*load_buffer)(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb);
	ut64 (*size)(RzBinFile *bin); // return ut64 maybe? meh
	void (*destroy)(RzBinFile *bf);
	bool (*check_bytes)(const ut8 *buf, ut64 length);
	bool (*check_buffer)(RzBuffer *buf);
	ut64 (*baddr)(RzBinFile *bf);
	ut64 (*boffset)(RzBinFile *bf);
	RzBinAddr *(*binsym)(RzBinFile *bf, int num);
	RzList /*<RzBinAddr>*/ *(*entries)(RzBinFile *bf);
	RzList /*<RzBinSection>*/ *(*sections)(RzBinFile *bf);
	RZ_BORROW RzList /*<RzBinDwarfRow>*/ *(*lines)(RzBinFile *bf);
	RzList /*<RzBinSymbol>*/ *(*symbols)(RzBinFile *bf);
	RzList /*<RzBinImport>*/ *(*imports)(RzBinFile *bf);
	RzList /*<RzBinString>*/ *(*strings)(RzBinFile *bf);
	RzBinInfo /*<RzBinInfo>*/ *(*info)(RzBinFile *bf);
	RzList /*<RzBinField>*/ *(*fields)(RzBinFile *bf);
	RzList /*<char *>*/ *(*libs)(RzBinFile *bf);
	RzList /*<RzBinReloc>*/ *(*relocs)(RzBinFile *bf);
	RzList /*<RzBinTrycatch>*/ *(*trycatch)(RzBinFile *bf);
	RzList /*<RzBinClass>*/ *(*classes)(RzBinFile *bf);
	RzList /*<RzBinMem>*/ *(*mem)(RzBinFile *bf);
	RzList /*<RzBinReloc>*/ *(*patch_relocs)(RzBinFile *bf);
	RzList /*<RzBinMap>*/ *(*maps)(RzBinFile *bf);
	RzList /*<RzBinFileHash>*/ *(*hashes)(RzBinFile *bf);
	void (*header)(RzBinFile *bf);
	char *(*signature)(RzBinFile *bf, bool json);
	int (*demangle_type)(const char *str);
	struct rz_bin_dbginfo_t *dbginfo;
	struct rz_bin_write_t *write;
	int (*get_offset)(RzBinFile *bf, int type, int idx);
	char *(*get_name)(RzBinFile *bf, int type, int idx, bool simplified);
	ut64 (*get_vaddr)(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr);
	RzBuffer *(*create)(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt);
	char *(*demangle)(const char *str);
	char *(*regstate)(RzBinFile *bf);
	int (*file_type)(RzBinFile *bf);
	/* default value if not specified by user */
	int minstrlen;
	char strfilter;
	void *user;
} RzBinPlugin;

typedef void (*RzBinSymbollCallback)(RzBinObject *obj, void *symbol);

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
} RzBinSection;

typedef struct rz_bin_class_t {
	char *name;
	// TODO: char *module;
	char *super;
	char *visibility_str; // XXX only used by java
	int index;
	ut64 addr;
	RzList *methods; // <RzBinSymbol>
	RzList *fields; // <RzBinField>
	// RzList *interfaces; // <char *>
	int visibility;
} RzBinClass;

#define RzBinSectionName   rz_offsetof(RzBinSection, name)
#define RzBinSectionOffset rz_offsetof(RzBinSection, offset)

#define REBASE_PADDR(o, l, type_t) \
	do { \
		RzListIter *_it; \
		type_t *_el; \
		rz_list_foreach ((l), _it, _el) { \
			_el->paddr += (o)->loadaddr; \
		} \
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
	//char descriptor[RZ_BIN_SIZEOF_STRINGS+1];
	ut64 vaddr;
	ut64 paddr;
	ut32 size;
	ut32 ordinal;
	ut32 visibility;
	int bits;
	/* see RZ_BIN_METH_* constants */
	ut64 method_flags;
	int dup_count;
} RzBinSymbol;

typedef struct rz_bin_import_t {
	char *name;
	char *libname;
	const char *bind;
	const char *type;
	char *classname;
	char *descriptor;
	ut32 ordinal;
	ut32 visibility;
} RzBinImport;

typedef struct rz_bin_reloc_t {
	ut8 type;
	ut8 additive;
	RzBinSymbol *symbol;
	RzBinImport *import;
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
} RzBinReloc;

typedef struct rz_bin_string_t {
	// TODO: rename string->name (avoid colisions)
	char *string;
	ut64 vaddr;
	ut64 paddr;
	ut32 ordinal;
	ut32 size; // size of buffer containing the string in bytes
	ut32 length; // length of string in chars
	char type; // Ascii Wide cp850 utf8 base64 ...
} RzBinString;

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
} RzBinField;

RZ_API RzBinField *rz_bin_field_new(ut64 paddr, ut64 vaddr, int size, const char *name, const char *comment, const char *format, bool format_named);
RZ_API void rz_bin_field_free(void *);

typedef struct rz_bin_mem_t {
	char *name;
	ut64 addr;
	int size;
	int perms;
	RzList *mirrors; //for mirror access; stuff here should only create new maps not new fds
} RzBinMem;

typedef struct rz_bin_map_t {
	ut64 addr;
	ut64 offset;
	int size;
	int perms;
	char *file;
} RzBinMap;

typedef struct rz_bin_dbginfo_t {
	bool (*get_line)(RzBinFile *arch, ut64 addr, char *file, int len, int *line);
} RzBinDbgInfo;

typedef struct rz_bin_write_t {
	ut64 (*scn_resize)(RzBinFile *bf, const char *name, ut64 size);
	bool (*scn_perms)(RzBinFile *bf, const char *name, int perms);
	int (*rpath_del)(RzBinFile *bf);
	bool (*entry)(RzBinFile *bf, ut64 addr);
	bool (*addlib)(RzBinFile *bf, const char *lib);
} RzBinWrite;

// TODO: deprecate rz_bin_is_big_endian
// TODO: has_dbg_syms... maybe flags?

typedef int (*RzBinGetOffset)(RzBin *bin, int type, int idx);
typedef const char *(*RzBinGetName)(RzBin *bin, int type, int idx, bool sd);
typedef RzList *(*RzBinGetSections)(RzBin *bin);
typedef RzBinSection *(*RzBinGetSectionAt)(RzBin *bin, ut64 addr);
typedef char *(*RzBinDemangle)(RzBinFile *bf, const char *def, const char *str, ut64 vaddr, bool libs);

typedef struct rz_bin_bind_t {
	RzBin *bin;
	RzBinGetOffset get_offset;
	RzBinGetName get_name;
	RzBinGetSections get_sections;
	RzBinGetSectionAt get_vsect_at;
	RzBinDemangle demangle;
	ut32 visibility;
} RzBinBind;

RZ_IPI RzBinSection *rz_bin_section_new(const char *name);
RZ_IPI void rz_bin_section_free(RzBinSection *bs);
RZ_API void rz_bin_info_free(RzBinInfo *rb);
RZ_API void rz_bin_import_free(void *_imp);
RZ_API void rz_bin_symbol_free(void *_sym);
RZ_API RzBinSymbol *rz_bin_symbol_new(const char *name, ut64 paddr, ut64 vaddr);
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
} RzBinOptions;

RZ_API RzBinImport *rz_bin_import_clone(RzBinImport *o);
RZ_API const char *rz_bin_symbol_name(RzBinSymbol *s);
typedef void (*RzBinSymbolCallback)(RzBinObject *obj, RzBinSymbol *symbol);

// options functions
RZ_API void rz_bin_options_init(RzBinOptions *opt, int fd, ut64 baseaddr, ut64 loadaddr, int rawstr);
RZ_API void rz_bin_arch_options_init(RzBinArchOptions *opt, const char *arch, int bits);

// open/close/reload functions
RZ_API RzBin *rz_bin_new(void);
RZ_API void rz_bin_free(RzBin *bin);
RZ_API bool rz_bin_open(RzBin *bin, const char *file, RzBinOptions *opt);
RZ_API bool rz_bin_open_io(RzBin *bin, RzBinOptions *opt);
RZ_API bool rz_bin_open_buf(RzBin *bin, RzBuffer *buf, RzBinOptions *opt);
RZ_API bool rz_bin_reload(RzBin *bin, ut32 bf_id, ut64 baseaddr);

// plugins/bind functions
RZ_API void rz_bin_bind(RzBin *b, RzBinBind *bnd);
RZ_API bool rz_bin_add(RzBin *bin, RzBinPlugin *foo);
RZ_API bool rz_bin_xtr_add(RzBin *bin, RzBinXtrPlugin *foo);
RZ_API bool rz_bin_ldr_add(RzBin *bin, RzBinLdrPlugin *foo);
RZ_API void rz_bin_list(RzBin *bin, PJ *pj, int format);
RZ_API bool rz_bin_list_plugin(RzBin *bin, const char *name, PJ *pj, int json);
RZ_API RzBinPlugin *rz_bin_get_binplugin_by_bytes(RzBin *bin, const ut8 *bytes, ut64 sz);
RZ_API RzBinPlugin *rz_bin_get_binplugin_by_buffer(RzBin *bin, RzBuffer *buf);
RZ_API void rz_bin_force_plugin(RzBin *bin, const char *pname);

// get/set various bin information
RZ_API ut64 rz_bin_get_baddr(RzBin *bin);
RZ_API ut64 rz_bin_file_get_baddr(RzBinFile *bf);
RZ_API void rz_bin_set_user_ptr(RzBin *bin, void *user);
RZ_API RzBinInfo *rz_bin_get_info(RzBin *bin);
RZ_API void rz_bin_set_baddr(RzBin *bin, ut64 baddr);
RZ_API ut64 rz_bin_get_laddr(RzBin *bin);
RZ_API ut64 rz_bin_get_size(RzBin *bin);
RZ_API RzBinAddr *rz_bin_get_sym(RzBin *bin, int sym);
RZ_API RzList *rz_bin_raw_strings(RzBinFile *a, int min);
RZ_API RzList *rz_bin_dump_strings(RzBinFile *a, int min, int raw);

// use RzBinFile instead
RZ_API RZ_DEPRECATE RzList *rz_bin_get_entries(RzBin *bin);
RZ_API RZ_DEPRECATE RzList *rz_bin_get_fields(RzBin *bin);
RZ_API RZ_DEPRECATE RzList *rz_bin_get_imports(RzBin *bin);
RZ_API RZ_DEPRECATE RzList *rz_bin_get_libs(RzBin *bin);
RZ_API RZ_DEPRECATE RBNode *rz_bin_patch_relocs(RzBin *bin);
RZ_API RZ_DEPRECATE RzList *rz_bin_patch_relocs_list(RzBin *bin);
RZ_API RZ_DEPRECATE RBNode *rz_bin_get_relocs(RzBin *bin);
RZ_API RZ_DEPRECATE RzList *rz_bin_get_relocs_list(RzBin *bin);
RZ_API RZ_DEPRECATE RzList *rz_bin_get_sections(RzBin *bin);
RZ_API RZ_DEPRECATE RzList *rz_bin_get_classes(RzBin *bin);
RZ_API RZ_DEPRECATE RzList *rz_bin_get_strings(RzBin *bin);
RZ_API RzList *rz_bin_file_get_trycatch(RzBinFile *bf);
RZ_API RZ_DEPRECATE RzList *rz_bin_get_symbols(RzBin *bin);
RZ_API RZ_DEPRECATE RzList *rz_bin_reset_strings(RzBin *bin);
RZ_API RZ_DEPRECATE int rz_bin_is_string(RzBin *bin, ut64 va);
RZ_API RZ_DEPRECATE int rz_bin_is_big_endian(RzBin *bin);
RZ_API RZ_DEPRECATE int rz_bin_is_static(RzBin *bin);
RZ_API RZ_DEPRECATE ut64 rz_bin_get_vaddr(RzBin *bin, ut64 paddr, ut64 vaddr);
RZ_API ut64 rz_bin_file_get_vaddr(RzBinFile *bf, ut64 paddr, ut64 vaddr);

RZ_API int rz_bin_load_languages(RzBinFile *binfile);
RZ_API RzBinFile *rz_bin_cur(RzBin *bin);
RZ_API RzBinObject *rz_bin_cur_object(RzBin *bin);

// select/list binfiles functions
RZ_API bool rz_bin_select(RzBin *bin, const char *arch, int bits, const char *name);
RZ_API bool rz_bin_select_bfid(RzBin *bin, ut32 bf_id);
RZ_API bool rz_bin_use_arch(RzBin *bin, const char *arch, int bits, const char *name);
RZ_API void rz_bin_list_archs(RzBin *bin, PJ *pj, int mode);
RZ_API RzBuffer *rz_bin_create(RzBin *bin, const char *plugin_name, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt);
RZ_API RzBuffer *rz_bin_package(RzBin *bin, const char *type, const char *file, RzList *files);

RZ_API const char *rz_bin_string_type(int type);
RZ_API const char *rz_bin_entry_type_string(int etype);

RZ_API bool rz_bin_file_object_new_from_xtr_data(RzBin *bin, RzBinFile *bf, ut64 baseaddr, ut64 loadaddr, RzBinXtrData *data);

// RzBinFile lifecycle
// RZ_IPI RzBinFile *rz_bin_file_new(RzBin *bin, const char *file, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr);
RZ_API bool rz_bin_file_close(RzBin *bin, int bd);
RZ_API void rz_bin_file_free(void /*RzBinFile*/ *bf_);
// RzBinFile.get
RZ_API RzBinFile *rz_bin_file_at(RzBin *bin, ut64 addr);
RZ_API RzBinFile *rz_bin_file_find_by_object_id(RzBin *bin, ut32 binobj_id);
RZ_API RzList *rz_bin_file_get_symbols(RzBinFile *bf);
//
RZ_API ut64 rz_bin_file_get_vaddr(RzBinFile *bf, ut64 paddr, ut64 vaddr);
// RzBinFile.add
RZ_API RzBinClass *rz_bin_file_add_class(RzBinFile *binfile, const char *name, const char *super, int view);
RZ_API RzBinSymbol *rz_bin_file_add_method(RzBinFile *bf, const char *classname, const char *name, int nargs);
RZ_API RzBinField *rz_bin_file_add_field(RzBinFile *binfile, const char *classname, const char *name);
// RzBinFile.find
RZ_API RzBinFile *rz_bin_file_find_by_arch_bits(RzBin *bin, const char *arch, int bits);
RZ_API RzBinFile *rz_bin_file_find_by_id(RzBin *bin, ut32 bin_id);
RZ_API RzBinFile *rz_bin_file_find_by_fd(RzBin *bin, ut32 bin_fd);
RZ_API RzBinFile *rz_bin_file_find_by_name(RzBin *bin, const char *name);

RZ_API bool rz_bin_file_set_cur_binfile(RzBin *bin, RzBinFile *bf);
RZ_API bool rz_bin_file_set_cur_by_name(RzBin *bin, const char *name);
RZ_API bool rz_bin_file_deref(RzBin *bin, RzBinFile *a);
RZ_API bool rz_bin_file_set_cur_by_fd(RzBin *bin, ut32 bin_fd);
RZ_API bool rz_bin_file_set_cur_by_id(RzBin *bin, ut32 bin_id);
RZ_API bool rz_bin_file_set_cur_by_name(RzBin *bin, const char *name);
RZ_API ut64 rz_bin_file_delete_all(RzBin *bin);
RZ_API bool rz_bin_file_delete(RzBin *bin, ut32 bin_id);
RZ_API RzList *rz_bin_file_compute_hashes(RzBin *bin, ut64 limit);
RZ_API RzList *rz_bin_file_set_hashes(RzBin *bin, RzList *new_hashes);
RZ_API RzBinPlugin *rz_bin_file_cur_plugin(RzBinFile *binfile);
RZ_API void rz_bin_file_hash_free(RzBinFileHash *fhash);

// binobject functions
RZ_API int rz_bin_object_set_items(RzBinFile *binfile, RzBinObject *o);
RZ_API bool rz_bin_object_delete(RzBin *bin, ut32 binfile_id);
RZ_API ut64 rz_bin_object_addr_with_base(RzBinObject *o, ut64 addr);
RZ_API void rz_bin_mem_free(void *data);

// demangle functions
RZ_API char *rz_bin_demangle(RzBinFile *binfile, const char *lang, const char *str, ut64 vaddr, bool libs);
RZ_API char *rz_bin_demangle_java(const char *str);
RZ_API char *rz_bin_demangle_cxx(RzBinFile *binfile, const char *str, ut64 vaddr);
RZ_API char *rz_bin_demangle_msvc(const char *str);
RZ_API char *rz_bin_demangle_swift(const char *s, bool syscmd);
RZ_API char *rz_bin_demangle_objc(RzBinFile *binfile, const char *sym);
RZ_API char *rz_bin_demangle_rust(RzBinFile *binfile, const char *str, ut64 vaddr);
RZ_API int rz_bin_demangle_type(const char *str);
RZ_API void rz_bin_demangle_list(RzBin *bin);
RZ_API char *rz_bin_demangle_plugin(RzBin *bin, const char *name, const char *str);
RZ_API const char *rz_bin_get_meth_flag_string(ut64 flag, bool compact);

RZ_API RzBinSection *rz_bin_get_section_at(RzBinObject *o, ut64 off, int va);

/* dbginfo.c */
RZ_API bool rz_bin_addr2line(RzBin *bin, ut64 addr, char *file, int len, int *line);
RZ_API char *rz_bin_addr2text(RzBin *bin, ut64 addr, int origin);
RZ_API char *rz_bin_addr2fileline(RzBin *bin, ut64 addr);
/* bin_write.c */
RZ_API bool rz_bin_wr_addlib(RzBin *bin, const char *lib);
RZ_API ut64 rz_bin_wr_scn_resize(RzBin *bin, const char *name, ut64 size);
RZ_API bool rz_bin_wr_scn_perms(RzBin *bin, const char *name, int perms);
RZ_API bool rz_bin_wr_rpath_del(RzBin *bin);
RZ_API bool rz_bin_wr_entry(RzBin *bin, ut64 addr);
RZ_API bool rz_bin_wr_output(RzBin *bin, const char *filename);

RZ_API RzList *rz_bin_get_mem(RzBin *bin);

/* filter.c */
RZ_API void rz_bin_load_filter(RzBin *bin, ut64 rules);
RZ_API void rz_bin_filter_symbols(RzBinFile *bf, RzList *list);
RZ_API void rz_bin_filter_sections(RzBinFile *bf, RzList *list);
RZ_API char *rz_bin_filter_name(RzBinFile *bf, Sdb *db, ut64 addr, char *name);
RZ_API void rz_bin_filter_sym(RzBinFile *bf, HtPP *ht, ut64 vaddr, RzBinSymbol *sym);
RZ_API bool rz_bin_strpurge(RzBin *bin, const char *str, ut64 addr);
RZ_API bool rz_bin_string_filter(RzBin *bin, const char *str, int len, ut64 addr);

/* plugin pointers */
extern RzBinPlugin rz_bin_plugin_any;
extern RzBinPlugin rz_bin_plugin_fs;
extern RzBinPlugin rz_bin_plugin_cgc;
extern RzBinPlugin rz_bin_plugin_elf;
extern RzBinPlugin rz_bin_plugin_elf64;
extern RzBinPlugin rz_bin_plugin_p9;
extern RzBinPlugin rz_bin_plugin_ne;
extern RzBinPlugin rz_bin_plugin_le;
extern RzBinPlugin rz_bin_plugin_pe;
extern RzBinPlugin rz_bin_plugin_mz;
extern RzBinPlugin rz_bin_plugin_pe64;
extern RzBinPlugin rz_bin_plugin_pebble;
extern RzBinPlugin rz_bin_plugin_bios;
extern RzBinPlugin rz_bin_plugin_bf;
extern RzBinPlugin rz_bin_plugin_te;
extern RzBinPlugin rz_bin_plugin_symbols;
extern RzBinPlugin rz_bin_plugin_mach0;
extern RzBinPlugin rz_bin_plugin_mach064;
extern RzBinPlugin rz_bin_plugin_mdmp;
extern RzBinPlugin rz_bin_plugin_java;
extern RzBinPlugin rz_bin_plugin_dex;
extern RzBinPlugin rz_bin_plugin_coff;
extern RzBinPlugin rz_bin_plugin_ningb;
extern RzBinPlugin rz_bin_plugin_ningba;
extern RzBinPlugin rz_bin_plugin_ninds;
extern RzBinPlugin rz_bin_plugin_nin3ds;
extern RzBinPlugin rz_bin_plugin_xbe;
extern RzBinPlugin rz_bin_plugin_bflt;
extern RzBinXtrPlugin rz_bin_xtr_plugin_xtr_fatmach0;
extern RzBinXtrPlugin rz_bin_xtr_plugin_xtr_dyldcache;
extern RzBinXtrPlugin rz_bin_xtr_plugin_xtr_pemixed;
extern RzBinXtrPlugin rz_bin_xtr_plugin_xtr_sep64;
extern RzBinLdrPlugin rz_bin_ldr_plugin_ldr_linux;
extern RzBinPlugin rz_bin_plugin_zimg;
extern RzBinPlugin rz_bin_plugin_omf;
extern RzBinPlugin rz_bin_plugin_art;
extern RzBinPlugin rz_bin_plugin_bootimg;
extern RzBinPlugin rz_bin_plugin_dol;
extern RzBinPlugin rz_bin_plugin_nes;
extern RzBinPlugin rz_bin_plugin_qnx;
extern RzBinPlugin rz_bin_plugin_mbn;
extern RzBinPlugin rz_bin_plugin_smd;
extern RzBinPlugin rz_bin_plugin_sms;
extern RzBinPlugin rz_bin_plugin_psxexe;
extern RzBinPlugin rz_bin_plugin_spc700;
extern RzBinPlugin rz_bin_plugin_vsf;
extern RzBinPlugin rz_bin_plugin_dyldcache;
extern RzBinPlugin rz_bin_plugin_xnu_kernelcache;
extern RzBinPlugin rz_bin_plugin_avr;
extern RzBinPlugin rz_bin_plugin_menuet;
extern RzBinPlugin rz_bin_plugin_wasm;
extern RzBinPlugin rz_bin_plugin_nro;
extern RzBinPlugin rz_bin_plugin_nso;
extern RzBinPlugin rz_bin_plugin_sfc;
extern RzBinPlugin rz_bin_plugin_z64;
extern RzBinPlugin rz_bin_plugin_prg;
extern RzBinPlugin rz_bin_plugin_dmp64;
extern RzBinPlugin rz_bin_plugin_pyc;

#ifdef __cplusplus
}
#endif

#endif
#endif
