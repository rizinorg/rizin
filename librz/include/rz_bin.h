#ifndef RZ_BIN_H
#define RZ_BIN_H

#include <rz_util.h>
#include <rz_types.h>
#include <rz_io.h>
#include <rz_cons.h>
#include <rz_list.h>
#include <ht_pu.h>
#include <rz_demangler.h>
#include <rz_hash.h>

typedef struct rz_bin_t RzBin;
typedef struct rz_bin_file_t RzBinFile;
typedef struct rz_bin_source_line_info_t RzBinSourceLineInfo;
typedef struct rz_bin_reloc_storage_t RzBinRelocStorage;

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
#define RZ_BIN_REQ_CLASSES_SOURCES  0x400000000
#define RZ_BIN_REQ_BASEFIND         0x800000000

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
#define RZ_BIN_BIND_IMPORT_STR  "IMPORT"
#define RZ_BIN_BIND_UNKNOWN_STR "UNKNOWN"

#define RZ_BIN_TYPE_NOTYPE_STR      "NOTYPE"
#define RZ_BIN_TYPE_OBJECT_STR      "OBJ"
#define RZ_BIN_TYPE_FUNC_STR        "FUNC"
#define RZ_BIN_TYPE_FIELD_STR       "FIELD"
#define RZ_BIN_TYPE_IFACE_STR       "IFACE"
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

typedef enum {
	RZ_BIN_SPECIAL_SYMBOL_ENTRY,
	RZ_BIN_SPECIAL_SYMBOL_INIT,
	RZ_BIN_SPECIAL_SYMBOL_MAIN,
	RZ_BIN_SPECIAL_SYMBOL_FINI,
	RZ_BIN_SPECIAL_SYMBOL_LAST
} RzBinSpecialSymbol;

// name mangling types
typedef enum {
	RZ_BIN_LANGUAGE_UNKNOWN = 0,
	RZ_BIN_LANGUAGE_JAVA = 1,
	RZ_BIN_LANGUAGE_C = 1 << 1,
	RZ_BIN_LANGUAGE_GO = 1 << 2,
	RZ_BIN_LANGUAGE_CXX = 1 << 3,
	RZ_BIN_LANGUAGE_OBJC = 1 << 4,
	RZ_BIN_LANGUAGE_SWIFT = 1 << 5,
	RZ_BIN_LANGUAGE_DLANG = 1 << 6,
	RZ_BIN_LANGUAGE_MSVC = 1 << 7,
	RZ_BIN_LANGUAGE_RUST = 1 << 8,
	RZ_BIN_LANGUAGE_KOTLIN = 1 << 9,
	RZ_BIN_LANGUAGE_GROOVY = 1 << 10,
	RZ_BIN_LANGUAGE_DART = 1 << 11,
	RZ_BIN_LANGUAGE_PASCAL = 1 << 12,
	RZ_BIN_LANGUAGE_NIM = 1 << 13,
	RZ_BIN_LANGUAGE_BLOCKS = 1 << 31,
} RzBinLanguage;

#define RZ_BIN_LANGUAGE_MASK(x)       ((x) & ~RZ_BIN_LANGUAGE_BLOCKS)
#define RZ_BIN_LANGUAGE_HAS_BLOCKS(x) ((x)&RZ_BIN_LANGUAGE_BLOCKS)

enum {
	RZ_BIN_CLASS_PRIVATE,
	RZ_BIN_CLASS_PUBLIC,
	RZ_BIN_CLASS_FRIENDLY,
	RZ_BIN_CLASS_PROTECTED,
};

typedef enum {
	RZ_BIN_RELOC_8 = 8,
	RZ_BIN_RELOC_16 = 16,
	RZ_BIN_RELOC_24 = 24,
	RZ_BIN_RELOC_32 = 32,
	RZ_BIN_RELOC_64 = 64
} RzBinRelocType;

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
	RzList /*<RzBinFileHash *>*/ *file_hashes;
	int bits;
	int has_va;
	int has_pi; // pic/pie
	int has_canary;
	int has_retguard;
	int has_sanitizers;
	int has_crypto;
	int has_nx;
	int big_endian;
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

typedef struct rz_bin_file_load_options_t {
	ut64 baseaddr; ///< where the linker maps the binary in memory
	ut64 loadaddr; ///< starting physical address to read from the target file
	bool patch_relocs; ///< ask the bin plugin to fill relocs with valid contents for analysis
	bool big_endian; ///< only used for binary formats that do not specify the endian in the file, but need it to load, otherwise ignored.
	bool elf_load_sections; ///< ELF specific, load or not ELF sections
	bool elf_checks_sections; ///< ELF specific, checks or not ELF sections
	bool elf_checks_segments; ///< ELF specific, checks or not ELF sections
} RzBinObjectLoadOptions;

typedef struct rz_bin_string_database_t RzBinStrDb;

typedef struct rz_bin_object_t {
	RzBinObjectLoadOptions opts;
	st64 baddr_shift;
	ut64 boffset;
	ut64 size;
	ut64 obj_size;
	RzList /*<RzBinVirtualFile *>*/ *vfiles;
	RzList /*<RzBinMap *>*/ *maps;
	RzList /*<RzBinSection *>*/ *sections;
	RzList /*<RzBinImport *>*/ *imports;
	RzList /*<RzBinSymbol *>*/ *symbols;
	RzList /*<RzBinResource *>*/ *resources;
	/**
	 * \brief Acceleration structure for fast access of the symbol for a given import.
	 * This associates the name of every symbol where is_imported == true to the symbol itself.
	 */
	HtPP /*<const char *, RzBinSymbol>*/ *import_name_symbols; // currently only used for imports, but could be extended to all symbols if needed.
	RzList /*<RzBinAddr *>*/ *entries;
	RzList /*<RzBinField *>*/ *fields;
	RzList /*<char *>*/ *libs;
	RzBinRelocStorage *relocs;
	RzBinStrDb *strings;
	RzList /*<RzBinClass *>*/ *classes;
	HtPP *classes_ht;
	HtPP *methods_ht;
	RzBinSourceLineInfo *lines;
	RzList /*<RzBinMem *>*/ *mem;
	char *regstate;
	RzBinInfo *info;
	RzBinAddr *binsym[RZ_BIN_SPECIAL_SYMBOL_LAST];
	struct rz_bin_plugin_t *plugin;
	RzBinLanguage lang;
	RZ_DEPRECATE RZ_BORROW Sdb *kv; ///< deprecated, put info in C structures instead of this (holds a copy of another pointer.)
	HtUP *addrzklassmethod;
	void *bin_obj; // internal pointer used by formats
} RzBinObject;

// XXX: RbinFile may hold more than one RzBinObject
/// XX curplugin == o->plugin
struct rz_bin_file_t {
	char *file;
	int fd; ///< when used in combination with RzIO, this refers to the io fd.
	int size;
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
	RzList /*<RzBinXtrData *>*/ *xtr_data;
	RZ_DEPRECATE Sdb *sdb; ///< deprecated, put info in C structures instead of this
	struct rz_bin_t *rbin;
}; // RzBinFile

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
	RZ_DEPRECATE RzBinFile *cur; ///< never use this in new code! Get a file from the binfiles list or track it yourself.
	int narch;
	void *user;
	RzEvent *event;
	/* preconfigured values */
	int debase64;
	int minstrlen;
	int maxstrlen; //< <= 0 means no limit
	ut64 maxstrbuf;
	int rawstr;
	RZ_DEPRECATE Sdb *sdb;
	RzIDStorage *ids;
	RzList /*<RzBinPlugin *>*/ *plugins;
	RzList /*<RzBinXtrPlugin *>*/ *binxtrs;
	RzList /*<RzBinFile *>*/ *binfiles;
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
	bool verbose;
	bool use_xtr; // use extract plugins when loading a file?
	bool strseach_check_ascii_freq; // str.search.check_ascii_freq
	RzStrConstPool constpool;
	bool is_reloc_patched; // used to indicate whether relocations were patched or not
	RzDemangler *demangler;
	RzHash *hash;
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
	RzBinObjectLoadOptions obj_opts;
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
	RzList /*<RzBinXtrData *>*/ *(*extractall_from_bytes)(RzBin *bin, const ut8 *buf, ut64 size);
	RzList /*<RzBinXtrData *>*/ *(*extractall_from_buffer)(RzBin *bin, RzBuffer *buf);
	RzBinXtrData *(*extract)(RzBin *bin, int idx);
	RzList /*<RzBinXtrData *>*/ *(*extractall)(RzBin *bin);

	bool (*load)(RzBin *bin);
	int (*size)(RzBin *bin);
	void (*destroy)(RzBin *bin);
	void (*free_xtr)(void *xtr_obj);
} RzBinXtrPlugin;

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

/**
 * \brief A single sample of source line info for a specific address
 *
 * If at least one of the line, column and file members is not 0/NULL, such a sample specifies the line info
 * for all addresses greater or equal to address until the next address that has another sample.
 *
 * If all the members line, column and file are 0/NULL, then this is a closing sample, indicating that the
 * previous entry stops here. The address is the first address **not contained** by the previous record.
 * Such a case corresponds for example to what DW_LNE_end_sequence emits in Dwarf.
 * Use rz_bin_source_line_sample_is_closing() for checking if a sample is closing.
 */
typedef struct rz_bin_source_line_sample_t {
	/**
	 * The first address that is covered by the given line and column,
	 * or, if all other members are 0/NULL, this is the first.
	 */
	ut64 address;

	/**
	 * If > 0, then indicates the line for the given address and the following.
	 * If == 0, then indicates that no line information is known.
	 *
	 * 32bit for this value is an intentional decision to lower memory consumption.
	 */
	ut32 line;

	/**
	 * If > 0, then indicates the column.
	 * If == 0, then no column information is known.
	 *
	 * 32bit for this value is an intentional decision to lower memory consumption.
	 */
	ut32 column;

	/**
	 * Filename, which must come out of the const pool of the owning
	 * RzBinSourceLineInfo or RzBinSourceLineInfoBuilder.
	 */
	const char *file;
} RzBinSourceLineSample;

/*
 * see documentation of RzBinSourceLineSample about what closing exactly means.
 */
static inline bool rz_bin_source_line_sample_is_closing(const RzBinSourceLineSample *s) {
	return !s->line && !s->column && !s->file;
}

struct rz_bin_source_line_info_t {
	/**
	 * \brief All source line references for given adresses
	 *
	 * These elements must be sorted by address and addresses must be unique, so binary search can be applied.
	 * Source file information is not contained within this array because source file changes
	 * are generally much sparser than line changes.
	 */
	RzBinSourceLineSample *samples;
	size_t samples_count;
	RzStrConstPool filename_pool;
}; // RzBinSourceLineInfo

/**
 * Temporary data structure for building an RzBinSourceLineInfo.
 */
typedef struct rz_bin_source_line_info_builder_t {
	RzVector /*<RzBinSourceLineSample>*/ samples; //< may be unsorted and will be sorted in the finalization step
	RzStrConstPool filename_pool;
} RzBinSourceLineInfoBuilder;

RZ_API void rz_bin_source_line_info_builder_init(RzBinSourceLineInfoBuilder *builder);
RZ_API void rz_bin_source_line_info_builder_fini(RzBinSourceLineInfoBuilder *builder);
RZ_API void rz_bin_source_line_info_builder_push_sample(RzBinSourceLineInfoBuilder *builder, ut64 address, ut32 line, ut32 column, const char *file);
RZ_API RzBinSourceLineInfo *rz_bin_source_line_info_builder_build_and_fini(RzBinSourceLineInfoBuilder *builder);

RZ_API void rz_bin_source_line_info_free(RzBinSourceLineInfo *sli);
RZ_API const RzBinSourceLineSample *rz_bin_source_line_info_get_first_at(const RzBinSourceLineInfo *sli, ut64 addr);
RZ_API const RzBinSourceLineSample *rz_bin_source_line_info_get_next(const RzBinSourceLineInfo *sli, RZ_NONNULL const RzBinSourceLineSample *cur);

typedef struct rz_bin_plugin_t {
	char *name;
	char *desc;
	char *author;
	char *version;
	char *license;
	RZ_DEPRECATE Sdb *(*get_sdb)(RzBinFile *obj); ///< deprecated, put info in C structures instead of this
	bool (*load_buffer)(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb);
	ut64 (*size)(RzBinFile *bin);
	void (*destroy)(RzBinFile *bf);
	bool (*check_bytes)(const ut8 *buf, ut64 length);
	bool (*check_buffer)(RzBuffer *buf);
	bool (*check_filename)(const char *filename);
	ut64 (*baddr)(RzBinFile *bf);
	ut64 (*boffset)(RzBinFile *bf);
	RzList /*<RzBinVirtualFile *>*/ *(*virtual_files)(RzBinFile *bf);
	RzList /*<RzBinMap *>*/ *(*maps)(RzBinFile *bf);
	RzBinAddr *(*binsym)(RzBinFile *bf, RzBinSpecialSymbol num);
	RzList /*<RzBinAddr *>*/ *(*entries)(RzBinFile *bf);
	RzList /*<RzBinSection *>*/ *(*sections)(RzBinFile *bf);
	RZ_OWN RzBinSourceLineInfo *(*lines)(RzBinFile *bf); //< only called once on load, ownership is transferred to the caller
	RzList /*<RzBinSymbol *>*/ *(*populate_symbols)(RzBinFile *bf); //< populate the symbols
	void (*demangle_symbols)(RZ_BORROW RzBinFile *file, RZ_BORROW RzList /*<RzBinSymbol *>*/ *symbols); //< demangle the symbols (must be called after populate_symbols)
	RzList /*<RzBinImport *>*/ *(*imports)(RzBinFile *bf);
	RzList /*<RzBinString *>*/ *(*strings)(RzBinFile *bf);
	RzBinInfo *(*info)(RzBinFile *bf);
	RzList /*<RzBinField *>*/ *(*fields)(RzBinFile *bf);
	RzList /*<char *>*/ *(*libs)(RzBinFile *bf);
	RzList /*<RzBinReloc *>*/ *(*relocs)(RzBinFile *bf);
	RzList /*<RzBinTrycatch *>*/ *(*trycatch)(RzBinFile *bf);
	RzList /*<RzBinClass *>*/ *(*classes)(RzBinFile *bf);
	RzList /*<RzBinMem *>*/ *(*mem)(RzBinFile *bf);
	RzList /*<RzBinReloc *>*/ *(*patch_relocs)(RzBinFile *bf);
	RzList /*<RzBinFileHash *>*/ *(*hashes)(RzBinFile *bf);
	RzList /*<RzBinResource *>*/ *(*resources)(RzBinFile *bf);
	void (*header)(RzBinFile *bf);
	char *(*signature)(RzBinFile *bf, bool json);
	int (*demangle_type)(const char *str);
	char *(*enrich_asm)(RzBinFile *bf, const char *asm_str, int asm_len);
	ut64 (*get_offset)(RzBinFile *bf, int type, int idx);
	char *(*get_name)(RzBinFile *bf, int type, int idx);
	ut64 (*get_vaddr)(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr);
	char *(*section_type_to_string)(ut64 type);
	RzList /*<char *>*/ *(*section_flag_to_rzlist)(ut64 flag);
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

/**
 * A virtual file is a binary buffer, exposed by a bin plugin for a loaded file.
 * These virtual files can be used whenever data that is related to the file but
 * not directly represented-as is in the raw file should be mapped into the virtual
 * address space.
 * Common examples for this include compressed segments or patching relocations.
 * The idea is that the bin plugin exposes virtual files and then refers to them
 * in the RzBinMap it returns.
 *
 * For example, when there is a binary format that contains a compressed segment
 * called "text", the bin plugin would create a virtual file:
 *
 * 	   RzBinVirtualFile {
 * 	     .name = "text_decompressed",
 * 	     .buf = rz_buf_new_with_bytes(<decompressed bytes>, <decompressed size>),
 * 	     ...
 * 	   }
 *
 * which it can then use for mapping by referring to its exact name:
 *
 *     RzBinMap {
 *       .vsize = <decompressed size>,
 *       .name = "text",
 *       .vfile_name = "text_decompressed",
 *       ...
 *     }
 *
 * When RzBin is used as part of RzCore, these virtual files can be opened as RzIO
 * files using an URI like `vfile://<binfile id>/<filename>`. By default, RzCore
 * sets everything up automatically though so it is rather rare that one has to
 * manually work with these URIs.
 */
typedef struct rz_bin_virtual_file_t {
	RZ_OWN RZ_NONNULL char *name;
	RZ_NONNULL RzBuffer *buf;
	bool buf_owned; ///< whether buf is owned and freed by this RzBinVirtualFile
} RzBinVirtualFile;

/// Description of a single memory mapping into virtual memory from a binary
typedef struct rz_bin_map_t {
	ut64 paddr; ///< address of the map inside the file
	ut64 psize; ///< size of the data inside the file
	ut64 vaddr; ///< address in the destination address space to map to
	ut64 vsize; ///< size to map in the destination address space. If vsize > psize, excessive bytes are meant to be filled with 0
	RZ_NULLABLE char *name;
	ut32 perm;

	/**
	 * If not NULL, the data will be taken from the virtual file returned by the
	 * plugin's virtual_file callback matching the given name.
	 * If NULL, the mapping will simply be taken from the raw file.
	 */
	RZ_NULLABLE char *vfile_name;
} RzBinMap;

typedef struct rz_bin_section_t {
	char *name;
	ut64 size;
	ut64 vsize;
	ut64 vaddr;
	ut64 paddr;
	ut32 perm;
	ut64 align;
	// per section platform info
	const char *arch;
	ut64 type;
	ut64 flags;
	char *format;
	int bits;
	bool has_strings;
	bool is_data;
	bool is_segment;
} RzBinSection;

/**
 * Structure to associate a segment with the list of sections that fall in that
 * segment.
 */
typedef struct rz_bin_section_map_t {
	const RzBinSection *segment;
	RzPVector /*<RzBinSection *>*/ sections;
} RzBinSectionMap;

typedef struct rz_bin_class_t {
	char *name;
	// TODO: char *module;
	char *super;
	char *visibility_str; // XXX only used by java
	int index;
	ut64 addr;
	RzList /*<RzBinSymbol *>*/ *methods;
	RzList /*<RzBinField *>*/ *fields;
	// RzList *interfaces; // <char *>
	int visibility;
} RzBinClass;

#define RzBinSectionName   rz_offsetof(RzBinSection, name)
#define RzBinSectionOffset rz_offsetof(RzBinSection, offset)

#define REBASE_PADDR(o, l, type_t) \
	do { \
		if ((o)->opts.loadaddr) { \
			RzListIter *_it; \
			type_t *_el; \
			rz_list_foreach ((l), _it, _el) { \
				_el->paddr += (o)->opts.loadaddr; \
			} \
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
	char *visibility_str;
	// ----------------
	// char descriptor[RZ_BIN_SIZEOF_STRINGS+1];
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
	RzBinRelocType type;
	RzBinSymbol *symbol;
	RzBinImport *import;
	st64 addend;
	ut64 vaddr; ///< the vaddr where the value should be patched into
	ut64 paddr; ///< the paddr where the value should be patched into
	ut64 target_vaddr; ///< the target address that the patched reloc points to
	ut32 visibility;
	bool additive;
	/* is_ifunc: indirect function, `addend` points to a resolver function
	 * that returns the actual relocation value, e.g. chooses
	 * an optimized version depending on the CPU.
	 * cf. https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html
	 */
	bool is_ifunc;
} RzBinReloc;

RZ_API ut64 rz_bin_reloc_size(RzBinReloc *reloc);

/// Efficient storage of relocations to query by address
struct rz_bin_reloc_storage_t {
	RzBinReloc **relocs; ///< all relocs, ordered by their vaddr
	size_t relocs_count;
	RzBinReloc **target_relocs; ///< all relocs that have a valid target_vaddr, ordered by their target_vaddr. size is target_relocs_count!
	size_t target_relocs_count;
}; // RzBinRelocStorage

RZ_API RzBinRelocStorage *rz_bin_reloc_storage_new(RZ_OWN RzList /*<RzBinReloc *>*/ *relocs);
RZ_API void rz_bin_reloc_storage_free(RzBinRelocStorage *storage);
RZ_API RzBinReloc *rz_bin_reloc_storage_get_reloc_in(RzBinRelocStorage *storage, ut64 vaddr, ut64 size);

/// return true iff there is at least one reloc in the storage with a target address
static inline bool rz_bin_reloc_storage_targets_available(RzBinRelocStorage *storage) {
	return storage->target_relocs_count != 0;
}

RZ_API RzBinReloc *rz_bin_reloc_storage_get_reloc_to(RzBinRelocStorage *storage, ut64 vaddr);

typedef struct rz_bin_string_t {
	// TODO: rename string->name (avoid colisions)
	char *string;
	ut64 vaddr;
	ut64 paddr;
	ut32 ordinal;
	ut32 size; // size of buffer containing the string in bytes
	ut32 length; // length of string in chars
	RzStrEnc type; // Ascii Wide cp850 utf8 mutf8 base64 ...
} RzBinString;

typedef struct rz_bin_field_t {
	ut64 vaddr;
	ut64 paddr;
	int size;
	int offset;
	ut32 visibility;
	char *name;
	char *type;
	char *visibility_str;
	char *comment;
	char *format;
	bool format_named; // whether format is the name of a format or a raw pf format string
	ut64 flags;
} RzBinField;

RZ_API RzBinField *rz_bin_field_new(ut64 paddr, ut64 vaddr, int size, const char *name, const char *comment, const char *format, bool format_named);
RZ_API void rz_bin_field_free(RzBinField *field);

typedef struct rz_bin_mem_t {
	char *name;
	ut64 addr;
	int size;
	int perms;
	RzList /*<RzBinMem *>*/ *mirrors; // for mirror access; stuff here should only create new maps not new fds
} RzBinMem;

typedef struct rz_bin_resource_t {
	size_t index;
	char *name;
	char *time;
	ut64 vaddr;
	ut64 size;
	char *type;
	char *language;
} RzBinResource;

// TODO: deprecate rz_bin_is_big_endian
// TODO: has_dbg_syms... maybe flags?

typedef ut64 (*RzBinGetOffset)(RzBin *bin, int type, int idx);
typedef char *(*RzBinGetName)(RzBin *bin, int type, int idx);
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

RZ_API void rz_bin_virtual_file_free(RzBinVirtualFile *vfile);
RZ_API void rz_bin_map_free(RzBinMap *map);
RZ_API bool rz_bin_map_is_data(RZ_NONNULL const RzBinMap *map);
RZ_API RZ_OWN RzList /*<RzBinMap *>*/ *rz_bin_maps_of_file_sections(RZ_NONNULL RzBinFile *binfile);
RZ_API RzList /*<RzBinSection *>*/ *rz_bin_sections_of_maps(RzList /*<RzBinMap *>*/ *maps);
RZ_API RzBinSection *rz_bin_section_new(const char *name);
RZ_API void rz_bin_section_free(RzBinSection *bs);
RZ_API bool rz_bin_section_is_data(RZ_NONNULL const RzBinSection *section);
RZ_API RZ_OWN char *rz_bin_section_type_to_string(RzBin *bin, int type);
RZ_API RZ_OWN RzList /*<char *>*/ *rz_bin_section_flag_to_list(RzBin *bin, ut64 flag);
RZ_API void rz_bin_info_free(RzBinInfo *rb);
RZ_API void rz_bin_import_free(RzBinImport *imp);
RZ_API void rz_bin_resource_free(RzBinResource *res);
RZ_API void rz_bin_symbol_free(RzBinSymbol *sym);
static inline bool rz_bin_reloc_has_target(RzBinReloc *reloc) {
	return reloc->target_vaddr && reloc->target_vaddr != UT64_MAX;
}
RZ_API void rz_bin_reloc_free(RzBinReloc *reloc);
RZ_API RzBinSymbol *rz_bin_symbol_new(const char *name, ut64 paddr, ut64 vaddr);
RZ_API void rz_bin_string_free(void *_str);

#ifdef RZ_API

typedef struct rz_bin_options_t {
	const char *pluginname;
	RzBinObjectLoadOptions obj_opts;
	ut64 sz;
	int xtr_idx; // load Nth binary
	int fd;
	const char *filename;
} RzBinOptions;

typedef struct rz_event_bin_file_del_t {
	RzBinFile *bf;
} RzEventBinFileDel;

RZ_API RzBinImport *rz_bin_import_clone(RzBinImport *o);
RZ_API const char *rz_bin_symbol_name(RzBinSymbol *s);
typedef void (*RzBinSymbolCallback)(RzBinObject *obj, RzBinSymbol *symbol);

// common functionality for patching relocs
RZ_API ut64 rz_bin_relocs_patch_find_targets_map_base(RzList /*<RzBinMap *>*/ *maps, ut64 target_sz);

typedef struct rz_bin_reloc_target_builder RzBinRelocTargetBuilder;
RZ_API RzBinRelocTargetBuilder *rz_bin_reloc_target_builder_new(ut64 target_size, ut64 target_base);
RZ_API void rz_bin_reloc_target_builder_free(RzBinRelocTargetBuilder *builder);
RZ_API ut64 rz_bin_reloc_target_builder_get_target(RzBinRelocTargetBuilder *builder, ut64 sym);

RZ_API void rz_bin_relocs_patch_maps(RZ_NONNULL RzList /*<RzBinMap *>*/ *maps,
	RZ_NULLABLE RzBuffer *buf_patched, ut64 buf_patched_offset,
	ut64 target_vfile_base, ut64 target_vfile_size,
	RZ_NONNULL const char *vfile_name_patched, RZ_NONNULL const char *vfile_name_reloc_targets);

// options functions
RZ_API void rz_bin_options_init(RzBinOptions *opt, int fd, ut64 baseaddr, ut64 loadaddr, bool patch_relocs);
RZ_API void rz_bin_arch_options_init(RzBinArchOptions *opt, const char *arch, int bits);

// open/close/reload functions
RZ_API RzBin *rz_bin_new(void);
RZ_API void rz_bin_free(RzBin *bin);
RZ_API RzBinFile *rz_bin_open(RzBin *bin, const char *file, RzBinOptions *opt);
RZ_API RzBinFile *rz_bin_open_io(RzBin *bin, RzBinOptions *opt);
RZ_API RzBinFile *rz_bin_open_buf(RzBin *bin, RzBuffer *buf, RzBinOptions *opt);
RZ_API RzBinFile *rz_bin_reload(RzBin *bin, RzBinFile *bf, ut64 baseaddr);

// plugins/bind functions
RZ_API void rz_bin_bind(RzBin *b, RzBinBind *bnd);
RZ_API bool rz_bin_plugin_add(RzBin *bin, RZ_NONNULL RzBinPlugin *plugin);
RZ_API bool rz_bin_plugin_del(RzBin *bin, RZ_NONNULL RzBinPlugin *plugin);
RZ_API bool rz_bin_xtr_plugin_add(RzBin *bin, RZ_NONNULL RzBinXtrPlugin *plugin);
RZ_API bool rz_bin_xtr_plugin_del(RzBin *bin, RZ_NONNULL RzBinXtrPlugin *plugin);
RZ_API bool rz_bin_list_plugin(RzBin *bin, const char *name, PJ *pj, int json);
RZ_API RzBinPlugin *rz_bin_get_binplugin_by_buffer(RzBin *bin, RzBuffer *buf);
RZ_API const RzBinPlugin *rz_bin_plugin_get(RZ_NONNULL RzBin *bin, RZ_NONNULL const char *name);
RZ_API const RzBinXtrPlugin *rz_bin_xtrplugin_get(RZ_NONNULL RzBin *bin, RZ_NONNULL const char *name);
RZ_API void rz_bin_force_plugin(RzBin *bin, const char *pname);

// get/set various bin information
RZ_API ut64 rz_bin_get_baddr(RzBin *bin);
RZ_API ut64 rz_bin_file_get_baddr(RzBinFile *bf);
RZ_API void rz_bin_set_user_ptr(RzBin *bin, void *user);
RZ_DEPRECATE RZ_API RZ_BORROW RzBinInfo *rz_bin_get_info(RzBin *bin);
RZ_API void rz_bin_set_baddr(RzBin *bin, ut64 baddr);
RZ_API ut64 rz_bin_get_laddr(RzBin *bin);
RZ_API ut64 rz_bin_get_size(RzBin *bin);
RZ_API RZ_OWN RzList /*<RzBinString *>*/ *rz_bin_file_strings(RZ_NONNULL RzBinFile *bf, size_t min_length, bool raw_strings);

// use RzBinFile instead
RZ_DEPRECATE RZ_API RZ_BORROW RzList /*<RzBinAddr *>*/ *rz_bin_get_entries(RZ_NONNULL RzBin *bin);
RZ_DEPRECATE RZ_API RZ_BORROW RzList /*<RzBinField *>*/ *rz_bin_get_fields(RZ_NONNULL RzBin *bin);
RZ_DEPRECATE RZ_API RZ_BORROW RzList /*<RzBinImport *>*/ *rz_bin_get_imports(RZ_NONNULL RzBin *bin);
RZ_DEPRECATE RZ_API RZ_BORROW RzList /*<char *>*/ *rz_bin_get_libs(RZ_NONNULL RzBin *bin);
RZ_DEPRECATE RZ_API RZ_BORROW RzList /*<RzBinSection *>*/ *rz_bin_get_sections(RZ_NONNULL RzBin *bin);
RZ_DEPRECATE RZ_API RZ_BORROW RzList /*<RzBinClass *>*/ *rz_bin_get_classes(RZ_NONNULL RzBin *bin);
RZ_DEPRECATE RZ_API RZ_BORROW RzList /*<RzBinString *>*/ *rz_bin_get_strings(RZ_NONNULL RzBin *bin);
RZ_DEPRECATE RZ_API RZ_BORROW RzList /*<RzBinMem *>*/ *rz_bin_get_mem(RZ_NONNULL RzBin *bin);
RZ_DEPRECATE RZ_API RZ_BORROW RzList /*<RzBinSymbol *>*/ *rz_bin_get_symbols(RZ_NONNULL RzBin *bin);
RZ_DEPRECATE RZ_API int rz_bin_is_static(RZ_NONNULL RzBin *bin);
RZ_API RzList /*<RzBinTrycatch *>*/ *rz_bin_file_get_trycatch(RZ_NONNULL RzBinFile *bf);

RZ_API const RzList /*<RzBinAddr *>*/ *rz_bin_object_get_entries(RZ_NONNULL RzBinObject *obj);
RZ_API const RzList /*<RzBinField *>*/ *rz_bin_object_get_fields(RZ_NONNULL RzBinObject *obj);
RZ_API const RzList /*<RzBinImport *>*/ *rz_bin_object_get_imports(RZ_NONNULL RzBinObject *obj);
RZ_API const RzBinInfo *rz_bin_object_get_info(RZ_NONNULL RzBinObject *obj);
RZ_API const RzList /*<char *>*/ *rz_bin_object_get_libs(RZ_NONNULL RzBinObject *obj);
RZ_API const RzList /*<RzBinSection *>*/ *rz_bin_object_get_sections_all(RZ_NONNULL RzBinObject *obj);
RZ_API RZ_OWN RzList /*<RzBinSection *>*/ *rz_bin_object_get_sections(RZ_NONNULL RzBinObject *obj);
RZ_API RZ_OWN RzList /*<RzBinSection *>*/ *rz_bin_object_get_segments(RZ_NONNULL RzBinObject *obj);
RZ_API RZ_OWN RzList /*<RzBinMap *>*/ *rz_bin_object_get_maps(RZ_NONNULL RzBinObject *obj);
RZ_API const RzList /*<RzBinClass *>*/ *rz_bin_object_get_classes(RZ_NONNULL RzBinObject *obj);
RZ_API const RzList /*<RzBinString *>*/ *rz_bin_object_get_strings(RZ_NONNULL RzBinObject *obj);
RZ_API const RzList /*<RzBinMem *>*/ *rz_bin_object_get_mem(RZ_NONNULL RzBinObject *obj);
RZ_API const RzList /*<RzBinResource *>*/ *rz_bin_object_get_resources(RZ_NONNULL RzBinObject *obj);
RZ_API const RzList /*<RzBinSymbol *>*/ *rz_bin_object_get_symbols(RZ_NONNULL RzBinObject *obj);
RZ_API bool rz_bin_object_reset_strings(RZ_NONNULL RzBin *bin, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzBinObject *obj);
RZ_API RZ_BORROW RzBinString *rz_bin_object_get_string_at(RZ_NONNULL RzBinObject *obj, ut64 address, bool is_va);
RZ_API bool rz_bin_object_is_big_endian(RZ_NONNULL RzBinObject *obj);
RZ_API bool rz_bin_object_is_static(RZ_NONNULL RzBinObject *obj);
RZ_API RZ_OWN RzVector /*<RzBinSectionMap>*/ *rz_bin_object_sections_mapping_list(RZ_NONNULL RzBinObject *obj);
RZ_API RZ_OWN RzPVector /*<RzBinMap *>*/ *rz_bin_object_get_maps_at(RzBinObject *o, ut64 off, bool va);
RZ_API RZ_BORROW RzBinMap *rz_bin_object_get_map_at(RZ_NONNULL RzBinObject *o, ut64 off, bool va);
RZ_API ut64 rz_bin_object_p2v(RZ_NONNULL RzBinObject *obj, ut64 paddr);
RZ_API RzVector /*<ut64>*/ *rz_bin_object_p2v_all(RZ_NONNULL RzBinObject *obj, ut64 paddr);
RZ_API ut64 rz_bin_object_v2p(RZ_NONNULL RzBinObject *obj, ut64 vaddr);

RZ_API RzBinLanguage rz_bin_language_detect(RzBinFile *binfile);
RZ_API RzBinLanguage rz_bin_language_to_id(const char *language);
RZ_API const char *rz_bin_language_to_string(RzBinLanguage language);

RZ_API RzBinFile *rz_bin_cur(RzBin *bin);
RZ_API RzBinObject *rz_bin_cur_object(RzBin *bin);

// select/list binfiles functions
RZ_API bool rz_bin_select(RzBin *bin, const char *arch, int bits, const char *name);
RZ_API bool rz_bin_select_bfid(RzBin *bin, ut32 bf_id);
RZ_API bool rz_bin_use_arch(RzBin *bin, const char *arch, int bits, const char *name);
RZ_API RzBuffer *rz_bin_create(RzBin *bin, const char *plugin_name, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt);

RZ_API const char *rz_bin_entry_type_string(int etype);

RZ_API bool rz_bin_file_object_new_from_xtr_data(RzBin *bin, RzBinFile *bf, RzBinObjectLoadOptions *opts, RzBinXtrData *data);

// RzBinFile.get
RZ_API RzBinFile *rz_bin_file_at(RzBin *bin, ut64 addr);
RZ_API RzList /*<RzBinSymbol *>*/ *rz_bin_file_get_symbols(RzBinFile *bf);
// RzBinFile.add
RZ_API RzBinClass *rz_bin_file_add_class(RzBinFile *binfile, const char *name, const char *super, int view);
RZ_API RzBinSymbol *rz_bin_file_add_method(RzBinFile *bf, const char *classname, const char *name, int nargs);
// RzBinFile.find
RZ_API RzBinFile *rz_bin_file_find_by_arch_bits(RzBin *bin, const char *arch, int bits);
RZ_API RzBinFile *rz_bin_file_find_by_id(RzBin *bin, ut32 bin_id);
RZ_API RzBinFile *rz_bin_file_find_by_fd(RzBin *bin, ut32 bin_fd);
RZ_API RzBinFile *rz_bin_file_find_by_name(RzBin *bin, const char *name);

RZ_API bool rz_bin_file_set_cur_binfile(RzBin *bin, RzBinFile *bf);
RZ_API bool rz_bin_file_set_cur_by_fd(RzBin *bin, ut32 bin_fd);
RZ_API bool rz_bin_file_set_cur_by_id(RzBin *bin, ut32 bin_id);
RZ_API bool rz_bin_file_set_cur_by_name(RzBin *bin, const char *name);
RZ_API ut64 rz_bin_file_delete_all(RzBin *bin);
RZ_API bool rz_bin_file_delete(RzBin *bin, RzBinFile *bf);
RZ_API RZ_OWN RzList /*<RzBinFileHash *>*/ *rz_bin_file_compute_hashes(RzBin *bin, RzBinFile *bf, ut64 limit);
RZ_API RZ_OWN RzList /*<RzBinFileHash *>*/ *rz_bin_file_set_hashes(RzBin *bin, RZ_OWN RzList /*<RzBinFileHash *>*/ *new_hashes);
RZ_API RzBinPlugin *rz_bin_file_cur_plugin(RzBinFile *binfile);
RZ_API void rz_bin_file_hash_free(RzBinFileHash *fhash);

// binobject functions
RZ_API int rz_bin_object_set_items(RzBinFile *binfile, RzBinObject *o);
RZ_API ut64 rz_bin_object_addr_with_base(RzBinObject *o, ut64 addr);
RZ_API ut64 rz_bin_object_get_vaddr(RzBinObject *o, ut64 paddr, ut64 vaddr);
RZ_API const RzBinAddr *rz_bin_object_get_special_symbol(RzBinObject *o, RzBinSpecialSymbol sym);
RZ_API RzBinRelocStorage *rz_bin_object_patch_relocs(RzBinFile *bf, RzBinObject *o);
RZ_API RzBinSymbol *rz_bin_object_get_symbol_of_import(RzBinObject *o, RzBinImport *imp);
RZ_API RzBinVirtualFile *rz_bin_object_get_virtual_file(RzBinObject *o, const char *name);
RZ_API void rz_bin_mem_free(void *data);

// demangle functions
RZ_API RZ_OWN char *rz_bin_demangle(RZ_NULLABLE RzBinFile *bf, RZ_NULLABLE const char *language, RZ_NULLABLE const char *symbol, ut64 vaddr, bool libs);
RZ_API const char *rz_bin_get_meth_flag_string(ut64 flag, bool compact);

RZ_API RZ_BORROW RzBinSection *rz_bin_get_section_at(RzBinObject *o, ut64 off, int va);

/* dbginfo.c */
RZ_DEPRECATE RZ_API bool rz_bin_addr2line(RzBin *bin, ut64 addr, char *file, int len, int *line);
RZ_DEPRECATE RZ_API char *rz_bin_addr2text(RzBin *bin, ut64 addr, int origin);

/* filter.c */
RZ_API void rz_bin_load_filter(RzBin *bin, ut64 rules);
RZ_API void rz_bin_filter_symbols(RzBinFile *bf, RzList /*<RzBinSymbol *>*/ *list);
RZ_API void rz_bin_filter_sections(RzBinFile *bf, RzList /*<RzBinSection *>*/ *list);
RZ_API char *rz_bin_filter_name(RzBinFile *bf, HtPU *db, ut64 addr, char *name);
RZ_API void rz_bin_filter_sym(RzBinFile *bf, HtPP *ht, ut64 vaddr, RzBinSymbol *sym);
RZ_API bool rz_bin_strpurge(RzBin *bin, const char *str, ut64 addr);
RZ_API bool rz_bin_string_filter(RzBin *bin, const char *str, int len, ut64 addr);

/* bin string */
RZ_API void rz_bin_string_decode_base64(RZ_NONNULL RzBinString *bstr);
RZ_API RZ_OWN RzBinStrDb *rz_bin_string_database_new(RZ_NULLABLE RZ_OWN RzList /*<RzBinString *>*/ *list);
RZ_API void rz_bin_string_database_free(RZ_NULLABLE RzBinStrDb *db);
RZ_API bool rz_bin_string_database_add(RZ_NONNULL RzBinStrDb *db, RZ_NONNULL RzBinString *bstr);
RZ_API bool rz_bin_string_database_remove(RZ_NONNULL RzBinStrDb *db, ut64 address, bool is_va);

/* plugin pointers */
extern RzBinPlugin rz_bin_plugin_any;
extern RzBinPlugin rz_bin_plugin_fs;
extern RzBinPlugin rz_bin_plugin_cgc;
extern RzBinPlugin rz_bin_plugin_elf;
extern RzBinPlugin rz_bin_plugin_elf64;
extern RzBinPlugin rz_bin_plugin_p9;
extern RzBinPlugin rz_bin_plugin_ne;
extern RzBinPlugin rz_bin_plugin_le;
extern RzBinPlugin rz_bin_plugin_luac;
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
