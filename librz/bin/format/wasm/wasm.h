// SPDX-FileCopyrightText: 2017-2018 cgvwzq
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#ifndef _INCLUDE_WASM_H_
#define _INCLUDE_WASM_H_

// version 0x1 (WIP)
// https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md

#define RZ_BIN_WASM_MAGIC_BYTES "\x00" \
				"asm"
#define RZ_BIN_WASM_VERSION       0x1
#define RZ_BIN_WASM_STRING_LENGTH 256
#define RZ_BIN_WASM_END_OF_CODE   0xb

#define RZ_BIN_WASM_SECTION_CUSTOM   0x0
#define RZ_BIN_WASM_SECTION_TYPE     0x1
#define RZ_BIN_WASM_SECTION_IMPORT   0x2
#define RZ_BIN_WASM_SECTION_FUNCTION 0x3
#define RZ_BIN_WASM_SECTION_TABLE    0x4
#define RZ_BIN_WASM_SECTION_MEMORY   0x5
#define RZ_BIN_WASM_SECTION_GLOBAL   0x6
#define RZ_BIN_WASM_SECTION_EXPORT   0x7
#define RZ_BIN_WASM_SECTION_START    0x8
#define RZ_BIN_WASM_SECTION_ELEMENT  0x9
#define RZ_BIN_WASM_SECTION_CODE     0xa
#define RZ_BIN_WASM_SECTION_DATA     0xb

typedef enum {
	RZ_BIN_WASM_VALUETYPE_i32 = 0x1,
	RZ_BIN_WASM_VALUETYPE_i64 = 0x2,
	RZ_BIN_WASM_VALUETYPE_f32 = 0x3,
	RZ_BIN_WASM_VALUETYPE_f64 = 0x4,
	RZ_BIN_WASM_VALUETYPE_v128 = 0x5,
	RZ_BIN_WASM_VALUETYPE_ANYFUNC = 0x10,
	RZ_BIN_WASM_VALUETYPE_FUNC = 0x20,
	RZ_BIN_WASM_VALUETYPE_EMPTY = 0x40,
} rz_bin_wasm_value_type_t;

typedef enum {
	RZ_BIN_WASM_EXTERNALKIND_Function = 0x0,
	RZ_BIN_WASM_EXTERNALKIND_Table = 0x1,
	RZ_BIN_WASM_EXTERNALKIND_Memory = 0x2,
	RZ_BIN_WASM_EXTERNALKIND_Global = 0x3,
} rz_bin_wasm_external_kind_t;

typedef enum {
	RZ_BIN_WASM_NAMETYPE_Module = 0x0,
	RZ_BIN_WASM_NAMETYPE_Function = 0x1,
	RZ_BIN_WASM_NAMETYPE_Local = 0x2,
} rz_bin_wasm_custom_name_type_t;

struct rz_bin_wasm_init_expr_t {
	// bytecode	terminated in 0xb
	size_t len;
};

struct rz_bin_wasm_resizable_limits_t {
	ut8 flags; // 1 if max field is present, 0 otherwise
	ut32 initial;
	ut32 maximum;
};

struct rz_bin_wasm_name_t {
	ut32 len;
	ut8 name[RZ_BIN_WASM_STRING_LENGTH];
};

typedef struct rz_bin_wasm_section_t {
	ut8 id;
	ut32 size;
	ut32 name_len;
	char name[RZ_BIN_WASM_STRING_LENGTH];
	ut32 offset;
	ut32 payload_data;
	ut32 payload_len;
	ut32 count;
} RzBinWasmSection;

typedef struct rz_bin_wasm_type_t {
	ut8 form;
	ut32 param_count;
	rz_bin_wasm_value_type_t *param_types;
	st8 return_count; // MVP = 1
	rz_bin_wasm_value_type_t return_type;
	char to_str[RZ_BIN_WASM_STRING_LENGTH];
} RzBinWasmTypeEntry;

// Other Types
struct rz_bin_wasm_global_type_t {
	rz_bin_wasm_value_type_t content_type;
	ut8 mutability;
};

struct rz_bin_wasm_table_type_t {
	rz_bin_wasm_value_type_t elem_type;
	struct rz_bin_wasm_resizable_limits_t limits;
};

struct rz_bin_wasm_memory_type_t {
	struct rz_bin_wasm_resizable_limits_t limits;
};

typedef struct rz_bin_wasm_import_t {
	ut32 module_len;
	char module_str[RZ_BIN_WASM_STRING_LENGTH];
	ut32 field_len;
	char field_str[RZ_BIN_WASM_STRING_LENGTH];
	ut8 kind;
	union {
		ut32 type_f;
		struct rz_bin_wasm_global_type_t type_g;
		struct rz_bin_wasm_table_type_t type_t;
		struct rz_bin_wasm_memory_type_t type_m;
	};

} RzBinWasmImportEntry;

typedef struct rz_bin_wasm_function_t {
	ut32 type_index; // index to Type entries
} RzBinWasmFunctionEntry;

typedef struct rz_bin_wasm_table_t {
	ut8 element_type; // only anyfunc
	struct rz_bin_wasm_resizable_limits_t limits;
} RzBinWasmTableEntry;

typedef struct rz_bin_wasm_memory_t {
	struct rz_bin_wasm_resizable_limits_t limits;
} RzBinWasmMemoryEntry;

typedef struct rz_bin_wasm_global_t {
	rz_bin_wasm_value_type_t content_type;
	ut8 mutability; // 0 if immutable, 1 if mutable
	struct rz_bin_wasm_init_expr_t init;
} RzBinWasmGlobalEntry;

typedef struct rz_bin_wasm_export_t {
	ut32 field_len;
	char field_str[RZ_BIN_WASM_STRING_LENGTH];
	ut8 kind;
	ut32 index;
} RzBinWasmExportEntry;

typedef struct rz_bin_wasm_start_t {
	ut32 index;
} RzBinWasmStartEntry;

struct rz_bin_wasm_local_entry_t {
	ut32 count;
	rz_bin_wasm_value_type_t type;
};

typedef struct rz_bin_wasm_element_t {
	ut32 index;
	struct rz_bin_wasm_init_expr_t init;
	ut32 num_elem;
	ut32 elems[];
} RzBinWasmElementEntry;

typedef struct rz_bin_wasm_code_t {
	ut32 body_size;
	ut32 local_count; // numer of local entries
	struct rz_bin_wasm_local_entry_t *locals;
	ut32 code; // offset
	ut32 len; // real bytecode length
	ut8 byte; // 0xb, indicating end of the body
	char name[RZ_BIN_WASM_STRING_LENGTH];
	char *signature;
} RzBinWasmCodeEntry;

typedef struct rz_bin_wasm_data_t {
	ut32 index; // linear memory index (0 in MVP)
	struct rz_bin_wasm_init_expr_t offset; // bytecode evaluated at runtime
	ut32 size;
	ut32 data; // offset
} RzBinWasmDataEntry;

// TODO: custom sections

typedef struct rz_bin_wasm_custom_name_function_names_t {
	ut32 count;
	RzIDStorage *names;
} RzBinWasmCustomNameFunctionNames;

typedef struct rz_bin_wasm_custom_name_local_name_t {
	ut32 index; // function index

	ut32 names_count;
	RzIDStorage *names; // local names
} RzBinWasmCustomNameLocalName;

typedef struct rz_bin_wasm_custom_name_local_names_t {
	ut32 count;
	RzList *locals; // RzBinWasmCustomNameLocalName
} RzBinWasmCustomNameLocalNames;

// "name" section entry
typedef struct rz_bin_wasm_custom_name_entry_t {
	ut8 type;
	ut32 size;

	ut8 payload_data;
	union {
		struct rz_bin_wasm_name_t *mod_name;
		RzBinWasmCustomNameFunctionNames *func;
		RzBinWasmCustomNameLocalNames *local;
	};
} RzBinWasmCustomNameEntry;

typedef struct rz_bin_wasm_obj_t {

	RzBuffer *buf;
	size_t size;

	ut32 entrypoint;

	// cache purposes
	RzList *g_sections;
	RzList *g_types;
	RzList *g_imports;
	RzList *g_exports;
	RzList *g_tables;
	RzList *g_memories;
	RzList *g_globals;
	RzList *g_elements;
	RzList *g_codes;
	RzList *g_datas;
	RzBinWasmStartEntry *g_start;

	RzList *g_names;
	// etc...

} RzBinWasmObj;

RzBinWasmObj *rz_bin_wasm_init(RzBinFile *bf, RzBuffer *buf);
void rz_bin_wasm_destroy(RzBinFile *bf);
RzList *rz_bin_wasm_get_sections(RzBinWasmObj *bin);
RzList *rz_bin_wasm_get_types(RzBinWasmObj *bin);
RzList *rz_bin_wasm_get_imports(RzBinWasmObj *bin);
RzList *rz_bin_wasm_get_exports(RzBinWasmObj *bin);
RzList *rz_bin_wasm_get_tables(RzBinWasmObj *bin);
RzList *rz_bin_wasm_get_memories(RzBinWasmObj *bin);
RzList *rz_bin_wasm_get_globals(RzBinWasmObj *bin);
RzList *rz_bin_wasm_get_elements(RzBinWasmObj *bin);
RzList *rz_bin_wasm_get_codes(RzBinWasmObj *bin);
RzList *rz_bin_wasm_get_datas(RzBinWasmObj *bin);
RzList *rz_bin_wasm_get_custom_names(RzBinWasmObj *bin);
ut32 rz_bin_wasm_get_entrypoint(RzBinWasmObj *bin);
const char *rz_bin_wasm_get_function_name(RzBinWasmObj *bin, ut32 idx);
const char *rz_bin_wasm_valuetype_to_string(rz_bin_wasm_value_type_t type);

#endif
