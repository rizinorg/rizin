// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef LUAJIT_H
#define LUAJIT_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define LUAJIT_GET_INTERNAL_BIN_INFO_OBJ(bf) ((LuaJITBinInfo *)(bf)->o->bin_obj)
#define IS_FLAG(off, flag)                   ((off) & flag)

/* Header Info */
#define LUAJIT_MAGIC           "\x1b\x4c\x4a"
#define LUAJIT_MAGIC_OFFSET    0x00
#define LUAJIT_MAGIC_BYTE_SIZE 3
#define LUAJIT_VERSION_OFFSET  0x03
#define LUAJIT_FLAG_OFFSET_AT  0x04
#define LUAJIT_FILE_LEN_START  0x05

/* Header Flags */
#define LUAJIT_BCDUMP_F_BE    0x01
#define LUAJIT_BCDUMP_F_STRIP 0x02
#define LUAJIT_BCDUMP_F_FFI   0x04
#define LUAJIT_BCDUMP_F_FR2   0x08

/* Protos flags */
#define LUAJIT_PROTO_CHILD   0x01
#define LUAJIT_PROTO_VARARGS 0x02
#define LUAJIT_PROTO_FFI     0x04
#define LUAJIT_PROTO_NOJIT   0x08
#define LUAJIT_PROTO_ILOOP   0x10

/* LuaJIT Value Types */
typedef enum {
	LUAJIT_TNILL, ///< Type is nil
	LUAJIT_TFALSE, ///< Type is False
	LUAJIT_TTRUE, ///< Type is True
	LUAJIT_TINT, ///< Integer
	LUAJIT_TFLT, ///< Float value and complex values
	LUAJIT_TSTR ///< Type is a string
} LuaJITValueType;

/* LuaJIT Sections */
typedef enum {
	LUAJIT_STKGCOBJ, ///< KGC objects section
	LUAJIT_STTABLE, ///< Table section
	LUAJIT_STCONSTENTR, ///< Constants section
	LUAJIT_STLOCALVAR, ///< Local variables section
	LUAJIT_STUPVALINFO ///< Up value at debug section
} LuaJITSection;

/* LuaJIT KGC object type */
typedef enum {
	LUAJIT_KGCCHILD, ///< Previous parsed proto was child proto of the current proto
	LUAJIT_KGCTABLE, ///< Type is Table
	LUAJIT_KGCINT, ///< Type is Integer value
	LUAJIT_KGCFLT, ///< Type is Float value
	LUAJIT_KGCCMPLX, ///< Type is Complex number
	LUAJIT_KGCSTR ///< Type is String
} LuaJITKGCTypes;

/**
 * \struct LuaJIT_binInfo
 * \brief Store the global binary info (majority recieved from header)
 */
typedef struct LuaJIT_binInfo {
	char *version; /*version*/
	ut64 hdr_flags; ///< bitmasked header flag
	char *file_name; ///< Source
	ut64 header_end; ///< End offset of the header
	RzPVector /*<RzBinSection *>*/ *sections; ///< list of sections
	RzList /*<RzBinSymbol *>*/ *symbol_list; ///< list of symbols
	RzPVector /*<RzBinAddr *>*/ *entry_vec; ///< list of entries
	RzList /*<RzBinString *>*/ *strings; //< list of strings
	RzBinInfo *general_bin_info;
} LuaJITBinInfo;

/**
 * \struct luajit_proto_hdr_debug
 * \brief Stores the proto header debug info
 */
typedef struct luajit_proto_hdr_debug {
	ut64 dbg_len; ///< Proto head debug length (exists if -bg was enabled while compiling)
	int first_line; ///< starting line of proto in raw file
	int lines_covered; ///< Number of lines covered from this proto
	ut64 offset; ///< Offset at which this section starts
	int size; ///< Size of the section.
} LuaJITHdrDebug;

/**
 * \struct LuaJIT_Proto
 * \brief Stores the proto info
 */
typedef struct LuaJIT_Proto {
	/* Header Inf */
	ut64 start_offset; ///< Beginning of the proto (starts from header)
	ut64 end_offset; ///< End address of the proto
	ut64 size; ///< Proto size
	int hdr_size; ///< Header size

	LuaJITHdrDebug *hdr_dbg; ///< Info of Current proto header debug section.

	/* Protos body */
	RzList /*<LuaJITProto *>*/ *proto_entries; ///< Nested protos

	int num_istr_cnt; ///< Number of bytecode instructions
	ut64 instr_offset; ///< Instructions start offset.

	ut64 up_val_entry_offset; ///< Up_val section offset
	int num_up_val; ///< Number of Up_values

	RzList /*<LuaJITKgcObj *>*/ *kgc_obj; ///< List of KGC objects
	RzList /*<LuaJITTable *>*/ *table; ///< List of the table
	int k_const; ///< Number of KGC objects present

	RzList /*<LuaJITConstEntry *>*/ *constant_entries; ///< List for Constants
	int num_const; ///< Number of constants present

	ut64 debug_info_offset; ///< Debug mapping section offset
	int dbg_info_size; ///< Debug mapping section size
	RzList /*<LuaJITLocalVar *>*/ *local_var_entry; ///< List to store local variables info
	RzList /*<LuaJITUpValue *>*/ *up_val_info; ///< List to store Up_value info
} LuaJITProto;

/**
 * \struct luajit_table
 * \brief Stores the table data in proto
 */
typedef struct luajit_table {
	int narray; ///< Size of array part
	int nhash; ///< Size of hash part
	ut64 offset; ///< Current table offset
	int size; ///< Size of the current table

	// Array Part
	RzList /*<LuaJITValue *>*/ *array_items; ///< List of values in array

	// Hash Part
	RzList /*<LuaJITValue *>*/ *hash_keys; ///< List of Keys for hash values
	RzList /*<LuaJITValue *>*/ *hash_values; ///< List of hash values
} LuaJITTable;

/**
 * \struct luajit_kgc_obj
 * \brief Stores the kgc objects data in proto
 */
typedef struct luajit_kgc_obj {
	LuaJITKGCTypes type; ///< Type of the data (e.g: LUAJIT_KGCFLT, LUAJIT_KGCSTR)
	ut64 offset; ///< offset of the KGC object start
	void *data; ///< Can be a string or number
	int size; //< Size of kgc_object.

	struct complex_num {
		double r_bits; ///< Real number
		double i_bits; ///< Imaginary number
	} cmplx; ///< Struct for storing complex numbers
} LuaJITKgcObj;

/**
 * \struct luajit_value
 * \brief Stores the values in proto
 */
typedef struct luajit_value {
	LuaJITValueType type; ///< The ktabtypeU (e.g: LUAJIT_VFLT, LUAJIT_VSTR)
	ut64 offset; ///< offset of the value start
	void *data; ///< Can be a string or number
	int size; ///< Size of this Value
} LuaJITValue;

/**
 * \struct luajit_local_var
 * \brief Stores the Local Variables info in proto
 */
typedef struct luajit_local_var {
	char *varname; ///< Name of the variable
	int varname_len; ///< Length of the variable
	int start_pc; ///< Stores PC
	ut64 offset; ///< Start offset of the local variable
	int size; ///< Size of the Local Variable Section.
} LuaJITLocalVar;

/**
 * \struct luajit_up_val
 * \brief Stores the Up value info in proto
 */
typedef struct luajit_up_val {
	char *uv_name; ///< Upvalue name
	ut64 offset; ///< Start offset of the up_value in debug info of proto
	int size; ///< Size of the Upvalue debug section
} LuaJITUpValue;

/**
 * \struct luajit_constant_entry
 * \brief Stores the Constants info
 */
typedef struct luajit_constant_entry {
	void *constant_val; ///< Constant data
	ut64 offset; ///< offset of the constant
	int type; ///< type of constant (e.g: LUAJIT_DOUBLE, LUAJIT_INT)
	int size; ///< Size of the constant section.
} LuaJITConstEntry;

/* Plugin */
RZ_IPI LuaJITProto *luajit_parse_proto(RzBuffer *buff, RzList /*<LuaJITProto *>*/ *proto_list, ut64 base_offset, ut64 byte_rd, bool last_proto);
RZ_IPI RzBinInfo *luajit_header_parser(RzBinFile *bf, LuaJITBinInfo *bin_info, int min);

/* Common */
RZ_IPI bool check_malformed_ULEB128(int val);
RZ_IPI ut64 luajit_parse_string(RzBuffer *buf, ut64 offset, ut32 type, char **dest);

RZ_IPI RZ_BORROW LuaJITKgcObj *luajit_kgc_obj_new();
RZ_IPI RZ_BORROW LuaJITValue *luajit_new_val();
RZ_IPI RZ_BORROW LuaJITProto *luajit_new_proto();
RZ_IPI RZ_BORROW LuaJITTable *luajit_new_table();
RZ_IPI RZ_BORROW LuaJITConstEntry *luajit_new_constant();
RZ_IPI RZ_BORROW LuaJITLocalVar *luajit_new_localvar();
RZ_IPI RZ_BORROW LuaJITUpValue *luajit_new_upvalue();

void luajit_free_proto_entry(LuaJITProto *proto);
void luajit_free_kgc_obj(LuaJITKgcObj *kgc_obj);
void free_luajit_value(LuaJITValue *value);
void luajit_free_table(LuaJITTable *table);

#define luajit_return_if_null(p, ret) \
	if ((p) == NULL) { \
		return ret; \
	}

#define READ_SPLIT_64(out_val) \
	do { \
		ut64 _lo_val, _hi_val; \
		int _len = rz_buf_uleb128_at(buf, offset, &_lo_val); \
		if (check_malformed_ULEB128(_len)) { \
			luajit_free_kgc_obj(kgc_obj); \
			return offset; \
		} \
		offset += _len; \
		kgc_obj->size += _len; \
		_len = rz_buf_uleb128_at(buf, offset, &_hi_val); \
		if (check_malformed_ULEB128(_len)) { \
			luajit_free_kgc_obj(kgc_obj); \
			return offset; \
		} \
		offset += _len; \
		kgc_obj->size += _len; \
		(out_val) = (_hi_val << 32) | (_lo_val & 0xFFFFFFFF); \
	} while (0)

#endif