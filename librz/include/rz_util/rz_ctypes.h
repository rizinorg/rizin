#ifndef RZ_CTYPES_H
#define RZ_CTYPES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_type_enum {
	const char *name;
	const char *val;
} RTypeEnum;

enum RTypeKind {
	RZ_TYPE_BASIC = 0,
	RZ_TYPE_ENUM = 1,
	RZ_TYPE_STRUCT = 2,
	RZ_TYPE_UNION = 3,
	RZ_TYPE_TYPEDEF = 4
};

RZ_API int rz_type_set(Sdb *TDB, ut64 at, const char *field, ut64 val);
RZ_API void rz_type_del(Sdb *TDB, const char *name);
RZ_API int rz_type_kind(Sdb *TDB, const char *name);
RZ_API char *rz_type_enum_member(Sdb *TDB, const char *name, const char *member, ut64 val);
RZ_API RzList *rz_type_enum_find_member(Sdb *TDB, ut64 val);
RZ_API char *rz_type_enum_getbitfield(Sdb *TDB, const char *name, ut64 val);
RZ_API RzList *rz_type_get_enum(Sdb *TDB, const char *name);
RZ_API ut64 rz_type_get_bitsize(Sdb *TDB, const char *type);
RZ_API RzList *rz_type_get_by_offset(Sdb *TDB, ut64 offset);
RZ_API char *rz_type_get_struct_memb(Sdb *TDB, const char *type, int offset);
RZ_API char *rz_type_link_at(Sdb *TDB, ut64 addr);
RZ_API int rz_type_set_link(Sdb *TDB, const char *val, ut64 addr);
RZ_API int rz_type_unlink(Sdb *TDB, ut64 addr);
RZ_API int rz_type_unlink_all(Sdb *TDB);
RZ_API int rz_type_link_offset(Sdb *TDB, const char *val, ut64 addr);
RZ_API char *rz_type_format(Sdb *TDB, const char *t);

// Function prototypes api
RZ_API int rz_type_func_exist(Sdb *TDB, const char *func_name);
RZ_API const char *rz_type_func_cc(Sdb *TDB, const char *func_name);
RZ_API const char *rz_type_func_ret(Sdb *TDB, const char *func_name);
RZ_API int rz_type_func_args_count(Sdb *TDB, RZ_NONNULL const char *func_name);
RZ_API RZ_OWN char *rz_type_func_args_type(Sdb *TDB, RZ_NONNULL const char *func_name, int i);
RZ_API const char *rz_type_func_args_name(Sdb *TDB, RZ_NONNULL const char *func_name, int i);
RZ_API RZ_OWN char *rz_type_func_guess(Sdb *TDB, RZ_NONNULL char *func_name);

#ifdef __cplusplus
}
#endif

#endif //  RZ_CTYPES_H
