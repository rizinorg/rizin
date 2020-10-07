/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2DB_R_SERIALIZE_H
#define R2DB_R_SERIALIZE_H

#include <rz_core.h>
#include <rz_util/rz_json.h>

typedef RzList RSerializeResultInfo;
static inline RSerializeResultInfo *rz_serialize_result_info_new(void) { return rz_list_newf (free); }
static inline void rz_serialize_result_info_free(RSerializeResultInfo *info) { rz_list_free (info); }

// RSpaces

RZ_API void rz_serialize_spaces_save(RZ_NONNULL Sdb *db, RZ_NONNULL RSpaces *spaces);
/**
 * @param load_name whether to overwrite the name in spaces with the value from db
 */
RZ_API bool rz_serialize_spaces_load(RZ_NONNULL Sdb *db, RZ_NONNULL RSpaces *spaces, bool load_name, RZ_NULLABLE RSerializeResultInfo *res);

// RzFlag

RZ_API void rz_serialize_flag_zones_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzList/*<RzFlagZoneItem *>*/ *zones);
RZ_API bool rz_serialize_flag_zones_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzList/*<RzFlagZoneItem *>*/ *zones, RZ_NULLABLE RSerializeResultInfo *res);
RZ_API void rz_serialize_flag_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzFlag *flag);
RZ_API bool rz_serialize_flag_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzFlag *flag, RZ_NULLABLE RSerializeResultInfo *res);

// RzConfig

RZ_API void rz_serialize_config_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config);
RZ_API bool rz_serialize_config_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config, RZ_NULLABLE RSerializeResultInfo *res);

// RzAnal

RZ_API void rz_serialize_anal_case_op_save(RZ_NONNULL PJ *j, RZ_NONNULL RzAnalCaseOp *op);
RZ_API void rz_serialize_anal_switch_op_save(RZ_NONNULL PJ *j, RZ_NONNULL RzAnalSwitchOp *op);
RZ_API RzAnalSwitchOp *rz_serialize_anal_switch_op_load(RZ_NONNULL const RJson *json);

typedef void *RSerializeAnalDiffParser;
RZ_API RSerializeAnalDiffParser rz_serialize_anal_diff_parser_new(void);
RZ_API void rz_serialize_anal_diff_parser_free(RSerializeAnalDiffParser parser);
RZ_API RZ_NULLABLE RzAnalDiff *rz_serialize_anal_diff_load(RZ_NONNULL RSerializeAnalDiffParser parser, RZ_NONNULL const RJson *json);
RZ_API void rz_serialize_anal_diff_save(RZ_NONNULL PJ *j, RZ_NONNULL RzAnalDiff *diff);
RZ_API void rz_serialize_anal_blocks_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);

/**
 * RzAnal must not contain any blocks when calling this function!
 * All loaded blocks will have a ref of 1 after this function and should be unrefd once after loading functions.
 */
RZ_API bool rz_serialize_anal_blocks_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RSerializeAnalDiffParser diff_parser, RZ_NULLABLE RSerializeResultInfo *res);

typedef void *RSerializeAnalVarParser;
RZ_API RSerializeAnalVarParser rz_serialize_anal_var_parser_new(void);
RZ_API void rz_serialize_anal_var_parser_free(RSerializeAnalVarParser parser);
RZ_API RZ_NULLABLE RzAnalVar *rz_serialize_anal_var_load(RZ_NONNULL RzAnalFunction *fcn, RZ_NONNULL RSerializeAnalVarParser parser, RZ_NONNULL const RJson *json);

RZ_API void rz_serialize_anal_functions_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_functions_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RSerializeAnalDiffParser diff_parser, RZ_NULLABLE RSerializeResultInfo *res);
RZ_API void rz_serialize_anal_xrefs_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_xrefs_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RZ_NULLABLE RSerializeResultInfo *res);
RZ_API void rz_serialize_anal_meta_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_meta_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RZ_NULLABLE RSerializeResultInfo *res);
RZ_API void rz_serialize_anal_hints_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_hints_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RZ_NULLABLE RSerializeResultInfo *res);
RZ_API void rz_serialize_anal_classes_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_classes_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RZ_NULLABLE RSerializeResultInfo *res);
RZ_API void rz_serialize_anal_types_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_types_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RZ_NULLABLE RSerializeResultInfo *res);
RZ_API void rz_serialize_anal_sign_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_sign_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RZ_NULLABLE RSerializeResultInfo *res);
RZ_API void rz_serialize_anal_imports_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_imports_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RZ_NULLABLE RSerializeResultInfo *res);
RZ_API void rz_serialize_anal_pin_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_pin_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RZ_NULLABLE RSerializeResultInfo *res);
RZ_API void rz_serialize_anal_cc_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_cc_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RZ_NULLABLE RSerializeResultInfo *res);

RZ_API void rz_serialize_anal_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal);
RZ_API bool rz_serialize_anal_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnal *anal, RZ_NULLABLE RSerializeResultInfo *res);

// RzCore

RZ_API void rz_serialize_core_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core);
RZ_API bool rz_serialize_core_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE RSerializeResultInfo *res);

#endif //R2DB_R_SERIALIZE_H
