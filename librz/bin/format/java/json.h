// SPDX-License-Identifier: Apache-2.0
#ifndef JAVA_JSON_H
#define JAVA_JSON_H

#include "class.h"

RZ_API bool rz_bin_java_get_field_json_definitions(RzBinJavaObj *bin, PJ *j);
RZ_API bool rz_bin_java_get_method_json_definitions(RzBinJavaObj *bin, PJ *j);
RZ_API bool rz_bin_java_get_import_json_definitions(RzBinJavaObj *bin, PJ *j);
RZ_API bool rz_bin_java_get_interface_json_definitions(RzBinJavaObj *bin, PJ *j);
RZ_API bool rz_bin_java_get_fm_type_definition_json(RzBinJavaObj *bin, RzBinJavaField *fm_type, int is_method, PJ *j);
RZ_API bool rz_bin_java_get_field_json_definition(RzBinJavaObj *bin, RzBinJavaField *fm_type, PJ *j);
RZ_API bool rz_bin_java_get_method_json_definition(RzBinJavaObj *bin, RzBinJavaField *fm_type, PJ *j);
RZ_API bool rz_bin_java_get_bin_obj_json(RzBinJavaObj *bin, PJ *j);

#endif /* JAVA_JSON_H */
