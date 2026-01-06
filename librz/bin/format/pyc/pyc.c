// SPDX-FileCopyrightText: 2016-2020 c0riolis
// SPDX-FileCopyrightText: 2016-2020 x0urc3
// SPDX-License-Identifier: LGPL-3.0-only

#include "pyc.h"
#include "marshal.h"

bool pyc_get_sections_symbols(RzBinPycObj *pyc, RzPVector /*<RzBinSection *>*/ *sections, RzPVector /*<RzBinSymbol *>*/ *symbols, RzList /*<pyc_code_object *>*/ *cobjs, RzBuffer *buf, ut32 magic) {
	return get_sections_symbols_from_code_objects(pyc, buf, sections, symbols, cobjs, magic);
}

static bool pyc_is_object(ut8 b, pyc_marshal_type type) {
	return b == type;
}

bool pyc_is_code(ut8 b, ut32 magic) {
	if ((magic == 0x00949494 || magic == 0x0099be2a || magic == 0x0099be3a || magic == 0x00999901) && (pyc_is_object((b & ~FLAG_REF), TYPE_CODE_v0))) {
		// TYPE_CODE_V0 for Python < 1.0
		return true;
	}
	if (pyc_is_object((b & ~FLAG_REF), TYPE_CODE_v1)) {
		return true;
	}
	return false;
}
RZ_API RzStructuredData *rz_bin_pyc_structure(RzBinPycObj *pyc) {
	rz_return_val_if_fail(pyc, NULL);
	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}
	RzStructuredData *pyc_data = rz_structured_data_map_add_map(info, "pyc");
	if (!pyc_data) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add_unsigned(pyc_data, "magic", (ut64)pyc->version.magic, true);
	if (pyc->version.version) {
		rz_structured_data_map_add_string(pyc_data, "version", pyc->version.version);
	}
	if (pyc->version.revision) {
		rz_structured_data_map_add_string(pyc_data, "revision", pyc->version.revision);
	}
	if (pyc->code_start_offset > 0) {
		rz_structured_data_map_add_unsigned(pyc_data, "code_start_offset", pyc->code_start_offset, true);
	}
	return info;
}