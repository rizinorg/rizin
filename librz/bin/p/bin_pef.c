// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

static bool check_buffer(RzBuffer *b) {
	// TODO
	if (rz_buf_size(b) >= 4) {
		ut8 buf[4] = { 0 };
		if (rz_buf_read_at(b, 0, buf, 4)) {
			if (!memcmp(buf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp(buf, "\xfe\xed\xfa\xce", 4)) {
				return true;
			}
		}
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && buf, false);
	// TODO
	return false;
}

static ut64 baddr(RzBinFile *bf) {
	rz_return_val_if_fail(bf, UT64_MAX);
	// TODO
	return UT64_MAX;
}

static RzList /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	// TODO
	return NULL;
}

static RzList /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	// TODO
	return NULL;
}

static RzList /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}
	// TODO
	return ret;
}

static RzList /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	RzList *ret = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	// TODO
	return ret;
}
static RzList /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	RzList *ret = rz_list_newf((RzListFree)rz_bin_import_free);
	if (!ret) {
		return NULL;
	}
	// TODO
	return ret;
}

static RzList /*<RzBinReloc *>*/ *relocs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	RzList *ret = ret = rz_list_newf(free); // TODO: right free function?
	if (!ret) {
		return NULL;
	}
	// TODO
	return ret;
}

static RzList /*<char *>*/ *libs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	RzList *ret = ret = rz_list_newf(free); // TODO: right free function?
	if (!ret) {
			return NULL;
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	// TODO
	ret->rclass = strdup("pef");
	ret->os = strdup("darwin");
	return ret;
}

RzBinPlugin rz_bin_plugin_pef = {
	.name = "pef",
	.desc = "Preferred Executable Format (Classic Mac OS)",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
	.maps = &maps,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.relocs = &relocs
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_pef,
	.version = RZ_VERSION
};
#endif
