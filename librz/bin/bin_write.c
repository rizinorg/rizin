// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>

/* XXX Implement rz__bin_wr_scn_{   set, del   } instead */
RZ_API ut64 rz_bin_wr_scn_resize(RzBin *bin, const char *name, ut64 size) {
	RzBinFile *bf = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	if (plugin && plugin->write && plugin->write->scn_resize) {
		return plugin->write->scn_resize(bf, name, size);
	}
	return false;
}

RZ_API bool rz_bin_wr_scn_perms(RzBin *bin, const char *name, int perms) {
	RzBinFile *bf = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	if (plugin && plugin->write && plugin->write->scn_perms) {
		return plugin->write->scn_perms(bf, name, perms);
	}
	return false;
}

RZ_API bool rz_bin_wr_rpath_del(RzBin *bin) {
	RzBinFile *bf = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	if (plugin && plugin->write && plugin->write->rpath_del) {
		return plugin->write->rpath_del(bf);
	}
	return false;
}

RZ_API bool rz_bin_wr_output(RzBin *bin, const char *filename) {
	rz_return_val_if_fail(bin && filename, false);
	RzBinFile *bf = rz_bin_cur(bin);
	if (!bf || !bf->buf) {
		return false;
	}
	ut64 tmpsz;
	const ut8 *tmp = rz_buf_data(bf->buf, &tmpsz);
	return rz_file_dump(filename, tmp, tmpsz, 0);
}

RZ_API bool rz_bin_wr_entry(RzBin *bin, ut64 addr) {
	RzBinFile *bf = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	if (plugin && plugin->write && plugin->write->entry) {
		return plugin->write->entry(bf, addr);
	}
	return false;
}

RZ_API bool rz_bin_wr_addlib(RzBin *bin, const char *lib) {
	RzBinFile *bf = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	if (plugin && plugin->write && plugin->write->addlib) {
		return plugin->write->addlib(bin->cur, lib);
	}
	return false;
}
