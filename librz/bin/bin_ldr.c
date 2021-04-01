// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

RZ_API bool rz_bin_loader(RzBin *bin, ut32 boid, int options) {
	// uses a plugin from bin.loader eval var and loads the selected binobj
	// options must be used to specify if we want to load the libraries of the libraries recursively
	// or resolve the PLT from the binary or not
	// this requires io.cache
	return false;
}

RZ_API bool rz_bin_loader_library(RzBin *bin, const char *name, int options) {
	// options specify if we want to resolve the symbols and fill the PLT
	// this is obviously a problem if we have multiple libs that depend
	// on symbols recursively, and that's where the LD_BIND_NOW option comes to the action
	// the plt must be modified by using io.cache writes
	return false;
}

RZ_API bool rz_bin_loader_option(RzBin *bin, const char *key, const char *data) {
	// key value storage to specify LD_LIBRARY_PATH LD_BIND_NOW and other useful options
	// RzCore or rizin can set those vars from the environment if desired
	return false;
}

RZ_API bool rz_bin_loader_unload(RzBin *bin) {
	// unload all libraries and drop PLT changes
	return false;
}
