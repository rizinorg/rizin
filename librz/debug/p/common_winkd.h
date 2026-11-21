// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <winkd.h>

RZ_OWN Profile *winkd_build_profile(RzTypeDB *db);
bool winkd_download_module_and_pdb(WindModule *module, const char *symserver, const char *symstore, char **exepath, char **pdbpath);
