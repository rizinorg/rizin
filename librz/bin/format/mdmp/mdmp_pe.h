// SPDX-FileCopyrightText: 2016 Davis
// SPDX-FileCopyrightText: 2016 Alex Kornitzer <alex.kornitzer@countercept.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MDMP_PE_H
#define MDMP_PE_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "pe/pe.h"

#include "mdmp_specs.h"

struct PE_(rz_bin_mdmp_pe_bin) {
	ut64 vaddr;
	ut64 paddr;
	struct PE_(rz_bin_pe_obj_t) * bin;
};

RzList *PE_(rz_bin_mdmp_pe_get_entrypoint)(struct PE_(rz_bin_mdmp_pe_bin) * pe_bin);
RzList *PE_(rz_bin_mdmp_pe_get_imports)(struct PE_(rz_bin_mdmp_pe_bin) * pe_bin);
RzList *PE_(rz_bin_mdmp_pe_get_sections)(struct PE_(rz_bin_mdmp_pe_bin) * pe_bin);
RzList *PE_(rz_bin_mdmp_pe_get_symbols)(RzBin *rbin, struct PE_(rz_bin_mdmp_pe_bin) * pe_bin);

#endif /* MDMP_PE_H */
