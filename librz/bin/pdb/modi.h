// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MODI_H
#define MODI_H

#include <rz_util/rz_buf.h>
#include "dbi.h"
#include "pdb.h"

#define CV_SIGNATURE_C6       0L // Actual signature is >64K
#define CV_SIGNATURE_C7       1L // First explicit signature
#define CV_SIGNATURE_C11      2L // C11 (vc5.x) 32-bit types
#define CV_SIGNATURE_C13      4L // C13 (vc7.x) zero terminated names
#define CV_SIGNATURE_RESERVED 5L // All signatures from 5 to 64K are reserved

RZ_IPI bool PDBModuleInfo_parse(const RzPdb *pdb, const PDB_DBIModule *m, PDBModuleInfo *modi);

#endif // MODI_H
