// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_pdb.h>
#include "dbi.h"
#include "gdata.h"
#include "omap.h"
#include "stream_pe.h"
#include "tpi.h"

#ifndef PDB_PRIVATE_INCLUDE_H_
#define PDB_PRIVATE_INCLUDE_H_
// OMAP
RZ_IPI bool parse_omap_stream(RzPdb *pdb, RzPdbMsfStream *stream);
RZ_IPI void free_omap_stream(RzPdbOmapStream *stream);
RZ_IPI int omap_remap(void *stream, int address);

// GDATA
RZ_IPI bool parse_gdata_stream(RzPdb *pdb, RzPdbMsfStream *stream);
RZ_IPI void free_gdata_stream(RzPdbGDataStream *stream);

// DBI
RZ_IPI bool parse_dbi_stream(RzPdb *pdb, RzPdbMsfStream *stream);
RZ_IPI void free_dbi_stream(RzPdbDbiStream *stream);

// PE
RZ_IPI bool parse_pe_stream(RzPdb *pdb, RzPdbMsfStream *stream);
RZ_IPI void free_pe_stream(RzPdbPeStream *stream);

// TPI
RZ_IPI bool parse_tpi_stream(RzPdb *pdb, RzPdbMsfStream *stream);
RZ_IPI RzPdbTpiType *parse_simple_type(RzPdbTpiStream *stream, ut32 idx);
RZ_IPI void free_tpi_stream(RzPdbTpiStream *stream);

#endif