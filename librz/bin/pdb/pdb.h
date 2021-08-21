// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_pdb.h>

#ifndef PDB_PRIVATE_INCLUDE_H_
#define PDB_PRIVATE_INCLUDE_H_
// OMAP
RZ_IPI bool parse_omap_stream(RzPdb *pdb, MsfStream *stream);
RZ_IPI void free_omap_stream(OmapStream *stream);
RZ_IPI int omap_remap(void *stream, int address);

// GDATA
RZ_IPI bool parse_gdata_stream(RzPdb *pdb, MsfStream *stream);
RZ_IPI void free_gdata_stream(GDataStream *stream);

// DBI
RZ_IPI bool parse_dbi_stream(RzPdb *pdb, MsfStream *stream);
RZ_IPI void free_dbi_stream(DbiStream *stream);

// PE
RZ_IPI bool parse_pe_stream(RzPdb *pdb, MsfStream *stream);
RZ_IPI void free_pe_stream(PeStream *stream);

// TPI
RZ_IPI bool parse_tpi_stream(RzPdb *pdb, MsfStream *stream);
RZ_IPI TpiType *parse_simple_type(TpiStream *stream, ut32 idx);
RZ_IPI void free_tpi_stream(TpiStream *stream);

#endif