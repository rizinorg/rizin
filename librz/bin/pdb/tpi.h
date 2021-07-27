// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef TPI_H
#define TPI_H

void init_tpi_stream(STpiStream *tpi_stream);

int parse_tpi_stream(void *parsed_pdb_stream, RZ_STREAM_FILE *stream);

// TODO: Remove to separate file
int parse_scstring(SCString *sctr, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len);

// use rizin types here (ut16 instead of unsigned short, ut32 for unsigned int ..)
void init_scstring(SCString *cstr, unsigned int size, char *name);
// Get SType data by type_info->type_index
RZ_API SType *rz_bin_pdb_stype_by_index(ut32 index);
RZ_API char *rz_bin_pdb_calling_convention_as_string(ECV_CALL idx);
RZ_IPI STypeInfo parse_simple_type(ut32 idx);
#endif // TPI_H
