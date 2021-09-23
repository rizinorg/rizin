// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DBI_H
#define DBI_H

void init_dbi_stream(SDbiStream *dbi_stream);
void parse_dbi_stream(void *parsed_pdb_stream, RZ_STREAM_FILE *stream_file);

#endif // DBI_H
