// SPDX-FileCopyrightText: 2014-2020 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"
#include "gdata.h"
#include "stream_file.h"
#include "tpi.h"

///////////////////////////////////////////////////////////////////////////////
static int parse_global(char *data, int data_size, SGlobal *global) {
	unsigned int read_bytes = 2;

	READ4(read_bytes, data_size, global->symtype, data, ut32);
	READ4(read_bytes, data_size, global->offset, data, ut32);
	READ2(read_bytes, data_size, global->segment, data, ut8);
	if (global->leaf_type == 0x110E) {
		parse_sctring(&global->name, (unsigned char *)data, &read_bytes, data_size);
	} else {
		READ1(read_bytes, data_size, global->name.size, data, ut8);
		init_scstring(&global->name, global->name.size, data);
	}

	return read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
void parse_gdata_stream(void *stream, RZ_STREAM_FILE *stream_file) {
	unsigned short len = 0;
	unsigned short leaf_type = 0;
	char *data = 0;
	SGDATAStream *data_stream = (SGDATAStream *)stream;
	SGlobal *global = 0;

	data_stream->globals_list = rz_list_new();
	while (1) {
		stream_file_read(stream_file, 2, (char *)&len);
		if (len == 0) {
			break;
		}
		data = (char *)malloc(len);
		if (!data) {
			return;
		}
		stream_file_read(stream_file, len, data);

		leaf_type = *(unsigned short *)(data);
		if ((leaf_type == 0x110E) || (leaf_type == 0x1009)) {
			global = (SGlobal *)malloc(sizeof(SGlobal));
			if (!global) {
				free(data);
				return;
			}
			global->leaf_type = leaf_type;
			parse_global(data + 2, len, global);
			rz_list_append(data_stream->globals_list, global);
		}
		free(data);
	}

	// TODO: for more fast access
	//	for g in self.globals:
	//        if not hasattr(g, 'symtype'): continue
	//        if g.symtype == 0:
	//            if g.name.startswith("_"):
	//                self.vars[g.name[1:]] = g
	//            else:
	//                self.vars[g.name] = g
	//        elif g.symtype == 2:
	//            self.funcs[g.name] = g
}

///////////////////////////////////////////////////////////////////////////////
void free_gdata_stream(void *stream) {
	SGDATAStream *data_stream = (SGDATAStream *)stream;
	SGlobal *global = 0;
	RzListIter *it = 0;

	it = rz_list_iterator(data_stream->globals_list);
	while (rz_list_iter_next(it)) {
		global = (SGlobal *)rz_list_iter_get(it);
		if (global->name.name) {
			free(global->name.name);
		}
		free(global);
	}
	rz_list_free(data_stream->globals_list);
}
