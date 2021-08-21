// SPDX-FileCopyrightText: 2014-2020 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

static void parse_gdata_global(GDataGlobal *global, RzBuffer *buf, ut32 *read_len) {
	global->symtype = rz_buf_read_le32(buf);
	global->offset = rz_buf_read_le32(buf);
	*read_len += sizeof(ut32) * 2;
	global->segment = rz_buf_read_le16(buf);
	*read_len += sizeof(ut16);
	if (global->leaf_type == 0x110E) {
		global->name = rz_buf_get_string(buf, rz_buf_tell(buf));
		ut16 len = strlen(global->name) + 1;
		global->name_len = len;
		rz_buf_seek(buf, rz_buf_tell(buf) + len, RZ_BUF_SET);
		*read_len += len;
	} else {
		global->name_len = rz_buf_read8(buf);
		*read_len += sizeof(ut8);
	}
	if ((*read_len % 4)) {
		ut16 remain = 4 - (*read_len % 4);
		rz_buf_seek(buf, rz_buf_tell(buf) + remain, RZ_BUF_SET);
		read_len += remain;
	}
}

RZ_IPI bool parse_gdata_stream(RzPdb *pdb, MsfStream *stream) {
	rz_return_val_if_fail(pdb && stream, false);
	if (!pdb->s_gdata) {
		pdb->s_gdata = RZ_NEW0(GDataStream);
	}
	GDataStream *s = pdb->s_gdata;
	RzBuffer *buf = stream->stream_data;
	s->global_list = rz_list_new();
	if (!s->global_list) {
		return false;
	}
	ut16 len;
	while (true) {
		ut32 read_len = 0;
		len = rz_buf_read_le16(buf);
		read_len += sizeof(ut16);
		if (len == 0 || len == UT16_MAX) {
			break;
		}
		ut16 leaf_type = rz_buf_read_le16(buf);
		read_len += sizeof(ut16);
		if (leaf_type == 0x110E || leaf_type == 0x1009) {
			GDataGlobal *global = RZ_NEW0(GDataGlobal);
			if (!global) {
				goto skip;
			}
			global->leaf_type = leaf_type;
			parse_gdata_global(global, buf, &read_len);
			rz_list_append(s->global_list, global);
			continue;
		}
	skip:
		rz_buf_seek(buf, rz_buf_tell(buf) + len - sizeof(ut16), RZ_BUF_SET);
	}
	return true;
}

RZ_IPI void free_gdata_stream(GDataStream *stream) {
	GDataGlobal *global;
	RzListIter *it;
	rz_list_foreach (stream->global_list, it, global) {
		RZ_FREE(global->name);
		RZ_FREE(global);
	}
	rz_list_free(stream->global_list);
}
