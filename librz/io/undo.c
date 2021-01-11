// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>

#if 0
* TODO:
* - make path of indirections shortr (io->undo.foo is slow) */
* - Plugin changes in write and seeks
* - Per-fd history log
#endif

RZ_API int rz_io_undo_init(RzIO *io) {
	/* seek undo */
	rz_io_sundo_reset (io);
	return true;
}

RZ_API void rz_io_undo_enable(RzIO *io, bool s) {
	io->undo.s_enable = s;
}

/* undo seekz */

RZ_API RzIOUndos *rz_io_sundo(RzIO *io, ut64 offset) {
	if (!io->undo.s_enable || !io->undo.undos) {
		return NULL;
	}

	RzIOUndos *undo;
	/* No redos yet, store the current seek so we can redo to it. */
	if (!io->undo.redos) {
		undo = &io->undo.seek[io->undo.idx];
		undo->off = offset;
		undo->cursor = 0;
	}

	io->undo.idx = (io->undo.idx - 1 + RZ_IO_UNDOS) % RZ_IO_UNDOS;
	io->undo.undos--;
	io->undo.redos++;

	undo = &io->undo.seek[io->undo.idx];
	RzIOMap *map = rz_io_map_get (io, undo->off);
	if (!map || (map->delta == map->itv.addr)) {
		io->off = undo->off;
	} else {
		io->off = undo->off - (map->itv.addr + map->delta);
	}
	return undo;
}

RZ_API RzIOUndos *rz_io_sundo_redo(RzIO *io) {
	RzIOUndos *undo;
	RzIOMap *map;

	if (!io->undo.s_enable || !io->undo.redos) {
		return NULL;
	}

	io->undo.idx = (io->undo.idx + 1) % RZ_IO_UNDOS;
	io->undo.undos++;
	io->undo.redos--;

	undo = &io->undo.seek[io->undo.idx];
	map = rz_io_map_get (io, undo->off);
	if (!map || (map->delta == map->itv.addr)) {
		io->off = undo->off;
	} else {
		io->off = undo->off - map->itv.addr + map->delta;
	}
	return undo;
}

RZ_API void rz_io_sundo_push(RzIO *io, ut64 off, int cursor) {
	RzIOUndos *undo;
	if (!io->undo.s_enable) {
		return;
	}
	// don't push duplicate seek
	if (io->undo.undos > 0) {
		undo = &io->undo.seek[(io->undo.idx - 1 + RZ_IO_UNDOS) % RZ_IO_UNDOS];
		if (undo->off == off && undo->cursor == cursor) {
			return;
		}
	}

	undo = &io->undo.seek[io->undo.idx];
	undo->off = off;
	undo->cursor = cursor;
	io->undo.idx = (io->undo.idx + 1) % RZ_IO_UNDOS;
	/* Only RZ_IO_UNDOS - 1 undos can be used because rz_io_sundo_undo () must
	 * push the current position for redo as well, which takes one entry in
	 * the table. */
	if (io->undo.undos < RZ_IO_UNDOS - 1) {
		io->undo.undos++;
	}
	/* We only have linear undo/redo, no tree. So after this new possible
	 * undo, all redos are lost. */
	io->undo.redos = 0;
}

RZ_API void rz_io_sundo_reset(RzIO *io) {
	io->undo.idx = 0;
	io->undo.undos = 0;
	io->undo.redos = 0;
}

RZ_API RzList *rz_io_sundo_list(RzIO *io, int mode) {
	int idx, undos, redos, i, j, start, end;
	RzList* list = NULL;

	if (mode == '!') {
		mode = 0;
	}
	if (!io->undo.s_enable) {
		return NULL;
	}
	undos = io->undo.undos;
	redos = io->undo.redos;

	idx = io->undo.idx;
	start = (idx - undos + RZ_IO_UNDOS) % RZ_IO_UNDOS;
	end = (idx + redos + 1 - 1) % RZ_IO_UNDOS; // +1 slot for current position, -1 due to inclusive end

	j = 0;
	switch (mode) {
	case 'j':
		io->cb_printf ("[");
		break;
	case 0:
		list = rz_list_newf (free);
		break;
	}
	for (i = start;/* condition at the end of loop */; i = (i + 1) % RZ_IO_UNDOS) {
		int idx = (j < undos)? undos - j - 1: j - undos - 1;
		RzIOUndos *undo = &io->undo.seek[i];
		ut64 addr = undo->off;
		bool notLast = (j + 1 < undos);
		switch (mode) {
		case '=':
			if (j < undos) {
				io->cb_printf ("0x%"PFMT64x"%s", addr, notLast? " > ": "");
			}
			break;
		case '*':
			if (j < undos) {
				io->cb_printf ("f undo_%d @ 0x%"PFMT64x"\n", idx, addr);
			} else if (j == undos && j != 0 && redos != 0) {
				io->cb_printf ("# Current undo/redo position.\n");
			} else if (j != undos) {
				io->cb_printf ("f redo_%d @ 0x%"PFMT64x"\n", idx, addr);
			}
			break;
		case 0:
			if (list) {
				RzIOUndos  *u = RZ_NEW0 (RzIOUndos);
				if (u) {
					if (!(j == undos && redos == 0)) {
						// Current position gets pushed before seek, so there
						// is no valid offset when we are at the end of list.
						memcpy (u, undo, sizeof (RzIOUndos));
					} else {
						u->off = io->off;
					}
					rz_list_append (list, u);
				}
			}
			break;
		}
		j++;
		if (i == end) {
			break;
		}
	}
	switch (mode) {
	case '=':
		io->cb_printf ("\n");
		break;
	}
	return list;
}