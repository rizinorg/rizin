/* radare - LGPL - Copyright 2019 - pancake */

#include <rz_core.h>

RZ_API RzCoreItem *rz_core_item_at (RzCore *core, ut64 addr) {
	RzCoreItem *ci = RZ_NEW0 (RzCoreItem);
	ci->addr = addr;
	RzIOMap *map = rz_io_map_get (core->io, addr);
	if (map) {
		ci->perm = map->perm;
		// TODO: honor section perms too?
		if (map->perm & RZ_PERM_X) {
			// if theres a meta consider it data
			ut64 size;
			RzAnalMetaItem *item = rz_meta_get_at (core->anal, addr, RZ_META_TYPE_ANY, &size);
			if (item) {
				switch (item->type) {
				case RZ_META_TYPE_DATA:
					ci->type = "data";
					ci->size = size;
					ci->data = rz_core_cmd_strf (core, "pdi 1 @e:asm.flags=0@e:asm.lines=0@e:scr.color=0@0x%08"PFMT64x, addr);
					rz_str_trim (ci->data);
					break;
				case RZ_META_TYPE_FORMAT:
					ci->type = "format"; // struct :?
					ci->size = size;
					break;
				case RZ_META_TYPE_STRING:
					ci->type = "string";
					ci->size = size;
					break;
				default:
					break;
				}
				if (item->str) {
					if (!ci->data) {
						ci->data = strdup (item->str);
					}
				}
			}
		}
	}
	RzAnalFunction *fcn = rz_anal_get_fcn_in (core->anal, addr, 1);
	if (fcn) {
		ci->fcnname = strdup (fcn->name);
	}
	RzBinObject *o = rz_bin_cur_object (core->bin);
	RzBinSection *sec = rz_bin_get_section_at (o, addr, core->io->va);
	if (sec) {
		ci->sectname = strdup (sec->name);
	}
	if (!ci->data) {
		RzAnalOp* op = rz_core_anal_op (core, addr, RZ_ANAL_OP_MASK_ESIL | RZ_ANAL_OP_MASK_HINT);
		if (op) {
			if (!ci->data) {
				if (op->mnemonic) {
					ci->data = strdup (op->mnemonic);
				} else {
					ci->data = rz_core_cmd_strf (core, "pi 1 @e:scr.color=0@0x%08"PFMT64x, addr);
					rz_str_trim (ci->data);
				}
			}
			ci->size = op->size;
			rz_anal_op_free (op);
		}
	}
	char *cmt = rz_core_cmd_strf (core, "CC.@0x%08"PFMT64x, addr);
	if (cmt) {
		if (*cmt) {
			ci->comment = strdup (cmt);
			rz_str_trim (ci->comment);
		}
		free (cmt);
	}
	if (!ci->type) {
		ci->type = "code";
	}
	ci->next = ci->addr + ci->size;
	char *prev = rz_core_cmd_strf (core, "pd -1@e:asm.lines=0~[0]");
	rz_str_trim (prev);
	ci->prev = rz_num_get (NULL, prev);
	free (prev);
	return ci;
}

RZ_API void rz_core_item_free (RzCoreItem *ci) {
	free (ci->data);
	free (ci);
}

