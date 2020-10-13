/* radare - LGPL - Copyright 2013-2016 - pancake */

#include <rz_bin.h>

RZ_IPI bool rz_bin_lang_swift(RzBinFile *binfile) {
	RzBinObject *o = binfile? binfile->o: NULL;
	RzBinInfo *info = o? o->info: NULL;
	RzBinSymbol *sym;
	RzListIter *iter;
	if (info) {
		rz_list_foreach (o->symbols, iter, sym) {
			if (sym->name && strstr (sym->name, "swift_once")) {
				info->lang = "swift";
				return true;
			}
		}
	}
	return false;
}
