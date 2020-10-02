/* radare - LGPL - Copyright 2013 - condret */

#include <rz_io.h>
#include <rz_anal.h>

void meta_gb_bankswitch_cmt(RzAnal *a, ut64 addr, ut16 ldarg) {
	if(0x1fff <ldarg && ldarg < 0x4000 && addr < 0x4000)
		rz_meta_set_string (a, RZ_META_TYPE_COMMENT, addr, "Bankswitch");
	if(0x6000 > ldarg && ldarg > 0x3fff)
		rz_meta_set_string(a, RZ_META_TYPE_COMMENT, addr, "Ramswitch");
}
