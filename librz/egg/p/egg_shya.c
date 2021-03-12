// SPDX-FileCopyrightText: 2011 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
/* shoorisu yagana shellcode encoder */
/* wishlist:
 - fork/setuid
 - polimorphic
 - mmap to skip w^x
 - avoid 00 or alphanumeric
 - random cipher algorithm
 - trash
 - antidisasm tricks
 - virtual machine
*/

static RzBuffer *build(RzEgg *egg) {
	RzBuffer *buf = rz_buf_new();
	char *key = rz_egg_option_get(egg, "key");
	char *seed = rz_egg_option_get(egg, "seed");
	eprintf("TODO: shoorisu yagana shellcode encoder\n");
	free(key);
	free(seed);
	return buf;
}

RzEggPlugin rz_egg_plugin_shya = {
	.name = "shya",
	.type = RZ_EGG_PLUGIN_ENCODER,
	.desc = "shoorisu yagana",
	.build = (void *)build
};

#if 0
#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_EGG,
	.data = &rz_egg_plugin_shya,
	.version = RZ_VERSION
};
#endif
#endif
