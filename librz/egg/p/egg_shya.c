/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
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

static RBuffer *build (RzEgg *egg) {
	RBuffer *buf = rz_buf_new ();
	char *key = rz_egg_option_get (egg, "key");
	char *seed = rz_egg_option_get (egg, "seed");
	eprintf ("TODO: shoorisu yagana shellcode encoder\n");
	free (key);
	free (seed);
	return buf;
}

RzEggPlugin rz_egg_plugin_shya = {
	.name = "shya",
	.type = R_EGG_PLUGIN_ENCODER,
	.desc = "shoorisu yagana",
	.build = (void *)build
};

#if 0
#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &rz_egg_plugin_shya,
	.version = R2_VERSION
};
#endif
#endif
