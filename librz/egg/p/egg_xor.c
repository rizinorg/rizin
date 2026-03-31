// SPDX-FileCopyrightText: 2011-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/* based on @santitox patch */
#include <rz_egg.h>

#define DEFAULT_XOR_KEY "0xFF"

static RzBuffer *build(RzEgg *egg) {
	RzBuffer *buf, *sc;
	ut8 aux[32], nkey;
	const char *default_key = DEFAULT_XOR_KEY;
	char *key = rz_egg_option_get(egg, "key");

	if (!key || !*key) {
		free(key);
		key = rz_str_dup(default_key);
		eprintf("XOR key not provided. Using (%s) as the key\n", key);
	}
	nkey = rz_num_math(NULL, key);
	if (nkey == 0) {
		eprintf("Invalid key (%s)\n", key);
		free(key);
		return false;
	}
	if (nkey != (nkey & 0xff)) {
		nkey &= 0xff;
		eprintf("xor key wrapped to (%d)\n", nkey);
	}
	if (rz_buf_size(egg->bin) > 240) { // XXX
		eprintf("shellcode is too long :(\n");
		free(key);
		return NULL;
	}
	sc = egg->bin; // hack
	if (!rz_buf_size(sc)) {
		eprintf("No shellcode found!\n");
		free(key);
		return NULL;
	}

	for (size_t i = 0; i < rz_buf_size(sc); i++) {
		// eprintf ("%02x -> %02x\n", sc->buf[i], sc->buf[i] ^nkey);
		ut8 tmp;
		if (!rz_buf_read8_at(sc, i, &tmp)) {
			free(key);
			return NULL;
		}

		if ((tmp ^ nkey) == 0) {
			eprintf("This xor key generates null bytes. Try again.\n");
			free(key);
			return NULL;
		}
	}

	buf = rz_buf_new_with_bytes(NULL, 0);
	sc = rz_buf_new_with_bytes(NULL, 0);

	// TODO: alphanumeric? :D
	// This is the x86-32/64 xor encoder
	rz_buf_append_buf(sc, egg->bin);
	if (egg->arch == RZ_SYS_ARCH_X86) {
#define STUBLEN 18
		ut8 stub[STUBLEN] =
			"\xe8\xff\xff\xff\xff" // call $$+4
			"\xc1" // ffc1 = inc ecx
			"\x5e" // pop esi
			"\x48\x83\xc6\x0d" // add rsi, xx ... 64bit
			// loop0:
			"\x30\x1e" // xor [esi], bl
			"\x48\xff\xc6" // inc rsi
			"\xe2\xf9"; // loop loop0
		// ecx = length
		aux[0] = 0x6a; // push length
		aux[1] = rz_buf_size(sc);
		aux[2] = 0x59; // pop ecx
		// ebx = key
		aux[3] = 0x6a; // push key
		aux[4] = nkey;
		aux[5] = 0x5b; // pop ebx
		rz_buf_set_bytes(buf, aux, 6);

		rz_buf_append_bytes(buf, stub, STUBLEN);

		for (size_t i = 0; i < rz_buf_size(sc); i++) {
			ut8 v;
			if (!rz_buf_read8_at(sc, i, &v)) {
				free(key);
				return NULL;
			}

			v ^= nkey;
			rz_buf_write_at(sc, i, &v, sizeof(v));
		}
		rz_buf_append_buf(buf, sc);
	}
	rz_buf_free(sc);
	free(key);
	return buf;
}

// TODO: rename plugin to run
RzEggPlugin rz_egg_plugin_xor = {
	.name = "xor",
	.type = RZ_EGG_PLUGIN_ENCODER,
	.desc = "xor encoder for shellcode",
	.build = (void *)build
};

#if 0
#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_EGG,
	.data = &rz_egg_plugin_xor,
	.version = RZ_VERSION
};
#endif
#endif
