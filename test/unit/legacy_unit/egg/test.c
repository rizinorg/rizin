// SPDX-FileCopyrightText: 2011-2012 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_egg.h>
#include <getopt.h>

static int usage(void) {
	eprintf("./test [-a x86|arm] [-b 32|64] hi.r\n");
	return 1;
}

int main(int argc, char **argv) {
	const char *arch = "x86";
	int bits = 32;
	int c, i;
	RzBuffer *b;
	RzEgg *egg = rz_egg_new();

	while ((c = getopt(argc, argv, "ha:b:")) != -1) {
		switch (c) {
		case 'a':
			arch = optarg;
			break;
		case 'b':
			bits = atoi(optarg);
			break;
		case 'h':
			return usage();
		}
	}

	if (optind == argc)
		return usage();

	rz_egg_setup(egg, arch, bits, 0, 0);
	rz_egg_include(egg, argv[optind], 0);
	rz_egg_compile(egg);
	rz_egg_assemble(egg);
	//rz_egg_setup (egg, "x86", 32, 0, 0);
	//rz_egg_setup (egg, "x86", 64, 0, 0);

	//printf ("src (%s)\n", rz_egg_get_source (egg));
	printf("asm (%s)\n", rz_egg_get_assembly(egg));
	b = rz_egg_get_bin(egg);
	if (b == NULL) {
		eprintf("Cannot assemble egg :(\n");
	} else {
		printf("BUFFER : %d\n", b->length);
		for (i = 0; i < b->length; i++) {
			printf("%02x", b->buf[i]);
		}
		printf("\n");
	}
#if VALA
	var egg = new RzEgg();
	egg.include("test.r", 'r');
	egg.compile();
#endif
	rz_egg_free(egg);
	return 0;
}
