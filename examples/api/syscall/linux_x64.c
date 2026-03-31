// SPDX-FileCopyrightText: 2025 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_syscall.h>
#include <rz_util.h>
#include <stdio.h>

int main(void) {
	RzPath *path = rz_path_new();
	if (!path) {
		fprintf(stderr, "Failed to create RzPath\n");
		return 1;
	}

	RzSyscall *sc = rz_syscall_new();
	if (!sc) {
		fprintf(stderr, "Failed to create RzSyscall\n");
		rz_path_free(path);
		return 1;
	}

	// Setup for Linux x86_64
	if (!rz_syscall_setup(sc, path, "x86", 64, NULL, "linux")) {
		fprintf(stderr, "Failed to setup RzSyscall for linux-x86-64\n");
		rz_syscall_free(sc);
		rz_path_free(path);
		return 1;
	}

	// Resolve syscall number 1 (write)
	int syscall_num = 1;
	RzSyscallItem *item = rz_syscall_get(sc, syscall_num, -1);
	if (item) {
		printf("Syscall %d on Linux x86_64 is '%s'\n", syscall_num, item->name);
		rz_syscall_item_free(item);
	} else {
		printf("Syscall %d not found\n", syscall_num);
	}

	// Resolve syscall name 'open'
	int num;
	if (rz_syscall_get_num(sc, "open", &num)) {
		printf("Syscall 'open' on Linux x86_64 is %d\n", num);
	} else {
		printf("Syscall 'open' not found\n");
	}

	rz_syscall_free(sc);
	rz_path_free(path);
	return 0;
}
