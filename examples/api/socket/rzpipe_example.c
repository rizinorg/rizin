// SPDX-FileCopyrightText: 2025 Maijin <Maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Example: Communication with Rizin using RzPipe
 *
 * This example demonstrates how to spawn a Rizin utility (rz-asm)
 * and communicate with it using the RzPipe IPC mechanism.
 */

#include <rz_socket.h>
#include <rz_util.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	// RzPipe expects the child to write a synchronization byte (0x00)
	// when it's ready. For a non-interactive utility like rz-asm,
	// we can simulate this by prepending a printf.
	const char *cmd = "printf '\\0'; ./build/binrz/rz-asm/rz-asm -a x86 -b 32 'push eax'";

	printf("Opening pipe to: %s\n", cmd);

	// rzpipe_open spawns the command and sets up pipes for communication.
	RzPipe *p = rzpipe_open(cmd);
	if (!p) {
		fprintf(stderr, "Failed to open rzpipe. Make sure 'rz-asm' is in your PATH.\n");
		return 1;
	}

	// rzpipe_read reads the output from the spawned process.
	char *res = rzpipe_read(p);
	if (res) {
		printf("Result from rz-asm: %s", res);
		free(res);
	} else {
		fprintf(stderr, "Failed to read from rzpipe.\n");
	}

	// Close the pipe and clean up.
	rzpipe_close(p);

	return 0;
}
