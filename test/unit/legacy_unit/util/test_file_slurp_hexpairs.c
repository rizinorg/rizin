#include <stdio.h>
#include <rz_util.h>

int main(int argc, char *argv[]) {
	int i, size;
	ut8 *ret = rz_file_slurp_hexpairs("hexpairs.txt", &size);

	if (ret) {
		for (i = 0; i < size; i++)
			putchar(ret[i]);
	} else
		printf("Error processing the file.\n");

	return 0;
}
