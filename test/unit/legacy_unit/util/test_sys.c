#include <stdio.h>
#include "rz_util.h"

int main(int argc, char *argv[]) {
	int len = 0;
	char *sterr;
	char *output = rz_sys_cmd_str("find /etc", 0, &len);
	int result = rz_sys_cmd_str_full("find /etc", 0, &output, &len, &sterr);
	printf("RESULT: %d\n", result);
	printf("STDOUT\n");
	printf("%s", output);
	printf("STDERR\n");
	printf("%s", sterr);
	printf("bytes in STDOUT: %d\n", len);
	return 0;
}
