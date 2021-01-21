#include <stdio.h>
#include <rz_regex.h>

int _main(void) {
	RzRegex rx;
	int rc = rz_regex_comp(&rx, "^hi", RZ_REGEX_NOSUB);
	if (rc) {
		printf("error\n");

	} else {
		rc = rz_regex_exec(&rx, "patata", 0, 0, 0);
		printf("out = %d\n", rc);

		rc = rz_regex_exec(&rx, "hillow", 0, 0, 0);
		printf("out = %d\n", rc);
	}
	rz_regex_free(&rx);
	return 0;
}

static void test_or(void) {
	RzRegex *rx = rz_regex_new("(eax|ebx)", "e");
	printf("result (%s) = %d\n", "mov eax", rz_regex_match("(eax|ebx)", "e", "mov eax"));
	printf("result (%s) = %d\n", "mov ebx", rz_regex_match("(eax|ebx)", "e", "mov ebx"));
	printf("result (%s) = %d\n", "mov eax", rz_regex_match("(eax|ebx)", "e", "mov ecx"));
	printf("result (%s) = %d\n", "mov ebx", rz_regex_match("(eax|ecx)", "e", "mov ebx"));
	printf("result (%s) = %d\n", "mov eax", rz_regex_check(rx, "mov eax"));
	printf("result (%s) = %d\n", "mov ebx", rz_regex_check(rx, "mov ebx"));
	printf("result (%s) = %d\n", "mov eax", rz_regex_exec(rx, "mov eax", 0, 0, 1));
	printf("result (%s) = %d\n", "mov ebx", rz_regex_exec(rx, "mov ebx", 0, 0, 1));
	rz_regex_free(rx);
}

int main(int argc, char **argv) {
	const char *needle = "^hi";
	const char *haystack_1 = "patata";
	const char *haystack_2 = "hillow";
	if (argc > 3) {
		needle = argv[1];
		haystack_1 = argv[2];
		haystack_2 = argv[3];
	} else
		printf("Using default values\n");
	RzRegex *rx = rz_regex_new(needle, "");
	if (rx) {
		int res = rz_regex_exec(rx, haystack_1, 0, 0, 0);
		printf("result (%s) = %d\n", haystack_1, res);
		res = rz_regex_exec(rx, haystack_2, 0, 0, 0);
		printf("result (%s) = %d\n", haystack_2, res);
		rz_regex_free(rx);
	} else
		printf("oops, cannot compile regexp\n");
	test_or();
	return 0;
}
