// gcc test.c `pkg-config --cflags rz_hash` `pkg-config --libs rz_hash`
#include <rz_msg_digest.h>

void do_md5(const char *string) {
	char *result = rz_msg_digest_calculate_small_block_string("md5", string, strlen(string), NULL, false);
	printf("md5: %s\n", result);
	free(result);
}

int main() {
	do_md5("hello");
	do_md5("world");
	do_md5("FINISH");
	do_md5("helloworld");
	return 0;
}
