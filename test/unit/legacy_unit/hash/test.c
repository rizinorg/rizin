#include <rz_hash.h>

void printmd5(const char *str, RzHash *h) {
	int i;
	printf("(%d) %s: ", h->rst, str);
	for (i = 0; i < RZ_HASH_SIZE_MD5; i++) {
		printf("%02x", h->digest[i]);
	}
	printf("\n");
}

main() {
	int HASH = RZ_HASH_MD5;
	RzHash *h = rz_hash_new(1, HASH);

	rz_hash_do_begin(h, HASH);

	rz_hash_do_md5(h, "hello", 5);
	printmd5("hello", h);
	rz_hash_do_md5(h, "world", 5);
	printmd5("world", h);

	rz_hash_do_end(h, HASH);
	printmd5("FINISH", h);

	rz_hash_do_md5(h, "helloworld", 10);
	printmd5("helloworld", h);
}
