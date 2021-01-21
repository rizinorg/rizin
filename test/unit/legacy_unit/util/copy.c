#include <rz_util.h>

#define F "/etc/services"

int main() {
	size_t len;
	char *out = rz_file_slurp(F, &len);
	rz_file_dump("a", out, (int)len);
	system("md5 " F);
	system("md5 a");
	return 0;
}
