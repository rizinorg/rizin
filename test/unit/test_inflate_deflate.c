#include <rz_util.h>
#include "minunit.h"

struct {
	char inflated[1285];
	char deflated[640];
} test_cases[] = {
	{ "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n", "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x35\x90\xc1\x71\x43\x31\x08\x44\xef\xa9\x62\x0b\xf0\xfc\x2a\x92\x5b\xae\x29\x80\x20\xec\x30\x23\x09\x59\x02\x8f\xcb\x0f\xf2\x4f\x6e\x42\xc0\xb2\xfb\x3e\x6d\x4a\x83\x8e\x15\x0d\xc5\xaa\x4d\x2c\x75\x50\x13\xbf\x80\xad\x2f\x61\x17\x8f\x09\x2a\x3a\x74\xb1\xf6\x1b\xa4\x6a\x36\x97\x94\x5c\x80\x68\xac\x66\x05\x2e\x6d\xe4\xb2\x76\xd6\xa2\x25\xba\x23\x1c\x95\xbe\x53\x1e\xe2\xa7\xb4\xa0\xd1\xad\x13\xa8\xea\x3d\xe8\xc0\x97\x43\xba\xb6\xd4\x46\xd3\xfd\x78\x64\x49\xed\x82\x7b\xe8\x42\xb7\xe5\x33\x0a\xe4\x29\x93\xd5\xc9\xd5\x3a\xa2\x56\x6a\x6c\xa7\xf2\x1e\xd2\xa5\xfb\xd2\x4b\x52\x47\x0e\x43\x28\x8d\xb7\xf4\x64\x67\x80\x3c\xe5\x07\xde\xb7\x24\x85\x0b\x74\x46\x3a\x39\xb3\x6a\xc7\x94\x31\xe5\x47\x7a\x91\x99\xc1\xf3\xe3\x61\x35\x46\x9e\x93\xb4\x93\x49\x21\x6b\x09\x58\x6b\xfd\x27\x94\x81\x02\xd7\xb8\x29\x39\xfa\x36\x84\x41\x33\x8b\x98\x07\x3e\x9e\x2c\xc3\x25\x36\xc6\x64\x60\xcc\x24\x9c\x73\x1c\x43\x0b\xf9\xde\xc8\x14\x63\x9a\x16\xe9\x9b\xe2\x26\x95\x47\x39\xea\xa0\x9d\x1b\x76\xbd\x2a\x2b\xa1\xc8\x92\xb9\xbb\xcd\xea\xb6\x41\x1b\x90\x26\x8e\xf5\xc7\x35\xda\xf1\xf6\x0b\x67\x7b\x9f\x87\xbe\x01\x00\x00" },
	{ "I’d just like to interject for a moment. What you’re refering to as Linux, is in fact, GNU/Linux, or as I’ve recently taken to calling it, GNU plus Linux. Linux is not an operating system unto itself, but rather another free component of a fully functioning GNU system made useful by the GNU corelibs, shell utilities and vital system components comprising a full OS as defined by POSIX.\n\nMany computer users run a modified version of the GNU system every day, without realizing it. Through a peculiar turn of events, the version of GNU which is widely used today is often called Linux, and many of its users are not aware that it is basically the GNU system, developed by the GNU Project.\n\nThere really is a Linux, and these people are using it, but it is just a part of the system they use. Linux is the kernel: the program in the system that allocates the machine’s resources to the other programs that you run. The kernel is an essential part of an operating system, but useless by itself; it can only function in the context of a complete operating system. Linux is normally used in combination with the GNU operating system: the whole system is basically GNU with Linux added, or GNU/Linux. All the so-called Linux distributions are really distributions of GNU/Linux!\n", "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x6d\x54\xcb\x72\x13\x31\x10\xbc\xe7\x2b\x86\xfb\x62\xee\x70\xe2\x44\xa5\x0a\x48\xaa\x12\x0a\xae\xb2\x34\x9b\x9d\x58\x2b\xb9\xf4\xb0\xb3\x9c\xf8\x0d\x7e\x8f\x2f\xa1\x47\x5a\xbb\xec\xc0\x69\x55\x92\xa6\x7b\xa6\xbb\xb5\xb7\x7f\x7e\xfd\x76\xf4\x5c\x73\x21\x2f\x3b\xa6\x12\x49\x42\xe1\xf4\xcc\xb6\xd0\x18\x13\x19\x9a\xe3\xcc\xa1\x6c\xe8\xfb\x64\x0a\x2d\xb1\xa2\x22\x31\x25\x1e\x39\x49\x78\xd2\x0a\x93\xe9\xb3\x84\xfa\x32\x90\x64\x94\xd3\x68\x6c\x19\xe8\xd3\xd7\x6f\xef\xd6\x6d\xc5\xc9\x74\x8b\xca\x83\x56\x5a\xe0\xf9\x85\x8a\xd9\x71\xd0\x7a\x6b\xbc\x57\x28\xe9\x55\xb4\xf7\x75\x45\xdc\xf4\x8f\xe2\x86\x58\xc8\x04\x8a\x7b\x4e\xa6\xe8\xed\xbc\xe4\xc2\x33\xd5\xa0\x3d\x97\xcc\x7e\x1c\x68\x5b\x0b\xe1\x78\x62\x10\xa2\x40\xbf\x63\x62\x26\x1b\xe7\x7d\x0c\xa0\xa5\x38\x62\xa4\xb1\x7a\xf0\x8f\x35\xd8\x22\x31\x28\x98\xd2\xae\x80\xb3\x71\x4c\x35\x33\x2e\xd1\x16\x5d\x4e\xdc\x4e\x6d\x4c\xec\x65\x9b\x07\xca\x13\x7b\x4f\xb5\x88\x97\x22\x9c\xc1\xe4\xe8\x20\xc5\xf8\x13\xc2\x99\x2d\xb7\x65\x92\xac\x14\x9d\x96\xee\x1e\x54\x0b\xc7\xa3\x04\x76\x4a\x70\x7f\xf7\x70\xfb\x63\x73\x73\xf3\xc5\x84\xa5\xdd\xaf\xd0\x5f\x1b\x48\x99\x52\x0d\xcd\x01\x27\xa3\xe0\xf6\x01\x7b\x68\x58\x87\x38\xb5\xb5\x52\x32\x8e\x16\x72\x66\x19\xe8\x28\x65\x8a\xaa\x03\x1b\x2f\x3f\xbb\xae\x1b\x7a\x9c\x52\xac\x4f\x13\xd0\xf6\x6c\xab\x17\x93\xa8\xd4\xd4\xa0\x50\x8b\x56\x87\x06\x79\xc1\xa0\xe8\xc7\x49\xec\xa4\xea\x1f\xc5\x31\x24\x43\x57\x0e\x8e\x81\x47\x37\xe3\x58\x60\xa0\xba\x87\xdd\xd5\x6a\x15\x63\xd6\x49\x80\x00\x57\xd6\x39\x0c\x12\xd3\x0c\x3c\xea\xaa\x68\x92\xa4\x28\xc4\xd6\x64\x51\x80\xe5\xd5\x40\x03\x14\x3a\xb0\x87\xdb\xee\xd2\x84\xfb\x14\x35\x99\x50\xeb\x11\xde\x72\x9b\xd1\xb7\x5e\xcc\x65\x03\xb8\x9e\x19\x83\xc6\xbd\xe7\xc6\x5d\xf3\x29\x5f\x9a\x90\x4e\xdd\x42\x0f\x39\x4c\x2a\x27\x41\x57\x31\xb1\x6c\xa3\x5e\xa4\x4f\x4f\x77\x9c\x02\xfb\xf7\x6d\xbd\x4f\xf1\x29\x99\x59\xd3\x7e\x55\x88\xc1\xd0\x51\xb4\xa6\x70\x2f\x9a\x8d\x9d\xe0\x34\xa2\x0f\x37\x39\xc7\x9a\xac\x9e\xc4\x76\xd8\x13\xba\x62\xe5\x5e\x8e\x17\xa6\xb6\xab\x63\x27\xca\x36\x5f\x20\xce\x19\x46\x09\x72\x76\xea\xf9\x3f\xef\xa1\x4f\x88\xe6\x3d\xae\xab\x74\xfd\x69\x7c\xd0\xa1\xad\xde\x0f\x17\xc9\x3f\xb5\x6f\x23\xde\xfc\xcb\xfa\x38\x34\x82\x9e\x0b\xff\x03\x7d\xf5\x18\xd3\xdc\x94\x6f\x81\x00\x0a\x8a\xb6\x12\x4c\x03\xd5\x00\x9e\x1d\x7b\x0d\xd2\xe5\x3b\x4e\xd1\x9f\x55\xbb\x8a\x41\x4b\x9d\x02\x74\x2e\xe3\x1c\xbb\xf6\x03\x39\xff\x4e\x36\xf4\x11\xcf\xa8\xa9\x1e\xdf\x5e\x86\x8f\x9c\xe4\x92\x04\xf3\xa3\x8b\x9e\xb9\x35\x1f\xd7\x07\x3d\xdb\x1d\xec\xcd\xcd\x5f\x74\x05\x61\x4b\x02\x05\x00\x00" },
	{ "1234567890abcdefghijklmnopqrstuvwxyz\n", "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x33\x34\x32\x36\x31\x35\x33\xb7\xb0\x34\x48\x4c\x4a\x4e\x49\x4d\x4b\xcf\xc8\xcc\xca\xce\xc9\xcd\xcb\x2f\x28\x2c\x2a\x2e\x29\x2d\x2b\xaf\xa8\xac\xe2\x02\x00\x9f\x79\xdc\xdb\x25\x00\x00\x00" }
};

int deflated_lengths[3] = { 284, 637, 57 };
int inflated_lengths[3];

void init_lengths()
{
	for (int i = 0; i < 3; i++)
	{
		inflated_lengths[i] = strlen(test_cases[i].inflated);
	}
}

void check_os()
{
#if __APPLE__
	for (int i = 0; i < 3; i++)
	{
		test_cases[i].deflated[9] = 0x13 // set OS bit for MacOS
	}
#endif
}

bool test_rz_inflate(void) {
	for (int i = 0; i < 3; i++) {
		unsigned char *inflated = rz_inflate((unsigned char *)test_cases[i].deflated, deflated_lengths[i], NULL, NULL);
		mu_assert_notnull(inflated, "rz_inflate returned null");
		mu_assert_memeq(inflated, (unsigned char *)test_cases[i].inflated, inflated_lengths[i], "rz_inflate failed");
		free(inflated);
	}

	mu_end;
}

bool test_rz_deflate(void) {
	for (int i = 0; i < 3; i++) {
		unsigned char *deflated = rz_deflate((unsigned char *)test_cases[i].inflated, inflated_lengths[i], NULL, NULL);
		mu_assert_notnull(deflated, "rz_deflate returned null");
		mu_assert_memeq(deflated, (unsigned char *)test_cases[i].deflated, deflated_lengths[i], "rz_deflate failed");
		free(deflated);
	}

	mu_end;
}

bool test_rz_inflate_buf(void) {
	for (int i = 0; i < 3; i++) {
		RzBuffer *deflated_buf = rz_buf_new_with_bytes((unsigned char *)test_cases[i].deflated, deflated_lengths[i]);
		RzBuffer *inflated_buf = rz_buf_new_empty(inflated_lengths[i]);
		mu_assert_true(rz_inflate_buf(deflated_buf, inflated_buf, 1 << 13, NULL), "rz_inflate_buf failed");
		unsigned char *inflated = malloc(inflated_lengths[i]);
		rz_buf_read(inflated_buf, inflated, inflated_lengths[i]);

		mu_assert_notnull(inflated, "rz_buf_read failed");
		mu_assert_memeq(inflated, (unsigned char *)test_cases[i].inflated, inflated_lengths[i], "rz_inflate_buf does not return expected output");
		free(inflated);
	}

	mu_end;
}

bool test_rz_deflate_buf(void) {
	for (int i = 0; i < 3; i++) {
		RzBuffer *inflated_buf = rz_buf_new_with_bytes((unsigned char *)test_cases[i].inflated, inflated_lengths[i]);
		RzBuffer *deflated_buf = rz_buf_new_empty(deflated_lengths[i]);
		mu_assert_true(rz_deflate_buf(inflated_buf, deflated_buf, 1 << 18, NULL), "rz_deflate_buf failed");
		unsigned char *deflated = malloc(deflated_lengths[i]);
		rz_buf_read(deflated_buf, deflated, deflated_lengths[i]);

		mu_assert_notnull(deflated, "rz_buf_read failed");
		mu_assert_memeq(deflated, (unsigned char *)test_cases[i].deflated, deflated_lengths[i], "rz_deflate_buf does not return expected output");
		free(deflated);
	}

	mu_end;
}

int all_tests() {
	init_lengths();
	check_os();
	mu_run_test(test_rz_inflate);
	mu_run_test(test_rz_deflate);
	mu_run_test(test_rz_inflate_buf);
	mu_run_test(test_rz_deflate_buf);

	return tests_passed != tests_run;
}

mu_main(all_tests);
