#ifndef TEST_SDB_H
#define TEST_SDB_H

#define PERTURBATOR      "\\,\";] [}{'"
#define PERTURBATOR_JSON "\\\\,\\\";] [}{'"

static void diff_cb(const SdbDiff *diff, void *user) {
	char buf[2048];
	if (sdb_diff_format(buf, sizeof(buf), diff) < 0) {
		return;
	}
	printf("%s\n", buf);
}

static inline void print_sdb(Sdb *sdb) {
	Sdb *e = sdb_new0();
	sdb_diff(e, sdb, diff_cb, NULL);
	sdb_free(e);
}

#define assert_sdb_eq(actual, expected, msg) mu_assert((msg), sdb_diff(expected, actual, diff_cb, NULL));

#define assert_streq_null(actual, expected, message) \
	do { \
		mu_assert(message, (!(actual)) == (!(expected))); \
		if (expected) { \
			mu_assert_streq(actual, expected, message); \
		} \
	} while (0)

#endif // TEST_SDB_H
