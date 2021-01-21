#include "rz_config.h"

int main() {
	struct rz_config_t *cfg;

	/* initialize config table */
	cfg = rz_config_new(NULL);
	rz_config_set(cfg, "foo", "bar");
	rz_config_set_i(cfg, "bar", 33);
	rz_config_lock(cfg, 1);

	/* usage */
	printf("foo = %s\n", rz_config_get(cfg, "foo"));
	printf("bar = %d\n", (int)rz_config_get_i(cfg, "bar"));

	rz_config_free(cfg);

	return 0;
}
