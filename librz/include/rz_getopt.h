#ifndef RZ_GETOPT_H
#define RZ_GETOPT_H

#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_GETOPT_LONG_BASE 0x100

typedef struct rz_getopt_long_t {
	const char *name;
	int val;
	const char **values;
	const char *default_value;
} RzGetoptLong;

typedef struct rz_getopt_t {
	int err;
	int ind;
	int opt;
	int reset;
	const char *arg;
	// ...
	int argc;
	const char **argv;
	const char *ostr;
	const RzGetoptLong *longopts;
} RzGetopt;

RZ_API void rz_getopt_init(RzGetopt *go, int argc, const char **argv, const char *ostr);
RZ_API void rz_getopt_init_long(RzGetopt *go, int argc, const char **argv, const char *ostr, const RzGetoptLong *longopts);
RZ_API int rz_getopt_next(RzGetopt *opt);

#ifdef __cplusplus
}
#endif

#endif
