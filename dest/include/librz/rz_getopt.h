#ifndef RZ_GETOPT_H
#define RZ_GETOPT_H

#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

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
} RzGetopt;

RZ_API void rz_getopt_init(RzGetopt *go, int argc, const char **argv, const char *ostr);
RZ_API int rz_getopt_next(RzGetopt *opt);

#ifdef __cplusplus
}
#endif

#endif
