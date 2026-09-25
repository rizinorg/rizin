#ifndef RZ_GETOPT_H
#define RZ_GETOPT_H

#include <rz_types.h>
#include <rz_vector.h>
#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

// 256, all long options values are >= RZ_GETOPT_LONG_BASE so that they can be distinguished from single-char short options
#define RZ_GETOPT_LONG_BASE 0x100

typedef struct rz_getopt_long_t {
	const char *name; ///< Name of the long option. e.g. --name
	int val; ///< enum value (>= RZ_GETOPT_LONG_BASE) returned by rz_getopt_next when the long option is consumed
	const RzPVector /*<const char *>*/ *values; ///< All possible valid cmdline values for the long option. If NULL, long option is a yes/no flag only.
	RZ_NULLABLE const char *default_value; ///< Default of the long option when it's given no cmdline value
} RzGetoptLong;

typedef struct rz_getopt_t {
	int err;
	int ind;
	int opt;
	int reset;
	const char *arg;
	const char *place; ///< current position within the argv element being processed
	// ...
	int argc;
	const char **argv;
	const char *ostr;
	const RzVector /*<RzGetoptLong>*/ *longopts; ///< vector of decsriptors of long options
} RzGetopt;

RZ_API void rz_getopt_init(RzGetopt *go, int argc, const char **argv, const char *ostr);
RZ_API void rz_getopt_init_long(RzGetopt *go, int argc, const char **argv, const char *ostr, const RzVector /*<RzGetoptLong>*/ *longopts);
RZ_API int rz_getopt_next(RzGetopt *opt);

#ifdef __cplusplus
}
#endif

#endif
