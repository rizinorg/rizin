#ifndef RZ_TIME_H
#define RZ_TIME_H

#include <rz_types.h>
#include <time.h>

#define RZ_NSEC_PER_SEC  1000000000ULL
#define RZ_NSEC_PER_MSEC 1000000ULL
#define RZ_USEC_PER_SEC  1000000ULL
#define RZ_NSEC_PER_USEC 1000ULL
#define RZ_USEC_PER_MSEC 1000ULL

#define ASCTIME_BUF_MINLEN 26

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
struct timeval;
#endif

RZ_API int rz_time_gettimeofday(struct timeval *p);

// wall clock time in microseconds
RZ_API ut64 rz_time_now(void);

// monotonic time in microseconds
RZ_API ut64 rz_time_now_mono(void);

RZ_API RZ_OWN char *rz_time_stamp_to_str(ut32 timestamp);
RZ_API ut32 rz_time_dos_time_stamp_to_posix(ut32 timestamp);
RZ_API bool rz_time_stamp_is_dos_format(const ut32 certainPosixTimeStamp, const ut32 possiblePosixOrDosTimeStamp);
RZ_API RZ_OWN char *rz_time_date_dos_to_string(ut32 timestamp);
RZ_API RZ_OWN char *rz_time_date_hfs_to_string(ut32 timestamp);
RZ_API RZ_OWN char *rz_time_date_w32_to_string(ut64 timestamp);
#define rz_time_date_unix_to_string rz_time_stamp_to_str
RZ_API RZ_OWN char *rz_time_date_now_to_string(void);

// Thread-safe cross platform wrappers
RZ_API char *rz_asctime_r(RZ_NONNULL const struct tm *tm, RZ_NONNULL char *buf);
RZ_API char *rz_ctime_r(RZ_NONNULL const time_t *timer, RZ_NONNULL char *buf);
RZ_API struct tm *rz_localtime_r(RZ_NONNULL const time_t *time, RZ_NONNULL struct tm *res);
RZ_API struct tm *rz_gmtime_r(RZ_NONNULL const time_t *time, RZ_NONNULL struct tm *res);

#define RZ_TIME_PROFILE_ENABLED 0

#if RZ_TIME_PROFILE_ENABLED
#define RZ_TIME_PROFILE_BEGIN ut64 __now__ = rz_time_now_mono()
#define RZ_TIME_PROFILE_END   eprintf("%s %" PFMT64d "\n", __FUNCTION__, rz_time_now_mono() - __now__)
#else
#define RZ_TIME_PROFILE_BEGIN \
	do { \
	} while (0)
#define RZ_TIME_PROFILE_END \
	do { \
	} while (0)
#endif

#ifdef __cplusplus
}
#endif

#endif
