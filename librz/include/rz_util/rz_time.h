#ifndef RZ_TIME_H
#define RZ_TIME_H

#include <rz_types.h>
#include <time.h>

#define RZ_NSEC_PER_SEC  1000000000ULL
#define RZ_NSEC_PER_MSEC 1000000ULL
#define RZ_USEC_PER_SEC  1000000ULL
#define RZ_NSEC_PER_USEC 1000ULL
#define RZ_USEC_PER_MSEC 1000ULL

#define ASCTIME_BUF_MINLEN (26)

// wall clock time in microseconds
RZ_API ut64 rz_time_now(void);

// monotonic time in microseconds
RZ_API ut64 rz_time_now_mono(void);

RZ_API char *rz_time_stamp_to_str(ut32 timeStamp);
RZ_API ut32 rz_time_dos_time_stamp_to_posix(ut32 timeStamp);
RZ_API bool rz_time_stamp_is_dos_format(const ut32 certainPosixTimeStamp, const ut32 possiblePosixOrDosTimeStamp);
RZ_API const char *rz_time_to_string(ut64 ts);

// Thread-safe cross platform wrappers
RZ_API char *rz_asctime_r(const struct tm *tm, char *buf);
RZ_API char *rz_ctime_r(const time_t *timer, char *buf);
RZ_API struct tm *rz_localtime_r(const time_t *time, struct tm *res);

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

#endif
