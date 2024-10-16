// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#define TIME_HFS_SINCE_1970 2082844800u // Mac HFS/HFS+ constant to convert timestamp to epoch
#define TIME_W32_SINCE_1970 0x2b6109100ull // The number of seconds from the Windows Runtime epoch to January 1, 1970.

#if __linux__
#include <time.h>
#elif __APPLE__ && !defined(MAC_OS_X_VERSION_10_12)
#include <mach/mach_time.h>
#elif __WINDOWS__
#include <rz_windows.h>
#endif

#ifdef _MSC_VER
/**
 * \brief Get the system current time and the current time zone.
 *
 * See https://man7.org/linux/man-pages/man2/gettimeofday.2.html for more
 * information.
 *
 * \param p Pointer to a \p timeval structure that will be filled by this function
 * \return 0 if the function succeeds, -1 on error
 */
RZ_API int rz_time_gettimeofday(struct timeval *p) {
	// ULARGE_INTEGER ul; // As specified on MSDN.
	ut64 ul = 0;
	FILETIME ft = { 0 };
	if (p) {
		// Returns a 64-bit value representing the number of
		// 100-nanosecond intervals since January 1, 1601 (UTC).
		GetSystemTimeAsFileTime(&ft);
		// Fill ULARGE_INTEGER low and high parts.
		// ul.LowPart = ft.dwLowDateTime;
		// ul.HighPart = ft.dwHighDateTime;
		ul |= ft.dwHighDateTime;
		ul <<= 32;
		ul |= ft.dwLowDateTime;
		// Convert to microseconds.
		// ul.QuadPart /= 10ULL;
		ul /= 10;
		// Remove Windows to UNIX Epoch delta.
		// ul.QuadPart -= 11644473600000000ULL;
		ul -= 11644473600000000ULL;
		// Modulo to retrieve the microseconds.
		// p->tv_usec = (long)(ul.QuadPart % 1000000LL);
		// Divide to retrieve the seconds.
		// p->tv_sec = (long)(ul.QuadPart / 1000000LL);
		p->tv_sec = (long)(ul / 1000000LL);
		p->tv_usec = (long)(ul % 1000000LL);
	}
	return 0;
}
#else
/**
 * \brief Get the system current time and the current time zone.
 *
 * See https://man7.org/linux/man-pages/man2/gettimeofday.2.html for more
 * information.
 *
 * \param p Pointer to a \p timeval structure that will be filled by this function
 * \return 0 if the function succeeds, -1 on error
 */
RZ_API int rz_time_gettimeofday(struct timeval *p) {
	// struct timezone is obsolete and shall not be used.
	return gettimeofday(p, NULL);
}
#endif

/**
 * \brief Returns the current time in microseconds.
 *
 * Note: Don't use this for timestamps! The returned time can fluctuate.
 * Strictly ascending values are not guaranteed with consecutive calls!
 * So use it only for human-readable date/time information.
 * For timestamps use rz_time_now_mono().
 *
 * \return The current time
 */
RZ_API ut64 rz_time_now(void) {
	ut64 ret;
	struct timeval now;
	rz_time_gettimeofday(&now);
	ret = now.tv_sec * RZ_USEC_PER_SEC;
	ret += now.tv_usec;
	return ret;
}

/**
 * \brief Returns microseconds since the start of the
 * system-wide valid monotonic clock.
 * Start point of the clock differs from system to system.
 *
 * \return The monotonic clock microseconds
 */
RZ_API ut64 rz_time_now_mono(void) {
#if __WINDOWS__
	LARGE_INTEGER f;
	if (!QueryPerformanceFrequency(&f)) {
		return 0;
	}
	LARGE_INTEGER v;
	if (!QueryPerformanceCounter(&v)) {
		return 0;
	}
	v.QuadPart *= 1000000;
	v.QuadPart /= f.QuadPart;
	return v.QuadPart;
#elif __APPLE__ && !defined(MAC_OS_X_VERSION_10_12)
	ut64 ticks = mach_absolute_time();
	mach_timebase_info_data_t tb;
	mach_timebase_info(&tb);
	return ((ticks * tb.numer) / tb.denom) / RZ_NSEC_PER_USEC;
#else
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec * RZ_USEC_PER_SEC + now.tv_nsec / RZ_NSEC_PER_USEC;
#endif
}

/* Valid only from midnight 31 Dec 1969 until Jan 1970 */
static inline long get_seconds_since_12am31Dec1969(struct tm *time) {
	if (time->tm_mday == 31 && time->tm_mon == 11 && time->tm_year == 69) {
		return time->tm_hour * 3600 + time->tm_min * 60 + time->tm_sec;
	} else if (time->tm_mon == 0 && time->tm_year == 70) {
		return 86400 + (time->tm_mday - 1) * 86400 + time->tm_hour * 3600 + time->tm_min * 60 + time->tm_sec;
	}
	return -1;
}

/**
 * \brief Converts an unix epoch timestamp to string
 *
 * \param  timestamp  The unix epoch timestamp
 * \return            The timestamp in string format
 */
RZ_API RZ_OWN char *rz_time_stamp_to_str(ut32 timestamp) {
	char timestr_buf[ASCTIME_BUF_MINLEN];
	time_t ts = (time_t)timestamp;
	struct tm gmt_tm;
	rz_gmtime_r(&ts, &gmt_tm);
	struct tm local_tm;
	rz_localtime_r(&ts, &local_tm);
	time_t gmt_time;
	time_t local_time;
	long diff;
	if (gmt_tm.tm_mday == 1 && gmt_tm.tm_mon == 0 && gmt_tm.tm_year == 70) {
		gmt_time = get_seconds_since_12am31Dec1969(&gmt_tm);
		local_time = get_seconds_since_12am31Dec1969(&local_tm);
		diff = local_time - gmt_time;
	} else {
		gmt_time = mktime(&gmt_tm);
		local_time = mktime(&local_tm);
		diff = (long)difftime(local_time, gmt_time);
	}
	bool err = gmt_time == -1 || local_time == -1;
	char *timestr = rz_ctime_r(&ts, timestr_buf);
	if (timestr) {
		rz_str_trim(timestr);
		long hours = diff / 3600;
		long minutes = labs(diff % 3600 / 60);
		long seconds = labs(diff % 3600 % 60);
		if (err) {
			timestr = rz_str_newf("%s ERR", timestr);
		} else if (seconds) {
			timestr = rz_str_newf("%s UTC%+ld:%ld:%ld", timestr, hours, minutes, seconds);
		} else if (minutes) {
			timestr = rz_str_newf("%s UTC%+ld:%ld", timestr, hours, minutes);
		} else if (hours) {
			timestr = rz_str_newf("%s UTC%+ld", timestr, hours);
		} else {
			timestr = rz_str_newf("%s UTC", timestr);
		}
	}
	return timestr;
}

/**
 * \brief Converts dos timestamp to posix timestamp
 *
 * \param  timestamp  The timestamp in dos format to convert
 * \return            The converted posix timestamp
 */
RZ_API ut32 rz_time_dos_time_stamp_to_posix(ut32 timestamp) {
	ut16 date = timestamp >> 16;
	ut16 time = timestamp & 0xFFFF;

	/* Date */
	ut32 year = ((date & 0xfe00) >> 9) + 1980;
	ut32 month = (date & 0x01e0) >> 5;
	ut32 day = date & 0x001f;

	/* Time */
	ut32 hour = (time & 0xf800) >> 11;
	ut32 minutes = (time & 0x07e0) >> 5;
	ut32 seconds = (time & 0x001f) << 1;

	/* Convert to epoch */
	struct tm t = { 0 };
	t.tm_year = year - 1900;
	t.tm_mon = month > 0 ? month - 1 : month;
	t.tm_mday = day > 0 ? day : 1;
	t.tm_hour = hour;
	t.tm_min = minutes;
	t.tm_sec = seconds;
	t.tm_isdst = -1;
	time_t epochTime = mktime(&t);

	return (ut32)epochTime;
}

/**
 * \brief Verifies that the timestamp is in dos format
 *
 * \param  certainPosixTimeStamp       Certain posix timestamp
 * \param  possiblePosixOrDosTimeStamp Possible posix or dos timestamp to test
 * \return true if format is in dos format, otherwise false
 */
RZ_API bool rz_time_stamp_is_dos_format(const ut32 certainPosixTimeStamp, const ut32 possiblePosixOrDosTimeStamp) {
	/* We assume they're both POSIX timestamp and thus the higher bits would be equal if they're close to each other */
	if ((certainPosixTimeStamp >> 16) == (possiblePosixOrDosTimeStamp >> 16)) {
		return false;
	}
	return true;
}

/**
 * \brief Converts a dos date (ut32) and returns the timestamp in string format
 *
 * \param  timestamp The number to convert to string
 * \return           The timestamp in string format
 */
RZ_API RZ_OWN char *rz_time_date_dos_to_string(ut32 timestamp) {
	ut32 posix = rz_time_dos_time_stamp_to_posix(timestamp);
	return rz_time_stamp_to_str(posix);
}

/**
 * \brief Converts a Mac HFS+ date (ut32) and returns the timestamp in string format
 *
 * \param  timestamp The number to convert to string
 * \return           The timestamp in string format
 */
RZ_API RZ_OWN char *rz_time_date_hfs_to_string(ut32 timestamp) {
	timestamp += TIME_HFS_SINCE_1970; // add Mac HFS+ epoch
	return rz_time_stamp_to_str(timestamp);
}

/**
 * \brief Converts a Win32 date (ut64) and returns the timestamp in string format
 *
 * \param  timestamp The number to convert to string
 * \return           The timestamp in string format
 */
RZ_API RZ_OWN char *rz_time_date_w32_to_string(ut64 timestamp) {
	timestamp /= 10000000ll; // 100 nanoseconds to seconds
	if (timestamp > TIME_W32_SINCE_1970) {
		timestamp -= TIME_W32_SINCE_1970;
	} else {
		// TODO: this usecase is not handled and defaulted to 0
		timestamp = 0;
	}
	time_t t = (time_t)timestamp;
	return rz_time_stamp_to_str(t);
}

/**
 * \brief Returns the timestamp in string format of the current time (now)
 *
 * \return The timestamp in string format
 */
RZ_API RZ_OWN char *rz_time_date_now_to_string(void) {
	ut64 now = rz_time_now();
	now /= RZ_USEC_PER_SEC;
	return rz_time_stamp_to_str(now);
}

RZ_API struct tm *rz_localtime_r(RZ_NONNULL const time_t *time, RZ_NONNULL struct tm *res) {
	rz_return_val_if_fail(time && res, NULL);
#if __WINDOWS__
	errno_t err = localtime_s(res, time);
	return err ? NULL : res;
#else
	return localtime_r(time, res);
#endif
}

RZ_API struct tm *rz_gmtime_r(RZ_NONNULL const time_t *time, RZ_NONNULL struct tm *res) {
	rz_return_val_if_fail(time && res, NULL);
#if __WINDOWS__
	errno_t err = gmtime_s(res, time);
	return err ? NULL : res;
#else
	return gmtime_r(time, res);
#endif
}

RZ_API char *rz_asctime_r(RZ_NONNULL const struct tm *tm, RZ_NONNULL char *buf) {
	rz_return_val_if_fail(tm && buf, NULL);
#if __WINDOWS__
	errno_t err = asctime_s(buf, ASCTIME_BUF_MINLEN, tm);
	return err ? NULL : buf;
#else
	return asctime_r(tm, buf);
#endif
}

RZ_API char *rz_ctime_r(RZ_NONNULL const time_t *timer, RZ_NONNULL char *buf) {
	rz_return_val_if_fail(timer && buf, NULL);
#if __WINDOWS__
	errno_t err = ctime_s(buf, ASCTIME_BUF_MINLEN, timer);
	return err ? NULL : buf;
#else
	return ctime_r(timer, buf);
#endif
}
