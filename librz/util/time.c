// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_util/rz_print.h>

#if __linux__
#include <time.h>
#elif __APPLE__ && !defined(MAC_OS_X_VERSION_10_12)
#include <mach/mach_time.h>
#endif

RZ_API ut64 rz_time_now(void) {
	ut64 ret;
	struct timeval now;
	gettimeofday(&now, NULL);
	ret = now.tv_sec * RZ_USEC_PER_SEC;
	ret += now.tv_usec;
	return ret;
}

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
	static mach_timebase_info_data_t tb;
	mach_timebase_info(&tb);
	return ((ticks * tb.numer) / tb.denom) / RZ_NSEC_PER_USEC;
#else
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec * RZ_USEC_PER_SEC + now.tv_nsec / RZ_NSEC_PER_USEC;
#endif
}

RZ_API char *rz_time_stamp_to_str(ut32 timeStamp) {
#ifdef _MSC_VER
	time_t rawtime;
	struct tm *tminfo;
	rawtime = (time_t)timeStamp;
	tminfo = localtime(&rawtime);
	//tminfo = gmtime (&rawtime);
	return rz_str_trim_dup(asctime(tminfo));
#else
	struct my_timezone {
		int tz_minuteswest; /* minutes west of Greenwich */
		int tz_dsttime; /* type of DST correction */
	} tz;
	struct timeval tv;
	int gmtoff;
	time_t ts = (time_t)timeStamp;
	gettimeofday(&tv, (void *)&tz);
	gmtoff = (int)(tz.tz_minuteswest * 60); // in seconds
	ts += (time_t)gmtoff;
	char *res = malloc(ASCTIME_BUF_MINLEN);
	if (res) {
		ctime_r(&ts, res);
		rz_str_trim(res); // XXX we probably need an rz_str_trim_dup()
	}
	return res;
#endif
}

RZ_API ut32 rz_time_dos_time_stamp_to_posix(ut32 timeStamp) {
	ut16 date = timeStamp >> 16;
	ut16 time = timeStamp & 0xFFFF;

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

RZ_API bool rz_time_stamp_is_dos_format(const ut32 certainPosixTimeStamp, const ut32 possiblePosixOrDosTimeStamp) {
	/* We assume they're both POSIX timestamp and thus the higher bits would be equal if they're close to each other */
	if ((certainPosixTimeStamp >> 16) == (possiblePosixOrDosTimeStamp >> 16)) {
		return false;
	}
	return true;
}

RZ_API int rz_print_date_dos(RzPrint *p, const ut8 *buf, int len) {
	if (len < 4) {
		return 0;
	}

	ut32 dt = buf[3] << 24 | buf[2] << 16 | buf[1] << 8 | buf[0];
	char *s = rz_time_stamp_to_str(rz_time_dos_time_stamp_to_posix(dt));
	if (!s) {
		return 0;
	}
	p->cb_printf("%s\n", s);
	free(s);
	return 4;
}

RZ_API int rz_print_date_hfs(RzPrint *p, const ut8 *buf, int len) {
	const int hfs_unix_delta = 2082844800;
	time_t t = 0;
	int ret = 0;

	if (p && len >= sizeof(ut32)) {
		t = rz_read_ble32(buf, p->big_endian);
		if (p->datefmt[0]) {
			t += p->datezone * (60 * 60);
			t += hfs_unix_delta;

			p->cb_printf("%s\n", rz_time_stamp_to_str(t));
			ret = sizeof(time_t);
		}
	}
	return ret;
}

RZ_API int rz_print_date_unix(RzPrint *p, const ut8 *buf, int len) {
	time_t t = 0;
	int ret = 0;

	if (p && len >= sizeof(ut32)) {
		t = rz_read_ble32(buf, p->big_endian);
		if (p->datefmt[0]) {
			t += p->datezone * (60 * 60);
			char *datestr = rz_time_stamp_to_str(t);
			if (datestr) {
				p->cb_printf("%s\n", datestr);
				free(datestr);
			}
			ret = sizeof(time_t);
		}
	}
	return ret;
}

RZ_API int rz_print_date_get_now(RzPrint *p, char *str) {
	int ret = 0;
	time_t l;

	*str = 0;
	l = time(0);

	str = rz_time_stamp_to_str(l);
	p->cb_printf("%s\n", str);
	ret = sizeof(time_t);
	return ret;
}

RZ_API int rz_print_date_w32(RzPrint *p, const ut8 *buf, int len) {
	ut64 l, L = 0x2b6109100LL;
	time_t t;
	int ret = 0;

	if (p && len >= sizeof(ut64)) {
		l = rz_read_ble64(buf, p->big_endian);
		l /= 10000000; // 100ns to s
		l = (l > L ? l - L : 0); // isValidUnixTime?
		t = (time_t)l; // TODO limit above!
		if (p->datefmt[0]) {
			p->cb_printf("%s\n", rz_time_stamp_to_str(t));
			ret = sizeof(time_t);
		}
	}

	return ret;
}

RZ_API const char *rz_time_to_string(ut64 ts) {
	time_t l;
	l = ts >> 20;
	return rz_time_stamp_to_str(l);
}

RZ_API struct tm *rz_localtime_r(const time_t *time, struct tm *res) {
#if __WINDOWS__
	errno_t err = localtime_s(res, time);
	return err ? NULL : res;
#else
	return localtime_r(time, res);
#endif
}

RZ_API char *rz_asctime_r(const struct tm *tm, char *buf) {
#if __WINDOWS__
	errno_t err = asctime_s(buf, ASCTIME_BUF_MINLEN, tm);
	return err ? NULL : buf;
#else
	return asctime_r(tm, buf);
#endif
}

RZ_API char *rz_ctime_r(const time_t *timer, char *buf) {
#if __WINDOWS__
	errno_t err = ctime_s(buf, ASCTIME_BUF_MINLEN, timer);
	return err ? NULL : buf;
#else
	return ctime_r(timer, buf);
#endif
}
