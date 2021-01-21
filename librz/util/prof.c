// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util.h"

typedef struct timeval tv;

// Subtract the 'tv' values begin from end, storing result in RESULT
// Return 1 if the difference is negative, otherwise 0.
static int timeval_subtract(tv *result, tv *end, tv *begin) {
	// Perform the carry for the later subtraction by updating Y
	if (end->tv_usec < begin->tv_usec) {
		int nsec = (begin->tv_usec - end->tv_usec) / 1000000 + 1;
		begin->tv_usec -= 1000000 * nsec;
		begin->tv_sec += nsec;
	}
	if (end->tv_usec - begin->tv_usec > 1000000) {
		int nsec = (end->tv_usec - begin->tv_usec) / 1000000;
		begin->tv_usec += 1000000 * nsec;
		begin->tv_sec -= nsec;
	}

	// Compute the time remaining to wait. 'tv_usec' is certainly positive.
	result->tv_sec = end->tv_sec - begin->tv_sec;
	result->tv_usec = end->tv_usec - begin->tv_usec;

	// Return 1 if result is negative
	return end->tv_sec < begin->tv_sec;
}

RZ_API void rz_prof_start(struct rz_prof_t *p) {
	tv *begin = &p->begin;
	p->result = 0.0;
	gettimeofday(begin, NULL);
}

RZ_API double rz_prof_end(struct rz_prof_t *p) {
	tv end, diff, *begin = &p->begin;
	int sign;
	gettimeofday(&end, NULL);
	sign = timeval_subtract(&diff, begin, &end);
	p->result = RZ_ABS(((double)(diff.tv_sec) + ((double)diff.tv_usec / 1000000.)));
	return RZ_ABS(sign);
}
