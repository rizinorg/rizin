#ifndef RZ_SIGNAL_H
#define RZ_SIGNAL_H

#if __UNIX__
#include <signal.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Returns atoi(str) if signal with `str` name not found. */
RZ_API int rz_signal_from_string(const char *str);

/* Return NULL if signal with `code` not found. */
RZ_API const char *rz_signal_to_string(int code);

// XXX this function should be portable, not-unix specific
#if __UNIX__
RZ_API void rz_signal_sigmask(int how, const sigset_t *newmask, sigset_t *oldmask);
#endif

#ifdef __cplusplus
}
#endif

#endif //  RZ_SIGNAL_H
