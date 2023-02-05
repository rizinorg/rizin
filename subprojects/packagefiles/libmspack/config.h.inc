#ifndef MSPACK_CONFIG_H
#define MSPACK_CONFIG_H
/* Define if building universal (internal helper macro) */

/* Turn debugging mode on? */
#define DEBUG @DEBUG@

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H @HAVE_DLFCN_H@

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
#define HAVE_FSEEKO @HAVE_FSEEKO@

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H @HAVE_INTTYPES_H@

/* Define to 1 if you have the `mkdir' function. */
#define HAVE_MKDIR @HAVE_MKDIR@

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H @HAVE_STDINT_H@

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H @HAVE_STDIO_H@

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H @HAVE_STDLIB_H@

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H @HAVE_STRINGS_H@

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H @HAVE_STRING_H@

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H @HAVE_SYS_STAT_H@

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H @HAVE_SYS_TYPES_H@

/* Define to 1 if you have the `towlower' function. */
#define HAVE_TOWLOWER @HAVE_TOWLOWER@

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H @HAVE_UNISTD_H@

/* Define to 1 if you have the `_mkdir' function. */
#define HAVE__MKDIR @HAVE__MKDIR@

/* Define if mkdir takes only one argument. */
#define MKDIR_TAKES_ONE_ARG @MKDIR_TAKES_ONE_ARG@

/* Version number of package */
#define VERSION "0.10.1alpha"

/* The size of `off_t', as computed by sizeof. */
#define SIZEOF_OFF_T @SIZEOF_OFF_T@

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS @STDC_HEADERS@

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#define WORDS_BIGENDIAN @WORDS_BIGENDIAN@

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
#define _LARGEFILE_SOURCE @_LARGEFILE_SOURCE@

/* Define for large files, on AIX-style hosts. */
#define _LARGE_FILES @_LARGE_FILES@

/* Define to `int' if <sys/types.h> does not define. */
#if !(@HAVE_MODE_T@)
#define mode_t int
#endif

/* Define to `long int' if <sys/types.h> does not define. */
#if !(@HAVE_OFF_T@)
#define off_t long int
#endif

/* Define to `unsigned int' if <sys/types.h> does not define. */
#if !(@HAVE_SIZE_T@)
#define size_t unsigned int
#endif

#endif /* MSPACK_CONFIG_H */
