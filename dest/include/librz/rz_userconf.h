#ifndef RZ_CONFIGURE_H
#define RZ_CONFIGURE_H

#include "rz_build_version.h"

// clang-format off
#define RZ_CHECKS_LEVEL             2
#define DEBUGGER                    1
#define HAVE_THREADS                1
#define HAVE_PTHREAD                0
#define HAVE_LZMA                   1
#define HAVE_ZLIB                   1
#define HAVE_DECL_ADDR_NO_RANDOMIZE 0
#define HAVE_DECL_PROCCTL_ASLR_CTL  0
#define HAVE_ARC4RANDOM             0
#define HAVE_ARC4RANDOM_UNIFORM     0
#define HAVE_EXPLICIT_BZERO         0
#define HAVE_EXPLICIT_MEMSET        0
#define HAVE_CLOCK_NANOSLEEP        0
#define HAVE_SIGACTION              0
#define HAVE_PIPE                   0
#define HAVE_EXECV                  0
#define HAVE_EXECVE                 0
#define HAVE_EXECVP                 0
#define HAVE_EXECL                  0
#define HAVE_SYSTEM                 1
#define HAVE_REALPATH               0
#define HAVE_PIPE2                  0
#define HAVE_ENVIRON                1
#define HAVE_OPENPTY                0
#define HAVE_FORKPTY                0
#define HAVE_LOGIN_TTY              0
#define HAVE_SHM_OPEN               0
#define HAVE_LIB_MAGIC              0
#define USE_LIB_MAGIC               0
#define HAVE_LIB_XXHASH             1
#define USE_LIB_XXHASH              1
#define USE_SYS_ZYDIS               0
#define HAVE_LIB_SSL                0
#define HAVE_PTRACE                 0
#define USE_PTRACE_WRAP             0
#define HAVE_FORK                   0
#define HAVE_STRLCPY                0
#define HAVE_STRLCAT                0
#define HAVE_STRNLEN                1
#define WANT_DYLINK                 1
#define WITH_GPL                    1
#define HAVE_JEMALLOC               0
#define IS_IOS                      0
#define RZ_BUILD_DEBUG              1
#define N_THREAD_LIMIT              32767
#define HAVE_COPYFILE               0
#define HAVE_COPY_FILE_RANGE        0
#define HAVE_BACKTRACE              0
#define HAVE___BUILTIN_BSWAP16      0
#define HAVE___BUILTIN_BSWAP32      0
#define HAVE___BUILTIN_BSWAP64      0
#define HAVE___BUILTIN_CLZLL        0
#define HAVE___BUILTIN_CTZLL        0
#define HAVE_POSIX_MEMALIGN         0
#define HAVE__ALIGNED_MALLOC        1

#define HAVE_HEADER_LINUX_ASHMEM_H  0
#define HAVE_HEADER_SYS_SHM_H       0
#define HAVE_HEADER_SYS_IPC_H       0
#define HAVE_HEADER_SYS_MMAN_H      0
#define HAVE_HEADER_INTTYPES_H      1

#define RZ_IS_PORTABLE 0

#define RZ_BINDIR_DEPTH 1
// clang-format on

#define RZ_PREFIX "C:\\Farhan\\rizin\\dest"
#define RZ_BINDIR "bin"
#define RZ_LIBDIR "lib"
#define RZ_INCDIR "include\\librz"
#define RZ_DATDIR "share"

#define RZ_WWWROOT  "share\\www"
#define RZ_PLUGINS  "lib\\rizin\\plugins"
#define RZ_DATADIR  "share"
#define RZ_SDB      "share"
#define RZ_SIGDB    "share\\sigdb"
#define RZ_THEMES   "share\\cons"
#define RZ_FORTUNES "share\\fortunes"
#define RZ_FLAGS    "share\\flag"
#define RZ_HUD      "share\\hud"

#define RZ_SDB_ARCH_PLATFORMS RZ_JOIN_3_PATHS(RZ_SDB, "arch", "platforms")
#define RZ_SDB_ARCH_CPUS      RZ_JOIN_3_PATHS(RZ_SDB, "asm", "cpus")
#define RZ_SDB_TYPES          RZ_JOIN_2_PATHS(RZ_SDB, "types")
#define RZ_SDB_OPCODES        RZ_JOIN_2_PATHS(RZ_SDB, "opcodes")
#define RZ_SDB_REG            RZ_JOIN_2_PATHS(RZ_SDB, "reg")
#define RZ_SDB_MAGIC          RZ_JOIN_2_PATHS(RZ_SDB, "magic")
#define RZ_SDB_FORMAT         RZ_JOIN_2_PATHS(RZ_SDB, "format")
#define RZ_PDB                RZ_JOIN_2_PATHS(RZ_DATADIR, "pdb")
#define RZ_PROJECTS           RZ_JOIN_2_PATHS(RZ_DATADIR, "projects")
#define RZ_BINRC              RZ_JOIN_2_PATHS(RZ_DATADIR, "rc.d")

#define RZ_HOME_PREFIX    ".local"
#define RZ_HOME_CONFIGDIR RZ_JOIN_2_PATHS(".config", "rizin")
#define RZ_HOME_CACHEDIR  RZ_JOIN_2_PATHS(".cache", "rizin")

#define RZ_HOME_HISTORY RZ_JOIN_2_PATHS(RZ_HOME_CACHEDIR, "history")

#define RZ_HOME_CONFIG_RC     RZ_JOIN_2_PATHS(RZ_HOME_CONFIGDIR, "rizinrc")
#define RZ_HOME_CONFIG_RC_DIR RZ_JOIN_2_PATHS(RZ_HOME_CONFIGDIR, "rizinrc.d")
#define RZ_GLOBAL_RC          RZ_JOIN_2_PATHS(RZ_DATADIR, "rizinrc")
#define RZ_HOME_RC            ".rizinrc"

// This is an optional extra prefix used to load plugins, sdb files, sdb files,
// etc. It can be outside the default prefix. Used e.g. by Homebrew to load
// plugins from the general /opt/homebrew prefix instead of the version specific
// prefix e.g. /opt/homebrew/Cellar/rizin/0.x.y/
// clang-format off
#define RZ_EXTRA_PREFIX 0
// clang-format on

#endif
