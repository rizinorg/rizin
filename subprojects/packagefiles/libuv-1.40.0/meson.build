project('libuv', 'c', version : '1.40.0', license : 'libuv', default_options: ['werror=false'])

cc = meson.get_compiler('c')

uvsrc = [
  'src/fs-poll.c',
  'src/idna.c',
  'src/inet.c',
  'src/random.c',
  'src/strscpy.c',
  'src/threadpool.c',
  'src/timer.c',
  'src/uv-common.c',
  'src/uv-data-getter-setters.c',
  'src/version.c',
]

uvdefines = [ ]

pthread = dependency('threads')
libuv_deps = [
  cc.find_library('m', required: false),
  cc.find_library('dl', required: false),
  pthread
]

if host_machine.system() == 'windows'
  uvsrc += [
    'src/win/async.c',
    'src/win/core.c',
    'src/win/detect-wakeup.c',
    'src/win/dl.c',
    'src/win/error.c',
    'src/win/fs.c',
    'src/win/fs-event.c',
    'src/win/getaddrinfo.c',
    'src/win/getnameinfo.c',
    'src/win/handle.c',
    'src/win/loop-watcher.c',
    'src/win/pipe.c',
    'src/win/thread.c',
    'src/win/poll.c',
    'src/win/process.c',
    'src/win/process-stdio.c',
    'src/win/signal.c',
    'src/win/snprintf.c',
    'src/win/stream.c',
    'src/win/tcp.c',
    'src/win/tty.c',
    'src/win/udp.c',
    'src/win/util.c',
    'src/win/winapi.c',
    'src/win/winsock.c',
  ]
  uvdefines += [
    '-DWIN32_LEAN_AND_MEAN',
    '-D_WIN32_WINNT=0x0602',
  ]
  libuv_deps += [
    cc.find_library('psapi'),
    cc.find_library('user32'),
    cc.find_library('advapi32'),
    cc.find_library('iphlpapi'),
    cc.find_library('userenv'),
    cc.find_library('ws2_32'),
  ]
else
  uvsrc += [
    'src/unix/async.c',
    'src/unix/core.c',
    'src/unix/dl.c',
    'src/unix/fs.c',
    'src/unix/getaddrinfo.c',
    'src/unix/getnameinfo.c',
    'src/unix/loop-watcher.c',
    'src/unix/loop.c',
    'src/unix/pipe.c',
    'src/unix/poll.c',
    'src/unix/process.c',
    'src/unix/random-devurandom.c',
    'src/unix/signal.c',
    'src/unix/stream.c',
    'src/unix/tcp.c',
    'src/unix/thread.c',
    'src/unix/tty.c',
    'src/unix/udp.c',
  ]
  uvdefines += [
    '-D_FILE_OFFSET_BITS=64',
    '-D_LARGEFILE_SOURCE'
  ]
endif

if host_machine.system() == 'android'
  uvsrc += [
    'src/unix/android-ifaddrs.c',
    'src/unix/linux-core.c',
    'src/unix/linux-inotify.c',
    'src/unix/linux-syscalls.c',
    'src/unix/procfs-exepath.c',
    'src/unix/pthread-fixes.c',
    'src/unix/random-getentropy.c',
    'src/unix/random-getrandom.c',
    'src/unix/random-sysctl-linux.c',
    'src/unix/proctitle.c',
  ]
  uvdefines += [
    '-D_GNU_SOURCE',
  ]
endif

if host_machine.system() == 'dragonfly' or host_machine.system() == 'freebsd'
  uvsrc += [
    'src/unix/freebsd.c',
  ]
endif

if host_machine.system().endswith('bsd') or host_machine.system() == 'dragonfly'
  uvsrc += [
    'src/unix/posix-hrtime.c',
    'src/unix/bsd-proctitle.c',
  ]
endif

if host_machine.system().endswith('bsd') or host_machine.system() == 'dragonfly' or host_machine.system() == 'darwin'
  uvsrc += [
    'src/unix/bsd-ifaddrs.c',
    'src/unix/kqueue.c',
  ]
endif

if host_machine.system() == 'freebsd'
  uvsrc += [
    'src/unix/random-getrandom.c',
  ]
endif

if host_machine.system() == 'openbsd' or host_machine.system() == 'darwin'
  uvsrc += [
    'src/unix/random-getentropy.c',
  ]
endif

if host_machine.system() == 'darwin'
  uvsrc += [
    'src/unix/darwin-proctitle.c',
    'src/unix/darwin.c',
    'src/unix/fsevents.c',
    'src/unix/proctitle.c',
  ]
  uvdefines += [
    '-D_DARWIN_USE_64_BIT_INODE=1',
    '-D_DARWIN_UNLIMITED_SELECT=1'
  ]
endif

if host_machine.system() == 'linux'
  uvsrc += [
    'src/unix/linux-core.c',
    'src/unix/linux-inotify.c',
    'src/unix/linux-syscalls.c',
    'src/unix/procfs-exepath.c',
    'src/unix/random-getrandom.c',
    'src/unix/random-sysctl-linux.c',
    'src/unix/proctitle.c',
  ]
  uvdefines += [
    '-D_GNU_SOURCE',
    '-D_POSIX_C_SOURCE=200112',
  ]
endif

if host_machine.system() == 'netbsd'
  uvsrc += [
    'src/unix/netbsd.c',
  ]
  libuv_deps += [
    cc.find_library('kvm', required: true),
  ]
endif

if host_machine.system() == 'openbsd'
  uvsrc += [
    'src/unix/openbsd.c',
  ]
endif

if host_machine.system() == 'sunos'
  uvsrc += [
    'src/unix/no-proctitle.c',
    'src/unix/sunos.c',
  ]
  uvdefines += [
    '-D__EXTENSIONS__',
    '-D_XOPEN_SOURCE=500',
  ]
  libuv_deps += [
    cc.find_library('kstat', required: true),
    cc.find_library('nsl', required: true),
    cc.find_library('sendfile', required: true),
    cc.find_library('socket', required: true),
  ]
endif

if host_machine.system() == 'haiku'
  uvsrc += [
    'src/unix/haiku.c',
	  'src/unix/bsd-ifaddrs.c',
	  'src/unix/no-fsevents.c',
	  'src/unix/no-proctitle.c',
	  'src/unix/posix-hrtime.c',
	  'src/unix/posix-poll.c',
  ]
  uvdefines += [
    '-D_BSD_SOURCE',
  ]
  libuv_deps += [
    cc.find_library('bsd', required: true),
    cc.find_library('network', required: true),
  ]
endif

add_project_arguments(
  # https://github.com/libuv/libuv/issues/2603
  cc.get_supported_arguments('-fcommon'),
  language: 'c',
)
uvincdir = include_directories('include', 'src', 'src/unix')

libuv = library('uv',
  uvsrc,
  c_args: uvdefines,
  dependencies: libuv_deps,
  include_directories: uvincdir,
  install: false,
)

libuv_dep = declare_dependency(link_with: libuv,
  include_directories: include_directories('include'))
