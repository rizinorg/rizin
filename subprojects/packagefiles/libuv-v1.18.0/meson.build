project('libuv', 'c', version : '1.18.0', license : 'libuv')

cc = meson.get_compiler('c')

uvsrc = [
  'src/fs-poll.c',
  'src/inet.c',
  'src/threadpool.c',
  'src/uv-common.c',
  'src/version.c',
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
  'src/unix/signal.c',
  'src/unix/stream.c',
  'src/unix/tcp.c',
  'src/unix/thread.c',
  'src/unix/timer.c',
  'src/unix/tty.c',
  'src/unix/udp.c'
]

# Linux systems
if cc.get_define('__linux__') != ''
    uvsrc += [
      'src/unix/linux-core.c',
      'src/unix/linux-inotify.c',
      'src/unix/linux-syscalls.c',
      'src/unix/procfs-exepath.c',
      'src/unix/proctitle.c',
      'src/unix/sysinfo-loadavg.c',
      'src/unix/sysinfo-memory.c',
    ]
endif


uvdefines = [ '-D_GNU_SOURCE', ]
add_project_arguments(
  # https://github.com/libuv/libuv/issues/2603
  cc.get_supported_arguments('-fcommon'),
  language: 'c',
)
uvincdir = include_directories('include', 'src', 'src/unix')

if cc.get_define('__ANDROID__') != ''
  uvsrc += [ 'src/unix/android-ifaddrs.c',
             'src/unix/pthread-fixes.c' ]
endif

# OSX systems
if cc.get_define('__APPLE__') != ''
    uvsrc += [
      'src/unix/bsd-ifaddrs.c',
      'src/unix/darwin.c',
      'src/unix/darwin-proctitle.c',
      'src/unix/fsevents.c',
      'src/unix/kqueue.c',
      'src/unix/proctitle.c'
    ]
    uvdefines += [
      '-D_DARWIN_USE_64_BIT_INODE=1',
      '-D_DARWIN_UNLIMITED_SELECT=1'
    ]
endif

pthread = dependency('threads')

libuv_deps = [ cc.find_library('m', required: false),
               cc.find_library('dl', required: false),
               pthread ]

libuv = library('uv',
  uvsrc,
  c_args: uvdefines,
  dependencies: libuv_deps,
  include_directories: uvincdir,
  install: false,
)

libuv_dep = declare_dependency(link_with: libuv,
  include_directories: include_directories('include'))
