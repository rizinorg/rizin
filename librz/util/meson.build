subdir('sdb/src')

rz_util_common_sources = [
  'alloc.c',
  'annotated_code.c',
  'ascii_table.c',
  'asn1.c',
  'assert.c',
  'astr.c',
  'axml.c',
  'base85.c',
  'base91.c',
  'bitvector.c',
  'buf.c',
  'calc.c',
  'chmod.c',
  'compression.c',
  'debruijn.c',
  'ebcdic.c',
  'event.c',
  'file.c',
  'float/float.c',
  'getopt.c',
  'graph.c',
  'graph_drawable.c',
  'hex.c',
  'idpool.c',
  'intervaltree.c',
  'json_indent.c',
  'json_parser.c',
  'lang_byte_array.c',
  'lib.c',
  'list.c',
  'log.c',
  'luhn.c',
  'mem.c',
  'name.c',
  'path.c',
  'pj.c',
  'pkcs7.c',
  'print.c',
  'protobuf.c',
  'punycode.c',
  'range.c',
  'rbtree.c',
  'regex/regcomp.c',
  'regex/regerror.c',
  'regex/regexec.c',
  'serialize_spaces.c',
  'signal.c',
  'skiplist.c',
  'skyline.c',
  'spaces.c',
  'stack.c',
  'str.c',
  'str_constpool.c',
  'str_search.c',
  'str_trim.c',
  'strbuf.c',
  'strpool.c',
  'subprocess.c',
  'sys.c',
  'syscmd.c',
  'table.c',
  'thread.c',
  'thread_cond.c',
  'thread_hash_table.c',
  'thread_iterators.c',
  'thread_lock.c',
  'thread_pool.c',
  'thread_queue.c',
  'thread_sem.c',
  'thread_types.c',
  'time.c',
  'tree.c',
  'ubase64.c',
  'uleb128.c',
  'unum.c',
  'utf16.c',
  'utf32.c',
  'utf8.c',
  'vector.c',
  'version.c',
  'w32-sys.c',
  'x509.c',
]
rz_util_sources = rz_util_common_sources

rz_util_deps = [ldl, lrt, mth, th, utl] + platform_deps
if zlib_dep.found()
  rz_util_deps += [zlib_dep]
endif
if liblzma_dep.found()
  rz_util_deps += [liblzma_dep]
endif
if ['freebsd', 'netbsd', 'haiku', 'dragonfly'].contains(host_machine.system())
  # backtrace_symbols_fd requires -lexecinfo
  rz_util_deps += [cc.find_library('execinfo', static: is_static_build)]
endif
if meson.is_cross_build()
  execinfo_native = disabler()
  if ['freebsd', 'netbsd', 'haiku', 'dragonfly'].contains(build_machine.system())
    # backtrace_symbols_fd requires -lexecinfo
    execinfo_native = cc_native.find_library('execinfo', static: is_static_build)
  endif
endif

if sys_openssl.found()
  rz_util_deps += [sys_openssl]
  rz_util_sources += ['big-ssl.c']
else
  rz_util_sources += ['big.c']
endif

rz_util_includes = [platform_inc, include_directories('sdb/src', 'sdb')]

rz_util = library('rz_util', rz_util_sources, libsdb_sources,
  include_directories: rz_util_includes,
  dependencies: rz_util_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_util_dep = declare_dependency(
  link_with: rz_util,
  include_directories: rz_util_includes,
)
meson.override_dependency('rz_util', rz_util_dep)

if meson.is_cross_build()
  # this is a bit messy, it duplicates most of the code required to get the
  # regular dependencies but for the build_system. This is required to build
  # sdb_native, used at build time to compile .sdb.txt files into .sdb ones.
  platform_native_deps = []
  if build_machine.system() == 'windows'
    platform_native_deps = [
      cc_native.find_library('ws2_32'),
      cc_native.find_library('wininet'),
      cc_native.find_library('psapi'),
    ]
  endif
  rz_util_native_deps = [ldl_native, lrt_native, mth_native, th_native, utl_native] + platform_native_deps
  if execinfo_native.found()
    rz_util_native_deps += [execinfo_native]
  endif
  # do not use external libs, we do not need them
  userconf_native.set10('HAVE_LIB_MAGIC', false)
  userconf_native.set10('USE_LIB_MAGIC', false)
  userconf_native.set10('HAVE_LIB_XXHASH', false)
  userconf_native.set10('USE_LIB_XXHASH', false)
  userconf_native.set10('HAVE_OPENSSL', false)
  userconf_native.set10('HAVE_LZMA', false)
  userconf_native.set10('HAVE_ZLIB', false)

  rz_userconf_native_h = configure_file(
    input: rz_userconf_h_in,
    output: 'rz_userconf.h',
    configuration: userconf_native,
    install_dir: rizin_incdir
  )
  rz_util_native_includes = [include_directories('.'), rz_util_includes]
  rz_util_native_sources = rz_util_common_sources + ['big.c']

  rz_util_native = static_library('rz_util_native', rz_util_native_sources, libsdb_sources,
    include_directories: rz_util_native_includes,
    dependencies: rz_util_native_deps,
    implicit_include_directories: false,
    install_rpath: rpath_lib,
    install: false,
    native: true,
  )

  rz_util_native_dep = declare_dependency(
    link_with: rz_util_native,
    include_directories: rz_util_native_includes,
  )
else
  rz_util_native_dep = rz_util_dep
endif

modules += { 'rz_util': {
    'target': rz_util,
    'dependencies': [],
    'include_subdirs_extra': ['librz/sdb']
}}

sdb_exe = executable('sdb_native', 'sdb/src/main.c',
  dependencies: rz_util_native_dep,
  install: false,
  native: true,
  implicit_include_directories: false,
  install_rpath: rpath_exe,
)

sdb_gen_cmd = [
  sdb_exe,
  '@OUTPUT@',
  '==',
  '@INPUT@'
]
