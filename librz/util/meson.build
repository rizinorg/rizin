
rz_util_sources = [
  'alloc.c',
  'annotated_code.c',
  'ascii_table.c',
  'asn1.c',
  'assert.c',
  'astr.c',
  'axml.c',
  'base85.c',
  'base91.c',
  'bitmap.c',
  'bitvector.c',
  'buf.c',
  'calc.c',
  'chmod.c',
  'debruijn.c',
  'ebcdic.c',
  'event.c',
  'file.c',
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
  'queue.c',
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
  'thread_lock.c',
  'thread_sem.c',
  'thread_pool.c',
  'thread_queue.c',
  'time.c',
  'tree.c',
  'ubase64.c',
  'uleb128.c',
  'unum.c',
  'utf16.c',
  'utf32.c',
  'utf8.c',
  'vector.c',
  'w32-sys.c',
  'x509.c',
  'zip.c',
]

rz_util_deps = [ldl, lrt, mth, th, utl, sdb_dep, zlib_dep] + platform_deps
if ['freebsd', 'netbsd', 'haiku', 'dragonfly'].contains(host_machine.system())
  # backtrace_symbols_fd requires -lexecinfo
  rz_util_deps += [cc.find_library('execinfo', static: is_static_build)]
endif

if sys_openssl.found()
  rz_util_deps += [sys_openssl]
  rz_util_sources += ['big-ssl.c']
else
  rz_util_sources += ['big.c']
endif

rz_util = library('rz_util', rz_util_sources,
  include_directories: platform_inc,
  c_args: library_cflags,
  dependencies: rz_util_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_util_dep = declare_dependency(
  link_with: rz_util,
  include_directories: platform_inc,
  dependencies: [
    sdb_dep.partial_dependency(includes: true),
  ]
)
meson.override_dependency('rz_util', rz_util_dep)

pkgconfig_mod.generate(rz_util,
  subdirs: ['librz', 'librz/sdb'],
  version: rizin_version,
  name: 'rz_util',
  filebase: 'rz_util',
  description: 'rizin foundation libraries',
  variables: [
    'datdir=@0@'.format(rizin_datdir_rz),
  ],
)

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('RIZIN_MODULE', rz_util.name())
  conf.set('RIZIN_MODULE_DEPS', ' '.join([]))
  conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
  conf.set('INSTALL_INCDIR', rizin_incdir)
  conf.set('INSTALL_LIBDIR', rizin_libdir)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  conf.set('rizin_libname', rz_util.name())
  cmake_mod.configure_package_config_file(
    name: conf.get('rizin_libname'),
    input: '../RzModulesConfig.cmake.in',
    install_dir: rizin_cmakedir / conf.get('rizin_libname'),
    configuration: conf,
  )
endif
