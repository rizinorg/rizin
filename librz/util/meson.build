
rz_util_sources = [
  'ascii_table.c',
  'assert.c',
  'alloc.c',
  'table.c',
  'getopt.c',
  'print_code.c',
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
  'graph.c',
  'graph_drawable.c',
  'hex.c',
  'idpool.c',
  'json_parser.c',
  'json_indent.c',
  'lib.c',
  'list.c',
  'log.c',
  'mem.c',
  'name.c',
  'pie.c',
  'seven.c',
  'path.c',
  'print.c',
  'punycode.c',
  'queue.c',
  'asn1.c',
  'astr.c',
  'pkcs7.c',
  'x509.c',
  'randomart.c',
  'range.c',
  'rbtree.c',
  'intervaltree.c',
  'signal.c',
  'skiplist.c',
  'spaces.c',
  'stack.c',
  'str.c',
  'str_constpool.c',
  'str_search.c',
  'str_trim.c',
  'strbuf.c',
  'strpool.c',
  'sys.c',
  'syscmd.c',
  'thread.c',
  'thread_sem.c',
  'thread_lock.c',
  'thread_cond.c',
  'time.c',
  'tree.c',
  'pj.c',
  'ubase64.c',
  'uleb128.c',
  'unum.c',
  'utf8.c',
  'utf16.c',
  'utf32.c',
  'vector.c',
  'skyline.c',
  'w32-sys.c',
  'zip.c',
  'protobuf.c',
  'regex/regcomp.c',
  'regex/regexec.c',
  'regex/regerror.c',
  'annotated_code.c',
  'serialize_spaces.c',
  'subprocess.c',
  'luhn.c'
]

rz_util_deps = [ldl, lrt, mth, pth, utl, sdb_dep, zlib_dep] + platform_deps
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
  soversion: rizin_libversion
)

rz_util_dep = declare_dependency(
  link_with: rz_util,
  include_directories: platform_inc,
  dependencies: [
    sdb_dep.partial_dependency(includes: true),
  ]
)

pkgconfig_mod.generate(rz_util,
  subdirs: ['librz', 'librz/sdb'],
  version: rizin_version,
  name: 'rz_util',
  filebase: 'rz_util',
  description: 'rizin foundation libraries'
)

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', rz_util.name())
conf.set('RIZIN_MODULE_DEPS', ' '.join([]))
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('INSTALL_PLUGDIR', rizin_plugins)
conf.set('rizin_libname', rz_util.name())
cmake_mod.configure_package_config_file(
  name: conf.get('rizin_libname'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir,
  configuration: conf,
)
