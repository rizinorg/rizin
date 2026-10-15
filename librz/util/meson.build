subdir('sdb/src')

rz_util_common_sources = [
  'alloc.c',
  'annotated_code.c',
  'ascii_table.c',
  'asn1.c',
  'asn1_str.c',
  'assert.c',
  'axml.c',
  'bits.c',
  'bitvector.c',
  'buf.c',
  'chmod.c',
  'compression.c',
  'debruijn.c',
  'ebcdic.c',
  'event.c',
  'file.c',
  'float/float.c',
  'getopt.c',
  'graph_drawable.c',
  'graph_impl.c',
  'graph_algorithm.c',
  'hex.c',
  'idpool.c',
  'intervaltree.c',
  'iterator.c',
  'itv.c',
  'json_indent.c',
  'json_parser.c',
  'lang_byte_array.c',
  'lib.c',
  'list.c',
  'log.c',
  'luhn.c',
  'math.c',
  'mem.c',
  'name.c',
  'path.c',
  'pj.c',
  'pkcs7.c',
  'pkcs8.c',
  'print.c',
  'protobuf.c',
  'punycode.c',
  'rbtree.c',
  'regex.c',
  'serialize_spaces.c',
  'set.c',
  'signal.c',
  'skiplist.c',
  'skyline.c',
  'spaces.c',
  'stack.c',
  'str.c',
  'str_constpool.c',
  'str_search.c',
  'str_trim.c',
  'str_uri.c',
  'strbuf.c',
  'strpool.c',
  'structured_data.c',
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
  'thread_ring_buf.c',
  'thread_sem.c',
  'thread_types.c',
  'time.c',
  'tree.c',
  'trie.c',
  'base16.c',
  'base32.c',
  'base36.c',
  'base64.c',
  'base85.c',
  'base91.c',
  'uleb128.c',
  'unicode.c',
  'unum.c',
  'utf16.c',
  'utf32.c',
  'utf8.c',
  'vector.c',
  'version.c',
  'w32-sys.c',
  'x509.c',
  'ht/ht_uu.c',
  'ht/ht_pp.c',
  'ht/ht_up.c',
  'ht/ht_pu.c',
  'ht/ht_sp.c',
  'ht/ht_ss.c',
  'ht/ht_su.c',
]
rz_util_sources = rz_util_common_sources

# The RzNum tree-sitter evaluator. It needs the tree-sitter runtime and
# the generated math grammar, so it is kept apart from the common
# sources: the regular library builds it (rz_util_sources below), but
# the build-machine variant used only for sdb_gen does not (sdb_gen
# never evaluates expressions), which keeps tree-sitter out of the
# native toolchain. See the native block for the small shim that
# satisfies unum.c's two references in that configuration.
rz_util_evaluator_sources = [
  'num/parser.c',
  'num/evaluator.c',
  'num/value_print.c',
  'num/expr.c',
]
rz_util_sources += rz_util_evaluator_sources

# tree-sitter and the RzNum math grammar are pulled in so that the
# rz_num_math_value() evaluator (introduced in a subsequent commit)
# can drive a real grammar-based parser.
math_parser_dep = dependency('rizin-math-parser')
rz_util_deps = [ldl, lrt, mth, th, utl, pcre2_dep, softfloat_dep, math_parser_dep] + platform_deps
rz_util_public_deps = []
rz_util_public_cmake_deps = []
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
  rz_util_public_deps += [sys_openssl]
  rz_util_public_cmake_deps += ['OpenSSL|OpenSSL::Crypto']
  rz_util_sources += ['big-ssl.c']
else
  rz_util_sources += ['big.c', 'big_decimal.c']
endif

rz_util_includes = [platform_inc, include_directories('sdb/src')]

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
  dependencies: rz_util_public_deps,
  include_directories: rz_util_includes,
)
meson.override_dependency('rz_util', rz_util_dep)

if meson.is_cross_build()
  # this is a bit messy, it duplicates most of the code required to get the
  # regular dependencies but for the build_system. This is required to build
  # sdb_gen natively, used at build time to compile .sdb.txt files into .sdb
  # ones.
  platform_native_deps = []
  if build_machine.system() == 'windows'
    platform_native_deps = [
      cc_native.find_library('ws2_32'),
      cc_native.find_library('wininet'),
      cc_native.find_library('psapi'),
    ]
  endif
  rz_util_native_deps = [ldl_native, lrt_native, mth_native, th_native, utl_native, pcre2_native_dep, softfloat_cross_native_dep] + platform_native_deps
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
  # No num/* here: the evaluator is replaced by native_shim.c,
  # which provides the two entry points unum.c links against without
  # pulling in tree-sitter. sdb_gen does not evaluate expressions, so the
  # shim's degenerate "every expression is 0" behaviour is all the native
  # build ever needs (there is no longer a legacy calculator to fall back on).
  rz_util_native_sources = rz_util_common_sources + ['big.c', 'big_decimal.c', 'num/native_shim.c']

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
    'cmake_external_deps': rz_util_public_cmake_deps,
    'include_subdirs_extra': ['librz/sdb']
}}

sdb_exe = executable('sdb_gen', 'sdb/src/main.c',
  dependencies: rz_util_native_dep,
  install: false,
  native: meson.is_cross_build(),
  implicit_include_directories: false,
  install_rpath: rpath_exe,
)

sdb_gen_cmd = [
  sdb_exe,
  '@OUTPUT@',
  '==',
  '@INPUT@'
]
