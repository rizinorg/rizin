rz_bin_dependencies = [
  rz_util_dep,
  rz_socket_dep,
  rz_hash_dep,
  rz_cons_dep,
  rz_io_dep,
]

rz_bin_sources = [
  'bin.c',
  'bin_write.c',
  'dbginfo.c',
  'demangle.c',
  'dwarf.c',
  'blang.c',
  'filter.c',
  'bfile.c',
  'bobj.c',

  'mangling/cxx.c',
  'mangling/cxx/cp-demangle.c',
  'mangling/demangler.c',
  'mangling/rust.c',
  'mangling/java.c',
  'mangling/microsoft_demangle.c',
  'mangling/msvc.c',
  'mangling/objc.c',
  'mangling/swift-sd.c',
  'mangling/swift.c',

  'pdb/dbi.c',
  'pdb/fpo.c',
  'pdb/gdata.c',
  'pdb/omap.c',
  'pdb/pdb.c',
  'pdb/pdb_downloader.c',
  'pdb/stream_file.c',
  'pdb/stream_pe.c',
  'pdb/tpi.c'
]

rz_bin_inc = [platform_inc, include_directories('mangling', 'format')]

rz_bin = library('rz_bin', rz_bin_sources,
  include_directories: rz_bin_inc,
  c_args: ['-DRZ_API_BIN_ONLY=1'] + library_cflags,
  dependencies: rz_bin_dependencies,
  link_with: rz_bin_static_plugins,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_bin_dep = declare_dependency(link_with: rz_bin,
                               include_directories: rz_bin_inc)

pkgconfig_mod.generate(rz_bin,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_bin',
  filebase: 'rz_bin',
  libraries: pkgcfg_sanitize_libs,
  requires: pkgconfig_magic_requires + [
    'rz_util',
    'rz_io',
    'rz_socket',
    'rz_syscall'
  ],
  description: 'rizin foundation libraries'
)

subdir('d')
