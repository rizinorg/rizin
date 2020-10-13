rz_hash_sources = [
  'adler32.c',
  'hcalc.c',
  'crca.c',
  'entropy.c',
  'fletcher.c',
  'hamdist.c',
  'hash.c',
  'luhn.c',
  'state.c'
]

dependencies = [mth, rz_util_dep]

if use_sys_xxhash
  dependencies += [sys_xxhash]
else
  rz_hash_sources += ['xxhash.c']
endif

if use_sys_openssl
  dependencies += [sys_openssl]
else
  rz_hash_sources += ['md4.c', 'md5.c', 'sha1.c', 'sha2.c']
endif

rz_hash = library('rz_hash', rz_hash_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: dependencies,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_hash_dep = declare_dependency(link_with: rz_hash,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(rz_hash,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_hash',
  filebase: 'rz_hash',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'radare foundation libraries'
)
