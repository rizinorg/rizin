rz_crypto_sources = [
  'des.c',
  'crypto.c',
  'p/crypto_aes.c',
  'p/crypto_aes_algo.c',
  'p/crypto_aes_cbc.c',
  'p/crypto_base64.c',
  'p/crypto_base91.c',
  'p/crypto_blowfish.c',
  'p/crypto_cps2.c',
  'p/crypto_des.c',
  'p/crypto_punycode.c',
  'p/crypto_rc2.c',
  'p/crypto_rc4.c',
  'p/crypto_rc6.c',
  'p/crypto_rol.c',
  'p/crypto_ror.c',
  'p/crypto_rot.c',
  'p/crypto_serpent.c',
  'p/crypto_serpent_algo.c',
  'p/crypto_xor.c',
]

rz_crypto = library('rz_crypto', rz_crypto_sources,
  include_directories: [platform_inc],
  dependencies: [rz_util_dep],
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_crypto_dep = declare_dependency(link_with: rz_crypto,
                                  include_directories: [platform_inc])

pkgconfig_mod.generate(rz_crypto,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_crypto',
  filebase: 'rz_crypto',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
