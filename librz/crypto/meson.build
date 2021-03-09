crypto_plugins = [
  'aes',
  'aes_cbc',
  'base64',
  'base91',
  'blowfish',
  'cps2',
  'des',
  'punycode',
  'rc2',
  'rc4',
  'rc6',
  'rol',
  'ror',
  'rot',
  'serpent',
  'xor',
]

crypto_enabled_static_plugins = crypto_plugins
crypto_enabled_shared_plugins = []

rz_crypto_dependencies = [
  rz_util_dep,
]

crypto_aes_sources = [
  'p/crypto_aes.c',
  'p/crypto_aes_algo.c',
]

crypto_aes_cbc_sources = [
  'p/crypto_aes_cbc.c',
  'p/crypto_aes_algo.c',
]

crypto_base64_sources = [
  'p/crypto_base64.c',
]

crypto_base91_sources = [
  'p/crypto_base91.c',
]

crypto_blowfish_sources = [
  'p/crypto_blowfish.c',
]

crypto_cps2_sources = [
  'p/crypto_cps2.c',
]

crypto_des_sources = [
  'p/crypto_des.c',
]

crypto_punycode_sources = [
  'p/crypto_punycode.c',
]

crypto_rc2_sources = [
  'p/crypto_rc2.c',
]

crypto_rc4_sources = [
  'p/crypto_rc4.c',
]

crypto_rc6_sources = [
  'p/crypto_rc6.c',
]

crypto_rol_sources = [
  'p/crypto_rol.c',
]

crypto_ror_sources = [
  'p/crypto_ror.c',
]

crypto_rot_sources = [
  'p/crypto_rot.c',
]

crypto_serpent_sources = [
  'p/crypto_serpent.c',
  'p/crypto_serpent_algo.c',
]

crypto_xor_sources = [
  'p/crypto_xor.c',
]

# compile static plugins
rz_crypto_static_plugins = []
crypto_enabled_static_plugins_str = []
foreach p : crypto_plugins
  c_files = get_variable('crypto_@0@_sources'.format(p))
  h_files = get_variable('crypto_@0@_headers'.format(p), [])
  crypto_plugin_deps = get_variable('crypto_@0@_deps'.format(p), [])

  h_files = include_directories(h_files)
  name = 'crypto_plugin_@0@'.format(p)
  crypto_plugin_inc = [h_files, platform_inc]

  if p in crypto_enabled_static_plugins
    crypto_plugin = static_library(name, c_files,
      include_directories: crypto_plugin_inc,
      dependencies: rz_crypto_dependencies + crypto_plugin_deps,
      c_args: library_cflags,
      install: false,
    )

    rz_crypto_static_plugins += [crypto_plugin]
    crypto_enabled_static_plugins_str += ['&rz_crypto_plugin_@0@'.format(p)]
  endif
endforeach
crypto_enabled_static_plugins_str += ['0']

rz_crypto_sources = [
  'des.c',
  'crypto.c',
]

rz_crypto = library('rz_crypto', rz_crypto_sources,
  include_directories: [platform_inc],
  dependencies: rz_crypto_dependencies,
  link_with: rz_crypto_static_plugins,
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

# compile shared plugins
foreach p : crypto_plugins
  c_files = get_variable('crypto_@0@_sources'.format(p))
  h_files = get_variable('crypto_@0@_headers'.format(p), [])
  crypto_plugin_deps = get_variable('crypto_@0@_deps'.format(p), [])

  h_files = include_directories(h_files)
  name = 'crypto_plugin_@0@'.format(p)
  crypto_plugin_inc = [h_files, platform_inc]

  if p in crypto_enabled_shared_plugins
    crypto_plugin = shared_library(name, c_files,
      include_directories: crypto_plugin_inc,
      dependencies: [rz_crypto_dependencies, rz_crypto_dep, crypto_plugin_deps],
      install: true,
      install_dir: rizin_plugins,
    )
  endif
endforeach
