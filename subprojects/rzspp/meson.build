project('rzspp', 'c')
spp_version = '1.2.0'

spp_files = [
  'spp.c',
]

spp_inc = [include_directories('.')]

rz_util_dep = dependency('rz_util')
librzspp = static_library('rzspp', spp_files,
  dependencies: [rz_util_dep],
  include_directories: spp_inc,
  c_args: ['-DUSE_RZ_UTIL=1'],
  implicit_include_directories: false
)

cc = meson.get_compiler('c')

userconf = configuration_data()
foreach item : [
    ['system', '#include <stdlib.h>', []],
    ['fork', '#include <unistd.h>', []],
  ]
  func = item[0]
  ok = cc.has_function(func, prefix: item[1], dependencies: item[2])
  userconf.set10('HAVE_@0@'.format(func.to_upper()), ok)
endforeach

userconf_h_in = files('config.h.in')
userconf_h = configure_file(
  input: userconf_h_in,
  output: 'config.h',
  configuration: userconf,
)

spp_static_dep = declare_dependency(
  link_whole: librzspp,
  include_directories: spp_inc,
)
meson.override_dependency('rzspp', spp_static_dep)
