lang_plugins = [
  'lib',
  'pipe',
  'rust',
  'vala',
  'zig',
  'spp',
]

if host_machine.system() != 'windows'
  lang_plugins += [
    'c',
    'cpipe'
  ]
endif

lang_enabled_static_plugins = lang_plugins
lang_enabled_shared_plugins = []

lang_c_sources = files(
  'c.c',
)

lang_cpipe_sources = files(
  'cpipe.c',
  'pipe_common.c',
)

lang_cpipe_deps = [
  rz_cons_dep,
]

lang_lib_sources = files(
  'lib.c',
)

lang_pipe_sources = files(
  'pipe.c',
  'pipe_common.c',
)

lang_pipe_deps = [
  rz_cons_dep,
]

lang_rust_sources = files(
  'rust.c',
)

lang_vala_sources = files(
  'vala.c',
)

lang_zig_sources = files(
  'zig.c',
)

lang_spp_sources = files(
  'spp.c',
)

lang_spp_deps = [
  spp_dep,
  rz_cons_dep,
]
