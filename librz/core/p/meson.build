core_plugins = [
  'java',
]

core_enabled_static_plugins = core_plugins
core_enabled_shared_plugins = []

core_java_sources = files(
  'core_java.c',
  '../../bin/format/java/json.c',
  '../../bin/format/java/class.c',
  '../../bin/format/java/print.c',
)

core_java_headers = include_directories(
  '../../bin/format/',
)

core_java_deps = [
  rz_cons_dep,
  rz_io_dep,
]
