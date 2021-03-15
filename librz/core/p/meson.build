core_plugins = [
  'java',
]

core_java_sources = files(
  'core_java.c',
  '../../bin/format/java/class_bin.c',
  '../../bin/format/java/class_attribute.c',
  '../../bin/format/java/class_const_pool.c',
  '../../bin/format/java/class_field.c',
  '../../bin/format/java/class_method.c',
  '../../bin/format/java/class_interface.c',
)

core_java_headers = include_directories(
  '../../bin/format/',
)

core_java_deps = [
  rz_cons_dep,
  rz_io_dep,
  rz_bin_dep,
]
