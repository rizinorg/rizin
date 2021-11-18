project('rizin-cpp-test', 'cpp')

rizin_libs = dependency('rz_core', required: true)

exe = executable('test_cpp', 'test_cpp.cpp',
  c_args: executable_cflags,
  dependencies: [rizin_libs],
  install: false,
  implicit_include_directories: false,
  link_args: executable_linkflags
)

test('cpp', exe)
