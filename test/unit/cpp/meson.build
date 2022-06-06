project('rizin-cpp-test', 'cpp')

rizin_libs = dependency('rz_core', required: true)

exe = executable('test_cpp', 'test_cpp.cpp',
  dependencies: [rizin_libs],
  install: false,
  implicit_include_directories: false,
)

test('cpp', exe)