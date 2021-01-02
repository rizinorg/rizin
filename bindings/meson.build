swig = find_program('swig')

# todo: depfile
custom_target('rz_core_swig',
  input: 'rz_core.i',
  output: ['rz_core.py', 'rz_core_wrap.c'],
  command: [swig, '-python', '-py3', '-outdir', '.', '-I@SOURCE_DIR@/librz/include', '-MMD', '@INPUT@']
)

py3_exe.extension_module('_rz_core',
  ['rz_core_wrap.c'],
  dependencies: [rz_core_dep, sdb_dep, py3_exe.dependency()],
  install_rpath: rpath_lib,
  install: true,
  install_dir: py3_exe.get_install_dir()
)
py3_exe.install_sources('rz_core.py')

