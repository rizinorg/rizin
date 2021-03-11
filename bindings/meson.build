swig = find_program('swig')

# todo: depfile
rz_core_swig = custom_target('rz_core_swig',
  input: 'rz_core.i',
  output: ['rz_core.py', 'rz_core_wrap.c'],
  command: [swig, '-python', '-py3', '-outdir', '@OUTDIR@', '-o', '@OUTPUT1@', '-I@CURRENT_SOURCE_DIR@/librz/include', '-MMD', '@INPUT@'],
  install: true,
  install_dir: [py3_exe.get_install_dir(), false]
)

rz_core_swig_c_dep = declare_dependency(
    sources: [rz_core_swig[1]]
)

py3_exe.extension_module('_rz_core',
  [rz_core_swig[1]],
  dependencies: [rz_core_swig_c_dep, sdb_dep, py3_exe.dependency(), rz_core_dep],
  install_rpath: rpath_lib,
  install: true,
  install_dir: py3_exe.get_install_dir()
)
