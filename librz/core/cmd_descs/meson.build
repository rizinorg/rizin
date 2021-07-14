cmd_descs_generate_py = files('cmd_descs_generate.py')
cmd_descs_yaml = files(
  'cmd_analysis.yaml',
  'cmd_debug.yaml',
  'cmd_descs.yaml',
  'cmd_eval.yaml',
  'cmd_heap_glibc.yaml',
  'cmd_info.yaml',
  'cmd_interpret.yaml',
  'cmd_plugins.yaml',
  'cmd_project.yaml',
  'cmd_print.yaml',
  'cmd_quit.yaml',
  'cmd_remote.yaml',
  'cmd_seek.yaml',
  'cmd_tasks.yaml',
  'cmd_type.yaml',
  'cmd_write.yaml',
  'cmd_zign.yaml',
)
cmd_descs_src_c = files('cmd_descs.c')

r = run_command(py3_exe, '-c', 'import yaml')
if r.returncode() == 0
  cmd_descs_c = custom_target(
    'cmd_descs.c',
    output: ['cmd_descs.c'],
    input: [cmd_descs_generate_py, cmd_descs_yaml],
    command: [py3_exe, cmd_descs_generate_py, '--output-dir', '@OUTDIR@', '--src-output-dir', meson.current_source_dir(), cmd_descs_yaml]
  )
else
  warning('PyYAML python module was not found, using cmd_descs.c/cmd_descs.h from source directory. Install PyYAML (either from your package manager or through pip) if you need to modify cmd_descs files.')
  cmd_descs_c = cmd_descs_src_c
endif
