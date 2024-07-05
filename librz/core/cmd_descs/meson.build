cmd_descs_generate_py = files('cmd_descs_generate.py')
cmd_descs_yaml = files(
  'cmd_alias.yaml',
  'cmd_analysis.yaml',
  'cmd_block.yaml',
  'cmd_cmp.yaml',
  'cmd_debug.yaml',
  'cmd_descs.yaml',
  'cmd_egg.yaml',
  'cmd_eval.yaml',
  'cmd_flag.yaml',
  'cmd_flirt.yaml',
  'cmd_heap_glibc.yaml',
  'cmd_slub.yaml',
  'cmd_history.yaml',
  'cmd_info.yaml',
  'cmd_interpret.yaml',
  'cmd_macro.yaml',
  'cmd_math.yaml',
  'cmd_meta.yaml',
  'cmd_open.yaml',
  'cmd_plugins.yaml',
  'cmd_print.yaml',
  'cmd_project.yaml',
  'cmd_quit.yaml',
  'cmd_remote.yaml',
  'cmd_resize.yaml',
  'cmd_seek.yaml',
  'cmd_search.yaml',
  'cmd_shell.yaml',
  'cmd_system.yaml',
  'cmd_tasks.yaml',
  'cmd_type.yaml',
  'cmd_write.yaml',
  'cmd_yank.yaml',
)
cmd_descs_src_c = files('cmd_descs.c', 'cmd_descs.h')

r = run_command(py3_exe, '-c', 'import yaml', check: false)
cmd_option = get_option('regenerate_cmds')
has_pyyaml = r.returncode() == 0
if (cmd_option.auto() or cmd_option.enabled()) and has_pyyaml
  cmd_descs_ch = custom_target(
    'cmd_descs.[ch]',
    output: ['cmd_descs.c', 'cmd_descs.h'],
    input: cmd_descs_yaml,
    command: [py3_exe, cmd_descs_generate_py, '--output-dir', '@OUTDIR@', '--src-output-dir', meson.current_source_dir(), '@INPUT@']
  )
elif cmd_option.enabled() and not has_pyyaml
  error('PyYAML python module was not found, but it is required to regenerate cmd_descs.[ch]')
else
  warning('PyYAML python module was not found, using cmd_descs.c/cmd_descs.h from source directory. Install PyYAML (either from your package manager or through pip) if you need to modify cmd_descs files.')
  cmd_descs_ch = cmd_descs_src_c
endif
