if get_option('enable_doc')
  doxygen_exe = find_program('doxygen', required: true)

  r = run_command(py3_exe, check_meson_subproject_py, 'doxygen-awesome-css', check: false)
  if r.returncode() == 1 and get_option('subprojects_check')
    error(subproject_clean_error_msg)
  endif
  doxygen_awesome_css = subproject('doxygen-awesome-css')

  doxygen_args = [
    py3_exe, files('../sys/doxygen.py'),
    '--doxygen', doxygen_exe.full_path(),
    '--source-dir', meson.project_source_root(),
    '--output-dir', meson.project_build_root() / 'doc',
    '--theme-dir', doxygen_awesome_css.get_variable('doxygen_awesome_css_dir'),
    '--project-number', meson.project_version(),
  ]
  if get_option('werror')
    doxygen_args += '--warnings-as-errors'
  endif

  # Not built by default: generating the docs takes far longer than the library
  # itself and needs no compiler output, so it stays an explicit `ninja doc`.
  run_target('doc', command: doxygen_args)
endif
