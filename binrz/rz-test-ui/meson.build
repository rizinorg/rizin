if get_option('enable_rz_test')
  rz_test_ui_exe = executable('rz-test-ui', ['rz-test-ui.c', 'load.c', 'run.c', 'vscreen.c', 'worker.c', '../rz-test/run.c'],
    include_directories: [platform_inc],
    dependencies: [
      rz_util_dep,
      rz_main_dep,
      rz_cons_dep,
      rz_diff_dep,
      lrt,
    ],
    install: true,
    install_rpath: rpath_exe,
    implicit_include_directories: false,
  )
endif
