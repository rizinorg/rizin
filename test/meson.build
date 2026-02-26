subdir('unit')
subdir('integration')

# Regression tests (rz-test) for CRIS ESIL/RzIL - run with proper PATH on Windows
if get_option('enable_tests') and get_option('enable_rz_test') and cli_enabled
  rz_test_env = environment()
  if test_env_common_path != []
    rz_test_env.prepend('PATH', test_env_common_path)
  endif
  test('rz-test db cris',
    rz_test_exe,
    args: [
      '-r', rizin_exe.full_path(),
      '-m', rz_asm_exe.full_path(),
      'db/asm/cris_v10_32',
      'db/asm/cris_v32_32',
      'db/analysis/cris',
      'db/esil/cris',
      'db/rzil/cris',
    ],
    workdir: meson.current_source_dir(),
    env: rz_test_env,
    suite: 'db',
    timeout: 120,
  )
endif

if get_option('enable_benchmarks')
  subdir('bench')
endif
