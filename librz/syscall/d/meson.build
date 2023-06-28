sdb_files = [
  'darwin-arm-32',
  'darwin-arm-64',
  'darwin-x86-32',
  'darwin-x86-64',
  'dos-x86-16',
  'freebsd-x86-32',
  'ios-arm-32',
  'ios-arm-64',
  'ios-x86-32',
  'linux-arm-32',
  'linux-arm-64',
  'linux-mips-32',
  'linux-sparc-32',
  'linux-x86-32',
  'linux-x86-64',
  'netbsd-x86-32',
  'openbsd-x86-32',
  'openbsd-x86-64',
  's110-arm-16',
  'windows-x86-32',
  'windows-x86-64',
]

foreach file : sdb_files
  tmp_outfile = '@0@.sdb.txt.tmp'.format(file)
  pre_sdb_txt = custom_target(tmp_outfile,
    input: '@0@.sdb.txt'.format(file),
    output: tmp_outfile,
    command: [py3_exe, syscall_preprocessing_py, '@INPUT@', '@OUTPUT@'],
    build_by_default: true,
    install: false
  )

  outfile = '@0@.sdb'.format(file)
  custom_target(outfile,
    input: pre_sdb_txt,
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(rizin_sdb, 'syscall')
  )
endforeach
