sdb_files = [
  'cc-arm-16',
  'cc-arm-32',
  'cc-arm-64',
  'cc-avr-8',
  'cc-m68k-32',
  'cc-mips-32',
  'cc-mips-64',
  'cc-ppc-32',
  'cc-ppc-64',
  'cc-riscv-64',
  'cc-sparc-32',
  'cc-spc700-16',
  'cc-sysz-64',
  'cc-x86-16',
  'cc-x86-32',
  'cc-x86-64',
  'cc-xtensa-32',
  'spec',
  'types-16',
  'types-32',
  'types-64',
  'types-arm-ios-16',
  'types-arm-ios-32',
  'types-arm-ios-64',
  'types-android',
  'types-atomic',
  'types-darwin',
  'types-libc',
  'types-linux',
  'types-windows',
  'types-x86-macos-64',
  'types-x86-windows-32',
  'types-x86-windows-64',
  'functions-android',
  'functions-darwin',
  'functions-libc',
  'functions-linux',
  'functions-windows'
]

win_types_extra = [
  'bcrypt',
  'cfgmgr32',
  'combaseapi',
  'commctrl',
  'consoleapi2',
  'dbghelp',
  'evntrace',
  'fileapi',
  'libloaderapi',
  'memoryapi',
  'ncrypt',
  'objbase',
  'oleauto',
  'processthreadsapi',
  'psapi',
  'securitybaseapi',
  'shellapi',
  'shlwapi',
  'synchapi',
  'sysinfoapi',
  'threadpoolapiset',
  'userenv',
  'winbase',
  'wincred',
  'wincrypt',
  'winhttp',
  'winldap',
  'winnls',
  'winreg',
  'winsock2',
  'winsvc',
  'winuser',
  'ws2spi',
]

fs = import('fs')

foreach file : sdb_files
  outfile = '@0@.sdb'.format(file)
  infiles = ['@0@.sdb.txt'.format(file)]
  if file == 'types-windows'
    foreach f : win_types_extra
      win_file = 'types-windows_@0@.sdb.txt'.format(f)
      if fs.exists(win_file)
          infiles += win_file
      endif
    endforeach
  endif
  if file == 'functions-windows'
    foreach f : win_types_extra
      infiles += 'functions-windows_@0@.sdb.txt'.format(f)
    endforeach
  endif
  custom_target(outfile,
    input: infiles,
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(rizin_sdb, 'types')
  )
endforeach
