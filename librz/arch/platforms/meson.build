sdb_platform_files = [
  'arm-arm1176-bcm2835',
  'arm-cortexA72-bcm2711',
  'arm-cortexA8-omap3430',
  'x86-generic-generic',
]

foreach file : sdb_platform_files
  outfile = '@0@.sdb'.format(file)
  custom_target(outfile,
    input: '@0@.sdb.txt'.format(file),
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(rizin_sdb, 'arch/platforms')
  )
endforeach
