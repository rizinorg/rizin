sdb_cpus_files = [
  'avr-ATmega1280',
  'avr-ATmega1281',
  'avr-ATxmega128a4u',
  'avr-ATmega2560',
  'avr-ATmega2561',
  'avr-ATmega640',
  'avr-ATmega8',
  'avr-ATmega88',
  'avr-ATmega16',
  'avr-ATmega168',
  'avr-ATTiny48',
  'avr-ATTiny88',
]

foreach file : sdb_cpus_files
  outfile = '@0@.sdb'.format(file)
  custom_target(outfile,
    input: '@0@.sdb.txt'.format(file),
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(rizin_sdb, 'asm/cpus')
  )
endforeach
