sdb_files = [
  'aclui',
  'activeds',
  'atl',
  'borlndmm',
  'browseui',
  'cabinet',
  'comctl32',
  'csmfpapi',
  'csmtpapi',
  'csncdapi',
  'dsound',
  'gsprop32',
  'iertutil',
  'kernel32',
  'mfc100u',
  'mfc120',
  'mfc140u',
  'mfc30',
  'mfc40',
  'mfc42',
  'mfc42u',
  'mfc71',
  'mfc71u',
  'mfc90u',
  'msi',
  'mstlsapi',
  'msvbvm50',
  'msvbvm60',
  'odbc32',
  'oleaut32',
  'olecli32',
  'oledlg',
  'olepro32',
  'olesvr32',
  'shdocvw',
  'shell32',
  'shlwapi',
  'spr32d70',
  'urlmon',
  'uxtheme',
  'vb40032',
  'vssapi',
  'winmm',
  'wldap32',
  'ws2_32',
  'wsnmp32',
  'wsock32',
  'AVICAP',
  'AVIFILE',
  'AWDEVL16',
  'CARDS',
  'CMC',
  'COMM',
  'COMMCTRL',
  'COMMDLG',
  'COMPOBJ',
  'CSPMAN',
  'DCIMAN',
  'DDEML',
  'DESKCP16',
  'DIBENG',
  'DISPDIB',
  'DISPLAY',
  'DSKMAINT',
  'ENABLE3',
  'FAXCODEC',
  'GDI',
  'INET16',
  'IOSCLASS',
  'KERNEL',
  'KEYBOARD',
  'LZEXPAND',
  'MAINCP16',
  'MAPI',
  'MAPIU',
  'MAPIX',
  'MCIAVI',
  'MCICDA',
  'MCIMIDI',
  'MCIOLE',
  'MCIWAVE',
  'MIDIMAP',
  'ML3XEC16',
  'MMCI',
  'MMSYSTEM',
  'MODEM',
  'MODEMUI',
  'MOUSE',
  'MSACM',
  'MSACMMAP',
  'MSDOS',
  'MSDOSD',
  'MSJSTICK',
  'MSMIXMGR',
  'MSPCIC',
  'MSPRINT',
  'MSTCP',
  'MSVIDEO',
  'NETAPI',
  'NETCPL',
  'NETDI',
  'NETOS',
  'NETWARE',
  'NW16',
  'OLE2',
  'OLE2CONV',
  'OLE2DISP',
  'OLE2NLS',
  'OLECLI',
  'OLESVR',
  'PIFMGR',
  'PKPD',
  'PMSPL',
  'POWER',
  'RASAPI16',
  'RNASETUP',
  'RSRC16',
  'SB16SND',
  'SBFM',
  'SETUP4',
  'SETUPX',
  'SHELL',
  'SOUND',
  'SPOOLER',
  'STORAGE',
  'SYSCLASS',
  'SYSDETMG',
  'SYSDM',
  'SYSEDIT',
  'SYSTEM',
  'SYSTHUNK',
  'TAPI',
  'TAPIADDR',
  'TOOLHELP',
  'TYPELIB',
  'UMDM16',
  'USER',
  'VER',
  'WHLP16T',
  'WIN32S16',
  'WIN87EM',
  'WINASPI',
  'WINNET16',
  'WINOLDAP',
  'WINSOCK',
  'WINSPL16',
  'WPSAPD',
  'WPSUNI',
  'WPSUNIRE',
  'WSASRV',
]

foreach file : sdb_files
  outfile = '@0@.sdb'.format(file)
  custom_target(outfile,
    input: 'dll/@0@.sdb.txt'.format(file),
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(rizin_sdb, 'format/dll')
  )
endforeach

format_files = [
  'elf32',
  'elf64',
  'elf_enums',
  'pe32',
  'mz',
  'zip'
]

install_data(format_files,
  install_dir: join_paths(rizin_sdb, 'format')
)
