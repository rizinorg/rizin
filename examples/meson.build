if get_option('enable_examples')
  executable('md5', 'api/hash/md5.c',
    include_directories: [platform_inc],
    dependencies: [rz_hash_dep],
    install: false
  )

  executable('linux_x64', 'api/syscall/linux_x64.c',
    include_directories: [platform_inc],
    dependencies: [rz_syscall_dep, rz_util_dep],
    install: false
  )
  executable('sign_create_example', 'api/sign/sign_create_example.c',
    include_directories: [platform_inc],
    dependencies: [rz_sign_dep, rz_util_dep],
    install: false
  )
  executable('sign_match_example', 'api/sign/sign_match_example.c',
    include_directories: [platform_inc],
    dependencies: [rz_sign_dep, rz_util_dep],
    install: false
  )
endif
