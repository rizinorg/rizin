# SPDX-FileCopyrightText: 2025
# SPDX-License-Identifier: LGPL-3.0-only

if get_option('enable_benchmarks')
  # Build utility library for benchmarks
  bench_utils = static_library('bench_utils',
    'bench_utils.c',
    include_directories: [platform_inc],
    dependencies: [
      rz_util_dep,
      rz_il_dep
    ],
  )

  bench_utils_dep = declare_dependency(
    link_with: bench_utils,
    include_directories: [include_directories('.')],
  )

  # List of benchmarks to build
  benchmarks = [
    'bitvector',
    'il',
  ]

  # Create benchmark executables
  foreach bench : benchmarks
    exe = executable('bench_@0@'.format(bench),
      'bench_@0@.c'.format(bench),
      include_directories: [platform_inc, '.'],
      dependencies: [
        bench_utils_dep,
        rz_util_dep,
        rz_core_dep,
      ],
      install: false,
      implicit_include_directories: false,
    )
    
    # Register with meson test system (run with: meson test --benchmark)
    benchmark(bench, exe, suite: 'bench', timeout: 120)
  endforeach

  message('Benchmarks enabled - build with "meson compile" and run with "meson test --benchmark"')
endif
