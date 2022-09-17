project('blake3', 'c', version: '1.3.1', license : ['CC0-1.0'], meson_version: '>=0.55.0')

cc = meson.get_compiler('c')

# handle blake3 dependency
blake3_files = [
  # 'c' / 'blake3_sse41.c',
  # 'c' / 'blake3_sse2.c',
  'c' / 'blake3_portable.c',
  # 'c' / 'blake3_neon.c',
  'c' / 'blake3_impl.h',
  'c' / 'blake3_dispatch.c',
  # 'c' / 'blake3_avx512.c',
  # 'c' / 'blake3_avx2.c',
  'c' / 'blake3.h',
  'c' / 'blake3.c',
]

blake3_dflags = [
  '-DBLAKE3_NO_SSE2',
  '-DBLAKE3_NO_SSE41',
  '-DBLAKE3_NO_AVX2',
  '-DBLAKE3_NO_AVX512',
  '-DBLAKE3_USE_NEON=0',
]
foreach dflag : blake3_dflags
  add_project_arguments(dflag, language: 'c')
endforeach


blake3_inc = [
  include_directories(['c'])
]

blake3 = static_library('blake3', blake3_files,
  dependencies: [],
  include_directories: blake3_inc,
  implicit_include_directories: false
)

blake3_dep = declare_dependency(
  link_with: blake3,
  include_directories: blake3_inc
)
