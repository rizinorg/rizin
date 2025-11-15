# SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

interpreter_plugins_list = [
  'prototype',
]

interpreter_plugins = {
  'base_name': 'rz_interpreter',
  'base_struct': 'RzInterpreterPlugin',
  'list': interpreter_plugins_list,
}

rz_interpreter_sources = [
  'interpreter.c',
  'p/interpreter_prototype.c',
]

rz_interpreter_inc = [platform_inc]

rz_interpreter = library('rz_interpreter', rz_interpreter_sources,
  include_directories: rz_interpreter_inc,
  dependencies: [
    rz_cons_dep,
    rz_hash_dep,
    rz_il_dep,
    rz_type_dep,
    rz_util_dep,
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_interpreter_dep = declare_dependency(link_with: rz_interpreter,
                               include_directories: rz_interpreter_inc)
meson.override_dependency('rz_interpreter', rz_interpreter_dep)

modules += { 'rz_interpreter': {
    'target': rz_interpreter,
    'dependencies': [
      'rz_cons',
      'rz_hash',
      'rz_il',
      'rz_type',
      'rz_util'
    ],
    'plugins': [interpreter_plugins]
}}
