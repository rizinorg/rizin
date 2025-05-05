project('subpoj_tester', 'c')

rz_deps = [
  dependency('rz_core'),
  dependency('rz_reg'),
  dependency('rz_flag'),
  dependency('rz_hash'),
  dependency('rz_bin'),
  dependency('rz_io'),
  dependency('rz_search'),
  dependency('rz_sign'),
  dependency('rz_cons'),
  dependency('rz_lang'),
  dependency('rz_socket'),
  dependency('rz_type'),
  dependency('rz_debug'),
  dependency('rz_il'),
  dependency('rz_demangler'),
  dependency('rz_util'),
  dependency('rz_main'),
  dependency('rz_crypto'),
  dependency('rz_config'),
  dependency('rz_egg'),
  dependency('rz_syscall'),
  dependency('rz_magic'),
  ]

tester_source = custom_target('main.c',
  command: ['echo', '''
#include <rz_core.h>

int main(void) {
    RzCore *core = rz_core_new();
    rz_cons_printf("hello world\n");
    rz_core_free(core);
    return 0;
}
  '''],
  output: 'main.c',
  capture: true,
  )


subproj_tester = executable('subproj_tester',
           tester_source,
           dependencies: rz_deps,
           pie: true,
           )

test('basic', subproj_tester)


