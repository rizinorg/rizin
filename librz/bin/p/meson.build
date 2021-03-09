bin_xtr_plugins = [
  'xtr_dyldcache',
  'xtr_fatmach0',
  'xtr_sep64',
]

bin_plugins = [
  'any',
  'art',
  'avr',
  'bf',
  'bflt',
  'bios',
  'bootimg',
  'cgc',
  'coff',
  'dex',
  'dmp64',
  'dol',
  'dyldcache',
  'elf',
  'elf64',
  'java',
  'le',
  'luac',
  'mach0',
  'mach064',
  'mbn',
  'mdmp',
  'menuet',
  'mz',
  'ne',
  'nes',
  'nin3ds',
  'ninds',
  'ningb',
  'ningba',
  'nro',
  'nso',
  'omf',
  'qnx',
  'p9',
  'pe',
  'pe64',
  'pebble',
  'prg',
  'psxexe',
  'pyc',
  'sfc',
  'smd',
  'sms',
  'spc700',
  'symbols',
  'te',
  'vsf',
  'wasm',
  'xbe',
  'xnu_kernelcache',
  'z64',
  'zimg',
]

bin_plugins += bin_xtr_plugins

bin_enabled_static_plugins = bin_plugins
bin_enabled_shared_plugins = []

bin_any_sources = files(
  'bin_any.c',
)

bin_any_deps = [
  rz_magic_dep,
]

bin_art_sources = files(
  'bin_art.c',
)

bin_avr_sources = files(
  'bin_avr.c',
)

bin_bf_sources = files(
  'bin_bf.c',
)

bin_bflt_sources = files(
  'bin_bflt.c',
  '../format/bflt/bflt.c',
)

bin_bflt_headers = include_directories(
  '../format/',
)

bin_bios_sources = files(
  'bin_bios.c',
)

bin_bootimg_sources = files(
  'bin_bootimg.c',
)

bin_cgc_sources = files(
  'bin_cgc.c',
  'bin_write_elf.c',
  '../format/elf/elf.c',
  '../format/elf/elf_write.c',
)

bin_cgc_headers = include_directories(
  '../format/',
)

bin_coff_sources = files(
  'bin_coff.c',
  '../format/coff/coff.c',
)

bin_coff_headers = include_directories(
  '../format/',
)

bin_dex_sources = files(
  'bin_dex.c',
  '../format/dex/dex.c',
)

bin_dex_headers = include_directories(
  '../format/',
)

bin_dmp64_sources = files(
  'bin_dmp64.c',
  '../format/dmp/dmp64.c',
)

bin_dmp64_headers = include_directories(
  '../format',
)

bin_dol_sources = files(
  'bin_dol.c',
)

bin_dyldcache_sources = files(
  'bin_dyldcache.c',
  '../format/mach0/mach0.c',
  '../format/mach0/mach064.c',
  '../format/objc/mach064_classes.c',
  '../format/objc/mach0_classes.c',
)

bin_dyldcache_headers = include_directories(
  '../format',
)

bin_dyldcache_deps = [
  rz_hash_dep,
]

bin_elf_sources = files(
  'bin_elf.c',
  'bin_write_elf.c',
  '../format/elf/elf.c',
  '../format/elf/elf_write.c',
)

bin_elf_headers = include_directories(
  '../format/',
)

bin_elf64_sources = files(
  'bin_elf64.c',
  'bin_write_elf64.c',
  '../format/elf/elf64.c',
  '../format/elf/elf64_write.c',
)

bin_elf64_headers = include_directories(
  '../format/',
)

bin_java_sources = files(
  'bin_java.c',
  '../format/java/class_bin.c',
  '../format/java/class_const_pool.c',
  '../format/java/class_method.c',
  '../format/java/class_field.c',
  '../format/java/class_attribute.c',
  '../format/java/class_interface.c',
)

bin_java_headers = include_directories(
  '../format/',
)

bin_le_sources = files(
  'bin_le.c',
  '../format/le/le.c',
)

bin_luac_sources = files(
  'bin_luac.c',
  '../format/luac/v54/parse_54.c',
  '../format/luac/luac_common.c',
  '../format/luac/luac_bin.c',
)

bin_mach0_sources = files(
  'bin_mach0.c',
  'bin_write_mach0.c',
  '../format/mach0/coresymbolication.c',
  '../format/mach0/dyldcache.c',
  '../format/mach0/fatmach0.c',
  '../format/mach0/mach0.c',
  '../format/objc/mach0_classes.c',
)

bin_mach0_headers = include_directories(
  '../format',
)

bin_mach0_deps = [
  rz_hash_dep,
  rz_io_dep,
]

bin_mach064_sources = files(
  'bin_mach064.c',
  'bin_write_mach064.c',
  '../format/mach0/mach064.c',
  '../format/objc/mach064_classes.c',
)

bin_mach064_headers = include_directories(
  '../format',
)

bin_mach064_deps = [
  rz_hash_dep,
  rz_io_dep,
]

bin_mbn_sources = files(
  'bin_mbn.c',
)

bin_mdmp_sources = files(
  'bin_mdmp.c',
  '../format/mdmp/mdmp.c',
  '../format/mdmp/mdmp_pe.c',
  '../format/mdmp/mdmp_pe64.c',
  '../format/pe/pe.c',
  '../format/pe/pe64.c',
)

bin_mdmp_headers = include_directories(
  '../format',
)

bin_mdmp_deps = [
  rz_hash_dep,
]

bin_menuet_sources = files(
  'bin_menuet.c',
)

bin_mz_sources = files(
  'bin_mz.c',
  '../format/mz/mz.c',
)

bin_mz_headers = include_directories(
  '../format',
)

bin_ne_sources = files(
  'bin_ne.c',
  '../format/ne/ne.c',
)

bin_nes_sources = files(
  'bin_nes.c',
)

bin_nes_headers = include_directories(
  '../format',
)

bin_nin3ds_sources = files(
  'bin_nin3ds.c',
)

bin_nin3ds_headers = include_directories(
  '../format',
)

bin_ninds_sources = files(
  'bin_ninds.c',
)

bin_ningb_sources = files(
  'bin_ningb.c',
)

bin_ningba_sources = files(
  'bin_ningba.c',
)

bin_nro_sources = files(
  'bin_nro.c',
  '../format/nxo/nxo.c',
)

bin_nro_headers = include_directories(
  '../format',
)

bin_nso_sources = files(
  'bin_nso.c',
  '../format/nxo/nxo.c',
)

bin_nso_headers = include_directories(
  '../format/nxo/',
)

bin_nso_deps = [
  lz4_dep,
  rz_io_dep,
]

bin_omf_sources = files(
  'bin_omf.c',
  '../format/omf/omf.c',
)

bin_omf_headers = include_directories(
  '../format/omf/',
)

bin_p9_sources = files(
  'bin_p9.c',
  '../format/p9/p9bin.c',
)

bin_pe_sources = files(
  'bin_pe.c',
  'bin_write_pe.c',
  '../format/pe/pe.c',
  '../format/pe/pe_write.c',
  '../format/pe/pemixed.c',
)

bin_pe_headers = include_directories(
  '../format/',
)

bin_pe_deps = [
  rz_hash_dep,
]

bin_pe64_sources = files(
  'bin_pe64.c',
  'bin_write_pe64.c',
  '../format/pe/pe64.c',
  '../format/pe/pe64_write.c',
)

bin_pe64_headers = include_directories(
  '../format/',
)

bin_pe64_deps = [
  rz_hash_dep,
  rz_io_dep,
]

bin_pebble_sources = files(
  'bin_pebble.c',
)

bin_prg_sources = files(
  'bin_prg.c',
)

bin_psxexe_sources = files(
  'bin_psxexe.c',
)

bin_psxexe_headers = include_directories(
  '../format/',
)

bin_pyc_sources = files(
  'bin_pyc.c',
  '../format/pyc/marshal.c',
  '../format/pyc/pyc.c',
  '../format/pyc/pyc_magic.c',
)

bin_qnx_sources = files(
  'bin_qnx.c',
)

bin_qnx_headers = include_directories(
  '../format/qnx/',
)

bin_sfc_sources = files(
  'bin_sfc.c',
)

bin_sfc_headers = include_directories(
  '../format/',
)

bin_smd_sources = files(
  'bin_smd.c',
)

bin_sms_sources = files(
  'bin_sms.c',
)

bin_spc700_sources = files(
  'bin_spc700.c',
)

bin_symbols_sources = files(
  'bin_symbols.c',
  '../format/mach0/coresymbolication.c',
)

bin_symbols_headers = include_directories(
  '../format/',
)

bin_te_sources = files(
  'bin_te.c',
  '../format/te/te.c',
)

bin_te_headers = include_directories(
  '../format/',
)

bin_vsf_sources = files(
  'bin_vsf.c',
)

bin_vsf_headers = include_directories(
  '../format/',
)

bin_wasm_sources = files(
  'bin_wasm.c',
  '../format/wasm/wasm.c',
)

bin_wasm_headers = include_directories(
  '../format/',
)

bin_xbe_sources = files(
  'bin_xbe.c',
)

bin_xnu_kernelcache_sources = files(
  'bin_xnu_kernelcache.c',
  '../format/mach0/mach064.c',
  '../format/xnu/rz_cf_dict.c',
)

bin_xnu_kernelcache_deps = [
  yxml_dep,
  rz_hash_dep,
  rz_syscall_dep,
]

bin_xtr_dyldcache_sources = files(
  'bin_xtr_dyldcache.c',
  '../format/mach0/dyldcache.c',
  '../format/mach0/mach0.c',
)

bin_xtr_dyldcache_headers = include_directories(
  '../format/',
)

bin_xtr_dyldcache_deps = [
  rz_hash_dep,
]

bin_xtr_fatmach0_sources = files(
  'bin_xtr_fatmach0.c',
  '../format/mach0/fatmach0.c',
  '../format/mach0/mach0.c',
)

bin_xtr_fatmach0_headers = include_directories(
  '../format',
)

bin_xtr_fatmach0_deps = [
  rz_hash_dep,
]

bin_xtr_pemixed_sources = files(
  'bin_xtr_pemixed.c',
)

bin_xtr_sep64_sources = files(
  'bin_xtr_sep64.c',
  '../format/mach0/mach064.c',
)

bin_xtr_sep64_deps = [
  rz_hash_dep,
]

bin_z64_sources = files(
  'bin_z64.c',
)

bin_zimg_sources = files(
  'bin_zimg.c',
  '../format/zimg/zimg.c',
)

bin_zimg_headers = include_directories(
  '../format/',
)