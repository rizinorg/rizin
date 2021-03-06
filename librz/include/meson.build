include_files =[
  'rz_agraph.h',
  'rz_analysis.h',
  'rz_asm.h',
  'rz_bind.h',
  'rz_getopt.h',
  'rz_bin_dwarf.h',
  'rz_bin.h',
  'rz_binheap.h',
  'rz_bp.h',
  'rz_cmd.h',
  'rz_config.h',
  'rz_cons.h',
  'rz_core.h',
  'rz_crypto.h',
  'rz_debug.h',
  'rz_diff.h',
  'rz_egg.h',
  'rz_main.h',
  'rz_endian.h',
  'rz_flag.h',
  'rz_flist.h',
  'rz_hash.h',
  'rz_heap_glibc.h',
  'rz_heap_jemalloc.h',
  'rz_io.h',
  'rz_lang.h',
  'rz_lib.h',
  'rz_list.h',
  'rz_magic.h',
  'rz_parse.h',
  'rz_pdb.h',
  'rz_project.h',
  'rz_qrcode.h',
  'rz_regex.h',
  'rz_reg.h',
  'rz_search.h',
  'rz_sign.h',
  'rz_skiplist.h',
  'rz_socket.h',
  'rz_syscall.h',
  'rz_th.h',
  'rz_types_overflow.h',
  'rz_types_base.h',
  'rz_types.h',
  'rz_util.h',
  'rz_vector.h',
  'rz_skyline.h',
]
install_headers(include_files, install_dir: rizin_incdir)

rz_util_files = [
  'rz_util/pj.h',
  'rz_util/rz_annotated_code.h',
  'rz_util/rz_ascii_table.h',
  'rz_util/rz_asn1.h',
  'rz_util/rz_assert.h',
  'rz_util/rz_protobuf.h',
  'rz_util/rz_base64.h',
  'rz_util/rz_base91.h',
  'rz_util/rz_big.h',
  'rz_util/rz_bitmap.h',
  'rz_util/rz_buf.h',
  'rz_util/rz_cache.h',
  'rz_util/rz_ctypes.h',
  'rz_util/rz_debruijn.h',
  'rz_util/rz_event.h',
  'rz_util/rz_file.h',
  'rz_util/rz_graph.h',
  'rz_util/rz_graph_drawable.h',
  'rz_util/rz_hex.h',
  'rz_util/rz_idpool.h',
  'rz_util/rz_itv.h',
  'rz_util/rz_json.h',
  'rz_util/rz_log.h',
  'rz_util/rz_mem.h',
  'rz_util/rz_name.h',
  'rz_util/rz_num.h',
  'rz_util/rz_panels.h',
  'rz_util/rz_table.h',
  'rz_util/rz_pkcs7.h',
  'rz_util/rz_pool.h',
  'rz_util/rz_print.h',
  'rz_util/rz_punycode.h',
  'rz_util/rz_queue.h',
  'rz_util/rz_range.h',
  'rz_util/rz_rbtree.h',
  'rz_util/rz_intervaltree.h',
  'rz_util/rz_serialize.h',
  'rz_util/rz_signal.h',
  'rz_util/rz_spaces.h',
  'rz_util/rz_stack.h',
  'rz_util/rz_strbuf.h',
  'rz_util/rz_str.h',
  'rz_util/rz_strpool.h',
  'rz_util/rz_str_constpool.h',
  'rz_util/rz_str_util.h',
  'rz_util/rz_subprocess.h',
  'rz_util/rz_sys.h',
  'rz_util/rz_alloc.h',
  'rz_util/rz_time.h',
  'rz_util/rz_tree.h',
  'rz_util/rz_uleb128.h',
  'rz_util/rz_utf16.h',
  'rz_util/rz_utf32.h',
  'rz_util/rz_utf8.h',
  'rz_util/rz_x509.h',
]
install_headers(rz_util_files, install_dir: join_paths(rizin_incdir, 'rz_util'))

rz_crypto_files = [
  'rz_crypto/rz_des.h'
]
install_headers(rz_crypto_files, install_dir: join_paths(rizin_incdir, 'rz_crypto'))

sflib_common_files = [
  'sflib/common/sftypes.h',
  'sflib/common/sfsocketcall.h'
]

sflib_arch = [
  'linux-x86-64',
  'linux-x86-32',
  'linux-arm-64',
  'linux-arm-32',
  'darwin-x86-64',
  'darwin-x86-32',
  'darwin-arm-64'
]

sflib_arch_files = [
  'sflib.h',
  'sfsyscall.h',
  'sfsysnr.h'
]

install_headers(sflib_common_files, install_dir: join_paths(rizin_incdir, 'sflib/common'))
foreach arch : sflib_arch
  foreach file : sflib_arch_files
    install_headers(join_paths('sflib', arch, file), install_dir: join_paths(rizin_incdir, 'sflib', arch))
  endforeach
endforeach