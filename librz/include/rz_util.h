// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_UTIL_H
#define RZ_UTIL_H

#include <rz_types.h>
#include <rz_diff.h>
#include <rz_regex.h>
#include <rz_getopt.h>
#include <rz_list.h> // rizin linked list
#include <rz_skiplist.h> // skiplist
#include <rz_flist.h> // rizin fixed pointer array iterators
#include <rz_binheap.h>
#include <rz_th.h>
#if !__WINDOWS__
#include <dirent.h>
#include <signal.h>
#endif
#ifdef HAVE_LIB_GMP
#include <gmp.h>
#endif
#if HAVE_LIB_SSL
#include <openssl/bn.h>
#endif
#ifdef _MSC_VER
#include <windows.h>
int gettimeofday (struct timeval* p, void* tz);
#endif
#include "rz_util/rz_event.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_itv.h"
#include "rz_util/rz_signal.h"
#include "rz_util/rz_alloc.h"
#include "rz_util/rz_rbtree.h"
#include "rz_util/rz_intervaltree.h"
#include "rz_util/rz_big.h"
#include "rz_util/rz_base64.h"
#include "rz_util/rz_base91.h"
#include "rz_util/rz_buf.h"
#include "rz_util/rz_bitmap.h"
#include "rz_util/rz_time.h"
#include "rz_util/rz_debruijn.h"
#include "rz_util/rz_cache.h"
#include "rz_util/rz_ctypes.h"
#include "rz_util/rz_file.h"
#include "rz_util/rz_hex.h"
#include "rz_util/rz_log.h"
#include "rz_util/rz_mem.h"
#include "rz_util/rz_name.h"
#include "rz_util/rz_num.h"
#include "rz_util/rz_table.h"
#include "rz_util/rz_graph.h"
#include "rz_util/rz_panels.h"
#include "rz_util/rz_pool.h"
#include "rz_util/rz_punycode.h"
#include "rz_util/rz_queue.h"
#include "rz_util/rz_range.h"
#include "rz_util/rz_sandbox.h"
#include "rz_util/rz_signal.h"
#include "rz_util/rz_spaces.h"
#include "rz_util/rz_stack.h"
#include "rz_util/rz_str.h"
#include "rz_util/rz_ascii_table.h"
#include "rz_util/rz_strbuf.h"
#include "rz_util/rz_strpool.h"
#include "rz_util/rz_str_constpool.h"
#include "rz_util/rz_sys.h"
#include "rz_util/rz_tree.h"
#include "rz_util/rz_uleb128.h"
#include "rz_util/rz_utf8.h"
#include "rz_util/rz_utf16.h"
#include "rz_util/rz_utf32.h"
#include "rz_util/rz_idpool.h"
#include "rz_util/rz_asn1.h"
#include "rz_util/pj.h"
#include "rz_util/rz_x509.h"
#include "rz_util/rz_pkcs7.h"
#include "rz_util/rz_protobuf.h"
#include "rz_util/rz_big.h"
#include "rz_util/rz_subprocess.h"
// requires io, core, ... #include "rz_util/rz_print.h"

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_util);

#ifdef __cplusplus
}
#endif

#endif
