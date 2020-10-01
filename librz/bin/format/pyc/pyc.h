/* radare - LGPL3 - Copyright 2016-2020 - c0riolis, x0urc3 */

#ifndef PYC_H
#define PYC_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "pyc_magic.h"
#include "marshal.h"

bool pyc_get_sections_symbols(RzList *sections, RzList *symbols, RzList *mem, RBuffer *buf, ut32 magic);
bool pyc_is_code(ut8 b, ut32 magic);

#endif
