// SPDX-FileCopyrightText: 2001-2004 Fabrice Bellard
// SPDX-License-Identifier: LGPL-2.0-or-later

#ifndef __GNU_STAB__

/* Indicate the GNU stab.h is in use.  */

#define __GNU_STAB__

#define __define_stab(NAME, CODE, STRING) NAME = CODE,

enum __stab_debug_code {
#include "stab.def"
	LAST_UNUSED_STAB_CODE
};

#undef __define_stab

#endif /* __GNU_STAB_ */
