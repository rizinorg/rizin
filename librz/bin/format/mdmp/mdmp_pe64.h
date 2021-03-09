// SPDX-FileCopyrightText: 2016 Davis
// SPDX-FileCopyrightText: 2016 Alex Kornitzer <alex.kornitzer@countercept.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MDMP_PE64_H
#define MDMP_PE64_H

#define RZ_BIN_PE64 1

#ifdef MDMP_PE_H
#undef MDMP_PE_H
#include "mdmp_pe.h"
#else
#include "mdmp_pe.h"
#undef MDMP_PE_H
#endif

#endif /* MDMP_PE64_H */
