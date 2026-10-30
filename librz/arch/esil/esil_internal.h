// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef ESIL_INTERNAL_H
#define ESIL_INTERNAL_H
#include <rz_esil/rz_esil.h>

RZ_IPI bool rz_analysis_esil_call_cmd_in_mdev(RzAnalysisEsil *esil, ut64 addr, const char *command, ut64 arg0, ut64 arg1);

#endif /* ESIL_INTERNAL_H */
