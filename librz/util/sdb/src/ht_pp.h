#ifndef SDB_HT_PP_H
#define SDB_HT_PP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header provides an hashtable HtPP that has void* as key and void* as
 * value. The API functions starts with "ht_pp_" and the types starts with "HtPP".
 */
#define HT_TYPE 1
#include "ht_inc.h"

RZ_API HtName_(Ht) * Ht_(new0)(void);
RZ_API HtName_(Ht) * Ht_(new)(HT_(DupValue) valdup, HT_(KvFreeFunc) pair_free, HT_(CalcSizeV) valueSize);
RZ_API HtName_(Ht) * Ht_(new_size)(ut32 initial_size, HT_(DupValue) valdup, HT_(KvFreeFunc) pair_free, HT_(CalcSizeV) valueSize);
#undef HT_TYPE

#ifdef __cplusplus
}
#endif

#endif
