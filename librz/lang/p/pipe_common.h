#ifndef PIPE_COMMON_H_
#define PIPE_COMMON_H_

#include <rz_types.h>
#include <rz_lang.h>

RZ_IPI int lang_pipe_run(RzLang *lang, const char *code, int len);

#endif