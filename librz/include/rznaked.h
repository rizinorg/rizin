#ifndef RZ_NAKED_H
#define RZ_NAKED_H

#ifdef __cplusplus
extern "C" {
#endif

void *rz_core_new(void);
char *rz_core_cmd_str(void *p, const char *cmd);
void rz_core_free(void *core);
void free(void *);

#ifdef __cplusplus
}
#endif

#endif
