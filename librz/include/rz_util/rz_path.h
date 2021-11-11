#ifndef RZ_UTIL_PATH_H_
#define RZ_UTIL_PATH_H_

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RZ_OWN char *rz_path_prefix(RZ_NULLABLE const char *path);
RZ_API RZ_OWN char *rz_path_incdir(void);
RZ_API RZ_OWN char *rz_path_bindir(void);
RZ_API RZ_OWN char *rz_path_libdir(void);

RZ_API RZ_OWN char *rz_path_system_rc(void);
RZ_API RZ_OWN char *rz_path_system_plugins(void);
RZ_API RZ_OWN char *rz_path_system_bindings(void);
RZ_API RZ_OWN char *rz_path_system_data(void);
RZ_API RZ_OWN char *rz_path_system_sdb(void);
RZ_API RZ_OWN char *rz_path_system_sdb_arch_platforms(void);
RZ_API RZ_OWN char *rz_path_system_sdb_arch_cpus(void);
RZ_API RZ_OWN char *rz_path_system_sdb_types(void);
RZ_API RZ_OWN char *rz_path_system_sdb_opcodes(void);
RZ_API RZ_OWN char *rz_path_system_sdb_magic(void);
RZ_API RZ_OWN char *rz_path_system_sdb_format(void);
RZ_API RZ_OWN char *rz_path_system_sdb_reg(void);
RZ_API RZ_OWN char *rz_path_system_zigns(void);
RZ_API RZ_OWN char *rz_path_system_themes(void);
RZ_API RZ_OWN char *rz_path_system_fortunes(void);
RZ_API RZ_OWN char *rz_path_system_flags(void);
RZ_API RZ_OWN char *rz_path_system_hud(void);
RZ_API RZ_OWN char *rz_path_system_wwwroot(void);

RZ_API RZ_OWN char *rz_path_home(RZ_NULLABLE const char *path);
RZ_API RZ_OWN char *rz_path_home_config(void);
RZ_API RZ_OWN char *rz_path_home_cache(void);
RZ_API RZ_OWN char *rz_path_home_data(void);
RZ_API RZ_OWN char *rz_path_home_history(void);
RZ_API RZ_OWN char *rz_path_home_rc(void);
RZ_API RZ_OWN char *rz_path_home_config_rc(void);
RZ_API RZ_OWN char *rz_path_home_config_rcdir(void);

RZ_API RZ_OWN char *rz_path_home_plugins(void);
RZ_API RZ_OWN char *rz_path_home_pdb(void);
RZ_API RZ_OWN char *rz_path_home_projects(void);
RZ_API RZ_OWN char *rz_path_home_sdb(void);
RZ_API RZ_OWN char *rz_path_home_sdb_types(void);
RZ_API RZ_OWN char *rz_path_home_sdb_opcodes(void);
RZ_API RZ_OWN char *rz_path_home_sdb_magic(void);
RZ_API RZ_OWN char *rz_path_home_sdb_format(void);
RZ_API RZ_OWN char *rz_path_home_zigns(void);
RZ_API RZ_OWN char *rz_path_home_themes(void);
RZ_API RZ_OWN char *rz_path_home_fortunes(void);
RZ_API RZ_OWN char *rz_path_home_flags(void);
RZ_API RZ_OWN char *rz_path_home_hud(void);
RZ_API RZ_OWN char *rz_path_home_binrcdir(void);
RZ_API RZ_OWN char *rz_path_home_wwwroot(void);

#ifdef __cplusplus
}
#endif

#endif
