
#ifndef R2DB_SDB_ARCHIVE_H
#define R2DB_SDB_ARCHIVE_H

#include <sdb.h>

SDB_API bool sdb_archive_save(Sdb *db, const char *filename);
SDB_API Sdb *sdb_archive_load(const char *filename);

#endif
