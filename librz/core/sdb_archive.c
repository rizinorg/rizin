
#include <sdb_archive.h>

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>

static void sdb_archive_save_ns(struct archive *archive, struct archive_entry *entry, const char *path, struct archive *disk_archive, const char *tmpfile, Sdb *db) {
	archive_entry_clear (entry);

	sdb_file (db, tmpfile);
	if (!sdb_sync (db)) {
		eprintf ("Failed to sync tmp sdb to %s\n", tmpfile);
		return;
	}
	sdb_close (db);

	size_t pathlen = path ? strlen (path) : 0;
	if (pathlen) {
		char *dbpath = malloc (pathlen + 5);
		if (!dbpath) {
			return;
		}
		memcpy (dbpath, path, pathlen);
		memcpy (dbpath + pathlen, "/sdb", 5);
		archive_entry_set_pathname (entry, dbpath);
		free (dbpath);
	} else {
		archive_entry_set_pathname (entry, "sdb");
	}

	int fd = open (tmpfile, O_RDONLY);
	if (fd < 0) {
		eprintf ("Failed to open tmp sdb at %s\n", tmpfile);
		return;
	}

	archive_entry_copy_sourcepath (entry, tmpfile);
	if (archive_read_disk_entry_from_file (disk_archive, entry, fd, NULL) != ARCHIVE_OK) {
		eprintf ("Failed to stat tmpfile %s\n", tmpfile);
		close (fd);
		return;
	}
	archive_entry_set_filetype (entry, AE_IFREG);
	archive_entry_set_perm (entry, 0644);
	archive_write_header (archive, entry);

	char buf[8192];
	int len;
	while (true) {
		len = read (fd, buf, sizeof(buf));
		if (len <= 0) {
			break;
		}
		size_t written = archive_write_data (archive, buf, len);
		if (written != len) {
			eprintf ("Failed to write to archive\n");
			break;
		}
	}
	close (fd);

	SdbListIter *it;
	SdbNs *ns;
	ls_foreach (db->ns, it, ns) {
		size_t subnamelen = strlen (ns->name);
		char *subpath = malloc ((pathlen ? pathlen + 1 : 0) + subnamelen + 1);
		if (!subpath) {
			continue;
		}
		if (pathlen) {
			memcpy (subpath, path, pathlen);
			subpath[pathlen] = '/';
		}
		memcpy (subpath + (pathlen ? pathlen + 1 : 0), ns->name, subnamelen + 1);
		sdb_archive_save_ns (archive, entry, subpath, disk_archive, tmpfile, ns->sdb);
		free (subpath);
	}
}

static char *tmpfilename(const char *filename) {
	size_t filename_len = strlen (filename);
	char *tmpfile = malloc (filename_len + 5);
	if (!tmpfile) {
		return NULL;
	}
	memcpy (tmpfile, filename, filename_len);
	memcpy (tmpfile + filename_len, ".tmp", 5);
	return tmpfile;
}

SDB_API bool sdb_archive_save(Sdb *db, const char *filename) {
	char *tmpfile = tmpfilename (filename);
	if (!tmpfile) {
		return false;
	}

	bool ret = true;
	struct archive *archive = archive_write_new ();
	archive_write_add_filter_gzip (archive);
	archive_write_set_format_pax_restricted (archive);
	if (archive_write_open_filename (archive, filename) != ARCHIVE_OK) {
		eprintf ("Failed to open archive %s\n", filename);
		ret = false;
		goto beach;
	}

	struct archive *disk_archive = archive_read_disk_new ();
	struct archive_entry *entry = archive_entry_new ();
	sdb_archive_save_ns (archive, entry, NULL, disk_archive, tmpfile, db);
	archive_entry_free (entry);
	archive_free (disk_archive);

	remove (tmpfile);

	archive_write_close (archive);

beach:
	archive_write_free (archive);
	free (tmpfile);
	return ret;
}

SDB_API Sdb *sdb_archive_load(const char *filename) {
	Sdb *db = NULL;

	char *tmpfile = tmpfilename (filename);
	if (!tmpfile) {
		return NULL;
	}

	struct archive *archive = archive_read_new ();
	archive_read_support_filter_all(archive);
	archive_read_support_format_all(archive);
	if (archive_read_open_filename (archive, filename, 10240) != ARCHIVE_OK) {
		eprintf ("Failed to open archive %s\n", filename);
		goto beach;
	}

	db = sdb_new0 ();

	struct archive_entry *entry;
	while (archive_read_next_header (archive, &entry) == ARCHIVE_OK) {
		if (archive_entry_filetype (entry) != AE_IFREG) {
			continue;
		}
		const char *path = archive_entry_pathname (entry);
		size_t pathlen = strlen (path);
		if (pathlen < 3 || memcmp (path + pathlen - 3, "sdb", 3) != 0) {
			eprintf ("Unknown file in archive: %s\n", path);
			continue;
		}
		pathlen -= 3;
		if (pathlen > 0 && path[pathlen - 1] == '/') {
			pathlen--;
		}
		int fd = open (tmpfile, O_BINARY | O_RDWR | O_CREAT | O_TRUNC, SDB_MODE);
		if (fd <= 0) {
			eprintf ("Failed to open tmpfile %s\n", tmpfile);
			break;
		}
		archive_read_data_into_fd (archive, fd);
		close (fd);

		Sdb *tmp_db = sdb_new0 ();
		if (sdb_open (tmp_db, tmpfile) == -1) {
			eprintf ("Failed to open tmpfile %s for reading\n", tmpfile);
			break;
		}

		char *nspath = malloc (pathlen + 1);
		if (!nspath) {
			sdb_free (tmp_db);
			continue;
		}
		memcpy (nspath, path, pathlen);
		nspath[pathlen] = '\0';
		Sdb *ns = sdb_ns_path (db, nspath, true);
		sdb_copy (tmp_db, ns);
		free (nspath);
		sdb_free (tmp_db);
	}

	remove (tmpfile);

beach:
	archive_read_free (archive);
	free (tmpfile);
	return db;
}