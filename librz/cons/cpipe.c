// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <limits.h>

#if __WINDOWS__
#include <io.h>

/**
 * \brief Duplicates a file descriptor and returns the new one.
 *
 * \param old_fd File descriptor to duplicate
 * \return On success is a positive integer, otherwise -1
 */
static int pipe_dup_fd(int old_fd) {
	int new_fd = _dup(old_fd);
	if (new_fd < 0) {
		return -1;
	}
	return new_fd;
}

/**
 * \brief Duplicates a file descriptor by assigning a given one.
 *
 * \param old_fd Old file descriptor to duplicate
 * \param new_fd New file descriptor
 * \return true on success, otherwise false.
 */
static bool pipe_dup2_fd(int old_fd, int new_fd) {
	if (!_dup2(old_fd, new_fd)) {
		return true;
	}
	return false;
}

#else /* !__WINDOWS__ */

/**
 * \brief Duplicates a file descriptor and returns the new one.
 *
 * \param old_fd File descriptor to duplicate
 * \return On success is a positive integer, otherwise -1
 */
static int pipe_dup_fd(int old_fd) {
	int new_fd = dup(old_fd);
	if (new_fd < 0) {
		return -1;
	}
	return new_fd;
}

/**
 * \brief Duplicates a file descriptor by assigning a given one.
 *
 * \param old_fd Old file descriptor to duplicate
 * \param new_fd New file descriptor
 * \return true on success, otherwise false.
 */
static bool pipe_dup2_fd(int old_fd, int new_fd) {
	if (dup2(old_fd, new_fd) == new_fd) {
		return true;
	}
	return false;
}

#endif /* __WINDOWS__ */

struct rz_cons_pipe_t {
	int fd; ///< File descriptor number to override.
	int copy_fd; ///< Copy of the file descriptor.
	int file_fd; ///< File descriptor of the opened file.
};

/**
 * \brief Redirects the data flow from a file descriptor to a file.
 *
 * \param file File name to open where to redirect the file descriptor.
 * \param fd The file descriptor to pipe
 * \param append When true, the data written to the file is appended.
 * \return On success a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzConsPipe *rz_cons_pipe_open(RZ_NONNULL const char *file, int fd, bool append) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(file), NULL);

	if (fd < 1) {
		RZ_LOG_ERROR("cpipe: invalid file descriptor '%d'\n", fd);
		return NULL;
	}

	RzConsPipe *cpipe = RZ_NEW0(RzConsPipe);
	if (!cpipe) {
		RZ_LOG_ERROR("cpipe: cannot allocate RzConsPipe\n");
		return NULL;
	}

	// open file to which we pipe all the data from fd
	const int file_flags = O_BINARY | O_RDWR | O_CREAT | (append ? O_APPEND : O_TRUNC);
	int file_fd = rz_sys_open(file, file_flags, 0644);
	if (file_fd < 0) {
		RZ_LOG_ERROR("cpipe: Cannot open file '%s'\n", file);
		free(cpipe);
		return NULL;
	}

	// save the original file descriptor by making a copy
	int copy_fd = pipe_dup_fd(fd);
	if (copy_fd < 0) {
		RZ_LOG_ERROR("cpipe: Cannot duplicate %d\n", fd);
		close(file_fd);
		free(cpipe);
		return NULL;
	}

	// override file descriptor with the opened file one.
	if (!pipe_dup2_fd(file_fd, fd)) {
		RZ_LOG_ERROR("cpipe: Cannot duplicate %d to %d\n", file_fd, fd);
		close(copy_fd);
		close(file_fd);
		free(cpipe);
		return NULL;
	}

	cpipe->fd = fd;
	cpipe->copy_fd = copy_fd;
	cpipe->file_fd = file_fd;
	return cpipe;
}

/**
 * \brief Closes a given RzConsPipe and restores the file descriptor.
 *
 * \param cpipe The console pipe to close.
 */
RZ_API void rz_cons_pipe_close(RZ_NULLABLE RzConsPipe *cpipe) {
	if (!cpipe) {
		return;
	}

	// restore file descriptor from copy.
	if (!pipe_dup2_fd(cpipe->copy_fd, cpipe->fd)) {
		RZ_LOG_ERROR("cpipe: Cannot duplicate %d to %d\n", cpipe->copy_fd, cpipe->fd);
	}

	// close the opened file descriptors
	close(cpipe->copy_fd);
	close(cpipe->file_fd);
	free(cpipe);
}
