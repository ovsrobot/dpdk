/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Red Hat, Inc.
 */

#ifdef RTE_HAS_LIBARCHIVE
#include <archive.h>
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_firmware.h>
#include <rte_log.h>

static int
firmware_read(const char *name, void **buf, size_t *bufsz)
{
	const size_t blocksize = 4096;
	int ret = -1;
	int err;
#ifdef RTE_HAS_LIBARCHIVE
	struct archive_entry *entry;
	struct archive *a;
#else
	int fd;
#endif

	*buf = NULL;
	*bufsz = 0;

#ifdef RTE_HAS_LIBARCHIVE
	a = archive_read_new();
	if (a == NULL || archive_read_support_format_raw(a) != ARCHIVE_OK ||
			archive_read_support_filter_xz(a) != ARCHIVE_OK ||
			archive_read_open_filename(a, name, blocksize) != ARCHIVE_OK ||
			archive_read_next_header(a, &entry) != ARCHIVE_OK)
		goto out;
#else
	fd = open(name, O_RDONLY);
	if (fd < 0)
		goto out;
#endif

	do {
		void *tmp;

		tmp = realloc(*buf, *bufsz + blocksize);
		if (tmp == NULL) {
			free(*buf);
			*buf = NULL;
			*bufsz = 0;
			break;
		}
		*buf = tmp;

#ifdef RTE_HAS_LIBARCHIVE
		err = archive_read_data(a, RTE_PTR_ADD(*buf, *bufsz), blocksize);
#else
		err = read(fd, RTE_PTR_ADD(*buf, *bufsz), blocksize);
#endif
		if (err < 0) {
			free(*buf);
			*buf = NULL;
			*bufsz = 0;
			break;
		}
		*bufsz += err;

	} while (err != 0);

	if (*buf != NULL)
		ret = 0;
out:
#ifdef RTE_HAS_LIBARCHIVE
	if (a != NULL)
		archive_read_free(a);
#else
	if (fd >= 0)
		close(fd);
#endif
	return ret;
}

int
rte_firmware_read(const char *name, void **buf, size_t *bufsz)
{
	char path[PATH_MAX];
	int ret;

	ret = firmware_read(name, buf, bufsz);
	if (ret < 0) {
		snprintf(path, sizeof(path), "%s.xz", name);
		path[PATH_MAX - 1] = '\0';
#ifndef RTE_HAS_LIBARCHIVE
		if (access(path, F_OK) == 0) {
			RTE_LOG(WARNING, EAL, "libarchive not available, %s cannot be decompressed\n",
				path);
		}
#else
		ret = firmware_read(path, buf, bufsz);
#endif
	}
	return ret;
}
