/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_idxd_inter_dom.h>

#include "idxd_internal.h"

#define IDXD_TYPE       ('d')
#define IDXD_IOC_BASE   100
#define IDXD_WIN_BASE   200

enum idxd_win_type {
	IDXD_WIN_TYPE_SA_SS = 0,
	IDXD_WIN_TYPE_SA_MS,
};

#define IDXD_WIN_FLAGS_MASK (RTE_IDXD_WIN_FLAGS_PROT_READ | RTE_IDXD_WIN_FLAGS_PROT_WRITE |\
		RTE_IDXD_WIN_FLAGS_WIN_CHECK | RTE_IDXD_WIN_FLAGS_OFFSET_MODE|\
		RTE_IDXD_WIN_FLAGS_TYPE_SAMS)

struct idxd_win_param {
	uint64_t base;          /* Window base */
	uint64_t size;          /* Window size */
	uint32_t type;          /* Window type, see enum idxd_win_type */
	uint16_t flags;         /* See IDXD windows flags */
	uint16_t handle;        /* Window handle returned by driver */
} __attribute__((packed));

struct idxd_win_attach {
	uint32_t fd;            /* Window file descriptor returned by IDXD_WIN_CREATE */
	uint16_t handle;        /* Window handle returned by driver */
} __attribute__((packed));

struct idxd_win_fault {
	uint64_t offset;        /* Window offset of faulting address */
	uint64_t len;           /* Faulting range */
	uint32_t write_fault;   /* Fault generated on write */
} __attribute__((packed));

#define IDXD_WIN_CREATE         _IOWR(IDXD_TYPE, IDXD_IOC_BASE + 1, struct idxd_win_param)
#define IDXD_WIN_ATTACH         _IOR(IDXD_TYPE, IDXD_IOC_BASE + 2, struct idxd_win_attach)
#define IDXD_WIN_FAULT          _IOR(IDXD_TYPE, IDXD_WIN_BASE + 1, struct idxd_win_fault)
#define DSA_DEV_PATH "/dev/dsa"

static inline const char *
dsa_get_dev_path(void)
{
	const char *path = getenv("DSA_DEV_PATH");
	return path ? path : DSA_DEV_PATH;
}

static int
dsa_find_work_queue(int controller_id)
{
	char dev_templ[PATH_MAX], path_templ[PATH_MAX];
	const char *path = dsa_get_dev_path();
	struct dirent *wq;
	DIR *dev_dir;
	int fd = -1;

	/* construct work queue path template */
	snprintf(dev_templ, sizeof(dev_templ), "wq%d.", controller_id);

	/* open the DSA device directory */
	dev_dir = opendir(path);
	if (dev_dir == NULL)
		return -1;

	/* find any available work queue */
	while ((wq = readdir(dev_dir)) != NULL) {
		/* skip things that aren't work queues */
		if (strncmp(wq->d_name, dev_templ, strlen(dev_templ)) != 0)
			continue;

		/* try this work queue */
		snprintf(path_templ, sizeof(path_templ), "%s/%s", path, wq->d_name);

		fd = open(path_templ, O_RDWR);
		if (fd < 0)
			continue;

		break;
	}

	return fd;
}

int
rte_idxd_window_create(int controller_id, void *win_addr,
	unsigned int win_len, int flags)
{
	struct idxd_win_param param = {0};
	int idpte_fd, fd;

	fd = dsa_find_work_queue(controller_id);

	/* did we find anything? */
	if (fd < 0) {
		IDXD_PMD_ERR("%s(): creatomg idpt window failed", __func__);
		return -1;
	}

	/* create a wormhole into a parallel reality... */
	param.base = (uint64_t)win_addr;
	param.size = win_len;
	param.flags = flags & IDXD_WIN_FLAGS_MASK;
	param.type = (flags & RTE_IDXD_WIN_FLAGS_TYPE_SAMS) ?
		IDXD_WIN_TYPE_SA_MS : IDXD_WIN_TYPE_SA_SS;

	idpte_fd = ioctl(fd, IDXD_WIN_CREATE, &param);

	close(fd);

	if (idpte_fd < 0)
		rte_errno = idpte_fd;

	return idpte_fd;
}

int
rte_idxd_window_attach(int controller_id, int idpte_fd,
	uint16_t *handle)
{

	struct idxd_win_attach win_attach = {0};
	int ret, fd;

	if (handle == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	fd = dsa_find_work_queue(controller_id);

	/* did we find anything? */
	if (fd < 0) {
		IDXD_PMD_ERR("%s(): creatomg idpt window failed", __func__);
		rte_errno = ENOENT;
		return -1;
	}

	/* get access to someone else's wormhole */
	win_attach.fd = idpte_fd;

	ret = ioctl(fd, IDXD_WIN_ATTACH, &win_attach);
	if (ret != 0) {
		IDXD_PMD_ERR("%s(): attaching idpt window failed: %s",
				__func__, strerror(ret));
		rte_errno = ret;
		return -1;
	}

	*handle = win_attach.handle;

	return 0;
}
