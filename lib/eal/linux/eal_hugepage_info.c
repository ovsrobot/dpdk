/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <string.h>
#include <sys/file.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <mntent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#include <linux/mman.h> /* for hugetlb-related flags */
#include <linux/magic.h> /* for HUGETLBFS_MAGIC */

#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <rte_common.h>
#include "rte_string_fns.h"

#include "eal_private.h"
#include "eal_internal_cfg.h"
#include "eal_hugepages.h"
#include "eal_filesystem.h"

static const char sys_dir_path[] = "/sys/kernel/mm/hugepages";
static const char sys_pages_numa_dir_path[] = "/sys/devices/system/node";

/*
 * Uses mmap to create a shared memory area for storage of data
 * Used in this file to store the hugepage file map on disk
 */
static void *
map_shared_memory(const char *filename, const size_t mem_size, int flags)
{
	void *retval;
	int fd = open(filename, flags, 0600);
	if (fd < 0)
		return NULL;
	if (ftruncate(fd, mem_size) < 0) {
		close(fd);
		return NULL;
	}
	retval = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	close(fd);
	return retval == MAP_FAILED ? NULL : retval;
}

static void *
open_shared_memory(const char *filename, const size_t mem_size)
{
	return map_shared_memory(filename, mem_size, O_RDWR);
}

static void *
create_shared_memory(const char *filename, const size_t mem_size)
{
	return map_shared_memory(filename, mem_size, O_RDWR | O_CREAT);
}

static int get_hp_sysfs_value(const char *subdir, const char *file, unsigned long *val)
{
	char *path = NULL;
	int ret;

	if (asprintf(&path, "%s/%s/%s", sys_dir_path, subdir, file) < 0)
		return -1;
	ret = eal_parse_sysfs_value(path, val);
	free(path);
	return ret;
}

/* this function is only called from eal_hugepage_info_init which itself
 * is only called from a primary process */
static uint32_t
get_num_hugepages(const char *subdir, size_t sz, unsigned int reusable_pages)
{
	unsigned long resv_pages, num_pages, over_pages, surplus_pages;
	const char *nr_hp_file = "free_hugepages";
	const char *nr_rsvd_file = "resv_hugepages";
	const char *nr_over_file = "nr_overcommit_hugepages";
	const char *nr_splus_file = "surplus_hugepages";

	/* first, check how many reserved pages kernel reports */
	if (get_hp_sysfs_value(subdir, nr_rsvd_file, &resv_pages) < 0)
		return 0;

	if (get_hp_sysfs_value(subdir, nr_hp_file, &num_pages) < 0)
		return 0;

	if (get_hp_sysfs_value(subdir, nr_over_file, &over_pages) < 0)
		over_pages = 0;

	if (get_hp_sysfs_value(subdir, nr_splus_file, &surplus_pages) < 0)
		surplus_pages = 0;

	/* adjust num_pages */
	if (num_pages >= resv_pages)
		num_pages -= resv_pages;
	else if (resv_pages)
		num_pages = 0;

	if (over_pages >= surplus_pages)
		over_pages -= surplus_pages;
	else
		over_pages = 0;

	if (num_pages == 0 && over_pages == 0 && reusable_pages)
		EAL_LOG(WARNING, "No available %zu kB hugepages reported",
				sz >> 10);

	num_pages += over_pages;
	if (num_pages < over_pages) /* overflow */
		num_pages = UINT32_MAX;

	num_pages += reusable_pages;
	if (num_pages < reusable_pages) /* overflow */
		num_pages = UINT32_MAX;

	/* we want to return a uint32_t and more than this looks suspicious
	 * anyway ... */
	if (num_pages > UINT32_MAX)
		num_pages = UINT32_MAX;

	return num_pages;
}

static uint32_t
get_num_hugepages_on_node(const char *subdir, unsigned int socket, size_t sz)
{
	char *path = NULL, *socketpath = NULL;
	DIR *socketdir;
	unsigned long num_pages = 0;
	const char *nr_hp_file = "free_hugepages";

	if (asprintf(&socketpath, "%s/node%u/hugepages", sys_pages_numa_dir_path, socket) < 0) {
		EAL_LOG(ERR, "Can not format node huge page path");
		socketpath = NULL;
		goto nopages;
	}

	socketdir = opendir(socketpath);
	if (socketdir) {
		/* Keep calm and carry on */
		closedir(socketdir);
	} else {
		/* Can't find socket dir, so ignore it */
		goto nopages;
	}

	if (asprintf(&path, "%s/%s/%s", socketpath, subdir, nr_hp_file) < 0) {
		EAL_LOG(ERR, "Can not format free hugepages path");
		path = NULL;
		goto nopages;
	}

	if (eal_parse_sysfs_value(path, &num_pages) < 0)
		goto nopages;

	if (num_pages == 0)
		EAL_LOG(WARNING, "No free %zu kB hugepages reported on node %u",
				sz >> 10, socket);

	/*
	 * we want to return a uint32_t and more than this looks suspicious
	 * anyway ...
	 */
	if (num_pages > UINT32_MAX)
		num_pages = UINT32_MAX;

nopages:
	free(path);
	free(socketpath);

	return num_pages;
}

static uint64_t
get_default_hp_size(void)
{
	const char proc_meminfo[] = "/proc/meminfo";
	const char str_hugepagesz[] = "Hugepagesize:";
	unsigned hugepagesz_len = sizeof(str_hugepagesz) - 1;
	char buffer[256];
	unsigned long long size = 0;

	FILE *fd = fopen(proc_meminfo, "r");
	if (fd == NULL)
		rte_panic("Cannot open %s\n", proc_meminfo);
	while(fgets(buffer, sizeof(buffer), fd)){
		if (strncmp(buffer, str_hugepagesz, hugepagesz_len) == 0){
			size = rte_str_to_size(&buffer[hugepagesz_len]);
			break;
		}
	}
	fclose(fd);
	if (size == 0)
		rte_panic("Cannot get default hugepage size from %s\n", proc_meminfo);
	return size;
}

static int
get_hugepage_dir(uint64_t hugepage_sz, char *hugedir, int len)
{
	static uint64_t default_size = 0;
	const char pagesize_opt[] = "pagesize=";
	const size_t pagesize_opt_len = sizeof(pagesize_opt) - 1;
	const struct eal_user_cfg *user_cfg = eal_get_user_configuration();
	struct mntent *mnt;
	FILE *fp;

	/* Fast path: hugepage_dir explicitly specified */
	if (user_cfg->hugepage_dir != NULL) {
		struct statfs sfs;

		/* Query info about mounted filesystem */
		if (statfs(user_cfg->hugepage_dir, &sfs) != 0 ||
				(uint32_t)sfs.f_type != HUGETLBFS_MAGIC ||
				(uint64_t)sfs.f_bsize != hugepage_sz)
			return -1;

		strlcpy(hugedir, user_cfg->hugepage_dir, len);
		return 0;
	}

	/* Discover mount point from /proc/mounts */
	fp = setmntent("/proc/mounts", "r");
	if (fp == NULL)
		rte_panic("Cannot open /proc/mounts\n");

	if (default_size == 0)
		default_size = get_default_hp_size();

	while ((mnt = getmntent(fp)) != NULL) {
		const char *pagesz_str;

		if (strcmp(mnt->mnt_type, "hugetlbfs") != 0)
			continue;

		pagesz_str = hasmntopt(mnt, "pagesize");

		if (pagesz_str == NULL) {
			if (hugepage_sz != default_size)
				continue;
		} else {
			uint64_t pagesz = rte_str_to_size(&pagesz_str[pagesize_opt_len]);
			if (pagesz != hugepage_sz)
				continue;
		}

		/* Found a match */
		strlcpy(hugedir, mnt->mnt_dir, len);
		endmntent(fp);
		return 0;
	}

	endmntent(fp);
	return -1;
}

struct walk_hugedir_data {
	int dir_fd;
	int file_fd;
	const char *file_name;
	void *user_data;
};

typedef void (walk_hugedir_t)(const struct walk_hugedir_data *whd);

/*
 * Search the hugepage directory for whatever hugepage files there are.
 * Check if the file is in use by another DPDK process.
 * If not, execute a callback on it.
 */
static int
walk_hugedir(const char *hugedir, walk_hugedir_t *cb, void *user_data)
{
	DIR *dir;
	struct dirent *dirent;
	int dir_fd, fd, lck_result;
	const char filter[] = "*map_*"; /* matches hugepage files */

	dir = opendir(hugedir);
	if (!dir) {
		EAL_LOG(ERR, "Unable to open hugepage directory %s",
				hugedir);
		goto error;
	}
	dir_fd = dirfd(dir);

	dirent = readdir(dir);
	if (!dirent) {
		EAL_LOG(ERR, "Unable to read hugepage directory %s",
				hugedir);
		goto error;
	}

	while (dirent != NULL) {
		/* skip files that don't match the hugepage pattern */
		if (fnmatch(filter, dirent->d_name, 0) > 0) {
			dirent = readdir(dir);
			continue;
		}

		/* try and lock the file */
		fd = openat(dir_fd, dirent->d_name, O_RDONLY);

		/* skip to next file */
		if (fd == -1) {
			dirent = readdir(dir);
			continue;
		}

		/* non-blocking lock */
		lck_result = flock(fd, LOCK_EX | LOCK_NB);

		/* if lock succeeds, execute callback */
		if (lck_result != -1)
			cb(&(struct walk_hugedir_data){
				.dir_fd = dir_fd,
				.file_fd = fd,
				.file_name = dirent->d_name,
				.user_data = user_data,
			});

		close (fd);
		dirent = readdir(dir);
	}

	closedir(dir);
	return 0;

error:
	if (dir)
		closedir(dir);

	EAL_LOG(ERR, "Error while walking hugepage dir: %s",
		strerror(errno));

	return -1;
}

static void
clear_hugedir_cb(const struct walk_hugedir_data *whd)
{
	unlinkat(whd->dir_fd, whd->file_name, 0);
}

/* Remove hugepage files not used by other DPDK processes from a directory. */
static int
clear_hugedir(const char *hugedir)
{
	return walk_hugedir(hugedir, clear_hugedir_cb, NULL);
}

static void
inspect_hugedir_cb(const struct walk_hugedir_data *whd)
{
	uint64_t *total_size = whd->user_data;
	struct stat st;

	if (fstat(whd->file_fd, &st) < 0)
		EAL_LOG(DEBUG, "%s(): stat(\"%s\") failed: %s",
				__func__, whd->file_name, strerror(errno));
	else
		(*total_size) += st.st_size;
}

/*
 * Count the total size in bytes of all files in the directory
 * not mapped by other DPDK process.
 */
static int
inspect_hugedir(const char *hugedir, uint64_t *total_size)
{
	return walk_hugedir(hugedir, inspect_hugedir_cb, total_size);
}

static int
compare_hp_sizes(const void *a, const void *b)
{
	const struct hp_sizes *ha = a;
	const struct hp_sizes *hb = b;

	if (hb->size > ha->size)
		return 1;
	if (hb->size < ha->size)
		return -1;
	return 0;
}

int
eal_get_platform_hp_info(struct eal_platform_info *platform_info)
{
	static const char dirent_start_text[] = "hugepages-";
	const size_t dirent_start_len = sizeof(dirent_start_text) - 1;
	unsigned int num_sizes = 0;
	DIR *dir;
	struct dirent *dirent;

	dir = opendir(sys_dir_path);
	if (dir == NULL) {
		/* if we are using no-huge, unavailabiltity of hugepages may not be a problem,
		 * so just log a warning and return 0 hugepage sizes.
		 */
		EAL_LOG(WARNING, "Cannot open directory %s to read system hugepage info",
				sys_dir_path);
		return 0;
	}

	for (dirent = readdir(dir); dirent != NULL; dirent = readdir(dir)) {
		struct hp_sizes *hps;
		uint64_t sz;
		unsigned int i;

		if (strncmp(dirent->d_name, dirent_start_text,
			    dirent_start_len) != 0)
			continue;

		if (num_sizes >= MAX_HUGEPAGE_SIZES)
			break;

		sz = rte_str_to_size(&dirent->d_name[dirent_start_len]);
		hps = &platform_info->hugepage_sizes[num_sizes];
		hps->size = sz;
		if (strlcpy(hps->subdir, dirent->d_name,
				sizeof(hps->subdir)) >= sizeof(hps->subdir)) {
			/* buffer is properly sized, this should never occur;
			 * check to avoid compiler warning about return value being ignored.
			 */
			EAL_LOG(ERR, "Hugepage subdir name too long: %s", dirent->d_name);
			continue;
		}

		/* fill per-socket page counts; fall back to socket 0 total */
		hps->total_pages = 0;
		for (i = 0; i < platform_info->numa_node_count; i++) {
			int socket = (int)platform_info->numa_nodes[i];
			hps->max_pages[socket] = get_num_hugepages_on_node(dirent->d_name,
					socket, sz);
			hps->total_pages += hps->max_pages[socket];
		}
		if (hps->total_pages == 0) {
			hps->max_pages[0] = get_num_hugepages(dirent->d_name, sz, 0);
			hps->total_pages = hps->max_pages[0];
		}

		if (get_hugepage_dir(sz, hps->dir, sizeof(hps->dir)) < 0)
			hps->dir[0] = '\0';

		num_sizes++;
	}
	closedir(dir);

	/* sort largest to smallest, matching hugepage_info ordering */
	qsort(&platform_info->hugepage_sizes[0], num_sizes,
	      sizeof(platform_info->hugepage_sizes[0]), compare_hp_sizes);

	platform_info->num_hugepage_sizes = num_sizes;
	return 0;
}

static void
calc_num_pages(struct hugepage_info *hpi, const struct hp_sizes *hps,
		unsigned int reusable_pages)
{
	uint64_t total_pages = 0;
	unsigned int i;
	const struct eal_user_cfg *user_cfg = eal_get_user_configuration();

	/*
	 * We also don't want to do this for legacy init.
	 * When there are hugepage files to reuse it is unknown
	 * what NUMA node the pages are on.
	 * This could be determined by mapping,
	 * but it is precisely what hugepage file reuse is trying to avoid.
	 */
	if (!user_cfg->legacy_mem && reusable_pages == 0) {
		for (i = 0; i < RTE_MAX_NUMA_NODES; i++) {
			hpi->num_pages[i] = hps->max_pages[i];
			total_pages += hps->max_pages[i];
		}
	}
	/*
	 * we failed to sort memory from the get go, so fall
	 * back to old way
	 */
	if (total_pages == 0) {
		hpi->num_pages[0] = hps->total_pages > 0 ?
			hps->total_pages + reusable_pages :
			get_num_hugepages(hps->subdir, hpi->hugepage_sz,
				reusable_pages);

#ifndef RTE_ARCH_64
		/* for 32-bit systems, limit number of hugepages to
		 * 1GB per page size */
		hpi->num_pages[0] = RTE_MIN(hpi->num_pages[0],
				RTE_PGSIZE_1G / hpi->hugepage_sz);
#endif
	}
}

static int
hugepage_info_init(void)
{
	unsigned int i, num_sizes = 0;
	uint64_t reusable_bytes;
	unsigned int reusable_pages;
	struct eal_runtime_state *runtime_state = eal_get_runtime_state();
	const struct eal_user_cfg *user_cfg = eal_get_user_configuration();
	const struct eal_platform_info *platform_info = eal_get_platform_info();
	int failed = 0;

	/* platform_info->hugepage_sizes[] is already sorted largest to smallest */
	for (i = 0; i < platform_info->num_hugepage_sizes; i++) {
		const struct hp_sizes *hps = &platform_info->hugepage_sizes[i];
		struct hugepage_info *hpi;

		if (num_sizes >= MAX_HUGEPAGE_SIZES)
			break;

		hpi = &runtime_state->hugepage_info[num_sizes];
		hpi->hugepage_sz = hps->size;

		/* first, check if we have a mountpoint */
		if (get_hugepage_dir(hpi->hugepage_sz,
			hpi->hugedir, sizeof(hpi->hugedir)) < 0) {
			if (hps->total_pages > 0)
				EAL_LOG(NOTICE,
					"%" PRIu32 " hugepages of size "
					"%" PRIu64 " reserved, but no mounted "
					"hugetlbfs found for that size",
					hps->total_pages, hpi->hugepage_sz);
			/* if we have kernel support for reserving hugepages
			 * through mmap, and we're in in-memory mode, treat this
			 * page size as valid. we cannot be in legacy mode at
			 * this point because we've checked this earlier in the
			 * init process.
			 */
#ifdef MAP_HUGE_SHIFT
			if (user_cfg->in_memory) {
				EAL_LOG(DEBUG, "In-memory mode enabled, hugepages of size %" PRIu64 " bytes will be allocated anonymously",
					hpi->hugepage_sz);
				calc_num_pages(hpi, hps, 0);
				num_sizes++;
			}
#endif
			continue;
		}

		/* try to obtain a writelock */
		hpi->lock_descriptor = open(hpi->hugedir, O_RDONLY);

		/* if blocking lock failed */
		if (flock(hpi->lock_descriptor, LOCK_EX) == -1) {
			EAL_LOG(CRIT,
				"Failed to lock hugepage directory!");
			failed = 1;
			break;
		}

		/*
		 * Check for existing hugepage files and either remove them
		 * or count how many of them can be reused.
		 */
		reusable_pages = 0;
		if (!user_cfg->hugepage_file.unlink_existing) {
			reusable_bytes = 0;
			if (inspect_hugedir(hpi->hugedir, &reusable_bytes) < 0) {
				failed = 1;
				break;
			}
			RTE_ASSERT(reusable_bytes % hpi->hugepage_sz == 0);
			reusable_pages = reusable_bytes / hpi->hugepage_sz;
		} else if (clear_hugedir(hpi->hugedir) < 0) {
			failed = 1;
			break;
		}
		calc_num_pages(hpi, hps, reusable_pages);

		num_sizes++;
	}

	if (failed)
		return -1;

	runtime_state->num_hugepage_sizes = num_sizes;

	/* now we have all info, check we have at least one valid size */
	for (i = 0; i < num_sizes; i++) {
		/* pages may no longer all be on socket 0, so check all */
		unsigned int j, num_pages = 0;
		struct hugepage_info *hpi = &runtime_state->hugepage_info[i];

		for (j = 0; j < RTE_MAX_NUMA_NODES; j++)
			num_pages += hpi->num_pages[j];
		if (num_pages > 0)
			return 0;
	}

	/* no valid hugepage mounts available, return error */
	return -1;
}

/*
 * when we initialize the hugepage info, everything goes
 * to socket 0 by default. it will later get sorted by memory
 * initialization procedure.
 */
int
eal_hugepage_info_init(void)
{
	struct hugepage_info *hpi, *tmp_hpi;
	unsigned int i;
	struct eal_runtime_state *runtime_state = eal_get_runtime_state();
	const struct eal_user_cfg *user_cfg = eal_get_user_configuration();

	if (hugepage_info_init() < 0)
		return -1;

	/* for no shared files mode, we're done */
	if (user_cfg->no_shconf)
		return 0;

	hpi = &runtime_state->hugepage_info[0];

	tmp_hpi = create_shared_memory(eal_hugepage_info_path(),
			sizeof(runtime_state->hugepage_info));
	if (tmp_hpi == NULL) {
		EAL_LOG(ERR, "Failed to create shared memory!");
		return -1;
	}

	memcpy(tmp_hpi, hpi, sizeof(runtime_state->hugepage_info));

	/* we've copied file descriptors along with everything else, but they
	 * will be invalid in secondary process, so overwrite them
	 */
	for (i = 0; i < RTE_DIM(runtime_state->hugepage_info); i++) {
		struct hugepage_info *tmp = &tmp_hpi[i];
		tmp->lock_descriptor = -1;
	}

	if (munmap(tmp_hpi, sizeof(runtime_state->hugepage_info)) < 0) {
		EAL_LOG(ERR, "Failed to unmap shared memory!");
		return -1;
	}
	return 0;
}

int eal_hugepage_info_read(void)
{
	struct eal_runtime_state *runtime_state = eal_get_runtime_state();
	struct hugepage_info *hpi = &runtime_state->hugepage_info[0];
	struct hugepage_info *tmp_hpi;

	tmp_hpi = open_shared_memory(eal_hugepage_info_path(),
				  sizeof(runtime_state->hugepage_info));
	if (tmp_hpi == NULL) {
		EAL_LOG(ERR, "Failed to open shared memory!");
		return -1;
	}

	memcpy(hpi, tmp_hpi, sizeof(runtime_state->hugepage_info));

	if (munmap(tmp_hpi, sizeof(runtime_state->hugepage_info)) < 0) {
		EAL_LOG(ERR, "Failed to unmap shared memory!");
		return -1;
	}

	/* count valid entries copied from primary process */
	for (unsigned int i = 0; i < MAX_HUGEPAGE_SIZES; i++) {
		if (runtime_state->hugepage_info[i].hugepage_sz == 0)
			break;
		runtime_state->num_hugepage_sizes = i + 1;
	}
	return 0;
}
