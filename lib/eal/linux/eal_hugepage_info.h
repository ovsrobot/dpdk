/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
 */

#ifndef _EAL_HUGEPAGE_INFO_
#define _EAL_HUGEPAGE_INFO_

#include <stdint.h>

/**
 * Function called for each hugetlbfs mount point.
 *
 * @param path
 *  Mount point directory.
 * @param hugepage_sz
 *  Hugepage size for the mount or default system hugepage size.
 * @param arg
 *  User data.
 *
 * @return
 *  0 to continue walking, 1 to stop.
 */
typedef int (eal_hugepage_mount_walk_cb)(const char *path, uint64_t hugepage_sz,
					 void *arg);

/**
 * Enumerate hugetlbfs mount points.
 *
 * @param cb
 *  Function called for each mount point.
 * @param cb_arg
 *  User data passed to the callback.
 *
 * @return
 *  0 on success, negative on failure.
 */
int eal_hugepage_mount_walk(eal_hugepage_mount_walk_cb *cb, void *cb_arg);

#endif /* _EAL_HUGEPAGE_INFO_ */
