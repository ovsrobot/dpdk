/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

/*
 * The syscall mmap does not exist on Windows,
 * but this error code is used in a badly defined DPDK API for PCI mapping.
 */
#define MAP_FAILED ((void *) -1)
