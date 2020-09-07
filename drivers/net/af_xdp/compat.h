/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation.
 */

#include <linux/version.h>

#if KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE && \
	defined(RTE_LIBRTE_AF_XDP_PMD_SHARED_UMEM)
#define ETH_AF_XDP_SHARED_UMEM 1
#endif
