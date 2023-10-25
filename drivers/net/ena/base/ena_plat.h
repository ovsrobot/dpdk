/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2019 Amazon.com, Inc. or its affiliates.
 * All rights reserved.
 */

#ifndef ENA_PLAT_H_
#define ENA_PLAT_H_

#if defined(ENA_IPXE)
#include <ena_plat_ipxe.h>
#elif defined(__linux__)
#if defined(__KERNEL__)
#include <ena_plat_linux.h>
#else
#include <ena_plat_dpdk.h>
#endif
#elif defined(_WIN32)
#include <ena_plat_windows.h>
#elif defined(__FreeBSD__)
#if defined(__KERNEL__)
#include <ena_plat_fbsd.h>
#else
#include <ena_plat_dpdk.h>
#endif
#elif defined(__APPLE__)
#include <ena_plat_macos.h>
#else
#error "Invalid platform"
#endif

#endif /* ENA_PLAT_H_ */
