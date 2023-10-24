/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 IBM Corporation
 */

#ifndef _EAL_LINUX_PRIVATE_H_
#define _EAL_LINUX_PRIVATE_H_

#include <stdbool.h>

/**
 * Check for architecture supported MMU.
 *
 * This function is private to the EAL for Linux.
 */
bool eal_mmu_supported_linux_arch(void);

#endif /* _EAL_LINUX_PRIVATE_H_ */
