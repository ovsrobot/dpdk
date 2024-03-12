/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Microsoft Corporation
 */

#ifndef _RTE_ETHDEV_EXPORT_H_
#define _RTE_ETHDEV_EXPORT_H_

/**
 * @file
 *
 * Import / Export macros for ethdev data variables.
 */

#include <rte_common.h>

#ifndef __rte_ethdev_export
#define __rte_ethdev_export __rte_declare_import
#else
#undef __rte_ethdev_export
#define __rte_ethdev_export __rte_declare_export
#endif

#endif
