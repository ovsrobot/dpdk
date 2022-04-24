/* SPDX-License-Identifier: (BSD-3-Clause OR LGPL-2.1) */
/*
 * Copyright(c) 2007-2014 Intel Corporation.
 */

#ifndef _RTE_KNI_ABI_H_
#define _RTE_KNI_ABI_H_

#ifndef ABI_VERSION_MAJOR
#error Need ABI_VERSION_MAJOR being the major part of dpdk/ABI_VERSION
#endif
#define RTE_KNI_ABI_VERSION_MAGIC_MASK 0xAAAA
#define RTE_KNI_ABI_VERSION_MAGIC (((ABI_VERSION_MAJOR) ^ RTE_KNI_ABI_VERSION_MAGIC_MASK))
#define RTE_KNI_ABI_VERSION_FROM_MAGIC(__magic) (((__magic) ^ RTE_KNI_ABI_VERSION_MAGIC_MASK))

#endif

