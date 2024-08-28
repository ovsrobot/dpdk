/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_interrupts.h>
#include <eal_interrupts.h>
#include <ethdev_pci.h>
#include <rte_kvargs.h>
#include <rte_hexdump.h>

RTE_PMD_REGISTER_KMOD_DEP(net_zxdh, "* vfio-pci");
RTE_LOG_REGISTER_SUFFIX(zxdh_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(zxdh_logtype_driver, driver, NOTICE);
RTE_LOG_REGISTER_SUFFIX(zxdh_logtype_rx, rx, DEBUG);
RTE_LOG_REGISTER_SUFFIX(zxdh_logtype_tx, tx, DEBUG);

RTE_LOG_REGISTER_SUFFIX(zxdh_logtype_msg, msg, NOTICE);
RTE_PMD_REGISTER_PARAM_STRING(net_zxdh,
	"q_depth=<int>");

