/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Realtek Corporation. All rights reserved
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>

#include <rte_eal.h>

#include <rte_string_fns.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <bus_pci_driver.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <dev_driver.h>

#include "r8169_ethdev.h"
#include "r8169_hw.h"
#include "r8169_logs.h"

/* ---------------------------------RX---------------------------------- */
int
rtl_rx_init(struct rte_eth_dev *dev)
{
	return 0;
}

uint16_t
rtl_recv_pkts(void *rxq, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	return 0;
}

/* ---------------------------------TX---------------------------------- */
int
rtl_tx_init(struct rte_eth_dev *dev)
{
	return 0;
}

uint16_t
rtl_xmit_pkts(void *txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	return 0;
}
