/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Red Hat Corp.
 */

#ifndef _NOISY_VNF_H_
#define _NOISY_VNF_H_

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_malloc.h>

#include "testpmd.h"

void
noisy_fwd_end(portid_t pi);

int
noisy_fwd_begin(portid_t pi);

uint16_t
noisy_eth_tx_burst(struct fwd_stream *fs, uint16_t nb_rx, struct rte_mbuf **pkts_burst);

#endif
