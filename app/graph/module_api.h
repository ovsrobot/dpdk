/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#ifndef APP_GRAPH_MODULE_API_H
#define APP_GRAPH_MODULE_API_H

#include <stdint.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_node_eth_api.h>

#include "conn.h"
#include "cli.h"
#include "ethdev.h"
#include "ethdev_rx.h"
#include "graph.h"
#include "l3fwd.h"
#include "mempool.h"
#include "neigh.h"
#include "route.h"
#include "utils.h"

/*
 * Externs
 */
extern volatile bool force_quit;

bool app_graph_stats_enabled(void);

#endif
