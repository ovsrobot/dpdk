/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _FLOW_API_H_
#define _FLOW_API_H_

#include <pthread.h>
#include <stdint.h>
#include <assert.h>

#include "ntlog.h"

#include "flow_api_actions.h"
#include "flow_api_engine.h"
#include "hw_mod_backend.h"
#include "stream_binary_flow_api.h"

/*
 * Flow NIC and Eth port device management
 */

struct hw_mod_resource_s {
	uint8_t *alloc_bm;	/* allocation bitmap */
	uint32_t *ref;	/* reference counter for each resource element */
	uint32_t resource_count;/* number of total available entries */
};

struct flow_eth_dev {
	struct flow_nic_dev *ndev;	/* NIC that owns this port device */
	uint8_t port;	/* NIC port id */
	uint32_t port_id;	/* App assigned port_id - may be DPDK port_id */

	struct flow_queue_id_s rx_queue[FLOW_MAX_QUEUES + 1];	/* 0th for exception */
	int num_queues;	/* VSWITCH has exceptions sent on queue 0 per design */

	int rss_target_id;	/* QSL_HSH index if RSS needed QSL v6+ */
	struct flow_eth_dev *next;
};

enum flow_nic_hash_e {
	HASH_ALGO_ROUND_ROBIN = 0,
	HASH_ALGO_5TUPLE,
};

/* registered NIC backends */
struct flow_nic_dev {
	uint8_t adapter_no;	/* physical adapter no in the host system */
	uint16_t ports;	/* number of in-ports addressable on this NIC */
	enum flow_eth_dev_profile
	flow_profile;	/* flow profile this NIC is initially prepared for */
	int flow_mgnt_prepared;

	struct hw_mod_resource_s res[RES_COUNT];/* raw NIC resource allocation table */
	void *km_res_handle;
	void *kcc_res_handle;

	void *flm_mtr_handle;
	void *group_handle;
	void *hw_db_handle;
	void *id_table_handle;

	/* statistics */
	uint32_t flow_stat_id_map[MAX_COLOR_FLOW_STATS];

	uint32_t flow_unique_id_counter;
	/* linked list of all flows created on this NIC */
	struct flow_handle *flow_base;
	/* linked list of all FLM flows created on this NIC */
	struct flow_handle *flow_base_flm;
	pthread_mutex_t flow_mtx;

	/* NIC backend API */
	struct flow_api_backend_s be;
	/* linked list of created eth-port devices on this NIC */
	struct flow_eth_dev *eth_base;
	pthread_mutex_t mtx;

	/* pre allocated default QSL Drop */
	int default_qsl_drop_index;
	/* pre allocated default QSL Discard */
	int default_qsl_discard_index;

	/* next NIC linked list */
	struct flow_nic_dev *next;
};

#endif
