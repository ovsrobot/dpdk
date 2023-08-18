/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _FLOW_API_H_
#define _FLOW_API_H_

#include <pthread.h>

#include "ntlog.h"
#include "stream_binary_flow_api.h"

#include "flow_api_actions.h"
#include "flow_api_backend.h"
#include "flow_api_engine.h"

/*
 * ****************************************************
 *        Flow NIC and Eth port device management
 * ****************************************************
 */

struct hw_mod_resource_s {
	uint8_t *alloc_bm; /* allocation bitmap */
	uint32_t *ref; /* reference counter for each resource element */
	uint32_t resource_count; /* number of total available entries */
};

/*
 * Set of definitions to be used to map desirable fields for RSS
 * hash functions. Supposed to be used with dpdk, so the values
 * correspond to dpdk definitions, but we avoid dependency to
 * dpdk headers here.
 */

#define NT_ETH_RSS_IPV4 (UINT64_C(1) << 2)
#define NT_ETH_RSS_FRAG_IPV4 (UINT64_C(1) << 3)
#define NT_ETH_RSS_NONFRAG_IPV4_OTHER (UINT64_C(1) << 7)
#define NT_ETH_RSS_IPV6 (UINT64_C(1) << 8)
#define NT_ETH_RSS_FRAG_IPV6 (UINT64_C(1) << 9)
#define NT_ETH_RSS_NONFRAG_IPV6_OTHER (UINT64_C(1) << 13)
#define NT_ETH_RSS_IPV6_EX (UINT64_C(1) << 15)
#define NT_ETH_RSS_C_VLAN (UINT64_C(1) << 26)
#define NT_ETH_RSS_L3_DST_ONLY (UINT64_C(1) << 62)
#define NT_ETH_RSS_L3_SRC_ONLY (UINT64_C(1) << 63)

#define NT_ETH_RSS_IP                                           \
	(NT_ETH_RSS_IPV4 | NT_ETH_RSS_FRAG_IPV4 |               \
	 NT_ETH_RSS_NONFRAG_IPV4_OTHER | NT_ETH_RSS_IPV6 |      \
	 NT_ETH_RSS_FRAG_IPV6 | NT_ETH_RSS_NONFRAG_IPV6_OTHER | \
	 NT_ETH_RSS_IPV6_EX)

/*
 * level 1, requests RSS to be performed on the outermost packet
 * encapsulation level.
 */
#define NT_ETH_RSS_LEVEL_OUTERMOST (UINT64_C(1) << 50)

/*
 * level 2, requests RSS to be performed on the specified inner packet
 * encapsulation level, from outermost to innermost (lower to higher values).
 */
#define NT_ETH_RSS_LEVEL_INNERMOST (UINT64_C(2) << 50)

/*
 * Struct wrapping unsigned 64 bit integer carry RSS hash option bits
 * to avoid occasional incorrect usage interfacing with higher level
 * framework (e.g. DPDK)
 */
struct nt_eth_rss {
	uint64_t fields;
};

struct flow_eth_dev {
	struct flow_nic_dev *ndev; /* NIC that owns this port device */
	uint8_t port; /* NIC port id */
	uint32_t port_id; /* App assigned port_id - may be DPDK port_id */

	struct flow_queue_id_s
		rx_queue[FLOW_MAX_QUEUES + 1]; /* 0th for exception */
	int num_queues; /* VSWITCH has exceptions sent on queue 0 per design */

	int rss_target_id; /* QSL_HSH index if RSS needed QSL v6+ */
	struct flow_eth_dev *next;
};

enum flow_nic_hash_e {
	HASH_ALGO_ROUND_ROBIN = 0,
	HASH_ALGO_5TUPLE,
};

/* registered NIC backends */
struct flow_nic_dev {
	uint8_t adapter_no; /* physical adapter no in the host system */
	uint16_t ports; /* number of in-ports addressable on this NIC */
	enum flow_eth_dev_profile
	flow_profile; /* flow profile this NIC is initially prepared for */
	int flow_mgnt_prepared;

	struct hw_mod_resource_s
		res[RES_COUNT]; /* raw NIC resource allocation table */
	void *flm_res_handle;
	void *km_res_handle;
	void *kcc_res_handle;

	void *flm_mtr_handle;
	void *ft_res_handle;
	void *mtr_stat_handle;
	void *group_handle;

	/* statistics */
	uint32_t flow_stat_id_map[MAX_COLOR_FLOW_STATS];

	struct flow_handle
		*flow_base; /* linked list of all flows created on this NIC */
	struct flow_handle *
		flow_base_flm; /* linked list of all FLM flows created on this NIC */

	struct flow_api_backend_s be; /* NIC backend API */
	struct flow_eth_dev *
		eth_base; /* linked list of created eth-port devices on this NIC */
	pthread_mutex_t mtx;

	int default_qsl_drop_index; /* pre allocated default QSL Drop */
	int default_qsl_discard_index; /* pre allocated default QSL Discard */
	/* RSS hash function settings bitfields correspond to data used for hashing */
	struct nt_eth_rss
		rss_hash_config;
	struct flow_nic_dev *next; /* next NIC linked list */
};

/*
 * ****************************************************
 * Error
 * ****************************************************
 */

enum flow_nic_err_msg_e {
	ERR_SUCCESS = 0,
	ERR_FAILED = 1,
	ERR_MEMORY = 2,
	ERR_OUTPUT_TOO_MANY = 3,
	ERR_RSS_TOO_MANY_QUEUES = 4,
	ERR_VLAN_TYPE_NOT_SUPPORTED = 5,
	ERR_VXLAN_HEADER_NOT_ACCEPTED = 6,
	ERR_VXLAN_POP_INVALID_RECIRC_PORT = 7,
	ERR_VXLAN_POP_FAILED_CREATING_VTEP = 8,
	ERR_MATCH_VLAN_TOO_MANY = 9,
	ERR_MATCH_INVALID_IPV6_HDR = 10,
	ERR_MATCH_TOO_MANY_TUNNEL_PORTS = 11,
	ERR_MATCH_INVALID_OR_UNSUPPORTED_ELEM = 12,
	ERR_MATCH_FAILED_BY_HW_LIMITS = 13,
	ERR_MATCH_RESOURCE_EXHAUSTION = 14,
	ERR_MATCH_FAILED_TOO_COMPLEX = 15,
	ERR_ACTION_REPLICATION_FAILED = 16,
	ERR_ACTION_OUTPUT_RESOURCE_EXHAUSTION = 17,
	ERR_ACTION_TUNNEL_HEADER_PUSH_OUTPUT_LIMIT = 18,
	ERR_ACTION_INLINE_MOD_RESOURCE_EXHAUSTION = 19,
	ERR_ACTION_RETRANSMIT_RESOURCE_EXHAUSTION = 20,
	ERR_ACTION_FLOW_COUNTER_EXHAUSTION = 21,
	ERR_ACTION_INTERNAL_RESOURCE_EXHAUSTION = 22,
	ERR_INTERNAL_QSL_COMPARE_FAILED = 23,
	ERR_INTERNAL_CAT_FUNC_REUSE_FAILED = 24,
	ERR_MATCH_ENTROPY_FAILED = 25,
	ERR_MATCH_CAM_EXHAUSTED = 26,
	ERR_INTERNAL_VIRTUAL_PORT_CREATION_FAILED = 27,
	ERR_ACTION_UNSUPPORTED = 28,
	ERR_REMOVE_FLOW_FAILED = 29,
	ERR_ACTION_NO_OUTPUT_DEFINED_USE_DEFAULT = 30,
	ERR_ACTION_NO_OUTPUT_QUEUE_FOUND = 31,
	ERR_MATCH_UNSUPPORTED_ETHER_TYPE = 32,
	ERR_OUTPUT_INVALID = 33,
	ERR_MATCH_PARTIAL_OFFLOAD_NOT_SUPPORTED = 34,
	ERR_MATCH_CAT_CAM_EXHAUSTED = 35,
	ERR_MATCH_KCC_KEY_CLASH = 36,
	ERR_MATCH_CAT_CAM_FAILED = 37,
	ERR_PARTIAL_FLOW_MARK_TOO_BIG = 38,
	ERR_FLOW_PRIORITY_VALUE_INVALID = 39,
	ERR_MSG_NO_MSG
};

void flow_nic_set_error(enum flow_nic_err_msg_e msg, struct flow_error *error);

/*
 * ****************************************************
 * Resources
 * ****************************************************
 */

extern const char *dbg_res_descr[];

#define flow_nic_set_bit(arr, x) \
	do { \
		uint8_t *_temp_arr = (arr); \
		size_t _temp_x = (x); \
		_temp_arr[_temp_x / 8] = (uint8_t)(_temp_arr[_temp_x / 8] | \
		(uint8_t)(1 << (_temp_x % 8))); \
	} while (0)



#define flow_nic_unset_bit(arr, x) \
	do { \
		size_t _temp_x = (x); \
		arr[_temp_x / 8] &= (uint8_t)~(1 << (_temp_x % 8)); \
	} while (0)

#define flow_nic_is_bit_set(arr, x) \
	({ \
		size_t _temp_x = (x); \
		(arr[_temp_x / 8] & (uint8_t)(1 << (_temp_x % 8))); \
	})

#define flow_nic_mark_resource_used(_ndev, res_type, index) \
	do { \
		struct flow_nic_dev *_temp_ndev = (_ndev); \
		__typeof__(res_type) _temp_res_type = (res_type); \
		size_t _temp_index = (index); \
		NT_LOG(DBG, FILTER, "mark resource used: %s idx %zu\n", \
		dbg_res_descr[_temp_res_type], _temp_index); \
		assert(flow_nic_is_bit_set(_temp_ndev->res[_temp_res_type].alloc_bm, _temp_index) \
		== 0); \
		flow_nic_set_bit(_temp_ndev->res[_temp_res_type].alloc_bm, _temp_index); \
	} while (0)



#define flow_nic_mark_resource_unused(_ndev, res_type, index) \
	do { \
		__typeof__(res_type) _temp_res_type = (res_type); \
		size_t _temp_index = (index); \
		NT_LOG(DBG, FILTER, "mark resource unused: %s idx %zu\n", \
		dbg_res_descr[_temp_res_type], _temp_index); \
		flow_nic_unset_bit((_ndev)->res[_temp_res_type].alloc_bm, _temp_index); \
	} while (0)


#define flow_nic_is_resource_used(_ndev, res_type, index) \
	(!!flow_nic_is_bit_set((_ndev)->res[res_type].alloc_bm, index))

int flow_nic_alloc_resource(struct flow_nic_dev *ndev, enum res_type_e res_type,
			    uint32_t alignment);
int flow_nic_alloc_resource_index(struct flow_nic_dev *ndev, int idx,
				  enum res_type_e res_type);
int flow_nic_alloc_resource_contig(struct flow_nic_dev *ndev,
				   enum res_type_e res_type, unsigned int num,
				   uint32_t alignment);
void flow_nic_free_resource(struct flow_nic_dev *ndev, enum res_type_e res_type,
			    int idx);

int flow_nic_ref_resource(struct flow_nic_dev *ndev, enum res_type_e res_type,
			  int index);
int flow_nic_deref_resource(struct flow_nic_dev *ndev, enum res_type_e res_type,
			    int index);
int flow_nic_find_next_used_resource(struct flow_nic_dev *ndev,
				     enum res_type_e res_type, int idx_start);

int flow_nic_allocate_fh_resource(struct flow_nic_dev *ndev,
				  enum res_type_e res_type,
				  struct flow_handle *fh, uint32_t count,
				  uint32_t alignment);
int flow_nic_allocate_fh_resource_index(struct flow_nic_dev *ndev,
					enum res_type_e res_type, int idx,
					struct flow_handle *fh);

/*
 * ****************************************************
 * Other
 * ****************************************************
 */

struct flow_eth_dev *nic_and_port_to_eth_dev(uint8_t adapter_no, uint8_t port);
struct flow_nic_dev *get_nic_dev_from_adapter_no(uint8_t adapter_no);

int flow_nic_set_hasher(struct flow_nic_dev *ndev, int hsh_idx,
			enum flow_nic_hash_e algorithm);
int flow_nic_set_hasher_fields(struct flow_nic_dev *ndev, int hsh_idx,
			       struct nt_eth_rss fields);

int lag_set_config(uint8_t adapter_no, enum flow_lag_cmd cmd, uint32_t index,
		   uint32_t value);
int lag_set_port_block(uint8_t adapter_no, uint32_t port_mask);
int lag_set_port_group(uint8_t adapter_no, uint32_t port_mask);

int flow_get_num_queues(uint8_t adapter_no, uint8_t port_no);
int flow_get_hw_id(uint8_t adapter_no, uint8_t port_no, uint8_t queue_no);

int flow_get_flm_stats(struct flow_nic_dev *ndev, uint64_t *data,
		       uint64_t size);

#endif
