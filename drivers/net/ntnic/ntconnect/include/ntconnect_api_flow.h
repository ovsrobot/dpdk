/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTCONNECT_API_FILTER_H_
#define _NTCONNECT_API_FILTER_H_

#include "stream_binary_flow_api.h"

/*
 * Create structures allocating the space to carry through ntconnect interface
 */
#define MAX_FLOW_STREAM_ELEM 16
#define MAX_FLOW_STREAM_QUERY_DATA 1024
#define MAX_FLOW_STREAM_ERROR_MSG 128
#define MAX_FLOW_STREAM_VXLAN_TUN_ELEM 8
#define MAX_FLOW_STREAM_COUNT_ACTIONS 4

#define MAX_PATH_LEN 128

enum ntconn_flow_err_e {
	NTCONN_FLOW_ERR_NONE = 0,
	NTCONN_FLOW_ERR_INTERNAL_ERROR = 0x100,
	NTCONN_FLOW_ERR_PORT_IS_NOT_INITIALIZED,
	NTCONN_FLOW_ERR_INVALID_PORT,
	NTCONN_FLOW_ERR_UNEXPECTED_VIRTIO_PATH,
	NTCONN_FLOW_ERR_UNSUPPORTED_ADAPTER,
	NTCONN_FLOW_ERR_TO_MANY_FLOWS,
	NTCONN_FLOW_ERR_NOT_YET_IMPLEMENTED,
	NTCONN_FLOW_ERR_NO_VF_QUEUES,
};

struct flow_elem_types_s {
	int valid;
	union {
		int start_addr;
		struct flow_elem_eth eth;
		struct flow_elem_vlan vlan[2];
		struct flow_elem_ipv4 ipv4;
		struct flow_elem_ipv6 ipv6;
		struct flow_elem_sctp sctp;
		struct flow_elem_tcp tcp;
		struct flow_elem_udp udp;
		struct flow_elem_icmp icmp;
		struct flow_elem_vxlan vxlan;
		struct flow_elem_port_id port_id;
		struct flow_elem_tag tag;
	} u;
};

struct flow_elem_cpy {
	enum flow_elem_type type; /* element type */
	struct flow_elem_types_s spec_cpy;
	struct flow_elem_types_s mask_cpy;
};

struct flow_action_vxlan_encap_cpy {
	/* Encapsulating vxlan tunnel definition */
	struct flow_elem_cpy vxlan_tunnel[MAX_FLOW_STREAM_VXLAN_TUN_ELEM];
};

struct flow_action_rss_cpy {
	struct flow_action_rss rss;
	uint16_t cpy_queue[FLOW_MAX_QUEUES];
};

#define MAX_ACTION_ENCAP_DATA 512
struct flow_action_decap_cpy {
	uint8_t data[MAX_ACTION_ENCAP_DATA];
	size_t size;
	struct flow_elem_cpy item_cpy
		[RAW_ENCAP_DECAP_ELEMS_MAX]; /* Need room for end command */
	int item_count;
};

struct flow_action_encap_cpy {
	uint8_t data[MAX_ACTION_ENCAP_DATA];
	size_t size;
	struct flow_elem_cpy item_cpy
		[RAW_ENCAP_DECAP_ELEMS_MAX]; /* Need room for end command */
	int item_count;
};

struct flow_action_types_s {
	int valid;
	union {
		int start_addr;
		struct flow_action_rss_cpy rss;
		struct flow_action_push_vlan vlan;
		struct flow_action_set_vlan_vid vlan_vid;
		struct flow_action_vxlan_encap_cpy vxlan;
		struct flow_action_count count;
		struct flow_action_mark mark;
		struct flow_action_port_id port_id;
		struct flow_action_tag tag;
		struct flow_action_queue queue;
		struct flow_action_decap_cpy decap;
		struct flow_action_encap_cpy encap;
		struct flow_action_jump jump;
		struct flow_action_meter meter;
	} u;
};

struct flow_action_cpy {
	enum flow_action_type type;
	struct flow_action_types_s conf_cpy;
};

struct query_flow_ntconnect {
	uint8_t port;
	struct flow_action_cpy action;
	uint64_t flow;
};

struct create_flow_ntconnect {
	uint8_t port;
	uint8_t vport;
	struct flow_attr attr;
	struct flow_elem_cpy elem[MAX_FLOW_STREAM_ELEM];
	struct flow_action_cpy action[MAX_FLOW_STREAM_ELEM];
};

struct destroy_flow_ntconnect {
	uint8_t port;
	uint64_t flow;
};

#define ERR_MSG_LEN 128LLU

struct flow_setport_return {
	struct flow_queue_id_s queues[FLOW_MAX_QUEUES];
	uint8_t num_queues;
};

struct flow_error_return_s {
	enum flow_error_e type;
	char err_msg[ERR_MSG_LEN];
	int status;
};

struct create_flow_return_s {
	uint64_t flow;
};

struct validate_flow_return_s {
	int status;
};

struct query_flow_return_s {
	enum flow_error_e type;
	char err_msg[ERR_MSG_LEN];
	int status;
	uint32_t data_length;
	uint8_t data[];
};

struct flow_return_s {
	enum flow_error_e type;
	char err_msg[ERR_MSG_LEN];
	int status;
};

struct flow_error_ntconn {
	enum flow_error_e type;
	char message[ERR_MSG_LEN];
};

#endif /* _NTCONNECT_API_FILTER_H_ */
