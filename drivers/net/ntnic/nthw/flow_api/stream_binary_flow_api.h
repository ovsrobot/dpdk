/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _STREAM_BINARY_FLOW_API_H_
#define _STREAM_BINARY_FLOW_API_H_

#include <stdint.h> /* uint16_t, uint32_t, uint64_t */
#include <stdio.h> /* snprintf */

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t be16_t; /* 16-bit big-endian */
typedef uint32_t be32_t; /* 32-bit big-endian */
typedef uint64_t be64_t; /* 64-bit big-endian */

/*
 * Flow frontend for binary programming interface
 */

#define FLOW_MAX_QUEUES 128

#define RAW_ENCAP_DECAP_ELEMS_MAX 16

/*
 * Partial flow mark and special flow marks
 */
#define FLOW_MARK_LACP 0x7fffffff
#define FLOW_MARK_MAX 0x7ffffffe
/*
 * Flow eth dev profile determines how the FPGA module resources are
 * managed and what features are available
 */
enum flow_eth_dev_profile {
	FLOW_ETH_DEV_PROFILE_VSWITCH = 0,
	FLOW_ETH_DEV_PROFILE_INLINE = 1,
};

/*
 * Flow rule attributes
 */
struct flow_attr {
	uint32_t group; /* Priority group. */
	uint32_t priority; /* Rule priority level within group. */
	uint16_t forced_vlan_vid; /* Forced VLAN VID that filter must match. Ignored if 0. */
	uint8_t caller_id; /* Unique ID of caller application. */
};

struct flow_queue_id_s {
	int id;
	int hw_id;
};

/* NT Private rte flow items. */

/* NT Private rte flow actions. */

enum flow_elem_type {
	FLOW_ELEM_TYPE_END,
	FLOW_ELEM_TYPE_ANY,
	FLOW_ELEM_TYPE_ETH,
	FLOW_ELEM_TYPE_VLAN,
	FLOW_ELEM_TYPE_IPV4,
	FLOW_ELEM_TYPE_IPV6,
	FLOW_ELEM_TYPE_SCTP,
	FLOW_ELEM_TYPE_TCP,
	FLOW_ELEM_TYPE_UDP,
	FLOW_ELEM_TYPE_ICMP,
	FLOW_ELEM_TYPE_VXLAN,
	FLOW_ELEM_TYPE_GTP,
	FLOW_ELEM_TYPE_PORT_ID,
	FLOW_ELEM_TYPE_TAG,
	FLOW_ELEM_TYPE_VOID,

	/*
	 * Not associated with a RTE_ITEM..., but rather an restoration API device specific
	 * extension
	 */
	FLOW_ELEM_TYPE_TUNNEL
};

enum flow_action_type { /* conf structure */
	FLOW_ACTION_TYPE_END, /* -none- : End tag for action list */
	FLOW_ACTION_TYPE_POP_VLAN, /* -none- : Pops outer vlan tag */
	FLOW_ACTION_TYPE_PUSH_VLAN, /* struct flow_action_push_vlan : Push VLAN TAG */
	FLOW_ACTION_TYPE_SET_VLAN_VID, /* struct flow_action_set_vlan_vid : Set VLAN VID */
	FLOW_ACTION_TYPE_SET_VLAN_PCP, /* struct flow_action_set_vlan_pcp : Set VLAN PCP */
	/* -none- : Decapsulate outer most VXLAN tunnel from matched flow */
	FLOW_ACTION_TYPE_VXLAN_DECAP,
	FLOW_ACTION_TYPE_VXLAN_ENCAP, /* struct flow_action_vxlan_encap */
	FLOW_ACTION_TYPE_DROP, /* -none- : Drop packets of this flow */
	FLOW_ACTION_TYPE_COUNT, /* struct flow_action_count : Used for "query" flow function */
	FLOW_ACTION_TYPE_MARK, /* struct flow_action_mark : Used to tag a flow in HW with a MARK */
	FLOW_ACTION_TYPE_SET_TAG, /* struct flow_action_tag : Used to tag a flow in HW with a TAG */
	/* struct flow_action_port_id : Destination port ID - HW port ID */
	FLOW_ACTION_TYPE_PORT_ID,
	FLOW_ACTION_TYPE_RSS, /* struct flow_action_rss : */
	FLOW_ACTION_TYPE_QUEUE, /* struct flow_action_queue : */
	FLOW_ACTION_TYPE_JUMP, /* struct flow_action_jump : */
	/* struct flow_action_meter : Used to set MBR record ids in FLM learn records */
	FLOW_ACTION_TYPE_METER,
	FLOW_ACTION_TYPE_RAW_ENCAP, /* struct flow_action_raw_encap : */
	FLOW_ACTION_TYPE_RAW_DECAP, /* struct flow_action_raw_decap : */
	FLOW_ACTION_TYPE_MODIFY_FIELD, /* struct flow_action_modify_field : */

	/*
	 * -none- : not associated with a RTE_ACTION..., but rather an restoration API device
	 * specific extension
	 */
	FLOW_ACTION_TYPE_TUNNEL_SET
};

#pragma pack(1)
struct ether_addr_s {
	uint8_t addr_b[6];
};

#pragma pack()

static inline void flow_ether_format_addr(char *buf, uint16_t size,
		const struct ether_addr_s *eth_addr)
{
	snprintf(buf, size, "%02X:%02X:%02X:%02X:%02X:%02X",
		 eth_addr->addr_b[0], eth_addr->addr_b[1], eth_addr->addr_b[2],
		 eth_addr->addr_b[3], eth_addr->addr_b[4], eth_addr->addr_b[5]);
}

/*
 * IPv4 Header
 */
#pragma pack(1)
struct ipv4_hdr_s {
	uint8_t version_ihl;
	uint8_t tos;
	be16_t length;
	be16_t id;
	be16_t frag_offset;
	uint8_t ttl;
	uint8_t next_proto_id;
	be16_t hdr_csum;
	be32_t src_ip;
	be32_t dst_ip;
};

#pragma pack()
/*
 * IPv6 Header
 */
#pragma pack(1)
struct ipv6_hdr_s {
	be32_t vtc_flow; /* IP version, traffic class & flow label */
	be16_t payload_len; /* IP packet length - includes ip header */
	uint8_t proto;
	uint8_t hop_limits;
	uint8_t src_addr[16];
	uint8_t dst_addr[16];
};

#pragma pack()

/*
 * SCTP Header
 */
#pragma pack(1)
struct sctp_hdr_s {
	be16_t src_port;
	be16_t dst_port;
	be32_t tag; /* Validation tag */
	be32_t cksum;
};

#pragma pack()

/*
 * TCP Header
 */
#pragma pack(1)
struct tcp_hdr_s {
	be16_t src_port;
	be16_t dst_port;
	be32_t sent_seq;
	be32_t recv_ack;
	uint8_t data_off;
	uint8_t tcp_flags;
	be16_t rx_win;
	be16_t cksum;
	be16_t tcp_urp;
};

#pragma pack()

/*
 * UDP Header
 */
#pragma pack(1)
struct udp_hdr_s {
	be16_t src_port;
	be16_t dst_port;
	be16_t len;
	be16_t cksum;
};

#pragma pack()

/*
 * ICMP Header
 */
#pragma pack(1)
struct icmp_hdr_s {
	uint8_t type;
	uint8_t code;
	be16_t cksum;
	be16_t ident;
	be16_t seq_nb;
};

#pragma pack()
/*
 * FLOW_ELEM_TYPE_ETH specification
 */
#pragma pack(1)
struct flow_elem_eth {
	struct ether_addr_s d_addr; /* DMAC */
	struct ether_addr_s s_addr; /* SMAC */
	be16_t ether_type; /* Frame type */
};

#pragma pack()

/*
 * FLOW_ELEM_TYPE_VLAN specification
 */
#pragma pack(1)
struct flow_elem_vlan {
	be16_t tci; /* Tag control information */
	be16_t inner_type; /* Inner EtherType or TPID */
};

#pragma pack()

/*
 * FLOW_ELEM_TYPE_IPV4 specification
 */
struct flow_elem_ipv4 {
	struct ipv4_hdr_s hdr;
};

/*
 * FLOW_ELEM_TYPE_IPV6 specification
 */
struct flow_elem_ipv6 {
	struct ipv6_hdr_s hdr;
};

/*
 * FLOW_ELEM_TYPE_SCTP specification
 */
struct flow_elem_sctp {
	struct sctp_hdr_s hdr;
};

/*
 * FLOW_ELEM_TYPE_TCP specification
 */
struct flow_elem_tcp {
	struct tcp_hdr_s hdr;
};

/*
 * FLOW_ELEM_TYPE_UDP specification
 */
struct flow_elem_udp {
	struct udp_hdr_s hdr;
};

/*
 * FLOW_ELEM_TYPE_ICMP specification
 */
struct flow_elem_icmp {
	struct icmp_hdr_s hdr;
};

/*
 * FLOW_ELEM_TYPE_GTP specification
 */
#pragma pack(1)
struct flow_elem_gtp {
	uint8_t v_pt_rsv_flags;
	uint8_t msg_type;
	be16_t msg_len;
	be32_t teid;
};

#pragma pack()

/*
 * FLOW_ELEM_TYPE_VXLAN specification (RFC 7348)
 */
#pragma pack(1)
struct flow_elem_vxlan {
	uint8_t flags; /* Normally 0x08 (I flag) */
	uint8_t rsvd0[3];
	uint8_t vni[3];
	uint8_t rsvd1;
};

#pragma pack()
/*
 * FLOW_ELEM_TYPE_PORT_ID specification
 */
struct flow_elem_port_id {
	uint32_t id; /* HW port no */
};

/*
 * FLOW_ELEM_TYPE_TAG specification
 */
struct flow_elem_tag {
	uint32_t data;
	uint8_t index;
};

/*
 * FLOW_ELEM_TYPE_ANY specification
 */
struct flow_elem_any {
	uint32_t num; /**< Number of layers covered. */
};

struct flow_elem {
	enum flow_elem_type type; /* element type */
	const void *spec; /* Pointer to element specification structure */
	const void *mask; /* Bitmask applied to spec - same type */
};

/*
 * FLOW_ACTION_TYPE_RSS
 */
enum flow_hash_function {
	FLOW_HASH_FUNCTION_DEFAULT = 0,
	FLOW_HASH_FUNCTION_TOEPLITZ, /* Unsupported in current supported FPGA */
	FLOW_HASH_FUNCTION_SIMPLE_XOR /* Simple XOR - not supported */
};

struct flow_action_rss {
	enum flow_hash_function func;
	uint32_t level; /* only level 0 supported */
	/* Specific RSS hash types (see like DPDK ETH_RSS_*) */
	uint64_t types;
	uint32_t key_len; /* Not supported yet - Hash key length in bytes */
	uint32_t queue_num; /* Number of entries in queue */
	const uint8_t *key; /* Not supported yet - Hash key */
	const uint16_t *queue; /* Queue indices to use */
};

/*
 * FLOW_ACTION_TYPE_PUSH_VLAN
 * Push a new vlan TAG
 */
struct flow_action_push_vlan {
	be16_t ethertype;
};

/*
 * FLOW_ACTION_TYPE_SET_VLAN_VID
 */
struct flow_action_set_vlan_vid {
	be16_t vlan_vid;
};

/*
 * FLOW_ACTION_TYPE_SET_VLAN_PCP
 */
struct flow_action_set_vlan_pcp {
	uint8_t vlan_pcp; /* < VLAN priority. */
};

/*
 * FLOW_ACTION_TYPE_VXLAN_ENCAP specification
 * Valid flow definition:
 *
 * - ETH / IPV4 / UDP / VXLAN / END
 * - ETH / IPV6 / UDP / VXLAN / END
 * - ETH / VLAN / IPV4 / UDP / VXLAN / END
 *
 */
struct flow_action_vxlan_encap {
	/* Encapsulating vxlan tunnel definition */
	struct flow_elem *vxlan_tunnel;
};

/*
 * FLOW_ACTION_TYPE_COUNT specification
 */
struct flow_action_count {
	uint32_t id; /* HW port no */
};

/*
 * FLOW_ACTION_TYPE_COUNT specification (query)
 */
struct flow_query_count {
	uint32_t reset : 1;
	uint32_t hits_set : 1;
	uint32_t bytes_set : 1;

	uint32_t tcp_flags : 9;

	uint32_t reserved : 20;
	uint64_t hits;
	uint64_t bytes;
};

/*
 * FLOW_ACTION_TYPE_MARK specification
 */
struct flow_action_mark {
	uint32_t id; /* mark flow with this ID */
};

/*
 * FLOW_ACTION_TYPE_TAG specification
 */
struct flow_action_tag {
	uint32_t data; /* tag flow with this value */
	uint32_t mask; /* bit-mask applied to "data" */
	uint8_t index; /* index of tag to set */
};

/*
 * FLOW_ACTION_TYPE_PORT_ID specification
 */
struct flow_action_port_id {
	uint32_t rte_flags; /* not used but to be binary compatible with rte flow */
	uint32_t id;
};

/*
 * FLOW_ACTION_TYPE_QUEUE
 */
struct flow_action_queue {
	uint16_t index;
};

/*
 * FLOW_ACTION_TYPE_JUMP
 */
struct flow_action_jump {
	uint32_t group;
};

/*
 * FLOW_ACTION_TYPE_METER
 */
struct flow_action_meter {
	uint32_t mtr_id;
};

/*
 * FLOW_ACTION_TYPE_RAW_ENCAP
 */
struct flow_action_raw_encap {
	uint8_t *data;
	uint8_t *preserve;
	size_t size;
	struct flow_elem items[RAW_ENCAP_DECAP_ELEMS_MAX];
	int item_count;
};

/*
 * FLOW_ACTION_TYPE_RAW_DECAP
 */
struct flow_action_raw_decap {
	uint8_t *data;
	size_t size;
	struct flow_elem items[RAW_ENCAP_DECAP_ELEMS_MAX];
	int item_count;
};

/*
 * Field IDs for MODIFY_FIELD action.
 */
enum flow_field_id {
	FLOW_FIELD_START = 0, /* Start of a packet. */
	FLOW_FIELD_MAC_DST, /* Destination MAC Address. */
	FLOW_FIELD_MAC_SRC, /* Source MAC Address. */
	FLOW_FIELD_VLAN_TYPE, /* 802.1Q Tag Identifier. */
	FLOW_FIELD_VLAN_ID, /* 802.1Q VLAN Identifier. */
	FLOW_FIELD_MAC_TYPE, /* EtherType. */
	FLOW_FIELD_IPV4_DSCP, /* IPv4 DSCP. */
	FLOW_FIELD_IPV4_TTL, /* IPv4 Time To Live. */
	FLOW_FIELD_IPV4_SRC, /* IPv4 Source Address. */
	FLOW_FIELD_IPV4_DST, /* IPv4 Destination Address. */
	FLOW_FIELD_IPV6_DSCP, /* IPv6 DSCP. */
	FLOW_FIELD_IPV6_HOPLIMIT, /* IPv6 Hop Limit. */
	FLOW_FIELD_IPV6_SRC, /* IPv6 Source Address. */
	FLOW_FIELD_IPV6_DST, /* IPv6 Destination Address. */
	FLOW_FIELD_TCP_PORT_SRC, /* TCP Source Port Number. */
	FLOW_FIELD_TCP_PORT_DST, /* TCP Destination Port Number. */
	FLOW_FIELD_TCP_SEQ_NUM, /* TCP Sequence Number. */
	FLOW_FIELD_TCP_ACK_NUM, /* TCP Acknowledgment Number. */
	FLOW_FIELD_TCP_FLAGS, /* TCP Flags. */
	FLOW_FIELD_UDP_PORT_SRC, /* UDP Source Port Number. */
	FLOW_FIELD_UDP_PORT_DST, /* UDP Destination Port Number. */
	FLOW_FIELD_VXLAN_VNI, /* VXLAN Network Identifier. */
	FLOW_FIELD_GENEVE_VNI, /* GENEVE Network Identifier. */
	FLOW_FIELD_GTP_TEID, /* GTP Tunnel Endpoint Identifier. */
	FLOW_FIELD_TAG, /* Tag value. */
	FLOW_FIELD_MARK, /* Mark value. */
	FLOW_FIELD_META, /* Metadata value. */
	FLOW_FIELD_POINTER, /* Memory pointer. */
	FLOW_FIELD_VALUE, /* Immediate value. */
	FLOW_FIELD_IPV4_ECN, /* IPv4 ECN. */
	FLOW_FIELD_IPV6_ECN, /* IPv6 ECN. */
	FLOW_FIELD_GTP_PSC_QFI, /* GTP QFI. */
	FLOW_FIELD_METER_COLOR, /* Meter color marker. */
};

/*
 * Field description for MODIFY_FIELD action.
 */
struct flow_action_modify_data {
	enum flow_field_id field; /* Field or memory type ID. */
	union {
		struct {
			/* Encapsulation level or tag index. */
			uint32_t level;
			/* Number of bits to skip from a field. */
			uint32_t offset;
		};
		/*
		 * Immediate value for FLOW_FIELD_VALUE, presented in the
		 * same byte order and length as in relevant rte_flow_item_xxx.
		 */
		uint8_t value[16];
		/*
		 * Memory address for FLOW_FIELD_POINTER, memory layout
		 * should be the same as for relevant field in the
		 * rte_flow_item_xxx structure.
		 */
		void *pvalue;
	};
};

/*
 * Operation types for MODIFY_FIELD action.
 */
enum flow_modify_op {
	FLOW_MODIFY_SET = 0,
	FLOW_MODIFY_ADD,
	FLOW_MODIFY_SUB,
};

/*
 * FLOW_ACTION_TYPE_MODIFY_FIELD
 */
struct flow_action_modify_field {
	enum flow_modify_op operation;
	struct flow_action_modify_data dst;
	struct flow_action_modify_data src;
	uint32_t width;
};

struct flow_action {
	enum flow_action_type type;
	const void *conf;
};

enum flow_error_e { FLOW_ERROR_NONE, FLOW_ERROR_SUCCESS, FLOW_ERROR_GENERAL };

struct flow_error {
	enum flow_error_e type;
	const char *message;
};

enum flow_lag_cmd {
	FLOW_LAG_SET_ENTRY,
	FLOW_LAG_SET_ALL,
	FLOW_LAG_SET_BALANCE,
};

/*
 * Tunnel definition for DPDK RTE tunnel helper function support
 */
struct tunnel_cfg_s {
	union {
		struct {
			uint32_t src_ip; /* BE */
			uint32_t dst_ip; /* BE */
		} v4;
		struct {
			uint8_t src_ip[16];
			uint8_t dst_ip[16];
		} v6;
		struct {
			uint64_t src_ip[2];
			uint64_t dst_ip[2];
		} v6_long;
	};
	int ipversion;
	uint16_t s_port; /* BE */
	uint16_t d_port; /* BE */
	int tun_type;
};

struct flow_eth_dev; /* port device */
struct flow_handle;

/*
 * Device Management API
 */
int flow_reset_nic_dev(uint8_t adapter_no);

struct flow_eth_dev *flow_get_eth_dev(uint8_t adapter_no, uint8_t hw_port_no,
				      uint32_t port_id, int alloc_queues,
				      struct flow_queue_id_s queue_ids[],
				      int *rss_target_id,
				      enum flow_eth_dev_profile flow_profile,
				      uint32_t exception_path);

int flow_eth_dev_add_queue(struct flow_eth_dev *eth_dev,
			   struct flow_queue_id_s *queue_id);

int flow_delete_eth_dev(struct flow_eth_dev *eth_dev);

int flow_get_tunnel_definition(struct tunnel_cfg_s *tun, uint32_t flow_stat_id,
			       uint8_t vport);

/*
 * NT Flow API
 */
int flow_validate(struct flow_eth_dev *dev, const struct flow_elem item[],
		  const struct flow_action action[], struct flow_error *error);

struct flow_handle *flow_create(struct flow_eth_dev *dev,
				const struct flow_attr *attr,
				const struct flow_elem item[],
				const struct flow_action action[],
				struct flow_error *error);

int flow_destroy(struct flow_eth_dev *dev, struct flow_handle *flow,
		 struct flow_error *error);

int flow_flush(struct flow_eth_dev *dev, struct flow_error *error);

int flow_query(struct flow_eth_dev *dev, struct flow_handle *flow,
	       const struct flow_action *action, void **data, uint32_t *length,
	       struct flow_error *error);

/*
 * NT Flow FLM Meter API
 */
int flow_mtr_supported(struct flow_eth_dev *dev);

uint64_t flow_mtr_meter_policy_n_max(void);

int flow_mtr_set_profile(struct flow_eth_dev *dev, uint32_t profile_id,
			 uint64_t bucket_rate_a, uint64_t bucket_size_a,
			 uint64_t bucket_rate_b, uint64_t bucket_size_b);

int flow_mtr_set_policy(struct flow_eth_dev *dev, uint32_t policy_id, int drop);

int flow_mtr_create_meter(struct flow_eth_dev *dev, uint32_t mtr_id,
			  uint32_t profile_id, uint32_t policy_id,
			  uint64_t stats_mask);

int flow_mtr_destroy_meter(struct flow_eth_dev *dev, uint32_t mtr_id);

int flm_mtr_adjust_stats(struct flow_eth_dev *dev, uint32_t mtr_id,
			 uint32_t adjust_value);

uint32_t flow_mtr_meters_supported(void);

uint32_t flm_mtr_update_stats(struct flow_eth_dev *dev);
void flm_mtr_read_stats(struct flow_eth_dev *dev, uint32_t id,
			uint64_t *stats_mask, uint64_t *green_pkt,
			uint64_t *green_bytes, int clear);

/*
 * Config API
 */
int lag_set_port_group(uint8_t adapter_no, uint32_t port_mask);

int lag_set_port_block(uint8_t adapter_no, uint32_t port_mask);

int lag_set_config(uint8_t adapter_no, enum flow_lag_cmd cmd, uint32_t index,
		   uint32_t value);

int flow_set_mtu_inline(struct flow_eth_dev *dev, uint32_t port, uint16_t mtu);

#ifdef __cplusplus
}
#endif

#endif /* _STREAM_BINARY_FLOW_API_H_ */
