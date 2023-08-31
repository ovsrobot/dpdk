/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_ETHDEV_FDIR_H_
#define _SSSNIC_ETHDEV_FDIR_H_

#define SSSINC_ETHDEV_FDIR_FLOW_KEY_SIZE 44
#define SSSNIC_ETHDEV_FDIR_FLOW_KEY_NUM_DW                                     \
	(SSSINC_ETHDEV_FDIR_FLOW_KEY_SIZE / sizeof(uint32_t))

enum sssnic_ethdev_fdir_match_type {
	SSSNIC_ETHDEV_FDIR_MATCH_ETHERTYPE = RTE_ETH_FILTER_ETHERTYPE,
	SSSNIC_ETHDEV_FDIR_MATCH_FLOW = RTE_ETH_FILTER_FDIR,
};

enum sssnic_ethdev_fdir_flow_ip_type {
	SSSNIC_ETHDEV_FDIR_FLOW_IPV4 = 0,
	SSSNIC_ETHDEV_FDIR_FLOW_IPV6 = 1,
};

enum sssnic_ethdev_fdir_flow_tunnel_type {
	SSSNIC_ETHDEV_FDIR_FLOW_TUNNEL_NONE = 0,
	SSSNIC_ETHDEV_FDIR_FLOW_TUNNEL_VXLAN = 1,
};

#define SSSNIC_ETHDEV_FDIR_FLOW_FUNC_ID_MASK 0x7fff
#define SSSNIC_ETHDEV_FDIR_FLOW_IP_TYPE_MASK 0x1
#define SSSNIC_ETHDEV_FDIR_FLOW_TUNNEL_TYPE_MASK 0xf

struct sssnic_ethdev_fdir_ethertype_key {
	uint16_t ether_type;
};

struct sssnic_ethdev_fdir_ipv4_flow_key {
#if (RTE_BYTE_ORDER == RTE_BIG_ENDIAN)
	uint32_t resvd0 : 16;
	uint32_t ip_proto : 8;
	uint32_t tunnel_type : 4;
	uint32_t resvd1 : 4;

	uint32_t func_id : 15;
	uint32_t ip_type : 1;
	uint32_t sip_w1 : 16;

	uint32_t sip_w0 : 16;
	uint32_t dip_w1 : 16;

	uint32_t dip_w0 : 16;
	uint32_t resvd2 : 16;

	uint32_t resvd3;

	uint32_t resvd4 : 16;
	uint32_t dport : 16;

	uint32_t sport : 16;
	uint32_t resvd5 : 16;

	uint32_t resvd6 : 16;
	uint32_t outer_sip_w1 : 16;

	uint32_t outer_sip_w0 : 16;
	uint32_t outer_dip_w1 : 16;

	uint32_t outer_dip_w0 : 16;
	uint32_t vni_w1 : 16;

	uint32_t vni_w0 : 16;
	uint32_t resvd7 : 16;
#else
	uint32_t resvd1 : 4;
	uint32_t tunnel_type : 4;
	uint32_t ip_proto : 8;
	uint32_t resvd0 : 16;

	uint32_t sip_w1 : 16;
	uint32_t ip_type : 1;
	uint32_t func_id : 15;

	uint32_t dip_w1 : 16;
	uint32_t sip_w0 : 16;

	uint32_t resvd2 : 16;
	uint32_t dip_w0 : 16;

	uint32_t rsvd3;

	uint32_t dport : 16;
	uint32_t resvd4 : 16;

	uint32_t resvd5 : 16;
	uint32_t sport : 16;

	uint32_t outer_sip_w1 : 16;
	uint32_t resvd6 : 16;

	uint32_t outer_dip_w1 : 16;
	uint32_t outer_sip_w0 : 16;

	uint32_t vni_w1 : 16;
	uint32_t outer_dip_w0 : 16;

	uint32_t resvd7 : 16;
	uint32_t vni_w0 : 16;
#endif
};

struct sssnic_ethdev_fdir_ipv6_flow_key {
#if (RTE_BYTE_ORDER == RTE_BIG_ENDIAN)
	uint32_t resvd0 : 16;
	uint32_t ip_proto : 8;
	uint32_t tunnel_type : 4;
	uint32_t resvd1 : 4;

	uint32_t func_id : 15;
	uint32_t ip_type : 1;
	uint32_t sip6_w0 : 16;

	uint32_t sip6_w1 : 16;
	uint32_t sip6_w2 : 16;

	uint32_t sip6_w3 : 16;
	uint32_t sip6_w4 : 16;

	uint32_t sip6_w5 : 16;
	uint32_t sip6_w6 : 16;

	uint32_t sip6_w7 : 16;
	uint32_t dport : 16;

	uint32_t sport : 16;
	uint32_t dip6_w0 : 16;

	uint32_t dip6_w1 : 16;
	uint32_t dip6_w2 : 16;

	uint32_t dip6_w3 : 16;
	uint32_t dip6_w4 : 16;

	uint32_t dip6_w5 : 16;
	uint32_t dip6_w6 : 16;

	uint32_t dip6_w7 : 16;
	uint32_t resvd2 : 16;
#else
	uint32_t resvd1 : 4;
	uint32_t tunnel_type : 4;
	uint32_t ip_proto : 8;
	uint32_t resvd0 : 16;

	uint32_t sip6_w0 : 16;
	uint32_t ip_type : 1;
	uint32_t func_id : 15;

	uint32_t sip6_w2 : 16;
	uint32_t sip6_w1 : 16;

	uint32_t sip6_w4 : 16;
	uint32_t sip6_w3 : 16;

	uint32_t sip6_w6 : 16;
	uint32_t sip6_w5 : 16;

	uint32_t dport : 16;
	uint32_t sip6_w7 : 16;

	uint32_t dip6_w0 : 16;
	uint32_t sport : 16;

	uint32_t dip6_w2 : 16;
	uint32_t dip6_w1 : 16;

	uint32_t dip6_w4 : 16;
	uint32_t dip6_w3 : 16;

	uint32_t dip6_w6 : 16;
	uint32_t dip6_w5 : 16;

	uint32_t resvd2 : 16;
	uint32_t dip6_w7 : 16;
#endif
};

struct sssnic_ethdev_fdir_vxlan_ipv6_flow_key {
#if (RTE_BYTE_ORDER == RTE_BIG_ENDIAN)
	uint32_t resvd0 : 16;
	uint32_t ip_proto : 8;
	uint32_t tunnel_type : 4;
	uint32_t resvd1 : 4;

	uint32_t func_id : 15;
	uint32_t ip_type : 1;
	uint32_t dip6_w0 : 16;

	uint32_t dip6_w1 : 16;
	uint32_t dip6_w2 : 16;

	uint32_t dip6_w3 : 16;
	uint32_t dip6_w4 : 16;

	uint32_t dip6_w5 : 16;
	uint32_t dip6_w6 : 16;

	uint32_t dip6_w7 : 16;
	uint32_t dport : 16;

	uint32_t sport : 16;
	uint32_t resvd2 : 16;

	uint32_t resvd3 : 16;
	uint32_t outer_sip_w1 : 16;

	uint32_t outer_sip_w0 : 16;
	uint32_t outer_dip_w1 : 16;

	uint32_t outer_dip_w0 : 16;
	uint32_t vni_w1 : 16;

	uint32_t vni_w0 : 16;
	uint32_t resvd4 : 16;
#else
	uint32_t rsvd1 : 4;
	uint32_t tunnel_type : 4;
	uint32_t ip_proto : 8;
	uint32_t resvd0 : 16;

	uint32_t dip6_w0 : 16;
	uint32_t ip_type : 1;
	uint32_t function_id : 15;

	uint32_t dip6_w2 : 16;
	uint32_t dip6_w1 : 16;

	uint32_t dip6_w4 : 16;
	uint32_t dip6_w3 : 16;

	uint32_t dip6_w6 : 16;
	uint32_t dip6_w5 : 16;

	uint32_t dport : 16;
	uint32_t dip6_w7 : 16;

	uint32_t resvd2 : 16;
	uint32_t sport : 16;

	uint32_t outer_sip_w1 : 16;
	uint32_t resvd3 : 16;

	uint32_t outer_dip_w1 : 16;
	uint32_t outer_sip_w0 : 16;

	uint32_t vni_w1 : 16;
	uint32_t outer_dip_w0 : 16;

	uint32_t resvd4 : 16;
	uint32_t vni_w0 : 16;
#endif
};

struct sssnic_ethdev_fdir_flow_key {
	union {
		uint32_t dword[SSSNIC_ETHDEV_FDIR_FLOW_KEY_NUM_DW];
		struct {
			struct sssnic_ethdev_fdir_ipv4_flow_key ipv4;
			struct sssnic_ethdev_fdir_ipv6_flow_key ipv6;
			struct sssnic_ethdev_fdir_vxlan_ipv6_flow_key vxlan_ipv6;
		};
	};
};

struct sssnic_ethdev_fdir_flow_match {
	struct sssnic_ethdev_fdir_flow_key key;
	struct sssnic_ethdev_fdir_flow_key mask;
};

struct sssnic_ethdev_fdir_ethertype_match {
	struct sssnic_ethdev_fdir_ethertype_key key;
};

struct sssnic_ethdev_fdir_match {
	enum sssnic_ethdev_fdir_match_type type;
	union {
		struct sssnic_ethdev_fdir_flow_match flow;
		struct sssnic_ethdev_fdir_ethertype_match ethertype;
	};
};

struct sssnic_ethdev_fdir_action {
	uint16_t qid;
};

/* struct sssnic_ethdev_fdir_rule must be dynamically allocated in the heap */
struct sssnic_ethdev_fdir_rule {
	struct sssnic_ethdev_fdir_match match;
	struct sssnic_ethdev_fdir_action action;
	void *cookie; /* low level data, initial value must be set to  NULL*/
};

struct sssnic_ethdev_fdir_info;

static inline struct sssnic_ethdev_fdir_rule *
sssnic_ethdev_fdir_rule_alloc(void)
{
	struct sssnic_ethdev_fdir_rule *rule;

	rule = rte_zmalloc("sssnic_fdir_rule",
		sizeof(struct sssnic_ethdev_fdir_rule), 0);

	return rule;
}

static inline void
sssnic_ethdev_fdir_rule_free(struct sssnic_ethdev_fdir_rule *rule)
{
	if (rule != NULL)
		rte_free(rule);
}

int sssnic_ethdev_fdir_rules_disable_by_queue(struct rte_eth_dev *ethdev,
	uint16_t qid);
int sssnic_ethdev_fdir_rules_enable_by_queue(struct rte_eth_dev *ethdev,
	uint16_t qid);
int sssnic_ethdev_fdir_rule_add(struct rte_eth_dev *ethdev,
	struct sssnic_ethdev_fdir_rule *rule);
int sssnic_ethdev_fdir_rule_del(struct rte_eth_dev *ethdev,
	struct sssnic_ethdev_fdir_rule *fdir_rule);
int sssnic_ethdev_fdir_rules_flush(struct rte_eth_dev *ethdev);
int sssnic_ethdev_fdir_init(struct rte_eth_dev *ethdev);
void sssnic_ethdev_fdir_shutdown(struct rte_eth_dev *ethdev);

#endif /* _SSSNIC_ETHDEV_FDIR_H_ */
