/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2022 NXP
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_flow_driver.h>
#include <rte_tailq.h>

#include <fsl_dpni.h>
#include <fsl_dpkg.h>

#include <dpaa2_ethdev.h>
#include <dpaa2_pmd_logs.h>

/* Workaround to discriminate the UDP/TCP/SCTP
 * with next protocol of l3.
 * MC/WRIOP are not able to identify
 * the l4 protocol with l4 ports.
 */
static int mc_l4_port_identification;

static char *dpaa2_flow_control_log;
static uint16_t dpaa2_flow_miss_flow_id; /* Default miss flow id is 0. */

enum dpaa2_flow_entry_size {
	DPAA2_FLOW_ENTRY_MIN_SIZE = (DPNI_MAX_KEY_SIZE / 2),
	DPAA2_FLOW_ENTRY_MAX_SIZE = DPNI_MAX_KEY_SIZE
};

enum dpaa2_flow_dist_type {
	DPAA2_FLOW_QOS_TYPE = 1 << 0,
	DPAA2_FLOW_FS_TYPE = 1 << 1
};

#define DPAA2_FLOW_RAW_OFFSET_FIELD_SHIFT	16
#define DPAA2_FLOW_MAX_KEY_SIZE			16

struct dpaa2_dev_flow {
	LIST_ENTRY(dpaa2_dev_flow) next;
	struct dpni_rule_cfg qos_rule;
	uint8_t *qos_key_addr;
	uint8_t *qos_mask_addr;
	uint16_t qos_rule_size;
	struct dpni_rule_cfg fs_rule;
	uint8_t qos_real_key_size;
	uint8_t fs_real_key_size;
	uint8_t *fs_key_addr;
	uint8_t *fs_mask_addr;
	uint16_t fs_rule_size;
	uint8_t tc_id; /** Traffic Class ID. */
	uint8_t tc_index; /** index within this Traffic Class. */
	enum rte_flow_action_type action_type;
	struct dpni_fs_action_cfg fs_action_cfg;
};

static const
enum rte_flow_item_type dpaa2_supported_pattern_type[] = {
	RTE_FLOW_ITEM_TYPE_END,
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_ICMP,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_GRE,
};

static const
enum rte_flow_action_type dpaa2_supported_action_type[] = {
	RTE_FLOW_ACTION_TYPE_END,
	RTE_FLOW_ACTION_TYPE_QUEUE,
	RTE_FLOW_ACTION_TYPE_PORT_ID,
	RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,
	RTE_FLOW_ACTION_TYPE_RSS
};

static const
enum rte_flow_action_type dpaa2_supported_fs_action_type[] = {
	RTE_FLOW_ACTION_TYPE_QUEUE,
	RTE_FLOW_ACTION_TYPE_PORT_ID,
	RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,
};

#ifndef __cplusplus
static const struct rte_flow_item_eth dpaa2_flow_item_eth_mask = {
	.hdr.dst_addr.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.hdr.src_addr.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.hdr.ether_type = RTE_BE16(0xffff),
};

static const struct rte_flow_item_vlan dpaa2_flow_item_vlan_mask = {
	.hdr.vlan_tci = RTE_BE16(0xffff),
};

static const struct rte_flow_item_ipv4 dpaa2_flow_item_ipv4_mask = {
	.hdr.src_addr = RTE_BE32(0xffffffff),
	.hdr.dst_addr = RTE_BE32(0xffffffff),
	.hdr.next_proto_id = 0xff,
};

static const struct rte_flow_item_ipv6 dpaa2_flow_item_ipv6_mask = {
	.hdr = {
		.src_addr =
			"\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff",
		.dst_addr =
			"\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff",
		.proto = 0xff
	},
};

static const struct rte_flow_item_icmp dpaa2_flow_item_icmp_mask = {
	.hdr.icmp_type = 0xff,
	.hdr.icmp_code = 0xff,
};

static const struct rte_flow_item_udp dpaa2_flow_item_udp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};

static const struct rte_flow_item_tcp dpaa2_flow_item_tcp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};

static const struct rte_flow_item_sctp dpaa2_flow_item_sctp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};

static const struct rte_flow_item_gre dpaa2_flow_item_gre_mask = {
	.protocol = RTE_BE16(0xffff),
};
#endif

#define DPAA2_FLOW_DUMP printf

static inline void
dpaa2_prot_field_string(uint32_t prot, uint32_t field,
	char *string)
{
	if (!dpaa2_flow_control_log)
		return;

	if (prot == NET_PROT_ETH) {
		strcpy(string, "eth");
		if (field == NH_FLD_ETH_DA)
			strcat(string, ".dst");
		else if (field == NH_FLD_ETH_SA)
			strcat(string, ".src");
		else if (field == NH_FLD_ETH_TYPE)
			strcat(string, ".type");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_VLAN) {
		strcpy(string, "vlan");
		if (field == NH_FLD_VLAN_TCI)
			strcat(string, ".tci");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_IP) {
		strcpy(string, "ip");
		if (field == NH_FLD_IP_SRC)
			strcat(string, ".src");
		else if (field == NH_FLD_IP_DST)
			strcat(string, ".dst");
		else if (field == NH_FLD_IP_PROTO)
			strcat(string, ".proto");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_TCP) {
		strcpy(string, "tcp");
		if (field == NH_FLD_TCP_PORT_SRC)
			strcat(string, ".src");
		else if (field == NH_FLD_TCP_PORT_DST)
			strcat(string, ".dst");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_UDP) {
		strcpy(string, "udp");
		if (field == NH_FLD_UDP_PORT_SRC)
			strcat(string, ".src");
		else if (field == NH_FLD_UDP_PORT_DST)
			strcat(string, ".dst");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_ICMP) {
		strcpy(string, "icmp");
		if (field == NH_FLD_ICMP_TYPE)
			strcat(string, ".type");
		else if (field == NH_FLD_ICMP_CODE)
			strcat(string, ".code");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_SCTP) {
		strcpy(string, "sctp");
		if (field == NH_FLD_SCTP_PORT_SRC)
			strcat(string, ".src");
		else if (field == NH_FLD_SCTP_PORT_DST)
			strcat(string, ".dst");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_GRE) {
		strcpy(string, "gre");
		if (field == NH_FLD_GRE_TYPE)
			strcat(string, ".type");
		else
			strcat(string, ".unknown field");
	} else {
		strcpy(string, "unknown protocol");
	}
}

static inline void
dpaa2_flow_qos_extracts_log(const struct dpaa2_dev_priv *priv)
{
	int idx;
	char string[32];
	const struct dpkg_profile_cfg *dpkg =
		&priv->extract.qos_key_extract.dpkg;
	const struct dpkg_extract *extract;
	enum dpkg_extract_type type;
	enum net_prot prot;
	uint32_t field;

	if (!dpaa2_flow_control_log)
		return;

	DPAA2_FLOW_DUMP("QoS table: %d extracts\r\n",
		dpkg->num_extracts);
	for (idx = 0; idx < dpkg->num_extracts; idx++) {
		extract = &dpkg->extracts[idx];
		type = extract->type;
		if (type == DPKG_EXTRACT_FROM_HDR) {
			prot = extract->extract.from_hdr.prot;
			field = extract->extract.from_hdr.field;
			dpaa2_prot_field_string(prot, field,
				string);
		} else if (type == DPKG_EXTRACT_FROM_DATA) {
			sprintf(string, "raw offset/len: %d/%d",
				extract->extract.from_data.offset,
				extract->extract.from_data.size);
		}
		DPAA2_FLOW_DUMP("%s", string);
		if ((idx + 1) < dpkg->num_extracts)
			DPAA2_FLOW_DUMP(" / ");
	}
	DPAA2_FLOW_DUMP("\r\n");
}

static inline void
dpaa2_flow_fs_extracts_log(const struct dpaa2_dev_priv *priv,
	int tc_id)
{
	int idx;
	char string[32];
	const struct dpkg_profile_cfg *dpkg =
		&priv->extract.tc_key_extract[tc_id].dpkg;
	const struct dpkg_extract *extract;
	enum dpkg_extract_type type;
	enum net_prot prot;
	uint32_t field;

	if (!dpaa2_flow_control_log)
		return;

	DPAA2_FLOW_DUMP("FS table: %d extracts in TC[%d]\r\n",
		dpkg->num_extracts, tc_id);
	for (idx = 0; idx < dpkg->num_extracts; idx++) {
		extract = &dpkg->extracts[idx];
		type = extract->type;
		if (type == DPKG_EXTRACT_FROM_HDR) {
			prot = extract->extract.from_hdr.prot;
			field = extract->extract.from_hdr.field;
			dpaa2_prot_field_string(prot, field,
				string);
		} else if (type == DPKG_EXTRACT_FROM_DATA) {
			sprintf(string, "raw offset/len: %d/%d",
				extract->extract.from_data.offset,
				extract->extract.from_data.size);
		}
		DPAA2_FLOW_DUMP("%s", string);
		if ((idx + 1) < dpkg->num_extracts)
			DPAA2_FLOW_DUMP(" / ");
	}
	DPAA2_FLOW_DUMP("\r\n");
}

static inline void
dpaa2_flow_qos_entry_log(const char *log_info,
	const struct dpaa2_dev_flow *flow, int qos_index)
{
	int idx;
	uint8_t *key, *mask;

	if (!dpaa2_flow_control_log)
		return;

	if (qos_index >= 0) {
		DPAA2_FLOW_DUMP("%s QoS entry[%d](size %d/%d) for TC[%d]\r\n",
			log_info, qos_index, flow->qos_rule_size,
			flow->qos_rule.key_size,
			flow->tc_id);
	} else {
		DPAA2_FLOW_DUMP("%s QoS entry(size %d/%d) for TC[%d]\r\n",
			log_info, flow->qos_rule_size,
			flow->qos_rule.key_size,
			flow->tc_id);
	}

	key = flow->qos_key_addr;
	mask = flow->qos_mask_addr;

	DPAA2_FLOW_DUMP("key:\r\n");
	for (idx = 0; idx < flow->qos_rule_size; idx++)
		DPAA2_FLOW_DUMP("%02x ", key[idx]);

	DPAA2_FLOW_DUMP("\r\nmask:\r\n");
	for (idx = 0; idx < flow->qos_rule_size; idx++)
		DPAA2_FLOW_DUMP("%02x ", mask[idx]);
	DPAA2_FLOW_DUMP("\r\n");
}

static inline void
dpaa2_flow_fs_entry_log(const char *log_info,
	const struct dpaa2_dev_flow *flow)
{
	int idx;
	uint8_t *key, *mask;

	if (!dpaa2_flow_control_log)
		return;

	DPAA2_FLOW_DUMP("%s FS/TC entry[%d](size %d/%d) of TC[%d]\r\n",
		log_info, flow->tc_index,
		flow->fs_rule_size, flow->fs_rule.key_size,
		flow->tc_id);

	key = flow->fs_key_addr;
	mask = flow->fs_mask_addr;

	DPAA2_FLOW_DUMP("key:\r\n");
	for (idx = 0; idx < flow->fs_rule_size; idx++)
		DPAA2_FLOW_DUMP("%02x ", key[idx]);

	DPAA2_FLOW_DUMP("\r\nmask:\r\n");
	for (idx = 0; idx < flow->fs_rule_size; idx++)
		DPAA2_FLOW_DUMP("%02x ", mask[idx]);
	DPAA2_FLOW_DUMP("\r\n");
}

static int
dpaa2_flow_ip_address_extract(enum net_prot prot,
	uint32_t field)
{
	if (prot == NET_PROT_IPV4 &&
		(field == NH_FLD_IPV4_SRC_IP ||
		field == NH_FLD_IPV4_DST_IP))
		return true;
	else if (prot == NET_PROT_IPV6 &&
		(field == NH_FLD_IPV6_SRC_IP ||
		field == NH_FLD_IPV6_DST_IP))
		return true;
	else if (prot == NET_PROT_IP &&
		(field == NH_FLD_IP_SRC ||
		field == NH_FLD_IP_DST))
		return true;

	return false;
}

static int
dpaa2_flow_l4_src_port_extract(enum net_prot prot,
	uint32_t field)
{
	if (prot == NET_PROT_TCP &&
		field == NH_FLD_TCP_PORT_SRC)
		return true;
	else if (prot == NET_PROT_UDP &&
		field == NH_FLD_UDP_PORT_SRC)
		return true;
	else if (prot == NET_PROT_SCTP &&
		field == NH_FLD_SCTP_PORT_SRC)
		return true;

	return false;
}

static int
dpaa2_flow_l4_dst_port_extract(enum net_prot prot,
	uint32_t field)
{
	if (prot == NET_PROT_TCP &&
		field == NH_FLD_TCP_PORT_DST)
		return true;
	else if (prot == NET_PROT_UDP &&
		field == NH_FLD_UDP_PORT_DST)
		return true;
	else if (prot == NET_PROT_SCTP &&
		field == NH_FLD_SCTP_PORT_DST)
		return true;

	return false;
}

static int
dpaa2_flow_add_qos_rule(struct dpaa2_dev_priv *priv,
	struct dpaa2_dev_flow *flow)
{
	uint16_t qos_index;
	int ret;
	struct fsl_mc_io *dpni = priv->hw;

	if (priv->num_rx_tc <= 1 &&
		flow->action_type != RTE_FLOW_ACTION_TYPE_RSS) {
		DPAA2_PMD_WARN("No QoS Table for FS");
		return -EINVAL;
	}

	/* QoS entry added is only effective for multiple TCs.*/
	qos_index = flow->tc_id * priv->fs_entries + flow->tc_index;
	if (qos_index >= priv->qos_entries) {
		DPAA2_PMD_ERR("QoS table full(%d >= %d)",
			qos_index, priv->qos_entries);
		return -EINVAL;
	}

	dpaa2_flow_qos_entry_log("Start add", flow, qos_index);

	ret = dpni_add_qos_entry(dpni, CMD_PRI_LOW,
			priv->token, &flow->qos_rule,
			flow->tc_id, qos_index,
			0, 0);
	if (ret < 0) {
		DPAA2_PMD_ERR("Add entry(%d) to table(%d) failed",
			qos_index, flow->tc_id);
		return ret;
	}

	return 0;
}

static int
dpaa2_flow_add_fs_rule(struct dpaa2_dev_priv *priv,
	struct dpaa2_dev_flow *flow)
{
	int ret;
	struct fsl_mc_io *dpni = priv->hw;

	if (flow->tc_index >= priv->fs_entries) {
		DPAA2_PMD_ERR("FS table full(%d >= %d)",
			flow->tc_index, priv->fs_entries);
		return -EINVAL;
	}

	dpaa2_flow_fs_entry_log("Start add", flow);

	ret = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
			priv->token, flow->tc_id,
			flow->tc_index, &flow->fs_rule,
			&flow->fs_action_cfg);
	if (ret < 0) {
		DPAA2_PMD_ERR("Add rule(%d) to FS table(%d) failed",
			flow->tc_index, flow->tc_id);
		return ret;
	}

	return 0;
}

static int
dpaa2_flow_rule_insert_hole(struct dpaa2_dev_flow *flow,
	int offset, int size,
	enum dpaa2_flow_dist_type dist_type)
{
	int end;

	if (dist_type & DPAA2_FLOW_QOS_TYPE) {
		end = flow->qos_rule_size;
		if (end > offset) {
			memmove(flow->qos_key_addr + offset + size,
					flow->qos_key_addr + offset,
					end - offset);
			memset(flow->qos_key_addr + offset,
					0, size);

			memmove(flow->qos_mask_addr + offset + size,
					flow->qos_mask_addr + offset,
					end - offset);
			memset(flow->qos_mask_addr + offset,
					0, size);
		}
		flow->qos_rule_size += size;
	}

	if (dist_type & DPAA2_FLOW_FS_TYPE) {
		end = flow->fs_rule_size;
		if (end > offset) {
			memmove(flow->fs_key_addr + offset + size,
					flow->fs_key_addr + offset,
					end - offset);
			memset(flow->fs_key_addr + offset,
					0, size);

			memmove(flow->fs_mask_addr + offset + size,
					flow->fs_mask_addr + offset,
					end - offset);
			memset(flow->fs_mask_addr + offset,
					0, size);
		}
		flow->fs_rule_size += size;
	}

	return 0;
}

static int
dpaa2_flow_rule_add_all(struct dpaa2_dev_priv *priv,
	enum dpaa2_flow_dist_type dist_type,
	uint16_t entry_size, uint8_t tc_id)
{
	struct dpaa2_dev_flow *curr = LIST_FIRST(&priv->flows);
	int ret;

	while (curr) {
		if (dist_type & DPAA2_FLOW_QOS_TYPE) {
			if (priv->num_rx_tc > 1 ||
				curr->action_type ==
				RTE_FLOW_ACTION_TYPE_RSS) {
				curr->qos_rule.key_size = entry_size;
				ret = dpaa2_flow_add_qos_rule(priv, curr);
				if (ret)
					return ret;
			}
		}
		if (dist_type & DPAA2_FLOW_FS_TYPE &&
			curr->tc_id == tc_id) {
			curr->fs_rule.key_size = entry_size;
			ret = dpaa2_flow_add_fs_rule(priv, curr);
			if (ret)
				return ret;
		}
		curr = LIST_NEXT(curr, next);
	}

	return 0;
}

static int
dpaa2_flow_qos_rule_insert_hole(struct dpaa2_dev_priv *priv,
	int offset, int size)
{
	struct dpaa2_dev_flow *curr;
	int ret;

	curr = priv->curr;
	if (!curr) {
		DPAA2_PMD_ERR("Current qos flow insert hole failed.");
		return -EINVAL;
	} else {
		ret = dpaa2_flow_rule_insert_hole(curr, offset, size,
				DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;
	}

	curr = LIST_FIRST(&priv->flows);
	while (curr) {
		ret = dpaa2_flow_rule_insert_hole(curr, offset, size,
				DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;
		curr = LIST_NEXT(curr, next);
	}

	return 0;
}

static int
dpaa2_flow_fs_rule_insert_hole(struct dpaa2_dev_priv *priv,
	int offset, int size, int tc_id)
{
	struct dpaa2_dev_flow *curr;
	int ret;

	curr = priv->curr;
	if (!curr || curr->tc_id != tc_id) {
		DPAA2_PMD_ERR("Current flow insert hole failed.");
		return -EINVAL;
	} else {
		ret = dpaa2_flow_rule_insert_hole(curr, offset, size,
				DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	curr = LIST_FIRST(&priv->flows);

	while (curr) {
		if (curr->tc_id != tc_id) {
			curr = LIST_NEXT(curr, next);
			continue;
		}
		ret = dpaa2_flow_rule_insert_hole(curr, offset, size,
				DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
		curr = LIST_NEXT(curr, next);
	}

	return 0;
}

/* Move IPv4/IPv6 addresses to fill new extract previous IP address.
 * Current MC/WRIOP only support generic IP extract but IP address
 * is not fixed, so we have to put them at end of extracts, otherwise,
 * the extracts position following them can't be identified.
 */
static int
dpaa2_flow_key_profile_advance(enum net_prot prot,
	uint32_t field, uint8_t field_size,
	struct dpaa2_dev_priv *priv,
	enum dpaa2_flow_dist_type dist_type, int tc_id,
	int *insert_offset)
{
	int offset, ret;
	struct dpaa2_key_profile *key_profile;
	int num, pos;

	if (dpaa2_flow_ip_address_extract(prot, field)) {
		DPAA2_PMD_ERR("%s only for none IP address extract",
			__func__);
		return -EINVAL;
	}

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_profile = &priv->extract.qos_key_extract.key_profile;
	else
		key_profile = &priv->extract.tc_key_extract[tc_id].key_profile;

	num = key_profile->num;

	if (num >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	if (key_profile->ip_addr_type != IP_NONE_ADDR_EXTRACT) {
		offset = key_profile->ip_addr_extract_off;
		pos = key_profile->ip_addr_extract_pos;
		key_profile->ip_addr_extract_pos++;
		key_profile->ip_addr_extract_off += field_size;
		if (dist_type == DPAA2_FLOW_QOS_TYPE) {
			ret = dpaa2_flow_qos_rule_insert_hole(priv,
					offset, field_size);
		} else {
			ret = dpaa2_flow_fs_rule_insert_hole(priv,
				offset, field_size, tc_id);
		}
		if (ret)
			return ret;
	} else {
		pos = num;
	}

	if (pos > 0) {
		key_profile->key_offset[pos] =
			key_profile->key_offset[pos - 1] +
			key_profile->key_size[pos - 1];
	} else {
		key_profile->key_offset[pos] = 0;
	}

	key_profile->key_size[pos] = field_size;
	key_profile->prot_field[pos].prot = prot;
	key_profile->prot_field[pos].key_field = field;
	key_profile->num++;

	if (insert_offset)
		*insert_offset = key_profile->key_offset[pos];

	if (dpaa2_flow_l4_src_port_extract(prot, field)) {
		key_profile->l4_src_port_present = 1;
		key_profile->l4_src_port_pos = pos;
		key_profile->l4_src_port_offset =
			key_profile->key_offset[pos];
	} else if (dpaa2_flow_l4_dst_port_extract(prot, field)) {
		key_profile->l4_dst_port_present = 1;
		key_profile->l4_dst_port_pos = pos;
		key_profile->l4_dst_port_offset =
			key_profile->key_offset[pos];
	}
	key_profile->key_max_size += field_size;

	return pos;
}

static int
dpaa2_flow_extract_add_hdr(enum net_prot prot,
	uint32_t field, uint8_t field_size,
	struct dpaa2_dev_priv *priv,
	enum dpaa2_flow_dist_type dist_type, int tc_id,
	int *insert_offset)
{
	int pos, i;
	struct dpaa2_key_extract *key_extract;
	struct dpkg_profile_cfg *dpkg;
	struct dpkg_extract *extracts;

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[tc_id];

	dpkg = &key_extract->dpkg;
	extracts = dpkg->extracts;

	if (dpaa2_flow_ip_address_extract(prot, field)) {
		DPAA2_PMD_ERR("%s only for none IP address extract",
			__func__);
		return -EINVAL;
	}

	if (dpkg->num_extracts >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	pos = dpaa2_flow_key_profile_advance(prot,
			field, field_size, priv,
			dist_type, tc_id,
			insert_offset);
	if (pos < 0)
		return pos;

	if (pos != dpkg->num_extracts) {
		/* Not the last pos, must have IP address extract.*/
		for (i = dpkg->num_extracts - 1; i >= pos; i--) {
			memcpy(&extracts[i + 1],
				&extracts[i], sizeof(struct dpkg_extract));
		}
	}

	extracts[pos].type = DPKG_EXTRACT_FROM_HDR;
	extracts[pos].extract.from_hdr.prot = prot;
	extracts[pos].extract.from_hdr.type = DPKG_FULL_FIELD;
	extracts[pos].extract.from_hdr.field = field;

	dpkg->num_extracts++;

	return 0;
}

static int
dpaa2_flow_extract_add_raw(struct dpaa2_key_extract *key_extract,
	int size)
{
	struct dpkg_profile_cfg *dpkg = &key_extract->dpkg;
	struct dpaa2_key_profile *key_info = &key_extract->key_profile;
	int last_extract_size, index;

	if (dpkg->num_extracts != 0 && dpkg->extracts[0].type !=
	    DPKG_EXTRACT_FROM_DATA) {
		DPAA2_PMD_WARN("RAW extract cannot be combined with others");
		return -1;
	}

	last_extract_size = (size % DPAA2_FLOW_MAX_KEY_SIZE);
	dpkg->num_extracts = (size / DPAA2_FLOW_MAX_KEY_SIZE);
	if (last_extract_size)
		dpkg->num_extracts++;
	else
		last_extract_size = DPAA2_FLOW_MAX_KEY_SIZE;

	for (index = 0; index < dpkg->num_extracts; index++) {
		dpkg->extracts[index].type = DPKG_EXTRACT_FROM_DATA;
		if (index == dpkg->num_extracts - 1)
			dpkg->extracts[index].extract.from_data.size =
				last_extract_size;
		else
			dpkg->extracts[index].extract.from_data.size =
				DPAA2_FLOW_MAX_KEY_SIZE;
		dpkg->extracts[index].extract.from_data.offset =
			DPAA2_FLOW_MAX_KEY_SIZE * index;
	}

	key_info->key_max_size = size;
	return 0;
}

static inline int
dpaa2_flow_extract_search(struct dpaa2_key_profile *key_profile,
	enum net_prot prot, uint32_t key_field)
{
	int pos;
	struct key_prot_field *prot_field;

	if (dpaa2_flow_ip_address_extract(prot, key_field)) {
		DPAA2_PMD_ERR("%s only for none IP address extract",
			__func__);
		return -EINVAL;
	}

	prot_field = key_profile->prot_field;
	for (pos = 0; pos < key_profile->num; pos++) {
		if (prot_field[pos].prot == prot &&
			prot_field[pos].key_field == key_field) {
			return pos;
		}
	}

	if (dpaa2_flow_l4_src_port_extract(prot, key_field)) {
		if (key_profile->l4_src_port_present)
			return key_profile->l4_src_port_pos;
	} else if (dpaa2_flow_l4_dst_port_extract(prot, key_field)) {
		if (key_profile->l4_dst_port_present)
			return key_profile->l4_dst_port_pos;
	}

	return -ENXIO;
}

static inline int
dpaa2_flow_extract_key_offset(struct dpaa2_key_profile *key_profile,
	enum net_prot prot, uint32_t key_field)
{
	int i;

	i = dpaa2_flow_extract_search(key_profile, prot, key_field);

	if (i >= 0)
		return key_profile->key_offset[i];
	else
		return i;
}

struct prev_proto_field_id {
	enum net_prot prot;
	union {
		rte_be16_t eth_type;
		uint8_t ip_proto;
	};
};

static int
dpaa2_flow_prev_proto_rule(struct dpaa2_dev_priv *priv,
	struct dpaa2_dev_flow *flow,
	const struct prev_proto_field_id *prev_proto,
	int group,
	enum dpaa2_flow_dist_type dist_type)
{
	int offset;
	uint8_t *key_addr;
	uint8_t *mask_addr;
	uint32_t field = 0;
	rte_be16_t eth_type;
	uint8_t ip_proto;
	struct dpaa2_key_extract *key_extract;
	struct dpaa2_key_profile *key_profile;

	if (prev_proto->prot == NET_PROT_ETH) {
		field = NH_FLD_ETH_TYPE;
	} else if (prev_proto->prot == NET_PROT_IP) {
		field = NH_FLD_IP_PROTO;
	} else {
		DPAA2_PMD_ERR("Prev proto(%d) not support!",
			prev_proto->prot);
		return -EINVAL;
	}

	if (dist_type & DPAA2_FLOW_QOS_TYPE) {
		key_extract = &priv->extract.qos_key_extract;
		key_profile = &key_extract->key_profile;

		offset = dpaa2_flow_extract_key_offset(key_profile,
				prev_proto->prot, field);
		if (offset < 0) {
			DPAA2_PMD_ERR("%s QoS key extract failed", __func__);
			return -EINVAL;
		}
		key_addr = flow->qos_key_addr + offset;
		mask_addr = flow->qos_mask_addr + offset;
		if (prev_proto->prot == NET_PROT_ETH) {
			eth_type = prev_proto->eth_type;
			memcpy(key_addr, &eth_type, sizeof(rte_be16_t));
			eth_type = 0xffff;
			memcpy(mask_addr, &eth_type, sizeof(rte_be16_t));
			flow->qos_rule_size += sizeof(rte_be16_t);
		} else if (prev_proto->prot == NET_PROT_IP) {
			ip_proto = prev_proto->ip_proto;
			memcpy(key_addr, &ip_proto, sizeof(uint8_t));
			ip_proto = 0xff;
			memcpy(mask_addr, &ip_proto, sizeof(uint8_t));
			flow->qos_rule_size += sizeof(uint8_t);
		} else {
			DPAA2_PMD_ERR("Invalid Prev proto(%d)",
				prev_proto->prot);
			return -EINVAL;
		}
	}

	if (dist_type & DPAA2_FLOW_FS_TYPE) {
		key_extract = &priv->extract.tc_key_extract[group];
		key_profile = &key_extract->key_profile;

		offset = dpaa2_flow_extract_key_offset(key_profile,
				prev_proto->prot, field);
		if (offset < 0) {
			DPAA2_PMD_ERR("%s TC[%d] key extract failed",
				__func__, group);
			return -EINVAL;
		}
		key_addr = flow->fs_key_addr + offset;
		mask_addr = flow->fs_mask_addr + offset;

		if (prev_proto->prot == NET_PROT_ETH) {
			eth_type = prev_proto->eth_type;
			memcpy(key_addr, &eth_type, sizeof(rte_be16_t));
			eth_type = 0xffff;
			memcpy(mask_addr, &eth_type, sizeof(rte_be16_t));
			flow->fs_rule_size += sizeof(rte_be16_t);
		} else if (prev_proto->prot == NET_PROT_IP) {
			ip_proto = prev_proto->ip_proto;
			memcpy(key_addr, &ip_proto, sizeof(uint8_t));
			ip_proto = 0xff;
			memcpy(mask_addr, &ip_proto, sizeof(uint8_t));
			flow->fs_rule_size += sizeof(uint8_t);
		} else {
			DPAA2_PMD_ERR("Invalid Prev proto(%d)",
				prev_proto->prot);
			return -EINVAL;
		}
	}

	return 0;
}

static inline int
dpaa2_flow_hdr_rule_data_set(struct dpaa2_dev_flow *flow,
	struct dpaa2_key_profile *key_profile,
	enum net_prot prot, uint32_t field, int size,
	const void *key, const void *mask,
	enum dpaa2_flow_dist_type dist_type)
{
	int offset;

	if (dpaa2_flow_ip_address_extract(prot, field)) {
		DPAA2_PMD_ERR("%s only for none IP address extract",
			__func__);
		return -EINVAL;
	}

	offset = dpaa2_flow_extract_key_offset(key_profile,
			prot, field);
	if (offset < 0) {
		DPAA2_PMD_ERR("P(%d)/F(%d) does not exist!",
			prot, field);
		return -EINVAL;
	}

	if (dist_type & DPAA2_FLOW_QOS_TYPE) {
		memcpy((flow->qos_key_addr + offset), key, size);
		memcpy((flow->qos_mask_addr + offset), mask, size);
		if (key_profile->ip_addr_type == IP_NONE_ADDR_EXTRACT)
			flow->qos_rule_size = offset + size;
	}

	if (dist_type & DPAA2_FLOW_FS_TYPE) {
		memcpy((flow->fs_key_addr + offset), key, size);
		memcpy((flow->fs_mask_addr + offset), mask, size);
		if (key_profile->ip_addr_type == IP_NONE_ADDR_EXTRACT)
			flow->fs_rule_size = offset + size;
	}

	return 0;
}

static inline int
dpaa2_flow_rule_data_set_raw(struct dpni_rule_cfg *rule,
			     const void *key, const void *mask, int size)
{
	int offset = 0;

	memcpy((void *)(size_t)(rule->key_iova + offset), key, size);
	memcpy((void *)(size_t)(rule->mask_iova + offset), mask, size);

	return 0;
}

static int
dpaa2_flow_extract_support(const uint8_t *mask_src,
	enum rte_flow_item_type type)
{
	char mask[64];
	int i, size = 0;
	const char *mask_support = 0;

	switch (type) {
	case RTE_FLOW_ITEM_TYPE_ETH:
		mask_support = (const char *)&dpaa2_flow_item_eth_mask;
		size = sizeof(struct rte_flow_item_eth);
		break;
	case RTE_FLOW_ITEM_TYPE_VLAN:
		mask_support = (const char *)&dpaa2_flow_item_vlan_mask;
		size = sizeof(struct rte_flow_item_vlan);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV4:
		mask_support = (const char *)&dpaa2_flow_item_ipv4_mask;
		size = sizeof(struct rte_flow_item_ipv4);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6:
		mask_support = (const char *)&dpaa2_flow_item_ipv6_mask;
		size = sizeof(struct rte_flow_item_ipv6);
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP:
		mask_support = (const char *)&dpaa2_flow_item_icmp_mask;
		size = sizeof(struct rte_flow_item_icmp);
		break;
	case RTE_FLOW_ITEM_TYPE_UDP:
		mask_support = (const char *)&dpaa2_flow_item_udp_mask;
		size = sizeof(struct rte_flow_item_udp);
		break;
	case RTE_FLOW_ITEM_TYPE_TCP:
		mask_support = (const char *)&dpaa2_flow_item_tcp_mask;
		size = sizeof(struct rte_flow_item_tcp);
		break;
	case RTE_FLOW_ITEM_TYPE_SCTP:
		mask_support = (const char *)&dpaa2_flow_item_sctp_mask;
		size = sizeof(struct rte_flow_item_sctp);
		break;
	case RTE_FLOW_ITEM_TYPE_GRE:
		mask_support = (const char *)&dpaa2_flow_item_gre_mask;
		size = sizeof(struct rte_flow_item_gre);
		break;
	default:
		return -EINVAL;
	}

	memcpy(mask, mask_support, size);

	for (i = 0; i < size; i++)
		mask[i] = (mask[i] | mask_src[i]);

	if (memcmp(mask, mask_support, size))
		return -1;

	return 0;
}

static int
dpaa2_flow_identify_by_prev_prot(struct dpaa2_dev_priv *priv,
	struct dpaa2_dev_flow *flow,
	const struct prev_proto_field_id *prev_prot,
	enum dpaa2_flow_dist_type dist_type,
	int group, int *recfg)
{
	int ret, index, local_cfg = 0, size = 0;
	struct dpaa2_key_extract *extract;
	struct dpaa2_key_profile *key_profile;
	enum net_prot prot = prev_prot->prot;
	uint32_t key_field = 0;

	if (prot == NET_PROT_ETH) {
		key_field = NH_FLD_ETH_TYPE;
		size = sizeof(rte_be16_t);
	} else if (prot == NET_PROT_IP) {
		key_field = NH_FLD_IP_PROTO;
		size = sizeof(uint8_t);
	} else if (prot == NET_PROT_IPV4) {
		prot = NET_PROT_IP;
		key_field = NH_FLD_IP_PROTO;
		size = sizeof(uint8_t);
	} else if (prot == NET_PROT_IPV6) {
		prot = NET_PROT_IP;
		key_field = NH_FLD_IP_PROTO;
		size = sizeof(uint8_t);
	} else {
		DPAA2_PMD_ERR("Invalid Prev prot(%d)", prot);
		return -EINVAL;
	}

	if (dist_type & DPAA2_FLOW_QOS_TYPE) {
		extract = &priv->extract.qos_key_extract;
		key_profile = &extract->key_profile;

		index = dpaa2_flow_extract_search(key_profile,
				prot, key_field);
		if (index < 0) {
			ret = dpaa2_flow_extract_add_hdr(prot,
					key_field, size, priv,
					DPAA2_FLOW_QOS_TYPE, group,
					NULL);
			if (ret) {
				DPAA2_PMD_ERR("QOS prev extract add failed");

				return -EINVAL;
			}
			local_cfg |= DPAA2_FLOW_QOS_TYPE;
		}

		ret = dpaa2_flow_prev_proto_rule(priv, flow, prev_prot, group,
				DPAA2_FLOW_QOS_TYPE);
		if (ret) {
			DPAA2_PMD_ERR("QoS prev rule set failed");
			return -EINVAL;
		}
	}

	if (dist_type & DPAA2_FLOW_FS_TYPE) {
		extract = &priv->extract.tc_key_extract[group];
		key_profile = &extract->key_profile;

		index = dpaa2_flow_extract_search(key_profile,
				prot, key_field);
		if (index < 0) {
			ret = dpaa2_flow_extract_add_hdr(prot,
					key_field, size, priv,
					DPAA2_FLOW_FS_TYPE, group,
					NULL);
			if (ret) {
				DPAA2_PMD_ERR("FS[%d] prev extract add failed",
					group);

				return -EINVAL;
			}
			local_cfg |= DPAA2_FLOW_FS_TYPE;
		}

		ret = dpaa2_flow_prev_proto_rule(priv, flow, prev_prot, group,
				DPAA2_FLOW_FS_TYPE);
		if (ret) {
			DPAA2_PMD_ERR("FS[%d] prev rule set failed",
				group);
			return -EINVAL;
		}
	}

	if (recfg)
		*recfg = local_cfg;

	return 0;
}

static int
dpaa2_flow_add_hdr_extract_rule(struct dpaa2_dev_flow *flow,
	enum net_prot prot, uint32_t field,
	const void *key, const void *mask, int size,
	struct dpaa2_dev_priv *priv, int tc_id, int *recfg,
	enum dpaa2_flow_dist_type dist_type)
{
	int index, ret, local_cfg = 0;
	struct dpaa2_key_extract *key_extract;
	struct dpaa2_key_profile *key_profile;

	if (dpaa2_flow_ip_address_extract(prot, field))
		return -EINVAL;

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[tc_id];

	key_profile = &key_extract->key_profile;

	index = dpaa2_flow_extract_search(key_profile,
			prot, field);
	if (index < 0) {
		ret = dpaa2_flow_extract_add_hdr(prot,
				field, size, priv,
				dist_type, tc_id, NULL);
		if (ret) {
			DPAA2_PMD_ERR("QoS Extract P(%d)/F(%d) failed",
				prot, field);

			return ret;
		}
		local_cfg |= dist_type;
	}

	ret = dpaa2_flow_hdr_rule_data_set(flow, key_profile,
			prot, field, size, key, mask, dist_type);
	if (ret) {
		DPAA2_PMD_ERR("QoS P(%d)/F(%d) rule data set failed",
			prot, field);

		return ret;
	}

	if (recfg)
		*recfg |= local_cfg;

	return 0;
}

static int
dpaa2_flow_add_ipaddr_extract_rule(struct dpaa2_dev_flow *flow,
	enum net_prot prot, uint32_t field,
	const void *key, const void *mask, int size,
	struct dpaa2_dev_priv *priv, int tc_id, int *recfg,
	enum dpaa2_flow_dist_type dist_type)
{
	int local_cfg = 0, num, ipaddr_extract_len = 0;
	struct dpaa2_key_extract *key_extract;
	struct dpaa2_key_profile *key_profile;
	struct dpkg_profile_cfg *dpkg;
	uint8_t *key_addr, *mask_addr;
	union ip_addr_extract_rule *ip_addr_data;
	union ip_addr_extract_rule *ip_addr_mask;
	enum net_prot orig_prot;
	uint32_t orig_field;

	if (prot != NET_PROT_IPV4 && prot != NET_PROT_IPV6)
		return -EINVAL;

	if (prot == NET_PROT_IPV4 && field != NH_FLD_IPV4_SRC_IP &&
		field != NH_FLD_IPV4_DST_IP) {
		return -EINVAL;
	}

	if (prot == NET_PROT_IPV6 && field != NH_FLD_IPV6_SRC_IP &&
		field != NH_FLD_IPV6_DST_IP) {
		return -EINVAL;
	}

	orig_prot = prot;
	orig_field = field;

	if (prot == NET_PROT_IPV4 &&
		field == NH_FLD_IPV4_SRC_IP) {
		prot = NET_PROT_IP;
		field = NH_FLD_IP_SRC;
	} else if (prot == NET_PROT_IPV4 &&
		field == NH_FLD_IPV4_DST_IP) {
		prot = NET_PROT_IP;
		field = NH_FLD_IP_DST;
	} else if (prot == NET_PROT_IPV6 &&
		field == NH_FLD_IPV6_SRC_IP) {
		prot = NET_PROT_IP;
		field = NH_FLD_IP_SRC;
	} else if (prot == NET_PROT_IPV6 &&
		field == NH_FLD_IPV6_DST_IP) {
		prot = NET_PROT_IP;
		field = NH_FLD_IP_DST;
	} else {
		DPAA2_PMD_ERR("Inval P(%d)/F(%d) to extract ip address",
			prot, field);
		return -EINVAL;
	}

	if (dist_type == DPAA2_FLOW_QOS_TYPE) {
		key_extract = &priv->extract.qos_key_extract;
		key_profile = &key_extract->key_profile;
		dpkg = &key_extract->dpkg;
		num = key_profile->num;
		key_addr = flow->qos_key_addr;
		mask_addr = flow->qos_mask_addr;
	} else {
		key_extract = &priv->extract.tc_key_extract[tc_id];
		key_profile = &key_extract->key_profile;
		dpkg = &key_extract->dpkg;
		num = key_profile->num;
		key_addr = flow->fs_key_addr;
		mask_addr = flow->fs_mask_addr;
	}

	if (num >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	if (key_profile->ip_addr_type == IP_NONE_ADDR_EXTRACT) {
		if (field == NH_FLD_IP_SRC)
			key_profile->ip_addr_type = IP_SRC_EXTRACT;
		else
			key_profile->ip_addr_type = IP_DST_EXTRACT;
		ipaddr_extract_len = size;

		key_profile->ip_addr_extract_pos = num;
		if (num > 0) {
			key_profile->ip_addr_extract_off =
				key_profile->key_offset[num - 1] +
				key_profile->key_size[num - 1];
		} else {
			key_profile->ip_addr_extract_off = 0;
		}
		key_profile->key_max_size += NH_FLD_IPV6_ADDR_SIZE;
	} else if (key_profile->ip_addr_type == IP_SRC_EXTRACT) {
		if (field == NH_FLD_IP_SRC) {
			ipaddr_extract_len = size;
			goto rule_configure;
		}
		key_profile->ip_addr_type = IP_SRC_DST_EXTRACT;
		ipaddr_extract_len = size * 2;
		key_profile->key_max_size += NH_FLD_IPV6_ADDR_SIZE;
	} else if (key_profile->ip_addr_type == IP_DST_EXTRACT) {
		if (field == NH_FLD_IP_DST) {
			ipaddr_extract_len = size;
			goto rule_configure;
		}
		key_profile->ip_addr_type = IP_DST_SRC_EXTRACT;
		ipaddr_extract_len = size * 2;
		key_profile->key_max_size += NH_FLD_IPV6_ADDR_SIZE;
	}
	key_profile->num++;

	dpkg->extracts[num].extract.from_hdr.prot = prot;
	dpkg->extracts[num].extract.from_hdr.field = field;
	dpkg->extracts[num].extract.from_hdr.type = DPKG_FULL_FIELD;
	dpkg->num_extracts++;

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		local_cfg = DPAA2_FLOW_QOS_TYPE;
	else
		local_cfg = DPAA2_FLOW_FS_TYPE;

rule_configure:
	key_addr += key_profile->ip_addr_extract_off;
	ip_addr_data = (union ip_addr_extract_rule *)key_addr;
	mask_addr += key_profile->ip_addr_extract_off;
	ip_addr_mask = (union ip_addr_extract_rule *)mask_addr;

	if (orig_prot == NET_PROT_IPV4 &&
		orig_field == NH_FLD_IPV4_SRC_IP) {
		if (key_profile->ip_addr_type == IP_SRC_EXTRACT ||
			key_profile->ip_addr_type == IP_SRC_DST_EXTRACT) {
			memcpy(&ip_addr_data->ipv4_sd_addr.ipv4_src,
				key, size);
			memcpy(&ip_addr_mask->ipv4_sd_addr.ipv4_src,
				mask, size);
		} else {
			memcpy(&ip_addr_data->ipv4_ds_addr.ipv4_src,
				key, size);
			memcpy(&ip_addr_mask->ipv4_ds_addr.ipv4_src,
				mask, size);
		}
	} else if (orig_prot == NET_PROT_IPV4 &&
		orig_field == NH_FLD_IPV4_DST_IP) {
		if (key_profile->ip_addr_type == IP_DST_EXTRACT ||
			key_profile->ip_addr_type == IP_DST_SRC_EXTRACT) {
			memcpy(&ip_addr_data->ipv4_ds_addr.ipv4_dst,
				key, size);
			memcpy(&ip_addr_mask->ipv4_ds_addr.ipv4_dst,
				mask, size);
		} else {
			memcpy(&ip_addr_data->ipv4_sd_addr.ipv4_dst,
				key, size);
			memcpy(&ip_addr_mask->ipv4_sd_addr.ipv4_dst,
				mask, size);
		}
	} else if (orig_prot == NET_PROT_IPV6 &&
		orig_field == NH_FLD_IPV6_SRC_IP) {
		if (key_profile->ip_addr_type == IP_SRC_EXTRACT ||
			key_profile->ip_addr_type == IP_SRC_DST_EXTRACT) {
			memcpy(ip_addr_data->ipv6_sd_addr.ipv6_src,
				key, size);
			memcpy(ip_addr_mask->ipv6_sd_addr.ipv6_src,
				mask, size);
		} else {
			memcpy(ip_addr_data->ipv6_ds_addr.ipv6_src,
				key, size);
			memcpy(ip_addr_mask->ipv6_ds_addr.ipv6_src,
				mask, size);
		}
	} else if (orig_prot == NET_PROT_IPV6 &&
		orig_field == NH_FLD_IPV6_DST_IP) {
		if (key_profile->ip_addr_type == IP_DST_EXTRACT ||
			key_profile->ip_addr_type == IP_DST_SRC_EXTRACT) {
			memcpy(ip_addr_data->ipv6_ds_addr.ipv6_dst,
				key, size);
			memcpy(ip_addr_mask->ipv6_ds_addr.ipv6_dst,
				mask, size);
		} else {
			memcpy(ip_addr_data->ipv6_sd_addr.ipv6_dst,
				key, size);
			memcpy(ip_addr_mask->ipv6_sd_addr.ipv6_dst,
				mask, size);
		}
	}

	if (dist_type == DPAA2_FLOW_QOS_TYPE) {
		flow->qos_rule_size =
			key_profile->ip_addr_extract_off + ipaddr_extract_len;
	} else {
		flow->fs_rule_size =
			key_profile->ip_addr_extract_off + ipaddr_extract_len;
	}

	if (recfg)
		*recfg |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_eth(struct dpaa2_dev_flow *flow,
	struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern,
	const struct rte_flow_action actions[] __rte_unused,
	struct rte_flow_error *error __rte_unused,
	int *device_configured)
{
	int ret, local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_eth *spec, *mask;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	const char zero_cmp[RTE_ETHER_ADDR_LEN] = {0};

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
			pattern->mask : &dpaa2_flow_item_eth_mask;
	if (!spec) {
		DPAA2_PMD_WARN("No pattern spec for Eth flow");
		return -EINVAL;
	}

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_ETH)) {
		DPAA2_PMD_WARN("Extract field(s) of ethernet failed");

		return -EINVAL;
	}

	if (memcmp((const char *)&mask->src,
		zero_cmp, RTE_ETHER_ADDR_LEN)) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ETH,
			NH_FLD_ETH_SA, &spec->src.addr_bytes,
			&mask->src.addr_bytes, RTE_ETHER_ADDR_LEN,
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ETH,
			NH_FLD_ETH_SA, &spec->src.addr_bytes,
			&mask->src.addr_bytes, RTE_ETHER_ADDR_LEN,
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	if (memcmp((const char *)&mask->dst,
		zero_cmp, RTE_ETHER_ADDR_LEN)) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ETH,
			NH_FLD_ETH_DA, &spec->dst.addr_bytes,
			&mask->dst.addr_bytes, RTE_ETHER_ADDR_LEN,
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ETH,
			NH_FLD_ETH_DA, &spec->dst.addr_bytes,
			&mask->dst.addr_bytes, RTE_ETHER_ADDR_LEN,
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	if (memcmp((const char *)&mask->type,
		zero_cmp, sizeof(rte_be16_t))) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ETH,
			NH_FLD_ETH_TYPE, &spec->type,
			&mask->type, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ETH,
			NH_FLD_ETH_TYPE, &spec->type,
			&mask->type, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_vlan(struct dpaa2_dev_flow *flow,
	struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern,
	const struct rte_flow_action actions[] __rte_unused,
	struct rte_flow_error *error __rte_unused,
	int *device_configured)
{
	int ret, local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_vlan *spec, *mask;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ? pattern->mask : &dpaa2_flow_item_vlan_mask;

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec) {
		struct prev_proto_field_id prev_proto;

		prev_proto.prot = NET_PROT_ETH;
		prev_proto.eth_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
		ret = dpaa2_flow_identify_by_prev_prot(priv, flow, &prev_proto,
				DPAA2_FLOW_QOS_TYPE | DPAA2_FLOW_FS_TYPE,
				group, &local_cfg);
		if (ret)
			return ret;
		(*device_configured) |= local_cfg;
		return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
				       RTE_FLOW_ITEM_TYPE_VLAN)) {
		DPAA2_PMD_WARN("Extract field(s) of vlan not support.");
		return -EINVAL;
	}

	if (!mask->tci)
		return 0;

	ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_VLAN,
					      NH_FLD_VLAN_TCI, &spec->tci,
					      &mask->tci, sizeof(rte_be16_t),
					      priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
	if (ret)
		return ret;

	ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_VLAN,
					      NH_FLD_VLAN_TCI, &spec->tci,
					      &mask->tci, sizeof(rte_be16_t),
					      priv, group, &local_cfg,
					      DPAA2_FLOW_FS_TYPE);
	if (ret)
		return ret;

	(*device_configured) |= local_cfg;
	return 0;
}

static int
dpaa2_configure_flow_ipv4(struct dpaa2_dev_flow *flow, struct rte_eth_dev *dev,
			  const struct rte_flow_attr *attr,
			  const struct rte_flow_item *pattern,
			  const struct rte_flow_action actions[] __rte_unused,
			  struct rte_flow_error *error __rte_unused,
			  int *device_configured)
{
	int ret, local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_ipv4 *spec_ipv4 = 0, *mask_ipv4 = 0;
	const void *key, *mask;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	int size;
	struct prev_proto_field_id prev_prot;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec_ipv4 = pattern->spec;
	mask_ipv4 = pattern->mask ?
		    pattern->mask : &dpaa2_flow_item_ipv4_mask;

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	prev_prot.prot = NET_PROT_ETH;
	prev_prot.eth_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	ret = dpaa2_flow_identify_by_prev_prot(priv, flow, &prev_prot,
			DPAA2_FLOW_QOS_TYPE | DPAA2_FLOW_FS_TYPE, group,
			&local_cfg);
	if (ret) {
		DPAA2_PMD_ERR("IPv4 identification failed!");
		return ret;
	}

	if (!spec_ipv4)
		return 0;

	if (dpaa2_flow_extract_support((const uint8_t *)mask_ipv4,
				       RTE_FLOW_ITEM_TYPE_IPV4)) {
		DPAA2_PMD_WARN("Extract field(s) of IPv4 not support.");
		return -EINVAL;
	}

	if (mask_ipv4->hdr.src_addr) {
		key = &spec_ipv4->hdr.src_addr;
		mask = &mask_ipv4->hdr.src_addr;
		size = sizeof(rte_be32_t);

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV4,
							 NH_FLD_IPV4_SRC_IP,
							 key, mask, size, priv,
							 group, &local_cfg,
							 DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV4,
							 NH_FLD_IPV4_SRC_IP,
							 key, mask, size, priv,
							 group, &local_cfg,
							 DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	if (mask_ipv4->hdr.dst_addr) {
		key = &spec_ipv4->hdr.dst_addr;
		mask = &mask_ipv4->hdr.dst_addr;
		size = sizeof(rte_be32_t);

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV4,
							 NH_FLD_IPV4_DST_IP,
							 key, mask, size, priv,
							 group, &local_cfg,
							 DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;
		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV4,
							 NH_FLD_IPV4_DST_IP,
							 key, mask, size, priv,
							 group, &local_cfg,
							 DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	if (mask_ipv4->hdr.next_proto_id) {
		key = &spec_ipv4->hdr.next_proto_id;
		mask = &mask_ipv4->hdr.next_proto_id;
		size = sizeof(uint8_t);

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_IP,
						      NH_FLD_IP_PROTO, key,
						      mask, size, priv, group,
						      &local_cfg,
						      DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_IP,
						      NH_FLD_IP_PROTO, key,
						      mask, size, priv, group,
						      &local_cfg,
						      DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	(*device_configured) |= local_cfg;
	return 0;
}

static int
dpaa2_configure_flow_ipv6(struct dpaa2_dev_flow *flow, struct rte_eth_dev *dev,
			  const struct rte_flow_attr *attr,
			  const struct rte_flow_item *pattern,
			  const struct rte_flow_action actions[] __rte_unused,
			  struct rte_flow_error *error __rte_unused,
			  int *device_configured)
{
	int ret, local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_ipv6 *spec_ipv6 = 0, *mask_ipv6 = 0;
	const void *key, *mask;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	const char zero_cmp[NH_FLD_IPV6_ADDR_SIZE] = {0};
	int size;
	struct prev_proto_field_id prev_prot;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec_ipv6 = pattern->spec;
	mask_ipv6 = pattern->mask ? pattern->mask : &dpaa2_flow_item_ipv6_mask;

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	prev_prot.prot = NET_PROT_ETH;
	prev_prot.eth_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

	ret = dpaa2_flow_identify_by_prev_prot(priv, flow, &prev_prot,
			DPAA2_FLOW_QOS_TYPE | DPAA2_FLOW_FS_TYPE,
			group, &local_cfg);
	if (ret) {
		DPAA2_PMD_ERR("IPv6 identification failed!");
		return ret;
	}

	if (!spec_ipv6)
		return 0;

	if (dpaa2_flow_extract_support((const uint8_t *)mask_ipv6,
				       RTE_FLOW_ITEM_TYPE_IPV6)) {
		DPAA2_PMD_WARN("Extract field(s) of IPv6 not support.");
		return -EINVAL;
	}

	if (memcmp(mask_ipv6->hdr.src_addr, zero_cmp, NH_FLD_IPV6_ADDR_SIZE)) {
		key = &spec_ipv6->hdr.src_addr[0];
		mask = &mask_ipv6->hdr.src_addr[0];
		size = NH_FLD_IPV6_ADDR_SIZE;

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV6,
							 NH_FLD_IPV6_SRC_IP,
							 key, mask, size, priv,
							 group, &local_cfg,
							 DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV6,
							 NH_FLD_IPV6_SRC_IP,
							 key, mask, size, priv,
							 group, &local_cfg,
							 DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	if (memcmp(mask_ipv6->hdr.dst_addr, zero_cmp, NH_FLD_IPV6_ADDR_SIZE)) {
		key = &spec_ipv6->hdr.dst_addr[0];
		mask = &mask_ipv6->hdr.dst_addr[0];
		size = NH_FLD_IPV6_ADDR_SIZE;

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV6,
							 NH_FLD_IPV6_DST_IP,
							 key, mask, size, priv,
							 group, &local_cfg,
							 DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV6,
							 NH_FLD_IPV6_DST_IP,
							 key, mask, size, priv,
							 group, &local_cfg,
							 DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	if (mask_ipv6->hdr.proto) {
		key = &spec_ipv6->hdr.proto;
		mask = &mask_ipv6->hdr.proto;
		size = sizeof(uint8_t);

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_IP,
						      NH_FLD_IP_PROTO, key,
						      mask, size, priv, group,
						      &local_cfg,
						      DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_IP,
						      NH_FLD_IP_PROTO, key,
						      mask, size, priv, group,
						      &local_cfg,
						      DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	(*device_configured) |= local_cfg;
	return 0;
}

static int
dpaa2_configure_flow_icmp(struct dpaa2_dev_flow *flow,
	struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern,
	const struct rte_flow_action actions[] __rte_unused,
	struct rte_flow_error *error __rte_unused,
	int *device_configured)
{
	int ret, local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_icmp *spec, *mask;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_icmp_mask;

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec) {
		/* Next proto of Generical IP is actually used
		 * for ICMP identification.
		 * Example: flow create 0 ingress pattern icmp
		 */
		struct prev_proto_field_id prev_proto;

		prev_proto.prot = NET_PROT_IP;
		prev_proto.ip_proto = IPPROTO_ICMP;
		ret = dpaa2_flow_identify_by_prev_prot(priv,
			flow, &prev_proto,
			DPAA2_FLOW_QOS_TYPE | DPAA2_FLOW_FS_TYPE,
			group, &local_cfg);
		if (ret)
			return ret;

		(*device_configured) |= local_cfg;
		return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_ICMP)) {
		DPAA2_PMD_WARN("Extract field(s) of ICMP not support.");

		return -EINVAL;
	}

	if (mask->hdr.icmp_type) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ICMP,
			NH_FLD_ICMP_TYPE, &spec->hdr.icmp_type,
			&mask->hdr.icmp_type, sizeof(uint8_t),
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ICMP,
			NH_FLD_ICMP_TYPE, &spec->hdr.icmp_type,
			&mask->hdr.icmp_type, sizeof(uint8_t),
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	if (mask->hdr.icmp_code) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ICMP,
			NH_FLD_ICMP_CODE, &spec->hdr.icmp_code,
			&mask->hdr.icmp_code, sizeof(uint8_t),
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ICMP,
			NH_FLD_ICMP_CODE, &spec->hdr.icmp_code,
			&mask->hdr.icmp_code, sizeof(uint8_t),
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_udp(struct dpaa2_dev_flow *flow,
	struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern,
	const struct rte_flow_action actions[] __rte_unused,
	struct rte_flow_error *error __rte_unused,
	int *device_configured)
{
	int ret, local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_udp *spec, *mask;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_udp_mask;

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec || !mc_l4_port_identification) {
		struct prev_proto_field_id prev_proto;

		prev_proto.prot = NET_PROT_IP;
		prev_proto.ip_proto = IPPROTO_UDP;
		ret = dpaa2_flow_identify_by_prev_prot(priv,
			flow, &prev_proto,
			DPAA2_FLOW_QOS_TYPE | DPAA2_FLOW_FS_TYPE,
			group, &local_cfg);
		if (ret)
			return ret;

		(*device_configured) |= local_cfg;

		if (!spec)
			return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_UDP)) {
		DPAA2_PMD_WARN("Extract field(s) of UDP not support.");

		return -EINVAL;
	}

	if (mask->hdr.src_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_UDP,
			NH_FLD_UDP_PORT_SRC, &spec->hdr.src_port,
			&mask->hdr.src_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_UDP,
			NH_FLD_UDP_PORT_SRC, &spec->hdr.src_port,
			&mask->hdr.src_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	if (mask->hdr.dst_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_UDP,
			NH_FLD_UDP_PORT_DST, &spec->hdr.dst_port,
			&mask->hdr.dst_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_UDP,
			NH_FLD_UDP_PORT_DST, &spec->hdr.dst_port,
			&mask->hdr.dst_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_tcp(struct dpaa2_dev_flow *flow,
	struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern,
	const struct rte_flow_action actions[] __rte_unused,
	struct rte_flow_error *error __rte_unused,
	int *device_configured)
{
	int ret, local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_tcp *spec, *mask;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_tcp_mask;

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec || !mc_l4_port_identification) {
		struct prev_proto_field_id prev_proto;

		prev_proto.prot = NET_PROT_IP;
		prev_proto.ip_proto = IPPROTO_TCP;
		ret = dpaa2_flow_identify_by_prev_prot(priv,
			flow, &prev_proto,
			DPAA2_FLOW_QOS_TYPE | DPAA2_FLOW_FS_TYPE,
			group, &local_cfg);
		if (ret)
			return ret;

		(*device_configured) |= local_cfg;

		if (!spec)
			return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_TCP)) {
		DPAA2_PMD_WARN("Extract field(s) of TCP not support.");

		return -EINVAL;
	}

	if (mask->hdr.src_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_TCP,
			NH_FLD_TCP_PORT_SRC, &spec->hdr.src_port,
			&mask->hdr.src_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_TCP,
			NH_FLD_TCP_PORT_SRC, &spec->hdr.src_port,
			&mask->hdr.src_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	if (mask->hdr.dst_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_TCP,
			NH_FLD_TCP_PORT_DST, &spec->hdr.dst_port,
			&mask->hdr.dst_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_TCP,
			NH_FLD_TCP_PORT_DST, &spec->hdr.dst_port,
			&mask->hdr.dst_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_sctp(struct dpaa2_dev_flow *flow,
	struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern,
	const struct rte_flow_action actions[] __rte_unused,
	struct rte_flow_error *error __rte_unused,
	int *device_configured)
{
	int ret, local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_sctp *spec, *mask;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_sctp_mask;

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec || !mc_l4_port_identification) {
		struct prev_proto_field_id prev_proto;

		prev_proto.prot = NET_PROT_IP;
		prev_proto.ip_proto = IPPROTO_SCTP;
		ret = dpaa2_flow_identify_by_prev_prot(priv,
			flow, &prev_proto,
			DPAA2_FLOW_QOS_TYPE | DPAA2_FLOW_FS_TYPE,
			group, &local_cfg);
		if (ret)
			return ret;

		(*device_configured) |= local_cfg;

		if (!spec)
			return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_SCTP)) {
		DPAA2_PMD_WARN("Extract field(s) of SCTP not support.");

		return -1;
	}

	if (mask->hdr.src_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_SCTP,
			NH_FLD_SCTP_PORT_SRC, &spec->hdr.src_port,
			&mask->hdr.src_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_SCTP,
			NH_FLD_SCTP_PORT_SRC, &spec->hdr.src_port,
			&mask->hdr.src_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	if (mask->hdr.dst_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_SCTP,
			NH_FLD_SCTP_PORT_DST, &spec->hdr.dst_port,
			&mask->hdr.dst_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
		if (ret)
			return ret;

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_SCTP,
			NH_FLD_SCTP_PORT_DST, &spec->hdr.dst_port,
			&mask->hdr.dst_port, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
		if (ret)
			return ret;
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_gre(struct dpaa2_dev_flow *flow,
	struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern,
	const struct rte_flow_action actions[] __rte_unused,
	struct rte_flow_error *error __rte_unused,
	int *device_configured)
{
	int ret, local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_gre *spec, *mask;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_gre_mask;

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec) {
		struct prev_proto_field_id prev_proto;

		prev_proto.prot = NET_PROT_IP;
		prev_proto.ip_proto = IPPROTO_GRE;
		ret = dpaa2_flow_identify_by_prev_prot(priv,
			flow, &prev_proto,
			DPAA2_FLOW_QOS_TYPE | DPAA2_FLOW_FS_TYPE,
			group, &local_cfg);
		if (ret)
			return ret;

		(*device_configured) |= local_cfg;

		if (!spec)
			return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_GRE)) {
		DPAA2_PMD_WARN("Extract field(s) of GRE not support.");

		return -1;
	}

	if (!mask->protocol)
		return 0;

	ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_GRE,
			NH_FLD_GRE_TYPE, &spec->protocol,
			&mask->protocol, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_QOS_TYPE);
	if (ret)
		return ret;

	ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_GRE,
			NH_FLD_GRE_TYPE, &spec->protocol,
			&mask->protocol, sizeof(rte_be16_t),
			priv, group, &local_cfg, DPAA2_FLOW_FS_TYPE);
	if (ret)
		return ret;

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_raw(struct dpaa2_dev_flow *flow,
	struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern,
	const struct rte_flow_action actions[] __rte_unused,
	struct rte_flow_error *error __rte_unused,
	int *device_configured)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	const struct rte_flow_item_raw *spec = pattern->spec;
	const struct rte_flow_item_raw *mask = pattern->mask;
	int prev_key_size =
		priv->extract.qos_key_extract.key_profile.key_max_size;
	int local_cfg = 0, ret;
	uint32_t group;

	/* Need both spec and mask */
	if (!spec || !mask) {
		DPAA2_PMD_ERR("spec or mask not present.");
		return -EINVAL;
	}
	/* Only supports non-relative with offset 0 */
	if (spec->relative || spec->offset != 0 ||
	    spec->search || spec->limit) {
		DPAA2_PMD_ERR("relative and non zero offset not supported.");
		return -EINVAL;
	}
	/* Spec len and mask len should be same */
	if (spec->length != mask->length) {
		DPAA2_PMD_ERR("Spec len and mask len mismatch.");
		return -EINVAL;
	}

	/* Get traffic class index and flow id to be configured */
	group = attr->group;
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (prev_key_size <= spec->length) {
		ret = dpaa2_flow_extract_add_raw(&priv->extract.qos_key_extract,
						 spec->length);
		if (ret) {
			DPAA2_PMD_ERR("QoS Extract RAW add failed.");
			return -1;
		}
		local_cfg |= DPAA2_FLOW_QOS_TYPE;

		ret = dpaa2_flow_extract_add_raw(&priv->extract.tc_key_extract[group],
					spec->length);
		if (ret) {
			DPAA2_PMD_ERR("FS Extract RAW add failed.");
			return -1;
		}
		local_cfg |= DPAA2_FLOW_FS_TYPE;
	}

	ret = dpaa2_flow_rule_data_set_raw(&flow->qos_rule, spec->pattern,
					   mask->pattern, spec->length);
	if (ret) {
		DPAA2_PMD_ERR("QoS RAW rule data set failed");
		return -1;
	}

	ret = dpaa2_flow_rule_data_set_raw(&flow->fs_rule, spec->pattern,
					   mask->pattern, spec->length);
	if (ret) {
		DPAA2_PMD_ERR("FS RAW rule data set failed");
		return -1;
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static inline int
dpaa2_fs_action_supported(enum rte_flow_action_type action)
{
	int i;
	int action_num = sizeof(dpaa2_supported_fs_action_type) /
		sizeof(enum rte_flow_action_type);

	for (i = 0; i < action_num; i++) {
		if (action == dpaa2_supported_fs_action_type[i])
			return true;
	}

	return false;
}

static inline int
dpaa2_flow_verify_attr(struct dpaa2_dev_priv *priv,
	const struct rte_flow_attr *attr)
{
	struct dpaa2_dev_flow *curr = LIST_FIRST(&priv->flows);

	while (curr) {
		if (curr->tc_id == attr->group &&
			curr->tc_index == attr->priority) {
			DPAA2_PMD_ERR("Flow(TC[%d].entry[%d] exists",
				attr->group, attr->priority);

			return -EINVAL;
		}
		curr = LIST_NEXT(curr, next);
	}

	return 0;
}

static inline struct rte_eth_dev *
dpaa2_flow_redirect_dev(struct dpaa2_dev_priv *priv,
	const struct rte_flow_action *action)
{
	const struct rte_flow_action_port_id *port_id;
	const struct rte_flow_action_ethdev *ethdev;
	int idx = -1;
	struct rte_eth_dev *dest_dev;

	if (action->type == RTE_FLOW_ACTION_TYPE_PORT_ID) {
		port_id = action->conf;
		if (!port_id->original)
			idx = port_id->id;
	} else if (action->type == RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT) {
		ethdev = action->conf;
		idx = ethdev->port_id;
	} else {
		return NULL;
	}

	if (idx >= 0) {
		if (!rte_eth_dev_is_valid_port(idx))
			return NULL;
		if (!rte_pmd_dpaa2_dev_is_dpaa2(idx))
			return NULL;
		dest_dev = &rte_eth_devices[idx];
	} else {
		dest_dev = priv->eth_dev;
	}

	return dest_dev;
}

static inline int
dpaa2_flow_verify_action(struct dpaa2_dev_priv *priv,
	const struct rte_flow_attr *attr,
	const struct rte_flow_action actions[])
{
	int end_of_list = 0, i, j = 0;
	const struct rte_flow_action_queue *dest_queue;
	const struct rte_flow_action_rss *rss_conf;
	struct dpaa2_queue *rxq;

	while (!end_of_list) {
		switch (actions[j].type) {
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			dest_queue = actions[j].conf;
			rxq = priv->rx_vq[dest_queue->index];
			if (attr->group != rxq->tc_index) {
				DPAA2_PMD_ERR("FSQ(%d.%d) not in TC[%d]",
					rxq->tc_index, rxq->flow_id,
					attr->group);

				return -ENOTSUP;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			if (!dpaa2_flow_redirect_dev(priv, &actions[j])) {
				DPAA2_PMD_ERR("Invalid port id of action");
				return -ENOTSUP;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			rss_conf = (const struct rte_flow_action_rss *)
					(actions[j].conf);
			if (rss_conf->queue_num > priv->dist_queues) {
				DPAA2_PMD_ERR("RSS number too large");
				return -ENOTSUP;
			}
			for (i = 0; i < (int)rss_conf->queue_num; i++) {
				if (rss_conf->queue[i] >= priv->nb_rx_queues) {
					DPAA2_PMD_ERR("RSS queue not in range");
					return -ENOTSUP;
				}
				rxq = priv->rx_vq[rss_conf->queue[i]];
				if (rxq->tc_index != attr->group) {
					DPAA2_PMD_ERR("RSS queue not in group");
					return -ENOTSUP;
				}
			}

			break;
		case RTE_FLOW_ACTION_TYPE_END:
			end_of_list = 1;
			break;
		default:
			DPAA2_PMD_ERR("Invalid action type");
			return -ENOTSUP;
		}
		j++;
	}

	return 0;
}

static int
dpaa2_configure_flow_fs_action(struct dpaa2_dev_priv *priv,
	struct dpaa2_dev_flow *flow,
	const struct rte_flow_action *rte_action)
{
	struct rte_eth_dev *dest_dev;
	struct dpaa2_dev_priv *dest_priv;
	const struct rte_flow_action_queue *dest_queue;
	struct dpaa2_queue *dest_q;

	memset(&flow->fs_action_cfg, 0,
		sizeof(struct dpni_fs_action_cfg));
	flow->action_type = rte_action->type;

	if (flow->action_type == RTE_FLOW_ACTION_TYPE_QUEUE) {
		dest_queue = rte_action->conf;
		dest_q = priv->rx_vq[dest_queue->index];
		flow->fs_action_cfg.flow_id = dest_q->flow_id;
	} else if (flow->action_type == RTE_FLOW_ACTION_TYPE_PORT_ID ||
		   flow->action_type == RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT) {
		dest_dev = dpaa2_flow_redirect_dev(priv, rte_action);
		if (!dest_dev) {
			DPAA2_PMD_ERR("Invalid device to redirect");
			return -EINVAL;
		}

		dest_priv = dest_dev->data->dev_private;
		dest_q = dest_priv->tx_vq[0];
		flow->fs_action_cfg.options =
			DPNI_FS_OPT_REDIRECT_TO_DPNI_TX;
		flow->fs_action_cfg.redirect_obj_token =
			dest_priv->token;
		flow->fs_action_cfg.flow_id = dest_q->flow_id;
	}

	return 0;
}

static inline uint16_t
dpaa2_flow_entry_size(uint16_t key_max_size)
{
	if (key_max_size > DPAA2_FLOW_ENTRY_MAX_SIZE) {
		DPAA2_PMD_ERR("Key size(%d) > max(%d)",
			key_max_size,
			DPAA2_FLOW_ENTRY_MAX_SIZE);

		return 0;
	}

	if (key_max_size > DPAA2_FLOW_ENTRY_MIN_SIZE)
		return DPAA2_FLOW_ENTRY_MAX_SIZE;

	/* Current MC only support fixed entry size(56)*/
	return DPAA2_FLOW_ENTRY_MAX_SIZE;
}

static inline int
dpaa2_flow_clear_fs_table(struct dpaa2_dev_priv *priv,
	uint8_t tc_id)
{
	struct dpaa2_dev_flow *curr = LIST_FIRST(&priv->flows);
	int need_clear = 0, ret;
	struct fsl_mc_io *dpni = priv->hw;

	while (curr) {
		if (curr->tc_id == tc_id) {
			need_clear = 1;
			break;
		}
		curr = LIST_NEXT(curr, next);
	}

	if (need_clear) {
		ret = dpni_clear_fs_entries(dpni, CMD_PRI_LOW,
				priv->token, tc_id);
		if (ret) {
			DPAA2_PMD_ERR("TC[%d] clear failed", tc_id);
			return ret;
		}
	}

	return 0;
}

static int
dpaa2_configure_fs_rss_table(struct dpaa2_dev_priv *priv,
	uint8_t tc_id, uint16_t dist_size, int rss_dist)
{
	struct dpaa2_key_extract *tc_extract;
	uint8_t *key_cfg_buf;
	uint64_t key_cfg_iova;
	int ret;
	struct dpni_rx_dist_cfg tc_cfg;
	struct fsl_mc_io *dpni = priv->hw;
	uint16_t entry_size;
	uint16_t key_max_size;

	ret = dpaa2_flow_clear_fs_table(priv, tc_id);
	if (ret < 0) {
		DPAA2_PMD_ERR("TC[%d] clear failed", tc_id);
		return ret;
	}

	tc_extract = &priv->extract.tc_key_extract[tc_id];
	key_cfg_buf = priv->extract.tc_extract_param[tc_id];
	key_cfg_iova = DPAA2_VADDR_TO_IOVA(key_cfg_buf);

	key_max_size = tc_extract->key_profile.key_max_size;
	entry_size = dpaa2_flow_entry_size(key_max_size);

	dpaa2_flow_fs_extracts_log(priv, tc_id);
	ret = dpkg_prepare_key_cfg(&tc_extract->dpkg,
			key_cfg_buf);
	if (ret < 0) {
		DPAA2_PMD_ERR("TC[%d] prepare key failed", tc_id);
		return ret;
	}

	memset(&tc_cfg, 0, sizeof(struct dpni_rx_dist_cfg));
	tc_cfg.dist_size = dist_size;
	tc_cfg.key_cfg_iova = key_cfg_iova;
	if (rss_dist)
		tc_cfg.enable = true;
	else
		tc_cfg.enable = false;
	tc_cfg.tc = tc_id;
	ret = dpni_set_rx_hash_dist(dpni, CMD_PRI_LOW,
			priv->token, &tc_cfg);
	if (ret < 0) {
		if (rss_dist) {
			DPAA2_PMD_ERR("RSS TC[%d] set failed",
				tc_id);
		} else {
			DPAA2_PMD_ERR("FS TC[%d] hash disable failed",
				tc_id);
		}

		return ret;
	}

	if (rss_dist)
		return 0;

	tc_cfg.enable = true;
	tc_cfg.fs_miss_flow_id = dpaa2_flow_miss_flow_id;
	ret = dpni_set_rx_fs_dist(dpni, CMD_PRI_LOW,
			priv->token, &tc_cfg);
	if (ret < 0) {
		DPAA2_PMD_ERR("TC[%d] FS configured failed", tc_id);
		return ret;
	}

	ret = dpaa2_flow_rule_add_all(priv, DPAA2_FLOW_FS_TYPE,
			entry_size, tc_id);
	if (ret)
		return ret;

	return 0;
}

static int
dpaa2_configure_qos_table(struct dpaa2_dev_priv *priv,
	int rss_dist)
{
	struct dpaa2_key_extract *qos_extract;
	uint8_t *key_cfg_buf;
	uint64_t key_cfg_iova;
	int ret;
	struct dpni_qos_tbl_cfg qos_cfg;
	struct fsl_mc_io *dpni = priv->hw;
	uint16_t entry_size;
	uint16_t key_max_size;

	if (!rss_dist && priv->num_rx_tc <= 1) {
		/* QoS table is effecitive for FS multiple TCs or RSS.*/
		return 0;
	}

	if (LIST_FIRST(&priv->flows)) {
		ret = dpni_clear_qos_table(dpni, CMD_PRI_LOW,
				priv->token);
		if (ret < 0) {
			DPAA2_PMD_ERR("QoS table clear failed");
			return ret;
		}
	}

	qos_extract = &priv->extract.qos_key_extract;
	key_cfg_buf = priv->extract.qos_extract_param;
	key_cfg_iova = DPAA2_VADDR_TO_IOVA(key_cfg_buf);

	key_max_size = qos_extract->key_profile.key_max_size;
	entry_size = dpaa2_flow_entry_size(key_max_size);

	dpaa2_flow_qos_extracts_log(priv);

	ret = dpkg_prepare_key_cfg(&qos_extract->dpkg,
			key_cfg_buf);
	if (ret < 0) {
		DPAA2_PMD_ERR("QoS prepare extract failed");
		return ret;
	}
	memset(&qos_cfg, 0, sizeof(struct dpni_qos_tbl_cfg));
	qos_cfg.keep_entries = true;
	qos_cfg.key_cfg_iova = key_cfg_iova;
	if (rss_dist) {
		qos_cfg.discard_on_miss = true;
	} else {
		qos_cfg.discard_on_miss = false;
		qos_cfg.default_tc = 0;
	}

	ret = dpni_set_qos_table(dpni, CMD_PRI_LOW,
			priv->token, &qos_cfg);
	if (ret < 0) {
		DPAA2_PMD_ERR("QoS table set failed");
		return ret;
	}

	ret = dpaa2_flow_rule_add_all(priv, DPAA2_FLOW_QOS_TYPE,
			entry_size, 0);
	if (ret)
		return ret;

	return 0;
}

static int
dpaa2_generic_flow_set(struct dpaa2_dev_flow *flow,
	struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item pattern[],
	const struct rte_flow_action actions[],
	struct rte_flow_error *error)
{
	const struct rte_flow_action_rss *rss_conf;
	int is_keycfg_configured = 0, end_of_list = 0;
	int ret = 0, i = 0, j = 0;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_flow *curr = LIST_FIRST(&priv->flows);
	uint16_t dist_size, key_size;
	struct dpaa2_key_extract *qos_key_extract;
	struct dpaa2_key_extract *tc_key_extract;

	ret = dpaa2_flow_verify_attr(priv, attr);
	if (ret)
		return ret;

	ret = dpaa2_flow_verify_action(priv, attr, actions);
	if (ret)
		return ret;

	/* Parse pattern list to get the matching parameters */
	while (!end_of_list) {
		switch (pattern[i].type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			ret = dpaa2_configure_flow_eth(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("ETH flow config failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			ret = dpaa2_configure_flow_vlan(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("vLan flow config failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			ret = dpaa2_configure_flow_ipv4(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("IPV4 flow config failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			ret = dpaa2_configure_flow_ipv6(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("IPV6 flow config failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_ICMP:
			ret = dpaa2_configure_flow_icmp(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("ICMP flow config failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			ret = dpaa2_configure_flow_udp(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("UDP flow config failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			ret = dpaa2_configure_flow_tcp(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("TCP flow config failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_SCTP:
			ret = dpaa2_configure_flow_sctp(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("SCTP flow config failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
			ret = dpaa2_configure_flow_gre(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("GRE flow config failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_RAW:
			ret = dpaa2_configure_flow_raw(flow,
					dev, attr, &pattern[i],
					actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("RAW flow config failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_END:
			end_of_list = 1;
			break; /*End of List*/
		default:
			DPAA2_PMD_ERR("Invalid action type");
			ret = -ENOTSUP;
			break;
		}
		i++;
	}

	qos_key_extract = &priv->extract.qos_key_extract;
	key_size = qos_key_extract->key_profile.key_max_size;
	flow->qos_rule.key_size = dpaa2_flow_entry_size(key_size);

	tc_key_extract = &priv->extract.tc_key_extract[flow->tc_id];
	key_size = tc_key_extract->key_profile.key_max_size;
	flow->fs_rule.key_size = dpaa2_flow_entry_size(key_size);

	/* Let's parse action on matching traffic */
	end_of_list = 0;
	while (!end_of_list) {
		switch (actions[j].type) {
		case RTE_FLOW_ACTION_TYPE_QUEUE:
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			ret = dpaa2_configure_flow_fs_action(priv, flow,
							     &actions[j]);
			if (ret)
				return ret;

			/* Configure FS table first*/
			dist_size = priv->nb_rx_queues / priv->num_rx_tc;
			if (is_keycfg_configured & DPAA2_FLOW_FS_TYPE) {
				ret = dpaa2_configure_fs_rss_table(priv,
								   flow->tc_id,
								   dist_size,
								   false);
				if (ret)
					return ret;
			}

			/* Configure QoS table then.*/
			if (is_keycfg_configured & DPAA2_FLOW_QOS_TYPE) {
				ret = dpaa2_configure_qos_table(priv, false);
				if (ret)
					return ret;
			}

			if (priv->num_rx_tc > 1) {
				ret = dpaa2_flow_add_qos_rule(priv, flow);
				if (ret)
					return ret;
			}

			if (flow->tc_index >= priv->fs_entries) {
				DPAA2_PMD_ERR("FS table with %d entries full",
					priv->fs_entries);
				return -1;
			}

			ret = dpaa2_flow_add_fs_rule(priv, flow);
			if (ret)
				return ret;

			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			rss_conf = actions[j].conf;
			flow->action_type = RTE_FLOW_ACTION_TYPE_RSS;

			ret = dpaa2_distset_to_dpkg_profile_cfg(rss_conf->types,
					&tc_key_extract->dpkg);
			if (ret < 0) {
				DPAA2_PMD_ERR("TC[%d] distset RSS failed",
					      flow->tc_id);
				return ret;
			}

			dist_size = rss_conf->queue_num;
			if (is_keycfg_configured & DPAA2_FLOW_FS_TYPE) {
				ret = dpaa2_configure_fs_rss_table(priv,
								   flow->tc_id,
								   dist_size,
								   true);
				if (ret)
					return ret;
			}

			if (is_keycfg_configured & DPAA2_FLOW_QOS_TYPE) {
				ret = dpaa2_configure_qos_table(priv, true);
				if (ret)
					return ret;
			}

			ret = dpaa2_flow_add_qos_rule(priv, flow);
			if (ret)
				return ret;

			ret = dpaa2_flow_add_fs_rule(priv, flow);
			if (ret)
				return ret;

			break;
		case RTE_FLOW_ACTION_TYPE_END:
			end_of_list = 1;
			break;
		default:
			DPAA2_PMD_ERR("Invalid action type");
			ret = -ENOTSUP;
			break;
		}
		j++;
	}

	if (!ret) {
		/* New rules are inserted. */
		if (!curr) {
			LIST_INSERT_HEAD(&priv->flows, flow, next);
		} else {
			while (LIST_NEXT(curr, next))
				curr = LIST_NEXT(curr, next);
			LIST_INSERT_AFTER(curr, flow, next);
		}
	}
	return ret;
}

static inline int
dpaa2_dev_verify_attr(struct dpni_attr *dpni_attr,
	const struct rte_flow_attr *attr)
{
	int ret = 0;

	if (unlikely(attr->group >= dpni_attr->num_rx_tcs)) {
		DPAA2_PMD_ERR("Priority group is out of range");
		ret = -ENOTSUP;
	}
	if (unlikely(attr->priority >= dpni_attr->fs_entries)) {
		DPAA2_PMD_ERR("Priority within the group is out of range");
		ret = -ENOTSUP;
	}
	if (unlikely(attr->egress)) {
		DPAA2_PMD_ERR(
			"Flow configuration is not supported on egress side");
		ret = -ENOTSUP;
	}
	if (unlikely(!attr->ingress)) {
		DPAA2_PMD_ERR("Ingress flag must be configured");
		ret = -EINVAL;
	}
	return ret;
}

static inline int
dpaa2_dev_verify_patterns(const struct rte_flow_item pattern[])
{
	unsigned int i, j, is_found = 0;
	int ret = 0;

	for (j = 0; pattern[j].type != RTE_FLOW_ITEM_TYPE_END; j++) {
		for (i = 0; i < RTE_DIM(dpaa2_supported_pattern_type); i++) {
			if (dpaa2_supported_pattern_type[i]
					== pattern[j].type) {
				is_found = 1;
				break;
			}
		}
		if (!is_found) {
			ret = -ENOTSUP;
			break;
		}
	}
	/* Lets verify other combinations of given pattern rules */
	for (j = 0; pattern[j].type != RTE_FLOW_ITEM_TYPE_END; j++) {
		if (!pattern[j].spec) {
			ret = -EINVAL;
			break;
		}
	}

	return ret;
}

static inline int
dpaa2_dev_verify_actions(const struct rte_flow_action actions[])
{
	unsigned int i, j, is_found = 0;
	int ret = 0;

	for (j = 0; actions[j].type != RTE_FLOW_ACTION_TYPE_END; j++) {
		for (i = 0; i < RTE_DIM(dpaa2_supported_action_type); i++) {
			if (dpaa2_supported_action_type[i] == actions[j].type) {
				is_found = 1;
				break;
			}
		}
		if (!is_found) {
			ret = -ENOTSUP;
			break;
		}
	}
	for (j = 0; actions[j].type != RTE_FLOW_ACTION_TYPE_END; j++) {
		if (actions[j].type != RTE_FLOW_ACTION_TYPE_DROP &&
		    !actions[j].conf)
			ret = -EINVAL;
	}
	return ret;
}

static int
dpaa2_flow_validate(struct rte_eth_dev *dev,
	const struct rte_flow_attr *flow_attr,
	const struct rte_flow_item pattern[],
	const struct rte_flow_action actions[],
	struct rte_flow_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpni_attr dpni_attr;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	uint16_t token = priv->token;
	int ret = 0;

	memset(&dpni_attr, 0, sizeof(struct dpni_attr));
	ret = dpni_get_attributes(dpni, CMD_PRI_LOW, token, &dpni_attr);
	if (ret < 0) {
		DPAA2_PMD_ERR(
			"Failure to get dpni@%p attribute, err code  %d",
			dpni, ret);
		rte_flow_error_set(error, EPERM,
			   RTE_FLOW_ERROR_TYPE_ATTR,
			   flow_attr, "invalid");
		return ret;
	}

	/* Verify input attributes */
	ret = dpaa2_dev_verify_attr(&dpni_attr, flow_attr);
	if (ret < 0) {
		DPAA2_PMD_ERR(
			"Invalid attributes are given");
		rte_flow_error_set(error, EPERM,
			   RTE_FLOW_ERROR_TYPE_ATTR,
			   flow_attr, "invalid");
		goto not_valid_params;
	}
	/* Verify input pattern list */
	ret = dpaa2_dev_verify_patterns(pattern);
	if (ret < 0) {
		DPAA2_PMD_ERR(
			"Invalid pattern list is given");
		rte_flow_error_set(error, EPERM,
			   RTE_FLOW_ERROR_TYPE_ITEM,
			   pattern, "invalid");
		goto not_valid_params;
	}
	/* Verify input action list */
	ret = dpaa2_dev_verify_actions(actions);
	if (ret < 0) {
		DPAA2_PMD_ERR(
			"Invalid action list is given");
		rte_flow_error_set(error, EPERM,
			   RTE_FLOW_ERROR_TYPE_ACTION,
			   actions, "invalid");
		goto not_valid_params;
	}
not_valid_params:
	return ret;
}

static struct rte_flow *
dpaa2_flow_create(struct rte_eth_dev *dev, const struct rte_flow_attr *attr,
		  const struct rte_flow_item pattern[],
		  const struct rte_flow_action actions[],
		  struct rte_flow_error *error)
{
	struct dpaa2_dev_flow *flow = NULL;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	int ret;

	dpaa2_flow_control_log =
		getenv("DPAA2_FLOW_CONTROL_LOG");

	if (getenv("DPAA2_FLOW_CONTROL_MISS_FLOW")) {
		dpaa2_flow_miss_flow_id =
			(uint16_t)atoi(getenv("DPAA2_FLOW_CONTROL_MISS_FLOW"));
		if (dpaa2_flow_miss_flow_id >= priv->dist_queues) {
			DPAA2_PMD_ERR("Missed flow ID %d >= dist size(%d)",
				      dpaa2_flow_miss_flow_id,
				      priv->dist_queues);
			return NULL;
		}
	}

	flow = rte_zmalloc(NULL, sizeof(struct dpaa2_dev_flow),
			   RTE_CACHE_LINE_SIZE);
	if (!flow) {
		DPAA2_PMD_ERR("Failure to allocate memory for flow");
		goto mem_failure;
	}

	/* Allocate DMA'ble memory to write the qos rules */
	flow->qos_key_addr = rte_zmalloc(NULL, 256, 64);
	if (!flow->qos_key_addr) {
		DPAA2_PMD_ERR("Memory allocation failed");
		goto mem_failure;
	}
	flow->qos_rule.key_iova = DPAA2_VADDR_TO_IOVA(flow->qos_key_addr);

	flow->qos_mask_addr = rte_zmalloc(NULL, 256, 64);
	if (!flow->qos_mask_addr) {
		DPAA2_PMD_ERR("Memory allocation failed");
		goto mem_failure;
	}
	flow->qos_rule.mask_iova = DPAA2_VADDR_TO_IOVA(flow->qos_mask_addr);

	/* Allocate DMA'ble memory to write the FS rules */
	flow->fs_key_addr = rte_zmalloc(NULL, 256, 64);
	if (!flow->fs_key_addr) {
		DPAA2_PMD_ERR("Memory allocation failed");
		goto mem_failure;
	}
	flow->fs_rule.key_iova = DPAA2_VADDR_TO_IOVA(flow->fs_key_addr);

	flow->fs_mask_addr = rte_zmalloc(NULL, 256, 64);
	if (!flow->fs_mask_addr) {
		DPAA2_PMD_ERR("Memory allocation failed");
		goto mem_failure;
	}
	flow->fs_rule.mask_iova = DPAA2_VADDR_TO_IOVA(flow->fs_mask_addr);

	priv->curr = flow;

	ret = dpaa2_generic_flow_set(flow, dev, attr, pattern, actions, error);
	if (ret < 0) {
		if (error && error->type > RTE_FLOW_ERROR_TYPE_ACTION)
			rte_flow_error_set(error, EPERM,
					   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					   attr, "unknown");
		DPAA2_PMD_ERR("Create flow failed (%d)", ret);
		goto creation_error;
	}

	priv->curr = NULL;
	return (struct rte_flow *)flow;

mem_failure:
	rte_flow_error_set(error, EPERM, RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			   "memory alloc");

creation_error:
	if (flow) {
		if (flow->qos_key_addr)
			rte_free(flow->qos_key_addr);
		if (flow->qos_mask_addr)
			rte_free(flow->qos_mask_addr);
		if (flow->fs_key_addr)
			rte_free(flow->fs_key_addr);
		if (flow->fs_mask_addr)
			rte_free(flow->fs_mask_addr);
		rte_free(flow);
	}
	priv->curr = NULL;

	return NULL;
}

static int
dpaa2_flow_destroy(struct rte_eth_dev *dev, struct rte_flow *_flow,
		   struct rte_flow_error *error)
{
	int ret = 0;
	struct dpaa2_dev_flow *flow;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = priv->hw;

	flow = (struct dpaa2_dev_flow *)_flow;

	switch (flow->action_type) {
	case RTE_FLOW_ACTION_TYPE_QUEUE:
	case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
	case RTE_FLOW_ACTION_TYPE_PORT_ID:
		if (priv->num_rx_tc > 1) {
			/* Remove entry from QoS table first */
			ret = dpni_remove_qos_entry(dpni, CMD_PRI_LOW,
						    priv->token,
						    &flow->qos_rule);
			if (ret < 0) {
				DPAA2_PMD_ERR("Remove FS QoS entry failed");
				dpaa2_flow_qos_entry_log("Delete failed", flow,
							 -1);
				abort();
				goto error;
			}
		}

		/* Then remove entry from FS table */
		ret = dpni_remove_fs_entry(dpni, CMD_PRI_LOW, priv->token,
					   flow->tc_id, &flow->fs_rule);
		if (ret < 0) {
			DPAA2_PMD_ERR("Remove entry from FS[%d] failed",
				      flow->tc_id);
			goto error;
		}
		break;
	case RTE_FLOW_ACTION_TYPE_RSS:
		if (priv->num_rx_tc > 1) {
			ret = dpni_remove_qos_entry(dpni, CMD_PRI_LOW,
						    priv->token,
						    &flow->qos_rule);
			if (ret < 0) {
				DPAA2_PMD_ERR("Remove RSS QoS entry failed");
				goto error;
			}
		}
		break;
	default:
		DPAA2_PMD_ERR("Action(%d) not supported", flow->action_type);
		ret = -ENOTSUP;
		break;
	}

	LIST_REMOVE(flow, next);
	if (flow->qos_key_addr)
		rte_free(flow->qos_key_addr);
	if (flow->qos_mask_addr)
		rte_free(flow->qos_mask_addr);
	if (flow->fs_key_addr)
		rte_free(flow->fs_key_addr);
	if (flow->fs_mask_addr)
		rte_free(flow->fs_mask_addr);
	/* Now free the flow */
	rte_free(flow);

error:
	if (ret)
		rte_flow_error_set(error, EPERM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL, "unknown");
	return ret;
}

/**
 * Destroy user-configured flow rules.
 *
 * This function skips internal flows rules.
 *
 * @see rte_flow_flush()
 * @see rte_flow_ops
 */
static int
dpaa2_flow_flush(struct rte_eth_dev *dev,
		struct rte_flow_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_flow *flow = LIST_FIRST(&priv->flows);

	while (flow) {
		struct dpaa2_dev_flow *next = LIST_NEXT(flow, next);

		dpaa2_flow_destroy(dev, (struct rte_flow *)flow, error);
		flow = next;
	}
	return 0;
}

static int
dpaa2_flow_query(struct rte_eth_dev *dev __rte_unused,
	struct rte_flow *_flow __rte_unused,
	const struct rte_flow_action *actions __rte_unused,
	void *data __rte_unused,
	struct rte_flow_error *error __rte_unused)
{
	return 0;
}

/**
 * Clean up all flow rules.
 *
 * Unlike dpaa2_flow_flush(), this function takes care of all remaining flow
 * rules regardless of whether they are internal or user-configured.
 *
 * @param priv
 *   Pointer to private structure.
 */
void
dpaa2_flow_clean(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_flow *flow;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	while ((flow = LIST_FIRST(&priv->flows)))
		dpaa2_flow_destroy(dev, (struct rte_flow *)flow, NULL);
}

const struct rte_flow_ops dpaa2_flow_ops = {
	.create	= dpaa2_flow_create,
	.validate = dpaa2_flow_validate,
	.destroy = dpaa2_flow_destroy,
	.flush	= dpaa2_flow_flush,
	.query	= dpaa2_flow_query,
};
