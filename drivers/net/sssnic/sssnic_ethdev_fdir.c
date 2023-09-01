/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_common.h>
#include <rte_tailq.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"
#include "sssnic_ethdev.h"
#include "sssnic_ethdev_fdir.h"
#include "base/sssnic_hw.h"
#include "base/sssnic_api.h"

#define SSSNIC_NETDEV_FDIR_INFO(netdev) ((netdev)->fdir_info)
#define SSSNIC_ETHDEV_FDIR_INFO(ethdev)                                        \
	(SSSNIC_NETDEV_FDIR_INFO(SSSNIC_ETHDEV_PRIVATE(ethdev)))

enum {
	SSSNIC_ETHDEV_PTYPE_INVAL = 0,
	SSSNIC_ETHDEV_PTYPE_ARP = 1,
	SSSNIC_ETHDEV_PTYPE_ARP_REQ = 2,
	SSSNIC_ETHDEV_PTYPE_ARP_REP = 3,
	SSSNIC_ETHDEV_PTYPE_RARP = 4,
	SSSNIC_ETHDEV_PTYPE_LACP = 5,
	SSSNIC_ETHDEV_PTYPE_LLDP = 6,
	SSSNIC_ETHDEV_PTYPE_OAM = 7,
	SSSNIC_ETHDEV_PTYPE_CDCP = 8,
	SSSNIC_ETHDEV_PTYPE_CNM = 9,
	SSSNIC_ETHDEV_PTYPE_ECP = 10,
};

#define SSSNIC_ETHDEV_TCAM_ENTRY_INVAL_IDX 0xffff
struct sssnic_ethdev_fdir_entry {
	TAILQ_ENTRY(sssnic_ethdev_fdir_entry) node;
	struct sssnic_ethdev_tcam_block *tcam_block;
	uint32_t tcam_entry_idx;
	int enabled;
	struct sssnic_ethdev_fdir_rule *rule;
};

#define SSSNIC_ETHDEV_TCAM_BLOCK_SZ 16
struct sssnic_ethdev_tcam_block {
	TAILQ_ENTRY(sssnic_ethdev_tcam_block) node;
	uint16_t id;
	uint16_t used_entries;
	uint8_t entries_status[SSSNIC_ETHDEV_TCAM_BLOCK_SZ]; /* 0: IDLE, 1: USED */
};

struct sssnic_ethdev_tcam {
	TAILQ_HEAD(, sssnic_ethdev_tcam_block) block_list;
	uint16_t num_blocks;
	uint16_t used_entries; /* Count of used entries */
	int enabled;
};

struct sssnic_ethdev_fdir_info {
	struct rte_eth_dev *ethdev;
	struct sssnic_ethdev_tcam tcam;
	uint32_t num_entries;
	TAILQ_HEAD(, sssnic_ethdev_fdir_entry) ethertype_entry_list;
	TAILQ_HEAD(, sssnic_ethdev_fdir_entry) flow_entry_list;
};

static int
sssnic_ethdev_tcam_init(struct rte_eth_dev *ethdev)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct sssnic_ethdev_fdir_info *fdir_info;

	fdir_info = SSSNIC_ETHDEV_FDIR_INFO(ethdev);
	TAILQ_INIT(&fdir_info->tcam.block_list);

	sssnic_tcam_disable_and_flush(hw);

	return 0;
}

static void
sssnic_ethdev_tcam_shutdown(struct rte_eth_dev *ethdev)
{
	struct sssnic_ethdev_fdir_info *fdir_info;
	struct sssnic_ethdev_tcam *tcam;
	struct sssnic_ethdev_tcam_block *block, *tmp;

	fdir_info = SSSNIC_ETHDEV_FDIR_INFO(ethdev);
	tcam = &fdir_info->tcam;

	RTE_TAILQ_FOREACH_SAFE(block, &tcam->block_list, node, tmp)
	{
		TAILQ_REMOVE(&tcam->block_list, block, node);
		rte_free(block);
	}
}

static int
sssnic_ethdev_tcam_enable(struct rte_eth_dev *ethdev)
{
	struct sssnic_ethdev_fdir_info *fdir_info;
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	fdir_info = SSSNIC_ETHDEV_FDIR_INFO(ethdev);

	if (!fdir_info->tcam.enabled) {
		ret = sssnic_tcam_enable_set(hw, 1);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to enable TCAM");
			return ret;
		}

		fdir_info->tcam.enabled = 1;
	}

	return 0;
}

static int
sssnic_ethdev_tcam_disable(struct rte_eth_dev *ethdev)
{
	struct sssnic_ethdev_fdir_info *fdir_info;
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	fdir_info = SSSNIC_ETHDEV_FDIR_INFO(ethdev);

	if (fdir_info->tcam.enabled) {
		ret = sssnic_tcam_enable_set(hw, 0);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to enable TCAM");
			return ret;
		}

		fdir_info->tcam.enabled = 0;
	}

	return 0;
}

static int
sssnic_ethdev_tcam_block_alloc(struct rte_eth_dev *ethdev,
	struct sssnic_ethdev_tcam_block **block)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct sssnic_ethdev_fdir_info *fdir_info =
		SSSNIC_ETHDEV_FDIR_INFO(ethdev);
	struct sssnic_ethdev_tcam_block *new;
	int ret;

	new = rte_zmalloc("sssnic_tcam_block", sizeof(*new), 0);
	if (new == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to allocate memory for tcam block struct!");
		return -ENOMEM;
	}

	ret = sssnic_tcam_block_alloc(hw, &new->id);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to alloc tcam block!");
		rte_free(new);
		return ret;
	}

	TAILQ_INSERT_HEAD(&fdir_info->tcam.block_list, new, node);
	fdir_info->tcam.num_blocks++;

	if (block != NULL)
		*block = new;

	return 0;
}

static int
sssnic_ethdev_tcam_block_free(struct rte_eth_dev *ethdev,
	struct sssnic_ethdev_tcam_block *block)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct sssnic_ethdev_fdir_info *fdir_info =
		SSSNIC_ETHDEV_FDIR_INFO(ethdev);
	int ret;

	ret = sssnic_tcam_block_free(hw, block->id);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to free tcam block:%u!", block->id);
		return ret;
	}

	TAILQ_REMOVE(&fdir_info->tcam.block_list, block, node);
	fdir_info->tcam.num_blocks--;
	rte_free(block);

	return 0;
}

static struct sssnic_ethdev_tcam_block *
sssnic_ethdev_available_tcam_block_lookup(struct sssnic_ethdev_tcam *tcam)
{
	struct sssnic_ethdev_tcam_block *block;

	TAILQ_FOREACH(block, &tcam->block_list, node)
	{
		if (block->used_entries < SSSNIC_ETHDEV_TCAM_BLOCK_SZ)
			return block;
	}

	return NULL;
}

static int
sssnic_ethdev_tcam_block_entry_alloc(struct sssnic_ethdev_tcam_block *block,
	uint32_t *entry_idx)
{
	uint32_t i;

	for (i = 0; i < SSSNIC_ETHDEV_TCAM_BLOCK_SZ; i++) {
		if (block->entries_status[i] == 0) {
			*entry_idx = i;
			block->entries_status[i] = 1;
			block->used_entries++;
			return 0;
		}
	}

	return -ENOMEM;
}

static int
sssnic_ethdev_tcam_block_entry_free(struct sssnic_ethdev_tcam_block *block,
	uint32_t entry_idx)
{
	if (block != NULL && entry_idx < SSSNIC_ETHDEV_TCAM_BLOCK_SZ) {
		if (block->entries_status[entry_idx] == 1) {
			block->entries_status[entry_idx] = 0;
			block->used_entries--;
			return 0; /* found and freed */
		}
	}
	return -1; /* not found */
}

static int
sssnic_ethdev_tcam_entry_alloc(struct rte_eth_dev *ethdev,
	struct sssnic_ethdev_tcam_block **block, uint32_t *entry_idx)
{
	struct sssnic_ethdev_fdir_info *fdir_info =
		SSSNIC_ETHDEV_FDIR_INFO(ethdev);
	struct sssnic_ethdev_tcam *tcam;
	struct sssnic_ethdev_tcam_block *tcam_block;
	int new_block = 0;
	uint32_t eid;
	int ret;

	tcam = &fdir_info->tcam;

	if (tcam->num_blocks == 0 ||
		tcam->used_entries >=
			tcam->num_blocks * SSSNIC_ETHDEV_TCAM_BLOCK_SZ) {
		ret = sssnic_ethdev_tcam_block_alloc(ethdev, &tcam_block);
		if (ret != 0) {
			PMD_DRV_LOG(ERR,
				"No TCAM memory, used block count: %u, used entries count:%u",
				tcam->num_blocks, tcam->used_entries);
			return ret;
		}
		new_block = 1;
	} else {
		tcam_block = sssnic_ethdev_available_tcam_block_lookup(tcam);
		if (tcam_block == NULL) {
			PMD_DRV_LOG(CRIT,
				"No available TCAM block, used block count:%u, used entries count:%u",
				tcam->num_blocks, tcam->used_entries);
			return -ENOMEM;
		}
	}

	ret = sssnic_ethdev_tcam_block_entry_alloc(tcam_block, &eid);
	if (ret != 0) {
		PMD_DRV_LOG(CRIT,
			"No available entry in TCAM block, block idx:%u, used entries:%u",
			tcam_block->id, tcam_block->used_entries);
		if (unlikely(new_block))
			sssnic_ethdev_tcam_block_free(ethdev, tcam_block);

		return -ENOMEM;
	}

	tcam->used_entries++;

	*block = tcam_block;
	*entry_idx = eid;

	return 0;
}

static int
sssnic_ethdev_tcam_entry_free(struct rte_eth_dev *ethdev,
	struct sssnic_ethdev_tcam_block *tcam_block, uint32_t entry_idx)
{
	int ret;
	struct sssnic_ethdev_fdir_info *fdir_info =
		SSSNIC_ETHDEV_FDIR_INFO(ethdev);
	struct sssnic_ethdev_tcam *tcam;

	tcam = &fdir_info->tcam;

	ret = sssnic_ethdev_tcam_block_entry_free(tcam_block, entry_idx);
	if (ret != 0)
		return 0; /* not found was considered as success */

	if (tcam_block->used_entries == 0) {
		ret = sssnic_ethdev_tcam_block_free(ethdev, tcam_block);
		if (ret != 0)
			PMD_DRV_LOG(ERR, "Failed to free TCAM block:%u",
				tcam_block->id);
	}

	tcam->used_entries--;
	return 0;
}

static void
sssnic_ethdev_tcam_entry_init(struct sssnic_ethdev_fdir_flow_match *flow,
	struct sssnic_tcam_entry *entry)
{
	uint8_t i;
	uint8_t *flow_key;
	uint8_t *flow_mask;

	flow_key = (uint8_t *)&flow->key;
	flow_mask = (uint8_t *)&flow->mask;

	for (i = 0; i < sizeof(entry->key.data0); i++) {
		entry->key.data1[i] = flow_key[i] & flow_mask[i];
		entry->key.data0[i] =
			entry->key.data1[i] ^ flow_mask[i];
	}
}


static struct sssnic_ethdev_fdir_entry *
sssnic_ethdev_fdir_entry_lookup(struct sssnic_ethdev_fdir_info *fdir_info,
	struct sssnic_ethdev_fdir_rule *rule)
{
	struct sssnic_ethdev_fdir_entry *e;
	struct sssnic_ethdev_fdir_match *m;
	struct sssnic_ethdev_fdir_match *match = &rule->match;

	/* fast lookup */
	if (rule->cookie != NULL)
		return (struct sssnic_ethdev_fdir_entry *)rule->cookie;

	if (rule->match.type == SSSNIC_ETHDEV_FDIR_MATCH_FLOW) {
		TAILQ_FOREACH(e, &fdir_info->flow_entry_list, node)
		{
			m = &e->rule->match;
			if (memcmp(&match->flow, &m->flow, sizeof(m->flow)) ==
				0)
				return e;
		}
	} else if (rule->match.type == SSSNIC_ETHDEV_FDIR_MATCH_ETHERTYPE) {
		TAILQ_FOREACH(e, &fdir_info->ethertype_entry_list, node)
		{
			m = &e->rule->match;
			if (match->ethertype.key.ether_type ==
				m->ethertype.key.ether_type)
				return e;
		}
	}

	return NULL;
}

static inline void
sssnic_ethdev_fdir_entry_add(struct sssnic_ethdev_fdir_info *fdir_info,
	struct sssnic_ethdev_fdir_entry *entry)
{
	if (entry->rule->match.type == SSSNIC_ETHDEV_FDIR_MATCH_ETHERTYPE)
		TAILQ_INSERT_TAIL(&fdir_info->ethertype_entry_list, entry,
			node);
	else
		TAILQ_INSERT_TAIL(&fdir_info->flow_entry_list, entry, node);

	fdir_info->num_entries++;
}

static inline void
sssnic_ethdev_fdir_entry_del(struct sssnic_ethdev_fdir_info *fdir_info,
	struct sssnic_ethdev_fdir_entry *entry)
{
	if (entry->rule->match.type == SSSNIC_ETHDEV_FDIR_MATCH_ETHERTYPE)
		TAILQ_REMOVE(&fdir_info->ethertype_entry_list, entry, node);
	else
		TAILQ_REMOVE(&fdir_info->flow_entry_list, entry, node);

	fdir_info->num_entries--;
}

static int
sssnic_ethdev_fdir_arp_pkt_filter_set(struct rte_eth_dev *ethdev, uint16_t qid,
	int enabled)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	ret = sssnic_tcam_packet_type_filter_set(hw, SSSNIC_ETHDEV_PTYPE_ARP,
		qid, enabled);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to %s ARP packet filter!",
			enabled ? "enable" : "disable");
		return ret;
	}

	ret = sssnic_tcam_packet_type_filter_set(hw,
		SSSNIC_ETHDEV_PTYPE_ARP_REQ, qid, enabled);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to %s ARP request packet filter!",
			enabled ? "enable" : "disable");
		goto set_arp_req_fail;
	}

	ret = sssnic_tcam_packet_type_filter_set(hw,
		SSSNIC_ETHDEV_PTYPE_ARP_REP, qid, enabled);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to %s ARP reply packet filter!",
			enabled ? "enable" : "disable");
		goto set_arp_rep_fail;
	}

	return 0;

set_arp_rep_fail:
	sssnic_tcam_packet_type_filter_set(hw, SSSNIC_ETHDEV_PTYPE_ARP_REQ, qid,
		!enabled);
set_arp_req_fail:
	sssnic_tcam_packet_type_filter_set(hw, SSSNIC_ETHDEV_PTYPE_ARP, qid,
		!enabled);

	return ret;
}

static int
sssnic_ethdev_fdir_slow_pkt_filter_set(struct rte_eth_dev *ethdev, uint16_t qid,
	int enabled)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	ret = sssnic_tcam_packet_type_filter_set(hw, SSSNIC_ETHDEV_PTYPE_LACP,
		qid, enabled);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to %s LACP packet filter!",
			enabled ? "enable" : "disable");
		return ret;
	}

	ret = sssnic_tcam_packet_type_filter_set(hw, SSSNIC_ETHDEV_PTYPE_OAM,
		qid, enabled);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to %s OAM packet filter!",
			enabled ? "enable" : "disable");

		sssnic_tcam_packet_type_filter_set(hw, SSSNIC_ETHDEV_PTYPE_LACP,
			qid, !enabled);
	}

	return ret;
}

static int
sssnic_ethdev_fdir_lldp_pkt_filter_set(struct rte_eth_dev *ethdev, uint16_t qid,
	int enabled)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	ret = sssnic_tcam_packet_type_filter_set(hw, SSSNIC_ETHDEV_PTYPE_LLDP,
		qid, enabled);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to %s LLDP packet filter!",
			enabled ? "enable" : "disable");
		return ret;
	}

	ret = sssnic_tcam_packet_type_filter_set(hw, SSSNIC_ETHDEV_PTYPE_CDCP,
		qid, enabled);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to %s CDCP packet filter!",
			enabled ? "enable" : "disable");

		sssnic_tcam_packet_type_filter_set(hw, SSSNIC_ETHDEV_PTYPE_LLDP,
			qid, !enabled);
	}

	return ret;
}

static int
sssnic_ethdev_fdir_pkt_filter_set(struct rte_eth_dev *ethdev,
	uint16_t ether_type, uint16_t qid, int enabled)
{
	int ret;
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);

	switch (ether_type) {
	case RTE_ETHER_TYPE_ARP:
		ret = sssnic_ethdev_fdir_arp_pkt_filter_set(ethdev, qid,
			enabled);
		break;
	case RTE_ETHER_TYPE_RARP:
		ret = sssnic_tcam_packet_type_filter_set(hw,
			SSSNIC_ETHDEV_PTYPE_RARP, qid, enabled);
		break;
	case RTE_ETHER_TYPE_SLOW:
		ret = sssnic_ethdev_fdir_slow_pkt_filter_set(ethdev, qid,
			enabled);
		break;
	case RTE_ETHER_TYPE_LLDP:
		ret = sssnic_ethdev_fdir_lldp_pkt_filter_set(ethdev, qid,
			enabled);
		break;
	case 0x22e7: /* CNM ether type */
		ret = sssnic_tcam_packet_type_filter_set(hw,
			SSSNIC_ETHDEV_PTYPE_CNM, qid, enabled);
		break;
	case 0x8940: /* ECP ether type */
		ret = sssnic_tcam_packet_type_filter_set(hw,
			SSSNIC_ETHDEV_PTYPE_ECP, qid, enabled);
		break;
	default:
		PMD_DRV_LOG(ERR, "Ethertype 0x%x is not supported to filter!",
			ether_type);
		return -EINVAL;
	}

	if (ret != 0)
		PMD_DRV_LOG(ERR, "Failed to %s filter for ether type: %x.",
			enabled ? "enable" : "disable", ether_type);

	return ret;
}

static inline struct sssnic_ethdev_fdir_entry *
sssnic_ethdev_fdir_entry_alloc(void)
{
	struct sssnic_ethdev_fdir_entry *e;

	e = rte_zmalloc("sssnic_fdir_entry", sizeof(*e), 0);
	if (e != NULL)
		e->tcam_entry_idx = SSSNIC_ETHDEV_TCAM_ENTRY_INVAL_IDX;
	else
		PMD_DRV_LOG(ERR,
			"Failed to allocate memory for fdir entry struct!");

	return e;
}

static inline void
sssnic_ethdev_fdir_entry_free(struct sssnic_ethdev_fdir_entry *e)
{
	if (e != NULL)
		rte_free(e);
}

/* Apply fdir rule to HW */
static int
sssnic_ethdev_fdir_entry_enable(struct rte_eth_dev *ethdev,
	struct sssnic_ethdev_fdir_entry *entry)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct sssnic_tcam_entry tcam_entry;
	int ret;

	if (unlikely(entry->rule == NULL)) {
		PMD_DRV_LOG(ERR, "fdir rule is null!");
		return -EINVAL;
	}

	if (entry->enabled)
		return 0;

	if (entry->tcam_entry_idx != SSSNIC_ETHDEV_TCAM_ENTRY_INVAL_IDX) {
		memset(&tcam_entry, 0, sizeof(tcam_entry));
		sssnic_ethdev_tcam_entry_init(&entry->rule->match.flow,
			&tcam_entry);
		tcam_entry.result.qid = entry->rule->action.qid;
		tcam_entry.index =
			entry->tcam_entry_idx +
			(entry->tcam_block->id * SSSNIC_ETHDEV_TCAM_BLOCK_SZ);

		ret = sssnic_tcam_entry_add(hw, &tcam_entry);
		if (ret != 0)
			PMD_DRV_LOG(ERR,
				"Failed to add TCAM entry, block:%u, entry:%u, tcam_entry:%u",
				entry->tcam_block->id, entry->tcam_entry_idx,
				tcam_entry.index);

	} else {
		ret = sssnic_ethdev_fdir_pkt_filter_set(ethdev,
			entry->rule->match.ethertype.key.ether_type,
			entry->rule->action.qid, 1);
		if (ret != 0)
			PMD_DRV_LOG(ERR, "Failed to enable ethertype(%x) filter",
				entry->rule->match.ethertype.key.ether_type);
	}

	entry->enabled = 1;

	return ret;
}

/* remove fdir rule from HW */
static int
sssnic_ethdev_fdir_entry_disable(struct rte_eth_dev *ethdev,
	struct sssnic_ethdev_fdir_entry *entry)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	uint32_t tcam_entry_idx;
	int ret;

	if (unlikely(entry->rule == NULL)) {
		PMD_DRV_LOG(ERR, "fdir rule is null!");
		return -EINVAL;
	}

	if (!entry->enabled)
		return 0;

	if (entry->tcam_entry_idx != SSSNIC_ETHDEV_TCAM_ENTRY_INVAL_IDX) {
		tcam_entry_idx =
			entry->tcam_entry_idx +
			(entry->tcam_block->id * SSSNIC_ETHDEV_TCAM_BLOCK_SZ);

		ret = sssnic_tcam_entry_del(hw, tcam_entry_idx);
		if (ret != 0) {
			PMD_DRV_LOG(ERR,
				"Failed to del TCAM entry, block:%u, entry:%u",
				entry->tcam_block->id, entry->tcam_entry_idx);
			return ret;
		}
	} else {
		ret = sssnic_ethdev_fdir_pkt_filter_set(ethdev,
			entry->rule->match.ethertype.key.ether_type,
			entry->rule->action.qid, 0);
		if (ret != 0) {
			PMD_DRV_LOG(ERR,
				"Failed to disable ethertype(%x) filter",
				entry->rule->match.ethertype.key.ether_type);
			return ret;
		}
	}

	entry->enabled = 0;

	return 0;
}

static int
sssnic_ethdev_fdir_ethertype_rule_add(struct sssnic_ethdev_fdir_info *fdir_info,
	struct sssnic_ethdev_fdir_rule *rule)
{
	struct sssnic_ethdev_fdir_entry *fdir_entry;
	int ret;

	fdir_entry = sssnic_ethdev_fdir_entry_alloc();
	if (fdir_entry == NULL)
		return -ENOMEM;

	fdir_entry->rule = rule;

	ret = sssnic_ethdev_fdir_entry_enable(fdir_info->ethdev, fdir_entry);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to enable ethertype(%u) entry",
			rule->match.ethertype.key.ether_type);

		sssnic_ethdev_fdir_entry_free(fdir_entry);

		return ret;
	}

	rule->cookie = fdir_entry;
	sssnic_ethdev_fdir_entry_add(fdir_info, fdir_entry);

	return 0;
}

static int
sssnic_ethdev_fdir_ethertype_rule_del(struct sssnic_ethdev_fdir_info *fdir_info,
	struct sssnic_ethdev_fdir_rule *rule)
{
	struct sssnic_ethdev_fdir_entry *fdir_entry;
	int ret;

	fdir_entry = (struct sssnic_ethdev_fdir_entry *)rule->cookie;

	ret = sssnic_ethdev_fdir_entry_disable(fdir_info->ethdev, fdir_entry);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to disable ethertype(%u) entry",
			rule->match.ethertype.key.ether_type);
		return ret;
	}

	rule->cookie = NULL;
	sssnic_ethdev_fdir_entry_del(fdir_info, fdir_entry);
	sssnic_ethdev_fdir_entry_free(fdir_entry);

	return 0;
}

static int
sssnic_ethdev_fdir_flow_rule_add(struct sssnic_ethdev_fdir_info *fdir_info,
	struct sssnic_ethdev_fdir_rule *rule)
{
	struct sssnic_ethdev_fdir_entry *fdir_entry;
	int ret;

	fdir_entry = sssnic_ethdev_fdir_entry_alloc();
	if (fdir_entry == NULL)
		return -ENOMEM;

	fdir_entry->rule = rule;

	ret = sssnic_ethdev_tcam_entry_alloc(fdir_info->ethdev,
		&fdir_entry->tcam_block, &fdir_entry->tcam_entry_idx);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to alloc TCAM entry");
		goto tcam_entry_alloc_fail;
	}

	ret = sssnic_ethdev_fdir_entry_enable(fdir_info->ethdev, fdir_entry);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to enable fdir flow entry");
		goto fdir_entry_enable_fail;
	}

	rule->cookie = fdir_entry;
	sssnic_ethdev_fdir_entry_add(fdir_info, fdir_entry);

	return 0;

fdir_entry_enable_fail:
	sssnic_ethdev_tcam_entry_free(fdir_info->ethdev, fdir_entry->tcam_block,
		fdir_entry->tcam_entry_idx);
tcam_entry_alloc_fail:
	sssnic_ethdev_fdir_entry_free(fdir_entry);

	return ret;
}

static int
sssnic_ethdev_fdir_flow_rule_del(struct sssnic_ethdev_fdir_info *fdir_info,
	struct sssnic_ethdev_fdir_rule *rule)
{
	struct sssnic_ethdev_fdir_entry *fdir_entry;
	int ret;

	fdir_entry = (struct sssnic_ethdev_fdir_entry *)rule->cookie;

	ret = sssnic_ethdev_fdir_entry_disable(fdir_info->ethdev, fdir_entry);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to disable fdir flow entry");
		return ret;
	}

	rule->cookie = NULL;
	sssnic_ethdev_fdir_entry_del(fdir_info, fdir_entry);
	sssnic_ethdev_fdir_entry_free(fdir_entry);

	return 0;
}

int
sssnic_ethdev_fdir_rule_add(struct rte_eth_dev *ethdev,
	struct sssnic_ethdev_fdir_rule *rule)
{
	struct sssnic_ethdev_fdir_info *fdir_info;
	int ret;

	fdir_info = SSSNIC_ETHDEV_FDIR_INFO(ethdev);

	if (sssnic_ethdev_fdir_entry_lookup(fdir_info, rule) != NULL) {
		PMD_DRV_LOG(ERR, "FDIR rule exists!");
		return -EEXIST;
	}

	if (rule->match.type == SSSNIC_ETHDEV_FDIR_MATCH_ETHERTYPE) {
		ret = sssnic_ethdev_fdir_ethertype_rule_add(fdir_info, rule);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to add fdir ethertype rule");
			return ret;
		}
		PMD_DRV_LOG(DEBUG,
			"Added fdir ethertype rule, total number of rules: %u",
			fdir_info->num_entries);
	} else {
		ret = sssnic_ethdev_fdir_flow_rule_add(fdir_info, rule);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to add fdir flow rule");
			return ret;
		}
		PMD_DRV_LOG(DEBUG,
			"Added fdir flow rule, total number of rules: %u",
			fdir_info->num_entries);
	}

	ret = sssnic_ethdev_tcam_enable(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to enable TCAM");
		sssnic_ethdev_fdir_flow_rule_del(fdir_info, rule);
	}

	return ret;
}

int
sssnic_ethdev_fdir_rule_del(struct rte_eth_dev *ethdev,
	struct sssnic_ethdev_fdir_rule *fdir_rule)
{
	struct sssnic_ethdev_fdir_info *fdir_info;
	struct sssnic_ethdev_fdir_entry *entry;
	struct sssnic_ethdev_fdir_rule *rule;
	int ret;

	fdir_info = SSSNIC_ETHDEV_FDIR_INFO(ethdev);

	entry = sssnic_ethdev_fdir_entry_lookup(fdir_info, fdir_rule);
	if (entry == NULL)
		return 0;

	rule = entry->rule;
	if (rule != fdir_rule)
		return 0;

	if (rule->match.type == SSSNIC_ETHDEV_FDIR_MATCH_ETHERTYPE) {
		ret = sssnic_ethdev_fdir_ethertype_rule_del(fdir_info, rule);
		if (ret != 0) {
			PMD_DRV_LOG(ERR,
				"Failed to delete fdir ethertype rule!");
			return ret;
		}
		PMD_DRV_LOG(DEBUG,
			"Deleted fdir ethertype rule, total number of rules: %u",
			fdir_info->num_entries);
	} else {
		ret = sssnic_ethdev_fdir_flow_rule_del(fdir_info, rule);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to delete fdir flow rule!");
			return ret;
		}
		PMD_DRV_LOG(DEBUG,
			"Deleted fdir flow rule, total number of rules: %u",
			fdir_info->num_entries);
	}

	/* if there are no added rules, then disable TCAM */
	if (fdir_info->num_entries == 0) {
		ret = sssnic_ethdev_tcam_disable(ethdev);
		if (ret != 0) {
			PMD_DRV_LOG(NOTICE,
				"There are no added rules, but failed to disable TCAM");
			ret = 0;
		}
	}

	return ret;
}

int
sssnic_ethdev_fdir_rules_disable_by_queue(struct rte_eth_dev *ethdev,
	uint16_t qid)
{
	struct sssnic_ethdev_fdir_info *fdir_info;
	struct sssnic_ethdev_fdir_entry *entry;
	int ret;

	fdir_info = SSSNIC_ETHDEV_FDIR_INFO(ethdev);

	TAILQ_FOREACH(entry, &fdir_info->flow_entry_list, node)
	{
		if (entry->rule->action.qid == qid) {
			ret = sssnic_ethdev_fdir_entry_disable(ethdev, entry);
			if (ret != 0) {
				PMD_DRV_LOG(ERR,
					"Failed to disable flow rule of queue:%u",
					qid);

				return ret;
			}
		}
	}

	return 0;
}

int
sssnic_ethdev_fdir_rules_enable_by_queue(struct rte_eth_dev *ethdev,
	uint16_t qid)
{
	struct sssnic_ethdev_fdir_info *fdir_info;
	struct sssnic_ethdev_fdir_entry *entry;
	int ret;

	fdir_info = SSSNIC_ETHDEV_FDIR_INFO(ethdev);

	TAILQ_FOREACH(entry, &fdir_info->flow_entry_list, node)
	{
		if (entry->rule->action.qid == qid) {
			ret = sssnic_ethdev_fdir_entry_enable(ethdev, entry);
			if (ret != 0) {
				PMD_DRV_LOG(ERR,
					"Failed to enable flow rule of queue:%u",
					qid);

				return ret;
			}
		}
	}

	return 0;
}

int
sssnic_ethdev_fdir_rules_flush(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_ethdev_fdir_entry *entry, *tmp;
	struct sssnic_ethdev_fdir_rule *rule;
	int ret;

	RTE_TAILQ_FOREACH_SAFE(entry, &netdev->fdir_info->flow_entry_list, node,
		tmp)
	{
		rule = entry->rule;
		ret = sssnic_ethdev_fdir_entry_disable(ethdev, entry);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to disable fdir flow entry");
			return ret;
		}
		TAILQ_REMOVE(&netdev->fdir_info->flow_entry_list, entry, node);
		sssnic_ethdev_fdir_entry_free(entry);
		sssnic_ethdev_fdir_rule_free(rule);
	}

	RTE_TAILQ_FOREACH_SAFE(entry, &netdev->fdir_info->ethertype_entry_list,
		node, tmp)
	{
		rule = entry->rule;
		ret = sssnic_ethdev_fdir_entry_disable(ethdev, entry);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to disable ethertype(%u) entry",
				rule->match.ethertype.key.ether_type);
			return ret;
		}
		TAILQ_REMOVE(&netdev->fdir_info->ethertype_entry_list, entry,
			node);
		sssnic_ethdev_fdir_entry_free(entry);
		sssnic_ethdev_fdir_rule_free(rule);
	}

	return 0;
}

int
sssnic_ethdev_fdir_init(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);

	PMD_INIT_FUNC_TRACE();

	netdev->fdir_info = rte_zmalloc("sssnic_fdir_info",
		sizeof(struct sssnic_ethdev_fdir_info), 0);

	if (netdev->fdir_info == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc fdir info memory for port %u",
			ethdev->data->port_id);
		return -ENOMEM;
	}

	netdev->fdir_info->ethdev = ethdev;

	TAILQ_INIT(&netdev->fdir_info->ethertype_entry_list);
	TAILQ_INIT(&netdev->fdir_info->flow_entry_list);

	sssnic_ethdev_tcam_init(ethdev);

	return 0;
}

void
sssnic_ethdev_fdir_shutdown(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_ethdev_fdir_entry *entry, *tmp;

	PMD_INIT_FUNC_TRACE();

	if (netdev->fdir_info == NULL)
		return;

	RTE_TAILQ_FOREACH_SAFE(entry, &netdev->fdir_info->flow_entry_list, node,
		tmp)
	{
		TAILQ_REMOVE(&netdev->fdir_info->flow_entry_list, entry, node);
		sssnic_ethdev_fdir_entry_free(entry);
	}

	RTE_TAILQ_FOREACH_SAFE(entry, &netdev->fdir_info->ethertype_entry_list,
		node, tmp)
	{
		TAILQ_REMOVE(&netdev->fdir_info->ethertype_entry_list, entry,
			node);
		sssnic_ethdev_fdir_entry_free(entry);
	}

	sssnic_ethdev_tcam_shutdown(ethdev);

	rte_free(netdev->fdir_info);
}
