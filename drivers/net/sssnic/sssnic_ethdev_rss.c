/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <error.h>
#include <rte_common.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"
#include "sssnic_ethdev.h"
#include "sssnic_ethdev_rx.h"
#include "sssnic_ethdev_tx.h"
#include "sssnic_ethdev_stats.h"
#include "sssnic_ethdev_rss.h"
#include "base/sssnic_hw.h"
#include "base/sssnic_api.h"

static uint8_t default_rss_hash_key[SSSNIC_ETHDEV_RSS_KEY_SZ] = { 0x6d, 0x5a,
	0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
	0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb,
	0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac,
	0x01, 0xfa };

#define SSSNIC_ETHDEV_RSS_IPV4                                                 \
	(RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_FRAG_IPV4 |                            \
		RTE_ETH_RSS_NONFRAG_IPV4_OTHER)
#define SSSNIC_ETHDEV_RSS_IPV6                                                 \
	(RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_FRAG_IPV6 |                            \
		RTE_ETH_RSS_NONFRAG_IPV6_OTHER)

static inline void
sssnic_ethdev_rss_type_from_rss_hf(struct sssnic_rss_type *rss_type,
	uint64_t rss_hf)
{
	rss_type->mask = 0;
	rss_type->ipv4 = (rss_hf & SSSNIC_ETHDEV_RSS_IPV4) ? 1 : 0;
	rss_type->ipv6 = (rss_hf & SSSNIC_ETHDEV_RSS_IPV6) ? 1 : 0;
	rss_type->ipv6_ex = (rss_hf & RTE_ETH_RSS_IPV6_EX) ? 1 : 0;
	rss_type->ipv4_tcp = (rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_TCP) ? 1 : 0;
	rss_type->ipv6_tcp = (rss_hf & RTE_ETH_RSS_NONFRAG_IPV6_TCP) ? 1 : 0;
	rss_type->ipv6_tcp_ex = (rss_hf & RTE_ETH_RSS_IPV6_TCP_EX) ? 1 : 0;
	rss_type->ipv4_udp = (rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_UDP) ? 1 : 0;
	rss_type->ipv6_udp = (rss_hf & RTE_ETH_RSS_NONFRAG_IPV6_UDP) ? 1 : 0;
}

static inline uint64_t
sssnic_ethdev_rss_type_to_rss_hf(struct sssnic_rss_type *rss_type)
{
	uint64_t rss_hf = 0;

	rss_hf |= (rss_type->ipv4 == 0) ? 0 : SSSNIC_ETHDEV_RSS_IPV4;
	rss_hf |= (rss_type->ipv6 == 0) ? 0 : SSSNIC_ETHDEV_RSS_IPV6;
	rss_hf |= (rss_type->ipv6_ex == 0) ? 0 : RTE_ETH_RSS_IPV6_EX;
	rss_hf |= (rss_type->ipv4_tcp == 0) ? 0 : RTE_ETH_RSS_NONFRAG_IPV4_TCP;
	rss_hf |= (rss_type->ipv6_tcp == 0) ? 0 : RTE_ETH_RSS_NONFRAG_IPV6_TCP;
	rss_hf |= (rss_type->ipv6_tcp_ex == 0) ? 0 : RTE_ETH_RSS_IPV6_TCP_EX;
	rss_hf |= (rss_type->ipv4_udp == 0) ? 0 : RTE_ETH_RSS_NONFRAG_IPV4_UDP;
	rss_hf |= (rss_type->ipv6_udp == 0) ? 0 : RTE_ETH_RSS_NONFRAG_IPV6_UDP;

	return rss_hf;
}

int
sssnic_ethdev_rss_hash_update(struct rte_eth_dev *ethdev,
	struct rte_eth_rss_conf *rss_conf)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct sssnic_rss_type rss_type;
	uint64_t rss_hf;
	uint8_t *rss_key;
	uint16_t rss_key_len;
	int ret;

	rss_key = rss_conf->rss_key;
	rss_key_len = rss_conf->rss_key_len;
	if (rss_key == NULL) {
		rss_key = default_rss_hash_key;
		rss_key_len = SSSNIC_ETHDEV_RSS_KEY_SZ;
	} else if (rss_key_len > SSSNIC_ETHDEV_RSS_KEY_SZ) {
		PMD_DRV_LOG(ERR, "RSS hash key length too long");
		return -EINVAL;
	}

	ret = sssnic_rss_hash_key_set(hw, rss_key, rss_key_len);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set RSS hash key");
		return ret;
	}

	rte_memcpy(netdev->rss_hash_key, rss_key, rss_key_len);

	rss_hf = rss_conf->rss_hf;

	if (rss_hf == 0)
		rss_hf = SSSNIC_ETHDEV_RSS_OFFLOAD_FLOW_TYPES;
	else
		rss_hf &= SSSNIC_ETHDEV_RSS_OFFLOAD_FLOW_TYPES;

	sssnic_ethdev_rss_type_from_rss_hf(&rss_type, rss_hf);
	rss_type.valid = 1;
	ret = sssnic_rss_type_set(hw, &rss_type);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set RSS type: %x", rss_type.mask);
		return ret;
	}

	return 0;
}

int
sssnic_ethdev_rss_hash_config_get(struct rte_eth_dev *ethdev,
	struct rte_eth_rss_conf *rss_conf)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw;
	struct sssnic_rss_type rss_type;
	int ret;

	hw = SSSNIC_NETDEV_TO_HW(netdev);

	if (!netdev->rss_enable) {
		PMD_DRV_LOG(NOTICE, "Port %u RSS is not enabled",
			ethdev->data->port_id);
		rss_conf->rss_hf = 0;
		return 0;
	}

	ret = sssnic_rss_type_get(hw, &rss_type);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to get RSS type");
		return ret;
	}
	rss_conf->rss_hf = sssnic_ethdev_rss_type_to_rss_hf(&rss_type);

	if (rss_conf->rss_key != NULL &&
		rss_conf->rss_key_len >= SSSNIC_ETHDEV_RSS_KEY_SZ) {
		rte_memcpy(rss_conf->rss_key, netdev->rss_hash_key,
			SSSNIC_ETHDEV_RSS_KEY_SZ);
		rss_conf->rss_key_len = SSSNIC_ETHDEV_RSS_KEY_SZ;
	}

	return 0;
}

int
sssnic_ethdev_rss_reta_update(struct rte_eth_dev *ethdev,
	struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw;
	uint16_t *entries;
	int i, group, idx;
	int ret;

	if (!netdev->rss_enable) {
		PMD_DRV_LOG(ERR, "Port %u RSS is not enabled",
			ethdev->data->port_id);
		return -EINVAL;
	}

	if (reta_size != SSSNIC_ETHDEV_RSS_RETA_SZ) {
		PMD_DRV_LOG(ERR, "Invalid reta size:%u, expected reta size:%u ",
			reta_size, SSSNIC_ETHDEV_RSS_RETA_SZ);
		return -EINVAL;
	}

	hw = SSSNIC_NETDEV_TO_HW(netdev);

	entries = rte_zmalloc(NULL,
		SSSNIC_ETHDEV_RSS_RETA_SZ * sizeof(uint16_t), 0);
	if (entries == NULL) {
		PMD_DRV_LOG(ERR, "Could not allocate memory");
		return -ENOMEM;
	}

	ret = sssnic_rss_indir_table_get(hw, entries,
		SSSNIC_ETHDEV_RSS_RETA_SZ);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to get RSS indirect table");
		goto out;
	}

	for (i = 0; i < SSSNIC_ETHDEV_RSS_RETA_SZ; i++) {
		group = i / RTE_ETH_RETA_GROUP_SIZE;
		idx = i % RTE_ETH_RETA_GROUP_SIZE;
		if ((reta_conf[group].mask & RTE_BIT64(idx)) != 0)
			entries[i] = reta_conf[group].reta[idx];
	}

	ret = sssnic_rss_indir_table_set(hw, entries,
		SSSNIC_ETHDEV_RSS_RETA_SZ);
	if (ret != 0)
		PMD_DRV_LOG(ERR, "Failed to set RSS indirect table");

out:
	rte_free(entries);
	return ret;
}

int
sssnic_ethdev_rss_reta_query(struct rte_eth_dev *ethdev,
	struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw;
	uint16_t *entries;
	int i, group, idx;
	int ret;

	if (!netdev->rss_enable) {
		PMD_DRV_LOG(ERR, "Port %u RSS is not enabled",
			ethdev->data->port_id);
		return -EINVAL;
	}

	if (reta_size != SSSNIC_ETHDEV_RSS_RETA_SZ) {
		PMD_DRV_LOG(ERR, "Invalid reta size:%u, expected reta size:%u ",
			reta_size, SSSNIC_ETHDEV_RSS_RETA_SZ);
		return -EINVAL;
	}

	hw = SSSNIC_NETDEV_TO_HW(netdev);

	entries = rte_zmalloc(NULL,
		SSSNIC_ETHDEV_RSS_RETA_SZ * sizeof(uint16_t), 0);
	if (entries == NULL) {
		PMD_DRV_LOG(ERR, "Could not allocate memory");
		return -ENOMEM;
	}

	ret = sssnic_rss_indir_table_get(hw, entries,
		SSSNIC_ETHDEV_RSS_RETA_SZ);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to get RSS indirect table");
		goto out;
	}

	for (i = 0; i < SSSNIC_ETHDEV_RSS_RETA_SZ; i++) {
		group = i / RTE_ETH_RETA_GROUP_SIZE;
		idx = i % RTE_ETH_RETA_GROUP_SIZE;
		if ((reta_conf[group].mask & RTE_BIT64(idx)) != 0)
			reta_conf[group].reta[idx] = entries[i];
	}

out:
	rte_free(entries);
	return ret;
}

int
sssnic_ethdev_rss_reta_reset(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	uint16_t *entries;
	uint16_t nb_rxq;
	uint8_t rxq_state;
	uint16_t qid, i = 0;
	int ret;

	if (!netdev->rss_enable)
		return 0;

	entries = rte_zmalloc(NULL,
		SSSNIC_ETHDEV_RSS_RETA_SZ * sizeof(uint16_t), 0);
	if (entries == NULL) {
		PMD_DRV_LOG(ERR, "Could not allocate memory");
		return -ENOMEM;
	}

	nb_rxq = ethdev->data->nb_rx_queues;

	if (netdev->num_started_rxqs == 0) {
		while (i < SSSNIC_ETHDEV_RSS_RETA_SZ)
			entries[i++] = 0xffff;
	} else {
		while (i < SSSNIC_ETHDEV_RSS_RETA_SZ) {
			for (qid = 0; qid < nb_rxq; qid++) {
				if (i >= SSSNIC_ETHDEV_RSS_RETA_SZ)
					break;
				rxq_state = ethdev->data->rx_queue_state[qid];
				if (rxq_state == RTE_ETH_QUEUE_STATE_STARTED)
					entries[i++] = qid;
			}
		}
	}

	ret = sssnic_rss_indir_table_set(hw, entries,
		SSSNIC_ETHDEV_RSS_RETA_SZ);
	if (ret != 0)
		PMD_DRV_LOG(ERR, "Failed to set RSS indirect table");

	rte_free(entries);

	return ret;
}

int
sssnic_ethdev_rss_setup(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct rte_eth_conf *dev_conf = &ethdev->data->dev_conf;
	struct rte_eth_rss_conf *rss_conf;
	int ret;

	if (!((dev_conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_RSS_HASH) &&
		    ethdev->data->nb_rx_queues > 1)) {
		PMD_DRV_LOG(INFO, "RSS is not enabled");
		return 0;
	}

	if (netdev->rss_enable)
		return 0;

	ret = sssnic_rss_profile_create(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to create RSS profile");
		return ret;
	}

	rss_conf = &dev_conf->rx_adv_conf.rss_conf;
	ret = sssnic_ethdev_rss_hash_update(ethdev, rss_conf);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to setup RSS config");
		goto err_out;
	}

	ret = sssnic_rss_hash_engine_set(hw, SSSNIC_RSS_HASH_ENGINE_TOEP);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set RSS hash engine");
		goto err_out;
	}

	ret = sssnic_rss_enable_set(hw, true);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to enable RSS");
		goto err_out;
	}

	netdev->rss_enable = true;

	PMD_DRV_LOG(INFO, "Enabled RSS");

	return 0;

err_out:
	sssnic_rss_profile_destroy(hw);
	return ret;
}

int
sssnic_ethdev_rss_shutdown(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	if (!netdev->rss_enable)
		return 0;

	ret = sssnic_rss_enable_set(hw, false);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to disable rss");
		return ret;
	}

	ret = sssnic_rss_profile_destroy(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to delete rss profile");
		return ret;
	}

	netdev->rss_enable = false;

	return 0;
}
