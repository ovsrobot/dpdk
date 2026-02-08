/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <ethdev_driver.h>
#include "sxe.h"
#include "sxe_offload.h"
#include "sxe_logs.h"
#include "sxe_compat_version.h"
#include "sxe_queue_common.h"
#include "sxe_offload_common.h"

static u8 rss_sxe_key[40] = {
	0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
	0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
	0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
	0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
	0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA,
};

#define SXE_4_BIT_WIDTH  (CHAR_BIT / 2)
#define SXE_4_BIT_MASK   RTE_LEN2MASK(SXE_4_BIT_WIDTH, u8)
#define SXE_8_BIT_WIDTH  CHAR_BIT
#define SXE_8_BIT_MASK   UINT8_MAX

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_FILTER_CTRL
u8 *sxe_rss_hash_key_get(void)
{
	return rss_sxe_key;
}
#endif

u64 sxe_rx_queue_offload_capa_get(struct rte_eth_dev *dev)
{
	return __sxe_rx_queue_offload_capa_get(dev);
}

u64 sxe_rx_port_offload_capa_get(struct rte_eth_dev *dev)
{
	return __sxe_rx_port_offload_capa_get(dev);
}

u64 sxe_tx_queue_offload_capa_get(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);

	return 0;
}

u64 sxe_tx_port_offload_capa_get(struct rte_eth_dev *dev)
{
	return __sxe_tx_port_offload_capa_get(dev);
}

void sxe_rss_disable(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	PMD_INIT_FUNC_TRACE();

	sxe_hw_rss_cap_switch(hw, false);
}

void sxe_rss_hash_set(struct sxe_hw *hw,
				struct rte_eth_rss_conf *rss_conf)
{
	u8  *hash_key;
	u32 rss_key[SXE_MAX_RSS_KEY_ENTRIES];
	u16 i;
	u64 rss_hf;
	u32 rss_field = 0;

	PMD_INIT_FUNC_TRACE();

	hash_key = rss_conf->rss_key;
	if (hash_key != NULL) {
		for (i = 0; i < SXE_MAX_RSS_KEY_ENTRIES; i++) {
			rss_key[i]  = hash_key[(i * 4)];
			rss_key[i] |= hash_key[(i * 4) + 1] << 8;
			rss_key[i] |= hash_key[(i * 4) + 2] << 16;
			rss_key[i] |= hash_key[(i * 4) + 3] << 24;
		}
		sxe_hw_rss_key_set_all(hw, rss_key);
	}

	rss_hf = rss_conf->rss_hf;
	if (rss_hf & RTE_ETH_RSS_IPV4)
		rss_field |= SXE_MRQC_RSS_FIELD_IPV4;

	if (rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_TCP)
		rss_field |= SXE_MRQC_RSS_FIELD_IPV4_TCP;

	if (rss_hf & RTE_ETH_RSS_IPV6)
		rss_field |= SXE_MRQC_RSS_FIELD_IPV6;

	if (rss_hf & RTE_ETH_RSS_NONFRAG_IPV6_TCP)
		rss_field |= SXE_MRQC_RSS_FIELD_IPV6_TCP;

	if (rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_UDP)
		rss_field |= SXE_MRQC_RSS_FIELD_IPV4_UDP;

	if (rss_hf & RTE_ETH_RSS_NONFRAG_IPV6_UDP)
		rss_field |= SXE_MRQC_RSS_FIELD_IPV6_UDP;

	sxe_hw_rss_field_set(hw, rss_field);

	sxe_hw_rss_cap_switch(hw, true);
}

void sxe_rss_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_rss_conf *rss_conf;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u16 i;
	u16 j;
	u8  rss_indir_tbl[SXE_MAX_RETA_ENTRIES];

	PMD_INIT_FUNC_TRACE();

	if (!adapter->rss_reta_updated) {
		for (i = 0, j = 0; i < SXE_MAX_RETA_ENTRIES; i++, j++) {
			if (j == dev->data->nb_rx_queues)
				j = 0;

			rss_indir_tbl[i] = j;
		}

		sxe_hw_rss_redir_tbl_set_all(hw, rss_indir_tbl);
	}

	rss_conf = &dev->data->dev_conf.rx_adv_conf.rss_conf;
	if ((rss_conf->rss_hf & SXE_RSS_OFFLOAD_ALL) == 0) {
		PMD_LOG_INFO(INIT, "user rss config match hw supports is 0");
		sxe_rss_disable(dev);
		return;
	}

	if (rss_conf->rss_key == NULL)
		rss_conf->rss_key = rss_sxe_key;

	sxe_rss_hash_set(hw, rss_conf);
}

s32 sxe_rss_reta_update(struct rte_eth_dev *dev,
			struct rte_eth_rss_reta_entry64 *reta_conf,
			u16 reta_size)
{
	u16 i;
	u8 j, mask;
	u32 reta, r;
	u16 idx, shift;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct rte_eth_dev_data *dev_data = dev->data;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret = 0;

	PMD_INIT_FUNC_TRACE();

	if (!dev_data->dev_started) {
		PMD_LOG_ERR(DRV,
			"port %d must be started before rss reta update",
			 dev_data->port_id);
		ret = -EIO;
		goto l_end;
	}

	if (reta_size != RTE_ETH_RSS_RETA_SIZE_128) {
		PMD_LOG_ERR(DRV, "The size of hash lookup table configured "
			"(%d) doesn't match the number hardware can supported "
			"(%d)", reta_size, RTE_ETH_RSS_RETA_SIZE_128);
		ret = -EINVAL;
		goto l_end;
	}

	for (i = 0; i < reta_size; i += SXE_4_BIT_WIDTH) {
		idx = i / RTE_ETH_RETA_GROUP_SIZE;
		shift = i % RTE_ETH_RETA_GROUP_SIZE;
		mask = (u8)((reta_conf[idx].mask >> shift) &
						SXE_4_BIT_MASK);
		if (!mask)
			continue;

		if (mask == SXE_4_BIT_MASK)
			r = 0;
		else
			r = sxe_hw_rss_redir_tbl_get_by_idx(hw, i);

		for (j = 0, reta = 0; j < SXE_4_BIT_WIDTH; j++) {
			if (mask & (0x1 << j)) {
				reta |= reta_conf[idx].reta[shift + j] <<
						(CHAR_BIT * j);
			} else {
				reta |= r & (SXE_8_BIT_MASK <<
					(CHAR_BIT * j));
			}
		}

		sxe_hw_rss_redir_tbl_set_by_idx(hw, i, reta);
	}
	adapter->rss_reta_updated = true;

l_end:
	return ret;
}

s32 sxe_rss_reta_query(struct rte_eth_dev *dev,
			 struct rte_eth_rss_reta_entry64 *reta_conf,
			 u16 reta_size)
{
	u16 i;
	u8 j, mask;
	u32 reta;
	u16 idx, shift;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret = 0;

	PMD_INIT_FUNC_TRACE();
	if (reta_size != RTE_ETH_RSS_RETA_SIZE_128) {
		PMD_LOG_ERR(DRV, "the size of hash lookup table configured "
			"(%d) doesn't match the number hardware can supported "
			"(%d)", reta_size, RTE_ETH_RSS_RETA_SIZE_128);
		ret = -EINVAL;
		goto l_end;
	}

	for (i = 0; i < reta_size; i += SXE_4_BIT_WIDTH) {
		idx = i / RTE_ETH_RETA_GROUP_SIZE;
		shift = i % RTE_ETH_RETA_GROUP_SIZE;
		mask = (u8)((reta_conf[idx].mask >> shift) &
						SXE_4_BIT_MASK);
		if (!mask)
			continue;

		reta = sxe_hw_rss_redir_tbl_get_by_idx(hw, i);
		for (j = 0; j < SXE_4_BIT_WIDTH; j++) {
			if (mask & (0x1 << j)) {
				reta_conf[idx].reta[shift + j] =
					((reta >> (CHAR_BIT * j)) &
						SXE_8_BIT_MASK);
			}
		}
	}

l_end:
	return ret;
}

s32 sxe_rss_hash_update(struct rte_eth_dev *dev,
			struct rte_eth_rss_conf *rss_conf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u64 rss_hf;
	s32 ret = 0;

	rss_hf = (rss_conf->rss_hf & SXE_RSS_OFFLOAD_ALL);

	if (!sxe_hw_is_rss_enabled(hw)) {
		if (rss_hf != 0) {
			PMD_LOG_ERR(DRV, "rss not init but want set");
			ret = -EINVAL;
			goto l_end;
		}

		goto l_end;
	}

	if (rss_hf == 0) {
		PMD_LOG_ERR(DRV, "rss init but want disable it");
		ret = -EINVAL;
		goto l_end;
	}

	sxe_rss_hash_set(hw, rss_conf);

l_end:
	return ret;
}

s32 sxe_rss_hash_conf_get(struct rte_eth_dev *dev,
				struct rte_eth_rss_conf *rss_conf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u8 *hash_key;
	u32 rss_field;
	u32 rss_key;
	u64 rss_hf;
	u16 i;

	hash_key = rss_conf->rss_key;
	if (hash_key != NULL) {
		for (i = 0; i < SXE_MAX_RSS_KEY_ENTRIES; i++) {
			rss_key = sxe_hw_rss_key_get_by_idx(hw, i);
			hash_key[(i * 4)] = rss_key & 0x000000FF;
			hash_key[(i * 4) + 1] = (rss_key >> 8) & 0x000000FF;
			hash_key[(i * 4) + 2] = (rss_key >> 16) & 0x000000FF;
			hash_key[(i * 4) + 3] = (rss_key >> 24) & 0x000000FF;
		}
	}


	if (!sxe_hw_is_rss_enabled(hw)) {
		rss_conf->rss_hf = 0;
		PMD_LOG_INFO(DRV, "rss not enabled, return 0");
		goto l_end;
	}

	rss_hf = 0;
	rss_field = sxe_hw_rss_field_get(hw);
	if (rss_field & SXE_MRQC_RSS_FIELD_IPV4)
		rss_hf |= RTE_ETH_RSS_IPV4;

	if (rss_field & SXE_MRQC_RSS_FIELD_IPV4_TCP)
		rss_hf |= RTE_ETH_RSS_NONFRAG_IPV4_TCP;

	if (rss_field & SXE_MRQC_RSS_FIELD_IPV4_UDP)
		rss_hf |= RTE_ETH_RSS_NONFRAG_IPV4_UDP;

	if (rss_field & SXE_MRQC_RSS_FIELD_IPV6)
		rss_hf |= RTE_ETH_RSS_IPV6;

	if (rss_field & SXE_MRQC_RSS_FIELD_IPV6_TCP)
		rss_hf |= RTE_ETH_RSS_NONFRAG_IPV6_TCP;

	if (rss_field & SXE_MRQC_RSS_FIELD_IPV6_UDP)
		rss_hf |= RTE_ETH_RSS_NONFRAG_IPV6_UDP;

	PMD_LOG_DEBUG(DRV, "got rss hash func=0x%" SXE_PRIX64, rss_hf);
	rss_conf->rss_hf = rss_hf;

l_end:
	return 0;
}
