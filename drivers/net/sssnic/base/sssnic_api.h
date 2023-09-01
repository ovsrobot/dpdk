/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_API_H_
#define _SSSNIC_API_H_

struct sssnic_msix_attr {
	uint32_t lli_set;
	uint32_t coalescing_set;
	uint8_t lli_credit;
	uint8_t lli_timer;
	uint8_t pending_limit;
	uint8_t coalescing_timer;
	uint8_t resend_timer;
};

struct sssnic_capability {
	uint16_t max_num_txq;
	uint16_t max_num_rxq;
	uint8_t phy_port;
	uint8_t cos;
};

struct sssnic_netif_link_info {
	uint8_t status;
	uint8_t type;
	uint8_t autoneg_capa;
	uint8_t autoneg;
	uint8_t duplex;
	uint8_t speed;
	uint8_t fec;
};

int sssnic_msix_attr_get(struct sssnic_hw *hw, uint16_t msix_idx,
	struct sssnic_msix_attr *attr);
int sssnic_msix_attr_set(struct sssnic_hw *hw, uint16_t msix_idx,
	struct sssnic_msix_attr *attr);
int sssnic_capability_get(struct sssnic_hw *hw, struct sssnic_capability *capa);
int sssnic_mac_addr_get(struct sssnic_hw *hw, uint8_t *addr);
int sssnic_mac_addr_update(struct sssnic_hw *hw, uint8_t *new, uint8_t *old);
int sssnic_mac_addr_add(struct sssnic_hw *hw, uint8_t *addr);
int sssnic_mac_addr_del(struct sssnic_hw *hw, uint8_t *addr);
int sssnic_netif_link_status_get(struct sssnic_hw *hw, uint8_t *status);
int sssnic_netif_link_info_get(struct sssnic_hw *hw,
	struct sssnic_netif_link_info *info);
int sssnic_netif_enable_set(struct sssnic_hw *hw, uint8_t state);
int sssnic_port_enable_set(struct sssnic_hw *hw, bool state);
int sssnic_rxq_flush(struct sssnic_hw *hw, uint16_t qid);

#endif /* _SSSNIC_API_H_ */
