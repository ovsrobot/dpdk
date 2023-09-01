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

int sssnic_msix_attr_get(struct sssnic_hw *hw, uint16_t msix_idx,
	struct sssnic_msix_attr *attr);
int sssnic_msix_attr_set(struct sssnic_hw *hw, uint16_t msix_idx,
	struct sssnic_msix_attr *attr);
int sssnic_capability_get(struct sssnic_hw *hw, struct sssnic_capability *capa);

#endif /* _SSSNIC_API_H_ */
