/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZXDH_COMMON_H_
#define _ZXDH_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_ethdev.h>

#include "zxdh_ethdev.h"

struct zxdh_res_para {
	uint64_t virt_addr;
	uint16_t pcie_id;
	uint16_t src_type; /* refer to BAR_DRIVER_TYPE */
};

int32_t zxdh_phyport_get(struct rte_eth_dev *dev, uint8_t *phyport);
int32_t zxdh_pannelid_get(struct rte_eth_dev *dev, uint8_t *pannelid);

#ifdef __cplusplus
}
#endif

#endif /* _ZXDH_COMMON_H_ */
