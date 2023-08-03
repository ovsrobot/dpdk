/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#ifndef __RNP_HW_H__
#define __RNP_HW_H__

struct rnp_eth_adapter;
struct rnp_hw {
	struct rnp_eth_adapter *back;
	void *iobar0;
	uint32_t iobar0_len;
	void *iobar4;
	uint32_t iobar4_len;

	uint16_t device_id;
	uint16_t vendor_id;
} __rte_cache_aligned;

#endif /* __RNP_H__*/
