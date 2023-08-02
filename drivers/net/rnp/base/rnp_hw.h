/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#ifndef __RNP_HW_H__
#define __RNP_HW_H__

struct rnp_hw {
	void *back;
	char *iobar0;
	uint32_t iobar0_len;
	char *iobar4;
	uint32_t iobar4_len;

	uint16_t device_id;
	uint16_t vendor_id;
} __rte_cache_aligned;

#endif /* __RNP_H__*/
