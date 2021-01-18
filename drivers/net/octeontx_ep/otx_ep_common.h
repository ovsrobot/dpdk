/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell.
 */
#ifndef _OTX_EP_COMMON_H_
#define _OTX_EP_COMMON_H_

#define otx_ep_printf(level, fmt, args...)		\
	rte_log(RTE_LOG_ ## level, RTE_LOGTYPE_PMD,		\
		 fmt, ##args)

#define otx_ep_info(fmt, args...)				\
	otx_ep_printf(INFO, fmt, ##args)

#define otx_ep_err(fmt, args...)				\
	otx_ep_printf(ERR, fmt, ##args)

#define otx_ep_dbg(fmt, args...)				\
	otx_ep_printf(DEBUG, fmt, ##args)

/* OTX_EP EP VF device data structure */
struct otx_ep_device {
	/* PCI device pointer */
	struct rte_pci_device *pdev;
	uint16_t chip_id;
	struct rte_eth_dev *eth_dev;
	int port_id;
	/* Memory mapped h/w address */
	uint8_t *hw_addr;
	int port_configured;
};
#endif  /* _OTX_EP_COMMON_H_ */
