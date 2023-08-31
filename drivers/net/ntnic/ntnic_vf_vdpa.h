/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTNIC_VF_VDPA_H__
#define __NTNIC_VF_VDPA_H__

extern int ntvf_vdpa_logtype;

#define LOG_FUNC_TRACE
#ifdef LOG_FUNC_TRACE
#define LOG_FUNC_ENTER() NT_LOG(DBG, VDPA, "%s: enter\n", __func__)
#define LOG_FUNC_LEAVE() NT_LOG(DBG, VDPA, "%s: leave\n", __func__)
#else
#define LOG_FUNC_ENTER()
#define LOG_FUNC_LEAVE()
#endif

int ntvf_vdpa_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			struct rte_pci_device *pci_dev);
int ntvf_vdpa_pci_remove(struct rte_pci_device *pci_dev);

void ntvf_vdpa_reset_hw(int vid);

#endif /* __NTNIC_VF_VDPA_H__ */
