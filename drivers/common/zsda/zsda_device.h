/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_DEVICE_H_
#define _ZSDA_DEVICE_H_

#include "bus_pci_driver.h"

#include <rte_bus_pci.h>

#include "zsda_common.h"
#include "zsda_logs.h"

struct zsda_device_info {
	const struct rte_memzone *mz;
	/**< mz to store the：  struct zsda_pci_device ,    so it can be
	 * shared across processes
	 */

	struct rte_pci_device *pci_dev;

	struct rte_device comp_rte_dev;
	/**< This represents the compression subset of this pci device.
	 * Register with this rather than with the one in
	 * pci_dev so that its driver can have a compression-specific name
	 */
};

extern struct zsda_device_info zsda_devs[];

struct zsda_comp_dev_private;

struct zsda_qp_hw_data {
	bool used;

	uint8_t tx_ring_num;
	uint8_t rx_ring_num;
	uint16_t tx_msg_size;
	uint16_t rx_msg_size;
};

struct zsda_qp_hw {
	struct zsda_qp_hw_data data[MAX_QPS_ON_FUNCTION];
};

/*
 * This struct holds all the data about a ZSDA pci device
 * including data about all services it supports.
 * It contains
 *  - hw_data
 *  - config data
 *  - runtime data
 * Note: as this data can be shared in a multi-process scenario,
 * any pointers in it must also point to shared memory.
 */
struct zsda_pci_device {
	/* Data used by all services */
	char name[ZSDA_DEV_NAME_MAX_LEN];
	/**< Name of zsda pci device */
	uint8_t zsda_dev_id;
	/**< Id of device instance for this zsda pci device */

	rte_spinlock_t arb_csr_lock;
	/**< lock to protect accesses to the arbiter CSR */

	struct rte_pci_device *pci_dev;

	/* Data relating to compression service */
	struct zsda_comp_dev_private *comp_dev;
	/**< link back to compressdev private data */

	struct zsda_qp_hw zsda_hw_qps[ZSDA_MAX_SERVICES];
	uint16_t zsda_qp_hw_num[ZSDA_MAX_SERVICES];
};

struct zsda_pci_device *
zsda_pci_device_allocate(struct rte_pci_device *pci_dev);

struct zsda_pci_device *
zsda_get_zsda_dev_from_pci_dev(struct rte_pci_device *pci_dev);

__rte_weak int
zsda_get_queue_cfg(struct zsda_pci_device *zsda_pci_dev);

__rte_weak int
zsda_comp_dev_create(struct zsda_pci_device *zsda_pci_dev);

__rte_weak int
zsda_comp_dev_destroy(struct zsda_pci_device *zsda_pci_dev);

int
zsda_get_queue_cfg_by_id(struct zsda_pci_device *zsda_pci_dev, uint8_t qid,
			 struct qinfo *qcfg);

int zsda_queue_start(const struct rte_pci_device *pci_dev);
int zsda_queue_stop(const struct rte_pci_device *pci_dev);
int zsda_queue_clear(const struct rte_pci_device *pci_dev);

int zsda_admin_q_start(const struct rte_pci_device *pci_dev);
int zsda_admin_q_stop(const struct rte_pci_device *pci_dev);
int zsda_admin_q_clear(const struct rte_pci_device *pci_dev);

int zsda_set_cycle_head_tail(struct zsda_pci_device *zsda_pci_dev);

#endif /* _ZSDA_DEVICE_H_ */
