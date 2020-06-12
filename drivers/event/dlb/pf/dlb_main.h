/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#ifndef __DLB_MAIN_H
#define __DLB_MAIN_H

#include <rte_debug.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE (sysconf(_SC_PAGESIZE))
#endif

#include "base/dlb_hw_types.h"
#include "../dlb_user.h"

#define DLB_DEFAULT_UNREGISTER_TIMEOUT_S 5

struct dlb_dev;

struct dlb_port_page {
	struct dlb_list_head list;
	unsigned long offs;
	struct iova *iova;
	struct page *page;
	uintptr_t dma_addr;
	unsigned long dma_size;
	int refcnt;
};

struct dlb_port_memory {
	struct dlb_list_head list;
	struct dlb_port_page *pages;
	void *cq_base;
	uintptr_t cq_dma_base;
	void *pc_base;
	uintptr_t pc_dma_base;
	int domain_id;
	bool valid;
};

struct dlb_dev {
	struct rte_pci_device *pdev;
	struct dlb_hw hw;
	/* struct list_head list; */
	struct device *dlb_device;
	struct dlb_port_memory ldb_port_pages[DLB_MAX_NUM_LDB_PORTS];
	struct dlb_port_memory dir_port_pages[DLB_MAX_NUM_DIR_PORTS];
	/* The enqueue_four function enqueues four HCWs (one cache-line worth)
	 * to the DLB, using whichever mechanism is supported by the platform
	 * on which this driver is running.
	 */
	void (*enqueue_four)(void *qe4, void *pp_addr);
	bool domain_reset_failed;
	/* The resource mutex serializes access to driver data structures and
	 * hardware registers.
	 */
	rte_spinlock_t resource_mutex;
	rte_spinlock_t measurement_lock;
	bool worker_launched;
	u8 revision;
};

struct dlb_dev *dlb_probe(struct rte_pci_device *pdev);
void dlb_reset_done(struct dlb_dev *dlb_dev);

/* pf_ops */
int dlb_pf_init_driver_state(struct dlb_dev *dev);
void dlb_pf_free_driver_state(struct dlb_dev *dev);
int dlb_pf_init_interrupts(struct dlb_dev *dev);
int dlb_hw_enable_ldb_cq_interrupts(struct dlb_dev *dev,
				    int port_id,
				    u16 thresh);
int dlb_hw_enable_dir_cq_interrupts(struct dlb_dev *dev,
				    int port_id,
				    u16 thresh);
int dlb_pf_arm_cq_interrupt(struct dlb_dev *dev,
			    int domain_id,
			    int port_id,
			    bool is_ldb);
void dlb_pf_reinit_interrupts(struct dlb_dev *dev);
void dlb_pf_free_interrupts(struct dlb_dev *dev);
void dlb_pf_init_hardware(struct dlb_dev *dev);
int dlb_pf_reset(struct dlb_dev *dlb_dev);

#endif /* __DLB_MAIN_H */
