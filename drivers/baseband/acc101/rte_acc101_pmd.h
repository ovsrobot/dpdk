/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_ACC101_PMD_H_
#define _RTE_ACC101_PMD_H_

/* Helper macro for logging */
#define rte_bbdev_log(level, fmt, ...) \
	rte_log(RTE_LOG_ ## level, acc101_logtype, fmt "\n", \
		##__VA_ARGS__)

#ifdef RTE_LIBRTE_BBDEV_DEBUG
#define rte_bbdev_log_debug(fmt, ...) \
		rte_bbdev_log(DEBUG, "acc101_pmd: " fmt, \
		##__VA_ARGS__)
#else
#define rte_bbdev_log_debug(fmt, ...)
#endif

/* ACC101 PF and VF driver names */
#define ACC101PF_DRIVER_NAME           intel_acc101_pf
#define ACC101VF_DRIVER_NAME           intel_acc101_vf

/* ACC101 PCI vendor & device IDs */
#define RTE_ACC101_VENDOR_ID           (0x8086)
#define RTE_ACC101_PF_DEVICE_ID        (0x57c4)
#define RTE_ACC101_VF_DEVICE_ID        (0x57c5)

/* Private data structure for each ACC101 device */
struct acc101_device {
	void *mmio_base;  /**< Base address of MMIO registers (BAR0) */
	void *sw_rings_base;  /* Base addr of un-aligned memory for sw rings */
	void *sw_rings;  /* 64MBs of 64MB aligned memory for sw rings */
	rte_iova_t sw_rings_iova;  /* IOVA address of sw_rings */

	union acc101_harq_layout_data *harq_layout;
	/* Number of bytes available for each queue in device, depending on
	 * how many queues are enabled with configure()
	 */
	uint32_t sw_ring_size;
	uint32_t ddr_size; /* Size in kB */
	uint32_t *tail_ptrs; /* Base address of response tail pointer buffer */
	rte_iova_t tail_ptr_iova; /* IOVA address of tail pointers */
	/* Max number of entries available for each queue in device, depending
	 * on how many queues are enabled with configure()
	 */
	uint32_t sw_ring_max_depth;
	bool pf_device; /**< True if this is a PF ACC101 device */
	bool configured; /**< True if this ACC101 device is configured */
};

#endif /* _RTE_ACC101_PMD_H_ */
