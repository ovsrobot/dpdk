/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include <rte_debug.h>
#include <rte_log.h>
#include <dev_driver.h>
#include <rte_devargs.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_io.h>
#include <rte_pci.h>
#include <bus_pci_driver.h>
#include <rte_eventdev.h>
#include <eventdev_pmd.h>
#include <eventdev_pmd_pci.h>
#include <rte_memory.h>
#include <rte_string_fns.h>

#include "../dlb2_priv.h"
#include "../dlb2_iface.h"
#include "../dlb2_inline_fns.h"
#include "dlb2_main.h"
#include "base/dlb2_hw_types.h"
#include "base/dlb2_osdep.h"
#include "base/dlb2_resource.h"

static const char *event_dlb2_pf_name = RTE_STR(EVDEV_DLB2_NAME_PMD);
static unsigned int dlb2_qe_sa_pct = 1;
static unsigned int dlb2_qid_sa_pct;

static void
dlb2_pf_low_level_io_init(struct dlb2_hw_dev *handle)
{
	int i;

	if (handle == NULL) {
		/* Addresses will be initialized at port create in primary process*/
		for (i = 0; i < DLB2_MAX_NUM_PORTS(DLB2_HW_V2_5); i++) {
			/* First directed ports */
			dlb2_port[i][DLB2_DIR_PORT].pp_addr = NULL;
			dlb2_port[i][DLB2_DIR_PORT].cq_base = NULL;
			dlb2_port[i][DLB2_DIR_PORT].mmaped = false;

			/* Now load balanced ports */
			dlb2_port[i][DLB2_LDB_PORT].pp_addr = NULL;
			dlb2_port[i][DLB2_LDB_PORT].cq_base = NULL;
			dlb2_port[i][DLB2_LDB_PORT].mmaped = false;
		}
	} else {
		/* Retrieve stored addresses in secondary processes */
		struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
		struct dlb2_ldb_port *ldb_ports = dlb2_dev->hw.rsrcs.ldb_ports;
		struct dlb2_dir_pq_pair *dir_ports = dlb2_dev->hw.rsrcs.dir_pq_pairs;

		for (i = 0; i < DLB2_MAX_NUM_LDB_PORTS; i++) {
			dlb2_port[i][DLB2_LDB_PORT].cq_base = ldb_ports[i].port_data.cq_base;
			dlb2_port[i][DLB2_LDB_PORT].pp_addr = ldb_ports[i].port_data.pp_addr;
			dlb2_port[i][DLB2_LDB_PORT].mmaped = true;
		}
		for (i = 0; i < DLB2_MAX_NUM_DIR_PORTS_V2_5; i++) {
			dlb2_port[i][DLB2_DIR_PORT].cq_base = dir_ports[i].port_data.cq_base;
			dlb2_port[i][DLB2_DIR_PORT].pp_addr = dir_ports[i].port_data.pp_addr;
			dlb2_port[i][DLB2_DIR_PORT].mmaped = true;
		}
	}
}

static int
dlb2_pf_open(struct dlb2_hw_dev *handle, const char *name)
{
	RTE_SET_USED(handle);
	RTE_SET_USED(name);

	return 0;
}

static int
dlb2_pf_get_device_version(struct dlb2_hw_dev *handle,
			   uint8_t *revision)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;

	*revision = dlb2_dev->revision;

	return 0;
}

static void dlb2_pf_calc_arbiter_weights(u8 *weight,
					 unsigned int pct)
{
	int val, i;

	/* Largest possible weight (100% SA case): 32 */
	val = (DLB2_MAX_WEIGHT + 1) / DLB2_NUM_ARB_WEIGHTS;

	/* Scale val according to the starvation avoidance percentage */
	val = (val * pct) / 100;
	if (val == 0 && pct != 0)
		val = 1;

	/* Prio 7 always has weight 0xff */
	weight[DLB2_NUM_ARB_WEIGHTS - 1] = DLB2_MAX_WEIGHT;

	for (i = DLB2_NUM_ARB_WEIGHTS - 2; i >= 0; i--)
		weight[i] = weight[i + 1] - val;
}


static void
dlb2_pf_hardware_init(struct dlb2_hw_dev *handle)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;

	dlb2_hw_enable_sparse_ldb_cq_mode(&dlb2_dev->hw);
	dlb2_hw_enable_sparse_dir_cq_mode(&dlb2_dev->hw);

	/* Configure arbitration weights for QE selection */
	if (dlb2_qe_sa_pct <= 100) {
		u8 weight[DLB2_NUM_ARB_WEIGHTS];

		dlb2_pf_calc_arbiter_weights(weight,
					     dlb2_qe_sa_pct);

		dlb2_hw_set_qe_arbiter_weights(&dlb2_dev->hw, weight);
	}

	/* Configure arbitration weights for QID selection */
	if (dlb2_qid_sa_pct <= 100) {
		u8 weight[DLB2_NUM_ARB_WEIGHTS];

		dlb2_pf_calc_arbiter_weights(weight,
					     dlb2_qid_sa_pct);

		dlb2_hw_set_qid_arbiter_weights(&dlb2_dev->hw, weight);
	}

}

static int
dlb2_pf_get_num_resources(struct dlb2_hw_dev *handle,
			  struct dlb2_get_num_resources_args *rsrcs)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;

	return dlb2_hw_get_num_resources(&dlb2_dev->hw, rsrcs, false, 0);
}

static int
dlb2_pf_get_cq_poll_mode(struct dlb2_hw_dev *handle,
			 enum dlb2_cq_poll_modes *mode)
{
	RTE_SET_USED(handle);

	*mode = DLB2_CQ_POLL_MODE_SPARSE;

	return 0;
}

static int
dlb2_pf_sched_domain_create(struct dlb2_hw_dev *handle,
			    struct dlb2_create_sched_domain_args *arg)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	if (dlb2_dev->domain_reset_failed) {
		response.status = DLB2_ST_DOMAIN_RESET_FAILED;
		ret = -EINVAL;
		goto done;
	}

	ret = dlb2_pf_create_sched_domain(&dlb2_dev->hw, arg, &response);
	if (ret)
		goto done;

done:

	arg->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static void
dlb2_pf_domain_reset(struct dlb2_eventdev *dlb2)
{
	struct dlb2_dev *dlb2_dev;
	int ret;

	dlb2_dev = (struct dlb2_dev *)dlb2->qm_instance.pf_dev;
	ret = dlb2_pf_reset_domain(&dlb2_dev->hw, dlb2->qm_instance.domain_id);
	if (ret)
		DLB2_LOG_ERR("dlb2_pf_reset_domain err %d", ret);
}

static int
dlb2_pf_ldb_queue_create(struct dlb2_hw_dev *handle,
			 struct dlb2_create_ldb_queue_args *cfg)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_pf_create_ldb_queue(&dlb2_dev->hw,
				       handle->domain_id,
				       cfg,
				       &response);

	cfg->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_get_sn_occupancy(struct dlb2_hw_dev *handle,
			 struct dlb2_get_sn_occupancy_args *args)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	ret = dlb2_get_group_sequence_number_occupancy(&dlb2_dev->hw,
						       args->group);

	response.id = ret;
	response.status = 0;

	args->response = response;

	return ret;
}

static int
dlb2_pf_get_sn_allocation(struct dlb2_hw_dev *handle,
			  struct dlb2_get_sn_allocation_args *args)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	ret = dlb2_get_group_sequence_numbers(&dlb2_dev->hw, args->group);

	response.id = ret;
	response.status = 0;

	args->response = response;

	return ret;
}

static int
dlb2_pf_set_sn_allocation(struct dlb2_hw_dev *handle,
			  struct dlb2_set_sn_allocation_args *args)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	ret = dlb2_set_group_sequence_numbers(&dlb2_dev->hw, args->group,
					      args->num);

	response.status = 0;

	args->response = response;

	return ret;
}

static void *
dlb2_alloc_coherent_aligned(const struct rte_memzone **mz, uintptr_t *phys,
			    size_t size, int align)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	uint32_t core_id = rte_lcore_id();
	unsigned int socket_id;

	snprintf(mz_name, sizeof(mz_name) - 1, "event_dlb2_pf_%lx",
		 (unsigned long)rte_get_timer_cycles());
	if (core_id == (unsigned int)LCORE_ID_ANY)
		core_id = rte_get_main_lcore();
	socket_id = rte_lcore_to_socket_id(core_id);
	*mz = rte_memzone_reserve_aligned(mz_name, size, socket_id,
					 RTE_MEMZONE_IOVA_CONTIG, align);
	if (*mz == NULL) {
		DLB2_LOG_LINE_DBG("Unable to allocate DMA memory of size %zu bytes - %s",
			     size, rte_strerror(rte_errno));
		*phys = 0;
		return NULL;
	}
	*phys = (*mz)->iova;
	return (*mz)->addr;
}

static int
dlb2_pf_enable_ldb_cq_interrupts(struct dlb2_hw *hw,
				 int id,
				 u16 thresh)
{
	int mode = DLB2_CQ_ISR_MODE_MSIX, vec = 0, efd;

	efd = eventfd(0, 0);
	if (efd < 0) {
		DLB2_LOG_ERR("[%s()] failed to create eventfd for port %d", __func__, id);
		return -1;
	}

	hw->intr.ldb_cq_intr[id].disabled = false;
	hw->intr.ldb_cq_intr[id].configured = true;
	hw->intr.ldb_cq_intr[id].efd = efd;

	return  dlb2_configure_ldb_cq_interrupt(hw, id, vec, mode, 0, 0, thresh);
}

static int
dlb2_pf_enable_dir_cq_interrupts(struct dlb2_hw *hw,
				 int id,
				 u16 thresh)
{
	int mode = DLB2_CQ_ISR_MODE_MSIX, vec = 0, efd;

	efd = eventfd(0, 0);
	if (efd < 0) {
		DLB2_LOG_ERR("[%s()] failed to create eventfd for port %d", __func__, id);
		return -1;
	}

	hw->intr.dir_cq_intr[id].disabled = false;
	hw->intr.dir_cq_intr[id].configured = true;
	hw->intr.dir_cq_intr[id].efd = efd;

	return  dlb2_configure_dir_cq_interrupt(hw, id, vec, mode, 0, 0, thresh);
}

static void
dlb2_wake_thread(struct dlb2_cq_intr *intr, enum dlb2_wake_reason reason)
{
	intr->reason = reason;
	eventfd_write(intr->efd, 1);
}

static void
dlb2_cq_interrupt_handler(void *intr_param)
{
	u32 dir_cq_interrupts[DLB2_MAX_NUM_DIR_PORTS_V2_5 / 32];
	u32 ldb_cq_interrupts[DLB2_MAX_NUM_LDB_PORTS / 32];
	struct dlb2_dev *dlb2_dev = intr_param;
	struct dlb2_hw *hw = &dlb2_dev->hw;

	dlb2_read_compressed_cq_intr_status(hw, ldb_cq_interrupts, dir_cq_interrupts);
	dlb2_ack_compressed_cq_intr(hw, ldb_cq_interrupts, dir_cq_interrupts);

	for (int i = 0; i < DLB2_MAX_NUM_LDB_PORTS; i++) {
		u32 mask = 1 << (i % 32);
		int idx = i / 32;

		if (!(ldb_cq_interrupts[idx] & mask))
			continue;

		dlb2_wake_thread(&hw->intr.ldb_cq_intr[i], WAKE_CQ_INTR);
	}

	for (int i = 0; i < DLB2_MAX_NUM_DIR_PORTS(hw->ver); i++) {
		u32 mask = 1 << (i % 32);
		int idx = i / 32;

		if (!(dir_cq_interrupts[idx] & mask))
			continue;

		dlb2_wake_thread(&hw->intr.dir_cq_intr[i], WAKE_CQ_INTR);
	}
}

static void
dlb2_detect_ingress_err_overload(struct dlb2_hw *dlb2)
{
	struct timespec ts;
	u64 delta_us;

	if (dlb2->ingress_err.count == 0)
		clock_gettime(CLOCK_REALTIME, &dlb2->ingress_err.ts);

	dlb2->ingress_err.count++;

	/* Don't check for overload until OVERLOAD_THRESH ISRs have run */
	if (dlb2->ingress_err.count < DLB2_ISR_OVERLOAD_THRESH)
		return;

	clock_gettime(CLOCK_REALTIME, &ts);
	delta_us = (ts.tv_sec - dlb2->ingress_err.ts.tv_sec) * 1000000LL +
		   (ts.tv_nsec - dlb2->ingress_err.ts.tv_nsec) / 1000;

	/* Reset stats for next measurement period */
	dlb2->ingress_err.count = 0;
	clock_gettime(CLOCK_REALTIME, &dlb2->ingress_err.ts);

	/* Check for overload during this measurement period */
	if (delta_us > DLB2_ISR_OVERLOAD_PERIOD_S * 1000000)
		return;

	/*
	 * Alarm interrupt overload: disable software-generated alarms,
	 * so only hardware problems (e.g. ECC errors) interrupt the PF.
	 */
	dlb2_disable_ingress_error_alarms(dlb2);

	dlb2->ingress_err.enabled = false;

	DLB2_HW_DBG(dlb2, "[%s()] Overloaded detected: disabling ingress error interrupts",
		    __func__);
}

static void
dlb2_service_intr_handler(void *intr_param)
{
	struct dlb2_dev *dlb2_dev = intr_param;
	u32 synd;

	rte_spinlock_lock(&dlb2_dev->resource_mutex);

	synd = DLB2_CSR_RD(&dlb2_dev->hw, DLB2_SYS_ALARM_HW_SYND);

	/*
	 * Clear the MSI-X ack bit before processing the watchdog timer
	 * interrupts. This order is necessary so that if an interrupt event
	 * arrives after reading the corresponding bit vector, the event won't
	 * be lost.
	 */
	dlb2_ack_msix_interrupt(&dlb2_dev->hw, DLB2_INT_NON_CQ);

	if (DLB2_SYND(ALARM) & DLB2_SYND(VALID))
		dlb2_process_alarm_interrupt(&dlb2_dev->hw);

	if (dlb2_process_ingress_error_interrupt(&dlb2_dev->hw))
		dlb2_detect_ingress_err_overload(&dlb2_dev->hw);

	if (DLB2_SYND(CWD) & DLB2_SYND(VALID))
		dlb2_process_wdt_interrupt(&dlb2_dev->hw);

	rte_spinlock_unlock(&dlb2_dev->resource_mutex);
}

static int
dlb2_intr_setup(struct rte_eventdev *eventdev)
{
	struct rte_intr_handle *dlb2_intr = rte_intr_instance_alloc(RTE_INTR_INSTANCE_F_SHARED);
	struct rte_pci_device *pci_dev = RTE_DEV_TO_PCI(eventdev->dev);
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(eventdev);
	struct dlb2_dev *dlb2_dev = dlb2->qm_instance.pf_dev;
	struct dlb2_hw *hw = &dlb2_dev->hw;
	uint32_t intr_vector = 1;

	/* Setup eventfd for VFIO-MSIX interrupts */
	if (rte_intr_cap_multiple(intr_handle) && rte_intr_efd_enable(intr_handle, intr_vector))
		return -1;

	rte_intr_enable(intr_handle);

	/* Set the dlb2 interrupt type and fd to eventfd of the VFIO-MSIX and register
	 * the interrupt handler
	 */
	rte_intr_type_set(dlb2_intr, RTE_INTR_HANDLE_VFIO_MSIX);
	rte_intr_fd_set(dlb2_intr, rte_intr_efds_index_get(intr_handle, 0));
	rte_intr_callback_register(dlb2_intr, dlb2_cq_interrupt_handler, dlb2_dev);

	/* Enable alarms and register interrupt handler*/
	hw->ingress_err.count = 0;
	hw->ingress_err.enabled = true;
	dlb2_enable_ingress_error_alarms(hw);
	rte_intr_callback_register(intr_handle, dlb2_service_intr_handler, dlb2_dev);

	/* Initilaize the interrupt structures */
	for (int i = 0; i < DLB2_MAX_NUM_LDB_PORTS; i++) {
		if (pthread_mutex_init(&hw->intr.ldb_cq_intr[i].mutex, NULL) != 0) {
			perror("Mutex initialization failed");
			return EXIT_FAILURE;
		}
		hw->intr.ldb_cq_intr[i].configured = false;
		hw->intr.ldb_cq_intr[i].disabled = true;
	}

	for (int i = 0; i < DLB2_MAX_NUM_DIR_PORTS(hw->ver); i++) {
		if (pthread_mutex_init(&hw->intr.dir_cq_intr[i].mutex, NULL) != 0) {
			perror("Mutex initialization failed");
			return EXIT_FAILURE;
		}
		hw->intr.dir_cq_intr[i].configured = false;
		hw->intr.dir_cq_intr[i].disabled = true;
	}

	return 0;
}

static int
dlb2_pf_ldb_port_create(struct dlb2_hw_dev *handle,
			struct dlb2_create_ldb_port_args *cfg,
			enum dlb2_cq_poll_modes poll_mode)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct process_local_port_data *port_data;
	struct dlb2_cmd_response response = {0};
	struct dlb2_port_memory port_memory;
	int ret, cq_alloc_depth;
	uint8_t *port_base;
	const struct rte_memzone *mz;
	int alloc_sz, qe_sz;
	phys_addr_t cq_base;
	phys_addr_t pp_base;
	int is_dir = false;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	if (poll_mode == DLB2_CQ_POLL_MODE_STD)
		qe_sz = sizeof(struct dlb2_dequeue_qe);
	else
		qe_sz = RTE_CACHE_LINE_SIZE;

	/* Calculate the port memory required, and round up to the nearest
	 * cache line.
	 */
	cq_alloc_depth = RTE_MAX(cfg->cq_depth, DLB2_MIN_HARDWARE_CQ_DEPTH);
	alloc_sz = cq_alloc_depth * qe_sz;
	alloc_sz = RTE_CACHE_LINE_ROUNDUP(alloc_sz);

	port_base = dlb2_alloc_coherent_aligned(&mz, &cq_base, alloc_sz,
						rte_mem_page_size());
	if (port_base == NULL)
		return -ENOMEM;

	/* Lock the page in memory */
	ret = rte_mem_lock_page(port_base);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2 pf pmd could not lock page for device i/o");
		goto create_port_err;
	}

	memset(port_base, 0, alloc_sz);

	ret = dlb2_pf_create_ldb_port(&dlb2_dev->hw,
				      handle->domain_id,
				      cfg,
				      cq_base,
				      &response);
	cfg->response = response;
	if (ret)
		goto create_port_err;

	ret = dlb2_pf_enable_ldb_cq_interrupts(&dlb2_dev->hw, response.id, cfg->cq_depth_threshold);
	if (ret)
		goto create_port_err;

	pp_base = (uintptr_t)dlb2_dev->hw.func_kva + PP_BASE(is_dir);
	dlb2_port[response.id][DLB2_LDB_PORT].pp_addr =
		(void *)(pp_base + (rte_mem_page_size() * response.id));

	dlb2_port[response.id][DLB2_LDB_PORT].cq_base = (void *)(port_base);
	dlb2_port[response.id][DLB2_LDB_PORT].mmaped = true;
	memset(&port_memory, 0, sizeof(port_memory));

	dlb2_port[response.id][DLB2_LDB_PORT].mz = mz;

	dlb2_list_init_head(&port_memory.list);

	cfg->response = response;

	/* Store cq_base and pp_addr for secondary processes*/
	port_data = &dlb2_dev->hw.rsrcs.ldb_ports[response.id].port_data;
	port_data->pp_addr = dlb2_port[response.id][DLB2_LDB_PORT].pp_addr;
	port_data->cq_base = (struct dlb2_dequeue_qe *)cq_base;

	return 0;

create_port_err:

	rte_memzone_free(mz);

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);
	return ret;
}

static int
dlb2_pf_dir_port_create(struct dlb2_hw_dev *handle,
			struct dlb2_create_dir_port_args *cfg,
			enum dlb2_cq_poll_modes poll_mode)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct process_local_port_data *port_data;
	struct dlb2_cmd_response response = {0};
	struct dlb2_port_memory port_memory;
	int ret;
	uint8_t *port_base;
	const struct rte_memzone *mz;
	int alloc_sz, qe_sz;
	phys_addr_t cq_base;
	phys_addr_t pp_base;
	int is_dir = true;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	if (poll_mode == DLB2_CQ_POLL_MODE_STD)
		qe_sz = sizeof(struct dlb2_dequeue_qe);
	else
		qe_sz = RTE_CACHE_LINE_SIZE;

	/* Calculate the port memory required, and round up to the nearest
	 * cache line.
	 */
	alloc_sz = RTE_MAX(cfg->cq_depth, DLB2_MIN_HARDWARE_CQ_DEPTH) * qe_sz;
	alloc_sz = RTE_CACHE_LINE_ROUNDUP(alloc_sz);

	port_base = dlb2_alloc_coherent_aligned(&mz, &cq_base, alloc_sz,
						rte_mem_page_size());
	if (port_base == NULL)
		return -ENOMEM;

	/* Lock the page in memory */
	ret = rte_mem_lock_page(port_base);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2 pf pmd could not lock page for device i/o");
		goto create_port_err;
	}

	memset(port_base, 0, alloc_sz);

	ret = dlb2_pf_create_dir_port(&dlb2_dev->hw,
				      handle->domain_id,
				      cfg,
				      cq_base,
				      &response);

	cfg->response = response;

	if (ret)
		goto create_port_err;

	ret = dlb2_pf_enable_dir_cq_interrupts(&dlb2_dev->hw, response.id, cfg->cq_depth_threshold);
	if (ret)
		goto create_port_err;

	pp_base = (uintptr_t)dlb2_dev->hw.func_kva + PP_BASE(is_dir);
	dlb2_port[response.id][DLB2_DIR_PORT].pp_addr =
		(void *)(pp_base + (rte_mem_page_size() * response.id));

	dlb2_port[response.id][DLB2_DIR_PORT].cq_base =
		(void *)(port_base);
	dlb2_port[response.id][DLB2_DIR_PORT].mmaped = true;
	memset(&port_memory, 0, sizeof(port_memory));

	dlb2_port[response.id][DLB2_DIR_PORT].mz = mz;

	dlb2_list_init_head(&port_memory.list);

	cfg->response = response;

	/* Store cq_base and pp_addr for secondary processes*/
	port_data = &dlb2_dev->hw.rsrcs.dir_pq_pairs[response.id].port_data;
	port_data->pp_addr = dlb2_port[response.id][DLB2_DIR_PORT].pp_addr;
	port_data->cq_base = (struct dlb2_dequeue_qe *)cq_base;

	return 0;

create_port_err:

	rte_memzone_free(mz);

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_dir_queue_create(struct dlb2_hw_dev *handle,
			 struct dlb2_create_dir_queue_args *cfg)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_pf_create_dir_queue(&dlb2_dev->hw,
				       handle->domain_id,
				       cfg,
				       &response);

	cfg->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_map_qid(struct dlb2_hw_dev *handle,
		struct dlb2_map_qid_args *cfg)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_hw_map_qid(&dlb2_dev->hw,
			      handle->domain_id,
			      cfg,
			      &response,
			      false,
			      0);

	cfg->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_unmap_qid(struct dlb2_hw_dev *handle,
		  struct dlb2_unmap_qid_args *cfg)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_hw_unmap_qid(&dlb2_dev->hw,
				handle->domain_id,
				cfg,
				&response,
				false,
				0);

	cfg->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_pending_port_unmaps(struct dlb2_hw_dev *handle,
			    struct dlb2_pending_port_unmaps_args *args)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_hw_pending_port_unmaps(&dlb2_dev->hw,
					  handle->domain_id,
					  args,
					  &response,
					  false,
					  0);

	args->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_sched_domain_start(struct dlb2_hw_dev *handle,
			   struct dlb2_start_domain_args *cfg)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_pf_start_domain(&dlb2_dev->hw,
				   handle->domain_id,
				   cfg,
				   &response);

	cfg->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_get_ldb_queue_depth(struct dlb2_hw_dev *handle,
			    struct dlb2_get_ldb_queue_depth_args *args)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_hw_get_ldb_queue_depth(&dlb2_dev->hw,
					  handle->domain_id,
					  args,
					  &response,
					  false,
					  0);

	args->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_get_dir_queue_depth(struct dlb2_hw_dev *handle,
			    struct dlb2_get_dir_queue_depth_args *args)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret = 0;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_hw_get_dir_queue_depth(&dlb2_dev->hw,
					  handle->domain_id,
					  args,
					  &response,
					  false,
					  0);

	args->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_enable_cq_weight(struct dlb2_hw_dev *handle,
			 struct dlb2_enable_cq_weight_args *args)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret = 0;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_hw_enable_cq_weight(&dlb2_dev->hw,
				       handle->domain_id,
				       args,
				       &response,
				       false,
				       0);
	args->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_set_cq_inflight_ctrl(struct dlb2_hw_dev *handle,
			     struct dlb2_cq_inflight_ctrl_args *args)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	struct dlb2_cmd_response response = {0};
	int ret = 0;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_hw_set_cq_inflight_ctrl(&dlb2_dev->hw, handle->domain_id,
					   args, &response, false, 0);
	args->response = response;

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_set_cos_bandwidth(struct dlb2_hw_dev *handle,
			  struct dlb2_set_cos_bw_args *args)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;
	int ret = 0;

	DLB2_INFO(dev->dlb2_device, "Entering %s()\n", __func__);

	ret = dlb2_hw_set_cos_bandwidth(&dlb2_dev->hw,
					args->cos_id,
					args->bandwidth);

	DLB2_INFO(dev->dlb2_device, "Exiting %s() with ret=%d\n",
		  __func__, ret);

	return ret;
}

static int
dlb2_pf_block_on_cq_interrupt(struct dlb2_hw_dev *handle,
			      int port_id,
			      bool is_ldb,
			      volatile void *cq_va,
			      u8 cq_gen,
			      bool arm)
{
	struct dlb2_dev *dlb2_dev = (struct dlb2_dev *)handle->pf_dev;

	return dlb2_block_on_cq_interrupt(&dlb2_dev->hw, port_id, is_ldb, cq_va, cq_gen, arm);
}

static void
dlb2_pf_iface_fn_ptrs_init(void)
{
	dlb2_iface_low_level_io_init = dlb2_pf_low_level_io_init;
	dlb2_iface_open = dlb2_pf_open;
	dlb2_iface_domain_reset = dlb2_pf_domain_reset;
	dlb2_iface_get_device_version = dlb2_pf_get_device_version;
	dlb2_iface_hardware_init = dlb2_pf_hardware_init;
	dlb2_iface_get_num_resources = dlb2_pf_get_num_resources;
	dlb2_iface_get_cq_poll_mode = dlb2_pf_get_cq_poll_mode;
	dlb2_iface_sched_domain_create = dlb2_pf_sched_domain_create;
	dlb2_iface_ldb_queue_create = dlb2_pf_ldb_queue_create;
	dlb2_iface_ldb_port_create = dlb2_pf_ldb_port_create;
	dlb2_iface_dir_queue_create = dlb2_pf_dir_queue_create;
	dlb2_iface_dir_port_create = dlb2_pf_dir_port_create;
	dlb2_iface_map_qid = dlb2_pf_map_qid;
	dlb2_iface_unmap_qid = dlb2_pf_unmap_qid;
	dlb2_iface_get_ldb_queue_depth = dlb2_pf_get_ldb_queue_depth;
	dlb2_iface_get_dir_queue_depth = dlb2_pf_get_dir_queue_depth;
	dlb2_iface_sched_domain_start = dlb2_pf_sched_domain_start;
	dlb2_iface_pending_port_unmaps = dlb2_pf_pending_port_unmaps;
	dlb2_iface_get_sn_allocation = dlb2_pf_get_sn_allocation;
	dlb2_iface_set_sn_allocation = dlb2_pf_set_sn_allocation;
	dlb2_iface_get_sn_occupancy = dlb2_pf_get_sn_occupancy;
	dlb2_iface_enable_cq_weight = dlb2_pf_enable_cq_weight;
	dlb2_iface_set_cos_bw = dlb2_pf_set_cos_bandwidth;
	dlb2_iface_set_cq_inflight_ctrl = dlb2_pf_set_cq_inflight_ctrl;
	dlb2_iface_block_on_cq_interrupt = dlb2_pf_block_on_cq_interrupt;
}

/* PCI DEV HOOKS */
static int
dlb2_eventdev_pci_init(struct rte_eventdev *eventdev)
{
	int ret = 0;
	struct rte_pci_device *pci_dev;
	struct dlb2_devargs dlb2_args = {
		.socket_id = rte_socket_id(),
		.max_num_events = DLB2_MAX_NUM_LDB_CREDITS,
		.producer_coremask = NULL,
		.num_dir_credits_override = -1,
		.qid_depth_thresholds = { {0} },
		.poll_interval = DLB2_POLL_INTERVAL_DEFAULT,
		.sw_credit_quanta = DLB2_SW_CREDIT_QUANTA_DEFAULT,
		.hw_credit_quanta = DLB2_SW_CREDIT_BATCH_SZ,
		.default_depth_thresh = DLB2_DEPTH_THRESH_DEFAULT,
		.max_cq_depth = DLB2_DEFAULT_CQ_DEPTH,
		.max_enq_depth = DLB2_MAX_ENQUEUE_DEPTH,
		.use_default_hl = true,
		.alloc_hl_entries = 0
	};
	struct dlb2_eventdev *dlb2;
	int q;
	const void *probe_args = NULL;

	DLB2_LOG_LINE_DBG("Enter with dev_id=%d socket_id=%d",
		     eventdev->data->dev_id, eventdev->data->socket_id);

	for (q = 0; q < DLB2_MAX_NUM_PORTS_ALL; q++)
		dlb2_args.port_cos.cos_id[q] = DLB2_COS_DEFAULT;

	dlb2_pf_iface_fn_ptrs_init();

	pci_dev = RTE_DEV_TO_PCI(eventdev->dev);

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		dlb2 = dlb2_pmd_priv(eventdev); /* rte_zmalloc_socket mem */
		dlb2->version = DLB2_HW_DEVICE_FROM_PCI_ID(pci_dev);
		if (dlb2->version == DLB2_HW_V2_5)
			dlb2_args.max_num_events = DLB2_MAX_NUM_CREDITS(DLB2_HW_V2_5);

		/* Were we invoked with runtime parameters? */
		if (pci_dev->device.devargs) {
			ret = dlb2_parse_params(pci_dev->device.devargs->args,
						pci_dev->device.devargs->name,
						&dlb2_args,
						dlb2->version);
			if (ret) {
				DLB2_LOG_ERR("PFPMD failed to parse args ret=%d, errno=%d",
					     ret, rte_errno);
				goto dlb2_probe_failed;
			}
			probe_args = &dlb2_args;
		}

		/* Probe the DLB2 PF layer */
		dlb2->qm_instance.pf_dev = dlb2_probe(pci_dev, probe_args);

		if (dlb2->qm_instance.pf_dev == NULL) {
			DLB2_LOG_ERR("DLB2 PF Probe failed with error %d",
				     rte_errno);
			ret = -rte_errno;
			goto dlb2_probe_failed;
		}

		ret = dlb2_primary_eventdev_probe(eventdev,
						  event_dlb2_pf_name,
						  &dlb2_args);
		ret = ret ?: dlb2_intr_setup(eventdev);
	} else {
		dlb2 = dlb2_pmd_priv(eventdev);
		dlb2->version = DLB2_HW_DEVICE_FROM_PCI_ID(pci_dev);
		ret = dlb2_secondary_eventdev_probe(eventdev,
						    event_dlb2_pf_name);
	}
	if (ret)
		goto dlb2_probe_failed;

	DLB2_LOG_INFO("DLB2 PF Probe success");

	return 0;

dlb2_probe_failed:

	DLB2_LOG_INFO("DLB2 PF Probe failed, ret=%d", ret);

	return ret;
}

#define EVENTDEV_INTEL_VENDOR_ID 0x8086

static const struct rte_pci_id pci_id_dlb2_map[] = {
	{
		RTE_PCI_DEVICE(EVENTDEV_INTEL_VENDOR_ID,
			       PCI_DEVICE_ID_INTEL_DLB2_PF)
	},
	{
		.vendor_id = 0,
	},
};

static const struct rte_pci_id pci_id_dlb2_5_map[] = {
	{
		RTE_PCI_DEVICE(EVENTDEV_INTEL_VENDOR_ID,
			       PCI_DEVICE_ID_INTEL_DLB2_5_PF)
	},
	{
		.vendor_id = 0,
	},
};

static int
event_dlb2_pci_probe(struct rte_pci_driver *pci_drv,
		     struct rte_pci_device *pci_dev)
{
	int ret;

	ret = rte_event_pmd_pci_probe_named(pci_drv, pci_dev,
					     sizeof(struct dlb2_eventdev),
					     dlb2_eventdev_pci_init,
					     event_dlb2_pf_name);
	if (ret) {
		DLB2_LOG_INFO("rte_event_pmd_pci_probe_named() failed, "
				"ret=%d", ret);
	}

	return ret;
}

static int
event_dlb2_pci_remove(struct rte_pci_device *pci_dev)
{
	int ret;

	ret = rte_event_pmd_pci_remove(pci_dev, NULL);

	if (ret) {
		DLB2_LOG_INFO("rte_event_pmd_pci_remove() failed, "
				"ret=%d", ret);
	}

	return ret;

}

static int
event_dlb2_5_pci_probe(struct rte_pci_driver *pci_drv,
		       struct rte_pci_device *pci_dev)
{
	int ret;

	ret = rte_event_pmd_pci_probe_named(pci_drv, pci_dev,
					    sizeof(struct dlb2_eventdev),
					    dlb2_eventdev_pci_init,
					    event_dlb2_pf_name);
	if (ret) {
		DLB2_LOG_INFO("rte_event_pmd_pci_probe_named() failed, "
				"ret=%d", ret);
	}

	return ret;
}

static int
event_dlb2_5_pci_remove(struct rte_pci_device *pci_dev)
{
	int ret;

	ret = rte_event_pmd_pci_remove(pci_dev, NULL);

	if (ret) {
		DLB2_LOG_INFO("rte_event_pmd_pci_remove() failed, "
				"ret=%d", ret);
	}

	return ret;

}

static struct rte_pci_driver pci_eventdev_dlb2_pmd = {
	.id_table = pci_id_dlb2_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = event_dlb2_pci_probe,
	.remove = event_dlb2_pci_remove,
};

static struct rte_pci_driver pci_eventdev_dlb2_5_pmd = {
	.id_table = pci_id_dlb2_5_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = event_dlb2_5_pci_probe,
	.remove = event_dlb2_5_pci_remove,
};

RTE_PMD_REGISTER_PCI(event_dlb2_pf, pci_eventdev_dlb2_pmd);
RTE_PMD_REGISTER_PCI_TABLE(event_dlb2_pf, pci_id_dlb2_map);

RTE_PMD_REGISTER_PCI(event_dlb2_5_pf, pci_eventdev_dlb2_5_pmd);
RTE_PMD_REGISTER_PCI_TABLE(event_dlb2_5_pf, pci_id_dlb2_5_map);
