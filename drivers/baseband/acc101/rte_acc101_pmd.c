/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_dev.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_branch_prediction.h>
#include <rte_hexdump.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#ifdef RTE_BBDEV_OFFLOAD_COST
#include <rte_cycles.h>
#endif

#include <rte_bbdev.h>
#include <rte_bbdev_pmd.h>
#include "rte_acc101_pmd.h"

#ifdef RTE_LIBRTE_BBDEV_DEBUG
RTE_LOG_REGISTER_DEFAULT(acc101_logtype, DEBUG);
#else
RTE_LOG_REGISTER_DEFAULT(acc101_logtype, NOTICE);
#endif

/* Write to MMIO register address */
static inline void
mmio_write(void *addr, uint32_t value)
{
	*((volatile uint32_t *)(addr)) = rte_cpu_to_le_32(value);
}

/* Write a register of a ACC101 device */
static inline void
acc101_reg_write(struct acc101_device *d, uint32_t offset, uint32_t value)
{
	void *reg_addr = RTE_PTR_ADD(d->mmio_base, offset);
	mmio_write(reg_addr, value);
	usleep(ACC101_LONG_WAIT);
}

/* Read a register of a ACC101 device */
static inline uint32_t
acc101_reg_read(struct acc101_device *d, uint32_t offset)
{
	void *reg_addr = RTE_PTR_ADD(d->mmio_base, offset);
	uint32_t ret = *((volatile uint32_t *)(reg_addr));
	return rte_le_to_cpu_32(ret);
}

/* Basic Implementation of Log2 for exact 2^N */
static inline uint32_t
log2_basic(uint32_t value)
{
	return (value == 0) ? 0 : rte_bsf32(value);
}

/* Calculate memory alignment offset assuming alignment is 2^N */
static inline uint32_t
calc_mem_alignment_offset(void *unaligned_virt_mem, uint32_t alignment)
{
	rte_iova_t unaligned_phy_mem = rte_malloc_virt2iova(unaligned_virt_mem);
	return (uint32_t)(alignment -
			(unaligned_phy_mem & (alignment-1)));
}

/* Calculate the offset of the enqueue register */
static inline uint32_t
queue_offset(bool pf_device, uint8_t vf_id, uint8_t qgrp_id, uint16_t aq_id)
{
	if (pf_device)
		return ((vf_id << 12) + (qgrp_id << 7) + (aq_id << 3) +
				HWPfQmgrIngressAq);
	else
		return ((qgrp_id << 7) + (aq_id << 3) +
				HWVfQmgrIngressAq);
}

enum {UL_4G = 0, UL_5G, DL_4G, DL_5G, NUM_ACC};

/* Return the queue topology for a Queue Group Index */
static inline void
qtopFromAcc(struct rte_acc101_queue_topology **qtop, int acc_enum,
		struct rte_acc101_conf *acc101_conf)
{
	struct rte_acc101_queue_topology *p_qtop;
	p_qtop = NULL;
	switch (acc_enum) {
	case UL_4G:
		p_qtop = &(acc101_conf->q_ul_4g);
		break;
	case UL_5G:
		p_qtop = &(acc101_conf->q_ul_5g);
		break;
	case DL_4G:
		p_qtop = &(acc101_conf->q_dl_4g);
		break;
	case DL_5G:
		p_qtop = &(acc101_conf->q_dl_5g);
		break;
	default:
		/* NOTREACHED */
		rte_bbdev_log(ERR, "Unexpected error evaluating qtopFromAcc");
		break;
	}
	*qtop = p_qtop;
}

static void
initQTop(struct rte_acc101_conf *acc101_conf)
{
	acc101_conf->q_ul_4g.num_aqs_per_groups = 0;
	acc101_conf->q_ul_4g.num_qgroups = 0;
	acc101_conf->q_ul_4g.first_qgroup_index = -1;
	acc101_conf->q_ul_5g.num_aqs_per_groups = 0;
	acc101_conf->q_ul_5g.num_qgroups = 0;
	acc101_conf->q_ul_5g.first_qgroup_index = -1;
	acc101_conf->q_dl_4g.num_aqs_per_groups = 0;
	acc101_conf->q_dl_4g.num_qgroups = 0;
	acc101_conf->q_dl_4g.first_qgroup_index = -1;
	acc101_conf->q_dl_5g.num_aqs_per_groups = 0;
	acc101_conf->q_dl_5g.num_qgroups = 0;
	acc101_conf->q_dl_5g.first_qgroup_index = -1;
}

static inline void
updateQtop(uint8_t acc, uint8_t qg, struct rte_acc101_conf *acc101_conf,
		struct acc101_device *d) {
	uint32_t reg;
	struct rte_acc101_queue_topology *q_top = NULL;
	qtopFromAcc(&q_top, acc, acc101_conf);
	if (unlikely(q_top == NULL))
		return;
	uint16_t aq;
	q_top->num_qgroups++;
	if (q_top->first_qgroup_index == -1) {
		q_top->first_qgroup_index = qg;
		/* Can be optimized to assume all are enabled by default */
		reg = acc101_reg_read(d, queue_offset(d->pf_device,
				0, qg, ACC101_NUM_AQS - 1));
		if (reg & ACC101_QUEUE_ENABLE) {
			q_top->num_aqs_per_groups = ACC101_NUM_AQS;
			return;
		}
		q_top->num_aqs_per_groups = 0;
		for (aq = 0; aq < ACC101_NUM_AQS; aq++) {
			reg = acc101_reg_read(d, queue_offset(d->pf_device,
					0, qg, aq));
			if (reg & ACC101_QUEUE_ENABLE)
				q_top->num_aqs_per_groups++;
		}
	}
}

/* Fetch configuration enabled for the PF/VF using MMIO Read (slow) */
static inline void
fetch_acc101_config(struct rte_bbdev *dev)
{
	struct acc101_device *d = dev->data->dev_private;
	struct rte_acc101_conf *acc101_conf = &d->acc101_conf;
	const struct acc101_registry_addr *reg_addr;
	uint8_t acc, qg;
	uint32_t reg, reg_aq, reg_len0, reg_len1;
	uint32_t reg_mode;

	/* No need to retrieve the configuration is already done */
	if (d->configured)
		return;

	/* Choose correct registry addresses for the device type */
	if (d->pf_device)
		reg_addr = &pf_reg_addr;
	else
		reg_addr = &vf_reg_addr;

	d->ddr_size = (1 + acc101_reg_read(d, reg_addr->ddr_range)) << 10;

	/* Single VF Bundle by VF */
	acc101_conf->num_vf_bundles = 1;
	initQTop(acc101_conf);

	struct rte_acc101_queue_topology *q_top = NULL;
	int qman_func_id[ACC101_NUM_ACCS] = {ACC101_ACCMAP_0, ACC101_ACCMAP_1,
			ACC101_ACCMAP_2, ACC101_ACCMAP_3, ACC101_ACCMAP_4};
	reg = acc101_reg_read(d, reg_addr->qman_group_func);
	for (qg = 0; qg < ACC101_NUM_QGRPS_PER_WORD; qg++) {
		reg_aq = acc101_reg_read(d,
				queue_offset(d->pf_device, 0, qg, 0));
		if (reg_aq & ACC101_QUEUE_ENABLE) {
			uint32_t idx = (reg >> (qg * 4)) & 0x7;
			if (idx < ACC101_NUM_ACCS) {
				acc = qman_func_id[idx];
				updateQtop(acc, qg, acc101_conf, d);
			}
		}
	}

	/* Check the depth of the AQs*/
	reg_len0 = acc101_reg_read(d, reg_addr->depth_log0_offset);
	reg_len1 = acc101_reg_read(d, reg_addr->depth_log1_offset);
	for (acc = 0; acc < NUM_ACC; acc++) {
		qtopFromAcc(&q_top, acc, acc101_conf);
		if (q_top->first_qgroup_index < ACC101_NUM_QGRPS_PER_WORD)
			q_top->aq_depth_log2 = (reg_len0 >>
					(q_top->first_qgroup_index * 4))
					& 0xF;
		else
			q_top->aq_depth_log2 = (reg_len1 >>
					((q_top->first_qgroup_index -
					ACC101_NUM_QGRPS_PER_WORD) * 4))
					& 0xF;
	}
	/* Start Pmon */
	acc101_reg_write(d, reg_addr->pmon_ctrl_a, 0x2);
	acc101_reg_write(d, reg_addr->pmon_ctrl_b, 0x2);

	/* Read PF mode */
	if (d->pf_device) {
		reg_mode = acc101_reg_read(d, HWPfHiPfMode);
		acc101_conf->pf_mode_en = (reg_mode == ACC101_PF_VAL) ? 1 : 0;
	}

	rte_bbdev_log_debug(
			"%s Config LLR SIGN IN/OUT %s %s QG %u %u %u %u AQ %u %u %u %u Len %u %u %u %u\n",
			(d->pf_device) ? "PF" : "VF",
			(acc101_conf->input_pos_llr_1_bit) ? "POS" : "NEG",
			(acc101_conf->output_pos_llr_1_bit) ? "POS" : "NEG",
			acc101_conf->q_ul_4g.num_qgroups,
			acc101_conf->q_dl_4g.num_qgroups,
			acc101_conf->q_ul_5g.num_qgroups,
			acc101_conf->q_dl_5g.num_qgroups,
			acc101_conf->q_ul_4g.num_aqs_per_groups,
			acc101_conf->q_dl_4g.num_aqs_per_groups,
			acc101_conf->q_ul_5g.num_aqs_per_groups,
			acc101_conf->q_dl_5g.num_aqs_per_groups,
			acc101_conf->q_ul_4g.aq_depth_log2,
			acc101_conf->q_dl_4g.aq_depth_log2,
			acc101_conf->q_ul_5g.aq_depth_log2,
			acc101_conf->q_dl_5g.aq_depth_log2);
}

static inline void
acc101_vf2pf(struct acc101_device *d, unsigned int payload)
{
	acc101_reg_write(d, HWVfHiVfToPfDbellVf, payload);
}

static void
free_base_addresses(void **base_addrs, int size)
{
	int i;
	for (i = 0; i < size; i++)
		rte_free(base_addrs[i]);
}

static inline uint32_t
get_desc_len(void)
{
	return sizeof(union acc101_dma_desc);
}

/* Allocate the 2 * 64MB block for the sw rings */
static int
alloc_2x64mb_sw_rings_mem(struct rte_bbdev *dev, struct acc101_device *d,
		int socket)
{
	uint32_t sw_ring_size = ACC101_SIZE_64MBYTE;
	d->sw_rings_base = rte_zmalloc_socket(dev->device->driver->name,
			2 * sw_ring_size, RTE_CACHE_LINE_SIZE, socket);
	if (d->sw_rings_base == NULL) {
		rte_bbdev_log(ERR, "Failed to allocate memory for %s:%u",
				dev->device->driver->name,
				dev->data->dev_id);
		return -ENOMEM;
	}
	uint32_t next_64mb_align_offset = calc_mem_alignment_offset(
			d->sw_rings_base, ACC101_SIZE_64MBYTE);
	d->sw_rings = RTE_PTR_ADD(d->sw_rings_base, next_64mb_align_offset);
	d->sw_rings_iova = rte_malloc_virt2iova(d->sw_rings_base) +
			next_64mb_align_offset;
	d->sw_ring_size = ACC101_MAX_QUEUE_DEPTH * get_desc_len();
	d->sw_ring_max_depth = ACC101_MAX_QUEUE_DEPTH;

	return 0;
}

/* Attempt to allocate minimised memory space for sw rings */
static void
alloc_sw_rings_min_mem(struct rte_bbdev *dev, struct acc101_device *d,
		uint16_t num_queues, int socket)
{
	rte_iova_t sw_rings_base_iova, next_64mb_align_addr_iova;
	uint32_t next_64mb_align_offset;
	rte_iova_t sw_ring_iova_end_addr;
	void *base_addrs[ACC101_SW_RING_MEM_ALLOC_ATTEMPTS];
	void *sw_rings_base;
	int i = 0;
	uint32_t q_sw_ring_size = ACC101_MAX_QUEUE_DEPTH * get_desc_len();
	uint32_t dev_sw_ring_size = q_sw_ring_size * num_queues;
	/* Free first in case this is a reconfiguration */
	rte_free(d->sw_rings_base);

	/* Find an aligned block of memory to store sw rings */
	while (i < ACC101_SW_RING_MEM_ALLOC_ATTEMPTS) {
		/*
		 * sw_ring allocated memory is guaranteed to be aligned to
		 * q_sw_ring_size at the condition that the requested size is
		 * less than the page size
		 */
		sw_rings_base = rte_zmalloc_socket(
				dev->device->driver->name,
				dev_sw_ring_size, q_sw_ring_size, socket);

		if (sw_rings_base == NULL) {
			rte_bbdev_log(ERR,
					"Failed to allocate memory for %s:%u",
					dev->device->driver->name,
					dev->data->dev_id);
			break;
		}

		sw_rings_base_iova = rte_malloc_virt2iova(sw_rings_base);
		next_64mb_align_offset = calc_mem_alignment_offset(
				sw_rings_base, ACC101_SIZE_64MBYTE);
		next_64mb_align_addr_iova = sw_rings_base_iova +
				next_64mb_align_offset;
		sw_ring_iova_end_addr = sw_rings_base_iova + dev_sw_ring_size;

		/* Check if the end of the sw ring memory block is before the
		 * start of next 64MB aligned mem address
		 */
		if (sw_ring_iova_end_addr < next_64mb_align_addr_iova) {
			d->sw_rings_iova = sw_rings_base_iova;
			d->sw_rings = sw_rings_base;
			d->sw_rings_base = sw_rings_base;
			d->sw_ring_size = q_sw_ring_size;
			d->sw_ring_max_depth = ACC101_MAX_QUEUE_DEPTH;
			break;
		}
		/* Store the address of the unaligned mem block */
		base_addrs[i] = sw_rings_base;
		i++;
	}

	/* Free all unaligned blocks of mem allocated in the loop */
	free_base_addresses(base_addrs, i);
}

/* Allocate 64MB memory used for all software rings */
static int
acc101_setup_queues(struct rte_bbdev *dev, uint16_t num_queues, int socket_id)
{
	uint32_t phys_low, phys_high, value;
	struct acc101_device *d = dev->data->dev_private;
	const struct acc101_registry_addr *reg_addr;

	if (d->pf_device && !d->acc101_conf.pf_mode_en) {
		rte_bbdev_log(NOTICE,
				"%s has PF mode disabled. This PF can't be used.",
				dev->data->name);
		return -ENODEV;
	}

	alloc_sw_rings_min_mem(dev, d, num_queues, socket_id);

	/* If minimal memory space approach failed, then allocate
	 * the 2 * 64MB block for the sw rings
	 */
	if (d->sw_rings == NULL)
		alloc_2x64mb_sw_rings_mem(dev, d, socket_id);

	if (d->sw_rings == NULL) {
		rte_bbdev_log(NOTICE,
				"Failure allocating sw_rings memory");
		return -ENODEV;
	}

	/* Configure ACC101 with the base address for DMA descriptor rings
	 * Same descriptor rings used for UL and DL DMA Engines
	 * Note : Assuming only VF0 bundle is used for PF mode
	 */
	phys_high = (uint32_t)(d->sw_rings_iova >> 32);
	phys_low  = (uint32_t)(d->sw_rings_iova & ~(ACC101_SIZE_64MBYTE-1));

	/* Choose correct registry addresses for the device type */
	if (d->pf_device)
		reg_addr = &pf_reg_addr;
	else
		reg_addr = &vf_reg_addr;

	/* Read the populated cfg from ACC101 registers */
	fetch_acc101_config(dev);

	/* Release AXI from PF with 2 ms threshold */
	if (d->pf_device) {
		usleep(2000);
		acc101_reg_write(d, HWPfDmaAxiControl, 1);
	}

	acc101_reg_write(d, reg_addr->dma_ring_ul5g_hi, phys_high);
	acc101_reg_write(d, reg_addr->dma_ring_ul5g_lo, phys_low);
	acc101_reg_write(d, reg_addr->dma_ring_dl5g_hi, phys_high);
	acc101_reg_write(d, reg_addr->dma_ring_dl5g_lo, phys_low);
	acc101_reg_write(d, reg_addr->dma_ring_ul4g_hi, phys_high);
	acc101_reg_write(d, reg_addr->dma_ring_ul4g_lo, phys_low);
	acc101_reg_write(d, reg_addr->dma_ring_dl4g_hi, phys_high);
	acc101_reg_write(d, reg_addr->dma_ring_dl4g_lo, phys_low);

	/*
	 * Configure Ring Size to the max queue ring size
	 * (used for wrapping purpose)
	 */
	value = log2_basic(d->sw_ring_size / 64);
	acc101_reg_write(d, reg_addr->ring_size, value);

	/* Configure tail pointer for use when SDONE enabled */
	if (d->tail_ptrs == NULL)
		d->tail_ptrs = rte_zmalloc_socket(
				dev->device->driver->name,
				ACC101_NUM_QGRPS * ACC101_NUM_AQS * sizeof(uint32_t),
				RTE_CACHE_LINE_SIZE, socket_id);
	if (d->tail_ptrs == NULL) {
		rte_bbdev_log(ERR, "Failed to allocate tail ptr for %s:%u",
				dev->device->driver->name,
				dev->data->dev_id);
		rte_free(d->sw_rings);
		return -ENOMEM;
	}
	d->tail_ptr_iova = rte_malloc_virt2iova(d->tail_ptrs);

	phys_high = (uint32_t)(d->tail_ptr_iova >> 32);
	phys_low  = (uint32_t)(d->tail_ptr_iova);
	acc101_reg_write(d, reg_addr->tail_ptrs_ul5g_hi, phys_high);
	acc101_reg_write(d, reg_addr->tail_ptrs_ul5g_lo, phys_low);
	acc101_reg_write(d, reg_addr->tail_ptrs_dl5g_hi, phys_high);
	acc101_reg_write(d, reg_addr->tail_ptrs_dl5g_lo, phys_low);
	acc101_reg_write(d, reg_addr->tail_ptrs_ul4g_hi, phys_high);
	acc101_reg_write(d, reg_addr->tail_ptrs_ul4g_lo, phys_low);
	acc101_reg_write(d, reg_addr->tail_ptrs_dl4g_hi, phys_high);
	acc101_reg_write(d, reg_addr->tail_ptrs_dl4g_lo, phys_low);

	if (d->harq_layout == NULL)
		d->harq_layout = rte_zmalloc_socket("HARQ Layout",
				ACC101_HARQ_LAYOUT * sizeof(*d->harq_layout),
				RTE_CACHE_LINE_SIZE, dev->data->socket_id);
	if (d->harq_layout == NULL) {
		rte_bbdev_log(ERR, "Failed to allocate harq_layout for %s:%u",
				dev->device->driver->name,
				dev->data->dev_id);
		rte_free(d->sw_rings);
		return -ENOMEM;
	}

	/* Mark as configured properly */
	d->configured = true;
	acc101_vf2pf(d, ACC101_VF2PF_USING_VF);

	rte_bbdev_log_debug(
			"ACC101 (%s) configured  sw_rings = %p, sw_rings_iova = %#"
			PRIx64, dev->data->name, d->sw_rings, d->sw_rings_iova);

	return 0;
}

/* Free memory used for software rings */
static int
acc101_dev_close(struct rte_bbdev *dev)
{
	struct acc101_device *d = dev->data->dev_private;
	if (d->sw_rings_base != NULL) {
		rte_free(d->tail_ptrs);
		rte_free(d->sw_rings_base);
		rte_free(d->harq_layout);
		d->sw_rings_base = NULL;
	}
	return 0;
}

/**
 * Report a ACC101 queue index which is free
 * Return 0 to 16k for a valid queue_idx or -1 when no queue is available
 * Note : Only supporting VF0 Bundle for PF mode
 */
static int
acc101_find_free_queue_idx(struct rte_bbdev *dev,
		const struct rte_bbdev_queue_conf *conf)
{
	struct acc101_device *d = dev->data->dev_private;
	int op_2_acc[5] = {0, UL_4G, DL_4G, UL_5G, DL_5G};
	int acc = op_2_acc[conf->op_type];
	struct rte_acc101_queue_topology *qtop = NULL;

	qtopFromAcc(&qtop, acc, &(d->acc101_conf));
	if (qtop == NULL)
		return -1;
	/* Identify matching QGroup Index which are sorted in priority order */
	uint16_t group_idx = qtop->first_qgroup_index;
	group_idx += conf->priority;
	if (group_idx >= ACC101_NUM_QGRPS ||
			conf->priority >= qtop->num_qgroups) {
		rte_bbdev_log(INFO, "Invalid Priority on %s, priority %u",
				dev->data->name, conf->priority);
		return -1;
	}
	/* Find a free AQ_idx  */
	uint16_t aq_idx;
	for (aq_idx = 0; aq_idx < qtop->num_aqs_per_groups; aq_idx++) {
		if (((d->q_assigned_bit_map[group_idx] >> aq_idx) & 0x1) == 0) {
			/* Mark the Queue as assigned */
			d->q_assigned_bit_map[group_idx] |= (1 << aq_idx);
			/* Report the AQ Index */
			return (group_idx << ACC101_GRP_ID_SHIFT) + aq_idx;
		}
	}
	rte_bbdev_log(INFO, "Failed to find free queue on %s, priority %u",
			dev->data->name, conf->priority);
	return -1;
}

/* Setup ACC101 queue */
static int
acc101_queue_setup(struct rte_bbdev *dev, uint16_t queue_id,
		const struct rte_bbdev_queue_conf *conf)
{
	struct acc101_device *d = dev->data->dev_private;
	struct acc101_queue *q;
	int16_t q_idx;

	if (d == NULL) {
		rte_bbdev_log(ERR, "Undefined device");
		return -ENODEV;
	}
	/* Allocate the queue data structure. */
	q = rte_zmalloc_socket(dev->device->driver->name, sizeof(*q),
			RTE_CACHE_LINE_SIZE, conf->socket);
	if (q == NULL) {
		rte_bbdev_log(ERR, "Failed to allocate queue memory");
		return -ENOMEM;
	}

	q->d = d;
	q->ring_addr = RTE_PTR_ADD(d->sw_rings, (d->sw_ring_size * queue_id));
	q->ring_addr_iova = d->sw_rings_iova + (d->sw_ring_size * queue_id);

	/* Prepare the Ring with default descriptor format */
	union acc101_dma_desc *desc = NULL;
	unsigned int desc_idx, b_idx;
	int fcw_len = (conf->op_type == RTE_BBDEV_OP_LDPC_ENC ?
		ACC101_FCW_LE_BLEN : (conf->op_type == RTE_BBDEV_OP_TURBO_DEC ?
		ACC101_FCW_TD_BLEN : ACC101_FCW_LD_BLEN));

	for (desc_idx = 0; desc_idx < d->sw_ring_max_depth; desc_idx++) {
		desc = q->ring_addr + desc_idx;
		desc->req.word0 = ACC101_DMA_DESC_TYPE;
		desc->req.word1 = 0; /**< Timestamp */
		desc->req.word2 = 0;
		desc->req.word3 = 0;
		uint64_t fcw_offset = (desc_idx << 8) + ACC101_DESC_FCW_OFFSET;
		desc->req.data_ptrs[0].address = q->ring_addr_iova + fcw_offset;
		desc->req.data_ptrs[0].blen = fcw_len;
		desc->req.data_ptrs[0].blkid = ACC101_DMA_BLKID_FCW;
		desc->req.data_ptrs[0].last = 0;
		desc->req.data_ptrs[0].dma_ext = 0;
		for (b_idx = 1; b_idx < ACC101_DMA_MAX_NUM_POINTERS - 1;
				b_idx++) {
			desc->req.data_ptrs[b_idx].blkid = ACC101_DMA_BLKID_IN;
			desc->req.data_ptrs[b_idx].last = 1;
			desc->req.data_ptrs[b_idx].dma_ext = 0;
			b_idx++;
			desc->req.data_ptrs[b_idx].blkid =
					ACC101_DMA_BLKID_OUT_ENC;
			desc->req.data_ptrs[b_idx].last = 1;
			desc->req.data_ptrs[b_idx].dma_ext = 0;
		}
		/* Preset some fields of LDPC FCW */
		desc->req.fcw_ld.FCWversion = ACC101_FCW_VER;
		desc->req.fcw_ld.gain_i = 1;
		desc->req.fcw_ld.gain_h = 1;
	}

	q->lb_in = rte_zmalloc_socket(dev->device->driver->name,
			RTE_CACHE_LINE_SIZE,
			RTE_CACHE_LINE_SIZE, conf->socket);
	if (q->lb_in == NULL) {
		rte_bbdev_log(ERR, "Failed to allocate lb_in memory");
		rte_free(q);
		return -ENOMEM;
	}
	q->lb_in_addr_iova = rte_malloc_virt2iova(q->lb_in);
	q->lb_out = rte_zmalloc_socket(dev->device->driver->name,
			RTE_CACHE_LINE_SIZE,
			RTE_CACHE_LINE_SIZE, conf->socket);
	if (q->lb_out == NULL) {
		rte_bbdev_log(ERR, "Failed to allocate lb_out memory");
		rte_free(q->lb_in);
		rte_free(q);
		return -ENOMEM;
	}
	q->derm_buffer = rte_zmalloc_socket(dev->device->driver->name,
			RTE_BBDEV_TURBO_MAX_CB_SIZE * 10,
			RTE_CACHE_LINE_SIZE, conf->socket);
	if (q->derm_buffer == NULL) {
		rte_bbdev_log(ERR, "Failed to allocate derm_buffer memory");
		rte_free(q->lb_in);
		rte_free(q->lb_out);
		rte_free(q);
		return -ENOMEM;
	}
	q->lb_out_addr_iova = rte_malloc_virt2iova(q->lb_out);
	q->companion_ring_addr = rte_zmalloc_socket(dev->device->driver->name,
			d->sw_ring_max_depth * sizeof(*q->companion_ring_addr),
			RTE_CACHE_LINE_SIZE, conf->socket);
	if (q->companion_ring_addr == NULL) {
		rte_bbdev_log(ERR, "Failed to allocate companion_ring memory");
		rte_free(q->derm_buffer);
		rte_free(q->lb_in);
		rte_free(q->lb_out);
		rte_free(q);
		return -ENOMEM;
	}

	/*
	 * Software queue ring wraps synchronously with the HW when it reaches
	 * the boundary of the maximum allocated queue size, no matter what the
	 * sw queue size is. This wrapping is guarded by setting the wrap_mask
	 * to represent the maximum queue size as allocated at the time when
	 * the device has been setup (in configure()).
	 *
	 * The queue depth is set to the queue size value (conf->queue_size).
	 * This limits the occupancy of the queue at any point of time, so that
	 * the queue does not get swamped with enqueue requests.
	 */
	q->sw_ring_depth = conf->queue_size;
	q->sw_ring_wrap_mask = d->sw_ring_max_depth - 1;

	q->op_type = conf->op_type;

	q_idx = acc101_find_free_queue_idx(dev, conf);
	if (q_idx == -1) {
		rte_free(q->companion_ring_addr);
		rte_free(q->derm_buffer);
		rte_free(q->lb_in);
		rte_free(q->lb_out);
		rte_free(q);
		return -1;
	}

	q->qgrp_id = (q_idx >> ACC101_GRP_ID_SHIFT) & 0xF;
	q->vf_id = (q_idx >> ACC101_VF_ID_SHIFT)  & 0x3F;
	q->aq_id = q_idx & 0xF;
	q->aq_depth = 0;
	if (conf->op_type ==  RTE_BBDEV_OP_TURBO_DEC)
		q->aq_depth = (1 << d->acc101_conf.q_ul_4g.aq_depth_log2);
	else if (conf->op_type ==  RTE_BBDEV_OP_TURBO_ENC)
		q->aq_depth = (1 << d->acc101_conf.q_dl_4g.aq_depth_log2);
	else if (conf->op_type ==  RTE_BBDEV_OP_LDPC_DEC)
		q->aq_depth = (1 << d->acc101_conf.q_ul_5g.aq_depth_log2);
	else if (conf->op_type ==  RTE_BBDEV_OP_LDPC_ENC)
		q->aq_depth = (1 << d->acc101_conf.q_dl_5g.aq_depth_log2);

	q->mmio_reg_enqueue = RTE_PTR_ADD(d->mmio_base,
			queue_offset(d->pf_device,
					q->vf_id, q->qgrp_id, q->aq_id));

	rte_bbdev_log_debug(
			"Setup dev%u q%u: qgrp_id=%u, vf_id=%u, aq_id=%u, aq_depth=%u, mmio_reg_enqueue=%p",
			dev->data->dev_id, queue_id, q->qgrp_id, q->vf_id,
			q->aq_id, q->aq_depth, q->mmio_reg_enqueue);

	dev->data->queues[queue_id].queue_private = q;

	return 0;
}

static inline void
acc101_print_op(struct rte_bbdev_dec_op *op, enum rte_bbdev_op_type op_type,
		uint16_t index)
{
	if (op == NULL)
		return;
	if (op_type == RTE_BBDEV_OP_LDPC_DEC)
		rte_bbdev_log(INFO,
			"  Op 5GUL %d %d %d %d %d %d %d %d %d %d %d %d",
			index,
			op->ldpc_dec.basegraph, op->ldpc_dec.z_c,
			op->ldpc_dec.n_cb, op->ldpc_dec.q_m,
			op->ldpc_dec.n_filler, op->ldpc_dec.cb_params.e,
			op->ldpc_dec.op_flags, op->ldpc_dec.rv_index,
			op->ldpc_dec.iter_max, op->ldpc_dec.iter_count,
			op->ldpc_dec.harq_combined_input.length
			);
	else if (op_type == RTE_BBDEV_OP_LDPC_ENC) {
		struct rte_bbdev_enc_op *op_dl = (struct rte_bbdev_enc_op *) op;
		rte_bbdev_log(INFO,
			"  Op 5GDL %d %d %d %d %d %d %d %d %d",
			index,
			op_dl->ldpc_enc.basegraph, op_dl->ldpc_enc.z_c,
			op_dl->ldpc_enc.n_cb, op_dl->ldpc_enc.q_m,
			op_dl->ldpc_enc.n_filler, op_dl->ldpc_enc.cb_params.e,
			op_dl->ldpc_enc.op_flags, op_dl->ldpc_enc.rv_index
			);
	}
}

static int
acc101_queue_stop(struct rte_bbdev *dev, uint16_t queue_id)
{
	struct acc101_queue *q;
	struct rte_bbdev_dec_op *op;
	uint16_t i;
	q = dev->data->queues[queue_id].queue_private;
	rte_bbdev_log(INFO, "Queue Stop %d H/T/D %d %d %x OpType %d",
			queue_id, q->sw_ring_head, q->sw_ring_tail,
			q->sw_ring_depth, q->op_type);
	for (i = 0; i < q->sw_ring_depth; ++i) {
		op = (q->ring_addr + i)->req.op_addr;
		acc101_print_op(op, q->op_type, i);
	}
	/* ignore all operations in flight and clear counters */
	q->sw_ring_tail = q->sw_ring_head;
	q->aq_enqueued = 0;
	q->aq_dequeued = 0;
	dev->data->queues[queue_id].queue_stats.enqueued_count = 0;
	dev->data->queues[queue_id].queue_stats.dequeued_count = 0;
	dev->data->queues[queue_id].queue_stats.enqueue_err_count = 0;
	dev->data->queues[queue_id].queue_stats.dequeue_err_count = 0;
	return 0;
}

/* Release ACC101 queue */
static int
acc101_queue_release(struct rte_bbdev *dev, uint16_t q_id)
{
	struct acc101_device *d = dev->data->dev_private;
	struct acc101_queue *q = dev->data->queues[q_id].queue_private;

	if (q != NULL) {
		/* Mark the Queue as un-assigned */
		d->q_assigned_bit_map[q->qgrp_id] &= (0xFFFFFFFF -
				(1 << q->aq_id));
		rte_free(q->companion_ring_addr);
		rte_free(q->derm_buffer);
		rte_free(q->lb_in);
		rte_free(q->lb_out);
		rte_free(q);
		dev->data->queues[q_id].queue_private = NULL;
	}

	return 0;
}

/* Get ACC101 device info */
static void
acc101_dev_info_get(struct rte_bbdev *dev,
		struct rte_bbdev_driver_info *dev_info)
{
	struct acc101_device *d = dev->data->dev_private;
	static const struct rte_bbdev_op_cap bbdev_capabilities[] = {
		{
			.type   = RTE_BBDEV_OP_LDPC_ENC,
			.cap.ldpc_enc = {
				.capability_flags =
					RTE_BBDEV_LDPC_RATE_MATCH |
					RTE_BBDEV_LDPC_CRC_24B_ATTACH |
					RTE_BBDEV_LDPC_INTERLEAVER_BYPASS,
				.num_buffers_src =
						RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
				.num_buffers_dst =
						RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			}
		},
		{
			.type   = RTE_BBDEV_OP_LDPC_DEC,
			.cap.ldpc_dec = {
			.capability_flags =
				RTE_BBDEV_LDPC_CRC_TYPE_24B_CHECK |
				RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP |
				RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE |
				RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE |
#ifdef ACC101_EXT_MEM
				RTE_BBDEV_LDPC_INTERNAL_HARQ_MEMORY_LOOPBACK |
				RTE_BBDEV_LDPC_INTERNAL_HARQ_MEMORY_IN_ENABLE |
				RTE_BBDEV_LDPC_INTERNAL_HARQ_MEMORY_OUT_ENABLE |
#endif
				RTE_BBDEV_LDPC_ITERATION_STOP_ENABLE |
				RTE_BBDEV_LDPC_DEINTERLEAVER_BYPASS |
				RTE_BBDEV_LDPC_DECODE_BYPASS |
				RTE_BBDEV_LDPC_DEC_SCATTER_GATHER |
				RTE_BBDEV_LDPC_HARQ_6BIT_COMPRESSION |
				RTE_BBDEV_LDPC_LLR_COMPRESSION,
			.llr_size = 8,
			.llr_decimals = 1,
			.num_buffers_src =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			.num_buffers_hard_out =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			.num_buffers_soft_out = 0,
			}
		},
		RTE_BBDEV_END_OF_CAPABILITIES_LIST()
	};

	static struct rte_bbdev_queue_conf default_queue_conf;
	default_queue_conf.socket = dev->data->socket_id;
	default_queue_conf.queue_size = ACC101_MAX_QUEUE_DEPTH;

	dev_info->driver_name = dev->device->driver->name;

	/* Read and save the populated config from ACC101 registers */
	fetch_acc101_config(dev);
	/* This isn't ideal because it reports the maximum number of queues but
	 * does not provide info on how many can be uplink/downlink or different
	 * priorities
	 */
	dev_info->max_num_queues =
			d->acc101_conf.q_dl_5g.num_aqs_per_groups *
			d->acc101_conf.q_dl_5g.num_qgroups +
			d->acc101_conf.q_ul_5g.num_aqs_per_groups *
			d->acc101_conf.q_ul_5g.num_qgroups +
			d->acc101_conf.q_dl_4g.num_aqs_per_groups *
			d->acc101_conf.q_dl_4g.num_qgroups +
			d->acc101_conf.q_ul_4g.num_aqs_per_groups *
			d->acc101_conf.q_ul_4g.num_qgroups;
	dev_info->queue_size_lim = ACC101_MAX_QUEUE_DEPTH;
	dev_info->hardware_accelerated = true;
	dev_info->max_dl_queue_priority =
			d->acc101_conf.q_dl_4g.num_qgroups - 1;
	dev_info->max_ul_queue_priority =
			d->acc101_conf.q_ul_4g.num_qgroups - 1;
	dev_info->default_queue_conf = default_queue_conf;
	dev_info->cpu_flag_reqs = NULL;
	dev_info->min_alignment = 64;
	dev_info->capabilities = bbdev_capabilities;
#ifdef ACC101_EXT_MEM
	dev_info->harq_buffer_size = d->ddr_size;
#else
	dev_info->harq_buffer_size = 0;
#endif
}

static const struct rte_bbdev_ops acc101_bbdev_ops = {
	.setup_queues = acc101_setup_queues,
	.close = acc101_dev_close,
	.info_get = acc101_dev_info_get,
	.queue_setup = acc101_queue_setup,
	.queue_release = acc101_queue_release,
	.queue_stop = acc101_queue_stop,
};

/* ACC101 PCI PF address map */
static struct rte_pci_id pci_id_acc101_pf_map[] = {
	{
		RTE_PCI_DEVICE(RTE_ACC101_VENDOR_ID, RTE_ACC101_PF_DEVICE_ID)
	},
	{.device_id = 0},
};

/* ACC101 PCI VF address map */
static struct rte_pci_id pci_id_acc101_vf_map[] = {
	{
		RTE_PCI_DEVICE(RTE_ACC101_VENDOR_ID, RTE_ACC101_VF_DEVICE_ID)
	},
	{.device_id = 0},
};

/* Read flag value 0/1 from bitmap */
static inline bool
check_bit(uint32_t bitmap, uint32_t bitmask)
{
	return bitmap & bitmask;
}

static inline char *
mbuf_append(struct rte_mbuf *m_head, struct rte_mbuf *m, uint16_t len)
{
	if (unlikely(len > rte_pktmbuf_tailroom(m)))
		return NULL;

	char *tail = (char *)m->buf_addr + m->data_off + m->data_len;
	m->data_len = (uint16_t)(m->data_len + len);
	m_head->pkt_len  = (m_head->pkt_len + len);
	return tail;
}

/* Compute value of k0.
 * Based on 3GPP 38.212 Table 5.4.2.1-2
 * Starting position of different redundancy versions, k0
 */
static inline uint16_t
get_k0(uint16_t n_cb, uint16_t z_c, uint8_t bg, uint8_t rv_index)
{
	if (rv_index == 0)
		return 0;
	uint16_t n = (bg == 1 ? ACC101_N_ZC_1 : ACC101_N_ZC_2) * z_c;
	if (n_cb == n) {
		if (rv_index == 1)
			return (bg == 1 ? ACC101_K0_1_1 : ACC101_K0_1_2) * z_c;
		else if (rv_index == 2)
			return (bg == 1 ? ACC101_K0_2_1 : ACC101_K0_2_2) * z_c;
		else
			return (bg == 1 ? ACC101_K0_3_1 : ACC101_K0_3_2) * z_c;
	}
	/* LBRM case - includes a division by N */
	if (unlikely(z_c == 0))
		return 0;
	if (rv_index == 1)
		return (((bg == 1 ? ACC101_K0_1_1 : ACC101_K0_1_2) * n_cb)
				/ n) * z_c;
	else if (rv_index == 2)
		return (((bg == 1 ? ACC101_K0_2_1 : ACC101_K0_2_2) * n_cb)
				/ n) * z_c;
	else
		return (((bg == 1 ? ACC101_K0_3_1 : ACC101_K0_3_2) * n_cb)
				/ n) * z_c;
}

/* Fill in a frame control word for LDPC encoding. */
static inline void
acc101_fcw_le_fill(const struct rte_bbdev_enc_op *op,
		struct acc101_fcw_le *fcw, int num_cb, uint32_t default_e)
{
	fcw->qm = op->ldpc_enc.q_m;
	fcw->nfiller = op->ldpc_enc.n_filler;
	fcw->BG = (op->ldpc_enc.basegraph - 1);
	fcw->Zc = op->ldpc_enc.z_c;
	fcw->ncb = op->ldpc_enc.n_cb;
	fcw->k0 = get_k0(fcw->ncb, fcw->Zc, op->ldpc_enc.basegraph,
			op->ldpc_enc.rv_index);
	fcw->rm_e = (default_e == 0) ? op->ldpc_enc.cb_params.e : default_e;
	fcw->crc_select = check_bit(op->ldpc_enc.op_flags,
			RTE_BBDEV_LDPC_CRC_24B_ATTACH);
	fcw->bypass_intlv = check_bit(op->ldpc_enc.op_flags,
			RTE_BBDEV_LDPC_INTERLEAVER_BYPASS);
	fcw->mcb_count = num_cb;
}

/* Convert offset to harq index for harq_layout structure */
static inline uint32_t hq_index(uint32_t offset)
{
	return (offset >> ACC101_HARQ_OFFSET_SHIFT) & ACC101_HARQ_OFFSET_MASK;
}

/* Fill in a frame control word for LDPC decoding. */
static inline void
acc101_fcw_ld_fill(struct rte_bbdev_dec_op *op, struct acc101_fcw_ld *fcw,
		union acc101_harq_layout_data *harq_layout)
{
	uint16_t harq_out_length, harq_in_length, ncb_p, k0_p, parity_offset;
	uint32_t harq_index;
	uint32_t l;

	fcw->qm = op->ldpc_dec.q_m;
	fcw->nfiller = op->ldpc_dec.n_filler;
	fcw->BG = (op->ldpc_dec.basegraph - 1);
	fcw->Zc = op->ldpc_dec.z_c;
	fcw->ncb = op->ldpc_dec.n_cb;
	fcw->k0 = get_k0(fcw->ncb, fcw->Zc, op->ldpc_dec.basegraph,
			op->ldpc_dec.rv_index);
	if (op->ldpc_dec.code_block_mode == RTE_BBDEV_CODE_BLOCK)
		fcw->rm_e = op->ldpc_dec.cb_params.e;
	else
		fcw->rm_e = (op->ldpc_dec.tb_params.r <
				op->ldpc_dec.tb_params.cab) ?
						op->ldpc_dec.tb_params.ea :
						op->ldpc_dec.tb_params.eb;

	if (unlikely(check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
			(op->ldpc_dec.harq_combined_input.length == 0))) {
		rte_bbdev_log(WARNING, "Null HARQ input size provided");
		/* Disable HARQ input in that case to carry forward */
		op->ldpc_dec.op_flags ^= RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE;
	}

	fcw->hcin_en = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE);
	fcw->hcout_en = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE);
	fcw->crc_select = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_CRC_TYPE_24B_CHECK);
	fcw->bypass_dec = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_DECODE_BYPASS);
	fcw->bypass_intlv = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_DEINTERLEAVER_BYPASS);
	if (op->ldpc_dec.q_m == 1) {
		fcw->bypass_intlv = 1;
		fcw->qm = 2;
	}
	fcw->hcin_decomp_mode = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_HARQ_6BIT_COMPRESSION);
	fcw->hcout_comp_mode = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_HARQ_6BIT_COMPRESSION);
	fcw->llr_pack_mode = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_LLR_COMPRESSION);
	harq_index = hq_index(op->ldpc_dec.harq_combined_output.offset);
	if (fcw->hcin_en > 0) {
		harq_in_length = op->ldpc_dec.harq_combined_input.length;
		if (fcw->hcin_decomp_mode > 0)
			harq_in_length = harq_in_length * 8 / 6;
		harq_in_length = RTE_MIN(harq_in_length, op->ldpc_dec.n_cb
				- op->ldpc_dec.n_filler);
		/* Alignment on next 64B - Already enforced from HC output */
		harq_in_length = RTE_ALIGN_FLOOR(harq_in_length, 64);
		fcw->hcin_size0 = harq_in_length;
		fcw->hcin_offset = 0;
		fcw->hcin_size1 = 0;
	} else {
		fcw->hcin_size0 = 0;
		fcw->hcin_offset = 0;
		fcw->hcin_size1 = 0;
	}

	fcw->itmax = op->ldpc_dec.iter_max;
	fcw->itstop = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_ITERATION_STOP_ENABLE);
	fcw->synd_precoder = fcw->itstop;
	/*
	 * These are all implicitly set
	 * fcw->synd_post = 0;
	 * fcw->so_en = 0;
	 * fcw->so_bypass_rm = 0;
	 * fcw->so_bypass_intlv = 0;
	 * fcw->dec_convllr = 0;
	 * fcw->hcout_convllr = 0;
	 * fcw->hcout_size1 = 0;
	 * fcw->so_it = 0;
	 * fcw->hcout_offset = 0;
	 * fcw->negstop_th = 0;
	 * fcw->negstop_it = 0;
	 * fcw->negstop_en = 0;
	 * fcw->gain_i = 1;
	 * fcw->gain_h = 1;
	 */
	if (fcw->hcout_en > 0) {
		parity_offset = (op->ldpc_dec.basegraph == 1 ? 20 : 8)
			* op->ldpc_dec.z_c - op->ldpc_dec.n_filler;
		k0_p = (fcw->k0 > parity_offset) ?
				fcw->k0 - op->ldpc_dec.n_filler : fcw->k0;
		ncb_p = fcw->ncb - op->ldpc_dec.n_filler;
		l = RTE_MIN(k0_p + fcw->rm_e, INT16_MAX);
		harq_out_length = (uint16_t) fcw->hcin_size0;
		harq_out_length = RTE_MAX(harq_out_length, l);
		/* Cannot exceed the pruned Ncb circular buffer */
		harq_out_length = RTE_MIN(harq_out_length, ncb_p);
		/* Alignment on next 64B */
		harq_out_length = RTE_ALIGN_CEIL(harq_out_length, 64);
		fcw->hcout_size0 = harq_out_length;
		fcw->hcout_size1 = 0;
		fcw->hcout_offset = 0;
		harq_layout[harq_index].offset = fcw->hcout_offset;
		harq_layout[harq_index].size0 = fcw->hcout_size0;
	} else {
		fcw->hcout_size0 = 0;
		fcw->hcout_size1 = 0;
		fcw->hcout_offset = 0;
	}
}

/**
 * Fills descriptor with data pointers of one block type.
 *
 * @param desc
 *   Pointer to DMA descriptor.
 * @param input
 *   Pointer to pointer to input data which will be encoded. It can be changed
 *   and points to next segment in scatter-gather case.
 * @param offset
 *   Input offset in rte_mbuf structure. It is used for calculating the point
 *   where data is starting.
 * @param cb_len
 *   Length of currently processed Code Block
 * @param seg_total_left
 *   It indicates how many bytes still left in segment (mbuf) for further
 *   processing.
 * @param op_flags
 *   Store information about device capabilities
 * @param next_triplet
 *   Index for ACC101 DMA Descriptor triplet
 * @param scattergather
 *   Flag to support scatter-gather for the mbuf
 *
 * @return
 *   Returns index of next triplet on success, other value if lengths of
 *   pkt and processed cb do not match.
 *
 */
static inline int
acc101_dma_fill_blk_type_in(struct acc101_dma_req_desc *desc,
		struct rte_mbuf **input, uint32_t *offset, uint32_t cb_len,
		uint32_t *seg_total_left, int next_triplet,
		bool scattergather)
{
	uint32_t part_len;
	struct rte_mbuf *m = *input;

	if (scattergather)
		part_len = (*seg_total_left < cb_len) ?
				*seg_total_left : cb_len;
	else
		part_len = cb_len;
	cb_len -= part_len;
	*seg_total_left -= part_len;

	desc->data_ptrs[next_triplet].address =
			rte_pktmbuf_iova_offset(m, *offset);
	desc->data_ptrs[next_triplet].blen = part_len;
	desc->data_ptrs[next_triplet].blkid = ACC101_DMA_BLKID_IN;
	desc->data_ptrs[next_triplet].last = 0;
	desc->data_ptrs[next_triplet].dma_ext = 0;
	*offset += part_len;
	next_triplet++;

	while (cb_len > 0) {
		if (next_triplet < ACC101_DMA_MAX_NUM_POINTERS_IN && m->next != NULL) {

			m = m->next;
			*seg_total_left = rte_pktmbuf_data_len(m);
			part_len = (*seg_total_left < cb_len) ?
					*seg_total_left :
					cb_len;
			desc->data_ptrs[next_triplet].address =
					rte_pktmbuf_iova_offset(m, 0);
			desc->data_ptrs[next_triplet].blen = part_len;
			desc->data_ptrs[next_triplet].blkid =
					ACC101_DMA_BLKID_IN;
			desc->data_ptrs[next_triplet].last = 0;
			desc->data_ptrs[next_triplet].dma_ext = 0;
			cb_len -= part_len;
			*seg_total_left -= part_len;
			/* Initializing offset for next segment (mbuf) */
			*offset = part_len;
			next_triplet++;
		} else {
			rte_bbdev_log(ERR,
				"Some data still left for processing: "
				"data_left: %u, next_triplet: %u, next_mbuf: %p",
				cb_len, next_triplet, m->next);
			return -EINVAL;
		}
	}
	/* Storing new mbuf as it could be changed in scatter-gather case*/
	*input = m;

	return next_triplet;
}

/* Fills descriptor with data pointers of one block type.
 * Returns index of next triplet on success, other value if lengths of
 * output data and processed mbuf do not match.
 */
static inline int
acc101_dma_fill_blk_type_out(struct acc101_dma_req_desc *desc,
		struct rte_mbuf *output, uint32_t out_offset,
		uint32_t output_len, int next_triplet, int blk_id)
{
	desc->data_ptrs[next_triplet].address =
			rte_pktmbuf_iova_offset(output, out_offset);
	desc->data_ptrs[next_triplet].blen = output_len;
	desc->data_ptrs[next_triplet].blkid = blk_id;
	desc->data_ptrs[next_triplet].last = 0;
	desc->data_ptrs[next_triplet].dma_ext = 0;
	next_triplet++;

	return next_triplet;
}

static inline void
acc101_header_init(struct acc101_dma_req_desc *desc)
{
	desc->word0 = ACC101_DMA_DESC_TYPE;
	desc->word1 = 0; /**< Timestamp could be disabled */
	desc->word2 = 0;
	desc->word3 = 0;
	desc->numCBs = 1;
}

#ifdef RTE_LIBRTE_BBDEV_DEBUG
/* Check if any input data is unexpectedly left for processing */
static inline int
check_mbuf_total_left(uint32_t mbuf_total_left)
{
	if (mbuf_total_left == 0)
		return 0;
	rte_bbdev_log(ERR,
		"Some date still left for processing: mbuf_total_left = %u",
		mbuf_total_left);
	return -EINVAL;
}
#endif

static inline int
acc101_dma_desc_le_fill(struct rte_bbdev_enc_op *op,
		struct acc101_dma_req_desc *desc, struct rte_mbuf **input,
		struct rte_mbuf *output, uint32_t *in_offset,
		uint32_t *out_offset, uint32_t *out_length,
		uint32_t *mbuf_total_left, uint32_t *seg_total_left)
{
	int next_triplet = 1; /* FCW already done */
	uint16_t K, in_length_in_bits, in_length_in_bytes;
	struct rte_bbdev_op_ldpc_enc *enc = &op->ldpc_enc;

	acc101_header_init(desc);

	K = (enc->basegraph == 1 ? 22 : 10) * enc->z_c;
	in_length_in_bits = K - enc->n_filler;
	if (enc->op_flags & RTE_BBDEV_LDPC_CRC_24B_ATTACH)
		in_length_in_bits -= 24;
	in_length_in_bytes = in_length_in_bits >> 3;

	if (unlikely((*mbuf_total_left == 0) ||
			(*mbuf_total_left < in_length_in_bytes))) {
		rte_bbdev_log(ERR,
				"Mismatch between mbuf length and included CB sizes: mbuf len %u, cb len %u",
				*mbuf_total_left, in_length_in_bytes);
		return -1;
	}

	next_triplet = acc101_dma_fill_blk_type_in(desc, input, in_offset,
			in_length_in_bytes,
			seg_total_left, next_triplet,
			false);
	if (unlikely(next_triplet < 0)) {
		rte_bbdev_log(ERR,
				"Mismatch between data to process and mbuf data length in bbdev_op: %p",
				op);
		return -1;
	}
	desc->data_ptrs[next_triplet - 1].last = 1;
	desc->m2dlen = next_triplet;
	*mbuf_total_left -= in_length_in_bytes;

	/* Set output length */
	/* Integer round up division by 8 */
	*out_length = (enc->cb_params.e + 7) >> 3;

	next_triplet = acc101_dma_fill_blk_type_out(desc, output, *out_offset,
			*out_length, next_triplet, ACC101_DMA_BLKID_OUT_ENC);
	op->ldpc_enc.output.length += *out_length;
	*out_offset += *out_length;
	desc->data_ptrs[next_triplet - 1].last = 1;
	desc->data_ptrs[next_triplet - 1].dma_ext = 0;
	desc->d2mlen = next_triplet - desc->m2dlen;

	desc->op_addr = op;

	return 0;
}

static inline int
acc101_dma_desc_ld_fill(struct rte_bbdev_dec_op *op,
		struct acc101_dma_req_desc *desc,
		struct rte_mbuf **input, struct rte_mbuf *h_output,
		uint32_t *in_offset, uint32_t *h_out_offset,
		uint32_t *h_out_length, uint32_t *mbuf_total_left,
		uint32_t *seg_total_left,
		struct acc101_fcw_ld *fcw)
{
	struct rte_bbdev_op_ldpc_dec *dec = &op->ldpc_dec;
	int next_triplet = 1; /* FCW already done */
	uint32_t input_length;
	uint16_t output_length, crc24_overlap = 0;
	uint16_t sys_cols, K, h_p_size, h_np_size;
	bool h_comp = check_bit(dec->op_flags,
			RTE_BBDEV_LDPC_HARQ_6BIT_COMPRESSION);

	acc101_header_init(desc);

	if (check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP))
		crc24_overlap = 24;

	/* Compute some LDPC BG lengths */
	input_length = fcw->rm_e;
	if (check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_LLR_COMPRESSION))
		input_length = (input_length * 3 + 3) / 4;
	sys_cols = (dec->basegraph == 1) ? 22 : 10;
	K = sys_cols * dec->z_c;
	output_length = K - dec->n_filler - crc24_overlap;

	if (unlikely((*mbuf_total_left == 0) ||
			(*mbuf_total_left < input_length))) {
		rte_bbdev_log(ERR,
				"Mismatch between mbuf length and included CB sizes: mbuf len %u, cb len %u",
				*mbuf_total_left, input_length);
		return -1;
	}

	next_triplet = acc101_dma_fill_blk_type_in(desc, input,
			in_offset, input_length,
			seg_total_left, next_triplet,
			check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_DEC_SCATTER_GATHER));

	if (unlikely(next_triplet < 0)) {
		rte_bbdev_log(ERR,
				"Mismatch between data to process and mbuf data length in bbdev_op: %p",
				op);
		return -1;
	}

	if (check_bit(op->ldpc_dec.op_flags,
				RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE)) {
		h_p_size = fcw->hcin_size0 + fcw->hcin_size1;
		if (h_comp)
			h_p_size = (h_p_size * 3 + 3) / 4;
		desc->data_ptrs[next_triplet].address =
				dec->harq_combined_input.offset;
		desc->data_ptrs[next_triplet].blen = h_p_size;
		desc->data_ptrs[next_triplet].blkid = ACC101_DMA_BLKID_IN_HARQ;
		desc->data_ptrs[next_triplet].dma_ext = 1;
#ifndef ACC101_EXT_MEM
		acc101_dma_fill_blk_type_out(
				desc,
				op->ldpc_dec.harq_combined_input.data,
				op->ldpc_dec.harq_combined_input.offset,
				h_p_size,
				next_triplet,
				ACC101_DMA_BLKID_IN_HARQ);
#endif
		next_triplet++;
	}

	desc->data_ptrs[next_triplet - 1].last = 1;
	desc->m2dlen = next_triplet;
	*mbuf_total_left -= input_length;

	next_triplet = acc101_dma_fill_blk_type_out(desc, h_output,
			*h_out_offset, output_length >> 3, next_triplet,
			ACC101_DMA_BLKID_OUT_HARD);

	if (check_bit(op->ldpc_dec.op_flags,
				RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE)) {
		/* Pruned size of the HARQ */
		h_p_size = fcw->hcout_size0 + fcw->hcout_size1;
		/* Non-Pruned size of the HARQ */
		h_np_size = fcw->hcout_offset > 0 ?
				fcw->hcout_offset + fcw->hcout_size1 :
				h_p_size;
		if (h_comp) {
			h_np_size = (h_np_size * 3 + 3) / 4;
			h_p_size = (h_p_size * 3 + 3) / 4;
		}
		dec->harq_combined_output.length = h_np_size;
		desc->data_ptrs[next_triplet].address =
				dec->harq_combined_output.offset;
		desc->data_ptrs[next_triplet].blen = h_p_size;
		desc->data_ptrs[next_triplet].blkid = ACC101_DMA_BLKID_OUT_HARQ;
		desc->data_ptrs[next_triplet].dma_ext = 1;
#ifndef ACC101_EXT_MEM
		acc101_dma_fill_blk_type_out(
				desc,
				dec->harq_combined_output.data,
				dec->harq_combined_output.offset,
				h_p_size,
				next_triplet,
				ACC101_DMA_BLKID_OUT_HARQ);
#endif
		next_triplet++;
	}

	*h_out_length = output_length >> 3;
	dec->hard_output.length += *h_out_length;
	*h_out_offset += *h_out_length;
	desc->data_ptrs[next_triplet - 1].last = 1;
	desc->d2mlen = next_triplet - desc->m2dlen;

	desc->op_addr = op;

	return 0;
}

static inline void
acc101_dma_desc_ld_update(struct rte_bbdev_dec_op *op,
		struct acc101_dma_req_desc *desc,
		struct rte_mbuf *input, struct rte_mbuf *h_output,
		uint32_t *in_offset, uint32_t *h_out_offset,
		uint32_t *h_out_length,
		union acc101_harq_layout_data *harq_layout)
{
	int next_triplet = 1; /* FCW already done */
	desc->data_ptrs[next_triplet].address =
			rte_pktmbuf_iova_offset(input, *in_offset);
	next_triplet++;

	if (check_bit(op->ldpc_dec.op_flags,
				RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE)) {
		struct rte_bbdev_op_data hi = op->ldpc_dec.harq_combined_input;
		desc->data_ptrs[next_triplet].address = hi.offset;
#ifndef ACC101_EXT_MEM
		desc->data_ptrs[next_triplet].address =
				rte_pktmbuf_iova_offset(hi.data, hi.offset);
#endif
		next_triplet++;
	}

	desc->data_ptrs[next_triplet].address =
			rte_pktmbuf_iova_offset(h_output, *h_out_offset);
	*h_out_length = desc->data_ptrs[next_triplet].blen;
	next_triplet++;

	if (check_bit(op->ldpc_dec.op_flags,
				RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE)) {
		desc->data_ptrs[next_triplet].address =
				op->ldpc_dec.harq_combined_output.offset;
		/* Adjust based on previous operation */
		struct rte_bbdev_dec_op *prev_op = desc->op_addr;
		op->ldpc_dec.harq_combined_output.length =
				prev_op->ldpc_dec.harq_combined_output.length;
		uint32_t harq_idx = hq_index(
				op->ldpc_dec.harq_combined_output.offset);
		uint32_t prev_harq_idx = hq_index(
				prev_op->ldpc_dec.harq_combined_output.offset);
		harq_layout[harq_idx].val = harq_layout[prev_harq_idx].val;
#ifndef ACC101_EXT_MEM
		struct rte_bbdev_op_data ho =
				op->ldpc_dec.harq_combined_output;
		desc->data_ptrs[next_triplet].address =
				rte_pktmbuf_iova_offset(ho.data, ho.offset);
#endif
		next_triplet++;
	}

	op->ldpc_dec.hard_output.length += *h_out_length;
	desc->op_addr = op;
}


/* Enqueue a number of operations to HW and update software rings */
static inline void
acc101_dma_enqueue(struct acc101_queue *q, uint16_t n,
		struct rte_bbdev_stats *queue_stats)
{
	union acc101_enqueue_reg_fmt enq_req;
#ifdef RTE_BBDEV_OFFLOAD_COST
	uint64_t start_time = 0;
	queue_stats->acc_offload_cycles = 0;
#else
	RTE_SET_USED(queue_stats);
#endif

	enq_req.val = 0;
	/* Setting offset, 100b for 256 DMA Desc */
	enq_req.addr_offset = ACC101_DESC_OFFSET;

	/* Split ops into batches */
	do {
		union acc101_dma_desc *desc;
		uint16_t enq_batch_size;
		uint64_t offset;
		rte_iova_t req_elem_addr;

		enq_batch_size = RTE_MIN(n, MAX_ENQ_BATCH_SIZE);

		/* Set flag on last descriptor in a batch */
		desc = q->ring_addr + ((q->sw_ring_head + enq_batch_size - 1) &
				q->sw_ring_wrap_mask);
		desc->req.last_desc_in_batch = 1;

		/* Calculate the 1st descriptor's address */
		offset = ((q->sw_ring_head & q->sw_ring_wrap_mask) *
				sizeof(union acc101_dma_desc));
		req_elem_addr = q->ring_addr_iova + offset;

		/* Fill enqueue struct */
		enq_req.num_elem = enq_batch_size;
		/* low 6 bits are not needed */
		enq_req.req_elem_addr = (uint32_t)(req_elem_addr >> 6);

#ifdef RTE_LIBRTE_BBDEV_DEBUG
		rte_memdump(stderr, "Req sdone", desc, sizeof(*desc));
#endif
		rte_bbdev_log_debug(
				"Enqueue %u reqs (phys %#"PRIx64") to reg %p",
				enq_batch_size,
				req_elem_addr,
				(void *)q->mmio_reg_enqueue);

		rte_wmb();

#ifdef RTE_BBDEV_OFFLOAD_COST
		/* Start time measurement for enqueue function offload. */
		start_time = rte_rdtsc_precise();
#endif
		rte_bbdev_log(DEBUG, "Debug : MMIO Enqueue");
		mmio_write(q->mmio_reg_enqueue, enq_req.val);

#ifdef RTE_BBDEV_OFFLOAD_COST
		queue_stats->acc_offload_cycles +=
				rte_rdtsc_precise() - start_time;
#endif

		q->aq_enqueued++;
		q->sw_ring_head += enq_batch_size;
		n -= enq_batch_size;

	} while (n);


}

/* Enqueue one encode operations for ACC101 device in CB mode
 * multiplexed on the same descriptor
 */
static inline int
enqueue_ldpc_enc_n_op_cb(struct acc101_queue *q, struct rte_bbdev_enc_op **ops,
		uint16_t total_enqueued_descs, int16_t num)
{
	union acc101_dma_desc *desc = NULL;
	uint32_t out_length;
	struct rte_mbuf *output_head, *output;
	int i, next_triplet;
	uint16_t  in_length_in_bytes;
	struct rte_bbdev_op_ldpc_enc *enc = &ops[0]->ldpc_enc;

	uint16_t desc_idx = ((q->sw_ring_head + total_enqueued_descs)
			& q->sw_ring_wrap_mask);
	desc = q->ring_addr + desc_idx;
	acc101_fcw_le_fill(ops[0], &desc->req.fcw_le, num, 0);

	/** This could be done at polling */
	acc101_header_init(&desc->req);
	desc->req.numCBs = num;

	in_length_in_bytes = ops[0]->ldpc_enc.input.data->data_len;
	out_length = (enc->cb_params.e + 7) >> 3;
	desc->req.m2dlen = 1 + num;
	desc->req.d2mlen = num;
	next_triplet = 1;

	for (i = 0; i < num; i++) {
		desc->req.data_ptrs[next_triplet].address =
			rte_pktmbuf_iova_offset(ops[i]->ldpc_enc.input.data, 0);
		desc->req.data_ptrs[next_triplet].blen = in_length_in_bytes;
		next_triplet++;
		desc->req.data_ptrs[next_triplet].address =
				rte_pktmbuf_iova_offset(
				ops[i]->ldpc_enc.output.data, 0);
		desc->req.data_ptrs[next_triplet].blen = out_length;
		next_triplet++;
		ops[i]->ldpc_enc.output.length = out_length;
		output_head = output = ops[i]->ldpc_enc.output.data;
		mbuf_append(output_head, output, out_length);
		output->data_len = out_length;
	}

	desc->req.op_addr = ops[0];
	/* Keep track of pointers even when multiplexed in single descriptor */
	struct acc101_ptrs *context_ptrs = q->companion_ring_addr + desc_idx;
	for (i = 0; i < num; i++)
		context_ptrs->ptr[i].op_addr = ops[i];

#ifdef RTE_LIBRTE_BBDEV_DEBUG
	rte_memdump(stderr, "FCW", &desc->req.fcw_le,
			sizeof(desc->req.fcw_le) - 8);
	rte_memdump(stderr, "Req Desc.", desc, sizeof(*desc));
#endif

	/* One CB (one op) was successfully prepared to enqueue */
	return num;
}

/* Enqueue one encode operations for ACC101 device for a partial TB
 * all codes blocks have same configuration multiplexed on the same descriptor
 */
static inline void
enqueue_ldpc_enc_part_tb(struct acc101_queue *q, struct rte_bbdev_enc_op *op,
		uint16_t total_enqueued_descs, int16_t num_cbs, uint32_t e,
		uint16_t in_len_B, uint32_t out_len_B, uint32_t *in_offset,
		uint32_t *out_offset)
{

	union acc101_dma_desc *desc = NULL;
	struct rte_mbuf *output_head, *output;
	int i, next_triplet;
	struct rte_bbdev_op_ldpc_enc *enc = &op->ldpc_enc;


	uint16_t desc_idx = ((q->sw_ring_head + total_enqueued_descs)
			& q->sw_ring_wrap_mask);
	desc = q->ring_addr + desc_idx;
	acc101_fcw_le_fill(op, &desc->req.fcw_le, num_cbs, e);

	/** This could be done at polling */
	acc101_header_init(&desc->req);
	desc->req.numCBs = num_cbs;

	desc->req.m2dlen = 1 + num_cbs;
	desc->req.d2mlen = num_cbs;
	next_triplet = 1;

	for (i = 0; i < num_cbs; i++) {
		desc->req.data_ptrs[next_triplet].address =
			rte_pktmbuf_iova_offset(enc->input.data,
					*in_offset);
		*in_offset += in_len_B;
		desc->req.data_ptrs[next_triplet].blen = in_len_B;
		next_triplet++;
		desc->req.data_ptrs[next_triplet].address =
				rte_pktmbuf_iova_offset(
						enc->output.data, *out_offset);
		*out_offset += out_len_B;
		desc->req.data_ptrs[next_triplet].blen = out_len_B;
		next_triplet++;
		enc->output.length += out_len_B;
		output_head = output = enc->output.data;
		mbuf_append(output_head, output, out_len_B);
	}

#ifdef RTE_LIBRTE_BBDEV_DEBUG
	rte_memdump(stderr, "FCW", &desc->req.fcw_le,
			sizeof(desc->req.fcw_le) - 8);
	rte_memdump(stderr, "Req Desc.", desc, sizeof(*desc));
#endif

}

/* Enqueue one encode operations for ACC101 device in CB mode */
static inline int
enqueue_ldpc_enc_one_op_cb(struct acc101_queue *q, struct rte_bbdev_enc_op *op,
		uint16_t total_enqueued_cbs)
{
	union acc101_dma_desc *desc = NULL;
	int ret;
	uint32_t in_offset, out_offset, out_length, mbuf_total_left,
		seg_total_left;
	struct rte_mbuf *input, *output_head, *output;

	uint16_t desc_idx = ((q->sw_ring_head + total_enqueued_cbs)
			& q->sw_ring_wrap_mask);
	desc = q->ring_addr + desc_idx;
	acc101_fcw_le_fill(op, &desc->req.fcw_le, 1, 0);

	input = op->ldpc_enc.input.data;
	output_head = output = op->ldpc_enc.output.data;
	in_offset = op->ldpc_enc.input.offset;
	out_offset = op->ldpc_enc.output.offset;
	out_length = 0;
	mbuf_total_left = op->ldpc_enc.input.length;
	seg_total_left = rte_pktmbuf_data_len(op->ldpc_enc.input.data)
			- in_offset;

	ret = acc101_dma_desc_le_fill(op, &desc->req, &input, output,
			&in_offset, &out_offset, &out_length, &mbuf_total_left,
			&seg_total_left);

	if (unlikely(ret < 0))
		return ret;

	mbuf_append(output_head, output, out_length);

#ifdef RTE_LIBRTE_BBDEV_DEBUG
	rte_memdump(stderr, "FCW", &desc->req.fcw_le,
			sizeof(desc->req.fcw_le) - 8);
	rte_memdump(stderr, "Req Desc.", desc, sizeof(*desc));

	if (check_mbuf_total_left(mbuf_total_left) != 0)
		return -EINVAL;
#endif
	/* One CB (one op) was successfully prepared to enqueue */
	return 1;
}

/* Enqueue one encode operations for ACC101 device in TB mode.
 * returns the number of descs used
 */
static inline int
enqueue_ldpc_enc_one_op_tb(struct acc101_queue *q, struct rte_bbdev_enc_op *op,
		uint16_t enq_descs, uint8_t cbs_in_tb)
{
	uint8_t num_a, num_b;
	uint16_t desc_idx;
	uint8_t r = op->ldpc_enc.tb_params.r;
	uint8_t cab =  op->ldpc_enc.tb_params.cab;
	union acc101_dma_desc *desc;
	uint16_t init_enq_descs = enq_descs;
	uint16_t input_len_B = ((op->ldpc_enc.basegraph == 1 ? 22 : 10) *
			op->ldpc_enc.z_c - op->ldpc_enc.n_filler) >> 3;
	if (check_bit(op->ldpc_enc.op_flags, RTE_BBDEV_LDPC_CRC_24B_ATTACH))
		input_len_B -= 3;

	if (r < cab) {
		num_a = cab - r;
		num_b = cbs_in_tb - cab;
	} else {
		num_a = 0;
		num_b = cbs_in_tb - r;
	}
	uint32_t in_offset = 0, out_offset = 0;

	while (num_a > 0) {
		uint32_t e = op->ldpc_enc.tb_params.ea;
		uint32_t out_len_B = (e + 7) >> 3;
		uint8_t enq = RTE_MIN(num_a, ACC101_MUX_5GDL_DESC);
		num_a -= enq;
		enqueue_ldpc_enc_part_tb(q, op, enq_descs, enq, e, input_len_B,
				out_len_B, &in_offset, &out_offset);
		enq_descs++;
	}
	while (num_b > 0) {
		uint32_t e = op->ldpc_enc.tb_params.eb;
		uint32_t out_len_B = (e + 7) >> 3;
		uint8_t enq = RTE_MIN(num_b, ACC101_MUX_5GDL_DESC);
		num_b -= enq;
		enqueue_ldpc_enc_part_tb(q, op, enq_descs, enq, e, input_len_B,
				out_len_B, &in_offset, &out_offset);
		enq_descs++;
	}

	uint16_t return_descs = enq_descs - init_enq_descs;
	/* Keep total number of CBs in first TB */
	desc_idx = ((q->sw_ring_head + init_enq_descs)
			& q->sw_ring_wrap_mask);
	desc = q->ring_addr + desc_idx;
	desc->req.cbs_in_tb = return_descs; /** Actual number of descriptors */
	desc->req.op_addr = op;

	/* Set SDone on last CB descriptor for TB mode. */
	desc_idx = ((q->sw_ring_head + enq_descs - 1)
			& q->sw_ring_wrap_mask);
	desc = q->ring_addr + desc_idx;
	desc->req.sdone_enable = 1;
	desc->req.irq_enable = q->irq_enable;
	desc->req.op_addr = op;
	return return_descs;
}

static inline int
harq_loopback(struct acc101_queue *q, struct rte_bbdev_dec_op *op,
		uint16_t total_enqueued_cbs) {
	struct acc101_fcw_ld *fcw;
	union acc101_dma_desc *desc;
	int next_triplet = 1;
	struct rte_mbuf *hq_output_head, *hq_output;
	uint16_t harq_dma_length_in, harq_dma_length_out;
	uint16_t harq_in_length = op->ldpc_dec.harq_combined_input.length;
	if (harq_in_length == 0) {
		rte_bbdev_log(ERR, "Loopback of invalid null size\n");
		return -EINVAL;
	}

	int h_comp = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_HARQ_6BIT_COMPRESSION
			) ? 1 : 0;
	if (h_comp == 1) {
		harq_in_length = harq_in_length * 8 / 6;
		harq_in_length = RTE_ALIGN(harq_in_length, 64);
		harq_dma_length_in = harq_in_length * 6 / 8;
	} else {
		harq_in_length = RTE_ALIGN(harq_in_length, 64);
		harq_dma_length_in = harq_in_length;
	}
	harq_dma_length_out = harq_dma_length_in;

	bool ddr_mem_in = check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_INTERNAL_HARQ_MEMORY_IN_ENABLE);
	union acc101_harq_layout_data *harq_layout = q->d->harq_layout;
	uint32_t harq_index = hq_index(ddr_mem_in ?
			op->ldpc_dec.harq_combined_input.offset :
			op->ldpc_dec.harq_combined_output.offset);

	uint16_t desc_idx = ((q->sw_ring_head + total_enqueued_cbs)
			& q->sw_ring_wrap_mask);
	desc = q->ring_addr + desc_idx;
	fcw = &desc->req.fcw_ld;
	/* Set the FCW from loopback into DDR */
	memset(fcw, 0, sizeof(struct acc101_fcw_ld));
	fcw->FCWversion = ACC101_FCW_VER;
	fcw->qm = 2;
	fcw->Zc = 384;
	if (harq_in_length < 16 * ACC101_N_ZC_1)
		fcw->Zc = 16;
	fcw->ncb = fcw->Zc * ACC101_N_ZC_1;
	fcw->rm_e = 2;
	fcw->hcin_en = 1;
	fcw->hcout_en = 1;

	rte_bbdev_log(DEBUG, "Loopback IN %d Index %d offset %d length %d %d\n",
			ddr_mem_in, harq_index,
			harq_layout[harq_index].offset, harq_in_length,
			harq_dma_length_in);

	if (ddr_mem_in && (harq_layout[harq_index].offset > 0)) {
		fcw->hcin_size0 = harq_layout[harq_index].size0;
		fcw->hcin_offset = harq_layout[harq_index].offset;
		fcw->hcin_size1 = harq_in_length - fcw->hcin_offset;
		harq_dma_length_in = (fcw->hcin_size0 + fcw->hcin_size1);
		if (h_comp == 1)
			harq_dma_length_in = harq_dma_length_in * 6 / 8;
	} else {
		fcw->hcin_size0 = harq_in_length;
	}
	harq_layout[harq_index].val = 0;
	rte_bbdev_log(DEBUG, "Loopback FCW Config %d %d %d\n",
			fcw->hcin_size0, fcw->hcin_offset, fcw->hcin_size1);
	fcw->hcout_size0 = harq_in_length;
	fcw->hcin_decomp_mode = h_comp;
	fcw->hcout_comp_mode = h_comp;
	fcw->gain_i = 1;
	fcw->gain_h = 1;

	/* Set the prefix of descriptor. This could be done at polling */
	acc101_header_init(&desc->req);

	/* Null LLR input for Decoder */
	desc->req.data_ptrs[next_triplet].address =
			q->lb_in_addr_iova;
	desc->req.data_ptrs[next_triplet].blen = 2;
	desc->req.data_ptrs[next_triplet].blkid = ACC101_DMA_BLKID_IN;
	desc->req.data_ptrs[next_triplet].last = 0;
	desc->req.data_ptrs[next_triplet].dma_ext = 0;
	next_triplet++;

	/* HARQ Combine input from either Memory interface */
	if (!ddr_mem_in) {
		next_triplet = acc101_dma_fill_blk_type_out(&desc->req,
				op->ldpc_dec.harq_combined_input.data,
				op->ldpc_dec.harq_combined_input.offset,
				harq_dma_length_in,
				next_triplet,
				ACC101_DMA_BLKID_IN_HARQ);
	} else {
		desc->req.data_ptrs[next_triplet].address =
				op->ldpc_dec.harq_combined_input.offset;
		desc->req.data_ptrs[next_triplet].blen =
				harq_dma_length_in;
		desc->req.data_ptrs[next_triplet].blkid =
				ACC101_DMA_BLKID_IN_HARQ;
		desc->req.data_ptrs[next_triplet].dma_ext = 1;
		next_triplet++;
	}
	desc->req.data_ptrs[next_triplet - 1].last = 1;
	desc->req.m2dlen = next_triplet;

	/* Dropped decoder hard output */
	desc->req.data_ptrs[next_triplet].address =
			q->lb_out_addr_iova;
	desc->req.data_ptrs[next_triplet].blen = ACC101_BYTES_IN_WORD;
	desc->req.data_ptrs[next_triplet].blkid = ACC101_DMA_BLKID_OUT_HARD;
	desc->req.data_ptrs[next_triplet].last = 0;
	desc->req.data_ptrs[next_triplet].dma_ext = 0;
	next_triplet++;

	/* HARQ Combine output to either Memory interface */
	if (check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_INTERNAL_HARQ_MEMORY_OUT_ENABLE
			)) {
		desc->req.data_ptrs[next_triplet].address =
				op->ldpc_dec.harq_combined_output.offset;
		desc->req.data_ptrs[next_triplet].blen =
				harq_dma_length_out;
		desc->req.data_ptrs[next_triplet].blkid =
				ACC101_DMA_BLKID_OUT_HARQ;
		desc->req.data_ptrs[next_triplet].dma_ext = 1;
		next_triplet++;
	} else {
		hq_output_head = op->ldpc_dec.harq_combined_output.data;
		hq_output = op->ldpc_dec.harq_combined_output.data;
		next_triplet = acc101_dma_fill_blk_type_out(
				&desc->req,
				op->ldpc_dec.harq_combined_output.data,
				op->ldpc_dec.harq_combined_output.offset,
				harq_dma_length_out,
				next_triplet,
				ACC101_DMA_BLKID_OUT_HARQ);
		/* HARQ output */
		mbuf_append(hq_output_head, hq_output, harq_dma_length_out);
		op->ldpc_dec.harq_combined_output.length =
				harq_dma_length_out;
	}
	desc->req.data_ptrs[next_triplet - 1].last = 1;
	desc->req.d2mlen = next_triplet - desc->req.m2dlen;
	desc->req.op_addr = op;

	/* One CB (one op) was successfully prepared to enqueue */
	return 1;
}

/** Enqueue one decode operations for ACC101 device in CB mode */
static inline int
enqueue_ldpc_dec_one_op_cb(struct acc101_queue *q, struct rte_bbdev_dec_op *op,
		uint16_t total_enqueued_cbs, bool same_op,
		struct rte_bbdev_queue_data *q_data)
{
	RTE_SET_USED(q_data);
	int ret;
	if (unlikely(check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_INTERNAL_HARQ_MEMORY_LOOPBACK))) {
		ret = harq_loopback(q, op, total_enqueued_cbs);
		return ret;
	}

	union acc101_dma_desc *desc;
	uint16_t desc_idx = ((q->sw_ring_head + total_enqueued_cbs)
			& q->sw_ring_wrap_mask);
	desc = q->ring_addr + desc_idx;
	struct rte_mbuf *input, *h_output_head, *h_output;
	uint32_t in_offset, h_out_offset, mbuf_total_left, h_out_length = 0;
	input = op->ldpc_dec.input.data;
	h_output_head = h_output = op->ldpc_dec.hard_output.data;
	in_offset = op->ldpc_dec.input.offset;
	h_out_offset = op->ldpc_dec.hard_output.offset;
	mbuf_total_left = op->ldpc_dec.input.length;
#ifdef RTE_LIBRTE_BBDEV_DEBUG
	if (unlikely(input == NULL)) {
		rte_bbdev_log(ERR, "Invalid mbuf pointer");
		return -EFAULT;
	}
#endif
	union acc101_harq_layout_data *harq_layout = q->d->harq_layout;

	if (same_op) {
		union acc101_dma_desc *prev_desc;
		desc_idx = ((q->sw_ring_head + total_enqueued_cbs - 1)
				& q->sw_ring_wrap_mask);
		prev_desc = q->ring_addr + desc_idx;
		uint8_t *prev_ptr = (uint8_t *) prev_desc;
		uint8_t *new_ptr = (uint8_t *) desc;
		/* Copy first 4 words and BDESCs */
		rte_memcpy(new_ptr, prev_ptr, ACC101_5GUL_SIZE_0);
		rte_memcpy(new_ptr + ACC101_5GUL_OFFSET_0,
				prev_ptr + ACC101_5GUL_OFFSET_0,
				ACC101_5GUL_SIZE_1);
		desc->req.op_addr = prev_desc->req.op_addr;
		/* Copy FCW */
		rte_memcpy(new_ptr + ACC101_DESC_FCW_OFFSET,
				prev_ptr + ACC101_DESC_FCW_OFFSET,
				ACC101_FCW_LD_BLEN);
		acc101_dma_desc_ld_update(op, &desc->req, input, h_output,
				&in_offset, &h_out_offset,
				&h_out_length, harq_layout);
	} else {
		struct acc101_fcw_ld *fcw;
		uint32_t seg_total_left;
		fcw = &desc->req.fcw_ld;
		acc101_fcw_ld_fill(op, fcw, harq_layout);

		/* Special handling when using mbuf or not */
		if (check_bit(op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_DEC_SCATTER_GATHER))
			seg_total_left = rte_pktmbuf_data_len(input)
					- in_offset;
		else
			seg_total_left = fcw->rm_e;

		ret = acc101_dma_desc_ld_fill(op, &desc->req, &input, h_output,
				&in_offset, &h_out_offset,
				&h_out_length, &mbuf_total_left,
				&seg_total_left, fcw);
		if (unlikely(ret < 0))
			return ret;
	}

	/* Hard output */
	mbuf_append(h_output_head, h_output, h_out_length);
#ifndef ACC101_EXT_MEM
	if (op->ldpc_dec.harq_combined_output.length > 0) {
		/* Push the HARQ output into host memory */
		struct rte_mbuf *hq_output_head, *hq_output;
		hq_output_head = op->ldpc_dec.harq_combined_output.data;
		hq_output = op->ldpc_dec.harq_combined_output.data;
		mbuf_append(hq_output_head, hq_output,
				op->ldpc_dec.harq_combined_output.length);
	}
#endif

#ifdef RTE_LIBRTE_BBDEV_DEBUG
	rte_memdump(stderr, "FCW", &desc->req.fcw_ld,
			sizeof(desc->req.fcw_ld));
	rte_memdump(stderr, "Req Desc.", desc, sizeof(*desc));
#endif

	/* One CB (one op) was successfully prepared to enqueue */
	return 1;
}


/* Enqueue one decode operations for ACC101 device in TB mode */
static inline int
enqueue_ldpc_dec_one_op_tb(struct acc101_queue *q, struct rte_bbdev_dec_op *op,
		uint16_t total_enqueued_cbs, uint8_t cbs_in_tb)
{
	union acc101_dma_desc *desc = NULL;
	union acc101_dma_desc *desc_first = NULL;
	int ret;
	uint8_t r, c;
	uint32_t in_offset, h_out_offset,
		h_out_length, mbuf_total_left, seg_total_left;
	struct rte_mbuf *input, *h_output_head, *h_output;
	uint16_t current_enqueued_cbs = 0;

	uint16_t desc_idx = ((q->sw_ring_head + total_enqueued_cbs)
			& q->sw_ring_wrap_mask);
	desc = q->ring_addr + desc_idx;
	desc_first = desc;
	uint64_t fcw_offset = (desc_idx << 8) + ACC101_DESC_FCW_OFFSET;
	union acc101_harq_layout_data *harq_layout = q->d->harq_layout;
	acc101_fcw_ld_fill(op, &desc->req.fcw_ld, harq_layout);

	input = op->ldpc_dec.input.data;
	h_output_head = h_output = op->ldpc_dec.hard_output.data;
	in_offset = op->ldpc_dec.input.offset;
	h_out_offset = op->ldpc_dec.hard_output.offset;
	h_out_length = 0;
	mbuf_total_left = op->ldpc_dec.input.length;
	c = op->ldpc_dec.tb_params.c;
	r = op->ldpc_dec.tb_params.r;

	while (mbuf_total_left > 0 && r < c) {
		if (check_bit(op->ldpc_dec.op_flags,
				RTE_BBDEV_LDPC_DEC_SCATTER_GATHER))
			seg_total_left = rte_pktmbuf_data_len(input)
					- in_offset;
		else
			seg_total_left = op->ldpc_dec.input.length;
		/* Set up DMA descriptor */
		desc = q->ring_addr + ((q->sw_ring_head + total_enqueued_cbs)
				& q->sw_ring_wrap_mask);
		desc->req.data_ptrs[0].address = q->ring_addr_iova + fcw_offset;
		desc->req.data_ptrs[0].blen = ACC101_FCW_LD_BLEN;
		rte_memcpy(&desc->req.fcw_ld, &desc_first->req.fcw_ld,
				ACC101_FCW_LD_BLEN);
		ret = acc101_dma_desc_ld_fill(op, &desc->req, &input,
				h_output, &in_offset, &h_out_offset,
				&h_out_length,
				&mbuf_total_left, &seg_total_left,
				&desc->req.fcw_ld);

		if (unlikely(ret < 0))
			return ret;

		/* Hard output */
		mbuf_append(h_output_head, h_output, h_out_length);

		/* Set total number of CBs in TB */
		desc->req.cbs_in_tb = cbs_in_tb;
#ifdef RTE_LIBRTE_BBDEV_DEBUG
		rte_memdump(stderr, "FCW", &desc->req.fcw_td,
				sizeof(desc->req.fcw_td) - 8);
		rte_memdump(stderr, "Req Desc.", desc, sizeof(*desc));
#endif
		if (check_bit(op->ldpc_dec.op_flags,
				RTE_BBDEV_LDPC_DEC_SCATTER_GATHER)
				&& (seg_total_left == 0)) {
			/* Go to the next mbuf */
			input = input->next;
			in_offset = 0;
			h_output = h_output->next;
			h_out_offset = 0;
		}
		total_enqueued_cbs++;
		current_enqueued_cbs++;
		r++;
	}
#ifdef RTE_LIBRTE_BBDEV_DEBUG
	if (check_mbuf_total_left(mbuf_total_left) != 0)
		return -EINVAL;
#endif
	/* Set SDone on last CB descriptor for TB mode */
	desc->req.sdone_enable = 1;
	desc->req.irq_enable = q->irq_enable;

	return current_enqueued_cbs;
}

/* Calculates number of CBs in processed encoder TB based on 'r' and input
 * length.
 */
static inline uint8_t
get_num_cbs_in_tb_ldpc_enc(struct rte_bbdev_op_ldpc_enc *ldpc_enc)
{
	uint8_t c, r, crc24_bits = 0;
	uint16_t k = (ldpc_enc->basegraph == 1 ? 22 : 10) * ldpc_enc->z_c
		- ldpc_enc->n_filler;
	uint8_t cbs_in_tb = 0;
	int32_t length;

	length = ldpc_enc->input.length;
	r = ldpc_enc->tb_params.r;
	c = ldpc_enc->tb_params.c;
	crc24_bits = 0;
	if (check_bit(ldpc_enc->op_flags, RTE_BBDEV_LDPC_CRC_24B_ATTACH))
		crc24_bits = 24;
	while (length > 0 && r < c) {
		length -= (k - crc24_bits) >> 3;
		r++;
		cbs_in_tb++;
	}
	return cbs_in_tb;
}

/* Calculates number of CBs in processed decoder TB based on 'r' and input
 * length.
 */
static inline uint16_t
get_num_cbs_in_tb_ldpc_dec(struct rte_bbdev_op_ldpc_dec *ldpc_dec)
{
	uint16_t r, cbs_in_tb = 0;
	int32_t length = ldpc_dec->input.length;
	r = ldpc_dec->tb_params.r;
	while (length > 0 && r < ldpc_dec->tb_params.c) {
		length -=  (r < ldpc_dec->tb_params.cab) ?
				ldpc_dec->tb_params.ea :
				ldpc_dec->tb_params.eb;
		r++;
		cbs_in_tb++;
	}
	return cbs_in_tb;
}

/* Number of available descriptor in ring to enqueue */
static uint32_t
acc101_ring_avail_enq(struct acc101_queue *q)
{
	return (q->sw_ring_depth - 1 + q->sw_ring_tail - q->sw_ring_head) % q->sw_ring_depth;
}

/* Number of available descriptor in ring to dequeue */
static uint32_t
acc101_ring_avail_deq(struct acc101_queue *q)
{
	return (q->sw_ring_depth + q->sw_ring_head - q->sw_ring_tail) % q->sw_ring_depth;
}

/* Check we can mux encode operations with common FCW */
static inline int16_t
check_mux(struct rte_bbdev_enc_op **ops, uint16_t num) {
	uint16_t i;
	if (num <= 1)
		return 1;
	for (i = 1; i < num; ++i) {
		/* Only mux compatible code blocks */
		if (memcmp((uint8_t *)(&ops[i]->ldpc_enc) + ACC101_ENC_OFFSET,
				(uint8_t *)(&ops[0]->ldpc_enc) +
				ACC101_ENC_OFFSET,
				ACC101_CMP_ENC_SIZE) != 0)
			return i;
	}
	/* Avoid multiplexing small inbound size frames */
	int Kp = (ops[0]->ldpc_enc.basegraph == 1 ? 22 : 10) *
			ops[0]->ldpc_enc.z_c - ops[0]->ldpc_enc.n_filler;
	if (Kp  <= ACC101_LIMIT_DL_MUX_BITS)
		return 1;
	return num;
}

/** Enqueue encode operations for ACC101 device in CB mode. */
static inline uint16_t
acc101_enqueue_ldpc_enc_cb(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_enc_op **ops, uint16_t num)
{
	struct acc101_queue *q = q_data->queue_private;
	int32_t avail = acc101_ring_avail_enq(q);
	uint16_t i = 0;
	union acc101_dma_desc *desc;
	int ret, desc_idx = 0;
	int16_t enq, left = num;

	while (left > 0) {
		if (unlikely(avail < 1))
			break;
		avail--;
		enq = RTE_MIN(left, ACC101_MUX_5GDL_DESC);
		enq = check_mux(&ops[i], enq);
		if (enq > 1) {
			ret = enqueue_ldpc_enc_n_op_cb(q, &ops[i],
					desc_idx, enq);
			if (ret < 0)
				break;
			i += enq;
		} else {
			ret = enqueue_ldpc_enc_one_op_cb(q, ops[i], desc_idx);
			if (ret < 0)
				break;
			i++;
		}
		desc_idx++;
		left = num - i;
	}

	if (unlikely(i == 0))
		return 0; /* Nothing to enqueue */

	/* Set SDone in last CB in enqueued ops for CB mode*/
	desc = q->ring_addr + ((q->sw_ring_head + desc_idx - 1)
			& q->sw_ring_wrap_mask);
	desc->req.sdone_enable = 1;
	desc->req.irq_enable = q->irq_enable;

	acc101_dma_enqueue(q, desc_idx, &q_data->queue_stats);

	/* Update stats */
	q_data->queue_stats.enqueued_count += i;
	q_data->queue_stats.enqueue_err_count += num - i;

	return i;
}

/* Enqueue LDPC encode operations for ACC101 device in TB mode. */
static uint16_t
acc101_enqueue_ldpc_enc_tb(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_enc_op **ops, uint16_t num)
{
	struct acc101_queue *q = q_data->queue_private;
	int32_t avail = acc101_ring_avail_enq(q);
	uint16_t i, enqueued_descs = 0;
	uint8_t cbs_in_tb;
	int descs_used;

	for (i = 0; i < num; ++i) {
		cbs_in_tb = get_num_cbs_in_tb_ldpc_enc(&ops[i]->ldpc_enc);
		/* Check if there are available space for further processing */
		if (unlikely(avail - cbs_in_tb < 0))
			break;


		descs_used = enqueue_ldpc_enc_one_op_tb(q, ops[i],
				enqueued_descs, cbs_in_tb);
		if (descs_used < 0)
			break;
		enqueued_descs += descs_used;
		avail -= descs_used;
	}
	if (unlikely(enqueued_descs == 0))
		return 0; /* Nothing to enqueue */

	acc101_dma_enqueue(q, enqueued_descs, &q_data->queue_stats);

	/* Update stats */
	q_data->queue_stats.enqueued_count += i;
	q_data->queue_stats.enqueue_err_count += num - i;

	return i;
}

/* Check room in AQ for the enqueues batches into Qmgr */
static int32_t
acc101_aq_avail(struct rte_bbdev_queue_data *q_data, uint16_t num_ops)
{
	struct acc101_queue *q = q_data->queue_private;
	int32_t aq_avail = q->aq_depth -
			((q->aq_enqueued - q->aq_dequeued +
			ACC101_MAX_QUEUE_DEPTH) % ACC101_MAX_QUEUE_DEPTH)
			- (num_ops >> 7);
	return aq_avail;
}

/* Enqueue encode operations for ACC101 device. */
static uint16_t
acc101_enqueue_ldpc_enc(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_enc_op **ops, uint16_t num)
{
	uint16_t ret;
	int32_t aq_avail = acc101_aq_avail(q_data, num);
	if (unlikely((aq_avail <= 0) || (num == 0)))
		return 0;
	if (ops[0]->ldpc_enc.code_block_mode == RTE_BBDEV_TRANSPORT_BLOCK)
		ret = acc101_enqueue_ldpc_enc_tb(q_data, ops, num);
	else
		ret = acc101_enqueue_ldpc_enc_cb(q_data, ops, num);
	return ret;
}

/* Enqueue decode operations for ACC101 device in TB mode */
static uint16_t
acc101_enqueue_ldpc_dec_tb(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_dec_op **ops, uint16_t num)
{
	struct acc101_queue *q = q_data->queue_private;
	int32_t avail = acc101_ring_avail_enq(q);
	uint16_t i, enqueued_cbs = 0;
	uint8_t cbs_in_tb;
	int ret;

	for (i = 0; i < num; ++i) {
		cbs_in_tb = get_num_cbs_in_tb_ldpc_dec(&ops[i]->ldpc_dec);
		/* Check if there are available space for further processing */
		if (unlikely(avail - cbs_in_tb < 0))
			break;
		avail -= cbs_in_tb;

		ret = enqueue_ldpc_dec_one_op_tb(q, ops[i],
				enqueued_cbs, cbs_in_tb);
		if (ret < 0)
			break;
		enqueued_cbs += ret;
	}
	if (unlikely(enqueued_cbs == 0))
		return 0; /* Nothing to enqueue */

	acc101_dma_enqueue(q, enqueued_cbs, &q_data->queue_stats);

	/* Update stats */
	q_data->queue_stats.enqueued_count += i;
	q_data->queue_stats.enqueue_err_count += num - i;
	return i;
}

/* Enqueue decode operations for ACC101 device in CB mode */
static uint16_t
acc101_enqueue_ldpc_dec_cb(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_dec_op **ops, uint16_t num)
{
	struct acc101_queue *q = q_data->queue_private;
	int32_t avail = acc101_ring_avail_enq(q);
	uint16_t i;
	union acc101_dma_desc *desc;
	int ret;
	bool same_op = false;
	for (i = 0; i < num; ++i) {
		/* Check if there are available space for further processing */
		if (unlikely(avail < 1))
			break;
		avail -= 1;
		rte_bbdev_log(INFO, "Op %d %d %d %d %d %d %d %d %d %d %d %d\n",
			i, ops[i]->ldpc_dec.op_flags, ops[i]->ldpc_dec.rv_index,
			ops[i]->ldpc_dec.iter_max, ops[i]->ldpc_dec.iter_count,
			ops[i]->ldpc_dec.basegraph, ops[i]->ldpc_dec.z_c,
			ops[i]->ldpc_dec.n_cb, ops[i]->ldpc_dec.q_m,
			ops[i]->ldpc_dec.n_filler, ops[i]->ldpc_dec.cb_params.e,
			same_op);
		ret = enqueue_ldpc_dec_one_op_cb(q, ops[i], i, same_op, q_data);
		if (ret < 0)
			break;
	}

	if (unlikely(i == 0))
		return 0; /* Nothing to enqueue */

	/* Set SDone in last CB in enqueued ops for CB mode*/
	desc = q->ring_addr + ((q->sw_ring_head + i - 1)
			& q->sw_ring_wrap_mask);

	desc->req.sdone_enable = 1;
	desc->req.irq_enable = q->irq_enable;

	acc101_dma_enqueue(q, i, &q_data->queue_stats);

	/* Update stats */
	q_data->queue_stats.enqueued_count += i;
	q_data->queue_stats.enqueue_err_count += num - i;
	return i;
}

/* Enqueue decode operations for ACC101 device. */
static uint16_t
acc101_enqueue_ldpc_dec(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_dec_op **ops, uint16_t num)
{
	uint16_t ret;
	int32_t aq_avail = acc101_aq_avail(q_data, num);
	if (unlikely((aq_avail <= 0) || (num == 0)))
		return 0;
	if (ops[0]->ldpc_dec.code_block_mode == RTE_BBDEV_TRANSPORT_BLOCK)
		ret = acc101_enqueue_ldpc_dec_tb(q_data, ops, num);
	else
		ret = acc101_enqueue_ldpc_dec_cb(q_data, ops, num);
	return ret;
}


/* Dequeue one encode operations from ACC101 device in CB mode
 */
static inline int
dequeue_enc_one_op_cb(struct acc101_queue *q, struct rte_bbdev_enc_op **ref_op,
		uint16_t *dequeued_ops, uint32_t *aq_dequeued,
		uint16_t *dequeued_descs)
{
	union acc101_dma_desc *desc, atom_desc;
	union acc101_dma_rsp_desc rsp;
	struct rte_bbdev_enc_op *op;
	int i;
	int desc_idx = ((q->sw_ring_tail + *dequeued_descs)
			& q->sw_ring_wrap_mask);
	desc = q->ring_addr + desc_idx;
	atom_desc.atom_hdr = __atomic_load_n((uint64_t *)desc,
			__ATOMIC_RELAXED);

	/* Check fdone bit */
	if (!(atom_desc.rsp.val & ACC101_FDONE))
		return -1;

	rsp.val = atom_desc.rsp.val;
	rte_bbdev_log_debug("Resp. desc %p: %x num %d\n",
			desc, rsp.val, desc->req.numCBs);

	/* Dequeue */
	op = desc->req.op_addr;

	/* Clearing status, it will be set based on response */
	op->status = 0;
	op->status |= ((rsp.dma_err) ? (1 << RTE_BBDEV_DRV_ERROR) : 0);
	op->status |= ((rsp.fcw_err) ? (1 << RTE_BBDEV_DRV_ERROR) : 0);

	if (desc->req.last_desc_in_batch) {
		(*aq_dequeued)++;
		desc->req.last_desc_in_batch = 0;
	}
	desc->rsp.val = ACC101_DMA_DESC_TYPE;
	desc->rsp.add_info_0 = 0; /*Reserved bits */
	desc->rsp.add_info_1 = 0; /*Reserved bits */

	ref_op[0] = op;
	struct acc101_ptrs *context_ptrs = q->companion_ring_addr + desc_idx;
	for (i = 1 ; i < desc->req.numCBs; i++)
		ref_op[i] = context_ptrs->ptr[i].op_addr;

	/* One op was successfully dequeued */
	(*dequeued_descs)++;
	*dequeued_ops += desc->req.numCBs;
	return desc->req.numCBs;
}

/* Dequeue one LDPC encode operations from ACC101 device in TB mode
 * That operation may cover multiple descriptors
 */
static inline int
dequeue_enc_one_op_tb(struct acc101_queue *q, struct rte_bbdev_enc_op **ref_op,
		uint16_t *dequeued_ops, uint32_t *aq_dequeued,
		uint16_t *dequeued_descs)
{
	union acc101_dma_desc *desc, *last_desc, atom_desc;
	union acc101_dma_rsp_desc rsp;
	struct rte_bbdev_enc_op *op;
	uint8_t i = 0;
	uint16_t current_dequeued_descs = 0, descs_in_tb;

	desc = q->ring_addr + ((q->sw_ring_tail + *dequeued_descs)
			& q->sw_ring_wrap_mask);
	atom_desc.atom_hdr = __atomic_load_n((uint64_t *)desc,
			__ATOMIC_RELAXED);

	/* Check fdone bit */
	if (!(atom_desc.rsp.val & ACC101_FDONE))
		return -1;

	/* Get number of CBs in dequeued TB */
	descs_in_tb = desc->req.cbs_in_tb;
	/* Get last CB */
	last_desc = q->ring_addr + ((q->sw_ring_tail
			+ *dequeued_descs + descs_in_tb - 1)
			& q->sw_ring_wrap_mask);
	/* Check if last CB in TB is ready to dequeue (and thus
	 * the whole TB) - checking sdone bit. If not return.
	 */
	atom_desc.atom_hdr = __atomic_load_n((uint64_t *)last_desc,
			__ATOMIC_RELAXED);
	if (!(atom_desc.rsp.val & ACC101_SDONE))
		return -1;

	/* Dequeue */
	op = desc->req.op_addr;

	/* Clearing status, it will be set based on response */
	op->status = 0;

	while (i < descs_in_tb) {
		desc = q->ring_addr + ((q->sw_ring_tail
				+ *dequeued_descs)
				& q->sw_ring_wrap_mask);
		atom_desc.atom_hdr = __atomic_load_n((uint64_t *)desc,
				__ATOMIC_RELAXED);
		rsp.val = atom_desc.rsp.val;
		rte_bbdev_log_debug("Resp. desc %p: %x descs %d cbs %d\n",
				desc,
				rsp.val, descs_in_tb,
				desc->req.numCBs);

		op->status |= ((rsp.dma_err) ? (1 << RTE_BBDEV_DRV_ERROR) : 0);
		op->status |= ((rsp.fcw_err) ? (1 << RTE_BBDEV_DRV_ERROR) : 0);

		if (desc->req.last_desc_in_batch) {
			(*aq_dequeued)++;
			desc->req.last_desc_in_batch = 0;
		}
		desc->rsp.val = ACC101_DMA_DESC_TYPE;
		desc->rsp.add_info_0 = 0;
		desc->rsp.add_info_1 = 0;
		(*dequeued_descs)++;
		current_dequeued_descs++;
		i++;
	}

	*ref_op = op;
	(*dequeued_ops)++;
	return current_dequeued_descs;
}


/* Dequeue one decode operations from ACC101 device in CB mode */
static inline int
dequeue_ldpc_dec_one_op_cb(struct rte_bbdev_queue_data *q_data,
		struct acc101_queue *q, struct rte_bbdev_dec_op **ref_op,
		uint16_t dequeued_cbs, uint32_t *aq_dequeued)
{
	union acc101_dma_desc *desc, atom_desc;
	union acc101_dma_rsp_desc rsp;
	struct rte_bbdev_dec_op *op;

	desc = q->ring_addr + ((q->sw_ring_tail + dequeued_cbs)
			& q->sw_ring_wrap_mask);
	atom_desc.atom_hdr = __atomic_load_n((uint64_t *)desc,
			__ATOMIC_RELAXED);

	/* Check fdone bit */
	if (!(atom_desc.rsp.val & ACC101_FDONE))
		return -1;

	rsp.val = atom_desc.rsp.val;
	rte_bbdev_log_debug("Resp. desc %p: %x\n", desc, rsp.val);

	/* Dequeue */
	op = desc->req.op_addr;

	/* Clearing status, it will be set based on response */
	op->status = 0;
	op->status |= rsp.input_err << RTE_BBDEV_DATA_ERROR;
	op->status |= rsp.dma_err << RTE_BBDEV_DRV_ERROR;
	op->status |= rsp.fcw_err << RTE_BBDEV_DRV_ERROR;
	if (op->status != 0)
		q_data->queue_stats.dequeue_err_count++;

	op->status |= rsp.crc_status << RTE_BBDEV_CRC_ERROR;
	if (op->ldpc_dec.hard_output.length > 0 && !rsp.synd_ok)
		op->status |= 1 << RTE_BBDEV_SYNDROME_ERROR;
	op->ldpc_dec.iter_count = (uint8_t) rsp.iter_cnt;

	/* Check if this is the last desc in batch (Atomic Queue) */
	if (desc->req.last_desc_in_batch) {
		(*aq_dequeued)++;
		desc->req.last_desc_in_batch = 0;
	}

	desc->rsp.val = ACC101_DMA_DESC_TYPE;
	desc->rsp.add_info_0 = 0;
	desc->rsp.add_info_1 = 0;

	*ref_op = op;

	/* One CB (op) was successfully dequeued */
	return 1;
}

/* Dequeue one decode operations from ACC101 device in TB mode. */
static inline int
dequeue_dec_one_op_tb(struct acc101_queue *q, struct rte_bbdev_dec_op **ref_op,
		uint16_t dequeued_cbs, uint32_t *aq_dequeued)
{
	union acc101_dma_desc *desc, *last_desc, atom_desc;
	union acc101_dma_rsp_desc rsp;
	struct rte_bbdev_dec_op *op;
	uint8_t cbs_in_tb = 1, cb_idx = 0;

	desc = q->ring_addr + ((q->sw_ring_tail + dequeued_cbs)
			& q->sw_ring_wrap_mask);
	atom_desc.atom_hdr = __atomic_load_n((uint64_t *)desc,
			__ATOMIC_RELAXED);

	/* Check fdone bit */
	if (!(atom_desc.rsp.val & ACC101_FDONE))
		return -1;

	/* Dequeue */
	op = desc->req.op_addr;

	/* Get number of CBs in dequeued TB */
	cbs_in_tb = desc->req.cbs_in_tb;
	/* Get last CB */
	last_desc = q->ring_addr + ((q->sw_ring_tail
			+ dequeued_cbs + cbs_in_tb - 1)
			& q->sw_ring_wrap_mask);
	/* Check if last CB in TB is ready to dequeue (and thus
	 * the whole TB) - checking sdone bit. If not return.
	 */
	atom_desc.atom_hdr = __atomic_load_n((uint64_t *)last_desc,
			__ATOMIC_RELAXED);
	if (!(atom_desc.rsp.val & ACC101_SDONE))
		return -1;

	/* Clearing status, it will be set based on response */
	op->status = 0;

	/* Read remaining CBs if exists */
	while (cb_idx < cbs_in_tb) {
		desc = q->ring_addr + ((q->sw_ring_tail + dequeued_cbs)
				& q->sw_ring_wrap_mask);
		atom_desc.atom_hdr = __atomic_load_n((uint64_t *)desc,
				__ATOMIC_RELAXED);
		rsp.val = atom_desc.rsp.val;
		rte_bbdev_log_debug("Resp. desc %p: %x r %d c %d\n",
				desc, rsp.val,
				cb_idx, cbs_in_tb);

		op->status |= ((rsp.input_err)
				? (1 << RTE_BBDEV_DATA_ERROR) : 0);
		op->status |= ((rsp.dma_err) ? (1 << RTE_BBDEV_DRV_ERROR) : 0);
		op->status |= ((rsp.fcw_err) ? (1 << RTE_BBDEV_DRV_ERROR) : 0);

		/* CRC invalid if error exists */
		if (!op->status)
			op->status |= rsp.crc_status << RTE_BBDEV_CRC_ERROR;
		op->turbo_dec.iter_count = RTE_MAX((uint8_t) rsp.iter_cnt,
				op->turbo_dec.iter_count);

		/* Check if this is the last desc in batch (Atomic Queue) */
		if (desc->req.last_desc_in_batch) {
			(*aq_dequeued)++;
			desc->req.last_desc_in_batch = 0;
		}
		desc->rsp.val = ACC101_DMA_DESC_TYPE;
		desc->rsp.add_info_0 = 0;
		desc->rsp.add_info_1 = 0;
		dequeued_cbs++;
		cb_idx++;
	}

	*ref_op = op;

	return cb_idx;
}

/* Dequeue LDPC encode operations from ACC101 device. */
static uint16_t
acc101_dequeue_ldpc_enc(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_enc_op **ops, uint16_t num)
{
	struct acc101_queue *q = q_data->queue_private;
	uint32_t avail = acc101_ring_avail_deq(q);
	uint32_t aq_dequeued = 0;
	uint16_t i, dequeued_ops = 0, dequeued_descs = 0;
	int ret;
	struct rte_bbdev_enc_op *op;
	if (avail == 0)
		return 0;
	op = (q->ring_addr + (q->sw_ring_tail &
			q->sw_ring_wrap_mask))->req.op_addr;
#ifdef RTE_LIBRTE_BBDEV_DEBUG
	if (unlikely(ops == NULL || q == NULL || op == NULL))
		return 0;
#endif
	int cbm = op->ldpc_enc.code_block_mode;

	for (i = 0; i < num; i++) {
		if (cbm == RTE_BBDEV_TRANSPORT_BLOCK)
			ret = dequeue_enc_one_op_tb(q, &ops[dequeued_ops],
					&dequeued_ops, &aq_dequeued,
					&dequeued_descs);
		else
			ret = dequeue_enc_one_op_cb(q, &ops[dequeued_ops],
					&dequeued_ops, &aq_dequeued,
					&dequeued_descs);
		if (ret < 0)
			break;
		if (dequeued_ops >= num)
			break;
	}

	q->aq_dequeued += aq_dequeued;
	q->sw_ring_tail += dequeued_descs;

	/* Update enqueue stats */
	q_data->queue_stats.dequeued_count += dequeued_ops;
	return dequeued_ops;
}

/* Dequeue decode operations from ACC101 device. */
static uint16_t
acc101_dequeue_ldpc_dec(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_dec_op **ops, uint16_t num)
{
	struct acc101_queue *q = q_data->queue_private;
	uint16_t dequeue_num;
	uint32_t avail = acc101_ring_avail_deq(q);
	uint32_t aq_dequeued = 0;
	uint16_t i;
	uint16_t dequeued_cbs = 0;
	struct rte_bbdev_dec_op *op;
	int ret;

#ifdef RTE_LIBRTE_BBDEV_DEBUG
	if (unlikely(ops == 0 && q == NULL))
		return 0;
#endif

	dequeue_num = RTE_MIN(avail, num);

	for (i = 0; i < dequeue_num; ++i) {
		op = (q->ring_addr + ((q->sw_ring_tail + dequeued_cbs)
			& q->sw_ring_wrap_mask))->req.op_addr;
		if (op->ldpc_dec.code_block_mode == RTE_BBDEV_TRANSPORT_BLOCK)
			ret = dequeue_dec_one_op_tb(q, &ops[i], dequeued_cbs,
					&aq_dequeued);
		else
			ret = dequeue_ldpc_dec_one_op_cb(
					q_data, q, &ops[i], dequeued_cbs,
					&aq_dequeued);

		if (ret < 0)
			break;
		dequeued_cbs += ret;
	}

	q->aq_dequeued += aq_dequeued;
	q->sw_ring_tail += dequeued_cbs;

	/* Update enqueue stats */
	q_data->queue_stats.dequeued_count += i;
	return i;
}

/* Initialization Function */
static void
acc101_bbdev_init(struct rte_bbdev *dev, struct rte_pci_driver *drv)
{
	struct rte_pci_device *pci_dev = RTE_DEV_TO_PCI(dev->device);

	dev->dev_ops = &acc101_bbdev_ops;
	dev->enqueue_ldpc_enc_ops = acc101_enqueue_ldpc_enc;
	dev->enqueue_ldpc_dec_ops = acc101_enqueue_ldpc_dec;
	dev->dequeue_ldpc_enc_ops = acc101_dequeue_ldpc_enc;
	dev->dequeue_ldpc_dec_ops = acc101_dequeue_ldpc_dec;

	((struct acc101_device *) dev->data->dev_private)->pf_device =
			!strcmp(drv->driver.name,
					RTE_STR(ACC101PF_DRIVER_NAME));
	((struct acc101_device *) dev->data->dev_private)->mmio_base =
			pci_dev->mem_resource[0].addr;

	rte_bbdev_log_debug("Init device %s [%s] @ vaddr %p paddr %#"PRIx64"",
			drv->driver.name, dev->data->name,
			(void *)pci_dev->mem_resource[0].addr,
			pci_dev->mem_resource[0].phys_addr);
}

static int acc101_pci_probe(struct rte_pci_driver *pci_drv,
	struct rte_pci_device *pci_dev)
{
	struct rte_bbdev *bbdev = NULL;
	char dev_name[RTE_BBDEV_NAME_MAX_LEN];

	if (pci_dev == NULL) {
		rte_bbdev_log(ERR, "NULL PCI device");
		return -EINVAL;
	}

	rte_pci_device_name(&pci_dev->addr, dev_name, sizeof(dev_name));

	/* Allocate memory to be used privately by drivers */
	bbdev = rte_bbdev_allocate(pci_dev->device.name);
	if (bbdev == NULL)
		return -ENODEV;

	/* allocate device private memory */
	bbdev->data->dev_private = rte_zmalloc_socket(dev_name,
			sizeof(struct acc101_device), RTE_CACHE_LINE_SIZE,
			pci_dev->device.numa_node);

	if (bbdev->data->dev_private == NULL) {
		rte_bbdev_log(CRIT,
				"Allocate of %zu bytes for device \"%s\" failed",
				sizeof(struct acc101_device), dev_name);
				rte_bbdev_release(bbdev);
			return -ENOMEM;
	}

	/* Fill HW specific part of device structure */
	bbdev->device = &pci_dev->device;
	bbdev->intr_handle = pci_dev->intr_handle;
	bbdev->data->socket_id = pci_dev->device.numa_node;

	/* Invoke ACC101 device initialization function */
	acc101_bbdev_init(bbdev, pci_drv);

	rte_bbdev_log_debug("Initialised bbdev %s (id = %u)",
			dev_name, bbdev->data->dev_id);
	return 0;
}

static int acc101_pci_remove(struct rte_pci_device *pci_dev)
{
	struct rte_bbdev *bbdev;
	int ret;
	uint8_t dev_id;

	if (pci_dev == NULL)
		return -EINVAL;

	/* Find device */
	bbdev = rte_bbdev_get_named_dev(pci_dev->device.name);
	if (bbdev == NULL) {
		rte_bbdev_log(CRIT,
				"Couldn't find HW dev \"%s\" to uninitialise it",
				pci_dev->device.name);
		return -ENODEV;
	}
	dev_id = bbdev->data->dev_id;

	/* free device private memory before close */
	rte_free(bbdev->data->dev_private);

	/* Close device */
	ret = rte_bbdev_close(dev_id);
	if (ret < 0)
		rte_bbdev_log(ERR,
				"Device %i failed to close during uninit: %i",
				dev_id, ret);

	/* release bbdev from library */
	rte_bbdev_release(bbdev);

	rte_bbdev_log_debug("Destroyed bbdev = %u", dev_id);

	return 0;
}

static struct rte_pci_driver acc101_pci_pf_driver = {
		.probe = acc101_pci_probe,
		.remove = acc101_pci_remove,
		.id_table = pci_id_acc101_pf_map,
		.drv_flags = RTE_PCI_DRV_NEED_MAPPING
};

static struct rte_pci_driver acc101_pci_vf_driver = {
		.probe = acc101_pci_probe,
		.remove = acc101_pci_remove,
		.id_table = pci_id_acc101_vf_map,
		.drv_flags = RTE_PCI_DRV_NEED_MAPPING
};

RTE_PMD_REGISTER_PCI(ACC101PF_DRIVER_NAME, acc101_pci_pf_driver);
RTE_PMD_REGISTER_PCI_TABLE(ACC101PF_DRIVER_NAME, pci_id_acc101_pf_map);
RTE_PMD_REGISTER_PCI(ACC101VF_DRIVER_NAME, acc101_pci_vf_driver);
RTE_PMD_REGISTER_PCI_TABLE(ACC101VF_DRIVER_NAME, pci_id_acc101_vf_map);
