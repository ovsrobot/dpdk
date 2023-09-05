/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <unistd.h>
#include <time.h>
#include <rte_mbuf.h>
#include <rte_pci.h>

#include "ntdrv_4ga.h"
#include "nt_util.h"
#include "ntnic_dbsconfig.h"
#include "ntnic_ethdev.h"
#include "ntlog.h"

#define STRUCT_ALIGNMENT (4 * 1024LU)
#define MAX_VIRT_QUEUES 128

#define LAST_QUEUE 127
#define DISABLE 0
#define ENABLE 1
#define RX_AM_DISABLE DISABLE
#define RX_AM_ENABLE ENABLE
#define RX_UW_DISABLE DISABLE
#define RX_UW_ENABLE ENABLE
#define RX_Q_DISABLE DISABLE
#define RX_Q_ENABLE ENABLE
#define RX_AM_POLL_SPEED 5
#define RX_UW_POLL_SPEED 9
#define HOST_ID 0
#define INIT_QUEUE 1

#define TX_AM_DISABLE DISABLE
#define TX_AM_ENABLE ENABLE
#define TX_UW_DISABLE DISABLE
#define TX_UW_ENABLE ENABLE
#define TX_Q_DISABLE DISABLE
#define TX_Q_ENABLE ENABLE
#define TX_AM_POLL_SPEED 5
#define TX_UW_POLL_SPEED 8

/**************************************************************************/

#define le64 uint64_t
#define le32 uint32_t
#define le16 uint16_t

/**************************************************************************/

#define VIRTQ_AVAIL_F_NO_INTERRUPT 1
#pragma pack(1)
struct virtq_avail {
	le16 flags;
	le16 idx;
	le16 ring[]; /* Queue size */
};

#pragma pack()
/**************************************************************************/

/* le32 is used here for ids for padding reasons. */
#pragma pack(1)
struct virtq_used_elem {
	/* Index of start of used descriptor chain. */
	le32 id;
	/* Total length of the descriptor chain which was used (written to) */
	le32 len;
};

#pragma pack()

#define VIRTQ_USED_F_NO_NOTIFY 1

#pragma pack(1)
struct virtq_used {
	le16 flags;
	le16 idx;
	struct virtq_used_elem ring[]; /* Queue size */
};

#pragma pack()

struct virtq_struct_layout_s {
	size_t used_offset;
	size_t desc_offset;
};

enum nthw_virt_queue_usage { UNUSED = 0, UNMANAGED, MANAGED };

#define PACKED(vq_type) ((vq_type) == PACKED_RING ? 1 : 0)

struct nthw_virt_queue {
	/* Pointers to virt-queue structs */
	union {
		struct {
			/* SPLIT virtqueue */
			struct virtq_avail *p_avail;
			struct virtq_used *p_used;
			struct virtq_desc *p_desc;
			/* Control variables for virt-queue structs */
			le16 am_idx;
			le16 used_idx;
			le16 cached_idx;
			le16 tx_descr_avail_idx;
		};
		struct {
			/* PACKED virtqueue */
			struct pvirtq_event_suppress *driver_event;
			struct pvirtq_event_suppress *device_event;
			struct pvirtq_desc *desc;
			struct {
				le16 next;
				le16 num;
			} outs;
			/*
			 * when in-order release used Tx packets from FPGA it may collapse
			 * into a batch. When getting new Tx buffers we may only need
			 * partial
			 */
			le16 next_avail;
			le16 next_used;
			le16 avail_wrap_count;
			le16 used_wrap_count;
		};
	};

	/* Array with packet buffers */
	struct nthw_memory_descriptor *p_virtual_addr;

	/* Queue configuration info */
	enum nthw_virt_queue_usage usage;
	uint16_t vq_type;
	uint16_t in_order;
	int irq_vector;

	nthw_dbs_t *mp_nthw_dbs;
	uint32_t index;
	le16 queue_size;
	uint32_t am_enable;
	uint32_t host_id;
	uint32_t port; /* Only used by TX queues */
	uint32_t virtual_port; /* Only used by TX queues */
	uint32_t header;
	/*
	 * Only used by TX queues:
	 *   0: VirtIO-Net header (12 bytes).
	 *   1: Napatech DVIO0 descriptor (12 bytes).
	 */
	void *avail_struct_phys_addr;
	void *used_struct_phys_addr;
	void *desc_struct_phys_addr;
};

struct pvirtq_struct_layout_s {
	size_t driver_event_offset;
	size_t device_event_offset;
};

static struct nthw_virt_queue rxvq[MAX_VIRT_QUEUES];
static struct nthw_virt_queue txvq[MAX_VIRT_QUEUES];

static void dbs_init_rx_queue(nthw_dbs_t *p_nthw_dbs, uint32_t queue,
			      uint32_t start_idx, uint32_t start_ptr)
{
	uint32_t busy;
	uint32_t init;
	uint32_t dummy;

	do {
		get_rx_init(p_nthw_dbs, &init, &dummy, &busy);
	} while (busy != 0);

	set_rx_init(p_nthw_dbs, start_idx, start_ptr, INIT_QUEUE, queue);

	do {
		get_rx_init(p_nthw_dbs, &init, &dummy, &busy);
	} while (busy != 0);
}

static void dbs_init_tx_queue(nthw_dbs_t *p_nthw_dbs, uint32_t queue,
			      uint32_t start_idx, uint32_t start_ptr)
{
	uint32_t busy;
	uint32_t init;
	uint32_t dummy;

	do {
		get_tx_init(p_nthw_dbs, &init, &dummy, &busy);
	} while (busy != 0);

	set_tx_init(p_nthw_dbs, start_idx, start_ptr, INIT_QUEUE, queue);

	do {
		get_tx_init(p_nthw_dbs, &init, &dummy, &busy);
	} while (busy != 0);
}

int nthw_virt_queue_init(struct fpga_info_s *p_fpga_info)
{
	assert(p_fpga_info);

	nt_fpga_t *const p_fpga = p_fpga_info->mp_fpga;
	nthw_dbs_t *p_nthw_dbs;
	int res = 0;
	uint32_t i;

	p_fpga_info->mp_nthw_dbs = NULL;

	p_nthw_dbs = nthw_dbs_new();
	if (p_nthw_dbs == NULL)
		return -1;

	res = dbs_init(NULL, p_fpga, 0); /* Check that DBS exists in FPGA */
	if (res) {
		free(p_nthw_dbs);
		return res;
	}

	res = dbs_init(p_nthw_dbs, p_fpga, 0); /* Create DBS module */
	if (res) {
		free(p_nthw_dbs);
		return res;
	}

	p_fpga_info->mp_nthw_dbs = p_nthw_dbs;

	for (i = 0; i < MAX_VIRT_QUEUES; ++i) {
		rxvq[i].usage = UNUSED;
		txvq[i].usage = UNUSED;
	}

	dbs_reset(p_nthw_dbs);

	for (i = 0; i < NT_DBS_RX_QUEUES_MAX; ++i)
		dbs_init_rx_queue(p_nthw_dbs, i, 0, 0);

	for (i = 0; i < NT_DBS_TX_QUEUES_MAX; ++i)
		dbs_init_tx_queue(p_nthw_dbs, i, 0, 0);

	set_rx_control(p_nthw_dbs, LAST_QUEUE, RX_AM_DISABLE, RX_AM_POLL_SPEED,
		       RX_UW_DISABLE, RX_UW_POLL_SPEED, RX_Q_DISABLE);
	set_rx_control(p_nthw_dbs, LAST_QUEUE, RX_AM_ENABLE, RX_AM_POLL_SPEED,
		       RX_UW_ENABLE, RX_UW_POLL_SPEED, RX_Q_DISABLE);
	set_rx_control(p_nthw_dbs, LAST_QUEUE, RX_AM_ENABLE, RX_AM_POLL_SPEED,
		       RX_UW_ENABLE, RX_UW_POLL_SPEED, RX_Q_ENABLE);

	set_tx_control(p_nthw_dbs, LAST_QUEUE, TX_AM_DISABLE, TX_AM_POLL_SPEED,
		       TX_UW_DISABLE, TX_UW_POLL_SPEED, TX_Q_DISABLE);
	set_tx_control(p_nthw_dbs, LAST_QUEUE, TX_AM_ENABLE, TX_AM_POLL_SPEED,
		       TX_UW_ENABLE, TX_UW_POLL_SPEED, TX_Q_DISABLE);
	set_tx_control(p_nthw_dbs, LAST_QUEUE, TX_AM_ENABLE, TX_AM_POLL_SPEED,
		       TX_UW_ENABLE, TX_UW_POLL_SPEED, TX_Q_ENABLE);

	return 0;
}

static struct virtq_struct_layout_s dbs_calc_struct_layout(uint32_t queue_size)
{
	size_t avail_mem =
		sizeof(struct virtq_avail) +
		queue_size *
		sizeof(le16); /* + sizeof(le16); ("avail->used_event" is not used) */
	size_t avail_mem_aligned =
		((avail_mem % STRUCT_ALIGNMENT) == 0) ?
		avail_mem :
		STRUCT_ALIGNMENT * (avail_mem / STRUCT_ALIGNMENT + 1);

	/* + sizeof(le16); ("used->avail_event" is not used) */
	size_t used_mem =
		sizeof(struct virtq_used) +
		queue_size *
		sizeof(struct virtq_used_elem);
	size_t used_mem_aligned =
		((used_mem % STRUCT_ALIGNMENT) == 0) ?
		used_mem :
		STRUCT_ALIGNMENT * (used_mem / STRUCT_ALIGNMENT + 1);

	struct virtq_struct_layout_s virtq_layout;

	virtq_layout.used_offset = avail_mem_aligned;
	virtq_layout.desc_offset = avail_mem_aligned + used_mem_aligned;

	return virtq_layout;
}

static void dbs_initialize_avail_struct(void *addr, uint16_t queue_size,
					uint16_t initial_avail_idx)
{
	uint16_t i;
	struct virtq_avail *p_avail = (struct virtq_avail *)addr;

	p_avail->flags = VIRTQ_AVAIL_F_NO_INTERRUPT;
	p_avail->idx = initial_avail_idx;
	for (i = 0; i < queue_size; ++i)
		p_avail->ring[i] = i;
}

static void dbs_initialize_used_struct(void *addr, uint16_t queue_size)
{
	int i;
	struct virtq_used *p_used = (struct virtq_used *)addr;

	p_used->flags = 1;
	p_used->idx = 0;
	for (i = 0; i < queue_size; ++i) {
		p_used->ring[i].id = 0;
		p_used->ring[i].len = 0;
	}
}

static void dbs_initialize_descriptor_struct(void *addr,
	struct nthw_memory_descriptor *packet_buffer_descriptors,
	uint16_t queue_size, ule16 flgs)
{
	if (packet_buffer_descriptors) {
		int i;
		struct virtq_desc *p_desc = (struct virtq_desc *)addr;

		for (i = 0; i < queue_size; ++i) {
			p_desc[i].addr =
				(uint64_t)packet_buffer_descriptors[i].phys_addr;
			p_desc[i].len = packet_buffer_descriptors[i].len;
			p_desc[i].flags = flgs;
			p_desc[i].next = 0;
		}
	}
}

static void dbs_initialize_virt_queue_structs(void *avail_struct_addr,
	void *used_struct_addr, void *desc_struct_addr,
	struct nthw_memory_descriptor *packet_buffer_descriptors,
	uint16_t queue_size, uint16_t initial_avail_idx, ule16 flgs)
{
	dbs_initialize_avail_struct(avail_struct_addr, queue_size,
				    initial_avail_idx);
	dbs_initialize_used_struct(used_struct_addr, queue_size);
	dbs_initialize_descriptor_struct(desc_struct_addr,
					 packet_buffer_descriptors,
					 queue_size, flgs);
}

static le16 dbs_qsize_log2(le16 qsize)
{
	uint32_t qs = 0;

	while (qsize) {
		qsize = qsize >> 1;
		++qs;
	}
	--qs;
	return qs;
}

struct nthw_virt_queue *nthw_setup_rx_virt_queue(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint16_t start_idx,
	uint16_t start_ptr, void *avail_struct_phys_addr, void *used_struct_phys_addr,
	void *desc_struct_phys_addr, uint16_t queue_size, uint32_t host_id,
	uint32_t header, uint32_t vq_type, int irq_vector)
{
	uint32_t qs = dbs_qsize_log2(queue_size);
	uint32_t int_enable;
	uint32_t vec;
	uint32_t istk;

	/*
	 * Setup DBS module - DSF00094
	 * 3. Configure the DBS.RX_DR_DATA memory; good idea to initialize all
	 * DBS_RX_QUEUES entries.
	 */
	if (set_rx_dr_data(p_nthw_dbs, index, (uint64_t)desc_struct_phys_addr,
			   host_id, qs, header, PACKED(vq_type)) != 0)
		return NULL;

	/*
	 * 4. Configure the DBS.RX_UW_DATA memory; good idea to initialize all
	 *   DBS_RX_QUEUES entries.
	 *   Notice: We always start out with interrupts disabled (by setting the
	 *     "irq_vector" argument to -1). Queues that require interrupts will have
	 *     it enabled at a later time (after we have enabled vfio interrupts in
	 *     the kernel).
	 */
	int_enable = 0;
	vec = 0;
	istk = 0;
	NT_LOG(DBG, ETHDEV, "%s: set_rx_uw_data int=0 irq_vector=%u\n",
	       __func__, irq_vector);
	if (set_rx_uw_data(p_nthw_dbs, index,
			   vq_type == PACKED_RING ? (uint64_t)desc_struct_phys_addr :
			   (uint64_t)used_struct_phys_addr,
			   host_id, qs, PACKED(vq_type), int_enable, vec, istk) != 0)
		return NULL;

	/*
	 * 2. Configure the DBS.RX_AM_DATA memory and enable the queues you plan to use;
	 *  good idea to initialize all DBS_RX_QUEUES entries.
	 *  Notice: We do this only for queues that don't require interrupts (i.e. if
	 *    irq_vector < 0). Queues that require interrupts will have RX_AM_DATA enabled
	 *    at a later time (after we have enabled vfio interrupts in the kernel).
	 */
	if (irq_vector < 0) {
		if (set_rx_am_data(p_nthw_dbs, index,
				   (uint64_t)avail_struct_phys_addr, RX_AM_DISABLE,
				   host_id, PACKED(vq_type),
				   irq_vector >= 0 ? 1 : 0) != 0)
			return NULL;
	}

	/*
	 * 5. Initialize all RX queues (all DBS_RX_QUEUES of them) using the
	 *   DBS.RX_INIT register.
	 */
	dbs_init_rx_queue(p_nthw_dbs, index, start_idx, start_ptr);

	/*
	 * 2. Configure the DBS.RX_AM_DATA memory and enable the queues you plan to use;
	 *  good idea to initialize all DBS_RX_QUEUES entries.
	 */
	if (set_rx_am_data(p_nthw_dbs, index, (uint64_t)avail_struct_phys_addr,
			   RX_AM_ENABLE, host_id, PACKED(vq_type),
			   irq_vector >= 0 ? 1 : 0) != 0)
		return NULL;

	/* Save queue state */
	rxvq[index].usage = UNMANAGED;
	rxvq[index].mp_nthw_dbs = p_nthw_dbs;
	rxvq[index].index = index;
	rxvq[index].queue_size = queue_size;
	rxvq[index].am_enable = (irq_vector < 0) ? RX_AM_ENABLE : RX_AM_DISABLE;
	rxvq[index].host_id = host_id;
	rxvq[index].avail_struct_phys_addr = avail_struct_phys_addr;
	rxvq[index].used_struct_phys_addr = used_struct_phys_addr;
	rxvq[index].desc_struct_phys_addr = desc_struct_phys_addr;
	rxvq[index].vq_type = vq_type;
	rxvq[index].in_order = 0; /* not used */
	rxvq[index].irq_vector = irq_vector;

	/* Return queue handle */
	return &rxvq[index];
}

static int dbs_wait_hw_queue_shutdown(struct nthw_virt_queue *vq, int rx);

int nthw_disable_rx_virt_queue(struct nthw_virt_queue *rx_vq)
{
	if (!rx_vq) {
		NT_LOG(ERR, ETHDEV, "%s: Invalid queue\n", __func__);
		return -1;
	}

	nthw_dbs_t *p_nthw_dbs = rx_vq->mp_nthw_dbs;

	if (rx_vq->index >= MAX_VIRT_QUEUES)
		return -1;

	if (rx_vq->usage != UNMANAGED)
		return -1;

	uint32_t qs = dbs_qsize_log2(rx_vq->queue_size);

	/* If ISTK is set, make sure to unset it */
	if (set_rx_uw_data(p_nthw_dbs, rx_vq->index,
			   rx_vq->vq_type == PACKED_RING ?
			   (uint64_t)rx_vq->desc_struct_phys_addr :
			   (uint64_t)rx_vq->used_struct_phys_addr,
			   rx_vq->host_id, qs, PACKED(rx_vq->vq_type), 0, 0,
			   0) != 0)
		return -1;

	/* Disable AM */
	rx_vq->am_enable = RX_AM_DISABLE;
	if (set_rx_am_data(p_nthw_dbs, rx_vq->index,
			   (uint64_t)rx_vq->avail_struct_phys_addr,
			   rx_vq->am_enable, rx_vq->host_id,
			   PACKED(rx_vq->vq_type), 0) != 0)
		return -1;

	/* let the FPGA finish packet processing */
	if (dbs_wait_hw_queue_shutdown(rx_vq, 1) != 0)
		return -1;

	return 0;
}

int nthw_enable_rx_virt_queue(struct nthw_virt_queue *rx_vq)
{
	uint32_t int_enable;
	uint32_t vec;
	uint32_t istk;

	if (!rx_vq) {
		NT_LOG(ERR, ETHDEV, "%s: Invalid queue\n", __func__);
		return -1;
	}

	nthw_dbs_t *p_nthw_dbs = rx_vq->mp_nthw_dbs;

	if (rx_vq->index >= MAX_VIRT_QUEUES)
		return -1;

	if (rx_vq->usage != UNMANAGED)
		return -1;

	uint32_t qs = dbs_qsize_log2(rx_vq->queue_size);

	/* Set ISTK if */
	if (rx_vq->irq_vector >= 0 &&
			rx_vq->irq_vector < MAX_MSIX_VECTORS_PR_VF) {
		int_enable = 1;
		vec = rx_vq->irq_vector;
		istk = 1;
	} else {
		int_enable = 0;
		vec = 0;
		istk = 0;
	}
	NT_LOG(DBG, ETHDEV, "%s: set_rx_uw_data irq_vector=%u\n", __func__,
	       rx_vq->irq_vector);
	if (set_rx_uw_data(p_nthw_dbs, rx_vq->index,
			   rx_vq->vq_type == PACKED_RING ?
			   (uint64_t)rx_vq->desc_struct_phys_addr :
			   (uint64_t)rx_vq->used_struct_phys_addr,
			   rx_vq->host_id, qs, PACKED(rx_vq->vq_type),
			   int_enable, vec, istk) != 0)
		return -1;

	/* Enable AM */
	rx_vq->am_enable = RX_AM_ENABLE;
	if (set_rx_am_data(p_nthw_dbs, rx_vq->index,
			   (uint64_t)rx_vq->avail_struct_phys_addr,
			   rx_vq->am_enable, rx_vq->host_id,
			   PACKED(rx_vq->vq_type),
			   rx_vq->irq_vector >= 0 ? 1 : 0) != 0)
		return -1;

	return 0;
}

int nthw_disable_tx_virt_queue(struct nthw_virt_queue *tx_vq)
{
	if (!tx_vq) {
		NT_LOG(ERR, ETHDEV, "%s: Invalid queue\n", __func__);
		return -1;
	}

	nthw_dbs_t *p_nthw_dbs = tx_vq->mp_nthw_dbs;

	if (tx_vq->index >= MAX_VIRT_QUEUES)
		return -1;

	if (tx_vq->usage != UNMANAGED)
		return -1;

	uint32_t qs = dbs_qsize_log2(tx_vq->queue_size);

	/* If ISTK is set, make sure to unset it */
	if (set_tx_uw_data(p_nthw_dbs, tx_vq->index,
			   tx_vq->vq_type == PACKED_RING ?
			   (uint64_t)tx_vq->desc_struct_phys_addr :
			   (uint64_t)tx_vq->used_struct_phys_addr,
			   tx_vq->host_id, qs, PACKED(tx_vq->vq_type), 0, 0, 0,
			   tx_vq->in_order) != 0)
		return -1;

	/* Disable AM */
	tx_vq->am_enable = TX_AM_DISABLE;
	if (set_tx_am_data(p_nthw_dbs, tx_vq->index,
			   (uint64_t)tx_vq->avail_struct_phys_addr,
			   tx_vq->am_enable, tx_vq->host_id,
			   PACKED(tx_vq->vq_type), 0) != 0)
		return -1;

	/* let the FPGA finish packet processing */
	if (dbs_wait_hw_queue_shutdown(tx_vq, 0) != 0)
		return -1;

	return 0;
}

int nthw_enable_tx_virt_queue(struct nthw_virt_queue *tx_vq)
{
	uint32_t int_enable;
	uint32_t vec;
	uint32_t istk;

	if (!tx_vq) {
		NT_LOG(ERR, ETHDEV, "%s: Invalid queue\n", __func__);
		return -1;
	}

	nthw_dbs_t *p_nthw_dbs = tx_vq->mp_nthw_dbs;

	if (tx_vq->index >= MAX_VIRT_QUEUES)
		return -1;

	if (tx_vq->usage != UNMANAGED)
		return -1;

	uint32_t qs = dbs_qsize_log2(tx_vq->queue_size);

	/* Set ISTK if irq_vector is used */
	if (tx_vq->irq_vector >= 0 &&
			tx_vq->irq_vector < MAX_MSIX_VECTORS_PR_VF) {
		int_enable = 1;
		vec = tx_vq->irq_vector;
		istk = 1; /* Use sticky interrupt */
	} else {
		int_enable = 0;
		vec = 0;
		istk = 0;
	}
	if (set_tx_uw_data(p_nthw_dbs, tx_vq->index,
			   tx_vq->vq_type == PACKED_RING ?
			   (uint64_t)tx_vq->desc_struct_phys_addr :
			   (uint64_t)tx_vq->used_struct_phys_addr,
			   tx_vq->host_id, qs, PACKED(tx_vq->vq_type),
			   int_enable, vec, istk, tx_vq->in_order) != 0)
		return -1;

	/* Enable AM */
	tx_vq->am_enable = TX_AM_ENABLE;
	if (set_tx_am_data(p_nthw_dbs, tx_vq->index,
			   (uint64_t)tx_vq->avail_struct_phys_addr,
			   tx_vq->am_enable, tx_vq->host_id,
			   PACKED(tx_vq->vq_type),
			   tx_vq->irq_vector >= 0 ? 1 : 0) != 0)
		return -1;

	return 0;
}

int nthw_enable_and_change_port_tx_virt_queue(struct nthw_virt_queue *tx_vq,
		uint32_t outport)
{
	nthw_dbs_t *p_nthw_dbs = tx_vq->mp_nthw_dbs;
	uint32_t qs = dbs_qsize_log2(tx_vq->queue_size);

	if (set_tx_dr_data(p_nthw_dbs, tx_vq->index,
			   (uint64_t)tx_vq->desc_struct_phys_addr, tx_vq->host_id,
			   qs, outport, 0, PACKED(tx_vq->vq_type)) != 0)
		return -1;
	return nthw_enable_tx_virt_queue(tx_vq);
}

int nthw_set_tx_qos_config(nthw_dbs_t *p_nthw_dbs, uint32_t port, uint32_t enable,
			   uint32_t ir, uint32_t bs)
{
	return set_tx_qos_data(p_nthw_dbs, port, enable, ir, bs);
}

int nthw_set_tx_qos_rate_global(nthw_dbs_t *p_nthw_dbs, uint32_t multiplier,
				uint32_t divider)
{
	return set_tx_qos_rate(p_nthw_dbs, multiplier, divider);
}

#define INDEX_PTR_NOT_VALID 0x80000000
static int dbs_get_rx_ptr(nthw_dbs_t *p_nthw_dbs, uint32_t *p_index)
{
	uint32_t ptr;
	uint32_t queue;
	uint32_t valid;

	const int status = get_rx_ptr(p_nthw_dbs, &ptr, &queue, &valid);

	if (status == 0) {
		if (valid)
			*p_index = ptr;
		else
			*p_index = INDEX_PTR_NOT_VALID;
	}
	return status;
}

static int dbs_get_tx_ptr(nthw_dbs_t *p_nthw_dbs, uint32_t *p_index)
{
	uint32_t ptr;
	uint32_t queue;
	uint32_t valid;

	const int status = get_tx_ptr(p_nthw_dbs, &ptr, &queue, &valid);

	if (status == 0) {
		if (valid)
			*p_index = ptr;
		else
			*p_index = INDEX_PTR_NOT_VALID;
	}
	return status;
}

static int dbs_initialize_get_rx_ptr(nthw_dbs_t *p_nthw_dbs, uint32_t queue)
{
	return set_rx_ptr_queue(p_nthw_dbs, queue);
}

static int dbs_initialize_get_tx_ptr(nthw_dbs_t *p_nthw_dbs, uint32_t queue)
{
	return set_tx_ptr_queue(p_nthw_dbs, queue);
}

static int dbs_wait_on_busy(struct nthw_virt_queue *vq, uint32_t *idle, int rx)
{
	uint32_t busy;
	uint32_t queue;
	int err = 0;
	nthw_dbs_t *p_nthw_dbs = vq->mp_nthw_dbs;

	do {
		if (rx)
			err = get_rx_idle(p_nthw_dbs, idle, &queue, &busy);
		else
			err = get_tx_idle(p_nthw_dbs, idle, &queue, &busy);
	} while (!err && busy);

	return err;
}

static int dbs_wait_hw_queue_shutdown(struct nthw_virt_queue *vq, int rx)
{
	int err = 0;
	uint32_t idle = 0;
	nthw_dbs_t *p_nthw_dbs = vq->mp_nthw_dbs;

	err = dbs_wait_on_busy(vq, &idle, rx);
	if (err) {
		if (err == -ENOTSUP) {
			NT_OS_WAIT_USEC(200000);
			return 0;
		}
		return -1;
	}

	do {
		if (rx)
			err = set_rx_idle(p_nthw_dbs, 1, vq->index);
		else
			err = set_tx_idle(p_nthw_dbs, 1, vq->index);

		if (err)
			return -1;

		if (dbs_wait_on_busy(vq, &idle, rx) != 0)
			return -1;

	} while (idle == 0);

	return 0;
}

static int dbs_internal_release_rx_virt_queue(struct nthw_virt_queue *rxvq)
{
	nthw_dbs_t *p_nthw_dbs = rxvq->mp_nthw_dbs;

	if (rxvq == NULL)
		return -1;

	/* Clear UW */
	rxvq->used_struct_phys_addr = NULL;
	if (set_rx_uw_data(p_nthw_dbs, rxvq->index,
			   (uint64_t)rxvq->used_struct_phys_addr, rxvq->host_id, 0,
			   PACKED(rxvq->vq_type), 0, 0, 0) != 0)
		return -1;

	/* Disable AM */
	rxvq->am_enable = RX_AM_DISABLE;
	if (set_rx_am_data(p_nthw_dbs, rxvq->index,
			   (uint64_t)rxvq->avail_struct_phys_addr, rxvq->am_enable,
			   rxvq->host_id, PACKED(rxvq->vq_type), 0) != 0)
		return -1;

	/* Let the FPGA finish packet processing */
	if (dbs_wait_hw_queue_shutdown(rxvq, 1) != 0)
		return -1;

	/* Clear rest of AM */
	rxvq->avail_struct_phys_addr = NULL;
	rxvq->host_id = 0;
	if (set_rx_am_data(p_nthw_dbs, rxvq->index,
			   (uint64_t)rxvq->avail_struct_phys_addr, rxvq->am_enable,
			   rxvq->host_id, PACKED(rxvq->vq_type), 0) != 0)
		return -1;

	/* Clear DR */
	rxvq->desc_struct_phys_addr = NULL;
	if (set_rx_dr_data(p_nthw_dbs, rxvq->index,
			   (uint64_t)rxvq->desc_struct_phys_addr, rxvq->host_id, 0,
			   rxvq->header, PACKED(rxvq->vq_type)) != 0)
		return -1;

	/* Initialize queue */
	dbs_init_rx_queue(p_nthw_dbs, rxvq->index, 0, 0);

	/* Reset queue state */
	rxvq->usage = UNUSED;
	rxvq->mp_nthw_dbs = p_nthw_dbs;
	rxvq->index = 0;
	rxvq->queue_size = 0;

	return 0;
}

int nthw_release_rx_virt_queue(struct nthw_virt_queue *rxvq)
{
	if (rxvq == NULL || rxvq->usage != UNMANAGED)
		return -1;

	return dbs_internal_release_rx_virt_queue(rxvq);
}

int nthw_release_managed_rx_virt_queue(struct nthw_virt_queue *rxvq)
{
	if (rxvq == NULL || rxvq->usage != MANAGED)
		return -1;

	if (rxvq->p_virtual_addr) {
		free(rxvq->p_virtual_addr);
		rxvq->p_virtual_addr = NULL;
	}

	return dbs_internal_release_rx_virt_queue(rxvq);
}

static int dbs_internal_release_tx_virt_queue(struct nthw_virt_queue *txvq)
{
	nthw_dbs_t *p_nthw_dbs = txvq->mp_nthw_dbs;

	if (txvq == NULL)
		return -1;

	/* Clear UW */
	txvq->used_struct_phys_addr = NULL;
	if (set_tx_uw_data(p_nthw_dbs, txvq->index,
			   (uint64_t)txvq->used_struct_phys_addr, txvq->host_id, 0,
			   PACKED(txvq->vq_type), 0, 0, 0,
			   txvq->in_order) != 0)
		return -1;

	/* Disable AM */
	txvq->am_enable = TX_AM_DISABLE;
	if (set_tx_am_data(p_nthw_dbs, txvq->index,
			   (uint64_t)txvq->avail_struct_phys_addr, txvq->am_enable,
			   txvq->host_id, PACKED(txvq->vq_type), 0) != 0)
		return -1;

	/* Let the FPGA finish packet processing */
	if (dbs_wait_hw_queue_shutdown(txvq, 0) != 0)
		return -1;

	/* Clear rest of AM */
	txvq->avail_struct_phys_addr = NULL;
	txvq->host_id = 0;
	if (set_tx_am_data(p_nthw_dbs, txvq->index,
			   (uint64_t)txvq->avail_struct_phys_addr, txvq->am_enable,
			   txvq->host_id, PACKED(txvq->vq_type), 0) != 0)
		return -1;

	/* Clear DR */
	txvq->desc_struct_phys_addr = NULL;
	txvq->port = 0;
	txvq->header = 0;
	if (set_tx_dr_data(p_nthw_dbs, txvq->index,
			   (uint64_t)txvq->desc_struct_phys_addr, txvq->host_id, 0,
			   txvq->port, txvq->header,
			   PACKED(txvq->vq_type)) != 0)
		return -1;

	/* Clear QP */
	txvq->virtual_port = 0;
	if (nthw_dbs_set_tx_qp_data(p_nthw_dbs, txvq->index, txvq->virtual_port) !=
			0)
		return -1;

	/* Initialize queue */
	dbs_init_tx_queue(p_nthw_dbs, txvq->index, 0, 0);

	/* Reset queue state */
	txvq->usage = UNUSED;
	txvq->mp_nthw_dbs = p_nthw_dbs;
	txvq->index = 0;
	txvq->queue_size = 0;

	return 0;
}

int nthw_release_tx_virt_queue(struct nthw_virt_queue *txvq)
{
	if (txvq == NULL || txvq->usage != UNMANAGED)
		return -1;

	return dbs_internal_release_tx_virt_queue(txvq);
}

int nthw_release_managed_tx_virt_queue(struct nthw_virt_queue *txvq)
{
	if (txvq == NULL || txvq->usage != MANAGED)
		return -1;

	if (txvq->p_virtual_addr) {
		free(txvq->p_virtual_addr);
		txvq->p_virtual_addr = NULL;
	}

	return dbs_internal_release_tx_virt_queue(txvq);
}

struct nthw_virt_queue *nthw_setup_tx_virt_queue(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint16_t start_idx,
	uint16_t start_ptr, void *avail_struct_phys_addr, void *used_struct_phys_addr,
	void *desc_struct_phys_addr, uint16_t queue_size, uint32_t host_id,
	uint32_t port, uint32_t virtual_port, uint32_t header, uint32_t vq_type,
	int irq_vector, uint32_t in_order)
{
	uint32_t int_enable;
	uint32_t vec;
	uint32_t istk;
	uint32_t qs = dbs_qsize_log2(queue_size);

	/*
	 * Setup DBS module - DSF00094
	 * 3. Configure the DBS.TX_DR_DATA memory; good idea to initialize all
	 *    DBS_TX_QUEUES entries.
	 */
	if (set_tx_dr_data(p_nthw_dbs, index, (uint64_t)desc_struct_phys_addr,
			   host_id, qs, port, header, PACKED(vq_type)) != 0)
		return NULL;

	/*
	 * 4. Configure the DBS.TX_UW_DATA memory; good idea to initialize all
	 *    DBS_TX_QUEUES entries.
	 *    Notice: We always start out with interrupts disabled (by setting the
	 *            "irq_vector" argument to -1). Queues that require interrupts will have
	 *             it enabled at a later time (after we have enabled vfio interrupts in the
	 *             kernel).
	 */
	int_enable = 0;
	vec = 0;
	istk = 0;

	if (set_tx_uw_data(p_nthw_dbs, index,
			   vq_type == PACKED_RING ?
			   (uint64_t)desc_struct_phys_addr :
			   (uint64_t)used_struct_phys_addr,
			   host_id, qs, PACKED(vq_type), int_enable, vec, istk,
			   in_order) != 0)
		return NULL;

	/*
	 * 2. Configure the DBS.TX_AM_DATA memory and enable the queues you plan to use;
	 *    good idea to initialize all DBS_TX_QUEUES entries.
	 */
	if (set_tx_am_data(p_nthw_dbs, index, (uint64_t)avail_struct_phys_addr,
			   TX_AM_DISABLE, host_id, PACKED(vq_type),
			   irq_vector >= 0 ? 1 : 0) != 0)
		return NULL;

	/*
	 * 5. Initialize all TX queues (all DBS_TX_QUEUES of them) using the
	 *    DBS.TX_INIT register.
	 */
	dbs_init_tx_queue(p_nthw_dbs, index, start_idx, start_ptr);

	if (nthw_dbs_set_tx_qp_data(p_nthw_dbs, index, virtual_port) != 0)
		return NULL;

	/*
	 * 2. Configure the DBS.TX_AM_DATA memory and enable the queues you plan to use;
	 *    good idea to initialize all DBS_TX_QUEUES entries.
	 *    Notice: We do this only for queues that don't require interrupts (i.e. if
	 *            irq_vector < 0). Queues that require interrupts will have TX_AM_DATA
	 *            enabled at a later time (after we have enabled vfio interrupts in the
	 *            kernel).
	 */
	if (irq_vector < 0) {
		if (set_tx_am_data(p_nthw_dbs, index,
				   (uint64_t)avail_struct_phys_addr, TX_AM_ENABLE,
				   host_id, PACKED(vq_type),
				   irq_vector >= 0 ? 1 : 0) != 0)
			return NULL;
	}

	/* Save queue state */
	txvq[index].usage = UNMANAGED;
	txvq[index].mp_nthw_dbs = p_nthw_dbs;
	txvq[index].index = index;
	txvq[index].queue_size = queue_size;
	txvq[index].am_enable = (irq_vector < 0) ? TX_AM_ENABLE : TX_AM_DISABLE;
	txvq[index].host_id = host_id;
	txvq[index].port = port;
	txvq[index].virtual_port = virtual_port;
	txvq[index].header = header;
	txvq[index].avail_struct_phys_addr = avail_struct_phys_addr;
	txvq[index].used_struct_phys_addr = used_struct_phys_addr;
	txvq[index].desc_struct_phys_addr = desc_struct_phys_addr;
	txvq[index].vq_type = vq_type;
	txvq[index].in_order = in_order;
	txvq[index].irq_vector = irq_vector;

	/* Return queue handle */
	return &txvq[index];
}

static struct nthw_virt_queue *nthw_setup_managed_rx_virt_queue_split(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint32_t queue_size,
	uint32_t host_id, uint32_t header,
	struct nthw_memory_descriptor *p_virt_struct_area,
	struct nthw_memory_descriptor *p_packet_buffers, int irq_vector)
{
	struct virtq_struct_layout_s virtq_struct_layout =
			dbs_calc_struct_layout(queue_size);

	dbs_initialize_virt_queue_structs(p_virt_struct_area->virt_addr,
					  (char *)p_virt_struct_area->virt_addr +
					  virtq_struct_layout.used_offset,
					  (char *)p_virt_struct_area->virt_addr +
					  virtq_struct_layout.desc_offset,
					  p_packet_buffers, (uint16_t)queue_size,
					  p_packet_buffers ? (uint16_t)queue_size : 0,
					  VIRTQ_DESC_F_WRITE /* Rx */);

	rxvq[index].p_avail = p_virt_struct_area->virt_addr;
	rxvq[index].p_used = (void *)((char *)p_virt_struct_area->virt_addr +
				     virtq_struct_layout.used_offset);
	rxvq[index].p_desc = (void *)((char *)p_virt_struct_area->virt_addr +
				     virtq_struct_layout.desc_offset);

	rxvq[index].am_idx = p_packet_buffers ? (uint16_t)queue_size : 0;
	rxvq[index].used_idx = 0;
	rxvq[index].cached_idx = 0;
	rxvq[index].p_virtual_addr = NULL;

	if (p_packet_buffers) {
		rxvq[index].p_virtual_addr =
			malloc(queue_size * sizeof(*p_packet_buffers));
		memcpy(rxvq[index].p_virtual_addr, p_packet_buffers,
		       queue_size * sizeof(*p_packet_buffers));
	}

	nthw_setup_rx_virt_queue(p_nthw_dbs, index, 0, 0,
				 (void *)p_virt_struct_area->phys_addr,
				 (char *)p_virt_struct_area->phys_addr +
				 virtq_struct_layout.used_offset,
				 (char *)p_virt_struct_area->phys_addr +
				 virtq_struct_layout.desc_offset,
				 (uint16_t)queue_size, host_id, header,
				 SPLIT_RING, irq_vector);

	rxvq[index].usage = MANAGED;

	return &rxvq[index];
}

static struct nthw_virt_queue *nthw_setup_managed_tx_virt_queue_split(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint32_t queue_size,
	uint32_t host_id, uint32_t port, uint32_t virtual_port, uint32_t header,
	int irq_vector, uint32_t in_order,
	struct nthw_memory_descriptor *p_virt_struct_area,
	struct nthw_memory_descriptor *p_packet_buffers)
{
	struct virtq_struct_layout_s virtq_struct_layout =
			dbs_calc_struct_layout(queue_size);

	dbs_initialize_virt_queue_structs(p_virt_struct_area->virt_addr,
					  (char *)p_virt_struct_area->virt_addr +
					  virtq_struct_layout.used_offset,
					  (char *)p_virt_struct_area->virt_addr +
					  virtq_struct_layout.desc_offset,
					  p_packet_buffers, (uint16_t)queue_size, 0, 0 /* Tx */);

	txvq[index].p_avail = p_virt_struct_area->virt_addr;
	txvq[index].p_used = (void *)((char *)p_virt_struct_area->virt_addr +
				     virtq_struct_layout.used_offset);
	txvq[index].p_desc = (void *)((char *)p_virt_struct_area->virt_addr +
				     virtq_struct_layout.desc_offset);
	txvq[index].queue_size = (le16)queue_size;
	txvq[index].am_idx = 0;
	txvq[index].used_idx = 0;
	txvq[index].cached_idx = 0;
	txvq[index].p_virtual_addr = NULL;

	txvq[index].tx_descr_avail_idx = 0;

	if (p_packet_buffers) {
		txvq[index].p_virtual_addr =
			malloc(queue_size * sizeof(*p_packet_buffers));
		memcpy(txvq[index].p_virtual_addr, p_packet_buffers,
		       queue_size * sizeof(*p_packet_buffers));
	}

	nthw_setup_tx_virt_queue(p_nthw_dbs, index, 0, 0,
				 (void *)p_virt_struct_area->phys_addr,
				 (char *)p_virt_struct_area->phys_addr +
				 virtq_struct_layout.used_offset,
				 (char *)p_virt_struct_area->phys_addr +
				 virtq_struct_layout.desc_offset,
				 (uint16_t)queue_size, host_id, port, virtual_port,
				 header, SPLIT_RING, irq_vector, in_order);

	txvq[index].usage = MANAGED;

	return &txvq[index];
}

/*
 * Packed Ring
 */
static int nthw_setup_managed_virt_queue_packed(struct nthw_virt_queue *vq,
	struct pvirtq_struct_layout_s *pvirtq_layout,
	struct nthw_memory_descriptor *p_virt_struct_area,
	struct nthw_memory_descriptor *p_packet_buffers, ule16 flags, int rx)
{
	/* page aligned */
	assert(((uintptr_t)p_virt_struct_area->phys_addr & 0xfff) == 0);
	assert(p_packet_buffers);

	/* clean canvas */
	memset(p_virt_struct_area->virt_addr, 0,
	       sizeof(struct pvirtq_desc) * vq->queue_size +
	       sizeof(struct pvirtq_event_suppress) * 2 +
	       sizeof(int) * vq->queue_size);

	pvirtq_layout->device_event_offset =
		sizeof(struct pvirtq_desc) * vq->queue_size;
	pvirtq_layout->driver_event_offset =
		pvirtq_layout->device_event_offset +
		sizeof(struct pvirtq_event_suppress);

	vq->desc = p_virt_struct_area->virt_addr;
	vq->device_event = (void *)((uintptr_t)vq->desc +
				    pvirtq_layout->device_event_offset);
	vq->driver_event = (void *)((uintptr_t)vq->desc +
				    pvirtq_layout->driver_event_offset);

	vq->next_avail = 0;
	vq->next_used = 0;
	vq->avail_wrap_count = 1;
	vq->used_wrap_count = 1;

	/*
	 * Only possible if FPGA always delivers in-order
	 * Buffer ID used is the index in the pPacketBuffers array
	 */
	unsigned int i;
	struct pvirtq_desc *p_desc = vq->desc;

	for (i = 0; i < vq->queue_size; i++) {
		if (rx) {
			p_desc[i].addr = (uint64_t)p_packet_buffers[i].phys_addr;
			p_desc[i].len = p_packet_buffers[i].len;
		}
		p_desc[i].id = i;
		p_desc[i].flags = flags;
	}

	if (rx)
		vq->avail_wrap_count ^=
			1; /* filled up available buffers for Rx */
	else
		vq->used_wrap_count ^= 1; /* pre-fill free buffer IDs */

	if (vq->queue_size == 0)
		return -1; /* don't allocate memory with size of 0 bytes */
	vq->p_virtual_addr = malloc(vq->queue_size * sizeof(*p_packet_buffers));
	if (vq->p_virtual_addr == NULL)
		return -1;

	memcpy(vq->p_virtual_addr, p_packet_buffers,
	       vq->queue_size * sizeof(*p_packet_buffers));

	/* Not used yet by FPGA - make sure we disable */
	vq->device_event->flags = RING_EVENT_FLAGS_DISABLE;

	return 0;
}

static struct nthw_virt_queue *nthw_setup_managed_rx_virt_queue_packed(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint32_t queue_size,
	uint32_t host_id, uint32_t header,
	struct nthw_memory_descriptor *p_virt_struct_area,
	struct nthw_memory_descriptor *p_packet_buffers, int irq_vector)
{
	struct pvirtq_struct_layout_s pvirtq_layout;
	struct nthw_virt_queue *vq = &rxvq[index];
	/* Set size and setup packed vq ring */
	vq->queue_size = queue_size;
	/* Use Avail flag bit == 1 because wrap bit is initially set to 1 - and Used is inverse */
	if (nthw_setup_managed_virt_queue_packed(vq, &pvirtq_layout,
						 p_virt_struct_area, p_packet_buffers,
						 VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_AVAIL, 1) != 0)
		return NULL;

	nthw_setup_rx_virt_queue(p_nthw_dbs, index, 0x8000,
				 0, /* start wrap ring counter as 1 */
				 (void *)((uintptr_t)p_virt_struct_area->phys_addr +
					  pvirtq_layout.driver_event_offset),
				 (void *)((uintptr_t)p_virt_struct_area->phys_addr +
					  pvirtq_layout.device_event_offset),
				 p_virt_struct_area->phys_addr, (uint16_t)queue_size,
				 host_id, header, PACKED_RING, irq_vector);

	vq->usage = MANAGED;
	return vq;
}

static struct nthw_virt_queue *nthw_setup_managed_tx_virt_queue_packed(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint32_t queue_size,
	uint32_t host_id, uint32_t port, uint32_t virtual_port, uint32_t header,
	int irq_vector, uint32_t in_order,
	struct nthw_memory_descriptor *p_virt_struct_area,
	struct nthw_memory_descriptor *p_packet_buffers)
{
	struct pvirtq_struct_layout_s pvirtq_layout;
	struct nthw_virt_queue *vq = &txvq[index];
	/* Set size and setup packed vq ring */
	vq->queue_size = queue_size;
	if (nthw_setup_managed_virt_queue_packed(vq, &pvirtq_layout,
			p_virt_struct_area,
			p_packet_buffers, 0, 0) != 0)
		return NULL;

	nthw_setup_tx_virt_queue(p_nthw_dbs, index, 0x8000,
				 0, /* start wrap ring counter as 1 */
				 (void *)((uintptr_t)p_virt_struct_area->phys_addr +
					  pvirtq_layout.driver_event_offset),
				 (void *)((uintptr_t)p_virt_struct_area->phys_addr +
					  pvirtq_layout.device_event_offset),
				 p_virt_struct_area->phys_addr, (uint16_t)queue_size,
				 host_id, port, virtual_port, header, PACKED_RING,
				 irq_vector, in_order);

	vq->usage = MANAGED;
	return vq;
}

/*
 * Create a Managed Rx Virt Queue
 *
 * p_virt_struct_area - Memory that can be used for virtQueue structs
 * p_packet_buffers - Memory that can be used for packet buffers. Array must have queue_size entries
 *
 * Notice: The queue will be created with interrupts disabled.
 *   If interrupts are required, make sure to call nthw_enable_rx_virt_queue()
 *   afterwards.
 */
struct nthw_virt_queue *
nthw_setup_managed_rx_virt_queue(nthw_dbs_t *p_nthw_dbs, uint32_t index,
				 uint32_t queue_size, uint32_t host_id,
				 uint32_t header,
				 struct nthw_memory_descriptor *p_virt_struct_area,
				 struct nthw_memory_descriptor *p_packet_buffers,
				 uint32_t vq_type, int irq_vector)
{
	switch (vq_type) {
	case SPLIT_RING:
		return nthw_setup_managed_rx_virt_queue_split(p_nthw_dbs,
			index, queue_size, host_id, header,
			p_virt_struct_area, p_packet_buffers, irq_vector);
	case PACKED_RING:
		return nthw_setup_managed_rx_virt_queue_packed(p_nthw_dbs,
			index, queue_size, host_id, header,
			p_virt_struct_area, p_packet_buffers, irq_vector);
	default:
		break;
	}
	return NULL;
}

/*
 * Create a Managed Tx Virt Queue
 *
 * p_virt_struct_area - Memory that can be used for virtQueue structs
 * p_packet_buffers - Memory that can be used for packet buffers. Array must have queue_size entries
 *
 * Notice: The queue will be created with interrupts disabled.
 *   If interrupts are required, make sure to call nthw_enable_tx_virt_queue()
 *   afterwards.
 */
struct nthw_virt_queue *nthw_setup_managed_tx_virt_queue(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint32_t queue_size,
	uint32_t host_id, uint32_t port, uint32_t virtual_port, uint32_t header,
	struct nthw_memory_descriptor *p_virt_struct_area,
	struct nthw_memory_descriptor *p_packet_buffers, uint32_t vq_type,
	int irq_vector, uint32_t in_order)
{
	switch (vq_type) {
	case SPLIT_RING:
		return nthw_setup_managed_tx_virt_queue_split(p_nthw_dbs, index,
			queue_size, host_id, port, virtual_port,
			header, irq_vector, in_order, p_virt_struct_area,
			p_packet_buffers);
	case PACKED_RING:
		return nthw_setup_managed_tx_virt_queue_packed(p_nthw_dbs, index,
			queue_size, host_id, port, virtual_port,
			header, irq_vector, in_order, p_virt_struct_area,
			p_packet_buffers);
	default:
		break;
	}
	return NULL;
}

/*
 * Packed Ring helper macros
 */
#define avail_flag(vq) ((vq)->avail_wrap_count ? VIRTQ_DESC_F_AVAIL : 0)
#define used_flag_inv(vq) ((vq)->avail_wrap_count ? 0 : VIRTQ_DESC_F_USED)

#define inc_avail(_vq, _num)                               \
	do {                                             \
		__typeof__(_vq) (vq) = (_vq); \
		__typeof__(_num) (num) = (_num); \
		(vq)->next_avail += num;                   \
		if ((vq)->next_avail >= (vq)->queue_size) {   \
			(vq)->next_avail -= (vq)->queue_size; \
			(vq)->avail_wrap_count ^= 1;       \
		}                                        \
	} while (0)

#define inc_used(_vq, _num)                               \
	do {                                            \
		__typeof__(_vq) (vq) = (_vq); \
		__typeof__(_num) (num) = (_num); \
		(vq)->next_used += num;                   \
		if ((vq)->next_used >= (vq)->queue_size) {   \
			(vq)->next_used -= (vq)->queue_size; \
			(vq)->used_wrap_count ^= 1;       \
		}                                       \
	} while (0)

uint16_t nthw_get_rx_packets(struct nthw_virt_queue *rxvq, uint16_t n,
			     struct nthw_received_packets *rp, uint16_t *nb_pkts)
{
	le16 segs = 0;
	uint16_t pkts = 0;

	if (rxvq->vq_type == SPLIT_RING) {
		le16 i;
		le16 entries_ready = (le16)(rxvq->cached_idx - rxvq->used_idx);

		if (entries_ready < n) {
			/* Look for more packets */
			rxvq->cached_idx = rxvq->p_used->idx;
			entries_ready = (le16)(rxvq->cached_idx - rxvq->used_idx);
			if (entries_ready == 0) {
				*nb_pkts = 0;
				return 0;
			}

			if (n > entries_ready)
				n = entries_ready;
		}

		/* Give packets - make sure all packets are whole packets.
		 * Valid because queue_size is always 2^n
		 */
		const le16 queue_mask = (le16)(rxvq->queue_size - 1);
		const ule32 buf_len = rxvq->p_desc[0].len;

		le16 used = rxvq->used_idx;

		for (i = 0; i < n; ++i) {
			le32 id = rxvq->p_used->ring[used & queue_mask].id;

			rp[i].addr = rxvq->p_virtual_addr[id].virt_addr;
			rp[i].len = rxvq->p_used->ring[used & queue_mask].len;

			uint32_t pkt_len =
				((struct _pkt_hdr_rx *)rp[i].addr)->cap_len;

			if (pkt_len > buf_len) {
				/* segmented */
				int nbsegs = (pkt_len + buf_len - 1) / buf_len;

				if (((int)i + nbsegs) > n) {
					/* don't have enough segments - break out */
					break;
				}

				int ii;

				for (ii = 1; ii < nbsegs; ii++) {
					++i;
					id = rxvq->p_used
					     ->ring[(used + ii) &
								queue_mask]
					     .id;
					rp[i].addr =
						rxvq->p_virtual_addr[id].virt_addr;
					rp[i].len = rxvq->p_used
						    ->ring[(used + ii) &
								       queue_mask]
						    .len;
				}
				used += nbsegs;
			} else {
				++used;
			}

			pkts++;
			segs = i + 1;
		}

		rxvq->used_idx = used;
	} else if (rxvq->vq_type == PACKED_RING) {
		/* This requires in-order behavior from FPGA */
		int i;

		for (i = 0; i < n; i++) {
			struct pvirtq_desc *desc = &rxvq->desc[rxvq->next_used];

			ule16 flags = desc->flags;
			uint8_t avail = !!(flags & VIRTQ_DESC_F_AVAIL);
			uint8_t used = !!(flags & VIRTQ_DESC_F_USED);

			if (avail != rxvq->used_wrap_count ||
					used != rxvq->used_wrap_count)
				break;

			rp[pkts].addr = rxvq->p_virtual_addr[desc->id].virt_addr;
			rp[pkts].len = desc->len;
			pkts++;

			inc_used(rxvq, 1);
		}

		segs = pkts;
	}

	*nb_pkts = pkts;
	return segs;
}

/*
 * Put buffers back into Avail Ring
 */
void nthw_release_rx_packets(struct nthw_virt_queue *rxvq, le16 n)
{
	if (rxvq->vq_type == SPLIT_RING) {
		rxvq->am_idx = (le16)(rxvq->am_idx + n);
		rxvq->p_avail->idx = rxvq->am_idx;
	} else if (rxvq->vq_type == PACKED_RING) {
		int i;
		/*
		 * Defer flags update on first segment - due to serialization towards HW and
		 * when jumbo segments are added
		 */

		ule16 first_flags = VIRTQ_DESC_F_WRITE | avail_flag(rxvq) |
				    used_flag_inv(rxvq);
		struct pvirtq_desc *first_desc = &rxvq->desc[rxvq->next_avail];

		uint32_t len = rxvq->p_virtual_addr[0].len; /* all same size */

		/* Optimization point: use in-order release */

		for (i = 0; i < n; i++) {
			struct pvirtq_desc *desc =
					&rxvq->desc[rxvq->next_avail];

			desc->id = rxvq->next_avail;
			desc->addr =
				(ule64)rxvq->p_virtual_addr[desc->id].phys_addr;
			desc->len = len;
			if (i)
				desc->flags = VIRTQ_DESC_F_WRITE |
					      avail_flag(rxvq) |
					      used_flag_inv(rxvq);

			inc_avail(rxvq, 1);
		}
		rte_rmb();
		first_desc->flags = first_flags;
	}
}

#define vq_log_arg(vq, format, ...)

uint16_t nthw_get_tx_buffers(struct nthw_virt_queue *txvq, uint16_t n,
			     uint16_t *first_idx, struct nthw_cvirtq_desc *cvq,
			     struct nthw_memory_descriptor **p_virt_addr)
{
	int m = 0;
	le16 queue_mask = (le16)(txvq->queue_size -
				1); /* Valid because queue_size is always 2^n */
	*p_virt_addr = txvq->p_virtual_addr;

	if (txvq->vq_type == SPLIT_RING) {
		cvq->s = txvq->p_desc;
		cvq->vq_type = SPLIT_RING;

		*first_idx = txvq->tx_descr_avail_idx;

		le16 entries_used =
			(le16)((txvq->tx_descr_avail_idx - txvq->cached_idx) &
			       queue_mask);
		le16 entries_ready = (le16)(txvq->queue_size - 1 - entries_used);

		vq_log_arg(txvq,
			   "ask %i: descrAvail %i, cachedidx %i, used: %i, ready %i used->idx %i\n",
			   n, txvq->tx_descr_avail_idx, txvq->cached_idx, entries_used,
			   entries_ready, txvq->p_used->idx);

		if (entries_ready < n) {
			/*
			 * Look for more packets.
			 * Using the used_idx in the avail ring since they are held synchronous
			 * because of in-order
			 */
			txvq->cached_idx =
				txvq->p_avail->ring[(txvq->p_used->idx - 1) &
									  queue_mask];

			vq_log_arg(txvq,
				   "_update: get cachedidx %i (used_idx-1 %i)\n",
				   txvq->cached_idx,
				   (txvq->p_used->idx - 1) & queue_mask);
			entries_used = (le16)((txvq->tx_descr_avail_idx -
					      txvq->cached_idx) &
					     queue_mask);
			entries_ready =
				(le16)(txvq->queue_size - 1 - entries_used);
			vq_log_arg(txvq, "new used: %i, ready %i\n",
				   entries_used, entries_ready);
			if (n > entries_ready)
				n = entries_ready;
		}
	} else if (txvq->vq_type == PACKED_RING) {
		int i;

		cvq->p = txvq->desc;
		cvq->vq_type = PACKED_RING;

		if (txvq->outs.num) {
			*first_idx = txvq->outs.next;
			uint16_t num = RTE_MIN(n, txvq->outs.num);

			txvq->outs.next = (txvq->outs.next + num) & queue_mask;
			txvq->outs.num -= num;

			if (n == num)
				return n;

			m = num;
			n -= num;
		} else {
			*first_idx = txvq->next_used;
		}
		/* iterate the ring - this requires in-order behavior from FPGA */
		for (i = 0; i < n; i++) {
			struct pvirtq_desc *desc = &txvq->desc[txvq->next_used];

			ule16 flags = desc->flags;
			uint8_t avail = !!(flags & VIRTQ_DESC_F_AVAIL);
			uint8_t used = !!(flags & VIRTQ_DESC_F_USED);

			if (avail != txvq->used_wrap_count ||
					used != txvq->used_wrap_count) {
				n = i;
				break;
			}

			le16 incr = (desc->id - txvq->next_used) & queue_mask;

			i += incr;
			inc_used(txvq, incr + 1);
		}

		if (i > n) {
			int outs_num = i - n;

			txvq->outs.next = (txvq->next_used - outs_num) &
					  queue_mask;
			txvq->outs.num = outs_num;
		}

	} else {
		return 0;
	}
	return m + n;
}

void nthw_release_tx_buffers(struct nthw_virt_queue *txvq, uint16_t n,
			     uint16_t n_segs[])
{
	int i;

	if (txvq->vq_type == SPLIT_RING) {
		/* Valid because queue_size is always 2^n */
		le16 queue_mask = (le16)(txvq->queue_size - 1);

		vq_log_arg(txvq, "pkts %i, avail idx %i, start at %i\n", n,
			   txvq->am_idx, txvq->tx_descr_avail_idx);
		for (i = 0; i < n; i++) {
			int idx = txvq->am_idx & queue_mask;

			txvq->p_avail->ring[idx] = txvq->tx_descr_avail_idx;
			txvq->tx_descr_avail_idx =
				(txvq->tx_descr_avail_idx + n_segs[i]) & queue_mask;
			txvq->am_idx++;
		}
		/* Make sure the ring has been updated before HW reads index update */
		rte_mb();
		txvq->p_avail->idx = txvq->am_idx;
		vq_log_arg(txvq, "new avail idx %i, descr_idx %i\n",
			   txvq->p_avail->idx, txvq->tx_descr_avail_idx);

	} else if (txvq->vq_type == PACKED_RING) {
		/*
		 * Defer flags update on first segment - due to serialization towards HW and
		 * when jumbo segments are added
		 */

		ule16 first_flags = avail_flag(txvq) | used_flag_inv(txvq);
		struct pvirtq_desc *first_desc = &txvq->desc[txvq->next_avail];

		for (i = 0; i < n; i++) {
			struct pvirtq_desc *desc =
					&txvq->desc[txvq->next_avail];

			desc->id = txvq->next_avail;
			desc->addr =
				(ule64)txvq->p_virtual_addr[desc->id].phys_addr;

			if (i)
				/* bitwise-or here because next flags may already have been setup */
				desc->flags |= avail_flag(txvq) |
					       used_flag_inv(txvq);

			inc_avail(txvq, 1);
		}
		/* Proper read barrier before FPGA may see first flags */
		rte_rmb();
		first_desc->flags = first_flags;
	}
}

int nthw_get_rx_queue_ptr(struct nthw_virt_queue *rxvq, uint16_t *index)
{
	uint32_t rx_ptr;
	uint32_t loops = 100000;

	dbs_initialize_get_rx_ptr(rxvq->mp_nthw_dbs, rxvq->index);
	do {
		if (dbs_get_rx_ptr(rxvq->mp_nthw_dbs, &rx_ptr) != 0)
			return -1;
		if (--loops == 0)
			return -1;
		usleep(10);
	} while (rx_ptr == INDEX_PTR_NOT_VALID);

	*index = (uint16_t)(rx_ptr & 0xffff);
	return 0;
}

int nthw_get_tx_queue_ptr(struct nthw_virt_queue *txvq, uint16_t *index)
{
	uint32_t tx_ptr;
	uint32_t loops = 100000;

	dbs_initialize_get_tx_ptr(txvq->mp_nthw_dbs, txvq->index);
	do {
		if (dbs_get_tx_ptr(txvq->mp_nthw_dbs, &tx_ptr) != 0)
			return -1;
		if (--loops == 0)
			return -1;
		usleep(10);
	} while (tx_ptr == INDEX_PTR_NOT_VALID);

	*index = (uint16_t)(tx_ptr & 0xffff);
	return 0;
}
