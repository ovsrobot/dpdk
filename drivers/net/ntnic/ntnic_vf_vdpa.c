/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 * Copyright(c) 2023 Napatech A/S
 */

#include <unistd.h>
#include <stdint.h>

#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>

#include <linux/virtio_net.h>
#include <linux/pci_regs.h>

#include <rte_interrupts.h>
#include <eal_interrupts.h>

#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_bus_pci.h>
#include <rte_vhost.h>
#include <rte_vdpa.h>
#include <rte_vfio.h>
#include <rte_spinlock.h>
#include <rte_log.h>

#include <vhost.h>

#include "ntdrv_4ga.h"
#include "ntnic_ethdev.h"
#include "ntnic_vdpa.h"
#include "ntnic_vf_vdpa.h"
#include "ntnic_vf.h"
#include "ntnic_vfio.h"
#include "ntnic_dbsconfig.h"
#include "ntlog.h"

#define NTVF_VDPA_MAX_QUEUES (MAX_QUEUES)
#define NTVF_VDPA_MAX_INTR_VECTORS 8

#define NTVF_VDPA_SUPPORTED_PROTOCOL_FEATURES              \
	((1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK) |       \
	 (1ULL << VHOST_USER_PROTOCOL_F_BACKEND_REQ) |     \
	 (1ULL << VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD) | \
	 (1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER) |   \
	 (1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD) |       \
	 (1ULL << VHOST_USER_PROTOCOL_F_MQ))

#define NTVF_VIRTIO_NET_SUPPORTED_FEATURES                                 \
	((1ULL << VIRTIO_F_ANY_LAYOUT) | (1ULL << VIRTIO_F_VERSION_1) |    \
	 (1ULL << VHOST_F_LOG_ALL) | (1ULL << VIRTIO_NET_F_MRG_RXBUF) |    \
	 (1ULL << VIRTIO_F_IOMMU_PLATFORM) | (1ULL << VIRTIO_F_IN_ORDER) | \
	 (1ULL << VIRTIO_F_RING_PACKED) |                                  \
	 (1ULL << VIRTIO_NET_F_GUEST_ANNOUNCE) |                           \
	 (1ULL << VHOST_USER_F_PROTOCOL_FEATURES))

static int ntvf_vdpa_set_vring_state(int vid, int vring, int state);

struct vring_info {
	uint64_t desc;
	uint64_t avail;
	uint64_t used;
	uint16_t size;

	uint16_t last_avail_idx;
	uint16_t last_used_idx;

	int vq_type;
	struct nthw_virt_queue *p_vq;

	int enable;
};

struct ntvf_vdpa_hw {
	uint64_t negotiated_features;

	uint8_t nr_vring;

	struct vring_info vring[NTVF_VDPA_MAX_QUEUES * 2];
};

struct ntvf_vdpa_internal {
	struct rte_pci_device *pdev;
	struct rte_vdpa_device *vdev;

	int vfio_container_fd;
	int vfio_group_fd;
	int vfio_dev_fd;

	int vid;

	uint32_t outport;

	uint16_t max_queues;

	uint64_t features;

	struct ntvf_vdpa_hw hw;

	volatile int32_t started;
	volatile int32_t dev_attached;
	volatile int32_t running;

	rte_spinlock_t lock;

	volatile int32_t dma_mapped;
	volatile int32_t intr_enabled;
};

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define NTVF_USED_RING_LEN(size) \
	((size) * sizeof(struct vring_used_elem) + sizeof(uint16_t) * 3)

#define NTVF_MEDIATED_VRING 0x210000000000

struct internal_list {
	TAILQ_ENTRY(internal_list) next;
	struct ntvf_vdpa_internal *internal;
};

TAILQ_HEAD(internal_list_head, internal_list);

static struct internal_list_head internal_list =
	TAILQ_HEAD_INITIALIZER(internal_list);

static pthread_mutex_t internal_list_lock = PTHREAD_MUTEX_INITIALIZER;

int ntvf_vdpa_logtype;

static struct internal_list *
find_internal_resource_by_vdev(struct rte_vdpa_device *vdev)
{
	int found = 0;
	struct internal_list *list;

	NT_LOG(DBG, VDPA, "%s: vDPA dev=%p\n", __func__, vdev);

	pthread_mutex_lock(&internal_list_lock);

	TAILQ_FOREACH(list, &internal_list, next)
	{
		if (vdev == list->internal->vdev) {
			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&internal_list_lock);

	if (!found)
		return NULL;

	return list;
}

static struct internal_list *
ntvf_vdpa_find_internal_resource_by_dev(const struct rte_pci_device *pdev)
{
	int found = 0;
	struct internal_list *list;

	NT_LOG(DBG, VDPA, "%s: [%s:%u]\n", __func__, __FILE__, __LINE__);

	pthread_mutex_lock(&internal_list_lock);

	TAILQ_FOREACH(list, &internal_list, next)
	{
		if (pdev == list->internal->pdev) {
			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&internal_list_lock);

	if (!found)
		return NULL;

	return list;
}

static int ntvf_vdpa_vfio_setup(struct ntvf_vdpa_internal *internal)
{
	int vfio;

	LOG_FUNC_ENTER();

	internal->vfio_dev_fd = -1;
	internal->vfio_group_fd = -1;
	internal->vfio_container_fd = -1;

	vfio = nt_vfio_setup(internal->pdev);
	if (vfio == -1) {
		NT_LOG(ERR, VDPA, "%s: [%s:%u]\n", __func__, __FILE__, __LINE__);
		return -1;
	}
	internal->vfio_container_fd = nt_vfio_get_container_fd(vfio);
	internal->vfio_group_fd = nt_vfio_get_group_fd(vfio);
	internal->vfio_dev_fd = nt_vfio_get_dev_fd(vfio);
	return 0;
}

static int ntvf_vdpa_dma_map(struct ntvf_vdpa_internal *internal, int do_map)
{
	uint32_t i;
	int ret = 0;
	struct rte_vhost_memory *mem = NULL;
	int vf_num = nt_vfio_vf_num(internal->pdev);

	LOG_FUNC_ENTER();

	NT_LOG(DBG, VDPA, "%s: vid=%d vDPA dev=%p\n", __func__, internal->vid,
	       internal->vdev);

	if ((do_map && __atomic_load_n(&internal->dma_mapped, __ATOMIC_RELAXED)) ||
			(!do_map && !__atomic_load_n(&internal->dma_mapped, __ATOMIC_RELAXED))) {
		ret = -1;
		goto exit;
	}
	ret = rte_vhost_get_mem_table(internal->vid, &mem);
	if (ret < 0) {
		NT_LOG(ERR, VDPA, "failed to get VM memory layout.\n");
		goto exit;
	}

	for (i = 0; i < mem->nregions; i++) {
		struct rte_vhost_mem_region *reg = &mem->regions[i];

		NT_LOG(INF, VDPA,
		       "%s, region %u: HVA 0x%" PRIX64 ", GPA 0xllx, size 0x%" PRIX64 ".\n",
		       (do_map ? "DMA map" : "DMA unmap"), i,
		       reg->host_user_addr, reg->guest_phys_addr, reg->size);

		if (do_map) {
			ret = nt_vfio_dma_map_vdpa(vf_num, reg->host_user_addr,
						   reg->guest_phys_addr,
						   reg->size);
			if (ret < 0) {
				NT_LOG(ERR, VDPA, "%s: DMA map failed.\n",
				       __func__);
				goto exit;
			}
			__atomic_store_n(&internal->dma_mapped, 1, __ATOMIC_RELAXED);
		} else {
			ret = nt_vfio_dma_unmap_vdpa(vf_num,
						     reg->host_user_addr,
						     reg->guest_phys_addr,
						     reg->size);
			if (ret < 0) {
				NT_LOG(ERR, VDPA, "%s: DMA unmap failed.\n", __func__);
				goto exit;
			}
			__atomic_store_n(&internal->dma_mapped, 0, __ATOMIC_RELAXED);
		}
	}

exit:
	if (mem)
		free(mem);

	LOG_FUNC_LEAVE();
	return ret;
}

static uint64_t _hva_to_gpa(int vid, uint64_t hva)
{
	struct rte_vhost_memory *mem = NULL;
	struct rte_vhost_mem_region *reg;
	uint64_t gpa = 0;
	uint32_t i;

	if (rte_vhost_get_mem_table(vid, &mem) < 0)
		goto exit;

	for (i = 0; i < mem->nregions; i++) {
		reg = &mem->regions[i];
		if (hva >= reg->host_user_addr &&
				hva < reg->host_user_addr + reg->size) {
			gpa = hva - reg->host_user_addr + reg->guest_phys_addr;
			break;
		}
	}

exit:
	if (mem)
		free(mem);

	return gpa;
}

static int ntvf_vdpa_create_vring(struct ntvf_vdpa_internal *internal,
				  int vring)
{
	struct ntvf_vdpa_hw *hw = &internal->hw;
	struct rte_vhost_vring vq;
	int vid = internal->vid;
	uint64_t gpa;

	rte_vhost_get_vhost_vring(vid, vring, &vq);

	NT_LOG(INF, VDPA, "%s: idx=%d: vq.desc %p\n", __func__, vring, vq.desc);

	gpa = _hva_to_gpa(vid, (uint64_t)(uintptr_t)vq.desc);
	if (gpa == 0) {
		NT_LOG(ERR, VDPA,
		       "%s: idx=%d: failed to get GPA for descriptor ring: vq.desc %p\n",
		       __func__, vring, vq.desc);
		return -1;
	}
	hw->vring[vring].desc = gpa;

	gpa = _hva_to_gpa(vid, (uint64_t)(uintptr_t)vq.avail);
	if (gpa == 0) {
		NT_LOG(ERR, VDPA,
		       "%s: idx=%d: failed to get GPA for available ring\n",
		       __func__, vring);
		return -1;
	}
	hw->vring[vring].avail = gpa;

	gpa = _hva_to_gpa(vid, (uint64_t)(uintptr_t)vq.used);
	if (gpa == 0) {
		NT_LOG(ERR, VDPA, "%s: idx=%d: fail to get GPA for used ring\n",
		       __func__, vring);
		return -1;
	}

	hw->vring[vring].used = gpa;
	hw->vring[vring].size = vq.size;

	rte_vhost_get_vring_base(vid, vring, &hw->vring[vring].last_avail_idx,
				 &hw->vring[vring].last_used_idx);

	/* Prevent multiple creations */
	{
		const int index = vring;
		uint32_t hw_index = 0;
		uint32_t host_id = 0;
		const uint32_t header = 0; /* 0=VirtIO hdr, 1=NT virtio hdr */
		uint32_t vport = 0;
		uint32_t port = internal->outport;
		struct vring_info *p_vr_inf = &hw->vring[vring];
		nthw_dbs_t *p_nthw_dbs = get_pdbs_from_pci(internal->pdev->addr);

		int res = nthw_vdpa_get_queue_id_info(internal->vdev,
						      !(vring & 1), vring >> 1,
						      &hw_index, &host_id,
						      &vport);
		if (res) {
			NT_LOG(ERR, VDPA, "HW info received failed\n");
			p_vr_inf->p_vq = NULL; /* Failed to create the vring */
			return res;
		}

		if (!(vring & 1)) {
			NT_LOG(DBG, VDPA,
			       "Rx: idx %u, host_id %u, vport %u, queue %i\n",
			       hw_index, host_id, vport, vring >> 1);
		} else {
			NT_LOG(DBG, VDPA,
			       "Tx: idx %u, host_id %u, vport %u, queue %i\n",
			       hw_index, host_id, vport, vring >> 1);
		}
		NT_LOG(DBG, VDPA,
		       "%s: idx=%d: avail=%p used=%p desc=%p: %X: %d %d %d\n",
		       __func__, index, (void *)p_vr_inf->avail,
		       (void *)p_vr_inf->used, (void *)p_vr_inf->desc,
		       p_vr_inf->size, host_id, port, header);

		if ((hw->negotiated_features & (1ULL << VIRTIO_F_IN_ORDER)) ||
				(hw->negotiated_features &
				 (1ULL << VIRTIO_F_RING_PACKED))) {
			int res;

			NT_LOG(DBG, VDPA,
			       "%s: idx=%d: feature VIRTIO_F_IN_ORDER is set: 0x%016lX\n",
			       __func__, index, hw->negotiated_features);

			if (!(vring & 1)) {
				struct nthw_virt_queue *rx_vq;

				uint16_t start_idx =
					hw->vring[vring].last_avail_idx;
				uint16_t next_ptr =
					(start_idx & 0x7fff) % vq.size;

				/* disable doorbell not needed by FPGA */
				((struct pvirtq_event_suppress *)vq.used)
				->flags = RING_EVENT_FLAGS_DISABLE;
				rte_wmb();
				if (hw->negotiated_features &
						(1ULL << VIRTIO_F_RING_PACKED)) {
					NT_LOG(DBG, VDPA,
					       "Rx: hw_index %u, host_id %u, start_idx %u, header %u, vring %u, vport %u\n",
					       hw_index, host_id, start_idx,
					       header, vring, vport);
					/*  irq_vector 1,3,5... for Rx we support max 8 pr VF */
					rx_vq = nthw_setup_rx_virt_queue(p_nthw_dbs,
						hw_index, start_idx,
						next_ptr,
						(void *)p_vr_inf
						->avail, /* -> driver_event */
						(void *)p_vr_inf
						->used, /* -> device_event */
						(void *)p_vr_inf->desc,
						p_vr_inf->size, host_id, header,
						PACKED_RING,
						vring + 1);

				} else {
					rx_vq = nthw_setup_rx_virt_queue(p_nthw_dbs,
						hw_index, start_idx,
						next_ptr,
						(void *)p_vr_inf->avail,
						(void *)p_vr_inf->used,
						(void *)p_vr_inf->desc,
						p_vr_inf->size, host_id, header,
						SPLIT_RING,
						-1); /* no interrupt enabled */
				}

				p_vr_inf->p_vq = rx_vq;
				p_vr_inf->vq_type = 0;
				res = (rx_vq ? 0 : -1);
				if (res == 0)
					register_release_virtqueue_info(rx_vq,
									1, 0);

				NT_LOG(DBG, VDPA, "[%i] Rx Queue size %i\n",
				       hw_index, p_vr_inf->size);
			} else if (vring & 1) {
				/*
				 * transmit virt queue
				 */
				struct nthw_virt_queue *tx_vq;
				uint16_t start_idx =
					hw->vring[vring].last_avail_idx;
				uint16_t next_ptr;

				if (hw->negotiated_features &
						(1ULL << VIRTIO_F_RING_PACKED)) {
					next_ptr =
						(start_idx & 0x7fff) % vq.size;

					/* disable doorbell needs from FPGA */
					((struct pvirtq_event_suppress *)vq.used)
					->flags =
						RING_EVENT_FLAGS_DISABLE;
					rte_wmb();
					tx_vq = nthw_setup_tx_virt_queue(p_nthw_dbs,
						hw_index, start_idx,
						next_ptr,
						(void *)p_vr_inf->avail, /* driver_event */
						(void *)p_vr_inf->used, /* device_event */
						(void *)p_vr_inf->desc,
						p_vr_inf->size, host_id, port,
						vport, header, PACKED_RING,
						vring + 1, /* interrupt 2,4,6... */
						!!(hw->negotiated_features &
							(1ULL << VIRTIO_F_IN_ORDER)));

				} else {
					/*
					 * In Live Migration restart scenario:
					 * This only works if no jumbo packets has been send from VM
					 * on the LM source sideÑ This pointer points to the next
					 * free descr and may be pushed ahead by next flag and if
					 * so, this pointer calculation is incorrect
					 *
					 * NOTE: THEREFORE, THIS DOES NOT WORK WITH JUMBO PACKETS
					 *       SUPPORT IN VM
					 */
					next_ptr =
						(start_idx & 0x7fff) % vq.size;
					tx_vq = nthw_setup_tx_virt_queue(p_nthw_dbs,
						hw_index, start_idx,
						next_ptr,
						(void *)p_vr_inf->avail,
						(void *)p_vr_inf->used,
						(void *)p_vr_inf->desc,
						p_vr_inf->size, host_id, port,
						vport, header, SPLIT_RING,
						-1, /* no interrupt enabled */
						IN_ORDER);
				}

				p_vr_inf->p_vq = tx_vq;
				p_vr_inf->vq_type = 1;
				res = (tx_vq ? 0 : -1);
				if (res == 0)
					register_release_virtqueue_info(tx_vq,
									0, 0);

				NT_LOG(DBG, VDPA, "[%i] Tx Queue size %i\n",
				       hw_index, p_vr_inf->size);
			} else {
				NT_LOG(ERR, VDPA,
				       "%s: idx=%d: unexpected index: %d\n",
				       __func__, index, vring);
				res = -1;
			}
			if (res != 0) {
				NT_LOG(ERR, VDPA,
				       "%s: idx=%d: vring error: res=%d\n",
				       __func__, index, res);
			}

		} else {
			NT_LOG(WRN, VDPA,
			       "%s: idx=%d: for SPLIT RING: feature VIRTIO_F_IN_ORDER is *NOT* set: 0x%016lX\n",
			       __func__, index, hw->negotiated_features);
			return 0;
		}
	}

	return 0;
}

static int ntvf_vdpa_start(struct ntvf_vdpa_internal *internal)
{
	enum fpga_info_profile fpga_profile =
		get_fpga_profile_from_pci(internal->pdev->addr);
	struct ntvf_vdpa_hw *hw = &internal->hw;
	int vid;

	LOG_FUNC_ENTER();

	vid = internal->vid;
	hw->nr_vring = rte_vhost_get_vring_num(vid);
	rte_vhost_get_negotiated_features(vid, &hw->negotiated_features);

	if (fpga_profile == FPGA_INFO_PROFILE_INLINE) {
		NT_LOG(INF, VDPA, "%s: Number of VRINGs=%u\n", __func__,
		       hw->nr_vring);

		for (int i = 0; i < hw->nr_vring && i < 2; i++) {
			if (!hw->vring[i].enable) {
				ntvf_vdpa_dma_map(internal, 1);
				ntvf_vdpa_create_vring(internal, i);
				if (hw->vring[i].desc && hw->vring[i].p_vq) {
					if (hw->vring[i].vq_type == 0)
						nthw_enable_rx_virt_queue(hw->vring[i].p_vq);
					else
						nthw_enable_tx_virt_queue(hw->vring[i].p_vq);
					hw->vring[i].enable = 1;
				}
			}
		}
	} else {
		/*
		 * Initially vring 0 must be enabled/created here - it is not later
		 * enabled in vring state
		 */
		if (!hw->vring[0].enable) {
			ntvf_vdpa_dma_map(internal, 1);
			ntvf_vdpa_create_vring(internal, 0);
			hw->vring[0].enable = 1;
		}
	}

	LOG_FUNC_LEAVE();
	return 0;
}

static int ntvf_vdpa_stop(struct ntvf_vdpa_internal *internal)
{
	struct ntvf_vdpa_hw *hw = &internal->hw;
	uint64_t features;
	uint32_t i;
	int vid;
	int res;

	LOG_FUNC_ENTER();

	vid = internal->vid;

	for (i = 0; i < hw->nr_vring; i++) {
		rte_vhost_set_vring_base(vid, i, hw->vring[i].last_avail_idx,
					 hw->vring[i].last_used_idx);
	}

	rte_vhost_get_negotiated_features(vid, &features);

	for (i = 0; i < hw->nr_vring; i++) {
		struct vring_info *p_vr_inf = &hw->vring[i];

		if ((hw->negotiated_features & (1ULL << VIRTIO_F_IN_ORDER)) ||
				(hw->negotiated_features &
				 (1ULL << VIRTIO_F_RING_PACKED))) {
			NT_LOG(DBG, VDPA,
			       "%s: feature VIRTIO_F_IN_ORDER is set: 0x%016lX\n",
			       __func__, hw->negotiated_features);
			if (p_vr_inf->vq_type == 0) {
				de_register_release_virtqueue_info(p_vr_inf->p_vq);
				res = nthw_release_rx_virt_queue(p_vr_inf->p_vq);
			} else if (p_vr_inf->vq_type == 1) {
				de_register_release_virtqueue_info(p_vr_inf->p_vq);
				res = nthw_release_tx_virt_queue(p_vr_inf->p_vq);
			} else {
				NT_LOG(ERR, VDPA,
				       "%s: vring #%d: unknown type %d\n",
				       __func__, i, p_vr_inf->vq_type);
				res = -1;
			}
			if (res != 0) {
				NT_LOG(ERR, VDPA, "%s: vring #%d: res=%d\n",
				       __func__, i, res);
			}
		} else {
			NT_LOG(WRN, VDPA,
			       "%s: feature VIRTIO_F_IN_ORDER is *NOT* set: 0x%016lX\n",
			       __func__, hw->negotiated_features);
		}
		p_vr_inf->desc = 0UL;
	}

	if (RTE_VHOST_NEED_LOG(features)) {
		NT_LOG(WRN, VDPA,
		       "%s: vid %d: vhost logging feature needed - currently not supported\n",
		       __func__, vid);
	}

	LOG_FUNC_LEAVE();
	return 0;
}

#define MSIX_IRQ_SET_BUF_LEN           \
	(sizeof(struct vfio_irq_set) + \
	 sizeof(int) * NTVF_VDPA_MAX_QUEUES * 2 + 1)

static int ntvf_vdpa_enable_vfio_intr(struct ntvf_vdpa_internal *internal)
{
	int ret;
	uint32_t i, nr_vring;
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int *fd_ptr;
	struct rte_vhost_vring vring;

	if (__atomic_load_n(&internal->intr_enabled, __ATOMIC_RELAXED))
		return 0;

	LOG_FUNC_ENTER();
	vring.callfd = -1;

	nr_vring = rte_vhost_get_vring_num(internal->vid);

	NT_LOG(INF, VDPA,
	       "Enable VFIO interrupt MSI-X num rings %i on VID %i (%02x:%02x.%x)\n",
	       nr_vring, internal->vid, internal->pdev->addr.bus,
	       internal->pdev->addr.devid, internal->pdev->addr.function);

	if (nr_vring + 1 > NTVF_VDPA_MAX_INTR_VECTORS) {
		NT_LOG(WRN, VDPA,
		       "Can't enable MSI interrupts. Too many vectors requested: "
		       "%i (max: %i) only poll mode drivers will work",
		       nr_vring + 1, NTVF_VDPA_MAX_INTR_VECTORS);
		/*
		 * Return success, because polling drivers in VM still works without
		 * interrupts (i.e. DPDK PMDs)
		 */
		return 0;
	}

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = nr_vring + 1;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD |
			 VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
	irq_set->start = 0;
	fd_ptr = (int *)&irq_set->data;

	fd_ptr[RTE_INTR_VEC_ZERO_OFFSET] = internal->pdev->intr_handle->fd;

	for (i = 0; i < nr_vring; i += 2) {
		rte_vhost_get_vhost_vring(internal->vid, i, &vring);
		fd_ptr[RTE_INTR_VEC_RXTX_OFFSET + i] = vring.callfd;

		rte_vhost_get_vhost_vring(internal->vid, i + 1, &vring);
		fd_ptr[RTE_INTR_VEC_RXTX_OFFSET + i + 1] = vring.callfd;
	}

	ret = ioctl(internal->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret) {
		NT_LOG(ERR, VDPA, "Error enabling MSI-X interrupts: %s",
		       strerror(errno));
		return -1;
	}

	__atomic_store_n(&internal->intr_enabled, 1, __ATOMIC_RELAXED);

	LOG_FUNC_LEAVE();
	return 0;
}

static int ntvf_vdpa_disable_vfio_intr(struct ntvf_vdpa_internal *internal)
{
	int ret;
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int len;

	if (!__atomic_load_n(&internal->intr_enabled, __ATOMIC_RELAXED))
		return 0;
	LOG_FUNC_ENTER();

	NT_LOG(INF, VDPA, "Disable VFIO interrupt on VID %i (%02x:%02x.%x)\n",
	       internal->vid, internal->pdev->addr.bus,
	       internal->pdev->addr.devid, internal->pdev->addr.function);

	len = sizeof(struct vfio_irq_set);
	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->count = 0;
	irq_set->flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
	irq_set->start = 0;

	ret = ioctl(internal->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret) {
		NT_LOG(ERR, VDPA, "Error disabling MSI-X interrupts: %s",
		       strerror(errno));
		return -1;
	}

	__atomic_store_n(&internal->intr_enabled, 0, __ATOMIC_RELAXED);

	LOG_FUNC_LEAVE();
	return 0;
}

static int ntvf_vdpa_update_datapath(struct ntvf_vdpa_internal *internal)
{
	int ret;

	LOG_FUNC_ENTER();

	rte_spinlock_lock(&internal->lock);

	if (!__atomic_load_n(&internal->running, __ATOMIC_RELAXED) &&
			(__atomic_load_n(&internal->started, __ATOMIC_RELAXED) &&
			 __atomic_load_n(&internal->dev_attached, __ATOMIC_RELAXED))) {
		NT_LOG(DBG, VDPA, "%s: [%s:%u] start\n", __func__, __FILE__,
			       __LINE__);

		ret = ntvf_vdpa_start(internal);
		if (ret) {
			NT_LOG(ERR, VDPA, "%s: [%s:%u]\n", __func__, __FILE__,
			       __LINE__);
			goto err;
		}

		__atomic_store_n(&internal->running, 1, __ATOMIC_RELAXED);
	} else if (__atomic_load_n(&internal->running, __ATOMIC_RELAXED) &&
			(!__atomic_load_n(&internal->started, __ATOMIC_RELAXED) ||
			 !__atomic_load_n(&internal->dev_attached, __ATOMIC_RELAXED))) {
		NT_LOG(DBG, VDPA, "%s: stop\n", __func__);

		ret = ntvf_vdpa_stop(internal);
		if (ret) {
			NT_LOG(ERR, VDPA, "%s: [%s:%u]\n", __func__, __FILE__,
			       __LINE__);
			goto err;
		}

		ret = ntvf_vdpa_disable_vfio_intr(internal);
		if (ret) {
			goto err;
			NT_LOG(ERR, VDPA, "%s: [%s:%u]\n", __func__, __FILE__,
			       __LINE__);
		}

		ret = ntvf_vdpa_dma_map(internal, 0);
		if (ret) {
			NT_LOG(ERR, VDPA, "%s: [%s:%u]\n", __func__, __FILE__,
			       __LINE__);
			goto err;
		}

		__atomic_store_n(&internal->running, 0, __ATOMIC_RELAXED);
	} else {
		NT_LOG(INF, VDPA, "%s: unhandled state [%s:%u]\n", __func__,
		       __FILE__, __LINE__);
	}

	rte_spinlock_unlock(&internal->lock);
	LOG_FUNC_LEAVE();
	return 0;

err:
	rte_spinlock_unlock(&internal->lock);
	NT_LOG(ERR, VDPA, "%s: leave [%s:%u]\n", __func__, __FILE__, __LINE__);
	return ret;
}

static int ntvf_vdpa_dev_config(int vid)
{
	struct rte_vdpa_device *vdev;
	struct internal_list *list;
	struct ntvf_vdpa_internal *internal;

	LOG_FUNC_ENTER();

	vdev = rte_vhost_get_vdpa_device(vid);
	list = find_internal_resource_by_vdev(vdev);
	if (list == NULL) {
		NT_LOG(ERR, VDPA, "Invalid vDPA device: %p", vdev);
		return -1;
	}

	internal = list->internal;
	internal->vid = vid;

	__atomic_store_n(&internal->dev_attached, 1, __ATOMIC_RELAXED);

	ntvf_vdpa_update_datapath(internal);

	LOG_FUNC_LEAVE();
	return 0;
}

static int ntvf_vdpa_dev_close(int vid)
{
	struct rte_vdpa_device *vdev;
	struct internal_list *list;
	struct ntvf_vdpa_internal *internal;

	LOG_FUNC_ENTER();

	vdev = rte_vhost_get_vdpa_device(vid);
	list = find_internal_resource_by_vdev(vdev);
	if (list == NULL) {
		NT_LOG(ERR, VDPA, "Invalid vDPA device: %p", vdev);
		return -1;
	}

	internal = list->internal;

	__atomic_store_n(&internal->dev_attached, 0, __ATOMIC_RELAXED);
	ntvf_vdpa_update_datapath(internal);

	/* Invalidate the virt queue pointers */
	uint32_t i;
	struct ntvf_vdpa_hw *hw = &internal->hw;

	for (i = 0; i < hw->nr_vring; i++)
		hw->vring[i].p_vq = NULL;

	LOG_FUNC_LEAVE();
	return 0;
}

static int ntvf_vdpa_set_features(int vid)
{
	uint64_t features;
	struct rte_vdpa_device *vdev;
	struct internal_list *list;

	LOG_FUNC_ENTER();

	vdev = rte_vhost_get_vdpa_device(vid);
	list = find_internal_resource_by_vdev(vdev);
	if (list == NULL) {
		NT_LOG(ERR, VDPA, "Invalid vDPA device: %p", vdev);
		return -1;
	}

	rte_vhost_get_negotiated_features(vid, &features);
	NT_LOG(DBG, VDPA, "%s: vid %d: vDPA dev %p: features=0x%016lX\n",
	       __func__, vid, vdev, features);

	if (!RTE_VHOST_NEED_LOG(features))
		return 0;

	NT_LOG(INF, VDPA,
	       "%s: Starting Live Migration for vid=%d vDPA dev=%p\n", __func__,
	       vid, vdev);

	/* Relay core feature not present. We cannot do live migration then. */
	NT_LOG(ERR, VDPA,
	       "%s: Live Migration not possible. Relay core feature required.\n",
	       __func__);
	return -1;
}

static int ntvf_vdpa_get_vfio_group_fd(int vid)
{
	struct rte_vdpa_device *vdev;
	struct internal_list *list;

	LOG_FUNC_ENTER();

	vdev = rte_vhost_get_vdpa_device(vid);
	list = find_internal_resource_by_vdev(vdev);
	if (list == NULL) {
		NT_LOG(ERR, VDPA, "Invalid vDPA device: %p", vdev);
		return -1;
	}

	LOG_FUNC_LEAVE();
	return list->internal->vfio_group_fd;
}

static int ntvf_vdpa_get_vfio_device_fd(int vid)
{
	struct rte_vdpa_device *vdev;
	struct internal_list *list;

	LOG_FUNC_ENTER();

	vdev = rte_vhost_get_vdpa_device(vid);
	list = find_internal_resource_by_vdev(vdev);
	if (list == NULL) {
		NT_LOG(ERR, VDPA, "Invalid vDPA device: %p", vdev);
		return -1;
	}

	LOG_FUNC_LEAVE();
	return list->internal->vfio_dev_fd;
}

static int ntvf_vdpa_get_queue_num(struct rte_vdpa_device *vdev,
				   uint32_t *queue_num)
{
	struct internal_list *list;

	LOG_FUNC_ENTER();

	list = find_internal_resource_by_vdev(vdev);
	if (list == NULL) {
		NT_LOG(ERR, VDPA, "%s: Invalid device : %p\n", __func__, vdev);
		return -1;
	}
	*queue_num = list->internal->max_queues;
	NT_LOG(DBG, VDPA, "%s: vDPA dev=%p queue_num=%d\n", __func__, vdev,
	       *queue_num);

	LOG_FUNC_LEAVE();
	return 0;
}

static int ntvf_vdpa_get_vdpa_features(struct rte_vdpa_device *vdev,
				       uint64_t *features)
{
	struct internal_list *list;

	LOG_FUNC_ENTER();

	list = find_internal_resource_by_vdev(vdev);
	if (list == NULL) {
		NT_LOG(ERR, VDPA, "%s: Invalid device : %p\n", __func__, vdev);
		return -1;
	}

	if (!features) {
		NT_LOG(ERR, VDPA, "%s: vDPA dev=%p: no ptr to feature\n",
		       __func__, vdev);
		return -1;
	}

	*features = list->internal->features;
	NT_LOG(DBG, VDPA, "%s: vDPA dev=%p: features=0x%016lX\n", __func__,
	       vdev, *features);

	LOG_FUNC_LEAVE();
	return 0;
}

static int
ntvf_vdpa_get_protocol_features(struct rte_vdpa_device *vdev __rte_unused,
				uint64_t *features)
{
	LOG_FUNC_ENTER();

	if (!features) {
		NT_LOG(ERR, VDPA, "%s: vDPA dev=%p: no ptr to feature\n",
		       __func__, vdev);
		return -1;
	}

	*features = NTVF_VDPA_SUPPORTED_PROTOCOL_FEATURES;
	NT_LOG(DBG, VDPA, "%s: vDPA dev=%p: features=0x%016lX\n", __func__,
	       vdev, *features);

	LOG_FUNC_LEAVE();
	return 0;
}

static int ntvf_vdpa_configure_queue(struct ntvf_vdpa_hw *hw,
	struct ntvf_vdpa_internal *internal)
{
	int ret = 0;

	ret = ntvf_vdpa_enable_vfio_intr(internal);
	if (ret) {
		printf("ERROR - ENABLE INTERRUPT via VFIO\n");
		return ret;
	}
	/* Enable Rx and Tx for all vrings */
	for (int i = 0; i < hw->nr_vring; i++) {
		if (i & 1)
			nthw_enable_tx_virt_queue(hw->vring[i].p_vq);
		else
			nthw_enable_rx_virt_queue(hw->vring[i].p_vq);
	}
	return ret;
}
static int ntvf_vdpa_set_vring_state(int vid, int vring, int state)
{
	struct rte_vdpa_device *vdev;
	struct internal_list *list;

	struct ntvf_vdpa_internal *internal;
	struct ntvf_vdpa_hw *hw;
	int ret = 0;

	LOG_FUNC_ENTER();

	vdev = rte_vhost_get_vdpa_device(vid);
	list = find_internal_resource_by_vdev(vdev);
	if (list == NULL) {
		NT_LOG(ERR, VDPA, "Invalid vDPA device: %p", vdev);
		return -1;
	}

	internal = list->internal;
	if (vring < 0 || vring >= internal->max_queues * 2) {
		NT_LOG(ERR, VDPA, "Vring index %d not correct", vring);
		return -1;
	}

	hw = &internal->hw;
	enum fpga_info_profile fpga_profile =
		get_fpga_profile_from_pci(internal->pdev->addr);

	if (!state && hw->vring[vring].enable) {
		/* Disable vring */
		if (hw->vring[vring].desc && hw->vring[vring].p_vq) {
			if (hw->vring[vring].vq_type == 0)
				nthw_disable_rx_virt_queue(hw->vring[vring].p_vq);
			else
				nthw_disable_tx_virt_queue(hw->vring[vring].p_vq);
		}
	}

	if (state && !hw->vring[vring].enable) {
		/* Enable/Create vring */
		if (hw->vring[vring].desc && hw->vring[vring].p_vq) {
			if (hw->vring[vring].vq_type == 0)
				nthw_enable_rx_virt_queue(hw->vring[vring].p_vq);
			else
				nthw_enable_tx_virt_queue(hw->vring[vring].p_vq);
		} else {
			ntvf_vdpa_dma_map(internal, 1);
			ntvf_vdpa_create_vring(internal, vring);

			if (fpga_profile != FPGA_INFO_PROFILE_INLINE) {
				/*
				 * After last vq enable VFIO interrupt IOMMU re-mapping and enable
				 * FPGA Rx/Tx
				 */
				if (vring == hw->nr_vring - 1) {
					ret = ntvf_vdpa_configure_queue(hw, internal);
					if (ret)
						return ret;
				}
			}
		}
	}

	if (fpga_profile == FPGA_INFO_PROFILE_INLINE) {
		hw->vring[vring].enable = !!state;
		/* after last vq enable VFIO interrupt IOMMU re-mapping */
		if (hw->vring[vring].enable && vring == hw->nr_vring - 1) {
			ret = ntvf_vdpa_configure_queue(hw, internal);
			if (ret)
				return ret;
		}
	} else {
		hw->vring[vring].enable = !!state;
	}
	LOG_FUNC_LEAVE();
	return 0;
}

static struct rte_vdpa_dev_ops ntvf_vdpa_vdpa_ops = {
	.get_queue_num = ntvf_vdpa_get_queue_num,
	.get_features = ntvf_vdpa_get_vdpa_features,
	.get_protocol_features = ntvf_vdpa_get_protocol_features,
	.dev_conf = ntvf_vdpa_dev_config,
	.dev_close = ntvf_vdpa_dev_close,
	.set_vring_state = ntvf_vdpa_set_vring_state,
	.set_features = ntvf_vdpa_set_features,
	.migration_done = NULL,
	.get_vfio_group_fd = ntvf_vdpa_get_vfio_group_fd,
	.get_vfio_device_fd = ntvf_vdpa_get_vfio_device_fd,
	.get_notify_area = NULL,
};

int ntvf_vdpa_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			struct rte_pci_device *pci_dev)
{
	struct ntvf_vdpa_internal *internal = NULL;
	struct internal_list *list = NULL;
	enum fpga_info_profile fpga_profile;

	LOG_FUNC_ENTER();

	NT_LOG(INF, VDPA, "%s: [%s:%u] %04x:%02x:%02x.%x\n", __func__, __FILE__,
	       __LINE__, pci_dev->addr.domain, pci_dev->addr.bus,
	       pci_dev->addr.devid, pci_dev->addr.function);
	list = rte_zmalloc("ntvf_vdpa", sizeof(*list), 0);
	if (list == NULL) {
		NT_LOG(ERR, VDPA, "%s: [%s:%u]\n", __func__, __FILE__,
		       __LINE__);
		goto error;
	}

	internal = rte_zmalloc("ntvf_vdpa", sizeof(*internal), 0);
	if (internal == NULL) {
		NT_LOG(ERR, VDPA, "%s: [%s:%u]\n", __func__, __FILE__,
		       __LINE__);
		goto error;
	}

	internal->pdev = pci_dev;
	rte_spinlock_init(&internal->lock);

	if (ntvf_vdpa_vfio_setup(internal) < 0) {
		NT_LOG(ERR, VDPA, "%s: [%s:%u]\n", __func__, __FILE__,
		       __LINE__);
		return -1;
	}

	internal->max_queues = NTVF_VDPA_MAX_QUEUES;

	internal->features = NTVF_VIRTIO_NET_SUPPORTED_FEATURES;

	NT_LOG(DBG, VDPA, "%s: masked features=0x%016lX [%s:%u]\n", __func__,
	       internal->features, __FILE__, __LINE__);

	fpga_profile = get_fpga_profile_from_pci(internal->pdev->addr);
	if (fpga_profile == FPGA_INFO_PROFILE_VSWITCH) {
		internal->outport = 0;
	} else {
		/* VF4 output port 0, VF5 output port 1, VF6 output port 0, ....... */
		internal->outport = internal->pdev->addr.function & 1;
	}

	list->internal = internal;

	internal->vdev =
		rte_vdpa_register_device(&pci_dev->device, &ntvf_vdpa_vdpa_ops);
	NT_LOG(DBG, VDPA, "%s: vDPA dev=%p\n", __func__, internal->vdev);

	if (!internal->vdev) {
		NT_LOG(ERR, VDPA, "%s: [%s:%u] Register vDPA device failed\n",
		       __func__, __FILE__, __LINE__);
		goto error;
	}

	pthread_mutex_lock(&internal_list_lock);
	TAILQ_INSERT_TAIL(&internal_list, list, next);
	pthread_mutex_unlock(&internal_list_lock);

	__atomic_store_n(&internal->started, 1, __ATOMIC_RELAXED);

	ntvf_vdpa_update_datapath(internal);

	LOG_FUNC_LEAVE();
	return 0;

error:
	rte_free(list);
	rte_free(internal);
	return -1;
}

int ntvf_vdpa_pci_remove(struct rte_pci_device *pci_dev)
{
	struct ntvf_vdpa_internal *internal;
	struct internal_list *list;
	int vf_num = nt_vfio_vf_num(pci_dev);

	LOG_FUNC_ENTER();
	list = ntvf_vdpa_find_internal_resource_by_dev(pci_dev);
	if (list == NULL) {
		NT_LOG(ERR, VDPA, "%s: Invalid device: %s", __func__,
		       pci_dev->name);
		return -1;
	}

	internal = list->internal;
	__atomic_store_n(&internal->started, 0, __ATOMIC_RELAXED);

	ntvf_vdpa_update_datapath(internal);

	rte_pci_unmap_device(internal->pdev);
	nt_vfio_remove(vf_num);
	rte_vdpa_unregister_device(internal->vdev);

	pthread_mutex_lock(&internal_list_lock);
	TAILQ_REMOVE(&internal_list, list, next);
	pthread_mutex_unlock(&internal_list_lock);

	rte_free(list);
	rte_free(internal);

	LOG_FUNC_LEAVE();
	return 0;
}

static const struct rte_pci_id pci_id_ntvf_vdpa_map[] = {
	{
		.vendor_id = 0,
	},
};

static struct rte_pci_driver rte_ntvf_vdpa = {
	.id_table = pci_id_ntvf_vdpa_map,
	.drv_flags = 0,
	.probe = ntvf_vdpa_pci_probe,
	.remove = ntvf_vdpa_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_ntvf_vdpa, rte_ntvf_vdpa);
RTE_PMD_REGISTER_PCI_TABLE(net_ntvf_vdpa, pci_id_ntvf_vdpa_map);
RTE_PMD_REGISTER_KMOD_DEP(net_ntvf_vdpa, "* vfio-pci");

