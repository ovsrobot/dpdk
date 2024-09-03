/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 ZTE Corporation
 */

#include <stdint.h>
#include <unistd.h>

#ifdef RTE_EXEC_ENV_LINUX
 #include <dirent.h>
 #include <fcntl.h>
#endif

#include <rte_io.h>
#include <rte_bus.h>
#include <rte_common.h>

#include "zxdh_pci.h"
#include "zxdh_logs.h"
#include "zxdh_queue.h"

/*
 * Following macros are derived from linux/pci_regs.h, however,
 * we can't simply include that header here, as there is no such
 * file for non-Linux platform.
 */
#define PCI_CAPABILITY_LIST             0x34
#define PCI_CAP_ID_VNDR                 0x09
#define PCI_CAP_ID_MSIX                 0x11

/*
 * The remaining space is defined by each driver as the per-driver
 * configuration space.
 */
#define ZXDH_PCI_CONFIG(hw)  (((hw)->use_msix == ZXDH_MSIX_ENABLED) ? 24 : 20)
#define PCI_MSIX_ENABLE 0x8000

static inline int32_t check_vq_phys_addr_ok(struct virtqueue *vq)
{
	/**
	 * Virtio PCI device ZXDH_PCI_QUEUE_PF register is 32bit,
	 * and only accepts 32 bit page frame number.
	 * Check if the allocated physical memory exceeds 16TB.
	 */
	if ((vq->vq_ring_mem + vq->vq_ring_size - 1) >> (ZXDH_PCI_QUEUE_ADDR_SHIFT + 32)) {
		PMD_INIT_LOG(ERR, "vring address shouldn't be above 16TB!");
		return 0;
	}
	return 1;
}
static inline void io_write64_twopart(uint64_t val, uint32_t *lo, uint32_t *hi)
{
	rte_write32(val & ((1ULL << 32) - 1), lo);
	rte_write32(val >> 32, hi);
}

static void modern_read_dev_config(struct zxdh_hw *hw,
								   size_t offset,
								   void *dst,
								   int32_t length)
{
	int32_t i       = 0;
	uint8_t *p      = NULL;
	uint8_t old_gen = 0;
	uint8_t new_gen = 0;

	do {
		old_gen = rte_read8(&hw->common_cfg->config_generation);

		p = dst;
		for (i = 0;  i < length; i++)
			*p++ = rte_read8((uint8_t *)hw->dev_cfg + offset + i);

		new_gen = rte_read8(&hw->common_cfg->config_generation);
	} while (old_gen != new_gen);
}

static void modern_write_dev_config(struct zxdh_hw *hw,
									size_t offset,
									const void *src,
									int32_t length)
{
	int32_t i = 0;
	const uint8_t *p = src;

	for (i = 0;  i < length; i++)
		rte_write8((*p++), (((uint8_t *)hw->dev_cfg) + offset + i));
}

static uint64_t modern_get_features(struct zxdh_hw *hw)
{
	uint32_t features_lo = 0;
	uint32_t features_hi = 0;

	rte_write32(0, &hw->common_cfg->device_feature_select);
	features_lo = rte_read32(&hw->common_cfg->device_feature);

	rte_write32(1, &hw->common_cfg->device_feature_select);
	features_hi = rte_read32(&hw->common_cfg->device_feature);

	return ((uint64_t)features_hi << 32) | features_lo;
}

static void modern_set_features(struct zxdh_hw *hw, uint64_t features)
{
	rte_write32(0, &hw->common_cfg->guest_feature_select);
	rte_write32(features & ((1ULL << 32) - 1), &hw->common_cfg->guest_feature);
	rte_write32(1, &hw->common_cfg->guest_feature_select);
	rte_write32(features >> 32, &hw->common_cfg->guest_feature);
}

static uint8_t modern_get_status(struct zxdh_hw *hw)
{
	return rte_read8(&hw->common_cfg->device_status);
}

static void modern_set_status(struct zxdh_hw *hw, uint8_t status)
{
	rte_write8(status, &hw->common_cfg->device_status);
}

static uint8_t modern_get_isr(struct zxdh_hw *hw)
{
	return rte_read8(hw->isr);
}

static uint16_t modern_set_config_irq(struct zxdh_hw *hw, uint16_t vec)
{
	rte_write16(vec, &hw->common_cfg->msix_config);
	return rte_read16(&hw->common_cfg->msix_config);
}

static uint16_t modern_set_queue_irq(struct zxdh_hw *hw, struct virtqueue *vq, uint16_t vec)
{
	rte_write16(vq->vq_queue_index, &hw->common_cfg->queue_select);
	rte_write16(vec, &hw->common_cfg->queue_msix_vector);
	return rte_read16(&hw->common_cfg->queue_msix_vector);
}

static uint16_t modern_get_queue_num(struct zxdh_hw *hw, uint16_t queue_id)
{
	rte_write16(queue_id, &hw->common_cfg->queue_select);
	return rte_read16(&hw->common_cfg->queue_size);
}

static void modern_set_queue_num(struct zxdh_hw *hw, uint16_t queue_id, uint16_t vq_size)
{
	rte_write16(queue_id, &hw->common_cfg->queue_select);
	rte_write16(vq_size, &hw->common_cfg->queue_size);
}

static int32_t modern_setup_queue(struct zxdh_hw *hw, struct virtqueue *vq)
{
	uint64_t desc_addr  = 0;
	uint64_t avail_addr = 0;
	uint64_t used_addr  = 0;
	uint16_t notify_off = 0;

	if (!check_vq_phys_addr_ok(vq))
		return -1;

	desc_addr = vq->vq_ring_mem;
	avail_addr = desc_addr + vq->vq_nentries * sizeof(struct vring_desc);
	if (vtpci_packed_queue(vq->hw)) {
		used_addr = RTE_ALIGN_CEIL((avail_addr + sizeof(struct vring_packed_desc_event)),
							ZXDH_PCI_VRING_ALIGN);
	} else {
		used_addr = RTE_ALIGN_CEIL(avail_addr + offsetof(struct vring_avail,
						ring[vq->vq_nentries]), ZXDH_PCI_VRING_ALIGN);
	}

	rte_write16(vq->vq_queue_index, &hw->common_cfg->queue_select);

	io_write64_twopart(desc_addr, &hw->common_cfg->queue_desc_lo,
					   &hw->common_cfg->queue_desc_hi);
	io_write64_twopart(avail_addr, &hw->common_cfg->queue_avail_lo,
					   &hw->common_cfg->queue_avail_hi);
	io_write64_twopart(used_addr, &hw->common_cfg->queue_used_lo,
					   &hw->common_cfg->queue_used_hi);

	notify_off = rte_read16(&hw->common_cfg->queue_notify_off); /* default 0 */
	notify_off = 0;
	vq->notify_addr = (void *)((uint8_t *)hw->notify_base +
			notify_off * hw->notify_off_multiplier);

	rte_write16(1, &hw->common_cfg->queue_enable);

	return 0;
}

static void modern_del_queue(struct zxdh_hw *hw, struct virtqueue *vq)
{
	rte_write16(vq->vq_queue_index, &hw->common_cfg->queue_select);

	io_write64_twopart(0, &hw->common_cfg->queue_desc_lo,
					   &hw->common_cfg->queue_desc_hi);
	io_write64_twopart(0, &hw->common_cfg->queue_avail_lo,
					   &hw->common_cfg->queue_avail_hi);
	io_write64_twopart(0, &hw->common_cfg->queue_used_lo,
					   &hw->common_cfg->queue_used_hi);

	rte_write16(0, &hw->common_cfg->queue_enable);
}

static void modern_notify_queue(struct zxdh_hw *hw, struct virtqueue *vq)
{
	uint32_t notify_data = 0;

	if (!vtpci_with_feature(hw, ZXDH_F_NOTIFICATION_DATA)) {
		rte_write16(vq->vq_queue_index, vq->notify_addr);
		return;
	}

	if (vtpci_with_feature(hw, ZXDH_F_RING_PACKED)) {
		/*
		 * Bit[0:15]: vq queue index
		 * Bit[16:30]: avail index
		 * Bit[31]: avail wrap counter
		 */
		notify_data = ((uint32_t)(!!(vq->vq_packed.cached_flags &
						VRING_PACKED_DESC_F_AVAIL)) << 31) |
						((uint32_t)vq->vq_avail_idx << 16) |
						vq->vq_queue_index;
	} else {
		/*
		 * Bit[0:15]: vq queue index
		 * Bit[16:31]: avail index
		 */
		notify_data = ((uint32_t)vq->vq_avail_idx << 16) | vq->vq_queue_index;
	}
	PMD_DRV_LOG(DEBUG, "queue:%d notify_data 0x%x notify_addr 0x%p",
				 vq->vq_queue_index, notify_data, vq->notify_addr);
	rte_write32(notify_data, vq->notify_addr);
}

const struct zxdh_pci_ops zxdh_modern_ops = {
	.read_dev_cfg   = modern_read_dev_config,
	.write_dev_cfg  = modern_write_dev_config,
	.get_status     = modern_get_status,
	.set_status     = modern_set_status,
	.get_features   = modern_get_features,
	.set_features   = modern_set_features,
	.get_isr        = modern_get_isr,
	.set_config_irq = modern_set_config_irq,
	.set_queue_irq  = modern_set_queue_irq,
	.get_queue_num  = modern_get_queue_num,
	.set_queue_num  = modern_set_queue_num,
	.setup_queue    = modern_setup_queue,
	.del_queue      = modern_del_queue,
	.notify_queue   = modern_notify_queue,
};

void zxdh_vtpci_read_dev_config(struct zxdh_hw *hw, size_t offset, void *dst, int32_t length)
{
	VTPCI_OPS(hw)->read_dev_cfg(hw, offset, dst, length);
}
void zxdh_vtpci_write_dev_config(struct zxdh_hw *hw, size_t offset, const void *src, int32_t length)
{
	VTPCI_OPS(hw)->write_dev_cfg(hw, offset, src, length);
}

uint16_t zxdh_vtpci_get_features(struct zxdh_hw *hw)
{
	return VTPCI_OPS(hw)->get_features(hw);
}

void zxdh_vtpci_reset(struct zxdh_hw *hw)
{
	PMD_INIT_LOG(INFO, "port %u device start reset, just wait...", hw->port_id);
	uint32_t retry = 0;

	VTPCI_OPS(hw)->set_status(hw, ZXDH_CONFIG_STATUS_RESET);
	/* Flush status write and wait device ready max 3 seconds. */
	while (VTPCI_OPS(hw)->get_status(hw) != ZXDH_CONFIG_STATUS_RESET) {
		++retry;
		usleep(1000L);
	}
	PMD_INIT_LOG(INFO, "port %u device reset %u ms done", hw->port_id, retry);
}

void zxdh_vtpci_reinit_complete(struct zxdh_hw *hw)
{
	zxdh_vtpci_set_status(hw, ZXDH_CONFIG_STATUS_DRIVER_OK);
}

void zxdh_vtpci_set_status(struct zxdh_hw *hw, uint8_t status)
{
	if (status != ZXDH_CONFIG_STATUS_RESET)
		status |= VTPCI_OPS(hw)->get_status(hw);

	VTPCI_OPS(hw)->set_status(hw, status);
}

uint8_t zxdh_vtpci_get_status(struct zxdh_hw *hw)
{
	return VTPCI_OPS(hw)->get_status(hw);
}

uint8_t zxdh_vtpci_isr(struct zxdh_hw *hw)
{
	return VTPCI_OPS(hw)->get_isr(hw);
}

static void *get_cfg_addr(struct rte_pci_device *dev, struct zxdh_pci_cap *cap)
{
	uint8_t  bar    = cap->bar;
	uint32_t length = cap->length;
	uint32_t offset = cap->offset;

	if (bar >= PCI_MAX_RESOURCE) {
		PMD_INIT_LOG(ERR, "invalid bar: %u", bar);
		return NULL;
	}
	if (offset + length < offset) {
		PMD_INIT_LOG(ERR, "offset(%u) + length(%u) overflows", offset, length);
		return NULL;
	}
	if (offset + length > dev->mem_resource[bar].len) {
		PMD_INIT_LOG(ERR, "invalid cap: overflows bar space: %u > %" PRIu64,
			offset + length, dev->mem_resource[bar].len);
		return NULL;
	}
	uint8_t *base = dev->mem_resource[bar].addr;

	if (base == NULL) {
		PMD_INIT_LOG(ERR, "bar %u base addr is NULL", bar);
		return NULL;
	}
	return base + offset;
}

int32_t zxdh_read_pci_caps(struct rte_pci_device *dev, struct zxdh_hw *hw)
{
	if (dev->mem_resource[0].addr == NULL) {
		PMD_INIT_LOG(ERR, "bar0 base addr is NULL");
		return -1;
	}
	uint8_t pos = 0;
	int32_t ret = rte_pci_read_config(dev, &pos, 1, PCI_CAPABILITY_LIST);

	if (ret != 1) {
		PMD_INIT_LOG(DEBUG, "failed to read pci capability list, ret %d", ret);
		return -1;
	}
	while (pos) {
		struct zxdh_pci_cap cap;

		ret = rte_pci_read_config(dev, &cap, 2, pos);
		if (ret != 2) {
			PMD_INIT_LOG(DEBUG, "failed to read pci cap at pos: %x ret %d", pos, ret);
			break;
		}
		if (cap.cap_vndr == PCI_CAP_ID_MSIX) {
			/**
			 * Transitional devices would also have this capability,
			 * that's why we also check if msix is enabled.
			 * 1st byte is cap ID; 2nd byte is the position of next cap;
			 * next two bytes are the flags.
			 */
			uint16_t flags = 0;

			ret = rte_pci_read_config(dev, &flags, sizeof(flags), pos + 2);
			if (ret != sizeof(flags)) {
				PMD_INIT_LOG(ERR, "failed to read pci cap at pos: %x ret %d",
					pos + 2, ret);
				break;
			}
			hw->use_msix = (flags & PCI_MSIX_ENABLE) ?
					ZXDH_MSIX_ENABLED : ZXDH_MSIX_DISABLED;
		}
		if (cap.cap_vndr != PCI_CAP_ID_VNDR) {
			PMD_INIT_LOG(DEBUG, "[%2x] skipping non VNDR cap id: %02x",
				pos, cap.cap_vndr);
			goto next;
		}
		ret = rte_pci_read_config(dev, &cap, sizeof(cap), pos);
		if (ret != sizeof(cap)) {
			PMD_INIT_LOG(ERR, "failed to read pci cap at pos: %x ret %d", pos, ret);
			break;
		}
		PMD_INIT_LOG(DEBUG, "[%2x] cfg type: %u, bar: %u, offset: %04x, len: %u",
			pos, cap.cfg_type, cap.bar, cap.offset, cap.length);
		switch (cap.cfg_type) {
		case ZXDH_PCI_CAP_COMMON_CFG:
			hw->common_cfg = get_cfg_addr(dev, &cap);
			break;
		case ZXDH_PCI_CAP_NOTIFY_CFG: {
			ret = rte_pci_read_config(dev, &hw->notify_off_multiplier,
						4, pos + sizeof(cap));
			if (ret != 4)
				PMD_INIT_LOG(ERR,
					"failed to read notify_off_multiplier, ret %d", ret);
			else
				hw->notify_base = get_cfg_addr(dev, &cap);
			break;
		}
		case ZXDH_PCI_CAP_DEVICE_CFG:
			hw->dev_cfg = get_cfg_addr(dev, &cap);
			break;
		case ZXDH_PCI_CAP_ISR_CFG:
			hw->isr = get_cfg_addr(dev, &cap);
			break;
		case ZXDH_PCI_CAP_PCI_CFG: {
			hw->pcie_id = *(uint16_t *)&cap.padding[1];
			PMD_INIT_LOG(DEBUG, "get pcie id 0x%x", hw->pcie_id);
			uint16_t pcie_id = hw->pcie_id;

			if ((pcie_id >> 11) & 0x1) /* PF */ {
				PMD_INIT_LOG(DEBUG, "EP %u PF %u",
					pcie_id >> 12, (pcie_id >> 8) & 0x7);
			} else { /* VF */
				PMD_INIT_LOG(DEBUG, "EP %u PF %u VF %u",
					pcie_id >> 12, (pcie_id >> 8) & 0x7, pcie_id & 0xff);
			}
			break;
		}
		}
next:
	pos = cap.cap_next;
	}
	if (hw->common_cfg == NULL || hw->notify_base == NULL ||
		hw->dev_cfg == NULL || hw->isr == NULL) {
		PMD_INIT_LOG(ERR, "no modern pci device found.");
		return -1;
	}
	return 0;
}

enum zxdh_msix_status zxdh_vtpci_msix_detect(struct rte_pci_device *dev)
{
	uint8_t pos = 0;
	int32_t ret = rte_pci_read_config(dev, &pos, 1, PCI_CAPABILITY_LIST);

	if (ret != 1) {
		PMD_INIT_LOG(ERR, "failed to read pci capability list, ret %d", ret);
		return ZXDH_MSIX_NONE;
	}
	while (pos) {
		uint8_t cap[2] = {0};

		ret = rte_pci_read_config(dev, cap, sizeof(cap), pos);
		if (ret != sizeof(cap)) {
			PMD_INIT_LOG(ERR, "failed to read pci cap at pos: %x ret %d", pos, ret);
			break;
		}
		if (cap[0] == PCI_CAP_ID_MSIX) {
			uint16_t flags = 0;

			ret = rte_pci_read_config(dev, &flags, sizeof(flags), pos + sizeof(cap));
			if (ret != sizeof(flags)) {
				PMD_INIT_LOG(ERR,
					"failed to read pci cap at pos: %x ret %d", pos + 2, ret);
				break;
			}
			if (flags & PCI_MSIX_ENABLE)
				return ZXDH_MSIX_ENABLED;
			else
				return ZXDH_MSIX_DISABLED;
		}
		pos = cap[1];
	}
	return ZXDH_MSIX_NONE;
	}
