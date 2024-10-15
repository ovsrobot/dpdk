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
#include <rte_pci.h>
#include <rte_common.h>

#include "zxdh_ethdev.h"
#include "zxdh_pci.h"
#include "zxdh_logs.h"
#include "zxdh_queue.h"

#define ZXDH_PMD_DEFAULT_GUEST_FEATURES   \
	(1ULL << ZXDH_NET_F_MRG_RXBUF | \
	 1ULL << ZXDH_NET_F_STATUS    | \
	 1ULL << ZXDH_NET_F_MQ        | \
	 1ULL << ZXDH_F_ANY_LAYOUT    | \
	 1ULL << ZXDH_F_VERSION_1     | \
	 1ULL << ZXDH_F_RING_PACKED   | \
	 1ULL << ZXDH_F_IN_ORDER      | \
	 1ULL << ZXDH_F_NOTIFICATION_DATA | \
	 1ULL << ZXDH_NET_F_MAC)

static void zxdh_read_dev_config(struct zxdh_hw *hw,
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

static void zxdh_write_dev_config(struct zxdh_hw *hw,
									size_t offset,
									const void *src,
									int32_t length)
{
	int32_t i = 0;
	const uint8_t *p = src;

	for (i = 0;  i < length; i++)
		rte_write8((*p++), (((uint8_t *)hw->dev_cfg) + offset + i));
}

static uint8_t zxdh_get_status(struct zxdh_hw *hw)
{
	return rte_read8(&hw->common_cfg->device_status);
}

static void zxdh_set_status(struct zxdh_hw *hw, uint8_t status)
{
	rte_write8(status, &hw->common_cfg->device_status);
}

static uint64_t zxdh_get_features(struct zxdh_hw *hw)
{
	uint32_t features_lo = 0;
	uint32_t features_hi = 0;

	rte_write32(0, &hw->common_cfg->device_feature_select);
	features_lo = rte_read32(&hw->common_cfg->device_feature);

	rte_write32(1, &hw->common_cfg->device_feature_select);
	features_hi = rte_read32(&hw->common_cfg->device_feature);

	return ((uint64_t)features_hi << 32) | features_lo;
}

static void zxdh_set_features(struct zxdh_hw *hw, uint64_t features)
{
	rte_write32(0, &hw->common_cfg->guest_feature_select);
	rte_write32(features & ((1ULL << 32) - 1), &hw->common_cfg->guest_feature);
	rte_write32(1, &hw->common_cfg->guest_feature_select);
	rte_write32(features >> 32, &hw->common_cfg->guest_feature);
}

static uint16_t zxdh_set_config_irq(struct zxdh_hw *hw, uint16_t vec)
{
	rte_write16(vec, &hw->common_cfg->msix_config);
	return rte_read16(&hw->common_cfg->msix_config);
}

static uint16_t zxdh_set_queue_irq(struct zxdh_hw *hw, struct virtqueue *vq, uint16_t vec)
{
	rte_write16(vq->vq_queue_index, &hw->common_cfg->queue_select);
	rte_write16(vec, &hw->common_cfg->queue_msix_vector);
	return rte_read16(&hw->common_cfg->queue_msix_vector);
}

static uint8_t zxdh_get_isr(struct zxdh_hw *hw)
{
	return rte_read8(hw->isr);
}

const struct zxdh_pci_ops zxdh_dev_pci_ops = {
	.read_dev_cfg   = zxdh_read_dev_config,
	.write_dev_cfg  = zxdh_write_dev_config,
	.get_status     = zxdh_get_status,
	.set_status     = zxdh_set_status,
	.get_features   = zxdh_get_features,
	.set_features   = zxdh_set_features,
	.set_queue_irq  = zxdh_set_queue_irq,
	.set_config_irq = zxdh_set_config_irq,
	.get_isr        = zxdh_get_isr,
};

uint8_t zxdh_vtpci_isr(struct zxdh_hw *hw)
{
	return VTPCI_OPS(hw)->get_isr(hw);
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
	uint8_t pos = 0;
	int32_t ret = 0;

	if (dev->mem_resource[0].addr == NULL) {
		PMD_INIT_LOG(ERR, "bar0 base addr is NULL");
		return -1;
	}

	ret = rte_pci_read_config(dev, &pos, 1, PCI_CAPABILITY_LIST);

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
		PMD_INIT_LOG(ERR, "no zxdh pci device found.");
		return -1;
	}
	return 0;
}

void zxdh_vtpci_read_dev_config(struct zxdh_hw *hw, size_t offset, void *dst, int32_t length)
{
	VTPCI_OPS(hw)->read_dev_cfg(hw, offset, dst, length);
}

int32_t zxdh_get_pci_dev_config(struct zxdh_hw *hw)
{
	uint64_t guest_features = 0;
	uint64_t nego_features = 0;
	uint32_t max_queue_pairs = 0;

	hw->host_features = zxdh_vtpci_get_features(hw);

	guest_features = (uint64_t)ZXDH_PMD_DEFAULT_GUEST_FEATURES;
	nego_features = guest_features & hw->host_features;

	hw->guest_features = nego_features;

	if (hw->guest_features & (1ULL << ZXDH_NET_F_MAC)) {
		zxdh_vtpci_read_dev_config(hw, offsetof(struct zxdh_net_config, mac),
				&hw->mac_addr, RTE_ETHER_ADDR_LEN);
	} else {
		rte_eth_random_addr(&hw->mac_addr[0]);
	}

	zxdh_vtpci_read_dev_config(hw, offsetof(struct zxdh_net_config, max_virtqueue_pairs),
			&max_queue_pairs, sizeof(max_queue_pairs));

	if (max_queue_pairs == 0)
		hw->max_queue_pairs = ZXDH_RX_QUEUES_MAX;
	else
		hw->max_queue_pairs = RTE_MIN(ZXDH_RX_QUEUES_MAX, max_queue_pairs);
	PMD_INIT_LOG(DEBUG, "set max queue pairs %d", hw->max_queue_pairs);

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
