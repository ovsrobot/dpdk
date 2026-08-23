/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Advanced Micro Devices, Inc.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include <rte_io.h>
#include <rte_eal.h>
#include <rte_pci.h>
#include <bus_pci_driver.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>
#include <rte_malloc.h>
#include <rte_memzone.h>

#include "ntb.h"
#include "ntb_hw_amd.h"

static enum amd_ntb_bar amd_ntb_bar[] = {
	AMD_NTB_BAR23,
	AMD_NTB_BAR45,
};

static int
amd_ntb_dev_init(const struct rte_rawdev *dev)
{
	struct ntb_hw *ntb = dev->dev_private;
	struct amd_ntb_hw *amd_hw;
	uint32_t sideinfo;
	int i, bar;

	if (ntb == NULL) {
		NTB_LOG(ERR, "Invalid device.");
		return -EINVAL;
	}

	amd_hw = rte_zmalloc("amd_ntb_hw", sizeof(struct amd_ntb_hw), 0);
	if (amd_hw == NULL) {
		NTB_LOG(ERR, "Failed to allocate memory for amd_ntb_hw.");
		return -ENOMEM;
	}
	ntb->pmd_private = amd_hw;

	ntb->hw_addr = (char *)ntb->pci_dev->mem_resource[0].addr;
	amd_hw->self_mmio = ntb->hw_addr;
	amd_hw->peer_mmio = (char *)amd_hw->self_mmio + AMD_PEER_OFFSET;
	amd_hw->int_mask = AMD_EVENT_INTMASK;

	/* Bit 0 of the link status register carries the topology. */
	sideinfo = rte_read32((char *)ntb->hw_addr + AMD_SIDEINFO_OFFSET);
	if (sideinfo & AMD_SIDE_MASK)
		ntb->topo = NTB_TOPO_SEC;
	else
		ntb->topo = NTB_TOPO_PRI;

	NTB_LOG(INFO, "Device topology: %s (sideinfo 0x%" PRIx32 ")",
		ntb->topo == NTB_TOPO_SEC ? "secondary" : "primary", sideinfo);

	ntb->mw_cnt = AMD_MW_COUNT;
	ntb->db_cnt = AMD_DB_COUNT;
	/* The 16-register scratchpad bank is split into two halves, so only
	 * AMD_SPAD_PER_SIDE registers are usable per side.
	 */
	ntb->spad_cnt = AMD_SPAD_PER_SIDE;

	ntb->mw_size = rte_zmalloc("ntb_mw_size",
				   ntb->mw_cnt * sizeof(uint64_t), 0);
	if (ntb->mw_size == NULL) {
		NTB_LOG(ERR, "Cannot allocate memory for mw size.");
		rte_free(amd_hw);
		ntb->pmd_private = NULL;
		return -ENOMEM;
	}
	for (i = 0; i < ntb->mw_cnt; i++) {
		bar = amd_ntb_bar[i];
		ntb->mw_size[i] = ntb->pci_dev->mem_resource[bar].len;
		NTB_LOG(INFO, "mw[%d] bar%d size 0x%" PRIx64, i, bar,
			ntb->mw_size[i]);
	}

	/* The 16-register scratchpad bank is shared between both sides, so
	 * split it into two disjoint sets to avoid clobbering: one side owns
	 * offset 0, the other offset AMD_SPAD_SET_OFFSET.
	 */
	if (ntb->topo == NTB_TOPO_PRI) {
		amd_hw->self_spad = 0;
		amd_hw->peer_spad = AMD_SPAD_SET_OFFSET;
	} else {
		amd_hw->self_spad = AMD_SPAD_SET_OFFSET;
		amd_hw->peer_spad = 0;
	}

	/* Reserve the last 2 scratchpad registers for application use. */
	for (i = 0; i < NTB_SPAD_USER_MAX_NUM; i++)
		ntb->spad_user_list[i] = ntb->spad_cnt;
	ntb->spad_user_list[0] = ntb->spad_cnt - 2;
	ntb->spad_user_list[1] = ntb->spad_cnt - 1;

	return 0;
}

static void *
amd_ntb_get_peer_mw_addr(const struct rte_rawdev *dev, int mw_idx)
{
	struct ntb_hw *ntb = dev->dev_private;

	if (mw_idx < 0 || mw_idx >= ntb->mw_cnt) {
		NTB_LOG(ERR, "Invalid memory window index (0 - %u).",
			ntb->mw_cnt - 1);
		return NULL;
	}

	return ntb->pci_dev->mem_resource[amd_ntb_bar[mw_idx]].addr;
}

static int
amd_ntb_mw_set_trans(const struct rte_rawdev *dev, int mw_idx,
		     uint64_t addr, uint64_t size)
{
	struct ntb_hw *ntb = dev->dev_private;
	struct amd_ntb_hw *amd_hw = ntb->pmd_private;
	uint32_t xlat_off, limit_off;
	uint64_t mw_size, reg_val;
	uint8_t bar;

	if (mw_idx < 0 || mw_idx >= ntb->mw_cnt) {
		NTB_LOG(ERR, "Invalid memory window index (0 - %u).",
			ntb->mw_cnt - 1);
		return -EINVAL;
	}

	bar = amd_ntb_bar[mw_idx];
	mw_size = ntb->pci_dev->mem_resource[bar].len;
	if (size > mw_size) {
		NTB_LOG(ERR, "Set translation size 0x%" PRIx64 " exceeds mw "
			"size 0x%" PRIx64, size, mw_size);
		return -EINVAL;
	}

	/*
	 * The NTB uses an outbound translation window (see AMD doc 63939):
	 * a write to a BAR window offset is forwarded to (xlat_base | offset)
	 * in the peer's memory, rather than (xlat_base + offset). This is only
	 * correct when the base has no set bits within the window's offset
	 * range, i.e. the base must be aligned to a power of two >= the window
	 * size. Otherwise offset bits collide with base bits and writes
	 * silently alias to the wrong location. The memzone is reserved with
	 * that alignment (see mw_addr_align in ntb_dev_info); reject a
	 * misaligned base early.
	 */
	if (addr & (rte_align64pow2(size) - 1)) {
		NTB_LOG(ERR, "mw%d translation base 0x%" PRIx64 " is not "
			"aligned to a power of two >= size 0x%" PRIx64
			"; window writes would alias.", mw_idx, addr, size);
		return -EINVAL;
	}

	/* Program the peer's outbound translation window (S* registers) so
	 * that peer writes into its BAR land in our local memory at 'addr'.
	 */
	if (mw_idx == 0) {
		xlat_off = AMD_BAR23_XLAT_OFFSET;
		limit_off = AMD_BAR23_LIMIT_OFFSET;
	} else {
		xlat_off = AMD_BAR45_XLAT_OFFSET;
		limit_off = AMD_BAR45_LIMIT_OFFSET;
	}

	rte_write64(addr, (char *)amd_hw->peer_mmio + xlat_off);
	reg_val = rte_read64((char *)amd_hw->peer_mmio + xlat_off);
	if (reg_val != addr) {
		NTB_LOG(ERR, "Failed to set mw%d translation.", mw_idx);
		rte_write64(0, (char *)amd_hw->peer_mmio + xlat_off);
		return -EIO;
	}

	rte_write64(size, (char *)amd_hw->peer_mmio + limit_off);
	reg_val = rte_read64((char *)amd_hw->peer_mmio + limit_off);
	if (reg_val != size) {
		NTB_LOG(ERR, "Failed to set mw%d limit.", mw_idx);
		rte_write64(0, (char *)amd_hw->peer_mmio + xlat_off);
		rte_write64(0, (char *)amd_hw->peer_mmio + limit_off);
		return -EIO;
	}

	return 0;
}

static void *
amd_ntb_ioremap(const struct rte_rawdev *dev, uint64_t addr)
{
	struct ntb_hw *ntb = dev->dev_private;
	void *mapped = NULL;
	void *base;
	int i;

	for (i = 0; i < ntb->peer_used_mws; i++) {
		if (addr >= ntb->peer_mw_base[i] &&
		    addr <= ntb->peer_mw_base[i] + ntb->mw_size[i]) {
			base = amd_ntb_get_peer_mw_addr(dev, i);
			mapped = (void *)(size_t)(addr - ntb->peer_mw_base[i] +
						  (size_t)base);
			break;
		}
	}

	return mapped;
}

/* Read link speed/width from the device's PCIe capability link status. */
static int
amd_ntb_read_pcie_link_status(struct ntb_hw *ntb, uint16_t *link_status)
{
	struct rte_pci_device *pci_dev = ntb->pci_dev;
	uint8_t pos, cap_id, next;
	uint16_t status;
	int ret;

	ret = rte_pci_read_config(pci_dev, &status, sizeof(status),
				  RTE_PCI_STATUS);
	if (ret != sizeof(status))
		return -EIO;
	if (!(status & RTE_PCI_STATUS_CAP_LIST))
		return -ENOTSUP;

	ret = rte_pci_read_config(pci_dev, &pos, sizeof(pos),
				  RTE_PCI_CAPABILITY_LIST);
	if (ret != sizeof(pos))
		return -EIO;

	while (pos) {
		ret = rte_pci_read_config(pci_dev, &cap_id, sizeof(cap_id),
					  pos);
		if (ret != sizeof(cap_id))
			return -EIO;
		ret = rte_pci_read_config(pci_dev, &next, sizeof(next),
					  pos + 1);
		if (ret != sizeof(next))
			return -EIO;
		if (cap_id == RTE_PCI_CAP_ID_EXP) {
			ret = rte_pci_read_config(pci_dev, link_status,
						  sizeof(*link_status),
						  pos + RTE_PCI_EXP_LNKSTA);
			if (ret != sizeof(*link_status))
				return -EIO;
			return 0;
		}
		pos = next;
	}

	return -ENOTSUP;
}

/* Read the PCIe link status (LNKSTA) from an arbitrary device's config space
 * exposed via sysfs. Used to query bridges that are not bound to this driver
 * (e.g. the upstream switch above a secondary-side NTB), which rte_pci_*
 * cannot access directly.
 */
static int
amd_ntb_read_lnksta_sysfs(const char *config_path, uint16_t *link_status)
{
	uint8_t pos, cap_id, next;
	uint16_t status;
	int fd, ret = -EIO;

	fd = open(config_path, O_RDONLY);
	if (fd < 0)
		return -errno;

	if (pread(fd, &status, sizeof(status), RTE_PCI_STATUS) !=
	    sizeof(status))
		goto out;
	if (!(status & RTE_PCI_STATUS_CAP_LIST))
		goto out;

	if (pread(fd, &pos, sizeof(pos), RTE_PCI_CAPABILITY_LIST) !=
	    sizeof(pos))
		goto out;

	while (pos) {
		if (pread(fd, &cap_id, sizeof(cap_id), pos) != sizeof(cap_id))
			goto out;
		if (pread(fd, &next, sizeof(next), pos + 1) != sizeof(next))
			goto out;
		if (cap_id == RTE_PCI_CAP_ID_EXP) {
			if (pread(fd, link_status, sizeof(*link_status),
				  pos + RTE_PCI_EXP_LNKSTA) ==
			    sizeof(*link_status))
				ret = 0;
			goto out;
		}
		pos = next;
	}
out:
	close(fd);
	return ret;
}

/* On the secondary side the NTB device's own PCIe link status does not reflect
 * the inter-host link. Mirror the Linux amd_ntb behaviour by walking up two
 * bridge levels (device -> downstream switch -> upstream switch) and reading
 * the upstream switch port's link status instead.
 */
static int
amd_ntb_read_upstream_link_status(struct ntb_hw *ntb, uint16_t *link_status)
{
	char path[PATH_MAX];
	char real[PATH_MAX];
	char *p;
	int i;

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%04x:%02x:%02x.%x",
		 ntb->pci_dev->addr.domain, ntb->pci_dev->addr.bus,
		 ntb->pci_dev->addr.devid, ntb->pci_dev->addr.function);

	if (realpath(path, real) == NULL)
		return -errno;

	/* Strip two trailing path components to reach the upstream switch. */
	for (i = 0; i < 2; i++) {
		p = strrchr(real, '/');
		if (p == NULL || p == real)
			return -ENOENT;
		*p = '\0';
	}

	snprintf(path, sizeof(path), "%s/config", real);
	return amd_ntb_read_lnksta_sysfs(path, link_status);
}

static int
amd_ntb_get_link_status(const struct rte_rawdev *dev)
{
	struct ntb_hw *ntb = dev->dev_private;
	struct amd_ntb_hw *amd_hw = ntb->pmd_private;
	uint16_t link_status = 0;
	uint32_t sideinfo;
	int ret;

	/* The link is usable once the peer has set its SIDE_READY bit. */
	sideinfo = rte_read32((char *)amd_hw->peer_mmio + AMD_SIDEINFO_OFFSET);
	ntb->link_status = !!(sideinfo & AMD_SIDE_READY);

	if (!ntb->link_status) {
		ntb->link_speed = NTB_SPEED_NONE;
		ntb->link_width = NTB_WIDTH_NONE;
		return 0;
	}

	/* The primary reads its own PCIe link status; the secondary must read
	 * the upstream switch port above it. If the upstream read fails, fall
	 * back to the local device so speed/width is still best-effort.
	 */
	if (ntb->topo == NTB_TOPO_SEC) {
		ret = amd_ntb_read_upstream_link_status(ntb, &link_status);
		if (ret != 0)
			ret = amd_ntb_read_pcie_link_status(ntb, &link_status);
	} else {
		ret = amd_ntb_read_pcie_link_status(ntb, &link_status);
	}

	if (ret == 0) {
		ntb->link_speed = AMD_LNK_STA_SPEED(link_status);
		ntb->link_width = AMD_LNK_STA_WIDTH(link_status);
	} else {
		NTB_LOG(WARNING, "Failed to read PCIe link status (%d).", ret);
		ntb->link_speed = NTB_SPEED_NONE;
		ntb->link_width = NTB_WIDTH_NONE;
	}

	return 0;
}

static int
amd_ntb_set_link(const struct rte_rawdev *dev, bool up)
{
	struct ntb_hw *ntb = dev->dev_private;
	struct amd_ntb_hw *amd_hw = ntb->pmd_private;
	void *mmio = amd_hw->self_mmio;
	uint32_t reg;

	reg = rte_read32((char *)mmio + AMD_SIDEINFO_OFFSET);
	if (up) {
		if (!(reg & AMD_SIDE_READY)) {
			reg |= AMD_SIDE_READY;
			rte_write32(reg, (char *)mmio + AMD_SIDEINFO_OFFSET);
		}
		reg = rte_read32((char *)mmio + AMD_CNTL_OFFSET);
		reg |= (AMD_PMM_REG_CTL | AMD_SMM_REG_CTL);
		rte_write32(reg, (char *)mmio + AMD_CNTL_OFFSET);
	} else {
		if (reg & AMD_SIDE_READY) {
			reg &= ~AMD_SIDE_READY;
			rte_write32(reg, (char *)mmio + AMD_SIDEINFO_OFFSET);
		}
		reg = rte_read32((char *)mmio + AMD_CNTL_OFFSET);
		reg &= ~(AMD_PMM_REG_CTL | AMD_SMM_REG_CTL);
		rte_write32(reg, (char *)mmio + AMD_CNTL_OFFSET);
	}

	return 0;
}

static uint32_t
amd_ntb_spad_read(const struct rte_rawdev *dev, int spad, bool peer)
{
	struct ntb_hw *ntb = dev->dev_private;
	struct amd_ntb_hw *amd_hw = ntb->pmd_private;
	uint32_t offset;

	if (spad < 0 || spad >= ntb->spad_cnt) {
		NTB_LOG(ERR, "Invalid scratchpad index.");
		return 0;
	}

	offset = peer ? amd_hw->peer_spad : amd_hw->self_spad;

	return rte_read32((char *)ntb->hw_addr + AMD_SPAD_OFFSET + offset +
			  (spad << 2));
}

static int
amd_ntb_spad_write(const struct rte_rawdev *dev, int spad,
		   bool peer, uint32_t spad_v)
{
	struct ntb_hw *ntb = dev->dev_private;
	struct amd_ntb_hw *amd_hw = ntb->pmd_private;
	uint32_t offset;

	if (spad < 0 || spad >= ntb->spad_cnt) {
		NTB_LOG(ERR, "Invalid scratchpad index.");
		return -EINVAL;
	}

	offset = peer ? amd_hw->peer_spad : amd_hw->self_spad;

	rte_write32(spad_v, (char *)ntb->hw_addr + AMD_SPAD_OFFSET + offset +
		    (spad << 2));

	return 0;
}

static uint64_t
amd_ntb_db_read(const struct rte_rawdev *dev)
{
	struct ntb_hw *ntb = dev->dev_private;
	struct amd_ntb_hw *amd_hw = ntb->pmd_private;

	return (uint64_t)rte_read16((char *)amd_hw->self_mmio +
				    AMD_DBSTAT_OFFSET);
}

static int
amd_ntb_db_clear(const struct rte_rawdev *dev, uint64_t db_bits)
{
	struct ntb_hw *ntb = dev->dev_private;
	struct amd_ntb_hw *amd_hw = ntb->pmd_private;

	rte_write16((uint16_t)db_bits, (char *)amd_hw->self_mmio +
		    AMD_DBSTAT_OFFSET);

	return 0;
}

static int
amd_ntb_db_set_mask(const struct rte_rawdev *dev, uint64_t db_mask)
{
	struct ntb_hw *ntb = dev->dev_private;
	struct amd_ntb_hw *amd_hw = ntb->pmd_private;

	if (db_mask & ~ntb->db_valid_mask)
		return -EINVAL;

	ntb->db_mask |= db_mask;
	rte_write16((uint16_t)ntb->db_mask, (char *)amd_hw->self_mmio +
		    AMD_DBMASK_OFFSET);

	return 0;
}

static int
amd_ntb_peer_db_set(const struct rte_rawdev *dev, uint8_t db_idx)
{
	struct ntb_hw *ntb = dev->dev_private;

	if (((uint64_t)1 << db_idx) & ~ntb->db_valid_mask) {
		NTB_LOG(ERR, "Invalid doorbell.");
		return -EINVAL;
	}

	rte_write16((uint16_t)1 << db_idx, (char *)ntb->hw_addr +
		    AMD_DBREQ_OFFSET);

	return 0;
}

static int
amd_ntb_vector_bind(const struct rte_rawdev *dev __rte_unused,
		    uint8_t intr __rte_unused, uint8_t msix __rte_unused)
{
	/* Each doorbell/event maps to its MSI-X vector by default. */
	return 0;
}

/* Handshake: advertises the local configuration to the peer using the
 * packed 8-register scratchpad layout, programs the peer's outbound
 * translation windows and rings doorbell 0 to signal readiness.
 */
static int
amd_dev_handshake(const struct rte_rawdev *dev)
{
	struct ntb_hw *ntb = dev->dev_private;
	uint32_t info;
	uint64_t base;
	int i, ret;

	info = (ntb->mw_cnt & 0xff) |
	       ((uint32_t)(ntb->queue_pairs & 0xff) << 8) |
	       ((uint32_t)(ntb->used_mw_num & 0xff) << 16);
	ret = amd_ntb_spad_write(dev, AMD_SPAD_CNT_INFO, 1, info);
	if (ret < 0)
		return ret;

	ret = amd_ntb_spad_write(dev, AMD_SPAD_QUEUE_SZ, 1, ntb->queue_size);
	if (ret < 0)
		return ret;

	for (i = 0; i < ntb->used_mw_num; i++) {
		/* Advertise the memzone virtual base (used by ioremap on the
		 * peer) and program the translation with the IOVA.
		 */
		base = (uint64_t)(size_t)ntb->mz[i]->addr;
		ret = amd_ntb_spad_write(dev, AMD_SPAD_MW0_BA_L + 2 * i, 1,
					 (uint32_t)base);
		if (ret < 0)
			return ret;
		ret = amd_ntb_spad_write(dev, AMD_SPAD_MW0_BA_H + 2 * i, 1,
					 (uint32_t)(base >> 32));
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < ntb->used_mw_num; i++) {
		ret = amd_ntb_mw_set_trans(dev, i, ntb->mz[i]->iova,
					   ntb->mz[i]->len);
		if (ret < 0)
			return ret;
	}

	/* Ring doorbell 0 to tell the peer the device is ready. */
	return amd_ntb_peer_db_set(dev, 0);
}

/* Peer-config read at device start. Validates the peer's queue
 * configuration and records the peer memory-window base addresses.
 */
static int
amd_read_peer_config(const struct rte_rawdev *dev)
{
	struct ntb_hw *ntb = dev->dev_private;
	uint32_t info, peer_qps, peer_qsz, lo, hi;
	int i;

	info = amd_ntb_spad_read(dev, AMD_SPAD_CNT_INFO, 0);
	peer_qps = (info >> 8) & 0xff;
	if (peer_qps != ntb->queue_pairs) {
		NTB_LOG(ERR, "Inconsistent number of queues! (local: %u peer: %u)",
			ntb->queue_pairs, peer_qps);
		return -EINVAL;
	}

	peer_qsz = amd_ntb_spad_read(dev, AMD_SPAD_QUEUE_SZ, 0);
	if (peer_qsz != ntb->queue_size) {
		NTB_LOG(ERR, "Inconsistent queue size! (local: %u peer: %u)",
			ntb->queue_size, peer_qsz);
		return -EINVAL;
	}

	ntb->peer_used_mws = (info >> 16) & 0xff;
	for (i = 0; i < ntb->peer_used_mws; i++) {
		lo = amd_ntb_spad_read(dev, AMD_SPAD_MW0_BA_L + 2 * i, 0);
		hi = amd_ntb_spad_read(dev, AMD_SPAD_MW0_BA_H + 2 * i, 0);
		ntb->peer_mw_base[i] = ((uint64_t)hi << 32) | lo;
	}

	return 0;
}

static void
amd_ntb_dev_interrupt_handler(void *param)
{
	struct rte_rawdev *dev = (struct rte_rawdev *)param;
	struct ntb_hw *ntb = dev->dev_private;
	struct amd_ntb_hw *amd_hw = ntb->pmd_private;
	uint32_t event, ack, info;
	uint64_t db_bits;
	uint32_t peer_mw_cnt;

	db_bits = amd_ntb_db_read(dev);

	/* Doorbell 0: peer device is ready. */
	if (db_bits & 1) {
		amd_ntb_db_clear(dev, 1);
		if (ntb->peer_dev_up)
			return;

		info = amd_ntb_spad_read(dev, AMD_SPAD_CNT_INFO, 0);
		peer_mw_cnt = info & 0xff;
		if (peer_mw_cnt != ntb->mw_cnt) {
			NTB_LOG(ERR, "Peer mw cnt %u != local mw cnt %u.",
				peer_mw_cnt, ntb->mw_cnt);
			return;
		}

		ntb->peer_dev_up = 1;

		/* Re-run the handshake so the device that came up second does
		 * not miss the first doorbell (scratchpad/mw programming only
		 * takes effect once both sides are up).
		 */
		if (amd_dev_handshake(dev) < 0) {
			NTB_LOG(ERR, "Handshake work failed.");
			return;
		}

		(*ntb->ntb_ops->get_link_status)(dev);
		NTB_LOG(INFO, "Peer device up. Link speed %u width %u.",
			ntb->link_speed, ntb->link_width);
		return;
	}

	/* Doorbell 1: peer device is going down. */
	if (db_bits & (1 << 1)) {
		NTB_LOG(INFO, "DB1: Peer device is down.");
		amd_ntb_db_clear(dev, (1 << 1));
		ntb->peer_dev_up = 0;
		(*ntb->ntb_ops->peer_db_set)(dev, 2);
		return;
	}

	/* Doorbell 2: peer acknowledged our device-down request. */
	if (db_bits & (1 << 2)) {
		NTB_LOG(INFO, "DB2: Peer agrees device to be down.");
		amd_ntb_db_clear(dev, (1 << 2));
		ntb->peer_dev_up = 0;
		return;
	}

	/* Any remaining doorbells. */
	if (db_bits)
		amd_ntb_db_clear(dev, db_bits);

	/* Handle link/power-management events and acknowledge the SMU. */
	event = rte_read32((char *)amd_hw->self_mmio + AMD_INTSTAT_OFFSET);
	event &= AMD_EVENT_INTMASK;
	if (event == 0)
		return;

	switch (event) {
	case AMD_PEER_FLUSH_EVENT:
		NTB_LOG(INFO, "Peer flush event.");
		break;
	case AMD_PEER_D0_EVENT:
		ack = rte_read32((char *)amd_hw->self_mmio + AMD_PMESTAT_OFFSET);
		if (ack & 0x1)
			NTB_LOG(INFO, "D0 wakeup completed for NTB.");
		/* fall through to ack the SMU */
		/* Falls through. */
	case AMD_PEER_RESET_EVENT:
	case AMD_LINK_DOWN_EVENT:
	case AMD_PEER_D3_EVENT:
	case AMD_PEER_PMETO_EVENT:
	case AMD_LINK_UP_EVENT:
		ack = rte_read32((char *)amd_hw->self_mmio + AMD_SMUACK_OFFSET);
		ack |= event;
		rte_write32(ack, (char *)amd_hw->self_mmio + AMD_SMUACK_OFFSET);
		break;
	default:
		NTB_LOG(ERR, "Unknown interrupt event 0x%" PRIx32, event);
		break;
	}
}

const struct ntb_dev_ops amd_ntb_ops = {
	.ntb_dev_init		= amd_ntb_dev_init,
	.get_peer_mw_addr	= amd_ntb_get_peer_mw_addr,
	.mw_set_trans		= amd_ntb_mw_set_trans,
	.ioremap		= amd_ntb_ioremap,
	.get_link_status	= amd_ntb_get_link_status,
	.set_link		= amd_ntb_set_link,
	.spad_read		= amd_ntb_spad_read,
	.spad_write		= amd_ntb_spad_write,
	.db_read		= amd_ntb_db_read,
	.db_clear		= amd_ntb_db_clear,
	.db_set_mask		= amd_ntb_db_set_mask,
	.peer_db_set		= amd_ntb_peer_db_set,
	.vector_bind		= amd_ntb_vector_bind,
	.interrupt_handler	= amd_ntb_dev_interrupt_handler,
	.dev_handshake		= amd_dev_handshake,
	.read_peer_config	= amd_read_peer_config,
};
