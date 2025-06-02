
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * VFIO API definition
 *
 * WARNING: CONTENTS OF THIS HEADER NEEDS TO BE MERGED INTO KERNEL'S
 * uapi/linux/vifo.h IN A FUTURE KERNEL RELEASE. UNTIL THEN IT'S TACKED
 * ON TO DPDK'S kernel/linux/uapi DIRECTORY TO PREVENT BUILD FAILURES.
 *
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _UAPIVFIO_TPH_H
#define _UAPIVFIO_TPH_H

/**
 * VFIO_DEVICE_PCI_TPH	- _IO(VFIO_TYPE, VFIO_BASE + 22)
 *
 * This command is used to control PCIe TLP Processing Hints (TPH)
 * capability in a PCIe device.
 * It supports following operations on a PCIe device with respect to TPH
 * capability.
 *
 * - Enabling/disabling TPH capability in a PCIe device.
 *
 *   Setting VFIO_DEVICE_TPH_ENABLE flag enables TPH in no-steering-tag,
 *   interrupt-vector, or device-specific mode defined in the PCIe specficiation
 *   when feature flags TPH_ST_NS_MODE, TPH_ST_IV_MODE, and TPH_ST_DS_MODE are
 *   set respectively. TPH_ST_xx_MODE macros are defined in
 *   uapi/linux/pci_regs.h.
 *
 *   VFIO_DEVICE_TPH_DISABLE disables PCIe TPH on the device.
 *
 * - Writing STs to MSI-X or ST table in a PCIe device.
 *
 *   VFIO_DEVICE_TPH_SET_ST flag set steering tags on a device at an index in
 *   MSI-X or ST-table depending on the VFIO_TPH_ST_x_MODE flag used and device
 *   capabilities. The caller can set one or more steering tags by passing an
 *   array of vfio_pci_tph_entry objects containing cpu_id, cache_level, and
 *   MSI-X/ST-table index. The caller can also set the intended memory type and
 *   the processing hint by setting VFIO_TPH_MEM_TYPE_x and VFIO_TPH_HINT_x
 *   flags, respectively.
 *
 * - Reading Steering Tags (ST) from the host platform.
 *
 *   VFIO_DEVICE_TPH_GET_ST flags returns steering tags to the caller. Caller
 *   can request one or more steering tags by passing an array of
 *   vfio_pci_tph_entry objects. Steering Tag for each request is returned via
 *   the st field in vfio_pci_tph_entry.
 */
struct vfio_pci_tph_entry {
	/* in */
	__u32 cpu_id;			/* CPU logical ID */
	__u32 cache_level;		/* Cache level. L1 D= 0, L2D = 2, ...*/
	__u8  flags;
#define VFIO_TPH_MEM_TYPE_MASK		0x1
#define VFIO_TPH_MEM_TYPE_SHIFT		0
#define VFIO_TPH_MEM_TYPE_VMEM		0   /* Request volatile memory ST */
#define VFIO_TPH_MEM_TYPE_PMEM		1   /* Request persistent memory ST */

#define VFIO_TPH_HINT_MASK		0x3
#define VFIO_TPH_HINT_SHIFT		1
#define VFIO_TPH_HINT_BIDIR		0
#define VFIO_TPH_HINT_REQSTR		(1 << VFIO_TPH_HINT_SHIFT)
#define VFIO_TPH_HINT_TARGET		(2 << VFIO_TPH_HINT_SHIFT)
#define VFIO_TPH_HINT_TARGET_PRIO	(3 << VFIO_TPH_HINT_SHIFT)
	__u8  pad0;
	__u16 index;			/* MSI-X/ST-table index to set ST */
	/* out */
	__u16 st;			/* Steering-Tag */
	__u8  ph_ignore;		/* Platform ignored the Processing */
	__u8  pad1;
};

struct vfio_pci_tph {
	__u32 argsz;			/* Size of vfio_pci_tph and info[] */
	__u32 flags;
#define VFIO_TPH_ST_MODE_MASK		0x7

#define VFIO_DEVICE_TPH_OP_SHIFT	3
#define VFIO_DEVICE_TPH_OP_MASK		(0x7 << VFIO_DEVICE_TPH_OP_SHIFT)
/* Enable TPH on device */
#define VFIO_DEVICE_TPH_ENABLE		0
/* Disable TPH on device */
#define VFIO_DEVICE_TPH_DISABLE		(1 << VFIO_DEVICE_TPH_OP_SHIFT)
/* Get steering-tags */
#define VFIO_DEVICE_TPH_GET_ST		(2 << VFIO_DEVICE_TPH_OP_SHIFT)
/* Set steering-tags */
#define VFIO_DEVICE_TPH_SET_ST		(4 << VFIO_DEVICE_TPH_OP_SHIFT)
	__u32 count;			/* Number of entries in ents[] */
	struct vfio_pci_tph_entry ents[];
#define VFIO_TPH_INFO_MAX	2048	/* Max entries in ents[] */
};

#define VFIO_DEVICE_PCI_TPH	_IO(VFIO_TYPE, VFIO_BASE + 22)

#endif /* _UAPIVFIO_TPH_H */
