/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#ifndef _IECM_CONTROLQ_H_
#define _IECM_CONTROLQ_H_

#ifdef __KERNEL__
#include <linux/slab.h>
#endif

#ifndef __KERNEL__
#include "iecm_osdep.h"
#include "iecm_alloc.h"
/* This is used to explicitly annotate when a switch case falls through to the
 * next case.
 */
#define fallthrough do {} while (0)
#endif
#include "iecm_controlq_api.h"

/* Maximum buffer lengths for all control queue types */
#define IECM_CTLQ_MAX_RING_SIZE 1024
#define IECM_CTLQ_MAX_BUF_LEN	4096

#define IECM_CTLQ_DESC(R, i) \
	(&(((struct iecm_ctlq_desc *)((R)->desc_ring.va))[i]))

#define IECM_CTLQ_DESC_UNUSED(R) \
	(u16)((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->ring_size) + \
	      (R)->next_to_clean - (R)->next_to_use - 1)

#ifndef __KERNEL__
/* Data type manipulation macros. */
#define IECM_HI_DWORD(x)	((u32)((((x) >> 16) >> 16) & 0xFFFFFFFF))
#define IECM_LO_DWORD(x)	((u32)((x) & 0xFFFFFFFF))
#define IECM_HI_WORD(x)		((u16)(((x) >> 16) & 0xFFFF))
#define IECM_LO_WORD(x)		((u16)((x) & 0xFFFF))

#endif
/* Control Queue default settings */
#define IECM_CTRL_SQ_CMD_TIMEOUT	250  /* msecs */

struct iecm_ctlq_desc {
	__le16	flags;
	__le16	opcode;
	__le16	datalen;	/* 0 for direct commands */
	union {
		__le16 ret_val;
		__le16 pfid_vfid;
#define IECM_CTLQ_DESC_VF_ID_S	0
#define IECM_CTLQ_DESC_VF_ID_M	(0x7FF << IECM_CTLQ_DESC_VF_ID_S)
#define IECM_CTLQ_DESC_PF_ID_S	11
#define IECM_CTLQ_DESC_PF_ID_M	(0x1F << IECM_CTLQ_DESC_PF_ID_S)
	};
	__le32 cookie_high;
	__le32 cookie_low;
	union {
		struct {
			__le32 param0;
			__le32 param1;
			__le32 param2;
			__le32 param3;
		} direct;
		struct {
			__le32 param0;
			__le32 param1;
			__le32 addr_high;
			__le32 addr_low;
		} indirect;
		u8 raw[16];
	} params;
};

/* Flags sub-structure
 * |0  |1  |2  |3  |4  |5  |6  |7  |8  |9  |10 |11 |12 |13 |14 |15 |
 * |DD |CMP|ERR|  * RSV *  |FTYPE  | *RSV* |RD |VFC|BUF|  HOST_ID  |
 */
/* command flags and offsets */
#define IECM_CTLQ_FLAG_DD_S		0
#define IECM_CTLQ_FLAG_CMP_S		1
#define IECM_CTLQ_FLAG_ERR_S		2
#define IECM_CTLQ_FLAG_FTYPE_S		6
#define IECM_CTLQ_FLAG_RD_S		10
#define IECM_CTLQ_FLAG_VFC_S		11
#define IECM_CTLQ_FLAG_BUF_S		12
#define IECM_CTLQ_FLAG_HOST_ID_S	13

#define IECM_CTLQ_FLAG_DD	BIT(IECM_CTLQ_FLAG_DD_S)	/* 0x1	  */
#define IECM_CTLQ_FLAG_CMP	BIT(IECM_CTLQ_FLAG_CMP_S)	/* 0x2	  */
#define IECM_CTLQ_FLAG_ERR	BIT(IECM_CTLQ_FLAG_ERR_S)	/* 0x4	  */
#define IECM_CTLQ_FLAG_FTYPE_VM	BIT(IECM_CTLQ_FLAG_FTYPE_S)	/* 0x40	  */
#define IECM_CTLQ_FLAG_FTYPE_PF	BIT(IECM_CTLQ_FLAG_FTYPE_S + 1)	/* 0x80   */
#define IECM_CTLQ_FLAG_RD	BIT(IECM_CTLQ_FLAG_RD_S)	/* 0x400  */
#define IECM_CTLQ_FLAG_VFC	BIT(IECM_CTLQ_FLAG_VFC_S)	/* 0x800  */
#define IECM_CTLQ_FLAG_BUF	BIT(IECM_CTLQ_FLAG_BUF_S)	/* 0x1000 */

/* Host ID is a special field that has 3b and not a 1b flag */
#define IECM_CTLQ_FLAG_HOST_ID_M MAKE_MASK(0x7000UL, IECM_CTLQ_FLAG_HOST_ID_S)

struct iecm_mbxq_desc {
	u8 pad[8];		/* CTLQ flags/opcode/len/retval fields */
	u32 chnl_opcode;	/* avoid confusion with desc->opcode */
	u32 chnl_retval;	/* ditto for desc->retval */
	u32 pf_vf_id;		/* used by CP when sending to PF */
};

enum iecm_mac_type {
	IECM_MAC_UNKNOWN = 0,
	IECM_MAC_PF,
	IECM_MAC_GENERIC
};

#define ETH_ALEN 6

struct iecm_mac_info {
	enum iecm_mac_type type;
	u8 addr[ETH_ALEN];
	u8 perm_addr[ETH_ALEN];
};

#define IECM_AQ_LINK_UP 0x1

/* PCI bus types */
enum iecm_bus_type {
	iecm_bus_type_unknown = 0,
	iecm_bus_type_pci,
	iecm_bus_type_pcix,
	iecm_bus_type_pci_express,
	iecm_bus_type_reserved
};

/* PCI bus speeds */
enum iecm_bus_speed {
	iecm_bus_speed_unknown	= 0,
	iecm_bus_speed_33	= 33,
	iecm_bus_speed_66	= 66,
	iecm_bus_speed_100	= 100,
	iecm_bus_speed_120	= 120,
	iecm_bus_speed_133	= 133,
	iecm_bus_speed_2500	= 2500,
	iecm_bus_speed_5000	= 5000,
	iecm_bus_speed_8000	= 8000,
	iecm_bus_speed_reserved
};

/* PCI bus widths */
enum iecm_bus_width {
	iecm_bus_width_unknown	= 0,
	iecm_bus_width_pcie_x1	= 1,
	iecm_bus_width_pcie_x2	= 2,
	iecm_bus_width_pcie_x4	= 4,
	iecm_bus_width_pcie_x8	= 8,
	iecm_bus_width_32	= 32,
	iecm_bus_width_64	= 64,
	iecm_bus_width_reserved
};

/* Bus parameters */
struct iecm_bus_info {
	enum iecm_bus_speed speed;
	enum iecm_bus_width width;
	enum iecm_bus_type type;

	u16 func;
	u16 device;
	u16 lan_id;
	u16 bus_id;
};

/* Function specific capabilities */
struct iecm_hw_func_caps {
	u32 num_alloc_vfs;
	u32 vf_base_id;
};

/* Define the APF hardware struct to replace other control structs as needed
 * Align to ctlq_hw_info
 */
struct iecm_hw {
	u8 *hw_addr;
	u64 hw_addr_len;
	void *back;

	/* control queue - send and receive */
	struct iecm_ctlq_info *asq;
	struct iecm_ctlq_info *arq;

	/* subsystem structs */
	struct iecm_mac_info mac;
	struct iecm_bus_info bus;
	struct iecm_hw_func_caps func_caps;

	/* pci info */
	u16 device_id;
	u16 vendor_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	u8 revision_id;
	bool adapter_stopped;

	LIST_HEAD_TYPE(list_head, iecm_ctlq_info) cq_list_head;
};

int iecm_ctlq_alloc_ring_res(struct iecm_hw *hw,
			     struct iecm_ctlq_info *cq);

void iecm_ctlq_dealloc_ring_res(struct iecm_hw *hw, struct iecm_ctlq_info *cq);

/* prototype for functions used for dynamic memory allocation */
void *iecm_alloc_dma_mem(struct iecm_hw *hw, struct iecm_dma_mem *mem,
			 u64 size);
void iecm_free_dma_mem(struct iecm_hw *hw, struct iecm_dma_mem *mem);
#endif /* _IECM_CONTROLQ_H_ */
