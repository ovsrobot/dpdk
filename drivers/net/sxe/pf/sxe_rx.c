/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>
#include <rte_malloc.h>
#include <rte_atomic.h>
#include <ethdev_driver.h>
#include "sxe_ethdev.h"

#include "sxe.h"
#include "sxe_rx.h"
#include "sxe_logs.h"
#include "sxe_hw.h"
#include "sxe_queue.h"
#include "sxe_offload.h"
#include "sxe_dcb.h"
#include "sxe_queue_common.h"
#include "sxe_vf.h"
#include "sxe_errno.h"
#include "sxe_irq.h"
#include "sxe_ethdev.h"
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#include "sxe_vec_common.h"
#endif
#include "sxe_rx_common.h"

#define SXE_LRO_HDR_SIZE				128

#define SXE_PACKET_TYPE_ETHER				0x00
#define SXE_PACKET_TYPE_IPV4				0x01
#define SXE_PACKET_TYPE_IPV4_TCP			0x11
#define SXE_PACKET_TYPE_IPV4_UDP			0x21
#define SXE_PACKET_TYPE_IPV4_SCTP			0x41
#define SXE_PACKET_TYPE_IPV4_EXT			0x03
#define SXE_PACKET_TYPE_IPV4_EXT_TCP			0x13
#define SXE_PACKET_TYPE_IPV4_EXT_UDP			0x23
#define SXE_PACKET_TYPE_IPV4_EXT_SCTP			0x43
#define SXE_PACKET_TYPE_IPV6				0x04
#define SXE_PACKET_TYPE_IPV6_TCP			0x14
#define SXE_PACKET_TYPE_IPV6_UDP			0x24
#define SXE_PACKET_TYPE_IPV6_SCTP			0x44
#define SXE_PACKET_TYPE_IPV6_EXT			0x0C
#define SXE_PACKET_TYPE_IPV6_EXT_TCP			0x1C
#define SXE_PACKET_TYPE_IPV6_EXT_UDP			0x2C
#define SXE_PACKET_TYPE_IPV6_EXT_SCTP			0x4C
#define SXE_PACKET_TYPE_IPV4_IPV6			0x05
#define SXE_PACKET_TYPE_IPV4_IPV6_TCP			0x15
#define SXE_PACKET_TYPE_IPV4_IPV6_UDP			0x25
#define SXE_PACKET_TYPE_IPV4_IPV6_SCTP			0x45
#define SXE_PACKET_TYPE_IPV4_EXT_IPV6			0x07
#define SXE_PACKET_TYPE_IPV4_EXT_IPV6_TCP		0x17
#define SXE_PACKET_TYPE_IPV4_EXT_IPV6_UDP		0x27
#define SXE_PACKET_TYPE_IPV4_EXT_IPV6_SCTP		0x47
#define SXE_PACKET_TYPE_IPV4_IPV6_EXT			0x0D
#define SXE_PACKET_TYPE_IPV4_IPV6_EXT_TCP		0x1D
#define SXE_PACKET_TYPE_IPV4_IPV6_EXT_UDP		0x2D
#define SXE_PACKET_TYPE_IPV4_IPV6_EXT_SCTP		0x4D
#define SXE_PACKET_TYPE_IPV4_EXT_IPV6_EXT		0x0F
#define SXE_PACKET_TYPE_IPV4_EXT_IPV6_EXT_TCP		0x1F
#define SXE_PACKET_TYPE_IPV4_EXT_IPV6_EXT_UDP		0x2F
#define SXE_PACKET_TYPE_IPV4_EXT_IPV6_EXT_SCTP		0x4F

#define SXE_PACKET_TYPE_NVGRE				   0x00
#define SXE_PACKET_TYPE_NVGRE_IPV4			  0x01
#define SXE_PACKET_TYPE_NVGRE_IPV4_TCP		  0x11
#define SXE_PACKET_TYPE_NVGRE_IPV4_UDP		  0x21
#define SXE_PACKET_TYPE_NVGRE_IPV4_SCTP		 0x41
#define SXE_PACKET_TYPE_NVGRE_IPV4_EXT		  0x03
#define SXE_PACKET_TYPE_NVGRE_IPV4_EXT_TCP	  0x13
#define SXE_PACKET_TYPE_NVGRE_IPV4_EXT_UDP	  0x23
#define SXE_PACKET_TYPE_NVGRE_IPV4_EXT_SCTP	 0x43
#define SXE_PACKET_TYPE_NVGRE_IPV6			  0x04
#define SXE_PACKET_TYPE_NVGRE_IPV6_TCP		  0x14
#define SXE_PACKET_TYPE_NVGRE_IPV6_UDP		  0x24
#define SXE_PACKET_TYPE_NVGRE_IPV6_SCTP		 0x44
#define SXE_PACKET_TYPE_NVGRE_IPV6_EXT		  0x0C
#define SXE_PACKET_TYPE_NVGRE_IPV6_EXT_TCP	  0x1C
#define SXE_PACKET_TYPE_NVGRE_IPV6_EXT_UDP	  0x2C
#define SXE_PACKET_TYPE_NVGRE_IPV6_EXT_SCTP	 0x4C
#define SXE_PACKET_TYPE_NVGRE_IPV4_IPV6		 0x05
#define SXE_PACKET_TYPE_NVGRE_IPV4_IPV6_TCP	 0x15
#define SXE_PACKET_TYPE_NVGRE_IPV4_IPV6_UDP	 0x25
#define SXE_PACKET_TYPE_NVGRE_IPV4_IPV6_EXT	 0x0D
#define SXE_PACKET_TYPE_NVGRE_IPV4_IPV6_EXT_TCP 0x1D
#define SXE_PACKET_TYPE_NVGRE_IPV4_IPV6_EXT_UDP 0x2D

#define SXE_PACKET_TYPE_VXLAN				   0x80
#define SXE_PACKET_TYPE_VXLAN_IPV4			  0x81
#define SXE_PACKET_TYPE_VXLAN_IPV4_TCP		  0x91
#define SXE_PACKET_TYPE_VXLAN_IPV4_UDP		  0xA1
#define SXE_PACKET_TYPE_VXLAN_IPV4_SCTP		 0xC1
#define SXE_PACKET_TYPE_VXLAN_IPV4_EXT		  0x83
#define SXE_PACKET_TYPE_VXLAN_IPV4_EXT_TCP	  0x93
#define SXE_PACKET_TYPE_VXLAN_IPV4_EXT_UDP	  0xA3
#define SXE_PACKET_TYPE_VXLAN_IPV4_EXT_SCTP	 0xC3
#define SXE_PACKET_TYPE_VXLAN_IPV6			  0x84
#define SXE_PACKET_TYPE_VXLAN_IPV6_TCP		  0x94
#define SXE_PACKET_TYPE_VXLAN_IPV6_UDP		  0xA4
#define SXE_PACKET_TYPE_VXLAN_IPV6_SCTP		 0xC4
#define SXE_PACKET_TYPE_VXLAN_IPV6_EXT		  0x8C
#define SXE_PACKET_TYPE_VXLAN_IPV6_EXT_TCP	  0x9C
#define SXE_PACKET_TYPE_VXLAN_IPV6_EXT_UDP	  0xAC
#define SXE_PACKET_TYPE_VXLAN_IPV6_EXT_SCTP	 0xCC
#define SXE_PACKET_TYPE_VXLAN_IPV4_IPV6		 0x85
#define SXE_PACKET_TYPE_VXLAN_IPV4_IPV6_TCP	 0x95
#define SXE_PACKET_TYPE_VXLAN_IPV4_IPV6_UDP	 0xA5
#define SXE_PACKET_TYPE_VXLAN_IPV4_IPV6_EXT	 0x8D
#define SXE_PACKET_TYPE_VXLAN_IPV4_IPV6_EXT_TCP 0x9D
#define SXE_PACKET_TYPE_VXLAN_IPV4_IPV6_EXT_UDP 0xAD


const alignas(RTE_CACHE_LINE_SIZE) u32 sxe_ptype_table[SXE_PACKET_TYPE_MAX] = {
	[SXE_PACKET_TYPE_ETHER] = RTE_PTYPE_L2_ETHER,
	[SXE_PACKET_TYPE_IPV4] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4,
	[SXE_PACKET_TYPE_IPV4_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP,
	[SXE_PACKET_TYPE_IPV4_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP,
	[SXE_PACKET_TYPE_IPV4_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_SCTP,
	[SXE_PACKET_TYPE_IPV4_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT,
	[SXE_PACKET_TYPE_IPV4_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_TCP,
	[SXE_PACKET_TYPE_IPV4_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_UDP,
	[SXE_PACKET_TYPE_IPV4_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_SCTP,
	[SXE_PACKET_TYPE_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6,
	[SXE_PACKET_TYPE_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP,
	[SXE_PACKET_TYPE_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP,
	[SXE_PACKET_TYPE_IPV6_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_SCTP,
	[SXE_PACKET_TYPE_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6_EXT,
	[SXE_PACKET_TYPE_IPV6_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_TCP,
	[SXE_PACKET_TYPE_IPV6_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_UDP,
	[SXE_PACKET_TYPE_IPV6_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_SCTP,
	[SXE_PACKET_TYPE_IPV4_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6,
	[SXE_PACKET_TYPE_IPV4_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_IPV4_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
	RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_UDP,
	[SXE_PACKET_TYPE_IPV4_IPV6_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_IPV4_EXT_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6,
	[SXE_PACKET_TYPE_IPV4_EXT_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_IPV4_EXT_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_UDP,
	[SXE_PACKET_TYPE_IPV4_EXT_IPV6_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_IPV4_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT,
	[SXE_PACKET_TYPE_IPV4_IPV6_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_IPV4_IPV6_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_UDP,
	[SXE_PACKET_TYPE_IPV4_IPV6_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_IPV4_EXT_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT,
	[SXE_PACKET_TYPE_IPV4_EXT_IPV6_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_IPV4_EXT_IPV6_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_UDP,
	[SXE_PACKET_TYPE_IPV4_EXT_IPV6_EXT_SCTP] =
		RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_SCTP,
};


const alignas(RTE_CACHE_LINE_SIZE) u32 sxe_ptype_table_tn[SXE_PACKET_TYPE_TN_MAX] = {

	[SXE_PACKET_TYPE_NVGRE] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER,
	[SXE_PACKET_TYPE_NVGRE_IPV4] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_NVGRE_IPV4_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4_EXT,
	[SXE_PACKET_TYPE_NVGRE_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6,
	[SXE_PACKET_TYPE_NVGRE_IPV4_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_NVGRE_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6_EXT,
	[SXE_PACKET_TYPE_NVGRE_IPV4_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_NVGRE_IPV4_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4 |
		RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_NVGRE_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6 |
		RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_NVGRE_IPV4_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_NVGRE_IPV6_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6_EXT |
		RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_NVGRE_IPV4_IPV6_EXT_TCP] =
		RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_GRE | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_NVGRE_IPV4_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4 |
		RTE_PTYPE_INNER_L4_UDP,
	[SXE_PACKET_TYPE_NVGRE_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6 |
		RTE_PTYPE_INNER_L4_UDP,
	[SXE_PACKET_TYPE_NVGRE_IPV6_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6 |
		RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_NVGRE_IPV4_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_NVGRE_IPV6_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6_EXT |
		RTE_PTYPE_INNER_L4_UDP,
	[SXE_PACKET_TYPE_NVGRE_IPV6_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6_EXT |
		RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_NVGRE_IPV4_IPV6_EXT_UDP] =
		RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_GRE | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_NVGRE_IPV4_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4 |
		RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_NVGRE_IPV4_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4_EXT |
		RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_NVGRE_IPV4_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4_EXT |
		RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_NVGRE_IPV4_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4_EXT |
		RTE_PTYPE_INNER_L4_UDP,

	[SXE_PACKET_TYPE_VXLAN] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER,
	[SXE_PACKET_TYPE_VXLAN_IPV4] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_VXLAN_IPV4_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4_EXT,
	[SXE_PACKET_TYPE_VXLAN_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6,
	[SXE_PACKET_TYPE_VXLAN_IPV4_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_VXLAN_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6_EXT,
	[SXE_PACKET_TYPE_VXLAN_IPV4_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_VXLAN_IPV4_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4 | RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_VXLAN_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_VXLAN_IPV4_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_VXLAN_IPV6_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_VXLAN_IPV4_IPV6_EXT_TCP] =
		RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_VXLAN |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_VXLAN_IPV4_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4 | RTE_PTYPE_INNER_L4_UDP,
	[SXE_PACKET_TYPE_VXLAN_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_UDP,
	[SXE_PACKET_TYPE_VXLAN_IPV6_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_VXLAN_IPV4_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_VXLAN_IPV6_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_UDP,
	[SXE_PACKET_TYPE_VXLAN_IPV6_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_VXLAN_IPV4_IPV6_EXT_UDP] =
		RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_VXLAN |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[SXE_PACKET_TYPE_VXLAN_IPV4_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4 | RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_VXLAN_IPV4_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4_EXT | RTE_PTYPE_INNER_L4_SCTP,
	[SXE_PACKET_TYPE_VXLAN_IPV4_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4_EXT | RTE_PTYPE_INNER_L4_TCP,
	[SXE_PACKET_TYPE_VXLAN_IPV4_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4_EXT | RTE_PTYPE_INNER_L4_UDP,
};

void sxe_rx_mbuf_common_header_fill(sxe_rx_queue_s *rxq,
					struct rte_mbuf *mbuf,
					volatile union sxe_rx_data_desc desc,
					u32 pkt_info, u32 staterr)
{
	u64 pkt_flags;
	u64 vlan_flags = rxq->vlan_flags;

	LOG_DEBUG("port_id=%u, rxq=%u, desc.lower=0x%" SXE_PRIX64 ", upper=0x%" SXE_PRIX64 ","
			"pkt_info=0x%x, staterr=0x%x",
			rxq->port_id, rxq->queue_id,
			rte_le_to_cpu_64(desc.read.pkt_addr),
			rte_le_to_cpu_64(desc.read.hdr_addr),
			pkt_info, staterr);

	mbuf->port = rxq->port_id;

	mbuf->vlan_tci = rte_le_to_cpu_16(desc.wb.upper.vlan);

	pkt_flags = sxe_rx_desc_status_to_pkt_flags(staterr, vlan_flags);
	pkt_flags |= sxe_rx_desc_error_to_pkt_flags(staterr);
	pkt_flags |= sxe_rx_desc_pkt_info_to_pkt_flags((u16)pkt_info);

	if (pkt_flags & (RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD)) {
		rxq->rx_stats.csum_err++;
		LOG_WARN("pkt_flags:0x%" SXE_PRIX64 " rx checksum error",
				pkt_flags);
	}

	mbuf->ol_flags = pkt_flags;
	mbuf->packet_type =
		sxe_rxd_pkt_info_to_pkt_type(pkt_info,
						rxq->pkt_type_mask);

	if (likely(pkt_flags & RTE_MBUF_F_RX_RSS_HASH)) {
		mbuf->hash.rss =
				rte_le_to_cpu_32(desc.wb.lower.hi_dword.rss);
	} else if (pkt_flags & RTE_MBUF_F_RX_FDIR) {
		mbuf->hash.fdir.hash =
				rte_le_to_cpu_16(desc.wb.lower.hi_dword.csum_ip.csum) &
				SXE_SAMPLE_HASH_MASK;
		mbuf->hash.fdir.id =
				rte_le_to_cpu_16(desc.wb.lower.hi_dword.csum_ip.ip_id);
	}
}

static inline void sxe_rx_resource_prefetch(u16 next_idx,
				sxe_rx_buffer_s *buf_ring,
				volatile union sxe_rx_data_desc *desc_ring)
{
	/* preftech next mbuf */
	rte_sxe_prefetch(buf_ring[next_idx].mbuf);

	if ((next_idx & 0x3) == 0) {
		rte_sxe_prefetch(&desc_ring[next_idx]);
		rte_sxe_prefetch(&buf_ring[next_idx]);
	}
}

u16 sxe_pkts_recv(void *rx_queue, struct rte_mbuf **rx_pkts,
		u16 pkts_num)
{
	return __sxe_pkts_recv(rx_queue, rx_pkts, pkts_num);
}

static inline u16 sxe_ret_pkts_to_user(sxe_rx_queue_s *rxq,
					struct rte_mbuf **rx_pkts,
					u16 pkts_num)
{
	struct rte_mbuf **completed_mbuf = &rxq->completed_ring[rxq->next_ret_pkg];
	u16 i;

	pkts_num = (u16)RTE_MIN(pkts_num, rxq->completed_pkts_num);

	for (i = 0; i < pkts_num; ++i)
		rx_pkts[i] = completed_mbuf[i];

	/* Update completed packets num and next available position */
	rxq->completed_pkts_num = (u16)(rxq->completed_pkts_num - pkts_num);
	rxq->next_ret_pkg = (u16)(rxq->next_ret_pkg + pkts_num);

	return pkts_num;
}

#define LOOK_AHEAD 8
#if (LOOK_AHEAD != 8)
#error "PMD SXE: LOOK_AHEAD must be 8"
#endif

static inline u16 sxe_rx_hw_ring_scan(sxe_rx_queue_s *rxq)
{
	volatile union sxe_rx_data_desc *rx_desc;
	sxe_rx_buffer_s *rx_buf;
	struct rte_mbuf *cur_mb;
	u16 num_dd_set;
	u32 status_arr[LOOK_AHEAD];
	u32 pkt_info[LOOK_AHEAD];
	u16 i, j;
	u32 status;
	u16 done_num = 0;
	u16 pkt_len;

	/* Obtain the desc and rx buff to be processed  */
	rx_desc = &rxq->desc_ring[rxq->processing_idx];
	rx_buf = &rxq->buffer_ring[rxq->processing_idx];

	status = rx_desc->wb.upper.status_error;

	if (!(status & rte_cpu_to_le_32(SXE_RXDADV_STAT_DD)))
		goto l_end;

	for (i = 0; i < RTE_PMD_SXE_MAX_RX_BURST;
		i += LOOK_AHEAD, rx_desc += LOOK_AHEAD, rx_buf += LOOK_AHEAD) {
		for (j = 0; j < LOOK_AHEAD; j++)
			status_arr[j] = rte_le_to_cpu_32(rx_desc[j].wb.upper.status_error);

		rte_atomic_thread_fence(rte_memory_order_acquire);

		for (num_dd_set = 0; num_dd_set < LOOK_AHEAD &&
			(status_arr[num_dd_set] & SXE_RXDADV_STAT_DD);
			num_dd_set++) {
			;
		}

		for (j = 0; j < num_dd_set; j++)
			pkt_info[j] = rte_le_to_cpu_32(rx_desc[j].wb.lower.lo_dword.data);

		done_num += num_dd_set;

		for (j = 0; j < num_dd_set; ++j) {
			cur_mb = rx_buf[j].mbuf;

			pkt_len = (u16)(rte_le_to_cpu_16(rx_desc[j].wb.upper.length) -
							rxq->crc_len);
			cur_mb->pkt_len = pkt_len;
			cur_mb->data_len = pkt_len;
			sxe_rx_mbuf_common_header_fill(rxq, cur_mb, rx_desc[j],
						pkt_info[j], status_arr[j]);
		}

		for (j = 0; j < LOOK_AHEAD; ++j)
			rxq->completed_ring[i + j] = rx_buf[j].mbuf;

		if (num_dd_set != LOOK_AHEAD)
			break;
	}

	for (i = 0; i < done_num; ++i)
		rxq->buffer_ring[rxq->processing_idx + i].mbuf = NULL;

l_end:
	return done_num;
}

static inline s32 sxe_rx_bufs_batch_alloc(sxe_rx_queue_s *rxq,
							bool reset_mbuf)
{
	volatile union sxe_rx_data_desc *desc_ring;
	sxe_rx_buffer_s *buf_ring;
	struct rte_mbuf *mbuf;
	u16 alloc_idx;
	__le64 dma_addr;
	s32 diag, i;
	s32 ret = 0;

	alloc_idx = rxq->batch_alloc_trigger - (rxq->batch_alloc_size - 1);
	buf_ring = &rxq->buffer_ring[alloc_idx];

	LOG_DEBUG("port_id=%u, rxq=%u, alloc_idx=%u, "
			"batch_alloc_trigger=%u, batch_alloc_size=%u",
			rxq->port_id, rxq->queue_id, alloc_idx,
			rxq->batch_alloc_trigger, rxq->batch_alloc_size);

	diag = rte_mempool_get_bulk(rxq->mb_pool, (void *)buf_ring,
					rxq->batch_alloc_size);
	if (unlikely(diag != 0)) {
		LOG_DEBUG("port_id=%u, rxq=%u buffer alloc failed",
				rxq->port_id, rxq->queue_id);
		ret = -ENOMEM;
		goto l_end;
	}

	desc_ring = &rxq->desc_ring[alloc_idx];
	for (i = 0; i < rxq->batch_alloc_size; ++i) {
		mbuf = buf_ring[i].mbuf;
		if (reset_mbuf)
			mbuf->port = rxq->port_id;

		rte_mbuf_refcnt_set(mbuf, 1);
		mbuf->data_off = RTE_PKTMBUF_HEADROOM;

		dma_addr = rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbuf));
		desc_ring[i].read.hdr_addr = 0;
		desc_ring[i].read.pkt_addr = dma_addr;
	}

	rxq->batch_alloc_trigger = rxq->batch_alloc_trigger + rxq->batch_alloc_size;
	if (rxq->batch_alloc_trigger >= rxq->ring_depth)
		rxq->batch_alloc_trigger = rxq->batch_alloc_size - 1;

l_end:
	return ret;
}

static inline u16 sxe_burst_pkts_recv(void *rx_queue,
					struct rte_mbuf **rx_pkts,
					u16 pkts_num)
{
	sxe_rx_queue_s *rxq = (sxe_rx_queue_s *)rx_queue;
	u16 done_num;

	if (rxq->completed_pkts_num) {
		done_num = sxe_ret_pkts_to_user(rxq, rx_pkts, pkts_num);
		LOG_DEBUG("there are %u mbuf in completed ring "
				"of queue[%u] return to user, done_num=%u",
				rxq->completed_pkts_num,
				rxq->queue_id, done_num);
		goto l_end;
	}

	done_num = (u16)sxe_rx_hw_ring_scan(rxq);

	rxq->next_ret_pkg = 0;
	rxq->completed_pkts_num = done_num;
	rxq->processing_idx = (u16)(rxq->processing_idx + done_num);

	if (rxq->processing_idx > rxq->batch_alloc_trigger) {
		u16 alloced_idx = rxq->batch_alloc_trigger;

		if (sxe_rx_bufs_batch_alloc(rxq, true) != 0) {
			u32 i, j;

			LOG_ERROR("rx mbuf alloc failed port_id=%u "
					"queue_id=%u", (unsigned int)rxq->port_id,
					(u16)rxq->queue_id);

			rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed +=
				rxq->batch_alloc_size;

			rxq->completed_pkts_num = 0;
			rxq->processing_idx = (u16)(rxq->processing_idx - done_num);
			for (i = 0, j = rxq->processing_idx; i < done_num; ++i, ++j)
				rxq->buffer_ring[j].mbuf = rxq->completed_ring[i];

			done_num = 0;
			goto l_end;
		}

		rte_wmb();
		SXE_PCI_REG_WC_WRITE_RELAXED(rxq->rdt_reg_addr, alloced_idx);
	}

	if (rxq->processing_idx >= rxq->ring_depth)
		rxq->processing_idx = 0;

	if (rxq->completed_pkts_num) {
		done_num = sxe_ret_pkts_to_user(rxq, rx_pkts, pkts_num);
		LOG_DEBUG("there are %u mbuf in completed ring "
				"of queue[%u] return to user, done_num=%u",
				rxq->completed_pkts_num,
				rxq->queue_id, done_num);
	}

l_end:
	return done_num;
}

u16 sxe_batch_alloc_pkts_recv(void *rx_queue,
					struct rte_mbuf **rx_pkts,
					u16 pkts_num)
{
	u16 done_num;

	if (unlikely(pkts_num == 0)) {
		LOG_DEBUG("user need pkts = 0");
		done_num = 0;
		goto l_end;
	}

	if (likely(pkts_num <= RTE_PMD_SXE_MAX_RX_BURST)) {
		done_num = sxe_burst_pkts_recv(rx_queue, rx_pkts, pkts_num);
		goto l_end;
	}

	done_num = 0;
	while (pkts_num) {
		u16 ret, n;

		n = (u16)RTE_MIN(pkts_num, RTE_PMD_SXE_MAX_RX_BURST);
		ret = sxe_burst_pkts_recv(rx_queue, &rx_pkts[done_num], n);
		done_num = (u16)(done_num + ret);
		pkts_num = (u16)(pkts_num - ret);
		if (ret < n)
			break;
	}

l_end:
	return done_num;
}

static inline s32 sxe_lro_new_mbufs_alloc(sxe_rx_queue_s *rxq,
					struct rte_mbuf **new_mbuf,
					u16 *hold_num, bool batch_alloc)
{
	s32 ret = 0;

	LOG_DEBUG("rxq[%u] %s alloc mem, current num_hold=%u",
			rxq->queue_id, batch_alloc ? "batch" : "single", *hold_num);
	if (!batch_alloc) {
		*new_mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (*new_mbuf == NULL) {
			LOG_DEBUG("RX mbuf alloc failed "
				"port_id=%u queue_id=%u",
				rxq->port_id, rxq->queue_id);

			rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
			ret = -ENOMEM;
			goto l_end;
		}

		(*new_mbuf)->data_off = RTE_PKTMBUF_HEADROOM;
	} else if (*hold_num > rxq->batch_alloc_size) {
		u16 next_rdt = rxq->batch_alloc_trigger;

		if (!sxe_rx_bufs_batch_alloc(rxq, false)) {
			rte_wmb();
			SXE_PCI_REG_WC_WRITE_RELAXED(rxq->rdt_reg_addr,
						next_rdt);

			*hold_num -= rxq->batch_alloc_size;
		} else {
			LOG_DEBUG("RX bulk alloc failed "
					"port_id=%u queue_id=%u",
					rxq->port_id, rxq->queue_id);

			rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
			ret = -ENOMEM;
			goto l_end;
		}
	}

l_end:
	return ret;
}

static inline void sxe_rx_resource_update(sxe_rx_buffer_s *rx_buf,
				volatile union sxe_rx_data_desc *cur_desc,
				struct rte_mbuf *new_mbuf, bool batch_alloc)
{
	LOG_DEBUG("%s update resource, new_mbuf=%p",
				batch_alloc ? "batch" : "single", cur_desc);

	if (!batch_alloc) {
		__le64 dma =
		  rte_cpu_to_le_64(rte_mbuf_data_iova_default(new_mbuf));
		rx_buf->mbuf = new_mbuf;
		cur_desc->read.hdr_addr = 0;
		cur_desc->read.pkt_addr = dma;
	} else {
		rx_buf->mbuf = NULL;
	}
}

static inline u16 sxe_rx_next_idx_get(union sxe_rx_data_desc *desc,
						u16 next_idx)
{
	u16 nextp_id;
	u32 staterr = rte_le_to_cpu_32(desc->wb.upper.status_error);


	if (sxe_lro_count(desc)) {
		nextp_id =
			(staterr & SXE_RXDADV_NEXTP_MASK) >>
			SXE_RXDADV_NEXTP_SHIFT;
	} else {
		nextp_id = next_idx;
	}
	LOG_DEBUG("next idx = %u", nextp_id);
	return nextp_id;
}

static inline void sxe_lro_first_seg_update(struct rte_mbuf **first_seg,
						struct rte_mbuf *cur_mbuf,
						u16 data_len)
{
	if (*first_seg == NULL) {
		(*first_seg) = cur_mbuf;
		(*first_seg)->pkt_len = data_len;
		(*first_seg)->nb_segs = 1;
	} else {
		(*first_seg)->pkt_len += data_len;
		(*first_seg)->nb_segs++;
	}
}

static inline void sxe_mbuf_fields_process(struct rte_mbuf *first_seg,
					sxe_rx_queue_s *rxq,
					union sxe_rx_data_desc desc,
					struct rte_mbuf *cur_mbuf,
					u32 staterr)
{
	u32 pkt_info;

	pkt_info = rte_le_to_cpu_32(desc.wb.lower.lo_dword.data);
	sxe_rx_mbuf_common_header_fill(rxq, first_seg, desc,
					pkt_info, staterr);

	first_seg->pkt_len -= rxq->crc_len;
	if (unlikely(cur_mbuf->data_len <= rxq->crc_len)) {
		struct rte_mbuf *lp;

		for (lp = first_seg; lp->next != cur_mbuf; lp = lp->next)
			;

		first_seg->nb_segs--;
		lp->data_len -= rxq->crc_len - cur_mbuf->data_len;
		lp->next = NULL;
		rte_pktmbuf_free_seg(cur_mbuf);
	} else {
		cur_mbuf->data_len -= rxq->crc_len;
	}

	rte_packet_prefetch((u8 *)first_seg->buf_addr + first_seg->data_off);
}

static inline u16 sxe_lro_pkts_recv(void *rx_queue,
			struct rte_mbuf **rx_pkts, u16 pkts_num,
			bool batch_alloc)
{
	sxe_rx_queue_s *rxq = rx_queue;
	volatile union sxe_rx_data_desc *desc_ring = rxq->desc_ring;
	sxe_rx_buffer_s *buf_ring = rxq->buffer_ring;
	sxe_rx_buffer_s *sc_buf_ring = rxq->sc_buffer_ring;
	u16 cur_idx = rxq->processing_idx;
	u16 done_num = 0;
	u16 hold_num = rxq->hold_num;
	u16 prev_idx = rxq->processing_idx;
	s32 err;

	while (done_num < pkts_num) {
		bool is_eop;
		sxe_rx_buffer_s *rx_buf;
		sxe_rx_buffer_s *sc_rx_buf;
		sxe_rx_buffer_s *next_sc_rx_buf = NULL;
		sxe_rx_buffer_s *next_rx_buf = NULL;
		struct rte_mbuf *first_seg;
		struct rte_mbuf *cur_mbuf;
		struct rte_mbuf *new_mbuf = NULL;
		union sxe_rx_data_desc desc_copy;
		u16 data_len;
		u16 next_idx;
		volatile union sxe_rx_data_desc *cur_desc;
		u32 staterr;

next_desc:
		cur_desc = &desc_ring[cur_idx];
		staterr = rte_le_to_cpu_32(cur_desc->wb.upper.status_error);

		if (!(staterr & SXE_RXDADV_STAT_DD))
			break;

		rte_atomic_thread_fence(rte_memory_order_acquire);


		desc_copy = *cur_desc;

		LOG_DEBUG("port_id=%u queue_id=%u cur_idx=%u "
				"staterr=0x%x data_len=%u",
				rxq->port_id, rxq->queue_id, cur_idx, staterr,
				rte_le_to_cpu_16(desc_copy.wb.upper.length));

		err = sxe_lro_new_mbufs_alloc(rxq, &new_mbuf, &hold_num, batch_alloc);
		if (err) {
			LOG_ERROR("mbuf %s alloc failed",
					batch_alloc ? "batch" : "single");
			break;
		}

		hold_num++;
		rx_buf = &buf_ring[cur_idx];
		is_eop = !!(staterr & SXE_RXDADV_STAT_EOP);

		next_idx = cur_idx + 1;
		if (next_idx == rxq->ring_depth)
			next_idx = 0;

		sxe_rx_resource_prefetch(next_idx, buf_ring, desc_ring);

		cur_mbuf = rx_buf->mbuf;

		sxe_rx_resource_update(rx_buf, cur_desc, new_mbuf, batch_alloc);

		data_len = rte_le_to_cpu_16(desc_copy.wb.upper.length);
		cur_mbuf->data_len = data_len;

		if (!is_eop) {
			u16 nextp_id = sxe_rx_next_idx_get(&desc_copy, next_idx);

			next_sc_rx_buf = &sc_buf_ring[nextp_id];
			next_rx_buf = &buf_ring[nextp_id];
			rte_sxe_prefetch(next_rx_buf);
		}

		sc_rx_buf = &sc_buf_ring[cur_idx];
		first_seg = sc_rx_buf->mbuf;
		sc_rx_buf->mbuf = NULL;

		sxe_lro_first_seg_update(&first_seg, cur_mbuf, data_len);

		prev_idx = cur_idx;
		cur_idx = next_idx;

		if (!is_eop && next_rx_buf) {
			cur_mbuf->next = next_rx_buf->mbuf;
			next_sc_rx_buf->mbuf = first_seg;
			goto next_desc;
		}

		sxe_mbuf_fields_process(first_seg, rxq, desc_copy, cur_mbuf, staterr);

		rx_pkts[done_num++] = first_seg;
	}

	rxq->processing_idx = cur_idx;

	if (!batch_alloc && hold_num > rxq->batch_alloc_size) {
		LOG_DEBUG("port_id=%u queue_id=%u rx_tail=%u "
			   "num_hold=%u done_num=%u",
			   rxq->port_id, rxq->queue_id,
			   cur_idx, hold_num, done_num);

		rte_wmb();
		SXE_PCI_REG_WC_WRITE_RELAXED(rxq->rdt_reg_addr, prev_idx);
		hold_num = 0;
	}

	rxq->hold_num = hold_num;
	return done_num;
}

u16 sxe_batch_alloc_lro_pkts_recv(void *rx_queue,
					struct rte_mbuf **rx_pkts,
					u16 pkts_num)
{
	return sxe_lro_pkts_recv(rx_queue, rx_pkts, pkts_num, true);
}

u16 sxe_single_alloc_lro_pkts_recv(void *rx_queue,
					struct rte_mbuf **rx_pkts,
					u16 pkts_num)
{
	return sxe_lro_pkts_recv(rx_queue, rx_pkts, pkts_num, false);
}

void __rte_cold sxe_rx_function_set(struct rte_eth_dev *dev,
	bool rx_batch_alloc_allowed, bool *rx_vec_allowed)
{
	__sxe_rx_function_set(dev, rx_batch_alloc_allowed, rx_vec_allowed);
}

s32 sxe_rx_descriptor_status(void *rx_queue, u16 offset)
{
	int ret = RTE_ETH_RX_DESC_AVAIL;
	sxe_rx_queue_s *rxq = rx_queue;
	volatile u32 *status;
	u32 hold_num, desc;

	if (unlikely(offset >= rxq->ring_depth)) {
		LOG_DEBUG("rx queue[%u] get desc status err,"
			"offset=%u >= ring_depth=%u",
			rxq->queue_id, offset, rxq->ring_depth);
		ret = -EINVAL;
		goto l_end;
	}

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#if defined(RTE_ARCH_X86)
	if (rxq->is_using_sse)
		hold_num = rxq->realloc_num;
	else
#endif
#endif

		hold_num = rxq->hold_num;
	if (offset >= rxq->ring_depth - hold_num) {
		ret = RTE_ETH_RX_DESC_UNAVAIL;
		goto l_end;
	}

	desc = rxq->processing_idx + offset;
	if (desc >= rxq->ring_depth)
		desc -= rxq->ring_depth;

	status = &rxq->desc_ring[desc].wb.upper.status_error;
	if (*status & rte_cpu_to_le_32(SXE_RXDADV_STAT_DD))
		ret =  RTE_ETH_RX_DESC_DONE;

l_end:
	LOG_DEBUG("rx queue[%u] get desc status=%d", rxq->queue_id, ret);
	return ret;
}

s32 __rte_cold sxe_rx_queue_setup(struct rte_eth_dev *dev,
			 u16 queue_idx, u16 desc_num,
			 unsigned int socket_id,
			 const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw	 *hw = &adapter->hw;
	struct rx_setup rx_setup = { 0 };
	s32 ret;

	PMD_INIT_FUNC_TRACE();

	rx_setup.desc_num = desc_num;
	rx_setup.queue_idx = queue_idx;
	rx_setup.socket_id = socket_id;
	rx_setup.mp = mp;
	rx_setup.dev = dev;
	rx_setup.reg_base_addr = hw->reg_base_addr;
	rx_setup.rx_conf = rx_conf;
	rx_setup.rx_batch_alloc_allowed = &adapter->rx_batch_alloc_allowed;

	ret = __sxe_rx_queue_setup(&rx_setup, false);
	if (ret)
		LOG_ERROR_BDF("rx queue setup fail.(err:%d)", ret);

	return ret;
}

static void sxe_rx_mode_configure(struct sxe_hw *hw)
{
	u32 flt_ctrl;

	flt_ctrl = sxe_hw_rx_mode_get(hw);
	LOG_DEBUG("read flt_ctrl=%u", flt_ctrl);
	flt_ctrl |= SXE_FCTRL_BAM;
	flt_ctrl |= SXE_FCTRL_DPF;
	flt_ctrl |= SXE_FCTRL_PMCF;
	LOG_DEBUG("write flt_ctrl=0x%x", flt_ctrl);
	sxe_hw_rx_mode_set(hw, flt_ctrl);
}

static inline void
	sxe_rx_queue_offload_configure(struct rte_eth_dev *dev)
{
	u16 i;
	sxe_rx_queue_s *rxq;
	struct rte_eth_rxmode *rx_conf = &dev->data->dev_conf.rxmode;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];

		if (rx_conf->offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC)
			rxq->crc_len = RTE_ETHER_CRC_LEN;
		else
			rxq->crc_len = 0;

		if (rxq->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
			rx_conf->offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	}
}

static inline void
	sxe_rx_offload_configure(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw	 *hw = &adapter->hw;
	struct rte_eth_rxmode *rx_conf = &dev->data->dev_conf.rxmode;
	bool ip_csum_offload;

	sxe_hw_rx_dma_ctrl_init(hw);


	if (dev->data->mtu > RTE_ETHER_MTU)
		adapter->mtu = dev->data->mtu;

	rx_conf->offloads &= ~RTE_ETH_RX_OFFLOAD_VLAN_STRIP;

	if (rx_conf->offloads & RTE_ETH_RX_OFFLOAD_SCATTER)
		dev->data->scattered_rx = 1;

	sxe_hw_rx_udp_frag_checksum_disable(hw);

	if (rx_conf->offloads & DEV_RX_OFFLOAD_CHECKSUM)
		ip_csum_offload = true;
	else
		ip_csum_offload = false;

	sxe_hw_rx_ip_checksum_offload_switch(hw, ip_csum_offload);

	sxe_rx_queue_offload_configure(dev);
}

static inline void sxe_rx_queue_attr_configure(struct rte_eth_dev *dev,
					sxe_rx_queue_s *queue)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw	 *hw = &adapter->hw;
	u32 srrctl_size;
	u64 desc_dma_addr;
	u32 desc_mem_len;
	u8 reg_idx;
	u16 buf_size;
	u32 frame_size = SXE_GET_FRAME_SIZE(dev);
	reg_idx = queue->reg_idx;

	sxe_hw_rx_ring_switch(hw, reg_idx, false);

	desc_mem_len = queue->ring_depth * sizeof(union sxe_rx_data_desc);
	desc_dma_addr = queue->base_addr;
	sxe_hw_rx_ring_desc_configure(hw, desc_mem_len,
						desc_dma_addr, reg_idx);

	buf_size = (u16)(rte_pktmbuf_data_room_size(queue->mb_pool) -
		RTE_PKTMBUF_HEADROOM);

	sxe_hw_rx_rcv_ctl_configure(hw, reg_idx,
			SXE_LRO_HDR_SIZE, buf_size);

	if (queue->drop_en)
		sxe_hw_rx_drop_switch(hw, reg_idx, true);

	sxe_hw_rx_desc_thresh_set(hw, reg_idx);

	srrctl_size = ((buf_size >> SXE_SRRCTL_BSIZEPKT_SHIFT) &
				SXE_SRRCTL_BSIZEPKT_MASK);

	buf_size = (u16)((srrctl_size & SXE_SRRCTL_BSIZEPKT_MASK) <<
				SXE_SRRCTL_BSIZEPKT_SHIFT);

	if (frame_size + 2 * SXE_VLAN_TAG_SIZE > buf_size)
		dev->data->scattered_rx = 1;

	sxe_hw_rx_ring_switch(hw, reg_idx, true);
}

static inline void sxe_rx_queue_configure(struct rte_eth_dev *dev)
{
	u16 i;
	sxe_rx_queue_s **queue = (sxe_rx_queue_s **)dev->data->rx_queues;

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		sxe_rx_queue_attr_configure(dev, queue[i]);
}

static u32 sxe_lro_max_desc_get(struct rte_mempool *pool)
{
	u8 desc_num;
	struct rte_pktmbuf_pool_private *mp_priv = rte_mempool_get_priv(pool);

	u16 maxdesc = RTE_IPV4_MAX_PKT_LEN /
			(mp_priv->mbuf_data_room_size - RTE_PKTMBUF_HEADROOM);

	if (maxdesc >= 16)
		desc_num = SXE_LROCTL_MAXDESC_16;
	else if (maxdesc >= 8)
		desc_num = SXE_LROCTL_MAXDESC_8;
	else if (maxdesc >= 4)
		desc_num = SXE_LROCTL_MAXDESC_4;
	else
		desc_num = SXE_LROCTL_MAXDESC_1;

	return desc_num;
}

static s32 sxe_lro_sanity_check(struct rte_eth_dev *dev, bool *lro_capable)
{
	s32 ret = 0;
	struct rte_eth_dev_info dev_info = { 0 };
	struct rte_eth_rxmode *rx_conf = &dev->data->dev_conf.rxmode;


	if ((rx_conf->offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC) &&
		(rx_conf->offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO)) {
		PMD_LOG_CRIT(INIT, "lro can't be enabled when HW CRC "
				"is disabled");
		ret = -EINVAL;
		goto l_end;
	}

	dev->dev_ops->dev_infos_get(dev, &dev_info);
	if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO)
		*lro_capable = true;

	if (!(*lro_capable) && (rx_conf->offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO)) {
		PMD_LOG_CRIT(INIT, "lro is requested on HW that doesn't "
				   "support it");
		ret = -EINVAL;
		goto l_end;
	}

l_end:
	return ret;
}

static void sxe_lro_hw_configure(struct sxe_hw *hw, bool lro_capable,
					struct rte_eth_rxmode *rx_conf)
{
	bool is_enable;

	sxe_hw_rx_lro_ack_switch(hw, false);

	sxe_hw_rx_dma_lro_ctrl_set(hw);

	if ((lro_capable) && (rx_conf->offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO))
		is_enable = true;
	else
		is_enable = false;

	if (is_enable)
		sxe_hw_rx_nfs_filter_disable(hw);

	sxe_hw_rx_lro_enable(hw, is_enable);
}

static void sxe_lro_irq_configure(struct sxe_hw *hw, u16 reg_idx,
						u16 irq_idx)
{
	u32 irq_interval;

	irq_interval = SXE_EITR_INTERVAL_US(SXE_QUEUE_ITR_INTERVAL_DEFAULT);
	sxe_hw_ring_irq_interval_set(hw, reg_idx, irq_interval);

	sxe_hw_ring_irq_map(hw, false, reg_idx, irq_idx);
}

static void sxe_lro_hw_queue_configure(struct rte_eth_dev *dev,
						struct sxe_hw *hw)
{
	u16 i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		sxe_rx_queue_s *rxq = dev->data->rx_queues[i];
		u16 reg_idx = rxq->reg_idx;
		u32 max_desc_num;

		max_desc_num = sxe_lro_max_desc_get(rxq->mb_pool);
		sxe_hw_rx_lro_ctl_configure(hw, reg_idx, max_desc_num);

		sxe_lro_irq_configure(hw, reg_idx, i);
	}
}

static s32 sxe_lro_configure(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw	 *hw = &adapter->hw;
	struct rte_eth_rxmode *rx_conf = &dev->data->dev_conf.rxmode;
	bool lro_capable = false;

	s32 ret;

	ret = sxe_lro_sanity_check(dev, &lro_capable);
	if (ret) {
		PMD_LOG_CRIT(INIT, "lro sanity check failed, err=%d", ret);
		goto l_end;
	}

	sxe_lro_hw_configure(hw, lro_capable, rx_conf);

	if (!(rx_conf->offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO)) {
		PMD_LOG_DEBUG(INIT, "user app do not turn lro on");
		goto l_end;
	}

	sxe_lro_hw_queue_configure(dev, hw);

	dev->data->lro = 1;

	PMD_LOG_DEBUG(INIT, "enabling lro mode");

l_end:
	return ret;
}

static s32 __rte_cold sxe_rx_start(struct rte_eth_dev *dev)
{
	sxe_rx_queue_s *rxq;
	u16 i;
	s32 ret = 0;

	PMD_INIT_FUNC_TRACE();

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		if (!rxq->deferred_start) {
			ret = sxe_rx_queue_start(dev, i);
			if (ret < 0) {
				PMD_LOG_ERR(INIT, "rx queue[%u] start failed", i);
				goto l_end;
			}
		}
	}

l_end:
	return ret;
}

s32 __rte_cold sxe_rx_configure(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw	 *hw = &adapter->hw;
	s32 ret;

	PMD_INIT_FUNC_TRACE();

	sxe_hw_rx_cap_switch_off(hw);

	sxe_hw_rx_pkt_buf_size_set(hw, 0, SXE_RX_PKT_BUF_SIZE);

	sxe_rx_mode_configure(hw);

	sxe_rx_offload_configure(dev);

	sxe_rx_queue_configure(dev);

	sxe_rx_features_configure(dev);

	ret = sxe_lro_configure(dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "lro config failed, err = %d", ret);
		goto l_end;
	}

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	sxe_rx_function_set(dev, adapter->rx_batch_alloc_allowed,
			&adapter->rx_vec_allowed);
#else
	sxe_rx_function_set(dev, adapter->rx_batch_alloc_allowed, NULL);
#endif

	ret = sxe_rx_start(dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "rx start failed, err = %d", ret);
		goto l_end;
	}

l_end:
	return ret;
}

void sxe_vmdq_rx_mode_get(u32 rx_mask, u32 *orig_val)
{
	if (rx_mask & RTE_ETH_VMDQ_ACCEPT_UNTAG)
		*orig_val |= SXE_VMOLR_AUPE;

	if (rx_mask & RTE_ETH_VMDQ_ACCEPT_HASH_MC)
		*orig_val |= SXE_VMOLR_ROMPE;

	if (rx_mask & RTE_ETH_VMDQ_ACCEPT_HASH_UC)
		*orig_val |= SXE_VMOLR_ROPE;

	if (rx_mask & RTE_ETH_VMDQ_ACCEPT_BROADCAST)
		*orig_val |= SXE_VMOLR_BAM;

	if (rx_mask & RTE_ETH_VMDQ_ACCEPT_MULTICAST)
		*orig_val |= SXE_VMOLR_MPE;
}

static void sxe_vmdq_rx_hw_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_vmdq_rx_conf *cfg;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw	 *hw = &adapter->hw;
	enum rte_eth_nb_pools pools_num;
	u32 rx_mode = 0;
	u16 i;

	PMD_INIT_FUNC_TRACE();
	cfg = &dev->data->dev_conf.rx_adv_conf.vmdq_rx_conf;
	pools_num = cfg->nb_queue_pools;

	sxe_rss_disable(dev);

	sxe_hw_vmdq_mq_configure(hw);

	sxe_hw_vmdq_default_pool_configure(hw,
						cfg->enable_default_pool,
						cfg->default_pool);

	sxe_vmdq_rx_mode_get(cfg->rx_mode, &rx_mode);
	sxe_hw_vmdq_vlan_configure(hw, pools_num, rx_mode);

	for (i = 0; i < cfg->nb_pool_maps; i++) {
		sxe_hw_vmdq_pool_configure(hw, i,
						cfg->pool_map[i].vlan_id,
						cfg->pool_map[i].pools);
	}

	if (cfg->enable_loop_back)
		sxe_hw_vmdq_loopback_configure(hw);
}

s32 sxe_rx_features_configure(struct rte_eth_dev *dev)
{
	s32 ret = 0;

	if (RTE_ETH_DEV_SRIOV(dev).active == 0) {
		switch (dev->data->dev_conf.rxmode.mq_mode) {
		case RTE_ETH_MQ_RX_RSS:
		case RTE_ETH_MQ_RX_DCB_RSS:
		case RTE_ETH_MQ_RX_VMDQ_RSS:
			sxe_rss_configure(dev);
			break;
		case RTE_ETH_MQ_RX_VMDQ_DCB:
			sxe_dcb_vmdq_rx_hw_configure(dev);
			break;
		case RTE_ETH_MQ_RX_VMDQ_ONLY:
			sxe_vmdq_rx_hw_configure(dev);
			break;
		case RTE_ETH_MQ_RX_NONE:
		default:
			sxe_rss_disable(dev);
			break;
		}
	} else {
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
		switch (dev->data->dev_conf.rxmode.mq_mode) {
		case RTE_ETH_MQ_RX_RSS:
		case RTE_ETH_MQ_RX_VMDQ_RSS:
			sxe_vf_rss_configure(dev);
			break;
		case RTE_ETH_MQ_RX_VMDQ_DCB:
		case RTE_ETH_MQ_RX_DCB:
			sxe_dcb_vmdq_rx_hw_configure(dev);
			break;
		case RTE_ETH_MQ_RX_VMDQ_DCB_RSS:
		case RTE_ETH_MQ_RX_DCB_RSS:
			ret = -SXE_ERR_CONFIG;
			PMD_LOG_ERR(DRV,
				"DCB and RSS with vmdq or sriov not "
				"support.(err:%d)", ret);
			break;
		default:
			sxe_vf_default_mode_configure(dev);
			break;
		}
#else
		PMD_LOG_ERR(INIT, "unsupport sriov");
		ret = -EINVAL;
#endif
	}

	LOG_INFO("pool num:%u rx mq_mode:0x%x configure result:%d.",
			 RTE_ETH_DEV_SRIOV(dev).active,
			 dev->data->dev_conf.rxmode.mq_mode, ret);

	return ret;
}

const u32 *sxe_dev_supported_ptypes_get(struct rte_eth_dev *dev, size_t *no_of_elements)
{
	return __sxe_dev_supported_ptypes_get(dev, no_of_elements);
}

static s32
sxe_monitor_callback(const u64 value,
		const u64 arg[RTE_POWER_MONITOR_OPAQUE_SZ] __rte_unused)
{
	const u64 dd_state = rte_cpu_to_le_32(SXE_RXDADV_STAT_DD);
	return (value & dd_state) == dd_state ? -1 : 0;
}

s32
sxe_monitor_addr_get(void *rx_queue, struct rte_power_monitor_cond *pmc)
{
	volatile union sxe_rx_data_desc *rxdp;
	struct sxe_rx_queue *rxq = rx_queue;

	rxdp = &rxq->desc_ring[rxq->processing_idx];

	pmc->addr = &rxdp->wb.upper.status_error;
	pmc->fn = sxe_monitor_callback;
	pmc->size = sizeof(u32);

	return 0;
}
