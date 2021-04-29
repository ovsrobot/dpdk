/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2020 Beijing WangXun Technology Co., Ltd.
 */

#include <rte_mbuf.h>
#include <rte_memory.h>

#include "base/txgbe_type.h"
#include "txgbe_ptypes.h"

/* The txgbe_ptype_lookup is used to convert from the 8-bit ptid in the
 * hardware to a bit-field that can be used by SW to more easily determine the
 * packet type.
 *
 * Macros are used to shorten the table lines and make this table human
 * readable.
 *
 * We store the PTYPE in the top byte of the bit field - this is just so that
 * we can check that the table doesn't have a row missing, as the index into
 * the table should be the PTYPE.
 *
 * Typical work flow:
 *
 * IF NOT txgbe_ptype_lookup[ptid].known
 * THEN
 *      Packet is unknown
 * ELSE IF txgbe_ptype_lookup[ptid].mac == TXGBE_DEC_PTYPE_MAC_IP
 *      Use the rest of the fields to look at the tunnels, inner protocols, etc
 * ELSE
 *      Use the enum txgbe_l2_ptypes to decode the packet type
 * ENDIF
 */
#define TPTE(ptid, l2, l3, l4, tun, el2, el3, el4) \
	[ptid] = (RTE_PTYPE_L2_##l2 | \
		RTE_PTYPE_L3_##l3 | \
		RTE_PTYPE_L4_##l4 | \
		RTE_PTYPE_TUNNEL_##tun | \
		RTE_PTYPE_INNER_L2_##el2 | \
		RTE_PTYPE_INNER_L3_##el3 | \
		RTE_PTYPE_INNER_L4_##el4)

#define RTE_PTYPE_L2_NONE               0
#define RTE_PTYPE_L3_NONE               0
#define RTE_PTYPE_L4_NONE               0
#define RTE_PTYPE_TUNNEL_NONE           0
#define RTE_PTYPE_INNER_L2_NONE         0
#define RTE_PTYPE_INNER_L3_NONE         0
#define RTE_PTYPE_INNER_L4_NONE         0

static u32 txgbe_ptype_lookup[TXGBE_PTID_MAX] __rte_cache_aligned = {
	/* L2:0-3 L3:4-7 L4:8-11 TUN:12-15 EL2:16-19 EL3:20-23 EL2:24-27 */
	/* L2: ETH */
	TPTE(0x10, ETHER,          NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x11, ETHER,          NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x12, ETHER_TIMESYNC, NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x13, ETHER_FIP,      NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x14, ETHER_LLDP,     NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x15, ETHER_CNM,      NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x16, ETHER_EAPOL,    NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x17, ETHER_ARP,      NONE, NONE, NONE, NONE, NONE, NONE),
	/* L2: Ethertype Filter */
	TPTE(0x18, ETHER_FILTER,   NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x19, ETHER_FILTER,   NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x1A, ETHER_FILTER,   NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x1B, ETHER_FILTER,   NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x1C, ETHER_FILTER,   NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x1D, ETHER_FILTER,   NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x1E, ETHER_FILTER,   NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x1F, ETHER_FILTER,   NONE, NONE, NONE, NONE, NONE, NONE),
	/* L3: IP */
	TPTE(0x20, ETHER, IPV4, NONFRAG, NONE, NONE, NONE, NONE),
	TPTE(0x21, ETHER, IPV4, FRAG,    NONE, NONE, NONE, NONE),
	TPTE(0x22, ETHER, IPV4, NONFRAG, NONE, NONE, NONE, NONE),
	TPTE(0x23, ETHER, IPV4, UDP,     NONE, NONE, NONE, NONE),
	TPTE(0x24, ETHER, IPV4, TCP,     NONE, NONE, NONE, NONE),
	TPTE(0x25, ETHER, IPV4, SCTP,    NONE, NONE, NONE, NONE),
	TPTE(0x29, ETHER, IPV6, FRAG,    NONE, NONE, NONE, NONE),
	TPTE(0x2A, ETHER, IPV6, NONFRAG, NONE, NONE, NONE, NONE),
	TPTE(0x2B, ETHER, IPV6, UDP,     NONE, NONE, NONE, NONE),
	TPTE(0x2C, ETHER, IPV6, TCP,     NONE, NONE, NONE, NONE),
	TPTE(0x2D, ETHER, IPV6, SCTP,    NONE, NONE, NONE, NONE),
	/* L2: FCoE */
	TPTE(0x30, ETHER_FCOE, NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x31, ETHER_FCOE, NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x32, ETHER_FCOE, NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x33, ETHER_FCOE, NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x34, ETHER_FCOE, NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x35, ETHER_FCOE, NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x36, ETHER_FCOE, NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x37, ETHER_FCOE, NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x38, ETHER_FCOE, NONE, NONE, NONE, NONE, NONE, NONE),
	TPTE(0x39, ETHER_FCOE, NONE, NONE, NONE, NONE, NONE, NONE),
	/* IPv4 -> IPv4/IPv6 */
	TPTE(0x81, ETHER, IPV4, NONE, IP, NONE, IPV4, FRAG),
	TPTE(0x82, ETHER, IPV4, NONE, IP, NONE, IPV4, NONFRAG),
	TPTE(0x83, ETHER, IPV4, NONE, IP, NONE, IPV4, UDP),
	TPTE(0x84, ETHER, IPV4, NONE, IP, NONE, IPV4, TCP),
	TPTE(0x85, ETHER, IPV4, NONE, IP, NONE, IPV4, SCTP),
	TPTE(0x89, ETHER, IPV4, NONE, IP, NONE, IPV6, FRAG),
	TPTE(0x8A, ETHER, IPV4, NONE, IP, NONE, IPV6, NONFRAG),
	TPTE(0x8B, ETHER, IPV4, NONE, IP, NONE, IPV6, UDP),
	TPTE(0x8C, ETHER, IPV4, NONE, IP, NONE, IPV6, TCP),
	TPTE(0x8D, ETHER, IPV4, NONE, IP, NONE, IPV6, SCTP),
	/* IPv4 -> GRE/Teredo/VXLAN -> NONE/IPv4/IPv6 */
	TPTE(0x90, ETHER, IPV4, NONE, VXLAN_GPE, NONE, NONE, NONE),
	TPTE(0x91, ETHER, IPV4, NONE, VXLAN_GPE, NONE, IPV4, FRAG),
	TPTE(0x92, ETHER, IPV4, NONE, VXLAN_GPE, NONE, IPV4, NONFRAG),
	TPTE(0x93, ETHER, IPV4, NONE, VXLAN_GPE, NONE, IPV4, UDP),
	TPTE(0x94, ETHER, IPV4, NONE, VXLAN_GPE, NONE, IPV4, TCP),
	TPTE(0x95, ETHER, IPV4, NONE, VXLAN_GPE, NONE, IPV4, SCTP),
	TPTE(0x99, ETHER, IPV4, NONE, VXLAN_GPE, NONE, IPV6, FRAG),
	TPTE(0x9A, ETHER, IPV4, NONE, VXLAN_GPE, NONE, IPV6, NONFRAG),
	TPTE(0x9B, ETHER, IPV4, NONE, VXLAN_GPE, NONE, IPV6, UDP),
	TPTE(0x9C, ETHER, IPV4, NONE, VXLAN_GPE, NONE, IPV6, TCP),
	TPTE(0x9D, ETHER, IPV4, NONE, VXLAN_GPE, NONE, IPV6, SCTP),
	/* IPv4 -> GRE/Teredo/VXLAN -> MAC -> NONE/IPv4/IPv6 */
	TPTE(0xA0, ETHER, IPV4, NONE, GRENAT, ETHER, NONE,  NONE),
	TPTE(0xA1, ETHER, IPV4, NONE, GRENAT, ETHER, IPV4, FRAG),
	TPTE(0xA2, ETHER, IPV4, NONE, GRENAT, ETHER, IPV4, NONFRAG),
	TPTE(0xA3, ETHER, IPV4, NONE, GRENAT, ETHER, IPV4, UDP),
	TPTE(0xA4, ETHER, IPV4, NONE, GRENAT, ETHER, IPV4, TCP),
	TPTE(0xA5, ETHER, IPV4, NONE, GRENAT, ETHER, IPV4, SCTP),
	TPTE(0xA9, ETHER, IPV4, NONE, GRENAT, ETHER, IPV6, FRAG),
	TPTE(0xAA, ETHER, IPV4, NONE, GRENAT, ETHER, IPV6, NONFRAG),
	TPTE(0xAB, ETHER, IPV4, NONE, GRENAT, ETHER, IPV6, UDP),
	TPTE(0xAC, ETHER, IPV4, NONE, GRENAT, ETHER, IPV6, TCP),
	TPTE(0xAD, ETHER, IPV4, NONE, GRENAT, ETHER, IPV6, SCTP),
	/* IPv4 -> GRE/Teredo/VXLAN -> MAC+VLAN -> NONE/IPv4/IPv6 */
	TPTE(0xB0, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, NONE,  NONE),
	TPTE(0xB1, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, IPV4, FRAG),
	TPTE(0xB2, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, IPV4, NONFRAG),
	TPTE(0xB3, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, IPV4, UDP),
	TPTE(0xB4, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, IPV4, TCP),
	TPTE(0xB5, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, IPV4, SCTP),
	TPTE(0xB9, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, IPV6, FRAG),
	TPTE(0xBA, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, IPV6, NONFRAG),
	TPTE(0xBB, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, IPV6, UDP),
	TPTE(0xBC, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, IPV6, TCP),
	TPTE(0xBD, ETHER, IPV4, NONE, GRENAT, ETHER_VLAN, IPV6, SCTP),
	/* IPv6 -> IPv4/IPv6 */
	TPTE(0xC1, ETHER, IPV6, NONE, IP, NONE, IPV4, FRAG),
	TPTE(0xC2, ETHER, IPV6, NONE, IP, NONE, IPV4, NONFRAG),
	TPTE(0xC3, ETHER, IPV6, NONE, IP, NONE, IPV4, UDP),
	TPTE(0xC4, ETHER, IPV6, NONE, IP, NONE, IPV4, TCP),
	TPTE(0xC5, ETHER, IPV6, NONE, IP, NONE, IPV4, SCTP),
	TPTE(0xC9, ETHER, IPV6, NONE, IP, NONE, IPV6, FRAG),
	TPTE(0xCA, ETHER, IPV6, NONE, IP, NONE, IPV6, NONFRAG),
	TPTE(0xCB, ETHER, IPV6, NONE, IP, NONE, IPV6, UDP),
	TPTE(0xCC, ETHER, IPV6, NONE, IP, NONE, IPV6, TCP),
	TPTE(0xCD, ETHER, IPV6, NONE, IP, NONE, IPV6, SCTP),
	/* IPv6 -> GRE/Teredo/VXLAN -> NONE/IPv4/IPv6 */
	TPTE(0xD0, ETHER, IPV6, NONE, GRENAT, NONE, NONE,  NONE),
	TPTE(0xD1, ETHER, IPV6, NONE, GRENAT, NONE, IPV4, FRAG),
	TPTE(0xD2, ETHER, IPV6, NONE, GRENAT, NONE, IPV4, NONFRAG),
	TPTE(0xD3, ETHER, IPV6, NONE, GRENAT, NONE, IPV4, UDP),
	TPTE(0xD4, ETHER, IPV6, NONE, GRENAT, NONE, IPV4, TCP),
	TPTE(0xD5, ETHER, IPV6, NONE, GRENAT, NONE, IPV4, SCTP),
	TPTE(0xD9, ETHER, IPV6, NONE, GRENAT, NONE, IPV6, FRAG),
	TPTE(0xDA, ETHER, IPV6, NONE, GRENAT, NONE, IPV6, NONFRAG),
	TPTE(0xDB, ETHER, IPV6, NONE, GRENAT, NONE, IPV6, UDP),
	TPTE(0xDC, ETHER, IPV6, NONE, GRENAT, NONE, IPV6, TCP),
	TPTE(0xDD, ETHER, IPV6, NONE, GRENAT, NONE, IPV6, SCTP),
	/* IPv6 -> GRE/Teredo/VXLAN -> MAC -> NONE/IPv4/IPv6 */
	TPTE(0xE0, ETHER, IPV6, NONE, GRENAT, ETHER, NONE,  NONE),
	TPTE(0xE1, ETHER, IPV6, NONE, GRENAT, ETHER, IPV4, FRAG),
	TPTE(0xE2, ETHER, IPV6, NONE, GRENAT, ETHER, IPV4, NONFRAG),
	TPTE(0xE3, ETHER, IPV6, NONE, GRENAT, ETHER, IPV4, UDP),
	TPTE(0xE4, ETHER, IPV6, NONE, GRENAT, ETHER, IPV4, TCP),
	TPTE(0xE5, ETHER, IPV6, NONE, GRENAT, ETHER, IPV4, SCTP),
	TPTE(0xE9, ETHER, IPV6, NONE, GRENAT, ETHER, IPV6, FRAG),
	TPTE(0xEA, ETHER, IPV6, NONE, GRENAT, ETHER, IPV6, NONFRAG),
	TPTE(0xEB, ETHER, IPV6, NONE, GRENAT, ETHER, IPV6, UDP),
	TPTE(0xEC, ETHER, IPV6, NONE, GRENAT, ETHER, IPV6, TCP),
	TPTE(0xED, ETHER, IPV6, NONE, GRENAT, ETHER, IPV6, SCTP),
	/* IPv6 -> GRE/Teredo/VXLAN -> MAC+VLAN -> NONE/IPv4/IPv6 */
	TPTE(0xF0, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, NONE,  NONE),
	TPTE(0xF1, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, IPV4, FRAG),
	TPTE(0xF2, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, IPV4, NONFRAG),
	TPTE(0xF3, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, IPV4, UDP),
	TPTE(0xF4, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, IPV4, TCP),
	TPTE(0xF5, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, IPV4, SCTP),
	TPTE(0xF9, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, IPV6, FRAG),
	TPTE(0xFA, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, IPV6, NONFRAG),
	TPTE(0xFB, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, IPV6, UDP),
	TPTE(0xFC, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, IPV6, TCP),
	TPTE(0xFD, ETHER, IPV6, NONE, GRENAT, ETHER_VLAN, IPV6, SCTP),
};

u32 *txgbe_get_supported_ptypes(void)
{
	static u32 ptypes[] = {
		/* For non-vec functions,
		 * refers to txgbe_rxd_pkt_info_to_pkt_type();
		 */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV4_EXT,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_TUNNEL_IP,
		RTE_PTYPE_INNER_L3_IPV6,
		RTE_PTYPE_INNER_L3_IPV6_EXT,
		RTE_PTYPE_INNER_L4_TCP,
		RTE_PTYPE_INNER_L4_UDP,
		RTE_PTYPE_UNKNOWN
	};

	return ptypes;
}

static inline u8
txgbe_encode_ptype_fcoe(u32 ptype)
{
	u8 ptid;

	UNREFERENCED_PARAMETER(ptype);
	ptid = TXGBE_PTID_PKT_FCOE;

	return ptid;
}

static inline u8
txgbe_encode_ptype_mac(u32 ptype)
{
	u8 ptid;

	ptid = TXGBE_PTID_PKT_MAC;

	switch (ptype & RTE_PTYPE_L2_MASK) {
	case RTE_PTYPE_L2_ETHER_FCOE:
		ptid = txgbe_encode_ptype_fcoe(ptype);
		break;
	case RTE_PTYPE_UNKNOWN:
		break;
	case RTE_PTYPE_L2_ETHER_TIMESYNC:
		ptid |= TXGBE_PTID_TYP_TS;
		break;
	case RTE_PTYPE_L2_ETHER_ARP:
		ptid |= TXGBE_PTID_TYP_ARP;
		break;
	case RTE_PTYPE_L2_ETHER_LLDP:
		ptid |= TXGBE_PTID_TYP_LLDP;
		break;
	default:
		ptid |= TXGBE_PTID_TYP_MAC;
		break;
	}

	return ptid;
}

static inline u8
txgbe_encode_ptype_ip(u32 ptype)
{
	u8 ptid;

	ptid = TXGBE_PTID_PKT_IP;

	switch (ptype & RTE_PTYPE_L3_MASK) {
	case RTE_PTYPE_L3_IPV4:
	case RTE_PTYPE_L3_IPV4_EXT:
	case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
		break;
	case RTE_PTYPE_L3_IPV6:
	case RTE_PTYPE_L3_IPV6_EXT:
	case RTE_PTYPE_L3_IPV6_EXT_UNKNOWN:
		ptid |= TXGBE_PTID_PKT_IPV6;
		break;
	default:
		return txgbe_encode_ptype_mac(ptype);
	}

	switch (ptype & RTE_PTYPE_L4_MASK) {
	case RTE_PTYPE_L4_TCP:
		ptid |= TXGBE_PTID_TYP_TCP;
		break;
	case RTE_PTYPE_L4_UDP:
		ptid |= TXGBE_PTID_TYP_UDP;
		break;
	case RTE_PTYPE_L4_SCTP:
		ptid |= TXGBE_PTID_TYP_SCTP;
		break;
	case RTE_PTYPE_L4_FRAG:
		ptid |= TXGBE_PTID_TYP_IPFRAG;
		break;
	default:
		ptid |= TXGBE_PTID_TYP_IPDATA;
		break;
	}

	return ptid;
}

static inline u8
txgbe_encode_ptype_tunnel(u32 ptype)
{
	u8 ptid;

	ptid = TXGBE_PTID_PKT_TUN;

	switch (ptype & RTE_PTYPE_L3_MASK) {
	case RTE_PTYPE_L3_IPV4:
	case RTE_PTYPE_L3_IPV4_EXT:
	case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
		break;
	case RTE_PTYPE_L3_IPV6:
	case RTE_PTYPE_L3_IPV6_EXT:
	case RTE_PTYPE_L3_IPV6_EXT_UNKNOWN:
		ptid |= TXGBE_PTID_TUN_IPV6;
		break;
	default:
		return txgbe_encode_ptype_ip(ptype);
	}

	switch (ptype & RTE_PTYPE_TUNNEL_MASK) {
	case RTE_PTYPE_TUNNEL_IP:
		ptid |= TXGBE_PTID_TUN_EI;
		break;
	case RTE_PTYPE_TUNNEL_GRE:
	case RTE_PTYPE_TUNNEL_VXLAN_GPE:
		ptid |= TXGBE_PTID_TUN_EIG;
		break;
	case RTE_PTYPE_TUNNEL_VXLAN:
	case RTE_PTYPE_TUNNEL_NVGRE:
	case RTE_PTYPE_TUNNEL_GENEVE:
	case RTE_PTYPE_TUNNEL_GRENAT:
		break;
	default:
		return ptid;
	}

	switch (ptype & RTE_PTYPE_INNER_L2_MASK) {
	case RTE_PTYPE_INNER_L2_ETHER:
		ptid |= TXGBE_PTID_TUN_EIGM;
		break;
	case RTE_PTYPE_INNER_L2_ETHER_VLAN:
		ptid |= TXGBE_PTID_TUN_EIGMV;
		break;
	case RTE_PTYPE_INNER_L2_ETHER_QINQ:
		ptid |= TXGBE_PTID_TUN_EIGMV;
		break;
	default:
		break;
	}

	switch (ptype & RTE_PTYPE_INNER_L3_MASK) {
	case RTE_PTYPE_INNER_L3_IPV4:
	case RTE_PTYPE_INNER_L3_IPV4_EXT:
	case RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN:
		break;
	case RTE_PTYPE_INNER_L3_IPV6:
	case RTE_PTYPE_INNER_L3_IPV6_EXT:
	case RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN:
		ptid |= TXGBE_PTID_PKT_IPV6;
		break;
	default:
		return ptid;
	}

	switch (ptype & RTE_PTYPE_INNER_L4_MASK) {
	case RTE_PTYPE_INNER_L4_TCP:
		ptid |= TXGBE_PTID_TYP_TCP;
		break;
	case RTE_PTYPE_INNER_L4_UDP:
		ptid |= TXGBE_PTID_TYP_UDP;
		break;
	case RTE_PTYPE_INNER_L4_SCTP:
		ptid |= TXGBE_PTID_TYP_SCTP;
		break;
	case RTE_PTYPE_INNER_L4_FRAG:
		ptid |= TXGBE_PTID_TYP_IPFRAG;
		break;
	default:
		ptid |= TXGBE_PTID_TYP_IPDATA;
		break;
	}

	return ptid;
}

u32 txgbe_decode_ptype(u8 ptid)
{
	if (-1 != txgbe_etflt_id(ptid))
		return RTE_PTYPE_UNKNOWN;

	return txgbe_ptype_lookup[ptid];
}

u8 txgbe_encode_ptype(u32 ptype)
{
	u8 ptid = 0;

	if (ptype & RTE_PTYPE_TUNNEL_MASK)
		ptid = txgbe_encode_ptype_tunnel(ptype);
	else if (ptype & RTE_PTYPE_L3_MASK)
		ptid = txgbe_encode_ptype_ip(ptype);
	else if (ptype & RTE_PTYPE_L2_MASK)
		ptid = txgbe_encode_ptype_mac(ptype);
	else
		ptid = TXGBE_PTID_NULL;

	return ptid;
}

/**
 * Use 2 different table for normal packet and tunnel packet
 * to save the space.
 */
const u32
txgbe_ptype_table[TXGBE_PTID_MAX] __rte_cache_aligned = {
	[TXGBE_PT_ETHER] = RTE_PTYPE_L2_ETHER,
	[TXGBE_PT_IPV4] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4,
	[TXGBE_PT_IPV4_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP,
	[TXGBE_PT_IPV4_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP,
	[TXGBE_PT_IPV4_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_SCTP,
	[TXGBE_PT_IPV4_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT,
	[TXGBE_PT_IPV4_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_TCP,
	[TXGBE_PT_IPV4_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_UDP,
	[TXGBE_PT_IPV4_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_SCTP,
	[TXGBE_PT_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6,
	[TXGBE_PT_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP,
	[TXGBE_PT_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP,
	[TXGBE_PT_IPV6_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_SCTP,
	[TXGBE_PT_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6_EXT,
	[TXGBE_PT_IPV6_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_TCP,
	[TXGBE_PT_IPV6_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_UDP,
	[TXGBE_PT_IPV6_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_SCTP,
	[TXGBE_PT_IPV4_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6,
	[TXGBE_PT_IPV4_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_IPV4_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_UDP,
	[TXGBE_PT_IPV4_IPV6_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_IPV4_EXT_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6,
	[TXGBE_PT_IPV4_EXT_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_IPV4_EXT_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_UDP,
	[TXGBE_PT_IPV4_EXT_IPV6_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_IPV4_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT,
	[TXGBE_PT_IPV4_IPV6_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_IPV4_IPV6_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_UDP,
	[TXGBE_PT_IPV4_IPV6_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_IPV4_EXT_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT,
	[TXGBE_PT_IPV4_EXT_IPV6_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_IPV4_EXT_IPV6_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_UDP,
	[TXGBE_PT_IPV4_EXT_IPV6_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_IP |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_SCTP,
};

const u32
txgbe_ptype_table_tn[TXGBE_PTID_MAX] __rte_cache_aligned = {
	[TXGBE_PT_NVGRE] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER,
	[TXGBE_PT_NVGRE_IPV4] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_NVGRE_IPV4_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4_EXT,
	[TXGBE_PT_NVGRE_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6,
	[TXGBE_PT_NVGRE_IPV4_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_NVGRE_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6_EXT,
	[TXGBE_PT_NVGRE_IPV4_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_NVGRE_IPV4_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4 |
		RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_NVGRE_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6 |
		RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_NVGRE_IPV4_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_NVGRE_IPV6_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6_EXT |
		RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_NVGRE_IPV4_IPV6_EXT_TCP] =
		RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_GRE | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_NVGRE_IPV4_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4 |
		RTE_PTYPE_INNER_L4_UDP,
	[TXGBE_PT_NVGRE_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6 |
		RTE_PTYPE_INNER_L4_UDP,
	[TXGBE_PT_NVGRE_IPV6_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6 |
		RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_NVGRE_IPV4_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_NVGRE_IPV6_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6_EXT |
		RTE_PTYPE_INNER_L4_UDP,
	[TXGBE_PT_NVGRE_IPV6_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV6_EXT |
		RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_NVGRE_IPV4_IPV6_EXT_UDP] =
		RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_GRE | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_NVGRE_IPV4_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4 |
		RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_NVGRE_IPV4_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4_EXT |
		RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_NVGRE_IPV4_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4_EXT |
		RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_NVGRE_IPV4_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_TUNNEL_GRE |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4_EXT |
		RTE_PTYPE_INNER_L4_UDP,

	[TXGBE_PT_VXLAN] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER,
	[TXGBE_PT_VXLAN_IPV4] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_VXLAN_IPV4_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4_EXT,
	[TXGBE_PT_VXLAN_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6,
	[TXGBE_PT_VXLAN_IPV4_IPV6] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_VXLAN_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6_EXT,
	[TXGBE_PT_VXLAN_IPV4_IPV6_EXT] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_VXLAN_IPV4_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4 | RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_VXLAN_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_VXLAN_IPV4_IPV6_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_VXLAN_IPV6_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_VXLAN_IPV4_IPV6_EXT_TCP] =
		RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_VXLAN |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_VXLAN_IPV4_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4 | RTE_PTYPE_INNER_L4_UDP,
	[TXGBE_PT_VXLAN_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_UDP,
	[TXGBE_PT_VXLAN_IPV6_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_VXLAN_IPV4_IPV6_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_VXLAN_IPV6_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_UDP,
	[TXGBE_PT_VXLAN_IPV6_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV6_EXT | RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_VXLAN_IPV4_IPV6_EXT_UDP] =
		RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_VXLAN |
		RTE_PTYPE_INNER_L2_ETHER | RTE_PTYPE_INNER_L3_IPV4,
	[TXGBE_PT_VXLAN_IPV4_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4 | RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_VXLAN_IPV4_EXT_SCTP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4_EXT | RTE_PTYPE_INNER_L4_SCTP,
	[TXGBE_PT_VXLAN_IPV4_EXT_TCP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4_EXT | RTE_PTYPE_INNER_L4_TCP,
	[TXGBE_PT_VXLAN_IPV4_EXT_UDP] = RTE_PTYPE_L2_ETHER |
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP |
		RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_INNER_L2_ETHER |
		RTE_PTYPE_INNER_L3_IPV4_EXT | RTE_PTYPE_INNER_L4_UDP,
};

