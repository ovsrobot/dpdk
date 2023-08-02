#ifndef _RNP_ETH_REGS_H_
#define _RNP_ETH_REGS_H_

#include "rnp_osdep.h"

/* PTP 1588 TM Offload */
#define RNP_ETH_PTP_TX_STATUS(n)	_ETH_(0x0400 + ((n) * 0x14))
#define RNP_ETH_PTP_TX_HTIMES(n)	_ETH_(0x0404 + ((n) * 0x14))
#define RNP_ETH_PTP_TX_LTIMES(n)	_ETH_(0x0408 + ((n) * 0x14))
#define RNP_ETH_PTP_TX_TS_ST(n)		_ETH_(0x040c + ((n) * 0x14))
#define RNP_ETH_PTP_TX_CLEAR(n)		_ETH_(0x0410 + ((n) * 0x14))

#define RNP_ETH_ENGINE_BYPASS		_ETH_(0x8000)
#define RNP_EN_TUNNEL_VXLAN_PARSE	_ETH_(0x8004)
#define RNP_ETH_MAC_LOOPBACK		_ETH_(0x8008)
#define RNP_ETH_FIFO_CTRL		_ETH_(0x800c)
#define RNP_ETH_FOUR_FIFO		BIT(0)
#define RNP_ETH_TWO_FIFO		BIT(1)
#define RNP_ETH_ONE_FIFO		BIT(2)
#define RNP_FIFO_CFG_EN			(0x1221)
#define RNP_ETH_VXLAN_PORT_CTRL		_ETH_(0x8010)
#define RNP_ETH_VXLAN_DEF_PORT		(4789)
#define RNP_HOST_FILTER_EN		_ETH_(0x801c)
#define RNP_HW_SCTP_CKSUM_CTRL		_ETH_(0x8038)
#define RNP_HW_CHECK_ERR_CTRL		_ETH_(0x8060)
#define RNP_HW_ERR_HDR_LEN		BIT(0)
#define RNP_HW_ERR_PKTLEN		BIT(1)
#define RNP_HW_L3_CKSUM_ERR		BIT(2)
#define RNP_HW_L4_CKSUM_ERR		BIT(3)
#define RNP_HW_SCTP_CKSUM_ERR		BIT(4)
#define RNP_HW_INNER_L3_CKSUM_ERR	BIT(5)
#define RNP_HW_INNER_L4_CKSUM_ERR	BIT(6)
#define RNP_HW_CKSUM_ERR_MASK		GENMASK(6, 2)
#define RNP_HW_CHECK_ERR_MASK		GENMASK(6, 0)
#define RNP_HW_ERR_RX_ALL_MASK		GENMASK(1, 0)

#define RNP_REDIR_CTRL			_ETH_(0x8030)
#define RNP_VLAN_Q_STRIP_CTRL(n)	_ETH_(0x8040 + 0x4 * ((n) / 32))
/* This Just VLAN Master Switch */
#define RNP_VLAN_TUNNEL_STRIP_EN	_ETH_(0x8050)
#define RNP_VLAN_TUNNEL_STRIP_MODE	_ETH_(0x8054)
#define RNP_VLAN_TUNNEL_STRIP_OUTER	(0)
#define RNP_VLAN_TUNNEL_STRIP_INNER	(1)
#define RNP_RSS_INNER_CTRL		_ETH_(0x805c)
#define RNP_INNER_RSS_EN		(1)

#define RNP_ETH_DEFAULT_RX_RING		_ETH_(0x806c)
#define RNP_RX_FC_HI_WATER(n)		_ETH_(0x80c0 + ((n) * 0x8))
#define RNP_RX_FC_LO_WATER(n)		_ETH_(0x80c4 + ((n) * 0x8))

#define RNP_RX_FIFO_FULL_THRETH(n)	_ETH_(0x8070 + ((n) * 0x8))
#define RNP_RX_WORKAROUND_VAL		_ETH_(0x7ff)
#define RNP_RX_DEFAULT_VAL		_ETH_(0x270)

#define RNP_MIN_FRAME_CTRL		_ETH_(0x80f0)
#define RNP_MAX_FRAME_CTRL		_ETH_(0x80f4)

#define RNP_RX_FC_ENABLE		_ETH_(0x8520)
#define RNP_RING_FC_EN(n)		_ETH_(0x8524 + 0x4 * ((n) / 32))
#define RNP_RING_FC_THRESH(n)		_ETH_(0x8a00 + 0x4 * (n))

/* Mac Host Filter  */
#define RNP_MAC_FCTRL			_ETH_(0x9110)
#define RNP_MAC_FCTRL_MPE		BIT(8)	/* Multicast Promiscuous En */
#define RNP_MAC_FCTRL_UPE		BIT(9)	/* Unicast Promiscuous En */
#define RNP_MAC_FCTRL_BAM		BIT(10) /* Broadcast Accept Mode */
#define RNP_MAC_FCTRL_BYPASS		(RNP_MAC_FCTRL_MPE | \
					RNP_MAC_FCTRL_UPE | \
					RNP_MAC_FCTRL_BAM)
/* MC UC Mac Hash Filter Ctrl */
#define RNP_MAC_MCSTCTRL		_ETH_(0x9114)
#define RNP_MAC_HASH_MASK		GENMASK(11, 0)
#define RNP_MAC_MULTICASE_TBL_EN	BIT(2)
#define RNP_MAC_UNICASE_TBL_EN		BIT(3)
#define RNP_UC_HASH_TB(n)		_ETH_(0xA800 + ((n) * 0x4))
#define RNP_MC_HASH_TB(n)		_ETH_(0xAC00 + ((n) * 0x4))

#define RNP_VLAN_FILTER_CTRL		_ETH_(0x9118)
#define RNP_L2TYPE_FILTER_CTRL		(RNP_VLAN_FILTER_CTRL)
#define RNP_L2TYPE_FILTER_EN		BIT(31)
#define RNP_VLAN_FILTER_EN		BIT(30)

#define RNP_FC_PAUSE_FWD_ACT		_ETH_(0x9280)
#define RNP_FC_PAUSE_DROP		BIT(31)
#define RNP_FC_PAUSE_PASS		(0)
#define RNP_FC_PAUSE_TYPE		_ETH_(0x9284)
#define RNP_FC_PAUSE_POLICY_EN		BIT(31)
#define RNP_PAUSE_TYPE			_ETH_(0x8808)

#define RNP_INPUT_USE_CTRL		_ETH_(0x91d0)
#define RNP_INPUT_VALID_MASK		(0xf)
#define RNP_INPUT_POLICY(n)		_ETH_(0x91e0 + ((n) * 0x4))
/* RSS */
#define RNP_RSS_MRQC_ADDR		_ETH_(0x92a0)
#define RNP_SRIOV_CTRL			RNP_RSS_MRQC_ADDR
#define RNP_SRIOV_ENABLE		BIT(3)

#define RNP_RSS_REDIR_TB(mac, idx)	_ETH_(0xe000 + \
		((mac) * 0x200) + ((idx) * 0x4))
#define RNP_RSS_KEY_TABLE(idx)		_ETH_(0x92d0 + ((idx) * 0x4))
/*=======================================================================
 *HOST_MAC_ADDRESS_FILTER
 *=======================================================================
 */
#define RNP_RAL_BASE_ADDR(vf_id)	_ETH_(0xA000 + 0x04 * (vf_id))
#define RNP_RAH_BASE_ADDR(vf_id)	_ETH_(0xA400 + 0x04 * (vf_id))
#define RNP_MAC_FILTER_EN		BIT(31)

/* ETH Statistic */
#define RNP_ETH_RXTRANS_DROP(p_id)	_ETH_((0x8904) + ((p_id) * (0x40)))
#define RNP_ETH_RXTRANS_CAT_ERR(p_id)	_ETH_((0x8928) + ((p_id) * (0x40)))
#define RNP_ETH_TXTM_DROP		_ETH_(0X0470)

#define RNP_VFTA_BASE_ADDR		_ETH_(0xB000)
#define RNP_VFTA_HASH_TABLE(id)		(RNP_VFTA_BASE_ADDR + 0x4 * (id))
#define RNP_ETYPE_BASE_ADDR		_ETH_(0xB300)
#define RNP_MPSAR_BASE_ADDR(vf_id)	_ETH_(0xB400 + 0x04 * (vf_id))
#define RNP_PFVLVF_BASE_ADDR		_ETH_(0xB600)
#define RNP_PFVLVFB_BASE_ADDR		_ETH_(0xB700)
#define RNP_TUNNEL_PFVLVF_BASE_ADDR	_ETH_(0xB800)
#define RNP_TUNNEL_PFVLVFB_BASE_ADDR	_ETH_(0xB900)

#define RNP_TC_PORT_MAP_TB(port)	_ETH_(0xe840 + 0x04 * (port))
#endif /* RNP_ETH_REGS_H_ */
