#ifndef __RNP_MAC_REGS_H__
#define __RNP_MAC_REGS_H__

#include "rnp_osdep.h"
#define RNP_MAC_TX_CFG		(0x0)

/* Transmitter Enable */
#define RNP_MAC_TE			BIT(0)
/* Jabber Disable */
#define RNP_MAC_JD			BIT(16)
#define RNP_SPEED_SEL_1G		(BIT(30) | BIT(29) | BIT(28))
#define RNP_SPEED_SEL_10G		BIT(30)
#define RNP_SPEED_SEL_40G		(0)
#define RNP_MAC_RX_CFG			(0x4)
/* Receiver Enable */
#define RNP_MAC_RE			BIT(0)
/* Automatic Pad or CRC Stripping */
#define RNP_MAC_ACS			BIT(1)
/* CRC stripping for Type packets */
#define RNP_MAC_CST			BIT(2)
/* Disable CRC Check */
#define RNP_MAC_DCRCC			BIT(3)
/* Enable Max Frame Size Limit */
#define RNP_MAC_GPSLCE			BIT(6)
/* Watchdog Disable */
#define RNP_MAC_WD			BIT(7)
/* Jumbo Packet Support En */
#define RNP_MAC_JE			BIT(8)
/* Loopback Mode */
#define RNP_MAC_LM			BIT(10)
/* Giant Packet Size Limit */
#define RNP_MAC_GPSL_MASK		GENMASK(29, 16)
#define RNP_MAC_MAX_GPSL		(1518)
#define RNP_MAC_CPSL_SHIFT		(16)

#define RNP_MAC_PKT_FLT_CTRL		(0x8)

/* Receive All */
#define RNP_MAC_RA			BIT(31)
/* Pass Control Packets */
#define RNP_MAC_PCF			GENMASK(7, 6)
#define RNP_MAC_PCF_OFFSET		(6)
/* Mac Filter ALL Ctrl Frame */
#define RNP_MAC_PCF_FAC			(0)
/* Mac Forward ALL Ctrl Frame Except Pause */
#define RNP_MAC_PCF_NO_PAUSE		(1)
/* Mac Forward All Ctrl Pkt */
#define RNP_MAC_PCF_PA			(2)
/* Mac Forward Ctrl Frame Match Unicast */
#define RNP_MAC_PCF_PUN			(3)
/* Promiscuous Mode */
#define RNP_MAC_PROMISC_EN		BIT(0)
/* Hash Unicast */
#define RNP_MAC_HUC			BIT(1)
/* Hash Multicast */
#define RNP_MAC_HMC			BIT(2)
/*  Pass All Multicast */
#define RNP_MAC_PM			BIT(4)
/* Disable Broadcast Packets */
#define RNP_MAC_DBF			BIT(5)
/* Hash or Perfect Filter */
#define RNP_MAC_HPF			BIT(10)
#define RNP_MAC_VTFE			BIT(16)
/* Interrupt Status */
#define RNP_MAC_INT_STATUS		_MAC_(0xb0)
#define RNP_MAC_LS_MASK			GENMASK(25, 24)
#define RNP_MAC_LS_UP			(0)
#define RNP_MAC_LS_LOCAL_FAULT		BIT(25)
#define RNP_MAC_LS_REMOTE_FAULT		(BIT(25) | BIT(24))
/* Unicast Mac Hash Table */
#define RNP_MAC_UC_HASH_TB(n)		_MAC_(0x10 + ((n) * 0x4))


#define RNP_MAC_LPI_CTRL		(0xd0)

/* PHY Link Status Disable */
#define RNP_MAC_PLSDIS			BIT(18)
/* PHY Link Status */
#define RNP_MAC_PLS			BIT(17)

/* MAC VLAN CTRL Strip REG */
#define RNP_MAC_VLAN_TAG		(0x50)

/* En Inner VLAN Strip Action */
#define RNP_MAC_EIVLS			GENMASK(29, 28)
/* Inner VLAN Strip Action Shift */
#define RNP_MAC_IV_EIVLS_SHIFT		(28)
/* Inner Vlan Don't Strip*/
#define RNP_MAC_IV_STRIP_NONE		(0x0)
/* Inner Vlan Strip When Filter Match Success */
#define RNP_MAC_IV_STRIP_PASS		(0x1)
/* Inner Vlan STRIP When Filter Match FAIL */
#define RNP_MAC_IV_STRIP_FAIL		(0x2)
/* Inner Vlan STRIP Always */
#define RNP_MAC_IV_STRIP_ALL		(0X3)
/* VLAN Strip Mode Ctrl Shift */
#define RNP_VLAN_TAG_CTRL_EVLS_SHIFT	(21)
/* En Double Vlan Processing */
#define RNP_MAC_VLAN_EDVLP		BIT(26)
/* VLAN Tag Hash Table Match Enable */
#define RNP_MAC_VLAN_VTHM		BIT(25)
/*  Enable VLAN Tag in Rx status */
#define RNP_MAC_VLAN_EVLRXS		BIT(24)
/* Disable VLAN Type Check */
#define RNP_MAC_VLAN_DOVLTC		BIT(20)
/* Enable S-VLAN */
#define RNP_MAC_VLAN_ESVL		BIT(18)
/* Enable 12-Bit VLAN Tag Comparison Filter */
#define RNP_MAC_VLAN_ETV		BIT(16)
#define RNP_MAC_VLAN_HASH_EN		GENMASK(15, 0)
#define RNP_MAC_VLAN_VID		GENMASK(15, 0)
/* VLAN Don't Strip */
#define RNP_MAC_VLAN_STRIP_NONE		(0x0 << RNP_VLAN_TAG_CTRL_EVLS_SHIFT)
/* VLAN Filter Success Then STRIP */
#define RNP_MAC_VLAN_STRIP_PASS		(0x1 << RNP_VLAN_TAG_CTRL_EVLS_SHIFT)
/* VLAN Filter Failed Then STRIP */
#define RNP_MAC_VLAN_STRIP_FAIL		(0x2 << RNP_VLAN_TAG_CTRL_EVLS_SHIFT)
/* All Vlan Will Strip */
#define RNP_MAC_VLAN_STRIP_ALL		(0x3 << RNP_VLAN_TAG_CTRL_EVLS_SHIFT)

#define RNP_MAC_VLAN_HASH_TB		(0x58)
#define RNP_MAC_VLAN_HASH_MASK		GENMASK(15, 0)

/* MAC VLAN CTRL INSERT REG */
#define RNP_MAC_VLAN_INCL		(0x60)
#define RNP_MAC_INVLAN_INCL		(0x64)

/* VLAN Tag Input */
/* VLAN_Tag Insert From Description */
#define RNP_MAC_VLAN_VLTI		BIT(20)
/* C-VLAN or S-VLAN */
#define RNP_MAC_VLAN_CSVL		BIT(19)
#define RNP_MAC_VLAN_INSERT_CVLAN	(0 << 19)
#define RNP_MAC_VLAN_INSERT_SVLAN	(1 << 19)
/* VLAN Tag Control in Transmit Packets */
#define RNP_MAC_VLAN_VLC		GENMASK(17, 16)
/* VLAN Tag Control Offset Bit */
#define RNP_MAC_VLAN_VLC_SHIFT		(16)
/* Don't Anything ON TX VLAN*/
#define RNP_MAC_VLAN_VLC_NONE		(0x0 << RNP_MAC_VLAN_VLC_SHIFT)
/* MAC Delete VLAN */
#define RNP_MAC_VLAN_VLC_DEL		(0x1 << RNP_MAC_VLAN_VLC_SHIFT)
/* MAC Add VLAN */
#define RNP_MAC_VLAN_VLC_ADD		(0x2 << RNP_MAC_VLAN_VLC_SHIFT)
/* MAC Replace VLAN */
#define RNP_MAC_VLAN_VLC_REPLACE	(0x3 << RNP_MAC_VLAN_VLC_SHIFT)
/* VLAN Tag for Transmit Packets For Insert/Remove */
#define RNP_MAC_VLAN_VLT		GENMASK(15, 0)
/* TX Peer TC Flow Ctrl */

#define RNP_MAC_Q0_TX_FC(n)		(0x70 + ((n) * 0x4))

/* Edit Pause Time */
#define RNP_MAC_FC_PT			GENMASK(31, 16)
#define RNP_MAC_FC_PT_OFFSET		(16)
/*  Disable Zero-Quanta Pause */
#define RNP_MAC_FC_DZPQ			BIT(7)
/* Pause Low Threshold */
#define RNP_MAC_FC_PLT			GENMASK(6, 4)
#define RNP_MAC_FC_PLT_OFFSET		(4)
#define RNP_MAC_FC_PLT_4_SLOT		(0)
#define RNP_MAC_FC_PLT_28_SLOT		(1)
#define RNP_MAC_FC_PLT_36_SLOT		(2)
#define RNP_MAC_FC_PLT_144_SLOT		(3)
#define RNP_MAC_FC_PLT_256_SLOT		(4)
/* Transmit Flow Control Enable */
#define RNP_MAC_FC_TEE			BIT(1)
/* Transmit Flow Control Busy Immediately */
#define RNP_MAC_FC_FCB			BIT(0)
/* Mac RX Flow Ctrl*/

#define RNP_MAC_RX_FC			(0x90)

/* Rx Priority Based Flow Control Enable */
#define RNP_MAC_RX_FC_PFCE		BIT(8)
/* Unicast Pause Packet Detect */
#define RNP_MAC_RX_FC_UP		BIT(1)
/* Receive Flow Control Enable */
#define RNP_MAC_RX_FC_RFE		BIT(0)

/* Rx Mac Address Base */
#define RNP_MAC_ADDR_DEF_HI		_MAC_(0x0300)

#define RNP_MAC_AE			BIT(31)
#define RNP_MAC_ADDR_LO(n)		_MAC_((0x0304) + ((n) * 0x8))
#define RNP_MAC_ADDR_HI(n)		_MAC_((0x0300) + ((n) * 0x8))

/* Mac Manage Counts */
#define RNP_MMC_CTRL			_MAC_(0x0800)
#define RNP_MMC_RSTONRD			BIT(2)
/* Tx Good And Bad Bytes Base */
#define RNP_MMC_TX_GBOCTGB		_MAC_(0x0814)
/* Tx Good And Bad Frame Num Base */
#define RNP_MMC_TX_GBFRMB		_MAC_(0x081c)
/* Tx Good Broadcast Frame Num Base */
#define RNP_MMC_TX_BCASTB		_MAC_(0x0824)
/* Tx Good Multicast Frame Num Base */
#define RNP_MMC_TX_MCASTB		_MAC_(0x082c)
/* Tx 64Bytes Frame Num */
#define RNP_MMC_TX_64_BYTESB		_MAC_(0x0834)
#define RNP_MMC_TX_65TO127_BYTESB	_MAC_(0x083c)
#define RNP_MMC_TX_128TO255_BYTEB	_MAC_(0x0844)
#define RNP_MMC_TX_256TO511_BYTEB	_MAC_(0x084c)
#define RNP_MMC_TX_512TO1023_BYTEB	_MAC_(0x0854)
#define RNP_MMC_TX_1024TOMAX_BYTEB	_MAC_(0x085c)
/* Tx Good And Bad Unicast Frame Num Base */
#define RNP_MMC_TX_GBUCASTB		_MAC_(0x0864)
/* Tx Good And Bad Multicast Frame Num Base */
#define RNP_MMC_TX_GBMCASTB		_MAC_(0x086c)
/* Tx Good And Bad Broadcast Frame NUM Base */
#define RNP_MMC_TX_GBBCASTB		_MAC_(0x0874)
/* Tx Frame Underflow Error */
#define RNP_MMC_TX_UNDRFLWB		_MAC_(0x087c)
/* Tx Good Frame Bytes Base */
#define RNP_MMC_TX_GBYTESB		_MAC_(0x0884)
/* Tx Good Frame Num Base*/
#define RNP_MMC_TX_GBRMB		_MAC_(0x088c)
/* Tx Good Pause Frame Num Base */
#define RNP_MMC_TX_PAUSEB		_MAC_(0x0894)
/* Tx Good Vlan Frame Num Base */
#define RNP_MMC_TX_VLANB		_MAC_(0x089c)

/* Rx Good And Bad Frames Num Base */
#define RNP_MMC_RX_GBFRMB		_MAC_(0x0900)
/* Rx Good And Bad Frames Bytes Base */
#define RNP_MMC_RX_GBOCTGB		_MAC_(0x0908)
/* Rx Good Framse Bytes Base */
#define RNP_MMC_RX_GOCTGB		_MAC_(0x0910)
/* Rx Good Broadcast Frames Num Base */
#define RNP_MMC_RX_BCASTGB		_MAC_(0x0918)
/* Rx Good Multicast Frames Num Base */
#define RNP_MMC_RX_MCASTGB		_MAC_(0x0920)
/* Rx Crc Error Frames Num Base */
#define RNP_MMC_RX_CRCERB		_MAC_(0x0928)
/* Rx Less Than 64Byes with Crc Err Base*/
#define RNP_MMC_RX_RUNTERB		_MAC_(0x0930)
/* Receive Jumbo Frame Error */
#define RNP_MMC_RX_JABBER_ERR		_MAC_(0x0934)
/* Shorter Than 64Bytes without Any Errora Base */
#define RNP_MMC_RX_USIZEGB		_MAC_(0x0938)
/* Len Oversize Than Support */
#define RNP_MMC_RX_OSIZEGB		_MAC_(0x093c)
/* Rx 64Byes Frame Num Base */
#define RNP_MMC_RX_64_BYTESB		_MAC_(0x0940)
/* Rx 65Bytes To 127Bytes Frame Num Base */
#define RNP_MMC_RX_65TO127_BYTESB	_MAC_(0x0948)
/* Rx 128Bytes To 255Bytes Frame Num Base */
#define RNP_MMC_RX_128TO255_BYTESB	_MAC_(0x0950)
/* Rx 256Bytes To 511Bytes Frame Num Base */
#define RNP_MMC_RX_256TO511_BYTESB	_MAC_(0x0958)
/* Rx 512Bytes To 1023Bytes Frame Num Base */
#define RNP_MMC_RX_512TO1203_BYTESB	_MAC_(0x0960)
/* Rx Len Bigger Than 1024Bytes Base */
#define RNP_MMC_RX_1024TOMAX_BYTESB	_MAC_(0x0968)
/* Rx Unicast Frame Good Num Base */
#define RNP_MMC_RX_UCASTGB		_MAC_(0x0970)
/* Rx Length Error Of Frame Part */
#define RNP_MMC_RX_LENERRB		_MAC_(0x0978)
/* Rx received with a Length field not equal to the valid frame size */
#define RNP_MMC_RX_OUTOF_RANGE		_MAC_(0x0980)
/* Rx Pause Frame Good Num Base */
#define RNP_MMC_RX_PAUSEB		_MAC_(0x0988)
/* Rx Vlan Frame Good Num Base */
#define RNP_MMC_RX_VLANGB		_MAC_(0x0998)
/* Rx With A Watchdog Timeout Err Frame Base */
#define RNP_MMC_RX_WDOGERRB		_MAC_(0x09a0)

/* 1588 */
#define RNP_MAC_TS_CTRL                 _MAC_(0X0d00)
#define RNP_MAC_SUB_SECOND_INCREMENT    _MAC_(0x0d04)
#define RNP_MAC_SYS_TIME_SEC_CFG        _MAC_(0x0d08)
#define RNP_MAC_SYS_TIME_NANOSEC_CFG    _MAC_(0x0d0c)
#define RNP_MAC_SYS_TIME_SEC_UPDATE     _MAC_(0x0d10)
#define RNP_MAC_SYS_TIME_NANOSEC_UPDATE _MAC_(0x0d14)
#define RNP_MAC_TS_ADDEND               _MAC_(0x0d18)
#define RNP_MAC_TS_STATS                _MAC_(0x0d20)
#define RNP_MAC_INTERRUPT_ENABLE        _MAC_(0x00b4)

#endif /* __RNP_MAC_REGS_H__ */
