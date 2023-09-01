#ifndef __TSRN10_MBX_H__
#define __TSRN10_MBX_H__

#define VF_NUM_MASK_TEMP	(0xff0)
#define VF_NUM_OFF		(4)
#define RNP_VF_NUM		(0x75f000)
#define RNP_VF_NB_MASK		(0x3f)
#define RNP_PF_NB_MASK		(0x40)
#define RNP_VF_ISOLATE_CTRL	(0x7982fc)
#define RNP_IS_SRIOV		BIT(7)
#define RNP_SRIOV_ST_SHIFT	(24)
#define RNP_VF_DEFAULT_PORT	(0)

/* Mbx Ctrl state */
#define RNP_VFMAILBOX_SIZE	(14) /* 16 32 bit words - 64 bytes */
#define RNP_FW_MAILBOX_SIZE	RNP_VFMAILBOX_SIZE
#define RNP_VFMBX_SIZE		(RNP_VFMAILBOX_SIZE)
#define RNP_VT_MSGTYPE_ACK	(0x80000000)

#define RNP_VT_MSGTYPE_NACK	(0x40000000)
/* Messages below or'd with * this are the NACK */
#define RNP_VT_MSGTYPE_CTS	(0x20000000)
/* Indicates that VF is still
 *clear to send requests
 */
#define RNP_VT_MSGINFO_SHIFT	(16)

#define RNP_VT_MSGINFO_MASK	(0xFF << RNP_VT_MSGINFO_SHIFT)
/* The mailbox memory size is 64 bytes accessed by 32-bit registers */
#define RNP_VLVF_VIEN		(0x80000000) /* filter is valid */
#define RNP_VLVF_ENTRIES	(64)
#define RNP_VLVF_VLANID_MASK	(0x00000FFF)
/* Every VF own 64 bytes mem for communitate accessed by 32-bit */

#define RNP_VF_RESET		(0x01) /* VF requests reset */
#define RNP_VF_SET_MAC_ADDR	(0x02) /* VF requests PF to set MAC addr */
#define RNP_VF_SET_MULTICAST	(0x03) /* VF requests PF to set MC addr */
#define RNP_VF_SET_VLAN		(0x04) /* VF requests PF to set VLAN */

#define RNP_VF_SET_LPE		(0x05) /* VF requests PF to set VMOLR.LPE */
#define RNP_VF_SET_MACVLAN	(0x06) /* VF requests PF for unicast filter */
#define RNP_VF_GET_MACVLAN	(0x07) /* VF requests mac */
#define RNP_VF_API_NEGOTIATE	(0x08) /* negotiate API version */
#define RNP_VF_GET_QUEUES	(0x09) /* get queue configuration */
#define RNP_VF_GET_LINK		(0x10) /* get link status */

#define RNP_VF_SET_VLAN_STRIP	(0x0a) /* VF Requests PF to set VLAN STRIP */
#define RNP_VF_REG_RD		(0x0b) /* VF Read Reg */
#define RNP_VF_GET_MAX_MTU	(0x0c) /* VF Get Max Mtu */
#define RNP_VF_SET_MTU		(0x0d) /* VF Set Mtu */
#define RNP_VF_GET_FW		(0x0e) /* VF Get Firmware Version */

#define RNP_PF_VFNUM_MASK	GENMASK(26, 21)

#define RNP_PF_SET_FCS		(0x10) /* PF set fcs status */
#define RNP_PF_SET_PAUSE	(0x11) /* PF set pause status */
#define RNP_PF_SET_FT_PADDING	(0x12) /* PF set ft padding status */
#define RNP_PF_SET_VLAN_FILTER	(0x13) /* PF set ntuple status */
#define RNP_PF_SET_VLAN		(0x14)
#define RNP_PF_SET_LINK		(0x15)
#define RNP_PF_SET_SPEED_40G	BIT(8)
#define RNP_PF_SET_SPEED_10G	BIT(7)
#define RNP_PF_SET_SPEED_1G	BIT(5)
#define RNP_PF_SET_SPEED_100M	BIT(3)

#define RNP_PF_SET_MTU		(0x16)
#define RNP_PF_SET_RESET	(0x17)
#define RNP_PF_LINK_UP		BIT(31)
#define RNP_PF_SPEED_MASK	GENMASK(15, 0)

/* Define mailbox register bits */
#define RNP_PF_REMOVE		(0x0f)

/* Mailbox API ID VF Request */
/* length of permanent address message returned from PF */
#define RNP_VF_PERMADDR_MSG_LEN (11)
#define RNP_VF_TX_QUEUES	(1) /* number of Tx queues supported */
#define RNP_VF_RX_QUEUES	(2) /* number of Rx queues supported */
#define RNP_VF_TRANS_VLAN	(3) /* Indication of port vlan */
#define RNP_VF_DEF_QUEUE	(4) /* Default queue offset */
/* word in permanent address message with the current multicast type */
#define RNP_VF_VLAN_WORD	(5)
#define RNP_VF_PHY_TYPE_WORD	(6)
#define RNP_VF_FW_VERSION_WORD	(7)
#define RNP_VF_LINK_STATUS_WORD	(8)
#define RNP_VF_AXI_MHZ		(9)
#define RNP_VF_RNP_VF_FEATURE	(10)
#define RNP_VF_RNP_VF_FILTER_EN	BIT(0)

#define RNP_LINK_SPEED_UNKNOWN 0
#define RNP_LINK_SPEED_10_FULL    BIT(2)
#define RNP_LINK_SPEED_100_FULL   BIT(3)
#define RNP_LINK_SPEED_1GB_FULL   BIT(4)
#define RNP_LINK_SPEED_10GB_FULL  BIT(5)
#define RNP_LINK_SPEED_40GB_FULL  BIT(6)
#define RNP_LINK_SPEED_25GB_FULL  BIT(7)
#define RNP_LINK_SPEED_50GB_FULL  BIT(8)
#define RNP_LINK_SPEED_100GB_FULL BIT(9)
#define RNP_LINK_SPEED_10_HALF    BIT(10)
#define RNP_LINK_SPEED_100_HALF   BIT(11)
#define RNP_LINK_SPEED_1GB_HALF   BIT(12)

/* Mailbox API ID PF Request */
#define RNP_VF_MC_TYPE_WORD		(3)
#define RNP_VF_DMA_VERSION_WORD		(4)
/* Get Queue write-back reference value */
#define RNP_PF_CONTROL_PRING_MSG	(0x0100) /* PF control message */

#define TSRN10_MBX_VECTOR_ID            (0)
#define TSRN10_PF2VF_MBX_VEC_CTR(n)     (0xa5000 + 0x4 * (n))

#define RNP_VF_INIT_TIMEOUT		(200) /* Number of retries to clear RSTI */
#define RNP_VF_MBX_INIT_TIMEOUT		(2000) /* number of retries on mailbox */

#define MBOX_CTRL_REQ			(1 << 0) /* WO */
#define MBOX_CTRL_VF_HOLD_SHM		(1 << 2) /* VF:WR, PF:RO */
#define VF_NUM_MASK 0x3f
#define VFNUM(num)			((num) & VF_NUM_MASK)

#define PF_VF_SHM(vf)	\
	((0xa6000) + (64 * (vf))) /* for PF1 rtl will remap 6000 to 0xb000 */
#define PF2VF_COUNTER(vf)		(PF_VF_SHM(vf) + 0)
#define VF2PF_COUNTER(vf)		(PF_VF_SHM(vf) + 4)
#define PF_VF_SHM_DATA(vf)		(PF_VF_SHM(vf) + 8)
#define VF2PF_MBOX_CTRL(vf)		((0xa7000) + (4 * (vf)))

/* Error Codes */
#define RNP_ERR_INVALID_MAC_ADDR	(-1)
#define RNP_ERR_MBX			(-100)

#define RNP_MBX_DELAY_US		(100) /* Delay us for Retry */
/* Max Retry Time */
#define RNP_MBX_TIMEOUT_SECONDS	(2) /* Max Retry Time 2s */
#define RNP_ARRAY_OPCODE_OFFSET	(0)
#define RNP_ARRAY_CTRL_OFFSET	(1)

void rnp_init_mbx_ops_pf(struct rnp_hw *hw);
extern const struct rnp_mbx_api rnp_mbx_pf_ops;
void *rnp_memzone_reserve(const char *name, unsigned int size);
#endif
